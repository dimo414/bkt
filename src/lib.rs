use std::time::{Duration, Instant, SystemTime};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::process::{Command};
use std::io::{self, BufReader, ErrorKind, BufWriter, Write};
use std::path::{PathBuf, Path};
use std::hash::{Hash, Hasher};

use anyhow::{Context, Error, Result};
use serde::{Serialize, Deserialize};

// Describes a command to be cached. Is used as the cache key.
// TODO use OsStr/OsString rather than String
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CommandDesc {
    args: Vec<String>,
    // TODO cwd - https://doc.rust-lang.org/std/env/fn.current_dir.html
    // TODO env vars - https://doc.rust-lang.org/std/env/fn.var.html
}

impl CommandDesc {
    pub fn new<I, S>(command: I) -> CommandDesc where I: IntoIterator<Item = S>, S: Into<String> {
        CommandDesc {
            args: command.into_iter().map(Into::into).collect(),
        }
    }

    fn cache_key(&self) -> String {
        // The hash_map DefaultHasher is somewhat underspecified, but it notes that "hashes should
        // not be relied upon over releases", which implies it is stable across multiple
        // invocations of the same build....
        let mut s = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut s);
        let hash = s.finish();
        if cfg!(feature = "debug") {
            let cmd_str: String = self.args.join("-")
                .chars().filter(|&c| c.is_alphanumeric() || c == '-').collect();
            format!("{:.100}_{:16X}", cmd_str, hash)
        } else {
            format!("{:16X}", hash)
        }
    }
}

impl fmt::Display for CommandDesc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.args[0])
    }
}

// TODO helpers to get out/err as strings
#[derive(Serialize, Deserialize)]
pub struct Invocation {
    command: CommandDesc, // just used for cache key validation
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: i32,
    pub runtime: Duration,
}

struct FileLock {
    lock_file: PathBuf,
}

impl FileLock {
    fn try_acquire(lock_dir: &Path, name: &str, consider_stale: Duration) -> Result<Option<FileLock>> {
        let lock_file = lock_dir.join(name).with_extension("lock");
        match OpenOptions::new().create_new(true).write(true).open(&lock_file) {
            Ok(mut lock) => {
                write!(lock, "{}", std::process::id())?;
                Ok(Some(FileLock{ lock_file }))
            },
            Err(io) => {
                match io.kind() {
                    ErrorKind::AlreadyExists => {
                        if let Ok(lock_metadata) = std::fs::metadata(&lock_file) {
                            if let Ok(age) = lock_metadata.modified()?.elapsed() {
                                if age > consider_stale {
                                    return Err(Error::msg(format!(
                                        "Lock {} held by PID {} appears stale and may need to be deleted manually.",
                                        lock_file.display(),
                                        std::fs::read_to_string(&lock_file).unwrap_or("unknown".into()))));
                                }
                            }
                        }
                        Ok(None)
                    },
                    _ => { Err(Error::new(io)) }
                }
            },
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.lock_file) {
            eprintln!("Failed to delete lockfile {}, may need to be deleted manually. Reason: {:?}",
                      self.lock_file.display(), e);
        }
    }
}

// See https://doc.rust-lang.org/std/fs/fn.soft_link.html
#[cfg(windows)]
use std::os::windows::fs::symlink_file as symlink;
#[cfg(unix)]
use std::os::unix::fs::symlink;

// TODO make this a trait so we can swap out impls, namely an in-memory impl
#[derive(Clone)]
struct Cache {
    cache_dir: PathBuf,
    key_dir: PathBuf,
    data_dir: PathBuf,
}

impl Cache {
    fn new(root_dir: Option<&str>, scope: Option<&str>) -> Cache {
        let root_dir = root_dir.map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        // Note the cache is invalidated when the minor version changes
        let cache_dir = root_dir.join(format!("bkt-{}.{}-cache", env!("CARGO_PKG_VERSION_MAJOR"), env!("CARGO_PKG_VERSION_MINOR")));
        let mut key_dir = cache_dir.join("keys");
        if let Some(scope) = scope {
            let scope = Path::new(scope);
            assert_eq!(scope.iter().count(), 1, "scope should be a single path element");
            key_dir.push(scope);
        }
        let data_dir = cache_dir.join("data");
        Cache{ cache_dir, key_dir, data_dir }
    }

    #[cfg(not(feature = "debug"))]
    fn serialize<W, T>(writer: W, value: &T) -> Result<()>
        where W: io::Write, T: ?Sized + Serialize {
        Ok(bincode::serialize_into(writer, value)?)
    }

    #[cfg(feature = "debug")]
    fn serialize<W, T>(writer: W, value: &T) -> Result<()>
        where W: io::Write, T: ?Sized + Serialize {
        Ok(serde_json::to_writer(writer, value)?)
    }

    #[cfg(not(feature = "debug"))]
    fn deserialize<R, T>(reader: R) -> Result<T>
        where R: std::io::Read, T: serde::de::DeserializeOwned {
        Ok(bincode::deserialize_from(reader)?)
    }

    #[cfg(feature = "debug")]
    fn deserialize<R, T>(reader: R) -> Result<T>
        where R: std::io::Read, T: serde::de::DeserializeOwned {
        Ok(serde_json::from_reader(reader)?)
    }

    fn lookup(&self, command: &CommandDesc, max_age: Duration)
              -> Result<Option<(Invocation, SystemTime)>> {
        let path = self.key_dir.join(command.cache_key());
        let file = File::open(&path);
        if let Err(ref e) = file {
            if e.kind() == ErrorKind::NotFound {
                return Ok(None);
            }
        }
        // Missing file is OK; other errors get propagated to the caller
        let reader = BufReader::new(file.context("Failed to access cache file")?);
        let found: Invocation = Cache::deserialize(reader)?;
        // Discard data that is too old
        let mtime = std::fs::metadata(&path)?.modified()?;
        let elapsed = mtime.elapsed();
        if elapsed.is_err() || elapsed.unwrap() > max_age {
            std::fs::remove_file(&path).context("Failed to remove expired invocation data")?;
            return Ok(None);
        }
        // Ignore false-positive hits that happened to collide with the hash code
        if &found.command != command {
            return Ok(None);
        }
        Ok(Some((found, mtime)))
    }

    fn store(&self, invocation: &Invocation, ttl: Duration) -> Result<()> {
        // TODO allow sub-second precision by rounding up the ttl_dir; lookup() already respects
        // sub-second TTLs
        assert!(ttl.as_secs() > 0, "ttl must be a positive number of seconds");
        let ttl_dir = self.data_dir.join(ttl.as_secs().to_string());
        std::fs::create_dir_all(&ttl_dir)?;
        std::fs::create_dir_all(&self.key_dir)?;
        let file = tempfile::NamedTempFile::new_in(ttl_dir)?;
        Cache::serialize(BufWriter::new(&file), invocation)?;
        let (_, path) = file.keep()?;
        // Roundabout approach to an atomic symlink replacement
        // https://github.com/dimo414/bash-cache/blob/59bcad6/bash-cache.sh#
        // Create and immediately destroy a file, to capture a (hopefully still) unique path name
        // TODO eliminate this wasteful I/O
        let tmp_symlink = tempfile::NamedTempFile::new()?.path().to_path_buf();
        symlink(&path, &tmp_symlink)?;
        std::fs::rename(&tmp_symlink, self.key_dir.join(invocation.command.cache_key()))?;
        Ok(())
    }

    fn cleanup(&self) -> Result<()> {
        if let Some(_lock) = FileLock::try_acquire(&self.cache_dir, "cleanup", Duration::from_secs(60*10))? {
            // Don't bother if cleanup has been attempted recently
            let last_attempt_file = self.cache_dir.join("last_cleanup");
            if let Ok(metadata) = last_attempt_file.metadata() {
                if metadata.modified()?.elapsed()? < Duration::from_secs(30) {
                    return Ok(());
                }
            }
            File::create(&last_attempt_file)?; // resets mtime if already exists

            // First delete stale data files
            for entry in std::fs::read_dir(&self.data_dir)? {
                let ttl_dir = entry?.path();
                let ttl = Duration::from_secs(
                    ttl_dir.file_name().and_then(|s| s.to_str()).and_then(|s| s.parse().ok())
                        .ok_or(Error::msg(format!("Invalid ttl directory {}", ttl_dir.display())))?);

                for entry in std::fs::read_dir(&ttl_dir)? {
                    let file = entry?.path();
                    // Disregard errors on individual files; typically due to concurrent deletion
                    // or other changes we don't care about.
                    let _ = Cache::delete_stale_file(&file, ttl);
                }
            }

            // Then delete broken symlinks
            // TODO this only deletes symlinks in the scoped key_dir, which is fine but sub-optimal
            for entry in std::fs::read_dir(&self.key_dir)? {
                let symlink = entry?.path();
                // This reads as if we're deleting files that no longer exist, but what it really
                // means is "if the symlink is broken, try to delete _the symlink_." It would also
                // try to delete a symlink that happened to be deleted concurrently, but this is
                // harmless since we ignore the error.
                // std::fs::symlink_metadata() could be used to check that the symlink itself exists
                // if needed, but this could still have false-positives due to a TOCTOU race.
                if !symlink.exists() {
                    let _ = std::fs::remove_file(symlink);
                }
            }
        }
        Ok(())
    }

    fn delete_stale_file(file: &Path, ttl: Duration) -> Result<()> {
        let age = std::fs::metadata(file)?.modified()?.elapsed()?;
        if age > ttl {
            std::fs::remove_file(&file)?;
        }
        Ok(())
    }
}

pub struct Bkt {
    cache: Cache,
}

impl Bkt {
    pub fn new() -> Bkt {
        Bkt::create(None, None)
    }

    pub fn scoped(scope: &str) -> Bkt {
        Bkt::create(None, Some(scope))
    }

    pub fn create(root_dir: Option<&str>, scope: Option<&str>) -> Bkt {
        Bkt {
            cache: Cache::new(root_dir, scope),
        }
    }

    fn build_command(desc: &CommandDesc) -> Command {
        let mut command = Command::new(&desc.args[0]);
        command.args(&desc.args[1..]);
        command
    }

    fn execute_subprocess(desc: &CommandDesc) -> Result<Invocation> {
        let mut cmd = Bkt::build_command(&desc);
        let start = Instant::now();
        // TODO write to stdout/stderr while running, rather than after the process completes?
        // See https://stackoverflow.com/q/66060139
        let result = cmd.output()
            .with_context(|| format!("Failed to run command {}", desc))?;
        let runtime = start.elapsed();
        Ok(Invocation {
            command: desc.clone(),
            stdout: result.stdout,
            stderr: result.stderr,
            // TODO handle signals, see https://stackoverflow.com/q/66272686
            status: result.status.code().unwrap_or(126),
            runtime,
        })
    }

    // TODO better name than execute?
    pub fn execute(&self, command: &CommandDesc, ttl: Duration) -> Result<(Invocation, Duration)> {
        let cached = self.cache.lookup(command, ttl)?;
        let result = match cached {
            Some((cached, mtime)) => (cached, mtime.elapsed()?),
            None => {
                let result = Bkt::execute_subprocess(command)?;
                self.cache.store(&result, ttl)?;
                (result, Duration::default())
            }
        };
        Ok(result)
    }

    pub fn refresh(&self, command: &CommandDesc, ttl: Duration) -> Result<Invocation> {
        let result = Bkt::execute_subprocess(command)?;
        self.cache.store(&result, ttl)?;
        Ok(result)
    }

    pub fn cleanup_once(&self) -> Result<()> {
        self.cache.cleanup()
    }

    pub fn cleanup_thread(&self) -> std::thread::JoinHandle<()> {
        let cache = self.cache.clone();
        std::thread::spawn(move || {
            //  Hard-coded for now, could be made configurable if needed
            let poll_duration = Duration::from_secs(60);
            loop {
                if let Err(e) = cache.cleanup() {
                    eprintln!("bkt: cache cleanup failed: {:?}", e);
                }
                std::thread::sleep(poll_duration);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanity-checking that CommandDesc::cache_key isn't changing over time. This test may need
    // to be updated if the implementation changes in the future.
    #[test]
    fn stable_hash() {
        assert_eq!(CommandDesc::new(vec!("foo", "bar")).cache_key(), "13EFD84004DBAD3A");
    }
}