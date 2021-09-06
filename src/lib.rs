use std::time::{Duration, Instant, SystemTime};
use std::fmt;
use std::fs::File;
use std::process::{Command};
use std::io::{self, BufReader, ErrorKind, BufWriter};
use std::path::{PathBuf, Path};
use std::hash::{Hash, Hasher};

use anyhow::{Context, Result};
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

// See https://doc.rust-lang.org/std/fs/fn.soft_link.html
#[cfg(windows)]
use std::os::windows::fs::symlink_file as symlink;
#[cfg(unix)]
use std::os::unix::fs::symlink;

// TODO make this a trait so we can swap out impls, namely an in-memory impl
struct Cache {
    key_dir: PathBuf,
    data_dir: PathBuf,
}

impl Cache {
    fn new(root_dir: Option<&str>, scope: Option<&str>) -> Cache {
        let mut dir = root_dir.map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        // Note the cache is invalidated when the minor version changes
        dir.push(format!("bkt-{}.{}-cache", env!("CARGO_PKG_VERSION_MAJOR"), env!("CARGO_PKG_VERSION_MINOR")));
        let mut key_dir = dir.clone();
        key_dir.push("keys");
        if let Some(scope) = scope {
            let scope = Path::new(scope);
            assert_eq!(scope.iter().count(), 1, "scope should be a single path element");
            key_dir.push(scope);
        }
        let mut data_dir = dir;
        data_dir.push("data");
        Cache{ key_dir, data_dir }
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

    fn store(&self, invocation: &Invocation, ttl: &Duration) -> Result<()> {
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
                self.cache.store(&result, &ttl)?;
                (result, Duration::default())
            }
        };
        Ok(result)
    }

    pub fn refresh(&self, command: &CommandDesc, ttl: Duration) -> Result<Invocation> {
        let result = Bkt::execute_subprocess(command)?;
        self.cache.store(&result, &ttl)?;
        Ok(result)
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