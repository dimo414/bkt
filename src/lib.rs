//! `bkt` (pronounced "bucket") is a library for caching subprocess executions. It enables reuse of
//! expensive invocations across separate processes and supports synchronous and asynchronous
//! refreshing, TTLs, and other functionality. `bkt` is also a standalone binary for use by shell
//! scripts and other languages, see https://github.com/dimo414/bkt for binary details.
//!
//! ```no_run
//! # fn do_something(_: &str) {}
//! # fn main() -> anyhow::Result<()> {
//! # use std::time::Duration;
//! let bkt = bkt::Bkt::in_tmp();
//! let expensive_cmd = bkt::CommandDesc::new(&["wget", "http://example.com"]);
//! let (result, age) = bkt.execute(&expensive_cmd, Duration::from_secs(3600))?;
//! do_something(result.stdout_utf8());
//! # Ok(()) }
//! ```
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::ffi::{OsString, OsStr};
use std::fs::{File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{self, BufReader, ErrorKind, BufWriter, Write};
use std::path::{PathBuf, Path};
use std::process::{Command};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Error, Result};
use serde::{Serialize, Deserialize};

/// Describes a command to be executed and cached. This struct also serves as the cache key.
/// It consists of a command line invocation and, optionally, a working directory to execute in and
/// environment variables to set. When set these fields contribute to the cache key, therefore two
/// invocations with different working directories set will be cached separately.
///
/// ```
/// let cmd = bkt::CommandDesc::new(&["echo", "Hello World!"]);
/// let with_cwd = bkt::CommandDesc::new(&["ls"]).with_working_dir("/tmp");
/// let with_env = bkt::CommandDesc::new(&["date"]).with_env_value("TZ", "America/New_York");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CommandDesc {
    args: Vec<OsString>,
    cwd: Option<PathBuf>,
    env: BTreeMap<OsString, OsString>,
}

impl CommandDesc {
    /// Constructs a CommandDesc instance for the given command line.
    ///
    /// ```
    /// let cmd = bkt::CommandDesc::new(&["echo", "Hello World!"]);
    /// ```
    pub fn new<I, S>(command: I) -> Self where I: IntoIterator<Item = S>, S: Into<OsString> {
        let ret = CommandDesc {
            args: command.into_iter().map(Into::into).collect(),
            cwd: None,
            env: BTreeMap::new(),
        };
        assert!(!ret.args.is_empty(), "Command cannot be empty");
        ret
    }

    /// Sets the working directory the command should be run from, and causes the working directory
    /// to be included in the cache key. If unset the working directory will be inherited from the
    /// current process' and will _not_ be used to differentiate invocations in separate working
    /// directories.
    ///
    /// ```
    /// let cmd = bkt::CommandDesc::new(&["pwd"]).with_working_dir("/tmp");
    /// ```
    pub fn with_working_dir<P: AsRef<Path>>(mut self, cwd: P) -> Self {
        self.cwd = Some(cwd.as_ref().into());
        self
    }

    /// Sets the working directory to the current process' working directory. This has no effect
    /// on the subprocess that will be executed (assuming the current process' working directory
    /// remains unchanged) but does cause the working directory to be included in the cache key.
    /// Commands that depend on the working directory should call this in order to cache executions
    /// in different working directories separately.
    ///
    /// # Errors
    ///
    /// This delegates to [`std::env::current_dir()`] and will fail if it does.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> anyhow::Result<()> {
    /// let cmd = bkt::CommandDesc::new(&["pwd"]).with_cwd()?;
    /// # Ok(()) }
    /// ```
    pub fn with_cwd(self) -> Result<Self> {
        Ok(self.with_working_dir(std::env::current_dir()?))
    }

    /// Adds the given key/value pair to the environment the command should be run from, and causes
    /// this pair to be included in the cache key.
    ///
    /// ```
    /// let cmd = bkt::CommandDesc::new(&["pwd"]).with_env_value("FOO", "bar");
    /// ```
    pub fn with_env_value<K, V>(mut self, key: K, value: V) -> Self
            where K: AsRef<OsStr>, V: AsRef<OsStr> {
        self.env.insert(key.as_ref().into(), value.as_ref().into());
        self
    }

    /// Looks up the given environment variable in the current process' environment and, if set,
    /// adds that key/value pair to the environment the command should be run from, and causes this
    /// pair to be included in the cache key. This has no effect on the subprocess that will be
    /// executed (assuming the current process' environment remains unchanged).
    ///
    /// If the given variable name is not found in the current process' environment this call is a
    /// no-op, and the cache key will remain unchanged.
    ///
    /// ```
    /// let cmd = bkt::CommandDesc::new(&["date"]).with_env("TZ");
    /// ```
    pub fn with_env<K>(self, key: K) -> Self
            where K: AsRef<OsStr> {
        match std::env::var_os(&key) {
            Some(val) => self.with_env_value(&key, val),
            None => self,
        }
    }

    /// Adds the given key/value pairs to the environment the command should be run from, and causes
    /// these pair to be included in the cache key.
    ///
    /// ```
    /// use std::env;
    /// use std::collections::HashMap;
    ///
    /// let important_envs : HashMap<String, String> =
    ///     env::vars().filter(|&(ref k, _)|
    ///         k == "TERM" || k == "TZ" || k == "LANG" || k == "PATH"
    ///     ).collect();
    /// let cmd = bkt::CommandDesc::new(&["..."]).with_envs(&important_envs);
    /// ```
    pub fn with_envs<I, K, V>(mut self, envs: I) -> Self
        where
            I: IntoIterator<Item = (K, V)>,
            K: AsRef<OsStr>,
            V: AsRef<OsStr>,
    {
        for (ref key, ref val) in envs {
            self.env.insert(key.as_ref().into(), val.as_ref().into());
        }
        self
    }

    fn cache_key(&self) -> String {
        // The hash_map DefaultHasher is somewhat underspecified, but it notes that "hashes should
        // not be relied upon over releases", which implies it is stable across multiple
        // invocations of the same build....
        let mut s = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut s);
        let hash = s.finish();
        if cfg!(feature = "debug") {
            let cmd_str: String = self.args.iter()
                .map(|a| a.to_string_lossy()).collect::<Vec<_>>().join("-")
                .chars().filter(|&c| c.is_alphanumeric() || c == '-').collect();
            format!("{:.100}_{:16X}", cmd_str, hash)
        } else {
            format!("{:16X}", hash)
        }
    }
}

#[cfg(test)]
mod cmd_tests {
    use super::*;

    // Sanity-checking that CommandDesc::cache_key isn't changing over time. This test may need
    // to be updated if the implementation changes in the future.
    #[test]
    fn stable_hash() {
        assert_eq!(CommandDesc::new(vec!("foo", "bar")).cache_key(), "E6152829B1A98275");
    }

    #[test]
    fn collisions() {
        let commands = vec!(
            CommandDesc::new(vec!("foo")),
            CommandDesc::new(vec!("foo", "bar")),
            CommandDesc::new(vec!("foo", "b", "ar")),
            CommandDesc::new(vec!("foo", "b ar")),
            CommandDesc::new(vec!("foo")).with_working_dir("/bar").clone(),
            CommandDesc::new(vec!("foo")).with_working_dir("/bar/baz").clone(),
            CommandDesc::new(vec!("foo")).with_env_value("a", "b"),
            CommandDesc::new(vec!("foo")).with_working_dir("/bar").with_env_value("a", "b"),
        );

        // https://old.reddit.com/r/rust/comments/2koptu/best_way_to_visit_all_pairs_in_a_vec/clnhxr5/
        let mut iter = commands.iter();
        for a in commands.iter() {
            iter.next();
            for b in iter.clone() {
                assert_ne!(a.cache_key(), b.cache_key(), "{:?} and {:?} have equivalent hashes", a, b);
            }
        }
    }
}

/// The outputs of a cached invocation of a [`CommandDesc`], akin to [`std::process::Output`].
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Invocation {
    /// Used internally for cache key validation
    command: CommandDesc,
    /// The data that the process wrote to stdout.
    pub stdout: Vec<u8>,
    /// The data that the process wrote to stderr.
    pub stderr: Vec<u8>,
    /// The exit status of the program, or 126 if the program terminated without an exit status.
    /// See [`ExitStatus::code()`](std::process::ExitStatus::code()). This is subject to change to
    /// better support other termination states.
    pub status: i32,
    /// The time the process took to complete.
    pub runtime: Duration,
}

impl Invocation {
    /// Helper to view stdout as a UTF-8 string. Use [`from_utf8`](std::str::from_utf8) directly if
    /// you need to handle output that may not be UTF-8.
    pub fn stdout_utf8(&self) -> &str {
        std::str::from_utf8(&self.stdout).expect("stdout not valid UTF-8")
    }

    /// Helper to view stderr as a UTF-8 string. Use [`from_utf8`](std::str::from_utf8) directly if
    /// you need to handle output that may not be UTF-8.
    pub fn stderr_utf8(&self) -> &str {
        std::str::from_utf8(&self.stderr).expect("stderr not valid UTF-8")
    }
}

/// A file-lock mechanism that holds a lock by atomically creating a file in the given directory,
/// and deleting the file upon being dropped. Callers should beware that dropping is not guaranteed
/// (e.g. if the program panics). When a conflicting lock file is found its age (mtime) is checked
/// to detect stale locks leaked by a separate process that failed to properly drop its lock.
struct FileLock {
    lock_file: PathBuf,
}

impl FileLock {
    fn try_acquire<P: AsRef<Path>>(lock_dir: P, name: &str, consider_stale: Duration) -> Result<Option<Self>> {
        let lock_file = lock_dir.as_ref().join(name).with_extension("lock");
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

#[cfg(test)]
mod file_lock_tests {
    use super::*;
    use test_dir::{TestDir, DirBuilder};

    #[test]
    fn locks() {
        let dir = TestDir::temp();
        let lock = FileLock::try_acquire(&dir.root(), "test", Duration::from_secs(100)).unwrap();
        let lock = lock.expect("Could not take lock");
        assert!(dir.path("test.lock").exists());
        std::mem::drop(lock);
        assert!(!dir.path("test.lock").exists());
    }

    #[test]
    fn already_locked() {
        let dir = TestDir::temp();
        let lock = FileLock::try_acquire(&dir.root(), "test", Duration::from_secs(100)).unwrap();
        let lock = lock.expect("Could not take lock");

        let attempt = FileLock::try_acquire(&dir.root(), "test", Duration::from_secs(100)).unwrap();
        assert!(attempt.is_none());

        std::mem::drop(lock);
        let attempt = FileLock::try_acquire(&dir.root(), "test", Duration::from_secs(100)).unwrap();
        assert!(attempt.is_some());
    }
}

// See https://doc.rust-lang.org/std/fs/fn.soft_link.html
#[cfg(windows)]
use std::os::windows::fs::symlink_file as symlink;
#[cfg(unix)]
use std::os::unix::fs::symlink;

/// A file-system-backed cache for mapping `CommandDesc` keys to `Invocation` values for a given
/// duration.
// TODO make this a trait so we can swap out impls, namely an in-memory impl
#[derive(Clone)]
struct Cache {
    cache_dir: PathBuf,
    scope: Option<String>,
}

impl Cache {
    fn new<P: AsRef<Path>>(cache_dir: P) -> Self {
        Cache{ cache_dir: cache_dir.as_ref().into(), scope: None }
    }

    fn scoped(&mut self, scope: String) -> &mut Self {
        assert!(self.scope.is_none());
        self.scope = Some(scope);
        self
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

    fn key_dir(&self) -> PathBuf {
        self.cache_dir.join("keys")
    }

    fn key_path(&self, key: &str) -> PathBuf {
        let file = match &self.scope {
            Some(scope) => format!("{}.{}", scope, key),
            None => key.into(),
        };
        self.key_dir().join(file)
    }

    fn data_dir(&self) -> PathBuf {
        self.cache_dir.join("data")
    }

    fn lookup(&self, command: &CommandDesc, max_age: Duration)
              -> Result<Option<(Invocation, SystemTime)>> {
        let path = self.key_path(&command.cache_key());
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

    fn seconds_ceiling(duration: Duration) -> u64 {
        duration.as_secs() + if duration.subsec_nanos() != 0 { 1 } else { 0 }
    }

    // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html#create-random-passwords-from-a-set-of-alphanumeric-characters
    fn rand_filename(dir: &Path, label: &str) -> PathBuf {
        use rand::{thread_rng, Rng};
        use rand::distributions::Alphanumeric;
        let rand_str: String = thread_rng().sample_iter(&Alphanumeric).take(16).map(char::from).collect();
        dir.join(format!("{}.{}", label, rand_str))
    }

    fn store(&self, invocation: &Invocation, ttl: Duration) -> Result<()> {
        assert!(!ttl.as_secs() > 0 || ttl.subsec_nanos() > 0, "ttl cannot be zero"); // TODO use is_zero once stable
        let ttl_dir = self.data_dir().join(Cache::seconds_ceiling(ttl).to_string());
        std::fs::create_dir_all(&ttl_dir)?;
        std::fs::create_dir_all(&self.key_dir())?;
        let path = Cache::rand_filename(&ttl_dir, "invocation");
        // Note: this will fail if filename collides, could retry in a loop if that happens
        let file = OpenOptions::new().create_new(true).write(true).open(&path)?;
        Cache::serialize(BufWriter::new(&file), invocation)?;
        // Roundabout approach to an atomic symlink replacement
        // https://github.com/dimo414/bash-cache/issues/26
        let tmp_symlink = Cache::rand_filename(&self.key_dir(), "tmp-symlink");
        // Note: this will fail if filename collides, could retry in a loop if that happens
        symlink(&path, &tmp_symlink)?;
        std::fs::rename(&tmp_symlink, self.key_path(&invocation.command.cache_key()))?;
        Ok(())
    }

    fn cleanup(&self) -> Result<()> {
        fn delete_stale_file(file: &Path, ttl: Duration) -> Result<()> {
            let age = std::fs::metadata(file)?.modified()?.elapsed()?;
            if age > ttl {
                std::fs::remove_file(&file)?;
            }
            Ok(())
        }

        // if try_acquire fails, e.g. because the directory does not exist, there's nothing to clean up
        if let Ok(Some(_lock)) = FileLock::try_acquire(&self.cache_dir, "cleanup", Duration::from_secs(60*10)) {
            // Don't bother if cleanup has been attempted recently
            let last_attempt_file = self.cache_dir.join("last_cleanup");
            if let Ok(metadata) = last_attempt_file.metadata() {
                if metadata.modified()?.elapsed()? < Duration::from_secs(30) {
                    return Ok(());
                }
            }
            File::create(&last_attempt_file)?; // resets mtime if already exists

            // First delete stale data files
            if let Ok(data_dir_iter) = std::fs::read_dir(&self.data_dir()) {
                for entry in data_dir_iter {
                    let ttl_dir = entry?.path();
                    let ttl = Duration::from_secs(
                        ttl_dir.file_name().and_then(|s| s.to_str()).and_then(|s| s.parse().ok())
                            .ok_or(Error::msg(format!("Invalid ttl directory {}", ttl_dir.display())))?);

                    for entry in std::fs::read_dir(&ttl_dir)? {
                        let file = entry?.path();
                        // Disregard errors on individual files; typically due to concurrent deletion
                        // or other changes we don't care about.
                        let _ = delete_stale_file(&file, ttl);
                    }
                }
            }

            // Then delete broken symlinks
            if let Ok(key_dir_iter) = std::fs::read_dir(&self.key_dir()) {
                for entry in key_dir_iter {
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
        }
        Ok(())
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use test_dir::{TestDir, DirBuilder};

    fn modtime<P: AsRef<Path>>(path: P) -> SystemTime {
        std::fs::metadata(&path).expect("No metadata").modified().expect("No modtime")
    }

    fn make_dir_stale<P: AsRef<Path>>(dir: P, age: Duration) -> Result<()> {
        let desired_time = SystemTime::now() - age;
        let stale_time = filetime::FileTime::from_system_time(desired_time);
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let last_modified = modtime(&path);

            if path.is_file() && last_modified > desired_time {
                filetime::set_file_mtime(&path, stale_time)?;
            } else if path.is_dir() {
                make_dir_stale(&path, age)?;
            }
        }
        Ok(())
    }

    fn dir_contents<P: AsRef<Path>>(dir: P) -> Vec<String> {
        fn contents(dir: &Path, ret: &mut Vec<PathBuf>) -> Result<()> {
            for entry in std::fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.is_dir() {
                    contents(&path, ret)?;
                } else {
                    ret.push(path);
                }
            }
            Ok(())
        }
        let mut paths = vec!();
        contents(dir.as_ref(), &mut paths).unwrap();
        paths.iter().map(|p| p.strip_prefix(dir.as_ref()).unwrap().display().to_string()).collect()
    }

    fn inv(cmd: &CommandDesc, stdout: &str) -> Invocation {
        Invocation{
            command: cmd.clone(), stdout: stdout.into(),
            stderr: "".into(), status: 0, runtime: Duration::from_secs(0), }
    }

    #[test]
    fn cache() {
        let dir = TestDir::temp();
        let cmd = CommandDesc::new(vec!("foo"));
        let inv = inv(&cmd, "A");
        let cache = Cache::new(&dir.root());

        let absent = cache.lookup(&cmd, Duration::from_secs(100)).unwrap();
        assert!(absent.is_none());

        cache.store(&inv, Duration::from_secs(100)).unwrap();
        let present = cache.lookup(&cmd, Duration::from_secs(100)).unwrap();
        assert_eq!(present.unwrap().0.stdout_utf8(), "A");
    }

    #[test]
    fn lookup_ttls() {
        let dir = TestDir::temp();
        let cmd = CommandDesc::new(vec!("foo"));
        let inv = inv(&cmd, "A");
        let cache = Cache::new(&dir.root());

        cache.store(&inv, Duration::from_secs(5)).unwrap(); // store duration doesn't affect lookups
        make_dir_stale(dir.root(), Duration::from_secs(15)).unwrap();

        // data is still present until a cleanup iteration runs, or a lookup() invalidates it
        let present = cache.lookup(&cmd, Duration::from_secs(20)).unwrap();
        assert_eq!(present.unwrap().0.stdout_utf8(), "A");
        // lookup() finds stale data, deletes it
        let absent = cache.lookup(&cmd, Duration::from_secs(10)).unwrap();
        assert!(absent.is_none());
        // now data is gone, even though this lookup() would have accepted it
        let absent = cache.lookup(&cmd, Duration::from_secs(20)).unwrap();
        assert!(absent.is_none());
    }

    #[test]
    fn scoped() {
        let dir = TestDir::temp();
        let cmd = CommandDesc::new(vec!("foo"));
        let inv_a = inv(&cmd, "A");
        let inv_b = inv(&cmd, "B");
        let cache = Cache::new(&dir.root());
        let mut cache_scoped = Cache::new(&dir.root());
        cache_scoped.scoped("scope".into());

        cache.store(&inv_a, Duration::from_secs(100)).unwrap();
        cache_scoped.store(&inv_b, Duration::from_secs(100)).unwrap();

        let present = cache.lookup(&cmd, Duration::from_secs(20)).unwrap();
        assert_eq!(present.unwrap().0.stdout_utf8(), "A");
        let present_scoped = cache_scoped.lookup(&cmd, Duration::from_secs(20)).unwrap();
        assert_eq!(present_scoped.unwrap().0.stdout_utf8(), "B");
    }

    #[test]
    fn cleanup() {
        let dir = TestDir::temp();
        let cmd = CommandDesc::new(vec!("foo"));
        let inv = inv(&cmd, "A");
        let cache = Cache::new(&dir.root());

        cache.store(&inv, Duration::from_secs(5)).unwrap();
        make_dir_stale(dir.root(), Duration::from_secs(10)).unwrap();
        cache.cleanup().unwrap();

        assert_eq!(dir_contents(dir.root()), vec!("last_cleanup")); // keys and data dirs are now empty

        let absent = cache.lookup(&cmd, Duration::from_secs(20)).unwrap();
        assert!(absent.is_none());
    }
}

/// This struct is the main API entry point for the `bkt` library, allowing callers to invoke and
/// cache subprocesses for later reuse.
pub struct Bkt {
    cache: Cache,
}

impl Bkt {
    /// Creates a new Bkt instance using the [`std::env::temp_dir`] as the cache location.
    pub fn in_tmp() -> Self {
        Bkt::create(std::env::temp_dir())
    }

    /// Creates a new Bkt instance.
    ///
    /// The given `root_dir` will be used as the parent directory of the cache. It's recommended
    /// this directory be in a tmpfs partition, and SSD, or similar so operations are fast.
    ///
    /// See `scoped()` for the effect of passing a non-None `scope` argument.
    pub fn create(root_dir: PathBuf) -> Self {
        // Note the cache is invalidated when the minor version changes
        // TODO use separate directories per user, like bash-cache
        // See https://stackoverflow.com/q/57951893/113632
        let cache_dir = root_dir
            .join(format!("bkt-{}.{}-cache", env!("CARGO_PKG_VERSION_MAJOR"), env!("CARGO_PKG_VERSION_MINOR")));
        // TODO remove this expect(), make factory functions return a Result<Bkt>.
        Bkt::restrict_dir(&cache_dir).expect("Failed to create cache dir");
        Bkt {
            cache: Cache::new(&cache_dir),
        }
    }

    /// Associates a scope with this Bkt instance, causing it to namespace its cache keys so that
    /// they do not collide with other instances using the same cache directory. This is useful when
    /// separate applications could potentially invoke the same commands but should not share a
    /// cache. Consider using the application's name, PID, and/or a timestamp in order to create a
    /// sufficiently unique namespace.
    pub fn scoped(&mut self, scope: String) -> &mut Self {
        self.cache.scoped(scope);
        self
    }

    #[cfg(not(unix))]
    fn restrict_dir(cache_dir: &Path) -> Result<()> { Ok(()) }
    #[cfg(unix)]
    fn restrict_dir(cache_dir: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if !cache_dir.exists() {
            std::fs::create_dir_all(cache_dir)?;
            let metadata = std::fs::metadata(cache_dir)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o700); // Only accessible to current user
            std::fs::set_permissions(cache_dir, permissions)?;
        }
        Ok(())
    }

    // TODO make this a From impl
    fn build_command(desc: &CommandDesc) -> Command {
        let mut command = Command::new(&desc.args[0]);
        command.args(&desc.args[1..]);
        if let Some(cwd) = &desc.cwd {
            command.current_dir(cwd);
        }
        if !desc.env.is_empty() {
            command.envs(&desc.env);
        }
        command
    }

    fn execute_subprocess(desc: &CommandDesc) -> Result<Invocation> {
        let mut cmd = Bkt::build_command(&desc);
        let start = Instant::now();
        // TODO write to stdout/stderr while running, rather than after the process completes?
        // See https://stackoverflow.com/q/66060139
        let result = cmd.output()
            .with_context(|| format!("Failed to run command {}", desc.args[0].to_string_lossy()))?;
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

    /// Looks up the given command in Bkt's cache, returning it, and its age, if found and newer
    /// than the given TTL.
    ///
    /// If stale or not found the command is executed and the result is cached and then returned.
    /// A zero-duration age will be returned if this invocation refreshed the cache. A background
    /// cleanup thread will also run on cache misses to remove stale data.
    // TODO better name than execute?
    pub fn execute(&self, command: &CommandDesc, ttl: Duration) -> Result<(Invocation, Duration)> {
        self._execute(command, ttl, true)
    }

    /// See the documentation on `execute()`. This functions like `execute()` but does not attempt
    /// to clean up stale data. Prefer this method if you decide to manage cleanup yourself via
    /// `cleanup_once()` or `cleanup_thread()`.
    pub fn execute_without_cleanup(&self, command: &CommandDesc, ttl: Duration) -> Result<(Invocation, Duration)> {
        self._execute(command, ttl, false)
    }

    fn _execute(&self, command: &CommandDesc, ttl: Duration, cleanup: bool) -> Result<(Invocation, Duration)> {
        let cached = self.cache.lookup(command, ttl)?;
        let result = match cached {
            Some((cached, mtime)) => (cached, mtime.elapsed()?),
            None => {
                let mut cleanup_hook = None;
                if cleanup {
                    // clean the cache in the background on a cache-miss; this will usually
                    // be much faster than the actual background process.
                    cleanup_hook = Some(self.cleanup_once());
                }
                let result = Bkt::execute_subprocess(command)?;
                self.cache.store(&result, ttl)?;
                if let Some(cleanup_hook) = cleanup_hook {
                    if let Err(e) = cleanup_hook.join().expect("cleanup thread panicked") {
                        eprintln!("bkt: cache cleanup failed: {:?}", e);
                    }
                }
                (result, Duration::default())
            }
        };
        Ok(result)
    }

    /// Unconditionally executes the given command and caches the invocation for the given TTL.
    /// This can be used to "warm" the cache so that subsequent calls to `execute` are fast.
    pub fn refresh(&self, command: &CommandDesc, ttl: Duration) -> Result<Invocation> {
        let result = Bkt::execute_subprocess(command)?;
        self.cache.store(&result, ttl)?;
        Ok(result)
    }

    /// Initiates a single cleanup cycle of the cache, removing stale data in the background. This
    /// should be invoked by short-lived applications early in their lifecycle and then joined
    /// before exiting. `execute_and_cleanup` can be used instead to only trigger a cleanup on a
    /// cache miss, avoiding the extra work on cache hits. Long-running applications should
    /// typically prefer `cleanup_thread` which triggers periodic cleanups.
    pub fn cleanup_once(&self) -> std::thread::JoinHandle<Result<()>> {
        let cache = self.cache.clone();
        std::thread::spawn(move || { cache.cleanup() })
    }

    /// Initiates an infinite-loop thread that triggers periodic cleanups of the cache, removing
    /// stale data in the background. It is not necessary to `join()` this thread, it will
    /// be terminated when the main thread exits.
    pub fn cleanup_thread(&self) -> std::thread::JoinHandle<()> {
        let cache = self.cache.clone();
        std::thread::spawn(move || {
            //  Hard-coded for now, could be made configurable if needed
            let poll_duration = Duration::from_secs(60);
            loop {
                if let Err(e) = cache.cleanup() {
                    eprintln!("Bkt: cache cleanup failed: {:?}", e);
                }
                std::thread::sleep(poll_duration);
            }
        })
    }
}

// Note: most functionality of Bkt is tested via cli.rs
#[cfg(test)]
mod bkt_tests {
    use super::*;
    use test_dir::{TestDir, DirBuilder, FileType};

    #[test]
    fn cached() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let cmd = CommandDesc::new(
            vec!("bash", "-c", "echo \"$RANDOM\" > \"${1:?}\"; cat \"${1:?}\"", "arg0", file.to_str().unwrap()));
        let bkt = Bkt::create(dir.path("cache"));
        let (first_inv, _) = bkt.execute(&cmd, Duration::from_secs(10)).unwrap();

        for _ in 1..3 {
            let (subsequent_inv, _) = bkt.execute(&cmd, Duration::from_secs(10)).unwrap();
            assert_eq!(first_inv, subsequent_inv);
        }
    }

    #[test]
    fn with_working_dir() {
        let dir = TestDir::temp().create("dir", FileType::Dir);
        let cwd = dir.path("dir");
        let cmd = CommandDesc::new(vec!("bash", "-c", "echo Hello World > file")).with_working_dir(&cwd);
        let bkt = Bkt::create(dir.path("cache"));
        let (result, _) = bkt.execute(&cmd, Duration::from_secs(10)).unwrap();
        assert_eq!(result.stderr_utf8(), "");
        assert_eq!(result.status, 0);
        assert_eq!(std::fs::read_to_string(cwd.join("file")).unwrap(), "Hello World\n");
    }

    #[test]
    fn with_env() {
        let dir = TestDir::temp().create("dir", FileType::Dir);
        let cmd = CommandDesc::new(vec!("bash", "-c", "echo \"FOO:${FOO:?}\"")).with_env_value("FOO", "bar");
        let bkt = Bkt::create(dir.path("cache"));
        let (result, _) = bkt.execute(&cmd, Duration::from_secs(10)).unwrap();
        assert_eq!(result.stderr_utf8(), "");
        assert_eq!(result.status, 0);
        assert_eq!(result.stdout_utf8(), "FOO:bar\n");
    }
}