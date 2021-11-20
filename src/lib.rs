//! `bkt` (pronounced "bucket") is a library for caching subprocess executions. It enables reuse of
//! expensive invocations across separate processes and supports synchronous and asynchronous
//! refreshing, TTLs, and other functionality. `bkt` is also a standalone binary for use by shell
//! scripts and other languages, see <https://github.com/dimo414/bkt> for binary details.
//!
//! ```no_run
//! # fn do_something(_: &str) {}
//! # fn main() -> anyhow::Result<()> {
//! # use std::time::Duration;
//! let bkt = bkt::Bkt::in_tmp()?;
//! let expensive_cmd = bkt::CommandDesc::new(["wget", "http://example.com"]);
//! let (result, age) = bkt.retrieve(&expensive_cmd, Duration::from_secs(3600))?;
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
use serde::de::DeserializeOwned;

#[cfg(feature="debug")]
macro_rules! debug_msg {
    ($($arg:tt)*) => { eprintln!("bkt: {}", format!($($arg)*)) }
}
#[cfg(not(feature="debug"))]
macro_rules! debug_msg {
    ($($arg:tt)*) => {  }
}

/// Describes a command to be executed and cached. This struct also serves as the cache key.
/// It consists of a command line invocation and, optionally, a working directory to execute in and
/// environment variables to set. When set these fields contribute to the cache key, therefore two
/// invocations with different working directories set will be cached separately.
///
/// ```
/// let cmd = bkt::CommandDesc::new(["echo", "Hello World!"]);
/// let with_cwd = bkt::CommandDesc::new(["ls"]).with_working_dir("/tmp");
/// let with_env = bkt::CommandDesc::new(["date"]).with_env_value("TZ", "America/New_York");
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
    /// let cmd = bkt::CommandDesc::new(["echo", "Hello World!"]);
    /// ```
    pub fn new<I, S>(command: I) -> Self where I: IntoIterator<Item=S>, S: Into<OsString> {
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
    /// let cmd = bkt::CommandDesc::new(["pwd"]).with_working_dir("/tmp");
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
    /// let cmd = bkt::CommandDesc::new(["pwd"]).with_cwd()?;
    /// # Ok(()) }
    /// ```
    pub fn with_cwd(self) -> Result<Self> {
        Ok(self.with_working_dir(std::env::current_dir()?))
    }

    /// Adds the given key/value pair to the environment the command should be run from, and causes
    /// this pair to be included in the cache key.
    ///
    /// ```
    /// let cmd = bkt::CommandDesc::new(["pwd"]).with_env_value("FOO", "bar");
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
    /// let cmd = bkt::CommandDesc::new(["date"]).with_env("TZ");
    /// ```
    pub fn with_env<K>(self, key: K) -> Self where K: AsRef<OsStr> {
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
    /// let cmd = bkt::CommandDesc::new(["..."]).with_envs(&important_envs);
    /// ```
    pub fn with_envs<I, K, V>(mut self, envs: I) -> Self
        where
            I: IntoIterator<Item=(K, V)>,
            K: AsRef<OsStr>,
            V: AsRef<OsStr>,
    {
        for (ref key, ref val) in envs {
            self.env.insert(key.as_ref().into(), val.as_ref().into());
        }
        self
    }
}

impl CacheKey for CommandDesc {
    fn debug_label(&self) -> Option<String> {
        Some(self.args.iter()
            .map(|a| a.to_string_lossy()).collect::<Vec<_>>().join("-")
            .chars()
            .map(|c| if c.is_whitespace() { '_' } else { c })
            .filter(|&c| c.is_alphanumeric() || c == '-' || c == '_')
            .take(100).collect())
    }
}

impl From<&CommandDesc> for std::process::Command {
    fn from(desc: &CommandDesc) -> Self {
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
}

#[cfg(test)]
mod cmd_tests {
    use super::*;

    #[test]
    fn debug_label() {
        assert_eq!(CommandDesc::new(["foo", "bar", "b&r _- a"]).debug_label(), Some("foo-bar-br__-_a".into()));
    }

    #[test]
    fn collisions() {
        let commands = [
            CommandDesc::new(["foo"]),
            CommandDesc::new(["foo", "bar"]),
            CommandDesc::new(["foo", "b", "ar"]),
            CommandDesc::new(["foo", "b ar"]),
            CommandDesc::new(["foo"]).with_working_dir("/bar"),
            CommandDesc::new(["foo"]).with_working_dir("/bar/baz"),
            CommandDesc::new(["foo"]).with_env_value("a", "b"),
            CommandDesc::new(["foo"]).with_working_dir("/bar").with_env_value("a", "b"),
        ];

        // https://old.reddit.com/r/rust/comments/2koptu/best_way_to_visit_all_pairs_in_a_vec/clnhxr5/
        let mut iter = commands.iter();
        for a in &commands {
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
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: i32,
    runtime: Duration,
}

impl Invocation {
    /// The data that the process wrote to stdout.
    pub fn stdout(&self) -> &[u8] { &self.stdout }

    /// Helper to view stdout as a UTF-8 string. Use [`from_utf8`](std::str::from_utf8) directly if
    /// you need to handle output that may not be UTF-8.
    pub fn stdout_utf8(&self) -> &str {
        std::str::from_utf8(&self.stdout).expect("stdout not valid UTF-8")
    }

    /// The data that the process wrote to stderr.
    pub fn stderr(&self) -> &[u8] { &self.stderr }

    /// Helper to view stderr as a UTF-8 string. Use [`from_utf8`](std::str::from_utf8) directly if
    /// you need to handle output that may not be UTF-8.
    pub fn stderr_utf8(&self) -> &str {
        std::str::from_utf8(&self.stderr).expect("stderr not valid UTF-8")
    }

    /// The exit code of the program, or 126 if the program terminated without an exit status.
    /// See [`ExitStatus::code()`](std::process::ExitStatus::code()). This is subject to change to
    /// better support other termination states.
    pub fn exit_code(&self) -> i32 { self.exit_code }

    /// The time the process took to complete.
    pub fn runtime(&self) -> Duration { self.runtime }
}

/// A file-lock mechanism that holds a lock by atomically creating a file in the given directory,
/// and deleting the file upon being dropped. Callers should beware that dropping is not guaranteed
/// (e.g. if the program panics). When a conflicting lock file is found its age (mtime) is checked
/// to detect stale locks leaked by a separate process that failed to properly drop its lock.
#[derive(Debug)]
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
                                        std::fs::read_to_string(&lock_file).unwrap_or_else(|_| "unknown".into()))));
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

/// Trait allowing a type to be used as a cache key. It would be nice to blanket-implement
/// this for all types that implement the dependent traits, but without a way for specific
/// impls to opt-out of the blanket that would prevent customizing the debug_label().
/// Specialization might resolve that issue, in the meantime it's fine since Cache is a
/// private type anyways.
trait CacheKey: std::fmt::Debug+Hash+PartialEq {
    /// Label is added to the cache key when run with the debug feature, useful for diagnostics.
    fn debug_label(&self) -> Option<String> { None }

    /// Generates a string sufficiently unique to describe the key; typically just the hex encoding
    /// of the key's hash code. Most impls should not need to override this.
    fn cache_key(&self) -> String {
        // The hash_map::DefaultHasher is somewhat underspecified, but it notes that "hashes should
        // not be relied upon over releases", which implies it is stable across multiple
        // invocations of the same build.... See cache_tests::stable_hash.
        let mut s = std::collections::hash_map::DefaultHasher::new();
        self.hash(&mut s);
        let hash = s.finish();
        if cfg!(feature = "debug") {
            if let Some(label) = self.debug_label() {
                if !label.is_empty() {
                    return format!("{}_{:016X}", label, hash);
                }
            }
        }
        format!("{:016X}", hash)
    }
}

/// Container for serialized key/value pairs.
#[derive(Serialize, Deserialize)]
struct CacheEntry<K, V> {
    key: K,
    value: V,
}

// See https://doc.rust-lang.org/std/fs/fn.soft_link.html
#[cfg(windows)]
fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(original: P, link: Q) -> Result<()> {
    std::os::windows::fs::symlink_file(original, link)
        .context("Windows prevents most programs from creating symlinks; see https://github.com/dimo414/bkt/issues/3")
}
#[cfg(unix)]
use std::os::unix::fs::symlink;

/// A file-system-backed cache for mapping keys (i.e. `CommandDesc`) to values (i.e. `Invocation`)
/// for a given duration.
// TODO make this a trait so we can swap out impls, namely an in-memory impl
#[derive(Clone, Debug)]
struct Cache {
    cache_dir: PathBuf,
    scope: Option<String>,
}

impl Cache {
    fn new<P: AsRef<Path>>(cache_dir: P) -> Self {
        Cache{ cache_dir: cache_dir.as_ref().into(), scope: None }
    }

    fn scoped(mut self, scope: String) -> Self {
        assert!(self.scope.is_none());
        self.scope = Some(scope);
        self
    }

    #[cfg(not(feature = "debug"))]
    fn serialize<W, T>(writer: W, value: &T) -> Result<()>
            where W: io::Write, T: Serialize + ?Sized {
        Ok(bincode::serialize_into(writer, value)?)
    }

    #[cfg(feature = "debug")]
    fn serialize<W, T>(writer: W, value: &T) -> Result<()>
            where W: io::Write, T: Serialize + ?Sized {
        Ok(serde_json::to_writer_pretty(writer, value)?)
    }

    #[cfg(not(feature = "debug"))]
    fn deserialize<R, T>(reader: R) -> Result<T>
            where R: std::io::Read, T: DeserializeOwned {
        Ok(bincode::deserialize_from(reader)?)
    }

    #[cfg(feature = "debug")]
    fn deserialize<R, T>(reader: R) -> Result<T>
            where R: std::io::Read, T: DeserializeOwned {
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

    /// Looks up the given key in the cache, returning the associated value and its age
    /// if the data is found and is newer than the max_age.
    fn lookup<K, V>(&self, key: &K, max_age: Duration) -> Result<Option<(V, SystemTime)>>
            where K: CacheKey+DeserializeOwned, V: DeserializeOwned {
        let path = self.key_path(&key.cache_key());
        let file = File::open(&path);
        if let Err(ref e) = file {
            if e.kind() == ErrorKind::NotFound {
                debug_msg!("lookup {} not found", path.display());
                return Ok(None);
            }
        }
        // Missing file is OK; other errors get propagated to the caller
        let reader = BufReader::new(file.context("Failed to access cache file")?);
        // TODO consider returning OK(None) if deserialization fails, which could happen if
        //      different types hashed to the same key
        let found: CacheEntry<K, V> = Cache::deserialize(reader)?;
        // Discard data that is too old
        let mtime = std::fs::metadata(&path)?.modified()?;
        let elapsed = mtime.elapsed();
        if elapsed.is_err() || elapsed.unwrap() > max_age {
            debug_msg!("lookup {} expired", path.display());
            std::fs::remove_file(&path).context("Failed to remove expired data")?;
            return Ok(None);
        }
        // Ignore false-positive hits that happened to collide with the hash code
        if &found.key != key {
            debug_msg!("lookup {} hash collision", path.display());
            return Ok(None);
        }
        debug_msg!("lookup {} found", path.display());
        Ok(Some((found.value, mtime)))
    }

    fn seconds_ceiling(duration: Duration) -> u64 {
        duration.as_secs() + if duration.subsec_nanos() != 0 { 1 } else { 0 }
    }

    // https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html#create-random-passwords-from-a-set-of-alphanumeric-characters
    fn rand_filename(dir: &Path, label: &str) -> PathBuf {
        use rand::{thread_rng, Rng};
        use rand::distributions::Alphanumeric;
        let rand_str: String = thread_rng().sample_iter(Alphanumeric).take(16).map(char::from).collect();
        dir.join(format!("{}.{}", label, rand_str))
    }

    /// Write the given key/value pair to the cache, persisting it for at least the given TTL.
    fn store<K, V>(&self, key: &K, value: &V, ttl: Duration) -> Result<()>
            where K: CacheKey+Serialize, V: Serialize {
        assert!(!ttl.as_secs() > 0 || ttl.subsec_nanos() > 0, "ttl cannot be zero"); // TODO use is_zero once stable
        let ttl_dir = self.data_dir().join(Cache::seconds_ceiling(ttl).to_string());
        std::fs::create_dir_all(&ttl_dir)?;
        std::fs::create_dir_all(&self.key_dir())?;
        let path = Cache::rand_filename(&ttl_dir, "data");
        // Note: this will fail if filename collides, could retry in a loop if that happens
        let file = OpenOptions::new().create_new(true).write(true).open(&path)?;
        let entry = CacheEntry{ key, value };
        Cache::serialize(BufWriter::new(&file), &entry).context("Serialization failed")?;
        debug_msg!("store data {}", path.display());
        // Roundabout approach to an atomic symlink replacement
        // https://github.com/dimo414/bash-cache/issues/26
        let tmp_symlink = Cache::rand_filename(&self.key_dir(), "tmp-symlink");
        // Note: this will fail if filename collides, could retry in a loop if that happens
        symlink(&path, &tmp_symlink)?;
        let key_path = self.key_path(&entry.key.cache_key());
        std::fs::rename(&tmp_symlink, &key_path)?;
        debug_msg!("store key {}", key_path.display());
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
                    debug_msg!("cleanup skip recent");
                    return Ok(());
                }
            }
            File::create(&last_attempt_file)?; // resets mtime if already exists

            // First delete stale data files
            debug_msg!("cleanup data {}", &self.data_dir().display());
            if let Ok(data_dir_iter) = std::fs::read_dir(&self.data_dir()) {
                for entry in data_dir_iter {
                    let ttl_dir = entry?.path();
                    let ttl = Duration::from_secs(
                        ttl_dir.file_name().and_then(|s| s.to_str()).and_then(|s| s.parse().ok())
                            .ok_or_else(|| Error::msg(format!("Invalid ttl directory {}", ttl_dir.display())))?);

                    for entry in std::fs::read_dir(&ttl_dir)? {
                        let file = entry?.path();
                        // Disregard errors on individual files; typically due to concurrent deletion
                        // or other changes we don't care about.
                        let _ = delete_stale_file(&file, ttl);
                    }
                }
            }

            // Then delete broken symlinks
            debug_msg!("cleanup keys {}", &self.key_dir().display());
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

    impl CacheKey for i32 {}
    impl CacheKey for String {
        fn debug_label(&self) -> Option<String> {
            Some(self.clone())
        }
    }

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
        let mut paths = vec![];
        contents(dir.as_ref(), &mut paths).unwrap();
        paths.iter().map(|p| p.strip_prefix(dir.as_ref()).unwrap().display().to_string()).collect()
    }

    // Sanity-checking that cache_key's behavior is stable over time. This test may need to be
    // updated when changing Rust versions / editions.
    #[test]
    fn stable_hash() {
        assert_eq!(100.cache_key(), "7D208C81E8236995");
        if cfg!(feature = "debug") {
            assert_eq!("FooBar".to_string().cache_key(), "FooBar_2C8878C07E3ADA57");
        } else {
            assert_eq!("FooBar".to_string().cache_key(), "2C8878C07E3ADA57");
        }
    }

    #[test]
    fn cache() {
        let dir = TestDir::temp();
        let key = "foo".to_string();
        let val = "A".to_string();
        let cache = Cache::new(&dir.root());

        let absent = cache.lookup::<_, String>(&key, Duration::from_secs(100)).unwrap();
        assert!(absent.is_none());

        cache.store(&key, &val, Duration::from_secs(100)).unwrap();
        let present = cache.lookup::<_, String>(&key, Duration::from_secs(100)).unwrap();
        assert_eq!(present.unwrap().0, "A");
    }

    #[test]
    fn lookup_ttls() {
        let dir = TestDir::temp();
        let key = "foo".to_string();
        let val = "A".to_string();
        let cache = Cache::new(&dir.root());

        cache.store(&key, &val, Duration::from_secs(5)).unwrap(); // store duration doesn't affect lookups
        make_dir_stale(dir.root(), Duration::from_secs(15)).unwrap();

        // data is still present until a cleanup iteration runs, or a lookup() invalidates it
        let present = cache.lookup::<_, String>(&key, Duration::from_secs(20)).unwrap();
        assert_eq!(present.unwrap().0, "A");
        // lookup() finds stale data, deletes it
        let absent = cache.lookup::<_, String>(&key, Duration::from_secs(10)).unwrap();
        assert!(absent.is_none());
        // now data is gone, even though this lookup() would have accepted it
        let absent = cache.lookup::<_, String>(&key, Duration::from_secs(20)).unwrap();
        assert!(absent.is_none());
    }

    #[test]
    fn scoped() {
        let dir = TestDir::temp();
        let key = "foo".to_string();
        let val_a = "A".to_string();
        let val_b = "B".to_string();
        let cache = Cache::new(&dir.root());
        let cache_scoped = Cache::new(&dir.root()).scoped("scope".into());

        cache.store(&key, &val_a, Duration::from_secs(100)).unwrap();
        cache_scoped.store(&key, &val_b, Duration::from_secs(100)).unwrap();

        let present = cache.lookup::<_, String>(&key, Duration::from_secs(20)).unwrap();
        assert_eq!(present.unwrap().0, "A");
        let present_scoped = cache_scoped.lookup::<_, String>(&key, Duration::from_secs(20)).unwrap();
        assert_eq!(present_scoped.unwrap().0, "B");
    }

    #[test]
    fn cleanup() {
        let dir = TestDir::temp();
        let key = "foo".to_string();
        let val = "A".to_string();
        let cache = Cache::new(&dir.root());

        cache.store(&key, &val, Duration::from_secs(5)).unwrap();
        make_dir_stale(dir.root(), Duration::from_secs(10)).unwrap();
        cache.cleanup().unwrap();

        assert_eq!(dir_contents(dir.root()), ["last_cleanup"]); // keys and data dirs are now empty

        let absent = cache.lookup::<_, String>(&key, Duration::from_secs(20)).unwrap();
        assert!(absent.is_none());
    }
}

/// This struct is the main API entry point for the `bkt` library, allowing callers to invoke and
/// cache subprocesses for later reuse.
#[derive(Clone, Debug)]
pub struct Bkt {
    cache: Cache,
    cleanup_on_refresh: bool,
    persist_failures: bool,
}

impl Bkt {
    fn temp_dir() -> PathBuf {
        std::env::var_os("BKT_TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir)
    }

    /// Creates a new Bkt instance using the [`std::env::temp_dir`] as the cache location. If a
    /// `BKT_TMPDIR` environment variable is set that value will be preferred.
    ///
    /// # Errors
    ///
    /// If preparing the tmp cache directory fails.
    pub fn in_tmp() -> Result<Self> {
        Bkt::create(Bkt::temp_dir())
    }

    /// Creates a new Bkt instance.
    ///
    /// The given `root_dir` will be used as the parent directory of the cache. It's recommended
    /// this directory be in a tmpfs partition, on an SSD, or similar, so operations are fast.
    ///
    /// # Errors
    ///
    /// If preparing the cache directory under `root_dir` fails.
    pub fn create(root_dir: PathBuf) -> Result<Self> {
        // Note the cache is invalidated when the minor version changes
        // TODO use separate directories per user, like bash-cache
        //      See https://stackoverflow.com/q/57951893/113632
        let cache_dir = root_dir
            .join(format!("bkt-{}.{}-cache", env!("CARGO_PKG_VERSION_MAJOR"), env!("CARGO_PKG_VERSION_MINOR")));
        Bkt::restrict_dir(&cache_dir)?;
        Ok(Bkt {
            cache: Cache::new(&cache_dir),
            cleanup_on_refresh: true,
            persist_failures: true,
        })
    }

    /// Associates a scope with this Bkt instance, causing it to namespace its cache keys so that
    /// they do not collide with other instances using the same cache directory. This is useful when
    /// separate applications could potentially invoke the same commands but should not share a
    /// cache. Consider using the application's name, PID, and/or a timestamp in order to create a
    /// sufficiently unique namespace.
    pub fn scoped(mut self, scope: String) -> Self {
        self.cache = self.cache.scoped(scope);
        self
    }

    /// By default a background cleanup thread runs on cache misses and calls to [`Bkt::refresh()`]
    /// to remove stale data. You may prefer to manage cleanup yourself if you expect frequent cache
    /// misses and want to minimize the number of threads being created. See [`Bkt::cleanup_once()`]
    /// and [`Bkt::cleanup_thread()`] if you set this to `false`.
    pub fn cleanup_on_refresh(mut self, cleanup: bool) -> Self {
        self.cleanup_on_refresh = cleanup;
        self
    }

    /// Configures this instance to not cache invocations that return non-zero exit codes. This only
    /// affects _writing_ to the cache; if a failed invocation has already been cached (e.g. by a
    /// different instance) that data will still be used until it expires.
    ///
    /// **WARNING:** use this function with caution. Discarding invocations that fail can overload
    /// downstream resources that were protected by the caching layer limiting QPS. For example,
    /// if a website is rejecting a fraction of requests to shed load and then clients start
    /// sending _more_ requests when their attempts fail the website could be taken down outright by
    /// the added load. In other words, using this function can lead to accidental DDoSes.
    pub fn discard_failures(mut self, discard_failures: bool) -> Self {
        // Flip the boolean here to make the conditional in retrieve() clearer
        self.persist_failures = !discard_failures;
        self
    }

    #[cfg(not(unix))]
    fn restrict_dir(_cache_dir: &Path) -> Result<()> { Ok(()) }
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

    fn execute_subprocess(desc: &CommandDesc) -> Result<Invocation> {
        let mut cmd: std::process::Command = desc.into();
        let start = Instant::now();
        // TODO write to stdout/stderr while running, rather than after the process completes?
        // See https://stackoverflow.com/q/66060139
        let result = cmd.output()
            .with_context(|| format!("Failed to run command {}", desc.args[0].to_string_lossy()))?;
        let runtime = start.elapsed();
        Ok(Invocation {
            stdout: result.stdout,
            stderr: result.stderr,
            // TODO handle signals, see https://stackoverflow.com/q/66272686
            exit_code: result.status.code().unwrap_or(126),
            runtime,
        })
    }

    /// Looks up the given command in Bkt's cache, returning it, and its age, if found and newer
    /// than the given TTL.
    ///
    /// If stale or not found the command is executed and the result is cached and then returned.
    /// A zero-duration age will be returned if this invocation refreshed the cache.
    ///
    /// # Errors
    ///
    /// If looking up, deserializing, executing, or serializing the command fails. This generally
    /// reflects a user error such as an invalid command.
    // TODO per C-CALLER-CONTROL perhaps this should consume the CommandDesc rather than cloning it
    //     in execute_subprocess(). See https://rust-lang.github.io/api-guidelines/flexibility.html
    //     See also C-BUILDER in https://rust-lang.github.io/api-guidelines/type-safety.html
    pub fn retrieve(&self, command: &CommandDesc, ttl: Duration) -> Result<(Invocation, Duration)> {
        let cached = self.cache.lookup(command, ttl).context("Cache lookup failed")?;
        let result = match cached {
            Some((cached, mtime)) => (cached, mtime.elapsed()?),
            None => {
                let cleanup_hook = self.maybe_cleanup_once();
                let result = Bkt::execute_subprocess(command).context("Subprocess execution failed")?;
                if self.persist_failures || result.exit_code == 0 {
                    self.cache.store(command, &result, ttl).context("Cache write failed")?;
                }
                Bkt::join_cleanup_thread(cleanup_hook);
                (result, Duration::default())
            }
        };
        Ok(result)
    }

    /// Unconditionally executes the given command and caches the invocation for the given TTL.
    /// This can be used to "warm" the cache so that subsequent calls to `execute` are fast.
    ///
    /// # Errors
    ///
    /// If executing or serializing the command fails. This generally reflects a user error such as
    /// an invalid command.
    pub fn refresh(&self, command: &CommandDesc, ttl: Duration) -> Result<Invocation> {
        let cleanup_hook = self.maybe_cleanup_once();
        let result = Bkt::execute_subprocess(command).context("Subprocess execution failed")?;
        if self.persist_failures || result.exit_code == 0 {
            self.cache.store(command, &result, ttl).context("Cache write failed")?;
        }
        Bkt::join_cleanup_thread(cleanup_hook);
        Ok(result)
    }

    /// Clean the cache in the background on a cache-miss; this will usually
    /// be much faster than the actual background process.
    fn maybe_cleanup_once(&self) -> Option<std::thread::JoinHandle<Result<()>>> {
        if self.cleanup_on_refresh {
            Some(self.cleanup_once())
        } else {
            None
        }
    }

    fn join_cleanup_thread(cleanup_hook: Option<std::thread::JoinHandle<Result<()>>>) {
        if let Some(cleanup_hook) = cleanup_hook {
            if let Err(e) = cleanup_hook.join().expect("cleanup thread panicked") {
                eprintln!("bkt: cache cleanup failed: {:?}", e);
            }
        }
    }

    /// Initiates a single cleanup cycle of the cache, removing stale data in the background. This
    /// should be invoked by short-lived applications early in their lifecycle and then joined
    /// before exiting. `execute_and_cleanup` can be used instead to only trigger a cleanup on a
    /// cache miss, avoiding the extra work on cache hits. Long-running applications should
    /// typically prefer `cleanup_thread` which triggers periodic cleanups.
    ///
    /// # Errors
    ///
    /// The Result returned by joining indicates whether there were any unexpected errors while
    /// cleaning up. It should be Ok in all normal circumstances.
    // TODO if cleanup should always succeed (or no-op) why return Result?
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

    // Just validating that Bkt can be cloned to create siblings with different settings.
    #[test]
    #[allow(clippy::redundant_clone)]
    fn cloneable() {
        let dir = TestDir::temp();
        let bkt = Bkt::create(dir.path("cache")).unwrap();
        let _scoped = bkt.clone().scoped("scope".into());
        let _no_cleanup = bkt.clone().cleanup_on_refresh(false);
    }

    #[test]
    fn cached() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let cmd = CommandDesc::new(
            ["bash", "-c", r#"echo "$RANDOM" > "${1:?}"; cat "${1:?}""#, "arg0", file.to_str().unwrap()]);
        let bkt = Bkt::create(dir.path("cache")).unwrap();
        let (first_inv, _) = bkt.retrieve(&cmd, Duration::from_secs(10)).unwrap();

        for _ in 1..3 {
            let (subsequent_inv, _) = bkt.retrieve(&cmd, Duration::from_secs(10)).unwrap();
            assert_eq!(first_inv, subsequent_inv);
        }
    }

    #[test]
    fn discard_failures() {
        let dir = TestDir::temp();
        let output = dir.path("output");
        let code = dir.path("code");

        let cmd = CommandDesc::new(
            ["bash", "-c", r#"cat "${1:?}"; exit "$(< "${2:?}")""#, "arg0", output.to_str().unwrap(), code.to_str().unwrap()]);
        let bkt = Bkt::create(dir.path("cache")).unwrap().discard_failures(true);

        write!(File::create(&output).unwrap(), "A").unwrap();
        write!(File::create(&code).unwrap(), "10").unwrap();
        let (first_inv, _) = bkt.retrieve(&cmd, Duration::from_secs(10)).unwrap();
        assert_eq!(first_inv.exit_code, 10, "{:?}\nstderr:{}", first_inv, first_inv.stderr_utf8());
        assert_eq!(first_inv.stdout_utf8(), "A");

        write!(File::create(&output).unwrap(), "B").unwrap();
        let (subsequent_inv, _) = bkt.retrieve(&cmd, Duration::from_secs(10)).unwrap();
        // call is not cached
        assert_eq!(subsequent_inv.stdout_utf8(), "B");

        write!(File::create(&output).unwrap(), "C").unwrap();
        write!(File::create(&code).unwrap(), "0").unwrap();
        let (success_inv, _) = bkt.retrieve(&cmd, Duration::from_secs(10)).unwrap();
        assert_eq!(success_inv.exit_code, 0);
        assert_eq!(success_inv.stdout_utf8(), "C");

        write!(File::create(&output).unwrap(), "D").unwrap();
        let (cached_inv, _) = bkt.retrieve(&cmd, Duration::from_secs(10)).unwrap();
        assert_eq!(success_inv, cached_inv);
    }

    #[test]
    fn with_working_dir() {
        let dir = TestDir::temp().create("dir", FileType::Dir);
        let cwd = dir.path("dir");
        let cmd = CommandDesc::new(["bash", "-c", "echo Hello World > file"]).with_working_dir(&cwd);
        let bkt = Bkt::create(dir.path("cache")).unwrap();
        let (result, _) = bkt.retrieve(&cmd, Duration::from_secs(10)).unwrap();
        assert_eq!(result.stderr_utf8(), "");
        assert_eq!(result.exit_code(), 0);
        assert_eq!(std::fs::read_to_string(cwd.join("file")).unwrap(), "Hello World\n");
    }

    #[test]
    // TODO the JSON serializer doesn't support OsString keys, CommandDesc needs a custom Serializer
    //      (for feature="debug", at least) - see https://stackoverflow.com/q/51276896/113632 and
    //      https://github.com/serde-rs/json/issues/809
    #[cfg(not(feature = "debug"))]
    fn with_env() {
        let dir = TestDir::temp().create("dir", FileType::Dir);
        let cmd = CommandDesc::new(["bash", "-c", r#"echo "FOO:${FOO:?}""#]).with_env_value("FOO", "bar");
        let bkt = Bkt::create(dir.path("cache")).unwrap();
        let (result, _) = bkt.retrieve(&cmd, Duration::from_secs(10)).unwrap();
        assert_eq!(result.stderr_utf8(), "");
        assert_eq!(result.exit_code(), 0);
        assert_eq!(result.stdout_utf8(), "FOO:bar\n");
    }
}
