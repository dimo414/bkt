#[macro_use] extern crate clap;

use std::fmt;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{self, Write, BufReader, ErrorKind, BufWriter};
use std::path::PathBuf;
use std::process::{Command, exit, Child};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use clap::{Arg, App};
use serde::{Serialize, Deserialize};

// See https://doc.rust-lang.org/std/fs/fn.soft_link.html
#[cfg(windows)]
use std::os::windows::fs::symlink_file as symlink;
#[cfg(unix)]
use std::os::unix::fs::symlink;

// Describes a command to be cached. Is used as the cache key.
#[derive(Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
struct CommandDesc {
    args: Vec<String>,
    // TODO cwd - https://doc.rust-lang.org/std/env/fn.current_dir.html
    // TODO env vars - https://doc.rust-lang.org/std/env/fn.var.html
}

impl CommandDesc {
    fn new<I, S>(command: I) -> CommandDesc where I: IntoIterator<Item = S>, S: Into<String> {
        CommandDesc {
            args: command.into_iter().map(Into::into).collect(),
        }
    }

    fn build_command(&self) -> Command {
        let mut command = Command::new(&self.args[0]);
        command.args(&self.args[1..]);
        command
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

#[derive(Serialize, Deserialize)]
struct Invocation {
    command: CommandDesc,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: i32,
    runtime: Duration, // TODO is this useful?
}

struct Cache {
    key_dir: PathBuf,
    data_dir: PathBuf,
}

impl Cache {
    fn new(root_dir: Option<&str>, scope: Option<&str>) -> Cache {
        let mut dir = root_dir.map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        // Note the cache is invalidated when the minor version changes
        dir.push(format!(".bkt-{}.{}-cache", env!("CARGO_PKG_VERSION_MAJOR"), env!("CARGO_PKG_VERSION_MINOR")));
        let mut key_dir = dir.clone();
        key_dir.push("keys");
        if let Some(scope) = scope {
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

fn execute_subprocess(command: CommandDesc) -> Result<Invocation> {
    let mut cmd = command.build_command();
    let start = Instant::now();
    // TODO write to stdout/stderr while running, rather than after the process completes
    // See https://stackoverflow.com/q/66060139
    let result = cmd.output()
        .with_context(|| format!("Failed to run command {}", command))?;
    let runtime = start.elapsed();
    Ok(Invocation {
        command,
        stdout: result.stdout,
        stderr: result.stderr,
        // TODO handle signals, see https://stackoverflow.com/q/66272686
        status: result.status.code().unwrap_or(126),
        runtime,
    })
}

fn force_background_update() -> Result<Child> {
    let mut args = std::env::args_os();
    let arg0 = args.next().expect("Must always be a 0th argument");
    let mut command = match std::env::current_exe() {
        Ok(path) => Command::new(path),
        Err(_) => Command::new(arg0),
    };
    command.arg("--force_update").args(args);
    command.spawn().context("Failed to start background process")
}

// TODO refactor most of this out to a Bkt struct in lib.rs, leaving just the CLI logic in a binary
// https://stackoverflow.com/a/26953326/113632
struct AppState {
    cache: Cache,
    command: CommandDesc,
    // TODO enforce that stale < ttl and both are non-zero
    ttl: Duration,
    stale: Option<Duration>,
    force_update: bool,
}

// Looks up a command in the cache, outputting its stdout/stderr if found. Otherwise executes
// the command and caches the invocation. An exit code that _attempts_ to reflect the subprocess'
// exit status is returned, or an error message if either the cache could not be accessed or the
// subprocess could not be run.
fn run(state: AppState) -> Result<i32> {
    // Warm the cache and return; nothing should be written to out/err
    if state.force_update {
        let result = execute_subprocess(state.command)?;
        state.cache.store(&result, &state.ttl)?;
        return Ok(0);
    }

    let cached = state.cache.lookup(&state.command, state.ttl)?;
    let (invocation, age) = match cached {
        Some((cached, mtime)) => (cached, mtime.elapsed()?),
        None => {
            let result = execute_subprocess(state.command)?;
            state.cache.store(&result, &state.ttl)?;
            (result, Duration::default())
        }
    };

    if let Some(stale) = state.stale {
        if age > stale {
            // Intentionally drop the returned Child; this process will exit momentarily and the
            // child process will continue running in the background.
            force_background_update()?;
        }
    }

    io::stdout().write_all(&invocation.stdout).unwrap();
    io::stderr().write_all(&invocation.stderr).unwrap();
    // TODO occasionally clean up cache dir, see https://crates.io/crates/walkdir
    Ok(invocation.status)
}

fn main() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(Arg::with_name("command")
            .required(true)
            .multiple(true)
            .last(true)
            .help("The command to run"))
        .arg(Arg::with_name("ttl")
            .long("time_to_live")
            .alias("ttl")
            .default_value("60s")
            .help("Duration the cached result will be valid"))
        .arg(Arg::with_name("stale")
            .long("stale")
            .takes_value(true)
            .help("Duration after which the cached result will be asynchronously refreshed"))
        .arg(Arg::with_name("cache_dir")
            .long("cache_dir")
            .takes_value(true)
            .help("The directory under which to persist cached invocations; defaults to the \
                   system's temp directory. Setting this to a directory backed by RAM or an SSD, \
                   such as a tmpfs partition, will significantly reduce caching overhead."))
        .arg(Arg::with_name("cache_scope")
            .long("cache_scope")
            .takes_value(true)
            .help("If set, all cached data will be scoped to this value, preventing collisions \
                   with commands cached with different scopes"))
        .arg(Arg::with_name("force_update")
            .long("force_update")
            .takes_value(false)
            .hidden(true))
        .get_matches();

    // https://github.com/clap-rs/clap/discussions/2453
    let stale = matches.value_of("stale")
        .map(|v|
            v.parse::<humantime::Duration>()
                .map_err(|v| ::clap::Error::value_validation_auto(
                    format!("The argument '{}' isn't a valid value", v)))
                .unwrap_or_else(|e| e.exit())
                .into());

    let state = AppState {
        cache: Cache::new(matches.value_of("cache_dir"), matches.value_of("cache_scope")),
        command: CommandDesc::new(matches.values_of("command").expect("Required").collect::<Vec<_>>()),
        ttl: value_t_or_exit!(matches.value_of("ttl"), humantime::Duration).into(),
        stale,
        force_update: matches.is_present("force_update"),
    };

    match run(state) {
        Ok(code) => exit(code),
        Err(msg) => {
            eprintln!("bkt: {:#}", msg);
            // TODO 127 is probably a better fallback code, using 128 for now to differentiate
            exit(128);
        },
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