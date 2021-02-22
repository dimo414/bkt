#[macro_use] extern crate clap;

use std::fmt;
use std::io::{self, Write, BufReader, ErrorKind, BufWriter};
use std::process::{Command, exit};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Arg, App};
use serde::{Serialize, Deserialize};
use std::hash::{Hash, Hasher};
use std::fs::File;

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
}

struct Cache {
    dir: PathBuf,
}

impl Cache {
    fn new(root_dir: Option<&str>, scope: Option<&str>) -> Cache {
        let mut dir = root_dir.map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        // Note the cache is invalidated when the minor version changes
        dir.push(format!(".bkt-{}.{}-cache", env!("CARGO_PKG_VERSION_MAJOR"), env!("CARGO_PKG_VERSION_MINOR")));
        if let Some(scope) = scope {
            dir.push(scope);
        }
        Cache{ dir }
    }

    #[cfg(not(feature = "debug"))]
    fn serialize<W, T>(writer: W, value: &T) -> Result<()> where W: io::Write, T: ?Sized + Serialize {
        Ok(bincode::serialize_into(writer, value)?)
    }

    #[cfg(feature = "debug")]
    fn serialize<W, T>(writer: W, value: &T) -> Result<()> where W: io::Write, T: ?Sized + Serialize {
        Ok(serde_json::to_writer(writer, value)?)
    }

    #[cfg(not(feature = "debug"))]
    fn deserialize<R, T>(reader: R) -> Result<T> where R: std::io::Read, T: serde::de::DeserializeOwned {
        Ok(bincode::deserialize_from(reader)?)
    }

    #[cfg(feature = "debug")]
    fn deserialize<R, T>(reader: R) -> Result<T> where R: std::io::Read, T: serde::de::DeserializeOwned {
        Ok(serde_json::from_reader(reader)?)
    }

    fn lookup(&self, command: &CommandDesc) -> Result<Option<Invocation>> {
        let file = File::open(self.dir.join(command.cache_key()));
        if let Err(ref e) = file {
            if e.kind() == ErrorKind::NotFound {
                return Ok(None);
            }
        }
        // Missing file is OK; other errors get propagated to the caller
        let reader = BufReader::new(file.context("Failed to access cache file")?);
        let found: Option<Invocation> = Cache::deserialize(reader).map(Some)?;
        // Discard data that happened to collide with the hash code
        if let Some(ref found) = found {
            if &found.command != command {
                return Ok(None);
            }
        }
        Ok(found)
    }

    fn store(&self, invocation: &Invocation) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let file = tempfile::NamedTempFile::new()?;
        Cache::serialize(BufWriter::new(&file), invocation)?;
        file.persist(self.dir.join(invocation.command.cache_key()))?;
        Ok(())
    }
}

fn execute_subprocess(command: CommandDesc) -> Result<Invocation> {
    // TODO write to stdout/stderr while running, rather than after the process completes
    // See https://stackoverflow.com/q/66060139
    let result = command.build_command().output()
        .with_context(|| format!("Failed to run command {}", command))?;
    Ok(Invocation {
        command,
        stdout: result.stdout,
        stderr: result.stderr,
        // TODO handle signals, see https://stackoverflow.com/q/66272686
        status: result.status.code().unwrap_or(126),
    })
}

struct AppState {
    cache: Cache,
    command: CommandDesc,
}

// Looks up a command in the cache, outputting its stdout/stderr if found. Otherwise executes
// the command and caches the invocation. An exit code that _attempts_ to reflect the subprocess'
// exit status is returned, or an error message if either the cache could not be accessed or the
// subprocess could not be run.
fn run(state: AppState) -> Result<i32> {
    let invocation = match state.cache.lookup(&state.command)? {
        Some(cached) => {
            // TODO TTL
            // TODO warm cache
            cached
        },
        None => {
            let result = execute_subprocess(state.command)?;
            state.cache.store(&result)?;
            result
        },
    };
    io::stdout().write_all(&invocation.stdout).unwrap();
    io::stderr().write_all(&invocation.stderr).unwrap();
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
        .arg(Arg::with_name("cache_dir")
            .long("cache_dir")
            .help("The directory under which to persist cached invocations; defaults to the system's temp directory"))
        .arg(Arg::with_name("cache_key")
            .long("cache_scope")
            .help("If set all cached data will be scoped to this value, preventing collisions with commands cached with different scopes"))
        .get_matches();

    let state = AppState {
        cache: Cache::new(matches.value_of("cache_dir"), matches.value_of("cache_scope")),
        command: CommandDesc::new(matches.values_of("command").expect("Required").collect::<Vec<_>>()),
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
