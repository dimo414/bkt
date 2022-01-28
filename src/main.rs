use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, exit, Stdio};
use std::time::{Duration};

use anyhow::{Context, Result};
use clap::{AppSettings, Parser};

use bkt::{CommandDesc, Bkt};

// Re-invokes bkt with --force and then discards the subprocess, causing the cache
// to be refreshed asynchronously.
fn force_update_async() -> Result<()> {
    let mut args = std::env::args_os();
    let arg0 = args.next().expect("Must always be a 0th argument");
    let mut command = match std::env::current_exe() {
        Ok(path) => Command::new(path),
        Err(_) => Command::new(arg0),
    };
    // Discard stdout/err so the calling process doesn't wait for them to close.
    // Intentionally drop the returned Child; after this process exits the
    // child process will continue running in the background.
    command.arg("--force").args(args.filter(|a| a != "--warm"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().context("Failed to start background process")?;
    Ok(())
}

// Runs bkt after main() handles flag parsing
fn run(cli: Cli) -> Result<i32> {
    let ttl: Duration = cli.ttl.into();
    let stale: Option<Duration> = cli.stale.map(Into::into);

    assert!(!ttl.as_secs() > 0 || ttl.subsec_nanos() > 0, "--ttl cannot be zero"); // TODO use is_zero once stable
    if let Some(stale) = stale {
        assert!(!stale.as_secs() > 0 || stale.subsec_nanos() > 0, "--stale cannot be zero"); // TODO use is_zero once stable
        assert!(stale < ttl, "--stale must be less than --ttl");
    }

    let mut bkt = match cli.cache_dir {
        Some(cache_dir) => Bkt::create(cache_dir)?,
        None => Bkt::in_tmp()?,
    };
    bkt = bkt.discard_failures(cli.discard_failures);
    if let Some(scope) = cli.scope {
        bkt = bkt.scoped(scope);
    }

    let mut command = CommandDesc::new(cli.command);

    if cli.cwd {
        command = command.with_cwd()?;
    }

    let env_keys: BTreeSet<_> = cli.env.into_iter().flatten().collect();

    if !env_keys.is_empty() {
        let envs: BTreeMap<_, _> = std::env::vars_os()
            .filter(|(k, _)| env_keys.contains(k))
            .collect();
        command = command.with_envs(&envs);
    }

    if cli.warm && !cli.force {
        force_update_async()?;
        return Ok(0);
    }

    let (invocation, age) = if cli.force {
        (bkt.refresh(&command, ttl)?, Duration::from_secs(0))
    } else {
        bkt.retrieve(&command, ttl)?
    };

    if let Some(stale) = stale {
        if age > stale {
            force_update_async()?;
        }
    }

    io::stdout().write_all(invocation.stdout()).unwrap();
    io::stderr().write_all(invocation.stderr()).unwrap();
    Ok(invocation.exit_code())
}

#[derive(Parser)]
#[clap(setting = AppSettings::DeriveDisplayOrder)]
#[clap(about, version)]
struct Cli {
    /// The command to run
    #[clap(required = true, last = true)]
    command: Vec<OsString>,

    /// Duration the cached result will be valid for
    #[clap(long, default_value = "60s", visible_alias = "time-to-live")]
    ttl: humantime::Duration,

    /// Duration after which the result will be asynchronously refreshed
    #[clap(long, conflicts_with = "warm")]
    stale: Option<humantime::Duration>,

    /// Asynchronously execute and cache the given command, even if it's already cached
    #[clap(long)]
    warm: bool,

    /// Execute and cache the given command, even if it's already cached
    #[clap(long, conflicts_with = "warm")]
    force: bool,

    /// Includes the current working directory in the cache key,
    /// so that the same command run in different directories caches separately
    #[clap(long, visible_alias = "use-working-dir")]
    cwd: bool,

    /// Includes the given environment variable in the cache key,
    /// so that the same command run with different values for the given variables caches separately
    #[clap(long, visible_alias = "use-environment")]
    env: Option<Vec<OsString>>,

    /// Don't cache invocations that fail (non-zero exit code).
    /// USE CAUTION when passing this flag, as unexpected failures can lead to a spike in invocations
    /// which can exacerbate ongoing issues, effectively a DDoS.
    #[clap(long)]
    discard_failures: bool,

    /// If set, all cached data will be scoped to this value,
    /// preventing collisions with commands cached with different scopes
    #[clap(long)]
    scope: Option<String>,

    /// The directory under which to persist cached invocations;
    /// defaults to the system's temp directory.
    /// Setting this to a directory backed by RAM or an SSD, such as a tmpfs partition,
    /// will significantly reduce caching overhead.
    #[clap(long)]
    cache_dir: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    match run(cli) {
        Ok(code) => exit(code),
        Err(msg) => {
            eprintln!("bkt: {:#}", msg);
            exit(127);
        }
    }
}
