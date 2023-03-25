use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, exit, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;

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

    assert!(!ttl.is_zero(), "--ttl cannot be zero");
    if let Some(stale) = stale {
        assert!(!stale.is_zero(), "--stale cannot be zero");
        assert!(stale < ttl, "--stale must be less than --ttl");
    }

    let mut bkt = match cli.cache_dir {
        Some(cache_dir) => Bkt::create(cache_dir)?,
        None => Bkt::in_tmp()?,
    };
    if let Some(scope) = cli.scope {
        bkt = bkt.scoped(scope);
    }

    let mut command = CommandDesc::new(cli.command);

    if cli.cwd {
        command = command.with_cwd();
    }

    let envs = cli.env;
    if !envs.is_empty() {
        command = command.with_envs(&envs);
    }

    let files = cli.modtime;
    if !files.is_empty() {
        command = command.with_modtimes(&files);
    }

    if cli.discard_failures {
        command = command.with_discard_failures(true);
    }

    if cli.warm && !cli.force {
        force_update_async()?;
        return Ok(0);
    }

    let invocation = if cli.force {
        bkt.refresh(&command, ttl)?.0
    } else {
        let (invocation, status) = bkt.retrieve(&command, ttl)?;
        if let Some(stale) = stale {
            if let bkt::CacheStatus::Hit(cached_at) = status {
                if (Instant::now() - cached_at) > stale {
                    force_update_async()?;
                }
            }
        }
        invocation
    };

    // BrokenPipe errors are uninteresting for command line applications; just stop writing to that
    // descriptor and, if appropriate, exit. Rust doesn't have good support for this presently, see
    // https://github.com/rust-lang/rust/issues/46016
    fn disregard_broken_pipe(result: std::io::Result<()>) -> std::io::Result<()> {
        use std::io::ErrorKind::*;
        if let Err(e) = &result {
            if let BrokenPipe = e.kind() {
                return Ok(());
            }
        }
        result
    }

    disregard_broken_pipe(io::stdout().write_all(invocation.stdout()))
        .context("error writing to stdout")?;
    disregard_broken_pipe(io::stderr().write_all(invocation.stderr()))
        .context("error writing to stderr")?;
    Ok(invocation.exit_code())
}

#[derive(Debug, Parser)]
#[command(about, version)]
struct Cli {
    /// The command to run
    #[arg(required = true, last = true)]
    command: Vec<OsString>,

    /// Duration the cached result will be valid for
    #[arg(long, value_name = "DURATION", default_value = "60s", visible_alias = "time-to-live", env = "BKT_TTL")]
    ttl: humantime::Duration,

    /// Duration after which the result will be asynchronously refreshed
    #[arg(long, value_name = "DURATION", conflicts_with = "warm")]
    stale: Option<humantime::Duration>,

    /// Asynchronously execute and cache the given command, even if it's already cached
    #[arg(long)]
    warm: bool,

    /// Execute and cache the given command, even if it's already cached
    #[arg(long, conflicts_with = "warm")]
    force: bool,

    /// Includes the current working directory in the cache key,
    /// so that the same command run in different directories caches separately
    #[arg(long, visible_alias = "use-working-dir")]
    cwd: bool,

    /// Includes the given environment variable in the cache key,
    /// so that the same command run with different values for the given variables caches separately
    #[arg(long, value_name = "NAME", visible_alias = "use-environment")]
    env: Vec<OsString>,

    /// Includes the last modification time of the given file(s) in the cache key,
    /// so that the same command run with different modtimes for the given files caches separately
    #[arg(long, value_name = "FILE", visible_alias = "use-file-modtime")]
    modtime: Vec<OsString>,

    /// Don't cache invocations that fail (non-zero exit code).
    /// USE CAUTION when passing this flag, as unexpected failures can lead to a spike in invocations
    /// which can exacerbate ongoing issues, effectively a DDoS.
    #[arg(long)]
    discard_failures: bool,

    /// If set, all cached data will be scoped to this value,
    /// preventing collisions with commands cached with different scopes
    #[arg(long, value_name = "NAME", env = "BKT_SCOPE")]
    scope: Option<String>,

    /// The directory under which to persist cached invocations;
    /// defaults to the system's temp directory.
    /// Setting this to a directory backed by RAM or an SSD, such as a tmpfs partition,
    /// will significantly reduce caching overhead.
    #[arg(long, value_name = "DIR", env = "BKT_CACHE_DIR")]
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
