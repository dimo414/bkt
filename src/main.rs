#[macro_use] extern crate clap;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, exit, Stdio};
use std::time::{Duration};

use anyhow::{Context, Result};
use clap::{Arg, App};

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
    command.arg("--force").args(args)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().context("Failed to start background process")?;
    Ok(())
}

// Runs bkt after main() handles flag parsing
fn run(bkt: Bkt, mut command: CommandDesc, use_cwd: bool, env_keys: BTreeSet<&OsStr>,
       ttl: Duration, stale: Option<Duration>, warm: bool, force: bool) -> Result<i32> {
    assert!(!ttl.as_secs() > 0, "--ttl cannot be zero"); // TODO use is_zero once stable
    if let Some(stale) = stale {
        assert!(!stale.as_secs() > 0, "--stale cannot be zero"); // TODO use is_zero once stable
        assert!(stale < ttl, "--stale must be less than --ttl");
    }

    if use_cwd {
        command = command.with_cwd()?;
    }
    if !env_keys.is_empty() {
        let envs: BTreeMap<_,_> = std::env::vars_os()
            // `as &OsStr` required per https://stackoverflow.com/q/65549983/113632
            .filter(|(k,_)| env_keys.contains(&k as &OsStr)).collect();
        command = command.with_envs(&envs);
    }

    if warm && !force {
        force_update_async()?;
        return Ok(0);
    }

    let (invocation, age) = if force {
        (bkt.refresh(&command, ttl)?, Duration::from_secs(0))
    } else {
        bkt.execute_and_cleanup(&command, ttl)?
    };

    if let Some(stale) = stale {
        if age > stale {
            force_update_async()?;
        }
    }

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
        .arg(Arg::with_name("ttl")
            .long("time_to_live")
            .alias("ttl")
            .default_value("60s")
            .help("Duration the cached result will be valid"))
        .arg(Arg::with_name("stale")
            .long("stale")
            .takes_value(true)
            .help("Duration after which the cached result will be asynchronously refreshed"))
        .arg(Arg::with_name("warm")
            .long("warm")
            .takes_value(false)
            .help("Asynchronously execute and cache the given command, even if it's already cached"))
        .arg(Arg::with_name("force")
            .long("force")
            .takes_value(false)
            .help("Execute and cache the given command, even if it's already cached"))
        .arg(Arg::with_name("cwd")
            .long("use_working_dir")
            .alias("cwd")
            .takes_value(false)
            .help("Includes the current working directory in the cache key, so that the same \
                   command run in different directories caches separately."))
        .arg(Arg::with_name("env")
            .long("use_environment")
            .alias("env")
            .takes_value(true)
            .multiple(true)
            .help("Includes the given environment variable in the cache key, so that the same \
                   command run with different values for the given variables caches separately."))
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
        .get_matches();

    let bkt = Bkt::create(matches.value_of("cache_dir").map(PathBuf::from),
                          matches.value_of("cache_scope"));
    let command = CommandDesc::new(matches.values_of_os("command").expect("Required").collect::<Vec<_>>());
    let use_cwd = matches.is_present("cwd");
    let env = matches.values_of_os("env").map(|e| e.collect()).unwrap_or_else(BTreeSet::new);
    let ttl = value_t_or_exit!(matches.value_of("ttl"), humantime::Duration).into();

    // https://github.com/clap-rs/clap/discussions/2453
    let stale = matches.value_of("stale")
        .map(|v|
            v.parse::<humantime::Duration>()
                .map_err(|v| ::clap::Error::value_validation_auto(
                    format!("The argument '{}' isn't a valid value", v)))
                .unwrap_or_else(|e| e.exit())
                .into());
    let warm = matches.is_present("warm");

    let force = matches.is_present("force");

    match run(bkt, command, use_cwd, env, ttl, stale, warm, force) {
        Ok(code) => exit(code),
        Err(msg) => {
            eprintln!("bkt: {:#}", msg);
            // TODO 127 is probably a better fallback code, using 128 for now to differentiate
            exit(128);
        },
    }
}