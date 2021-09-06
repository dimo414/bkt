#[macro_use] extern crate clap;

use std::io::{self, Write};
use std::process::{Command, exit, Child};
use std::time::{Duration};

use anyhow::{Context, Result};
use clap::{Arg, App};

use bkt::{CommandDesc,Bkt};

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

struct AppState {
    bkt: Bkt,
    command: CommandDesc,
    ttl: Duration,
    stale: Option<Duration>,
    force_update: bool,
}

// Looks up a command in the cache, outputting its stdout/stderr if found. Otherwise executes
// the command and caches the invocation. An exit code that _attempts_ to reflect the subprocess'
// exit status is returned, or an error message if either the cache could not be accessed or the
// subprocess could not be run.
fn run(state: AppState) -> Result<i32> {
    assert!(!state.ttl.as_secs() > 0, "--ttl cannot be zero"); // TODO use is_zero once stable
    if let Some(stale) = state.stale {
        assert!(!stale.as_secs() > 0, "--stale cannot be zero"); // TODO use is_zero once stable
        assert!(stale < state.ttl, "--stale must be less than --ttl");
    }

    // Warm the cache and return; nothing should be written to out/err
    if state.force_update {
        state.bkt.refresh(&state.command, state.ttl)?;
        return Ok(0);
    }

    let (invocation, age) = state.bkt.execute(&state.command, state.ttl)?;

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
        // TODO add a public --warm flag
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
        bkt: Bkt::create(matches.value_of("cache_dir"), matches.value_of("cache_scope")),
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