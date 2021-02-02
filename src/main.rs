#[macro_use] extern crate clap;

use std::io::{self, Write};
use clap::{Arg, App};
use std::process::{Command, exit};

fn main() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(Arg::with_name("command")
            .required(true)
            .multiple(true)
            .last(true)
            .help("The command to run"))
        .get_matches();

    let command: Vec<_> = matches.values_of("command").expect("Required").collect();

    if let Ok(result) = Command::new(&command[0]).args(&command[1..]).output() {
        io::stdout().write_all(&result.stdout).unwrap();
        io::stderr().write_all(&result.stderr).unwrap();
        exit(result.status.code().unwrap());
    }

    exit(127);
}
