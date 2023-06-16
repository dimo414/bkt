// Demo of streaming the out/err of a subprocess as it executes.
// See also https://stackoverflow.com/a/72862682/113632 and #31

use std::io::{Read, Write};
use std::process::{Command, Stdio};

static BASH_CMD: &str =
    "echo START; date >&2
    sleep 1
    printf MID
    sleep 1
    echo DLE; date >&2
    sleep 3
    echo DONE; date >&2";

fn stream(
    mut source: impl Read,
    mut sink: impl Write,
) -> std::io::Result<()> {
    // This initialization can be avoided (safely) once
    // https://github.com/rust-lang/rust/issues/78485 is stable.
    let mut buf = [0u8; 1024];
    loop {
        let num_read = source.read(&mut buf)?;
        if num_read == 0 {
            break;
        }

        let buf = &buf[..num_read];
        sink.write_all(buf)?;
        // flush is needed to print partial lines, otherwise output is buffered until a newline
        sink.flush()?;
    }

    Ok(())
}

fn main() {
    let mut child = Command::new("bash").args(&["-c", BASH_CMD])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to execute child");

    let child_out = child.stdout.take().expect("cannot attach to child stdout");
    let child_err = child.stderr.take().expect("cannot attach to child stderr");

    let thread_out = std::thread::spawn(move || {
        stream(child_out, std::io::stdout())
            .expect("error communicating with child stdout")
    });
    let thread_err = std::thread::spawn(move || {
        stream(child_err, std::io::stderr()).expect("error communicating with child stderr")
    });

    thread_out.join().expect("child stdout thread failed to join");
    thread_err.join().expect("child stderr thread failed to join");

    let status = child.wait().expect("Subprocess wait failed");
    assert!(status.success(), "Subprocess failed");
}