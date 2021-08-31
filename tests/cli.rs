use std::process::Command;

use test_dir::{TestDir, DirBuilder};
use std::path::Path;

// Bash scripts to pass to -c.
// Avoid depending on external programs.
const ECHO_RANDOM: &str = "echo \"$RANDOM\";";
const COUNT_INVOCATIONS: &str = "file=${1:?} lines=0;
                                 printf '%s' '.' >> \"$file\";\
                                 read < \"$file\";\
                                 printf '%s' \"${#REPLY}\";";
const PRINT_ARGS: &str = "args=(\"$@\"); declare -p args;";
const EXIT_WITH: &str = "exit \"${1:?}\";";
const SENSITIVE_OUTPUT: &str = "printf 'foo\\0bar'; printf 'bar\\0baz\\n' >&2";

fn bkt(cache_dir: &Path) -> Command {
    let test_exe = std::env::current_exe().expect("Could not resolve test location");
    let dir = test_exe
        .parent().expect("Could not resolve test directory")
        .parent().expect("Could not resolve binary directory");
    let mut path = dir.join("bkt");
    if !path.exists() {
        path.set_extension("exe");
    }
    assert!(path.exists(), "Could not find bkt binary in {:?}", dir);
    let mut bkt = Command::new(&path);
    bkt.arg(format!("--cache_dir={}", cache_dir.to_str().unwrap()));
    bkt
}

#[derive(Eq, PartialEq, Debug)]
struct CmdResult {
    out: String,
    err: String,
    status: Option<i32>,
}

fn run(cmd: &mut Command) -> CmdResult {
    let result = cmd.output().unwrap();
    CmdResult{
        out: std::str::from_utf8(&result.stdout).unwrap().into(),
        err: std::str::from_utf8(&result.stderr).unwrap().into(),
        status: result.status.code()
    }
}

fn succeed(cmd: &mut Command) -> String {
    let result = run(cmd);
    assert_eq!(result.err, "");
    assert_eq!(result.status, Some(0));
    result.out
}

#[test]
fn help() {
    let dir = TestDir::temp();
    let out = succeed(bkt(&dir.path("cache")).arg("--help"));
    assert!(out.contains("bkt [OPTIONS] [--] <command>..."));
}

#[test]
fn cached() {
    let dir = TestDir::temp();
    let args = vec!("--", "bash", "-c", ECHO_RANDOM);
    let first_result = run(bkt(&dir.path("cache")).args(&args));

    for _ in 1..3 {
        let subsequent_result = run(bkt(&dir.path("cache")).args(&args));
        assert_eq!(first_result, subsequent_result);
    }
}

#[test]
fn respects_cache_dir() {
    let dir = TestDir::temp();
    let file = dir.path("file").display().to_string();
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file);

    let first_call = succeed(bkt(&dir.path("cache")).args(&args));
    assert_eq!(first_call, "1");
    assert_eq!(first_call, succeed(bkt(&dir.path("cache")).args(&args)));

    let diff_cache = succeed(bkt(&dir.path("new-cache")).args(&args));
    assert_eq!(diff_cache, "2");
}

#[test]
fn respects_cache_scope() {
    let dir = TestDir::temp();
    let file = dir.path("file").display().to_string();
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file);

    let first_call = succeed(bkt(&dir.path("cache")).args(&args));
    assert_eq!(first_call, "1");
    assert_eq!(first_call, succeed(bkt(&dir.path("cache")).args(&args)));

    let diff_scope = succeed(bkt(&dir.path("cache"))
        .arg("--cache_scope=scope").args(&args));
    assert_eq!(diff_scope, "2");
    assert_eq!(diff_scope, succeed(bkt(&dir.path("cache"))
        .arg("--cache_scope=scope").args(&args)));
}

#[test]
fn respects_args() {
    let dir = TestDir::temp();
    let file = dir.path("file").display().to_string();
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file);

    let first_call = succeed(bkt(&dir.path("cache")).args(&args));
    assert_eq!(first_call, "1");
    assert_eq!(first_call, succeed(bkt(&dir.path("cache")).args(&args)));

    let diff_args = succeed(bkt(&dir.path("cache")).args(&args).arg("A B"));
    assert_eq!(diff_args, "2");

    let split_args = succeed(bkt(&dir.path("cache")).args(&args).args(vec!{"A", "B"}));
    assert_eq!(split_args, "3");
}

#[test]
fn no_debug_output() {
    let dir = TestDir::temp();
    let args = vec!("--", "bash", "-c", "true");

    // Not cached
    assert_eq!(run(bkt(&dir.path("cache")).args(&args)),
               CmdResult{out:"".into(),err:"".into(),status:Some(0)});
    // Cached
    assert_eq!(run(bkt(&dir.path("cache")).args(&args)),
               CmdResult{out:"".into(),err:"".into(),status:Some(0)});
}

#[test]
fn output_preserved() {
    let dir = TestDir::temp();
    fn same_output(dir: &TestDir, args: &[&str]) {
        let bkt_args = vec!("--", "bash", "-c", PRINT_ARGS, "arg0");
        // Second call will be cached
        assert_eq!(
            succeed(bkt(&dir.path("cache")).args(&bkt_args).args(args)),
            succeed(bkt(&dir.path("cache")).args(&bkt_args).args(args)));
    }
    same_output(&dir, &[]);
    same_output(&dir, &[""]);
    same_output(&dir, &["a", "b"]);
    same_output(&dir, &["a b"]);
    same_output(&dir, &["a b", "c"]);
}

#[test]
fn sensitive_output() {
    let dir = TestDir::temp();
    let args = vec!("--", "bash", "-c", SENSITIVE_OUTPUT);

    // Not cached
    let output = run(bkt(&dir.path("cache")).args(&args));
    assert_eq!(output,
               CmdResult{ out:"foo\u{0}bar".into(), err:"bar\u{0}baz\n".into(), status:Some(0) });
    // Cached
    assert_eq!(run(bkt(&dir.path("cache")).args(&args)),  output);
}

#[test]
fn exit_code_preserved() {
    let dir = TestDir::temp();
    let args = vec!("--", "bash", "-c", EXIT_WITH, "arg0");

    assert_eq!(run(bkt(&dir.path("cache")).args(&args).arg("14")).status, Some(14));
    assert_eq!(run(bkt(&dir.path("cache")).args(&args).arg("14")).status, Some(14));
}

// TODO
// respects env
// respects cwd
// refresh cache in background
// cache expires
// differing cache expirations
// concurrent calls race
// cleanup stale cache data
// warm cache
