use std::process::Command;

use test_dir::{TestDir, DirBuilder, FileType};
use std::path::Path;
use std::time::{SystemTime, Duration};

use anyhow::Result;

// Bash scripts to pass to -c.
// Avoid depending on external programs.
const COUNT_INVOCATIONS: &str = "file=${1:?} lines=0;
                                 printf '%s' '.' >> \"$file\";\
                                 read < \"$file\";\
                                 printf '%s' \"${#REPLY}\";";
const PRINT_ARGS: &str = "args=(\"$@\"); declare -p args;";
const EXIT_WITH: &str = "exit \"${1:?}\";";

fn bkt<P: AsRef<Path>>(cache_dir: P) -> Command {
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
    bkt.arg(format!("--cache_dir={}", cache_dir.as_ref().display()));
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

fn modtime<P: AsRef<Path>>(path: P) -> SystemTime {
    std::fs::metadata(path).expect("No metadata").modified().expect("No modtime")
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

#[test]
fn help() {
    let dir = TestDir::temp();
    let out = succeed(bkt(dir.path("cache")).arg("--help"));
    assert!(out.contains("bkt [FLAGS] [OPTIONS] [--] <command>..."));
}

#[test]
fn cached() {
    let dir = TestDir::temp();
    let file = dir.path("file").display().to_string();
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file);
    let first_result = run(bkt(dir.path("cache")).args(&args));

    for _ in 1..3 {
        let subsequent_result = run(bkt(dir.path("cache")).args(&args));
        assert_eq!(first_result, subsequent_result);
    }
}

#[test]
fn cache_expires() {
    let dir = TestDir::temp();
    let file = dir.path("file").display().to_string();
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file);
    let first_result = succeed(bkt(dir.path("cache")).args(&args));
    assert_eq!(first_result, "1");

    let subsequent_result = succeed(bkt(dir.path("cache")).args(&args));
    assert_eq!(first_result, subsequent_result);

    make_dir_stale(dir.path("cache"), Duration::from_secs(120)).unwrap();
    let after_stale_result = succeed(bkt(dir.path("cache")).args(&args));
    assert_eq!(after_stale_result, "2");
}

#[test]
fn cache_expires_separately() {
    let dir = TestDir::temp();
    let file1 = dir.path("file1").display().to_string();
    let file2 = dir.path("file2").display().to_string();
    let args1 = vec!("--ttl=10s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file1);
    let args2 = vec!("--ttl=20s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file2);

    // first invocation
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args1)), "1");
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args2)), "1");

    // second invocation, cached
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args1)), "1");
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args2)), "1");

    // only shorter TTL is invalidated
    make_dir_stale(dir.path("cache"), Duration::from_secs(15)).unwrap();
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args1)), "2");
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args2)), "1");
}

#[test]
fn cache_hits_with_different_settings() {
    let dir = TestDir::temp();
    let file = dir.path("file1").display().to_string();
    let args1 = vec!("--ttl=10s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file);
    let args2 = vec!("--ttl=20s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file);

    // despite different TTLs the invocation is still cached
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args1)), "1");
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args2)), "1");

    // the provided TTL is respected, though it was cached with a smaller TTL
    make_dir_stale(dir.path("cache"), Duration::from_secs(15)).unwrap();
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args2)), "1");
    // TODO however the cache may be invalidated in the background using the older TTL
}

#[test]
fn cache_refreshes_in_background() {
    let dir = TestDir::temp();
    let file = dir.path("file");
    let file_str = file.display().to_string();
    let args = vec!("--stale=10s", "--ttl=20s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file_str);
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args)), "1");

    let last_mod = modtime(&file);
    make_dir_stale(dir.path("cache"), Duration::from_secs(15)).unwrap();
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args)), "1");

    for _ in 1..10 {
        if modtime(&file) > last_mod { break; }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(modtime(&file) > last_mod);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "..");
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args)), "2");
}

#[test]
fn respects_cache_dir() {
    let dir = TestDir::temp();
    let file = dir.path("file").display().to_string();
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file);

    let first_call = succeed(bkt(dir.path("cache")).args(&args));
    assert_eq!(first_call, "1");
    assert_eq!(first_call, succeed(bkt(dir.path("cache")).args(&args)));

    let diff_cache = succeed(bkt(dir.path("new-cache")).args(&args));
    assert_eq!(diff_cache, "2");
}

#[test]
fn respects_cache_scope() {
    let dir = TestDir::temp();
    let file = dir.path("file").display().to_string();
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file);

    let first_call = succeed(bkt(dir.path("cache")).args(&args));
    assert_eq!(first_call, "1");
    assert_eq!(first_call, succeed(bkt(dir.path("cache")).args(&args)));

    let diff_scope = succeed(bkt(dir.path("cache"))
        .arg("--cache_scope=scope").args(&args));
    assert_eq!(diff_scope, "2");
    assert_eq!(diff_scope, succeed(bkt(dir.path("cache"))
        .arg("--cache_scope=scope").args(&args)));
}

#[test]
fn respects_args() {
    let dir = TestDir::temp();
    let file = dir.path("file").display().to_string();
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", &file);

    let first_call = succeed(bkt(dir.path("cache")).args(&args));
    assert_eq!(first_call, "1");
    assert_eq!(first_call, succeed(bkt(dir.path("cache")).args(&args)));

    let diff_args = succeed(bkt(dir.path("cache")).args(&args).arg("A B"));
    assert_eq!(diff_args, "2");

    let split_args = succeed(bkt(dir.path("cache")).args(&args).args(vec!{"A", "B"}));
    assert_eq!(split_args, "3");
}

#[test]
fn respects_cwd() {
    let dir = TestDir::temp()
        .create("dir1", FileType::Dir)
        .create("dir2", FileType::Dir);
    let args = vec!("--", "bash", "-c", "pwd");
    let cwd_args = vec!("--cwd", "--", "bash", "-c", "pwd");

    let without_cwd_dir1 = succeed(bkt(dir.path("cache")).args(&args).current_dir(dir.path("dir1")));
    let without_cwd_dir2 = succeed(bkt(dir.path("cache")).args(&args).current_dir(dir.path("dir2")));
    assert!(without_cwd_dir1.trim().ends_with("/dir1"));
    assert!(without_cwd_dir2.trim().ends_with("/dir1")); // incorrect! cached too eagerly

    let cwd_dir1 = succeed(bkt(dir.path("cache")).args(&cwd_args).current_dir(dir.path("dir1")));
    let cwd_dir2 = succeed(bkt(dir.path("cache")).args(&cwd_args).current_dir(dir.path("dir2")));
    assert!(cwd_dir1.trim().ends_with("/dir1"));
    assert!(cwd_dir2.trim().ends_with("/dir2"));
}

#[test]
fn no_debug_output() {
    let dir = TestDir::temp();
    let args = vec!("--", "bash", "-c", "true");

    // Not cached
    assert_eq!(run(bkt(dir.path("cache")).args(&args)),
               CmdResult{out:"".into(),err:"".into(),status:Some(0)});
    // Cached
    assert_eq!(run(bkt(dir.path("cache")).args(&args)),
               CmdResult{out:"".into(),err:"".into(),status:Some(0)});
}

#[test]
fn output_preserved() {
    let dir = TestDir::temp();
    fn same_output(dir: &TestDir, args: &[&str]) {
        let bkt_args = vec!("--", "bash", "-c", PRINT_ARGS, "arg0");
        // Second call will be cached
        assert_eq!(
            succeed(bkt(dir.path("cache")).args(&bkt_args).args(args)),
            succeed(bkt(dir.path("cache")).args(&bkt_args).args(args)));
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
    let args = vec!("--", "bash", "-c", "printf 'foo\\0bar'; printf 'bar\\0baz\\n' >&2");

    // Not cached
    let output = run(bkt(dir.path("cache")).args(&args));
    assert_eq!(output,
               CmdResult{ out:"foo\u{0}bar".into(), err:"bar\u{0}baz\n".into(), status:Some(0) });
    // Cached
    assert_eq!(run(bkt(dir.path("cache")).args(&args)),  output);
}

#[test]
fn exit_code_preserved() {
    let dir = TestDir::temp();
    let args = vec!("--", "bash", "-c", EXIT_WITH, "arg0");

    assert_eq!(run(bkt(dir.path("cache")).args(&args).arg("14")).status, Some(14));
    assert_eq!(run(bkt(dir.path("cache")).args(&args).arg("14")).status, Some(14));
}

// TODO
// respects env
// respects cwd
// concurrent calls race
// warm cache
