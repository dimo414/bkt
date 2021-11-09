use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, Duration};

use anyhow::Result;
use test_dir::{TestDir, DirBuilder, FileType};
use std::fs::File;

// Bash scripts to pass to -c.
// Avoid depending on external programs.
const COUNT_INVOCATIONS: &str = "file=${1:?} lines=0; \
                                 printf '%s' '.' >> \"$file\"; \
                                 read < \"$file\"; \
                                 printf '%s' \"${#REPLY}\";";
const PRINT_ARGS: &str = "args=(\"$@\"); declare -p args;";
const EXIT_WITH: &str = "exit \"${1:?}\";";
const AWAIT_AND_TOUCH: &str = "echo awaiting; \
                               until [[ -e \"${1:?}\" ]]; do sleep .1; done; \
                               echo > \"${2:?}\"";

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
    bkt.arg(format!("--cache-dir={}", cache_dir.as_ref().display()));
    bkt
}

#[derive(Eq, PartialEq, Debug)]
struct CmdResult {
    out: String,
    err: String,
    status: Option<i32>,
}

impl From<std::process::Output> for CmdResult {
    fn from(output: std::process::Output) -> Self {
        CmdResult{
            out: std::str::from_utf8(&output.stdout).unwrap().into(),
            err: std::str::from_utf8(&output.stderr).unwrap().into(),
            status: output.status.code()
        }
    }
}

fn run(cmd: &mut Command) -> CmdResult {
    cmd.output().unwrap().into()
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

fn join<A: Clone>(mut vec: Vec<A>, tail: &[A]) -> Vec<A> {
    vec.extend_from_slice(tail);
    vec
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
    let file = dir.path("file");
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap());
    let first_result = run(bkt(dir.path("cache")).args(&args));

    for _ in 1..3 {
        let subsequent_result = run(bkt(dir.path("cache")).args(&args));
        assert_eq!(first_result, subsequent_result);
    }
}

#[test]
fn cache_expires() {
    let dir = TestDir::temp();
    let file = dir.path("file");
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap());
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
    let file1 = dir.path("file1");
    let file2 = dir.path("file2");
    let args1 = vec!("--ttl=10s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file1.to_str().unwrap());
    let args2 = vec!("--ttl=20s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file2.to_str().unwrap());

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
    let file = dir.path("file");
    let args1 = vec!("--ttl=10s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap());
    let args2 = vec!("--ttl=20s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap());

    // despite different TTLs the invocation is still cached
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args1)), "1");
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args2)), "1");

    // the provided TTL is respected, though it was cached with a smaller TTL
    make_dir_stale(dir.path("cache"), Duration::from_secs(15)).unwrap();
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args2)), "1");

    // However the cache can be invalidated in the background using the older TTL
    make_dir_stale(dir.path("cache"), Duration::from_secs(60)).unwrap(); // ensure the following call triggers a cleanup
    succeed(bkt(dir.path("cache")).args(&["--", "bash", "-c", "sleep 1"])); // trigger cleanup via a different command
    assert_eq!(succeed(bkt(dir.path("cache")).args(&args1)), "2");
}

#[test]
fn cache_refreshes_in_background() {
    let dir = TestDir::temp();
    let file = dir.path("file");
    let args = vec!("--stale=10s", "--ttl=20s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap());
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
    let file = dir.path("file");
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap());

    let first_call = succeed(bkt(dir.path("cache")).args(&args));
    assert_eq!(first_call, "1");
    assert_eq!(first_call, succeed(bkt(dir.path("cache")).args(&args)));

    let diff_cache = succeed(bkt(dir.path("new-cache")).args(&args));
    assert_eq!(diff_cache, "2");
}

#[test]
fn respects_cache_scope() {
    let dir = TestDir::temp();
    let file = dir.path("file");
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap());

    let first_call = succeed(bkt(dir.path("cache")).args(&args));
    assert_eq!(first_call, "1");
    assert_eq!(first_call, succeed(bkt(dir.path("cache")).args(&args)));

    let diff_scope = succeed(bkt(dir.path("cache"))
        .arg("--scope=foo").args(&args));
    assert_eq!(diff_scope, "2");
    assert_eq!(diff_scope, succeed(bkt(dir.path("cache"))
        .arg("--scope=foo").args(&args)));
}

#[test]
fn respects_args() {
    let dir = TestDir::temp();
    let file = dir.path("file");
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap());

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
    let cwd_args = join(vec!("--cwd"), &args);

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
#[cfg(not(feature = "debug"))] // See lib's bkt_tests::with_env
fn respects_env() {
    let dir = TestDir::temp();
    let args = vec!("--", "bash", "-c", "printf 'foo:%s bar:%s baz:%s' \"$FOO\" \"$BAR\" \"$BAZ\"");
    let env_args = join(vec!("--env=FOO", "--env=BAR"), &args);

    let without_env = succeed(bkt(dir.path("cache")).args(&args)
        .env("FOO", "1").env("BAR", "1").env("BAZ", "1"));
    assert_eq!(without_env, succeed(bkt(dir.path("cache")).args(&args)));
    // even if --env is set, if the vars are absent cache still hits earlier call
    assert_eq!(without_env, succeed(bkt(dir.path("cache")).args(&env_args)));

    let env = succeed(bkt(dir.path("cache")).args(&env_args)
        .env("FOO", "2").env("BAR", "2").env("BAZ", "2"));
    assert_eq!(env, "foo:2 bar:2 baz:2");
    let env = succeed(bkt(dir.path("cache")).args(&env_args)
        .env("FOO", "3").env("BAR", "2").env("BAZ", "3"));
    assert_eq!(env, "foo:3 bar:2 baz:3");
    let env = succeed(bkt(dir.path("cache")).args(&env_args)
        .env("FOO", "4").env("BAR", "4").env("BAZ", "4"));
    assert_eq!(env, "foo:4 bar:4 baz:4");
    let env = succeed(bkt(dir.path("cache")).args(&env_args)
        .env("FOO", "2").env("BAR", "2").env("BAZ", "5"));
    assert_eq!(env, "foo:2 bar:2 baz:2"); // BAZ doesn't invalidate cache

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

#[test]
fn warm() {
    let dir = TestDir::temp();
    let await_file = dir.path("await");
    let touch_file = dir.path("touch");
    let args = vec!("--", "bash", "-c", AWAIT_AND_TOUCH, "arg0",
                    await_file.to_str().unwrap(), touch_file.to_str().unwrap());
    let warm_args = join(vec!("--warm"), &args);

    let output = succeed(bkt(dir.path("cache")).args(&warm_args));
    assert_eq!(output, "");
    assert!(!touch_file.exists());

    File::create(&await_file).unwrap(); // allow the bash process to terminate
    for _ in 0..10 {
        if touch_file.exists() { break; }
        std::thread::sleep(Duration::from_millis(200));
    }
    // This ensures the bash process has almost-completed, but it could still race with bkt actually
    // caching the result and creating a key file. If this proves flaky a more robust check would be
    // to inspect the keys directory.
    assert!(touch_file.exists());

    std::fs::remove_file(&await_file).unwrap(); // process would not terminate if run again
    let output = succeed(bkt(dir.path("cache")).args(&args));
    assert_eq!(output, "awaiting\n");
}

#[test]
fn force() {
    let dir = TestDir::temp();
    let file = dir.path("file");
    let args = vec!("--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap());
    let args_force = join(vec!("--force"), &args);

    let output = succeed(bkt(&dir.path("cache")).args(&args));
    assert_eq!(output, "1");
    let output = succeed(bkt(&dir.path("cache")).args(&args));
    assert_eq!(output, "1");

    let output = succeed(bkt(&dir.path("cache")).args(&args_force));
    assert_eq!(output, "2");
    let output = succeed(bkt(&dir.path("cache")).args(&args));
    assert_eq!(output, "2");
}

#[test]
fn concurrent_call_race() {
    let dir = TestDir::temp();
    let file = dir.path("file");
    let slow_count_invocations = format!("sleep \"0.5$RANDOM\"; {}", COUNT_INVOCATIONS);
    let args = vec!("--", "bash", "-c", &slow_count_invocations, "arg0", file.to_str().unwrap());
    println!("{:?}", args);

    let proc1 = bkt(dir.path("cache")).args(&args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let proc2 = bkt(dir.path("cache")).args(&args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let result1: CmdResult = proc1.wait_with_output().unwrap().into();
    assert_eq!(result1.err, "");
    assert_eq!(result1.status, Some(0));
    let result2: CmdResult = proc2.wait_with_output().unwrap().into();
    assert_eq!(result2.err, "");
    assert_eq!(result2.status, Some(0));

    assert_eq!(std::fs::read_to_string(&file).unwrap(), "..");
    assert!(result1.out == "2" || result2.out == "2"); // arbitrary which completes first
}
