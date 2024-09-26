mod cli {
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, Duration};

    use anyhow::Result;
    use test_dir::{TestDir, DirBuilder, FileType};
    use std::fs::File;
    use std::io::Read;

    // Bash scripts to pass to -c.
    // Avoid depending on external programs.
    const COUNT_INVOCATIONS: &str = r#"file=${1:?} lines=0; \
                                       printf '%s' '.' >> "$file"; \
                                       read < "$file"; \
                                       printf '%s' "${#REPLY}";"#;
    const PRINT_ARGS: &str = r#"args=("$@"); declare -p args;"#;
    const EXIT_WITH: &str = r#"exit "${1:?}";"#;
    const EXIT_WITH_ENV: &str = r#"exit "${EXIT_WITH:?}";"#;
    const AWAIT_AND_TOUCH: &str = r#"echo awaiting; \
                                     until [[ -e "${1:?}" ]]; do sleep .1; done; \
                                     echo > "${2:?}";"#;

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
        // Set a TTL here rather than in every test - tests that care about the TTL should override
        bkt.env("BKT_TTL", "5s");
        bkt.env("BKT_TMPDIR", cache_dir.as_ref().as_os_str());
        bkt
    }

    fn sudo(cmd: &mut Command) -> Command {
        let mut sudo = Command::new("sudo");
        sudo.args(&["-n", "-E"]).arg(cmd.get_program()).args(cmd.get_args());
        for (key, value) in cmd.get_envs() {
            match value {
                Some(value) => sudo.env(key, value),
                None => sudo.env_remove(key),
            };
        }
        sudo
    }

    #[derive(Eq, PartialEq, Debug)]
    struct CmdResult {
        out: String,
        err: String,
        status: Option<i32>,
    }

    impl From<std::process::Output> for CmdResult {
        fn from(output: std::process::Output) -> Self {
            CmdResult {
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
        if cfg!(feature="debug") {
            if !result.err.is_empty() { eprintln!("stderr:\n{}", result.err); }
        } else {
            // debug writes to stderr, so don't bother checking it in that mode
            assert_eq!(result.err, "");
        }
        assert_eq!(result.status, Some(0));
        result.out
    }

    // Returns once the given file contains different contents than those provided. Panics if the
    // file does not change after ~5s.
    //
    // Note this could return immediately if the file already doesn't contain initial_contents
    // (e.g. if the given contents were wrong) because such a check could race. Do additional
    // checks prior to waiting if needed.
    fn wait_for_contents_to_change<P: AsRef<Path>>(file: P, initial_contents: &str) {
        for _ in 1..50 {
            if std::fs::read_to_string(&file).unwrap() != initial_contents { return; }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("Contents of {} did not change", file.as_ref().to_string_lossy());
    }

    fn make_dir_stale<P: AsRef<Path>>(dir: P, age: Duration) -> Result<()> {
        debug_assert!(dir.as_ref().is_dir());
        let desired_time = SystemTime::now() - age;
        let stale_time = filetime::FileTime::from_system_time(desired_time);
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let last_modified = std::fs::metadata(&path)?.modified()?;

            if path.is_file() && last_modified > desired_time {
                filetime::set_file_mtime(&path, stale_time)?;
            } else if path.is_dir() {
                make_dir_stale(&path, age)?;
            }
        }
        Ok(())
    }

    fn make_file_stale<P: AsRef<Path>>(file: P, age: Duration) -> Result<()> {
        debug_assert!(file.as_ref().is_file());
        let desired_time = SystemTime::now() - age;
        let stale_time = filetime::FileTime::from_system_time(desired_time);
        filetime::set_file_mtime(&file, stale_time)?;
        Ok(())
    }

    fn join<A: Clone>(beg: &[A], tail: &[A]) -> Vec<A> {
        beg.iter().chain(tail).cloned().collect()
    }

    #[test]
    fn help() {
        let dir = TestDir::temp();
        let out = succeed(bkt(dir.path("cache")).arg("--help"));
        assert!(out.contains("bkt [OPTIONS] --ttl <DURATION> -- <COMMAND>..."), "Was:\n---\n{}\n---", out);
    }

    #[test]
    fn cached() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let args = ["--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];
        let first_result = run(bkt(dir.path("cache")).args(args));

        for _ in 1..3 {
            let subsequent_result = run(bkt(dir.path("cache")).args(args));
            if cfg!(feature="debug") {
                assert_eq!(first_result.status, subsequent_result.status);
                assert_eq!(first_result.out, subsequent_result.out);
            } else {
                assert_eq!(first_result, subsequent_result);
            }
        }
    }

    #[test]
    fn cache_expires() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let args = ["--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];
        let first_result = succeed(bkt(dir.path("cache")).arg("--ttl=1m").args(args));
        assert_eq!(first_result, "1");

        // Slightly stale is still cached
        make_dir_stale(dir.path("cache"), Duration::from_secs(10)).unwrap();
        let subsequent_result = succeed(bkt(dir.path("cache")).arg("--ttl=1m").args(args));
        assert_eq!(first_result, subsequent_result);

        make_dir_stale(dir.path("cache"), Duration::from_secs(120)).unwrap();
        let after_stale_result = succeed(bkt(dir.path("cache")).arg("--ttl=1m").args(args));
        assert_eq!(after_stale_result, "2");

        // Respects BKT_TTL env var (other tests cover --ttl)
        make_dir_stale(dir.path("cache"), Duration::from_secs(10)).unwrap();
        let env_result = succeed(bkt(dir.path("cache")).env("BKT_TTL", "5s").args(args));
        assert_eq!(env_result, "3");
    }

    #[test]
    fn cache_expires_separately() {
        let dir = TestDir::temp();
        let file1 = dir.path("file1");
        let file2 = dir.path("file2");
        let args1 = ["--ttl=10s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file1.to_str().unwrap()];
        let args2 = ["--ttl=20s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file2.to_str().unwrap()];

        // first invocation
        assert_eq!(succeed(bkt(dir.path("cache")).args(args1)), "1");
        assert_eq!(succeed(bkt(dir.path("cache")).args(args2)), "1");

        // second invocation, cached
        assert_eq!(succeed(bkt(dir.path("cache")).args(args1)), "1");
        assert_eq!(succeed(bkt(dir.path("cache")).args(args2)), "1");

        // only shorter TTL is invalidated
        make_dir_stale(dir.path("cache"), Duration::from_secs(15)).unwrap();
        assert_eq!(succeed(bkt(dir.path("cache")).args(args1)), "2");
        assert_eq!(succeed(bkt(dir.path("cache")).args(args2)), "1");
    }

    #[test]
    fn cache_hits_with_different_settings() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let args1 = ["--ttl=10s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];
        let args2 = ["--ttl=20s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];

        // despite different TTLs the invocation is still cached
        assert_eq!(succeed(bkt(dir.path("cache")).args(args1)), "1");
        assert_eq!(succeed(bkt(dir.path("cache")).args(args2)), "1");

        // the provided TTL is respected, though it was cached with a smaller TTL
        make_dir_stale(dir.path("cache"), Duration::from_secs(15)).unwrap();
        assert_eq!(succeed(bkt(dir.path("cache")).args(args2)), "1");

        // However the cache can be invalidated in the background using the older TTL
        make_dir_stale(dir.path("cache"), Duration::from_secs(60)).unwrap(); // ensure the following call triggers a cleanup
        succeed(bkt(dir.path("cache")).args(["--", "bash", "-c", "sleep 1"])); // trigger cleanup via a different command
        assert_eq!(succeed(bkt(dir.path("cache")).args(args1)), "2");
    }

    #[test]
    fn cache_refreshes_in_background() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let args = ["--stale=10s", "--ttl=20s", "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];
        assert_eq!(succeed(bkt(dir.path("cache")).args(args)), "1");

        make_dir_stale(dir.path("cache"), Duration::from_secs(15)).unwrap();
        assert_eq!(succeed(bkt(dir.path("cache")).args(args)), "1");

        wait_for_contents_to_change(&file, ".");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "..");
        assert_eq!(succeed(bkt(dir.path("cache")).args(args)), "2");
    }

    #[test]
    fn discard_failures() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let cmd = format!("{} false;", COUNT_INVOCATIONS);
        let args = ["--discard-failures", "--", "bash", "-c", &cmd, "arg0", file.to_str().unwrap()];

        let result = run(bkt(dir.path("cache")).args(args));
        assert_eq!(result.out, "1");
        assert_eq!(result.status, Some(1));

        // Not cached
        let result = run(bkt(dir.path("cache")).args(args));
        assert_eq!(result.out, "2");
        assert_eq!(result.status, Some(1));
    }

    #[test]
    fn discard_failure_cached_separately() {
        let dir = TestDir::temp();

        let allow_args = ["--", "bash", "-c", EXIT_WITH_ENV, "arg0"];
        let discard_args = join(&["--discard-failures"], &allow_args);

        // without separate caches a --discard-failures invocation could return a previously-cached
        // failed result. In 0.5.4 and earlier this would mean result2.status == 14.
        let result1 = run(bkt(dir.path("cache")).args(allow_args).env("EXIT_WITH", "14"));
        assert_eq!(result1.status, Some(14));
        let result2 = run(bkt(dir.path("cache")).args(discard_args).env("EXIT_WITH", "0"));
        assert_eq!(result2.status, Some(0));
    }

    #[test]
    fn discard_failures_in_background() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let cmd = format!("{} ! \"${{FAIL:-false}}\";", COUNT_INVOCATIONS);
        let args = ["--ttl=20s", "--discard-failures", "--", "bash", "-c", &cmd, "arg0", file.to_str().unwrap()];
        let stale_args = join(&["--stale=10s"], &args);

        // Cache result normally
        assert_eq!(succeed(bkt(dir.path("cache")).args(args)), "1");

        // Cause cmd to fail and not be cached
        std::env::set_var("FAIL", "true");

        // returns cached result, but attempts to warm in the background
        make_dir_stale(dir.path("cache"), Duration::from_secs(15)).unwrap();
        assert_eq!(succeed(bkt(dir.path("cache")).args(&stale_args)), "1");

        // Verify command ran
        wait_for_contents_to_change(&file, ".");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "..");

        // But cached success is still returned
        assert_eq!(succeed(bkt(dir.path("cache")).args(args)), "1");
    }

    // depends on sudo and libc::geteuid(), but also on Windows we don't split by user presently anyways
    #[cfg(unix)]
    #[test]
    fn cache_dirs_multi_user() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let args = ["--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];

        // Skip the test if we can't run `sudo bkt --version`
        // Calling into sudo like this isn't great, but it's an easy and reasonably reliable way to
        // run bkt as two different users. It generally won't run on CI but at least it provides
        // some manual test coverage.
        if unsafe { libc::geteuid() } == 0 {
            // https://github.com/rust-lang/rust/issues/68007 tracking skippable tests
            eprint!("Running tests as root already, skipping");
            return;
        }
        let mut sudo_bkt = sudo(bkt(dir.path("cache")).arg("--version"));
        if run(&mut sudo_bkt).status.unwrap_or(127) != 0 {
            // https://github.com/rust-lang/rust/issues/68007 tracking skippable tests
            eprint!("Couldn't run `sudo bkt`, skipping");
            return;
        }

        // can call bkt as both current and super-user
        let user_call = succeed(bkt(dir.path("cache")).args(args));
        assert_eq!(user_call, "1");

        let sudo_call = succeed(&mut sudo(bkt(dir.path("cache")).args(args)));
        assert_eq!(sudo_call, "2");

        // cached separately
        assert_eq!(user_call, succeed(bkt(dir.path("cache")).args(args)));

        assert_eq!(sudo_call, succeed(&mut sudo(bkt(dir.path("cache")).args(args))));
    }

    #[test]
    fn respects_cache_dir() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let args = ["--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];

        let first_call = succeed(bkt(dir.path("cache")).arg(format!("--cache-dir={}", dir.path("cache").display())).args(args));
        assert_eq!(first_call, "1");
        assert_eq!(first_call, succeed(bkt(dir.path("cache")).arg(format!("--cache-dir={}", dir.path("cache").display())).args(args)));

        let diff_cache = succeed(bkt(dir.path("cache")).arg(format!("--cache-dir={}", dir.path("new-cache").display())).args(args));
        assert_eq!(diff_cache, "2");

        let env_cache = succeed(bkt(dir.path("cache")).env("BKT_CACHE_DIR", dir.path("env-cache").as_os_str()).args(args));
        assert_eq!(env_cache, "3");
    }

    // https://github.com/dimo414/bkt/issues/9
    #[test]
    fn respects_relative_cache() {
        let dir = TestDir::temp();
        let cwd = dir.path("cwd");
        std::fs::create_dir(&cwd).unwrap();
        let file = dir.path("file");
        let args = ["--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];

        let first_call = succeed(bkt(dir.path("unused")).arg("--cache-dir=cache").args(args).current_dir(&cwd));
        assert_eq!(first_call, "1");
        assert_eq!(first_call, succeed(bkt(dir.path("unused")).arg("--cache-dir=cache").args(args).current_dir(&cwd)));
    }

    #[test]
    fn respects_cache_scope() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let args = ["--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];

        let first_call = succeed(bkt(dir.path("cache")).args(args));
        assert_eq!(first_call, "1");
        assert_eq!(first_call, succeed(bkt(dir.path("cache")).args(args)));

        let diff_scope = succeed(bkt(dir.path("cache"))
            .arg("--scope=foo").args(args));
        assert_eq!(diff_scope, "2");
        assert_eq!(diff_scope, succeed(bkt(dir.path("cache"))
            .arg("--scope=foo").args(args)));
        assert_eq!(diff_scope, succeed(bkt(dir.path("cache"))
            .env("BKT_SCOPE", "foo").args(args)));
    }

    #[test]
    fn respects_args() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let args = ["--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];

        let first_call = succeed(bkt(dir.path("cache")).args(args));
        assert_eq!(first_call, "1");
        assert_eq!(first_call, succeed(bkt(dir.path("cache")).args(args)));

        let diff_args = succeed(bkt(dir.path("cache")).args(args).arg("A B"));
        assert_eq!(diff_args, "2");

        let split_args = succeed(bkt(dir.path("cache")).args(args).args(["A", "B"]));
        assert_eq!(split_args, "3");
    }

    #[test]
    fn respects_cwd() {
        let dir = TestDir::temp()
            .create("dir1", FileType::Dir)
            .create("dir2", FileType::Dir);
        let args = ["--", "bash", "-c", "pwd"];
        let cwd_args = join(&["--cwd"], &args);

        let without_cwd_dir1 = succeed(bkt(dir.path("cache")).args(args).current_dir(dir.path("dir1")));
        let without_cwd_dir2 = succeed(bkt(dir.path("cache")).args(args).current_dir(dir.path("dir2")));
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
        let args = ["--", "bash", "-c", r#"printf 'foo:%s bar:%s baz:%s' "$FOO" "$BAR" "$BAZ""#];
        let env_args = join(&["--env=FOO", "--env=BAR"], &args);

        let without_env = succeed(bkt(dir.path("cache")).args(args)
            .env("FOO", "1").env("BAR", "1").env("BAZ", "1"));
        assert_eq!(without_env, succeed(bkt(dir.path("cache")).args(args)));
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
    fn respects_modtime() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let watch_file = dir.path("watch");
        let args = ["--modtime", watch_file.to_str().unwrap(), "--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];
        let no_file_result = succeed(bkt(dir.path("cache")).args(args));
        // File absent is cached
        assert_eq!(no_file_result, "1");
        assert_eq!(no_file_result, succeed(bkt(dir.path("cache")).args(args)));

        // create a new file, invalidating cache
        File::create(&watch_file).unwrap();
        let new_file_result = succeed(bkt(dir.path("cache")).args(args));
        assert_eq!(new_file_result, "2");
        assert_eq!(new_file_result, succeed(bkt(dir.path("cache")).args(args)));

        // update the modtime, again invalidating the cache
        make_file_stale(&watch_file, Duration::from_secs(10)).unwrap();
        let old_file_result = succeed(bkt(dir.path("cache")).args(args));
        assert_eq!(old_file_result, "3");
        assert_eq!(old_file_result, succeed(bkt(dir.path("cache")).args(args)));
    }

    #[test]
    fn streaming() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let script = r#"echo BEFORE; for (( i=0; i<50; i++ )); do if [[ -e "$1" ]]; then echo AFTER; exit 0; fi; sleep .1; done; exit 10"#;
        let args = ["--", "bash", "-c", script, "arg0", file.to_str().unwrap()];
        let mut proc = bkt(dir.path("cache")).args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()).spawn().unwrap();

        // partial output is observable before the process exits
        let mut buf = [0; 64];
        let mut stdout = proc.stdout.take().unwrap();
        let len = stdout.read(&mut buf).unwrap();
        assert_eq!("BEFORE\n".as_bytes(), &buf[0..len], "len:{} - {:?}", len, buf);
        assert_eq!(proc.try_wait().unwrap(), None); // process is still running

        File::create(&file).unwrap(); // allow the bash process to terminate
        let len = stdout.read(&mut buf).unwrap();
        assert_eq!("AFTER\n".as_bytes(), &buf[0..len], "len:{} - {:?}", len, buf);

        if !cfg!(feature="debug") {
            let mut buf = String::new();
            assert_eq!(proc.stderr.as_mut().unwrap().read_to_string(&mut buf).unwrap(), 0, "{}", buf);
            assert_eq!(buf, "");
        }
        assert_eq!(proc.wait().unwrap().code(), Some(0));

        // Command is cached and can be re-run without blocking
        std::fs::remove_file(&file).unwrap();
        assert_eq!(succeed(bkt(dir.path("cache")).args(args)), "BEFORE\nAFTER\n");
    }

    #[test]
    fn large_output() {
        let dir = TestDir::temp();
        let bytes = 1024*100; // 100KB is larger than the standard OS process buffer
        // Write a large amount of data to stdout and stderr; an incorrect implementation reads
        // each stream sequentially which will hang on sufficiently large streams as the subprocess
        // waits for the reader to catch up.
        let script = format!(r#"printf '.%.0s' {{1..{0}}}; printf '.%.0s' {{1..{0}}} >&2"#, bytes);
        let args = ["--", "bash", "-c", &script, "arg0"];
        let result = run(bkt(dir.path("cache")).args(args));
        assert_eq!(result.out.len(), bytes);
        if !cfg!(feature="debug") {
            assert_eq!(result.err.len(), bytes);
        }
        assert_eq!(result.status, Some(0));
    }

    #[test]
    fn truncated_output() {
        let dir = TestDir::temp();
        let bytes = 1024*100; // 100KB is larger than the standard OS process buffer
        // Write a large amount of data to stdout and close the process' stream without reading it;
        // this should be supported silently, see https://github.com/dimo414/bkt/issues/44.
        let script = format!(r#"printf '.%.0s' {{1..{0}}}"#, bytes);
        let args = ["--", "bash", "-c", &script, "arg0"];
        let mut cmd = bkt(dir.path("cache"));
        let cmd = cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd.spawn().unwrap();
        // Read the beginning of stdout
        // It's not strictly necessary to do this, in fact closing the stream without reading
        // anything causes the error even for small outputs, but this seems like the more
        // "interesting" case and it covers the read-nothing behavior too.
        let mut buf = [0; 10];
        child.stdout.as_mut().unwrap().read_exact(&mut buf).unwrap();
        assert_eq!(buf, [b'.'; 10]);

        std::mem::drop(child.stdout.take().unwrap()); // close stdout without reading further

        let result: CmdResult = child.wait_with_output().unwrap().into();
        assert_eq!(result.out, "");
        // Unexpected error messages will show up in stderr
        if !cfg!(feature="debug") { assert_eq!(result.err, ""); }
        assert_eq!(result.status, Some(0));
    }

    #[test]
    #[cfg(not(feature="debug"))]
    fn no_debug_output() {
        let dir = TestDir::temp();
        let args = ["--", "bash", "-c", "true"];

        // Not cached
        assert_eq!(run(bkt(dir.path("cache")).args(args)),
                   CmdResult { out: "".into(), err: "".into(), status: Some(0) });
        // Cached
        assert_eq!(run(bkt(dir.path("cache")).args(args)),
                   CmdResult { out: "".into(), err: "".into(), status: Some(0) });
    }

    #[test]
    #[cfg(feature="debug")]
    fn debug_output() {
        fn starts_with_bkt(s: &str) -> bool { s.lines().all(|l| l.starts_with("bkt: ")) }

        let miss_debug_re = regex::Regex::new(
            "bkt: state: \nbkt: lookup .* not found\nbkt: cleanup data .*\nbkt: cleanup keys .*\nbkt: store data .*\nbkt: store key .*\n").unwrap();
        let hit_debug_re = regex::Regex::new("bkt: lookup .* found\n").unwrap();

        let dir = TestDir::temp();
        let args = ["--", "bash", "-c", PRINT_ARGS, "arg0"];

        let miss = run(bkt(dir.path("cache")).args(args));
        assert!(starts_with_bkt(&miss.err), "{}", miss.err);
        assert!(miss_debug_re.is_match(&miss.err), "{}", miss.err);

        let hit = run(bkt(dir.path("cache")).args(args));
        assert!(starts_with_bkt(&hit.err), "{}", hit.err);
        assert!(hit_debug_re.is_match(&hit.err), "{}", hit.err);
    }

    #[test]
    fn output_preserved() {
        let dir = TestDir::temp();
        fn same_output(dir: &TestDir, args: &[&str]) {
            let bkt_args = ["--", "bash", "-c", PRINT_ARGS, "arg0"];
            // Second call will be cached
            assert_eq!(
                succeed(bkt(dir.path("cache")).args(bkt_args).args(args)),
                succeed(bkt(dir.path("cache")).args(bkt_args).args(args)));
        }

        same_output(&dir, &[]);
        same_output(&dir, &[""]);
        same_output(&dir, &["a", "b"]);
        same_output(&dir, &["a b"]);
        same_output(&dir, &["a b", "c"]);
    }

    #[test]
    #[cfg(not(feature="debug"))]
    fn sensitive_output() {
        let dir = TestDir::temp();
        let args = ["--", "bash", "-c", r"printf 'foo\0bar'; printf 'bar\0baz\n' >&2"];

        // Not cached
        let output = run(bkt(dir.path("cache")).args(args));
        assert_eq!(output,
                   CmdResult { out: "foo\u{0}bar".into(), err: "bar\u{0}baz\n".into(), status: Some(0) });
        // Cached
        assert_eq!(run(bkt(dir.path("cache")).args(args)), output);
    }

    #[test]
    fn exit_code_preserved() {
        let dir = TestDir::temp();
        let args = ["--", "bash", "-c", EXIT_WITH, "arg0"];

        assert_eq!(run(bkt(dir.path("cache")).args(args).arg("14")).status, Some(14));
        assert_eq!(run(bkt(dir.path("cache")).args(args).arg("14")).status, Some(14));
    }

    #[test]
    fn warm() {
        let dir = TestDir::temp();
        let await_file = dir.path("await");
        let touch_file = dir.path("touch");
        let args = ["--", "bash", "-c", AWAIT_AND_TOUCH, "arg0",
                    await_file.to_str().unwrap(), touch_file.to_str().unwrap()];
        let warm_args = join(&["--warm"], &args);

        let output = succeed(bkt(dir.path("cache")).args(warm_args));
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
        let output = succeed(bkt(dir.path("cache")).args(args));
        assert_eq!(output, "awaiting\n");
    }

    #[test]
    fn force() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let args = ["--", "bash", "-c", COUNT_INVOCATIONS, "arg0", file.to_str().unwrap()];
        let args_force = join(&["--force"], &args);

        let output = succeed(bkt(dir.path("cache")).args(args));
        assert_eq!(output, "1");
        let output = succeed(bkt(dir.path("cache")).args(args));
        assert_eq!(output, "1");

        let output = succeed(bkt(dir.path("cache")).args(args_force));
        assert_eq!(output, "2");
        let output = succeed(bkt(dir.path("cache")).args(args));
        assert_eq!(output, "2");
    }

    #[test]
    fn concurrent_call_race() {
        let dir = TestDir::temp();
        let file = dir.path("file");
        let slow_count_invocations = format!(r#"sleep "0.5$RANDOM"; {}"#, COUNT_INVOCATIONS);
        let args = ["--", "bash", "-c", &slow_count_invocations, "arg0", file.to_str().unwrap()];
        println!("{:?}", args);

        let proc1 = bkt(dir.path("cache")).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let proc2 = bkt(dir.path("cache")).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let result1: CmdResult = proc1.wait_with_output().unwrap().into();
        if !cfg!(feature="debug") { assert_eq!(result1.err, ""); }
        assert_eq!(result1.status, Some(0));
        let result2: CmdResult = proc2.wait_with_output().unwrap().into();
        if !cfg!(feature="debug") { assert_eq!(result2.err, ""); }
        assert_eq!(result2.status, Some(0));

        assert_eq!(std::fs::read_to_string(&file).unwrap(), "..");
        assert!(result1.out == "2" || result2.out == "2"); // arbitrary which completes first
    }
}
