mod cwd {
    use std::time::Duration;
    use test_dir::{TestDir, FileType, DirBuilder};
    use bkt::{Bkt, CacheStatus, CommandDesc};

    // This test is pulled out from the unit tests into a separate file to avoid racing with other
    // tests that depend on the cwd. See #40 for more. If we need to add more tests like this consider
    // https://docs.rs/serial_test/
    #[test]
    fn cwd_and_working_dir_share_cache() {
        let dir = TestDir::temp().create("wd", FileType::Dir);
        let wd = dir.path("wd");
        let bkt = Bkt::create(dir.path("cache")).unwrap();
        // Note we haven't changed the cwd yet - with_cwd() doesn't read it
        let cmd = CommandDesc::new(["bash", "-c", "pwd; echo '.' > file"]).with_cwd();
        // The initial cwd is captured, but it's overwritten by with_working_dir()
        let state = cmd.capture_state().unwrap().with_working_dir(&wd);
        let (result, status) = bkt.retrieve(state, Duration::from_secs(10)).unwrap();
        assert_eq!(result.stdout_utf8(), format!("{}\n", wd.to_str().unwrap()));
        assert_eq!(result.stderr_utf8(), "");
        assert_eq!(result.exit_code(), 0);
        assert!(matches!(status, CacheStatus::Miss(_)));

        // now change the cwd and see it get captured lazily
        std::env::set_current_dir(&wd).unwrap();
        let (result, status) = bkt.retrieve(&cmd, Duration::from_secs(10)).unwrap();
        assert_eq!(result.stdout_utf8(), format!("{}\n", wd.to_str().unwrap()));
        assert_eq!(result.stderr_utf8(), "");
        assert_eq!(result.exit_code(), 0);
        assert!(matches!(status, CacheStatus::Hit(_)));

        // and the file was only written to once, hence the cache was shared
        assert_eq!(std::fs::read_to_string(wd.join("file")).unwrap(), ".\n");
    }
}
