use super::*;

#[test]
fn test_candidate_receipt_snapshot_and_restore_on_failed_certification() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-receipt-snap-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    // Setup pre-existing receipt at /opt/mockpkg/.af-version
    let pre_existing = temp_dir.join("opt/mockpkg/.af-version");
    std::fs::create_dir_all(pre_existing.parent().unwrap()).unwrap();
    std::fs::write(&pre_existing, b"1.0.0\n").unwrap();

    // Snapshot candidate receipts before operation
    let snapshots = snapshot_candidate_receipts_with_env("mockpkg", &env_cfg).unwrap();
    assert!(!snapshots.is_empty(), "Must find candidate paths");

    // Verify pre-existing receipt has Some(b"1.0.0\n")
    let pre_snap = snapshots
        .iter()
        .find(|s| s.path == pre_existing)
        .expect("pre-existing must be tracked");
    assert_eq!(pre_snap.bytes(), Some(b"1.0.0\n".as_slice()));

    // Verify non-existent candidate path (e.g. /var/lib/mockpkg/.af-version) has None
    let var_lib_path = temp_dir.join("var/lib/mockpkg/.af-version");
    let non_exist_snap = snapshots
        .iter()
        .find(|s| s.path == var_lib_path)
        .expect("var/lib candidate must be tracked");
    assert_eq!(non_exist_snap.state, None);

    // Mutate pre-existing receipt (installer writes new version)
    std::fs::write(&pre_existing, b"2.0.0-uncertified\n").unwrap();

    // Also write a newly created receipt at var/lib
    std::fs::create_dir_all(var_lib_path.parent().unwrap()).unwrap();
    std::fs::write(&var_lib_path, b"2.0.0-uncertified\n").unwrap();

    // Target certification fails -> restore candidate receipts!
    let restore_res = restore_candidate_receipts(&snapshots);
    assert!(
        restore_res.is_ok(),
        "Restoration must succeed: {:?}",
        restore_res
    );

    // Pre-existing receipt must be rolled back to 1.0.0
    assert_eq!(std::fs::read(&pre_existing).unwrap(), b"1.0.0\n");

    // Newly created receipt at var/lib must be completely removed
    assert!(
        !var_lib_path.exists(),
        "Newly created receipt must be removed after failed certification"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_restore_candidate_receipts_symlink_swap_does_not_modify_victim() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-symlink-restore-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let receipt_path = temp_dir.join("opt/vulnpkg/.af-version");
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    std::fs::write(&receipt_path, b"1.0.0\n").unwrap();

    // Snapshot original receipt (1.0.0)
    let snapshots = snapshot_candidate_receipts_with_env("vulnpkg", &env_cfg).unwrap();

    // Attacker creates a victim file outside
    let victim_file = temp_dir.join("victim_file.txt");
    std::fs::write(&victim_file, b"VICTIM_INTACT_CONTENT").unwrap();

    // Attacker replaces .af-version with a symlink pointing to victim_file
    std::fs::remove_file(&receipt_path).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&victim_file, &receipt_path).unwrap();

    // Now restore candidate receipts!
    let restore_res = restore_candidate_receipts(&snapshots);
    assert!(
        restore_res.is_ok(),
        "Restoration must succeed: {:?}",
        restore_res
    );

    // Victim file MUST NOT have been modified!
    assert_eq!(
        std::fs::read(&victim_file).unwrap(),
        b"VICTIM_INTACT_CONTENT"
    );

    // .af-version MUST now be a regular file with b"1.0.0\n", NOT a symlink!
    let meta = std::fs::symlink_metadata(&receipt_path).unwrap();
    assert!(
        !meta.file_type().is_symlink(),
        ".af-version must not be a symlink after restoration"
    );
    assert!(
        meta.file_type().is_file(),
        ".af-version must be a regular file"
    );
    assert_eq!(std::fs::read(&receipt_path).unwrap(), b"1.0.0\n");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_snapshot_symlink_or_fifo_fails_closed_and_marks_job_failed() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-symlink-snap-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let receipt_path = temp_dir.join("opt/symlinkpkg/.af-version");
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    let target_file = temp_dir.join("target.txt");
    std::fs::write(&target_file, b"target").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_file, &receipt_path).unwrap();

    // 1. snapshot_candidate_receipts_with_env must fail closed with Err
    let snap_res = snapshot_candidate_receipts_with_env("symlinkpkg", &env_cfg);
    assert!(
        snap_res.is_err(),
        "Snapshotting a symlink must fail closed: {:?}",
        snap_res
    );
    let err_msg = snap_res.unwrap_err();
    assert!(
        err_msg.to_ascii_lowercase().contains("symlink"),
        "Error must mention symlink: {}",
        err_msg
    );

    // Also verify FIFO fails closed with non-regular file error
    #[cfg(unix)]
    {
        let fifo_path = temp_dir.join("opt/fifopkg/.af-version");
        std::fs::create_dir_all(fifo_path.parent().unwrap()).unwrap();
        let fifo_cstr = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
        let _ = unsafe { libc::mkfifo(fifo_cstr.as_ptr(), 0o644) };
        let fifo_snap = snapshot_candidate_receipts_with_env("fifopkg", &env_cfg);
        assert!(fifo_snap.is_err(), "Snapshotting a FIFO must fail closed");
        let fifo_err = fifo_snap.unwrap_err();
        assert!(
            fifo_err.contains("non-regular file") || fifo_err.contains("symlink"),
            "FIFO error must mention non-regular file: {}",
            fifo_err
        );
    }

    // 2. CoordinatedOperation::execute must mark job as terminal "failed"
    let db_path = temp_dir.join("var/lib/aetherflow/aetherflow.sqlite");
    std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
        CREATE TABLE settings(id INTEGER PRIMARY KEY,base_domain TEXT);
        INSERT INTO settings VALUES(1,'default.example.test');
        CREATE TABLE app_updates(package_name TEXT PRIMARY KEY);
        CREATE TABLE app_ingress_configs(app_name TEXT PRIMARY KEY,public_domain TEXT,
            external_access_enabled BOOLEAN,listen_port INTEGER,tls_enabled BOOLEAN,
            created_at TEXT,updated_at TEXT);",
    )
    .unwrap();

    let req = PackageRunnerRequest {
        package_id: "symlinkpkg".to_string(),
        action: "install".to_string(),
        script_name: "installpackage-symlinkpkg".to_string(),
        app_port: 8080,
        delete_data: false,
        expected_target_version: Some("1.0.0".to_string()),
        ..Default::default()
    };
    let package = Package {
        name: "symlinkpkg".into(),
        service_name: "symlinkpkg".into(),
        service_type: "systemd".into(),
        default_port: 8080,
        ..Default::default()
    };

    struct DummyBackend;
    impl LifecycleBackend for DummyBackend {
        fn runtime_port(&self, _: &str) -> i32 {
            8080
        }
        fn available_port(&self, _: i32) -> bool {
            true
        }
        fn active<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async { Ok(false) })
        }
        fn control<'a>(&'a self, _: &'a str, _: &'a str, _: &'a str) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn script<'a>(
            &'a self,
            _: &'a PackageRunnerRequest,
            _: &'a mpsc::Sender<String>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    let mut coord =
        CoordinatedOperation::admit(conn, req, package, vec!["symlinkpkg".into()]).unwrap();
    let (tx, _rx) = mpsc::channel(10);
    let exec_res = coord.execute(&DummyBackend, &tx).await;
    assert!(
        exec_res.is_err(),
        "Execute must fail due to symlink receipt snapshot"
    );

    let (status, failure_category, failed_stage): (String, Option<String>, Option<String>) = coord.conn.query_row(
        "SELECT status, failure_category, failed_stage FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
        rusqlite::params![coord.request.package_id, coord.request.lifecycle_job_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).unwrap();

    assert_eq!(status, "failed", "Job status must be terminal 'failed'");
    assert_eq!(
        failure_category.as_deref(),
        Some("preflight"),
        "failure_category must be preflight"
    );
    assert_eq!(
        failed_stage.as_deref(),
        Some("preflight_receipt_snapshot"),
        "failed_stage must be preflight_receipt_snapshot"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sanitize_lifecycle_field_redacts_credentials_and_tokens() {
    let input = "Failed to fetch: password=supersecret, token: mytoken123, Bearer eyJhbGciOi..., Basic dXNlcjpwYXNz; url=https://example.com";
    let sanitized = sanitize_lifecycle_field(input);
    assert!(
        !sanitized.contains("supersecret"),
        "Password must be redacted"
    );
    assert!(!sanitized.contains("mytoken123"), "Token must be redacted");
    assert!(
        !sanitized.contains("eyJhbGciOi"),
        "Bearer token must be redacted"
    );
    assert!(
        !sanitized.contains("dXNlcjpwYXNz"),
        "Basic auth must be redacted"
    );
    assert!(sanitized.contains("password=[REDACTED]"));
    assert!(sanitized.contains("token: [REDACTED]"));
    assert!(sanitized.contains("Bearer [REDACTED]"));
    assert!(sanitized.contains("Basic [REDACTED]"));

    // Quoted and multi-word credential values
    let multiword_input = r#"Encountered error with password="first SECRET_TAIL" and "secret": "alpha beta gamma" and 'token': 'delta epsilon'"#;
    let sanitized_multi = sanitize_lifecycle_field(multiword_input);
    assert!(
        !sanitized_multi.contains("SECRET_TAIL"),
        "Must not leak SECRET_TAIL"
    );
    assert!(
        !sanitized_multi.contains("alpha beta gamma"),
        "Must not leak alpha beta gamma"
    );
    assert!(
        !sanitized_multi.contains("beta gamma"),
        "Must not leak beta gamma"
    );
    assert!(
        !sanitized_multi.contains("delta epsilon"),
        "Must not leak delta epsilon"
    );
    assert!(sanitized_multi.contains("password=[REDACTED]"));
    assert!(sanitized_multi.contains(r#""secret": [REDACTED]"#));

    // Verify db_password and escaped quotes are completely redacted
    let db_pw_input = r#"db_password="secret_val""#;
    let sanitized_db_pw = sanitize_lifecycle_field(db_pw_input);
    assert!(
        !sanitized_db_pw.contains("secret_val"),
        "db_password value must be redacted"
    );
    assert_eq!(sanitized_db_pw, "db_password=[REDACTED]");

    let json_db_pw = r#"{"db_password": "secret_val"}"#;
    let sanitized_json_db = sanitize_lifecycle_field(json_db_pw);
    assert!(
        !sanitized_json_db.contains("secret_val"),
        "JSON db_password must be redacted"
    );
    assert_eq!(sanitized_json_db, r#"{"db_password": [REDACTED]}"#);

    let escaped_quotes_input = r#"secret="part1 \"quoted\" tail_secret""#;
    let sanitized_escaped = sanitize_lifecycle_field(escaped_quotes_input);
    assert!(!sanitized_escaped.contains("part1"), "Must not leak part1");
    assert!(
        !sanitized_escaped.contains("quoted"),
        "Must not leak quoted"
    );
    assert!(
        !sanitized_escaped.contains("tail_secret"),
        "Must not leak tail_secret"
    );
    assert_eq!(sanitized_escaped, "secret=[REDACTED]");
}

#[test]
fn test_restore_candidate_receipts_parent_enotdir_fails_closed() {
    let temp_dir = std::env::temp_dir().join(format!("af-test-enotdir-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let parent_file = temp_dir.join("parent_regular_file");
    std::fs::write(&parent_file, b"regular file content").unwrap();
    let receipt_path = parent_file.join(".af-version");

    let snapshots = vec![FileSnapshot::absent(receipt_path)];
    let res = restore_candidate_receipts(&snapshots);
    assert!(
        res.is_err(),
        "restore_candidate_receipts must return Err when parent is a regular file (ENOTDIR), got: {:?}",
        res
    );
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.to_lowercase().contains("not a directory")
            || err_msg.contains("ENOTDIR")
            || err_msg.contains("stepwise"),
        "Error must indicate stepwise open failure on non-directory: {}",
        err_msg
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_snapshot_blueprint_targets_symlink_or_oversized_fails_closed() {
    let temp_dir = std::env::temp_dir().join(format!("af-test-bp-snap-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let sonarr_dir = temp_dir.join("var/lib/sonarr");
    std::fs::create_dir_all(&sonarr_dir).unwrap();
    let config_target = sonarr_dir.join("config.xml");

    // 1. Symlink target
    let victim_file = temp_dir.join("victim.txt");
    std::fs::write(&victim_file, b"victim content").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&victim_file, &config_target).unwrap();

    let snap_res = snapshot_blueprint_targets("sonarr", &env_cfg);
    assert!(
        snap_res.is_err(),
        "Snapshotting a symlink blueprint target must fail closed: {:?}",
        snap_res
    );
    let err_msg = snap_res.unwrap_err();
    assert!(
        err_msg.to_ascii_lowercase().contains("symlink"),
        "Error must mention symlink: {}",
        err_msg
    );
    // Verify victim file and symlink were NOT deleted
    assert!(victim_file.is_file(), "Victim file must not be deleted");
    assert!(
        std::fs::symlink_metadata(&config_target)
            .unwrap()
            .file_type()
            .is_symlink(),
        "Symlink must not be unlinked"
    );

    // 2. Oversized file (> 1 MiB)
    let _ = std::fs::remove_file(&config_target);
    let oversized_buf = vec![0x41u8; 2 * 1024 * 1024];
    std::fs::write(&config_target, &oversized_buf).unwrap();

    let snap_res_over = snapshot_blueprint_targets("sonarr", &env_cfg);
    assert!(
        snap_res_over.is_err(),
        "Snapshotting an oversized blueprint target must fail closed: {:?}",
        snap_res_over
    );
    let over_err = snap_res_over.unwrap_err();
    assert!(
        over_err.contains("exceeds") && over_err.contains("byte limit"),
        "Error must mention length cap: {}",
        over_err
    );
    assert!(
        config_target.is_file(),
        "Oversized file must not be deleted"
    );
    assert_eq!(
        std::fs::metadata(&config_target).unwrap().len(),
        2 * 1024 * 1024
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_restore_preserves_exact_permissions_and_ownership() {
    let temp_dir = std::env::temp_dir().join(format!("af-test-perms-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let secret_file = temp_dir.join("secret.conf");
    std::fs::write(&secret_file, b"SECRET_KEY=confidential_data_12345").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let state = read_file_entry_bounded_nofollow(&secret_file, 1024 * 1024)
        .expect("read_file_entry_bounded_nofollow must succeed")
        .expect("file must be present");
    assert_eq!(state.mode & 0o7777, 0o600);
    let expected_uid = state.uid;
    let expected_gid = state.gid;

    let snap = FileSnapshot {
        path: secret_file.clone(),
        state: Some(state),
    };

    // Mutate file to 0o644 with altered content
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    std::fs::write(&secret_file, b"LEAKED_AND_MUTATED").unwrap();

    // Restore file
    let restore_res = restore_candidate_receipts(&[snap]);
    assert!(
        restore_res.is_ok(),
        "Restoration must succeed: {:?}",
        restore_res
    );

    // Verify content
    assert_eq!(
        std::fs::read(&secret_file).unwrap(),
        b"SECRET_KEY=confidential_data_12345"
    );

    // Verify permissions are exactly 0o600, NEVER 0o644!
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&secret_file).unwrap();
        let mode = meta.permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "Restored file must have 0o600 mode, not 0o644");
        assert_eq!(meta.uid(), expected_uid, "Restored file must preserve UID");
        assert_eq!(meta.gid(), expected_gid, "Restored file must preserve GID");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sanitize_lifecycle_field_attached_curl_and_comma_credentials() {
    // Attached curl -u credentials
    let curl_attached = "curl -uadmin:supersecret https://example.com/api";
    let sanitized_attached = sanitize_lifecycle_field(curl_attached);
    assert!(
        !sanitized_attached.contains("supersecret"),
        "Attached curl password must be redacted"
    );
    assert!(
        !sanitized_attached.contains("admin:supersecret"),
        "Attached curl credentials must be redacted"
    );
    assert_eq!(
        sanitized_attached,
        "curl -u[REDACTED] https://example.com/api"
    );

    // Attached curl -u credentials with quotes
    let curl_quoted = "curl -u\"admin:supersecret\" https://example.com/api";
    let sanitized_quoted = sanitize_lifecycle_field(curl_quoted);
    assert!(
        !sanitized_quoted.contains("supersecret"),
        "Quoted curl password must be redacted"
    );
    assert_eq!(
        sanitized_quoted,
        "curl -u[REDACTED] https://example.com/api"
    );

    // Attached curl -u at end of command or line
    let curl_bare = "curl -uadmin:supersecret";
    let sanitized_bare = sanitize_lifecycle_field(curl_bare);
    assert_eq!(sanitized_bare, "curl -u[REDACTED]");

    // Attached curl with comma in credentials
    let curl_comma = "curl -uadmin:pass,word https://example.com";
    let sanitized_curl_comma = sanitize_lifecycle_field(curl_comma);
    assert!(
        !sanitized_curl_comma.contains("pass,word"),
        "Comma-containing curl credential must be redacted"
    );
    assert_eq!(
        sanitized_curl_comma,
        "curl -u[REDACTED] https://example.com"
    );

    // Unquoted credentials containing commas
    let input_comma = "Failed: password=part1,part2, status=500";
    let sanitized_comma = sanitize_lifecycle_field(input_comma);
    assert!(!sanitized_comma.contains("part1"), "part1 must be redacted");
    assert!(!sanitized_comma.contains("part2"), "part2 must be redacted");
    assert!(sanitized_comma.contains("password=[REDACTED]"));
    assert!(sanitized_comma.contains("status=500"));

    // Comma-separated key-value credentials: both password and token redacted cleanly
    let input_multi = "error: password=part1,part2, token: secret_token_xyz; details";
    let sanitized_multi = sanitize_lifecycle_field(input_multi);
    assert!(!sanitized_multi.contains("part1"));
    assert!(!sanitized_multi.contains("part2"));
    assert!(!sanitized_multi.contains("secret_token_xyz"));
    assert_eq!(
        sanitized_multi,
        "error: password=[REDACTED], token: [REDACTED]; details"
    );

    // Semicolon-delimited unquoted credentials with commas
    let input_semi = "password=part1,part2; token=token1,token2; url=https://example.com";
    let sanitized_semi = sanitize_lifecycle_field(input_semi);
    assert!(!sanitized_semi.contains("part1"));
    assert!(!sanitized_semi.contains("part2"));
    assert!(!sanitized_semi.contains("token1"));
    assert!(!sanitized_semi.contains("token2"));
    assert_eq!(
        sanitized_semi,
        "password=[REDACTED]; token=[REDACTED]; url=https://example.com"
    );
}

#[test]
fn test_sanitize_lifecycle_field_redacts_nested_json_object_and_array_secrets() {
    // Raw key-value with nested object
    let raw_obj = sanitize_lifecycle_field("failed with password: {\"value\":\"CANARY_SECRET\"}");
    assert!(
        !raw_obj.contains("CANARY_SECRET"),
        "Secret must be redacted: {}",
        raw_obj
    );
    assert!(
        raw_obj.contains("password: [REDACTED]"),
        "Must redact raw object: {}",
        raw_obj
    );

    // JSON key-value with nested object
    let json_obj = sanitize_lifecycle_field("{\"password\":{\"value\":\"CANARY_SECRET\"}}");
    assert!(
        !json_obj.contains("CANARY_SECRET"),
        "Secret must be redacted: {}",
        json_obj
    );
    assert!(
        json_obj.contains("\"password\":[REDACTED]"),
        "Must redact JSON object: {}",
        json_obj
    );

    // Raw key-value with JSON array
    let raw_arr = sanitize_lifecycle_field("secret: [\"CANARY_SECRET_1\", \"CANARY_SECRET_2\"]");
    assert!(
        !raw_arr.contains("CANARY_SECRET"),
        "Secrets in array must be redacted: {}",
        raw_arr
    );
    assert!(
        raw_arr.contains("secret: [REDACTED]"),
        "Must redact raw array: {}",
        raw_arr
    );

    // JSON key-value with array
    let json_arr = sanitize_lifecycle_field("{\"token\":[\"SECRET_A\",\"SECRET_B\"]}");
    assert!(
        !json_arr.contains("SECRET"),
        "Secrets in JSON array must be redacted: {}",
        json_arr
    );
    assert!(
        json_arr.contains("\"token\":[REDACTED]"),
        "Must redact JSON array: {}",
        json_arr
    );

    // 2 levels of nested braces
    let nested_2_lvl =
        sanitize_lifecycle_field("api_key: {\"outer\": {\"inner\": \"SECRET_KEY\"}}");
    assert!(
        !nested_2_lvl.contains("SECRET_KEY"),
        "2-level nested secret must be redacted: {}",
        nested_2_lvl
    );
    assert!(nested_2_lvl.contains("api_key: [REDACTED]"));

    // 3-level and 4-level nested JSON objects
    let nested_3_lvl =
        sanitize_lifecycle_field("{\"password\": {\"l1\": {\"l2\": {\"l3\": \"CANARY_3LVL\"}}}}");
    assert!(
        !nested_3_lvl.contains("CANARY_3LVL"),
        "3-level nested secret must be redacted: {}",
        nested_3_lvl
    );
    assert!(
        nested_3_lvl.contains("\"password\": [REDACTED]")
            || nested_3_lvl.contains("\"password\":[REDACTED]")
    );

    let nested_4_lvl = sanitize_lifecycle_field(
        "api_key: {\"l1\": {\"l2\": {\"l3\": {\"l4\": \"CANARY_4LVL\"}}}}",
    );
    assert!(
        !nested_4_lvl.contains("CANARY_4LVL"),
        "4-level nested secret must be redacted: {}",
        nested_4_lvl
    );
    assert!(nested_4_lvl.contains("api_key: [REDACTED]"));

    // Multiline nested JSON objects
    let nested_multiline = sanitize_lifecycle_field(
        "\"secret\": {\n  \"l1\": {\n    \"l2\": \"CANARY_MULTILINE\"\n  }\n}",
    );
    assert!(
        !nested_multiline.contains("CANARY_MULTILINE"),
        "Multiline nested secret must be redacted: {}",
        nested_multiline
    );
    assert!(nested_multiline.contains("\"secret\": [REDACTED]"));

    // Already redacted strings should not be corrupted
    let already_redacted_raw = sanitize_lifecycle_field("password: [REDACTED]");
    assert_eq!(already_redacted_raw, "password: [REDACTED]");

    let already_redacted_json = sanitize_lifecycle_field("{\"password\":[REDACTED]}");
    assert_eq!(already_redacted_json, "{\"password\":[REDACTED]}");
}

#[test]
fn test_wave22_sanitize_lifecycle_field_scalar_credentials() {
    let test_cases = [
        "Cookie: session=CANARY_COOKIE",
        "Set-Cookie: theme=\"CANARY_COOKIE\"; HttpOnly",
        "session=CANARY_SESSION",
        "{\"webhook_url\":\"https://example.test/CANARY_HOOK\"}",
        "pass=CANARY_PASSWORD",
    ];

    for tc in test_cases {
        let sanitized = sanitize_lifecycle_field(tc);
        assert!(
            !sanitized.contains("CANARY_"),
            "Sanitized text must contain zero CANARY_ substrings for input {:?}, got {:?}",
            tc,
            sanitized
        );
    }

    // Idempotency check:
    assert_eq!(
        sanitize_lifecycle_field("password: [REDACTED]"),
        "password: [REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("{\"password\":[REDACTED]}"),
        "{\"password\":[REDACTED]}"
    );
}

#[test]
fn test_wave23_escaped_cookie_header_quotes_redacted() {
    let input1 = r#"curl -H "Cookie: sid=\"COOKIE_CANARY\"" https://example.invalid"#;
    let sanitized1 = sanitize_lifecycle_field(input1);
    assert!(
        !sanitized1.contains("COOKIE_CANARY"),
        "Escaped cookie canary must be redacted: {}",
        sanitized1
    );
    assert!(
        sanitized1.contains("Cookie: [REDACTED]"),
        "Must contain redacted cookie header: {}",
        sanitized1
    );

    let input2 = r#"curl -H "Set-Cookie: token=\"COOKIE_CANARY\"; Path=/" https://example.invalid"#;
    let sanitized2 = sanitize_lifecycle_field(input2);
    assert!(
        !sanitized2.contains("COOKIE_CANARY"),
        "Set-Cookie canary must be redacted: {}",
        sanitized2
    );

    let input3 = r#"{"args": ["curl", "-H", "Cookie: sid=\"COOKIE_CANARY\""]}"#;
    let sanitized3 = sanitize_lifecycle_field(input3);
    assert!(
        !sanitized3.contains("COOKIE_CANARY"),
        "JSON escaped cookie must be redacted: {}",
        sanitized3
    );
}

#[test]
fn test_wave24_sanitize_escaped_quotes_cli_flags_and_redacted_suffix() {
    let cases = [
        r#"password=\"SECRET words\""#,
        r#"api_key=\"SECRET words\""#,
        r#"client_secret=\"SECRET words\""#,
        r#"session=\"SECRET words\""#,
        r#"webhook=\"SECRET words\""#,
        r#"rclone_rc_pass=\"SECRET words\""#,
        "--password SECRET words",
        "--passwd SECRET words",
        "--pwd SECRET words",
        "--pass SECRET words",
        "--secret SECRET words",
        "--token SECRET words",
        "--api-key SECRET words",
        "--apikey SECRET words",
        "--cookie SECRET words",
        "--cookies SECRET words",
        "--session SECRET words",
        "--webhook SECRET words",
        "--password=SECRET words",
        r#"--password=\"SECRET words\""#,
        r#"--token=\"SECRET words\""#,
        r#"curl --user=\"admin:SECRET words\" https://example.invalid"#,
        r#"curl -u \"admin:SECRET words\" https://example.invalid"#,
        "bypass=visible passed=true monkey=1",
    ];
    for input in cases {
        let sanitized = sanitize_lifecycle_field(input);
        assert!(
            !sanitized.contains("SECRET"),
            "secret leaked for {input:?} -> {sanitized:?}"
        );
    }

    let boundary = sanitize_lifecycle_field("bypass=visible passed=true monkey=1");
    assert!(boundary.contains("bypass=visible"), "{boundary}");
    assert!(boundary.contains("passed=true"), "{boundary}");
    assert!(boundary.contains("monkey=1"), "{boundary}");

    let json_password = "AF_DIAG_FAILURE={\"stage\": \"password=[REDACTED]\\\"SECRET words\\\\\\\"\", \"status\": \"ok\"}";
    let sanitized_password = sanitize_lifecycle_field(json_password);
    assert!(
        !sanitized_password.contains("SECRET"),
        "{sanitized_password}"
    );
    let payload = sanitized_password.trim_start_matches("AF_DIAG_FAILURE=");
    serde_json::from_str::<serde_json::Value>(payload)
        .unwrap_or_else(|e| panic!("password diagnostic is not JSON ({e}): {sanitized_password}"));

    let json_user = "AF_DIAG_FAILURE={\"stage\": \"--user [REDACTED]\\\"user:SECRET words\\\\\\\"\", \"status\": \"ok\"}";
    let sanitized_user = sanitize_lifecycle_field(json_user);
    assert!(!sanitized_user.contains("SECRET"), "{sanitized_user}");
    let payload = sanitized_user.trim_start_matches("AF_DIAG_FAILURE=");
    serde_json::from_str::<serde_json::Value>(payload)
        .unwrap_or_else(|e| panic!("user diagnostic is not JSON ({e}): {sanitized_user}"));

    let token_json = sanitize_lifecycle_field(r#"{"note":"token=SECRET\""}"#);
    assert!(!token_json.contains("SECRET"), "{token_json}");
    serde_json::from_str::<serde_json::Value>(&token_json)
        .unwrap_or_else(|e| panic!("token JSON broken ({e}): {token_json}"));
}

#[test]
fn test_wave25_sanitize_shell_escapes_glued_suffixes_and_unicode_keys() {
    let cases = [
        r#"curl --password prefix\ SENTINEL --verbose"#,
        "curl --user operator:prefix\\ SENTINEL https://example.invalid",
        r#"{"command":"curl --password prefix\ SENTINEL --verbose"}"#,
        r#"{"command":"curl --password prefix\\ SENTINEL --verbose"}"#,
        r#"password=prefix\;SENTINEL"#,
        r#"password=prefix\&SENTINEL"#,
        r#"password=prefix\,SENTINEL"#,
        "curl --password $'SENTINEL' https://example.invalid",
        "curl --password $\"SENTINEL\" https://example.invalid",
        "curl --password prefix\"SENTINEL\" https://example.invalid",
        "curl --password prefix'SENTINEL' https://example.invalid",
        "password=[REDACTED]SENTINEL",
        "curl --password [REDACTED]SENTINEL --verbose",
        "curl --password [REDACTED]'SENTINEL'",
        "curl --password [REDACTED]\"SENTINEL\" --verbose",
        "curl --password [REDACTED]$'SENTINEL' --verbose",
        r#"{"pass\u0077ord":"SENTINEL"}"#,
        r#"{"pass\\u0077ord":"SENTINEL"}"#,
    ];
    assert_eq!(cases.len(), 18, "wave 25 sanitizer scenario count");
    for input in cases {
        let once = sanitize_lifecycle_field(input);
        let twice = sanitize_lifecycle_field(&once);
        assert!(
            !once.contains("SENTINEL"),
            "secret leaked for {input:?} -> {once:?}"
        );
        assert_eq!(once, twice, "not idempotent for {input:?} -> {once:?}");
    }

    assert_eq!(
        sanitize_lifecycle_field(r#"curl --password prefix\ SENTINEL --verbose"#),
        "curl --password [REDACTED] --verbose"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl --user operator:prefix\\ SENTINEL https://example.invalid"),
        "curl --user [REDACTED] https://example.invalid"
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"password=prefix\;SENTINEL"#),
        "password=[REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl --password $'SENTINEL' https://example.invalid"),
        "curl --password [REDACTED] https://example.invalid"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl --password prefix\"SENTINEL\" https://example.invalid"),
        "curl --password [REDACTED] https://example.invalid"
    );
    assert_eq!(
        sanitize_lifecycle_field("password=[REDACTED]SENTINEL"),
        "password=[REDACTED]"
    );

    let json_cmd =
        sanitize_lifecycle_field(r#"{"command":"curl --password prefix\\ SENTINEL --verbose"}"#);
    assert!(!json_cmd.contains("SENTINEL"), "{json_cmd}");
    serde_json::from_str::<serde_json::Value>(&json_cmd)
        .unwrap_or_else(|e| panic!("command JSON broken ({e}): {json_cmd}"));

    let unicode_key = sanitize_lifecycle_field(r#"{"pass\u0077ord":"SENTINEL"}"#);
    assert!(!unicode_key.contains("SENTINEL"), "{unicode_key}");
    assert!(
        unicode_key.contains("password") || unicode_key.contains("pass\\u0077ord"),
        "{unicode_key}"
    );
    let double_escaped = sanitize_lifecycle_field(r#"{"pass\\u0077ord":"SENTINEL"}"#);
    assert!(!double_escaped.contains("SENTINEL"), "{double_escaped}");

    let untouched = r#"{"na\u006de":"VISIBLE"}"#;
    assert_eq!(sanitize_lifecycle_field(untouched), untouched);

    assert_eq!(
        sanitize_lifecycle_field("webhook_url=[REDACTED_URL]"),
        "webhook_url=[REDACTED_URL]"
    );
    assert_eq!(
        sanitize_lifecycle_field("webhook_url=[REDACTED_url]"),
        "webhook_url=[REDACTED_url]"
    );

    let enclosing = r#"{"stage":"password=[REDACTED]","ok":true}"#;
    let enclosing_out = sanitize_lifecycle_field(enclosing);
    assert_eq!(enclosing_out, enclosing, "{enclosing_out}");
    serde_json::from_str::<serde_json::Value>(&enclosing_out)
        .unwrap_or_else(|e| panic!("enclosing JSON broken ({e}): {enclosing_out}"));

    let closer = r#"{"note":"--password [REDACTED]\" https://example.invalid"}"#;
    let closer_out = sanitize_lifecycle_field(closer);
    assert!(
        closer_out.contains("https://example.invalid"),
        "{closer_out}"
    );
    assert!(!closer_out.contains("SENTINEL"), "{closer_out}");
    serde_json::from_str::<serde_json::Value>(&closer_out)
        .unwrap_or_else(|e| panic!("closer JSON broken ({e}): {closer_out}"));
}
