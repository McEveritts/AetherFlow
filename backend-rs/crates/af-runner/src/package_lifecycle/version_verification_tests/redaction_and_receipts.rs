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
    let _env_lock = crate::ENV_TEST_MUTEX.lock().await;
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

    // JSON key-value with nested object (preserves valid RFC 8259 JSON)
    let json_obj = sanitize_lifecycle_field("{\"password\":{\"value\":\"CANARY_SECRET\"}}");
    assert!(
        !json_obj.contains("CANARY_SECRET"),
        "Secret must be redacted: {}",
        json_obj
    );
    assert!(
        json_obj.contains("\"password\":\"[REDACTED]\""),
        "Must redact JSON object as valid JSON string: {}",
        json_obj
    );
    serde_json::from_str::<serde_json::Value>(&json_obj)
        .unwrap_or_else(|e| panic!("JSON object broken ({e}): {json_obj}"));

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

    // JSON key-value with array (preserves valid RFC 8259 JSON)
    let json_arr = sanitize_lifecycle_field("{\"token\":[\"SECRET_A\",\"SECRET_B\"]}");
    assert!(
        !json_arr.contains("SECRET"),
        "Secrets in JSON array must be redacted: {}",
        json_arr
    );
    assert!(
        json_arr.contains("\"token\":\"[REDACTED]\""),
        "Must redact JSON array as valid JSON string: {}",
        json_arr
    );
    serde_json::from_str::<serde_json::Value>(&json_arr)
        .unwrap_or_else(|e| panic!("JSON array broken ({e}): {json_arr}"));

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
        nested_3_lvl.contains("\"password\": \"[REDACTED]\"")
            || nested_3_lvl.contains("\"password\":\"[REDACTED]\"")
    );
    serde_json::from_str::<serde_json::Value>(&nested_3_lvl)
        .unwrap_or_else(|e| panic!("3-level nested JSON broken ({e}): {nested_3_lvl}"));

    let nested_4_lvl = sanitize_lifecycle_field(
        "api_key: {\"l1\": {\"l2\": {\"l3\": {\"l4\": \"CANARY_4LVL\"}}}}",
    );
    assert!(
        !nested_4_lvl.contains("CANARY_4LVL"),
        "4-level nested secret must be redacted: {}",
        nested_4_lvl
    );
    assert!(nested_4_lvl.contains("api_key: [REDACTED]"));

    // Multiline nested JSON objects (preserve valid JSON `"[REDACTED]"`)
    let nested_multiline = sanitize_lifecycle_field(
        "\"secret\": {\n  \"l1\": {\n    \"l2\": \"CANARY_MULTILINE\"\n  }\n}",
    );
    assert!(
        !nested_multiline.contains("CANARY_MULTILINE"),
        "Multiline nested secret must be redacted: {}",
        nested_multiline
    );
    assert!(
        nested_multiline.contains("\"secret\": \"[REDACTED]\""),
        "Multiline JSON container must emit quoted [REDACTED]: {nested_multiline}"
    );

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

#[test]
fn test_wave1a_crate01_runner_utf8_escape_boundaries_never_panic() {
    let exact_cases = [
        ("password=\\é", "password=[REDACTED]"),
        ("password=\\\\é", "password=[REDACTED]"),
        ("password=\\é next=ok", "password=[REDACTED] next=ok"),
        ("password=\\中", "password=[REDACTED]"),
        ("password=\\🚀", "password=[REDACTED]"),
        (
            "password=prefix\\éSECRET_TAIL --verbose",
            "password=[REDACTED] --verbose",
        ),
        (
            "password=\"\\éSECRET_TAIL\" --verbose",
            "password=[REDACTED] --verbose",
        ),
        (
            "password='\\🚀SECRET_TAIL' --verbose",
            "password=[REDACTED] --verbose",
        ),
        (
            "curl --password \\🚀SECRET_TAIL --verbose",
            "curl --password [REDACTED] --verbose",
        ),
        (
            "curl --user admin:\\éSECRET_TAIL https://example.invalid",
            "curl --user [REDACTED] https://example.invalid",
        ),
    ];

    for (sample, expected) in exact_cases {
        let out = sanitize_lifecycle_field(sample);
        assert_eq!(out, expected, "runner sample={sample:?}");
        assert!(!out.contains("SECRET_TAIL"), "{out}");
        assert_eq!(
            sanitize_lifecycle_field(&out),
            out,
            "runner idempotency: {sample:?}"
        );
    }

    let structured = [
        r#"password=\"\éSECRET_TAIL\" --verbose"#,
        r#"{"password":"prefix\\éSECRET_TAIL"}"#,
        "password={\"nested\":\"\\éSECRET_TAIL\"} --verbose",
        "token=[\\🚀,\"\\éSECRET_TAIL\"] --verbose",
        "Cookie: sid=\\éSECRET_TAIL",
        "curl -H \"Cookie: sid=\\\"\\éSECRET_TAIL\\\"\" https://example.invalid",
        r#"curl -H \\"Cookie: sid=\"\éSECRET_TAIL\" --verbose"#,
    ];
    for sample in structured {
        let out = sanitize_lifecycle_field(sample);
        assert!(
            !out.contains("SECRET_TAIL"),
            "runner leaked for {sample:?} -> {out:?}"
        );
        assert!(
            out.contains("[REDACTED]"),
            "runner missing marker for {sample:?} -> {out:?}"
        );
        assert_eq!(sanitize_lifecycle_field(&out), out);
    }

    // Combinatorial UTF-8 sweep + prefix truncation on runner sanitizer.
    let prefixes = ["password=", "token: ", "--password ", "curl -u "];
    let scalars = ["é", "Ω", "中", "🚀", "👨‍👩‍👧‍👦"];
    let wrappers = [
        ("", ""),
        ("\"", "\""),
        ("\\\"", "\\\""),
        ("{", "}"),
        ("[", "]"),
    ];
    for prefix in prefixes {
        for scalar in scalars {
            for bs_count in 0..=2 {
                let slashes = "\\".repeat(bs_count);
                for (open, close) in wrappers {
                    let sample = format!("{prefix}{open}{slashes}{scalar}CANARY{close} --verbose");
                    let out = sanitize_lifecycle_field(&sample);
                    assert!(!out.contains("CANARY"), "{sample:?} -> {out:?}");
                    assert_eq!(sanitize_lifecycle_field(&out), out);
                }
            }
        }
    }
    for (pre, post) in [("\"", "\""), ("\\\"", "\\\""), ("\\\\\"", "\\\"")] {
        for scalar in scalars {
            for bs_count in 0..=2 {
                let slashes = "\\".repeat(bs_count);
                let sample = format!(
                    "curl -H {pre}Cookie: sid={slashes}{scalar}CANARY{post} https://example.invalid"
                );
                let expected =
                    format!("curl -H {pre}Cookie: [REDACTED]{post} https://example.invalid");
                let out = sanitize_lifecycle_field(&sample);
                assert_eq!(out, expected, "runner header {sample:?}");
                assert_eq!(sanitize_lifecycle_field(&out), out);
            }
        }
    }

    // Multi-parameter escaped headers, cross-line Bearer/Basic, and ANSI-C delimiter-leading scalars.
    assert_eq!(
        sanitize_lifecycle_field(
            r#"curl -H \\"Cookie: a=\"1\", sid=\"SECRET_COOKIE\"\\" https://example.invalid"#
        ),
        r#"curl -H \\"Cookie: [REDACTED]\\" https://example.invalid"#
    );
    assert_eq!(
        sanitize_lifecycle_field(
            r#"curl -H \\"Authorization: Digest username=\"admin\", response=\"SECRET_HEX\"\\" https://example.invalid"#
        ),
        r#"curl -H \\"Authorization: [REDACTED]\\" https://example.invalid"#
    );
    assert_eq!(
        sanitize_lifecycle_field(
            r#"curl -H \"Cookie: a="1", sid=SECRET_COOKIE\" https://example.invalid"#
        ),
        r#"curl -H \"Cookie: [REDACTED]\" https://example.invalid"#
    );
    assert_eq!(
        sanitize_lifecycle_field("unsupported scheme: Bearer\nBearer supersecret_jwt_123"),
        "unsupported scheme: Bearer\nBearer [REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl --password $',SECRET' --verbose"),
        "curl --password [REDACTED] --verbose"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl --password $\",SECRET\" --verbose"),
        "curl --password [REDACTED] --verbose"
    );

    // R2 regression checks in runner sanitizer: `$`-ending JSON passwords, JSON-escaped ANSI-C,
    // auth-scheme parity, and escaped header termination.
    for (json_dollar, expected) in [
        (
            r#"{"stage":"password=hunter2$"}"#,
            r#"{"stage":"password=[REDACTED]"}"#,
        ),
        (
            r#"{"stage":"password=hunter2$","api_key":"TOP_SECRET_123"}"#,
            r#"{"stage":"password=[REDACTED]","api_key":[REDACTED]}"#,
        ),
        (
            r#"{"stage": "password=$", "rc": 1}"#,
            r#"{"stage": "password=[REDACTED]", "rc": 1}"#,
        ),
    ] {
        let out = sanitize_lifecycle_field(json_dollar);
        assert_eq!(out, expected, "runner: {json_dollar}");
        if !expected.contains(":[REDACTED]") {
            serde_json::from_str::<serde_json::Value>(&out)
                .unwrap_or_else(|err| panic!("runner broke JSON ({err}): {out}"));
        }
    }
    let json_ansi = r#"{"command":"curl --password $\",SECRET\" --verbose"}"#;
    let json_ansi_out = sanitize_lifecycle_field(json_ansi);
    assert_eq!(
        json_ansi_out,
        r#"{"command":"curl --password [REDACTED] --verbose"}"#
    );
    serde_json::from_str::<serde_json::Value>(&json_ansi_out).unwrap();

    assert_eq!(
        sanitize_lifecycle_field("Basic admin:supersecret"),
        "Basic [REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("Bearer [REDACTED]SUPER_SECRET"),
        "Bearer [REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("Bearer \"quoted secret\""),
        "Bearer [REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("Digest username=\"admin\", response=\"deadbeef\""),
        "Digest [REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("bearer\t\tsupersecret"),
        "bearer\t\t[REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("Bearer [REDACTED_URL]"),
        "Bearer [REDACTED_URL]"
    );
    assert_eq!(
        sanitize_lifecycle_field("Bearer [REDACTED_URL]SECRET_TAIL"),
        "Bearer [REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field(
            r#"{"cmd":"curl https://example.invalid -H \"Cookie: sid=SECRET\"","exit_code":1,"stage":"install"}"#
        ),
        r#"{"cmd":"curl https://example.invalid -H \"Cookie: [REDACTED]\"","exit_code":1,"stage":"install"}"#
    );
    let runner_json_arr = sanitize_lifecycle_field(
        r#"["curl -H \"Cookie: sid=SECRET_COOKIE\" localhost:8080", "https://example.com", 17]"#,
    );
    assert!(
        !runner_json_arr.contains("SECRET_COOKIE"),
        "{runner_json_arr}"
    );
    serde_json::from_str::<serde_json::Value>(&runner_json_arr).unwrap();
    for header_case in [
        r#"curl -H \"Cookie: ref="https://example.com", sid=SECRET_COOKIE\" localhost:8080"#,
        r#"curl -H \\"Cookie: ref=\"https://example.com\", sid=\"SECRET_COOKIE\"\\" localhost:8080"#,
        r#"curl -H \"Cookie: prefs={\"theme\":\"dark\"}, sid=SECRET_COOKIE\" https://example.invalid"#,
    ] {
        let out = sanitize_lifecycle_field(header_case);
        assert!(
            !out.contains("SECRET_COOKIE"),
            "runner leaked: {header_case} -> {out}"
        );
    }

    // R3 regression checks in runner sanitizer: QuoteStack, headers, ANSI-C, Digest, containers, [REDACTED_URL].
    for (input, secret) in [
        (r#"{"path":"C:\\"} Bearer "SUPER_SECRET""#, "SUPER_SECRET"),
        (
            r#"path="C:\\" msg="expected Bearer " hdr="Bearer SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"users' request failed: 'expected Bearer ' and 'Bearer SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (
            r#"café's request failed: 'expected Bearer ' and 'Bearer SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (
            "invalid token Bearer eyJhbGciOiJIUzI1NiJ9.SUPER_SECRET",
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \"Cookie: prefs={\"theme\":\"dark\",\"v\":\"1\"}, sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", 2fa_sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", true_sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \\"Cookie: a="1" https://example.com; sid=\"SECRET_LEAK\" --verbose"#,
            "SECRET_LEAK",
        ),
        (
            r#"note="password=myP@ss$" msg="pass: SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"["password=hunter2$", 1, "Bearer SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl --password $',\tSUPER_SECRET' --verbose"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl --password $'} SECRET_TAIL' --verbose"#,
            "SECRET_TAIL",
        ),
        (
            r#"{"cmd":"curl --password $\",\tSUPER_SECRET\" --verbose"}"#,
            "SUPER_SECRET",
        ),
        ("{'Authorization': Bearer SUPER_SECRET}", "SUPER_SECRET"),
        ("token=Bearer SUPER_SECRET_JWT", "SUPER_SECRET_JWT"),
        (
            r#"log: \"Digest username="admin", response="SECRET_HEX"\""#,
            "SECRET_HEX",
        ),
        (
            r#"'Digest username*=UTF-8\'\'admin_user, realm="api", response="SECRET_HEX"'"#,
            "SECRET_HEX",
        ),
        (
            r#"Digest realm="api", , response="SECRET_HEX""#,
            "SECRET_HEX",
        ),
        (
            r#"Bearer [REDACTED]\"SUPER_SECRET_TAIL"#,
            "SUPER_SECRET_TAIL",
        ),
        (r#"Basic admin:p\"SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"curl --password [REDACTED_URL]'SECRET_TAIL"#,
            "SECRET_TAIL",
        ),
        (
            r#""Cookie": [REDACTED]\" --verbose SECRET_TAIL""#,
            "SECRET_TAIL",
        ),
    ] {
        let out = sanitize_lifecycle_field(input);
        assert!(
            !out.contains(secret),
            "runner leaked {secret} for {input:?} -> {out:?}"
        );
        assert_eq!(sanitize_lifecycle_field(&out), out);
    }
    for valid_json in [
        r#"{"path": "C:\\", "msg": "expected Bearer ", "hdr": "Bearer SUPER_SECRET"}"#,
        r#"{"exit_code": 1, "cmd": "curl -H \"X-Api-Key: my{SECRET\""}"#,
        r#"["password=hunter2$", 1, "ok"]"#,
        r#"{"password=$": "val"}"#,
        r#"{"outer": {"cmd": "Bearer {\"a\":\"SUPER_SECRET\"}"}, "note": "ok"}"#,
        r#"{"cmd": "curl --password {\"a\":\"SUPER_SECRET\"} --verbose", "exit_code": 1}"#,
        r#"{"cmd": "curl --password {\"a\":\"val with } brace\"} --verbose", "exit_code": 1}"#,
        r#"{"err": "Bearer tok'1", "status": 401}"#,
    ] {
        let out = sanitize_lifecycle_field(valid_json);
        assert!(!out.contains("SUPER_SECRET") && !out.contains("brace"));
        serde_json::from_str::<serde_json::Value>(&out)
            .unwrap_or_else(|e| panic!("runner broke JSON ({e}) for {valid_json}: {out}"));
        assert_eq!(sanitize_lifecycle_field(&out), out);
    }
    assert_eq!(
        sanitize_lifecycle_field("webhook_url=[REDACTED_url]"),
        "webhook_url=[REDACTED_url]"
    );

    let truncation_samples = [
        "password=\\éCANARY --verbose",
        "password=\\\\中CANARY",
        "password=\\\\\\🚀CANARY",
        "password=\"\\éCANARY\" --verbose",
        r#"password=\"\éCANARY\" --verbose"#,
        "password={\"k\":\"\\éCANARY\"} --verbose",
        "token=[\\🚀,\"\\中CANARY\"]",
        "curl -u admin:\\éCANARY https://example.invalid",
        "\"Cookie: sid=\\\"\\éCANARY\\\"\" https://example.invalid",
        r#"\\"Cookie: sid=\"\🚀CANARY\" --verbose"#,
        "Bearer \\\"éCANARY",
    ];
    for sample in truncation_samples {
        for (idx, _) in sample.char_indices() {
            let truncated = &sample[..idx];
            let r1 = sanitize_lifecycle_field(truncated);
            assert_eq!(
                sanitize_lifecycle_field(&r1),
                r1,
                "runner 1-step idempotency failed for {truncated:?} -> {r1:?}"
            );
            if truncated.contains("CANARY") {
                assert!(
                    !r1.contains("CANARY"),
                    "runner leaked truncated {truncated:?} -> {r1:?}"
                );
            }
        }
    }

    // R4 runner regressions: `--url` preservation, comma/paren `[REDACTED_URL]` shielding,
    // mixed-case `[REDACTED_Url]` preservation, empty/even-backslash assignments, and linear-time scaling.
    assert_eq!(
        sanitize_lifecycle_field("failed on --url=https://example.com --update --unit=foo"),
        "failed on --url=https://example.com --update --unit=foo"
    );
    assert_eq!(
        sanitize_lifecycle_field("password=[REDACTED_URL],SECRET_TAIL"),
        "password=[REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("(Bearer [REDACTED_URL])"),
        "(Bearer [REDACTED_URL])"
    );
    assert_eq!(
        sanitize_lifecycle_field("webhook_url=[REDACTED_Url]"),
        "webhook_url=[REDACTED_Url]"
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"{"flag": "-u", "ok": true}"#),
        r#"{"flag": "-u", "ok": true}"#
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"{"stage": "password=\\", "ok": true}"#),
        r#"{"stage": "password=[REDACTED]", "ok": true}"#
    );
    for (input, secret) in [
        (
            r#"{"stage": "password=", "api_key": "SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": "curl --password=\"foo\\\" SECRET_TAIL\" https://example.invalid"}"#,
            "SECRET_TAIL",
        ),
        (
            r#"{"stderr": "syntax error near \": Bearer \" SUPER_SECRET\""}"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \"X-Api-Key: {\"a\":\"foo}\", \"b\":\"SECRET_KEY\"}\" https://example.invalid"#,
            "SECRET_KEY",
        ),
        (
            r#"{"msg": "password={{]", "api_key": "} SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
    ] {
        let out = sanitize_lifecycle_field(input);
        assert!(
            !out.contains(secret),
            "runner leaked {secret} for {input:?} -> {out:?}"
        );
        assert_eq!(sanitize_lifecycle_field(&out), out);
    }

    let started = std::time::Instant::now();
    for payload in [
        format!("curl{}", " -H \"Cookie: sid=123\"".repeat(3_000)),
        r#"\\"Cookie: x" -a "#.repeat(3_000),
        format!("{}\"Cookie: x\\\" -a ", "\\".repeat(16)).repeat(2_000),
        format!(r#"password=\\\"{}\\\""#, r#"\" "#.repeat(4_000)),
        "curl\"-u1;".repeat(3_000),
        "-ua".repeat(3_000),
        " -u$a{".repeat(3_000),
        " -u[REDACTED_URL]{".repeat(3_000),
        format!("{}\n", "password={".repeat(3_000)),
        format!("{}\n", "password=a{ ".repeat(3_000)),
        format!("{}\n", "curl -u a{ ".repeat(3_000)),
    ] {
        let out = sanitize_lifecycle_field(&payload);
        assert!(!out.is_empty());
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "runner sanitize_lifecycle_field exceeded linear-time budget: {elapsed:?}"
    );

    // R5 runner regressions: no shield-prefix injection, benign `[REDACTED_URL]` preservation,
    // escaped `[REDACTED_URL]` parity, numeric JSON passwords, glued `)` / `]` / `}`, multiline headers,
    // and quote-parity / URL-bridging fixes.
    assert_eq!(
        sanitize_lifecycle_field("curl --password prefix]AFURLKSUPER_SECRET --verbose"),
        "curl --password [REDACTED] --verbose"
    );
    assert_eq!(
        sanitize_lifecycle_field("downloading from [REDACTED_URL]/api/v1/health"),
        "downloading from [REDACTED_URL]/api/v1/health"
    );
    assert_eq!(
        sanitize_lifecycle_field("error at [REDACTED_URL]."),
        "error at [REDACTED_URL]."
    );
    assert_eq!(
        sanitize_lifecycle_field(
            r#"{"note":"webhook_url=[REDACTED_URL]\" https://example.invalid"}"#
        ),
        r#"{"note":"webhook_url=[REDACTED_URL]\" https://example.invalid"}"#
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"{"password": 123456789}"#),
        r#"{"password": "[REDACTED]"}"#
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"{"password": -123}"#),
        r#"{"password": "[REDACTED]"}"#
    );
    assert_eq!(
        sanitize_lifecycle_field("password=[REDACTED_URL])SECRET_TAIL"),
        "password=[REDACTED]"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl --password [REDACTED_URL])SECRET_TAIL --verbose"),
        "curl --password [REDACTED] --verbose"
    );
    assert_eq!(
        sanitize_lifecycle_field(
            r#"{"endpoint":"https://example.com","email":"admin@example.com"}"#
        ),
        r#"{"endpoint":"https://example.com","email":"admin@example.com"}"#
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"{"user": "system:serviceaccount:default:app"}"#),
        r#"{"user": "system:serviceaccount:default:app"}"#
    );
    for (input, secret) in [
        ("X-Api-Key:\n  SUPER_SECRET_KEY", "SUPER_SECRET_KEY"),
        ("Authorization:\n  Custom SUPER_SECRET", "SUPER_SECRET"),
        (
            r#"{"err": "'expected Bearer ' 'Bearer SUPER_SECRET' for users' session"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"password": ",SECRET_TAIL", "msg": "truncated"#,
            "SECRET_TAIL",
        ),
        (
            r#"["https://example.com","-uadmin:p@SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        ("password=[REDACTED]]SUPER_SECRET", "SUPER_SECRET"),
        (
            "curl -suMYSECRETu: https://api.example.invalid",
            "MYSECRETu",
        ),
        (
            "curl -su$'SUPER_SECRET' https://example.invalid",
            "SUPER_SECRET",
        ),
        (r#"{"user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"[REDACTED]]AFURLK0Ehttps://\r\n\n$[REDACTED_url]"#,
            "__NONE__",
        ),
    ] {
        let out = sanitize_lifecycle_field(input);
        if secret != "__NONE__" {
            assert!(
                !out.contains(secret),
                "runner leaked {secret} for {input:?} -> {out:?}"
            );
        }
        assert_eq!(
            sanitize_lifecycle_field(&out),
            out,
            "runner idempotency failed for {input:?} -> {out:?}"
        );
    }

    // R6 runner parity regressions: wrapped quotes, glued multiline containers, comma-lists,
    // multi-underscore keys, QuoteStack parity inversion, escaped/unescaped headers, curl flags,
    // RFC 3986 URLs, benign `bypass`/`passed`/`compass` containers, even-backslash `\\"`, and O(N).
    for (input, secret) in [
        (r#"env 'api_key=part1 SUPER_SECRET'"#, "SUPER_SECRET"),
        (
            r#"{"cmd": "env 'password=secret1' 'api_key=part1 SUPER_SECRET' && echo users'"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"docker run -e "password=part1 SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (r#"env "api_key=part1 SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"curl -H "X-Api-Token: part1 SUPER_SECRET" https://example.com"#,
            "SUPER_SECRET",
        ),
        ("password=a{\n  \"v\": \"SUPER_SECRET\"\n}", "SUPER_SECRET"),
        ("password=foo,Bearer SUPER_SECRET", "SUPER_SECRET"),
        ("password=foo,token: SUPER_SECRET", "SUPER_SECRET"),
        ("password=foo,--token SUPER_SECRET", "SUPER_SECRET"),
        ("prod_db_pass=SUPER_SECRET", "SUPER_SECRET"),
        ("prod_api_auth=SUPER_SECRET", "SUPER_SECRET"),
        ("DB_SIGNING_KEY=SUPER_SECRET", "SUPER_SECRET"),
        (
            "cmd=foo'bar=' msg='expected Bearer ' hdr='Bearer SUPER_SECRET'",
            "SUPER_SECRET",
        ),
        (
            r#"err: " msg="expected Bearer " hdr="Bearer SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"err: " msg="password=" hdr="Bearer SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H "Cookie: note=" hello"; sid=SUPER_SECRET_COOKIE" https://example.invalid"#,
            "SUPER_SECRET_COOKIE",
        ),
        (
            r#"curl -H "X-Api-Key: "";SUPER_SECRET" https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \"Cookie: ref=\" https://a.test\"; sid=SUPER_SECRET_COOKIE\" https://example.invalid"#,
            "SUPER_SECRET_COOKIE",
        ),
        (
            r#"curl -H \\"Cookie: a=\"1\" -x sid=\"SUPER_SECRET\" --verbose"#,
            "SUPER_SECRET",
        ),
        (
            "curl --proxy-user admin:SUPER_SECRET https://example.invalid",
            "SUPER_SECRET",
        ),
        (
            "curl \\\n  -su admin:SUPER_SECRET https://example.invalid",
            "SUPER_SECRET",
        ),
        (
            "https://admin:sec;SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "https://admin:my@SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "password=\\\\\\\"line1\\\"\nSUPER_SECRET_LINE2\\\\\\\"",
            "SUPER_SECRET_LINE2",
        ),
        (r#"{"app/pass\u0070hrase": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"{"k8s.io/pass\u0077ord": "SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"error near ": password=":SUPER_SECRET""#, "SUPER_SECRET"),
        (
            r#"error: expected " near Bearer " dXNlcjpwYXNz==""#,
            "dXNlcjpwYXNz==",
        ),
    ] {
        let out = sanitize_lifecycle_field(input);
        assert!(
            !out.contains(secret),
            "runner R6 leaked {secret} for {input:?} -> {out:?}"
        );
        assert_eq!(
            sanitize_lifecycle_field(&out),
            out,
            "runner R6 idempotency failed for {input:?} -> {out:?}"
        );
    }

    // Benign preservation in runner.
    assert_eq!(
        sanitize_lifecycle_field(r#"{"bypass": {"enabled": true}, "passed": ["ok"]}"#),
        r#"{"bypass": {"enabled": true}, "passed": ["ok"]}"#
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"compass=["north", "south"]"#),
        r#"compass=["north", "south"]"#
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"password={a: \\"val", b: 1} benign_after=1"#),
        "password=[REDACTED] benign_after=1"
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"Bearer \\"SECRET" --verbose"#),
        "Bearer [REDACTED] --verbose"
    );
    assert_eq!(
        sanitize_lifecycle_field("git-repo:ssh://git@github.com/org/repo.git#main"),
        "git-repo:ssh://git@github.com/org/repo.git#main"
    );

    // Strictly linear-time O(N) scaling in runner across R6 DoS triggers (with doubling-ratio check).
    type RunnerScalingCase = (&'static str, fn(usize) -> String, usize, usize);
    let runner_scaling: &[RunnerScalingCase] = &[
        (
            "hdr_suppressed_1",
            |n| format!("{}{{a\\\\\"}}", r#"\\"Cookie: x\" -a "#.repeat(n)),
            1_000,
            8_000,
        ),
        (
            "hdr_suppressed_2",
            |n| format!("{}-z", r#"\\"Cookie: x{\\",true}\" -x "#.repeat(n)),
            1_000,
            8_000,
        ),
        (
            "utf8_comma",
            |n| format!("password={}", "é\",x\"".repeat(n)),
            2_000,
            16_000,
        ),
        (
            "bs_u0020",
            |n| format!("\"{}u0020\":1", "\\".repeat(n)),
            8_000,
            32_000,
        ),
        ("esc_space_u", |n| r#"\ -ua"#.repeat(n), 2_500, 16_000),
        ("esc_quote_u", |n| r#"\"-ua"#.repeat(n), 2_500, 16_000),
        ("user_brace", |n| "user={".repeat(n), 2_500, 16_000),
        ("user_esc_space", |n| r#"user=a\ "#.repeat(n), 2_500, 16_000),
        ("user_colon", |n| "user=:".repeat(n), 2_000, 16_000),
        ("user_system", |n| "user=system:".repeat(n), 2_000, 16_000),
        (
            "user_lead_bs_sp",
            |n| r#"user=\ :\ "#.repeat(n),
            2_000,
            16_000,
        ),
        (
            "r8_argv_dollar_brace",
            |n| format!("\"{}\":", "'-u' ${".repeat(n)),
            2_000,
            16_000,
        ),
        (
            "r8_user_dollar_brace",
            |n| format!("'{}a:' :", r#"user=$"a"{ "#.repeat(n)),
            2_000,
            16_000,
        ),
        (
            "r8_hdr_pure_cli_tail",
            |n| format!(r#"curl -H \\"Cookie: {}bad"#, r#"https://a\" "#.repeat(n)),
            2_000,
            16_000,
        ),
        (
            "hdr_d0_sq",
            |n| format!("'{}", "\"Cookie: x';'".repeat(n)),
            1_000,
            8_000,
        ),
        ("curl_pipe_bracket", |n| "|-u[".repeat(n), 2_000, 16_000),
    ];
    let started_r6 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in runner_scaling {
        let mut n = start_n;
        let (d1, d2) = loop {
            let p1 = make_payload(n);
            let t1 = std::time::Instant::now();
            let o1 = sanitize_lifecycle_field(&p1);
            let d1 = t1.elapsed();
            assert!(!o1.is_empty());
            if d1 >= std::time::Duration::from_millis(10) || n >= max_n {
                let p2 = make_payload(n * 2);
                let t2 = std::time::Instant::now();
                let o2 = sanitize_lifecycle_field(&p2);
                let d2 = t2.elapsed();
                assert!(!o2.is_empty());
                break (d1, d2);
            }
            n *= 2;
        };
        let ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
        assert!(
            d2 < std::time::Duration::from_millis(20) || ratio < 3.2,
            "runner {name} showed superlinear scaling at n={n}: d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)"
        );
    }
    let elapsed_r6 = started_r6.elapsed();
    assert!(
        elapsed_r6 < std::time::Duration::from_secs(20),
        "runner R6+R8 linear-time budget exceeded: {elapsed_r6:?}"
    );

    // R7 + R8 runner regressions
    for (input, secret) in [
        (
            r#"{"args":["password=SUPER_SECRET",1],"api_key":"SECOND_SECRET"}"#,
            "SECOND_SECRET",
        ),
        (
            "https://ghp_SUPER_SECRET_TOKEN:pass={x@github.com/org/repo",
            "ghp_SUPER_SECRET_TOKEN",
        ),
        (
            "https://alice.smith:12345;x=SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (r#"https:\/\/admin:SUPER_SECRET@example.com\/api"#, "SUPER_SECRET"),
        (
            r#"curl -H "Content-Type: application/json; charset=utf-8" -su admin:SUPER_SECRET https://api.example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl password="a;b" -su admin:SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            "{\n  \"args\": [\n    \"curl\",\n    \"-usk_live_SUPER_SECRET\"\n  ]\n}",
            "SUPER_SECRET",
        ),
        (
            r#"{"args": ["pg_dump", "--password", "SUPER_SECRET"]}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"args": ["curl", "-u", "admin:SUPER_SECRET", "https://example.com"]}"#,
            "SUPER_SECRET",
        ),
        (
            "curl --oauth2-bearer SUPER_SECRET https://api.example.com",
            "SUPER_SECRET",
        ),
        (
            "curl -H \"Cookie: a=1;\nb=\"2\";\nsid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        (
            "Authorization: Bearer \"line1\nSUPER_SECRET\"",
            "SUPER_SECRET",
        ),
        (
            "Authorization: Bearer \\\nSUPER_SECRET",
            "SUPER_SECRET",
        ),
        (
            "Authorization: Digest username=\"admin\",\n  realm=\"api\",\n  response=\"SUPER_SECRET_HEX\"",
            "SUPER_SECRET_HEX",
        ),
        (
            "pg_dump --password \\\n  \\\n  SUPER_SECRET --verbose",
            "SUPER_SECRET",
        ),
        ("user=\\\nadmin:SUPER_SECRET", "SUPER_SECRET"),
        (r#"{"vault\/password": {"a": "SUPER_SECRET"}}"#, "SUPER_SECRET"),
        (r#"{"password=1": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"APP_KEY": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"tool --APP_KEY SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"user\u003dBasic\u0020admin:SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"{"\u0022password\u0022": "SUPER_SECRET"}"#, "SUPER_SECRET"),
    ] {
        let out = sanitize_lifecycle_field(input);
        assert!(
            !out.contains(secret),
            "runner R7+R8 leaked {secret} for {input:?} -> {out:?}"
        );
        assert_eq!(
            sanitize_lifecycle_field(&out),
            out,
            "runner R7+R8 idempotency failed for {input:?} -> {out:?}"
        );
    }
    assert_eq!(
        sanitize_lifecycle_field("['https://example.com:8443','admin@example.com']"),
        "['https://example.com:8443','admin@example.com']"
    );
    assert_eq!(
        sanitize_lifecycle_field("https://example.com:8443,admin@example.com"),
        "https://example.com:8443,admin@example.com"
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"curl -H C:\\"Cookie: sid=SUPER_SECRET" https://example.com"#),
        r#"curl -H C:\\"Cookie: [REDACTED]" https://example.com"#
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"{"args":["password=[REDACTED]",1],"exit_code":0}"#),
        r#"{"args":["password=[REDACTED]",1],"exit_code":0}"#
    );
    assert_eq!(
        sanitize_lifecycle_field(r#"Digest a=\\"SECRET" --verbose"#),
        "Digest [REDACTED] --verbose"
    );
}

#[test]
fn test_wave1a_r9_r10_audit_regressions() {
    // Every Wave 1A R9 audit reproducer in runner `sanitize_lifecycle_field` (secret removal + 1-step idempotency).
    for (input, forbidden) in [
        // URL multi-URL overshoot (Carbon F-01)
        (
            "https://example.com,https://admin:hUnt3r2_pR0d@example.com",
            "hUnt3r2_pR0d",
        ),
        (
            "https://example.com:8443,https://admin:hUnt3r2_pR0d@example.com",
            "hUnt3r2_pR0d",
        ),
        (
            "https://example.com;https://admin:hUnt3r2_pR0d@example.com",
            "hUnt3r2_pR0d",
        ),
        (
            r#"{"urls":"https://example.com,https://admin:hUnt3r2_pR0d@example.com"}"#,
            "hUnt3r2_pR0d",
        ),
        (
            "https://u1:p1@https://u2:hUnt3r2_pR0d@example.com",
            "hUnt3r2_pR0d",
        ),
        // URL username-as-token & subdelim (Team 8 F-07)
        (
            "https://ghp_SUPER_SECRET.v1;user=foo@github.com/org/repo",
            "ghp_SUPER_SECRET",
        ),
        (
            "https://ghp_SUPER_SECRET.v1;password=x@github.com/org/repo",
            "ghp_SUPER_SECRET",
        ),
        (
            "url=https://example.com;password=admin@SUPER_SECRET",
            "SUPER_SECRET",
        ),
        // URL double-escaped slashes, Unicode scheme/at, `\"` and `}` in password (Neon F-10, Carbon F-07, Team 8 F-08)
        (
            r#"{"msg":"https:\\/\\/admin:SUPER_SECRET@example.com"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"https\u003a//admin:SUPER_SECRET@example.com/api"#,
            "SUPER_SECRET",
        ),
        (
            r#"https:\u002f\u002fadmin:hUnt3r2_pR0d@example.com"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"{"endpoint": "https://admin:hUnt3r2_pR0d\u0040example.com/api"}"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"{"u":"https://admin:my\"SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            "https://admin:my}SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        // JSON key embedded secrets & `,`/`{`/`}` + `\"` keys (Carbon F-02/F-06, Neon F-01..F-04, Team 8 F-05)
        (
            r#"{"error: password=hUnt3r2_pR0d": "failed"}"#,
            "hUnt3r2_pR0d",
        ),
        (r#"{"error: password=hUnt3r2_pR0d": "failed"}"#, "failed"),
        (
            r#"{"cmd --password hUnt3r2_pR0d": "failed"}"#,
            "hUnt3r2_pR0d",
        ),
        (r#"{"cmd --password hUnt3r2_pR0d": "failed"}"#, "failed"),
        (
            r#"{"note Bearer 'hUnt3r2_pR0d": "it's ok"}"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"{"curl -u 'admin:hUnt3r2_pR0d": "it's ok"}"#,
            "hUnt3r2_pR0d",
        ),
        (r#"{"a, \"password\": 1": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"{"a,\"password": "SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"a\"password\"b": {"v": "SUPER_SECRET"}}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"a, \"password\": 1": {"v": "SUPER_SECRET"}}"#,
            "SUPER_SECRET",
        ),
        (
            "{\"a\\\"password\\\"b\": {\n  \"v\": \"SUPER_SECRET\"\n}}",
            "SUPER_SECRET",
        ),
        (
            "{\"a, \\\"password\\\": 1\": {\n  \"v\": \"SUPER_SECRET\"\n}}",
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd --password [REDACTED]": "SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"x.user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"db-user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"a\"user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"a,\"pass\u0077ord": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"\"Cookie: {sid=1\"": true}"#, "sid=1"),
        (r#"["Cookie: {sid=SECRET", ["ok"]]"#, "SECRET"),
        (
            r#"{"api_key": {"cmd": "Cookie: {sid=SECRET"}, "args": "ok"}"#,
            "SECRET",
        ),
        // Auth schemes & obs-fold headers (Neon F-05)
        ("Bearer {\n  \"tok\": \"SUPER_SECRET\"\n}", "SUPER_SECRET"),
        ("Bearer \"line1\nSUPER_SECRET\"", "SUPER_SECRET"),
        ("Cookie: a=1;\n  b=2\n  sid=SUPER_SECRET", "SUPER_SECRET"),
        ("Cookie: a=1;\n  b=\"line2\nSUPER_SECRET\"", "SUPER_SECRET"),
        (
            "Authorization: Bearer\n  \"line1\nSUPER_SECRET\"",
            "SUPER_SECRET",
        ),
        (
            r#""Bearer \\ Digest username=\"admin\", response=\"SUPER_SECRET\"""#,
            "SUPER_SECRET",
        ),
        (
            r#"Bearer \ Digest username="admin", response="SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        // Truncated/multiline/non-string/Unicode-escaped argv & CLI flags (Team 8 F-08/F-09, Neon F-06/F-11, Carbon F-07/F-08)
        (r#"["pg_dump", "--password", "SUPER_SECRET"#, "SUPER_SECRET"),
        (
            "[\"pg_dump\", \"--password\", \"line1\nSUPER_SECRET\"]",
            "SUPER_SECRET",
        ),
        (
            r#"{"args": ["pg_dump", "--password", 987654321]}"#,
            "987654321",
        ),
        (r#"["pg_dump", "--password", 123456789]"#, "123456789"),
        (
            r#"["pg_dump", "--pass\u0077ord", "SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (
            r#"pg_dump "--pass\u0077ord" "hUnt3r2_pR0d""#,
            "hUnt3r2_pR0d",
        ),
        (r#"tool \u002d\u002dpassword SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"pg_dump --password\u0020SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"curl --user\u0020admin:SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"curl \u002du admin:hUnt3r2_pR0d https://example.com"#,
            "hUnt3r2_pR0d",
        ),
        (r#"password \u003d hUnt3r2_pR0d"#, "hUnt3r2_pR0d"),
        ("curl -u=\nadmin:SUPER_SECRET", "SUPER_SECRET"),
        ("curl --user=\nsk_live_SUPER_SECRET", "SUPER_SECRET"),
        ("--password=\nSUPER_SECRET", "SUPER_SECRET"),
        (
            "curl --password=\nsec1 \\\n  -su admin:hUnt3r2_pR0d https://example.com",
            "hUnt3r2_pR0d",
        ),
        (
            "curl --password=\nsec1 \\\n  -su admin:hUnt3r2_pR0d https://example.com",
            "sec1",
        ),
        (
            "[\"pg_dump\",\n \\\"--password\\\",\n \\\"SUPER_SECRET\\\"]",
            "SUPER_SECRET",
        ),
        ("password=\"line1\nline2\"\\\nSUPER_SECRET", "SUPER_SECRET"),
        (r#"{"rclone_rcPass": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        // user= pairs & Windows even-backslash wrapped KV (Team 8 F-02/F-10/F-11)
        ("user='\"':SUPER_SECRET", "SUPER_SECRET"),
        (r#"user=admin\ :SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"cmd C:\\"api_key=part1 SUPER_SECRET" --verbose"#,
            "SUPER_SECRET",
        ),
    ] {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R9/R10 leaked {forbidden:?} for {input:?} -> {once:?}"
        );
        let twice = sanitize_lifecycle_field(&once);
        assert_eq!(
            twice, once,
            "runner R9/R10 1-step idempotency failed for {input:?} -> {once:?} vs {twice:?}"
        );
    }

    // Structural & sibling preservation checks
    assert_eq!(
        sanitize_lifecycle_field(r#"cmd C:\\"api_key=part1 SUPER_SECRET" --verbose"#),
        r#"cmd C:\\"api_key=[REDACTED]" --verbose"#
    );
    let cookie_arr = sanitize_lifecycle_field(r#"["Cookie: {sid=SECRET", ["ok"]]"#);
    assert_eq!(cookie_arr, r#"["Cookie: [REDACTED]", ["ok"]]"#);
    serde_json::from_str::<serde_json::Value>(&cookie_arr).unwrap();

    let cookie_obj =
        sanitize_lifecycle_field(r#"{"api_key": {"cmd": "Cookie: {sid=SECRET"}, "args": "ok"}"#);
    assert!(!cookie_obj.contains("SECRET"), "{cookie_obj}");
    assert!(
        cookie_obj.contains(r#""args": "ok""#),
        "sibling field lost: {cookie_obj}"
    );

    let curl_in_key = sanitize_lifecycle_field(r#"{"curl -u 'admin:hUnt3r2_pR0d": "it's ok"}"#);
    assert_eq!(curl_in_key, r#"{"curl -u [REDACTED]": "it's ok"}"#);
    serde_json::from_str::<serde_json::Value>(&curl_in_key).unwrap();

    let embedded_kv_key = sanitize_lifecycle_field(r#"{"error: password=hUnt3r2_pR0d": "failed"}"#);
    assert_eq!(
        embedded_kv_key,
        r#"{"error: password=[REDACTED]": "[REDACTED]"}"#
    );
    serde_json::from_str::<serde_json::Value>(&embedded_kv_key).unwrap();

    let comma_urls_json = sanitize_lifecycle_field(
        r#"{"urls":"https://example.com,https://admin:hUnt3r2_pR0d@example.com"}"#,
    );
    assert_eq!(
        comma_urls_json,
        r#"{"urls":"https://example.com,https://[REDACTED]@example.com"}"#
    );
    serde_json::from_str::<serde_json::Value>(&comma_urls_json).unwrap();

    let comma_escq_key = sanitize_lifecycle_field(r#"{"a, \"password\": 1": "SUPER_SECRET"}"#);
    assert!(!comma_escq_key.contains("SUPER_SECRET"), "{comma_escq_key}");
    assert!(
        !comma_escq_key.contains(": 1\""),
        "inner secret in JSON key leaked: {comma_escq_key}"
    );

    let benign_semi_pw =
        sanitize_lifecycle_field("url=https://example.com;password=admin@SUPER_SECRET");
    assert_eq!(
        benign_semi_pw,
        "url=https://example.com;password=[REDACTED]"
    );

    // Benign preservation
    for benign in [
        "sort_key=asc bypass=true auth_token stay_visible sha256_digest verified ok",
        r#"{"flag": "-u", "ok": true}"#,
        "['https://example.com:8443','admin@example.com']",
        "https://example.com:8443,admin@example.com",
        "url=https://example.com;email=admin@example.com",
    ] {
        assert_eq!(
            sanitize_lifecycle_field(benign),
            benign,
            "benign text altered: {benign:?}"
        );
    }

    // Adaptive-n strictly linear O(N) scaling across ALL R9 DoS triggers in `sanitize_lifecycle_field`.
    type R9ScalingCase = (&'static str, fn(usize) -> String, usize, usize);
    let r9_scaling: &[R9ScalingCase] = &[
        (
            "r9_url_comma",
            |n| format!("https://a.b{}", ",a".repeat(n)),
            2_000,
            64_000,
        ),
        (
            "r9_url_semi_kv",
            |n| format!("https://a{}", ";a=1".repeat(n)),
            2_000,
            64_000,
        ),
        (
            "r9_bs17_marker_url",
            |n| {
                let mut s = String::from("\"");
                let mut k = 0usize;
                while s.len() < n {
                    s.push_str("password=[REDACTED]");
                    for _ in 0..(17 + 2 * k) {
                        s.push('\\');
                    }
                    s.push_str("\" https://a ");
                    k += 1;
                }
                s
            },
            8_192,
            131_072,
        ),
        (
            "r9_bs17_quote_scan",
            |n| {
                let mut s = String::new();
                let mut k = 0usize;
                while s.len() < n {
                    s.push_str("password=");
                    for _ in 0..(17 + 2 * k) {
                        s.push('\\');
                    }
                    s.push_str("\"a\\\" ");
                    k += 1;
                }
                s
            },
            8_192,
            131_072,
        ),
        (
            "r9_user_urn_quotes",
            |n| r#"user='u""""""""""""""""""""rn':{ "#.repeat(n),
            1_000,
            32_000,
        ),
        (
            "r9_user_sq_dq_brace",
            |n| "user='\"':x{ ".repeat(n),
            1_000,
            32_000,
        ),
        (
            "r9_curl_cross_quote",
            |n| format!("'{}\"' :x", "(-ua{".repeat(n)),
            2_000,
            64_000,
        ),
        (
            "r9_odd_bs_nested_json",
            |n| format!(r#"{}\"password": {{"v": 1}}"#, r#"\"a"#.repeat(n)),
            2_000,
            64_000,
        ),
    ];

    let started = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r9_scaling {
        let mut n = start_n;
        let (d1, d2) = loop {
            let p1 = make_payload(n);
            let t1 = std::time::Instant::now();
            let o1 = sanitize_lifecycle_field(&p1);
            let d1 = t1.elapsed();
            assert!(!o1.is_empty());
            if d1 >= std::time::Duration::from_millis(15) || n >= max_n {
                let p2 = make_payload(n * 2);
                let t2 = std::time::Instant::now();
                let o2 = sanitize_lifecycle_field(&p2);
                let d2 = t2.elapsed();
                assert!(!o2.is_empty());
                break (d1, d2);
            }
            n *= 2;
        };
        let ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
        assert!(
            ratio < 3.2,
            "runner {name} showed superlinear scaling at n={n}: d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)"
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "runner R9/R10 linear-time budget exceeded: {elapsed:?}"
    );
}

#[test]
fn test_wave1a_r10_r11_audit_regressions() {
    // 1. P0 UTF-8 slice safety on \u0022-encoded sensitive values (Team 8 F-02, Neon P0-2, Carbon F-01)
    for (input, secret) in [
        (r#"\u0022password\u0022:\u0022é\u0022"#, "é"),
        (r#"\u0022password\u0022:\u0022🚀\u0022"#, "🚀"),
        (r#"\u0022password\u0022:\u0022a🚀\u0022"#, "a🚀"),
        (r#"\u0022password\u0022:\u0022aéaa\u0022"#, "aéaa"),
        (
            r#"{"msg": "\\u0022password\\u0022:\\u0022🚀\\u0022"}"#,
            "🚀",
        ),
        (
            r#"{"msg": "\\u0022password\\u0022:\\u0022abcd🚀\\u0022"}"#,
            "abcd🚀",
        ),
        (r#"{"\u0022password\u0022:\u0022é\u0022": "x"}"#, "é"),
        (r#"{"\u0022password\u0022:\u0022a🚀\u0022": "x"}"#, "a🚀"),
    ] {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(secret),
            "runner R11 UTF-8 leaked {secret:?} for {input:?} -> {once:?}"
        );
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }

    // 2. Every R10 secret redaction & parity reproducer in `sanitize_lifecycle_field`
    let long_user_key = format!(r#"{{"{}-user": "admin:SUPER_SECRET"}}"#, "a".repeat(300));
    let long_url_userinfo = format!(
        "https://admin:{}SUPER_SECRET\\u0040example.com",
        "a".repeat(520)
    );
    let long_bs_curl_user = format!("curl --{}u0075ser admin:SUPER_SECRET", "\\".repeat(520));
    let cases: &[(&str, &str)] = &[
        // Neon P1-1 / Carbon F-03 (valid JSON preservation + redaction)
        (
            r#"{"msg": "['pg_dump', '--password', 123456789]"}"#,
            "123456789",
        ),
        (
            r#"{"msg": "['pg_dump', '--password', {'v': 'SUPER_SECRET'}]"}"#,
            "SUPER_SECRET",
        ),
        (long_user_key.as_str(), "SUPER_SECRET"),
        (
            r#"["'Cookie: a=1", {"msg": "x' https://example.com"}]"#,
            "a=1",
        ),
        (
            r#"["'Cookie: a=1", "'Cookie: a=2", "'Cookie: a=3", "'Cookie: a=4", "Authorization: Basic dXNlcjpwYXNz="]"#,
            "dXNlcjpwYXNz=",
        ),
        (
            r#"["'Cookie: a=1", "'Cookie: a=2", "'Cookie: a=3", "'Cookie: a=4", "Authorization: Basic dXNlcjpwYXNz=", "keep_me"]"#,
            "dXNlcjpwYXNz=",
        ),
        // Neon P1-2 (marker-prefixed multiline quotes)
        ("password=[REDACTED]\"\nSUPER_SECRET\"", "SUPER_SECRET"),
        ("password=[REDACTED]'\nSUPER_SECRET'", "SUPER_SECRET"),
        ("password=\"[REDACTED]\"\"\nSUPER_SECRET\"", "SUPER_SECRET"),
        (
            "curl --password [REDACTED]\"\nSUPER_SECRET\"",
            "SUPER_SECRET",
        ),
        // Team 8 F-03 / F-04 & Neon P1-3 (multiline quoted headers & obs-fold)
        (
            "curl -H \"Cookie: a=1;\nb=\" 2\";\nsid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl -H \"Cookie: a=1;\nb=\",2\";\nsid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        (
            "Cookie: a=1;\n  b=\"line2\n  sid=SUPER_SECRET",
            "SUPER_SECRET",
        ),
        ("Cookie: a=1;\n  b=\"line2\\\nSUPER_SECRET", "SUPER_SECRET"),
        ("curl -H \"Cookie: a=1\n  sid=SUPER_SECRET", "SUPER_SECRET"),
        (
            "curl -H \"Authorization: Bearer part1\n  SUPER_SECRET",
            "SUPER_SECRET",
        ),
        (
            "curl -H \"Cookie: a=1\n\"note\" sid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        // Carbon F-02 & Neon P1-4 (multiline Bearer containers & quotes)
        (
            "Bearer [\nBearer {\n  \"v\": \"SUPER_SECRET\"\n}\nstatus=ok",
            "SUPER_SECRET",
        ),
        ("Bearer \"part1\nSUPER_SECRET", "SUPER_SECRET"),
        ("Bearer {\n  \"tok\": \"SUPER_SECRET\"", "SUPER_SECRET"),
        // Neon P1-5 (CLI `=` spacing)
        (
            "curl -u= admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl --user= sk_live_SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl --proxy-user= sk_live_SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        ("curl -u= \nadmin:SUPER_SECRET", "SUPER_SECRET"),
        ("curl --password= \nSUPER_SECRET", "SUPER_SECRET"),
        ("curl --password=\t\nSUPER_SECRET", "SUPER_SECRET"),
        // Neon P1-6 & Carbon F-08 (escaped JSON argv non-strings, escaped `\"` keys, suffixed ALL-CAPS *_KEY)
        (
            r#"{"msg": "[\"pg_dump\", \"--password\", 987654321]"}"#,
            "987654321",
        ),
        (
            r#"{"msg": "[\"pg_dump\", \"--password\", {\"v\": \"SUPER_SECRET\"}]"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "{\"password\\\"b\":\"SUPER_SECRET\"}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "{\"password\\\"b\":{\"v\":\"SUPER_SECRET\"}}"}"#,
            "SUPER_SECRET",
        ),
        (
            "APP_KEY.v1=SUPER_SECRET_1 APP_KEY-prod=SUPER_SECRET_2",
            "SUPER_SECRET_1",
        ),
        (
            "APP_KEY.v1=SUPER_SECRET_1 APP_KEY-prod=SUPER_SECRET_2",
            "SUPER_SECRET_2",
        ),
        // Team 8 F-05, Neon P1-7, Carbon F-04/F-05 (URL `}`, pathless subdelim, Unicode URLs)
        (
            "https://admin:p}}SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "https://admin:p}:SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "https://admin:p},SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://ghp_SUPER_SECRET.v1;foo@github.com"}"#,
            "ghp_SUPER_SECRET",
        ),
        (
            r#"{"url": "https://alice.smith:1234;SUPER_SECRET@example.com"}"#,
            "SUPER_SECRET",
        ),
        (
            "https://ghp-SUPER-SECRET.v1;password=x@github.com",
            "ghp-SUPER-SECRET",
        ),
        (
            r#"https:\u002f\/admin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"https:\u002f/admin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"ssh://admin\u003aSUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://admin:my'SUPER_SECRET\u0040example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"endpoint": "https://admin:my\"SUPER_SECRET\u0040example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://admin:p@ss_SUPER_SECRET\u0040example.com/api"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"endpoint": "https://admin:p\u0040ss_SUPER_SECRET\u0040example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (long_url_userinfo.as_str(), "SUPER_SECRET"),
        // Team 8 F-06/F-10, Neon P1-8/P2-1, Carbon F-08 #2 (Unicode normalization & \u0022-quoted KV & user keys)
        (
            r#"\u0022password\u0022:\u0022a\u005cu0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (r#"\u0022password\u0022: 987654321"#, "987654321"),
        (
            r#"{"outer": "{\u0022password\u0022: \u0022SUPER_SECRET\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\u0022Bearer SUPER_SECRET\u0022"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"db-\u0075ser": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"user-1": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"user-name": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"user": "admin\u003aSUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"["curl", "-s\u0075", "admin:SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (r#"foo\u003aBearer SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"curl -s\u0075 admin:SUPER_SECRET https://example.com"#,
            "SUPER_SECRET",
        ),
        (long_bs_curl_user.as_str(), "SUPER_SECRET"),
        // Neon P1-9, Carbon F-06/F-07 (exempt user= watermark & multiline curl argv)
        (
            r#"user=\"system:foo user=admin:SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            r#"{\"user\": \"system:foo user=admin:SUPER_SECRET\"}"#,
            "SUPER_SECRET",
        ),
        (
            "x = \"[\\\"curl\\\",\n\\\"-su\\\", \\\"admin:SUPER_SECRET\\\"]\"",
            "SUPER_SECRET",
        ),
        (
            "users' job failed: [\"curl\",\n  \"-su\",\n  \"admin:SUPER_SECRET\"\n]",
            "SUPER_SECRET",
        ),
    ];

    for &(input, forbidden) in cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R10/R11 leaked {forbidden:?} for {input:?} -> {once:?}"
        );
        let twice = sanitize_lifecycle_field(&once);
        assert_eq!(
            twice, once,
            "runner R10/R11 1-step idempotency failed for {input:?} -> {once:?} vs {twice:?}"
        );
    }

    // 3. Valid RFC 8259 JSON & benign preservation checks (Team 8 F-08, Neon P1-1/P2-2, Carbon F-03/F-09)
    for valid_json in [
        r#"{"password":{"value":"SUPER_SECRET"}}"#,
        r#"{"token":["SECRET_A","SECRET_B"]}"#,
        r#"{"api_key": {"cmd": "Cookie: {sid=SECRET"}, "args": "ok"}"#,
        r#"{"a\"password\"b": {"v": "SUPER_SECRET"}}"#,
        r#"{"a, \"password\": 1": {"v": "SUPER_SECRET"}}"#,
        r#"{"msg": "['pg_dump', '--password', 123456789]"}"#,
        r#"{"msg": "['pg_dump', '--password', {'v': 'SUPER_SECRET'}]"}"#,
        r#"{"msg": "{\"password\\\"b\":\"SUPER_SECRET\"}"}"#,
        r#"{"msg": "{\"password\\\"b\":{\"v\":\"SUPER_SECRET\"}}"}"#,
        r#"["'Cookie: a=1", {"msg": "x' https://example.com"}]"#,
        r#"["'Cookie: a=1", "'Cookie: a=2", "'Cookie: a=3", "'Cookie: a=4", "Authorization: Basic dXNlcjpwYXNz="]"#,
        r#"["'Cookie: a=1", "'Cookie: a=2", "'Cookie: a=3", "'Cookie: a=4", "Authorization: Basic dXNlcjpwYXNz=", "keep_me"]"#,
    ] {
        let out = sanitize_lifecycle_field(valid_json);
        serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
            panic!("runner R11 broke valid JSON ({e}) for {valid_json:?} -> {out:?}")
        });
        assert_eq!(sanitize_lifecycle_field(&out), out);
    }

    let j3_out = sanitize_lifecycle_field(
        r#"["'Cookie: a=1", "'Cookie: a=2", "'Cookie: a=3", "'Cookie: a=4", "Authorization: Basic dXNlcjpwYXNz=", "keep_me"]"#,
    );
    assert!(j3_out.contains("keep_me"), "j3 dropped sibling: {j3_out}");

    // Carbon F-09 benign curl short-flag argument preservation
    let curl_ua = r#"{"args": ["curl", "-AMozillaUbuntu", "https://example.com"]}"#;
    assert_eq!(sanitize_lifecycle_field(curl_ua), curl_ua);

    // Neon P2-2 unclosed Bearer { preserves unrelated trailing benign lines
    let unclosed_bearer = "Bearer {\nbenign_line_1=ok\nbenign_line_2={\"x\":1}";
    let unclosed_out = sanitize_lifecycle_field(unclosed_bearer);
    assert!(
        unclosed_out.contains("benign_line_1=ok")
            && unclosed_out.contains("benign_line_2={\"x\":1}"),
        "unclosed Bearer over-redacted benign lines: {unclosed_out:?}"
    );
    assert_eq!(sanitize_lifecycle_field(&unclosed_out), unclosed_out);

    // 4. Adaptive-n linear scaling on new R10/R11 DoS vectors in `sanitize_lifecycle_field`
    type R11ScalingCase = (&'static str, fn(usize) -> String, usize, usize);
    let r11_scaling: &[R11ScalingCase] = &[
        (
            "r11_bearer_unclosed_braces",
            |n| format!("{}}}", "Bearer {\n".repeat(n)),
            2_000,
            64_000,
        ),
        (
            "r11_bearer_unclosed_brackets_then_balanced",
            |n| format!("{}Bearer {{\n\"v\":\"s\"\n}}", "Bearer [\n".repeat(n)),
            2_000,
            64_000,
        ),
        (
            "r11_exempt_user_unclosed",
            |n| r#"user=\"system:foo "#.repeat(n),
            1_000,
            32_000,
        ),
        (
            "r11_long_user_json_key",
            |n| format!(r#"{{"{}-user":"admin:sec"}}"#, "a".repeat(n)),
            8_000,
            256_000,
        ),
        (
            "r11_url_password_braces",
            |n| format!("https://a:p{}}}@h", "}".repeat(n)),
            8_000,
            256_000,
        ),
        (
            "r11_marker_multiline_unclosed",
            |n| "password=[REDACTED]\"\n".repeat(n),
            2_000,
            64_000,
        ),
    ];

    let started = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r11_scaling {
        let mut n = start_n;
        let (d1, d2) = loop {
            let p1 = make_payload(n);
            let t1 = std::time::Instant::now();
            let o1 = sanitize_lifecycle_field(&p1);
            let d1 = t1.elapsed();
            assert!(!o1.is_empty());
            if d1 >= std::time::Duration::from_millis(15) || n >= max_n {
                let p2 = make_payload(n * 2);
                let t2 = std::time::Instant::now();
                let o2 = sanitize_lifecycle_field(&p2);
                let d2 = t2.elapsed();
                assert!(!o2.is_empty());
                break (d1, d2);
            }
            n *= 2;
        };
        let ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
        assert!(
            ratio < 3.2,
            "runner {name} showed superlinear scaling at n={n}: d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)"
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "runner R10/R11 linear-time budget exceeded: {elapsed:?}"
    );
}

#[test]
fn test_wave1a_r11_r12_audit_regressions() {
    // 1. All R11 secret redaction, JSON preservation, and 1-step idempotency reproducers in `sanitize_lifecycle_field`
    let long_u_key = format!(
        r#"{{"outer": "{{\\u0022{}_password\\u0022: \\u0022SUPER_SECRET\\u0022}}"}}"#,
        "x".repeat(130)
    );
    let long_u_key_raw = format!(
        r#"\u0022{}_password\u0022:\u0022SUPER_SECRET\u0022"#,
        "a".repeat(130)
    );
    let long_bs_argv = format!(
        r#"["curl", "-s{}u0075", "admin:SUPER_SECRET"]"#,
        "\\".repeat(520)
    );
    let cases: &[(&str, &str)] = &[
        // URL credentials with `\"`/`"`/`'` + delimiters, mixed/depth-3 slashes, multi-URL Unicode, localhost/[::1]
        (
            r#"{"url": "https://admin:p\":SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p\";SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"u": "https://admin:my\",SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"u": "https://admin:my\"}SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"u": "https://admin:my\"'SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            "https://admin:p\";SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "'https://admin:p',SUPER_SECRET@example.com'",
            "SUPER_SECRET",
        ),
        (
            r#"https:/\/admin:SUPER_SECRET@example.com/api"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "{\"url\": \"https:\\/\\/admin:SUPER_SECRET@example.com\"}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "{\"url\": \"https:\\\\\\/\\\\\\/admin:SUPER_SECRET@example.com\"}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://example.com,https\u003a//admin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://example.com;https:\u002f/admin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://example.com,https:\u002f\u002fadmin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            "https://ghp-SUPER-SECRET.v1;password=x@localhost",
            "ghp-SUPER-SECRET",
        ),
        (
            "https://ghp-SUPER-SECRET.v1;password=x@[::1]",
            "ghp-SUPER-SECRET",
        ),
        // User pairs, compound keys, multiline user, wrapped quote, space-containing JSON user
        (
            r#"{"user=admin:SEC1, user": "admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"user=admin:SEC1, user": "admin:SUPER_SECRET"}"#, "SEC1"),
        (
            r#"{"msg": "{\u0022user\u0022:\u0022my user:SUPER_SECRET\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"vault/user/primary":"admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"user/v1": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"user\"v1": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        ("env 'db-user=admin:part1 SUPER_SECRET'", "SUPER_SECRET"),
        ("user=\"admin:\nSUPER_SECRET\"", "SUPER_SECRET"),
        // Argv unclosed inner quotes & truncated multiline
        (
            r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "[\"pg_dump\", \"--password\", \"SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "note": "it's ok"}"#,
            "SUPER_SECRET",
        ),
        (
            "[\"pg_dump\", \"--password\", \"line1\nSUPER_SECRET_LINE2",
            "SUPER_SECRET_LINE2",
        ),
        // Multiline Bearer containers & headers
        (
            "Bearer {\n  \"a\": \"line1\n  } still_in_str\",\n  \"b\": \"SUPER_SECRET\"\n}",
            "SUPER_SECRET",
        ),
        (
            "Bearer [\n  \"line1\n  ] still_in_str\",\n  \"SUPER_SECRET\"\n]",
            "SUPER_SECRET",
        ),
        ("curl -H \"Cookie: a=1;\nsid=SUPER_SECRET", "SUPER_SECRET"),
        (
            "curl -H \"Cookie: a=1;\nb=\"line2\nline3\";\nsid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        // QuoteStack stray single quote (Carbon F-05)
        (
            r#"{"msg": "'foo --password ';;SUPER_SECRET'", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "'foo --password '&&SUPER_SECRET'", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "'foo --password '}}SUPER_SECRET'", "ok": true}"#,
            "SUPER_SECRET",
        ),
        // Auth left delims & JSON-escaped \t / \n (Team 8 F-09, Neon F-10 #4)
        ("<auth>Bearer SUPER_SECRET</auth>", "SUPER_SECRET"),
        (
            r#"{"msg": "failed with Bearer\tSUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"cmd": "curl\t-u\tadmin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"{"a": "pg_dump --password\tSUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"msg": "password=\n  SUPER_SECRET"}"#, "SUPER_SECRET"),
        // Unicode escapes & \u0022-encoded JSON-in-JSON (Team 8 F-07, Neon F-10/F-14, Carbon F-04)
        (
            r#"{"outer": "{\u0022pass\u005cu0077ord\u0022: \u0022SUPER_SECRET\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "{\u0022url\u0022: \u0022https://admin:SUPER_SECRET\u005cu0040example.com\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"\u0022password\u0022 \u003a \u0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            r#"\u0022pass\u0022\u003a\u0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            r#"\u0022APP_KEY\u0022\u003a\u0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            r#"\u0022user\u0022\u003a\u0022admin:SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            "{\\u0022password\\u0022: {\n  \\u0022v\\u0022: \\u0022SUPER_SECRET\\u0022\n}}",
            "SUPER_SECRET",
        ),
        (
            r#"\u0022vault\/password\u0022:\u0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "{\\u0022password\\u0022: \\u0022a\\\"SUPER_SECRET\\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "{\\u0022vault\\\\/password\\u0022: \\u0022SUPER_SECRET\\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "[\\u0022pg_dump\\u0022, \\u0022--password\\u0022, \\u0022SUPER_SECRET\\u0022]"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"a": "password\u0009=SUPER_SECRET", "b": "\u0022"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -suadmin\u003aSUPER_SECRET https://example.com"#,
            "SUPER_SECRET",
        ),
        (r#"["tool","-u","admin\u003aSUPER_SECRET"]"#, "SUPER_SECRET"),
        (long_u_key.as_str(), "SUPER_SECRET"),
        (long_u_key_raw.as_str(), "SUPER_SECRET"),
        (long_bs_argv.as_str(), "SUPER_SECRET"),
    ];

    for &(input, forbidden) in cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R11/R12 leaked {forbidden:?} for {input:?} -> {once:?}"
        );
        let twice = sanitize_lifecycle_field(&once);
        assert_eq!(
            twice, once,
            "runner R11/R12 1-step idempotency failed for {input:?} -> {once:?} vs {twice:?}"
        );
    }

    // 2. Pretty-printed multiline JSON containers preserve valid RFC 8259 JSON (Neon F-14 #2 / Carbon F-08)
    let pretty_ml =
        "{\n  \"password\": {\n    \"value\": \"SUPER_SECRET\"\n  },\n  \"ok\": true\n}";
    let pretty_out = sanitize_lifecycle_field(pretty_ml);
    assert_eq!(
        pretty_out,
        "{\n  \"password\": \"[REDACTED]\",\n  \"ok\": true\n}"
    );
    serde_json::from_str::<serde_json::Value>(&pretty_out).unwrap();
    assert_eq!(sanitize_lifecycle_field(&pretty_out), pretty_out);

    // Sibling & valid JSON preservation (Carbon F-03, Team 8 F-10, Carbon F-07)
    for (valid_json, must_keep) in [
        (
            r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "ok": true}"#,
            r#""ok": true"#,
        ),
        (
            r#"{"msg": "[\"pg_dump\", \"--password\", \"SUPER_SECRET", "ok": true}"#,
            r#""ok": true"#,
        ),
        (
            r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "note": "it's ok"}"#,
            r#""note": "it's ok""#,
        ),
        (
            r#"{"msg": "{\"a\": \"Authorization: Basic dXNlcjpwYXNz=\", \" b\": \"keep_me\"}"}"#,
            "keep_me",
        ),
        (
            r#"{"msg": "Authorization: Bearer SUPER_SECRET\nstep 2: service healthy", "ok": true}"#,
            "step 2: service healthy",
        ),
    ] {
        let out = sanitize_lifecycle_field(valid_json);
        assert!(!out.contains("SUPER_SECRET") && !out.contains("dXNlcjpwYXNz="));
        assert!(
            out.contains(must_keep),
            "runner R12 dropped {must_keep:?} for {valid_json:?} -> {out:?}"
        );
        serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
            panic!("runner R12 broke JSON ({e}) for {valid_json:?} -> {out:?}")
        });
        assert_eq!(sanitize_lifecycle_field(&out), out);
    }

    // Benign preservation (Neon F-13, Team 8 F-10, Neon F-12)
    assert_eq!(
        sanitize_lifecycle_field(
            r#"curl -H "Authorization: Basic dXNlcjpwYXNz=" --data "" https://example.com"#
        ),
        r#"curl -H "Authorization: [REDACTED]" --data "" https://example.com"#
    );
    for benign in [
        r#"{"user": "see https://example.com"}"#,
        r#"{"user": "expected Cookie: "}"#,
        "\u{00A0}-su benign_arg",
    ] {
        assert_eq!(
            sanitize_lifecycle_field(benign),
            benign,
            "runner R12 altered benign input {benign:?}"
        );
    }

    // 3. Adaptive-n linear scaling across ALL 5 new R11 quadratic DoS vectors
    type R12ScalingCase = (&'static str, fn(usize) -> String, usize, usize);
    let r12_scaling: &[R12ScalingCase] = &[
        (
            "r12_hdr_ml_param_quotes",
            |n| format!("\"Cookie: a=1\n{}\"", "b=\"2\" ".repeat(n)),
            1_000,
            64_000,
        ),
        (
            "r12_hdr_ml_standalone_quotes",
            |n| format!("\"Cookie: a=1\n{}", "\"x\" ".repeat(n)),
            1_000,
            64_000,
        ),
        (
            "r12_unicode_kv_strings",
            |n| r#"\u0022pwd\u0022:\u0022a\u0022,"#.repeat(n),
            1_000,
            64_000,
        ),
        (
            "r12_unicode_kv_containers",
            |n| r#"\u0022pwd\u0022:{},"#.repeat(n),
            1_000,
            64_000,
        ),
        (
            "r12_esc_sq_key_rescan",
            |n| r#"\'a password=[REDACTED] "#.repeat(n),
            1_000,
            64_000,
        ),
    ];

    let started = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r12_scaling {
        let mut n = start_n;
        let (d1, d2) = loop {
            let p1 = make_payload(n);
            let t1 = std::time::Instant::now();
            let o1 = sanitize_lifecycle_field(&p1);
            let d1 = t1.elapsed();
            assert!(!o1.is_empty());
            if d1 >= std::time::Duration::from_millis(15) || n >= max_n {
                let p2 = make_payload(n * 2);
                let t2 = std::time::Instant::now();
                let o2 = sanitize_lifecycle_field(&p2);
                let d2 = t2.elapsed();
                assert!(!o2.is_empty());
                break (d1, d2);
            }
            n *= 2;
        };
        let ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
        assert!(
            ratio < 3.2,
            "runner {name} showed superlinear scaling at n={n}: d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)"
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "runner R11/R12 linear-time budget exceeded: {elapsed:?}"
    );
}

#[test]
fn test_wave1a_r12_r13_audit_regressions() {
    let long_chained_eq = format!("{}password\\u005cu003dSUPER_SECRET", "a".repeat(520));
    let cases: &[(&str, &str)] = &[
        // Team 8 F-04: CRLF `\r\n  ` and `\u000d\u000a  ` obs-fold headers
        (
            r#"{"hdr": "Authorization: Bearer part1\r\n  SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"hdr": "Cookie: sid=part1\r\n  SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"hdr": "Authorization: Bearer part1\u000d\u000a  SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"hdr": "Cookie: sid=part1\u000d\u000a  SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"Authorization: Bearer part1\r\n  SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (r#"Cookie: sid=part1\r\n  SUPER_SECRET"#, "SUPER_SECRET"),
        ("Authorization: Bearer\r\n  SUPER_SECRET", "SUPER_SECRET"),
        ("Cookie: sid=part1;\r\n  SUPER_SECRET", "SUPER_SECRET"),
        (
            r#"log="Cookie: sid=part1\r\n  SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        // Team 8 F-05 / Carbon F-04: chained `\u005cu00XX` auth scheme & long fallback separators
        (
            r#"{"msg": "hdr\u005cu0020Bearer SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\u005cu0022Bearer SUPER_SECRET\u005cu0022"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "Bearer\u005cu0020SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "Bearer\u005cu0009SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (long_chained_eq.as_str(), "SUPER_SECRET"),
        // Team 8 F-06: pretty JSON-in-JSON argv with literal `\n`, pathed `curl.exe`, uppercase `/CURL`
        (
            r#"{"cmd": "[\n  \"pg_dump\",\n  \"--password\",\n  \"SUPER_SECRET\"\n]"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"["C:\\Windows\\System32\\curl.exe", "-su", "admin:SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (
            r#"["/usr/bin/CURL", "-su", "admin:SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        // Team 8 F-07: unclosed multiline quoted values in unquoted HTTP headers
        (
            "Authorization: Bearer \"line1\nSUPER_SECRET",
            "SUPER_SECRET",
        ),
        ("Cookie: sid=\"line1\nSUPER_SECRET", "SUPER_SECRET"),
        ("X-Api-Key: \"line1\nSUPER_SECRET", "SUPER_SECRET"),
        ("Cookie: a=1;\n  b=\"line2\nSUPER_SECRET", "SUPER_SECRET"),
        // Team 8 F-08 / Carbon F-03: URL passwords with `\"`/`,`/`:`/`}`/`;"`/`,"`/`','`
        (
            r#"{"url": "https://admin:p\",\"SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p\":\"SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p\"},SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            "https://admin:p\";\"SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "https://admin:p\",\"SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "https://admin:p;\"SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "https://admin:p,\"SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "https://admin:p','SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        // Team 8 F-09: stray quote before multiline quoted secret
        (
            "warn: unmatched \" in input; password=\"line1\nSUPER_SECRET\"",
            "SUPER_SECRET",
        ),
        (
            "err=\"unclosed Bearer \"line1\nSUPER_SECRET\"",
            "SUPER_SECRET",
        ),
        // Carbon F-06: `\u0022` multiline, truncated, unquoted, and curl argv
        (
            "\\u0022password\\u0022: \\u0022line1\nSUPER_SECRET\\u0022",
            "SUPER_SECRET",
        ),
        (
            r#"\u0022password\u0022: \u0022SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\u0022password\u0022: \u0022SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            r#"\u0022password\u0022: sk_live_SUPER_SECRET"#,
            "sk_live_SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-su\u0022, \u0022admin:SUPER_SECRET\u0022]"#,
            "SUPER_SECRET",
        ),
        // Team 8 F-10: NBSP `\u{00A0}` separators on auth schemes, CLI flags, and curl user flags
        ("Bearer\u{00A0}SUPER_SECRET", "SUPER_SECRET"),
        ("--password\u{00A0}SUPER_SECRET", "SUPER_SECRET"),
        (
            "curl --user\u{00A0}admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl --proxy-user\u{00A0}admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl -u\u{00A0}admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl --user\u{00A0}admin:SUPER_SECRET\u{00A0}https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl\u{00A0}-su\u{00A0}admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        // Carbon F-07: multiline quoted shell `curl` preserving curl context across `\n`
        (
            "sh -c \"curl\n  -su admin:SUPER_SECRET https://example.com\"",
            "SUPER_SECRET",
        ),
        (
            "sh -c 'curl\n  -su admin:SUPER_SECRET https://example.com'",
            "SUPER_SECRET",
        ),
        // Carbon F-05: `user=` watermark poisoning after multi-word exempt prefix
        (
            r#"user="see system:x user=admin:SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"{"log": "user='see system:x user=admin:SUPER_SECRET'"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"user="ref urn:oid:1 user=root:SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        // Team 8 F-11 & Carbon F-08: JSON user keys with spaces/brackets & `\t` in JSON keys
        (r#"{"user name": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"user[0]": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"cmd\t--password\tSUPER_SECRET":"ok"}"#, "SUPER_SECRET"),
        (r#"{"hdr\tBearer\tSUPER_SECRET":"ok"}"#, "SUPER_SECRET"),
    ];

    for &(input, forbidden) in cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R12/R13 leaked {forbidden:?} for {input:?} -> {once:?}"
        );
        let twice = sanitize_lifecycle_field(&once);
        assert_eq!(
            twice, once,
            "runner R12/R13 1-step idempotency failed for {input:?} -> {once:?} vs {twice:?}"
        );
    }

    // Verify trailing URL preserved on NBSP curl and multiline quoted shell curl (Team 8 F-10 & Carbon F-07)
    for preserve_url in [
        "curl --user\u{00A0}admin:SUPER_SECRET\u{00A0}https://example.com",
        "sh -c \"curl\n  -su admin:SUPER_SECRET https://example.com\"",
        "sh -c 'curl\n  -su admin:SUPER_SECRET https://example.com'",
    ] {
        let out = sanitize_lifecycle_field(preserve_url);
        assert!(
            !out.contains("SUPER_SECRET") && out.contains("https://example.com"),
            "runner R13 lost trailing URL for {preserve_url:?} -> {out:?}"
        );
    }

    // Carbon F-02 & Carbon F-06: valid RFC 8259 JSON & sibling preservation
    for benign_json in [
        r#"{"a":["https://example.com:8443",1,["alice@corp.com"]]}"#,
        r#"{"a":["https://example.com:8443",true,["alice@corp.com"]]}"#,
        r#"{"a":["https://example.com:8443",null,["alice@corp.com"]]}"#,
        r#"{"msg": "https://example.com\nadmin@corp.com"}"#,
        r#"{"cmd": "curl", "items": ["-su", "benign_item"]}"#,
    ] {
        let out = sanitize_lifecycle_field(benign_json);
        assert_eq!(
            out, benign_json,
            "runner R13 altered benign valid JSON {benign_json:?} -> {out:?}"
        );
        serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
            panic!("runner R13 broke valid JSON ({e}) for {benign_json:?} -> {out:?}")
        });
    }

    for (secret_json, secret, must_keep) in [
        (
            r#"{"a":["\\u0022password\\u0022:\\u0022Part1",1,["\\u0022"]]}"#,
            "Part1",
            r#",1,["\\u0022"]"#,
        ),
        (
            r#"{"msg": "\u0022password\u0022: \u0022SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
            r#""ok": true"#,
        ),
        (
            r#"{"url": "https://admin:p\",\"SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
            "@example.com/api",
        ),
        (
            r#"{"url": "https://admin:p\":\"SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
            "@example.com/api",
        ),
        (
            r#"{"url": "https://admin:p\"},SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
            "@example.com/api",
        ),
    ] {
        let out = sanitize_lifecycle_field(secret_json);
        assert!(
            !out.contains(secret),
            "runner R13 leaked {secret:?} for {secret_json:?} -> {out:?}"
        );
        assert!(
            out.contains(must_keep),
            "runner R13 dropped {must_keep:?} for {secret_json:?} -> {out:?}"
        );
        serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
            panic!("runner R13 broke valid JSON ({e}) for {secret_json:?} -> {out:?}")
        });
        assert_eq!(sanitize_lifecycle_field(&out), out);
    }

    // Carbon F-10 #2: quoted HTTP header preserves trailing prose and later quoted server name
    let header_prose = r#"sent header "Cookie: sid=SUPER_SECRET" to server "api.internal""#;
    let header_prose_out = sanitize_lifecycle_field(header_prose);
    assert_eq!(
        header_prose_out,
        r#"sent header "Cookie: [REDACTED]" to server "api.internal""#
    );
    assert_eq!(
        sanitize_lifecycle_field(&header_prose_out),
        header_prose_out
    );

    // Team 8 F-02 / Carbon F-01 & Team 8 F-03: adaptive-n linear scaling on R12 DoS vectors
    type R13ScalingCase = (&'static str, fn(usize) -> String, usize, usize);
    let r13_scaling: &[R13ScalingCase] = &[
        (
            "r13_quoted_argv_enclosing_dq",
            |n| format!(r#"{{"msg": "{}"}}"#, "'-u','a',".repeat(n)),
            1_000,
            16_000,
        ),
        (
            "r13_unicode_quoted_cache_eviction",
            |n| {
                let mut s = String::new();
                for i in 1..=16 {
                    s.push_str(&format!(
                        r#"{}u0022password{}u0022:{}u0022a "#,
                        "\\".repeat(i),
                        "\\".repeat(i),
                        "\\".repeat(i)
                    ));
                }
                let unit = format!(
                    r#"{}u005c{}u0022--password="#,
                    "\\".repeat(17),
                    "\\".repeat(17)
                );
                s.push_str(&unit.repeat(n));
                s
            },
            500,
            8_000,
        ),
    ];

    let started = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r13_scaling {
        let mut n = start_n;
        let (d1, d2) = loop {
            let p1 = make_payload(n);
            let t1 = std::time::Instant::now();
            let o1 = sanitize_lifecycle_field(&p1);
            let d1 = t1.elapsed();
            assert!(!o1.is_empty());
            if d1 >= std::time::Duration::from_millis(15) || n >= max_n {
                let p2 = make_payload(n * 2);
                let t2 = std::time::Instant::now();
                let o2 = sanitize_lifecycle_field(&p2);
                let d2 = t2.elapsed();
                assert!(!o2.is_empty());
                break (d1, d2);
            }
            n *= 2;
        };
        let ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
        assert!(
            ratio < 3.2,
            "runner {name} showed superlinear scaling at n={n}: d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)"
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "runner R12/R13 linear-time budget exceeded: {elapsed:?}"
    );
}

#[test]
fn test_wave1a_r14_audit_regressions() {
    let pw = concat!("pass", "word");
    let tok = concat!("tok", "en");
    let auth_hdr = concat!("authori", "zation");
    let pa = concat!("pa", "ss");
    let au = concat!("au", "th");
    let sec = concat!("SEC", "RET");
    let api_sec = concat!("api_", "secret");

    let secret_cases: Vec<(String, &'static str)> = vec![
        // Team 8 F-03: `\u0022...\u0022` values with spaces & multiline `\n`, auth schemes, mixed escapes, argv
        (
            format!("{pw}=\\u0022part1 SUPER_SECRET\\u0022"),
            "SUPER_SECRET",
        ),
        (
            format!("{pw}=\\u0022line1\nSUPER_SECRET\\u0022"),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "{pw}=\\u0022part1 SUPER_SECRET\\u0022", "ok": true}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"\u0022{tok}\u0022: Basic dXNlcjpwYXNz"#),
            "dXNlcjpwYXNz",
        ),
        (
            format!(r#"\u0022{pw}\u0022: Bearer SUPER_SECRET"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "\\u0022{auth_hdr}\\u0022: Bearer SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"\u0022{pw}\u0022: $'SUPER_SECRET'"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"\u0022{pw}\u0022: part1\ SUPER_SECRET"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"log: \u0022{pw}\u0022: \"SUPER_SECRET\""#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "\\u0022{pw}\\u0022: \\\"SUPER_SECRET\\\""}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "\u0022{pw}\u0022: \"SUPER_SECRET\""}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"[\u0022pg_dump\u0022, \u0022--{pw}\u0022, "SUPER_SECRET"]"#),
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-uadmin:SUPER_SECRET\u0022]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-u=admin:SUPER_SECRET\u0022]"#.to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-07: `\u0022` keys/argv with `\u00XX`, spaces, multiline
        (
            format!(
                r#"[\u0022pg_dump\u0022, \u0022--\u0070ass{word}\u0022, \u0022SUPER_SECRET\u0022]"#,
                word = "word"
            ),
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-\u0075\u0022, \u0022SUPER_SECRET\u0022]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"\u0022\u0070ass{word} v2\u0022: \u0022SUPER_SECRET\u0022"#,
                word = "word"
            ),
            "SUPER_SECRET",
        ),
        (
            "user=\\u0022admin:\nSUPER_SECRET\\u0022".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("--{pw} \\u0022line1\nSUPER_SECRET\\u0022"),
            "SUPER_SECRET",
        ),
        (
            "Authorization: Bearer \\u0022line1\nSUPER_SECRET\\u0022".to_string(),
            "SUPER_SECRET",
        ),
        (
            "curl -u \\u0022admin:\nSUPER_SECRET\\u0022 https://example.com".to_string(),
            "SUPER_SECRET",
        ),
        // Team 8 F-04: single-quoted & escaped keys containing `[REDACTED]`
        (
            format!("{{'https://admin:SEC1@example.com {pw}': 'SUPER_SECRET'}}"),
            "SUPER_SECRET",
        ),
        (
            format!("{{'https://admin:SEC1@example.com {pw}': 'SUPER_SECRET'}}"),
            "SEC1",
        ),
        (
            format!("{{'cmd --{pw} SEC1': 'SUPER_SECRET'}}"),
            "SUPER_SECRET",
        ),
        (format!("{{'cmd --{pw} SEC1': 'SUPER_SECRET'}}"), "SEC1"),
        (
            format!(
                r#"{{"msg": "{{\"https://admin:SEC1@example.com {pw}\": \"SUPER_SECRET\"}}"}}"#
            ),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"{{"msg": "{{\"https://admin:SEC1@example.com {pw}\": \"SUPER_SECRET\"}}"}}"#
            ),
            "SEC1",
        ),
        // Team 8 F-05 & F-06: JSON-escaped `\n` inside escaped header quotes & multiline Digest
        (
            "{\"hdr\": \"Cookie: sid=\\\"line1\nSUPER_SECRET_LINE2\\\"\"}".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "{\"hdr\": \"Authorization: Bearer \\\"line1\nSUPER_SECRET_LINE2\\\"\"}".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "{\"cmd\": \"curl -H 'Cookie: a=1;\nSUPER_SECRET_LINE2\"}".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "Digest username=\"admin\", response=\"line1\nSUPER_SECRET_LINE2\"".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "Digest username=\"line1\npart2\", response=\"SUPER_SECRET_HEX\"".to_string(),
            "SUPER_SECRET_HEX",
        ),
        // Neon AUD-04..AUD-09: NBSP `\u00a0`, non-`00` Unicode escapes, `\u005c\u0022`, bundled `-su<TOKEN>`, URL `","`+`\u0040`/`\u002f`
        (r#"Bearer\u00a0SUPER_SECRET"#.to_string(), "SUPER_SECRET"),
        (format!(r#"--{pw}\u00a0SUPER_SECRET"#), "SUPER_SECRET"),
        (
            r#"curl\u00a0-u\u00a0SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"Bearer\u00a0SUPER_SECRET": "ok"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"\u4e2d\u0070assword": "SUPER_SECRET", "ok": true}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"\ud83d\ude80_\u0070assword": "SUPER_SECRET", "ok": true}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{'\u4e2d\u0070assword': 'SUPER_SECRET'}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"{{"a":"{{\u0022b\u0022:\u0022{{\u005c\u0022{pw}\u005c\u0022:\u005c\u0022SUPER_SECRET\u005c\u0022}}\u0022}}"}}"#
            ),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"err: {{\u005c\u0022{pw}\u005c\u0022:\u005c\u0022SUPER_SECRET\u005c\u0022}}"#
            ),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-suSUPER_SECRET", "https://example.com"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-sUSUPER_SECRET", "https://example.com"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"https://admin:p","SUPER_SECRET\u0040example.com/api"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"https:\u002f\u002fadmin:p","SUPER_SECRET@example.com/api"#.to_string(),
            "SUPER_SECRET",
        ),
        // Carbon CRATE-W1A-04 & CRATE-W1A-05 & CRATE-W1A-06 & CRATE-W1A-07 + AUD-16
        (
            r#"\u0063url -su admin:SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl -\u0075admin:SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl -s\u0075admin:SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": ["\u0063url", "-su", "admin:SUPER_SECRET"]}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": ["curl", "-\u0075sk_live_SUPER_SECRET"]}"#.to_string(),
            "SUPER_SECRET",
        ),
        (format!("café_{pa}=SUPER_SECRET"), "SUPER_SECRET"),
        (format!("café_{au}=SUPER_SECRET"), "SUPER_SECRET"),
        (
            format!(r#"{{"café_{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u2603_{pa}\u0077ord": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u2014{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\uD83D\uDD11{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"{"user (primary)": "admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"\u2014user": "admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        ("éCookie: sid=SUPER_SECRET".to_string(), "SUPER_SECRET"),
    ];

    for (input, forbidden) in &secret_cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R14 leaked {forbidden:?} for {input:?} -> {once:?}"
        );
        let twice = sanitize_lifecycle_field(&once);
        assert_eq!(
            twice, once,
            "runner R14 1-step idempotency failed for {input:?} -> {once:?} vs {twice:?}"
        );
    }

    // Neon AUD-12: Windows paths with `\\t-u` / `\\t--password` must NOT be over-redacted
    for benign in [
        r#"{"path": "C:\\t-u benign_arg"}"#.to_string(),
        format!(r#"log: C:\\t--{pw} benign_arg"#),
        format!(r#"log: C:\t--{pw} benign_arg"#),
        // Neon AUD-11: empty sensitive headers must not over-redact subsequent unrelated lines/headers
        "Cookie:\n\nstep 2: service healthy".to_string(),
        "Cookie:\nHost: example.com".to_string(),
        "Authorization:\n\nstep 2: service healthy".to_string(),
        // Team 8 F-02: valid RFC 8259 JSON with >64-byte numeric literal before sibling email
        r#"{"a":["https://user:notaport",0.0000000000000000000000000000000000000000000000000000000000000001,{"alice@corp.com":1}]}"#.to_string(),
        // Carbon CRATE-W1A-01: valid RFC 8259 JSON containing `"-u":null`
        r#"["",{"":{"-u":null}}]"#.to_string(),
    ] {
        let out = sanitize_lifecycle_field(&benign);
        assert_eq!(
            out, benign,
            "runner R14 altered benign input {benign:?} -> {out:?}"
        );
        if benign.starts_with(['{', '[']) {
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("runner R14 broke benign JSON ({e}) for {benign:?} -> {out:?}")
            });
        }
    }

    // Carbon CRATE-W1A-02 & CRATE-W1A-03: JSON validity, sibling preservation, and 1-step idempotency
    let single_q_obj = format!(r#"{{"'{sec}":{{"":"","":{{}}}}}}"#);
    let single_q_obj_out = sanitize_lifecycle_field(&single_q_obj);
    assert_eq!(single_q_obj_out, format!(r#"{{"'{sec}":"[REDACTED]"}}"#));
    serde_json::from_str::<serde_json::Value>(&single_q_obj_out).unwrap();
    assert_eq!(
        sanitize_lifecycle_field(&single_q_obj_out),
        single_q_obj_out
    );

    let single_q_arr = format!(r#"["'{sec}",[{{"[REDACTED]':{au}":5}},""]]"#);
    let single_q_arr_out = sanitize_lifecycle_field(&single_q_arr);
    serde_json::from_str::<serde_json::Value>(&single_q_arr_out).unwrap_or_else(|e| {
        panic!("runner R14 broke JSON ({e}) for {single_q_arr:?} -> {single_q_arr_out:?}")
    });
    assert_eq!(
        sanitize_lifecycle_field(&single_q_arr_out),
        single_q_arr_out
    );

    let inner_colon_arr = format!(r#"["\"{sec}:\":\"}}"]"#);
    let ic1 = sanitize_lifecycle_field(&inner_colon_arr);
    let ic2 = sanitize_lifecycle_field(&ic1);
    assert_eq!(ic2, ic1, "runner R14 non-idempotent on {inner_colon_arr:?}");

    let inner_colon_sib = format!(r#"{{"outer": "{{\"{api_sec}:\": 123, \"sibling\": \"ok\"}}"}}"#);
    let ics_out = sanitize_lifecycle_field(&inner_colon_sib);
    assert!(
        ics_out.contains(r#"\"sibling\": \"ok\""#) || ics_out.contains(r#"\"sibling\":\"ok\""#),
        "runner R14 dropped sibling field: {ics_out}"
    );
    assert!(!ics_out.contains("123"), "runner R14 leaked 123: {ics_out}");
    serde_json::from_str::<serde_json::Value>(&ics_out).unwrap();
    assert_eq!(sanitize_lifecycle_field(&ics_out), ics_out);

    let nested_u22_bearer = r#"{"outer": "{\"msg\": \"\\u0022Bearer SUPER_SECRET\\u0022\"}"}"#;
    let nested_u22_out = sanitize_lifecycle_field(nested_u22_bearer);
    assert!(!nested_u22_out.contains("SUPER_SECRET"), "{nested_u22_out}");
    let outer_v: serde_json::Value = serde_json::from_str(&nested_u22_out).unwrap();
    let inner_s = outer_v["outer"].as_str().unwrap();
    serde_json::from_str::<serde_json::Value>(inner_s).unwrap_or_else(|e| {
        panic!("runner R14 broke inner JSON ({e}): {inner_s} (outer={nested_u22_out})")
    });
    assert_eq!(sanitize_lifecycle_field(&nested_u22_out), nested_u22_out);

    // Team 8 F-01 = Neon AUD-01, AUD-02, AUD-03: adaptive-n linear scaling across R13 DoS vectors
    type R14ScalingCase = (&'static str, fn(usize) -> String, usize, usize);
    let r14_scaling: &[R14ScalingCase] = &[
        (
            "r14_user_url_brace",
            |n| "user=foo://{".repeat(n),
            1_000,
            16_000,
        ),
        (
            "r14_attached_curl_esc_nl",
            |n| format!(r#"{{"msg":"{}:"}}"#, r#"-ua\n"#.repeat(n)),
            1_000,
            16_000,
        ),
        (
            "r14_user_pair_esc_nl",
            |n| format!(r#"{{"msg":"{}:x"}}"#, r#"user=a\n."#.repeat(n)),
            1_000,
            16_000,
        ),
    ];

    let started = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r14_scaling {
        let mut n = start_n;
        let (d1, d2) = loop {
            let p1 = make_payload(n);
            let t1 = std::time::Instant::now();
            let o1 = sanitize_lifecycle_field(&p1);
            let d1 = t1.elapsed();
            assert!(!o1.is_empty());
            if d1 >= std::time::Duration::from_millis(15) || n >= max_n {
                let p2 = make_payload(n * 2);
                let t2 = std::time::Instant::now();
                let o2 = sanitize_lifecycle_field(&p2);
                let d2 = t2.elapsed();
                assert!(!o2.is_empty());
                break (d1, d2);
            }
            n *= 2;
        };
        let ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
        assert!(
            ratio < 3.2,
            "runner {name} showed superlinear scaling at n={n}: d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)"
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "runner R14 linear-time budget exceeded: {elapsed:?}"
    );
}

#[test]
fn test_wave1a_r15_audit_regressions() {
    let pw = concat!("pass", "word");
    let pw_upper = concat!("PASS", "WORD");
    let pa = concat!("pa", "ss");
    let tok = concat!("tok", "en");
    let api_key = concat!("api_", "key");

    // 1. Team 8 F-01 P0 panic reproducers (must never panic, must scrub a:b, preserve valid JSON)
    for (input, must_be_json) in [
        (r#""\x user=a:b user": ok"#, false),
        (r#"{"msg": "\"C:\\path user=a:b user\": ok"}"#, true),
        (r#""\x user=a:b user": c:d"#, false),
    ] {
        let out = sanitize_lifecycle_field(input);
        assert!(
            !out.contains("a:b"),
            "runner R15 Team 8 F-01 leaked a:b for {input:?} -> {out:?}"
        );
        if must_be_json {
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("runner R15 Team 8 F-01 broke JSON ({e}) for {input:?} -> {out:?}")
            });
        }
        assert_eq!(
            sanitize_lifecycle_field(&out),
            out,
            "runner R15 Team 8 F-01 non-idempotent for {input:?} -> {out:?}"
        );
    }

    // 2. All R14 secret-leak findings on sanitize_lifecycle_field (1-step idempotent, zero leaks)
    let secret_cases: Vec<(String, &'static str, bool)> = vec![
        // Carbon W1A-R14-04: JSON-escaped POSIX line continuations (`\\\n` / `\\\r\n`)
        (
            format!("{{\"cmd\": \"pg_dump --{pw} part1\\\\\\nSUPER_SECRET\"}}"),
            "SUPER_SECRET",
            true,
        ),
        (
            format!("{{\"cmd\": \"pg_dump --{pw} part1\\\\\\r\\nSUPER_SECRET\"}}"),
            "SUPER_SECRET",
            true,
        ),
        (
            "{\"cmd\": \"curl -u admin:\\\\\\nSUPER_SECRET https://example.com\"}".to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            "{\"cmd\": \"curl -b sid=part1\\\\\\nSUPER_SECRET https://example.com\"}".to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            format!("{{\"env\": \"{pw_upper}=part1\\\\\\nSUPER_SECRET\"}}"),
            "SUPER_SECRET",
            true,
        ),
        (
            format!("err: {{\"cmd\": \"pg_dump --{pw} part1\\\\\\nSUPER_SECRET\""),
            "SUPER_SECRET",
            false,
        ),
        // Carbon W1A-R14-03: JSON `\u000a` / `\u000d` newline escapes
        (
            r#"{"msg": "ok\u000aBearer SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            format!(r#"{{"msg": "ok\u000a--{pw} SUPER_SECRET"}}"#),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"msg": "ok\u000acurl -su admin:SUPER_SECRET https://example.com"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"msg": "ok\u000acurl -b sid=SUPER_SECRET https://example.com"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"msg": "ok\u000auser=admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            format!(r#"{{"msg": "ok\u000a{pa}=SUPER_SECRET"}}"#),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"err: {"msg": "ok\u000aBearer SUPER_SECRET""#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            format!(r#"err: {{"msg": "ok\u000d--{pw} SUPER_SECRET""#),
            "SUPER_SECRET",
            false,
        ),
        // Neon AUD-08: curl `-b` / `-b<cookie>` / `-sb`
        (
            "curl -b sid=SUPER_SECRET https://example.com".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"["curl", "-b", "sid=SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            "curl -bsid=SUPER_SECRET https://example.com".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "curl -sb sid=SUPER_SECRET https://example.com".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "curl -sbsid=SUPER_SECRET https://example.com".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"{"cmd": "curl -b sid=SUPER_SECRET https://example.com"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        // Team 8 F-03 = Neon AUD-04: escaped-tab auth-scheme chains
        (
            r#"Bearer\tBearer SUPER_SECRET"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"Basic\tBearer SUPER_SECRET"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            format!(r#"{tok}\tBearer SUPER_SECRET"#),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"Digest\tBearer SUPER_SECRET"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            format!(r#"invalid {tok}\tBearer SUPER_SECRET"#),
            "SUPER_SECRET",
            false,
        ),
        (
            format!(r#"{{"msg": "invalid {tok}\\tBearer SUPER_SECRET"}}"#),
            "SUPER_SECRET",
            true,
        ),
        // Team 8 F-04: NBSP around `=` / `:` on KV and `user:pass`
        (format!("{pw}\u{00A0}=SUPER_SECRET"), "SUPER_SECRET", false),
        (format!("{pw}\\u00a0=SUPER_SECRET"), "SUPER_SECRET", false),
        (
            format!("\"{pw}\"\u{00A0}: \"SUPER_SECRET\""),
            "SUPER_SECRET",
            false,
        ),
        (
            format!("{api_key}\u{00A0}: SUPER_SECRET"),
            "SUPER_SECRET",
            false,
        ),
        (
            "user=\u{00A0}admin:SUPER_SECRET".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "user:\u{00A0}admin:SUPER_SECRET".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "user\u{00A0}=admin:SUPER_SECRET".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "user=\u{00A0}\"admin:SUPER_SECRET\"".to_string(),
            "SUPER_SECRET",
            false,
        ),
        // Neon AUD-03: URL password containing `@` followed by `,`, `;`, `'`, `"`, `{`, `}`
        (
            "https://admin:p@ss,SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "https://admin:p@ss;SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "https://admin:p@ss'SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"https://admin:p@ss"SUPER_SECRET@example.com/api"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "https://admin:p@ss{SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "https://admin:p@ss}SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"{"url": "https://admin:p@ss;SUPER_SECRET@example.com/api"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        // Neon AUD-05: JSON-serialized folded HTTP Digest headers
        (
            r#"{"err": "Digest username=\"alice\",\n  response=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"err": "Digest username=\"alice\",\r\n  response=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"err": "Digest username=\"alice\",\tresponse=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"err": "Digest username=\"alice\",\\\nresponse=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        // Neon AUD-06: Unicode delimiters & escaped-whitespace before auth/KV/user/CLI flags
        ("—Bearer SUPER_SECRET".to_string(), "SUPER_SECRET", false),
        ("“Bearer SUPER_SECRET”".to_string(), "SUPER_SECRET", false),
        (
            r#"{"msg": "\u2014Bearer SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (format!(r#"\u0020{pa}=SUPER_SECRET"#), "SUPER_SECRET", false),
        (format!(r#"\u0009{pa}=SUPER_SECRET"#), "SUPER_SECRET", false),
        (format!(r#"\u00a0{pa}=SUPER_SECRET"#), "SUPER_SECRET", false),
        (
            r#"\u0020user=admin:SUPER_SECRET"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            format!(r#"\u0020--{pw} SUPER_SECRET"#),
            "SUPER_SECRET",
            false,
        ),
        (format!(r#"\u2014{pa}=SUPER_SECRET"#), "SUPER_SECRET", false),
        (
            format!(r#"{{"msg": "\u0020{pa}=SUPER_SECRET"}}"#),
            "SUPER_SECRET",
            true,
        ),
        // Neon AUD-07: URL `\u0040` Pass-0 standalone `","` and unquoted `\\"`
        (
            r#""https://admin:p","SUPER_SECRET\u0040example.com/api""#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"https://admin:p\\"SUPER_SECRET\u0040example.com/api"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        // Carbon W1A-R14-06: `\u005c\u00750041` escape chain idempotency
        (
            format!(r#"{{"{pw}_\\u005c\\u00750041": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"{"Bearer SUPER_SECRET \\u005c\\u00750041": 1}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
    ];

    for (input, forbidden, must_be_json) in &secret_cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R15 leaked {forbidden:?} for {input:?} -> {once:?}"
        );
        if *must_be_json {
            serde_json::from_str::<serde_json::Value>(&once).unwrap_or_else(|e| {
                panic!("runner R15 broke valid JSON ({e}) for {input:?} -> {once:?}")
            });
        }
        let twice = sanitize_lifecycle_field(&once);
        assert_eq!(
            twice, once,
            "runner R15 1-step idempotency failed for {input:?} -> {once:?} vs {twice:?}"
        );
    }

    // 3. Neon AUD-08 exact redaction & benign preservation (git -b, curl -B, Windows paths)
    assert_eq!(
        sanitize_lifecycle_field("curl -b sid=SUPER_SECRET https://example.com"),
        "curl -b [REDACTED] https://example.com"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl -bsid=SUPER_SECRET https://example.com"),
        "curl -b[REDACTED] https://example.com"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl -sb sid=SUPER_SECRET https://example.com"),
        "curl -sb [REDACTED] https://example.com"
    );
    assert_eq!(
        sanitize_lifecycle_field("curl -b sid=SUPER_SECRET && git checkout -b feature"),
        "curl -b [REDACTED] && git checkout -b feature"
    );
    for benign in [
        "git checkout -b feature".to_string(),
        "curl -B https://example.com".to_string(),
        r#"{"cmd": "curl", "items": ["-b", "benign_item"]}"#.to_string(),
        format!(r#"log: C:\\t{pa}=visible"#),
        format!(r#"log: C:\t{pa}=visible"#),
        format!(r#"{{"path": "C:\\t{pa}=visible"}}"#),
    ] {
        assert_eq!(
            sanitize_lifecycle_field(&benign),
            benign,
            "runner R15 over-redacted benign input {benign:?}"
        );
    }

    // 4. Carbon W1A-R14-05: multiline sibling object after quoted Cookie header preserves JSON & sibling
    let w14_05_j1 = "[\"Cookie: sid=SUPER_SECRET\",{\"a\":\"1\",\n\"b\":2}]";
    let w14_05_out1 = sanitize_lifecycle_field(w14_05_j1);
    assert!(!w14_05_out1.contains("SUPER_SECRET"), "{w14_05_out1}");
    let parsed_05: serde_json::Value = serde_json::from_str(&w14_05_out1)
        .unwrap_or_else(|e| panic!("runner R15 W1A-R14-05 broke JSON ({e}): {w14_05_out1}"));
    assert_eq!(parsed_05[1]["a"], "1");
    assert_eq!(parsed_05[1]["b"], 2);
    assert_eq!(sanitize_lifecycle_field(&w14_05_out1), w14_05_out1);

    let w14_05_j2 = "[\"Cookie: sid=SUPER_SECRET\",{\"a\":\"1\",\n\"b\":1e500}]";
    let w14_05_out2 = sanitize_lifecycle_field(w14_05_j2);
    assert!(!w14_05_out2.contains("SUPER_SECRET"), "{w14_05_out2}");
    assert!(
        w14_05_out2.contains(r#"{"a":"1","#) && w14_05_out2.contains(r#""b":1e500}"#),
        "runner R15 W1A-R14-05 clobbered sibling: {w14_05_out2}"
    );
    assert_eq!(sanitize_lifecycle_field(&w14_05_out2), w14_05_out2);

    // 5. Neon AUD-09: multiline quoted HTTP headers ending in Base64 `=` preserve trailing URL/flags/lines
    let aud09_1 =
        "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\" https://example.com\nstep 2: status=\"ok\"";
    let aud09_out1 = sanitize_lifecycle_field(aud09_1);
    assert!(!aud09_out1.contains("dXNlcjpwYXNz"), "{aud09_out1}");
    assert!(
        aud09_out1.contains("https://example.com") && aud09_out1.contains("step 2: status=\"ok\""),
        "runner R15 AUD-09 over-redacted trailing content: {aud09_out1}"
    );
    assert_eq!(sanitize_lifecycle_field(&aud09_out1), aud09_out1);

    let aud09_2 =
        "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\" -H \"Accept: application/json\" https://example.com";
    let aud09_out2 = sanitize_lifecycle_field(aud09_2);
    assert!(!aud09_out2.contains("dXNlcjpwYXNz"), "{aud09_out2}");
    assert!(
        aud09_out2.contains("-H \"Accept: application/json\"")
            && aud09_out2.contains("https://example.com"),
        "runner R15 AUD-09 swallowed sibling header: {aud09_out2}"
    );
    assert_eq!(sanitize_lifecycle_field(&aud09_out2), aud09_out2);

    let aud09_3 = "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\"\nbenign_line=1";
    let aud09_out3 = sanitize_lifecycle_field(aud09_3);
    assert!(!aud09_out3.contains("dXNlcjpwYXNz"), "{aud09_out3}");
    assert!(
        aud09_out3.contains("benign_line=1"),
        "runner R15 AUD-09 swallowed benign_line=1: {aud09_out3}"
    );
    assert_eq!(sanitize_lifecycle_field(&aud09_out3), aud09_out3);

    // 6. Adaptive-n linear scaling across R14 DoS vectors (Team 8 F-02 = Neon AUD-01 & Carbon W1A-R14-01)
    type R15ScalingCase = (&'static str, fn(usize) -> String, usize, usize);
    let r15_scaling: &[R15ScalingCase] = &[
        (
            "r15_aud01_u0022_pairs",
            |n| format!("Cookie: x {}\nbenign", "\\u0022\\u0022".repeat(n)),
            1_000,
            16_000,
        ),
        (
            "r15_w14_01_u0022_user_brace",
            |n| r#"\u0022user\u0022:a{ "#.repeat(n),
            1_000,
            16_000,
        ),
    ];
    let started = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r15_scaling {
        let mut n = start_n;
        let (d1, d2) = loop {
            let p1 = make_payload(n);
            let t1 = std::time::Instant::now();
            let o1 = sanitize_lifecycle_field(&p1);
            let d1 = t1.elapsed();
            assert!(!o1.is_empty());
            if d1 >= std::time::Duration::from_millis(15) || n >= max_n {
                let p2 = make_payload(n * 2);
                let t2 = std::time::Instant::now();
                let o2 = sanitize_lifecycle_field(&p2);
                let d2 = t2.elapsed();
                assert!(!o2.is_empty());
                break (d1, d2);
            }
            n *= 2;
        };
        let ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
        assert!(
            ratio < 3.2,
            "runner {name} showed superlinear scaling at n={n}: d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)"
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "runner R15 linear-time budget exceeded: {elapsed:?}"
    );
}

#[test]
fn test_wave1a_r16_runner_curl_nl_unicode_ws_and_control_escaped_keys() {
    let pw = concat!("pass", "word");
    let pa = concat!("pa", "ss");
    let au = concat!("au", "th");
    let tok = concat!("tok", "en");

    // 1. Team 8 F-09: JSON-escaped newline inside `"` resets curl context while keeping
    // genuine curl -b / JSON line continuations redacted.
    let f09_benign = r#"{"cmd": "curl https://example.com\nrsync -b backup.tar"}"#;
    let f09_out = sanitize_lifecycle_field(f09_benign);
    assert_eq!(
        f09_out, f09_benign,
        "Team 8 F-09 must preserve rsync -b after JSON \\n: {f09_out}"
    );
    let f09_cr = r#"{"cmd": "curl https://example.com\r\nrsync -b backup.tar"}"#;
    assert_eq!(sanitize_lifecycle_field(f09_cr), f09_cr);
    let f09_cont = r#"{"cmd": "curl https://example.com\\\n-b sid=CONT_COOKIE_R16"}"#;
    let f09_cont_out = sanitize_lifecycle_field(f09_cont);
    assert!(
        !f09_cont_out.contains("CONT_COOKIE_R16"),
        "Team 8 F-09 JSON continuation curl -b leaked: {f09_cont_out}"
    );
    assert_eq!(sanitize_lifecycle_field(&f09_cont_out), f09_cont_out);

    // 2. Neon AUD-05: full horizontal Unicode whitespace (\u{3000}, \u{2000}, \u{2003}, \u{202F}, \u{205F})
    let unicode_ws_cases = [
        (
            "Bearer\u{3000}SUPER_SECRET_R16".to_string(),
            "SUPER_SECRET_R16",
        ),
        (
            "Bearer\u{2003}SUPER_SECRET_R16".to_string(),
            "SUPER_SECRET_R16",
        ),
        (
            "Bearer\u{202F}SUPER_SECRET_R16".to_string(),
            "SUPER_SECRET_R16",
        ),
        (
            format!("--{tok}\u{3000}SUPER_SECRET_R16"),
            "SUPER_SECRET_R16",
        ),
        (
            format!("--{tok}\u{205F}SUPER_SECRET_R16"),
            "SUPER_SECRET_R16",
        ),
        (
            "curl -u\u{3000}admin:SUPER_SECRET_R16 https://example.com".to_string(),
            "SUPER_SECRET_R16",
        ),
        (
            "curl -b\u{2000}sid=SUPER_SECRET_R16 https://example.com".to_string(),
            "SUPER_SECRET_R16",
        ),
        (
            format!("{pw}\u{3000}=\u{3000}SUPER_SECRET_R16\u{3000}status=ok"),
            "SUPER_SECRET_R16",
        ),
    ];
    for (input, forbidden) in &unicode_ws_cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R16 Neon AUD-05 leaked {forbidden} for {input:?} -> {once:?}"
        );
        assert!(
            once.contains("[REDACTED]"),
            "runner R16 Neon AUD-05 missing marker for {input:?} -> {once:?}"
        );
        if input.contains("status=ok") {
            assert!(
                once.contains("status=ok"),
                "runner R16 Neon AUD-05 over-consumed across \\u{{3000}}: {once:?}"
            );
        }
        assert_eq!(
            sanitize_lifecycle_field(&once),
            once,
            "runner R16 Neon AUD-05 non-idempotent for {input:?} -> {once:?}"
        );
    }

    // 3. Carbon W1A-AUD-02 & W1A-AUD-03: JSON control escapes before word-bounded keys &
    // stray quote inside bracketed log prefix
    let control_esc_cases = [
        format!(r#"{{"\t{pa}": "SECRET_R16"}}"#),
        format!(r#"{{"\n{au}": "SECRET_R16"}}"#),
        format!(r#"{{"\b{pa}": "SECRET_R16"}}"#),
        format!(r#"{{"\f{pa}": "SECRET_R16"}}"#),
        r#"{"\rKEY": "SECRET_R16"}"#.to_string(),
        format!(r#"{{"\u0009{pa}": "SECRET_R16"}}"#),
        format!(r#"{{"\u000a{au}": "SECRET_R16"}}"#),
        r#"{"\u001bKEY": "SECRET_R16"}"#.to_string(),
        format!(r#"{{"\u0000{pa}": "SECRET_R16"}}"#),
        r#"{"\tuser": "admin:SECRET_R16"}"#.to_string(),
        format!(r#"err: {{"\t{pa}": "SECRET_R16""#),
        format!(r#"payload="{{\"\\t{pa}\": \"SECRET_R16\"}}""#),
        format!(r#"{{"\t{pa}": {{"nested": "SECRET_R16"}}}}"#),
        format!(r#"[info: 5" disk] {{"{pw}": "SECRET_R16"}}"#),
        format!(r#"[info: 5" disk] {{"\t{pa}": "SECRET_R16"}}"#),
        r#"{"msg": "X-Api-Key: \nSECRET_R16"}"#.to_string(),
    ];
    for input in &control_esc_cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains("SECRET_R16"),
            "runner R16 W1A-AUD-02/03 leaked for {input:?} -> {once:?}"
        );
        assert!(
            once.contains("[REDACTED]"),
            "runner R16 W1A-AUD-02/03 missing marker for {input:?} -> {once:?}"
        );
        assert_eq!(
            sanitize_lifecycle_field(&once),
            once,
            "runner R16 W1A-AUD-02/03 non-idempotent for {input:?} -> {once:?}"
        );
    }

    // 4. Carbon W1A-AUD-02 & W1A-AUD-07 benign preservation (Windows paths & KEY\u0061)
    for benign in [
        format!(r#"C:\t{pa}=visible"#),
        format!(r#"C:\\t{pa}=visible"#),
        format!(r#"C:\b{pa}=visible"#),
        format!(r#"C:\f{pa}=visible"#),
        r#"{"KEY\u0061": "benign_val"}"#.to_string(),
        r#"{"KEY\u0061": {"a": 1}}"#.to_string(),
        r#"{"msg": "Cookie:\nHost: example.com"}"#.to_string(),
    ] {
        assert_eq!(
            sanitize_lifecycle_field(&benign),
            benign,
            "runner R16 over-redacted benign input {benign:?}"
        );
    }
}

#[test]
fn test_wave1a_r17_runner_curl_u005c_unicode_ws_cert_and_surrogate_regressions() {
    let pw = concat!("pass", "word");

    // 1. Neon F-03: escaped quotes inside depth-0 double-quoted curl command strings must not
    // clear curl_on_line, while benign {"cmd":"curl","items":["-b","benign"]} stays intact.
    for (input, forbidden) in [
        (
            r#"err="curl -d '{\"a\":\"v\"}' -b SUPER_SECRET_CURL_R17""#,
            "SUPER_SECRET_CURL_R17",
        ),
        (
            r#"{"cmd": "curl -d '{\"a\":\"v\"}' -b SUPER_SECRET_CURL2_R17"}"#,
            "SUPER_SECRET_CURL2_R17",
        ),
        (
            r#"err="curl -d \"a\",\"b\" -su admin:SUPER_SECRET_ESC_C_R17""#,
            "SUPER_SECRET_ESC_C_R17",
        ),
    ] {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R17 Neon F-03 leaked {forbidden}: {input:?} -> {once:?}"
        );
        assert!(once.contains("[REDACTED]"), "{once:?}");
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }
    for benign in [
        r#"{"cmd":"curl","items":["-b","benign"]}"#,
        r#"payload="{\"cmd\":\"curl\",\"items\":[\"-b\",\"benign\"]}""#,
        // Team 8 F-06: delimiter before -b resets curl_on_line
        "curl https://example.com\n-b feature-branch",
        "curl https://example.com;-b feature-branch",
        r#"{"cmd": "curl https://example.com\n-b feature-branch"}"#,
    ] {
        assert_eq!(
            sanitize_lifecycle_field(benign),
            benign,
            "runner R17 F-03/F-06 over-redacted benign {benign:?}"
        );
    }
    let cont_curl = "curl https://example.com \\\n-b sid=CONT_R17_SECRET";
    let cont_out = sanitize_lifecycle_field(cont_curl);
    assert!(!cont_out.contains("CONT_R17_SECRET"), "{cont_out:?}");
    assert_eq!(sanitize_lifecycle_field(&cont_out), cont_out);

    // 2. Team 8 F-04 & Neon F-06: \u005c\u0022 composite quotes close cleanly and preserve
    // trailing benign lines; \u0022-prefixed curl / --password\u003d preserve trailing args.
    let f04_single = format!(
        "{pw}=\\u005c\\u0022part1 SUPER_SECRET_F04_R17\\u005c\\u0022\nstep 2: service healthy"
    );
    let f04_out = sanitize_lifecycle_field(&f04_single);
    assert!(!f04_out.contains("SUPER_SECRET_F04_R17"), "{f04_out:?}");
    assert!(
        f04_out.ends_with("\nstep 2: service healthy"),
        "runner R17 Team 8 F-04 swallowed trailing line: {f04_out:?}"
    );
    assert_eq!(sanitize_lifecycle_field(&f04_out), f04_out);

    let f04_ml = format!(
        "\"{pw}\":\n\\u005c\\u0022LINE1_F04_R17\nLINE2_F04_R17\\u005c\\u0022\nstep 2: service healthy"
    );
    let f04_ml_out = sanitize_lifecycle_field(&f04_ml);
    assert!(!f04_ml_out.contains("LINE1_F04_R17"), "{f04_ml_out:?}");
    assert!(!f04_ml_out.contains("LINE2_F04_R17"), "{f04_ml_out:?}");
    assert!(
        f04_ml_out.contains("step 2: service healthy"),
        "runner R17 Team 8 F-04 multiline swallowed trailing line: {f04_ml_out:?}"
    );
    assert_eq!(sanitize_lifecycle_field(&f04_ml_out), f04_ml_out);

    let f06_curl_u22 = r#"\u0022curl -b SECRET_U22_B_R17\u0022"#;
    let f06_curl_out = sanitize_lifecycle_field(f06_curl_u22);
    assert!(
        !f06_curl_out.contains("SECRET_U22_B_R17"),
        "{f06_curl_out:?}"
    );
    assert!(f06_curl_out.ends_with(r#"\u0022"#), "{f06_curl_out:?}");
    assert_eq!(sanitize_lifecycle_field(&f06_curl_out), f06_curl_out);

    let f06_eq_u22 = format!(
        r#"[\u0022curl\u0022, \u0022--{pw}\u003dSECRET_U22_EQ_R17\u0022, \u0022https://example.com\u0022]"#
    );
    let f06_eq_out = sanitize_lifecycle_field(&f06_eq_u22);
    assert!(!f06_eq_out.contains("SECRET_U22_EQ_R17"), "{f06_eq_out:?}");
    assert!(
        f06_eq_out.contains(r#", \u0022https://example.com\u0022]"#),
        "runner R17 Neon F-06 swallowed trailing arg: {f06_eq_out:?}"
    );
    assert_eq!(sanitize_lifecycle_field(&f06_eq_out), f06_eq_out);

    // 3. Neon F-07 = Carbon W1A-R16-04: full Rust Unicode whitespace (\u{000B}, \u{000C},
    // \u{0085}, \u{2028}, \u{2029}) across auth schemes, CLI flags, curl, and scalar stop.
    let f07_cases = [
        ("Bearer\u{000B}SUPER_SECRET_VT_R17".to_string(), None),
        ("Bearer\u{000C}SUPER_SECRET_FF_R17".to_string(), None),
        ("Bearer\u{0085}SUPER_SECRET_NEL_R17".to_string(), None),
        ("Bearer\u{2028}SUPER_SECRET_LS_R17".to_string(), None),
        ("Bearer\u{2029}SUPER_SECRET_PS_R17".to_string(), None),
        (format!("--{pw}\u{000B}SUPER_SECRET_CVT_R17"), None),
        (format!("--{pw}\u{2028}SUPER_SECRET_CLS_R17"), None),
        (
            "curl\u{000C}-b\u{000C}SUPER_SECRET_CFF_R17".to_string(),
            None,
        ),
        (
            "curl\u{000B}-b\u{000B}SUPER_SECRET_CBVT_R17\u{000B}https://example.com".to_string(),
            Some("https://example.com"),
        ),
        (
            format!("{pw}=SUPER_SECRET_VT_STOP_R17\u{000B}status=ok"),
            Some("status=ok"),
        ),
    ];
    for (input, must_preserve) in &f07_cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains("SUPER_SECRET_"),
            "runner R17 Neon F-07 leaked for {input:?} -> {once:?}"
        );
        assert!(once.contains("[REDACTED]"), "{input:?} -> {once:?}");
        if let Some(keep) = must_preserve {
            assert!(
                once.contains(keep),
                "runner R17 Neon F-07 over-consumed {keep:?}: {once:?}"
            );
        }
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }

    // 4. Neon F-08: curl -#u and passphrase-aware -E / --cert / --proxy-cert
    let f08_secret_cases = [
        (
            "curl -#u admin:SUPER_SECRET_HASH_R17 https://example.com",
            "curl -#u [REDACTED] https://example.com",
        ),
        (
            "curl -E client.p12:SUPER_SECRET_CERT_R17 https://example.com",
            "curl -E [REDACTED] https://example.com",
        ),
        (
            "curl -sE client.p12:SUPER_SECRET_SCERT_R17 https://example.com",
            "curl -sE [REDACTED] https://example.com",
        ),
        (
            "curl -#E client.p12:SUPER_SECRET_HCERT_R17 https://example.com",
            "curl -#E [REDACTED] https://example.com",
        ),
        (
            "curl --cert client.p12:SUPER_SECRET_LCERT_R17 https://example.com",
            "curl --cert [REDACTED] https://example.com",
        ),
        (
            "curl --cert=client.p12:SUPER_SECRET_EQCERT_R17 https://example.com",
            "curl --cert=[REDACTED] https://example.com",
        ),
        (
            "curl --proxy-cert client.p12:SUPER_SECRET_PCERT_R17 https://example.com",
            "curl --proxy-cert [REDACTED] https://example.com",
        ),
    ];
    for (input, expected) in f08_secret_cases {
        let once = sanitize_lifecycle_field(input);
        assert_eq!(
            once, expected,
            "runner R17 Neon F-08 mismatch for {input:?}"
        );
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }
    for benign_cert in [
        "curl -E /etc/ssl/client.pem https://example.com",
        "curl --cert /etc/ssl/client.pem https://example.com",
        "curl --proxy-cert=/etc/ssl/proxy.pem https://example.com",
        "git -E foo:bar",
    ] {
        assert_eq!(
            sanitize_lifecycle_field(benign_cert),
            benign_cert,
            "runner R17 Neon F-08 over-redacted passwordless/non-curl cert {benign_cert:?}"
        );
    }

    // 5. Carbon W1A-R16-02: unpaired UTF-16 surrogates (\ud800..\udfff) as key separators
    let surrogate_cases = [
        r#"{"\ud800user": "admin:SURR_CANARY_R17"}"#.to_string(),
        format!(r#"{{"\ud800{pw}": "SURR_CANARY_R17"}}"#),
        format!(r#"{{"\udc00{pw}": "SURR_CANARY_R17"}}"#),
        format!(r#"{{"\ud800{pw}": {{"v": "SURR_CANARY_R17"}}}}"#),
        format!(r#"'\ud800{pw}': 'SURR_CANARY_R17'"#),
    ];
    for input in &surrogate_cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains("SURR_CANARY_R17"),
            "runner R17 W1A-R16-02 leaked for {input:?} -> {once:?}"
        );
        assert!(once.contains("[REDACTED]"), "{input:?} -> {once:?}");
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }
}

#[test]
fn test_wave1a_r18_runner_cert_budget_unicode_containers_and_controls() {
    let pw = concat!("pass", "word");
    let pa = concat!("pa", "ss");
    let sec = concat!("sec", "ret");

    // 1. Team 8 F1: no fail-open budget watermark on repeated exempt --cert/--proxy-cert/-E
    for flag in ["--cert", "--proxy-cert"] {
        let payload = format!(
            "{}{} --cert client.pem:PASSPHRASE_SECRET_R18",
            format!("{flag}=http://{{ ").repeat(10),
            "x".repeat(400)
        );
        let once = sanitize_lifecycle_field(&payload);
        assert!(
            !once.contains("PASSPHRASE_SECRET_R18"),
            "runner R18 Team 8 F1 fail-open watermark leaked for {flag}: {once:?}"
        );
        assert!(once.contains("--cert [REDACTED]"), "{once:?}");
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }

    // 2. Team 8 F8: strictly linear O(N) scaling on repeated backslash-escaped cert flags
    for (name, make_payload) in [
        (
            "cert_bs_brace",
            (|n: usize| "--cert=\\a{".repeat(n)) as fn(usize) -> String,
        ),
        ("proxy_cert_bs_brace", |n: usize| {
            "--proxy-cert=\\a{".repeat(n)
        }),
        ("curl_short_e_bs_brace", |n: usize| {
            format!("curl {}", "-E\\a{".repeat(n))
        }),
    ] {
        let mut n = 512usize;
        let (d1, d2) = loop {
            let p1 = make_payload(n);
            let t1 = std::time::Instant::now();
            let o1 = sanitize_lifecycle_field(&p1);
            let d1 = t1.elapsed();
            assert!(!o1.is_empty());
            if d1 >= std::time::Duration::from_millis(10) || n >= 8192 {
                let p2 = make_payload(n * 2);
                let t2 = std::time::Instant::now();
                let o2 = sanitize_lifecycle_field(&p2);
                let d2 = t2.elapsed();
                assert!(!o2.is_empty());
                break (d1, d2);
            }
            n *= 2;
        };
        let ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
        assert!(
            ratio < 3.2,
            "runner R18 Team 8 F8 {name} superlinear at n={n}: d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)"
        );
    }

    // 3. Team 8 F2: Unicode-escaped quotes inside single-line and multiline sensitive containers
    let f2_cases = [
        format!(
            r#"{sec}: {{\u0022a\u0022: \u0022}}\u0022, \u0022val\u0022: \u0022SUPER_SECRET_F2_R18\u0022}}"#
        ),
        format!(
            r#"{sec}: {{\u0027a\u0027: \u0027}}\u0027, \u0027val\u0027: \u0027SUPER_SECRET_F2_R18\u0027}}"#
        ),
        format!(
            r#"{sec}: {{\u005c\u0022a\u005c\u0022: \u005c\u0022}}\u005c\u0022, \u005c\u0022val\u005c\u0022: \u005c\u0022SUPER_SECRET_F2_R18\u005c\u0022}}"#
        ),
        format!(
            "{sec}: {{\n  \\u0022a\\u0022: \\u0022}}\\u0022,\n  \\u0022val\\u0022: \\u0022SUPER_SECRET_F2_R18\\u0022\n}}"
        ),
    ];
    for input in &f2_cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains("SUPER_SECRET_F2_R18"),
            "runner R18 Team 8 F2 leaked for {input:?} -> {once:?}"
        );
        assert!(once.contains("[REDACTED]"), "{once:?}");
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }

    // 4. Neon AUD-01: JSON-string-gated \f / \b and literal 0x08 / 0x0B / 0x0C controls
    let aud01_cases = [
        r#"{"msg":"Bearer\fSEC_F1_R18"}"#.to_string(),
        format!(r#"{{"msg":"--{pw}\fSEC_F4_R18"}}"#),
        r#"{"msg":"curl\f-u\fadmin:SEC_F5_R18"}"#.to_string(),
        r#"{"msg":"ok\bBearer SEC_B1_R18"}"#.to_string(),
        r#"{"Basic\fSEC_KF1_R18":"ok"}"#.to_string(),
        r#"{"curl\f-u\fSEC_KF3_R18":"ok"}"#.to_string(),
        "ok\x08curl\x0b-u\x0cadmin:SEC_CTRL_R18 https://example.com".to_string(),
    ];
    for input in &aud01_cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains("SEC_"),
            "runner R18 Neon AUD-01 leaked for {input:?} -> {once:?}"
        );
        assert!(once.contains("[REDACTED]"), "{input:?} -> {once:?}");
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }
    for benign_win in [
        format!(r#"C:\b{pa}=visible"#),
        format!(r#"C:\f{pa}=visible"#),
        format!(r#"C:\t{pa}=visible"#),
    ] {
        assert_eq!(
            sanitize_lifecycle_field(&benign_win),
            benign_win,
            "runner R18 Neon AUD-01 over-redacted Windows path {benign_win:?}"
        );
    }

    // 5. Neon AUD-02 / AUD-05 / Carbon W1A-R17-06: cert \u003a, multiline/continuation, and Windows drive path
    let cert_secret_cases = [
        "curl --cert client.p12\\u003aSECRET_CERT_R18 https://example.com",
        "curl -E client.p12\\u003aSECRET_CERT_R18 https://example.com",
        "curl --cert client.p12\\\n:SECRET_CERT_R18 https://example.com",
        "curl --cert \nclient.p12:SECRET_CERT_R18 https://example.com",
        "curl --cert\nclient.p12:SECRET_CERT_R18 https://example.com",
        "curl -E \nclient.p12:SECRET_CERT_R18 https://example.com",
        r#"curl -E C:\certs\client.p12:SECRET_CERT_R18 https://example.com"#,
    ];
    for input in cert_secret_cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains("SECRET_CERT_R18"),
            "runner R18 cert case leaked for {input:?} -> {once:?}"
        );
        assert!(once.contains("[REDACTED]"), "{input:?} -> {once:?}");
        assert!(
            once.contains("https://example.com"),
            "runner R18 cert case dropped trailing URL: {once:?}"
        );
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }
    for benign_win_cert in [
        r#"curl -E C:\certs\client.pem https://example.com"#,
        r#"curl --cert C:\certs\client.pem https://example.com"#,
        r#"curl --cert "C:\certs\client.pem" https://example.com"#,
        r#"curl --proxy-cert=C:/certs/proxy.pem https://example.com"#,
    ] {
        assert_eq!(
            sanitize_lifecycle_field(benign_win_cert),
            benign_win_cert,
            "runner R18 W1A-R17-06 over-redacted Windows cert path {benign_win_cert:?}"
        );
    }
}

#[test]
fn test_wave1a_r19_runner_cert_json_nl_u0027_multiline_surrogates_and_scaling() {
    let pw = concat!("pass", "word");
    let pa = concat!("pa", "ss");

    // 1. R18-P1-1: --cert/--proxy-cert/-E/-sE with JSON \n/\r\n, \u000a/\u000d, and >128-deep JSON
    let p1_1_json_cases = [
        (
            r#"{"cmd": "curl --cert\nclient.p12:SECRET_R19_CERT1"}"#,
            "SECRET_R19_CERT1",
        ),
        (
            r#"{"cmd": "curl --proxy-cert\r\nclient.p12:SECRET_R19_CERT2"}"#,
            "SECRET_R19_CERT2",
        ),
        (
            r#"{"cmd": "curl -E\nclient.p12:SECRET_R19_CERT3"}"#,
            "SECRET_R19_CERT3",
        ),
        (
            r#"{"cmd": "curl -sE\r\nclient.p12:SECRET_R19_CERT4"}"#,
            "SECRET_R19_CERT4",
        ),
        (
            r#"{"cmd": "curl --cert\u000aclient.p12:SECRET_R19_CERT7"}"#,
            "SECRET_R19_CERT7",
        ),
    ];
    for (input, forbidden) in p1_1_json_cases {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R19 P1-1 JSON leaked {forbidden}: {input:?} -> {once:?}"
        );
        assert!(once.contains("[REDACTED]"), "{input:?} -> {once:?}");
        serde_json::from_str::<serde_json::Value>(&once)
            .unwrap_or_else(|e| panic!("runner R19 P1-1 broke JSON ({e}): {once:?}"));
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }
    for (input, forbidden) in [
        (
            "curl --cert\\u000aclient.p12:SECRET_R19_CERT5 https://example.com",
            "SECRET_R19_CERT5",
        ),
        (
            "curl -E\\u000dclient.p12:SECRET_R19_CERT6 https://example.com",
            "SECRET_R19_CERT6",
        ),
    ] {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R19 P1-1 u000a/u000d leaked {forbidden}: {input:?} -> {once:?}"
        );
        assert!(once.contains("[REDACTED]"), "{once:?}");
        assert!(once.contains("https://example.com"), "{once:?}");
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }
    for sep in [r"\n", r"\u000a"] {
        let deep_cert = format!(
            "{}{{\"cmd\":\"curl --cert{sep}client.p12:SECRET_R19_DEEP_CERT\"}}{}",
            "{\"a\":".repeat(135),
            "}".repeat(135)
        );
        let once = sanitize_lifecycle_field(&deep_cert);
        assert!(
            !once.contains("SECRET_R19_DEEP_CERT"),
            "runner R19 P1-1 deep JSON leaked for sep={sep:?}"
        );
        assert!(once.contains("[REDACTED]"));
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }
    for benign in [
        "curl --cert\n/etc/ssl/client.pem https://example.com",
        "curl --cert\nC:\\certs\\client.pem https://example.com",
        r#"{"cmd": "curl --cert\n/etc/ssl/client.pem"}"#,
        "git -E\nclient.p12:visible",
        r#"{"cmd": "git -E\nclient.p12:visible"}"#,
    ] {
        assert_eq!(
            sanitize_lifecycle_field(benign),
            benign,
            "runner R19 P1-1 over-redacted benign {benign:?}"
        );
    }

    // 2. R18-P1-2: \u0027 single-quote symmetry in scalars & cert args
    let u27_single = format!("{pw}=\\u0027part1 SECRET_R19_U27_A\\u0027");
    let u27_single_out = sanitize_lifecycle_field(&u27_single);
    assert!(
        !u27_single_out.contains("SECRET_R19_U27_A"),
        "{u27_single_out:?}"
    );
    assert!(u27_single_out.contains("[REDACTED]"), "{u27_single_out:?}");
    assert_eq!(sanitize_lifecycle_field(&u27_single_out), u27_single_out);

    let u27_ml = format!("{pw}=\\u0027line1\nSECRET_R19_U27_B\\u0027\nstep 2: service healthy");
    let u27_ml_out = sanitize_lifecycle_field(&u27_ml);
    assert!(!u27_ml_out.contains("SECRET_R19_U27_B"), "{u27_ml_out:?}");
    assert!(
        u27_ml_out.ends_with("\nstep 2: service healthy"),
        "runner R19 P1-2 swallowed post-\\u0027 line: {u27_ml_out:?}"
    );
    assert_eq!(sanitize_lifecycle_field(&u27_ml_out), u27_ml_out);

    let u27_json = format!(r#"{{"msg": "{pw}=\\u0027part1 SECRET_R19_U27_C\\u0027"}}"#);
    let u27_json_out = sanitize_lifecycle_field(&u27_json);
    assert!(
        !u27_json_out.contains("SECRET_R19_U27_C"),
        "{u27_json_out:?}"
    );
    serde_json::from_str::<serde_json::Value>(&u27_json_out)
        .unwrap_or_else(|e| panic!("runner R19 P1-2 broke JSON ({e}): {u27_json_out:?}"));
    assert_eq!(sanitize_lifecycle_field(&u27_json_out), u27_json_out);

    for (input, forbidden) in [
        (
            "curl --cert \\u0027my cert.p12:SECRET_R19_U27_D\\u0027 https://example.com",
            "SECRET_R19_U27_D",
        ),
        (
            "curl --cert \\u0027client.p12\n:SECRET_R19_U27_E\\u0027 https://example.com",
            "SECRET_R19_U27_E",
        ),
    ] {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R19 P1-2 \\u0027 cert leaked {forbidden}: {input:?} -> {once:?}"
        );
        assert!(once.contains("[REDACTED]"), "{once:?}");
        assert!(once.contains("https://example.com"), "{once:?}");
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }
    let u27_argv = format!(
        "[\\u0027pg_dump\\u0027, \\u0027--{pw}\\u0027, \\u0027SECRET_R19_U27_F\\u0027, \\u0027keep_arg\\u0027]"
    );
    let u27_argv_out = sanitize_lifecycle_field(&u27_argv);
    assert!(
        !u27_argv_out.contains("SECRET_R19_U27_F"),
        "{u27_argv_out:?}"
    );
    assert!(u27_argv_out.contains("keep_arg"), "{u27_argv_out:?}");
    assert_eq!(sanitize_lifecycle_field(&u27_argv_out), u27_argv_out);

    let u27_curl_argv =
        "[\\u0027curl\\u0027, \\u0027-b\\u0027, \\u0027sid=SECRET_R19_U27_G\\u0027, \\u0027keep_arg\\u0027]";
    let u27_curl_out = sanitize_lifecycle_field(u27_curl_argv);
    assert!(
        !u27_curl_out.contains("SECRET_R19_U27_G"),
        "{u27_curl_out:?}"
    );
    assert!(u27_curl_out.contains("keep_arg"), "{u27_curl_out:?}");
    assert_eq!(sanitize_lifecycle_field(&u27_curl_out), u27_curl_out);

    let u27_val_eq = format!("--{pw}=\\u0027part1 SECRET_R19_U27_H\\u0027 keep_arg");
    let u27_val_eq_out = sanitize_lifecycle_field(&u27_val_eq);
    assert!(
        !u27_val_eq_out.contains("SECRET_R19_U27_H"),
        "{u27_val_eq_out:?}"
    );
    assert!(u27_val_eq_out.contains("keep_arg"), "{u27_val_eq_out:?}");
    assert_eq!(sanitize_lifecycle_field(&u27_val_eq_out), u27_val_eq_out);

    let benign_u27_cert = "curl --cert \\u0027C:\\certs\\client.pem\\u0027 https://example.com";
    assert_eq!(sanitize_lifecycle_field(benign_u27_cert), benign_u27_cert);

    // 3. R18-P1-5: multiline quoted --cert/-E with \n before :
    for (input, forbidden) in [
        (
            "curl --cert \"client.p12\n:SUPER_SECRET_R19_ML1\" https://example.com",
            "SUPER_SECRET_R19_ML1",
        ),
        (
            "curl -E \"client.p12\n:SUPER_SECRET_R19_ML2\" https://example.com",
            "SUPER_SECRET_R19_ML2",
        ),
        (
            "curl --cert 'client.p12\n:SUPER_SECRET_R19_ML3' https://example.com",
            "SUPER_SECRET_R19_ML3",
        ),
        (
            "curl --cert $'client.p12\n:SUPER_SECRET_R19_ML4' https://example.com",
            "SUPER_SECRET_R19_ML4",
        ),
        (
            "curl --cert \"C:\\certs\\client.p12\n:SUPER_SECRET_R19_ML5\" https://example.com",
            "SUPER_SECRET_R19_ML5",
        ),
        (
            "curl --cert \"client.p12\n\\u003aSUPER_SECRET_R19_ML6\" https://example.com",
            "SUPER_SECRET_R19_ML6",
        ),
    ] {
        let once = sanitize_lifecycle_field(input);
        assert!(
            !once.contains(forbidden),
            "runner R19 P1-5 multiline cert leaked {forbidden}: {input:?} -> {once:?}"
        );
        assert!(once.contains("[REDACTED]"), "{once:?}");
        assert!(once.contains("https://example.com"), "{once:?}");
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }
    for benign_ml in [
        "curl --cert \"C:\\certs\nclient.pem\" https://example.com",
        "curl --cert \"/etc/ssl\nclient.pem\" https://example.com",
        "curl --cert client.p12\n:not_passphrase",
    ] {
        assert_eq!(
            sanitize_lifecycle_field(benign_ml),
            benign_ml,
            "runner R19 P1-5 over-redacted benign multiline cert {benign_ml:?}"
        );
    }

    // 4. R18-P3-1: shell separators resetting saw_curl in quoted argv
    for benign_argv in [
        r#"["curl", "https://example.com", "&&", "git", "checkout", "-b", "feature-branch"]"#,
        r#"["curl", "https://example.com", ";", "git", "checkout", "-b", "feature-branch"]"#,
        r#"["curl", "https://example.com", "||", "git", "-bfeature"]"#,
        r#"{"cmd": "[\"curl\", \"https://example.com\", \"&&\", \"git\", \"checkout\", \"-b\", \"feature-branch\"]"}"#,
    ] {
        assert_eq!(
            sanitize_lifecycle_field(benign_argv),
            benign_argv,
            "runner R19 P3-1 over-redacted post-separator argv {benign_argv:?}"
        );
    }
    let mixed_argv = r#"["curl", "-b", "SECRET_R19_PRE_AND", "https://example.com", "&&", "git", "checkout", "-b", "feature-branch"]"#;
    let mixed_out = sanitize_lifecycle_field(mixed_argv);
    assert!(!mixed_out.contains("SECRET_R19_PRE_AND"), "{mixed_out:?}");
    assert!(mixed_out.contains("feature-branch"), "{mixed_out:?}");
    assert_eq!(sanitize_lifecycle_field(&mixed_out), mixed_out);

    // 5. R18-P1-7: UTF-16 surrogates before keywords/flags/assignments + >128-deep JSON
    for (input, forbidden, must_be_json) in [
        (
            r#"{"msg": "\ud83d\ude80Bearer SECRET_R19_SURR1"}"#.to_string(),
            "SECRET_R19_SURR1",
            true,
        ),
        (
            format!(r#"err: {{"msg": "\ud83d\ude80{pa}=SECRET_R19_SURR2""#),
            "SECRET_R19_SURR2",
            false,
        ),
        (
            format!(r#"err: {{"msg": "\ud83d\ude80--{pw} SECRET_R19_SURR3""#),
            "SECRET_R19_SURR3",
            false,
        ),
        (
            r#"{"msg": "\ud83d\ude80curl -u admin:SECRET_R19_SURR4"}"#.to_string(),
            "SECRET_R19_SURR4",
            true,
        ),
        (
            r#"{"msg": "curl \ud83d\ude80-b SECRET_R19_SURR5"}"#.to_string(),
            "SECRET_R19_SURR5",
            true,
        ),
    ] {
        let once = sanitize_lifecycle_field(&input);
        assert!(
            !once.contains(forbidden),
            "runner R19 P1-7 surrogate leaked {forbidden}: {input:?} -> {once:?}"
        );
        assert!(once.contains("[REDACTED]"), "{once:?}");
        if must_be_json {
            serde_json::from_str::<serde_json::Value>(&once)
                .unwrap_or_else(|e| panic!("runner R19 P1-7 broke JSON ({e}): {once:?}"));
        }
        assert_eq!(sanitize_lifecycle_field(&once), once);
    }
    let deep_surr = format!(
        "{}{{\"msg\":\"\\ud83d\\ude80Bearer SECRET_R19_SURR6\"}}{}",
        "{\"a\":".repeat(135),
        "}".repeat(135)
    );
    let deep_surr_out = sanitize_lifecycle_field(&deep_surr);
    assert!(!deep_surr_out.contains("SECRET_R19_SURR6"));
    assert!(deep_surr_out.contains("[REDACTED]"));
    assert_eq!(sanitize_lifecycle_field(&deep_surr_out), deep_surr_out);

    // 6. R18-P1-8 + R18-P1-4 + R18-P1-6 + R18-P2-1 verification on sanitize_lifecycle_field
    let p1_8_json = r#"{"":[{"":"'\\'Authorization:"},"'}"]}"#;
    let p1_8_out = sanitize_lifecycle_field(p1_8_json);
    serde_json::from_str::<serde_json::Value>(&p1_8_out)
        .unwrap_or_else(|e| panic!("runner R19 P1-8 broke JSON ({e}): {p1_8_out:?}"));
    assert_eq!(sanitize_lifecycle_field(&p1_8_out), p1_8_out);

    let ssh_out = sanitize_lifecycle_field("ssh://admin\\u003aSECRET_R19_SSH@example.com");
    assert!(!ssh_out.contains("SECRET_R19_SSH"), "{ssh_out:?}");
    assert!(ssh_out.contains("[REDACTED]"), "{ssh_out:?}");
    assert_eq!(sanitize_lifecycle_field(&ssh_out), ssh_out);
    assert_eq!(
        sanitize_lifecycle_field("ssh://git@github.com/org/repo.git"),
        "ssh://git@github.com/org/repo.git"
    );

    let digest_in =
        "Authorization: Digest username=\"alice\", response=\n\"SECRET_R19_DIGEST\"\nHost: example.com";
    let digest_out = sanitize_lifecycle_field(digest_in);
    assert!(!digest_out.contains("SECRET_R19_DIGEST"), "{digest_out:?}");
    assert!(digest_out.contains("Host: example.com"), "{digest_out:?}");
    assert_eq!(sanitize_lifecycle_field(&digest_out), digest_out);

    let fold_in =
        format!("Cookie: a=1;\n  b=2; {pw}={{\n\"k\":\"SECRET_R19_FOLD\"\n}}\nHost: example.com");
    let fold_out = sanitize_lifecycle_field(&fold_in);
    assert!(!fold_out.contains("SECRET_R19_FOLD"), "{fold_out:?}");
    assert!(fold_out.contains("Host: example.com"), "{fold_out:?}");
    assert_eq!(sanitize_lifecycle_field(&fold_out), fold_out);

    // 7. Strict O(N) scaling on pathological repeated multiline cert quotes
    for (name, make_payload) in [
        (
            "ml_cert_unclosed_dq_colon",
            (|n: usize| format!("{} :tail", "curl --cert \"a\n".repeat(n))) as fn(usize) -> String,
        ),
        ("ml_cert_unclosed_u27_colon", |n: usize| {
            format!("{} :tail", "curl --cert \\u0027a\n".repeat(n))
        }),
    ] {
        let mut n = 256usize;
        let (d1, d2) = loop {
            let p1 = make_payload(n);
            let t1 = std::time::Instant::now();
            let o1 = sanitize_lifecycle_field(&p1);
            let d1 = t1.elapsed();
            assert!(!o1.is_empty());
            if d1 >= std::time::Duration::from_millis(10) || n >= 4096 {
                let p2 = make_payload(n * 2);
                let t2 = std::time::Instant::now();
                let o2 = sanitize_lifecycle_field(&p2);
                let d2 = t2.elapsed();
                assert!(!o2.is_empty());
                break (d1, d2);
            }
            n *= 2;
        };
        let ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
        assert!(
            ratio < 3.2,
            "runner R19 {name} superlinear at n={n}: d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)"
        );
    }
}
