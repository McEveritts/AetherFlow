use super::*;

#[test]
fn test_candidate_receipt_snapshot_and_restoration_with_target_certification_failure() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("af-test-receipt-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let syncthing_ver = temp_dir.join("var/lib/syncthing/.af-version");
    let _ = std::fs::create_dir_all(syncthing_ver.parent().unwrap());
    std::fs::write(&syncthing_ver, b"v1.0.0").unwrap();

    let opt_syncthing = temp_dir.join("opt/syncthing/.af-version");

    // 1. Snapshot candidate receipts
    let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
    assert!(snapshots
        .iter()
        .any(|(p, bytes)| p == &syncthing_ver && bytes.as_deref() == Some(b"v1.0.0")));
    assert!(snapshots
        .iter()
        .any(|(p, bytes)| p == &opt_syncthing && bytes.is_none()));

    // 2. Simulate installer making changes (overwriting existing, creating new)
    std::fs::write(&syncthing_ver, b"v2.0.0").unwrap();
    let _ = std::fs::create_dir_all(opt_syncthing.parent().unwrap());
    std::fs::write(&opt_syncthing, b"v2.0.0").unwrap();

    // 3. Target certification fails -> restore candidate receipts
    restore_candidate_receipts(&snapshots).unwrap();

    // 4. Verify previous receipt is restored and new receipt was removed
    assert_eq!(std::fs::read(&syncthing_ver).unwrap(), b"v1.0.0");
    assert!(
        !opt_syncthing.exists(),
        "uncertified new receipt must be removed"
    );

    // 5. Verify TargetVerification reports stage target_certification_after_install_commit
    let job_id = "test-target-cert-job";
    let _ = af_services::try_start_package_job(af_services::PackageJobInfo {
        job_id: job_id.into(),
        package_id: "syncthing".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 10,
        last_line: "init".into(),
        started_at: "test-time".into(),
        expected_target_version: Some("v3.0.0".into()),
    });
    finish_package_lifecycle(
            "syncthing",
            "update",
            Some(af_services::PackageJobFailure::TargetVerification),
            95,
            "Target certification failed after installer execution (runtime state may be partially committed): expected v3.0.0, achieved v2.0.0",
            "test-time",
            job_id,
            Some("v3.0.0"),
            Some("v2.0.0"),
            &[],
        );
    let outcome = af_services::get_package_job_outcome("syncthing").unwrap();
    assert_eq!(outcome.status, "failed");
    assert_eq!(
        outcome.failed_stage.as_deref(),
        Some("target_certification_after_install_commit")
    );
    assert!(outcome
        .sanitized_summary
        .as_ref()
        .unwrap()
        .contains("Target certification failed after installer execution"));
    assert_eq!(
        outcome.message,
        af_services::PackageJobFailure::TargetVerification.summary()
    );

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_candidate_receipt_symlink_swap_restoration_does_not_overwrite_victim() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-symlink-swap-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let receipt_path = temp_dir.join("var/lib/radarr/.af-version");
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    std::fs::write(&receipt_path, b"1.0.0").unwrap();

    let victim_file = temp_dir.join("victim");
    std::fs::write(&victim_file, b"VICTIM_INTACT_CONTENT").unwrap();

    // 1. Snapshot candidate receipts
    let snapshots = snapshot_candidate_receipts("radarr").unwrap();
    assert!(snapshots
        .iter()
        .any(|(p, bytes)| p == &receipt_path && bytes.as_deref() == Some(b"1.0.0")));

    // 2. Attacker swaps receipt for a symlink pointing to /tmp/victim
    std::fs::remove_file(&receipt_path).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&victim_file, &receipt_path).unwrap();

    // 3. Restore candidate receipts
    let restore_res = restore_candidate_receipts(&snapshots);
    assert!(
        restore_res.is_ok(),
        "Restoration should succeed: {:?}",
        restore_res
    );

    // 4. Victim file must NOT be overwritten!
    let victim_content = std::fs::read(&victim_file).unwrap();
    assert_eq!(victim_content, b"VICTIM_INTACT_CONTENT");

    // 5. Receipt file must be restored as a regular file (not a symlink) with original bytes
    let meta = std::fs::symlink_metadata(&receipt_path).unwrap();
    assert!(
        meta.file_type().is_file(),
        "Receipt must be restored as a regular file"
    );
    assert!(
        !meta.file_type().is_symlink(),
        "Receipt must not be a symlink"
    );
    assert_eq!(std::fs::read(&receipt_path).unwrap(), b"1.0.0");

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_candidate_receipt_snapshot_fails_closed_on_symlink_fifo_or_oversized() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-bad-receipt-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let receipt_path = temp_dir.join("var/lib/sonarr/.af-version");
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();

    // 1. Symlink at receipt path fails closed
    let dummy_target = temp_dir.join("dummy_target");
    std::fs::write(&dummy_target, b"test").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&dummy_target, &receipt_path).unwrap();
    let sym_err = snapshot_candidate_receipts("sonarr");
    assert!(
        sym_err.is_err(),
        "Snapshot must fail closed on symlink receipt"
    );
    assert!(sym_err.unwrap_err().contains("symlink or non-regular file"));
    let _ = std::fs::remove_file(&receipt_path);

    // 2. FIFO at receipt path fails closed
    #[cfg(unix)]
    {
        let cstr = std::ffi::CString::new(receipt_path.as_os_str().as_bytes()).unwrap();
        let res = unsafe { libc::mkfifo(cstr.as_ptr(), 0o644) };
        assert_eq!(res, 0);
        let fifo_err = snapshot_candidate_receipts("sonarr");
        assert!(
            fifo_err.is_err(),
            "Snapshot must fail closed on FIFO receipt"
        );
        assert!(fifo_err
            .unwrap_err()
            .contains("symlink or non-regular file"));
        let _ = std::fs::remove_file(&receipt_path);
    }

    // 3. File > 64 KiB at receipt path fails closed
    let oversized = vec![b'X'; 64 * 1024 + 1];
    std::fs::write(&receipt_path, &oversized).unwrap();
    let size_err = snapshot_candidate_receipts("sonarr");
    assert!(
        size_err.is_err(),
        "Snapshot must fail closed on oversized receipt"
    );
    assert!(size_err.unwrap_err().contains("exceeds 64 KiB limit"));
    let _ = std::fs::remove_file(&receipt_path);

    // 4. Ancestor directory being a symlink fails closed
    let ancestor_link = temp_dir.join("var/lib/sonarr");
    let _ = std::fs::remove_dir(&ancestor_link);
    let real_dir = temp_dir.join("real_sonarr");
    std::fs::create_dir_all(&real_dir).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_dir, &ancestor_link).unwrap();
    std::fs::write(ancestor_link.join(".af-version"), b"1.0.0").unwrap();
    let ancestor_err = snapshot_candidate_receipts("sonarr");
    assert!(
        ancestor_err.is_err(),
        "Snapshot must fail closed on symlink ancestor"
    );
    assert!(ancestor_err.unwrap_err().contains("is a symlink"));

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_candidate_receipt_intermediate_ancestor_symlink_fails_closed() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "af-test-intermediate-symlink-{}",
        uuid::Uuid::new_v4()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    // Intermediate ancestor "var/lib" is a symlink to "real_lib"
    let real_lib = temp_dir.join("real_lib");
    std::fs::create_dir_all(real_lib.join("syncthing")).unwrap();
    std::fs::write(real_lib.join("syncthing/.af-version"), b"1.0.0").unwrap();

    let var_dir = temp_dir.join("var");
    std::fs::create_dir_all(&var_dir).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_lib, var_dir.join("lib")).unwrap();

    // 1. Snapshot must fail closed because intermediate ancestor "lib" is a symlink
    let snap_err = snapshot_candidate_receipts("syncthing");
    assert!(
        snap_err.is_err(),
        "Snapshot must fail closed when intermediate ancestor is a symlink"
    );
    assert!(snap_err.unwrap_err().contains("is a symlink"));

    // 2. Restore must also fail closed
    let receipt_path = temp_dir.join("var/lib/syncthing/.af-version");
    let fake_snapshot: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> = vec![(
        receipt_path.clone(),
        Some(ReceiptSnapshotEntry::from(b"2.0.0".to_vec())),
    )];
    let restore_err = restore_candidate_receipts(&fake_snapshot);
    assert!(
        restore_err.is_err(),
        "Restore must fail closed when intermediate ancestor is a symlink"
    );
    assert!(restore_err.unwrap_err().contains("is a symlink"));

    // 3. Restore None (uncertified receipt removal) must also fail closed on symlink ancestor
    let fake_snapshot_none: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> =
        vec![(receipt_path, None)];
    let restore_none_err = restore_candidate_receipts(&fake_snapshot_none);
    assert!(
        restore_none_err.is_err(),
        "Restore None must fail closed when intermediate ancestor is a symlink"
    );
    assert!(restore_none_err.unwrap_err().contains("is a symlink"));

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_lifecycle_job_fails_closed_and_restores_receipts_on_service_restart_failure() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!(
        "af-test-service-restart-fail-{}",
        uuid::Uuid::new_v4()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let syncthing_ver = temp_dir.join("var/lib/syncthing/.af-version");
    let _ = std::fs::create_dir_all(syncthing_ver.parent().unwrap());
    std::fs::write(&syncthing_ver, b"v1.0.0").unwrap();

    let opt_syncthing = temp_dir.join("opt/syncthing/.af-version");

    // 1. Snapshot candidate receipts
    let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
    assert!(snapshots
        .iter()
        .any(|(p, bytes)| p == &syncthing_ver && bytes.as_deref() == Some(b"v1.0.0")));
    assert!(snapshots
        .iter()
        .any(|(p, bytes)| p == &opt_syncthing && bytes.is_none()));

    // 2. Simulate installer making changes
    std::fs::write(&syncthing_ver, b"v2.0.0").unwrap();
    let _ = std::fs::create_dir_all(opt_syncthing.parent().unwrap());
    std::fs::write(&opt_syncthing, b"v2.0.0").unwrap();

    // 3. Service restart failed: stopped unit is inactive
    let stopped_units = vec!["nonexistent-restart-fail.service".to_string()];

    // Receipts are rolled back
    restore_candidate_receipts(&snapshots).unwrap();
    assert_eq!(std::fs::read(&syncthing_ver).unwrap(), b"v1.0.0");
    assert!(!opt_syncthing.exists());

    // 4. Job lifecycle finishes with finish_package_lifecycle
    let job_id = "test-service-restart-fail-job";
    let _ = af_services::try_start_package_job(af_services::PackageJobInfo {
        job_id: job_id.into(),
        package_id: "syncthing".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 10,
        last_line: "init".into(),
        started_at: "test-time".into(),
        expected_target_version: Some("v2.0.0".into()),
    });

    // Even if the caller passed failure: None and progress: 100,
    // finish_package_lifecycle must verify stopped_units and fail closed!
    finish_package_lifecycle(
        "syncthing",
        "update",
        None,
        100,
        "Completed update for syncthing",
        "test-time",
        job_id,
        Some("v2.0.0"),
        Some("v2.0.0"),
        &stopped_units,
    );

    let outcome = af_services::get_package_job_outcome("syncthing").unwrap();
    assert_ne!(
        outcome.status, "completed",
        "Job must NEVER be completed if stopped unit failed to restart"
    );
    assert_eq!(outcome.status, "failed");
    assert_eq!(outcome.failed_stage.as_deref(), Some("service_restore"));
    assert!(
        outcome.message.contains("service")
            || outcome.message.contains("stopped")
            || outcome
                .sanitized_summary
                .as_ref()
                .map(|s| s.contains("service") || s.contains("stopped"))
                .unwrap_or(false)
    );

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_candidate_receipt_sanitize_url_or_source_key_for_api_strips_credentials() {
    let sample_url = "https://user:super_secret@git.example.com/team/App.git";
    assert_eq!(
        sanitize_url_or_source_key_for_api(sample_url),
        "https://git.example.com/team/App.git"
    );

    let url_with_query =
        "https://user:super_secret@git.example.com/team/App.git?token=secret123&branch=main";
    assert_eq!(
        sanitize_url_or_source_key_for_api(url_with_query),
        "https://git.example.com/team/App.git"
    );

    let release_url_with_query =
        "https://github.com/org/repo/releases/v1.1.0?download=true&token=xyz";
    assert_eq!(
        sanitize_url_or_source_key_for_api(release_url_with_query),
        "https://github.com/org/repo/releases/v1.1.0"
    );

    let sample_key = "git_head:https://user:super_secret@git.example.com/team/App.git|team/App";
    assert_eq!(
        sanitize_url_or_source_key_for_api(sample_key),
        "git_head:https://git.example.com/team/App.git|team/App"
    );

    let key_with_query = "git_head:https://user:super_secret@git.example.com/team/App.git?token=secret123&branch=main|team/App";
    assert_eq!(
        sanitize_url_or_source_key_for_api(key_with_query),
        "git_head:https://git.example.com/team/App.git?token=[REDACTED]&branch=main|team/App"
    );

    let ssh_url = "ssh://user:super_secret@git.example.com/team/App.git";
    assert_eq!(
        sanitize_url_or_source_key_for_api(ssh_url),
        "ssh://git.example.com/team/App.git"
    );

    let token_url = "https://ghp_supersecret12345@github.com/org/repo.git";
    assert_eq!(
        sanitize_url_or_source_key_for_api(token_url),
        "https://github.com/org/repo.git"
    );

    let err_diagnostic = "Clone failed for https://user:pass@host/repo: password=\"secret123\"";
    let sanitized_err = sanitize_url_or_source_key_for_api(err_diagnostic);
    assert!(!sanitized_err.contains("user:pass@"));
    assert!(!sanitized_err.contains("secret123"));
    assert_eq!(
        sanitized_err,
        "Clone failed for https://host/repo: password=[REDACTED]"
    );
}

#[test]
fn test_admin_update_response_sanitizes_credentials() {
    let rec = af_services::workers::PackageUpdateRecord {
        package_id: "testapp".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "1.1.0".to_string(),
        update_available: true,
        checked_at: "2026-11-09T10:00:00Z".to_string(),
        release_url: "https://user:secret_token@git.example.com/org/testapp/releases/v1.1.0"
            .to_string(),
        error: "connection failed with password=\"super_secret_pw\" to https://admin:pwd@host/repo"
            .to_string(),
        source_key: "git_head:https://user:secret_token@git.example.com/org/testapp.git|main"
            .to_string(),
    };

    let sanitized_rec = sanitize_package_update_record(rec.clone());
    assert_eq!(
        sanitized_rec.release_url,
        "https://git.example.com/org/testapp/releases/v1.1.0"
    );
    assert_eq!(
        sanitized_rec.source_key,
        "git_head:https://git.example.com/org/testapp.git|main"
    );
    assert!(!sanitized_rec.error.contains("super_secret_pw"));
    assert!(!sanitized_rec.error.contains("pwd@"));

    let body = build_single_package_update_response("testapp", Some(rec));
    let body_str = body.to_string();
    assert!(!body_str.contains("secret_token"));
    assert!(!body_str.contains("super_secret_pw"));
    assert!(!body_str.contains("pwd@"));
    assert_eq!(
        body["update_url"],
        "https://git.example.com/org/testapp/releases/v1.1.0"
    );
    assert_eq!(
        body["release_url"],
        "https://git.example.com/org/testapp/releases/v1.1.0"
    );
    assert_eq!(
        body["update_source_key"],
        "git_head:https://git.example.com/org/testapp.git|main"
    );
}

#[test]
fn test_sanitize_package_update_record_redacts_installed_version() {
    let rec = af_services::workers::PackageUpdateRecord {
            package_id: "testapp".to_string(),
            installed: true,
            installed_version: "https://user:leak_token@git.example.com/app/v1.0.0?token=leak#secret-frag".to_string(),
            latest_version: "https://user:leak_token@git.example.com/app/v2.0.0?token=leak#secret-frag".to_string(),
            update_available: true,
            checked_at: "2026-11-09T10:00:00Z".to_string(),
            release_url: "https://user:leak_token@git.example.com/org/testapp/releases/v2.0.0?token=leak#secret-frag".to_string(),
            error: "failure with password=\"leak_pw\"".to_string(),
            source_key: "git_head:https://user:leak_token@git.example.com/org/testapp.git|main".to_string(),
        };

    let sanitized_rec = sanitize_package_update_record(rec);
    assert_eq!(
        sanitized_rec.installed_version,
        "https://git.example.com/app/v1.0.0"
    );
    assert!(!sanitized_rec.installed_version.contains("leak_token"));
    assert!(!sanitized_rec.installed_version.contains("secret-frag"));
    assert!(!sanitized_rec.installed_version.contains("token=leak"));

    let rec_kv = af_services::workers::PackageUpdateRecord {
        package_id: "testapp".to_string(),
        installed: true,
        installed_version: "1.2.3 token=leak_secret_token_123".to_string(),
        latest_version: "1.2.4".to_string(),
        update_available: true,
        checked_at: "2026-11-09T10:00:00Z".to_string(),
        release_url: "https://github.com/org/repo".to_string(),
        error: String::new(),
        source_key: "github:org/repo".to_string(),
    };
    let sanitized_kv = sanitize_package_update_record(rec_kv);
    assert_eq!(sanitized_kv.installed_version, "1.2.3 token=[REDACTED]");
    assert!(!sanitized_kv
        .installed_version
        .contains("leak_secret_token_123"));
}

#[test]
fn test_sanitize_url_or_source_key_for_api_strips_fragments_and_queries() {
    assert_eq!(
        sanitize_url_or_source_key_for_api(
            "https://user:pass@github.com/org/repo?token=1#secret-frag"
        ),
        "https://github.com/org/repo"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api("git@github.com:org/repo.git?token=1#secret-frag"),
        "git@github.com:org/repo.git"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api("user:pass@host:path?token=1#secret-frag"),
        "user@host:path"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api("https://example.com/download#hash"),
        "https://example.com/download"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api(
            "git-repo:ssh://Deploy@git.example.com/Team/App.git#main"
        ),
        "git-repo:ssh://Deploy@git.example.com/Team/App.git#main"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api(
            "git-repo:https://cred#a1b2c3d4e5f6@github.com/org/repo?q#123456789abc#main"
        ),
        "git-repo:https://cred#a1b2c3d4e5f6@github.com/org/repo?q#123456789abc#main"
    );
    assert_eq!(
        sanitize_url_or_source_key_for_api(
            "git-repo:https://user:pass@github.com/org/repo?bad_query#main"
        ),
        "git-repo:https://github.com/org/repo#main"
    );
}

#[test]
fn test_restore_candidate_receipts_creates_missing_directories_via_stepwise_mkdirat() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("af-test-mkdirat-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    // Nested parent directory does NOT exist initially
    let nested_receipt = temp_dir.join("var/lib/syncthing/.af-version");
    assert!(!nested_receipt.parent().unwrap().exists());

    let snapshots: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> = vec![(
        nested_receipt.clone(),
        Some(ReceiptSnapshotEntry::from(b"1.5.0".to_vec())),
    )];
    // Must succeed using stepwise descriptor-relative mkdirat + openat without std::fs::create_dir_all
    let res = restore_candidate_receipts(&snapshots);
    assert!(
        res.is_ok(),
        "Restoration must create missing directories safely: {:?}",
        res
    );
    assert_eq!(std::fs::read(&nested_receipt).unwrap(), b"1.5.0");

    // None case where parent does not exist should cleanly succeed as no-op
    let non_existent_file = temp_dir.join("opt/nonexistent/.af-version");
    let none_snapshots: Vec<(PathBuf, Option<ReceiptSnapshotEntry>)> =
        vec![(non_existent_file.clone(), None)];
    let none_res = restore_candidate_receipts(&none_snapshots);
    assert!(
        none_res.is_ok(),
        "None restoration with ENOENT parent must succeed as no-op"
    );
    assert!(!non_existent_file.exists());

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_finish_package_lifecycle_appends_inactive_stopped_units_diagnostics_when_failure_already_present(
) {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let job_id = "test-inactive-diag-job";
    let pkg_id = "syncthing";
    af_services::clear_package_job_info(pkg_id);
    let started = af_services::try_start_package_job(af_services::PackageJobInfo {
        job_id: job_id.into(),
        package_id: pkg_id.into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 10,
        last_line: "initial state".into(),
        started_at: "test-time".into(),
        expected_target_version: Some("v2.0.0".into()),
    });
    assert!(started, "Job must start");

    let stopped_units = vec!["nonexistent-inactive-dummy.service".to_string()];

    // Failure is already set (e.g. TargetVerification)
    finish_package_lifecycle(
        pkg_id,
        "update",
        Some(af_services::PackageJobFailure::TargetVerification),
        95,
        "Target certification failed: expected v2.0.0, achieved v1.0.0",
        "test-time",
        job_id,
        Some("v2.0.0"),
        Some("v1.0.0"),
        &stopped_units,
    );

    let outcome = af_services::get_package_job_outcome(pkg_id).unwrap();
    assert_eq!(outcome.status, "failed");
    let summary = outcome.sanitized_summary.as_deref().unwrap_or("");
    assert!(
        summary.contains("nonexistent-inactive-dummy.service")
            || summary.contains("stopped services failed to resume"),
        "Sanitized summary must contain inactive unit diagnostics: {summary}"
    );
}

#[test]
fn test_candidate_receipt_paths_includes_blueprint_config_and_restores_atomically() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir = std::env::temp_dir().join(format!("af-test-bp-config-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let (pkg, cfg_path) = if let Some(bp) =
        af_services::get_blueprint("radarr").filter(|b| !b.config_file_path.trim().is_empty())
    {
        ("radarr", bp.config_file_path.clone())
    } else if let Some(bp) =
        af_services::get_blueprint("sonarr").filter(|b| !b.config_file_path.trim().is_empty())
    {
        ("sonarr", bp.config_file_path.clone())
    } else {
        ("radarr", "/etc/radarr/config.xml".to_string())
    };

    let paths = marketplace::resolve_candidate_receipt_paths(pkg);
    let rel_trimmed = cfg_path.trim_start_matches(['/', '\\']);
    let expected_cfg = temp_dir.join(rel_trimmed);
    assert!(
        paths.contains(&expected_cfg),
        "Candidate receipt paths must include blueprint config {expected_cfg:?}, got: {paths:?}"
    );

    let _ = std::fs::create_dir_all(expected_cfg.parent().unwrap());
    std::fs::write(&expected_cfg, b"<Config><Port>7878</Port></Config>").unwrap();

    let snapshots = snapshot_candidate_receipts(pkg).unwrap();
    assert!(
        snapshots.iter().any(|(p, b)| p == &expected_cfg
            && b.as_deref() == Some(b"<Config><Port>7878</Port></Config>")),
        "Blueprint config must be snapshotted"
    );

    std::fs::write(
        &expected_cfg,
        b"<Config><Port>9999</Port><Corrupted/></Config>",
    )
    .unwrap();

    restore_candidate_receipts(&snapshots).unwrap();

    assert_eq!(
        std::fs::read(&expected_cfg).unwrap(),
        b"<Config><Port>7878</Port></Config>",
        "Blueprint config must be rolled back on certification or restart failure"
    );

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_candidate_receipt_preserves_mode_and_ownership_on_restoration() {
    let _env_lock = RECEIPT_TEST_MUTEX.lock().unwrap();
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-mode-restore-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let orig_root = std::env::var("AETHERFLOW_FS_ROOT").ok();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let receipt_path = temp_dir.join("var/lib/syncthing/.af-version");
    std::fs::create_dir_all(receipt_path.parent().unwrap()).unwrap();
    std::fs::write(&receipt_path, b"v1.0.0-secret").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let initial_meta = std::fs::symlink_metadata(&receipt_path).unwrap();
    #[cfg(unix)]
    let (initial_mode, initial_uid, initial_gid) = {
        use std::os::unix::fs::MetadataExt;
        (
            initial_meta.mode() & 0o7777,
            initial_meta.uid(),
            initial_meta.gid(),
        )
    };
    #[cfg(unix)]
    assert_eq!(initial_mode, 0o600);

    // 1. Snapshot candidate receipts
    let snapshots = snapshot_candidate_receipts("syncthing").unwrap();
    let snap_entry = snapshots
        .iter()
        .find(|(p, _)| p == &receipt_path)
        .and_then(|(_, e)| e.as_ref())
        .expect("receipt must be snapshotted");

    assert_eq!(snap_entry.bytes, b"v1.0.0-secret");
    #[cfg(unix)]
    {
        assert_eq!(snap_entry.mode, 0o600);
        assert_eq!(snap_entry.uid, initial_uid);
        assert_eq!(snap_entry.gid, initial_gid);
    }

    // 2. Simulate installer/attacker clobbering the file: modifying bytes and changing permissions to 0o644
    std::fs::write(&receipt_path, b"v2.0.0-clobbered").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&receipt_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    let clobbered_meta = std::fs::symlink_metadata(&receipt_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(clobbered_meta.mode() & 0o7777, 0o644);
    }

    // 3. Call restore_candidate_receipts
    restore_candidate_receipts(&snapshots).unwrap();

    // 4. Verify exact bytes restored
    assert_eq!(std::fs::read(&receipt_path).unwrap(), b"v1.0.0-secret");

    // 5. Verify mode is 0600 (NEVER 0644) and uid/gid preserved
    let restored_meta = std::fs::symlink_metadata(&receipt_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            restored_meta.mode() & 0o7777,
            0o600,
            "Mode must be restored to 0600, never left as 0644"
        );
        assert_eq!(restored_meta.uid(), initial_uid, "UID must be preserved");
        assert_eq!(restored_meta.gid(), initial_gid, "GID must be preserved");
    }

    if let Some(r) = orig_root {
        std::env::set_var("AETHERFLOW_FS_ROOT", r);
    } else {
        std::env::remove_var("AETHERFLOW_FS_ROOT");
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave22_api_sanitize_scalar_credentials_and_filebot_receipts() {
    let paths = marketplace::resolve_candidate_receipt_paths("filebot");
    assert!(
        paths
            .iter()
            .any(|p| p.to_string_lossy().contains("filebot-node")),
        "FileBot receipt paths must include opt/filebot-node/.af-version: {paths:?}"
    );

    let cases = [
        "Cookie: session=CANARY_COOKIE",
        "session=CANARY_SESSION",
        "{\"webhook_url\":\"https://example.test/CANARY_HOOK\"}",
        "pass=CANARY_PASSWORD",
        "https://example.test/cb?session=CANARY_Q1&pass=CANARY_Q2&webhook_url=CANARY_Q3",
    ];
    for case in cases {
        let sanitized = sanitize_url_or_source_key_for_api(case);
        assert!(
                !sanitized.contains("CANARY_"),
                "CANARY_ leaked in sanitize_url_or_source_key_for_api for input: {case:?}, got: {sanitized:?}"
            );
    }
}

#[test]
fn test_wave23_catalog_footprint_plex_and_mcvnc_unit_restoration() {
    let clean_plex = "plex";
    let mut plex_units = af_services::resolve_controllable_service_units(clean_plex, "stop");
    if let Ok(pkgs) = af_services::get_packages() {
        if let Some(p) = pkgs.into_iter().find(|p| p.name == clean_plex) {
            let svc = p.service_name.trim().to_string();
            if !svc.is_empty()
                && !matches!(
                    svc.as_str(),
                    "apache2" | "nginx" | "apache2.service" | "nginx.service"
                )
                && !plex_units.contains(&svc)
            {
                plex_units.push(svc);
            }
        }
    }
    let clean_mcvnc = "mcvnc";
    let mut mcvnc_units = af_services::resolve_controllable_service_units(clean_mcvnc, "stop");
    if let Ok(pkgs) = af_services::get_packages() {
        if let Some(p) = pkgs.into_iter().find(|p| p.name == clean_mcvnc) {
            let svc = p.service_name.trim().to_string();
            if !svc.is_empty()
                && !matches!(
                    svc.as_str(),
                    "apache2" | "nginx" | "apache2.service" | "nginx.service"
                )
                && !mcvnc_units.contains(&svc)
            {
                mcvnc_units.push(svc);
            }
        }
    }

    let temp_dir = std::env::temp_dir().join(format!(
        "af-test-w23-api-footprint-{}",
        uuid::Uuid::new_v4()
    ));
    let mut env_cfg = af_runner::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let sysd = temp_dir.join("etc/systemd/system");
    std::fs::create_dir_all(&sysd).unwrap();
    let mcvnc_file = sysd.join("af-mcvnc.service");
    std::fs::write(&mcvnc_file, b"OLD_MCVNC").unwrap();

    let mut mcvnc_snap = af_runner::package_lifecycle::PackageRuntimeSnapshot::capture(
        clean_mcvnc,
        &mcvnc_units,
        &env_cfg,
        false,
    )
    .unwrap();

    std::fs::write(&mcvnc_file, b"NEW_MCVNC").unwrap();
    mcvnc_snap.restore().unwrap();
    assert_eq!(std::fs::read(&mcvnc_file).unwrap(), b"OLD_MCVNC");

    let _ = std::fs::remove_dir_all(&temp_dir);
}
