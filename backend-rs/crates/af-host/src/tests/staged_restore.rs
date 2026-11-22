use super::{create_sample_wal_database, TempTestDir};
use crate::*;
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[test]
fn staged_restore_executes_verified_replacement_and_rolls_back_on_partial_failure() {
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MockQuiescence {
        events: Arc<Mutex<Vec<String>>>,
        fail_on_start: bool,
    }

    impl ServiceQuiescenceController for MockQuiescence {
        fn stop_services(&self, units: &[String]) -> HostBackupResult<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("stop:{}", units.join(",")));
            Ok(())
        }

        fn start_and_verify_services(&self, units: &[String]) -> HostBackupResult<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("start:{}", units.join(",")));
            if self.fail_on_start {
                return Err(HostBackupError::ServiceQuiescenceFailed {
                    unit: units.first().cloned().unwrap_or_default(),
                    phase: "start".to_string(),
                    reason: "simulated service restart failure".to_string(),
                });
            }
            Ok(())
        }
    }

    let tmp = TempTestDir::new("staged-restore");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    fs::write(etc_af.join("cluster.conf"), b"node_role=primary_v1\n").unwrap();

    let etc_env = host_root.join("etc/aetherflow");
    fs::create_dir_all(&etc_env).unwrap();
    fs::write(etc_env.join("aetherflow.env"), b"APP_MODE=golden_v1\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-01-120000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // 1. Mutate live host state (simulate post-backup drift + active WAL)
    {
        let conn = Connection::open(&live_db).unwrap();
        conn.execute(
            "UPDATE settings SET base_domain = 'drifted.example.test'",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (id, username) VALUES (99, 'drifted_user')",
            [],
        )
        .unwrap();
    }
    fs::write(etc_af.join("cluster.conf"), b"node_role=drifted_broken\n").unwrap();
    fs::write(etc_env.join("aetherflow.env"), b"APP_MODE=drifted_v1\n").unwrap();

    // 2. Unconfirmed restore must fail closed without touching files or stopping services
    let events = Arc::new(Mutex::new(Vec::new()));
    let mock_q = MockQuiescence {
        events: Arc::clone(&events),
        fail_on_start: false,
    };
    let unconfirmed_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            confirm_destructive_restore: false,
            allow_overwrite: true,
            quiesce_services: vec!["aetherflow-api.service".to_string()],
            ..Default::default()
        },
        &mock_q,
    )
    .unwrap_err();
    assert!(matches!(
        unconfirmed_err,
        HostBackupError::DestructiveRestoreUnsupported { .. }
    ));
    assert!(events.lock().unwrap().is_empty());

    // 3. Inject a mid-restore failure after 1 replacement (`fail_after_replacements: Some(1)`)
    // and verify automatic rollback restores drifted DB + configs + restarts services!
    let rollback_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["aetherflow-api.service".to_string()],
            fail_after_replacements: Some(1),
            ..Default::default()
        },
        &mock_q,
    )
    .unwrap_err();
    assert!(matches!(
        rollback_err,
        HostBackupError::RestoreRolledBack { .. }
    ));

    // Verify drifted files and DB were rolled back intact
    assert_eq!(
        fs::read_to_string(etc_af.join("cluster.conf")).unwrap(),
        "node_role=drifted_broken\n"
    );
    assert_eq!(
        fs::read_to_string(etc_env.join("aetherflow.env")).unwrap(),
        "APP_MODE=drifted_v1\n"
    );
    {
        let conn = Connection::open(&live_db).unwrap();
        let domain: String = conn
            .query_row("SELECT base_domain FROM settings WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(domain, "drifted.example.test");
    }

    // 3b. Fault-injection regression: inject BOTH a post-apply failure (`fail_after_replacements: Some(2)`)
    // AND a rollback failure (`fail_rollback_after_restores: Some(0)`) while a live WAL sidecar exists!
    // Verify:
    //  - returns `HostBackupError::RestoreRollbackFailed` (never claims rolled-back success),
    //  - preserves `recovery_dir` with pre-restore `.bak` and `.wal.bak` recovery copies intact,
    //  - writes a durable `rollback-failure-journal.json` recording all entries and errors,
    //  - leaves writer services STOPPED (`services_left_stopped == true`, no `start:` called).
    let live_wal = host_root.join("var/lib/aetherflow/aetherflow.sqlite-wal");
    fs::write(&live_wal, b"preserved-wal-frames-for-manual-recovery").unwrap();
    events.lock().unwrap().clear();

    let rb_failed_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["aetherflow-api.service".to_string()],
            fail_after_replacements: Some(2),
            fail_rollback_after_restores: Some(0),
            ..Default::default()
        },
        &mock_q,
    )
    .unwrap_err();

    match rb_failed_err {
        HostBackupError::RestoreRollbackFailed {
            recovery_dir,
            failure_journal_path,
            services_left_stopped,
            ..
        } => {
            assert!(
                services_left_stopped,
                "services must remain stopped when file rollback is incomplete"
            );
            assert!(
                recovery_dir.is_dir(),
                "recovery_dir must be preserved on rollback error"
            );
            assert!(
                failure_journal_path.is_file(),
                "durable rollback-failure-journal.json must exist"
            );
            // Services were stopped before replacement, and NEVER restarted after incomplete rollback
            assert_eq!(
                *events.lock().unwrap(),
                vec!["stop:aetherflow-api.service".to_string()]
            );

            let journal_raw = fs::read_to_string(&failure_journal_path).unwrap();
            let journal: RollbackFailureJournal = serde_json::from_str(&journal_raw).unwrap();
            assert!(journal.file_rollback_incomplete);
            assert!(journal.services_left_stopped);
            assert!(!journal.rollback_errors.is_empty());
            assert!(!journal.entries.is_empty());

            // Verify that pre-restore SQLite `.bak` and `.wal.bak` recovery copies survived in `recovery_dir`
            let sqlite_journal_entry = journal
                .entries
                .iter()
                .find(|e| e.destination_path.ends_with("aetherflow.sqlite"))
                .expect("SQLite entry must be recorded in rollback failure journal");
            let rb_db_copy = sqlite_journal_entry
                .rollback_copy_path
                .as_ref()
                .expect("SQLite rollback_copy_path must be present");
            let rb_wal_copy = sqlite_journal_entry
                .had_wal_copy
                .as_ref()
                .expect("SQLite WAL rollback copy path must be present");
            assert!(
                rb_db_copy.is_file(),
                "pre-restore SQLite recovery copy must survive failed rollback"
            );
            assert!(
                rb_wal_copy.is_file(),
                "pre-restore WAL recovery copy must survive failed rollback"
            );
            assert_eq!(
                fs::read(rb_wal_copy).unwrap(),
                b"preserved-wal-frames-for-manual-recovery"
            );

            // Clean up preserved recovery dir after verifying manual recovery artifacts
            let _ = fs::remove_dir_all(&recovery_dir);
        }
        other => panic!("expected RestoreRollbackFailed, got: {:?}", other),
    }

    // 4. Execute full confirmed staged restore and verify golden backup state is restored
    events.lock().unwrap().clear();
    let report = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            max_supported_sqlite_user_version: Some(50),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["aetherflow-api.service".to_string()],
            fail_after_replacements: None,
            ..Default::default()
        },
        &mock_q,
    )
    .expect("staged restore should succeed");

    assert!(report.sqlite_restored);
    assert!(report.sqlite_integrity_verified);
    assert_eq!(report.sqlite_user_version, Some(42));
    assert!(!report.rolled_back);
    assert_eq!(report.restored_files.len(), 3);
    assert_eq!(
        *events.lock().unwrap(),
        vec![
            "stop:aetherflow-api.service".to_string(),
            "start:aetherflow-api.service".to_string()
        ]
    );

    assert_eq!(
        fs::read_to_string(etc_af.join("cluster.conf")).unwrap(),
        "node_role=primary_v1\n"
    );
    assert_eq!(
        fs::read_to_string(etc_env.join("aetherflow.env")).unwrap(),
        "APP_MODE=golden_v1\n"
    );
    {
        let conn = Connection::open(&live_db).unwrap();
        let domain: String = conn
            .query_row("SELECT base_domain FROM settings WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        let user_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .unwrap();
        assert_eq!(domain, "seedbox.example.test");
        assert_eq!(user_count, 2);
    }
}

#[test]
fn restore_enforces_mandatory_quiescence_compensates_partial_stop_and_requiesces_on_partial_start(
) {
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct GranularQuiescence {
        events: Arc<Mutex<Vec<String>>>,
        fail_stop_unit: Option<String>,
        fail_start_call_index: Option<usize>,
        start_calls: Arc<Mutex<usize>>,
    }

    impl ServiceQuiescenceController for GranularQuiescence {
        fn stop_services(&self, units: &[String]) -> HostBackupResult<()> {
            for u in units {
                self.events.lock().unwrap().push(format!("stop:{}", u));
                if self.fail_stop_unit.as_deref() == Some(u.as_str()) {
                    return Err(HostBackupError::ServiceQuiescenceFailed {
                        unit: u.clone(),
                        phase: "stop".to_string(),
                        reason: "simulated stop failure on second unit".to_string(),
                    });
                }
            }
            Ok(())
        }

        fn start_and_verify_services(&self, units: &[String]) -> HostBackupResult<()> {
            let mut calls = self.start_calls.lock().unwrap();
            let current_call = *calls;
            *calls += 1;
            drop(calls);

            for u in units {
                self.events.lock().unwrap().push(format!("start:{}", u));
            }
            if self.fail_start_call_index == Some(current_call) {
                return Err(HostBackupError::ServiceQuiescenceFailed {
                    unit: units.last().cloned().unwrap_or_default(),
                    phase: "start".to_string(),
                    reason: "simulated partial restart failure".to_string(),
                });
            }
            Ok(())
        }
    }

    let tmp = TempTestDir::new("quiescence-compensation");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    fs::write(etc_af.join("cluster.conf"), b"node_role=golden\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-02-010000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Drift live file
    fs::write(etc_af.join("cluster.conf"), b"node_role=drifted\n").unwrap();

    let events = Arc::new(Mutex::new(Vec::new()));
    let q_partial_stop = GranularQuiescence {
        events: Arc::clone(&events),
        fail_stop_unit: Some("custom-writer.service".to_string()),
        fail_start_call_index: None,
        start_calls: Arc::new(Mutex::new(0)),
    };

    let stop_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["custom-writer.service".to_string()],
            ..Default::default()
        },
        &q_partial_stop,
    )
    .unwrap_err();
    assert!(matches!(
        stop_err,
        HostBackupError::ServiceQuiescenceFailed { ref phase, .. } if phase == "stop"
    ));
    assert_eq!(
        *events.lock().unwrap(),
        vec![
            "stop:aetherflow-api.service".to_string(),
            "stop:custom-writer.service".to_string(),
            "start:custom-writer.service".to_string(),
            "start:aetherflow-api.service".to_string(),
        ]
    );
    assert_eq!(
        fs::read_to_string(etc_af.join("cluster.conf")).unwrap(),
        "node_role=drifted\n"
    );

    let runner_bypass_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["aetherflow-runner.service".to_string()],
            ..Default::default()
        },
        &q_partial_stop,
    )
    .unwrap_err();
    assert!(matches!(
        runner_bypass_err,
        HostBackupError::InvalidConfig(_)
    ));

    let blank_bypass_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["".to_string()],
            ..Default::default()
        },
        &q_partial_stop,
    )
    .unwrap_err();
    assert!(matches!(
        blank_bypass_err,
        HostBackupError::InvalidConfig(_)
    ));

    let none_bypass_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["none".to_string()],
            ..Default::default()
        },
        &q_partial_stop,
    )
    .unwrap_err();
    assert!(matches!(none_bypass_err, HostBackupError::InvalidConfig(_)));

    events.lock().unwrap().clear();
    let q_partial_start = GranularQuiescence {
        events: Arc::clone(&events),
        fail_stop_unit: None,
        fail_start_call_index: Some(0),
        start_calls: Arc::new(Mutex::new(0)),
    };

    let post_commit_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["custom-writer.service".to_string()],
            ..Default::default()
        },
        &q_partial_start,
    )
    .unwrap_err();
    assert!(matches!(
        post_commit_err,
        HostBackupError::ServiceQuiescenceFailed { ref phase, .. } if phase == "start"
    ));
    assert_eq!(
        *events.lock().unwrap(),
        vec![
            "stop:aetherflow-api.service".to_string(),
            "stop:custom-writer.service".to_string(),
            "start:aetherflow-api.service".to_string(),
            "start:custom-writer.service".to_string(),
        ]
    );
    assert_eq!(
        fs::read_to_string(etc_af.join("cluster.conf")).unwrap(),
        "node_role=golden\n"
    );
    fs::write(
        etc_af.join("cluster.conf"),
        b"node_role=post_commit_live_write\n",
    )
    .unwrap();

    let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
    let recovered_after_commit =
        recover_interrupted_restore_with_context(&cfg.backup_dir, &rec_ctx, &q_partial_start)
            .unwrap();
    assert_eq!(recovered_after_commit.len(), 1);
    assert_eq!(
        fs::read_to_string(etc_af.join("cluster.conf")).unwrap(),
        "node_role=post_commit_live_write\n"
    );
}

#[test]
fn interrupted_restore_journal_recovers_pre_restore_state_and_preserves_permissions() {
    let tmp = TempTestDir::new("interrupted-recovery");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    let conf_path = etc_af.join("cluster.conf");
    fs::write(&conf_path, b"node_role=golden_before_backup\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&conf_path, fs::Permissions::from_mode(0o640)).unwrap();
    }

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-02-020000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    fs::write(&conf_path, b"node_role=pre_crash_live_state\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&conf_path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    let _ = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            fail_after_replacements: Some(2),
            fail_rollback_after_restores: Some(0),
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();

    let legacy_err =
        recover_interrupted_restore(&cfg.backup_dir, &NoopQuiescenceController).unwrap_err();
    assert!(matches!(legacy_err, HostBackupError::InvalidConfig(_)));

    let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
    let recovered = recover_interrupted_restore_with_context(
        &cfg.backup_dir,
        &rec_ctx,
        &NoopQuiescenceController,
    )
    .unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        fs::read_to_string(&conf_path).unwrap(),
        "node_role=pre_crash_live_state\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::symlink_metadata(&conf_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
    }
}

#[test]
fn delete_backup_artifacts_rejects_uninventoried_and_unverified_files_and_lock_serializes() {
    let tmp = TempTestDir::new("delete-and-lock");
    let backup_dir = tmp.path().join("backups");
    fs::create_dir_all(&backup_dir).unwrap();

    let secret_conf = backup_dir.join("important.conf");
    fs::write(&secret_conf, b"do-not-delete").unwrap();
    let err_conf = delete_backup_artifacts(&backup_dir, "important.conf").unwrap_err();
    assert!(matches!(err_conf, HostBackupError::PathValidation { .. }));
    assert!(secret_conf.is_file());

    let unverified_db = backup_dir.join("live_unverified.sqlite");
    fs::write(&unverified_db, b"unverified-db-bytes").unwrap();
    let err_unver = delete_backup_artifacts(&backup_dir, "live_unverified.sqlite").unwrap_err();
    assert!(matches!(
        err_unver,
        HostBackupError::MissingChecksumSidecar { .. }
    ));
    assert!(unverified_db.is_file());

    let lock_path = backup_dir.join(".maintenance.lock");
    let guard1 =
        HostMaintenanceLockGuard::acquire(&lock_path, Duration::from_millis(100)).unwrap();
    let busy_err =
        HostMaintenanceLockGuard::acquire(&lock_path, Duration::from_millis(60)).unwrap_err();
    assert!(busy_err.to_string().contains("maintenance lock busy"));
    drop(guard1);
    let guard2 =
        HostMaintenanceLockGuard::acquire(&lock_path, Duration::from_millis(100)).unwrap();
    drop(guard2);

    let primary_lock_path = tmp.path().join("primary-system.lock");
    std::env::set_var("AETHERFLOW_MAINTENANCE_LOCK_PATH", &primary_lock_path);
    let primary_guard =
        HostMaintenanceLockGuard::acquire(&primary_lock_path, Duration::from_millis(100))
            .unwrap();
    let fallback_bypass_err =
        HostMaintenanceLockGuard::acquire_default(Some(&backup_dir), Duration::from_millis(60))
            .unwrap_err();
    std::env::remove_var("AETHERFLOW_MAINTENANCE_LOCK_PATH");
    assert!(fallback_bypass_err
        .to_string()
        .contains("maintenance lock busy"));
    drop(primary_guard);

    let (_, mapped) = resolve_trusted_canonical_host_destination(
        Path::new("/"),
        "etc/AetherFlow/cluster.conf",
    )
    .unwrap();
    assert_eq!(mapped, PathBuf::from("/etc/AetherFlow/cluster.conf"));

    let bad_canonical =
        resolve_trusted_canonical_host_destination(Path::new("/"), "etc/passwd").unwrap_err();
    assert!(bad_canonical.is_security_rejection());
}

#[test]
fn backup_and_restore_enforce_source_sqlite_metadata_and_sanitize_corrupt_target_modes() {
    let tmp = TempTestDir::new("metadata-policy-regression");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    let lock_file = etc_af.join(".Lock");
    fs::write(&lock_file, b"lock_state=installed_v4\n").unwrap();

    let etc_env = host_root.join("etc/aetherflow");
    fs::create_dir_all(&etc_env).unwrap();
    let env_file = etc_env.join("aetherflow.env");
    fs::write(&env_file, b"ENV_PROFILE=golden_v1\n").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&live_db, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&lock_file, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&env_file, fs::Permissions::from_mode(0o644)).unwrap();
    }

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let sqlite_receipt =
        create_sqlite_snapshot_backup(&cfg, Some("2026-11-03_01-00-00")).unwrap();
    let archive_receipt = create_host_archive_backup(&cfg, Some("2026-11-03-010000")).unwrap();

    let sqlite_entry = sqlite_receipt
        .manifest
        .entries
        .iter()
        .find(|entry| entry.kind == BackupTargetKind::SqliteSnapshot)
        .expect("standalone sqlite manifest entry");
    let archive_db_entry = archive_receipt
        .manifest
        .entries
        .iter()
        .find(|entry| entry.kind == BackupTargetKind::SqliteSnapshot)
        .expect("archive sqlite manifest entry");
    let archive_lock_entry = archive_receipt
        .manifest
        .entries
        .iter()
        .find(|entry| entry.relative_path.ends_with(".Lock"))
        .expect("archive .Lock manifest entry");

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let source_meta = fs::symlink_metadata(&live_db).unwrap();
        let expected_uid = source_meta.uid();
        let expected_gid = source_meta.gid();
        assert_eq!(sqlite_entry.unix_mode, Some(0o640));
        assert_eq!(sqlite_entry.unix_uid, Some(expected_uid));
        assert_eq!(sqlite_entry.unix_gid, Some(expected_gid));
        assert_eq!(archive_db_entry.unix_mode, Some(0o640));
        assert_eq!(archive_db_entry.unix_uid, Some(expected_uid));
        assert_eq!(archive_db_entry.unix_gid, Some(expected_gid));
        assert_eq!(archive_lock_entry.unix_mode, Some(0o640));

        let snapshot_disk_mode = fs::symlink_metadata(&sqlite_receipt.primary_artifact_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(snapshot_disk_mode, 0o600);
    }

    #[cfg(unix)]
    let (expected_db_uid, expected_db_gid) = {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(&live_db).unwrap();
        (Some(meta.uid()), Some(meta.gid()))
    };
    #[cfg(not(unix))]
    let (expected_db_uid, expected_db_gid) = (None, None);

    let mut custom_manifest = archive_receipt.manifest.clone();
    for entry in &mut custom_manifest.entries {
        if entry.kind == BackupTargetKind::SqliteSnapshot {
            entry.unix_uid = expected_db_uid;
            entry.unix_gid = expected_db_gid;
            entry.unix_mode = Some(0o640);
        }
    }
    custom_manifest
        .save_atomic(&archive_receipt.manifest_path)
        .unwrap();

    fs::write(&lock_file, b"lock_state=corrupted\n").unwrap();
    fs::write(&env_file, b"ENV_PROFILE=corrupted\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&live_db, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&lock_file, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&env_file, fs::Permissions::from_mode(0o777)).unwrap();
    }

    let archive_filename = archive_receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let rb_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            fail_after_replacements: Some(2),
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();
    assert!(matches!(rb_err, HostBackupError::RestoreRolledBack { .. }));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let lock_rb_mode = fs::symlink_metadata(&lock_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(lock_rb_mode, 0o777);
    }

    let report = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap();
    assert!(report.sqlite_restored);
    assert_eq!(
        fs::read_to_string(&lock_file).unwrap(),
        "lock_state=installed_v4\n"
    );
    assert_eq!(
        fs::read_to_string(&env_file).unwrap(),
        "ENV_PROFILE=golden_v1\n"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let db_mode = fs::symlink_metadata(&live_db).unwrap().permissions().mode() & 0o777;
        let lock_mode = fs::symlink_metadata(&lock_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let env_mode = fs::symlink_metadata(&env_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(db_mode, 0o640);
        assert_eq!(lock_mode, 0o640);
        assert_eq!(env_mode, 0o600);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&live_db, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let sqlite_filename = sqlite_receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let sqlite_report = execute_staged_restore(
        &cfg.backup_dir,
        &sqlite_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap();
    assert!(sqlite_report.sqlite_restored);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let db_mode_after_sqlite_restore =
            fs::symlink_metadata(&live_db).unwrap().permissions().mode() & 0o777;
        assert_eq!(db_mode_after_sqlite_restore, 0o640);
    }
}

#[test]
fn terminal_committed_and_rolled_back_journals_recover_without_clobbering_new_writes() {
    use std::sync::{Arc, Mutex};

    struct RecordingQuiescence {
        events: Arc<Mutex<Vec<String>>>,
        fail_first_start: Arc<Mutex<bool>>,
    }

    impl ServiceQuiescenceController for RecordingQuiescence {
        fn stop_services(&self, units: &[String]) -> HostBackupResult<()> {
            for unit in units {
                self.events.lock().unwrap().push(format!("stop:{}", unit));
            }
            Ok(())
        }

        fn start_and_verify_services(&self, units: &[String]) -> HostBackupResult<()> {
            for unit in units {
                self.events.lock().unwrap().push(format!("start:{}", unit));
            }
            let mut fail_flag = self.fail_first_start.lock().unwrap();
            if *fail_flag {
                *fail_flag = false;
                return Err(HostBackupError::ServiceQuiescenceFailed {
                    unit: units.first().cloned().unwrap_or_default(),
                    phase: "start".to_string(),
                    reason: "simulated post-commit start failure".to_string(),
                });
            }
            Ok(())
        }
    }

    let tmp = TempTestDir::new("terminal-journal-idempotency");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    let conf_path = etc_af.join("cluster.conf");
    fs::write(&conf_path, b"node_role=backup_v1\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-030000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    fs::write(&conf_path, b"node_role=stale_pre_restore\n").unwrap();

    let events = Arc::new(Mutex::new(Vec::new()));
    let rec_q = RecordingQuiescence {
        events: Arc::clone(&events),
        fail_first_start: Arc::new(Mutex::new(true)),
    };

    let start_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            ..Default::default()
        },
        &rec_q,
    )
    .unwrap_err();
    assert!(matches!(
        start_err,
        HostBackupError::ServiceQuiescenceFailed { .. }
    ));

    fs::write(&conf_path, b"node_role=post_restore_new_write\n").unwrap();
    events.lock().unwrap().clear();

    let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
    let recovered =
        recover_interrupted_restore_with_context(&cfg.backup_dir, &rec_ctx, &rec_q).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        fs::read_to_string(&conf_path).unwrap(),
        "node_role=post_restore_new_write\n"
    );
    assert_eq!(
        *events.lock().unwrap(),
        vec!["start:aetherflow-api.service".to_string()]
    );
}

#[test]
fn compensation_restart_failure_propagates_and_leaves_quiescing_journal_for_recovery() {
    use std::sync::{Arc, Mutex};

    struct FailingCompensationQuiescence {
        events: Arc<Mutex<Vec<String>>>,
        fail_stop: bool,
        fail_comp_start: bool,
    }

    impl ServiceQuiescenceController for FailingCompensationQuiescence {
        fn stop_services(&self, units: &[String]) -> HostBackupResult<()> {
            for unit in units {
                self.events.lock().unwrap().push(format!("stop:{}", unit));
                if self.fail_stop && unit == "second-writer.service" {
                    return Err(HostBackupError::ServiceQuiescenceFailed {
                        unit: unit.clone(),
                        phase: "stop".to_string(),
                        reason: "second unit stop failed".to_string(),
                    });
                }
            }
            Ok(())
        }

        fn start_and_verify_services(&self, units: &[String]) -> HostBackupResult<()> {
            for unit in units {
                self.events.lock().unwrap().push(format!("start:{}", unit));
                if self.fail_comp_start {
                    return Err(HostBackupError::ServiceQuiescenceFailed {
                        unit: unit.clone(),
                        phase: "start".to_string(),
                        reason: "compensation start failed".to_string(),
                    });
                }
            }
            Ok(())
        }
    }

    let tmp = TempTestDir::new("comp-restart-failure");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_sqlite_snapshot_backup(&cfg, Some("2026-11-03_03-10-00")).unwrap();
    let filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let events = Arc::new(Mutex::new(Vec::new()));
    let fail_q = FailingCompensationQuiescence {
        events: Arc::clone(&events),
        fail_stop: true,
        fail_comp_start: true,
    };

    let err = execute_staged_restore(
        &cfg.backup_dir,
        &filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["second-writer.service".to_string()],
            ..Default::default()
        },
        &fail_q,
    )
    .unwrap_err();

    assert!(err.to_string().contains("compensation restart errors"));

    let ok_q = FailingCompensationQuiescence {
        events: Arc::clone(&events),
        fail_stop: false,
        fail_comp_start: false,
    };
    let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
    let recovered =
        recover_interrupted_restore_with_context(&cfg.backup_dir, &rec_ctx, &ok_q).unwrap();
    assert_eq!(recovered.len(), 1);
}

#[test]
fn recovery_journal_rejects_untrusted_destinations_missing_sidecars_and_outside_copies() {
    let tmp = TempTestDir::new("journal-validation");
    let host_root = tmp.path().join("host");
    let backup_dir = host_root.join("var/lib/aetherflow/backups");
    fs::create_dir_all(&backup_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&backup_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let rb_dir = backup_dir.join(".rollback-restore.forged");
    open_or_create_dir_nofollow(&rb_dir, 0o700, "forged rb_dir").unwrap();

    let outside_target = tmp.path().join("outside-target.conf");
    let forged_journal = RollbackFailureJournal {
        backup_id: "forged-id".to_string(),
        primary_artifact: "aetherflow-backup-2026-11-03-000000.tar.gz".to_string(),
        target_root: host_root.clone(),
        recovery_dir: rb_dir.clone(),
        apply_failure_reason: "in_progress".to_string(),
        rollback_errors: Vec::new(),
        file_rollback_incomplete: true,
        services_left_stopped: true,
        quiesced_services: vec!["aetherflow-api.service".to_string()],
        entries: vec![RollbackFailureJournalEntry {
            destination_path: outside_target,
            kind: Some(BackupTargetKind::ConfigFile),
            existed_before: false,
            rollback_copy_path: None,
            rollback_copy_sha256: None,
            had_wal_copy: None,
            wal_copy_sha256: None,
            had_shm_copy: None,
            shm_copy_sha256: None,
            original_mode: None,
            original_uid: None,
            original_gid: None,
            wal_mode: None,
            wal_uid: None,
            wal_gid: None,
            shm_mode: None,
            shm_uid: None,
            shm_gid: None,
            restored_during_rollback: false,
        }],
        journal_state: "in_progress".to_string(),
        trusted_sqlite_db_path: None,
        generation: 1,
        journal_digest_sha256: Some("0".repeat(64)),
    };

    let journal_path = rb_dir.join(IN_PROGRESS_RECOVERY_JOURNAL_FILENAME);
    fs::write(
        &journal_path,
        serde_json::to_vec_pretty(&forged_journal).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
    let missing_sidecar_err = recover_interrupted_restore_with_context(
        &backup_dir,
        &rec_ctx,
        &NoopQuiescenceController,
    )
    .unwrap_err();
    assert!(matches!(
        missing_sidecar_err,
        HostBackupError::MissingChecksumSidecar { .. }
    ));

    write_sha256_sidecar(&journal_path).unwrap();
    let unauthenticated_err = recover_interrupted_restore_with_context(
        &backup_dir,
        &rec_ctx,
        &NoopQuiescenceController,
    )
    .unwrap_err();
    assert!(matches!(
        unauthenticated_err,
        HostBackupError::InvalidManifest(_)
    ));
}
