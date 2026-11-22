use super::{
    build_synthetic_release_tarball, read_sqlite_marker, seed_valid_sqlite_db,
    MockArtifactProvider, MockHealthProber, MockLifecycle, TempSandbox,
};
use crate::*;
use rusqlite::Connection;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tar::EntryType;

#[test]
fn test_automatic_rollback_and_corrupted_db_recovery_on_probe_failure() {
    let sb = TempSandbox::new("rollback-corrupt");
    let mut cfg = ReleaseConfig::for_root(sb.path());
    cfg.health_retries = 2;
    cfg.health_interval = Duration::from_millis(1);

    let live_db = cfg.host_data_dir.join(&cfg.sqlite_db);
    seed_valid_sqlite_db(&live_db, "golden-before-bad-deploy");

    let tar_path = sb.path().join("release.tar.gz");
    let (_, manifest) = build_synthetic_release_tarball(
        &tar_path,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"binary", EntryType::Regular),
            (".version", b"v4.0.0\n", EntryType::Regular),
            (
                "web/dist/index.html",
                b"synthetic test index",
                EntryType::Regular,
            ),
            (
                "web/dist/app.wasm",
                b"synthetic test wasm",
                EntryType::Regular,
            ),
        ],
    );

    let provider = MockArtifactProvider {
        resolved_tag: Ok("v4.0.0".to_string()),
        archive_source: tar_path,
        manifest_content: manifest,
    };

    // First deploy succeeds to establish a valid `.previous_release` target
    let initial_lifecycle = MockLifecycle::default();
    let initial_prober = MockHealthProber::new(vec![Ok(HealthCheckAttempt {
        http_status: 200,
        body: r#"{"status":"ready"}"#.to_string(),
    })]);
    let initial_engine = ReleaseEngine::new(
        cfg.clone(),
        provider.clone(),
        initial_lifecycle,
        initial_prober,
    );
    let opts = ReleaseOptions::default();
    let first_deploy = match initial_engine.execute(&opts).unwrap() {
        ReleaseOutcome::Deploy(r) => r,
        _ => panic!("expected deploy"),
    };

    // Second deploy: simulates database corruption during service restart AND fails readiness probes
    let bad_lifecycle = MockLifecycle {
        unit_env: None,
        calls: Arc::new(Mutex::new(Vec::new())),
        corrupt_db_on_restart: Some(live_db.clone()),
        fail_stop_services: false,
        stale_identity: false,
        always_stale_identity: false,
    };
    let failing_prober = MockHealthProber::new(vec![
        Ok(HealthCheckAttempt {
            http_status: 500,
            body: r#"{"status":"degraded"}"#.to_string(),
        }),
        Ok(HealthCheckAttempt {
            http_status: 500,
            body: r#"{"status":"degraded"}"#.to_string(),
        }),
        Ok(HealthCheckAttempt {
            http_status: 200,
            body: r#"{"status":"ready"}"#.to_string(),
        }),
    ]);
    let bad_engine =
        ReleaseEngine::new(cfg.clone(), provider, bad_lifecycle.clone(), failing_prober);

    let err = bad_engine.execute(&opts).unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::HealthProbeFailedRollback);
    match err {
        ReleaseError::RolledBackAfterProbeFailure {
            reverted_to,
            db_restored,
            ..
        } => {
            assert_eq!(
                canonicalize_preserve_normal(&reverted_to),
                canonicalize_preserve_normal(&first_deploy.release_dir)
            );
            assert!(
                db_restored,
                "corrupted live DB must be restored from pre-swap snapshot"
            );
        }
        other => panic!("unexpected error variant: {:?}", other),
    }

    // Verify current_link points back to first_deploy, WAL/SHM sidecars were cleaned,
    // services were stopped BEFORE restore, and live DB has original marker data intact.
    assert_eq!(
        read_current_link_target(&cfg.current_link).unwrap(),
        canonicalize_preserve_normal(&first_deploy.release_dir)
    );
    assert_eq!(sqlite_integrity(&live_db), "ok");
    assert_eq!(read_sqlite_marker(&live_db), "golden-before-bad-deploy");
    assert!(!PathBuf::from(format!("{}-wal", live_db.display())).exists());
    assert!(!PathBuf::from(format!("{}-shm", live_db.display())).exists());

    let calls = bad_lifecycle.recorded_calls();
    assert!(
        calls.iter().any(|c| c.starts_with("stop_db_services:")),
        "services must be stopped before restoring corrupted database"
    );
}
#[test]
fn test_regression_preplanted_collision_and_symlink_escape_rejected() {
    let sb = TempSandbox::new("escape-regression");
    let cfg = ReleaseConfig::for_root(sb.path());

    let tar_path = sb.path().join("release.tar.gz");
    build_synthetic_release_tarball(
        &tar_path,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"binary-content", EntryType::Regular),
            (".version", b"v4.0.0\n", EntryType::Regular),
            (
                "web/dist/index.html",
                b"synthetic test index",
                EntryType::Regular,
            ),
            (
                "web/dist/app.wasm",
                b"synthetic test wasm",
                EntryType::Regular,
            ),
            ("config/app.json", b"{\"ok\":true}", EntryType::Regular),
        ],
    );

    // 1. Pre-existing non-empty release directory or pre-planted file inside release_dir must be rejected
    let preplanted_dir = sb.path().join("preplanted-release");
    fs::create_dir_all(&preplanted_dir).unwrap();
    fs::write(preplanted_dir.join("aetherflow-api"), b"preplanted").unwrap();
    let err_non_empty =
        extract_and_validate_release_archive(&tar_path, &preplanted_dir, "v4.0.0", &cfg)
            .unwrap_err();
    assert!(matches!(
        err_non_empty,
        ReleaseError::ArchiveExtraction { .. }
    ));

    // 2. Duplicate file entry inside tarball must be rejected by open_exclusive_private_file / collision check
    let dup_tar = sb.path().join("dup.tar.gz");
    build_synthetic_release_tarball(
        &dup_tar,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"first", EntryType::Regular),
            ("aetherflow-api", b"second-overwrite", EntryType::Regular),
        ],
    );
    let dup_extract_dir = sb.path().join("dup-extract");
    let err_dup = extract_and_validate_release_archive(&dup_tar, &dup_extract_dir, "v4.0.0", &cfg)
        .unwrap_err();
    assert!(matches!(err_dup, ReleaseError::ArchiveExtraction { .. }));

    // 3. On Unix, pre-existing symlinked release_dir or ancestor symlink must be rejected before extraction
    #[cfg(unix)]
    {
        let outside_victim = sb.path().join("outside-victim");
        fs::create_dir_all(&outside_victim).unwrap();
        let symlink_release_dir = sb.path().join("symlink-release-dir");
        std::os::unix::fs::symlink(&outside_victim, &symlink_release_dir).unwrap();

        let err_sym =
            extract_and_validate_release_archive(&tar_path, &symlink_release_dir, "v4.0.0", &cfg)
                .unwrap_err();
        assert!(
            matches!(
                err_sym,
                ReleaseError::PathValidation { .. } | ReleaseError::ArchiveExtraction { .. }
            ),
            "expected symlinked release_dir to be rejected, got: {:?}",
            err_sym
        );
        assert!(
            !outside_victim.join("aetherflow-api").exists(),
            "must never extract files into symlink target outside root"
        );

        // Ancestor symlink test
        let nested_under_symlink = symlink_release_dir.join("sub-release");
        let err_anc =
            extract_and_validate_release_archive(&tar_path, &nested_under_symlink, "v4.0.0", &cfg)
                .unwrap_err();
        assert!(matches!(err_anc, ReleaseError::PathValidation { .. }));
    }
}

#[test]
fn test_rollback_database_failure_remains_failed_without_readmitting_writers() {
    for fail_stop_services in [false, true] {
        let sandbox = TempSandbox::new("rollback-recovery-failure");
        let config = ReleaseConfig::for_root(sandbox.path());
        let live_db = config.host_data_dir.join(&config.sqlite_db);
        seed_valid_sqlite_db(&live_db, "protected-rollback-state");
        let previous_release = config.releases_dir.join("1700000001");
        let candidate_release = config.releases_dir.join("1700000002");
        fs::create_dir_all(&previous_release).unwrap();
        fs::create_dir_all(&candidate_release).unwrap();
        let resolved = ResolvedDbPath {
            path: live_db.clone(),
            source: DbPathSource::DataDirDefault,
        };
        create_state_snapshot(&config, &resolved, &previous_release, false).unwrap();
        fs::write(
            previous_release.join("data-snapshot/MANIFEST.sha256"),
            format!("{}  {}.bak\n", "0".repeat(64), config.sqlite_db),
        )
        .unwrap();
        fs::write(&live_db, b"CORRUPT DATABASE MUST REMAIN UNMODIFIED").unwrap();
        let wal_path = PathBuf::from(format!("{}-wal", live_db.display()));
        fs::write(&wal_path, b"PRESERVED WAL SENTINEL").unwrap();
        let shm_path = PathBuf::from(format!("{}-shm", live_db.display()));
        fs::write(&shm_path, b"PRESERVED SHM SENTINEL").unwrap();
        fs::write(
            config.releases_dir.join(".previous_release"),
            previous_release.to_string_lossy().as_bytes(),
        )
        .unwrap();
        atomic_replace_symlink(&config.current_link, &candidate_release, "failed-rollback")
            .unwrap();
        let lifecycle = MockLifecycle {
            fail_stop_services,
            ..MockLifecycle::default()
        };
        let provider = MockArtifactProvider {
            resolved_tag: Err("rollback must not fetch a release".to_string()),
            archive_source: PathBuf::new(),
            manifest_content: String::new(),
        };
        let engine = ReleaseEngine::new(
            config.clone(),
            provider,
            lifecycle.clone(),
            MockHealthProber::new(vec![]),
        );
        let options = ReleaseOptions {
            command: ReleaseCommand::Rollback,
            ..ReleaseOptions::default()
        };
        let error = engine.execute(&options).unwrap_err();
        assert_eq!(error.exit_code(), ExitCode::RollbackFailed);
        assert!(error.to_string().contains("database recovery failed"));
        let calls = lifecycle.recorded_calls();
        assert!(calls
            .iter()
            .any(|call| call.starts_with("stop_db_services:")));
        assert!(!calls.iter().any(|call| call == "restart_units"));
        let recovery = RecoveryState::load(&config.releases_dir).unwrap().unwrap();
        assert_eq!(recovery.phase, ReleasePhase::Failed);
        assert!(recovery
            .last_error
            .unwrap()
            .contains("database recovery failed"));
        assert_eq!(
            fs::read(&live_db).unwrap(),
            b"CORRUPT DATABASE MUST REMAIN UNMODIFIED"
        );
        assert_eq!(fs::read(&wal_path).unwrap(), b"PRESERVED WAL SENTINEL");
        assert_eq!(fs::read(&shm_path).unwrap(), b"PRESERVED SHM SENTINEL");
        assert!(!fs::read_to_string(&config.log_file)
            .unwrap()
            .contains("ROLLBACK COMPLETE"));
        if fail_stop_services {
            assert!(error.to_string().contains("writer quiescence also failed"));
        }
    }
}

#[test]
fn test_regression_restore_rejects_stop_services_failure_and_tampered_snapshot() {
    let sb = TempSandbox::new("restore-safety");
    let cfg = ReleaseConfig::for_root(sb.path());
    let live_db = cfg.host_data_dir.join(&cfg.sqlite_db);
    seed_valid_sqlite_db(&live_db, "clean-v4-state");

    let resolved = ResolvedDbPath {
        path: live_db.clone(),
        source: DbPathSource::DataDirDefault,
    };
    let release_dir = cfg.releases_dir.join("1700000001");
    create_new_dir_exclusive(&release_dir, 0o755, 0o755).unwrap();

    let snap = create_state_snapshot(&cfg, &resolved, &release_dir, false).unwrap();
    assert!(snap.created);

    // Corrupt the live DB
    fs::write(&live_db, b"CORRUPTED LIVE DB BYTES").unwrap();
    fs::write(format!("{}-wal", live_db.display()), b"active-wal").unwrap();

    // Case A: stop_services returns Err -> restore MUST fail closed and MUST NOT remove WAL or overwrite DB
    let stop_err = restore_state_if_corrupted(&cfg, &resolved, &release_dir, false, |_db| {
        Err(ReleaseError::Systemd {
            action: "systemctl stop".to_string(),
            reason: "permission denied stopping service".to_string(),
        })
    })
    .unwrap_err();
    assert!(stop_err.to_string().contains("stopping services failed"));
    assert!(
        PathBuf::from(format!("{}-wal", live_db.display())).exists(),
        "WAL sidecar must not be removed when stopping services failed"
    );

    // Case B: Tamper with MANIFEST.sha256 -> restore MUST fail closed before stopping services or copying
    let manifest_path = snap.manifest_path.as_ref().unwrap();
    let original_manifest = fs::read_to_string(manifest_path).unwrap();
    fs::write(
        manifest_path,
        format!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  {}.bak\n",
            cfg.sqlite_db
        ),
    )
    .unwrap();

    let mut stop_called = false;
    let tamper_err = restore_state_if_corrupted(&cfg, &resolved, &release_dir, false, |_db| {
        stop_called = true;
        Ok(())
    })
    .unwrap_err();
    assert!(
        tamper_err.to_string().contains("SHA-256 mismatch"),
        "expected SHA-256 mismatch error, got: {}",
        tamper_err
    );
    assert!(
        !stop_called,
        "services should not even be stopped if snapshot manifest verification fails"
    );

    // Restore valid manifest -> restore succeeds atomically and recovers original marker
    fs::write(manifest_path, original_manifest).unwrap();
    let ok_report =
        restore_state_if_corrupted(&cfg, &resolved, &release_dir, false, |_db| Ok(())).unwrap();
    assert!(ok_report.restored_from_snapshot);
    assert!(ok_report.quarantined_corrupted_path.is_some());
    assert_eq!(read_sqlite_marker(&live_db), "clean-v4-state");
}

#[test]
fn test_regression_interrupted_post_swap_deploy_blocks_overwrite_until_rollback() {
    let sb = TempSandbox::new("interrupted-recovery");
    let mut cfg = ReleaseConfig::for_root(sb.path());
    cfg.health_interval = Duration::from_millis(1);

    let tar_path = sb.path().join("release.tar.gz");
    let (_, manifest) = build_synthetic_release_tarball(
        &tar_path,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"binary", EntryType::Regular),
            (".version", b"v4.0.0\n", EntryType::Regular),
            (
                "web/dist/index.html",
                b"synthetic test index",
                EntryType::Regular,
            ),
            (
                "web/dist/app.wasm",
                b"synthetic test wasm",
                EntryType::Regular,
            ),
        ],
    );

    let provider = MockArtifactProvider {
        resolved_tag: Ok("v4.0.0".to_string()),
        archive_source: tar_path,
        manifest_content: manifest,
    };
    let lifecycle = MockLifecycle::default();
    let prober = MockHealthProber::new(vec![
        Ok(HealthCheckAttempt {
            http_status: 200,
            body: r#"{"status":"ready"}"#.to_string(),
        }),
        Ok(HealthCheckAttempt {
            http_status: 200,
            body: r#"{"status":"ready"}"#.to_string(),
        }),
        Ok(HealthCheckAttempt {
            http_status: 200,
            body: r#"{"status":"ready"}"#.to_string(),
        }),
    ]);

    let engine = ReleaseEngine::new(cfg.clone(), provider, lifecycle, prober);
    let deploy_opts = ReleaseOptions::default();

    // 1. Deploy good release R1
    let r1 = match engine.execute(&deploy_opts).unwrap() {
        ReleaseOutcome::Deploy(r) => r,
        _ => panic!("expected deploy"),
    };

    // 2. Simulate an interrupted unhealthy deployment R2 that crashed right after Stage 2 symlink swap
    // (`current` points to broken R2, `.previous_release` points to R1, `.recovery_state.json` is in Stage3HealthProbe)
    let broken_r2 = cfg.releases_dir.join("9999999999");
    create_new_dir_exclusive(&broken_r2, 0o755, 0o755).unwrap();
    perform_symlink_swap(
        &cfg.releases_dir,
        &cfg.current_link,
        &broken_r2,
        "9999999999",
    )
    .unwrap();

    let mut crashed_state =
        RecoveryState::new(ReleaseCommand::Deploy, ReleaseChannel::Stable, false);
    crashed_state.phase = ReleasePhase::Stage3HealthProbe;
    crashed_state.candidate_release = Some(broken_r2.clone());
    crashed_state.previous_release = Some(r1.release_dir.clone());
    crashed_state.save(&cfg.releases_dir).unwrap();

    // 3. Attempting a new `deploy` while R2 is unfinished MUST fail closed so `.previous_release` (R1)
    // is not overwritten with broken R2!
    let blocked_err = engine.execute(&deploy_opts).unwrap_err();
    assert_eq!(blocked_err.exit_code(), ExitCode::RollbackFailed);
    assert!(blocked_err
        .to_string()
        .contains("unfinished after symlink swap"));
    assert_eq!(
        canonicalize_preserve_normal(&read_previous_release(&cfg.releases_dir).unwrap()),
        canonicalize_preserve_normal(&r1.release_dir),
        "known-good .previous_release (R1) must remain intact"
    );

    // 4. Running `rollback` recovers cleanly back to R1 and marks recovery state Complete
    let rollback_opts = ReleaseOptions {
        command: ReleaseCommand::Rollback,
        ..ReleaseOptions::default()
    };
    let rb = match engine.execute(&rollback_opts).unwrap() {
        ReleaseOutcome::Rollback(r) => r,
        _ => panic!("expected rollback"),
    };
    assert_eq!(
        canonicalize_preserve_normal(&rb.reverted_to),
        canonicalize_preserve_normal(&r1.release_dir)
    );
    assert_eq!(
        read_current_link_target(&cfg.current_link).unwrap(),
        canonicalize_preserve_normal(&r1.release_dir)
    );
    assert_eq!(
        RecoveryState::load(&cfg.releases_dir)
            .unwrap()
            .unwrap()
            .phase,
        ReleasePhase::Complete
    );

    // 5. Subsequent deploy now succeeds cleanly
    let r3 = match engine.execute(&deploy_opts).unwrap() {
        ReleaseOutcome::Deploy(r) => r,
        _ => panic!("expected deploy after rollback"),
    };
    assert_eq!(
        canonicalize_preserve_normal(&r3.previous_release.unwrap()),
        canonicalize_preserve_normal(&r1.release_dir)
    );
}

#[test]
fn test_regression_snapshot_and_recovery_permissions_and_cleanup_state() {
    let sb = TempSandbox::new("perms-and-state");
    let cfg = ReleaseConfig::for_root(sb.path());
    let live_db = cfg.host_data_dir.join(&cfg.sqlite_db);
    seed_valid_sqlite_db(&live_db, "secret-data");

    // Legacy .env migration in Stage 0
    fs::create_dir_all(cfg.legacy_opt_root.join("backend")).unwrap();
    fs::write(
        cfg.legacy_opt_root.join("backend/.env"),
        "JWT_SECRET=topsecret\n",
    )
    .unwrap();

    let provider = MockArtifactProvider {
        resolved_tag: Ok("v4.0.0".to_string()),
        archive_source: PathBuf::new(),
        manifest_content: String::new(),
    };
    let engine = ReleaseEngine::new(
        cfg.clone(),
        provider,
        MockLifecycle::default(),
        MockHealthProber::new(vec![]),
    );

    let resolved = engine.ensure_fhs_layout(&cfg, false).unwrap();
    let release_dir = cfg.releases_dir.join("1700000002");
    create_new_dir_exclusive(&release_dir, 0o755, 0o755).unwrap();
    let snap = create_state_snapshot(&cfg, &resolved, &release_dir, false).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let data_dir_mode = fs::symlink_metadata(&cfg.data_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(data_dir_mode, 0o700, "data_dir must be 0700");

        let env_mode = fs::symlink_metadata(&cfg.host_env_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(env_mode, 0o600, "migrated .env must be 0600");

        let snap_dir = release_dir.join("data-snapshot");
        let snap_dir_mode = fs::symlink_metadata(&snap_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(snap_dir_mode, 0o700, "data-snapshot dir must be 0700");

        let bak_mode = fs::symlink_metadata(snap.backup_path.as_ref().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(bak_mode, 0o600, "snapshot .bak must be 0600");

        let manifest_mode = fs::symlink_metadata(snap.manifest_path.as_ref().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(manifest_mode, 0o600, "MANIFEST.sha256 must be 0600");
    }
    let _ = snap;

    // Verify `cleanup` and `migrate-systemd` persist started/completed recovery state
    let cleanup_opts = ReleaseOptions {
        command: ReleaseCommand::Cleanup,
        ..ReleaseOptions::default()
    };
    engine.execute(&cleanup_opts).unwrap();
    let rec_cleanup = RecoveryState::load(&cfg.releases_dir).unwrap().unwrap();
    assert_eq!(rec_cleanup.command, ReleaseCommand::Cleanup);
    assert_eq!(rec_cleanup.phase, ReleasePhase::Complete);

    let migrate_opts = ReleaseOptions {
        command: ReleaseCommand::MigrateSystemd,
        dry_run: true,
        ..ReleaseOptions::default()
    };
    engine.execute(&migrate_opts).unwrap();
    let rec_mig = RecoveryState::load(&cfg.with_dry_run(true).releases_dir)
        .unwrap()
        .unwrap();
    assert_eq!(rec_mig.command, ReleaseCommand::MigrateSystemd);
    assert_eq!(rec_mig.phase, ReleasePhase::Complete);
}
#[cfg(unix)]
#[test]
fn test_rollback_probe_failure_marks_recovery_failed() {
    let sandbox = TempSandbox::new("rollback-probe-fail");
    let mut cfg = ReleaseConfig::for_root(sandbox.path());
    cfg.health_retries = 1;
    cfg.health_interval = Duration::ZERO;
    seed_valid_sqlite_db(&cfg.data_dir.join("aetherflow.sqlite"), "rollback-probe");

    let previous = cfg.releases_dir.join("1111111111");
    let broken = cfg.releases_dir.join("2222222222");
    fs::create_dir_all(&previous).unwrap();
    fs::create_dir_all(&broken).unwrap();
    fs::write(previous.join("aetherflow-api"), b"old").unwrap();
    fs::write(previous.join(".version"), b"v4.0.0-old\n").unwrap();
    fs::write(broken.join("aetherflow-api"), b"broken").unwrap();
    std::os::unix::fs::symlink(&broken, &cfg.current_link).unwrap();
    write_previous_release(&cfg.releases_dir, &previous).unwrap();

    let tar_path = sandbox.path().join("unused.tar.gz");
    let (_, manifest) = build_synthetic_release_tarball(
        &tar_path,
        &cfg.artifact_name,
        &[("aetherflow-api", b"unused", EntryType::Regular)],
    );
    let provider = MockArtifactProvider {
        resolved_tag: Ok("v4.0.0".to_string()),
        archive_source: tar_path,
        manifest_content: manifest,
    };
    let lifecycle = MockLifecycle::default();
    let failing_rollback_prober = MockHealthProber::new(vec![Ok(HealthCheckAttempt {
        http_status: 500,
        body: r#"{"status":"degraded"}"#.to_string(),
    })]);

    let engine = ReleaseEngine::new(cfg.clone(), provider, lifecycle, failing_rollback_prober);
    let err = engine
        .execute(&ReleaseOptions {
            command: ReleaseCommand::Rollback,
            ..ReleaseOptions::default()
        })
        .unwrap_err();
    assert!(err.to_string().contains("failed"));
    let recovery = RecoveryState::load(&cfg.releases_dir).unwrap().unwrap();
    assert_eq!(recovery.phase, ReleasePhase::Failed);
}

#[cfg(unix)]
#[test]
fn test_round8_standalone_rollback_restores_current_release_data_snapshot() {
    let sandbox = TempSandbox::new("standalone-rollback-snap");
    let mut cfg = ReleaseConfig::for_root(sandbox.path());
    cfg.health_retries = 1;
    cfg.health_interval = Duration::ZERO;
    let live_db = cfg.host_data_dir.join(&cfg.sqlite_db);

    let previous = cfg.releases_dir.join("1111111111");
    let broken = cfg.releases_dir.join("2222222222");
    fs::create_dir_all(&previous).unwrap();
    fs::create_dir_all(&broken).unwrap();
    fs::write(previous.join("aetherflow-api"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(previous.join(".version"), b"v4.0.0-prev\n").unwrap();
    fs::write(broken.join("aetherflow-api"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(broken.join(".version"), b"v4.0.0-broken\n").unwrap();

    // Snapshot pre-deploy good DB under `broken/data-snapshot/` (just like Stage 1 of `broken`'s deploy).
    seed_valid_sqlite_db(&live_db, "pre-deploy-good-state");
    let resolved = ResolvedDbPath {
        path: live_db.clone(),
        source: DbPathSource::DataDirDefault,
    };
    create_state_snapshot(&cfg, &resolved, &broken, false).unwrap();

    // Corrupt live DB to simulate post-deploy corruption before operator runs standalone `Rollback`.
    fs::write(&live_db, b"CORRUPT_POST_DEPLOY_DB").unwrap();
    std::os::unix::fs::symlink(&broken, &cfg.current_link).unwrap();
    write_previous_release(&cfg.releases_dir, &previous).unwrap();

    let tar_path = sandbox.path().join("unused.tar.gz");
    let (_, manifest) = build_synthetic_release_tarball(
        &tar_path,
        &cfg.artifact_name,
        &[("aetherflow-api", b"unused", EntryType::Regular)],
    );
    let provider = MockArtifactProvider {
        resolved_tag: Ok("v4.0.0".to_string()),
        archive_source: tar_path,
        manifest_content: manifest,
    };
    let prober = MockHealthProber::new(vec![Ok(HealthCheckAttempt {
        http_status: 200,
        body: r#"{"status":"ok"}"#.to_string(),
    })]);
    let engine = ReleaseEngine::new(cfg.clone(), provider, MockLifecycle::default(), prober);
    let outcome = engine
        .execute(&ReleaseOptions {
            command: ReleaseCommand::Rollback,
            ..ReleaseOptions::default()
        })
        .expect("standalone rollback must succeed");
    let ReleaseOutcome::Rollback(report) = outcome else {
        panic!("expected Rollback outcome");
    };
    assert_eq!(report.snapshot_release, broken);
    assert!(report.restore_error.is_none());

    let conn = Connection::open(&live_db).unwrap();
    let restored_marker: String = conn
        .query_row("SELECT marker FROM test_state LIMIT 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        restored_marker, "pre-deploy-good-state",
        "standalone rollback must restore snapshot from outgoing current release (`broken/data-snapshot`)"
    );
}
