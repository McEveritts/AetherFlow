use super::{
    build_synthetic_release_tarball, legacy_completed_manifest, seed_valid_sqlite_db,
    MockArtifactProvider, MockHealthProber, MockLifecycle, TempSandbox,
};
use crate::*;
use af_models::SelfUpdateRequest;
use rusqlite::Connection;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tar::EntryType;

#[cfg(unix)]
#[test]
fn missing_frontend_assets_stop_deploy_before_cutover() {
    let sb = TempSandbox::new("frontend-no-cutover");
    let cfg = ReleaseConfig::for_root(sb.path());
    seed_valid_sqlite_db(&cfg.host_data_dir.join(&cfg.sqlite_db), "synthetic state");
    let previous = cfg.releases_dir.join("previous");
    fs::create_dir_all(&previous).unwrap();
    std::os::unix::fs::symlink(&previous, &cfg.current_link).unwrap();

    let archive = sb.path().join("missing-frontend.tar.gz");
    let (_, manifest) = build_synthetic_release_tarball(
        &archive,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"synthetic api", EntryType::Regular),
            (".version", b"v4.0.0\n", EntryType::Regular),
        ],
    );
    let provider = MockArtifactProvider {
        resolved_tag: Ok("v4.0.0".to_string()),
        archive_source: archive,
        manifest_content: manifest,
    };
    let lifecycle = MockLifecycle::default();
    let engine = ReleaseEngine::new(
        cfg.clone(),
        provider,
        lifecycle.clone(),
        MockHealthProber::new(vec![]),
    );
    let err = engine.execute(&ReleaseOptions::default()).unwrap_err();
    assert!(matches!(err, ReleaseError::ArtifactVerification(_)));
    assert_eq!(fs::read_link(&cfg.current_link).unwrap(), previous);
    assert!(!lifecycle
        .recorded_calls()
        .iter()
        .any(|call| call == "restart_units"));
    let recovery = RecoveryState::load(&cfg.releases_dir).unwrap().unwrap();
    assert_eq!(recovery.phase, ReleasePhase::Failed);
    assert!(!recovery.candidate_release.unwrap().exists());
}

#[cfg(unix)]
#[test]
fn healthy_old_runtime_triggers_rollback_instead_of_completion() {
    let sandbox = TempSandbox::new("stale-runtime");
    let mut config = ReleaseConfig::for_root(sandbox.path());
    config.health_interval = Duration::ZERO;
    seed_valid_sqlite_db(
        &config.data_dir.join("aetherflow.sqlite"),
        "preserve-live-data",
    );
    let previous = config.releases_dir.join("previous");
    fs::create_dir_all(&previous).unwrap();
    fs::write(previous.join("aetherflow-api"), b"old").unwrap();
    fs::write(previous.join(".version"), "v4.0.0-old").unwrap();
    std::os::unix::fs::symlink(&previous, &config.current_link).unwrap();
    let archive = sandbox.path().join("release.tar.gz");
    let (_, manifest) = build_synthetic_release_tarball(
        &archive,
        &config.artifact_name,
        &[
            ("aetherflow-api", b"new", EntryType::Regular),
            (".version", b"v4.0.0-new", EntryType::Regular),
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
        resolved_tag: Ok("v4.0.0-new".to_string()),
        archive_source: archive,
        manifest_content: manifest,
    };
    let lifecycle = MockLifecycle {
        stale_identity: true,
        ..Default::default()
    };
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
    let engine = ReleaseEngine::new(config.clone(), provider, lifecycle, prober);
    let result = engine.execute(&ReleaseOptions {
        command: ReleaseCommand::Deploy,
        channel: ReleaseChannel::Nightly,
        dry_run: false,
        offline: false,
        from_source: false,
    });
    assert!(matches!(
        result,
        Err(ReleaseError::RolledBackAfterProbeFailure { .. })
    ));
    assert_eq!(fs::read_link(&config.current_link).unwrap(), previous);
    let recovery = RecoveryState::load(&config.releases_dir).unwrap().unwrap();
    assert_eq!(recovery.phase, ReleasePhase::Complete);
    assert!(recovery.last_error.unwrap().contains("old executable"));
}

#[test]
fn test_full_deploy_lifecycle_and_housekeeping_pruning() {
    let sb = TempSandbox::new("full-deploy");
    let mut cfg = ReleaseConfig::for_root(sb.path());
    cfg.max_releases = 2;
    cfg.health_interval = Duration::from_millis(1);

    // Seed live database at a non-FHS legacy path referenced via ENV_FILE
    let custom_db = sb
        .path()
        .join("opt/AetherFlow/backend/data/aetherflow.sqlite");
    seed_valid_sqlite_db(&custom_db, "live-v3-data");
    fs::create_dir_all(&cfg.env_dir).unwrap();
    fs::write(
        &cfg.host_env_file,
        format!("DB_PATH={}\n", custom_db.display()),
    )
    .unwrap();

    // Pre-install a custom aetherflow-api.service unit to verify Stage 3 does NOT overwrite it
    fs::create_dir_all(&cfg.systemd_units_dst).unwrap();
    let existing_api_unit = cfg.systemd_units_dst.join("aetherflow-api.service");
    fs::write(&existing_api_unit, "# Custom ReadWritePaths preserved\n").unwrap();

    let tar_path = sb.path().join("release.tar.gz");
    let (_, manifest) = build_synthetic_release_tarball(
        &tar_path,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"rust-v4-binary", EntryType::Regular),
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
            (
                "deploy/systemd/aetherflow-api.service",
                b"# Packaged API unit\n",
                EntryType::Regular,
            ),
            (
                "deploy/systemd/aetherflow-runner.service",
                b"# Packaged Runner unit\n",
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
            http_status: 503,
            body: r#"{"status":"starting"}"#.to_string(),
        }),
        Ok(HealthCheckAttempt {
            http_status: 200,
            body: r#"{"database":"ok","redis":"disabled","status":"ready","uptime":"0.1s"}"#
                .to_string(),
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

    let engine = ReleaseEngine::new(cfg.clone(), provider, lifecycle.clone(), prober);
    let opts = ReleaseOptions {
        command: ReleaseCommand::Deploy,
        channel: ReleaseChannel::Stable,
        dry_run: false,
        offline: false,
        from_source: false,
    };

    // Deploy 1
    let out1 = match engine.execute(&opts).unwrap() {
        ReleaseOutcome::Deploy(r) => r,
        _ => panic!("expected deploy outcome"),
    };
    assert_eq!(out1.release_tag, "v4.0.0");
    assert!(out1.snapshot.created);
    assert_eq!(out1.health_status.as_deref(), Some("ready"));
    // Verify Stage 0 did NOT copy custom_db into FHS data_dir since resolved DB was elsewhere
    assert!(!cfg.host_data_dir.join(&cfg.sqlite_db).exists());
    // Verify existing systemd unit was preserved while missing runner unit was installed
    assert_eq!(
        fs::read_to_string(&existing_api_unit).unwrap(),
        "# Custom ReadWritePaths preserved\n"
    );
    assert!(cfg
        .systemd_units_dst
        .join("aetherflow-runner.service")
        .is_file());

    let completed_state = RecoveryState::load(&cfg.releases_dir).unwrap().unwrap();
    let legacy_state = legacy_completed_manifest(&completed_state);
    let legacy_bytes = serde_json::to_vec_pretty(&legacy_state).unwrap();
    let state_path = RecoveryState::state_file_path(&cfg.releases_dir);
    fs::write(&state_path, &legacy_bytes).unwrap();
    let legacy_status = engine.inspect_status().unwrap();
    let loaded_state = legacy_status.recovery_state.unwrap();
    assert_eq!(loaded_state.phase, ReleasePhase::Complete);
    assert_eq!(loaded_state.started_at, completed_state.updated_at);
    assert_eq!(
        loaded_state.candidate_release,
        completed_state.candidate_release
    );
    assert_eq!(loaded_state.snapshot_path, completed_state.snapshot_path);
    assert!(!loaded_state.is_unfinished());
    assert_eq!(fs::read(&state_path).unwrap(), legacy_bytes);

    // Deploy 2 & Deploy 3 to trigger Stage 5 pruning (max_releases = 2)
    let out2 = match engine.execute(&opts).unwrap() {
        ReleaseOutcome::Deploy(r) => r,
        _ => panic!("expected deploy outcome"),
    };
    let out3 = match engine.execute(&opts).unwrap() {
        ReleaseOutcome::Deploy(r) => r,
        _ => panic!("expected deploy outcome"),
    };

    assert_eq!(out3.pruned_releases.len(), 1);
    assert!(
        !out1.release_dir.exists(),
        "oldest release should be pruned"
    );
    assert!(
        out2.release_dir.exists(),
        "previous release must be protected from pruning"
    );
    assert!(
        out3.release_dir.exists(),
        "current release must be protected from pruning"
    );

    let status = engine.inspect_status().unwrap();
    assert_eq!(status.current_version.as_deref(), Some("v4.0.0"));
    assert_eq!(status.recovery_state.unwrap().phase, ReleasePhase::Complete);
    let canonical_state: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(canonical_state["phase"], "complete");
    assert!(canonical_state["started_at"].as_str().is_some());
    assert!(canonical_state.get("source").is_none());
}
#[test]
fn deployment_remains_complete_when_pruning_an_old_release_fails() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let sandbox = TempSandbox::new("deploy-prune-failure");
    let mut config = ReleaseConfig::for_root(sandbox.path());
    config.max_releases = 1;
    let dry_run_config = config.with_dry_run(true);
    let removable = dry_run_config.releases_dir.join("1");
    let blocked = dry_run_config.releases_dir.join("2");
    fs::create_dir_all(&removable).unwrap();
    fs::create_dir_all(&blocked).unwrap();
    fs::write(blocked.join("old-binary"), b"old release").unwrap();
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o500)).unwrap();

    let engine = ReleaseEngine::new(
        config,
        MockArtifactProvider {
            resolved_tag: Err("offline fixture must not resolve a release".into()),
            archive_source: sandbox.path().join("unused.tar.gz"),
            manifest_content: String::new(),
        },
        MockLifecycle::default(),
        MockHealthProber::new(vec![]),
    );
    let deployment = engine.execute(&ReleaseOptions {
        command: ReleaseCommand::Deploy,
        channel: ReleaseChannel::Stable,
        dry_run: true,
        offline: true,
        from_source: false,
    });
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();

    let ReleaseOutcome::Deploy(report) = deployment.unwrap() else {
        panic!("expected deploy outcome");
    };
    assert_eq!(report.pruned_releases, vec![removable]);
    assert!(blocked.join("old-binary").is_file());
    assert_eq!(
        read_current_link_target(&dry_run_config.current_link),
        Some(report.release_dir)
    );
    let recovery = RecoveryState::load(&dry_run_config.releases_dir)
        .unwrap()
        .unwrap();
    assert_eq!(recovery.phase, ReleasePhase::Complete);
    assert!(!recovery.is_unfinished());
    let log = fs::read_to_string(dry_run_config.log_file).unwrap();
    assert!(log.contains("Release retention cleanup can be retried"));
}

#[test]
fn test_regression_completed_phase_alias_serializes_canonically() {
    let phase: ReleasePhase = serde_json::from_str(r#""completed""#).unwrap();
    assert_eq!(phase, ReleasePhase::Complete);
    assert_eq!(serde_json::to_string(&phase).unwrap(), r#""complete""#);
}

#[test]
fn test_regression_native_recovery_still_requires_started_at() {
    let sandbox = TempSandbox::new("missing-recovery-start");
    for phase in [
        "stage0_fhs_layout",
        "stage1_scaffold",
        "stage1_5_snapshot",
        "stage2_symlink_swap",
        "stage3_health_probe",
        "stage4_rollback",
        "stage5_cleanup",
        "stage6_migrate_systemd",
        "complete",
        "failed",
        "unknown",
    ] {
        let state = RecoveryState::new(ReleaseCommand::Deploy, ReleaseChannel::Nightly, false);
        let mut payload = serde_json::to_value(state).unwrap();
        payload["phase"] = serde_json::json!(phase);
        payload.as_object_mut().unwrap().remove("started_at");
        fs::write(
            RecoveryState::state_file_path(sandbox.path()),
            serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
        assert!(
            RecoveryState::load(sandbox.path()).is_err(),
            "phase={phase}"
        );
    }
}

#[test]
fn test_regression_legacy_completed_manifest_requires_valid_completion_time() {
    let sandbox = TempSandbox::new("invalid-legacy-completion");
    let state = RecoveryState::new(ReleaseCommand::Deploy, ReleaseChannel::Nightly, false);
    for timestamp in [
        None,
        Some(serde_json::json!(null)),
        Some(serde_json::json!(42)),
        Some(serde_json::json!("not-a-timestamp")),
    ] {
        let mut payload = legacy_completed_manifest(&state);
        if let Some(timestamp) = timestamp {
            payload["updated_at"] = timestamp;
        } else {
            payload.as_object_mut().unwrap().remove("updated_at");
        }
        fs::write(
            RecoveryState::state_file_path(sandbox.path()),
            serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
        assert!(RecoveryState::load(sandbox.path()).is_err());
    }
    for (field, value) in [
        ("command", serde_json::json!("rollback")),
        ("dry_run", serde_json::json!(true)),
        ("started_at", serde_json::json!(null)),
    ] {
        let mut payload = legacy_completed_manifest(&state);
        payload[field] = value;
        fs::write(
            RecoveryState::state_file_path(sandbox.path()),
            serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
        assert!(
            RecoveryState::load(sandbox.path()).is_err(),
            "field={field}"
        );
    }
}
#[test]
fn test_dry_run_offline_never_touches_host_or_restarts_systemd() {
    let sb = TempSandbox::new("dry-run-offline");
    let cfg = ReleaseConfig::for_root(sb.path());
    let host_db = cfg.host_data_dir.join(&cfg.sqlite_db);
    seed_valid_sqlite_db(&host_db, "production-data");

    let provider = MockArtifactProvider {
        resolved_tag: Err("network should not be called in offline dry-run".to_string()),
        archive_source: PathBuf::new(),
        manifest_content: String::new(),
    };
    let lifecycle = MockLifecycle::default();
    let prober = MockHealthProber::new(vec![]);

    let engine = ReleaseEngine::new(cfg.clone(), provider, lifecycle.clone(), prober);
    let opts = ReleaseOptions::parse_args(
        [
            "deploy",
            "--dry-run",
            "--offline",
            "--channel",
            "experimental",
        ],
        ReleaseChannel::Stable,
    )
    .unwrap();

    let report = match engine.execute(&opts).unwrap() {
        ReleaseOutcome::Deploy(r) => r,
        _ => panic!("expected deploy report"),
    };

    assert!(report.dry_run);
    assert!(report.offline);
    assert_eq!(report.release_tag, "v4.0.0-dryrun");
    assert_eq!(report.channel, ReleaseChannel::Nightly);
    assert!(report.release_dir.starts_with(&cfg.dry_run_root));
    assert!(report.current_link.starts_with(&cfg.dry_run_root));
    for path in [
        "aetherflow-api",
        "bin/af",
        "bin/speedtest-backend",
        "plugins/telemetry-inspector/backend/hooks/start.sh",
    ] {
        let contents = fs::read_to_string(report.release_dir.join(path)).unwrap();
        assert!(contents.contains("Offline dry-run placeholder"), "{path}");
    }
    assert!(
        !report.release_dir.join("af").exists(),
        "offline dry-run should not duplicate root af"
    );
    assert!(
        !report.release_dir.join("speedtest-backend").exists(),
        "offline dry-run should not duplicate root speedtest-backend"
    );
    assert!(report
        .release_dir
        .join("plugins/telemetry-inspector/plugin.manifest.json")
        .is_file());
    let index = fs::read_to_string(report.release_dir.join("web/dist/index.html")).unwrap();
    assert!(index.contains("Offline dry-run placeholder"));
    let wasm =
        fs::symlink_metadata(report.release_dir.join("web/dist/dry-run-placeholder.wasm")).unwrap();
    assert!(wasm.is_file());
    assert_eq!(
        wasm.len(),
        0,
        "dry-run WASM must not pass release validation"
    );
    assert!(
        !cfg.current_link.exists(),
        "production current_link must remain untouched"
    );
    assert!(
        !lifecycle
            .recorded_calls()
            .iter()
            .any(|c| c == "restart_units"),
        "dry-run must never restart systemd units"
    );
}

#[test]
fn test_unsupported_from_source_and_offline_validation() {
    let err_offline =
        ReleaseOptions::parse_args(["deploy", "--offline"], ReleaseChannel::Stable).unwrap_err();
    assert_eq!(err_offline.exit_code(), ExitCode::ConfigurationOrUsageError);

    let err_source =
        ReleaseOptions::parse_args(["deploy", "--from-source"], ReleaseChannel::Stable)
            .unwrap_err();
    assert!(is_unsupported_error(&err_source));
    assert_eq!(err_source.exit_code(), ExitCode::ConfigurationOrUsageError);
}

#[test]
fn test_runner_self_update_contract_validation() {
    // Empty defaults -> deploy + stable
    let req_default = SelfUpdateRequest {
        command: String::new(),
        channel: String::new(),
    };
    let v_default = validate_self_update_request(&req_default).unwrap();
    assert_eq!(v_default.command, ReleaseCommand::Deploy);
    assert_eq!(v_default.channel, ReleaseChannel::Stable);

    // Experimental channel is accepted
    let req_exp = SelfUpdateRequest {
        command: "deploy".to_string(),
        channel: "experimental".to_string(),
    };
    let v_exp = validate_self_update_request(&req_exp).unwrap();
    assert_eq!(v_exp.channel, ReleaseChannel::Nightly);

    // Invalid command / channel preserve exact runner error strings
    let bad_cmd = SelfUpdateRequest {
        command: "destroy".to_string(),
        channel: "stable".to_string(),
    };
    assert_eq!(
        validate_self_update_request(&bad_cmd).unwrap_err().error,
        "invalid self-update command"
    );

    let bad_ch = SelfUpdateRequest {
        command: "deploy".to_string(),
        channel: "beta".to_string(),
    };
    assert_eq!(
        validate_self_update_request(&bad_ch).unwrap_err().error,
        "invalid update channel"
    );
}

#[test]
fn test_lock_contention_returns_lock_busy() {
    let sb = TempSandbox::new("lock-busy");
    let lock_path = sb.path().join(".release.lock");
    let _guard1 = ReleaseLockGuard::acquire(&lock_path, Duration::from_millis(100)).unwrap();

    let err = ReleaseLockGuard::acquire(&lock_path, Duration::from_millis(60)).unwrap_err();
    assert_eq!(err.exit_code(), ExitCode::LockContention);
}

// ── Safety Review Regression Tests ──────────────────────────────────────
#[test]
fn stage0_migrates_legacy_v3_slot_current_backend_db_and_env() {
    let sb = TempSandbox::new("v3-slot-migration");
    let cfg = ReleaseConfig::for_root(sb.path());
    fs::create_dir_all(&cfg.releases_dir).unwrap();

    let v3_slot = cfg.releases_dir.join("v3.2.0");
    fs::create_dir_all(v3_slot.join("backend/data")).unwrap();
    seed_valid_sqlite_db(
        &v3_slot.join("backend/data").join(&cfg.sqlite_db),
        "v3-slot-marker",
    );
    fs::write(
        v3_slot.join("backend/.env"),
        "JWT_SECRET=from-v3-slot-secret\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&v3_slot, &cfg.current_link).unwrap();

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
    let fhs_db = cfg.host_data_dir.join(&cfg.sqlite_db);
    assert_eq!(resolved.path, fhs_db);
    assert!(fhs_db.is_file(), "v3 slot SQLite DB must migrate to FHS");

    let conn = Connection::open(&fhs_db).unwrap();
    let marker: String = conn
        .query_row("SELECT marker FROM test_state LIMIT 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(marker, "v3-slot-marker");

    let env_contents = fs::read_to_string(&cfg.host_env_file).unwrap();
    assert_eq!(env_contents, "JWT_SECRET=from-v3-slot-secret\n");
}
#[test]
fn cli_preflight_blocks_swap_and_post_swap_cli_failure_triggers_unified_rollback() {
    let sb = TempSandbox::new("post-swap-cli-rollback");
    let mut cfg = ReleaseConfig::for_root(sb.path());
    cfg.health_retries = 2;
    cfg.health_interval = Duration::from_millis(1);

    let tar_v1 = sb.path().join("release-v1.tar.gz");
    let (_, manifest_v1) = build_synthetic_release_tarball(
        &tar_v1,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"api-v1", EntryType::Regular),
            ("af", b"cli-v1", EntryType::Regular),
            (".version", b"v4.0.0\n", EntryType::Regular),
            ("web/dist/index.html", b"index-v1", EntryType::Regular),
            ("web/dist/app.wasm", b"wasm-v1", EntryType::Regular),
        ],
    );
    let provider_v1 = MockArtifactProvider {
        resolved_tag: Ok("v4.0.0".to_string()),
        archive_source: tar_v1,
        manifest_content: manifest_v1,
    };
    let prober_v1 = MockHealthProber::new(vec![Ok(HealthCheckAttempt {
        http_status: 200,
        body: r#"{"status":"ready"}"#.to_string(),
    })]);
    let engine_v1 = ReleaseEngine::new(
        cfg.clone(),
        provider_v1,
        MockLifecycle::default(),
        prober_v1,
    );
    let opts = ReleaseOptions::default();
    let deploy_v1 = match engine_v1.execute(&opts).unwrap() {
        ReleaseOutcome::Deploy(r) => r,
        _ => panic!("expected deploy v1"),
    };
    let af_link = cfg.cli_bin_dir.join("af");
    assert!(
        fs::symlink_metadata(&af_link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "deploy v1 must create CLI symlink"
    );
    assert_eq!(
        fs::read(&af_link).unwrap(),
        b"cli-v1",
        "CLI symlink must resolve to v1 binary"
    );

    // 1. Pre-swap CLI preflight failure when cli_bin_dir is obstructed leaves `current` on v1
    let tar_v2 = sb.path().join("release-v2.tar.gz");
    let (_, manifest_v2) = build_synthetic_release_tarball(
        &tar_v2,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"api-v2", EntryType::Regular),
            ("af", b"cli-v2", EntryType::Regular),
            (".version", b"v4.0.1\n", EntryType::Regular),
            ("web/dist/index.html", b"index-v2", EntryType::Regular),
            ("web/dist/app.wasm", b"wasm-v2", EntryType::Regular),
        ],
    );
    let provider_v2 = MockArtifactProvider {
        resolved_tag: Ok("v4.0.1".to_string()),
        archive_source: tar_v2,
        manifest_content: manifest_v2,
    };

    let mut preflight_cfg = cfg.clone();
    let blocked_bin = sb.path().join("blocked-cli-bin");
    fs::write(&blocked_bin, b"not-a-directory").unwrap();
    preflight_cfg.cli_bin_dir = blocked_bin;
    let preflight_engine = ReleaseEngine::new(
        preflight_cfg,
        provider_v2.clone(),
        MockLifecycle::default(),
        MockHealthProber::new(vec![]),
    );
    let preflight_err = preflight_engine.execute(&opts).unwrap_err();
    assert_eq!(
        read_current_link_target(&cfg.current_link).unwrap(),
        canonicalize_preserve_normal(&deploy_v1.release_dir),
        "CLI preflight failure must abort BEFORE swapping current symlink: {preflight_err}"
    );

    // 2. Post-swap CLI sync failure routes through unified rollback, reverting current and CLI link
    let rollback_prober = MockHealthProber::new(vec![Ok(HealthCheckAttempt {
        http_status: 200,
        body: r#"{"status":"ready"}"#.to_string(),
    })]);
    let rollback_lifecycle = MockLifecycle::default();
    let engine_v2 = ReleaseEngine::new(
        cfg.clone(),
        provider_v2,
        rollback_lifecycle.clone(),
        rollback_prober,
    );
    engine_v2.arm_next_post_swap_cli_sync_failure();
    let err = engine_v2.execute(&opts).unwrap_err();
    match err {
        ReleaseError::RolledBackAfterProbeFailure {
            probe_error,
            reverted_to,
            ..
        } => {
            assert!(probe_error.contains("injected post-swap CLI sync failure"));
            assert_eq!(
                canonicalize_preserve_normal(&reverted_to),
                canonicalize_preserve_normal(&deploy_v1.release_dir)
            );
        }
        other => panic!("expected RolledBackAfterProbeFailure, got {other:?}"),
    }
    assert_eq!(
        read_current_link_target(&cfg.current_link).unwrap(),
        canonicalize_preserve_normal(&deploy_v1.release_dir)
    );
    assert_eq!(fs::read(&af_link).unwrap(), b"cli-v1");
    let recovery = RecoveryState::load(&cfg.releases_dir).unwrap().unwrap();
    assert_eq!(recovery.phase, ReleasePhase::Complete);
    assert!(recovery
        .last_error
        .unwrap()
        .contains("injected post-swap CLI sync failure"));
    assert!(rollback_lifecycle
        .recorded_calls()
        .iter()
        .any(|c| c == "restart_units"));
}

#[test]
fn canonical_bin_and_managed_plugin_archive_deploys_alongside_legacy_root_archive() {
    use std::os::unix::fs::PermissionsExt;

    let sb = TempSandbox::new("canonical-and-legacy-archives");
    let mut cfg = ReleaseConfig::for_root(sb.path());
    cfg.health_retries = 2;
    cfg.health_interval = Duration::from_millis(1);

    // 1. Canonical archive: bin/af, bin/speedtest-backend, and plugins/telemetry-inspector only (no root duplicates).
    let canonical_tar = sb.path().join("canonical-v4.0.0.tar.gz");
    let (_, canonical_manifest) = build_synthetic_release_tarball(
        &canonical_tar,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"api-canonical", EntryType::Regular),
            ("bin/af", b"cli-canonical", EntryType::Regular),
            (
                "bin/speedtest-backend",
                b"speedtest-canonical",
                EntryType::Regular,
            ),
            (".version", b"v4.0.0\n", EntryType::Regular),
            (
                "web/dist/index.html",
                b"<html>canonical</html>",
                EntryType::Regular,
            ),
            ("web/dist/app.wasm", b"\0asm\x01\0\0\0", EntryType::Regular),
            (
                "plugins/telemetry-inspector/plugin.manifest.json",
                b"{\"id\":\"telemetry-inspector\"}\n",
                EntryType::Regular,
            ),
            (
                "plugins/telemetry-inspector/backend/hooks/start.sh",
                b"#!/usr/bin/env bash\nexit 0\n",
                EntryType::Regular,
            ),
            (
                "plugins/telemetry-inspector/backend/runtime.py",
                b"print('ok')\n",
                EntryType::Regular,
            ),
            (
                "plugins/telemetry-inspector/frontend/dist/index.html",
                b"<!doctype html>\n",
                EntryType::Regular,
            ),
        ],
    );

    let engine_canonical = ReleaseEngine::new(
        cfg.clone(),
        MockArtifactProvider {
            resolved_tag: Ok("v4.0.0".to_string()),
            archive_source: canonical_tar,
            manifest_content: canonical_manifest,
        },
        MockLifecycle::default(),
        MockHealthProber::new(vec![Ok(HealthCheckAttempt {
            http_status: 200,
            body: r#"{"status":"ready"}"#.to_string(),
        })]),
    );

    let deploy_canonical = match engine_canonical
        .execute(&ReleaseOptions::default())
        .unwrap()
    {
        ReleaseOutcome::Deploy(r) => r,
        _ => panic!("expected deploy outcome"),
    };

    assert!(!deploy_canonical.release_dir.join("af").exists());
    assert!(!deploy_canonical
        .release_dir
        .join("speedtest-backend")
        .exists());
    for exec_rel in [
        "aetherflow-api",
        "bin/af",
        "bin/speedtest-backend",
        "plugins/telemetry-inspector/backend/hooks/start.sh",
    ] {
        assert_eq!(
            fs::symlink_metadata(deploy_canonical.release_dir.join(exec_rel))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "expected 0755 on {exec_rel}"
        );
    }
    assert_eq!(
        fs::read_link(cfg.cli_bin_dir.join("af")).unwrap(),
        cfg.current_link.join("bin/af")
    );
    assert_eq!(
        fs::read(cfg.cli_bin_dir.join("af")).unwrap(),
        b"cli-canonical"
    );

    // 2. Legacy root-only archive (no bin/, no plugins/) still deploys cleanly.
    let legacy_tar = sb.path().join("legacy-v4.0.1.tar.gz");
    let (_, legacy_manifest) = build_synthetic_release_tarball(
        &legacy_tar,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"api-legacy", EntryType::Regular),
            ("af", b"cli-legacy", EntryType::Regular),
            ("speedtest-backend", b"speedtest-legacy", EntryType::Regular),
            (".version", b"v4.0.1\n", EntryType::Regular),
            (
                "web/dist/index.html",
                b"<html>legacy</html>",
                EntryType::Regular,
            ),
            ("web/dist/app.wasm", b"\0asm\x01\0\0\0", EntryType::Regular),
        ],
    );

    let engine_legacy = ReleaseEngine::new(
        cfg.clone(),
        MockArtifactProvider {
            resolved_tag: Ok("v4.0.1".to_string()),
            archive_source: legacy_tar,
            manifest_content: legacy_manifest,
        },
        MockLifecycle::default(),
        MockHealthProber::new(vec![Ok(HealthCheckAttempt {
            http_status: 200,
            body: r#"{"status":"ready"}"#.to_string(),
        })]),
    );

    let deploy_legacy = match engine_legacy.execute(&ReleaseOptions::default()).unwrap() {
        ReleaseOutcome::Deploy(r) => r,
        _ => panic!("expected legacy deploy outcome"),
    };

    assert_eq!(
        fs::read_link(cfg.cli_bin_dir.join("af")).unwrap(),
        cfg.current_link.join("af")
    );
    assert_eq!(fs::read(cfg.cli_bin_dir.join("af")).unwrap(), b"cli-legacy");
    assert!(deploy_legacy
        .release_dir
        .join("speedtest-backend")
        .is_file());
}
