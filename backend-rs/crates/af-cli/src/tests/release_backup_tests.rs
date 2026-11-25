use super::{create_sample_sqlite_db, MockRunnerTransport, TempTestDir};
use crate::*;
use af_models::SelfUpdateJobStatus;
use af_release::ReleaseChannel;
use rusqlite::Connection;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn release_status_and_local_dry_run_integrate_with_af_release() {
    let tmp = TempTestDir::new("release-engine");
    let root_str = tmp.path().to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    // Create minimal release directories matching `ReleaseConfig::for_root` (`opt/AetherFlow/releases`)
    let rel_v1 = tmp.path().join("opt/AetherFlow/releases/v4.0.0");
    fs::create_dir_all(&rel_v1).unwrap();
    let etc_dir = tmp.path().join("etc/aetherflow");
    fs::create_dir_all(&etc_dir).unwrap();

    let status_inv = parse_cli_args(["--json", "--root", &root_str, "release", "status"]).unwrap();
    let status_env = execute_invocation(&status_inv, &transport);
    assert_eq!(
        status_env.status, "ok",
        "release status failed: {}",
        status_env.message
    );
    let data = status_env.data.unwrap();
    assert_eq!(data["configured_channel"], "stable");
    let avail = data["available_releases"]
        .as_array()
        .expect("available_releases array");
    assert_eq!(avail.len(), 1);
    assert!(avail[0].as_str().unwrap_or_default().ends_with("v4.0.0"));

    // Cleanup in --dry-run mode
    let clean_inv = parse_cli_args([
        "--dry-run",
        "--root",
        &root_str,
        "release",
        "cleanup",
        "--keep-releases",
        "2",
    ])
    .unwrap();
    let clean_env = execute_invocation(&clean_inv, &transport);
    assert_eq!(
        clean_env.status, "ok",
        "release cleanup failed: {}",
        clean_env.message
    );
}

#[test]
fn backup_commands_create_verify_list_and_run_non_destructive_restore_preflight_via_af_host() {
    let tmp = TempTestDir::new("backup-e2e");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_sqlite_db(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    fs::write(etc_af.join("settings.conf"), b"theme=dark\n").unwrap();

    let root_str = host_root.to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    // 1. Create a full host archive backup with chunk splitting in isolated root
    let create_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "backup",
        "create",
        "--archive",
        "--timestamp",
        "2026-10-31-180000",
        "--chunk-size",
        "512",
    ])
    .unwrap();
    let create_env = execute_invocation(&create_inv, &transport);
    assert_eq!(
        create_env.status, "ok",
        "backup create failed: {}",
        create_env.message
    );

    let archive_name = "aetherflow-backup-2026-10-31-180000.tar.gz";

    // 2. List backups
    let list_inv = parse_cli_args(["--json", "--root", &root_str, "backup", "list"]).unwrap();
    let list_env = execute_invocation(&list_inv, &transport);
    assert_eq!(list_env.status, "ok");
    let list_data = list_env.data.unwrap();
    assert_eq!(list_data["count"], 1);
    assert_eq!(list_data["items"][0]["filename"], archive_name);
    assert_eq!(list_data["items"][0]["checksum_present"], true);
    assert_eq!(list_data["items"][0]["manifest_present"], true);

    // 3. Verify backup artifact and sidecar/manifest
    let verify_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "backup",
        "verify",
        archive_name,
    ])
    .unwrap();
    let verify_env = execute_invocation(&verify_inv, &transport);
    assert_eq!(verify_env.status, "ok");

    // 4. Run NON-DESTRUCTIVE restore-preflight into an isolated staging directory
    let stage_target = tmp.path().join("restore-preflight-stage");
    let stage_str = stage_target.to_string_lossy().to_string();
    let preflight_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "backup",
        "restore-preflight",
        archive_name,
        "--target-root",
        &stage_str,
    ])
    .unwrap();
    let preflight_env = execute_invocation(&preflight_inv, &transport);
    assert_eq!(
        preflight_env.status, "ok",
        "restore-preflight failed: {}",
        preflight_env.message
    );
    let plan_data = preflight_env.data.unwrap();
    assert_eq!(plan_data["non_destructive_only"], true);
    assert!(
        !stage_target.exists(),
        "restore-preflight must never write to target_root"
    );

    // 5. Verify destructive `af backup restore` without confirmation fails closed with UnsupportedOperation (exit code 6)
    let restore_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "backup",
        "restore",
        archive_name,
    ])
    .unwrap();
    let restore_env = execute_invocation(&restore_inv, &transport);
    assert_eq!(restore_env.status, "error");
    assert_eq!(
        restore_env.exit_code,
        CliExitCode::UnsupportedOperation.as_i32()
    );
    assert!(restore_env.message.contains("explicitly unsupported"));

    // 6. Verify confirmed `af backup restore --confirm-destructive-restore` succeeds into isolated staging target
    let confirmed_restore_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "backup",
        "restore",
        archive_name,
        "--target-root",
        &stage_str,
        "--confirm-destructive-restore",
        "--allow-overwrite",
    ])
    .unwrap();
    let confirmed_env = execute_invocation(&confirmed_restore_inv, &transport);
    assert_eq!(
        confirmed_env.status, "ok",
        "confirmed restore failed: {}",
        confirmed_env.message
    );
    assert!(stage_target
        .join("var/lib/aetherflow/aetherflow.sqlite")
        .is_file());
    assert!(stage_target.join("etc/AetherFlow/settings.conf").is_file());
}

#[test]
fn backup_assembly_dry_run_does_not_create_directories() {
    let sandbox = TempTestDir::new("assemble-dry-run");
    let backup_dir = sandbox.path().join("not-created/backups");
    let digest = "a".repeat(64);
    let invocation = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        sandbox.path().to_str().unwrap(),
        "backup",
        "assemble",
        "--output",
        "backup.sqlite",
        "--sha256",
        &digest,
        "--backup-dir",
        backup_dir.to_str().unwrap(),
        "part.00000",
    ])
    .unwrap();
    let response = execute_invocation(&invocation, &MockRunnerTransport::default());
    assert_eq!(response.status, "ok", "{}", response.message);
    assert_eq!(fs::read_dir(sandbox.path()).unwrap().count(), 0);
}

#[test]
fn backup_restore_failures_have_nonzero_execution_exit_codes() {
    let failures = [
        af_host::HostBackupError::ServiceQuiescenceFailed {
            unit: "fixture-writer.service".to_string(),
            phase: "stop".to_string(),
            reason: "fixture stop failure".to_string(),
        },
        af_host::HostBackupError::RestoreRolledBack {
            reason: "fixture restore failure".to_string(),
            rollback_summary: "original files recovered".to_string(),
        },
        af_host::HostBackupError::RestoreRollbackFailed {
            reason: "fixture restore failure".to_string(),
            rollback_errors: "fixture rollback failure".to_string(),
            recovery_dir: PathBuf::from("/fixture/recovery"),
            failure_journal_path: PathBuf::from("/fixture/recovery/journal.json"),
            services_left_stopped: true,
        },
    ];
    for failure in failures {
        let error = CliError::Backup(failure);
        assert_eq!(error.exit_code(), CliExitCode::ExecutionFailure);
        let envelope = error.to_error_envelope("backup", "restore");
        assert_eq!(envelope.status, "error");
        assert_ne!(envelope.exit_code, 0);
    }
}

#[test]
fn release_local_deploy_and_rollback_write_status_receipts_and_honor_root_conf() {
    let tmp = TempTestDir::new("release-status-receipt");
    let root_str = tmp.path().to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    let rel_v1 = tmp.path().join("opt/AetherFlow/releases/v4.0.0");
    let rel_v2 = tmp.path().join("opt/AetherFlow/releases/v4.0.1");
    fs::create_dir_all(&rel_v1).unwrap();
    fs::create_dir_all(&rel_v2).unwrap();
    let etc_dir = tmp.path().join("etc/aetherflow");
    fs::create_dir_all(&etc_dir).unwrap();
    fs::write(
        etc_dir.join("release-manager.conf"),
        "RELEASE_CHANNEL=\"nightly\"\nMAX_RELEASES=4\n",
    )
    .unwrap();

    // 1. `af --root <root> release status` loads `<root>/etc/aetherflow/release-manager.conf`
    let status_inv = parse_cli_args(["--json", "--root", &root_str, "release", "status"]).unwrap();
    let status_env = execute_invocation(&status_inv, &transport);
    assert_eq!(status_env.status, "ok", "{}", status_env.message);
    let data = status_env.data.unwrap();
    assert_eq!(data["configured_channel"], "nightly");

    // 2. Local rollback fails when no `previous` slot exists and writes a `failed` receipt
    let fail_receipt_path = tmp
        .path()
        .join("var/lib/aetherflow/.self-update-jobs/job-fail.json");
    let fail_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "release",
        "rollback",
        "--local",
        "--job-status-file",
        fail_receipt_path.to_str().unwrap(),
        "--job-unit",
        "aetherflow-self-update-rollback-nightly-12345678.service",
    ])
    .unwrap();
    let fail_env = execute_invocation(&fail_inv, &transport);
    assert_eq!(fail_env.status, "error");
    let fail_receipt: SelfUpdateJobStatus =
        serde_json::from_str(&fs::read_to_string(&fail_receipt_path).unwrap()).unwrap();
    assert_eq!(fail_receipt.status, "failed");
    assert!(fail_receipt.completed);
    assert!(!fail_receipt.success);
    assert_ne!(fail_receipt.exit_code, Some(0));
    assert!(!fail_receipt.error.is_empty());
    let retry_closed_receipt = execute_invocation(&fail_inv, &transport);
    assert_eq!(retry_closed_receipt.status, "error");
    assert!(retry_closed_receipt
        .message
        .contains("admission was closed"));

    // 3. Dry-run local rollback with `.previous_release` in dry_run_root succeeds and writes a `succeeded` receipt
    #[cfg(unix)]
    {
        let dry_releases = tmp.path().join("tmp/aetherflow-dryrun/releases");
        fs::create_dir_all(&dry_releases).unwrap();
        fs::write(
            dry_releases.join(".previous_release"),
            format!("{}\n", rel_v1.display()),
        )
        .unwrap();
        let ok_receipt_path = tmp
            .path()
            .join("var/lib/aetherflow/.self-update-jobs/job-ok.json");
        let ok_inv = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "release",
            "rollback",
            "--local",
            "--job-status-file",
            ok_receipt_path.to_str().unwrap(),
            "--job-unit",
            "aetherflow-self-update-rollback-nightly-87654321.service",
        ])
        .unwrap();
        let ok_env = execute_invocation(&ok_inv, &transport);
        assert_eq!(ok_env.status, "ok", "{}", ok_env.message);
        let ok_receipt: SelfUpdateJobStatus =
            serde_json::from_str(&fs::read_to_string(&ok_receipt_path).unwrap()).unwrap();
        assert_eq!(ok_receipt.status, "succeeded");
        assert!(ok_receipt.completed);
        assert!(ok_receipt.success);
        assert_eq!(ok_receipt.exit_code, Some(0));
    }
}

#[test]
fn standalone_cleanup_reconciles_dead_api_owner_without_api_startup() {
    let root = TempTestDir::new("standalone-owner-recovery");
    let cfg = af_release::ReleaseConfig::for_root(root.path());
    let database = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    fs::create_dir_all(database.parent().unwrap()).unwrap();
    let conn = Connection::open(&database).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    af_release::lifecycle::initialize_schema(&conn).unwrap();
    let owner = af_release::lifecycle::OwnerLease::create(&database).unwrap();
    conn.execute(
        "INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id)
        VALUES ('fixture','original-job','update','updating','now',?1)",
        [&owner.id],
    )
    .unwrap();
    let invocation = parse_cli_args([
        "--json",
        "--root",
        root.path().to_str().unwrap(),
        "release",
        "cleanup",
    ])
    .unwrap();
    let transport = MockRunnerTransport::default();
    let blocked = execute_invocation(&invocation, &transport);
    assert_eq!(blocked.status, "error");
    assert!(blocked
        .message
        .contains("lifecycle orchestration is active"));
    drop(owner);
    let recovered = execute_invocation(&invocation, &transport);
    assert_eq!(recovered.status, "ok", "{}", recovered.message);
    let status: String = conn
        .query_row("SELECT status FROM package_lifecycle_jobs", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(status, "interrupted");
}

#[test]
fn runner_dispatched_release_and_update_commands_reject_local_root_and_config_overrides() {
    let sandbox = TempTestDir::new("runner-release-override-reject");
    let root_str = sandbox.path().to_string_lossy().to_string();
    let conf_path = sandbox.path().join("custom.conf");
    fs::write(&conf_path, "RELEASE_CHANNEL=\"nightly\"\n").unwrap();
    let conf_str = conf_path.to_string_lossy().to_string();
    let status_file = sandbox.path().join("job.json");
    let status_str = status_file.to_string_lossy().to_string();

    let rejected_arg_sets: Vec<Vec<&str>> = vec![
        vec!["--json", "--root", &root_str, "release", "deploy"],
        vec!["--json", "--root", &root_str, "release", "rollback"],
        vec!["--json", "release", "deploy", "--config", &conf_str],
        vec!["--json", "release", "deploy", "--keep-releases", "3"],
        vec![
            "--json",
            "release",
            "deploy",
            "--job-status-file",
            &status_str,
        ],
        vec![
            "--json",
            "release",
            "deploy",
            "--job-unit",
            "aetherflow-self-update-deploy-stable-12345678.service",
        ],
        vec!["--json", "--root", &root_str, "update"],
        vec!["--json", "--root", &root_str, "upgrade"],
    ];

    for raw_args in rejected_arg_sets {
        let transport = MockRunnerTransport::default();
        let invocation = parse_cli_args(raw_args.clone()).unwrap();
        let envelope = execute_invocation(&invocation, &transport);
        assert_eq!(
            envelope.status, "error",
            "expected error for {:?}",
            raw_args
        );
        assert_eq!(
            envelope.exit_code,
            CliExitCode::UsageOrValidation.as_i32(),
            "expected validation exit code for {:?}: {}",
            raw_args,
            envelope.message
        );
        assert!(
            transport.self_update_calls.lock().unwrap().is_empty(),
            "runner socket must not be invoked when local overrides are rejected: {:?}",
            raw_args
        );
    }
}

#[test]
fn isolated_root_backup_cli_rejects_out_of_root_backup_dir_and_contains_staging_sqlite_override() {
    let sandbox = TempTestDir::new("backup-cli-containment");
    let root_dir = sandbox.path().join("iso-root");
    let outside_dir = sandbox.path().join("outside-backups");
    fs::create_dir_all(&root_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    let bad_inv = parse_cli_args([
        "--json",
        "--root",
        root_dir.to_str().unwrap(),
        "backup",
        "create",
        "--backup-dir",
        outside_dir.to_str().unwrap(),
    ])
    .unwrap();
    let bad_env = execute_invocation(&bad_inv, &MockRunnerTransport::default());
    assert_eq!(bad_env.status, "error");
    assert_eq!(bad_env.exit_code, CliExitCode::UsageOrValidation.as_i32());
    assert!(bad_env.message.contains("outside active isolated root"));

    let db_path = root_dir.join("srv/custom-af/aetherflow.sqlite");
    let backup_dir = root_dir.join("var/lib/aetherflow/backups");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    fs::create_dir_all(&backup_dir).unwrap();
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA user_version = 7;
         CREATE TABLE sample (id INTEGER PRIMARY KEY, label TEXT NOT NULL);
         INSERT INTO sample (id, label) VALUES (1, 'contained');",
    )
    .unwrap();
    drop(conn);

    let mut backup_cfg = af_host::HostBackupConfig::for_isolated_root(&root_dir, "v4.0.0");
    backup_cfg.backup_dir = backup_dir.clone();
    backup_cfg.sqlite_db_path = Some(db_path.clone());
    let receipt =
        af_host::create_sqlite_snapshot_backup(&backup_cfg, Some("20261103_110000")).unwrap();
    let backup_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let stage_target = root_dir.join("var/lib/aetherflow/restore-staging/stage-one");
    let preflight_inv = parse_cli_args([
        "--json",
        "--root",
        root_dir.to_str().unwrap(),
        "backup",
        "restore-preflight",
        &backup_filename,
        "--backup-dir",
        backup_dir.to_str().unwrap(),
        "--target-root",
        stage_target.to_str().unwrap(),
    ])
    .unwrap();
    let preflight_env = execute_invocation(&preflight_inv, &MockRunnerTransport::default());
    assert_eq!(preflight_env.status, "ok", "{}", preflight_env.message);
    let plan_items = preflight_env.data.unwrap()["items"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(plan_items.len(), 1);
    let destination_str = plan_items[0]["destination_path"].as_str().unwrap();
    assert!(
        Path::new(destination_str).starts_with(&stage_target),
        "staging restore destination '{}' escaped staging target '{}'",
        destination_str,
        stage_target.display()
    );

    let recover_inv = parse_cli_args([
        "--json",
        "--root",
        root_dir.to_str().unwrap(),
        "backup",
        "recover",
        "--backup-dir",
        backup_dir.to_str().unwrap(),
    ])
    .unwrap();
    let recover_env = execute_invocation(&recover_inv, &MockRunnerTransport::default());
    assert_eq!(recover_env.status, "ok", "{}", recover_env.message);
}

#[test]
fn release_deploy_omitting_channel_honors_configured_channel_from_release_manager_conf() {
    let tmp = TempTestDir::new("release-channel-conf-honor");
    let root_str = tmp.path().to_string_lossy().to_string();
    let etc_dir = tmp.path().join("etc/aetherflow");
    fs::create_dir_all(&etc_dir).unwrap();
    fs::write(
        etc_dir.join("release-manager.conf"),
        "RELEASE_CHANNEL=\"nightly\"\nMAX_RELEASES=4\n",
    )
    .unwrap();

    // Create a minimal local release slot + staging artifact or verify channel flag propagation
    let implicit_inv = parse_cli_args([
        "--json", "--root", &root_str, "release", "deploy", "--local",
    ])
    .unwrap();
    match &implicit_inv.command {
        AfCommand::Release(ReleaseCliCommand::Deploy {
            channel_explicit, ..
        }) => assert!(!*channel_explicit),
        other => panic!("unexpected command: {other:?}"),
    }

    let explicit_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "release",
        "deploy",
        "--local",
        "--channel",
        "stable",
    ])
    .unwrap();
    match &explicit_inv.command {
        AfCommand::Release(ReleaseCliCommand::Deploy {
            channel,
            channel_explicit,
            ..
        }) => {
            assert!(*channel_explicit);
            assert_eq!(*channel, ReleaseChannel::Stable);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    // Also verify dry-run local rollback without --channel honors nightly from release-manager.conf
    #[cfg(unix)]
    {
        let rel_v1 = tmp.path().join("opt/AetherFlow/releases/v4.0.0-nightly.1");
        fs::create_dir_all(&rel_v1).unwrap();
        let dry_releases = tmp.path().join("tmp/aetherflow-dryrun/releases");
        fs::create_dir_all(&dry_releases).unwrap();
        fs::write(
            dry_releases.join(".previous_release"),
            format!("{}\n", rel_v1.display()),
        )
        .unwrap();
        let rb_inv = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "release",
            "rollback",
            "--local",
        ])
        .unwrap();
        let rb_env = execute_invocation(&rb_inv, &MockRunnerTransport::default());
        assert_eq!(rb_env.status, "ok", "{}", rb_env.message);
    }
}

#[test]
fn backup_maintenance_lock_resolution_prevents_split_brain_and_preserves_unprivileged_local_ops() {
    let _env_guard = super::ENV_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let sandbox = TempTestDir::new("backup-lock-resolution");
    let iso_root = sandbox.path().join("iso-root");
    let iso_db = iso_root.join("var/lib/aetherflow/aetherflow.sqlite");
    let iso_custom_backups = iso_root.join("custom-backups");
    create_sample_sqlite_db(&iso_db);
    fs::create_dir_all(&iso_custom_backups).unwrap();

    // 1. Live host `af backup restore --backup-dir /mnt/usb --target-root /` MUST resolve the
    // canonical host maintenance lock (not `/mnt/usb/.snapshot.lock`).
    let live_global = GlobalOptions::default();
    let live_restore_cmd = BackupCliCommand::RestoreDestructive {
        filename: "aetherflow-backup.tar.gz".to_string(),
        backup_dir: Some(PathBuf::from("/mnt/usb")),
        target_root: Some(PathBuf::from("/")),
        confirm_destructive_restore: true,
        allow_overwrite: true,
        operator_privileged: true,
        trusted_sqlite_uid: None,
        trusted_sqlite_gid: None,
    };
    let live_restore_cfg = crate::commands::backup::resolve_backup_config(
        &live_global,
        Some(Path::new("/mnt/usb")),
        None,
        "v4.0.0",
    )
    .unwrap();
    let expected_live_lock = af_models::try_resolve_canonical_maintenance_lock_path_from_env(
        None,
        live_restore_cfg.sqlite_db_path.as_deref(),
        Some(&live_restore_cfg.backup_dir),
    )
    .unwrap();
    let resolved_live_restore_lock = crate::commands::backup::resolve_backup_maintenance_lock_path(
        &live_global,
        &live_restore_cmd,
        &live_restore_cfg,
    )
    .unwrap();
    assert_eq!(resolved_live_restore_lock, expected_live_lock);
    assert_ne!(
        resolved_live_restore_lock,
        PathBuf::from("/mnt/usb/.snapshot.lock")
    );

    // 2. Live host `backup create --backup-dir /mnt/usb` (default live DB) and system-scoped
    // `backup prune --backup-dir /var/lib/aetherflow/backups` also acquire the canonical host lock.
    let live_create_cmd = BackupCliCommand::Create {
        kind: BackupCreateKind::Sqlite,
        backup_dir: Some(PathBuf::from("/mnt/usb")),
        db_path: None,
        app_version: "v4.0.0".to_string(),
        chunk_size_bytes: None,
        timestamp_slug: None,
        operator_privileged: true,
        trusted_sqlite_uid: None,
        trusted_sqlite_gid: None,
    };
    assert_eq!(
        crate::commands::backup::resolve_backup_maintenance_lock_path(
            &live_global,
            &live_create_cmd,
            &live_restore_cfg,
        )
        .unwrap(),
        expected_live_lock
    );
    let system_prune_cmd = BackupCliCommand::Prune {
        backup_dir: Some(PathBuf::from("/var/lib/aetherflow/backups")),
        max_retained: 5,
        retention_days: 30,
        operator_privileged: true,
    };
    let system_prune_cfg = crate::commands::backup::resolve_backup_config(
        &live_global,
        Some(Path::new("/var/lib/aetherflow/backups")),
        None,
        "v4.0.0",
    )
    .unwrap();
    assert_eq!(
        crate::commands::backup::resolve_backup_maintenance_lock_path(
            &live_global,
            &system_prune_cmd,
            &system_prune_cfg,
        )
        .unwrap(),
        expected_live_lock
    );

    // 3. Isolated `--root` mutation with explicit `--backup-dir` MUST acquire the root's canonical
    // lock (`<root>/var/lib/aetherflow/.snapshot.lock`), NOT `<custom-backups>/.snapshot.lock`.
    let create_iso_inv = parse_cli_args([
        "--json",
        "--root",
        iso_root.to_str().unwrap(),
        "backup",
        "create",
        "--sqlite-only",
        "--backup-dir",
        iso_custom_backups.to_str().unwrap(),
        "--timestamp",
        "2026-11-22-080000",
    ])
    .unwrap();
    let create_iso_env = execute_invocation(&create_iso_inv, &MockRunnerTransport::default());
    assert_eq!(create_iso_env.status, "ok", "{}", create_iso_env.message);
    assert!(
        iso_root.join("var/lib/aetherflow/.snapshot.lock").is_file(),
        "isolated --root backup create with --backup-dir must acquire canonical root lock"
    );
    assert!(
        !iso_custom_backups.join(".snapshot.lock").exists(),
        "must not split-brain onto custom --backup-dir lock under --root"
    );

    // 4. Isolated `--root` with out-of-root `--db-path` is rejected before executing backup.
    let outside_db = sandbox.path().join("outside.sqlite");
    create_sample_sqlite_db(&outside_db);
    let bad_db_inv = parse_cli_args([
        "--json",
        "--root",
        iso_root.to_str().unwrap(),
        "backup",
        "create",
        "--sqlite-only",
        "--db-path",
        outside_db.to_str().unwrap(),
    ])
    .unwrap();
    let bad_db_env = execute_invocation(&bad_db_inv, &MockRunnerTransport::default());
    assert_eq!(bad_db_env.status, "error");
    assert_eq!(
        bad_db_env.exit_code,
        CliExitCode::UsageOrValidation.as_i32()
    );
    assert!(bad_db_env.message.contains("outside active isolated root"));

    // 5. Unprivileged non-root local operations (`global.root = None`) with non-system `--backup-dir`
    // and `--db-path` must use `<local>/.snapshot.lock` and succeed without PermissionDenied on `/run`.
    let local_dir = sandbox.path().join("local-only");
    let local_db = local_dir.join("test.sqlite");
    create_sample_sqlite_db(&local_db);
    let local_create_inv = parse_cli_args([
        "--json",
        "backup",
        "create",
        "--sqlite-only",
        "--backup-dir",
        local_dir.to_str().unwrap(),
        "--db-path",
        local_db.to_str().unwrap(),
        "--timestamp",
        "2026-11-22-080100",
    ])
    .unwrap();
    let local_create_env = execute_invocation(&local_create_inv, &MockRunnerTransport::default());
    assert_eq!(
        local_create_env.status, "ok",
        "unprivileged local backup create must succeed: {}",
        local_create_env.message
    );
    assert!(local_dir.join(".snapshot.lock").is_file());
    let created_filename = Path::new(
        local_create_env.data.as_ref().unwrap()["primary_artifact_path"]
            .as_str()
            .unwrap(),
    )
    .file_name()
    .unwrap()
    .to_str()
    .unwrap()
    .to_string();

    let local_prune_inv = parse_cli_args([
        "--json",
        "backup",
        "prune",
        "--backup-dir",
        local_dir.to_str().unwrap(),
        "--max-retained",
        "5",
    ])
    .unwrap();
    let local_prune_env = execute_invocation(&local_prune_inv, &MockRunnerTransport::default());
    assert_eq!(
        local_prune_env.status, "ok",
        "unprivileged local backup prune must succeed: {}",
        local_prune_env.message
    );

    let local_delete_inv = parse_cli_args([
        "--json",
        "backup",
        "delete",
        &created_filename,
        "--backup-dir",
        local_dir.to_str().unwrap(),
    ])
    .unwrap();
    let local_delete_env = execute_invocation(&local_delete_inv, &MockRunnerTransport::default());
    assert_eq!(
        local_delete_env.status, "ok",
        "unprivileged local backup delete must succeed: {}",
        local_delete_env.message
    );
}

#[test]
fn backup_restore_dry_run_validates_traversal_and_missing_artifact_or_manifest() {
    let sandbox = TempTestDir::new("backup-restore-dry-run");
    let root_dir = sandbox.path().join("host");
    let db_path = root_dir.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_sqlite_db(&db_path);
    let root_str = root_dir.to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    // Create a valid backup artifact + manifest inside isolated root
    let create_inv = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "backup",
        "create",
        "--sqlite-only",
        "--timestamp",
        "2026-11-22-080200",
    ])
    .unwrap();
    let create_env = execute_invocation(&create_inv, &transport);
    assert_eq!(create_env.status, "ok", "{}", create_env.message);
    let valid_filename = Path::new(
        create_env.data.as_ref().unwrap()["primary_artifact_path"]
            .as_str()
            .unwrap(),
    )
    .file_name()
    .unwrap()
    .to_str()
    .unwrap()
    .to_string();

    // 1. Valid backup artifact + manifest succeeds under --dry-run WITHOUT --confirm-destructive-restore.
    let dry_ok_inv = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "backup",
        "restore",
        &valid_filename,
    ])
    .unwrap();
    let dry_ok_env = execute_invocation(&dry_ok_inv, &transport);
    assert_eq!(dry_ok_env.status, "ok", "{}", dry_ok_env.message);

    // 2. Path traversal fails dry-run cleanly (both via CLI parser and direct command execution).
    assert!(parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "backup",
        "restore",
        "../../etc/passwd",
    ])
    .is_err());
    let direct_traversal_inv = ParsedInvocation {
        global: GlobalOptions {
            json: true,
            dry_run: true,
            root: Some(root_dir.clone()),
            ..GlobalOptions::default()
        },
        command: AfCommand::Backup(BackupCliCommand::RestoreDestructive {
            filename: "../../etc/passwd".to_string(),
            backup_dir: None,
            target_root: None,
            confirm_destructive_restore: false,
            allow_overwrite: false,
            operator_privileged: false,
            trusted_sqlite_uid: None,
            trusted_sqlite_gid: None,
        }),
    };
    let traversal_env = execute_invocation(&direct_traversal_inv, &transport);
    assert_eq!(traversal_env.status, "error");
    assert_eq!(
        traversal_env.exit_code,
        CliExitCode::UsageOrValidation.as_i32()
    );

    // 3. Missing artifact fails dry-run cleanly.
    let missing_inv = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "backup",
        "restore",
        "does-not-exist.sqlite",
    ])
    .unwrap();
    let missing_env = execute_invocation(&missing_inv, &transport);
    assert_eq!(missing_env.status, "error");
    assert_eq!(
        missing_env.exit_code,
        CliExitCode::PreflightOrIntegrityFailure.as_i32()
    );
    assert!(missing_env.message.contains("missing backup artifact"));

    // 4. Artifact present without required `.manifest.json` fails dry-run cleanly.
    let backup_dir = root_dir.join("var/lib/aetherflow/backups");
    fs::write(backup_dir.join("orphan.sqlite"), b"not-a-manifested-backup").unwrap();
    let missing_manifest_inv = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "backup",
        "restore",
        "orphan.sqlite",
    ])
    .unwrap();
    let missing_manifest_env = execute_invocation(&missing_manifest_inv, &transport);
    assert_eq!(missing_manifest_env.status, "error");
    assert_eq!(
        missing_manifest_env.exit_code,
        CliExitCode::PreflightOrIntegrityFailure.as_i32()
    );
    assert!(missing_manifest_env
        .message
        .contains("missing required backup manifest"));
}

#[test]
fn backup_preflight_allow_overwrite_alias_quiescence_gating_and_dynamic_version() {
    let tmp = TempTestDir::new("esc08-cli-flags-quiescence-version");
    let root = tmp.path().join("root");
    let current = root.join("opt/AetherFlow/current");
    fs::create_dir_all(&current).unwrap();
    fs::write(current.join(".version"), "v4.2.1-nightly.9\n").unwrap();

    // 1. Dynamic host version resolution honors `<root>/opt/AetherFlow/current/.version`.
    let resolved_root_ver = crate::commands::backup::resolve_runtime_host_version(Some(&root));
    assert_eq!(resolved_root_ver, "v4.2.1-nightly.9");

    // Non-semver `.version` falls back safely to Cargo package version.
    fs::write(current.join(".version"), "dev-untagged\n").unwrap();
    let fallback_ver = crate::commands::backup::resolve_runtime_host_version(Some(&root));
    assert_eq!(fallback_ver, concat!("v", env!("CARGO_PKG_VERSION")));

    // 2. `--allow-overwrite` is accepted as an alias for `--allow-staging-overwrite` on restore-preflight.
    fs::write(current.join(".version"), "v4.2.1\n").unwrap();
    let inv = parse_cli_args([
        "--root",
        root.to_str().unwrap(),
        "backup",
        "restore-preflight",
        "sample.tar.gz",
        "--target-root",
        "/tmp/stage-preflight",
        "--allow-overwrite",
    ])
    .unwrap();
    match inv.command {
        AfCommand::Backup(BackupCliCommand::RestorePreflight {
            host_version,
            overwrite_policy,
            ..
        }) => {
            assert_eq!(host_version, "v4.2.1");
            assert_eq!(
                overwrite_policy,
                af_host::OverwritePolicy::AllowRegularFilesInStaging
            );
        }
        other => panic!("unexpected command: {other:?}"),
    }

    // 3. Quiescence gating: isolated staging target without `--root` does NOT trigger live
    //    quiescence unless the target is `/`, system-scoped, or contains the active AF_DB_PATH.
    let live_global = GlobalOptions::default();
    let default_db = Path::new("/var/lib/aetherflow/aetherflow.sqlite");
    assert!(
        !crate::commands::backup::target_requires_live_quiescence(
            &live_global,
            Path::new("/tmp/stage-123"),
            Some(default_db),
        ),
        "isolated staging target must use NoopQuiescenceController"
    );
    assert!(
        crate::commands::backup::target_requires_live_quiescence(
            &live_global,
            Path::new("/"),
            Some(default_db),
        ),
        "canonical `/` restore must quiesce live services"
    );
    let custom_db = Path::new("/mnt/fast-ssd/af-data/aetherflow.sqlite");
    assert!(
        crate::commands::backup::target_requires_live_quiescence(
            &live_global,
            Path::new("/mnt/fast-ssd/af-data"),
            Some(custom_db),
        ),
        "target containing custom live AF_DB_PATH must quiesce live services"
    );
    let isolated_global = GlobalOptions {
        root: Some(root.clone()),
        ..GlobalOptions::default()
    };
    assert!(!crate::commands::backup::target_requires_live_quiescence(
        &isolated_global,
        &root,
        Some(&root.join("var/lib/aetherflow/aetherflow.sqlite")),
    ));
}
