use super::{create_sample_wal_database, TempTestDir};
use crate::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[test]
fn missing_configured_sqlite_db_fails_archive_backup_and_trusted_sqlite_override_ignores_manifest_logical_path(
) {
    let tmp = TempTestDir::new("missing-db-and-custom-sqlite");
    let host_root = tmp.path().join("host");
    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    fs::write(etc_af.join("cluster.conf"), b"node_role=primary\n").unwrap();

    let missing_cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let missing_err =
        create_host_archive_backup(&missing_cfg, Some("2026-11-03-040000")).unwrap_err();
    assert!(matches!(
        missing_err,
        HostBackupError::SqliteSnapshot { .. }
    ));

    let custom_db = tmp.path().join("custom-db-dir/aetherflow.sqlite");
    create_sample_wal_database(&custom_db);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&custom_db, fs::Permissions::from_mode(0o660)).unwrap();
    }

    let mut custom_cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    custom_cfg.sqlite_db_path = Some(custom_db.clone());
    let sqlite_receipt =
        create_sqlite_snapshot_backup(&custom_cfg, Some("2026-11-03_04-10-00")).unwrap();
    let sqlite_filename = sqlite_receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let mut tampered_manifest = sqlite_receipt.manifest.clone();
    tampered_manifest.entries[0].logical_target_path =
        Some("/etc/AetherFlow/evil_redirect.sqlite".to_string());
    tampered_manifest
        .save_atomic(&sqlite_receipt.manifest_path)
        .unwrap();

    let restored_custom_db = tmp.path().join("restored-custom-db/aetherflow.sqlite");
    let pf_plan = preflight_restore_directory_with_sqlite_override(
        &custom_cfg.backup_dir,
        &tampered_manifest,
        &host_root,
        &RestorePreflightOptions {
            host_app_version: "v4.0.0".to_string(),
            max_supported_sqlite_user_version: Some(50),
            overwrite_policy: OverwritePolicy::AllowRegularFilesInStaging,
            require_artifact_sidecar: true,
        },
        Some(&restored_custom_db),
    )
    .unwrap();
    assert_eq!(pf_plan.items[0].destination_path, restored_custom_db);

    let report = execute_staged_restore(
        &custom_cfg.backup_dir,
        &sqlite_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            trusted_sqlite_db_path: Some(restored_custom_db.clone()),
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap();
    assert!(report.sqlite_restored);
    assert_eq!(report.restored_files, vec![restored_custom_db.clone()]);
    assert!(!host_root
        .join("etc/AetherFlow/evil_redirect.sqlite")
        .exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let db_mode = fs::symlink_metadata(&restored_custom_db)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(db_mode, 0o660);
    }
}

#[cfg(unix)]
#[test]
fn dirfd_service_owner_policy_wal_shm_mode_preservation_and_non_enoent_unlink_failure() {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    let tmp = TempTestDir::new("dirfd-wal-unlink");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    fs::write(etc_af.join("cluster.conf"), b"node_role=primary\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-050000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let wal_path = host_root.join("var/lib/aetherflow/aetherflow.sqlite-wal");
    let shm_path = host_root.join("var/lib/aetherflow/aetherflow.sqlite-shm");
    fs::write(&wal_path, b"live-wal-bytes").unwrap();
    fs::write(&shm_path, b"live-shm-bytes").unwrap();
    fs::set_permissions(&wal_path, fs::Permissions::from_mode(0o660)).unwrap();
    fs::set_permissions(&shm_path, fs::Permissions::from_mode(0o640)).unwrap();

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

    let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
    let recovered = recover_interrupted_restore_with_context(
        &cfg.backup_dir,
        &rec_ctx,
        &NoopQuiescenceController,
    )
    .unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        fs::symlink_metadata(&wal_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o660
    );
    assert_eq!(
        fs::symlink_metadata(&shm_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );

    fs::remove_file(&wal_path).unwrap();
    fs::create_dir_all(&wal_path).unwrap();
    let direct_unlink_err =
        unlink_file_at_destination(&wal_path, "direct non-enoent unlink").unwrap_err();
    assert!(matches!(
        direct_unlink_err,
        HostBackupError::UnsafeOverwriteRejected { .. }
    ));
    let non_enoent_err = execute_staged_restore(
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
    .unwrap_err();
    assert!(matches!(
        non_enoent_err,
        HostBackupError::UnsafeOverwriteRejected { .. }
            | HostBackupError::RestoreRolledBack { .. }
            | HostBackupError::RestoreRollbackFailed { .. }
    ));
    fs::remove_dir_all(&wal_path).unwrap();

    let symlink_lock = tmp.path().join("symlink.lock");
    let lock_target = tmp.path().join("real-target.lock");
    fs::write(&lock_target, b"").unwrap();
    symlink(&lock_target, &symlink_lock).unwrap();
    let symlink_lock_err =
        HostMaintenanceLockGuard::acquire(&symlink_lock, Duration::from_millis(50))
            .unwrap_err();
    assert!(symlink_lock_err.is_security_rejection());

    let valid_lock = tmp.path().join("valid-maint.lock");
    let guard =
        HostMaintenanceLockGuard::acquire(&valid_lock, Duration::from_millis(100)).unwrap();
    let lock_mode = fs::symlink_metadata(&valid_lock)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(lock_mode, 0o660);
    drop(guard);

    let world_writable_dir = tmp.path().join("world-writable-ancestor/sub");
    fs::create_dir_all(&world_writable_dir).unwrap();
    fs::set_permissions(
        world_writable_dir.parent().unwrap(),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let ww_err =
        open_or_create_dir_nofollow(&world_writable_dir, 0o750, "world-writable check")
            .unwrap_err();
    assert!(ww_err.is_security_rejection());

    if unsafe { libc::geteuid() } == 0 {
        let svc_dir = tmp.path().join("service-owned-dir");
        fs::create_dir_all(&svc_dir).unwrap();
        fs::set_permissions(&svc_dir, fs::Permissions::from_mode(0o750)).unwrap();
        let c_svc_dir = std::ffi::CString::new(svc_dir.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::chown(c_svc_dir.as_ptr(), 65534, 65534) }, 0);

        let untrusted_err =
            open_or_create_dir_nofollow(&svc_dir, 0o750, "untrusted-65534").unwrap_err();
        assert!(untrusted_err.is_security_rejection());

        open_or_create_dir_nofollow_with_trusted_uid(
            &svc_dir,
            0o750,
            Some(65534),
            "explicit-trusted-65534",
        )
        .unwrap();

        let src_file = tmp.path().join("staged-svc-db.sqlite");
        fs::write(&src_file, b"sqlite-payload").unwrap();
        let dest_file = svc_dir.join("aetherflow.sqlite");
        atomic_install_file_at_destination_with_trusted_ancestor_uid(
            &src_file,
            &dest_file,
            0o660,
            Some(65534),
            Some(65534),
            Some(65534),
            "installing service-owned sqlite db",
        )
        .unwrap();
        let dest_meta = fs::symlink_metadata(&dest_file).unwrap();
        assert_eq!(dest_meta.uid(), 65534);
        assert_eq!(dest_meta.gid(), 65534);
        assert_eq!(dest_meta.permissions().mode() & 0o777, 0o660);
    }
}

#[test]
fn duplicate_destination_mappings_and_non_sqlite_wal_shm_are_rejected_and_preserved() {
    let tmp = TempTestDir::new("dup-dest-and-non-sqlite-sidecars");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    let conf_path = etc_af.join("cluster.conf");
    let conf_wal_lookalike = etc_af.join("cluster.conf-wal");
    let conf_shm_lookalike = etc_af.join("cluster.conf-shm");
    fs::write(&conf_path, b"node_role=primary\n").unwrap();
    fs::write(&conf_wal_lookalike, b"must-not-be-unlinked-wal\n").unwrap();
    fs::write(&conf_shm_lookalike, b"must-not-be-unlinked-shm\n").unwrap();

    let owner_home = host_root.join("home/aetherflow");
    fs::create_dir_all(&owner_home).unwrap();
    fs::write(
        owner_home.join(".rtorrent.rc"),
        b"port_range = 50000-50010\n",
    )
    .unwrap();

    let mut dup_manifest = BackupManifest::new("4.0.0", "aetherflow-backup.tar.gz").unwrap();
    dup_manifest.entries.push(BackupManifestEntry {
        relative_path: "home/owner/.rtorrent.rc".to_string(),
        logical_target_path: None,
        kind: BackupTargetKind::ConfigFile,
        sha256: "a".repeat(64),
        size_bytes: 16,
        unix_mode: Some(0o640),
        unix_uid: None,
        unix_gid: None,
        required: true,
    });
    dup_manifest.entries.push(BackupManifestEntry {
        relative_path: "home/aetherflow/.rtorrent.rc".to_string(),
        logical_target_path: None,
        kind: BackupTargetKind::ConfigFile,
        sha256: "b".repeat(64),
        size_bytes: 16,
        unix_mode: Some(0o640),
        unix_uid: None,
        unix_gid: None,
        required: true,
    });
    assert!(matches!(
        dup_manifest.validate().unwrap_err(),
        HostBackupError::InvalidManifest(_)
    ));

    let mut non_sqlite_wal_manifest =
        BackupManifest::new("4.0.0", "aetherflow-backup.tar.gz").unwrap();
    non_sqlite_wal_manifest.entries.push(BackupManifestEntry {
        relative_path: "var/lib/aetherflow/aetherflow.sqlite-wal".to_string(),
        logical_target_path: None,
        kind: BackupTargetKind::ConfigFile,
        sha256: "a".repeat(64),
        size_bytes: 16,
        unix_mode: Some(0o600),
        unix_uid: None,
        unix_gid: None,
        required: true,
    });
    assert!(matches!(
        non_sqlite_wal_manifest.validate().unwrap_err(),
        HostBackupError::InvalidManifest(_)
    ));

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-060000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let _ = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            fail_after_replacements: Some(1),
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();

    assert_eq!(
        fs::read_to_string(&conf_wal_lookalike).unwrap(),
        "must-not-be-unlinked-wal\n"
    );
    assert_eq!(
        fs::read_to_string(&conf_shm_lookalike).unwrap(),
        "must-not-be-unlinked-shm\n"
    );
}

#[test]
fn standalone_sqlite_planning_preflight_and_execution_resolve_identical_destinations_and_lock_path_is_stable(
) {
    let tmp = TempTestDir::new("sqlite-dest-and-lock-stability");
    let host_root = tmp.path().join("fresh-empty-stage");
    fs::create_dir_all(&host_root).unwrap();

    let source_root = tmp.path().join("source-host");
    let source_db = source_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&source_db);

    let cfg = HostBackupConfig::for_isolated_root(&source_root, "v4.0.0");
    let receipt = create_sqlite_snapshot_backup(&cfg, Some("2026-11-03_06-30-00")).unwrap();
    let sqlite_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let mut stripped_manifest = receipt.manifest.clone();
    stripped_manifest.entries[0].logical_target_path = None;
    stripped_manifest
        .save_atomic(&receipt.manifest_path)
        .unwrap();

    let pf_opts = RestorePreflightOptions {
        host_app_version: "v4.0.0".to_string(),
        max_supported_sqlite_user_version: Some(50),
        overwrite_policy: OverwritePolicy::RejectExisting,
        require_artifact_sidecar: true,
    };
    let planned = plan_restore_from_manifest(&stripped_manifest, &host_root, &pf_opts).unwrap();
    let preflighted =
        preflight_restore_directory(&cfg.backup_dir, &stripped_manifest, &host_root, &pf_opts)
            .unwrap();
    let expected_dest = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    assert_eq!(planned.items[0].destination_path, expected_dest);
    assert_eq!(preflighted.items[0].destination_path, expected_dest);

    let report = execute_staged_restore(
        &cfg.backup_dir,
        &sqlite_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: false,
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap();
    assert_eq!(report.restored_files, vec![expected_dest.clone()]);
    assert!(expected_dest.is_file());

    let missing_dir_root = tmp.path().join("nonexistent-var-lib/aetherflow/backups");
    let resolved_before = resolve_maintenance_lock_path(Some(&missing_dir_root));
    fs::create_dir_all(missing_dir_root.parent().unwrap()).unwrap();
    let resolved_after = resolve_maintenance_lock_path(Some(&missing_dir_root));
    assert_eq!(resolved_before, resolved_after);
}

#[test]
fn recovery_context_rejects_mismatched_target_root_forged_sqlite_override_and_tampered_provenance(
) {
    let tmp = TempTestDir::new("provenance-context-security");
    let host_root = tmp.path().join("host");
    let other_root = tmp.path().join("other-host");
    fs::create_dir_all(&other_root).unwrap();
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    fs::write(etc_af.join("cluster.conf"), b"node_role=golden\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-070000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    fs::write(
        etc_af.join("cluster.conf"),
        b"node_role=live_before_crash\n",
    )
    .unwrap();

    let rb_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            fail_after_replacements: Some(1),
            fail_rollback_after_restores: Some(0),
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();

    let (rb_dir, failure_journal_path) = match rb_err {
        HostBackupError::RestoreRollbackFailed {
            recovery_dir,
            failure_journal_path,
            ..
        } => (recovery_dir, failure_journal_path),
        other => panic!("expected RestoreRollbackFailed, got {:?}", other),
    };

    let wrong_root_ctx = RecoveryContext::for_target_root(&other_root, None);
    let wrong_root_err = recover_interrupted_restore_with_context(
        &cfg.backup_dir,
        &wrong_root_ctx,
        &NoopQuiescenceController,
    )
    .unwrap_err();
    assert!(matches!(
        wrong_root_err,
        HostBackupError::InvalidManifest(_)
    ));
    assert!(rb_dir.is_dir());

    let orig_journal_bytes = fs::read(&failure_journal_path).unwrap();
    let mut tampered_journal: RollbackFailureJournal =
        serde_json::from_slice(&orig_journal_bytes).unwrap();
    tampered_journal.trusted_sqlite_db_path =
        Some(tmp.path().join("untrusted-override/aetherflow.sqlite"));
    fs::write(
        &failure_journal_path,
        serde_json::to_vec_pretty(&tampered_journal).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&failure_journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    write_sha256_sidecar(&failure_journal_path).unwrap();

    let valid_ctx = RecoveryContext::for_target_root(&host_root, None);
    let forged_override_err = recover_interrupted_restore_with_context(
        &cfg.backup_dir,
        &valid_ctx,
        &NoopQuiescenceController,
    )
    .unwrap_err();
    assert!(
        forged_override_err.is_integrity_failure()
            || forged_override_err.is_security_rejection()
    );

    fs::write(&failure_journal_path, &orig_journal_bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&failure_journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    write_sha256_sidecar(&failure_journal_path).unwrap();

    let etc_sqlite_err =
        validate_trusted_sqlite_db_path(Path::new("/etc/AetherFlow/aetherflow.sqlite"))
            .unwrap_err();
    assert!(etc_sqlite_err.is_security_rejection());

    let recovered = recover_interrupted_restore_with_context(
        &cfg.backup_dir,
        &valid_ctx,
        &NoopQuiescenceController,
    )
    .unwrap();
    assert_eq!(recovered, vec![rb_dir]);
    assert_eq!(
        fs::read_to_string(etc_af.join("cluster.conf")).unwrap(),
        "node_role=live_before_crash\n"
    );
}

#[cfg(unix)]
#[test]
fn non_root_mismatching_chown_fails_closed_and_untrusted_entry_uid_never_widens_ancestor_trust()
{
    use std::os::unix::fs::{symlink, PermissionsExt};

    let tmp = TempTestDir::new("chown-and-nofollow");
    let src_file = tmp.path().join("staged.txt");
    fs::write(&src_file, b"payload").unwrap();
    let dest_file = tmp.path().join("installed.txt");

    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        let bogus_uid = euid.saturating_add(1000);
        let chown_err = atomic_install_file_at_destination(
            &src_file,
            &dest_file,
            0o600,
            Some(bogus_uid),
            None,
            "testing non-root mismatched uid rejection",
        )
        .unwrap_err();
        assert!(matches!(chown_err, HostBackupError::Io { .. }));
        assert!(!dest_file.exists());
    }

    let live_db = tmp.path().join("db/aetherflow.sqlite");
    create_sample_wal_database(&live_db);
    let wal_path = tmp.path().join("db/aetherflow.sqlite-wal");
    if wal_path.exists() {
        fs::remove_file(&wal_path).unwrap();
    }
    let target_secret = tmp.path().join("db/secret.txt");
    fs::write(&target_secret, b"secret").unwrap();
    symlink(&target_secret, &wal_path).unwrap();

    let snap_dest = tmp.path().join("out/snap.sqlite");
    let wal_symlink_err = snapshot_sqlite_database(
        &live_db,
        &snap_dest,
        "snap.sqlite",
        &SnapshotOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(
        wal_symlink_err,
        HostBackupError::SymlinkRejected { .. }
    ));
    fs::remove_file(&wal_path).unwrap();
    let _ = fs::Permissions::from_mode(0o600);
}

#[test]
fn provenance_overlap_and_pending_authority_destinations_are_rejected_across_plan_preflight_and_execution(
) {
    let tmp = TempTestDir::new("provenance-overlap-p1-1");
    let host_root = tmp.path().join("host");
    fs::create_dir_all(host_root.join("etc/AetherFlow")).unwrap();

    let mut bad_manifest = BackupManifest::new("4.0.0", "aetherflow-backup.tar.gz").unwrap();
    bad_manifest.entries.push(BackupManifestEntry {
        relative_path: "etc/AetherFlow/.restore-provenance/evil.json".to_string(),
        logical_target_path: None,
        kind: BackupTargetKind::ConfigFile,
        sha256: "a".repeat(64),
        size_bytes: 16,
        unix_mode: Some(0o600),
        unix_uid: None,
        unix_gid: None,
        required: true,
    });
    let bad_err = bad_manifest.validate().unwrap_err();
    assert!(bad_err.is_security_rejection() || bad_err.is_integrity_failure());

    let canonical_err = resolve_trusted_canonical_host_destination(
        Path::new("/"),
        "etc/AetherFlow/.restore-provenance/forged.journal.json",
    )
    .unwrap_err();
    assert!(canonical_err.is_security_rejection());

    let custom_prov = host_root.join("etc/AetherFlow/custom-prov-dir");
    fs::create_dir_all(&custom_prov).unwrap();
    let pending_auth = custom_prov.join(".rollback-restore.pending123.journal.json");
    fs::write(&pending_auth, b"{}").unwrap();

    let mut custom_overlap_manifest =
        BackupManifest::new("4.0.0", "aetherflow-backup.tar.gz").unwrap();
    custom_overlap_manifest.entries.push(BackupManifestEntry {
        relative_path: "etc/AetherFlow/custom-prov-dir/some.conf".to_string(),
        logical_target_path: None,
        kind: BackupTargetKind::ConfigFile,
        sha256: "b".repeat(64),
        size_bytes: 16,
        unix_mode: Some(0o600),
        unix_uid: None,
        unix_gid: None,
        required: true,
    });

    let overlap_err = plan_restore_from_manifest(
        &custom_overlap_manifest,
        &host_root,
        &RestorePreflightOptions {
            host_app_version: "v4.0.0".to_string(),
            max_supported_sqlite_user_version: None,
            overwrite_policy: OverwritePolicy::AllowRegularFilesInStaging,
            require_artifact_sidecar: false,
        },
    )
    .unwrap_err();
    assert!(overlap_err.is_security_rejection());
}

#[test]
fn authenticated_inode_and_digest_verification_blocks_post_stage_replacement() {
    let tmp = TempTestDir::new("inode-digest-binding-p1-2");
    let src_file = tmp.path().join("staged_verified.txt");
    fs::write(&src_file, b"trusted-content-v1").unwrap();
    let (expected_digest, expected_size) = compute_file_sha256(&src_file).unwrap();

    #[cfg(unix)]
    let orig_dev_ino = {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(&src_file).unwrap();
        Some((meta.dev(), meta.ino()))
    };
    #[cfg(not(unix))]
    let orig_dev_ino: Option<(u64, u64)> = None;

    let swapped_tmp = tmp.path().join("swapped.txt");
    fs::write(&swapped_tmp, b"attacker-replaced-content").unwrap();
    fs::rename(&swapped_tmp, &src_file).unwrap();

    let dest_file = tmp.path().join("dest/installed.txt");
    let install_err = atomic_install_file_at_destination_with_verification(
        &src_file,
        orig_dev_ino,
        Some(&expected_digest),
        Some(expected_size),
        &dest_file,
        0o600,
        None,
        None,
        None,
        "verifying post-stage replacement detection",
    )
    .unwrap_err();
    assert!(install_err.is_security_rejection() || install_err.is_integrity_failure());
    assert!(!dest_file.exists());
}

#[test]
fn durable_provenance_commit_never_rolls_back_when_local_journal_fails_and_rejects_rollback_in_progress_commit(
) {
    let tmp = TempTestDir::new("commit-irreversibility-p1-3");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    let conf_path = etc_af.join("cluster.conf");
    fs::write(&conf_path, b"node_role=restored_committed\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-080000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    fs::write(&conf_path, b"node_role=pre_restore_old\n").unwrap();

    let pre_commit_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            fail_provenance_on_commit: true,
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();
    assert!(matches!(
        pre_commit_err,
        HostBackupError::RestoreRolledBack { .. }
    ));
    assert_eq!(
        fs::read_to_string(&conf_path).unwrap(),
        "node_role=pre_restore_old\n"
    );

    let post_prov_commit_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            fail_local_journal_on_commit: true,
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();
    assert!(!matches!(
        post_prov_commit_err,
        HostBackupError::RestoreRolledBack { .. }
    ));
    assert_eq!(
        fs::read_to_string(&conf_path).unwrap(),
        "node_role=restored_committed\n"
    );

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
        "node_role=restored_committed\n"
    );
}

#[test]
fn recovery_stop_failure_does_not_restart_services_on_partially_restored_state() {
    use std::sync::Mutex;

    struct FailingSecondStopQuiescence {
        events: Mutex<Vec<String>>,
    }

    impl ServiceQuiescenceController for FailingSecondStopQuiescence {
        fn stop_services(&self, units: &[String]) -> HostBackupResult<()> {
            let mut guard = self.events.lock().unwrap();
            for unit_name in units {
                guard.push(format!("stop:{}", unit_name));
                if guard.len() >= 2 {
                    return Err(HostBackupError::ServiceQuiescenceFailed {
                        unit: unit_name.clone(),
                        phase: "stop".to_string(),
                        reason: "simulated stop failure during recovery".to_string(),
                    });
                }
            }
            Ok(())
        }

        fn start_and_verify_services(&self, units: &[String]) -> HostBackupResult<()> {
            let mut guard = self.events.lock().unwrap();
            for unit_name in units {
                guard.push(format!("start:{}", unit_name));
            }
            Ok(())
        }
    }

    let tmp = TempTestDir::new("recovery-stop-no-comp-p1-4");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);

    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    fs::write(etc_af.join("cluster.conf"), b"node_role=golden\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-083000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let _ = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["custom-writer.service".to_string()],
            fail_after_replacements: Some(1),
            fail_rollback_after_restores: Some(0),
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();

    let controller = FailingSecondStopQuiescence {
        events: Mutex::new(Vec::new()),
    };
    let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
    let rec_err =
        recover_interrupted_restore_with_context(&cfg.backup_dir, &rec_ctx, &controller)
            .unwrap_err();
    assert!(matches!(
        rec_err,
        HostBackupError::ServiceQuiescenceFailed { .. }
    ));
    let recorded_events = controller.events.lock().unwrap().clone();
    assert!(
        !recorded_events
            .iter()
            .any(|item| item.starts_with("start:")),
        "recovery must not run compensation starts on partially restored state: {:?}",
        recorded_events
    );
}

#[test]
fn sidecar_nofollow_and_redacted_parse_errors_and_cleanup_preserves_provenance_on_removal_failure(
) {
    let tmp = TempTestDir::new("sidecar-redaction-and-cleanup-p1-7-p2-9");
    let secret_err =
        parse_sha256_sidecar_str("super_secret_database_password_token  backup.sqlite")
            .unwrap_err();
    let err_msg = secret_err.to_string();
    assert!(
        !err_msg.contains("super_secret_database_password_token"),
        "sidecar parse error must not echo sensitive token: {}",
        err_msg
    );

    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);
    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    fs::write(etc_af.join("cluster.conf"), b"node_role=golden\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-090000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let cleanup_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            fail_cleanup_remove_rb_dir: true,
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();
    assert!(matches!(cleanup_err, HostBackupError::Io { .. }));

    let prov_dir = resolve_recovery_provenance_dir(&host_root, None);
    assert!(prov_dir.is_dir());
    let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
    let recovered = recover_interrupted_restore_with_context(
        &cfg.backup_dir,
        &rec_ctx,
        &NoopQuiescenceController,
    )
    .unwrap();
    assert_eq!(recovered.len(), 1);
}

#[test]
fn recovery_tolerates_interrupted_sidecar_publication_and_ignores_stale_failure_journal_candidate(
) {
    let tmp = TempTestDir::new("checkpoint-selection-p2-8");
    let host_root = tmp.path().join("host");
    let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&live_db);
    let etc_af = host_root.join("etc/AetherFlow");
    fs::create_dir_all(&etc_af).unwrap();
    let conf_path = etc_af.join("cluster.conf");
    fs::write(&conf_path, b"node_role=golden\n").unwrap();

    let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
    let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-093000")).unwrap();
    let archive_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    fs::write(&conf_path, b"node_role=before_crash\n").unwrap();

    let rb_err = execute_staged_restore(
        &cfg.backup_dir,
        &archive_filename,
        &host_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            fail_after_replacements: Some(1),
            fail_rollback_after_restores: Some(0),
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap_err();

    let (rb_dir, failure_journal_path) = match rb_err {
        HostBackupError::RestoreRollbackFailed {
            recovery_dir,
            failure_journal_path,
            ..
        } => (recovery_dir, failure_journal_path),
        other => panic!("expected RestoreRollbackFailed, got {:?}", other),
    };

    let in_prog_path = rb_dir.join(IN_PROGRESS_RECOVERY_JOURNAL_FILENAME);
    let valid_bytes = fs::read(&failure_journal_path).unwrap();
    fs::write(&in_prog_path, &valid_bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&in_prog_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let in_prog_sidecar = checksum_sidecar_path(&in_prog_path);
    if in_prog_sidecar.exists() {
        fs::remove_file(&in_prog_sidecar).unwrap();
    }

    let mut invalid_gen_journal: RollbackFailureJournal =
        serde_json::from_slice(&valid_bytes).unwrap();
    invalid_gen_journal.generation = 0;
    fs::write(
        &failure_journal_path,
        serde_json::to_vec_pretty(&invalid_gen_journal).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&failure_journal_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    write_sha256_sidecar(&failure_journal_path).unwrap();

    let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
    let recovered = recover_interrupted_restore_with_context(
        &cfg.backup_dir,
        &rec_ctx,
        &NoopQuiescenceController,
    )
    .unwrap();
    assert_eq!(recovered, vec![rb_dir]);
    assert_eq!(
        fs::read_to_string(&conf_path).unwrap(),
        "node_role=before_crash\n"
    );
}

#[test]
fn sqlite_relative_override_parity_across_plan_preflight_and_execution() {
    let tmp = TempTestDir::new("sqlite-rel-override-p2-10");
    let source_root = tmp.path().join("source");
    let source_db = source_root.join("var/lib/aetherflow/aetherflow.sqlite");
    create_sample_wal_database(&source_db);

    let cfg = HostBackupConfig::for_isolated_root(&source_root, "v4.0.0");
    let receipt = create_sqlite_snapshot_backup(&cfg, Some("2026-11-03_10-00-00")).unwrap();
    let sqlite_filename = receipt
        .primary_artifact_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let target_root = tmp.path().join("custom-target-root");
    fs::create_dir_all(&target_root).unwrap();
    let rel_override = "custom-subdir/override.sqlite";

    let pf_opts = RestorePreflightOptions {
        host_app_version: "v4.0.0".to_string(),
        max_supported_sqlite_user_version: Some(50),
        overwrite_policy: OverwritePolicy::RejectExisting,
        require_artifact_sidecar: true,
    };

    let planned = plan_restore_from_manifest_with_sqlite_overrides(
        &receipt.manifest,
        &target_root,
        &pf_opts,
        Some(rel_override),
        None,
    )
    .unwrap();
    let preflighted = preflight_restore_directory_with_sqlite_overrides(
        &cfg.backup_dir,
        &receipt.manifest,
        &target_root,
        &pf_opts,
        Some(rel_override),
        None,
    )
    .unwrap();

    let expected_dest = target_root.join("custom-subdir/override.sqlite");
    assert_eq!(planned.items[0].destination_path, expected_dest);
    assert_eq!(preflighted.items[0].destination_path, expected_dest);

    let report = execute_staged_restore(
        &cfg.backup_dir,
        &sqlite_filename,
        &target_root,
        &RestoreExecutionOptions {
            host_app_version: "v4.0.0".to_string(),
            confirm_destructive_restore: true,
            allow_overwrite: false,
            sqlite_target_rel_path: Some(rel_override.to_string()),
            ..Default::default()
        },
        &NoopQuiescenceController,
    )
    .unwrap();
    assert_eq!(report.restored_files, vec![expected_dest.clone()]);
    assert!(expected_dest.is_file());

    let canonical_planned = plan_restore_from_manifest_with_sqlite_overrides(
        &receipt.manifest,
        Path::new("/"),
        &RestorePreflightOptions {
            host_app_version: "v4.0.0".to_string(),
            max_supported_sqlite_user_version: Some(50),
            overwrite_policy: OverwritePolicy::AllowRegularFilesInStaging,
            require_artifact_sidecar: false,
        },
        Some("var/lib/custom-af-sqlite/aetherflow.sqlite"),
        None,
    )
    .unwrap();
    assert_eq!(
        canonical_planned.items[0].destination_path,
        PathBuf::from("/var/lib/custom-af-sqlite/aetherflow.sqlite")
    );
}

#[cfg(unix)]
#[test]
fn maintenance_lock_preserves_existing_parent_mode_and_configured_custom_sqlite_uid_succeeds_end_to_end(
) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let tmp = TempTestDir::new("lock-parent-and-custom-uid-p1-5-p2-11-p2-12");
    let existing_parent = tmp.path().join("existing-parent");
    fs::create_dir_all(&existing_parent).unwrap();
    fs::set_permissions(&existing_parent, fs::Permissions::from_mode(0o750)).unwrap();
    let before_meta = fs::symlink_metadata(&existing_parent).unwrap();

    let lock_file = existing_parent.join(".maintenance.lock");
    let guard =
        HostMaintenanceLockGuard::acquire(&lock_file, Duration::from_millis(100)).unwrap();
    let after_meta = fs::symlink_metadata(&existing_parent).unwrap();
    assert_eq!(before_meta.uid(), after_meta.uid());
    assert_eq!(before_meta.gid(), after_meta.gid());
    assert_eq!(after_meta.permissions().mode() & 0o777, 0o750);
    drop(guard);

    let root_a = Path::new("/tmp/stage-x/var/lib/aetherflow/backups");
    let root_b = Path::new("/tmp/stage-x/var/lib/aetherflow/restore-staging");
    let root_c = Path::new("/tmp/stage-x/etc/AetherFlow");
    let resolved_a = resolve_maintenance_lock_path(Some(root_a));
    let resolved_b = resolve_maintenance_lock_path(Some(root_b));
    let resolved_c = resolve_maintenance_lock_path(Some(root_c));
    assert_eq!(resolved_a, resolved_b);
    assert_eq!(resolved_b, resolved_c);

    if unsafe { libc::geteuid() } == 0 {
        let custom_uid: u32 = 65534;
        let custom_gid: u32 = 65534;
        let host_root = tmp.path().join("host-custom-uid");
        let etc_af = host_root.join("etc/AetherFlow");
        fs::create_dir_all(&etc_af).unwrap();
        fs::write(etc_af.join("cluster.conf"), b"node_role=custom_uid\n").unwrap();

        let custom_db_dir = host_root.join("var/lib/custom-sqlite");
        fs::create_dir_all(&custom_db_dir).unwrap();
        fs::set_permissions(&custom_db_dir, fs::Permissions::from_mode(0o750)).unwrap();
        let custom_db = custom_db_dir.join("aetherflow.sqlite");
        create_sample_wal_database(&custom_db);
        fs::set_permissions(&custom_db, fs::Permissions::from_mode(0o640)).unwrap();

        let c_dir = std::ffi::CString::new(custom_db_dir.to_str().unwrap()).unwrap();
        let c_db = std::ffi::CString::new(custom_db.to_str().unwrap()).unwrap();
        assert_eq!(
            unsafe { libc::chown(c_dir.as_ptr(), custom_uid, custom_gid) },
            0
        );
        assert_eq!(
            unsafe { libc::chown(c_db.as_ptr(), custom_uid, custom_gid) },
            0
        );
        for suffix in ["-wal", "-shm"] {
            let side_path = PathBuf::from(format!("{}{}", custom_db.display(), suffix));
            if side_path.exists() {
                fs::set_permissions(&side_path, fs::Permissions::from_mode(0o640)).unwrap();
                let c_side = std::ffi::CString::new(side_path.to_str().unwrap()).unwrap();
                assert_eq!(
                    unsafe { libc::chown(c_side.as_ptr(), custom_uid, custom_gid) },
                    0
                );
            }
        }

        let mut untrusted_cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
        untrusted_cfg.sqlite_db_path = Some(custom_db.clone());
        let untrusted_err =
            create_sqlite_snapshot_backup(&untrusted_cfg, Some("2026-11-03_11-00-00"))
                .unwrap_err();
        assert!(untrusted_err.is_security_rejection());

        let mut trusted_cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
        trusted_cfg.sqlite_db_path = Some(custom_db.clone());
        trusted_cfg.snapshot_options.trusted_source_uid = Some(custom_uid);

        let sqlite_receipt =
            create_sqlite_snapshot_backup(&trusted_cfg, Some("2026-11-03_11-05-00")).unwrap();
        let archive_receipt =
            create_host_archive_backup(&trusted_cfg, Some("2026-11-03-110500")).unwrap();
        let archive_filename = archive_receipt
            .primary_artifact_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let (ver, _) = verify_backup_artifact_with_trusted_uid(
            &trusted_cfg.backup_dir,
            &archive_filename,
            Some(custom_uid),
        )
        .unwrap();
        assert!(ver.verified);

        let report = execute_staged_restore(
            &trusted_cfg.backup_dir,
            &archive_filename,
            &host_root,
            &RestoreExecutionOptions {
                host_app_version: "v4.0.0".to_string(),
                confirm_destructive_restore: true,
                allow_overwrite: true,
                trusted_sqlite_db_path: Some(custom_db.clone()),
                trusted_sqlite_uid: Some(custom_uid),
                trusted_sqlite_gid: Some(custom_gid),
                ..Default::default()
            },
            &NoopQuiescenceController,
        )
        .unwrap();
        assert!(report.sqlite_restored);
        let restored_meta = fs::symlink_metadata(&custom_db).unwrap();
        assert_eq!(restored_meta.uid(), custom_uid);
        assert_eq!(restored_meta.gid(), custom_gid);
        let _ = sqlite_receipt;
    }
}
