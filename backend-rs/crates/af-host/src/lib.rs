//! `af-host`: Bounded shared Rust host backup, consistent SQLite snapshot, SHA-256 verification,
//! versioned manifest, and non-destructive restore preflight foundation for AetherFlow.
//!
//! # Core Responsibilities
//! 1. **Typed Versioned Manifest (`manifest`)**: [`BackupManifest`] (`af-host.backup-manifest.v1`)
//!    with per-entry SHA-256 digests, byte sizes, target classifications, SQLite snapshot provenance,
//!    and schema/application version compatibility checks ([`BackupManifest::check_compatibility`]).
//! 2. **Safe SQLite Consistent Snapshot (`snapshot`)**: [`snapshot_sqlite_database`] and
//!    [`snapshot_sqlite_with_conn`] using `VACUUM INTO` or SQLite's Online Backup API
//!    (`rusqlite::backup::Backup`) plus `PRAGMA quick_check` verification — never plain-copying
//!    a live database file.
//! 3. **SHA-256 File Verification & Chunking (`verify`)**: [`compute_file_sha256`],
//!    [`write_sha256_sidecar`], [`verify_file_sha256`], [`verify_file_with_sidecar`],
//!    [`split_backup_into_chunks`], and [`assemble_verified_chunks`] compatible with both GNU
//!    `sha256sum` (`packages/system/af-backup`) and bare-hex sidecars (`af-api` / `af-services`).
//! 4. **Non-Destructive Restore Planning & Preflight (`restore`)**: [`plan_restore_from_manifest`],
//!    [`preflight_restore_directory`], and [`preflight_tar_gz_archive`] rejecting parent traversal
//!    (`..`), rooted/prefixed paths, symbolic/hard links, and unsafe overwrites. Actual destructive
//!    live restore execution ([`execute_destructive_restore`]) fails closed with
//!    [`HostBackupError::DestructiveRestoreUnsupported`].
//! 5. **Backup Bundle Orchestration & Maintenance Ownership (`backup`)**:
//!    [`create_sqlite_snapshot_backup`], [`create_host_archive_backup`], [`list_backup_inventory`],
//!    [`verify_backup_artifact`], [`delete_backup_artifacts`], [`prune_backup_inventory`], and
//!    [`maintenance_helper_ownership_registry`].

pub mod backup;
pub mod error;
pub mod maintenance;
pub mod manifest;
pub mod restore;
pub mod snapshot;
pub mod verify;

pub use backup::{
    create_host_archive_backup, create_sqlite_snapshot_backup, default_host_targets_for_root,
    delete_backup_artifacts, list_backup_inventory, maintenance_helper_ownership_registry,
    prune_backup_inventory, verify_backup_artifact, verify_backup_artifact_with_trusted_uid,
    BackupInventoryItem, HostBackupConfig, HostBackupReceipt, HostBackupTargetSpec,
    MaintenanceHelperOwnership, MaintenanceOwnerCrate, DEFAULT_MAX_RETAINED_BACKUPS,
    DEFAULT_RETENTION_DAYS,
};
pub use error::{HostBackupError, HostBackupResult};
pub use maintenance::{
    apply_network_tuning, clean_system_logs, compute_sysctl_network_tuning,
    format_human_space_bytes, inspect_home_disk_space, sentinel_scan_auth_log, CleanLogReport,
    CleanedLogFile, HomeSpaceEntry, SentinelScanReport, TuningReport, DEFAULT_SENTINEL_THRESHOLD,
};
pub use manifest::{
    parse_semver_triplet, BackupManifest, BackupManifestEntry, BackupTargetKind,
    CompatibilityReport, SqliteSnapshotMetadata, BACKUP_MANIFEST_FORMAT,
    CURRENT_MANIFEST_SCHEMA_VERSION, MAX_SUPPORTED_MANIFEST_SCHEMA_VERSION,
    MIN_SUPPORTED_MANIFEST_SCHEMA_VERSION, SUPPORTED_APP_MAJOR_VERSION,
};
pub use restore::{
    execute_coordinated_restore, RestoreReceipt,
    execute_destructive_restore, execute_staged_restore, plan_restore_from_manifest,
    plan_restore_from_manifest_with_sqlite_override,
    plan_restore_from_manifest_with_sqlite_overrides, preflight_restore_directory,
    preflight_restore_directory_with_sqlite_override,
    preflight_restore_directory_with_sqlite_overrides,
    preflight_restore_directory_with_sqlite_overrides_and_trusted_uid, preflight_tar_gz_archive,
    preflight_tar_gz_archive_with_sqlite_override, preflight_tar_gz_archive_with_sqlite_overrides,
    preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid, recover_interrupted_restore,
    recover_interrupted_restore_with_context, resolve_effective_quiesce_services,
    resolve_recovery_provenance_dir, resolve_trusted_canonical_host_destination,
    resolve_trusted_canonical_host_destination_with_sqlite_override,
    validate_quiesce_service_entries, validate_trusted_sqlite_db_path, CommandQuiescenceController,
    NoopQuiescenceController, OverwritePolicy, PlannedRestoreAction, RecoveryContext,
    RestoreExecutionOptions, RestoreExecutionReport, RestorePlan, RestorePlanItem,
    RestorePreflightOptions, RollbackFailureJournal, RollbackFailureJournalEntry,
    ServiceQuiescenceController, DEFAULT_MANDATORY_QUIESCE_SERVICES,
    IN_PROGRESS_RECOVERY_JOURNAL_FILENAME,
};
pub use snapshot::{
    snapshot_sqlite_database, snapshot_sqlite_with_conn, verify_sqlite_snapshot_integrity,
    verify_sqlite_snapshot_integrity_with_trusted_uid, SnapshotMethod, SnapshotOptions,
    SqliteSnapshotReceipt,
};
pub use verify::{
    assemble_verified_chunks, atomic_install_file_at_destination,
    atomic_install_file_at_destination_with_trusted_ancestor_uid,
    atomic_install_file_at_destination_with_verification, checksum_sidecar_path,
    compute_file_sha256, open_existing_regular_file_nofollow, open_or_create_dir_nofollow,
    open_or_create_dir_nofollow_with_trusted_uid, open_or_create_provenance_dir_nofollow,
    open_verified_regular_file_for_read, parse_sha256_sidecar_str,
    read_verified_text_file_nofollow, reject_if_symlink, reject_symlink_chain,
    resolve_maintenance_lock_path, resolve_trusted_service_account_ids, safe_backup_file_path,
    split_backup_into_chunks, sync_parent_directory, unlink_file_at_destination,
    unlink_file_at_destination_with_trusted_ancestor_uid, validate_backup_filename,
    validate_no_parent_traversal, validate_relative_backup_path, verify_file_sha256,
    verify_file_sha256_with_trusted_uid, verify_file_with_sidecar,
    verify_file_with_sidecar_and_trusted_uid, write_sha256_sidecar, ChecksumVerification,
    HostMaintenanceLockGuard, DEFAULT_MAINTENANCE_LOCK_PATH,
};

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use rusqlite::Connection;
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    /// RAII temporary directory guard under `std::env::temp_dir()` for isolated unit tests.
    struct TempTestDir {
        path: PathBuf,
    }

    impl TempTestDir {
        fn new(prefix: &str) -> Self {
            let unique = format!(
                "af-host-test-{}-{}-{}",
                prefix,
                std::process::id(),
                uuid::Uuid::new_v4()
            );
            let path = std::env::temp_dir().join(unique);
            fs::create_dir_all(&path).expect("create isolated temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn create_sample_wal_database(db_path: &Path) {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let conn = Connection::open(db_path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA user_version = 42;
             CREATE TABLE settings (id INTEGER PRIMARY KEY, base_domain TEXT NOT NULL);
             INSERT INTO settings (id, base_domain) VALUES (1, 'seedbox.example.test');
             CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL);
             INSERT INTO users (id, username) VALUES (1, 'admin'), (2, 'operator');",
        )
        .unwrap();
    }

    #[test]
    fn sqlite_snapshot_vacuum_into_and_online_backup_produce_verified_snapshots() {
        let tmp = TempTestDir::new("sqlite-snap");
        let live_db = tmp.path().join("live/aetherflow.sqlite");
        create_sample_wal_database(&live_db);

        // Keep an active connection with uncommitted/committed state to simulate live WAL operation
        let writer_conn = Connection::open(&live_db).unwrap();
        writer_conn
            .execute("INSERT INTO users (id, username) VALUES (3, 'alice')", [])
            .unwrap();

        // 1. Test VACUUM INTO snapshot
        let snap_vacuum = tmp.path().join("backups/aetherflow_vacuum.sqlite");
        let receipt_vac = snapshot_sqlite_database(
            &live_db,
            &snap_vacuum,
            "aetherflow_vacuum.sqlite",
            &SnapshotOptions {
                method: SnapshotMethod::VacuumInto,
                busy_timeout: Duration::from_secs(5),
                ..Default::default()
            },
        )
        .expect("VACUUM INTO snapshot should succeed");

        assert!(receipt_vac.snapshot_path.is_file());
        assert!(receipt_vac.sidecar_path.is_file());
        assert_eq!(receipt_vac.metadata.capture_method, "vacuum_into");
        assert_eq!(receipt_vac.metadata.sqlite_user_version, 42);
        assert_eq!(receipt_vac.metadata.integrity_check.to_lowercase(), "ok");

        // Verify the snapshot has all 3 rows and passes sidecar verification
        let check_vac = verify_file_with_sidecar(&snap_vacuum).unwrap();
        assert!(check_vac.verified);
        let ro_conn = Connection::open(&snap_vacuum).unwrap();
        let count: i64 = ro_conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 3);
        drop(ro_conn);

        // 2. Test Online Backup API snapshot
        let snap_online = tmp.path().join("backups/aetherflow_online.sqlite");
        let receipt_online = snapshot_sqlite_database(
            &live_db,
            &snap_online,
            "aetherflow_online.sqlite",
            &SnapshotOptions {
                method: SnapshotMethod::OnlineBackupApi,
                busy_timeout: Duration::from_secs(5),
                pages_per_step: 64,
                step_pause: Duration::from_millis(1),
                trusted_source_uid: None,
            },
        )
        .expect("Online Backup API snapshot should succeed");

        assert_eq!(receipt_online.metadata.capture_method, "online_backup_api");
        assert_eq!(receipt_online.metadata.sqlite_user_version, 42);
        verify_file_with_sidecar(&snap_online).unwrap();
    }

    #[test]
    fn sha256_sidecar_verification_detects_tampering_and_supports_gnu_and_bare_formats() {
        let tmp = TempTestDir::new("sha256");
        let artifact = tmp.path().join("aetherflow_2026-10-31.sqlite");
        fs::write(&artifact, b"consistent-sqlite-snapshot-bytes").unwrap();

        let (sidecar, digest, size) = write_sha256_sidecar(&artifact).unwrap();
        assert_eq!(size, 32);
        assert!(sidecar.is_file());

        // Verify GNU coreutils format (`<hex>  <filename>`)
        let verified = verify_file_with_sidecar(&artifact).unwrap();
        assert_eq!(verified.expected_sha256, digest);
        assert_eq!(verified.actual_sha256, digest);

        // Verify bare `<hex>\n` format emitted by af-api / af-services
        fs::write(&sidecar, format!("{}\n", digest.to_uppercase())).unwrap();
        let verified_bare = verify_file_with_sidecar(&artifact).unwrap();
        assert_eq!(verified_bare.actual_sha256, digest);

        // Tamper with the artifact payload and ensure verification fails with ChecksumMismatch
        fs::write(&artifact, b"tampered-sqlite-snapshot-bytes!!").unwrap();
        let err = verify_file_with_sidecar(&artifact).unwrap_err();
        assert!(err.is_integrity_failure());
        assert!(matches!(err, HostBackupError::ChecksumMismatch { .. }));
    }

    #[test]
    fn chunk_split_and_reassembly_verifies_sha256() {
        let tmp = TempTestDir::new("chunks");
        let src_file = tmp.path().join("aetherflow-backup-test.tar.gz");
        let payload: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        fs::write(&src_file, &payload).unwrap();

        let (_, expected_sha, _) = write_sha256_sidecar(&src_file).unwrap();
        let chunks = split_backup_into_chunks(&src_file, 3000).unwrap();
        assert_eq!(chunks.len(), 4);

        let reassembled = tmp.path().join("reassembled.tar.gz");
        let check = assemble_verified_chunks(&chunks, &reassembled, &expected_sha).unwrap();
        assert!(check.verified);
        assert_eq!(fs::read(&reassembled).unwrap(), payload);

        // Wrong expected checksum must reject and remove temporary file
        let bad_sha = "0000000000000000000000000000000000000000000000000000000000000000";
        let bad_out = tmp.path().join("bad-reassembled.tar.gz");
        let err = assemble_verified_chunks(&chunks, &bad_out, bad_sha).unwrap_err();
        assert!(matches!(err, HostBackupError::ChecksumMismatch { .. }));
        assert!(!bad_out.exists());
    }

    #[test]
    fn manifest_compatibility_checks_schema_semver_and_sqlite_user_version() {
        let mut manifest = BackupManifest::new("v4.0.0", "aetherflow_2026-10-31.sqlite").unwrap();
        manifest.entries.push(BackupManifestEntry {
            relative_path: "aetherflow_2026-10-31.sqlite".to_string(),
            logical_target_path: Some("/var/lib/aetherflow/aetherflow.sqlite".to_string()),
            kind: BackupTargetKind::SqliteSnapshot,
            sha256: "a".repeat(64),
            size_bytes: 4096,
            unix_mode: Some(0o600),
            unix_uid: None,
            unix_gid: None,
            required: true,
        });
        manifest.sqlite_snapshot = Some(SqliteSnapshotMetadata {
            snapshot_relative_path: "aetherflow_2026-10-31.sqlite".to_string(),
            capture_method: "vacuum_into".to_string(),
            sqlite_user_version: 12,
            journal_mode: "delete".to_string(),
            integrity_check: "ok".to_string(),
            size_bytes: 4096,
            sha256: "a".repeat(64),
        });

        // Compatible with same or newer v4.x host
        let report = manifest.check_compatibility("v4.1.0", Some(15)).unwrap();
        assert!(report.compatible);
        assert!(report.has_sqlite_snapshot);

        // Incompatible major version (v3.x or v5.x)
        let err_major = manifest.check_compatibility("v5.0.0", None).unwrap_err();
        assert!(matches!(
            err_major,
            HostBackupError::IncompatibleVersion { .. }
        ));

        // Incompatible downgrade (backup from 4.2.0 onto 4.0.0 host)
        manifest.app_version = "4.2.0".to_string();
        let err_downgrade = manifest.check_compatibility("4.0.0", None).unwrap_err();
        assert!(matches!(
            err_downgrade,
            HostBackupError::IncompatibleVersion { .. }
        ));
        manifest.app_version = "4.0.0".to_string();

        // Incompatible SQLite user_version (backup has v12, host supports up to v10)
        let err_uv = manifest.check_compatibility("4.0.0", Some(10)).unwrap_err();
        assert!(matches!(
            err_uv,
            HostBackupError::IncompatibleVersion { .. }
        ));

        // Unsupported manifest schema version (v99)
        manifest.schema_version = 99;
        let err_schema = manifest.check_compatibility("4.0.0", None).unwrap_err();
        assert!(matches!(
            err_schema,
            HostBackupError::IncompatibleManifest { found: 99, .. }
        ));
    }

    #[test]
    fn restore_planning_rejects_traversal_rooted_paths_and_unsafe_overwrite() {
        let tmp = TempTestDir::new("restore-plan");
        let target_root = tmp.path().join("restore-stage");
        fs::create_dir_all(&target_root).unwrap();

        // 1. Relative path validation rejects traversal, leading slash, backslash, and drive letters
        for bad_path in [
            "../etc/passwd",
            "etc/../../shadow",
            "/etc/AetherFlow/config",
            "\\etc\\AetherFlow\\config",
            "C:\\Windows\\System32",
            "./etc/config",
            "etc/./config",
            "",
        ] {
            let err = validate_relative_backup_path(bad_path).unwrap_err();
            assert!(
                err.is_security_rejection(),
                "expected security rejection for {:?}",
                bad_path
            );
        }

        // 2. Build a valid manifest and verify non-destructive planning on an empty staging dir
        let mut manifest = BackupManifest::new("4.0.0", "aetherflow-backup.tar.gz").unwrap();
        manifest.entries.push(BackupManifestEntry {
            relative_path: "etc/AetherFlow/aetherflow.env".to_string(),
            logical_target_path: Some("/etc/aetherflow/aetherflow.env".to_string()),
            kind: BackupTargetKind::ConfigFile,
            sha256: "b".repeat(64),
            size_bytes: 128,
            unix_mode: Some(0o600),
            unix_uid: None,
            unix_gid: None,
            required: true,
        });

        let opts = RestorePreflightOptions::default();
        let plan = plan_restore_from_manifest(&manifest, &target_root, &opts).unwrap();
        assert!(plan.non_destructive_only);
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].action, PlannedRestoreAction::CreateNew);
        // Ensure target_root was not mutated
        assert!(!target_root.join("etc/AetherFlow/aetherflow.env").exists());

        // 3. Create an existing file at the destination and verify OverwritePolicy::RejectExisting fails closed
        let existing_dest = target_root.join("etc/AetherFlow/aetherflow.env");
        fs::create_dir_all(existing_dest.parent().unwrap()).unwrap();
        fs::write(&existing_dest, b"existing-live-config").unwrap();

        let overwrite_err = plan_restore_from_manifest(&manifest, &target_root, &opts).unwrap_err();
        assert!(matches!(
            overwrite_err,
            HostBackupError::UnsafeOverwriteRejected { .. }
        ));

        // 4. Verify AllowRegularFilesInStaging permits planning replacement in staging without mutating disk
        let staging_opts = RestorePreflightOptions {
            overwrite_policy: OverwritePolicy::AllowRegularFilesInStaging,
            ..Default::default()
        };
        let staging_plan =
            plan_restore_from_manifest(&manifest, &target_root, &staging_opts).unwrap();
        assert_eq!(
            staging_plan.items[0].action,
            PlannedRestoreAction::ReplaceExistingRegularFile
        );
        assert_eq!(
            fs::read(&existing_dest).unwrap(),
            b"existing-live-config",
            "planning must never modify existing files"
        );

        // 5. Verify execute_destructive_restore is explicitly unsupported
        let exec_err = execute_destructive_restore(&staging_plan).unwrap_err();
        assert!(matches!(
            exec_err,
            HostBackupError::DestructiveRestoreUnsupported { .. }
        ));
    }

    #[test]
    fn tar_gz_preflight_rejects_symlinks_and_traversal_entries() {
        let tmp = TempTestDir::new("tar-security");
        let target_root = tmp.path().join("stage-out");
        fs::create_dir_all(&target_root).unwrap();

        let mut manifest = BackupManifest::new("4.0.0", "malicious.tar.gz").unwrap();
        manifest.entries.push(BackupManifestEntry {
            relative_path: "etc/AetherFlow/safe.conf".to_string(),
            logical_target_path: None,
            kind: BackupTargetKind::ConfigFile,
            sha256: "c".repeat(64),
            size_bytes: 4,
            unix_mode: None,
            unix_uid: None,
            unix_gid: None,
            required: true,
        });

        // Build a tar.gz containing a symlink entry
        let symlink_tar_path = tmp.path().join("malicious.tar.gz");
        {
            let f = File::create(&symlink_tar_path).unwrap();
            let gz = GzEncoder::new(f, Compression::fast());
            let mut builder = tar::Builder::new(gz);

            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            builder
                .append_link(&mut header, "etc/AetherFlow/evil_link", "/etc/shadow")
                .unwrap();
            let gz = builder.into_inner().unwrap();
            gz.finish().unwrap();
        }
        write_sha256_sidecar(&symlink_tar_path).unwrap();

        let err = preflight_tar_gz_archive(
            &symlink_tar_path,
            &manifest,
            &target_root,
            &RestorePreflightOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, HostBackupError::SymlinkRejected { .. }));
    }

    #[test]
    fn end_to_end_host_archive_backup_and_non_destructive_preflight_in_isolated_temp_dir() {
        let tmp = TempTestDir::new("e2e-bundle");
        let host_root = tmp.path().join("host");
        let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
        create_sample_wal_database(&live_db);

        // Populate mock host configuration files matching packages/system/af-backup TARGETS
        let etc_af = host_root.join("etc/AetherFlow");
        fs::create_dir_all(&etc_af).unwrap();
        fs::write(etc_af.join("cluster.conf"), b"node_role=primary\n").unwrap();

        let etc_env = host_root.join("etc/aetherflow");
        fs::create_dir_all(&etc_env).unwrap();
        fs::write(
            etc_env.join("aetherflow.env"),
            b"DB_PATH=/var/lib/aetherflow/aetherflow.sqlite\n",
        )
        .unwrap();

        let owner_home = host_root.join("home/aetherflow");
        fs::create_dir_all(&owner_home).unwrap();
        fs::write(
            owner_home.join(".rtorrent.rc"),
            b"max_memory_usage = 1073741824\n",
        )
        .unwrap();

        let mut cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
        cfg.chunk_size_bytes = Some(512);

        let receipt =
            create_host_archive_backup(&cfg, Some("2026-10-31-120000")).expect("create archive");
        assert!(receipt.primary_artifact_path.is_file());
        assert!(receipt.primary_sidecar_path.is_file());
        assert!(receipt.manifest_path.is_file());
        assert!(receipt.manifest_sidecar_path.is_file());
        assert!(!receipt.chunk_paths.is_empty());
        assert!(receipt.manifest.sqlite_snapshot.is_some());

        // Verify inventory listing and artifact verification
        let inv = list_backup_inventory(&cfg.backup_dir).unwrap();
        assert_eq!(inv.len(), 1);
        assert!(inv[0].checksum_present);
        assert!(inv[0].manifest_present);
        assert_eq!(inv[0].chunk_count, receipt.chunk_paths.len());

        let (ver, loaded_manifest) =
            verify_backup_artifact(&cfg.backup_dir, &inv[0].filename).unwrap();
        assert!(ver.verified);
        let loaded_manifest = loaded_manifest.expect("manifest loaded");

        // Run non-destructive restore preflight on the tar.gz archive into a clean staging target
        let restore_stage = tmp.path().join("restore-preflight-target");
        let plan = preflight_tar_gz_archive(
            &receipt.primary_artifact_path,
            &loaded_manifest,
            &restore_stage,
            &RestorePreflightOptions {
                host_app_version: "v4.0.0".to_string(),
                max_supported_sqlite_user_version: Some(50),
                overwrite_policy: OverwritePolicy::RejectExisting,
                require_artifact_sidecar: true,
            },
        )
        .expect("non-destructive archive preflight should succeed");

        assert!(plan.non_destructive_only);
        assert!(!plan.sqlite_integrity_verified);
        assert_eq!(plan.items.len(), 4); // sqlite snapshot + cluster.conf + aetherflow.env + .rtorrent.rc
        assert!(
            !restore_stage.exists(),
            "preflight must not write to target_root"
        );

        // Delete backup artifacts and verify clean removal
        let removed = delete_backup_artifacts(&cfg.backup_dir, &inv[0].filename).unwrap();
        assert!(removed.len() >= 4);
        assert!(list_backup_inventory(&cfg.backup_dir).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_symlinks_rejected_for_backup_dir_source_db_target_root_and_staged_paths() {
        use std::os::unix::fs::symlink;

        let tmp = TempTestDir::new("ancestor-symlinks");
        let real_dir = tmp.path().join("real");
        fs::create_dir_all(real_dir.join("sub")).unwrap();

        let live_db = real_dir.join("sub/aetherflow.sqlite");
        create_sample_wal_database(&live_db);

        let symlinked_parent = tmp.path().join("linked-parent");
        symlink(&real_dir, &symlinked_parent).unwrap();

        // 1. Source DB accessed through an ancestor symlink must be rejected
        let db_via_symlink_ancestor = symlinked_parent.join("sub/aetherflow.sqlite");
        let safe_dest = tmp.path().join("safe-backups/snap.sqlite");
        let err_src = snapshot_sqlite_database(
            &db_via_symlink_ancestor,
            &safe_dest,
            "snap.sqlite",
            &SnapshotOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err_src, HostBackupError::SymlinkRejected { .. }));

        // 2. backup_dir under an ancestor symlink must be rejected before creating directories/files
        let backup_via_symlink_ancestor = symlinked_parent.join("backups/nested");
        let err_dest = snapshot_sqlite_database(
            &live_db,
            &backup_via_symlink_ancestor.join("snap.sqlite"),
            "snap.sqlite",
            &SnapshotOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err_dest, HostBackupError::SymlinkRejected { .. }));

        // 3. target_root under an ancestor symlink must be rejected by restore planning
        let mut manifest = BackupManifest::new("4.0.0", "aetherflow-backup.tar.gz").unwrap();
        manifest.entries.push(BackupManifestEntry {
            relative_path: "etc/AetherFlow/cluster.conf".to_string(),
            logical_target_path: None,
            kind: BackupTargetKind::ConfigFile,
            sha256: "d".repeat(64),
            size_bytes: 16,
            unix_mode: Some(0o600),
            unix_uid: None,
            unix_gid: None,
            required: true,
        });

        let target_via_symlink_ancestor = symlinked_parent.join("restore-stage/inner");
        let err_target = plan_restore_from_manifest(
            &manifest,
            &target_via_symlink_ancestor,
            &RestorePreflightOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err_target,
            HostBackupError::SymlinkRejected { .. }
        ));

        // 4. reject_symlink_chain must reject when `root` itself has an ancestor symlink
        let err_chain = reject_symlink_chain(
            &symlinked_parent.join("sub"),
            &symlinked_parent.join("sub/aetherflow.sqlite"),
        )
        .unwrap_err();
        assert!(matches!(err_chain, HostBackupError::SymlinkRejected { .. }));
    }

    #[test]
    fn restore_target_root_rejects_system_root_bypasses_and_relative_paths() {
        let mut manifest = BackupManifest::new("4.0.0", "aetherflow-backup.tar.gz").unwrap();
        manifest.entries.push(BackupManifestEntry {
            relative_path: "etc/AetherFlow/cluster.conf".to_string(),
            logical_target_path: None,
            kind: BackupTargetKind::ConfigFile,
            sha256: "e".repeat(64),
            size_bytes: 16,
            unix_mode: Some(0o600),
            unix_uid: None,
            unix_gid: None,
            required: true,
        });
        let opts = RestorePreflightOptions {
            overwrite_policy: OverwritePolicy::AllowRegularFilesInStaging,
            ..Default::default()
        };

        let canonical_plan = plan_restore_from_manifest(&manifest, Path::new("/"), &opts).expect(
            "canonical '/' target_root should be accepted for allowlisted AetherFlow paths",
        );
        assert_eq!(
            canonical_plan.items[0].destination_path,
            PathBuf::from("/etc/AetherFlow/cluster.conf")
        );

        let mut unallowlisted_manifest =
            BackupManifest::new("4.0.0", "aetherflow-backup.tar.gz").unwrap();
        unallowlisted_manifest.entries.push(BackupManifestEntry {
            relative_path: "etc/passwd".to_string(),
            logical_target_path: None,
            kind: BackupTargetKind::ConfigFile,
            sha256: "e".repeat(64),
            size_bytes: 16,
            unix_mode: Some(0o600),
            unix_uid: None,
            unix_gid: None,
            required: true,
        });
        let unallowlisted_err =
            plan_restore_from_manifest(&unallowlisted_manifest, Path::new("/"), &opts).unwrap_err();
        assert!(unallowlisted_err.is_security_rejection());

        let direct_root_err = validate_trusted_sqlite_db_path(Path::new("/")).unwrap_err();
        assert!(direct_root_err.is_security_rejection());

        for forbidden_root in [
            "//",
            "/etc",
            "//etc",
            "/etc/",
            "//etc//",
            "/etc/AetherFlow",
            "/./etc",
            "/etc/.",
            "/var/tmp/../etc",
            "/var",
            "/var/lib",
            "/var/www",
            "/usr",
            "/usr/local",
            "/proc/self",
            "/sys/fs",
            "/dev/shm",
            "/tmp",
            "/opt",
            "etc",
            "./etc",
            ".",
            "..",
            "relative/staging/root",
        ] {
            let res = plan_restore_from_manifest(&manifest, Path::new(forbidden_root), &opts);
            let err = res.expect_err(&format!(
                "expected target_root {:?} to be rejected",
                forbidden_root
            ));
            assert!(
                err.is_security_rejection(),
                "expected security rejection for target_root {:?}, got {:?}",
                forbidden_root,
                err
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn backup_dirs_snapshots_archives_manifests_sidecars_and_chunks_enforce_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempTestDir::new("perms");
        let host_root = tmp.path().join("host");
        let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
        create_sample_wal_database(&live_db);

        let etc_af = host_root.join("etc/AetherFlow");
        fs::create_dir_all(&etc_af).unwrap();
        fs::write(etc_af.join("cluster.conf"), b"cluster_mode=xyz\n").unwrap();

        let mut cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
        cfg.chunk_size_bytes = Some(256);

        // 1. Archive backup bundle permissions
        let archive_receipt = create_host_archive_backup(&cfg, Some("2026-10-31-130000")).unwrap();
        let dir_mode = fs::symlink_metadata(&cfg.backup_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "backup_dir must be 0700");

        for secret_file in [
            &archive_receipt.primary_artifact_path,
            &archive_receipt.primary_sidecar_path,
            &archive_receipt.manifest_path,
            &archive_receipt.manifest_sidecar_path,
        ] {
            let mode = fs::symlink_metadata(secret_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode,
                0o600,
                "expected 0600 permissions on {}",
                secret_file.display()
            );
        }
        for chunk in &archive_receipt.chunk_paths {
            let mode = fs::symlink_metadata(chunk).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o600,
                "expected 0600 permissions on chunk {}",
                chunk.display()
            );
        }

        // 2. Standalone SQLite snapshot permissions (both VacuumInto and OnlineBackupApi)
        for (slug, method) in [
            ("vac", SnapshotMethod::VacuumInto),
            ("online", SnapshotMethod::OnlineBackupApi),
        ] {
            let mut snap_cfg = cfg.clone();
            snap_cfg.snapshot_options.method = method;
            let snap_receipt = create_sqlite_snapshot_backup(&snap_cfg, Some(slug)).unwrap();
            let snap_mode = fs::symlink_metadata(&snap_receipt.primary_artifact_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                snap_mode, 0o600,
                "expected 0600 on SQLite snapshot ({})",
                slug
            );
        }
    }

    #[test]
    fn manifest_validate_and_verify_backup_artifact_detect_metadata_archive_and_chunk_tampering() {
        let tmp = TempTestDir::new("manifest-verify");
        let host_root = tmp.path().join("host");
        let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
        create_sample_wal_database(&live_db);

        let etc_af = host_root.join("etc/AetherFlow");
        fs::create_dir_all(&etc_af).unwrap();
        fs::write(etc_af.join("cluster.conf"), b"node_role=primary\n").unwrap();

        let mut cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
        cfg.chunk_size_bytes = Some(512);

        let receipt = create_host_archive_backup(&cfg, Some("2026-10-31-140000")).unwrap();
        let archive_filename = receipt
            .primary_artifact_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // 1.BackupManifest::validate must reject sqlite_snapshot mismatch against entries
        let mut bad_manifest = receipt.manifest.clone();
        bad_manifest.sqlite_snapshot.as_mut().unwrap().sha256 = "f".repeat(64);
        assert!(matches!(
            bad_manifest.validate().unwrap_err(),
            HostBackupError::ChecksumMismatch { .. }
        ));

        let mut bad_size_manifest = receipt.manifest.clone();
        bad_size_manifest
            .sqlite_snapshot
            .as_mut()
            .unwrap()
            .size_bytes += 10;
        assert!(matches!(
            bad_size_manifest.validate().unwrap_err(),
            HostBackupError::InvalidManifest(_)
        ));

        let mut bad_kind_manifest = receipt.manifest.clone();
        for entry in &mut bad_kind_manifest.entries {
            if entry.kind == BackupTargetKind::SqliteSnapshot {
                entry.kind = BackupTargetKind::ConfigFile;
            }
        }
        assert!(matches!(
            bad_kind_manifest.validate().unwrap_err(),
            HostBackupError::InvalidManifest(_)
        ));

        let mut orphan_snap_manifest = receipt.manifest.clone();
        orphan_snap_manifest
            .sqlite_snapshot
            .as_mut()
            .unwrap()
            .snapshot_relative_path = "var/lib/aetherflow/other.sqlite".to_string();
        assert!(matches!(
            orphan_snap_manifest.validate().unwrap_err(),
            HostBackupError::InvalidManifest(_)
        ));

        // 2. Tampering with a chunk payload must cause verify_backup_artifact to fail
        let first_chunk = &receipt.chunk_paths[0];
        let orig_chunk_bytes = fs::read(first_chunk).unwrap();
        let mut tampered_chunk = orig_chunk_bytes.clone();
        tampered_chunk[0] ^= 0xFF;
        fs::write(first_chunk, &tampered_chunk).unwrap();

        let chunk_err = verify_backup_artifact(&cfg.backup_dir, &archive_filename).unwrap_err();
        assert!(matches!(
            chunk_err,
            HostBackupError::ChecksumMismatch { .. }
        ));

        // Restore valid chunk bytes, then remove the last chunk and verify count mismatch is caught
        fs::write(first_chunk, &orig_chunk_bytes).unwrap();
        verify_backup_artifact(&cfg.backup_dir, &archive_filename).unwrap();

        let last_chunk = receipt.chunk_paths.last().unwrap().clone();
        let last_chunk_bytes = fs::read(&last_chunk).unwrap();
        fs::remove_file(&last_chunk).unwrap();
        let missing_chunk_err =
            verify_backup_artifact(&cfg.backup_dir, &archive_filename).unwrap_err();
        assert!(matches!(
            missing_chunk_err,
            HostBackupError::ChunkError { .. }
        ));
        fs::write(&last_chunk, &last_chunk_bytes).unwrap();

        // 3. Tampering with a manifest entry SHA-256 (even if manifest.json.sha256 is re-signed)
        // must be caught by verify_backup_artifact inspecting the tar.gz members
        let mut tampered_manifest = receipt.manifest.clone();
        for entry in &mut tampered_manifest.entries {
            if entry.kind == BackupTargetKind::ConfigDirectoryEntry {
                entry.sha256 = "0".repeat(64);
            }
        }
        tampered_manifest
            .save_atomic(&receipt.manifest_path)
            .unwrap();
        let archive_member_err =
            verify_backup_artifact(&cfg.backup_dir, &archive_filename).unwrap_err();
        assert!(matches!(
            archive_member_err,
            HostBackupError::ChecksumMismatch { .. }
        ));
    }

    #[test]
    fn chunk_resplit_removes_stale_parts_and_inventory_delete_match_exact_five_digit_parts() {
        let tmp = TempTestDir::new("chunk-exact");
        let backup_dir = tmp.path().join("backups");
        fs::create_dir_all(&backup_dir).unwrap();

        let artifact = backup_dir.join("aetherflow_2026-10-31.sqlite");
        let payload: Vec<u8> = (0..2500).map(|i| (i % 251) as u8).collect();
        fs::write(&artifact, &payload).unwrap();
        write_sha256_sidecar(&artifact).unwrap();

        // First split with small chunk size (500 bytes -> 5 chunks: .part.00000 .. .part.00004)
        let chunks_small = split_backup_into_chunks(&artifact, 500).unwrap();
        assert_eq!(chunks_small.len(), 5);

        // Re-split with larger chunk size (1000 bytes -> 3 chunks: .part.00000 .. .part.00002)
        // Stale .part.00003 and .part.00004 must be removed automatically
        let chunks_large = split_backup_into_chunks(&artifact, 1000).unwrap();
        assert_eq!(chunks_large.len(), 3);
        assert!(!backup_dir
            .join("aetherflow_2026-10-31.sqlite.part.00003")
            .exists());
        assert!(!backup_dir
            .join("aetherflow_2026-10-31.sqlite.part.00004")
            .exists());

        // Plant non-matching `.part.` lookalikes and a directory named `.part.00009`
        let bogus_alpha = backup_dir.join("aetherflow_2026-10-31.sqlite.part.abcde");
        let bogus_long = backup_dir.join("aetherflow_2026-10-31.sqlite.part.000001");
        let bogus_dir = backup_dir.join("aetherflow_2026-10-31.sqlite.part.00009");
        fs::write(&bogus_alpha, b"keep-me").unwrap();
        fs::write(&bogus_long, b"keep-me-too").unwrap();
        fs::create_dir_all(&bogus_dir).unwrap();

        // Inventory must count only the 3 exact 5-digit regular non-symlink chunk files
        let inv = list_backup_inventory(&backup_dir).unwrap();
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].chunk_count, 3);

        // Delete must remove the primary artifact, sidecar, and 3 valid chunks while leaving bogus files/dirs untouched
        let removed = delete_backup_artifacts(&backup_dir, "aetherflow_2026-10-31.sqlite").unwrap();
        assert_eq!(removed.len(), 5); // primary + sidecar + 3 chunks
        assert!(bogus_alpha.exists());
        assert!(bogus_long.exists());
        assert!(bogus_dir.is_dir());
    }

    #[test]
    fn concurrent_sidecar_and_manifest_saves_do_not_collide() {
        use std::sync::Arc;
        use std::thread;

        let tmp = TempTestDir::new("concurrency");
        let dir = Arc::new(tmp.path().join("concurrent-backups"));
        fs::create_dir_all(&*dir).unwrap();

        let artifact = dir.join("aetherflow_shared.sqlite");
        fs::write(&artifact, b"concurrent-sqlite-payload-bytes").unwrap();

        let mut handles = Vec::new();
        for i in 0..8 {
            let dir_cloned = Arc::clone(&dir);
            let art_cloned = artifact.clone();
            handles.push(thread::spawn(move || {
                let (_, digest, size) = write_sha256_sidecar(&art_cloned).unwrap();
                let mut m = BackupManifest::new("v4.0.0", "aetherflow_shared.sqlite").unwrap();
                m.entries.push(BackupManifestEntry {
                    relative_path: "aetherflow_shared.sqlite".to_string(),
                    logical_target_path: None,
                    kind: BackupTargetKind::ConfigFile,
                    sha256: digest,
                    size_bytes: size,
                    unix_mode: Some(0o600),
                    unix_uid: None,
                    unix_gid: None,
                    required: true,
                });
                let manifest_path =
                    dir_cloned.join(format!("aetherflow_shared_{}.manifest.json", i));
                m.save_atomic(&manifest_path).unwrap();
                let loaded = BackupManifest::load_from_path(&manifest_path, true).unwrap();
                assert_eq!(loaded.entries.len(), 1);
            }));
        }

        for h in handles {
            h.join().expect("concurrent worker thread panicked");
        }
        let ver = verify_file_with_sidecar(&artifact).unwrap();
        assert!(ver.verified);
    }

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

    #[cfg(unix)]
    #[test]
    fn s01_atomic_install_rejects_pre_rename_staging_swap_and_records_unverified_post_rename_fault()
    {
        let tmp = TempTestDir::new("s01-atomic-install-post-rename");
        let src_file = tmp.path().join("staged_source.txt");
        fs::write(&src_file, b"verified_payload_bytes").unwrap();
        let dest_dir = tmp.path().join("dest");
        fs::create_dir_all(&dest_dir).unwrap();
        let dest_file = dest_dir.join("target.conf");

        let expected_dest = dest_file.clone();
        crate::verify::set_pre_rename_install_hook(Some(Box::new(
            move |dest, parent_dir, temp_name| {
                if dest == expected_dest.as_path() {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    assert_ne!(Some(parent_dir), dest.parent());
                    let metadata = fs::metadata(parent_dir).unwrap();
                    assert_eq!(metadata.permissions().mode() & 0o077, 0);
                    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
                    let temp_path = parent_dir.join(temp_name);
                    let rogue_path = parent_dir.join(".rogue_swap_candidate");
                    fs::write(&rogue_path, b"rogue_tampered_bytes").unwrap();
                    fs::rename(&rogue_path, &temp_path).unwrap();
                }
            },
        )));
        let pre_swap_res = atomic_install_file_at_destination(
            &src_file,
            &dest_file,
            0o600,
            None,
            None,
            "testing S-01 pre-rename staging swap detection",
        );
        crate::verify::set_pre_rename_install_hook(None);
        let pre_swap_err = pre_swap_res.unwrap_err();
        assert!(pre_swap_err.is_security_rejection());
        assert!(!dest_file.exists());

        let host_root = tmp.path().join("host-s01");
        let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
        create_sample_wal_database(&live_db);
        let etc_af = host_root.join("etc/AetherFlow");
        fs::create_dir_all(&etc_af).unwrap();
        let conf_path = etc_af.join("cluster.conf");
        fs::write(&conf_path, b"node_role=restored_v2\n").unwrap();

        let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
        let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-120000")).unwrap();
        let archive_filename = receipt
            .primary_artifact_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        fs::write(&conf_path, b"node_role=original_v1\n").unwrap();

        let rb_err = execute_staged_restore(
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
        assert!(matches!(rb_err, HostBackupError::RestoreRolledBack { .. }));
        assert_eq!(
            fs::read_to_string(&conf_path).unwrap(),
            "node_role=original_v1\n"
        );
    }

    #[test]
    fn s02_parent_dir_fsync_failure_after_provenance_rename_preserves_committed_authority_without_rollback(
    ) {
        let tmp = TempTestDir::new("s02-provenance-parent-sync-boundary");
        let host_root = tmp.path().join("host-s02");
        let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
        create_sample_wal_database(&live_db);
        let etc_af = host_root.join("etc/AetherFlow");
        fs::create_dir_all(&etc_af).unwrap();
        let conf_path = etc_af.join("cluster.conf");
        fs::write(&conf_path, b"node_role=committed_authority\n").unwrap();

        let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
        let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-121000")).unwrap();
        let archive_filename = receipt
            .primary_artifact_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        fs::write(&conf_path, b"node_role=stale_before_restore\n").unwrap();

        let sync_err = execute_staged_restore(
            &cfg.backup_dir,
            &archive_filename,
            &host_root,
            &RestoreExecutionOptions {
                host_app_version: "v4.0.0".to_string(),
                confirm_destructive_restore: true,
                allow_overwrite: true,
                fail_provenance_parent_sync_on_commit: true,
                ..Default::default()
            },
            &NoopQuiescenceController,
        )
        .unwrap_err();
        assert!(!matches!(
            sync_err,
            HostBackupError::RestoreRolledBack { .. }
        ));
        assert_eq!(
            fs::read_to_string(&conf_path).unwrap(),
            "node_role=committed_authority\n"
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
            "node_role=committed_authority\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn s03_s04_s08_shared_runtime_lock_interoperability_and_strict_root_lock_parent_guard() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let tmp = TempTestDir::new("s03-s04-s08-lock-interop");
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };

        let default_resolved =
            resolve_maintenance_lock_path(Some(Path::new("/var/lib/aetherflow/backups")));
        assert_eq!(
            default_resolved,
            PathBuf::from("/run/aetherflow/.snapshot.lock")
        );

        let sticky_parent = tmp.path().join("run/aetherflow");
        fs::create_dir_all(&sticky_parent).unwrap();
        fs::set_permissions(&sticky_parent, fs::Permissions::from_mode(0o1770)).unwrap();
        let sticky_lock = sticky_parent.join(".snapshot.lock");
        let guard =
            HostMaintenanceLockGuard::acquire(&sticky_lock, Duration::from_millis(100)).unwrap();
        guard.verify_still_active().unwrap();
        drop(guard);

        if euid == 0 {
            let group_writable_non_sticky = tmp.path().join("group-writable-non-sticky");
            fs::create_dir_all(&group_writable_non_sticky).unwrap();
            let c_gw = std::ffi::CString::new(group_writable_non_sticky.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::chown(c_gw.as_ptr(), 0, 65534) }, 0);
            fs::set_permissions(
                &group_writable_non_sticky,
                fs::Permissions::from_mode(0o770),
            )
            .unwrap();
            let bad_lock_path = group_writable_non_sticky.join(".snapshot.lock");
            let gw_err =
                HostMaintenanceLockGuard::acquire(&bad_lock_path, Duration::from_millis(100))
                    .unwrap_err();
            assert!(gw_err.is_security_rejection());

            let service_owned_var_lib = tmp.path().join("service-owned-var-lib");
            fs::create_dir_all(&service_owned_var_lib).unwrap();
            fs::set_permissions(&service_owned_var_lib, fs::Permissions::from_mode(0o700)).unwrap();
            let c_var_lib =
                std::ffi::CString::new(service_owned_var_lib.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::chown(c_var_lib.as_ptr(), 65534, 65534) }, 0);

            let rejected_root_lock = service_owned_var_lib.join(".snapshot.lock");
            let root_reject_err =
                HostMaintenanceLockGuard::acquire(&rejected_root_lock, Duration::from_millis(100))
                    .unwrap_err();
            assert!(root_reject_err.is_security_rejection());

            let nested_root_under_service = service_owned_var_lib.join("locks/.snapshot.lock");
            let nested_reject_err = HostMaintenanceLockGuard::acquire(
                nested_root_lock_under_service(&nested_root_under_service),
                Duration::from_millis(100),
            )
            .unwrap_err();
            assert!(nested_reject_err.is_security_rejection());

            let shared_run = tmp.path().join("shared-run/aetherflow");
            fs::create_dir_all(&shared_run).unwrap();
            let c_shared_run = std::ffi::CString::new(shared_run.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::chown(c_shared_run.as_ptr(), 0, 65534) }, 0);
            fs::set_permissions(&shared_run, fs::Permissions::from_mode(0o1770)).unwrap();

            let shared_lock_file = shared_run.join(".snapshot.lock");
            let c_lock = std::ffi::CString::new(shared_lock_file.to_str().unwrap()).unwrap();
            let fd = unsafe {
                libc::open(
                    c_lock.as_ptr(),
                    libc::O_CREAT | libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    0o660,
                )
            };
            assert!(fd >= 0);
            assert_eq!(unsafe { libc::fchown(fd, 65534, 65534) }, 0);
            assert_eq!(unsafe { libc::fchmod(fd, 0o660) }, 0);
            unsafe {
                libc::close(fd);
            }

            std::env::set_var("AETHERFLOW_SERVICE_UID", "65534");
            std::env::set_var("AETHERFLOW_SERVICE_GID", "65534");
            let root_guard_res =
                HostMaintenanceLockGuard::acquire(&shared_lock_file, Duration::from_millis(100));
            std::env::remove_var("AETHERFLOW_SERVICE_UID");
            std::env::remove_var("AETHERFLOW_SERVICE_GID");
            let root_guard = root_guard_res.unwrap();
            root_guard.verify_still_active().unwrap();
            let lock_meta = fs::symlink_metadata(&shared_lock_file).unwrap();
            assert_eq!(lock_meta.uid(), 0);
            assert_eq!(lock_meta.gid(), 65534);
            assert_eq!(lock_meta.permissions().mode() & 0o777, 0o660);
            drop(root_guard);
        } else if egid != 0 {
            let s08_dir = tmp.path().join("s08-nonroot-zero-gid");
            fs::create_dir_all(&s08_dir).unwrap();
            fs::set_permissions(&s08_dir, fs::Permissions::from_mode(0o700)).unwrap();
            let s08_lock = s08_dir.join(".snapshot.lock");
            fs::write(&s08_lock, b"pid=1\n").unwrap();
            fs::set_permissions(&s08_lock, fs::Permissions::from_mode(0o660)).unwrap();

            std::env::set_var("AETHERFLOW_SERVICE_UID", euid.to_string());
            std::env::set_var("AETHERFLOW_SERVICE_GID", "0");
            let zero_gid_res =
                HostMaintenanceLockGuard::acquire(&s08_lock, Duration::from_millis(100));
            std::env::remove_var("AETHERFLOW_SERVICE_UID");
            std::env::remove_var("AETHERFLOW_SERVICE_GID");
            assert!(zero_gid_res.is_err());
        }
    }

    fn nested_root_lock_under_service(lock_path: &Path) -> PathBuf {
        if let Some(parent_dir) = lock_path.parent() {
            let _ = fs::create_dir_all(parent_dir);
        }
        lock_path.to_path_buf()
    }

    #[cfg(unix)]
    #[test]
    fn s05_sqlite_snapshot_detects_connection_specific_inode_swap_despite_held_guard_fd() {
        let tmp = TempTestDir::new("s05-sqlite-conn-fd-binding");
        let db_dir = tmp.path().join("db");
        fs::create_dir_all(&db_dir).unwrap();
        let live_db = db_dir.join("aetherflow.sqlite");
        create_sample_wal_database(&live_db);

        let existing_conn = Connection::open(&live_db).unwrap();
        let _: i64 = existing_conn
            .query_row("PRAGMA schema_version;", [], |row| row.get(0))
            .unwrap();

        let decoy_db = db_dir.join("decoy.sqlite");
        create_sample_wal_database(&decoy_db);

        let expected_source_db = live_db.clone();
        crate::snapshot::set_pre_sqlite_connect_hook(Some(Box::new(move |source_db_path| {
            if source_db_path == expected_source_db.as_path() {
                let parent_dir = source_db_path.parent().unwrap();
                let swapped_db = parent_dir.join("decoy.sqlite");
                fs::rename(&swapped_db, source_db_path).unwrap();
            }
        })));
        let snap_dest = tmp.path().join("out/snap.sqlite");
        let swap_res = snapshot_sqlite_database(
            &live_db,
            &snap_dest,
            "snap.sqlite",
            &SnapshotOptions::default(),
        );
        crate::snapshot::set_pre_sqlite_connect_hook(None);
        drop(existing_conn);
        let swap_err = swap_res.unwrap_err();
        assert!(swap_err.is_security_rejection());
        assert!(!snap_dest.exists());
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_connection_substitution_is_rejected_after_original_name_is_restored() {
        let temporary = TempTestDir::new("sqlite-restored-name-substitution");
        let database = temporary.path().join("live.sqlite");
        let substitute = temporary.path().join("substitute.sqlite");
        let saved = temporary.path().join("saved.sqlite");
        for (path, marker) in [(&database, "original"), (&substitute, "substitute")] {
            let connection = Connection::open(path).unwrap();
            connection
                .execute("CREATE TABLE identity (value TEXT)", [])
                .unwrap();
            connection
                .execute("INSERT INTO identity VALUES (?1)", [marker])
                .unwrap();
        }
        let existing_connection = Connection::open(&database).unwrap();
        existing_connection
            .query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
            .unwrap();
        let expected_database = database.clone();
        let saved_before = saved.clone();
        let substitute_before = substitute.clone();
        crate::snapshot::set_pre_sqlite_connect_hook(Some(Box::new(move |path| {
            if path == expected_database {
                fs::rename(path, &saved_before).unwrap();
                fs::rename(&substitute_before, path).unwrap();
            }
        })));
        let expected_database = database.clone();
        crate::snapshot::set_post_sqlite_connect_hook(Some(Box::new(move |path| {
            if path == expected_database {
                fs::rename(path, &substitute).unwrap();
                fs::rename(&saved, path).unwrap();
            }
        })));
        let destination = temporary.path().join("output/snapshot.sqlite");
        let result = snapshot_sqlite_database(
            &database,
            &destination,
            "snapshot.sqlite",
            &SnapshotOptions::default(),
        );
        crate::snapshot::set_pre_sqlite_connect_hook(None);
        crate::snapshot::set_post_sqlite_connect_hook(None);
        drop(existing_connection);
        assert!(result.unwrap_err().is_security_rejection());
        assert!(!destination.exists());
    }

    #[test]
    fn s06_s10_s11_recovery_cleans_post_commit_sidecars_blocks_partial_restart_and_binds_checkpoint(
    ) {
        let tmp = TempTestDir::new("s06-s10-s11-recovery-closure");
        let host_root = tmp.path().join("host");
        let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
        create_sample_wal_database(&live_db);
        let etc_af = host_root.join("etc/AetherFlow");
        fs::create_dir_all(&etc_af).unwrap();
        let conf_a = etc_af.join("alpha.conf");
        let conf_b = etc_af.join("beta.conf");
        fs::write(&conf_a, b"alpha=restored\n").unwrap();
        fs::write(&conf_b, b"beta=restored\n").unwrap();

        let mut cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
        cfg.config_targets = vec![
            HostBackupTargetSpec {
                source_path: conf_a.clone(),
                archive_relative_path: "etc/AetherFlow/alpha.conf".to_string(),
                logical_fhs_path: Some("/etc/AetherFlow/alpha.conf".to_string()),
                required: true,
            },
            HostBackupTargetSpec {
                source_path: conf_b.clone(),
                archive_relative_path: "etc/AetherFlow/beta.conf".to_string(),
                logical_fhs_path: Some("/etc/AetherFlow/beta.conf".to_string()),
                required: true,
            },
        ];
        let receipt = create_host_archive_backup(&cfg, Some("2026-11-03-123000")).unwrap();
        let archive_filename = receipt
            .primary_artifact_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        fs::write(&conf_a, b"alpha=pre_crash\n").unwrap();
        fs::write(&conf_b, b"beta=pre_crash\n").unwrap();

        let rb_err = execute_staged_restore(
            &cfg.backup_dir,
            &archive_filename,
            &host_root,
            &RestoreExecutionOptions {
                host_app_version: "v4.0.0".to_string(),
                confirm_destructive_restore: true,
                allow_overwrite: true,
                quiesce_services: vec!["aetherflow-api.service".to_string()],
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

        let prov_dir = resolve_recovery_provenance_dir(&host_root, None);
        let rb_dir_name = rb_dir.file_name().unwrap().to_str().unwrap();
        let prev_prov_path = prov_dir.join(format!("{}.journal.json.prev", rb_dir_name));
        assert!(prev_prov_path.is_file());
        let (prev_digest, _) = compute_file_sha256(&prev_prov_path).unwrap();
        let local_failure_sidecar = checksum_sidecar_path(&failure_journal_path);
        fs::write(
            &local_failure_sidecar,
            format!("{}  rollback-failure-journal.json\n", prev_digest),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&local_failure_sidecar, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let rec_ctx = RecoveryContext::for_target_root(&host_root, None);
        let recovered_s06 = recover_interrupted_restore_with_context(
            &cfg.backup_dir,
            &rec_ctx,
            &NoopQuiescenceController,
        )
        .unwrap();
        assert_eq!(recovered_s06, vec![rb_dir]);
        assert_eq!(fs::read_to_string(&conf_a).unwrap(), "alpha=pre_crash\n");

        let legacy_authority_dir = host_root.join("etc/AetherFlow/legacy-authority");
        fs::create_dir_all(&legacy_authority_dir).unwrap();
        let pending_journal =
            legacy_authority_dir.join(".rollback-restore.pending999.journal.json");
        fs::write(&pending_journal, b"{}").unwrap();

        let deep_dest = host_root.join("etc/AetherFlow/legacy-authority/sub/nested/deep.conf");
        let s10_err =
            crate::restore::validate_destination_not_provenance(&deep_dest, &host_root, None)
                .unwrap_err();
        assert!(s10_err.is_security_rejection());
        fs::remove_file(&pending_journal).unwrap();

        let s11_err = execute_staged_restore(
            &cfg.backup_dir,
            &archive_filename,
            &host_root,
            &RestoreExecutionOptions {
                host_app_version: "v4.0.0".to_string(),
                confirm_destructive_restore: true,
                allow_overwrite: true,
                fail_initial_local_journal_write: true,
                fail_early_cleanup_remove_rb_dir: true,
                ..Default::default()
            },
            &NoopQuiescenceController,
        )
        .unwrap_err();
        let s11_msg = s11_err.to_string();
        assert!(
            s11_msg.contains("initial recovery journal persistence failed")
                && s11_msg.contains("cleanup of"),
            "expected compound early publication + cleanup failure message, got: {}",
            s11_msg
        );

        let recovered_s11 = recover_interrupted_restore_with_context(
            &cfg.backup_dir,
            &rec_ctx,
            &NoopQuiescenceController,
        )
        .unwrap();
        assert_eq!(recovered_s11.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn s07_s09_relative_path_dirfd_containment_and_archive_custom_sqlite_uid_verification() {
        use std::os::unix::fs::symlink;

        let tmp = TempTestDir::new("s07-s09-rel-path-and-archive-uid");
        let outside_secret = tmp.path().join("outside_secret.txt");
        fs::write(&outside_secret, b"top_secret").unwrap();

        let rel_dir_name = format!(
            ".af-s07-rel-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let rel_base = PathBuf::from(&rel_dir_name);
        if fs::create_dir(&rel_base).is_ok() {
            let rel_sym = rel_base.join("symdir");
            let _ = symlink(tmp.path(), &rel_sym);
            let rel_target = rel_base.join("symdir/outside_secret.txt");
            let rel_err = compute_file_sha256(&rel_target).unwrap_err();
            let _ = fs::remove_dir_all(&rel_base);
            assert!(rel_err.is_security_rejection());
        } else {
            let abs_sym = tmp.path().join("symdir");
            symlink(tmp.path(), &abs_sym).unwrap();
            let abs_err = compute_file_sha256(&abs_sym.join("outside_secret.txt")).unwrap_err();
            assert!(abs_err.is_security_rejection());
        }
    }
    #[test]
    fn sentinel_scan_auth_log_aggregates_ipv4_and_ipv6_and_flags_offenders() {
        let tmp = TempTestDir::new("sentinel-test");
        let log_path = tmp.path().join("auth.log");

        let log_content = "\
Nov  1 04:01:00 host sshd[100]: Failed password for invalid user root from 192.168.1.100 port 45123 ssh2
Nov  1 04:01:02 host sshd[101]: Failed password for invalid user admin from 192.168.1.100 port 45124 ssh2
Nov  1 04:01:05 host sshd[102]: Failed password for root from 192.168.1.100 port 45125 ssh2
Nov  1 04:01:10 host sshd[103]: Invalid user test from 2001:db8::1 port 50000
Nov  1 04:01:12 host sshd[104]: Failed password for test from 2001:db8::1 port 50001
Nov  1 04:01:15 host sshd[105]: Failed password for test from 2001:db8::1 port 50002
Nov  1 04:01:20 host sshd[106]: Failed password for operator from 10.0.0.5 port 40000
Nov  1 04:01:25 host sshd[107]: Accepted publickey for admin from 10.0.0.1 port 38000 ssh2
";
        fs::write(&log_path, log_content).unwrap();

        // Threshold = 3: 192.168.1.100 (3) and 2001:db8::1 (3) meet threshold, 10.0.0.5 (1) does not
        let report = sentinel_scan_auth_log(&log_path, 3).expect("sentinel scan succeeds");
        assert_eq!(report.scanned_lines, 8);
        assert_eq!(report.failed_event_count, 7);
        assert_eq!(report.threshold, 3);
        assert_eq!(report.ip_counts.get("192.168.1.100"), Some(&3));
        assert_eq!(report.ip_counts.get("2001:db8::1"), Some(&3));
        assert_eq!(report.ip_counts.get("10.0.0.5"), Some(&1));
        assert_eq!(
            report.offending_ips,
            vec!["192.168.1.100".to_string(), "2001:db8::1".to_string()]
        );

        // Threshold = 5: none meet threshold
        let report5 = sentinel_scan_auth_log(&log_path, 5).unwrap();
        assert!(report5.offending_ips.is_empty());
    }

    #[test]
    fn clean_system_logs_truncates_oversized_files_safely() {
        let tmp = TempTestDir::new("clean-log");
        let root = tmp.path().join("rootfs");

        let var_log = root.join("var/log");
        let lock_dir = root.join("srv/aetherflow/lock");
        fs::create_dir_all(&var_log).unwrap();
        fs::create_dir_all(&lock_dir).unwrap();

        let big_log = var_log.join("daemon.log");
        let small_log = var_log.join("small.log");
        let lock_log = lock_dir.join("worker.log");

        fs::write(&big_log, vec![b'a'; 10_000]).unwrap();
        fs::write(&small_log, vec![b'b'; 500]).unwrap();
        fs::write(&lock_log, vec![b'c'; 8_000]).unwrap();

        // 1. Dry run with threshold 1000 bytes: identifies big_log and lock_log without modifying disk
        let dry_rep = clean_system_logs(&root, 1000, true).unwrap();
        assert!(dry_rep.dry_run);
        assert_eq!(dry_rep.cleaned_files.len(), 2);
        assert_eq!(dry_rep.total_bytes_freed, 18_000);
        assert_eq!(fs::metadata(&big_log).unwrap().len(), 10_000);
        assert_eq!(fs::metadata(&lock_log).unwrap().len(), 8_000);

        // 2. Live clean: truncates oversized logs to 0 bytes while small_log remains 500 bytes
        let live_rep = clean_system_logs(&root, 1000, false).unwrap();
        assert!(!live_rep.dry_run);
        assert_eq!(live_rep.cleaned_files.len(), 2);
        assert_eq!(fs::metadata(&big_log).unwrap().len(), 0);
        assert_eq!(fs::metadata(&lock_log).unwrap().len(), 0);
        assert_eq!(fs::metadata(&small_log).unwrap().len(), 500);
    }

    #[test]
    fn sysctl_tuning_computes_exact_parameters_and_writes_atomically() {
        let tmp = TempTestDir::new("sysctl-tune");
        let root = tmp.path().join("sysctl-root");

        let settings = compute_sysctl_network_tuning();
        assert_eq!(settings.get("net.core.rmem_max").unwrap(), "67108864");
        assert_eq!(settings.get("net.core.wmem_max").unwrap(), "67108864");
        assert_eq!(
            settings.get("net.ipv4.tcp_rmem").unwrap(),
            "4096 87380 33554432"
        );
        assert_eq!(
            settings.get("net.ipv4.tcp_wmem").unwrap(),
            "4096 65536 33554432"
        );
        assert_eq!(settings.get("net.core.default_qdisc").unwrap(), "fq");
        assert_eq!(
            settings.get("net.ipv4.tcp_congestion_control").unwrap(),
            "bbr"
        );

        // Dry-run mode must not create any file on disk
        let dry_rep = apply_network_tuning(&root, true).expect("dry run succeeds");
        assert!(dry_rep.dry_run);
        assert!(!dry_rep.applied);
        assert!(!dry_rep.config_path.exists());

        // Live mode creates /etc/sysctl.d/99-aetherflow-tune.conf atomically
        let live_rep = apply_network_tuning(&root, false).expect("live tuning succeeds");
        assert!(live_rep.applied);
        assert!(!live_rep.dry_run);
        assert!(live_rep.config_path.is_file());

        let content = fs::read_to_string(&live_rep.config_path).unwrap();
        assert!(content.contains("net.core.rmem_max = 67108864"));
        assert!(content.contains("net.ipv4.tcp_congestion_control = bbr"));
    }

    #[test]
    fn inspect_home_disk_space_calculates_per_user_usage() {
        let tmp = TempTestDir::new("showspace-test");
        let root = tmp.path().join("rootfs");

        let user1_dir = root.join("home/alice");
        let user2_dir = root.join("home/bob/downloads");
        fs::create_dir_all(&user1_dir).unwrap();
        fs::create_dir_all(&user2_dir).unwrap();

        fs::write(user1_dir.join("test.txt"), vec![b'x'; 2048]).unwrap();
        fs::write(user2_dir.join("data.bin"), vec![b'y'; 4096]).unwrap();

        let entries = inspect_home_disk_space(&root).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].user, "alice");
        assert_eq!(entries[0].bytes, 2048);
        assert_eq!(entries[0].human, "2.0KB");

        assert_eq!(entries[1].user, "bob");
        assert_eq!(entries[1].bytes, 4096);
        assert_eq!(entries[1].human, "4.0KB");
    }

    #[test]
    fn execute_coordinated_restore_safely_extracts_verifies_and_cleans_stale_wal() {
        let tmp = TempTestDir::new("staged-restore");
        let host_root = tmp.path().join("host");
        let live_db = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
        create_sample_wal_database(&live_db);

        let etc_af = host_root.join("etc/AetherFlow");
        fs::create_dir_all(&etc_af).unwrap();
        fs::write(etc_af.join("cluster.conf"), b"node_role=replica\n").unwrap();

        let cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
        let receipt =
            create_host_archive_backup(&cfg, Some("2026-11-01-restore")).expect("create backup");

        let stage_root = tmp.path().join("staging-restore-target");
        fs::create_dir_all(&stage_root).unwrap();

        // Plant stale -wal and -shm files in the staging target where the database will be restored
        let stale_wal = stage_root.join("var/lib/aetherflow/aetherflow.sqlite-wal");
        let stale_shm = stage_root.join("var/lib/aetherflow/aetherflow.sqlite-shm");
        fs::create_dir_all(stale_wal.parent().unwrap()).unwrap();
        fs::write(&stale_wal, b"stale-wal-bytes-should-be-purged").unwrap();
        fs::write(&stale_shm, b"stale-shm-bytes-should-be-purged").unwrap();

        let opts = RestorePreflightOptions {
            host_app_version: "v4.0.0".to_string(),
            max_supported_sqlite_user_version: Some(50),
            overwrite_policy: OverwritePolicy::AllowRegularFilesInStaging,
            require_artifact_sidecar: true,
        };

        let restore_receipt =
            execute_coordinated_restore(&receipt.primary_artifact_path, &stage_root, opts)
                .expect("coordinated staged restore succeeds");

        assert!(restore_receipt.sqlite_verified);
        assert_eq!(restore_receipt.backup_id, receipt.manifest.backup_id);
        assert!(!stale_wal.exists(), "stale -wal file must be removed");
        assert!(!stale_shm.exists(), "stale -shm file must be removed");

        // Verify restored SQLite database is valid and readable
        let restored_db = stage_root.join("var/lib/aetherflow/aetherflow.sqlite");
        assert!(restored_db.is_file());
        let (uv, _, ic) = verify_sqlite_snapshot_integrity(&restored_db).unwrap();
        assert_eq!(uv, 42);
        assert_eq!(ic.to_lowercase(), "ok");

        // System root overwrite must fail closed
        let bad_opts = RestorePreflightOptions::default();
        let err_root = execute_coordinated_restore(
            &receipt.primary_artifact_path,
            Path::new("/"),
            bad_opts,
        )
        .unwrap_err();
        assert!(err_root.is_security_rejection());
    }

}
