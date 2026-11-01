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
pub mod manifest;
pub mod restore;
pub mod snapshot;
pub mod verify;

pub use backup::{
    create_host_archive_backup, create_sqlite_snapshot_backup, default_host_targets_for_root,
    delete_backup_artifacts, list_backup_inventory, maintenance_helper_ownership_registry,
    prune_backup_inventory, verify_backup_artifact, BackupInventoryItem, HostBackupConfig,
    HostBackupReceipt, HostBackupTargetSpec, MaintenanceHelperOwnership, MaintenanceOwnerCrate,
    DEFAULT_MAX_RETAINED_BACKUPS, DEFAULT_RETENTION_DAYS,
};
pub use error::{HostBackupError, HostBackupResult};
pub use manifest::{
    parse_semver_triplet, BackupManifest, BackupManifestEntry, BackupTargetKind,
    CompatibilityReport, SqliteSnapshotMetadata, BACKUP_MANIFEST_FORMAT,
    CURRENT_MANIFEST_SCHEMA_VERSION, MAX_SUPPORTED_MANIFEST_SCHEMA_VERSION,
    MIN_SUPPORTED_MANIFEST_SCHEMA_VERSION, SUPPORTED_APP_MAJOR_VERSION,
};
pub use restore::{
    execute_destructive_restore, plan_restore_from_manifest, preflight_restore_directory,
    preflight_tar_gz_archive, OverwritePolicy, PlannedRestoreAction, RestorePlan, RestorePlanItem,
    RestorePreflightOptions,
};
pub use snapshot::{
    snapshot_sqlite_database, snapshot_sqlite_with_conn, verify_sqlite_snapshot_integrity,
    SnapshotMethod, SnapshotOptions, SqliteSnapshotReceipt,
};
pub use verify::{
    assemble_verified_chunks, checksum_sidecar_path, compute_file_sha256,
    parse_sha256_sidecar_str, reject_if_symlink, reject_symlink_chain, safe_backup_file_path,
    split_backup_into_chunks, validate_backup_filename, validate_no_parent_traversal,
    validate_relative_backup_path, verify_file_sha256, verify_file_with_sidecar,
    write_sha256_sidecar, ChecksumVerification,
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
        assert!(matches!(err_major, HostBackupError::IncompatibleVersion { .. }));

        // Incompatible downgrade (backup from 4.2.0 onto 4.0.0 host)
        manifest.app_version = "4.2.0".to_string();
        let err_downgrade = manifest.check_compatibility("4.0.0", None).unwrap_err();
        assert!(matches!(err_downgrade, HostBackupError::IncompatibleVersion { .. }));
        manifest.app_version = "4.0.0".to_string();

        // Incompatible SQLite user_version (backup has v12, host supports up to v10)
        let err_uv = manifest.check_compatibility("4.0.0", Some(10)).unwrap_err();
        assert!(matches!(err_uv, HostBackupError::IncompatibleVersion { .. }));

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

        let overwrite_err =
            plan_restore_from_manifest(&manifest, &target_root, &opts).unwrap_err();
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
        fs::write(owner_home.join(".rtorrent.rc"), b"max_memory_usage = 1073741824\n").unwrap();

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
        assert!(!restore_stage.exists(), "preflight must not write to target_root");

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
            required: true,
        });

        let target_via_symlink_ancestor = symlinked_parent.join("restore-stage/inner");
        let err_target = plan_restore_from_manifest(
            &manifest,
            &target_via_symlink_ancestor,
            &RestorePreflightOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err_target, HostBackupError::SymlinkRejected { .. }));

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
            required: true,
        });
        let opts = RestorePreflightOptions::default();

        for forbidden_root in [
            "/",
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
        fs::write(etc_af.join("cluster.conf"), b"secret_token=xyz\n").unwrap();

        let mut cfg = HostBackupConfig::for_isolated_root(&host_root, "v4.0.0");
        cfg.chunk_size_bytes = Some(256);

        // 1. Archive backup bundle permissions
        let archive_receipt =
            create_host_archive_backup(&cfg, Some("2026-10-31-130000")).unwrap();
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
            assert_eq!(mode, 0o600, "expected 0600 permissions on chunk {}", chunk.display());
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
            assert_eq!(snap_mode, 0o600, "expected 0600 on SQLite snapshot ({})", slug);
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
        bad_size_manifest.sqlite_snapshot.as_mut().unwrap().size_bytes += 10;
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
        assert!(matches!(chunk_err, HostBackupError::ChecksumMismatch { .. }));

        // Restore valid chunk bytes, then remove the last chunk and verify count mismatch is caught
        fs::write(first_chunk, &orig_chunk_bytes).unwrap();
        verify_backup_artifact(&cfg.backup_dir, &archive_filename).unwrap();

        let last_chunk = receipt.chunk_paths.last().unwrap().clone();
        let last_chunk_bytes = fs::read(&last_chunk).unwrap();
        fs::remove_file(&last_chunk).unwrap();
        let missing_chunk_err =
            verify_backup_artifact(&cfg.backup_dir, &archive_filename).unwrap_err();
        assert!(matches!(missing_chunk_err, HostBackupError::ChunkError { .. }));
        fs::write(&last_chunk, &last_chunk_bytes).unwrap();

        // 3. Tampering with a manifest entry SHA-256 (even if manifest.json.sha256 is re-signed)
        // must be caught by verify_backup_artifact inspecting the tar.gz members
        let mut tampered_manifest = receipt.manifest.clone();
        for entry in &mut tampered_manifest.entries {
            if entry.kind == BackupTargetKind::ConfigDirectoryEntry {
                entry.sha256 = "0".repeat(64);
            }
        }
        tampered_manifest.save_atomic(&receipt.manifest_path).unwrap();
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
        assert!(!backup_dir.join("aetherflow_2026-10-31.sqlite.part.00003").exists());
        assert!(!backup_dir.join("aetherflow_2026-10-31.sqlite.part.00004").exists());

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
        let removed =
            delete_backup_artifacts(&backup_dir, "aetherflow_2026-10-31.sqlite").unwrap();
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
}
