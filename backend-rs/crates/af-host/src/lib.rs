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

/// Resolves the running host application version dynamically from a sibling `.version`
/// metadata file next to the current executable when it parses as a valid semver triplet,
/// falling back to `concat!("v", env!("CARGO_PKG_VERSION"))`.
pub fn default_host_app_version() -> String {
    if let Ok(exe) = std::env::current_exe() {
        let canonical = std::fs::canonicalize(&exe).unwrap_or(exe);
        if let Some(parent) = canonical.parent() {
            if let Ok(raw) = std::fs::read_to_string(parent.join(".version")) {
                let candidate = raw.trim();
                if !candidate.is_empty() && parse_semver_triplet(candidate).is_ok() {
                    return candidate.to_string();
                }
            }
        }
    }
    concat!("v", env!("CARGO_PKG_VERSION")).to_string()
}
pub use restore::{
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
mod tests;
