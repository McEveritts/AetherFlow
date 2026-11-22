//! Non-destructive restore planning, preflight inspection, and archive verification for `af-host`.
//!
//! # Security & Non-Destructive Invariants
//! 1. **Non-Destructive Planning & Preflight Only:** `plan_restore`, `preflight_restore_directory`,
//!    and `preflight_tar_gz_archive` never overwrite, delete, or mutate live host files.
//! 2. **Explicitly Unsupported Destructive Execution:** `execute_destructive_restore` always fails
//!    closed with [`HostBackupError::DestructiveRestoreUnsupported`] rather than performing an
//!    unsafe or uncoordinated live overwrite while `aetherflow-api` or systemd services hold open
//!    SQLite/configuration descriptors.
//! 3. **Path Traversal Rejection:** Any manifest or archive entry containing `..`, `.`, leading
//!    `/`, `\`, drive prefixes, or NUL bytes is rejected immediately.
//! 4. **Symlink & Link Rejection:** Symbolic links (`EntryType::Symlink`), hard links (`EntryType::Link`),
//!    FIFOs, character/block devices, and existing destination symlinks along any ancestor chain
//!    under `target_root` (including ancestors of `target_root` itself) are rejected.
//! 5. **Unsafe Overwrite Rejection:** Direct system roots (`/`, `/etc`, `/var`, `/usr`, `C:\`, etc.),
//!    relative roots, or paths with fewer than two normal components are unconditionally rejected as
//!    `target_root`. Under `OverwritePolicy::RejectExisting` (the default), any existing file or
//!    directory collision under `target_root` is rejected unless the caller explicitly opts into
//!    `OverwritePolicy::AllowRegularFilesInStaging` on a non-production staging root.

#[cfg(test)]
mod coordinated_test;
mod execution;
mod journal;
mod policy;
mod preflight;
mod quiescence;
mod recovery;

#[cfg(test)]
pub use coordinated_test::{execute_coordinated_restore, RestoreReceipt};
pub use execution::execute_staged_restore;
pub use journal::{
    RestoreExecutionOptions, RestoreExecutionReport, RollbackFailureJournal,
    RollbackFailureJournalEntry, IN_PROGRESS_RECOVERY_JOURNAL_FILENAME,
};
pub use policy::{
    resolve_effective_quiesce_services, resolve_recovery_provenance_dir,
    resolve_trusted_canonical_host_destination,
    resolve_trusted_canonical_host_destination_with_sqlite_override,
    validate_destination_not_provenance, validate_quiesce_service_entries,
    validate_trusted_sqlite_db_path, OverwritePolicy, PlannedRestoreAction, RecoveryContext,
    RestorePlan, RestorePlanItem, RestorePreflightOptions, DEFAULT_MANDATORY_QUIESCE_SERVICES,
};
pub(crate) use preflight::verify_tar_gz_against_manifest_with_trusted_uid;
pub use preflight::{
    execute_destructive_restore, plan_restore_from_manifest,
    plan_restore_from_manifest_for_execution, plan_restore_from_manifest_with_sqlite_override,
    plan_restore_from_manifest_with_sqlite_overrides, preflight_restore_directory,
    preflight_restore_directory_for_execution, preflight_restore_directory_with_sqlite_override,
    preflight_restore_directory_with_sqlite_overrides,
    preflight_restore_directory_with_sqlite_overrides_and_trusted_uid, preflight_tar_gz_archive,
    preflight_tar_gz_archive_for_execution, preflight_tar_gz_archive_with_sqlite_override,
    preflight_tar_gz_archive_with_sqlite_overrides,
    preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid,
};
pub use quiescence::{
    CommandQuiescenceController, NoopQuiescenceController, ServiceQuiescenceController,
};
pub use recovery::{recover_interrupted_restore, recover_interrupted_restore_with_context};
