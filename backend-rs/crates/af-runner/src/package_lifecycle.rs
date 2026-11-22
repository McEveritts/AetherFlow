mod admitted_snapshots;
mod backend;
mod coordinator;
mod probe_command;
mod receipt_snapshots;
mod recovery_storage;
mod redaction;
mod runtime_snapshot;
mod runtime_targets;
pub(crate) mod snapshot_policy;
mod version_probe;

#[cfg(test)]
mod tests;
#[cfg(test)]
#[allow(clippy::await_holding_lock, clippy::field_reassign_with_default)]
mod version_verification_tests;

// Re-exports required by `snapshot_policy.rs` (`use super::*;`).
use runtime_snapshot::CommittedSwap;
#[cfg(test)]
use runtime_snapshot::SNAPSHOT_CAPTURE_THREAD;
use runtime_targets::verify_no_symlink_ancestors_with_root;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[cfg(test)]
pub use admitted_snapshots::admitted_lifecycle_snapshot_backup_root;
pub use admitted_snapshots::{
    capture_admitted_lifecycle_snapshot, discard_admitted_lifecycle_snapshot,
    execute_coordinated_package_stream, has_admitted_lifecycle_snapshot, package_service_units,
    restore_admitted_lifecycle_snapshot, LifecycleReceipt, JOB_MARKER, RECEIPT_MARKER,
};

pub use backend::is_incomplete_rollback_error;
#[allow(unused_imports)]
pub(crate) use backend::{parse_systemd_active_state, parse_systemd_quiesced_state};

#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub(crate) use probe_command::is_process_zombie_linux;
#[cfg(test)]
pub use probe_command::INJECT_WAITID_EPERM;
pub use probe_command::{run_bounded_probe_command, run_bounded_probe_command_cancellable};

pub use receipt_snapshots::{
    candidate_version_marker_paths, candidate_version_marker_paths_with_env,
    open_dir_nofollow_stepwise, open_dir_nofollow_stepwise_ext, open_dir_nofollow_stepwise_inner,
    open_dir_nofollow_stepwise_inner_ext, read_file_entry_bounded_nofollow,
    read_receipt_bounded_nofollow, restore_candidate_receipts, rollback_operation_state,
    rollback_operation_state_with_runtime, snapshot_blueprint_targets, snapshot_candidate_receipts,
    snapshot_candidate_receipts_with_env, FileSnapshot, SnapshotFileEntry, SnapshotFileState,
    StepwiseDirError,
};
#[cfg(test)]
pub use receipt_snapshots::{TEST_CERTIFY_FAIL_HOOK, TEST_ROLLBACK_HOOK};

pub use redaction::sanitize_lifecycle_field;

pub use runtime_snapshot::{PackageRuntimeSnapshot, RuntimeSnapshotEntry};
pub use runtime_targets::{is_receipt_file_name, RuntimeTargetKind};

pub use version_probe::{
    extract_version_token, has_independent_runtime_evidence, has_prerelease_or_build,
    has_prerelease_or_build_with_alnum, probe_live_runtime_version, read_af_version_receipt,
    resolve_verified_installed_version, resolve_verified_installed_version_with_prober,
    trim_version_token, Confirmed, LiveRuntimeProbeOutcome,
};
