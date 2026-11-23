mod catalog;
mod dispatch;
mod handlers;
mod job_runner;
mod lifecycle;
mod receipts;
mod rollback;

#[cfg(test)]
pub(crate) use catalog::get_marketplace_auth_info;
#[cfg(test)]
pub(super) use catalog::{
    build_single_package_update_response, get_marketplace_apps_blocking, package_progress_payload,
    PackageProgressQuery,
};
pub(super) use catalog::{
    check_package_updates, check_single_package_update, get_marketplace_apps, package_progress,
};

#[cfg(test)]
pub(crate) use dispatch::dispatch_package_lifecycle;
#[cfg(test)]
pub(super) use dispatch::dispatch_package_lifecycle_with_target;

pub(super) use handlers::{install_package, uninstall_package, update_package};
#[cfg(test)]
pub(super) use handlers::{parse_uninstall_purge, UninstallQuery};
pub(crate) use handlers::{reinstall_package, PackageActionQuery};

#[cfg(test)]
pub(super) use lifecycle::{
    allocate_or_resolve_app_port, allocate_or_resolve_app_port_for_job,
    allocate_or_resolve_app_port_with, emit_package_progress, finish_package_lifecycle,
    finish_package_lifecycle_with_recovery, is_lock_file_present,
    pre_stop_units_for_package_update_with, reserve_api_lifecycle_ports,
    resolve_package_lifecycle_port_with, run_package_lifecycle_dispatch_gate_with,
    system_update_lifecycle_block_with, verified_prior_state_recovery,
};
pub(crate) use lifecycle::{append_package_job_output, PackageLifecycleFailure};
pub(super) use lifecycle::{load_authoritative_app_ingress_config, system_update_lifecycle_block};
pub use lifecycle::{target_version_matches, versions_match_target};

pub(crate) use receipts::ReceiptSnapshotEntry;
#[cfg(test)]
pub(super) use receipts::{
    resolve_candidate_receipt_paths, restore_candidate_receipts, snapshot_candidate_receipts,
};
pub use receipts::{sanitize_package_update_record, sanitize_url_or_source_key_for_api};

pub(crate) use rollback::should_rollback_post_certification_failure;
#[cfg(test)]
pub(super) use rollback::{
    finalize_post_script_lifecycle_with, handle_post_certification_finalization_failure_ext_with,
    quiesce_and_restore_candidate_receipts_and_runtime_ext_with,
    restore_pre_stopped_units_after_installer_failure_with, CANDIDATE_QUIESCE_RECORDER,
};
#[cfg(test)]
pub(crate) use rollback::{
    handle_post_certification_finalization_failure_with, quiesce_and_restore_candidate_receipts,
    quiesce_and_restore_candidate_receipts_and_runtime,
    quiesce_and_restore_candidate_receipts_and_runtime_with,
    quiesce_and_restore_candidate_receipts_with,
};
