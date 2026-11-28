pub use libc;
use once_cell::sync::Lazy;
use regex::Regex;

af_models::define_package_diagnostic_redaction!();

mod jobs;
mod lease;
mod units;
mod version;
mod version_matching;

#[cfg(test)]
mod tests;

pub use jobs::{
    admit_job, admit_job_with_target, check_package_reservation, check_reservation, finish_job,
    finish_job_with_diagnostics, get_lifecycle_history, initialize_schema,
    normalize_recovery_state, normalize_retention_state, query_package_retention_history,
    query_retained_lifecycle_packages, reconcile_jobs, reconcile_jobs_with_options,
    record_completed_lifecycle_job, LifecycleJobDiagnostics, PackageLifecycleRetentionRecord,
    RECOVERY_STATE_PRIOR_VERIFIED, RECOVERY_STATE_UNVERIFIED, RETENTION_STATE_PURGED,
    RETENTION_STATE_RETAINED,
};
pub use lease::{owner_is_alive, OwnerLease};
pub use units::{
    is_activation_unit, is_legacy_optional_companion_unit, is_socket_unit, is_timer_unit,
    ordered_units_for_start, package_resources, port_resource, sort_units_for_start,
    sort_units_for_stop, unit_start_order_key, unit_stop_order_key, ReservationTarget,
};
pub use version::{
    commits_match_prefix, compare_debian_versions_str, compare_versions, dpkg_verrevcmp,
    is_debian_plus_revision, is_debian_revision_suffix, is_hex_commit, is_hex_digits_7_to_40,
    is_hex_digits_7_to_64, is_hex_sha_7_to_64, is_prerelease_version_for_channel,
    is_prerelease_version_for_channel_with_source, is_valid_apt_debian_revision_suffix,
    normalize_version, normalize_version_str, strip_semver_build_metadata, strip_version_prefix,
};
pub use version_matching::{
    apt_receipt_matches_live_debian_revision, is_valid_component_version,
    is_valid_target_version_token, matches_component_manifest, parse_apt_policy_candidate,
    parse_component_manifest, parse_installed_dpkg_status_version, parse_piped_component_manifest,
    single_version_matches, single_version_matches_target, validate_exact_apt_version,
    validate_single_version_token, validate_target_version, versions_match_target,
};
