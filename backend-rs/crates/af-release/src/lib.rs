//! `af-release` — AetherFlow Rust Release Management Foundation.
//!
//! Incrementally replaces `deploy/release-manager.sh` with a strongly-typed, lock-serialized,
//! crash-recoverable Rust library and administrative interface while preserving:
//! - Stage 0: FHS state & secret layout verification and 4-tier live SQLite path resolution (`resolve_db_path`).
//! - Stage 1: Release tag resolution (`stable`, `nightly`), SHA-256 manifest verification,
//!   Zip-Slip-safe archive extraction, and `--dry-run --offline` simulation.
//! - Stage 1.5: WAL-safe online SQLite backups (`rusqlite::backup::Backup` opened read-only so hot WALs are never checkpointed),
//!   `PRAGMA integrity_check` verification, and `MANIFEST.sha256` generation.
//! - Stage 2: Atomic symlink swaps (`/opt/AetherFlow/current`) and `.previous_release` tracking.
//! - Stage 3: Non-destructive systemd unit installation (`install_packaged_unit_if_missing`), service restarts,
//!   and deep readiness probing (`/health/ready`).
//! - Stage 4: Automatic and manual rollback with service stop prior to WAL/SHM sidecar removal and SQLite corruption quarantine.
//! - Stage 5: Old release pruning (`cleanup_old_releases`) protecting active and previous targets.
//! - Stage 6: One-shot PM2 -> systemd migration (`migrate-systemd`).

pub mod admin;
pub mod artifact;
pub mod config;
pub mod engine;
pub mod error;
pub mod fs_security;
pub mod health;
pub mod lifecycle;
pub mod lock;
pub mod runtime;
pub mod snapshot;
pub mod symlink;

pub use admin::{
    ensure_interoperable_maintenance_lock_file, execute_self_update_sync, is_unsupported_error,
    resolve_maintenance_lock_path_for_config, resolve_release_manager_conf,
    resolve_release_manager_conf_for_root, resolve_self_update_jobs_dir_for_config,
    resolve_self_update_jobs_dir_from_process_env, run_cli_from_args, validate_self_update_request,
    ValidatedSelfUpdateRequest,
};
pub use artifact::{
    compute_file_sha256, extract_and_validate_release_archive, parse_sha256_manifest,
    parse_stable_tag_from_redirect_url, prepare_release_permissions,
    resolve_stable_tag_from_latest_redirect, select_release_tag_from_json,
    simulate_offline_artifact, stage_running_release_manager, verify_artifact_checksum,
    verify_release_provenance, verify_release_provenance_with_token, ArtifactProvider,
    GitHubReleaseItem, GithubHttpArtifactProvider,
};
pub use config::{
    decode_quoted_or_raw_conf_value, default_release_asset_for_arch, escape_conf_value,
    parse_conf_file, parse_conf_str, read_env_file_value, read_env_str_value,
    read_systemd_environment_value, resolve_db_path, try_parse_conf_entries, try_resolve_db_path,
    validate_no_parent_traversal, DbPathSource, RedactedSecret, ReleaseChannel, ReleaseCommand,
    ReleaseConfig, ReleaseOptions, ResolvedDbPath,
};
pub use engine::{
    append_jsonl_log, CleanupReport, DeployReport, MigrateSystemdReport, ReleaseEngine,
    ReleaseEngineStatus, ReleaseLogEntry, ReleaseOutcome, RollbackReport,
};
pub use error::{ExitCode, ReleaseError, ReleaseResult};
pub use fs_security::{
    apply_data_dir_ownership_and_mode, apply_root_aetherflow_dir_ownership_and_mode,
    apply_service_ownership, atomic_copy_file_with_mode, atomic_write_bytes_with_mode,
    create_dir_all_no_symlinks, create_new_dir_exclusive, ensure_no_symlink_ancestors,
    ensure_no_symlink_in_relative_chain, open_exclusive_private_file, set_dir_mode, set_file_mode,
    OwnershipMetadata,
};
pub use health::{
    install_packaged_unit_if_missing, install_systemd_hardening_dropins, is_healthy_status,
    parse_endpoint_socket_addr, parse_health_status, poll_readiness_probe,
    run_post_restart_log_retention_with_bin, sync_cli_entrypoints, verify_deployed_frontend_assets,
    verify_isolated_systemd_lifecycle_authorized, wait_for_listener_stopped, HealthCheckAttempt,
    HealthProber, LifecycleController, NoopLifecycleController, ReqwestHealthProber,
    SystemdLifecycleController,
};
pub use lock::{RecoveryState, ReleaseLockGuard, ReleasePhase};
pub use snapshot::{
    create_dry_run_placeholder_db, create_state_snapshot, restore_state_if_corrupted,
    sqlite_integrity, sqlite_online_backup, verify_snapshot_manifest, RestoreReport,
    SnapshotReport,
};
pub use symlink::{
    atomic_replace_symlink, canonicalize_preserve_normal, cleanup_old_releases,
    perform_symlink_swap, read_current_link_target, read_previous_release, write_previous_release,
};

#[cfg(test)]
mod tests;
