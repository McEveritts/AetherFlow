//! `af-cli`: Bounded unified Rust administrative CLI (`af`) and resumable provisioning foundation
//! for AetherFlow (`v4.0.0` pure bare-metal `systemd` + `Apache2`, zero Docker).
//!
//! # Core Responsibilities
//! 1. **Manual CLI Parser & Legacy Compatibility (`cli`)**:
//!    Supports both legacy `packages/system/af` shorthands (`af install`, `af remove`, `af list`,
//!    `af update`, `af upgrade`, `af -h`) and structured domain subcommands (`package`, `service`,
//!    `quota`, `sandbox`, `release`, `backup`, `provision`, `health`) with `--json`, `--dry-run`,
//!    `--socket`, and `--root` flags.
//! 2. **Privileged Runner Unix Socket Client (`client`)**:
//!    Dispatches validated `af-models` IPC structs (`PackageRunnerRequest`, `SystemctlRequest`,
//!    `QuotaRunnerRequest`, `SandboxRunnerRequest`, `SelfUpdateRequest`) over `/run/aetherflow/runner.sock`
//!    via [`RunnerClientTransport`] and [`UnixSocketRunnerClient`].
//! 3. **Release Engine & Self-Update Integration**:
//!    Reuses `af-release` (`ReleaseConfig`, `ReleaseEngine`, `ReleaseOptions`, `validate_self_update_request`)
//!    and `af-runner`'s `/v1/self-update` contract without inventing custom wire formats.
//! 4. **Host Backup & Non-Destructive Restore Preflight**:
//!    Reuses `af-host` (`create_host_archive_backup`, `create_sqlite_snapshot_backup`,
//!    `list_backup_inventory`, `verify_backup_artifact`, `preflight_tar_gz_archive`,
//!    `preflight_restore_directory`, `plan_restore_from_manifest`, `execute_destructive_restore`)
//!    while keeping live destructive restore (`af backup restore`) explicitly unsupported.
//! 5. **Resumable Provisioning Foundation (`provision`)**:
//!    Persists `# STATE_VERSION=2` step completion (`/install/.aetherflow.state`), atomic key-value
//!    configuration (`/install/.aetherflow.conf`), PID lockfile (`/var/run/aetherflow-setup.lock`),
//!    preflight checks, SHA-256 sidecar config overlays, and explicit `--repair` / `--resume` / `--dry-run`
//!    semantics while retaining `setup/AetherFlow-Setup` for interactive shell bootstrap.

pub mod cli;
pub mod client;
mod commands;
pub mod error;
pub mod provision;

pub use cli::{
    build_hosts_runner_request, build_package_runner_request,
    build_package_runner_request_with_target, build_quota_runner_request,
    build_release_engine_options, build_sandbox_runner_request, build_self_update_runner_request,
    parse_byte_size_arg, parse_cli_args, render_help_text, resolve_package_lock_name,
    validate_service_request, AfCommand, BackupCliCommand, BackupCreateKind, GlobalOptions,
    HelpTopic, HostsCliCommand, MaintenanceCliCommand, PackageCommand, ParsedInvocation,
    ProvisionCliCommand, QuotaCommand, ReleaseCliCommand, ReleaseDispatchMode, SandboxCommand,
    ServiceCommand, ALLOWED_SYSTEMCTL_ACTIONS,
};
pub use client::{
    format_human_progress_line, parse_package_stream_body, parse_package_stream_line,
    PackageExecutionReceipt, PackageStreamAccumulator, PackageStreamEvent, RunnerClientTransport,
    UnixSocketRunnerClient, MAX_PACKAGE_STREAM_LINE_CARRY_BYTES, MAX_RETAINED_PACKAGE_LOG_LINES,
};
pub use error::{CliError, CliExitCode, CliResponseEnvelope, CliResult};
pub use provision::{
    canonical_step_catalog, ensure_no_symlink_ancestors, execute_provision_steps,
    is_canonical_step, is_effective_root_user, parse_and_validate_os_release,
    run_provision_preflight, safe_overlay_config_file, validate_step_id, ConfigOverlayOutcome,
    ConfigOverlayReceipt, OsReleaseInfo, ProvisionLockGuard, ProvisionPaths,
    ProvisionPreflightReport, ProvisionRunReport, ProvisionStateStore, ProvisionStatusReport,
    ProvisionStepDescriptor, ProvisionStepTier, StepExecutionRecord, StepExecutionStatus,
    CANONICAL_ALL_STEPS, PROVISION_STATE_VERSION, STATE_VERSION_HEADER,
};

pub use af_host::{
    apply_network_tuning, assemble_verified_chunks, clean_system_logs,
    compute_sysctl_network_tuning, create_host_archive_backup, create_sqlite_snapshot_backup,
    delete_backup_artifacts, execute_destructive_restore, inspect_home_disk_space,
    list_backup_inventory, maintenance_helper_ownership_registry,
    plan_restore_from_manifest_with_sqlite_overrides,
    preflight_restore_directory_with_sqlite_overrides_and_trusted_uid,
    preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid, prune_backup_inventory,
    safe_backup_file_path, sentinel_scan_auth_log, split_backup_into_chunks,
    verify_backup_artifact_with_trusted_uid, BackupManifest, HostBackupConfig, RestorePlan,
    RestorePreflightOptions,
};

use commands::backup::execute_backup_command;
use commands::ops::{
    execute_hosts_command, execute_maintenance_command, execute_quota_command,
    execute_sandbox_command, execute_service_command,
};
use commands::package::execute_package_command;
use commands::provision::execute_provision_command;
use commands::release::execute_release_command;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::PathBuf;

pub(crate) const EMBEDDED_PACKAGE_AUTOMATION_JSON: &str =
    include_str!("../../../../config/package_automation.json");

/// Canonical package lockfile status entry returned by `af list` / `af package list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageListEntry {
    pub package_id: String,
    pub lock_name: String,
    pub lock_path: PathBuf,
    pub installed: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub retained_receipt_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_lock_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub legacy_receipt_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_lock_path: Option<PathBuf>,
    pub service_name: String,
    pub sandbox_profile: String,
}

/// Parses raw CLI arguments and executes the resulting command using the default
/// [`UnixSocketRunnerClient`] resolved from `--socket` or `AETHERFLOW_RUNNER_SOCK`.
pub fn run_cli_from_args<I, S>(raw_args: I) -> CliResponseEnvelope
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    match parse_cli_args(raw_args) {
        Ok(invocation) => {
            let client = UnixSocketRunnerClient::new(&invocation.global.socket_path);
            execute_invocation(&invocation, &client)
        }
        Err(err) => err.to_error_envelope("cli", "parse"),
    }
}

/// Executes a parsed [`ParsedInvocation`] using the supplied [`RunnerClientTransport`].
pub fn execute_invocation(
    invocation: &ParsedInvocation,
    transport: &dyn RunnerClientTransport,
) -> CliResponseEnvelope {
    let domain = invocation.command.domain_name();
    let action = invocation.command.action_name();
    match execute_command_inner(&invocation.global, &invocation.command, transport) {
        Ok(envelope) => envelope,
        Err(err) => err.to_error_envelope(domain, action),
    }
}

fn execute_command_inner(
    global: &GlobalOptions,
    command: &AfCommand,
    transport: &dyn RunnerClientTransport,
) -> CliResult<CliResponseEnvelope> {
    match command {
        AfCommand::Help { topic } => {
            let text = render_help_text(*topic);
            Ok(CliResponseEnvelope::success(
                "help",
                "help",
                text,
                Some(json!({ "topic": topic })),
            ))
        }
        AfCommand::Version => {
            let ver = env!("CARGO_PKG_VERSION");
            let msg = format!(
                "af (af-cli) v{} ({}/{}) - AetherFlow Bare-Metal Control Plane CLI",
                ver,
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            Ok(CliResponseEnvelope::success(
                "version",
                "version",
                msg,
                Some(json!({
                    "name": "af-cli",
                    "binary": "af",
                    "version": ver,
                    "os": std::env::consts::OS,
                    "arch": std::env::consts::ARCH,
                })),
            ))
        }
        AfCommand::Health => {
            if global.dry_run {
                return Ok(CliResponseEnvelope::success(
                    "health",
                    "check",
                    format!(
                        "[DRY-RUN] Would check /v1/health on runner socket {}",
                        global.socket_path.display()
                    ),
                    Some(json!({
                        "dry_run": true,
                        "socket_path": global.socket_path,
                    })),
                ));
            }
            let resp = transport.check_health()?;
            Ok(CliResponseEnvelope::success(
                "health",
                "check",
                format!(
                    "Privileged runner healthy ({}): {}",
                    global.socket_path.display(),
                    resp.output.trim()
                ),
                Some(json!({
                    "socket_path": global.socket_path,
                    "runner_response": resp,
                })),
            ))
        }
        AfCommand::Package(pkg_cmd) => execute_package_command(global, pkg_cmd, transport),
        AfCommand::Service(svc_cmd) => execute_service_command(global, svc_cmd, transport),
        AfCommand::Quota(quota_cmd) => execute_quota_command(global, quota_cmd, transport),
        AfCommand::Sandbox(sbx_cmd) => execute_sandbox_command(global, sbx_cmd, transport),
        AfCommand::Release(rel_cmd) => execute_release_command(global, rel_cmd, transport),
        AfCommand::Backup(bak_cmd) => execute_backup_command(global, bak_cmd),
        AfCommand::Provision(prov_cmd) => execute_provision_command(global, prov_cmd),
        AfCommand::Maintenance(maint_cmd) => execute_maintenance_command(global, maint_cmd),
        AfCommand::Hosts(hosts_cmd) => execute_hosts_command(global, hosts_cmd, transport),
    }
}

#[cfg(test)]
mod tests;
