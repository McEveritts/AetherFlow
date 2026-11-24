//! Manual command-line parser, typed command AST, and request builders for `af` (`af-cli`).
//!
//! Supports both the legacy `packages/system/af` CLI surface (`af install`, `af remove`, `af list`,
//! `af update`, `af upgrade`, `af -h`) and the unified structured administrative subcommands
//! (`package`, `service`, `quota`, `sandbox`, `release`, `backup`, `provision`, `health`).

mod help;
mod parse;
mod parse_backup;
mod parse_ops;
mod requests;

#[cfg(test)]
mod tests;

pub use help::render_help_text;
pub use parse::{parse_cli_args, parse_cluster_subcommand, parse_hosts_subcommand};
pub use parse_ops::parse_byte_size_arg;
pub use requests::{
    build_hosts_runner_request, build_package_runner_request,
    build_package_runner_request_with_target, build_quota_runner_request,
    build_release_engine_options, build_sandbox_runner_request, build_self_update_runner_request,
    resolve_package_lock_name, validate_service_request,
};

use crate::error::CliResult;
use af_host::OverwritePolicy;
use af_models::SystemctlRequest;
use af_release::ReleaseChannel;
use af_runner::resolve_runner_socket_path;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Allowed systemctl actions matching `af-runner`'s `/v1/systemctl` allowlist.
pub const ALLOWED_SYSTEMCTL_ACTIONS: &[&str] = &[
    "start", "stop", "restart", "reload", "enable", "disable", "status",
];

/// Global flags shared across all `af` subcommands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalOptions {
    /// Emit structured JSON (`CliResponseEnvelope`) instead of human text.
    pub json: bool,
    /// Override the privileged runner Unix domain socket path (`/run/aetherflow/runner.sock`).
    pub socket_path: PathBuf,
    /// Perform validation and dry-run planning without mutating live services or disk state.
    pub dry_run: bool,
    /// Optional filesystem root override for isolated testing, backup inspection, and provisioning.
    pub root: Option<PathBuf>,
}

impl Default for GlobalOptions {
    fn default() -> Self {
        Self {
            json: false,
            socket_path: PathBuf::from(resolve_runner_socket_path()),
            dry_run: false,
            root: None,
        }
    }
}

/// Top-level parsed CLI invocation combining global flags with a typed [`AfCommand`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedInvocation {
    pub global: GlobalOptions,
    pub command: AfCommand,
}

/// Help topic selector for `af help [topic]` or `--help`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelpTopic {
    General,
    Package,
    Update,
    Service,
    Quota,
    Sandbox,
    Release,
    Backup,
    Provision,
    Maintenance,
    Hosts,
    Cluster,
}

/// Typed administrative command AST for the `af` CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "domain", rename_all = "snake_case")]
pub enum AfCommand {
    /// Print general or domain-specific usage instructions.
    Help { topic: HelpTopic },
    /// Print binary version and architecture metadata.
    Version,
    /// Check `/v1/health` on the privileged runner socket.
    Health,
    /// Package management commands (`af install`, `af remove`, `af list`, `af package ...`).
    Package(PackageCommand),
    /// Systemd service control mediated by `af-runner` (`/v1/systemctl`).
    Service(ServiceCommand),
    /// Disk quota management mediated by `af-runner` (`/v1/quota`).
    Quota(QuotaCommand),
    /// Systemd drop-in sandboxing mediated by `af-runner` (`/v1/sandbox`).
    Sandbox(SandboxCommand),
    /// Atomic release lifecycle & self-update commands backed by `af-release` and `af-runner`.
    Release(ReleaseCliCommand),
    /// Host backup, SHA-256 verification, and non-destructive restore preflight backed by `af-host`.
    Backup(BackupCliCommand),
    /// Resumable bare-metal provisioning foundation (`STATE_VERSION=2`).
    Provision(ProvisionCliCommand),
    /// Host maintenance utilities (tune, sentinel, clean-logs, showspace) backed by `af-host`.
    Maintenance(MaintenanceCliCommand),
    /// Local DNS and /etc/hosts reconciliation mediated by `af-runner` (`/v1/hosts`).
    Hosts(HostsCliCommand),
    /// Read-only Peer Clustering diagnostic commands (`af cluster diagnose <link>`).
    Cluster(ClusterCliCommand),
}

impl AfCommand {
    pub const fn domain_name(&self) -> &'static str {
        match self {
            AfCommand::Help { .. } => "help",
            AfCommand::Version => "version",
            AfCommand::Health => "health",
            AfCommand::Package(_) => "package",
            AfCommand::Service(_) => "service",
            AfCommand::Quota(_) => "quota",
            AfCommand::Sandbox(_) => "sandbox",
            AfCommand::Release(_) => "release",
            AfCommand::Backup(_) => "backup",
            AfCommand::Provision(_) => "provision",
            AfCommand::Maintenance(_) => "maintenance",
            AfCommand::Hosts(_) => "hosts",
            AfCommand::Cluster(_) => "cluster",
        }
    }

    pub fn action_name(&self) -> &'static str {
        match self {
            AfCommand::Help { .. } => "help",
            AfCommand::Version => "version",
            AfCommand::Health => "check",
            AfCommand::Package(cmd) => cmd.action_name(),
            AfCommand::Service(cmd) => cmd.action_name(),
            AfCommand::Quota(cmd) => cmd.action_name(),
            AfCommand::Sandbox(cmd) => cmd.action_name(),
            AfCommand::Release(cmd) => cmd.action_name(),
            AfCommand::Backup(cmd) => cmd.action_name(),
            AfCommand::Provision(cmd) => cmd.action_name(),
            AfCommand::Maintenance(cmd) => cmd.action_name(),
            AfCommand::Hosts(cmd) => cmd.action_name(),
            AfCommand::Cluster(cmd) => cmd.action_name(),
        }
    }
}

/// Package lifecycle subcommands (`af package ...` and legacy `af install/reinstall/remove/list/update/upgrade`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PackageCommand {
    /// Install one or more allowlisted packages via `/v1/package`.
    Install {
        packages: Vec<String>,
        port: Option<i32>,
    },
    /// Reinstall one or more allowlisted packages in-place via `/v1/package` without skipping existing lockfiles.
    Reinstall {
        packages: Vec<String>,
        port: Option<i32>,
    },
    /// Remove one or more allowlisted packages via `/v1/package`.
    Remove { packages: Vec<String>, purge: bool },
    /// Update a specific package (`Some(pkg)`) via `/v1/package` or trigger control-plane update (`None`).
    Update {
        package: Option<String>,
        channel: ReleaseChannel,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_version: Option<String>,
    },
    /// Legacy `af upgrade` alias for control-plane self-update via runner `/v1/self-update`.
    Upgrade { channel: ReleaseChannel },
    /// List all available packages and their `/install/.<lock>.lock` installation status.
    List { installed_only: bool },
    /// Inspect the declarative execution plan and lockfile metadata for a package.
    Info { package: String },
    /// Request cooperative cancellation of an in-flight package operation via `/v1/package/cancel`.
    Cancel { package: String },
}

impl PackageCommand {
    pub const fn action_name(&self) -> &'static str {
        match self {
            PackageCommand::Install { .. } => "install",
            PackageCommand::Reinstall { .. } => "reinstall",
            PackageCommand::Remove { .. } => "remove",
            PackageCommand::Update { .. } => "update",
            PackageCommand::Upgrade { .. } => "upgrade",
            PackageCommand::List { .. } => "list",
            PackageCommand::Info { .. } => "info",
            PackageCommand::Cancel { .. } => "cancel",
        }
    }
}

/// Service control subcommands (`af service <action> <unit>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCommand {
    /// One of `start`, `stop`, `restart`, `reload`, `enable`, `disable`, `status`.
    pub action: String,
    /// Validated systemd unit name (matching `SAFE_SERVICE_NAME`).
    pub service: String,
}

impl ServiceCommand {
    pub fn action_name(&self) -> &'static str {
        match self.action.as_str() {
            "start" => "start",
            "stop" => "stop",
            "restart" => "restart",
            "reload" => "reload",
            "enable" => "enable",
            "disable" => "disable",
            "status" => "status",
            _ => "systemctl",
        }
    }

    /// Generates a validated [`SystemctlRequest`] for `/v1/systemctl`.
    pub fn to_runner_request(&self) -> CliResult<SystemctlRequest> {
        validate_service_request(&self.service, &self.action)
    }
}

/// Disk quota subcommands (`af quota set <username> <size>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum QuotaCommand {
    /// Set user filesystem quota via `af-runner` `/v1/quota` (`setdisk` contract).
    Set { username: String, size: String },
    /// Inspect parsed 1K block calculations for a quota size string without mutating quotas.
    CheckSize { size: String },
}

impl QuotaCommand {
    pub const fn action_name(&self) -> &'static str {
        match self {
            QuotaCommand::Set { .. } => "set",
            QuotaCommand::CheckSize { .. } => "check-size",
        }
    }
}

/// Systemd sandbox hardening subcommands (`af sandbox <apply|render> <package>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SandboxCommand {
    /// Apply systemd drop-in hardening via `af-runner` `/v1/sandbox`.
    Apply { package: String },
    /// Render the canonical drop-in unit file via `af_runner::render_systemd_sandbox_dropin`.
    Render {
        package: String,
        username: Option<String>,
    },
}

impl SandboxCommand {
    pub const fn action_name(&self) -> &'static str {
        match self {
            SandboxCommand::Apply { .. } => "apply",
            SandboxCommand::Render { .. } => "render",
        }
    }
}

/// Execution mode for `af release deploy` and `af release rollback`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDispatchMode {
    /// Dispatch via the privileged runner Unix socket (`/v1/self-update`) using `SelfUpdateRequest`.
    #[default]
    RunnerSocket,
    /// Execute directly in-process via `af_release::ReleaseEngine` (requires root or isolated `--root`).
    LocalEngine,
}

/// Release lifecycle subcommands (`af release <status|deploy|rollback|cleanup|migrate-systemd>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ReleaseCliCommand {
    /// Inspect release slots, active symlink, previous slot, and channel via `af_release::ReleaseEngine::inspect_status`.
    Status { config_path: Option<PathBuf> },
    /// Deploy a release via `/v1/self-update` or `af_release::ReleaseEngine` (`ReleaseCommand::Deploy`).
    Deploy {
        channel: ReleaseChannel,
        #[serde(default)]
        channel_explicit: bool,
        mode: ReleaseDispatchMode,
        offline: bool,
        from_source: bool,
        keep_releases: Option<usize>,
        config_path: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_status_file: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_unit: Option<String>,
    },
    /// Roll back to the previous verified release via `/v1/self-update` or `af_release::ReleaseEngine`.
    Rollback {
        channel: ReleaseChannel,
        #[serde(default)]
        channel_explicit: bool,
        mode: ReleaseDispatchMode,
        config_path: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_status_file: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_unit: Option<String>,
    },
    /// Prune old release slots via `af_release::ReleaseEngine` (`ReleaseCommand::Cleanup`).
    Cleanup {
        keep_releases: Option<usize>,
        config_path: Option<PathBuf>,
    },
    /// Migrate legacy PM2/Apache configurations to bare-metal systemd via `af_release::ReleaseEngine`.
    MigrateSystemd { config_path: Option<PathBuf> },
}

impl ReleaseCliCommand {
    pub const fn action_name(&self) -> &'static str {
        match self {
            ReleaseCliCommand::Status { .. } => "status",
            ReleaseCliCommand::Deploy { .. } => "deploy",
            ReleaseCliCommand::Rollback { .. } => "rollback",
            ReleaseCliCommand::Cleanup { .. } => "cleanup",
            ReleaseCliCommand::MigrateSystemd { .. } => "migrate-systemd",
        }
    }
}

/// Backup creation mode (`sqlite` snapshot vs full `archive` bundle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BackupCreateKind {
    /// Consistent SQLite snapshot (`VACUUM INTO`) + `.sha256` + `.manifest.json`.
    Sqlite,
    /// Full host configuration `.tar.gz` bundle + consistent SQLite snapshot + `.sha256` + `.manifest.json`.
    #[default]
    Archive,
}

/// Host backup, verification, and non-destructive restore preflight subcommands (`af backup ...`)
/// backed by `af-host`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum BackupCliCommand {
    /// Create a verified SQLite snapshot or full host archive backup via `af-host`.
    Create {
        kind: BackupCreateKind,
        backup_dir: Option<PathBuf>,
        db_path: Option<PathBuf>,
        app_version: String,
        chunk_size_bytes: Option<u64>,
        timestamp_slug: Option<String>,
        operator_privileged: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_sqlite_uid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_sqlite_gid: Option<u32>,
    },
    /// List existing `.sqlite` and `.tar.gz` backup artifacts in `backup_dir` via `af_host::list_backup_inventory`.
    List { backup_dir: Option<PathBuf> },
    /// Verify a backup artifact's `.sha256` sidecar and `.manifest.json` via `af_host::verify_backup_artifact`.
    Verify {
        filename: String,
        backup_dir: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_sqlite_uid: Option<u32>,
    },
    /// Run a purely NON-DESTRUCTIVE restore preflight and compatibility check via `af-host`
    /// (`preflight_tar_gz_archive`, `preflight_restore_directory`, or `plan_restore_from_manifest`).
    RestorePreflight {
        filename: String,
        backup_dir: Option<PathBuf>,
        target_root: PathBuf,
        host_version: String,
        max_sqlite_user_version: Option<i64>,
        overwrite_policy: OverwritePolicy,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_sqlite_uid: Option<u32>,
    },
    /// Destructive/staged restore command (`af backup restore ...`).
    /// Without `--confirm-destructive-restore`, intentionally fails closed via
    /// `af_host::execute_destructive_restore` (`HostBackupError::DestructiveRestoreUnsupported`).
    /// When `--confirm-destructive-restore` is supplied, executes `af_host::execute_staged_restore`
    /// with full pre-restore backup, service quiescence, atomic swap, and automatic rollback on failure.
    RestoreDestructive {
        filename: String,
        backup_dir: Option<PathBuf>,
        target_root: Option<PathBuf>,
        #[serde(default)]
        confirm_destructive_restore: bool,
        #[serde(default)]
        allow_overwrite: bool,
        #[serde(default)]
        operator_privileged: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_sqlite_uid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_sqlite_gid: Option<u32>,
    },
    /// Delete a backup artifact and its companion sidecars/chunks via `af_host::delete_backup_artifacts`.
    Delete {
        filename: String,
        backup_dir: Option<PathBuf>,
        operator_privileged: bool,
    },
    /// Prune old backups via `af_host::prune_backup_inventory`.
    Prune {
        backup_dir: Option<PathBuf>,
        max_retained: usize,
        retention_days: i64,
        operator_privileged: bool,
    },
    /// Split an existing backup artifact into fixed-size `.part.NNNNN` chunks via `af_host::split_backup_into_chunks`.
    Chunk {
        filename: String,
        chunk_size_bytes: u64,
        backup_dir: Option<PathBuf>,
        operator_privileged: bool,
    },
    /// Reassemble `.part.NNNNN` chunks and verify SHA-256 via `af_host::assemble_verified_chunks`.
    Assemble {
        output_filename: String,
        expected_sha256: String,
        chunks: Vec<PathBuf>,
        backup_dir: Option<PathBuf>,
        operator_privileged: bool,
    },
    /// Recover an interrupted staged restore using an explicit server-validated `af_host::RecoveryContext`.
    RecoverInterrupted {
        backup_dir: Option<PathBuf>,
        target_root: Option<PathBuf>,
        #[serde(default)]
        operator_privileged: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_sqlite_uid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_sqlite_gid: Option<u32>,
    },
    /// Display the canonical `packages/system/*` maintenance script ownership table from `af-host`.
    OwnershipRegistry,
}

impl BackupCliCommand {
    pub const fn action_name(&self) -> &'static str {
        match self {
            BackupCliCommand::Create { .. } => "create",
            BackupCliCommand::List { .. } => "list",
            BackupCliCommand::Verify { .. } => "verify",
            BackupCliCommand::RestorePreflight { .. } => "restore-preflight",
            BackupCliCommand::RestoreDestructive { .. } => "restore",
            BackupCliCommand::Delete { .. } => "delete",
            BackupCliCommand::Prune { .. } => "prune",
            BackupCliCommand::Chunk { .. } => "chunk",
            BackupCliCommand::Assemble { .. } => "assemble",
            BackupCliCommand::RecoverInterrupted { .. } => "recover-interrupted",
            BackupCliCommand::OwnershipRegistry => "ownership",
        }
    }
}

/// Host maintenance subcommands (`af maintenance ...`, `af tune`, `af sentinel`, `af clean-log`, `af showspace`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum MaintenanceCliCommand {
    /// Apply sysctl network tuning configuration (`af maintenance tune`, `af tune`).
    Tune {
        root: Option<PathBuf>,
        dry_run: bool,
    },
    /// Scan authentication log for brute-force password / invalid user anomalies (`af maintenance sentinel`, `af sentinel`).
    Sentinel {
        log_path: Option<PathBuf>,
        threshold: usize,
    },
    /// Safely truncate oversized .log files under /var/log or /srv/aetherflow/lock (`af maintenance clean-logs`, `af clean-logs`).
    CleanLogs {
        root: Option<PathBuf>,
        max_size_bytes: Option<u64>,
        dry_run: bool,
    },
    /// Inspect disk space usage across /home/<user> entries (`af maintenance showspace`, `af showspace`).
    Showspace {
        root: Option<PathBuf>,
        user: Option<String>,
    },
    /// Display canonical maintenance script ownership registry (`af maintenance ownership`).
    OwnershipRegistry,
}

impl MaintenanceCliCommand {
    pub const fn action_name(&self) -> &'static str {
        match self {
            MaintenanceCliCommand::Tune { .. } => "tune",
            MaintenanceCliCommand::Sentinel { .. } => "sentinel",
            MaintenanceCliCommand::CleanLogs { .. } => "clean-logs",
            MaintenanceCliCommand::Showspace { .. } => "showspace",
            MaintenanceCliCommand::OwnershipRegistry => "ownership",
        }
    }
}

/// Resumable bare-metal provisioning foundation subcommands (`af provision ...`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ProvisionCliCommand {
    /// Run non-destructive host preflight checks (OS release, systemd, paths, lockfile, disk space).
    Preflight {
        os_release_path: Option<PathBuf>,
        require_root: bool,
    },
    /// Inspect persisted `# STATE_VERSION=2` step completion and configuration state.
    Status,
    /// List all canonical `ALL_STEPS` from `setup/modules/06-state.sh` and their Rust migration/foundation status.
    ListSteps,
    /// Run or resume bounded Rust-native provisioning steps with persisted state (`--fresh` resets prior state).
    Run {
        steps: Vec<String>,
        fresh: bool,
        require_root: bool,
    },
    /// Explicitly clear completion markers for `<steps...>` and re-execute them with persisted state.
    Repair {
        steps: Vec<String>,
        require_root: bool,
    },
    /// Safely overlay a configuration file using `.aetherflow-sha256` sidecars and `.user-backup.<ts>` preservation.
    OverlayConfig {
        source: PathBuf,
        target: PathBuf,
        force: bool,
    },
    /// Clear the persisted `/install/.aetherflow.state` file (requires `--confirm`).
    Reset { confirm: bool },
}

impl ProvisionCliCommand {
    pub const fn action_name(&self) -> &'static str {
        match self {
            ProvisionCliCommand::Preflight { .. } => "preflight",
            ProvisionCliCommand::Status => "status",
            ProvisionCliCommand::ListSteps => "list-steps",
            ProvisionCliCommand::Run { .. } => "run",
            ProvisionCliCommand::Repair { .. } => "repair",
            ProvisionCliCommand::OverlayConfig { .. } => "overlay-config",
            ProvisionCliCommand::Reset { .. } => "reset",
        }
    }
}

/// Local DNS and /etc/hosts reconciliation commands mediated by `af-runner`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HostsCliCommand {
    Update { ip: String, domains: Vec<String> },
    Remove { domains: Vec<String> },
    Reconcile { ip: String, domains: Vec<String> },
}

impl HostsCliCommand {
    pub const fn action_name(&self) -> &'static str {
        match self {
            HostsCliCommand::Update { .. } => "update",
            HostsCliCommand::Remove { .. } => "remove",
            HostsCliCommand::Reconcile { .. } => "reconcile",
        }
    }
}

/// Read-only Peer Clustering diagnostic commands (`af cluster ...`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ClusterCliCommand {
    /// Inspect peer link health, WireGuard handshake, grants, exports, mounts, transcode worker, and audit trail.
    Diagnose {
        link: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        db_path: Option<PathBuf>,
    },
}

impl ClusterCliCommand {
    pub const fn action_name(&self) -> &'static str {
        match self {
            ClusterCliCommand::Diagnose { .. } => "diagnose",
        }
    }
}
