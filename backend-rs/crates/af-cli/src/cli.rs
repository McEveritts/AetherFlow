//! Manual command-line parser, typed command AST, and request builders for `af` (`af-cli`).
//!
//! Supports both the legacy `packages/system/af` CLI surface (`af install`, `af remove`, `af list`,
//! `af update`, `af upgrade`, `af -h`) and the unified structured administrative subcommands
//! (`package`, `service`, `quota`, `sandbox`, `release`, `backup`, `provision`, `health`).

use crate::error::{CliError, CliResult};
use af_host::OverwritePolicy;
use af_models::{
    PackageRunnerRequest, QuotaRunnerRequest, SandboxRunnerRequest, SelfUpdateRequest,
    SystemctlRequest,
};
use af_release::{ReleaseChannel, ReleaseCommand, ReleaseOptions};
use af_runner::{
    get_runner_package_definition, parse_quota_size_to_1k_blocks, resolve_runner_socket_path,
    SAFE_PKG_ID, SAFE_QUOTA_SIZE, SAFE_SERVICE_NAME, SAFE_USERNAME,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;

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
    Service,
    Quota,
    Sandbox,
    Release,
    Backup,
    Provision,
    Maintenance,
    Hosts,
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
    /// List all 39 canonical `ALL_STEPS` from `setup/modules/06-state.sh` and their Rust migration/foundation status.
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
    Update {
        ip: String,
        domains: Vec<String>,
    },
    Remove {
        domains: Vec<String>,
    },
    Reconcile {
        ip: String,
        domains: Vec<String>,
    },
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

// ─────────────────────────────────────────────────────────────────────────────
// Typed Runner Request Builders & Validators
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves the legacy `packages/system/af` lockfile name for a package identifier
/// (handling the `autodl` -> `autodlirssi` special case in `packages/system/af`).
pub fn resolve_package_lock_name(pkg_id: &str) -> &str {
    if pkg_id == "autodl" {
        "autodlirssi"
    } else {
        pkg_id
    }
}

/// Validates and builds a [`PackageRunnerRequest`] for `/v1/package` (`install`, `remove`, `update`).
pub fn build_package_runner_request(
    action: &str,
    pkg_id: &str,
    app_port: Option<i32>,
) -> CliResult<PackageRunnerRequest> {
    let clean_pkg = pkg_id.trim();
    if !SAFE_PKG_ID.is_match(clean_pkg) {
        return Err(CliError::Validation(format!(
            "invalid package identifier {:?} (must match ^[a-z0-9][a-z0-9_-]{{0,62}}$)",
            pkg_id
        )));
    }

    // Verify package exists in af-runner's allowlisted package registry (or legacy `autodl` alias)
    let lookup_id = if clean_pkg == "autodl" {
        "autodlirssi"
    } else {
        clean_pkg
    };
    if get_runner_package_definition(lookup_id).is_none()
        && get_runner_package_definition(clean_pkg).is_none()
    {
        return Err(CliError::Validation(format!(
            "unknown or unallowlisted package {:?}",
            clean_pkg
        )));
    }

    let script_prefix = match action {
        "install" | "reinstall" => "installpackage-",
        "remove" => "removepackage-",
        "update" => "updatepackage-",
        other => {
            return Err(CliError::Validation(format!(
                "unsupported package action {:?} (expected install, reinstall, remove, or update)",
                other
            )));
        }
    };

    let port = app_port.unwrap_or(0);
    if !(0..=65535).contains(&port) {
        return Err(CliError::Validation(format!(
            "invalid application port {} (must be 0..=65535)",
            port
        )));
    }

    let target = std::env::var("AF_TARGET_VERSION").ok().filter(|s| !s.trim().is_empty());

    Ok(PackageRunnerRequest {
        action: action.to_string(),
        package_id: clean_pkg.to_string(),
        script_name: format!("{}{}", script_prefix, clean_pkg),
        lifecycle_job_id: String::new(),
        app_port: port,
        delete_data: false,
        expected_target_version: target,
        ..Default::default()
    })
}

/// Validates and builds a [`PackageRunnerRequest`] with an explicit target version.
pub fn build_package_runner_request_with_target(
    action: &str,
    pkg_id: &str,
    app_port: Option<i32>,
    expected_target_version: Option<String>,
) -> CliResult<PackageRunnerRequest> {
    let mut req = build_package_runner_request(action, pkg_id, app_port)?;
    if let Some(target) = expected_target_version.filter(|s| !s.trim().is_empty()) {
        req.expected_target_version = Some(target.trim().to_string());
    }
    Ok(req)
}

/// Validates and builds a [`SystemctlRequest`] for `/v1/systemctl`.
pub fn validate_service_request(service: &str, action: &str) -> CliResult<SystemctlRequest> {
    let clean_action = action.trim().to_ascii_lowercase();
    if !ALLOWED_SYSTEMCTL_ACTIONS.contains(&clean_action.as_str()) {
        return Err(CliError::Validation(format!(
            "unsupported service action {:?} (allowed: {})",
            action,
            ALLOWED_SYSTEMCTL_ACTIONS.join(", ")
        )));
    }

    let clean_service = service.trim();
    if !SAFE_SERVICE_NAME.is_match(clean_service) {
        return Err(CliError::Validation(format!(
            "invalid systemd service name {:?}",
            service
        )));
    }

    Ok(SystemctlRequest {
        service: clean_service.to_string(),
        action: clean_action,
        lifecycle_job_id: String::new(),
    })
}

/// Validates and builds a [`QuotaRunnerRequest`] for `/v1/quota`, reusing
/// `af_runner::SAFE_USERNAME`, `af_runner::SAFE_QUOTA_SIZE`, and `af_runner::parse_quota_size_to_1k_blocks`.
pub fn build_quota_runner_request(username: &str, size: &str) -> CliResult<(QuotaRunnerRequest, u64)> {
    let clean_user = username.trim();
    if !SAFE_USERNAME.is_match(clean_user) {
        return Err(CliError::Validation(format!(
            "invalid username {:?} (must match ^[a-z_][a-z0-9_-]{{0,31}}$)",
            username
        )));
    }

    let clean_size = size.trim();
    if !SAFE_QUOTA_SIZE.is_match(clean_size) {
        return Err(CliError::Validation(format!(
            "invalid quota size {:?} (expected integer bytes or K/M/G/T suffix, e.g. 500G)",
            size
        )));
    }

    let (blocks_1k, _) = parse_quota_size_to_1k_blocks(clean_size)
        .ok_or_else(|| CliError::Validation(format!("invalid quota size {:?}", size)))?;

    Ok((
        QuotaRunnerRequest {
            username: clean_user.to_string(),
            size: clean_size.to_string(),
        },
        blocks_1k,
    ))
}

/// Validates and builds a [`SandboxRunnerRequest`] for `/v1/sandbox`, reusing `af_runner::SAFE_PKG_ID`.
pub fn build_sandbox_runner_request(package: &str) -> CliResult<SandboxRunnerRequest> {
    let clean_pkg = package.trim();
    if !SAFE_PKG_ID.is_match(clean_pkg) {
        return Err(CliError::Validation(format!(
            "invalid package identifier for sandbox: {:?}",
            package
        )));
    }

    Ok(SandboxRunnerRequest {
        package: clean_pkg.to_string(),
        package_id: clean_pkg.to_string(),
        lifecycle_job_id: String::new(),
    })
}

/// Builds a [`SelfUpdateRequest`] for `/v1/self-update` and validates it using
/// `af_release::validate_self_update_request`.
pub fn build_self_update_runner_request(
    command: &str,
    channel: ReleaseChannel,
) -> CliResult<SelfUpdateRequest> {
    let req = SelfUpdateRequest {
        command: command.to_string(),
        channel: channel.as_str().to_string(),
    };
    af_release::validate_self_update_request(&req)
        .map_err(|resp| CliError::Validation(resp.error))?;
    Ok(req)
}

/// Converts a [`ReleaseCliCommand`] into an [`af_release::ReleaseOptions`] struct for direct `ReleaseEngine` execution.
pub fn build_release_engine_options(
    cmd: &ReleaseCliCommand,
    dry_run: bool,
) -> Option<ReleaseOptions> {
    match cmd {
        ReleaseCliCommand::Status { .. } => None,
        ReleaseCliCommand::Deploy {
            channel,
            offline,
            from_source,
            ..
        } => Some(ReleaseOptions {
            command: ReleaseCommand::Deploy,
            channel: *channel,
            dry_run,
            offline: *offline,
            from_source: *from_source,
        }),
        ReleaseCliCommand::Rollback { channel, .. } => Some(ReleaseOptions {
            command: ReleaseCommand::Rollback,
            channel: *channel,
            dry_run,
            offline: false,
            from_source: false,
        }),
        ReleaseCliCommand::Cleanup { .. } => Some(ReleaseOptions {
            command: ReleaseCommand::Cleanup,
            channel: ReleaseChannel::Stable,
            dry_run,
            offline: false,
            from_source: false,
        }),
        ReleaseCliCommand::MigrateSystemd { .. } => Some(ReleaseOptions {
            command: ReleaseCommand::MigrateSystemd,
            channel: ReleaseChannel::Stable,
            dry_run,
            offline: false,
            from_source: false,
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Manual CLI Parser Implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Parses raw command-line arguments (excluding `argv[0]`) into a [`ParsedInvocation`].
///
/// If `raw_args` is empty, returns `CliError::Unsupported` explaining that the legacy interactive
/// `whiptail` TUI menu remains in `packages/system/af` while `af` (Rust) requires an explicit
/// subcommand or `--help`.
pub fn parse_cli_args<I, S>(raw_args: I) -> CliResult<ParsedInvocation>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let tokens: Vec<String> = raw_args
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect();

    let mut global = GlobalOptions::default();
    let mut positional: Vec<String> = Vec::new();
    let mut help_requested = false;
    let mut version_requested = false;

    let mut idx = 0usize;
    while idx < tokens.len() {
        let arg = &tokens[idx];
        match arg.as_str() {
            "--json" => {
                global.json = true;
                idx += 1;
            }
            "--dry-run" | "-n" => {
                global.dry_run = true;
                idx += 1;
            }
            "--socket" => {
                let val = tokens.get(idx + 1).ok_or_else(|| {
                    CliError::Usage("--socket requires a Unix socket path".to_string())
                })?;
                if val.trim().is_empty() {
                    return Err(CliError::Usage("--socket path must not be empty".to_string()));
                }
                global.socket_path = PathBuf::from(val);
                idx += 2;
            }
            s if s.starts_with("--socket=") => {
                let val = s.trim_start_matches("--socket=");
                if val.trim().is_empty() {
                    return Err(CliError::Usage("--socket path must not be empty".to_string()));
                }
                global.socket_path = PathBuf::from(val);
                idx += 1;
            }
            "--root" => {
                let val = tokens.get(idx + 1).ok_or_else(|| {
                    CliError::Usage("--root requires a directory path".to_string())
                })?;
                if val.trim().is_empty() {
                    return Err(CliError::Usage("--root path must not be empty".to_string()));
                }
                global.root = Some(PathBuf::from(val));
                idx += 2;
            }
            s if s.starts_with("--root=") => {
                let val = s.trim_start_matches("--root=");
                if val.trim().is_empty() {
                    return Err(CliError::Usage("--root path must not be empty".to_string()));
                }
                global.root = Some(PathBuf::from(val));
                idx += 1;
            }
            "-h" | "--help" => {
                help_requested = true;
                idx += 1;
            }
            "-V" | "--version" => {
                version_requested = true;
                idx += 1;
            }
            _ => {
                positional.push(arg.clone());
                idx += 1;
            }
        }
    }

    if version_requested && positional.is_empty() {
        return Ok(ParsedInvocation {
            global,
            command: AfCommand::Version,
        });
    }

    if help_requested {
        let topic = positional
            .first()
            .map(|s| parse_help_topic(s))
            .unwrap_or(HelpTopic::General);
        return Ok(ParsedInvocation {
            global,
            command: AfCommand::Help { topic },
        });
    }

    if positional.is_empty() {
        return Err(CliError::Unsupported {
            operation: "interactive-tui".to_string(),
            reason: "interactive whiptail menu is not supported in non-interactive Rust af-cli; pass a subcommand (e.g. 'af --help', 'af list', 'af package ...', 'af service ...', 'af release ...', 'af backup ...', 'af provision ...')".to_string(),
        });
    }

    let head = positional[0].as_str();
    let rest = &positional[1..];

    let command = match head {
        "help" => {
            let topic = rest
                .first()
                .map(|s| parse_help_topic(s))
                .unwrap_or(HelpTopic::General);
            AfCommand::Help { topic }
        }
        "version" => AfCommand::Version,
        "health" | "ping" => {
            if !rest.is_empty() {
                return Err(CliError::Usage(format!(
                    "unexpected arguments for 'af health': {}",
                    rest.join(" ")
                )));
            }
            AfCommand::Health
        }

        // Legacy `packages/system/af` top-level package shorthands:
        "install" => AfCommand::Package(parse_package_install_args(rest)?),
        "reinstall" => AfCommand::Package(parse_package_reinstall_args(rest)?),
        "remove" | "uninstall" => AfCommand::Package(parse_package_remove_args(rest)?),
        "list" => AfCommand::Package(parse_package_list_args(rest)?),
        "update" => AfCommand::Package(parse_package_update_args(rest)?),
        "upgrade" => AfCommand::Package(parse_package_upgrade_args(rest)?),

        // Structured domain subcommands:
        "package" | "pkg" => AfCommand::Package(parse_package_subcommand(rest)?),
        "service" | "svc" | "systemctl" => AfCommand::Service(parse_service_subcommand(rest)?),
        "quota" | "setdisk" => AfCommand::Quota(parse_quota_subcommand(head, rest)?),
        "sandbox" => AfCommand::Sandbox(parse_sandbox_subcommand(rest)?),
        "release" | "self-update" => AfCommand::Release(parse_release_subcommand(rest)?),
        "backup" => AfCommand::Backup(parse_backup_subcommand(rest)?),
        "provision" | "setup" => AfCommand::Provision(parse_provision_subcommand(rest)?),
        "maintenance" => AfCommand::Maintenance(parse_maintenance_subcommand(rest)?),
        "tune" | "af-tune" => AfCommand::Maintenance(parse_tune_args(rest)?),
        "sentinel" | "af-sentinel" => AfCommand::Maintenance(parse_sentinel_args(rest)?),
        "clean-log" | "clean-logs" => AfCommand::Maintenance(parse_clean_log_args(rest)?),
        "showspace" => AfCommand::Maintenance(parse_showspace_args(rest)?),

        unknown => {
            return Err(CliError::Usage(format!(
                "unknown command {:?}. Run 'af --help' for usage.",
                unknown
            )));
        }
    };

    Ok(ParsedInvocation { global, command })
}

fn parse_help_topic(raw: &str) -> HelpTopic {
    match raw.trim().to_ascii_lowercase().as_str() {
        "package" | "pkg" | "install" | "reinstall" | "remove" | "list" => HelpTopic::Package,
        "service" | "svc" | "systemctl" => HelpTopic::Service,
        "quota" | "setdisk" => HelpTopic::Quota,
        "sandbox" => HelpTopic::Sandbox,
        "release" | "self-update" | "update" | "upgrade" => HelpTopic::Release,
        "backup" => HelpTopic::Backup,
        "provision" | "setup" => HelpTopic::Provision,
        "maintenance" | "tune" | "sentinel" | "clean-log" | "clean-logs" | "showspace" => {
            HelpTopic::Maintenance
        }
        "hosts" | "dns" => HelpTopic::Hosts,
        _ => HelpTopic::General,
    }
}

pub fn parse_hosts_subcommand(args: &[String]) -> CliResult<HostsCliCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "missing hosts subcommand (expected: update, remove, reconcile)".to_string(),
        ));
    };
    let tail = &args[1..];
    match sub {
        "update" => {
            if tail.len() < 2 {
                return Err(CliError::Usage("usage: af hosts update <ip> <domain...>".to_string()));
            }
            Ok(HostsCliCommand::Update {
                ip: tail[0].clone(),
                domains: tail[1..].to_vec(),
            })
        }
        "remove" => {
            if tail.is_empty() {
                return Err(CliError::Usage("usage: af hosts remove <domain...>".to_string()));
            }
            Ok(HostsCliCommand::Remove {
                domains: tail.to_vec(),
            })
        }
        "reconcile" => {
            let ip = tail.first().cloned().unwrap_or_else(|| "127.0.0.1".to_string());
            let domains = if tail.len() > 1 {
                tail[1..].to_vec()
            } else {
                Vec::new()
            };
            Ok(HostsCliCommand::Reconcile { ip, domains })
        }
        other => Err(CliError::Usage(format!(
            "unknown hosts subcommand {:?} (expected: update, remove, reconcile)",
            other
        ))),
    }
}

fn parse_package_subcommand(args: &[String]) -> CliResult<PackageCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "missing package subcommand (expected: install, reinstall, remove, update, upgrade, list, info, cancel)"
                .to_string(),
        ));
    };
    let tail = &args[1..];
    match sub {
        "install" => parse_package_install_args(tail),
        "reinstall" => parse_package_reinstall_args(tail),
        "remove" | "uninstall" => parse_package_remove_args(tail),
        "update" => parse_package_update_args(tail),
        "upgrade" => parse_package_upgrade_args(tail),
        "list" => parse_package_list_args(tail),
        "info" | "inspect" => {
            if tail.len() != 1 {
                return Err(CliError::Usage(
                    "usage: af package info <package>".to_string(),
                ));
            }
            let _ = build_package_runner_request("install", &tail[0], None)?;
            Ok(PackageCommand::Info {
                package: tail[0].trim().to_string(),
            })
        }
        "cancel" => {
            if tail.len() != 1 {
                return Err(CliError::Usage(
                    "usage: af package cancel <package>".to_string(),
                ));
            }
            let _ = build_package_runner_request("install", &tail[0], None)?;
            Ok(PackageCommand::Cancel {
                package: tail[0].trim().to_string(),
            })
        }
        other => Err(CliError::Usage(format!(
            "unknown package subcommand {:?} (expected: install, reinstall, remove, update, upgrade, list, info, cancel)",
            other
        ))),
    }
}

fn parse_package_install_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut packages = Vec::new();
    let mut port: Option<i32> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                let raw_port = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--port requires a numeric port value".to_string())
                })?;
                let parsed = raw_port.parse::<i32>().map_err(|_| {
                    CliError::Validation(format!("invalid port number {:?}", raw_port))
                })?;
                port = Some(parsed);
                i += 2;
            }
            s if s.starts_with("--port=") => {
                let raw_port = s.trim_start_matches("--port=");
                let parsed = raw_port.parse::<i32>().map_err(|_| {
                    CliError::Validation(format!("invalid port number {:?}", raw_port))
                })?;
                port = Some(parsed);
                i += 1;
            }
            pkg => {
                if pkg.starts_with('-') {
                    return Err(CliError::Usage(format!(
                        "unknown flag for package install: {}",
                        pkg
                    )));
                }
                let _ = build_package_runner_request("install", pkg, port)?;
                packages.push(pkg.trim().to_string());
                i += 1;
            }
        }
    }

    if packages.is_empty() {
        return Err(CliError::Usage(
            "usage: af [package] install <pkg1> [pkg2...] [--port <port>]".to_string(),
        ));
    }

    if packages.len() > 1 && port.is_some() {
        return Err(CliError::Usage(
            "--port may only be specified when installing a single package".to_string(),
        ));
    }

    Ok(PackageCommand::Install { packages, port })
}

fn parse_package_reinstall_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut packages = Vec::new();
    let mut port: Option<i32> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                let raw_port = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--port requires a numeric port value".to_string())
                })?;
                let parsed = raw_port.parse::<i32>().map_err(|_| {
                    CliError::Validation(format!("invalid port number {:?}", raw_port))
                })?;
                port = Some(parsed);
                i += 2;
            }
            s if s.starts_with("--port=") => {
                let raw_port = s.trim_start_matches("--port=");
                let parsed = raw_port.parse::<i32>().map_err(|_| {
                    CliError::Validation(format!("invalid port number {:?}", raw_port))
                })?;
                port = Some(parsed);
                i += 1;
            }
            pkg => {
                if pkg.starts_with('-') {
                    return Err(CliError::Usage(format!(
                        "unknown flag for package reinstall: {}",
                        pkg
                    )));
                }
                let _ = build_package_runner_request("reinstall", pkg, port)?;
                packages.push(pkg.trim().to_string());
                i += 1;
            }
        }
    }

    if packages.is_empty() {
        return Err(CliError::Usage(
            "usage: af [package] reinstall <pkg1> [pkg2...] [--port <port>]".to_string(),
        ));
    }

    if packages.len() > 1 && port.is_some() {
        return Err(CliError::Usage(
            "--port may only be specified when reinstalling a single package".to_string(),
        ));
    }

    Ok(PackageCommand::Reinstall { packages, port })
}

fn parse_package_remove_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut packages = Vec::new();
    let mut purge = false;
    for arg in args {
        if arg == "--purge" {
            purge = true;
            continue;
        }
        if arg.starts_with('-') {
            return Err(CliError::Usage(format!(
                "unknown flag for package remove: {}",
                arg
            )));
        }
        let _ = build_package_runner_request("remove", arg, None)?;
        packages.push(arg.trim().to_string());
    }

    if packages.is_empty() {
        return Err(CliError::Usage(
            "usage: af [package] remove <pkg1> [pkg2...]".to_string(),
        ));
    }

    Ok(PackageCommand::Remove { packages, purge })
}

fn parse_package_list_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut installed_only = false;
    for arg in args {
        match arg.as_str() {
            "--installed" => installed_only = true,
            other => {
                return Err(CliError::Usage(format!(
                    "unknown argument for package list: {}",
                    other
                )));
            }
        }
    }
    Ok(PackageCommand::List { installed_only })
}

fn parse_package_update_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut package: Option<String> = None;
    let mut channel = ReleaseChannel::Stable;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--channel" | "-c" => {
                let raw_ch = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage(
                        "--channel requires stable or nightly".to_string(),
                    )
                })?;
                channel = ReleaseChannel::from_str(raw_ch)?;
                i += 2;
            }
            s if s.starts_with("--channel=") => {
                channel = ReleaseChannel::from_str(s.trim_start_matches("--channel="))?;
                i += 1;
            }
            "--target-version" | "-t" => {
                let raw_target = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--target-version requires a version argument".to_string())
                })?;
                std::env::set_var("AF_TARGET_VERSION", raw_target.trim());
                i += 2;
            }
            s if s.starts_with("--target-version=") => {
                let raw_target = s.trim_start_matches("--target-version=");
                std::env::set_var("AF_TARGET_VERSION", raw_target.trim());
                i += 1;
            }
            pkg => {
                if pkg.starts_with('-') {
                    return Err(CliError::Usage(format!(
                        "unknown flag for update: {}",
                        pkg
                    )));
                }
                if package.is_some() {
                    return Err(CliError::Usage(
                        "usage: af [package] update [package_id] [--channel <channel>]"
                            .to_string(),
                    ));
                }
                let _ = build_package_runner_request("update", pkg, None)?;
                package = Some(pkg.trim().to_string());
                i += 1;
            }
        }
    }
    Ok(PackageCommand::Update { package, channel })
}

fn parse_package_upgrade_args(args: &[String]) -> CliResult<PackageCommand> {
    let mut channel = ReleaseChannel::Stable;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--channel" | "-c" => {
                let raw_ch = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage(
                        "--channel requires stable or nightly".to_string(),
                    )
                })?;
                channel = ReleaseChannel::from_str(raw_ch)?;
                i += 2;
            }
            s if s.starts_with("--channel=") => {
                channel = ReleaseChannel::from_str(s.trim_start_matches("--channel="))?;
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unexpected argument for upgrade: {}",
                    other
                )));
            }
        }
    }
    Ok(PackageCommand::Upgrade { channel })
}

fn parse_service_subcommand(args: &[String]) -> CliResult<ServiceCommand> {
    if args.len() != 2 {
        return Err(CliError::Usage(
            "usage: af service <start|stop|restart|reload|enable|disable|status> <service_name>"
                .to_string(),
        ));
    }
    let req = validate_service_request(&args[1], &args[0])?;
    Ok(ServiceCommand {
        action: req.action,
        service: req.service,
    })
}

fn parse_quota_subcommand(head: &str, args: &[String]) -> CliResult<QuotaCommand> {
    // Support both `af setdisk <user> <size>` and `af quota set <user> <size>`
    if head == "setdisk" && args.len() == 2 {
        let (req, _) = build_quota_runner_request(&args[0], &args[1])?;
        return Ok(QuotaCommand::Set {
            username: req.username,
            size: req.size,
        });
    }

    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "usage: af quota <set|check-size> ...".to_string(),
        ));
    };
    let tail = &args[1..];
    match sub {
        "set" => {
            if tail.len() != 2 {
                return Err(CliError::Usage(
                    "usage: af quota set <username> <size>".to_string(),
                ));
            }
            let (req, _) = build_quota_runner_request(&tail[0], &tail[1])?;
            Ok(QuotaCommand::Set {
                username: req.username,
                size: req.size,
            })
        }
        "check-size" | "parse" => {
            if tail.len() != 1 {
                return Err(CliError::Usage(
                    "usage: af quota check-size <size>".to_string(),
                ));
            }
            let clean = tail[0].trim();
            if !SAFE_QUOTA_SIZE.is_match(clean) {
                return Err(CliError::Validation(format!(
                    "invalid quota size {:?}",
                    tail[0]
                )));
            }
            let _ = parse_quota_size_to_1k_blocks(clean)
                .ok_or_else(|| CliError::Validation(format!("invalid quota size {:?}", clean)))?;
            Ok(QuotaCommand::CheckSize {
                size: clean.to_string(),
            })
        }
        other => Err(CliError::Unsupported {
            operation: format!("quota {}", other),
            reason: "only 'af quota set <username> <size>' (runner /v1/quota) and 'af quota check-size <size>' are backed by verified af-runner contracts".to_string(),
        }),
    }
}

fn parse_sandbox_subcommand(args: &[String]) -> CliResult<SandboxCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "usage: af sandbox <apply|render> <package> [--user <username>]".to_string(),
        ));
    };
    let tail = &args[1..];
    match sub {
        "apply" => {
            if tail.len() != 1 {
                return Err(CliError::Usage(
                    "usage: af sandbox apply <package>".to_string(),
                ));
            }
            let req = build_sandbox_runner_request(&tail[0])?;
            Ok(SandboxCommand::Apply {
                package: req.package_id,
            })
        }
        "render" | "preview" => {
            if tail.is_empty() {
                return Err(CliError::Usage(
                    "usage: af sandbox render <package> [--user <username>]".to_string(),
                ));
            }
            let req = build_sandbox_runner_request(&tail[0])?;
            let mut username: Option<String> = None;
            let mut i = 1usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--user" | "-u" => {
                        let u = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--user requires a username".to_string())
                        })?;
                        if !SAFE_USERNAME.is_match(u.trim()) {
                            return Err(CliError::Validation(format!(
                                "invalid username {:?}",
                                u
                            )));
                        }
                        username = Some(u.trim().to_string());
                        i += 2;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for sandbox render: {}",
                            other
                        )));
                    }
                }
            }
            Ok(SandboxCommand::Render {
                package: req.package_id,
                username,
            })
        }
        other => Err(CliError::Usage(format!(
            "unknown sandbox subcommand {:?} (expected: apply, render)",
            other
        ))),
    }
}

fn parse_release_subcommand(args: &[String]) -> CliResult<ReleaseCliCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "usage: af release <status|deploy|rollback|cleanup|migrate-systemd> [options]"
                .to_string(),
        ));
    };
    let tail = &args[1..];

    let mut channel = ReleaseChannel::Stable;
    let mut mode = ReleaseDispatchMode::RunnerSocket;
    let mut offline = false;
    let mut from_source = false;
    let mut keep_releases: Option<usize> = None;
    let mut config_path: Option<PathBuf> = None;
    let mut job_status_file: Option<PathBuf> = None;
    let mut job_unit: Option<String> = None;

    let mut i = 0usize;
    while i < tail.len() {
        match tail[i].as_str() {
            "--channel" | "-c" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage(
                        "--channel requires stable or nightly".to_string(),
                    )
                })?;
                channel = ReleaseChannel::from_str(val)?;
                i += 2;
            }
            s if s.starts_with("--channel=") => {
                channel = ReleaseChannel::from_str(s.trim_start_matches("--channel="))?;
                i += 1;
            }
            "--local" | "--direct-engine" => {
                mode = ReleaseDispatchMode::LocalEngine;
                i += 1;
            }
            "--via-runner" => {
                mode = ReleaseDispatchMode::RunnerSocket;
                i += 1;
            }
            "--offline" => {
                offline = true;
                mode = ReleaseDispatchMode::LocalEngine;
                i += 1;
            }
            "--from-source" => {
                from_source = true;
                mode = ReleaseDispatchMode::LocalEngine;
                i += 1;
            }
            "--keep-releases" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--keep-releases requires an integer >= 2".to_string())
                })?;
                let parsed = val.parse::<usize>().map_err(|_| {
                    CliError::Validation(format!("invalid --keep-releases count {:?}", val))
                })?;
                if parsed < 2 {
                    return Err(CliError::Validation(
                        "--keep-releases must be at least 2".to_string(),
                    ));
                }
                keep_releases = Some(parsed);
                i += 2;
            }
            "--config" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--config requires a path to release-manager.conf".to_string())
                })?;
                config_path = Some(PathBuf::from(val));
                i += 2;
            }
            s if s.starts_with("--config=") => {
                let val = s.trim_start_matches("--config=");
                if val.is_empty() {
                    return Err(CliError::Usage(
                        "--config requires a path to release-manager.conf".to_string(),
                    ));
                }
                config_path = Some(PathBuf::from(val));
                i += 1;
            }
            "--job-status-file" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage(
                        "--job-status-file requires a path to a status JSON file".to_string(),
                    )
                })?;
                job_status_file = Some(PathBuf::from(val));
                i += 2;
            }
            s if s.starts_with("--job-status-file=") => {
                let val = s.trim_start_matches("--job-status-file=");
                if val.is_empty() {
                    return Err(CliError::Usage(
                        "--job-status-file requires a path to a status JSON file".to_string(),
                    ));
                }
                job_status_file = Some(PathBuf::from(val));
                i += 1;
            }
            "--job-unit" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--job-unit requires a transient unit name".to_string())
                })?;
                job_unit = Some(val.clone());
                i += 2;
            }
            s if s.starts_with("--job-unit=") => {
                let val = s.trim_start_matches("--job-unit=");
                if val.is_empty() {
                    return Err(CliError::Usage(
                        "--job-unit requires a transient unit name".to_string(),
                    ));
                }
                job_unit = Some(val.to_string());
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown option for 'af release {}': {}",
                    sub, other
                )));
            }
        }
    }

    match sub {
        "status" => Ok(ReleaseCliCommand::Status { config_path }),
        "deploy" => {
            let _ = build_self_update_runner_request("deploy", channel)?;
            Ok(ReleaseCliCommand::Deploy {
                channel,
                mode,
                offline,
                from_source,
                keep_releases,
                config_path,
                job_status_file,
                job_unit,
            })
        }
        "rollback" => {
            let _ = build_self_update_runner_request("rollback", channel)?;
            Ok(ReleaseCliCommand::Rollback {
                channel,
                mode,
                config_path,
                job_status_file,
                job_unit,
            })
        }
        "cleanup" => Ok(ReleaseCliCommand::Cleanup {
            keep_releases,
            config_path,
        }),
        "migrate-systemd" => Ok(ReleaseCliCommand::MigrateSystemd { config_path }),
        other => Err(CliError::Usage(format!(
            "unknown release subcommand {:?} (expected: status, deploy, rollback, cleanup, migrate-systemd)",
            other
        ))),
    }
}

fn parse_backup_subcommand(args: &[String]) -> CliResult<BackupCliCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "usage: af backup <create|list|verify|restore-preflight|restore|delete|prune|chunk|assemble|ownership> [options]".to_string(),
        ));
    };
    let tail = &args[1..];

    match sub {
        "create" => {
            let mut kind = BackupCreateKind::Archive;
            let mut backup_dir: Option<PathBuf> = None;
            let mut db_path: Option<PathBuf> = None;
            let mut app_version = "v4.0.0".to_string();
            let mut chunk_size_bytes: Option<u64> = None;
            let mut timestamp_slug: Option<String> = None;
            let mut operator_privileged = false;
            let mut trusted_sqlite_uid: Option<u32> = None;
            let mut trusted_sqlite_gid: Option<u32> = None;

            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--sqlite-only" | "--db-only" => {
                        kind = BackupCreateKind::Sqlite;
                        i += 1;
                    }
                    "--archive" => {
                        kind = BackupCreateKind::Archive;
                        i += 1;
                    }
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--db-path" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--db-path requires a SQLite file path".to_string())
                        })?;
                        db_path = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--app-version" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--app-version requires a semver string".to_string())
                        })?;
                        let _ = af_host::parse_semver_triplet(val)?;
                        app_version = val.clone();
                        i += 2;
                    }
                    "--chunk-size" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--chunk-size requires a size (e.g. 50M or 1048576)".to_string())
                        })?;
                        chunk_size_bytes = Some(parse_byte_size_arg(val)?);
                        i += 2;
                    }
                    "--timestamp" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--timestamp requires a slug".to_string())
                        })?;
                        timestamp_slug = Some(val.clone());
                        i += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    "--trusted-sqlite-uid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-uid requires a numeric UID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-uid {:?}", val))
                        })?;
                        trusted_sqlite_uid = Some(parsed);
                        i += 2;
                    }
                    "--trusted-sqlite-gid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-gid requires a numeric GID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-gid {:?}", val))
                        })?;
                        trusted_sqlite_gid = Some(parsed);
                        i += 2;
                    }
                    other => {
                        if !other.starts_with('-') && chunk_size_bytes.is_none() {
                            chunk_size_bytes = Some(parse_byte_size_arg(other)?);
                            i += 1;
                        } else {
                            return Err(CliError::Usage(format!(
                                "unknown argument for 'af backup create': {}",
                                other
                            )));
                        }
                    }
                }
            }

            Ok(BackupCliCommand::Create {
                kind,
                backup_dir,
                db_path,
                app_version,
                chunk_size_bytes,
                timestamp_slug,
                operator_privileged,
                trusted_sqlite_uid,
                trusted_sqlite_gid,
            })
        }
        "list" | "ls" => {
            let mut backup_dir: Option<PathBuf> = None;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unknown argument for 'af backup list': {}",
                            other
                        )));
                    }
                }
            }
            Ok(BackupCliCommand::List { backup_dir })
        }
        "verify" => {
            let mut filename: Option<String> = None;
            let mut backup_dir: Option<PathBuf> = None;
            let mut trusted_sqlite_uid: Option<u32> = None;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--trusted-sqlite-uid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-uid requires a numeric UID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-uid {:?}", val))
                        })?;
                        trusted_sqlite_uid = Some(parsed);
                        i += 2;
                    }
                    arg if !arg.starts_with('-') && filename.is_none() => {
                        let clean = af_host::validate_backup_filename(arg)?;
                        filename = Some(clean);
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup verify': {}",
                            other
                        )));
                    }
                }
            }
            let filename = filename.ok_or_else(|| {
                CliError::Usage(
                    "usage: af backup verify <filename> [--backup-dir <dir>]".to_string(),
                )
            })?;
            Ok(BackupCliCommand::Verify {
                filename,
                backup_dir,
                trusted_sqlite_uid,
            })
        }
        "restore-preflight" | "plan-restore" | "preflight" => {
            let mut filename: Option<String> = None;
            let mut backup_dir: Option<PathBuf> = None;
            let mut target_root: Option<PathBuf> = None;
            let mut host_version = "v4.0.0".to_string();
            let mut max_sqlite_user_version: Option<i64> = None;
            let mut overwrite_policy = OverwritePolicy::RejectExisting;
            let mut trusted_sqlite_uid: Option<u32> = None;

            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--target-root" | "--staging-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--target-root requires a staging directory path".to_string())
                        })?;
                        target_root = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--host-version" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--host-version requires a semver string".to_string())
                        })?;
                        let _ = af_host::parse_semver_triplet(val)?;
                        host_version = val.clone();
                        i += 2;
                    }
                    "--max-sqlite-user-version" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--max-sqlite-user-version requires an integer".to_string())
                        })?;
                        let parsed = val.parse::<i64>().map_err(|_| {
                            CliError::Validation(format!(
                                "invalid --max-sqlite-user-version {:?}",
                                val
                            ))
                        })?;
                        max_sqlite_user_version = Some(parsed);
                        i += 2;
                    }
                    "--allow-staging-overwrite" => {
                        overwrite_policy = OverwritePolicy::AllowRegularFilesInStaging;
                        i += 1;
                    }
                    "--trusted-sqlite-uid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-uid requires a numeric UID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-uid {:?}", val))
                        })?;
                        trusted_sqlite_uid = Some(parsed);
                        i += 2;
                    }
                    arg if !arg.starts_with('-') && filename.is_none() => {
                        let clean = af_host::validate_backup_filename(arg)?;
                        filename = Some(clean);
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup restore-preflight': {}",
                            other
                        )));
                    }
                }
            }

            let filename = filename.ok_or_else(|| {
                CliError::Usage(
                    "usage: af backup restore-preflight <filename> --target-root <staging_dir> [--backup-dir <dir>]".to_string(),
                )
            })?;
            let target_root = target_root.ok_or_else(|| {
                CliError::Usage(
                    "af backup restore-preflight requires --target-root <staging_dir>".to_string(),
                )
            })?;

            Ok(BackupCliCommand::RestorePreflight {
                filename,
                backup_dir,
                target_root,
                host_version,
                max_sqlite_user_version,
                overwrite_policy,
                trusted_sqlite_uid,
            })
        }
        "restore" => {
            let mut filename: Option<String> = None;
            let mut backup_dir: Option<PathBuf> = None;
            let mut target_root: Option<PathBuf> = None;
            let mut confirm_destructive_restore = false;
            let mut allow_overwrite = false;
            let mut operator_privileged = false;
            let mut trusted_sqlite_uid: Option<u32> = None;
            let mut trusted_sqlite_gid: Option<u32> = None;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--target-root" | "--staging-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--target-root requires a directory path".to_string())
                        })?;
                        target_root = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--confirm-destructive-restore" | "--confirm" => {
                        confirm_destructive_restore = true;
                        i += 1;
                    }
                    "--allow-overwrite" | "--allow-staging-overwrite" => {
                        allow_overwrite = true;
                        i += 1;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    "--trusted-sqlite-uid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-uid requires a numeric UID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-uid {:?}", val))
                        })?;
                        trusted_sqlite_uid = Some(parsed);
                        i += 2;
                    }
                    "--trusted-sqlite-gid" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-gid requires a numeric GID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-gid {:?}", val))
                        })?;
                        trusted_sqlite_gid = Some(parsed);
                        i += 2;
                    }
                    arg if !arg.starts_with('-') && filename.is_none() => {
                        let clean = af_host::validate_backup_filename(arg)?;
                        filename = Some(clean);
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }
            let filename = filename.unwrap_or_else(|| "unspecified".to_string());
            Ok(BackupCliCommand::RestoreDestructive {
                filename,
                backup_dir,
                target_root,
                confirm_destructive_restore,
                allow_overwrite,
                operator_privileged,
                trusted_sqlite_uid,
                trusted_sqlite_gid,
            })
        }
        "delete" | "rm" => {
            let mut filename: Option<String> = None;
            let mut backup_dir: Option<PathBuf> = None;
            let mut operator_privileged = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    arg if !arg.starts_with('-') && filename.is_none() => {
                        let clean = af_host::validate_backup_filename(arg)?;
                        filename = Some(clean);
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup delete': {}",
                            other
                        )));
                    }
                }
            }
            let filename = filename.ok_or_else(|| {
                CliError::Usage(
                    "usage: af backup delete <filename> [--backup-dir <dir>]".to_string(),
                )
            })?;
            Ok(BackupCliCommand::Delete {
                filename,
                backup_dir,
                operator_privileged,
            })
        }
        "prune" => {
            let mut backup_dir: Option<PathBuf> = None;
            let mut max_retained = af_host::DEFAULT_MAX_RETAINED_BACKUPS;
            let mut retention_days = af_host::DEFAULT_RETENTION_DAYS;
            let mut operator_privileged = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--max-retained" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--max-retained requires an integer".to_string())
                        })?;
                        max_retained = val.parse::<usize>().map_err(|_| {
                            CliError::Validation(format!("invalid --max-retained {:?}", val))
                        })?;
                        i += 2;
                    }
                    "--retention-days" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--retention-days requires an integer".to_string())
                        })?;
                        retention_days = val.parse::<i64>().map_err(|_| {
                            CliError::Validation(format!("invalid --retention-days {:?}", val))
                        })?;
                        i += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup prune': {}",
                            other
                        )));
                    }
                }
            }
            Ok(BackupCliCommand::Prune {
                backup_dir,
                max_retained,
                retention_days,
                operator_privileged,
            })
        }
        "chunk" => {
            let mut filename: Option<String> = None;
            let mut chunk_size_bytes: Option<u64> = None;
            let mut backup_dir: Option<PathBuf> = None;
            let mut operator_privileged = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--size" | "--chunk-size" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--size requires a byte size".to_string())
                        })?;
                        chunk_size_bytes = Some(parse_byte_size_arg(val)?);
                        i += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    arg if !arg.starts_with('-') => {
                        if filename.is_none() {
                            filename = Some(af_host::validate_backup_filename(arg)?);
                        } else if chunk_size_bytes.is_none() {
                            chunk_size_bytes = Some(parse_byte_size_arg(arg)?);
                        } else {
                            return Err(CliError::Usage(format!(
                                "unexpected argument for 'af backup chunk': {}",
                                arg
                            )));
                        }
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup chunk': {}",
                            other
                        )));
                    }
                }
            }
            let filename = filename.ok_or_else(|| {
                CliError::Usage("usage: af backup chunk <filename> <size>".to_string())
            })?;
            let chunk_size_bytes = chunk_size_bytes.unwrap_or(50 * 1024 * 1024);
            Ok(BackupCliCommand::Chunk {
                filename,
                chunk_size_bytes,
                backup_dir,
                operator_privileged,
            })
        }
        "assemble" => {
            let mut output_filename: Option<String> = None;
            let mut expected_sha256: Option<String> = None;
            let mut chunks: Vec<PathBuf> = Vec::new();
            let mut backup_dir: Option<PathBuf> = None;
            let mut operator_privileged = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--output" | "-o" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--output requires a filename".to_string())
                        })?;
                        output_filename = Some(af_host::validate_backup_filename(val)?);
                        i += 2;
                    }
                    "--sha256" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--sha256 requires a 64-character hex digest".to_string())
                        })?;
                        expected_sha256 = Some(val.trim().to_ascii_lowercase());
                        i += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        i += 1;
                    }
                    arg if !arg.starts_with('-') => {
                        chunks.push(PathBuf::from(arg));
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup assemble': {}",
                            other
                        )));
                    }
                }
            }
            let output_filename = output_filename.ok_or_else(|| {
                CliError::Usage(
                    "usage: af backup assemble --output <filename> --sha256 <hex> <chunk1> [chunk2...]".to_string(),
                )
            })?;
            let expected_sha256 = expected_sha256.ok_or_else(|| {
                CliError::Usage("af backup assemble requires --sha256 <hex>".to_string())
            })?;
            if chunks.is_empty() {
                return Err(CliError::Usage(
                    "af backup assemble requires at least one chunk file path".to_string(),
                ));
            }
            Ok(BackupCliCommand::Assemble {
                output_filename,
                expected_sha256,
                chunks,
                backup_dir,
                operator_privileged,
            })
        }
        "recover" | "recover-interrupted" => {
            let mut backup_dir: Option<PathBuf> = None;
            let mut target_root: Option<PathBuf> = None;
            let mut operator_privileged = false;
            let mut trusted_sqlite_uid: Option<u32> = None;
            let mut trusted_sqlite_gid: Option<u32> = None;
            let mut index = 0usize;
            while index < tail.len() {
                match tail[index].as_str() {
                    "--backup-dir" => {
                        let val = tail.get(index + 1).ok_or_else(|| {
                            CliError::Usage("--backup-dir requires a directory path".to_string())
                        })?;
                        backup_dir = Some(PathBuf::from(val));
                        index += 2;
                    }
                    "--target-root" | "--staging-dir" => {
                        let val = tail.get(index + 1).ok_or_else(|| {
                            CliError::Usage("--target-root requires a directory path".to_string())
                        })?;
                        target_root = Some(PathBuf::from(val));
                        index += 2;
                    }
                    "--operator-privileged" => {
                        operator_privileged = true;
                        index += 1;
                    }
                    "--trusted-sqlite-uid" => {
                        let val = tail.get(index + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-uid requires a numeric UID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-uid {:?}", val))
                        })?;
                        trusted_sqlite_uid = Some(parsed);
                        index += 2;
                    }
                    "--trusted-sqlite-gid" => {
                        let val = tail.get(index + 1).ok_or_else(|| {
                            CliError::Usage("--trusted-sqlite-gid requires a numeric GID".to_string())
                        })?;
                        let parsed = val.parse::<u32>().map_err(|_| {
                            CliError::Validation(format!("invalid --trusted-sqlite-gid {:?}", val))
                        })?;
                        trusted_sqlite_gid = Some(parsed);
                        index += 2;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af backup {}': {}",
                            sub, other
                        )));
                    }
                }
            }
            Ok(BackupCliCommand::RecoverInterrupted {
                backup_dir,
                target_root,
                operator_privileged,
                trusted_sqlite_uid,
                trusted_sqlite_gid,
            })
        }
        "ownership" | "registry" => Ok(BackupCliCommand::OwnershipRegistry),
        other => Err(CliError::Usage(format!(
            "unknown backup subcommand {:?} (expected: create, list, verify, restore-preflight, restore, recover, delete, prune, chunk, assemble, ownership)",
            other
        ))),
    }
}

fn parse_provision_subcommand(args: &[String]) -> CliResult<ProvisionCliCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "usage: af provision <preflight|status|list-steps|run|resume|repair|overlay-config|reset> [options]".to_string(),
        ));
    };
    let tail = &args[1..];

    match sub {
        "preflight" => {
            let mut os_release_path: Option<PathBuf> = None;
            let mut require_root = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--os-release" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--os-release requires a file path".to_string())
                        })?;
                        os_release_path = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--require-root" => {
                        require_root = true;
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af provision preflight': {}",
                            other
                        )));
                    }
                }
            }
            Ok(ProvisionCliCommand::Preflight {
                os_release_path,
                require_root,
            })
        }
        "status" => Ok(ProvisionCliCommand::Status),
        "list-steps" | "steps" => Ok(ProvisionCliCommand::ListSteps),
        "run" | "resume" => {
            let mut steps = Vec::new();
            let mut fresh = false;
            let mut require_root = true;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--fresh" => {
                        fresh = true;
                        i += 1;
                    }
                    "--resume" => {
                        fresh = false;
                        i += 1;
                    }
                    "--no-root-check" => {
                        require_root = false;
                        i += 1;
                    }
                    "--step" | "-s" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--step requires a canonical step ID".to_string())
                        })?;
                        steps.push(val.trim().to_string());
                        i += 2;
                    }
                    arg if !arg.starts_with('-') => {
                        steps.push(arg.trim().to_string());
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af provision {}': {}",
                            sub, other
                        )));
                    }
                }
            }
            Ok(ProvisionCliCommand::Run {
                steps,
                fresh,
                require_root,
            })
        }
        "repair" => {
            let mut steps = Vec::new();
            let mut require_root = true;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--no-root-check" => {
                        require_root = false;
                        i += 1;
                    }
                    "--step" | "-s" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--step requires a canonical step ID".to_string())
                        })?;
                        steps.push(val.trim().to_string());
                        i += 2;
                    }
                    arg if !arg.starts_with('-') => {
                        steps.push(arg.trim().to_string());
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af provision repair': {}",
                            other
                        )));
                    }
                }
            }
            if steps.is_empty() {
                return Err(CliError::Usage(
                    "usage: af provision repair <step1> [step2...]".to_string(),
                ));
            }
            Ok(ProvisionCliCommand::Repair {
                steps,
                require_root,
            })
        }
        "overlay-config" => {
            let mut source: Option<PathBuf> = None;
            let mut target: Option<PathBuf> = None;
            let mut force = false;
            let mut i = 0usize;
            while i < tail.len() {
                match tail[i].as_str() {
                    "--source" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--source requires a file path".to_string())
                        })?;
                        source = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--target" => {
                        let val = tail.get(i + 1).ok_or_else(|| {
                            CliError::Usage("--target requires a file path".to_string())
                        })?;
                        target = Some(PathBuf::from(val));
                        i += 2;
                    }
                    "--force" => {
                        force = true;
                        i += 1;
                    }
                    arg if !arg.starts_with('-') => {
                        if source.is_none() {
                            source = Some(PathBuf::from(arg));
                        } else if target.is_none() {
                            target = Some(PathBuf::from(arg));
                        } else {
                            return Err(CliError::Usage(format!(
                                "unexpected argument for 'af provision overlay-config': {}",
                                arg
                            )));
                        }
                        i += 1;
                    }
                    other => {
                        return Err(CliError::Usage(format!(
                            "unexpected argument for 'af provision overlay-config': {}",
                            other
                        )));
                    }
                }
            }
            let source = source.ok_or_else(|| {
                CliError::Usage(
                    "usage: af provision overlay-config <source_path> <target_path> [--force]"
                        .to_string(),
                )
            })?;
            let target = target.ok_or_else(|| {
                CliError::Usage(
                    "usage: af provision overlay-config <source_path> <target_path> [--force]"
                        .to_string(),
                )
            })?;
            Ok(ProvisionCliCommand::OverlayConfig {
                source,
                target,
                force,
            })
        }
        "reset" => {
            let confirm = tail.iter().any(|a| a == "--confirm" || a == "--yes");
            Ok(ProvisionCliCommand::Reset { confirm })
        }
        other => Err(CliError::Usage(format!(
            "unknown provision subcommand {:?} (expected: preflight, status, list-steps, run, resume, repair, overlay-config, reset)",
            other
        ))),
    }
}

fn parse_tune_args(tail: &[String]) -> CliResult<MaintenanceCliCommand> {
    let mut root: Option<PathBuf> = None;
    let mut dry_run = false;
    let mut i = 0usize;
    while i < tail.len() {
        match tail[i].as_str() {
            "--root" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--root requires a directory path".to_string())
                })?;
                root = Some(PathBuf::from(val));
                i += 2;
            }
            "--dry-run" | "-n" => {
                dry_run = true;
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unexpected argument for 'af tune': {}",
                    other
                )));
            }
        }
    }
    Ok(MaintenanceCliCommand::Tune { root, dry_run })
}

fn parse_sentinel_args(tail: &[String]) -> CliResult<MaintenanceCliCommand> {
    let mut log_path: Option<PathBuf> = None;
    let mut threshold = af_host::DEFAULT_SENTINEL_THRESHOLD;
    let mut i = 0usize;
    while i < tail.len() {
        match tail[i].as_str() {
            "--log-path" | "--file" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--log-path requires a file path".to_string())
                })?;
                log_path = Some(PathBuf::from(val));
                i += 2;
            }
            "--threshold" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--threshold requires a number".to_string())
                })?;
                threshold = val
                    .parse::<usize>()
                    .map_err(|_| CliError::Usage(format!("invalid threshold {:?}", val)))?;
                i += 2;
            }
            arg if !arg.starts_with('-') && log_path.is_none() => {
                log_path = Some(PathBuf::from(arg));
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unexpected argument for 'af sentinel': {}",
                    other
                )));
            }
        }
    }
    Ok(MaintenanceCliCommand::Sentinel {
        log_path,
        threshold,
    })
}

fn parse_clean_log_args(tail: &[String]) -> CliResult<MaintenanceCliCommand> {
    let mut root: Option<PathBuf> = None;
    let mut max_size_bytes: Option<u64> = None;
    let mut dry_run = false;
    let mut i = 0usize;
    while i < tail.len() {
        match tail[i].as_str() {
            "--root" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--root requires a directory path".to_string())
                })?;
                root = Some(PathBuf::from(val));
                i += 2;
            }
            "--max-size" | "--size" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--max-size requires a byte size (e.g. 10MB)".to_string())
                })?;
                max_size_bytes = Some(parse_byte_size_arg(val)?);
                i += 2;
            }
            "--dry-run" | "-n" => {
                dry_run = true;
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unexpected argument for 'af clean-logs': {}",
                    other
                )));
            }
        }
    }
    Ok(MaintenanceCliCommand::CleanLogs {
        root,
        max_size_bytes,
        dry_run,
    })
}

fn parse_showspace_args(tail: &[String]) -> CliResult<MaintenanceCliCommand> {
    let mut root: Option<PathBuf> = None;
    let mut user: Option<String> = None;
    let mut i = 0usize;
    while i < tail.len() {
        match tail[i].as_str() {
            "--root" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--root requires a directory path".to_string())
                })?;
                root = Some(PathBuf::from(val));
                i += 2;
            }
            "--user" => {
                let val = tail.get(i + 1).ok_or_else(|| {
                    CliError::Usage("--user requires a username".to_string())
                })?;
                user = Some(val.clone());
                i += 2;
            }
            arg if !arg.starts_with('-') && user.is_none() => {
                user = Some(arg.to_string());
                i += 1;
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unexpected argument for 'af showspace': {}",
                    other
                )));
            }
        }
    }
    Ok(MaintenanceCliCommand::Showspace { root, user })
}

fn parse_maintenance_subcommand(args: &[String]) -> CliResult<MaintenanceCliCommand> {
    let Some(sub) = args.first().map(|s| s.as_str()) else {
        return Err(CliError::Usage(
            "missing maintenance subcommand (expected: tune, sentinel, clean-logs, showspace, ownership)".to_string(),
        ));
    };
    let tail = &args[1..];
    match sub {
        "tune" => parse_tune_args(tail),
        "sentinel" => parse_sentinel_args(tail),
        "clean-log" | "clean-logs" => parse_clean_log_args(tail),
        "showspace" => parse_showspace_args(tail),
        "ownership" | "registry" => Ok(MaintenanceCliCommand::OwnershipRegistry),
        unknown => Err(CliError::Usage(format!(
            "unknown maintenance subcommand {:?}. Expected: tune, sentinel, clean-logs, showspace, ownership",
            unknown
        ))),
    }
}

/// Parses human-friendly byte size strings (`"512"`, `"64K"`, `"50M"`, `"2G"`) into `u64` bytes.
pub fn parse_byte_size_arg(raw: &str) -> CliResult<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliError::Validation("size value must not be empty".to_string()));
    }
    let upper = trimmed.to_ascii_uppercase();
    let (num_part, mult) = if let Some(v) = upper.strip_suffix("KB") {
        (v, 1024u64)
    } else if let Some(v) = upper.strip_suffix('K') {
        (v, 1024u64)
    } else if let Some(v) = upper.strip_suffix("MB") {
        (v, 1024u64 * 1024)
    } else if let Some(v) = upper.strip_suffix('M') {
        (v, 1024u64 * 1024)
    } else if let Some(v) = upper.strip_suffix("GB") {
        (v, 1024u64 * 1024 * 1024)
    } else if let Some(v) = upper.strip_suffix('G') {
        (v, 1024u64 * 1024 * 1024)
    } else {
        (upper.as_str(), 1u64)
    };

    let base = num_part.trim().parse::<u64>().map_err(|_| {
        CliError::Validation(format!("invalid byte size specification {:?}", raw))
    })?;
    let bytes = base.checked_mul(mult).ok_or_else(|| {
        CliError::Validation(format!("byte size overflow for {:?}", raw))
    })?;
    if bytes == 0 {
        return Err(CliError::Validation(
            "chunk/byte size must be greater than zero".to_string(),
        ));
    }
    Ok(bytes)
}

/// Renders structured human help text for the requested [`HelpTopic`].
pub fn render_help_text(topic: HelpTopic) -> String {
    match topic {
        HelpTopic::General => "\
AetherFlow Unified Rust Administrative CLI (`af` v4.0.0)
Pure bare-metal systemd + Apache2 control plane (Zero Docker).

USAGE:
  af [GLOBAL_OPTIONS] <COMMAND> [ARGS...]

GLOBAL OPTIONS:
  --json                Emit machine-readable JSON response envelope
  --socket <path>       Override runner Unix socket (default: /run/aetherflow/runner.sock)
  --root <dir>          Override filesystem root for isolated inspection/testing
  --dry-run, -n         Validate & plan without mutating live services or disk state
  -h, --help            Print help (or 'af help <topic>')
  -V, --version         Print version information

LEGACY COMPATIBILITY SHORTHANDS (`packages/system/af`):
  af install <pkg1> [pkg2...] [--port <port>]
  af reinstall <pkg1> [pkg2...] [--port <port>]
  af remove <pkg1> [pkg2...] [--purge]
  af list [--installed]
  af update [pkg] [--channel <stable|nightly>]
  af upgrade [--channel <stable|nightly>]

ADMINISTRATIVE DOMAINS:
  package     Runner-mediated package install/reinstall/remove/update/list/info (/v1/package)
  service     Runner-mediated systemd service control (/v1/systemctl)
  quota       Runner-mediated user disk quota enforcement (/v1/quota)
  sandbox     Runner-mediated systemd unit drop-in hardening (/v1/sandbox)
  release     Atomic release status, deploy, rollback, cleanup & systemd migration (af-release)
  backup      Host backup bundle create/list/verify & non-destructive restore-preflight (af-host)
  provision   Resumable bare-metal provisioning foundation & safe config overlay (STATE_VERSION=2)
  maintenance Host maintenance utilities: tune, sentinel, clean-logs, showspace (af-host)
  health      Verify connectivity to the privileged runner Unix socket (/v1/health)

NOTE ON UNSUPPORTED INTERACTIVE / DESTRUCTIVE FLOWS:
  - Calling 'af' with no arguments returns an explicit unsupported error (the interactive
    whiptail TUI remains in the legacy shell wrapper).
  - 'af backup restore' fails closed by design; use 'af backup restore-preflight' for
    non-destructive verification before offline maintenance window replacement.
"
        .to_string(),
        HelpTopic::Package => "\
USAGE:
  af package install <pkg1> [pkg2...] [--port <port>]
  af package reinstall <pkg1> [pkg2...] [--port <port>]
  af package remove <pkg1> [pkg2...] [--purge]
  af package update [pkg] [--channel <stable|nightly>]
  af package upgrade [--channel <stable|nightly>]
  af package list [--installed]
  af package info <pkg>

Mediates privileged package lifecycle operations over /run/aetherflow/runner.sock (/v1/package)
using af-runner's declarative installer primitives and script allowlist.
"
        .to_string(),
        HelpTopic::Service => "\
USAGE:
  af service <start|stop|restart|reload|enable|disable|status> <service_name>

Dispatches validated SystemctlRequest payloads to /run/aetherflow/runner.sock (/v1/systemctl).
"
        .to_string(),
        HelpTopic::Quota => "\
USAGE:
  af quota set <username> <size>
  af quota check-size <size>

Dispatches validated QuotaRunnerRequest payloads to /run/aetherflow/runner.sock (/v1/quota)
and reuses af-runner's 1K block quota parser without duplicating setquota logic.
"
        .to_string(),
        HelpTopic::Sandbox => "\
USAGE:
  af sandbox apply <package>
  af sandbox render <package> [--user <username>]

Applies or previews systemd security drop-ins via af-runner (/v1/sandbox & render_systemd_sandbox_dropin).
"
        .to_string(),
        HelpTopic::Release => "\
USAGE:
  af release status [--config <path>]
  af release deploy [--channel <stable|nightly>] [--local] [--binary <path>] [--frontend-dist <dir>] [--version <ver>] [--keep-releases <n>] [--skip-apache-reload]
  af release rollback [--channel <stable|nightly>] [--local] [--skip-apache-reload]
  af release cleanup [--keep-releases <n>] [--config <path>]
  af release migrate-systemd [--skip-apache-reload] [--config <path>]

Reuses af-release's ReleaseEngine and af-runner's /v1/self-update contract without inventing wire formats.
"
        .to_string(),
        HelpTopic::Backup => "\
USAGE:
  af backup create [--archive | --sqlite-only] [--backup-dir <dir>] [--db-path <file>] [--app-version <ver>] [--chunk-size <size>] [--operator-privileged]
  af backup list [--backup-dir <dir>]
  af backup verify <filename> [--backup-dir <dir>]
  af backup restore-preflight <filename> --target-root <staging_dir> [--backup-dir <dir>] [--host-version <ver>] [--allow-staging-overwrite]
  af backup delete <filename> [--backup-dir <dir>] [--operator-privileged]
  af backup prune [--backup-dir <dir>] [--max-retained <n>] [--retention-days <days>] [--operator-privileged]
  af backup chunk <filename> <size> [--backup-dir <dir>] [--operator-privileged]
  af backup assemble --output <filename> --sha256 <hex> <chunk1> [chunk2...] [--backup-dir <dir>] [--operator-privileged]
  af backup ownership

Backed by af-host. Live destructive restore ('af backup restore') is intentionally unsupported and fails closed.
"
        .to_string(),
        HelpTopic::Provision => "\
USAGE:
  af provision preflight [--os-release <path>] [--require-root]
  af provision status
  af provision list-steps
  af provision run [<step1> ...] [--fresh | --resume] [--no-root-check]
  af provision repair <step1> [step2...] [--no-root-check]
  af provision overlay-config <source> <target> [--force]
  af provision reset --confirm

Implements persisted resumable step state (/install/.aetherflow.state # STATE_VERSION=2),
preflight verification, explicit repair semantics, and SHA-256 sidecar config overlays.
Retains setup/AetherFlow-Setup for interactive shell bootstrap.
"
        .to_string(),
        HelpTopic::Maintenance => "\
USAGE:
  af maintenance tune [--root <path>] [--dry-run]
  af maintenance sentinel [--log-path <path>] [--threshold <n>]
  af maintenance clean-logs [--root <path>] [--max-size <bytes>] [--dry-run]
  af maintenance showspace [--root <path>] [--user <user>]
  af maintenance ownership

SHORTHANDS:
  af tune [--root <path>] [--dry-run]
  af sentinel [--log-path <path>] [--threshold <n>]
  af clean-logs [--root <path>] [--max-size <bytes>] [--dry-run]
  af showspace [--root <path>] [--user <user>]

Pure-Rust replacements for legacy packages/system/* utilities:
  tune:      writes /etc/sysctl.d/99-aetherflow-tune.conf with optimized network buffers
  sentinel:  scans /var/log/auth.log for failed login attempts and identifies offending IPs
  clean-logs: safely truncates oversized .log files under /var/log or /srv/aetherflow/lock
  showspace: calculates disk usage for /home/<user> entries with human-readable formatting
"
        .to_string(),
        HelpTopic::Hosts => "\
USAGE:
  af hosts <update|remove|reconcile> [ip] [domains...]

Manage local /etc/hosts, dnsmasq, and Pi-hole DNS mappings.
  update <ip> <domains...>      Map domains to IP in managed block
  remove <domains...>           Remove domains from hosts
  reconcile [ip] [domains...]   Reconcile /etc/hosts to authoritative domain set (defaults to 127.0.0.1)
"
        .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hosts_subcommand() {
        let update_args = vec!["update".to_string(), "10.0.0.1".to_string(), "app.aether.local".to_string()];
        let cmd = parse_hosts_subcommand(&update_args).unwrap();
        assert_eq!(cmd, HostsCliCommand::Update {
            ip: "10.0.0.1".to_string(),
            domains: vec!["app.aether.local".to_string()],
        });

        let remove_args = vec!["remove".to_string(), "app.aether.local".to_string()];
        let cmd = parse_hosts_subcommand(&remove_args).unwrap();
        assert_eq!(cmd, HostsCliCommand::Remove {
            domains: vec!["app.aether.local".to_string()],
        });

        let reconcile_args = vec!["reconcile".to_string(), "127.0.0.1".to_string(), "app1.aether.local".to_string()];
        let cmd = parse_hosts_subcommand(&reconcile_args).unwrap();
        assert_eq!(cmd, HostsCliCommand::Reconcile {
            ip: "127.0.0.1".to_string(),
            domains: vec!["app1.aether.local".to_string()],
        });

        let reconcile_empty = vec!["reconcile".to_string()];
        let cmd = parse_hosts_subcommand(&reconcile_empty).unwrap();
        assert_eq!(cmd, HostsCliCommand::Reconcile {
            ip: "127.0.0.1".to_string(),
            domains: Vec::new(),
        });

        assert_eq!(parse_help_topic("hosts"), HelpTopic::Hosts);
        assert_eq!(parse_help_topic("dns"), HelpTopic::Hosts);
        assert!(render_help_text(HelpTopic::Hosts).contains("af hosts <update|remove|reconcile>"));
    }
}
