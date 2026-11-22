use af_models::{
    AppMetaRunnerRequest, BackupRunnerRequest, BackupRunnerResponse, NetworkRunnerRequest, Package,
    PackageAutomation, PackageLifecycleSnapshotRequest, PackageRunnerRequest,
    PluginRunnerStartRequest, PluginRunnerStatusRequest, PluginRunnerStatusResponse,
    PluginRunnerStopRequest, PluginRunnerTokenRotateRequest, QuotaRunnerRequest,
    RunnerApacheVhostRequest, RunnerResponse, SandboxRunnerRequest, SelfUpdateJobStatus,
    SelfUpdateRequest, SelfUpdateStatusRequest, SystemctlRequest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerPeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostsUpdateRequest {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub action: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub domain: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub domains: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provider_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provider_domains: Option<Vec<String>>,
}

pub type HostsRunnerRequest = HostsUpdateRequest;
use axum::body::Body;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Mutex;

pub use af_host;
pub use af_release;

mod adguard_dns;
pub mod blueprint;
pub mod bounded_command;
pub mod job_receipts;
mod legacy_stream_output;
#[cfg(all(test, unix))]
mod lifecycle_tests;
pub mod network;
pub mod package_executor;
pub use package_executor::check_domain_tls_ready;
pub mod package_lifecycle;
pub mod package_purge;
pub use package_purge::{
    candidate_package_sqlite_dbs, format_ambiguous_purge_error, inspect_package_purge_state,
    inspect_package_purge_state_with_conn, PackagePurgeEligibility, PackagePurgeInspection,
};
pub mod plugins;
pub use plugins::PluginRunnerError;
pub mod probe_metadata;
pub mod quota;

tokio::task_local! {
    pub static PACKAGE_JOB_ID: String;
    static PACKAGE_MAINTENANCE_LEASE: std::sync::Arc<af_release::ReleaseLockGuard>;
}

pub fn current_package_job_id() -> String {
    PACKAGE_JOB_ID.try_with(Clone::clone).unwrap_or_default()
}
pub use package_executor::*;

pub const DEFAULT_RUNNER_SOCKET_PATH: &str = "/run/aetherflow/runner.sock";

pub(crate) const EMBEDDED_PACKAGES_JSON: &str = include_str!("../../../../config/packages.json");
pub(crate) const EMBEDDED_AUTOMATION_JSON: &str =
    include_str!("../../../../config/package_automation.json");

pub(crate) static PACKAGE_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
pub(crate) static BACKUP_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub static SAFE_SCRIPT_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$").unwrap());
pub static SAFE_PKG_ID: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$").unwrap());
pub static SAFE_SERVICE_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$").unwrap());
pub static SAFE_USERNAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z_][a-z0-9_-]{0,31}$").unwrap());
pub static SAFE_USERNAME_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.-]{1,64}$").unwrap());
pub static SAFE_QUOTA_SIZE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9]+(?:\.[0-9]+)?\s*[KMGTPEkmgtpe]?[Bb]?$").unwrap());
pub use SAFE_QUOTA_SIZE as SAFE_QUOTA_SIZE_REGEX;

static ALLOWED_SERVICE_ACTIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "start",
        "stop",
        "restart",
        "reload",
        "enable",
        "disable",
        "status",
        "heal",
        "restart-deferred",
    ]
    .into()
});
static ALLOWED_BACKUP_ACTIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "create",
        "create_sqlite",
        "create_archive",
        "verify",
        "list",
        "delete",
        "prune",
        "restore_preflight",
        "restore_execute",
        "recover_interrupted",
    ]
    .into()
});

/// Release engine execution mode selected by the runner for `/v1/self-update`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseEngineMode {
    /// Executed by the typed Rust `af-release` engine (`ReleaseManager`).
    NativeRustRelease,
    /// Executed by the legacy `deploy/release-manager.sh` script.
    LegacyBashRelease,
}

/// Evaluates release engine selection given rollout flags (`_rust_enabled`, `force_bash`).
///
/// Certified `af-release` (`NativeRustRelease`) is the default engine unless an explicit Bash
/// escape hatch (`force_bash`) is requested.
pub fn select_release_engine_with_flags(rust_enabled: bool, force_bash: bool) -> ReleaseEngineMode {
    let _ = rust_enabled;
    if force_bash {
        ReleaseEngineMode::LegacyBashRelease
    } else {
        ReleaseEngineMode::NativeRustRelease
    }
}

/// Selects the active release engine for `/v1/self-update`.
///
/// Rollout control:
/// Certified `af-release` (`NativeRustRelease`) is enabled by default. The legacy
/// `AETHERFLOW_ENABLE_RUST_RELEASE`, `AETHERFLOW_USE_RUST_RELEASE`, and
/// `AETHERFLOW_RELEASE_ENGINE=rust` aliases remain accepted for backwards compatibility.
/// Setting `AETHERFLOW_FORCE_BASH_RELEASE=1`/`true` or `AETHERFLOW_RELEASE_ENGINE=bash`
/// selects the legacy Bash escape hatch (`LegacyBashRelease`).
pub fn select_release_engine() -> ReleaseEngineMode {
    let enabled = |key| {
        env::var(key)
            .is_ok_and(|value| value.trim() == "1" || value.trim().eq_ignore_ascii_case("true"))
    };
    let engine = env::var("AETHERFLOW_RELEASE_ENGINE").unwrap_or_default();
    let rust_enabled = engine.trim().eq_ignore_ascii_case("rust")
        || enabled("AETHERFLOW_ENABLE_RUST_RELEASE")
        || enabled("AETHERFLOW_USE_RUST_RELEASE");
    let force_bash =
        engine.trim().eq_ignore_ascii_case("bash") || enabled("AETHERFLOW_FORCE_BASH_RELEASE");
    select_release_engine_with_flags(rust_enabled, force_bash)
}

pub fn resolve_runner_socket_path() -> String {
    if let Ok(p) = env::var("AETHERFLOW_RUNNER_SOCK") {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    DEFAULT_RUNNER_SOCKET_PATH.to_string()
}

pub fn runner_socket_path() -> String {
    resolve_runner_socket_path()
}

pub fn is_runner_available() -> bool {
    let p = resolve_runner_socket_path();
    let path = Path::new(&p);
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        fs::metadata(path)
            .map(|meta| meta.file_type().is_socket())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.exists()
    }
}

pub fn resolve_package_script_path(action: &str, script_name: &str) -> Option<PathBuf> {
    resolve_package_script_in_roots(action, script_name, &package_script_roots())
}

fn package_script_roots() -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from("/opt/AetherFlow/current/packages/package"),
        PathBuf::from("/opt/AetherFlow/packages/package"),
        PathBuf::from("/usr/local/bin/AetherFlow/package"),
        PathBuf::from("packages/package"),
        PathBuf::from("../packages/package"),
        PathBuf::from("../../packages/package"),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            roots.push(exe_dir.join("packages/package"));
            roots.push(exe_dir.join("../packages/package"));
        }
    }
    roots
}

fn resolve_package_script_in_roots(
    action: &str,
    script_name: &str,
    roots: &[PathBuf],
) -> Option<PathBuf> {
    if !SAFE_SCRIPT_NAME.is_match(script_name) {
        return None;
    }
    let subdir = match action {
        "install" | "reinstall" => "install",
        "remove" | "uninstall" => "remove",
        "update" => "update",
        _ => return None,
    };

    let mut script_names = vec![script_name.to_string()];
    if subdir == "update" {
        if let Some(package) = script_name.strip_prefix("updatepackage-") {
            script_names.push(format!("installpackage-{package}"));
        } else if let Some(package) = script_name.strip_prefix("installpackage-") {
            script_names.insert(0, format!("updatepackage-{package}"));
        }
    }
    let subdirs: &[&str] = if subdir == "update" {
        &["update", "install"]
    } else {
        &[subdir]
    };

    // Finish all fallbacks within a release before consulting stale roots.
    for root in roots {
        for dir in subdirs {
            for name in &script_names {
                let candidate = root.join(dir).join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

pub fn resolve_release_manager_script() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("AETHERFLOW_RELEASE_MANAGER_SCRIPT") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let candidate_path = PathBuf::from(trimmed);
            if candidate_path.is_file() {
                return Some(candidate_path);
            }
        }
    }
    let mut candidates = vec![
        PathBuf::from("/opt/AetherFlow/current/deploy/release-manager.sh"),
        PathBuf::from("/opt/AetherFlow/deploy/release-manager.sh"),
        PathBuf::from("deploy/release-manager.sh"),
        PathBuf::from("../deploy/release-manager.sh"),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("deploy/release-manager.sh"));
            candidates.push(exe_dir.join("../deploy/release-manager.sh"));
        }
    }
    candidates.into_iter().find(|cand| cand.is_file())
}

pub fn resolve_systemd_run_binary() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("AETHERFLOW_SYSTEMD_RUN_BIN") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let candidate_path = PathBuf::from(trimmed);
            if candidate_path.is_file() {
                return Some(candidate_path);
            }
        }
    }
    let candidates = [
        PathBuf::from("/usr/bin/systemd-run"),
        PathBuf::from("/bin/systemd-run"),
    ];
    candidates.into_iter().find(|cand| cand.is_file())
}

pub fn resolve_af_cli_binary() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("AETHERFLOW_CLI_BIN") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let candidate_path = PathBuf::from(trimmed);
            if candidate_path.is_file() {
                return Some(candidate_path);
            }
        }
    }
    let mut candidates = vec![
        PathBuf::from("/opt/AetherFlow/current/bin/af"),
        PathBuf::from("/opt/AetherFlow/current/af"),
        PathBuf::from("/usr/local/bin/af"),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("bin/af"));
            candidates.push(exe_dir.join("af"));
        }
    }
    candidates.into_iter().find(|cand| cand.is_file())
}

/// Builds the Axum router for the Privileged Root Socket Daemon (`aetherflow-api runner`).
pub fn build_runner_router() -> Router {
    Router::new()
        .route("/v1/health", get(handle_health).post(handle_health))
        .route("/v1/systemctl", post(handle_systemctl))
        .route("/v1/package", post(handle_package))
        .route("/v1/package/cancel", post(handle_package_cancel))
        .route(
            "/v1/package/lifecycle-snapshot",
            post(handle_package_lifecycle_snapshot),
        )
        .route("/v1/self-update", post(handle_self_update))
        .route("/v1/self-update/status", post(handle_self_update_status))
        .route("/v1/backup", post(handle_backup))
        .route("/v1/sandbox", post(handle_sandbox))
        .route("/v1/hosts", post(handle_hosts))
        .route("/v1/blueprint/apply", post(handle_blueprint_apply))
        .route("/v1/network", post(handle_network))
        .route("/v1/quota", post(handle_quota))
        .route("/v1/quota/usage", post(quota::handle))
        .route("/v1/app-meta", post(handle_app_meta))
        .route(
            "/v1/package/probe-version",
            post(handle_package_version_probe),
        )
        .route(
            "/v1/dispatcharr-credentials",
            post(handle_dispatcharr_credentials),
        )
        .route("/v1/ingress/vhost", post(handle_ingress_vhost))
        .route("/v1/certbot-sync", post(handle_certbot_sync))
        .route("/v1/plugins/start", post(plugins::handle_plugin_start))
        .route("/v1/plugins/stop", post(plugins::handle_plugin_stop))
        .route("/v1/plugins/status", post(plugins::handle_plugin_status))
        .route(
            "/v1/plugins/token",
            post(plugins::handle_plugin_token_rotate),
        )
}

async fn handle_health() -> Json<RunnerResponse> {
    Json(RunnerResponse {
        success: true,
        output: "ready".to_string(),
        error: String::new(),
    })
}

pub fn resolve_sandbox_script_path() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("AETHERFLOW_SANDBOX_SCRIPT") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if p.is_file() {
                return Some(p);
            }
        }
    }

    let mut candidates = vec![
        PathBuf::from("/opt/AetherFlow/current/packages/system/af-systemd-sandbox"),
        PathBuf::from("/opt/AetherFlow/packages/system/af-systemd-sandbox"),
        PathBuf::from("/usr/local/bin/AetherFlow/system/af-systemd-sandbox"),
        PathBuf::from("deploy/security/af-systemd-sandbox"),
        PathBuf::from("../deploy/security/af-systemd-sandbox"),
        PathBuf::from("packages/system/af-systemd-sandbox"),
        PathBuf::from("../packages/system/af-systemd-sandbox"),
        PathBuf::from("/usr/local/bin/af-systemd-sandbox"),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("deploy/security/af-systemd-sandbox"));
            candidates.push(exe_dir.join("../deploy/security/af-systemd-sandbox"));
            candidates.push(exe_dir.join("packages/system/af-systemd-sandbox"));
            candidates.push(exe_dir.join("../packages/system/af-systemd-sandbox"));
        }
    }
    candidates.into_iter().find(|c| c.is_file())
}

pub fn open_and_read_regular_config(path: &Path) -> std::io::Result<String> {
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut file = {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("config file is a symlink: {}", path.display()),
            ));
        }
        fs::File::open(path)?
    };

    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("config file is not a regular file: {}", path.display()),
        ));
    }
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut file, &mut contents)?;
    Ok(contents)
}

pub fn is_missing_config_candidate(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::NotFound {
        return true;
    }
    #[cfg(unix)]
    {
        err.raw_os_error() == Some(libc::ENOTDIR)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn package_fs_root_override() -> Option<PathBuf> {
    af_models::resolve_package_fs_root(None)
}

fn installed_config_candidates(root: &Path, filename: &str) -> [PathBuf; 4] {
    [
        "opt/AetherFlow/current/config",
        "opt/AetherFlow/config",
        // Legacy v3 host upgrade fallback.
        "opt/AetherFlow/current/backend/config",
        "opt/AetherFlow/backend/config",
    ]
    .map(|directory| root.join(directory).join(filename))
}

pub fn canonical_config_candidates(filename: &str) -> Vec<PathBuf> {
    if let Some(root) = package_fs_root_override() {
        return installed_config_candidates(&root, filename).into();
    }

    #[cfg(unix)]
    let running_as_root = unsafe { libc::geteuid() == 0 };
    #[cfg(not(unix))]
    let running_as_root = false;

    let mut candidates = Vec::new();
    if !running_as_root {
        candidates.extend([
            PathBuf::from("config").join(filename),
            PathBuf::from("../config").join(filename),
            PathBuf::from("../../config").join(filename),
        ]);
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("config").join(filename));
        }
    }
    candidates.extend(installed_config_candidates(Path::new("/"), filename));
    candidates
}

fn try_load_runner_config_or_embedded_in_root(
    env_var: &str,
    filename: &str,
    embedded: &str,
    explicit_root: Option<&Path>,
) -> anyhow::Result<String> {
    if let Ok(explicit) = env::var(env_var) {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let p = Path::new(trimmed);
            return open_and_read_regular_config(p)
                .map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", p.display()));
        }
    }
    let candidates: Vec<PathBuf> = match af_models::resolve_package_fs_root(explicit_root) {
        Some(root) => installed_config_candidates(&root, filename).into(),
        None => canonical_config_candidates(filename),
    };
    for c in candidates {
        match open_and_read_regular_config(&c) {
            Ok(s) => return Ok(s),
            Err(err) if is_missing_config_candidate(&err) => continue,
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "refusing unsafe or unreadable config candidate {}: {err}",
                    c.display()
                ))
            }
        }
    }
    Ok(embedded.to_string())
}

pub(crate) fn try_load_runner_config_or_embedded(
    env_var: &str,
    filename: &str,
    embedded: &str,
) -> anyhow::Result<String> {
    try_load_runner_config_or_embedded_in_root(env_var, filename, embedded, None)
}

pub fn load_runner_package_definitions_in_root(
    explicit_root: Option<&Path>,
) -> anyhow::Result<impl Iterator<Item = Package>> {
    let raw_pkgs = try_load_runner_config_or_embedded_in_root(
        "AETHERFLOW_PACKAGES_CONFIG",
        "packages.json",
        EMBEDDED_PACKAGES_JSON,
        explicit_root,
    )?;
    let raw_auto = try_load_runner_config_or_embedded_in_root(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        "package_automation.json",
        EMBEDDED_AUTOMATION_JSON,
        explicit_root,
    )?;

    let pkgs: Vec<Package> = serde_json::from_str(&raw_pkgs)?;
    let auto_map: HashMap<String, PackageAutomation> =
        serde_json::from_str(&raw_auto).unwrap_or_default();

    Ok(pkgs.into_iter().map(move |mut package| {
        if let Some(automation) = auto_map.get(&package.name) {
            af_models::merge_package_automation(&mut package, automation);
        }
        package
    }))
}

pub fn get_runner_package_definition_in_root(
    pkg_id: &str,
    explicit_root: Option<&Path>,
) -> Option<Package> {
    load_runner_package_definitions_in_root(explicit_root)
        .ok()?
        .find(|package| package.name == pkg_id)
}

pub fn get_runner_package_definition(pkg_id: &str) -> Option<Package> {
    get_runner_package_definition_in_root(pkg_id, None)
}

mod app_metadata;
pub use app_metadata::*;

mod backup_ops;
use backup_ops::handle_backup;
pub use backup_ops::{dispatch_backup_request, execute_backup_local};

mod confined_fs;
pub(crate) use confined_fs::{
    confined_file_name, create_package_lock_directory, lookup_group_gid, open_confined_file,
    read_confined_text, replace_confined_file, replace_confined_text, write_hosts_file_atomically,
};
pub use confined_fs::{
    dns_provider_directory_exists, read_dns_provider_text, remove_dns_provider_file,
    write_dns_provider_text,
};

mod daemon;
#[cfg(unix)]
pub(crate) use daemon::lookup_passwd_uid_reentrant;
pub use daemon::{authorize_runner_peer_credentials, run_privileged_daemon, shutdown_signal};
#[cfg(all(test, unix))]
use daemon::{authorize_runner_socket_peer, serve_runner_connections, trusted_runner_peer_exe};

mod hosts_dns;
#[cfg(test)]
use hosts_dns::resolve_hosts_lock_path;
pub use hosts_dns::{
    apply_hosts_update, execute_hosts_cli_command, filter_hosts_line, modify_hosts_file_at_path,
    reconcile_hosts_file, reconcile_hosts_file_at_path, reconcile_pihole_custom_list_content,
    remove_dns_provider_domain, remove_dns_provider_files, remove_hosts_file_at_path,
    remove_pihole_custom_list_content, run_hosts_cli, sync_adguard_dns, sync_dns_provider_files,
    sync_dns_provider_files_with_mode, update_hosts_file, update_hosts_file_at_path,
    update_hosts_file_local, update_hosts_file_with_ip_at_path, validate_hosts_domain,
    validate_hosts_ip, HostsModifyAction, RunnerError,
};
use hosts_dns::{handle_hosts, resolve_provider_dir};

mod ingress_vhost;
#[cfg(test)]
use ingress_vhost::{apply_ingress_vhost_with_hooks, execute_certbot_sync_with_candidates};
#[allow(unused_imports)]
pub(crate) use ingress_vhost::{
    enable_managed_apache_modules, reload_apache_after_rollback_if_live, restore_app_vhost_backups,
    snapshot_app_vhost_backups, validate_ingress_vhost_request, PrevEnabledVhostState, VhostBackup,
};
use ingress_vhost::{handle_certbot_sync, handle_ingress_vhost};
pub use ingress_vhost::{
    sync_apache_vhost_local, sync_apache_vhost_via_runner, sync_certbot_and_managed_ingress,
    trigger_certbot_sync_via_runner,
};

mod network_quota_handlers;
pub use network_quota_handlers::{
    execute_network_action_local, execute_set_quota_local, parse_quota_size_to_1k_blocks,
    resolve_setdisk_script_path,
};
use network_quota_handlers::{handle_network, handle_quota};

mod runner_client;
pub(crate) use runner_client::post_runner_json;
#[cfg(test)]
use runner_client::{
    consume_package_output, IncrementalPackageLineDecoder, MAX_PACKAGE_STREAM_LINE_BYTES,
};
pub use runner_client::{
    dispatch_app_meta, dispatch_core_restart, dispatch_heal_restart, dispatch_hosts_reconcile,
    dispatch_hosts_reconcile_with_provider, dispatch_hosts_remove, dispatch_hosts_request,
    dispatch_hosts_update, dispatch_hosts_update_with_provider, dispatch_network_action,
    dispatch_network_control, dispatch_package_action, dispatch_package_action_with_options,
    dispatch_package_action_with_target, dispatch_package_cancel,
    dispatch_package_lifecycle_snapshot_capture, dispatch_package_lifecycle_snapshot_discard,
    dispatch_package_lifecycle_snapshot_discard_for_job,
    dispatch_package_lifecycle_snapshot_restore, dispatch_package_stream, dispatch_plugin_start,
    dispatch_plugin_status, dispatch_plugin_stop, dispatch_plugin_token_rotate, dispatch_quota_set,
    dispatch_sandbox, dispatch_sandbox_apply, dispatch_self_update, dispatch_self_update_request,
    dispatch_self_update_status_request, dispatch_set_quota, dispatch_systemctl,
    execute_package_local, is_lifecycle_busy, reconcile_hosts_file_via_runner,
    remove_hosts_file_via_runner, runner_is_ready, start_self_update, update_hosts_file_via_runner,
    LifecycleBusy,
};

mod sandbox_ops;
pub use sandbox_ops::{
    apply_package_sandbox_local, dispatch_blueprint_apply, render_systemd_sandbox_dropin,
};
#[allow(unused_imports)]
pub(crate) use sandbox_ops::{
    apply_package_sandbox_reserved, is_exempt_sandbox_unit, open_runner_state_database,
    render_systemd_sandbox_dropin_in_root,
};
#[cfg(test)]
use sandbox_ops::{
    apply_sandbox_dropins_in_dir, expand_sandbox_path, handle_sandbox_with, sandbox_master_user,
};
use sandbox_ops::{
    handle_blueprint_apply, handle_sandbox, remove_file_if_exists, write_file_atomically_with_mode,
};

mod self_update;
pub use self_update::{
    acquire_lifecycle_admission_lock, acquire_service_maintenance_guard, claim_self_update_job,
    execute_self_update_request, query_self_update_status_local,
    validate_self_update_job_unit_name, write_self_update_job_status_atomic,
};
pub(crate) use self_update::{
    acquire_owned_lifecycle_snapshot_guard, acquire_package_maintenance_guard,
    build_self_update_transient_unit_name, resolve_self_update_isolated_root_from_env,
};
#[cfg(test)]
use self_update::{
    discover_system_update, query_self_update_job_at, query_self_update_job_in,
    resolve_self_update_jobs_dir_from_env, spawn_self_update_transient_unit,
    update_status_allows_launch,
};
use self_update::{
    handle_self_update, handle_self_update_status, resolve_self_update_jobs_dir_for_cfg,
    resolve_self_update_lock_path_for_cfg, resolve_validated_self_update_config,
    service_reservation_target,
};

mod systemctl_handlers;
#[cfg(test)]
use systemctl_handlers::deferred_restart_arguments;
pub(crate) use systemctl_handlers::handle_systemctl;
pub use systemctl_handlers::is_managed_runner_systemd_unit;
use systemctl_handlers::{
    handle_package, handle_package_cancel, handle_package_lifecycle_snapshot,
};

#[cfg(test)]
pub(crate) static ENV_TEST_MUTEX: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

#[cfg(test)]
mod tests;
