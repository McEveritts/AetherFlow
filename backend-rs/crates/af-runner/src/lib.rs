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

const EMBEDDED_PACKAGES_JSON: &str = include_str!("../../../../config/packages.json");
const EMBEDDED_AUTOMATION_JSON: &str = include_str!("../../../../config/package_automation.json");

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
    Lazy::new(|| Regex::new(r"^(?:[a-z_][a-z0-9_-]{0,31}|[a-zA-Z0-9_.-]{1,64})$").unwrap());
pub static SAFE_QUOTA_SIZE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:[0-9]+[KMGTPkmgtp]?[Bb]?|[0-9]+(?:\.[0-9]+)?\s*[KMGTPEkmgtpe]?[Bb]?|0)$")
        .unwrap()
});
pub static SAFE_QUOTA_SIZE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:[0-9]+(?:\.[0-9]+)?\s*[KMGTPEkmgtpe]?[Bb]?|0)$").unwrap());

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

/// Evaluates release engine selection given explicit rollout flags (`rust_enabled`, `force_bash`).
pub fn select_release_engine_with_flags(rust_enabled: bool, force_bash: bool) -> ReleaseEngineMode {
    if rust_enabled && !force_bash {
        ReleaseEngineMode::NativeRustRelease
    } else {
        ReleaseEngineMode::LegacyBashRelease
    }
}

/// Selects the active release engine for `/v1/self-update`.
///
/// Rollout control:
/// The engine name and both Rust opt-in aliases share a selector. An explicit Bash
/// selection or the force-Bash flag takes precedence.
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
        PathBuf::from("/opt/AetherFlow/current/af"),
        PathBuf::from("/opt/AetherFlow/current/bin/af"),
        PathBuf::from("/usr/local/bin/af"),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
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

/// Schedule core restarts independently so killing the API/runner does not kill
/// the response reporting acceptance. Completion remains a status/readiness check.
fn deferred_restart_arguments(service: &str) -> Result<Vec<String>, String> {
    let service = service.trim_end_matches(".service");
    if !matches!(service, "aetherflow-api" | "aetherflow-runner") {
        return Err("Deferred restart is restricted to core API/runner services".into());
    }
    Ok(vec![
        format!(
            "--unit={}",
            build_self_update_transient_unit_name("restart", service)
        ),
        "--on-active=2s".into(),
        "--timer-property=AccuracySec=100ms".into(),
        "--timer-property=RemainAfterElapse=no".into(),
        "--collect".into(),
        "--quiet".into(),
        "--".into(),
        "/bin/bash".into(),
        "-c".into(),
        include_str!("core_restart_worker.sh").into(),
        "aetherflow-core-restart".into(),
        service.into(),
    ])
}

pub fn is_managed_runner_systemd_unit(raw_unit: &str) -> bool {
    let trimmed = raw_unit.trim();
    if trimmed.is_empty() || !SAFE_SERVICE_NAME.is_match(trimmed) || trimmed.contains("..") {
        return false;
    }
    let strip_suffixes = |s: &str| -> String {
        s.trim()
            .trim_end_matches(".service")
            .trim_end_matches(".timer")
            .trim_end_matches(".socket")
            .to_ascii_lowercase()
    };
    let lower = strip_suffixes(trimmed);
    if lower.is_empty() {
        return false;
    }

    if let Some((prefix, instance)) = lower.split_once('@') {
        // Marketplace ships exactly this Home Assistant instance.
        if matches!(
            trimmed,
            "home-assistant@homeassistant" | "home-assistant@homeassistant.service"
        ) {
            return true;
        }
        if instance.is_empty() {
            return false;
        }
        return matches!(
            prefix,
            "wg-quick"
                | "rtorrent"
                | "deluged"
                | "deluge-web"
                | "qbittorrent-nox"
                | "syncthing"
                | "irssi"
                | "flood"
        );
    }

    if matches!(
        lower.as_str(),
        "aetherflow-api"
            | "aetherflow-runner"
            | "aetherflow-frontend"
            | "apache2"
            | "nginx"
            | "fail2ban"
            | "pihole-ftl"
            | "netdata"
            | "node_exporter"
            | "prometheus"
            | "mariadb"
            | "mysql"
            | "postgresql"
            | "redis"
            | "redis-server"
            | "tailscale"
            | "tailscaled"
            | "wireguard"
            | "mergerfs"
            | "rclone"
            | "rclone-vfs"
            | "deluge"
            | "deluged"
            | "deluge-web"
            | "qbittorrent"
            | "qbittorrent-nox"
            | "rtorrent"
            | "transmission-daemon"
            | "paperless"
            | "paperless-ngx"
            | "paperless-webserver"
            | "paperless-worker"
            | "paperless-scheduler"
            | "scrutiny"
            | "scrutiny-collector"
            | "recyclarr"
            | "dispatcharr"
            | "dispatcharr-celery"
            | "dispatcharr-celerybeat"
            | "novnc"
            | "novnc-xvnc"
            | "novnc-session"
            | "x2goserver"
            | "xrdp"
            | "xrdp-sesman"
            | "vsftpd"
            | "proftpd"
            | "znc"
            | "thelounge"
            | "quasselcore"
            | "syncthing"
            | "maintainerr"
            | "af-maintainerr"
            | "palate"
            | "af-palate"
            | "kasmvnc"
            | "af-kasmvnc"
            | "mcvnc"
            | "af-mcvnc"
    ) {
        return true;
    }

    let Ok(raw_pkgs) = try_load_runner_config_or_embedded(
        "AETHERFLOW_PACKAGES_CONFIG",
        "packages.json",
        EMBEDDED_PACKAGES_JSON,
    ) else {
        return false;
    };
    if let Ok(pkgs) = serde_json::from_str::<Vec<Package>>(&raw_pkgs) {
        for p in &pkgs {
            if strip_suffixes(&p.name) == lower
                || (!p.service_name.trim().is_empty() && strip_suffixes(&p.service_name) == lower)
                || p.sandbox_service_ids
                    .iter()
                    .any(|u| strip_suffixes(u) == lower)
            {
                return true;
            }
        }
    }

    let Ok(raw_auto) = try_load_runner_config_or_embedded(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        "package_automation.json",
        EMBEDDED_AUTOMATION_JSON,
    ) else {
        return false;
    };
    if let Ok(auto_map) = serde_json::from_str::<HashMap<String, PackageAutomation>>(&raw_auto) {
        for (pkg_id, auto) in &auto_map {
            if strip_suffixes(pkg_id) == lower
                || auto
                    .sandbox_service_ids
                    .iter()
                    .any(|u| strip_suffixes(u) == lower)
            {
                return true;
            }
        }
    }

    false
}

async fn handle_systemctl(Json(req): Json<SystemctlRequest>) -> (StatusCode, Json<RunnerResponse>) {
    if !ALLOWED_SERVICE_ACTIONS.contains(req.action.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "disallowed systemctl action".to_string(),
            }),
        );
    }
    if !SAFE_SERVICE_NAME.is_match(&req.service) || req.service.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid service name".to_string(),
            }),
        );
    }
    if !is_managed_runner_systemd_unit(&req.service) {
        return (
            StatusCode::FORBIDDEN,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "unmanaged systemd unit".to_string(),
            }),
        );
    }

    // Automatic recovery shares both locks with privileged package execution.
    // The persistent flock file's existence alone never means a job is active.
    let _heal_mutex;
    let _heal_flock;
    let action = if req.action != "status" {
        _heal_mutex = match PACKAGE_MUTEX.try_lock() {
            Ok(guard) => Some(guard),
            Err(_) => {
                return (
                    if req.action == "heal" {
                        StatusCode::OK
                    } else {
                        StatusCode::CONFLICT
                    },
                    Json(RunnerResponse {
                        success: req.action == "heal",
                        output: if req.action == "heal" { "skipped" } else { "" }.into(),
                        error: if req.action == "heal" {
                            ""
                        } else {
                            "Package lifecycle operation is active"
                        }
                        .into(),
                    }),
                )
            }
        };
        _heal_flock = match package_executor::CrossProcessLockGuard::try_acquire(
            &PackageExecutionEnv::default(),
            "af-heal",
        ) {
            Ok(guard) => Some(guard),
            Err(PackageExecutorError::LockConflict(_)) => {
                return (
                    if req.action == "heal" {
                        StatusCode::OK
                    } else {
                        StatusCode::CONFLICT
                    },
                    Json(RunnerResponse {
                        success: req.action == "heal",
                        output: if req.action == "heal" { "skipped" } else { "" }.into(),
                        error: if req.action == "heal" {
                            ""
                        } else {
                            "Package lifecycle operation is active"
                        }
                        .into(),
                    }),
                )
            }
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: error.to_string(),
                    }),
                )
            }
        };
        if req.action == "heal" {
            "restart"
        } else {
            req.action.as_str()
        }
    } else {
        _heal_mutex = None;
        _heal_flock = None;
        req.action.as_str()
    };

    let _maintenance_guard = if action != "status" {
        match acquire_package_maintenance_guard(
            PackageExecutionEnv::default().fs_root.as_deref(),
            service_reservation_target(&req.service, action),
            &req.lifecycle_job_id,
            None,
        )
        .await
        {
            Ok(guard) => Some(guard),
            Err(error) => {
                return (
                    StatusCode::CONFLICT,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: error.to_string(),
                    }),
                )
            }
        }
    } else {
        None
    };
    if action == "restart-deferred" {
        let mut args = match deferred_restart_arguments(&req.service) {
            Ok(args) => args,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error,
                    }),
                )
            }
        };
        let cfg = match resolve_validated_self_update_config(af_release::ReleaseChannel::Stable) {
            Ok((cfg, _, _)) => cfg,
            Err((code, error)) => {
                return (
                    code,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error,
                    }),
                )
            }
        };
        let lock_path = match resolve_self_update_lock_path_for_cfg(&cfg) {
            Ok(path) => path,
            Err((code, error)) => {
                return (
                    code,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error,
                    }),
                )
            }
        };
        let unit = args[0].trim_start_matches("--unit=").to_string();
        let jobs_dir = match resolve_self_update_jobs_dir_for_cfg(&cfg) {
            Ok(dir) => dir,
            Err((code, error)) => {
                return (
                    code,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error,
                    }),
                )
            }
        };
        let path = jobs_dir.join(format!("{unit}.json"));
        let _launch_owner = match job_receipts::begin_launch(&path) {
            Ok(owner) => owner,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: error.to_string(),
                    }),
                )
            }
        };
        let initial = SelfUpdateJobStatus {
            status: "launching".into(),
            completed: false,
            success: false,
            job_unit: unit.clone(),
            error: String::new(),
            exit_code: None,
        };
        if let Err(error) = write_self_update_job_status_atomic(&path, &initial) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: error.to_string(),
                }),
            );
        }
        args.extend([
            path.to_string_lossy().into_owned(),
            unit.clone(),
            lock_path.to_string_lossy().into_owned(),
            env::var("AETHERFLOW_SYSTEMCTL_BIN").unwrap_or_else(|_| "/usr/bin/systemctl".into()),
        ]);
        #[cfg(unix)]
        match _maintenance_guard.as_ref().unwrap().file_identity() {
            Ok((device, inode)) => args.extend([device.to_string(), inode.to_string()]),
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: error.to_string(),
                    }),
                )
            }
        }
        match _launch_owner.directory_identity() {
            Ok((device, inode)) => args.extend([device.to_string(), inode.to_string()]),
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: error.to_string(),
                    }),
                )
            }
        }
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            Command::new("systemd-run")
                .args(args)
                .kill_on_drop(true)
                .output(),
        )
        .await;
        if let Ok(Ok(output)) = &result {
            if output.status.success() {
                let mut running = initial.clone();
                running.status = "running".into();
                let observed = match job_receipts::compare_exchange(&path, &initial, &running) {
                    Ok(observed) => observed,
                    Err(error) => {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(RunnerResponse {
                                success: false,
                                output: String::new(),
                                error: error.to_string(),
                            }),
                        );
                    }
                };
                if observed.completed && !observed.success {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(RunnerResponse {
                            success: false,
                            output: String::new(),
                            error:
                                "Core restart already failed; inspect its receipt and service logs."
                                    .into(),
                        }),
                    );
                }
                return (
                    StatusCode::ACCEPTED,
                    Json(RunnerResponse {
                        success: true,
                        output: json!({
                            "status": if observed.completed { observed.status.as_str() } else { "accepted" },
                            "job_unit": unit,
                            "completed": observed.completed,
                            "success": observed.success,
                        }).to_string(),
                        error: String::new(),
                    }),
                );
            }
        }
        let error = format!("Could not schedule core restart: {:?}", result);
        if result.is_ok() {
            let failure = SelfUpdateJobStatus {
                status: "failed".into(),
                completed: true,
                success: false,
                job_unit: unit,
                error: error.clone(),
                exit_code: Some(1),
            };
            let _ = job_receipts::compare_exchange(&path, &initial, &failure);
        }
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error,
            }),
        );
    }

    let mut command = Command::new("systemctl");
    command
        .arg(action)
        .arg("--")
        .arg(&req.service)
        .kill_on_drop(true);
    #[cfg(unix)]
    if let Some(guard) = &_maintenance_guard {
        if let Err(error) = guard.preserve_in_child(command.as_std_mut()) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: error.to_string(),
                }),
            );
        }
    }
    match bounded_command::output(command, Duration::from_secs(40), 1024 * 1024).await {
        Ok(out) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if out.status.success() {
                (
                    StatusCode::OK,
                    Json(RunnerResponse {
                        success: true,
                        output: combined,
                        error: String::new(),
                    }),
                )
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RunnerResponse {
                        success: false,
                        output: combined,
                        error: format!("exit status: {}", out.status),
                    }),
                )
            }
        }
        Err(error) => (
            if error.kind() == std::io::ErrorKind::TimedOut {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            },
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: error.to_string(),
            }),
        ),
    }
}

async fn handle_package(Json(req): Json<PackageRunnerRequest>) -> Response {
    if !matches!(
        req.action.as_str(),
        "install" | "reinstall" | "remove" | "update"
    ) {
        return (StatusCode::BAD_REQUEST, "disallowed package action").into_response();
    }
    if !SAFE_SCRIPT_NAME.is_match(&req.script_name) || !SAFE_SCRIPT_NAME.is_match(&req.package_id) {
        return (
            StatusCode::BAD_REQUEST,
            "invalid script or package identifier",
        )
            .into_response();
    }
    if req.app_port != 0 && !(1024..=65535).contains(&req.app_port) {
        return (StatusCode::BAD_REQUEST, "invalid application port").into_response();
    }
    if req.delete_data && req.action != "remove" {
        return (
            StatusCode::BAD_REQUEST,
            "data purge is only valid for package removal",
        )
            .into_response();
    }
    if !script_matches_package_identity(&req.action, &req.package_id, &req.script_name) {
        return (
            StatusCode::BAD_REQUEST,
            "script_name does not match package_id and action",
        )
            .into_response();
    }

    if !can_resolve_package_operation(&req.action, &req.package_id, &req.script_name) {
        return (StatusCode::NOT_FOUND, "package script not found").into_response();
    }

    let engine = select_package_engine(&req.package_id);
    let stream = package_lifecycle::execute_coordinated_package_stream(req);

    let mut resp = Response::new(Body::from_stream(stream));
    resp.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.headers_mut().insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    resp.headers_mut().insert(
        "X-AetherFlow-Package-Engine",
        HeaderValue::from_static(match engine {
            PackageEngineMode::DeclarativeRust => "declarative_rust",
            PackageEngineMode::LegacyBashFallback => "legacy_bash_fallback",
        }),
    );
    resp
}

async fn handle_package_cancel(
    Json(req): Json<SandboxRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let pkg = if !req.package_id.trim().is_empty() {
        req.package_id.trim().to_string()
    } else {
        req.package.trim().to_string()
    };
    if !SAFE_PKG_ID.is_match(&pkg) || pkg.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid package identifier".to_string(),
            }),
        );
    }

    let signalled = cancel_package_execution(&pkg);
    (
        StatusCode::OK,
        Json(RunnerResponse {
            success: true,
            output: if signalled {
                format!("cancellation signalled for {}", pkg)
            } else {
                format!("no active package execution for {}", pkg)
            },
            error: String::new(),
        }),
    )
}

async fn handle_package_lifecycle_snapshot(
    Json(req): Json<PackageLifecycleSnapshotRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let pkg = req.package_id.trim();
    let job_id = req.lifecycle_job_id.trim();
    let action = req.action.trim();
    if pkg.is_empty() || !SAFE_PKG_ID.is_match(pkg) || pkg.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid package identifier".into(),
            }),
        );
    }
    if job_id.is_empty()
        || job_id.len() > 128
        || job_id.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid lifecycle_job_id".into(),
            }),
        );
    }
    if req
        .units
        .iter()
        .any(|u| u.trim().is_empty() || !SAFE_SERVICE_NAME.is_match(u.trim()) || u.contains(".."))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid systemd unit name in snapshot request".into(),
            }),
        );
    }

    let result = match action {
        "capture" => {
            package_lifecycle::capture_admitted_lifecycle_snapshot(pkg, job_id, &req.units)
                .await
                .map(|()| "snapshot captured".to_string())
        }
        "restore" => package_lifecycle::restore_admitted_lifecycle_snapshot(pkg, job_id)
            .await
            .map(|()| "snapshot restored".to_string()),
        "discard" => {
            package_lifecycle::discard_admitted_lifecycle_snapshot(pkg, job_id, req.preserve_backup)
                .await
                .map(|discarded| {
                    if discarded {
                        "snapshot discarded".to_string()
                    } else {
                        "no active snapshot".to_string()
                    }
                })
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: "disallowed lifecycle snapshot action".into(),
                }),
            );
        }
    };

    match result {
        Ok(output) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output,
                error: String::new(),
            }),
        ),
        Err(err) => {
            let status = if is_lifecycle_busy(&err) {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: af_models::secret_redaction::redact_diagnostic(&err.to_string())
                        .into_owned(),
                }),
            )
        }
    }
}

fn build_self_update_transient_unit_name(command: &str, channel: &str) -> String {
    let cmd_slug: String = command
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .collect();
    let chan_slug: String = channel
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .collect();
    let raw_uuid = uuid::Uuid::new_v4().simple().to_string();
    let short_id = &raw_uuid[..8];
    format!(
        "aetherflow-self-update-{}-{}-{}.service",
        cmd_slug, chan_slug, short_id
    )
}

static SAFE_SELF_UPDATE_UNIT_NAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^aetherflow-self-update-[a-z0-9-]+-[a-z0-9-]+-[a-f0-9]{8,32}\.service$").unwrap()
});

pub fn validate_self_update_job_unit_name(unit_name: &str) -> Result<String, (StatusCode, String)> {
    let trimmed = unit_name.trim();
    if trimmed.is_empty()
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || !SAFE_SELF_UPDATE_UNIT_NAME.is_match(trimmed)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("invalid self-update job_unit identifier: {:?}", unit_name),
        ));
    }
    Ok(trimmed.to_string())
}

fn resolve_self_update_isolated_root_from_env() -> Result<Option<PathBuf>, String> {
    if let Ok(raw) = env::var("AETHERFLOW_RELEASE_ROOT") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if !p.is_absolute()
                || p.components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(format!(
                    "AETHERFLOW_RELEASE_ROOT '{}' must be an absolute path without '..'",
                    trimmed
                ));
            }
            return Ok(Some(p));
        }
    }
    af_models::try_resolve_isolated_root_with_env(None, |k| env::var(k).ok())
        .map_err(|e| e.to_string())
}

fn resolve_self_update_lock_path_for_cfg(
    cfg: &af_release::ReleaseConfig,
) -> Result<PathBuf, (StatusCode, String)> {
    af_release::resolve_maintenance_lock_path_for_config(cfg)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))
}

fn resolve_self_update_db_path_for_cfg(
    cfg: &af_release::ReleaseConfig,
) -> Result<PathBuf, (StatusCode, String)> {
    af_release::try_resolve_db_path(cfg, None)
        .map(|resolved| resolved.path)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))
}

fn resolve_self_update_backup_dir_for_cfg(cfg: &af_release::ReleaseConfig) -> PathBuf {
    cfg.data_dir.join("backups")
}

fn resolve_self_update_jobs_dir_for_cfg(
    cfg: &af_release::ReleaseConfig,
) -> Result<PathBuf, (StatusCode, String)> {
    af_release::resolve_self_update_jobs_dir_for_config(cfg)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))
}

fn resolve_self_update_jobs_dir_from_env() -> Result<PathBuf, (StatusCode, String)> {
    let explicit_root = resolve_self_update_isolated_root_from_env()
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let conf_path = af_release::resolve_release_manager_conf_for_root(explicit_root.as_deref());
    af_release::resolve_self_update_jobs_dir_from_process_env(
        explicit_root.as_deref(),
        conf_path.as_deref(),
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))
}

pub fn write_self_update_job_status_atomic(
    status_path: &Path,
    status: &SelfUpdateJobStatus,
) -> std::io::Result<()> {
    job_receipts::write(status_path, status)
}

pub fn claim_self_update_job(status_path: &Path, unit: &str) -> std::io::Result<()> {
    job_receipts::claim(status_path, unit)
}

type ValidatedSelfUpdateConfig = (af_release::ReleaseConfig, Option<PathBuf>, Option<PathBuf>);

fn resolve_validated_self_update_config(
    channel: af_release::ReleaseChannel,
) -> Result<ValidatedSelfUpdateConfig, (StatusCode, String)> {
    let explicit_root =
        resolve_self_update_isolated_root_from_env().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let conf_path = af_release::resolve_release_manager_conf_for_root(explicit_root.as_deref());
    let mut cfg = af_release::ReleaseConfig::load_for_root_from_process_env(
        explicit_root.as_deref(),
        conf_path.as_deref(),
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    cfg.release_channel = channel;
    af_release::ensure_interoperable_maintenance_lock_file(&cfg)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok((cfg, explicit_root, conf_path))
}

async fn spawn_self_update_transient_unit(
    unit_name: &str,
    program: &Path,
    args: &[String],
    extra_envs: &[(&str, String)],
) -> Result<String, (StatusCode, String)> {
    let Some(systemd_run) = resolve_systemd_run_binary() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "systemd-run binary not found for out-of-cgroup self-update handoff".to_string(),
        ));
    };

    let mut cmd = Command::new(&systemd_run);
    cmd.kill_on_drop(true);
    cmd.arg(format!("--unit={}", unit_name))
        .arg("--collect")
        .arg("--no-block")
        .arg("--property=Type=exec")
        .arg("--property=KillMode=control-group");

    let preserved_envs = [
        "AETHERFLOW_ENABLE_RUST_RELEASE",
        "AETHERFLOW_USE_RUST_RELEASE",
        "AETHERFLOW_RELEASE_ENGINE",
        "AETHERFLOW_FORCE_BASH_RELEASE",
        "AETHERFLOW_RELEASE_ROOT",
        "AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE",
        "AETHERFLOW_BACKUP_ISOLATED_ROOT",
        "AETHERFLOW_MAINTENANCE_LOCK_PATH",
        "AF_DB_PATH",
        "DB_PATH",
        "AETHERFLOW_DB_PATH",
        "AETHERFLOW_BACKUP_DIR",
        "AF_BACKUP_DIR",
        "BACKUP_DIR",
        "AF_OFFLINE",
        "DRY_RUN_ROOT",
    ];
    for env_key in &preserved_envs {
        if extra_envs.iter().any(|(k, _)| k == env_key) {
            continue;
        }
        if let Ok(env_val) = env::var(env_key) {
            let trimmed = env_val.trim();
            if !trimmed.is_empty() {
                cmd.arg(format!("--setenv={}={}", env_key, trimmed));
            }
        }
    }
    for (env_key, env_val) in extra_envs {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            cmd.arg(format!("--setenv={}={}", env_key, trimmed));
        }
    }

    cmd.arg("--").arg(program);
    for arg_val in args {
        cmd.arg(arg_val);
    }

    match tokio::time::timeout(Duration::from_secs(15), cmd.output()).await {
        Ok(Ok(out)) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
            .trim()
            .to_string();
            if out.status.success() {
                Ok(combined)
            } else {
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "transient systemd unit '{}' failed to start ({}): {}",
                        unit_name, out.status, combined
                    ),
                ))
            }
        }
        Ok(Err(err)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "failed to launch transient systemd unit '{}': {}",
                unit_name, err
            ),
        )),
        Err(_) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            format!(
                "systemd-run timed out while launching transient unit '{}'",
                unit_name
            ),
        )),
    }
}

/// A successful launch request may already have a terminal worker receipt.
/// `RunnerResponse::success` reports that the request was handled; the payload
/// carries the actual operation result, including a fast failure.
fn self_update_launch_response(
    engine: &str,
    command: &str,
    channel: &str,
    observed: &SelfUpdateJobStatus,
) -> RunnerResponse {
    RunnerResponse {
        success: true,
        output: json!({
            "status": if observed.completed { observed.status.as_str() } else { "initiated" },
            "completed": observed.completed,
            "success": observed.success,
            "error": observed.error,
            "exit_code": observed.exit_code,
            "engine": engine,
            "command": command,
            "channel": channel,
            "job_unit": observed.job_unit,
        })
        .to_string(),
        error: String::new(),
    }
}

/// Validates and executes a `SelfUpdateRequest` using either the native Rust `af-release`
/// engine (when `AETHERFLOW_ENABLE_RUST_RELEASE=1` and not `AETHERFLOW_FORCE_BASH_RELEASE=1`)
/// or the legacy `deploy/release-manager.sh` script.
///
/// Experimental channel safety: `af_release::validate_self_update_request` validates
/// `stable`, `nightly`, and `experimental` channels.
pub async fn execute_self_update_request(
    req: &SelfUpdateRequest,
    background: bool,
) -> (StatusCode, RunnerResponse) {
    let validated = match af_release::validate_self_update_request(req) {
        Ok(val) => val,
        Err(err_resp) => return (StatusCode::BAD_REQUEST, err_resp),
    };

    let (cfg, explicit_root, _resolved_conf) =
        match resolve_validated_self_update_config(validated.channel) {
            Ok(tuple) => tuple,
            Err((code, err_msg)) => {
                return (
                    code,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: err_msg,
                    },
                );
            }
        };

    let cfg_lock_path = match resolve_self_update_lock_path_for_cfg(&cfg) {
        Ok(resolved) => resolved,
        Err((code, err_msg)) => {
            return (
                code,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: err_msg,
                },
            );
        }
    };
    let cfg_db_path = match resolve_self_update_db_path_for_cfg(&cfg) {
        Ok(resolved) => resolved,
        Err((code, err_msg)) => {
            return (
                code,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: err_msg,
                },
            );
        }
    };
    let cfg_backup_dir = resolve_self_update_backup_dir_for_cfg(&cfg);
    let cfg_jobs_dir = match resolve_self_update_jobs_dir_for_cfg(&cfg) {
        Ok(resolved) => resolved,
        Err((code, err_msg)) => {
            return (
                code,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: err_msg,
                },
            );
        }
    };

    let _admission_guard = if background {
        let guard = match af_release::ReleaseLockGuard::acquire(&cfg_lock_path, Duration::ZERO) {
            Ok(guard) => guard,
            Err(err) => {
                return (
                    StatusCode::CONFLICT,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!("Application or system lifecycle work is active: {}", err),
                    },
                )
            }
        };
        if let Err(error) =
            af_release::admin::ensure_no_active_package_lifecycle_jobs(&cfg, validated.command)
        {
            return (
                StatusCode::CONFLICT,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: error.to_string(),
                },
            );
        }
        match discover_system_update(&cfg).await {
            Ok(status) if update_status_allows_launch(&status, validated.command) => {}
            Ok(status) => {
                return (
                    StatusCode::CONFLICT,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!(
                            "System update in progress or recovery required: {}",
                            status.error
                        ),
                    },
                )
            }
            Err((code, error)) => {
                return (
                    code,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error,
                    },
                )
            }
        }
        Some(guard)
    } else {
        None
    };

    let engine = select_release_engine();
    if engine == ReleaseEngineMode::NativeRustRelease {
        if background {
            let Some(af_bin) = resolve_af_cli_binary() else {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: "af CLI binary not found for transient systemd release unit"
                            .to_string(),
                    },
                );
            };
            let unit_name = build_self_update_transient_unit_name(
                validated.command.as_str(),
                validated.channel.as_str(),
            );
            let job_status_path = cfg_jobs_dir.join(format!("{}.json", unit_name));
            let job_conf_path = cfg_jobs_dir.join(format!("{}.conf", unit_name));
            let _launch_owner = match job_receipts::begin_launch(&job_status_path) {
                Ok(owner) => owner,
                Err(error) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        RunnerResponse {
                            success: false,
                            output: String::new(),
                            error: format!("Cannot reserve updater launch: {error}"),
                        },
                    )
                }
            };

            if let Err(err) = cfg.write_protected_config_file(&job_conf_path) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!("failed to persist self-update job config: {}", err),
                    },
                );
            }
            let initial_status = SelfUpdateJobStatus {
                status: "launching".to_string(),
                completed: false,
                success: false,
                job_unit: unit_name.clone(),
                error: String::new(),
                exit_code: None,
            };
            if let Err(err) = write_self_update_job_status_atomic(&job_status_path, &initial_status)
            {
                let _ = fs::remove_file(&job_conf_path);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!("failed to persist initial self-update job status: {}", err),
                    },
                );
            }

            let mut unit_args = Vec::new();
            if let Some(ref root) = explicit_root {
                unit_args.push("--root".to_string());
                unit_args.push(root.to_string_lossy().into_owned());
            }
            unit_args.extend([
                "release".to_string(),
                validated.command.as_str().to_string(),
                "--channel".to_string(),
                validated.channel.as_str().to_string(),
                "--local".to_string(),
                "--config".to_string(),
                job_conf_path.to_string_lossy().into_owned(),
                "--job-status-file".to_string(),
                job_status_path.to_string_lossy().into_owned(),
                "--job-unit".to_string(),
                unit_name.clone(),
            ]);

            let mut extra_envs = vec![
                (
                    "AETHERFLOW_SELF_UPDATE_STATUS_FILE",
                    job_status_path.to_string_lossy().into_owned(),
                ),
                ("AETHERFLOW_SELF_UPDATE_JOB_UNIT", unit_name.clone()),
                (
                    "AETHERFLOW_RELEASE_CONF",
                    job_conf_path.to_string_lossy().into_owned(),
                ),
                (
                    "AETHERFLOW_MAINTENANCE_LOCK_PATH",
                    cfg_lock_path.to_string_lossy().into_owned(),
                ),
                (
                    "AETHERFLOW_DB_PATH",
                    cfg_db_path.to_string_lossy().into_owned(),
                ),
                (
                    "AETHERFLOW_BACKUP_DIR",
                    cfg_backup_dir.to_string_lossy().into_owned(),
                ),
            ];
            if let Some(ref root) = explicit_root {
                extra_envs.push((
                    "AETHERFLOW_RELEASE_ROOT",
                    root.to_string_lossy().into_owned(),
                ));
            }

            match spawn_self_update_transient_unit(&unit_name, &af_bin, &unit_args, &extra_envs)
                .await
            {
                Ok(_) => {
                    let mut admitted = initial_status.clone();
                    admitted.status = "running".into();
                    let observed = match job_receipts::compare_exchange(
                        &job_status_path,
                        &initial_status,
                        &admitted,
                    ) {
                        Ok(observed) => observed,
                        Err(error) => {
                            return (StatusCode::INTERNAL_SERVER_ERROR, RunnerResponse {
                                success: false, output: String::new(), error: format!("Unit admitted but launch acknowledgment could not be persisted: {error}"),
                            });
                        }
                    };
                    return (
                        StatusCode::OK,
                        self_update_launch_response(
                            "native_rust_release",
                            validated.command.as_str(),
                            validated.channel.as_str(),
                            &observed,
                        ),
                    );
                }
                Err((code, err_msg)) => {
                    if code != StatusCode::GATEWAY_TIMEOUT {
                        let failed_receipt = SelfUpdateJobStatus {
                            status: "failed".to_string(),
                            completed: true,
                            success: false,
                            job_unit: unit_name.clone(),
                            error: err_msg.clone(),
                            exit_code: Some(1),
                        };
                        let _ = job_receipts::compare_exchange(
                            &job_status_path,
                            &initial_status,
                            &failed_receipt,
                        );
                        let _ = fs::remove_file(&job_conf_path);
                    }
                    return (
                        code,
                        RunnerResponse {
                            success: false,
                            output: String::new(),
                            error: err_msg,
                        },
                    );
                }
            }
        } else {
            let req_clone = validated.clone();
            let (_exit_code, resp) = tokio::task::spawn_blocking(move || {
                af_release::execute_self_update_sync(&req_clone, cfg)
            })
            .await
            .unwrap_or_else(|err| {
                (
                    af_release::ExitCode::ConfigurationOrUsageError,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: err.to_string(),
                    },
                )
            });
            let status = if resp.success {
                StatusCode::OK
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return (status, resp);
        }
    }

    let Some(script_path) = resolve_release_manager_script() else {
        return (
            StatusCode::NOT_FOUND,
            RunnerResponse {
                success: false,
                output: String::new(),
                error: "release-manager.sh not found".to_string(),
            },
        );
    };

    let cmd_name = validated.command.as_str().to_string();
    let channel_str = validated.channel.as_str().to_string();
    if background {
        let unit_name = build_self_update_transient_unit_name(&cmd_name, &channel_str);
        let job_status_path = cfg_jobs_dir.join(format!("{}.json", unit_name));
        let job_conf_path = cfg_jobs_dir.join(format!("{}.conf", unit_name));
        let _launch_owner = match job_receipts::begin_launch(&job_status_path) {
            Ok(owner) => owner,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!("Cannot reserve updater launch: {error}"),
                    },
                )
            }
        };

        if let Err(err) = cfg.write_protected_config_file(&job_conf_path) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: format!("failed to persist self-update job config: {}", err),
                },
            );
        }
        let initial_status = SelfUpdateJobStatus {
            status: "launching".to_string(),
            completed: false,
            success: false,
            job_unit: unit_name.clone(),
            error: String::new(),
            exit_code: None,
        };
        if let Err(err) = write_self_update_job_status_atomic(&job_status_path, &initial_status) {
            let _ = fs::remove_file(&job_conf_path);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: format!("failed to persist initial self-update job status: {}", err),
                },
            );
        }

        let receipt_directory_identity = match _launch_owner.directory_identity() {
            Ok(identity) => identity,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: format!("Cannot bind updater receipt directory: {error}"),
                    },
                );
            }
        };
        let mut unit_args = vec![
            script_path.to_string_lossy().into_owned(),
            cmd_name.clone(),
            "--channel".to_string(),
            channel_str.clone(),
        ];
        if let Some(ref root) = explicit_root {
            unit_args.push("--root".to_string());
            unit_args.push(root.to_string_lossy().into_owned());
        }
        unit_args.extend([
            "--config".to_string(),
            job_conf_path.to_string_lossy().into_owned(),
            "--job-status-file".to_string(),
            job_status_path.to_string_lossy().into_owned(),
            "--job-unit".to_string(),
            unit_name.clone(),
        ]);

        let mut extra_envs = vec![
            (
                "AETHERFLOW_SELF_UPDATE_STATUS_FILE",
                job_status_path.to_string_lossy().into_owned(),
            ),
            ("AETHERFLOW_SELF_UPDATE_JOB_UNIT", unit_name.clone()),
            (
                "AETHERFLOW_SELF_UPDATE_DIRECTORY_DEV",
                receipt_directory_identity.0.to_string(),
            ),
            (
                "AETHERFLOW_SELF_UPDATE_DIRECTORY_INO",
                receipt_directory_identity.1.to_string(),
            ),
            (
                "AETHERFLOW_RELEASE_CONF",
                job_conf_path.to_string_lossy().into_owned(),
            ),
            (
                "AETHERFLOW_MAINTENANCE_LOCK_PATH",
                cfg_lock_path.to_string_lossy().into_owned(),
            ),
            (
                "AETHERFLOW_DB_PATH",
                cfg_db_path.to_string_lossy().into_owned(),
            ),
            (
                "AETHERFLOW_BACKUP_DIR",
                cfg_backup_dir.to_string_lossy().into_owned(),
            ),
        ];
        if let Some(ref root) = explicit_root {
            extra_envs.push((
                "AETHERFLOW_RELEASE_ROOT",
                root.to_string_lossy().into_owned(),
            ));
        }

        match spawn_self_update_transient_unit(
            &unit_name,
            Path::new("/bin/bash"),
            &unit_args,
            &extra_envs,
        )
        .await
        {
            Ok(_) => {
                let mut admitted = initial_status.clone();
                admitted.status = "running".into();
                let observed = match job_receipts::compare_exchange(
                    &job_status_path,
                    &initial_status,
                    &admitted,
                ) {
                    Ok(observed) => observed,
                    Err(error) => {
                        return (StatusCode::INTERNAL_SERVER_ERROR, RunnerResponse {
                            success: false, output: String::new(), error: format!("Unit admitted but launch acknowledgment could not be persisted: {error}"),
                        });
                    }
                };
                (
                    StatusCode::OK,
                    self_update_launch_response(
                        "legacy_bash_release",
                        &cmd_name,
                        &channel_str,
                        &observed,
                    ),
                )
            }
            Err((code, err_msg)) => {
                if code != StatusCode::GATEWAY_TIMEOUT {
                    let failed_receipt = SelfUpdateJobStatus {
                        status: "failed".to_string(),
                        completed: true,
                        success: false,
                        job_unit: unit_name.clone(),
                        error: err_msg.clone(),
                        exit_code: Some(1),
                    };
                    let _ = job_receipts::compare_exchange(
                        &job_status_path,
                        &initial_status,
                        &failed_receipt,
                    );
                    let _ = fs::remove_file(&job_conf_path);
                }
                (
                    code,
                    RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: err_msg,
                    },
                )
            }
        }
    } else {
        let _guard = BACKUP_MUTEX.lock().await;
        let sync_conf_path = cfg_jobs_dir.join(format!("sync-{}.conf", std::process::id()));
        if let Err(err) = cfg.write_protected_config_file(&sync_conf_path) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: format!("failed to persist sync self-update config: {}", err),
                },
            );
        }
        let mut cmd = Command::new("/bin/bash");
        cmd.arg(&script_path)
            .arg(&cmd_name)
            .arg("--channel")
            .arg(&channel_str);
        if let Some(ref root) = explicit_root {
            cmd.arg("--root").arg(root);
            cmd.env("AETHERFLOW_RELEASE_ROOT", root);
        }
        cmd.arg("--config").arg(&sync_conf_path);
        cmd.env("AETHERFLOW_RELEASE_CONF", &sync_conf_path);
        cmd.env("AETHERFLOW_MAINTENANCE_LOCK_PATH", &cfg_lock_path);
        cmd.env("AETHERFLOW_DB_PATH", &cfg_db_path);
        cmd.env("AETHERFLOW_BACKUP_DIR", &cfg_backup_dir);

        let res = cmd.output().await;
        let _ = fs::remove_file(&sync_conf_path);
        match res {
            Ok(out) => {
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                if out.status.success() {
                    (
                        StatusCode::OK,
                        RunnerResponse {
                            success: true,
                            output: combined,
                            error: String::new(),
                        },
                    )
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        RunnerResponse {
                            success: false,
                            output: combined,
                            error: format!("exit status: {}", out.status),
                        },
                    )
                }
            }
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: err.to_string(),
                },
            ),
        }
    }
}

/// Empty job identity discovers all persisted receipts, even after API/runner
/// restart. Missing directories mean no jobs; unreadable/corrupt state fails closed.
pub async fn query_self_update_status_local(
    job_unit: &str,
) -> Result<SelfUpdateJobStatus, (StatusCode, String)> {
    if !job_unit.trim().is_empty() {
        return query_self_update_job_status_local(job_unit).await;
    }
    let root =
        resolve_self_update_isolated_root_from_env().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let conf = af_release::resolve_release_manager_conf_for_root(root.as_deref());
    let cfg =
        af_release::ReleaseConfig::load_for_root_from_process_env(root.as_deref(), conf.as_deref())
            .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    discover_system_update(&cfg).await
}

fn update_status_allows_launch(
    status: &SelfUpdateJobStatus,
    command: af_release::ReleaseCommand,
) -> bool {
    status.completed
        || (status.status == "recovery_required" && command == af_release::ReleaseCommand::Rollback)
}

async fn discover_system_update(
    cfg: &af_release::ReleaseConfig,
) -> Result<SelfUpdateJobStatus, (StatusCode, String)> {
    let dir = resolve_self_update_jobs_dir_for_cfg(cfg)?;
    match job_receipts::ReceiptDirectory::open_existing(&dir) {
        Ok(Some(directory)) => {
            let names = directory
                .names()
                .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
            for name in names {
                let path = dir.join(name);
                if path.extension().and_then(|p| p.to_str()) != Some("json") {
                    continue;
                }
                let unit = path
                    .file_stem()
                    .and_then(|p| p.to_str())
                    .unwrap_or_default();
                validate_self_update_job_unit_name(unit)
                    .map_err(|(_, error)| (StatusCode::SERVICE_UNAVAILABLE, error))?;
                let status = query_self_update_job_in(unit, &path, &directory).await?;
                if !status.completed {
                    return Ok(status);
                }
            }
        }
        Ok(None) => {}
        Err(e) => return Err((StatusCode::SERVICE_UNAVAILABLE, e.to_string())),
    }
    let recovery = af_release::RecoveryState::load(&cfg.releases_dir)
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    if recovery
        .is_some_and(|r| r.is_unfinished() || r.has_unhealthy_or_interrupted_post_swap_deploy())
    {
        return Ok(SelfUpdateJobStatus {
            status: "recovery_required".into(),
            completed: false,
            success: false,
            job_unit: String::new(),
            error: "System update recovery is required before application work".into(),
            exit_code: None,
        });
    }
    Ok(SelfUpdateJobStatus {
        status: "succeeded".into(),
        completed: true,
        success: true,
        job_unit: String::new(),
        error: String::new(),
        exit_code: Some(0),
    })
}

/// API admission holds this only while checking updater receipts and persisting
/// its job. Updaters inspect that durable row under the same lock before launch.
pub fn acquire_lifecycle_admission_lock(
    root: Option<&Path>,
) -> anyhow::Result<af_release::ReleaseLockGuard> {
    let env_root = resolve_self_update_isolated_root_from_env().map_err(|e| anyhow::anyhow!(e))?;
    let root = root.or(env_root.as_deref());
    let conf = af_release::resolve_release_manager_conf_for_root(root);
    let cfg = af_release::ReleaseConfig::load_for_root_from_process_env(root, conf.as_deref())?;
    let path = af_release::ensure_interoperable_maintenance_lock_file(&cfg)?;
    Ok(af_release::ReleaseLockGuard::acquire(path, Duration::ZERO)?)
}

/// Same cross-process lock used by local releases. Order: package process lock,
/// package flock, maintenance lock. Updater launch takes only maintenance.
async fn acquire_package_maintenance_guard(
    root: Option<&Path>,
    target: af_release::lifecycle::ReservationTarget<'_>,
    job_id: &str,
    action: Option<&str>,
) -> anyhow::Result<af_release::ReleaseLockGuard> {
    let conf = af_release::resolve_release_manager_conf_for_root(root).filter(|conf_path| {
        root.map(|explicit_root| conf_path.starts_with(explicit_root))
            .unwrap_or(true)
    });
    let cfg = if let Some(explicit_root) = root {
        let mut env_map: HashMap<String, String> = env::vars().collect();
        env_map.remove("AETHERFLOW_RELEASE_ROOT");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            if let Some(val) = env_map.get(key) {
                if !Path::new(val.trim()).starts_with(explicit_root) {
                    env_map.remove(key);
                }
            }
        }
        af_release::ReleaseConfig::load_for_root_with_env(
            Some(explicit_root),
            conf.as_deref(),
            &env_map,
        )?
    } else {
        af_release::ReleaseConfig::load_for_root_from_process_env(root, conf.as_deref())?
    };
    let path = af_release::ensure_interoperable_maintenance_lock_file(&cfg)?;
    let owned_restore = !job_id.is_empty()
        && matches!(target, af_release::lifecycle::ReservationTarget::Service(_));
    let guard = if owned_restore {
        tokio::task::spawn_blocking(move || {
            af_release::ReleaseLockGuard::acquire(path, Duration::from_secs(30))
        })
        .await??
    } else {
        af_release::ReleaseLockGuard::acquire(path, Duration::ZERO)?
    };
    let status = discover_system_update(&cfg)
        .await
        .map_err(|(_, e)| anyhow::anyhow!(e))?;
    anyhow::ensure!(status.completed, LifecycleBusy);
    let database = af_release::config::try_resolve_db_path(&cfg, None)?.path;
    if database.exists() {
        let conn = rusqlite::Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        conn.busy_timeout(Duration::from_secs(5))?;
        af_release::lifecycle::reconcile_jobs(&conn, &database)?;
        match target {
            af_release::lifecycle::ReservationTarget::Package(package) => {
                let units = package_lifecycle::package_service_units(package)?;
                af_release::lifecycle::check_package_reservation(
                    &conn, package, &units, job_id, action,
                )
            }
            _ => af_release::lifecycle::check_reservation(&conn, target, job_id, action),
        }
        .map_err(|error| error.context(LifecycleBusy))?;
    } else {
        anyhow::ensure!(
            job_id.is_empty(),
            "Lifecycle reservation database is missing"
        );
    }
    Ok(guard)
}

pub(crate) async fn acquire_owned_lifecycle_snapshot_guard(
    root: Option<&Path>,
    package: &str,
    job_id: &str,
) -> anyhow::Result<(af_release::ReleaseLockGuard, PathBuf)> {
    anyhow::ensure!(!job_id.trim().is_empty(), "lifecycle_job_id is required");
    let conf = af_release::resolve_release_manager_conf_for_root(root).filter(|conf_path| {
        root.map(|explicit_root| conf_path.starts_with(explicit_root))
            .unwrap_or(true)
    });
    let cfg = if let Some(explicit_root) = root {
        let mut env_map: HashMap<String, String> = env::vars().collect();
        env_map.remove("AETHERFLOW_RELEASE_ROOT");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            if let Some(val) = env_map.get(key) {
                if !Path::new(val.trim()).starts_with(explicit_root) {
                    env_map.remove(key);
                }
            }
        }
        af_release::ReleaseConfig::load_for_root_with_env(
            Some(explicit_root),
            conf.as_deref(),
            &env_map,
        )?
    } else {
        af_release::ReleaseConfig::load_for_root_from_process_env(root, conf.as_deref())?
    };
    let path = af_release::ensure_interoperable_maintenance_lock_file(&cfg)?;
    let guard = tokio::task::spawn_blocking(move || {
        af_release::ReleaseLockGuard::acquire(path, Duration::from_secs(10))
    })
    .await??;
    let status = discover_system_update(&cfg)
        .await
        .map_err(|(_, e)| anyhow::anyhow!(e))?;
    anyhow::ensure!(status.completed, LifecycleBusy);
    let database = af_release::config::try_resolve_db_path(&cfg, None)?.path;
    anyhow::ensure!(
        database.exists(),
        "Lifecycle reservation database is missing"
    );
    let conn = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )?;
    conn.busy_timeout(Duration::from_secs(5))?;
    af_release::lifecycle::reconcile_jobs(&conn, &database)?;
    let units = package_lifecycle::package_service_units(package)?;
    af_release::lifecycle::check_package_reservation(&conn, package, &units, job_id, None)
        .map_err(|error| error.context(LifecycleBusy))?;
    let action: String = conn.query_row(
        "SELECT action FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
        rusqlite::params![package, job_id],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        matches!(action.as_str(), "install" | "reinstall" | "update"),
        "removal cannot own lifecycle runtime snapshots"
    );
    Ok((guard, database))
}

fn service_reservation_target<'a>(
    service: &'a str,
    action: &str,
) -> af_release::lifecycle::ReservationTarget<'a> {
    if matches!(
        service.trim_end_matches(".service"),
        "aetherflow-api" | "aetherflow-runner"
    ) && matches!(action, "stop" | "restart" | "restart-deferred")
    {
        af_release::lifecycle::ReservationTarget::System
    } else {
        af_release::lifecycle::ReservationTarget::Service(service)
    }
}

pub async fn acquire_service_maintenance_guard(
    service: &str,
    action: &str,
) -> anyhow::Result<af_release::ReleaseLockGuard> {
    acquire_package_maintenance_guard(
        PackageExecutionEnv::default().fs_root.as_deref(),
        service_reservation_target(service, action),
        &current_package_job_id(),
        None,
    )
    .await
}

async fn query_self_update_job_status_local(
    job_unit: &str,
) -> Result<SelfUpdateJobStatus, (StatusCode, String)> {
    let valid_unit = validate_self_update_job_unit_name(job_unit)?;
    let jobs_dir = resolve_self_update_jobs_dir_from_env()?;
    let status_path = jobs_dir.join(format!("{}.json", valid_unit));
    query_self_update_job_at(&valid_unit, &status_path).await
}

async fn query_self_update_job_at(
    valid_unit: &str,
    status_path: &Path,
) -> Result<SelfUpdateJobStatus, (StatusCode, String)> {
    let directory = job_receipts::ReceiptDirectory::open_existing(
        status_path.parent().unwrap_or(Path::new(".")),
    )
    .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("self-update job '{valid_unit}' not found"),
        )
    })?;
    query_self_update_job_in(valid_unit, status_path, &directory).await
}

async fn query_self_update_job_in(
    valid_unit: &str,
    status_path: &Path,
    directory: &job_receipts::ReceiptDirectory,
) -> Result<SelfUpdateJobStatus, (StatusCode, String)> {
    let name = status_path.file_name().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Missing receipt filename".into(),
        )
    })?;
    if let Some(mut parsed) = directory.read_status(name, valid_unit).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidData {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("corrupt self-update status file: {error}"),
            )
        } else {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Cannot read confined self-update status: {error}"),
            )
        }
    })? {
        if parsed.completed {
            return Ok(parsed);
        }
        if directory
            .launch_is_alive(name, parsed.status == "launching")
            .map_err(|error| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Cannot verify launch owner: {error}"),
                )
            })?
        {
            return Ok(parsed);
        }

        let custom_systemd_run = env::var("AETHERFLOW_SYSTEMD_RUN_BIN")
            .map(|val| !val.trim().is_empty())
            .unwrap_or(false);
        let systemctl_bin = env::var("AETHERFLOW_SYSTEMCTL_BIN")
            .ok()
            .map(|val| val.trim().to_string())
            .filter(|val| !val.is_empty());
        if cfg!(target_os = "linux") && (!custom_systemd_run || systemctl_bin.is_some()) {
            let ctl_prog = systemctl_bin.as_deref().unwrap_or("systemctl");
            if let Ok(Ok(out)) = tokio::time::timeout(
                Duration::from_secs(5),
                Command::new(ctl_prog)
                    .args([
                        "show",
                        "--property=LoadState,ActiveState,SubState,Result,ExecMainStatus",
                        valid_unit,
                    ])
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            {
                {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let mut load_state = "";
                    let mut active_state = "";
                    let mut sub_state = "";
                    let mut result_prop = "";
                    let mut exec_status: Option<i32> = None;
                    for line in stdout.lines() {
                        if let Some(val) = line.strip_prefix("LoadState=") {
                            load_state = val.trim();
                        } else if let Some(val) = line.strip_prefix("ActiveState=") {
                            active_state = val.trim();
                        } else if let Some(val) = line.strip_prefix("SubState=") {
                            sub_state = val.trim();
                        } else if let Some(val) = line.strip_prefix("Result=") {
                            result_prop = val.trim();
                        } else if let Some(val) = line.strip_prefix("ExecMainStatus=") {
                            exec_status = val.trim().parse::<i32>().ok();
                        }
                    }
                    let unit_no_longer_running =
                        matches!(load_state, "loaded" | "not-found" | "error" | "masked")
                            && matches!(active_state, "failed" | "inactive");
                    if unit_no_longer_running {
                        if valid_unit.contains("-restart-")
                            && core_restart_timer_pending(ctl_prog, valid_unit).await?
                        {
                            return Ok(parsed);
                        }
                        let expected = parsed.clone();
                        let reread_status = directory
                            .read_status(name, valid_unit)
                            .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?
                            .ok_or_else(|| {
                                (
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "Receipt disappeared during reconciliation".into(),
                                )
                            })?;
                        if reread_status.completed {
                            return Ok(reread_status);
                        }
                        parsed.status = "failed".to_string();
                        parsed.completed = true;
                        parsed.success = false;
                        parsed.exit_code = exec_status.filter(|code| *code != 0).or(Some(1));
                        if parsed.error.is_empty() {
                            parsed.error = format!(
                                "transient systemd unit '{}' terminated without writing completion receipt (LoadState={}, ActiveState={}, SubState={}, Result={}, exit_code={:?})",
                                valid_unit,
                                load_state,
                                active_state,
                                sub_state,
                                result_prop,
                                parsed.exit_code
                            );
                        }
                        return directory
                            .compare_exchange(name, &expected, &parsed)
                            .map_err(|error| {
                                (
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    format!("Cannot persist reconciled updater status: {error}"),
                                )
                            });
                    }
                    if load_state == "loaded"
                        && matches!(
                            active_state,
                            "active" | "activating" | "deactivating" | "reloading"
                        )
                    {
                        if parsed.status == "launching" {
                            let mut admitted = parsed.clone();
                            admitted.status = "running".into();
                            return directory
                                .compare_exchange(name, &parsed, &admitted)
                                .map_err(|error| {
                                    (StatusCode::SERVICE_UNAVAILABLE, error.to_string())
                                });
                        }
                        return Ok(parsed);
                    }
                }
            }
            return Err((StatusCode::SERVICE_UNAVAILABLE,
                format!("Cannot determine authoritative systemd state for '{valid_unit}'; receipt retained as unresolved. Retry status after restoring systemd access.")));
        }
        return Ok(parsed);
    }

    Err((
        StatusCode::NOT_FOUND,
        format!("self-update job '{}' not found", valid_unit),
    ))
}

async fn core_restart_timer_pending(
    program: &str,
    unit: &str,
) -> Result<bool, (StatusCode, String)> {
    let timer = format!("{}.timer", unit.trim_end_matches(".service"));
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(program)
            .args(["show", "--property=LoadState,ActiveState,SubState", &timer])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Core restart timer query timed out".into(),
        )
    })?
    .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let load = text
        .lines()
        .find_map(|line| line.strip_prefix("LoadState="))
        .unwrap_or("");
    let active = text
        .lines()
        .find_map(|line| line.strip_prefix("ActiveState="))
        .unwrap_or("");
    let phase = text
        .lines()
        .find_map(|line| line.strip_prefix("SubState="))
        .unwrap_or("");
    if load == "loaded"
        && matches!(active, "active" | "activating" | "deactivating")
        && matches!(phase, "waiting" | "running")
    {
        return Ok(true);
    }
    if load == "loaded" && active == "active" && phase == "elapsed" {
        return Ok(false);
    }
    if matches!(load, "loaded" | "not-found" | "error" | "masked")
        && matches!(active, "inactive" | "failed")
    {
        return Ok(false);
    }
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "Core restart timer state is unknown; admission remains reserved".into(),
    ))
}

async fn handle_self_update(
    Json(req): Json<SelfUpdateRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let (status, resp) = execute_self_update_request(&req, true).await;
    (status, Json(resp))
}

async fn handle_self_update_status(
    Json(req): Json<SelfUpdateStatusRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match query_self_update_status_local(&req.job_unit).await {
        Ok(status_payload) => {
            let output = serde_json::to_string(&status_payload).unwrap_or_default();
            (
                StatusCode::OK,
                Json(RunnerResponse {
                    success: true,
                    output,
                    error: String::new(),
                }),
            )
        }
        Err((code, err_msg)) => (
            code,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: err_msg,
            }),
        ),
    }
}

type RunnerResolvedBackupConfig = (
    af_host::HostBackupConfig,
    Option<PathBuf>,
    Option<u32>,
    Option<u32>,
);

fn resolve_server_owned_backup_config(
    app_version: &str,
) -> Result<RunnerResolvedBackupConfig, (StatusCode, String)> {
    let isolated_root = af_models::try_resolve_isolated_root_with_env(None, |k| env::var(k).ok())
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let active_db = af_models::try_resolve_active_db_path_from_env(
        isolated_root.as_deref(),
        "/var/lib/aetherflow/aetherflow.sqlite",
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let active_backup_dir = af_models::try_resolve_active_backup_dir_from_env(
        isolated_root.as_deref(),
        Some(&active_db),
        "/var/lib/aetherflow/backups",
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let (env_sqlite_uid, env_sqlite_gid) =
        af_models::try_resolve_trusted_sqlite_ids_from_env(isolated_root.as_deref())
            .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    if let Some(root_path) = isolated_root {
        let mut cfg = af_host::HostBackupConfig::for_isolated_root(&root_path, app_version);
        cfg.backup_dir = active_backup_dir;
        cfg.sqlite_db_path = Some(active_db);
        cfg.snapshot_options.trusted_source_uid = env_sqlite_uid;
        return Ok((cfg, Some(root_path), env_sqlite_uid, env_sqlite_gid));
    }

    let mut cfg = af_host::HostBackupConfig {
        app_version: app_version.to_string(),
        backup_dir: active_backup_dir,
        sqlite_db_path: Some(active_db),
        ..Default::default()
    };
    cfg.snapshot_options.trusted_source_uid = env_sqlite_uid;
    Ok((cfg, None, env_sqlite_uid, env_sqlite_gid))
}

fn build_runner_backup_config(
    req: &BackupRunnerRequest,
) -> Result<RunnerResolvedBackupConfig, (StatusCode, String)> {
    let app_version = if req.app_version.trim().is_empty() {
        "v4.0.0"
    } else {
        req.app_version.trim()
    };

    let (mut cfg, isolated_root, mut trusted_sqlite_uid, mut trusted_sqlite_gid) =
        resolve_server_owned_backup_config(app_version)?;

    if let Some(req_uid) = req.trusted_sqlite_uid {
        if let Some(existing_uid) = trusted_sqlite_uid {
            if existing_uid != req_uid {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!(
                        "untrusted trusted_sqlite_uid override '{}' rejected: runner enforces configured UID {}",
                        req_uid, existing_uid
                    ),
                ));
            }
        } else if isolated_root.is_some() {
            trusted_sqlite_uid = Some(req_uid);
        } else {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "untrusted trusted_sqlite_uid override '{}' rejected without server-side configuration",
                    req_uid
                ),
            ));
        }
    }
    if let Some(req_gid) = req.trusted_sqlite_gid {
        if let Some(existing_gid) = trusted_sqlite_gid {
            if existing_gid != req_gid {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!(
                        "untrusted trusted_sqlite_gid override '{}' rejected: runner enforces configured GID {}",
                        req_gid, existing_gid
                    ),
                ));
            }
        } else if isolated_root.is_some() {
            trusted_sqlite_gid = Some(req_gid);
        } else {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "untrusted trusted_sqlite_gid override '{}' rejected without server-side configuration",
                    req_gid
                ),
            ));
        }
    }
    cfg.snapshot_options.trusted_source_uid = trusted_sqlite_uid;

    if !req.backup_dir.trim().is_empty() {
        let req_bdir = PathBuf::from(req.backup_dir.trim());
        af_host::validate_no_parent_traversal(&req_bdir, "backup_dir")
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let allowed = req_bdir == cfg.backup_dir
            || isolated_root
                .as_ref()
                .map(|iso| req_bdir.starts_with(iso))
                .unwrap_or(false);
        if !allowed {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "untrusted backup_dir override '{}' rejected: runner enforces server-owned backup root '{}'",
                    req_bdir.display(),
                    cfg.backup_dir.display()
                ),
            ));
        }
        cfg.backup_dir = req_bdir;
    }

    if !req.db_path.trim().is_empty() {
        let req_db = PathBuf::from(req.db_path.trim());
        af_host::validate_no_parent_traversal(&req_db, "db_path")
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        let allowed = cfg.sqlite_db_path.as_ref() == Some(&req_db)
            || isolated_root
                .as_ref()
                .map(|iso| req_db.starts_with(iso))
                .unwrap_or(false);
        if !allowed {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "untrusted db_path override '{}' rejected: runner enforces server-owned database path",
                    req_db.display()
                ),
            ));
        }
        cfg.sqlite_db_path = Some(req_db);
    }

    if let Some(chunk_sz) = req.chunk_size_bytes {
        cfg.chunk_size_bytes = if chunk_sz > 0 { Some(chunk_sz) } else { None };
    }
    if let Some(days) = req.retention_days {
        cfg.retention_days = days;
    }
    if let Some(max_keep) = req.max_retained {
        cfg.max_retained_backups = max_keep;
    }
    Ok((cfg, isolated_root, trusted_sqlite_uid, trusted_sqlite_gid))
}

fn validate_runner_restore_target_root(raw_target: &str) -> Result<PathBuf, (StatusCode, String)> {
    let trimmed = raw_target.trim();
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "target_root must not be empty".to_string(),
        ));
    }
    let target = PathBuf::from(trimmed);
    if target == Path::new("/") {
        return Ok(target);
    }
    af_host::validate_no_parent_traversal(&target, "target_root")
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    if target.starts_with("/var/lib/aetherflow/restore-staging") {
        return Ok(target);
    }
    if let Ok(staging_env) = env::var("AETHERFLOW_RESTORE_STAGING_ROOT") {
        let st = staging_env.trim();
        if !st.is_empty() && target.starts_with(Path::new(st)) {
            return Ok(target);
        }
    }
    if let Ok(Some(iso_path)) =
        af_models::try_resolve_isolated_root_with_env(None, |k| env::var(k).ok())
    {
        if target.starts_with(&iso_path)
            || iso_path
                .parent()
                .map(|p| target.starts_with(p))
                .unwrap_or(false)
        {
            return Ok(target);
        }
    }

    Err((
        StatusCode::FORBIDDEN,
        format!(
            "untrusted target_root '{}' rejected: runner only permits '/' (canonical FHS mapping) or configured restore-staging roots",
            target.display()
        ),
    ))
}

/// Executes a validated `BackupRunnerRequest` using `af-host` with serialized write locking.
pub async fn execute_backup_local(
    req: &BackupRunnerRequest,
) -> Result<BackupRunnerResponse, (StatusCode, String)> {
    let action = req.action.trim();
    if !ALLOWED_BACKUP_ACTIONS.contains(action) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("disallowed backup action: {:?}", action),
        ));
    }

    let _guard = BACKUP_MUTEX.lock().await;
    let (cfg, isolated_root, trusted_sqlite_uid, trusted_sqlite_gid) =
        build_runner_backup_config(req)?;
    let canonical_lock_path = af_models::try_resolve_canonical_maintenance_lock_path_from_env(
        isolated_root.as_deref(),
        cfg.sqlite_db_path.as_deref(),
        Some(&cfg.backup_dir),
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
    let _maint_lock =
        af_host::HostMaintenanceLockGuard::acquire(&canonical_lock_path, Duration::from_secs(30))
            .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;

    let slug_opt = if req.timestamp_slug.trim().is_empty() {
        None
    } else {
        Some(req.timestamp_slug.trim())
    };

    let effective_action = if action == "create" {
        if req.kind.eq_ignore_ascii_case("archive") || req.kind.eq_ignore_ascii_case("full") {
            "create_archive"
        } else {
            "create_sqlite"
        }
    } else {
        action
    };

    match effective_action {
        "create_sqlite" => {
            let receipt = af_host::create_sqlite_snapshot_backup(&cfg, slug_opt)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let filename = receipt
                .primary_artifact_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let sha256 = receipt
                .manifest
                .sqlite_snapshot
                .as_ref()
                .map(|s| s.sha256.clone())
                .unwrap_or_default();
            let size_bytes = receipt
                .manifest
                .sqlite_snapshot
                .as_ref()
                .map(|s| s.size_bytes)
                .unwrap_or(0);
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                backup_id: receipt.manifest.backup_id.clone(),
                filename,
                artifact_path: receipt.primary_artifact_path.to_string_lossy().into_owned(),
                manifest_path: receipt.manifest_path.to_string_lossy().into_owned(),
                sha256,
                size_bytes,
                chunk_count: receipt.chunk_paths.len(),
                verified: true,
                restored_files: 0,
                rolled_back: false,
                details: serde_json::to_value(&receipt.manifest).unwrap_or(Value::Null),
            })
        }
        "create_archive" => {
            let receipt = af_host::create_host_archive_backup(&cfg, slug_opt)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let filename = receipt
                .primary_artifact_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let primary_entry = receipt.manifest.entries.first();
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                backup_id: receipt.manifest.backup_id.clone(),
                filename,
                artifact_path: receipt.primary_artifact_path.to_string_lossy().into_owned(),
                manifest_path: receipt.manifest_path.to_string_lossy().into_owned(),
                sha256: primary_entry.map(|e| e.sha256.clone()).unwrap_or_default(),
                size_bytes: fs::metadata(&receipt.primary_artifact_path)
                    .map(|m| m.len())
                    .unwrap_or(0),
                chunk_count: receipt.chunk_paths.len(),
                verified: true,
                restored_files: 0,
                rolled_back: false,
                details: serde_json::to_value(&receipt.manifest).unwrap_or(Value::Null),
            })
        }
        "list" => {
            let inv = af_host::list_backup_inventory(&cfg.backup_dir)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                verified: true,
                details: serde_json::to_value(&inv).unwrap_or(Value::Array(Vec::new())),
                ..Default::default()
            })
        }
        "verify" => {
            let filename = req.filename.trim();
            af_host::validate_backup_filename(filename)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            let (ver, manifest) = af_host::verify_backup_artifact_with_trusted_uid(
                &cfg.backup_dir,
                filename,
                trusted_sqlite_uid,
            )
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                backup_id: manifest
                    .as_ref()
                    .map(|m| m.backup_id.clone())
                    .unwrap_or_default(),
                filename: filename.to_string(),
                artifact_path: ver.artifact_path.to_string_lossy().into_owned(),
                manifest_path: manifest
                    .as_ref()
                    .map(|_| format!("{}.manifest.json", ver.artifact_path.display()))
                    .unwrap_or_default(),
                sha256: ver.actual_sha256,
                size_bytes: ver.size_bytes,
                verified: ver.verified,
                details: serde_json::to_value(&manifest).unwrap_or(Value::Null),
                ..Default::default()
            })
        }
        "delete" => {
            let filename = req.filename.trim();
            af_host::validate_backup_filename(filename)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            let removed = af_host::delete_backup_artifacts(&cfg.backup_dir, filename)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                filename: filename.to_string(),
                verified: true,
                details: json!({
                    "removed_files": removed.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>(),
                }),
                ..Default::default()
            })
        }
        "prune" => {
            let removed = af_host::prune_backup_inventory(
                &cfg.backup_dir,
                cfg.max_retained_backups,
                cfg.retention_days,
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(BackupRunnerResponse {
                action: action.to_string(),
                verified: true,
                details: json!({
                    "removed_files": removed,
                }),
                ..Default::default()
            })
        }
        "restore_preflight" => {
            let filename = req.filename.trim();
            af_host::validate_backup_filename(filename)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            let target_root = validate_runner_restore_target_root(&req.target_root)?;
            let (ver, maybe_manifest) = af_host::verify_backup_artifact_with_trusted_uid(
                &cfg.backup_dir,
                filename,
                trusted_sqlite_uid,
            )
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            let manifest = maybe_manifest.ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("backup '{}' is missing a .manifest.json sidecar", filename),
                )
            })?;
            let opts = af_host::RestorePreflightOptions {
                host_app_version: cfg.app_version.clone(),
                max_supported_sqlite_user_version: req.max_sqlite_user_version,
                overwrite_policy: if req.allow_overwrite {
                    af_host::OverwritePolicy::AllowRegularFilesInStaging
                } else {
                    af_host::OverwritePolicy::RejectExisting
                },
                require_artifact_sidecar: true,
            };
            let sqlite_override_buf = af_models::resolve_contained_sqlite_restore_override(
                &target_root,
                cfg.sqlite_db_path.as_deref(),
            );
            let sqlite_override = sqlite_override_buf.as_deref();
            let sqlite_target_rel = sqlite_override
                .and_then(|db_p| af_models::derive_sqlite_target_rel_path(&target_root, db_p));
            let plan = if filename.ends_with(".tar.gz") {
                af_host::preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid(
                    &ver.artifact_path,
                    &manifest,
                    &target_root,
                    &opts,
                    sqlite_target_rel.as_deref(),
                    sqlite_override,
                    trusted_sqlite_uid,
                )
            } else {
                af_host::preflight_restore_directory_with_sqlite_overrides_and_trusted_uid(
                    &cfg.backup_dir,
                    &manifest,
                    &target_root,
                    &opts,
                    sqlite_target_rel.as_deref(),
                    sqlite_override,
                    trusted_sqlite_uid,
                )
            }
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            Ok(BackupRunnerResponse {
                action: action.to_string(),
                backup_id: manifest.backup_id,
                filename: filename.to_string(),
                artifact_path: ver.artifact_path.to_string_lossy().into_owned(),
                manifest_path: format!("{}.manifest.json", ver.artifact_path.display()),
                sha256: ver.actual_sha256,
                size_bytes: ver.size_bytes,
                verified: true,
                restored_files: plan.items.len(),
                rolled_back: false,
                details: serde_json::to_value(&plan).unwrap_or(Value::Null),
                ..Default::default()
            })
        }
        "restore_execute" => {
            let filename = req.filename.trim();
            af_host::validate_backup_filename(filename)
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            let validated_quiesce =
                af_host::validate_quiesce_service_entries(&req.quiesce_services)
                    .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            for svc in &validated_quiesce {
                if !SAFE_SERVICE_NAME.is_match(svc) || svc.contains("..") {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("invalid quiesce service unit name: {:?}", svc),
                    ));
                }
            }
            let target_root = validate_runner_restore_target_root(&req.target_root)?;
            let trusted_sqlite_db_path = af_models::resolve_contained_sqlite_restore_override(
                &target_root,
                cfg.sqlite_db_path.as_deref(),
            );
            let sqlite_target_rel_path = trusted_sqlite_db_path
                .as_deref()
                .and_then(|db_p| af_models::derive_sqlite_target_rel_path(&target_root, db_p));
            let exec_opts = af_host::RestoreExecutionOptions {
                host_app_version: cfg.app_version.clone(),
                max_supported_sqlite_user_version: req.max_sqlite_user_version,
                confirm_destructive_restore: req.confirm_destructive_restore,
                allow_overwrite: req.allow_overwrite,
                quiesce_services: af_host::resolve_effective_quiesce_services(&validated_quiesce),
                sqlite_target_rel_path,
                trusted_sqlite_db_path,
                trusted_sqlite_uid,
                trusted_sqlite_gid,
                ..Default::default()
            };

            let dry_quiesce = env::var("AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE")
                .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
                || af_models::try_resolve_isolated_root_with_env(None, |k| env::var(k).ok())
                    .ok()
                    .flatten()
                    .is_some()
                || !cfg!(target_os = "linux");

            let report = if dry_quiesce {
                af_host::execute_staged_restore(
                    &cfg.backup_dir,
                    filename,
                    &target_root,
                    &exec_opts,
                    &af_host::NoopQuiescenceController,
                )
            } else {
                af_host::execute_staged_restore(
                    &cfg.backup_dir,
                    filename,
                    &target_root,
                    &exec_opts,
                    &af_host::CommandQuiescenceController::default(),
                )
            }
            .map_err(|err| {
                let code = match err {
                    af_host::HostBackupError::DestructiveRestoreUnsupported { .. }
                    | af_host::HostBackupError::UnsafeOverwriteRejected { .. }
                    | af_host::HostBackupError::TraversalRejected { .. }
                    | af_host::HostBackupError::SymlinkRejected { .. }
                    | af_host::HostBackupError::ChecksumMismatch { .. }
                    | af_host::HostBackupError::InvalidManifest(_)
                    | af_host::HostBackupError::InvalidConfig(_) => StatusCode::BAD_REQUEST,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (code, err.to_string())
            })?;

            Ok(BackupRunnerResponse {
                action: action.to_string(),
                backup_id: report.backup_id.clone(),
                filename: filename.to_string(),
                verified: true,
                restored_files: report.restored_files.len(),
                rolled_back: report.rolled_back,
                details: serde_json::to_value(&report).unwrap_or(Value::Null),
                ..Default::default()
            })
        }
        "recover_interrupted" => {
            let mut recovery_context = if !req.target_root.trim().is_empty() {
                let target_root = validate_runner_restore_target_root(&req.target_root)?;
                let trusted_sqlite_db_path = af_models::resolve_contained_sqlite_restore_override(
                    &target_root,
                    cfg.sqlite_db_path.as_deref(),
                );
                if target_root == Path::new("/") {
                    af_host::RecoveryContext::for_canonical_host(trusted_sqlite_db_path)
                } else {
                    af_host::RecoveryContext::for_target_root(target_root, trusted_sqlite_db_path)
                }
            } else {
                let trusted_sqlite_db_path = match isolated_root.as_deref() {
                    Some(iso_root) => af_models::resolve_contained_sqlite_restore_override(
                        iso_root,
                        cfg.sqlite_db_path.as_deref(),
                    ),
                    None => cfg.sqlite_db_path.clone(),
                };
                af_host::RecoveryContext::from_host_config(
                    isolated_root.as_deref(),
                    trusted_sqlite_db_path,
                )
            };
            recovery_context.trusted_sqlite_uid = trusted_sqlite_uid;
            recovery_context.trusted_sqlite_gid = trusted_sqlite_gid;

            let dry_quiesce = env::var("AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
                || af_models::try_resolve_isolated_root_with_env(None, |k| env::var(k).ok())
                    .ok()
                    .flatten()
                    .is_some()
                || !cfg!(target_os = "linux");

            let recovered_directories = if dry_quiesce {
                af_host::recover_interrupted_restore_with_context(
                    &cfg.backup_dir,
                    &recovery_context,
                    &af_host::NoopQuiescenceController,
                )
            } else {
                af_host::recover_interrupted_restore_with_context(
                    &cfg.backup_dir,
                    &recovery_context,
                    &af_host::CommandQuiescenceController::default(),
                )
            }
            .map_err(|err| {
                let code = match err {
                    af_host::HostBackupError::DestructiveRestoreUnsupported { .. }
                    | af_host::HostBackupError::UnsafeOverwriteRejected { .. }
                    | af_host::HostBackupError::TraversalRejected { .. }
                    | af_host::HostBackupError::SymlinkRejected { .. }
                    | af_host::HostBackupError::ChecksumMismatch { .. }
                    | af_host::HostBackupError::PathValidation { .. }
                    | af_host::HostBackupError::InvalidManifest(_)
                    | af_host::HostBackupError::InvalidConfig(_) => StatusCode::BAD_REQUEST,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (code, err.to_string())
            })?;

            Ok(BackupRunnerResponse {
                action: action.to_string(),
                verified: true,
                rolled_back: !recovered_directories.is_empty(),
                details: json!({"recovered_directories": recovered_directories}),
                ..Default::default()
            })
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            "unsupported backup action".to_string(),
        )),
    }
}

async fn handle_backup(Json(req): Json<BackupRunnerRequest>) -> (StatusCode, Json<RunnerResponse>) {
    match execute_backup_local(&req).await {
        Ok(resp) => {
            let output = serde_json::to_string(&resp).unwrap_or_default();
            (
                StatusCode::OK,
                Json(RunnerResponse {
                    success: true,
                    output,
                    error: String::new(),
                }),
            )
        }
        Err((code, err_msg)) => (
            code,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: err_msg,
            }),
        ),
    }
}

pub async fn dispatch_backup_request(
    req: &BackupRunnerRequest,
) -> anyhow::Result<BackupRunnerResponse> {
    if is_runner_available() {
        let resp = post_runner_json("/v1/backup", req, Duration::from_secs(300)).await?;
        if !resp.success {
            anyhow::bail!("runner backup error: {}", resp.error);
        }
        let parsed: BackupRunnerResponse = serde_json::from_str(&resp.output)?;
        return Ok(parsed);
    }
    execute_backup_local(req)
        .await
        .map_err(|(_, msg)| anyhow::anyhow!(msg))
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

pub fn get_runner_package_definition_in_root(
    pkg_id: &str,
    explicit_root: Option<&Path>,
) -> Option<Package> {
    let raw_pkgs = try_load_runner_config_or_embedded_in_root(
        "AETHERFLOW_PACKAGES_CONFIG",
        "packages.json",
        EMBEDDED_PACKAGES_JSON,
        explicit_root,
    )
    .ok()?;
    let raw_auto = try_load_runner_config_or_embedded_in_root(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        "package_automation.json",
        EMBEDDED_AUTOMATION_JSON,
        explicit_root,
    )
    .ok()?;

    let pkgs: Vec<Package> = serde_json::from_str(&raw_pkgs).ok()?;
    let auto_map: HashMap<String, PackageAutomation> =
        serde_json::from_str(&raw_auto).unwrap_or_default();

    let mut package = pkgs.into_iter().find(|p| p.name == pkg_id)?;
    if let Some(automation) = auto_map.get(pkg_id) {
        af_models::merge_package_automation(&mut package, automation);
    }
    Some(package)
}

pub fn get_runner_package_definition(pkg_id: &str) -> Option<Package> {
    get_runner_package_definition_in_root(pkg_id, None)
}

fn normalize_systemd_unit(unit: &str) -> String {
    let trimmed = unit.trim();
    if trimmed.ends_with(".service") || trimmed.ends_with(".timer") || trimmed.ends_with(".socket")
    {
        trimmed.to_string()
    } else {
        format!("{}.service", trimmed)
    }
}

pub(crate) fn is_exempt_sandbox_unit(unit: &str) -> bool {
    let unit = unit.trim();
    unit.ends_with(".timer")
        || unit.ends_with(".socket")
        || matches!(
            unit,
            "aetherflow-api"
                | "aetherflow-runner"
                | "aetherflow-api.service"
                | "aetherflow-runner.service"
                | "fail2ban.service"
                | "pihole-FTL.service"
                | "netdata.service"
                | "node_exporter.service"
                | "apache2.service"
                | "mariadb.service"
                | "mysql.service"
                | "tailscale"
                | "tailscaled"
                | "tailscale.service"
                | "tailscaled.service"
        )
        || unit.starts_with("wg-quick@")
        || unit.starts_with("wireguard")
        || unit.starts_with("tailscale")
        || unit.starts_with("tailscaled")
        || unit.starts_with("mergerfs")
        || unit.starts_with("rclone-vfs")
        || unit.starts_with("scrutiny-collector")
        || unit.starts_with("x2goserver")
        || unit.starts_with("novnc-xvnc")
        || unit.starts_with("novnc-session")
}

fn sandbox_master_user(credentials: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<Value>(credentials) {
        let username = value.get("username")?.as_str()?;
        return SAFE_USERNAME
            .is_match(username)
            .then(|| username.to_string());
    }
    let first = credentials.lines().next()?.trim();
    let username = first
        .strip_prefix("username=")
        .or_else(|| first.split_once(':').map(|(username, _)| username))?;
    SAFE_USERNAME
        .is_match(username)
        .then(|| username.to_string())
}

fn expand_sandbox_path(
    raw: &str,
    service_user: &str,
    service_home: &str,
    master_user: &str,
) -> String {
    let clean = raw
        .trim_start_matches('-')
        .replace("{{SERVICE_USER}}", service_user)
        .replace("{{SERVICE_HOME}}", service_home)
        .replace("{{MASTER_USER}}", master_user);
    let prefixed = if raw.starts_with('-') || !Path::new(&clean).exists() {
        format!("-{}", clean)
    } else {
        clean
    };
    if prefixed.contains(char::is_whitespace) {
        format!("\"{}\"", prefixed)
    } else {
        prefixed
    }
}

pub fn render_systemd_sandbox_dropin(profile: &str, unit: &str, rw_paths: &[String]) -> String {
    let norm_unit = normalize_systemd_unit(unit);
    if is_exempt_sandbox_unit(&norm_unit) {
        return String::new();
    }
    let private_devices = if norm_unit.starts_with("jellyfin")
        || norm_unit.starts_with("plex")
        || norm_unit.starts_with("emby")
        || norm_unit.starts_with("tdarr")
        || norm_unit.starts_with("threadfin")
        || norm_unit.starts_with("scrutiny")
        || norm_unit.starts_with("dispatcharr")
        || norm_unit.starts_with("unmanic")
    {
        "no"
    } else {
        "yes"
    };
    let restrict_namespaces = if norm_unit.starts_with("flaresolverr") {
        "no"
    } else {
        "yes"
    };

    let protect_home = if norm_unit == "librespeed.service" {
        "yes"
    } else {
        "read-only"
    };

    let mut lines = vec![
        "[Service]".to_string(),
        "NoNewPrivileges=yes".to_string(),
        "PrivateTmp=yes".to_string(),
        format!("PrivateDevices={}", private_devices),
        "ProtectSystem=strict".to_string(),
        format!("ProtectHome={}", protect_home),
        "ProtectClock=yes".to_string(),
        "ProtectControlGroups=yes".to_string(),
        "ProtectKernelLogs=yes".to_string(),
        "ProtectKernelModules=yes".to_string(),
        "ProtectKernelTunables=yes".to_string(),
        "ProtectProc=invisible".to_string(),
        "ProcSubset=pid".to_string(),
        "LockPersonality=yes".to_string(),
        format!("RestrictNamespaces={}", restrict_namespaces),
        "RestrictRealtime=yes".to_string(),
        "RestrictSUIDSGID=yes".to_string(),
        "SystemCallArchitectures=native".to_string(),
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK".to_string(),
        "CapabilityBoundingSet=".to_string(),
        "AmbientCapabilities=".to_string(),
        "UMask=0077".to_string(),
    ];

    if !matches!(profile, "node" | "mono" | "dotnet" | "java" | "python") {
        lines.push("MemoryDenyWriteExecute=yes".to_string());
    }

    if !rw_paths.is_empty() {
        let needs_identity = rw_paths.iter().any(|raw| raw.contains("{{"));
        let service_user = if needs_identity && cfg!(target_os = "linux") {
            std::process::Command::new("systemctl")
                .args(["show", &norm_unit, "-p", "User", "--value"])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
                .filter(|username| SAFE_USERNAME.is_match(username))
                .unwrap_or_else(|| "root".to_string())
        } else {
            "root".to_string()
        };
        let service_home = fs::read_to_string("/etc/passwd")
            .ok()
            .and_then(|passwd| {
                passwd.lines().find_map(|entry| {
                    let fields: Vec<_> = entry.split(':').collect();
                    (fields.len() >= 7 && fields[0] == service_user).then(|| fields[5].to_string())
                })
            })
            .unwrap_or_else(|| format!("/home/{}", service_user));
        let master_user = [
            "/var/lib/aetherflow/.master.creds",
            "/etc/aetherflow/.master.creds",
            "/root/.master.creds",
        ]
        .iter()
        .find_map(|path| {
            fs::read_to_string(path)
                .ok()
                .and_then(|credentials| sandbox_master_user(&credentials))
        })
        .unwrap_or_else(|| service_user.clone());
        let mut expanded = Vec::with_capacity(rw_paths.len());
        for raw in rw_paths {
            expanded.push(expand_sandbox_path(
                raw,
                &service_user,
                &service_home,
                &master_user,
            ));
        }
        lines.push(format!("ReadWritePaths={}", expanded.join(" ")));
    }

    format!("{}\n", lines.join("\n"))
}

pub async fn apply_package_sandbox_local(pkg_id: &str) -> anyhow::Result<String> {
    if !SAFE_PKG_ID.is_match(pkg_id) {
        anyhow::bail!("invalid package identifier");
    }

    let target = if matches!(pkg_id, "aetherflow-api" | "aetherflow-runner") {
        af_release::lifecycle::ReservationTarget::System
    } else {
        af_release::lifecycle::ReservationTarget::Package(pkg_id)
    };
    let guard = acquire_package_maintenance_guard(
        PackageExecutionEnv::default().fs_root.as_deref(),
        target,
        &current_package_job_id(),
        None,
    )
    .await?;
    apply_package_sandbox_reserved(pkg_id, &guard).await
}

fn write_file_atomically_with_mode(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let temp_path = parent.join(format!(".{}.tmp.{}", file_name, uuid::Uuid::new_v4()));
    let write_res = (|| -> anyhow::Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut temp_file = opts.open(&temp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temp_path, fs::Permissions::from_mode(mode))?;
        }
        temp_file.write_all(bytes)?;
        temp_file.sync_all()?;
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err.into());
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn apply_sandbox_dropins_in_dir(
    sys_dir: &Path,
    units: &[String],
    sandbox_profile: &str,
    sandbox_read_write: &[String],
) -> anyhow::Result<()> {
    for raw_unit in units {
        let norm_unit = normalize_systemd_unit(raw_unit);
        let dropin_dir = sys_dir.join(format!("{}.d", norm_unit));
        let dropin_aether = dropin_dir.join("aetherflow-sandbox.conf");
        let dropin_10 = dropin_dir.join("10-aetherflow-sandbox.conf");
        if sandbox_profile == "privileged"
            || sandbox_profile == "none"
            || is_exempt_sandbox_unit(&norm_unit)
        {
            remove_file_if_exists(&dropin_aether)?;
            remove_file_if_exists(&dropin_10)?;
            continue;
        }
        fs::create_dir_all(&dropin_dir)?;
        let content =
            render_systemd_sandbox_dropin(sandbox_profile, &norm_unit, sandbox_read_write);
        write_file_atomically_with_mode(&dropin_10, content.as_bytes(), 0o644)?;
        remove_file_if_exists(&dropin_aether)?;
    }
    Ok(())
}

pub(crate) async fn apply_package_sandbox_reserved(
    pkg_id: &str,
    guard: &af_release::ReleaseLockGuard,
) -> anyhow::Result<String> {
    let pkg = get_runner_package_definition(pkg_id)
        .ok_or_else(|| anyhow::anyhow!("Sandbox target is not a managed package: {pkg_id}"))?;

    if !pkg.service_type.is_empty() && pkg.service_type != "systemd" {
        return Ok("sandbox skipped (non-systemd service)".to_string());
    }
    if pkg.sandbox_profile.is_empty() {
        return Ok("sandbox skipped (no profile configured)".to_string());
    }
    if pkg.sandbox_read_write.is_empty()
        && pkg.sandbox_profile != "privileged"
        && pkg.sandbox_profile != "none"
    {
        return Ok("sandbox skipped (no read-write paths)".to_string());
    }

    let mut units = pkg.sandbox_service_ids.clone();
    if units.is_empty() && !pkg.service_name.is_empty() {
        units.push(pkg.service_name.clone());
    }
    if units.is_empty() {
        units.push(pkg_id.to_string());
    }

    let dry_run = env::var("AETHERFLOW_SANDBOX_DRY_RUN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let systemd_root_override = env::var("AETHERFLOW_SYSTEMD_ROOT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            env::var("AETHERFLOW_INSTALL_ROOT")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s != "/")
                .map(|root| {
                    Path::new(&root)
                        .join("etc/systemd/system")
                        .to_string_lossy()
                        .into_owned()
                })
        });

    // 1. If systemd root override is set, write canonical 10-aetherflow-sandbox.conf drop-in files
    if let Some(ref sys_root) = systemd_root_override {
        apply_sandbox_dropins_in_dir(
            Path::new(sys_root),
            &units,
            &pkg.sandbox_profile,
            &pkg.sandbox_read_write,
        )?;
        return Ok("sandbox applied".to_string());
    }

    if dry_run || !cfg!(target_os = "linux") {
        return Ok("sandbox applied".to_string());
    }

    // 2. On Linux, prefer executing `af-systemd-sandbox` script if available
    if let Some(script_path) = resolve_sandbox_script_path() {
        let mut args = vec![
            script_path.to_string_lossy().to_string(),
            "apply".to_string(),
            "--profile".to_string(),
            pkg.sandbox_profile.clone(),
        ];
        for rw in &pkg.sandbox_read_write {
            args.push("--rw".to_string());
            args.push(rw.clone());
        }
        for u in &units {
            args.push(u.clone());
        }

        let mut command = Command::new("bash");
        command.args(&args).kill_on_drop(true);
        #[cfg(unix)]
        guard.preserve_in_child(command.as_std_mut())?;
        if let Ok(out) = command.output().await {
            if out.status.success() {
                return Ok("sandbox applied".to_string());
            }
        }
    }

    // 3. Direct drop-in fallback in /etc/systemd/system/<unit>.service.d/10-aetherflow-sandbox.conf
    let sys_dir = Path::new("/etc/systemd/system");
    if sys_dir.exists() {
        apply_sandbox_dropins_in_dir(
            sys_dir,
            &units,
            &pkg.sandbox_profile,
            &pkg.sandbox_read_write,
        )?;
        let mut command = Command::new("systemctl");
        command.arg("daemon-reload").kill_on_drop(true);
        #[cfg(unix)]
        guard.preserve_in_child(command.as_std_mut())?;
        let out = command
            .output()
            .await
            .map_err(|err| anyhow::anyhow!("failed to execute systemctl daemon-reload: {err}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("systemctl daemon-reload failed: {}", stderr.trim());
        }
    }

    Ok("sandbox applied".to_string())
}

async fn handle_sandbox(
    Json(req): Json<SandboxRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let identity = req.lifecycle_job_id.clone();
    PACKAGE_JOB_ID
        .scope(
            identity,
            handle_sandbox_with(
                req,
                |pkg| async move { apply_package_sandbox_local(&pkg).await },
            ),
        )
        .await
}

async fn handle_sandbox_with<F, Fut>(
    req: SandboxRunnerRequest,
    apply: F,
) -> (StatusCode, Json<RunnerResponse>)
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<String>>,
{
    let pkg = if !req.package.trim().is_empty() {
        req.package.trim().to_string()
    } else {
        req.package_id.trim().to_string()
    };
    if !SAFE_PKG_ID.is_match(&pkg) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid package identifier".to_string(),
            }),
        );
    }

    match apply(pkg).await {
        Ok(out) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: if out.is_empty() {
                    "sandbox applied".to_string()
                } else {
                    out
                },
                error: String::new(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: e.to_string(),
            }),
        ),
    }
}

pub fn validate_hosts_domain(domain: &str) -> Result<String, RunnerError> {
    if domain.is_empty()
        || domain != domain.trim()
        || domain.len() > 253
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
        || domain.chars().any(|c| {
            matches!(
                c,
                ' ' | '\t' | '\r' | '\n' | ';' | '"' | '\'' | '$' | '`' | '\\'
            )
        })
        || domain
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    {
        return Err(RunnerError::InvalidRequest(format!(
            "invalid domain format: {:?}",
            domain
        )));
    }
    Ok(domain.to_string())
}

pub async fn apply_hosts_update(req: HostsUpdateRequest) -> Result<RunnerResponse, RunnerError> {
    tokio::task::spawn_blocking(move || apply_hosts_update_local(req))
        .await
        .map_err(anyhow::Error::from)?
}

fn apply_hosts_update_local(req: HostsUpdateRequest) -> Result<RunnerResponse, RunnerError> {
    let mut domains = req.domains.clone();
    if domains.is_empty() && !req.domain.is_empty() {
        domains.push(req.domain.clone());
    }
    let is_reconcile = req.action.eq_ignore_ascii_case("reconcile");
    let is_remove = req.action.eq_ignore_ascii_case("remove");
    if domains.is_empty() && !is_reconcile {
        return Err(RunnerError::InvalidRequest(
            "no domains specified".to_string(),
        ));
    }

    let ip = if !req.ip.is_empty() {
        validate_hosts_ip(&req.ip)?;
        req.ip.as_str()
    } else {
        "127.0.0.1"
    };

    let mut validated_domains = Vec::with_capacity(domains.len());
    for d in &domains {
        let val = validate_hosts_domain(d)?;
        validated_domains.push(val);
    }

    let effective_provider_ip = if let Some(ref pip) = req.provider_ip {
        validate_hosts_ip(pip)?;
        pip.as_str()
    } else {
        ip
    };

    let mut validated_provider_domains = Vec::new();
    if let Some(ref pdomains) = req.provider_domains {
        for d in pdomains {
            let val = validate_hosts_domain(d)?;
            validated_provider_domains.push(val);
        }
    }
    let effective_provider_domains: &[String] = if req.provider_domains.is_some() {
        &validated_provider_domains
    } else {
        &validated_domains
    };

    if is_reconcile {
        reconcile_hosts_file(&validated_domains, ip)?;
        sync_dns_provider_files_with_mode(effective_provider_ip, effective_provider_domains, true)
            .map_err(RunnerError::from)?;
        Ok(RunnerResponse {
            success: true,
            output: "hosts reconciled".to_string(),
            error: String::new(),
        })
    } else if is_remove {
        update_hosts_file_local(&validated_domains, true).map_err(RunnerError::from)?;
        remove_dns_provider_files(effective_provider_domains).map_err(RunnerError::from)?;
        Ok(RunnerResponse {
            success: true,
            output: "hosts updated".to_string(),
            error: String::new(),
        })
    } else {
        update_hosts_file(&validated_domains, ip)?;
        sync_dns_provider_files_with_mode(effective_provider_ip, effective_provider_domains, false)
            .map_err(RunnerError::from)?;
        Ok(RunnerResponse {
            success: true,
            output: "hosts updated".to_string(),
            error: String::new(),
        })
    }
}

pub(crate) fn open_runner_state_database(
    root: Option<&Path>,
) -> anyhow::Result<rusqlite::Connection> {
    let env_root = resolve_self_update_isolated_root_from_env().map_err(anyhow::Error::msg)?;
    let root = root.or(env_root.as_deref());
    let conf = af_release::resolve_release_manager_conf_for_root(root);
    let config = af_release::ReleaseConfig::load_for_root_from_process_env(root, conf.as_deref())?;
    let path = af_release::config::try_resolve_db_path(&config, None)?.path;
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

async fn handle_blueprint_apply(
    Json(req): Json<af_models::RunnerBlueprintApplyRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !SAFE_PKG_ID.is_match(&req.app_name) || !(0..=65535).contains(&req.listen_port) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid blueprint app or port".into(),
            }),
        );
    }
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let package = if req.app_name == "transmission-daemon" {
            "transmission"
        } else {
            &req.app_name
        };
        anyhow::ensure!(
            get_runner_package_definition(package).is_some(),
            "unknown blueprint package"
        );
        let units = package_lifecycle::package_service_units(package)?;
        let conn = open_runner_state_database(None)?;
        af_release::lifecycle::check_package_reservation(
            &conn,
            package,
            &units,
            &req.lifecycle_job_id,
            None,
        )
        .map_err(|err| err.context(LifecycleBusy))?;
        if !req.lifecycle_job_id.is_empty() {
            let action: String = conn.query_row(
                "SELECT action FROM package_lifecycle_jobs WHERE package_id=?1 AND job_id=?2",
                rusqlite::params![package, req.lifecycle_job_id],
                |row| row.get(0),
            )?;
            anyhow::ensure!(
                matches!(action.as_str(), "install" | "reinstall" | "update"),
                "removal cannot own blueprint configuration mutations"
            );
        }
        Ok(serde_json::to_string(
            &blueprint::apply_host_config_with_state(&req, Some(&conn))?,
        )?)
    })
    .await;
    match result {
        Ok(Ok(output)) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output,
                error: String::new(),
            }),
        ),
        Ok(Err(err)) => {
            let status = if is_lifecycle_busy(&err) {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: af_models::secret_redaction::redact_diagnostic(&err.to_string())
                        .into_owned(),
                }),
            )
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "blueprint config worker failed".into(),
            }),
        ),
    }
}

pub async fn dispatch_blueprint_apply(
    req: &af_models::RunnerBlueprintApplyRequest,
) -> anyhow::Result<af_models::RunnerBlueprintApplyResponse> {
    let response = post_runner_json("/v1/blueprint/apply", req, Duration::from_secs(45)).await?;
    anyhow::ensure!(
        response.success,
        "runner blueprint apply failed: {}",
        response.error
    );
    Ok(serde_json::from_str(&response.output)?)
}

async fn handle_hosts(Json(req): Json<HostsRunnerRequest>) -> (StatusCode, Json<RunnerResponse>) {
    match apply_hosts_update(req).await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(e) => {
            let status = match e {
                RunnerError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: e.to_string(),
                }),
            )
        }
    }
}

pub fn filter_hosts_line<F>(line: &str, should_filter_host: F) -> Option<String>
where
    F: Fn(&str) -> bool,
{
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Some(line.to_string());
    }

    // Split off trailing comment if present
    let (body, comment) = match line.split_once('#') {
        Some((b, c)) => (b, Some(c)),
        None => (line, None),
    };

    let mut tokens = body.split_whitespace();
    let ip = match tokens.next() {
        Some(ip) => ip,
        None => return Some(line.to_string()),
    };

    let remaining_hosts: Vec<&str> = tokens.filter(|host| !should_filter_host(host)).collect();

    if remaining_hosts.is_empty() {
        if let Some(c) = comment {
            let inline_comment = format!("#{}", c);
            let trimmed_comment = inline_comment.trim_start();
            if trimmed_comment != "#" && !trimmed_comment[1..].trim().is_empty() {
                return Some(trimmed_comment.to_string());
            }
        }
        None
    } else {
        let hosts_str = remaining_hosts.join("\t");
        let line_content = format!("{}\t{}", ip, hosts_str);
        if let Some(c) = comment {
            Some(format!("{} #{}", line_content, c))
        } else {
            Some(line_content)
        }
    }
}

pub fn remove_hosts_file_at_path(hosts_path: &Path, domains: &[String]) -> anyhow::Result<()> {
    update_hosts_file_at_path(hosts_path, domains, true)
}

fn resolve_hosts_lock_path(hosts_path: &Path) -> PathBuf {
    if hosts_path == Path::new("/etc/hosts") {
        // A shared sticky /var/lock may contain a user-owned legacy lock.
        // Linux protected_regular rejects O_CREAT on that file even for root.
        // Use the runner's protected runtime directory and verified lock opener.
        PathBuf::from("/run/aetherflow/hosts.lock")
    } else {
        hosts_path.with_extension("lock")
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RunnerError {
    #[error("{0}")]
    InvalidRequest(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn validate_hosts_ip(ip: &str) -> Result<std::net::IpAddr, RunnerError> {
    if ip.is_empty() || ip != ip.trim() || ip.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(RunnerError::InvalidRequest(
            "Invalid IP address for hosts modification".into(),
        ));
    }
    ip.parse::<std::net::IpAddr>().map_err(|_| {
        RunnerError::InvalidRequest("Invalid IP address for hosts modification".into())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostsModifyAction<'a> {
    Update { ip: &'a str },
    Remove,
    Reconcile { ip: &'a str },
}

pub fn modify_hosts_file_at_path(
    hosts_path: &Path,
    lock_path: &Path,
    domains: &[String],
    action: HostsModifyAction,
) -> Result<(), RunnerError> {
    let canonical_ip_opt = match action {
        HostsModifyAction::Update { ip } | HostsModifyAction::Reconcile { ip } => {
            let validated_ip = validate_hosts_ip(ip)?;
            let canonical_ip = validated_ip.to_string();
            Some(canonical_ip)
        }
        HostsModifyAction::Remove => None,
    };
    let hosts_lock =
        af_host::HostMaintenanceLockGuard::acquire(lock_path, std::time::Duration::from_secs(10))
            .map_err(|e| {
            anyhow::anyhow!(
                "failed to acquire hosts lock {}: {}",
                lock_path.display(),
                e
            )
        })?;

    let existing = match read_confined_text(hosts_path, &[]) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "failed to read hosts file {}: {}",
                hosts_path.display(),
                e
            )
            .into());
        }
    };

    let is_start_marker = |t: &str| -> bool {
        t == "# BEGIN AETHERFLOW MANAGED BLOCK" || t == "# --- AETHERFLOW INTERNAL DNS ---"
    };
    let is_end_marker = |t: &str| -> bool {
        t == "# END AETHERFLOW MANAGED BLOCK" || t == "# --- END AETHERFLOW INTERNAL DNS ---"
    };

    let chosen_start_marker = if existing.contains("# --- AETHERFLOW INTERNAL DNS ---") {
        "# --- AETHERFLOW INTERNAL DNS ---"
    } else {
        "# BEGIN AETHERFLOW MANAGED BLOCK"
    };
    let chosen_end_marker = if existing.contains("# --- END AETHERFLOW INTERNAL DNS ---") {
        "# --- END AETHERFLOW INTERNAL DNS ---"
    } else {
        "# END AETHERFLOW MANAGED BLOCK"
    };

    let mut outside_lines: Vec<String> = Vec::new();
    let mut managed_comments: Vec<String> = Vec::new();
    let mut existing_managed: Vec<(String, String)> = Vec::new(); // (domain, ip)
    let mut in_block = false;

    for line in existing.lines() {
        let trimmed = line.trim();
        if is_start_marker(trimmed) {
            in_block = true;
            continue;
        }
        if is_end_marker(trimmed) {
            in_block = false;
            continue;
        }

        if in_block {
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('#') {
                managed_comments.push(line.to_string());
                continue;
            }

            let (code_part, comment_opt) = match line.split_once('#') {
                Some((b, c)) => (b.trim(), Some(c)),
                None => (line.trim(), None),
            };
            let mut tokens = code_part.split_whitespace();
            let line_ip = match tokens.next() {
                Some(ip) => ip,
                None => {
                    if let Some(c) = comment_opt {
                        managed_comments.push(format!("#{}", c));
                    }
                    continue;
                }
            };
            let mut non_aether = Vec::new();
            for tok in tokens {
                if tok.ends_with(".aether.local") {
                    if !existing_managed.iter().any(|(d, _)| d == tok) {
                        existing_managed.push((tok.to_string(), line_ip.to_string()));
                    }
                } else {
                    non_aether.push(tok);
                }
            }
            if !non_aether.is_empty() {
                let line_str = format!("{}\t{}", line_ip, non_aether.join("\t"));
                if let Some(c) = comment_opt {
                    outside_lines.push(format!("{} #{}", line_str, c));
                } else {
                    outside_lines.push(line_str);
                }
            } else if let Some(c) = comment_opt {
                managed_comments.push(format!("#{}", c));
            }
        } else {
            let filter_fn = |tok: &str| -> bool {
                match action {
                    HostsModifyAction::Update { .. } => domains.contains(&tok.to_string()),
                    HostsModifyAction::Remove => domains.contains(&tok.to_string()),
                    HostsModifyAction::Reconcile { .. } => {
                        tok.ends_with(".aether.local") || domains.contains(&tok.to_string())
                    }
                }
            };
            if let Some(filtered) = filter_hosts_line(line, filter_fn) {
                outside_lines.push(filtered);
            }
        }
    }

    let mut final_managed: Vec<(String, String)> = Vec::new();
    match action {
        HostsModifyAction::Update { .. } => {
            let canonical_ip = canonical_ip_opt.as_deref().unwrap_or("");
            for (dom, old_ip) in existing_managed {
                if !domains.contains(&dom) {
                    final_managed.push((dom, old_ip));
                }
            }
            for dom in domains {
                if !final_managed.iter().any(|(d, _)| d == dom) {
                    final_managed.push((dom.clone(), canonical_ip.to_string()));
                }
            }
        }
        HostsModifyAction::Remove => {
            for (dom, old_ip) in existing_managed {
                if !domains.contains(&dom) {
                    final_managed.push((dom, old_ip));
                }
            }
        }
        HostsModifyAction::Reconcile { .. } => {
            let canonical_ip = canonical_ip_opt.as_deref().unwrap_or("");
            for dom in domains {
                if !final_managed.iter().any(|(d, _)| d == dom) {
                    final_managed.push((dom.clone(), canonical_ip.to_string()));
                }
            }
        }
    }

    let mut out = outside_lines.join("\n");
    if !out.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }
    if !final_managed.is_empty() || !managed_comments.is_empty() {
        out.push_str(chosen_start_marker);
        out.push('\n');
        for c in &managed_comments {
            out.push_str(c);
            out.push('\n');
        }
        for (dom, ip) in &final_managed {
            out.push_str(&format!("{}\t{}\n", ip, dom));
        }
        out.push_str(chosen_end_marker);
        out.push('\n');
    }

    hosts_lock
        .verify_still_active()
        .map_err(anyhow::Error::from)?;
    write_hosts_file_atomically(hosts_path, &out).map_err(RunnerError::from)
}

pub fn update_hosts_file(domains: &[String], ip: &str) -> Result<(), RunnerError> {
    let validated_ip = validate_hosts_ip(ip)?;
    let canonical_ip = validated_ip.to_string();
    let hosts_path = env::var("AF_HOSTS_FILE")
        .or_else(|_| env::var("AETHERFLOW_HOSTS_FILE"))
        .unwrap_or_else(|_| "/etc/hosts".to_string());
    let path = Path::new(&hosts_path);
    let lock_path = resolve_hosts_lock_path(path);
    update_hosts_file_with_ip_at_path(path, &lock_path, domains, &canonical_ip, false)
}

pub fn update_hosts_file_local(domains: &[String], remove: bool) -> anyhow::Result<()> {
    let hosts_path = env::var("AF_HOSTS_FILE")
        .or_else(|_| env::var("AETHERFLOW_HOSTS_FILE"))
        .unwrap_or_else(|_| "/etc/hosts".to_string());
    update_hosts_file_at_path(Path::new(&hosts_path), domains, remove)
}

pub fn update_hosts_file_with_ip_at_path(
    hosts_path: &Path,
    lock_path: &Path,
    domains: &[String],
    ip: &str,
    remove: bool,
) -> Result<(), RunnerError> {
    if remove {
        modify_hosts_file_at_path(hosts_path, lock_path, domains, HostsModifyAction::Remove)
    } else {
        let validated_ip = validate_hosts_ip(ip)?;
        let canonical_ip = validated_ip.to_string();
        modify_hosts_file_at_path(
            hosts_path,
            lock_path,
            domains,
            HostsModifyAction::Update { ip: &canonical_ip },
        )
    }
}

pub fn update_hosts_file_at_path(
    hosts_path: &Path,
    domains: &[String],
    remove: bool,
) -> anyhow::Result<()> {
    let lock_path = resolve_hosts_lock_path(hosts_path);
    if remove {
        modify_hosts_file_at_path(hosts_path, &lock_path, domains, HostsModifyAction::Remove)?;
    } else {
        let validated_ip = validate_hosts_ip("127.0.0.1")?;
        let canonical_ip = validated_ip.to_string();
        modify_hosts_file_at_path(
            hosts_path,
            &lock_path,
            domains,
            HostsModifyAction::Update { ip: &canonical_ip },
        )?;
    }
    Ok(())
}

pub fn reconcile_hosts_file_at_path(
    hosts_path: &Path,
    lock_path: &Path,
    domains: &[String],
    ip: &str,
) -> Result<(), RunnerError> {
    let validated_ip = validate_hosts_ip(ip)?;
    let canonical_ip = validated_ip.to_string();
    modify_hosts_file_at_path(
        hosts_path,
        lock_path,
        domains,
        HostsModifyAction::Reconcile { ip: &canonical_ip },
    )
}

pub fn reconcile_hosts_file(domains: &[String], ip: &str) -> Result<(), RunnerError> {
    let validated_ip = validate_hosts_ip(ip)?;
    let canonical_ip = validated_ip.to_string();
    let hosts_path = env::var("AF_HOSTS_FILE")
        .or_else(|_| env::var("AETHERFLOW_HOSTS_FILE"))
        .unwrap_or_else(|_| "/etc/hosts".to_string());
    let path = Path::new(&hosts_path);
    let lock_path = resolve_hosts_lock_path(path);
    reconcile_hosts_file_at_path(path, &lock_path, domains, &canonical_ip)
}

pub fn sync_dns_provider_files(ip: &str, domains: &[String]) -> anyhow::Result<()> {
    sync_dns_provider_files_with_mode(ip, domains, true)
}

fn resolve_provider_dir(env_var: &str, default_path: &str) -> PathBuf {
    if let Ok(dir) = env::var(env_var) {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    for root_key in ["AETHERFLOW_CONFIG_ROOT", "AETHERFLOW_FS_ROOT"] {
        if let Ok(root) = env::var(root_key) {
            let root_trim = root.trim();
            if !root_trim.is_empty() {
                let rel = default_path.trim_start_matches(['/', '\\']);
                return Path::new(root_trim).join(rel);
            }
        }
    }
    PathBuf::from(default_path)
}

fn render_dnsmasq_content(
    existing: Option<&str>,
    canonical_ip: &str,
    domains: &[String],
    is_reconcile: bool,
) -> String {
    let mut domain_set: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    if !is_reconcile {
        if let Some(content) = existing {
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("address=/") {
                    if let Some((dom, ip)) = rest.split_once('/') {
                        let dom_clean = dom.trim().to_ascii_lowercase();
                        if !dom_clean.is_empty() {
                            domain_set.insert(dom_clean, ip.trim().to_string());
                        }
                    }
                }
            }
        }
    }
    for d in domains {
        domain_set.insert(d.trim().to_ascii_lowercase(), canonical_ip.to_string());
    }
    let mut lines = vec!["# Automatically managed by AetherFlow".to_string()];
    for (d, ip) in domain_set {
        lines.push(format!("address=/{}/{}", d, ip));
    }
    lines.push(String::new());
    lines.join("\n")
}

pub fn reconcile_pihole_custom_list_content(
    existing: &str,
    canonical_ip: &str,
    domains: &[String],
    is_reconcile: bool,
) -> String {
    let target_domains: HashSet<String> = domains.iter().map(|d| d.to_ascii_lowercase()).collect();
    let mut emitted_domains: HashSet<String> = HashSet::new();
    let mut out_lines: Vec<String> = Vec::new();

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            out_lines.push(line.to_string());
            continue;
        }
        if trimmed.starts_with('#') {
            if trimmed == "# --- AETHERFLOW MANAGED DNS ---"
                || trimmed == "# --- END AETHERFLOW MANAGED DNS ---"
            {
                continue;
            }
            out_lines.push(line.to_string());
            continue;
        }

        let (entry_part, comment_part) = match line.find('#') {
            Some(idx) => (&line[..idx], Some(&line[idx..])),
            None => (line, None),
        };

        let parts: Vec<&str> = entry_part.split_whitespace().collect();
        if parts.len() < 2 {
            out_lines.push(line.to_string());
            continue;
        }

        let line_ip = parts[0];
        let hostnames = &parts[1..];
        let is_line_tagged_managed = comment_part
            .map(|c| c.contains("aetherflow-managed"))
            .unwrap_or(false);
        let single_host_managed = is_line_tagged_managed && hostnames.len() == 1;

        let mut unmanaged_tokens: Vec<&str> = Vec::new();
        let mut managed_tokens: Vec<&str> = Vec::new();

        for host in hostnames {
            let h_lower = host.to_ascii_lowercase();
            let is_managed = h_lower.ends_with(".aether.local")
                || target_domains.contains(&h_lower)
                || single_host_managed;
            if is_managed {
                managed_tokens.push(host);
            } else {
                unmanaged_tokens.push(host);
            }
        }

        if !unmanaged_tokens.is_empty() {
            let mut preserved_line = format!("{} {}", line_ip, unmanaged_tokens.join(" "));
            if let Some(c) = comment_part {
                let trimmed_c = c.trim();
                if !trimmed_c.is_empty() && trimmed_c != "# aetherflow-managed" {
                    preserved_line.push(' ');
                    preserved_line.push_str(trimmed_c);
                }
            }
            out_lines.push(preserved_line);

            if !is_reconcile {
                for m in managed_tokens {
                    let m_lower = m.to_ascii_lowercase();
                    if !target_domains.contains(&m_lower) && !emitted_domains.contains(&m_lower) {
                        emitted_domains.insert(m_lower);
                        out_lines.push(format!("{} {} # aetherflow-managed", line_ip, m));
                    }
                }
            }
        } else {
            for m in managed_tokens {
                let m_lower = m.to_ascii_lowercase();
                if target_domains.contains(&m_lower) {
                    if !emitted_domains.contains(&m_lower) {
                        emitted_domains.insert(m_lower.clone());
                        let comment = if let Some(c) = comment_part {
                            let trimmed_c = c.trim();
                            if !trimmed_c.is_empty() && trimmed_c != "# aetherflow-managed" {
                                trimmed_c
                            } else {
                                "# aetherflow-managed"
                            }
                        } else {
                            "# aetherflow-managed"
                        };
                        out_lines.push(format!("{} {} {}", canonical_ip, m, comment));
                    }
                } else if !is_reconcile && !emitted_domains.contains(&m_lower) {
                    emitted_domains.insert(m_lower.clone());
                    let comment = if let Some(c) = comment_part {
                        let trimmed_c = c.trim();
                        if !trimmed_c.is_empty() {
                            trimmed_c
                        } else {
                            "# aetherflow-managed"
                        }
                    } else {
                        "# aetherflow-managed"
                    };
                    out_lines.push(format!("{} {} {}", line_ip, m, comment));
                }
            }
        }
    }

    for d in domains {
        let d_lower = d.to_ascii_lowercase();
        if !emitted_domains.contains(&d_lower) {
            emitted_domains.insert(d_lower);
            out_lines.push(format!("{} {} # aetherflow-managed", canonical_ip, d));
        }
    }

    let mut result = out_lines.join("\n");
    if !result.is_empty() {
        result.push('\n');
    }
    result
}

pub fn remove_pihole_custom_list_content(existing: &str, domains_to_remove: &[String]) -> String {
    if domains_to_remove.is_empty() {
        return existing.to_string();
    }
    let lower_remove: HashSet<String> = domains_to_remove
        .iter()
        .map(|d| d.to_ascii_lowercase())
        .collect();

    let mut out_lines: Vec<String> = Vec::new();

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out_lines.push(line.to_string());
            continue;
        }

        let (entry_part, comment_part) = match line.find('#') {
            Some(idx) => (&line[..idx], Some(&line[idx..])),
            None => (line, None),
        };

        let parts: Vec<&str> = entry_part.split_whitespace().collect();
        if parts.len() < 2 {
            out_lines.push(line.to_string());
            continue;
        }

        let line_ip = parts[0];
        let hostnames = &parts[1..];

        let mut remaining_hosts: Vec<&str> = Vec::new();
        let mut had_matching = false;

        for host in hostnames {
            let h_lower = host.to_ascii_lowercase();
            if lower_remove.contains(&h_lower) {
                had_matching = true;
            } else {
                remaining_hosts.push(host);
            }
        }

        if !had_matching {
            out_lines.push(line.to_string());
        } else if !remaining_hosts.is_empty() {
            let mut line_str = format!("{} {}", line_ip, remaining_hosts.join(" "));
            if let Some(c) = comment_part {
                let trimmed_c = c.trim();
                if !trimmed_c.is_empty() {
                    line_str.push(' ');
                    line_str.push_str(trimmed_c);
                }
            }
            out_lines.push(line_str);
        }
    }

    let mut result = out_lines.join("\n");
    if !result.is_empty() {
        result.push('\n');
    }
    result
}

pub fn sync_dns_provider_files_with_mode(
    ip: &str,
    domains: &[String],
    is_reconcile: bool,
) -> anyhow::Result<()> {
    let validated_ip = validate_hosts_ip(ip)?;
    let canonical_ip = validated_ip.to_string();
    for domain in domains {
        anyhow::ensure!(
            af_models::valid_ingress_hostname(domain),
            "invalid DNS provider domain"
        );
    }
    let dnsmasq_dir = resolve_provider_dir("AETHERFLOW_DNSMASQ_DIR", "/etc/dnsmasq.d");
    if dns_provider_directory_exists(&dnsmasq_dir, false)? {
        for conf_name in [
            "aetherflow-local-dns.conf",
            "aetherflow.conf",
            "aetherflow-local.conf",
            "05-aetherflow-dns.conf",
        ] {
            let conf_path = dnsmasq_dir.join(conf_name);
            let existing = match read_dns_provider_text(&conf_path, false) {
                Ok(content) => Some(content),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to read {}: {}",
                        conf_path.display(),
                        e
                    ));
                }
            };
            let payload =
                render_dnsmasq_content(existing.as_deref(), &canonical_ip, domains, is_reconcile);
            write_dns_provider_text(&conf_path, &payload, false)?;
        }
    }

    let pihole_dir = resolve_provider_dir("AETHERFLOW_PIHOLE_DIR", "/etc/pihole");
    if dns_provider_directory_exists(&pihole_dir, true)? {
        let custom_list = pihole_dir.join("custom.list");
        let existing = match read_dns_provider_text(&custom_list, true) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to read {}: {}",
                    custom_list.display(),
                    e
                ));
            }
        };
        let payload =
            reconcile_pihole_custom_list_content(&existing, &canonical_ip, domains, is_reconcile);
        write_dns_provider_text(&custom_list, &payload, true)?;
    }
    sync_adguard_dns(&canonical_ip, domains, is_reconcile)?;
    Ok(())
}

pub fn sync_adguard_dns(ip: &str, domains: &[String], reconcile: bool) -> anyhow::Result<()> {
    let ip = validate_hosts_ip(ip)?.to_string();
    adguard_dns::sync(domains, adguard_dns::Change::Update { ip: &ip, reconcile })
}

pub fn remove_dns_provider_files(domains: &[String]) -> anyhow::Result<()> {
    if domains.is_empty() {
        return Ok(());
    }
    let lower_domains: std::collections::HashSet<String> =
        domains.iter().map(|d| d.to_ascii_lowercase()).collect();

    let dnsmasq_dir = resolve_provider_dir("AETHERFLOW_DNSMASQ_DIR", "/etc/dnsmasq.d");
    if dns_provider_directory_exists(&dnsmasq_dir, false)? {
        for conf_name in [
            "aetherflow-local-dns.conf",
            "aetherflow.conf",
            "aetherflow-local.conf",
            "05-aetherflow-dns.conf",
        ] {
            let conf_path = dnsmasq_dir.join(conf_name);
            match read_dns_provider_text(&conf_path, false) {
                Ok(content) => {
                    let mut out_lines = Vec::new();
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if let Some(rest) = trimmed.strip_prefix("address=/") {
                            if let Some((dom, _)) = rest.split_once('/') {
                                if lower_domains.contains(&dom.trim().to_ascii_lowercase()) {
                                    continue;
                                }
                            }
                        }
                        out_lines.push(line.to_string());
                    }
                    out_lines.push(String::new());
                    write_dns_provider_text(&conf_path, &out_lines.join("\n"), false)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to read {}: {}",
                        conf_path.display(),
                        e
                    ));
                }
            }
        }
    }

    let pihole_dir = resolve_provider_dir("AETHERFLOW_PIHOLE_DIR", "/etc/pihole");
    if dns_provider_directory_exists(&pihole_dir, true)? {
        let custom_list = pihole_dir.join("custom.list");
        match read_dns_provider_text(&custom_list, true) {
            Ok(content) => {
                let payload = remove_pihole_custom_list_content(&content, domains);
                if payload != content {
                    write_dns_provider_text(&custom_list, &payload, true)?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to read {}: {}",
                    custom_list.display(),
                    e
                ));
            }
        }
    }
    adguard_dns::sync(domains, adguard_dns::Change::Remove)?;
    Ok(())
}

pub fn remove_dns_provider_domain(domain: &str) -> anyhow::Result<()> {
    remove_dns_provider_files(&[domain.to_string()])
}

pub fn execute_hosts_cli_command(
    action: &str,
    ip: &str,
    domains: &[String],
) -> anyhow::Result<String> {
    if action.eq_ignore_ascii_case("update")
        || action.eq_ignore_ascii_case("reconcile")
        || action.eq_ignore_ascii_case("add")
        || !ip.is_empty()
    {
        validate_hosts_ip(ip)?;
    }
    match action {
        "reconcile" => {
            let validated_ip = validate_hosts_ip(ip)?;
            let canonical_ip = validated_ip.to_string();
            reconcile_hosts_file(domains, &canonical_ip)?;
            sync_dns_provider_files_with_mode(&canonical_ip, domains, true)?;
            Ok(format!(
                "reconciled {} domain(s) to {}",
                domains.len(),
                canonical_ip
            ))
        }
        "update" | "add" => {
            let validated_ip = validate_hosts_ip(ip)?;
            let canonical_ip = validated_ip.to_string();
            update_hosts_file(domains, &canonical_ip)?;
            sync_dns_provider_files_with_mode(&canonical_ip, domains, false)?;
            Ok(format!(
                "updated {} domain(s) to {}",
                domains.len(),
                canonical_ip
            ))
        }
        "remove" => {
            update_hosts_file_local(domains, true)?;
            for d in domains {
                remove_dns_provider_domain(d)?;
            }
            Ok(format!("removed {} domain(s)", domains.len()))
        }
        other => anyhow::bail!(
            "unknown hosts action {:?}, expected reconcile, update, or remove",
            other
        ),
    }
}

pub fn run_hosts_cli(args: &[String]) -> anyhow::Result<String> {
    if args.is_empty() {
        anyhow::bail!("missing hosts action (update, remove, reconcile)");
    }
    let action = args[0].to_ascii_lowercase();
    match action.as_str() {
        "reconcile" => {
            let ip = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1");
            let domains: Vec<String> = if args.len() > 2 {
                args[2..].to_vec()
            } else {
                Vec::new()
            };
            execute_hosts_cli_command("reconcile", ip, &domains)
        }
        "update" | "add" => {
            if args.len() < 2 {
                anyhow::bail!("usage: hosts update <ip> <domain...>");
            }
            let ip = &args[1];
            let domains = args[2..].to_vec();
            execute_hosts_cli_command(&action, ip, &domains)
        }
        "remove" => {
            if args.len() < 2 {
                anyhow::bail!("usage: hosts remove <domain...>");
            }
            let domains = args[1..].to_vec();
            execute_hosts_cli_command("remove", "127.0.0.1", &domains)
        }
        other => anyhow::bail!(
            "unknown hosts action {:?}, expected reconcile, update, or remove",
            other
        ),
    }
}

fn lookup_group_gid(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut group = std::mem::MaybeUninit::<libc::group>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0; 1024];
    loop {
        let code = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                group.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        match code {
            0 if !result.is_null() => return Some(unsafe { group.assume_init() }.gr_gid),
            libc::ERANGE if buffer.len() < 64 * 1024 => buffer.resize(buffer.len() * 2, 0),
            _ => return None,
        }
    }
}

fn confined_parent(
    path: &Path,
    expected_users: &[&str],
) -> std::io::Result<(job_receipts::ReceiptDirectory, Vec<u32>)> {
    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir = job_receipts::ReceiptDirectory::open_existing(parent)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    let mut owners = Vec::new();
    if unsafe { libc::geteuid() } == 0 {
        owners.push(0);
        owners.extend(
            expected_users
                .iter()
                .filter_map(|name| lookup_passwd_uid_reentrant(name)),
        );
        dir.verify_owners(&owners)?;
    }
    Ok((dir, owners))
}

fn check_confined_owner(file: &fs::File, owners: &[u32]) -> std::io::Result<fs::Metadata> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !owners.is_empty() && !owners.contains(&metadata.uid()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "unexpected file owner",
        ));
    }
    Ok(metadata)
}

fn confined_file_name(path: &Path) -> std::io::Result<&std::ffi::OsStr> {
    path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected a regular file name",
        )
    })
}

fn open_confined_file(path: &Path, users: &[&str]) -> std::io::Result<fs::File> {
    let (dir, owners) = confined_parent(path, users)?;
    let file = dir.open_file(confined_file_name(path)?, libc::O_RDONLY, 0)?;
    check_confined_owner(&file, &owners)?;
    Ok(file)
}

fn read_confined_text(path: &Path, users: &[&str]) -> std::io::Result<String> {
    use std::io::Read;
    const LIMIT: u64 = 2 * 1024 * 1024;
    let file = open_confined_file(path, users)?;
    let mut text = String::new();
    file.take(LIMIT + 1).read_to_string(&mut text)?;
    if text.len() as u64 > LIMIT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "configuration exceeds 2 MiB",
        ));
    }
    Ok(text)
}

fn dns_provider_users(pihole: bool) -> &'static [&'static str] {
    if pihole {
        &["pihole"]
    } else {
        &["dnsmasq"]
    }
}

pub fn dns_provider_directory_exists(path: &Path, pihole: bool) -> std::io::Result<bool> {
    let Some(directory) = job_receipts::ReceiptDirectory::open_existing(path)? else {
        return Ok(false);
    };
    if unsafe { libc::geteuid() } == 0 {
        let mut owners = vec![0];
        owners.extend(
            dns_provider_users(pihole)
                .iter()
                .filter_map(|name| lookup_passwd_uid_reentrant(name)),
        );
        directory.verify_owners(&owners)?;
    }
    Ok(true)
}

pub fn remove_dns_provider_file(path: &Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let (dir, owners) = confined_parent(path, dns_provider_users(false))?;
    let name = confined_file_name(path)?;
    let file = match dir.open_file(name, libc::O_RDONLY, 0) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    check_confined_owner(&file, &owners)?;
    dir.verify()?;
    job_receipts::verify_entry(dir.file(), name, &file, false)?;
    if unsafe {
        libc::unlinkat(
            dir.file().as_raw_fd(),
            job_receipts::c_name(name)?.as_ptr(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn read_dns_provider_text(path: &Path, pihole: bool) -> std::io::Result<String> {
    read_confined_text(path, dns_provider_users(pihole))
}

pub fn write_dns_provider_text(path: &Path, content: &str, pihole: bool) -> std::io::Result<()> {
    replace_confined_text(path, content, dns_provider_users(pihole), false, pihole)
}

fn write_hosts_file_atomically(path: &Path, content: &str) -> anyhow::Result<()> {
    replace_confined_text(path, content, &[], true, false)?;
    Ok(())
}

fn replace_confined_text(
    path: &Path,
    content: &str,
    users: &[&str],
    hosts: bool,
    pihole: bool,
) -> std::io::Result<()> {
    replace_confined_file(
        path,
        content.as_bytes(),
        Some(users),
        None,
        hosts,
        pihole,
        None,
    )
}

fn replace_confined_file(
    path: &Path,
    content: &[u8],
    users: Option<&[&str]>,
    force_mode: Option<u32>,
    hosts: bool,
    pihole: bool,
    owner_override: Option<(u32, u32)>,
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (dir, owners) = if let Some(users) = users {
        confined_parent(path, users)?
    } else {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = job_receipts::ReceiptDirectory::open_existing(parent)?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        (dir, Vec::new())
    };
    let name = confined_file_name(path)?;
    let mut previous =
        match dir.open_file(name, if hosts { libc::O_RDWR } else { libc::O_RDONLY }, 0) {
            Ok(file) => Some(file),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
    let previous_metadata = previous
        .as_ref()
        .map(|file| check_confined_owner(file, &owners))
        .transpose()?;
    let root = unsafe { libc::geteuid() } == 0;
    let (mode, owner) = if hosts {
        (0o644, root.then_some((0, 0)))
    } else if let Some(metadata) = previous_metadata {
        (
            metadata.mode() & if users.is_some() { 0o7777 } else { 0o777 },
            Some((metadata.uid(), metadata.gid())),
        )
    } else {
        (
            if users.is_some() { 0o640 } else { 0o600 },
            root.then(|| {
                (
                    0,
                    if pihole {
                        lookup_group_gid("pihole").unwrap_or(0)
                    } else {
                        0
                    },
                )
            }),
        )
    };
    let mode = force_mode.unwrap_or(mode);
    let owner = owner_override.or(owner);
    let configure = |file: &fs::File| -> std::io::Result<()> {
        if let Some((uid, gid)) = owner {
            let metadata = file.metadata()?;
            if (uid != metadata.uid() || gid != metadata.gid())
                && unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0
            {
                let error = std::io::Error::last_os_error();
                if users.is_some() || root || error.raw_os_error() != Some(libc::EPERM) {
                    return Err(error);
                }
            }
        }
        file.set_permissions(fs::Permissions::from_mode(mode))
    };
    let temporary = format!(".aetherflow.tmp.{}", uuid::Uuid::new_v4());
    let temporary = std::ffi::OsStr::new(&temporary);
    let mut file = dir.open_file(
        temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let parent = dir.file().as_raw_fd();
    let temporary_c = job_receipts::c_name(temporary)?;
    let name_c = job_receipts::c_name(name)?;
    let result = (|| {
        file.write_all(content)?;
        configure(&file)?;
        file.sync_all()?;
        dir.verify()?;
        job_receipts::verify_entry(dir.file(), temporary, &file, false)?;
        if let Some(previous) = &previous {
            job_receipts::verify_entry(dir.file(), name, previous, false)?;
        } else if !matches!(job_receipts::entry_at(dir.file(), name), Err(err) if err.kind() == std::io::ErrorKind::NotFound)
        {
            return Err(std::io::Error::other(
                "configuration appeared during update",
            ));
        }
        if unsafe { libc::renameat(parent, temporary_c.as_ptr(), parent, name_c.as_ptr()) } == 0 {
            return dir.file().sync_all();
        }
        let error = std::io::Error::last_os_error();
        // Bind-mounted /etc/hosts cannot be replaced. Use only the previously verified inode.
        if hosts && matches!(error.raw_os_error(), Some(libc::EXDEV) | Some(libc::EBUSY)) {
            if let Some(destination) = &mut previous {
                if unsafe { libc::flock(destination.as_raw_fd(), libc::LOCK_EX) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                dir.verify()?;
                job_receipts::verify_entry(dir.file(), name, destination, false)?;
                configure(destination)?;
                destination.set_len(0)?;
                destination.write_all(content)?;
                return destination.sync_all();
            }
        }
        Err(error)
    })();
    unsafe {
        libc::unlinkat(parent, temporary_c.as_ptr(), 0);
    }
    result
}

pub(crate) fn create_package_lock_directory(path: &Path) -> std::io::Result<()> {
    if path.file_name() != Some(std::ffi::OsStr::new("install")) {
        return fs::create_dir_all(path);
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let created = match fs::create_dir(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error),
    };
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let directory = job_receipts::ReceiptDirectory::open_existing(path)?
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
    if unsafe { libc::geteuid() } == 0 {
        directory.verify_owners(&[0])?;
        if created {
            let metadata = directory.file().metadata()?;
            let gid = lookup_group_gid("aetherflow").unwrap_or(metadata.gid());
            if metadata.gid() != gid
                && unsafe { libc::fchown(directory.file().as_raw_fd(), 0, gid) } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    if created {
        directory
            .file()
            .set_permissions(fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}

async fn handle_network(
    Json(req): Json<NetworkRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !network::is_allowed_action(&req.action) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "disallowed network action".to_string(),
            }),
        );
    }

    match execute_network_action_local(&req).await {
        Ok(out) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: out,
                error: String::new(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: e.to_string(),
            }),
        ),
    }
}

pub async fn execute_network_action_local(req: &NetworkRunnerRequest) -> anyhow::Result<String> {
    network::execute(req).await
}

pub fn resolve_setdisk_script_path() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("AF_SETDISK_PATH") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if p.is_file() {
                return Some(p);
            }
        }
    }

    let mut candidates = vec![
        PathBuf::from("/opt/AetherFlow/current/packages/system/setdisk"),
        PathBuf::from("/opt/AetherFlow/packages/system/setdisk"),
        PathBuf::from("/usr/local/bin/AetherFlow/system/setdisk"),
        PathBuf::from("packages/system/setdisk"),
        PathBuf::from("../packages/system/setdisk"),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("packages/system/setdisk"));
            candidates.push(exe_dir.join("../packages/system/setdisk"));
        }
    }
    candidates.into_iter().find(|c| c.is_file())
}

pub fn parse_quota_size_to_1k_blocks(size_raw: &str) -> Option<(u64, u64)> {
    let trimmed = size_raw.trim().to_uppercase();
    if trimmed == "0" {
        return Some((0, 0));
    }
    let re = Regex::new(r"^([0-9]+(?:\.[0-9]+)?)\s*([KMGTPE]?)[B]?$").ok()?;
    let caps = re.captures(&trimmed)?;
    let num: f64 = caps.get(1)?.as_str().parse().ok()?;
    let unit = caps.get(2).map(|m| m.as_str()).unwrap_or("");
    let bytes: u64 = match unit {
        "" => num as u64,
        "K" => (num * 1024.0) as u64,
        "M" => (num * 1024.0 * 1024.0) as u64,
        "G" => (num * 1024.0 * 1024.0 * 1024.0) as u64,
        "T" => (num * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64,
        "P" => (num * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64,
        "E" => (num * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0) as u64,
        _ => return None,
    };
    let blocks_1k = bytes.div_ceil(1024);
    Some((blocks_1k, bytes))
}

pub async fn execute_set_quota_local(username: &str, size: &str) -> anyhow::Result<String> {
    if !quota::valid_username(username) {
        anyhow::bail!("invalid username format");
    }
    if !SAFE_QUOTA_SIZE.is_match(size) && !SAFE_QUOTA_SIZE_REGEX.is_match(size) {
        anyhow::bail!("invalid size format");
    }

    let dry_run = env::var("AETHERFLOW_QUOTA_DRY_RUN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if dry_run || !cfg!(target_os = "linux") {
        let (_, quota_bytes) = parse_quota_size_to_1k_blocks(size).unwrap_or((0, 0));
        return Ok(json!({
            "username": username,
            "quota": size.trim().to_uppercase(),
            "quota_bytes": quota_bytes,
            "status": "applied"
        })
        .to_string());
    }

    let bin_setdisk_opt = resolve_setdisk_script_path().or_else(|| {
        let fallback = PathBuf::from("/usr/local/bin/AetherFlow/system/setdisk");
        if fallback.is_file() {
            Some(fallback)
        } else {
            None
        }
    });

    // Legacy setdisk only accepts whole MB/GB/TB. Exact byte requests must
    // use setquota directly rather than failing inside the legacy script.
    if let Some(bin_setdisk) =
        bin_setdisk_opt.filter(|_| Regex::new(r"(?i)^[0-9]+[MGT]B$").unwrap().is_match(size))
    {
        let out = Command::new("bash")
            .arg(&bin_setdisk)
            .arg("--username")
            .arg(username)
            .arg("--size")
            .arg(size)
            .arg("--json")
            .output()
            .await;
        if let Ok(o) = out {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            if o.status.success() {
                return Ok(combined.trim().to_string());
            }
            // Also try positional invocation `<username> <size>` if script variant expects positional args
            if let Ok(o2) = Command::new(&bin_setdisk)
                .arg(username)
                .arg(size)
                .output()
                .await
            {
                if o2.status.success() {
                    return Ok(String::from_utf8_lossy(&o2.stdout).trim().to_string());
                }
            }
            anyhow::bail!("setdisk failed: {}", combined.trim());
        }
    }

    let (blocks_1k, quota_bytes) = parse_quota_size_to_1k_blocks(size)
        .ok_or_else(|| anyhow::anyhow!("invalid quota size: {:?}", size))?;
    let block_str = blocks_1k.to_string();
    let mut command = Command::new("setquota");
    command
        .args(["-u", username, &block_str, &block_str, "0", "0", "-a"])
        .kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(20), command.output()).await??;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        anyhow::bail!("setquota failed: {}", combined.trim());
    }

    Ok(json!({
        "username": username,
        "quota": size.trim().to_uppercase(),
        "quota_bytes": quota_bytes,
        "status": "applied"
    })
    .to_string())
}

async fn handle_quota(Json(req): Json<QuotaRunnerRequest>) -> (StatusCode, Json<RunnerResponse>) {
    if !quota::valid_username(&req.username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid username format".to_string(),
            }),
        );
    }
    if !SAFE_QUOTA_SIZE.is_match(&req.size) && !SAFE_QUOTA_SIZE_REGEX.is_match(&req.size) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid size format".to_string(),
            }),
        );
    }

    match execute_set_quota_local(&req.username, &req.size).await {
        Ok(out) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: out,
                error: String::new(),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: e.to_string(),
            }),
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Privileged Application Runtime Metadata Extraction
// ─────────────────────────────────────────────────────────────────────────────

mod app_metadata;
pub use app_metadata::*;

static SAFE_INGRESS_APP_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,47}$").unwrap());

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PrevEnabledVhostState {
    Missing,
    Symlink(PathBuf),
    RegularFile(Vec<u8>, u32),
}

fn ensure_non_symlink_dir(dir: &Path, create_if_missing: bool) -> anyhow::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                anyhow::bail!("refusing non-directory or symlinked path {}", dir.display());
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if create_if_missing {
                fs::create_dir_all(dir)?;
                let meta = fs::symlink_metadata(dir)?;
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    anyhow::bail!("refusing non-directory or symlinked path {}", dir.display());
                }
            }
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

fn read_regular_file_nofollow(path: &Path) -> anyhow::Result<Option<(Vec<u8>, u32)>> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    const LIMIT: u64 = 1024 * 1024;
    let file = match open_confined_file(path, &[]) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow::anyhow!(
                "unsafe Apache vhost {}: {err}",
                path.display()
            ))
        }
    };
    let mode = file.metadata()?.permissions().mode() & 0o777;
    let mut buf = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut buf)?;
    anyhow::ensure!(buf.len() as u64 <= LIMIT, "Apache vhost exceeds 1 MiB");
    Ok(Some((buf, mode)))
}

fn snapshot_enabled_vhost(path: &Path) -> anyhow::Result<PrevEnabledVhostState> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok(PrevEnabledVhostState::Missing)
        }
        Err(err) => Err(err.into()),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                Ok(PrevEnabledVhostState::Symlink(fs::read_link(path)?))
            } else if meta.is_file() {
                let (bytes, mode) = read_regular_file_nofollow(path)?
                    .ok_or_else(|| anyhow::anyhow!("vhost disappeared during snapshot"))?;
                Ok(PrevEnabledVhostState::RegularFile(bytes, mode))
            } else {
                anyhow::bail!("refusing non-regular enabled vhost path {}", path.display());
            }
        }
    }
}

fn rollback_ingress_vhost(
    avail_path: &Path,
    enabled_path: &Path,
    prev_avail: &Option<(Vec<u8>, u32)>,
    prev_enabled: &PrevEnabledVhostState,
) -> anyhow::Result<()> {
    match prev_enabled {
        PrevEnabledVhostState::Missing => remove_file_if_exists(enabled_path)?,
        PrevEnabledVhostState::Symlink(target) => {
            remove_file_if_exists(enabled_path)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, enabled_path)?;
            #[cfg(not(unix))]
            let _ = target;
        }
        PrevEnabledVhostState::RegularFile(bytes, mode) => {
            remove_file_if_exists(enabled_path)?;
            write_file_atomically_with_mode(enabled_path, bytes, *mode)?;
        }
    }
    match prev_avail {
        Some((bytes, mode)) => write_file_atomically_with_mode(avail_path, bytes, *mode)?,
        None => remove_file_if_exists(avail_path)?,
    }
    Ok(())
}

pub(crate) fn enable_managed_apache_modules(downstream_tls: bool) -> anyhow::Result<()> {
    let mut modules = vec![
        "proxy",
        "proxy_http",
        "proxy_wstunnel",
        "rewrite",
        "headers",
        "alias",
    ];
    if downstream_tls {
        modules.push("ssl");
    }
    let apache = Path::new("/etc/apache2");
    if !apache.join("mods-available").is_dir() {
        return Ok(());
    }
    modules.retain(|module| {
        !apache
            .join("mods-enabled")
            .join(format!("{module}.load"))
            .is_file()
    });
    if !modules.is_empty() {
        let output = std::process::Command::new("/usr/sbin/a2enmod")
            .args(modules)
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "a2enmod failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

async fn run_apache_configtest_if_present() -> anyhow::Result<()> {
    for bin in [
        "/usr/sbin/apache2ctl",
        "/usr/sbin/apachectl",
        "apache2ctl",
        "apachectl",
    ] {
        let mut cmd = Command::new(bin);
        cmd.arg("-t").kill_on_drop(true);
        match tokio::time::timeout(Duration::from_secs(15), cmd.output()).await {
            Ok(Ok(out)) => {
                if out.status.success() {
                    return Ok(());
                }
                let combined = format!(
                    "{} {}",
                    String::from_utf8_lossy(&out.stderr).trim(),
                    String::from_utf8_lossy(&out.stdout).trim()
                );
                anyhow::bail!("apache2ctl -t failed: {}", combined.trim());
            }
            Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Ok(Err(err)) => anyhow::bail!("failed to execute {} -t: {}", bin, err),
            Err(_) => anyhow::bail!("{} -t timed out", bin),
        }
    }
    Ok(())
}

async fn reload_apache_if_active() -> anyhow::Result<()> {
    let active_out = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("systemctl")
            .args(["is-active", "--quiet", "apache2"])
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let is_active = match active_out {
        Ok(Ok(out)) => out.status.success(),
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(Err(err)) => anyhow::bail!("failed to check apache2 status: {}", err),
        Err(_) => anyhow::bail!("systemctl is-active apache2 timed out"),
    };
    if !is_active {
        return Ok(());
    }
    let reload_out = tokio::time::timeout(
        Duration::from_secs(20),
        Command::new("systemctl")
            .args(["reload", "apache2"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("systemctl reload apache2 timed out"))?
    .map_err(|err| anyhow::anyhow!("failed to execute systemctl reload apache2: {}", err))?;
    if !reload_out.status.success() {
        let combined = format!(
            "{} {}",
            String::from_utf8_lossy(&reload_out.stderr).trim(),
            String::from_utf8_lossy(&reload_out.stdout).trim()
        );
        anyhow::bail!("systemctl reload apache2 failed: {}", combined.trim());
    }
    Ok(())
}

fn validate_ingress_vhost_request(req: &RunnerApacheVhostRequest) -> Result<(), String> {
    if !SAFE_INGRESS_APP_NAME.is_match(&req.app_name) {
        return Err("invalid app_name: must match ^[a-z0-9][a-z0-9-]{0,47}$".to_string());
    }
    if get_runner_package_definition(&req.app_name).is_none() {
        return Err("app_name is not in the package catalog".to_string());
    }
    if !req.remove_only && !(1..=65535).contains(&req.listen_port) {
        return Err("listen_port must be in 1..=65535".to_string());
    }
    if let Some(domain) = &req.internal_domain {
        if !domain.eq_ignore_ascii_case(&format!("{}.aether.local", req.app_name)) {
            return Err("invalid internal_domain: expected <app_name>.aether.local".to_string());
        }
    }
    if let Some(domain) = &req.public_domain {
        if !af_models::valid_ingress_hostname(domain)
            || domain.eq_ignore_ascii_case("aether.local")
            || domain.to_ascii_lowercase().ends_with(".aether.local")
        {
            return Err("invalid public_domain".to_string());
        }
    }
    if !req.remove_only && req.external_access_enabled && req.public_domain.is_none() {
        return Err("public_domain is required for external access".to_string());
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct VhostBackup {
    avail_path: PathBuf,
    enabled_path: PathBuf,
    prev_avail: Option<(Vec<u8>, u32)>,
    prev_enabled: PrevEnabledVhostState,
}

fn resolve_lifecycle_apache_dir(fs_root: Option<&Path>) -> PathBuf {
    if let Ok(explicit) = env::var("AETHERFLOW_APACHE_DIR") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Some(root) = fs_root {
        root.join("etc/apache2")
    } else {
        PathBuf::from("/etc/apache2")
    }
}

pub(crate) fn snapshot_app_vhost_backups(
    app_name: &str,
    fs_root: Option<&Path>,
) -> anyhow::Result<Vec<VhostBackup>> {
    if !SAFE_INGRESS_APP_NAME.is_match(app_name) {
        return Ok(Vec::new());
    }
    let apache_dir = resolve_lifecycle_apache_dir(fs_root);
    let avail_dir = apache_dir.join("sites-available");
    let enabled_dir = apache_dir.join("sites-enabled");
    if apache_dir.exists() {
        ensure_non_symlink_dir(&apache_dir, false)?;
    }
    if avail_dir.exists() {
        ensure_non_symlink_dir(&avail_dir, false)?;
    }
    if enabled_dir.exists() {
        ensure_non_symlink_dir(&enabled_dir, false)?;
    }
    let names = [
        format!("aetherflow-app-{app_name}.conf"),
        format!("aetherflow-ext-{app_name}.conf"),
        format!("aetherflow-ext-{app_name}-le-ssl.conf"),
        format!("{app_name}.conf"),
    ];
    let mut backups = Vec::with_capacity(names.len());
    for name in names {
        let avail_path = avail_dir.join(&name);
        let enabled_path = enabled_dir.join(&name);
        let prev_avail = if avail_dir.exists() {
            read_regular_file_nofollow(&avail_path)?
        } else {
            None
        };
        let prev_enabled = if enabled_dir.exists() {
            snapshot_enabled_vhost(&enabled_path)?
        } else {
            PrevEnabledVhostState::Missing
        };
        backups.push(VhostBackup {
            avail_path,
            enabled_path,
            prev_avail,
            prev_enabled,
        });
    }
    Ok(backups)
}

pub(crate) fn restore_app_vhost_backups(backups: &[VhostBackup]) -> anyhow::Result<bool> {
    if backups.is_empty() {
        return Ok(false);
    }
    let mut changed = false;
    for backup in backups {
        let curr_avail = if backup.avail_path.parent().is_some_and(Path::exists) {
            read_regular_file_nofollow(&backup.avail_path)?
        } else {
            None
        };
        let curr_enabled = if backup.enabled_path.parent().is_some_and(Path::exists) {
            snapshot_enabled_vhost(&backup.enabled_path)?
        } else {
            PrevEnabledVhostState::Missing
        };
        if curr_avail != backup.prev_avail || curr_enabled != backup.prev_enabled {
            changed = true;
            break;
        }
    }
    if !changed {
        return Ok(false);
    }
    rollback_vhost_backups(backups)?;
    Ok(true)
}

pub(crate) async fn reload_apache_after_rollback_if_live(fs_root: Option<&Path>) {
    if fs_root.is_none()
        && env::var_os("AETHERFLOW_APACHE_DIR").is_none()
        && env::var_os("AETHERFLOW_SYSTEMD_ROOT").is_none()
    {
        let _ = reload_apache_if_active().await;
    }
}

fn apply_single_ingress_vhost(
    enabled: bool,
    content: Option<&str>,
    conf_name: &str,
    avail_path: &Path,
    enabled_path: &Path,
) -> anyhow::Result<()> {
    if enabled {
        let body = content.unwrap_or_default();
        write_file_atomically_with_mode(avail_path, body.as_bytes(), 0o644)?;
        remove_file_if_exists(enabled_path)?;
        #[cfg(unix)]
        {
            let target = format!("../sites-available/{conf_name}");
            std::os::unix::fs::symlink(target, enabled_path)?;
        }
    } else {
        remove_file_if_exists(enabled_path)?;
        remove_file_if_exists(avail_path)?;
    }
    Ok(())
}

fn rollback_vhost_backups(backups: &[VhostBackup]) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    for backup in backups {
        if let Err(err) = rollback_ingress_vhost(
            &backup.avail_path,
            &backup.enabled_path,
            &backup.prev_avail,
            &backup.prev_enabled,
        ) {
            errors.push(format!("{}: {err}", backup.avail_path.display()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{}", errors.join("; "))
    }
}

async fn apply_ingress_vhost_with_hooks<FTest, FutTest, FReload, FutReload>(
    req: &RunnerApacheVhostRequest,
    apache_dir: &Path,
    configtest_fn: FTest,
    reload_fn: FReload,
) -> anyhow::Result<String>
where
    FTest: FnOnce() -> FutTest,
    FutTest: std::future::Future<Output = anyhow::Result<()>>,
    FReload: FnOnce() -> FutReload,
    FutReload: std::future::Future<Output = anyhow::Result<()>>,
{
    if let Err(msg) = validate_ingress_vhost_request(req) {
        anyhow::bail!("{msg}");
    }

    let internal = req.internal_domain.as_deref().filter(|_| !req.remove_only);
    let external = req
        .public_domain
        .as_deref()
        .filter(|_| !req.remove_only && req.external_access_enabled);
    let any_enabled = internal.is_some() || external.is_some();
    let fs_root = if apache_dir.ends_with("etc/apache2") && apache_dir != Path::new("/etc/apache2")
    {
        apache_dir.parent().and_then(Path::parent)
    } else {
        None
    };
    let upstream = if any_enabled {
        package_executor::apache_upstream_tls(&req.app_name, fs_root)?
    } else {
        Default::default()
    };
    let avail_dir = apache_dir.join("sites-available");
    let enabled_dir = apache_dir.join("sites-enabled");

    if any_enabled {
        ensure_non_symlink_dir(apache_dir, true)?;
        ensure_non_symlink_dir(&avail_dir, true)?;
        ensure_non_symlink_dir(&enabled_dir, true)?;
    } else {
        if apache_dir.exists() {
            ensure_non_symlink_dir(apache_dir, false)?;
        }
        if avail_dir.exists() {
            ensure_non_symlink_dir(&avail_dir, false)?;
        }
        if enabled_dir.exists() {
            ensure_non_symlink_dir(&enabled_dir, false)?;
        }
    }

    let int_conf_name = format!("aetherflow-app-{}.conf", req.app_name);
    let ext_conf_name = format!("aetherflow-ext-{}.conf", req.app_name);
    let ssl_conf_name = format!("aetherflow-ext-{}-le-ssl.conf", req.app_name);
    let legacy_conf_name = format!("{}.conf", req.app_name);
    let targets = [
        &int_conf_name,
        &ext_conf_name,
        &ssl_conf_name,
        &legacy_conf_name,
    ];
    let mut backups = Vec::with_capacity(targets.len());
    for name in targets {
        let avail_path = avail_dir.join(name);
        let enabled_path = enabled_dir.join(name);
        let prev_avail = read_regular_file_nofollow(&avail_path)?;
        let prev_enabled = snapshot_enabled_vhost(&enabled_path)?;
        backups.push(VhostBackup {
            avail_path,
            enabled_path,
            prev_avail,
            prev_enabled,
        });
    }

    let contents = |index: usize| -> anyhow::Result<Vec<&str>> {
        let backup = &backups[index];
        let available = backup.prev_avail.iter().map(|(bytes, _)| bytes);
        let enabled = match &backup.prev_enabled {
            PrevEnabledVhostState::RegularFile(bytes, _) => Some(bytes),
            _ => None,
        };
        available
            .chain(enabled)
            .map(|bytes| Ok(std::str::from_utf8(bytes)?))
            .collect()
    };
    let legacy = if any_enabled {
        contents(3)?
    } else {
        Vec::new()
    };
    let int_existing = if internal.is_some() {
        contents(0)?
    } else {
        Vec::new()
    };
    let mut ext_existing = Vec::new();
    if external.is_some() {
        ext_existing.extend(contents(1)?);
        ext_existing.extend(contents(2)?);
    }
    let int_body = internal
        .map(|domain| {
            package_executor::render_managed_apache_vhost(
                req,
                domain,
                true,
                &upstream,
                fs_root,
                &int_existing,
                &legacy,
            )
        })
        .transpose()?;
    let ext_body = external
        .map(|domain| {
            package_executor::render_managed_apache_vhost(
                req,
                domain,
                false,
                &upstream,
                fs_root,
                &ext_existing,
                &legacy,
            )
        })
        .transpose()?;

    let write_result = (|| -> anyhow::Result<()> {
        for ((name, body), backup) in targets
            .into_iter()
            .zip([int_body.as_deref(), ext_body.as_deref(), None])
            .zip(&backups)
        {
            apply_single_ingress_vhost(
                body.is_some(),
                body,
                name,
                &backup.avail_path,
                &backup.enabled_path,
            )?;
        }
        if any_enabled {
            let backup = &backups[3];
            let update = |bytes: &[u8]| -> anyhow::Result<String> {
                package_executor::update_legacy_apache_vhost(
                    std::str::from_utf8(bytes)?,
                    req,
                    &upstream,
                    fs_root,
                    false,
                )
            };
            if let Some((bytes, mode)) = &backup.prev_avail {
                let body = update(bytes)?;
                if body.as_bytes() != bytes {
                    write_file_atomically_with_mode(&backup.avail_path, body.as_bytes(), *mode)?;
                }
            }
            if let PrevEnabledVhostState::RegularFile(bytes, mode) = &backup.prev_enabled {
                let body = update(bytes)?;
                if body.as_bytes() != bytes {
                    write_file_atomically_with_mode(&backup.enabled_path, body.as_bytes(), *mode)?;
                }
            }
        }
        Ok(())
    })();
    if let Err(err) = write_result {
        if let Err(rb_err) = rollback_vhost_backups(&backups) {
            anyhow::bail!("{err}; rollback failed: {rb_err}");
        }
        return Err(err);
    }

    if let Err(test_err) = configtest_fn().await {
        if let Err(rb_err) = rollback_vhost_backups(&backups) {
            anyhow::bail!("{test_err}; rollback failed: {rb_err}");
        }
        return Err(test_err);
    }

    if req.reload_apache {
        if let Err(reload_err) = reload_fn().await {
            if let Err(rb_err) = rollback_vhost_backups(&backups) {
                anyhow::bail!("{reload_err}; rollback failed: {rb_err}");
            }
            return Err(reload_err);
        }
    }

    Ok(format!(
        "synced apache vhosts ({}={}, {}={})",
        int_conf_name,
        if internal.is_some() {
            "enabled"
        } else {
            "disabled"
        },
        ext_conf_name,
        if external.is_some() {
            "enabled"
        } else {
            "disabled"
        }
    ))
}

async fn handle_ingress_vhost(
    Json(req): Json<RunnerApacheVhostRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if let Err(msg) = validate_ingress_vhost_request(&req) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: msg,
            }),
        );
    }

    let apache_dir = resolve_provider_dir("AETHERFLOW_APACHE_DIR", "/etc/apache2");
    let res = sync_apache_vhost_local(&req, &apache_dir).await;

    match res {
        Ok(output) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output,
                error: String::new(),
            }),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: err.to_string(),
            }),
        ),
    }
}

pub async fn sync_apache_vhost_local(
    req: &RunnerApacheVhostRequest,
    apache_dir: &Path,
) -> anyhow::Result<String> {
    validate_ingress_vhost_request(req).map_err(anyhow::Error::msg)?;
    static VHOST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _guard = VHOST_LOCK.lock().await;
    let live = apache_dir == Path::new("/etc/apache2");
    if live && !req.remove_only && unsafe { libc::geteuid() } == 0 {
        let tls = req.tls_enabled || matches!(req.app_name.as_str(), "kasmvnc" | "librespeed");
        tokio::task::spawn_blocking(move || enable_managed_apache_modules(tls)).await??;
    }
    apply_ingress_vhost_with_hooks(
        req,
        apache_dir,
        || async {
            if live {
                run_apache_configtest_if_present().await
            } else {
                Ok(())
            }
        },
        || async {
            if live {
                reload_apache_if_active().await
            } else {
                Ok(())
            }
        },
    )
    .await
}

pub async fn sync_apache_vhost_via_runner(
    req: &RunnerApacheVhostRequest,
) -> anyhow::Result<RunnerResponse> {
    if let Err(msg) = validate_ingress_vhost_request(req) {
        anyhow::bail!("{msg}");
    }
    let result = post_runner_json("/v1/ingress/vhost", req, Duration::from_secs(45)).await?;
    if !result.success {
        anyhow::bail!("runner ingress vhost error: {}", result.error);
    }
    Ok(result)
}

async fn execute_certbot_sync_with_candidates(
    candidates: &[&Path],
    require_root_owner: bool,
    timeout: Duration,
) -> anyhow::Result<String> {
    let mut selected: Option<&Path> = None;
    for candidate in candidates {
        match fs::symlink_metadata(candidate) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    anyhow::bail!(
                        "refusing symlinked certbot-sync executable: {}",
                        candidate.display()
                    );
                }
                if !meta.is_file() {
                    anyhow::bail!(
                        "refusing non-regular certbot-sync path: {}",
                        candidate.display()
                    );
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if require_root_owner && meta.uid() != 0 {
                        anyhow::bail!(
                            "certbot-sync executable {} must be owned by root",
                            candidate.display()
                        );
                    }
                    let mode = meta.mode();
                    if (mode & 0o022) != 0 {
                        anyhow::bail!(
                            "certbot-sync executable {} must not be group/world writable",
                            candidate.display()
                        );
                    }
                    if (mode & 0o111) == 0 {
                        anyhow::bail!(
                            "certbot-sync executable {} is not executable",
                            candidate.display()
                        );
                    }
                }
                #[cfg(not(unix))]
                let _ = require_root_owner;
                selected = Some(candidate);
                break;
            }
        }
    }

    let bin = selected.ok_or_else(|| {
        anyhow::anyhow!("af-certbot-sync executable not found in /usr/local/bin or /usr/bin")
    })?;

    let mut cmd = Command::new(bin);
    cmd.stdin(std::process::Stdio::null()).kill_on_drop(true);
    let out = tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| anyhow::anyhow!("af-certbot-sync timed out after {}s", timeout.as_secs()))?
        .map_err(|err| anyhow::anyhow!("failed to execute {}: {}", bin.display(), err))?;

    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !out.status.success() {
        let combined = [stdout, stderr]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        anyhow::bail!(
            "af-certbot-sync exited with {:?}: {}",
            out.status.code(),
            combined
        );
    }
    Ok(if stdout.is_empty() {
        "certbot-sync completed".to_string()
    } else {
        stdout
    })
}

pub async fn sync_certbot_and_managed_ingress() -> anyhow::Result<String> {
    static CERTBOT_SYNC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _lock = CERTBOT_SYNC_LOCK.lock().await;
    let candidates = [
        Path::new("/usr/local/bin/af-certbot-sync"),
        Path::new("/usr/bin/af-certbot-sync"),
    ];
    let output =
        execute_certbot_sync_with_candidates(&candidates, true, Duration::from_secs(120)).await?;
    let apache_dir = resolve_provider_dir("AETHERFLOW_APACHE_DIR", "/etc/apache2");
    let active = apache_dir.join("sites-enabled");
    if !active.is_dir() {
        return Ok(output);
    }
    let configs = tokio::task::spawn_blocking(|| -> anyhow::Result<Vec<(String, String, i32)>> {
        let conn = open_runner_state_database(None)?;
        let mut stmt = conn.prepare(
            "SELECT app_name, public_domain, listen_port FROM app_ingress_configs \
             WHERE external_access_enabled = 1 AND tls_enabled = 1 AND public_domain <> '' AND listen_port > 0",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }).await??;
    for (app_name, domain, listen_port) in configs {
        if !SAFE_INGRESS_APP_NAME.is_match(&app_name)
            || !active
                .join(format!("aetherflow-ext-{app_name}.conf"))
                .is_file()
        {
            continue;
        }
        let req = RunnerApacheVhostRequest {
            internal_domain: active
                .join(format!("aetherflow-app-{app_name}.conf"))
                .is_file()
                .then(|| format!("{app_name}.aether.local")),
            app_name,
            public_domain: Some(domain),
            listen_port,
            external_access_enabled: true,
            tls_enabled: true,
            reload_apache: true,
            ..Default::default()
        };
        validate_ingress_vhost_request(&req).map_err(anyhow::Error::msg)?;
        sync_apache_vhost_local(&req, &apache_dir).await?;
    }
    Ok(output)
}

async fn handle_certbot_sync() -> (StatusCode, Json<RunnerResponse>) {
    match sync_certbot_and_managed_ingress().await {
        Ok(output) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output,
                error: String::new(),
            }),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: err.to_string(),
            }),
        ),
    }
}

pub async fn trigger_certbot_sync_via_runner() -> anyhow::Result<RunnerResponse> {
    let result = post_runner_json("/v1/certbot-sync", &json!({}), Duration::from_secs(130)).await?;
    if !result.success {
        anyhow::bail!("runner certbot-sync error: {}", result.error);
    }
    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// UNIX Domain Socket Client Dispatchers
// ─────────────────────────────────────────────────────────────────────────────

/// Retryable lifecycle exclusion, kept typed across runner and API boundaries.
#[derive(Debug, thiserror::Error)]
#[error("Application lifecycle or system maintenance is busy. Retry after the active operation completes.")]
pub struct LifecycleBusy;

pub fn is_lifecycle_busy(error: &anyhow::Error) -> bool {
    error.is::<LifecycleBusy>()
        || matches!(
            error.downcast_ref::<af_release::ReleaseError>(),
            Some(af_release::ReleaseError::LockBusy { .. })
        )
}

#[cfg(unix)]
async fn post_runner_json<T: Serialize + ?Sized>(
    endpoint: &str,
    payload: &T,
    timeout: Duration,
) -> anyhow::Result<RunnerResponse> {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    let sock_path = resolve_runner_socket_path();
    let body_bytes = serde_json::to_vec(payload)?;

    let fut = async {
        let stream = tokio::net::UnixStream::connect(&sock_path).await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(endpoint)
            .header("Host", "unix")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))?;

        let resp = sender.send_request(req).await?;
        if matches!(endpoint, "/v1/systemctl" | "/v1/blueprint/apply")
            && resp.status() == StatusCode::CONFLICT
        {
            return Err(LifecycleBusy.into());
        }
        if endpoint == "/v1/health" && !resp.status().is_success() {
            anyhow::bail!(
                "runner health probe returned non-success status {}",
                resp.status()
            );
        }
        let collected = resp.into_body().collect().await?.to_bytes();
        let decoded: RunnerResponse = serde_json::from_slice(&collected)?;
        Ok::<RunnerResponse, anyhow::Error>(decoded)
    };

    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow::anyhow!("runner socket request timed out ({})", endpoint))?
}

#[cfg(not(unix))]
async fn post_runner_json<T: Serialize + ?Sized>(
    endpoint: &str,
    _payload: &T,
    _timeout: Duration,
) -> anyhow::Result<RunnerResponse> {
    anyhow::bail!(
        "UNIX domain socket runner client is only supported on Unix hosts ({})",
        endpoint
    )
}

/// Ask the running daemon itself. A socket path can survive a daemon crash.
pub async fn runner_is_ready() -> bool {
    post_runner_json("/v1/health", &(), Duration::from_secs(2))
        .await
        .is_ok_and(|response| response.success && response.output == "ready")
}

#[cfg(unix)]
async fn post_runner_plugin_json<T: Serialize + ?Sized>(
    endpoint: &str,
    payload: &T,
    timeout: Duration,
) -> Result<(StatusCode, RunnerResponse), PluginRunnerError> {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    let sock_path = resolve_runner_socket_path();
    let body_bytes = serde_json::to_vec(payload)
        .map_err(|err| PluginRunnerError::InvalidRequest(format!("Serialization error: {err}")))?;

    let fut = async {
        let stream = tokio::net::UnixStream::connect(&sock_path)
            .await
            .map_err(|err| {
                PluginRunnerError::IsolationUnavailable(format!(
                    "Managed plugin isolation is unavailable: cannot connect to aetherflow-runner socket '{}' ({err}). Start aetherflow-runner.service on a systemd-managed Linux host or run this plugin as an external backend.",
                    sock_path
                ))
            })?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|err| {
                PluginRunnerError::IsolationUnavailable(format!(
                    "Managed plugin isolation is unavailable: runner IPC handshake failed on '{}' ({err}).",
                    sock_path
                ))
            })?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(endpoint)
            .header("Host", "unix")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|err| {
                PluginRunnerError::Runtime(format!("Failed to build runner request: {err}"))
            })?;

        let resp = sender.send_request(req).await.map_err(|err| {
            PluginRunnerError::Runtime(format!("Runner request failed ({endpoint}): {err}"))
        })?;
        let status = resp.status();
        let collected = resp
            .into_body()
            .collect()
            .await
            .map_err(|err| {
                PluginRunnerError::Runtime(format!(
                    "Failed to read runner response ({endpoint}): {err}"
                ))
            })?
            .to_bytes();
        let decoded: RunnerResponse = serde_json::from_slice(&collected).map_err(|err| {
            PluginRunnerError::Runtime(format!(
                "Invalid JSON response from runner ({endpoint}, HTTP {}): {err}",
                status.as_u16()
            ))
        })?;
        Ok((status, decoded))
    };

    tokio::time::timeout(timeout, fut).await.map_err(|_| {
        PluginRunnerError::Runtime(format!("Runner plugin request timed out ({endpoint})"))
    })?
}

#[cfg(not(unix))]
async fn post_runner_plugin_json<T: Serialize + ?Sized>(
    endpoint: &str,
    _payload: &T,
    _timeout: Duration,
) -> Result<(StatusCode, RunnerResponse), PluginRunnerError> {
    Err(PluginRunnerError::IsolationUnavailable(format!(
        "Managed plugin isolation is unavailable: UNIX domain socket runner requires Linux/Unix ({endpoint})."
    )))
}

fn map_plugin_runner_failure(status: StatusCode, resp: RunnerResponse) -> PluginRunnerError {
    let msg = if resp.error.trim().is_empty() {
        format!("Runner returned HTTP {}", status.as_u16())
    } else {
        resp.error
    };
    match status {
        StatusCode::SERVICE_UNAVAILABLE => PluginRunnerError::IsolationUnavailable(msg),
        StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN => PluginRunnerError::InvalidRequest(msg),
        _ => PluginRunnerError::Runtime(msg),
    }
}

pub async fn dispatch_plugin_start(
    req: &PluginRunnerStartRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let (status, resp) =
        post_runner_plugin_json("/v1/plugins/start", req, Duration::from_secs(25)).await?;
    if status != StatusCode::OK || !resp.success {
        return Err(map_plugin_runner_failure(status, resp));
    }
    serde_json::from_str(&resp.output).map_err(|err| {
        PluginRunnerError::Runtime(format!("Invalid plugin start response payload: {err}"))
    })
}

pub async fn dispatch_plugin_stop(
    req: &PluginRunnerStopRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let (status, resp) =
        post_runner_plugin_json("/v1/plugins/stop", req, Duration::from_secs(30)).await?;
    if status != StatusCode::OK || !resp.success {
        return Err(map_plugin_runner_failure(status, resp));
    }
    serde_json::from_str(&resp.output).map_err(|err| {
        PluginRunnerError::Runtime(format!("Invalid plugin stop response payload: {err}"))
    })
}

pub async fn dispatch_plugin_status(
    req: &PluginRunnerStatusRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let (status, resp) =
        post_runner_plugin_json("/v1/plugins/status", req, Duration::from_secs(10)).await?;
    if status != StatusCode::OK || !resp.success {
        return Err(map_plugin_runner_failure(status, resp));
    }
    serde_json::from_str(&resp.output).map_err(|err| {
        PluginRunnerError::Runtime(format!("Invalid plugin status response payload: {err}"))
    })
}

pub async fn dispatch_plugin_token_rotate(
    req: &PluginRunnerTokenRotateRequest,
) -> Result<(), PluginRunnerError> {
    let (status, resp) =
        post_runner_plugin_json("/v1/plugins/token", req, Duration::from_secs(10)).await?;
    if status != StatusCode::OK || !resp.success {
        return Err(map_plugin_runner_failure(status, resp));
    }
    Ok(())
}

pub async fn dispatch_heal_restart(service_name: &str) -> anyhow::Result<bool> {
    let req = SystemctlRequest {
        service: service_name.to_string(),
        action: "heal".to_string(),
        lifecycle_job_id: String::new(),
    };
    let result = if is_runner_available() {
        post_runner_json("/v1/systemctl", &req, Duration::from_secs(45)).await?
    } else {
        let (_, Json(result)) = handle_systemctl(Json(req)).await;
        result
    };
    if !result.success {
        anyhow::bail!(
            "runner recovery error: {} ({})",
            result.error,
            result.output
        );
    }
    Ok(result.output != "skipped")
}

pub async fn dispatch_systemctl(service_name: &str, action: &str) -> anyhow::Result<()> {
    let req = SystemctlRequest {
        service: service_name.to_string(),
        action: action.to_string(),
        lifecycle_job_id: current_package_job_id(),
    };
    let result = post_runner_json("/v1/systemctl", &req, Duration::from_secs(45)).await?;
    if !result.success {
        anyhow::bail!(
            "runner systemctl error: {} ({})",
            result.error,
            result.output
        );
    }
    Ok(())
}

pub async fn dispatch_core_restart(service_name: &str) -> anyhow::Result<String> {
    let req = SystemctlRequest {
        service: service_name.into(),
        action: "restart-deferred".into(),
        lifecycle_job_id: String::new(),
    };
    let result = post_runner_json("/v1/systemctl", &req, Duration::from_secs(45)).await?;
    anyhow::ensure!(
        result.success,
        "runner core restart error: {}",
        result.error
    );
    let payload: serde_json::Value = serde_json::from_str(&result.output)?;
    let unit = payload
        .get("job_unit")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    anyhow::ensure!(
        af_models::is_valid_self_update_job_unit_name(unit),
        "Core restart acknowledgment is missing its receipt identity"
    );
    Ok(unit.into())
}

const MAX_PACKAGE_STREAM_LINE_BYTES: usize = 64 * 1024;

#[derive(Default)]
struct IncrementalPackageLineDecoder {
    pending: Vec<u8>,
    discarding_overlong: bool,
    exit_error: Option<String>,
}

impl IncrementalPackageLineDecoder {
    fn handle_line_bytes<F>(&mut self, raw_bytes: &[u8], on_line: &mut F)
    where
        F: FnMut(String),
    {
        let raw_line = String::from_utf8_lossy(raw_bytes);
        let line = raw_line.trim();
        if let Some(message) = line.strip_prefix("__RUNNER_EXIT_ERROR__:") {
            self.exit_error = Some(if message.trim().is_empty() {
                "runner reported package execution failure".to_string()
            } else {
                message.trim().to_string()
            });
        } else if !line.is_empty() {
            on_line(line.to_string());
        }
    }

    fn push_bytes<F>(&mut self, chunk: &[u8], on_line: &mut F)
    where
        F: FnMut(String),
    {
        let mut rest = chunk;
        while !rest.is_empty() {
            if self.discarding_overlong {
                if let Some(nl_pos) = rest.iter().position(|&b| b == b'\n') {
                    self.discarding_overlong = false;
                    let drained = std::mem::take(&mut self.pending);
                    self.handle_line_bytes(&drained, on_line);
                    rest = &rest[nl_pos + 1..];
                } else {
                    return;
                }
            } else if let Some(nl_pos) = rest.iter().position(|&b| b == b'\n') {
                let to_take = &rest[..nl_pos];
                let room = MAX_PACKAGE_STREAM_LINE_BYTES.saturating_sub(self.pending.len());
                self.pending
                    .extend_from_slice(&to_take[..to_take.len().min(room)]);
                let drained = std::mem::take(&mut self.pending);
                self.handle_line_bytes(&drained, on_line);
                rest = &rest[nl_pos + 1..];
            } else {
                let room = MAX_PACKAGE_STREAM_LINE_BYTES.saturating_sub(self.pending.len());
                let take_len = rest.len().min(room);
                self.pending.extend_from_slice(&rest[..take_len]);
                if self.pending.len() >= MAX_PACKAGE_STREAM_LINE_BYTES && rest.len() > take_len {
                    self.discarding_overlong = true;
                }
                return;
            }
        }
    }

    fn finish<F>(mut self, on_line: &mut F) -> anyhow::Result<()>
    where
        F: FnMut(String),
    {
        if !self.pending.is_empty() {
            let drained = std::mem::take(&mut self.pending);
            self.handle_line_bytes(&drained, on_line);
        }
        if let Some(error) = self.exit_error {
            anyhow::bail!("{}", error);
        }
        Ok(())
    }
}

#[cfg(test)]
fn consume_package_output<F>(body_text: &str, mut on_line: F) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    let mut decoder = IncrementalPackageLineDecoder::default();
    decoder.push_bytes(body_text.as_bytes(), &mut on_line);
    decoder.finish(&mut on_line)
}

pub async fn dispatch_package_action<F>(
    action: &str,
    pkg_id: &str,
    script_name: &str,
    app_port: i32,
    on_line: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    dispatch_package_action_with_options(action, pkg_id, script_name, app_port, false, on_line)
        .await
}

/// Dispatches a package operation through the runner socket. `delete_data` is
/// only honored for `remove`; it is the sole way to request a destructive purge.
pub async fn dispatch_package_action_with_options<F>(
    action: &str,
    pkg_id: &str,
    script_name: &str,
    app_port: i32,
    delete_data: bool,
    on_line: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    dispatch_package_action_with_target(
        action,
        pkg_id,
        script_name,
        app_port,
        delete_data,
        None,
        on_line,
    )
    .await
}

pub async fn dispatch_package_action_with_target<F>(
    action: &str,
    pkg_id: &str,
    script_name: &str,
    app_port: i32,
    delete_data: bool,
    expected_target_version: Option<String>,
    mut on_line: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    if delete_data && action != "remove" {
        anyhow::bail!("data purge is only valid for package removal");
    }
    #[cfg(unix)]
    {
        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;
        use hyper_util::rt::TokioIo;

        let sock_path = resolve_runner_socket_path();
        let req_payload = PackageRunnerRequest {
            action: action.to_string(),
            package_id: pkg_id.to_string(),
            script_name: script_name.to_string(),
            lifecycle_job_id: current_package_job_id(),
            app_port,
            delete_data,
            expected_target_version,
            achieved_version: None,
        };
        let body_bytes = serde_json::to_vec(&req_payload)?;

        let fut = async {
            let stream = tokio::net::UnixStream::connect(&sock_path).await?;
            let io = TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });

            let req = hyper::Request::builder()
                .method(hyper::Method::POST)
                .uri("http://unix/v1/package")
                .header("Host", "unix")
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body_bytes)))?;

            let resp = sender.send_request(req).await?;
            let status = resp.status();
            let mut body = resp.into_body();

            if status != StatusCode::OK {
                let mut err_buf = Vec::new();
                while let Some(frame_res) = body.frame().await {
                    let frame = frame_res?;
                    if let Some(data) = frame.data_ref() {
                        let room = (64 * 1024usize).saturating_sub(err_buf.len());
                        if room == 0 {
                            break;
                        }
                        err_buf.extend_from_slice(&data[..data.len().min(room)]);
                    }
                }
                let body_text = String::from_utf8_lossy(&err_buf);
                anyhow::bail!(
                    "runner rejected package action (HTTP {}): {}",
                    status.as_u16(),
                    body_text.trim()
                );
            }

            let mut decoder = IncrementalPackageLineDecoder::default();
            while let Some(frame_res) = body.frame().await {
                let frame = frame_res?;
                if let Some(data) = frame.data_ref() {
                    decoder.push_bytes(data, &mut on_line);
                }
            }
            decoder.finish(&mut on_line)
        };

        tokio::time::timeout(Duration::from_secs(30 * 60), fut)
            .await
            .map_err(|_| anyhow::anyhow!("runner socket package request timed out"))?
    }
    #[cfg(not(unix))]
    {
        let _ = (
            action,
            pkg_id,
            script_name,
            app_port,
            delete_data,
            &mut on_line,
        );
        anyhow::bail!("UNIX domain socket runner client is only supported on Unix hosts")
    }
}

pub async fn dispatch_package_stream<F>(
    action: &str,
    pkg_id: &str,
    script_name: &str,
    app_port: i32,
    on_line: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    dispatch_package_action(action, pkg_id, script_name, app_port, on_line).await
}

/// Requests cooperative cancellation of an in-flight package operation (`install`, `update`, or `remove`)
/// via the runner socket if available, or directly in-process.
pub async fn dispatch_package_cancel(pkg_id: &str) -> anyhow::Result<bool> {
    if !SAFE_PKG_ID.is_match(pkg_id) || pkg_id.contains("..") {
        anyhow::bail!("invalid package identifier");
    }
    if cancel_package_execution(pkg_id) {
        return Ok(true);
    }
    if is_runner_available() {
        let req = SandboxRunnerRequest {
            package: pkg_id.to_string(),
            package_id: pkg_id.to_string(),
            lifecycle_job_id: current_package_job_id(),
        };
        let result = post_runner_json("/v1/package/cancel", &req, Duration::from_secs(5)).await?;
        return Ok(result.success && result.output.starts_with("cancellation signalled"));
    }
    Ok(false)
}

pub async fn dispatch_package_lifecycle_snapshot_capture(
    pkg_id: &str,
    units: &[String],
) -> anyhow::Result<()> {
    let job_id = current_package_job_id();
    anyhow::ensure!(
        !job_id.trim().is_empty(),
        "lifecycle_job_id is required to capture a runner lifecycle snapshot"
    );
    let req = PackageLifecycleSnapshotRequest {
        action: "capture".to_string(),
        package_id: pkg_id.to_string(),
        lifecycle_job_id: job_id,
        units: units.to_vec(),
        preserve_backup: false,
    };
    let resp = post_runner_json(
        "/v1/package/lifecycle-snapshot",
        &req,
        Duration::from_secs(10 * 60),
    )
    .await?;
    anyhow::ensure!(
        resp.success,
        "runner lifecycle snapshot capture failed: {}",
        resp.error
    );
    Ok(())
}

pub async fn dispatch_package_lifecycle_snapshot_restore(pkg_id: &str) -> anyhow::Result<()> {
    let job_id = current_package_job_id();
    anyhow::ensure!(
        !job_id.trim().is_empty(),
        "lifecycle_job_id is required to restore a runner lifecycle snapshot"
    );
    let req = PackageLifecycleSnapshotRequest {
        action: "restore".to_string(),
        package_id: pkg_id.to_string(),
        lifecycle_job_id: job_id,
        units: Vec::new(),
        preserve_backup: false,
    };
    let resp = post_runner_json(
        "/v1/package/lifecycle-snapshot",
        &req,
        Duration::from_secs(10 * 60),
    )
    .await?;
    anyhow::ensure!(
        resp.success,
        "runner lifecycle snapshot restore failed: {}",
        resp.error
    );
    Ok(())
}

pub async fn dispatch_package_lifecycle_snapshot_discard_for_job(
    pkg_id: &str,
    job_id: &str,
    preserve_backup: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !job_id.trim().is_empty(),
        "lifecycle_job_id is required to discard a runner lifecycle snapshot"
    );
    let req = PackageLifecycleSnapshotRequest {
        action: "discard".to_string(),
        package_id: pkg_id.to_string(),
        lifecycle_job_id: job_id.to_string(),
        units: Vec::new(),
        preserve_backup,
    };
    let resp = post_runner_json(
        "/v1/package/lifecycle-snapshot",
        &req,
        Duration::from_secs(60),
    )
    .await?;
    anyhow::ensure!(
        resp.success,
        "runner lifecycle snapshot discard failed: {}",
        resp.error
    );
    Ok(())
}

pub async fn dispatch_package_lifecycle_snapshot_discard(
    pkg_id: &str,
    preserve_backup: bool,
) -> anyhow::Result<()> {
    let job_id = current_package_job_id();
    dispatch_package_lifecycle_snapshot_discard_for_job(pkg_id, &job_id, preserve_backup).await
}

/// Executes a package operation locally in-process (for CLI/provisioner or direct root execution),
/// streaming newline-delimited progress/log lines to `on_line`.
pub async fn execute_package_local<F>(
    action: &str,
    pkg_id: &str,
    script_name: &str,
    app_port: i32,
    mut on_line: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    use futures::StreamExt;

    if !matches!(action, "install" | "remove" | "update") {
        anyhow::bail!("disallowed package action");
    }
    if !SAFE_SCRIPT_NAME.is_match(script_name) || !SAFE_SCRIPT_NAME.is_match(pkg_id) {
        anyhow::bail!("invalid script or package identifier");
    }
    if app_port != 0 && !(1024..=65535).contains(&app_port) {
        anyhow::bail!("invalid application port");
    }
    if !script_matches_package_identity(action, pkg_id, script_name) {
        anyhow::bail!("script_name does not match package_id and action");
    }
    if !can_resolve_package_operation(action, pkg_id, script_name) {
        anyhow::bail!("package script not found");
    }

    let req = PackageRunnerRequest {
        action: action.to_string(),
        package_id: pkg_id.to_string(),
        script_name: script_name.to_string(),
        lifecycle_job_id: current_package_job_id(),
        app_port,
        delete_data: false,
        ..Default::default()
    };
    let stream = execute_package_request_stream(req);
    futures::pin_mut!(stream);
    let mut decoder = IncrementalPackageLineDecoder::default();
    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res?;
        decoder.push_bytes(chunk.as_bytes(), &mut on_line);
    }
    decoder.finish(&mut on_line)
}

pub async fn dispatch_self_update_request(
    req: &SelfUpdateRequest,
) -> anyhow::Result<RunnerResponse> {
    if is_runner_available() {
        let result = post_runner_json("/v1/self-update", req, Duration::from_secs(15)).await?;
        if !result.success {
            anyhow::bail!("runner self-update error: {}", result.error);
        }
        return Ok(result);
    }
    let (status, resp) = execute_self_update_request(req, true).await;
    if status != StatusCode::OK || !resp.success {
        anyhow::bail!(
            "self-update failed (HTTP {}): {}",
            status.as_u16(),
            resp.error
        );
    }
    Ok(resp)
}

pub async fn dispatch_self_update_status_request(
    req: &SelfUpdateStatusRequest,
) -> anyhow::Result<SelfUpdateJobStatus> {
    if is_runner_available() {
        let result =
            post_runner_json("/v1/self-update/status", req, Duration::from_secs(10)).await?;
        if !result.success {
            anyhow::bail!("runner self-update status error: {}", result.error);
        }
        let parsed: SelfUpdateJobStatus = serde_json::from_str(&result.output)?;
        return Ok(parsed);
    }
    query_self_update_status_local(&req.job_unit)
        .await
        .map_err(|(_, msg)| anyhow::anyhow!(msg))
}

pub async fn start_self_update(command: &str, channel: &str) -> anyhow::Result<String> {
    let response = dispatch_self_update_request(&SelfUpdateRequest {
        command: command.to_string(),
        channel: channel.to_string(),
    })
    .await?;
    let payload: Value = serde_json::from_str(&response.output)?;
    let job_unit = payload["job_unit"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("updater launch did not acknowledge a job unit"))?;
    validate_self_update_job_unit_name(job_unit)
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    Ok(job_unit.to_string())
}

pub async fn dispatch_self_update(command: &str, channel: &str) -> anyhow::Result<()> {
    start_self_update(command, channel).await.map(|_| ())
}

pub async fn dispatch_sandbox_apply(pkg_id: &str) -> anyhow::Result<()> {
    let req = SandboxRunnerRequest {
        package: pkg_id.to_string(),
        package_id: pkg_id.to_string(),
        lifecycle_job_id: current_package_job_id(),
    };
    let result = post_runner_json("/v1/sandbox", &req, Duration::from_secs(30)).await?;
    if !result.success {
        anyhow::bail!("runner sandbox error: {}", result.error);
    }
    Ok(())
}

pub async fn dispatch_sandbox(pkg_id: &str) -> anyhow::Result<()> {
    dispatch_sandbox_apply(pkg_id).await
}

pub async fn dispatch_hosts_request(req: &HostsUpdateRequest) -> anyhow::Result<()> {
    let result = post_runner_json("/v1/hosts", req, Duration::from_secs(45)).await?;
    if !result.success {
        anyhow::bail!("runner hosts error: {}", result.error);
    }
    Ok(())
}

pub async fn dispatch_hosts_update(domains: &[String]) -> anyhow::Result<()> {
    let req = HostsUpdateRequest {
        action: "update".to_string(),
        domains: domains.to_vec(),
        ..Default::default()
    };
    dispatch_hosts_request(&req).await
}

pub async fn dispatch_hosts_update_with_provider(
    domains: &[String],
    provider_ip: Option<&str>,
    provider_domains: Option<&[String]>,
) -> anyhow::Result<()> {
    let req = HostsUpdateRequest {
        action: "update".to_string(),
        domains: domains.to_vec(),
        provider_ip: provider_ip.map(|s| s.to_string()),
        provider_domains: provider_domains.map(|d| d.to_vec()),
        ..Default::default()
    };
    dispatch_hosts_request(&req).await
}

pub async fn dispatch_hosts_remove(domains: &[String]) -> anyhow::Result<()> {
    let req = HostsUpdateRequest {
        action: "remove".to_string(),
        domains: domains.to_vec(),
        ..Default::default()
    };
    dispatch_hosts_request(&req).await
}

pub async fn update_hosts_file_via_runner(domains: &[String]) -> anyhow::Result<()> {
    dispatch_hosts_update(domains).await
}

pub async fn remove_hosts_file_via_runner(domains: &[String]) -> anyhow::Result<()> {
    dispatch_hosts_remove(domains).await
}

pub async fn dispatch_hosts_reconcile(domains: &[String], ip: &str) -> anyhow::Result<()> {
    let req = HostsUpdateRequest {
        action: "reconcile".to_string(),
        domains: domains.to_vec(),
        ip: ip.to_string(),
        ..Default::default()
    };
    dispatch_hosts_request(&req).await
}

pub async fn dispatch_hosts_reconcile_with_provider(
    domains: &[String],
    ip: &str,
    provider_ip: Option<&str>,
    provider_domains: Option<&[String]>,
) -> anyhow::Result<()> {
    let req = HostsUpdateRequest {
        action: "reconcile".to_string(),
        domains: domains.to_vec(),
        ip: ip.to_string(),
        provider_ip: provider_ip.map(|s| s.to_string()),
        provider_domains: provider_domains.map(|d| d.to_vec()),
        ..Default::default()
    };
    dispatch_hosts_request(&req).await
}

pub async fn reconcile_hosts_file_via_runner(domains: &[String], ip: &str) -> anyhow::Result<()> {
    dispatch_hosts_reconcile(domains, ip).await
}

pub async fn dispatch_network_control(
    req: &NetworkRunnerRequest,
) -> anyhow::Result<RunnerResponse> {
    let result = post_runner_json("/v1/network", req, Duration::from_secs(60)).await?;
    if !result.success {
        anyhow::bail!("runner network error: {} ({})", result.error, result.output);
    }
    Ok(result)
}

pub async fn dispatch_network_action(req: &NetworkRunnerRequest) -> anyhow::Result<RunnerResponse> {
    dispatch_network_control(req).await
}

pub async fn dispatch_quota_set(username: &str, size: &str) -> anyhow::Result<()> {
    let req = QuotaRunnerRequest {
        username: username.to_string(),
        size: size.to_string(),
    };
    let result = post_runner_json("/v1/quota", &req, Duration::from_secs(30)).await?;
    if !result.success {
        anyhow::bail!("runner quota error: {} ({})", result.error, result.output);
    }
    Ok(())
}

pub async fn dispatch_set_quota(username: &str, size: &str) -> anyhow::Result<()> {
    dispatch_quota_set(username, size).await
}

pub async fn dispatch_app_meta(app_name: &str) -> anyhow::Result<AppRuntimeMeta> {
    let req = AppMetaRunnerRequest {
        app_name: app_name.to_string(),
    };
    let result = post_runner_json("/v1/app-meta", &req, Duration::from_secs(3)).await?;
    if !result.success {
        anyhow::bail!("runner app-meta error: {}", result.error);
    }
    if result.output.trim().is_empty() {
        return Ok(AppRuntimeMeta::default());
    }
    let mut meta: AppRuntimeMeta = serde_json::from_str(&result.output)?;
    meta.url_base =
        af_models::app_metadata::validate_app_web_path(&meta.url_base).unwrap_or_default();
    Ok(meta)
}

/// Authorizes a UNIX domain socket peer (`SO_PEERCRED` / `UCred`) connecting to the privileged runner.
///
/// Permits:
/// - `uid == 0` (root)
/// - `uid == euid` (same effective user running the runner process)
/// - the `aetherflow` service user UID resolved via thread-safe `getpwnam_r` on Unix
/// - any explicit UID listed in `AETHERFLOW_ALLOWED_RUNNER_UIDS` (comma-separated)
///
/// Furthermore, destructive endpoints (`/v1/self-update`, `/v1/backup` with `restore_execute` or `delete`)
/// require either `uid == 0`, `uid == euid`, the `aetherflow` service account, or an explicitly authorized UID.
#[cfg(unix)]
fn lookup_passwd_uid_reentrant(username: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(username).ok()?;
    let mut buf_len = 1024usize;
    const MAX_BUF_LEN: usize = 16 * 1024;
    while buf_len <= MAX_BUF_LEN {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; buf_len];
        let rc = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut res,
            )
        };
        if rc == 0 {
            if res.is_null() {
                return None;
            }
            return Some(pwd.pw_uid as u32);
        }
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        return None;
    }
    None
}

pub fn authorize_runner_peer_credentials(
    peer_uid: u32,
    peer_gid: u32,
    endpoint_path: &str,
) -> Result<(), (StatusCode, String)> {
    #[cfg(unix)]
    let self_euid = unsafe { libc::geteuid() as u32 };
    #[cfg(not(unix))]
    let self_euid = 0u32;

    if peer_uid == 0 || peer_uid == self_euid {
        return Ok(());
    }

    if let Ok(raw_uids) = env::var("AETHERFLOW_ALLOWED_RUNNER_UIDS") {
        for token in raw_uids.split(',') {
            if let Ok(allowed_uid) = token.trim().parse::<u32>() {
                if peer_uid == allowed_uid {
                    return Ok(());
                }
            }
        }
    }

    #[cfg(unix)]
    {
        if let Some(af_uid) = lookup_passwd_uid_reentrant("aetherflow") {
            if peer_uid == af_uid {
                return Ok(());
            }
        }
    }

    Err((
        StatusCode::FORBIDDEN,
        format!(
            "unauthorized unix socket peer uid={} gid={} for endpoint {}",
            peer_uid, peer_gid, endpoint_path
        ),
    ))
}

#[cfg(unix)]
fn authorize_runner_socket_peer(
    uid: u32,
    gid: u32,
    pid: Option<i32>,
    endpoint: &str,
) -> Result<(), (StatusCode, String)> {
    authorize_runner_peer_credentials(uid, gid, endpoint)?;
    #[cfg(target_os = "linux")]
    if uid != 0 && !pid.is_some_and(trusted_runner_peer_exe) {
        return Err((
            StatusCode::FORBIDDEN,
            "untrusted runner peer executable".into(),
        ));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = pid;
    Ok(())
}

#[cfg(target_os = "linux")]
fn trusted_runner_peer_exe(pid: i32) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    if exe
        .components()
        .any(|component| component.as_os_str() == "plugins")
    {
        return false;
    }
    let Some(name) = exe.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if name.starts_with("python") || matches!(name, "bash" | "sh" | "dash" | "node") {
        return false;
    }
    if env::current_exe()
        .and_then(fs::canonicalize)
        .is_ok_and(|path| path == exe)
    {
        return true;
    }
    #[cfg(test)]
    if exe
        .components()
        .any(|component| component.as_os_str() == "deps")
    {
        return true;
    }
    // A basename alone can be chosen by an unprivileged caller. Require a
    // root-owned executable and directory chain for the named control-plane binaries.
    matches!(name, "aetherflow-api" | "af")
        && exe.is_absolute()
        && exe.ancestors().all(|path| {
            fs::symlink_metadata(path).is_ok_and(|meta| {
                !meta.file_type().is_symlink() && meta.uid() == 0 && meta.mode() & 0o022 == 0
            })
        })
}

/// Register both termination signals before serving requests. Shared by API and runner.
pub fn shutdown_signal() -> anyhow::Result<impl std::future::Future<Output = ()> + Send> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        Ok(async move {
            tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(async {
            let _ = tokio::signal::ctrl_c().await;
        })
    }
}

/// Runs the Privileged Root Daemon (`aetherflow-api runner` / `--runner`) over `/run/aetherflow/runner.sock`.
#[cfg(unix)]
pub async fn run_privileged_daemon() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let sock_path = runner_socket_path();
    if let Some(dir) = Path::new(&sock_path).parent() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        if unsafe { libc::geteuid() == 0 } {
            // Keep /run/aetherflow non-group-writable (0750 root:aetherflow) to prevent lock DoS,
            // and pre-create shared 0660 root:aetherflow lockfiles for aetherflow-api access.
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o750));
            for lock_name in [".snapshot.lock", "hosts.lock"] {
                let lock_path = dir.join(lock_name);
                if let Ok(_guard) =
                    af_host::HostMaintenanceLockGuard::acquire(&lock_path, Duration::from_secs(1))
                {
                    let _ = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o660));
                }
            }
        }
    }
    let _ = fs::remove_file(&sock_path);

    let listener = tokio::net::UnixListener::bind(&sock_path)?;
    let _ = fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o660));

    tracing::info!(socket = %sock_path, "AetherFlow Privileged Runner listening");
    let app = build_runner_router();

    serve_runner_connections(listener, app, shutdown_signal()?).await?;
    let _ = fs::remove_file(&sock_path);
    Ok(())
}

#[cfg(unix)]
async fn serve_runner_connections(
    listener: tokio::net::UnixListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    use hyper::service::Service;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;
    let mut connections = tokio::task::JoinSet::new();
    let (drain, drain_rx) = tokio::sync::watch::channel(false);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result { tracing::warn!(%error, "Runner connection task failed"); }
            }
            accept_res = listener.accept() => {
                let (stream, _) = accept_res?;
                let (peer_uid, peer_gid, peer_pid) = match stream.peer_cred() {
                    Ok(cred) => (cred.uid(), cred.gid(), cred.pid()),
                    Err(err) => {
                        tracing::warn!(error = %err, "Rejecting runner connection without SO_PEERCRED");
                        continue;
                    }
                };
                let initial_auth = authorize_runner_socket_peer(peer_uid, peer_gid, peer_pid, "/v1/*");
                let io = TokioIo::new(stream);
                let tower_service = TowerToHyperService::new(app.clone());
                let mut drain_rx = drain_rx.clone();
                connections.spawn(async move {
                    let hyper_service = hyper::service::service_fn(
                        move |request: hyper::Request<hyper::body::Incoming>| {
                            let req_path = request.uri().path().to_string();
                            let auth_res = initial_auth.clone().and_then(|()| {
                                authorize_runner_socket_peer(peer_uid, peer_gid, peer_pid, &req_path)
                            });
                            let svc = tower_service.clone();
                            async move {
                                if let Err((code, msg)) = auth_res {
                                    let body = serde_json::to_string(&RunnerResponse {
                                        success: false,
                                        output: String::new(),
                                        error: msg,
                                    }).unwrap_or_default();
                                    return Ok(Response::builder()
                                        .status(code)
                                        .header("Content-Type", "application/json")
                                        .body(Body::from(body))
                                        .unwrap());
                                }
                                let mut req = request.map(axum::body::Body::new);
                                req.extensions_mut().insert(RunnerPeerCred {
                                    uid: peer_uid,
                                    gid: peer_gid,
                                    pid: peer_pid,
                                });
                                svc.call(req).await
                            }
                        },
                    );
                    let builder = Builder::new(TokioExecutor::new());
                    let connection = builder.serve_connection(io, hyper_service);
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = drain_rx.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    tracing::info!("Privileged Runner draining active requests");
    let _ = drain.send(true);
    let draining = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(std::time::Duration::from_secs(30), draining)
        .await
        .is_err()
    {
        tracing::warn!("Runner drain deadline exceeded; terminating remaining connections");
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn run_privileged_daemon() -> anyhow::Result<()> {
    tracing::warn!("UNIX domain socket runner mode requires a Unix/Linux host");
    Ok(())
}

#[cfg(test)]
pub(crate) static ENV_TEST_MUTEX: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

#[cfg(test)]
mod tests;
