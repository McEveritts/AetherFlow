use af_models::{
    AppMetaRunnerRequest, BackupRunnerRequest, BackupRunnerResponse,
    NetworkRunnerRequest, Package, PackageAutomation, PackageRunnerRequest, QuotaRunnerRequest,
    RunnerResponse, SandboxRunnerRequest, SelfUpdateJobStatus, SelfUpdateRequest,
    SelfUpdateStatusRequest, SystemctlRequest,
};

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

pub mod bounded_command;
mod job_receipts;
mod legacy_stream_output;
#[cfg(all(test, unix))]
mod lifecycle_tests;
pub mod network;
pub mod package_executor;
pub mod package_lifecycle;
pub mod quota;
pub mod self_update;

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
/// - Default is `LegacyBashRelease` (`deploy/release-manager.sh`) unless `AETHERFLOW_ENABLE_RUST_RELEASE=1`
///   is set.
/// - `AETHERFLOW_FORCE_BASH_RELEASE=1` forces `LegacyBashRelease` even when `AETHERFLOW_ENABLE_RUST_RELEASE=1`.
pub fn select_release_engine() -> ReleaseEngineMode {
    let rust_enabled = env::var("AETHERFLOW_ENABLE_RUST_RELEASE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let force_bash = env::var("AETHERFLOW_FORCE_BASH_RELEASE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
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
    if !path.exists() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if let Ok(meta) = fs::metadata(path) {
            return meta.file_type().is_socket() || meta.is_file();
        }
        false
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
        .route("/v1/self-update", post(handle_self_update))
        .route("/v1/self-update/status", post(handle_self_update_status))
        .route("/v1/backup", post(handle_backup))
        .route("/v1/sandbox", post(handle_sandbox))
        .route("/v1/hosts", post(handle_hosts))
        .route("/v1/network", post(handle_network))
        .route("/v1/quota", post(handle_quota))
        .route("/v1/quota/usage", post(quota::handle))
        .route("/v1/app-meta", post(handle_app_meta))
        .route(
            "/v1/dispatcharr-credentials",
            post(handle_dispatcharr_credentials),
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
    if !matches!(req.action.as_str(), "install" | "reinstall" | "remove" | "update") {
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
                return (StatusCode::INTERNAL_SERVER_ERROR, RunnerResponse {
                    success: false, output: String::new(),
                    error: format!("Cannot bind updater receipt directory: {error}"),
                });
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
            ("AETHERFLOW_SELF_UPDATE_DIRECTORY_DEV", receipt_directory_identity.0.to_string()),
            ("AETHERFLOW_SELF_UPDATE_DIRECTORY_INO", receipt_directory_identity.1.to_string()),
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
                return (
                    StatusCode::OK,
                    self_update_launch_response(
                        "legacy_bash_release",
                        &cmd_name,
                        &channel_str,
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

fn load_runner_config_or_embedded(env_var: &str, filename: &str, embedded: &str) -> String {
    if let Ok(explicit) = env::var(env_var) {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            if let Ok(s) = fs::read_to_string(trimmed) {
                return s;
            }
        }
    }
    let mut candidates = vec![
        PathBuf::from("/opt/AetherFlow/current/config").join(filename),
        PathBuf::from("/opt/AetherFlow/current/backend/config").join(filename),
        PathBuf::from("config").join(filename),
        PathBuf::from("../config").join(filename),
        PathBuf::from("/opt/AetherFlow/current/config").join(filename),
        PathBuf::from("/opt/AetherFlow/config").join(filename),
        PathBuf::from("backend/config").join(filename),
        PathBuf::from("../backend/config").join(filename),
        PathBuf::from("/opt/AetherFlow/backend/config").join(filename),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.insert(2, exe_dir.join("config").join(filename));
        }
    }
    for c in candidates {
        if let Ok(s) = fs::read_to_string(&c) {
            return s;
        }
    }
    embedded.to_string()
}

pub fn get_runner_package_definition(pkg_id: &str) -> Option<Package> {
    let raw_pkgs = load_runner_config_or_embedded(
        "AETHERFLOW_PACKAGES_CONFIG",
        "packages.json",
        EMBEDDED_PACKAGES_JSON,
    );
    let raw_auto = load_runner_config_or_embedded(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        "package_automation.json",
        EMBEDDED_AUTOMATION_JSON,
    );

    let mut pkgs: Vec<Package> = serde_json::from_str(&raw_pkgs).ok()?;
    let auto_map: HashMap<String, PackageAutomation> =
        serde_json::from_str(&raw_auto).unwrap_or_default();

    for p in &mut pkgs {
        if let Some(auto) = auto_map.get(&p.name) {
            p.update_source = auto.update_source.clone();
            p.update_repo = auto.update_repo.clone();
            p.update_repo_url = auto.update_repo_url.clone();
            p.update_package = auto.update_package.clone();
            p.version_command = auto.version_command.clone();
            p.version_regex = auto.version_regex.clone();
            p.sandbox_profile = auto.sandbox_profile.clone();
            p.sandbox_read_write = auto.sandbox_read_write.clone();
            p.sandbox_service_ids = auto.sandbox_service_ids.clone();
        }
    }

    pkgs.into_iter().find(|p| p.name == pkg_id)
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
    unit.ends_with(".timer")
        || unit.ends_with(".socket")
        || matches!(
            unit,
            "aetherflow-api.service"
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

    let mut lines = vec![
        "[Service]".to_string(),
        "NoNewPrivileges=yes".to_string(),
        "PrivateTmp=yes".to_string(),
        format!("PrivateDevices={}", private_devices),
        "ProtectSystem=strict".to_string(),
        "ProtectHome=read-only".to_string(),
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

    // 1. If systemd root override is set (or on Linux when writing drop-ins directly), write drop-in files
    if let Some(ref sys_root) = systemd_root_override {
        for raw_unit in &units {
            let norm_unit = normalize_systemd_unit(raw_unit);
            let dropin_dir = Path::new(sys_root).join(format!("{}.d", norm_unit));
            let dropin_aether = dropin_dir.join("aetherflow-sandbox.conf");
            let dropin_10 = dropin_dir.join("10-aetherflow-sandbox.conf");
            if pkg.sandbox_profile == "privileged"
                || pkg.sandbox_profile == "none"
                || is_exempt_sandbox_unit(&norm_unit)
            {
                let _ = fs::remove_file(&dropin_aether);
                let _ = fs::remove_file(&dropin_10);
                continue;
            }
            fs::create_dir_all(&dropin_dir)?;
            let content = render_systemd_sandbox_dropin(
                &pkg.sandbox_profile,
                &norm_unit,
                &pkg.sandbox_read_write,
            );
            fs::write(&dropin_aether, &content)?;
            fs::write(&dropin_10, &content)?;
        }
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

    // 3. Direct drop-in fallback in /etc/systemd/system/<unit>.service.d/aetherflow-sandbox.conf
    let sys_dir = Path::new("/etc/systemd/system");
    if sys_dir.exists() {
        for raw_unit in &units {
            let norm_unit = normalize_systemd_unit(raw_unit);
            let dropin_dir = sys_dir.join(format!("{}.d", norm_unit));
            let dropin_aether = dropin_dir.join("aetherflow-sandbox.conf");
            let dropin_10 = dropin_dir.join("10-aetherflow-sandbox.conf");
            if pkg.sandbox_profile == "privileged"
                || pkg.sandbox_profile == "none"
                || is_exempt_sandbox_unit(&norm_unit)
            {
                let _ = fs::remove_file(&dropin_aether);
                let _ = fs::remove_file(&dropin_10);
                continue;
            }
            if fs::create_dir_all(&dropin_dir).is_ok() {
                let content = render_systemd_sandbox_dropin(
                    &pkg.sandbox_profile,
                    &norm_unit,
                    &pkg.sandbox_read_write,
                );
                let _ = fs::write(&dropin_aether, &content);
                let _ = fs::write(&dropin_10, &content);
            }
        }
        let mut command = Command::new("systemctl");
        command.arg("daemon-reload").kill_on_drop(true);
        #[cfg(unix)]
        guard.preserve_in_child(command.as_std_mut())?;
        let _ = command.output().await;
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
        || domain.chars().any(|c| matches!(c, ' ' | '\t' | '\r' | '\n' | ';' | '"' | '\'' | '$' | '`' | '\\'))
        || domain.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    {
        return Err(RunnerError::InvalidRequest(format!(
            "invalid domain format: {:?}",
            domain
        )));
    }
    Ok(domain.to_string())
}

pub async fn apply_hosts_update(req: HostsUpdateRequest) -> Result<RunnerResponse, RunnerError> {
    let mut domains = req.domains.clone();
    if domains.is_empty() && !req.domain.is_empty() {
        domains.push(req.domain.clone());
    }
    let is_reconcile = req.action.eq_ignore_ascii_case("reconcile");
    let is_remove = req.action.eq_ignore_ascii_case("remove");
    if domains.is_empty() && !is_reconcile {
        return Err(RunnerError::InvalidRequest("no domains specified".to_string()));
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
        let var_lock = Path::new("/var/lock");
        if var_lock.is_dir() {
            var_lock.join("aetherflow-hosts.lock")
        } else {
            let run_lock = Path::new("/run/lock");
            if run_lock.is_dir() {
                run_lock.join("aetherflow-hosts.lock")
            } else {
                hosts_path.with_extension("lock")
            }
        }
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
    if ip.is_empty()
        || ip != ip.trim()
        || ip.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(RunnerError::InvalidRequest(
            "Invalid IP address for hosts modification".into(),
        ));
    }
    ip.parse::<std::net::IpAddr>()
        .map_err(|_| RunnerError::InvalidRequest("Invalid IP address for hosts modification".into()))
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
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|e| anyhow::anyhow!("failed to open hosts lockfile {}: {}", lock_path.display(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(anyhow::anyhow!(
                "failed to acquire exclusive lock on {}: {}",
                lock_path.display(),
                std::io::Error::last_os_error()
            ).into());
        }
    }

    let existing = match fs::read_to_string(hosts_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "failed to read hosts file {}: {}",
                hosts_path.display(),
                e
            ).into());
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
        modify_hosts_file_at_path(hosts_path, lock_path, domains, HostsModifyAction::Update { ip: &canonical_ip })
    }
}

pub fn update_hosts_file_at_path(hosts_path: &Path, domains: &[String], remove: bool) -> anyhow::Result<()> {
    let lock_path = resolve_hosts_lock_path(hosts_path);
    if remove {
        modify_hosts_file_at_path(hosts_path, &lock_path, domains, HostsModifyAction::Remove)?;
    } else {
        let validated_ip = validate_hosts_ip("127.0.0.1")?;
        let canonical_ip = validated_ip.to_string();
        modify_hosts_file_at_path(hosts_path, &lock_path, domains, HostsModifyAction::Update { ip: &canonical_ip })?;
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
    modify_hosts_file_at_path(hosts_path, lock_path, domains, HostsModifyAction::Reconcile { ip: &canonical_ip })
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
    let mut domain_set: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
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
    let dnsmasq_dir = resolve_provider_dir("AETHERFLOW_DNSMASQ_DIR", "/etc/dnsmasq.d");
    if dnsmasq_dir.is_dir() {
        for conf_name in [
            "aetherflow-local-dns.conf",
            "aetherflow.conf",
            "aetherflow-local.conf",
            "05-aetherflow-dns.conf",
        ] {
            let conf_path = dnsmasq_dir.join(conf_name);
            let existing = match fs::read_to_string(&conf_path) {
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
            let payload = render_dnsmasq_content(
                existing.as_deref(),
                &canonical_ip,
                domains,
                is_reconcile,
            );
            write_hosts_file_atomically(&conf_path, &payload)?;
        }
    }

    let pihole_dir = resolve_provider_dir("AETHERFLOW_PIHOLE_DIR", "/etc/pihole");
    if pihole_dir.is_dir() {
        let custom_list = pihole_dir.join("custom.list");
        let existing = match fs::read_to_string(&custom_list) {
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
        let payload = reconcile_pihole_custom_list_content(
            &existing,
            &canonical_ip,
            domains,
            is_reconcile,
        );
        write_hosts_file_atomically(&custom_list, &payload)?;
    }
    Ok(())
}

pub fn remove_dns_provider_files(domains: &[String]) -> anyhow::Result<()> {
    if domains.is_empty() {
        return Ok(());
    }
    let lower_domains: std::collections::HashSet<String> =
        domains.iter().map(|d| d.to_ascii_lowercase()).collect();

    let dnsmasq_dir = resolve_provider_dir("AETHERFLOW_DNSMASQ_DIR", "/etc/dnsmasq.d");
    if dnsmasq_dir.is_dir() {
        for conf_name in [
            "aetherflow-local-dns.conf",
            "aetherflow.conf",
            "aetherflow-local.conf",
            "05-aetherflow-dns.conf",
        ] {
            let conf_path = dnsmasq_dir.join(conf_name);
            match fs::read_to_string(&conf_path) {
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
                    write_hosts_file_atomically(&conf_path, &out_lines.join("\n"))?;
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
    if pihole_dir.is_dir() {
        let custom_list = pihole_dir.join("custom.list");
        match fs::read_to_string(&custom_list) {
            Ok(content) => {
                let payload = remove_pihole_custom_list_content(&content, domains);
                if payload != content {
                    write_hosts_file_atomically(&custom_list, &payload)?;
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
            Ok(format!("reconciled {} domain(s) to {}", domains.len(), canonical_ip))
        }
        "update" | "add" => {
            let validated_ip = validate_hosts_ip(ip)?;
            let canonical_ip = validated_ip.to_string();
            update_hosts_file(domains, &canonical_ip)?;
            sync_dns_provider_files_with_mode(&canonical_ip, domains, false)?;
            Ok(format!("updated {} domain(s) to {}", domains.len(), canonical_ip))
        }
        "remove" => {
            update_hosts_file_local(domains, true)?;
            for d in domains {
                remove_dns_provider_domain(d)?;
            }
            Ok(format!("removed {} domain(s)", domains.len()))
        }
        other => anyhow::bail!("unknown hosts action {:?}, expected reconcile, update, or remove", other),
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
        other => anyhow::bail!("unknown hosts action {:?}, expected reconcile, update, or remove", other),
    }
}

fn write_hosts_file_atomically(hosts_path: &Path, content: &str) -> anyhow::Result<()> {
    let parent = hosts_path.parent().unwrap_or_else(|| Path::new("."));
    let temp_path = parent.join(format!(".hosts.tmp.{}", uuid::Uuid::new_v4()));
    {
        use std::io::Write;
        let mut temp_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o644));
        }
        temp_file.write_all(content.as_bytes())?;
        temp_file.sync_all()?;
    }

    if let Err(err) = fs::rename(&temp_path, hosts_path) {
        #[cfg(unix)]
        let is_cross_device = err.raw_os_error() == Some(libc::EXDEV)
            || err.raw_os_error() == Some(libc::EBUSY);
        #[cfg(not(unix))]
        let is_cross_device = false;

        if is_cross_device {
            use std::io::Write;
            let dest_file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(hosts_path)?;
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = dest_file.as_raw_fd();
                let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
                if rc != 0 {
                    let _ = fs::remove_file(&temp_path);
                    return Err(anyhow::anyhow!(
                        "failed to lock hosts file on cross-device fallback: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            dest_file.set_len(0)?;
            let mut writer = std::io::BufWriter::new(dest_file);
            writer.write_all(content.as_bytes())?;
            writer.flush()?;
            let inner = writer.into_inner()?;
            inner.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = inner.as_raw_fd();
                unsafe { libc::flock(fd, libc::LOCK_UN) };
            }
            let _ = fs::remove_file(&temp_path);
        } else {
            let _ = fs::remove_file(&temp_path);
            return Err(err.into());
        }
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
    if let Some(bin_setdisk) = bin_setdisk_opt.filter(|_| Regex::new(r"(?i)^[0-9]+[MGT]B$").unwrap().is_match(size)) {
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
    command.args(["-u", username, &block_str, &block_str, "0", "0", "-a"]).kill_on_drop(true);
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
// Privileged Application Runtime Metadata Extraction (`app_credentials.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppRuntimeMeta {
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub configured_port: i32,
}

static PLEX_TOKEN_ATTR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\bPlexOnlineToken\s*=\s*"([^"]+)""#).unwrap());
static PHP_ORGANIZR_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)['"]organizrAPI['"]\s*=>\s*['"]([^'"]+)['"]"#).unwrap());

pub fn normalize_runner_app_name(app_name: &str) -> String {
    let clean = app_name
        .trim()
        .to_lowercase()
        .trim_end_matches(".service")
        .to_string();
    match clean.as_str() {
        "plexmediaserver" => "plex".to_string(),
        "emby-server" => "emby".to_string(),
        "pihole-ftl" => "pihole".to_string(),
        "transmission-daemon" => "transmission".to_string(),
        "deluged" | "deluge-web" => "deluge".to_string(),
        "paperless-webserver" | "paperless" => "paperless-ngx".to_string(),
        "qbittorrent-nox" => "qbittorrent".to_string(),
        "calibreweb" => "calibre-web".to_string(),
        "grafana-server" => "grafana".to_string(),
        "uptimekuma" => "uptime-kuma".to_string(),
        "adguard-home" => "adguardhome".to_string(),
        "pyload-ng" => "pyload".to_string(),
        "af-maintainerr" => "maintainerr".to_string(),
        "af-palate" => "palate".to_string(),
        "af-mcvnc" => "mcvnc".to_string(),
        "af-piped" => "piped".to_string(),
        "af-invidious" => "invidious".to_string(),
        "home-assistant@homeassistant" => "homeassistant".to_string(),
        _ => clean,
    }
}

fn resolve_runner_fs_path(raw_path: &str) -> PathBuf {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return PathBuf::new();
    }
    for env_key in ["AETHERFLOW_CONFIG_ROOT", "AETHERFLOW_FS_ROOT"] {
        if let Ok(root) = env::var(env_key) {
            let root_trim = root.trim();
            if !root_trim.is_empty() {
                let rel = trimmed.trim_start_matches(['/', '\\']);
                return Path::new(root_trim).join(rel);
            }
        }
    }
    PathBuf::from(trimmed)
}

fn read_runner_config_text(raw_path: &str) -> Option<String> {
    let resolved = resolve_runner_fs_path(raw_path);
    let meta = fs::metadata(&resolved).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > 2 * 1024 * 1024 {
        return None;
    }
    fs::read_to_string(&resolved).ok()
}

fn parse_valid_runner_port(raw: &str) -> i32 {
    let clean = raw.trim().trim_matches(['"', '\'']);
    if clean.is_empty() {
        return 0;
    }
    match clean.parse::<i32>() {
        Ok(p) if (1..=65535).contains(&p) => p,
        _ => 0,
    }
}

fn parse_pihole_runner_port(raw: &str) -> i32 {
    for part in raw.split(',') {
        let tok = part
            .trim()
            .trim_matches(['"', '\''])
            .trim_end_matches(['o', 'O', 's', 'S']);
        let p = parse_valid_runner_port(tok);
        if p > 0 {
            return p;
        }
    }
    0
}

fn parse_host_port_or_port(raw: &str) -> i32 {
    let clean = raw.trim().trim_matches(['"', '\'']);
    if clean.is_empty() {
        return 0;
    }
    if let Some((_, port_str)) = clean.rsplit_once(':') {
        let p = parse_valid_runner_port(port_str);
        if p > 0 {
            return p;
        }
    }
    parse_valid_runner_port(clean)
}

fn extract_runner_xml_tag(content: &str, tag: &str) -> String {
    if content.is_empty() || tag.is_empty() {
        return String::new();
    }
    let pattern = format!(r"(?is)<{0}>\s*([^<]*?)\s*</{0}>", regex::escape(tag));
    let Ok(re) = Regex::new(&pattern) else {
        return String::new();
    };
    if let Some(caps) = re.captures(content) {
        if let Some(m) = caps.get(1) {
            return m.as_str().trim().to_string();
        }
    }
    String::new()
}

fn extract_runner_ini_value(content: &str, keys: &[&str]) -> String {
    if content.is_empty() || keys.is_empty() {
        return String::new();
    }
    for want_key in keys {
        let want_lower = want_key.trim().to_lowercase();
        for line in content.lines() {
            let mut trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with(';')
                || trimmed.starts_with("//")
                || trimmed.starts_with('[')
            {
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("export ") {
                trimmed = rest.trim();
            }
            let Some(idx) = trimmed.find(['=', ':']) else {
                continue;
            };
            if idx == 0 {
                continue;
            }
            let k = trimmed[..idx].trim().to_lowercase();
            if k != want_lower {
                continue;
            }
            let mut val = trimmed[idx + 1..].trim();
            if !val.starts_with('"') && !val.starts_with('\'') {
                if let Some(hash_idx) = val.find(" #") {
                    val = val[..hash_idx].trim();
                }
            }
            let val = val.trim_matches(['"', '\'']).trim();
            if !val.is_empty() {
                return val.to_string();
            }
        }
    }
    String::new()
}

fn extract_runner_yaml_key_in_section(content: &str, section: &str, key: &str) -> String {
    if content.is_empty() || key.is_empty() {
        return String::new();
    }
    let want_section = section.trim().to_lowercase();
    let want_key = key.trim().to_lowercase();
    let mut in_section = want_section.is_empty();

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let is_indented = raw_line.starts_with(' ') || raw_line.starts_with('\t');
        if !is_indented && trimmed.ends_with(':') {
            let sec_name = trimmed.trim_end_matches(':').trim().to_lowercase();
            if !want_section.is_empty() {
                in_section = sec_name == want_section;
            }
            continue;
        }
        if !in_section {
            continue;
        }
        let Some(idx) = trimmed.find(':') else {
            continue;
        };
        if idx == 0 {
            continue;
        }
        let k = trimmed[..idx].trim().to_lowercase();
        if k != want_key {
            continue;
        }
        let mut val = trimmed[idx + 1..].trim();
        if !val.starts_with('"') && !val.starts_with('\'') {
            if let Some(hash_idx) = val.find(" #") {
                val = val[..hash_idx].trim();
            }
        }
        let val = val.trim_matches(['"', '\'']).trim();
        if !val.is_empty() && val != "null" && val != "~" {
            return val.to_string();
        }
    }
    String::new()
}

fn json_value_to_port(v: &Value) -> i32 {
    match v {
        Value::Number(n) => n
            .as_i64()
            .and_then(|i| i32::try_from(i).ok())
            .filter(|&p| (1..=65535).contains(&p))
            .unwrap_or(0),
        Value::String(s) => parse_valid_runner_port(s),
        _ => 0,
    }
}

fn extract_runner_json_key_and_port(content: &str) -> (String, i32) {
    let mut parsed_obj: Option<serde_json::Map<String, Value>> = None;
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(content) {
        parsed_obj = Some(map);
    } else {
        // Support concatenated JSON objects like Deluge web.conf
        let mut stream = serde_json::Deserializer::from_str(content).into_iter::<Value>();
        if let Some(Ok(Value::Object(first))) = stream.next() {
            if let Some(Ok(Value::Object(second))) = stream.next() {
                parsed_obj = Some(second);
            } else {
                parsed_obj = Some(first);
            }
        }
    }

    let Some(raw) = parsed_obj else {
        return (String::new(), 0);
    };

    let mut api_key = String::new();
    for k in ["APIKey", "ApiKey", "apiKey", "api_key", "apikey", "token"] {
        if let Some(Value::String(s)) = raw.get(k) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                api_key = trimmed.to_string();
                break;
            }
        }
    }

    let mut port = 0;
    for k in ["Port", "port", "rpc-port", "http_port"] {
        if let Some(v) = raw.get(k) {
            let p = json_value_to_port(v);
            if p > 0 {
                port = p;
                break;
            }
        }
    }

    if let Some(Value::Object(main_obj)) = raw.get("main") {
        if api_key.is_empty() {
            for k in ["apiKey", "APIKey", "api_key"] {
                if let Some(Value::String(s)) = main_obj.get(k) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        api_key = trimmed.to_string();
                        break;
                    }
                }
            }
        }
        if port <= 0 {
            for k in ["port", "Port"] {
                if let Some(v) = main_obj.get(k) {
                    let p = json_value_to_port(v);
                    if p > 0 {
                        port = p;
                        break;
                    }
                }
            }
        }
    }

    (api_key, port)
}

fn query_runner_sqlite_single_string(raw_path: &str, queries: &[&str]) -> String {
    let resolved = resolve_runner_fs_path(raw_path);
    let Ok(meta) = fs::metadata(&resolved) else {
        return String::new();
    };
    if !meta.is_file() || meta.len() == 0 {
        return String::new();
    }
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = rusqlite::Connection::open_with_flags(&resolved, flags) else {
        return String::new();
    };
    let _ = conn.busy_timeout(Duration::from_millis(1000));

    for query_sql in queries {
        if let Ok(Some(val)) = conn.query_row(query_sql, [], |row| row.get::<_, Option<String>>(0))
        {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

pub fn extract_app_runtime_meta_local(app_name: &str) -> AppRuntimeMeta {
    let canonical = normalize_runner_app_name(app_name);
    let mut meta = AppRuntimeMeta::default();

    match canonical.as_str() {
        "sonarr" | "radarr" | "lidarr" | "readarr" | "prowlarr" | "whisparr" | "listenarr" => {
            let candidates = [
                format!("/var/lib/{}/config.xml", canonical),
                format!("/var/lib/{}/config/config.xml", canonical),
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = extract_runner_xml_tag(&content, "ApiKey");
                }
                if meta.configured_port <= 0 {
                    meta.configured_port =
                        parse_valid_runner_port(&extract_runner_xml_tag(&content, "Port"));
                }
                if !meta.api_key.is_empty() && meta.configured_port > 0 {
                    break;
                }
            }
        }

        "bazarr" => {
            let yaml_paths = [
                "/var/lib/bazarr/config/config.yaml",
                "/var/lib/bazarr/config.yaml",
                "/opt/bazarr/data/config/config.yaml",
            ];
            for raw_path in &yaml_paths {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = extract_runner_yaml_key_in_section(&content, "auth", "apikey");
                    if meta.api_key.is_empty() {
                        meta.api_key = extract_runner_yaml_key_in_section(&content, "", "apikey");
                    }
                }
                if meta.configured_port <= 0 {
                    meta.configured_port = parse_valid_runner_port(
                        &extract_runner_yaml_key_in_section(&content, "general", "port"),
                    );
                }
            }
            let ini_paths = [
                "/var/lib/bazarr/config/config.ini",
                "/var/lib/bazarr/config.ini",
                "/opt/bazarr/data/config/config.ini",
            ];
            for raw_path in &ini_paths {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = extract_runner_ini_value(&content, &["apikey", "api_key"]);
                }
                if meta.configured_port <= 0 {
                    meta.configured_port =
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]));
                }
            }
        }

        "sabnzbd" => {
            let candidates = [
                "/var/lib/sabnzbd/sabnzbd.ini",
                "/var/lib/sabnzbd/.sabnzbd/sabnzbd.ini",
                "/etc/sabnzbd/sabnzbd.ini",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = extract_runner_ini_value(&content, &["api_key", "nzb_key"]);
                }
                if meta.configured_port <= 0 {
                    meta.configured_port =
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]));
                }
            }
        }

        "tautulli" => {
            let candidates = [
                "/var/lib/tautulli/config.ini",
                "/opt/Tautulli/config.ini",
                "/etc/tautulli/config.ini",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = extract_runner_ini_value(&content, &["api_key"]);
                }
                if meta.configured_port <= 0 {
                    meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["http_port", "port"],
                    ));
                }
            }
        }

        "jackett" => {
            let candidates = [
                "/var/lib/jackett/Jackett/ServerConfig.json",
                "/var/lib/jackett/ServerConfig.json",
                "/var/lib/jackett/.config/Jackett/ServerConfig.json",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                let (key, port) = extract_runner_json_key_and_port(&content);
                if meta.api_key.is_empty() && !key.is_empty() {
                    meta.api_key = key;
                }
                if meta.configured_port <= 0 && port > 0 {
                    meta.configured_port = port;
                }
            }
        }

        "overseerr" | "jellyseerr" => {
            let candidates = [
                format!("/var/lib/{}/settings.json", canonical),
                format!("/var/lib/{}/config/settings.json", canonical),
                format!("/opt/{}/config/settings.json", canonical),
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                let (key, port) = extract_runner_json_key_and_port(&content);
                if meta.api_key.is_empty() && !key.is_empty() {
                    meta.api_key = key;
                }
                if meta.configured_port <= 0 && port > 0 {
                    meta.configured_port = port;
                }
            }
            let env_paths = [
                format!("/etc/{}/{}.conf", canonical, canonical),
                format!("/etc/default/{}", canonical),
            ];
            for raw_path in &env_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if meta.configured_port <= 0 {
                        meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["PORT", "port"],
                        ));
                    }
                }
            }
        }

        "syncthing" => {
            let candidates = [
                "/var/lib/syncthing/config.xml",
                "/var/lib/syncthing/.local/state/syncthing/config.xml",
                "/var/lib/syncthing/.config/syncthing/config.xml",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    meta.api_key = extract_runner_xml_tag(&content, "apikey");
                }
                if meta.configured_port <= 0 {
                    let addr = extract_runner_xml_tag(&content, "address");
                    meta.configured_port = parse_host_port_or_port(&addr);
                }
            }
        }

        "plex" => {
            let candidates = [
                "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml",
                "/var/lib/plex/Plex Media Server/Preferences.xml",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if let Some(caps) = PLEX_TOKEN_ATTR_RE.captures(&content) {
                    if let Some(m) = caps.get(1) {
                        meta.api_key = m.as_str().trim().to_string();
                        break;
                    }
                }
            }
        }

        "jellyfin" => {
            if let Ok(env_key) = env::var("JELLYFIN_API_KEY") {
                if !env_key.trim().is_empty() {
                    meta.api_key = env_key.trim().to_string();
                }
            }
            if meta.api_key.is_empty() {
                let db_paths = [
                    "/var/lib/jellyfin/data/jellyfin.db",
                    "/var/lib/jellyfin/jellyfin.db",
                ];
                for raw_path in &db_paths {
                    let token = query_runner_sqlite_single_string(
                        raw_path,
                        &[
                            "SELECT AccessToken FROM ApiKeys WHERE AccessToken IS NOT NULL AND AccessToken != '' LIMIT 1",
                            "SELECT AccessToken FROM Devices WHERE AccessToken IS NOT NULL AND AccessToken != '' ORDER BY DateLastActivity DESC LIMIT 1",
                        ],
                    );
                    if !token.is_empty() {
                        meta.api_key = token;
                        break;
                    }
                }
            }
            let net_paths = [
                "/etc/jellyfin/network.xml",
                "/var/lib/jellyfin/config/network.xml",
            ];
            for raw_path in &net_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let mut port = parse_valid_runner_port(&extract_runner_xml_tag(
                        &content,
                        "InternalHttpPort",
                    ));
                    if port <= 0 {
                        port = parse_valid_runner_port(&extract_runner_xml_tag(
                            &content,
                            "HttpServerPortNumber",
                        ));
                    }
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "emby" => {
            if let Ok(env_key) = env::var("EMBY_API_KEY") {
                if !env_key.trim().is_empty() {
                    meta.api_key = env_key.trim().to_string();
                }
            }
            if meta.api_key.is_empty() {
                let db_paths = [
                    "/var/lib/emby/data/authentication.db",
                    "/var/lib/emby/data/users.db",
                ];
                for raw_path in &db_paths {
                    let token = query_runner_sqlite_single_string(
                        raw_path,
                        &[
                            "SELECT AccessToken FROM Tokens WHERE AccessToken IS NOT NULL AND AccessToken != '' LIMIT 1",
                            "SELECT AccessToken FROM ApiKeys WHERE AccessToken IS NOT NULL AND AccessToken != '' LIMIT 1",
                        ],
                    );
                    if !token.is_empty() {
                        meta.api_key = token;
                        break;
                    }
                }
            }
            let sys_paths = ["/var/lib/emby/config/system.xml", "/etc/emby/system.xml"];
            for raw_path in &sys_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let mut port = parse_valid_runner_port(&extract_runner_xml_tag(
                        &content,
                        "HttpServerPortNumber",
                    ));
                    if port <= 0 {
                        port = parse_valid_runner_port(&extract_runner_xml_tag(
                            &content,
                            "PublicPort",
                        ));
                    }
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "ombi" => {
            if let Some(content) = read_runner_config_text("/etc/systemd/system/ombi.service") {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            for raw_path in &[
                "/var/lib/ombi/database.json",
                "/etc/Ombi/database.json",
                "/var/lib/ombi/appsettings.json",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (_, port) = extract_runner_json_key_and_port(&content);
                    if port > 0 && meta.configured_port <= 0 {
                        meta.configured_port = port;
                    }
                }
            }
            let db_paths = [
                "/var/lib/ombi/OmbiSettings.db",
                "/etc/Ombi/OmbiSettings.db",
                "/opt/Ombi/OmbiSettings.db",
            ];
            for raw_path in &db_paths {
                let raw_json = query_runner_sqlite_single_string(
                    raw_path,
                    &["SELECT Content FROM GlobalSettings WHERE SettingsName = 'OmbiSettings' LIMIT 1"],
                );
                if !raw_json.is_empty() {
                    let (key, port) = extract_runner_json_key_and_port(&raw_json);
                    if !key.is_empty() {
                        meta.api_key = key;
                    }
                    if port > 0 && meta.configured_port <= 0 {
                        meta.configured_port = port;
                    }
                    if !meta.api_key.is_empty() {
                        break;
                    }
                }
            }
        }

        "autobrr" | "qui" => {
            let toml_paths = [
                format!("/var/lib/{}/config.toml", canonical),
                format!("/var/lib/{}/.config/{}/config.toml", canonical, canonical),
            ];
            for raw_path in &toml_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if meta.configured_port <= 0 {
                        meta.configured_port =
                            parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]));
                    }
                    if meta.api_key.is_empty() {
                        meta.api_key = extract_runner_ini_value(&content, &["api_key", "apikey"]);
                    }
                }
            }
            let db_paths = [
                format!("/var/lib/{}/{}.db", canonical, canonical),
                format!(
                    "/var/lib/{}/.config/{}/{}.db",
                    canonical, canonical, canonical
                ),
            ];
            for raw_path in &db_paths {
                let key = query_runner_sqlite_single_string(
                    raw_path,
                    &["SELECT key FROM api_key WHERE key IS NOT NULL AND key != '' LIMIT 1"],
                );
                if !key.is_empty() {
                    meta.api_key = key;
                    break;
                }
            }
        }

        "kavita" => {
            let json_paths = [
                "/var/lib/kavita/config/appsettings.json",
                "/opt/Kavita/config/appsettings.json",
            ];
            for raw_path in &json_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (_, port) = extract_runner_json_key_and_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
            let db_paths = [
                "/var/lib/kavita/config/kavita.db",
                "/opt/Kavita/config/kavita.db",
            ];
            for raw_path in &db_paths {
                let key = query_runner_sqlite_single_string(
                    raw_path,
                    &["SELECT ApiKey FROM AspNetUsers WHERE ApiKey IS NOT NULL AND ApiKey != '' LIMIT 1"],
                );
                if !key.is_empty() {
                    meta.api_key = key;
                    break;
                }
            }
        }

        "audiobookshelf" => {
            if let Some(content) =
                read_runner_config_text("/etc/systemd/system/audiobookshelf.service")
            {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            let env_paths = [
                "/etc/default/audiobookshelf",
                "/var/lib/audiobookshelf/config.env",
                "/var/lib/audiobookshelf/config/.env",
            ];
            for raw_path in &env_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if meta.configured_port <= 0 {
                        meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["PORT", "port"],
                        ));
                    }
                }
            }
            let db_paths = [
                "/var/lib/audiobookshelf/config/absdatabase.sqlite",
                "/var/lib/audiobookshelf/absdatabase.sqlite",
            ];
            for raw_path in &db_paths {
                let key = query_runner_sqlite_single_string(
                    raw_path,
                    &[
                        "SELECT apiKey FROM apiKeys WHERE apiKey IS NOT NULL AND apiKey != '' LIMIT 1",
                        "SELECT token FROM users WHERE token IS NOT NULL AND token != '' LIMIT 1",
                    ],
                );
                if !key.is_empty() {
                    meta.api_key = key;
                    break;
                }
            }
        }

        "notifiarr" => {
            let candidates = [
                "/etc/notifiarr/notifiarr.conf",
                "/var/lib/notifiarr/notifiarr.conf",
            ];
            for raw_path in &candidates {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                let key = extract_runner_ini_value(&content, &["api_key"]);
                if !key.is_empty()
                    && key != "00000000-0000-0000-0000-000000000000"
                    && !key.eq_ignore_ascii_case("api-key-from-notifiarr.com")
                {
                    meta.api_key = key;
                }
                let bind_addr = extract_runner_ini_value(&content, &["bind_addr"]);
                if !bind_addr.is_empty() {
                    meta.configured_port = parse_host_port_or_port(&bind_addr);
                }
            }
        }

        "vaultwarden" => {
            let token_paths = [
                "/opt/AetherFlow/logs/vaultwarden_admin_token.txt",
                "/etc/vaultwarden/admin_token.txt",
            ];
            for raw_path in &token_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if let Some(first_line) = content.lines().next() {
                        let trimmed = first_line.trim();
                        if !trimmed.is_empty() {
                            meta.api_key = trimmed.to_string();
                            break;
                        }
                    }
                }
            }
            let env_paths = [
                "/etc/vaultwarden/vaultwarden.env",
                "/var/lib/vaultwarden/.env",
            ];
            for raw_path in &env_paths {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if meta.api_key.is_empty() {
                    let token = extract_runner_ini_value(&content, &["ADMIN_TOKEN"]);
                    if !token.is_empty() {
                        meta.api_key = token;
                    }
                }
                if meta.configured_port <= 0 {
                    meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["ROCKET_PORT", "PORT"],
                    ));
                }
            }
        }

        "organizr" => {
            let php_paths = [
                "/var/www/organizr/api/config/config.php",
                "/var/lib/organizr/www/api/config/config.php",
            ];
            for raw_path in &php_paths {
                let Some(content) = read_runner_config_text(raw_path) else {
                    continue;
                };
                if let Some(caps) = PHP_ORGANIZR_KEY_RE.captures(&content) {
                    if let Some(m) = caps.get(1) {
                        meta.api_key = m.as_str().trim().to_string();
                        break;
                    }
                }
            }
        }

        "pihole" => {
            if let Some(content) = read_runner_config_text("/etc/pihole/setupVars.conf") {
                meta.api_key = extract_runner_ini_value(&content, &["WEBPASSWORD"]);
            }
            if let Some(content) = read_runner_config_text("/etc/pihole/pihole.toml") {
                let port_val = extract_runner_ini_value(&content, &["port", "webserver.port"]);
                if !port_val.is_empty() {
                    meta.configured_port = parse_pihole_runner_port(&port_val);
                }
            }
        }

        "dispatcharr" => {
            if let Some(content) = read_runner_config_text("/etc/dispatcharr/dispatcharr.env") {
                meta.configured_port = dispatcharr_runtime_port(&content);
            }
        }

        "paperless-ngx" => {
            let conf_paths = [
                "/etc/paperless.conf",
                "/opt/paperless/paperless.conf",
                "/var/lib/paperless/paperless.conf",
            ];
            for raw_path in &conf_paths {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if meta.configured_port <= 0 {
                        meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["PAPERLESS_PORT", "PORT"],
                        ));
                    }
                }
            }
            let db_paths = [
                "/var/lib/paperless/db.sqlite3",
                "/opt/paperless/data/db.sqlite3",
            ];
            for raw_path in &db_paths {
                let key = query_runner_sqlite_single_string(
                    raw_path,
                    &["SELECT key FROM authtoken_token WHERE key IS NOT NULL AND key != '' LIMIT 1"],
                );
                if !key.is_empty() {
                    meta.api_key = key;
                    break;
                }
            }
        }

        "requestrr" => {
            let candidates = [
                "/var/lib/requestrr/config/settings.json",
                "/opt/requestrr/config/settings.json",
                "/var/lib/requestrr/settings.json",
                "/opt/requestrr/settings.json",
                "/opt/requestrr/Settings/settings.json",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (key, port) = extract_runner_json_key_and_port(&content);
                    if meta.api_key.is_empty() && !key.is_empty() {
                        meta.api_key = key;
                    }
                    if meta.configured_port <= 0 && port > 0 {
                        meta.configured_port = port;
                    }
                }
            }
        }

        "seedcross" => {
            for raw_path in &[
                "/opt/seedcross/start-seedcross.sh",
                "/etc/systemd/system/seedcross.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
            let candidates = [
                "/var/lib/seedcross/.env",
                "/opt/seedcross/.env",
                "/etc/seedcross/seedcross.env",
                "/etc/seedcross/config.json",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (json_key, json_port) = extract_runner_json_key_and_port(&content);
                    if meta.api_key.is_empty() && !json_key.is_empty() {
                        meta.api_key = json_key;
                    }
                    if meta.configured_port <= 0 && json_port > 0 {
                        meta.configured_port = json_port;
                    }
                    if meta.api_key.is_empty() {
                        meta.api_key = extract_runner_ini_value(
                            &content,
                            &["API_KEY", "SEEDCROSS_API_KEY", "AUTH_TOKEN"],
                        );
                    }
                    if meta.configured_port <= 0 {
                        meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["PORT", "SEEDCROSS_PORT"],
                        ));
                    }
                }
            }
        }

        "qbittorrent" => {
            let candidates = [
                "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
                "/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &[r"WebUI\Port", "Port"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "deluge" => {
            if let Some(content) =
                read_runner_config_text("/var/lib/deluge/.config/deluge/web.conf")
            {
                let (_, port) = extract_runner_json_key_and_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
        }

        "transmission" => {
            let candidates = [
                "/etc/transmission-daemon/settings.json",
                "/var/lib/transmission-daemon/info/settings.json",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (_, port) = extract_runner_json_key_and_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "nzbget" => {
            let candidates = [
                "/var/lib/nzbget/nzbget.conf",
                "/etc/nzbget.conf",
                "/opt/nzbget/nzbget.conf",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["ControlPort"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "gitea" => {
            let candidates = ["/etc/gitea/app.ini", "/var/lib/gitea/custom/conf/app.ini"];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["HTTP_PORT"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "znc" => {
            let candidates = [
                "/var/lib/znc/configs/znc.conf",
                "/var/lib/znc/.znc/configs/znc.conf",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port =
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["Port"]));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "thelounge" => {
            let candidates = ["/var/lib/thelounge/config.js", "/etc/thelounge/config.js"];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(
                        extract_runner_ini_value(&content, &["port"]).trim_end_matches(','),
                    );
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "filebrowser" => {
            if let Some(content) =
                read_runner_config_text("/etc/systemd/system/filebrowser.service")
            {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            if meta.configured_port <= 0 {
                let candidates = [
                    "/etc/filebrowser/filebrowser.json",
                    "/etc/filebrowser/config.json",
                    "/var/lib/filebrowser/filebrowser.json",
                    "/var/lib/filebrowser/.filebrowser.json",
                    "/etc/filebrowser/.filebrowser.json",
                    "/opt/filebrowser/filebrowser.json",
                ];
                for raw_path in &candidates {
                    if let Some(content) = read_runner_config_text(raw_path) {
                        let (_, port) = extract_runner_json_key_and_port(&content);
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }

        "navidrome" => {
            let candidates = [
                "/var/lib/navidrome/navidrome.toml",
                "/etc/navidrome/navidrome.toml",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["Port", "port"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "komga" => {
            let candidates = [
                "/var/lib/komga/application.yml",
                "/etc/komga/application.yml",
                "/etc/default/komga",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let mut port = parse_valid_runner_port(&extract_runner_yaml_key_in_section(
                        &content, "server", "port",
                    ));
                    if port <= 0 {
                        port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["SERVER_PORT", "PORT", "port"],
                        ));
                    }
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "calibre-web" | "calibreweb" => {
            let db_paths = ["/var/lib/calibre-web/app.db", "/opt/calibre-web/app.db"];
            for raw_path in &db_paths {
                let port_str = query_runner_sqlite_single_string(
                    raw_path,
                    &["SELECT CAST(config_port AS TEXT) FROM settings LIMIT 1"],
                );
                let port = parse_valid_runner_port(&port_str);
                if port > 0 {
                    meta.configured_port = port;
                    break;
                }
            }
        }

        "grafana" => {
            let candidates = ["/etc/grafana/grafana.ini", "/var/lib/grafana/grafana.ini"];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["http_port", "port"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "prometheus" => {
            let candidates = [
                "/etc/systemd/system/prometheus.service",
                "/etc/default/prometheus",
                "/etc/sysconfig/prometheus",
                "/etc/prometheus/prometheus.yml",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["PORT", "port"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "uptime-kuma" => {
            if let Some(content) = read_runner_config_text("/etc/systemd/system/uptime-kuma.service") {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            if meta.configured_port <= 0 {
                let candidates = [
                    "/var/lib/uptime-kuma/.env",
                    "/opt/uptime-kuma/.env",
                    "/etc/default/uptime-kuma",
                ];
                for raw_path in &candidates {
                    if let Some(content) = read_runner_config_text(raw_path) {
                        let port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["UPTIME_KUMA_PORT", "PORT", "port"],
                        ));
                        if port > 0 {
                            meta.configured_port = port;
                            break;
                        }
                    }
                }
            }
        }

        "immich" => {
            let candidates = [
                "/var/lib/immich/.env",
                "/opt/immich/.env",
                "/etc/immich/immich.env",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if meta.api_key.is_empty() {
                        meta.api_key =
                            extract_runner_ini_value(&content, &["IMMICH_API_KEY", "API_KEY"]);
                    }
                    if meta.configured_port <= 0 {
                        meta.configured_port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["IMMICH_PORT", "SERVER_PORT", "PORT"],
                        ));
                    }
                }
            }
        }

        "maintainerr" => {
            for raw_path in &[
                "/etc/systemd/system/af-maintainerr.service",
                "/etc/systemd/system/maintainerr.service",
                "/var/lib/maintainerr/.env",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content).max(
                        parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["UI_PORT", "PORT"],
                        )),
                    );
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "flaresolverr" => {
            for raw_path in &[
                "/etc/systemd/system/flaresolverr.service",
                "/opt/flaresolverr/.env",
                "/etc/default/flaresolverr",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content).max(
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["PORT"])),
                    );
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "threadfin" => {
            if let Some(content) = read_runner_config_text("/etc/systemd/system/threadfin.service")
            {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
            if meta.configured_port <= 0 {
                if let Some(content) =
                    read_runner_config_text("/var/lib/threadfin/conf/settings.json")
                {
                    let (_, port) = extract_runner_json_key_and_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                    }
                }
            }
        }

        "flood" => {
            for raw_path in &["/etc/systemd/system/flood.service", "/etc/default/flood"] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "nextcloud" | "rutorrent" => {
            for raw_path in &[
                format!("/etc/apache2/conf-available/aetherflow-{canonical}-listen.conf"),
                format!("/etc/apache2/sites-available/{canonical}.conf"),
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "netdata" => {
            for raw_path in &[
                "/etc/netdata/netdata.conf",
                "/etc/systemd/system/netdata.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["default port", "port"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "homeassistant" => {
            for raw_path in &[
                "/home/homeassistant/.homeassistant/configuration.yaml",
                "/var/lib/homeassistant/configuration.yaml",
                "/etc/homeassistant/configuration.yaml",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let mut port = parse_valid_runner_port(&extract_runner_yaml_key_in_section(
                        &content,
                        "http",
                        "server_port",
                    ));
                    if port <= 0 {
                        port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["server_port"],
                        ));
                    }
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "adguardhome" => {
            for raw_path in &[
                "/opt/AdGuardHome/AdGuardHome.yaml",
                "/etc/AdGuardHome/AdGuardHome.yaml",
                "/var/lib/AdGuardHome/AdGuardHome.yaml",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let addr = extract_runner_yaml_key_in_section(&content, "http", "address");
                    let mut port = parse_host_port_or_port(&addr);
                    if port <= 0 {
                        port = parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["bind_port"],
                        ));
                    }
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "rclone" => {
            for raw_path in &[
                "/etc/systemd/system/rclone.service",
                "/etc/rclone/rclone.env",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content).max(
                        parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["RCLONE_PORT", "PORT"],
                        )),
                    );
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "autoscan" => {
            for raw_path in &["/etc/autoscan/config.yml", "/var/lib/autoscan/config.yml"] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "librespeed" => {
            for raw_path in &["/opt/librespeed/settings.toml", "/etc/librespeed/settings.toml"] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["listen_port", "port"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "scrutiny" => {
            for raw_path in &[
                "/etc/scrutiny/scrutiny.yaml",
                "/opt/scrutiny/config/scrutiny.yaml",
                "/etc/systemd/system/scrutiny.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]))
                        .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "n8n" => {
            for raw_path in &[
                "/etc/systemd/system/n8n.service",
                "/var/lib/n8n/.env",
                "/etc/n8n/n8n.env",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content).max(
                        parse_valid_runner_port(&extract_runner_ini_value(
                            &content,
                            &["N8N_PORT", "PORT"],
                        )),
                    );
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "palate" => {
            for raw_path in &[
                "/etc/palate/palate.env",
                "/etc/systemd/system/af-palate.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["PORT", "PALATE_PORT"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "duplicati" => {
            for raw_path in &[
                "/etc/duplicati/duplicati.env",
                "/etc/default/duplicati",
                "/etc/systemd/system/duplicati.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["DUPLICATI_PORT", "PORT"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "filebot" => {
            for raw_path in &[
                "/var/lib/filebot/filebot-node.env",
                "/etc/default/filebot",
                "/etc/systemd/system/filebot.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["FILEBOT_NODE_HTTP_PORT", "PORT"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "novnc" => {
            if let Some(content) = read_runner_config_text("/etc/systemd/system/novnc.service") {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                }
            }
        }

        "kasmvnc" => {
            for raw_path in &[
                "/var/lib/kasmvnc/.vnc/kasmvnc.yaml",
                "/etc/kasmvnc/kasmvnc.yaml",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["websocket_port", "port"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "mcvnc" => {
            for raw_path in &[
                "/etc/mcvnc/mcvnc.env",
                "/etc/systemd/system/af-mcvnc.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_host_port_or_port(&extract_runner_ini_value(
                        &content,
                        &["MCVNC_BIND", "MCVNC_PORT", "PORT"],
                    ))
                    .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "pyload" => {
            for raw_path in &[
                "/var/lib/pyload/settings/pyload.cfg",
                "/var/lib/pyload/.pyload/settings/pyload.cfg",
                "/etc/systemd/system/pyload.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let raw_val = extract_runner_ini_value(&content, &["int port", "port"]);
                    let rhs = raw_val.rsplit('=').next().unwrap_or(&raw_val).trim();
                    let port = parse_valid_runner_port(rhs)
                        .max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "unmanic" => {
            for raw_path in &[
                "/var/lib/unmanic/.unmanic/config/settings.json",
                "/etc/systemd/system/unmanic.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let (_, json_port) = extract_runner_json_key_and_port(&content);
                    let port = json_port.max(extract_runner_systemd_or_apache_port(&content));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "piped" => {
            for raw_path in &[
                "/etc/piped/httpd.conf",
                "/etc/af-piped/httpd.conf",
                "/etc/systemd/system/af-piped.service",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = extract_runner_systemd_or_apache_port(&content);
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "invidious" => {
            for raw_path in &[
                "/etc/invidious/config.yml",
                "/etc/af-invidious/config.yml",
                "/var/lib/invidious/config/config.yml",
            ] {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(&content, &["port"]));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        _ => {}
    }

    if meta.configured_port <= 0 {
        let mut fallback_candidates = vec![
            format!("/etc/systemd/system/{canonical}.service"),
            format!("/etc/systemd/system/af-{canonical}.service"),
            format!("/etc/apache2/conf-available/aetherflow-{canonical}-listen.conf"),
            format!("/etc/apache2/sites-available/{canonical}.conf"),
            format!("/etc/apache2/sites-available/aetherflow-app-{canonical}.conf"),
        ];
        if canonical == "uptime-kuma" {
            fallback_candidates.push("/etc/systemd/system/uptimekuma.service".to_string());
            fallback_candidates
                .push("/etc/apache2/sites-available/aetherflow-app-uptimekuma.conf".to_string());
        } else if canonical == "calibre-web" {
            fallback_candidates.push("/etc/systemd/system/calibreweb.service".to_string());
            fallback_candidates
                .push("/etc/apache2/sites-available/aetherflow-app-calibreweb.conf".to_string());
        }
        for raw_path in &fallback_candidates {
            if let Some(content) = read_runner_config_text(raw_path) {
                let port = extract_runner_systemd_or_apache_port(&content);
                if port > 0 {
                    meta.configured_port = port;
                    break;
                }
            }
        }
    }

    meta
}

fn extract_runner_systemd_or_apache_port(text: &str) -> i32 {
    static ENV_PORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^\s*(?:Environment\s*=\s*["']?|export\s+)?(?:[A-Z0-9_]*_PORT|PORT)\s*=\s*["']?([0-9]{2,5})\b"#,
        )
        .unwrap()
    });
    static ENV_BIND_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^\s*(?:Environment\s*=\s*["']?|export\s+)?(?:[A-Z0-9_]*_BIND|ASPNETCORE_URLS)\s*=\s*["']?(?:https?://)?[^:\s"']+:([0-9]{2,5})\b"#,
        )
        .unwrap()
    });
    static CLI_PORT_FLAG_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)(?:--(?:webservice-)?port|-port|-p)(?:\s+|=)["']?([0-9]{2,5})\b"#,
        )
        .unwrap()
    });
    static CLI_ADDR_FLAG_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)(?:--(?:web\.listen-address|rc-addr|bind|host|listen)|websockify[^\n]*?)(?:\s+|=)["']?(?:https?://)?(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\*)?:([0-9]{2,5})\b"#,
        )
        .unwrap()
    });
    static APACHE_LISTEN_VHOST_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)(?:^\s*Listen\s+(?:[0-9.]+:)?([0-9]{2,5})\b|<VirtualHost\s+[^>:]+:([0-9]{2,5})>|ProxyPass\s+/[^\s]*\s+(?:http|ws)s?://(?:127\.0\.0\.1|localhost):([0-9]{2,5})\b)"#,
        )
        .unwrap()
    });

    for re in [
        &*ENV_PORT_RE,
        &*ENV_BIND_RE,
        &*CLI_PORT_FLAG_RE,
        &*CLI_ADDR_FLAG_RE,
    ] {
        if let Some(caps) = re.captures(text) {
            if let Some(m) = caps.get(1) {
                let p = parse_valid_runner_port(m.as_str());
                if p > 0 {
                    return p;
                }
            }
        }
    }
    if let Some(caps) = APACHE_LISTEN_VHOST_RE.captures(text) {
        for idx in [1, 2, 3] {
            if let Some(m) = caps.get(idx) {
                let p = parse_valid_runner_port(m.as_str());
                if p > 0 {
                    return p;
                }
            }
        }
    }
    0
}

fn dispatcharr_runtime_port(content: &str) -> i32 {
    parse_valid_runner_port(&extract_runner_ini_value(content, &["DISPATCHARR_PORT"]))
}

const DISPATCHARR_ADMIN_SCRIPT: &str = r#"import os
from django.contrib.auth import get_user_model
from django.db import transaction

with transaction.atomic():
    user, _ = get_user_model().objects.get_or_create(username=os.environ["AF_ADMIN_USER"])
    user.email = os.environ["AF_ADMIN_EMAIL"]
    user.user_level = 10
    user.is_staff = True
    user.is_superuser = True
    user.is_active = True
    user.set_password(os.environ["AF_ADMIN_PASS"])
    user.save()
"#;

#[derive(Deserialize)]
struct DispatcharrCredentialsRequest {
    username: String,
    password: String,
}

fn dispatcharr_credentials_command(username: &str, password: &str) -> Command {
    let mut command = Command::new("runuser");
    command
        .args([
            "-u", "dispatcharr", "--", "/bin/bash", "-ec",
            "set -a; source /etc/dispatcharr/dispatcharr.env; set +a; cd /opt/dispatcharr; exec /opt/dispatcharr/env/bin/python manage.py shell",
        ])
        .env("AF_ADMIN_USER", username)
        .env("AF_ADMIN_PASS", password)
        .env("AF_ADMIN_EMAIL", format!("{}@localhost", username))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    command
}

async fn handle_dispatcharr_credentials(
    Json(req): Json<DispatcharrCredentialsRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let username = req.username.trim();
    if username.is_empty()
        || req.password.is_empty()
        || username.len() > 256
        || req.password.len() > 4096
        || username.contains('\0')
        || req.password.contains('\0')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid Dispatcharr credentials".to_string(),
            }),
        );
    }
    if !Path::new("/opt/dispatcharr/manage.py").is_file() {
        return (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: "Dispatcharr is not installed".to_string(),
                error: String::new(),
            }),
        );
    }
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        use tokio::io::AsyncWriteExt;
        let mut child = dispatcharr_credentials_command(username, &req.password).spawn()?;
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("missing stdin"))?;
        input.write_all(DISPATCHARR_ADMIN_SCRIPT.as_bytes()).await?;
        drop(input);
        child.wait().await
    })
    .await;
    let success = matches!(result, Ok(Ok(status)) if status.success());
    (
        if success {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        },
        Json(RunnerResponse {
            success,
            output: String::new(),
            error: if success {
                String::new()
            } else {
                "Dispatcharr credential sync failed".to_string()
            },
        }),
    )
}

async fn handle_app_meta(
    Json(req): Json<AppMetaRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !SAFE_SCRIPT_NAME.is_match(&req.app_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid application identifier".to_string(),
            }),
        );
    }
    let meta = extract_app_runtime_meta_local(&req.app_name);
    let output = serde_json::to_string(&json!({
        "api_key": meta.api_key,
        "configured_port": meta.configured_port,
    }))
    .unwrap_or_else(|_| "{\"api_key\":\"\",\"configured_port\":0}".to_string());

    (
        StatusCode::OK,
        Json(RunnerResponse {
            success: true,
            output,
            error: String::new(),
        }),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// UNIX Domain Socket Client Dispatchers (`backend/services/privileged_runner.go`)
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
            .uri(format!("http://unix{}", endpoint))
            .header("Host", "unix")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))?;

        let resp = sender.send_request(req).await?;
        if endpoint == "/v1/systemctl" && resp.status() == StatusCode::CONFLICT {
            return Err(LifecycleBusy.into());
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

pub async fn fetch_self_update_status() -> anyhow::Result<self_update::UpdateStatus> {
    let result =
        post_runner_json("/v1/self-update/status", &json!({}), Duration::from_secs(5)).await?;
    if !result.success {
        anyhow::bail!("updater status unavailable: {}", result.error);
    }
    Ok(serde_json::from_str(&result.output)?)
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
    let result = post_runner_json("/v1/hosts", req, Duration::from_secs(15)).await?;
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
    let meta: AppRuntimeMeta = serde_json::from_str(&result.output)?;
    Ok(meta)
}

/// Authorizes a UNIX domain socket peer (`SO_PEERCRED` / `UCred`) connecting to the privileged runner.
///
/// Permits:
/// - `uid == 0` (root)
/// - `uid == euid` (same effective user running the runner process)
/// - the `aetherflow` service user UID resolved via `getpwnam` on Unix
/// - any explicit UID listed in `AETHERFLOW_ALLOWED_RUNNER_UIDS` (comma-separated)
///
/// Furthermore, destructive endpoints (`/v1/self-update`, `/v1/backup` with `restore_execute` or `delete`)
/// require either `uid == 0`, `uid == euid`, the `aetherflow` service account, or an explicitly authorized UID.
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
        if let Ok(c_name) = std::ffi::CString::new("aetherflow") {
            let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
            if !pw.is_null() {
                let af_uid = unsafe { (*pw).pw_uid as u32 };
                if peer_uid == af_uid {
                    return Ok(());
                }
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
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use tower::Service;
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
                let (peer_uid, peer_gid) = match stream.peer_cred() {
                    Ok(cred) => (cred.uid(), cred.gid()),
                    Err(err) => {
                        tracing::warn!(error = %err, "Rejecting runner connection without SO_PEERCRED");
                        continue;
                    }
                };
                if let Err((_, reason)) = authorize_runner_peer_credentials(peer_uid, peer_gid, "/v1/*") {
                    tracing::warn!(peer_uid, peer_gid, %reason, "Rejected unauthorized UNIX socket peer");
                    continue;
                }
                let io = TokioIo::new(stream);
                let tower_service = app.clone();
                let mut drain_rx = drain_rx.clone();
                connections.spawn(async move {
                    let hyper_service = hyper::service::service_fn(
                        move |request: hyper::Request<hyper::body::Incoming>| {
                            let req_path = request.uri().path().to_string();
                            let auth_res = authorize_runner_peer_credentials(peer_uid, peer_gid, &req_path);
                            let mut svc = tower_service.clone();
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
                                svc.call(request.map(axum::body::Body::new)).await
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
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_signal_handles_sigint_and_sigterm_in_isolated_processes() {
        const ENV: &str = "AETHERFLOW_SHUTDOWN_TEST_SIGNAL";
        if let Ok(number) = env::var(ENV) {
            let signal = shutdown_signal().unwrap();
            let number = number.parse::<i32>().unwrap();
            assert_eq!(unsafe { libc::kill(std::process::id() as i32, number) }, 0);
            tokio::time::timeout(Duration::from_secs(2), signal)
                .await
                .unwrap();
            return;
        }
        for signal in [libc::SIGINT, libc::SIGTERM] {
            let status = std::process::Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::shutdown_signal_handles_sigint_and_sigterm_in_isolated_processes",
                    "--nocapture",
                ])
                .env(ENV, signal.to_string())
                .status()
                .unwrap();
            assert!(
                status.success(),
                "Signal {signal} must complete the graceful-shutdown future"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_shutdown_drains_inflight_response_before_exiting() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir_name = format!("ad-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let base = env::var_os("TMPDIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        let candidate = base.join(&dir_name);
        let root = if candidate.join("runner.sock").as_os_str().len() < 95 {
            candidate
        } else {
            PathBuf::from("/tmp").join(dir_name)
        };
        fs::create_dir(&root).unwrap();
        let path = root.join("runner.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        // Test auth in a child so process-global peer settings cannot affect other tests.
        const ENV: &str = "AETHERFLOW_RUNNER_DRAIN_TEST";
        if env::var_os(ENV).is_none() {
            drop(listener);
            fs::remove_dir_all(root).unwrap();
            let status = std::process::Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::runner_shutdown_drains_inflight_response_before_exiting",
                    "--nocapture",
                ])
                .env(ENV, "1")
                .env(
                    "AETHERFLOW_ALLOWED_RUNNER_UIDS",
                    unsafe { libc::geteuid() }.to_string(),
                )
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let enter_handler = entered.clone();
        let release_handler = release.clone();
        let app = Router::new().route(
            "/v1/drain-test",
            axum::routing::get(move || {
                let entered = enter_handler.clone();
                let release = release_handler.clone();
                async move {
                    entered.notify_one();
                    release.notified().await;
                    "completed-before-exit"
                }
            }),
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_runner_connections(listener, app, async {
            let _ = shutdown_rx.await;
        }));
        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        stream
            .write_all(b"GET /v1/drain-test HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        shutdown_tx.send(()).unwrap();
        tokio::task::yield_now().await;
        assert!(
            !server.is_finished(),
            "Active request must keep runner alive during drain"
        );
        release.notify_one();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.contains("completed-before-exit"));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_package_script_resolution_prefers_current_release() {
        let defaults = package_script_roots();
        assert_eq!(
            defaults[0],
            PathBuf::from("/opt/AetherFlow/current/packages/package")
        );
        assert_eq!(
            defaults[1],
            PathBuf::from("/opt/AetherFlow/packages/package")
        );
        assert_eq!(
            defaults[2],
            PathBuf::from("/usr/local/bin/AetherFlow/package")
        );

        let scratch = env::temp_dir().join(format!("af-script-paths-{}", uuid::Uuid::new_v4()));
        let roots: Vec<_> = defaults[..3]
            .iter()
            .map(|root| scratch.join(root.strip_prefix("/").unwrap()))
            .collect();
        for root in &roots {
            fs::create_dir_all(root.join("install")).unwrap();
            fs::create_dir_all(root.join("update")).unwrap();
            fs::create_dir_all(root.join("remove")).unwrap();
            fs::write(root.join("install/installpackage-dispatcharr"), "release").unwrap();
            fs::write(root.join("remove/removepackage-dispatcharr"), "remove").unwrap();
        }
        // A stale dedicated updater must not override the current installer.
        fs::write(roots[1].join("update/updatepackage-dispatcharr"), "stale").unwrap();
        for name in ["installpackage-dispatcharr", "updatepackage-dispatcharr"] {
            assert_eq!(
                resolve_package_script_in_roots("update", name, &roots),
                Some(roots[0].join("install/installpackage-dispatcharr"))
            );
        }
        for action in ["remove", "uninstall"] {
            assert_eq!(
                resolve_package_script_in_roots(action, "removepackage-dispatcharr", &roots),
                Some(roots[0].join("remove/removepackage-dispatcharr"))
            );
        }
        fs::write(roots[0].join("update/updatepackage-dispatcharr"), "current").unwrap();
        assert_eq!(
            resolve_package_script_in_roots("update", "installpackage-dispatcharr", &roots),
            Some(roots[0].join("update/updatepackage-dispatcharr"))
        );
        fs::remove_file(roots[0].join("install/installpackage-dispatcharr")).unwrap();
        assert_eq!(
            resolve_package_script_in_roots("install", "installpackage-dispatcharr", &roots),
            Some(roots[1].join("install/installpackage-dispatcharr"))
        );
        fs::remove_file(roots[1].join("install/installpackage-dispatcharr")).unwrap();
        assert_eq!(
            resolve_package_script_in_roots("install", "installpackage-dispatcharr", &roots),
            Some(roots[2].join("install/installpackage-dispatcharr"))
        );
        assert!(resolve_package_script_in_roots("install", "../dispatcharr", &roots).is_none());
        assert!(
            resolve_package_script_in_roots("invalid", "installpackage-dispatcharr", &roots)
                .is_none()
        );
        fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn test_core_restart_is_independent_and_restricted() {
        let args = deferred_restart_arguments("aetherflow-api.service").unwrap();
        assert!(args.contains(&"--on-active=2s".to_string()));
        assert!(args[0].starts_with("--unit=aetherflow-self-update-restart-"));
        assert_eq!(args.last().unwrap(), "aetherflow-api");
        assert!(args
            .iter()
            .any(|arg| arg == include_str!("core_restart_worker.sh")));
        assert!(deferred_restart_arguments("sonarr").is_err());
        assert!(deferred_restart_arguments("../aetherflow-api").is_err());
    }

    #[tokio::test]
    async fn test_heal_restart_skips_active_package_operation() {
        let _operation = PACKAGE_MUTEX.lock().await;
        let (status, Json(response)) = handle_systemctl(Json(SystemctlRequest {
            service: "gitea".into(),
            action: "heal".into(),
            lifecycle_job_id: String::new(),
        }))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(response.success);
        assert_eq!(response.output, "skipped");
        let (status, Json(response)) = handle_systemctl(Json(SystemctlRequest {
            service: "gitea".into(),
            action: "restart".into(),
            lifecycle_job_id: String::new(),
        }))
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(!response.success);
    }

    #[test]
    fn test_package_output_propagates_failure_markers() {
        let mut lines = Vec::new();
        let result = consume_package_output(
            "installing\n__RUNNER_EXIT_ERROR__:exit status 7\nlast log\n",
            |line| lines.push(line),
        );
        assert!(result.unwrap_err().to_string().contains("exit status 7"));
        assert_eq!(lines, vec!["installing", "last log"]);
        assert!(consume_package_output("__RUNNER_EXIT_ERROR__:\n", |_| {}).is_err());
    }

    #[test]
    fn test_package_output_accepts_success_logs() {
        let mut lines = Vec::new();
        consume_package_output("\nready\n\ncomplete\n", |line| lines.push(line)).unwrap();
        assert_eq!(lines, vec!["ready", "complete"]);
    }

    #[test]
    fn test_incremental_decoder_handles_split_chunks_and_overlong_lines() {
        let mut lines = Vec::new();
        let mut decoder = IncrementalPackageLineDecoder::default();
        decoder.push_bytes(b"[PROGRESS:20] Part ", &mut |l| lines.push(l));
        assert!(lines.is_empty());
        decoder.push_bytes(b"one\nSecond ", &mut |l| lines.push(l));
        assert_eq!(lines, vec!["[PROGRESS:20] Part one"]);

        // Feed an overlong line (> MAX_PACKAGE_STREAM_LINE_BYTES) and ensure memory stays bounded
        let huge = vec![b'x'; MAX_PACKAGE_STREAM_LINE_BYTES + 8192];
        decoder.push_bytes(&huge, &mut |l| lines.push(l));
        assert!(decoder.pending.len() <= MAX_PACKAGE_STREAM_LINE_BYTES);
        decoder.push_bytes(b"\n[PROGRESS:100] Done\n", &mut |l| lines.push(l));
        decoder.finish(&mut |l| lines.push(l)).unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2], "[PROGRESS:100] Done");
    }

    #[test]
    fn test_regex_allowlists() {
        assert!(SAFE_SCRIPT_NAME.is_match("installpackage-jellyfin"));
        assert!(!SAFE_SCRIPT_NAME.is_match("../etc/passwd"));
        assert!(SAFE_PKG_ID.is_match("sonarr"));
        assert!(!SAFE_PKG_ID.is_match("../sonarr"));
        assert!(SAFE_USERNAME.is_match("alice_01"));
        assert!(!SAFE_USERNAME.is_match("1invalid;rm"));
        assert!(SAFE_QUOTA_SIZE.is_match("500G"));
        assert!(SAFE_QUOTA_SIZE.is_match("500GB"));
        assert!(SAFE_QUOTA_SIZE.is_match("1073741824"));
        assert!(SAFE_QUOTA_SIZE_REGEX.is_match("500G"));
        assert!(SAFE_QUOTA_SIZE_REGEX.is_match("0"));
        assert!(!SAFE_QUOTA_SIZE_REGEX.is_match("500G; rm -rf /"));
    }

    #[test]
    fn test_render_systemd_sandbox_dropin() {
        let dropin = render_systemd_sandbox_dropin(
            "dotnet",
            "sonarr",
            &["/var/lib/sonarr".to_string(), "-/mnt".to_string()],
        );
        assert!(dropin.contains("NoNewPrivileges=yes"));
        assert!(dropin.contains("PrivateTmp=yes"));
        assert!(dropin.contains("ProtectSystem=strict"));
        assert!(!dropin.contains("MemoryDenyWriteExecute=yes"));
        assert!(dropin.contains("ReadWritePaths="));

        let native_dropin = render_systemd_sandbox_dropin("native", "plexmediaserver", &[]);
        assert!(native_dropin.contains("PrivateDevices=no"));
        assert!(native_dropin.contains("MemoryDenyWriteExecute=yes"));
    }

    #[test]
    fn test_sandbox_master_credentials_formats() {
        assert_eq!(
            sandbox_master_user(r#"{"username":"media_owner","password":"secret"}"#),
            Some("media_owner".into())
        );
        assert_eq!(
            sandbox_master_user("username=media_owner\r\npassword=secret"),
            Some("media_owner".into())
        );
        assert_eq!(
            sandbox_master_user("media_owner:secret\n"),
            Some("media_owner".into())
        );
        assert_eq!(sandbox_master_user("username=../../etc"), None);
        assert_eq!(sandbox_master_user("password=secret"), None);
        assert_eq!(sandbox_master_user(""), None);
    }

    #[test]
    fn test_sandbox_paths_use_distinct_service_and_master_identities() {
        assert_eq!(
            expand_sandbox_path(
                "-/home/{{MASTER_USER}}/Google/Media/Music Import",
                "sonarr",
                "/var/lib/sonarr",
                "media_owner"
            ),
            "\"-/home/media_owner/Google/Media/Music Import\""
        );
        assert_eq!(
            expand_sandbox_path(
                "-{{SERVICE_HOME}}/{{SERVICE_USER}}",
                "sonarr",
                "/var/lib/sonarr",
                "media_owner"
            ),
            "-/var/lib/sonarr/sonarr"
        );
    }

    #[tokio::test]
    async fn test_handle_sandbox_and_quota_graceful_fallback() {
        let (code, Json(resp)) = handle_sandbox_with(
            SandboxRunnerRequest {
                package: "sonarr".to_string(),
                package_id: String::new(),
                lifecycle_job_id: String::new(),
            },
            |_| async { Ok("sandbox fixture applied".into()) },
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert!(resp.success);

        let (bad_code, Json(bad_resp)) = handle_sandbox_with(
            SandboxRunnerRequest {
                package: "../evil".to_string(),
                package_id: String::new(),
                lifecycle_job_id: String::new(),
            },
            |_| async { Ok("sandbox fixture applied".into()) },
        )
        .await;
        assert_eq!(bad_code, StatusCode::BAD_REQUEST);
        assert!(!bad_resp.success);

        env::set_var("AETHERFLOW_QUOTA_DRY_RUN", "1");
        let (q_code, Json(q_resp)) = handle_quota(Json(QuotaRunnerRequest {
            username: "mediauser".to_string(),
            size: "500G".to_string(),
        }))
        .await;
        assert_eq!(q_code, StatusCode::OK);
        assert!(q_resp.success);
        assert!(q_resp.output.contains("mediauser"));
    }

    #[tokio::test]
    async fn test_handle_app_meta_wire_format() {
        let (code, Json(resp)) = handle_app_meta(Json(AppMetaRunnerRequest {
            app_name: "sonarr".to_string(),
        }))
        .await;
        assert_eq!(code, StatusCode::OK);
        assert!(resp.success);
        let decoded: AppRuntimeMeta = serde_json::from_str(&resp.output).unwrap();
        assert!(decoded.configured_port >= 0);
    }

    #[test]
    fn test_dispatcharr_runtime_port_and_package_fallback() {
        assert_eq!(dispatcharr_runtime_port("DISPATCHARR_PORT=19200\n"), 19200);
        assert_eq!(
            dispatcharr_runtime_port("DISPATCHARR_PORT=\"9191\"\n"),
            9191
        );
        assert_eq!(dispatcharr_runtime_port("DISPATCHARR_PORT=70000\n"), 0);
        assert_eq!(dispatcharr_runtime_port("POSTGRES_PORT=5432\n"), 0);
        assert!(package_script_roots().contains(&PathBuf::from("../../packages/package")));
    }

    #[test]
    fn test_dispatcharr_credential_sync_drops_privileges_and_preserves_literals() {
        let username = "user'\"$`\\";
        let password = "p'\"\\$(touch /tmp/not-executed)\npassword";
        let command = dispatcharr_credentials_command(username, password);
        let command = command.as_std();
        assert_eq!(command.get_program(), "runuser");
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect();
        assert_eq!(&args[..5], &["-u", "dispatcharr", "--", "/bin/bash", "-ec"]);
        assert!(args
            .last()
            .unwrap()
            .contains("source /etc/dispatcharr/dispatcharr.env"));
        assert!(!args
            .iter()
            .any(|arg| arg.contains(password) || arg.contains(username)));
        let variables: HashMap<_, _> = command.get_envs().collect();
        assert_eq!(
            variables[std::ffi::OsStr::new("AF_ADMIN_USER")],
            Some(std::ffi::OsStr::new(username))
        );
        assert_eq!(
            variables[std::ffi::OsStr::new("AF_ADMIN_PASS")],
            Some(std::ffi::OsStr::new(password))
        );
        assert!(DISPATCHARR_ADMIN_SCRIPT.contains("user.user_level = 10"));
        assert!(DISPATCHARR_ADMIN_SCRIPT.contains("os.environ[\"AF_ADMIN_PASS\"]"));
    }

    #[tokio::test]
    async fn test_dispatcharr_sync_rejects_invalid_credentials_before_execution() {
        for (username, password) in [("", "secret"), ("admin", ""), ("admin\0", "secret")] {
            let (status, Json(response)) =
                handle_dispatcharr_credentials(Json(DispatcharrCredentialsRequest {
                    username: username.to_string(),
                    password: password.to_string(),
                }))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(!response.success);
        }
    }

    #[tokio::test]
    async fn test_handle_package_rejects_purge_for_non_remove_actions() {
        for action in ["install", "update"] {
            let response = handle_package(Json(PackageRunnerRequest {
                action: action.to_string(),
                package_id: "sonarr".to_string(),
                script_name: "installpackage-sonarr".to_string(),
                lifecycle_job_id: String::new(),
                app_port: 0,
                delete_data: true,
                ..Default::default()
            }))
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{}", action);
        }
        let error = dispatch_package_action_with_options(
            "update",
            "sonarr",
            "installpackage-sonarr",
            0,
            true,
            |_| {},
        )
        .await
        .expect_err("client must refuse purge outside removal");
        assert!(error.to_string().contains("only valid for package removal"));
    }

    #[tokio::test]
    async fn test_handle_package_cancel_validation_and_signalling() {
        let (bad_code, Json(bad_resp)) = handle_package_cancel(Json(SandboxRunnerRequest {
            package: "../bad".to_string(),
            package_id: String::new(),
            lifecycle_job_id: String::new(),
        }))
        .await;
        assert_eq!(bad_code, StatusCode::BAD_REQUEST);
        assert!(!bad_resp.success);

        let tok = CancellationToken::new();
        let _guard = register_package_cancellation("cancel-handler-test", tok.clone()).unwrap();
        let (ok_code, Json(ok_resp)) = handle_package_cancel(Json(SandboxRunnerRequest {
            package: String::new(),
            package_id: "cancel-handler-test".to_string(),
            lifecycle_job_id: String::new(),
        }))
        .await;
        assert_eq!(ok_code, StatusCode::OK);
        assert!(ok_resp.success);
        assert!(ok_resp.output.contains("cancellation signalled"));
        assert!(tok.is_cancelled());
    }

    #[tokio::test]
    async fn test_update_discovery_and_admission_survive_api_restart_and_fail_closed() {
        let _env_guard = ENV_TEST_MUTEX.lock().await;
        let root = env::temp_dir().join(format!("af-admission-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let cfg =
            af_release::ReleaseConfig::load_for_root_from_process_env(Some(&root), None).unwrap();
        assert!(discover_system_update(&cfg).await.unwrap().completed);
        let lock = af_release::ensure_interoperable_maintenance_lock_file(&cfg).unwrap();
        let guard = af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).unwrap();
        assert!(
            af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).is_err(),
            "simultaneous updater/package admission cannot both hold the lock"
        );
        drop(guard);
        let dir = resolve_self_update_jobs_dir_for_cfg(&cfg).unwrap();
        let unit = "aetherflow-self-update-deploy-nightly-1234abcd.service";
        let path = dir.join(format!("{}.json", unit));
        let mut receipt = SelfUpdateJobStatus {
            status: "running".into(),
            completed: false,
            success: false,
            job_unit: unit.into(),
            error: String::new(),
            exit_code: None,
        };
        write_self_update_job_status_atomic(&path, &receipt).unwrap();
        // No ACTIVE_SYSTEM_UPDATE flag is set. Read from a fresh config, as a
        // restarted API would. A fake launcher disables real systemd queries.
        let previous = env::var_os("AETHERFLOW_SYSTEMD_RUN_BIN");
        env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", root.join("unused-fixture"));
        assert!(!discover_system_update(&cfg).await.unwrap().completed);
        assert!(acquire_package_maintenance_guard(
            Some(&root),
            af_release::lifecycle::ReservationTarget::Package("fixture"),
            "",
            Some("update")
        )
        .await
        .is_err());
        receipt.status = "failed".into();
        receipt.completed = true;
        receipt.exit_code = Some(1);
        receipt.error = "fixture failure".into();
        write_self_update_job_status_atomic(&path, &receipt).unwrap();
        assert!(discover_system_update(&cfg).await.unwrap().completed);
        let package_guard = acquire_package_maintenance_guard(
            Some(&root),
            af_release::lifecycle::ReservationTarget::Package("fixture"),
            "",
            Some("update"),
        )
        .await
        .unwrap();
        assert!(af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).is_err());
        drop(package_guard);
        fs::write(&path, "{invalid receipt").unwrap();
        assert!(discover_system_update(&cfg).await.is_err());
        assert!(acquire_package_maintenance_guard(
            Some(&root),
            af_release::lifecycle::ReservationTarget::Package("fixture"),
            "",
            Some("update")
        )
        .await
        .is_err());
        fs::remove_file(&path).unwrap();
        let mut recovery = af_release::RecoveryState::new(
            af_release::ReleaseCommand::Deploy,
            af_release::ReleaseChannel::Nightly,
            false,
        );
        recovery.save(&cfg.releases_dir).unwrap();
        let recovery_status = discover_system_update(&cfg).await.unwrap();
        assert!(!update_status_allows_launch(
            &recovery_status,
            af_release::ReleaseCommand::Deploy
        ));
        assert!(update_status_allows_launch(
            &recovery_status,
            af_release::ReleaseCommand::Rollback
        ));
        assert!(!recovery_status.completed);
        assert!(acquire_package_maintenance_guard(
            Some(&root),
            af_release::lifecycle::ReservationTarget::Package("fixture"),
            "",
            Some("update")
        )
        .await
        .is_err());
        match previous {
            Some(value) => env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", value),
            None => env::remove_var("AETHERFLOW_SYSTEMD_RUN_BIN"),
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn test_release_engine_rollout_control_and_self_update_validation() {
        let _env_guard = ENV_TEST_MUTEX.lock().await;
        assert_eq!(
            select_release_engine_with_flags(false, false),
            ReleaseEngineMode::LegacyBashRelease
        );
        assert_eq!(
            select_release_engine_with_flags(true, false),
            ReleaseEngineMode::NativeRustRelease
        );
        assert_eq!(
            select_release_engine_with_flags(true, true),
            ReleaseEngineMode::LegacyBashRelease
        );

        let (bad_cmd_code, bad_cmd_resp) = execute_self_update_request(
            &SelfUpdateRequest {
                command: "rm -rf /".to_string(),
                channel: "stable".to_string(),
            },
            false,
        )
        .await;
        assert_eq!(bad_cmd_code, StatusCode::BAD_REQUEST);
        assert!(!bad_cmd_resp.success);

        let (bad_chan_code, bad_chan_resp) = execute_self_update_request(
            &SelfUpdateRequest {
                command: "deploy".to_string(),
                channel: "untrusted-channel".to_string(),
            },
            false,
        )
        .await;
        assert_eq!(bad_chan_code, StatusCode::BAD_REQUEST);
        assert!(!bad_chan_resp.success);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let test_dir = env::temp_dir().join(format!(
                "af-runner-self-update-unit-test-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&test_dir).unwrap();

            let args_log = test_dir.join("systemd-run.args");
            let fake_systemd_run = test_dir.join("fake-systemd-run.sh");
            fs::write(
                &fake_systemd_run,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{}\"\nexit 0\n",
                    args_log.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&fake_systemd_run, fs::Permissions::from_mode(0o755)).unwrap();

            let fake_af = test_dir.join("af");
            fs::write(&fake_af, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&fake_af, fs::Permissions::from_mode(0o755)).unwrap();

            let fake_rm = test_dir.join("release-manager.sh");
            fs::write(&fake_rm, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&fake_rm, fs::Permissions::from_mode(0o755)).unwrap();

            env::set_var("AETHERFLOW_RELEASE_ROOT", &test_dir);
            env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fake_systemd_run);
            env::set_var("AETHERFLOW_CLI_BIN", &fake_af);
            env::set_var("AETHERFLOW_RELEASE_MANAGER_SCRIPT", &fake_rm);
            env::set_var("AETHERFLOW_ENABLE_RUST_RELEASE", "1");
            env::remove_var("AETHERFLOW_FORCE_BASH_RELEASE");
            env::set_var("AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE", "1");

            let (ok_code, ok_resp) = execute_self_update_request(
                &SelfUpdateRequest {
                    command: "deploy".to_string(),
                    channel: "stable".to_string(),
                },
                true,
            )
            .await;
            assert_eq!(ok_code, StatusCode::OK);
            assert!(ok_resp.success);
            let parsed_native: Value = serde_json::from_str(&ok_resp.output).unwrap();
            assert_eq!(parsed_native["status"], "initiated");
            assert_eq!(parsed_native["completed"], false);
            assert_eq!(parsed_native["engine"], "native_rust_release");
            let native_unit = parsed_native["job_unit"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(native_unit.starts_with("aetherflow-self-update-deploy-stable-"));
            let logged_native = fs::read_to_string(&args_log).unwrap();
            assert!(logged_native.contains("--no-block"));
            assert!(logged_native.contains("--root"));
            assert!(logged_native.contains(test_dir.to_string_lossy().as_ref()));
            assert!(logged_native.contains("release"));
            assert!(logged_native.contains("--local"));
            assert!(logged_native.contains("--job-status-file"));
            assert!(
                logged_native.contains("--setenv=AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE=1")
            );

            // Verify durable status is initially "running" (completed=false)
            let running_st = query_self_update_status_local(&native_unit).await.unwrap();
            assert_eq!(running_st.status, "running");
            assert!(!running_st.completed);
            assert!(!running_st.success);

            // Simulate completion receipt write and verify query_self_update_status_local returns it
            let status_file = test_dir
                .join("var/lib/aetherflow/.self-update-jobs")
                .join(format!("{}.json", native_unit));
            write_self_update_job_status_atomic(
                &status_file,
                &SelfUpdateJobStatus {
                    status: "succeeded".to_string(),
                    completed: true,
                    success: true,
                    job_unit: native_unit.clone(),
                    error: String::new(),
                    exit_code: Some(0),
                },
            )
            .unwrap();
            let done_st = query_self_update_status_local(&native_unit).await.unwrap();
            assert_eq!(done_st.status, "succeeded");
            assert!(done_st.completed);
            assert!(done_st.success);
            assert_eq!(done_st.exit_code, Some(0));

            env::set_var("AETHERFLOW_FORCE_BASH_RELEASE", "1");
            let (bash_code, bash_resp) = execute_self_update_request(
                &SelfUpdateRequest {
                    command: "rollback".to_string(),
                    channel: "nightly".to_string(),
                },
                true,
            )
            .await;
            assert_eq!(bash_code, StatusCode::OK);
            assert!(bash_resp.success);
            let parsed_bash: Value = serde_json::from_str(&bash_resp.output).unwrap();
            assert_eq!(parsed_bash["status"], "initiated");
            assert_eq!(parsed_bash["completed"], false);
            assert_eq!(parsed_bash["engine"], "legacy_bash_release");
            let logged_bash = fs::read_to_string(&args_log).unwrap();
            let directory = fs::metadata(test_dir.join("var/lib/aetherflow/.self-update-jobs")).unwrap();
            assert!(logged_bash.contains(&format!("--setenv=AETHERFLOW_SELF_UPDATE_DIRECTORY_DEV={}", std::os::unix::fs::MetadataExt::dev(&directory))));
            assert!(logged_bash.contains(&format!("--setenv=AETHERFLOW_SELF_UPDATE_DIRECTORY_INO={}", std::os::unix::fs::MetadataExt::ino(&directory))));
            assert!(logged_bash.contains("/bin/bash"));
            assert!(logged_bash.contains("rollback"));
            assert!(logged_bash.contains("--root"));
            assert!(logged_bash.contains("--config"));
            assert!(logged_bash.contains("--job-status-file"));
            assert!(logged_bash.contains("--setenv=AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE=1"));

            let bash_unit = parsed_bash["job_unit"].as_str().unwrap();
            write_self_update_job_status_atomic(
                &test_dir
                    .join("var/lib/aetherflow/.self-update-jobs")
                    .join(format!("{}.json", bash_unit)),
                &SelfUpdateJobStatus {
                    status: "succeeded".into(),
                    completed: true,
                    success: true,
                    job_unit: bash_unit.into(),
                    error: String::new(),
                    exit_code: Some(0),
                },
            )
            .unwrap();

            env::remove_var("AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE");
            spawn_self_update_transient_unit(
                "aetherflow-self-update-deploy-stable-12345678.service",
                &fake_af,
                &[],
                &[],
            )
            .await
            .unwrap();
            let logged_without_opt_in = fs::read_to_string(&args_log).unwrap();
            assert!(!logged_without_opt_in.contains("AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE"));

            // Verify malformed release-manager.conf fails closed instead of defaulting
            let bad_conf = test_dir.join("malformed.conf");
            fs::write(&bad_conf, "BROKEN_LINE_WITHOUT_EQUALS\n").unwrap();
            env::set_var("AETHERFLOW_RELEASE_CONF", &bad_conf);
            let (mal_code, mal_resp) = execute_self_update_request(
                &SelfUpdateRequest {
                    command: "deploy".to_string(),
                    channel: "stable".to_string(),
                },
                true,
            )
            .await;
            assert_eq!(mal_code, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(!mal_resp.success);
            env::remove_var("AETHERFLOW_RELEASE_CONF");

            let fail_systemd_run = test_dir.join("fail-systemd-run.sh");
            fs::write(
                &fail_systemd_run,
                "#!/bin/sh\necho 'dbus unit limit exceeded' >&2\nexit 1\n",
            )
            .unwrap();
            fs::set_permissions(&fail_systemd_run, fs::Permissions::from_mode(0o755)).unwrap();
            env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fail_systemd_run);

            let (fail_code, fail_resp) = execute_self_update_request(
                &SelfUpdateRequest {
                    command: "deploy".to_string(),
                    channel: "stable".to_string(),
                },
                true,
            )
            .await;
            assert_eq!(fail_code, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(!fail_resp.success);
            assert!(fail_resp.error.contains("failed to start"));

            env::remove_var("AETHERFLOW_RELEASE_ROOT");
            env::remove_var("AETHERFLOW_SYSTEMD_RUN_BIN");
            env::remove_var("AETHERFLOW_CLI_BIN");
            env::remove_var("AETHERFLOW_RELEASE_MANAGER_SCRIPT");
            env::remove_var("AETHERFLOW_ENABLE_RUST_RELEASE");
            env::remove_var("AETHERFLOW_FORCE_BASH_RELEASE");
            env::remove_var("AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE");
            let _ = fs::remove_dir_all(&test_dir);
        }
    }

    #[tokio::test]
    async fn test_handle_backup_create_verify_list_restore_and_prune() {
        let _env_guard = ENV_TEST_MUTEX.lock().await;
        let root = env::temp_dir().join(format!(
            "af-runner-backup-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let host_root = root.join("host");
        let db_path = host_root.join("var/lib/aetherflow/aetherflow.sqlite");
        let backup_dir = host_root.join("var/lib/aetherflow/backups");
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        fs::create_dir_all(&backup_dir).unwrap();

        env::set_var(
            "AETHERFLOW_BACKUP_ISOLATED_ROOT",
            host_root.to_string_lossy().as_ref(),
        );

        assert!(authorize_runner_peer_credentials(0, 0, "/v1/backup").is_ok());
        let (unauth_code, unauth_msg) =
            authorize_runner_peer_credentials(65534, 65534, "/v1/backup").unwrap_err();
        assert_eq!(unauth_code, StatusCode::FORBIDDEN);
        assert!(unauth_msg.contains("unauthorized unix socket peer"));

        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA user_version = 7;
                 CREATE TABLE settings (id INTEGER PRIMARY KEY, base_domain TEXT NOT NULL);
                 INSERT INTO settings (id, base_domain) VALUES (1, 'runner.example.test');",
            )
            .unwrap();
        }

        let (bad_code, Json(bad_resp)) = handle_backup(Json(BackupRunnerRequest {
            action: "drop_table".to_string(),
            ..Default::default()
        }))
        .await;
        assert_eq!(bad_code, StatusCode::BAD_REQUEST);
        assert!(!bad_resp.success);

        let (forbid_code, Json(forbid_resp)) = handle_backup(Json(BackupRunnerRequest {
            action: "delete".to_string(),
            filename: "aetherflow-db-20261103_000000.sqlite".to_string(),
            backup_dir: "/etc".to_string(),
            ..Default::default()
        }))
        .await;
        assert_eq!(forbid_code, StatusCode::FORBIDDEN);
        assert!(!forbid_resp.success);

        let (create_code, Json(create_resp)) = handle_backup(Json(BackupRunnerRequest {
            action: "create_sqlite".to_string(),
            backup_dir: backup_dir.to_string_lossy().into_owned(),
            db_path: db_path.to_string_lossy().into_owned(),
            app_version: "v4.0.0".to_string(),
            ..Default::default()
        }))
        .await;
        assert_eq!(create_code, StatusCode::OK);
        assert!(create_resp.success);
        let created: BackupRunnerResponse = serde_json::from_str(&create_resp.output).unwrap();
        assert!(created.verified);
        assert!(created.filename.ends_with(".sqlite"));

        let (ver_code, Json(ver_resp)) = handle_backup(Json(BackupRunnerRequest {
            action: "verify".to_string(),
            filename: created.filename.clone(),
            backup_dir: backup_dir.to_string_lossy().into_owned(),
            ..Default::default()
        }))
        .await;
        assert_eq!(ver_code, StatusCode::OK);
        assert!(ver_resp.success);

        let stage_target = root.join("restore-stage");
        let (pf_code, Json(pf_resp)) = handle_backup(Json(BackupRunnerRequest {
            action: "restore_preflight".to_string(),
            filename: created.filename.clone(),
            backup_dir: backup_dir.to_string_lossy().into_owned(),
            target_root: stage_target.to_string_lossy().into_owned(),
            ..Default::default()
        }))
        .await;
        assert_eq!(pf_code, StatusCode::OK);
        assert!(pf_resp.success);

        let (unconf_code, Json(unconf_resp)) = handle_backup(Json(BackupRunnerRequest {
            action: "restore_execute".to_string(),
            filename: created.filename.clone(),
            backup_dir: backup_dir.to_string_lossy().into_owned(),
            target_root: stage_target.to_string_lossy().into_owned(),
            confirm_destructive_restore: false,
            ..Default::default()
        }))
        .await;
        assert_eq!(unconf_code, StatusCode::BAD_REQUEST);
        assert!(!unconf_resp.success);

        let (self_stop_code, Json(self_stop_resp)) = handle_backup(Json(BackupRunnerRequest {
            action: "restore_execute".to_string(),
            filename: created.filename.clone(),
            backup_dir: backup_dir.to_string_lossy().into_owned(),
            target_root: stage_target.to_string_lossy().into_owned(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["aetherflow-runner.service".to_string()],
            ..Default::default()
        }))
        .await;
        assert_eq!(self_stop_code, StatusCode::BAD_REQUEST);
        assert!(!self_stop_resp.success);

        let (bypass_code, Json(bypass_resp)) = handle_backup(Json(BackupRunnerRequest {
            action: "restore_execute".to_string(),
            filename: created.filename.clone(),
            backup_dir: backup_dir.to_string_lossy().into_owned(),
            target_root: stage_target.to_string_lossy().into_owned(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["none".to_string()],
            ..Default::default()
        }))
        .await;
        assert_eq!(bypass_code, StatusCode::BAD_REQUEST);
        assert!(!bypass_resp.success);

        let (rest_code, Json(rest_resp)) = handle_backup(Json(BackupRunnerRequest {
            action: "restore_execute".to_string(),
            filename: created.filename.clone(),
            backup_dir: backup_dir.to_string_lossy().into_owned(),
            target_root: stage_target.to_string_lossy().into_owned(),
            confirm_destructive_restore: true,
            allow_overwrite: true,
            quiesce_services: vec!["custom-writer.service".to_string()],
            ..Default::default()
        }))
        .await;
        assert_eq!(rest_code, StatusCode::OK);
        assert!(rest_resp.success);
        let restored: BackupRunnerResponse = serde_json::from_str(&rest_resp.output).unwrap();
        assert!(restored.verified);
        assert_eq!(restored.restored_files, 1);
        assert_eq!(
            restored.details["quiesced_services"],
            json!(["aetherflow-api.service", "custom-writer.service"])
        );

        let (rec_code, Json(rec_resp)) = handle_backup(Json(BackupRunnerRequest {
            action: "recover_interrupted".to_string(),
            backup_dir: backup_dir.to_string_lossy().into_owned(),
            target_root: stage_target.to_string_lossy().into_owned(),
            ..Default::default()
        }))
        .await;
        assert_eq!(rec_code, StatusCode::OK, "{}", rec_resp.error);
        assert!(rec_resp.success);

        let custom_db = host_root.join("srv/custom-af/aetherflow.sqlite");
        fs::create_dir_all(custom_db.parent().unwrap()).unwrap();
        fs::copy(&db_path, &custom_db).unwrap();
        env::set_var("AF_DB_PATH", custom_db.to_string_lossy().as_ref());

        let stage_contained = root.join("restore-stage-contained");
        let (pf2_code, Json(pf2_resp)) = handle_backup(Json(BackupRunnerRequest {
            action: "restore_preflight".to_string(),
            filename: created.filename.clone(),
            backup_dir: backup_dir.to_string_lossy().into_owned(),
            target_root: stage_contained.to_string_lossy().into_owned(),
            ..Default::default()
        }))
        .await;
        assert_eq!(pf2_code, StatusCode::OK, "{}", pf2_resp.error);
        let pf2_parsed: BackupRunnerResponse = serde_json::from_str(&pf2_resp.output).unwrap();
        let dest_str = pf2_parsed.details["items"][0]["destination_path"]
            .as_str()
            .unwrap();
        assert!(
            Path::new(dest_str).starts_with(&stage_contained),
            "staging preflight destination '{}' escaped staging target '{}'",
            dest_str,
            stage_contained.display()
        );
        env::remove_var("AF_DB_PATH");

        env::remove_var("AETHERFLOW_BACKUP_ISOLATED_ROOT");
        let _ = fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn test_self_update_status_honors_custom_data_dir_and_rejects_contradictory_receipts() {
        let _env_guard = ENV_TEST_MUTEX.lock().await;
        let test_dir = env::temp_dir().join(format!(
            "af-runner-status-datadir-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let custom_data_dir = test_dir.join("srv/aetherflow-data");
        let etc_dir = test_dir.join("etc/aetherflow");
        fs::create_dir_all(&custom_data_dir).unwrap();
        fs::create_dir_all(&etc_dir).unwrap();
        fs::write(
            etc_dir.join("release-manager.conf"),
            format!("DATA_DIR=\"{}\"\n", custom_data_dir.display()),
        )
        .unwrap();

        env::set_var("AETHERFLOW_RELEASE_ROOT", &test_dir);
        let jobs_dir = resolve_self_update_jobs_dir_from_env().unwrap();
        assert_eq!(jobs_dir, custom_data_dir.join(".self-update-jobs"));

        let unit_name = "aetherflow-self-update-deploy-stable-11223344.service";
        let status_file = jobs_dir.join(format!("{}.json", unit_name));
        write_self_update_job_status_atomic(
            &status_file,
            &SelfUpdateJobStatus {
                status: "succeeded".to_string(),
                completed: true,
                success: true,
                job_unit: unit_name.to_string(),
                error: String::new(),
                exit_code: Some(0),
            },
        )
        .unwrap();
        let valid_res = query_self_update_status_local(unit_name).await.unwrap();
        assert!(valid_res.completed);
        assert!(valid_res.success);

        fs::write(
            &status_file,
            serde_json::to_vec(&SelfUpdateJobStatus {
                status: "running".to_string(),
                completed: false,
                success: true,
                job_unit: unit_name.to_string(),
                error: String::new(),
                exit_code: None,
            })
            .unwrap(),
        )
        .unwrap();
        let corrupt_err = query_self_update_status_local(unit_name)
            .await
            .expect_err("contradictory receipt must fail closed");
        assert_eq!(corrupt_err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(corrupt_err.1.contains("corrupt self-update status file"));

        #[cfg(target_os = "linux")]
        {
            let vanished_unit = "aetherflow-self-update-deploy-stable-99887766.service";
            let vanished_file = jobs_dir.join(format!("{}.json", vanished_unit));
            write_self_update_job_status_atomic(
                &vanished_file,
                &SelfUpdateJobStatus {
                    status: "running".to_string(),
                    completed: false,
                    success: false,
                    job_unit: vanished_unit.to_string(),
                    error: String::new(),
                    exit_code: None,
                },
            )
            .unwrap();
            // A missing unit is a fixture, never a query to the host manager.
            use std::os::unix::fs::PermissionsExt;
            let fake_ctl = test_dir.join("systemctl-fixture");
            fs::write(&fake_ctl, "#!/bin/sh\nprintf 'LoadState=not-found\\nActiveState=inactive\\nExecMainStatus=0\\n'\n").unwrap();
            fs::set_permissions(&fake_ctl, fs::Permissions::from_mode(0o755)).unwrap();
            env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_ctl);
            let reconciled = query_self_update_status_local(vanished_unit).await.unwrap();
            env::remove_var("AETHERFLOW_SYSTEMCTL_BIN");
            assert_eq!(reconciled.status, "failed");
            assert!(reconciled.completed);
            assert!(!reconciled.success);
            assert_eq!(reconciled.exit_code, Some(1));
        }

        env::remove_var("AETHERFLOW_RELEASE_ROOT");
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_tailscale_and_wireguard_exempt_from_sandbox() {
        assert!(is_exempt_sandbox_unit("tailscale"));
        assert!(is_exempt_sandbox_unit("tailscaled"));
        assert!(is_exempt_sandbox_unit("tailscale.service"));
        assert!(is_exempt_sandbox_unit("tailscaled.service"));
        assert!(is_exempt_sandbox_unit("wg-quick@wg0.service"));
        assert!(is_exempt_sandbox_unit("wireguard.service"));
        assert!(!is_exempt_sandbox_unit("sonarr.service"));
    }

    #[test]
    fn test_hosts_file_preserves_unrelated_host_aliases_and_multi_app() {
        let scratch_dir = env::temp_dir().join(format!("af-hosts-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&scratch_dir).unwrap();
        let hosts_file = scratch_dir.join("hosts");

        // Initial hosts file with unrelated alias on the same line as appa.aether.local
        let initial_content = "127.0.0.1 localhost\n192.168.1.10 server.lan appa.aether.local\n";
        fs::write(&hosts_file, initial_content).unwrap();

        // 1. Update with appb.aether.local: both apps and server.lan must be preserved!
        update_hosts_file_at_path(&hosts_file, &["appb.aether.local".to_string()], false).unwrap();
        let content_after_appb = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_appb.contains("server.lan"));
        assert!(content_after_appb.contains("appb.aether.local"));

        // 2. Remove appa.aether.local: server.lan must remain!
        update_hosts_file_at_path(&hosts_file, &["appa.aether.local".to_string()], true).unwrap();
        let content_after_remove = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_remove.contains("192.168.1.10\tserver.lan"));
        assert!(!content_after_remove.contains("appa.aether.local"));
        assert!(content_after_remove.contains("appb.aether.local"));

        // 3. Reconcile with authoritative list [appc.aether.local]:
        // server.lan must still remain, appb pruned, appc added.
        let lock_file = scratch_dir.join("hosts.lock");
        reconcile_hosts_file_at_path(
            &hosts_file,
            &lock_file,
            &["appc.aether.local".to_string()],
            "127.0.0.1",
        )
        .unwrap();
        let content_after_reconcile = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_reconcile.contains("192.168.1.10\tserver.lan"));
        assert!(!content_after_reconcile.contains("appb.aether.local"));
        assert!(content_after_reconcile.contains("appc.aether.local"));

        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[test]
    fn test_hosts_managed_block_preserves_comments_and_multi_alias_lines() {
        let _env_guard = ENV_TEST_MUTEX.blocking_lock();
        let scratch_dir = env::temp_dir().join(format!("af-hosts-comment-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&scratch_dir).unwrap();
        let hosts_file = scratch_dir.join("hosts");
        let lock_file = scratch_dir.join("hosts.lock");

        // Initial hosts file containing managed block with internal comments and multi-alias lines
        let initial = "\
127.0.0.1 localhost
# BEGIN AETHERFLOW MANAGED BLOCK
# Internal managed note
10.0.0.5 app1.aether.local custom.lan # note
127.0.0.1 app2.aether.local
# END AETHERFLOW MANAGED BLOCK
";
        fs::write(&hosts_file, initial).unwrap();

        // 1. Update: add app3.aether.local
        update_hosts_file_at_path(&hosts_file, &["app3.aether.local".to_string()], false).unwrap();
        let content_after_update = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_update.contains("# Internal managed note"), "managed comments must be preserved");
        assert!(content_after_update.contains("10.0.0.5\tcustom.lan # note"), "non-aether alias must be preserved with comment");
        assert!(content_after_update.contains("app1.aether.local"));
        assert!(content_after_update.contains("app2.aether.local"));
        assert!(content_after_update.contains("app3.aether.local"));

        // 2. Remove: remove app1.aether.local
        update_hosts_file_at_path(&hosts_file, &["app1.aether.local".to_string()], true).unwrap();
        let content_after_remove = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_remove.contains("# Internal managed note"));
        assert!(content_after_remove.contains("10.0.0.5\tcustom.lan # note"));
        assert!(!content_after_remove.contains("app1.aether.local"));
        assert!(content_after_remove.contains("app2.aether.local"));
        assert!(content_after_remove.contains("app3.aether.local"));

        // 3. Reconcile: authoritative list is [app4.aether.local]
        reconcile_hosts_file_at_path(&hosts_file, &lock_file, &["app4.aether.local".to_string()], "127.0.0.1").unwrap();
        let content_after_reconcile = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_reconcile.contains("# Internal managed note"));
        assert!(content_after_reconcile.contains("10.0.0.5\tcustom.lan # note"));
        assert!(!content_after_reconcile.contains("app2.aether.local"));
        assert!(!content_after_reconcile.contains("app3.aether.local"));
        assert!(content_after_reconcile.contains("127.0.0.1\tapp4.aether.local"));

        // 4. CLI reconcile test: empty domains clears managed entries while preserving comments & custom aliases
        let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
        let pihole_dir = scratch_dir.join("pihole");
        fs::create_dir_all(&dnsmasq_dir).unwrap();
        fs::create_dir_all(&pihole_dir).unwrap();
        env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());
        env::set_var("AETHERFLOW_DNSMASQ_DIR", dnsmasq_dir.to_string_lossy().as_ref());
        env::set_var("AETHERFLOW_PIHOLE_DIR", pihole_dir.to_string_lossy().as_ref());

        let cli_res = run_hosts_cli(&["reconcile".to_string(), "127.0.0.1".to_string()]);
        assert!(cli_res.is_ok());
        let content_after_cli_empty = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_cli_empty.contains("# Internal managed note"));
        assert!(content_after_cli_empty.contains("10.0.0.5\tcustom.lan # note"));
        assert!(!content_after_cli_empty.contains("app4.aether.local"));

        // Check dnsmasq and pihole files were written
        assert!(dnsmasq_dir.join("aetherflow.conf").exists());
        assert!(pihole_dir.join("custom.list").exists());

        env::remove_var("AF_HOSTS_FILE");
        env::remove_var("AETHERFLOW_DNSMASQ_DIR");
        env::remove_var("AETHERFLOW_PIHOLE_DIR");
        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[test]
    fn test_hosts_ip_validation_rejects_injections_and_invalid_ips() {
        let scratch_dir = env::temp_dir().join(format!("af-hosts-ip-val-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&scratch_dir).unwrap();
        let hosts_file = scratch_dir.join("hosts");
        let lock_file = scratch_dir.join("hosts.lock");
        fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
        let domains = vec!["sonarr.aether.local".to_string()];

        let injection_ip = "127.0.0.1\n10.0.0.1 injected.host";
        let invalid_ip = "not-an-ip";
        let leading_space_ip = " 127.0.0.1";
        let trailing_space_ip = "127.0.0.1 ";
        let tab_ip = "\t127.0.0.1\t";

        for bad_ip in [
            injection_ip,
            invalid_ip,
            leading_space_ip,
            trailing_space_ip,
            tab_ip,
        ] {
            assert!(validate_hosts_ip(bad_ip).is_err());
            // Verify update_hosts_file_with_ip_at_path and reconcile_hosts_file_at_path reject invalid IPs
            assert!(update_hosts_file_with_ip_at_path(&hosts_file, &lock_file, &domains, bad_ip, false).is_err());
            assert!(reconcile_hosts_file_at_path(&hosts_file, &lock_file, &domains, bad_ip).is_err());

            // Verify modify_hosts_file_at_path directly
            assert!(modify_hosts_file_at_path(&hosts_file, &lock_file, &domains, HostsModifyAction::Update { ip: bad_ip }).is_err());
            assert!(modify_hosts_file_at_path(&hosts_file, &lock_file, &domains, HostsModifyAction::Reconcile { ip: bad_ip }).is_err());

            // Verify sync_dns_provider_files and execute_hosts_cli_command
            assert!(sync_dns_provider_files(bad_ip, &domains).is_err());
            assert!(execute_hosts_cli_command("update", bad_ip, &domains).is_err());
            assert!(execute_hosts_cli_command("reconcile", bad_ip, &domains).is_err());
        }

        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[test]
    fn test_hosts_removes_or_updates_last_alias_preserves_standalone_comment() {
        let scratch_dir = env::temp_dir().join(format!("af-hosts-comment-preserve-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&scratch_dir).unwrap();
        let hosts_file = scratch_dir.join("hosts");
        let lock_file = scratch_dir.join("hosts.lock");

        // 1. Direct filter_hosts_line test
        let line = "127.0.0.1 sonarr.aether.local # admin note";
        let filtered = filter_hosts_line(line, |host| host == "sonarr.aether.local");
        assert_eq!(filtered, Some("# admin note".to_string()));

        // 2. Removing last alias on an outside-block line preserves # admin note as standalone comment line
        let initial_remove = "127.0.0.1 sonarr.aether.local # admin note\n";
        fs::write(&hosts_file, initial_remove).unwrap();
        update_hosts_file_with_ip_at_path(&hosts_file, &lock_file, &["sonarr.aether.local".to_string()], "127.0.0.1", true).unwrap();
        let content_after_remove = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_remove.contains("# admin note"), "standalone comment must be preserved on removal: {}", content_after_remove);
        assert!(!content_after_remove.contains("sonarr.aether.local"));
        assert!(content_after_remove.lines().any(|l| l.trim() == "# admin note"));

        // 3. Updating last alias on an outside-block line preserves # admin note as standalone comment line
        let initial_update = "127.0.0.1 sonarr.aether.local # admin note\n";
        fs::write(&hosts_file, initial_update).unwrap();
        update_hosts_file_with_ip_at_path(&hosts_file, &lock_file, &["sonarr.aether.local".to_string()], "10.0.0.2", false).unwrap();
        let content_after_update = fs::read_to_string(&hosts_file).unwrap();
        assert!(content_after_update.contains("# admin note"), "standalone comment must be preserved on update: {}", content_after_update);
        assert!(content_after_update.lines().any(|l| l.trim() == "# admin note"));
        assert!(content_after_update.contains("10.0.0.2\tsonarr.aether.local"));

        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[tokio::test]
    async fn test_pihole_custom_list_preserves_unmanaged_records_aliases_and_comments() {
        let initial_content = "\
# Pi-hole Custom Domain List
192.168.1.1 router.home
192.168.1.50 nas.home.lan
192.168.1.10 app.aether.local keep.lan # custom note
192.168.1.20 oldapp.aether.local # aetherflow-managed
192.168.1.30 sonarr.aether.local # user note
";
        let reconciled = reconcile_pihole_custom_list_content(
            initial_content,
            "192.168.1.200",
            &["sonarr.aether.local".to_string(), "radarr.aether.local".to_string()],
            true,
        );

        // Header and unmanaged records preserved
        assert!(reconciled.contains("# Pi-hole Custom Domain List"));
        assert!(reconciled.contains("192.168.1.1 router.home"));
        assert!(reconciled.contains("192.168.1.50 nas.home.lan"));

        // Multi-alias line with unmanaged hostname keep.lan preserved intact without app.aether.local
        assert!(reconciled.contains("192.168.1.10 keep.lan # custom note"));
        assert!(!reconciled.contains("192.168.1.10 app.aether.local"));

        // Multi-alias line with # aetherflow-managed tag preserves unmanaged aliases
        let managed_multi_line = "192.168.1.10 old.aether.local unrelated.lan # aetherflow-managed\n";
        let reconciled_multi = reconcile_pihole_custom_list_content(
            managed_multi_line,
            "192.168.1.200",
            &["sonarr.aether.local".to_string()],
            true,
        );
        assert!(
            reconciled_multi.contains("192.168.1.10 unrelated.lan"),
            "unrelated.lan must be preserved even if line has # aetherflow-managed: {}",
            reconciled_multi
        );
        assert!(
            !reconciled_multi.contains("old.aether.local"),
            "old.aether.local must be dropped on reconcile: {}",
            reconciled_multi
        );
        assert!(reconciled_multi.contains("192.168.1.200 sonarr.aether.local # aetherflow-managed"));

        // Old managed domain dropped on reconcile
        assert!(!reconciled.contains("oldapp.aether.local"));

        // Single-domain user note preserved with updated IP
        assert!(reconciled.contains("192.168.1.200 sonarr.aether.local # user note"));

        // Newly added domain appended
        assert!(reconciled.contains("192.168.1.200 radarr.aether.local # aetherflow-managed"));

        // Now test removal
        let after_removal = remove_pihole_custom_list_content(
            &reconciled,
            &["sonarr.aether.local".to_string()],
        );
        assert!(!after_removal.contains("sonarr.aether.local"));
        assert!(after_removal.contains("192.168.1.1 router.home"));
        assert!(after_removal.contains("192.168.1.10 keep.lan # custom note"));
        assert!(after_removal.contains("192.168.1.200 radarr.aether.local # aetherflow-managed"));

        // Test removing one alias from multi-alias line
        let multi_alias = "192.168.1.99 host1.lan host2.lan host3.lan # my comment\n";
        let removed_alias = remove_pihole_custom_list_content(multi_alias, &["host2.lan".to_string()]);
        assert_eq!(removed_alias.trim(), "192.168.1.99 host1.lan host3.lan # my comment");
    }

    #[tokio::test]
    async fn test_pihole_custom_list_invalid_utf8_fails_closed_and_leaves_file_intact() {
        let _env_guard = ENV_TEST_MUTEX.lock().await;
        let scratch_dir = env::temp_dir().join(format!("af-pihole-utf8-test-{}", uuid::Uuid::new_v4()));
        let pihole_dir = scratch_dir.join("pihole");
        fs::create_dir_all(&pihole_dir).unwrap();

        let custom_list = pihole_dir.join("custom.list");
        let invalid_bytes = vec![0xff, 0xfe, b'a', b'b', b'c'];
        fs::write(&custom_list, &invalid_bytes).unwrap();

        env::set_var("AETHERFLOW_PIHOLE_DIR", pihole_dir.to_string_lossy().as_ref());

        // Test sync fails closed
        let sync_res = sync_dns_provider_files_with_mode(
            "192.168.1.100",
            &["sonarr.aether.local".to_string()],
            true,
        );
        assert!(sync_res.is_err(), "sync must fail on invalid UTF-8");
        // Verify file is untouched on disk
        let on_disk_after_sync = fs::read(&custom_list).unwrap();
        assert_eq!(on_disk_after_sync, invalid_bytes);

        // Test remove fails closed
        let rm_res = remove_dns_provider_files(&["sonarr.aether.local".to_string()]);
        assert!(rm_res.is_err(), "remove must fail on invalid UTF-8");
        // Verify file is untouched on disk
        let on_disk_after_rm = fs::read(&custom_list).unwrap();
        assert_eq!(on_disk_after_rm, invalid_bytes);

        env::remove_var("AETHERFLOW_PIHOLE_DIR");
        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[tokio::test]
    async fn test_runner_hosts_handler_separates_loopback_hosts_from_provider_lan_ip_and_public_domains() {
        let _env_guard = ENV_TEST_MUTEX.lock().await;
        let scratch_dir = env::temp_dir().join(format!("af-runner-sep-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&scratch_dir).unwrap();

        let hosts_file = scratch_dir.join("hosts");
        fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
        let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
        fs::create_dir_all(&dnsmasq_dir).unwrap();
        let pihole_dir = scratch_dir.join("pihole");
        fs::create_dir_all(&pihole_dir).unwrap();

        env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());
        env::set_var("AETHERFLOW_DNSMASQ_DIR", dnsmasq_dir.to_string_lossy().as_ref());
        env::set_var("AETHERFLOW_PIHOLE_DIR", pihole_dir.to_string_lossy().as_ref());

        let req = HostsUpdateRequest {
            action: "reconcile".to_string(),
            ip: "127.0.0.1".to_string(),
            domains: vec!["sonarr.aether.local".to_string()],
            provider_ip: Some("192.168.1.50".to_string()),
            provider_domains: Some(vec![
                "sonarr.aether.local".to_string(),
                "media.example.com".to_string(),
            ]),
            ..Default::default()
        };

        let resp = apply_hosts_update(req).await.unwrap();
        assert!(resp.success);
        assert_eq!(resp.output, "hosts reconciled");

        // 1. /etc/hosts must contain 127.0.0.1 sonarr.aether.local only
        let hosts_content = fs::read_to_string(&hosts_file).unwrap();
        assert!(hosts_content.contains("127.0.0.1\tsonarr.aether.local"));
        assert!(!hosts_content.contains("192.168.1.50"));
        assert!(!hosts_content.contains("media.example.com"));

        // 2. dnsmasq must contain 192.168.1.50 and both domains, but not 127.0.0.1
        let dnsmasq_conf = fs::read_to_string(dnsmasq_dir.join("aetherflow.conf")).unwrap();
        assert!(dnsmasq_conf.contains("address=/sonarr.aether.local/192.168.1.50"));
        assert!(dnsmasq_conf.contains("address=/media.example.com/192.168.1.50"));
        assert!(!dnsmasq_conf.contains("127.0.0.1"));

        // 3. Pi-hole custom.list must contain 192.168.1.50 and both domains, but not 127.0.0.1
        let pihole_list = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
        assert!(pihole_list.contains("192.168.1.50 sonarr.aether.local # aetherflow-managed"));
        assert!(pihole_list.contains("192.168.1.50 media.example.com # aetherflow-managed"));
        assert!(!pihole_list.contains("127.0.0.1"));

        env::remove_var("AF_HOSTS_FILE");
        env::remove_var("AETHERFLOW_DNSMASQ_DIR");
        env::remove_var("AETHERFLOW_PIHOLE_DIR");
        let _ = fs::remove_dir_all(&scratch_dir);
    }

    #[tokio::test]
    async fn test_hosts_cli_remove_clears_providers_and_propagates_errors() {
        let _env_guard = ENV_TEST_MUTEX.lock().await;
        let scratch_dir = env::temp_dir().join(format!("af-cli-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&scratch_dir).unwrap();

        let hosts_file = scratch_dir.join("hosts");
        fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
        let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
        fs::create_dir_all(&dnsmasq_dir).unwrap();
        let pihole_dir = scratch_dir.join("pihole");
        fs::create_dir_all(&pihole_dir).unwrap();

        env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());
        env::set_var("AETHERFLOW_DNSMASQ_DIR", dnsmasq_dir.to_string_lossy().as_ref());
        env::set_var("AETHERFLOW_PIHOLE_DIR", pihole_dir.to_string_lossy().as_ref());

        // 1. Add entry
        let add_res = run_hosts_cli(&[
            "update".to_string(),
            "10.0.0.50".to_string(),
            "sonarr.aether.local".to_string(),
        ]);
        assert!(add_res.is_ok(), "{:?}", add_res);

        let hosts_after_add = fs::read_to_string(&hosts_file).unwrap();
        assert!(hosts_after_add.contains("sonarr.aether.local"));
        let dnsmasq_after_add = fs::read_to_string(dnsmasq_dir.join("aetherflow.conf")).unwrap();
        assert!(dnsmasq_after_add.contains("sonarr.aether.local"));
        let pihole_after_add = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
        assert!(pihole_after_add.contains("sonarr.aether.local"));

        // 2. Remove entry via CLI
        let rm_res = run_hosts_cli(&[
            "remove".to_string(),
            "sonarr.aether.local".to_string(),
        ]);
        assert!(rm_res.is_ok(), "{:?}", rm_res);

        let hosts_after_rm = fs::read_to_string(&hosts_file).unwrap();
        assert!(!hosts_after_rm.contains("sonarr.aether.local"));
        let dnsmasq_after_rm = fs::read_to_string(dnsmasq_dir.join("aetherflow.conf")).unwrap();
        assert!(!dnsmasq_after_rm.contains("sonarr.aether.local"));
        let pihole_after_rm = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
        assert!(!pihole_after_rm.contains("sonarr.aether.local"));

        // 3. Provider error propagation: write to read-only dir
        let ro_dir = scratch_dir.join("ro_dir");
        fs::create_dir_all(&ro_dir).unwrap();
        fs::write(ro_dir.join("custom.list"), "10.0.0.50 testfail.aether.local\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o444));
            env::set_var("AETHERFLOW_PIHOLE_DIR", ro_dir.to_string_lossy().as_ref());
            let err_res = run_hosts_cli(&[
                "update".to_string(),
                "10.0.0.50".to_string(),
                "testfail.aether.local".to_string(),
            ]);
            assert!(err_res.is_err(), "provider sync error must be propagated");

            let err_rm = run_hosts_cli(&[
                "remove".to_string(),
                "testfail.aether.local".to_string(),
            ]);
            assert!(err_rm.is_err(), "remove provider error must be propagated");
            let _ = fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o755));
        }

        env::remove_var("AF_HOSTS_FILE");
        env::remove_var("AETHERFLOW_DNSMASQ_DIR");
        env::remove_var("AETHERFLOW_PIHOLE_DIR");
        let _ = fs::remove_dir_all(&scratch_dir);
    }
}
