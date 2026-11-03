use af_models::{
    AppMetaRunnerRequest, HostsRunnerRequest, NetworkRunnerRequest, Package, PackageAutomation,
    PackageRunnerRequest, QuotaRunnerRequest, RunnerResponse, SandboxRunnerRequest,
    SelfUpdateRequest, SystemctlRequest,
};
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

pub use af_release;
pub mod package_executor;
pub mod network;
pub use package_executor::*;

pub const DEFAULT_RUNNER_SOCKET_PATH: &str = "/run/aetherflow/runner.sock";

const EMBEDDED_PACKAGES_JSON: &str = include_str!("../../../../backend/config/packages.json");
const EMBEDDED_AUTOMATION_JSON: &str =
    include_str!("../../../../backend/config/package_automation.json");

pub(crate) static PACKAGE_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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
pub static SAFE_QUOTA_SIZE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:[0-9]+[KMGTPkmgtp]?[Bb]?|[0-9]+(?:\.[0-9]+)?\s*[KMGTPEkmgtpe]?[Bb]?|0)$").unwrap());
pub static SAFE_QUOTA_SIZE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:[0-9]+(?:\.[0-9]+)?\s*[KMGTPEkmgtpe]?[Bb]?|0)$").unwrap());

static ALLOWED_SERVICE_ACTIONS: Lazy<HashSet<&'static str>> =
    Lazy::new(|| ["start", "stop", "restart", "reload", "enable", "disable", "status", "heal"].into());

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
        "install" => "install",
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
            let p = PathBuf::from(trimmed);
            if p.is_file() {
                return Some(p);
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
    candidates.into_iter().find(|c| c.is_file())
}

/// Builds the Axum router for the Privileged Root Socket Daemon (`aetherflow-api runner`).
pub fn build_runner_router() -> Router {
    Router::new()
        .route("/v1/health", get(handle_health).post(handle_health))
        .route("/v1/systemctl", post(handle_systemctl))
        .route("/v1/package", post(handle_package))
        .route("/v1/package/cancel", post(handle_package_cancel))
        .route("/v1/self-update", post(handle_self_update))
        .route("/v1/sandbox", post(handle_sandbox))
        .route("/v1/hosts", post(handle_hosts))
        .route("/v1/network", post(handle_network))
        .route("/v1/quota", post(handle_quota))
        .route("/v1/app-meta", post(handle_app_meta))
        .route("/v1/dispatcharr-credentials", post(handle_dispatcharr_credentials))
}

async fn handle_health() -> Json<RunnerResponse> {
    Json(RunnerResponse {
        success: true,
        output: "ready".to_string(),
        error: String::new(),
    })
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
    let action = if req.action == "heal" {
        _heal_mutex = match PACKAGE_MUTEX.try_lock() {
            Ok(guard) => Some(guard),
            Err(_) => {
                return (
                    StatusCode::OK,
                    Json(RunnerResponse {
                        success: true,
                        output: "skipped".into(),
                        error: String::new(),
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
                    StatusCode::OK,
                    Json(RunnerResponse {
                        success: true,
                        output: "skipped".into(),
                        error: String::new(),
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
        "restart"
    } else {
        _heal_mutex = None;
        _heal_flock = None;
        req.action.as_str()
    };

    match tokio::time::timeout(
        Duration::from_secs(45),
        Command::new("systemctl")
            .arg(action)
            .arg("--")
            .arg(&req.service)
            .output(),
    )
    .await
    {
        Ok(Ok(out)) => {
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
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: e.to_string(),
            }),
        ),
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: format!(
                    "systemctl {} {} timed out after 45s",
                    req.action, req.service
                ),
            }),
        ),
    }
}


async fn handle_package(Json(req): Json<PackageRunnerRequest>) -> Response {
    if !matches!(req.action.as_str(), "install" | "remove" | "update") {
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

    if !can_resolve_package_operation(&req.action, &req.package_id, &req.script_name) {
        return (StatusCode::NOT_FOUND, "package script not found").into_response();
    }

    let engine = select_package_engine(&req.package_id);
    let stream = execute_package_request_stream(req);

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

async fn handle_self_update(
    Json(req): Json<SelfUpdateRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let validated = match af_release::admin::validate_self_update_request(&req) {
        Ok(v) => v,
        Err(err_resp) => return (StatusCode::BAD_REQUEST, Json(err_resp)),
    };

    let engine_pref = env::var("AETHERFLOW_RELEASE_ENGINE")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let custom_script_override = env::var("AETHERFLOW_RELEASE_MANAGER_SCRIPT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let use_bash = engine_pref == "bash" || custom_script_override.is_some();

    if use_bash {
        let script_path = if let Some(ref custom) = custom_script_override {
            let p = PathBuf::from(custom);
            if p.is_file() {
                Some(p)
            } else {
                None
            }
        } else {
            resolve_release_manager_script()
        };

        let Some(script_path) = script_path else {
            return (
                StatusCode::NOT_FOUND,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: "release-manager.sh not found".to_string(),
                }),
            );
        };

        let cmd_name = validated.command.as_str().to_string();
        let channel = validated.channel.as_str().to_string();
        tokio::spawn(async move {
            let _ = Command::new("/bin/bash")
                .arg(&script_path)
                .arg(&cmd_name)
                .arg("--channel")
                .arg(&channel)
                .status()
                .await;
        });

        return (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: "Release manager initiated in root runner cgroup".to_string(),
                error: String::new(),
            }),
        );
    }

    tokio::task::spawn_blocking(move || {
        let conf_path = af_release::admin::resolve_release_manager_conf();
        let mut cfg = af_release::ReleaseConfig::load_from_process_env(conf_path.as_deref())
            .unwrap_or_default();
        cfg.release_channel = validated.channel;
        let (code, resp) = af_release::admin::execute_self_update_sync(&validated, cfg);
        if !resp.success {
            tracing::error!(
                exit_code = code.as_i32(),
                error = %resp.error,
                "Native af-release self-update failed"
            );
        } else {
            tracing::info!(output = %resp.output, "Native af-release self-update completed");
        }
    });

    (
        StatusCode::OK,
        Json(RunnerResponse {
            success: true,
            output: "Release manager initiated in root runner cgroup".to_string(),
            error: String::new(),
        }),
    )
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
    unit.ends_with(".timer") || unit.ends_with(".socket") || matches!(
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
    ) || unit.starts_with("wg-quick@")
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
        return SAFE_USERNAME.is_match(username).then(|| username.to_string());
    }
    let first = credentials.lines().next()?.trim();
    let username = first
        .strip_prefix("username=")
        .or_else(|| first.split_once(':').map(|(username, _)| username))?;
    SAFE_USERNAME.is_match(username).then(|| username.to_string())
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

pub fn render_systemd_sandbox_dropin(
    profile: &str,
    unit: &str,
    rw_paths: &[String],
) -> String {
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
                    (fields.len() >= 7 && fields[0] == service_user)
                        .then(|| fields[5].to_string())
                })
            })
            .unwrap_or_else(|| format!("/home/{}", service_user));
        let master_user = ["/var/lib/aetherflow/.master.creds", "/etc/aetherflow/.master.creds", "/root/.master.creds"]
            .iter()
            .find_map(|path| {
                fs::read_to_string(path)
                    .ok()
                    .and_then(|credentials| sandbox_master_user(&credentials))
            })
            .unwrap_or_else(|| service_user.clone());
        let mut expanded = Vec::with_capacity(rw_paths.len());
        for raw in rw_paths {
            expanded.push(expand_sandbox_path(raw, &service_user, &service_home, &master_user));
        }
        lines.push(format!("ReadWritePaths={}", expanded.join(" ")));
    }

    format!("{}\n", lines.join("\n"))
}

pub async fn apply_package_sandbox_local(pkg_id: &str) -> anyhow::Result<String> {
    if !SAFE_PKG_ID.is_match(pkg_id) {
        anyhow::bail!("invalid package identifier");
    }

    let pkg = get_runner_package_definition(pkg_id).unwrap_or_else(|| Package {
        name: pkg_id.to_string(),
        service_type: "systemd".to_string(),
        service_name: pkg_id.to_string(),
        sandbox_profile: "native".to_string(),
        sandbox_read_write: vec![format!("/var/lib/{}", pkg_id)],
        sandbox_service_ids: vec![format!("{}.service", pkg_id)],
        ..Default::default()
    });

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
        .filter(|s| !s.is_empty());

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

        if let Ok(out) = Command::new("bash").args(&args).output().await {
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
        let _ = Command::new("systemctl")
            .arg("daemon-reload")
            .output()
            .await;
    }

    Ok("sandbox applied".to_string())
}

async fn handle_sandbox(
    Json(req): Json<SandboxRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
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

    match apply_package_sandbox_local(&pkg).await {
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

async fn handle_hosts(
    Json(req): Json<HostsRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let mut domains = req.domains;
    if domains.is_empty() && !req.domain.is_empty() {
        domains.push(req.domain);
    }
    if domains.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "no domains specified".to_string(),
            }),
        );
    }

    for d in &domains {
        if !d.ends_with(".aether.local")
            || d.chars()
                .any(|c| matches!(c, ' ' | '\t' | '\r' | '\n' | ';' | '"' | '\'' | '$' | '`'))
            || d.len() > 253
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: format!("invalid domain format: {:?}", d),
                }),
            );
        }
    }

    let remove = req.action.eq_ignore_ascii_case("remove");
    match update_hosts_file_local(&domains, remove) {
        Ok(()) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: "hosts updated".to_string(),
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

pub fn update_hosts_file_local(domains: &[String], remove: bool) -> anyhow::Result<()> {
    let hosts_path = env::var("AETHERFLOW_HOSTS_FILE").unwrap_or_else(|_| "/etc/hosts".to_string());
    let existing = fs::read_to_string(&hosts_path).unwrap_or_default();

    const START_MARKER: &str = "# --- AETHERFLOW INTERNAL DNS ---";
    const END_MARKER: &str = "# --- END AETHERFLOW INTERNAL DNS ---";

    let mut outside_lines = Vec::new();
    let mut managed_domains = Vec::new();
    let mut in_block = false;

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed == START_MARKER {
            in_block = true;
            continue;
        }
        if trimmed == END_MARKER {
            in_block = false;
            continue;
        }
        if in_block {
            if let Some(dom) = trimmed.split_whitespace().nth(1) {
                if !managed_domains.contains(&dom.to_string()) {
                    managed_domains.push(dom.to_string());
                }
            }
        } else {
            outside_lines.push(line.to_string());
        }
    }

    if remove {
        managed_domains.retain(|d| !domains.contains(d));
    } else {
        for d in domains {
            if !managed_domains.contains(d) {
                managed_domains.push(d.clone());
            }
        }
    }

    let mut out = outside_lines.join("\n");
    if !out.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }
    if !managed_domains.is_empty() {
        out.push_str(START_MARKER);
        out.push('\n');
        for d in &managed_domains {
            out.push_str(&format!("127.0.0.1\t{}\n", d));
        }
        out.push_str(END_MARKER);
        out.push('\n');
    }

    fs::write(&hosts_path, out)?;
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
    if !SAFE_USERNAME.is_match(username) && !SAFE_USERNAME_REGEX.is_match(username) {
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

    if let Some(bin_setdisk) = bin_setdisk_opt {
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
    let out = Command::new("setquota")
        .args(["-u", username, &block_str, &block_str, "0", "0", "-a"])
        .output()
        .await?;
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

async fn handle_quota(
    Json(req): Json<QuotaRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if (!SAFE_USERNAME.is_match(&req.username) && !SAFE_USERNAME_REGEX.is_match(&req.username))
        || req.username.contains("..")
    {
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
    let pattern = format!(
        r"(?is)<{0}>\s*([^<]*?)\s*</{0}>",
        regex::escape(tag)
    );
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
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let Ok(conn) = rusqlite::Connection::open_with_flags(&resolved, flags) else {
        return String::new();
    };
    let _ = conn.busy_timeout(Duration::from_millis(1000));

    for q in queries {
        if let Ok(val) = conn.query_row(q, [], |row| row.get::<_, Option<String>>(0)) {
            if let Some(s) = val {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
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
                        meta.api_key =
                            extract_runner_ini_value(&content, &["api_key", "apikey"]);
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
            let env_paths = [
                "/etc/default/audiobookshelf",
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
                let port_val =
                    extract_runner_ini_value(&content, &["port", "webserver.port"]);
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
                "/var/lib/requestrr/settings.json",
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
            let candidates = [
                "/var/lib/seedcross/.env",
                "/opt/seedcross/.env",
                "/etc/seedcross/seedcross.env",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
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
            let candidates = [
                "/var/lib/thelounge/config.js",
                "/etc/thelounge/config.js",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(
                        &extract_runner_ini_value(&content, &["port"])
                            .trim_end_matches(',')
                            .to_string(),
                    );
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "filebrowser" => {
            let candidates = [
                "/etc/filebrowser/config.json",
                "/var/lib/filebrowser/filebrowser.json",
                "/var/lib/filebrowser/.filebrowser.json",
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

        "navidrome" => {
            let candidates = [
                "/var/lib/navidrome/navidrome.toml",
                "/etc/navidrome/navidrome.toml",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port =
                        parse_valid_runner_port(&extract_runner_ini_value(&content, &["Port", "port"]));
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
                    let mut port = parse_valid_runner_port(
                        &extract_runner_yaml_key_in_section(&content, "server", "port"),
                    );
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

        "calibre-web" => {
            let db_paths = [
                "/var/lib/calibre-web/app.db",
                "/opt/calibre-web/app.db",
            ];
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
            let candidates = ["/etc/default/prometheus", "/etc/prometheus/prometheus.yml"];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    let port = parse_valid_runner_port(&extract_runner_ini_value(
                        &content,
                        &["PORT", "port"],
                    ));
                    if port > 0 {
                        meta.configured_port = port;
                        break;
                    }
                }
            }
        }

        "uptime-kuma" => {
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

        "immich" => {
            let candidates = [
                "/var/lib/immich/.env",
                "/opt/immich/.env",
                "/etc/immich/immich.env",
            ];
            for raw_path in &candidates {
                if let Some(content) = read_runner_config_text(raw_path) {
                    if meta.api_key.is_empty() {
                        meta.api_key = extract_runner_ini_value(
                            &content,
                            &["IMMICH_API_KEY", "API_KEY"],
                        );
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

        _ => {}
    }

    meta
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
    if username.is_empty() || req.password.is_empty()
        || username.len() > 256 || req.password.len() > 4096
        || username.contains('\0') || req.password.contains('\0')
    {
        return (StatusCode::BAD_REQUEST, Json(RunnerResponse {
            success: false,
            output: String::new(),
            error: "invalid Dispatcharr credentials".to_string(),
        }));
    }
    if !Path::new("/opt/dispatcharr/manage.py").is_file() {
        return (StatusCode::OK, Json(RunnerResponse {
            success: true,
            output: "Dispatcharr is not installed".to_string(),
            error: String::new(),
        }));
    }
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        use tokio::io::AsyncWriteExt;
        let mut child = dispatcharr_credentials_command(username, &req.password).spawn()?;
        let mut input = child.stdin.take().ok_or_else(|| std::io::Error::other("missing stdin"))?;
        input.write_all(DISPATCHARR_ADMIN_SCRIPT.as_bytes()).await?;
        drop(input);
        child.wait().await
    }).await;
    let success = matches!(result, Ok(Ok(status)) if status.success());
    (if success { StatusCode::OK } else { StatusCode::INTERNAL_SERVER_ERROR }, Json(RunnerResponse {
        success,
        output: String::new(),
        error: if success { String::new() } else { "Dispatcharr credential sync failed".to_string() },
    }))
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
    };
    let result = post_runner_json("/v1/systemctl", &req, Duration::from_secs(45)).await?;
    if !result.success {
        anyhow::bail!("runner systemctl error: {} ({})", result.error, result.output);
    }
    Ok(())
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
                self.pending.extend_from_slice(&to_take[..to_take.len().min(room)]);
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
    mut on_line: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
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
            app_port,
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
        let _ = (action, pkg_id, script_name, app_port, &mut on_line);
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
    if !can_resolve_package_operation(action, pkg_id, script_name) {
        anyhow::bail!("package script not found");
    }

    let req = PackageRunnerRequest {
        action: action.to_string(),
        package_id: pkg_id.to_string(),
        script_name: script_name.to_string(),
        app_port,
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

pub async fn dispatch_self_update(command: &str, channel: &str) -> anyhow::Result<()> {
    let req = SelfUpdateRequest {
        command: command.to_string(),
        channel: channel.to_string(),
    };
    let result = post_runner_json("/v1/self-update", &req, Duration::from_secs(15)).await?;
    if !result.success {
        anyhow::bail!("runner self-update error: {}", result.error);
    }
    Ok(())
}

pub async fn dispatch_sandbox_apply(pkg_id: &str) -> anyhow::Result<()> {
    let req = SandboxRunnerRequest {
        package: pkg_id.to_string(),
        package_id: pkg_id.to_string(),
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

pub async fn dispatch_hosts_update(domains: &[String]) -> anyhow::Result<()> {
    let req = HostsRunnerRequest {
        action: "update".to_string(),
        domains: domains.to_vec(),
        ..Default::default()
    };
    let result = post_runner_json("/v1/hosts", &req, Duration::from_secs(15)).await?;
    if !result.success {
        anyhow::bail!("runner hosts error: {}", result.error);
    }
    Ok(())
}

pub async fn dispatch_hosts_remove(domains: &[String]) -> anyhow::Result<()> {
    let req = HostsRunnerRequest {
        action: "remove".to_string(),
        domains: domains.to_vec(),
        ..Default::default()
    };
    let result = post_runner_json("/v1/hosts", &req, Duration::from_secs(15)).await?;
    if !result.success {
        anyhow::bail!("runner hosts remove error: {}", result.error);
    }
    Ok(())
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

pub async fn dispatch_network_action(
    req: &NetworkRunnerRequest,
) -> anyhow::Result<RunnerResponse> {
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

/// Runs the Privileged Root Daemon (`aetherflow-api runner` / `--runner`) over `/run/aetherflow/runner.sock`.
#[cfg(unix)]
pub async fn run_privileged_daemon() -> anyhow::Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use std::os::unix::fs::PermissionsExt;
    use tower::Service;

    let sock_path = runner_socket_path();
    if let Some(dir) = Path::new(&sock_path).parent() {
        fs::create_dir_all(dir)?;
    }
    let _ = fs::remove_file(&sock_path);

    let listener = tokio::net::UnixListener::bind(&sock_path)?;
    let _ = fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o660));

    tracing::info!(socket = %sock_path, "AetherFlow Privileged Runner listening");
    let app = build_runner_router();

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                let (stream, _) = accept_res?;
                let io = TokioIo::new(stream);
                let tower_service = app.clone();
                tokio::spawn(async move {
                    let hyper_service = hyper::service::service_fn(
                        move |request: hyper::Request<hyper::body::Incoming>| {
                            let mut svc = tower_service.clone();
                            async move { svc.call(request.map(axum::body::Body::new)).await }
                        },
                    );
                    let _ = Builder::new(TokioExecutor::new())
                        .serve_connection(io, hyper_service)
                        .await;
                });
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Privileged Runner shutting down");
                let _ = fs::remove_file(&sock_path);
                break;
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn run_privileged_daemon() -> anyhow::Result<()> {
    tracing::warn!("UNIX domain socket runner mode requires a Unix/Linux host");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_script_resolution_prefers_current_release() {
        let defaults = package_script_roots();
        assert_eq!(defaults[0], PathBuf::from("/opt/AetherFlow/current/packages/package"));
        assert_eq!(defaults[1], PathBuf::from("/opt/AetherFlow/packages/package"));
        assert_eq!(defaults[2], PathBuf::from("/usr/local/bin/AetherFlow/package"));

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
        assert!(resolve_package_script_in_roots("invalid", "installpackage-dispatcharr", &roots).is_none());
        fs::remove_dir_all(scratch).unwrap();
    }

    #[tokio::test]
    async fn test_heal_restart_skips_active_package_operation() {
        let _operation = PACKAGE_MUTEX.lock().await;
        let (status, Json(response)) = handle_systemctl(Json(SystemctlRequest {
            service: "gitea".into(),
            action: "heal".into(),
        }))
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(response.success);
        assert_eq!(response.output, "skipped");
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
        assert_eq!(sandbox_master_user(r#"{"username":"media_owner","password":"secret"}"#), Some("media_owner".into()));
        assert_eq!(sandbox_master_user("username=media_owner\r\npassword=secret"), Some("media_owner".into()));
        assert_eq!(sandbox_master_user("media_owner:secret\n"), Some("media_owner".into()));
        assert_eq!(sandbox_master_user("username=../../etc"), None);
        assert_eq!(sandbox_master_user("password=secret"), None);
        assert_eq!(sandbox_master_user(""), None);
    }

    #[test]
    fn test_sandbox_paths_use_distinct_service_and_master_identities() {
        assert_eq!(
            expand_sandbox_path("-/home/{{MASTER_USER}}/Google/Media/Music Import", "sonarr", "/var/lib/sonarr", "media_owner"),
            "\"-/home/media_owner/Google/Media/Music Import\""
        );
        assert_eq!(
            expand_sandbox_path("-{{SERVICE_HOME}}/{{SERVICE_USER}}", "sonarr", "/var/lib/sonarr", "media_owner"),
            "-/var/lib/sonarr/sonarr"
        );
    }

    #[tokio::test]
    async fn test_handle_sandbox_and_quota_graceful_fallback() {
        let (code, Json(resp)) = handle_sandbox(Json(SandboxRunnerRequest {
            package: "sonarr".to_string(),
            package_id: String::new(),
        }))
        .await;
        assert_eq!(code, StatusCode::OK);
        assert!(resp.success);

        let (bad_code, Json(bad_resp)) = handle_sandbox(Json(SandboxRunnerRequest {
            package: "../evil".to_string(),
            package_id: String::new(),
        }))
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
        assert_eq!(dispatcharr_runtime_port("DISPATCHARR_PORT=\"9191\"\n"), 9191);
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
        let args: Vec<_> = command.get_args().map(|arg| arg.to_string_lossy()).collect();
        assert_eq!(&args[..5], &["-u", "dispatcharr", "--", "/bin/bash", "-ec"]);
        assert!(args.last().unwrap().contains("source /etc/dispatcharr/dispatcharr.env"));
        assert!(!args.iter().any(|arg| arg.contains(password) || arg.contains(username)));
        let variables: HashMap<_, _> = command.get_envs().collect();
        assert_eq!(variables[std::ffi::OsStr::new("AF_ADMIN_USER")], Some(std::ffi::OsStr::new(username)));
        assert_eq!(variables[std::ffi::OsStr::new("AF_ADMIN_PASS")], Some(std::ffi::OsStr::new(password)));
        assert!(DISPATCHARR_ADMIN_SCRIPT.contains("user.user_level = 10"));
        assert!(DISPATCHARR_ADMIN_SCRIPT.contains("os.environ[\"AF_ADMIN_PASS\"]"));
    }

    #[tokio::test]
    async fn test_dispatcharr_sync_rejects_invalid_credentials_before_execution() {
        for (username, password) in [("", "secret"), ("admin", ""), ("admin\0", "secret")] {
            let (status, Json(response)) = handle_dispatcharr_credentials(Json(DispatcharrCredentialsRequest {
                username: username.to_string(),
                password: password.to_string(),
            })).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(!response.success);
        }
    }

    #[tokio::test]
    async fn test_handle_package_cancel_validation_and_signalling() {
        let (bad_code, Json(bad_resp)) = handle_package_cancel(Json(SandboxRunnerRequest {
            package: "../bad".to_string(),
            package_id: String::new(),
        }))
        .await;
        assert_eq!(bad_code, StatusCode::BAD_REQUEST);
        assert!(!bad_resp.success);

        let tok = CancellationToken::new();
        let _guard = register_package_cancellation("cancel-handler-test", tok.clone()).unwrap();
        let (ok_code, Json(ok_resp)) = handle_package_cancel(Json(SandboxRunnerRequest {
            package: String::new(),
            package_id: "cancel-handler-test".to_string(),
        }))
        .await;
        assert_eq!(ok_code, StatusCode::OK);
        assert!(ok_resp.success);
        assert!(ok_resp.output.contains("cancellation signalled"));
        assert!(tok.is_cancelled());
    }

    #[tokio::test]
    async fn test_handle_self_update_accepts_experimental_and_validates_inputs() {
        let tmp_script = std::env::temp_dir().join(format!(
            "af-runner-self-update-test-{}.sh",
            std::process::id()
        ));
        fs::write(&tmp_script, "#!/bin/sh\nexit 0\n").unwrap();
        env::set_var("AETHERFLOW_RELEASE_MANAGER_SCRIPT", &tmp_script);

        for ch in ["stable", "nightly", "experimental"] {
            let (code, Json(resp)) = handle_self_update(Json(SelfUpdateRequest {
                command: "deploy".to_string(),
                channel: ch.to_string(),
            }))
            .await;
            assert_eq!(code, StatusCode::OK, "expected OK for channel {}", ch);
            assert!(resp.success);
            assert!(resp.output.contains("Release manager initiated"));
        }

        let (bad_ch_code, Json(bad_ch_resp)) = handle_self_update(Json(SelfUpdateRequest {
            command: "deploy".to_string(),
            channel: "invalid-channel".to_string(),
        }))
        .await;
        assert_eq!(bad_ch_code, StatusCode::BAD_REQUEST);
        assert!(!bad_ch_resp.success);
        assert_eq!(bad_ch_resp.error, "invalid update channel");

        let (bad_cmd_code, Json(bad_cmd_resp)) = handle_self_update(Json(SelfUpdateRequest {
            command: "rm-rf".to_string(),
            channel: "experimental".to_string(),
        }))
        .await;
        assert_eq!(bad_cmd_code, StatusCode::BAD_REQUEST);
        assert!(!bad_cmd_resp.success);
        assert_eq!(bad_cmd_resp.error, "invalid self-update command");

        env::remove_var("AETHERFLOW_RELEASE_MANAGER_SCRIPT");
        let _ = fs::remove_file(&tmp_script);
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
}
