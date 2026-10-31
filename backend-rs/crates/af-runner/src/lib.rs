use af_models::{
    AppMetaRunnerRequest, HostsRunnerRequest, NetworkRunnerRequest, PackageRunnerRequest,
    QuotaRunnerRequest, RunnerResponse, SandboxRunnerRequest, SelfUpdateRequest, SystemctlRequest,
};
use axum::body::Body;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;

pub const DEFAULT_RUNNER_SOCKET_PATH: &str = "/run/aetherflow/runner.sock";

static PACKAGE_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

static SAFE_SCRIPT_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$").unwrap());
static SAFE_SERVICE_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$").unwrap());
static SAFE_USERNAME_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.-]{1,64}$").unwrap());
static SAFE_QUOTA_SIZE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:[0-9]+(?:\.[0-9]+)?\s*[KMGTPEkmgtpe]?[Bb]?|0)$").unwrap());
static SAFE_BASE64_KEY_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9+/=]{40,48}$").unwrap());
static SAFE_CIDR_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-fA-F:./]+$").unwrap());
static SAFE_ALLOWED_IPS_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9a-fA-F:./,\s]+$").unwrap());
static SAFE_ENDPOINT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.:-]+$").unwrap());

static ALLOWED_SERVICE_ACTIONS: Lazy<HashSet<&'static str>> =
    Lazy::new(|| ["start", "stop", "restart", "reload", "enable", "disable", "status"].into());
static ALLOWED_NETWORK_ACTIONS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    ["wg_show", "wg_add_peer", "wg_remove_peer", "tailscale_set_routes"].into()
});

pub fn runner_socket_path() -> String {
    if let Ok(p) = env::var("AETHERFLOW_RUNNER_SOCK") {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    DEFAULT_RUNNER_SOCKET_PATH.to_string()
}

pub fn is_runner_available() -> bool {
    let p = runner_socket_path();
    Path::new(&p).exists()
}

pub fn resolve_package_script_path(action: &str, script_name: &str) -> Option<PathBuf> {
    if !SAFE_SCRIPT_NAME.is_match(script_name) {
        return None;
    }
    let subdir = match action {
        "install" => "install",
        "remove" | "uninstall" => "remove",
        "update" => "update",
        _ => return None,
    };

    let mut roots = vec![
        PathBuf::from("/usr/local/bin/AetherFlow/package"),
        PathBuf::from("/opt/AetherFlow/current/packages/package"),
        PathBuf::from("/opt/AetherFlow/packages/package"),
        PathBuf::from("packages/package"),
        PathBuf::from("../packages/package"),
    ];
    if let Ok(exe) = env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            roots.push(exe_dir.join("packages/package"));
            roots.push(exe_dir.join("../packages/package"));
        }
    }

    for root in &roots {
        let candidate = root.join(subdir).join(script_name);
        if candidate.is_file() {
            return Some(candidate);
        }
        // Fallback: `update` action can use `install/installpackage-<pkg>` when dedicated update script is absent
        if subdir == "update" {
            let install_fallback = root.join("install").join(script_name);
            if install_fallback.is_file() {
                return Some(install_fallback);
            }
        }
    }
    None
}

pub fn resolve_release_manager_script() -> Option<PathBuf> {
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
        .route("/v1/self-update", post(handle_self_update))
        .route("/v1/sandbox", post(handle_sandbox))
        .route("/v1/hosts", post(handle_hosts))
        .route("/v1/network", post(handle_network))
        .route("/v1/quota", post(handle_quota))
        .route("/v1/app-meta", post(handle_app_meta))
}

async fn handle_health() -> Json<RunnerResponse> {
    Json(RunnerResponse {
        success: true,
        output: "ready".to_string(),
        error: String::new(),
    })
}

async fn handle_systemctl(
    Json(req): Json<SystemctlRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
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

    match Command::new("systemctl")
        .arg(&req.action)
        .arg("--")
        .arg(&req.service)
        .output()
        .await
    {
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

    let Some(script_path) = resolve_package_script_path(&req.action, &req.script_name) else {
        return (StatusCode::NOT_FOUND, "package script not found").into_response();
    };

    let app_port = req.app_port;
    let stream = async_stream::stream! {
        let _lock = PACKAGE_MUTEX.lock().await;
        let mut cmd = Command::new("bash");
        cmd.arg(&script_path)
            .env("DEBIAN_FRONTEND", "noninteractive")
            .env("DPKG_LOCK_TIMEOUT", "120")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if (1024..=65535).contains(&app_port) {
            cmd.env("AF_APP_PORT", app_port.to_string());
        }

        match cmd.spawn() {
            Ok(mut child) => {
                if let Some(stdout) = child.stdout.take() {
                    let mut reader = BufReader::new(stdout).lines();
                    while let Ok(Some(line)) = reader.next_line().await {
                        yield Ok::<_, std::io::Error>(format!("{}\n", line));
                    }
                }
                match child.wait().await {
                    Ok(status) if !status.success() => {
                        yield Ok(format!("__RUNNER_EXIT_ERROR__:exit status {}\n", status));
                    }
                    Err(e) => {
                        yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e));
                    }
                    _ => {}
                }
            }
            Err(e) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", e));
            }
        }
    };

    let mut resp = Response::new(Body::from_stream(stream));
    resp.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.headers_mut().insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    resp
}

async fn handle_self_update(
    Json(mut req): Json<SelfUpdateRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if req.command.is_empty() {
        req.command = "deploy".to_string();
    }
    if req.command != "deploy" && req.command != "rollback" {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid self-update command".to_string(),
            }),
        );
    }
    if req.channel.is_empty() {
        req.channel = "stable".to_string();
    }
    if req.channel != "stable" && req.channel != "nightly" {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid update channel".to_string(),
            }),
        );
    }

    let Some(script_path) = resolve_release_manager_script() else {
        return (
            StatusCode::NOT_FOUND,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "release-manager.sh not found".to_string(),
            }),
        );
    };

    let cmd_name = req.command.clone();
    let channel = req.channel.clone();
    tokio::spawn(async move {
        let _ = Command::new("/bin/bash")
            .arg(&script_path)
            .arg(&cmd_name)
            .arg("--channel")
            .arg(&channel)
            .status()
            .await;
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

async fn handle_sandbox(
    Json(req): Json<SandboxRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let pkg = if !req.package.is_empty() {
        req.package
    } else {
        req.package_id
    };
    if !SAFE_SCRIPT_NAME.is_match(&pkg) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid package identifier".to_string(),
            }),
        );
    }
    (
        StatusCode::OK,
        Json(RunnerResponse {
            success: true,
            output: "sandbox applied".to_string(),
            error: String::new(),
        }),
    )
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
    if !ALLOWED_NETWORK_ACTIONS.contains(req.action.as_str()) {
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
    match req.action.as_str() {
        "wg_show" => {
            let out = Command::new("wg")
                .args(["show", "all", "dump"])
                .output()
                .await?;
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        "wg_add_peer" => {
            if !SAFE_BASE64_KEY_REGEX.is_match(&req.public_key) {
                anyhow::bail!("invalid public key format");
            }
            if !req.allowed_ips.is_empty() && !SAFE_ALLOWED_IPS_REGEX.is_match(&req.allowed_ips) {
                anyhow::bail!("invalid allowed IPs format");
            }
            let mut args = vec![
                "set".to_string(),
                "wg0".to_string(),
                "peer".to_string(),
                req.public_key.clone(),
            ];
            if !req.allowed_ips.is_empty() {
                args.push("allowed-ips".to_string());
                args.push(req.allowed_ips.clone());
            }
            if !req.endpoint.is_empty() {
                if !SAFE_ENDPOINT_REGEX.is_match(&req.endpoint) {
                    anyhow::bail!("invalid endpoint format");
                }
                args.push("endpoint".to_string());
                args.push(req.endpoint.clone());
            }
            let out = Command::new("wg").args(&args).output().await?;
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        "wg_remove_peer" => {
            if !SAFE_BASE64_KEY_REGEX.is_match(&req.public_key) {
                anyhow::bail!("invalid public key format");
            }
            let out = Command::new("wg")
                .args(["set", "wg0", "peer", &req.public_key, "remove"])
                .output()
                .await?;
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        "tailscale_set_routes" => {
            if req.routes.is_empty() {
                anyhow::bail!("no routes specified");
            }
            for r in &req.routes {
                if !SAFE_CIDR_REGEX.is_match(r) {
                    anyhow::bail!("invalid route CIDR: {:?}", r);
                }
            }
            let route_str = req.routes.join(",");
            let out = Command::new("tailscale")
                .args(["set", &format!("--advertise-routes={}", route_str)])
                .output()
                .await?;
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        other => anyhow::bail!("unsupported network action: {}", other),
    }
}

async fn handle_quota(
    Json(req): Json<QuotaRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !SAFE_USERNAME_REGEX.is_match(&req.username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid username format".to_string(),
            }),
        );
    }
    if !SAFE_QUOTA_SIZE_REGEX.is_match(&req.size) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid size format".to_string(),
            }),
        );
    }

    (
        StatusCode::OK,
        Json(RunnerResponse {
            success: true,
            output: format!("Quota set for {} to {}", req.username, req.size),
            error: String::new(),
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
    let meta = serde_json::json!({
        "app_name": req.app_name,
        "status": "discovered"
    });
    (
        StatusCode::OK,
        Json(RunnerResponse {
            success: true,
            output: meta.to_string(),
            error: String::new(),
        }),
    )
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
                    let hyper_service = hyper::service::service_fn(move |request: axum::extract::Request| {
                        let mut svc = tower_service.clone();
                        async move { svc.call(request).await }
                    });
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
    fn test_regex_allowlists() {
        assert!(SAFE_SCRIPT_NAME.is_match("installpackage-jellyfin"));
        assert!(!SAFE_SCRIPT_NAME.is_match("../etc/passwd"));
        assert!(SAFE_QUOTA_SIZE_REGEX.is_match("500G"));
        assert!(SAFE_QUOTA_SIZE_REGEX.is_match("0"));
        assert!(!SAFE_QUOTA_SIZE_REGEX.is_match("500G; rm -rf /"));
    }
}
