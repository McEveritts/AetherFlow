mod handlers;
mod isolation;
mod manifest;
#[cfg(test)]
mod tests;

pub use handlers::{
    handle_plugin_start, handle_plugin_status, handle_plugin_stop, handle_plugin_token_rotate,
};
pub use manifest::validate_loopback_api_base_url;

use af_models::RunnerResponse;
use axum::http::StatusCode;
use axum::Json;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex as AsyncMutex;

use manifest::validate_systemd_path_value;

pub const DEFAULT_PLUGIN_TOKENS_ROOT: &str = "/run/aetherflow-runner-plugin-tokens";
pub const PLUGIN_APP_MOUNT_POINT: &str = "/run/aetherflow-plugin-app";
pub const PLUGIN_TOKEN_MOUNT_POINT: &str = "/run/aetherflow-plugin-token";
pub const PLUGIN_TOKEN_FILE_IN_SANDBOX: &str = "/run/aetherflow-plugin-token/runtime.token";
pub(super) const MAX_PLUGIN_MANIFEST_BYTES: u64 = 256 * 1024;
pub(super) const MAX_PLUGIN_TOKEN_BYTES: usize = 8192;

static PLUGIN_RUNNER_LOCKS: Lazy<StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PluginRunnerError {
    #[error("{0}")]
    IsolationUnavailable(String),
    #[error("{0}")]
    InvalidRequest(String),
    #[error("{0}")]
    Runtime(String),
}

impl PluginRunnerError {
    pub(super) fn into_http_response(self) -> (StatusCode, Json<RunnerResponse>) {
        let (code, error) = match self {
            Self::IsolationUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
            Self::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::Runtime(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (
            code,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error,
            }),
        )
    }
}

pub(super) fn plugin_lock(plugin_id: &str) -> Arc<AsyncMutex<()>> {
    let mut locks = PLUGIN_RUNNER_LOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    locks
        .entry(plugin_id.to_string())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

pub(super) fn using_custom_systemd_run_override() -> bool {
    env::var("AETHERFLOW_SYSTEMD_RUN_BIN")
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
}

pub(super) fn resolve_plugin_systemd_run_binary() -> Option<(PathBuf, bool)> {
    if let Ok(explicit) = env::var("AETHERFLOW_SYSTEMD_RUN_BIN") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let candidate = PathBuf::from(trimmed);
            if candidate.is_file() {
                return Some((candidate, true));
            }
            return None;
        }
    }
    [
        PathBuf::from("/usr/bin/systemd-run"),
        PathBuf::from("/bin/systemd-run"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
    .map(|path| (path, false))
}

pub fn resolve_systemctl_binary() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("AETHERFLOW_SYSTEMCTL_BIN") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let candidate = PathBuf::from(trimmed);
            if candidate.is_file() {
                return Some(candidate);
            }
            return None;
        }
    }
    [
        PathBuf::from("/usr/bin/systemctl"),
        PathBuf::from("/bin/systemctl"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
}

pub(super) fn resolve_plugin_tokens_root() -> Result<PathBuf, PluginRunnerError> {
    let raw = env::var("AETHERFLOW_PLUGIN_TOKENS_ROOT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_PLUGIN_TOKENS_ROOT.to_string());
    let path = PathBuf::from(raw);
    validate_systemd_path_value(&path, "plugin tokens root")?;
    Ok(path)
}

pub fn ensure_systemd_isolation_ready() -> Result<(PathBuf, PathBuf), PluginRunnerError> {
    if !cfg!(target_os = "linux") {
        return Err(PluginRunnerError::IsolationUnavailable(
            "Managed plugin isolation is unavailable: independent OS and mount-namespace isolation requires a Linux host with systemd. Run the plugin as an external backend instead."
                .to_string(),
        ));
    }
    let (systemd_run, is_override) = resolve_plugin_systemd_run_binary().ok_or_else(|| {
        PluginRunnerError::IsolationUnavailable(
            "Managed plugin isolation is unavailable: systemd-run was not found (/usr/bin/systemd-run or /bin/systemd-run). Ensure systemd is installed and aetherflow-runner.service is active."
                .to_string(),
        )
    })?;
    let systemctl = resolve_systemctl_binary().ok_or_else(|| {
        PluginRunnerError::IsolationUnavailable(
            "Managed plugin isolation is unavailable: systemctl was not found (/usr/bin/systemctl or /bin/systemctl). Ensure systemd is installed and aetherflow-runner.service is active."
                .to_string(),
        )
    })?;

    if !is_override {
        #[cfg(unix)]
        if unsafe { libc::geteuid() } != 0 {
            return Err(PluginRunnerError::IsolationUnavailable(
                "Managed plugin isolation is unavailable: aetherflow-runner must run as root (UID 0) to spawn DynamicUser=yes systemd units isolated from the API OS account."
                    .to_string(),
            ));
        }
        if !Path::new("/run/systemd/system").is_dir() {
            return Err(PluginRunnerError::IsolationUnavailable(
                "Managed plugin isolation is unavailable: systemd PID 1 is not active (/run/systemd/system is absent). Managed plugin backends require a systemd-managed Linux host, or must be run as external backends."
                    .to_string(),
            ));
        }
    }

    Ok((systemd_run, systemctl))
}
