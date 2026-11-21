use af_models::{
    is_valid_plugin_id, plugin_stop_hook_unit_name, plugin_systemd_unit_name,
    PluginRunnerStartRequest, PluginRunnerStatusRequest, PluginRunnerStatusResponse,
    PluginRunnerStopRequest, PluginRunnerTokenRotateRequest, RunnerResponse, PLUGIN_PORT_RANGE_END,
    PLUGIN_PORT_RANGE_START,
};
use axum::http::StatusCode;
use axum::{Extension, Json};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use crate::{lookup_passwd_uid_reentrant, RunnerPeerCred};

pub const DEFAULT_PLUGIN_TOKENS_ROOT: &str = "/run/aetherflow-runner-plugin-tokens";
pub const PLUGIN_APP_MOUNT_POINT: &str = "/run/aetherflow-plugin-app";
pub const PLUGIN_TOKEN_MOUNT_POINT: &str = "/run/aetherflow-plugin-token";
pub const PLUGIN_TOKEN_FILE_IN_SANDBOX: &str = "/run/aetherflow-plugin-token/runtime.token";
const MAX_PLUGIN_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_PLUGIN_TOKEN_BYTES: usize = 8192;

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
    fn into_http_response(self) -> (StatusCode, Json<RunnerResponse>) {
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

#[derive(Debug, Clone, Deserialize, Default)]
struct RunnerPluginHooks {
    #[serde(default)]
    on_start: String,
    #[serde(default)]
    on_stop: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RunnerPluginBackend {
    #[serde(default)]
    manifest_path: String,
    #[serde(default)]
    binary_name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RunnerPluginManifest {
    id: String,
    name: String,
    version: String,
    #[serde(default)]
    lifecycle_hooks: RunnerPluginHooks,
    #[serde(default)]
    backend: RunnerPluginBackend,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedPluginStart {
    Binary(String),
    BashHook(String),
}

#[derive(Debug, Clone)]
struct VerifiedPluginSpec {
    id: String,
    name: String,
    version: String,
    plugin_dir: PathBuf,
    start_target: Option<ResolvedPluginStart>,
    stop_hook_rel: Option<String>,
}

fn plugin_lock(plugin_id: &str) -> Arc<AsyncMutex<()>> {
    let mut locks = PLUGIN_RUNNER_LOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    locks
        .entry(plugin_id.to_string())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

fn using_custom_systemd_run_override() -> bool {
    env::var("AETHERFLOW_SYSTEMD_RUN_BIN")
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
}

fn resolve_plugin_systemd_run_binary() -> Option<(PathBuf, bool)> {
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

fn resolve_plugins_dir() -> PathBuf {
    af_models::resolve_plugins_dir()
}

fn resolve_plugin_tokens_root() -> Result<PathBuf, PluginRunnerError> {
    let raw = env::var("AETHERFLOW_PLUGIN_TOKENS_ROOT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_PLUGIN_TOKENS_ROOT.to_string());
    let path = PathBuf::from(raw);
    validate_systemd_path_value(&path, "plugin tokens root")?;
    Ok(path)
}

fn validate_plugin_id(id: &str) -> Result<String, PluginRunnerError> {
    let trimmed = id.trim();
    if !is_valid_plugin_id(trimmed) || matches!(trimmed, "sdk-template" | "sdk-template-rust") {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Invalid plugin identifier '{}'",
            trimmed
        )));
    }
    Ok(trimmed.to_string())
}

fn validate_port(port: u16) -> Result<u16, PluginRunnerError> {
    if !(PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&port) {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Plugin port {} is outside permitted loopback range {}..={}",
            port, PLUGIN_PORT_RANGE_START, PLUGIN_PORT_RANGE_END
        )));
    }
    Ok(port)
}

fn validate_runtime_id(raw: &str) -> Result<String, PluginRunnerError> {
    let trimmed = raw.trim();
    let parsed = Uuid::parse_str(trimmed)
        .map_err(|_| PluginRunnerError::InvalidRequest("Invalid plugin runtime_id".to_string()))?;
    let canonical = parsed.hyphenated().to_string();
    if trimmed != canonical {
        return Err(PluginRunnerError::InvalidRequest(
            "Non-canonical plugin runtime_id".to_string(),
        ));
    }
    Ok(canonical)
}

pub fn validate_loopback_api_base_url(raw: &str) -> Result<String, PluginRunnerError> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty()
        || trimmed.len() > 128
        || trimmed
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '?' | '#' | '%'))
    {
        return Err(PluginRunnerError::InvalidRequest(
            "Invalid loopback AETHERFLOW_API_BASE_URL".to_string(),
        ));
    }
    let (scheme, rest) = if let Some(rest) = trimmed.strip_prefix("http://") {
        ("http", rest)
    } else if let Some(rest) = trimmed.strip_prefix("https://") {
        ("https", rest)
    } else {
        return Err(PluginRunnerError::InvalidRequest(
            "AETHERFLOW_API_BASE_URL must use http:// or https://".to_string(),
        ));
    };
    if rest.contains('/') {
        return Err(PluginRunnerError::InvalidRequest(
            "AETHERFLOW_API_BASE_URL must not contain a path".to_string(),
        ));
    }
    let (host, port_opt) = if let Some(ipv6_rest) = rest.strip_prefix("[::1]") {
        if ipv6_rest.is_empty() {
            ("[::1]", None)
        } else if let Some(port_str) = ipv6_rest.strip_prefix(':') {
            ("[::1]", Some(port_str))
        } else {
            return Err(PluginRunnerError::InvalidRequest(
                "Invalid IPv6 loopback AETHERFLOW_API_BASE_URL".to_string(),
            ));
        }
    } else if let Some((h, p)) = rest.split_once(':') {
        (h, Some(p))
    } else {
        (rest, None)
    };
    if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
        return Err(PluginRunnerError::InvalidRequest(
            "AETHERFLOW_API_BASE_URL must target loopback (127.0.0.1, ::1, or localhost)"
                .to_string(),
        ));
    }
    if let Some(port_str) = port_opt {
        let port = port_str.parse::<u16>().map_err(|_| {
            PluginRunnerError::InvalidRequest("Invalid port in AETHERFLOW_API_BASE_URL".to_string())
        })?;
        if port == 0 {
            return Err(PluginRunnerError::InvalidRequest(
                "Port 0 is not permitted in AETHERFLOW_API_BASE_URL".to_string(),
            ));
        }
        Ok(format!("{scheme}://{host}:{port}"))
    } else {
        Ok(format!("{scheme}://{host}"))
    }
}

fn validate_plugin_token(token: &str) -> Result<&str, PluginRunnerError> {
    if token.is_empty() || token.len() > MAX_PLUGIN_TOKEN_BYTES {
        return Err(PluginRunnerError::InvalidRequest(
            "Invalid plugin runtime token length".to_string(),
        ));
    }
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(PluginRunnerError::InvalidRequest(
            "Invalid characters in plugin runtime token".to_string(),
        ));
    }
    Ok(token)
}

fn validate_systemd_env_value(value: &str, label: &str) -> Result<String, PluginRunnerError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > 256
        || trimmed.chars().any(|c| c.is_control() || c == '\0')
    {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Invalid plugin manifest metadata for {label}"
        )));
    }
    Ok(trimmed.to_string())
}

fn validate_systemd_path_value(path: &Path, label: &str) -> Result<String, PluginRunnerError> {
    if !path.is_absolute() {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "{label} must be an absolute path"
        )));
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(PluginRunnerError::InvalidRequest(format!(
                "{label} must not contain '..'"
            )));
        }
    }
    let Some(s) = path.to_str() else {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "{label} must be valid UTF-8"
        )));
    };
    if s.is_empty()
        || s.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(c, '%' | ':' | ';' | '"' | '\'' | '\\' | '$' | '`')
        })
    {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "{label} contains characters unsupported by systemd isolation properties"
        )));
    }
    Ok(s.to_string())
}

fn validate_relative_segment_chars(rel: &str, label: &str) -> Result<(), PluginRunnerError> {
    if rel.is_empty()
        || rel.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(c, '%' | ':' | ';' | '"' | '\'' | '\\' | '$' | '`')
        })
    {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Plugin {label} contains disallowed characters"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn check_trusted_ownership(path: &Path) -> Result<std::fs::Metadata, PluginRunnerError> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path).map_err(|e| {
        PluginRunnerError::InvalidRequest(format!("Failed to stat '{}': {}", path.display(), e))
    })?;
    if meta.file_type().is_symlink() {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Symbolic link '{}' is forbidden inside plugin boundary",
            path.display()
        )));
    }
    let mode = meta.mode();
    if (mode & 0o002) != 0 {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Insecure world-writable permissions (mode {:o}) on '{}'",
            mode & 0o777,
            path.display()
        )));
    }
    let file_uid = meta.uid();
    let euid = unsafe { libc::geteuid() };
    if file_uid != 0 && file_uid != euid {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Untrusted owner uid={} on '{}' (must be root or runner uid={})",
            file_uid,
            path.display(),
            euid
        )));
    }
    Ok(meta)
}

#[cfg(not(unix))]
fn check_trusted_ownership(path: &Path) -> Result<std::fs::Metadata, PluginRunnerError> {
    fs::symlink_metadata(path).map_err(|e| {
        PluginRunnerError::InvalidRequest(format!("Failed to stat '{}': {}", path.display(), e))
    })
}

#[cfg(unix)]
fn check_isolated_user_accessible(
    path: &Path,
    meta: &std::fs::Metadata,
    require_exec: bool,
) -> Result<(), PluginRunnerError> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode();
    let needed = if meta.is_dir() || require_exec {
        0o005
    } else {
        0o004
    };
    if (mode & needed) != needed {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Plugin asset '{}' (mode {:o}) is not accessible to the isolated DynamicUser runtime (requires world-read{})",
            path.display(),
            mode & 0o777,
            if needed == 0o005 { "/execute" } else { "" }
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_isolated_user_accessible(
    _path: &Path,
    _meta: &std::fs::Metadata,
    _require_exec: bool,
) -> Result<(), PluginRunnerError> {
    Ok(())
}

fn validate_relative_plugin_file(
    canon_plugin_dir: &Path,
    raw_rel: &str,
    require_exec: bool,
    label: &str,
) -> Result<String, PluginRunnerError> {
    let trimmed = raw_rel.trim();
    validate_relative_segment_chars(trimmed, label)?;
    let rel_path = Path::new(trimmed);
    if rel_path.is_absolute() {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Absolute path in plugin {label} is forbidden"
        )));
    }
    let mut normalized_parts = Vec::new();
    let mut cursor = canon_plugin_dir.to_path_buf();
    for comp in rel_path.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(seg) => {
                let seg_str = seg.to_str().ok_or_else(|| {
                    PluginRunnerError::InvalidRequest(format!(
                        "Non-UTF-8 path component in plugin {label}"
                    ))
                })?;
                cursor.push(seg);
                let meta = check_trusted_ownership(&cursor)?;
                if meta.is_dir() {
                    check_isolated_user_accessible(&cursor, &meta, true)?;
                }
                normalized_parts.push(seg_str.to_string());
            }
            _ => {
                return Err(PluginRunnerError::InvalidRequest(format!(
                    "Path traversal in plugin {label} is forbidden"
                )));
            }
        }
    }
    if normalized_parts.is_empty() {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Empty plugin {label} path is forbidden"
        )));
    }
    let meta = check_trusted_ownership(&cursor)?;
    if !meta.is_file() {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Plugin {label} '{}' is not a regular file",
            trimmed
        )));
    }
    check_isolated_user_accessible(&cursor, &meta, require_exec)?;
    let canon_target = fs::canonicalize(&cursor).map_err(|e| {
        PluginRunnerError::InvalidRequest(format!("Failed to canonicalize plugin {label}: {}", e))
    })?;
    if !canon_target.starts_with(canon_plugin_dir) {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Plugin {label} escapes canonical plugin directory"
        )));
    }
    Ok(normalized_parts.join("/"))
}

fn load_verified_plugin_spec(plugin_id: &str) -> Result<VerifiedPluginSpec, PluginRunnerError> {
    let plugin_id = validate_plugin_id(plugin_id)?;
    let plugins_root = resolve_plugins_dir();
    let canon_root = fs::canonicalize(&plugins_root).map_err(|e| {
        PluginRunnerError::InvalidRequest(format!(
            "Plugins root '{}' is unavailable: {}",
            plugins_root.display(),
            e
        ))
    })?;
    let raw_plugin_dir = canon_root.join(&plugin_id);
    let dir_meta = check_trusted_ownership(&raw_plugin_dir)?;
    if !dir_meta.is_dir() {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Plugin '{}' directory does not exist",
            plugin_id
        )));
    }
    check_isolated_user_accessible(&raw_plugin_dir, &dir_meta, true)?;
    let canon_plugin_dir = fs::canonicalize(&raw_plugin_dir).map_err(|e| {
        PluginRunnerError::InvalidRequest(format!("Failed to canonicalize plugin dir: {}", e))
    })?;
    if !canon_plugin_dir.starts_with(&canon_root)
        || canon_plugin_dir.file_name().and_then(|n| n.to_str()) != Some(plugin_id.as_str())
    {
        return Err(PluginRunnerError::InvalidRequest(
            "Plugin directory escapes canonical plugins root".to_string(),
        ));
    }
    validate_systemd_path_value(&canon_plugin_dir, "plugin directory")?;

    let manifest_path = canon_plugin_dir.join("plugin.manifest.json");
    let manifest_meta = check_trusted_ownership(&manifest_path)?;
    if !manifest_meta.is_file() || manifest_meta.len() > MAX_PLUGIN_MANIFEST_BYTES {
        return Err(PluginRunnerError::InvalidRequest(
            "Invalid or oversized plugin.manifest.json".to_string(),
        ));
    }
    let raw_manifest = fs::read_to_string(&manifest_path).map_err(|e| {
        PluginRunnerError::InvalidRequest(format!("Failed to read plugin.manifest.json: {}", e))
    })?;
    let parsed: RunnerPluginManifest = serde_json::from_str(&raw_manifest).map_err(|e| {
        PluginRunnerError::InvalidRequest(format!("Invalid plugin.manifest.json: {}", e))
    })?;
    if parsed.id.trim() != plugin_id {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Plugin manifest id '{}' does not match requested plugin '{}'",
            parsed.id.trim(),
            plugin_id
        )));
    }
    let name = validate_systemd_env_value(&parsed.name, "name")?;
    let version = validate_systemd_env_value(&parsed.version, "version")?;

    let mut start_target = None;
    let bin = parsed.backend.binary_name.trim();
    if !bin.is_empty() {
        if bin.contains('/') || bin.contains('\\') || bin.contains("..") {
            return Err(PluginRunnerError::InvalidRequest(
                "Invalid backend.binary_name in plugin manifest".to_string(),
            ));
        }
        validate_relative_segment_chars(bin, "backend.binary_name")?;
        let mut candidates = Vec::with_capacity(8);
        let manifest_path_trimmed = parsed.backend.manifest_path.trim();
        if !manifest_path_trimmed.is_empty() {
            validate_relative_segment_chars(manifest_path_trimmed, "backend.manifest_path")?;
            let mp = Path::new(manifest_path_trimmed);
            if mp.is_absolute()
                || mp
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::RootDir))
            {
                return Err(PluginRunnerError::InvalidRequest(
                    "Invalid backend.manifest_path in plugin manifest".to_string(),
                ));
            }
            if let Some(parent) = mp.parent() {
                let parent_str = parent.to_string_lossy().trim_matches('/').to_string();
                if parent_str.is_empty() || parent_str == "." {
                    candidates.push(format!("target/release/{bin}"));
                    candidates.push(format!("target/debug/{bin}"));
                } else {
                    candidates.push(format!("{parent_str}/target/release/{bin}"));
                    candidates.push(format!("{parent_str}/target/debug/{bin}"));
                }
            }
        }
        for default_rel in [
            format!("backend-rs/target/release/{bin}"),
            format!("backend-rs/target/debug/{bin}"),
            format!("backend/target/release/{bin}"),
            format!("backend/target/debug/{bin}"),
            format!("bin/{bin}"),
            bin.to_string(),
        ] {
            if !candidates.contains(&default_rel) {
                candidates.push(default_rel);
            }
        }
        for rel in candidates {
            let candidate = canon_plugin_dir.join(&rel);
            if fs::symlink_metadata(&candidate).is_ok() {
                let validated_rel =
                    validate_relative_plugin_file(&canon_plugin_dir, &rel, true, "backend binary")?;
                start_target = Some(ResolvedPluginStart::Binary(validated_rel));
                break;
            }
        }
    }

    if start_target.is_none() && !parsed.lifecycle_hooks.on_start.trim().is_empty() {
        let hook_rel = validate_relative_plugin_file(
            &canon_plugin_dir,
            &parsed.lifecycle_hooks.on_start,
            false,
            "lifecycle_hooks.on_start",
        )?;
        start_target = Some(ResolvedPluginStart::BashHook(hook_rel));
    }

    let stop_hook_rel = if !parsed.lifecycle_hooks.on_stop.trim().is_empty() {
        Some(validate_relative_plugin_file(
            &canon_plugin_dir,
            &parsed.lifecycle_hooks.on_stop,
            false,
            "lifecycle_hooks.on_stop",
        )?)
    } else {
        None
    };

    Ok(VerifiedPluginSpec {
        id: plugin_id,
        name,
        version,
        plugin_dir: canon_plugin_dir,
        start_target,
        stop_hook_rel,
    })
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

#[cfg(unix)]
fn ensure_private_root_dir(dir: &Path, mode: u32) -> Result<(), PluginRunnerError> {
    use std::io::ErrorKind;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    if let Some(parent) = dir.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                PluginRunnerError::Runtime(format!(
                    "Failed to create parent directory '{}': {}",
                    parent.display(),
                    e
                ))
            })?;
        }
    }
    match fs::DirBuilder::new().mode(mode).create(dir) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(PluginRunnerError::Runtime(format!(
                "Failed to create directory '{}': {}",
                dir.display(),
                err
            )));
        }
    }
    let meta = fs::symlink_metadata(dir).map_err(|e| {
        PluginRunnerError::Runtime(format!("Failed to stat '{}': {}", dir.display(), e))
    })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(PluginRunnerError::Runtime(format!(
            "Unsafe non-directory or symlink at '{}'",
            dir.display()
        )));
    }
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(PluginRunnerError::Runtime(format!(
            "Directory '{}' is owned by uid={}, expected runner uid={}",
            dir.display(),
            meta.uid(),
            euid
        )));
    }
    if (meta.mode() & 0o777) != mode {
        fs::set_permissions(dir, fs::Permissions::from_mode(mode)).map_err(|e| {
            PluginRunnerError::Runtime(format!(
                "Failed to enforce mode {:o} on '{}': {}",
                mode,
                dir.display(),
                e
            ))
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_root_dir(_dir: &Path, _mode: u32) -> Result<(), PluginRunnerError> {
    Err(PluginRunnerError::IsolationUnavailable(
        "Managed plugin token isolation requires Unix".to_string(),
    ))
}

#[cfg(unix)]
fn write_staged_plugin_token(
    tokens_root: &Path,
    plugin_id: &str,
    runtime_id: &str,
    token: &str,
    must_exist: bool,
) -> Result<PathBuf, PluginRunnerError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    validate_plugin_token(token)?;
    ensure_private_root_dir(tokens_root, 0o700)?;
    let plugin_dir = tokens_root.join(plugin_id);
    ensure_private_root_dir(&plugin_dir, 0o700)?;

    // Prune stale runtime directories when launching a fresh runtime instance.
    if !must_exist {
        if let Ok(entries) = fs::read_dir(&plugin_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_str() != Some(runtime_id) {
                    let path = entry.path();
                    if let Ok(meta) = fs::symlink_metadata(&path) {
                        if meta.is_dir() && !meta.file_type().is_symlink() {
                            let _ = fs::remove_dir_all(&path);
                        } else {
                            let _ = fs::remove_file(&path);
                        }
                    }
                }
            }
        }
    }

    let runtime_dir = plugin_dir.join(runtime_id);
    if must_exist {
        let meta = fs::symlink_metadata(&runtime_dir).map_err(|_| {
            PluginRunnerError::InvalidRequest(
                "Active plugin runtime token directory does not exist".to_string(),
            )
        })?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(PluginRunnerError::Runtime(
                "Unsafe plugin runtime token directory".to_string(),
            ));
        }
    }
    ensure_private_root_dir(&runtime_dir, 0o755)?;

    let token_path = runtime_dir.join("runtime.token");
    let temp_path = runtime_dir.join(format!(".runtime-{}.tmp", Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)
        .map_err(|e| {
            PluginRunnerError::Runtime(format!("Failed to stage plugin token file: {}", e))
        })?;
    let write_res = file
        .write_all(token.as_bytes())
        .and_then(|_| file.set_permissions(fs::Permissions::from_mode(0o444)))
        .and_then(|_| file.sync_all())
        .and_then(|_| fs::rename(&temp_path, &token_path));
    if let Err(err) = write_res {
        let _ = fs::remove_file(&temp_path);
        return Err(PluginRunnerError::Runtime(format!(
            "Failed to publish plugin token file: {}",
            err
        )));
    }
    Ok(runtime_dir)
}

#[cfg(not(unix))]
fn write_staged_plugin_token(
    _tokens_root: &Path,
    _plugin_id: &str,
    _runtime_id: &str,
    _token: &str,
    _must_exist: bool,
) -> Result<PathBuf, PluginRunnerError> {
    Err(PluginRunnerError::IsolationUnavailable(
        "Managed plugin token isolation requires Unix".to_string(),
    ))
}

fn cleanup_plugin_tokens(tokens_root: &Path, plugin_id: &str) {
    let plugin_dir = tokens_root.join(plugin_id);
    if let Ok(meta) = fs::symlink_metadata(&plugin_dir) {
        if !meta.file_type().is_symlink() && meta.is_dir() {
            let _ = fs::remove_dir_all(&plugin_dir);
        }
    }
}

fn ensure_host_mountpoints() -> Result<(), PluginRunnerError> {
    if using_custom_systemd_run_override() {
        return Ok(());
    }
    ensure_private_root_dir(Path::new(PLUGIN_APP_MOUNT_POINT), 0o555)?;
    ensure_private_root_dir(Path::new(PLUGIN_TOKEN_MOUNT_POINT), 0o555)?;
    Ok(())
}

fn is_critical_os_root(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some(
            "/" | "/bin"
                | "/dev"
                | "/etc"
                | "/lib"
                | "/lib64"
                | "/opt"
                | "/proc"
                | "/run"
                | "/sbin"
                | "/sys"
                | "/tmp"
                | "/usr"
                | "/var"
                | "/var/lib"
                | "/var/log"
                | "/var/tmp"
        )
    )
}

fn collect_control_plane_inaccessible_paths(
    canon_plugin_dir: &Path,
    runtime_token_dir: Option<&Path>,
    tokens_root: &Path,
) -> Vec<String> {
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/var/lib/aetherflow"),
        PathBuf::from("/etc/aetherflow"),
        PathBuf::from("/etc/AetherFlow"),
        PathBuf::from("/run/aetherflow"),
        PathBuf::from("/var/log/aetherflow"),
        PathBuf::from("/opt/AetherFlow/backend"),
        PathBuf::from("/opt/AetherFlow/current/backend"),
    ];

    for key in [
        "DATA_DIR",
        "AETHERFLOW_BACKUP_DIR",
        "AF_BACKUP_DIR",
        "BACKUP_DIR",
    ] {
        if let Ok(val) = env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                candidates.push(PathBuf::from(trimmed));
            }
        }
    }

    for key in [
        "DB_PATH",
        "AETHERFLOW_DB_PATH",
        "AF_DB_PATH",
        "AETHERFLOW_RUNNER_SOCK",
        "AETHERFLOW_ENV_FILE",
    ] {
        if let Ok(val) = env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                let p = PathBuf::from(trimmed);
                if let Some(parent) = p.parent() {
                    if !is_critical_os_root(parent) {
                        candidates.push(parent.to_path_buf());
                    } else {
                        candidates.push(p);
                    }
                }
            }
        }
    }

    let mut result = BTreeSet::new();
    // Mask the host token staging root when it sorts strictly after the token mount
    // destination (avoiding systemd mount-order collisions) while keeping host 0700 DAC.
    let canon_tokens_root =
        fs::canonicalize(tokens_root).unwrap_or_else(|_| tokens_root.to_path_buf());
    if !is_critical_os_root(&canon_tokens_root)
        && !canon_plugin_dir.starts_with(&canon_tokens_root)
        && canon_tokens_root
            .to_str()
            .is_some_and(|s| s > PLUGIN_TOKEN_MOUNT_POINT)
    {
        if let Ok(validated) = validate_systemd_path_value(&canon_tokens_root, "tokens root") {
            result.insert(validated);
        }
    }
    for raw in candidates {
        let candidate = fs::canonicalize(&raw).unwrap_or(raw);
        if is_critical_os_root(&candidate) {
            continue;
        }
        let overlaps_plugin = canon_plugin_dir.starts_with(&candidate);
        let overlaps_token = runtime_token_dir.is_some_and(|td| td.starts_with(&candidate));
        if overlaps_plugin || overlaps_token {
            // If an operator staged data and plugins under the same parent, still mask
            // specific control-plane subpaths that cannot contain this plugin.
            for child in [
                "aetherflow.sqlite",
                "aetherflow.sqlite-wal",
                "aetherflow.sqlite-shm",
                "mcbrowser",
                "backups",
                "plugin-tokens",
                "aetherflow.env",
            ] {
                let sub = candidate.join(child);
                if !canon_plugin_dir.starts_with(&sub)
                    && !runtime_token_dir.is_some_and(|td| td.starts_with(&sub))
                {
                    if let Ok(validated) = validate_systemd_path_value(&sub, "inaccessible path") {
                        result.insert(validated);
                    }
                }
            }
            continue;
        }
        if let Ok(validated) = validate_systemd_path_value(&candidate, "inaccessible path") {
            result.insert(validated);
        }
    }

    // Also mask sibling plugin directories inside the same plugins root so a managed
    // plugin cannot inspect other plugins' static assets.
    if let Some(plugins_root) = canon_plugin_dir.parent() {
        if let Ok(entries) = fs::read_dir(plugins_root) {
            for entry in entries.flatten().take(64) {
                let sibling = entry.path();
                if sibling == canon_plugin_dir {
                    continue;
                }
                if let Ok(meta) = fs::symlink_metadata(&sibling) {
                    if !meta.file_type().is_symlink() && meta.is_dir() {
                        if let Ok(validated) =
                            validate_systemd_path_value(&sibling, "sibling plugin path")
                        {
                            result.insert(validated);
                        }
                    }
                }
            }
        }
    }

    result.into_iter().collect()
}

fn push_common_isolation_properties(
    args: &mut Vec<String>,
    spec: &VerifiedPluginSpec,
    port: u16,
    runtime_id: Option<&str>,
    api_base_url: &str,
    runtime_token_dir: Option<&Path>,
    tokens_root: &Path,
) -> Result<(), PluginRunnerError> {
    let plugin_dir_str = validate_systemd_path_value(&spec.plugin_dir, "plugin directory")?;
    let state_dir_name = format!("aetherflow-plugin-{}", spec.id);
    let state_dir_path = format!("/var/lib/{state_dir_name}");

    args.extend([
        "--property=DynamicUser=yes".to_string(),
        "--property=SupplementaryGroups=".to_string(),
        "--property=UMask=0077".to_string(),
        "--property=NoNewPrivileges=yes".to_string(),
        "--property=CapabilityBoundingSet=".to_string(),
        "--property=AmbientCapabilities=".to_string(),
        "--property=ProtectSystem=strict".to_string(),
        "--property=ProtectHome=yes".to_string(),
        "--property=PrivateTmp=yes".to_string(),
        "--property=PrivateDevices=yes".to_string(),
        "--property=ProtectClock=yes".to_string(),
        "--property=ProtectControlGroups=yes".to_string(),
        "--property=ProtectKernelLogs=yes".to_string(),
        "--property=ProtectKernelModules=yes".to_string(),
        "--property=ProtectKernelTunables=yes".to_string(),
        "--property=ProtectProc=invisible".to_string(),
        "--property=ProcSubset=all".to_string(),
        "--property=RemoveIPC=yes".to_string(),
        "--property=LockPersonality=yes".to_string(),
        "--property=RestrictNamespaces=yes".to_string(),
        "--property=RestrictRealtime=yes".to_string(),
        "--property=RestrictSUIDSGID=yes".to_string(),
        "--property=SystemCallArchitectures=native".to_string(),
        "--property=SystemCallFilter=@system-service".to_string(),
        "--property=SystemCallFilter=~@privileged @mount @debug @obsolete @cpu-emulation"
            .to_string(),
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6".to_string(),
        "--property=StandardInput=null".to_string(),
        "--property=StandardOutput=null".to_string(),
        "--property=StandardError=null".to_string(),
        format!("--property=SyslogIdentifier=aetherflow-plugin-{}", spec.id),
        format!("--property=StateDirectory={state_dir_name}"),
        "--property=StateDirectoryMode=0700".to_string(),
        format!("--property=BindReadOnlyPaths={plugin_dir_str}:{PLUGIN_APP_MOUNT_POINT}"),
        format!("--property=WorkingDirectory={PLUGIN_APP_MOUNT_POINT}"),
    ]);

    if let Some(token_dir) = runtime_token_dir {
        let token_dir_str = validate_systemd_path_value(token_dir, "plugin token directory")?;
        args.push(format!(
            "--property=BindReadOnlyPaths={token_dir_str}:{PLUGIN_TOKEN_MOUNT_POINT}"
        ));
    }

    for inaccessible in
        collect_control_plane_inaccessible_paths(&spec.plugin_dir, runtime_token_dir, tokens_root)
    {
        args.push(format!("--property=InaccessiblePaths=-{inaccessible}"));
    }

    // Explicitly pass only sanitized non-secret environment variables.
    args.extend([
        "--setenv=PATH=/usr/local/bin:/usr/bin:/bin".to_string(),
        format!("--setenv=PLUGIN_ID={}", spec.id),
        format!("--setenv=PLUGIN_NAME={}", spec.name),
        format!("--setenv=PLUGIN_VERSION={}", spec.version),
        "--setenv=PLUGIN_BIND_ADDR=127.0.0.1".to_string(),
        format!("--setenv=PLUGIN_PORT={port}"),
        format!("--setenv=PORT={port}"),
        format!("--setenv=AETHERFLOW_API_BASE_URL={api_base_url}"),
        format!("--setenv=PLUGIN_STATE_DIR={state_dir_path}"),
        format!("--setenv=AETHERFLOW_PLUGIN_STATE_DIR={state_dir_path}"),
        format!("--setenv=HOME={state_dir_path}"),
        "--setenv=TMPDIR=/tmp".to_string(),
    ]);
    if let Some(rid) = runtime_id {
        args.push(format!("--setenv=AETHERFLOW_PLUGIN_RUNTIME_ID={rid}"));
    }
    if runtime_token_dir.is_some() {
        args.push(format!(
            "--setenv=AETHERFLOW_PLUGIN_TOKEN_FILE={PLUGIN_TOKEN_FILE_IN_SANDBOX}"
        ));
    }

    Ok(())
}

fn build_plugin_start_systemd_run_args(
    unit_name: &str,
    spec: &VerifiedPluginSpec,
    port: u16,
    runtime_id: &str,
    api_base_url: &str,
    runtime_token_dir: &Path,
    tokens_root: &Path,
) -> Result<Vec<String>, PluginRunnerError> {
    let start_target = spec.start_target.as_ref().ok_or_else(|| {
        PluginRunnerError::InvalidRequest(format!(
            "Plugin '{}' has no managed backend executable or on_start hook",
            spec.id
        ))
    })?;

    let mut args = vec![
        "--no-ask-password".to_string(),
        format!("--unit={unit_name}"),
        format!(
            "--description=AetherFlow Isolated Plugin Backend ({})",
            spec.id
        ),
        "--collect".to_string(),
        "--quiet".to_string(),
        "--property=Type=exec".to_string(),
        "--property=Restart=no".to_string(),
        "--property=KillMode=control-group".to_string(),
        "--property=KillSignal=SIGTERM".to_string(),
        "--property=TimeoutStopSec=10s".to_string(),
    ];

    push_common_isolation_properties(
        &mut args,
        spec,
        port,
        Some(runtime_id),
        api_base_url,
        Some(runtime_token_dir),
        tokens_root,
    )?;

    if let Some(stop_rel) = &spec.stop_hook_rel {
        args.push(format!(
            "--property=ExecStop=/bin/bash {PLUGIN_APP_MOUNT_POINT}/{stop_rel}"
        ));
    }

    args.push("--".to_string());
    match start_target {
        ResolvedPluginStart::Binary(rel) => {
            args.push(format!("{PLUGIN_APP_MOUNT_POINT}/{rel}"));
        }
        ResolvedPluginStart::BashHook(rel) => {
            args.push("/bin/bash".to_string());
            args.push(format!("{PLUGIN_APP_MOUNT_POINT}/{rel}"));
        }
    }

    Ok(args)
}

fn build_plugin_stop_hook_systemd_run_args(
    stop_unit_name: &str,
    spec: &VerifiedPluginSpec,
    port: u16,
    runtime_id: Option<&str>,
    api_base_url: &str,
    runtime_token_dir: Option<&Path>,
    tokens_root: &Path,
) -> Result<Vec<String>, PluginRunnerError> {
    let stop_rel = spec.stop_hook_rel.as_ref().ok_or_else(|| {
        PluginRunnerError::InvalidRequest(format!(
            "Plugin '{}' has no lifecycle_hooks.on_stop hook",
            spec.id
        ))
    })?;

    let mut args = vec![
        "--no-ask-password".to_string(),
        format!("--unit={stop_unit_name}"),
        format!(
            "--description=AetherFlow Isolated Plugin Stop Hook ({})",
            spec.id
        ),
        "--wait".to_string(),
        "--collect".to_string(),
        "--quiet".to_string(),
        "--property=Type=oneshot".to_string(),
        "--property=Restart=no".to_string(),
        "--property=KillMode=control-group".to_string(),
        "--property=KillSignal=SIGTERM".to_string(),
        "--property=TimeoutStartSec=5s".to_string(),
        "--property=TimeoutStopSec=5s".to_string(),
    ];

    push_common_isolation_properties(
        &mut args,
        spec,
        port,
        runtime_id,
        api_base_url,
        runtime_token_dir,
        tokens_root,
    )?;

    args.push("--".to_string());
    args.push("/bin/bash".to_string());
    args.push(format!("{PLUGIN_APP_MOUNT_POINT}/{stop_rel}"));
    Ok(args)
}

#[derive(Debug, Default)]
struct UnitShowProps {
    active_state: String,
    sub_state: String,
    main_pid: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

fn parse_optional_u32(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "[not set]" {
        return None;
    }
    trimmed.parse::<u32>().ok()
}

#[cfg(target_os = "linux")]
fn read_proc_uid_gid(pid: u32) -> (Option<u32>, Option<u32>) {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return (None, None);
    };
    let mut uid = None;
    let mut gid = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest
                .split_whitespace()
                .nth(1)
                .or_else(|| rest.split_whitespace().next())
                .and_then(|v| v.parse::<u32>().ok());
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = rest
                .split_whitespace()
                .nth(1)
                .or_else(|| rest.split_whitespace().next())
                .and_then(|v| v.parse::<u32>().ok());
        }
    }
    (uid, gid)
}

#[cfg(not(target_os = "linux"))]
fn read_proc_uid_gid(_pid: u32) -> (Option<u32>, Option<u32>) {
    (None, None)
}

#[cfg(unix)]
fn lookup_group_gid_reentrant(group_name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(group_name).ok()?;
    let mut buf_len = 1024usize;
    const MAX_BUF_LEN: usize = 16 * 1024;
    while buf_len <= MAX_BUF_LEN {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::group = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; buf_len];
        let rc = unsafe {
            libc::getgrnam_r(
                c_name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr(),
                buf.len(),
                &mut res,
            )
        };
        if rc == 0 {
            if res.is_null() {
                return None;
            }
            return Some(grp.gr_gid as u32);
        }
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        return None;
    }
    None
}

async fn query_unit_properties(
    systemctl: &Path,
    unit_name: &str,
) -> Result<UnitShowProps, PluginRunnerError> {
    let mut cmd = Command::new(systemctl);
    cmd.args([
        "show",
        "--property=ActiveState",
        "--property=SubState",
        "--property=MainPID",
        "--property=UID",
        "--property=GID",
        unit_name,
    ])
    .kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(5), cmd.output())
        .await
        .map_err(|_| {
            PluginRunnerError::Runtime(format!(
                "systemctl show timed out for plugin unit '{unit_name}'"
            ))
        })?
        .map_err(|e| {
            PluginRunnerError::Runtime(format!(
                "Failed to execute systemctl show for '{unit_name}': {e}"
            ))
        })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(PluginRunnerError::Runtime(format!(
            "systemctl show failed for '{unit_name}': {}",
            stderr.trim()
        )));
    }
    let mut props = UnitShowProps::default();
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "ActiveState" => props.active_state = value.trim().to_string(),
                "SubState" => props.sub_state = value.trim().to_string(),
                "MainPID" => props.main_pid = parse_optional_u32(value).filter(|&p| p > 0),
                "UID" => props.uid = parse_optional_u32(value),
                "GID" => props.gid = parse_optional_u32(value),
                _ => {}
            }
        }
    }
    if (props.uid.is_none() || props.gid.is_none()) && props.main_pid.is_some() {
        if let Some(pid) = props.main_pid {
            let (proc_uid, proc_gid) = read_proc_uid_gid(pid);
            if props.uid.is_none() {
                props.uid = proc_uid;
            }
            if props.gid.is_none() {
                props.gid = proc_gid;
            }
        }
    }
    Ok(props)
}

fn verify_isolated_identity(
    props: &UnitShowProps,
    peer: Option<RunnerPeerCred>,
    strict_required: bool,
) -> Result<(), PluginRunnerError> {
    let Some(uid) = props.uid else {
        if strict_required {
            return Err(PluginRunnerError::Runtime(
                "Refusing managed plugin start: isolated systemd unit did not report a verified non-root UID"
                    .to_string(),
            ));
        }
        return Ok(());
    };
    let Some(gid) = props.gid else {
        if strict_required {
            return Err(PluginRunnerError::Runtime(
                "Refusing managed plugin start: isolated systemd unit did not report a verified non-root GID"
                    .to_string(),
            ));
        }
        return Ok(());
    };

    if uid == 0 || gid == 0 {
        return Err(PluginRunnerError::Runtime(format!(
            "Refusing managed plugin start: isolated unit resolved privileged root identity uid={uid} gid={gid}"
        )));
    }

    #[cfg(unix)]
    {
        if let Some(api_uid) = lookup_passwd_uid_reentrant("aetherflow") {
            if uid == api_uid {
                return Err(PluginRunnerError::Runtime(format!(
                    "Refusing managed plugin start: isolated unit uid={uid} matches aetherflow API user"
                )));
            }
        }
        if let Some(api_gid) = lookup_group_gid_reentrant("aetherflow") {
            if gid == api_gid {
                return Err(PluginRunnerError::Runtime(format!(
                    "Refusing managed plugin start: isolated unit gid={gid} matches aetherflow API group"
                )));
            }
        }
    }

    if let Some(cred) = peer {
        if cred.uid != 0 && uid == cred.uid {
            return Err(PluginRunnerError::Runtime(format!(
                "Refusing managed plugin start: isolated unit uid={uid} matches API caller OS uid={}",
                cred.uid
            )));
        }
        if cred.gid != 0 && gid == cred.gid {
            return Err(PluginRunnerError::Runtime(format!(
                "Refusing managed plugin start: isolated unit gid={gid} matches API caller OS gid={}",
                cred.gid
            )));
        }
    }

    Ok(())
}

async fn stop_and_reset_unit(systemctl: &Path, unit_name: &str) -> Result<(), PluginRunnerError> {
    let mut stop_cmd = Command::new(systemctl);
    stop_cmd.args(["stop", unit_name]).kill_on_drop(true);
    let stop_out = tokio::time::timeout(Duration::from_secs(20), stop_cmd.output())
        .await
        .map_err(|_| {
            PluginRunnerError::Runtime(format!(
                "systemctl stop timed out for plugin unit '{unit_name}'"
            ))
        })?
        .map_err(|e| {
            PluginRunnerError::Runtime(format!(
                "Failed to execute systemctl stop for '{unit_name}': {e}"
            ))
        })?;
    if !stop_out.status.success() {
        let stderr = String::from_utf8_lossy(&stop_out.stderr);
        let lower = stderr.to_ascii_lowercase();
        if !lower.contains("not loaded") && !lower.contains("could not be found") {
            return Err(PluginRunnerError::Runtime(format!(
                "systemctl stop failed for '{unit_name}': {}",
                stderr.trim()
            )));
        }
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(systemctl)
            .args(["reset-failed", unit_name])
            .kill_on_drop(true)
            .output(),
    )
    .await;
    Ok(())
}

pub async fn handle_plugin_start(
    peer: Option<Extension<RunnerPeerCred>>,
    Json(req): Json<PluginRunnerStartRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match handle_plugin_start_inner(peer.map(|Extension(c)| c), req).await {
        Ok(status) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: serde_json::to_string(&status).unwrap_or_default(),
                error: String::new(),
            }),
        ),
        Err(err) => err.into_http_response(),
    }
}

async fn handle_plugin_start_inner(
    peer: Option<RunnerPeerCred>,
    req: PluginRunnerStartRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let plugin_id = validate_plugin_id(&req.plugin_id)?;
    let port = validate_port(req.port)?;
    let runtime_id = validate_runtime_id(&req.runtime_id)?;
    let api_base_url = validate_loopback_api_base_url(&req.api_base_url)?;
    validate_plugin_token(&req.initial_token)?;

    let (systemd_run, systemctl) = ensure_systemd_isolation_ready()?;
    let lock = plugin_lock(&plugin_id);
    let _guard = lock.lock().await;

    let spec = load_verified_plugin_spec(&plugin_id)?;
    if spec.start_target.is_none() {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Plugin '{}' has no managed backend executable or on_start hook",
            spec.id
        )));
    }
    let unit_name = plugin_systemd_unit_name(&plugin_id)
        .ok_or_else(|| PluginRunnerError::InvalidRequest("Invalid plugin id".to_string()))?;
    let tokens_root = resolve_plugin_tokens_root()?;

    ensure_host_mountpoints()?;

    // Ensure no stale unit instance remains before staging the fresh runtime.
    let _ = stop_and_reset_unit(&systemctl, &unit_name).await;

    let runtime_token_dir = write_staged_plugin_token(
        &tokens_root,
        &plugin_id,
        &runtime_id,
        &req.initial_token,
        false,
    )?;

    let args = match build_plugin_start_systemd_run_args(
        &unit_name,
        &spec,
        port,
        &runtime_id,
        &api_base_url,
        &runtime_token_dir,
        &tokens_root,
    ) {
        Ok(args) => args,
        Err(err) => {
            cleanup_plugin_tokens(&tokens_root, &plugin_id);
            return Err(err);
        }
    };

    let launch_res = tokio::time::timeout(
        Duration::from_secs(15),
        Command::new(&systemd_run)
            .args(&args)
            .kill_on_drop(true)
            .output(),
    )
    .await;

    match launch_res {
        Ok(Ok(out)) if out.status.success() => {}
        Ok(Ok(out)) => {
            let detail = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
            cleanup_plugin_tokens(&tokens_root, &plugin_id);
            let sanitized = detail.trim();
            let lower = sanitized.to_ascii_lowercase();
            if lower.contains("failed to connect to bus")
                || lower.contains("system has not been booted with systemd")
                || lower.contains("interactive authentication required")
            {
                return Err(PluginRunnerError::IsolationUnavailable(format!(
                    "Managed plugin isolation is unavailable: systemd manager rejected transient unit '{unit_name}': {sanitized}"
                )));
            }
            return Err(PluginRunnerError::Runtime(format!(
                "Failed to start isolated plugin unit '{unit_name}': {sanitized}"
            )));
        }
        Ok(Err(err)) => {
            cleanup_plugin_tokens(&tokens_root, &plugin_id);
            return Err(PluginRunnerError::Runtime(format!(
                "Failed to execute systemd-run for '{unit_name}': {err}"
            )));
        }
        Err(_) => {
            let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
            cleanup_plugin_tokens(&tokens_root, &plugin_id);
            return Err(PluginRunnerError::Runtime(format!(
                "Timed out launching isolated plugin unit '{unit_name}'"
            )));
        }
    }

    let props = match query_unit_properties(&systemctl, &unit_name).await {
        Ok(props) => props,
        Err(err) => {
            let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
            cleanup_plugin_tokens(&tokens_root, &plugin_id);
            return Err(err);
        }
    };

    let strict_identity = !using_custom_systemd_run_override();
    if let Err(err) = verify_isolated_identity(&props, peer, strict_identity) {
        let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
        cleanup_plugin_tokens(&tokens_root, &plugin_id);
        return Err(err);
    }

    let active = matches!(props.active_state.as_str(), "active" | "activating");
    if !active {
        let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
        cleanup_plugin_tokens(&tokens_root, &plugin_id);
        return Err(PluginRunnerError::Runtime(format!(
            "Isolated plugin unit '{unit_name}' failed to enter active state (state={} sub={})",
            props.active_state, props.sub_state
        )));
    }

    Ok(PluginRunnerStatusResponse {
        plugin_id,
        unit_name,
        active,
        sub_state: props.sub_state,
        runtime_id: Some(runtime_id),
        uid: props.uid,
        gid: props.gid,
    })
}

pub async fn handle_plugin_stop(
    Json(req): Json<PluginRunnerStopRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match handle_plugin_stop_inner(req).await {
        Ok(status) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: serde_json::to_string(&status).unwrap_or_default(),
                error: String::new(),
            }),
        ),
        Err(err) => err.into_http_response(),
    }
}

async fn handle_plugin_stop_inner(
    req: PluginRunnerStopRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let plugin_id = validate_plugin_id(&req.plugin_id)?;
    let port = if req.port == 0 {
        0
    } else {
        validate_port(req.port)?
    };
    let runtime_id = match req.runtime_id.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(validate_runtime_id(raw)?),
        _ => None,
    };
    let api_base_url = if req.api_base_url.trim().is_empty() {
        "http://127.0.0.1:8080".to_string()
    } else {
        validate_loopback_api_base_url(&req.api_base_url)?
    };

    let (systemd_run, systemctl) = ensure_systemd_isolation_ready()?;
    let lock = plugin_lock(&plugin_id);
    let _guard = lock.lock().await;

    let unit_name = plugin_systemd_unit_name(&plugin_id)
        .ok_or_else(|| PluginRunnerError::InvalidRequest("Invalid plugin id".to_string()))?;
    let tokens_root = resolve_plugin_tokens_root()?;

    let pre_props = query_unit_properties(&systemctl, &unit_name).await.ok();
    let was_active = pre_props.as_ref().is_some_and(|p| {
        matches!(
            p.active_state.as_str(),
            "active" | "activating" | "reloading"
        )
    });

    let stop_result = if was_active {
        // Active managed units execute their validated `ExecStop=` hook inside the same
        // DynamicUser/StateDirectory sandbox before systemd sweeps the control group.
        stop_and_reset_unit(&systemctl, &unit_name).await
    } else {
        let _ = stop_and_reset_unit(&systemctl, &unit_name).await;
        if req.run_stop_hook {
            if let Ok(spec) = load_verified_plugin_spec(&plugin_id) {
                if spec.stop_hook_rel.is_some() {
                    ensure_host_mountpoints()?;
                    let stop_unit = plugin_stop_hook_unit_name(&plugin_id).ok_or_else(|| {
                        PluginRunnerError::InvalidRequest("Invalid plugin id".to_string())
                    })?;
                    let existing_token_dir = runtime_id
                        .as_deref()
                        .map(|rid| tokens_root.join(&plugin_id).join(rid))
                        .filter(|p| {
                            fs::symlink_metadata(p)
                                .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
                        });
                    let stop_args = build_plugin_stop_hook_systemd_run_args(
                        &stop_unit,
                        &spec,
                        port,
                        runtime_id.as_deref(),
                        &api_base_url,
                        existing_token_dir.as_deref(),
                        &tokens_root,
                    )?;
                    let run_res = tokio::time::timeout(
                        Duration::from_secs(10),
                        Command::new(&systemd_run)
                            .args(&stop_args)
                            .kill_on_drop(true)
                            .output(),
                    )
                    .await;
                    if run_res.is_err() {
                        let _ = stop_and_reset_unit(&systemctl, &stop_unit).await;
                    } else {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(3),
                            Command::new(&systemctl)
                                .args(["reset-failed", &stop_unit])
                                .kill_on_drop(true)
                                .output(),
                        )
                        .await;
                    }
                }
            }
        }
        Ok(())
    };

    cleanup_plugin_tokens(&tokens_root, &plugin_id);
    stop_result?;

    Ok(PluginRunnerStatusResponse {
        plugin_id,
        unit_name,
        active: false,
        sub_state: "dead".to_string(),
        runtime_id: None,
        uid: None,
        gid: None,
    })
}

pub async fn handle_plugin_status(
    Json(req): Json<PluginRunnerStatusRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match handle_plugin_status_inner(req).await {
        Ok(status) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: serde_json::to_string(&status).unwrap_or_default(),
                error: String::new(),
            }),
        ),
        Err(err) => err.into_http_response(),
    }
}

async fn handle_plugin_status_inner(
    req: PluginRunnerStatusRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let plugin_id = validate_plugin_id(&req.plugin_id)?;
    let runtime_id = match req.runtime_id.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(validate_runtime_id(raw)?),
        _ => None,
    };
    let (_, systemctl) = ensure_systemd_isolation_ready()?;
    let unit_name = plugin_systemd_unit_name(&plugin_id)
        .ok_or_else(|| PluginRunnerError::InvalidRequest("Invalid plugin id".to_string()))?;

    let props = query_unit_properties(&systemctl, &unit_name).await?;
    let active = matches!(props.active_state.as_str(), "active" | "activating");
    Ok(PluginRunnerStatusResponse {
        plugin_id,
        unit_name,
        active,
        sub_state: props.sub_state,
        runtime_id: if active { runtime_id } else { None },
        uid: props.uid,
        gid: props.gid,
    })
}

pub async fn handle_plugin_token_rotate(
    Json(req): Json<PluginRunnerTokenRotateRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match handle_plugin_token_rotate_inner(req).await {
        Ok(()) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output: "rotated".to_string(),
                error: String::new(),
            }),
        ),
        Err(err) => err.into_http_response(),
    }
}

async fn handle_plugin_token_rotate_inner(
    req: PluginRunnerTokenRotateRequest,
) -> Result<(), PluginRunnerError> {
    let plugin_id = validate_plugin_id(&req.plugin_id)?;
    let runtime_id = validate_runtime_id(&req.runtime_id)?;
    validate_plugin_token(&req.token)?;

    let (_, systemctl) = ensure_systemd_isolation_ready()?;
    let lock = plugin_lock(&plugin_id);
    let _guard = lock.lock().await;

    let unit_name = plugin_systemd_unit_name(&plugin_id)
        .ok_or_else(|| PluginRunnerError::InvalidRequest("Invalid plugin id".to_string()))?;
    let props = query_unit_properties(&systemctl, &unit_name).await?;
    if !matches!(props.active_state.as_str(), "active" | "activating") {
        return Err(PluginRunnerError::Runtime(format!(
            "Cannot rotate token: isolated plugin unit '{unit_name}' is not active"
        )));
    }
    let tokens_root = resolve_plugin_tokens_root()?;
    let _ = write_staged_plugin_token(&tokens_root, &plugin_id, &runtime_id, &req.token, true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_fixture_plugin(root: &Path, plugin_id: &str, with_stop_hook: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let plugin_dir = root.join(plugin_id);
        let hooks_dir = plugin_dir.join("backend/hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        fs::set_permissions(&plugin_dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            plugin_dir.join("backend"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::set_permissions(&hooks_dir, fs::Permissions::from_mode(0o755)).unwrap();

        let start_hook = hooks_dir.join("start.sh");
        fs::write(&start_hook, "#!/bin/bash\nexit 0\n").unwrap();
        fs::set_permissions(&start_hook, fs::Permissions::from_mode(0o755)).unwrap();

        let mut hooks = serde_json::json!({
            "on_start": "backend/hooks/start.sh"
        });
        if with_stop_hook {
            let stop_hook = hooks_dir.join("stop.sh");
            fs::write(&stop_hook, "#!/bin/bash\nexit 0\n").unwrap();
            fs::set_permissions(&stop_hook, fs::Permissions::from_mode(0o755)).unwrap();
            hooks["on_stop"] = serde_json::json!("backend/hooks/stop.sh");
        }

        let manifest = serde_json::json!({
            "id": plugin_id,
            "name": "Fixture Plugin",
            "version": "1.2.3",
            "lifecycle_hooks": hooks,
            "backend": {
                "health_path": "/healthz"
            }
        });
        let manifest_path = plugin_dir.join("plugin.manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o644)).unwrap();
        plugin_dir
    }

    #[test]
    fn request_debug_redacts_plugin_tokens() {
        let start_req = PluginRunnerStartRequest {
            plugin_id: "demo-plugin".into(),
            port: 21001,
            runtime_id: Uuid::new_v4().to_string(),
            api_base_url: "http://127.0.0.1:8080".into(),
            initial_token: "super-secret-jwt-value".into(),
        };
        let rendered = format!("{start_req:?}");
        assert!(!rendered.contains("super-secret-jwt-value"));
        assert!(rendered.contains("[REDACTED]"));

        let rotate_req = PluginRunnerTokenRotateRequest {
            plugin_id: "demo-plugin".into(),
            runtime_id: Uuid::new_v4().to_string(),
            token: "another-secret-jwt-value".into(),
        };
        let rendered_rot = format!("{rotate_req:?}");
        assert!(!rendered_rot.contains("another-secret-jwt-value"));
        assert!(rendered_rot.contains("[REDACTED]"));
    }

    #[test]
    fn validates_loopback_api_base_url_and_rejects_external_or_malformed_inputs() {
        assert_eq!(
            validate_loopback_api_base_url("http://127.0.0.1:8080/").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            validate_loopback_api_base_url("http://[::1]:8080").unwrap(),
            "http://[::1]:8080"
        );
        assert_eq!(
            validate_loopback_api_base_url("http://localhost:18080").unwrap(),
            "http://localhost:18080"
        );
        for bad in [
            "",
            "http://169.254.169.254:80",
            "http://example.com:8080",
            "http://127.0.0.1:8080/api",
            "http://user@127.0.0.1:8080",
            "http://127.0.0.1:8080?x=1",
            "http://127.0.0.1:0",
            "file:///etc/passwd",
            "http://127.0.0.1:8080\nINJECT=1",
        ] {
            assert!(
                validate_loopback_api_base_url(bad).is_err(),
                "expected rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_ids_ports_tokens_and_symlink_manifests() {
        assert!(validate_plugin_id("../escape").is_err());
        assert!(validate_plugin_id("sdk-template-rust").is_err());
        assert!(validate_plugin_id("BadUpper").is_err());
        assert!(validate_port(8080).is_err());
        assert!(validate_port(20999).is_err());
        assert!(validate_port(22000).is_err());
        assert!(validate_plugin_token("").is_err());
        assert!(validate_plugin_token("abc\ndef").is_err());
        assert!(validate_plugin_token("abc def").is_err());
        assert!(validate_plugin_token("abc;id").is_err());
        assert!(validate_plugin_token("eyJhbGciOiJIUzI1NiJ9.payload.sig_1-2").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn systemd_run_args_enforce_isolation_and_keep_credentials_out_of_argv() {
        let tmp = env::temp_dir().join(format!("af-runner-plugin-args-{}", Uuid::new_v4()));
        let plugins_root = tmp.join("plugins");
        let tokens_root = tmp.join("tokens");
        let plugin_dir = write_fixture_plugin(&plugins_root, "telemetry-fixture", true);
        let sibling_dir = write_fixture_plugin(&plugins_root, "other-plugin", false);

        let _env_guard = crate::ENV_TEST_MUTEX.blocking_lock();
        let prev_plugins = env::var_os("AETHERFLOW_PLUGINS_DIR");
        env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);

        let spec = load_verified_plugin_spec("telemetry-fixture").unwrap();
        let runtime_id = Uuid::new_v4().to_string();
        let token_secret = "eyJhbGciOiJIUzI1NiJ9.fixture_secret_payload.signature123";
        let runtime_token_dir = write_staged_plugin_token(
            &tokens_root,
            "telemetry-fixture",
            &runtime_id,
            token_secret,
            false,
        )
        .unwrap();

        let args = build_plugin_start_systemd_run_args(
            "aetherflow-plugin-telemetry-fixture.service",
            &spec,
            21042,
            &runtime_id,
            "http://127.0.0.1:8080",
            &runtime_token_dir,
            &tokens_root,
        )
        .unwrap();

        if let Some(v) = prev_plugins {
            env::set_var("AETHERFLOW_PLUGINS_DIR", v);
        } else {
            env::remove_var("AETHERFLOW_PLUGINS_DIR");
        }

        let joined = args.join("\n");
        assert!(args.iter().any(|a| a == "--property=DynamicUser=yes"));
        assert!(args.iter().any(|a| a == "--property=SupplementaryGroups="));
        assert!(args.iter().any(|a| a == "--property=ProtectSystem=strict"));
        assert!(args.iter().any(|a| a == "--property=ProtectHome=yes"));
        assert!(args.iter().any(|a| a == "--property=PrivateTmp=yes"));
        assert!(args.iter().any(|a| a == "--property=PrivateDevices=yes"));
        assert!(args.iter().any(|a| a == "--property=NoNewPrivileges=yes"));
        assert!(args
            .iter()
            .any(|a| a == "--property=CapabilityBoundingSet="));
        assert!(args.iter().any(|a| a == "--property=ProtectProc=invisible"));
        assert!(args
            .iter()
            .any(|a| a == "--property=StateDirectory=aetherflow-plugin-telemetry-fixture"));
        assert!(args
            .iter()
            .any(|a| a == "--property=StateDirectoryMode=0700"));
        assert!(args
            .iter()
            .any(|a| a == "--property=InaccessiblePaths=-/var/lib/aetherflow"));
        assert!(args
            .iter()
            .any(|a| a == "--property=InaccessiblePaths=-/etc/aetherflow"));
        assert!(args
            .iter()
            .any(|a| a == "--property=InaccessiblePaths=-/run/aetherflow"));
        assert!(args
            .iter()
            .any(|a| a == "--property=InaccessiblePaths=-/var/log/aetherflow"));
        let default_inaccessible = collect_control_plane_inaccessible_paths(
            &fs::canonicalize(&plugin_dir).unwrap(),
            Some(&runtime_token_dir),
            Path::new(DEFAULT_PLUGIN_TOKENS_ROOT),
        );
        assert!(
            default_inaccessible
                .iter()
                .any(|p| p == DEFAULT_PLUGIN_TOKENS_ROOT),
            "default tokens root must be masked in InaccessiblePaths: {default_inaccessible:?}"
        );
        assert!(args.iter().any(|a| a
            == &format!(
                "--property=InaccessiblePaths=-{}",
                fs::canonicalize(&sibling_dir).unwrap().display()
            )));
        assert!(args.iter().any(|a| a
            == &format!(
                "--property=BindReadOnlyPaths={}:{PLUGIN_APP_MOUNT_POINT}",
                fs::canonicalize(&plugin_dir).unwrap().display()
            )));
        assert!(args.iter().any(|a| a
            == &format!(
                "--property=BindReadOnlyPaths={}:{PLUGIN_TOKEN_MOUNT_POINT}",
                runtime_token_dir.display()
            )));
        assert!(args.iter().any(|a| a
            == &format!(
                "--property=ExecStop=/bin/bash {PLUGIN_APP_MOUNT_POINT}/backend/hooks/stop.sh"
            )));
        assert!(args.iter().any(|a| a
            == &format!("--setenv=AETHERFLOW_PLUGIN_TOKEN_FILE={PLUGIN_TOKEN_FILE_IN_SANDBOX}")));
        assert!(
            !joined.contains(token_secret),
            "Plugin runtime token MUST NEVER appear in systemd-run argv!"
        );
        assert!(
            !joined.contains("AETHERFLOW_PLUGIN_TOKEN="),
            "Raw AETHERFLOW_PLUGIN_TOKEN env var must not be passed in argv!"
        );
        assert_eq!(
            fs::read_to_string(runtime_token_dir.join("runtime.token")).unwrap(),
            token_secret
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn staged_token_replacement_is_atomic_private_and_rejects_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let tmp = env::temp_dir().join(format!("af-runner-token-stage-{}", Uuid::new_v4()));
        let tokens_root = tmp.join("tokens");
        let rid = Uuid::new_v4().to_string();

        let runtime_dir =
            write_staged_plugin_token(&tokens_root, "demo-plugin", &rid, "token.one.sig", false)
                .unwrap();
        assert_eq!(
            fs::metadata(&tokens_root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(tokens_root.join("demo-plugin"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let token_path = runtime_dir.join("runtime.token");
        assert_eq!(
            fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
            0o444
        );

        let mut old_reader = fs::File::open(&token_path).unwrap();
        write_staged_plugin_token(&tokens_root, "demo-plugin", &rid, "token.two.sig", true)
            .unwrap();
        let mut old_val = String::new();
        std::io::Read::read_to_string(&mut old_reader, &mut old_val).unwrap();
        assert_eq!(old_val, "token.one.sig");
        assert_eq!(fs::read_to_string(&token_path).unwrap(), "token.two.sig");

        // Symlink at token_path is atomically replaced without modifying symlink target.
        let sentinel = tmp.join("sentinel");
        fs::write(&sentinel, "untouched").unwrap();
        fs::remove_file(&token_path).unwrap();
        symlink(&sentinel, &token_path).unwrap();
        write_staged_plugin_token(&tokens_root, "demo-plugin", &rid, "token.three.sig", true)
            .unwrap();
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "untouched");
        assert!(!fs::symlink_metadata(&token_path).unwrap().is_symlink());

        // Symlink root directory is rejected fail-closed.
        let link_root = tmp.join("linked-root");
        symlink(&tokens_root, &link_root).unwrap();
        assert!(write_staged_plugin_token(
            &link_root,
            "demo-plugin",
            &rid,
            "token.four.sig",
            false
        )
        .is_err());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn verify_isolated_identity_rejects_root_and_api_caller_uid_gid() {
        let peer = Some(RunnerPeerCred {
            uid: 1001,
            gid: 1001,
            pid: Some(4242),
        });
        assert!(verify_isolated_identity(
            &UnitShowProps {
                uid: Some(0),
                gid: Some(61234),
                ..Default::default()
            },
            peer,
            true
        )
        .is_err());
        assert!(verify_isolated_identity(
            &UnitShowProps {
                uid: Some(1001),
                gid: Some(61234),
                ..Default::default()
            },
            peer,
            true
        )
        .is_err());
        assert!(verify_isolated_identity(
            &UnitShowProps {
                uid: Some(61234),
                gid: Some(1001),
                ..Default::default()
            },
            peer,
            true
        )
        .is_err());
        assert!(verify_isolated_identity(
            &UnitShowProps {
                uid: None,
                gid: None,
                ..Default::default()
            },
            peer,
            true
        )
        .is_err());
        assert!(verify_isolated_identity(
            &UnitShowProps {
                uid: Some(61234),
                gid: Some(61234),
                ..Default::default()
            },
            peer,
            true
        )
        .is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn handler_start_rotate_status_stop_and_identity_fail_closed_with_shims() {
        use std::os::unix::fs::PermissionsExt;

        let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
        let tmp = env::temp_dir().join(format!("af-runner-plugin-e2e-{}", Uuid::new_v4()));
        let plugins_root = tmp.join("plugins");
        let tokens_root = tmp.join("tokens");
        let state_file = tmp.join("unit.state");
        let args_log = tmp.join("systemd-run.log");
        let _plugin_dir = write_fixture_plugin(&plugins_root, "fixture-demo", true);

        let fake_systemd_run = tmp.join("fake-systemd-run");
        fs::write(
            &fake_systemd_run,
            format!(
                "#!/bin/bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" >> {:?}\necho active > {:?}\n",
                args_log, state_file
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_systemd_run, fs::Permissions::from_mode(0o755)).unwrap();

        let uid_file = tmp.join("unit.uid");
        fs::write(&uid_file, "62100\n").unwrap();
        let fake_systemctl = tmp.join("fake-systemctl");
        fs::write(
            &fake_systemctl,
            format!(
                r#"#!/bin/bash
set -euo pipefail
cmd="${{1:-}}"
case "$cmd" in
  show)
    st="inactive"
    if [[ -f {state:?} ]]; then st="$(cat {state:?})"; fi
    uid="$(cat {uid:?})"
    echo "ActiveState=$st"
    echo "SubState=running"
    echo "MainPID=0"
    echo "UID=$uid"
    echo "GID=$uid"
    ;;
  stop)
    echo inactive > {state:?}
    ;;
  reset-failed)
    ;;
esac
"#,
                state = state_file,
                uid = uid_file
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_systemctl, fs::Permissions::from_mode(0o755)).unwrap();

        let prev_plugins = env::var_os("AETHERFLOW_PLUGINS_DIR");
        let prev_tokens = env::var_os("AETHERFLOW_PLUGIN_TOKENS_ROOT");
        let prev_sdrun = env::var_os("AETHERFLOW_SYSTEMD_RUN_BIN");
        let prev_sdctl = env::var_os("AETHERFLOW_SYSTEMCTL_BIN");
        env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
        env::set_var("AETHERFLOW_PLUGIN_TOKENS_ROOT", &tokens_root);
        env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fake_systemd_run);
        env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_systemctl);

        let rid = Uuid::new_v4().to_string();
        let peer = Some(Extension(RunnerPeerCred {
            uid: 1001,
            gid: 1001,
            pid: Some(123),
        }));

        // 1. Start succeeds when unit reports independent DynamicUser UID/GID (62100 != 1001)
        let (code, Json(resp)) = handle_plugin_start(
            peer,
            Json(PluginRunnerStartRequest {
                plugin_id: "fixture-demo".into(),
                port: 21055,
                runtime_id: rid.clone(),
                api_base_url: "http://127.0.0.1:8080".into(),
                initial_token: "hdr.initial_secret.sig".into(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "resp={resp:?}");
        assert!(resp.success);
        let parsed: PluginRunnerStatusResponse = serde_json::from_str(&resp.output).unwrap();
        assert!(parsed.active);
        assert_eq!(parsed.uid, Some(62100));
        let logged_argv = fs::read_to_string(&args_log).unwrap();
        assert!(!logged_argv.contains("hdr.initial_secret.sig"));

        // 2. Token rotation updates staged runtime.token atomically
        let (rot_code, Json(rot_resp)) =
            handle_plugin_token_rotate(Json(PluginRunnerTokenRotateRequest {
                plugin_id: "fixture-demo".into(),
                runtime_id: rid.clone(),
                token: "hdr.rotated_secret.sig".into(),
            }))
            .await;
        assert_eq!(rot_code, StatusCode::OK, "rot_resp={rot_resp:?}");
        assert_eq!(
            fs::read_to_string(
                tokens_root
                    .join("fixture-demo")
                    .join(&rid)
                    .join("runtime.token")
            )
            .unwrap(),
            "hdr.rotated_secret.sig"
        );

        // 3. Status reports active
        let (st_code, Json(st_resp)) = handle_plugin_status(Json(PluginRunnerStatusRequest {
            plugin_id: "fixture-demo".into(),
            runtime_id: Some(rid.clone()),
        }))
        .await;
        assert_eq!(st_code, StatusCode::OK);
        let st_parsed: PluginRunnerStatusResponse = serde_json::from_str(&st_resp.output).unwrap();
        assert!(st_parsed.active);

        // 4. Stop clears active unit and wipes token directory
        let (stop_code, Json(stop_resp)) = handle_plugin_stop(Json(PluginRunnerStopRequest {
            plugin_id: "fixture-demo".into(),
            port: 21055,
            runtime_id: Some(rid.clone()),
            api_base_url: "http://127.0.0.1:8080".into(),
            run_stop_hook: true,
        }))
        .await;
        assert_eq!(stop_code, StatusCode::OK, "stop_resp={stop_resp:?}");
        assert!(!tokens_root.join("fixture-demo").exists());

        // 5. If unit ever reports API caller UID (1001), runner stops it and fails closed!
        fs::write(&uid_file, "1001\n").unwrap();
        let (bad_code, Json(bad_resp)) = handle_plugin_start(
            Some(Extension(RunnerPeerCred {
                uid: 1001,
                gid: 1001,
                pid: Some(123),
            })),
            Json(PluginRunnerStartRequest {
                plugin_id: "fixture-demo".into(),
                port: 21055,
                runtime_id: Uuid::new_v4().to_string(),
                api_base_url: "http://127.0.0.1:8080".into(),
                initial_token: "hdr.blocked_secret.sig".into(),
            }),
        )
        .await;
        assert_eq!(bad_code, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!bad_resp.success);
        assert!(bad_resp.error.contains("matches API caller OS uid"));
        assert!(!tokens_root.join("fixture-demo").exists());
        assert_eq!(fs::read_to_string(&state_file).unwrap().trim(), "inactive");

        for (k, v) in [
            ("AETHERFLOW_PLUGINS_DIR", prev_plugins),
            ("AETHERFLOW_PLUGIN_TOKENS_ROOT", prev_tokens),
            ("AETHERFLOW_SYSTEMD_RUN_BIN", prev_sdrun),
            ("AETHERFLOW_SYSTEMCTL_BIN", prev_sdctl),
        ] {
            if let Some(val) = v {
                env::set_var(k, val);
            } else {
                env::remove_var(k);
            }
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn handler_reports_503_when_isolation_unavailable_and_runs_oneshot_stop_hook() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let _env_guard = crate::ENV_TEST_MUTEX.lock().await;
        let tmp = env::temp_dir().join(format!("af-runner-plugin-503-{}", Uuid::new_v4()));
        let plugins_root = tmp.join("plugins");
        let tokens_root = tmp.join("tokens");
        let _plugin_dir = write_fixture_plugin(&plugins_root, "stop-fixture", true);

        // Symlinked on_start must be rejected fail-closed.
        let bad_dir = write_fixture_plugin(&plugins_root, "symlink-fixture", false);
        let outside = tmp.join("outside.sh");
        fs::write(&outside, "#!/bin/bash\nexit 0\n").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        let bad_start = bad_dir.join("backend/hooks/start.sh");
        fs::remove_file(&bad_start).unwrap();
        symlink(&outside, &bad_start).unwrap();

        let prev_plugins = env::var_os("AETHERFLOW_PLUGINS_DIR");
        let prev_tokens = env::var_os("AETHERFLOW_PLUGIN_TOKENS_ROOT");
        let prev_sdrun = env::var_os("AETHERFLOW_SYSTEMD_RUN_BIN");
        let prev_sdctl = env::var_os("AETHERFLOW_SYSTEMCTL_BIN");
        env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
        env::set_var("AETHERFLOW_PLUGIN_TOKENS_ROOT", &tokens_root);

        // 1. Missing systemd-run binary -> 503 SERVICE_UNAVAILABLE with actionable message
        env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", tmp.join("missing-sdrun"));
        let (code, Json(resp)) = handle_plugin_start(
            None,
            Json(PluginRunnerStartRequest {
                plugin_id: "stop-fixture".into(),
                port: 21060,
                runtime_id: Uuid::new_v4().to_string(),
                api_base_url: "http://127.0.0.1:8080".into(),
                initial_token: "hdr.tok.sig".into(),
            }),
        )
        .await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.error.contains("systemd-run"));

        // 2. Non-root without override -> 503 SERVICE_UNAVAILABLE
        if unsafe { libc::geteuid() } != 0 {
            env::remove_var("AETHERFLOW_SYSTEMD_RUN_BIN");
            env::remove_var("AETHERFLOW_SYSTEMCTL_BIN");
            let (nr_code, Json(nr_resp)) = handle_plugin_start(
                None,
                Json(PluginRunnerStartRequest {
                    plugin_id: "stop-fixture".into(),
                    port: 21060,
                    runtime_id: Uuid::new_v4().to_string(),
                    api_base_url: "http://127.0.0.1:8080".into(),
                    initial_token: "hdr.tok.sig".into(),
                }),
            )
            .await;
            assert_eq!(nr_code, StatusCode::SERVICE_UNAVAILABLE);
            assert!(
                nr_resp.error.contains("DynamicUser=yes")
                    || nr_resp.error.contains("systemd-run")
                    || nr_resp.error.contains("systemctl"),
                "nr_resp={nr_resp:?}"
            );
        }

        // 3. Symlinked on_start hook rejected with 400 BAD_REQUEST; inactive stop runs isolated oneshot stop unit
        let stop_args_log = tmp.join("stop-hook-args.log");
        let fake_sdrun = tmp.join("fake-sdrun");
        fs::write(
            &fake_sdrun,
            format!(
                "#!/bin/bash\nset -euo pipefail\nprintf '%s\\n' \"$@\" > {:?}\n",
                stop_args_log
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_sdrun, fs::Permissions::from_mode(0o755)).unwrap();

        let fake_sdctl = tmp.join("fake-sdctl");
        fs::write(
            &fake_sdctl,
            "#!/bin/bash\nset -euo pipefail\nif [[ \"${1:-}\" == \"show\" ]]; then echo ActiveState=inactive; echo SubState=dead; fi\n",
        )
        .unwrap();
        fs::set_permissions(&fake_sdctl, fs::Permissions::from_mode(0o755)).unwrap();

        env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fake_sdrun);
        env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_sdctl);

        let (sym_code, Json(sym_resp)) = handle_plugin_start(
            None,
            Json(PluginRunnerStartRequest {
                plugin_id: "symlink-fixture".into(),
                port: 21061,
                runtime_id: Uuid::new_v4().to_string(),
                api_base_url: "http://127.0.0.1:8080".into(),
                initial_token: "hdr.tok.sig".into(),
            }),
        )
        .await;
        assert_eq!(sym_code, StatusCode::BAD_REQUEST, "sym_resp={sym_resp:?}");
        assert!(sym_resp.error.contains("Symbolic link"));

        let (stop_code, Json(stop_resp)) = handle_plugin_stop(Json(PluginRunnerStopRequest {
            plugin_id: "stop-fixture".into(),
            port: 21060,
            runtime_id: None,
            api_base_url: "http://127.0.0.1:8080".into(),
            run_stop_hook: true,
        }))
        .await;
        assert_eq!(stop_code, StatusCode::OK, "stop_resp={stop_resp:?}");
        let stop_argv = fs::read_to_string(&stop_args_log).unwrap();
        assert!(stop_argv.contains("--unit=aetherflow-plugin-stop-fixture-stop.service"));
        assert!(stop_argv.contains("--property=DynamicUser=yes"));
        assert!(stop_argv.contains("--property=Type=oneshot"));
        assert!(stop_argv.contains("--property=InaccessiblePaths=-/var/lib/aetherflow"));
        assert!(stop_argv.contains("/run/aetherflow-plugin-app/backend/hooks/stop.sh"));

        for (k, v) in [
            ("AETHERFLOW_PLUGINS_DIR", prev_plugins),
            ("AETHERFLOW_PLUGIN_TOKENS_ROOT", prev_tokens),
            ("AETHERFLOW_SYSTEMD_RUN_BIN", prev_sdrun),
            ("AETHERFLOW_SYSTEMCTL_BIN", prev_sdctl),
        ] {
            if let Some(val) = v {
                env::set_var(k, val);
            } else {
                env::remove_var(k);
            }
        }
        let _ = fs::remove_dir_all(&tmp);
    }
}
