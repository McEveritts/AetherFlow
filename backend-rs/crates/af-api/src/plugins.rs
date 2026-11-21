use crate::auth::{api_error, jwt_secret_bytes, AuthUser};
use af_models::{
    plugin_systemd_unit_name, PluginRunnerStartRequest, PluginRunnerStatusRequest,
    PluginRunnerStopRequest, PluginRunnerTokenRotateRequest, PLUGIN_PORT_RANGE_END,
    PLUGIN_PORT_RANGE_START,
};
use af_runner::{
    dispatch_plugin_start, dispatch_plugin_status, dispatch_plugin_stop,
    dispatch_plugin_token_rotate, PluginRunnerError,
};
use axum::body::Body;
use axum::extract::{Extension, Path, Request};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Component, Path as StdPath, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Constants & Security Policies
// ─────────────────────────────────────────────────────────────────────────────

const MAX_PLUGIN_PROXY_BODY_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
const DEFAULT_PLUGIN_TOKEN_TTL_SECS: i64 = 300; // 5 minutes
const MAX_PLUGIN_TOKEN_TTL_SECS: i64 = 900; // 15 minutes
pub const PLUGIN_TOKEN_ISSUER: &str = "aetherflow-plugin";
pub const PLUGIN_TOKEN_TYP: &str = "plugin";
pub const PLUGIN_TOKEN_AUDIENCE: &str = "aetherflow-plugin-api";

const DEFAULT_DENY_ROUTE_PREFIXES: &[&str] = &[
    "/api/v1/admin",
    "/api/admin",
    "/api/v1/ingress",
    "/api/ingress",
    "/api/v1/auth/session",
    "/api/v1/auth/sessions",
    "/api/v1/auth/refresh",
    "/api/v1/auth/logout",
    "/api/v1/auth/ws",
    "/api/v1/auth/profile",
    "/api/v1/auth/user/2fa",
    "/api/v1/auth/oidc",
    "/api/v1/auth/plugins",
    "/api/v1/plugins",
    "/plugins",
    "/api/auth/session",
    "/api/auth/sessions",
    "/api/auth/refresh",
    "/api/auth/logout",
    "/api/auth/ws",
    "/api/auth/profile",
    "/api/auth/user/2fa",
    "/api/auth/oidc",
    "/api/auth/plugins",
    "/api/plugins",
];

// ─────────────────────────────────────────────────────────────────────────────
// Manifest & Scope Schema
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginScopeRule {
    pub method: String,
    pub route: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RawScopeEntry {
    Simple(String),
    Structured(PluginScopeRule),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginLifecycleHooks {
    #[serde(default)]
    pub on_start: String,
    #[serde(default)]
    pub on_stop: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginBackendSpec {
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub manifest_path: String,
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub binary_name: String,
    #[serde(default = "default_health_path")]
    pub health_path: String,
    #[serde(default = "default_port_allocation")]
    pub port_allocation: String,
}

fn default_health_path() -> String {
    "/healthz".to_string()
}

fn default_port_allocation() -> String {
    "dynamic".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginFrontendSpec {
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub bundle: String,
    #[serde(default = "default_frontend_slot")]
    pub slot: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

fn default_frontend_slot() -> String {
    "marketplace".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub sdk: String,
    #[serde(default)]
    pub contract_version: String,
    #[serde(default)]
    pub runtime_status: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub api_scopes: Vec<RawScopeEntry>,
    #[serde(default)]
    pub lifecycle_hooks: PluginLifecycleHooks,
    #[serde(default)]
    pub backend: PluginBackendSpec,
    #[serde(default)]
    pub frontend: PluginFrontendSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedPluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sdk: String,
    pub contract_version: String,
    pub runtime_status: String,
    pub description: String,
    pub author: String,
    pub permissions: Vec<String>,
    pub granted_scopes: Vec<PluginScopeRule>,
    pub lifecycle_hooks: PluginLifecycleHooks,
    pub backend: PluginBackendSpec,
    pub frontend: PluginFrontendSpec,
    #[serde(skip)]
    pub plugin_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRegistryState {
    pub plugin_id: String,
    pub enabled: bool,
    pub allocated_port: u16,
    pub token_epoch: i64,
    pub status: String,
    pub last_health_at: Option<String>,
    pub last_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRuntimeView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sdk: String,
    pub contract_version: String,
    pub runtime_status: String,
    pub description: String,
    pub author: String,
    pub permissions: Vec<String>,
    pub granted_scopes: Vec<PluginScopeRule>,
    pub enabled: bool,
    pub status: String,
    pub healthy: bool,
    pub allocated_port: u16,
    pub health_path: String,
    pub ui_url: String,
    pub proxy_base_url: String,
    pub slot: String,
    pub capabilities: Vec<String>,
    pub last_health_at: Option<String>,
    pub last_error: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoped Short-Lived Plugin Token Claims & Validation
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginTokenClaims {
    pub typ: String,
    pub iss: String,
    #[serde(default = "default_plugin_aud")]
    pub aud: String,
    pub sub: String,
    pub plugin_id: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub epoch: i64,
    pub scopes: Vec<PluginScopeRule>,
}

fn default_plugin_aud() -> String {
    PLUGIN_TOKEN_AUDIENCE.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginLifecycleError {
    IsolationUnavailable(String),
    InvalidInput(String),
    Runtime(String),
}

impl std::fmt::Display for PluginLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IsolationUnavailable(msg) | Self::InvalidInput(msg) | Self::Runtime(msg) => {
                f.write_str(msg)
            }
        }
    }
}

impl std::error::Error for PluginLifecycleError {}

impl From<PluginRunnerError> for PluginLifecycleError {
    fn from(value: PluginRunnerError) -> Self {
        match value {
            PluginRunnerError::IsolationUnavailable(msg) => Self::IsolationUnavailable(msg),
            PluginRunnerError::InvalidRequest(msg) => Self::InvalidInput(msg),
            PluginRunnerError::Runtime(msg) => Self::Runtime(msg),
        }
    }
}

impl PluginLifecycleError {
    pub fn into_api_response(self) -> Response {
        match self {
            Self::IsolationUnavailable(msg) => api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "PLUGIN_ISOLATION_UNAVAILABLE",
                msg,
            ),
            Self::InvalidInput(msg) => {
                api_error(StatusCode::BAD_REQUEST, "INVALID_PLUGIN_CONFIG", msg)
            }
            Self::Runtime(msg) => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PLUGIN_LIFECYCLE_ERROR",
                msg,
            ),
        }
    }
}

struct ActivePluginRuntime {
    port: u16,
    #[allow(dead_code)]
    unit_name: String,
    runtime_id: Uuid,
    monitor: Option<tokio::task::JoinHandle<()>>,
}

static ACTIVE_PROCESSES: Lazy<Mutex<HashMap<String, ActivePluginRuntime>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static PLUGIN_LIFECYCLE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static PLUGIN_HEALTH: Lazy<Mutex<HashMap<String, (u16, bool)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static ACTIVE_PLUGIN_JTIS: Lazy<Mutex<HashMap<String, HashMap<String, i64>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static PROXY_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(3))
        .no_proxy()
        .build()
        .expect("plugin proxy client")
});

fn plugin_signing_key() -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&jwt_secret_bytes())
        .expect("HMAC accepts arbitrary key length");
    mac.update(b"aetherflow-plugin-token-v1");
    mac.finalize().into_bytes().to_vec()
}

pub fn is_valid_plugin_id(id: &str) -> bool {
    af_models::is_valid_plugin_id(id)
}

pub fn is_route_default_denied(path: &str) -> bool {
    let clean = path.trim();
    if clean.is_empty() || !clean.starts_with('/') || clean.contains("..") {
        return true;
    }
    for prefix in DEFAULT_DENY_ROUTE_PREFIXES {
        if clean == *prefix || clean.starts_with(&format!("{}/", prefix)) {
            return true;
        }
    }
    false
}

const ADMIN_USER_ONLY_WRITE_PREFIXES: &[&str] = &[
    "/api/v1/admin/packages",
    "/api/v1/admin/services",
    "/api/v1/admin/system/update",
    "/api/v1/auth/packages",
    "/api/v1/auth/services",
    "/api/v1/auth/system/update",
    "/api/v1/auth/deploy",
];

fn canonical_plugin_route(path: &str) -> String {
    match path.strip_prefix("/api/") {
        Some(rest) if !rest.starts_with("v1/") => format!("/api/v1/{rest}"),
        _ => path.to_string(),
    }
}

fn route_is_within(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

pub fn is_plugin_request_denied(method: &Method, path: &str) -> bool {
    is_route_default_denied(path)
        || (!matches!(*method, Method::GET | Method::HEAD)
            && ADMIN_USER_ONLY_WRITE_PREFIXES
                .iter()
                .any(|prefix| route_is_within(&canonical_plugin_route(path), prefix)))
}

fn permission_route_prefixes(permission: &str, read: bool) -> &[&str] {
    match (permission, read) {
        ("telemetry:read" | "system:read", true) => &[
            "/api/v1/auth/system/metrics",
            "/api/v1/auth/system/hardware",
            "/api/v1/auth/services",
        ],
        ("system:metrics:read", true) => &["/api/v1/auth/system/metrics"],
        ("system:hardware:read", true) => &["/api/v1/auth/system/hardware"],
        ("services:read", true) => &["/api/v1/auth/services"],
        ("packages:read", true) => &["/api/v1/auth/packages"],
        ("marketplace:read", true) => &["/api/v1/public/marketplace"],
        ("notifications:read", true) | ("notifications:write", false) => {
            &["/api/v1/auth/notifications"]
        }
        _ => &[],
    }
}

fn plugin_requires_admin(permissions: &[String]) -> bool {
    permissions.iter().any(|permission| {
        matches!(
            permission.trim().rsplit(':').next(),
            Some("write" | "control" | "admin")
        )
    })
}

pub fn normalize_scope_entry(
    raw: &RawScopeEntry,
    permissions: &[String],
) -> Result<Vec<PluginScopeRule>, String> {
    let (raw_method, raw_route) = match raw {
        RawScopeEntry::Structured(rule) => (
            rule.method.trim().to_uppercase(),
            rule.route.trim().to_string(),
        ),
        RawScopeEntry::Simple(spec) => {
            let trimmed = spec.trim();
            if let Some((m, r)) = trimmed.split_once(' ') {
                (m.trim().to_uppercase(), r.trim().to_string())
            } else {
                ("GET".to_string(), trimmed.to_string())
            }
        }
    };

    if raw_route.is_empty() || !raw_route.starts_with("/api/") || raw_route.contains("..") {
        return Err(format!(
            "Invalid plugin API scope route '{}': must start with /api/ and not contain '..'",
            raw_route
        ));
    }

    if is_route_default_denied(raw_route.trim_end_matches('*').trim_end_matches('/')) {
        return Err(format!(
            "Plugin API scope '{}' targets a protected or default-denied endpoint",
            raw_route
        ));
    }

    let read = matches!(raw_method.as_str(), "GET" | "HEAD");
    let methods = match raw_method.as_str() {
        "GET" | "HEAD" => vec!["GET".to_string(), "HEAD".to_string()],
        "POST" | "PUT" | "PATCH" | "DELETE" => vec![raw_method],
        _ => {
            return Err(format!(
                "Unsupported HTTP method '{}' in plugin scope",
                raw_method
            ))
        }
    };

    let route = raw_route.strip_suffix("/*").unwrap_or(&raw_route);
    if route.contains(['*', '?', '#', '%', '\\'])
        || !permissions.iter().any(|permission| {
            permission_route_prefixes(permission.trim(), read)
                .iter()
                .any(|prefix| route_is_within(&canonical_plugin_route(route), prefix))
        })
    {
        return Err(format!(
            "Plugin API scope '{}' is outside its manifest permissions",
            raw_route
        ));
    }

    Ok(methods
        .into_iter()
        .map(|method| PluginScopeRule {
            method,
            route: raw_route.clone(),
        })
        .collect())
}

pub fn route_pattern_matches(pattern: &str, request_path: &str) -> bool {
    if pattern == request_path {
        return true;
    }
    // Also normalize `/api/` vs `/api/v1/` equivalence when matching
    let alt_request = if let Some(rest) = request_path.strip_prefix("/api/v1/") {
        Some(format!("/api/{}", rest))
    } else {
        request_path
            .strip_prefix("/api/")
            .map(|rest| format!("/api/v1/{}", rest))
    };

    let matches_single = |pat: &str, path: &str| -> bool {
        if pat == path {
            return true;
        }
        if let Some(prefix) = pat.strip_suffix("/*") {
            return path == prefix || path.starts_with(&format!("{}/", prefix));
        }
        if let Some(prefix) = pat.strip_suffix('*') {
            return path.starts_with(prefix);
        }
        false
    };

    if matches_single(pattern, request_path) {
        return true;
    }
    if let Some(ref alt) = alt_request {
        if matches_single(pattern, alt) {
            return true;
        }
    }
    false
}

pub fn plugin_claims_allow_request(
    claims: &PluginTokenClaims,
    method: &Method,
    path: &str,
) -> bool {
    if is_plugin_request_denied(method, path) {
        return false;
    }
    let req_method = method.as_str().to_uppercase();
    claims.scopes.iter().any(|rule| {
        rule.method.eq_ignore_ascii_case(&req_method) && route_pattern_matches(&rule.route, path)
    })
}

pub fn validate_relative_plugin_subpath(
    plugin_dir: &StdPath,
    rel: &str,
    must_exist: bool,
) -> Result<PathBuf, String> {
    let trimmed = rel.trim();
    if trimmed.is_empty() {
        return Err("Empty path is not allowed".to_string());
    }
    if trimmed.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '%' | ':' | ';' | '"' | '\'' | '\\' | '$' | '`')
    }) {
        return Err(format!("Path '{}' contains disallowed characters", trimmed));
    }
    let rel_path = StdPath::new(trimmed);
    if rel_path.is_absolute() {
        return Err(format!(
            "Absolute path '{}' is forbidden in plugin manifest",
            trimmed
        ));
    }
    for comp in rel_path.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(format!(
                    "Path traversal component in '{}' is forbidden",
                    trimmed
                ))
            }
        }
    }

    let canon_root = fs::canonicalize(plugin_dir)
        .map_err(|e| format!("Failed to canonicalize plugin dir: {}", e))?;
    let mut cursor = canon_root.clone();
    for comp in rel_path.components() {
        if let Component::Normal(seg) = comp {
            cursor.push(seg);
            if let Ok(sym_meta) = fs::symlink_metadata(&cursor) {
                if sym_meta.file_type().is_symlink() {
                    return Err(format!(
                        "Symlink '{}' inside plugin directory is forbidden",
                        trimmed
                    ));
                }
                check_trusted_ownership(&cursor)?;
            }
        }
    }

    let joined = plugin_dir.join(rel_path);
    if joined.exists() || fs::symlink_metadata(&joined).is_ok() {
        let sym_meta = fs::symlink_metadata(&joined)
            .map_err(|e| format!("Failed to inspect '{}': {}", trimmed, e))?;
        if sym_meta.file_type().is_symlink() {
            return Err(format!(
                "Symlink '{}' inside plugin directory is forbidden",
                trimmed
            ));
        }
        let canon_target = fs::canonicalize(&joined)
            .map_err(|e| format!("Failed to canonicalize '{}': {}", trimmed, e))?;
        if !canon_target.starts_with(&canon_root) {
            return Err(format!(
                "Path '{}' escapes canonical plugin directory boundary",
                trimmed
            ));
        }
        check_trusted_ownership(&canon_target)?;
        Ok(canon_target)
    } else if must_exist {
        Err(format!("Required plugin file '{}' does not exist", trimmed))
    } else {
        Ok(joined)
    }
}

#[cfg(unix)]
fn check_trusted_ownership(path: &StdPath) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("Failed to stat '{}': {}", path.display(), e))?;
    let mode = meta.mode();
    if (mode & 0o002) != 0 {
        return Err(format!(
            "Insecure world-writable permissions (mode {:o}) on '{}'",
            mode & 0o777,
            path.display()
        ));
    }
    let file_uid = meta.uid();
    let euid = unsafe { libc::geteuid() };
    if file_uid != 0 && file_uid != euid {
        return Err(format!(
            "Untrusted file owner uid={} on '{}' (must be root or service uid={})",
            file_uid,
            path.display(),
            euid
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_trusted_ownership(_path: &StdPath) -> Result<(), String> {
    Ok(())
}

pub fn validate_plugin_manifest(
    plugin_dir: &StdPath,
    raw: RawPluginManifest,
) -> Result<ValidatedPluginManifest, String> {
    let id = raw.id.trim().to_string();
    if !is_valid_plugin_id(&id) {
        return Err(format!(
            "Invalid plugin id '{}': must match ^[a-z0-9][a-z0-9-_]{{1,62}}$",
            id
        ));
    }

    if let Some(dir_name) = plugin_dir.file_name().and_then(|n| n.to_str()) {
        if dir_name != id {
            return Err(format!(
                "Plugin directory name '{}' must match manifest id '{}'",
                dir_name, id
            ));
        }
    }

    check_trusted_ownership(plugin_dir)?;

    if raw.name.trim().is_empty()
        || raw.version.trim().is_empty()
        || raw.name.len() > 256
        || raw.version.len() > 256
        || raw.name.chars().any(char::is_control)
        || raw.version.chars().any(char::is_control)
    {
        return Err(
            "Plugin manifest requires non-empty, printable 'name' and 'version'".to_string(),
        );
    }

    if !raw.backend.health_path.starts_with('/')
        || raw.backend.health_path.contains("..")
        || raw.backend.health_path.chars().any(char::is_control)
    {
        return Err(format!(
            "Invalid backend.health_path '{}'",
            raw.backend.health_path
        ));
    }

    if !raw.backend.binary_name.trim().is_empty() {
        let bin = raw.backend.binary_name.trim();
        if bin.contains('/')
            || bin.contains('\\')
            || bin.contains("..")
            || bin.chars().any(|c| {
                c.is_whitespace()
                    || c.is_control()
                    || matches!(c, '%' | ':' | ';' | '"' | '\'' | '$' | '`')
            })
        {
            return Err(format!("Invalid backend.binary_name '{}'", bin));
        }
    }
    if !raw.backend.manifest_path.trim().is_empty() {
        validate_relative_plugin_subpath(plugin_dir, &raw.backend.manifest_path, false)?;
    }

    for hook in [&raw.lifecycle_hooks.on_start, &raw.lifecycle_hooks.on_stop] {
        if !hook.trim().is_empty() {
            validate_relative_plugin_subpath(plugin_dir, hook, false)?;
        }
    }
    if !raw.backend.entry.trim().is_empty() {
        validate_relative_plugin_subpath(plugin_dir, &raw.backend.entry, false)?;
    }
    if !raw.frontend.entry.trim().is_empty() {
        validate_relative_plugin_subpath(plugin_dir, &raw.frontend.entry, false)?;
    }
    if !raw.frontend.bundle.trim().is_empty() {
        validate_relative_plugin_subpath(plugin_dir, &raw.frontend.bundle, false)?;
    }

    let mut granted_scopes = Vec::new();
    for entry in &raw.api_scopes {
        let mut normalized = normalize_scope_entry(entry, &raw.permissions)?;
        granted_scopes.append(&mut normalized);
    }

    Ok(ValidatedPluginManifest {
        id,
        name: raw.name.trim().to_string(),
        version: raw.version.trim().to_string(),
        sdk: if raw.sdk.trim().is_empty() {
            "rust".to_string()
        } else {
            raw.sdk.trim().to_string()
        },
        contract_version: if raw.contract_version.trim().is_empty() {
            "v1".to_string()
        } else {
            raw.contract_version.trim().to_string()
        },
        runtime_status: if raw.runtime_status.trim().is_empty() {
            "managed".to_string()
        } else {
            raw.runtime_status.trim().to_string()
        },
        description: raw.description.trim().to_string(),
        author: raw.author.trim().to_string(),
        permissions: raw.permissions,
        granted_scopes,
        lifecycle_hooks: raw.lifecycle_hooks,
        backend: raw.backend,
        frontend: raw.frontend,
        plugin_dir: plugin_dir.to_path_buf(),
    })
}

pub fn resolve_plugins_dir() -> PathBuf {
    if let Ok(custom) = env::var("AETHERFLOW_PLUGINS_DIR") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Ok(fs_root) = env::var("AETHERFLOW_FS_ROOT") {
        let trimmed = fs_root.trim();
        if !trimmed.is_empty() {
            let candidate = PathBuf::from(trimmed).join("plugins");
            if candidate.is_dir() {
                return candidate;
            }
        }
    }
    for candidate in [
        "plugins",
        "../plugins",
        "../../plugins",
        "/opt/AetherFlow/plugins",
    ] {
        let p = PathBuf::from(candidate);
        if p.is_dir() {
            return p;
        }
    }
    PathBuf::from("plugins")
}

pub fn discover_plugins() -> (Vec<ValidatedPluginManifest>, Vec<(String, String)>) {
    let root = resolve_plugins_dir();
    discover_plugins_in_dir(&root)
}

pub fn discover_plugins_in_dir(
    root: &StdPath,
) -> (Vec<ValidatedPluginManifest>, Vec<(String, String)>) {
    let mut manifests = Vec::new();
    let mut rejected = Vec::new();

    if !root.exists() {
        return (manifests, rejected);
    }
    let Ok(canon_root) = fs::canonicalize(root) else {
        return (manifests, rejected);
    };
    let Ok(entries) = fs::read_dir(&canon_root) else {
        return (manifests, rejected);
    };

    for entry in entries.flatten() {
        let dir_name = entry.file_name().to_string_lossy().into_owned();
        if dir_name.starts_with('.')
            || dir_name == "sdk-template"
            || dir_name == "sdk-template-rust"
        {
            continue;
        }
        let path = entry.path();
        let Ok(sym_meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if sym_meta.file_type().is_symlink() {
            rejected.push((
                dir_name,
                "Plugin directory cannot be a symbolic link".to_string(),
            ));
            continue;
        }
        if !sym_meta.is_dir() {
            continue;
        }
        let Ok(canon_dir) = fs::canonicalize(&path) else {
            continue;
        };
        if !canon_dir.starts_with(&canon_root) {
            rejected.push((
                dir_name,
                "Plugin directory escapes canonical plugins root".to_string(),
            ));
            continue;
        }

        let manifest_path = canon_dir.join("plugin.manifest.json");
        if !manifest_path.exists() {
            continue;
        }
        if let Ok(m_sym) = fs::symlink_metadata(&manifest_path) {
            if m_sym.file_type().is_symlink() {
                rejected.push((
                    dir_name,
                    "plugin.manifest.json cannot be a symbolic link".to_string(),
                ));
                continue;
            }
        }
        let raw_text = match fs::read_to_string(&manifest_path) {
            Ok(t) => t,
            Err(e) => {
                rejected.push((dir_name, format!("Failed to read manifest: {}", e)));
                continue;
            }
        };
        let raw: RawPluginManifest = match serde_json::from_str(&raw_text) {
            Ok(m) => m,
            Err(e) => {
                rejected.push((dir_name, format!("Invalid manifest JSON: {}", e)));
                continue;
            }
        };
        match validate_plugin_manifest(&canon_dir, raw) {
            Ok(valid) => manifests.push(valid),
            Err(err) => rejected.push((dir_name, err)),
        }
    }

    manifests.sort_by(|a, b| a.id.cmp(&b.id));
    (manifests, rejected)
}

// ─────────────────────────────────────────────────────────────────────────────
// Database Persistence & Port Allocation
// ─────────────────────────────────────────────────────────────────────────────

fn read_registry_state(plugin_id: &str) -> PluginRegistryState {
    if let Ok(conn) = af_db::get_read_conn() {
        if let Ok(state) = conn.query_row(
            "SELECT plugin_id, enabled, allocated_port, token_epoch, status, last_health_at, COALESCE(last_error, '') \
             FROM plugins_registry WHERE plugin_id = ?1",
            params![plugin_id],
            |r| {
                Ok(PluginRegistryState {
                    plugin_id: r.get(0)?,
                    enabled: r.get(1)?,
                    allocated_port: r.get::<_, i64>(2)?.clamp(0, 65535) as u16,
                    token_epoch: r.get(3)?,
                    status: r.get(4)?,
                    last_health_at: r.get(5).ok().flatten(),
                    last_error: r.get(6)?,
                })
            },
        ) {
            return state;
        }
    }
    PluginRegistryState {
        plugin_id: plugin_id.to_string(),
        enabled: false,
        allocated_port: 0,
        token_epoch: 1,
        status: "stopped".to_string(),
        last_health_at: None,
        last_error: String::new(),
    }
}

pub(crate) fn update_registry_state(
    plugin_id: &str,
    enabled: bool,
    allocated_port: u16,
    status: &str,
    last_error: &str,
    bump_epoch: bool,
) -> PluginRegistryState {
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "INSERT OR IGNORE INTO plugins_registry (plugin_id, enabled, allocated_port, token_epoch, status) VALUES (?1, 0, 0, 1, 'stopped')",
            params![plugin_id],
        );
        if bump_epoch {
            let _ = conn.execute(
                "UPDATE plugins_registry SET enabled = ?1, allocated_port = ?2, status = ?3, last_error = ?4, \
                 token_epoch = token_epoch + 1, updated_at = CURRENT_TIMESTAMP WHERE plugin_id = ?5",
                params![enabled, allocated_port as i64, status, last_error, plugin_id],
            );
        } else {
            let _ = conn.execute(
                "UPDATE plugins_registry SET enabled = ?1, allocated_port = ?2, status = ?3, last_error = ?4, \
                 updated_at = CURRENT_TIMESTAMP WHERE plugin_id = ?5",
                params![enabled, allocated_port as i64, status, last_error, plugin_id],
            );
        }
    }
    read_registry_state(plugin_id)
}

fn allocate_plugin_port(
    plugin_id: &str,
    preferred: u16,
    allow_listening_preferred: bool,
) -> Result<u16, String> {
    let mut used_ports = HashSet::new();
    if let Ok(conn) = af_db::get_conn() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT plugin_id, allocated_port FROM plugins_registry WHERE allocated_port > 0",
        ) {
            if let Ok(rows) =
                stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            {
                for (pid, p) in rows.flatten() {
                    if pid != plugin_id && (1024..=65535).contains(&p) {
                        used_ports.insert(p as u16);
                    }
                }
            }
        }
    }
    if let Ok(procs) = ACTIVE_PROCESSES.lock() {
        for (pid, proc_entry) in procs.iter() {
            if pid != plugin_id {
                used_ports.insert(proc_entry.port);
            }
        }
    }

    if (PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&preferred)
        && !used_ports.contains(&preferred)
        && (allow_listening_preferred || TcpListener::bind(("127.0.0.1", preferred)).is_ok())
    {
        return Ok(preferred);
    }

    for port in PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END {
        if used_ports.contains(&port) {
            continue;
        }
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }

    Err("No available loopback ports in plugin range 21000..21999".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Token Minting, Verification & Revocation
// ─────────────────────────────────────────────────────────────────────────────

pub fn mint_scoped_plugin_token(
    manifest: &ValidatedPluginManifest,
    requested_ttl_secs: Option<i64>,
) -> Result<(String, PluginTokenClaims), String> {
    let reg = read_registry_state(&manifest.id);
    if !reg.enabled && reg.status != "running" {
        return Err(format!(
            "Plugin '{}' must be enabled before minting a scoped runtime token",
            manifest.id
        ));
    }

    let (token, claims) = sign_plugin_token(manifest, reg.token_epoch, requested_ttl_secs, None)?;
    if let Ok(mut map) = ACTIVE_PLUGIN_JTIS.lock() {
        let jtis = map.entry(manifest.id.clone()).or_default();
        jtis.retain(|_, expiry| *expiry >= claims.iat);
        jtis.insert(claims.jti.clone(), claims.exp);
    }
    Ok((token, claims))
}

fn sign_plugin_token(
    manifest: &ValidatedPluginManifest,
    epoch: i64,
    requested_ttl_secs: Option<i64>,
    runtime_id: Option<Uuid>,
) -> Result<(String, PluginTokenClaims), String> {
    let now = Utc::now().timestamp();
    let ttl = requested_ttl_secs
        .unwrap_or(DEFAULT_PLUGIN_TOKEN_TTL_SECS)
        .clamp(30, MAX_PLUGIN_TOKEN_TTL_SECS);
    let exp = now + ttl;
    let jti = match runtime_id {
        Some(id) => format!("plg-runtime:{id}:{}", Uuid::new_v4()),
        None => format!("plg-{}-{}", manifest.id, Uuid::new_v4()),
    };

    let claims = PluginTokenClaims {
        typ: PLUGIN_TOKEN_TYP.to_string(),
        iss: PLUGIN_TOKEN_ISSUER.to_string(),
        aud: PLUGIN_TOKEN_AUDIENCE.to_string(),
        sub: format!("plugin:{}", manifest.id),
        plugin_id: manifest.id.clone(),
        jti,
        iat: now,
        exp,
        epoch,
        scopes: manifest.granted_scopes.clone(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&plugin_signing_key()),
    )
    .map_err(|e| format!("Failed to encode plugin token: {}", e))?;

    Ok((token, claims))
}

pub fn decode_and_verify_plugin_token(token: &str) -> Result<PluginTokenClaims, String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[PLUGIN_TOKEN_AUDIENCE]);
    validation.leeway = 0;

    let data = decode::<PluginTokenClaims>(
        token,
        &DecodingKey::from_secret(&plugin_signing_key()),
        &validation,
    )
    .map_err(|e| format!("Invalid plugin token signature or expiry: {}", e))?;

    let mut claims = data.claims;
    if claims.typ != PLUGIN_TOKEN_TYP
        || claims.iss != PLUGIN_TOKEN_ISSUER
        || claims.aud != PLUGIN_TOKEN_AUDIENCE
    {
        return Err("Token is not a valid AetherFlow plugin token".to_string());
    }
    if !is_valid_plugin_id(&claims.plugin_id) {
        return Err("Invalid plugin_id in token".to_string());
    }
    if let Some(runtime_jti) = claims.jti.strip_prefix("plg-runtime:") {
        let run = runtime_jti
            .split_once(':')
            .and_then(|(id, _)| Uuid::parse_str(id).ok());
        let active = ACTIVE_PROCESSES
            .lock()
            .ok()
            .and_then(|processes| processes.get(&claims.plugin_id).map(|p| p.runtime_id));
        if run.is_none() || run != active {
            return Err("Managed plugin process is no longer active".to_string());
        }
    }
    if af_db::is_token_revoked(&claims.jti) {
        return Err("Plugin token has been revoked".to_string());
    }

    let reg = read_registry_state(&claims.plugin_id);
    if !reg.enabled || reg.status == "stopped" || reg.token_epoch != claims.epoch {
        return Err(
            "Plugin token is no longer active for the current plugin lifecycle epoch".to_string(),
        );
    }

    let (manifests, _) = discover_plugins();
    let live_manifest = manifests
        .into_iter()
        .find(|m| m.id == claims.plugin_id)
        .ok_or_else(|| "Plugin manifest is unavailable".to_string())?;
    claims
        .scopes
        .retain(|scope| live_manifest.granted_scopes.contains(scope));

    Ok(claims)
}

pub fn revoke_all_tokens_for_plugin(plugin_id: &str) {
    let jtis = ACTIVE_PLUGIN_JTIS
        .lock()
        .ok()
        .and_then(|mut map| map.remove(plugin_id));
    for (jti, _) in jtis.into_iter().flatten() {
        let _ = af_db::revoke_token(
            &jti,
            Duration::from_secs(MAX_PLUGIN_TOKEN_TTL_SECS as u64 + 60),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unprivileged Process Lifecycle & Health Probing
// ─────────────────────────────────────────────────────────────────────────────

fn resolve_plugin_executable(manifest: &ValidatedPluginManifest) -> Option<(PathBuf, Vec<String>)> {
    let bin = manifest.backend.binary_name.trim();
    if !bin.is_empty() {
        let mut candidates = Vec::with_capacity(8);

        // 1. Honor explicit Cargo manifest directory from `backend.manifest_path`
        // (e.g. `backend/Cargo.toml` -> `backend/target/{release,debug}/<bin>`).
        let manifest_path_trimmed = manifest.backend.manifest_path.trim();
        if !manifest_path_trimmed.is_empty() {
            if let Some(parent) = std::path::Path::new(manifest_path_trimmed).parent() {
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

        // 2. Canonical Rust plugin workspace target & packaged binary layouts.
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
            if let Ok(path) = validate_relative_plugin_subpath(&manifest.plugin_dir, &rel, true) {
                if path.is_file() {
                    return Some((path, Vec::new()));
                }
            }
        }
    }
    if !manifest.lifecycle_hooks.on_start.trim().is_empty() {
        if let Ok(hook_path) = validate_relative_plugin_subpath(
            &manifest.plugin_dir,
            &manifest.lifecycle_hooks.on_start,
            true,
        ) {
            if hook_path.is_file() && cfg!(unix) {
                return Some((
                    PathBuf::from("/bin/bash"),
                    vec![hook_path.to_string_lossy().into_owned()],
                ));
            }
        }
    }
    None
}

fn resolve_api_base_url() -> Result<String, PluginLifecycleError> {
    let api_port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let raw = env::var("AETHERFLOW_INTERNAL_API_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("http://127.0.0.1:{api_port}"));
    af_runner::plugins::validate_loopback_api_base_url(&raw).map_err(PluginLifecycleError::from)
}

fn privileged_runner_explicitly_disabled() -> bool {
    env::var("PRIVILEGED_RUNNER_ENABLED")
        .ok()
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
}

fn check_plugin_isolation_available() -> Result<(), PluginLifecycleError> {
    if privileged_runner_explicitly_disabled() {
        return Err(PluginLifecycleError::IsolationUnavailable(
            "Managed plugin isolation is unavailable because PRIVILEGED_RUNNER_ENABLED is disabled. Enable PRIVILEGED_RUNNER_ENABLED=true with aetherflow-runner.service on a systemd-managed Linux host (af-api refuses to spawn managed plugins as the API OS user), or configure this plugin as an external backend."
                .to_string(),
        ));
    }
    if !af_runner::is_runner_available() {
        let sock = af_runner::resolve_runner_socket_path();
        return Err(PluginLifecycleError::IsolationUnavailable(format!(
            "Managed plugin isolation is unavailable because aetherflow-runner.service is not reachable at '{sock}'. Start aetherflow-runner.service on a systemd-managed Linux host (af-api refuses to spawn managed plugins as the API OS user), or configure this plugin as an external backend."
        )));
    }
    Ok(())
}

pub async fn probe_plugin_health(port: u16, health_path: &str) -> Result<bool, String> {
    if !(PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&port) {
        return Err(format!(
            "Port {} is outside allowed plugin loopback range",
            port
        ));
    }
    let clean_path = if health_path.starts_with('/') {
        health_path.to_string()
    } else {
        format!("/{}", health_path)
    };
    let url = format!("http://127.0.0.1:{}{}", port, clean_path);
    match PROXY_HTTP_CLIENT.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(conn) = af_db::get_conn() {
                let _ = conn.execute(
                    "UPDATE plugins_registry SET last_health_at = CURRENT_TIMESTAMP, last_error = '' WHERE allocated_port = ?1",
                    params![port as i64],
                );
            }
            Ok(true)
        }
        Ok(resp) => Err(format!("Health check returned HTTP {}", resp.status())),
        Err(e) => Err(format!("Health probe unreachable: {}", e)),
    }
}

// The lifecycle lock serializes status reaping and token rotation with stop/restart.
async fn monitor_plugin(
    manifest: ValidatedPluginManifest,
    port: u16,
    runtime_id: Uuid,
    mut epoch: i64,
) {
    let mut rotated_at = std::time::Instant::now();
    let mut consecutive_status_errors: u8 = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let healthy = probe_plugin_health(port, &manifest.backend.health_path)
            .await
            .unwrap_or(false);
        let _lifecycle = PLUGIN_LIFECYCLE.lock().await;
        let still_current = ACTIVE_PROCESSES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&manifest.id)
            .is_some_and(|runtime| runtime.runtime_id == runtime_id);
        if !still_current {
            return;
        }

        let status_req = PluginRunnerStatusRequest {
            plugin_id: manifest.id.clone(),
            runtime_id: Some(runtime_id.to_string()),
        };
        match dispatch_plugin_status(&status_req).await {
            Ok(status) if !status.active => {
                ACTIVE_PROCESSES
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&manifest.id);
                PLUGIN_HEALTH
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&manifest.id);
                let _ = dispatch_plugin_stop(&PluginRunnerStopRequest {
                    plugin_id: manifest.id.clone(),
                    port,
                    runtime_id: Some(runtime_id.to_string()),
                    api_base_url: resolve_api_base_url()
                        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
                    run_stop_hook: false,
                })
                .await;
                update_registry_state(
                    &manifest.id,
                    false,
                    port,
                    "error",
                    "Plugin process exited",
                    true,
                );
                revoke_all_tokens_for_plugin(&manifest.id);
                return;
            }
            Ok(_) => {
                consecutive_status_errors = 0;
            }
            Err(error) => {
                consecutive_status_errors = consecutive_status_errors.saturating_add(1);
                tracing::warn!(
                    plugin = %manifest.id,
                    %error,
                    failures = consecutive_status_errors,
                    "Managed plugin isolation status check failed"
                );
                if consecutive_status_errors >= 3 && !healthy {
                    ACTIVE_PROCESSES
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&manifest.id);
                    PLUGIN_HEALTH
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&manifest.id);
                    update_registry_state(
                        &manifest.id,
                        false,
                        port,
                        "error",
                        "Managed plugin isolation runner became unreachable",
                        true,
                    );
                    revoke_all_tokens_for_plugin(&manifest.id);
                    return;
                }
                continue;
            }
        }

        PLUGIN_HEALTH
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(manifest.id.clone(), (port, healthy));
        let state = read_registry_state(&manifest.id);
        if state.enabled
            && (state.token_epoch != epoch || rotated_at.elapsed() >= Duration::from_secs(180))
        {
            match sign_plugin_token(&manifest, state.token_epoch, None, Some(runtime_id)) {
                Ok((token, _)) => {
                    let rotate_req = PluginRunnerTokenRotateRequest {
                        plugin_id: manifest.id.clone(),
                        runtime_id: runtime_id.to_string(),
                        token,
                    };
                    match dispatch_plugin_token_rotate(&rotate_req).await {
                        Ok(()) => {
                            epoch = state.token_epoch;
                            rotated_at = std::time::Instant::now();
                        }
                        Err(error) => {
                            tracing::warn!(
                                plugin = %manifest.id,
                                %error,
                                "Isolated plugin token rotation failed"
                            );
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        plugin = %manifest.id,
                        %error,
                        "Failed to sign rotated plugin token"
                    );
                }
            }
        }
    }
}

async fn stop_tracked_runtime_without_hook(plugin_id: &str) {
    let maybe_runtime = ACTIVE_PROCESSES
        .lock()
        .ok()
        .and_then(|mut map| map.remove(plugin_id));
    PLUGIN_HEALTH
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(plugin_id);
    if let Some(mut runtime) = maybe_runtime {
        if let Some(monitor) = runtime.monitor.take() {
            monitor.abort();
            let _ = monitor.await;
        }
        if af_runner::is_runner_available() && !privileged_runner_explicitly_disabled() {
            let _ = dispatch_plugin_stop(&PluginRunnerStopRequest {
                plugin_id: plugin_id.to_string(),
                port: runtime.port,
                runtime_id: Some(runtime.runtime_id.to_string()),
                api_base_url: resolve_api_base_url()
                    .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
                run_stop_hook: false,
            })
            .await;
        }
    }
}

pub async fn start_plugin_instance(
    manifest: &ValidatedPluginManifest,
) -> Result<PluginRuntimeView, PluginLifecycleError> {
    start_plugin_instance_with_port(manifest, None).await
}

pub async fn start_plugin_instance_with_port(
    manifest: &ValidatedPluginManifest,
    preferred_port: Option<u16>,
) -> Result<PluginRuntimeView, PluginLifecycleError> {
    let spawned_managed = resolve_plugin_executable(manifest).is_some();
    let existing = read_registry_state(&manifest.id);

    if spawned_managed {
        if let Err(err) = check_plugin_isolation_available() {
            let msg = err.to_string();
            update_registry_state(
                &manifest.id,
                false,
                existing.allocated_port,
                "error",
                &msg,
                false,
            );
            return Err(err);
        }
    }

    stop_tracked_runtime_without_hook(&manifest.id).await;
    let port = allocate_plugin_port(
        &manifest.id,
        preferred_port.unwrap_or(existing.allocated_port),
        !spawned_managed,
    )
    .map_err(PluginLifecycleError::Runtime)?;

    let api_base_url = if spawned_managed {
        resolve_api_base_url()?
    } else {
        String::new()
    };

    let state = update_registry_state(&manifest.id, true, port, "running", "", true);
    if !state.enabled || state.allocated_port != port || state.token_epoch == existing.token_epoch {
        return Err(PluginLifecycleError::Runtime(
            "Could not enable plugin registry entry".into(),
        ));
    }

    if spawned_managed {
        let runtime_id = Uuid::new_v4();
        let unit_name = plugin_systemd_unit_name(&manifest.id).ok_or_else(|| {
            PluginLifecycleError::InvalidInput("Invalid plugin identifier".to_string())
        })?;
        let (initial_token, _) =
            sign_plugin_token(manifest, state.token_epoch, None, Some(runtime_id))
                .map_err(PluginLifecycleError::Runtime)?;

        // Register runtime_id prior to launching the isolated systemd unit so immediate
        // startup API calls with the scoped token validate cleanly.
        ACTIVE_PROCESSES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                manifest.id.clone(),
                ActivePluginRuntime {
                    port,
                    unit_name: unit_name.clone(),
                    runtime_id,
                    monitor: None,
                },
            );

        let start_req = PluginRunnerStartRequest {
            plugin_id: manifest.id.clone(),
            port,
            runtime_id: runtime_id.to_string(),
            api_base_url,
            initial_token,
        };
        if let Err(runner_err) = dispatch_plugin_start(&start_req).await {
            ACTIVE_PROCESSES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            PLUGIN_HEALTH
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            let lifecycle_err = PluginLifecycleError::from(runner_err);
            let msg = lifecycle_err.to_string();
            update_registry_state(
                &manifest.id,
                false,
                existing.allocated_port,
                "error",
                &msg,
                true,
            );
            revoke_all_tokens_for_plugin(&manifest.id);
            return Err(lifecycle_err);
        }

        let monitor = tokio::spawn(monitor_plugin(
            manifest.clone(),
            port,
            runtime_id,
            state.token_epoch,
        ));
        let mut procs = ACTIVE_PROCESSES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = procs.get_mut(&manifest.id) {
            if entry.runtime_id == runtime_id {
                entry.monitor = Some(monitor);
            } else {
                monitor.abort();
            }
        } else {
            monitor.abort();
        }
    }

    let max_attempts = if spawned_managed { 30 } else { 1 };
    let mut healthy = false;
    for attempt in 0..max_attempts {
        if probe_plugin_health(port, &manifest.backend.health_path)
            .await
            .unwrap_or(false)
        {
            healthy = true;
            break;
        }
        if attempt + 1 < max_attempts {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    PLUGIN_HEALTH
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(manifest.id.clone(), (port, healthy));
    let state = read_registry_state(&manifest.id);
    Ok(build_runtime_view(manifest, &state, healthy))
}

pub async fn stop_plugin_instance(
    manifest: &ValidatedPluginManifest,
) -> Result<PluginRuntimeView, PluginLifecycleError> {
    let existing = read_registry_state(&manifest.id);
    let has_managed_exec = resolve_plugin_executable(manifest).is_some();
    let has_stop_hook = !manifest.lifecycle_hooks.on_stop.trim().is_empty();

    // Pause the background monitor before running stop/on_stop, while preserving
    // runtime_id in ACTIVE_PROCESSES so an isolated on_stop hook can still call the API.
    let (active_monitor, active_runtime_id, active_port) = {
        let mut procs = ACTIVE_PROCESSES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = procs.get_mut(&manifest.id) {
            (
                entry.monitor.take(),
                Some(entry.runtime_id),
                Some(entry.port),
            )
        } else {
            (None, None, None)
        }
    };
    if let Some(monitor) = active_monitor {
        monitor.abort();
        let _ = monitor.await;
    }

    let needs_isolated_stop =
        active_runtime_id.is_some() || has_stop_hook || (has_managed_exec && existing.enabled);

    if needs_isolated_stop {
        if let Err(err) = check_plugin_isolation_available() {
            ACTIVE_PROCESSES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            PLUGIN_HEALTH
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            revoke_all_tokens_for_plugin(&manifest.id);
            let msg = err.to_string();
            let _ = update_registry_state(
                &manifest.id,
                false,
                existing.allocated_port,
                "error",
                &msg,
                true,
            );
            return Err(err);
        }

        let stop_req = PluginRunnerStopRequest {
            plugin_id: manifest.id.clone(),
            port: active_port.unwrap_or(existing.allocated_port),
            runtime_id: active_runtime_id.map(|id| id.to_string()),
            api_base_url: resolve_api_base_url()
                .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
            run_stop_hook: has_stop_hook,
        };
        if let Err(runner_err) = dispatch_plugin_stop(&stop_req).await {
            ACTIVE_PROCESSES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            PLUGIN_HEALTH
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&manifest.id);
            revoke_all_tokens_for_plugin(&manifest.id);
            let lifecycle_err = PluginLifecycleError::from(runner_err);
            let msg = lifecycle_err.to_string();
            let _ = update_registry_state(
                &manifest.id,
                false,
                existing.allocated_port,
                "error",
                &msg,
                true,
            );
            return Err(lifecycle_err);
        }
    }

    ACTIVE_PROCESSES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&manifest.id);
    PLUGIN_HEALTH
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&manifest.id);
    revoke_all_tokens_for_plugin(&manifest.id);
    let existing = read_registry_state(&manifest.id);
    let state = update_registry_state(
        &manifest.id,
        false,
        existing.allocated_port,
        "stopped",
        "",
        true,
    );
    if state.enabled || state.token_epoch == existing.token_epoch {
        return Err(PluginLifecycleError::Runtime(
            "Could not disable plugin registry entry".into(),
        ));
    }
    Ok(build_runtime_view(manifest, &state, false))
}

pub async fn restart_plugin_instance(
    manifest: &ValidatedPluginManifest,
) -> Result<PluginRuntimeView, PluginLifecycleError> {
    restart_plugin_instance_with_port(manifest, None).await
}

pub async fn restart_plugin_instance_with_port(
    manifest: &ValidatedPluginManifest,
    preferred_port: Option<u16>,
) -> Result<PluginRuntimeView, PluginLifecycleError> {
    if resolve_plugin_executable(manifest).is_some() {
        check_plugin_isolation_available()?;
    }
    stop_plugin_instance(manifest).await?;
    start_plugin_instance_with_port(manifest, preferred_port).await
}

/// Reconciles managed plugins after API startup: auto-starts enabled managed plugins in fresh
/// isolated systemd units and reaps orphaned units belonging to disabled managed plugins.
pub async fn reconcile_managed_plugins_on_startup() {
    let _lifecycle = PLUGIN_LIFECYCLE.lock().await;
    let (manifests, _) = discover_plugins();
    for manifest in manifests {
        if resolve_plugin_executable(&manifest).is_none() {
            continue;
        }
        let state = read_registry_state(&manifest.id);
        if state.enabled || state.status == "running" {
            let preferred = (PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END)
                .contains(&state.allocated_port)
                .then_some(state.allocated_port);
            if let Err(err) = start_plugin_instance_with_port(&manifest, preferred).await {
                tracing::warn!(
                    plugin = %manifest.id,
                    %err,
                    "Failed to auto-start managed plugin during startup reconciliation"
                );
            }
        } else if af_runner::is_runner_available() && !privileged_runner_explicitly_disabled() {
            if let Ok(status) = dispatch_plugin_status(&PluginRunnerStatusRequest {
                plugin_id: manifest.id.clone(),
                runtime_id: None,
            })
            .await
            {
                if status.active {
                    let _ = dispatch_plugin_stop(&PluginRunnerStopRequest {
                        plugin_id: manifest.id.clone(),
                        port: state.allocated_port,
                        runtime_id: None,
                        api_base_url: resolve_api_base_url()
                            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
                        run_stop_hook: false,
                    })
                    .await;
                }
            }
        }
    }
}

/// Gracefully tears down active managed plugin systemd units during API shutdown while
/// preserving their `enabled` preference in SQLite so the next startup reconciles them cleanly.
pub async fn shutdown_managed_plugins() {
    let _lifecycle = PLUGIN_LIFECYCLE.lock().await;
    let active: Vec<(String, u16, Uuid, Option<tokio::task::JoinHandle<()>>)> = {
        let mut procs = ACTIVE_PROCESSES.lock().unwrap_or_else(|e| e.into_inner());
        if procs.is_empty() {
            return;
        }
        procs
            .drain()
            .map(|(id, mut r)| (id, r.port, r.runtime_id, r.monitor.take()))
            .collect()
    };
    let (manifests, _) = discover_plugins();
    let stop_hooks: HashSet<String> = manifests
        .into_iter()
        .filter(|m| !m.lifecycle_hooks.on_stop.trim().is_empty())
        .map(|m| m.id)
        .collect();
    let api_base_url =
        resolve_api_base_url().unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    for (plugin_id, port, runtime_id, monitor) in active {
        if let Some(handle) = monitor {
            handle.abort();
            let _ = handle.await;
        }
        PLUGIN_HEALTH
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&plugin_id);
        revoke_all_tokens_for_plugin(&plugin_id);
        if af_runner::is_runner_available() && !privileged_runner_explicitly_disabled() {
            let _ = dispatch_plugin_stop(&PluginRunnerStopRequest {
                plugin_id: plugin_id.clone(),
                port,
                runtime_id: Some(runtime_id.to_string()),
                api_base_url: api_base_url.clone(),
                run_stop_hook: stop_hooks.contains(&plugin_id),
            })
            .await;
        }
    }
}

fn build_runtime_view(
    manifest: &ValidatedPluginManifest,
    state: &PluginRegistryState,
    healthy: bool,
) -> PluginRuntimeView {
    PluginRuntimeView {
        id: manifest.id.clone(),
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        sdk: manifest.sdk.clone(),
        contract_version: manifest.contract_version.clone(),
        runtime_status: manifest.runtime_status.clone(),
        description: manifest.description.clone(),
        author: manifest.author.clone(),
        permissions: manifest.permissions.clone(),
        granted_scopes: manifest.granted_scopes.clone(),
        enabled: state.enabled,
        status: state.status.clone(),
        healthy,
        allocated_port: state.allocated_port,
        health_path: manifest.backend.health_path.clone(),
        ui_url: format!("/api/v1/auth/plugins/{}/ui", manifest.id),
        proxy_base_url: format!("/api/v1/auth/plugins/{}/proxy", manifest.id),
        slot: manifest.frontend.slot.clone(),
        capabilities: if manifest.frontend.capabilities.is_empty() {
            vec![
                "sandbox-iframe".to_string(),
                "postmessage-bridge".to_string(),
                "scoped-proxy".to_string(),
            ]
        } else {
            manifest.frontend.capabilities.clone()
        },
        last_health_at: state.last_health_at.clone(),
        last_error: state.last_error.clone(),
    }
}

fn find_validated_plugin(plugin_id: &str) -> Result<ValidatedPluginManifest, Box<Response>> {
    if !is_valid_plugin_id(plugin_id) {
        return Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_PLUGIN_ID",
            "Invalid plugin identifier",
        )));
    }
    let (manifests, rejected) = discover_plugins();
    if let Some(m) = manifests.into_iter().find(|m| m.id == plugin_id) {
        return Ok(m);
    }
    if let Some((_, reason)) = rejected.into_iter().find(|(dir, _)| dir == plugin_id) {
        return Err(Box::new(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_PLUGIN_MANIFEST",
            reason,
        )));
    }
    Err(Box::new(api_error(
        StatusCode::NOT_FOUND,
        "PLUGIN_NOT_FOUND",
        "Plugin not found",
    )))
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP Handlers: Discovery, Control, Token Minting, UI & Reverse Proxy
// ─────────────────────────────────────────────────────────────────────────────

pub async fn list_plugins_handler(Extension(user): Extension<AuthUser>) -> Response {
    let admin = user.role == "admin";
    tokio::task::spawn_blocking(move || {
        let (manifests, rejected) = discover_plugins();
        let health = PLUGIN_HEALTH
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let views: Vec<_> = manifests
            .iter()
            .map(|manifest| {
                let state = read_registry_state(&manifest.id);
                let healthy = state.enabled
                    && health.get(&manifest.id) == Some(&(state.allocated_port, true));
                let view = build_runtime_view(manifest, &state, healthy);
                let mut value = serde_json::json!(view);
                if !admin {
                    if let Some(fields) = value.as_object_mut() {
                        fields.remove("allocated_port");
                        fields.remove("last_error");
                    }
                }
                value
            })
            .collect();
        let rejected: Vec<_> = rejected
            .into_iter()
            .filter(|_| admin)
            .map(|(id, error)| serde_json::json!({ "id": id, "error": error }))
            .collect();
        Json(serde_json::json!({ "plugins": views, "rejected": rejected })).into_response()
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PLUGIN_DISCOVERY_ERROR",
            "Plugin discovery failed",
        )
    })
}

#[derive(Debug, Deserialize)]
pub struct PluginControlRequest {
    pub action: String,
    #[serde(default)]
    pub port: Option<u16>,
}

pub async fn control_plugin_handler(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<PluginControlRequest>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
    let _lifecycle = PLUGIN_LIFECYCLE.lock().await;
    let manifest = match find_validated_plugin(&id) {
        Ok(m) => m,
        Err(response) => return *response,
    };

    if let Some(custom_port) = req.port {
        if !(PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&custom_port) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_PLUGIN_PORT",
                format!(
                    "Plugin port must be within loopback range {}..{}",
                    PLUGIN_PORT_RANGE_START, PLUGIN_PORT_RANGE_END
                ),
            );
        }
    }

    let action = req.action.trim().to_lowercase();
    let result = match action.as_str() {
        "start" | "enable" => start_plugin_instance_with_port(&manifest, req.port).await,
        "stop" | "disable" => stop_plugin_instance(&manifest).await,
        "restart" => restart_plugin_instance_with_port(&manifest, req.port).await,
        "revoke_tokens" => {
            revoke_all_tokens_for_plugin(&manifest.id);
            let existing = read_registry_state(&manifest.id);
            let updated = update_registry_state(
                &manifest.id,
                existing.enabled,
                existing.allocated_port,
                &existing.status,
                "",
                true,
            );
            let active_rid = ACTIVE_PROCESSES
                .lock()
                .ok()
                .and_then(|procs| procs.get(&manifest.id).map(|r| r.runtime_id));
            if let Some(runtime_id) = active_rid {
                if updated.enabled {
                    if let Ok((token, _)) =
                        sign_plugin_token(&manifest, updated.token_epoch, None, Some(runtime_id))
                    {
                        let _ = dispatch_plugin_token_rotate(&PluginRunnerTokenRotateRequest {
                            plugin_id: manifest.id.clone(),
                            runtime_id: runtime_id.to_string(),
                            token,
                        })
                        .await;
                    }
                }
            }
            let healthy = PLUGIN_HEALTH
                .lock()
                .ok()
                .and_then(|h| h.get(&manifest.id).copied())
                .is_some_and(|(p, ok)| p == updated.allocated_port && ok);
            Ok(build_runtime_view(&manifest, &updated, healthy))
        }
        _ => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ACTION",
                "Allowed plugin actions: start, stop, restart, enable, disable, revoke_tokens",
            )
        }
    };

    match result {
        Ok(view) => {
            let ip = crate::ws::extract_client_ip(&headers);
            let ua = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            af_db::record_audit(
                auth_user.user_id,
                &auth_user.username,
                &format!("plugin_{}", action),
                "plugin",
                &manifest.id,
                &format!("port={}", view.allocated_port),
                &ip,
                ua,
            );
            Json(serde_json::json!({
                "message": format!("Plugin '{}' action '{}' completed", manifest.id, action),
                "plugin": view,
            }))
            .into_response()
        }
        Err(err) => err.into_api_response(),
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct MintPluginTokenRequest {
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

pub async fn mint_plugin_token_handler(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    body: Option<Json<MintPluginTokenRequest>>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
    let manifest = match find_validated_plugin(&id) {
        Ok(m) => m,
        Err(response) => return *response,
    };

    let ttl = body.and_then(|b| b.0.ttl_seconds);
    match mint_scoped_plugin_token(&manifest, ttl) {
        Ok((token, claims)) => {
            let ip = crate::ws::extract_client_ip(&headers);
            let ua = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            af_db::record_audit(
                auth_user.user_id,
                &auth_user.username,
                "plugin_token_mint",
                "plugin",
                &manifest.id,
                &claims.jti,
                &ip,
                ua,
            );
            Json(serde_json::json!({
                "token": token,
                "token_type": claims.typ,
                "audience": claims.aud,
                "plugin_id": manifest.id,
                "jti": claims.jti,
                "expires_at": claims.exp,
                "scopes": claims.scopes,
            }))
            .into_response()
        }
        Err(err) => api_error(StatusCode::CONFLICT, "PLUGIN_NOT_ENABLED", err),
    }
}

pub async fn serve_plugin_ui_handler(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    let manifest = match find_validated_plugin(&id) {
        Ok(m) => m,
        Err(response) => return *response,
    };
    if plugin_requires_admin(&manifest.permissions) {
        if let Err(response) = crate::auth::require_admin(&auth_user) {
            return *response;
        }
    }

    let state = read_registry_state(&manifest.id);
    if !state.enabled {
        return api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_DISABLED",
            "Plugin must be enabled before mounting its UI",
        );
    }

    // Check if plugin provides a custom HTML bundle file inside its directory
    let custom_html = if !manifest.frontend.bundle.trim().is_empty() {
        validate_relative_plugin_subpath(&manifest.plugin_dir, &manifest.frontend.bundle, true)
            .ok()
            .and_then(|p| fs::read_to_string(p).ok())
    } else {
        validate_relative_plugin_subpath(&manifest.plugin_dir, "frontend/dist/index.html", true)
            .ok()
            .and_then(|p| fs::read_to_string(p).ok())
    };

    let html = custom_html.unwrap_or_else(|| render_default_sandboxed_plugin_ui(&manifest, &state));

    let mut resp = html.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    h.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; frame-ancestors 'self'; sandbox allow-scripts",
        ),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    resp
}

fn render_default_sandboxed_plugin_ui(
    manifest: &ValidatedPluginManifest,
    state: &PluginRegistryState,
) -> String {
    let scopes_label = if manifest.granted_scopes.is_empty() {
        "none (default-deny)".to_string()
    } else {
        manifest
            .granted_scopes
            .iter()
            .map(|s| format!("{} {}", s.method, s.route))
            .collect::<Vec<_>>()
            .join(", ")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{name} ({version})</title>
<style>
  body {{
    margin: 0;
    padding: 16px;
    background: #050811;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
  }}
  .card {{
    border: 1px solid rgba(99, 102, 241, 0.25);
    background: rgba(15, 23, 42, 0.75);
    border-radius: 12px;
    padding: 16px;
  }}
  .badge {{
    display: inline-block;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 999px;
    background: rgba(16, 185, 129, 0.15);
    color: #6ee7b7;
    border: 1px solid rgba(16, 185, 129, 0.3);
  }}
  button {{
    margin-top: 12px;
    background: #4f46e5;
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
  }}
  pre {{
    margin-top: 12px;
    padding: 10px;
    background: #020617;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 8px;
    font-size: 11px;
    overflow-x: auto;
  }}
</style>
</head>
<body>
  <div class="card" data-plugin-id="{id}">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <strong>{name} <span style="opacity:0.6;">v{version}</span></strong>
      <span class="badge">Sandboxed Capability Bridge · Port {port}</span>
    </div>
    <p style="font-size:12px;color:#94a3b8;margin:8px 0;">{desc}</p>
    <div style="font-size:11px;color:#64748b;">Granted Scopes: <code>{scopes}</code></div>
    <button id="probe-btn" type="button">Probe Plugin /status via Host Bridge</button>
    <pre id="output">Waiting for host capability handshake...</pre>
  </div>
  <script>
    const pluginId = {id_json};
    const out = document.getElementById('output');
    window.addEventListener('message', (event) => {{
      const msg = event.data || {{}};
      if (msg.type === 'AF_PLUGIN_INIT') {{
        out.textContent = JSON.stringify({{ status: 'handshake_complete', capabilities: msg.capabilities || [] }}, null, 2);
      }} else if (msg.type === 'AF_PLUGIN_PROXY_RESPONSE') {{
        out.textContent = JSON.stringify(msg.payload, null, 2);
      }}
    }});
    document.getElementById('probe-btn').addEventListener('click', () => {{
      window.parent.postMessage({{
        type: 'AF_PLUGIN_PROXY_REQUEST',
        pluginId,
        path: 'status',
        method: 'GET'
      }}, window.location.origin);
    }});
    window.parent.postMessage({{ type: 'AF_PLUGIN_READY', pluginId }}, window.location.origin);
  </script>
</body>
</html>"#,
        id = html_escape(&manifest.id),
        name = html_escape(&manifest.name),
        version = html_escape(&manifest.version),
        port = state.allocated_port,
        desc = html_escape(&manifest.description),
        scopes = html_escape(&scopes_label),
        id_json = serde_json::to_string(&manifest.id).unwrap_or_else(|_| "\"\"".to_string()),
    )
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// This internal response marker survives the routing and auth layers and cannot
// be supplied by an upstream plugin as an HTTP header. The outer security-header
// middleware uses it to isolate every proxied representation as a document.
#[derive(Clone, Copy)]
pub(crate) struct ProxiedPluginResponse;

fn mark_plugin_proxy_response(mut response: Response) -> Response {
    response.extensions_mut().insert(ProxiedPluginResponse);
    response
}

pub async fn proxy_plugin_root_handler(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    req: Request,
) -> Response {
    mark_plugin_proxy_response(proxy_plugin_request_inner(id, String::new(), auth_user, req).await)
}

pub async fn proxy_plugin_wildcard_handler(
    Path((id, rest)): Path<(String, String)>,
    Extension(auth_user): Extension<AuthUser>,
    req: Request,
) -> Response {
    mark_plugin_proxy_response(proxy_plugin_request_inner(id, rest, auth_user, req).await)
}

#[allow(clippy::result_large_err)]
async fn collect_proxy_body(body: Body) -> Result<axum::body::Bytes, Response> {
    match axum::body::to_bytes(body, MAX_PLUGIN_PROXY_BODY_BYTES).await {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            use std::error::Error;
            if error
                .source()
                .is_some_and(|cause| cause.is::<http_body_util::LengthLimitError>())
            {
                Err(api_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "PAYLOAD_TOO_LARGE",
                    "Plugin proxy request body exceeds 2 MiB limit",
                ))
            } else {
                Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_BODY",
                    "Failed to read plugin proxy request body",
                ))
            }
        }
    }
}

#[allow(clippy::result_large_err)]
async fn collect_proxy_response(mut upstream_resp: reqwest::Response) -> Result<Vec<u8>, Response> {
    let mut resp_bytes = Vec::new();
    loop {
        match upstream_resp.chunk().await {
            Ok(Some(chunk)) => {
                if resp_bytes.len().saturating_add(chunk.len()) > MAX_PLUGIN_PROXY_BODY_BYTES {
                    return Err(api_error(
                        StatusCode::BAD_GATEWAY,
                        "PLUGIN_RESPONSE_TOO_LARGE",
                        "Plugin upstream response exceeded maximum 2 MiB size limit",
                    ));
                }
                resp_bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                return Err(api_error(
                    StatusCode::BAD_GATEWAY,
                    "PLUGIN_READ_ERROR",
                    format!("Failed reading plugin response: {}", e),
                ));
            }
        }
    }

    Ok(resp_bytes)
}

async fn proxy_plugin_request_inner(
    id: String,
    subpath: String,
    auth_user: AuthUser,
    req: Request,
) -> Response {
    // Reject plugin tokens from calling the plugin proxy to prevent recursive proxy loops
    if auth_user.jti.starts_with("plg-") {
        return api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_PROXY_FORBIDDEN",
            "Plugin tokens cannot invoke the host plugin proxy",
        );
    }

    let manifest = match find_validated_plugin(&id) {
        Ok(m) => m,
        Err(response) => return *response,
    };

    if plugin_requires_admin(&manifest.permissions) {
        if let Err(response) = crate::auth::require_admin(&auth_user) {
            return *response;
        }
    }

    let state = read_registry_state(&manifest.id);
    if !state.enabled || state.status == "stopped" {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "PLUGIN_STOPPED",
            format!("Plugin '{}' is not enabled or running", manifest.id),
        );
    }

    let port = state.allocated_port;
    if !(PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&port) {
        return api_error(
            StatusCode::BAD_GATEWAY,
            "INVALID_UPSTREAM_PORT",
            "Plugin port is outside the permitted loopback range",
        );
    }

    let clean_subpath = subpath.trim_start_matches('/');
    let raw_uri_path = req.uri().path().to_ascii_lowercase();
    let lower_subpath = clean_subpath.to_ascii_lowercase();
    if clean_subpath.contains("..")
        || clean_subpath.contains('\\')
        || clean_subpath.starts_with("//")
        || lower_subpath.contains("%2e")
        || lower_subpath.contains("%2f")
        || lower_subpath.contains("%5c")
        || raw_uri_path.contains("..")
        || raw_uri_path.contains("%2e")
        || raw_uri_path.contains("%5c")
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_PROXY_PATH",
            "Path traversal in plugin proxy request is forbidden",
        );
    }

    let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    if !target_addr.ip().is_loopback() {
        return api_error(
            StatusCode::FORBIDDEN,
            "SSRF_BLOCKED",
            "Plugin upstream must resolve strictly to 127.0.0.1 loopback",
        );
    }

    let query_suffix = req
        .uri()
        .query()
        .filter(|q| !q.is_empty())
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let target_url = if clean_subpath.is_empty() {
        format!("http://127.0.0.1:{}/{}", port, query_suffix)
    } else {
        format!(
            "http://127.0.0.1:{}/{}{}",
            port, clean_subpath, query_suffix
        )
    };

    let method = req.method().clone();
    let req_headers = req.headers().clone();

    let body_bytes = match collect_proxy_body(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };

    let reqwest_method = match reqwest::Method::from_bytes(method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return api_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "INVALID_METHOD",
                "Unsupported HTTP method",
            )
        }
    };

    let mut upstream_req = PROXY_HTTP_CLIENT
        .request(reqwest_method, &target_url)
        .body(body_bytes.to_vec());

    // Forward safe headers ONLY — strip Cookie, Authorization, X-CSRF-Token, identity headers, and hop-by-hop headers
    for (name, val) in req_headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if lower.starts_with("x-aetherflow-")
            || matches!(
                lower.as_str(),
                "cookie"
                    | "authorization"
                    | "x-csrf-token"
                    | "remote-user"
                    | "x-remote-user"
                    | "x-forwarded-user"
                    | "x-forwarded-email"
                    | "x-forwarded-groups"
                    | "host"
                    | "connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "upgrade"
                    | "content-length"
            )
        {
            continue;
        }
        if let (Ok(r_name), Ok(r_val)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(val.as_bytes()),
        ) {
            upstream_req = upstream_req.header(r_name, r_val);
        }
    }

    upstream_req = upstream_req
        .header("X-AetherFlow-Plugin-Id", &manifest.id)
        .header("X-AetherFlow-User", &auth_user.username)
        .header("X-AetherFlow-Role", &auth_user.role);

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            return api_error(
                StatusCode::BAD_GATEWAY,
                "PLUGIN_UPSTREAM_UNAVAILABLE",
                format!("Plugin '{}' upstream failed: {}", manifest.id, e),
            )
        }
    };

    // Block upstream redirects so plugins cannot redirect operators to external origins
    if upstream_resp.status().is_redirection() {
        return api_error(
            StatusCode::BAD_GATEWAY,
            "PLUGIN_REDIRECT_BLOCKED",
            "Plugin upstream redirects are disallowed by security policy",
        );
    }

    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let upstream_headers = upstream_resp.headers().clone();

    let resp_bytes = match collect_proxy_response(upstream_resp).await {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };

    let mut response = Response::builder()
        .status(status)
        .body(Body::from(resp_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());

    let out_headers = response.headers_mut();
    for (name, val) in upstream_headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        // Never allow a plugin upstream to set cookies on the AetherFlow host origin!
        if matches!(
            lower.as_str(),
            "set-cookie"
                | "set-cookie2"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "upgrade"
                | "location"
                | "content-security-policy"
                | "x-frame-options"
        ) {
            continue;
        }
        if let (Ok(h_name), Ok(h_val)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(val.as_bytes()),
        ) {
            out_headers.insert(h_name, h_val);
        }
    }
    out_headers.insert(
        "X-AetherFlow-Proxied-Plugin",
        HeaderValue::from_str(&manifest.id).unwrap_or_else(|_| HeaderValue::from_static("plugin")),
    );

    response
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn run_plugin_test_in_subprocess() -> bool {
        if std::env::var_os("AETHERFLOW_PLUGIN_TEST_ISOLATED").is_some() {
            return false;
        }
        let thread = std::thread::current();
        let test_name = thread.name().expect("named Rust test thread");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env("AETHERFLOW_PLUGIN_TEST_ISOLATED", "1")
            .status()
            .expect("start isolated plugin fixture");
        assert!(
            status.success(),
            "isolated plugin fixture failed: {test_name}"
        );
        true
    }

    #[tokio::test]
    async fn proxy_body_collection_stops_at_limit_and_distinguishes_transport_errors() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = polls.clone();
        let body = Body::from_stream(futures::stream::unfold(0, move |index| {
            let observed = observed.clone();
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                assert!(
                    index <= MAX_PLUGIN_PROXY_BODY_BYTES / 65536,
                    "Must not poll stream past first over-limit chunk"
                );
                Some((Ok::<_, std::io::Error>(vec![0u8; 65536]), index + 1))
            }
        }));
        assert_eq!(
            collect_proxy_body(body).await.unwrap_err().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            MAX_PLUGIN_PROXY_BODY_BYTES / 65536 + 1
        );
        assert_eq!(
            collect_proxy_body(Body::from(vec![0u8; MAX_PLUGIN_PROXY_BODY_BYTES]))
                .await
                .unwrap()
                .len(),
            MAX_PLUGIN_PROXY_BODY_BYTES
        );
        let body = Body::from_stream(futures::stream::once(async {
            Err::<Vec<u8>, _>(std::io::Error::other("broken transport"))
        }));
        assert_eq!(
            collect_proxy_body(body).await.unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn upstream_response_limit_rejects_before_the_unfinished_body_ends() {
        use futures::StreamExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/",
                axum::routing::get(|| async {
                    let stream = futures::stream::iter(
                        (0..34).map(|_| Ok::<_, std::io::Error>(vec![b'x'; 65536])),
                    )
                    .chain(futures::stream::pending());
                    Body::from_stream(stream)
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        let response = reqwest::get(format!("http://{address}/")).await.unwrap();
        let result =
            tokio::time::timeout(Duration::from_secs(2), collect_proxy_response(response)).await;
        server.abort();
        let rejected = result
            .expect("Must reject the first chunk beyond 2 MiB without waiting for EOF")
            .unwrap_err();
        assert_eq!(rejected.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(rejected.into_body(), 10000)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("PLUGIN_RESPONSE_TOO_LARGE"));
    }

    #[test]
    fn test_manifest_validation_rejects_bad_ids_and_traversal() {
        let tmp = std::env::temp_dir().join(format!("af-plugin-test-{}", Uuid::new_v4()));
        let plugin_dir = tmp.join("valid-plugin");
        fs::create_dir_all(&plugin_dir).unwrap();

        let bad_id_manifest = RawPluginManifest {
            id: "../escape".to_string(),
            name: "Bad".to_string(),
            version: "0.1.0".to_string(),
            sdk: "rust".to_string(),
            contract_version: "v1".to_string(),
            runtime_status: "managed".to_string(),
            description: String::new(),
            author: String::new(),
            permissions: vec!["system:metrics:read".to_string()],
            api_scopes: vec![],
            lifecycle_hooks: PluginLifecycleHooks::default(),
            backend: PluginBackendSpec::default(),
            frontend: PluginFrontendSpec::default(),
        };
        assert!(validate_plugin_manifest(&plugin_dir, bad_id_manifest).is_err());

        let traversal_hook_manifest = RawPluginManifest {
            id: "valid-plugin".to_string(),
            name: "Traversal".to_string(),
            version: "0.1.0".to_string(),
            sdk: "rust".to_string(),
            contract_version: "v1".to_string(),
            runtime_status: "managed".to_string(),
            description: String::new(),
            author: String::new(),
            permissions: vec!["system:metrics:read".to_string()],
            api_scopes: vec![],
            lifecycle_hooks: PluginLifecycleHooks {
                on_start: "../../etc/passwd".to_string(),
                on_stop: String::new(),
            },
            backend: PluginBackendSpec::default(),
            frontend: PluginFrontendSpec::default(),
        };
        assert!(validate_plugin_manifest(&plugin_dir, traversal_hook_manifest).is_err());

        let forbidden_scope_manifest = RawPluginManifest {
            id: "valid-plugin".to_string(),
            name: "ForbiddenScope".to_string(),
            version: "0.1.0".to_string(),
            sdk: "rust".to_string(),
            contract_version: "v1".to_string(),
            runtime_status: "managed".to_string(),
            description: String::new(),
            author: String::new(),
            permissions: vec!["system:metrics:read".to_string()],
            api_scopes: vec![RawScopeEntry::Simple("/api/v1/admin/users".to_string())],
            lifecycle_hooks: PluginLifecycleHooks::default(),
            backend: PluginBackendSpec::default(),
            frontend: PluginFrontendSpec::default(),
        };
        assert!(validate_plugin_manifest(&plugin_dir, forbidden_scope_manifest).is_err());

        let systemd_specifier_manifest = RawPluginManifest {
            id: "valid-plugin".to_string(),
            name: "Valid".to_string(),
            version: "0.1.0".to_string(),
            sdk: "rust".to_string(),
            contract_version: "v1".to_string(),
            runtime_status: "managed".to_string(),
            description: String::new(),
            author: String::new(),
            permissions: vec![],
            api_scopes: vec![],
            lifecycle_hooks: PluginLifecycleHooks {
                on_start: "hooks/%i.sh".to_string(),
                on_stop: String::new(),
            },
            backend: PluginBackendSpec::default(),
            frontend: PluginFrontendSpec::default(),
        };
        assert!(validate_plugin_manifest(&plugin_dir, systemd_specifier_manifest).is_err());

        let control_char_name_manifest = RawPluginManifest {
            id: "valid-plugin".to_string(),
            name: "Bad\nINJECT=1".to_string(),
            version: "0.1.0".to_string(),
            sdk: "rust".to_string(),
            contract_version: "v1".to_string(),
            runtime_status: "managed".to_string(),
            description: String::new(),
            author: String::new(),
            permissions: vec![],
            api_scopes: vec![],
            lifecycle_hooks: PluginLifecycleHooks::default(),
            backend: PluginBackendSpec::default(),
            frontend: PluginFrontendSpec::default(),
        };
        assert!(validate_plugin_manifest(&plugin_dir, control_char_name_manifest).is_err());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn destructive_plugin_scope_policy_rejects_explicit_and_overlapping_wildcards() {
        let destructive = [
            "/api/v1/admin/packages/demo/uninstall",
            "/api/admin/packages/*",
            "/api/v1/admin/services/aetherflow-api/control",
            "/api/admin/services/aetherflow-runner/control",
            "/api/v1/admin/system/update/run",
            "/api/v1/auth/deploy/demo",
            "/api/v1/auth/services/restart",
            "/api/v1/admin/*",
            "/api/v1/admin/pack*",
            "/api/v*",
            "/api/*",
        ];
        for permission in ["packages:write", "services:control", "system:admin"] {
            for route in destructive {
                for method in ["POST", "PUT", "PATCH", "DELETE"] {
                    let scope = RawScopeEntry::Simple(format!("{method} {route}"));
                    assert!(
                        normalize_scope_entry(&scope, &[permission.into()]).is_err(),
                        "{permission}: {method} {route}"
                    );
                }
            }
        }
        for route in [
            "/api/v1/admin/services/restart/status",
            "/api/admin/system/update/status",
            "/api/v1/ingress/configs",
            "/api/v1/admin/*",
            "/api/v1/auth/*",
        ] {
            assert!(normalize_scope_entry(
                &RawScopeEntry::Simple(format!("GET {route}")),
                &["telemetry:read".into()],
            )
            .is_err());
        }
        assert!(normalize_scope_entry(
            &RawScopeEntry::Simple("GET /api/auth/services".into()),
            &["telemetry:read".into()],
        )
        .is_ok());
        for permission in ["system:read", "demo:write", "services:control"] {
            assert!(normalize_scope_entry(
                &RawScopeEntry::Simple("POST /api/v1/auth/notifications/1/read".into()),
                &[permission.into()],
            )
            .is_err());
        }
    }

    #[test]
    fn destructive_plugin_request_policy_blocks_previously_minted_grants() {
        let mut claims = PluginTokenClaims {
            typ: PLUGIN_TOKEN_TYP.into(),
            iss: PLUGIN_TOKEN_ISSUER.into(),
            aud: PLUGIN_TOKEN_AUDIENCE.into(),
            sub: "plugin:fixture".into(),
            plugin_id: "fixture".into(),
            jti: "fixture".into(),
            iat: 1,
            exp: 2,
            epoch: 1,
            scopes: Vec::new(),
        };
        for path in [
            "/api/v1/admin/packages/demo/install",
            "/api/admin/packages/demo/uninstall",
            "/api/v1/admin/packages/demo/update",
            "/api/v1/admin/services/aetherflow-api/control",
            "/api/admin/services/demo/control",
            "/api/v1/admin/system/update/run",
            "/api/auth/deploy/demo",
        ] {
            for scope in [path, "/api/v1/admin/*", "/api/*"] {
                for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
                    claims.scopes = vec![PluginScopeRule {
                        method: method.to_string(),
                        route: scope.into(),
                    }];
                    assert!(
                        !plugin_claims_allow_request(&claims, &method, path),
                        "{method} {path} from {scope}"
                    );
                }
            }
        }
        for (path, allowed) in [
            ("/api/v1/auth/services", true),
            ("/api/v1/admin/services/restart/status", false),
            ("/api/admin/system/update/status", false),
            ("/api/v1/ingress/configs", false),
            ("/api/ingress/configs", false),
            ("/api/v1/auth/packages/demo/progress", true),
        ] {
            for method in [Method::GET, Method::HEAD] {
                claims.scopes = vec![PluginScopeRule {
                    method: method.to_string(),
                    route: "/api/*".into(),
                }];
                assert_eq!(
                    plugin_claims_allow_request(&claims, &method, path),
                    allowed,
                    "{path}"
                );
            }
        }
        assert!(plugin_requires_admin(&["services:control".into()]));
        assert!(plugin_requires_admin(&["unknown:admin".into()]));
        assert!(!plugin_requires_admin(&["telemetry:read".into()]));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_plugin_fails_closed_with_actionable_503_when_isolation_unavailable() {
        if run_plugin_test_in_subprocess() {
            return;
        }
        use std::os::unix::fs::PermissionsExt;

        let _env_guard = test_env_lock().lock().await;
        let db = ensure_shared_test_db();
        let tmp = db
            .parent()
            .unwrap()
            .join(format!("fail-closed-{}", Uuid::new_v4()));
        let plugins_root = tmp.join("plugins");
        let plugin_dir = plugins_root.join("managed-fixture");
        let hooks_dir = plugin_dir.join("backend/hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        fs::set_permissions(&plugins_root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&plugin_dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            plugin_dir.join("backend"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::set_permissions(&hooks_dir, fs::Permissions::from_mode(0o755)).unwrap();

        let forbidden_marker = tmp.join("api-user-executed.marker");
        let start_hook = hooks_dir.join("start.sh");
        fs::write(
            &start_hook,
            format!("#!/bin/bash\ntouch {:?}\n", forbidden_marker),
        )
        .unwrap();
        fs::set_permissions(&start_hook, fs::Permissions::from_mode(0o755)).unwrap();
        let stop_hook = hooks_dir.join("stop.sh");
        fs::write(
            &stop_hook,
            format!("#!/bin/bash\ntouch {:?}\n", forbidden_marker),
        )
        .unwrap();
        fs::set_permissions(&stop_hook, fs::Permissions::from_mode(0o755)).unwrap();

        let manifest_json = serde_json::json!({
            "id": "managed-fixture",
            "name": "Managed Fixture",
            "version": "1.0.0",
            "permissions": ["system:metrics:read"],
            "api_scopes": ["GET /api/v1/auth/system/metrics"],
            "lifecycle_hooks": {
                "on_start": "backend/hooks/start.sh",
                "on_stop": "backend/hooks/stop.sh"
            },
            "backend": { "health_path": "/healthz" }
        });
        fs::write(
            plugin_dir.join("plugin.manifest.json"),
            serde_json::to_vec_pretty(&manifest_json).unwrap(),
        )
        .unwrap();

        env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
        env::set_var("AETHERFLOW_RUNNER_SOCK", tmp.join("absent-runner.sock"));
        env::remove_var("PRIVILEGED_RUNNER_ENABLED");

        let admin = AuthUser {
            user_id: 1,
            username: "admin".into(),
            role: "admin".into(),
            jti: "op-1".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };

        // 1. Start must fail closed with 503 PLUGIN_ISOLATION_UNAVAILABLE and never spawn locally
        let start_resp = control_plugin_handler(
            Path("managed-fixture".into()),
            Extension(admin.clone()),
            HeaderMap::new(),
            Json(PluginControlRequest {
                action: "start".into(),
                port: Some(21444),
            }),
        )
        .await;
        assert_eq!(start_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(start_resp.into_body(), 8192)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("PLUGIN_ISOLATION_UNAVAILABLE"), "body={text}");
        assert!(
            text.contains("aetherflow-runner.service"),
            "actionable runner hint missing: {text}"
        );
        assert!(
            !forbidden_marker.exists(),
            "af-api MUST NOT fall back to spawning plugin hooks as the API user"
        );
        let reg = read_registry_state("managed-fixture");
        assert!(!reg.enabled);
        assert_eq!(
            reg.allocated_port, 0,
            "failed start must not persist custom port mutation"
        );
        assert_eq!(reg.status, "error");

        // 2. Stop with on_stop hook also fails closed without running hook as API user
        let stop_resp = control_plugin_handler(
            Path("managed-fixture".into()),
            Extension(admin.clone()),
            HeaderMap::new(),
            Json(PluginControlRequest {
                action: "stop".into(),
                port: None,
            }),
        )
        .await;
        assert_eq!(stop_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!forbidden_marker.exists());

        // 3. Explicitly disabled PRIVILEGED_RUNNER_ENABLED=false also fails closed with 503
        env::set_var("PRIVILEGED_RUNNER_ENABLED", "false");
        let disabled_resp = control_plugin_handler(
            Path("managed-fixture".into()),
            Extension(admin),
            HeaderMap::new(),
            Json(PluginControlRequest {
                action: "start".into(),
                port: None,
            }),
        )
        .await;
        assert_eq!(disabled_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let disabled_body = axum::body::to_bytes(disabled_resp.into_body(), 8192)
            .await
            .unwrap();
        let disabled_text = String::from_utf8_lossy(&disabled_body);
        assert!(disabled_text.contains("PRIVILEGED_RUNNER_ENABLED"));
        assert!(!forbidden_marker.exists());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_scope_method_and_default_deny_enforcement() {
        let claims = PluginTokenClaims {
            typ: PLUGIN_TOKEN_TYP.to_string(),
            iss: PLUGIN_TOKEN_ISSUER.to_string(),
            aud: PLUGIN_TOKEN_AUDIENCE.to_string(),
            sub: "plugin:demo".to_string(),
            plugin_id: "demo".to_string(),
            jti: "plg-demo-1".to_string(),
            iat: 1000,
            exp: 2000,
            epoch: 1,
            scopes: vec![PluginScopeRule {
                method: "GET".to_string(),
                route: "/api/v1/auth/system/metrics".to_string(),
            }],
        };

        assert!(plugin_claims_allow_request(
            &claims,
            &Method::GET,
            "/api/v1/auth/system/metrics"
        ));
        assert!(!plugin_claims_allow_request(
            &claims,
            &Method::POST,
            "/api/v1/auth/system/metrics"
        ));
        assert!(!plugin_claims_allow_request(
            &claims,
            &Method::GET,
            "/api/v1/auth/session"
        ));
        assert!(!plugin_claims_allow_request(
            &claims,
            &Method::POST,
            "/api/v1/auth/refresh"
        ));
        assert!(!plugin_claims_allow_request(
            &claims,
            &Method::GET,
            "/api/v1/admin/users"
        ));
    }

    #[test]
    fn test_credential_domain_separation_and_mutating_scope_permission_gate() {
        // Read-only permissions cannot request POST scopes
        let read_only_perms = vec!["system:metrics:read".to_string()];
        let post_scope = RawScopeEntry::Simple("POST /api/v1/auth/system/metrics".to_string());
        assert!(normalize_scope_entry(&post_scope, &read_only_perms).is_err());

        // Write permissions allow explicit POST scope on non-denied route
        let write_perms = vec!["notifications:write".to_string()];
        let valid_post =
            RawScopeEntry::Simple("POST /api/v1/auth/notifications/1/read".to_string());
        let rules = normalize_scope_entry(&valid_post, &write_perms).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].method, "POST");

        // Operator session tokens signed with raw JWT_SECRET cannot validate as plugin tokens
        let fake_session = crate::auth::SessionClaims {
            user_id: 1,
            sub: "1".to_string(),
            iss: "aetherflow".to_string(),
            iat: Utc::now().timestamp(),
            auth_time: Utc::now().timestamp(),
            exp: Utc::now().timestamp() + 900,
            jti: "op-session-1".to_string(),
            cfp: String::new(),
            ver: 0,
            plugin_id: String::new(),
            plugin_scopes: Vec::new(),
        };
        let op_jwt = encode(
            &Header::new(Algorithm::HS256),
            &fake_session,
            &EncodingKey::from_secret(&jwt_secret_bytes()),
        )
        .unwrap();
        assert!(decode_and_verify_plugin_token(&op_jwt).is_err());
    }

    pub(crate) fn test_env_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    pub(crate) fn ensure_shared_test_db() -> &'static PathBuf {
        static DB_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        DB_PATH.get_or_init(|| {
            let db_dir =
                std::env::temp_dir().join(format!("af-plugin-shared-db-{}", Uuid::new_v4()));
            fs::create_dir_all(&db_dir).unwrap();
            let db_path = db_dir.join("test.sqlite");
            std::env::set_var("DB_PATH", &db_path);
            let _ = af_db::init_db();
            db_path
        })
    }

    #[tokio::test]
    async fn plugin_listing_uses_cached_health_and_redacts_operator_details() {
        if run_plugin_test_in_subprocess() {
            return;
        }
        let db = ensure_shared_test_db();
        let root = db.parent().unwrap().join("list-plugins");
        let plugin = root.join("test-plugin");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.manifest.json"),
            r#"{
            "id": "test-plugin", "name": "Fixture", "version": "1.0.0", "sdk": "rust",
            "backend": {"health_path": "/healthz"}
        }"#,
        )
        .unwrap();
        fs::create_dir_all(root.join("rejected-plugin")).unwrap();
        fs::write(root.join("rejected-plugin/plugin.manifest.json"), "invalid").unwrap();
        env::set_var("AETHERFLOW_PLUGINS_DIR", &root);
        update_registry_state(
            "test-plugin",
            true,
            21099,
            "running",
            "private diagnostic",
            false,
        );
        PLUGIN_HEALTH
            .lock()
            .unwrap()
            .insert("test-plugin".into(), (21099, true));

        let writer = af_db::get_conn().unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        for role in ["user", "admin"] {
            let user = AuthUser {
                user_id: 1,
                username: "fixture".into(),
                role: role.into(),
                jti: String::new(),
                plugin_id: None,
                plugin_scopes: Vec::new(),
            };
            let response = tokio::time::timeout(
                Duration::from_secs(1),
                list_plugins_handler(Extension(user)),
            )
            .await
            .expect("plugin listing does not wait on the writer");
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let plugin = &result["plugins"][0];
            assert_eq!(plugin["id"], "test-plugin");
            assert_eq!(plugin["healthy"], true);
            assert_eq!(plugin.get("allocated_port").is_some(), role == "admin");
            assert_eq!(plugin.get("last_error").is_some(), role == "admin");
            assert_eq!(
                result["rejected"].as_array().unwrap().is_empty(),
                role != "admin"
            );
        }
        writer.execute_batch("ROLLBACK").unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn managed_plugin_lifecycle_delegates_to_runner_with_rotation_restart_and_rollback() {
        if run_plugin_test_in_subprocess() {
            return;
        }
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto::Builder;
        use hyper_util::service::TowerToHyperService;
        use std::os::unix::fs::PermissionsExt;

        let _env_guard = test_env_lock().lock().await;
        let db = ensure_shared_test_db();
        let tmp = db
            .parent()
            .unwrap()
            .join(format!("runner-delegated-{}", Uuid::new_v4()));
        let plugins_root = tmp.join("plugins");
        let tokens_root = tmp.join("runner-tokens");
        let plugin_dir = plugins_root.join("isolated-demo");
        let hooks_dir = plugin_dir.join("backend/hooks");
        fs::create_dir_all(&hooks_dir).unwrap();
        fs::set_permissions(&plugins_root, fs::Permissions::from_mode(0o755)).unwrap();
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
        let stop_hook = hooks_dir.join("stop.sh");
        fs::write(&stop_hook, "#!/bin/bash\nexit 0\n").unwrap();
        fs::set_permissions(&stop_hook, fs::Permissions::from_mode(0o755)).unwrap();

        let manifest_json = serde_json::json!({
            "id": "isolated-demo",
            "name": "Isolated Demo",
            "version": "1.0.0",
            "permissions": ["system:metrics:read"],
            "api_scopes": ["GET /api/v1/auth/system/metrics"],
            "lifecycle_hooks": {
                "on_start": "backend/hooks/start.sh",
                "on_stop": "backend/hooks/stop.sh"
            },
            "backend": { "health_path": "/healthz" }
        });
        fs::write(
            plugin_dir.join("plugin.manifest.json"),
            serde_json::to_vec_pretty(&manifest_json).unwrap(),
        )
        .unwrap();

        let unit_state = tmp.join("unit.state");
        let args_log = tmp.join("systemd-run.args");
        let fail_flag = tmp.join("fail-start.flag");
        let fake_sdrun = tmp.join("fake-systemd-run");
        fs::write(
            &fake_sdrun,
            format!(
                r#"#!/bin/bash
set -euo pipefail
printf '%s\n' "$@" >> {args:?}
if [[ -f {fail:?} ]]; then
  echo "simulated systemd-run failure" >&2
  exit 1
fi
echo active > {state:?}
"#,
                args = args_log,
                fail = fail_flag,
                state = unit_state
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_sdrun, fs::Permissions::from_mode(0o755)).unwrap();

        let fake_sdctl = tmp.join("fake-systemctl");
        fs::write(
            &fake_sdctl,
            format!(
                r#"#!/bin/bash
set -euo pipefail
case "${{1:-}}" in
  show)
    st="inactive"
    if [[ -f {state:?} ]]; then st="$(cat {state:?})"; fi
    echo "ActiveState=$st"
    echo "SubState=running"
    echo "MainPID=0"
    echo "UID=62444"
    echo "GID=62444"
    ;;
  stop)
    echo inactive > {state:?}
    ;;
  reset-failed)
    ;;
esac
"#,
                state = unit_state
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_sdctl, fs::Permissions::from_mode(0o755)).unwrap();

        let sock_path = env::temp_dir().join(format!(
            "af-plg-{}.sock",
            &Uuid::new_v4().simple().to_string()[..12]
        ));
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let runner_app = af_runner::build_runner_router();
        let runner_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let io = TokioIo::new(stream);
                let svc = TowerToHyperService::new(runner_app.clone());
                tokio::spawn(async move {
                    let _ = Builder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
        env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
        env::set_var("AETHERFLOW_PLUGIN_TOKENS_ROOT", &tokens_root);
        env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fake_sdrun);
        env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_sdctl);
        env::set_var("PRIVILEGED_RUNNER_ENABLED", "true");

        let admin = AuthUser {
            user_id: 1,
            username: "admin".into(),
            role: "admin".into(),
            jti: "op-2".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };

        // 1. Start succeeds through af-runner and stages a valid runtime token outside DATA_DIR
        let start_resp = control_plugin_handler(
            Path("isolated-demo".into()),
            Extension(admin.clone()),
            HeaderMap::new(),
            Json(PluginControlRequest {
                action: "start".into(),
                port: Some(21222),
            }),
        )
        .await;
        assert_eq!(start_resp.status(), StatusCode::OK);

        let runtime_id_1 = ACTIVE_PROCESSES
            .lock()
            .unwrap()
            .get("isolated-demo")
            .unwrap()
            .runtime_id
            .to_string();
        let token_path_1 = tokens_root
            .join("isolated-demo")
            .join(&runtime_id_1)
            .join("runtime.token");
        let token_1 = fs::read_to_string(&token_path_1).unwrap();
        assert!(decode_and_verify_plugin_token(&token_1).is_ok());
        assert!(
            !fs::read_to_string(&args_log).unwrap().contains(&token_1),
            "runtime token must never appear in systemd-run argv"
        );

        // 2. revoke_tokens bumps epoch, invalidates token_1, and rotates staged token immediately
        let revoke_resp = control_plugin_handler(
            Path("isolated-demo".into()),
            Extension(admin.clone()),
            HeaderMap::new(),
            Json(PluginControlRequest {
                action: "revoke_tokens".into(),
                port: None,
            }),
        )
        .await;
        assert_eq!(revoke_resp.status(), StatusCode::OK);
        assert!(decode_and_verify_plugin_token(&token_1).is_err());
        let token_2 = fs::read_to_string(&token_path_1).unwrap();
        assert_ne!(token_1, token_2);
        assert!(decode_and_verify_plugin_token(&token_2).is_ok());

        // 3. Restart rotates runtime_id and invalidates prior runtime token
        let restart_resp = control_plugin_handler(
            Path("isolated-demo".into()),
            Extension(admin.clone()),
            HeaderMap::new(),
            Json(PluginControlRequest {
                action: "restart".into(),
                port: None,
            }),
        )
        .await;
        assert_eq!(restart_resp.status(), StatusCode::OK);
        let runtime_id_2 = ACTIVE_PROCESSES
            .lock()
            .unwrap()
            .get("isolated-demo")
            .unwrap()
            .runtime_id
            .to_string();
        assert_ne!(runtime_id_1, runtime_id_2);
        assert!(decode_and_verify_plugin_token(&token_2).is_err());

        // 4. Stop clears runner unit, wipes token dir, and disables plugin
        let stop_resp = control_plugin_handler(
            Path("isolated-demo".into()),
            Extension(admin.clone()),
            HeaderMap::new(),
            Json(PluginControlRequest {
                action: "stop".into(),
                port: None,
            }),
        )
        .await;
        assert_eq!(stop_resp.status(), StatusCode::OK);
        assert!(!tokens_root.join("isolated-demo").exists());
        assert!(!read_registry_state("isolated-demo").enabled);

        // 5. Rollback when runner fails to launch transient unit
        fs::write(&fail_flag, "1").unwrap();
        let failed_start = control_plugin_handler(
            Path("isolated-demo".into()),
            Extension(admin),
            HeaderMap::new(),
            Json(PluginControlRequest {
                action: "start".into(),
                port: Some(21333),
            }),
        )
        .await;
        assert_eq!(failed_start.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let reg_after_fail = read_registry_state("isolated-demo");
        assert!(!reg_after_fail.enabled);
        assert_eq!(reg_after_fail.status, "error");
        assert_eq!(
            reg_after_fail.allocated_port, 21222,
            "failed start must restore previous allocated port"
        );
        assert!(!ACTIVE_PROCESSES
            .lock()
            .unwrap()
            .contains_key("isolated-demo"));

        runner_task.abort();
        let _ = fs::remove_file(&sock_path);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn external_plugin_backend_preserves_lifecycle_without_runner() {
        if run_plugin_test_in_subprocess() {
            return;
        }
        let _env_guard = test_env_lock().lock().await;
        let db = ensure_shared_test_db();
        let tmp = db
            .parent()
            .unwrap()
            .join(format!("external-plugin-{}", Uuid::new_v4()));
        let plugins_root = tmp.join("plugins");
        let plugin_dir = plugins_root.join("external-only");
        fs::create_dir_all(&plugin_dir).unwrap();
        fs::write(
            plugin_dir.join("plugin.manifest.json"),
            r#"{
                "id": "external-only",
                "name": "External Backend",
                "version": "1.0.0",
                "runtime_status": "external",
                "permissions": ["system:metrics:read"],
                "api_scopes": ["GET /api/v1/auth/system/metrics"],
                "backend": { "health_path": "/healthz" }
            }"#,
        )
        .unwrap();

        env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
        env::set_var("AETHERFLOW_RUNNER_SOCK", tmp.join("absent-runner.sock"));
        env::set_var("PRIVILEGED_RUNNER_ENABLED", "false");

        let (manifests, rejected) = discover_plugins_in_dir(&plugins_root);
        assert!(rejected.is_empty());
        let manifest = manifests
            .into_iter()
            .find(|m| m.id == "external-only")
            .unwrap();

        let started = start_plugin_instance(&manifest).await.unwrap();
        assert!(started.enabled);
        assert_eq!(started.status, "running");
        assert!((PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&started.allocated_port));

        let (token, _) = mint_scoped_plugin_token(&manifest, Some(120)).unwrap();
        assert!(decode_and_verify_plugin_token(&token).is_ok());

        let stopped = stop_plugin_instance(&manifest).await.unwrap();
        assert!(!stopped.enabled);
        assert_eq!(stopped.status, "stopped");
        assert!(decode_and_verify_plugin_token(&token).is_err());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn external_plugin_reuses_listening_preferred_port_while_preserving_guards() {
        if run_plugin_test_in_subprocess() {
            return;
        }
        let _env_guard = test_env_lock().lock().await;
        let db = ensure_shared_test_db();
        let tmp = db
            .parent()
            .unwrap()
            .join(format!("external-port-{}", Uuid::new_v4()));
        let plugins_root = tmp.join("plugins");

        for id in ["external-listening", "other-external"] {
            let plugin_dir = plugins_root.join(id);
            fs::create_dir_all(&plugin_dir).unwrap();
            fs::write(
                plugin_dir.join("plugin.manifest.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "id": id,
                    "name": id,
                    "version": "1.0.0",
                    "runtime_status": "external",
                    "permissions": ["system:metrics:read"],
                    "api_scopes": ["GET /api/v1/auth/system/metrics"],
                    "backend": { "health_path": "/healthz" }
                }))
                .unwrap(),
            )
            .unwrap();
        }

        let mut bound = None;
        for candidate in (21500..=PLUGIN_PORT_RANGE_END).chain(PLUGIN_PORT_RANGE_START..21500) {
            if let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", candidate)).await {
                bound = Some((candidate, listener));
                break;
            }
        }
        let (ext_port, listener) = bound.expect("bind loopback port in plugin range");
        let server = tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/healthz",
                axum::routing::get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
            );
            let _ = axum::serve(listener, app).await;
        });

        env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
        env::set_var("AETHERFLOW_RUNNER_SOCK", tmp.join("absent-runner.sock"));
        env::set_var("PRIVILEGED_RUNNER_ENABLED", "false");

        let (manifests, rejected) = discover_plugins_in_dir(&plugins_root);
        assert!(rejected.is_empty(), "rejected={rejected:?}");
        let ext_manifest = manifests
            .iter()
            .find(|m| m.id == "external-listening")
            .unwrap()
            .clone();
        let other_manifest = manifests
            .iter()
            .find(|m| m.id == "other-external")
            .unwrap()
            .clone();

        // 1. Explicitly selected already-listening external port is honored and healthy.
        let started = start_plugin_instance_with_port(&ext_manifest, Some(ext_port))
            .await
            .unwrap();
        assert!(started.enabled);
        assert!(started.healthy);
        assert_eq!(started.allocated_port, ext_port);

        // 2. Stopping and re-starting without an explicit port honors the registered port.
        let stopped = stop_plugin_instance(&ext_manifest).await.unwrap();
        assert!(!stopped.enabled);
        assert_eq!(stopped.allocated_port, ext_port);

        let restarted = start_plugin_instance(&ext_manifest).await.unwrap();
        assert!(restarted.enabled);
        assert!(restarted.healthy);
        assert_eq!(restarted.allocated_port, ext_port);

        // 3. Another plugin cannot claim the same port registered to external-listening.
        let other_started = start_plugin_instance_with_port(&other_manifest, Some(ext_port))
            .await
            .unwrap();
        assert_ne!(other_started.allocated_port, ext_port);
        assert!((PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END)
            .contains(&other_started.allocated_port));

        // 4. Out-of-range preferred ports are never returned for external launches.
        let in_range_port = allocate_plugin_port("external-out-of-range", 19999, true).unwrap();
        assert_ne!(in_range_port, 19999);
        assert!((PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&in_range_port));

        // 5. Managed launches still enforce free-port binding and skip already-listening ports.
        let managed_port = allocate_plugin_port("external-listening", ext_port, false).unwrap();
        assert_ne!(managed_port, ext_port);
        assert!((PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&managed_port));

        let _ = stop_plugin_instance(&other_manifest).await;
        let _ = stop_plugin_instance(&ext_manifest).await;
        server.abort();
        let _ = fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_plugin_executable_supports_sdk_template_manifest_path_and_backend_rs() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = env::temp_dir().join(format!("af-plugin-bin-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();

        let make_exec = |rel: &str| {
            let p = tmp.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            p
        };

        let mut manifest = ValidatedPluginManifest {
            id: "bin-test".to_string(),
            name: "bin-test".to_string(),
            version: "1.0.0".to_string(),
            sdk: "rust".to_string(),
            contract_version: "v1".to_string(),
            runtime_status: "managed".to_string(),
            description: String::new(),
            author: String::new(),
            permissions: Vec::new(),
            granted_scopes: Vec::new(),
            lifecycle_hooks: PluginLifecycleHooks::default(),
            backend: PluginBackendSpec {
                manifest_path: "backend/Cargo.toml".to_string(),
                binary_name: "my-plugin-bin".to_string(),
                ..Default::default()
            },
            frontend: PluginFrontendSpec::default(),
            plugin_dir: tmp.clone(),
        };

        // 1. Fallback order from lowest to highest priority when manifest_path = "backend/Cargo.toml":
        // root <bin> -> bin/<bin> -> backend-rs/target/debug -> backend-rs/target/release -> backend/target/debug -> backend/target/release.
        let root_bin = make_exec("my-plugin-bin");
        assert_eq!(resolve_plugin_executable(&manifest).unwrap().0, root_bin);

        let bin_dir_bin = make_exec("bin/my-plugin-bin");
        assert_eq!(resolve_plugin_executable(&manifest).unwrap().0, bin_dir_bin);

        let debug_rs_bin = make_exec("backend-rs/target/debug/my-plugin-bin");
        assert_eq!(
            resolve_plugin_executable(&manifest).unwrap().0,
            debug_rs_bin
        );

        let release_rs_bin = make_exec("backend-rs/target/release/my-plugin-bin");
        assert_eq!(
            resolve_plugin_executable(&manifest).unwrap().0,
            release_rs_bin
        );

        let sdk_debug_bin = make_exec("backend/target/debug/my-plugin-bin");
        assert_eq!(
            resolve_plugin_executable(&manifest).unwrap().0,
            sdk_debug_bin
        );

        let sdk_release_bin = make_exec("backend/target/release/my-plugin-bin");
        assert_eq!(
            resolve_plugin_executable(&manifest).unwrap().0,
            sdk_release_bin
        );

        // Clearing binary_name skips candidate resolution.
        manifest.backend.binary_name.clear();
        assert!(resolve_plugin_executable(&manifest).is_none());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reconcile_startup_and_graceful_shutdown_preserve_enabled_and_reap_orphans() {
        if run_plugin_test_in_subprocess() {
            return;
        }
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto::Builder;
        use hyper_util::service::TowerToHyperService;
        use std::os::unix::fs::PermissionsExt;

        let _env_guard = test_env_lock().lock().await;
        let db = ensure_shared_test_db();
        let tmp = db
            .parent()
            .unwrap()
            .join(format!("reconcile-shutdown-{}", Uuid::new_v4()));
        let plugins_root = tmp.join("plugins");
        let tokens_root = tmp.join("tokens");
        let state_dir = tmp.join("units");
        fs::create_dir_all(&state_dir).unwrap();

        for id in ["auto-demo", "orphan-demo"] {
            let pdir = plugins_root.join(id);
            let hdir = pdir.join("backend/hooks");
            fs::create_dir_all(&hdir).unwrap();
            fs::set_permissions(&pdir, fs::Permissions::from_mode(0o755)).unwrap();
            fs::set_permissions(pdir.join("backend"), fs::Permissions::from_mode(0o755)).unwrap();
            fs::set_permissions(&hdir, fs::Permissions::from_mode(0o755)).unwrap();
            let sh = hdir.join("start.sh");
            fs::write(&sh, "#!/bin/bash\nexit 0\n").unwrap();
            fs::set_permissions(&sh, fs::Permissions::from_mode(0o755)).unwrap();
            let manifest = serde_json::json!({
                "id": id,
                "name": id,
                "version": "1.0.0",
                "lifecycle_hooks": { "on_start": "backend/hooks/start.sh" },
                "backend": { "health_path": "/healthz" }
            });
            fs::write(
                pdir.join("plugin.manifest.json"),
                serde_json::to_vec_pretty(&manifest).unwrap(),
            )
            .unwrap();
        }
        fs::set_permissions(&plugins_root, fs::Permissions::from_mode(0o755)).unwrap();

        let fake_sdrun = tmp.join("fake-sdrun");
        fs::write(
            &fake_sdrun,
            format!(
                r#"#!/bin/bash
set -euo pipefail
unit=""
for arg in "$@"; do
  case "$arg" in
    --unit=*) unit="${{arg#--unit=}}" ;;
  esac
done
echo active > {dir:?}/"$unit"
"#,
                dir = state_dir
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_sdrun, fs::Permissions::from_mode(0o755)).unwrap();

        let fake_sdctl = tmp.join("fake-sdctl");
        fs::write(
            &fake_sdctl,
            format!(
                r#"#!/bin/bash
set -euo pipefail
cmd="${{1:-}}"
unit="${{@: -1}}"
case "$cmd" in
  show)
    st="inactive"
    if [[ -f {dir:?}/"$unit" ]]; then st="$(cat {dir:?}/"$unit")"; fi
    echo "ActiveState=$st"
    echo "SubState=running"
    echo "MainPID=0"
    echo "UID=62555"
    echo "GID=62555"
    ;;
  stop)
    echo inactive > {dir:?}/"$unit"
    ;;
  reset-failed)
    ;;
esac
"#,
                dir = state_dir
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_sdctl, fs::Permissions::from_mode(0o755)).unwrap();

        // Simulate a stale orphaned unit for disabled plugin `orphan-demo`, while `auto-demo` is enabled in DB.
        fs::write(
            state_dir.join("aetherflow-plugin-orphan-demo.service"),
            "active\n",
        )
        .unwrap();
        update_registry_state("auto-demo", true, 21401, "running", "", false);
        update_registry_state("orphan-demo", false, 21402, "stopped", "", false);

        let sock_path = env::temp_dir().join(format!(
            "af-plg-{}.sock",
            &Uuid::new_v4().simple().to_string()[..12]
        ));
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let runner_app = af_runner::build_runner_router();
        let runner_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let io = TokioIo::new(stream);
                let svc = TowerToHyperService::new(runner_app.clone());
                tokio::spawn(async move {
                    let _ = Builder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        env::set_var("AETHERFLOW_PLUGINS_DIR", &plugins_root);
        env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
        env::set_var("AETHERFLOW_PLUGIN_TOKENS_ROOT", &tokens_root);
        env::set_var("AETHERFLOW_SYSTEMD_RUN_BIN", &fake_sdrun);
        env::set_var("AETHERFLOW_SYSTEMCTL_BIN", &fake_sdctl);
        env::set_var("PRIVILEGED_RUNNER_ENABLED", "true");

        reconcile_managed_plugins_on_startup().await;

        assert_eq!(
            fs::read_to_string(state_dir.join("aetherflow-plugin-auto-demo.service"))
                .unwrap()
                .trim(),
            "active"
        );
        assert_eq!(
            fs::read_to_string(state_dir.join("aetherflow-plugin-orphan-demo.service"))
                .unwrap()
                .trim(),
            "inactive",
            "disabled plugin's orphaned unit must be reaped on startup"
        );
        assert!(ACTIVE_PROCESSES.lock().unwrap().contains_key("auto-demo"));

        // Graceful shutdown stops active unit via runner while preserving enabled=true in SQLite
        shutdown_managed_plugins().await;
        assert_eq!(
            fs::read_to_string(state_dir.join("aetherflow-plugin-auto-demo.service"))
                .unwrap()
                .trim(),
            "inactive"
        );
        assert!(!ACTIVE_PROCESSES.lock().unwrap().contains_key("auto-demo"));
        assert!(
            read_registry_state("auto-demo").enabled,
            "graceful shutdown must preserve enabled=true so next startup auto-starts the plugin"
        );
        assert!(!tokens_root.join("auto-demo").exists());

        runner_task.abort();
        let _ = fs::remove_file(&sock_path);
        let _ = fs::remove_dir_all(&tmp);
    }
}
