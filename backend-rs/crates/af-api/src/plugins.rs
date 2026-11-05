use crate::auth::{api_error, jwt_secret_bytes, AuthUser};
use axum::body::Body;
use axum::extract::{Extension, Path, Request};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use regex::Regex;
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
use tokio::process::{Child, Command};
use tokio::task::JoinSet;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Constants & Security Policies
// ─────────────────────────────────────────────────────────────────────────────

const PLUGIN_PORT_RANGE_START: u16 = 21000;
const PLUGIN_PORT_RANGE_END: u16 = 21999;
const MAX_CONCURRENT_HEALTH_PROBES: usize = 8;
const MAX_PLUGIN_PROXY_BODY_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
const DEFAULT_PLUGIN_TOKEN_TTL_SECS: i64 = 300; // 5 minutes
const MAX_PLUGIN_TOKEN_TTL_SECS: i64 = 900; // 15 minutes
pub const PLUGIN_TOKEN_ISSUER: &str = "aetherflow-plugin";
pub const PLUGIN_TOKEN_TYP: &str = "plugin";
pub const PLUGIN_TOKEN_AUDIENCE: &str = "aetherflow-plugin-api";

static PLUGIN_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9][a-z0-9-_]{1,62}$").expect("valid regex"));

const DEFAULT_DENY_ROUTE_PREFIXES: &[&str] = &[
    "/api/v1/auth/session",
    "/api/v1/auth/sessions",
    "/api/v1/auth/refresh",
    "/api/v1/auth/logout",
    "/api/v1/auth/ws",
    "/api/v1/auth/profile",
    "/api/v1/auth/user/2fa",
    "/api/v1/auth/oidc",
    "/api/v1/auth/plugins",
    "/api/v1/admin/users",
    "/api/v1/admin/settings",
    "/api/v1/admin/backup",
    "/api/v1/admin/oidc",
    "/api/v1/admin/actions",
    "/api/v1/admin/audit-log",
    "/api/v1/admin/plugins",
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
    "/api/admin/users",
    "/api/admin/settings",
    "/api/admin/backup",
    "/api/admin/oidc",
    "/api/admin/actions",
    "/api/admin/audit-log",
    "/api/admin/plugins",
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

struct ActivePluginProcess {
    child: Child,
    port: u16,
}

static ACTIVE_PROCESSES: Lazy<Mutex<HashMap<String, ActivePluginProcess>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static ACTIVE_PLUGIN_JTIS: Lazy<Mutex<HashMap<String, HashSet<String>>>> =
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
    PLUGIN_ID_RE.is_match(id)
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

pub fn normalize_scope_entry(
    raw: &RawScopeEntry,
    permissions: &[String],
) -> Result<Vec<PluginScopeRule>, String> {
    let can_write_permission = permissions
        .iter()
        .any(|p| p.ends_with(":write") || p.ends_with(":admin") || p.ends_with(":control"));

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

    let methods: Vec<String> = match raw_method.as_str() {
        "GET" | "HEAD" => vec!["GET".to_string(), "HEAD".to_string()],
        "POST" | "PUT" | "PATCH" | "DELETE" => {
            if !can_write_permission {
                return Err(format!(
                    "Mutating method '{}' on '{}' requires an explicit *:write permission in manifest",
                    raw_method, raw_route
                ));
            }
            vec![raw_method]
        }
        _ => {
            return Err(format!(
            "Unsupported or wildcard HTTP method '{}' in plugin scope (explicit method required)",
            raw_method
        ))
        }
    };

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
    if is_route_default_denied(path) {
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

    let joined = plugin_dir.join(rel_path);
    let canon_root = fs::canonicalize(plugin_dir)
        .map_err(|e| format!("Failed to canonicalize plugin dir: {}", e))?;

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

    if raw.name.trim().is_empty() || raw.version.trim().is_empty() {
        return Err("Plugin manifest requires non-empty 'name' and 'version'".to_string());
    }

    if !raw.backend.health_path.starts_with('/') || raw.backend.health_path.contains("..") {
        return Err(format!(
            "Invalid backend.health_path '{}'",
            raw.backend.health_path
        ));
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

fn get_or_init_registry_state(plugin_id: &str) -> PluginRegistryState {
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "INSERT OR IGNORE INTO plugins_registry (plugin_id, enabled, allocated_port, token_epoch, status) VALUES (?1, 0, 0, 1, 'stopped')",
            params![plugin_id],
        );
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
    get_or_init_registry_state(plugin_id)
}

fn allocate_plugin_port(plugin_id: &str, preferred: u16) -> Result<u16, String> {
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
        && TcpListener::bind(("127.0.0.1", preferred)).is_ok()
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
    let reg = get_or_init_registry_state(&manifest.id);
    if !reg.enabled && reg.status != "running" {
        return Err(format!(
            "Plugin '{}' must be enabled before minting a scoped runtime token",
            manifest.id
        ));
    }

    let now = Utc::now().timestamp();
    let ttl = requested_ttl_secs
        .unwrap_or(DEFAULT_PLUGIN_TOKEN_TTL_SECS)
        .clamp(30, MAX_PLUGIN_TOKEN_TTL_SECS);
    let exp = now + ttl;
    let jti = format!("plg-{}-{}", manifest.id, Uuid::new_v4());

    let claims = PluginTokenClaims {
        typ: PLUGIN_TOKEN_TYP.to_string(),
        iss: PLUGIN_TOKEN_ISSUER.to_string(),
        aud: PLUGIN_TOKEN_AUDIENCE.to_string(),
        sub: format!("plugin:{}", manifest.id),
        plugin_id: manifest.id.clone(),
        jti: jti.clone(),
        iat: now,
        exp,
        epoch: reg.token_epoch,
        scopes: manifest.granted_scopes.clone(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&plugin_signing_key()),
    )
    .map_err(|e| format!("Failed to encode plugin token: {}", e))?;

    if let Ok(mut map) = ACTIVE_PLUGIN_JTIS.lock() {
        map.entry(manifest.id.clone()).or_default().insert(jti);
    }

    Ok((token, claims))
}

pub fn decode_and_verify_plugin_token(token: &str) -> Result<PluginTokenClaims, String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[PLUGIN_TOKEN_AUDIENCE]);

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
    if af_db::is_token_revoked(&claims.jti) {
        return Err("Plugin token has been revoked".to_string());
    }

    let reg = get_or_init_registry_state(&claims.plugin_id);
    if !reg.enabled || reg.status == "stopped" || reg.token_epoch != claims.epoch {
        return Err(
            "Plugin token is no longer active for the current plugin lifecycle epoch".to_string(),
        );
    }

    // Intersect token scopes with the live verified manifest on disk if discoverable
    let (manifests, _) = discover_plugins();
    if let Some(live_manifest) = manifests.into_iter().find(|m| m.id == claims.plugin_id) {
        claims
            .scopes
            .retain(|s| live_manifest.granted_scopes.contains(s));
    }

    Ok(claims)
}

pub fn revoke_all_tokens_for_plugin(plugin_id: &str) {
    if let Ok(mut map) = ACTIVE_PLUGIN_JTIS.lock() {
        if let Some(jtis) = map.remove(plugin_id) {
            for jti in jtis {
                af_db::revoke_token(
                    &jti,
                    Duration::from_secs(MAX_PLUGIN_TOKEN_TTL_SECS as u64 + 60),
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unprivileged Process Lifecycle & Health Probing
// ─────────────────────────────────────────────────────────────────────────────

fn resolve_plugin_executable(manifest: &ValidatedPluginManifest) -> Option<(PathBuf, Vec<String>)> {
    if !manifest.backend.binary_name.trim().is_empty() {
        for rel in [
            format!(
                "backend/target/release/{}",
                manifest.backend.binary_name.trim()
            ),
            format!(
                "backend/target/debug/{}",
                manifest.backend.binary_name.trim()
            ),
            format!("bin/{}", manifest.backend.binary_name.trim()),
            manifest.backend.binary_name.trim().to_string(),
        ] {
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

fn configure_unprivileged_command(
    cmd: &mut Command,
    manifest: &ValidatedPluginManifest,
    port: u16,
    scoped_token: &str,
) {
    cmd.env_clear();
    let safe_path = env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());
    let api_port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let api_base = env::var("AETHERFLOW_INTERNAL_API_URL")
        .unwrap_or_else(|_| format!("http://127.0.0.1:{}", api_port));

    cmd.current_dir(&manifest.plugin_dir)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .env("PATH", safe_path)
        .env("PLUGIN_ID", &manifest.id)
        .env("PLUGIN_NAME", &manifest.name)
        .env("PLUGIN_VERSION", &manifest.version)
        .env("PLUGIN_BIND_ADDR", "127.0.0.1")
        .env("PLUGIN_PORT", port.to_string())
        .env("PORT", port.to_string())
        .env("AETHERFLOW_API_BASE_URL", api_base)
        .env("AETHERFLOW_PLUGIN_TOKEN", scoped_token);

    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(|| {
            // Ensure no new privileges can be acquired by plugin child processes
            let _ = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            Ok(())
        });
    }
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

pub async fn start_plugin_instance(
    manifest: &ValidatedPluginManifest,
) -> Result<PluginRuntimeView, String> {
    let resolved_exec = resolve_plugin_executable(manifest);
    if resolved_exec.is_some() {
        stop_running_process(&manifest.id).await;
    }
    let existing = get_or_init_registry_state(&manifest.id);
    let port = allocate_plugin_port(&manifest.id, existing.allocated_port)?;

    let _ = update_registry_state(&manifest.id, true, port, "running", "", false);
    let (scoped_token, _) =
        mint_scoped_plugin_token(manifest, Some(DEFAULT_PLUGIN_TOKEN_TTL_SECS))?;

    let mut spawned_managed = false;
    if let Some((program, args)) = resolved_exec {
        let mut cmd = Command::new(&program);
        cmd.args(&args);
        configure_unprivileged_command(&mut cmd, manifest, port, &scoped_token);
        match cmd.spawn() {
            Ok(child) => {
                spawned_managed = true;
                if let Ok(mut map) = ACTIVE_PROCESSES.lock() {
                    map.insert(manifest.id.clone(), ActivePluginProcess { child, port });
                }
            }
            Err(err) => {
                let err_msg = format!("Failed to spawn plugin binary: {}", err);
                let _ = update_registry_state(&manifest.id, false, port, "error", &err_msg, true);
                revoke_all_tokens_for_plugin(&manifest.id);
                return Err(err_msg);
            }
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
    let state = get_or_init_registry_state(&manifest.id);
    Ok(build_runtime_view(manifest, &state, healthy))
}

async fn stop_running_process(plugin_id: &str) {
    let maybe_proc = ACTIVE_PROCESSES
        .lock()
        .ok()
        .and_then(|mut map| map.remove(plugin_id));
    if let Some(mut proc_entry) = maybe_proc {
        let _ = proc_entry.child.kill().await;
        let _ = proc_entry.child.wait().await;
    }
}

pub async fn stop_plugin_instance(
    manifest: &ValidatedPluginManifest,
) -> Result<PluginRuntimeView, String> {
    stop_running_process(&manifest.id).await;
    revoke_all_tokens_for_plugin(&manifest.id);
    let existing = get_or_init_registry_state(&manifest.id);
    let state = update_registry_state(
        &manifest.id,
        false,
        existing.allocated_port,
        "stopped",
        "",
        true,
    );
    Ok(build_runtime_view(manifest, &state, false))
}

pub async fn restart_plugin_instance(
    manifest: &ValidatedPluginManifest,
) -> Result<PluginRuntimeView, String> {
    let _ = stop_plugin_instance(manifest).await;
    start_plugin_instance(manifest).await
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

pub async fn collect_plugin_runtime_views(
    manifests: &[ValidatedPluginManifest],
) -> Vec<PluginRuntimeView> {
    let mut ordered_views: Vec<Option<PluginRuntimeView>> = vec![None; manifests.len()];
    let mut join_set: JoinSet<(usize, bool)> = JoinSet::new();

    for (index, manifest) in manifests.iter().enumerate() {
        let state = get_or_init_registry_state(&manifest.id);
        if !state.enabled || state.allocated_port == 0 {
            ordered_views[index] = Some(build_runtime_view(manifest, &state, false));
            continue;
        }
        while join_set.len() >= MAX_CONCURRENT_HEALTH_PROBES {
            let Some(joined) = join_set.join_next().await else {
                break;
            };
            if let Ok((done_index, healthy)) = joined {
                let done_manifest = &manifests[done_index];
                let refreshed_state = get_or_init_registry_state(&done_manifest.id);
                ordered_views[done_index] =
                    Some(build_runtime_view(done_manifest, &refreshed_state, healthy));
            }
        }
        let allocated_port = state.allocated_port;
        let health_path = manifest.backend.health_path.clone();
        join_set.spawn(async move {
            let healthy = probe_plugin_health(allocated_port, &health_path)
                .await
                .unwrap_or(false);
            (index, healthy)
        });
    }

    while let Some(joined) = join_set.join_next().await {
        if let Ok((done_index, healthy)) = joined {
            let done_manifest = &manifests[done_index];
            let refreshed_state = get_or_init_registry_state(&done_manifest.id);
            ordered_views[done_index] =
                Some(build_runtime_view(done_manifest, &refreshed_state, healthy));
        }
    }

    ordered_views.into_iter().flatten().collect()
}

pub async fn list_plugins_handler() -> Response {
    let (manifests, rejected) = discover_plugins();
    let views = collect_plugin_runtime_views(&manifests).await;
    let rejected_items: Vec<serde_json::Value> = rejected
        .into_iter()
        .map(|(id, error)| serde_json::json!({ "id": id, "error": error }))
        .collect();

    Json(serde_json::json!({
        "plugins": views,
        "rejected": rejected_items,
    }))
    .into_response()
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
        let existing = get_or_init_registry_state(&manifest.id);
        let _ = update_registry_state(
            &manifest.id,
            existing.enabled,
            custom_port,
            &existing.status,
            &existing.last_error,
            false,
        );
    }

    let action = req.action.trim().to_lowercase();
    let result = match action.as_str() {
        "start" | "enable" => start_plugin_instance(&manifest).await,
        "stop" | "disable" => stop_plugin_instance(&manifest).await,
        "restart" => restart_plugin_instance(&manifest).await,
        "revoke_tokens" => {
            revoke_all_tokens_for_plugin(&manifest.id);
            let existing = get_or_init_registry_state(&manifest.id);
            let updated = update_registry_state(
                &manifest.id,
                existing.enabled,
                existing.allocated_port,
                &existing.status,
                "",
                true,
            );
            Ok(build_runtime_view(&manifest, &updated, false))
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
        Err(err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PLUGIN_LIFECYCLE_ERROR",
            err,
        ),
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

pub async fn serve_plugin_ui_handler(Path(id): Path<String>) -> Response {
    let manifest = match find_validated_plugin(&id) {
        Ok(m) => m,
        Err(response) => return *response,
    };
    let state = get_or_init_registry_state(&manifest.id);
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
      }}, '*');
    }});
    window.parent.postMessage({{ type: 'AF_PLUGIN_READY', pluginId }}, '*');
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

pub async fn proxy_plugin_root_handler(
    Path(id): Path<String>,
    Extension(auth_user): Extension<AuthUser>,
    req: Request,
) -> Response {
    proxy_plugin_request_inner(id, String::new(), auth_user, req).await
}

pub async fn proxy_plugin_wildcard_handler(
    Path((id, rest)): Path<(String, String)>,
    Extension(auth_user): Extension<AuthUser>,
    req: Request,
) -> Response {
    proxy_plugin_request_inner(id, rest, auth_user, req).await
}

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

    let state = get_or_init_registry_state(&manifest.id);
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

    // Forward safe headers ONLY — strip Cookie, Authorization, X-CSRF-Token, and hop-by-hop headers
    for (name, val) in req_headers.iter() {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "cookie"
                | "authorization"
                | "x-csrf-token"
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
        ) {
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
        let write_perms = vec!["services:control:write".to_string()];
        let valid_post = RawScopeEntry::Simple("POST /api/v1/auth/services/restart".to_string());
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
    async fn test_list_plugins_concurrent_health_probing_preserves_order_and_bounds_latency() {
        if run_plugin_test_in_subprocess() {
            return;
        }
        use axum::routing::get as axum_get;
        use std::time::Instant;

        let _env_guard = test_env_lock().lock().await;
        let _ = ensure_shared_test_db();

        let tmp = std::env::temp_dir().join(format!("af-plugin-concurrent-{}", Uuid::new_v4()));
        fs::create_dir_all(&tmp).unwrap();

        let plugin_ids = [
            "plugin-alpha",
            "plugin-beta",
            "plugin-gamma",
            "plugin-delta",
        ];
        let mut manifests = Vec::new();
        let mut next_candidate_port = 21200u16;

        for plugin_id in plugin_ids {
            let mut bound_listener = None;
            let start_port = next_candidate_port;
            let mut allocated_port = start_port;
            for candidate in start_port..=21400 {
                if let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", candidate)).await
                {
                    allocated_port = candidate;
                    next_candidate_port = candidate + 1;
                    bound_listener = Some(listener);
                    break;
                }
            }
            let listener = bound_listener.expect("bind concurrent test listener");
            tokio::spawn(async move {
                let app = axum::Router::new().route(
                    "/healthz",
                    axum_get(|| async {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        Json(serde_json::json!({"status": "ok"}))
                    }),
                );
                let _ = axum::serve(listener, app).await;
            });

            let _ = update_registry_state(plugin_id, true, allocated_port, "running", "", false);
            manifests.push(ValidatedPluginManifest {
                id: plugin_id.to_string(),
                name: plugin_id.to_string(),
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
                    health_path: "/healthz".to_string(),
                    port_allocation: "dynamic".to_string(),
                    ..Default::default()
                },
                frontend: PluginFrontendSpec::default(),
                plugin_dir: tmp.join(plugin_id),
            });
        }

        let started_at = Instant::now();
        let views = collect_plugin_runtime_views(&manifests).await;
        let elapsed = started_at.elapsed();

        let returned_ids: Vec<&str> = views.iter().map(|view| view.id.as_str()).collect();
        assert_eq!(returned_ids, plugin_ids);
        assert!(views.iter().all(|view| view.healthy));
        assert!(
            elapsed < Duration::from_millis(700),
            "expected concurrent health probes to complete under 700ms, took {:?}",
            elapsed
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
