//! Native Rust Plugin Runtime, Manifest Loader, Port Allocator & Scope Verifier (`af-services::plugins`)

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

static PLUGIN_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-z0-9][a-z0-9_-]{1,62}$").unwrap());
static PERMISSION_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9:_-]{0,63}$").unwrap());

static ALLOCATED_PORTS: Lazy<RwLock<HashMap<String, u16>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub const PLUGIN_PORT_MIN: u16 = 21000;
pub const PLUGIN_PORT_MAX: u16 = 21999;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginBackendConfig {
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub manifest_path: String,
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub binary_name: String,
    #[serde(default)]
    pub health_path: String,
    #[serde(default)]
    pub port_allocation: String,
    #[serde(default)]
    pub default_port: Option<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginFrontendConfig {
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub slot: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginEntryPoints {
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub frontend: String,
    #[serde(default)]
    pub wasm: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginNetworkConfig {
    #[serde(default)]
    pub port_allocation: String,
    #[serde(default)]
    pub health_path: String,
    #[serde(default)]
    pub default_port: Option<u16>,
    #[serde(default)]
    pub allow_outbound: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginLifecycleHooks {
    #[serde(default)]
    pub on_start: String,
    #[serde(default)]
    pub on_stop: String,
    #[serde(default)]
    pub on_install: String,
    #[serde(default)]
    pub on_uninstall: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginManifest {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default, alias = "contract_version")]
    pub api_version: String,
    #[serde(default)]
    pub sdk: String,
    #[serde(default)]
    pub runtime_status: String,
    #[serde(default)]
    pub entry_points: PluginEntryPoints,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub api_scopes: Vec<String>,
    #[serde(default)]
    pub network: PluginNetworkConfig,
    #[serde(default)]
    pub lifecycle_hooks: PluginLifecycleHooks,
    #[serde(default)]
    pub frontend_slot: Option<String>,
    #[serde(default)]
    pub backend: Option<PluginBackendConfig>,
    #[serde(default)]
    pub frontend: Option<PluginFrontendConfig>,
}

impl PluginManifest {
    /// Normalizes nested `backend` and `frontend` blocks from SDK templates into
    /// top-level `entry_points`, `network`, `api_version`, and `frontend_slot` fields.
    pub fn normalized(mut self) -> Self {
        if let Some(ref b) = self.backend {
            if self.entry_points.backend.is_empty() && !b.entry.is_empty() {
                self.entry_points.backend = b.entry.clone();
            }
            if self.network.port_allocation.is_empty() && !b.port_allocation.is_empty() {
                self.network.port_allocation = b.port_allocation.clone();
            }
            if self.network.health_path.is_empty() && !b.health_path.is_empty() {
                self.network.health_path = b.health_path.clone();
            }
            if self.network.default_port.is_none() && b.default_port.is_some() {
                self.network.default_port = b.default_port;
            }
        }
        if let Some(ref f) = self.frontend {
            if self.entry_points.frontend.is_empty() && !f.entry.is_empty() {
                self.entry_points.frontend = f.entry.clone();
            }
            if self.frontend_slot.is_none() && !f.slot.trim().is_empty() {
                self.frontend_slot = Some(f.slot.trim().to_string());
            }
        }
        if self.api_version.is_empty() {
            self.api_version = "v1".to_string();
        }
        if self.network.health_path.is_empty() {
            self.network.health_path = "/healthz".to_string();
        }
        if self.network.port_allocation.is_empty() {
            self.network.port_allocation = "dynamic".to_string();
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginInstanceView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub status: String,
    pub allocated_port: u16,
    pub permissions: Vec<String>,
    pub api_scopes: Vec<String>,
    pub manifest_path: String,
    #[serde(default)]
    pub is_template: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub frontend_slot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub validation_error: Option<String>,
}

/// Parses a `PluginManifest` from raw JSON text and normalizes SDK template fields.
pub fn parse_plugin_manifest_str(raw: &str) -> anyhow::Result<PluginManifest> {
    let manifest: PluginManifest = serde_json::from_str(raw)?;
    Ok(manifest.normalized())
}

/// Maximum allowed byte size for `plugin.manifest.json` (`64 KiB`).
pub const MAX_PLUGIN_MANIFEST_BYTES: u64 = 64 * 1024;

/// Loads a `PluginManifest` from disk, converting template placeholders (`{{PLUGIN_ID}}`)
/// into the parent directory name when loading SDK templates.
pub fn load_plugin_manifest_file(manifest_path: &Path) -> anyhow::Result<PluginManifest> {
    let meta = fs::symlink_metadata(manifest_path)?;
    if meta.file_type().is_symlink() {
        anyhow::bail!(
            "plugin manifest '{}' must not be a symlink",
            manifest_path.display()
        );
    }
    if meta.len() > MAX_PLUGIN_MANIFEST_BYTES {
        anyhow::bail!(
            "plugin manifest '{}' exceeds maximum size ({} bytes > {} bytes)",
            manifest_path.display(),
            meta.len(),
            MAX_PLUGIN_MANIFEST_BYTES
        );
    }
    let raw = fs::read_to_string(manifest_path)?;
    let mut manifest = parse_plugin_manifest_str(&raw)?;
    if let Some(parent_name) = manifest_path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
    {
        if manifest.id == "{{PLUGIN_ID}}" {
            manifest.id = parent_name.to_lowercase();
        }
        if manifest.name == "{{PLUGIN_NAME}}" {
            manifest.name = parent_name.to_string();
        }
    }
    Ok(manifest)
}

fn validate_safe_relative_path(
    rel_path: &str,
    field_name: &str,
    plugin_root: Option<&Path>,
) -> anyhow::Result<()> {
    let trimmed = rel_path.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if trimmed.contains('\0') || trimmed.contains('\\') {
        anyhow::bail!(
            "{} '{}' contains disallowed path characters",
            field_name,
            trimmed
        );
    }
    let path = Path::new(trimmed);
    if path.is_absolute() || trimmed.starts_with('/') || trimmed.starts_with('~') {
        anyhow::bail!("{} '{}' must be a relative path", field_name, trimmed);
    }
    for comp in path.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s == ".." || s.contains("..") {
                    anyhow::bail!(
                        "{} '{}' contains path traversal segment",
                        field_name,
                        trimmed
                    );
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("{} '{}' contains path traversal", field_name, trimmed);
            }
        }
    }

    if let Some(root) = plugin_root {
        let canon_root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        let joined = root.join(path);

        // Check every prefix component along the relative path for symlinks escaping plugin_root
        let mut cursor = root.to_path_buf();
        for comp in path.components() {
            if let Component::Normal(seg) = comp {
                cursor.push(seg);
                if let Ok(sym_meta) = fs::symlink_metadata(&cursor) {
                    if sym_meta.file_type().is_symlink() {
                        let resolved = fs::canonicalize(&cursor).map_err(|_| {
                            anyhow::anyhow!(
                                "{} '{}' points to a broken or unresolvable symlink",
                                field_name,
                                trimmed
                            )
                        })?;
                        if !resolved.starts_with(&canon_root) {
                            anyhow::bail!(
                                "{} '{}' escapes plugin directory via symlink",
                                field_name,
                                trimmed
                            );
                        }
                    }
                }
            }
        }

        if joined.exists() {
            let resolved = fs::canonicalize(&joined)?;
            if !resolved.starts_with(&canon_root) {
                anyhow::bail!(
                    "{} '{}' escapes plugin directory root",
                    field_name,
                    trimmed
                );
            }
        }
    }

    Ok(())
}

/// Validates a `PluginManifest` for structural and security constraints:
/// - Plugin ID matches `^[a-z0-9][a-z0-9_-]{1,62}$` (no `..` or `/`).
/// - Every `api_scopes` entry starts with `/api/v1/` and has no traversal or whitespace.
/// - Every `permissions` entry matches `^[a-zA-Z0-9][a-zA-Z0-9:_-]{0,63}$`.
/// - `entry_points`, `backend`, `frontend`, and `lifecycle_hooks` paths do not traverse or escape via symlinks.
pub fn validate_plugin_manifest(manifest: &PluginManifest) -> anyhow::Result<()> {
    validate_plugin_manifest_in_dir(manifest, None)
}

/// Validates a `PluginManifest` including on-disk symlink escape checks against `plugin_dir` when provided.
pub fn validate_plugin_manifest_in_dir(
    manifest: &PluginManifest,
    plugin_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let id = manifest.id.trim();
    if id.is_empty()
        || id.contains("..")
        || id.contains('/')
        || id.contains('\\')
        || !PLUGIN_ID_RE.is_match(id)
    {
        anyhow::bail!(
            "invalid plugin id '{}': must match ^[a-z0-9][a-z0-9_-]{{1,62}}$",
            manifest.id
        );
    }

    if manifest.name.trim().is_empty() {
        anyhow::bail!("plugin name must not be empty");
    }
    if manifest.version.trim().is_empty() {
        anyhow::bail!("plugin version must not be empty");
    }

    for perm in &manifest.permissions {
        let p = perm.trim();
        if p.is_empty() || !PERMISSION_TOKEN_RE.is_match(p) {
            anyhow::bail!(
                "invalid permission token '{}': must be non-empty alphanumeric/colon token",
                perm
            );
        }
    }

    for scope in &manifest.api_scopes {
        let s = scope.trim();
        if !s.starts_with("/api/v1/")
            || s.len() <= "/api/v1/".len()
            || s.contains("..")
            || s.contains('\\')
            || s.chars().any(|c| c.is_whitespace())
        {
            anyhow::bail!(
                "invalid api_scope '{}': must start with '/api/v1/' and not contain '..'",
                scope
            );
        }
    }

    validate_safe_relative_path(
        &manifest.entry_points.backend,
        "entry_points.backend",
        plugin_dir,
    )?;
    validate_safe_relative_path(
        &manifest.entry_points.frontend,
        "entry_points.frontend",
        plugin_dir,
    )?;
    validate_safe_relative_path(&manifest.entry_points.wasm, "entry_points.wasm", plugin_dir)?;

    if let Some(ref b) = manifest.backend {
        validate_safe_relative_path(&b.entry, "backend.entry", plugin_dir)?;
        validate_safe_relative_path(&b.manifest_path, "backend.manifest_path", plugin_dir)?;
    }
    if let Some(ref f) = manifest.frontend {
        validate_safe_relative_path(&f.entry, "frontend.entry", plugin_dir)?;
    }

    validate_safe_relative_path(
        &manifest.lifecycle_hooks.on_start,
        "lifecycle_hooks.on_start",
        plugin_dir,
    )?;
    validate_safe_relative_path(
        &manifest.lifecycle_hooks.on_stop,
        "lifecycle_hooks.on_stop",
        plugin_dir,
    )?;
    validate_safe_relative_path(
        &manifest.lifecycle_hooks.on_install,
        "lifecycle_hooks.on_install",
        plugin_dir,
    )?;
    validate_safe_relative_path(
        &manifest.lifecycle_hooks.on_uninstall,
        "lifecycle_hooks.on_uninstall",
        plugin_dir,
    )?;

    if !manifest.network.health_path.is_empty() && !manifest.network.health_path.starts_with('/') {
        anyhow::bail!(
            "network.health_path '{}' must start with '/'",
            manifest.network.health_path
        );
    }

    Ok(())
}

/// Deterministically allocates a plugin port in `21000..=21999` based on the SHA-256 hash of `plugin_id`,
/// preserving existing allocations across calls and resolving collisions within the range.
pub fn allocate_plugin_port(plugin_id: &str) -> u16 {
    allocate_plugin_port_with_hint(plugin_id, 0)
}

/// Allocates a plugin port in `21000..=21999`, preferring `default_port_hint` when it lies within
/// `21000..=21999` and is not already claimed by another plugin, otherwise falling back to
/// deterministic SHA-256 probing.
pub fn allocate_plugin_port_with_hint(plugin_id: &str, default_port_hint: u16) -> u16 {
    let clean_id = plugin_id.trim().to_lowercase();
    if let Ok(guard) = ALLOCATED_PORTS.read() {
        if let Some(&port) = guard.get(&clean_id) {
            return port;
        }
    }

    let range_size = (PLUGIN_PORT_MAX - PLUGIN_PORT_MIN + 1) as u32; // 1000 ports (21000..=21999)
    let digest = Sha256::digest(clean_id.as_bytes());
    let hash_val = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let base_offset = hash_val % range_size;

    let mut guard = match ALLOCATED_PORTS.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(&port) = guard.get(&clean_id) {
        return port;
    }

    let used_ports: std::collections::HashSet<u16> = guard.values().copied().collect();
    if (PLUGIN_PORT_MIN..=PLUGIN_PORT_MAX).contains(&default_port_hint)
        && !used_ports.contains(&default_port_hint)
    {
        guard.insert(clean_id, default_port_hint);
        return default_port_hint;
    }

    for step in 0..range_size {
        let candidate = PLUGIN_PORT_MIN + ((base_offset + step) % range_size) as u16;
        if !used_ports.contains(&candidate) {
            guard.insert(clean_id, candidate);
            return candidate;
        }
    }

    let fallback = PLUGIN_PORT_MIN + (base_offset as u16);
    guard.insert(clean_id, fallback);
    fallback
}

/// Verifies whether `request_path` is authorized by at least one scope in `allowed_scopes`.
/// Enforces exact or segment-boundary prefix matching (`/api/v1/public/marketplace` matches
/// `/api/v1/public/marketplace` and `/api/v1/public/marketplace/items`, but NOT
/// `/api/v1/public/marketplace_admin`).
pub fn verify_plugin_route_scope(allowed_scopes: &[String], request_path: &str) -> bool {
    let raw_path = request_path.split('?').next().unwrap_or("").trim();
    if !raw_path.starts_with("/api/v1/")
        || raw_path.contains("..")
        || raw_path.contains('\\')
        || raw_path.contains("//")
    {
        return false;
    }
    let norm_path = if raw_path.len() > 1 {
        raw_path.trim_end_matches('/')
    } else {
        raw_path
    };

    for raw_scope in allowed_scopes {
        let scope = raw_scope.trim();
        if !scope.starts_with("/api/v1/") || scope.contains("..") {
            continue;
        }

        if let Some(prefix) = scope.strip_suffix("/*") {
            let clean_prefix = prefix.trim_end_matches('/');
            if clean_prefix.len() < "/api/v1".len() {
                continue;
            }
            if norm_path == clean_prefix {
                return true;
            }
            if let Some(rest) = norm_path.strip_prefix(clean_prefix) {
                if rest.starts_with('/') {
                    return true;
                }
            }
        } else if scope.ends_with('*') {
            continue;
        } else {
            let clean_scope = scope.trim_end_matches('/');
            if norm_path == clean_scope {
                return true;
            }
            if let Some(rest) = norm_path.strip_prefix(clean_scope) {
                if rest.starts_with('/') {
                    return true;
                }
            }
        }
    }

    false
}

/// Checks if a local plugin companion TCP service is accepting connections on `127.0.0.1:<port>`.
pub fn is_plugin_port_listening(port: u16) -> bool {
    if port == 0 {
        return false;
    }
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(80)).is_ok()
}

fn is_sdk_template_dir(dir_name: &str) -> bool {
    matches!(dir_name, "sdk-template" | "sdk-template-rust")
}

/// Discovers all plugin directories containing `plugin.manifest.json` inside `plugins_dir`.
/// Marks `sdk-template` and `sdk-template-rust` with `is_template: true`.
pub fn discover_plugins_in_dir(plugins_dir: &Path) -> Vec<PluginInstanceView> {
    let Ok(entries) = fs::read_dir(plugins_dir) else {
        return Vec::new();
    };

    let mut views = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name = entry.file_name().to_string_lossy().to_string();
        if dir_name.starts_with('.') {
            continue;
        }
        let manifest_path = path.join("plugin.manifest.json");
        if !manifest_path.is_file() {
            continue;
        }

        let is_template = is_sdk_template_dir(&dir_name);
        let manifest_path_str = manifest_path.to_string_lossy().to_string();

        match load_plugin_manifest_file(&manifest_path) {
            Ok(manifest) => {
                let validation_res = validate_plugin_manifest_in_dir(&manifest, Some(&path));
                let (status, allocated_port, validation_error) = match validation_res {
                    Ok(()) => {
                        let port = allocate_plugin_port_with_hint(
                            &manifest.id,
                            manifest.network.default_port.unwrap_or(0),
                        );
                        let st = if is_plugin_port_listening(port) {
                            "running"
                        } else {
                            "installed"
                        };
                        (st.to_string(), port, None)
                    }
                    Err(e) => ("invalid".to_string(), 0, Some(e.to_string())),
                };

                views.push(PluginInstanceView {
                    id: manifest.id,
                    name: manifest.name,
                    version: manifest.version,
                    description: manifest.description,
                    author: manifest.author,
                    status,
                    allocated_port,
                    permissions: manifest.permissions,
                    api_scopes: manifest.api_scopes,
                    manifest_path: manifest_path_str,
                    is_template,
                    frontend_slot: manifest.frontend_slot,
                    validation_error,
                });
            }
            Err(e) => {
                let fallback_id = dir_name.to_lowercase();
                views.push(PluginInstanceView {
                    id: fallback_id,
                    name: dir_name,
                    version: "0.0.0".to_string(),
                    description: String::new(),
                    author: String::new(),
                    status: "invalid".to_string(),
                    allocated_port: 0,
                    permissions: Vec::new(),
                    api_scopes: Vec::new(),
                    manifest_path: manifest_path_str,
                    is_template,
                    frontend_slot: None,
                    validation_error: Some(e.to_string()),
                });
            }
        }
    }

    views.sort_by(|a, b| a.id.cmp(&b.id));
    views
}

/// Resolves the active plugins directory from `AETHERFLOW_PLUGINS_DIR`, `/opt/AetherFlow/current/plugins`,
/// or relative `./plugins` candidates.
pub fn resolve_plugins_dir() -> PathBuf {
    if let Ok(explicit) = env::var("AETHERFLOW_PLUGINS_DIR") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    let candidates = [
        PathBuf::from("plugins"),
        PathBuf::from("../plugins"),
        PathBuf::from("../../plugins"),
        PathBuf::from("../../../plugins"),
        PathBuf::from("/opt/AetherFlow/current/plugins"),
        PathBuf::from("/opt/AetherFlow/plugins"),
    ];
    for candidate in candidates {
        if candidate.is_dir() {
            return candidate;
        }
    }
    PathBuf::from("plugins")
}

/// Discovers plugins from the resolved plugins directory (`AETHERFLOW_PLUGINS_DIR`,
/// `/opt/AetherFlow/current/plugins`, or `./plugins`).
pub fn discover_installed_plugins() -> Vec<PluginInstanceView> {
    let dir = resolve_plugins_dir();
    discover_plugins_in_dir(&dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_plugins_dir() -> PathBuf {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .map(|root| root.join("plugins"))
            .unwrap_or_else(|| PathBuf::from("plugins"))
    }

    #[test]
    fn test_parse_and_validate_rust_sdk_template_manifest() {
        let plugins_dir = repo_plugins_dir();
        let rust_manifest_path = plugins_dir
            .join("sdk-template-rust")
            .join("plugin.manifest.json");
        assert!(
            rust_manifest_path.is_file(),
            "expected {:?} to exist",
            rust_manifest_path
        );

        let manifest = load_plugin_manifest_file(&rust_manifest_path)
            .expect("should parse sdk-template-rust manifest");
        assert_eq!(manifest.id, "sdk-template-rust");
        assert_eq!(manifest.version, "0.1.0");
        assert_eq!(manifest.api_version, "v1-staged");
        assert_eq!(manifest.entry_points.backend, "backend/src/main.rs");
        assert_eq!(manifest.entry_points.frontend, "frontend/src/index.tsx");
        assert_eq!(manifest.frontend_slot.as_deref(), Some("marketplace"));
        assert_eq!(manifest.network.health_path, "/healthz");
        assert_eq!(manifest.network.port_allocation, "dynamic");
        assert_eq!(
            manifest.permissions,
            vec![
                "marketplace:read".to_string(),
                "system:metrics:read".to_string()
            ]
        );
        assert_eq!(
            manifest.api_scopes,
            vec![
                "/api/v1/public/marketplace".to_string(),
                "/api/v1/auth/system/metrics".to_string()
            ]
        );

        validate_plugin_manifest_in_dir(&manifest, rust_manifest_path.parent())
            .expect("sdk-template-rust manifest should pass strict validation");
    }

    #[test]
    fn test_validate_plugin_manifest_rejects_malformed_ids_traversal_and_scopes() {
        let base = PluginManifest {
            id: "valid-plugin_1".to_string(),
            name: "Valid Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Test plugin".to_string(),
            author: "Tester".to_string(),
            api_version: "v1".to_string(),
            entry_points: PluginEntryPoints {
                backend: "backend/src/main.rs".to_string(),
                frontend: "frontend/src/index.tsx".to_string(),
                wasm: String::new(),
            },
            permissions: vec![
                "marketplace:read".to_string(),
                "system:metrics:read".to_string(),
            ],
            api_scopes: vec![
                "/api/v1/public/marketplace".to_string(),
                "/api/v1/auth/system/metrics".to_string(),
            ],
            network: PluginNetworkConfig {
                port_allocation: "dynamic".to_string(),
                health_path: "/healthz".to_string(),
                default_port: None,
                allow_outbound: false,
            },
            lifecycle_hooks: PluginLifecycleHooks {
                on_start: "backend/hooks/start.sh".to_string(),
                on_stop: "backend/hooks/stop.sh".to_string(),
                on_install: String::new(),
                on_uninstall: String::new(),
            },
            frontend_slot: Some("marketplace".to_string()),
            ..Default::default()
        };

        assert!(validate_plugin_manifest(&base).is_ok());

        // Reject malformed plugin IDs
        for bad_id in [
            "",
            "a",
            "../evil",
            "plugin/evil",
            "UpperCaseId",
            "-starts-with-dash",
            "_starts_with_underscore",
            "has spaces",
            "a..b",
        ] {
            let mut m = base.clone();
            m.id = bad_id.to_string();
            assert!(
                validate_plugin_manifest(&m).is_err(),
                "expected bad plugin ID '{}' to be rejected",
                bad_id
            );
        }

        // Reject invalid api_scopes
        for bad_scope in [
            "",
            "/api/system/metrics",
            "/api/v1/",
            "/api/v1/auth/../admin/users",
            "http://127.0.0.1:8080/api/v1/public/marketplace",
            "/api/v1/public/marketplace with space",
        ] {
            let mut m = base.clone();
            m.api_scopes = vec![bad_scope.to_string()];
            assert!(
                validate_plugin_manifest(&m).is_err(),
                "expected bad scope '{}' to be rejected",
                bad_scope
            );
        }

        // Reject invalid permissions
        for bad_perm in ["", "marketplace/read", "system:metrics;rm -rf", ":leading"] {
            let mut m = base.clone();
            m.permissions = vec![bad_perm.to_string()];
            assert!(
                validate_plugin_manifest(&m).is_err(),
                "expected bad permission '{}' to be rejected",
                bad_perm
            );
        }

        // Reject path traversal in entry_points and lifecycle_hooks
        let mut traversal_entry = base.clone();
        traversal_entry.entry_points.backend = "../outside/main.rs".to_string();
        assert!(validate_plugin_manifest(&traversal_entry).is_err());

        let mut abs_entry = base.clone();
        abs_entry.entry_points.frontend = "/etc/passwd".to_string();
        assert!(validate_plugin_manifest(&abs_entry).is_err());

        let mut traversal_hook = base.clone();
        traversal_hook.lifecycle_hooks.on_start = "backend/hooks/../../evil.sh".to_string();
        assert!(validate_plugin_manifest(&traversal_hook).is_err());

        // Reject symlink escape on disk
        #[cfg(unix)]
        {
            let tmp_dir = std::env::temp_dir()
                .join(format!("af_plugin_symlink_test_{}", uuid::Uuid::new_v4()));
            let _ = fs::create_dir_all(tmp_dir.join("backend"));
            let outside_file =
                std::env::temp_dir().join(format!("af_outside_target_{}", uuid::Uuid::new_v4()));
            let _ = fs::write(&outside_file, b"#!/bin/sh\n");
            let symlink_path = tmp_dir.join("backend").join("escape.sh");
            std::os::unix::fs::symlink(&outside_file, &symlink_path).unwrap();

            let mut sym_manifest = base.clone();
            sym_manifest.lifecycle_hooks.on_start = "backend/escape.sh".to_string();
            let res = validate_plugin_manifest_in_dir(&sym_manifest, Some(&tmp_dir));
            let _ = fs::remove_dir_all(&tmp_dir);
            let _ = fs::remove_file(&outside_file);
            assert!(res.is_err(), "expected symlink escape to be rejected");
        }
    }

    #[test]
    fn test_verify_plugin_route_scope_boundaries() {
        let scopes = vec![
            "/api/v1/public/marketplace".to_string(),
            "/api/v1/auth/system/*".to_string(),
        ];

        // Exact & sub-path match for exact scope
        assert!(verify_plugin_route_scope(
            &scopes,
            "/api/v1/public/marketplace"
        ));
        assert!(verify_plugin_route_scope(
            &scopes,
            "/api/v1/public/marketplace/"
        ));
        assert!(verify_plugin_route_scope(
            &scopes,
            "/api/v1/public/marketplace/featured?limit=10"
        ));

        // Segment boundary check: must NOT match sibling prefix
        assert!(!verify_plugin_route_scope(
            &scopes,
            "/api/v1/public/marketplace_admin"
        ));
        assert!(!verify_plugin_route_scope(
            &scopes,
            "/api/v1/public/marketplace-internal"
        ));

        // Wildcard prefix match
        assert!(verify_plugin_route_scope(
            &scopes,
            "/api/v1/auth/system/metrics"
        ));
        assert!(verify_plugin_route_scope(
            &scopes,
            "/api/v1/auth/system/hardware"
        ));
        assert!(!verify_plugin_route_scope(
            &scopes,
            "/api/v1/auth/system_other"
        ));

        // Disallowed routes & traversal attempts
        assert!(!verify_plugin_route_scope(&scopes, "/api/v1/admin/users"));
        assert!(!verify_plugin_route_scope(
            &scopes,
            "/api/v1/auth/system/../admin/users"
        ));
        assert!(!verify_plugin_route_scope(
            &scopes,
            "/api/public/marketplace"
        ));
    }

    #[test]
    fn test_allocate_plugin_port_and_discover_plugins() {
        let p1 = allocate_plugin_port("telemetry-pro");
        let p2 = allocate_plugin_port("telemetry-pro");
        assert_eq!(p1, p2);
        assert!((PLUGIN_PORT_MIN..=PLUGIN_PORT_MAX).contains(&p1));

        let plugins_dir = repo_plugins_dir();
        let discovered = discover_plugins_in_dir(&plugins_dir);
        assert!(
            discovered
                .iter()
                .any(|p| p.id == "sdk-template-rust" && p.is_template && p.status != "invalid"),
            "expected sdk-template-rust to be discovered as a valid template: {:?}",
            discovered
        );
    }
}
