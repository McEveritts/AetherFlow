use super::types::{
    PluginScopeRule, PluginTokenClaims, RawPluginManifest, RawScopeEntry, ValidatedPluginManifest,
};
use crate::auth::api_error;
use axum::http::{Method, StatusCode};
use axum::response::Response;
use std::fs;
use std::path::{Component, Path as StdPath, PathBuf};

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

pub(super) fn plugin_requires_admin(permissions: &[String]) -> bool {
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

pub fn discover_plugins() -> (Vec<ValidatedPluginManifest>, Vec<(String, String)>) {
    match af_models::resolve_plugins_dir() {
        Some(root) => discover_plugins_in_dir(&root),
        None => (Vec::new(), Vec::new()),
    }
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

pub(super) fn find_validated_plugin(
    plugin_id: &str,
) -> Result<ValidatedPluginManifest, Box<Response>> {
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
