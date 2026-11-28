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

const MAX_PLUGIN_MANIFEST_BYTES: u64 = 256 * 1024;

#[cfg(unix)]
fn is_production_env_with_lookup<F>(get_env: &mut F) -> bool
where
    F: FnMut(&str) -> Option<String>,
{
    get_env("AETHERFLOW_ENV")
        .as_deref()
        .is_some_and(crate::auth::is_production_or_release_env)
}

#[cfg(unix)]
fn is_env_flag_truthy(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(unix)]
fn normalize_non_root_isolated_path(candidate: &StdPath, label: &str) -> Option<PathBuf> {
    af_models::normalize_lexical_path(candidate, label)
        .ok()
        .filter(|norm| norm.is_absolute() && norm != StdPath::new("/"))
}

#[cfg(unix)]
fn is_non_root_isolated_path(candidate: &StdPath, label: &str) -> bool {
    normalize_non_root_isolated_path(candidate, label).is_some()
}

#[cfg(unix)]
fn is_path_strictly_within_isolated_root(path: &StdPath, isolated_root: &StdPath) -> bool {
    let Some(norm_root) = normalize_non_root_isolated_path(isolated_root, "isolated_root") else {
        return false;
    };
    let candidate = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let root_effective = fs::canonicalize(&norm_root).unwrap_or(norm_root);
    if !root_effective.is_absolute() || root_effective == StdPath::new("/") {
        return false;
    }
    af_models::validate_path_within_isolated_root(&candidate, &root_effective, "plugin_path")
        .is_ok()
}

#[cfg(unix)]
fn is_isolated_plugin_root_for_path_with_env<F>(path: &StdPath, mut get_env: F) -> bool
where
    F: FnMut(&str) -> Option<String>,
{
    if is_production_env_with_lookup(&mut get_env) {
        return false;
    }
    if get_env("AETHERFLOW_E2E_ISOLATED").is_some_and(|v| is_env_flag_truthy(&v)) {
        return true;
    }
    if af_models::try_resolve_isolated_root_with_env(None, &mut get_env)
        .ok()
        .flatten()
        .is_some_and(|root| is_path_strictly_within_isolated_root(path, &root))
    {
        return true;
    }
    ["AETHERFLOW_FS_ROOT", "AETHERFLOW_INSTALL_ROOT"]
        .iter()
        .any(|key| {
            get_env(key).is_some_and(|v| {
                let trimmed = v.trim();
                !trimmed.is_empty()
                    && is_non_root_isolated_path(StdPath::new(trimmed), key)
                    && is_path_strictly_within_isolated_root(path, StdPath::new(trimmed))
            })
        })
}

#[cfg(unix)]
fn is_isolated_plugin_test_root_for_path(path: &StdPath) -> bool {
    let mut get_env = |k: &str| std::env::var(k).ok();
    if is_production_env_with_lookup(&mut get_env) {
        return false;
    }
    cfg!(test) || is_isolated_plugin_root_for_path_with_env(path, get_env)
}

#[cfg(unix)]
fn check_trusted_metadata_with_root_policy(
    path: &StdPath,
    meta: &fs::Metadata,
    require_root_only: bool,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode();
    if (mode & 0o002) != 0 {
        return Err(format!(
            "Insecure world-writable permissions (mode {:o}) on '{}'",
            mode & 0o777,
            path.display()
        ));
    }
    if require_root_only && (mode & 0o020) != 0 && meta.gid() != 0 {
        return Err(format!(
            "Insecure group-writable permissions (mode {:o}, gid={}) on '{}' (must not be writable by non-root group)",
            mode & 0o777,
            meta.gid(),
            path.display()
        ));
    }
    let file_uid = meta.uid();
    let euid = unsafe { libc::geteuid() };
    let trusted = if require_root_only {
        file_uid == 0
    } else {
        file_uid == 0 || file_uid == euid
    };
    if !trusted {
        return Err(if require_root_only {
            format!(
                "Untrusted file owner uid={} on '{}' (must be root uid=0)",
                file_uid,
                path.display()
            )
        } else {
            format!(
                "Untrusted file owner uid={} on '{}' (must be root or service uid={})",
                file_uid,
                path.display(),
                euid
            )
        });
    }
    Ok(())
}

#[cfg(unix)]
fn check_trusted_ownership_with_root_policy(
    path: &StdPath,
    require_root_only: bool,
) -> Result<(), String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("Failed to stat '{}': {}", path.display(), e))?;
    check_trusted_metadata_with_root_policy(path, &meta, require_root_only)
}

#[cfg(unix)]
fn check_trusted_metadata(path: &StdPath, meta: &fs::Metadata) -> Result<(), String> {
    check_trusted_metadata_with_root_policy(
        path,
        meta,
        !is_isolated_plugin_test_root_for_path(path),
    )
}

#[cfg(unix)]
fn check_trusted_ownership(path: &StdPath) -> Result<(), String> {
    // Production `aetherflow-api` runs as the unprivileged `aetherflow` user while
    // `aetherflow-runner` runs as root (`uid == 0`). Match root `af-runner` by
    // requiring `file_uid == 0` outside isolated test environments so `af-api`
    // never admits service-owned plugin assets that `af-runner` rejects.
    check_trusted_ownership_with_root_policy(path, !is_isolated_plugin_test_root_for_path(path))
}

#[cfg(all(test, unix))]
mod ownership_tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use uuid::Uuid;

    fn lookup_from<'a>(
        entries: &'a [(&'a str, &'a str)],
    ) -> impl FnMut(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = entries.iter().copied().collect();
        move |k: &str| map.get(k).map(|v| (*v).to_string())
    }

    #[test]
    fn production_root_policy_rejects_non_root_service_owned_and_group_writable_plugin_paths() {
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return;
        }
        let dir = std::env::temp_dir().join(format!("af-plugin-own-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let err = check_trusted_ownership_with_root_policy(&dir, true)
            .expect_err("root-only policy must reject non-root owner even when file_uid == euid");
        assert!(err.contains("must be root uid=0"), "{err}");
        assert!(check_trusted_ownership_with_root_policy(&dir, false).is_ok());

        let gw_file = dir.join("group-writable.json");
        fs::write(&gw_file, "{}").unwrap();
        fs::set_permissions(&gw_file, fs::Permissions::from_mode(0o664)).unwrap();
        let gw_err = check_trusted_ownership_with_root_policy(&gw_file, true)
            .expect_err("root-only policy must reject group-writable non-root-gid paths");
        assert!(gw_err.contains("group-writable"), "{gw_err}");
        assert!(
            check_trusted_ownership_with_root_policy(&gw_file, false).is_ok(),
            "non-root isolated policy permits service-owned group-writable test files"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn isolated_plugin_env_scopes_relaxation_to_absolute_isolated_root_and_denies_production() {
        let inside_fs = StdPath::new("/tmp/af-iso/opt/AetherFlow/plugins/demo");
        let outside_fs = StdPath::new("/var/tmp/outside-plugins/demo");
        let inside_install = StdPath::new("/tmp/af-install/plugins/demo");
        let inside_backup = StdPath::new("/tmp/af-backup-iso/plugins/demo");

        // Non-production isolated flags and paths strictly inside configured absolute roots are allowed
        assert!(is_isolated_plugin_root_for_path_with_env(
            outside_fs,
            lookup_from(&[("AETHERFLOW_E2E_ISOLATED", "1")]),
        ));
        assert!(is_isolated_plugin_root_for_path_with_env(
            outside_fs,
            lookup_from(&[
                ("AETHERFLOW_ENV", "development"),
                ("AETHERFLOW_E2E_ISOLATED", "true"),
            ]),
        ));
        assert!(is_isolated_plugin_root_for_path_with_env(
            inside_fs,
            lookup_from(&[("AETHERFLOW_FS_ROOT", "/tmp/af-iso")]),
        ));
        assert!(is_isolated_plugin_root_for_path_with_env(
            inside_install,
            lookup_from(&[("AETHERFLOW_INSTALL_ROOT", "/tmp/af-install")]),
        ));
        assert!(is_isolated_plugin_root_for_path_with_env(
            inside_backup,
            lookup_from(&[("AETHERFLOW_BACKUP_ISOLATED_ROOT", "/tmp/af-backup-iso")]),
        ));

        // Paths OUTSIDE the isolated root (e.g. AETHERFLOW_PLUGINS_DIR pointing elsewhere or
        // sibling prefix collision) MUST NOT inherit isolated-root ownership relaxation
        assert!(!is_isolated_plugin_root_for_path_with_env(
            outside_fs,
            lookup_from(&[
                ("AETHERFLOW_FS_ROOT", "/tmp/af-iso"),
                ("AETHERFLOW_PLUGINS_DIR", "/var/tmp/outside-plugins"),
            ]),
        ));
        assert!(!is_isolated_plugin_root_for_path_with_env(
            StdPath::new("/tmp/af-iso-evil/plugins/demo"),
            lookup_from(&[("AETHERFLOW_FS_ROOT", "/tmp/af-iso")]),
        ));
        assert!(!is_isolated_plugin_root_for_path_with_env(
            StdPath::new("/tmp/af-iso"),
            lookup_from(&[("AETHERFLOW_FS_ROOT", "/tmp/af-iso")]),
        ));

        // Root `/`, `//`, `/.`, relative paths, or AETHERFLOW_PLUGINS_DIR alone MUST NOT weaken checks
        for root_key in [
            "AETHERFLOW_FS_ROOT",
            "AETHERFLOW_INSTALL_ROOT",
            "AETHERFLOW_RELEASE_ROOT",
            "AETHERFLOW_BACKUP_ISOLATED_ROOT",
        ] {
            for root_val in [
                "/",
                "//",
                "/.",
                "/./",
                ".",
                "relative",
                "tmp/af-iso",
                "../iso",
            ] {
                assert!(
                    !is_non_root_isolated_path(StdPath::new(root_val), root_key),
                    "expected {root_key}={root_val:?} to fail non-root absolute path check"
                );
                assert!(
                    !is_isolated_plugin_root_for_path_with_env(
                        inside_fs,
                        lookup_from(&[(root_key, root_val)]),
                    ),
                    "expected {root_key}={root_val:?} to be rejected"
                );
            }
        }
        assert!(!is_isolated_plugin_root_for_path_with_env(
            StdPath::new("/tmp/custom-plugins/demo"),
            lookup_from(&[("AETHERFLOW_PLUGINS_DIR", "/tmp/custom-plugins")]),
        ));
        assert!(!is_isolated_plugin_root_for_path_with_env(
            inside_fs,
            lookup_from(&[("AETHERFLOW_E2E_ISOLATED", "0")]),
        ));

        // Production and release environments MUST ALWAYS deny isolated fallback regardless of other env flags
        for prod_val in [
            "production",
            "PRODUCTION",
            " Production ",
            "release",
            "RELEASE",
            " Release ",
        ] {
            assert!(
                !is_isolated_plugin_root_for_path_with_env(
                    inside_fs,
                    lookup_from(&[
                        ("AETHERFLOW_ENV", prod_val),
                        ("AETHERFLOW_E2E_ISOLATED", "1"),
                        ("AETHERFLOW_FS_ROOT", "/tmp/af-iso"),
                        ("AETHERFLOW_RELEASE_ROOT", "/tmp/af-release-iso"),
                        ("AETHERFLOW_BACKUP_ISOLATED_ROOT", "/tmp/af-backup-iso"),
                    ]),
                ),
                "expected AETHERFLOW_ENV={prod_val:?} to deny isolated fallback"
            );
        }
    }

    #[test]
    fn discover_plugins_in_dir_rejects_untrusted_parent_plugins_root() {
        let root = std::env::temp_dir().join(format!("af-plugin-root-ww-{}", Uuid::new_v4()));
        let valid_plugin = root.join("good-plugin");
        fs::create_dir_all(&valid_plugin).unwrap();
        fs::write(
            valid_plugin.join("plugin.manifest.json"),
            r#"{"id":"good-plugin","name":"Good Plugin","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();

        let (manifests, rejected) = discover_plugins_in_dir(&root);
        assert!(
            manifests.is_empty(),
            "world-writable plugins root must admit 0 manifests, got {manifests:?}"
        );
        assert!(
            rejected
                .iter()
                .any(|(_, reason)| reason.contains("world-writable")),
            "expected world-writable parent root rejection, got {rejected:?}"
        );

        let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn discover_plugins_in_dir_rejects_world_writable_and_oversized_manifests() {
        let root = std::env::temp_dir().join(format!("af-plugin-disc-{}", Uuid::new_v4()));
        let writable_plugin = root.join("bad-perms");
        fs::create_dir_all(&writable_plugin).unwrap();
        let writable_manifest = writable_plugin.join("plugin.manifest.json");
        fs::write(
            &writable_manifest,
            r#"{"id":"bad-perms","name":"Bad Perms","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::set_permissions(&writable_manifest, fs::Permissions::from_mode(0o666)).unwrap();

        let writable_dir_plugin = root.join("bad-dir-perms");
        fs::create_dir_all(&writable_dir_plugin).unwrap();
        fs::write(
            writable_dir_plugin.join("plugin.manifest.json"),
            r#"{"id":"bad-dir-perms","name":"Bad Dir Perms","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::set_permissions(&writable_dir_plugin, fs::Permissions::from_mode(0o777)).unwrap();

        let oversized_plugin = root.join("too-big");
        fs::create_dir_all(&oversized_plugin).unwrap();
        let oversized_manifest = oversized_plugin.join("plugin.manifest.json");
        fs::write(
            &oversized_manifest,
            vec![b' '; (MAX_PLUGIN_MANIFEST_BYTES as usize) + 16],
        )
        .unwrap();

        let dir_manifest_plugin = root.join("dir-manifest");
        fs::create_dir_all(dir_manifest_plugin.join("plugin.manifest.json")).unwrap();

        let (manifests, rejected) = discover_plugins_in_dir(&root);
        assert!(
            manifests.is_empty(),
            "expected 0 valid manifests, got {manifests:?}"
        );
        assert!(
            rejected
                .iter()
                .any(|(id, reason)| id == "bad-perms" && reason.contains("world-writable")),
            "expected world-writable rejection, got {rejected:?}"
        );
        assert!(
            rejected
                .iter()
                .any(|(id, reason)| id == "bad-dir-perms" && reason.contains("world-writable")),
            "expected world-writable plugin directory rejection, got {rejected:?}"
        );
        assert!(
            rejected
                .iter()
                .any(|(id, reason)| id == "too-big" && reason.contains("oversized")),
            "expected oversized rejection, got {rejected:?}"
        );
        assert!(
            rejected
                .iter()
                .any(|(id, reason)| id == "dir-manifest" && reason.contains("Invalid or oversized")),
            "expected non-regular file rejection, got {rejected:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }
}

#[cfg(not(unix))]
fn check_trusted_metadata(_path: &StdPath, _meta: &fs::Metadata) -> Result<(), String> {
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
    if let Err(err) = check_trusted_ownership(&canon_root) {
        rejected.push((
            canon_root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| canon_root.display().to_string()),
            err,
        ));
        return (manifests, rejected);
    }
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
        if let Err(err) = check_trusted_ownership(&canon_dir) {
            rejected.push((dir_name, err));
            continue;
        }

        let manifest_path = canon_dir.join("plugin.manifest.json");
        let m_sym = match fs::symlink_metadata(&manifest_path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                rejected.push((
                    dir_name,
                    format!("Failed to inspect plugin.manifest.json: {}", e),
                ));
                continue;
            }
        };
        if m_sym.file_type().is_symlink() {
            rejected.push((
                dir_name,
                "plugin.manifest.json cannot be a symbolic link".to_string(),
            ));
            continue;
        }
        if let Err(err) = check_trusted_metadata(&manifest_path, &m_sym) {
            rejected.push((dir_name, err));
            continue;
        }
        if !m_sym.is_file() || m_sym.len() > MAX_PLUGIN_MANIFEST_BYTES {
            rejected.push((
                dir_name,
                "Invalid or oversized plugin.manifest.json".to_string(),
            ));
            continue;
        }

        let mut open_opts = fs::OpenOptions::new();
        open_opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let file = match open_opts.open(&manifest_path) {
            Ok(f) => f,
            Err(e) => {
                #[cfg(unix)]
                if e.raw_os_error() == Some(libc::ELOOP) {
                    rejected.push((
                        dir_name,
                        "plugin.manifest.json cannot be a symbolic link".to_string(),
                    ));
                    continue;
                }
                rejected.push((dir_name, format!("Failed to read manifest: {}", e)));
                continue;
            }
        };
        let file_meta = match file.metadata() {
            Ok(meta) => meta,
            Err(e) => {
                rejected.push((
                    dir_name,
                    format!("Failed to inspect plugin.manifest.json: {}", e),
                ));
                continue;
            }
        };
        if let Err(err) = check_trusted_metadata(&manifest_path, &file_meta) {
            rejected.push((dir_name, err));
            continue;
        }
        if !file_meta.is_file() || file_meta.len() > MAX_PLUGIN_MANIFEST_BYTES {
            rejected.push((
                dir_name,
                "Invalid or oversized plugin.manifest.json".to_string(),
            ));
            continue;
        }
        let read_result = {
            use std::io::Read;
            let mut buf = String::new();
            file.take(MAX_PLUGIN_MANIFEST_BYTES + 1)
                .read_to_string(&mut buf)
                .map(|_| buf)
        };
        let raw_text = match read_result {
            Ok(t) if (t.len() as u64) <= MAX_PLUGIN_MANIFEST_BYTES => t,
            Ok(_) => {
                rejected.push((
                    dir_name,
                    "Invalid or oversized plugin.manifest.json".to_string(),
                ));
                continue;
            }
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
