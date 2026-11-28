use af_models::{is_valid_plugin_id, PLUGIN_PORT_RANGE_END, PLUGIN_PORT_RANGE_START};
use serde::Deserialize;
use std::fs;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

use super::{PluginRunnerError, MAX_PLUGIN_MANIFEST_BYTES, MAX_PLUGIN_TOKEN_BYTES};

#[derive(Debug, Clone, Deserialize, Default)]
pub(super) struct RunnerPluginHooks {
    #[serde(default)]
    pub(super) on_start: String,
    #[serde(default)]
    pub(super) on_stop: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub(super) struct RunnerPluginBackend {
    #[serde(default)]
    pub(super) manifest_path: String,
    #[serde(default)]
    pub(super) binary_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RunnerPluginManifest {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) version: String,
    #[serde(default)]
    pub(super) lifecycle_hooks: RunnerPluginHooks,
    #[serde(default)]
    pub(super) backend: RunnerPluginBackend,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ResolvedPluginStart {
    Binary(String),
    BashHook(String),
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedPluginSpec {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) plugin_dir: PathBuf,
    pub(super) start_target: Option<ResolvedPluginStart>,
    pub(super) stop_hook_rel: Option<String>,
}

pub(super) fn validate_plugin_id(id: &str) -> Result<String, PluginRunnerError> {
    let trimmed = id.trim();
    if !is_valid_plugin_id(trimmed) || matches!(trimmed, "sdk-template" | "sdk-template-rust") {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Invalid plugin identifier '{}'",
            trimmed
        )));
    }
    Ok(trimmed.to_string())
}

pub(super) fn validate_port(port: u16) -> Result<u16, PluginRunnerError> {
    if !(PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&port) {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Plugin port {} is outside permitted loopback range {}..={}",
            port, PLUGIN_PORT_RANGE_START, PLUGIN_PORT_RANGE_END
        )));
    }
    Ok(port)
}

pub(super) fn validate_runtime_id(raw: &str) -> Result<String, PluginRunnerError> {
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

pub(super) fn validate_plugin_token(token: &str) -> Result<&str, PluginRunnerError> {
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

pub(super) fn validate_systemd_env_value(
    value: &str,
    label: &str,
) -> Result<String, PluginRunnerError> {
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

pub(super) fn validate_systemd_path_value(
    path: &Path,
    label: &str,
) -> Result<String, PluginRunnerError> {
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
    if euid == 0 && (mode & 0o020) != 0 && meta.gid() != 0 {
        return Err(PluginRunnerError::InvalidRequest(format!(
            "Insecure group-writable permissions (mode {:o}, gid={}) on '{}' (must not be writable by non-root group)",
            mode & 0o777,
            meta.gid(),
            path.display()
        )));
    }
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

pub(super) fn load_verified_plugin_spec(
    plugin_id: &str,
) -> Result<VerifiedPluginSpec, PluginRunnerError> {
    let plugin_id = validate_plugin_id(plugin_id)?;
    let plugins_root = af_models::resolve_plugins_dir().ok_or_else(|| {
        PluginRunnerError::InvalidRequest("Plugins root is unavailable".to_string())
    })?;
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
