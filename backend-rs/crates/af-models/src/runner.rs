use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────────────────────────────────────
// Privileged Runner IPC Models
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SystemctlRequest {
    pub service: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lifecycle_job_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PackageRunnerRequest {
    pub action: String,
    pub package_id: String,
    pub script_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lifecycle_job_id: String,
    #[serde(skip_serializing_if = "crate::is_zero_i32", default)]
    pub app_port: i32,
    #[serde(skip_serializing_if = "crate::is_zero_i32", default)]
    pub secondary_port: i32,
    /// Explicit destructive purge for `remove` only. The runner never inherits
    /// `DELETE_DATA` from its own environment; ordinary removals retain data.
    #[serde(skip_serializing_if = "crate::is_false", default)]
    pub delete_data: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_target_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub achieved_version: Option<String>,
}

/// Manages a privileged `af-runner` runtime/blueprint/receipt snapshot tied to
/// an admitted `lifecycle_job_id` across API-coordinated certification and
/// post-script finalization (`capture`, `restore`, or `discard`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PackageLifecycleSnapshotRequest {
    pub action: String,
    pub package_id: String,
    pub lifecycle_job_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    #[serde(default, skip_serializing_if = "crate::is_false")]
    pub preserve_backup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SelfUpdateRequest {
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub channel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SelfUpdateStatusRequest {
    #[serde(default)]
    pub job_unit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SelfUpdateJobStatus {
    pub status: String,
    pub completed: bool,
    pub success: bool,
    pub job_unit: String,
    #[serde(default)]
    pub error: String,
    pub exit_code: Option<i32>,
}

pub fn is_valid_self_update_job_unit_name(unit_name: &str) -> bool {
    let trimmed = unit_name.trim();
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') {
        return false;
    }
    let Some(rest) = trimmed.strip_prefix("aetherflow-self-update-") else {
        return false;
    };
    let Some(body) = rest.strip_suffix(".service") else {
        return false;
    };
    if let Some((prefix, hex_tail)) = body.rsplit_once('-') {
        if prefix.is_empty()
            || prefix.starts_with('-')
            || prefix.ends_with('-')
            || prefix.contains("--")
            || !prefix.contains('-')
        {
            return false;
        }
        if !prefix
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        {
            return false;
        }
        if hex_tail.len() < 8 || hex_tail.len() > 32 {
            return false;
        }
        return hex_tail
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase());
    }
    if body.len() < 16 || body.len() > 64 {
        return false;
    }
    body.chars()
        .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

impl SelfUpdateJobStatus {
    pub fn validate_invariants(&self, expected_job_unit: Option<&str>) -> Result<(), String> {
        let trimmed_unit = self.job_unit.trim();
        if !is_valid_self_update_job_unit_name(trimmed_unit) {
            return Err(format!(
                "invalid self-update job_unit '{}' in status payload",
                self.job_unit
            ));
        }
        if let Some(expected_unit) = expected_job_unit {
            if trimmed_unit != expected_unit.trim() {
                return Err(format!(
                    "self-update receipt job_unit '{}' does not match requested unit '{}'",
                    trimmed_unit,
                    expected_unit.trim()
                ));
            }
        }
        match self.status.as_str() {
            "initiated" | "queued" | "launching" | "running" => {
                if self.completed {
                    return Err(format!(
                        "contradictory self-update status '{}': completed must be false",
                        self.status
                    ));
                }
                if self.success {
                    return Err(format!(
                        "contradictory self-update status '{}': success must be false while in progress",
                        self.status
                    ));
                }
                if self.exit_code.is_some() {
                    return Err(format!(
                        "contradictory self-update status '{}': exit_code must be None while in progress",
                        self.status
                    ));
                }
                if !self.error.trim().is_empty() {
                    return Err(format!(
                        "contradictory self-update status '{}': error must be empty while in progress",
                        self.status
                    ));
                }
                Ok(())
            }
            "succeeded" => {
                if !self.completed || !self.success {
                    return Err(
                        "contradictory self-update status 'succeeded': completed and success must be true"
                            .to_string(),
                    );
                }
                if self.exit_code != Some(0) {
                    return Err(format!(
                        "contradictory self-update status 'succeeded': exit_code must be Some(0), got {:?}",
                        self.exit_code
                    ));
                }
                if !self.error.trim().is_empty() {
                    return Err(
                        "contradictory self-update status 'succeeded': error must be empty"
                            .to_string(),
                    );
                }
                Ok(())
            }
            "failed" => {
                if !self.completed || self.success {
                    return Err(
                        "contradictory self-update status 'failed': completed must be true and success must be false"
                            .to_string(),
                    );
                }
                if self.exit_code == Some(0) {
                    return Err(
                        "contradictory self-update status 'failed': exit_code must not be 0"
                            .to_string(),
                    );
                }
                if self.error.trim().is_empty() {
                    return Err(
                        "contradictory self-update status 'failed': error message must not be empty"
                            .to_string(),
                    );
                }
                Ok(())
            }
            other_status => Err(format!(
                "unrecognized self-update job status '{}'",
                other_status
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SandboxRunnerRequest {
    #[serde(default)]
    pub package: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub package_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub lifecycle_job_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostsRunnerRequest {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub action: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub domain: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub domains: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NetworkRunnerRequest {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub subsystem: String,
    pub action: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub public_key: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub allowed_ips: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub endpoint: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub routes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "serde_json::Value::is_null", default)]
    pub options: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct QuotaRunnerRequest {
    pub username: String,
    pub size: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AppMetaRunnerRequest {
    pub app_name: String,
}

/// Applies server-defined native app configuration through the privileged runner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerBlueprintApplyRequest {
    pub app_name: String,
    pub listen_port: i32,
    #[serde(default)]
    pub lifecycle_job_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunnerBlueprintApplyResponse {
    pub mutated_files: Vec<String>,
    pub sqlite_routes_injected: usize,
}

pub const APP_LAUNCH_EXCHANGE_PATH: &str = "/.well-known/aetherflow/app-launch";

/// Validates the ASCII RFC 1123 labels used in ingress hostnames.
pub fn valid_ingress_hostname(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RunnerApacheVhostRequest {
    pub app_name: String,
    #[serde(default)]
    pub listen_port: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_domain: Option<String>,
    #[serde(default)]
    pub external_access_enabled: bool,
    #[serde(default)]
    pub tls_enabled: bool,
    #[serde(default)]
    pub remove_only: bool,
    #[serde(default)]
    pub reload_apache: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BackupRunnerRequest {
    #[serde(default)]
    pub action: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub filename: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub backup_dir: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub db_path: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub target_root: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub app_version: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chunk_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub timestamp_slug: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_retained: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub retention_days: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_sqlite_user_version: Option<i64>,
    #[serde(skip_serializing_if = "crate::is_false", default)]
    pub allow_overwrite: bool,
    #[serde(skip_serializing_if = "crate::is_false", default)]
    pub confirm_destructive_restore: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub quiesce_services: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub trusted_sqlite_uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub trusted_sqlite_gid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BackupRunnerResponse {
    #[serde(default)]
    pub action: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub backup_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub filename: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub artifact_path: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub manifest_path: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub sha256: String,
    #[serde(default)]
    pub size_bytes: u64,
    #[serde(default)]
    pub chunk_count: usize,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub restored_files: usize,
    #[serde(default)]
    pub rolled_back: bool,
    #[serde(default)]
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RunnerResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub output: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error: String,
}

/// Permitted loopback port range for AetherFlow plugin backends.
pub const PLUGIN_PORT_RANGE_START: u16 = 21000;
pub const PLUGIN_PORT_RANGE_END: u16 = 21999;

/// Validates a plugin identifier (`^[a-z0-9][a-z0-9-_]{1,62}$`).
pub fn is_valid_plugin_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if !(2..=63).contains(&bytes.len()) {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Returns the canonical transient systemd service unit name for a managed plugin backend.
pub fn plugin_systemd_unit_name(plugin_id: &str) -> Option<String> {
    if is_valid_plugin_id(plugin_id) {
        Some(format!("aetherflow-plugin-{plugin_id}.service"))
    } else {
        None
    }
}

/// Returns the canonical transient systemd service unit name for a one-shot plugin stop hook.
pub fn plugin_stop_hook_unit_name(plugin_id: &str) -> Option<String> {
    if is_valid_plugin_id(plugin_id) {
        Some(format!("aetherflow-plugin-{plugin_id}-stop.service"))
    } else {
        None
    }
}

/// Resolves bundled and source plugins for the API and privileged runner.
/// An isolated filesystem root confines automatic discovery to that root.
#[cfg(not(target_arch = "wasm32"))]
pub fn resolve_plugins_dir_from(
    plugins_dir_env: Option<&str>,
    fs_root_env: Option<&str>,
    exe_path: Option<&Path>,
    cwd: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(custom) = plugins_dir_env.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(custom));
    }
    if let Some(root) = fs_root_env
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "/")
    {
        let root = std::fs::canonicalize(root).ok()?;
        return [
            "plugins",
            "opt/AetherFlow/current/plugins",
            "opt/AetherFlow/plugins",
        ]
        .into_iter()
        .filter_map(|relative| std::fs::canonicalize(root.join(relative)).ok())
        .find(|candidate| candidate.starts_with(&root) && candidate.is_dir());
    }
    if let Some(candidate) = exe_path
        .and_then(Path::parent)
        .map(|dir| dir.join("plugins"))
    {
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    let cwd = cwd.unwrap_or_else(|| Path::new("."));
    [
        cwd.join("plugins"),
        cwd.join("../plugins"),
        cwd.join("../../plugins"),
        PathBuf::from("/opt/AetherFlow/current/plugins"),
        PathBuf::from("/opt/AetherFlow/plugins"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_dir())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn resolve_plugins_dir() -> Option<PathBuf> {
    let plugins_dir_env = std::env::var("AETHERFLOW_PLUGINS_DIR").ok();
    let fs_root_env = std::env::var("AETHERFLOW_FS_ROOT").ok();
    let exe_path = std::env::current_exe().ok();
    let cwd = std::env::current_dir().ok();
    resolve_plugins_dir_from(
        plugins_dir_env.as_deref(),
        fs_root_env.as_deref(),
        exe_path.as_deref(),
        cwd.as_deref(),
    )
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PluginRunnerStartRequest {
    pub plugin_id: String,
    pub port: u16,
    pub runtime_id: String,
    pub api_base_url: String,
    pub initial_token: String,
}

impl std::fmt::Debug for PluginRunnerStartRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRunnerStartRequest")
            .field("plugin_id", &self.plugin_id)
            .field("port", &self.port)
            .field("runtime_id", &self.runtime_id)
            .field("api_base_url", &self.api_base_url)
            .field("initial_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PluginRunnerStopRequest {
    pub plugin_id: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_id: Option<String>,
    #[serde(default)]
    pub api_base_url: String,
    #[serde(default)]
    pub run_stop_hook: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PluginRunnerStatusRequest {
    pub plugin_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PluginRunnerTokenRotateRequest {
    pub plugin_id: String,
    pub runtime_id: String,
    pub token: String,
}

impl std::fmt::Debug for PluginRunnerTokenRotateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRunnerTokenRotateRequest")
            .field("plugin_id", &self.plugin_id)
            .field("runtime_id", &self.runtime_id)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PluginRunnerStatusResponse {
    pub plugin_id: String,
    pub unit_name: String,
    pub active: bool,
    #[serde(default)]
    pub sub_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}
