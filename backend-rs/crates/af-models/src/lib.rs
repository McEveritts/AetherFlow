use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Hardware & System Telemetry Models (`backend/models/hardware.go` & `models.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CpuInfo {
    pub vendor: String,
    pub model: String,
    pub cores: u32,
    pub threads: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MemoryInfo {
    pub total_bytes: i64,
    pub banks: i32,
    #[serde(rename = "type")]
    pub mem_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GpuInfo {
    pub vendor: String,
    pub product: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub driver: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NetworkInfo {
    pub name: String,
    pub mac: String,
    pub vendor: String,
    pub product: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StorageInfo {
    pub name: String,
    pub model: String,
    pub size_bytes: u64,
    pub drive_type: String,
    pub is_removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HardwareReport {
    pub system_vendor: String,
    pub system_product: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cpu: Option<CpuInfo>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub memory: Option<MemoryInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub gpus: Vec<GpuInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub network: Vec<NetworkInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub storage: Vec<StorageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ProcessInfo {
    pub pid: i32,
    pub name: String,
    pub cpu: f64,
    pub mem: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GpuMetric {
    pub index: usize,
    pub name: String,
    pub usage_pct: f64,
    pub memory_total: f64,
    pub memory_used: f64,
    pub temp: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DiskPartition {
    pub mount_point: String,
    pub device: String,
    pub fs_type: String,
    pub total_gb: f64,
    pub used_gb: f64,
    pub free_gb: f64,
    pub used_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SystemMetrics {
    pub cpu_usage: f64,
    pub per_core_cpu: Vec<f64>,
    pub cpu_freq_mhz: f64,
    pub disk_space: HashMap<String, f64>,
    pub disks: Vec<DiskPartition>,
    pub disk_io: HashMap<String, f64>,
    pub services: HashMap<String, bool>,
    pub memory: HashMap<String, f64>,
    pub swap: HashMap<String, f64>,
    pub network: HashMap<String, serde_json::Value>,
    pub total_net_bytes: HashMap<String, u64>,
    pub uptime: String,
    pub load_average: Vec<f64>,
    pub processes: Vec<ProcessInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub gpus: Vec<GpuMetric>,
}

// ─────────────────────────────────────────────────────────────────────────────
// User, Session & Ingress Models (`backend/models/user.go` & `models.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub avatar_url: String,
    pub role: String,
    #[serde(skip)]
    pub google_id: String,
    pub is_oauth: bool,
    pub totp_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppIngressConfig {
    pub app_name: String,
    pub public_domain: String,
    pub external_access_enabled: bool,
    pub listen_port: i32,
    pub tls_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Default for AppIngressConfig {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            app_name: String::new(),
            public_domain: String::new(),
            external_access_enabled: false,
            listen_port: 0,
            tls_enabled: false,
            created_at: now,
            updated_at: now,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Marketplace & Package Automation Models (`backend/models/package.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Package {
    pub name: String,
    pub label: String,
    pub description: String,
    pub lock_file: String,
    pub category: String,

    #[serde(default)]
    pub hits: i32,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub service_type: String,
    #[serde(default)]
    pub service_name: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub default_port: i32,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub web_path: String,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_source: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_repo: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_repo_url: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_package: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub version_command: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub version_regex: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub sandbox_profile: String,
    #[serde(
        rename = "sandbox_rw_paths",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub sandbox_read_write: Vec<String>,
    #[serde(
        rename = "sandbox_service_units",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub sandbox_service_ids: Vec<String>,

    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub installed_version: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub latest_version: String,
    #[serde(default)]
    pub update_available: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_checked_at: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_url: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PackageAutomation {
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_source: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_repo: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_repo_url: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_package: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub version_command: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub version_regex: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub sandbox_profile: String,
    #[serde(
        rename = "sandbox_rw_paths",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub sandbox_read_write: Vec<String>,
    #[serde(
        rename = "sandbox_service_units",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub sandbox_service_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MarketplaceApp {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub job_id: Option<String>,
    pub id: String,
    pub name: String,
    pub desc: String,
    pub hits: i32,
    pub category: String,
    pub status: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub default_port: i32,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub active_port: i32,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub internal_domain: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub public_domain: String,
    #[serde(skip_serializing_if = "is_false", default)]
    pub external_access_enabled: bool,
    #[serde(default)]
    pub tls_enabled: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub web_path: String,
    pub progress: i32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub log_line: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub installed_version: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub latest_version: String,
    #[serde(default)]
    pub update_available: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_checked_at: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_url: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub update_error: String,
    /// Terminal outcome of the most recent lifecycle job. Deliberately carries
    /// no error text because this catalog is served without authentication;
    /// failure detail is available from the authenticated progress endpoint.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_job: Option<MarketplaceJobOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MarketplaceJobOutcome {
    pub job_id: String,
    pub action: String,
    /// `completed` or `failed`.
    pub status: String,
    pub started_at: String,
    pub finished_at: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Privileged Runner IPC Models (`backend/services/privileged_runner.go`)
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
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub app_port: i32,
    /// Explicit destructive purge for `remove` only. The runner never inherits
    /// `DELETE_DATA` from its own environment; ordinary removals retain data.
    #[serde(skip_serializing_if = "is_false", default)]
    pub delete_data: bool,
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
    #[serde(skip_serializing_if = "is_false", default)]
    pub allow_overwrite: bool,
    #[serde(skip_serializing_if = "is_false", default)]
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

fn normalize_path_for_comparison(path: &std::path::Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    if raw.len() > 1 {
        raw.trim_end_matches('/').to_string()
    } else {
        raw
    }
}

pub fn normalize_lexical_path(
    path: &std::path::Path,
    label: &str,
) -> Result<std::path::PathBuf, String> {
    let raw_str = path.to_string_lossy();
    if raw_str.trim().is_empty() {
        return Err(format!("{} must not be empty", label));
    }
    if raw_str.contains('\0') {
        return Err(format!("{} contains NUL byte", label));
    }
    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(format!(
                    "{} '{}' must not contain parent traversal ('..')",
                    label,
                    path.display()
                ));
            }
            std::path::Component::Normal(segment) => {
                if segment.to_string_lossy() == ".." {
                    return Err(format!(
                        "{} '{}' must not contain parent traversal ('..')",
                        label,
                        path.display()
                    ));
                }
                normalized.push(segment);
            }
        }
    }
    Ok(normalized)
}

pub fn validate_path_within_isolated_root(
    candidate: &std::path::Path,
    isolated_root: &std::path::Path,
    label: &str,
) -> Result<std::path::PathBuf, String> {
    let norm_root = normalize_lexical_path(isolated_root, "isolated_root")?;
    if !norm_root.is_absolute() {
        return Err(format!(
            "isolated_root '{}' must be an absolute path",
            isolated_root.display()
        ));
    }
    let norm_candidate = normalize_lexical_path(candidate, label)?;
    if !norm_candidate.is_absolute() {
        return Err(format!(
            "{} '{}' must be an absolute path when isolated root '{}' is active",
            label,
            candidate.display(),
            norm_root.display()
        ));
    }
    if !norm_candidate.starts_with(&norm_root) || norm_candidate == norm_root {
        return Err(format!(
            "{} '{}' is outside active isolated root '{}'",
            label,
            candidate.display(),
            norm_root.display()
        ));
    }
    Ok(norm_candidate)
}

fn unescape_env_file_value(raw_val: &str) -> String {
    let trimmed = raw_val.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        let quote_char = trimmed.chars().next().unwrap_or('"');
        let inner = &trimmed[1..trimmed.len() - 1];
        if quote_char == '\'' {
            return inner.to_string();
        }
        let mut decoded = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('n') => decoded.push('\n'),
                    Some('r') => decoded.push('\r'),
                    Some('t') => decoded.push('\t'),
                    Some('\\') => decoded.push('\\'),
                    Some('"') => decoded.push('"'),
                    Some('$') => decoded.push('$'),
                    Some('`') => decoded.push('`'),
                    Some(other_ch) => {
                        decoded.push('\\');
                        decoded.push(other_ch);
                    }
                    None => decoded.push('\\'),
                }
            } else {
                decoded.push(ch);
            }
        }
        return decoded;
    }
    trimmed.to_string()
}

pub fn parse_key_value_env_str(contents: &str) -> HashMap<String, String> {
    let mut parsed_map = HashMap::new();
    for raw_line in contents.lines() {
        let trimmed_line = raw_line.trim();
        if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
            continue;
        }
        let without_export = trimmed_line
            .strip_prefix("export ")
            .map(str::trim)
            .unwrap_or(trimmed_line);
        let Some((raw_key, raw_val)) = without_export.split_once('=') else {
            continue;
        };
        let key_name = raw_key.trim();
        if key_name.is_empty() {
            continue;
        }
        let value_str = unescape_env_file_value(raw_val);
        if !value_str.is_empty() {
            parsed_map.insert(key_name.to_string(), value_str);
        }
    }
    parsed_map
}

fn load_authoritative_env_fallback_map<F>(
    isolated_root: Option<&std::path::Path>,
    allow_host_etc_fallback: bool,
    get_env: &mut F,
) -> Result<HashMap<String, String>, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut combined = HashMap::new();
    let mut candidate_files: Vec<std::path::PathBuf> = Vec::new();

    if let Some(root_path) = isolated_root {
        candidate_files.push(root_path.join("etc/aetherflow/release-manager.conf"));
        candidate_files.push(root_path.join("etc/aetherflow/aetherflow.env"));
        candidate_files.push(root_path.join("etc/AetherFlow/.env"));
    } else if allow_host_etc_fallback {
        candidate_files.push(std::path::PathBuf::from(
            "/etc/aetherflow/release-manager.conf",
        ));
        candidate_files.push(std::path::PathBuf::from("/etc/aetherflow/aetherflow.env"));
    }

    if let Some(explicit_env_file) = get_env("AETHERFLOW_ENV_FILE") {
        let trimmed_file = explicit_env_file.trim();
        if !trimmed_file.is_empty() {
            let env_file_path = std::path::PathBuf::from(trimmed_file);
            if let Some(root_path) = isolated_root {
                validate_path_within_isolated_root(&env_file_path, root_path, "AETHERFLOW_ENV_FILE")?;
            }
            candidate_files.push(env_file_path);
        }
    }

    for file_path in candidate_files {
        if let Ok(meta) = std::fs::symlink_metadata(&file_path) {
            if meta.file_type().is_file() {
                if let Ok(contents) = std::fs::read_to_string(&file_path) {
                    for (entry_key, entry_val) in parse_key_value_env_str(&contents) {
                        combined.insert(entry_key, entry_val);
                    }
                }
            }
        }
    }

    Ok(combined)
}

pub fn try_resolve_isolated_root_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    mut get_env: F,
) -> Result<Option<std::path::PathBuf>, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut roots: Vec<(&str, std::path::PathBuf)> = Vec::new();
    if let Some(root) = explicit_root {
        if !root.as_os_str().is_empty() {
            let norm = normalize_lexical_path(root, "--root")?;
            roots.push(("--root", norm));
        }
    }
    for key in ["AETHERFLOW_BACKUP_ISOLATED_ROOT", "AETHERFLOW_RELEASE_ROOT"] {
        if let Some(val) = get_env(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                let norm = normalize_lexical_path(std::path::Path::new(trimmed), key)?;
                roots.push((key, norm));
            }
        }
    }
    if let Some((first_label, first_path)) = roots.first() {
        let first_norm = normalize_path_for_comparison(first_path);
        for (other_label, other_path) in roots.iter().skip(1) {
            let other_norm = normalize_path_for_comparison(other_path);
            if first_norm != other_norm {
                return Err(format!(
                    "conflicting isolated root overrides: {}='{}' vs {}='{}'",
                    first_label,
                    first_path.display(),
                    other_label,
                    other_path.display()
                ));
            }
        }
        return Ok(Some(first_path.clone()));
    }
    Ok(None)
}

fn try_resolve_active_db_path_internal<F>(
    explicit_root: Option<&std::path::Path>,
    default_fallback: &str,
    allow_host_etc_fallback: bool,
    mut get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let isolated_root = try_resolve_isolated_root_with_env(explicit_root, &mut get_env)?;
    let file_env_map = load_authoritative_env_fallback_map(
        isolated_root.as_deref(),
        allow_host_etc_fallback,
        &mut get_env,
    )?;

    let mut db_overrides: Vec<(&str, std::path::PathBuf)> = Vec::new();
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        if let Some(val) = get_env(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                db_overrides.push((key, std::path::PathBuf::from(trimmed)));
            }
        }
    }
    if db_overrides.is_empty() {
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            if let Some(val) = file_env_map.get(key) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    db_overrides.push((key, std::path::PathBuf::from(trimmed)));
                }
            }
        }
    }

    let configured_data_dir = get_env("DATA_DIR")
        .or_else(|| file_env_map.get("DATA_DIR").cloned())
        .map(|raw_dir| raw_dir.trim().to_string())
        .filter(|trimmed_dir| !trimmed_dir.is_empty());

    let custom_non_default_data_dir = configured_data_dir
        .as_deref()
        .filter(|dir_str| normalize_path_for_comparison(std::path::Path::new(dir_str)) != "/var/lib/aetherflow");

    let file_has_explicit_default_db = ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"]
        .iter()
        .any(|key| {
            file_env_map
                .get(*key)
                .map(|val| {
                    normalize_path_for_comparison(std::path::Path::new(val.trim()))
                        == "/var/lib/aetherflow/aetherflow.sqlite"
                })
                .unwrap_or(false)
        });

    if let Some((first_key, first_path)) = db_overrides.first() {
        let first_norm = normalize_path_for_comparison(first_path);
        for (other_key, other_path) in db_overrides.iter().skip(1) {
            let other_norm = normalize_path_for_comparison(other_path);
            if first_norm != other_norm {
                return Err(format!(
                    "conflicting database path overrides: {}='{}' vs {}='{}'",
                    first_key,
                    first_path.display(),
                    other_key,
                    other_path.display()
                ));
            }
        }
        let is_legacy_unit_default_db = first_norm == "/var/lib/aetherflow/aetherflow.sqlite"
            && *first_key != "AF_DB_PATH"
            && !file_has_explicit_default_db;
        if !(is_legacy_unit_default_db && custom_non_default_data_dir.is_some() && isolated_root.is_none()) {
            if let Some(ref root_path) = isolated_root {
                return validate_path_within_isolated_root(first_path, root_path, first_key);
            }
            return normalize_lexical_path(first_path, first_key);
        }
    }

    if let Some(ref root_path) = isolated_root {
        if let Some(custom_dir) = custom_non_default_data_dir {
            let candidate_db = std::path::Path::new(custom_dir).join("aetherflow.sqlite");
            return validate_path_within_isolated_root(&candidate_db, root_path, "DATA_DIR");
        }
        return Ok(root_path.join("var/lib/aetherflow/aetherflow.sqlite"));
    }

    if let Some(custom_dir) = custom_non_default_data_dir {
        let candidate_db = std::path::Path::new(custom_dir).join("aetherflow.sqlite");
        return normalize_lexical_path(&candidate_db, "DATA_DIR");
    }

    if let Some(state_dir) = get_env("STATE_DIRECTORY") {
        if let Some(first_dir) = state_dir
            .split(':')
            .map(str::trim)
            .find(|entry| !entry.is_empty())
        {
            return Ok(std::path::Path::new(first_dir).join("aetherflow.sqlite"));
        }
    }

    if let Some(ref data_dir) = configured_data_dir {
        return Ok(std::path::Path::new(data_dir).join("aetherflow.sqlite"));
    }

    Ok(std::path::PathBuf::from(default_fallback))
}

pub fn try_resolve_active_db_path_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    default_fallback: &str,
    get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    try_resolve_active_db_path_internal(explicit_root, default_fallback, false, get_env)
}

pub fn try_resolve_active_db_path_from_env(
    explicit_root: Option<&std::path::Path>,
    default_fallback: &str,
) -> Result<std::path::PathBuf, String> {
    let allow_host_etc = std::env::var("AETHERFLOW_DISABLE_HOST_ENV_FILE")
        .map(|val| val.trim() != "1")
        .unwrap_or(true);
    try_resolve_active_db_path_internal(explicit_root, default_fallback, allow_host_etc, |key| {
        std::env::var(key).ok()
    })
}

pub fn resolve_active_db_path_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    default_fallback: &str,
    mut get_env: F,
) -> std::path::PathBuf
where
    F: FnMut(&str) -> Option<String>,
{
    match try_resolve_active_db_path_with_env(explicit_root, default_fallback, &mut get_env) {
        Ok(resolved_path) => resolved_path,
        Err(_) => {
            if let Ok(Some(root_path)) =
                try_resolve_isolated_root_with_env(explicit_root, &mut get_env)
            {
                return root_path.join("var/lib/aetherflow/aetherflow.sqlite");
            }
            if let Some(root_path) = explicit_root.filter(|path_val| !path_val.as_os_str().is_empty())
            {
                return root_path.join("var/lib/aetherflow/aetherflow.sqlite");
            }
            std::path::PathBuf::from(default_fallback)
        }
    }
}

pub fn resolve_active_db_path_from_env(
    explicit_root: Option<&std::path::Path>,
    default_fallback: &str,
) -> std::path::PathBuf {
    match try_resolve_active_db_path_from_env(explicit_root, default_fallback) {
        Ok(resolved_path) => resolved_path,
        Err(_) => resolve_active_db_path_with_env(explicit_root, default_fallback, |key| {
            std::env::var(key).ok()
        }),
    }
}

fn try_resolve_active_backup_dir_internal<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    default_fallback: &str,
    allow_host_etc_fallback: bool,
    mut get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let isolated_root = try_resolve_isolated_root_with_env(explicit_root, &mut get_env)?;
    let file_env_map = load_authoritative_env_fallback_map(
        isolated_root.as_deref(),
        allow_host_etc_fallback,
        &mut get_env,
    )?;

    if let Some(val) = get_env("AETHERFLOW_BACKUP_DIR")
        .or_else(|| file_env_map.get("AETHERFLOW_BACKUP_DIR").cloned())
    {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            let candidate_dir = std::path::PathBuf::from(trimmed);
            if let Some(ref root_path) = isolated_root {
                return validate_path_within_isolated_root(
                    &candidate_dir,
                    root_path,
                    "AETHERFLOW_BACKUP_DIR",
                );
            }
            return normalize_lexical_path(&candidate_dir, "AETHERFLOW_BACKUP_DIR");
        }
    }

    if let Some(db_path) = active_db_path {
        if !db_path.as_os_str().is_empty() {
            if let Some(ref root_path) = isolated_root {
                validate_path_within_isolated_root(db_path, root_path, "active_db_path")?;
            }
            if let Some(parent) = db_path.parent() {
                if !parent.as_os_str().is_empty() {
                    let candidate_dir = parent.join("backups");
                    if let Some(ref root_path) = isolated_root {
                        return validate_path_within_isolated_root(
                            &candidate_dir,
                            root_path,
                            "backup_dir",
                        );
                    }
                    return Ok(candidate_dir);
                }
            }
        }
    }

    let resolved_db = try_resolve_active_db_path_internal(
        explicit_root,
        "",
        allow_host_etc_fallback,
        &mut get_env,
    )?;
    if !resolved_db.as_os_str().is_empty() {
        if let Some(parent) = resolved_db.parent() {
            if !parent.as_os_str().is_empty() {
                let candidate_dir = parent.join("backups");
                if let Some(ref root_path) = isolated_root {
                    return validate_path_within_isolated_root(
                        &candidate_dir,
                        root_path,
                        "backup_dir",
                    );
                }
                return Ok(candidate_dir);
            }
        }
    }

    if let Some(root_path) = isolated_root {
        return Ok(root_path.join("var/lib/aetherflow/backups"));
    }

    Ok(std::path::PathBuf::from(default_fallback))
}

pub fn try_resolve_active_backup_dir_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    default_fallback: &str,
    get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    try_resolve_active_backup_dir_internal(
        explicit_root,
        active_db_path,
        default_fallback,
        false,
        get_env,
    )
}

pub fn try_resolve_active_backup_dir_from_env(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    default_fallback: &str,
) -> Result<std::path::PathBuf, String> {
    let allow_host_etc = std::env::var("AETHERFLOW_DISABLE_HOST_ENV_FILE")
        .map(|val| val.trim() != "1")
        .unwrap_or(true);
    try_resolve_active_backup_dir_internal(
        explicit_root,
        active_db_path,
        default_fallback,
        allow_host_etc,
        |key| std::env::var(key).ok(),
    )
}

pub fn resolve_active_backup_dir_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    default_fallback: &str,
    mut get_env: F,
) -> std::path::PathBuf
where
    F: FnMut(&str) -> Option<String>,
{
    match try_resolve_active_backup_dir_with_env(
        explicit_root,
        active_db_path,
        default_fallback,
        &mut get_env,
    ) {
        Ok(resolved_dir) => resolved_dir,
        Err(_) => {
            if let Ok(Some(root_path)) =
                try_resolve_isolated_root_with_env(explicit_root, &mut get_env)
            {
                return root_path.join("var/lib/aetherflow/backups");
            }
            if let Some(root_path) = explicit_root.filter(|path_val| !path_val.as_os_str().is_empty())
            {
                return root_path.join("var/lib/aetherflow/backups");
            }
            std::path::PathBuf::from(default_fallback)
        }
    }
}

pub fn resolve_active_backup_dir_from_env(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    default_fallback: &str,
) -> std::path::PathBuf {
    match try_resolve_active_backup_dir_from_env(explicit_root, active_db_path, default_fallback) {
        Ok(resolved_dir) => resolved_dir,
        Err(_) => resolve_active_backup_dir_with_env(
            explicit_root,
            active_db_path,
            default_fallback,
            |key| std::env::var(key).ok(),
        ),
    }
}

fn map_default_lock_parent_to_shared_runtime_anchor(
    candidate_parent: &std::path::Path,
    isolated_root: Option<&std::path::Path>,
) -> std::path::PathBuf {
    let normalized_parent = normalize_path_for_comparison(candidate_parent);
    if isolated_root.is_none() && normalized_parent == "/var/lib/aetherflow" {
        return std::path::PathBuf::from("/run/aetherflow/.snapshot.lock");
    }
    if let Some(root_path) = isolated_root {
        let isolated_var_lib = root_path.join("var/lib/aetherflow");
        if normalize_path_for_comparison(&isolated_var_lib) == normalized_parent {
            let isolated_run_dir = root_path.join("run/aetherflow");
            let mut use_run_anchor = isolated_run_dir.exists();
            #[cfg(unix)]
            if !use_run_anchor {
                use std::os::unix::fs::MetadataExt;
                if let (Ok(root_meta), Ok(var_meta)) = (
                    std::fs::symlink_metadata(root_path),
                    std::fs::symlink_metadata(&isolated_var_lib),
                ) {
                    if root_meta.uid() == 0 && var_meta.uid() != 0 {
                        use_run_anchor = true;
                    }
                }
            }
            if use_run_anchor {
                return isolated_run_dir.join(".snapshot.lock");
            }
        }
    }
    candidate_parent.join(".snapshot.lock")
}

fn try_resolve_canonical_maintenance_lock_path_internal<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    fallback_dir: Option<&std::path::Path>,
    allow_host_etc_fallback: bool,
    mut get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    let isolated_root = try_resolve_isolated_root_with_env(explicit_root, &mut get_env)?;
    let file_env_map = load_authoritative_env_fallback_map(
        isolated_root.as_deref(),
        allow_host_etc_fallback,
        &mut get_env,
    )?;

    if let Some(val) = get_env("AETHERFLOW_MAINTENANCE_LOCK_PATH")
        .or_else(|| file_env_map.get("AETHERFLOW_MAINTENANCE_LOCK_PATH").cloned())
    {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            let candidate_lock = std::path::PathBuf::from(trimmed);
            if let Some(ref root_path) = isolated_root {
                return validate_path_within_isolated_root(
                    &candidate_lock,
                    root_path,
                    "AETHERFLOW_MAINTENANCE_LOCK_PATH",
                );
            }
            return normalize_lexical_path(&candidate_lock, "AETHERFLOW_MAINTENANCE_LOCK_PATH");
        }
    }

    if let Some(db_path) = active_db_path {
        if !db_path.as_os_str().is_empty() {
            if let Some(ref root_path) = isolated_root {
                validate_path_within_isolated_root(db_path, root_path, "active_db_path")?;
            }
            if let Some(parent) = db_path.parent() {
                if !parent.as_os_str().is_empty() {
                    let candidate_lock = map_default_lock_parent_to_shared_runtime_anchor(
                        parent,
                        isolated_root.as_deref(),
                    );
                    if let Some(ref root_path) = isolated_root {
                        return validate_path_within_isolated_root(
                            &candidate_lock,
                            root_path,
                            "maintenance_lock_path",
                        );
                    }
                    return Ok(candidate_lock);
                }
            }
        }
    }

    let resolved_db = try_resolve_active_db_path_internal(
        explicit_root,
        "",
        allow_host_etc_fallback,
        &mut get_env,
    )?;
    if !resolved_db.as_os_str().is_empty() {
        if let Some(parent) = resolved_db.parent() {
            if !parent.as_os_str().is_empty() {
                let candidate_lock = map_default_lock_parent_to_shared_runtime_anchor(
                    parent,
                    isolated_root.as_deref(),
                );
                if let Some(ref root_path) = isolated_root {
                    return validate_path_within_isolated_root(
                        &candidate_lock,
                        root_path,
                        "maintenance_lock_path",
                    );
                }
                return Ok(candidate_lock);
            }
        }
    }

    if let Some(ref root_path) = isolated_root {
        let isolated_var_lib = root_path.join("var/lib/aetherflow");
        return Ok(map_default_lock_parent_to_shared_runtime_anchor(
            &isolated_var_lib,
            Some(root_path),
        ));
    }

    if let Some(data_dir) = get_env("DATA_DIR").or_else(|| file_env_map.get("DATA_DIR").cloned()) {
        let trimmed = data_dir.trim();
        if !trimmed.is_empty() {
            return Ok(map_default_lock_parent_to_shared_runtime_anchor(
                std::path::Path::new(trimmed),
                None,
            ));
        }
    }

    if let Some(dir) = fallback_dir {
        if let Some(parent) = dir.parent() {
            if dir.file_name().and_then(|os_str| os_str.to_str()) == Some("backups")
                && !parent.as_os_str().is_empty()
            {
                return Ok(map_default_lock_parent_to_shared_runtime_anchor(
                    parent,
                    None,
                ));
            }
        }
        return Ok(map_default_lock_parent_to_shared_runtime_anchor(dir, None));
    }

    Ok(std::path::PathBuf::from("/run/aetherflow/.snapshot.lock"))
}

pub fn try_resolve_trusted_sqlite_ids_from_env(
    explicit_root: Option<&std::path::Path>,
) -> Result<(Option<u32>, Option<u32>), String> {
    let allow_host_etc = std::env::var("AETHERFLOW_DISABLE_HOST_ENV_FILE")
        .map(|val| val.trim() != "1")
        .unwrap_or(true);
    let mut get_env = |key: &str| std::env::var(key).ok();
    let isolated_root = try_resolve_isolated_root_with_env(explicit_root, &mut get_env)?;
    let file_env_map = load_authoritative_env_fallback_map(
        isolated_root.as_deref(),
        allow_host_etc,
        &mut get_env,
    )?;

    let parse_optional_u32 = |keys: &[&str], label: &str| -> Result<Option<u32>, String> {
        for key in keys {
            let raw_opt = get_env(key).or_else(|| file_env_map.get(*key).cloned());
            if let Some(raw_val) = raw_opt {
                let trimmed = raw_val.trim();
                if !trimmed.is_empty() {
                    let parsed = trimmed
                        .parse::<u32>()
                        .map_err(|_| format!("invalid numeric {} '{}'", label, trimmed))?;
                    return Ok(Some(parsed));
                }
            }
        }
        Ok(None)
    };

    let uid_opt = parse_optional_u32(
        &["AETHERFLOW_TRUSTED_SQLITE_UID", "AETHERFLOW_SQLITE_UID"],
        "trusted_sqlite_uid",
    )?;
    let gid_opt = parse_optional_u32(
        &["AETHERFLOW_TRUSTED_SQLITE_GID", "AETHERFLOW_SQLITE_GID"],
        "trusted_sqlite_gid",
    )?;
    Ok((uid_opt, gid_opt))
}

pub fn resolve_trusted_sqlite_ids_from_env(
    explicit_root: Option<&std::path::Path>,
) -> (Option<u32>, Option<u32>) {
    try_resolve_trusted_sqlite_ids_from_env(explicit_root).unwrap_or((None, None))
}

pub fn try_resolve_canonical_maintenance_lock_path_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    fallback_dir: Option<&std::path::Path>,
    get_env: F,
) -> Result<std::path::PathBuf, String>
where
    F: FnMut(&str) -> Option<String>,
{
    try_resolve_canonical_maintenance_lock_path_internal(
        explicit_root,
        active_db_path,
        fallback_dir,
        false,
        get_env,
    )
}

pub fn try_resolve_canonical_maintenance_lock_path_from_env(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    fallback_dir: Option<&std::path::Path>,
) -> Result<std::path::PathBuf, String> {
    let allow_host_etc = std::env::var("AETHERFLOW_DISABLE_HOST_ENV_FILE")
        .map(|val| val.trim() != "1")
        .unwrap_or(true);
    try_resolve_canonical_maintenance_lock_path_internal(
        explicit_root,
        active_db_path,
        fallback_dir,
        allow_host_etc,
        |key| std::env::var(key).ok(),
    )
}

pub fn resolve_canonical_maintenance_lock_path_with_env<F>(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    fallback_dir: Option<&std::path::Path>,
    mut get_env: F,
) -> std::path::PathBuf
where
    F: FnMut(&str) -> Option<String>,
{
    match try_resolve_canonical_maintenance_lock_path_with_env(
        explicit_root,
        active_db_path,
        fallback_dir,
        &mut get_env,
    ) {
        Ok(resolved_lock) => resolved_lock,
        Err(_) => {
            if let Ok(Some(root_path)) =
                try_resolve_isolated_root_with_env(explicit_root, &mut get_env)
            {
                let isolated_var_lib = root_path.join("var/lib/aetherflow");
                return map_default_lock_parent_to_shared_runtime_anchor(
                    &isolated_var_lib,
                    Some(&root_path),
                );
            }
            if let Some(root_path) = explicit_root.filter(|path_val| !path_val.as_os_str().is_empty())
            {
                let isolated_var_lib = root_path.join("var/lib/aetherflow");
                return map_default_lock_parent_to_shared_runtime_anchor(
                    &isolated_var_lib,
                    Some(root_path),
                );
            }
            std::path::PathBuf::from("/run/aetherflow/.snapshot.lock")
        }
    }
}

pub fn resolve_canonical_maintenance_lock_path_from_env(
    explicit_root: Option<&std::path::Path>,
    active_db_path: Option<&std::path::Path>,
    fallback_dir: Option<&std::path::Path>,
) -> std::path::PathBuf {
    match try_resolve_canonical_maintenance_lock_path_from_env(
        explicit_root,
        active_db_path,
        fallback_dir,
    ) {
        Ok(resolved_lock) => resolved_lock,
        Err(_) => resolve_canonical_maintenance_lock_path_with_env(
            explicit_root,
            active_db_path,
            fallback_dir,
            |key| std::env::var(key).ok(),
        ),
    }
}

pub fn derive_sqlite_target_rel_path(
    target_root: &std::path::Path,
    configured_db_path: &std::path::Path,
) -> Option<String> {
    if configured_db_path.as_os_str().is_empty() {
        return None;
    }
    let norm_root = normalize_lexical_path(target_root, "target_root").ok()?;
    let norm_db = normalize_lexical_path(configured_db_path, "configured_db_path").ok()?;
    if let Ok(stripped) = norm_db.strip_prefix(&norm_root) {
        let rel = stripped
            .to_string_lossy()
            .replace('\\', "/")
            .trim_start_matches('/')
            .to_string();
        if !rel.is_empty() {
            return Some(rel);
        }
    }
    let root_norm = normalize_path_for_comparison(&norm_root);
    if root_norm == "/" {
        let rel = norm_db
            .to_string_lossy()
            .replace('\\', "/")
            .trim_start_matches('/')
            .to_string();
        if !rel.is_empty() {
            return Some(rel);
        }
    }
    if let Some(parent) = norm_db.parent() {
        if normalize_path_for_comparison(parent) == root_norm {
            if let Some(name) = norm_db.file_name().and_then(|os_name| os_name.to_str()) {
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

pub fn resolve_contained_sqlite_restore_override(
    target_root: &std::path::Path,
    configured_db_path: Option<&std::path::Path>,
) -> Option<std::path::PathBuf> {
    let db_path = configured_db_path?;
    if db_path.as_os_str().is_empty() {
        return None;
    }
    let norm_root = normalize_lexical_path(target_root, "target_root").ok()?;
    let norm_db = normalize_lexical_path(db_path, "configured_db_path").ok()?;
    if !norm_root.is_absolute() || !norm_db.is_absolute() {
        return None;
    }
    if normalize_path_for_comparison(&norm_root) == "/" {
        return Some(norm_db);
    }
    if norm_db.starts_with(&norm_root) && norm_db != norm_root {
        return Some(norm_db);
    }
    None
}

fn is_zero_i32(val: &i32) -> bool {
    *val == 0
}

fn is_false(val: &bool) -> bool {
    !*val
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_metrics_wire_format() {
        let mut mem = HashMap::new();
        mem.insert("total".to_string(), 32.0);
        mem.insert("used".to_string(), 8.5);
        let metrics = SystemMetrics {
            cpu_usage: 14.2,
            per_core_cpu: vec![12.0, 16.4],
            cpu_freq_mhz: 3600.0,
            memory: mem,
            uptime: "4d 2h 15m".to_string(),
            load_average: vec![0.42, 0.38, 0.31],
            gpus: vec![GpuMetric {
                index: 0,
                name: "NVIDIA RTX 4090".to_string(),
                usage_pct: 45.0,
                memory_total: 24576.0,
                memory_used: 4096.0,
                temp: 58.0,
            }],
            ..Default::default()
        };

        let json = serde_json::to_value(&metrics).unwrap();
        assert_eq!(json["cpu_usage"], 14.2);
        assert_eq!(json["gpus"][0]["name"], "NVIDIA RTX 4090");
        assert_eq!(json["gpus"][0]["usage_pct"], 45.0);
    }

    #[test]
    fn test_user_wire_format_omits_google_id() {
        let user_item = User {
            id: 1,
            username: "admin".to_string(),
            email: "admin@aether.local".to_string(),
            avatar_url: "".to_string(),
            role: "admin".to_string(),
            google_id: "secret-google-sub".to_string(),
            is_oauth: true,
            totp_enabled: false,
        };
        let serialized = serde_json::to_string(&user_item).unwrap();
        assert!(!serialized.contains("secret-google-sub"));
        assert!(serialized.contains("\"is_oauth\":true"));
    }

    #[test]
    fn test_unified_db_backup_and_lock_path_resolution() {
        let mut env = HashMap::new();
        env.insert("DB_PATH".to_string(), "/srv/custom/legacy.sqlite".to_string());
        let db = try_resolve_active_db_path_with_env(None, "data/aetherflow.sqlite", |key| {
            env.get(key).cloned()
        })
        .unwrap();
        assert_eq!(db, std::path::PathBuf::from("/srv/custom/legacy.sqlite"));

        let backup_dir = resolve_active_backup_dir_with_env(
            None,
            Some(&db),
            "data/backups",
            |key| env.get(key).cloned(),
        );
        assert_eq!(backup_dir, std::path::PathBuf::from("/srv/custom/backups"));

        let lock_path = resolve_canonical_maintenance_lock_path_with_env(
            None,
            Some(&db),
            Some(&backup_dir),
            |key| env.get(key).cloned(),
        );
        assert_eq!(
            lock_path,
            std::path::PathBuf::from("/srv/custom/.snapshot.lock")
        );

        env.insert("AF_DB_PATH".to_string(), "/srv/other/db.sqlite".to_string());
        let conflict = try_resolve_active_db_path_with_env(None, "data/aetherflow.sqlite", |key| {
            env.get(key).cloned()
        });
        assert!(conflict.is_err());

        env.insert("AF_DB_PATH".to_string(), "/srv/custom/legacy.sqlite".to_string());
        let resolved_same =
            try_resolve_active_db_path_with_env(None, "data/aetherflow.sqlite", |key| {
                env.get(key).cloned()
            })
            .unwrap();
        assert_eq!(
            resolved_same,
            std::path::PathBuf::from("/srv/custom/legacy.sqlite")
        );
    }

    #[test]
    fn test_isolated_root_rejects_out_of_root_db_backup_and_lock_overrides() {
        let iso_root = std::path::Path::new("/tmp/af-iso-root");
        let mut env = HashMap::new();
        env.insert(
            "AETHERFLOW_DB_PATH".to_string(),
            "/var/lib/aetherflow/host.sqlite".to_string(),
        );
        let out_of_root_db =
            try_resolve_active_db_path_with_env(Some(iso_root), "data/aetherflow.sqlite", |key| {
                env.get(key).cloned()
            });
        assert!(out_of_root_db.is_err());

        env.insert(
            "AETHERFLOW_DB_PATH".to_string(),
            "/tmp/af-iso-root/custom/inside.sqlite".to_string(),
        );
        let inside_db =
            try_resolve_active_db_path_with_env(Some(iso_root), "data/aetherflow.sqlite", |key| {
                env.get(key).cloned()
            })
            .unwrap();
        assert_eq!(
            inside_db,
            std::path::PathBuf::from("/tmp/af-iso-root/custom/inside.sqlite")
        );

        env.insert(
            "AETHERFLOW_BACKUP_DIR".to_string(),
            "/var/lib/aetherflow/backups".to_string(),
        );
        let out_of_root_backup = try_resolve_active_backup_dir_with_env(
            Some(iso_root),
            Some(&inside_db),
            "data/backups",
            |key| env.get(key).cloned(),
        );
        assert!(out_of_root_backup.is_err());

        env.remove("AETHERFLOW_BACKUP_DIR");
        env.insert(
            "AETHERFLOW_MAINTENANCE_LOCK_PATH".to_string(),
            "/tmp/.snapshot.lock".to_string(),
        );
        let out_of_root_lock = try_resolve_canonical_maintenance_lock_path_with_env(
            Some(iso_root),
            Some(&inside_db),
            None,
            |key| env.get(key).cloned(),
        );
        assert!(out_of_root_lock.is_err());
    }

    #[test]
    fn test_resolve_contained_sqlite_restore_override() {
        let custom_db = std::path::Path::new("/srv/af/live.sqlite");
        assert_eq!(
            resolve_contained_sqlite_restore_override(
                std::path::Path::new("/srv/af"),
                Some(custom_db)
            ),
            Some(std::path::PathBuf::from("/srv/af/live.sqlite"))
        );
        assert_eq!(
            resolve_contained_sqlite_restore_override(
                std::path::Path::new("/"),
                Some(custom_db)
            ),
            Some(std::path::PathBuf::from("/srv/af/live.sqlite"))
        );
        assert_eq!(
            resolve_contained_sqlite_restore_override(
                std::path::Path::new("/var/tmp/unrelated-staging"),
                Some(custom_db)
            ),
            None
        );
    }

    #[test]
    fn test_self_update_job_status_invariants() {
        let valid_unit = "aetherflow-self-update-0123456789abcdef0123456789abcdef.service";
        let ok_running = SelfUpdateJobStatus {
            status: "running".to_string(),
            completed: false,
            success: false,
            job_unit: valid_unit.to_string(),
            error: String::new(),
            exit_code: None,
        };
        assert!(ok_running.validate_invariants(Some(valid_unit)).is_ok());
        assert!(ok_running
            .validate_invariants(Some(
                "aetherflow-self-update-fedcba9876543210fedcba9876543210.service"
            ))
            .is_err());

        let bad_completed = SelfUpdateJobStatus {
            status: "running".to_string(),
            completed: true,
            success: true,
            job_unit: valid_unit.to_string(),
            error: String::new(),
            exit_code: Some(0),
        };
        assert!(bad_completed.validate_invariants(Some(valid_unit)).is_err());

        let bad_failed_zero = SelfUpdateJobStatus {
            status: "failed".to_string(),
            completed: true,
            success: false,
            job_unit: valid_unit.to_string(),
            error: "boom".to_string(),
            exit_code: Some(0),
        };
        assert!(bad_failed_zero.validate_invariants(Some(valid_unit)).is_err());
    }

    #[test]
    fn test_derive_sqlite_target_rel_path() {
        assert_eq!(
            derive_sqlite_target_rel_path(
                std::path::Path::new("/tmp/restore-root"),
                std::path::Path::new("/tmp/restore-root/custom/legacy.sqlite")
            ),
            Some("custom/legacy.sqlite".to_string())
        );
        assert_eq!(
            derive_sqlite_target_rel_path(
                std::path::Path::new("/"),
                std::path::Path::new("/opt/AetherFlow/data/aetherflow.sqlite")
            ),
            Some("opt/AetherFlow/data/aetherflow.sqlite".to_string())
        );
    }
    #[test]
    fn test_marketplace_tls_false_is_explicit_on_wire() {
        let app = MarketplaceApp {
            tls_enabled: false,
            ..Default::default()
        };
        let value = serde_json::to_value(app).unwrap();
        assert_eq!(value["tls_enabled"], false);
    }
}
