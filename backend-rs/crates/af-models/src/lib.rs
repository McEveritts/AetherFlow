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
}

// ─────────────────────────────────────────────────────────────────────────────
// Privileged Runner IPC Models (`backend/services/privileged_runner.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SystemctlRequest {
    pub service: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PackageRunnerRequest {
    pub action: String,
    pub package_id: String,
    pub script_name: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub app_port: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SelfUpdateRequest {
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub channel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SandboxRunnerRequest {
    #[serde(default)]
    pub package: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub package_id: String,
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
pub struct RunnerResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub output: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error: String,
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
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
        let u = User {
            id: 1,
            username: "admin".to_string(),
            email: "admin@aether.local".to_string(),
            avatar_url: "".to_string(),
            role: "admin".to_string(),
            google_id: "secret-google-sub".to_string(),
            is_oauth: true,
            totp_enabled: false,
        };
        let s = serde_json::to_string(&u).unwrap();
        assert!(!s.contains("secret-google-sub"));
        assert!(s.contains("\"is_oauth\":true"));
    }
}
