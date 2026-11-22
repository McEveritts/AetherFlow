use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Hardware & System Telemetry Models
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
    #[serde(default, skip_serializing_if = "is_zero_bank_count")]
    pub banks: i32,
    #[serde(rename = "type")]
    pub mem_type: String,
}

fn is_zero_bank_count(count: &i32) -> bool {
    *count == 0
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
// User, Session & Ingress Models
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppRuntimeMeta {
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub configured_port: i32,
    #[serde(default, skip_serializing_if = "crate::is_zero_i32")]
    pub secondary_port: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url_base: String,
}
