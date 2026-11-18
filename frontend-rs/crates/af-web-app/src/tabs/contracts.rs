//! Typed compatibility boundary for partial snapshots and versioned domain APIs.
//! Unknown fields survive round trips; presentation grids alone use JSON rows.
use af_web_core::models::{DiskPartition, HardwareReport, SystemMetrics};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

mod read;
pub use read::*;

pub fn decode<T: DeserializeOwned + Default>(value: &Value) -> T {
    serde_json::from_value(value.clone()).unwrap_or_default()
}
pub fn rows<T: DeserializeOwned>(value: &Value) -> Vec<T> {
    crate::state::json_rows(value)
        .into_iter()
        .filter_map(|row| serde_json::from_value(row).ok())
        .collect()
}
pub fn grid_rows<T: DeserializeOwned + Serialize>(value: &Value) -> Vec<Value> {
    rows::<T>(value)
        .into_iter()
        .filter_map(|row| serde_json::to_value(row).ok())
        .collect()
}
pub fn number<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<f64>, D::Error> {
    let value = Value::deserialize(deserializer)?;
    Ok(value
        .as_f64()
        .or_else(|| value.as_str()?.parse().ok())
        .filter(|n| n.is_finite()))
}
/// Preserve integer counters while accepting older APIs' float/string encodings.
pub fn integer_opt<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i64>, D::Error> {
    fn from_float(value: f64) -> Option<i64> {
        // The upper bound is exclusive: i64::MAX rounds up to 2^63 as f64.
        (value.is_finite()
            && value.fract() == 0.0
            && value >= i64::MIN as f64
            && value < -(i64::MIN as f64))
            .then_some(value as i64)
    }
    let value = Value::deserialize(deserializer)?;
    Ok(match value {
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                Some(value)
            } else if let Some(value) = number.as_u64() {
                i64::try_from(value).ok()
            } else {
                number.as_f64().and_then(from_float)
            }
        }
        Value::String(value) => {
            let value = value.trim();
            value.parse::<i64>().ok().or_else(|| {
                // Out-of-range integer strings must not round into range as f64.
                let digits = value.trim_start_matches(['+', '-']);
                if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                value.parse::<f64>().ok().and_then(from_float)
            })
        }
        _ => None,
    })
}
pub fn counters<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Option<f64>>, D::Error> {
    let values = Option::<BTreeMap<String, Value>>::deserialize(deserializer)?.unwrap_or_default();
    Ok(values
        .into_iter()
        .map(|(key, value)| {
            (
                key,
                value
                    .as_f64()
                    .or_else(|| value.as_str()?.parse().ok())
                    .filter(|n| n.is_finite()),
            )
        })
        .collect())
}
pub fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    deserializer: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}
pub fn boolean<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    let value = Value::deserialize(deserializer)?;
    Ok(value == true || value == 1 || value == "true")
}
pub fn string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Ok(match Value::deserialize(deserializer)? {
        Value::String(s) => s,
        Value::Null => String::new(),
        v => v.to_string(),
    })
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DiskTelemetry {
    #[serde(alias = "mount", alias = "path", alias = "mountPoint")]
    pub mount_point: String,
    pub device: String,
    #[serde(alias = "filesystem", alias = "fsType")]
    pub fs_type: String,
    #[serde(deserialize_with = "number", alias = "totalGb")]
    pub total_gb: Option<f64>,
    #[serde(deserialize_with = "number", alias = "usedGb")]
    pub used_gb: Option<f64>,
    #[serde(deserialize_with = "number", alias = "freeGb")]
    pub free_gb: Option<f64>,
    #[serde(deserialize_with = "number", alias = "usage_pct", alias = "usedPct")]
    pub used_pct: Option<f64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl DiskTelemetry {
    pub fn partition(&self) -> DiskPartition {
        DiskPartition {
            mount_point: self.mount_point.clone(),
            device: self.device.clone(),
            fs_type: self.fs_type.clone(),
            total_gb: self.total_gb.unwrap_or_default(),
            used_gb: self.used_gb.unwrap_or_default(),
            free_gb: self.free_gb.unwrap_or_default(),
            used_pct: self.used_pct.unwrap_or_default(),
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Telemetry {
    #[serde(deserialize_with = "number", alias = "cpu_avg")]
    pub cpu_usage: Option<f64>,
    pub per_core_cpu: Vec<f64>,
    pub cpu_freq_mhz: f64,
    pub memory: BTreeMap<String, f64>,
    pub swap: BTreeMap<String, f64>,
    pub disk_space: BTreeMap<String, f64>,
    #[serde(alias = "disk_partitions")]
    #[serde(deserialize_with = "nullable")]
    pub disks: Vec<DiskTelemetry>,
    pub disk_io: BTreeMap<String, Value>,
    pub network: BTreeMap<String, Value>,
    pub total_net_bytes: BTreeMap<String, u64>,
    pub uptime: String,
    pub load_average: Vec<f64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl Telemetry {
    pub fn metrics(&self) -> SystemMetrics {
        SystemMetrics {
            cpu_usage: self.cpu_usage.unwrap_or_default(),
            per_core_cpu: self.per_core_cpu.clone(),
            cpu_freq_mhz: self.cpu_freq_mhz,
            memory: self.memory.clone().into_iter().collect(),
            swap: self.swap.clone().into_iter().collect(),
            disk_space: self.disk_space.clone().into_iter().collect(),
            disks: self.disks.iter().map(DiskTelemetry::partition).collect(),
            uptime: self.uptime.clone(),
            load_average: self.load_average.clone(),
            network: self.network.clone().into_iter().collect(),
            total_net_bytes: self.total_net_bytes.clone().into_iter().collect(),
            ..Default::default()
        }
    }
}
/// Fill absent fields before deserializing a shared model, including nested
/// hardware records. Explicit server values always win over defaults.
pub fn shared_model<T: DeserializeOwned + Serialize + Default>(value: &Value) -> Option<T> {
    fn merge(target: &mut Value, source: &Value) {
        if let (Value::Object(target), Value::Object(source)) = (&mut *target, source) {
            for (key, value) in source {
                if let Some(previous) = target.get_mut(key) {
                    merge(previous, value);
                } else {
                    target.insert(key.clone(), value.clone());
                }
            }
        } else {
            *target = source.clone();
        }
    }
    let mut baseline = serde_json::to_value(T::default()).ok()?;
    merge(&mut baseline, value);
    serde_json::from_value(baseline).ok()
}
pub fn hardware(value: &Value) -> HardwareReport {
    let mut normalized = value.clone();
    for key in ["cpu", "memory"] {
        if let Some(fields) = normalized.get_mut(key).and_then(Value::as_object_mut) {
            let defaults = if key == "cpu" {
                serde_json::to_value(af_web_core::models::CpuInfo::default())
            } else {
                serde_json::to_value(af_web_core::models::MemoryInfo::default())
            }
            .unwrap_or_default();
            if let Some(defaults) = defaults.as_object() {
                for (field, value) in defaults {
                    fields.entry(field).or_insert_with(|| value.clone());
                }
            }
        }
    }
    if let Some(banks) = normalized.pointer_mut("/memory/banks") {
        if let Some(items) = banks.as_array() {
            *banks = serde_json::json!(items.len());
        }
    }
    // Hardware peripherals are partial on older hosts as well.
    for (key, default) in [
        (
            "storage",
            serde_json::to_value(af_web_core::models::StorageInfo::default()).unwrap_or_default(),
        ),
        (
            "network",
            serde_json::to_value(af_web_core::models::NetworkInfo::default()).unwrap_or_default(),
        ),
        (
            "gpus",
            serde_json::to_value(af_web_core::models::GpuInfo::default()).unwrap_or_default(),
        ),
    ] {
        if let Some(items) = normalized.get_mut(key).and_then(Value::as_array_mut) {
            for item in items {
                let mut full = default.clone();
                if let (Some(target), Some(fields)) = (full.as_object_mut(), item.as_object()) {
                    target.extend(fields.clone());
                }
                *item = full;
            }
        }
    }
    shared_model(&normalized).unwrap_or_default()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct UserRecord {
    pub id: i64,
    pub username: String,
    pub email: String,
    #[serde(alias = "avatarUrl")]
    pub avatar_url: String,
    pub role: String,
    #[serde(alias = "isOauth", deserialize_with = "boolean")]
    pub is_oauth: bool,
    #[serde(alias = "totpEnabled", deserialize_with = "boolean")]
    pub totp_enabled: bool,
    pub google_id: String,
    #[serde(alias = "createdAt")]
    pub created_at: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl UserRecord {
    pub fn user(&self) -> af_web_core::models::User {
        af_web_core::models::User {
            id: self.id,
            username: self.username.clone(),
            email: self.email.clone(),
            avatar_url: self.avatar_url.clone(),
            role: self.role.clone(),
            is_oauth: self.is_oauth,
            totp_enabled: self.totp_enabled,
            ..Default::default()
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ClusterNode {
    #[serde(deserialize_with = "string")]
    pub id: String,
    pub hostname: String,
    pub address: String,
    pub role: String,
    pub status: String,
    pub version: String,
    #[serde(alias = "lastHeartbeat")]
    pub last_heartbeat: String,
    #[serde(deserialize_with = "counters")]
    pub metrics: BTreeMap<String, Option<f64>>,
    pub heartbeat_latency_ms: Option<f64>,
    pub mtls_verified: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AuditLog {
    pub id: i64,
    pub username: String,
    pub action: String,
    #[serde(alias = "targetType")]
    pub target_type: String,
    #[serde(alias = "targetId", deserialize_with = "string")]
    pub target_id: String,
    #[serde(deserialize_with = "string")]
    pub detail: String,
    #[serde(alias = "ipAddress")]
    pub ip_address: String,
    #[serde(alias = "createdAt")]
    pub created_at: String,
    pub severity: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct UserQuota {
    #[serde(alias = "userId")]
    pub user_id: i64,
    pub username: String,
    #[serde(alias = "quotaBytes", deserialize_with = "integer_opt")]
    pub quota_bytes: Option<i64>,
    #[serde(alias = "usedBytes", deserialize_with = "integer_opt")]
    pub used_bytes: Option<i64>,
    pub soft_limit_bytes: Option<f64>,
    pub configured: bool,
    pub status: String,
    pub source: String,
    pub grace_status: Option<String>,
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ActionApprovalRequest {
    pub id: i64,
    pub action: String,
    pub status: String,
    pub source: String,
    pub reason: String,
    #[serde(alias = "riskLevel")]
    pub risk_level: String,
    pub classification: String,
    pub created_at: String,
    pub target: Option<Value>,
    pub resource: Option<Value>,
    pub service: Option<Value>,
    pub targets: Option<Value>,
    pub payload: Value,
    pub parameters: Value,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ActionScope {
    pub target: Option<Value>,
    pub resource: Option<Value>,
    pub service: Option<Value>,
    pub targets: Option<Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct NotificationChannel {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub enabled: bool,
    pub config: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct NotificationRule {
    pub id: i64,
    pub name: String,
    #[serde(alias = "conditionType")]
    pub condition_type: String,
    #[serde(alias = "conditionValue", deserialize_with = "string")]
    pub condition_value: String,
    pub level: String,
    pub enabled: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SharePolicyRecord {
    #[serde(deserialize_with = "string")]
    pub id: String,
    pub path: String,
    pub url: Option<String>,
    #[serde(alias = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(alias = "passwordRequired")]
    pub password_required: bool,
    #[serde(alias = "allowDownload")]
    pub allow_download: bool,
    pub revoked: bool,
    pub download_count: u64,
    pub max_downloads: Option<u64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct NetworkStatus {
    pub runner_available: Option<bool>,
    pub platform: String,
    pub checked_at: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct WireGuardStatus {
    #[serde(deserialize_with = "string")]
    pub listen_port: String,
    #[serde(alias = "address")]
    pub addresses: AddressList,
    pub public_key: String,
    pub next_ip: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AddressList {
    List(Vec<String>),
    Text(String),
}
impl Default for AddressList {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}
impl AddressList {
    pub fn joined(&self) -> String {
        match self {
            Self::List(items) => items
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(", "),
            Self::Text(s) if s.trim() != "[]" => s.trim().into(),
            _ => String::new(),
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct IngressConfig {
    #[serde(alias = "app_name")]
    pub app_name: String,
    #[serde(alias = "public_domain")]
    pub public_domain: String,
    #[serde(alias = "external_access_enabled")]
    pub external_access_enabled: bool,
    #[serde(alias = "tls_enabled")]
    pub tls_enabled: bool,
    #[serde(alias = "listen_port")]
    pub listen_port: i32,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl IngressConfig {
    pub fn config(&self) -> af_web_core::models::AppIngressConfig {
        af_web_core::models::AppIngressConfig {
            app_name: self.app_name.clone(),
            public_domain: self.public_domain.clone(),
            external_access_enabled: self.external_access_enabled,
            tls_enabled: self.tls_enabled,
            listen_port: self.listen_port,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct McBrowserPolicy {
    pub scope: String,
    pub permissions: BTreeMap<String, bool>,
    pub rules: Vec<McBrowserRule>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct McBrowserRule {
    pub path: String,
    pub allow: bool,
    pub regex: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ShareCreatedEnvelope {
    pub share: SharePolicyRecord,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct TusUploadLookup {
    #[serde(alias = "id")]
    pub upload_id: String,
    pub offset: Option<u64>,
    pub length: Option<u64>,
    pub exists: Option<bool>,
    pub path: String,
    pub fingerprint: String,
    pub status: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct StreamingSummaryContract {
    #[serde(alias = "activeStreams", deserialize_with = "number")]
    pub active_sessions: Option<f64>,
    #[serde(alias = "directPlayCount", deserialize_with = "number")]
    pub direct_play: Option<f64>,
    #[serde(alias = "directStreamCount", deserialize_with = "number")]
    pub direct_stream: Option<f64>,
    #[serde(alias = "transcodeCount", deserialize_with = "number")]
    pub transcode: Option<f64>,
    #[serde(alias = "totalBandwidthMbps", deserialize_with = "number")]
    pub total_bandwidth_mbps: Option<f64>,
    #[serde(alias = "updatedAt")]
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct MediaFlowServiceContract {
    pub id: String,
    pub name: String,
    pub status: String,
    pub installed: Option<bool>,
    pub wired: Option<bool>,
    pub auto_configured: Option<bool>,
    pub api_key: Option<String>,
    #[serde(alias = "webUiUrl")]
    pub web_ui_url: Option<String>,
    pub public_url: Option<String>,
    pub url: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct MediaFlowLiveProgress {
    #[serde(deserialize_with = "string")]
    pub frame: String,
    #[serde(deserialize_with = "string")]
    pub fps: String,
    #[serde(deserialize_with = "string")]
    pub speed: String,
    #[serde(deserialize_with = "string")]
    pub time: String,
    #[serde(deserialize_with = "string")]
    pub size: String,
    #[serde(deserialize_with = "string")]
    pub bitrate: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct MediaFlowQueueRecord {
    pub status: String,
    #[serde(
        rename = "originalSize",
        alias = "original_size",
        deserialize_with = "number"
    )]
    pub original_size: Option<f64>,
    #[serde(rename = "newSize", alias = "new_size", deserialize_with = "number")]
    pub new_size: Option<f64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct MediaFlowQueueSummary {
    pub queued: usize,
    pub pending: usize,
    pub processing: usize,
    pub saved_bytes: f64,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl MediaFlowQueueSummary {
    pub fn from_jobs(jobs: &[Value]) -> Self {
        let jobs: Vec<MediaFlowQueueRecord> = jobs
            .iter()
            .filter_map(|job| serde_json::from_value(job.clone()).ok())
            .collect();
        Self {
            queued: jobs.len(),
            pending: jobs
                .iter()
                .filter(|job| job.status == "PENDING_APPROVAL")
                .count(),
            processing: jobs.iter().filter(|job| job.status == "PROCESSING").count(),
            saved_bytes: jobs
                .iter()
                .filter(|job| job.status == "COMPLETED")
                .map(|job| {
                    (job.original_size.unwrap_or_default() - job.new_size.unwrap_or_default())
                        .max(0.0)
                })
                .sum(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests;
