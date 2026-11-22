use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Data Structures
// ─────────────────────────────────────────────────────────────────────────────

/// Static hardware/OS summary sent by a worker during registration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkerSystemInfo {
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub cpu_cores: i32,
    #[serde(default)]
    pub total_memory_bytes: i64,
    #[serde(default)]
    pub total_disk_bytes: i64,
}

/// Service status item reported by a worker node.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkerService {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub uptime: String,
    #[serde(default)]
    pub managed_by: String,
}

/// Command queued on the master for delivery to a worker on its next heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingWorkerCommand {
    pub id: String,
    #[serde(rename = "type")]
    pub cmd_type: String,
    #[serde(default)]
    pub params: HashMap<String, String>,
    #[serde(default)]
    pub lease_generation: i64,
}

/// Durable SQLite representation of a cluster worker command (`cluster_commands`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterCommandRecord {
    pub id: String,
    pub node_id: String,
    pub cmd_type: String,
    pub target: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leased_until: Option<i64>,
    #[serde(default)]
    pub lease_generation: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Terminal command execution report sent by a worker node on heartbeat or `/cluster/v1/commands/ack`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerCommandAck {
    pub id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_generation: Option<i64>,
}

/// Payload accepted by `/cluster/v1/commands/ack`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkerCommandAckRequest {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub psk: String,
    #[serde(default)]
    pub acks: Vec<WorkerCommandAck>,
}

/// Payload accepted by `/cluster/v1/register`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegisterWorkerRequest {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub psk: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub system_info: Option<WorkerSystemInfo>,
}

/// Response returned by `/cluster/v1/register`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterWorkerResponse {
    pub node_id: String,
    pub accepted: bool,
    pub message: String,
}

/// Payload accepted by `/cluster/v1/heartbeat`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkerHeartbeatRequest {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub psk: String,
    #[serde(default)]
    pub timestamp: i64,
    #[serde(default)]
    pub cpu_usage: Option<f64>,
    #[serde(default)]
    pub ram_usage: Option<f64>,
    #[serde(default)]
    pub disk_usage: Option<f64>,
    #[serde(default)]
    pub metrics: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<WorkerService>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services_observed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services_error: Option<String>,
    #[serde(default)]
    pub system_info: Option<WorkerSystemInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command_acks: Vec<WorkerCommandAck>,
}

/// Response returned by `/cluster/v1/heartbeat`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHeartbeatResponse {
    pub timestamp: i64,
    pub acknowledged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<PendingWorkerCommand>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confirmed_command_ids: Vec<String>,
}
