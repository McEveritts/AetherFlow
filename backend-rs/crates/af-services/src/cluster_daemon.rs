//! Cluster Master/Worker Heartbeat & Registration Daemon (`backend/cluster/cluster.go`, `server.go`, `client.go`).
//!
//! Provides:
//! - `start_cluster_runtime()`: Spawns the 30-second node health-sweep loop and, depending on
//!   `CLUSTER_MODE` (`"master"`, `"worker"`, or `"standalone"`), launches either the master
//!   TCP/HTTP JSON-RPC listener or the worker registration + 5-second telemetry heartbeat loop.
//! - `get_cached_worker_metrics(node_id)`: Returns the most recent rich telemetry snapshot
//!   pushed by a worker node if cached in memory.

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::env;
use std::sync::RwLock;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

// ─────────────────────────────────────────────────────────────────────────────
// Data Structures (`backend/cluster/cluster.go`)
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingWorkerCommand {
    pub id: String,
    #[serde(rename = "type")]
    pub cmd_type: String,
    #[serde(default)]
    pub params: HashMap<String, String>,
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
    #[serde(default)]
    pub services: Vec<WorkerService>,
    #[serde(default)]
    pub system_info: Option<WorkerSystemInfo>,
}

/// Response returned by `/cluster/v1/heartbeat`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHeartbeatResponse {
    pub timestamp: i64,
    pub acknowledged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<PendingWorkerCommand>,
}

// ─────────────────────────────────────────────────────────────────────────────
// In-Memory Telemetry & Command State
// ─────────────────────────────────────────────────────────────────────────────

static WORKER_METRICS_CACHE: Lazy<RwLock<HashMap<String, serde_json::Value>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

static WORKER_COMMAND_QUEUES: Lazy<RwLock<HashMap<String, VecDeque<PendingWorkerCommand>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Returns the most recent rich telemetry payload pushed by a worker node if cached in memory.
pub fn get_cached_worker_metrics(node_id: &str) -> Option<serde_json::Value> {
    WORKER_METRICS_CACHE.read().ok()?.get(node_id).cloned()
}

/// Stores or updates a worker node's telemetry snapshot in the in-memory cache.
pub fn cache_worker_metrics(node_id: &str, payload: serde_json::Value) {
    if let Ok(mut guard) = WORKER_METRICS_CACHE.write() {
        guard.insert(node_id.to_string(), payload);
    }
}

/// Removes a worker node's cached telemetry and pending commands from memory.
pub fn remove_cached_worker_metrics(node_id: &str) {
    if let Ok(mut guard) = WORKER_METRICS_CACHE.write() {
        guard.remove(node_id);
    }
    if let Ok(mut guard) = WORKER_COMMAND_QUEUES.write() {
        guard.remove(node_id);
    }
}

/// Queues a remote command for delivery to a worker node on its next heartbeat response.
pub fn queue_worker_command(node_id: &str, cmd: PendingWorkerCommand) -> bool {
    let Ok(mut guard) = WORKER_COMMAND_QUEUES.write() else {
        return false;
    };
    let q = guard.entry(node_id.to_string()).or_default();
    if q.len() >= 16 {
        return false;
    }
    q.push_back(cmd);
    true
}

/// Pops the next pending remote command for a worker node, if any.
pub fn pop_worker_command(node_id: &str) -> Option<PendingWorkerCommand> {
    WORKER_COMMAND_QUEUES
        .write()
        .ok()?
        .get_mut(node_id)?
        .pop_front()
}

// ─────────────────────────────────────────────────────────────────────────────
// Constant-Time PSK Verification & SQLite Schema Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Performs a constant-time byte slice equality check to prevent timing side-channels.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hash_psk_sha256(psk: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(psk.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Verifies a worker's pre-shared key against `CLUSTER_PSK` (if configured on the master)
/// or against a previously enrolled node's stored `psk_hash` using constant-time comparison.
pub fn verify_cluster_psk(node_id: &str, candidate_psk: &str) -> Result<(), &'static str> {
    let candidate = candidate_psk.trim();
    if candidate.is_empty() {
        return Err("psk is required");
    }

    if let Ok(master_psk) = env::var("CLUSTER_PSK") {
        let master_trimmed = master_psk.trim();
        if !master_trimmed.is_empty() {
            if constant_time_eq(candidate.as_bytes(), master_trimmed.as_bytes()) {
                return Ok(());
            }
            return Err("invalid cluster PSK");
        }
    }

    // Check if this node is already enrolled in `cluster_nodes` with a matching hash
    if !node_id.is_empty() {
        if let Ok(conn) = af_db::get_conn() {
            if let Ok(stored_hash) = conn.query_row(
                "SELECT COALESCE(psk_hash, '') FROM cluster_nodes WHERE id = ?1",
                params![node_id],
                |r| r.get::<_, String>(0),
            ) {
                if !stored_hash.is_empty() {
                    let candidate_hash = hash_psk_sha256(candidate);
                    if constant_time_eq(candidate_hash.as_bytes(), stored_hash.as_bytes())
                        || constant_time_eq(candidate.as_bytes(), stored_hash.as_bytes())
                    {
                        return Ok(());
                    }
                    return Err("invalid cluster PSK for enrolled node");
                }
            }
        }
    }

    // Match Go's `server.go`: require >= 32 chars when no explicit master `CLUSTER_PSK` override is set
    if candidate.len() < 32 {
        return Err("psk must be at least 32 characters for adequate security");
    }

    Ok(())
}

/// Ensures `cluster_nodes` has `last_seen`, `cpu_usage`, `ram_usage`, and `disk_usage` columns
/// alongside the core schema columns (`last_heartbeat`, `status`, etc.).
pub fn ensure_cluster_schema() {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let migrations = [
        "ALTER TABLE cluster_nodes ADD COLUMN last_seen DATETIME;",
        "ALTER TABLE cluster_nodes ADD COLUMN cpu_usage REAL DEFAULT 0.0;",
        "ALTER TABLE cluster_nodes ADD COLUMN ram_usage REAL DEFAULT 0.0;",
        "ALTER TABLE cluster_nodes ADD COLUMN disk_usage REAL DEFAULT 0.0;",
    ];
    for sql in migrations {
        let _ = conn.execute_batch(sql);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Master Node Registration, Heartbeat Processing & Health Sweep
// ─────────────────────────────────────────────────────────────────────────────

/// Sweeps `cluster_nodes` and marks any node whose `last_seen` (or `last_heartbeat`)
/// is older than 60 seconds as `status = 'offline'`. Returns the number of nodes marked offline.
pub fn sweep_stale_cluster_nodes() -> usize {
    ensure_cluster_schema();
    let Ok(conn) = af_db::get_conn() else {
        return 0;
    };

    let now = Utc::now();
    let mut stale_ids: Vec<(String, String)> = Vec::new();

    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, hostname, COALESCE(CAST(last_seen AS TEXT), ''), COALESCE(CAST(last_heartbeat AS TEXT), '') \
         FROM cluster_nodes WHERE status = 'online'",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        }) {
            for (id, hostname, last_seen, last_hb) in rows.flatten() {
                let ts_str = if !last_seen.trim().is_empty() {
                    last_seen.trim()
                } else {
                    last_hb.trim()
                };

                let is_stale = if ts_str.is_empty() {
                    true
                } else if let Ok(parsed) = DateTime::parse_from_rfc3339(ts_str) {
                    (now - parsed.with_timezone(&Utc)).num_seconds() > 60
                } else if let Ok(naive) =
                    chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%d %H:%M:%S")
                {
                    let dt = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
                    (now - dt).num_seconds() > 60
                } else {
                    false
                };

                if is_stale {
                    stale_ids.push((id, hostname));
                }
            }
        }
    }

    let mut marked = 0usize;
    for (id, hostname) in &stale_ids {
        if let Ok(n) = conn.execute(
            "UPDATE cluster_nodes SET status = 'offline' WHERE id = ?1 AND status != 'offline'",
            params![id],
        ) {
            if n > 0 {
                marked += n;
                tracing::warn!(node_id = %id, hostname = %hostname, "cluster worker went offline (heartbeat timeout > 60s)");
            }
        }
    }

    // Fallback SQLite native datetime sweep for any non-RFC3339 timestamps
    if let Ok(n) = conn.execute(
        "UPDATE cluster_nodes SET status = 'offline' \
         WHERE status = 'online' \
         AND datetime(COALESCE(NULLIF(CAST(last_seen AS TEXT), ''), CAST(last_heartbeat AS TEXT))) < datetime('now', '-60 seconds')",
        [],
    ) {
        marked += n;
    }

    marked
}

/// Validates and registers a worker node in `cluster_nodes` and initializes its in-memory state.
pub fn register_worker_node(req: &RegisterWorkerRequest) -> anyhow::Result<RegisterWorkerResponse> {
    let hostname = req.hostname.trim();
    let address = req.address.trim();
    let psk = req.psk.trim();

    if hostname.is_empty() || address.is_empty() || psk.is_empty() {
        return Ok(RegisterWorkerResponse {
            node_id: String::new(),
            accepted: false,
            message: "hostname, address, and psk are required".to_string(),
        });
    }

    let node_id = if !req.node_id.trim().is_empty() {
        req.node_id.trim().to_string()
    } else {
        format!("node-{}", hostname)
    };

    if let Err(msg) = verify_cluster_psk(&node_id, psk) {
        return Ok(RegisterWorkerResponse {
            node_id: String::new(),
            accepted: false,
            message: msg.to_string(),
        });
    }

    ensure_cluster_schema();
    let psk_hash = hash_psk_sha256(psk);
    let now_rfc3339 = Utc::now().to_rfc3339();

    if let Ok(conn) = af_db::get_conn() {
        conn.execute(
            "INSERT INTO cluster_nodes (id, hostname, address, psk_hash, role, status, last_heartbeat, last_seen, enrolled_at) \
             VALUES (?1, ?2, ?3, ?4, 'worker', 'online', ?5, ?5, ?5) \
             ON CONFLICT(id) DO UPDATE SET \
                 hostname = excluded.hostname, \
                 address = excluded.address, \
                 psk_hash = excluded.psk_hash, \
                 role = 'worker', \
                 status = 'online', \
                 last_heartbeat = excluded.last_heartbeat, \
                 last_seen = excluded.last_seen",
            params![node_id, hostname, address, psk_hash, now_rfc3339],
        )?;
    }

    let version = if req.version.trim().is_empty() {
        "4.0.0-rc1"
    } else {
        req.version.trim()
    };

    let existing = get_cached_worker_metrics(&node_id);
    let initial_snapshot = serde_json::json!({
        "node_id": node_id,
        "hostname": hostname,
        "address": address,
        "version": version,
        "status": "online",
        "last_seen": now_rfc3339,
        "last_heartbeat": now_rfc3339,
        "cpu_usage": existing.as_ref().and_then(|v| v.get("cpu_usage")).and_then(|v| v.as_f64()).unwrap_or(0.0),
        "ram_usage": existing.as_ref().and_then(|v| v.get("ram_usage")).and_then(|v| v.as_f64()).unwrap_or(0.0),
        "disk_usage": existing.as_ref().and_then(|v| v.get("disk_usage")).and_then(|v| v.as_f64()).unwrap_or(0.0),
        "metrics": existing.as_ref().and_then(|v| v.get("metrics")).cloned().unwrap_or(serde_json::Value::Null),
        "services": existing.as_ref().and_then(|v| v.get("services")).cloned().unwrap_or_else(|| serde_json::json!([])),
        "system_info": req.system_info,
    });
    cache_worker_metrics(&node_id, initial_snapshot);

    tracing::info!(
        node_id = %node_id,
        hostname = %hostname,
        address = %address,
        "cluster worker enrolled"
    );

    Ok(RegisterWorkerResponse {
        node_id,
        accepted: true,
        message: "welcome to the cluster".to_string(),
    })
}

/// Processes a worker metric heartbeat, updating `cluster_nodes` (`last_seen`, `last_heartbeat`,
/// `cpu_usage`, `ram_usage`, `disk_usage`, `status = 'online'`) and caching the full telemetry
/// snapshot in memory.
pub fn process_worker_heartbeat(
    req: &WorkerHeartbeatRequest,
) -> anyhow::Result<WorkerHeartbeatResponse> {
    let node_id = if !req.node_id.trim().is_empty() {
        req.node_id.trim().to_string()
    } else if !req.hostname.trim().is_empty() {
        format!("node-{}", req.hostname.trim())
    } else {
        anyhow::bail!("node_id is required");
    };

    // If PSK was supplied on the heartbeat or required by master config, verify it in constant time
    if !req.psk.trim().is_empty() || env::var("CLUSTER_PSK").map(|v| !v.trim().is_empty()).unwrap_or(false) {
        if let Err(msg) = verify_cluster_psk(&node_id, &req.psk) {
            anyhow::bail!("{}", msg);
        }
    }

    let (cpu_usage, ram_usage, disk_usage) = extract_usage_Rollups(req);
    let now = Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    let ts = if req.timestamp > 0 {
        req.timestamp
    } else {
        now.timestamp()
    };

    ensure_cluster_schema();
    if let Ok(conn) = af_db::get_conn() {
        let updated = conn
            .execute(
                "UPDATE cluster_nodes \
                 SET status = 'online', \
                     last_heartbeat = ?1, \
                     last_seen = ?1, \
                     cpu_usage = ?2, \
                     ram_usage = ?3, \
                     disk_usage = ?4 \
                 WHERE id = ?5",
                params![now_rfc3339, cpu_usage, ram_usage, disk_usage, node_id],
            )
            .unwrap_or(0);

        if updated == 0 {
            let hostname = if !req.hostname.trim().is_empty() {
                req.hostname.trim().to_string()
            } else {
                node_id.trim_start_matches("node-").to_string()
            };
            let address = if !req.address.trim().is_empty() {
                req.address.trim().to_string()
            } else {
                format!("{}:8080", hostname)
            };
            let psk_hash = if !req.psk.trim().is_empty() {
                hash_psk_sha256(req.psk.trim())
            } else {
                String::new()
            };
            let _ = conn.execute(
                "INSERT OR REPLACE INTO cluster_nodes \
                 (id, hostname, address, psk_hash, role, status, last_heartbeat, last_seen, cpu_usage, ram_usage, disk_usage, enrolled_at) \
                 VALUES (?1, ?2, ?3, ?4, 'worker', 'online', ?5, ?5, ?6, ?7, ?8, ?5)",
                params![
                    node_id,
                    hostname,
                    address,
                    psk_hash,
                    now_rfc3339,
                    cpu_usage,
                    ram_usage,
                    disk_usage
                ],
            );
        }
    }

    let previous = get_cached_worker_metrics(&node_id);
    let sys_info = req
        .system_info
        .as_ref()
        .and_then(|s| serde_json::to_value(s).ok())
        .or_else(|| previous.as_ref().and_then(|p| p.get("system_info")).cloned())
        .unwrap_or(serde_json::Value::Null);

    let metrics_val = if req.metrics.is_null() {
        serde_json::json!({
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage,
            "disk_usage": disk_usage,
        })
    } else {
        req.metrics.clone()
    };

    let snapshot = serde_json::json!({
        "node_id": node_id,
        "hostname": if !req.hostname.is_empty() {
            serde_json::Value::String(req.hostname.clone())
        } else {
            previous.as_ref().and_then(|p| p.get("hostname")).cloned().unwrap_or(serde_json::Value::String(node_id.clone()))
        },
        "status": "online",
        "timestamp": ts,
        "last_seen": now_rfc3339,
        "last_heartbeat": now_rfc3339,
        "cpu_usage": cpu_usage,
        "ram_usage": ram_usage,
        "disk_usage": disk_usage,
        "metrics": metrics_val,
        "services": req.services,
        "system_info": sys_info,
    });

    cache_worker_metrics(&node_id, snapshot);

    let command = pop_worker_command(&node_id);
    Ok(WorkerHeartbeatResponse {
        timestamp: ts,
        acknowledged: true,
        command,
    })
}

#[allow(non_snake_case)]
fn extract_usage_Rollups(req: &WorkerHeartbeatRequest) -> (f64, f64, f64) {
    let cpu = req
        .cpu_usage
        .or_else(|| req.metrics.get("cpu_usage").and_then(|v| v.as_f64()))
        .unwrap_or(0.0);

    let ram = req
        .ram_usage
        .or_else(|| req.metrics.get("ram_usage").and_then(|v| v.as_f64()))
        .or_else(|| {
            let used = req
                .metrics
                .get("memory")
                .and_then(|m| m.get("used"))
                .and_then(|v| v.as_f64())
                .or_else(|| req.metrics.get("mem_used_gb").and_then(|v| v.as_f64()))?;
            let total = req
                .metrics
                .get("memory")
                .and_then(|m| m.get("total"))
                .and_then(|v| v.as_f64())
                .or_else(|| req.metrics.get("mem_total_gb").and_then(|v| v.as_f64()))?;
            if total > 0.0 {
                Some(((used / total) * 1000.0).round() / 10.0)
            } else {
                Some(used)
            }
        })
        .unwrap_or(0.0);

    let disk = req
        .disk_usage
        .or_else(|| req.metrics.get("disk_usage").and_then(|v| v.as_f64()))
        .or_else(|| {
            let used = req
                .metrics
                .get("disk_space")
                .and_then(|d| d.get("used"))
                .and_then(|v| v.as_f64())
                .or_else(|| req.metrics.get("disk_used_gb").and_then(|v| v.as_f64()))?;
            let total = req
                .metrics
                .get("disk_space")
                .and_then(|d| d.get("total"))
                .and_then(|v| v.as_f64())
                .or_else(|| req.metrics.get("disk_total_gb").and_then(|v| v.as_f64()))?;
            if total > 0.0 {
                Some(((used / total) * 1000.0).round() / 10.0)
            } else {
                Some(used)
            }
        })
        .unwrap_or(0.0);

    (
        af_hardware::sanitize_f64(cpu),
        af_hardware::sanitize_f64(ram),
        af_hardware::sanitize_f64(disk),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Master TCP / HTTP JSON-RPC Listener (`CLUSTER_GRPC_PORT`, default 50051)
// ─────────────────────────────────────────────────────────────────────────────

async fn handle_master_connection(mut stream: TcpStream) -> anyhow::Result<()> {
    let mut reader = BufReader::new(&mut stream);
    let mut first_line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut first_line)).await??;
    if n == 0 {
        return Ok(());
    }

    let trimmed_first = first_line.trim();
    if trimmed_first.is_empty() {
        return Ok(());
    }

    // Support raw TCP JSON-RPC lines (`{"method": "/cluster/v1/register", "params": {...}}`)
    if trimmed_first.starts_with('{') {
        let resp_val = handle_raw_json_rpc(trimmed_first);
        let mut out = serde_json::to_vec(&resp_val)?;
        out.push(b'\n');
        stream.write_all(&out).await?;
        stream.flush().await?;
        return Ok(());
    }

    // Parse HTTP/1.x request line: `METHOD /path HTTP/1.1`
    let mut parts = trimmed_first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_uppercase();
    let raw_target = parts.next().unwrap_or("/");
    let path = raw_target.split('?').next().unwrap_or("/");

    let mut content_length = 0usize;
    let mut header_psk = String::new();

    loop {
        let mut line = String::new();
        let bytes_read =
            tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await??;
        if bytes_read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if key == "content-length" {
                content_length = val.parse::<usize>().unwrap_or(0).min(4 * 1024 * 1024);
            } else if key == "x-cluster-psk" {
                header_psk = val.to_string();
            } else if key == "authorization" {
                if let Some(token) = val.strip_prefix("Bearer ").or_else(|| val.strip_prefix("bearer ")) {
                    header_psk = token.trim().to_string();
                }
            }
        }
    }

    let mut body_bytes = vec![0u8; content_length];
    if content_length > 0 {
        tokio::time::timeout(Duration::from_secs(10), reader.read_exact(&mut body_bytes)).await??;
    }

    let (status_code, status_text, response_json) =
        route_cluster_http_request(&method, path, raw_target, &header_psk, &body_bytes);

    let payload_bytes = serde_json::to_vec(&response_json)?;
    let http_header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status_code,
        status_text,
        payload_bytes.len()
    );
    stream.write_all(http_header.as_bytes()).await?;
    stream.write_all(&payload_bytes).await?;
    stream.flush().await?;
    Ok(())
}

fn route_cluster_http_request(
    method: &str,
    path: &str,
    raw_target: &str,
    header_psk: &str,
    body_bytes: &[u8],
) -> (u16, &'static str, serde_json::Value) {
    match (method, path) {
        ("POST", "/cluster/v1/register") | ("POST", "/api/v1/admin/cluster/enroll") => {
            let mut req: RegisterWorkerRequest =
                serde_json::from_slice(body_bytes).unwrap_or_default();
            if req.psk.is_empty() && !header_psk.is_empty() {
                req.psk = header_psk.to_string();
            }
            match register_worker_node(&req) {
                Ok(resp) if resp.accepted => {
                    (200, "OK", serde_json::to_value(resp).unwrap_or_default())
                }
                Ok(resp) => (
                    401,
                    "Unauthorized",
                    serde_json::to_value(resp).unwrap_or_default(),
                ),
                Err(e) => (
                    500,
                    "Internal Server Error",
                    serde_json::json!({
                        "accepted": false,
                        "message": format!("enrollment failed: {}", e),
                    }),
                ),
            }
        }
        ("POST", "/cluster/v1/heartbeat") => {
            let mut req: WorkerHeartbeatRequest =
                serde_json::from_slice(body_bytes).unwrap_or_default();
            if req.psk.is_empty() && !header_psk.is_empty() {
                req.psk = header_psk.to_string();
            }
            match process_worker_heartbeat(&req) {
                Ok(resp) => (200, "OK", serde_json::to_value(resp).unwrap_or_default()),
                Err(e) => (
                    401,
                    "Unauthorized",
                    serde_json::json!({
                        "acknowledged": false,
                        "error": e.to_string(),
                    }),
                ),
            }
        }
        ("GET", "/cluster/v1/metrics") => {
            let node_id = raw_target
                .split_once('?')
                .and_then(|(_, q)| {
                    url::form_urlencoded::parse(q.as_bytes())
                        .find(|(k, _)| k == "node_id" || k == "id")
                        .map(|(_, v)| v.into_owned())
                })
                .unwrap_or_default();
            if let Some(metrics) = get_cached_worker_metrics(&node_id) {
                (200, "OK", metrics)
            } else {
                (
                    404,
                    "Not Found",
                    serde_json::json!({ "error": "Worker metrics not found", "node_id": node_id }),
                )
            }
        }
        _ => (
            404,
            "Not Found",
            serde_json::json!({ "error": "Unknown cluster RPC endpoint", "path": path }),
        ),
    }
}

fn handle_raw_json_rpc(raw_line: &str) -> serde_json::Value {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(raw_line) else {
        return serde_json::json!({ "error": "Invalid JSON payload" });
    };
    let method = val
        .get("method")
        .or_else(|| val.get("action"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let params_val = val.get("params").cloned().unwrap_or_else(|| val.clone());

    match method {
        "register" | "/cluster/v1/register" | "RegisterWorker" => {
            let req: RegisterWorkerRequest = serde_json::from_value(params_val).unwrap_or_default();
            match register_worker_node(&req) {
                Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                Err(e) => serde_json::json!({ "accepted": false, "message": e.to_string() }),
            }
        }
        "heartbeat" | "/cluster/v1/heartbeat" | "Heartbeat" => {
            let req: WorkerHeartbeatRequest = serde_json::from_value(params_val).unwrap_or_default();
            match process_worker_heartbeat(&req) {
                Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                Err(e) => serde_json::json!({ "acknowledged": false, "error": e.to_string() }),
            }
        }
        _ => {
            // Auto-detect by fields if no explicit `method` was specified
            if val.get("metrics").is_some() || val.get("cpu_usage").is_some() {
                let req: WorkerHeartbeatRequest = serde_json::from_value(val).unwrap_or_default();
                match process_worker_heartbeat(&req) {
                    Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                    Err(e) => serde_json::json!({ "acknowledged": false, "error": e.to_string() }),
                }
            } else {
                let req: RegisterWorkerRequest = serde_json::from_value(val).unwrap_or_default();
                match register_worker_node(&req) {
                    Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                    Err(e) => serde_json::json!({ "accepted": false, "message": e.to_string() }),
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Worker Registration & 5-Second Telemetry Heartbeat Loop (`client.go`)
// ─────────────────────────────────────────────────────────────────────────────

fn normalize_master_base_url(raw_addr: &str) -> String {
    let trimmed = raw_addr.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
    }
}

fn resolve_local_hostname() -> String {
    if let Ok(h) = env::var("HOSTNAME") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    if let Ok(h) = env::var("COMPUTERNAME") {
        if !h.trim().is_empty() {
            return h.trim().to_string();
        }
    }
    "aetherflow-worker".to_string()
}

fn collect_worker_services() -> Vec<WorkerService> {
    crate::get_active_services()
        .into_iter()
        .map(|(name, svc)| WorkerService {
            name,
            status: svc.status,
            uptime: svc.uptime,
            managed_by: svc.managed_by,
        })
        .collect()
}

fn build_worker_heartbeat_payload(
    node_id: &str,
    hostname: &str,
    address: &str,
    psk: &str,
) -> (WorkerHeartbeatRequest, WorkerSystemInfo) {
    let sys_metrics = af_hardware::get_system_metrics_core();
    let mem_used_gb = sys_metrics.memory.get("used").copied().unwrap_or(0.0);
    let mem_total_gb = sys_metrics.memory.get("total").copied().unwrap_or(0.0);
    let disk_used_gb = sys_metrics.disk_space.get("used").copied().unwrap_or(0.0);
    let disk_total_gb = sys_metrics.disk_space.get("total").copied().unwrap_or(0.0);

    let ram_pct = if mem_total_gb > 0.0 {
        af_hardware::sanitize_f64(((mem_used_gb / mem_total_gb) * 1000.0).round() / 10.0)
    } else {
        0.0
    };
    let disk_pct = if disk_total_gb > 0.0 {
        af_hardware::sanitize_f64(((disk_used_gb / disk_total_gb) * 1000.0).round() / 10.0)
    } else {
        0.0
    };

    let sys_info = WorkerSystemInfo {
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
        cpu_cores: sys_metrics.per_core_cpu.len().max(1) as i32,
        total_memory_bytes: (mem_total_gb * 1024.0 * 1024.0 * 1024.0) as i64,
        total_disk_bytes: (disk_total_gb * 1024.0 * 1024.0 * 1024.0) as i64,
    };

    let mut rich_metrics = serde_json::to_value(&sys_metrics).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = rich_metrics.as_object_mut() {
        obj.insert("mem_used_gb".to_string(), serde_json::json!(mem_used_gb));
        obj.insert("mem_total_gb".to_string(), serde_json::json!(mem_total_gb));
        obj.insert("disk_used_gb".to_string(), serde_json::json!(disk_used_gb));
        obj.insert("disk_total_gb".to_string(), serde_json::json!(disk_total_gb));
        obj.insert("ram_usage".to_string(), serde_json::json!(ram_pct));
        obj.insert("disk_usage".to_string(), serde_json::json!(disk_pct));
        obj.insert(
            "net_rx_speed".to_string(),
            sys_metrics
                .network
                .get("down")
                .cloned()
                .unwrap_or_else(|| serde_json::json!("0 B/s")),
        );
        obj.insert(
            "net_tx_speed".to_string(),
            sys_metrics
                .network
                .get("up")
                .cloned()
                .unwrap_or_else(|| serde_json::json!("0 B/s")),
        );
    }

    let hb = WorkerHeartbeatRequest {
        node_id: node_id.to_string(),
        hostname: hostname.to_string(),
        address: address.to_string(),
        psk: psk.to_string(),
        timestamp: Utc::now().timestamp(),
        cpu_usage: Some(sys_metrics.cpu_usage),
        ram_usage: Some(ram_pct),
        disk_usage: Some(disk_pct),
        metrics: rich_metrics,
        services: collect_worker_services(),
        system_info: Some(sys_info.clone()),
    };

    (hb, sys_info)
}

async fn execute_remote_worker_command(cmd: PendingWorkerCommand) {
    tracing::info!(
        command_id = %cmd.id,
        cmd_type = %cmd.cmd_type,
        "cluster worker executing remote command from master"
    );
    if cmd.cmd_type == "restart_service" {
        if let Some(service_name) = cmd.params.get("service") {
            if let Err(e) = crate::control_service(service_name, "restart").await {
                tracing::warn!(
                    service = %service_name,
                    error = %e,
                    "cluster worker service restart failed"
                );
            }
        }
    }
}

async fn run_worker_registration_and_heartbeat_loop(master_addr: String, psk: String) {
    let base_url = normalize_master_base_url(&master_addr);
    let hostname = resolve_local_hostname();
    let local_port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let worker_address = format!("{}:{}", hostname, local_port);
    let mut assigned_node_id = format!("node-{}", hostname);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let (_, sys_info) =
        build_worker_heartbeat_payload(&assigned_node_id, &hostname, &worker_address, &psk);
    let reg_payload = RegisterWorkerRequest {
        node_id: assigned_node_id.clone(),
        hostname: hostname.clone(),
        address: worker_address.clone(),
        psk: psk.clone(),
        version: "4.0.0-rc1".to_string(),
        system_info: Some(sys_info),
    };

    // Register with master via `/cluster/v1/register` (or fallback `/api/v1/admin/cluster/enroll`)
    let register_endpoints = [
        format!("{}/cluster/v1/register", base_url),
        format!("{}/api/v1/admin/cluster/enroll", base_url),
    ];

    for url in &register_endpoints {
        match client
            .post(url)
            .header("X-Cluster-PSK", &psk)
            .json(&reg_payload)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(parsed) = resp.json::<RegisterWorkerResponse>().await {
                    if parsed.accepted && !parsed.node_id.is_empty() {
                        assigned_node_id = parsed.node_id;
                    }
                }
                tracing::info!(
                    node_id = %assigned_node_id,
                    master = %base_url,
                    "cluster worker registered with master"
                );
                break;
            }
            Ok(resp) => {
                tracing::warn!(
                    endpoint = %url,
                    status = %resp.status(),
                    "cluster registration endpoint returned non-success"
                );
            }
            Err(e) => {
                tracing::warn!(
                    endpoint = %url,
                    error = %e,
                    "cluster worker registration attempt failed"
                );
            }
        }
    }

    // 5-second metric heartbeat loop pushing `af_hardware::get_system_metrics_core()`
    let heartbeat_url = format!("{}/cluster/v1/heartbeat", base_url);
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        ticker.tick().await;
        let (hb_payload, _) =
            build_worker_heartbeat_payload(&assigned_node_id, &hostname, &worker_address, &psk);

        match client
            .post(&heartbeat_url)
            .header("X-Cluster-PSK", &psk)
            .json(&hb_payload)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(pong) = resp.json::<WorkerHeartbeatResponse>().await {
                    if let Some(cmd) = pong.command {
                        tokio::spawn(execute_remote_worker_command(cmd));
                    }
                }
            }
            Ok(resp) => {
                tracing::warn!(
                    status = %resp.status(),
                    "cluster master rejected heartbeat"
                );
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    master = %heartbeat_url,
                    "cluster heartbeat send error"
                );
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public Entrypoint (`start_cluster_runtime`)
// ─────────────────────────────────────────────────────────────────────────────

/// Starts the Cluster Master/Worker runtime and background health-sweep daemon:
/// - Always spawns a 30-second health-sweep loop marking stale `cluster_nodes` (`last_seen` > 60s)
///   as `status = 'offline'`.
/// - If `CLUSTER_MODE=master`: spawns the cluster TCP/HTTP JSON-RPC listener on `CLUSTER_GRPC_PORT`
///   (or `GRPC_PORT`, default `50051`) handling `/cluster/v1/register` and `/cluster/v1/heartbeat`.
/// - If `CLUSTER_MODE=worker`: reads `CLUSTER_MASTER_ADDR` and `CLUSTER_PSK`, registers this worker
///   with the master, and runs a 5-second heartbeat loop pushing `af_hardware::get_system_metrics_core()`.
pub fn start_cluster_runtime() {
    ensure_cluster_schema();

    // Mark all persisted nodes offline at boot until they send a fresh heartbeat, matching Go's `loadFromDB()`
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute("UPDATE cluster_nodes SET status = 'offline'", []);
    }

    // 1. Always spawn the 30-second master node health-sweep loop
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            sweep_stale_cluster_nodes();
        }
    });

    // 2. Evaluate `CLUSTER_MODE` ("master", "worker", or "standalone" default)
    let mode = env::var("CLUSTER_MODE")
        .unwrap_or_else(|_| "standalone".to_string())
        .trim()
        .to_lowercase();

    match mode.as_str() {
        "master" => {
            let port = env::var("CLUSTER_GRPC_PORT")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| env::var("GRPC_PORT").ok().filter(|s| !s.trim().is_empty()))
                .unwrap_or_else(|| "50051".to_string());
            let host = env::var("CLUSTER_GRPC_HOST")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| env::var("GRPC_HOST").ok().filter(|s| !s.trim().is_empty()))
                .unwrap_or_else(|| "0.0.0.0".to_string());
            let bind_addr = format!("{}:{}", host.trim(), port.trim());

            tracing::info!(
                role = "master",
                listen_addr = %bind_addr,
                "cluster mode active"
            );

            tokio::spawn(async move {
                match TcpListener::bind(&bind_addr).await {
                    Ok(listener) => {
                        tracing::info!(
                            addr = %bind_addr,
                            "cluster heartbeat TCP/HTTP JSON-RPC listener bound"
                        );
                        loop {
                            match listener.accept().await {
                                Ok((stream, _peer)) => {
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_master_connection(stream).await {
                                            tracing::debug!(
                                                error = %e,
                                                "cluster connection handler error"
                                            );
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "cluster listener accept error");
                                    tokio::time::sleep(Duration::from_millis(200)).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            addr = %bind_addr,
                            error = %e,
                            "failed to bind cluster heartbeat listener"
                        );
                    }
                }
            });
        }
        "worker" => {
            let master_addr = env::var("CLUSTER_MASTER_ADDR")
                .unwrap_or_default()
                .trim()
                .to_string();
            let psk = env::var("CLUSTER_PSK")
                .unwrap_or_default()
                .trim()
                .to_string();

            if master_addr.is_empty() {
                tracing::error!(
                    "CLUSTER_MODE=worker requires CLUSTER_MASTER_ADDR to be set; skipping worker loop"
                );
                return;
            }

            tracing::info!(
                role = "worker",
                master_addr = %master_addr,
                "cluster mode active"
            );

            tokio::spawn(async move {
                run_worker_registration_and_heartbeat_loop(master_addr, psk).await;
            });
        }
        _ => {
            tracing::info!(role = "standalone", "cluster mode active");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"super-secret-psk-1234567890123456", b"super-secret-psk-1234567890123456"));
        assert!(!constant_time_eq(b"super-secret-psk-1234567890123456", b"super-secret-psk-1234567890123457"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_worker_metrics_cache_roundtrip() {
        let node_id = "node-test-worker-01";
        let payload = serde_json::json!({
            "node_id": node_id,
            "cpu_usage": 42.5,
            "ram_usage": 61.2,
            "disk_usage": 33.8,
        });
        cache_worker_metrics(node_id, payload.clone());
        let cached = get_cached_worker_metrics(node_id).expect("cached metrics should exist");
        assert_eq!(cached["cpu_usage"], serde_json::json!(42.5));
        remove_cached_worker_metrics(node_id);
        assert!(get_cached_worker_metrics(node_id).is_none());
    }
}
