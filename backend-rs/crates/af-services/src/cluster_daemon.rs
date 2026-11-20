//! Cluster Master/Worker Heartbeat & Registration Daemon.
//!
//! Provides:
//! - `start_cluster_runtime()`: Spawns the 30-second node health-sweep loop and, depending on
//!   `CLUSTER_MODE` (`"master"`, `"worker"`, or `"standalone"`), launches either the master
//!   TCP/HTTP JSON-RPC listener or the worker registration + 5-second telemetry heartbeat loop.
//! - `get_cached_worker_metrics(node_id)`: Returns the most recent rich telemetry snapshot
//!   pushed by a worker node if cached in memory.

use anyhow::Context;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use chrono::{DateTime, Utc};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HyperBody, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::params;
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::io::Read;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
}

// ─────────────────────────────────────────────────────────────────────────────
// In-Memory Telemetry & Durable SQLite Command Queue
// ─────────────────────────────────────────────────────────────────────────────

const CLUSTER_COMMAND_LEASE_SECS: i64 = 30;
const MAX_PENDING_COMMANDS_PER_NODE: i64 = 64;

static WORKER_METRICS_CACHE: Lazy<RwLock<HashMap<String, serde_json::Value>>> =
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

/// Removes a worker node's cached telemetry and queued commands when a node is removed.
pub fn remove_cached_worker_metrics(node_id: &str) {
    if let Ok(mut guard) = WORKER_METRICS_CACHE.write() {
        guard.remove(node_id);
    }
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "DELETE FROM cluster_commands WHERE node_id = ?1",
            params![node_id],
        );
    }
}

/// Enqueues a validated remote command into durable SQLite `cluster_commands`.
pub fn enqueue_cluster_command(
    node_id: &str,
    cmd_type: &str,
    target: &str,
) -> anyhow::Result<ClusterCommandRecord> {
    ensure_cluster_schema();
    let clean_node = node_id.trim();
    let clean_type = cmd_type.trim();
    let clean_target = target.trim();
    anyhow::ensure!(
        !clean_node.is_empty() && clean_node.len() <= 128,
        "valid node_id is required"
    );
    anyhow::ensure!(
        matches!(
            clean_type,
            "restart_service" | "start_service" | "stop_service" | "reload_service"
        ),
        "unsupported cluster command type (allowed: restart_service, start_service, stop_service, reload_service)"
    );
    anyhow::ensure!(
        !clean_target.is_empty()
            && clean_target.len() <= 128
            && clean_target
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@')),
        "invalid command target identifier"
    );

    let conn = af_db::get_conn().context("database unavailable")?;
    let active_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM cluster_commands WHERE node_id = ?1 AND status IN ('queued', 'leased')",
            params![clean_node],
            |r| r.get(0),
        )
        .unwrap_or(0);
    anyhow::ensure!(
        active_count < MAX_PENDING_COMMANDS_PER_NODE,
        "worker command queue is full for node '{}'",
        clean_node
    );

    let cmd_id = format!("cmd-{}", uuid::Uuid::new_v4().simple());
    let now_iso = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO cluster_commands (id, node_id, cmd_type, target, status, leased_until, result_message, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'queued', NULL, NULL, ?5, ?5)",
        params![cmd_id, clean_node, clean_type, clean_target, now_iso],
    )
    .context("failed to persist cluster command")?;

    Ok(ClusterCommandRecord {
        id: cmd_id,
        node_id: clean_node.to_string(),
        cmd_type: clean_type.to_string(),
        target: clean_target.to_string(),
        status: "queued".to_string(),
        leased_until: None,
        result_message: None,
        created_at: now_iso.clone(),
        updated_at: now_iso,
    })
}

/// Queues a remote command for delivery to a worker node on its next heartbeat response (durable SQLite wrapper).
pub fn queue_worker_command(node_id: &str, cmd: PendingWorkerCommand) -> bool {
    ensure_cluster_schema();
    let clean_node = node_id.trim();
    let clean_type = cmd.cmd_type.trim();
    let target = cmd
        .params
        .get("service")
        .or_else(|| cmd.params.get("target"))
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    if clean_node.is_empty() || clean_type.is_empty() {
        return false;
    }
    let cmd_id = if cmd.id.trim().is_empty() {
        format!("cmd-{}", uuid::Uuid::new_v4().simple())
    } else {
        cmd.id.trim().to_string()
    };
    let Ok(conn) = af_db::get_conn() else {
        return false;
    };
    let active_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM cluster_commands WHERE node_id = ?1 AND status IN ('queued', 'leased')",
            params![clean_node],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if active_count >= MAX_PENDING_COMMANDS_PER_NODE {
        return false;
    }
    let now_iso = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR IGNORE INTO cluster_commands (id, node_id, cmd_type, target, status, leased_until, result_message, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'queued', NULL, NULL, ?5, ?5)",
        params![cmd_id, clean_node, clean_type, target, now_iso],
    )
    .map(|n| n > 0)
    .unwrap_or(false)
}

/// Leases the next queued (or lease-expired) command for `node_id` from SQLite `cluster_commands`.
pub fn lease_next_worker_command(
    node_id: &str,
    now_unix: i64,
    lease_secs: i64,
) -> Option<PendingWorkerCommand> {
    ensure_cluster_schema();
    let mut conn = af_db::get_conn().ok()?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .ok()?;
    let candidate: Option<(String, String, String)> = tx
        .query_row(
            "SELECT id, cmd_type, target
             FROM cluster_commands
             WHERE node_id = ?1
               AND (status = 'queued' OR (status = 'leased' AND COALESCE(leased_until, 0) <= ?2))
             ORDER BY created_at ASC, rowid ASC
             LIMIT 1",
            params![node_id, now_unix],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    let (id, cmd_type, target) = candidate?;
    let lease_until = now_unix.saturating_add(lease_secs.max(5));
    let now_iso = Utc::now().to_rfc3339();
    let updated = tx
        .execute(
            "UPDATE cluster_commands
             SET status = 'leased', leased_until = ?1, updated_at = ?2
             WHERE id = ?3 AND node_id = ?4
               AND (status = 'queued' OR (status = 'leased' AND COALESCE(leased_until, 0) <= ?5))",
            params![lease_until, now_iso, id, node_id, now_unix],
        )
        .ok()?;
    if updated == 0 {
        return None;
    }
    tx.commit().ok()?;

    let mut params_map = HashMap::new();
    if !target.is_empty() {
        params_map.insert("service".to_string(), target.clone());
        params_map.insert("target".to_string(), target);
    }
    Some(PendingWorkerCommand {
        id,
        cmd_type,
        params: params_map,
    })
}

/// Compatibility alias leasing the next durable worker command using default lease duration.
pub fn pop_worker_command(node_id: &str) -> Option<PendingWorkerCommand> {
    lease_next_worker_command(node_id, Utc::now().timestamp(), CLUSTER_COMMAND_LEASE_SECS)
}

/// Records terminal execution status (`executed` or `failed`) reported by `node_id`.
pub fn acknowledge_worker_command(node_id: &str, ack: &WorkerCommandAck) -> anyhow::Result<bool> {
    ensure_cluster_schema();
    let clean_id = ack.id.trim();
    let clean_status = ack.status.trim().to_ascii_lowercase();
    anyhow::ensure!(!clean_id.is_empty(), "command id is required");
    anyhow::ensure!(
        matches!(clean_status.as_str(), "executed" | "failed"),
        "command ack status must be 'executed' or 'failed'"
    );
    let msg = ack
        .result_message
        .as_deref()
        .map(|s| {
            let trimmed = s.trim();
            if trimmed.len() > 1024 {
                trimmed[..1024].to_string()
            } else {
                trimmed.to_string()
            }
        })
        .filter(|s| !s.is_empty());
    let now_iso = Utc::now().to_rfc3339();
    let conn = af_db::get_conn().context("database unavailable")?;
    let changed = conn.execute(
        "UPDATE cluster_commands
         SET status = ?1,
             leased_until = NULL,
             result_message = ?2,
             updated_at = ?3
         WHERE id = ?4 AND node_id = ?5 AND status IN ('queued', 'leased')",
        params![clean_status, msg, now_iso, clean_id, node_id.trim()],
    )?;
    if changed > 0 {
        return Ok(true);
    }
    let already_terminal: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM cluster_commands WHERE id = ?1 AND node_id = ?2 AND status IN ('executed', 'failed'))",
            params![clean_id, node_id.trim()],
            |r| r.get(0),
        )
        .unwrap_or(false);
    Ok(already_terminal)
}

/// Lists durable cluster commands (optionally filtered by `node_id`), newest first.
pub fn list_cluster_commands(
    node_id_filter: Option<&str>,
    limit: usize,
) -> anyhow::Result<Vec<ClusterCommandRecord>> {
    ensure_cluster_schema();
    let effective_limit = limit.clamp(1, 200) as i64;
    let clean_filter = node_id_filter.map(str::trim).filter(|s| !s.is_empty());
    let conn = af_db::get_conn().context("database unavailable")?;
    let mut stmt = conn.prepare(
        "SELECT id, node_id, cmd_type, target, status, leased_until, result_message, created_at, updated_at
         FROM cluster_commands
         WHERE (?1 IS NULL OR node_id = ?1)
         ORDER BY created_at DESC, rowid DESC
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![clean_filter, effective_limit], |r| {
            Ok(ClusterCommandRecord {
                id: r.get(0)?,
                node_id: r.get(1)?,
                cmd_type: r.get(2)?,
                target: r.get(3)?,
                status: r.get(4)?,
                leased_until: r.get(5)?,
                result_message: r.get(6)?,
                created_at: r.get(7)?,
                updated_at: r.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// Constant-Time PSK Verification & SQLite Schema Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Performs a constant-time byte slice equality check to prevent timing side-channels.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut ha = Sha256::new();
    ha.update(a);
    let da = ha.finalize();
    let mut hb = Sha256::new();
    hb.update(b);
    let db = hb.finalize();
    let mut diff = 0u8;
    for (&x, &y) in da.iter().zip(db.iter()) {
        diff |= x ^ y;
    }
    diff == 0 && a.len() == b.len()
}

fn hash_psk_sha256(psk: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(psk.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Verified transport identity of the caller on a cluster listener connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTransportAuth {
    /// Direct in-process library call (e.g., unit tests).
    InternalCall,
    /// Opt-in `CLUSTER_ALLOW_INSECURE_LOOPBACK=true` plaintext loopback connection.
    InsecureLoopback,
    /// Verified TLS 1.3 mutual-TLS client certificate identity.
    Mtls {
        cert_sha256: String,
        subject_cn: Option<String>,
        is_admin_cert: bool,
    },
}

impl PeerTransportAuth {
    fn mtls_cert_sha256(&self) -> Option<&str> {
        match self {
            Self::Mtls { cert_sha256, .. } => Some(cert_sha256.as_str()),
            _ => None,
        }
    }
}

fn verify_master_control_plane_psk(candidate_psk: &str) -> bool {
    let candidate = candidate_psk.trim();
    if candidate.is_empty() {
        return false;
    }
    if let Ok(master_psk) = env::var("CLUSTER_PSK") {
        let master_trimmed = master_psk.trim();
        if !master_trimmed.is_empty() {
            return constant_time_eq(candidate.as_bytes(), master_trimmed.as_bytes());
        }
    }
    false
}

/// Verifies a worker's pre-shared key against `CLUSTER_PSK` (if configured on the master)
/// or against a previously enrolled node's stored `psk_hash` (`sha256:<hex>` or legacy Go
/// `$2a$`/`$2b$`/`$2y$` bcrypt hashes; Argon2id is reserved for user passwords in `af-auth`).
pub fn verify_cluster_psk(node_id: &str, candidate_psk: &str) -> Result<(), &'static str> {
    let candidate = candidate_psk.trim();
    if candidate.is_empty() {
        return Err("psk is required");
    }

    if verify_master_control_plane_psk(candidate) {
        return Ok(());
    }

    // Check if this node is already enrolled in `cluster_nodes` with a matching hash
    if !node_id.is_empty() {
        if let Ok(conn) = af_db::get_conn() {
            if let Ok(stored_hash) = conn.query_row(
                "SELECT COALESCE(psk_hash, '') FROM cluster_nodes WHERE id = ?1",
                params![node_id],
                |r| r.get::<_, String>(0),
            ) {
                return verify_enrolled_cluster_psk(candidate, &stored_hash);
            }
        }
    }

    Err("cluster PSK is not configured and node is not enrolled")
}

fn verify_enrolled_cluster_psk(candidate: &str, stored_hash: &str) -> Result<(), &'static str> {
    if candidate.is_empty() || stored_hash.is_empty() {
        return Err("cluster PSK is not configured and node is not enrolled");
    }
    if stored_hash.starts_with("$2a$")
        || stored_hash.starts_with("$2b$")
        || stored_hash.starts_with("$2y$")
    {
        return if bcrypt::verify(candidate, stored_hash).unwrap_or(false) {
            Ok(())
        } else {
            Err("invalid cluster PSK for enrolled node")
        };
    }
    let candidate_hash = hash_psk_sha256(candidate);
    if constant_time_eq(candidate_hash.as_bytes(), stored_hash.as_bytes())
        || (!stored_hash.starts_with("sha256:")
            && constant_time_eq(candidate.as_bytes(), stored_hash.as_bytes()))
    {
        return Ok(());
    }
    Err("invalid cluster PSK for enrolled node")
}

/// Ensures `cluster_nodes` has `last_seen`, `cpu_usage`, `ram_usage`, `disk_usage`, and
/// `peer_cert_sha256` columns plus the single-use `cluster_enrollment_tokens` table.
pub fn ensure_cluster_schema() {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let migrations = [
        "ALTER TABLE cluster_nodes ADD COLUMN last_seen DATETIME;",
        "ALTER TABLE cluster_nodes ADD COLUMN cpu_usage REAL DEFAULT 0.0;",
        "ALTER TABLE cluster_nodes ADD COLUMN ram_usage REAL DEFAULT 0.0;",
        "ALTER TABLE cluster_nodes ADD COLUMN disk_usage REAL DEFAULT 0.0;",
        "ALTER TABLE cluster_nodes ADD COLUMN peer_cert_sha256 TEXT DEFAULT '';",
        "CREATE TABLE IF NOT EXISTS cluster_enrollment_tokens (
            token_hash TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed_by TEXT
        );",
        "CREATE TABLE IF NOT EXISTS cluster_commands (
            id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL,
            cmd_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            leased_until INTEGER,
            result_message TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );",
        "CREATE INDEX IF NOT EXISTS idx_cluster_commands_node_status ON cluster_commands(node_id, status, created_at);",
    ];
    for sql in migrations {
        let _ = conn.execute_batch(sql);
    }
}

/// Mints a 256-bit CSPRNG single-use worker enrollment token (24-hour TTL), persists its
/// SHA-256 digest in `cluster_enrollment_tokens`, and returns the 64-char hex token.
pub fn issue_cluster_enrollment_token() -> anyhow::Result<String> {
    ensure_cluster_schema();
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    let token_hash = hash_psk_sha256(&token);
    let now = Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    let expires_at = now.timestamp() + 86_400;

    let conn = af_db::get_conn().context("failed opening database for cluster enrollment token")?;
    let _ = conn.execute(
        "DELETE FROM cluster_enrollment_tokens WHERE expires_at < ?1",
        params![now.timestamp()],
    );
    conn.execute(
        "INSERT INTO cluster_enrollment_tokens (token_hash, created_at, expires_at, consumed_by) \
         VALUES (?1, ?2, ?3, NULL)",
        params![token_hash, now_rfc3339, expires_at],
    )
    .context("failed persisting cluster enrollment token")?;
    Ok(token)
}

fn check_cert_not_enrolled_as_worker(cert_sha256: &str) -> Result<(), &'static str> {
    let fp = cert_sha256.trim();
    if fp.is_empty() {
        return Err("empty mTLS client certificate fingerprint");
    }
    ensure_cluster_schema();
    let conn = af_db::get_conn().map_err(|_| "cluster database unavailable")?;
    let cnt: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM cluster_nodes WHERE peer_cert_sha256 = ?1 AND COALESCE(role, 'worker') = 'worker'",
            params![fp],
            |r| r.get::<_, i64>(0),
        )
        .map_err(|_| "cluster database query failed")?;
    if cnt > 0 {
        return Err("enrolled worker certificates are prohibited from cluster control-plane RPCs");
    }
    Ok(())
}

fn authorize_cluster_control_plane(
    header_psk: &str,
    peer_auth: &PeerTransportAuth,
) -> Result<(), &'static str> {
    if let PeerTransportAuth::Mtls { cert_sha256, .. } = peer_auth {
        check_cert_not_enrolled_as_worker(cert_sha256)?;
    }
    match peer_auth {
        PeerTransportAuth::InternalCall => return Ok(()),
        PeerTransportAuth::Mtls {
            is_admin_cert: true,
            ..
        } => return Ok(()),
        _ => {}
    }
    if verify_master_control_plane_psk(header_psk) {
        return Ok(());
    }
    Err(
        "control-plane authentication required (master CLUSTER_PSK or control-plane client certificate)",
    )
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
    if !stale_ids.is_empty() {
        if let Ok(mut update_stmt) = conn.prepare(
            "UPDATE cluster_nodes SET status = 'offline' WHERE id = ?1 AND status != 'offline'",
        ) {
            for (id, hostname) in &stale_ids {
                if let Ok(n) = update_stmt.execute(params![id]) {
                    if n > 0 {
                        marked += n;
                        tracing::warn!(node_id = %id, hostname = %hostname, "cluster worker went offline (heartbeat timeout > 60s)");
                    }
                }
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

fn is_enrolled_cluster_node(node_id: &str) -> bool {
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return false;
    }
    let Ok(conn) = af_db::get_conn() else {
        return false;
    };
    conn.query_row(
        "SELECT COALESCE(psk_hash, '') FROM cluster_nodes WHERE id = ?1",
        params![trimmed],
        |r| r.get::<_, String>(0),
    )
    .map(|hash| !hash.trim().is_empty())
    .unwrap_or(false)
}

/// Validates and registers a worker node in `cluster_nodes` and initializes its in-memory state.
pub fn register_worker_node(req: &RegisterWorkerRequest) -> anyhow::Result<RegisterWorkerResponse> {
    register_worker_node_with_peer(req, &PeerTransportAuth::InternalCall)
}

/// Validates and registers a worker node with transport-layer peer certificate binding.
pub fn register_worker_node_with_peer(
    req: &RegisterWorkerRequest,
    peer_auth: &PeerTransportAuth,
) -> anyhow::Result<RegisterWorkerResponse> {
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

    if psk.len() < 32 {
        return Ok(RegisterWorkerResponse {
            node_id: String::new(),
            accepted: false,
            message: "psk must be at least 32 characters for adequate security".to_string(),
        });
    }

    let node_id = if !req.node_id.trim().is_empty() {
        req.node_id.trim().to_string()
    } else {
        format!("node-{}", hostname)
    };

    ensure_cluster_schema();
    let incoming_cert_fp = peer_auth.mtls_cert_sha256();
    let mut conn = af_db::get_conn().context("cluster database unavailable")?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .context("failed starting immediate cluster enrollment transaction")?;

    let existing_record: Option<(String, String)> = match tx.query_row(
        "SELECT COALESCE(psk_hash, ''), COALESCE(peer_cert_sha256, '') FROM cluster_nodes WHERE id = ?1",
        params![node_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    ) {
        Ok(row) => Some(row),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e).context("failed querying existing cluster node state"),
    };

    if let Some((_, ref existing_cert)) = existing_record {
        let pinned_fp = existing_cert.trim();
        if !pinned_fp.is_empty() && !matches!(peer_auth, PeerTransportAuth::InternalCall) {
            let matches_pin = incoming_cert_fp
                .is_some_and(|fp| constant_time_eq(fp.as_bytes(), pinned_fp.as_bytes()));
            if !matches_pin {
                return Ok(RegisterWorkerResponse {
                    node_id: String::new(),
                    accepted: false,
                    message: "peer certificate does not match enrolled worker certificate"
                        .to_string(),
                });
            }
        }
    }

    let is_master_psk = verify_master_control_plane_psk(psk);
    if !is_master_psk {
        let existing_psk_hash = existing_record
            .as_ref()
            .map(|(h, _)| h.trim())
            .unwrap_or("");
        if !existing_psk_hash.is_empty() {
            if let Err(err_msg) = verify_enrolled_cluster_psk(psk, existing_psk_hash) {
                return Ok(RegisterWorkerResponse {
                    node_id: String::new(),
                    accepted: false,
                    message: err_msg.to_string(),
                });
            }
        } else {
            let token_hash = hash_psk_sha256(psk);
            let now_ts = Utc::now().timestamp();
            let consumed = tx
                .execute(
                    "UPDATE cluster_enrollment_tokens \
                     SET consumed_by = ?1 \
                     WHERE token_hash = ?2 AND consumed_by IS NULL AND expires_at >= ?3",
                    params![node_id, token_hash, now_ts],
                )
                .context("failed consuming cluster enrollment token")?;
            if consumed != 1 {
                return Ok(RegisterWorkerResponse {
                    node_id: String::new(),
                    accepted: false,
                    message: "invalid or expired cluster enrollment token".to_string(),
                });
            }
        }
    }

    let psk_hash = hash_psk_sha256(psk);
    let cert_fp_to_store = incoming_cert_fp.unwrap_or("");
    let now_rfc3339 = Utc::now().to_rfc3339();

    tx.execute(
        "INSERT INTO cluster_nodes (id, hostname, address, psk_hash, peer_cert_sha256, role, status, last_heartbeat, last_seen, enrolled_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'worker', 'online', ?6, ?6, ?6) \
         ON CONFLICT(id) DO UPDATE SET \
             hostname = excluded.hostname, \
             address = excluded.address, \
             psk_hash = excluded.psk_hash, \
             peer_cert_sha256 = CASE WHEN excluded.peer_cert_sha256 != '' THEN excluded.peer_cert_sha256 ELSE COALESCE(cluster_nodes.peer_cert_sha256, '') END, \
             role = 'worker', \
             status = 'online', \
             last_heartbeat = excluded.last_heartbeat, \
             last_seen = excluded.last_seen",
        params![node_id, hostname, address, psk_hash, cert_fp_to_store, now_rfc3339],
    )
    .context("failed upserting enrolled cluster worker")?;
    tx.commit()
        .context("failed committing cluster worker enrollment")?;

    let version = if req.version.trim().is_empty() {
        "4.0.0"
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
        "services": existing.as_ref().and_then(|v| v.get("services")).cloned().unwrap_or(serde_json::Value::Null),
        "services_status": if existing.as_ref().and_then(|v| v.get("services")).is_some_and(|value| value.is_array()) { "stale" } else { "unknown" },
        "services_observed_at": existing.as_ref().and_then(|v| v.get("services_observed_at")).cloned().unwrap_or(serde_json::Value::Null),
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
    process_worker_heartbeat_with_peer(req, &PeerTransportAuth::InternalCall)
}

/// Processes a worker metric heartbeat while enforcing per-node mTLS peer certificate pinning.
pub fn process_worker_heartbeat_with_peer(
    req: &WorkerHeartbeatRequest,
    peer_auth: &PeerTransportAuth,
) -> anyhow::Result<WorkerHeartbeatResponse> {
    let node_id = if !req.node_id.trim().is_empty() {
        req.node_id.trim().to_string()
    } else if !req.hostname.trim().is_empty() {
        format!("node-{}", req.hostname.trim())
    } else {
        anyhow::bail!("node_id is required");
    };

    ensure_cluster_schema();
    let incoming_cert_fp = peer_auth.mtls_cert_sha256();

    if req.psk.trim().is_empty() {
        let Some(cert_fp) = incoming_cert_fp else {
            anyhow::bail!("psk is required");
        };
        let Ok(conn) = af_db::get_conn() else {
            anyhow::bail!("cluster database unavailable");
        };
        let Ok((stored_hash, stored_cert)) = conn.query_row(
            "SELECT COALESCE(psk_hash, ''), COALESCE(peer_cert_sha256, '') FROM cluster_nodes WHERE id = ?1",
            params![node_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        ) else {
            anyhow::bail!("unauthenticated cluster worker: node is not enrolled");
        };
        if stored_hash.trim().is_empty() {
            anyhow::bail!("unauthenticated cluster worker: node is not enrolled");
        }
        if stored_cert.trim().is_empty()
            || !constant_time_eq(stored_cert.trim().as_bytes(), cert_fp.as_bytes())
        {
            anyhow::bail!("peer certificate does not match enrolled worker certificate");
        }
        let shared_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cluster_nodes WHERE peer_cert_sha256 = ?1",
                params![cert_fp],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if shared_count != 1 {
            anyhow::bail!(
                "shared worker client certificate requires x-cluster-psk header to disambiguate node identity"
            );
        }
    } else {
        if let Err(msg) = verify_cluster_psk(&node_id, &req.psk) {
            anyhow::bail!("{}", msg);
        }
        if !matches!(peer_auth, PeerTransportAuth::InternalCall) {
            let conn = af_db::get_conn().context("cluster database unavailable")?;
            let stored_cert: Option<String> = match conn.query_row(
                "SELECT COALESCE(peer_cert_sha256, '') FROM cluster_nodes WHERE id = ?1",
                params![node_id],
                |r| r.get::<_, String>(0),
            ) {
                Ok(val) => Some(val),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(e).context("failed querying enrolled worker certificate pin"),
            };
            if let Some(stored) = stored_cert {
                let stored_trimmed = stored.trim();
                if !stored_trimmed.is_empty() {
                    let matches_pin = incoming_cert_fp.is_some_and(|fp| {
                        constant_time_eq(stored_trimmed.as_bytes(), fp.as_bytes())
                    });
                    if !matches_pin {
                        anyhow::bail!(
                            "peer certificate does not match enrolled worker certificate"
                        );
                    }
                }
            }
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

    if let Ok(conn) = af_db::get_conn() {
        let cert_fp_str = incoming_cert_fp.unwrap_or("");
        let updated = conn
            .execute(
                "UPDATE cluster_nodes \
                 SET status = 'online', \
                     last_heartbeat = ?1, \
                     last_seen = ?1, \
                     cpu_usage = ?2, \
                     ram_usage = ?3, \
                     disk_usage = ?4, \
                     peer_cert_sha256 = CASE WHEN COALESCE(peer_cert_sha256, '') = '' AND ?5 != '' THEN ?5 ELSE COALESCE(peer_cert_sha256, '') END \
                 WHERE id = ?6",
                params![now_rfc3339, cpu_usage, ram_usage, disk_usage, cert_fp_str, node_id],
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
                 (id, hostname, address, psk_hash, peer_cert_sha256, role, status, last_heartbeat, last_seen, cpu_usage, ram_usage, disk_usage, enrolled_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 'worker', 'online', ?6, ?6, ?7, ?8, ?9, ?6)",
                params![
                    node_id,
                    hostname,
                    address,
                    psk_hash,
                    cert_fp_str,
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
        .or_else(|| {
            previous
                .as_ref()
                .and_then(|p| p.get("system_info"))
                .cloned()
        })
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
    let (services, services_status, services_observed_at) =
        merge_worker_service_inventory(req, previous.as_ref(), ts);

    let version_val = previous
        .as_ref()
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("4.0.0");

    let snapshot = serde_json::json!({
        "node_id": node_id,
        "hostname": if !req.hostname.is_empty() {
            serde_json::Value::String(req.hostname.clone())
        } else {
            previous.as_ref().and_then(|p| p.get("hostname")).cloned().unwrap_or(serde_json::Value::String(node_id.clone()))
        },
        "version": version_val,
        "status": "online",
        "timestamp": ts,
        "last_seen": now_rfc3339,
        "last_heartbeat": now_rfc3339,
        "cpu_usage": cpu_usage,
        "ram_usage": ram_usage,
        "disk_usage": disk_usage,
        "metrics": metrics_val,
        "services": services,
        "services_status": services_status,
        "services_observed_at": services_observed_at,
        "services_error": req.services_error,
        "system_info": sys_info,
    });

    cache_worker_metrics(&node_id, snapshot);

    for ack in &req.command_acks {
        let _ = acknowledge_worker_command(&node_id, ack);
    }

    let command = lease_next_worker_command(&node_id, ts, CLUSTER_COMMAND_LEASE_SECS);
    Ok(WorkerHeartbeatResponse {
        timestamp: ts,
        acknowledged: true,
        command,
    })
}

fn merge_worker_service_inventory(
    request: &WorkerHeartbeatRequest,
    previous: Option<&serde_json::Value>,
    now: i64,
) -> (serde_json::Value, &'static str, Option<i64>) {
    let status = request.services_status.as_deref().unwrap_or("fresh");
    if status == "fresh" {
        if let Some(services) = &request.services {
            return (
                serde_json::json!(services),
                "fresh",
                Some(request.services_observed_at.unwrap_or(now)),
            );
        }
    }
    let previous_services = previous
        .and_then(|snapshot| snapshot.get("services"))
        .filter(|services| services.is_array())
        .cloned();
    if let Some(services) = previous_services {
        let observed_at = previous
            .and_then(|snapshot| snapshot.get("services_observed_at"))
            .and_then(|value| value.as_i64());
        return (services, "stale", observed_at);
    }
    if status == "stale" && request.services_observed_at.is_some() {
        if let Some(services) = &request.services {
            return (
                serde_json::json!(services),
                "stale",
                request.services_observed_at,
            );
        }
    }
    (serde_json::Value::Null, "unknown", None)
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
// Cluster mTLS Transport, HTTP/2 gRPC (`cluster.ClusterService`), & HTTP JSON
// ─────────────────────────────────────────────────────────────────────────────

const MAX_PREAUTH_HEADER_BYTES: usize = 16 * 1024;
const MAX_CLUSTER_CONCURRENT_CONNS: usize = 64;
const MAX_CLUSTER_PEM_BYTES: u64 = 1024 * 1024;
const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_JSON_BODY_BYTES: usize = 4 * 1024 * 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const GRPC_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(65);

fn env_flag_true(name: &str) -> bool {
    env::var(name)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn is_loopback_host(host: &str) -> bool {
    let clean = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if clean.eq_ignore_ascii_case("localhost") {
        return true;
    }
    clean
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterBindConfig {
    pub host: String,
    pub port: String,
    pub bind_addr: String,
}

/// Resolves the cluster master bind address, defaulting to `127.0.0.1:50051` so the listener
/// is never exposed on `0.0.0.0` unless explicitly configured by the operator.
pub fn resolve_master_bind_config() -> MasterBindConfig {
    let port = non_empty_env("CLUSTER_GRPC_PORT")
        .or_else(|| non_empty_env("GRPC_PORT"))
        .unwrap_or_else(|| "50051".to_string());
    let host = non_empty_env("CLUSTER_GRPC_HOST")
        .or_else(|| non_empty_env("GRPC_HOST"))
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let bind_addr = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    MasterBindConfig {
        host,
        port,
        bind_addr,
    }
}

fn read_tls_pem_nofollow(path: &Path, label: &str) -> anyhow::Result<Vec<u8>> {
    if path.as_os_str().is_empty() {
        anyhow::bail!("{} path must not be empty", label);
    }

    #[cfg(unix)]
    let file = {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
        use std::path::Component;

        let Some(leaf_os) = path.file_name() else {
            anyhow::bail!(
                "{} at {} must include a regular filename",
                label,
                path.display()
            );
        };
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut cur_dir: Option<OwnedFd> = None;

        for comp in parent.components() {
            let dirfd = cur_dir.as_ref().map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
            match comp {
                Component::Prefix(_) | Component::ParentDir => {
                    anyhow::bail!(
                        "{} at {} must not contain parent-directory traversal",
                        label,
                        path.display()
                    );
                }
                Component::CurDir => {}
                Component::RootDir => {
                    let c_root = CString::new("/").context("invalid root path")?;
                    let fd = unsafe {
                        libc::open(
                            c_root.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(std::io::Error::last_os_error()).with_context(|| {
                            format!("failed opening root directory for {}", label)
                        });
                    }
                    cur_dir = Some(unsafe { OwnedFd::from_raw_fd(fd) });
                }
                Component::Normal(seg) => {
                    let c_seg = CString::new(seg.as_bytes()).with_context(|| {
                        format!("invalid path segment in {} at {}", label, path.display())
                    })?;
                    let fd = unsafe {
                        libc::openat(
                            dirfd,
                            c_seg.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(std::io::Error::last_os_error()).with_context(|| {
                            format!(
                                "failed opening ancestor directory for {} at {} (symlinked directories forbidden)",
                                label,
                                path.display()
                            )
                        });
                    }
                    cur_dir = Some(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        }

        let dirfd = cur_dir.as_ref().map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
        let c_leaf = CString::new(leaf_os.as_bytes())
            .with_context(|| format!("invalid filename for {} at {}", label, path.display()))?;
        let leaf_fd = unsafe {
            libc::openat(
                dirfd,
                c_leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if leaf_fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed opening {} at {} (symlinks forbidden)",
                    label,
                    path.display()
                )
            });
        }
        let opened = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(leaf_fd) });

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(opened.as_raw_fd(), &mut st) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("fstat failed for {} at {}", label, path.display()));
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            anyhow::bail!("{} at {} must be a regular file", label, path.display());
        }
        if (st.st_mode & 0o002) != 0 {
            anyhow::bail!("{} at {} must not be world-writable", label, path.display());
        }
        if st.st_size <= 0 {
            anyhow::bail!("{} at {} is empty", label, path.display());
        }
        if (st.st_size as u64) > MAX_CLUSTER_PEM_BYTES {
            anyhow::bail!(
                "{} at {} exceeds maximum PEM size ({} bytes)",
                label,
                path.display(),
                MAX_CLUSTER_PEM_BYTES
            );
        }
        opened
    };

    #[cfg(not(unix))]
    let file = {
        let meta = std::fs::symlink_metadata(path).with_context(|| {
            format!(
                "failed reading metadata for {} at {}",
                label,
                path.display()
            )
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            anyhow::bail!(
                "{} at {} must be a regular non-symlink file",
                label,
                path.display()
            );
        }
        if meta.len() == 0 || meta.len() > MAX_CLUSTER_PEM_BYTES {
            anyhow::bail!(
                "{} at {} has invalid size ({} bytes)",
                label,
                path.display(),
                meta.len()
            );
        }
        std::fs::File::open(path)
            .with_context(|| format!("failed opening {} at {}", label, path.display()))?
    };

    let mut bytes = Vec::new();
    file.take(MAX_CLUSTER_PEM_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed reading {} from {}", label, path.display()))?;
    if bytes.is_empty() {
        anyhow::bail!("{} at {} is empty", label, path.display());
    }
    if (bytes.len() as u64) > MAX_CLUSTER_PEM_BYTES {
        anyhow::bail!(
            "{} at {} exceeds {} bytes",
            label,
            path.display(),
            MAX_CLUSTER_PEM_BYTES
        );
    }
    Ok(bytes)
}

fn load_root_cert_store(ca_path: &Path, label: &str) -> anyhow::Result<RootCertStore> {
    let ca_bytes = read_tls_pem_nofollow(ca_path, label)?;
    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&ca_bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed parsing CA PEM certificates in {}",
                ca_path.display()
            )
        })?;
    if ca_certs.is_empty() {
        anyhow::bail!("no PEM CA certificates found in {}", ca_path.display());
    }
    let mut store = RootCertStore::empty();
    let (added, _) = store.add_parsable_certificates(ca_certs);
    if added == 0 {
        anyhow::bail!(
            "failed adding any valid CA certificate from {}",
            ca_path.display()
        );
    }
    Ok(store)
}

fn load_cert_chain_and_key(
    cert_path: &Path,
    cert_label: &str,
    key_path: &Path,
    key_label: &str,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_bytes = read_tls_pem_nofollow(cert_path, cert_label)?;
    let key_bytes = read_tls_pem_nofollow(key_path, key_label)?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed parsing PEM certificate chain in {}",
                cert_path.display()
            )
        })?;
    if certs.is_empty() {
        anyhow::bail!("no PEM certificates found in {}", cert_path.display());
    }
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)
        .with_context(|| format!("failed parsing PEM private key in {}", key_path.display()))?;
    Ok((certs, key))
}

/// Builds a TLS 1.3 mutual-TLS (`RequireAndVerifyClientCert`) server acceptor with ALPN `h2` + `http/1.1`.
pub fn build_master_mtls_acceptor(
    ca_path: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<TlsAcceptor> {
    let root_store = load_root_cert_store(ca_path, "CLUSTER_CA_CERT")?;
    let (server_certs, server_key) = load_cert_chain_and_key(
        cert_path,
        "CLUSTER_SERVER_CERT",
        key_path,
        "CLUSTER_SERVER_KEY",
    )?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(root_store), Arc::clone(&provider))
            .build()
            .context("failed building mandatory cluster mTLS client certificate verifier")?;

    let mut server_cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed enforcing TLS 1.3 minimum version for cluster mTLS server")?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .context("invalid cluster server certificate or private key")?;
    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_cfg)))
}

/// Builds a TLS 1.3 mutual-TLS client connector with ALPN `h2` + `http/1.1`.
pub fn build_worker_mtls_connector(
    ca_path: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<TlsConnector> {
    let root_store = load_root_cert_store(ca_path, "CLUSTER_CA_CERT")?;
    let (client_certs, client_key) = load_cert_chain_and_key(
        cert_path,
        "CLUSTER_CLIENT_CERT",
        key_path,
        "CLUSTER_CLIENT_KEY",
    )?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed enforcing TLS 1.3 minimum version for cluster mTLS worker")?
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .context("invalid cluster worker client certificate or private key")?;
    client_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

#[derive(Clone)]
pub enum MasterTransportSecurity {
    Mtls {
        acceptor: TlsAcceptor,
        admin_cert_sha256: Option<String>,
    },
    InsecureLoopback,
}

fn load_pinned_admin_client_cert_sha256() -> anyhow::Result<Option<String>> {
    let Some(admin_cert_path) = non_empty_env("CLUSTER_ADMIN_CLIENT_CERT") else {
        return Ok(None);
    };
    let pem_bytes =
        read_tls_pem_nofollow(Path::new(&admin_cert_path), "CLUSTER_ADMIN_CLIENT_CERT")?;
    let mut certs = CertificateDer::pem_slice_iter(&pem_bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed parsing CLUSTER_ADMIN_CLIENT_CERT PEM at {}",
                admin_cert_path
            )
        })?;
    let Some(leaf) = certs.drain(..).next() else {
        anyhow::bail!(
            "no PEM certificate found in CLUSTER_ADMIN_CLIENT_CERT at {}",
            admin_cert_path
        );
    };
    Ok(Some(hex::encode(Sha256::digest(leaf.as_ref()))))
}

/// Evaluates `CLUSTER_CA_CERT`, `CLUSTER_SERVER_CERT`, and `CLUSTER_SERVER_KEY` (plus optional
/// exclusive `CLUSTER_ADMIN_CLIENT_CERT` pin).
/// Enforces mandatory TLS 1.3 mTLS in production; only allows unencrypted loopback when all three
/// cert variables are unset, `CLUSTER_ALLOW_INSECURE_LOOPBACK=true`, and `bind_host` is loopback.
pub fn load_master_transport_security(bind_host: &str) -> anyhow::Result<MasterTransportSecurity> {
    let ca = non_empty_env("CLUSTER_CA_CERT");
    let cert = non_empty_env("CLUSTER_SERVER_CERT");
    let key = non_empty_env("CLUSTER_SERVER_KEY");

    match (ca, cert, key) {
        (Some(ca_path), Some(cert_path), Some(key_path)) => {
            let acceptor = build_master_mtls_acceptor(
                Path::new(&ca_path),
                Path::new(&cert_path),
                Path::new(&key_path),
            )?;
            let admin_cert_sha256 = load_pinned_admin_client_cert_sha256()?;
            Ok(MasterTransportSecurity::Mtls {
                acceptor,
                admin_cert_sha256,
            })
        }
        (None, None, None) => {
            if env_flag_true("CLUSTER_ALLOW_INSECURE_LOOPBACK") && is_loopback_host(bind_host) {
                tracing::warn!(
                    bind_host = %bind_host,
                    "CLUSTER_ALLOW_INSECURE_LOOPBACK=true enabled without mTLS certificates on loopback"
                );
                Ok(MasterTransportSecurity::InsecureLoopback)
            } else {
                anyhow::bail!(
                    "CLUSTER_CA_CERT, CLUSTER_SERVER_CERT, and CLUSTER_SERVER_KEY must be set to enable secure cluster mTLS (refusing unencrypted listener on '{}')",
                    bind_host
                )
            }
        }
        _ => anyhow::bail!(
            "CLUSTER_CA_CERT, CLUSTER_SERVER_CERT, and CLUSTER_SERVER_KEY must all be set together for cluster mTLS"
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure-Rust `cluster.proto` Wire Codec & gRPC HTTP/2 Framing
// ─────────────────────────────────────────────────────────────────────────────

enum ClusterBody {
    Json(Full<Bytes>),
    Grpc(mpsc::Receiver<Result<Frame<Bytes>, Infallible>>),
}

impl HyperBody for ClusterBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ClusterBody::Json(full) => Pin::new(full).poll_frame(cx),
            ClusterBody::Grpc(rx) => rx.poll_recv(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ClusterBody::Json(full) => full.is_end_stream(),
            ClusterBody::Grpc(_) => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            ClusterBody::Json(full) => full.size_hint(),
            ClusterBody::Grpc(_) => SizeHint::default(),
        }
    }
}

#[derive(Debug)]
struct GrpcError {
    code: u8,
    message: String,
}

impl GrpcError {
    fn invalid_argument(msg: impl Into<String>) -> Self {
        Self {
            code: 3,
            message: msg.into(),
        }
    }
    fn resource_exhausted(msg: impl Into<String>) -> Self {
        Self {
            code: 8,
            message: msg.into(),
        }
    }
    fn unimplemented(msg: impl Into<String>) -> Self {
        Self {
            code: 12,
            message: msg.into(),
        }
    }
    fn internal(msg: impl Into<String>) -> Self {
        Self {
            code: 13,
            message: msg.into(),
        }
    }
    fn unauthenticated(msg: impl Into<String>) -> Self {
        Self {
            code: 16,
            message: msg.into(),
        }
    }
}

fn encode_grpc_data_frame(proto_bytes: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(5 + proto_bytes.len());
    out.push(0u8);
    out.extend_from_slice(&(proto_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(proto_bytes);
    Bytes::from(out)
}

fn build_grpc_trailers(code: u8, message: Option<&str>) -> HeaderMap {
    let mut trailers = HeaderMap::new();
    let code_str = code.to_string();
    if let Ok(val) = HeaderValue::from_str(&code_str) {
        trailers.insert("grpc-status", val);
    }
    if let Some(msg) = message {
        let sanitized: String = msg
            .chars()
            .filter(|c| c.is_ascii() && !c.is_ascii_control())
            .take(512)
            .collect();
        if !sanitized.is_empty() {
            if let Ok(val) = HeaderValue::from_str(&sanitized) {
                trailers.insert("grpc-message", val);
            }
        }
    }
    trailers
}

fn grpc_unary_ok_response(proto_bytes: &[u8]) -> Response<ClusterBody> {
    let (tx, rx) = mpsc::channel(2);
    let data_frame = encode_grpc_data_frame(proto_bytes);
    let _ = tx.try_send(Ok(Frame::data(data_frame)));
    let _ = tx.try_send(Ok(Frame::trailers(build_grpc_trailers(0, None))));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(ClusterBody::Grpc(rx))
        .unwrap()
}

fn grpc_error_response(err: GrpcError) -> Response<ClusterBody> {
    let (tx, rx) = mpsc::channel(1);
    let _ = tx.try_send(Ok(Frame::trailers(build_grpc_trailers(
        err.code,
        Some(&err.message),
    ))));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(ClusterBody::Grpc(rx))
        .unwrap()
}

struct GrpcFrameDecoder {
    incoming: Incoming,
    buf: Vec<u8>,
}

impl GrpcFrameDecoder {
    fn new(incoming: Incoming) -> Self {
        Self {
            incoming,
            buf: Vec::new(),
        }
    }

    async fn next_message(&mut self) -> Result<Option<Vec<u8>>, GrpcError> {
        loop {
            if self.buf.len() >= 5 {
                let compressed = self.buf[0];
                if compressed != 0 {
                    return Err(GrpcError::unimplemented(
                        "compressed gRPC frames are not supported",
                    ));
                }
                let msg_len =
                    u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]])
                        as usize;
                if msg_len > MAX_GRPC_MESSAGE_BYTES {
                    return Err(GrpcError::resource_exhausted(
                        "gRPC frame exceeds 4 MiB limit",
                    ));
                }
                if self.buf.len() >= 5 + msg_len {
                    let payload = self.buf[5..5 + msg_len].to_vec();
                    self.buf.drain(..5 + msg_len);
                    return Ok(Some(payload));
                }
            }

            let next_frame = tokio::time::timeout(GRPC_STREAM_IDLE_TIMEOUT, self.incoming.frame())
                .await
                .map_err(|_| GrpcError::internal("gRPC stream read timed out"))?;

            match next_frame {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if self.buf.len().saturating_add(data.len())
                            > MAX_GRPC_MESSAGE_BYTES + 64 * 1024
                        {
                            return Err(GrpcError::resource_exhausted(
                                "gRPC buffer exceeds maximum size",
                            ));
                        }
                        self.buf.extend_from_slice(&data);
                    }
                }
                Some(Err(e)) => {
                    return Err(GrpcError::internal(format!("gRPC transport error: {}", e)));
                }
                None => {
                    if self.buf.is_empty() {
                        return Ok(None);
                    }
                    return Err(GrpcError::invalid_argument("truncated gRPC frame"));
                }
            }
        }
    }
}

fn pb_encode_varint(buf: &mut Vec<u8>, mut val: u64) {
    while val >= 0x80 {
        buf.push(((val as u8) & 0x7f) | 0x80);
        val >>= 7;
    }
    buf.push(val as u8);
}

fn pb_encode_tag(buf: &mut Vec<u8>, field_num: u32, wire_type: u8) {
    pb_encode_varint(buf, ((field_num as u64) << 3) | (wire_type as u64));
}

fn pb_encode_string(buf: &mut Vec<u8>, field_num: u32, val: &str) {
    if !val.is_empty() {
        pb_encode_tag(buf, field_num, 2);
        pb_encode_varint(buf, val.len() as u64);
        buf.extend_from_slice(val.as_bytes());
    }
}

fn pb_encode_bool(buf: &mut Vec<u8>, field_num: u32, val: bool) {
    if val {
        pb_encode_tag(buf, field_num, 0);
        buf.push(1u8);
    }
}

fn pb_encode_int64(buf: &mut Vec<u8>, field_num: u32, val: i64) {
    if val != 0 {
        pb_encode_tag(buf, field_num, 0);
        pb_encode_varint(buf, val as u64);
    }
}

#[cfg(test)]
fn pb_encode_int32(buf: &mut Vec<u8>, field_num: u32, val: i32) {
    if val != 0 {
        pb_encode_tag(buf, field_num, 0);
        pb_encode_varint(buf, (val as i64) as u64);
    }
}

fn pb_encode_f64(buf: &mut Vec<u8>, field_num: u32, val: f64) {
    if val != 0.0 {
        pb_encode_tag(buf, field_num, 1);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

fn pb_encode_message_field(buf: &mut Vec<u8>, field_num: u32, msg_bytes: &[u8]) {
    pb_encode_tag(buf, field_num, 2);
    pb_encode_varint(buf, msg_bytes.len() as u64);
    buf.extend_from_slice(msg_bytes);
}

fn pb_decode_varint(input: &[u8], pos: &mut usize) -> anyhow::Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        if *pos >= input.len() {
            anyhow::bail!("unexpected EOF decoding protobuf varint");
        }
        let byte = input[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    anyhow::bail!("protobuf varint overflow")
}

fn pb_decode_f64(input: &[u8], pos: &mut usize) -> anyhow::Result<f64> {
    let end = pos
        .checked_add(8)
        .ok_or_else(|| anyhow::anyhow!("protobuf f64 offset overflow"))?;
    if end > input.len() {
        anyhow::bail!("unexpected EOF decoding protobuf double");
    }
    let bytes: [u8; 8] = input[*pos..end].try_into()?;
    *pos = end;
    Ok(f64::from_le_bytes(bytes))
}

fn pb_decode_bytes<'a>(input: &'a [u8], pos: &mut usize) -> anyhow::Result<&'a [u8]> {
    let len = usize::try_from(pb_decode_varint(input, pos)?)
        .map_err(|_| anyhow::anyhow!("protobuf length exceeds usize"))?;
    let end = pos
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("protobuf slice overflow"))?;
    if end > input.len() {
        anyhow::bail!("unexpected EOF decoding protobuf length-delimited field");
    }
    let slice = &input[*pos..end];
    *pos = end;
    Ok(slice)
}

fn pb_decode_string(input: &[u8], pos: &mut usize) -> anyhow::Result<String> {
    let raw = pb_decode_bytes(input, pos)?;
    Ok(std::str::from_utf8(raw)
        .context("invalid UTF-8 in protobuf string")?
        .to_string())
}

fn pb_skip_field(input: &[u8], pos: &mut usize, wire_type: u8) -> anyhow::Result<()> {
    match wire_type {
        0 => {
            let _ = pb_decode_varint(input, pos)?;
        }
        1 => {
            let end = pos
                .checked_add(8)
                .ok_or_else(|| anyhow::anyhow!("protobuf skip64 overflow"))?;
            if end > input.len() {
                anyhow::bail!("unexpected EOF skipping 64-bit protobuf field");
            }
            *pos = end;
        }
        2 => {
            let _ = pb_decode_bytes(input, pos)?;
        }
        5 => {
            let end = pos
                .checked_add(4)
                .ok_or_else(|| anyhow::anyhow!("protobuf skip32 overflow"))?;
            if end > input.len() {
                anyhow::bail!("unexpected EOF skipping 32-bit protobuf field");
            }
            *pos = end;
        }
        other => anyhow::bail!("unsupported protobuf wire type {}", other),
    }
    Ok(())
}

fn decode_proto_system_info(input: &[u8]) -> anyhow::Result<WorkerSystemInfo> {
    let mut info = WorkerSystemInfo::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => info.os = pb_decode_string(input, &mut pos)?,
            (2, 2) => info.arch = pb_decode_string(input, &mut pos)?,
            (3, 0) => info.cpu_cores = pb_decode_varint(input, &mut pos)? as i32,
            (4, 0) => info.total_memory_bytes = pb_decode_varint(input, &mut pos)? as i64,
            (5, 0) => info.total_disk_bytes = pb_decode_varint(input, &mut pos)? as i64,
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(info)
}

fn decode_proto_register_request(input: &[u8]) -> anyhow::Result<RegisterWorkerRequest> {
    let mut req = RegisterWorkerRequest::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => req.hostname = pb_decode_string(input, &mut pos)?,
            (2, 2) => req.address = pb_decode_string(input, &mut pos)?,
            (3, 2) => req.psk = pb_decode_string(input, &mut pos)?,
            (4, 2) => req.version = pb_decode_string(input, &mut pos)?,
            (5, 2) => {
                let sub = pb_decode_bytes(input, &mut pos)?;
                req.system_info = Some(decode_proto_system_info(sub)?);
            }
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(req)
}

fn encode_proto_register_response(resp: &RegisterWorkerResponse) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_string(&mut buf, 1, &resp.node_id);
    pb_encode_bool(&mut buf, 2, resp.accepted);
    pb_encode_string(&mut buf, 3, &resp.message);
    buf
}

#[derive(Debug, Clone, Default)]
struct ProtoWorkerMetrics {
    cpu_usage: f64,
    memory_used_gb: f64,
    memory_total_gb: f64,
    disk_used_gb: f64,
    disk_total_gb: f64,
    network_rx_speed: String,
    network_tx_speed: String,
    uptime: String,
    load_average: Vec<f64>,
}

fn decode_proto_worker_metrics(input: &[u8]) -> anyhow::Result<ProtoWorkerMetrics> {
    let mut m = ProtoWorkerMetrics::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 1) => m.cpu_usage = pb_decode_f64(input, &mut pos)?,
            (2, 1) => m.memory_used_gb = pb_decode_f64(input, &mut pos)?,
            (3, 1) => m.memory_total_gb = pb_decode_f64(input, &mut pos)?,
            (4, 1) => m.disk_used_gb = pb_decode_f64(input, &mut pos)?,
            (5, 1) => m.disk_total_gb = pb_decode_f64(input, &mut pos)?,
            (6, 2) => m.network_rx_speed = pb_decode_string(input, &mut pos)?,
            (7, 2) => m.network_tx_speed = pb_decode_string(input, &mut pos)?,
            (8, 2) => m.uptime = pb_decode_string(input, &mut pos)?,
            (9, 2) => {
                let packed = pb_decode_bytes(input, &mut pos)?;
                let mut sub_pos = 0usize;
                while sub_pos < packed.len() && m.load_average.len() < 16 {
                    m.load_average.push(pb_decode_f64(packed, &mut sub_pos)?);
                }
            }
            (9, 1) => {
                if m.load_average.len() < 16 {
                    m.load_average.push(pb_decode_f64(input, &mut pos)?);
                } else {
                    let _ = pb_decode_f64(input, &mut pos)?;
                }
            }
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(m)
}

fn encode_proto_worker_metrics(m: &ProtoWorkerMetrics) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_f64(&mut buf, 1, m.cpu_usage);
    pb_encode_f64(&mut buf, 2, m.memory_used_gb);
    pb_encode_f64(&mut buf, 3, m.memory_total_gb);
    pb_encode_f64(&mut buf, 4, m.disk_used_gb);
    pb_encode_f64(&mut buf, 5, m.disk_total_gb);
    pb_encode_string(&mut buf, 6, &m.network_rx_speed);
    pb_encode_string(&mut buf, 7, &m.network_tx_speed);
    pb_encode_string(&mut buf, 8, &m.uptime);
    if !m.load_average.is_empty() {
        pb_encode_tag(&mut buf, 9, 2);
        pb_encode_varint(&mut buf, (m.load_average.len() * 8) as u64);
        for &val in &m.load_average {
            buf.extend_from_slice(&val.to_le_bytes());
        }
    }
    buf
}

fn decode_proto_service_status(input: &[u8]) -> anyhow::Result<WorkerService> {
    let mut svc = WorkerService::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => svc.name = pb_decode_string(input, &mut pos)?,
            (2, 2) => svc.status = pb_decode_string(input, &mut pos)?,
            (3, 2) => svc.uptime = pb_decode_string(input, &mut pos)?,
            (4, 2) => svc.managed_by = pb_decode_string(input, &mut pos)?,
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(svc)
}

fn encode_proto_service_status(svc: &WorkerService) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_string(&mut buf, 1, &svc.name);
    pb_encode_string(&mut buf, 2, &svc.status);
    pb_encode_string(&mut buf, 3, &svc.uptime);
    pb_encode_string(&mut buf, 4, &svc.managed_by);
    buf
}

#[derive(Debug, Default)]
struct ProtoHeartbeatPing {
    node_id: String,
    timestamp: i64,
    metrics: Option<ProtoWorkerMetrics>,
    services: Vec<WorkerService>,
}

fn decode_proto_heartbeat_ping(input: &[u8]) -> anyhow::Result<ProtoHeartbeatPing> {
    let mut ping = ProtoHeartbeatPing::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => ping.node_id = pb_decode_string(input, &mut pos)?,
            (2, 0) => ping.timestamp = pb_decode_varint(input, &mut pos)? as i64,
            (3, 2) => {
                let sub = pb_decode_bytes(input, &mut pos)?;
                ping.metrics = Some(decode_proto_worker_metrics(sub)?);
            }
            (4, 2) => {
                let sub = pb_decode_bytes(input, &mut pos)?;
                if ping.services.len() < 256 {
                    ping.services.push(decode_proto_service_status(sub)?);
                }
            }
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(ping)
}

fn encode_proto_remote_command(cmd: &PendingWorkerCommand) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_string(&mut buf, 1, &cmd.id);
    pb_encode_string(&mut buf, 2, &cmd.cmd_type);
    let mut keys: Vec<&String> = cmd.params.keys().collect();
    keys.sort();
    for k in keys {
        if let Some(v) = cmd.params.get(k) {
            let mut entry = Vec::new();
            pb_encode_string(&mut entry, 1, k);
            pb_encode_string(&mut entry, 2, v);
            pb_encode_message_field(&mut buf, 3, &entry);
        }
    }
    buf
}

fn encode_proto_heartbeat_pong(resp: &WorkerHeartbeatResponse) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_int64(&mut buf, 1, resp.timestamp);
    pb_encode_bool(&mut buf, 2, resp.acknowledged);
    if let Some(cmd) = &resp.command {
        let cmd_bytes = encode_proto_remote_command(cmd);
        pb_encode_message_field(&mut buf, 3, &cmd_bytes);
    }
    buf
}

fn decode_proto_map_entry(input: &[u8]) -> anyhow::Result<(String, String)> {
    let mut k = String::new();
    let mut v = String::new();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => k = pb_decode_string(input, &mut pos)?,
            (2, 2) => v = pb_decode_string(input, &mut pos)?,
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok((k, v))
}

#[derive(Debug, Default)]
struct ProtoMetricsRequest {
    node_id: String,
}

fn decode_proto_metrics_request(input: &[u8]) -> anyhow::Result<ProtoMetricsRequest> {
    let mut req = ProtoMetricsRequest::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => req.node_id = pb_decode_string(input, &mut pos)?,
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(req)
}

fn encode_proto_metrics_response(
    node_id: &str,
    metrics: Option<&ProtoWorkerMetrics>,
    services: &[WorkerService],
) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_string(&mut buf, 1, node_id);
    if let Some(m) = metrics {
        let m_bytes = encode_proto_worker_metrics(m);
        pb_encode_message_field(&mut buf, 2, &m_bytes);
    }
    for svc in services {
        let svc_bytes = encode_proto_service_status(svc);
        pb_encode_message_field(&mut buf, 3, &svc_bytes);
    }
    buf
}

#[derive(Debug, Default)]
struct ProtoCommandRequest {
    node_id: String,
    command_id: String,
    cmd_type: String,
    params: HashMap<String, String>,
}

fn decode_proto_command_request(input: &[u8]) -> anyhow::Result<ProtoCommandRequest> {
    let mut req = ProtoCommandRequest::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => req.node_id = pb_decode_string(input, &mut pos)?,
            (2, 2) => req.command_id = pb_decode_string(input, &mut pos)?,
            (3, 2) => req.cmd_type = pb_decode_string(input, &mut pos)?,
            (4, 2) => {
                let sub = pb_decode_bytes(input, &mut pos)?;
                if req.params.len() < 64 {
                    let (k, v) = decode_proto_map_entry(sub)?;
                    req.params.insert(k, v);
                }
            }
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(req)
}

fn encode_proto_command_response(
    command_id: &str,
    success: bool,
    output: &str,
    error: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_string(&mut buf, 1, command_id);
    pb_encode_bool(&mut buf, 2, success);
    pb_encode_string(&mut buf, 3, output);
    pb_encode_string(&mut buf, 4, error);
    buf
}

fn extract_psk_from_headers(headers: &HeaderMap) -> String {
    if let Some(val) = headers.get("x-cluster-psk").and_then(|v| v.to_str().ok()) {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(val) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = val
            .trim()
            .strip_prefix("Bearer ")
            .or_else(|| val.trim().strip_prefix("bearer "))
        {
            return token.trim().to_string();
        }
    }
    String::new()
}

fn heartbeat_request_from_proto(
    ping: ProtoHeartbeatPing,
    header_psk: &str,
) -> WorkerHeartbeatRequest {
    let (cpu_usage, ram_usage, disk_usage, metrics_json) = if let Some(m) = &ping.metrics {
        let ram_pct = if m.memory_total_gb > 0.0 {
            af_hardware::sanitize_f64(
                ((m.memory_used_gb / m.memory_total_gb) * 1000.0).round() / 10.0,
            )
        } else {
            0.0
        };
        let disk_pct = if m.disk_total_gb > 0.0 {
            af_hardware::sanitize_f64(((m.disk_used_gb / m.disk_total_gb) * 1000.0).round() / 10.0)
        } else {
            0.0
        };
        let cpu = af_hardware::sanitize_f64(m.cpu_usage);
        let metrics_val = serde_json::json!({
            "cpu_usage": cpu,
            "ram_usage": ram_pct,
            "disk_usage": disk_pct,
            "mem_used_gb": af_hardware::sanitize_f64(m.memory_used_gb),
            "mem_total_gb": af_hardware::sanitize_f64(m.memory_total_gb),
            "disk_used_gb": af_hardware::sanitize_f64(m.disk_used_gb),
            "disk_total_gb": af_hardware::sanitize_f64(m.disk_total_gb),
            "memory": {
                "used": af_hardware::sanitize_f64(m.memory_used_gb),
                "total": af_hardware::sanitize_f64(m.memory_total_gb),
            },
            "disk_space": {
                "used": af_hardware::sanitize_f64(m.disk_used_gb),
                "total": af_hardware::sanitize_f64(m.disk_total_gb),
            },
            "net_rx_speed": m.network_rx_speed,
            "net_tx_speed": m.network_tx_speed,
            "uptime": m.uptime,
            "load_average": m.load_average,
        });
        (Some(cpu), Some(ram_pct), Some(disk_pct), metrics_val)
    } else {
        (None, None, None, serde_json::Value::Null)
    };

    let (services, services_status, services_observed_at) = if ping.services.is_empty() {
        (None, Some("unknown".to_string()), None)
    } else {
        let obs_ts = if ping.timestamp > 0 {
            ping.timestamp
        } else {
            Utc::now().timestamp()
        };
        (Some(ping.services), Some("fresh".to_string()), Some(obs_ts))
    };

    WorkerHeartbeatRequest {
        node_id: ping.node_id,
        psk: header_psk.to_string(),
        timestamp: ping.timestamp,
        cpu_usage,
        ram_usage,
        disk_usage,
        metrics: metrics_json,
        services,
        services_status,
        services_observed_at,
        ..Default::default()
    }
}

fn cached_snapshot_to_proto_metrics(
    snapshot: &serde_json::Value,
) -> (Option<ProtoWorkerMetrics>, Vec<WorkerService>) {
    let metrics_obj = snapshot.get("metrics");
    let proto_metrics = metrics_obj.map(|m| ProtoWorkerMetrics {
        cpu_usage: snapshot
            .get("cpu_usage")
            .and_then(|v| v.as_f64())
            .or_else(|| m.get("cpu_usage").and_then(|v| v.as_f64()))
            .unwrap_or(0.0),
        memory_used_gb: m
            .get("mem_used_gb")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                m.get("memory")
                    .and_then(|x| x.get("used"))
                    .and_then(|v| v.as_f64())
            })
            .unwrap_or(0.0),
        memory_total_gb: m
            .get("mem_total_gb")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                m.get("memory")
                    .and_then(|x| x.get("total"))
                    .and_then(|v| v.as_f64())
            })
            .unwrap_or(0.0),
        disk_used_gb: m
            .get("disk_used_gb")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                m.get("disk_space")
                    .and_then(|x| x.get("used"))
                    .and_then(|v| v.as_f64())
            })
            .unwrap_or(0.0),
        disk_total_gb: m
            .get("disk_total_gb")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                m.get("disk_space")
                    .and_then(|x| x.get("total"))
                    .and_then(|v| v.as_f64())
            })
            .unwrap_or(0.0),
        network_rx_speed: m
            .get("net_rx_speed")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        network_tx_speed: m
            .get("net_tx_speed")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        uptime: m
            .get("uptime")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        load_average: m
            .get("load_average")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_f64()).collect())
            .unwrap_or_default(),
    });

    let services = snapshot
        .get("services")
        .and_then(|v| serde_json::from_value::<Vec<WorkerService>>(v.clone()).ok())
        .unwrap_or_default();

    (proto_metrics, services)
}

fn der_read_tlv<'a>(input: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    if *pos >= input.len() {
        return None;
    }
    let tag = input[*pos];
    *pos += 1;
    if (tag & 0x1f) == 0x1f {
        // High-tag-number form is never used in X.509 TBSCertificate / Subject Name headers
        return None;
    }
    if *pos >= input.len() {
        return None;
    }
    let first_len = input[*pos];
    *pos += 1;
    let len = if (first_len & 0x80) == 0 {
        first_len as usize
    } else {
        let num_octets = (first_len & 0x7f) as usize;
        if num_octets == 0 || num_octets > 4 || *pos + num_octets > input.len() {
            return None;
        }
        let mut acc = 0usize;
        for &b in &input[*pos..*pos + num_octets] {
            acc = (acc << 8) | (b as usize);
        }
        *pos += num_octets;
        acc
    };
    let end = pos.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    let val = &input[*pos..end];
    *pos = end;
    Some((tag, val))
}

/// Extracts the leaf certificate's X.509 `TBSCertificate.subject` CommonName (`OID 2.5.4.3`),
/// strictly skipping `issuer` and `extensions` so neither CA CNs nor SANs can be confused for Subject CN.
fn extract_x509_subject_cn(cert_der: &[u8]) -> Option<String> {
    let mut top_pos = 0usize;
    let (cert_tag, cert_body) = der_read_tlv(cert_der, &mut top_pos)?;
    if cert_tag != 0x30 {
        return None;
    }
    let mut cert_pos = 0usize;
    let (tbs_tag, tbs_body) = der_read_tlv(cert_body, &mut cert_pos)?;
    if tbs_tag != 0x30 {
        return None;
    }
    let mut tbs_pos = 0usize;
    let (first_tag, _) = der_read_tlv(tbs_body, &mut tbs_pos)?;
    if first_tag == 0xa0 {
        // Explicit v3 [0] version present; next 4 elements are serialNumber, signature, issuer, validity
        let _serial = der_read_tlv(tbs_body, &mut tbs_pos)?;
    }
    // Skip signature, issuer, validity
    let _sig = der_read_tlv(tbs_body, &mut tbs_pos)?;
    let _issuer = der_read_tlv(tbs_body, &mut tbs_pos)?;
    let _validity = der_read_tlv(tbs_body, &mut tbs_pos)?;
    let (subj_tag, subj_body) = der_read_tlv(tbs_body, &mut tbs_pos)?;
    if subj_tag != 0x30 {
        return None;
    }

    let mut rdn_pos = 0usize;
    let mut last_cn: Option<String> = None;
    while rdn_pos < subj_body.len() {
        let (set_tag, set_body) = der_read_tlv(subj_body, &mut rdn_pos)?;
        if set_tag != 0x31 {
            continue;
        }
        let mut attr_pos = 0usize;
        while attr_pos < set_body.len() {
            let (seq_tag, seq_body) = der_read_tlv(set_body, &mut attr_pos)?;
            if seq_tag != 0x30 {
                continue;
            }
            let mut kv_pos = 0usize;
            let Some((oid_tag, oid_bytes)) = der_read_tlv(seq_body, &mut kv_pos) else {
                continue;
            };
            let Some((val_tag, val_bytes)) = der_read_tlv(seq_body, &mut kv_pos) else {
                continue;
            };
            // OID 2.5.4.3 (id-at-commonName) == 55 04 03
            if oid_tag == 0x06
                && oid_bytes == [0x55, 0x04, 0x03]
                && matches!(val_tag, 0x0c | 0x13 | 0x14 | 0x16)
            {
                if let Ok(s) = std::str::from_utf8(val_bytes) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        last_cn = Some(trimmed.to_string());
                    }
                }
            }
        }
    }
    last_cn
}

fn inspect_mtls_peer(
    tls_stream: &tokio_rustls::server::TlsStream<TcpStream>,
    pinned_admin_sha256: Option<&str>,
) -> anyhow::Result<PeerTransportAuth> {
    let (_, server_conn) = tls_stream.get_ref();
    let certs = server_conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("missing peer certificate chain after mTLS handshake"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty peer certificate chain after mTLS handshake"))?;
    let cert_sha256 = hex::encode(Sha256::digest(leaf.as_ref()));
    let subject_cn = extract_x509_subject_cn(leaf.as_ref());

    let is_admin_cert = if let Some(expected) = pinned_admin_sha256 {
        constant_time_eq(cert_sha256.as_bytes(), expected.as_bytes())
    } else {
        subject_cn.as_deref().is_some_and(|cn| {
            cn.eq_ignore_ascii_case("aetherflow-master")
                || cn.eq_ignore_ascii_case("aetherflow-control-plane")
                || cn.eq_ignore_ascii_case("aetherflow-admin")
        })
    };

    Ok(PeerTransportAuth::Mtls {
        cert_sha256,
        subject_cn,
        is_admin_cert,
    })
}

async fn handle_grpc_request(
    path: &str,
    header_psk: String,
    incoming: Incoming,
    peer_auth: PeerTransportAuth,
) -> Response<ClusterBody> {
    match path {
        "/cluster.ClusterService/RegisterWorker" => {
            let mut decoder = GrpcFrameDecoder::new(incoming);
            let payload = match decoder.next_message().await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    return grpc_error_response(GrpcError::invalid_argument(
                        "missing RegisterRequest frame",
                    ))
                }
                Err(err) => return grpc_error_response(err),
            };
            let mut req = match decode_proto_register_request(&payload) {
                Ok(parsed) => parsed,
                Err(e) => return grpc_error_response(GrpcError::invalid_argument(e.to_string())),
            };
            if req.psk.is_empty() && !header_psk.is_empty() {
                req.psk = header_psk;
            }
            match register_worker_node_with_peer(&req, &peer_auth) {
                Ok(resp) => {
                    let encoded = encode_proto_register_response(&resp);
                    grpc_unary_ok_response(&encoded)
                }
                Err(e) => {
                    grpc_error_response(GrpcError::internal(format!("enrollment failed: {}", e)))
                }
            }
        }
        "/cluster.ClusterService/Heartbeat" => {
            let (tx, rx) = mpsc::channel(16);
            tokio::spawn(async move {
                let mut decoder = GrpcFrameDecoder::new(incoming);
                loop {
                    match decoder.next_message().await {
                        Ok(Some(payload)) => {
                            let ping = match decode_proto_heartbeat_ping(&payload) {
                                Ok(p) => p,
                                Err(e) => {
                                    let _ = tx
                                        .send(Ok(Frame::trailers(build_grpc_trailers(
                                            3,
                                            Some(&e.to_string()),
                                        ))))
                                        .await;
                                    return;
                                }
                            };
                            let hb_req = heartbeat_request_from_proto(ping, &header_psk);
                            match process_worker_heartbeat_with_peer(&hb_req, &peer_auth) {
                                Ok(pong) => {
                                    let encoded = encode_proto_heartbeat_pong(&pong);
                                    if tx
                                        .send(Ok(Frame::data(encode_grpc_data_frame(&encoded))))
                                        .await
                                        .is_err()
                                    {
                                        return;
                                    }
                                }
                                Err(e) => {
                                    let _ = tx
                                        .send(Ok(Frame::trailers(build_grpc_trailers(
                                            16,
                                            Some(&e.to_string()),
                                        ))))
                                        .await;
                                    return;
                                }
                            }
                        }
                        Ok(None) => {
                            let _ = tx
                                .send(Ok(Frame::trailers(build_grpc_trailers(0, None))))
                                .await;
                            return;
                        }
                        Err(err) => {
                            let _ = tx
                                .send(Ok(Frame::trailers(build_grpc_trailers(
                                    err.code,
                                    Some(&err.message),
                                ))))
                                .await;
                            return;
                        }
                    }
                }
            });
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/grpc")
                .body(ClusterBody::Grpc(rx))
                .unwrap()
        }
        "/cluster.ClusterService/GetMetrics" => {
            let mut decoder = GrpcFrameDecoder::new(incoming);
            let payload = match decoder.next_message().await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => Vec::new(),
                Err(err) => return grpc_error_response(err),
            };
            let req = match decode_proto_metrics_request(&payload) {
                Ok(parsed) => parsed,
                Err(e) => return grpc_error_response(GrpcError::invalid_argument(e.to_string())),
            };
            if let Err(msg) = authorize_cluster_control_plane(&header_psk, &peer_auth) {
                return grpc_error_response(GrpcError::unauthenticated(msg));
            }
            let encoded = if let Some(snapshot) = get_cached_worker_metrics(&req.node_id) {
                let (m, svcs) = cached_snapshot_to_proto_metrics(&snapshot);
                encode_proto_metrics_response(&req.node_id, m.as_ref(), &svcs)
            } else {
                encode_proto_metrics_response(&req.node_id, None, &[])
            };
            grpc_unary_ok_response(&encoded)
        }
        "/cluster.ClusterService/ExecuteCommand" => {
            let mut decoder = GrpcFrameDecoder::new(incoming);
            let payload = match decoder.next_message().await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    return grpc_error_response(GrpcError::invalid_argument(
                        "missing CommandRequest frame",
                    ))
                }
                Err(err) => return grpc_error_response(err),
            };
            let req = match decode_proto_command_request(&payload) {
                Ok(parsed) => parsed,
                Err(e) => return grpc_error_response(GrpcError::invalid_argument(e.to_string())),
            };
            if let Err(msg) = authorize_cluster_control_plane(&header_psk, &peer_auth) {
                return grpc_error_response(GrpcError::unauthenticated(msg));
            }
            let known_worker = is_enrolled_cluster_node(&req.node_id)
                || get_cached_worker_metrics(&req.node_id).is_some();
            let cmd = PendingWorkerCommand {
                id: req.command_id.clone(),
                cmd_type: req.cmd_type,
                params: req.params,
            };
            let encoded = if known_worker && queue_worker_command(&req.node_id, cmd) {
                encode_proto_command_response(
                    &req.command_id,
                    true,
                    "command queued for delivery",
                    "",
                )
            } else {
                encode_proto_command_response(
                    &req.command_id,
                    false,
                    "",
                    "worker not found or command queue full",
                )
            };
            grpc_unary_ok_response(&encoded)
        }
        _ => grpc_error_response(GrpcError::unimplemented(format!(
            "unknown gRPC method {}",
            path
        ))),
    }
}

async fn read_bounded_http_body(
    mut incoming: Incoming,
    max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(frame_res) =
        tokio::time::timeout(Duration::from_secs(10), incoming.frame()).await?
    {
        let frame = frame_res?;
        if let Ok(data) = frame.into_data() {
            if out.len().saturating_add(data.len()) > max_bytes {
                anyhow::bail!("HTTP request body exceeds {} bytes", max_bytes);
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

async fn handle_hyper_cluster_request(
    req: Request<Incoming>,
    peer_auth: PeerTransportAuth,
) -> Result<Response<ClusterBody>, Infallible> {
    let method = req.method().as_str().to_uppercase();
    let path = req.uri().path().to_string();
    let raw_target = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| path.clone());
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let header_psk = extract_psk_from_headers(req.headers());

    if content_type.starts_with("application/grpc") || path.starts_with("/cluster.ClusterService/")
    {
        return Ok(handle_grpc_request(&path, header_psk, req.into_body(), peer_auth).await);
    }

    let body_bytes = match read_bounded_http_body(req.into_body(), MAX_JSON_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            let err_json = serde_json::to_vec(&serde_json::json!({
                "error": format!("invalid request body: {}", e),
            }))
            .unwrap_or_default();
            return Ok(Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header("content-type", "application/json")
                .body(ClusterBody::Json(Full::new(Bytes::from(err_json))))
                .unwrap());
        }
    };

    let (status_code, _status_text, response_json) = route_cluster_http_request(
        &method,
        &path,
        &raw_target,
        &header_psk,
        &body_bytes,
        &peer_auth,
    );
    let payload_bytes = serde_json::to_vec(&response_json).unwrap_or_default();
    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(ClusterBody::Json(Full::new(Bytes::from(payload_bytes))))
        .unwrap())
}

fn build_cluster_auto_conn_builder() -> AutoConnBuilder<TokioExecutor> {
    let mut builder = AutoConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HTTP_HEADER_READ_TIMEOUT)
        .max_buf_size(64 * 1024);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(32)
        .max_header_list_size(16 * 1024)
        .max_frame_size(16 * 1024)
        .max_send_buf_size(64 * 1024)
        .keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT);
    builder
}

async fn read_bounded_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> anyhow::Result<Option<String>> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
            let take_len = newline_pos + 1;
            if buf.len() + take_len > max_len {
                anyhow::bail!("cluster request line exceeds {} bytes", max_len);
            }
            buf.extend_from_slice(&available[..take_len]);
            reader.consume(take_len);
            break;
        }
        let chunk_len = available.len();
        if buf.len() + chunk_len > max_len {
            anyhow::bail!("cluster request line exceeds {} bytes", max_len);
        }
        buf.extend_from_slice(available);
        reader.consume(chunk_len);
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

pub async fn serve_cluster_master_connection(
    mut stream: TcpStream,
    security: MasterTransportSecurity,
) -> anyhow::Result<()> {
    match security {
        MasterTransportSecurity::Mtls {
            acceptor,
            admin_cert_sha256,
        } => {
            let tls_stream = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                .await
                .context("cluster mTLS handshake timed out")?
                .context("cluster mTLS handshake failed")?;
            let peer_auth = inspect_mtls_peer(&tls_stream, admin_cert_sha256.as_deref())?;
            let builder = build_cluster_auto_conn_builder();
            let svc = service_fn(move |req| {
                let auth = peer_auth.clone();
                handle_hyper_cluster_request(req, auth)
            });
            builder
                .serve_connection(TokioIo::new(tls_stream), svc)
                .await
                .map_err(|e| anyhow::anyhow!("cluster mTLS connection error: {}", e))?;
            Ok(())
        }
        MasterTransportSecurity::InsecureLoopback => {
            let mut peek_byte = [0u8; 1];
            let n = tokio::time::timeout(Duration::from_secs(10), stream.peek(&mut peek_byte))
                .await
                .context("cluster loopback peek timed out")??;
            if n == 0 {
                return Ok(());
            }
            if peek_byte[0] == b'{' {
                let mut reader = BufReader::new(&mut stream);
                if let Some(line) = tokio::time::timeout(
                    Duration::from_secs(10),
                    read_bounded_line(&mut reader, MAX_PREAUTH_HEADER_BYTES),
                )
                .await??
                {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        let resp_val = handle_raw_json_rpc(trimmed);
                        let mut out = serde_json::to_vec(&resp_val)?;
                        out.push(b'\n');
                        stream.write_all(&out).await?;
                        stream.flush().await?;
                    }
                }
                return Ok(());
            }
            let builder = build_cluster_auto_conn_builder();
            let svc = service_fn(|req| {
                handle_hyper_cluster_request(req, PeerTransportAuth::InsecureLoopback)
            });
            builder
                .serve_connection(TokioIo::new(stream), svc)
                .await
                .map_err(|e| anyhow::anyhow!("cluster loopback connection error: {}", e))?;
            Ok(())
        }
    }
}

fn route_cluster_http_request(
    method: &str,
    path: &str,
    raw_target: &str,
    header_psk: &str,
    body_bytes: &[u8],
    peer_auth: &PeerTransportAuth,
) -> (u16, &'static str, serde_json::Value) {
    match (method, path) {
        ("POST", "/cluster/v1/register") | ("POST", "/api/v1/admin/cluster/enroll") => {
            let mut req: RegisterWorkerRequest =
                serde_json::from_slice(body_bytes).unwrap_or_default();
            if req.psk.is_empty() && !header_psk.is_empty() {
                req.psk = header_psk.to_string();
            }
            match register_worker_node_with_peer(&req, peer_auth) {
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
            match process_worker_heartbeat_with_peer(&req, peer_auth) {
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
        ("POST", "/cluster/v1/commands/ack") => {
            let mut req: WorkerCommandAckRequest =
                serde_json::from_slice(body_bytes).unwrap_or_default();
            if req.psk.is_empty() && !header_psk.is_empty() {
                req.psk = header_psk.to_string();
            }
            let node_id = req.node_id.trim();
            if node_id.is_empty() {
                return (
                    400,
                    "Bad Request",
                    serde_json::json!({ "acknowledged": false, "error": "node_id is required" }),
                );
            }
            if let Err(msg) = verify_cluster_psk(node_id, &req.psk) {
                return (
                    401,
                    "Unauthorized",
                    serde_json::json!({ "acknowledged": false, "error": msg }),
                );
            }
            if let Some(incoming_fp) = peer_auth.mtls_cert_sha256() {
                if let Ok(conn) = af_db::get_conn() {
                    let pinned: String = conn
                        .query_row(
                            "SELECT COALESCE(peer_cert_sha256, '') FROM cluster_nodes WHERE id = ?1",
                            params![node_id],
                            |r| r.get(0),
                        )
                        .unwrap_or_default();
                    if !pinned.is_empty()
                        && !constant_time_eq(pinned.as_bytes(), incoming_fp.as_bytes())
                    {
                        return (
                            401,
                            "Unauthorized",
                            serde_json::json!({ "acknowledged": false, "error": "peer certificate mismatch" }),
                        );
                    }
                }
            }
            let mut processed = 0usize;
            for ack in &req.acks {
                if acknowledge_worker_command(node_id, ack).unwrap_or(false) {
                    processed += 1;
                }
            }
            (
                200,
                "OK",
                serde_json::json!({
                    "acknowledged": true,
                    "processed": processed,
                }),
            )
        }
        ("POST", "/cluster/v1/commands") => {
            if let Err(msg) = authorize_cluster_control_plane(header_psk, peer_auth) {
                return (401, "Unauthorized", serde_json::json!({ "error": msg }));
            }
            let val: serde_json::Value = serde_json::from_slice(body_bytes).unwrap_or_default();
            let node_id = val.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
            let cmd_type = val
                .get("cmd_type")
                .or_else(|| val.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let target = val
                .get("target")
                .or_else(|| val.get("service"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match enqueue_cluster_command(node_id, cmd_type, target) {
                Ok(rec) => (200, "OK", serde_json::to_value(rec).unwrap_or_default()),
                Err(e) => (
                    400,
                    "Bad Request",
                    serde_json::json!({ "error": e.to_string() }),
                ),
            }
        }
        ("GET", "/cluster/v1/commands") => {
            if let Err(msg) = authorize_cluster_control_plane(header_psk, peer_auth) {
                return (401, "Unauthorized", serde_json::json!({ "error": msg }));
            }
            let node_id = raw_target.split_once('?').and_then(|(_, q)| {
                url::form_urlencoded::parse(q.as_bytes())
                    .find(|(k, _)| k == "node_id" || k == "id")
                    .map(|(_, v)| v.into_owned())
            });
            match list_cluster_commands(node_id.as_deref(), 100) {
                Ok(items) => (200, "OK", serde_json::json!({ "commands": items })),
                Err(e) => (
                    500,
                    "Internal Server Error",
                    serde_json::json!({ "error": e.to_string() }),
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
            if node_id.is_empty() {
                return (
                    400,
                    "Bad Request",
                    serde_json::json!({ "error": "node_id is required" }),
                );
            }
            if let Err(msg) = authorize_cluster_control_plane(header_psk, peer_auth) {
                return (
                    401,
                    "Unauthorized",
                    serde_json::json!({ "error": msg, "node_id": node_id }),
                );
            }
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
    let peer_auth = PeerTransportAuth::InsecureLoopback;

    match method {
        "register" | "/cluster/v1/register" | "RegisterWorker" => {
            let req: RegisterWorkerRequest = serde_json::from_value(params_val).unwrap_or_default();
            match register_worker_node_with_peer(&req, &peer_auth) {
                Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                Err(e) => serde_json::json!({ "accepted": false, "message": e.to_string() }),
            }
        }
        "heartbeat" | "/cluster/v1/heartbeat" | "Heartbeat" => {
            let req: WorkerHeartbeatRequest =
                serde_json::from_value(params_val).unwrap_or_default();
            match process_worker_heartbeat_with_peer(&req, &peer_auth) {
                Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                Err(e) => serde_json::json!({ "acknowledged": false, "error": e.to_string() }),
            }
        }
        _ => {
            if val.get("metrics").is_some() || val.get("cpu_usage").is_some() {
                let req: WorkerHeartbeatRequest = serde_json::from_value(val).unwrap_or_default();
                match process_worker_heartbeat_with_peer(&req, &peer_auth) {
                    Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                    Err(e) => serde_json::json!({ "acknowledged": false, "error": e.to_string() }),
                }
            } else {
                let req: RegisterWorkerRequest = serde_json::from_value(val).unwrap_or_default();
                match register_worker_node_with_peer(&req, &peer_auth) {
                    Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                    Err(e) => serde_json::json!({ "accepted": false, "message": e.to_string() }),
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Worker Registration & 5-Second Telemetry Heartbeat Loop (mTLS Enforced)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerTargetEndpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub authority: String,
}

#[derive(Clone)]
pub enum WorkerTransportSecurity {
    Mtls(TlsConnector),
    InsecureLoopback,
}

pub fn parse_worker_endpoint(
    raw_addr: &str,
    default_https: bool,
) -> anyhow::Result<WorkerTargetEndpoint> {
    let trimmed = raw_addr.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        anyhow::bail!("CLUSTER_MASTER_ADDR must not be empty");
    }
    let url_str = if trimmed.contains("://") {
        trimmed.to_string()
    } else if default_https {
        format!("https://{}", trimmed)
    } else {
        format!("http://{}", trimmed)
    };
    let parsed = url::Url::parse(&url_str)
        .with_context(|| format!("invalid CLUSTER_MASTER_ADDR '{}'", raw_addr))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        anyhow::bail!("unsupported scheme '{}' in CLUSTER_MASTER_ADDR", scheme);
    }
    let raw_host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing host in CLUSTER_MASTER_ADDR '{}'", raw_addr))?;
    let host = raw_host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = parsed.port().unwrap_or(50051);
    let authority = if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    Ok(WorkerTargetEndpoint {
        scheme,
        host,
        port,
        authority,
    })
}

/// Evaluates `CLUSTER_CA_CERT`, `CLUSTER_CLIENT_CERT`, `CLUSTER_CLIENT_KEY`, and `CLUSTER_MASTER_ADDR`.
/// Fails closed on partial TLS configuration, plaintext `http://` when mTLS certs are present,
/// or remote/unopted-in plaintext worker transport.
pub fn resolve_worker_transport(
    raw_master_addr: &str,
) -> anyhow::Result<(WorkerTargetEndpoint, WorkerTransportSecurity)> {
    let ca = non_empty_env("CLUSTER_CA_CERT");
    let cert = non_empty_env("CLUSTER_CLIENT_CERT");
    let key = non_empty_env("CLUSTER_CLIENT_KEY");

    match (ca, cert, key) {
        (Some(ca_path), Some(cert_path), Some(key_path)) => {
            let endpoint = parse_worker_endpoint(raw_master_addr, true)?;
            if endpoint.scheme != "https" {
                anyhow::bail!(
                    "refusing plaintext {}:// CLUSTER_MASTER_ADDR when worker mTLS certificates are configured",
                    endpoint.scheme
                );
            }
            let connector = build_worker_mtls_connector(
                Path::new(&ca_path),
                Path::new(&cert_path),
                Path::new(&key_path),
            )?;
            Ok((endpoint, WorkerTransportSecurity::Mtls(connector)))
        }
        (None, None, None) => {
            let endpoint = parse_worker_endpoint(raw_master_addr, false)?;
            if endpoint.scheme == "https" {
                anyhow::bail!(
                    "https:// CLUSTER_MASTER_ADDR requires CLUSTER_CA_CERT, CLUSTER_CLIENT_CERT, and CLUSTER_CLIENT_KEY"
                );
            }
            if env_flag_true("CLUSTER_ALLOW_INSECURE_LOOPBACK") && is_loopback_host(&endpoint.host) {
                tracing::warn!(
                    master = %endpoint.authority,
                    "CLUSTER_ALLOW_INSECURE_LOOPBACK=true enabled for loopback worker without mTLS"
                );
                Ok((endpoint, WorkerTransportSecurity::InsecureLoopback))
            } else {
                anyhow::bail!(
                    "CLUSTER_MODE=worker requires CLUSTER_CA_CERT, CLUSTER_CLIENT_CERT, and CLUSTER_CLIENT_KEY (refusing unencrypted transport to '{}')",
                    raw_master_addr
                )
            }
        }
        _ => anyhow::bail!(
            "CLUSTER_CA_CERT, CLUSTER_CLIENT_CERT, and CLUSTER_CLIENT_KEY must all be set together for worker mTLS"
        ),
    }
}

pub async fn send_worker_json_post(
    endpoint: &WorkerTargetEndpoint,
    security: &WorkerTransportSecurity,
    path: &str,
    psk: &str,
    body_bytes: Vec<u8>,
) -> anyhow::Result<(StatusCode, Vec<u8>)> {
    let tcp = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .context("worker TCP connect timed out")?
    .with_context(|| format!("worker failed connecting to {}", endpoint.authority))?;

    match security {
        WorkerTransportSecurity::Mtls(connector) => {
            let server_name = ServerName::try_from(endpoint.host.clone())
                .map_err(|_| anyhow::anyhow!("invalid TLS server name '{}'", endpoint.host))?;
            let tls_stream =
                tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp))
                    .await
                    .context("worker mTLS handshake timed out")?
                    .context("worker mTLS handshake failed")?;

            let negotiated_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
            if negotiated_h2 {
                let (mut sender, conn) = hyper::client::conn::http2::handshake(
                    TokioExecutor::new(),
                    TokioIo::new(tls_stream),
                )
                .await
                .context("worker HTTP/2 handshake failed")?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                let uri = format!("https://{}{}", endpoint.authority, path);
                let req = Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("content-type", "application/json")
                    .header("x-cluster-psk", psk)
                    .body(Full::new(Bytes::from(body_bytes)))?;
                let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
                    .await
                    .context("worker HTTP/2 request timed out")??;
                let status = resp.status();
                let resp_bytes = read_bounded_http_body(resp.into_body(), 1024 * 1024).await?;
                Ok((status, resp_bytes))
            } else {
                let (mut sender, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
                        .await
                        .context("worker HTTP/1.1 handshake failed")?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                let req = Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("host", &endpoint.authority)
                    .header("content-type", "application/json")
                    .header("x-cluster-psk", psk)
                    .body(Full::new(Bytes::from(body_bytes)))?;
                let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
                    .await
                    .context("worker HTTP/1.1 request timed out")??;
                let status = resp.status();
                let resp_bytes = read_bounded_http_body(resp.into_body(), 1024 * 1024).await?;
                Ok((status, resp_bytes))
            }
        }
        WorkerTransportSecurity::InsecureLoopback => {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                .await
                .context("worker loopback HTTP/1.1 handshake failed")?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .header("host", &endpoint.authority)
                .header("content-type", "application/json")
                .header("x-cluster-psk", psk)
                .body(Full::new(Bytes::from(body_bytes)))?;
            let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
                .await
                .context("worker loopback HTTP/1.1 request timed out")??;
            let status = resp.status();
            let resp_bytes = read_bounded_http_body(resp.into_body(), 1024 * 1024).await?;
            Ok((status, resp_bytes))
        }
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

fn collect_worker_services() -> anyhow::Result<Vec<WorkerService>> {
    Ok(crate::get_active_services()?
        .into_iter()
        .map(|(name, svc)| WorkerService {
            name,
            status: svc.status,
            uptime: svc.uptime,
            managed_by: svc.managed_by,
        })
        .collect())
}

#[derive(Default)]
struct WorkerServiceInventory {
    services: Option<Vec<WorkerService>>,
    observed_at: Option<i64>,
    error: Option<String>,
    fresh: bool,
}

impl WorkerServiceInventory {
    fn observe(&mut self, result: anyhow::Result<Vec<WorkerService>>, now: i64) {
        match result {
            Ok(services) => {
                self.services = Some(services);
                self.observed_at = Some(now);
                self.error = None;
                self.fresh = true;
            }
            Err(error) => {
                self.error = Some(error.to_string());
                self.fresh = false;
            }
        }
    }

    fn status(&self) -> &'static str {
        if self.fresh {
            "fresh"
        } else if self.services.is_some() {
            "stale"
        } else {
            "unknown"
        }
    }
}

type WorkerInventoryTask = tokio::task::JoinHandle<anyhow::Result<Vec<WorkerService>>>;

async fn poll_worker_service_inventory(
    task: &mut Option<WorkerInventoryTask>,
    inventory: &mut WorkerServiceInventory,
    now: i64,
) {
    if task.as_ref().is_some_and(|task| task.is_finished()) {
        let result = task
            .take()
            .unwrap()
            .await
            .unwrap_or_else(|error| Err(anyhow::anyhow!("inventory worker failed: {error}")));
        if let Err(error) = &result {
            tracing::warn!(%error, "cluster inventory unknown; continuing liveness heartbeat");
        }
        inventory.observe(result, now);
    } else if task.is_none() {
        inventory.fresh = false;
        *task = Some(tokio::task::spawn_blocking(collect_worker_services));
    }
}

fn build_worker_heartbeat_payload(
    node_id: &str,
    hostname: &str,
    address: &str,
    psk: &str,
    inventory: &WorkerServiceInventory,
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

    let mut rich_metrics =
        serde_json::to_value(&sys_metrics).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = rich_metrics.as_object_mut() {
        obj.insert("mem_used_gb".to_string(), serde_json::json!(mem_used_gb));
        obj.insert("mem_total_gb".to_string(), serde_json::json!(mem_total_gb));
        obj.insert("disk_used_gb".to_string(), serde_json::json!(disk_used_gb));
        obj.insert(
            "disk_total_gb".to_string(),
            serde_json::json!(disk_total_gb),
        );
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
        services: inventory.services.clone(),
        services_status: Some(inventory.status().to_string()),
        services_observed_at: inventory.observed_at,
        services_error: inventory.error.clone(),
        system_info: Some(sys_info.clone()),
        command_acks: Vec::new(),
    };

    (hb, sys_info)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedWorkerRegistrationState {
    pub node_id: String,
    pub master_authority: String,
    pub credential: String,
    pub registered_at: String,
}

pub fn resolve_worker_registration_state_path() -> std::path::PathBuf {
    if let Ok(explicit) = env::var("CLUSTER_WORKER_STATE_FILE") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    if let Ok(root) = env::var("AETHERFLOW_FS_ROOT") {
        let trimmed = root.trim();
        if !trimmed.is_empty() && trimmed != "/" {
            return Path::new(trimmed).join("var/lib/aetherflow/cluster_worker_state.json");
        }
    }
    if let Ok(data_dir) = env::var("DATA_DIR") {
        let trimmed = data_dir.trim();
        if !trimmed.is_empty() {
            return Path::new(trimmed).join("cluster_worker_state.json");
        }
    }
    std::path::PathBuf::from("/var/lib/aetherflow/cluster_worker_state.json")
}

/// Atomically persists worker registration state & credential with `0600` permissions and `O_NOFOLLOW`.
pub fn persist_worker_registration_state_atomic(
    path: &Path,
    state: &PersistedWorkerRegistrationState,
) -> anyhow::Result<()> {
    use std::io::Write;
    let Some(parent) = path.parent() else {
        anyhow::bail!("worker state path must have a parent directory");
    };
    if let Ok(pmeta) = std::fs::symlink_metadata(parent) {
        if pmeta.file_type().is_symlink() {
            anyhow::bail!("refusing symlink parent directory for worker registration state");
        }
    } else {
        std::fs::create_dir_all(parent).context("creating worker state parent directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            anyhow::bail!("refusing to overwrite symlink worker registration state file");
        }
    }

    let payload = serde_json::to_vec_pretty(state)?;
    let tmp_name = format!(
        ".cluster_worker_state.{}.tmp",
        uuid::Uuid::new_v4().simple()
    );
    let tmp_path = parent.join(tmp_name);

    #[cfg(unix)]
    let mut tmp_file = {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;

        let c_tmp = CString::new(tmp_path.as_os_str().as_bytes())
            .context("worker state temp path contains interior NUL")?;
        let fd = unsafe {
            libc::open(
                c_tmp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("opening exclusive 0600 worker registration temp file");
        }
        unsafe {
            let _ = libc::fchmod(fd, 0o600);
            std::fs::File::from_raw_fd(fd)
        }
    };
    #[cfg(not(unix))]
    let mut tmp_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)?;

    if let Err(err) = tmp_file
        .write_all(&payload)
        .and_then(|_| tmp_file.sync_all())
    {
        drop(tmp_file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err).context("writing worker registration state temp file");
    }
    drop(tmp_file);

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            let _ = std::fs::remove_file(&tmp_path);
            anyhow::bail!("worker registration state target turned into a symlink");
        }
    }
    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err).context("atomically activating worker registration state file");
    }
    if let Ok(dir_f) = std::fs::File::open(parent) {
        let _ = dir_f.sync_all();
    }
    Ok(())
}

/// Loads persisted worker registration state safely with `O_NOFOLLOW`.
pub fn load_worker_registration_state_nofollow(
    path: &Path,
) -> Option<PersistedWorkerRegistrationState> {
    #[cfg(unix)]
    let file = {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;

        let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return None;
        }
        let f = unsafe { std::fs::File::from_raw_fd(fd) };
        if !f.metadata().ok()?.is_file() {
            return None;
        }
        f
    };
    #[cfg(not(unix))]
    let mut file = std::fs::File::open(path).ok()?;

    let mut raw = Vec::new();
    file.take(64 * 1024).read_to_end(&mut raw).ok()?;
    serde_json::from_slice(&raw).ok()
}

async fn execute_remote_worker_command_with_result(cmd: PendingWorkerCommand) -> WorkerCommandAck {
    tracing::info!(
        command_id = %cmd.id,
        cmd_type = %cmd.cmd_type,
        "cluster worker executing remote command from master"
    );
    let action = match cmd.cmd_type.as_str() {
        "restart_service" => Some("restart"),
        "start_service" => Some("start"),
        "stop_service" => Some("stop"),
        "reload_service" => Some("reload"),
        _ => None,
    };
    let Some(svc_action) = action else {
        return WorkerCommandAck {
            id: cmd.id,
            status: "failed".to_string(),
            result_message: Some(format!("unsupported command type '{}'", cmd.cmd_type)),
        };
    };
    let service_name = cmd
        .params
        .get("service")
        .or_else(|| cmd.params.get("target"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(service) = service_name else {
        return WorkerCommandAck {
            id: cmd.id,
            status: "failed".to_string(),
            result_message: Some("missing target service parameter".to_string()),
        };
    };
    match crate::control_service(&service, svc_action).await {
        Ok(()) => WorkerCommandAck {
            id: cmd.id,
            status: "executed".to_string(),
            result_message: Some(format!("{svc_action} {service} succeeded")),
        },
        Err(err) => {
            tracing::warn!(
                service = %service,
                action = %svc_action,
                error = %err,
                "cluster worker command failed"
            );
            WorkerCommandAck {
                id: cmd.id,
                status: "failed".to_string(),
                result_message: Some(err.to_string()),
            }
        }
    }
}

fn resolve_live_enrollment_credential(fallback: &str) -> String {
    env::var("CLUSTER_ENROLL_TOKEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| {
            env::var("CLUSTER_PSK")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_else(|| fallback.trim().to_string())
}

async fn register_worker_with_bounded_backoff(
    endpoint: &WorkerTargetEndpoint,
    security: &WorkerTransportSecurity,
    credential: &str,
    preferred_node_id: &str,
    hostname: &str,
    worker_address: &str,
    state_path: &Path,
) -> String {
    let initial_ms = env::var("CLUSTER_REGISTER_INITIAL_BACKOFF_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1000);
    let max_ms = env::var("CLUSTER_REGISTER_MAX_BACKOFF_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n >= initial_ms)
        .unwrap_or(30_000);

    let (_, sys_info) = build_worker_heartbeat_payload(
        preferred_node_id,
        hostname,
        worker_address,
        "",
        &WorkerServiceInventory::default(),
    );
    let reg_payload = RegisterWorkerRequest {
        node_id: preferred_node_id.to_string(),
        hostname: hostname.to_string(),
        address: worker_address.to_string(),
        psk: String::new(),
        version: "4.0.0".to_string(),
        system_info: Some(sys_info),
    };
    let reg_bytes = serde_json::to_vec(&reg_payload).unwrap_or_default();
    let register_paths = ["/cluster/v1/register", "/api/v1/admin/cluster/enroll"];

    let mut backoff_ms = initial_ms;
    loop {
        let live_cred = resolve_live_enrollment_credential(credential);
        for path in &register_paths {
            match send_worker_json_post(endpoint, security, path, &live_cred, reg_bytes.clone())
                .await
            {
                Ok((status, resp_bytes)) if status.is_success() => {
                    if let Ok(parsed) =
                        serde_json::from_slice::<RegisterWorkerResponse>(&resp_bytes)
                    {
                        if parsed.accepted {
                            let assigned = if parsed.node_id.trim().is_empty() {
                                preferred_node_id.to_string()
                            } else {
                                parsed.node_id.trim().to_string()
                            };
                            let persisted = PersistedWorkerRegistrationState {
                                node_id: assigned.clone(),
                                master_authority: endpoint.authority.clone(),
                                credential: live_cred,
                                registered_at: Utc::now().to_rfc3339(),
                            };
                            if let Err(err) =
                                persist_worker_registration_state_atomic(state_path, &persisted)
                            {
                                tracing::warn!(
                                    path = %state_path.display(),
                                    error = %err,
                                    "failed persisting worker registration state"
                                );
                            }
                            tracing::info!(
                                node_id = %assigned,
                                master = %endpoint.authority,
                                "cluster worker registered with master"
                            );
                            return assigned;
                        }
                    }
                }
                Ok((status, _)) => {
                    tracing::warn!(
                        endpoint = %path,
                        status = %status,
                        backoff_ms = backoff_ms,
                        "cluster registration endpoint returned non-success; backing off"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        endpoint = %path,
                        error = %e,
                        backoff_ms = backoff_ms,
                        "cluster worker registration attempt failed; backing off"
                    );
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        backoff_ms = backoff_ms.saturating_mul(2).min(max_ms);
    }
}

async fn run_worker_registration_and_heartbeat_loop(
    endpoint: WorkerTargetEndpoint,
    security: WorkerTransportSecurity,
    psk: String,
) {
    let hostname = resolve_local_hostname();
    let local_port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let worker_address = format!("{}:{}", hostname, local_port);
    let state_path = resolve_worker_registration_state_path();

    let mut active_cred = resolve_live_enrollment_credential(&psk);
    let mut assigned_node_id = format!("node-{}", hostname);

    if let Some(saved) = load_worker_registration_state_nofollow(&state_path)
        .filter(|s| s.master_authority == endpoint.authority && !s.node_id.trim().is_empty())
    {
        assigned_node_id = saved.node_id;
        if active_cred.is_empty() && !saved.credential.trim().is_empty() {
            active_cred = saved.credential;
        }
    } else {
        assigned_node_id = register_worker_with_bounded_backoff(
            &endpoint,
            &security,
            &active_cred,
            &assigned_node_id,
            &hostname,
            &worker_address,
            &state_path,
        )
        .await;
        if let Some(saved) = load_worker_registration_state_nofollow(&state_path) {
            if !saved.credential.trim().is_empty() {
                active_cred = saved.credential;
            }
        }
    }

    let hb_interval_ms = env::var("CLUSTER_HEARTBEAT_INTERVAL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n >= 20)
        .unwrap_or(5000);
    let mut ticker = tokio::time::interval(Duration::from_millis(hb_interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut inventory = WorkerServiceInventory::default();
    let mut inventory_task = None;

    let completed_cmds: Arc<std::sync::Mutex<HashMap<String, WorkerCommandAck>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let in_flight_cmds: Arc<std::sync::Mutex<std::collections::HashSet<String>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let pending_acks: Arc<std::sync::Mutex<Vec<WorkerCommandAck>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    loop {
        ticker.tick().await;
        poll_worker_service_inventory(&mut inventory_task, &mut inventory, Utc::now().timestamp())
            .await;
        let (mut hb_payload, _) = build_worker_heartbeat_payload(
            &assigned_node_id,
            &hostname,
            &worker_address,
            "",
            &inventory,
        );
        hb_payload.psk.clear();
        let batch_acks: Vec<WorkerCommandAck> = pending_acks
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default();
        hb_payload.command_acks = batch_acks.clone();

        let Ok(hb_bytes) = serde_json::to_vec(&hb_payload) else {
            continue;
        };

        match send_worker_json_post(
            &endpoint,
            &security,
            "/cluster/v1/heartbeat",
            &active_cred,
            hb_bytes,
        )
        .await
        {
            Ok((status, resp_bytes)) if status.is_success() => {
                if let Ok(pong) = serde_json::from_slice::<WorkerHeartbeatResponse>(&resp_bytes) {
                    if let Some(cmd) = pong.command {
                        let cached_ack = completed_cmds
                            .lock()
                            .ok()
                            .and_then(|m| m.get(&cmd.id).cloned());
                        if let Some(done_ack) = cached_ack {
                            if let Ok(mut q) = pending_acks.lock() {
                                if !q.iter().any(|a| a.id == done_ack.id) {
                                    q.push(done_ack);
                                }
                            }
                            continue;
                        }
                        let should_run = in_flight_cmds
                            .lock()
                            .map(|mut s| s.insert(cmd.id.clone()))
                            .unwrap_or(false);
                        if should_run {
                            let ep_clone = endpoint.clone();
                            let sec_clone = security.clone();
                            let cred_clone = active_cred.clone();
                            let node_clone = assigned_node_id.clone();
                            let done_map = Arc::clone(&completed_cmds);
                            let flight_set = Arc::clone(&in_flight_cmds);
                            let ack_queue = Arc::clone(&pending_acks);
                            tokio::spawn(async move {
                                let cmd_id = cmd.id.clone();
                                let ack = execute_remote_worker_command_with_result(cmd).await;
                                if let Ok(mut m) = done_map.lock() {
                                    if m.len() >= 256 {
                                        if let Some(k) = m.keys().next().cloned() {
                                            m.remove(&k);
                                        }
                                    }
                                    m.insert(cmd_id.clone(), ack.clone());
                                }
                                if let Ok(mut s) = flight_set.lock() {
                                    s.remove(&cmd_id);
                                }
                                let ack_req = WorkerCommandAckRequest {
                                    node_id: node_clone,
                                    psk: String::new(),
                                    acks: vec![ack.clone()],
                                };
                                let ack_sent = if let Ok(bytes) = serde_json::to_vec(&ack_req) {
                                    matches!(
                                        send_worker_json_post(
                                            &ep_clone,
                                            &sec_clone,
                                            "/cluster/v1/commands/ack",
                                            &cred_clone,
                                            bytes,
                                        )
                                        .await,
                                        Ok((st, _)) if st.is_success()
                                    )
                                } else {
                                    false
                                };
                                if !ack_sent {
                                    if let Ok(mut q) = ack_queue.lock() {
                                        q.push(ack);
                                    }
                                }
                            });
                        }
                    }
                }
            }
            Ok((status, _)) => {
                if !batch_acks.is_empty() {
                    if let Ok(mut q) = pending_acks.lock() {
                        q.extend(batch_acks);
                    }
                }
                tracing::warn!(
                    status = %status,
                    "cluster master rejected heartbeat"
                );
                if status == StatusCode::UNAUTHORIZED {
                    let fresh_cred = resolve_live_enrollment_credential(&active_cred);
                    if !fresh_cred.is_empty() {
                        tracing::info!(
                            node_id = %assigned_node_id,
                            "heartbeat received 401 with credential available; re-triggering worker registration"
                        );
                        active_cred = fresh_cred;
                        assigned_node_id = register_worker_with_bounded_backoff(
                            &endpoint,
                            &security,
                            &active_cred,
                            &assigned_node_id,
                            &hostname,
                            &worker_address,
                            &state_path,
                        )
                        .await;
                    }
                }
            }
            Err(e) => {
                if !batch_acks.is_empty() {
                    if let Ok(mut q) = pending_acks.lock() {
                        q.extend(batch_acks);
                    }
                }
                tracing::debug!(
                    error = %e,
                    master = %endpoint.authority,
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
/// - If `CLUSTER_MODE=master`: enforces TLS 1.3 mutual TLS (`CLUSTER_CA_CERT`, `CLUSTER_SERVER_CERT`,
///   `CLUSTER_SERVER_KEY`) and binds `CLUSTER_GRPC_HOST:CLUSTER_GRPC_PORT` (default `127.0.0.1:50051`),
///   serving both legacy `cluster.ClusterService` HTTP/2 gRPC and `/cluster/v1/*` HTTP JSON.
/// - If `CLUSTER_MODE=worker`: enforces TLS 1.3 mutual TLS (`CLUSTER_CA_CERT`, `CLUSTER_CLIENT_CERT`,
///   `CLUSTER_CLIENT_KEY`), enrolls with `CLUSTER_MASTER_ADDR`, and runs a 5-second heartbeat loop.
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
            let bind_cfg = resolve_master_bind_config();
            let security = match load_master_transport_security(&bind_cfg.host) {
                Ok(sec) => sec,
                Err(e) => {
                    tracing::error!(
                        listen_addr = %bind_cfg.bind_addr,
                        error = %e,
                        "cluster master refused startup due to missing or invalid mTLS configuration"
                    );
                    return;
                }
            };

            let bind_addr = bind_cfg.bind_addr;
            tracing::info!(
                role = "master",
                listen_addr = %bind_addr,
                "cluster mode active (mTLS enforced)"
            );

            tokio::spawn(async move {
                match TcpListener::bind(&bind_addr).await {
                    Ok(listener) => {
                        tracing::info!(
                            addr = %bind_addr,
                            "cluster mTLS gRPC + HTTP listener bound"
                        );
                        let conn_semaphore =
                            Arc::new(tokio::sync::Semaphore::new(MAX_CLUSTER_CONCURRENT_CONNS));
                        loop {
                            match listener.accept().await {
                                Ok((stream, _peer)) => {
                                    let Ok(permit) = conn_semaphore.clone().try_acquire_owned()
                                    else {
                                        tracing::warn!("cluster listener at connection capacity; dropping socket");
                                        continue;
                                    };
                                    let sec = security.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        if let Err(e) =
                                            serve_cluster_master_connection(stream, sec).await
                                        {
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
                            "failed to bind cluster listener"
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
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .or_else(|| {
                    env::var("CLUSTER_ENROLL_TOKEN")
                        .ok()
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                })
                .unwrap_or_default();

            if master_addr.is_empty() {
                tracing::error!(
                    "CLUSTER_MODE=worker requires CLUSTER_MASTER_ADDR to be set; skipping worker loop"
                );
                return;
            }
            if psk.is_empty() {
                tracing::error!(
                    "CLUSTER_MODE=worker requires CLUSTER_PSK or CLUSTER_ENROLL_TOKEN to be set; skipping worker loop"
                );
                return;
            }

            let (endpoint, security) = match resolve_worker_transport(&master_addr) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::error!(
                        master_addr = %master_addr,
                        error = %e,
                        "cluster worker refused startup due to missing or invalid mTLS configuration"
                    );
                    return;
                }
            };

            tracing::info!(
                role = "worker",
                master_addr = %endpoint.authority,
                "cluster mode active"
            );

            tokio::spawn(async move {
                run_worker_registration_and_heartbeat_loop(endpoint, security, psk).await;
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

    #[cfg(unix)]
    #[test]
    fn heartbeat_liveness_survives_unknown_and_pending_service_inventory() {
        use crate::inventory_regressions::{isolated, Fixture};
        let name = "cluster_daemon::tests::heartbeat_liveness_survives_unknown_and_pending_service_inventory";
        if !isolated(name) {
            return;
        }
        let fixture = Fixture::new();
        af_db::init_db().unwrap();
        assert_eq!(std::path::Path::new(&af_db::get_db_path()), fixture.journal);
        ensure_cluster_schema();
        let psk = "disposable-inventory-heartbeat-secret";
        env::set_var("CLUSTER_PSK", psk);
        let node = "node-inventory-regression";
        let mut inventory = WorkerServiceInventory::default();
        let (unknown, _) =
            build_worker_heartbeat_payload(node, "fixture", "fixture:8080", psk, &inventory);
        assert!(serde_json::to_value(&unknown)
            .unwrap()
            .get("services")
            .is_none());
        assert!(process_worker_heartbeat(&unknown).unwrap().acknowledged);
        let cached = get_cached_worker_metrics(node).unwrap();
        assert!(cached["services"].is_null());
        assert_eq!(cached["services_status"], "unknown");
        let observed_at = Utc::now().timestamp() - 80;
        inventory.observe(collect_worker_services(), observed_at);
        let (healthy, _) =
            build_worker_heartbeat_payload(node, "fixture", "fixture:8080", psk, &inventory);
        process_worker_heartbeat(&healthy).unwrap();
        let previous_services = get_cached_worker_metrics(node).unwrap()["services"].clone();
        assert_eq!(previous_services.as_array().unwrap().len(), 4);
        let hidden = fixture.journal.with_extension("temporarily-hidden");
        std::fs::rename(&fixture.journal, &hidden).unwrap();
        inventory.observe(collect_worker_services(), observed_at + 5);
        std::fs::rename(&hidden, &fixture.journal).unwrap();
        assert_eq!(inventory.status(), "stale");
        assert_eq!(inventory.observed_at, Some(observed_at));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (release, blocked) = tokio::sync::oneshot::channel::<()>();
            let mut pending = Some(tokio::spawn(async move {
                let _ = blocked.await;
                Err(anyhow::anyhow!("simulated inventory failure after a blocked collector"))
            }));
            let (stale, _) = build_worker_heartbeat_payload(node, "fixture", "fixture:8080", psk, &inventory);
            for elapsed in (5..=80).step_by(5) {
                poll_worker_service_inventory(&mut pending, &mut inventory, observed_at + elapsed).await;
                assert!(pending.as_ref().is_some_and(|task| !task.is_finished()));
                {
                    let conn = af_db::get_conn().unwrap();
                    conn.execute("UPDATE cluster_nodes SET last_seen=datetime('now','-65 seconds'),last_heartbeat=datetime('now','-65 seconds') WHERE id=?1", params![node]).unwrap();
                }
                let mut request = stale.clone();
                request.timestamp = observed_at + elapsed;
                assert!(process_worker_heartbeat(&request).unwrap().acknowledged);
                assert_eq!(sweep_stale_cluster_nodes(), 0);
                let cached = get_cached_worker_metrics(node).unwrap();
                assert_eq!(cached["status"], "online");
                assert_eq!(cached["services"], previous_services);
                assert_eq!(cached["services_status"], "stale");
                assert_eq!(cached["services_observed_at"], observed_at);
            }
            release.send(()).unwrap();
            inventory.observe(pending.take().unwrap().await.unwrap(), observed_at + 80);
        });
        inventory.observe(collect_worker_services(), observed_at + 85);
        let (recovered, _) =
            build_worker_heartbeat_payload(node, "fixture", "fixture:8080", psk, &inventory);
        process_worker_heartbeat(&recovered).unwrap();
        assert_eq!(
            get_cached_worker_metrics(node).unwrap()["services_status"],
            "fresh"
        );
        assert_eq!(
            get_cached_worker_metrics(node).unwrap()["services_observed_at"],
            observed_at + 85
        );
        inventory.observe(Ok(Vec::new()), observed_at + 90);
        let (empty, _) =
            build_worker_heartbeat_payload(node, "fixture", "fixture:8080", psk, &inventory);
        process_worker_heartbeat(&empty).unwrap();
        assert_eq!(
            get_cached_worker_metrics(node).unwrap()["services"],
            serde_json::json!([])
        );
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute("UPDATE cluster_nodes SET last_seen=datetime('now','-65 seconds'),last_heartbeat=datetime('now','-65 seconds') WHERE id=?1", params![node]).unwrap();
        }
        assert_eq!(sweep_stale_cluster_nodes(), 1);
        println!("16 fake 5-second heartbeats across 80 seconds kept actual disposable DB node online despite corrupt journal and pending inventory; retained services and original observation time; no-heartbeat negative control went offline");
    }

    #[test]
    fn test_heartbeat_requires_psk_before_mutating_state() {
        let request = WorkerHeartbeatRequest {
            node_id: "node-audit-missing-psk".to_string(),
            ..Default::default()
        };
        let error = process_worker_heartbeat(&request).unwrap_err();
        assert_eq!(error.to_string(), "psk is required");
        assert!(get_cached_worker_metrics(&request.node_id).is_none());
    }

    #[test]
    fn test_enrolled_psk_requires_a_trusted_matching_secret() {
        let candidate = "audit-secret-with-at-least-32-characters";
        assert!(verify_enrolled_cluster_psk(candidate, "").is_err());
        assert!(verify_enrolled_cluster_psk("", "").is_err());
        assert!(verify_enrolled_cluster_psk(candidate, &hash_psk_sha256("other-secret")).is_err());
        assert!(verify_enrolled_cluster_psk(candidate, &hash_psk_sha256(candidate)).is_ok());
        let stored_hash = hash_psk_sha256(candidate);
        assert!(verify_enrolled_cluster_psk(&stored_hash, &stored_hash).is_err());
        assert!(verify_enrolled_cluster_psk(candidate, candidate).is_ok());

        // Legacy Go cluster manager stored bcrypt ($2a$/$2b$) hashes in cluster_nodes.psk_hash
        let legacy_bcrypt = bcrypt::hash(candidate, 4).unwrap();
        let legacy_2a = legacy_bcrypt.replacen("$2b$", "$2a$", 1);
        assert!(verify_enrolled_cluster_psk(candidate, &legacy_bcrypt).is_ok());
        assert!(verify_enrolled_cluster_psk(candidate, &legacy_2a).is_ok());
        assert!(
            verify_enrolled_cluster_psk("wrong-secret-with-32-characters!!", &legacy_2a).is_err()
        );
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(
            b"super-secret-psk-1234567890123456",
            b"super-secret-psk-1234567890123456"
        ));
        assert!(!constant_time_eq(
            b"super-secret-psk-1234567890123456",
            b"super-secret-psk-1234567890123457"
        ));
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

    #[cfg(unix)]
    #[test]
    fn mtls_default_loopback_and_legacy_grpc_wire_compatibility() {
        use crate::inventory_regressions::{isolated, Fixture};
        use std::process::Command as StdCommand;

        let name =
            "cluster_daemon::tests::mtls_default_loopback_and_legacy_grpc_wire_compatibility";
        if !isolated(name) {
            return;
        }
        let fixture = Fixture::new();
        af_db::init_db().unwrap();
        ensure_cluster_schema();

        // 1. Default master bind config MUST bind 127.0.0.1:50051 (never 0.0.0.0 by default)
        for k in [
            "CLUSTER_GRPC_HOST",
            "GRPC_HOST",
            "CLUSTER_GRPC_PORT",
            "GRPC_PORT",
            "CLUSTER_CA_CERT",
            "CLUSTER_SERVER_CERT",
            "CLUSTER_SERVER_KEY",
            "CLUSTER_CLIENT_CERT",
            "CLUSTER_CLIENT_KEY",
            "CLUSTER_ALLOW_INSECURE_LOOPBACK",
        ] {
            env::remove_var(k);
        }
        let default_bind = resolve_master_bind_config();
        assert_eq!(default_bind.host, "127.0.0.1");
        assert_eq!(default_bind.port, "50051");
        assert_eq!(default_bind.bind_addr, "127.0.0.1:50051");

        // 2. Master and Worker MUST fail closed when mTLS certs are unset (even on 127.0.0.1 without opt-in)
        assert!(load_master_transport_security("127.0.0.1").is_err());
        assert!(resolve_worker_transport("127.0.0.1:50051").is_err());
        assert!(resolve_worker_transport("10.0.0.5:50051").is_err());

        // Even with CLUSTER_ALLOW_INSECURE_LOOPBACK=true, non-loopback hosts MUST fail closed
        env::set_var("CLUSTER_ALLOW_INSECURE_LOOPBACK", "true");
        assert!(load_master_transport_security("0.0.0.0").is_err());
        assert!(resolve_worker_transport("10.0.0.5:50051").is_err());
        env::remove_var("CLUSTER_ALLOW_INSECURE_LOOPBACK");

        // 3. Mint disposable CA + server + client X.509 v3 certificates (SAN: IP:127.0.0.1, DNS:localhost)
        let cert_dir = fixture.root.join("certs");
        std::fs::create_dir_all(&cert_dir).unwrap();
        let ca_key = cert_dir.join("ca.key");
        let ca_crt = cert_dir.join("ca.crt");
        let srv_key = cert_dir.join("server.key");
        let srv_csr = cert_dir.join("server.csr");
        let srv_crt = cert_dir.join("server.crt");
        let srv_ext = cert_dir.join("server.ext");
        let cli_key = cert_dir.join("client.key");
        let cli_csr = cert_dir.join("client.csr");
        let cli_crt = cert_dir.join("client.crt");
        let cli_ext = cert_dir.join("client.ext");
        let cli2_key = cert_dir.join("client2.key");
        let cli2_csr = cert_dir.join("client2.csr");
        let cli2_crt = cert_dir.join("client2.crt");
        let admin_key = cert_dir.join("admin.key");
        let admin_csr = cert_dir.join("admin.csr");
        let admin_crt = cert_dir.join("admin.crt");

        std::fs::write(
            &srv_ext,
            "basicConstraints=CA:FALSE\nsubjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n",
        )
        .unwrap();
        std::fs::write(
            &cli_ext,
            "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n",
        )
        .unwrap();

        assert!(StdCommand::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                ca_key.to_str().unwrap(),
                "-out",
                ca_crt.to_str().unwrap(),
                "-days",
                "1",
                "-subj",
                "/CN=AetherFlowClusterTestCA",
            ])
            .status()
            .unwrap()
            .success());

        for (key, csr, crt, ext, cn) in [
            (&srv_key, &srv_csr, &srv_crt, &srv_ext, "/CN=127.0.0.1"),
            (&cli_key, &cli_csr, &cli_crt, &cli_ext, "/CN=worker-node"),
            (
                &cli2_key,
                &cli2_csr,
                &cli2_crt,
                &cli_ext,
                "/CN=worker-node-2",
            ),
            (
                &admin_key,
                &admin_csr,
                &admin_crt,
                &cli_ext,
                "/CN=aetherflow-master",
            ),
        ] {
            assert!(StdCommand::new("openssl")
                .args([
                    "req",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:prime256v1",
                    "-nodes",
                    "-keyout",
                    key.to_str().unwrap(),
                    "-out",
                    csr.to_str().unwrap(),
                    "-subj",
                    cn,
                ])
                .status()
                .unwrap()
                .success());
            assert!(StdCommand::new("openssl")
                .args([
                    "x509",
                    "-req",
                    "-in",
                    csr.to_str().unwrap(),
                    "-CA",
                    ca_crt.to_str().unwrap(),
                    "-CAkey",
                    ca_key.to_str().unwrap(),
                    "-CAcreateserial",
                    "-out",
                    crt.to_str().unwrap(),
                    "-days",
                    "1",
                    "-extfile",
                    ext.to_str().unwrap(),
                ])
                .status()
                .unwrap()
                .success());
        }

        // Symlinked leaf, symlinked ancestor dir, and world-writable PEM files MUST be rejected
        let symlink_ca = cert_dir.join("symlink-ca.crt");
        std::os::unix::fs::symlink(&ca_crt, &symlink_ca).unwrap();
        assert!(build_master_mtls_acceptor(&symlink_ca, &srv_crt, &srv_key).is_err());

        let symlink_dir = fixture.root.join("certs-symlink-dir");
        std::os::unix::fs::symlink(&cert_dir, &symlink_dir).unwrap();
        assert!(
            build_master_mtls_acceptor(&symlink_dir.join("ca.crt"), &srv_crt, &srv_key).is_err(),
            "symlinked ancestor directory must be rejected by openat O_NOFOLLOW"
        );

        let ww_ca = cert_dir.join("world-writable-ca.crt");
        std::fs::copy(&ca_crt, &ww_ca).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ww_ca, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        assert!(
            build_master_mtls_acceptor(&ww_ca, &srv_crt, &srv_key).is_err(),
            "world-writable PEM file must be rejected"
        );

        let psk = "cluster-mtls-shared-secret-at-least-32-chars!!";
        env::set_var("CLUSTER_PSK", psk);
        env::set_var("CLUSTER_CA_CERT", &ca_crt);
        env::set_var("CLUSTER_SERVER_CERT", &srv_crt);
        env::set_var("CLUSTER_SERVER_KEY", &srv_key);
        env::set_var("CLUSTER_CLIENT_CERT", &cli_crt);
        env::set_var("CLUSTER_CLIENT_KEY", &cli_key);

        // Missing or unreadable CLUSTER_ADMIN_CLIENT_CERT MUST fail closed at startup
        env::set_var(
            "CLUSTER_ADMIN_CLIENT_CERT",
            cert_dir.join("missing-admin.crt"),
        );
        assert!(
            load_master_transport_security("127.0.0.1").is_err(),
            "invalid CLUSTER_ADMIN_CLIENT_CERT must fail closed at startup"
        );
        env::set_var("CLUSTER_ADMIN_CLIENT_CERT", &admin_crt);
        let pinned_sec = load_master_transport_security("127.0.0.1").unwrap();
        assert!(matches!(
            pinned_sec,
            MasterTransportSecurity::Mtls {
                admin_cert_sha256: Some(_),
                ..
            }
        ));
        env::remove_var("CLUSTER_ADMIN_CLIENT_CERT");

        // Plaintext http:// master addr MUST be rejected when worker mTLS certs are configured
        assert!(resolve_worker_transport("http://127.0.0.1:50051").is_err());

        let master_sec = load_master_transport_security("127.0.0.1").unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let bound_addr = listener.local_addr().unwrap();
            let server_sec = master_sec.clone();
            let server_task = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let sec = server_sec.clone();
                    tokio::spawn(async move {
                        let _ = serve_cluster_master_connection(stream, sec).await;
                    });
                }
            });

            // 4. Unauthenticated TLS client (no client cert) MUST be rejected by mTLS server
            {
                let root_store = load_root_cert_store(&ca_crt, "test_ca").unwrap();
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let no_cert_cfg = ClientConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .unwrap()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();
                let no_cert_connector = TlsConnector::from(Arc::new(no_cert_cfg));
                let tcp = TcpStream::connect(bound_addr).await.unwrap();
                let sn = ServerName::try_from("127.0.0.1".to_string()).unwrap();
                if let Ok(mut tls_s) = no_cert_connector.connect(sn, tcp).await {
                    // In TLS 1.3, post-ServerHello CertificateVerify rejection surfaces on first I/O
                    let io_res = tls_s
                        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                        .await;
                    let mut buf = [0u8; 16];
                    let read_res = tokio::io::AsyncReadExt::read(&mut tls_s, &mut buf).await;
                    assert!(
                        io_res.is_err() || matches!(read_res, Err(_) | Ok(0)),
                        "TLS client without client certificate must be rejected"
                    );
                }
            }

            // 5. Legacy Go gRPC worker simulation over TLS 1.3 + HTTP/2 (`cluster.ClusterService`)
            let (worker_ep, worker_sec) =
                resolve_worker_transport(&format!("127.0.0.1:{}", bound_addr.port())).unwrap();
            assert_eq!(worker_ep.scheme, "https");

            let connector = match &worker_sec {
                WorkerTransportSecurity::Mtls(c) => c.clone(),
                WorkerTransportSecurity::InsecureLoopback => panic!("expected mTLS connector"),
            };
            let tcp = TcpStream::connect(bound_addr).await.unwrap();
            let sn = ServerName::try_from("127.0.0.1".to_string()).unwrap();
            let tls_stream = connector.connect(sn, tcp).await.unwrap();
            assert_eq!(
                tls_stream.get_ref().1.alpn_protocol(),
                Some(b"h2".as_slice())
            );

            let (mut h2_sender, h2_conn) = hyper::client::conn::http2::handshake(
                TokioExecutor::new(),
                TokioIo::new(tls_stream),
            )
            .await
            .unwrap();
            tokio::spawn(async move {
                let _ = h2_conn.await;
            });

            // 5a. Unary gRPC RegisterWorker
            let mut sys_pb = Vec::new();
            pb_encode_string(&mut sys_pb, 1, "linux");
            pb_encode_string(&mut sys_pb, 2, "x86_64");
            pb_encode_int32(&mut sys_pb, 3, 8);
            pb_encode_int64(&mut sys_pb, 4, 16 * 1024 * 1024 * 1024);
            pb_encode_int64(&mut sys_pb, 5, 500 * 1024 * 1024 * 1024);

            let mut reg_pb = Vec::new();
            pb_encode_string(&mut reg_pb, 1, "legacy-go-worker");
            pb_encode_string(&mut reg_pb, 2, "10.10.0.12:8080");
            pb_encode_string(&mut reg_pb, 3, psk);
            pb_encode_string(&mut reg_pb, 4, "3.9.0");
            pb_encode_message_field(&mut reg_pb, 5, &sys_pb);

            let reg_req = Request::builder()
                .method("POST")
                .uri(format!(
                    "https://{}/cluster.ClusterService/RegisterWorker",
                    worker_ep.authority
                ))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(
                    &reg_pb,
                ))))
                .unwrap();
            let reg_resp = h2_sender.send_request(reg_req).await.unwrap();
            assert_eq!(reg_resp.status(), StatusCode::OK);
            let collected = reg_resp.into_body().collect().await.unwrap();
            let trailers = collected.trailers().cloned().unwrap_or_default();
            assert_eq!(
                trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
                Some("0")
            );
            let resp_bytes = collected.to_bytes();
            assert!(resp_bytes.len() > 5);
            let msg_len =
                u32::from_be_bytes([resp_bytes[1], resp_bytes[2], resp_bytes[3], resp_bytes[4]])
                    as usize;
            let reg_slice = &resp_bytes[5..5 + msg_len];
            let mut pos = 0usize;
            let mut got_node_id = String::new();
            let mut got_accepted = false;
            while pos < reg_slice.len() {
                let tag = pb_decode_varint(reg_slice, &mut pos).unwrap();
                match ((tag >> 3) as u32, (tag & 7) as u8) {
                    (1, 2) => got_node_id = pb_decode_string(reg_slice, &mut pos).unwrap(),
                    (2, 0) => got_accepted = pb_decode_varint(reg_slice, &mut pos).unwrap() != 0,
                    (_, wt) => pb_skip_field(reg_slice, &mut pos, wt).unwrap(),
                }
            }
            assert!(got_accepted);
            assert_eq!(got_node_id, "node-legacy-go-worker");

            // 5b. Enrolled worker cert MUST be rejected on ExecuteCommand BOTH without and WITH master CLUSTER_PSK
            let mut param_entry = Vec::new();
            pb_encode_string(&mut param_entry, 1, "service");
            pb_encode_string(&mut param_entry, 2, "radarr");
            let mut cmd_pb = Vec::new();
            pb_encode_string(&mut cmd_pb, 1, &got_node_id);
            pb_encode_string(&mut cmd_pb, 2, "cmd-99");
            pb_encode_string(&mut cmd_pb, 3, "restart_service");
            pb_encode_message_field(&mut cmd_pb, 4, &param_entry);

            let unauth_cmd_req = Request::builder()
                .method("POST")
                .uri(format!(
                    "https://{}/cluster.ClusterService/ExecuteCommand",
                    worker_ep.authority
                ))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(
                    &cmd_pb,
                ))))
                .unwrap();
            let unauth_cmd_resp = h2_sender.send_request(unauth_cmd_req).await.unwrap();
            let unauth_cmd_collected = unauth_cmd_resp.into_body().collect().await.unwrap();
            assert_eq!(
                unauth_cmd_collected
                    .trailers()
                    .and_then(|t| t.get("grpc-status"))
                    .and_then(|v| v.to_str().ok()),
                Some("16"),
                "worker certificate without master CLUSTER_PSK must be rejected on ExecuteCommand"
            );

            let worker_psk_cmd_req = Request::builder()
                .method("POST")
                .uri(format!(
                    "https://{}/cluster.ClusterService/ExecuteCommand",
                    worker_ep.authority
                ))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .header("x-cluster-psk", psk)
                .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(
                    &cmd_pb,
                ))))
                .unwrap();
            let worker_psk_cmd_resp = h2_sender.send_request(worker_psk_cmd_req).await.unwrap();
            let worker_psk_cmd_collected = worker_psk_cmd_resp.into_body().collect().await.unwrap();
            assert_eq!(
                worker_psk_cmd_collected
                    .trailers()
                    .and_then(|t| t.get("grpc-status"))
                    .and_then(|v| v.to_str().ok()),
                Some("16"),
                "enrolled worker certificate MUST be prohibited from ExecuteCommand even with shared CLUSTER_PSK"
            );

            // Dedicated control-plane certificate (CN=aetherflow-master, not enrolled as worker) queues ExecuteCommand
            let admin_connector =
                build_worker_mtls_connector(&ca_crt, &admin_crt, &admin_key).unwrap();
            let admin_tcp = TcpStream::connect(bound_addr).await.unwrap();
            let admin_tls = admin_connector
                .connect(
                    ServerName::try_from("127.0.0.1".to_string()).unwrap(),
                    admin_tcp,
                )
                .await
                .unwrap();
            let (mut admin_h2, admin_conn) = hyper::client::conn::http2::handshake(
                TokioExecutor::new(),
                TokioIo::new(admin_tls),
            )
            .await
            .unwrap();
            tokio::spawn(async move {
                let _ = admin_conn.await;
            });

            let cmd_req = Request::builder()
                .method("POST")
                .uri(format!(
                    "https://{}/cluster.ClusterService/ExecuteCommand",
                    worker_ep.authority
                ))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(
                    &cmd_pb,
                ))))
                .unwrap();
            let cmd_resp = admin_h2.send_request(cmd_req).await.unwrap();
            let cmd_collected = cmd_resp.into_body().collect().await.unwrap();
            assert_eq!(
                cmd_collected
                    .trailers()
                    .and_then(|t| t.get("grpc-status"))
                    .and_then(|v| v.to_str().ok()),
                Some("0")
            );

            // 5c. Bidirectional gRPC Heartbeat stream WITHOUT PSK in HeartbeatPing (matching legacy Go client.go)
            let (ping_tx, ping_rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
            let hb_stream_req = Request::builder()
                .method("POST")
                .uri(format!(
                    "https://{}/cluster.ClusterService/Heartbeat",
                    worker_ep.authority
                ))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(ClusterBody::Grpc(ping_rx))
                .unwrap();
            let hb_stream_resp = h2_sender.send_request(hb_stream_req).await.unwrap();
            assert_eq!(hb_stream_resp.status(), StatusCode::OK);
            let mut hb_incoming = hb_stream_resp.into_body();

            let metrics_pb = encode_proto_worker_metrics(&ProtoWorkerMetrics {
                cpu_usage: 31.5,
                memory_used_gb: 8.0,
                memory_total_gb: 16.0,
                disk_used_gb: 125.0,
                disk_total_gb: 500.0,
                network_rx_speed: "12.4 MB/s".to_string(),
                network_tx_speed: "3.1 MB/s".to_string(),
                uptime: "4d 2h".to_string(),
                load_average: vec![0.42, 0.38, 0.31],
            });
            let svc_pb = encode_proto_service_status(&WorkerService {
                name: "radarr".to_string(),
                status: "running".to_string(),
                uptime: "4d".to_string(),
                managed_by: "systemd".to_string(),
            });
            let mut ping_pb = Vec::new();
            pb_encode_string(&mut ping_pb, 1, &got_node_id);
            pb_encode_int64(&mut ping_pb, 2, 1_700_000_123);
            pb_encode_message_field(&mut ping_pb, 3, &metrics_pb);
            pb_encode_message_field(&mut ping_pb, 4, &svc_pb);

            ping_tx
                .send(Ok(Frame::data(encode_grpc_data_frame(&ping_pb))))
                .await
                .unwrap();

            // Receive streamed HeartbeatPong before closing client stream
            let first_pong_frame =
                tokio::time::timeout(Duration::from_secs(5), hb_incoming.frame())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            let pong_data = first_pong_frame.into_data().unwrap();
            assert!(pong_data.len() > 5);
            let pong_len =
                u32::from_be_bytes([pong_data[1], pong_data[2], pong_data[3], pong_data[4]])
                    as usize;
            let pong_slice = &pong_data[5..5 + pong_len];
            let mut ppos = 0usize;
            let mut pong_ack = false;
            let mut pong_has_cmd = false;
            while ppos < pong_slice.len() {
                let tag = pb_decode_varint(pong_slice, &mut ppos).unwrap();
                match ((tag >> 3) as u32, (tag & 7) as u8) {
                    (2, 0) => pong_ack = pb_decode_varint(pong_slice, &mut ppos).unwrap() != 0,
                    (3, 2) => {
                        let cmd_bytes = pb_decode_bytes(pong_slice, &mut ppos).unwrap();
                        assert!(!cmd_bytes.is_empty());
                        pong_has_cmd = true;
                    }
                    (_, wt) => pb_skip_field(pong_slice, &mut ppos, wt).unwrap(),
                }
            }
            assert!(pong_ack);
            assert!(
                pong_has_cmd,
                "queued command must be delivered on HeartbeatPong"
            );

            drop(ping_tx);
            let remaining = hb_incoming.collect().await.unwrap();
            assert_eq!(
                remaining
                    .trailers()
                    .and_then(|t| t.get("grpc-status"))
                    .and_then(|v| v.to_str().ok()),
                Some("0")
            );

            // Verify GetMetrics rejects enrolled worker cert (both without and WITH master PSK), then succeeds with admin cert
            let mut gm_pb = Vec::new();
            pb_encode_string(&mut gm_pb, 1, &got_node_id);
            let unauth_gm_req = Request::builder()
                .method("POST")
                .uri(format!(
                    "https://{}/cluster.ClusterService/GetMetrics",
                    worker_ep.authority
                ))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(&gm_pb))))
                .unwrap();
            let unauth_gm_resp = h2_sender.send_request(unauth_gm_req).await.unwrap();
            let unauth_gm_collected = unauth_gm_resp.into_body().collect().await.unwrap();
            assert_eq!(
                unauth_gm_collected
                    .trailers()
                    .and_then(|t| t.get("grpc-status"))
                    .and_then(|v| v.to_str().ok()),
                Some("16"),
                "worker certificate without master CLUSTER_PSK must be rejected on GetMetrics"
            );

            let worker_psk_gm_req = Request::builder()
                .method("POST")
                .uri(format!(
                    "https://{}/cluster.ClusterService/GetMetrics",
                    worker_ep.authority
                ))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .header("x-cluster-psk", psk)
                .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(&gm_pb))))
                .unwrap();
            let worker_psk_gm_resp = h2_sender.send_request(worker_psk_gm_req).await.unwrap();
            let worker_psk_gm_collected = worker_psk_gm_resp.into_body().collect().await.unwrap();
            assert_eq!(
                worker_psk_gm_collected
                    .trailers()
                    .and_then(|t| t.get("grpc-status"))
                    .and_then(|v| v.to_str().ok()),
                Some("16"),
                "enrolled worker certificate MUST be prohibited from GetMetrics even with shared CLUSTER_PSK"
            );

            // Dedicated control-plane certificate (CN=aetherflow-master) succeeds on GetMetrics WITHOUT PSK header
            let admin_gm_req = Request::builder()
                .method("POST")
                .uri(format!(
                    "https://{}/cluster.ClusterService/GetMetrics",
                    worker_ep.authority
                ))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(&gm_pb))))
                .unwrap();
            let admin_gm_resp = admin_h2.send_request(admin_gm_req).await.unwrap();
            let admin_gm_collected = admin_gm_resp.into_body().collect().await.unwrap();
            assert_eq!(
                admin_gm_collected
                    .trailers()
                    .and_then(|t| t.get("grpc-status"))
                    .and_then(|v| v.to_str().ok()),
                Some("0")
            );
            assert!(admin_gm_collected.to_bytes().len() > 15);

            // 6. Single-use enrollment token + second worker cert (`cli2_crt`) + cross-node spoofing rejection
            let worker2_sec = WorkerTransportSecurity::Mtls(
                build_worker_mtls_connector(&ca_crt, &cli2_crt, &cli2_key).unwrap(),
            );
            let enrollment_tok = issue_cluster_enrollment_token().unwrap();
            assert_eq!(enrollment_tok.len(), 64);

            let rust_reg = RegisterWorkerRequest {
                node_id: "node-rust-mtls-worker".to_string(),
                hostname: "rust-mtls-worker".to_string(),
                address: "10.10.0.13:8080".to_string(),
                psk: String::new(),
                version: "4.0.0".to_string(),
                system_info: None,
            };
            let rust_reg_json = serde_json::to_vec(&rust_reg).unwrap();
            assert!(!String::from_utf8_lossy(&rust_reg_json).contains(&enrollment_tok));
            let (st, body) = send_worker_json_post(
                &worker_ep,
                &worker2_sec,
                "/cluster/v1/register",
                &enrollment_tok,
                rust_reg_json,
            )
            .await
            .unwrap();
            assert_eq!(st, StatusCode::OK);
            let parsed_reg: RegisterWorkerResponse = serde_json::from_slice(&body).unwrap();
            assert!(parsed_reg.accepted);
            assert_eq!(parsed_reg.node_id, "node-rust-mtls-worker");

            // Replay of consumed single-use enrollment token for a different node MUST fail closed (401)
            let replay_reg = RegisterWorkerRequest {
                node_id: "node-rogue-replay".to_string(),
                hostname: "rogue-replay".to_string(),
                address: "10.10.0.99:8080".to_string(),
                psk: String::new(),
                version: "4.0.0".to_string(),
                system_info: None,
            };
            let (replay_st, _) = send_worker_json_post(
                &worker_ep,
                &worker2_sec,
                "/cluster/v1/register",
                &enrollment_tok,
                serde_json::to_vec(&replay_reg).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(
                replay_st,
                StatusCode::UNAUTHORIZED,
                "consumed single-use enrollment token must reject replay by another node"
            );

            // Worker-2 (`cli2_crt`) attempting to overwrite already-enrolled `node-legacy-go-worker` (`cli_crt`)
            // MUST fail closed (401) BOTH with master PSK and with a fresh unconsumed enrollment token!
            let original_pin: String = af_db::get_conn()
                .unwrap()
                .query_row(
                    "SELECT peer_cert_sha256 FROM cluster_nodes WHERE id = ?1",
                    params![got_node_id],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!original_pin.is_empty());

            let hijack_reg = RegisterWorkerRequest {
                node_id: got_node_id.clone(),
                hostname: "legacy-go-worker".to_string(),
                address: "10.10.0.99:8080".to_string(),
                psk: String::new(),
                version: "4.0.0".to_string(),
                system_info: None,
            };
            let (hijack_psk_st, _) = send_worker_json_post(
                &worker_ep,
                &worker2_sec,
                "/cluster/v1/register",
                psk,
                serde_json::to_vec(&hijack_reg).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(
                hijack_psk_st,
                StatusCode::UNAUTHORIZED,
                "mismatched peer certificate must not overwrite enrolled worker pin via shared CLUSTER_PSK"
            );

            let fresh_tok = issue_cluster_enrollment_token().unwrap();
            let (hijack_tok_st, _) = send_worker_json_post(
                &worker_ep,
                &worker2_sec,
                "/cluster/v1/register",
                &fresh_tok,
                serde_json::to_vec(&hijack_reg).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(
                hijack_tok_st,
                StatusCode::UNAUTHORIZED,
                "fresh single-use enrollment token must not overwrite an already-enrolled node"
            );
            let pin_after: String = af_db::get_conn()
                .unwrap()
                .query_row(
                    "SELECT peer_cert_sha256 FROM cluster_nodes WHERE id = ?1",
                    params![got_node_id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(pin_after, original_pin);
            let fresh_consumed: Option<String> = af_db::get_conn()
                .unwrap()
                .query_row(
                    "SELECT consumed_by FROM cluster_enrollment_tokens WHERE token_hash = ?1",
                    params![hash_psk_sha256(&fresh_tok)],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(
                fresh_consumed.is_none(),
                "rejected re-enrollment attempt must not consume unrelated enrollment token"
            );

            // Enrolled worker-2 can heartbeat for itself using its enrolled token...
            let (mut rust_hb, _) = build_worker_heartbeat_payload(
                "node-rust-mtls-worker",
                "rust-mtls-worker",
                "10.10.0.13:8080",
                "",
                &WorkerServiceInventory::default(),
            );
            rust_hb.psk.clear();
            let rust_hb_json = serde_json::to_vec(&rust_hb).unwrap();
            let (hb_st, hb_body) = send_worker_json_post(
                &worker_ep,
                &worker2_sec,
                "/cluster/v1/heartbeat",
                &enrollment_tok,
                rust_hb_json,
            )
            .await
            .unwrap();
            assert_eq!(hb_st, StatusCode::OK);
            let parsed_hb: WorkerHeartbeatResponse = serde_json::from_slice(&hb_body).unwrap();
            assert!(parsed_hb.acknowledged);

            // ...but worker-2 (`cli2_crt`) attempting to spoof `node-legacy-go-worker` (`cli_crt`) MUST be rejected EVEN with master PSK!
            let mut spoof_hb = rust_hb.clone();
            spoof_hb.node_id = got_node_id.clone();
            let (spoof_st, _) = send_worker_json_post(
                &worker_ep,
                &worker2_sec,
                "/cluster/v1/heartbeat",
                psk,
                serde_json::to_vec(&spoof_hb).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(
                spoof_st,
                StatusCode::UNAUTHORIZED,
                "peer certificate pinning must block cross-worker heartbeat spoofing"
            );

            server_task.abort();
        });
    }

    #[cfg(unix)]
    #[test]
    fn durable_sqlite_command_queue_leasing_ack_and_worker_backoff_registration() {
        let name =
            "cluster_daemon::tests::durable_sqlite_command_queue_leasing_ack_and_worker_backoff_registration";
        if !crate::inventory_regressions::isolated(name) {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let root = env::temp_dir().join(format!("af-cluster-p3-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let db_path = root.join("cluster.sqlite");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            env::set_var(key, &db_path);
        }
        env::set_var("CLUSTER_PSK", "master-secret-psk-1234567890");
        env::set_var("CLUSTER_REGISTER_INITIAL_BACKOFF_MS", "15");
        env::set_var("CLUSTER_REGISTER_MAX_BACKOFF_MS", "40");
        af_db::init_db().unwrap();
        ensure_cluster_schema();

        // 1. Enqueue durable command in SQLite
        let queued = enqueue_cluster_command("node-alpha", "restart_service", "sonarr").unwrap();
        assert_eq!(queued.status, "queued");

        // First lease succeeds; second lease before lease expiry returns None
        let first_lease = lease_next_worker_command("node-alpha", 1000, 30).unwrap();
        assert_eq!(first_lease.id, queued.id);
        assert_eq!(first_lease.cmd_type, "restart_service");
        assert_eq!(
            first_lease.params.get("service").map(String::as_str),
            Some("sonarr")
        );
        assert!(lease_next_worker_command("node-alpha", 1015, 30).is_none());

        // After lease expires (`now >= 1030`), command is re-leased cleanly
        let released = lease_next_worker_command("node-alpha", 1031, 30).unwrap();
        assert_eq!(released.id, queued.id);

        // Heartbeat carrying `command_acks` marks command terminal (`executed`) with message
        let hb_resp = process_worker_heartbeat(&WorkerHeartbeatRequest {
            node_id: "node-alpha".to_string(),
            hostname: "alpha".to_string(),
            address: "127.0.0.1:8080".to_string(),
            psk: "master-secret-psk-1234567890".to_string(),
            timestamp: 1035,
            command_acks: vec![WorkerCommandAck {
                id: queued.id.clone(),
                status: "executed".to_string(),
                result_message: Some("restart sonarr succeeded".to_string()),
            }],
            ..Default::default()
        })
        .unwrap();
        assert!(hb_resp.acknowledged);
        assert!(hb_resp.command.is_none());

        let listed = list_cluster_commands(Some("node-alpha"), 10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].status, "executed");
        assert_eq!(
            listed[0].result_message.as_deref(),
            Some("restart sonarr succeeded")
        );

        // 2. Worker registration retries bounded exponential backoff and persists 0600 O_NOFOLLOW state
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let attempts = Arc::new(AtomicUsize::new(0));
            let attempts_srv = Arc::clone(&attempts);

            let srv = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    let n = attempts_srv.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                        let (st, body) = if n < 2 {
                            (
                                "503 Service Unavailable",
                                r#"{"accepted":false,"message":"starting"}"#,
                            )
                        } else {
                            (
                                "200 OK",
                                r#"{"node_id":"node-backed-off-ok","accepted":true,"message":"enrolled"}"#,
                            )
                        };
                        let resp = format!(
                            "HTTP/1.1 {st}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    });
                }
            });

            let state_file = root.join("state/worker_reg.json");
            let ep = WorkerTargetEndpoint {
                scheme: "http".to_string(),
                host: "127.0.0.1".to_string(),
                port: addr.port(),
                authority: addr.to_string(),
            };
            let assigned = register_worker_with_bounded_backoff(
                &ep,
                &WorkerTransportSecurity::InsecureLoopback,
                "master-secret-psk-1234567890",
                "node-initial",
                "worker-host",
                "127.0.0.1:8080",
                &state_file,
            )
            .await;
            assert_eq!(assigned, "node-backed-off-ok");
            assert!(attempts.load(Ordering::SeqCst) >= 3);

            let mode = std::fs::symlink_metadata(&state_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            let loaded = load_worker_registration_state_nofollow(&state_file).unwrap();
            assert_eq!(loaded.node_id, "node-backed-off-ok");

            // Symlink state target must be rejected
            let sym_path = root.join("state/symlink_reg.json");
            std::os::unix::fs::symlink(&state_file, &sym_path).unwrap();
            assert!(persist_worker_registration_state_atomic(&sym_path, &loaded).is_err());
            assert!(load_worker_registration_state_nofollow(&sym_path).is_none());

            srv.abort();
        });

        let _ = std::fs::remove_dir_all(&root);
    }
}
