use super::auth::ensure_cluster_schema;
use super::types::{ClusterCommandRecord, PendingWorkerCommand, WorkerCommandAck};
use anyhow::Context;
use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::params;
use std::collections::HashMap;
use std::sync::RwLock;

// ─────────────────────────────────────────────────────────────────────────────
// In-Memory Telemetry & Durable SQLite Command Queue
// ─────────────────────────────────────────────────────────────────────────────

pub(super) const CLUSTER_COMMAND_LEASE_SECS: i64 = 30;
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

/// Slices `s` at the largest valid UTF-8 character boundary `<= max_bytes`.
#[inline]
pub fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut idx = max_bytes;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    &s[..idx]
}

pub(super) fn truncate_diagnostic_utf8(raw: &str, max_bytes: usize) -> String {
    let clean: String = raw
        .chars()
        .filter(|c| *c != '\r' && *c != '\n' && !c.is_control())
        .collect();
    let trimmed = clean.trim();
    if trimmed.len() <= max_bytes {
        return trimmed.to_string();
    }
    if max_bytes <= 3 {
        return truncate_utf8(trimmed, max_bytes).to_string();
    }
    let prefix = truncate_utf8(trimmed, max_bytes - 3);
    format!("{prefix}...")
}

/// Structured classification for cluster command admission, capacity, and persistence errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterCommandEnqueueError {
    InvalidInput(String),
    QueueFull(String),
    Storage(String),
}

impl std::fmt::Display for ClusterCommandEnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(msg) | Self::QueueFull(msg) | Self::Storage(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ClusterCommandEnqueueError {}

/// Canonical, admission-validated cluster worker command ready for durable persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedClusterCommand {
    pub node_id: String,
    pub cmd_type: &'static str,
    pub target: String,
}

/// Strictly validates whether `cmd_type` is an allowed remote cluster command verb.
#[inline]
pub fn is_allowed_worker_command_type(cmd_type: &str) -> bool {
    matches!(
        cmd_type.trim(),
        "restart_service"
            | "start_service"
            | "stop_service"
            | "reload_service"
            | "systemctl"
            | "ping"
    )
}

fn is_valid_command_target(cmd_type: &str, target: &str) -> bool {
    let clean = target.trim();
    if cmd_type.trim() == "ping" && clean.is_empty() {
        return true;
    }
    !clean.is_empty()
        && clean.len() <= 128
        && clean
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b':'))
}

/// Validates and normalizes any remote cluster command (including legacy `systemctl` + `action`)
/// into its canonical worker-executable verb before durable enqueue.
pub fn normalize_cluster_command(
    node_id: &str,
    cmd_type: &str,
    target: &str,
    action: Option<&str>,
) -> Result<NormalizedClusterCommand, ClusterCommandEnqueueError> {
    let clean_node = node_id.trim();
    if clean_node.is_empty() || clean_node.len() > 128 {
        return Err(ClusterCommandEnqueueError::InvalidInput(
            "valid node_id is required".to_string(),
        ));
    }

    let clean_type = cmd_type.trim();
    let clean_action = action
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());

    let canonical_type: &'static str = match clean_type {
        "restart_service" => "restart_service",
        "start_service" => "start_service",
        "stop_service" => "stop_service",
        "reload_service" => "reload_service",
        "ping" => "ping",
        "systemctl" => match clean_action.as_deref() {
            None | Some("restart") => "restart_service",
            Some("start") => "start_service",
            Some("stop") => "stop_service",
            Some("reload") => "reload_service",
            Some(other) => {
                return Err(ClusterCommandEnqueueError::InvalidInput(format!(
                    "unsupported systemctl action '{}' (allowed: start, stop, restart, reload)",
                    truncate_diagnostic_utf8(other, 64)
                )));
            }
        },
        _ => {
            return Err(ClusterCommandEnqueueError::InvalidInput(
                "unsupported cluster command type (allowed: restart_service, start_service, stop_service, reload_service, systemctl, ping)".to_string(),
            ));
        }
    };

    let clean_target = target.trim();
    if !is_valid_command_target(canonical_type, clean_target) {
        return Err(ClusterCommandEnqueueError::InvalidInput(
            "invalid command target identifier".to_string(),
        ));
    }

    Ok(NormalizedClusterCommand {
        node_id: clean_node.to_string(),
        cmd_type: canonical_type,
        target: clean_target.to_string(),
    })
}

fn insert_normalized_cluster_command_atomic(
    cmd_id: Option<&str>,
    normalized: &NormalizedClusterCommand,
    ignore_duplicate: bool,
) -> Result<Option<ClusterCommandRecord>, ClusterCommandEnqueueError> {
    let mut conn = af_db::get_conn().map_err(|err| {
        ClusterCommandEnqueueError::Storage(format!("database unavailable: {err}"))
    })?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|err| {
            ClusterCommandEnqueueError::Storage(format!(
                "failed to start cluster command transaction: {err}"
            ))
        })?;
    let active_count: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM cluster_commands WHERE node_id = ?1 AND status IN ('queued', 'leased')",
            params![normalized.node_id],
            |r| r.get(0),
        )
        .map_err(|err| {
            ClusterCommandEnqueueError::Storage(format!(
                "failed to check worker command queue capacity: {err}"
            ))
        })?;
    if active_count >= MAX_PENDING_COMMANDS_PER_NODE {
        return Err(ClusterCommandEnqueueError::QueueFull(format!(
            "worker command queue is full for node '{}'",
            normalized.node_id
        )));
    }

    let final_id = cmd_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("cmd-{}", uuid::Uuid::new_v4().simple()));
    let now_iso = Utc::now().to_rfc3339();
    let sql = if ignore_duplicate {
        "INSERT OR IGNORE INTO cluster_commands (id, node_id, cmd_type, target, status, leased_until, lease_generation, result_message, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'queued', NULL, 0, NULL, ?5, ?5)"
    } else {
        "INSERT INTO cluster_commands (id, node_id, cmd_type, target, status, leased_until, lease_generation, result_message, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'queued', NULL, 0, NULL, ?5, ?5)"
    };
    let changed = tx
        .execute(
            sql,
            params![
                final_id,
                normalized.node_id,
                normalized.cmd_type,
                normalized.target,
                now_iso
            ],
        )
        .map_err(|err| {
            ClusterCommandEnqueueError::Storage(format!("failed to persist cluster command: {err}"))
        })?;
    tx.commit().map_err(|err| {
        ClusterCommandEnqueueError::Storage(format!("failed to commit cluster command: {err}"))
    })?;
    if changed == 0 {
        return Ok(None);
    }

    Ok(Some(ClusterCommandRecord {
        id: final_id,
        node_id: normalized.node_id.clone(),
        cmd_type: normalized.cmd_type.to_string(),
        target: normalized.target.clone(),
        status: "queued".to_string(),
        leased_until: None,
        lease_generation: 0,
        result_message: None,
        created_at: now_iso.clone(),
        updated_at: now_iso,
    }))
}

/// Enqueues a validated remote command (normalizing legacy `systemctl` + optional `action`)
/// atomically into durable SQLite `cluster_commands`.
pub fn enqueue_cluster_command_with_action(
    node_id: &str,
    cmd_type: &str,
    target: &str,
    action: Option<&str>,
) -> anyhow::Result<ClusterCommandRecord> {
    ensure_cluster_schema();
    let normalized =
        normalize_cluster_command(node_id, cmd_type, target, action).map_err(anyhow::Error::new)?;
    let record = insert_normalized_cluster_command_atomic(None, &normalized, false)
        .map_err(anyhow::Error::new)?
        .ok_or_else(|| {
            anyhow::Error::new(ClusterCommandEnqueueError::Storage(
                "failed to persist cluster command".to_string(),
            ))
        })?;
    Ok(record)
}

/// Enqueues a validated remote command into durable SQLite `cluster_commands`.
pub fn enqueue_cluster_command(
    node_id: &str,
    cmd_type: &str,
    target: &str,
) -> anyhow::Result<ClusterCommandRecord> {
    enqueue_cluster_command_with_action(node_id, cmd_type, target, None)
}

/// Atomically validates, normalizes, checks queue capacity, and inserts a worker command,
/// returning typed admission/capacity/storage errors instead of swallowing SQLite failures.
pub fn queue_worker_command_checked(
    node_id: &str,
    cmd: PendingWorkerCommand,
) -> Result<bool, ClusterCommandEnqueueError> {
    ensure_cluster_schema();
    let target = cmd
        .params
        .get("service")
        .or_else(|| cmd.params.get("target"))
        .map(String::as_str)
        .unwrap_or("");
    let action = cmd.params.get("action").map(String::as_str);
    let normalized = normalize_cluster_command(node_id, &cmd.cmd_type, target, action)?;
    let inserted = insert_normalized_cluster_command_atomic(Some(&cmd.id), &normalized, true)?;
    Ok(inserted.is_some())
}

/// Queues a remote command for delivery to a worker node on its next heartbeat response (durable SQLite wrapper).
pub fn queue_worker_command(node_id: &str, cmd: PendingWorkerCommand) -> bool {
    queue_worker_command_checked(node_id, cmd).unwrap_or(false)
}

/// Leases the next queued (or lease-expired) command for `node_id` from SQLite `cluster_commands`,
/// incrementing `lease_generation` monotonically so delayed acks from expired leases are fenced.
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
    let candidate: Option<(String, String, String, i64)> = tx
        .query_row(
            "SELECT id, cmd_type, target, COALESCE(lease_generation, 0)
             FROM cluster_commands
             WHERE node_id = ?1
               AND (status = 'queued' OR (status = 'leased' AND COALESCE(leased_until, 0) <= ?2))
             ORDER BY created_at ASC, rowid ASC
             LIMIT 1",
            params![node_id, now_unix],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .ok();
    let (id, cmd_type, target, prev_gen) = candidate?;
    let next_gen = prev_gen.saturating_add(1);
    let lease_until = now_unix.saturating_add(lease_secs.max(5));
    let now_iso = Utc::now().to_rfc3339();
    let updated = tx
        .execute(
            "UPDATE cluster_commands
             SET status = 'leased',
                 leased_until = ?1,
                 lease_generation = ?2,
                 updated_at = ?3
             WHERE id = ?4 AND node_id = ?5
               AND COALESCE(lease_generation, 0) = ?6
               AND (status = 'queued' OR (status = 'leased' AND COALESCE(leased_until, 0) <= ?7))",
            params![
                lease_until,
                next_gen,
                now_iso,
                id,
                node_id,
                prev_gen,
                now_unix
            ],
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
    params_map.insert("lease_generation".to_string(), next_gen.to_string());
    Some(PendingWorkerCommand {
        id,
        cmd_type,
        params: params_map,
        lease_generation: next_gen,
    })
}

/// Compatibility alias leasing the next durable worker command using default lease duration.
pub fn pop_worker_command(node_id: &str) -> Option<PendingWorkerCommand> {
    lease_next_worker_command(node_id, Utc::now().timestamp(), CLUSTER_COMMAND_LEASE_SECS)
}

pub const WORKER_COMMAND_STATUS_EXECUTED: &str = "executed";
pub const WORKER_COMMAND_STATUS_FAILED: &str = "failed";
pub const WORKER_COMMAND_STATUS_UNKNOWN: &str = "unknown";

#[inline]
fn is_terminal_worker_command_status(status: &str) -> bool {
    matches!(
        status,
        WORKER_COMMAND_STATUS_EXECUTED
            | WORKER_COMMAND_STATUS_FAILED
            | WORKER_COMMAND_STATUS_UNKNOWN
    )
}

/// Records terminal execution status (`executed`, `failed`, or `unknown`) reported by `node_id`,
/// enforcing lease-generation fencing when `ack.lease_generation` is present.
///
/// `unknown` is a distinct operator-visible terminal state reported when a worker persisted
/// pre-mutation execution intent for an admitted non-idempotent command and restarted before
/// persisting a final outcome; the master stops re-leasing the command so an operator can inspect
/// host state before issuing a fresh command.
pub fn acknowledge_worker_command(node_id: &str, ack: &WorkerCommandAck) -> anyhow::Result<bool> {
    ensure_cluster_schema();
    let clean_id = ack.id.trim();
    let clean_status = ack.status.trim().to_ascii_lowercase();
    anyhow::ensure!(!clean_id.is_empty(), "command id is required");
    anyhow::ensure!(
        is_terminal_worker_command_status(clean_status.as_str()),
        "command ack status must be 'executed', 'failed', or 'unknown'"
    );
    let msg = ack
        .result_message
        .as_deref()
        .map(|s| truncate_utf8(s.trim(), 1024).to_string())
        .filter(|s| !s.is_empty());
    let now_iso = Utc::now().to_rfc3339();
    let conn = af_db::get_conn().context("database unavailable")?;
    let changed = if let Some(ack_gen) = ack.lease_generation {
        if ack_gen <= 0 {
            return Ok(false);
        }
        conn.execute(
            "UPDATE cluster_commands
             SET status = ?1,
                 leased_until = NULL,
                 result_message = ?2,
                 updated_at = ?3
             WHERE id = ?4
               AND node_id = ?5
               AND status = 'leased'
               AND COALESCE(lease_generation, 0) = ?6",
            params![
                clean_status,
                msg,
                now_iso,
                clean_id,
                node_id.trim(),
                ack_gen
            ],
        )?
    } else {
        conn.execute(
            "UPDATE cluster_commands
             SET status = ?1,
                 leased_until = NULL,
                 result_message = ?2,
                 updated_at = ?3
             WHERE id = ?4 AND node_id = ?5 AND status IN ('queued', 'leased')",
            params![clean_status, msg, now_iso, clean_id, node_id.trim()],
        )?
    };
    if changed > 0 {
        return Ok(true);
    }
    let existing_state: Option<(String, i64)> = match conn.query_row(
        "SELECT status, COALESCE(lease_generation, 0) FROM cluster_commands WHERE id = ?1 AND node_id = ?2",
        params![clean_id, node_id.trim()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ) {
        Ok(pair) => Some(pair),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(err) => return Err(err).context("failed querying cluster command terminal state"),
    };
    match existing_state {
        Some((st, existing_gen))
            if is_terminal_worker_command_status(st.as_str())
                && st == clean_status
                && (ack.lease_generation.is_none()
                    || ack.lease_generation == Some(existing_gen)) =>
        {
            Ok(true)
        }
        _ => Ok(false),
    }
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
        "SELECT id, node_id, cmd_type, target, status, leased_until, COALESCE(lease_generation, 0), result_message, created_at, updated_at
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
                lease_generation: r.get(6)?,
                result_message: r.get(7)?,
                created_at: r.get(8)?,
                updated_at: r.get(9)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}
