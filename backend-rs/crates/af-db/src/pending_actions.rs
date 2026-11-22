use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::pool::{get_conn, get_read_conn};

// ─────────────────────────────────────────────────────────────────────────────
// Action Approval Gates
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PendingAction {
    pub id: i64,
    pub classification: String,
    pub source: String,
    pub action: String,
    pub reason: String,
    pub status: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resolved_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub resolved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub execution_log: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub job_unit: Option<String>,
}

fn pending_actions_has_job_unit(conn: &Connection) -> bool {
    conn.prepare("PRAGMA table_info(pending_actions)")
        .and_then(|mut stmt| {
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                if name.eq_ignore_ascii_case("job_unit") {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .unwrap_or(false)
}

fn pending_action_select_columns(conn: &Connection) -> &'static str {
    if pending_actions_has_job_unit(conn) {
        "id, COALESCE(classification, 'warn'), COALESCE(source, ''), COALESCE(action, ''), COALESCE(reason, ''), COALESCE(status, 'pending'), COALESCE(CAST(created_at AS TEXT), ''), CAST(resolved_at AS TEXT), resolved_by, execution_log, NULLIF(TRIM(COALESCE(job_unit, '')), '')"
    } else {
        "id, COALESCE(classification, 'warn'), COALESCE(source, ''), COALESCE(action, ''), COALESCE(reason, ''), COALESCE(status, 'pending'), COALESCE(CAST(created_at AS TEXT), ''), CAST(resolved_at AS TEXT), resolved_by, execution_log, NULL"
    }
}

fn map_pending_action_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<PendingAction> {
    Ok(PendingAction {
        id: r.get(0)?,
        classification: r.get(1)?,
        source: r.get(2)?,
        action: r.get(3)?,
        reason: r.get(4)?,
        status: r.get(5)?,
        created_at: r.get(6)?,
        resolved_at: r.get(7).ok().flatten(),
        resolved_by: r.get(8).ok().flatten(),
        execution_log: r.get(9).ok().flatten(),
        job_unit: r.get(10).ok().flatten(),
    })
}

pub const MAX_PENDING_ACTIONS: i64 = 50;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueActionOutcome {
    Queued { action_id: i64 },
    SkippedSafe,
    AlreadyPending,
    CapacityReached { pending_count: i64, limit: i64 },
    DbError(String),
}

impl QueueActionOutcome {
    pub fn queued_action_id(&self) -> Option<i64> {
        match *self {
            Self::Queued { action_id } if action_id > 0 => Some(action_id),
            _ => None,
        }
    }
}

pub fn count_pending_actions() -> anyhow::Result<i64> {
    let conn = get_read_conn()?;
    count_pending_actions_with_connection(&conn)
}

pub(crate) fn count_pending_actions_with_connection(conn: &Connection) -> anyhow::Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM pending_actions WHERE COALESCE(status, 'pending') = 'pending'",
        [],
        |row| row.get::<_, i64>(0),
    )?)
}

pub fn queue_action(
    classification: &str,
    source: &str,
    action: &str,
    reason: &str,
) -> QueueActionOutcome {
    queue_action_inner(classification, source, action, reason, false)
}

pub fn queue_action_if_not_pending(
    classification: &str,
    source: &str,
    action: &str,
    reason: &str,
) -> QueueActionOutcome {
    queue_action_inner(classification, source, action, reason, true)
}

fn queue_action_inner(
    classification: &str,
    source: &str,
    action: &str,
    reason: &str,
    deduplicate_pending: bool,
) -> QueueActionOutcome {
    if classification == "safe" {
        return QueueActionOutcome::SkippedSafe;
    }
    let mut conn = match get_conn() {
        Ok(conn) => conn,
        Err(err) => return QueueActionOutcome::DbError(err.to_string()),
    };
    queue_action_with_connection(
        &mut conn,
        classification,
        source,
        action,
        reason,
        deduplicate_pending,
    )
}

pub(crate) fn queue_action_with_connection(
    conn: &mut Connection,
    classification: &str,
    source: &str,
    action: &str,
    reason: &str,
    deduplicate_pending: bool,
) -> QueueActionOutcome {
    if classification == "safe" {
        return QueueActionOutcome::SkippedSafe;
    }
    // Invariant: pending count, optional dedup check, and insert share one IMMEDIATE
    // transaction so competing writers cannot bypass MAX_PENDING_ACTIONS, and Queued
    // is returned only after commit confirms a positive row ID.
    let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(err) => return QueueActionOutcome::DbError(err.to_string()),
    };
    if deduplicate_pending {
        let already_pending = match tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pending_actions WHERE COALESCE(status, 'pending') = 'pending' AND source = ?1 AND action = ?2)",
            params![source, action],
            |r| r.get::<_, bool>(0),
        ) {
            Ok(exists) => exists,
            Err(err) => return QueueActionOutcome::DbError(err.to_string()),
        };
        if already_pending {
            return QueueActionOutcome::AlreadyPending;
        }
    }
    let pending_count = match count_pending_actions_with_connection(&tx) {
        Ok(count) => count,
        Err(err) => return QueueActionOutcome::DbError(err.to_string()),
    };
    if pending_count >= MAX_PENDING_ACTIONS {
        return QueueActionOutcome::CapacityReached {
            pending_count,
            limit: MAX_PENDING_ACTIONS,
        };
    }
    let inserted = match tx.execute(
        "INSERT INTO pending_actions (classification, source, action, reason, status) VALUES (?1, ?2, ?3, ?4, 'pending')",
        params![classification, source, action, reason],
    ) {
        Ok(rows) => rows,
        Err(err) => return QueueActionOutcome::DbError(err.to_string()),
    };
    let action_id = tx.last_insert_rowid();
    if inserted != 1 || action_id <= 0 {
        return QueueActionOutcome::DbError(format!(
            "pending_actions insert did not yield a positive row id (rows={inserted}, id={action_id})"
        ));
    }
    if let Err(err) = tx.commit() {
        return QueueActionOutcome::DbError(err.to_string());
    }
    QueueActionOutcome::Queued { action_id }
}

pub fn mark_action_executed(action_id: i64, execution_log: &str) {
    if let Ok(conn) = get_conn() {
        let now = Utc::now().to_rfc3339();
        let _ = conn.execute(
            "UPDATE pending_actions SET status = 'executed', resolved_at = ?1, execution_log = ?2 WHERE id = ?3 AND status = 'approved'",
            params![now, execution_log, action_id],
        );
    }
}

pub fn mark_action_failed(action_id: i64, execution_log: &str) {
    if let Ok(conn) = get_conn() {
        let now = Utc::now().to_rfc3339();
        let _ = conn.execute(
            "UPDATE pending_actions SET status = 'failed', resolved_at = ?1, execution_log = ?2 WHERE id = ?3 AND status = 'approved'",
            params![now, execution_log, action_id],
        );
    }
}

pub fn mark_action_queued(
    action_id: i64,
    job_unit: &str,
    execution_log: &str,
) -> anyhow::Result<PendingAction> {
    let conn = get_conn()?;
    mark_action_queued_with_connection(&conn, action_id, job_unit, execution_log)
}

pub(crate) fn mark_action_queued_with_connection(
    conn: &Connection,
    action_id: i64,
    job_unit: &str,
    execution_log: &str,
) -> anyhow::Result<PendingAction> {
    let unit = job_unit.trim();
    anyhow::ensure!(!unit.is_empty(), "job_unit is required to queue an action");
    let changed = conn.execute(
        "UPDATE pending_actions SET status = 'queued', job_unit = ?1, execution_log = ?2 WHERE id = ?3 AND status = 'approved'",
        params![unit, execution_log, action_id],
    )?;
    if changed == 0 {
        anyhow::bail!("Action not found or not awaiting deferred queue persistence");
    }
    get_pending_action_by_id_with_connection(conn, action_id)?
        .ok_or_else(|| anyhow::anyhow!("Action disappeared after queueing"))
}

pub fn mark_action_unavailable(
    action_id: i64,
    job_unit: Option<&str>,
    execution_log: &str,
) -> anyhow::Result<Option<PendingAction>> {
    let conn = get_conn()?;
    mark_action_unavailable_with_connection(&conn, action_id, job_unit, execution_log)
}

fn mark_action_unavailable_with_connection(
    conn: &Connection,
    action_id: i64,
    job_unit: Option<&str>,
    execution_log: &str,
) -> anyhow::Result<Option<PendingAction>> {
    let now = Utc::now().to_rfc3339();
    let normalized_unit = job_unit.map(str::trim).filter(|u| !u.is_empty());
    if let Some(unit) = normalized_unit {
        conn.execute(
            "UPDATE pending_actions SET status = 'unavailable', resolved_at = ?1, execution_log = ?2, job_unit = COALESCE(NULLIF(TRIM(COALESCE(job_unit, '')), ''), ?3) \
             WHERE id = ?4 AND status IN ('approved', 'queued') AND COALESCE(TRIM(job_unit), '') IN ('', ?3)",
            params![now, execution_log, unit, action_id],
        )?;
    } else {
        conn.execute(
            "UPDATE pending_actions SET status = 'unavailable', resolved_at = ?1, execution_log = ?2 \
             WHERE id = ?3 AND status IN ('approved', 'queued')",
            params![now, execution_log, action_id],
        )?;
    }
    get_pending_action_by_id_with_connection(conn, action_id)
}

pub fn finalize_queued_action_by_id(
    action_id: i64,
    expected_job_unit: &str,
    final_status: &str,
    execution_log: &str,
) -> anyhow::Result<Option<PendingAction>> {
    let conn = get_conn()?;
    finalize_queued_action_by_id_with_connection(
        &conn,
        action_id,
        expected_job_unit,
        final_status,
        execution_log,
    )
}

pub(crate) fn finalize_queued_action_by_id_with_connection(
    conn: &Connection,
    action_id: i64,
    expected_job_unit: &str,
    final_status: &str,
    execution_log: &str,
) -> anyhow::Result<Option<PendingAction>> {
    anyhow::ensure!(
        matches!(final_status, "executed" | "failed" | "unavailable"),
        "Invalid final action status"
    );
    let unit = expected_job_unit.trim();
    anyhow::ensure!(!unit.is_empty(), "expected_job_unit is required");
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE pending_actions SET status = ?1, resolved_at = ?2, execution_log = ?3 \
         WHERE id = ?4 AND status IN ('approved', 'queued') AND job_unit = ?5",
        params![final_status, now, execution_log, action_id, unit],
    )?;
    get_pending_action_by_id_with_connection(conn, action_id)
}

pub fn finalize_queued_action_by_job_unit(
    job_unit: &str,
    final_status: &str,
    execution_log: &str,
) -> anyhow::Result<usize> {
    let conn = get_conn()?;
    finalize_queued_action_by_job_unit_with_connection(&conn, job_unit, final_status, execution_log)
}

pub(crate) fn finalize_queued_action_by_job_unit_with_connection(
    conn: &Connection,
    job_unit: &str,
    final_status: &str,
    execution_log: &str,
) -> anyhow::Result<usize> {
    anyhow::ensure!(
        matches!(final_status, "executed" | "failed" | "unavailable"),
        "Invalid final action status"
    );
    let unit = job_unit.trim();
    anyhow::ensure!(!unit.is_empty(), "job_unit is required");
    if !pending_actions_has_job_unit(conn) {
        return Ok(0);
    }
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE pending_actions SET status = ?1, resolved_at = ?2, execution_log = ?3 \
         WHERE job_unit = ?4 AND status IN ('approved', 'queued')",
        params![final_status, now, execution_log, unit],
    )?;
    Ok(changed)
}

pub fn list_queued_actions_with_receipts(limit: i64) -> anyhow::Result<Vec<PendingAction>> {
    let conn = get_read_conn()?;
    list_queued_actions_with_receipts_with_connection(&conn, limit)
}

pub(crate) fn list_queued_actions_with_receipts_with_connection(
    conn: &Connection,
    limit: i64,
) -> anyhow::Result<Vec<PendingAction>> {
    if !pending_actions_has_job_unit(conn) {
        return Ok(Vec::new());
    }
    let limit = limit.clamp(1, 100);
    let cols = pending_action_select_columns(conn);
    let mut stmt = conn.prepare(&format!(
        "SELECT {cols} FROM pending_actions WHERE status = 'queued' AND NULLIF(TRIM(COALESCE(job_unit, '')), '') IS NOT NULL ORDER BY created_at DESC, id DESC LIMIT ?1",
    ))?;
    let rows = stmt.query_map(params![limit], map_pending_action_row)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn list_pending_actions(mut limit: i64, offset: i64) -> anyhow::Result<Vec<PendingAction>> {
    if limit <= 0 {
        limit = 50;
    } else if limit > 500 {
        limit = 500;
    }
    let conn = get_read_conn()?;
    let cols = pending_action_select_columns(&conn);
    let mut stmt = conn.prepare(&format!(
        "SELECT {cols} FROM pending_actions ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
    ))?;
    let rows = stmt.query_map(params![limit, offset.max(0)], map_pending_action_row)?;
    let mut actions = Vec::new();
    for r in rows {
        actions.push(r?);
    }
    Ok(actions)
}

pub fn query_pending_actions(
    status_filter: &str,
    limit: i64,
    offset: i64,
) -> anyhow::Result<(Vec<PendingAction>, i64)> {
    let conn = get_read_conn()?;
    query_pending_actions_with_connection(&conn, status_filter, limit, offset)
}

pub(crate) fn query_pending_actions_with_connection(
    conn: &Connection,
    status_filter: &str,
    limit: i64,
    offset: i64,
) -> anyhow::Result<(Vec<PendingAction>, i64)> {
    let limit = if limit <= 0 { 50 } else { limit.clamp(1, 500) };
    let offset = offset.max(0);
    let predicate = match status_filter {
        "all" | "" => "1 = 1",
        "pending" => "COALESCE(status, 'pending') = 'pending'",
        "approved_history" => {
            "COALESCE(status, 'pending') IN ('approved', 'queued', 'executed', 'failed', 'unavailable')"
        }
        "approved" | "queued" | "rejected" | "executed" | "failed" | "unavailable" => {
            "COALESCE(status, 'pending') = ?"
        }
        _ => anyhow::bail!("Invalid status filter"),
    };
    let mut bindings = Vec::<rusqlite::types::Value>::new();
    if predicate.ends_with("= ?") {
        bindings.push(status_filter.to_owned().into());
    }
    let total = conn.query_row(
        &format!("SELECT COUNT(*) FROM pending_actions WHERE {predicate}"),
        rusqlite::params_from_iter(bindings.iter()),
        |row| row.get::<_, i64>(0),
    )?;
    bindings.push(limit.into());
    bindings.push(offset.into());
    let cols = pending_action_select_columns(conn);
    let mut stmt = conn.prepare(&format!(
        "SELECT {cols} FROM pending_actions WHERE {predicate} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
    ))?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(bindings.iter()),
        map_pending_action_row,
    )?;
    Ok((rows.collect::<rusqlite::Result<Vec<_>>>()?, total))
}

pub fn get_pending_action_by_id(action_id: i64) -> anyhow::Result<Option<PendingAction>> {
    let conn = get_read_conn()?;
    get_pending_action_by_id_with_connection(&conn, action_id)
}

pub(crate) fn get_pending_action_by_id_with_connection(
    conn: &Connection,
    action_id: i64,
) -> anyhow::Result<Option<PendingAction>> {
    let cols = pending_action_select_columns(conn);
    let mut stmt = conn.prepare(&format!("SELECT {cols} FROM pending_actions WHERE id = ?1",))?;
    let res = stmt.query_row(params![action_id], map_pending_action_row);
    match res {
        Ok(action) => Ok(Some(action)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn resolve_action(
    action_id: i64,
    new_status: &str,
    resolved_by: &str,
) -> anyhow::Result<PendingAction> {
    let conn = get_conn()?;
    let now = Utc::now().to_rfc3339();
    let changed = conn.execute(
        "UPDATE pending_actions SET status = ?1, resolved_at = ?2, resolved_by = ?3 WHERE id = ?4 AND status = 'pending'",
        params![new_status, now, resolved_by, action_id],
    )?;
    if changed == 0 {
        anyhow::bail!("Action not found or already resolved");
    }
    get_pending_action_by_id_with_connection(&conn, action_id)?
        .ok_or_else(|| anyhow::anyhow!("Action disappeared after resolve"))
}
