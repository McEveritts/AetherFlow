use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::pool::{get_conn, get_read_conn};

// ─────────────────────────────────────────────────────────────────────────────
// Admin Audit Trail
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuditEntry {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub detail: String,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: String,
}

#[allow(clippy::too_many_arguments)]
pub fn record_audit(
    user_id: i64,
    username: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    detail: &str,
    ip_address: &str,
    user_agent: &str,
) {
    let result = get_conn().and_then(|conn| {
        conn.execute(
            "INSERT INTO admin_audit_log (user_id, username, action, target_type, target_id, detail, ip_address, user_agent) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                user_id,
                username,
                action,
                target_type,
                target_id,
                detail,
                ip_address,
                user_agent
            ],
        )
        .map_err(Into::into)
    });
    if let Err(error) = result {
        tracing::error!(%error, "Could not persist administrator audit entry");
    }
}

pub fn query_audit_log(
    mut limit: i64,
    offset: i64,
    action: &str,
    username: &str,
) -> anyhow::Result<(Vec<AuditEntry>, i64)> {
    if limit <= 0 || limit > 200 {
        limit = 50;
    }
    let conn = get_read_conn()?;
    let mut where_sql = String::from("WHERE 1=1");
    let mut bind_vals: Vec<String> = Vec::new();
    if !action.is_empty() {
        bind_vals.push(action.to_string());
        where_sql.push_str(&format!(" AND action = ?{}", bind_vals.len()));
    }
    if !username.is_empty() {
        bind_vals.push(username.to_string());
        where_sql.push_str(&format!(" AND username = ?{}", bind_vals.len()));
    }

    let count_sql = format!("SELECT COUNT(*) FROM admin_audit_log {}", where_sql);
    let total: i64 = match bind_vals.len() {
        0 => conn.query_row(&count_sql, [], |r| r.get(0))?,
        1 => conn.query_row(&count_sql, params![bind_vals[0]], |r| r.get(0))?,
        _ => conn.query_row(&count_sql, params![bind_vals[0], bind_vals[1]], |r| {
            r.get(0)
        })?,
    };

    let list_sql = format!(
        "SELECT id, user_id, username, action, target_type, target_id, detail, ip_address, user_agent, COALESCE(CAST(created_at AS TEXT), '') \
         FROM admin_audit_log {} ORDER BY created_at DESC LIMIT {} OFFSET {}",
        where_sql,
        limit,
        offset.max(0)
    );

    let mut stmt = conn.prepare(&list_sql)?;
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<AuditEntry> {
        Ok(AuditEntry {
            id: r.get(0)?,
            user_id: r.get(1)?,
            username: r.get(2)?,
            action: r.get(3)?,
            target_type: r.get(4)?,
            target_id: r.get(5)?,
            detail: r.get(6)?,
            ip_address: r.get(7)?,
            user_agent: r.get(8)?,
            created_at: r.get(9)?,
        })
    };

    let mut entries = Vec::new();
    match bind_vals.len() {
        0 => {
            for row in stmt.query_map([], map_row)? {
                entries.push(row?);
            }
        }
        1 => {
            for row in stmt.query_map(params![bind_vals[0]], map_row)? {
                entries.push(row?);
            }
        }
        _ => {
            for row in stmt.query_map(params![bind_vals[0], bind_vals[1]], map_row)? {
                entries.push(row?);
            }
        }
    }

    Ok((entries, total))
}

pub fn list_audit_entries(
    limit: i64,
    offset: i64,
    action: &str,
    username: &str,
) -> anyhow::Result<(Vec<AuditEntry>, i64)> {
    query_audit_log(limit, offset, action, username)
}
