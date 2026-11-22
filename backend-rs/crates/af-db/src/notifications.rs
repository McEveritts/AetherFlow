use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::pool::{get_conn, get_read_conn, run_atomic_migration_tx};

// ─────────────────────────────────────────────────────────────────────────────
// Per-User Notification Read State Helpers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserNotificationRow {
    pub id: i64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_id: Option<i64>,
    pub level: String,
    pub title: String,
    pub message: String,
    pub read: bool,
    pub created_at: String,
}

pub const UNREAD_NOTIFICATIONS_COUNT_FOR_USER_SQL: &str = "
    SELECT COUNT(*)
    FROM notifications n
    LEFT JOIN notification_reads nr
        ON nr.notification_id = n.id AND nr.user_id = ?1
    WHERE (n.user_id = ?1 OR n.user_id IS NULL)
      AND CASE
            WHEN n.user_id IS NULL THEN (COALESCE(n.read, 0) = 0 AND nr.notification_id IS NULL)
            ELSE COALESCE(n.read, 0) = 0
          END
";

pub const LIST_NOTIFICATIONS_FOR_USER_SQL: &str = "
    SELECT
        n.id,
        n.user_id,
        n.level,
        n.title,
        n.message,
        CASE
            WHEN n.user_id IS NULL THEN (COALESCE(n.read, 0) != 0 OR nr.notification_id IS NOT NULL)
            ELSE COALESCE(n.read, 0) != 0
        END AS effective_read,
        COALESCE(CAST(n.created_at AS TEXT), '')
    FROM notifications n
    LEFT JOIN notification_reads nr
        ON nr.notification_id = n.id AND nr.user_id = ?1
    WHERE (n.user_id = ?1 OR n.user_id IS NULL)
    ORDER BY n.created_at DESC, n.id DESC
    LIMIT ?2 OFFSET ?3
";

/// Marks a single notification read for `user_id`.
///
/// User-owned rows (`user_id = ?`) update `notifications.read = 1`.
/// Broadcast rows (`user_id IS NULL`) record `(notification_id, user_id)` in `notification_reads`
/// without mutating `notifications.read`, preserving unread state for other users.
pub fn mark_notification_read_for_user(user_id: i64, notification_id: i64) -> anyhow::Result<bool> {
    let conn = get_conn()?;
    mark_notification_read_for_user_with_conn(&conn, user_id, notification_id)
}

pub fn mark_notification_read_for_user_with_conn(
    conn: &Connection,
    user_id: i64,
    notification_id: i64,
) -> anyhow::Result<bool> {
    run_atomic_migration_tx(conn, |tx_conn| {
        let owner_id: Option<Option<i64>> = tx_conn
            .query_row(
                "SELECT user_id FROM notifications WHERE id = ?1",
                params![notification_id],
                |r| r.get(0),
            )
            .optional()?;
        match owner_id {
            None => Ok(false),
            Some(Some(owner)) if owner != user_id => Ok(false),
            Some(Some(_)) => {
                tx_conn.execute(
                    "UPDATE notifications SET read = 1 WHERE id = ?1 AND user_id = ?2",
                    params![notification_id, user_id],
                )?;
                Ok(true)
            }
            Some(None) => {
                tx_conn.execute(
                    "INSERT OR IGNORE INTO notification_reads (notification_id, user_id) VALUES (?1, ?2)",
                    params![notification_id, user_id],
                )?;
                Ok(true)
            }
        }
    })
}

/// Dismisses all unread notifications visible to `user_id`.
///
/// User-owned rows (`user_id = ?`) are marked `read = 1`; broadcast rows (`user_id IS NULL`)
/// are recorded in `notification_reads` for `user_id` without mutating `notifications.read`.
/// Returns the number of notifications newly marked read for `user_id`.
pub fn dismiss_all_notifications_for_user(user_id: i64) -> anyhow::Result<usize> {
    let conn = get_conn()?;
    dismiss_all_notifications_for_user_with_conn(&conn, user_id)
}

pub fn dismiss_all_notifications_for_user_with_conn(
    conn: &Connection,
    user_id: i64,
) -> anyhow::Result<usize> {
    run_atomic_migration_tx(conn, |tx_conn| {
        let owned_updated = tx_conn.execute(
            "UPDATE notifications SET read = 1 WHERE user_id = ?1 AND COALESCE(read, 0) = 0",
            params![user_id],
        )?;
        let broadcast_inserted = tx_conn.execute(
            "INSERT OR IGNORE INTO notification_reads (notification_id, user_id)
             SELECT n.id, ?1
             FROM notifications n
             LEFT JOIN notification_reads nr
                 ON nr.notification_id = n.id AND nr.user_id = ?1
             WHERE n.user_id IS NULL
               AND COALESCE(n.read, 0) = 0
               AND nr.notification_id IS NULL",
            params![user_id],
        )?;
        Ok(owned_updated + broadcast_inserted)
    })
}

pub fn count_unread_notifications_for_user(user_id: i64) -> anyhow::Result<i64> {
    let conn = get_read_conn()?;
    count_unread_notifications_for_user_with_conn(&conn, user_id)
}

pub fn count_unread_notifications_for_user_with_conn(
    conn: &Connection,
    user_id: i64,
) -> anyhow::Result<i64> {
    let unread: i64 = conn.query_row(
        UNREAD_NOTIFICATIONS_COUNT_FOR_USER_SQL,
        params![user_id],
        |r| r.get(0),
    )?;
    Ok(unread)
}

pub fn list_notifications_for_user(
    user_id: i64,
    limit: i64,
    offset: i64,
) -> anyhow::Result<(Vec<UserNotificationRow>, i64)> {
    let conn = get_read_conn()?;
    list_notifications_for_user_with_conn(&conn, user_id, limit, offset)
}

pub fn list_notifications_for_user_with_conn(
    conn: &Connection,
    user_id: i64,
    limit: i64,
    offset: i64,
) -> anyhow::Result<(Vec<UserNotificationRow>, i64)> {
    let unread = count_unread_notifications_for_user_with_conn(conn, user_id)?;
    let mut stmt = conn.prepare(LIST_NOTIFICATIONS_FOR_USER_SQL)?;
    let rows = stmt.query_map(params![user_id, limit.clamp(1, 200), offset.max(0)], |r| {
        Ok(UserNotificationRow {
            id: r.get(0)?,
            user_id: r.get(1)?,
            level: r.get(2)?,
            title: r.get(3)?,
            message: r.get(4)?,
            read: r.get(5)?,
            created_at: r.get(6)?,
        })
    })?;
    let mut list = Vec::new();
    for row in rows {
        list.push(row?);
    }
    Ok((list, unread))
}
