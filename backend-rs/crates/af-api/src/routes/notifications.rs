use crate::auth::{api_error, AuthUser};
use axum::extract::{Extension, Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use rusqlite::params;
use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct PageQuery {
    #[serde(default = "default_limit")]
    pub(super) limit: i64,
    #[serde(default)]
    pub(super) offset: i64,
    #[serde(default)]
    pub(super) action: String,
    #[serde(default)]
    pub(super) username: String,
}

fn default_limit() -> i64 {
    50
}

pub(super) async fn get_notifications(
    Extension(auth_user): Extension<AuthUser>,
    Query(q): Query<PageQuery>,
) -> Response {
    let user_id = auth_user.user_id;
    let limit = q.limit.clamp(1, 200);
    let offset = q.offset.max(0);
    let res = tokio::task::spawn_blocking(
        move || -> anyhow::Result<(Vec<af_services::Notification>, i64)> {
            let conn = af_db::get_read_conn()?;
            let unread = af_db::count_unread_notifications_for_user_with_conn(&conn, user_id)?;
            let mut stmt = conn.prepare(
                "SELECT n.id, n.user_id, n.level, n.title, n.message, n.read, COALESCE(CAST(n.created_at AS TEXT), '') \
                 FROM notifications n \
                 LEFT JOIN notification_reads nr ON nr.notification_id = n.id AND nr.user_id = ?1 \
                 WHERE (n.user_id = ?1 OR (n.user_id IS NULL AND nr.notification_id IS NULL)) \
                 ORDER BY n.created_at DESC LIMIT ?2 OFFSET ?3",
            )?;
            let rows = stmt.query_map(params![user_id, limit, offset], |r| {
                Ok(af_services::Notification {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    level: r.get(2)?,
                    title: r.get(3)?,
                    message: r.get(4)?,
                    read: r.get(5)?,
                    created_at: r.get(6)?,
                })
            })?;
            let list = rows.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((list, unread))
        },
    )
    .await;

    match res {
        Ok(Ok((notifications, unread_count))) => Json(serde_json::json!({
            "notifications": notifications,
            "unread_count": unread_count,
        }))
        .into_response(),
        Ok(Err(error)) => {
            tracing::warn!(%error, "Failed to load notifications");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Could not load notifications",
            )
        }
        Err(error) => {
            tracing::warn!(%error, "Notifications worker task failed");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Could not load notifications",
            )
        }
    }
}

pub(super) async fn mark_notification_read(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
) -> Response {
    let user_id = auth_user.user_id;
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        let conn = af_db::get_conn()?;
        af_db::mark_notification_read_for_user_with_conn(&conn, user_id, id)
    })
    .await;

    match res {
        Ok(Ok(true)) => {
            Json(serde_json::json!({ "message": "Notification marked as read" })).into_response()
        }
        Ok(Ok(false)) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Notification not found"),
        _ => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        ),
    }
}

pub(super) async fn dismiss_all_notifications(Extension(auth_user): Extension<AuthUser>) -> Response {
    let user_id = auth_user.user_id;
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut conn = af_db::get_conn()?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE notifications SET read = 1 WHERE user_id = ?1 AND read = 0",
            params![user_id],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO notification_reads (notification_id, user_id) \
             SELECT id, ?1 FROM notifications WHERE user_id IS NULL",
            params![user_id],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await;

    match res {
        Ok(Ok(())) => {
            Json(serde_json::json!({ "message": "All notifications dismissed" })).into_response()
        }
        _ => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to dismiss notifications",
        ),
    }
}

pub(super) async fn get_notification_rules() -> Response {
    crate::auth::blocking_response(|| {
        let result = (|| -> anyhow::Result<Vec<serde_json::Value>> {
            let conn = af_db::get_read_conn()?;
            let mut stmt = conn.prepare(
                "SELECT id, name, condition_type, condition_value, COALESCE(level, 'warning'), COALESCE(enabled, 1), COALESCE(CAST(created_at AS TEXT), '') \
                 FROM notification_rules ORDER BY created_at DESC",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "condition_type": r.get::<_, String>(2)?,
                    "condition_value": r.get::<_, String>(3)?,
                    "level": r.get::<_, String>(4)?,
                    "enabled": r.get::<_, i32>(5)? != 0,
                    "created_at": r.get::<_, String>(6)?,
                }))
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })();
        match result {
            Ok(rules) => Json(serde_json::json!({ "rules": rules })).into_response(),
            Err(error) => {
                tracing::warn!(%error, "Failed to load notification rules");
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DATABASE_ERROR",
                    "Could not load notification rules",
                )
            }
        }
    })
    .await
}

pub(super) async fn get_notification_channels() -> Response {
    crate::auth::blocking_response(|| {
        let result = (|| -> anyhow::Result<Vec<serde_json::Value>> {
            let conn = af_db::get_read_conn()?;
            let mut stmt = conn.prepare(
                "SELECT id, name, type, COALESCE(config, '{}'), COALESCE(enabled, 1), COALESCE(CAST(created_at AS TEXT), '') \
                 FROM notification_channels ORDER BY created_at DESC",
            )?;
            let raw_channels: Vec<(i64, String, String, String, bool, String)> = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, i32>(4)? != 0,
                        r.get::<_, String>(5)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;

            let mut channels = Vec::with_capacity(raw_channels.len());
            for (id, name, channel_type, raw_cfg, enabled, created_at) in raw_channels {
                let cfg_val = af_db::mask_notification_channel_config_str(&channel_type, &raw_cfg);
                let (pending_deliveries, last_delivery) =
                    crate::notifications_ext::channel_delivery_overview_in_conn(&conn, id);
                channels.push(serde_json::json!({
                    "id": id,
                    "name": name,
                    "type": channel_type,
                    "config": cfg_val,
                    "enabled": enabled,
                    "created_at": created_at,
                    "pending_deliveries": pending_deliveries,
                    "last_delivery": last_delivery,
                }));
            }
            Ok(channels)
        })();
        match result {
            Ok(channels) => Json(serde_json::json!({ "channels": channels })).into_response(),
            Err(error) => {
                tracing::warn!(%error, "Failed to load notification channels");
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DATABASE_ERROR",
                    "Could not load notification channels",
                )
            }
        }
    })
    .await
}

pub(super) async fn get_audit_log(Query(q): Query<PageQuery>) -> Response {
    crate::auth::blocking_response(move || {
        match af_db::list_audit_entries(q.limit, q.offset, &q.action, &q.username) {
            Ok((entries, total)) => Json(serde_json::json!({
                "entries": entries,
                "total": total,
                "limit": q.limit,
                "offset": q.offset,
            }))
            .into_response(),
            Err(error) => {
                tracing::warn!(%error, "Failed to load audit log");
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DATABASE_ERROR",
                    "Could not load audit log",
                )
            }
        }
    })
    .await
}
