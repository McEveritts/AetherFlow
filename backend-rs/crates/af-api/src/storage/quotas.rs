use super::accounting;
use crate::auth::{api_error, AuthUser};
use axum::extract::{Path, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserQuotaRecord {
    pub user_id: i64,
    pub username: String,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub available_bytes: i64,
    pub usage_pct: f64,
    pub configured: bool,
    pub status: String,
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
    #[serde(rename = "usedGB")]
    pub used_gb: f64,
    #[serde(rename = "totalGB")]
    pub total_gb: f64,
    pub percentage: f64,
}

static HUMAN_SIZE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgtp]?b)\s*$").unwrap());

pub fn parse_human_size(input: &str) -> anyhow::Result<i64> {
    let caps = HUMAN_SIZE_RE
        .captures(input.trim())
        .ok_or_else(|| anyhow::anyhow!("invalid size {:?}", input))?;
    let val: f64 = caps[1].parse()?;
    let mult: f64 = match caps[2].to_uppercase().as_str() {
        "B" => 1.0,
        "KB" => 1024.0,
        "MB" => 1024.0 * 1024.0,
        "GB" => 1024.0 * 1024.0 * 1024.0,
        "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "PB" => 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        other => anyhow::bail!("unsupported size unit {}", other),
    };
    let scaled = val * mult;
    if !scaled.is_finite() || scaled < 0.0 || scaled >= i64::MAX as f64 {
        anyhow::bail!("size overflows supported quota range");
    }
    Ok(scaled as i64)
}

pub(super) fn normalize_quota_record(mut rec: UserQuotaRecord) -> UserQuotaRecord {
    rec.configured = rec.quota_bytes > 0;
    rec.available_bytes = if rec.quota_bytes > 0 {
        (rec.quota_bytes - rec.used_bytes).max(0)
    } else {
        0
    };
    rec.usage_pct = if rec.quota_bytes > 0 {
        (rec.used_bytes as f64 / rec.quota_bytes as f64) * 100.0
    } else {
        0.0
    };
    rec.used_gb = rec.used_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    rec.total_gb = rec.quota_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    rec.percentage = rec.usage_pct;
    rec.status = match rec.status.trim() {
        "" => "active".to_owned(),
        status => status.to_ascii_lowercase(),
    };
    if !matches!(rec.source.as_str(), "manual" | "runner") {
        rec.source = "manual".to_string();
    }
    rec
}

pub fn query_user_quota_record(user_id: i64) -> anyhow::Result<UserQuotaRecord> {
    let conn = af_db::get_conn()?;
    query_user_quota_record_conn(&conn, user_id)
}

pub(super) fn query_user_quota_record_conn(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> anyhow::Result<UserQuotaRecord> {
    let username: String = conn.query_row(
        "SELECT username FROM users WHERE id = ?1",
        params![user_id],
        |r| r.get(0),
    )?;

    let row = conn.query_row(
        "SELECT quota_bytes, used_bytes, COALESCE(status, 'active'), COALESCE(source, 'manual'), \
         COALESCE(updated_at, '') \
         FROM user_quotas WHERE user_id = ?1",
        params![user_id],
        |r| {
            Ok(UserQuotaRecord {
                user_id,
                username: username.clone(),
                quota_bytes: r.get(0)?,
                used_bytes: r.get(1)?,
                available_bytes: 0,
                usage_pct: 0.0,
                configured: false,
                status: r.get(2)?,
                source: r.get(3)?,
                updated_at: r.get(4)?,
                used_gb: 0.0,
                total_gb: 0.0,
                percentage: 0.0,
            })
        },
    );

    match row {
        Ok(rec) => Ok(normalize_quota_record(rec)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(normalize_quota_record(UserQuotaRecord {
            user_id,
            username,
            quota_bytes: 0,
            used_bytes: 0,
            available_bytes: 0,
            usage_pct: 0.0,
            configured: false,
            status: "active".to_string(),
            source: "manual".to_string(),
            updated_at: String::new(),
            used_gb: 0.0,
            total_gb: 0.0,
            percentage: 0.0,
        })),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn list_user_quota_records_conn(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<Vec<UserQuotaRecord>> {
    let mut stmt = conn.prepare(
        "SELECT u.id, u.username, COALESCE(q.quota_bytes, 0), COALESCE(q.used_bytes, 0), \
         COALESCE(q.status, 'active'), COALESCE(q.source, 'manual'), \
         COALESCE(q.updated_at, '') \
         FROM users u LEFT JOIN user_quotas q ON q.user_id = u.id ORDER BY u.username ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(normalize_quota_record(UserQuotaRecord {
            user_id: r.get(0)?,
            username: r.get(1)?,
            quota_bytes: r.get(2)?,
            used_bytes: r.get(3)?,
            available_bytes: 0,
            usage_pct: 0.0,
            configured: false,
            status: r.get(4)?,
            source: r.get(5)?,
            updated_at: r.get(6)?,
            used_gb: 0.0,
            total_gb: 0.0,
            percentage: 0.0,
        }))
    })?;
    rows.collect()
}

pub async fn get_own_quota(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Authentication required",
        );
    };
    let user_id = user.user_id;
    let result = tokio::task::spawn_blocking(move || query_user_quota_record(user_id)).await;
    match result {
        Ok(Ok(rec)) => Json(rec).into_response(),
        Ok(Err(error))
            if matches!(
                error.downcast_ref::<rusqlite::Error>(),
                Some(rusqlite::Error::QueryReturnedNoRows)
            ) =>
        {
            api_error(StatusCode::NOT_FOUND, "NOT_FOUND", error.to_string())
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, user_id, "Failed to query user quota");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to query user quota",
            )
        }
        Err(error) => {
            tracing::warn!(%error, user_id, "User quota worker failed");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to query user quota",
            )
        }
    }
}

pub async fn list_user_quotas() -> Response {
    let result = tokio::task::spawn_blocking(|| -> anyhow::Result<Vec<UserQuotaRecord>> {
        let conn = af_db::get_conn()?;
        Ok(list_user_quota_records_conn(&conn)?)
    })
    .await;
    match result {
        Ok(Ok(records)) => Json(serde_json::json!({ "quotas": records })).into_response(),
        Ok(Err(error)) => {
            tracing::warn!(%error, "Failed to query user quota records");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to query quota records",
            )
        }
        Err(error) => {
            tracing::warn!(%error, "Quota listing worker failed");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to query quota records",
            )
        }
    }
}

pub async fn update_user_quota(
    Path(user_id): Path<i64>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    let mut quota_bytes = if let Some(raw_bytes) = req.get("quota_bytes") {
        if let Some(val) = raw_bytes.as_i64() {
            val
        } else if raw_bytes.as_u64().is_some() {
            return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Quota is too large");
        } else {
            0
        }
    } else {
        0
    };
    if quota_bytes <= 0 {
        if let Some(q_str) = req.get("quota").and_then(|v| v.as_str()) {
            if !q_str.trim().is_empty() {
                match parse_human_size(q_str) {
                    Ok(parsed) => quota_bytes = parsed,
                    Err(e) => {
                        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", e.to_string())
                    }
                }
            }
        }
    }
    if quota_bytes <= 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "quota_bytes or quota is required",
        );
    }
    if let Err(err) = accounting::align_quota_bytes_to_kib(quota_bytes) {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", err.to_string());
    }

    accounting::quota_operation(user_id, Some(quota_bytes)).await
}

pub async fn refresh_user_quota(Path(user_id): Path<i64>) -> Response {
    accounting::quota_operation(user_id, None).await
}
