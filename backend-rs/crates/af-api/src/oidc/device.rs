use super::authorize::{record_consent_in_tx, validate_oidc_scopes};
use super::keys::{get_oidc_issuer_for_peer, oidc_server_error};
use super::token_endpoint::{
    authenticate_oidc_client, extract_oidc_client_credentials, invalid_oidc_client_response,
};
use crate::auth::{blocking_response, AuthUser, SubjectStatusError};
use axum::extract::{Form, Request};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use std::collections::HashMap;

fn generate_user_code() -> String {
    use rand::{distributions::Uniform, Rng};
    const CHARSET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ23456789";
    let dist = Uniform::new(0, CHARSET.len());
    let mut rng = rand::rngs::OsRng;
    let chars: Vec<char> = (0..8).map(|_| CHARSET[rng.sample(dist)] as char).collect();
    format!(
        "{}-{}",
        chars[..4].iter().collect::<String>(),
        chars[4..].iter().collect::<String>()
    )
}

pub(super) fn normalize_device_user_code(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("user_code is required");
    }
    if trimmed.len() > 16
        || trimmed.starts_with('-')
        || trimmed.ends_with('-')
        || trimmed.contains("--")
    {
        return Err("invalid_user_code");
    }
    let mut compact = String::with_capacity(8);
    for ch in trimmed.chars() {
        if ch == '-' || ch == ' ' {
            continue;
        }
        if !ch.is_ascii_alphanumeric() {
            return Err("invalid_user_code");
        }
        compact.push(ch.to_ascii_uppercase());
    }
    if compact.len() != 8 {
        return Err("invalid_user_code");
    }
    Ok(format!("{}-{}", &compact[..4], &compact[4..]))
}

pub async fn oidc_device_authorize(
    crate::ws::PeerIp(peer_ip): crate::ws::PeerIp,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    blocking_response(move || oidc_device_authorize_blocking(headers, peer_ip, form)).await
}

fn oidc_device_authorize_blocking(
    headers: HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
    form: HashMap<String, String>,
) -> Response {
    let (client_id, client_secret) = match extract_oidc_client_credentials(&headers, &form) {
        Ok(creds) => creds,
        Err(err) => return err.into_response(),
    };
    match authenticate_oidc_client(&client_id, &client_secret, false) {
        Ok(false) => {}
        Ok(true) => return invalid_oidc_client_response(),
        Err(err) => return err.into_response(),
    }
    let scope = validate_oidc_scopes(form.get("scope").map(String::as_str).unwrap_or(""));

    let Ok(conn) = af_db::get_conn() else {
        return oidc_server_error();
    };

    let mut dc_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut dc_bytes);
    let device_code = hex::encode(dc_bytes);
    let expires_at = (Utc::now() + Duration::minutes(10)).to_rfc3339();

    let mut inserted_code = None;
    for _ in 0..8 {
        let candidate = generate_user_code();
        match conn.execute(
            "INSERT INTO oidc_device_codes (device_code, user_code, client_id, scope, expires_at, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending')",
            params![device_code, candidate, client_id, scope, expires_at],
        ) {
            Ok(_) => {
                inserted_code = Some(candidate);
                break;
            }
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
    let Some(user_code) = inserted_code else {
        return oidc_server_error();
    };

    let issuer = get_oidc_issuer_for_peer(&headers, peer_ip);
    let verification_uri = format!("{}/oauth/device", issuer);

    Json(serde_json::json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": format!("{}?user_code={}", verification_uri, user_code),
        "expires_in": 600,
        "interval": 5,
    }))
    .into_response()
}

pub async fn oidc_device_verify(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized" })),
        )
            .into_response();
    };
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 32 * 1024).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid body" })),
        )
            .into_response();
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid JSON" })),
        )
            .into_response();
    };
    blocking_response(move || oidc_device_verify_blocking(user, body)).await
}

fn oidc_device_verify_blocking(user: AuthUser, req: serde_json::Value) -> Response {
    let raw_code = req.get("user_code").and_then(|v| v.as_str()).unwrap_or("");
    let user_code = match normalize_device_user_code(raw_code) {
        Ok(code) => code,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": err })),
            )
                .into_response();
        }
    };

    let Ok(conn) = af_db::get_read_conn() else {
        return oidc_server_error();
    };

    match crate::auth::load_active_human_subject(&conn, user.user_id) {
        Ok(_) => {}
        Err(SubjectStatusError::DbError) => return oidc_server_error(),
        Err(SubjectStatusError::MissingOrPlugin | SubjectStatusError::Suspended) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": "access_denied" })),
            )
                .into_response();
        }
    }

    let (status, scope, client_id, expires_at) = match conn
        .query_row(
            "SELECT status, scope, client_id, expires_at FROM oidc_device_codes WHERE user_code = ?1",
            params![user_code],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_user_code" })),
            )
                .into_response();
        }
        Err(_) => return oidc_server_error(),
    };

    let expired = DateTime::parse_from_rfc3339(&expires_at)
        .map(|dt| Utc::now() > dt.with_timezone(&Utc))
        .unwrap_or(true);
    if expired {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "expired_token" })),
        )
            .into_response();
    }
    if status != "pending" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_user_code" })),
        )
            .into_response();
    }

    let (client_name, secret_hash) = match conn
        .query_row(
            "SELECT name, COALESCE(client_secret_hash, '') FROM oidc_clients WHERE id = ?1",
            params![client_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_client" })),
            )
                .into_response();
        }
        Err(_) => return oidc_server_error(),
    };
    if secret_hash.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_client" })),
        )
            .into_response();
    }

    let validated_scope = validate_oidc_scopes(&scope);

    Json(serde_json::json!({
        "status": status,
        "user_code": user_code,
        "scope": validated_scope,
        "client_id": client_id,
        "client_name": client_name,
        "expires_at": expires_at,
    }))
    .into_response()
}

pub async fn oidc_device_consent(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized" })),
        )
            .into_response();
    };
    let peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::ConnectInfo(addr)| addr.ip());
    let ip = crate::ws::extract_client_ip_for_peer(req.headers(), peer_ip);
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 32 * 1024).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid body" })),
        )
            .into_response();
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid JSON" })),
        )
            .into_response();
    };
    blocking_response(move || oidc_device_consent_blocking(user, body, ip, ua)).await
}

fn oidc_device_consent_blocking(
    user: AuthUser,
    body: serde_json::Value,
    ip: String,
    ua: String,
) -> Response {
    let raw_code = body.get("user_code").and_then(|v| v.as_str()).unwrap_or("");
    let user_code = match normalize_device_user_code(raw_code) {
        Ok(code) => code,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": err })),
            )
                .into_response();
        }
    };
    let Some(approved) = body.get("approved").and_then(|v| v.as_bool()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "approved boolean is required" })),
        )
            .into_response();
    };

    let status = if approved { "approved" } else { "denied" };
    let Ok(mut conn) = af_db::get_conn() else {
        return oidc_server_error();
    };
    let Ok(tx) = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) else {
        return oidc_server_error();
    };
    match crate::auth::load_active_human_subject(&tx, user.user_id) {
        Ok(_) => {}
        Err(SubjectStatusError::DbError) => return oidc_server_error(),
        Err(SubjectStatusError::MissingOrPlugin | SubjectStatusError::Suspended) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": "access_denied" })),
            )
                .into_response();
        }
    }

    let (device_code, client_id, scope, stored_status, expires_at) = match tx
        .query_row(
            "SELECT device_code, client_id, scope, status, expires_at FROM oidc_device_codes WHERE user_code = ?1",
            params![user_code],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_user_code" })),
            )
                .into_response();
        }
        Err(_) => return oidc_server_error(),
    };

    let expired = DateTime::parse_from_rfc3339(&expires_at)
        .map(|dt| Utc::now() > dt.with_timezone(&Utc))
        .unwrap_or(true);
    if expired {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "expired_token" })),
        )
            .into_response();
    }
    if stored_status != "pending" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_user_code" })),
        )
            .into_response();
    }

    let (client_name, secret_hash) = match tx
        .query_row(
            "SELECT name, COALESCE(client_secret_hash, '') FROM oidc_clients WHERE id = ?1",
            params![client_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_client" })),
            )
                .into_response();
        }
        Err(_) => return oidc_server_error(),
    };
    if secret_hash.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_client" })),
        )
            .into_response();
    }

    let validated_scope = validate_oidc_scopes(&scope);
    if let Some(expected_client) = body
        .get("client_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if expected_client != client_id {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_request" })),
            )
                .into_response();
        }
    }
    if let Some(expected_scope) = body
        .get("scope")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if validate_oidc_scopes(expected_scope) != validated_scope {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_request" })),
            )
                .into_response();
        }
    }

    let now_rfc3339 = Utc::now().to_rfc3339();
    let affected = match tx.execute(
        "UPDATE oidc_device_codes SET status = ?1, user_id = ?2, scope = ?3 WHERE device_code = ?4 AND status = 'pending' AND expires_at > ?5",
        params![status, user.user_id, &validated_scope, &device_code, &now_rfc3339],
    ) {
        Ok(n) => n,
        Err(_) => return oidc_server_error(),
    };
    if affected != 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_user_code" })),
        )
            .into_response();
    }
    if approved && record_consent_in_tx(&tx, user.user_id, &client_id, &validated_scope).is_err() {
        return oidc_server_error();
    }
    if tx.commit().is_err() {
        return oidc_server_error();
    }

    af_db::record_audit(
        user.user_id,
        &user.username,
        if approved {
            "oidc_device_approve"
        } else {
            "oidc_device_deny"
        },
        "oidc_client",
        &client_id,
        &validated_scope,
        &ip,
        &ua,
    );

    Json(serde_json::json!({
        "status": status,
        "client_id": client_id,
        "client_name": client_name,
        "scope": validated_scope,
    }))
    .into_response()
}
