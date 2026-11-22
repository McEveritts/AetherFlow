use crate::auth::{api_error, AuthUser};
use crate::ws::{
    extract_client_ip, extract_client_ip_for_peer, issue_ws_ticket_for_session, PeerIp,
};
use af_models::User;
use axum::extract::{Extension, Path};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use rusqlite::params;
use serde::Deserialize;

pub(super) async fn issue_ws_ticket(
    Extension(auth_user): Extension<AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
) -> Response {
    if auth_user.plugin_id.is_some()
        || !auth_user.plugin_scopes.is_empty()
        || auth_user.role == "plugin"
    {
        return api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_WEBSOCKET_FORBIDDEN",
            "Scoped plugins cannot create operator WebSocket sessions; use scoped telemetry reads",
        );
    }
    let ip = extract_client_ip_for_peer(&headers, peer_ip);
    let ticket = issue_ws_ticket_for_session(auth_user.user_id, &auth_user.jti, &ip);
    Json(serde_json::json!({ "ticket": ticket })).into_response()
}

#[derive(Deserialize)]
pub(super) struct UpdateProfileReq {
    email: String,
}

pub(super) async fn update_profile(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<UpdateProfileReq>,
) -> Response {
    let trimmed = req.email.trim().to_string();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid email address",
        );
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || trimmed
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Invalid email address",
        );
    }

    let user_id = auth_user.user_id;
    crate::auth::blocking_response(move || {
        let Ok(mut conn) = af_db::get_conn() else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            );
        };
        let Ok(tx) = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        else {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            );
        };
        let conflict: i64 = match tx.query_row(
            "SELECT COUNT(*) FROM users WHERE email = ?1 COLLATE NOCASE AND id != ?2",
            params![trimmed, user_id],
            |r| r.get(0),
        ) {
            Ok(c) => c,
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to update profile",
                );
            }
        };
        if conflict > 0 {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Email address is already in use",
            );
        }
        if tx
            .execute(
                "UPDATE users SET email = ?1 WHERE id = ?2",
                params![trimmed, user_id],
            )
            .is_err()
            || tx.commit().is_err()
        {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to update profile",
            );
        }
        Json(serde_json::json!({ "message": "Profile updated successfully" })).into_response()
    })
    .await
}

#[derive(Deserialize)]
pub(super) struct ChangePasswordReq {
    pub(super) current_password: String,
    pub(super) new_password: String,
}

pub(super) async fn update_password(
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordReq>,
) -> Response {
    if req.current_password.len() > 72 || req.new_password.len() > 72 {
        return crate::auth::password_too_long();
    }
    crate::auth::blocking_response(move || update_password_blocking(auth_user, headers, req)).await
}

pub(super) fn update_password_blocking(
    auth_user: AuthUser,
    headers: HeaderMap,
    req: ChangePasswordReq,
) -> Response {
    if req.new_password.len() < 8 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "New password must be at least 8 characters",
        );
    }
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };
    let pre_revoked_after =
        if crate::auth::column_exists(&conn, "users", "sessions_revoked_after").unwrap_or(false) {
            conn.query_row(
                "SELECT COALESCE(sessions_revoked_after, 0) FROM users WHERE id = ?1",
                params![auth_user.user_id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
        } else {
            0
        };
    let existing_hash = match conn.query_row(
        "SELECT COALESCE(password_hash, '') FROM users WHERE id = ?1",
        params![auth_user.user_id],
        |r| r.get::<_, String>(0),
    ) {
        Ok(hash) => hash,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "User not found");
        }
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            );
        }
    };
    drop(conn);

    if !crate::auth::verify_password(&req.current_password, &existing_hash) {
        return api_error(
            StatusCode::FORBIDDEN,
            "INVALID_CURRENT_PASSWORD",
            "Current password is incorrect",
        );
    }
    let Ok(new_hash) = bcrypt::hash(&req.new_password, bcrypt::DEFAULT_COST) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to hash password",
        );
    };
    let tx_outcome = (|| -> anyhow::Result<Option<(String, Vec<String>)>> {
        let mut conn = af_db::get_conn()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = if crate::auth::column_exists(&tx, "users", "sessions_revoked_after")
            .unwrap_or(false)
        {
            tx.execute(
                "UPDATE users SET password_hash = ?1 \
                 WHERE id = ?2 AND COALESCE(password_hash, '') = ?3 \
                   AND COALESCE(sessions_revoked_after, 0) <= ?4",
                params![
                    new_hash,
                    auth_user.user_id,
                    existing_hash,
                    pre_revoked_after
                ],
            )?
        } else {
            tx.execute(
                "UPDATE users SET password_hash = ?1 \
                 WHERE id = ?2 AND COALESCE(password_hash, '') = ?3",
                params![new_hash, auth_user.user_id, existing_hash],
            )?
        };
        if changed == 0 {
            return Ok(None);
        }
        let (new_ver, revoked_jtis) =
            crate::auth::revoke_all_user_credentials_in_tx(&tx, auth_user.user_id)?;
        let (new_token, _) = crate::auth::create_session_jwt_in_conn(
            &tx,
            auth_user.user_id,
            &headers,
            Utc::now().timestamp(),
            None,
            new_ver,
        )?;
        tx.commit()?;
        Ok(Some((new_token, revoked_jtis)))
    })();

    let (new_token, revoked_jtis) = match tx_outcome {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "SESSION_EXPIRED",
                "Credentials changed concurrently; please re-authenticate",
            );
        }
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to update password",
            );
        }
    };
    crate::auth::finalize_user_credential_revocation(auth_user.user_id, &revoked_jtis);

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        "password_update",
        "user",
        &auth_user.user_id.to_string(),
        "Password updated successfully",
        &ip,
        ua,
    );

    let mut resp = Json(serde_json::json!({
        "status": "success",
        "message": "Password updated successfully",
    }))
    .into_response();
    crate::auth::set_session_cookie(&mut resp, &new_token);
    resp
}

#[derive(Deserialize)]
pub(super) struct AvatarReq {
    #[serde(default)]
    avatar: String,
    #[serde(default)]
    avatar_url: String,
}

pub(super) fn validate_avatar_uri(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Avatar image or URL is required");
    }
    if trimmed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("Avatar URI must not contain control characters");
    }
    if trimmed.starts_with('/') {
        if trimmed.starts_with("//") || trimmed.starts_with("/\\") || trimmed.contains("..") {
            return Err("Disallowed avatar URI path");
        }
        return Ok(trimmed.to_string());
    }
    let lower = trimmed.to_ascii_lowercase();
    const ALLOWED_RASTER_PREFIXES: &[&str] = &[
        "data:image/png;base64,",
        "data:image/jpeg;base64,",
        "data:image/jpg;base64,",
        "data:image/webp;base64,",
        "data:image/gif;base64,",
    ];
    if let Some(prefix) = ALLOWED_RASTER_PREFIXES
        .iter()
        .find(|p| lower.starts_with(**p))
    {
        let b64_payload = &trimmed[prefix.len()..];
        if b64_payload.is_empty()
            || !b64_payload
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return Err("Invalid base64 raster avatar payload");
        }
        use base64::Engine as _;
        if base64::engine::general_purpose::STANDARD
            .decode(b64_payload)
            .is_err()
        {
            return Err("Malformed base64 raster avatar payload");
        }
        return Ok(trimmed.to_string());
    }
    if lower.starts_with("https://") {
        let Ok(parsed) = reqwest::Url::parse(trimmed) else {
            return Err("Invalid avatar HTTPS URL");
        };
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err("Invalid avatar HTTPS URL");
        }
        return Ok(trimmed.to_string());
    }
    Err("Disallowed avatar URI scheme; use https://, a root-relative path, or a base64 PNG/JPEG/WEBP/GIF data URI")
}

pub(super) async fn update_avatar(
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<AvatarReq>,
) -> Response {
    let val = if !req.avatar.trim().is_empty() {
        req.avatar
    } else {
        req.avatar_url
    };
    if val.len() > 2 * 1024 * 1024 {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PAYLOAD_TOO_LARGE",
            "Avatar payload exceeds maximum 2MB size limit",
        );
    }
    let validated = match validate_avatar_uri(&val) {
        Ok(uri) => uri,
        Err(msg) => {
            return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", msg);
        }
    };
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to update avatar",
        );
    };
    if conn
        .execute(
            "UPDATE users SET avatar_url = ?1 WHERE id = ?2",
            params![validated, auth_user.user_id],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to update avatar",
        );
    }
    Json(serde_json::json!({
        "status": "success",
        "message": "Avatar updated successfully",
        "avatar_url": validated,
    }))
    .into_response()
}

pub(super) async fn delete_avatar(Extension(auth_user): Extension<AuthUser>) -> Response {
    let updated = af_db::get_conn().and_then(|conn| {
        Ok(conn.execute(
            "UPDATE users SET avatar_url = '' WHERE id = ?1",
            params![auth_user.user_id],
        )?)
    });
    match updated {
        Ok(0) => return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "User not found"),
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(%error, "Failed to remove avatar");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "DATABASE_UNAVAILABLE",
                "Failed to remove avatar",
            );
        }
    }
    Json(serde_json::json!({
        "status": "success",
        "message": "Avatar removed successfully",
    }))
    .into_response()
}

pub(super) async fn get_users(Extension(user): Extension<AuthUser>) -> Response {
    if let Err(response) = crate::auth::require_admin(&user) {
        return *response;
    }
    match read_users() {
        Ok(users) => Json(users).into_response(),
        Err(error) => {
            tracing::warn!(%error, "Failed to list users");
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "DATABASE_UNAVAILABLE",
                "Failed to list users",
            )
        }
    }
}

pub(super) fn read_users() -> anyhow::Result<Vec<User>> {
    let conn = af_db::get_read_conn()?;
    let mut stmt = conn.prepare(
        "SELECT id, username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user'), \
         COALESCE(google_id, ''), COALESCE(totp_enabled, 0) FROM users",
    )?;
    let rows = stmt.query_map([], |row| {
        let google_id: String = row.get(5)?;
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            email: row.get(2)?,
            avatar_url: row.get(3)?,
            role: row.get(4)?,
            is_oauth: !google_id.is_empty(),
            google_id,
            totp_enabled: row.get(6)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

#[derive(Deserialize)]
pub(super) struct RoleReq {
    role: String,
}

pub(super) async fn update_user_role(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
    Json(req): Json<RoleReq>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
    if req.role != "admin" && req.role != "user" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid role specified. Must be 'admin' or 'user'.",
        );
    }
    if let Err(error) =
        crate::mcbrowser::lifecycle::update_account_role(auth_user.clone(), id, req.role.clone())
            .await
    {
        return error.into_response();
    }
    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        "user_role_change",
        "user",
        &id.to_string(),
        &format!("role={}", req.role),
        &ip,
        ua,
    );
    Json(serde_json::json!({ "message": "Role updated successfully" })).into_response()
}

pub(super) async fn delete_user(
    Path(id): Path<i64>,
    Extension(auth_user): Extension<AuthUser>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&auth_user) {
        return *response;
    }
    let pending_cleanup_count =
        match crate::mcbrowser::lifecycle::delete_account(auth_user.clone(), id).await {
            Ok(count) => count,
            Err(error) => return error.into_response(),
        };
    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        auth_user.user_id,
        &auth_user.username,
        "user_delete",
        "user",
        &id.to_string(),
        &format!("pending_cleanup_count={pending_cleanup_count}"),
        &ip,
        ua,
    );
    let (status, message) = if pending_cleanup_count == 0 {
        (StatusCode::OK, "User deleted successfully")
    } else {
        (
            StatusCode::ACCEPTED,
            "User deleted. Storage cleanup is pending.",
        )
    };
    (
        status,
        Json(serde_json::json!({
            "message": message,
            "cleanup_pending": pending_cleanup_count != 0,
            "pending_cleanup_count": pending_cleanup_count,
        })),
    )
        .into_response()
}
