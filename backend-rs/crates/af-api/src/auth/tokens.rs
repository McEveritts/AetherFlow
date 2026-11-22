use crate::ws::{build_set_cookie, extract_client_ip, extract_cookie};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use uuid::Uuid;

pub(super) const SESSION_COOKIE_MAX_AGE: i64 = 86400;
pub(super) const SESSION_ABSOLUTE_LIFETIME: i64 = 30 * 86400;

static AUTH_BLOCKING_LIMIT: Lazy<tokio::sync::Semaphore> =
    Lazy::new(|| tokio::sync::Semaphore::new(16));

// ─────────────────────────────────────────────────────────────────────────────
// Standard Error Helpers & Core Auth Types
// ─────────────────────────────────────────────────────────────────────────────

pub fn api_error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({
            "code": code,
            "message": message.into(),
        })),
    )
        .into_response()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    #[serde(default)]
    pub user_id: i64,
    pub sub: String,
    pub iss: String,
    pub iat: i64,
    #[serde(default)]
    pub auth_time: i64,
    pub exp: i64,
    pub jti: String,
    #[serde(default)]
    pub cfp: String,
    #[serde(default)]
    pub ver: i64,
    #[serde(default)]
    pub plugin_id: String,
    #[serde(default, alias = "scopes")]
    pub plugin_scopes: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub jti: String,
    pub plugin_id: Option<String>,
    pub plugin_scopes: Vec<String>,
}

/// Cryptographically verified initial authentication timestamp (`auth_time` fallback `iat`)
/// extracted from the validated session JWT in `auth_middleware`.
#[derive(Clone, Copy, Debug)]
pub struct SessionAuthTime(pub i64);

#[derive(Clone, Debug)]
pub(crate) struct ActiveSubject {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub sessions_revoked_after: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubjectStatusError {
    MissingOrPlugin,
    Suspended,
    DbError,
}

// ─────────────────────────────────────────────────────────────────────────────
// Schema Introspection & Active Subject Lookups
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) fn table_exists(conn: &rusqlite::Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        params![table],
        |row| row.get(0),
    )
}

pub(crate) fn column_exists(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
) -> rusqlite::Result<bool> {
    conn.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1)"),
        params![column],
        |row| row.get(0),
    )
}

pub(crate) fn load_active_human_subject(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> Result<ActiveSubject, SubjectStatusError> {
    if user_id <= 0 {
        return Err(SubjectStatusError::MissingOrPlugin);
    }
    let has_ver = column_exists(conn, "users", "sessions_revoked_after")
        .map_err(|_| SubjectStatusError::DbError)?;
    let has_role = column_exists(conn, "users", "role").map_err(|_| SubjectStatusError::DbError)?;
    let sql = match (has_role, has_ver) {
        (true, true) => {
            "SELECT id, COALESCE(username, ''), COALESCE(role, 'user'), COALESCE(sessions_revoked_after, 0) FROM users WHERE id = ?1"
        }
        (true, false) => {
            "SELECT id, COALESCE(username, ''), COALESCE(role, 'user'), 0 FROM users WHERE id = ?1"
        }
        (false, true) => {
            "SELECT id, COALESCE(username, ''), 'user', COALESCE(sessions_revoked_after, 0) FROM users WHERE id = ?1"
        }
        (false, false) => {
            "SELECT id, COALESCE(username, ''), 'user', 0 FROM users WHERE id = ?1"
        }
    };
    let row =
        if column_exists(conn, "users", "username").map_err(|_| SubjectStatusError::DbError)? {
            conn.query_row(sql, params![user_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .optional()
            .map_err(|_| SubjectStatusError::DbError)?
        } else {
            let role_sql = if has_role {
                "SELECT id, COALESCE(role, 'user') FROM users WHERE id = ?1"
            } else {
                "SELECT id, 'user' FROM users WHERE id = ?1"
            };
            conn.query_row(role_sql, params![user_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    String::new(),
                    r.get::<_, String>(1)?,
                    0i64,
                ))
            })
            .optional()
            .map_err(|_| SubjectStatusError::DbError)?
        };

    let Some((id, username, role, sessions_revoked_after)) = row else {
        return Err(SubjectStatusError::MissingOrPlugin);
    };
    if username.trim().to_ascii_lowercase().starts_with("plugin:") {
        return Err(SubjectStatusError::MissingOrPlugin);
    }

    if table_exists(conn, "user_quotas").map_err(|_| SubjectStatusError::DbError)? {
        let status: Option<String> = conn
            .query_row(
                "SELECT COALESCE(status, '') FROM user_quotas WHERE user_id = ?1",
                params![user_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| SubjectStatusError::DbError)?;
        if let Some(raw_status) = status {
            let trimmed = raw_status.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("active") {
                return Err(SubjectStatusError::Suspended);
            }
        }
    }

    Ok(ActiveSubject {
        user_id: id,
        username,
        role,
        sessions_revoked_after,
    })
}

pub(crate) fn query_user_credential_version(
    conn: &rusqlite::Connection,
    user_id: i64,
) -> rusqlite::Result<i64> {
    if column_exists(conn, "users", "sessions_revoked_after")? {
        Ok(conn
            .query_row(
                "SELECT COALESCE(sessions_revoked_after, 0) FROM users WHERE id = ?1",
                params![user_id],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    } else {
        Ok(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bounded Blocking Execution Pool
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) async fn blocking_auth_work<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, tokio::task::JoinError> {
    let permit = AUTH_BLOCKING_LIMIT
        .acquire()
        .await
        .expect("Auth semaphore is never closed");
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
}

pub(crate) async fn blocking_response(f: impl FnOnce() -> Response + Send + 'static) -> Response {
    blocking_auth_work(f).await.unwrap_or_else(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Authentication operation failed",
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Cookies, JWT Signing, Verification & Client Fingerprints
// ─────────────────────────────────────────────────────────────────────────────

pub(super) fn attach_logout_clear_cookie(mut resp: Response) -> Response {
    let clear_cookie = build_set_cookie(
        "aetherflow_session",
        "",
        -1,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    if let Ok(hv) = HeaderValue::from_str(&clear_cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

pub(crate) fn set_session_cookie(response: &mut Response, token: &str) {
    let cookie = build_set_cookie(
        "aetherflow_session",
        token,
        SESSION_COOKIE_MAX_AGE,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

pub(super) fn session_auth_time(claims: &SessionClaims) -> i64 {
    if claims.auth_time > 0 {
        claims.auth_time
    } else {
        claims.iat
    }
}

pub(super) fn session_within_absolute_lifetime(claims: &SessionClaims, now: i64) -> bool {
    let authenticated = session_auth_time(claims);
    authenticated > 0
        && authenticated <= now + 60
        && now < authenticated.saturating_add(SESSION_ABSOLUTE_LIFETIME)
}

pub fn secure_cookie_enabled() -> bool {
    env::var("COOKIE_SECURE")
        .map(|v| v.to_lowercase() != "false")
        .unwrap_or(true)
}

pub fn validate_startup_jwt_secret() -> anyhow::Result<()> {
    let secret = env::var("JWT_SECRET").unwrap_or_default();
    if secret.trim().is_empty() {
        anyhow::bail!(
            "FATAL: JWT_SECRET environment variable is not set. Refusing to start without a persistent signing key."
        );
    }
    if secret.len() < 32 {
        anyhow::bail!(
            "FATAL: JWT_SECRET must be at least 32 bytes long (got {} bytes).",
            secret.len()
        );
    }
    Ok(())
}

pub fn jwt_secret_bytes() -> Vec<u8> {
    let secret = env::var("JWT_SECRET").unwrap_or_default();
    if !secret.is_empty() {
        return secret.into_bytes();
    }
    static EPHEMERAL_JWT_SECRET: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    EPHEMERAL_JWT_SECRET
        .get_or_init(|| {
            let mut bytes = vec![0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            tracing::error!(
                "JWT_SECRET is unset; refusing the published dev fallback and using an ephemeral process secret"
            );
            bytes
        })
        .clone()
}

pub fn client_fingerprint(user_agent: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(user_agent.trim().as_bytes());
    hex::encode(hasher.finalize())
}

pub fn legacy_client_fingerprint(client_ip: &str, user_agent: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}|{}", client_ip, user_agent).as_bytes());
    hex::encode(hasher.finalize())
}

pub fn matches_client_fingerprint(claim_cfp: &str, client_ip: &str, user_agent: &str) -> bool {
    if claim_cfp.is_empty() {
        return true;
    }
    claim_cfp == client_fingerprint(user_agent)
        || claim_cfp == legacy_client_fingerprint(client_ip, user_agent)
}

pub fn create_standard_jwt(
    user_id: i64,
    headers: &HeaderMap,
) -> anyhow::Result<(String, SessionClaims)> {
    create_session_jwt(user_id, headers, Utc::now().timestamp())
}

pub(crate) fn create_session_jwt_in_conn(
    conn: &rusqlite::Connection,
    user_id: i64,
    headers: &HeaderMap,
    auth_time: i64,
    family_id: Option<&str>,
    credential_ver: i64,
) -> anyhow::Result<(String, SessionClaims)> {
    let now = Utc::now().timestamp();
    let absolute_exp = auth_time.saturating_add(SESSION_ABSOLUTE_LIFETIME);
    anyhow::ensure!(now < absolute_exp, "Absolute session lifetime exceeded");
    let exp = (now + 900).min(absolute_exp);
    let jti = Uuid::new_v4().to_string();
    let effective_family = family_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&jti)
        .to_string();
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ip = extract_client_ip(headers);
    let cfp = client_fingerprint(ua);

    let claims = SessionClaims {
        user_id,
        sub: user_id.to_string(),
        iss: "aetherflow".to_string(),
        iat: now,
        auth_time,
        exp,
        jti: jti.clone(),
        cfp,
        ver: credential_ver,
        plugin_id: String::new(),
        plugin_scopes: Vec::new(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&jwt_secret_bytes()),
    )?;

    af_db::prune_expired_active_sessions(conn, Utc::now().timestamp())?;
    // Track the full refresh window; otherwise a still-refreshable session disappears from revocation UI.
    let exp_rfc3339 = chrono::DateTime::from_timestamp((exp + 7200).min(absolute_exp), 0)
        .ok_or_else(|| anyhow::anyhow!("Invalid session expiry"))?
        .to_rfc3339();
    if column_exists(conn, "active_sessions", "family_id")? {
        conn.execute(
            "INSERT OR REPLACE INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, last_active, family_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP, ?6)",
            params![jti, user_id, ip, ua, exp_rfc3339, effective_family],
        )?;
    } else {
        conn.execute(
            "INSERT OR REPLACE INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, last_active) \
             VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)",
            params![jti, user_id, ip, ua, exp_rfc3339],
        )?;
    }

    Ok((token, claims))
}

pub(super) fn create_session_jwt(
    user_id: i64,
    headers: &HeaderMap,
    auth_time: i64,
) -> anyhow::Result<(String, SessionClaims)> {
    let conn = af_db::get_conn()?;
    let ver = query_user_credential_version(&conn, user_id)?;
    create_session_jwt_in_conn(&conn, user_id, headers, auth_time, None, ver)
}

#[cfg(test)]
pub(crate) fn mint_plugin_jwt(
    issuer_user_id: i64,
    plugin_id: &str,
    scopes: &[String],
    ttl_secs: i64,
) -> anyhow::Result<(String, SessionClaims)> {
    let now = Utc::now().timestamp();
    let exp = now + ttl_secs.clamp(60, 86400);
    let jti = Uuid::new_v4().to_string();
    let claims = SessionClaims {
        user_id: issuer_user_id,
        sub: format!("plugin:{}", plugin_id),
        iss: "aetherflow-plugin".to_string(),
        iat: now,
        auth_time: now,
        exp,
        jti,
        cfp: String::new(),
        ver: 0,
        plugin_id: plugin_id.to_string(),
        plugin_scopes: scopes.to_vec(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&jwt_secret_bytes()),
    )?;

    Ok((token, claims))
}

pub fn resolve_raw_token(headers: &HeaderMap) -> Option<String> {
    if let Some(raw_auth) = headers.get(header::AUTHORIZATION) {
        let auth_hdr = raw_auth.to_str().ok()?;
        let bearer = auth_hdr.strip_prefix("Bearer ")?.trim();
        if !bearer.is_empty() {
            return Some(bearer.to_string());
        }
        return None;
    }
    extract_cookie(headers, "aetherflow_session")
}

pub fn decode_session_claims(token: &str, allow_expired: bool) -> anyhow::Result<SessionClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_aud = false;
    if allow_expired {
        validation.validate_exp = false;
    }
    let data = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(&jwt_secret_bytes()),
        &validation,
    )?;
    if data.claims.iss != "aetherflow" || data.claims.jti.starts_with("plg-") {
        anyhow::bail!("Token is not a regular user session token");
    }
    anyhow::ensure!(
        session_within_absolute_lifetime(&data.claims, Utc::now().timestamp()),
        "Absolute session lifetime exceeded"
    );
    Ok(data.claims)
}
