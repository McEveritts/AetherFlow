use crate::ws::{build_set_cookie, extract_client_ip, extract_cookie};
use af_models::User;
use axum::extract::{Path, Request};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use data_encoding::BASE32_NOPAD;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Standard Error Helpers (`backend/api/errors.go`)
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

// ─────────────────────────────────────────────────────────────────────────────
// JWT Claims, Client Fingerprint & Rotation Grace (`auth.go` & `oidc.go`)
// ─────────────────────────────────────────────────────────────────────────────

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

pub(crate) fn query_user_credential_version(conn: &rusqlite::Connection, user_id: i64) -> i64 {
    if column_exists(conn, "users", "sessions_revoked_after").unwrap_or(false) {
        conn.query_row(
            "SELECT COALESCE(sessions_revoked_after, 0) FROM users WHERE id = ?1",
            params![user_id],
            |r| r.get(0),
        )
        .unwrap_or(0)
    } else {
        0
    }
}

#[derive(Clone)]
struct RotatedTokenGraceEntry {
    user_id: i64,
    family_id: String,
    successor_jti: String,
    new_token: String,
    successor_exp: i64,
    strict_fp: String,
    expires_at: Instant,
}

static ROTATED_TOKEN_GRACE: Lazy<Mutex<HashMap<String, RotatedTokenGraceEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static ROTATED_SESSION_SUCCESSOR: Lazy<Mutex<HashMap<String, (String, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const SESSION_COOKIE_MAX_AGE: i64 = 86400;
const SESSION_ABSOLUTE_LIFETIME: i64 = 30 * 86400;
const MIN_REVOCATION_TTL: Duration = Duration::from_secs(8160);
const ROTATED_TOKEN_GRACE_WINDOW: Duration = Duration::from_secs(10);

pub(crate) fn oidc_session_tag(family_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"af-oidc-sess:");
    hasher.update(family_id.trim().as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest[..32].to_string()
}

pub(crate) fn resolve_session_family_id(
    conn: &rusqlite::Connection,
    user_id: i64,
    jti: &str,
) -> String {
    let trimmed = jti.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let resolved_jti = resolve_current_session_jti(trimmed);
    if let Some(fam) = ROTATED_TOKEN_GRACE
        .lock()
        .ok()
        .and_then(|map| map.get(trimmed).cloned())
        .filter(|e| e.user_id == user_id && !e.family_id.trim().is_empty())
        .map(|e| e.family_id)
    {
        return fam;
    }
    if table_exists(conn, "active_sessions").unwrap_or(false)
        && column_exists(conn, "active_sessions", "family_id").unwrap_or(false)
    {
        if let Ok(Some(fam)) = conn
            .query_row(
                "SELECT COALESCE(family_id, '') FROM active_sessions \
                 WHERE user_id = ?1 AND (jti = ?2 OR jti = ?3) AND COALESCE(family_id, '') != '' LIMIT 1",
                params![user_id, trimmed, resolved_jti],
                |r| r.get::<_, String>(0),
            )
            .optional()
        {
            if !fam.trim().is_empty() {
                return fam.trim().to_string();
            }
        }
    }
    if let Ok(Some(fam)) = af_db::resolve_revoked_token_family_in_tx(conn, trimmed, user_id) {
        if !fam.trim().is_empty() {
            return fam.trim().to_string();
        }
    }
    trimmed.to_string()
}

pub(crate) fn resolve_current_session_jti(jti: &str) -> String {
    if jti.is_empty() {
        return String::new();
    }
    let Ok(mut map) = ROTATED_SESSION_SUCCESSOR.lock() else {
        return jti.to_string();
    };
    let now = Instant::now();
    if map.len() > 4096 {
        map.retain(|_, (_, exp)| *exp > now);
    }
    let mut current = jti.to_string();
    for _ in 0..32 {
        match map.get(&current) {
            Some((next, exp)) if *exp > now && next != &current => {
                current = next.clone();
            }
            _ => break,
        }
    }
    current
}

static AUTH_BLOCKING_LIMIT: Lazy<tokio::sync::Semaphore> =
    Lazy::new(|| tokio::sync::Semaphore::new(16));

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

fn is_refresh_path(path: &str) -> bool {
    matches!(
        path,
        "/api/v1/auth/refresh"
            | "/api/v1/public/auth/refresh"
            | "/api/auth/refresh"
            | "/api/public/auth/refresh"
    )
}

fn session_auth_time(claims: &SessionClaims) -> i64 {
    if claims.auth_time > 0 {
        claims.auth_time
    } else {
        claims.iat
    }
}

fn session_within_absolute_lifetime(claims: &SessionClaims, now: i64) -> bool {
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

    // Track the full refresh window; otherwise a still-refreshable session disappears from revocation UI.
    let exp_rfc3339 = chrono::DateTime::from_timestamp((exp + 7200).min(absolute_exp), 0)
        .ok_or_else(|| anyhow::anyhow!("Invalid session expiry"))?
        .to_rfc3339();
    if column_exists(conn, "active_sessions", "family_id").unwrap_or(false) {
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

fn create_session_jwt(
    user_id: i64,
    headers: &HeaderMap,
    auth_time: i64,
) -> anyhow::Result<(String, SessionClaims)> {
    let conn = af_db::get_conn()?;
    let ver = query_user_credential_version(&conn, user_id);
    create_session_jwt_in_conn(&conn, user_id, headers, auth_time, None, ver)
}

pub fn mint_plugin_jwt(
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
    if let Some(auth_hdr) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(bearer) = auth_hdr.strip_prefix("Bearer ") {
            let trimmed = bearer.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
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

fn check_rotation_grace(jti: &str) -> Option<RotatedTokenGraceEntry> {
    let mut map = ROTATED_TOKEN_GRACE.lock().ok()?;
    map.retain(|_, v| v.expires_at > Instant::now());
    map.get(jti).cloned()
}

fn resolve_latest_grace_token(
    jti: &str,
    user_id: i64,
    caller_strict_fp: Option<&str>,
) -> Option<(RotatedTokenGraceEntry, String, i64, String)> {
    let grace = check_rotation_grace(jti).filter(|g| g.user_id == user_id)?;
    if let Some(fp) = caller_strict_fp.filter(|s| !s.is_empty()) {
        if !grace.strict_fp.is_empty() && grace.strict_fp != fp {
            return None;
        }
    }
    if grace.successor_jti.is_empty() || grace.new_token.is_empty() {
        return None;
    }
    let mut latest_token = grace.new_token.clone();
    let mut latest_exp = grace.successor_exp;
    if let Ok(map) = ROTATED_TOKEN_GRACE.lock() {
        let now = Instant::now();
        let mut cur_succ = grace.successor_jti.clone();
        for _ in 0..32 {
            let Some(next) = map.get(&cur_succ) else {
                break;
            };
            if next.user_id != user_id
                || next.expires_at <= now
                || next.new_token.is_empty()
                || next.successor_jti == cur_succ
            {
                break;
            }
            if let Some(fp) = caller_strict_fp.filter(|s| !s.is_empty()) {
                if !next.strict_fp.is_empty() && next.strict_fp != fp {
                    return None;
                }
            }
            latest_token = next.new_token.clone();
            if next.successor_exp > 0 {
                latest_exp = next.successor_exp;
            }
            if next.successor_jti.is_empty() {
                break;
            }
            cur_succ = next.successor_jti.clone();
        }
    }
    let leaf_jti = resolve_current_session_jti(&grace.successor_jti);
    if leaf_jti.is_empty() {
        return None;
    }
    if latest_exp <= 0 {
        latest_exp = decode_session_claims(&latest_token, true)
            .map(|c| c.exp)
            .unwrap_or_else(|_| Utc::now().timestamp() + 900);
    }
    Some((grace, latest_token, latest_exp, leaf_jti))
}

pub(crate) fn is_session_token_revoked_beyond_grace_with_conn(
    conn: &rusqlite::Connection,
    jti: &str,
    user_id: i64,
) -> bool {
    match af_db::token_revocation_status_with_conn(conn, jti) {
        Ok(false) => false,
        Err(_) => true,
        Ok(true) => {
            let Some((grace, _, _, leaf_jti)) = resolve_latest_grace_token(jti, user_id, None)
            else {
                return true;
            };
            if matches!(
                af_db::token_revocation_status_with_conn(conn, &leaf_jti),
                Ok(false)
            ) {
                false
            } else {
                evict_rotation_grace_for_family(&grace.family_id, jti);
                true
            }
        }
    }
}

pub(crate) fn is_session_token_revoked_beyond_grace_for_fp(
    jti: &str,
    user_id: i64,
    caller_strict_fp: Option<&str>,
) -> bool {
    match af_db::token_revocation_status(jti) {
        Ok(false) => false,
        Err(_) => true,
        Ok(true) => {
            let Some((grace, _, _, leaf_jti)) =
                resolve_latest_grace_token(jti, user_id, caller_strict_fp)
            else {
                return true;
            };
            if matches!(af_db::token_revocation_status(&leaf_jti), Ok(false)) {
                false
            } else {
                evict_rotation_grace_for_family(&grace.family_id, jti);
                true
            }
        }
    }
}

pub(crate) fn is_session_token_revoked_beyond_grace(jti: &str, user_id: i64) -> bool {
    is_session_token_revoked_beyond_grace_for_fp(jti, user_id, None)
}

pub(crate) fn evict_rotation_grace_for_family(family_id: &str, target_jti: &str) {
    let mut evicted_jtis = std::collections::HashSet::new();
    if !target_jti.is_empty() {
        evicted_jtis.insert(target_jti.to_string());
    }
    if let Ok(mut map) = ROTATED_TOKEN_GRACE.lock() {
        map.retain(|old_jti, entry| {
            let leaf = resolve_current_session_jti(&entry.successor_jti);
            let keep = old_jti != target_jti
                && entry.successor_jti != target_jti
                && (target_jti.is_empty() || leaf != target_jti)
                && (family_id.is_empty() || entry.family_id != family_id);
            if !keep {
                evicted_jtis.insert(old_jti.clone());
                if !entry.successor_jti.is_empty() {
                    evicted_jtis.insert(entry.successor_jti.clone());
                }
                if !leaf.is_empty() {
                    evicted_jtis.insert(leaf);
                }
            }
            keep
        });
    }
    if !evicted_jtis.is_empty() {
        if let Ok(mut succ) = ROTATED_SESSION_SUCCESSOR.lock() {
            succ.retain(|old_jti, (next_jti, _)| {
                !evicted_jtis.contains(old_jti) && !evicted_jtis.contains(next_jti)
            });
        }
    }
}

pub(crate) fn evict_rotation_grace_for_user(user_id: i64) {
    let mut evicted_jtis = std::collections::HashSet::new();
    if let Ok(mut map) = ROTATED_TOKEN_GRACE.lock() {
        map.retain(|old_jti, entry| {
            let keep = entry.user_id != user_id;
            if !keep {
                evicted_jtis.insert(old_jti.clone());
                if !entry.successor_jti.is_empty() {
                    evicted_jtis.insert(entry.successor_jti.clone());
                }
            }
            keep
        });
    }
    if !evicted_jtis.is_empty() {
        if let Ok(mut succ) = ROTATED_SESSION_SUCCESSOR.lock() {
            succ.retain(|old_jti, (next_jti, _)| {
                !evicted_jtis.contains(old_jti) && !evicted_jtis.contains(next_jti)
            });
        }
    }
}

/// Bumps `users.sessions_revoked_after` (monotonic credential epoch), revokes all
/// active session JTIs for `user_id` into `revoked_tokens`, deletes `active_sessions`,
/// and revokes all OIDC refresh tokens, auth codes, and pending device codes for `user_id`.
/// Returns `(new_credential_ver, revoked_jtis)` so callers can cache JTIs and evict
/// rotation grace after committing the SQLite transaction.
pub(crate) fn revoke_all_user_credentials_in_tx(
    tx: &rusqlite::Connection,
    user_id: i64,
) -> anyhow::Result<(i64, Vec<String>)> {
    let mut new_ver = 1i64;
    if column_exists(tx, "users", "sessions_revoked_after").unwrap_or(false) {
        new_ver = tx.query_row(
            "UPDATE users SET sessions_revoked_after = COALESCE(sessions_revoked_after, 0) + 1 \
             WHERE id = ?1 RETURNING sessions_revoked_after",
            params![user_id],
            |r| r.get(0),
        )?;
    }

    let mut revoked_jtis = Vec::new();
    if table_exists(tx, "active_sessions").unwrap_or(false) {
        if column_exists(tx, "active_sessions", "jti").unwrap_or(false) {
            let mut stmt = tx.prepare("SELECT jti FROM active_sessions WHERE user_id = ?1")?;
            let rows = stmt.query_map(params![user_id], |r| r.get::<_, String>(0))?;
            for row in rows {
                revoked_jtis.push(row?);
            }
            drop(stmt);
            if table_exists(tx, "revoked_tokens").unwrap_or(false) {
                for jti in &revoked_jtis {
                    af_db::revoke_token_in_tx(tx, jti, MIN_REVOCATION_TTL)?;
                }
            }
        }
        tx.execute(
            "DELETE FROM active_sessions WHERE user_id = ?1",
            params![user_id],
        )?;
    }

    if table_exists(tx, "oidc_refresh_tokens").unwrap_or(false)
        && column_exists(tx, "oidc_refresh_tokens", "revoked").unwrap_or(false)
    {
        tx.execute(
            "UPDATE oidc_refresh_tokens SET revoked = 1 WHERE user_id = ?1",
            params![user_id],
        )?;
    }
    if table_exists(tx, "oidc_auth_codes").unwrap_or(false)
        && column_exists(tx, "oidc_auth_codes", "used").unwrap_or(false)
    {
        tx.execute(
            "UPDATE oidc_auth_codes SET used = 1 WHERE user_id = ?1",
            params![user_id],
        )?;
    }
    if table_exists(tx, "oidc_device_codes").unwrap_or(false) {
        tx.execute(
            "DELETE FROM oidc_device_codes WHERE user_id = ?1",
            params![user_id],
        )?;
    }
    af_db::delete_user_mfa_challenges_in_tx(tx, user_id)?;

    Ok((new_ver, revoked_jtis))
}

pub(crate) fn finalize_user_credential_revocation(user_id: i64, revoked_jtis: &[String]) {
    for jti in revoked_jtis {
        af_db::cache_revoked_token(jti, MIN_REVOCATION_TTL);
    }
    evict_rotation_grace_for_user(user_id);
    af_db::delete_2fa_pending(user_id);
}

// ──────────────────────────────────────────────────────────────────────────────
// Auth, Admin & CSRF Middlewares (`auth.go` & `csrf.go`)
// ──────────────────────────────────────────────────────────────────────────────

pub async fn auth_middleware(mut req: Request, next: Next) -> Response {
    let path = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|u| u.0.path().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    if is_refresh_path(&path) {
        return next.run(req).await;
    }

    let method = req.method().clone();
    let headers = req.headers();
    let bearer_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|b| b.trim().to_string())
        .filter(|b| !b.is_empty());

    let Some(token) = resolve_raw_token(headers) else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };

    // Check if the caller presented a scoped short-lived plugin Bearer token
    if let Some(ref raw_bearer) = bearer_token {
        let raw_bearer = raw_bearer.clone();
        if let Ok(Ok(plugin_claims)) =
            blocking_auth_work(move || crate::plugins::decode_and_verify_plugin_token(&raw_bearer))
                .await
        {
            if !crate::plugins::plugin_claims_allow_request(&plugin_claims, &method, &path) {
                return api_error(
                    StatusCode::FORBIDDEN,
                    "PLUGIN_SCOPE_DENIED",
                    format!(
                        "Plugin '{}' is not authorized for {} {}",
                        plugin_claims.plugin_id, method, path
                    ),
                );
            }
            req.extensions_mut().insert(AuthUser {
                user_id: 0,
                username: format!("plugin:{}", plugin_claims.plugin_id),
                role: "plugin".to_string(),
                jti: plugin_claims.jti.clone(),
                plugin_id: Some(plugin_claims.plugin_id.clone()),
                plugin_scopes: plugin_claims
                    .scopes
                    .iter()
                    .map(|scope| format!("{} {}", scope.method, scope.route))
                    .collect(),
            });
            req.extensions_mut().insert(plugin_claims);
            return next.run(req).await;
        }
    }

    let Ok(claims) = decode_session_claims(&token, false) else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };

    let jti = claims.jti.clone();
    let check_uid = claims.user_id;
    let req_peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::ConnectInfo(addr)| addr.ip());
    let req_ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let req_ip = crate::ws::extract_client_ip_for_peer(req.headers(), req_peer_ip);
    let caller_strict_fp = legacy_client_fingerprint(&req_ip, req_ua);
    let still_revoked = blocking_auth_work(move || {
        is_session_token_revoked_beyond_grace_for_fp(&jti, check_uid, Some(&caller_strict_fp))
    })
    .await;
    let Ok(false) = still_revoked else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_EXPIRED",
            "Session revoked",
        );
    };

    // Enforce scoped RBAC if this JWT is a plugin-scoped token (`plugin_id` or `plugin_scopes` set)
    if !claims.plugin_id.is_empty() || !claims.plugin_scopes.is_empty() {
        let check_path = if path.starts_with("/api/v1/") {
            path.clone()
        } else if let Some(rest) = path.strip_prefix("/api/") {
            format!("/api/v1/{}", rest)
        } else if let Some(rest) = path.strip_prefix("/plugins/") {
            let trimmed = rest.trim_matches('/');
            if let Some((pid, sub)) = trimmed.split_once('/') {
                format!("/api/v1/auth/plugins/{}/proxy/{}", pid, sub)
            } else {
                format!("/api/v1/auth/plugins/{}/proxy", trimmed)
            }
        } else {
            format!("/api/v1/auth{}", path)
        };
        if crate::plugins::is_plugin_request_denied(&method, &check_path)
            || crate::plugins::is_plugin_request_denied(&method, &path)
        {
            return api_error(
                StatusCode::FORBIDDEN,
                "PLUGIN_SCOPE_DENIED",
                "Plugin tokens cannot delegate this HTTP capability",
            );
        }
        if !af_services::plugins::verify_plugin_route_scope(&claims.plugin_scopes, &check_path)
            && !af_services::plugins::verify_plugin_route_scope(&claims.plugin_scopes, &path)
        {
            return api_error(
                StatusCode::FORBIDDEN,
                "PLUGIN_SCOPE_DENIED",
                format!(
                    "Plugin '{}' token is not authorized for route '{}'",
                    claims.plugin_id, path
                ),
            );
        }

        req.extensions_mut().insert(AuthUser {
            user_id: claims.user_id,
            username: format!("plugin:{}", claims.plugin_id),
            role: "plugin".to_string(),
            jti: claims.jti,
            plugin_id: Some(claims.plugin_id),
            plugin_scopes: claims.plugin_scopes,
        });

        return next.run(req).await;
    }

    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ip = extract_client_ip(headers);
    if !matches_client_fingerprint(&claims.cfp, &ip, ua) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_HIJACKED",
            "Session bound to a different client",
        );
    }

    let uid = claims.user_id;
    let subject_res = blocking_auth_work(move || {
        let conn = af_db::get_read_conn().map_err(|_| SubjectStatusError::DbError)?;
        load_active_human_subject(&conn, uid)
    })
    .await;

    let subj = match subject_res {
        Ok(Ok(subj)) => subj,
        Ok(Err(SubjectStatusError::Suspended)) => {
            return api_error(
                StatusCode::FORBIDDEN,
                "ACCOUNT_SUSPENDED",
                "Account is not active",
            );
        }
        _ => return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized"),
    };

    if claims.ver < subj.sessions_revoked_after {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_EXPIRED",
            "Session revoked",
        );
    }

    req.extensions_mut().insert(AuthUser {
        user_id: claims.user_id,
        username: subj.username,
        role: subj.role,
        jti: claims.jti,
        plugin_id: None,
        plugin_scopes: Vec::new(),
    });

    next.run(req).await
}

pub async fn admin_only_middleware(req: Request, next: Next) -> Response {
    if let Some(plugin_claims) = req.extensions().get::<crate::plugins::PluginTokenClaims>() {
        let method = req.method();
        let path = req
            .extensions()
            .get::<axum::extract::OriginalUri>()
            .map(|u| u.0.path().to_string())
            .unwrap_or_else(|| req.uri().path().to_string());
        if crate::plugins::plugin_claims_allow_request(plugin_claims, method, &path) {
            return next.run(req).await;
        }
        return api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_SCOPE_DENIED",
            "Plugin token does not hold scope for this admin endpoint",
        );
    }
    let is_admin = req
        .extensions()
        .get::<AuthUser>()
        .map(|u| u.role == "admin")
        .unwrap_or(false);
    if !is_admin {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    next.run(req).await
}

pub async fn csrf_middleware(req: Request, next: Next) -> Response {
    let csrf_disabled = env::var("CSRF_DISABLED")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if csrf_disabled {
        return next.run(req).await;
    }

    let method = req.method().clone();
    if !matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return next.run(req).await;
    }

    let path = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|u| u.0.path().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    if is_refresh_path(&path) {
        return next.run(req).await;
    }

    let headers = req.headers();
    // Bearer token requests with a non-empty token are exempt from cookie CSRF check
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|b| !b.trim().is_empty())
        .unwrap_or(false)
    {
        return next.run(req).await;
    }

    let header_token = headers
        .get("X-CSRF-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cookie_token = extract_cookie(headers, "csrf_token").unwrap_or_default();

    if header_token.is_empty() || header_token != cookie_token {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Invalid CSRF token" })),
        )
            .into_response();
    }

    next.run(req).await
}

pub async fn issue_csrf_token() -> Response {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let token = hex::encode(b);
    let cookie = build_set_cookie(
        "csrf_token",
        &token,
        3600,
        "Strict",
        secure_cookie_enabled(),
        false,
    );
    let mut resp = Json(serde_json::json!({ "csrf_token": token })).into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth & Setup Endpoints (`backend/api/auth.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CredentialsRequest {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

pub async fn check_setup_needed() -> Response {
    blocking_response(check_setup_needed_blocking).await
}

fn check_setup_needed_blocking() -> Response {
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to verify setup state",
        );
    };
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
        .unwrap_or(0);
    Json(serde_json::json!({ "setupRequired": count == 0 })).into_response()
}

pub fn save_master_credentials(username: &str, password: &str) {
    let u = username.trim();
    if u.is_empty() || password.is_empty() {
        return;
    }
    let _ = af_services::mutators::save_master_credentials(u, password);
}

fn revoke_session_family_in_tx(
    tx: &rusqlite::Connection,
    user_id: i64,
    target_jti: &str,
    revoke_oidc_grants: bool,
) -> anyhow::Result<(String, Vec<String>)> {
    let resolved_jti = resolve_current_session_jti(target_jti);
    let grace_info = ROTATED_TOKEN_GRACE
        .lock()
        .ok()
        .and_then(|map| map.get(target_jti).cloned())
        .filter(|e| e.user_id == user_id);
    let mut family_id = grace_info
        .as_ref()
        .map(|e| e.family_id.clone())
        .unwrap_or_default();

    let mut jtis_to_revoke = vec![target_jti.to_string()];
    if !resolved_jti.is_empty() && !jtis_to_revoke.contains(&resolved_jti) {
        jtis_to_revoke.push(resolved_jti.clone());
    }
    if let Some(ref g) = grace_info {
        if !g.successor_jti.is_empty() && !jtis_to_revoke.contains(&g.successor_jti) {
            jtis_to_revoke.push(g.successor_jti.clone());
        }
    }

    if table_exists(tx, "active_sessions").unwrap_or(false) {
        let has_family = column_exists(tx, "active_sessions", "family_id").unwrap_or(false);
        if has_family && family_id.is_empty() {
            family_id = tx
                .query_row(
                    "SELECT COALESCE(family_id, '') FROM active_sessions \
                     WHERE user_id = ?1 AND (jti = ?2 OR jti = ?3) AND COALESCE(family_id, '') != '' LIMIT 1",
                    params![user_id, target_jti, resolved_jti],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or_default();
        }
        if has_family && !family_id.is_empty() {
            let mut stmt = tx.prepare(
                "SELECT jti FROM active_sessions WHERE user_id = ?1 AND (family_id = ?2 OR jti = ?3 OR jti = ?4)",
            )?;
            let rows = stmt
                .query_map(params![user_id, family_id, target_jti, resolved_jti], |r| {
                    r.get::<_, String>(0)
                })?;
            for row in rows {
                let found = row?;
                if !found.is_empty() && !jtis_to_revoke.contains(&found) {
                    jtis_to_revoke.push(found);
                }
            }
        }
    }

    for jti in &jtis_to_revoke {
        af_db::revoke_token_in_tx(tx, jti, MIN_REVOCATION_TTL)?;
    }

    if table_exists(tx, "active_sessions").unwrap_or(false) {
        if !family_id.is_empty()
            && column_exists(tx, "active_sessions", "family_id").unwrap_or(false)
        {
            tx.execute(
                "DELETE FROM active_sessions WHERE user_id = ?1 AND family_id = ?2",
                params![user_id, family_id],
            )?;
        }
        for jti in &jtis_to_revoke {
            tx.execute("DELETE FROM active_sessions WHERE jti = ?1", params![jti])?;
        }
    }

    if revoke_oidc_grants {
        if family_id.is_empty() {
            if let Ok(Some(fam)) =
                af_db::resolve_revoked_token_family_in_tx(tx, target_jti, user_id)
            {
                if !fam.trim().is_empty() {
                    family_id = fam.trim().to_string();
                }
            }
        }
        let mut sess_tags = Vec::new();
        if !family_id.is_empty() {
            sess_tags.push(oidc_session_tag(&family_id));
        }
        let jti_tag = oidc_session_tag(target_jti);
        if !sess_tags.contains(&jti_tag) {
            sess_tags.push(jti_tag);
        }
        let has_oidc_table = table_exists(tx, "oidc_refresh_tokens").unwrap_or(false);
        let has_oidc_fam = has_oidc_table
            && column_exists(tx, "oidc_refresh_tokens", "family_id").unwrap_or(false);
        for tag in sess_tags {
            let marker = format!("oidc-sess:{}", tag);
            af_db::revoke_token_in_tx(tx, &marker, MIN_REVOCATION_TTL)?;
            if !jtis_to_revoke.contains(&marker) {
                jtis_to_revoke.push(marker);
            }
            if has_oidc_fam {
                let prefix = format!("sf:{}:", tag);
                tx.execute(
                    "UPDATE oidc_refresh_tokens SET revoked = 1 \
                     WHERE user_id = ?1 AND substr(COALESCE(family_id, ''), 1, 36) = ?2",
                    params![user_id, prefix],
                )?;
            }
        }
    }

    Ok((family_id, jtis_to_revoke))
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    if password.is_empty() || password_hash.is_empty() {
        return false;
    }
    bcrypt::verify(password, password_hash).unwrap_or(false)
}

pub async fn setup_admin(headers: HeaderMap, Json(req): Json<CredentialsRequest>) -> Response {
    blocking_response(move || setup_admin_blocking(headers, req)).await
}

fn setup_admin_blocking(headers: HeaderMap, req: CredentialsRequest) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
        .unwrap_or(0);
    if count > 0 {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Admin account already exists",
        );
    }

    let trimmed_username = req.username.trim();
    if trimmed_username.is_empty() || req.password.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Username and password are required",
        );
    }
    if trimmed_username.to_ascii_lowercase().starts_with("plugin:") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Reserved username prefix",
        );
    }
    if req.password.len() < 8 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Password must be at least 8 characters",
        );
    }

    let Ok(hash) = bcrypt::hash(&req.password, bcrypt::DEFAULT_COST) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to hash password",
        );
    };

    if conn
        .execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, 'admin')",
            params![trimmed_username, hash],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create admin account",
        );
    }
    let user_id = conn.last_insert_rowid();
    drop(conn);

    // Provision dedicated random package credentials rather than persisting the operator's control-plane password.
    af_services::mutators::ensure_provisioning_credentials(trimmed_username);

    let Ok((token, _)) = create_standard_jwt(user_id, &headers) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create session",
        );
    };

    let cookie = build_set_cookie(
        "aetherflow_session",
        &token,
        SESSION_COOKIE_MAX_AGE,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    let mut resp = Json(serde_json::json!({
        "message": "Admin account created",
        "username": trimmed_username,
    }))
    .into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn local_login(headers: HeaderMap, Json(req): Json<CredentialsRequest>) -> Response {
    blocking_response(move || local_login_blocking(headers, req)).await
}

fn local_login_blocking(headers: HeaderMap, req: CredentialsRequest) -> Response {
    let trimmed_username = req.username.trim();
    if trimmed_username.is_empty() || req.password.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Username and password are required",
        );
    }
    if trimmed_username.to_ascii_lowercase().starts_with("plugin:") {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid username or password",
        );
    }

    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };

    let row = conn.query_row(
        "SELECT id, username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user'), \
         COALESCE(password_hash, ''), COALESCE(google_id, ''), COALESCE(totp_enabled, 0) \
         FROM users WHERE username = ?1",
        params![trimmed_username],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, bool>(7)?,
            ))
        },
    );

    let Ok((id, _username, _email, _avatar_url, _role, password_hash, _google_id, _totp_enabled)) =
        row
    else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid username or password",
        );
    };

    let subject_status = load_active_human_subject(&conn, id);
    let pre_auth_ver = query_user_credential_version(&conn, id);
    drop(conn);

    if password_hash.is_empty() {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "This account uses Google OAuth. Use the Google login button.",
        );
    }

    let password_ok = bcrypt::verify(&req.password, &password_hash).unwrap_or(false);
    if !password_ok {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid username or password",
        );
    }

    match subject_status {
        Ok(_) => {}
        Err(SubjectStatusError::Suspended) => {
            return api_error(
                StatusCode::FORBIDDEN,
                "ACCOUNT_SUSPENDED",
                "Account is not active",
            );
        }
        Err(SubjectStatusError::MissingOrPlugin) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Invalid username or password",
            );
        }
        Err(SubjectStatusError::DbError) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database unavailable",
            );
        }
    }

    let Ok(mut write_conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let Ok(tx) = write_conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
    else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    match load_active_human_subject(&tx, id) {
        Ok(_) => {}
        Err(SubjectStatusError::Suspended) => {
            return api_error(
                StatusCode::FORBIDDEN,
                "ACCOUNT_SUSPENDED",
                "Account is not active",
            );
        }
        Err(SubjectStatusError::MissingOrPlugin) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Invalid username or password",
            );
        }
        Err(SubjectStatusError::DbError) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database unavailable",
            );
        }
    }
    let current_row = tx.query_row(
        "SELECT username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user'), \
         COALESCE(password_hash, ''), COALESCE(google_id, ''), COALESCE(totp_enabled, 0) \
         FROM users WHERE id = ?1",
        params![id],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, bool>(6)?,
            ))
        },
    );
    let Ok((username, email, avatar_url, role, current_password_hash, google_id, totp_enabled)) =
        current_row
    else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid username or password",
        );
    };
    let current_ver = query_user_credential_version(&tx, id);
    if current_password_hash.is_empty()
        || current_password_hash != password_hash
        || current_ver != pre_auth_ver
    {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid username or password",
        );
    }

    if totp_enabled {
        let mut raw_token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw_token);
        let mfa_token = hex::encode(raw_token);
        if af_db::store_mfa_challenge_in_tx(
            &tx,
            &mfa_token,
            id,
            current_ver,
            Duration::from_secs(300),
        )
        .is_err()
            || tx.commit().is_err()
        {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to create MFA challenge",
            );
        }
        return Json(serde_json::json!({
            "requires_mfa": true,
            "mfa_token": mfa_token,
        }))
        .into_response();
    }

    let client_ip = extract_client_ip(&headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let _ = tx.execute(
        "INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?1, ?2, ?3)",
        params![id, client_ip, user_agent],
    );

    let Ok((token, _)) =
        create_session_jwt_in_conn(&tx, id, &headers, Utc::now().timestamp(), None, current_ver)
    else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create session",
        );
    };
    if tx.commit().is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create session",
        );
    }
    drop(write_conn);

    let user = User {
        id,
        username,
        email,
        avatar_url,
        role,
        google_id: google_id.clone(),
        is_oauth: !google_id.is_empty(),
        totp_enabled,
    };

    let cookie = build_set_cookie(
        "aetherflow_session",
        &token,
        SESSION_COOKIE_MAX_AGE,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    let mut resp = Json(serde_json::json!({
        "message": "Login successful",
        "user": user,
    }))
    .into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn get_session(req: Request) -> Response {
    blocking_response(move || get_session_blocking(req)).await
}

fn get_session_blocking(req: Request) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };

    let row = conn.query_row(
        "SELECT id, username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user'), \
         COALESCE(google_id, ''), COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
        params![auth_user.user_id],
        |r| {
            let google_id: String = r.get(5)?;
            Ok(User {
                id: r.get(0)?,
                username: r.get(1)?,
                email: r.get(2)?,
                avatar_url: r.get(3)?,
                role: r.get(4)?,
                is_oauth: !google_id.is_empty(),
                google_id,
                totp_enabled: r.get(6)?,
            })
        },
    );

    match row {
        Ok(u) => Json(u).into_response(),
        Err(_) => api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "User not found"),
    }
}

pub async fn logout(req: Request) -> Response {
    blocking_response(move || logout_blocking(req)).await
}

fn logout_blocking(req: Request) -> Response {
    let resolved_subject: Option<(i64, String)> = req
        .extensions()
        .get::<AuthUser>()
        .map(|u| (u.user_id, u.jti.clone()))
        .or_else(|| {
            let raw = resolve_raw_token(req.headers())?;
            let claims = decode_session_claims(&raw, true).ok()?;
            if !claims.plugin_id.trim().is_empty() || claims.iss != "aetherflow" {
                return None;
            }
            Some((claims.user_id, claims.jti))
        });
    let clear_cookie = build_set_cookie(
        "aetherflow_session",
        "",
        -1,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    let attach_clear_cookie = |mut resp: Response| -> Response {
        if let Ok(hv) = HeaderValue::from_str(&clear_cookie) {
            resp.headers_mut().insert(header::SET_COOKIE, hv);
        }
        resp
    };
    if let Some((user_id, session_jti)) = resolved_subject {
        let Ok(mut conn) = af_db::get_conn() else {
            return attach_clear_cookie(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to revoke session",
            ));
        };
        let tx_res = (|| -> anyhow::Result<(String, Vec<String>)> {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let res = revoke_session_family_in_tx(&tx, user_id, &session_jti, true)?;
            tx.commit()?;
            Ok(res)
        })();
        let Ok((family_id, revoked_jtis)) = tx_res else {
            return attach_clear_cookie(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to revoke session",
            ));
        };
        for jti in &revoked_jtis {
            af_db::cache_revoked_token(jti, MIN_REVOCATION_TTL);
            evict_rotation_grace_for_family(&family_id, jti);
        }
        evict_rotation_grace_for_family(&family_id, &session_jti);
        drop(conn);
    }
    attach_clear_cookie(Json(serde_json::json!({ "message": "Logged out" })).into_response())
}

pub async fn refresh_session_with_peer(
    crate::ws::PeerIp(peer_ip): crate::ws::PeerIp,
    headers: HeaderMap,
) -> Response {
    blocking_response(move || refresh_session_for_peer_blocking(headers, peer_ip)).await
}

pub async fn refresh_session(headers: HeaderMap) -> Response {
    blocking_response(move || refresh_session_for_peer_blocking(headers, None)).await
}

fn refresh_session_for_peer_blocking(
    headers: HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
) -> Response {
    if let Some(auth_hdr) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(bearer) = auth_hdr.strip_prefix("Bearer ") {
            if crate::plugins::decode_and_verify_plugin_token(bearer.trim()).is_ok() {
                return api_error(
                    StatusCode::FORBIDDEN,
                    "PLUGIN_REFRESH_FORBIDDEN",
                    "Scoped plugin tokens cannot mint or refresh operator sessions",
                );
            }
        }
    }

    let Some(raw_token) = resolve_raw_token(&headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "No session token provided",
        );
    };

    if crate::plugins::decode_and_verify_plugin_token(&raw_token).is_ok() {
        return api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_REFRESH_FORBIDDEN",
            "Scoped plugin tokens cannot mint or refresh operator sessions",
        );
    }

    let Ok(claims) = decode_session_claims(&raw_token, true) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid session token",
        );
    };

    if !claims.plugin_id.trim().is_empty()
        || !claims.plugin_scopes.is_empty()
        || claims.iss != "aetherflow"
    {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Plugin-scoped tokens cannot be used to refresh user sessions",
        );
    }

    let now = Utc::now().timestamp();
    if now - claims.exp > 7200 {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Refresh window expired",
        );
    }

    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ip = crate::ws::extract_client_ip_for_peer(&headers, peer_ip);
    let caller_strict_fp = legacy_client_fingerprint(&ip, ua);
    let fp_matches = matches_client_fingerprint(&claims.cfp, &ip, ua);
    if !fp_matches && !af_db::is_token_revoked(&claims.jti) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Client fingerprint mismatch",
        );
    }

    let Ok(mut conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };

    let Ok(tx) = conn.transaction_with_behavior(TransactionBehavior::Immediate) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };

    let subj = match load_active_human_subject(&tx, claims.user_id) {
        Ok(subj) => subj,
        Err(SubjectStatusError::Suspended) => {
            return api_error(
                StatusCode::FORBIDDEN,
                "ACCOUNT_SUSPENDED",
                "Account is not active",
            );
        }
        Err(SubjectStatusError::MissingOrPlugin) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "User no longer exists",
            );
        }
        Err(SubjectStatusError::DbError) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "SESSION_EXPIRED",
                "Unable to validate session",
            );
        }
    };

    if claims.ver < subj.sessions_revoked_after {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Session has been revoked",
        );
    }

    let has_sessions_table = match table_exists(&tx, "active_sessions") {
        Ok(v) => v,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to inspect active sessions",
            );
        }
    };
    let has_family = if has_sessions_table {
        match column_exists(&tx, "active_sessions", "family_id") {
            Ok(v) => v,
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to inspect session schema",
                );
            }
        }
    } else {
        false
    };
    let existing_family_opt: Option<String> = if has_sessions_table {
        let query_res = if has_family {
            tx.query_row(
                "SELECT COALESCE(family_id, '') FROM active_sessions WHERE jti = ?1 AND user_id = ?2",
                params![claims.jti, subj.user_id],
                |r| r.get(0),
            )
            .optional()
        } else {
            tx.query_row(
                "SELECT jti FROM active_sessions WHERE jti = ?1 AND user_id = ?2",
                params![claims.jti, subj.user_id],
                |r| r.get(0),
            )
            .optional()
        };
        match query_res {
            Ok(v) => v,
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to query session family",
                );
            }
        }
    } else {
        None
    };

    let Ok(consumed) = af_db::try_consume_session_jti_in_tx(&tx, &claims.jti, MIN_REVOCATION_TTL)
    else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_EXPIRED",
            "Unable to validate session",
        );
    };

    if !consumed {
        if fp_matches {
            if let Some((_, latest_token, latest_exp, leaf_succ)) =
                resolve_latest_grace_token(&claims.jti, subj.user_id, Some(&caller_strict_fp))
            {
                let successor_revoked = leaf_succ.is_empty()
                    || af_db::token_revocation_status_with_conn(&tx, &leaf_succ).unwrap_or(true);
                let successor_active = has_sessions_table
                    && tx
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM active_sessions WHERE jti = ?1 AND user_id = ?2)",
                            params![leaf_succ, subj.user_id],
                            |r| r.get::<_, bool>(0),
                        )
                        .unwrap_or(false);
                if !successor_revoked && successor_active {
                    let cookie = build_set_cookie(
                        "aetherflow_session",
                        &latest_token,
                        SESSION_COOKIE_MAX_AGE,
                        "Lax",
                        secure_cookie_enabled(),
                        true,
                    );
                    let mut resp = Json(serde_json::json!({
                        "status": "success",
                        "token": latest_token,
                        "expires_at": latest_exp,
                        "user": { "id": subj.user_id, "username": subj.username, "role": subj.role }
                    }))
                    .into_response();
                    if let Ok(hv) = HeaderValue::from_str(&cookie) {
                        resp.headers_mut().insert(header::SET_COOKIE, hv);
                    }
                    return resp;
                }
            }
        }
        // Replay of an already-rotated or revoked token outside the 10s strict-fp grace window:
        // revoke the entire descendant session family (and session-scoped OIDC grants) before returning 401.
        let resolved_successor = resolve_current_session_jti(&claims.jti);
        let mut wiped_jtis = Vec::new();
        let mut resolved_family = existing_family_opt
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if resolved_family.is_none() {
            resolved_family =
                af_db::resolve_revoked_token_family_in_tx(&tx, &claims.jti, subj.user_id)
                    .ok()
                    .flatten();
        }
        if resolved_family.is_none() {
            resolved_family = ROTATED_TOKEN_GRACE
                .lock()
                .ok()
                .and_then(|map| map.get(&claims.jti).cloned())
                .filter(|e| e.user_id == subj.user_id && !e.family_id.trim().is_empty())
                .map(|e| e.family_id);
        }
        let wipe_outcome = (|| -> anyhow::Result<()> {
            if table_exists(&tx, "active_sessions")? {
                if resolved_family.is_none() && has_family {
                    resolved_family = tx
                        .query_row(
                            "SELECT COALESCE(family_id, '') FROM active_sessions \
                             WHERE user_id = ?1 AND (jti = ?2 OR jti = ?3 OR family_id = ?2) LIMIT 1",
                            params![subj.user_id, claims.jti, resolved_successor],
                            |r| r.get::<_, String>(0),
                        )
                        .optional()?
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                }
                let target_family = resolved_family.as_deref().unwrap_or(&claims.jti);
                if has_family {
                    let mut stmt = tx.prepare(
                        "SELECT jti FROM active_sessions \
                         WHERE user_id = ?1 AND (family_id = ?2 OR jti = ?3 OR jti = ?4)",
                    )?;
                    let rows = stmt.query_map(
                        params![subj.user_id, target_family, claims.jti, resolved_successor],
                        |r| r.get::<_, String>(0),
                    )?;
                    for row in rows {
                        let jti = row?;
                        if !jti.is_empty() {
                            wiped_jtis.push(jti);
                        }
                    }
                    drop(stmt);
                    tx.execute(
                        "DELETE FROM active_sessions \
                         WHERE user_id = ?1 AND (family_id = ?2 OR jti = ?3 OR jti = ?4)",
                        params![subj.user_id, target_family, claims.jti, resolved_successor],
                    )?;
                } else {
                    if resolved_successor != claims.jti {
                        wiped_jtis.push(resolved_successor.clone());
                    }
                    tx.execute(
                        "DELETE FROM active_sessions WHERE user_id = ?1 AND (jti = ?2 OR jti = ?3)",
                        params![subj.user_id, claims.jti, resolved_successor],
                    )?;
                }
                for jti in &wiped_jtis {
                    af_db::revoke_token_in_tx(&tx, jti, MIN_REVOCATION_TTL)?;
                    af_db::record_revoked_token_lineage_in_tx(
                        &tx,
                        jti,
                        target_family,
                        subj.user_id,
                    )?;
                }
                let sess_tag = oidc_session_tag(target_family);
                let sess_marker = format!("oidc-sess:{}", sess_tag);
                af_db::revoke_token_in_tx(&tx, &sess_marker, MIN_REVOCATION_TTL)?;
                wiped_jtis.push(sess_marker);
                if table_exists(&tx, "oidc_refresh_tokens").unwrap_or(false)
                    && column_exists(&tx, "oidc_refresh_tokens", "family_id").unwrap_or(false)
                {
                    let prefix = format!("sf:{}:", sess_tag);
                    tx.execute(
                        "UPDATE oidc_refresh_tokens SET revoked = 1 \
                         WHERE user_id = ?1 AND substr(COALESCE(family_id, ''), 1, 36) = ?2",
                        params![subj.user_id, prefix],
                    )?;
                }
            }
            tx.commit()?;
            Ok(())
        })();
        if wipe_outcome.is_err() {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to revoke compromised session family",
            );
        }
        for jti in &wiped_jtis {
            af_db::cache_revoked_token(jti, MIN_REVOCATION_TTL);
        }
        let target_family = resolved_family.as_deref().unwrap_or(&claims.jti);
        evict_rotation_grace_for_family(target_family, &claims.jti);
        for jti in &wiped_jtis {
            evict_rotation_grace_for_family(target_family, jti);
        }
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Session has been revoked",
        );
    }

    if !fp_matches {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Client fingerprint mismatch",
        );
    }

    let family_id = existing_family_opt
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&claims.jti)
        .to_string();

    let Ok((new_token, new_claims)) = create_session_jwt_in_conn(
        &tx,
        subj.user_id,
        &headers,
        session_auth_time(&claims),
        Some(&family_id),
        subj.sessions_revoked_after,
    ) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to rotate token",
        );
    };

    if af_db::record_revoked_token_lineage_in_tx(&tx, &claims.jti, &family_id, subj.user_id)
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to record token rotation lineage",
        );
    }
    if table_exists(&tx, "active_sessions").unwrap_or(false)
        && tx
            .execute(
                "DELETE FROM active_sessions WHERE jti = ?1",
                params![claims.jti],
            )
            .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to retire rotated session",
        );
    }

    if tx.commit().is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to commit rotated session",
        );
    }

    // Populate revocation cache and rotation grace BEFORE releasing `conn` so serialized concurrent racers see the exact successor.
    af_db::cache_revoked_token(&claims.jti, MIN_REVOCATION_TTL);
    if let Ok(mut succ) = ROTATED_SESSION_SUCCESSOR.lock() {
        succ.insert(
            claims.jti.clone(),
            (
                new_claims.jti.clone(),
                Instant::now() + Duration::from_secs(86400),
            ),
        );
    }
    if let Ok(mut grace) = ROTATED_TOKEN_GRACE.lock() {
        grace.insert(
            claims.jti.clone(),
            RotatedTokenGraceEntry {
                user_id: subj.user_id,
                family_id,
                successor_jti: new_claims.jti.clone(),
                new_token: new_token.clone(),
                successor_exp: new_claims.exp,
                strict_fp: caller_strict_fp,
                expires_at: Instant::now() + ROTATED_TOKEN_GRACE_WINDOW,
            },
        );
    }
    drop(conn);

    let cookie = build_set_cookie(
        "aetherflow_session",
        &new_token,
        SESSION_COOKIE_MAX_AGE,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    let mut resp = Json(serde_json::json!({
        "status": "success",
        "token": new_token,
        "expires_at": new_claims.exp,
        "user": { "id": subj.user_id, "username": subj.username, "role": subj.role }
    }))
    .into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn verify_proxy_auth(headers: HeaderMap) -> Response {
    blocking_response(move || verify_proxy_auth_blocking(headers)).await
}

fn verify_proxy_auth_blocking(headers: HeaderMap) -> Response {
    let Some(token) = resolve_raw_token(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized session" })),
        )
            .into_response();
    };
    let Ok(claims) = decode_session_claims(&token, false) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Invalid session token claims" })),
        )
            .into_response();
    };
    if !claims.plugin_id.trim().is_empty()
        || !claims.plugin_scopes.is_empty()
        || claims.iss != "aetherflow"
    {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Plugin-scoped tokens cannot be used for external proxy authentication",
        );
    }
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if is_session_token_revoked_beyond_grace(&claims.jti, claims.user_id)
        || !matches_client_fingerprint(&claims.cfp, &extract_client_ip(&headers), user_agent)
    {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid or revoked session",
        );
    }
    let Ok(conn) = af_db::get_read_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Internal validation error" })),
        )
            .into_response();
    };
    let subj = match load_active_human_subject(&conn, claims.user_id) {
        Ok(subj) => subj,
        Err(SubjectStatusError::Suspended) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Account is not active" })),
            )
                .into_response();
        }
        Err(SubjectStatusError::MissingOrPlugin) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "User no longer exists" })),
            )
                .into_response();
        }
        Err(SubjectStatusError::DbError) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Internal validation error" })),
            )
                .into_response();
        }
    };
    if claims.ver < subj.sessions_revoked_after {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid or revoked session",
        );
    }

    let mut resp = StatusCode::OK.into_response();
    if let Ok(hv) = HeaderValue::from_str(&subj.username) {
        resp.headers_mut().insert("X-Aetherflow-User", hv.clone());
        resp.headers_mut().insert("Remote-User", hv);
    }
    resp
}

pub async fn list_active_sessions(req: Request) -> Response {
    blocking_response(move || list_active_sessions_blocking(req)).await
}

fn list_active_sessions_blocking(req: Request) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };
    let _ = conn.execute(
        "DELETE FROM active_sessions WHERE expires_at < ?1",
        params![Utc::now().to_rfc3339()],
    );
    let mut stmt = match conn.prepare(
        "SELECT jti, ip_address, user_agent, COALESCE(CAST(expires_at AS TEXT), ''), COALESCE(CAST(last_active AS TEXT), '') \
         FROM active_sessions WHERE user_id = ?1 ORDER BY last_active DESC",
    ) {
        Ok(s) => s,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Query error",
            )
        }
    };

    let current_session_jti = resolve_current_session_jti(&auth_user.jti);
    let mut sessions = Vec::new();
    if let Ok(rows) = stmt.query_map(params![auth_user.user_id], |r| {
        let full_jti: String = r.get(0)?;
        let is_current = full_jti == auth_user.jti || full_jti == current_session_jti;
        let masked = if full_jti.len() > 8 {
            format!("{}...", &full_jti[..8])
        } else {
            full_jti
        };
        Ok(serde_json::json!({
            "jti": masked,
            "ip_address": r.get::<_, String>(1)?,
            "user_agent": r.get::<_, String>(2)?,
            "expires_at": r.get::<_, String>(3)?,
            "last_active": r.get::<_, String>(4)?,
            "is_current": is_current,
        }))
    }) {
        for s in rows.flatten() {
            sessions.push(s);
        }
    }

    let count = sessions.len();
    Json(serde_json::json!({
        "sessions": sessions,
        "count": count,
    }))
    .into_response()
}

pub async fn revoke_session(Path(jti_param): Path<String>, req: Request) -> Response {
    blocking_response(move || revoke_session_blocking(jti_param, req)).await
}

fn revoke_session_blocking(jti_param: String, req: Request) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let prefix = jti_param.trim_end_matches("...");
    if !(8..=36).contains(&prefix.len())
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid session identifier",
        );
    }
    let Ok(mut conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };
    let Ok(tx) = conn.transaction_with_behavior(TransactionBehavior::Immediate) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };
    let Ok(full_jti) = tx.query_row(
        "SELECT MIN(jti) FROM active_sessions WHERE substr(jti, 1, length(?1)) = ?1 AND user_id = ?2 HAVING COUNT(*) = 1",
        params![prefix, auth_user.user_id],
        |r| r.get::<_, String>(0),
    ) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Session not found");
    };

    let Ok((family_id, revoked_jtis)) =
        revoke_session_family_in_tx(&tx, auth_user.user_id, &full_jti, true)
    else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to revoke session",
        );
    };
    if tx.commit().is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to revoke session",
        );
    }
    for jti in &revoked_jtis {
        af_db::cache_revoked_token(jti, MIN_REVOCATION_TTL);
        evict_rotation_grace_for_family(&family_id, jti);
    }
    drop(conn);
    Json(serde_json::json!({ "message": "Session revoked" })).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 2FA TOTP Setup, Verification & MFA Login (`backend/api/totp.go`)
// ─────────────────────────────────────────────────────────────────────────────

fn matching_totp_step(secret_b32: &str, code: &str, now_secs: u64) -> Option<i64> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let secret_bytes = BASE32_NOPAD
        .decode(secret_b32.trim().to_uppercase().as_bytes())
        .ok()?;
    if secret_bytes.is_empty() {
        return None;
    }
    for offset in [0i64, -30, 30] {
        let ts = (now_secs as i64 + offset).max(0) as u64;
        let expected = totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &secret_bytes, ts);
        if af_services::cluster_daemon::constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            return Some((ts / 30) as i64);
        }
    }
    None
}

pub(crate) fn consume_totp_code(
    conn: &rusqlite::Connection,
    user_id: i64,
    secret: &str,
    code: &str,
) -> bool {
    let Some(step) = matching_totp_step(secret, code, Utc::now().timestamp().max(0) as u64) else {
        return false;
    };
    matches!(conn.execute(
        "UPDATE users SET last_totp_step = ?1 WHERE id = ?2 AND totp_enabled = 1 AND last_totp_step < ?1",
        params![step, user_id],
    ), Ok(1))
}

fn recovery_hash(salt: &[u8], compact: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"aetherflow-recovery-v1\0");
    hash.update(salt);
    hash.update(compact.as_bytes());
    hex::encode(hash.finalize())
}

pub(crate) fn generate_recovery_codes() -> Vec<String> {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut codes = Vec::with_capacity(8);
    for _ in 0..8 {
        let mut raw = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let chars: Vec<char> = raw
            .iter()
            .map(|&b| CHARSET[(b as usize) % CHARSET.len()] as char)
            .collect();
        let code = format!(
            "{}-{}",
            chars[0..4].iter().collect::<String>(),
            chars[4..8].iter().collect::<String>()
        );
        codes.push(code);
    }
    codes
}

pub(crate) fn store_recovery_codes(
    transaction: &rusqlite::Transaction<'_>,
    user_id: i64,
    codes: &[String],
) -> anyhow::Result<()> {
    transaction.execute(
        "DELETE FROM recovery_codes WHERE user_id = ?1",
        params![user_id],
    )?;
    for code in codes {
        let compact = code.replace('-', "");
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let hash = format!(
            "sha256:v1:{}:{}",
            hex::encode(salt),
            recovery_hash(&salt, &compact)
        );
        transaction.execute(
            "INSERT INTO recovery_codes (user_id, code_hash, used) VALUES (?1, ?2, 0)",
            params![user_id, hash],
        )?;
    }
    let has_legacy_column: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('users') WHERE name = 'totp_recovery_codes')",
        [], |row| row.get(0),
    )?;
    if has_legacy_column {
        transaction.execute(
            "UPDATE users SET totp_recovery_codes = '[]' WHERE id = ?1",
            params![user_id],
        )?;
    }
    Ok(())
}

pub(crate) fn validate_recovery_code(
    conn: &rusqlite::Connection,
    user_id: i64,
    raw_code: &str,
) -> bool {
    let normalized = raw_code.trim().to_uppercase();
    if normalized.is_empty() {
        return false;
    }
    let normalized_compact: String = normalized.chars().filter(|c| *c != '-').collect();
    let dashed = if normalized_compact.len() == 8 && normalized_compact.is_ascii() {
        format!("{}-{}", &normalized_compact[..4], &normalized_compact[4..])
    } else {
        normalized.clone()
    };
    let sha_hash = hex::encode(Sha256::digest(dashed.as_bytes()));
    let sha_compact_hash = hex::encode(Sha256::digest(normalized_compact.as_bytes()));

    let mut matched_id: Option<i64> = None;
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, code_hash FROM recovery_codes WHERE user_id = ?1 AND COALESCE(used, 0) = 0",
    ) {
        if let Ok(rows) = stmt.query_map(params![user_id], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        }) {
            for row in rows.flatten() {
                let (id, stored_hash) = row;
                let trimmed_hash = stored_hash.trim();
                let salted_match = trimmed_hash
                    .strip_prefix("sha256:v1:")
                    .and_then(|v| v.split_once(':'))
                    .and_then(|(salt, hash)| hex::decode(salt).ok().map(|salt| (salt, hash)))
                    .is_some_and(|(salt, hash)| {
                        salt.len() == 16
                            && af_services::cluster_daemon::constant_time_eq(
                                recovery_hash(&salt, &normalized_compact).as_bytes(),
                                hash.as_bytes(),
                            )
                    });
                let is_match = salted_match
                    || trimmed_hash.eq_ignore_ascii_case(&sha_hash)
                    || trimmed_hash.eq_ignore_ascii_case(&sha_compact_hash)
                    || (trimmed_hash.starts_with("$2")
                        && (bcrypt::verify(&dashed, trimmed_hash).unwrap_or(false)
                            || bcrypt::verify(&normalized_compact, trimmed_hash).unwrap_or(false)));
                if is_match {
                    matched_id = Some(id);
                    break;
                }
            }
        }
    }

    if let Some(id) = matched_id {
        return matches!(conn.execute(
            "UPDATE recovery_codes SET used = 1 WHERE id = ?1 AND user_id = ?2 AND COALESCE(used, 0) = 0",
            params![id, user_id],
        ), Ok(1));
    }
    false
}

pub async fn setup_2fa(req: Request) -> Response {
    blocking_response(move || setup_2fa_blocking(req)).await
}

fn setup_2fa_blocking(req: Request) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };

    let enabled: bool = conn
        .query_row(
            "SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
            params![auth_user.user_id],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if enabled {
        return api_error(
            StatusCode::CONFLICT,
            "CONFLICT",
            "Two-factor authentication is already enabled",
        );
    }

    let mut raw_secret = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut raw_secret);
    let secret = BASE32_NOPAD.encode(&raw_secret);
    af_db::store_2fa_pending(auth_user.user_id, &secret, Duration::from_secs(300));

    let uri = format!(
        "otpauth://totp/AetherFlow:{}?secret={}&issuer=AetherFlow&algorithm=SHA1&digits=6&period=30",
        urlencoding::encode(&auth_user.username),
        secret
    );

    Json(serde_json::json!({
        "otpauth_uri": uri,
        "secret": secret,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct CodeRequest {
    #[serde(default)]
    pub code: String,
}

#[derive(Deserialize, Default)]
pub struct Disable2FaRequest {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub password: String,
}

pub async fn verify_2fa(req: Request) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let bytes = match axum::body::to_bytes(req.into_body(), 4096).await {
        Ok(b) => b,
        Err(_) => return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid body"),
    };
    let Ok(payload) = serde_json::from_slice::<CodeRequest>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid JSON");
    };

    blocking_response(move || {
    if let Ok(conn) = af_db::get_read_conn() {
        let already_enabled: bool = conn
            .query_row(
                "SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
                params![auth_user.user_id],
                |r| r.get(0),
            )
            .unwrap_or(false);
        if already_enabled {
            af_db::delete_2fa_pending(auth_user.user_id);
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Two-factor authentication is already enabled",
            );
        }
    }
    let Some(secret) = af_db::get_2fa_pending(auth_user.user_id) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "No pending 2FA setup found",
        );
    };

    let Some(verified_step) = matching_totp_step(&secret, &payload.code, Utc::now().timestamp().max(0) as u64) else {
        return api_error(
            StatusCode::FORBIDDEN,
            "INVALID_2FA_CODE",
            "Invalid verification code",
        );
    };

    let Ok(enc_secret) = af_db::encrypt_key(&secret) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CRYPTO_ERROR",
            "Failed to encrypt two-factor secret",
        );
    };
    let recovery_codes = generate_recovery_codes();
    let result = (|| -> Result<bool, anyhow::Error> {
        let conn = af_db::get_conn()?;
        let transaction = rusqlite::Transaction::new_unchecked(
            &conn,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let affected = transaction.execute(
            "UPDATE users SET totp_secret = ?1, totp_enabled = 1, last_totp_step = ?3 WHERE id = ?2 AND COALESCE(totp_enabled, 0) = 0",
            params![enc_secret, auth_user.user_id, verified_step],
        )?;
        if affected == 0 {
            let already_enabled: bool = transaction
                .query_row(
                    "SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
                    params![auth_user.user_id],
                    |r| r.get(0),
                )
                .unwrap_or(false);
            if already_enabled {
                return Ok(false);
            }
            anyhow::bail!("User missing");
        }
        store_recovery_codes(&transaction, auth_user.user_id, &recovery_codes)?;
        transaction.commit()?;
        Ok(true)
    })();
    match result {
        Ok(true) => {}
        Ok(false) => {
            af_db::delete_2fa_pending(auth_user.user_id);
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "Two-factor authentication is already enabled",
            );
        }
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to enable two-factor authentication",
            );
        }
    }
    af_db::delete_2fa_pending(auth_user.user_id);

    Json(serde_json::json!({
        "message": "Two-factor authentication enabled",
        "recovery_codes": recovery_codes,
    }))
    .into_response()
    }).await
}

pub async fn disable_2fa(req: Request) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let headers = req.headers().clone();
    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 4096).await else {
        return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid body");
    };
    let Ok(payload) = serde_json::from_slice::<Disable2FaRequest>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", "Invalid JSON");
    };
    if payload.code.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "A valid TOTP or recovery code is required",
        );
    }
    blocking_auth_work(move || {
        let Ok(conn) = af_db::get_conn() else {
            return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Database error");
        };
        let Ok((encrypted_secret, password_hash)) = conn.query_row(
            "SELECT COALESCE(totp_secret, ''), COALESCE(password_hash, '') FROM users WHERE id = ?1",
            params![auth_user.user_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ) else {
            return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "User not found");
        };
        drop(conn);
        let secret = if encrypted_secret.is_empty() {
            String::new()
        } else {
            match af_db::decrypt_key(&encrypted_secret) {
                Ok(s) => s,
                Err(_) => {
                    return api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "CRYPTO_ERROR",
                        "Failed to decrypt 2FA secret",
                    );
                }
            }
        };
        let password_ok = payload.password.is_empty()
            || (!password_hash.is_empty() && verify_password(&payload.password, &password_hash));
        let result = (|| -> anyhow::Result<Option<(String, Vec<String>)>> {
            let mut conn = af_db::get_conn()?;
            let transaction =
                conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let current: (String, String) = transaction.query_row(
                "SELECT COALESCE(totp_secret, ''), COALESCE(password_hash, '') FROM users WHERE id = ?1",
                params![auth_user.user_id], |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let current_secret = if current.0.is_empty() {
                String::new()
            } else {
                af_db::decrypt_key(&current.0)?
            };
            anyhow::ensure!(current_secret == secret && current.1 == password_hash, "Credentials changed");
            if !password_ok {
                return Ok(None);
            }
            if !consume_totp_code(&transaction, auth_user.user_id, &secret, &payload.code)
                && !validate_recovery_code(&transaction, auth_user.user_id, &payload.code)
            {
                return Ok(None);
            }
            let affected = transaction.execute(
                "UPDATE users SET totp_secret = '', totp_enabled = 0, last_totp_step = -1 WHERE id = ?1",
                params![auth_user.user_id],
            )?;
            anyhow::ensure!(affected == 1, "User not found");
            store_recovery_codes(&transaction, auth_user.user_id, &[])?;
            let (new_ver, revoked_jtis) =
                revoke_all_user_credentials_in_tx(&transaction, auth_user.user_id)?;
            let (new_token, _) = create_session_jwt_in_conn(
                &transaction,
                auth_user.user_id,
                &headers,
                Utc::now().timestamp(),
                None,
                new_ver,
            )?;
            transaction.commit()?;
            Ok(Some((new_token, revoked_jtis)))
        })();
        let (new_token, revoked_jtis) = match result {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                let err_code = if !payload.password.is_empty() && !password_ok {
                    "INVALID_CURRENT_PASSWORD"
                } else {
                    "INVALID_2FA_CODE"
                };
                return api_error(StatusCode::FORBIDDEN, err_code, "Invalid verification code or password");
            }
            Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Failed to disable two-factor authentication"),
        };
        finalize_user_credential_revocation(auth_user.user_id, &revoked_jtis);
        af_db::record_audit(
            auth_user.user_id, &auth_user.username, "totp_disable", "user",
            &auth_user.user_id.to_string(), "Two-factor authentication disabled", &ip, &ua,
        );
        let mut resp =
            Json(serde_json::json!({ "message": "Two-factor authentication disabled" }))
                .into_response();
        set_session_cookie(&mut resp, &new_token);
        resp
    }).await.unwrap_or_else(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Verification failed"))
}

#[derive(Deserialize)]
pub struct MfaVerifyRequest {
    #[serde(default)]
    pub mfa_token: String,
    #[serde(default)]
    pub code: String,
}

pub async fn mfa_login_verify(headers: HeaderMap, Json(req): Json<MfaVerifyRequest>) -> Response {
    blocking_response(move || mfa_login_verify_blocking(headers, req)).await
}

#[derive(Debug)]
enum MfaVerifyOutcome {
    Verified(User, Option<String>),
    Invalid,
    Suspended,
}

fn redeem_mfa_challenge_in_tx(
    transaction: rusqlite::Transaction<'_>,
    token: &str,
    code: &str,
    session_headers: Option<&HeaderMap>,
) -> anyhow::Result<MfaVerifyOutcome> {
    let Some((user_id, challenge_ver)) = af_db::begin_mfa_attempt_with_epoch(&transaction, token)?
    else {
        return Ok(MfaVerifyOutcome::Invalid);
    };
    let subj = match load_active_human_subject(&transaction, user_id) {
        Ok(subj) => subj,
        Err(SubjectStatusError::Suspended) => {
            let _ = transaction.execute(
                "DELETE FROM mfa_challenges WHERE token = ?1",
                params![token],
            );
            transaction.commit()?;
            return Ok(MfaVerifyOutcome::Suspended);
        }
        Err(SubjectStatusError::MissingOrPlugin) => {
            let _ = transaction.execute(
                "DELETE FROM mfa_challenges WHERE token = ?1",
                params![token],
            );
            transaction.commit()?;
            return Ok(MfaVerifyOutcome::Invalid);
        }
        Err(SubjectStatusError::DbError) => {
            anyhow::bail!("Failed to verify account status during MFA");
        }
    };
    if subj.sessions_revoked_after != challenge_ver {
        let _ = transaction.execute(
            "DELETE FROM mfa_challenges WHERE token = ?1",
            params![token],
        );
        transaction.commit()?;
        return Ok(MfaVerifyOutcome::Invalid);
    }
    let (user, encrypted): (User, String) = transaction.query_row(
        "SELECT id, username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user'), COALESCE(google_id, ''), COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0) FROM users WHERE id = ?1",
        params![user_id], |r| {
            let google_id: String = r.get(5)?;
            Ok((User { id: r.get(0)?, username: r.get(1)?, email: r.get(2)?, avatar_url: r.get(3)?, role: r.get(4)?, is_oauth: !google_id.is_empty(), google_id, totp_enabled: r.get(7)? }, r.get(6)?))
        },
    )?;
    let verified = user.totp_enabled
        && (af_db::decrypt_key(&encrypted)
            .ok()
            .is_some_and(|secret| consume_totp_code(&transaction, user_id, &secret, code))
            || validate_recovery_code(&transaction, user_id, code));
    if !verified {
        // Commit failed attempts, including the final allowed guess.
        transaction.execute(
            "DELETE FROM mfa_challenges WHERE token = ?1 AND attempts >= ?2",
            params![token, af_db::MAX_MFA_ATTEMPTS],
        )?;
        transaction.commit()?;
        return Ok(MfaVerifyOutcome::Invalid);
    }
    anyhow::ensure!(
        af_db::consume_mfa_challenge_with_epoch(&transaction, token, user_id, challenge_ver)?,
        "Challenge already consumed"
    );
    let session_token = if let Some(headers) = session_headers {
        let (jwt, _) = create_session_jwt_in_conn(
            &transaction,
            user.id,
            headers,
            Utc::now().timestamp(),
            None,
            challenge_ver,
        )?;
        if table_exists(&transaction, "login_history").unwrap_or(false) {
            let _ = transaction.execute(
                "INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?1, ?2, ?3)",
                params![
                    user.id,
                    extract_client_ip(headers),
                    headers
                        .get(header::USER_AGENT)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                ],
            );
        }
        Some(jwt)
    } else {
        None
    };
    transaction.commit()?;
    Ok(MfaVerifyOutcome::Verified(user, session_token))
}

#[cfg(test)]
fn verify_mfa_factor_outcome(
    conn: &rusqlite::Connection,
    token: &str,
    code: &str,
) -> anyhow::Result<MfaVerifyOutcome> {
    let transaction =
        rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    redeem_mfa_challenge_in_tx(transaction, token, code, None)
}

#[cfg(test)]
fn verify_mfa_factor(
    conn: &rusqlite::Connection,
    token: &str,
    code: &str,
) -> anyhow::Result<Option<User>> {
    match verify_mfa_factor_outcome(conn, token, code)? {
        MfaVerifyOutcome::Verified(user, _) => Ok(Some(user)),
        MfaVerifyOutcome::Invalid | MfaVerifyOutcome::Suspended => Ok(None),
    }
}

fn mfa_login_verify_blocking(headers: HeaderMap, req: MfaVerifyRequest) -> Response {
    let result = (|| -> anyhow::Result<MfaVerifyOutcome> {
        let mut conn = af_db::get_conn()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        redeem_mfa_challenge_in_tx(tx, &req.mfa_token, &req.code, Some(&headers))
    })();
    let (user, token_opt) = match result {
        Ok(MfaVerifyOutcome::Verified(user, token_opt)) => (user, token_opt),
        Ok(MfaVerifyOutcome::Suspended) => {
            return api_error(
                StatusCode::FORBIDDEN,
                "ACCOUNT_SUSPENDED",
                "Account is suspended",
            )
        }
        Ok(MfaVerifyOutcome::Invalid) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "INVALID_2FA_CODE",
                "Invalid code or expired MFA challenge",
            )
        }
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "MFA verification failed",
            )
        }
    };
    let Some(token) = token_opt else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create session",
        );
    };
    let mut resp =
        Json(serde_json::json!({ "message": "Login successful", "user": user })).into_response();
    set_session_cookie(&mut resp, &token);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn mfa_database() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, avatar_url TEXT, role TEXT, google_id TEXT, totp_secret TEXT, totp_enabled INTEGER, last_totp_step INTEGER DEFAULT -1, sessions_revoked_after INTEGER DEFAULT 0);
            INSERT INTO users VALUES (1, 'mfa-user', '', '', 'admin', '', 'JBSWY3DPEHPK3PXP', 1, -1, 0);
            CREATE TABLE mfa_challenges (token TEXT PRIMARY KEY, user_id INTEGER, credential_ver INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0, expires_at INTEGER);
            CREATE TABLE recovery_codes (id INTEGER PRIMARY KEY, user_id INTEGER, code_hash TEXT, used INTEGER DEFAULT 0);").unwrap();
        conn
    }

    fn totp_now() -> String {
        let bytes = BASE32_NOPAD.decode(b"JBSWY3DPEHPK3PXP").unwrap();
        totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &bytes, Utc::now().timestamp() as u64)
    }

    fn add_challenge(conn: &rusqlite::Connection, token: &str) {
        conn.execute(
            "INSERT INTO mfa_challenges (token, user_id, expires_at) VALUES (?1, 1, ?2)",
            params![token, Utc::now().timestamp() + 300],
        )
        .unwrap();
    }

    #[test]
    fn mfa_attempt_limit_consumption_and_totp_replay_are_enforced() {
        let conn = mfa_database();
        add_challenge(&conn, "exhausted");
        for _ in 0..5 {
            assert!(verify_mfa_factor(&conn, "exhausted", "invalid")
                .unwrap()
                .is_none());
        }
        assert!(verify_mfa_factor(&conn, "exhausted", &totp_now())
            .unwrap()
            .is_none());
        add_challenge(&conn, "first");
        add_challenge(&conn, "second");
        let code = totp_now();
        assert!(verify_mfa_factor(&conn, "first", &code).unwrap().is_some());
        assert!(verify_mfa_factor(&conn, "first", &code).unwrap().is_none());
        assert!(verify_mfa_factor(&conn, "second", &code).unwrap().is_none());
        assert!(!consume_totp_code(&conn, 1, "JBSWY3DPEHPK3PXP", &code));
        conn.execute(
            "UPDATE mfa_challenges SET expires_at = 0 WHERE token = 'second'",
            [],
        )
        .unwrap();
        assert!(verify_mfa_factor(&conn, "second", &code).unwrap().is_none());
    }

    #[test]
    fn mfa_recovery_codes_still_work_after_totp_and_are_consumed_atomically() {
        let conn = mfa_database();
        let codes = generate_recovery_codes();
        let tx = conn.unchecked_transaction().unwrap();
        store_recovery_codes(&tx, 1, &codes).unwrap();
        tx.commit().unwrap();
        add_challenge(&conn, "totp");
        add_challenge(&conn, "recovery");
        add_challenge(&conn, "replay");
        assert!(verify_mfa_factor(&conn, "totp", &totp_now())
            .unwrap()
            .is_some());
        assert!(
            verify_mfa_factor(&conn, "recovery", &codes[0].replace('-', "").to_lowercase())
                .unwrap()
                .is_some()
        );
        assert!(verify_mfa_factor(&conn, "replay", &codes[0])
            .unwrap()
            .is_none());
    }

    #[test]
    fn concurrent_mfa_redemption_allows_one_success_and_persists_replay_guard() {
        let path = std::env::temp_dir().join(format!("af-mfa-race-{}.sqlite", Uuid::new_v4()));
        let seed = mfa_database();
        let schema: Vec<String> = seed
            .prepare("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let conn = rusqlite::Connection::open(&path).unwrap();
        for sql in schema {
            conn.execute_batch(&sql).unwrap();
        }
        conn.execute("INSERT INTO users VALUES (1, 'mfa-user', '', '', 'admin', '', 'JBSWY3DPEHPK3PXP', 1, -1, 0)", []).unwrap();
        add_challenge(&conn, "shared");
        add_challenge(&conn, "later");
        drop(conn);
        let code = totp_now();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let code = code.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let conn = rusqlite::Connection::open(path).unwrap();
                    conn.busy_timeout(Duration::from_secs(2)).unwrap();
                    barrier.wait();
                    verify_mfa_factor(&conn, "shared", &code).unwrap().is_some()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum::<usize>(),
            1
        );
        let reopened = rusqlite::Connection::open(&path).unwrap();
        assert!(verify_mfa_factor(&reopened, "later", &code)
            .unwrap()
            .is_none());
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn refresh_rejects_absolute_expiry_even_with_a_fresh_exp() {
        let now = Utc::now().timestamp();
        let claims = SessionClaims {
            user_id: 1,
            sub: "1".into(),
            iss: "aetherflow".into(),
            iat: now,
            auth_time: now - SESSION_ABSOLUTE_LIFETIME - 1,
            exp: now + 900,
            jti: Uuid::new_v4().to_string(),
            cfp: String::new(),
            ver: 0,
            plugin_id: String::new(),
            plugin_scopes: Vec::new(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&jwt_secret_bytes()),
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("aetherflow_session={token}").parse().unwrap(),
        );
        assert_eq!(
            refresh_session(headers).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let mut legacy = claims.clone();
        legacy.auth_time = 0;
        legacy.iat = now - SESSION_ABSOLUTE_LIFETIME - 1;
        assert!(!session_within_absolute_lifetime(&legacy, now));
        legacy.iat = now - 100;
        assert!(session_within_absolute_lifetime(&legacy, now));
    }

    #[tokio::test]
    async fn nested_refresh_suffixes_require_authentication_and_csrf() {
        use axum::{middleware, routing::post, Router};
        use tower::ServiceExt;
        for path in [
            "/api/v1/plugins/x/proxy/auth/refresh",
            "/plugins/x/proxy/auth/refresh",
            "/refresh",
        ] {
            let app = Router::new()
                .route(path, post(|| async { StatusCode::OK }))
                .layer(middleware::from_fn(auth_middleware));
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap();
            assert_eq!(
                app.oneshot(req).await.unwrap().status(),
                StatusCode::UNAUTHORIZED
            );
            let app = Router::new()
                .route(path, post(|| async { StatusCode::OK }))
                .layer(middleware::from_fn(csrf_middleware));
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .header(header::COOKIE, "aetherflow_session=test")
                .body(axum::body::Body::empty())
                .unwrap();
            assert_eq!(
                app.oneshot(req).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
        for path in [
            "/api/v1/auth/refresh",
            "/api/v1/public/auth/refresh",
            "/api/auth/refresh",
            "/api/public/auth/refresh",
        ] {
            let app = Router::new()
                .route(path, post(|| async { StatusCode::OK }))
                .layer(middleware::from_fn(csrf_middleware))
                .layer(middleware::from_fn(auth_middleware));
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .body(axum::body::Body::empty())
                .unwrap();
            assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authentication_readers_and_runtime_progress_while_writer_is_held() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        use axum::{middleware, routing::get, Router};
        use tower::ServiceExt;
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (987, 'writer-test', 'user')",
            [],
        )
        .unwrap();
        drop(conn);
        let headers = HeaderMap::new();
        let (token, claims) = create_standard_jwt(987, &headers).unwrap();
        let writer = af_db::get_conn().unwrap();
        writer.execute_batch("BEGIN IMMEDIATE;").unwrap();
        let app = Router::new()
            .route("/protected", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(auth_middleware));
        let req = Request::builder()
            .uri("/protected")
            .header(header::COOKIE, format!("aetherflow_session={token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let started = Instant::now();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(500), app.oneshot(req))
                .await
                .unwrap()
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        let mut req = Request::new(axum::body::Body::empty());
        req.extensions_mut().insert(AuthUser {
            user_id: 987,
            username: "writer-test".into(),
            role: "user".into(),
            jti: claims.jti,
            plugin_id: None,
            plugin_scopes: Vec::new(),
        });
        let operation = tokio::spawn(logout(req));
        tokio::task::yield_now().await;
        let started = Instant::now();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "Blocked SQLite acquisition must not stall Tokio"
        );
        assert!(
            !operation.is_finished(),
            "Write operation remains queued until writer is released"
        );
        writer.execute_batch("ROLLBACK;").unwrap();
        drop(writer);
        assert_eq!(operation.await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authenticated_wrong_2fa_code_is_forbidden_and_keeps_session() {
        af_db::store_2fa_pending(919, "JBSWY3DPEHPK3PXP", Duration::from_secs(300));
        let mut req = Request::new(axum::body::Body::from(r#"{"code":"invalid"}"#));
        req.extensions_mut().insert(AuthUser {
            user_id: 919,
            username: "setup-factor".into(),
            role: "user".into(),
            jti: "current-session".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        });
        let response = verify_2fa(req).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["code"], "INVALID_2FA_CODE");
    }

    #[tokio::test]
    async fn mfa_endpoint_race_issues_one_session_and_refresh_retains_original_auth_time() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let conn = af_db::get_conn().unwrap();
        conn.execute("INSERT INTO users (id, username, role, totp_enabled, totp_secret) VALUES (988, 'mfa-race', 'user', 1, 'JBSWY3DPEHPK3PXP')", []).unwrap();
        drop(conn);
        af_db::store_mfa_challenge("single-challenge", 988, Duration::from_secs(300)).unwrap();
        let code = totp_now();
        let (a, b) = tokio::join!(
            mfa_login_verify(
                HeaderMap::new(),
                Json(MfaVerifyRequest {
                    mfa_token: "single-challenge".into(),
                    code: code.clone()
                })
            ),
            mfa_login_verify(
                HeaderMap::new(),
                Json(MfaVerifyRequest {
                    mfa_token: "single-challenge".into(),
                    code
                })
            )
        );
        assert_eq!(
            [a.status(), b.status()]
                .into_iter()
                .filter(|status| *status == StatusCode::OK)
                .count(),
            1
        );
        let conn = af_db::get_read_conn().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM active_sessions WHERE user_id = 988",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        drop(conn);
        let original_time = Utc::now().timestamp() - 86400;
        let (old_token, _) = create_session_jwt(988, &HeaderMap::new(), original_time).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("aetherflow_session={old_token}").parse().unwrap(),
        );
        let response = refresh_session(headers.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let new_token = value["token"].as_str().unwrap();
        let claims = decode_session_claims(new_token, false).unwrap();
        assert_eq!(claims.auth_time, original_time);
        // Force a revocation query failure while a rotation-grace entry exists.
        let old_claims = decode_session_claims(&old_token, true).unwrap();
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE revoked_tokens", []).unwrap();
        drop(conn);
        // Use another token JTI for the grace case to bypass the intentional in-memory blacklist fast path.
        let mut failure_claims = old_claims;
        failure_claims.jti = Uuid::new_v4().to_string();
        ROTATED_TOKEN_GRACE.lock().unwrap().insert(
            failure_claims.jti.clone(),
            RotatedTokenGraceEntry {
                user_id: 988,
                family_id: failure_claims.jti.clone(),
                successor_jti: claims.jti.clone(),
                new_token: new_token.into(),
                successor_exp: claims.exp,
                strict_fp: String::new(),
                expires_at: Instant::now() + ROTATED_TOKEN_GRACE_WINDOW,
            },
        );
        let failure_token = encode(
            &Header::new(Algorithm::HS256),
            &failure_claims,
            &EncodingKey::from_secret(&jwt_secret_bytes()),
        )
        .unwrap();
        headers.insert(
            header::COOKIE,
            format!("aetherflow_session={failure_token}")
                .parse()
                .unwrap(),
        );
        assert_eq!(
            refresh_session(headers).await.status(),
            StatusCode::UNAUTHORIZED,
            "DB errors must fail closed even during rotation grace"
        );
    }

    fn recovery_database() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, totp_recovery_codes TEXT);
             INSERT INTO users VALUES (1, '[\"old-plaintext\"]');
             CREATE TABLE recovery_codes (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, code_hash TEXT NOT NULL, used INTEGER DEFAULT 0);",
        ).unwrap();
        conn
    }

    #[test]
    fn recovery_codes_are_hashed_normalized_and_single_use() {
        let conn = recovery_database();
        let codes = generate_recovery_codes();
        assert_eq!(codes.len(), 8);
        let transaction = conn.unchecked_transaction().unwrap();
        store_recovery_codes(&transaction, 1, &codes).unwrap();
        transaction.commit().unwrap();
        let legacy: String = conn
            .query_row(
                "SELECT totp_recovery_codes FROM users WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy, "[]");
        let hash: String = conn
            .query_row("SELECT code_hash FROM recovery_codes LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(hash.starts_with("sha256:v1:"));
        assert!(!codes.contains(&hash));
        assert!(!validate_recovery_code(&conn, 2, &codes[0]));
        assert!(validate_recovery_code(
            &conn,
            1,
            &codes[0].replace('-', "").to_lowercase()
        ));
        assert!(!validate_recovery_code(&conn, 1, &codes[0]));
    }

    #[test]
    fn recovery_replacement_rolls_back_and_consumption_fails_closed() {
        let conn = recovery_database();
        conn.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (1, 'old-hash')",
            [],
        )
        .unwrap();
        conn.execute_batch("CREATE TRIGGER reject_insert BEFORE INSERT ON recovery_codes BEGIN SELECT RAISE(ABORT, 'test failure'); END;").unwrap();
        {
            let transaction = conn.unchecked_transaction().unwrap();
            assert!(store_recovery_codes(&transaction, 1, &generate_recovery_codes()).is_err());
        }
        let hash: String = conn
            .query_row("SELECT code_hash FROM recovery_codes", [], |row| row.get(0))
            .unwrap();
        assert_eq!(hash, "old-hash");
        conn.execute_batch("DROP TRIGGER reject_insert; DELETE FROM recovery_codes;")
            .unwrap();
        let legacy_hash = hex::encode(Sha256::digest(b"ABCD-EFGH"));
        conn.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (1, ?1)",
            params![legacy_hash],
        )
        .unwrap();
        conn.execute_batch("CREATE TRIGGER reject_consume BEFORE UPDATE ON recovery_codes BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(!validate_recovery_code(&conn, 1, "abcdefgh"));
        conn.execute_batch("DROP TRIGGER reject_consume;").unwrap();
        assert!(validate_recovery_code(&conn, 1, "abcdefgh"));
        conn.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (1, 'ABCD-EFGH')",
            [],
        )
        .unwrap();
        assert!(!validate_recovery_code(&conn, 1, "ABCD-EFGH"));
    }

    #[test]
    fn legacy_bcrypt_recovery_codes_remain_usable() {
        let conn = recovery_database();
        let hash = bcrypt::hash("ABCD-EFGH", 4).unwrap();
        conn.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (1, ?1)",
            params![hash],
        )
        .unwrap();
        assert!(validate_recovery_code(&conn, 1, "abcdefgh"));
        assert!(!validate_recovery_code(&conn, 1, "ABCD-EFGH"));
    }

    #[tokio::test]
    async fn disable_2fa_rejects_missing_or_malformed_verification() {
        for body in ["", "{}", "{", "null", "{\"code\":\" \",\"password\":\"\"}"] {
            let mut req = Request::new(axum::body::Body::from(body.to_owned()));
            req.extensions_mut().insert(AuthUser {
                user_id: 1,
                username: "test".into(),
                role: "user".into(),
                jti: "test".into(),
                plugin_id: None,
                plugin_scopes: Vec::new(),
            });
            assert_eq!(disable_2fa(req).await.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn proxy_auth_rejects_revocation_and_fingerprint_mismatch() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO users (id, username, password_hash, role) VALUES (1, 'proxy-test-user', 'hash', 'user')",
                [],
            )
            .unwrap();
        }
        for revoked in [false, true] {
            let now = Utc::now().timestamp();
            let claims = SessionClaims {
                user_id: 1,
                sub: "1".into(),
                iss: "aetherflow".into(),
                iat: now,
                auth_time: now,
                exp: now + 900,
                jti: Uuid::new_v4().to_string(),
                cfp: client_fingerprint("original-agent"),
                ver: 0,
                plugin_id: String::new(),
                plugin_scopes: Vec::new(),
            };
            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(&jwt_secret_bytes()),
            )
            .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
            headers.insert(
                header::USER_AGENT,
                HeaderValue::from_static(if revoked {
                    "original-agent"
                } else {
                    "different-agent"
                }),
            );
            if revoked {
                af_db::revoke_token(&claims.jti, MIN_REVOCATION_TTL).unwrap();
            }
            assert_eq!(
                verify_proxy_auth(headers).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[tokio::test]
    async fn legacy_plugin_session_denies_destructive_http_capabilities() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        use axum::{
            body::Body,
            middleware,
            routing::{get, post},
            Router,
        };
        use tower::ServiceExt;
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let app = Router::new()
            .route(
                "/api/v1/admin/packages/fixture/uninstall",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/api/v1/admin/services/fixture/control",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/api/v1/admin/system/update/run",
                post(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/api/v1/auth/system/metrics",
                get(|| async { StatusCode::NO_CONTENT }),
            )
            .layer(middleware::from_fn(auth_middleware));
        for path in [
            "/api/v1/admin/packages/fixture/uninstall",
            "/api/v1/admin/services/fixture/control",
            "/api/v1/admin/system/update/run",
            "/api/v1/auth/system/metrics",
        ] {
            let now = Utc::now().timestamp();
            let claims = SessionClaims {
                user_id: 1,
                sub: "1".into(),
                iss: "aetherflow".into(),
                iat: now,
                auth_time: now,
                exp: now + 600,
                jti: Uuid::new_v4().to_string(),
                cfp: String::new(),
                ver: 0,
                plugin_id: "fixture".into(),
                plugin_scopes: vec![path.into()],
            };
            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(&jwt_secret_bytes()),
            )
            .unwrap();
            let read = path.ends_with("metrics");
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(if read { "GET" } else { "POST" })
                        .uri(path)
                        .header(header::AUTHORIZATION, format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if read {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::FORBIDDEN
                },
                "{path}"
            );
        }
    }

    #[test]
    fn mint_plugin_jwt_encodes_plugin_id_and_scopes() {
        let scopes = vec![
            "/api/v1/public/marketplace".to_string(),
            "/api/v1/auth/system/metrics".to_string(),
        ];
        let (token, claims) = mint_plugin_jwt(1, "sdk-template-rust", &scopes, 600).unwrap();
        assert_eq!(claims.plugin_id, "sdk-template-rust");
        assert_eq!(claims.plugin_scopes, scopes);
        assert!(decode_session_claims(&token, false).is_err());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_aud = false;
        let decoded = decode::<SessionClaims>(
            &token,
            &DecodingKey::from_secret(&jwt_secret_bytes()),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(decoded.plugin_id, "sdk-template-rust");
        assert_eq!(decoded.plugin_scopes, scopes);
        assert!(af_services::plugins::verify_plugin_route_scope(
            &decoded.plugin_scopes,
            "/api/v1/auth/system/metrics"
        ));
        assert!(!af_services::plugins::verify_plugin_route_scope(
            &decoded.plugin_scopes,
            "/api/v1/admin/users"
        ));
    }

    #[test]
    fn session_prefix_lookup_is_literal_unambiguous_and_user_scoped() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE active_sessions (jti TEXT, user_id INTEGER); INSERT INTO active_sessions VALUES ('abcdefgh-1', 1), ('abcdefgh-2', 1), ('abcdefgi-3', 2);").unwrap();
        let lookup = |prefix: &str| {
            conn.query_row(
            "SELECT MIN(jti) FROM active_sessions WHERE substr(jti, 1, length(?1)) = ?1 AND user_id = ?2 HAVING COUNT(*) = 1",
            params![prefix, 1], |row| row.get::<_, String>(0),
        )
        };
        assert!(lookup("________").is_err());
        assert!(lookup("%%%%%%%%").is_err());
        assert!(lookup("abcdefgh").is_err());
        assert!(lookup("abcdefgi").is_err());
        assert_eq!(lookup("abcdefgh-1").unwrap(), "abcdefgh-1");
    }

    #[tokio::test]
    async fn concurrent_refresh_is_single_winner_and_replay_after_grace_revokes_family() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO users (id, username, role) VALUES (991, 'refresh-race', 'user')",
                [],
            )
            .unwrap();
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static("race-agent"));
        let (seed_token, seed_claims) = create_standard_jwt(991, &headers).unwrap();
        headers.insert(
            header::COOKIE,
            format!("aetherflow_session={seed_token}").parse().unwrap(),
        );

        let (r1, r2) = tokio::join!(refresh_session(headers.clone()), refresh_session(headers));
        assert_eq!(r1.status(), StatusCode::OK);
        assert_eq!(r2.status(), StatusCode::OK);
        let b1 = axum::body::to_bytes(r1.into_body(), 8192).await.unwrap();
        let b2 = axum::body::to_bytes(r2.into_body(), 8192).await.unwrap();
        let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
        let rotated_token = v1["token"].as_str().unwrap().to_string();
        assert_eq!(rotated_token, v2["token"].as_str().unwrap());

        let rotated_claims = decode_session_claims(&rotated_token, false).unwrap();
        {
            let conn = af_db::get_read_conn().unwrap();
            let active_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM active_sessions WHERE user_id = 991",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(active_count, 1);
        }

        // Expire grace and replay the already-consumed seed token: family must be wiped.
        ROTATED_TOKEN_GRACE.lock().unwrap().remove(&seed_claims.jti);
        let mut replay_headers = HeaderMap::new();
        replay_headers.insert(header::USER_AGENT, HeaderValue::from_static("race-agent"));
        replay_headers.insert(
            header::COOKIE,
            format!("aetherflow_session={seed_token}").parse().unwrap(),
        );
        assert_eq!(
            refresh_session(replay_headers).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(af_db::is_token_revoked(&rotated_claims.jti));
        let conn = af_db::get_read_conn().unwrap();
        let remaining: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM active_sessions WHERE user_id = 991",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn disable_2fa_and_logout_revoke_concurrent_credentials_and_rotate_epoch() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let pw_hash = bcrypt::hash("correct-horse-battery", 4).unwrap();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, totp_enabled, totp_secret) \
                 VALUES (992, 'epoch-user', ?1, 'admin', 1, 'JBSWY3DPEHPK3PXP')",
                params![pw_hash],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO oidc_clients (id, name, client_secret_hash, redirect_uris) VALUES ('c1', 'App', 'h', '[]')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at, revoked, family_id) \
                 VALUES ('rt-epoch-1', 'c1', 992, 'openid', '2099-01-01T00:00:00Z', 0, 'fam-1')",
                [],
            )
            .unwrap();
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static("epoch-agent"));
        let (other_session, other_claims) = create_standard_jwt(992, &headers).unwrap();
        let (_, caller_claims) = create_standard_jwt(992, &headers).unwrap();

        let mut pw_only_req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/2fa/disable")
            .header(header::USER_AGENT, "epoch-agent")
            .body(axum::body::Body::from(
                r#"{"password":"correct-horse-battery"}"#,
            ))
            .unwrap();
        pw_only_req.extensions_mut().insert(AuthUser {
            user_id: 992,
            username: "epoch-user".into(),
            role: "admin".into(),
            jti: caller_claims.jti.clone(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        });
        assert_eq!(
            disable_2fa(pw_only_req).await.status(),
            StatusCode::BAD_REQUEST
        );

        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/2fa/disable")
            .header(header::USER_AGENT, "epoch-agent")
            .body(axum::body::Body::from(format!(
                r#"{{"password":"correct-horse-battery","code":"{}"}}"#,
                totp_now()
            )))
            .unwrap();
        req.extensions_mut().insert(AuthUser {
            user_id: 992,
            username: "epoch-user".into(),
            role: "admin".into(),
            jti: caller_claims.jti.clone(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        });
        let resp = disable_2fa(req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let set_cookie = resp.headers()[header::SET_COOKIE].to_str().unwrap();
        let replacement = set_cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("aetherflow_session=")
            .unwrap();
        let replacement_claims = decode_session_claims(replacement, false).unwrap();
        assert_eq!(replacement_claims.ver, 1);
        assert!(af_db::is_token_revoked(&other_claims.jti));

        // Concurrent old token fails auth_middleware even if forged without JTI blacklist hit.
        let mut old_headers = HeaderMap::new();
        old_headers.insert(header::USER_AGENT, HeaderValue::from_static("epoch-agent"));
        old_headers.insert(
            header::COOKIE,
            format!("aetherflow_session={other_session}")
                .parse()
                .unwrap(),
        );
        assert_eq!(
            refresh_session(old_headers).await.status(),
            StatusCode::UNAUTHORIZED
        );

        let conn = af_db::get_read_conn().unwrap();
        let rt_revoked: i64 = conn
            .query_row(
                "SELECT revoked FROM oidc_refresh_tokens WHERE token = 'rt-epoch-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rt_revoked, 1);
    }

    #[tokio::test]
    async fn suspended_accounts_return_forbidden_across_auth_surfaces() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        use axum::{middleware, routing::get, Router};
        use tower::ServiceExt;
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let pw_hash = bcrypt::hash("suspended-pass", 4).unwrap();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, totp_enabled, totp_secret) \
                 VALUES (993, 'suspended-user', ?1, 'user', 1, 'JBSWY3DPEHPK3PXP')",
                params![pw_hash],
            )
            .unwrap();
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static("susp-agent"));
        let (session_tok, _) = create_standard_jwt(993, &headers).unwrap();
        af_db::store_mfa_challenge("susp-mfa", 993, Duration::from_secs(300)).unwrap();

        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO user_quotas (user_id, username, status) VALUES (993, 'suspended-user', 'suspended')",
                [],
            )
            .unwrap();
        }

        // 1. local_login -> 403 FORBIDDEN
        let login_resp = local_login(
            headers.clone(),
            Json(CredentialsRequest {
                username: "suspended-user".into(),
                password: "suspended-pass".into(),
            }),
        )
        .await;
        assert_eq!(login_resp.status(), StatusCode::FORBIDDEN);

        // 2. auth_middleware -> 403 FORBIDDEN
        let app = Router::new()
            .route("/protected", get(|| async { StatusCode::OK }))
            .layer(middleware::from_fn(auth_middleware));
        let mw_resp = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header(header::USER_AGENT, "susp-agent")
                    .header(header::COOKIE, format!("aetherflow_session={session_tok}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mw_resp.status(), StatusCode::FORBIDDEN);

        // 3. refresh_session -> 403 FORBIDDEN
        let mut ref_headers = headers.clone();
        ref_headers.insert(
            header::COOKIE,
            format!("aetherflow_session={session_tok}").parse().unwrap(),
        );
        assert_eq!(
            refresh_session(ref_headers).await.status(),
            StatusCode::FORBIDDEN
        );

        // 4. mfa_login_verify -> 403 FORBIDDEN
        let mfa_resp = mfa_login_verify(
            headers,
            Json(MfaVerifyRequest {
                mfa_token: "susp-mfa".into(),
                code: totp_now(),
            }),
        )
        .await;
        assert_eq!(mfa_resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn round3_disable_2fa_requires_second_factor_and_mfa_epoch_invalidation() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        let pw_hash = bcrypt::hash("r3-strong-pass", 4).unwrap();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, totp_enabled, totp_secret, sessions_revoked_after) \
                 VALUES (994, 'r3-mfa-user', ?1, 'user', 1, 'JBSWY3DPEHPK3PXP', 50)",
                params![pw_hash],
            )
            .unwrap();
        }

        // 1. disable_2fa with password only (no second-factor `code`) MUST return 400 BAD_REQUEST
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/2fa/disable")
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(r#"{"password":"r3-strong-pass"}"#))
            .unwrap();
        req.extensions_mut().insert(AuthUser {
            user_id: 994,
            username: "r3-mfa-user".into(),
            role: "user".into(),
            jti: "jti-994".into(),
            plugin_id: None,
            plugin_scopes: vec![],
        });
        let disable_resp = disable_2fa(req).await;
        assert_eq!(disable_resp.status(), StatusCode::BAD_REQUEST);

        // 2. Pending MFA challenge issued at epoch 50 MUST fail after sessions_revoked_after advances to 60
        {
            let conn = af_db::get_conn().unwrap();
            af_db::store_mfa_challenge_in_tx(
                &conn,
                "r3-epoch-mfa",
                994,
                50,
                Duration::from_secs(300),
            )
            .unwrap();
            conn.execute(
                "UPDATE users SET sessions_revoked_after = 60 WHERE id = 994",
                [],
            )
            .unwrap();
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, HeaderValue::from_static("r3-agent"));
        let epoch_resp = mfa_login_verify(
            headers,
            Json(MfaVerifyRequest {
                mfa_token: "r3-epoch-mfa".into(),
                code: totp_now(),
            }),
        )
        .await;
        assert_eq!(epoch_resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn round6_chained_normal_rotation_preserves_grace_and_post_grace_replay_wipes_family() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, sessions_revoked_after) \
                 VALUES (996, 'r6-chain-user', 'hash', 'user', 0)",
                [],
            )
            .unwrap();
        }

        let mut base_headers = HeaderMap::new();
        base_headers.insert(header::USER_AGENT, HeaderValue::from_static("r6-chain-ua"));
        let (s0, s0_claims) = create_standard_jwt(996, &base_headers).unwrap();

        let do_refresh = |tok: String| async move {
            let mut h = HeaderMap::new();
            h.insert(header::USER_AGENT, HeaderValue::from_static("r6-chain-ua"));
            h.insert(
                header::COOKIE,
                format!("aetherflow_session={tok}").parse().unwrap(),
            );
            let resp = refresh_session(h).await;
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 16384).await.unwrap();
            let val: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            let next_tok = val["token"].as_str().unwrap_or("").to_string();
            (status, next_tok)
        };

        let (st1, s1) = do_refresh(s0.clone()).await;
        assert_eq!(st1, StatusCode::OK);
        assert!(!s1.is_empty());

        let (st2, s2) = do_refresh(s1.clone()).await;
        assert_eq!(st2, StatusCode::OK);
        assert!(!s2.is_empty());
        let s2_claims = decode_session_claims(&s2, false).unwrap();

        // In-flight refresh using ancestor s0 within 15s grace MUST return active leaf s2 (not wipe family)
        let (st_grace, s_grace) = do_refresh(s0.clone()).await;
        assert_eq!(st_grace, StatusCode::OK);
        assert_eq!(s_grace, s2);
        assert!(!is_session_token_revoked_beyond_grace(&s0_claims.jti, 996));
        assert!(!af_db::is_token_revoked(&s2_claims.jti));

        // Simulate restart / expired grace: replaying s0 MUST return 401 and wipe leaf s2
        ROTATED_TOKEN_GRACE.lock().unwrap().clear();
        ROTATED_SESSION_SUCCESSOR.lock().unwrap().clear();
        let (st_replay, _) = do_refresh(s0).await;
        assert_eq!(st_replay, StatusCode::UNAUTHORIZED);
        assert!(af_db::is_token_revoked(&s2_claims.jti));
    }

    #[tokio::test]
    async fn round8_verify_2fa_conflict_and_refresh_grace_strict_fingerprint_enforcement() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, totp_enabled, totp_secret, sessions_revoked_after) \
                 VALUES (997, 'r8-auth-user', 'hash', 'user', 1, 'JBSWY3DPEHPK3PXP', 0)",
                [],
            )
            .unwrap();
        }

        // 1. verify_2fa MUST return 409 CONFLICT when totp_enabled == 1
        let code = totp_now();
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/user/2fa/verify")
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(format!(r#"{{"code":"{code}"}}"#)))
            .unwrap();
        req.extensions_mut().insert(AuthUser {
            user_id: 997,
            username: "r8-auth-user".into(),
            role: "user".into(),
            jti: "jti-997".into(),
            plugin_id: None,
            plugin_scopes: vec![],
        });
        assert_eq!(verify_2fa(req).await.status(), StatusCode::CONFLICT);

        // 2. Within 10s grace, replaying rotated s0 from a DIFFERENT User-Agent MUST reject with 401
        //    and wipe the session family (`s1`).
        let mut h1 = HeaderMap::new();
        h1.insert(header::USER_AGENT, HeaderValue::from_static("r8-legit-ua"));
        let (s0, _) = create_standard_jwt(997, &h1).unwrap();
        h1.insert(
            header::COOKIE,
            format!("aetherflow_session={s0}").parse().unwrap(),
        );
        let resp1 = refresh_session(h1).await;
        assert_eq!(resp1.status(), StatusCode::OK);
        let b1 = axum::body::to_bytes(resp1.into_body(), 16384)
            .await
            .unwrap();
        let v1: serde_json::Value = serde_json::from_slice(&b1).unwrap();
        let s1 = v1["token"].as_str().unwrap().to_string();
        let s1_claims = decode_session_claims(&s1, false).unwrap();

        let mut h_mismatch = HeaderMap::new();
        h_mismatch.insert(
            header::USER_AGENT,
            HeaderValue::from_static("r8-different-ua"),
        );
        h_mismatch.insert(
            header::COOKIE,
            format!("aetherflow_session={s0}").parse().unwrap(),
        );
        let resp_mismatch = refresh_session(h_mismatch).await;
        assert_eq!(resp_mismatch.status(), StatusCode::UNAUTHORIZED);
        assert!(af_db::is_token_revoked(&s1_claims.jti));
    }
}
