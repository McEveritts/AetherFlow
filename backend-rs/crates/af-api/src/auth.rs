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
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
    pub user_id: i64,
    pub sub: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    #[serde(default)]
    pub cfp: String,
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub jti: String,
}

#[derive(Clone)]
struct RotatedTokenGraceEntry {
    user_id: i64,
    new_token: String,
    expires_at: Instant,
}

static ROTATED_TOKEN_GRACE: Lazy<Mutex<HashMap<String, RotatedTokenGraceEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const SESSION_COOKIE_MAX_AGE: i64 = 86400;

pub fn secure_cookie_enabled() -> bool {
    env::var("COOKIE_SECURE")
        .map(|v| v.to_lowercase() != "false")
        .unwrap_or(true)
}

pub fn jwt_secret_bytes() -> Vec<u8> {
    let secret = env::var("JWT_SECRET").unwrap_or_default();
    if secret.is_empty() {
        b"dev-fallback-jwt-secret-32-bytes!".to_vec()
    } else {
        secret.into_bytes()
    }
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
    let now = Utc::now().timestamp();
    let exp = now + 900; // 15 minutes
    let jti = Uuid::new_v4().to_string();
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
        exp,
        jti: jti.clone(),
        cfp,
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&jwt_secret_bytes()),
    )?;

    if let Ok(conn) = af_db::get_conn() {
        let exp_rfc3339 = (Utc::now() + chrono::Duration::seconds(900)).to_rfc3339();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, last_active) \
             VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)",
            params![jti, user_id, ip, ua, exp_rfc3339],
        );
    }

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
    Ok(data.claims)
}

fn check_rotation_grace(jti: &str) -> Option<(i64, String)> {
    let mut map = ROTATED_TOKEN_GRACE.lock().ok()?;
    map.retain(|_, v| v.expires_at > Instant::now());
    map.get(jti).map(|e| (e.user_id, e.new_token.clone()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth, Admin & CSRF Middlewares (`auth.go` & `csrf.go`)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn auth_middleware(mut req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path.ends_with("/auth/refresh") {
        return next.run(req).await;
    }

    let headers = req.headers();
    let Some(token) = resolve_raw_token(headers) else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };

    let Ok(claims) = decode_session_claims(&token, false) else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };

    if af_db::is_token_revoked(&claims.jti) && check_rotation_grace(&claims.jti).is_none() {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_EXPIRED",
            "Session revoked",
        );
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

    let user_row = af_db::get_conn().ok().and_then(|conn| {
        conn.query_row(
            "SELECT username, role FROM users WHERE id = ?1",
            params![claims.user_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .ok()
    });

    let Some((username, role)) = user_row else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };

    req.extensions_mut().insert(AuthUser {
        user_id: claims.user_id,
        username,
        role,
        jti: claims.jti,
    });

    next.run(req).await
}

pub async fn admin_only_middleware(req: Request, next: Next) -> Response {
    let is_admin = req
        .extensions()
        .get::<AuthUser>()
        .map(|u| u.role == "admin")
        .unwrap_or(false);
    if !is_admin {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Admin access required",
        );
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
    if !matches!(method, Method::POST | Method::PUT | Method::DELETE) {
        return next.run(req).await;
    }

    let path = req.uri().path();
    if path.ends_with("/auth/refresh") {
        return next.run(req).await;
    }

    let headers = req.headers();
    // Bearer token requests are exempt from cookie CSRF check
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.starts_with("Bearer "))
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
    let Ok(conn) = af_db::get_conn() else {
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

pub async fn setup_admin(
    headers: HeaderMap,
    Json(req): Json<CredentialsRequest>,
) -> Response {
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

    if req.username.trim().is_empty() || req.password.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Username and password are required",
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
            params![req.username.trim(), hash],
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
        "username": req.username.trim(),
    }))
    .into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn local_login(
    headers: HeaderMap,
    Json(req): Json<CredentialsRequest>,
) -> Response {
    if req.username.trim().is_empty() || req.password.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Username and password are required",
        );
    }

    let Ok(conn) = af_db::get_conn() else {
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
        params![req.username.trim()],
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

    let Ok((id, username, email, avatar_url, role, password_hash, google_id, totp_enabled)) = row
    else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid username or password",
        );
    };

    if password_hash.is_empty() {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "This account uses Google OAuth. Use the Google login button.",
        );
    }

    if !bcrypt::verify(&req.password, &password_hash).unwrap_or(false) {
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
        af_db::store_mfa_challenge(&mfa_token, id, Duration::from_secs(300));
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
    let _ = conn.execute(
        "INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?1, ?2, ?3)",
        params![id, client_ip, user_agent],
    );

    let Ok((token, _)) = create_standard_jwt(id, &headers) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create session",
        );
    };

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
    if let Some(auth_user) = req.extensions().get::<AuthUser>() {
        af_db::revoke_token(&auth_user.jti, Duration::from_secs(900));
        if let Ok(mut grace) = ROTATED_TOKEN_GRACE.lock() {
            grace.remove(&auth_user.jti);
        }
    }
    let cookie = build_set_cookie(
        "aetherflow_session",
        "",
        -1,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    let mut resp = Json(serde_json::json!({ "message": "Logged out" })).into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn refresh_session(headers: HeaderMap) -> Response {
    let Some(raw_token) = resolve_raw_token(&headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "No session token provided",
        );
    };

    let Ok(claims) = decode_session_claims(&raw_token, true) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid session token",
        );
    };

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
    let ip = extract_client_ip(&headers);
    if !matches_client_fingerprint(&claims.cfp, &ip, ua) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Client fingerprint mismatch",
        );
    }

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };

    let Ok((id, username, role)) = conn.query_row(
        "SELECT id, username, role FROM users WHERE id = ?1",
        params![claims.user_id],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
    ) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "User no longer exists",
        );
    };

    if af_db::is_token_revoked(&claims.jti) {
        if let Some((_, existing_new_token)) = check_rotation_grace(&claims.jti) {
            let cookie = build_set_cookie(
                "aetherflow_session",
                &existing_new_token,
                SESSION_COOKIE_MAX_AGE,
                "Lax",
                secure_cookie_enabled(),
                true,
            );
            let mut resp = Json(serde_json::json!({
                "status": "success",
                "token": existing_new_token,
                "expires_at": now + 900,
                "user": { "id": id, "username": username, "role": role }
            }))
            .into_response();
            if let Ok(hv) = HeaderValue::from_str(&cookie) {
                resp.headers_mut().insert(header::SET_COOKIE, hv);
            }
            return resp;
        }
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Session has been revoked",
        );
    }

    af_db::revoke_token(&claims.jti, Duration::from_secs(900));
    let Ok((new_token, new_claims)) = create_standard_jwt(id, &headers) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to rotate token",
        );
    };

    if let Ok(mut grace) = ROTATED_TOKEN_GRACE.lock() {
        grace.insert(
            claims.jti,
            RotatedTokenGraceEntry {
                user_id: id,
                new_token: new_token.clone(),
                expires_at: Instant::now() + Duration::from_secs(15),
            },
        );
    }

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
        "user": { "id": id, "username": username, "role": role }
    }))
    .into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn verify_proxy_auth(headers: HeaderMap) -> Response {
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
    let Ok(conn) = af_db::get_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Internal validation error" })),
        )
            .into_response();
    };
    let Ok(username) = conn.query_row(
        "SELECT username FROM users WHERE id = ?1",
        params![claims.user_id],
        |r| r.get::<_, String>(0),
    ) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "User no longer exists" })),
        )
            .into_response();
    };

    let mut resp = StatusCode::OK.into_response();
    if let Ok(hv) = HeaderValue::from_str(&username) {
        resp.headers_mut().insert("X-Aetherflow-User", hv.clone());
        resp.headers_mut().insert("Remote-User", hv);
    }
    resp
}

pub async fn list_active_sessions(req: Request) -> Response {
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
        "DELETE FROM active_sessions WHERE expires_at < CURRENT_TIMESTAMP",
        [],
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

    let mut sessions = Vec::new();
    if let Ok(rows) = stmt.query_map(params![auth_user.user_id], |r| {
        let full_jti: String = r.get(0)?;
        let is_current = full_jti == auth_user.jti;
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

pub async fn revoke_session(
    Path(jti_param): Path<String>,
    req: Request,
) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let prefix = jti_param.trim_end_matches("...");
    if prefix.len() < 8 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid session identifier",
        );
    }
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };
    let pattern = format!("{}%", prefix);
    let Ok(full_jti) = conn.query_row(
        "SELECT jti FROM active_sessions WHERE jti LIKE ?1 AND user_id = ?2",
        params![pattern, auth_user.user_id],
        |r| r.get::<_, String>(0),
    ) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Session not found");
    };

    af_db::revoke_token(&full_jti, Duration::from_secs(900));
    Json(serde_json::json!({ "message": "Session revoked" })).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 2FA TOTP Setup, Verification & MFA Login (`backend/api/totp.go`)
// ─────────────────────────────────────────────────────────────────────────────

fn verify_totp_code(secret_b32: &str, code: &str) -> bool {
    let clean = secret_b32.trim().to_uppercase();
    let Ok(secret_bytes) = BASE32_NOPAD.decode(clean.as_bytes()) else {
        return false;
    };
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for offset in [0i64, -30i64, 30i64] {
        let ts = (now_secs as i64 + offset).max(0) as u64;
        let expected = totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &secret_bytes, ts);
        if expected == code.trim() {
            return true;
        }
    }
    false
}

fn generate_recovery_codes(user_id: i64) -> Vec<String> {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut codes = Vec::with_capacity(8);
    let Ok(conn) = af_db::get_conn() else {
        return codes;
    };
    let _ = conn.execute("DELETE FROM recovery_codes WHERE user_id = ?1", params![user_id]);

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
        if let Ok(hash) = bcrypt::hash(&code, bcrypt::DEFAULT_COST) {
            let _ = conn.execute(
                "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)",
                params![user_id, hash],
            );
        }
        codes.push(code);
    }
    codes
}

pub async fn setup_2fa(req: Request) -> Response {
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

pub async fn verify_2fa(
    req: Request,
) -> Response {
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

    let Some(secret) = af_db::get_2fa_pending(auth_user.user_id) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "No pending 2FA setup found",
        );
    };

    if !verify_totp_code(&secret, &payload.code) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid verification code",
        );
    }

    let enc_secret = af_db::encrypt_key(&secret).unwrap_or(secret);
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE users SET totp_secret = ?1, totp_enabled = 1 WHERE id = ?2",
            params![enc_secret, auth_user.user_id],
        );
    }
    af_db::delete_2fa_pending(auth_user.user_id);
    let recovery_codes = generate_recovery_codes(auth_user.user_id);

    Json(serde_json::json!({
        "message": "Two-factor authentication enabled",
        "recovery_codes": recovery_codes,
    }))
    .into_response()
}

pub async fn disable_2fa(req: Request) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE users SET totp_secret = '', totp_enabled = 0 WHERE id = ?1",
            params![auth_user.user_id],
        );
        let _ = conn.execute(
            "DELETE FROM recovery_codes WHERE user_id = ?1",
            params![auth_user.user_id],
        );
    }
    Json(serde_json::json!({ "message": "Two-factor authentication disabled" })).into_response()
}

#[derive(Deserialize)]
pub struct MfaVerifyRequest {
    #[serde(default)]
    pub mfa_token: String,
    #[serde(default)]
    pub code: String,
}

pub async fn mfa_login_verify(
    headers: HeaderMap,
    Json(req): Json<MfaVerifyRequest>,
) -> Response {
    let Some(user_id) = af_db::get_mfa_challenge(&req.mfa_token) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid or expired MFA challenge",
        );
    };

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };

    let Ok((id, username, email, avatar_url, role, google_id, totp_secret_enc)) = conn.query_row(
        "SELECT id, username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user'), \
         COALESCE(google_id, ''), COALESCE(totp_secret, '') FROM users WHERE id = ?1",
        params![user_id],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        },
    ) else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "User not found");
    };

    let secret = af_db::decrypt_key(&totp_secret_enc).unwrap_or(totp_secret_enc);
    if !verify_totp_code(&secret, &req.code) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid verification code",
        );
    }

    af_db::delete_mfa_challenge(&req.mfa_token);
    let Ok((token, _)) = create_standard_jwt(id, &headers) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create session",
        );
    };

    let user = User {
        id,
        username,
        email,
        avatar_url,
        role,
        is_oauth: !google_id.is_empty(),
        google_id,
        totp_enabled: true,
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
