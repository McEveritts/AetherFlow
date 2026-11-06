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

#[derive(Clone)]
struct RotatedTokenGraceEntry {
    user_id: i64,
    new_token: String,
    expires_at: Instant,
}

static ROTATED_TOKEN_GRACE: Lazy<Mutex<HashMap<String, RotatedTokenGraceEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const SESSION_COOKIE_MAX_AGE: i64 = 86400;
const SESSION_ABSOLUTE_LIFETIME: i64 = 30 * 86400;

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

fn create_session_jwt(
    user_id: i64,
    headers: &HeaderMap,
    auth_time: i64,
) -> anyhow::Result<(String, SessionClaims)> {
    let now = Utc::now().timestamp();
    let absolute_exp = auth_time.saturating_add(SESSION_ABSOLUTE_LIFETIME);
    anyhow::ensure!(now < absolute_exp, "Absolute session lifetime exceeded");
    let exp = (now + 900).min(absolute_exp);
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
        auth_time,
        exp,
        jti: jti.clone(),
        cfp,
        plugin_id: String::new(),
        plugin_scopes: Vec::new(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(&jwt_secret_bytes()),
    )?;

    {
        let conn = af_db::get_conn()?;
        // Track the full refresh window; otherwise a still-refreshable session disappears from revocation UI.
        let exp_rfc3339 = chrono::DateTime::from_timestamp((exp + 7200).min(absolute_exp), 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid session expiry"))?
            .to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO active_sessions (jti, user_id, ip_address, user_agent, expires_at, last_active) \
             VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)",
            params![jti, user_id, ip, ua, exp_rfc3339],
        )?;
    }

    Ok((token, claims))
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

fn check_rotation_grace(jti: &str) -> Option<(i64, String)> {
    let mut map = ROTATED_TOKEN_GRACE.lock().ok()?;
    map.retain(|_, v| v.expires_at > Instant::now());
    map.get(jti).map(|e| (e.user_id, e.new_token.clone()))
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
    let revocation = blocking_auth_work(move || af_db::token_revocation_status(&jti)).await;
    let Ok(Ok(revoked)) = revocation else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_EXPIRED",
            "Unable to validate session",
        );
    };
    if revoked && check_rotation_grace(&claims.jti).is_none() {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_EXPIRED",
            "Session revoked",
        );
    }

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
    let user_row = blocking_auth_work(move || {
        af_db::get_read_conn().ok().and_then(|conn| {
            conn.query_row(
                "SELECT username, role FROM users WHERE id = ?1",
                params![uid],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .ok()
        })
    })
    .await
    .ok()
    .flatten();

    let Some((username, role)) = user_row else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };

    req.extensions_mut().insert(AuthUser {
        user_id: claims.user_id,
        username,
        role,
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
    blocking_response(move || check_setup_needed_blocking()).await
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

fn md5_hex(data: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    for chunk in msg.as_chunks::<64>().0 {
        let mut m = [0u32; 16];
        for (word_index, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            m[word_index] = u32::from_le_bytes(*word);
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            let added = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(added.rotate_left(S[i]));
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut digest = [0u8; 16];
    digest[0..4].copy_from_slice(&a0.to_le_bytes());
    digest[4..8].copy_from_slice(&b0.to_le_bytes());
    digest[8..12].copy_from_slice(&c0.to_le_bytes());
    digest[12..16].copy_from_slice(&d0.to_le_bytes());
    hex::encode(digest)
}

pub fn save_master_credentials(username: &str, password: &str) {
    let u = username.trim();
    if u.is_empty() || password.is_empty() {
        return;
    }
    let _ = af_services::mutators::save_master_credentials(u, password);
    let ha1_input = format!("{}:AetherFlow:{}", u, password);
    let ha1 = md5_hex(ha1_input.as_bytes());
    let payload = serde_json::json!({
        "username": u,
        "password": password,
        "ha1": ha1,
    });
    let Ok(mut raw) = serde_json::to_vec(&payload) else {
        return;
    };
    raw.push(b'\n');

    let default_paths = || {
        vec![
            af_services::mutators::resolve_config_path("/var/lib/aetherflow/.master.creds"),
            af_services::mutators::resolve_config_path(
                "/opt/AetherFlow/backend/data/.master.creds",
            ),
            std::path::PathBuf::from("backend/data/.master.creds"),
        ]
    };

    let paths: Vec<std::path::PathBuf> =
        if let Ok(custom) = env::var("AETHERFLOW_MASTER_CREDS_FILE") {
            let trimmed = custom.trim();
            if !trimmed.is_empty() {
                vec![std::path::PathBuf::from(trimmed)]
            } else {
                default_paths()
            }
        } else {
            default_paths()
        };

    for p in paths {
        if p.as_os_str().is_empty() {
            continue;
        }
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        if std::fs::write(&p, &raw).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
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
    drop(conn);

    save_master_credentials(req.username.trim(), &req.password);

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

pub async fn local_login(headers: HeaderMap, Json(req): Json<CredentialsRequest>) -> Response {
    blocking_response(move || local_login_blocking(headers, req)).await
}

fn local_login_blocking(headers: HeaderMap, req: CredentialsRequest) -> Response {
    if req.username.trim().is_empty() || req.password.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Username and password are required",
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

    if totp_enabled {
        let mut raw_token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw_token);
        let mfa_token = hex::encode(raw_token);
        if af_db::store_mfa_challenge(&mfa_token, id, Duration::from_secs(300)).is_err() {
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
    if let Ok(history_conn) = af_db::get_conn() {
        let _ = history_conn.execute(
            "INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?1, ?2, ?3)",
            params![id, client_ip, user_agent],
        );
    }

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
    if let Some(auth_user) = req.extensions().get::<AuthUser>() {
        // Keep revocation entry across the entire 15m JWT lifetime + 2h refresh grace window (8100s)
        af_db::revoke_token(&auth_user.jti, Duration::from_secs(8100));
        if let Ok(conn) = af_db::get_conn() {
            let _ = conn.execute(
                "DELETE FROM active_sessions WHERE jti = ?1",
                params![auth_user.jti],
            );
        }
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
    blocking_response(move || refresh_session_blocking(headers)).await
}

fn refresh_session_blocking(headers: HeaderMap) -> Response {
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
    let ip = extract_client_ip(&headers);
    if !matches_client_fingerprint(&claims.cfp, &ip, ua) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Client fingerprint mismatch",
        );
    }

    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };

    let Ok((id, username, role)) = conn.query_row(
        "SELECT id, username, role FROM users WHERE id = ?1",
        params![claims.user_id],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        },
    ) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "User no longer exists",
        );
    };

    drop(conn);

    let Ok(revoked) = af_db::token_revocation_status(&claims.jti) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_EXPIRED",
            "Unable to validate session",
        );
    };
    if revoked {
        if let Some((_, existing_new_token)) =
            check_rotation_grace(&claims.jti).filter(|(grace_user_id, _)| *grace_user_id == id)
        {
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

    let Ok((new_token, new_claims)) = create_session_jwt(id, &headers, session_auth_time(&claims))
    else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to rotate token",
        );
    };

    if let Ok(mut grace) = ROTATED_TOKEN_GRACE.lock() {
        grace.insert(
            claims.jti.clone(),
            RotatedTokenGraceEntry {
                user_id: id,
                new_token: new_token.clone(),
                expires_at: Instant::now() + Duration::from_secs(15),
            },
        );
    }

    af_db::revoke_token(&claims.jti, Duration::from_secs(900));

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
    if af_db::is_token_revoked(&claims.jti)
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
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database error",
        );
    };
    let Ok(full_jti) = conn.query_row(
        "SELECT MIN(jti) FROM active_sessions WHERE substr(jti, 1, length(?1)) = ?1 AND user_id = ?2 HAVING COUNT(*) = 1",
        params![prefix, auth_user.user_id],
        |r| r.get::<_, String>(0),
    ) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Session not found");
    };

    drop(conn);
    if let Ok(mut map) = ROTATED_TOKEN_GRACE.lock() {
        map.remove(&full_jti);
    }
    af_db::revoke_token(&full_jti, Duration::from_secs(900));
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

fn validate_recovery_code(conn: &rusqlite::Connection, user_id: i64, raw_code: &str) -> bool {
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

    let enc_secret = af_db::encrypt_key(&secret).unwrap_or(secret);
    let recovery_codes = generate_recovery_codes();
    let result = (|| -> anyhow::Result<()> {
        let conn = af_db::get_conn()?;
        let transaction = conn.unchecked_transaction()?;
        let affected = transaction.execute(
            "UPDATE users SET totp_secret = ?1, totp_enabled = 1, last_totp_step = ?3 WHERE id = ?2 AND COALESCE(totp_enabled, 0) = 0",
            params![enc_secret, auth_user.user_id, verified_step],
        )?;
        anyhow::ensure!(affected == 1, "User missing or 2FA already enabled");
        store_recovery_codes(&transaction, auth_user.user_id, &recovery_codes)?;
        transaction.commit()?;
        Ok(())
    })();
    if result.is_err() {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Failed to enable two-factor authentication");
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
    if payload.code.trim().is_empty() && payload.password.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Verification code or password required",
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
        let secret = af_db::decrypt_key(&encrypted_secret).unwrap_or(encrypted_secret);
        let password_verified = !payload.password.is_empty() && !password_hash.is_empty()
            && verify_password(&payload.password, &password_hash);
        let result = (|| -> anyhow::Result<bool> {
            let conn = af_db::get_conn()?;
            let transaction = conn.unchecked_transaction()?;
            let current: (String, String) = transaction.query_row(
                "SELECT COALESCE(totp_secret, ''), COALESCE(password_hash, '') FROM users WHERE id = ?1",
                params![auth_user.user_id], |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let current_secret = af_db::decrypt_key(&current.0).unwrap_or(current.0);
            anyhow::ensure!(current_secret == secret && current.1 == password_hash, "Credentials changed");
            if !password_verified && !consume_totp_code(&transaction, auth_user.user_id, &secret, &payload.code)
                && !validate_recovery_code(&transaction, auth_user.user_id, &payload.code) {
                return Ok(false);
            }
            let affected = transaction.execute(
                "UPDATE users SET totp_secret = '', totp_enabled = 0, last_totp_step = -1 WHERE id = ?1",
                params![auth_user.user_id],
            )?;
            anyhow::ensure!(affected == 1, "User not found");
            store_recovery_codes(&transaction, auth_user.user_id, &[])?;
            transaction.commit()?;
            Ok(true)
        })();
        match result {
            Ok(true) => {}
            Ok(false) => return api_error(StatusCode::FORBIDDEN, if payload.code.trim().is_empty() { "INVALID_CURRENT_PASSWORD" } else { "INVALID_2FA_CODE" }, "Invalid verification code or password"),
            Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Failed to disable two-factor authentication"),
        }
        af_db::record_audit(
            auth_user.user_id, &auth_user.username, "totp_disable", "user",
            &auth_user.user_id.to_string(), "Two-factor authentication disabled", &ip, &ua,
        );
        Json(serde_json::json!({ "message": "Two-factor authentication disabled" })).into_response()
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

fn verify_mfa_factor(
    conn: &rusqlite::Connection,
    token: &str,
    code: &str,
) -> anyhow::Result<Option<User>> {
    let transaction = conn.unchecked_transaction()?;
    let Some(user_id) = af_db::begin_mfa_attempt(&transaction, token)? else {
        return Ok(None);
    };
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
        return Ok(None);
    }
    anyhow::ensure!(
        af_db::consume_mfa_challenge(&transaction, token, user_id)?,
        "Challenge already consumed"
    );
    transaction.commit()?;
    Ok(Some(user))
}

fn mfa_login_verify_blocking(headers: HeaderMap, req: MfaVerifyRequest) -> Response {
    let result =
        af_db::get_conn().and_then(|conn| verify_mfa_factor(&conn, &req.mfa_token, &req.code));
    let user = match result {
        Ok(Some(user)) => user,
        Ok(None) => {
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
    let Ok((token, _)) = create_standard_jwt(user.id, &headers) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create session",
        );
    };
    record_login(user.id, &headers);
    let mut resp =
        Json(serde_json::json!({ "message": "Login successful", "user": user })).into_response();
    set_session_cookie(&mut resp, &token);
    resp
}

pub(crate) fn record_login(user_id: i64, headers: &HeaderMap) {
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?1, ?2, ?3)",
            params![
                user_id,
                extract_client_ip(headers),
                headers
                    .get(header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
            ],
        );
    }
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
        conn.execute_batch("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, avatar_url TEXT, role TEXT, google_id TEXT, totp_secret TEXT, totp_enabled INTEGER, last_totp_step INTEGER DEFAULT -1);
            INSERT INTO users VALUES (1, 'mfa-user', '', '', 'admin', '', 'JBSWY3DPEHPK3PXP', 1, -1);
            CREATE TABLE mfa_challenges (token TEXT PRIMARY KEY, user_id INTEGER, attempts INTEGER DEFAULT 0, expires_at INTEGER);
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
        conn.execute("INSERT INTO users VALUES (1, 'mfa-user', '', '', 'admin', '', 'JBSWY3DPEHPK3PXP', 1, -1)", []).unwrap();
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
                new_token: new_token.into(),
                expires_at: Instant::now() + Duration::from_secs(15),
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
                af_db::revoke_token(&claims.jti, Duration::from_secs(900));
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
}
