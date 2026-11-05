use crate::auth::{
    api_error, blocking_response, create_standard_jwt, decode_session_claims,
    secure_cookie_enabled, AuthUser,
};
use crate::ws::{build_set_cookie, extract_client_ip, extract_cookie};
use axum::extract::{Form, Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Redirect, Response};
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use rand::RngCore;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path as StdPath, PathBuf};

// ─────────────────────────────────────────────────────────────────────────────
// OIDC RSA-2048 Key Management (`backend/api/oidc.go`)
// ─────────────────────────────────────────────────────────────────────────────

pub struct OidcKeyMaterial {
    pub kid: String,
    pub n_b64: String,
    pub e_b64: String,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
}

static OIDC_KEYS: Lazy<Option<OidcKeyMaterial>> = Lazy::new(load_or_generate_oidc_key);

fn oidc_key_path(override_path: Option<&str>, state_directory: Option<&str>) -> PathBuf {
    if let Some(path) = override_path.map(str::trim).filter(|s| !s.is_empty()) {
        return PathBuf::from(path);
    }
    let state = state_directory
        .and_then(|s| s.split(':').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("/var/lib/aetherflow");
    PathBuf::from(state).join("oidc_rsa.pem")
}

fn resolve_oidc_key_path() -> PathBuf {
    oidc_key_path(
        env::var("OIDC_KEY_PATH").ok().as_deref(),
        env::var("STATE_DIRECTORY").ok().as_deref(),
    )
}

fn compute_key_id(pub_key: &RsaPublicKey) -> String {
    if let Ok(der) = pub_key.to_pkcs1_der() {
        let mut hasher = Sha256::new();
        hasher.update(der.as_bytes());
        let digest = hasher.finalize();
        return hex::encode(&digest[..8]);
    }
    "aetherflow-oidc-1".to_string()
}

fn build_material_from_private_key(
    priv_key: &RsaPrivateKey,
    pem_str: &str,
) -> Option<OidcKeyMaterial> {
    let pub_key = RsaPublicKey::from(priv_key);
    let kid = compute_key_id(&pub_key);
    let n_b64 = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e_b64 = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
    let encoding_key = EncodingKey::from_rsa_pem(pem_str.as_bytes()).ok()?;
    let decoding_key = DecodingKey::from_rsa_components(&n_b64, &e_b64).ok()?;
    Some(OidcKeyMaterial {
        kid,
        n_b64,
        e_b64,
        encoding_key,
        decoding_key,
    })
}

fn load_or_generate_oidc_key() -> Option<OidcKeyMaterial> {
    let path = resolve_oidc_key_path();
    match load_or_generate_oidc_key_at(&path) {
        Ok(material) => Some(material),
        Err(err) => {
            tracing::error!(path = %path.display(), error = %err, "OIDC signing disabled: cannot load persistent key");
            None
        }
    }
}

fn read_oidc_key(path: &StdPath) -> anyhow::Result<OidcKeyMaterial> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "OIDC key must be a regular file"
        );
        anyhow::ensure!(
            file.metadata()?.permissions().mode() & 0o077 == 0,
            "OIDC key permissions must be 0600 or stricter"
        );
        return read_oidc_material(file);
    }
    #[cfg(not(unix))]
    read_oidc_material(options.open(path)?)
}

fn read_oidc_material(mut file: fs::File) -> anyhow::Result<OidcKeyMaterial> {
    let mut pem = String::new();
    file.read_to_string(&mut pem)?;
    let private_key = RsaPrivateKey::from_pkcs1_pem(&pem)?;
    build_material_from_private_key(&private_key, &pem)
        .ok_or_else(|| anyhow::anyhow!("Invalid OIDC signing key"))
}

fn load_or_generate_oidc_key_at(path: &StdPath) -> anyhow::Result<OidcKeyMaterial> {
    match read_oidc_key(path) {
        Ok(material) => return Ok(material),
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
        Err(err) => return Err(err),
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| StdPath::new("."));
    fs::create_dir_all(parent)?;
    let private_key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)?;
    let pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
    // Write and fsync a private file, then publish it without replacing another process's key.
    let temporary = parent.join(format!(".oidc-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> anyhow::Result<OidcKeyMaterial> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(pem.as_bytes())?;
        file.sync_all()?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => {
                fs::File::open(parent)?.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        read_oidc_key(path)
    })();
    let _ = fs::remove_file(&temporary);
    result
}

pub fn get_base_url(headers: &HeaderMap) -> String {
    if let Ok(public_url) = env::var("PUBLIC_URL") {
        let trimmed = public_url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let proto = headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let host = headers
        .get("X-Forwarded-Host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:8080");
    format!("{}://{}", proto, host)
}

pub fn get_oidc_issuer(headers: &HeaderMap) -> String {
    if let Ok(issuer) = env::var("OIDC_ISSUER") {
        if !issuer.trim().is_empty() {
            return issuer.trim().trim_end_matches('/').to_string();
        }
    }
    get_base_url(headers)
}

// ─────────────────────────────────────────────────────────────────────────────
// OIDC Discovery & JWKS
// ─────────────────────────────────────────────────────────────────────────────

pub async fn oidc_discovery(headers: HeaderMap) -> Response {
    let issuer = get_oidc_issuer(&headers);
    Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/api/v1/public/oidc/authorize", issuer),
        "token_endpoint": format!("{}/api/v1/public/oidc/token", issuer),
        "userinfo_endpoint": format!("{}/api/v1/public/oidc/userinfo", issuer),
        "jwks_uri": format!("{}/api/v1/public/oidc/jwks", issuer),
        "revocation_endpoint": format!("{}/api/v1/public/oidc/revoke", issuer),
        "introspection_endpoint": format!("{}/api/v1/public/oidc/introspect", issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email", "picture", "role"],
        "code_challenge_methods_supported": ["S256", "plain"]
    }))
    .into_response()
}

pub async fn oidc_jwks() -> Response {
    blocking_response(move || oidc_jwks_blocking()).await
}

fn oidc_jwks_blocking() -> Response {
    let Some(keys) = OIDC_KEYS.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "OIDC keys not initialized" })),
        )
            .into_response();
    };

    Json(serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": keys.kid,
            "alg": "RS256",
            "n": keys.n_b64,
            "e": keys.e_b64,
        }]
    }))
    .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// OIDC Authorization & Consent Flow
// ─────────────────────────────────────────────────────────────────────────────

fn is_allowed_redirect_uri(uri: &str, stored_uris_json: &str) -> bool {
    let Ok(uris) = serde_json::from_str::<Vec<String>>(stored_uris_json) else {
        return false;
    };
    uris.iter().any(|allowed| allowed == uri)
}

fn validate_oidc_scopes(requested: &str) -> String {
    if requested.trim().is_empty() {
        return "openid profile email".to_string();
    }
    let supported = ["openid", "profile", "email"];
    let mut valid = Vec::new();
    let mut seen = HashSet::new();
    for s in requested.split_whitespace() {
        let trimmed = s.trim();
        if supported.contains(&trimmed) && seen.insert(trimmed) {
            valid.push(trimmed);
        }
    }
    if valid.is_empty() {
        "openid".to_string()
    } else {
        valid.join(" ")
    }
}

fn has_existing_consent(user_id: i64, client_id: &str, requested_scope: &str) -> bool {
    let Ok(conn) = af_db::get_read_conn() else {
        return false;
    };
    let Ok(stored_scope) = conn.query_row(
        "SELECT scope FROM oidc_consents WHERE user_id = ?1 AND client_id = ?2",
        params![user_id, client_id],
        |r| r.get::<_, String>(0),
    ) else {
        return false;
    };
    let stored_set: HashSet<&str> = stored_scope.split_whitespace().collect();
    requested_scope
        .split_whitespace()
        .all(|s| stored_set.contains(s))
}

fn record_consent(user_id: i64, client_id: &str, scope: &str) {
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "INSERT INTO oidc_consents (user_id, client_id, scope, granted_at) VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP) \
             ON CONFLICT(user_id, client_id) DO UPDATE SET scope = excluded.scope, granted_at = CURRENT_TIMESTAMP",
            params![user_id, client_id, scope],
        );
    }
}

fn generate_and_store_auth_code(
    client_id: &str,
    user_id: i64,
    redirect_uri: &str,
    scope: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    nonce: &str,
) -> anyhow::Result<String> {
    let mut code_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut code_bytes);
    let code = hex::encode(code_bytes);
    let expires_at = (Utc::now() + Duration::minutes(10)).to_rfc3339();

    let conn = af_db::get_conn()?;
    conn.execute(
        "INSERT INTO oidc_auth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, nonce) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            code,
            client_id,
            user_id,
            redirect_uri,
            scope,
            code_challenge,
            code_challenge_method,
            expires_at,
            nonce
        ],
    )?;
    Ok(code)
}

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub response_type: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: String,
}

pub async fn oidc_authorize(Query(q): Query<AuthorizeQuery>, req: Request) -> Response {
    blocking_response(move || oidc_authorize_blocking(q, req)).await
}

fn oidc_authorize_blocking(q: AuthorizeQuery, req: Request) -> Response {
    if q.response_type != "code" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "unsupported_response_type" })),
        )
            .into_response();
    }

    let Ok(conn) = af_db::get_read_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    let Ok(stored_redirect_uris) = conn.query_row(
        "SELECT redirect_uris FROM oidc_clients WHERE id = ?1",
        params![q.client_id],
        |r| r.get::<_, String>(0),
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_client" })),
        )
            .into_response();
    };

    if !is_allowed_redirect_uri(&q.redirect_uri, &stored_redirect_uris) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_redirect_uri" })),
        )
            .into_response();
    }

    let full_uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/api/v1/public/oidc/authorize");

    let Some(cookie) = extract_cookie(req.headers(), "aetherflow_session") else {
        let return_to = urlencoding::encode(full_uri);
        return Redirect::temporary(&format!("/login?return_to={}", return_to)).into_response();
    };

    let Ok(claims) = decode_session_claims(&cookie, false) else {
        let return_to = urlencoding::encode(full_uri);
        return Redirect::temporary(&format!("/login?return_to={}", return_to)).into_response();
    };

    drop(conn);
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if af_db::is_token_revoked(&claims.jti)
        || !crate::auth::matches_client_fingerprint(
            &claims.cfp,
            &extract_client_ip(req.headers()),
            user_agent,
        )
    {
        let return_to = urlencoding::encode(full_uri);
        return Redirect::temporary(&format!("/login?return_to={}", return_to)).into_response();
    }
    let validated_scope = validate_oidc_scopes(&q.scope);
    if has_existing_consent(claims.user_id, &q.client_id, &validated_scope) {
        let Ok(code) = generate_and_store_auth_code(
            &q.client_id,
            claims.user_id,
            &q.redirect_uri,
            &validated_scope,
            &q.code_challenge,
            &q.code_challenge_method,
            &q.nonce,
        ) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "server_error" })),
            )
                .into_response();
        };

        let sep = if q.redirect_uri.contains('?') {
            "&"
        } else {
            "?"
        };
        let mut redirect_url = format!("{}{}code={}", q.redirect_uri, sep, code);
        if !q.state.is_empty() {
            redirect_url.push_str(&format!("&state={}", urlencoding::encode(&q.state)));
        }
        return Redirect::temporary(&redirect_url).into_response();
    }

    let consent_url = format!(
        "/oauth/consent?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}&code_challenge={}&code_challenge_method={}&nonce={}",
        urlencoding::encode(&q.client_id),
        urlencoding::encode(&q.redirect_uri),
        urlencoding::encode(&q.response_type),
        urlencoding::encode(&validated_scope),
        urlencoding::encode(&q.state),
        urlencoding::encode(&q.code_challenge),
        urlencoding::encode(&q.code_challenge_method),
        urlencoding::encode(&q.nonce),
    );
    Redirect::temporary(&consent_url).into_response()
}

#[derive(Deserialize)]
pub struct ConsentRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: String,
    #[serde(default)]
    pub approved: bool,
}

pub async fn oidc_consent(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized" })),
        )
            .into_response();
    };

    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 64 * 1024).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid request body" })),
        )
            .into_response();
    };
    let Ok(payload) = serde_json::from_slice::<ConsentRequest>(&bytes) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid consent payload" })),
        )
            .into_response();
    };

    blocking_response(move || oidc_consent_blocking(user, payload)).await
}

fn oidc_consent_blocking(user: AuthUser, payload: ConsentRequest) -> Response {
    if !payload.approved {
        let Ok(conn) = af_db::get_conn() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "server_error" })),
            )
                .into_response();
        };
        let Ok(stored_uris) = conn.query_row(
            "SELECT redirect_uris FROM oidc_clients WHERE id = ?1",
            params![payload.client_id],
            |r| r.get::<_, String>(0),
        ) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_client_or_redirect_uri" })),
            )
                .into_response();
        };
        if !is_allowed_redirect_uri(&payload.redirect_uri, &stored_uris) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_client_or_redirect_uri" })),
            )
                .into_response();
        }
        drop(conn);
        let sep = if payload.redirect_uri.contains('?') {
            "&"
        } else {
            "?"
        };
        let mut redirect_url = format!(
            "{}{}error=access_denied&error_description=User+denied+access",
            payload.redirect_uri, sep
        );
        if !payload.state.is_empty() {
            redirect_url.push_str(&format!("&state={}", urlencoding::encode(&payload.state)));
        }
        return Json(serde_json::json!({
            "redirect_uri": redirect_url,
            "redirect_url": redirect_url,
        }))
        .into_response();
    }

    if payload.response_type != "code" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "unsupported_response_type" })),
        )
            .into_response();
    }

    let Ok(conn) = af_db::get_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    let Ok(stored_uris) = conn.query_row(
        "SELECT redirect_uris FROM oidc_clients WHERE id = ?1",
        params![payload.client_id],
        |r| r.get::<_, String>(0),
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_client_or_redirect_uri" })),
        )
            .into_response();
    };

    if !is_allowed_redirect_uri(&payload.redirect_uri, &stored_uris) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_client_or_redirect_uri" })),
        )
            .into_response();
    }

    drop(conn);
    let scope = validate_oidc_scopes(&payload.scope);
    let Ok(code) = generate_and_store_auth_code(
        &payload.client_id,
        user.user_id,
        &payload.redirect_uri,
        &scope,
        &payload.code_challenge,
        &payload.code_challenge_method,
        &payload.nonce,
    ) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    record_consent(user.user_id, &payload.client_id, &scope);

    let sep = if payload.redirect_uri.contains('?') {
        "&"
    } else {
        "?"
    };
    let mut redirect_url = format!("{}{}code={}", payload.redirect_uri, sep, code);
    if !payload.state.is_empty() {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(&payload.state)));
    }

    Json(serde_json::json!({
        "redirect_uri": redirect_url,
        "redirect_url": redirect_url,
    }))
    .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// OIDC Token, UserInfo, Revoke, Introspect & Device Code Flow
// ─────────────────────────────────────────────────────────────────────────────

fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = auth.strip_prefix("Basic ")?.trim();
    let decoded = BASE64_STD.decode(encoded).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

fn verify_client_credentials(client_id: &str, client_secret: &str) -> bool {
    if client_id.is_empty() {
        return false;
    }
    let Ok(conn) = af_db::get_read_conn() else {
        return false;
    };
    let Ok(stored_hash) = conn.query_row(
        "SELECT client_secret_hash FROM oidc_clients WHERE id = ?1",
        params![client_id],
        |r| r.get::<_, String>(0),
    ) else {
        return false;
    };
    let mut hasher = Sha256::new();
    hasher.update(client_secret.as_bytes());
    let computed = hex::encode(hasher.finalize());
    af_services::cluster_daemon::constant_time_eq(computed.as_bytes(), stored_hash.as_bytes())
}

fn verify_pkce(verifier: &str, challenge: &str, method: &str) -> bool {
    if verifier.is_empty() {
        return false;
    }
    match method {
        "S256" => {
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let computed = URL_SAFE_NO_PAD.encode(hasher.finalize());
            computed == challenge
        }
        "plain" | "" => verifier == challenge,
        _ => false,
    }
}

#[derive(Serialize, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    name: String,
    email: String,
    picture: String,
    role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct AccessTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    scope: String,
}

fn issue_oidc_tokens(
    headers: &HeaderMap,
    client_id: &str,
    user_id: i64,
    scope: &str,
    nonce: Option<&str>,
) -> Response {
    let Some(keys) = OIDC_KEYS.as_ref() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    let Ok(conn) = af_db::get_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    let Ok((username, email, avatar_url, role)) = conn.query_row(
        "SELECT username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user') FROM users WHERE id = ?1",
        params![user_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)),
    ) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    let issuer = get_oidc_issuer(headers);
    let now = Utc::now().timestamp();
    let exp = now + 3600;

    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some(keys.kid.clone());

    let id_claims = IdTokenClaims {
        iss: issuer.clone(),
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        exp,
        iat: now,
        name: username,
        email,
        picture: avatar_url,
        role,
        nonce: nonce.filter(|v| !v.is_empty()).map(str::to_string),
    };

    let access_claims = AccessTokenClaims {
        iss: issuer,
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        exp,
        iat: now,
        scope: scope.to_string(),
    };

    let Ok(id_token) = encode(&jwt_header, &id_claims, &keys.encoding_key) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    let Ok(access_token) = encode(&jwt_header, &access_claims, &keys.encoding_key) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    let mut refresh_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut refresh_bytes);
    let refresh_token = hex::encode(refresh_bytes);
    let refresh_exp = (Utc::now() + Duration::days(30)).to_rfc3339();

    if conn.execute(
        "INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![refresh_token, client_id, user_id, scope, refresh_exp],
    ).is_err() { return api_error(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Failed to persist OIDC refresh token"); }

    Json(serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "scope": scope,
    }))
    .into_response()
}

fn consume_device_code(
    conn: &rusqlite::Connection,
    code: &str,
    client_id: &str,
) -> rusqlite::Result<Option<(i64, String)>> {
    conn.query_row("DELETE FROM oidc_device_codes WHERE device_code = ?1 AND client_id = ?2 AND status = 'approved' AND user_id IS NOT NULL AND expires_at > ?3 RETURNING user_id, scope",
        params![code, client_id, Utc::now().to_rfc3339()], |r| Ok((r.get(0)?, r.get(1)?))).optional()
}

pub async fn oidc_token(headers: HeaderMap, Form(form): Form<HashMap<String, String>>) -> Response {
    blocking_response(move || oidc_token_blocking(headers, form)).await
}

fn oidc_token_blocking(headers: HeaderMap, form: HashMap<String, String>) -> Response {
    let grant_type = form.get("grant_type").cloned().unwrap_or_default();
    let mut client_id = form.get("client_id").cloned().unwrap_or_default();
    let mut client_secret = form.get("client_secret").cloned().unwrap_or_default();

    if client_id.is_empty() {
        if let Some((basic_id, basic_secret)) = extract_basic_auth(&headers) {
            client_id = basic_id;
            client_secret = basic_secret;
        }
    }

    if !verify_client_credentials(&client_id, &client_secret) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_client" })),
        )
            .into_response();
    }

    match grant_type.as_str() {
        "authorization_code" => {
            let code = form.get("code").cloned().unwrap_or_default();
            let redirect_uri = form.get("redirect_uri").cloned().unwrap_or_default();
            let code_verifier = form.get("code_verifier").cloned().unwrap_or_default();

            let Ok(mut conn) = af_db::get_conn() else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "server_error" })),
                )
                    .into_response();
            };

            let Ok((stored_client, user_id, stored_redirect, scope, challenge, challenge_method, expires_at, used, nonce)) =
                conn.query_row(
                    "SELECT client_id, user_id, redirect_uri, scope, COALESCE(code_challenge, ''), COALESCE(code_challenge_method, ''), expires_at, used, nonce \
                     FROM oidc_auth_codes WHERE code = ?1",
                    params![code],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, String>(5)?,
                            r.get::<_, String>(6)?,
                            r.get::<_, bool>(7)?,
                            r.get::<_, String>(8)?,
                        ))
                    },
                )
            else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_grant" })),
                )
                    .into_response();
            };

            if used {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "code already used"
                    })),
                )
                    .into_response();
            }

            if stored_client != client_id || stored_redirect != redirect_uri {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_grant" })),
                )
                    .into_response();
            }

            let Ok(exp_dt) = DateTime::parse_from_rfc3339(&expires_at) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "malformed expiry"
                    })),
                )
                    .into_response();
            };
            if Utc::now() > exp_dt.with_timezone(&Utc) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "code expired"
                    })),
                )
                    .into_response();
            }

            if !challenge.is_empty() && !verify_pkce(&code_verifier, &challenge, &challenge_method)
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "PKCE verification failed"
                    })),
                )
                    .into_response();
            }

            let Ok(tx) = conn.transaction() else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "server_error" })),
                )
                    .into_response();
            };
            let affected = tx
                .execute(
                    "UPDATE oidc_auth_codes SET used = 1 WHERE code = ?1 AND used = 0",
                    params![code],
                )
                .unwrap_or(0);
            if affected == 0 || tx.commit().is_err() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "code already used"
                    })),
                )
                    .into_response();
            }

            drop(conn);
            issue_oidc_tokens(&headers, &client_id, user_id, &scope, Some(&nonce))
        }
        "refresh_token" => {
            let refresh_token = form.get("refresh_token").cloned().unwrap_or_default();
            let Ok(mut conn) = af_db::get_conn() else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "server_error" })),
                )
                    .into_response();
            };

            let Ok((stored_client, user_id, scope, expires_at, revoked)) = conn.query_row(
                "SELECT client_id, user_id, scope, expires_at, revoked FROM oidc_refresh_tokens WHERE token = ?1",
                params![refresh_token],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, bool>(4)?,
                    ))
                },
            ) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_grant" })),
                )
                    .into_response();
            };

            if revoked || stored_client != client_id {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_grant" })),
                )
                    .into_response();
            }

            let Ok(exp_dt) = DateTime::parse_from_rfc3339(&expires_at) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "malformed expiry"
                    })),
                )
                    .into_response();
            };
            if Utc::now() > exp_dt.with_timezone(&Utc) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "refresh token expired"
                    })),
                )
                    .into_response();
            }

            let Ok(tx) = conn.transaction() else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "server_error" })),
                )
                    .into_response();
            };
            let affected = tx
                .execute(
                    "UPDATE oidc_refresh_tokens SET revoked = 1 WHERE token = ?1 AND revoked = 0",
                    params![refresh_token],
                )
                .unwrap_or(0);
            if affected == 0 || tx.commit().is_err() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "token already consumed"
                    })),
                )
                    .into_response();
            }

            drop(conn);
            issue_oidc_tokens(&headers, &client_id, user_id, &scope, None)
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            let device_code = form.get("device_code").cloned().unwrap_or_default();
            let Ok(conn) = af_db::get_conn() else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "server_error" })),
                )
                    .into_response();
            };

            let Ok((stored_client, user_id_opt, scope, expires_at, status)) = conn.query_row(
                "SELECT client_id, user_id, scope, expires_at, status FROM oidc_device_codes WHERE device_code = ?1",
                params![device_code],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<i64>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                },
            ) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_grant" })),
                )
                    .into_response();
            };

            if stored_client != client_id {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_grant" })),
                )
                    .into_response();
            }

            let Ok(exp_dt) = DateTime::parse_from_rfc3339(&expires_at) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "expired_token" })),
                )
                    .into_response();
            };
            if Utc::now() > exp_dt.with_timezone(&Utc) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "expired_token" })),
                )
                    .into_response();
            }

            match status.as_str() {
                "pending" => (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "authorization_pending" })),
                )
                    .into_response(),
                "denied" => (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "access_denied" })),
                )
                    .into_response(),
                "approved" => {
                    let Some(uid) = user_id_opt else {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "error": "server_error" })),
                        )
                            .into_response();
                    };
                    if !matches!(consume_device_code(&conn, &device_code, &client_id), Ok(Some((consumed_uid, _))) if consumed_uid == uid)
                    {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error":"invalid_grant"})),
                        )
                            .into_response();
                    }
                    drop(conn);
                    issue_oidc_tokens(&headers, &client_id, uid, &scope, None)
                }
                _ => (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_grant" })),
                )
                    .into_response(),
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "unsupported_grant_type" })),
        )
            .into_response(),
    }
}

pub async fn oidc_userinfo(headers: HeaderMap) -> Response {
    blocking_response(move || oidc_userinfo_blocking(headers)).await
}

fn oidc_userinfo_blocking(headers: HeaderMap) -> Response {
    let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_token" })),
        )
            .into_response();
    };
    let Some(token_str) = auth.strip_prefix("Bearer ") else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_token" })),
        )
            .into_response();
    };
    let Some(keys) = OIDC_KEYS.as_ref() else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_token" })),
        )
            .into_response();
    };

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    let Ok(token_data) =
        decode::<AccessTokenClaims>(token_str.trim(), &keys.decoding_key, &validation)
    else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_token" })),
        )
            .into_response();
    };

    let sub = token_data.claims.sub;
    let Ok(conn) = af_db::get_read_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    let Ok((username, email, avatar_url, role)) = conn.query_row(
        "SELECT username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user') FROM users WHERE id = ?1",
        params![sub],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)),
    ) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_token",
                "error_description": "user not found"
            })),
        )
            .into_response();
    };

    Json(serde_json::json!({
        "sub": sub,
        "name": username,
        "email": email,
        "picture": avatar_url,
        "role": role,
    }))
    .into_response()
}

pub async fn oidc_revoke(
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    blocking_response(move || oidc_revoke_blocking(headers, form)).await
}

fn oidc_revoke_blocking(headers: HeaderMap, form: HashMap<String, String>) -> Response {
    let mut client_id = form.get("client_id").cloned().unwrap_or_default();
    let mut client_secret = form.get("client_secret").cloned().unwrap_or_default();
    if client_id.is_empty() {
        if let Some((basic_id, basic_secret)) = extract_basic_auth(&headers) {
            client_id = basic_id;
            client_secret = basic_secret;
        }
    }
    if client_id.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "client authentication required"
            })),
        )
            .into_response();
    }
    if !verify_client_credentials(&client_id, &client_secret) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_client" })),
        )
            .into_response();
    }

    let token = form.get("token").cloned().unwrap_or_default();
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_request" })),
        )
            .into_response();
    }

    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "UPDATE oidc_refresh_tokens SET revoked = 1 WHERE token = ?1 AND client_id = ?2",
            params![token, client_id],
        );
    }
    Json(serde_json::json!({})).into_response()
}

fn access_token_subject_exists(connection: &rusqlite::Connection, subject: &str) -> bool {
    let Ok(user_id) = subject.parse::<i64>() else {
        return false;
    };
    user_id > 0
        && connection
            .query_row("SELECT 1 FROM users WHERE id = ?1", [user_id], |_| Ok(()))
            .is_ok()
}

#[cfg(test)]
mod lifecycle_tests {
    use super::access_token_subject_exists;

    #[test]
    fn access_token_introspection_requires_a_live_subject_and_fails_closed_on_database_errors() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE users (id INTEGER PRIMARY KEY); INSERT INTO users VALUES (1), (2);",
            )
            .unwrap();
        assert!(access_token_subject_exists(&connection, "1"));
        connection
            .execute("DELETE FROM users WHERE id = 1", [])
            .unwrap();
        assert!(!access_token_subject_exists(&connection, "1"));
        assert!(access_token_subject_exists(&connection, "2"));
        for invalid in ["", "-1", "0", "not-an-id", "9223372036854775808"] {
            assert!(!access_token_subject_exists(&connection, invalid));
        }
        connection.execute("DROP TABLE users", []).unwrap();
        assert!(!access_token_subject_exists(&connection, "2"));
    }
}

pub async fn oidc_introspect(
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    blocking_response(move || oidc_introspect_blocking(headers, form)).await
}

fn oidc_introspect_blocking(headers: HeaderMap, form: HashMap<String, String>) -> Response {
    let mut client_id = form.get("client_id").cloned().unwrap_or_default();
    let mut client_secret = form.get("client_secret").cloned().unwrap_or_default();
    if client_id.is_empty() {
        if let Some((basic_id, basic_secret)) = extract_basic_auth(&headers) {
            client_id = basic_id;
            client_secret = basic_secret;
        }
    }
    if client_id.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "client authentication required"
            })),
        )
            .into_response();
    }
    if !verify_client_credentials(&client_id, &client_secret) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_client" })),
        )
            .into_response();
    }

    let token_str = form.get("token").cloned().unwrap_or_default();
    if token_str.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "token parameter required"
            })),
        )
            .into_response();
    }
    let hint = form.get("token_type_hint").cloned().unwrap_or_default();

    if hint != "refresh_token" {
        if let Some(keys) = OIDC_KEYS.as_ref() {
            let mut validation = Validation::new(Algorithm::RS256);
            validation.validate_aud = false;
            if let Ok(data) =
                decode::<AccessTokenClaims>(&token_str, &keys.decoding_key, &validation)
            {
                let subject_exists = af_db::get_read_conn().ok().is_some_and(|connection| {
                    access_token_subject_exists(&connection, &data.claims.sub)
                });
                if data.claims.aud == client_id && subject_exists {
                    return Json(serde_json::json!({
                        "active": true,
                        "sub": data.claims.sub,
                        "client_id": client_id,
                        "scope": data.claims.scope,
                        "exp": data.claims.exp,
                        "iat": data.claims.iat,
                        "token_type": "Bearer",
                    }))
                    .into_response();
                }
            }
        }
    }

    if hint != "access_token" {
        if let Ok(conn) = af_db::get_read_conn() {
            if let Ok((user_id, scope, revoked, expires_at)) = conn.query_row(
                "SELECT user_id, scope, revoked, expires_at FROM oidc_refresh_tokens WHERE token = ?1 AND client_id = ?2",
                params![token_str, client_id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, bool>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                },
            ) {
                let expired = DateTime::parse_from_rfc3339(&expires_at)
                    .map(|dt| Utc::now() > dt.with_timezone(&Utc))
                    .unwrap_or(true);
                let user_exists = conn
                    .query_row(
                        "SELECT 1 FROM users WHERE id = ?1",
                        params![user_id],
                        |_| Ok(()),
                    )
                    .is_ok();
                if !revoked && !expired && user_exists {
                    return Json(serde_json::json!({
                        "active": true,
                        "sub": user_id.to_string(),
                        "client_id": client_id,
                        "scope": scope,
                        "token_type": "refresh_token",
                    }))
                    .into_response();
                }
            }
        }
    }

    Json(serde_json::json!({ "active": false })).into_response()
}

fn generate_user_code() -> String {
    const CHARSET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ23456789";
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let chars: Vec<char> = b
        .iter()
        .map(|byte| CHARSET[(*byte as usize) % CHARSET.len()] as char)
        .collect();
    format!(
        "{}-{}",
        chars[..4].iter().collect::<String>(),
        chars[4..].iter().collect::<String>()
    )
}

pub async fn oidc_device_authorize(
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    blocking_response(move || oidc_device_authorize_blocking(headers, form)).await
}

fn oidc_device_authorize_blocking(headers: HeaderMap, form: HashMap<String, String>) -> Response {
    let client_id = form.get("client_id").cloned().unwrap_or_default();
    let mut scope = form.get("scope").cloned().unwrap_or_default();
    if scope.is_empty() {
        scope = "openid profile email".to_string();
    }

    let Ok(conn) = af_db::get_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    let client_exists = conn
        .query_row(
            "SELECT client_secret_hash FROM oidc_clients WHERE id = ?1",
            params![client_id],
            |r| r.get::<_, String>(0),
        )
        .is_ok();
    if !client_exists {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_client" })),
        )
            .into_response();
    }

    let mut dc_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut dc_bytes);
    let device_code = hex::encode(dc_bytes);
    let user_code = generate_user_code();
    let expires_at = (Utc::now() + Duration::minutes(10)).to_rfc3339();

    if conn
        .execute(
            "INSERT INTO oidc_device_codes (device_code, user_code, client_id, scope, expires_at, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending')",
            params![device_code, user_code, client_id, scope, expires_at],
        )
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    }

    let issuer = get_oidc_issuer(&headers);
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

pub async fn oidc_device_verify(Json(req): Json<serde_json::Value>) -> Response {
    blocking_response(move || oidc_device_verify_blocking(req)).await
}

fn oidc_device_verify_blocking(req: serde_json::Value) -> Response {
    let user_code = req.get("user_code").and_then(|v| v.as_str()).unwrap_or("");
    if user_code.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "user_code is required" })),
        )
            .into_response();
    }

    let Ok(conn) = af_db::get_read_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    let Ok((status, scope, client_id, expires_at)) = conn.query_row(
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
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_user_code" })),
        )
            .into_response();
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

    let client_name: String = conn
        .query_row(
            "SELECT name FROM oidc_clients WHERE id = ?1",
            params![client_id],
            |r| r.get(0),
        )
        .unwrap_or_default();

    Json(serde_json::json!({
        "status": status,
        "scope": scope,
        "client_id": client_id,
        "client_name": client_name,
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
    blocking_response(move || oidc_device_consent_blocking(user, body)).await
}

fn oidc_device_consent_blocking(user: AuthUser, body: serde_json::Value) -> Response {
    let user_code = body.get("user_code").and_then(|v| v.as_str()).unwrap_or("");
    let approved = body
        .get("approved")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if user_code.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "user_code is required" })),
        )
            .into_response();
    }

    let status = if approved { "approved" } else { "denied" };
    let Ok(conn) = af_db::get_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    let affected = conn
        .execute(
            "UPDATE oidc_device_codes SET status = ?1, user_id = ?2 WHERE user_code = ?3 AND status = 'pending' AND expires_at > ?4",
            params![status, user.user_id, user_code, Utc::now().to_rfc3339()],
        )
        .unwrap_or(0);
    if affected == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_user_code" })),
        )
            .into_response();
    }

    Json(serde_json::json!({ "status": status })).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// OIDC Clients Admin CRUD (`backend/api/oidc_clients.go`)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_oidc_clients() -> Response {
    blocking_response(move || get_oidc_clients_blocking()).await
}

fn get_oidc_clients_blocking() -> Response {
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to query clients",
        );
    };
    let mut clients = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, name, redirect_uris, COALESCE(created_at, '') FROM oidc_clients ORDER BY created_at DESC",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            let uris_raw: String = r.get(2)?;
            let uris: Vec<String> = serde_json::from_str(&uris_raw).unwrap_or_default();
            Ok(serde_json::json!({
                "id": r.get::<_, String>(0)?,
                "name": r.get::<_, String>(1)?,
                "redirect_uris": uris,
                "created_at": r.get::<_, String>(3)?,
            }))
        }) {
            for row in rows.flatten() {
                clients.push(row);
            }
        }
    }
    Json(serde_json::json!({ "clients": clients })).into_response()
}

pub async fn create_oidc_client(req: Request) -> Response {
    let actor = req.extensions().get::<AuthUser>().cloned();
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 64 * 1024).await else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid body");
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON");
    };

    blocking_response(move || create_oidc_client_blocking(actor, ip, ua, body)).await
}

fn create_oidc_client_blocking(
    actor: Option<AuthUser>,
    ip: String,
    ua: String,
    body: serde_json::Value,
) -> Response {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let redirect_uris: Vec<String> = body
        .get("redirect_uris")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    if name.is_empty() || redirect_uris.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "name and at least one redirect_uri are required",
        );
    }

    let mut id_bytes = [0u8; 16];
    let mut secret_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    let client_id = hex::encode(id_bytes);
    let client_secret = hex::encode(secret_bytes);

    let mut hasher = Sha256::new();
    hasher.update(client_secret.as_bytes());
    let secret_hash_hex = hex::encode(hasher.finalize());
    let uris_json = serde_json::to_string(&redirect_uris).unwrap_or_else(|_| "[]".to_string());

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    if conn
        .execute(
            "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) VALUES (?1, ?2, ?3, ?4)",
            params![client_id, secret_hash_hex, name, uris_json],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create client",
        );
    }

    drop(conn);
    if let Some(u) = actor {
        af_db::record_audit(
            u.user_id,
            &u.username,
            "oidc_client_create",
            "oidc_client",
            &client_id,
            &format!("name={}", name),
            &ip,
            &ua,
        );
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "name": name,
            "redirect_uris": redirect_uris,
            "message": "Save the client_secret now — it cannot be retrieved later",
        })),
    )
        .into_response()
}

pub async fn delete_oidc_client(Path(client_id): Path<String>, req: Request) -> Response {
    blocking_response(move || delete_oidc_client_blocking(client_id, req)).await
}

fn delete_oidc_client_blocking(client_id: String, req: Request) -> Response {
    if client_id.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Client ID is required",
        );
    }
    let actor = req.extensions().get::<AuthUser>().cloned();
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete client",
        );
    };

    let affected = conn
        .execute("DELETE FROM oidc_clients WHERE id = ?1", params![client_id])
        .unwrap_or(0);
    if affected == 0 {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Client not found");
    }

    let _ = conn.execute(
        "UPDATE oidc_refresh_tokens SET revoked = 1 WHERE client_id = ?1",
        params![client_id],
    );
    let _ = conn.execute(
        "DELETE FROM oidc_auth_codes WHERE client_id = ?1",
        params![client_id],
    );

    drop(conn);
    if let Some(u) = actor {
        af_db::record_audit(
            u.user_id,
            &u.username,
            "oidc_client_delete",
            "oidc_client",
            &client_id,
            "",
            &ip,
            &ua,
        );
    }

    Json(serde_json::json!({ "message": "Client deleted and tokens revoked" })).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Google OAuth2 Login & Callback (`backend/api/auth.go`)
// ─────────────────────────────────────────────────────────────────────────────

fn safe_login_return_to(raw: &str) -> Option<String> {
    if raw.len() > 2048
        || !raw.starts_with('/')
        || raw.starts_with("//")
        || raw.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'\\')
    {
        return None;
    }
    let decoded = urlencoding::decode(raw).ok()?;
    if decoded.starts_with("//") || decoded.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'\\') {
        return None;
    }
    let url = url::Url::parse(&format!("https://aetherflow.invalid{raw}")).ok()?;
    if url.host_str() != Some("aetherflow.invalid") || url.path().starts_with("//") {
        return None;
    }
    Some(url[url::Position::BeforePath..].to_string())
}

fn google_return_to(headers: &HeaderMap) -> Option<String> {
    let cookie = extract_cookie(headers, "oauth2_return_to")?;
    safe_login_return_to(&urlencoding::decode(&cookie).ok()?)
}

fn google_login_location(headers: &HeaderMap, parameter: &str, value: &str) -> String {
    let mut location = format!("/login?{parameter}={}", urlencoding::encode(value));
    if let Some(destination) = google_return_to(headers) {
        location.push_str(&format!("&return_to={}", urlencoding::encode(&destination)));
    }
    location
}

fn clear_google_cookies(response: &mut Response) {
    for name in ["oauth2_state", "oauth2_return_to"] {
        let cookie = build_set_cookie(name, "", -1, "Lax", secure_cookie_enabled(), true);
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
}

fn google_login_error(headers: &HeaderMap, error: &str) -> Response {
    let mut response =
        Redirect::temporary(&google_login_location(headers, "error", error)).into_response();
    clear_google_cookies(&mut response);
    response
}

pub async fn google_login(Query(q): Query<HashMap<String, String>>) -> Response {
    let client_id = env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").unwrap_or_default();
    if client_id.is_empty() || redirect_uri.is_empty() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "OAuth not configured",
        );
    }

    let mut state_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut state_bytes);
    let state = hex::encode(state_bytes);

    let cookie = build_set_cookie(
        "oauth2_state",
        &state,
        600,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}&access_type=offline&prompt=consent",
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        state
    );

    let mut resp = Redirect::temporary(&auth_url).into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    // Keep continuation out of the external provider URL; clear any stale value.
    let destination = q
        .get("return_to")
        .and_then(|value| safe_login_return_to(value));
    let continuation = destination
        .as_deref()
        .map(urlencoding::encode)
        .unwrap_or_default();
    let cookie = build_set_cookie(
        "oauth2_return_to",
        &continuation,
        if destination.is_some() { 600 } else { -1 },
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn google_callback(
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Some(err_param) = q.get("error") {
        if !err_param.is_empty() {
            return google_login_error(&headers, err_param);
        }
    }

    let code = q.get("code").cloned().unwrap_or_default();
    let state = q.get("state").cloned().unwrap_or_default();
    let cookie_state = extract_cookie(&headers, "oauth2_state").unwrap_or_default();
    if state.is_empty() || state != cookie_state {
        return google_login_error(&headers, "invalid_state");
    }

    let client_id = env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
    let client_secret = env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default();
    let redirect_uri = env::var("GOOGLE_REDIRECT_URI").unwrap_or_default();

    let client = reqwest::Client::new();
    let token_res = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await;

    let Ok(resp) = token_res else {
        return google_login_error(&headers, "token_exchange_failed");
    };
    if !resp.status().is_success() {
        return google_login_error(&headers, "token_exchange_failed");
    }

    let Ok(token_json) = resp.json::<serde_json::Value>().await else {
        return google_login_error(&headers, "token_exchange_failed");
    };
    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if access_token.is_empty() {
        return google_login_error(&headers, "no_access_token");
    }

    let Ok(info_resp) = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
    else {
        return google_login_error(&headers, "userinfo_failed");
    };
    let info_resp_status_success = info_resp.status().is_success();
    let Ok(user_info) = info_resp.json::<serde_json::Value>().await else {
        return google_login_error(&headers, "userinfo_failed");
    };

    if !info_resp_status_success {
        return google_login_error(&headers, "userinfo_failed");
    }
    blocking_response(move || complete_google_login(&headers, &user_info)).await
}

fn google_email_allowed(email: &str, emails: &str, domains: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return false;
    }
    let entries = |list: &str| {
        list.split(|c: char| c == ',' || c.is_whitespace())
            .filter(|item| !item.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<HashSet<_>>()
    };
    entries(emails).contains(&email.to_ascii_lowercase())
        || entries(domains).contains(&domain.to_ascii_lowercase())
}

fn resolve_google_user(
    conn: &rusqlite::Connection,
    info: &serde_json::Value,
    emails: &str,
    domains: &str,
) -> anyhow::Result<Option<(i64, bool)>> {
    let google_id = info.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let email = info
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let verified = info
        .get("verified_email")
        .or_else(|| info.get("email_verified"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if google_id.is_empty() || email.is_empty() || !verified {
        return Ok(None);
    }
    let avatar = info.get("picture").and_then(|v| v.as_str()).unwrap_or("");
    let tx = conn.unchecked_transaction()?;
    let existing: Option<(i64, bool)> = tx
        .query_row(
            "SELECT id, COALESCE(totp_enabled, 0) FROM users WHERE google_id = ?1",
            params![google_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let user = if let Some(user) = existing {
        // Preserve configured role, username and email for a previously linked identity.
        tx.execute(
            "UPDATE users SET avatar_url = ?1 WHERE id = ?2",
            params![avatar, user.0],
        )?;
        user
    } else {
        let matches: i64 = tx.query_row(
            "SELECT COUNT(*) FROM users WHERE email = ?1 COLLATE NOCASE",
            params![email],
            |r| r.get(0),
        )?;
        if matches > 1 {
            return Ok(None);
        }
        if matches == 1 {
            let (id, linked, mfa): (i64, String, bool) = tx.query_row(
                "SELECT id, COALESCE(google_id, ''), COALESCE(totp_enabled, 0) FROM users WHERE email = ?1 COLLATE NOCASE", params![email], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            if !linked.is_empty() {
                return Ok(None);
            }
            tx.execute("UPDATE users SET google_id = ?1, avatar_url = ?2 WHERE id = ?3 AND COALESCE(google_id, '') = ''", params![google_id, avatar, id])?;
            (id, mfa)
        } else {
            if !google_email_allowed(email, emails, domains) {
                return Ok(None);
            }
            let prefix: String = email
                .split('@')
                .next()
                .unwrap_or("user")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
                .take(48)
                .collect();
            let username = format!(
                "{}-{}",
                if prefix.is_empty() { "user" } else { &prefix },
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            tx.execute("INSERT INTO users (username, google_id, email, avatar_url, role) VALUES (?1, ?2, ?3, ?4, 'user')", params![username, google_id, email, avatar])?;
            (tx.last_insert_rowid(), false)
        }
    };
    tx.commit()?;
    Ok(Some(user))
}

fn complete_google_login(headers: &HeaderMap, info: &serde_json::Value) -> Response {
    let result = af_db::get_conn().and_then(|conn| {
        resolve_google_user(
            &conn,
            info,
            &env::var("AETHERFLOW_GOOGLE_ALLOWED_EMAILS").unwrap_or_default(),
            &env::var("AETHERFLOW_GOOGLE_ALLOWED_DOMAINS").unwrap_or_default(),
        )
    });
    let mut response = match result {
        Ok(Some((user_id, true))) => {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let challenge = hex::encode(bytes);
            if af_db::store_mfa_challenge(&challenge, user_id, std::time::Duration::from_secs(300))
                .is_ok()
            {
                Redirect::temporary(&google_login_location(headers, "mfa", &challenge))
                    .into_response()
            } else {
                google_login_error(headers, "db_error")
            }
        }
        Ok(Some((user_id, false))) => match create_standard_jwt(user_id, headers) {
            Ok((token, _)) => {
                crate::auth::record_login(user_id, headers);
                let mut response =
                    Redirect::temporary(google_return_to(headers).as_deref().unwrap_or("/"))
                        .into_response();
                crate::auth::set_session_cookie(&mut response, &token);
                response
            }
            Err(_) => google_login_error(headers, "jwt_failed"),
        },
        Ok(None) => google_login_error(headers, "not_authorized"),
        Err(_) => google_login_error(headers, "db_error"),
    };
    clear_google_cookies(&mut response);
    response
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[test]
    fn continuation_validation_rejects_external_and_normalized_authorities() {
        for path in [
            "https://example.test/",
            "//example.test/",
            "/a/..//example.test/",
            "/%2fexample.test",
            "/\\example.test",
            "/%5cexample.test",
            "/path%0aLocation:evil",
            " /local",
        ] {
            assert!(safe_login_return_to(path).is_none(), "{path}");
        }
        assert_eq!(
            safe_login_return_to("/api/v1/public/oidc/authorize?state=hello%20world"),
            Some("/api/v1/public/oidc/authorize?state=hello%20world".into())
        );
    }

    #[tokio::test]
    async fn callback_errors_are_relative_and_preserve_safe_continuation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_static("localhost:@example.test"),
        );
        headers.insert("x-forwarded-host", HeaderValue::from_static("example.test"));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static(
                "oauth2_return_to=%2Fapi%2Fv1%2Fpublic%2Foidc%2Fauthorize%3Fstate%3Dretained",
            ),
        );
        let response = google_callback(
            headers.clone(),
            Query(HashMap::from([("error".into(), "access_denied".into())])),
        )
        .await;
        assert_eq!(response.headers()[header::LOCATION], "/login?error=access_denied&return_to=%2Fapi%2Fv1%2Fpublic%2Foidc%2Fauthorize%3Fstate%3Dretained");
        assert_eq!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        let response = google_callback(headers, Query(HashMap::new())).await;
        assert!(response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .starts_with("/login?error=invalid_state&return_to="));
    }

    fn google_database() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, google_id TEXT DEFAULT '', email TEXT DEFAULT '', avatar_url TEXT DEFAULT '', role TEXT DEFAULT 'user', totp_enabled INTEGER DEFAULT 0);").unwrap();
        conn
    }

    fn identity(verified: bool) -> serde_json::Value {
        serde_json::json!({"id":"google-123", "email":"person@example.com", "verified_email": verified, "picture":"avatar"})
    }

    #[test]
    fn google_provisioning_denies_by_default_and_never_bootstraps_an_admin() {
        let conn = google_database();
        assert!(resolve_google_user(&conn, &identity(true), "", "")
            .unwrap()
            .is_none());
        assert!(
            resolve_google_user(&conn, &identity(false), "person@example.com", "example.com")
                .unwrap()
                .is_none()
        );
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let (id, mfa) = resolve_google_user(&conn, &identity(true), " PERSON@example.com ", "")
            .unwrap()
            .unwrap();
        assert!(!mfa);
        let role: String = conn
            .query_row("SELECT role FROM users WHERE id = ?1", params![id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(role, "user");
        assert!(google_email_allowed(
            "other@EXAMPLE.com",
            "",
            "example.com,company.org"
        ));
        for email in [
            "evil@sub.example.com",
            "person@example.com.evil",
            "bad@@example.com",
            "@example.com",
        ] {
            assert!(!google_email_allowed(email, "", "example.com"));
        }
    }

    #[test]
    fn google_linking_requires_verification_and_preserves_existing_configuration() {
        let conn = google_database();
        conn.execute("INSERT INTO users (id, username, email, role, totp_enabled) VALUES (1, 'configured-admin', 'PERSON@example.com', 'admin', 1)", []).unwrap();
        assert!(resolve_google_user(&conn, &identity(false), "", "")
            .unwrap()
            .is_none());
        assert_eq!(
            resolve_google_user(&conn, &identity(true), "", "").unwrap(),
            Some((1, true))
        );
        let (name, role, email): (String, String, String) = conn
            .query_row(
                "SELECT username, role, email FROM users WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (name.as_str(), role.as_str(), email.as_str()),
            ("configured-admin", "admin", "PERSON@example.com")
        );
        let mut other = identity(true);
        other["id"] = "different-id".into();
        assert!(resolve_google_user(&conn, &other, "person@example.com", "")
            .unwrap()
            .is_none());
        assert_eq!(
            resolve_google_user(&conn, &identity(true), "", "").unwrap(),
            Some((1, true))
        );
    }

    #[tokio::test]
    async fn google_callback_mfa_has_no_session_until_factor_verification() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        ensure_shared_test_db();
        env::remove_var("AETHERFLOW_GOOGLE_ALLOWED_EMAILS");
        env::remove_var("AETHERFLOW_GOOGLE_ALLOWED_DOMAINS");
        let denied = complete_google_login(&HeaderMap::new(), &identity(true));
        assert_eq!(
            denied.headers()[header::LOCATION],
            "/login?error=not_authorized"
        );
        assert!(denied
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|v| !v.to_str().unwrap().starts_with("aetherflow_session=")));
        let conn = af_db::get_conn().unwrap();
        conn.execute("INSERT INTO users (id, username, google_id, email, role, totp_enabled, totp_secret) VALUES (654, 'google-mfa', 'google-123', 'person@example.com', 'admin', 1, 'JBSWY3DPEHPK3PXP')", []).unwrap();
        drop(conn);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static(
                "oauth2_return_to=%2Fapi%2Fv1%2Fpublic%2Foidc%2Fauthorize%3Fstate%3Dmfa",
            ),
        );
        let response = complete_google_login(&headers, &identity(true));
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        assert!(
            location.ends_with("&return_to=%2Fapi%2Fv1%2Fpublic%2Foidc%2Fauthorize%3Fstate%3Dmfa")
        );
        let challenge = location
            .strip_prefix("/login?mfa=")
            .expect("Exact MFA query contract")
            .split('&')
            .next()
            .unwrap();
        assert!(response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|v| !v.to_str().unwrap().starts_with("aetherflow_session=")));
        let conn = af_db::get_read_conn().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM active_sessions WHERE user_id = 654",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        drop(conn);
        let secret = data_encoding::BASE32_NOPAD
            .decode(b"JBSWY3DPEHPK3PXP")
            .unwrap();
        let code = totp_lite::totp_custom::<totp_lite::Sha1>(
            30,
            6,
            &secret,
            Utc::now().timestamp() as u64,
        );
        let response = crate::auth::mfa_login_verify(
            HeaderMap::new(),
            Json(crate::auth::MfaVerifyRequest {
                mfa_token: challenge.into(),
                code,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Secure"));
        let raw = cookie
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("aetherflow_session=")
            .unwrap();
        let claims = decode_session_claims(raw, false).unwrap();
        assert_eq!(claims.user_id, 654);
        assert_eq!(claims.exp - claims.iat, 900);
        let conn = af_db::get_read_conn().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM active_sessions WHERE user_id = 654 AND jti = ?1",
                params![claims.jti],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn oidc_key_defaults_use_persistent_state_and_explicit_override() {
        assert_eq!(
            oidc_key_path(None, None),
            PathBuf::from("/var/lib/aetherflow/oidc_rsa.pem")
        );
        assert_eq!(
            oidc_key_path(None, Some("/state/aetherflow:/state/other")),
            PathBuf::from("/state/aetherflow/oidc_rsa.pem")
        );
        assert_eq!(
            oidc_key_path(Some("/custom/key.pem"), Some("/state")),
            PathBuf::from("/custom/key.pem")
        );
    }

    #[test]
    fn oidc_key_is_private_persistent_and_never_replaces_corrupt_or_inaccessible_keys() {
        let root = env::temp_dir().join(format!("af-oidc-key-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("oidc.pem");
        let first = load_or_generate_oidc_key_at(&path).unwrap();
        let second = load_or_generate_oidc_key_at(&path).unwrap();
        assert_eq!(first.kid, second.kid);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let link = root.join("symlink.pem");
            symlink(&path, &link).unwrap();
            assert!(load_or_generate_oidc_key_at(&link).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_or_generate_oidc_key_at(&path).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(&path, "corrupt key").unwrap();
        assert!(load_or_generate_oidc_key_at(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "corrupt key");
        let parent_file = root.join("not-directory");
        fs::write(&parent_file, "x").unwrap();
        assert!(load_or_generate_oidc_key_at(&parent_file.join("key.pem")).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oidc_key_concurrent_creation_publishes_one_identity() {
        let root = env::temp_dir().join(format!("af-oidc-key-race-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("oidc.pem");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let tasks: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_generate_oidc_key_at(&path).unwrap().kid
                })
            })
            .collect();
        let kids: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(kids[0], kids[1]);
        assert_eq!(kids[0], read_oidc_key(&path).unwrap().kid);
        assert_eq!(
            fs::read_dir(&root).unwrap().count(),
            1,
            "Temporary private files must be removed"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn device_code_redemption_is_single_use_under_concurrency() {
        let path = env::temp_dir().join(format!("af-device-code-{}.sqlite", uuid::Uuid::new_v4()));
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE oidc_device_codes (device_code TEXT PRIMARY KEY, client_id TEXT, user_id INTEGER, scope TEXT, status TEXT, expires_at TEXT);").unwrap();
        conn.execute("INSERT INTO oidc_device_codes VALUES ('device', 'client', 1, 'openid', 'approved', ?1)", params![(Utc::now() + Duration::minutes(1)).to_rfc3339()]).unwrap();
        assert!(consume_device_code(&conn, "device", "wrong-client")
            .unwrap()
            .is_none());
        drop(conn);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let tasks: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let conn = rusqlite::Connection::open(path).unwrap();
                    conn.busy_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                    barrier.wait();
                    consume_device_code(&conn, "device", "client")
                        .unwrap()
                        .is_some()
                })
            })
            .collect();
        assert_eq!(
            tasks
                .into_iter()
                .map(|t| usize::from(t.join().unwrap()))
                .sum::<usize>(),
            1
        );
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn oidc_nonce_roundtrips_authorization_consent_code_and_id_token() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        if run_plugin_test_in_subprocess() {
            return;
        }
        let db = ensure_shared_test_db();
        env::set_var("OIDC_KEY_PATH", db.parent().unwrap().join("oidc.pem"));
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (765, 'oidc-user', 'user')",
            [],
        )
        .unwrap();
        let secret = hex::encode(Sha256::digest(b"client-secret"));
        conn.execute("INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) VALUES ('client', ?1, 'test', '[\"https://client.example/callback\"]')", params![secret]).unwrap();
        drop(conn);
        let (session, _) = create_standard_jwt(765, &HeaderMap::new()).unwrap();
        let q = AuthorizeQuery {
            client_id: "client".into(),
            redirect_uri: "https://client.example/callback".into(),
            response_type: "code".into(),
            scope: "openid".into(),
            state: "state".into(),
            nonce: "nonce-value&?".into(),
            code_challenge: String::new(),
            code_challenge_method: String::new(),
        };
        let req = Request::builder()
            .uri("/api/v1/public/oidc/authorize")
            .header(header::COOKIE, format!("aetherflow_session={session}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let response = oidc_authorize(Query(q), req).await;
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        let url = url::Url::parse(&format!("https://dashboard.example{location}")).unwrap();
        let values: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(values["nonce"], "nonce-value&?");
        let mut payload = serde_json::to_value(&values).unwrap();
        payload["approved"] = true.into();
        let mut req = Request::new(axum::body::Body::from(payload.to_string()));
        req.extensions_mut().insert(AuthUser {
            user_id: 765,
            username: "oidc-user".into(),
            role: "user".into(),
            jti: "consent".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        });
        let response = oidc_consent(req).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let redirect = url::Url::parse(value["redirect_uri"].as_str().unwrap()).unwrap();
        let code = redirect
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        let form: HashMap<String, String> = [
            ("grant_type", "authorization_code"),
            ("client_id", "client"),
            ("client_secret", "client-secret"),
            ("redirect_uri", "https://client.example/callback"),
            ("code", &code),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let response = oidc_token(HeaderMap::new(), Form(form.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 32768)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["client"]);
        let decoded = decode::<IdTokenClaims>(
            value["id_token"].as_str().unwrap(),
            &OIDC_KEYS.as_ref().unwrap().decoding_key,
            &validation,
        )
        .unwrap();
        assert_eq!(decoded.claims.nonce.as_deref(), Some("nonce-value&?"));
        assert_eq!(
            oidc_token(HeaderMap::new(), Form(form)).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
}
