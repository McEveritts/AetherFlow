use crate::auth::{
    api_error, create_standard_jwt, decode_session_claims, secure_cookie_enabled, AuthUser,
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
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::PathBuf;

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

fn resolve_oidc_key_path() -> PathBuf {
    if let Ok(p) = env::var("OIDC_KEY_PATH") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join("data").join("oidc_rsa.pem");
        }
    }
    PathBuf::from("data/oidc_rsa.pem")
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

fn build_material_from_private_key(priv_key: &RsaPrivateKey, pem_str: &str) -> Option<OidcKeyMaterial> {
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
    let key_path = resolve_oidc_key_path();
    if let Ok(existing_pem) = fs::read_to_string(&key_path) {
        if let Ok(priv_key) = RsaPrivateKey::from_pkcs1_pem(&existing_pem) {
            if let Some(mat) = build_material_from_private_key(&priv_key, &existing_pem) {
                tracing::info!(path = %key_path.display(), kid = %mat.kid, "OIDC RSA key loaded");
                return Some(mat);
            }
        }
    }

    let mut rng = rand::rngs::OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).ok()?;
    let pem_zeroizing = priv_key.to_pkcs1_pem(LineEnding::LF).ok()?;
    let pem_str = pem_zeroizing.as_str();

    if let Some(parent) = key_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(e) = fs::write(&key_path, pem_str.as_bytes()) {
        tracing::warn!(error = %e, "OIDC: failed to persist RSA key");
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        }
        tracing::info!(path = %key_path.display(), "OIDC RSA key generated");
    }

    build_material_from_private_key(&priv_key, pem_str)
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
    let Ok(conn) = af_db::get_conn() else {
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
) -> anyhow::Result<String> {
    let mut code_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut code_bytes);
    let code = hex::encode(code_bytes);
    let expires_at = (Utc::now() + Duration::minutes(10)).to_rfc3339();

    let conn = af_db::get_conn()?;
    conn.execute(
        "INSERT INTO oidc_auth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            code,
            client_id,
            user_id,
            redirect_uri,
            scope,
            code_challenge,
            code_challenge_method,
            expires_at
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
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: String,
}

pub async fn oidc_authorize(
    Query(q): Query<AuthorizeQuery>,
    req: Request,
) -> Response {
    if q.response_type != "code" {
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

    let validated_scope = validate_oidc_scopes(&q.scope);
    if has_existing_consent(claims.user_id, &q.client_id, &validated_scope) {
        let Ok(code) = generate_and_store_auth_code(
            &q.client_id,
            claims.user_id,
            &q.redirect_uri,
            &validated_scope,
            &q.code_challenge,
            &q.code_challenge_method,
        ) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "server_error" })),
            )
                .into_response();
        };

        let sep = if q.redirect_uri.contains('?') { "&" } else { "?" };
        let mut redirect_url = format!("{}{}code={}", q.redirect_uri, sep, code);
        if !q.state.is_empty() {
            redirect_url.push_str(&format!("&state={}", urlencoding::encode(&q.state)));
        }
        return Redirect::temporary(&redirect_url).into_response();
    }

    let consent_url = format!(
        "/oauth/consent?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}&code_challenge={}&code_challenge_method={}",
        urlencoding::encode(&q.client_id),
        urlencoding::encode(&q.redirect_uri),
        urlencoding::encode(&q.response_type),
        urlencoding::encode(&validated_scope),
        urlencoding::encode(&q.state),
        urlencoding::encode(&q.code_challenge),
        urlencoding::encode(&q.code_challenge_method),
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

    if !payload.approved {
        let sep = if payload.redirect_uri.contains('?') { "&" } else { "?" };
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

    let scope = validate_oidc_scopes(&payload.scope);
    let Ok(code) = generate_and_store_auth_code(
        &payload.client_id,
        user.user_id,
        &payload.redirect_uri,
        &scope,
        &payload.code_challenge,
        &payload.code_challenge_method,
    ) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "server_error" })),
        )
            .into_response();
    };

    record_consent(user.user_id, &payload.client_id, &scope);

    let sep = if payload.redirect_uri.contains('?') { "&" } else { "?" };
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
    let Ok(conn) = af_db::get_conn() else {
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
    computed == stored_hash
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

fn issue_oidc_tokens(headers: &HeaderMap, client_id: &str, user_id: i64, scope: &str) -> Response {
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

    let _ = conn.execute(
        "INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![refresh_token, client_id, user_id, scope, refresh_exp],
    );

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

pub async fn oidc_token(
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
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

            let Ok((stored_client, user_id, stored_redirect, scope, challenge, challenge_method, expires_at, used)) =
                conn.query_row(
                    "SELECT client_id, user_id, redirect_uri, scope, COALESCE(code_challenge, ''), COALESCE(code_challenge_method, ''), expires_at, used \
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

            if !challenge.is_empty() && !verify_pkce(&code_verifier, &challenge, &challenge_method) {
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

            issue_oidc_tokens(&headers, &client_id, user_id, &scope)
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

            issue_oidc_tokens(&headers, &client_id, user_id, &scope)
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
                    let _ = conn.execute(
                        "DELETE FROM oidc_device_codes WHERE device_code = ?1",
                        params![device_code],
                    );
                    issue_oidc_tokens(&headers, &client_id, uid, &scope)
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
    let Ok(token_data) = decode::<AccessTokenClaims>(token_str.trim(), &keys.decoding_key, &validation) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_token" })),
        )
            .into_response();
    };

    let sub = token_data.claims.sub;
    let Ok(conn) = af_db::get_conn() else {
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

pub async fn oidc_introspect(
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
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
            if let Ok(data) = decode::<AccessTokenClaims>(&token_str, &keys.decoding_key, &validation) {
                if data.claims.aud == client_id {
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
        if let Ok(conn) = af_db::get_conn() {
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
                    .unwrap_or(false);
                if !revoked && !expired {
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
    let user_code = req
        .get("user_code")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if user_code.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "user_code is required" })),
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

    let Ok((status, scope, client_id)) = conn.query_row(
        "SELECT status, scope, client_id FROM oidc_device_codes WHERE user_code = ?1",
        params![user_code],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_user_code" })),
        )
            .into_response();
    };

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
    let user_code = body
        .get("user_code")
        .and_then(|v| v.as_str())
        .unwrap_or("");
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
            "UPDATE oidc_device_codes SET status = ?1, user_id = ?2 WHERE user_code = ?3 AND status = 'pending'",
            params![status, user.user_id, user_code],
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
    let Ok(conn) = af_db::get_conn() else {
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

pub async fn delete_oidc_client(
    Path(client_id): Path<String>,
    req: Request,
) -> Response {
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

pub async fn google_login() -> Response {
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
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

pub async fn google_callback(
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let base_url = get_base_url(&headers);
    if let Some(err_param) = q.get("error") {
        if !err_param.is_empty() {
            return Redirect::temporary(&format!(
                "{}/login?error={}",
                base_url,
                urlencoding::encode(err_param)
            ))
            .into_response();
        }
    }

    let code = q.get("code").cloned().unwrap_or_default();
    let state = q.get("state").cloned().unwrap_or_default();
    let cookie_state = extract_cookie(&headers, "oauth2_state").unwrap_or_default();
    if state.is_empty() || state != cookie_state {
        return Redirect::temporary(&format!("{}/login?error=invalid_state", base_url))
            .into_response();
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
        return Redirect::temporary(&format!("{}/login?error=token_exchange_failed", base_url))
            .into_response();
    };
    if !resp.status().is_success() {
        return Redirect::temporary(&format!("{}/login?error=token_exchange_failed", base_url))
            .into_response();
    }

    let Ok(token_json) = resp.json::<serde_json::Value>().await else {
        return Redirect::temporary(&format!("{}/login?error=token_exchange_failed", base_url))
            .into_response();
    };
    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if access_token.is_empty() {
        return Redirect::temporary(&format!("{}/login?error=no_access_token", base_url))
            .into_response();
    }

    let Ok(info_resp) = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
    else {
        return Redirect::temporary(&format!("{}/login?error=userinfo_failed", base_url))
            .into_response();
    };
    let Ok(user_info) = info_resp.json::<serde_json::Value>().await else {
        return Redirect::temporary(&format!("{}/login?error=userinfo_failed", base_url))
            .into_response();
    };

    let google_id = user_info
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let email = user_info
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let name = user_info
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let avatar_url = user_info
        .get("picture")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if google_id.is_empty() {
        return Redirect::temporary(&format!("{}/login?error=no_google_id", base_url))
            .into_response();
    }

    let Ok(conn) = af_db::get_conn() else {
        return Redirect::temporary(&format!("{}/login?error=db_error", base_url)).into_response();
    };

    let existing_id = conn
        .query_row(
            "SELECT id FROM users WHERE google_id = ?1",
            params![google_id],
            |r| r.get::<_, i64>(0),
        )
        .ok();

    let user_id = if let Some(uid) = existing_id {
        let _ = conn.execute(
            "UPDATE users SET email = ?1, avatar_url = ?2 WHERE google_id = ?3",
            params![email, avatar_url, google_id],
        );
        uid
    } else {
        let raw_username = if let Some((prefix, _)) = email.split_once('@') {
            prefix
        } else {
            name
        };
        let clean_username: String = raw_username
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.' || *c == '-')
            .collect();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .unwrap_or(0);
        let admin_email = env::var("ADMIN_EMAIL").unwrap_or_default();
        let role = if count == 0 || (!admin_email.is_empty() && email == admin_email) {
            "admin"
        } else {
            "user"
        };
        if conn
            .execute(
                "INSERT INTO users (username, google_id, email, avatar_url, role) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![clean_username, google_id, email, avatar_url, role],
            )
            .is_err()
        {
            return Redirect::temporary(&format!("{}/login?error=db_error", base_url))
                .into_response();
        }
        conn.last_insert_rowid()
    };

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let _ = conn.execute(
        "INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?1, ?2, ?3)",
        params![user_id, ip, ua],
    );

    let Ok((token, _)) = create_standard_jwt(user_id, &headers) else {
        return Redirect::temporary(&format!("{}/login?error=jwt_failed", base_url))
            .into_response();
    };

    let session_cookie = build_set_cookie(
        "aetherflow_session",
        &token,
        86400,
        "Lax",
        secure_cookie_enabled(),
        true,
    );
    let mut resp = Redirect::temporary(&format!("{}/", base_url)).into_response();
    if let Ok(hv) = HeaderValue::from_str(&session_cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}
