use super::keys::oidc_server_error;
use crate::auth::{blocking_response, decode_session_claims, AuthUser, SubjectStatusError};
use crate::ws::extract_cookie;
use axum::extract::{Query, Request};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Redirect, Response};
use chrono::{Duration, Utc};
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(super) fn validate_pkce_request_params(
    code_challenge: &str,
    code_challenge_method: &str,
) -> Result<(), &'static str> {
    let challenge = code_challenge.trim();
    let method = code_challenge_method.trim();
    if challenge.is_empty() {
        return Err("PKCE S256 code_challenge is required");
    }
    if method != "S256" {
        return Err("code_challenge_method must be S256");
    }
    if challenge.len() != 43
        || !challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("code_challenge must be a valid 43-character base64url SHA-256 digest");
    }
    Ok(())
}

pub(super) fn is_safe_redirect_uri(uri: &str) -> bool {
    let trimmed = uri.trim();
    let Ok(parsed) = url::Url::parse(trimmed) else {
        return false;
    };
    if parsed.host_str().is_none_or(|h| h.is_empty())
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return false;
    }
    match parsed.scheme() {
        "https" => true,
        "http" => match parsed.host_str() {
            Some(h) => {
                let clean = h.trim_matches(['[', ']']);
                clean.eq_ignore_ascii_case("localhost") || clean == "127.0.0.1" || clean == "::1"
            }
            None => false,
        },
        _ => false,
    }
}

fn is_allowed_redirect_uri(uri: &str, stored_uris_json: &str) -> bool {
    if !is_safe_redirect_uri(uri) {
        return false;
    }
    let Ok(uris) = serde_json::from_str::<Vec<String>>(stored_uris_json) else {
        return false;
    };
    uris.iter().any(|allowed| allowed == uri)
}

pub(super) fn validate_oidc_scopes(requested: &str) -> String {
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

fn has_existing_consent_in_conn(
    conn: &rusqlite::Connection,
    user_id: i64,
    client_id: &str,
    requested_scope: &str,
) -> rusqlite::Result<bool> {
    if !crate::auth::table_exists(conn, "oidc_consents")? {
        return Ok(false);
    }
    let Some(stored_scope) = conn
        .query_row(
            "SELECT scope FROM oidc_consents WHERE user_id = ?1 AND client_id = ?2",
            params![user_id, client_id],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    else {
        return Ok(false);
    };
    let stored_set: HashSet<&str> = stored_scope.split_whitespace().collect();
    Ok(requested_scope
        .split_whitespace()
        .all(|s| stored_set.contains(s)))
}

pub(super) fn record_consent_in_tx(
    conn: &rusqlite::Connection,
    user_id: i64,
    client_id: &str,
    scope: &str,
) -> rusqlite::Result<()> {
    if !crate::auth::table_exists(conn, "oidc_consents")? {
        return Ok(());
    }
    conn.execute(
        "INSERT INTO oidc_consents (user_id, client_id, scope, granted_at) VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP) \
         ON CONFLICT(user_id, client_id) DO UPDATE SET scope = excluded.scope, granted_at = CURRENT_TIMESTAMP",
        params![user_id, client_id, scope],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn generate_and_store_auth_code_in_conn(
    conn: &rusqlite::Connection,
    client_id: &str,
    user_id: i64,
    redirect_uri: &str,
    scope: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    nonce: &str,
    session_family_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut code_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut code_bytes);
    let raw_hex = hex::encode(code_bytes);
    let code = match session_family_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(fam) => format!("s{}_{}", crate::auth::oidc_session_tag(fam), raw_hex),
        None => raw_hex,
    };
    let expires_at = (Utc::now() + Duration::minutes(10)).to_rfc3339();

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

#[allow(clippy::too_many_arguments)]
pub(super) fn generate_and_store_auth_code(
    client_id: &str,
    user_id: i64,
    redirect_uri: &str,
    scope: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    nonce: &str,
    session_family_id: Option<&str>,
) -> anyhow::Result<String> {
    let conn = af_db::get_conn()?;
    generate_and_store_auth_code_in_conn(
        &conn,
        client_id,
        user_id,
        redirect_uri,
        scope,
        code_challenge,
        code_challenge_method,
        nonce,
        session_family_id,
    )
}

pub(super) fn oidc_code_family_id(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"af-oidc-code:");
    hasher.update(code.as_bytes());
    let code_tag = &hex::encode(hasher.finalize())[..32];
    if code.len() > 33 && code.starts_with('s') && code.as_bytes()[33] == b'_' {
        let sess_tag = &code[1..33];
        if sess_tag
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return format!("sf:{}:{}", sess_tag, code_tag);
        }
    }
    format!("cf:{}", code_tag)
}

pub(super) fn oidc_device_family_id(device_code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"af-oidc-dc:");
    hasher.update(device_code.as_bytes());
    let dc_tag = &hex::encode(hasher.finalize())[..32];
    format!("dc:{}", dc_tag)
}

pub(super) fn try_is_oidc_grant_revoked(fam: &str) -> anyhow::Result<bool> {
    let trimmed = fam.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    if af_db::token_revocation_status(&format!("oidc-fam:{}", trimmed))? {
        return Ok(true);
    }
    if let Some(rest) = trimmed.strip_prefix("sf:") {
        if let Some((sess_tag, _)) = rest.split_once(':') {
            if sess_tag.len() == 32
                && af_db::token_revocation_status(&format!("oidc-sess:{}", sess_tag))?
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(super) fn is_oidc_grant_revoked(fam: &str) -> bool {
    try_is_oidc_grant_revoked(fam).unwrap_or(true)
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
        return oidc_server_error();
    };

    let stored_redirect_uris = match conn
        .query_row(
            "SELECT redirect_uris FROM oidc_clients WHERE id = ?1",
            params![q.client_id],
            |r| r.get::<_, String>(0),
        )
        .optional()
    {
        Ok(Some(uris)) => uris,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_client" })),
            )
                .into_response();
        }
        Err(_) => return oidc_server_error(),
    };

    if !is_allowed_redirect_uri(&q.redirect_uri, &stored_redirect_uris) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_redirect_uri" })),
        )
            .into_response();
    }

    if let Err(desc) = validate_pkce_request_params(&q.code_challenge, &q.code_challenge_method) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": desc,
            })),
        )
            .into_response();
    }

    let full_uri = req
        .extensions()
        .get::<axum::extract::OriginalUri>()
        .map(|uri| &uri.0)
        .unwrap_or_else(|| req.uri())
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
    if !claims.plugin_id.trim().is_empty() || !claims.plugin_scopes.is_empty() {
        let return_to = urlencoding::encode(full_uri);
        return Redirect::temporary(&format!("/login?return_to={}", return_to)).into_response();
    }

    let peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::ConnectInfo(addr)| addr.ip());
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let client_ip = crate::ws::extract_client_ip_for_peer(req.headers(), peer_ip);
    if !crate::auth::matches_client_fingerprint(&claims.cfp, &client_ip, user_agent) {
        let return_to = urlencoding::encode(full_uri);
        return Redirect::temporary(&format!("/login?return_to={}", return_to)).into_response();
    }
    let caller_strict_fp = crate::auth::legacy_client_fingerprint(&client_ip, user_agent);
    let session_check = crate::auth::verify_active_session_on_conn(
        &conn,
        claims.user_id,
        &claims.jti,
        claims.ver,
        Utc::now().timestamp(),
        crate::auth::RotationGrace::StrictFingerprint(&caller_strict_fp),
    );
    match session_check {
        Ok(_) => {}
        Err(crate::auth::SessionValidationError::DbError) => return oidc_server_error(),
        Err(
            crate::auth::SessionValidationError::Suspended
            | crate::auth::SessionValidationError::MissingOrRevoked,
        ) => {
            let return_to = urlencoding::encode(full_uri);
            return Redirect::temporary(&format!("/login?return_to={}", return_to)).into_response();
        }
    }
    let session_family_id =
        crate::auth::resolve_session_family_id(&conn, claims.user_id, &claims.jti);
    let validated_scope = validate_oidc_scopes(&q.scope);
    let existing_consent =
        match has_existing_consent_in_conn(&conn, claims.user_id, &q.client_id, &validated_scope) {
            Ok(consented) => consented,
            Err(_) => return oidc_server_error(),
        };
    drop(conn);

    if existing_consent {
        let Ok(code) = generate_and_store_auth_code(
            &q.client_id,
            claims.user_id,
            &q.redirect_uri,
            &validated_scope,
            &q.code_challenge,
            &q.code_challenge_method,
            &q.nonce,
            Some(&session_family_id),
        ) else {
            return oidc_server_error();
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
        let Ok(conn) = af_db::get_read_conn() else {
            return oidc_server_error();
        };
        let stored_uris = match conn
            .query_row(
                "SELECT redirect_uris FROM oidc_clients WHERE id = ?1",
                params![payload.client_id],
                |r| r.get::<_, String>(0),
            )
            .optional()
        {
            Ok(Some(uris)) => uris,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_client_or_redirect_uri" })),
                )
                    .into_response();
            }
            Err(_) => return oidc_server_error(),
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

    let stored_uris = match tx
        .query_row(
            "SELECT redirect_uris FROM oidc_clients WHERE id = ?1",
            params![payload.client_id],
            |r| r.get::<_, String>(0),
        )
        .optional()
    {
        Ok(Some(uris)) => uris,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_client_or_redirect_uri" })),
            )
                .into_response();
        }
        Err(_) => return oidc_server_error(),
    };

    if !is_allowed_redirect_uri(&payload.redirect_uri, &stored_uris) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_client_or_redirect_uri" })),
        )
            .into_response();
    }

    if let Err(desc) =
        validate_pkce_request_params(&payload.code_challenge, &payload.code_challenge_method)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": desc,
            })),
        )
            .into_response();
    }

    let session_family_id = crate::auth::resolve_session_family_id(&tx, user.user_id, &user.jti);
    let scope = validate_oidc_scopes(&payload.scope);
    let Ok(code) = generate_and_store_auth_code_in_conn(
        &tx,
        &payload.client_id,
        user.user_id,
        &payload.redirect_uri,
        &scope,
        &payload.code_challenge,
        &payload.code_challenge_method,
        &payload.nonce,
        Some(&session_family_id),
    ) else {
        return oidc_server_error();
    };

    if record_consent_in_tx(&tx, user.user_id, &payload.client_id, &scope).is_err()
        || tx.commit().is_err()
    {
        return oidc_server_error();
    }

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
