use super::authorize::{
    is_oidc_grant_revoked, oidc_code_family_id, oidc_device_family_id, validate_oidc_scopes,
};
use super::keys::{get_oidc_issuer_for_peer, oidc_server_error, OIDC_KEYS};
use crate::auth::{api_error, blocking_response, SubjectStatusError};
use axum::extract::Form;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, Algorithm, Header};
use rand::RngCore;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let mut auth_headers = headers.get_all(header::AUTHORIZATION).iter();
    let auth = auth_headers.next()?.to_str().ok()?.trim();
    if auth_headers.next().is_some() {
        return None;
    }
    let (scheme, rest) = auth.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = BASE64_STD.decode(rest.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((id.to_string(), secret.to_string()))
}

pub(super) fn invalid_oidc_client_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"oidc\"")],
        Json(serde_json::json!({ "error": "invalid_client" })),
    )
        .into_response()
}

pub(super) enum ClientCredentialError {
    Ambiguous(&'static str),
    InvalidClient,
}

impl IntoResponse for ClientCredentialError {
    fn into_response(self) -> Response {
        match self {
            Self::Ambiguous(description) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_request",
                    "error_description": description
                })),
            )
                .into_response(),
            Self::InvalidClient => invalid_oidc_client_response(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClientAuthError {
    InvalidClient,
    ServerError,
}

impl IntoResponse for ClientAuthError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidClient => invalid_oidc_client_response(),
            Self::ServerError => oidc_server_error(),
        }
    }
}

pub(super) fn extract_oidc_client_credentials(
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Result<(String, String), ClientCredentialError> {
    let auth_count = headers.get_all(header::AUTHORIZATION).iter().count();
    if auth_count > 1 {
        return Err(ClientCredentialError::Ambiguous(
            "multiple Authorization headers",
        ));
    }
    if auth_count == 1 {
        if form.contains_key("client_id") || form.contains_key("client_secret") {
            return Err(ClientCredentialError::Ambiguous(
                "multiple client authentication methods",
            ));
        }
        return extract_basic_auth(headers).ok_or(ClientCredentialError::InvalidClient);
    }
    let client_id = form.get("client_id").cloned().unwrap_or_default();
    let client_secret = form.get("client_secret").cloned().unwrap_or_default();
    Ok((client_id, client_secret))
}

pub(super) fn authenticate_oidc_client(
    client_id: &str,
    client_secret: &str,
    allow_public: bool,
) -> Result<bool, ClientAuthError> {
    if client_id.is_empty() {
        return Err(ClientAuthError::InvalidClient);
    }
    let Ok(conn) = af_db::get_read_conn() else {
        return Err(ClientAuthError::ServerError);
    };
    let stored_hash = match conn
        .query_row(
            "SELECT COALESCE(client_secret_hash, '') FROM oidc_clients WHERE id = ?1",
            params![client_id],
            |r| r.get::<_, String>(0),
        )
        .optional()
    {
        Ok(Some(hash)) => hash,
        Ok(None) => return Err(ClientAuthError::InvalidClient),
        Err(_) => return Err(ClientAuthError::ServerError),
    };
    if stored_hash.trim().is_empty() {
        if allow_public && client_secret.is_empty() {
            return Ok(true);
        }
        return Err(ClientAuthError::InvalidClient);
    }
    if client_secret.is_empty() {
        return Err(ClientAuthError::InvalidClient);
    }
    let mut hasher = Sha256::new();
    hasher.update(client_secret.as_bytes());
    let computed = hex::encode(hasher.finalize());
    if af_services::cluster_daemon::constant_time_eq(computed.as_bytes(), stored_hash.as_bytes()) {
        Ok(false)
    } else {
        Err(ClientAuthError::InvalidClient)
    }
}

pub(super) fn verify_pkce(verifier: &str, challenge: &str, method: &str) -> bool {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        || challenge.len() != 43
        || !challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || method != "S256"
    {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hasher.finalize());
    af_services::cluster_daemon::constant_time_eq(computed.as_bytes(), challenge.as_bytes())
}

#[derive(Serialize, Deserialize)]
pub(super) struct IdTokenClaims {
    pub(super) iss: String,
    pub(super) sub: String,
    pub(super) aud: String,
    pub(super) exp: i64,
    pub(super) iat: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) picture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) nonce: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct AccessTokenClaims {
    pub(super) iss: String,
    pub(super) sub: String,
    pub(super) aud: String,
    pub(super) exp: i64,
    pub(super) iat: i64,
    pub(super) scope: String,
    #[serde(default)]
    pub(super) jti: String,
    #[serde(default)]
    pub(super) ver: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(super) fam: String,
}

#[allow(clippy::result_large_err, clippy::too_many_arguments)]
pub(super) fn issue_oidc_tokens_in_tx(
    conn: &rusqlite::Connection,
    headers: &HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
    client_id: &str,
    user_id: i64,
    scope: &str,
    nonce: Option<&str>,
    family_id: Option<&str>,
) -> Result<serde_json::Value, Response> {
    let Some(keys) = OIDC_KEYS.as_ref() else {
        return Err(oidc_server_error());
    };

    let active_subj = match crate::auth::load_active_human_subject(conn, user_id) {
        Ok(subj) => subj,
        Err(SubjectStatusError::DbError) => return Err(oidc_server_error()),
        Err(SubjectStatusError::MissingOrPlugin | SubjectStatusError::Suspended) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_grant" })),
            )
                .into_response());
        }
    };

    let Ok((username, email, avatar_url, role)) = conn.query_row(
        "SELECT username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user') FROM users WHERE id = ?1",
        params![user_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?)),
    ) else {
        return Err(oidc_server_error());
    };

    let issuer = get_oidc_issuer_for_peer(headers, peer_ip);
    let now = Utc::now().timestamp();
    let exp = now + 3600;

    let validated_scope = validate_oidc_scopes(scope);
    let granted_scopes: HashSet<&str> = validated_scope.split_whitespace().collect();
    let include_profile = granted_scopes.contains("profile");
    let include_email = granted_scopes.contains("email");

    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some(keys.kid.clone());

    let id_claims = IdTokenClaims {
        iss: issuer.clone(),
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        exp,
        iat: now,
        name: include_profile.then_some(username),
        email: include_email.then_some(email),
        picture: include_profile.then_some(avatar_url),
        role: include_profile.then_some(role),
        nonce: nonce.filter(|v| !v.is_empty()).map(str::to_string),
    };

    let mut refresh_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut refresh_bytes);
    let refresh_token = hex::encode(refresh_bytes);
    let refresh_exp = (Utc::now() + Duration::days(30)).to_rfc3339();
    let effective_family = family_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&refresh_token)
        .to_string();

    let access_claims = AccessTokenClaims {
        iss: issuer,
        sub: user_id.to_string(),
        aud: client_id.to_string(),
        exp,
        iat: now,
        scope: validated_scope.clone(),
        jti: uuid::Uuid::new_v4().to_string(),
        ver: active_subj.sessions_revoked_after,
        fam: effective_family.clone(),
    };

    let Ok(id_token) = encode(&jwt_header, &id_claims, &keys.encoding_key) else {
        return Err(oidc_server_error());
    };

    let Ok(access_token) = encode(&jwt_header, &access_claims, &keys.encoding_key) else {
        return Err(oidc_server_error());
    };

    let has_family = match crate::auth::column_exists(conn, "oidc_refresh_tokens", "family_id") {
        Ok(v) => v,
        Err(_) => {
            return Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to persist OIDC refresh token",
            ));
        }
    };
    let insert_res = if has_family {
        conn.execute(
            "INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at, family_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                refresh_token,
                client_id,
                user_id,
                validated_scope,
                refresh_exp,
                &effective_family
            ],
        )
    } else {
        conn.execute(
            "INSERT INTO oidc_refresh_tokens (token, client_id, user_id, scope, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                refresh_token,
                client_id,
                user_id,
                validated_scope,
                refresh_exp
            ],
        )
    };
    if insert_res.is_err() {
        return Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to persist OIDC refresh token",
        ));
    }

    Ok(serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "scope": validated_scope,
    }))
}

pub(super) fn consume_device_code(
    conn: &rusqlite::Connection,
    code: &str,
    client_id: &str,
) -> rusqlite::Result<Option<(i64, String)>> {
    conn.query_row(
        "DELETE FROM oidc_device_codes WHERE device_code = ?1 AND client_id = ?2 AND status = 'approved' AND user_id IS NOT NULL AND expires_at > ?3 RETURNING user_id, scope",
        params![code, client_id, Utc::now().to_rfc3339()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

pub async fn oidc_token(
    crate::ws::PeerIp(peer_ip): crate::ws::PeerIp,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    blocking_response(move || oidc_token_blocking(headers, peer_ip, form)).await
}

fn oidc_token_blocking(
    headers: HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
    form: HashMap<String, String>,
) -> Response {
    let grant_type = form.get("grant_type").cloned().unwrap_or_default();
    let (client_id, client_secret) = match extract_oidc_client_credentials(&headers, &form) {
        Ok(creds) => creds,
        Err(err) => return err.into_response(),
    };

    let is_public_client = match authenticate_oidc_client(&client_id, &client_secret, true) {
        Ok(is_public) => is_public,
        Err(err) => return err.into_response(),
    };

    match grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(&headers, peer_ip, &client_id, &form),
        "refresh_token" => exchange_refresh_token(&headers, peer_ip, &client_id, &form),
        "urn:ietf:params:oauth:grant-type:device_code" => {
            if is_public_client {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "invalid_client" })),
                )
                    .into_response();
            }
            exchange_device_code(&headers, peer_ip, &client_id, &form)
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "unsupported_grant_type" })),
        )
            .into_response(),
    }
}

fn revoke_replayed_auth_code_family(
    tx: rusqlite::Transaction<'_>,
    user_id: i64,
    client_id: &str,
    code_family: &str,
    fam_marker: &str,
) -> Response {
    let has_family = match crate::auth::column_exists(&tx, "oidc_refresh_tokens", "family_id") {
        Ok(v) => v,
        Err(_) => return oidc_server_error(),
    };
    if has_family
        && tx
            .execute(
                "UPDATE oidc_refresh_tokens SET revoked = 1 \
                 WHERE user_id = ?1 AND client_id = ?2 AND family_id = ?3",
                params![user_id, client_id, code_family],
            )
            .is_err()
    {
        return oidc_server_error();
    }
    if af_db::revoke_token_in_tx(&tx, fam_marker, std::time::Duration::from_secs(8160)).is_err()
        || tx.commit().is_err()
    {
        return oidc_server_error();
    }
    af_db::cache_revoked_token(fam_marker, std::time::Duration::from_secs(8160));
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "code already used"
        })),
    )
        .into_response()
}

fn exchange_authorization_code(
    headers: &HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
    client_id: &str,
    form: &HashMap<String, String>,
) -> Response {
    let code = form.get("code").cloned().unwrap_or_default();
    let redirect_uri = form.get("redirect_uri").cloned().unwrap_or_default();
    let code_verifier = form.get("code_verifier").cloned().unwrap_or_default();

    let Ok(mut conn) = af_db::get_conn() else {
        return oidc_server_error();
    };
    let Ok(tx) = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) else {
        return oidc_server_error();
    };

    let row = match tx
        .query_row(
            "SELECT client_id, user_id, redirect_uri, scope, COALESCE(code_challenge, ''), COALESCE(code_challenge_method, ''), expires_at, used, COALESCE(nonce, '') \
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
        .optional()
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_grant" })),
            )
                .into_response();
        }
        Err(_) => return oidc_server_error(),
    };
    let (
        stored_client,
        user_id,
        stored_redirect,
        scope,
        challenge,
        challenge_method,
        expires_at,
        used,
        nonce,
    ) = row;

    if stored_client != client_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_grant" })),
        )
            .into_response();
    }

    let code_family = oidc_code_family_id(&code);
    let fam_marker = format!("oidc-fam:{}", code_family);

    if used {
        return revoke_replayed_auth_code_family(tx, user_id, client_id, &code_family, &fam_marker);
    }

    if stored_redirect != redirect_uri || is_oidc_grant_revoked(&code_family) {
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

    if challenge.trim().is_empty() || !verify_pkce(&code_verifier, &challenge, &challenge_method) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "PKCE S256 verification failed"
            })),
        )
            .into_response();
    }

    let affected = match tx.execute(
        "UPDATE oidc_auth_codes SET used = 1 WHERE code = ?1 AND used = 0",
        params![code],
    ) {
        Ok(n) => n,
        Err(_) => return oidc_server_error(),
    };
    if affected == 0 {
        return revoke_replayed_auth_code_family(tx, user_id, client_id, &code_family, &fam_marker);
    }

    let payload = match issue_oidc_tokens_in_tx(
        &tx,
        headers,
        peer_ip,
        client_id,
        user_id,
        &scope,
        Some(&nonce),
        Some(&code_family),
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if tx.commit().is_err() {
        return oidc_server_error();
    }
    Json(payload).into_response()
}

fn exchange_refresh_token(
    headers: &HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
    client_id: &str,
    form: &HashMap<String, String>,
) -> Response {
    let refresh_token = form.get("refresh_token").cloned().unwrap_or_default();
    let Ok(mut conn) = af_db::get_conn() else {
        return oidc_server_error();
    };
    let Ok(tx) = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) else {
        return oidc_server_error();
    };

    let has_family = match crate::auth::column_exists(&tx, "oidc_refresh_tokens", "family_id") {
        Ok(v) => v,
        Err(_) => return oidc_server_error(),
    };
    let select_sql = if has_family {
        "SELECT client_id, user_id, scope, expires_at, revoked, COALESCE(family_id, '') FROM oidc_refresh_tokens WHERE token = ?1"
    } else {
        "SELECT client_id, user_id, scope, expires_at, revoked, '' FROM oidc_refresh_tokens WHERE token = ?1"
    };
    let row = match tx
        .query_row(select_sql, params![refresh_token], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, bool>(4)?,
                r.get::<_, String>(5)?,
            ))
        })
        .optional()
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_grant" })),
            )
                .into_response();
        }
        Err(_) => return oidc_server_error(),
    };
    let (stored_client, user_id, scope, expires_at, revoked, stored_family) = row;

    if stored_client != client_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_grant" })),
        )
            .into_response();
    }

    let effective_family = if stored_family.trim().is_empty() {
        refresh_token.clone()
    } else {
        stored_family
    };
    let fam_marker = format!("oidc-fam:{}", effective_family);

    if is_oidc_grant_revoked(&effective_family) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_grant" })),
        )
            .into_response();
    }

    if revoked {
        let revoke_res = if has_family {
            tx.execute(
                "UPDATE oidc_refresh_tokens SET revoked = 1 \
                 WHERE user_id = ?1 AND client_id = ?2 AND (family_id = ?3 OR token = ?3)",
                params![user_id, client_id, effective_family],
            )
        } else {
            tx.execute(
                "UPDATE oidc_refresh_tokens SET revoked = 1 \
                 WHERE user_id = ?1 AND client_id = ?2",
                params![user_id, client_id],
            )
        };
        if revoke_res.is_err()
            || af_db::revoke_token_in_tx(&tx, &fam_marker, std::time::Duration::from_secs(8160))
                .is_err()
            || tx.commit().is_err()
        {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to revoke compromised refresh token family",
            );
        }
        af_db::cache_revoked_token(&fam_marker, std::time::Duration::from_secs(8160));
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "refresh token reuse detected"
            })),
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

    let affected = match tx.execute(
        "UPDATE oidc_refresh_tokens SET revoked = 1 WHERE token = ?1 AND revoked = 0",
        params![refresh_token],
    ) {
        Ok(n) => n,
        Err(_) => return oidc_server_error(),
    };
    if affected == 0 {
        if has_family
            && tx
                .execute(
                    "UPDATE oidc_refresh_tokens SET revoked = 1 \
                     WHERE user_id = ?1 AND client_id = ?2 AND (family_id = ?3 OR token = ?3)",
                    params![user_id, client_id, effective_family],
                )
                .is_err()
        {
            return oidc_server_error();
        }
        if af_db::revoke_token_in_tx(&tx, &fam_marker, std::time::Duration::from_secs(8160))
            .is_err()
            || tx.commit().is_err()
        {
            return oidc_server_error();
        }
        af_db::cache_revoked_token(&fam_marker, std::time::Duration::from_secs(8160));
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "token already consumed"
            })),
        )
            .into_response();
    }

    let payload = match issue_oidc_tokens_in_tx(
        &tx,
        headers,
        peer_ip,
        client_id,
        user_id,
        &scope,
        None,
        Some(&effective_family),
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if tx.commit().is_err() {
        return oidc_server_error();
    }
    Json(payload).into_response()
}

fn exchange_device_code(
    headers: &HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
    client_id: &str,
    form: &HashMap<String, String>,
) -> Response {
    let device_code = form.get("device_code").cloned().unwrap_or_default();
    let Ok(mut conn) = af_db::get_conn() else {
        return oidc_server_error();
    };
    let Ok(tx) = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) else {
        return oidc_server_error();
    };

    let row = match tx
        .query_row(
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
        )
        .optional()
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_grant" })),
            )
                .into_response();
        }
        Err(_) => return oidc_server_error(),
    };
    let (stored_client, user_id_opt, scope, expires_at, status) = row;

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
                return oidc_server_error();
            };
            match consume_device_code(&tx, &device_code, client_id) {
                Ok(Some((consumed_uid, _))) if consumed_uid == uid => {}
                Ok(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "invalid_grant" })),
                    )
                        .into_response();
                }
                Err(_) => return oidc_server_error(),
            }
            let dc_family = oidc_device_family_id(&device_code);
            let granted_scope = validate_oidc_scopes(&scope);
            let payload = match issue_oidc_tokens_in_tx(
                &tx,
                headers,
                peer_ip,
                client_id,
                uid,
                &granted_scope,
                None,
                Some(&dc_family),
            ) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            if tx.commit().is_err() {
                return oidc_server_error();
            }
            Json(payload).into_response()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_grant" })),
        )
            .into_response(),
    }
}
