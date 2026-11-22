use super::authorize::is_oidc_grant_revoked;
use super::keys::{is_accepted_oidc_issuer, oidc_server_error, OIDC_KEYS};
use super::token_endpoint::{
    authenticate_oidc_client, extract_oidc_client_credentials, AccessTokenClaims,
};
use crate::auth::blocking_response;
use axum::extract::Form;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Algorithm, Validation};
use rusqlite::{params, OptionalExtension};
use std::collections::{HashMap, HashSet};

pub async fn oidc_userinfo(
    crate::ws::PeerIp(peer_ip): crate::ws::PeerIp,
    headers: HeaderMap,
) -> Response {
    blocking_response(move || oidc_userinfo_blocking(headers, peer_ip)).await
}

fn oidc_userinfo_blocking(headers: HeaderMap, peer_ip: Option<std::net::IpAddr>) -> Response {
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
    if token_data.claims.jti.is_empty()
        || af_db::is_token_revoked(&token_data.claims.jti)
        || is_oidc_grant_revoked(&token_data.claims.fam)
        || !is_accepted_oidc_issuer(&token_data.claims.iss, &headers, peer_ip)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_token" })),
        )
            .into_response();
    }

    let granted_scopes: HashSet<&str> = token_data.claims.scope.split_whitespace().collect();
    if !granted_scopes.contains("openid") {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "insufficient_scope",
                "error_description": "openid scope required"
            })),
        )
            .into_response();
    }

    let sub = token_data.claims.sub;
    let Ok(conn) = af_db::get_read_conn() else {
        return oidc_server_error();
    };
    if !oidc_client_exists(&conn, &token_data.claims.aud)
        || !access_token_subject_valid(&conn, &sub, token_data.claims.ver)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_token" })),
        )
            .into_response();
    }

    let user_row = match conn
        .query_row(
            "SELECT username, COALESCE(email, ''), COALESCE(avatar_url, ''), COALESCE(role, 'user') FROM users WHERE id = ?1",
            params![sub],
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
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_token",
                    "error_description": "user not found"
                })),
            )
                .into_response();
        }
        Err(_) => return oidc_server_error(),
    };
    let (username, email, avatar_url, role) = user_row;

    let mut claims_obj = serde_json::Map::new();
    claims_obj.insert("sub".to_string(), serde_json::json!(sub));
    if granted_scopes.contains("profile") {
        claims_obj.insert("name".to_string(), serde_json::json!(username));
        claims_obj.insert("picture".to_string(), serde_json::json!(avatar_url));
        claims_obj.insert("role".to_string(), serde_json::json!(role));
    }
    if granted_scopes.contains("email") {
        claims_obj.insert("email".to_string(), serde_json::json!(email));
    }
    Json(serde_json::Value::Object(claims_obj)).into_response()
}

pub async fn oidc_revoke(
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    blocking_response(move || oidc_revoke_blocking(headers, form)).await
}

fn oidc_revoke_blocking(headers: HeaderMap, form: HashMap<String, String>) -> Response {
    let (client_id, client_secret) = match extract_oidc_client_credentials(&headers, &form) {
        Ok(creds) => creds,
        Err(err) => return err.into_response(),
    };
    if client_id.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"oidc\"")],
            Json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "client authentication required"
            })),
        )
            .into_response();
    }
    if let Err(err) = authenticate_oidc_client(&client_id, &client_secret, true) {
        return err.into_response();
    }

    let token = form.get("token").cloned().unwrap_or_default();
    if token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_request" })),
        )
            .into_response();
    }

    if let Some(keys) = OIDC_KEYS.as_ref() {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        if let Ok(data) = decode::<AccessTokenClaims>(token.trim(), &keys.decoding_key, &validation)
        {
            if data.claims.aud == client_id
                && !data.claims.jti.is_empty()
                && af_db::revoke_token(&data.claims.jti, std::time::Duration::from_secs(8160))
                    .is_err()
            {
                return oidc_server_error();
            }
        }
    }

    let Ok(mut conn) = af_db::get_conn() else {
        return oidc_server_error();
    };
    let Ok(tx) = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) else {
        return oidc_server_error();
    };
    let has_fam_col = match crate::auth::column_exists(&tx, "oidc_refresh_tokens", "family_id") {
        Ok(v) => v,
        Err(_) => return oidc_server_error(),
    };
    let revoked_family = if has_fam_col {
        match tx
            .query_row(
                "SELECT COALESCE(family_id, '') FROM oidc_refresh_tokens WHERE token = ?1 AND client_id = ?2",
                params![token, client_id],
                |r| r.get::<_, String>(0),
            )
            .optional()
        {
            Ok(opt) => opt.map(|f| {
                if f.trim().is_empty() {
                    token.clone()
                } else {
                    f
                }
            }),
            Err(_) => return oidc_server_error(),
        }
    } else {
        match tx
            .query_row(
                "SELECT token FROM oidc_refresh_tokens WHERE token = ?1 AND client_id = ?2",
                params![token, client_id],
                |r| r.get::<_, String>(0),
            )
            .optional()
        {
            Ok(opt) => opt,
            Err(_) => return oidc_server_error(),
        }
    };
    let revoke_sql = if has_fam_col {
        "UPDATE oidc_refresh_tokens SET revoked = 1 \
         WHERE client_id = ?2 AND (token = ?1 OR (COALESCE(family_id, '') != '' AND family_id IN \
         (SELECT family_id FROM oidc_refresh_tokens WHERE token = ?1 AND client_id = ?2)))"
    } else {
        "UPDATE oidc_refresh_tokens SET revoked = 1 WHERE token = ?1 AND client_id = ?2"
    };
    if tx.execute(revoke_sql, params![token, client_id]).is_err() {
        return oidc_server_error();
    }
    let mut cached_fam_marker: Option<String> = None;
    if let Some(fam) = revoked_family.filter(|s| !s.trim().is_empty()) {
        let marker = format!("oidc-fam:{}", fam.trim());
        if af_db::revoke_token_in_tx(&tx, &marker, std::time::Duration::from_secs(8160)).is_err() {
            return oidc_server_error();
        }
        cached_fam_marker = Some(marker);
    }
    if tx.commit().is_err() {
        return oidc_server_error();
    }
    if let Some(marker) = cached_fam_marker {
        af_db::cache_revoked_token(&marker, std::time::Duration::from_secs(8160));
    }
    Json(serde_json::json!({})).into_response()
}

fn oidc_client_exists(conn: &rusqlite::Connection, client_id: &str) -> bool {
    if client_id.trim().is_empty() {
        return false;
    }
    match crate::auth::table_exists(conn, "oidc_clients") {
        Ok(false) => return true,
        Err(_) => return false,
        Ok(true) => {}
    }
    conn.query_row(
        "SELECT 1 FROM oidc_clients WHERE id = ?1",
        params![client_id],
        |_| Ok(()),
    )
    .is_ok()
}

fn access_token_subject_valid(
    connection: &rusqlite::Connection,
    subject: &str,
    token_ver: i64,
) -> bool {
    let Ok(user_id) = subject.parse::<i64>() else {
        return false;
    };
    if user_id <= 0
        || connection
            .query_row("SELECT 1 FROM users WHERE id = ?1", [user_id], |_| Ok(()))
            .is_err()
    {
        return false;
    }
    crate::auth::load_active_human_subject(connection, user_id)
        .is_ok_and(|subj| token_ver >= subj.sessions_revoked_after)
}

#[cfg(test)]
pub(super) fn access_token_subject_exists(
    connection: &rusqlite::Connection,
    subject: &str,
) -> bool {
    access_token_subject_valid(connection, subject, 0)
}

pub async fn oidc_introspect(
    crate::ws::PeerIp(peer_ip): crate::ws::PeerIp,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    blocking_response(move || oidc_introspect_blocking(headers, peer_ip, form)).await
}

fn oidc_introspect_blocking(
    headers: HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
    form: HashMap<String, String>,
) -> Response {
    let (client_id, client_secret) = match extract_oidc_client_credentials(&headers, &form) {
        Ok(creds) => creds,
        Err(err) => return err.into_response(),
    };
    if client_id.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"oidc\"")],
            Json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "client authentication required"
            })),
        )
            .into_response();
    }
    if let Err(err) = authenticate_oidc_client(&client_id, &client_secret, false) {
        return err.into_response();
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
                let token_valid = !data.claims.jti.is_empty()
                    && !af_db::is_token_revoked(&data.claims.jti)
                    && !is_oidc_grant_revoked(&data.claims.fam)
                    && af_db::get_read_conn().ok().is_some_and(|connection| {
                        oidc_client_exists(&connection, &data.claims.aud)
                            && access_token_subject_valid(
                                &connection,
                                &data.claims.sub,
                                data.claims.ver,
                            )
                    });
                if data.claims.aud == client_id
                    && is_accepted_oidc_issuer(&data.claims.iss, &headers, peer_ip)
                    && token_valid
                {
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
            if let Ok(has_fam_col) =
                crate::auth::column_exists(&conn, "oidc_refresh_tokens", "family_id")
            {
                let rt_sql = if has_fam_col {
                    "SELECT user_id, scope, revoked, expires_at, COALESCE(family_id, '') FROM oidc_refresh_tokens WHERE token = ?1 AND client_id = ?2"
                } else {
                    "SELECT user_id, scope, revoked, expires_at, '' FROM oidc_refresh_tokens WHERE token = ?1 AND client_id = ?2"
                };
                if let Ok((user_id, scope, revoked, expires_at, rt_family)) =
                    conn.query_row(rt_sql, params![token_str, client_id], |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, bool>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, String>(4)?,
                        ))
                    })
                {
                    let expired = DateTime::parse_from_rfc3339(&expires_at)
                        .map(|dt| Utc::now() > dt.with_timezone(&Utc))
                        .unwrap_or(true);
                    let user_active = oidc_client_exists(&conn, &client_id)
                        && crate::auth::load_active_human_subject(&conn, user_id).is_ok();
                    let eff_fam = if rt_family.trim().is_empty() {
                        token_str.clone()
                    } else {
                        rt_family
                    };
                    if !revoked && !is_oidc_grant_revoked(&eff_fam) && !expired && user_active {
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
    }

    Json(serde_json::json!({ "active": false })).into_response()
}
