use super::revocation::{
    evict_rotation_grace_for_family, oidc_session_tag, resolve_current_session_jti,
    resolve_latest_grace_token, revoke_session_family_in_tx, RotatedTokenGraceEntry,
    MIN_REVOCATION_TTL, ROTATED_SESSION_SUCCESSOR, ROTATED_TOKEN_GRACE, ROTATED_TOKEN_GRACE_WINDOW,
};
use super::tokens::{
    api_error, blocking_response, column_exists, create_session_jwt_in_conn, decode_session_claims,
    legacy_client_fingerprint, load_active_human_subject, matches_client_fingerprint,
    resolve_raw_token, secure_cookie_enabled, session_auth_time, table_exists,
    verify_active_session_on_conn, AuthUser, RotationGrace, SessionValidationError,
    SubjectStatusError, SESSION_COOKIE_MAX_AGE,
};
use crate::ws::{build_set_cookie, extract_client_ip, extract_cookie};
use axum::extract::{Path, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use std::time::{Duration, Instant};

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
            af_db::prune_expired_active_sessions(&tx, Utc::now().timestamp())?;
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
    // A cookie can accompany a form submission from a sibling app. The
    // dashboard sends this header even when its CSRF token needs renewal.
    // A cross-origin browser request needs an allowed CORS preflight to set it.
    if !headers.contains_key(header::AUTHORIZATION)
        && extract_cookie(&headers, "aetherflow_session").is_some()
        && !headers
            .get("x-requested-with")
            .is_some_and(|value| value == "XMLHttpRequest")
    {
        return api_error(
            StatusCode::FORBIDDEN,
            "REFRESH_HEADER_REQUIRED",
            "Cookie session refresh requires X-Requested-With: XMLHttpRequest",
        );
    }
    blocking_response(move || refresh_session_for_peer_blocking(headers, peer_ip)).await
}

#[cfg(test)]
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
        Ok(true) => true,
        Ok(false) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Session is no longer active",
            );
        }
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to inspect active sessions",
            );
        }
    };
    let has_family = match column_exists(&tx, "active_sessions", "family_id") {
        Ok(v) => v,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to inspect session schema",
            );
        }
    };
    let existing_family_opt: Option<String> = {
        let query_res = if has_family {
            tx.query_row(
                "SELECT COALESCE(family_id, '') FROM active_sessions \
                 WHERE jti = ?1 AND user_id = ?2 AND unixepoch(expires_at, 'auto') > ?3",
                params![claims.jti, subj.user_id, now],
                |r| r.get(0),
            )
            .optional()
        } else {
            tx.query_row(
                "SELECT jti FROM active_sessions \
                 WHERE jti = ?1 AND user_id = ?2 AND unixepoch(expires_at, 'auto') > ?3",
                params![claims.jti, subj.user_id, now],
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
                    && af_db::has_unexpired_active_session(&tx, &leaf_succ, subj.user_id, now)
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
        let wipe_outcome = (|| -> anyhow::Result<()> {
            if resolved_family.is_none() {
                resolved_family =
                    af_db::resolve_revoked_token_family_in_tx(&tx, &claims.jti, subj.user_id)?;
            }
            if resolved_family.is_none() {
                resolved_family = ROTATED_TOKEN_GRACE
                    .lock()
                    .ok()
                    .and_then(|map| map.get(&claims.jti).cloned())
                    .filter(|e| e.user_id == subj.user_id && !e.family_id.trim().is_empty())
                    .map(|e| e.family_id);
            }
            if has_sessions_table {
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
                if table_exists(&tx, "oidc_refresh_tokens")?
                    && column_exists(&tx, "oidc_refresh_tokens", "family_id")?
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

    let Some(existing_family) = existing_family_opt else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Session is no longer active",
        );
    };

    let family_id = {
        let trimmed = existing_family.trim();
        if trimmed.is_empty() {
            claims.jti.clone()
        } else {
            trimmed.to_string()
        }
    };

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
    if has_sessions_table
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
    let client_ip = extract_client_ip(&headers);
    if !matches_client_fingerprint(&claims.cfp, &client_ip, user_agent) {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid or revoked session",
        );
    }
    let caller_strict_fp = legacy_client_fingerprint(&client_ip, user_agent);
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SESSION_UNAVAILABLE",
            "Unable to validate session",
        );
    };
    let subj = match verify_active_session_on_conn(
        &conn,
        claims.user_id,
        &claims.jti,
        claims.ver,
        Utc::now().timestamp(),
        RotationGrace::StrictFingerprint(&caller_strict_fp),
    ) {
        Ok(subj) => subj,
        Err(SessionValidationError::Suspended) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Account is not active" })),
            )
                .into_response();
        }
        Err(SessionValidationError::MissingOrRevoked) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Invalid or revoked session",
            );
        }
        Err(SessionValidationError::DbError) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SESSION_UNAVAILABLE",
                "Unable to validate session",
            );
        }
    };

    if subj.role != "admin" {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Administrator authentication required",
        );
    }

    let mut resp = StatusCode::OK.into_response();
    if let Ok(hv) = HeaderValue::from_str(&subj.username) {
        resp.headers_mut().insert("X-Aetherflow-User", hv.clone());
        resp.headers_mut().insert("Remote-User", hv);
    }
    resp
}

#[cfg(test)]
pub(super) fn is_session_active(
    conn: &rusqlite::Connection,
    jti: &str,
    user_id: i64,
) -> rusqlite::Result<bool> {
    af_db::has_unexpired_active_session(conn, jti, user_id, Utc::now().timestamp())
}

pub async fn list_active_sessions(req: Request) -> Response {
    blocking_response(move || list_active_sessions_blocking(req)).await
}

fn list_active_sessions_blocking(req: Request) -> Response {
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
    let mut stmt = match conn.prepare(
        "SELECT jti, COALESCE(ip_address, ''), COALESCE(user_agent, ''), \
         COALESCE(CAST(expires_at AS TEXT), ''), COALESCE(CAST(last_active AS TEXT), '') \
         FROM active_sessions WHERE user_id = ?1 AND unixepoch(expires_at, 'auto') > ?2 ORDER BY last_active DESC",
    ) {
        Ok(s) => s,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Query error",
            );
        }
    };

    let current_session_jti = resolve_current_session_jti(&auth_user.jti);
    let rows = match stmt.query_map(params![auth_user.user_id, Utc::now().timestamp()], |r| {
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
        Ok(rows) => rows,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Query error",
            );
        }
    };

    let mut sessions = Vec::new();
    for row in rows {
        match row {
            Ok(session) => sessions.push(session),
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Query error",
                );
            }
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
    let full_jti = match tx
        .query_row(
            "SELECT MIN(jti) FROM active_sessions WHERE substr(jti, 1, length(?1)) = ?1 AND user_id = ?2 HAVING COUNT(*) = 1",
            params![prefix, auth_user.user_id],
            |r| r.get::<_, String>(0),
        )
        .optional()
    {
        Ok(Some(jti)) => jti,
        Ok(None) => return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Session not found"),
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            );
        }
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
