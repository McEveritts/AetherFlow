use super::revocation::ROTATED_TOKEN_GRACE;
use super::tokens::{
    api_error, attach_logout_clear_cookie, blocking_auth_work, decode_session_claims,
    legacy_client_fingerprint, load_active_human_subject, matches_client_fingerprint,
    resolve_raw_token, secure_cookie_enabled, session_auth_time, verify_active_session_on_conn,
    ActiveSubject, AuthUser, PeerPrincipal, RotationGrace, SessionAuthTime, SessionValidationError,
    SubjectStatusError,
};
use crate::ws::{build_set_cookie, extract_client_ip, extract_cookie};
use axum::extract::Request;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use rand::RngCore;
use rusqlite::params;
use std::env;
use std::time::Instant;

fn is_refresh_path(path: &str) -> bool {
    matches!(
        path,
        "/api/v1/auth/refresh"
            | "/api/v1/public/auth/refresh"
            | "/api/auth/refresh"
            | "/api/public/auth/refresh"
    )
}

fn is_logout_path(path: &str) -> bool {
    matches!(path, "/api/v1/auth/logout" | "/api/auth/logout" | "/logout")
}

pub async fn auth_middleware(mut req: Request, next: Next) -> Response {
    if let Some(peer) = req.extensions().get::<PeerPrincipal>().cloned() {
        let valid_peer_user = req.extensions().get::<AuthUser>().is_some_and(|user| {
            user.user_id > 0
                && user.user_id == peer.run_as_user_id
                && user.username == peer.run_as_username
                && user.role == "admin"
                && user.plugin_id.is_none()
                && user.plugin_scopes.is_empty()
        });
        if !valid_peer_user
            || req
                .extensions()
                .get::<crate::plugins::PluginTokenClaims>()
                .is_some()
        {
            return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
        }
        req.extensions_mut().remove::<SessionAuthTime>();
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

    let method = req.method().clone();
    let is_logout = method == Method::POST && is_logout_path(&path);
    let headers = req.headers();
    let bearer_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|b| b.trim().to_string())
        .filter(|b| !b.is_empty());

    let Some(token) = resolve_raw_token(headers) else {
        let resp = api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
        return if is_logout {
            attach_logout_clear_cookie(resp)
        } else {
            resp
        };
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

    if is_logout {
        if crate::plugins::decode_and_verify_plugin_token(&token).is_ok() {
            return api_error(
                StatusCode::FORBIDDEN,
                "PLUGIN_SCOPE_DENIED",
                "Plugin tokens cannot revoke operator sessions",
            );
        }
        let Ok(claims) = decode_session_claims(&token, true) else {
            return attach_logout_clear_cookie(api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Unauthorized",
            ));
        };
        if !claims.plugin_id.trim().is_empty() || !claims.plugin_scopes.is_empty() {
            return api_error(
                StatusCode::FORBIDDEN,
                "PLUGIN_SCOPE_DENIED",
                "Plugin-scoped tokens cannot revoke operator sessions",
            );
        }
        let now = Utc::now().timestamp();
        if claims.user_id <= 0
            || claims.jti.trim().is_empty()
            || now.saturating_sub(claims.exp) > 7200
        {
            return attach_logout_clear_cookie(api_error(
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Unauthorized",
            ));
        }
        let req_peer_ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|axum::extract::ConnectInfo(addr)| addr.ip());
        let req_ua = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let peer_derived_ip = crate::ws::extract_client_ip_for_peer(req.headers(), req_peer_ip);
        let hdr_ip = extract_client_ip(req.headers());
        if !matches_client_fingerprint(&claims.cfp, &peer_derived_ip, req_ua)
            && !matches_client_fingerprint(&claims.cfp, &hdr_ip, req_ua)
        {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "SESSION_HIJACKED",
                "Session bound to a different client",
            );
        }
        let caller_strict_fp = legacy_client_fingerprint(&hdr_ip, req_ua);
        let check_uid = claims.user_id;
        let check_ver = claims.ver;
        let check_jti = claims.jti.clone();
        let logout_subject = blocking_auth_work(move || -> Result<ActiveSubject, StatusCode> {
            let conn = af_db::get_read_conn().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            let subj = match load_active_human_subject(&conn, check_uid) {
                Ok(s) => s,
                Err(SubjectStatusError::Suspended) => return Err(StatusCode::FORBIDDEN),
                Err(_) => return Err(StatusCode::UNAUTHORIZED),
            };
            if check_ver < subj.sessions_revoked_after {
                return Err(StatusCode::UNAUTHORIZED);
            }
            let revoked = af_db::token_revocation_status_with_conn(&conn, &check_jti)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if revoked {
                let in_grace = ROTATED_TOKEN_GRACE
                    .lock()
                    .ok()
                    .and_then(|map| map.get(&check_jti).cloned())
                    .is_some_and(|e| {
                        e.user_id == check_uid
                            && e.expires_at > Instant::now()
                            && (e.strict_fp.is_empty() || e.strict_fp == caller_strict_fp)
                    });
                if !in_grace {
                    let rotated_family_live = af_db::resolve_revoked_token_family_in_tx(
                        &conn, &check_jti, check_uid,
                    )
                    .ok()
                    .flatten()
                    .is_some_and(|fam| {
                        conn.query_row(
                            "SELECT EXISTS(SELECT 1 FROM active_sessions WHERE user_id = ?1 AND (family_id = ?2 OR jti = ?2))",
                            params![check_uid, fam],
                            |r| r.get::<_, bool>(0),
                        )
                        .unwrap_or(false)
                    });
                    if !rotated_family_live {
                        return Err(StatusCode::UNAUTHORIZED);
                    }
                }
            }
            Ok(subj)
        })
        .await;
        let subj = match logout_subject {
            Ok(Ok(subj)) => subj,
            Ok(Err(StatusCode::FORBIDDEN)) => {
                return attach_logout_clear_cookie(api_error(
                    StatusCode::FORBIDDEN,
                    "ACCOUNT_SUSPENDED",
                    "Account is not active",
                ));
            }
            _ => {
                return attach_logout_clear_cookie(api_error(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHORIZED",
                    "Unauthorized",
                ));
            }
        };
        req.extensions_mut().insert(AuthUser {
            user_id: claims.user_id,
            username: subj.username,
            role: subj.role,
            jti: claims.jti,
            plugin_id: None,
            plugin_scopes: Vec::new(),
        });
        return next.run(req).await;
    }

    let Ok(claims) = decode_session_claims(&token, false) else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };

    // Reject legacy session-signed plugin claims (`plugin_id` / `plugin_scopes`);
    // active plugins must authenticate via `crate::plugins::decode_and_verify_plugin_token`.
    if !claims.plugin_id.trim().is_empty() || !claims.plugin_scopes.is_empty() {
        return api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_SCOPE_DENIED",
            "Legacy session-scoped plugin tokens are no longer supported",
        );
    }

    let req_peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::ConnectInfo(addr)| addr.ip());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let hdr_ip = extract_client_ip(req.headers());
    let peer_ip = crate::ws::extract_client_ip_for_peer(req.headers(), req_peer_ip);
    if !matches_client_fingerprint(&claims.cfp, &hdr_ip, ua)
        && !matches_client_fingerprint(&claims.cfp, &peer_ip, ua)
    {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "SESSION_HIJACKED",
            "Session bound to a different client",
        );
    }

    let caller_strict_fp = legacy_client_fingerprint(&peer_ip, ua);
    let uid = claims.user_id;
    let jti = claims.jti.clone();
    let ver = claims.ver;
    let subject_res = blocking_auth_work(move || {
        let conn = af_db::get_read_conn().map_err(|_| SessionValidationError::DbError)?;
        verify_active_session_on_conn(
            &conn,
            uid,
            &jti,
            ver,
            Utc::now().timestamp(),
            RotationGrace::StrictFingerprint(&caller_strict_fp),
        )
    })
    .await;

    let subj = match subject_res {
        Ok(Ok(subj)) => subj,
        Ok(Err(SessionValidationError::Suspended)) => {
            return api_error(
                StatusCode::FORBIDDEN,
                "ACCOUNT_SUSPENDED",
                "Account is not active",
            );
        }
        Ok(Err(SessionValidationError::MissingOrRevoked)) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "SESSION_EXPIRED",
                "Session revoked",
            );
        }
        Ok(Err(SessionValidationError::DbError)) | Err(_) => {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SESSION_UNAVAILABLE",
                "Unable to validate session",
            );
        }
    };

    let verified_auth_time = session_auth_time(&claims);
    req.extensions_mut()
        .insert(SessionAuthTime(verified_auth_time));
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

pub(crate) fn require_admin(user: &AuthUser) -> Result<(), Box<Response>> {
    if user.role == "admin" && user.plugin_id.is_none() {
        return Ok(());
    }
    Err(Box::new(api_error(
        StatusCode::FORBIDDEN,
        "FORBIDDEN",
        "Admin access required",
    )))
}

pub async fn admin_only_middleware(req: Request, next: Next) -> Response {
    if req
        .extensions()
        .get::<crate::plugins::PluginTokenClaims>()
        .is_some()
    {
        return api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_SCOPE_DENIED",
            "Admin endpoints require an administrator session",
        );
    }
    let Some(user) = req.extensions().get::<AuthUser>() else {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    };
    if let Err(response) = require_admin(user) {
        return *response;
    }
    next.run(req).await
}

pub(crate) fn is_production_or_release_env(val: &str) -> bool {
    let trimmed = val.trim();
    trimmed.eq_ignore_ascii_case("production") || trimmed.eq_ignore_ascii_case("release")
}

pub(super) fn is_csrf_disabled_for_env(
    csrf_disabled: Option<&str>,
    aetherflow_env: Option<&str>,
) -> bool {
    let disabled = csrf_disabled
        .map(|v| v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !disabled {
        return false;
    }
    if aetherflow_env.is_some_and(is_production_or_release_env) {
        tracing::warn!("CSRF_DISABLED=true ignored because AETHERFLOW_ENV is production/release");
        return false;
    }
    true
}

pub async fn csrf_middleware(req: Request, next: Next) -> Response {
    if req.extensions().get::<PeerPrincipal>().is_some() {
        return next.run(req).await;
    }

    let csrf_disabled = env::var("CSRF_DISABLED").ok();
    let af_env = env::var("AETHERFLOW_ENV").ok();
    if is_csrf_disabled_for_env(csrf_disabled.as_deref(), af_env.as_deref()) {
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

    if header_token.is_empty()
        || !af_models::constant_time_eq(header_token.as_bytes(), cookie_token.as_bytes())
    {
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
        true,
    );
    let mut resp = Json(serde_json::json!({ "csrf_token": token })).into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}
