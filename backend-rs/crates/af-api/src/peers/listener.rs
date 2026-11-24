//! Isolated tunnel-IP peer listener (P3 link protocol + P5 scoped management dispatch).
//!
//! Binds strictly to `<own tunnel IP>:AF_PEER_LISTEN_PORT` once peer identity exists.
//! Serves:
//! - `POST /peer/v1/hello` (attempt-bound pre-activation bootstrap and authenticated acknowledge)
//! - `GET /health` (link-authenticated health & capability exchange)
//! - `GET /peer/v1/link` (link-authenticated link status view)
//! - `POST /peer/v1/revoke-notice` (link-authenticated peer revocation notice)
//! - `POST /peer/v1/grant-token` (link-authenticated inbound grant token delivery)
//! - `POST /peer/v1/grant-revoke` (link-authenticated inbound grant revocation notice)
//! - `POST /peer/v1/grant-offer` (link-authenticated informational grant review offer)
//! - Scoped `/api/v1/*` management routes (authenticated by tunnel source IP + link token +
//!   active grant token digest + active `account_type = 'peer'` run-as user + `peers::scopes`
//!   canonicalization and method/area policy), dispatched into `routes::build_router()`.
//!
//! All unknown, ambiguous, non-versioned, or forbidden targets fail closed and are audited.

use super::errors::{redact_sensitive_text, PeerError};
use super::pairing::sha256_prefixed;
use super::scopes::{self, RouteDecision};
use super::{
    capabilities, grants, is_live_link_state, is_revoked_or_revoking_state, links, pairing,
    ListenerHandle, PeerListenerRuntime, PeerRuntime, PeerWsPermit, HEADER_GRANT_TOKEN,
    HEADER_LINK_TOKEN, HEADER_ORIGIN_OPERATOR, PEER_PROTOCOL_VERSION,
};
use crate::auth::{api_error, AuthUser, PeerPrincipal, SessionAuthTime};
use crate::middlewares::{is_websocket_upgrade_request, GuardedBody};
use crate::storage::{
    extract_isolated_backup_ticket_cookie, is_canonical_backup_download_path,
    BACKUP_DOWNLOAD_COOKIE,
};
use af_db::peers::{self as db_peers, PeerLink};
use af_models::constant_time_eq;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{OriginalUri, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{watch, OwnedSemaphorePermit};
use tower::ServiceExt as _;
use uuid::Uuid;

pub(crate) const TUNNEL_INTERNAL_BODY_LIMIT_BYTES: usize = 8192;

#[derive(Clone)]
struct ListenerState {
    runtime: Arc<PeerRuntime>,
    management_router: Router,
}

/// Verified identity of an active peer link calling the tunnel listener.
#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedPeerLink {
    pub(crate) link: PeerLink,
    pub(crate) source_ip: IpAddr,
}

/// Verifies that the tunnel caller's TCP source IP (`ConnectInfo`) matches an active/down link
/// and that `X-AF-Link-Token` matches `peer_links.inbound_token_hash` in constant time.
pub(crate) async fn authenticate_active_link(
    runtime: &PeerRuntime,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    route_label: &str,
) -> Result<(AuthenticatedPeerLink, tokio::sync::OwnedSemaphorePermit), PeerError> {
    authenticate_active_link_for_kind(runtime, connect_info, headers, route_label, false).await
}

/// Same as [`authenticate_active_link`], acquiring a per-link WebSocket permit instead of HTTP.
pub(crate) async fn authenticate_active_link_ws(
    runtime: &PeerRuntime,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    route_label: &str,
) -> Result<(AuthenticatedPeerLink, tokio::sync::OwnedSemaphorePermit), PeerError> {
    authenticate_active_link_for_kind(runtime, connect_info, headers, route_label, true).await
}

async fn authenticate_active_link_for_kind(
    runtime: &PeerRuntime,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    route_label: &str,
    is_ws: bool,
) -> Result<(AuthenticatedPeerLink, tokio::sync::OwnedSemaphorePermit), PeerError> {
    let local_server = runtime.local_server_name();
    let step = "tunnel_link_auth";

    let Some(ConnectInfo(remote_addr)) = connect_info else {
        audit_listener_denial(runtime, route_label, "unknown", "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Tunnel peer source address is unavailable",
        ));
    };
    let source_ip = remote_addr.ip().to_canonical();
    let source_ip_str = source_ip.to_string();

    let ip_lookup = source_ip_str.clone();
    let link = runtime
        .db
        .read(&local_server, step, move |conn| {
            db_peers::get_peer_link_by_tunnel_ip(conn, &ip_lookup)
                .map_err(|err| PeerError::internal("local", "tunnel_link_auth", err.to_string()))
        })
        .await?;

    let Some(link) = link else {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Tunnel source IP does not match any registered peer link",
        ));
    };

    if is_revoked_or_revoking_state(&link.state) {
        audit_listener_denial(runtime, route_label, &source_ip_str, "LINK_REVOKED").await;
        return Err(PeerError::link_revoked(
            &local_server,
            step,
            format!("Link with '{}' has been revoked", link.name),
        ));
    }

    if !is_live_link_state(&link.state) {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Peer link is not active; complete pairing before calling link routes",
        ));
    }

    let Some(presented) = headers
        .get(HEADER_LINK_TOKEN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Missing X-AF-Link-Token header",
        ));
    };

    let Some(expected_hash) = link.inbound_token_hash.as_deref() else {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Peer link has no active incoming credential",
        ));
    };

    let presented_hash = sha256_prefixed(presented);
    if !constant_time_eq(presented_hash.as_bytes(), expected_hash.as_bytes()) {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_UNAUTHORIZED").await;
        return Err(PeerError::unauthorized(
            &local_server,
            step,
            "Invalid X-AF-Link-Token credential",
        ));
    }

    let permit = if is_ws {
        runtime.acquire_link_ws_permit(&link.id)
    } else {
        runtime.acquire_link_permit(&link.id)
    };
    let Some(permit) = permit else {
        audit_listener_denial(runtime, route_label, &source_ip_str, "PEER_BUSY").await;
        return Err(PeerError::busy(
            &local_server,
            step,
            if is_ws {
                "Per-link WebSocket concurrency limit exceeded on tunnel listener"
            } else {
                "Per-link concurrency limit exceeded on tunnel listener"
            },
        ));
    };

    Ok((AuthenticatedPeerLink { link, source_ip }, permit))
}

pub(crate) async fn audit_listener_denial(
    runtime: &PeerRuntime,
    route_label: &str,
    source_ip: &str,
    error_code: &str,
) {
    runtime
        .db
        .record_audit(
            0,
            "peer-listener".to_string(),
            "peer_listener_denied".to_string(),
            "peer_listener".to_string(),
            route_label.to_string(),
            format!("Denied tunnel request to {route_label} ({error_code})"),
            source_ip.to_string(),
            String::new(),
        )
        .await;
}

fn sanitize_origin_operator(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(HEADER_ORIGIN_OPERATOR)
        .and_then(|v| v.to_str().ok())?;
    let redacted = redact_sensitive_text(raw.trim());
    let cleaned: String = redacted
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

pub(crate) fn extract_or_generate_request_id(headers: &HeaderMap) -> String {
    if let Some(raw) = headers.get("x-request-id").and_then(|v| v.to_str().ok()) {
        let trimmed = raw.trim();
        if !trimmed.is_empty()
            && trimmed.len() <= 128
            && trimmed
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return trimmed.to_string();
        }
    }
    Uuid::new_v4().to_string()
}

fn strip_untrusted_peer_headers(headers: &mut HeaderMap) {
    for name in [
        header::COOKIE,
        header::AUTHORIZATION,
        header::HOST,
        header::ORIGIN,
        header::REFERER,
        HeaderName::from_static("forwarded"),
        HeaderName::from_static("x-forwarded-for"),
        HeaderName::from_static("x-forwarded-host"),
        HeaderName::from_static("x-forwarded-proto"),
        HeaderName::from_static("x-forwarded-port"),
        HeaderName::from_static("x-forwarded-server"),
        HeaderName::from_static("x-real-ip"),
        HeaderName::from_static("x-csrf-token"),
        HeaderName::from_static("x-reauth-password"),
        HeaderName::from_static("x-reauth-password-encoded"),
        HeaderName::from_static("x-reauth-totp"),
        HeaderName::from_static("x-reauth-confirm"),
    ] {
        headers.remove(&name);
    }

    let af_headers: Vec<HeaderName> = headers
        .keys()
        .filter(|k| k.as_str().starts_with("x-af-"))
        .cloned()
        .collect();
    for name in af_headers {
        headers.remove(&name);
    }
}

/// Link-authenticated `GET /health` over the WireGuard tunnel.
async fn tunnel_health(
    State(runtime): State<Arc<PeerRuntime>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let (_auth, _permit) =
        match authenticate_active_link(&runtime, connect_info, &headers, "GET /health").await {
            Ok(ok) => ok,
            Err(err) => return err.into_response(),
        };

    let transcode_caps = super::transcode::cached_local_capabilities_nonblocking(&runtime);

    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "status": "ok",
            "version": runtime.local_version(),
            "peer_protocol": PEER_PROTOCOL_VERSION,
            "capabilities": capabilities(),
            "transcode": transcode_caps,
        })),
    )
        .into_response()
}

/// Scoped management dispatch and fail-closed fallback for all routes outside the explicit
/// `/peer/v1/*` and `GET /health` internal endpoints.
async fn tunnel_management_or_deny_fallback(
    State(state): State<ListenerState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    mut req: Request,
) -> Response {
    let runtime = &state.runtime;
    let route_label = "unclassified tunnel request";
    let local_server = runtime.local_server_name();

    let canonical = scopes::canonicalize(req.uri().path());
    let is_ws = canonical
        .as_ref()
        .is_ok_and(scopes::CanonicalPath::is_websocket_path)
        && is_websocket_upgrade_request(req.headers(), req.method());
    let (auth, permit) = match authenticate_active_link_for_kind(
        runtime,
        connect_info,
        req.headers(),
        route_label,
        is_ws,
    )
    .await
    {
        Ok(ok) => ok,
        Err(err) => return err.into_response(),
    };

    let source_ip_str = auth.source_ip.to_string();
    let remote_addr = connect_info
        .map(|ConnectInfo(addr)| addr)
        .unwrap_or_else(|| SocketAddr::new(auth.source_ip, 0));

    // 1. Canonicalize path once; fail closed on any smuggling, control, dot-segment, or encoding
    //    ambiguity without logging untrusted raw path text.
    let canonical = match canonical {
        Ok(c) => c,
        Err(_) => {
            let err = PeerError::peer_route_unclassified(
                &local_server,
                "tunnel_dispatch",
                "Request path failed canonicalization and was rejected",
            );
            audit_listener_denial(runtime, route_label, &source_ip_str, err.code()).await;
            return err.into_response();
        }
    };

    // 2. Reject every non-versioned or non-`/api/v1/` path (including unknown `/peer/v1/*`,
    //    disallowed methods on `/health`, legacy `/api/*`, `/metrics`, etc.) without leaking raw
    //    unknown paths into audit records.
    if !canonical.as_str().starts_with("/api/v1/") {
        let err = PeerError::peer_route_unclassified(
            &local_server,
            "tunnel_dispatch",
            "Route is not an allowed peer internal or versioned management endpoint",
        );
        audit_listener_denial(runtime, route_label, &source_ip_str, err.code()).await;
        return err.into_response();
    }

    let origin_operator = sanitize_origin_operator(req.headers());
    let operator_display = origin_operator.as_deref().unwrap_or("unspecified");
    let request_id = extract_or_generate_request_id(req.headers());
    let method = req.method().clone();

    // 3. Verify active inbound grant and independent `X-AF-Grant-Token` digest BEFORE route/method
    //    authorization checks.
    let link_id_lookup = auth.link.id.clone();
    let local_server_c = local_server.clone();
    let active_grant = match runtime
        .db
        .read(&local_server, "tunnel_grant_auth", move |conn| {
            db_peers::get_active_peer_grant_for_link(conn, &link_id_lookup).map_err(|err| {
                PeerError::internal(&local_server_c, "tunnel_grant_auth", err.to_string())
            })
        })
        .await
    {
        Ok(g) => g,
        Err(err) => return err.into_response(),
    };

    let Some(grant) = active_grant else {
        let err = PeerError::peer_scope_denied(
            &local_server,
            "tunnel_grant_auth",
            format!(
                "No active management grant is configured for peer '{}'",
                auth.link.name
            ),
        );
        runtime
            .db
            .record_audit(
                0,
                format!("peer-{}", auth.link.name),
                "peer_management_denied".to_string(),
                "peer_link".to_string(),
                auth.link.id.clone(),
                format!(
                    "Denied management request via {} (operator={}, request_id={}, reason=no_active_grant)",
                    auth.link.name, operator_display, request_id
                ),
                source_ip_str,
                String::new(),
            )
            .await;
        return err.into_response();
    };

    let Some(presented_grant_token) = req
        .headers()
        .get(HEADER_GRANT_TOKEN)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        let err = PeerError::peer_scope_denied(
            &local_server,
            "tunnel_grant_auth",
            "Missing X-AF-Grant-Token header for management request",
        );
        runtime
            .db
            .record_audit(
                grant.run_as_user_id,
                format!("peer-{}", auth.link.name),
                "peer_management_denied".to_string(),
                "peer_grant".to_string(),
                grant.id.clone(),
                format!(
                    "Denied management request via {} (operator={}, request_id={}, reason=missing_grant_token)",
                    auth.link.name, operator_display, request_id
                ),
                source_ip_str,
                String::new(),
            )
            .await;
        return err.into_response();
    };

    let Some(expected_grant_hash) = grant.token_hash.as_deref() else {
        let err = PeerError::peer_scope_denied(
            &local_server,
            "tunnel_grant_auth",
            "Active management grant has no valid token digest",
        );
        audit_listener_denial(runtime, route_label, &source_ip_str, err.code()).await;
        return err.into_response();
    };

    let presented_grant_hash = sha256_prefixed(presented_grant_token);
    if !constant_time_eq(
        presented_grant_hash.as_bytes(),
        expected_grant_hash.as_bytes(),
    ) {
        let err = PeerError::unauthorized(
            &local_server,
            "tunnel_grant_auth",
            "Invalid X-AF-Grant-Token credential",
        );
        runtime
            .db
            .record_audit(
                grant.run_as_user_id,
                format!("peer-{}", auth.link.name),
                "peer_management_denied".to_string(),
                "peer_grant".to_string(),
                grant.id.clone(),
                format!(
                    "Denied management request via {} (operator={}, request_id={}, reason=invalid_grant_token)",
                    auth.link.name, operator_display, request_id
                ),
                source_ip_str,
                String::new(),
            )
            .await;
        return err.into_response();
    }

    // 4. Classify `(method, canonical_path)` and check area/mode permissions.
    let decision = scopes::classify(&method, &canonical);
    let requirement = match decision {
        RouteDecision::Unclassified => {
            let err = PeerError::peer_route_unclassified(
                &local_server,
                "tunnel_scope",
                "Requested route or HTTP method is not classified for peer management",
            );
            audit_listener_denial(runtime, route_label, &source_ip_str, err.code()).await;
            return err.into_response();
        }
        RouteDecision::Forbidden => {
            let err = PeerError::peer_scope_denied(
                &local_server,
                "tunnel_scope",
                "Requested endpoint is never reachable through a peer grant",
            );
            runtime
                .db
                .record_audit(
                    grant.run_as_user_id,
                    format!("peer-{}", auth.link.name),
                    "peer_management_denied".to_string(),
                    "peer_grant".to_string(),
                    grant.id.clone(),
                    format!(
                        "Denied forbidden route {} {} via {} (operator={}, request_id={}, code=PEER_SCOPE_DENIED)",
                        method,
                        canonical.as_str(),
                        auth.link.name,
                        operator_display,
                        request_id
                    ),
                    source_ip_str,
                    String::new(),
                )
                .await;
            return err.into_response();
        }
        RouteDecision::Allowed(requirement) => requirement,
    };

    if !scopes::access_allows(&grant.access, requirement) {
        let err = PeerError::peer_scope_denied(
            &local_server,
            "tunnel_scope",
            format!(
                "Peer '{}' grant does not permit {} ({})",
                auth.link.name,
                method,
                requirement.label()
            ),
        );
        runtime
            .db
            .record_audit(
                grant.run_as_user_id,
                format!("peer-{}", auth.link.name),
                "peer_management_denied".to_string(),
                "peer_grant".to_string(),
                grant.id.clone(),
                format!(
                    "Denied {} {} via {} (operator={}, request_id={}, required={}, code=PEER_SCOPE_DENIED)",
                    method,
                    canonical.as_str(),
                    auth.link.name,
                    operator_display,
                    request_id,
                    requirement.label()
                ),
                source_ip_str,
                String::new(),
            )
            .await;
        return err.into_response();
    }

    // 5. Verify dedicated `account_type = 'peer'` run-as admin subject is active in SQLite.
    let run_as_uid = grant.run_as_user_id;
    let local_server_c = local_server.clone();
    let run_as_subject = match runtime
        .db
        .read(&local_server, "tunnel_grant_subject", move |conn| {
            Ok(crate::auth::load_active_peer_subject(conn, run_as_uid))
        })
        .await
    {
        Ok(Ok(subj)) if subj.role == "admin" => subj,
        Ok(_) => {
            let err = PeerError::peer_scope_denied(
                &local_server_c,
                "tunnel_grant_subject",
                "Peer run-as account is inactive or not authorized",
            );
            runtime
                .db
                .record_audit(
                    grant.run_as_user_id,
                    format!("peer-{}", auth.link.name),
                    "peer_management_denied".to_string(),
                    "peer_grant".to_string(),
                    grant.id.clone(),
                    format!(
                        "Denied {} {} via {} (operator={}, request_id={}, reason=run_as_inactive)",
                        method,
                        canonical.as_str(),
                        auth.link.name,
                        operator_display,
                        request_id
                    ),
                    source_ip_str,
                    String::new(),
                )
                .await;
            return err.into_response();
        }
        Err(err) => return err.into_response(),
    };

    // 6. Reconcile request URI to the validated canonical path so Axum routing cannot diverge
    //    from the path we authorized.
    let reconciled_uri = match scopes::reconcile_uri(req.uri(), &canonical) {
        Some(uri) => uri,
        None => {
            let err = PeerError::peer_route_unclassified(
                &local_server,
                "tunnel_dispatch",
                "Failed reconciling canonical request URI",
            );
            audit_listener_denial(runtime, route_label, &source_ip_str, err.code()).await;
            return err.into_response();
        }
    };
    *req.uri_mut() = reconciled_uri;

    // 7. Isolate any one-use backup download ticket cookie strictly on canonical backup download
    //    GET requests (failing closed on malformed or ambiguous cookies without falling back),
    //    then strip all browser/peer auth, forwarding, reauth, and audit headers and untrusted
    //    extensions before injecting trusted `PeerPrincipal`, constrained run-as `AuthUser`,
    //    `PeerListenerRuntime`, `ConnectInfo`, and `X-Request-ID`.
    let isolated_backup_ticket = if method == Method::GET
        && is_canonical_backup_download_path(canonical.as_str())
    {
        match extract_isolated_backup_ticket_cookie(req.headers()) {
            Ok(ticket) => ticket,
            Err(_) => {
                runtime
                        .db
                        .record_audit(
                            run_as_subject.user_id,
                            run_as_subject.username.clone(),
                            "peer_management_denied".to_string(),
                            "peer_grant".to_string(),
                            grant.id.clone(),
                            format!(
                                "Denied {} {} via {} (operator={}, request_id={}, reason=invalid_backup_ticket_cookie)",
                                method,
                                canonical.as_str(),
                                auth.link.name,
                                operator_display,
                                request_id
                            ),
                            source_ip_str,
                            String::new(),
                        )
                        .await;
                return api_error(
                    StatusCode::FORBIDDEN,
                    "INVALID_CURRENT_PASSWORD",
                    "Invalid backup download ticket",
                );
            }
        }
    } else {
        None
    };

    strip_untrusted_peer_headers(req.headers_mut());
    if let Some(ticket) = isolated_backup_ticket {
        if let Ok(mut cookie_hv) =
            HeaderValue::from_str(&format!("{BACKUP_DOWNLOAD_COOKIE}={ticket}"))
        {
            cookie_hv.set_sensitive(true);
            req.headers_mut().insert(header::COOKIE, cookie_hv);
        }
    }
    if let Ok(hv) = HeaderValue::from_str(&request_id) {
        req.headers_mut().insert("x-request-id", hv);
    }

    let exts = req.extensions_mut();
    exts.remove::<PeerPrincipal>();
    exts.remove::<PeerListenerRuntime>();
    exts.remove::<PeerWsPermit>();
    exts.remove::<AuthUser>();
    exts.remove::<SessionAuthTime>();
    exts.remove::<crate::plugins::PluginTokenClaims>();
    exts.remove::<crate::ws::InboundProxyForwarded>();
    exts.remove::<OriginalUri>();

    let run_as_username = run_as_subject.username.clone();
    let principal = PeerPrincipal {
        link_id: auth.link.id.clone(),
        link_name: auth.link.name.clone(),
        local_server: local_server.clone(),
        grant_id: grant.id.clone(),
        run_as_user_id: run_as_subject.user_id,
        run_as_username: run_as_username.clone(),
        access: grant.access.clone(),
        origin_operator: origin_operator.clone(),
        request_id: request_id.clone(),
    };
    let run_as_auth_user = AuthUser {
        user_id: run_as_subject.user_id,
        username: run_as_username.clone(),
        role: "admin".to_string(),
        jti: format!("peer-grant:{}", grant.id),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    exts.insert(ConnectInfo(remote_addr));
    exts.insert(PeerListenerRuntime(Arc::clone(runtime)));
    let (http_permit, ws_permit) = if is_ws {
        let ws_permit = PeerWsPermit::new(permit);
        exts.insert(ws_permit.clone());
        (None, Some(ws_permit))
    } else {
        (Some(permit), None)
    };
    exts.insert(principal);
    exts.insert(run_as_auth_user);

    // The management handler can deny access based on the requested changes.
    let mut response = match state.management_router.clone().oneshot(req).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let (audit_action, outcome) = match response.extensions_mut().remove::<PeerError>() {
        Some(PeerError::PeerScopeDenied(denial)) => (
            "peer_management_denied",
            format!(
                "code=PEER_SCOPE_DENIED, step={}, reason={}",
                denial.step, denial.message
            ),
        ),
        _ if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) =>
        {
            (
                "peer_management_denied",
                format!("status={}", response.status().as_u16()),
            )
        }
        _ => (
            "peer_management_allowed",
            format!("scope={}", requirement.label()),
        ),
    };
    runtime
        .db
        .record_audit(
            run_as_subject.user_id,
            run_as_username,
            audit_action.to_string(),
            "peer_grant".to_string(),
            grant.id,
            format!(
                "{method} {} via {} (server={local_server}, operator={operator_display}, request_id={request_id}, {outcome})",
                canonical.as_str(),
                auth.link.name,
            ),
            source_ip_str,
            String::new(),
        )
        .await;
    guard_management_response(response, http_permit, ws_permit)
}

fn guard_management_response(
    response: Response,
    http_permit: Option<OwnedSemaphorePermit>,
    ws_permit: Option<PeerWsPermit>,
) -> Response {
    let body_permit = http_permit.or_else(|| {
        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            None
        } else {
            ws_permit.and_then(|permit| permit.take())
        }
    });
    if let Some(permit) = body_permit {
        let (parts, body) = response.into_parts();
        return Response::from_parts(parts, GuardedBody::wrap(body, Some(permit)));
    }
    response
}

/// Builds the isolated peer listener Axum router:
/// - Internal `/peer/v1/*` and `GET /health` endpoints with strict 8 KiB body cap
/// - Scoped management dispatch + fail-closed fallback using the production management router
pub(crate) fn build_listener_router(runtime: Arc<PeerRuntime>) -> Router {
    #[cfg(test)]
    let management_router = runtime
        .management_router_override
        .clone()
        .unwrap_or_else(crate::routes::build_router);
    #[cfg(not(test))]
    let management_router = crate::routes::build_router();

    let internal_routes = Router::new()
        .route("/peer/v1/hello", post(pairing::handle_tunnel_hello))
        .route("/health", get(tunnel_health))
        .route("/peer/v1/link", get(links::handle_tunnel_link_view))
        .route(
            "/peer/v1/revoke-notice",
            post(links::handle_tunnel_revoke_notice),
        )
        .route(
            "/peer/v1/grant-token",
            post(grants::handle_tunnel_grant_token),
        )
        .route(
            "/peer/v1/grant-revoke",
            post(grants::handle_tunnel_grant_revoke),
        )
        .route(
            "/peer/v1/grant-offer",
            post(grants::handle_tunnel_grant_offer),
        )
        .route(
            "/peer/v1/exports",
            get(super::storage::handle_tunnel_list_exports),
        )
        .route(
            "/peer/v1/transcode/mounts",
            post(super::transcode::handle_tunnel_transcode_mounts),
        )
        .layer(axum::extract::DefaultBodyLimit::max(
            TUNNEL_INTERNAL_BODY_LIMIT_BYTES,
        ))
        .with_state(Arc::clone(&runtime));

    let transcode_ws_routes = Router::new()
        .route(
            "/peer/v1/transcode/jobs",
            get(super::transcode::handle_tunnel_transcode_jobs),
        )
        .with_state(Arc::clone(&runtime));

    let listener_state = ListenerState {
        runtime,
        management_router,
    };

    Router::new()
        .merge(internal_routes)
        .merge(transcode_ws_routes)
        .fallback(tunnel_management_or_deny_fallback)
        .method_not_allowed_fallback(tunnel_management_or_deny_fallback)
        .with_state(listener_state)
}

/// Binds and spawns the peer listener strictly on `<tunnel_ip>:<port>`, constraining production
/// sockets to `afpeer0` via `SO_BINDTODEVICE` (`bind_device = Some("afpeer0")`) and allowing
/// unbound loopback sockets strictly for isolated loopback test fixtures (`bind_device = None`).
pub(crate) async fn spawn_tunnel_listener(
    runtime: Arc<PeerRuntime>,
    tunnel_ip: IpAddr,
    port: u16,
    bind_device: Option<&str>,
) -> std::io::Result<ListenerHandle> {
    let tunnel_ip = tunnel_ip.to_canonical();
    if tunnel_ip.is_unspecified() || tunnel_ip.is_multicast() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Peer tunnel listener refuses to bind unspecified or multicast address",
        ));
    }
    if bind_device.is_some() && tunnel_ip.is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "WireGuard-bound peer tunnel listener refuses loopback address",
        ));
    }
    if bind_device.is_none() && !tunnel_ip.is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Peer tunnel listener without device binding is restricted to loopback fixtures",
        ));
    }

    let bind_addr = SocketAddr::new(tunnel_ip, port);
    let socket = match tunnel_ip {
        IpAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        IpAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(iface) = bind_device {
        socket.bind_device(Some(iface.as_bytes()))?;
    }
    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    if bind_device.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Tunnel device binding requires Linux SO_BINDTODEVICE",
        ));
    }

    socket.bind(bind_addr)?;
    let tcp_listener = socket.listen(1024)?;
    let bound_addr = tcp_listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let app = build_listener_router(runtime);

    let task = tokio::spawn(async move {
        let serve_res = axum::serve(
            tcp_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            while !*shutdown_rx.borrow() {
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        if let Err(error) = serve_res {
            tracing::warn!(%error, "Peer tunnel listener exited with error");
        }
    });

    Ok(ListenerHandle {
        tunnel_ip,
        interface: bind_device.map(str::to_string),
        bound_addr,
        shutdown_tx,
        task,
    })
}

#[cfg(test)]
mod response_permit_tests {
    use super::*;
    use axum::body::{Body, Bytes};
    use tokio::sync::Semaphore;

    #[test]
    fn management_permits_remain_held_until_the_response_body_is_dropped() {
        for (status, uses_ws_pool) in [(StatusCode::OK, false), (StatusCode::FORBIDDEN, true)] {
            let pool = Arc::new(Semaphore::new(1));
            let acquired = pool.clone().try_acquire_owned().unwrap();
            let (http_permit, ws_permit) = if uses_ws_pool {
                (None, Some(PeerWsPermit::new(acquired)))
            } else {
                (Some(acquired), None)
            };
            let response = Response::builder()
                .status(status)
                .body(Body::from_stream(futures::stream::pending::<
                    Result<Bytes, std::io::Error>,
                >()))
                .unwrap();
            let response = guard_management_response(response, http_permit, ws_permit);
            assert_eq!(response.status(), status);
            assert_eq!(pool.available_permits(), 0);
            drop(response);
            assert_eq!(pool.available_permits(), 1);
        }
    }
}
