//! Managing-side admin-only peer proxy (`ANY /api/v1/peers/:id/*rest`, Design File 31).
//!
//! Forwards authenticated browser/admin requests over the WireGuard tunnel to the selected peer's
//! stored `<tunnel_ip>:<listen_port>/api/v1/<rest>` endpoint using the shared streaming HTTP and
//! WebSocket upgrade transport in [`crate::middlewares::stream_proxy`].
//!
//! Security & resource invariants:
//! - Mounted strictly under `/api/v1/peers/:id/*rest` behind `auth_middleware`, `csrf_middleware`,
//!   `admin_only_middleware`, and `reject_peer_principal_middleware` (plugin and peer principals
//!   are rejected; browser CSRF protection is retained on mutating methods).
//! - WebSocket upgrades enforce same-origin checks (`websocket_origin_matches_host`) on the
//!   managing server before stripping browser `Origin`/`Host`.
//! - Destination is built solely from the active, compatible link's stored `tunnel_ip` and
//!   configured listener port, bound to `afpeer0` + local tunnel IP in production (loopback in
//!   test fixtures).
//! - Resolves separate held `LinkToken` and committed `GrantToken` (via P5's
//!   `read_committed_received_grant_token`), attaching both as sensitive HTTP headers.
//! - Strips browser `Authorization`, `Cookie`, `Host`, `Origin`, `Referer`, forwarding, CSRF,
//!   reauth, and all client-supplied `X-AF-*` / spoofable identity headers before setting trusted
//!   peer credentials, operator metadata (`X-AF-Origin-Operator`), and `X-Request-ID`.
//! - Coordinates isolated one-use `af_backup_download` cookie transfer strictly on
//!   `GET /api/v1/admin/backup/download/:filename` (failing closed on malformed/ambiguous cookies
//!   without falling back) and discards local password bodies on `POST` remote backup step-up.
//! - Enforces response trust boundaries: strips untrusted `Set-Cookie`, `Clear-Site-Data`,
//!   `WWW-Authenticate`, and upstream CORS/credential headers; rewrites safe root-relative
//!   `/api/v1/...` `Location` headers (including tus uploads) and narrowly validated
//!   `af_backup_download` cookies under `/api/v1/peers/:id/...`.
//! - Enforces per-link HTTP (`AF_PEER_MAX_CONN`, default 64) and WebSocket (`AF_PEER_MAX_WS`,
//!   default 16) caps with permits held for the full streaming/upgrade lifetime and a 30-second
//!   connect/header timeout budget that never limits multi-minute streams.

use super::errors::PeerError;
use super::grants::read_committed_received_grant_token;
use super::health::{evaluate_compatibility, CompatibilityStatus};
use super::pairing::is_valid_credential_id;
use super::scopes;
use super::{
    is_active_link_state, is_down_link_state, is_revoked_or_revoking_state, PeerRuntime,
    RevocationEvent, TunnelHttpError, HEADER_GRANT_TOKEN, HEADER_LINK_TOKEN,
    HEADER_ORIGIN_OPERATOR,
};
use crate::auth::{api_error, secure_cookie_enabled, AuthUser, PeerPrincipal};
use crate::middlewares::{
    connection_header_tokens, is_hop_by_hop_header, is_websocket_upgrade_request, stream_proxy,
    StreamProxyErrorKind, StreamProxyOptions, StreamProxySocketBind, StreamProxyUpgradePolicy,
};
use crate::routes::RequestId;
use crate::storage::{
    extract_isolated_backup_ticket_cookie, is_canonical_backup_download_path,
    BACKUP_DOWNLOAD_COOKIE, BACKUP_DOWNLOAD_COOKIE_PATH,
};
use crate::ws::PeerIp;
use af_db::peers as db_peers;
use af_runner::{PeerCredentialSecret, PeerCredentialSlot, PeerNetworkError, PeerNetworkRequest};
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, watch};
use url::Url;
use uuid::Uuid;

const PROXY_REVOCATION_NONE: u8 = 0;
const PROXY_REVOCATION_LINK: u8 = 1;
const PROXY_REVOCATION_GRANT: u8 = 2;

fn is_valid_request_id(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

fn sanitize_operator_header_value(username: &str) -> Option<String> {
    let cleaned: String = username
        .trim()
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn should_strip_inbound_proxy_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("x-af-")
        || lower.starts_with("x-aetherflow-")
        || matches!(
            lower.as_str(),
            "authorization"
                | "cookie"
                | "host"
                | "origin"
                | "referer"
                | "forwarded"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
                | "x-forwarded-port"
                | "x-forwarded-server"
                | "x-real-ip"
                | "x-csrf-token"
                | "x-reauth-password"
                | "x-reauth-password-encoded"
                | "x-reauth-totp"
                | "x-reauth-confirm"
                | "x-request-id"
                | "remote-user"
                | "x-remote-user"
                | "x-forwarded-user"
                | "x-forwarded-email"
                | "x-forwarded-groups"
        )
}

pub(super) fn copy_peer_request_headers(
    incoming: &HeaderMap,
    discard_request_body: bool,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let connection_tokens = connection_header_tokens(incoming);
    for (k, v) in incoming.iter() {
        let name = k.as_str();
        if should_strip_inbound_proxy_header(name)
            || is_hop_by_hop_header(name)
            || connection_tokens.contains(name)
        {
            continue;
        }
        if discard_request_body
            && (name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("content-type"))
        {
            continue;
        }
        headers.append(k.clone(), v.clone());
    }
    headers
}

fn is_peer_hop_or_admin_peer_path(canonical_path: &str) -> bool {
    let lower = canonical_path.to_ascii_lowercase();
    lower == "/api/v1/peers"
        || lower.starts_with("/api/v1/peers/")
        || lower == "/api/v1/admin/peers"
        || lower.starts_with("/api/v1/admin/peers/")
}

/// Validates and rewrites a safe root-relative `/api/v1/...` `Location` header (including McBrowser
/// tus upload locations) to `/api/v1/peers/{link_id}/...`. Returns `None` for off-origin,
/// protocol-relative, non-`/api/v1/`, peer-hop, or malformed locations so they are stripped.
pub(crate) fn rewrite_peer_location_header(raw_location: &str, link_id: &str) -> Option<String> {
    if !is_valid_credential_id(link_id) {
        return None;
    }
    let trimmed = raw_location.trim();
    if trimmed.is_empty()
        || trimmed.bytes().any(|b| b < 0x20 || b == 0x7f)
        || trimmed.contains('\\')
        || trimmed.contains('#')
        || trimmed.starts_with("//")
        || !trimmed.starts_with("/api/v1/")
    {
        return None;
    }
    let (raw_path, query_opt) = match trimmed.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (trimmed, None),
    };
    let canonical = scopes::canonicalize(raw_path).ok()?;
    if !canonical.as_str().starts_with("/api/v1/")
        || is_peer_hop_or_admin_peer_path(canonical.as_str())
    {
        return None;
    }
    let orig_uri: axum::http::Uri = match query_opt {
        Some(q) => format!("{}?{q}", canonical.as_str()).parse().ok()?,
        None => canonical.as_str().parse().ok()?,
    };
    let reconciled = scopes::reconcile_uri(&orig_uri, &canonical)?;
    let reconciled_str = reconciled.to_string();
    let suffix = reconciled_str.strip_prefix("/api/v1")?;
    Some(format!("/api/v1/peers/{link_id}{suffix}"))
}

/// Validates and rewrites ONLY the narrowly scoped `af_backup_download` one-use ticket cookie
/// (issue or clearing) on canonical backup download paths under `/api/v1/peers/{link_id}/...`.
/// Returns `None` for all other cookies, routes, domain-widened cookies, or malformed attributes.
pub(crate) fn rewrite_peer_backup_set_cookie(
    raw_set_cookie: &str,
    link_id: &str,
    canonical_target_path: &str,
    secure: bool,
) -> Option<String> {
    if !is_valid_credential_id(link_id) || !is_canonical_backup_download_path(canonical_target_path)
    {
        return None;
    }
    if raw_set_cookie.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }

    let mut parts = raw_set_cookie.split(';');
    let first = parts.next()?.trim();
    let (name, raw_value) = first.split_once('=')?;
    if name.trim() != BACKUP_DOWNLOAD_COOKIE {
        return None;
    }
    let value = raw_value.trim();
    let is_clear = value.is_empty();
    if !is_clear && (value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }

    let mut saw_path: Option<&str> = None;
    let mut saw_max_age: Option<i64> = None;
    for raw_attr in parts {
        let attr = raw_attr.trim();
        if attr.is_empty() {
            continue;
        }
        if let Some((ak, av)) = attr.split_once('=') {
            let key = ak.trim().to_ascii_lowercase();
            let val = av.trim();
            match key.as_str() {
                "domain" => return None,
                "path" => {
                    if saw_path.is_some() {
                        return None;
                    }
                    saw_path = Some(val);
                }
                "max-age" => {
                    if saw_max_age.is_some() {
                        return None;
                    }
                    saw_max_age = Some(val.parse::<i64>().ok()?);
                }
                "samesite" => {
                    if !val.eq_ignore_ascii_case("strict") && !val.eq_ignore_ascii_case("lax") {
                        return None;
                    }
                }
                "expires" => {}
                _ => return None,
            }
        } else {
            let flag = attr.to_ascii_lowercase();
            if !matches!(flag.as_str(), "httponly" | "secure") {
                return None;
            }
        }
    }

    if saw_path != Some(BACKUP_DOWNLOAD_COOKIE_PATH) {
        return None;
    }

    let effective_max_age = if is_clear {
        match saw_max_age {
            Some(m) if m <= 0 => -1,
            _ => return None,
        }
    } else {
        match saw_max_age {
            Some(m) if m > 0 => m.min(60),
            _ => return None,
        }
    };

    let scoped_path = format!("/api/v1/peers/{link_id}/admin/backup/download/");
    let mut out = vec![
        format!("{BACKUP_DOWNLOAD_COOKIE}={value}"),
        format!("Path={scoped_path}"),
        format!("Max-Age={effective_max_age}"),
        "SameSite=Strict".to_string(),
    ];
    if secure {
        out.push("Secure".to_string());
    }
    out.push("HttpOnly".to_string());
    Some(out.join("; "))
}

fn sanitize_and_rewrite_peer_response(
    resp: &mut Response,
    is_switching_protocols: bool,
    link_id: &str,
    canonical_target_path: &str,
    request_id: &str,
    secure_cookies: bool,
) {
    let headers = resp.headers_mut();

    // Authorize each fetch against the current link and grant. Cache policy belongs to the
    // managing server because the response carries data under its dashboard origin.
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));

    // Discard browser-origin policy and internal credentials supplied by the peer.
    for forbidden in [
        header::HeaderName::from_static("clear-site-data"),
        header::HeaderName::from_static("refresh"),
        header::HeaderName::from_static("service-worker-allowed"),
        header::HeaderName::from_static("surrogate-control"),
        header::HeaderName::from_static("cdn-cache-control"),
        header::HeaderName::from_static("cloudflare-cdn-cache-control"),
        header::WWW_AUTHENTICATE,
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        header::ACCESS_CONTROL_ALLOW_METHODS,
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderName::from_static(HEADER_LINK_TOKEN),
        HeaderName::from_static(HEADER_GRANT_TOKEN),
        HeaderName::from_static(HEADER_ORIGIN_OPERATOR),
    ] {
        headers.remove(&forbidden);
    }

    // Rewrite or strip `Location` headers strictly within the peer proxy prefix.
    if !is_switching_protocols {
        let rewritten_locations: Vec<HeaderValue> = headers
            .get_all(header::LOCATION)
            .iter()
            .filter_map(|hv| hv.to_str().ok())
            .filter_map(|raw| rewrite_peer_location_header(raw, link_id))
            .filter_map(|rewritten| HeaderValue::from_str(&rewritten).ok())
            .collect();
        headers.remove(header::LOCATION);
        for loc in rewritten_locations {
            headers.append(header::LOCATION, loc);
        }

        // Strip all cookies except a narrowly validated backup download ticket cookie on the
        // canonical backup download route.
        let rewritten_cookies: Vec<HeaderValue> = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|hv| hv.to_str().ok())
            .filter_map(|raw| {
                rewrite_peer_backup_set_cookie(raw, link_id, canonical_target_path, secure_cookies)
            })
            .filter_map(|rewritten| HeaderValue::from_str(&rewritten).ok())
            .collect();
        headers.remove(header::SET_COOKIE);
        for cookie in rewritten_cookies {
            headers.append(header::SET_COOKIE, cookie);
        }
    } else {
        headers.remove(header::SET_COOKIE);
        headers.remove(header::LOCATION);
    }

    headers.remove("x-request-id");
    if let Ok(hv) = HeaderValue::from_str(request_id) {
        headers.insert(HeaderName::from_static("x-request-id"), hv);
    }
}

async fn read_held_link_token_for_proxy(
    runtime: &PeerRuntime,
    link_id: &str,
    peer_name: &str,
) -> Result<PeerCredentialSecret, PeerError> {
    let step = "peer_proxy";
    let resp = runtime
        .runner
        .dispatch(&PeerNetworkRequest::ReadCredential {
            slot: PeerCredentialSlot::LinkToken,
            id: link_id.to_string(),
        })
        .await
        .map_err(|err| match err {
            PeerNetworkError::Busy(msg) => PeerError::busy(peer_name, step, msg),
            other => PeerError::internal(
                peer_name,
                step,
                format!("Failed reading held peer link credential: {other}"),
            ),
        })?;
    let read = resp.into_credential_read().map_err(|err| {
        PeerError::internal(
            peer_name,
            step,
            format!("Invalid runner link credential response: {err}"),
        )
    })?;
    if read.slot != PeerCredentialSlot::LinkToken || read.id != link_id {
        return Err(PeerError::internal(
            peer_name,
            step,
            "Runner returned a mismatched peer link credential slot",
        ));
    }
    if !read.present {
        return Err(PeerError::unauthorized(
            peer_name,
            step,
            format!("Held link credential for peer '{peer_name}' is missing"),
        ));
    }
    read.into_secret().ok_or_else(|| {
        PeerError::internal(
            peer_name,
            step,
            "Runner reported a present peer link credential without a secret value",
        )
    })
}

fn spawn_proxy_revocation_watcher(
    runtime: Arc<PeerRuntime>,
    link_id: String,
    active_grant_id: String,
    mut revocation_rx: broadcast::Receiver<RevocationEvent>,
) -> (watch::Receiver<bool>, Arc<AtomicU8>) {
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let reason = Arc::new(AtomicU8::new(PROXY_REVOCATION_NONE));
    let reason_c = Arc::clone(&reason);
    tokio::spawn(async move {
        let recheck_revocation = |rt: &Arc<PeerRuntime>, id: &str| {
            let rt = Arc::clone(rt);
            let check_id = id.to_string();
            async move {
                rt.db
                    .read("local", "proxy_revocation_recheck", move |conn| {
                        let link_ok = db_peers::get_peer_link(conn, &check_id)
                            .ok()
                            .flatten()
                            .is_some_and(|l| is_active_link_state(&l.state));
                        if !link_ok {
                            return Ok(Some(PROXY_REVOCATION_LINK));
                        }
                        let grant_ok =
                            db_peers::get_active_peer_received_grant_for_link(conn, &check_id)
                                .ok()
                                .flatten()
                                .is_some_and(|g| g.access.has_any_access());
                        if !grant_ok {
                            return Ok(Some(PROXY_REVOCATION_GRANT));
                        }
                        Ok(None)
                    })
                    .await
                    .unwrap_or(Some(PROXY_REVOCATION_GRANT))
            }
        };

        if let Some(code) = recheck_revocation(&runtime, &link_id).await {
            reason_c.store(code, Ordering::Release);
            let _ = cancel_tx.send(true);
            return;
        }

        loop {
            tokio::select! {
                _ = cancel_tx.closed() => break,
                recv = revocation_rx.recv() => {
                    match recv {
                        Ok(RevocationEvent::LinkRevoked { link_id: revoked_id, .. }) => {
                            if revoked_id == link_id {
                                reason_c.store(PROXY_REVOCATION_LINK, Ordering::Release);
                                let _ = cancel_tx.send(true);
                                break;
                            }
                        }
                        Ok(RevocationEvent::GrantRevoked {
                            link_id: revoked_id,
                            grant_id: revoked_grant_id,
                            ..
                        }) => {
                            if revoked_id == link_id {
                                if revoked_grant_id == active_grant_id {
                                    reason_c.store(PROXY_REVOCATION_GRANT, Ordering::Release);
                                    let _ = cancel_tx.send(true);
                                    break;
                                }
                                if let Some(code) = recheck_revocation(&runtime, &link_id).await {
                                    reason_c.store(code, Ordering::Release);
                                    let _ = cancel_tx.send(true);
                                    break;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            if let Some(code) = recheck_revocation(&runtime, &link_id).await {
                                reason_c.store(code, Ordering::Release);
                                let _ = cancel_tx.send(true);
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            reason_c.store(PROXY_REVOCATION_LINK, Ordering::Release);
                            let _ = cancel_tx.send(true);
                            break;
                        }
                    }
                }
            }
        }
    });
    (cancel_rx, reason)
}

fn target_authority_host(target: &Url) -> Option<String> {
    let host = target.host_str()?;
    match target.port_or_known_default() {
        Some(port) => Some(format!("{host}:{port}")),
        None => Some(host.to_string()),
    }
}

/// Handler for `GET|HEAD|POST|PUT|PATCH|DELETE /api/v1/peers/:id/*rest`.
pub(crate) async fn handle_peer_proxy(
    State(runtime): State<Arc<PeerRuntime>>,
    Path((link_id, _rest)): Path<(String, String)>,
    PeerIp(peer_ip): PeerIp,
    req: Request,
) -> Response {
    let local_server = runtime.local_server_name();
    let step = "peer_proxy";

    // 1. Defense-in-depth caller checks: require a verified human admin; reject peer & plugin principals.
    if req.extensions().get::<PeerPrincipal>().is_some() {
        return PeerError::peer_scope_denied(
            &local_server,
            step,
            "Peer management proxy cannot be invoked through a peer grant",
        )
        .into_response();
    }
    if req
        .extensions()
        .get::<crate::plugins::PluginTokenClaims>()
        .is_some()
    {
        return api_error(
            StatusCode::FORBIDDEN,
            "PLUGIN_SCOPE_DENIED",
            "Peer management proxy requires an administrator session",
        );
    }
    let Some(auth_user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    if auth_user.user_id <= 0
        || auth_user.role != "admin"
        || auth_user.plugin_id.is_some()
        || !auth_user.plugin_scopes.is_empty()
    {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    let Some(origin_operator) = sanitize_operator_header_value(&auth_user.username) else {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Valid managing administrator identity is required",
        );
    };

    // 2. Validate link_id and canonicalize the raw target path strictly from `req.uri().path()`.
    if !is_valid_credential_id(&link_id) {
        return PeerError::invalid_request(
            &local_server,
            step,
            "Invalid peer link identifier",
            "Refresh the Cluster page and select a valid peer link",
        )
        .into_response();
    }

    let raw_path = req.uri().path();
    let after_slash = raw_path.strip_prefix('/').unwrap_or(raw_path);
    let Some((raw_id_seg, raw_rest_seg)) = after_slash.split_once('/') else {
        return PeerError::invalid_request(
            &local_server,
            step,
            "Missing proxied peer API path",
            "Provide a versioned API path under /api/v1/peers/{id}/",
        )
        .into_response();
    };
    if raw_id_seg != link_id || raw_rest_seg.is_empty() {
        return PeerError::invalid_request(
            &local_server,
            step,
            "Invalid peer proxy link segment or target path",
            "Use a plain link identifier and valid API path under /api/v1/peers/{id}/",
        )
        .into_response();
    }

    let raw_target_path = format!("/api/v1/{raw_rest_seg}");
    let canonical = match scopes::canonicalize(&raw_target_path) {
        Ok(c) if c.as_str().starts_with("/api/v1/") => c,
        _ => {
            return PeerError::peer_route_unclassified(
                &local_server,
                step,
                "Proxied peer request path failed canonicalization",
            )
            .into_response();
        }
    };

    // Never allow peer-hop recursion or peer administration endpoints through the managing proxy.
    if is_peer_hop_or_admin_peer_path(canonical.as_str()) {
        return PeerError::peer_scope_denied(
            &local_server,
            step,
            "Peer administration routes and multi-hop peer proxies are never reachable through the peer proxy",
        )
        .into_response();
    }

    let Some(reconciled_uri) = scopes::reconcile_uri(req.uri(), &canonical) else {
        return PeerError::peer_route_unclassified(
            &local_server,
            step,
            "Failed reconciling proxied peer request URI",
        )
        .into_response();
    };

    // 3. Validate the browser origin before forwarding an actual management upgrade.
    let is_ws =
        canonical.is_websocket_path() && is_websocket_upgrade_request(req.headers(), req.method());
    if is_ws {
        let cookie_authenticated = req.headers().contains_key(header::COOKIE)
            && !req.headers().contains_key(header::AUTHORIZATION);
        if !crate::ws::websocket_origin_matches_host(req.headers(), peer_ip, cookie_authenticated) {
            return api_error(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Cross-origin WebSocket upgrade rejected",
            );
        }
    }

    // 4. Subscribe to revocation broadcasts BEFORE loading link/grant state so no concurrent
    //    revocation between validation and stream start can be missed.
    let revocation_rx = runtime.subscribe_revocations();

    // Validate active, compatible peer link metadata from local SQLite.
    let id_lookup = link_id.clone();
    let local_server_c = local_server.clone();
    let link = match runtime
        .db
        .read(&local_server, step, move |conn| {
            db_peers::get_peer_link(conn, &id_lookup)
                .map_err(|err| PeerError::internal(&local_server_c, step, err.to_string()))
        })
        .await
    {
        Ok(Some(link)) => link,
        Ok(None) => {
            return PeerError::not_found(
                &local_server,
                step,
                format!("Peer link '{link_id}' was not found"),
            )
            .into_response();
        }
        Err(err) => return err.into_response(),
    };

    if is_revoked_or_revoking_state(&link.state) {
        return PeerError::link_revoked(
            &link.name,
            step,
            format!("Peer link '{}' has been revoked", link.name),
        )
        .into_response();
    }
    if is_down_link_state(&link.state) {
        return PeerError::link_down(
            &link.name,
            step,
            format!("Peer link '{}' is currently down", link.name),
        )
        .into_response();
    }
    if !is_active_link_state(&link.state) {
        return PeerError::conflict(
            &link.name,
            step,
            format!("Peer link '{}' is not active yet", link.name),
            "Complete pairing confirmation and wait for the link to become healthy",
        )
        .into_response();
    }

    let remote_caps: Vec<String> = link
        .capabilities
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
        .unwrap_or_default();
    let compat = evaluate_compatibility(link.peer_protocol, &remote_caps);
    match compat.status {
        CompatibilityStatus::Compatible => {}
        CompatibilityStatus::Limited => {
            if compat.missing_capabilities.iter().any(|c| c == "grants") {
                return PeerError::version_incompatible(
                    &link.name,
                    step,
                    format!(
                        "'{}' does not advertise scoped grant management support",
                        link.name
                    ),
                )
                .into_response();
            }
        }
        CompatibilityStatus::Incompatible | CompatibilityStatus::Unknown => {
            return PeerError::version_incompatible(
                &link.name,
                step,
                format!(
                    "'{}' peer protocol metadata is incompatible or unverified",
                    link.name
                ),
            )
            .into_response();
        }
    }

    // 5. Resolve committed outbound GrantToken (P5 resolver) and separate held LinkToken.
    let (received_grant, grant_secret) =
        match read_committed_received_grant_token(&runtime, &link.id).await {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                return PeerError::peer_scope_denied(
                    &link.name,
                    step,
                    format!(
                        "No active management grant is held for peer '{}'",
                        link.name
                    ),
                )
                .into_response();
            }
            Err(err) => return err.into_response(),
        };
    if !received_grant.access.has_any_access() {
        return PeerError::peer_scope_denied(
            &link.name,
            step,
            format!(
                "Held management grant for peer '{}' grants no area permissions",
                link.name
            ),
        )
        .into_response();
    }

    let link_secret = match read_held_link_token_for_proxy(&runtime, &link.id, &link.name).await {
        Ok(secret) => secret,
        Err(err) => return err.into_response(),
    };

    // 6. Build destination solely from stored tunnel IP and configured listener port, enforcing
    //    production `afpeer0` + local tunnel IP binding (or loopback-only in test fixtures).
    let reconciled_pq = reconciled_uri.to_string();
    let target_url = match runtime.build_tunnel_url(&link.tunnel_ip, &reconciled_pq) {
        Ok(url) => url,
        Err(err) => {
            return PeerError::invalid_request(
                &link.name,
                step,
                err.message(),
                "Verify the peer link tunnel IP and WireGuard configuration",
            )
            .into_response();
        }
    };
    let dest_ip: IpAddr = match link.tunnel_ip.trim().parse::<IpAddr>() {
        Ok(ip) => ip.to_canonical(),
        Err(_) => {
            return PeerError::invalid_request(
                &link.name,
                step,
                "Stored peer tunnel IP is invalid",
                "Re-pair or repair the peer link tunnel address",
            )
            .into_response();
        }
    };
    let binding = match runtime.resolve_outbound_tunnel_binding(dest_ip).await {
        Ok(b) => b,
        Err(TunnelHttpError::Timeout(msg)) => {
            return PeerError::handshake_timeout(&link.name, step, msg).into_response();
        }
        Err(TunnelHttpError::Unreachable(msg)) => {
            return PeerError::link_down(&link.name, step, msg).into_response();
        }
        Err(TunnelHttpError::InvalidTarget(msg)) => {
            return PeerError::invalid_request(
                &link.name,
                step,
                msg,
                "Verify local peer tunnel identity and afpeer0 binding",
            )
            .into_response();
        }
    };
    let client = match runtime.get_or_build_proxy_tunnel_client(&binding) {
        Ok(c) => c,
        Err(err) => {
            return PeerError::link_down(&link.name, step, err.message()).into_response();
        }
    };

    // 7. Isolate backup download ticket transfer BEFORE stripping Cookie headers, and discard
    //    any local password body on remote backup step-up POST.
    let is_backup_download = is_canonical_backup_download_path(canonical.as_str());
    let isolated_backup_ticket = if is_backup_download && *req.method() == Method::GET {
        match extract_isolated_backup_ticket_cookie(req.headers()) {
            Ok(ticket) => ticket,
            Err(_) => {
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
    let discard_request_body = is_backup_download && *req.method() == Method::POST;

    // 8. Acquire per-link concurrency permit (held through streaming body or upgraded WS lifetime).
    let permit: Box<dyn std::any::Any + Send + Sync> = if is_ws {
        match runtime.acquire_link_ws_permit(&link.id) {
            Some(p) => Box::new(p),
            None => {
                return PeerError::busy(
                    &link.name,
                    step,
                    format!(
                        "Per-link WebSocket limit ({}) exceeded for '{}'",
                        runtime.max_ws_per_link, link.name
                    ),
                )
                .into_response();
            }
        }
    } else {
        match runtime.acquire_link_permit(&link.id) {
            Some(p) => Box::new(p),
            None => {
                return PeerError::busy(
                    &link.name,
                    step,
                    format!(
                        "Per-link HTTP concurrency limit ({}) exceeded for '{}'",
                        runtime.max_conn_per_link, link.name
                    ),
                )
                .into_response();
            }
        }
    };

    // Watch managing-side link & grant revocations for ALL proxied requests (both WebSocket
    // tunnels and non-WS streaming HTTP requests/responses) so revocations abort in-flight streams
    // and release concurrency permits immediately even if the remote peer is unreachable.
    let (stream_cancel, revocation_kind) = spawn_proxy_revocation_watcher(
        Arc::clone(&runtime),
        link.id.clone(),
        received_grant.grant_id.clone(),
        revocation_rx,
    );

    // 9. Resolve trusted request ID from `RequestId` extension (set by `security_headers_middleware`).
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .filter(|id| is_valid_request_id(id))
        .or_else(|| {
            req.headers()
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|id| is_valid_request_id(id))
                .map(str::to_string)
        })
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // 10. Build clean upstream headers: strip untrusted browser/forwarding/internal headers,
    //     attach isolated backup ticket if present, and inject sensitive peer credentials.
    let mut upstream_headers = copy_peer_request_headers(req.headers(), discard_request_body);

    if let Some(ticket) = isolated_backup_ticket {
        if let Ok(mut cookie_hv) =
            HeaderValue::from_str(&format!("{BACKUP_DOWNLOAD_COOKIE}={ticket}"))
        {
            cookie_hv.set_sensitive(true);
            upstream_headers.insert(header::COOKIE, cookie_hv);
        }
    }

    let mut link_hv = match HeaderValue::from_str(link_secret.expose_secret()) {
        Ok(hv) => hv,
        Err(_) => {
            return PeerError::internal(
                &link.name,
                step,
                "Held peer link credential contains invalid HTTP header bytes",
            )
            .into_response();
        }
    };
    link_hv.set_sensitive(true);
    upstream_headers.insert(HeaderName::from_static(HEADER_LINK_TOKEN), link_hv);

    let mut grant_hv = match HeaderValue::from_str(grant_secret.expose_secret()) {
        Ok(hv) => hv,
        Err(_) => {
            return PeerError::internal(
                &link.name,
                step,
                "Held peer grant credential contains invalid HTTP header bytes",
            )
            .into_response();
        }
    };
    grant_hv.set_sensitive(true);
    upstream_headers.insert(HeaderName::from_static(HEADER_GRANT_TOKEN), grant_hv);

    if let Ok(op_hv) = HeaderValue::from_str(&origin_operator) {
        upstream_headers.insert(HeaderName::from_static(HEADER_ORIGIN_OPERATOR), op_hv);
    }
    if let Ok(req_id_hv) = HeaderValue::from_str(&request_id) {
        upstream_headers.insert(HeaderName::from_static("x-request-id"), req_id_hv);
    }

    let upstream_host = target_authority_host(&target_url);
    let peer_name_err = link.name.clone();
    let link_id_resp = link.id.clone();
    let canonical_resp = canonical.as_str().to_string();
    let req_id_resp = request_id.clone();
    let secure_cookies = secure_cookie_enabled();

    let opts = StreamProxyOptions {
        upstream_headers,
        upstream_host,
        tcp_bind: Some(StreamProxySocketBind {
            local_ip: binding.local_ip,
            interface: binding.interface,
        }),
        tls_ws_client: None,
        header_timeout: runtime.proxy_header_timeout,
        upload_idle_timeout: Some(runtime.proxy_header_timeout),
        ws_connect_timeout: runtime.proxy_header_timeout,
        upgrade_policy: if is_ws {
            StreamProxyUpgradePolicy::WebSocketOnly
        } else {
            StreamProxyUpgradePolicy::Disabled
        },
        guard: Some(permit),
        stream_cancel: Some(stream_cancel),
        response_transform: Some(Box::new(move |resp, is_101| {
            sanitize_and_rewrite_peer_response(
                resp,
                is_101,
                &link_id_resp,
                &canonical_resp,
                &req_id_resp,
                secure_cookies,
            );
        })),
        on_error: Some(Box::new(move |kind, detail| match kind {
            StreamProxyErrorKind::BadGateway => {
                PeerError::link_down(&peer_name_err, "peer_proxy", detail).into_response()
            }
            StreamProxyErrorKind::GatewayTimeout => {
                PeerError::handshake_timeout(&peer_name_err, "peer_proxy", detail).into_response()
            }
            StreamProxyErrorKind::Cancelled => {
                if revocation_kind.load(Ordering::Acquire) == PROXY_REVOCATION_LINK {
                    PeerError::link_revoked(
                        &peer_name_err,
                        "peer_proxy",
                        format!(
                            "Peer link '{peer_name_err}' was revoked while request was in flight"
                        ),
                    )
                    .into_response()
                } else {
                    PeerError::peer_scope_denied(
                        &peer_name_err,
                        "peer_proxy",
                        format!("Management grant for '{peer_name_err}' was revoked while request was in flight"),
                    )
                    .into_response()
                }
            }
        })),
        log_context: format!("peer:{}", link.name),
        discard_request_body,
    };

    stream_proxy(req, target_url, &client, opts).await
}
