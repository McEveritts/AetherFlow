use crate::auth::{self, ActiveSubject, AuthUser, SessionClaims};
use af_models::APP_LAUNCH_EXCHANGE_PATH;
use af_runner::package_executor::{requires_external_app_auth, GATEWAY_APP_HEADER};
use axum::body::to_bytes;
use axum::extract::{ConnectInfo, Extension, Request};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use url::Url;

pub(crate) const APP_SESSION_COOKIE: &str = "__Host-aetherflow_app";
pub(crate) const LOCAL_APP_SESSION_COOKIE: &str = "aetherflow_local_app";
const APP_SESSION_ISSUER: &str = "aetherflow-app-session";
const TICKET_TTL: Duration = Duration::from_secs(30);
const MAX_PENDING_LAUNCHES: usize = 2048;

#[derive(Deserialize)]
pub(crate) struct LaunchRequest {
    app: String,
    destination: String,
}

#[derive(Serialize, Deserialize)]
struct AppSession {
    iss: String,
    aud: String,
    app: String,
    user_id: i64,
    jti: String,
    ver: i64,
    cfp: String,
    exp: i64,
}

struct LaunchTicket {
    session: AppSession,
    dashboard_origin: String,
    destination: Url,
    expires_at: Instant,
}

static LAUNCH_TICKETS: LazyLock<Mutex<HashMap<String, LaunchTicket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn user_agent(headers: &HeaderMap) -> &str {
    header_str(headers, "user-agent").unwrap_or_default()
}

/// TCP peer address recorded by `into_make_service_with_connect_info`, if present.
fn connect_info_peer_ip(extensions: &axum::http::Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

/// Binds legacy `ip|ua` fingerprints to the client IP resolved through
/// `extract_client_ip_for_peer` (`SEC-09`): forwarded headers are honoured only when the TCP peer
/// is a trusted proxy. When the peer address is unavailable (`authenticated_admin`, called with
/// headers only) the request has already been normalised by the outermost
/// `normalize_peer_forwarding_middleware` in `main.rs`, which strips spoofed forwarding headers.
fn matches_client(headers: &HeaderMap, peer_ip: Option<IpAddr>, fingerprint: &str) -> bool {
    auth::matches_client_fingerprint(
        fingerprint,
        &crate::ws::extract_client_ip_for_peer(headers, peer_ip),
        user_agent(headers),
    )
}

fn live_admin(user_id: i64, jti: &str, ver: i64, exp: i64) -> Option<ActiveSubject> {
    let now = Utc::now().timestamp();
    if exp <= now {
        return None;
    }
    let conn = af_db::get_read_conn().ok()?;
    let subject = auth::verify_active_session_on_conn(
        &conn,
        user_id,
        jti,
        ver,
        now,
        auth::RotationGrace::Disabled,
    )
    .ok()?;
    (subject.role == "admin").then_some(subject)
}

fn dashboard_origin(headers: &HeaderMap) -> Option<String> {
    let raw = header_str(headers, "origin")?;
    let origin = Url::parse(raw).ok()?;
    let host = header_str(headers, "host")?;
    let request_origin = Url::parse(&format!("{}://{host}", origin.scheme())).ok()?;
    let normalized = origin.origin().ascii_serialization();
    (matches!(origin.scheme(), "http" | "https")
        && raw == normalized
        && origin.origin() == request_origin.origin())
    .then_some(normalized)
}

fn managed_tls_vhost(app: &str, host: &str) -> bool {
    // A protected app may still have an inherited Apache vhost with its own
    // authentication. Only the enabled, generated gateway vhost advertises
    // the exchange. Match the marker and ServerName in the same TLS block.
    let path = af_services::mutators::resolve_config_path(&format!(
        "/etc/apache2/sites-enabled/aetherflow-ext-{app}.conf"
    ));
    let Ok(config) = std::fs::read_to_string(path) else {
        return false;
    };
    let marker = format!("RequestHeader set {GATEWAY_APP_HEADER} {app}");
    config.split("</VirtualHost>").any(|block| {
        let mut lines = block.lines().map(str::trim);
        if !lines.any(|line| line == "<VirtualHost *:443>") {
            return false;
        }
        let mut server = false;
        let mut gateway = false;
        for line in lines {
            if let Some(name) = line.strip_prefix("ServerName ") {
                server = name.eq_ignore_ascii_case(host);
            }
            gateway |= line == marker;
        }
        server && gateway
    })
}

fn configured_tls_port(app: &str, host: &str) -> Option<i32> {
    let cfg = af_db::get_app_ingress_config(app).ok()??;
    (cfg.external_access_enabled && cfg.tls_enabled && cfg.public_domain.eq_ignore_ascii_case(host))
        .then_some(cfg.listen_port)
}

fn is_single_label_local_app_host(app: &str, host: &str) -> bool {
    let expected = format!("{}.aether.local", app.trim().to_ascii_lowercase());
    let lower = host.trim().trim_end_matches('.').to_ascii_lowercase();
    !app.trim().is_empty()
        && !app.contains('.')
        && lower == expected
        && af_models::valid_ingress_hostname(&lower)
}

fn eligible_destination(req: &LaunchRequest) -> Option<Url> {
    if !requires_external_app_auth(&req.app) || req.destination.len() > 4096 {
        return None;
    }
    let destination = Url::parse(&req.destination).ok()?;
    let host = destination.host_str()?;
    if destination.port().is_some()
        || !destination.username().is_empty()
        || destination.password().is_some()
        || destination.path() == APP_LAUNCH_EXCHANGE_PATH
        || !af_models::valid_ingress_hostname(host)
    {
        return None;
    }
    match destination.scheme() {
        "https" => {
            if host.ends_with(".aether.local") {
                return None;
            }
            let port = configured_tls_port(&req.app, host)?;
            (crate::middlewares::resolve_app_target_for_host(host) == Some((req.app.clone(), port))
                && managed_tls_vhost(&req.app, host))
            .then_some(destination)
        }
        "http" => {
            if !is_single_label_local_app_host(&req.app, host) {
                return None;
            }
            crate::middlewares::resolve_app_target_for_host(host)
                .filter(|(resolved_app, port)| {
                    resolved_app == &req.app && (1..=65535).contains(port)
                })
                .map(|_| destination)
        }
        _ => None,
    }
}

fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

fn invalid_session() -> Response {
    auth::api_error(
        StatusCode::UNAUTHORIZED,
        "UNAUTHORIZED",
        "Invalid or revoked session",
    )
}

pub(crate) async fn issue(
    Extension(user): Extension<AuthUser>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<LaunchRequest>,
) -> Response {
    let peer_ip = connect_info.map(|ConnectInfo(addr)| addr.ip());
    auth::blocking_response(move || no_store(issue_blocking(user, headers, peer_ip, req))).await
}

fn issue_blocking(
    user: AuthUser,
    headers: HeaderMap,
    peer_ip: Option<IpAddr>,
    req: LaunchRequest,
) -> Response {
    let Some(destination) = eligible_destination(&req) else {
        return Json(serde_json::json!({})).into_response();
    };
    let Some(dashboard_origin) = dashboard_origin(&headers) else {
        return auth::api_error(
            StatusCode::FORBIDDEN,
            "INVALID_ORIGIN",
            "App launch requires a dashboard request",
        );
    };
    // The normal admin and CSRF middleware have authenticated the request. A
    // handoff also needs a currently active, unrotated human session to bind.
    let Some(claims) = auth::resolve_raw_token(&headers)
        .and_then(|token| auth::decode_session_claims(&token, false).ok())
        .filter(|claims| {
            claims.user_id == user.user_id
                && claims.jti == user.jti
                && matches_client(&headers, peer_ip, &claims.cfp)
        })
    else {
        return invalid_session();
    };
    let SessionClaims {
        user_id,
        jti,
        ver,
        exp,
        cfp,
        ..
    } = claims;
    if live_admin(user_id, &jti, ver, exp).is_none() {
        return invalid_session();
    }

    let session = AppSession {
        iss: APP_SESSION_ISSUER.into(),
        aud: destination.origin().ascii_serialization(),
        app: req.app,
        user_id,
        jti,
        ver,
        cfp: if cfp.is_empty() {
            auth::client_fingerprint(user_agent(&headers))
        } else {
            cfp
        },
        exp,
    };
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let ticket = hex::encode(key);
    let Ok(mut pending) = LAUNCH_TICKETS.lock() else {
        return unavailable();
    };
    let now = Instant::now();
    pending.retain(|_, entry| entry.expires_at > now);
    if pending.len() >= MAX_PENDING_LAUNCHES {
        return unavailable();
    }
    pending.insert(
        ticket.clone(),
        LaunchTicket {
            session,
            dashboard_origin,
            destination,
            expires_at: now + TICKET_TTL,
        },
    );
    Json(serde_json::json!({ "ticket": ticket })).into_response()
}

fn unavailable() -> Response {
    auth::api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "APP_LAUNCH_UNAVAILABLE",
        "App launch is temporarily unavailable",
    )
}

pub(crate) fn managed_origin(headers: &HeaderMap, raw_host: &str, managed: bool) -> Option<String> {
    if managed {
        if header_str(headers, "x-forwarded-proto")? != "https" {
            return None;
        }
        let host = raw_host.strip_suffix(":443").unwrap_or(raw_host);
        return af_models::valid_ingress_hostname(host)
            .then(|| format!("https://{}", host.to_ascii_lowercase()));
    }
    let host = raw_host
        .trim()
        .strip_suffix(":80")
        .unwrap_or_else(|| raw_host.trim())
        .trim_end_matches('.');
    let lower = host.to_ascii_lowercase();
    let proto_is_http = header_str(headers, "x-forwarded-proto")
        .is_none_or(|proto| proto.trim().eq_ignore_ascii_case("http"));
    let is_single_label_local = lower
        .strip_suffix(".aether.local")
        .is_some_and(|label| !label.is_empty() && !label.contains('.'));
    (proto_is_http && is_single_label_local && af_models::valid_ingress_hostname(&lower))
        .then(|| format!("http://{lower}"))
}

pub(crate) async fn redeem(req: Request, app: String, origin: Option<String>) -> Response {
    let Some(origin) = origin else {
        return no_store(StatusCode::NOT_FOUND.into_response());
    };
    if req.method() != Method::POST {
        return no_store(
            (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response(),
        );
    }
    let (parts, body) = req.into_parts();
    if header_str(&parts.headers, "content-type") != Some("application/x-www-form-urlencoded") {
        return no_store(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
    }
    // A browser submits only one hex field. Limit the body before reading it.
    let Ok(body) = to_bytes(body, 128).await else {
        return no_store(StatusCode::BAD_REQUEST.into_response());
    };
    let Some(ticket) = body
        .strip_prefix(b"ticket=")
        .filter(|ticket| ticket.len() == 64 && ticket.iter().all(u8::is_ascii_hexdigit))
    else {
        return no_store(StatusCode::BAD_REQUEST.into_response());
    };
    let ticket = String::from_utf8_lossy(ticket).into_owned();
    let peer_ip = connect_info_peer_ip(&parts.extensions);
    auth::blocking_response(move || {
        no_store(redeem_blocking(
            &ticket,
            &parts.headers,
            peer_ip,
            &app,
            &origin,
        ))
    })
    .await
}

fn redeem_blocking(
    ticket: &str,
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    app: &str,
    origin: &str,
) -> Response {
    let entry = LAUNCH_TICKETS.lock().ok().and_then(|mut pending| {
        let entry = pending.get(ticket)?;
        if entry.expires_at <= Instant::now() {
            pending.remove(ticket);
            return None;
        }
        if entry.session.app != app
            || entry.session.aud != origin
            || Some(entry.dashboard_origin.as_str()) != header_str(headers, "origin")
            || !matches_client(headers, peer_ip, &entry.session.cfp)
        {
            return None;
        }
        pending.remove(ticket)
    });
    let Some(LaunchTicket {
        session,
        destination,
        ..
    }) = entry
    else {
        return invalid_session();
    };
    let (cookie_name, secure_cookie, origin_allowed) =
        if let Some(host) = origin.strip_prefix("https://") {
            (
                APP_SESSION_COOKIE,
                true,
                configured_tls_port(app, host).is_some(),
            )
        } else if let Some(host) = origin.strip_prefix("http://") {
            let allowed = is_single_label_local_app_host(app, host)
                && crate::middlewares::resolve_app_target_for_host(host)
                    .is_some_and(|(resolved, port)| resolved == app && (1..=65535).contains(&port));
            (LOCAL_APP_SESSION_COOKIE, false, allowed)
        } else {
            (APP_SESSION_COOKIE, true, false)
        };
    if !origin_allowed
        || live_admin(session.user_id, &session.jti, session.ver, session.exp).is_none()
    {
        return invalid_session();
    }

    let Ok(token) = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &session,
        &EncodingKey::from_secret(&auth::jwt_secret_bytes()),
    ) else {
        return unavailable();
    };
    let max_age = session.exp - Utc::now().timestamp();
    if max_age <= 0 {
        return invalid_session();
    }
    let cookie =
        crate::ws::build_set_cookie(cookie_name, &token, max_age, "Lax", secure_cookie, true);
    let Ok(cookie) = HeaderValue::from_str(&cookie) else {
        return unavailable();
    };
    let mut response = Redirect::to(destination.as_str()).into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

pub(crate) fn authenticated_admin(headers: &HeaderMap, app: &str, origin: &str) -> Option<String> {
    let cookie_name = if let Some(host) = origin.strip_prefix("https://") {
        configured_tls_port(app, host)?;
        APP_SESSION_COOKIE
    } else {
        let host = origin.strip_prefix("http://")?;
        if !is_single_label_local_app_host(app, host) {
            return None;
        }
        LOCAL_APP_SESSION_COOKIE
    };
    let token = crate::ws::extract_cookie(headers, cookie_name)?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[origin]);
    validation.set_issuer(&[APP_SESSION_ISSUER]);
    let claims = jsonwebtoken::decode::<AppSession>(
        &token,
        &DecodingKey::from_secret(&auth::jwt_secret_bytes()),
        &validation,
    )
    .ok()?
    .claims;
    if claims.app != app || !matches_client(headers, None, &claims.cfp) {
        return None;
    }
    live_admin(claims.user_id, &claims.jti, claims.ver, claims.exp).map(|subject| subject.username)
}
