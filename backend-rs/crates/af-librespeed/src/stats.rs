use crate::config::Config;
use crate::db::{TelemetryRecord, TelemetryVault};
use crate::redact::{
    extract_trusted_forwarded_ip_with_secret, is_trusted_proxy_peer, peer_ip_key,
    verify_proxy_secret,
};
use crate::ulid::{canonicalize_ulid, obfuscate_ulid, resolve_id};
use axum::body::Body;
use axum::extract::{ConnectInfo, OriginalUri, Query, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, COOKIE, LOCATION,
    RETRY_AFTER, SET_COOKIE, TRANSFER_ENCODING,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Version};
use axum::response::{Html, IntoResponse, Response};
use chrono::Utc;
use futures::StreamExt;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserialize;
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "logged";
const SESSION_TTL_SECS: i64 = 3600;
const LOGIN_WINDOW_SECS: i64 = 60;
const MAX_FAILED_LOGINS_PER_WINDOW: usize = 10;
pub const MAX_FAILED_LOGINS_PER_PROXY_PEER: usize = 50;
const MAX_TRACKED_LOGIN_IPS: usize = 4096;
const MAX_STATS_FORM_BYTES: usize = 64 * 1024;
const STATS_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

#[derive(Clone)]
pub struct StatsAuth {
    auth_key: [u8; 32],
    session_key: [u8; 32],
    login_attempts: Arc<Mutex<HashMap<String, (usize, i64)>>>,
}

impl Default for StatsAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsAuth {
    pub fn new() -> Self {
        let mut auth_key = [0u8; 32];
        let mut session_key = [0u8; 32];
        OsRng.fill_bytes(&mut auth_key);
        OsRng.fill_bytes(&mut session_key);
        Self {
            auth_key,
            session_key,
            login_attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn verify_password(&self, configured: &str, candidate: &str) -> bool {
        let trimmed = configured.trim();
        if trimmed.is_empty() || trimmed == "PASSWORD" {
            return false;
        }
        let expected_tag = compute_hmac(&self.auth_key, configured.as_bytes());
        let actual_tag = compute_hmac(&self.auth_key, candidate.as_bytes());
        constant_time_eq(&expected_tag, &actual_tag)
    }

    pub fn check_login_allowed(&self, ip: &str, now_unix: i64) -> bool {
        self.check_login_allowed_with_limit(ip, MAX_FAILED_LOGINS_PER_WINDOW, now_unix)
    }

    pub fn check_login_allowed_with_limit(
        &self,
        key: &str,
        max_failures: usize,
        now_unix: i64,
    ) -> bool {
        let Ok(mut map) = self.login_attempts.lock() else {
            return false;
        };
        active_login_count(&mut map, key, now_unix) < max_failures
    }

    /// Atomically checks both the per-client (`10/60s`) and optional outer per-proxy-peer
    /// (`50/60s`) login failure budgets and reserves one slot under a single mutex acquisition
    /// before `verify_password` runs, eliminating concurrent burst bypass races.
    pub fn try_reserve_login_attempt(
        &self,
        rate_key: &str,
        outer_proxy_key: Option<&str>,
        now_unix: i64,
    ) -> bool {
        let Ok(mut map) = self.login_attempts.lock() else {
            return false;
        };
        if active_login_count(&mut map, rate_key, now_unix) >= MAX_FAILED_LOGINS_PER_WINDOW {
            return false;
        }
        if let Some(pk) = outer_proxy_key {
            if pk != rate_key
                && active_login_count(&mut map, pk, now_unix) >= MAX_FAILED_LOGINS_PER_PROXY_PEER
            {
                return false;
            }
        }
        increment_login_bucket(&mut map, rate_key, now_unix);
        if let Some(pk) = outer_proxy_key {
            if pk != rate_key {
                increment_login_bucket(&mut map, pk, now_unix);
            }
        }
        true
    }

    /// Refunds a reserved login attempt upon successful authentication: clears `rate_key`
    /// and decrements `outer_proxy_key` by 1 without erasing unrelated failures on the proxy peer.
    pub fn complete_login_success(&self, rate_key: &str, outer_proxy_key: Option<&str>) {
        let Ok(mut map) = self.login_attempts.lock() else {
            return;
        };
        map.remove(rate_key);
        if let Some(pk) = outer_proxy_key {
            if pk != rate_key {
                if let Some((count, _)) = map.get_mut(pk) {
                    if *count <= 1 {
                        map.remove(pk);
                    } else {
                        *count -= 1;
                    }
                }
            }
        }
    }

    pub fn record_login_failure(&self, ip: &str, now_unix: i64) {
        let Ok(mut map) = self.login_attempts.lock() else {
            return;
        };
        increment_login_bucket(&mut map, ip, now_unix);
    }

    pub fn clear_login_failures(&self, ip: &str) {
        if let Ok(mut map) = self.login_attempts.lock() {
            map.remove(ip);
        }
    }

    pub fn issue_cookie_token(&self, now_unix: i64) -> String {
        let expires = now_unix.saturating_add(SESSION_TTL_SECS);
        let exp_str = expires.to_string();
        let sig = compute_hmac(&self.session_key, exp_str.as_bytes());
        format!("{exp_str}.{}", hex::encode(sig))
    }

    pub fn verify_cookie_token(&self, token: &str, now_unix: i64) -> bool {
        let Some((exp_str, sig_hex)) = token.split_once('.') else {
            return false;
        };
        let Ok(expires) = exp_str.parse::<i64>() else {
            return false;
        };
        if now_unix > expires {
            return false;
        }
        let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else {
            return false;
        };
        let expected_sig = compute_hmac(&self.session_key, exp_str.as_bytes());
        constant_time_eq(&sig_bytes, &expected_sig)
    }
}

fn active_login_count(map: &mut HashMap<String, (usize, i64)>, key: &str, now_unix: i64) -> usize {
    if let Some(&(count, window_start)) = map.get(key) {
        if now_unix.saturating_sub(window_start) < LOGIN_WINDOW_SECS {
            return count;
        }
        map.remove(key);
    }
    0
}

fn increment_login_bucket(map: &mut HashMap<String, (usize, i64)>, key: &str, now_unix: i64) {
    if map.len() >= MAX_TRACKED_LOGIN_IPS && !map.contains_key(key) {
        map.retain(|_, (_, ws)| now_unix.saturating_sub(*ws) < LOGIN_WINDOW_SECS);
        if map.len() >= MAX_TRACKED_LOGIN_IPS {
            if let Some(oldest_ip) = map
                .iter()
                .min_by_key(|(_, (_, ws))| *ws)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_ip);
            }
        }
    }
    let entry = map.entry(key.to_string()).or_insert((0, now_unix));
    if now_unix.saturating_sub(entry.1) >= LOGIN_WINDOW_SECS {
        *entry = (1, now_unix);
    } else {
        entry.0 = entry.0.saturating_add(1);
    }
}

fn compute_hmac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

const TELEMETRY_WINDOW_SECS: i64 = 60;
const MAX_TELEMETRY_PER_CLIENT_IP: usize = 30;
const MAX_TELEMETRY_PER_PEER_IP: usize = 60;
pub const MAX_TELEMETRY_PER_PROXY_PEER_IP: usize = 120;
const MAX_TELEMETRY_GLOBAL_PER_WINDOW: usize = 300;
const MAX_TRACKED_TELEMETRY_IPS: usize = 4096;

#[derive(Default)]
struct TelemetryRateWindow {
    global_count: usize,
    global_window_start: i64,
    by_peer: HashMap<String, (usize, i64)>,
    by_client: HashMap<String, (usize, i64)>,
}

#[derive(Clone, Default)]
pub struct TelemetryRateLimiter {
    inner: Arc<Mutex<TelemetryRateWindow>>,
}

impl TelemetryRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_acquire(
        &self,
        peer_ip: &str,
        client_ip: &str,
        is_trusted_proxy: bool,
        now_unix: i64,
    ) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };

        if now_unix.saturating_sub(state.global_window_start) >= TELEMETRY_WINDOW_SECS {
            state.global_count = 0;
            state.global_window_start = now_unix;
        }

        let client_used = current_bucket_count(&mut state.by_client, client_ip, now_unix);
        if client_used >= MAX_TELEMETRY_PER_CLIENT_IP {
            return false;
        }

        let peer_limit = if is_trusted_proxy {
            MAX_TELEMETRY_PER_PROXY_PEER_IP
        } else {
            MAX_TELEMETRY_PER_PEER_IP
        };
        let peer_used = current_bucket_count(&mut state.by_peer, peer_ip, now_unix);
        if peer_used >= peer_limit {
            return false;
        }

        if state.global_count >= MAX_TELEMETRY_GLOBAL_PER_WINDOW {
            return false;
        }

        bump_bucket(&mut state.by_client, client_ip, now_unix);
        bump_bucket(&mut state.by_peer, peer_ip, now_unix);
        state.global_count = state.global_count.saturating_add(1);
        true
    }
}

fn current_bucket_count(
    map: &mut HashMap<String, (usize, i64)>,
    key: &str,
    now_unix: i64,
) -> usize {
    if let Some(&(count, ws)) = map.get(key) {
        if now_unix.saturating_sub(ws) < TELEMETRY_WINDOW_SECS {
            return count;
        }
        map.remove(key);
    }
    0
}

fn bump_bucket(map: &mut HashMap<String, (usize, i64)>, key: &str, now_unix: i64) {
    if map.len() >= MAX_TRACKED_TELEMETRY_IPS && !map.contains_key(key) {
        map.retain(|_, (_, ws)| now_unix.saturating_sub(*ws) < TELEMETRY_WINDOW_SECS);
        if map.len() >= MAX_TRACKED_TELEMETRY_IPS {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, (_, ws))| *ws)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            }
        }
    }
    let entry = map.entry(key.to_string()).or_insert((0, now_unix));
    if now_unix.saturating_sub(entry.1) >= TELEMETRY_WINDOW_SECS {
        *entry = (1, now_unix);
    } else {
        entry.0 = entry.0.saturating_add(1);
    }
}

const MAX_GARBAGE_TRACKED_IPS: usize = 4096;

#[derive(Clone, Default)]
pub struct GarbageIpTracker {
    active: Arc<Mutex<HashMap<String, usize>>>,
}

pub struct GarbageStreamGuard {
    active: Arc<Mutex<HashMap<String, usize>>>,
    ip: String,
}

impl Drop for GarbageStreamGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.active.lock() {
            if let Some(count) = map.get_mut(&self.ip) {
                if *count <= 1 {
                    map.remove(&self.ip);
                } else {
                    *count -= 1;
                }
            }
        }
    }
}

impl GarbageIpTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_acquire(&self, ip: &str, max_per_ip: usize) -> Option<GarbageStreamGuard> {
        let mut map = self.active.lock().ok()?;
        let current = map.get(ip).copied().unwrap_or(0);
        if current >= max_per_ip {
            return None;
        }
        if map.len() >= MAX_GARBAGE_TRACKED_IPS && !map.contains_key(ip) {
            return None;
        }
        *map.entry(ip.to_string()).or_insert(0) = current + 1;
        Some(GarbageStreamGuard {
            active: Arc::clone(&self.active),
            ip: ip.to_string(),
        })
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub vault: Option<TelemetryVault>,
    pub stats_auth: StatsAuth,
    pub obfuscation_key: [u8; 32],
    pub garbage_semaphore: Arc<Semaphore>,
    pub garbage_ip_tracker: GarbageIpTracker,
    pub garbage_stream_timeout: Duration,
    pub upload_semaphore: Arc<Semaphore>,
    pub upload_ip_tracker: GarbageIpTracker,
    pub empty_upload_timeout: Duration,
    pub stats_body_timeout: Duration,
    pub telemetry_limiter: TelemetryRateLimiter,
    pub isp_cache: crate::routes::IspLookupCache,
    pub http_client: Option<reqwest::Client>,
}

#[derive(Debug, Deserialize, Default)]
pub struct StatsQuery {
    #[serde(default)]
    pub op: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
}

fn stats_html_response(status: StatusCode, html_body: String) -> Response {
    (
        status,
        [
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (CONTENT_SECURITY_POLICY, HeaderValue::from_static(STATS_CSP)),
        ],
        Html(html_body),
    )
        .into_response()
}

fn request_declares_body(headers: &HeaderMap) -> bool {
    if headers.contains_key(TRANSFER_ENCODING) {
        return true;
    }
    headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .map(|raw| {
            let trimmed = raw.trim();
            !trimmed.is_empty() && trimmed != "0"
        })
        .unwrap_or(false)
}

fn close_h1_if_unread_body(
    mut resp: Response,
    unread_body: bool,
    version: Version,
    conn_abort: &Option<axum::Extension<crate::tls::ConnectionAbortSignal>>,
) -> Response {
    if unread_body {
        if version != Version::HTTP_2 {
            resp.headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
            if let Some(axum::Extension(sig)) = conn_abort {
                sig.abort_after_flush();
            }
        } else {
            resp.extensions_mut()
                .insert(crate::tls::ResponseDrainDeadline(Duration::from_secs(5)));
        }
    }
    resp
}

fn is_https_via_trusted_proxy(
    peer_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpAddr],
    proxy_secret: &str,
) -> bool {
    if !is_trusted_proxy_peer(peer_addr, trusted_proxies)
        || !verify_proxy_secret(headers, proxy_secret)
    {
        return false;
    }
    headers
        .get_all("x-forwarded-proto")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| raw.rsplit(',').next())
        .map(|proto| proto.trim().eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

pub async fn handle_stats(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    OriginalUri(orig_uri): OriginalUri,
    Query(query): Query<StatsQuery>,
    req: Request<Body>,
) -> Response {
    let (parts, body) = req.into_parts();
    let version = parts.version;
    let method = parts.method;
    let headers = parts.headers;
    let conn_abort = parts
        .extensions
        .get::<crate::tls::ConnectionAbortSignal>()
        .cloned()
        .map(axum::Extension);
    let peer_addr = peer.map(|ConnectInfo(addr)| addr);
    let cookie_path = resolve_stats_cookie_path(&state.config.url_base, orig_uri.path());
    let secure_attr = if state.config.enable_tls
        || is_https_via_trusted_proxy(
            peer_addr,
            &headers,
            &state.config.trusted_proxies,
            &state.config.trusted_proxy_secret,
        ) {
        "; Secure"
    } else {
        ""
    };
    let declared_body = request_declares_body(&headers);

    if !state.config.telemetry_enabled() || state.vault.is_none() {
        return close_h1_if_unread_body(
            stats_html_response(
                StatusCode::SERVICE_UNAVAILABLE,
                render_layout(
                    "Telemetry Disabled",
                    r#"<section class="obs-auth-panel">
                    <h2>Statistics Disabled</h2>
                    <p class="obs-muted">Telemetry storage is currently disabled (<code>database_type = "none"</code>).</p>
                </section>"#,
                ),
            ),
            declared_body,
            version,
            &conn_abort,
        );
    }

    let form_map = if method == Method::POST {
        let mut stream = body.into_data_stream();
        let mut raw_body = Vec::with_capacity(256);
        let body_read = tokio::time::timeout(state.stats_body_timeout, async {
            while let Some(next_chunk) = stream.next().await {
                let Ok(chunk) = next_chunk else {
                    return Err((StatusCode::BAD_REQUEST, "failed reading stats form body"));
                };
                if raw_body.len().saturating_add(chunk.len()) > MAX_STATS_FORM_BYTES {
                    return Err((
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "stats form body exceeds 64 KiB limit",
                    ));
                }
                raw_body.extend_from_slice(&chunk);
            }
            Ok(())
        })
        .await;

        match body_read {
            Err(_) => {
                return close_h1_if_unread_body(
                    (
                        StatusCode::REQUEST_TIMEOUT,
                        "stats request body read timed out",
                    )
                        .into_response(),
                    true,
                    version,
                    &conn_abort,
                );
            }
            Ok(Err(err_resp)) => {
                return close_h1_if_unread_body(
                    err_resp.into_response(),
                    true,
                    version,
                    &conn_abort,
                );
            }
            Ok(Ok(())) => parse_urlencoded_map(&raw_body),
        }
    } else {
        HashMap::new()
    };

    let unread_non_post_body = method != Method::POST && declared_body;

    let op = form_map
        .get("op")
        .cloned()
        .or_else(|| query.op.clone())
        .unwrap_or_default();

    if op == "logout" {
        if method != Method::POST {
            return close_h1_if_unread_body(
                (StatusCode::METHOD_NOT_ALLOWED, "POST required for logout").into_response(),
                unread_non_post_body,
                version,
                &conn_abort,
            );
        }
        let now_logout = Utc::now().timestamp();
        let has_valid_session = extract_cookie(&headers, COOKIE_NAME)
            .map(|tok| state.stats_auth.verify_cookie_token(&tok, now_logout))
            .unwrap_or(false);
        if !has_valid_session {
            return stats_html_response(StatusCode::OK, render_login_page(&cookie_path, None));
        }
        return redirect_with_cookie(
            &cookie_path,
            &format!(
                "{COOKIE_NAME}=; Path={cookie_path}; Max-Age=0; HttpOnly; SameSite=Strict{secure_attr}"
            ),
        );
    }

    if state.config.stats_locked() {
        return close_h1_if_unread_body(
            stats_html_response(
                StatusCode::OK,
                render_layout(
                    "Statistics Locked",
                    r#"<section class="obs-auth-panel">
                    <h2>Statistics Access Locked</h2>
                    <p class="obs-alert">Set a custom non-default <code>statistics_password</code> in <code>settings.toml</code> to unlock the telemetry vault.</p>
                </section>"#,
                ),
            ),
            unread_non_post_body,
            version,
            &conn_abort,
        );
    }

    let now_unix = Utc::now().timestamp();

    if method == Method::POST && op == "login" {
        // When accessed via an explicitly configured trusted reverse proxy (e.g. loopback Apache)
        // that supplies a valid forwarded client IP, key login throttling primarily on that client IP
        // (10 failures / 60s) so one remote attacker cannot easily lock out normal users sharing the
        // proxy, while ALSO enforcing an outer per-proxy-peer ceiling (50 failures / 60s) so a local
        // loopback user rotating X-Forwarded-For directly against the listener cannot brute-force a
        // custom statistics password.
        let peer_raw = peer_ip_key(peer_addr);
        let (rate_key, outer_proxy_key) = match extract_trusted_forwarded_ip_with_secret(
            peer_addr,
            &headers,
            &state.config.trusted_proxies,
            &state.config.trusted_proxy_secret,
        ) {
            Some(forwarded_ip) => (
                format!("client:{forwarded_ip}"),
                Some(format!("proxy_peer:{peer_raw}")),
            ),
            None => (format!("peer:{peer_raw}"), None),
        };
        if !state.stats_auth.try_reserve_login_attempt(
            &rate_key,
            outer_proxy_key.as_deref(),
            now_unix,
        ) {
            let mut resp = stats_html_response(
                StatusCode::TOO_MANY_REQUESTS,
                render_login_page(
                    &cookie_path,
                    Some("Too many failed login attempts. Please wait 60 seconds."),
                ),
            );
            resp.headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("60"));
            return resp;
        }

        let candidate = form_map.get("password").map(String::as_str).unwrap_or("");
        if state
            .stats_auth
            .verify_password(&state.config.statistics_password, candidate)
        {
            state
                .stats_auth
                .complete_login_success(&rate_key, outer_proxy_key.as_deref());
            let token = state.stats_auth.issue_cookie_token(now_unix);
            let set_cookie = format!(
                "{COOKIE_NAME}={token}; Path={cookie_path}; Max-Age={SESSION_TTL_SECS}; HttpOnly; SameSite=Strict{secure_attr}"
            );
            return redirect_with_cookie(&cookie_path, &set_cookie);
        }
        return stats_html_response(
            StatusCode::UNAUTHORIZED,
            render_login_page(&cookie_path, Some("Invalid statistics password.")),
        );
    }

    let is_authenticated = extract_cookie(&headers, COOKIE_NAME)
        .map(|tok| state.stats_auth.verify_cookie_token(&tok, now_unix))
        .unwrap_or(false);

    if !is_authenticated {
        return close_h1_if_unread_body(
            stats_html_response(StatusCode::OK, render_login_page(&cookie_path, None)),
            unread_non_post_body,
            version,
            &conn_abort,
        );
    }

    let lookup_id = form_map
        .get("id")
        .cloned()
        .or_else(|| query.id.clone())
        .unwrap_or_default()
        .trim()
        .to_string();

    let vault = state.vault.as_ref().expect("checked above");
    let mut body_html = String::new();
    render_toolbar(&mut body_html, &cookie_path, &lookup_id);

    if lookup_id.eq_ignore_ascii_case("L100") || (op.is_empty() && lookup_id.is_empty()) {
        match vault.list_recent(100).await {
            Ok(records) => {
                render_recent_table(
                    &mut body_html,
                    &records,
                    &state.config,
                    &state.obfuscation_key,
                    &cookie_path,
                );
            }
            Err(err) => {
                tracing::error!(error = %err, "Failed querying recent telemetry records");
                body_html.push_str(
                    r#"<div class="obs-record-block"><p class="obs-alert">Database query error while reading recent tests.</p></div>"#,
                );
            }
        }
    } else {
        let mut resolved = resolve_id(
            &lookup_id,
            state.config.enable_id_obfuscation,
            &state.obfuscation_key,
        );
        if resolved.is_none() && state.config.enable_id_obfuscation {
            // Allow authenticated admins in /stats to also search directly by canonical DB UUID.
            resolved = canonicalize_ulid(&lookup_id);
        }
        let target_uuid = resolved.unwrap_or_else(|| lookup_id.clone());
        let mut record_opt = match vault.get_by_uuid(target_uuid.clone()).await {
            Ok(Some(r)) => Some(r),
            Ok(None) if state.config.enable_id_obfuscation => {
                if let Some(canon) = canonicalize_ulid(&lookup_id) {
                    if canon != target_uuid {
                        vault.get_by_uuid(canon).await.ok().flatten()
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            Ok(None) => None,
            Err(err) => {
                tracing::error!(error = %err, "Failed looking up telemetry record");
                None
            }
        };
        if record_opt.is_none() && lookup_id.len() == 22 {
            if let Ok(Some(legacy_uuid)) = vault.resolve_legacy_go_share_id(lookup_id.clone()).await
            {
                record_opt = vault.get_by_uuid(legacy_uuid).await.ok().flatten();
            }
        }

        match record_opt {
            Some(rec) => {
                render_single_record(
                    &mut body_html,
                    &rec,
                    &state.config,
                    &state.obfuscation_key,
                    &cookie_path,
                );
            }
            None => {
                let escaped_id = escape_html(&lookup_id);
                let _ = write!(
                    body_html,
                    r#"<div class="obs-record-block"><p class="obs-alert">No speedtest record found for ID <code>{escaped_id}</code>.</p></div>"#
                );
            }
        }
    }

    stats_html_response(
        StatusCode::OK,
        render_layout("LibreSpeed Telemetry Vault", &body_html),
    )
}

pub fn resolve_stats_cookie_path(url_base: &str, request_path: &str) -> String {
    if !url_base.is_empty() {
        let prefixed = format!("/{url_base}");
        if request_path == prefixed || request_path.starts_with(&format!("{prefixed}/")) {
            return format!("{prefixed}/stats");
        }
    }
    "/stats".to_string()
}

fn redirect_with_cookie(location: &str, set_cookie: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(loc) = HeaderValue::from_str(location) {
        headers.insert(LOCATION, loc);
    }
    if let Ok(sc) = HeaderValue::from_str(set_cookie) {
        headers.insert(SET_COOKIE, sc);
    }
    (StatusCode::SEE_OTHER, headers).into_response()
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for val in headers.get_all(COOKIE) {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            let trimmed = pair.trim();
            if let Some((k, v)) = trimmed.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

pub fn parse_urlencoded_map(body: &[u8]) -> HashMap<String, String> {
    let text = String::from_utf8_lossy(body);
    let mut map = HashMap::new();
    for pair in text.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = decode_form_component(raw_k);
        let v = decode_form_component(raw_v);
        map.insert(k, v);
    }
    map
}

pub fn decode_form_component(raw: &str) -> String {
    let plus_as_space = raw.replace('+', " ");
    urlencoding::decode(&plus_as_space)
        .map(|cow| cow.into_owned())
        .unwrap_or(plus_as_space)
}

pub fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn results_prefix_for_stats(stats_path: &str) -> String {
    stats_path.strip_suffix("/stats").unwrap_or("").to_string()
}

fn render_login_page(stats_path: &str, error_msg: Option<&str>) -> String {
    let escaped_path = escape_html(stats_path);
    let err_html = match error_msg {
        Some(msg) => format!(r#"<p class="obs-alert">{}</p>"#, escape_html(msg)),
        None => String::new(),
    };
    let inner = format!(
        r#"<section class="obs-auth-panel">
            <h2>LibreSpeed Statistics</h2>
            <p class="obs-muted">Enter the administrator statistics password to inspect speedtest telemetry.</p>
            {err_html}
            <form method="POST" action="{escaped_path}" class="obs-form-stack">
                <input type="hidden" name="op" value="login">
                <label for="obs-pw">Statistics Password</label>
                <input id="obs-pw" type="password" name="password" placeholder="Password" autocomplete="current-password" required autofocus>
                <button type="submit" class="obs-btn obs-btn-primary">Unlock Telemetry Vault</button>
            </form>
        </section>"#
    );
    render_layout("LibreSpeed Statistics Login", &inner)
}

fn render_toolbar(out: &mut String, stats_path: &str, lookup_id: &str) {
    let escaped_path = escape_html(stats_path);
    let escaped_lookup = escape_html(lookup_id);
    let _ = write!(
        out,
        r#"<div class="obs-toolbar-strip">
            <form method="GET" action="{escaped_path}" class="obs-search-form">
                <input type="hidden" name="op" value="id">
                <input type="text" name="id" value="{escaped_lookup}" placeholder="Test ID (or L100 for last 100)">
                <button type="submit" class="obs-btn obs-btn-primary">Lookup</button>
            </form>
            <div class="obs-toolbar-actions">
                <a class="obs-btn" href="{escaped_path}?op=id&amp;id=L100">Last 100 Tests</a>
                <form method="POST" action="{escaped_path}" class="obs-inline-form">
                    <input type="hidden" name="op" value="logout">
                    <button type="submit" class="obs-btn obs-btn-danger">Logout</button>
                </form>
            </div>
        </div>"#
    );
}

fn render_recent_table(
    out: &mut String,
    records: &[TelemetryRecord],
    cfg: &Config,
    obfuscation_key: &[u8; 32],
    stats_path: &str,
) {
    let escaped_stats = escape_html(stats_path);
    let results_base = escape_html(&results_prefix_for_stats(stats_path));
    out.push_str(r#"<div class="obs-record-block"><h3>Recent Speedtests (up to 100)</h3>"#);
    if records.is_empty() {
        out.push_str(
            r#"<p class="obs-muted">No speedtest telemetry records recorded yet.</p></div>"#,
        );
        return;
    }

    out.push_str(
        r#"<div class="obs-table-wrap"><table class="obs-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Timestamp (UTC)</th>
                    <th>IP</th>
                    <th>Download</th>
                    <th>Upload</th>
                    <th>Ping</th>
                    <th>Jitter</th>
                    <th>Badge</th>
                </tr>
            </thead>
            <tbody>"#,
    );

    for rec in records {
        let external_id = if cfg.enable_id_obfuscation {
            obfuscate_ulid(&rec.uuid, obfuscation_key)
        } else {
            rec.uuid.clone()
        };
        let esc_ext = escape_html(&external_id);
        let esc_ts = escape_html(&rec.timestamp);
        let esc_ip = escape_html(&rec.ip);
        let esc_dl = escape_html(&rec.dl);
        let esc_ul = escape_html(&rec.ul);
        let esc_ping = escape_html(&rec.ping);
        let esc_jitter = escape_html(&rec.jitter);

        let _ = write!(
            out,
            r#"<tr>
                <td><a href="{escaped_stats}?op=id&amp;id={esc_ext}"><code>{esc_ext}</code></a></td>
                <td>{esc_ts}</td>
                <td>{esc_ip}</td>
                <td>{esc_dl} Mbps</td>
                <td>{esc_ul} Mbps</td>
                <td>{esc_ping} ms</td>
                <td>{esc_jitter} ms</td>
                <td><a href="{results_base}/results?id={esc_ext}" target="_blank">PNG</a></td>
            </tr>"#
        );
    }

    out.push_str("</tbody></table></div></div>");
}

fn render_single_record(
    out: &mut String,
    rec: &TelemetryRecord,
    cfg: &Config,
    obfuscation_key: &[u8; 32],
    stats_path: &str,
) {
    let external_id = if cfg.enable_id_obfuscation {
        obfuscate_ulid(&rec.uuid, obfuscation_key)
    } else {
        rec.uuid.clone()
    };
    let esc_ext = escape_html(&external_id);
    let esc_uuid = escape_html(&rec.uuid);
    let results_base = escape_html(&results_prefix_for_stats(stats_path));

    let _ = write!(
        out,
        r#"<div class="obs-record-block">
            <div class="obs-record-header">
                <h3>Speedtest Record <code>{esc_ext}</code></h3>
                <a class="obs-btn" href="{results_base}/results?id={esc_ext}" target="_blank">Open PNG Badge</a>
            </div>
            <table class="obs-table">
                <tbody>
                    <tr><th>Canonical UUID</th><td><code>{esc_uuid}</code></td></tr>
                    <tr><th>Timestamp</th><td>{ts}</td></tr>
                    <tr><th>Client IP</th><td>{ip}</td></tr>
                    <tr><th>Download</th><td>{dl} Mbps</td></tr>
                    <tr><th>Upload</th><td>{ul} Mbps</td></tr>
                    <tr><th>Ping</th><td>{ping} ms</td></tr>
                    <tr><th>Jitter</th><td>{jitter} ms</td></tr>
                    <tr><th>ISP Info</th><td><pre>{ispinfo}</pre></td></tr>
                    <tr><th>User Agent</th><td>{ua}</td></tr>
                    <tr><th>Language</th><td>{lang}</td></tr>
                    <tr><th>Extra</th><td><pre>{extra}</pre></td></tr>
                    <tr><th>Log</th><td><pre>{log}</pre></td></tr>
                </tbody>
            </table>
        </div>"#,
        ts = escape_html(&rec.timestamp),
        ip = escape_html(&rec.ip),
        dl = escape_html(&rec.dl),
        ul = escape_html(&rec.ul),
        ping = escape_html(&rec.ping),
        jitter = escape_html(&rec.jitter),
        ispinfo = escape_html(&rec.ispinfo),
        ua = escape_html(&rec.ua),
        lang = escape_html(&rec.lang),
        extra = escape_html(&rec.extra),
        log = escape_html(&rec.log),
    );
}

fn render_layout(title: &str, body_inner: &str) -> String {
    let esc_title = escape_html(title);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc_title}</title>
<style>
:root {{
    color-scheme: dark;
    --bg: #080a18;
    --card: #0f1429;
    --surface: #141a36;
    --border: #232b52;
    --accent: #6366f1;
    --accent-2: #818cf8;
    --fuchsia: #d946ef;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --danger: #f87171;
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    padding: 24px;
    background: radial-gradient(circle at top right, #171c3d, var(--bg) 55%);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    min-height: 100vh;
}}
.obs-stats-shell {{
    max-width: 1120px;
    margin: 0 auto;
}}
.obs-auth-panel, .obs-record-block {{
    background: var(--card);
    border: 1px solid var(--border);
    border-top: 3px solid var(--accent);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 20px;
}}
.obs-auth-panel {{ max-width: 460px; margin: 60px auto; }}
.obs-toolbar-strip {{
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    justify-content: space-between;
    align-items: center;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 20px;
}}
.obs-search-form, .obs-toolbar-actions {{
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
}}
.obs-inline-form {{ margin: 0; display: inline-flex; }}
.obs-form-stack {{ display: flex; flex-direction: column; gap: 12px; margin-top: 16px; }}
input[type="text"], input[type="password"] {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    padding: 10px 12px;
    font-size: 14px;
    min-width: 240px;
}}
.obs-btn {{
    display: inline-block;
    padding: 10px 14px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--text);
    text-decoration: none;
    cursor: pointer;
    font-size: 14px;
    font-weight: 600;
}}
.obs-btn-primary {{ background: var(--accent); border-color: var(--accent-2); color: #fff; }}
.obs-btn-danger {{ border-color: #7f1d1d; color: var(--danger); }}
.obs-table-wrap {{ overflow-x: auto; }}
.obs-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.obs-table th, .obs-table td {{
    text-align: left;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}}
.obs-table th {{ color: var(--muted); font-weight: 600; }}
.obs-table pre {{
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
    font-size: 12px;
}}
.obs-table a {{ color: var(--accent-2); text-decoration: none; }}
.obs-muted {{ color: var(--muted); font-size: 14px; }}
.obs-alert {{
    background: rgba(248, 113, 113, 0.12);
    border: 1px solid rgba(248, 113, 113, 0.35);
    color: var(--danger);
    padding: 10px 12px;
    border-radius: 8px;
    font-size: 14px;
}}
.obs-record-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
}}
h2, h3 {{ margin-top: 0; }}
</style>
</head>
<body>
<main class="obs-stats-shell">
{body_inner}
</main>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_auth_password_and_signed_cookies() {
        let auth = StatsAuth::new();
        assert!(!auth.verify_password("PASSWORD", "PASSWORD"));
        assert!(!auth.verify_password("", ""));
        assert!(auth.verify_password("s3cr3t!", "s3cr3t!"));
        assert!(!auth.verify_password("s3cr3t!", "wrong"));

        let now = 1_700_000_000;
        let tok = auth.issue_cookie_token(now);
        assert!(auth.verify_cookie_token(&tok, now + 100));
        assert!(!auth.verify_cookie_token(&tok, now + SESSION_TTL_SECS + 1));
        assert!(!auth.verify_cookie_token("true", now));
        assert!(!auth.verify_cookie_token("9999999999.deadbeef", now));
    }

    #[test]
    fn html_escaping_blocks_xss_payloads() {
        let escaped = escape_html(r#"<script>alert("x'&y")</script>"#);
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&quot;x&#39;&amp;y&quot;)&lt;/script&gt;"
        );
    }
}
