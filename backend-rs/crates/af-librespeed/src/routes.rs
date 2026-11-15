use crate::assets::handle_static_asset;
use crate::config::Config;
use crate::db::{NewTelemetryRecord, TelemetryVault};
use crate::png_card::render_badge_png;
use crate::redact::{
    classify_ip_note, extract_trusted_forwarded_ip_with_secret, format_getip_display,
    parse_ip_token, peer_ip_key, redact_freeform_text, redact_single_ip,
    resolve_client_ip_with_secret,
};
use crate::stats::{
    handle_stats, parse_urlencoded_map, AppState, GarbageIpTracker, GarbageStreamGuard, StatsAuth,
    TelemetryRateLimiter,
};
use crate::ulid::{generate_ulid, obfuscate_ulid, resolve_id};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Multipart, Query, Request, State};
use axum::http::header::{
    ACCEPT_LANGUAGE, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONNECTION, CONTENT_DISPOSITION, CONTENT_LENGTH,
    CONTENT_TYPE, PRAGMA, RETRY_AFTER, TRANSFER_ENCODING, USER_AGENT,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use futures::StreamExt;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

pub const MAX_EMPTY_BODY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TELEMETRY_BODY_BYTES: usize = 256 * 1024;
pub const MAX_STATS_BODY_BYTES: usize = 64 * 1024;
pub const MAX_CONCURRENT_GARBAGE_STREAMS: usize = 64;
pub const MAX_GARBAGE_STREAMS_PER_IP: usize = 16;
pub const MAX_CONCURRENT_UPLOAD_STREAMS: usize = 64;
pub const MAX_UPLOAD_STREAMS_PER_IP: usize = 16;
pub const MAX_STREAMS_PER_PROXY_PEER: usize = 48;
const MAX_GARBAGE_STREAM_DURATION: Duration = Duration::from_secs(60);
const MAX_EMPTY_UPLOAD_DURATION: Duration = Duration::from_secs(60);
const MAX_STATS_BODY_DURATION: Duration = Duration::from_secs(10);
const MAX_TELEMETRY_READ_DURATION: Duration = Duration::from_secs(30);
const GARBAGE_CHUNK_BYTES: usize = 1_048_576; // 1 MiB
const MIN_GARBAGE_CHUNKS: usize = 1;
const MAX_GARBAGE_CHUNKS: usize = 1024;
const DEFAULT_GARBAGE_CHUNKS: usize = 4;

#[derive(Debug, Clone, Copy)]
pub struct RouteTimeouts {
    pub garbage_stream: Duration,
    pub empty_upload: Duration,
    pub stats_body: Duration,
}

impl Default for RouteTimeouts {
    fn default() -> Self {
        Self {
            garbage_stream: MAX_GARBAGE_STREAM_DURATION,
            empty_upload: MAX_EMPTY_UPLOAD_DURATION,
            stats_body: MAX_STATS_BODY_DURATION,
        }
    }
}

static RANDOM_CHUNK_1MIB: Lazy<Bytes> = Lazy::new(|| {
    let mut buf = vec![0u8; GARBAGE_CHUNK_BYTES];
    OsRng.fill_bytes(&mut buf);
    Bytes::from(buf)
});

pub fn build_router(config: Config, vault: Option<TelemetryVault>) -> Router {
    build_router_with_timeouts(config, vault, RouteTimeouts::default())
}

pub fn build_router_with_stream_timeout(
    config: Config,
    vault: Option<TelemetryVault>,
    garbage_stream_timeout: Duration,
) -> Router {
    build_router_with_timeouts(
        config,
        vault,
        RouteTimeouts {
            garbage_stream: garbage_stream_timeout,
            ..RouteTimeouts::default()
        },
    )
}

pub fn build_router_with_timeouts(
    config: Config,
    vault: Option<TelemetryVault>,
    timeouts: RouteTimeouts,
) -> Router {
    let obfuscation_key = vault
        .as_ref()
        .map(|v| *v.obfuscation_key())
        .unwrap_or_else(|| {
            let mut ephemeral = [0u8; 32];
            OsRng.fill_bytes(&mut ephemeral);
            ephemeral
        });
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http_client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .connect_timeout(Duration::from_secs(2))
        .build()
    {
        Ok(client) => Some(client),
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed building hardened reqwest HTTP client; external ipinfo lookups disabled"
            );
            None
        }
    };
    let state = AppState {
        config: Arc::new(config),
        vault,
        stats_auth: StatsAuth::new(),
        obfuscation_key,
        garbage_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_GARBAGE_STREAMS)),
        garbage_ip_tracker: GarbageIpTracker::new(),
        garbage_stream_timeout: timeouts.garbage_stream,
        upload_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_UPLOAD_STREAMS)),
        upload_ip_tracker: GarbageIpTracker::new(),
        empty_upload_timeout: timeouts.empty_upload,
        stats_body_timeout: timeouts.stats_body,
        telemetry_limiter: TelemetryRateLimiter::new(),
        isp_cache: IspLookupCache::new(),
        http_client,
    };

    let empty_routes = Router::new()
        .route("/empty", get(handle_empty).post(handle_empty))
        .route("/empty.php", get(handle_empty).post(handle_empty))
        .route("/backend/empty", get(handle_empty).post(handle_empty))
        .route("/backend/empty.php", get(handle_empty).post(handle_empty))
        .layer(DefaultBodyLimit::max(MAX_EMPTY_BODY_BYTES));

    let telemetry_routes = Router::new()
        .route("/results/telemetry", post(handle_telemetry))
        .route("/results/telemetry.php", post(handle_telemetry))
        .route("/backend/results/telemetry", post(handle_telemetry))
        .route("/backend/results/telemetry.php", post(handle_telemetry))
        .layer(DefaultBodyLimit::max(MAX_TELEMETRY_BODY_BYTES));

    let stats_routes = Router::new()
        .route("/stats", get(handle_stats).post(handle_stats))
        .route("/stats/", get(handle_stats).post(handle_stats))
        .route("/stats.php", get(handle_stats).post(handle_stats))
        .route("/stats/stats.php", get(handle_stats).post(handle_stats))
        .route("/backend/stats", get(handle_stats).post(handle_stats))
        .route("/backend/stats/", get(handle_stats).post(handle_stats))
        .route("/backend/stats.php", get(handle_stats).post(handle_stats))
        .layer(DefaultBodyLimit::max(MAX_STATS_BODY_BYTES));

    let core_routes = Router::new()
        .merge(empty_routes)
        .merge(telemetry_routes)
        .merge(stats_routes)
        .route("/garbage", get(handle_garbage))
        .route("/garbage.php", get(handle_garbage))
        .route("/backend/garbage", get(handle_garbage))
        .route("/backend/garbage.php", get(handle_garbage))
        .route("/getIP", get(handle_get_ip))
        .route("/getIP.php", get(handle_get_ip))
        .route("/backend/getIP", get(handle_get_ip))
        .route("/backend/getIP.php", get(handle_get_ip))
        .route("/results", get(handle_results_png))
        .route("/results/", get(handle_results_png))
        .route("/results/index.php", get(handle_results_png))
        .route("/backend/results", get(handle_results_png))
        .route("/backend/results/", get(handle_results_png))
        .route("/backend/results/index.php", get(handle_results_png))
        .route("/results/json", get(handle_results_json))
        .route("/results/json.php", get(handle_results_json))
        .route("/backend/results/json", get(handle_results_json))
        .route("/backend/results/json.php", get(handle_results_json));

    let mut app = core_routes.clone();
    if !state.config.url_base.is_empty() {
        let prefix = format!("/{}", state.config.url_base);
        let nested = core_routes
            .route("/", get(handle_static_asset))
            .fallback(handle_static_asset);
        app = app.nest(&prefix, nested);
    }

    app.fallback(handle_static_asset)
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(middleware::from_fn(cors_middleware))
        .with_state(state)
}

fn request_has_non_empty_body_framing(headers: &HeaderMap) -> bool {
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

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let unread_non_post_h1 = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS)
        && req.version() != Version::HTTP_2
        && request_has_non_empty_body_framing(req.headers());
    let abort_signal = if unread_non_post_h1 {
        req.extensions()
            .get::<crate::tls::ConnectionAbortSignal>()
            .cloned()
    } else {
        None
    };

    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers
        .entry(HeaderName::from_static("x-content-type-options"))
        .or_insert_with(|| HeaderValue::from_static("nosniff"));
    headers
        .entry(HeaderName::from_static("x-frame-options"))
        .or_insert_with(|| HeaderValue::from_static("DENY"));
    headers
        .entry(HeaderName::from_static("referrer-policy"))
        .or_insert_with(|| HeaderValue::from_static("no-referrer"));
    if unread_non_post_h1 {
        headers.insert(CONNECTION, HeaderValue::from_static("close"));
        if let Some(sig) = abort_signal {
            sig.abort_after_flush();
        }
    }
    res
}

async fn cors_middleware(req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let is_stats = path == "/stats"
        || path.ends_with("/stats")
        || path.contains("/stats/")
        || path.ends_with("/stats.php");
    let cors_enabled = !is_stats && query_flag_truthy(req.uri().query(), "cors");
    if req.method() == Method::OPTIONS && cors_enabled {
        let mut res = StatusCode::NO_CONTENT.into_response();
        apply_cors_headers(res.headers_mut());
        return res;
    }

    let mut res = next.run(req).await;
    if cors_enabled {
        apply_cors_headers(res.headers_mut());
    }
    res
}

fn apply_cors_headers(headers: &mut HeaderMap) {
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    headers.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Encoding, Content-Type"),
    );
}

fn query_flag_truthy(query: Option<&str>, key: &str) -> bool {
    let Some(q) = query else {
        return false;
    };
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            let val = v.trim();
            return val.is_empty() || val.eq_ignore_ascii_case("true") || val == "1";
        }
    }
    false
}

fn abort_stalled_h1_response(
    mut resp: Response,
    version: Version,
    conn_abort: &Option<axum::Extension<crate::tls::ConnectionAbortSignal>>,
) -> Response {
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
    resp
}

fn acquire_stream_guards(
    tracker: &GarbageIpTracker,
    peer_addr: Option<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[std::net::IpAddr],
    proxy_secret: &str,
    max_per_client: usize,
) -> Result<(Option<GarbageStreamGuard>, Option<GarbageStreamGuard>), ()> {
    let Some(addr) = peer_addr else {
        return Ok((None, None));
    };
    let client_ip =
        resolve_client_ip_with_secret(Some(addr), headers, trusted_proxies, proxy_secret);
    let client_key = format!("client:{client_ip}");
    let Some(client_guard) = tracker.try_acquire(&client_key, max_per_client) else {
        return Err(());
    };
    let proxy_guard = if extract_trusted_forwarded_ip_with_secret(
        Some(addr),
        headers,
        trusted_proxies,
        proxy_secret,
    )
    .is_some()
    {
        let proxy_key = format!("proxy_peer:{}", peer_ip_key(Some(addr)));
        let Some(pg) = tracker.try_acquire(&proxy_key, MAX_STREAMS_PER_PROXY_PEER) else {
            return Err(());
        };
        Some(pg)
    } else {
        None
    };
    Ok((Some(client_guard), proxy_guard))
}

async fn handle_empty(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    conn_abort: Option<axum::Extension<crate::tls::ConnectionAbortSignal>>,
    version: Version,
    method: Method,
    req_headers: HeaderMap,
    body: Body,
) -> Response {
    let has_upload_payload =
        method == Method::POST || request_has_non_empty_body_framing(&req_headers);

    if has_upload_payload {
        let peer_addr = peer.map(|ConnectInfo(addr)| addr);
        let Ok((_ip_guard, _proxy_guard)) = acquire_stream_guards(
            &state.upload_ip_tracker,
            peer_addr,
            &req_headers,
            &state.config.trusted_proxies,
            &state.config.trusted_proxy_secret,
            MAX_UPLOAD_STREAMS_PER_IP,
        ) else {
            return abort_stalled_h1_response(
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(RETRY_AFTER, HeaderValue::from_static("5"))],
                    "Too many concurrent upload streams from this client IP",
                )
                    .into_response(),
                version,
                &conn_abort,
            );
        };

        let Ok(_permit) = state.upload_semaphore.clone().try_acquire_owned() else {
            return abort_stalled_h1_response(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(RETRY_AFTER, HeaderValue::from_static("5"))],
                    "Too many concurrent upload streams",
                )
                    .into_response(),
                version,
                &conn_abort,
            );
        };

        let mut stream = body.into_data_stream();
        let mut total: usize = 0;
        let read_outcome = tokio::time::timeout(state.empty_upload_timeout, async {
            while let Some(next_chunk) = stream.next().await {
                let Ok(chunk) = next_chunk else {
                    return Err((StatusCode::BAD_REQUEST, "failed reading upload stream"));
                };
                total = total.saturating_add(chunk.len());
                if total > MAX_EMPTY_BODY_BYTES {
                    return Err((
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "upload body exceeds 64 MiB limit",
                    ));
                }
            }
            Ok(())
        })
        .await;

        match read_outcome {
            Err(_) => {
                return abort_stalled_h1_response(
                    (StatusCode::REQUEST_TIMEOUT, "upload stream timed out").into_response(),
                    version,
                    &conn_abort,
                );
            }
            Ok(Err(err_resp)) => {
                return abort_stalled_h1_response(err_resp.into_response(), version, &conn_abort);
            }
            Ok(Ok(())) => {}
        }
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static(
            "no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0",
        ),
    );
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    if version != Version::HTTP_2 {
        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
    }
    (StatusCode::OK, headers, "").into_response()
}

type GarbageGuardBundle = (
    OwnedSemaphorePermit,
    Option<GarbageStreamGuard>,
    Option<GarbageStreamGuard>,
);

struct SharedGarbageLease {
    guards: Mutex<Option<GarbageGuardBundle>>,
    expired: AtomicBool,
    finished: AtomicBool,
    done_notify: Notify,
}

struct GarbageStreamDropGuard {
    lease: Arc<SharedGarbageLease>,
}

impl Drop for GarbageStreamDropGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.lease.guards.lock() {
            let _ = slot.take();
        }
        self.lease.finished.store(true, Ordering::SeqCst);
        self.lease.done_notify.notify_one();
    }
}

#[derive(Debug, Deserialize, Default)]
struct GarbageQuery {
    #[serde(rename = "ckSize", default)]
    ck_size: Option<String>,
}

async fn handle_garbage(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    conn_abort: Option<axum::Extension<crate::tls::ConnectionAbortSignal>>,
    version: Version,
    headers: HeaderMap,
    method: Method,
    Query(q): Query<GarbageQuery>,
) -> Response {
    let peer_addr = peer.map(|ConnectInfo(addr)| addr);
    let Ok((ip_guard, proxy_guard)) = acquire_stream_guards(
        &state.garbage_ip_tracker,
        peer_addr,
        &headers,
        &state.config.trusted_proxies,
        &state.config.trusted_proxy_secret,
        MAX_GARBAGE_STREAMS_PER_IP,
    ) else {
        return abort_stalled_h1_response(
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(RETRY_AFTER, HeaderValue::from_static("5"))],
                "Too many concurrent download streams from this client IP",
            )
                .into_response(),
            version,
            &conn_abort,
        );
    };

    let Ok(permit) = state.garbage_semaphore.clone().try_acquire_owned() else {
        return abort_stalled_h1_response(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(RETRY_AFTER, HeaderValue::from_static("5"))],
                "Too many concurrent download streams",
            )
                .into_response(),
            version,
            &conn_abort,
        );
    };

    let chunks = q
        .ck_size
        .as_deref()
        .and_then(|s| s.trim().parse::<isize>().ok())
        .map(|n| n.clamp(MIN_GARBAGE_CHUNKS as isize, MAX_GARBAGE_CHUNKS as isize) as usize)
        .unwrap_or(DEFAULT_GARBAGE_CHUNKS);

    let total_bytes = chunks * GARBAGE_CHUNK_BYTES;

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        HeaderName::from_static("content-description"),
        HeaderValue::from_static("File Transfer"),
    );
    resp_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    resp_headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=random.dat"),
    );
    resp_headers.insert(
        HeaderName::from_static("content-transfer-encoding"),
        HeaderValue::from_static("binary"),
    );
    resp_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    resp_headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    if let Ok(len_hv) = HeaderValue::from_str(&total_bytes.to_string()) {
        resp_headers.insert(CONTENT_LENGTH, len_hv);
    }

    if method == Method::HEAD {
        drop(permit);
        drop(ip_guard);
        drop(proxy_guard);
        return (StatusCode::OK, resp_headers, Body::empty()).into_response();
    }

    let lease = Arc::new(SharedGarbageLease {
        guards: Mutex::new(Some((permit, ip_guard, proxy_guard))),
        expired: AtomicBool::new(false),
        finished: AtomicBool::new(false),
        done_notify: Notify::new(),
    });
    let watchdog_lease = Arc::clone(&lease);
    let stream_timeout = state.garbage_stream_timeout;
    let abort_signal = conn_abort.map(|axum::Extension(sig)| sig);
    let is_http2 = version == Version::HTTP_2;
    tokio::spawn(async move {
        let done = watchdog_lease.done_notify.notified();
        tokio::pin!(done);
        done.as_mut().enable();
        if watchdog_lease.finished.load(Ordering::SeqCst) {
            return;
        }
        tokio::select! {
            _ = &mut done => {}
            _ = tokio::time::sleep(stream_timeout) => {
                watchdog_lease.expired.store(true, Ordering::SeqCst);
                if let Ok(mut slot) = watchdog_lease.guards.lock() {
                    let _ = slot.take();
                }
                if let Some(abort) = abort_signal {
                    if is_http2 {
                        // Allow h2 a short window to poll the expired body, emit stream-scoped
                        // RST_STREAM, and drop GarbageStreamDropGuard while preserving sibling
                        // HTTP/2 streams. If the peer exhausted its HTTP/2 stream window (0 bytes)
                        // and withholds WINDOW_UPDATE so h2 never polls Body, abort the wedged
                        // connection to reclaim its listener concurrency slot.
                        if !watchdog_lease.finished.load(Ordering::SeqCst) {
                            tokio::select! {
                                _ = &mut done => {}
                                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                                    if !watchdog_lease.finished.load(Ordering::SeqCst) {
                                        abort.abort();
                                    }
                                }
                            }
                        }
                    } else {
                        abort.abort();
                    }
                }
            }
        }
    });

    let drop_guard = GarbageStreamDropGuard { lease };
    let stream = futures::stream::unfold(
        (0usize, chunks, drop_guard, false),
        |(idx, max, guard, terminated)| async move {
            if terminated || idx >= max {
                return None;
            }
            if guard.lease.expired.load(Ordering::SeqCst) {
                return Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "download stream deadline exceeded",
                    )),
                    (idx, max, guard, true),
                ));
            }
            Some((
                Ok::<Bytes, std::io::Error>(RANDOM_CHUNK_1MIB.clone()),
                (idx + 1, max, guard, false),
            ))
        },
    );

    let mut resp = (StatusCode::OK, resp_headers, Body::from_stream(stream)).into_response();
    resp.extensions_mut()
        .insert(crate::tls::ResponseDrainDeadline(
            state
                .garbage_stream_timeout
                .saturating_add(Duration::from_millis(150)),
        ));
    resp
}

const ISP_CACHE_TTL_SECS: i64 = 3600;
const MAX_ISP_CACHE_ENTRIES: usize = 4096;
const ISP_FETCH_WINDOW_SECS: i64 = 60;
const MAX_ISP_FETCH_GLOBAL_PER_MIN: usize = 30;
const MAX_ISP_FETCH_PER_CLIENT_PER_MIN: usize = 5;
const MAX_IPINFO_RESPONSE_BYTES: usize = 16 * 1024;

#[derive(Default)]
struct IspCacheState {
    entries: HashMap<std::net::IpAddr, (serde_json::Map<String, serde_json::Value>, i64)>,
    global_fetches: usize,
    global_window_start: i64,
    client_fetches: HashMap<std::net::IpAddr, (usize, i64)>,
}

#[derive(Clone, Default)]
pub struct IspLookupCache {
    inner: Arc<Mutex<IspCacheState>>,
}

impl IspLookupCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(
        &self,
        ip: std::net::IpAddr,
        now_unix: i64,
    ) -> Option<serde_json::Map<String, serde_json::Value>> {
        let mut guard = self.inner.lock().ok()?;
        if let Some((map, ts)) = guard.entries.get(&ip) {
            if now_unix.saturating_sub(*ts) < ISP_CACHE_TTL_SECS {
                return Some(map.clone());
            }
            guard.entries.remove(&ip);
        }
        None
    }

    fn allow_uncached_fetch(&self, ip: std::net::IpAddr, now_unix: i64) -> bool {
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        if now_unix.saturating_sub(guard.global_window_start) >= ISP_FETCH_WINDOW_SECS {
            guard.global_fetches = 0;
            guard.global_window_start = now_unix;
        }
        if guard.global_fetches >= MAX_ISP_FETCH_GLOBAL_PER_MIN {
            return false;
        }
        if let Some(&(cnt, ws)) = guard.client_fetches.get(&ip) {
            if now_unix.saturating_sub(ws) < ISP_FETCH_WINDOW_SECS {
                if cnt >= MAX_ISP_FETCH_PER_CLIENT_PER_MIN {
                    return false;
                }
            } else {
                guard.client_fetches.remove(&ip);
            }
        }
        if guard.client_fetches.len() >= MAX_ISP_CACHE_ENTRIES
            && !guard.client_fetches.contains_key(&ip)
        {
            guard
                .client_fetches
                .retain(|_, (_, ws)| now_unix.saturating_sub(*ws) < ISP_FETCH_WINDOW_SECS);
            if guard.client_fetches.len() >= MAX_ISP_CACHE_ENTRIES {
                return false;
            }
        }
        let entry = guard.client_fetches.entry(ip).or_insert((0, now_unix));
        if now_unix.saturating_sub(entry.1) >= ISP_FETCH_WINDOW_SECS {
            *entry = (1, now_unix);
        } else {
            entry.0 = entry.0.saturating_add(1);
        }
        guard.global_fetches = guard.global_fetches.saturating_add(1);
        true
    }

    fn insert(
        &self,
        ip: std::net::IpAddr,
        map: serde_json::Map<String, serde_json::Value>,
        now_unix: i64,
    ) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        if guard.entries.len() >= MAX_ISP_CACHE_ENTRIES && !guard.entries.contains_key(&ip) {
            guard
                .entries
                .retain(|_, (_, ts)| now_unix.saturating_sub(*ts) < ISP_CACHE_TTL_SECS);
            if guard.entries.len() >= MAX_ISP_CACHE_ENTRIES {
                if let Some(oldest) = guard
                    .entries
                    .iter()
                    .min_by_key(|(_, (_, ts))| *ts)
                    .map(|(k, _)| *k)
                {
                    guard.entries.remove(&oldest);
                }
            }
        }
        guard.entries.insert(ip, (map, now_unix));
    }
}

pub fn build_safe_ipinfo_lookup_url(base: &str, ip: std::net::IpAddr) -> Option<reqwest::Url> {
    let mut url = reqwest::Url::parse(base.trim()).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    if !matches!(url.path(), "" | "/") {
        return None;
    }
    match url.scheme() {
        "https" => {
            if url.host_str() != Some("ipinfo.io") || url.port().is_some() {
                return None;
            }
        }
        "http" => {
            url.port()?;
            let host = url.host_str()?;
            let unbracketed = host
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(host);
            let host_ip: std::net::IpAddr = unbracketed.parse().ok()?;
            if !host_ip.is_loopback() {
                return None;
            }
        }
        _ => return None,
    }
    url.set_path(&format!("/{ip}/json"));
    Some(url)
}

fn strip_asn_prefix(org: &str) -> &str {
    let trimmed = org.trim();
    if let Some(rest) = trimmed
        .strip_prefix("AS")
        .or_else(|| trimmed.strip_prefix("as"))
    {
        let digits_len = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits_len > 0 {
            let after_asn = rest[digits_len..].trim_start();
            if !after_asn.is_empty() {
                return after_asn;
            }
        }
    }
    trimmed
}

fn haversine_distance(
    lat1_deg: f64,
    lon1_deg: f64,
    lat2_deg: f64,
    lon2_deg: f64,
    miles: bool,
) -> f64 {
    let r = if miles { 3959.0_f64 } else { 6371.0_f64 };
    let dlat = (lat2_deg - lat1_deg).to_radians();
    let dlon = (lon2_deg - lon1_deg).to_radians();
    let lat1 = lat1_deg.to_radians();
    let lat2 = lat2_deg.to_radians();
    let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().clamp(0.0, 1.0).asin();
    r * c
}

async fn fetch_ipinfo_object(
    state: &AppState,
    ip: std::net::IpAddr,
    now_unix: i64,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    if let Some(cached) = state.isp_cache.get(ip, now_unix) {
        return Some(cached);
    }
    let client = state.http_client.as_ref()?;
    let url = build_safe_ipinfo_lookup_url(&state.config.ipinfo_base_url, ip)?;
    if !state.isp_cache.allow_uncached_fetch(ip, now_unix) {
        return None;
    }
    let mut req = client.get(url).header("Accept", "application/json");
    if !state.config.ipinfo_api_key.is_empty() {
        req = req.bearer_auth(&state.config.ipinfo_api_key);
    }
    let mut resp = req.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let mut buf = Vec::with_capacity(1024);
    while let Some(chunk) = resp.chunk().await.ok()? {
        if buf.len().saturating_add(chunk.len()) > MAX_IPINFO_RESPONSE_BYTES {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    let mut map: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&buf).ok()?;
    map.remove("readme");
    state.isp_cache.insert(ip, map.clone(), now_unix);
    Some(map)
}

fn redact_json_value_in_place(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::String(s) => {
            *s = redact_freeform_text(s);
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                redact_json_value_in_place(item);
            }
        }
        serde_json::Value::Object(obj) => {
            for (k, v) in obj.iter_mut() {
                let key_lower = k.to_ascii_lowercase();
                if matches!(
                    key_lower.as_str(),
                    "hostname"
                        | "city"
                        | "region"
                        | "postal"
                        | "loc"
                        | "latitude"
                        | "longitude"
                        | "lat"
                        | "lon"
                        | "lng"
                ) {
                    *v = serde_json::Value::String("REDACTED".to_string());
                } else if key_lower == "ip" {
                    let scrubbed = v
                        .as_str()
                        .map(redact_single_ip)
                        .unwrap_or_else(|| "0.0.0.0".to_string());
                    *v = serde_json::Value::String(scrubbed);
                } else {
                    redact_json_value_in_place(v);
                }
            }
        }
        _ => {}
    }
}

#[derive(Debug, Deserialize, Default)]
struct GetIpQuery {
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    distance: Option<String>,
}

#[derive(Serialize)]
struct GetIpJson {
    #[serde(rename = "processedString")]
    processed_string: String,
    #[serde(rename = "rawIspInfo")]
    raw_isp_info: serde_json::Value,
}

async fn handle_get_ip(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(q): Query<GetIpQuery>,
) -> Response {
    let peer_addr = peer.map(|ConnectInfo(addr)| addr);
    let client_ip = resolve_client_ip_with_secret(
        peer_addr,
        &headers,
        &state.config.trusted_proxies,
        &state.config.trusted_proxy_secret,
    );
    let display = format_getip_display(&client_ip, state.config.redact_ip_addresses);

    let want_isp = q
        .isp
        .as_deref()
        .map(|v| {
            let t = v.trim();
            t.eq_ignore_ascii_case("true") || t == "1"
        })
        .unwrap_or(false);

    if want_isp {
        let mut processed_string = display;
        let mut raw_isp_info = serde_json::Value::String(String::new());

        if let Some(ip) = parse_ip_token(&client_ip) {
            // Preserve privacy-by-default: when `redact_ip_addresses = true`, only send
            // public client IPs to `ipinfo.io` if the operator explicitly configured
            // `ipinfo_api_key` (and sanitize `rawIspInfo` before returning/persisting).
            let allow_external_lookup = classify_ip_note(ip).is_none()
                && (!state.config.ipinfo_api_key.is_empty() || !state.config.redact_ip_addresses);
            if allow_external_lookup {
                let now_unix = Utc::now().timestamp();
                if let Some(map) = fetch_ipinfo_object(&state, ip, now_unix).await {
                    let isp_name = map
                        .get("org")
                        .and_then(|v| v.as_str())
                        .map(strip_asn_prefix)
                        .unwrap_or("")
                        .trim();
                    let country = map
                        .get("country")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let mut isp_label = String::new();
                    if !isp_name.is_empty() {
                        isp_label.push_str(isp_name);
                        if !country.is_empty() {
                            isp_label.push_str(", ");
                            isp_label.push_str(country);
                        }
                    } else if !country.is_empty() {
                        isp_label.push_str(country);
                    }

                    let dist_unit = q.distance.as_deref().map(str::trim).unwrap_or("");
                    let want_miles = dist_unit.eq_ignore_ascii_case("mi");
                    let want_km = dist_unit.eq_ignore_ascii_case("km");
                    let mut dist_suffix = String::new();
                    if (want_km || want_miles)
                        && (state.config.server_lat != 0.0 || state.config.server_lng != 0.0)
                    {
                        if let Some((lat_s, lng_s)) = map
                            .get("loc")
                            .and_then(|v| v.as_str())
                            .and_then(|loc| loc.split_once(','))
                        {
                            if let (Ok(c_lat), Ok(c_lng)) =
                                (lat_s.trim().parse::<f64>(), lng_s.trim().parse::<f64>())
                            {
                                if c_lat.is_finite() && c_lng.is_finite() {
                                    let d = haversine_distance(
                                        state.config.server_lat,
                                        state.config.server_lng,
                                        c_lat,
                                        c_lng,
                                        want_miles,
                                    );
                                    let unit_label = if want_miles { "mi" } else { "km" };
                                    dist_suffix = format!(" ({d:.0} {unit_label})");
                                }
                            }
                        }
                    }

                    if !isp_label.is_empty() {
                        processed_string = format!("{processed_string} - {isp_label}{dist_suffix}");
                    }

                    let mut obj_val = serde_json::Value::Object(map);
                    if state.config.redact_ip_addresses {
                        redact_json_value_in_place(&mut obj_val);
                    }
                    raw_isp_info = obj_val;
                }
            }
        }

        let mut resp = Json(GetIpJson {
            processed_string,
            raw_isp_info,
        })
        .into_response();
        resp.headers_mut().insert(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
        );
        return resp;
    }

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp_headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    (StatusCode::OK, resp_headers, display).into_response()
}

fn clamp_utf8(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input[..end].to_string()
}

fn validate_telemetry_metric(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.eq_ignore_ascii_case("fail") {
        return Ok("Fail".to_string());
    }
    if trimmed.len() > 24 {
        return Err("telemetry measurement field exceeds maximum numeric length");
    }
    let mut dot_count = 0usize;
    let mut digit_count = 0usize;
    for ch in trimmed.chars() {
        if ch.is_ascii_digit() {
            digit_count += 1;
        } else if ch == '.' {
            dot_count += 1;
            if dot_count > 1 {
                return Err("telemetry measurement fields (dl, ul, ping, jitter) must be valid non-negative numbers");
            }
        } else {
            return Err("telemetry measurement fields (dl, ul, ping, jitter) must be valid non-negative numbers");
        }
    }
    if digit_count == 0 || trimmed.starts_with('.') || trimmed.ends_with('.') {
        return Err("telemetry measurement fields (dl, ul, ping, jitter) must be valid non-negative numbers");
    }
    let parsed: f64 = trimmed.parse().map_err(|_| {
        "telemetry measurement fields (dl, ul, ping, jitter) must be valid non-negative numbers"
    })?;
    if !parsed.is_finite() || !(0.0..=1_000_000.0).contains(&parsed) {
        return Err("telemetry measurement fields must be between 0 and 1000000");
    }
    Ok(trimmed.to_string())
}

async fn handle_telemetry(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let headers = parts.headers.clone();
    let version = parts.version;
    let conn_abort = parts
        .extensions
        .get::<crate::tls::ConnectionAbortSignal>()
        .cloned()
        .map(axum::Extension);

    let peer_addr = peer.map(|ConnectInfo(addr)| addr);
    let raw_ip = resolve_client_ip_with_secret(
        peer_addr,
        &headers,
        &state.config.trusted_proxies,
        &state.config.trusted_proxy_secret,
    );
    let peer_ip = peer_ip_key(peer_addr);
    let is_trusted_proxy = extract_trusted_forwarded_ip_with_secret(
        peer_addr,
        &headers,
        &state.config.trusted_proxies,
        &state.config.trusted_proxy_secret,
    )
    .is_some();
    let now_unix = Utc::now().timestamp();
    if state.config.telemetry_enabled()
        && state.vault.is_some()
        && !state
            .telemetry_limiter
            .try_acquire(&peer_ip, &raw_ip, is_trusted_proxy, now_unix)
    {
        return abort_stalled_h1_response(
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(RETRY_AFTER, HeaderValue::from_static("60"))],
                "Telemetry write rate limit exceeded",
            )
                .into_response(),
            version,
            &conn_abort,
        );
    }

    let mut stream = body.into_data_stream();
    let mut raw_bytes = Vec::with_capacity(4096);
    let telemetry_read = tokio::time::timeout(MAX_TELEMETRY_READ_DURATION, async {
        while let Some(next_chunk) = stream.next().await {
            let Ok(chunk) = next_chunk else {
                return Err((StatusCode::BAD_REQUEST, "failed reading telemetry body"));
            };
            if raw_bytes.len().saturating_add(chunk.len()) > MAX_TELEMETRY_BODY_BYTES {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "telemetry body exceeds 256 KiB limit",
                ));
            }
            raw_bytes.extend_from_slice(&chunk);
        }
        Ok(())
    })
    .await;

    match telemetry_read {
        Err(_) => {
            return abort_stalled_h1_response(
                (StatusCode::REQUEST_TIMEOUT, "telemetry body read timed out").into_response(),
                version,
                &conn_abort,
            )
        }
        Ok(Err(err_resp)) => {
            return abort_stalled_h1_response(err_resp.into_response(), version, &conn_abort)
        }
        Ok(Ok(())) => {}
    }

    let fields = match parse_telemetry_fields(&parts.headers, raw_bytes, &state).await {
        Ok(map) => map,
        Err(status_and_msg) => return status_and_msg.into_response(),
    };

    if !state.config.telemetry_enabled() {
        return (StatusCode::OK, "").into_response();
    }
    let Some(vault) = state.vault.as_ref() else {
        return (StatusCode::OK, "").into_response();
    };

    let mut ispinfo = clamp_utf8(
        fields.get("ispinfo").map(String::as_str).unwrap_or(""),
        8192,
    );
    let mut extra = clamp_utf8(fields.get("extra").map(String::as_str).unwrap_or(""), 8192);
    let dl = match validate_telemetry_metric(fields.get("dl").map(String::as_str).unwrap_or("")) {
        Ok(v) => v,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let ul = match validate_telemetry_metric(fields.get("ul").map(String::as_str).unwrap_or("")) {
        Ok(v) => v,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let ping = match validate_telemetry_metric(fields.get("ping").map(String::as_str).unwrap_or(""))
    {
        Ok(v) => v,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let jitter =
        match validate_telemetry_metric(fields.get("jitter").map(String::as_str).unwrap_or("")) {
            Ok(v) => v,
            Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
        };
    let mut log = clamp_utf8(fields.get("log").map(String::as_str).unwrap_or(""), 65_536);

    if dl.is_empty() && ul.is_empty() && ping.is_empty() && jitter.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "telemetry requires at least one measurement field (dl, ul, ping, or jitter)",
        )
            .into_response();
    }

    let ua_raw = fields
        .get("ua")
        .filter(|s| !s.is_empty())
        .map(String::as_str)
        .or_else(|| headers.get(USER_AGENT).and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    let mut ua = clamp_utf8(ua_raw, 512);

    let lang_raw = fields
        .get("lang")
        .filter(|s| !s.is_empty())
        .map(String::as_str)
        .or_else(|| headers.get(ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    let mut lang = clamp_utf8(lang_raw, 64);

    let ip = if state.config.redact_ip_addresses {
        if let Ok(mut parsed_isp) = serde_json::from_str::<serde_json::Value>(&ispinfo) {
            redact_json_value_in_place(&mut parsed_isp);
            if let Ok(serialized) = serde_json::to_string(&parsed_isp) {
                ispinfo = clamp_utf8(&serialized, 8192);
            }
        }
        ispinfo = redact_freeform_text(&ispinfo);
        log = redact_freeform_text(&log);
        extra = redact_freeform_text(&extra);
        ua = redact_freeform_text(&ua);
        lang = redact_freeform_text(&lang);
        redact_single_ip(&raw_ip)
    } else {
        raw_ip
    };

    let uuid = generate_ulid();
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let record = NewTelemetryRecord {
        uuid: uuid.clone(),
        timestamp,
        ip,
        ispinfo,
        extra,
        ua,
        lang,
        dl,
        ul,
        ping,
        jitter,
        log,
    };

    let issued_raw_id = !state.config.enable_id_obfuscation;
    if let Err(err) = vault.insert_with_mode(record, issued_raw_id).await {
        tracing::error!(error = %err, "Failed persisting telemetry record");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed saving telemetry").into_response();
    }

    let response_id = if state.config.enable_id_obfuscation {
        obfuscate_ulid(&uuid, &state.obfuscation_key)
    } else {
        uuid
    };

    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        format!("id {response_id}"),
    )
        .into_response()
}

async fn parse_telemetry_fields(
    headers: &HeaderMap,
    raw_bytes: Vec<u8>,
    state: &AppState,
) -> Result<HashMap<String, String>, (StatusCode, &'static str)> {
    let ct = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    if ct.starts_with("multipart/form-data") {
        let mut req_builder = Request::builder()
            .method(Method::POST)
            .uri("/results/telemetry");
        if let Some(ct_hv) = headers.get(CONTENT_TYPE) {
            req_builder = req_builder.header(CONTENT_TYPE, ct_hv);
        }
        let rebuilt = req_builder
            .body(Body::from(raw_bytes))
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid multipart request"))?;

        let mut mp = Multipart::from_request(rebuilt, state)
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "malformed multipart payload"))?;

        let mut map = HashMap::new();
        while let Some(field) = mp
            .next_field()
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid multipart field"))?
        {
            let Some(name) = field.name().map(str::to_string) else {
                continue;
            };
            let val = field
                .text()
                .await
                .map_err(|_| (StatusCode::BAD_REQUEST, "non-UTF8 multipart field"))?;
            map.insert(name, val);
        }
        Ok(map)
    } else {
        Ok(parse_urlencoded_map(&raw_bytes))
    }
}

#[derive(Debug, Deserialize, Default)]
struct ResultsQuery {
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ResultsJsonPayload {
    id: String,
    timestamp: String,
    dl: String,
    ul: String,
    ping: String,
    jitter: String,
    ispinfo: String,
    extra: String,
}

async fn lookup_result_record(
    state: &AppState,
    vault: &TelemetryVault,
    raw_id: &str,
) -> std::result::Result<(crate::db::TelemetryRecord, String), (StatusCode, &'static str)> {
    if let Some(canon_uuid) = resolve_id(
        raw_id,
        state.config.enable_id_obfuscation,
        &state.obfuscation_key,
    ) {
        match vault.get_by_uuid(canon_uuid).await {
            Ok(Some(rec)) => {
                let display_id = if state.config.enable_id_obfuscation {
                    obfuscate_ulid(&rec.uuid, &state.obfuscation_key)
                } else {
                    rec.uuid.clone()
                };
                return Ok((rec, display_id));
            }
            Ok(None) => {}
            Err(err) => {
                tracing::error!(error = %err, "Failed loading telemetry record");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
            }
        }
    }

    let safe_ascii_id = raw_id.len() <= 64
        && raw_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');

    if !state.config.enable_id_obfuscation && safe_ascii_id {
        match vault.get_by_uuid(raw_id.to_string()).await {
            Ok(Some(rec)) => {
                let display_id = rec.uuid.clone();
                return Ok((rec, display_id));
            }
            Ok(None) => {}
            Err(err) => {
                tracing::error!(error = %err, "Failed loading non-ULID telemetry record");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
            }
        }
    } else if state.config.enable_id_obfuscation && safe_ascii_id {
        let legacy_cand =
            crate::ulid::canonicalize_ulid(raw_id).unwrap_or_else(|| raw_id.to_string());
        match vault.is_legacy_raw_id(legacy_cand.clone()).await {
            Ok(true) => match vault.get_by_uuid(legacy_cand).await {
                Ok(Some(rec)) => {
                    let display_id = obfuscate_ulid(&rec.uuid, &state.obfuscation_key);
                    return Ok((rec, display_id));
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::error!(error = %err, "Failed loading migrated legacy telemetry record");
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
                }
            },
            Ok(false) => {}
            Err(err) => {
                tracing::error!(error = %err, "Failed checking legacy telemetry ID table");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
            }
        }
    }

    if raw_id.len() == 22 && safe_ascii_id {
        match vault.resolve_legacy_go_share_id(raw_id.to_string()).await {
            Ok(Some(legacy_uuid)) => match vault.get_by_uuid(legacy_uuid).await {
                Ok(Some(rec)) => {
                    let display_id = if state.config.enable_id_obfuscation {
                        obfuscate_ulid(&rec.uuid, &state.obfuscation_key)
                    } else {
                        rec.uuid.clone()
                    };
                    return Ok((rec, display_id));
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        "Failed loading migrated legacy Go obfuscated telemetry record"
                    );
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
                }
            },
            Ok(None) => {}
            Err(err) => {
                tracing::error!(error = %err, "Failed resolving legacy Go share ID");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error"));
            }
        }
    }

    Err((StatusCode::NOT_FOUND, "Result not found"))
}

async fn handle_results_png(
    State(state): State<AppState>,
    Query(q): Query<ResultsQuery>,
) -> Response {
    if !state.config.telemetry_enabled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "Telemetry disabled").into_response();
    }
    let Some(vault) = state.vault.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Telemetry disabled").into_response();
    };

    let Some(raw_id) = q.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return (StatusCode::BAD_REQUEST, "Missing speedtest id").into_response();
    };

    let (record, display_id) = match lookup_result_record(&state, vault, raw_id).await {
        Ok(found) => found,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    match render_badge_png(&record, &display_id) {
        Ok(png_bytes) => {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
            headers.insert(
                CACHE_CONTROL,
                HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
            );
            if let Ok(disp) =
                HeaderValue::from_str(&format!("inline; filename=\"speedtest-{display_id}.png\""))
            {
                headers.insert(CONTENT_DISPOSITION, disp);
            }
            (StatusCode::OK, headers, png_bytes).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "Failed rendering PNG badge");
            (StatusCode::INTERNAL_SERVER_ERROR, "PNG render failure").into_response()
        }
    }
}

async fn handle_results_json(
    State(state): State<AppState>,
    Query(q): Query<ResultsQuery>,
) -> Response {
    if !state.config.telemetry_enabled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "Telemetry disabled").into_response();
    }
    let Some(vault) = state.vault.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Telemetry disabled").into_response();
    };

    let Some(raw_id) = q.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return (StatusCode::BAD_REQUEST, "Missing speedtest id").into_response();
    };

    let (record, display_id) = match lookup_result_record(&state, vault, raw_id).await {
        Ok(found) => found,
        Err((status, msg)) => return (status, msg).into_response(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    (
        StatusCode::OK,
        headers,
        Json(ResultsJsonPayload {
            id: display_id,
            timestamp: record.timestamp,
            dl: record.dl,
            ul: record.ul,
            ping: record.ping,
            jitter: record.jitter,
            ispinfo: record.ispinfo,
            extra: record.extra,
        }),
    )
        .into_response()
}
