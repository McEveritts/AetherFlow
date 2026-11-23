use crate::auth::{api_error, AuthUser};
use axum::extract::connect_info::ConnectInfo;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use once_cell::sync::Lazy;
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(super) const RATE_LIMIT_KEY_CAPACITY: usize = 16_384;

#[derive(Default)]
pub(super) struct RateLimitVisitors {
    pub(super) timestamps: HashMap<String, Vec<Instant>>,
    pub(super) oldest_first: BTreeSet<(Instant, String)>,
}

pub(super) struct SlidingWindowLimiter {
    pub(super) visitors: Mutex<RateLimitVisitors>,
    limit: usize,
    window: Duration,
}

impl SlidingWindowLimiter {
    pub(super) fn new(limit: usize, window: Duration) -> Self {
        Self {
            visitors: Mutex::new(RateLimitVisitors::default()),
            limit,
            window,
        }
    }

    pub(super) fn allow(&self, ip: &str) -> bool {
        self.reserve(ip).is_some()
    }

    pub(super) fn reserve(&self, ip: &str) -> Option<Instant> {
        let mut guard = self
            .visitors
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let RateLimitVisitors {
            timestamps,
            oldest_first,
        } = &mut *guard;
        let now = Instant::now();
        while let Some((last_seen, _)) = oldest_first.first() {
            if now.duration_since(*last_seen) < self.window {
                break;
            }
            let (_, expired) = oldest_first.pop_first().expect("first entry exists");
            timestamps.remove(&expired);
        }
        if timestamps.len() >= RATE_LIMIT_KEY_CAPACITY && !timestamps.contains_key(ip) {
            if let Some((_, oldest)) = oldest_first.pop_first() {
                timestamps.remove(&oldest);
            }
        }
        let entry = timestamps.entry(ip.to_string()).or_default();
        let previous = entry.last().copied();
        entry.retain(|&t| now.duration_since(t) < self.window);
        if entry.len() >= self.limit {
            return None;
        }
        if let Some(previous) = previous {
            oldest_first.remove(&(previous, ip.to_string()));
        }
        entry.push(now);
        oldest_first.insert((now, ip.to_string()));
        Some(now)
    }

    pub(super) fn refund(&self, ip: &str, attempt: Instant) {
        let mut guard = self
            .visitors
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let RateLimitVisitors {
            timestamps,
            oldest_first,
        } = &mut *guard;
        let Some(entry) = timestamps.get_mut(ip) else {
            return;
        };
        let Ok(index) = entry.binary_search(&attempt) else {
            return;
        };
        let previous = *entry.last().expect("matched reservation exists");
        entry.remove(index);
        oldest_first.remove(&(previous, ip.to_owned()));
        if let Some(&newest) = entry.last() {
            oldest_first.insert((newest, ip.to_owned()));
        } else {
            timestamps.remove(ip);
        }
    }
}

pub(super) static PROXY_BASIC_AUTH_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(20, Duration::from_secs(60)));
static AUTH_RATE_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(10, Duration::from_secs(60)));
static OIDC_RATE_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(20, Duration::from_secs(60)));
static AI_RATE_LIMITER: Lazy<SlidingWindowLimiter> =
    Lazy::new(|| SlidingWindowLimiter::new(20, Duration::from_secs(60)));

pub(super) fn is_rate_limit_disabled_for_env(
    disable_flag: Option<&str>,
    aetherflow_env: Option<&str>,
) -> bool {
    let disabled = disable_flag
        .map(|v| {
            let trimmed = v.trim();
            trimmed.eq_ignore_ascii_case("true") || trimmed == "1"
        })
        .unwrap_or(false);
    if !disabled {
        return false;
    }
    if aetherflow_env.is_some_and(crate::auth::is_production_or_release_env) {
        tracing::warn!(
            "AF_DISABLE_RATELIMIT ignored because AETHERFLOW_ENV is production/release"
        );
        return false;
    }
    true
}

fn rate_limit_disabled() -> bool {
    let flag = env::var("AF_DISABLE_RATELIMIT").ok();
    let af_env = env::var("AETHERFLOW_ENV").ok();
    is_rate_limit_disabled_for_env(flag.as_deref(), af_env.as_deref())
}

pub(super) fn rate_limited_response() -> Response {
    let mut resp = api_error(
        StatusCode::TOO_MANY_REQUESTS,
        "RATE_LIMITED",
        "Too many requests, please try again later",
    );
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    resp
}

fn extract_request_ip(req: &Request) -> String {
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer_addr)| peer_addr.ip());
    crate::ws::extract_client_ip_for_peer(req.headers(), peer_ip)
}

pub async fn auth_rate_limit_middleware(req: Request, next: Next) -> Response {
    if rate_limit_disabled() {
        return next.run(req).await;
    }
    let ip = extract_request_ip(&req);
    if !AUTH_RATE_LIMITER.allow(&ip) {
        return rate_limited_response();
    }
    next.run(req).await
}

pub async fn oidc_rate_limit_middleware(req: Request, next: Next) -> Response {
    if rate_limit_disabled() {
        return next.run(req).await;
    }
    let ip = extract_request_ip(&req);
    if !OIDC_RATE_LIMITER.allow(&ip) {
        return rate_limited_response();
    }
    next.run(req).await
}

pub async fn ai_rate_limit_middleware(req: Request, next: Next) -> Response {
    if rate_limit_disabled() {
        return next.run(req).await;
    }
    let ip = extract_request_ip(&req);
    if !AI_RATE_LIMITER.allow(&ip) {
        return rate_limited_response();
    }
    next.run(req).await
}

// ──────────────────────────────────────────────────────────────────────────────
// 5. Storage Quota Upload Guard Middleware
// ──────────────────────────────────────────────────────────────────────────────

pub async fn quota_upload_guard_middleware(req: Request, next: Next) -> Response {
    let Some(auth_user) = req.extensions().get::<AuthUser>() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let user_id = auth_user.user_id;
    match tokio::task::spawn_blocking(move || {
        crate::mcbrowser::check_user_quota_pre_mutation(user_id, 0)
    })
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return error.into_response(),
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Storage authorization worker failed",
            )
        }
    }
    next.run(req).await
}
