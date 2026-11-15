use crate::assets::handle_static_asset;
use crate::config::Config;
use crate::db::{NewTelemetryRecord, TelemetryVault};
use crate::png_card::render_badge_png;
use crate::redact::{
    format_getip_display, redact_freeform_text, redact_single_ip, resolve_client_ip,
};
use crate::stats::{handle_stats, parse_urlencoded_map, AppState, StatsAuth};
use crate::ulid::{generate_ulid, obfuscate_ulid, resolve_id};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Multipart, Query, Request, State};
use axum::http::header::{
    ACCEPT_LANGUAGE, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONNECTION, CONTENT_DISPOSITION, CONTENT_LENGTH,
    CONTENT_TYPE, PRAGMA, USER_AGENT,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
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
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

pub const MAX_EMPTY_BODY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TELEMETRY_BODY_BYTES: usize = 256 * 1024;
const GARBAGE_CHUNK_BYTES: usize = 1_048_576; // 1 MiB
const MIN_GARBAGE_CHUNKS: usize = 1;
const MAX_GARBAGE_CHUNKS: usize = 1024;
const DEFAULT_GARBAGE_CHUNKS: usize = 4;

static RANDOM_CHUNK_1MIB: Lazy<Bytes> = Lazy::new(|| {
    let mut buf = vec![0u8; GARBAGE_CHUNK_BYTES];
    OsRng.fill_bytes(&mut buf);
    Bytes::from(buf)
});

pub fn build_router(config: Config, vault: Option<TelemetryVault>) -> Router {
    let state = AppState {
        config: Arc::new(config),
        vault,
        stats_auth: StatsAuth::new(),
    };

    let empty_routes = Router::new()
        .route("/empty", get(handle_empty).post(handle_empty))
        .route("/empty.php", get(handle_empty).post(handle_empty))
        .route("/backend/empty.php", get(handle_empty).post(handle_empty))
        .layer(DefaultBodyLimit::max(MAX_EMPTY_BODY_BYTES));

    let telemetry_routes = Router::new()
        .route("/results/telemetry", post(handle_telemetry))
        .route("/results/telemetry.php", post(handle_telemetry))
        .layer(DefaultBodyLimit::max(MAX_TELEMETRY_BODY_BYTES));

    let core_routes = Router::new()
        .merge(empty_routes)
        .merge(telemetry_routes)
        .route("/garbage", get(handle_garbage))
        .route("/garbage.php", get(handle_garbage))
        .route("/backend/garbage.php", get(handle_garbage))
        .route("/getIP", get(handle_get_ip))
        .route("/getIP.php", get(handle_get_ip))
        .route("/backend/getIP.php", get(handle_get_ip))
        .route("/results", get(handle_results_png))
        .route("/results/", get(handle_results_png))
        .route("/results/index.php", get(handle_results_png))
        .route("/stats", get(handle_stats).post(handle_stats))
        .route("/stats/", get(handle_stats).post(handle_stats))
        .route("/stats/stats.php", get(handle_stats).post(handle_stats));

    let mut app = core_routes.clone();
    if !state.config.url_base.is_empty() {
        let prefix = format!("/{}", state.config.url_base);
        let nested = core_routes
            .route("/", get(handle_static_asset))
            .fallback(handle_static_asset);
        app = app.nest(&prefix, nested);
    }

    app.fallback(handle_static_asset)
        .layer(middleware::from_fn(cors_middleware))
        .with_state(state)
}

async fn cors_middleware(req: Request, next: Next) -> Response {
    let cors_enabled = query_flag_truthy(req.uri().query(), "cors");
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

async fn handle_empty(body: Body) -> Response {
    let mut stream = body.into_data_stream();
    let mut total: usize = 0;
    while let Some(next_chunk) = stream.next().await {
        let Ok(chunk) = next_chunk else {
            return (StatusCode::BAD_REQUEST, "failed reading upload stream").into_response();
        };
        total = total.saturating_add(chunk.len());
        if total > MAX_EMPTY_BODY_BYTES {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "upload body exceeds 64 MiB limit",
            )
                .into_response();
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
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
    (StatusCode::OK, headers, "").into_response()
}

#[derive(Debug, Deserialize, Default)]
struct GarbageQuery {
    #[serde(rename = "ckSize", default)]
    ck_size: Option<String>,
}

async fn handle_garbage(Query(q): Query<GarbageQuery>) -> Response {
    let chunks = q
        .ck_size
        .as_deref()
        .and_then(|s| s.trim().parse::<isize>().ok())
        .map(|n| n.clamp(MIN_GARBAGE_CHUNKS as isize, MAX_GARBAGE_CHUNKS as isize) as usize)
        .unwrap_or(DEFAULT_GARBAGE_CHUNKS);

    let total_bytes = chunks * GARBAGE_CHUNK_BYTES;
    let stream = futures::stream::iter((0..chunks).map(|_| {
        let chunk = RANDOM_CHUNK_1MIB.clone();
        Ok::<Bytes, Infallible>(chunk)
    }));

    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("content-description"),
        HeaderValue::from_static("File Transfer"),
    );
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=random.dat"),
    );
    headers.insert(
        HeaderName::from_static("content-transfer-encoding"),
        HeaderValue::from_static("binary"),
    );
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    if let Ok(len_hv) = HeaderValue::from_str(&total_bytes.to_string()) {
        headers.insert(CONTENT_LENGTH, len_hv);
    }

    (StatusCode::OK, headers, Body::from_stream(stream)).into_response()
}

#[derive(Debug, Deserialize, Default)]
struct GetIpQuery {
    #[serde(default)]
    isp: Option<String>,
}

#[derive(Serialize)]
struct GetIpJson<'a> {
    #[serde(rename = "processedString")]
    processed_string: String,
    #[serde(rename = "rawIspInfo")]
    raw_isp_info: &'a str,
}

async fn handle_get_ip(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(q): Query<GetIpQuery>,
) -> Response {
    let peer_addr = peer.map(|ConnectInfo(addr)| addr);
    let client_ip = resolve_client_ip(peer_addr, &headers);
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
        let mut resp = Json(GetIpJson {
            processed_string: display,
            raw_isp_info: "",
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

async fn handle_telemetry(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let headers = parts.headers.clone();

    let mut stream = body.into_data_stream();
    let mut raw_bytes = Vec::with_capacity(4096);
    while let Some(next_chunk) = stream.next().await {
        let Ok(chunk) = next_chunk else {
            return (StatusCode::BAD_REQUEST, "failed reading telemetry body").into_response();
        };
        if raw_bytes.len().saturating_add(chunk.len()) > MAX_TELEMETRY_BODY_BYTES {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "telemetry body exceeds 256 KiB limit",
            )
                .into_response();
        }
        raw_bytes.extend_from_slice(&chunk);
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

    let peer_addr = peer.map(|ConnectInfo(addr)| addr);
    let raw_ip = resolve_client_ip(peer_addr, &headers);

    let mut ispinfo = fields.get("ispinfo").cloned().unwrap_or_default();
    let extra = fields.get("extra").cloned().unwrap_or_default();
    let dl = fields.get("dl").cloned().unwrap_or_default();
    let ul = fields.get("ul").cloned().unwrap_or_default();
    let ping = fields.get("ping").cloned().unwrap_or_default();
    let jitter = fields.get("jitter").cloned().unwrap_or_default();
    let mut log = fields.get("log").cloned().unwrap_or_default();

    let ua = fields
        .get("ua")
        .filter(|s| !s.is_empty())
        .cloned()
        .or_else(|| {
            headers
                .get(USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default();

    let lang = fields
        .get("lang")
        .filter(|s| !s.is_empty())
        .cloned()
        .or_else(|| {
            headers
                .get(ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default();

    let ip = if state.config.redact_ip_addresses {
        ispinfo = redact_freeform_text(&ispinfo);
        log = redact_freeform_text(&log);
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

    if let Err(err) = vault.insert(record).await {
        tracing::error!(error = %err, "Failed persisting telemetry record");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed saving telemetry").into_response();
    }

    let response_id = if state.config.enable_id_obfuscation {
        obfuscate_ulid(&uuid)
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

    let Some(canon_uuid) = resolve_id(raw_id, state.config.enable_id_obfuscation) else {
        return (StatusCode::NOT_FOUND, "Result not found").into_response();
    };

    let record = match vault.get_by_uuid(canon_uuid).await {
        Ok(Some(rec)) => rec,
        Ok(None) => return (StatusCode::NOT_FOUND, "Result not found").into_response(),
        Err(err) => {
            tracing::error!(error = %err, "Failed loading telemetry record for PNG");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    let display_id = if state.config.enable_id_obfuscation {
        obfuscate_ulid(&record.uuid)
    } else {
        record.uuid.clone()
    };

    match render_badge_png(&record, &display_id) {
        Ok(png_bytes) => {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
            headers.insert(
                CACHE_CONTROL,
                HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
            );
            (StatusCode::OK, headers, png_bytes).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "Failed rendering PNG badge");
            (StatusCode::INTERNAL_SERVER_ERROR, "PNG render failure").into_response()
        }
    }
}
