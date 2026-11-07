use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use af_services::{
    ActiveStreamSession, BreakdownEntry, StreamTypeDistribution, StreamingAnalytics,
    StreamingDashboardResponse, StreamingHistoryEstimate, StreamingHistoryItem, StreamingLibraryCounts, StreamingLiveSummary,
    StreamingServerStatus, StreamingTimeSeriesPoint, StreamingTitleStat, StreamingUserStat,
};
use axum::body::Body;
use axum::extract::{Extension, Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Datelike, Days, Months, NaiveDate, Utc};
use once_cell::sync::Lazy;
use reqwest::Client;
use rusqlite::{params, params_from_iter};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::env;
use std::time::Duration;

const JELLYFIN_TICKS_PER_SECOND: i64 = 10_000_000;
const MAX_UPSTREAM_PAYLOAD_SIZE: usize = 4 * 1024 * 1024; // 4 MB cap for JSON responses
const MAX_ARTWORK_PAYLOAD_SIZE: usize = 8 * 1024 * 1024; // 8 MB cap for poster/backdrop images

static JELLYFIN_CLIENT: Lazy<Client> = Lazy::new(|| {
    af_services::streaming_http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(16)
        .build()
        .expect("guarded streaming HTTP client")
});

// ──────────────────────────────────────────────────────────────────────────────
// Request & Upstream Payload Types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TestStreamingServerReq {
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub api_key: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SessionCommandReq {
    pub command: String,
    #[serde(default)]
    pub header: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub provider: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinSystemInfo {
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    operating_system: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinItemCounts {
    #[serde(default)]
    movie_count: i32,
    #[serde(default)]
    series_count: i32,
    #[serde(default)]
    episode_count: i32,
    #[serde(default)]
    song_count: i32,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinCapabilitiesRaw {
    #[serde(default)]
    supports_media_control: Option<bool>,
    #[serde(default)]
    supported_commands: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinPlayStateRaw {
    #[serde(default)]
    position_ticks: i64,
    #[serde(default)]
    is_paused: bool,
    #[serde(default)]
    play_method: String,
    #[serde(default)]
    play_session_id: String,
    #[serde(default)]
    media_source_id: String,
    #[serde(default)]
    audio_stream_index: Option<i32>,
    #[serde(default)]
    subtitle_stream_index: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinMediaStreamRaw {
    #[serde(default, rename = "Type")]
    stream_type: String,
    #[serde(default)]
    index: i32,
    #[serde(default)]
    codec: String,
    #[serde(default)]
    language: String,
    #[serde(default)]
    bit_rate: i64,
    #[serde(default)]
    width: i32,
    #[serde(default)]
    height: i32,
    #[serde(default)]
    video_range: String,
    #[serde(default)]
    real_frame_rate: f64,
    #[serde(default)]
    channels: i32,
    #[serde(default)]
    channel_layout: String,
    #[serde(default)]
    is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinNowPlayingItemRaw {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "Type")]
    item_type: String,
    #[serde(default)]
    series_name: String,
    #[serde(default)]
    series_id: String,
    #[serde(default)]
    parent_index_number: i32,
    #[serde(default)]
    index_number: i32,
    #[serde(default)]
    production_year: i32,
    #[serde(default)]
    run_time_ticks: i64,
    #[serde(default)]
    container: String,
    #[serde(default)]
    bitrate: i64,
    #[serde(default)]
    width: i32,
    #[serde(default)]
    height: i32,
    #[serde(default)]
    image_tags: HashMap<String, String>,
    #[serde(default)]
    series_primary_image_tag: String,
    #[serde(default)]
    media_streams: Vec<JellyfinMediaStreamRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinTranscodingInfoRaw {
    #[serde(default)]
    container: String,
    #[serde(default)]
    is_video_direct: bool,
    #[serde(default)]
    is_audio_direct: bool,
    #[serde(default)]
    video_codec: String,
    #[serde(default)]
    audio_codec: String,
    #[serde(default)]
    bitrate: i64,
    #[serde(default)]
    framerate: f64,
    #[serde(default)]
    completion_percentage: f64,
    #[serde(default)]
    hardware_acceleration_type: String,
    #[serde(default)]
    transcode_reasons: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinSessionRaw {
    #[serde(default)]
    id: String,
    #[serde(default)]
    server_id: String,
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    user_name: String,
    #[serde(default)]
    client: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    application_version: String,
    #[serde(default)]
    remote_end_point: String,
    #[serde(default)]
    supports_media_control: Option<bool>,
    #[serde(default)]
    supports_remote_control: Option<bool>,
    #[serde(default)]
    supported_commands: Vec<String>,
    #[serde(default)]
    capabilities: Option<JellyfinCapabilitiesRaw>,
    #[serde(default)]
    play_state: Option<JellyfinPlayStateRaw>,
    #[serde(default)]
    now_playing_item: Option<JellyfinNowPlayingItemRaw>,
    #[serde(default)]
    transcoding_info: Option<JellyfinTranscodingInfoRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinUserRaw {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinUserDataRaw {
    #[serde(default)]
    played: bool,
    #[serde(default)]
    playback_position_ticks: i64,
    #[serde(default)]
    played_percentage: f64,
    #[serde(default)]
    last_played_date: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinHistoryItemRaw {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "Type")]
    item_type: String,
    #[serde(default)]
    series_name: String,
    #[serde(default)]
    series_id: String,
    #[serde(default)]
    parent_index_number: i32,
    #[serde(default)]
    index_number: i32,
    #[serde(default)]
    production_year: i32,
    #[serde(default)]
    run_time_ticks: i64,
    #[serde(default)]
    container: String,
    #[serde(default)]
    bitrate: i64,
    #[serde(default)]
    width: i32,
    #[serde(default)]
    height: i32,
    #[serde(default)]
    media_streams: Vec<JellyfinMediaStreamRaw>,
    #[serde(default)]
    user_data: Option<JellyfinUserDataRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct JellyfinItemsEnvelope {
    #[serde(default)]
    total_record_count: usize,
    #[serde(default)]
    items: Vec<JellyfinHistoryItemRaw>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration & HTTP Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn resolve_default_jellyfin_url() -> String {
    if let Ok(env_url) = env::var("JELLYFIN_URL") {
        let trimmed = env_url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(Some(cfg)) = af_db::get_app_ingress_config("jellyfin") {
        let dom = cfg.public_domain.trim();
        if !dom.is_empty() && cfg.external_access_enabled {
            return format!("https://{}", dom);
        }
        if cfg.listen_port > 0 {
            return format!("http://127.0.0.1:{}", cfg.listen_port);
        }
    }
    let base_dom = af_services::resolve_base_domain();
    if !base_dom.is_empty() {
        return format!("https://jellyfin.{}", base_dom);
    }
    "http://127.0.0.1:8096".to_string()
}

pub fn get_stored_jellyfin_config() -> (String, String, String, bool) {
    let mut name = "Jellyfin".to_string();
    let mut server_url = resolve_default_jellyfin_url();
    let mut raw_api_key = env::var("JELLYFIN_API_KEY")
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut enabled = true;

    if let Ok(conn) = af_db::get_conn() {
        if let Ok((db_name, db_url, db_key, db_enabled)) = conn.query_row(
            "SELECT name, url, api_key, enabled FROM streaming_servers WHERE provider = 'jellyfin'",
            [],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                ))
            },
        ) {
            if !db_name.trim().is_empty() {
                name = db_name.trim().to_string();
            }
            if !db_url.trim().is_empty() {
                server_url = db_url.trim().trim_end_matches('/').to_string();
            }
            enabled = db_enabled;
            if !db_key.is_empty() {
                match af_db::decrypt_key(&db_key) {
                    Ok(dec) if !dec.is_empty() => raw_api_key = dec,
                    _ if !db_key.starts_with("enc:v1:") => raw_api_key = db_key,
                    _ => {
                        tracing::warn!(
                            "failed to decrypt stored Jellyfin API key; refusing ciphertext fallback"
                        );
                        raw_api_key.clear();
                    }
                }
            }
        }
    }

    (name, server_url, raw_api_key, enabled)
}

fn sanitize_emby_token(api_key: &str) -> String {
    api_key
        .chars()
        .filter(|&c| c != '"' && c != '\r' && c != '\n' && (c as u32) >= 0x20)
        .collect()
}

async fn do_jellyfin_request(
    method: reqwest::Method,
    full_url: &str,
    api_key: &str,
    json_body: Option<serde_json::Value>,
    timeout: Duration,
    max_bytes: usize,
) -> anyhow::Result<(Vec<u8>, StatusCode, String)> {
    let mut target = url::Url::parse(full_url)?;
    target.set_query(None);
    af_services::validate_server_url(target.as_str())?;
    let mut req = JELLYFIN_CLIENT
        .request(method, full_url)
        .timeout(timeout)
        .header(header::ACCEPT, "application/json");

    if !api_key.is_empty() {
        let clean_token = sanitize_emby_token(api_key);
        let auth_val = format!(
            "MediaBrowser Client=\"AetherFlow\", Device=\"Nexus\", DeviceId=\"aetherflow-nexus\", Version=\"3.2\", Token=\"{}\"",
            clean_token
        );
        req = req
            .header("X-Emby-Token", &clean_token)
            .header("X-MediaBrowser-Token", &clean_token)
            .header(header::AUTHORIZATION, auth_val);
    }

    if let Some(body) = json_body {
        req = req.json(&body);
    }

    let resp = req.send().await?;
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let bytes = read_bounded_streaming_body(resp, max_bytes).await?;
    Ok((bytes, status, content_type))
}

async fn read_bounded_streaming_body(mut response: reqwest::Response, cap: usize) -> anyhow::Result<Vec<u8>> {
    if response.content_length().is_some_and(|length| length > cap as u64) {
        anyhow::bail!("Streaming upstream payload exceeds {cap} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > cap.saturating_sub(body.len()) {
            anyhow::bail!("Streaming upstream payload exceeds {cap} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn format_resolution_label(width: i32, height: i32) -> String {
    if width >= 3800 || height >= 2100 {
        "4K UHD".to_string()
    } else if width >= 2500 || height >= 1400 {
        "1440p QHD".to_string()
    } else if width >= 1900 || height >= 1000 {
        "1080p FHD".to_string()
    } else if width >= 1200 || height >= 700 {
        "720p HD".to_string()
    } else if width > 0 || height > 0 {
        "480p SD".to_string()
    } else {
        String::new()
    }
}

fn format_audio_layout(channels: i32, layout: &str) -> String {
    if !layout.trim().is_empty() {
        return layout.trim().to_string();
    }
    match channels {
        8 => "7.1".to_string(),
        6 => "5.1".to_string(),
        2 => "Stereo".to_string(),
        1 => "Mono".to_string(),
        c if c > 0 => format!("{}ch", c),
        _ => String::new(),
    }
}

fn is_private_or_local_ip(ip: &str) -> bool {
    let mut clean = ip.trim().to_lowercase();
    if let Some(stripped) = clean.strip_prefix("::ffff:") {
        clean = stripped.to_string();
    }
    if clean.starts_with('[') {
        if let Some(idx) = clean.find(']') {
            clean = clean[1..idx].to_string();
        }
    } else if clean.matches(':').count() == 1 {
        if let Some((host, _)) = clean.split_once(':') {
            clean = host.to_string();
        }
    }
    if clean.is_empty()
        || clean == "127.0.0.1"
        || clean == "::1"
        || clean == "localhost"
        || clean.starts_with("127.")
        || clean.starts_with("fe80:")
        || clean.starts_with("fc")
        || clean.starts_with("fd")
        || clean.starts_with("10.")
        || clean.starts_with("192.168.")
    {
        return true;
    }
    if let Some(rest) = clean.strip_prefix("172.") {
        if let Some((oct_str, _)) = rest.split_once('.') {
            if let Ok(oct) = oct_str.parse::<u8>() {
                return (16..=31).contains(&oct);
            }
        }
    }
    false
}

fn normalize_media_type(raw_type: &str) -> String {
    match raw_type.trim().to_lowercase().as_str() {
        "movie" => "Movie".to_string(),
        "episode" | "series" => "Episode".to_string(),
        "audio" | "musicvideo" => "Audio".to_string(),
        "tvchannel" | "livetvchannel" | "livetvprogram" | "program" | "channel" | "livetv" => {
            "LiveTV".to_string()
        }
        "" => String::new(),
        _ => raw_type.trim().to_string(),
    }
}

fn normalize_play_method(raw_method: &str) -> String {
    match raw_method.trim().to_lowercase().as_str() {
        "directplay" | "direct_play" | "direct play" => "DirectPlay".to_string(),
        "directstream" | "direct_stream" | "direct stream" => "DirectStream".to_string(),
        "transcode" | "transcoding" => "Transcode".to_string(),
        "" => String::new(),
        _ => raw_method.trim().to_string(),
    }
}

fn resolve_session_capabilities(s: &JellyfinSessionRaw) -> (bool, bool, bool, Vec<String>) {
    let supports_media_control = s
        .supports_media_control
        .or_else(|| {
            s.capabilities
                .as_ref()
                .and_then(|c| c.supports_media_control)
        })
        .unwrap_or(false);

    let supports_remote_control = s.supports_remote_control.unwrap_or(supports_media_control);

    let cmds: Vec<String> = if !s.supported_commands.is_empty() {
        s.supported_commands.clone()
    } else if let Some(ref cap) = s.capabilities {
        cap.supported_commands.clone()
    } else {
        Vec::new()
    };

    let can_send_message = if !cmds.is_empty() {
        let has_display_msg = cmds
            .iter()
            .any(|c| c.trim().eq_ignore_ascii_case("DisplayMessage"));
        supports_media_control && has_display_msg
    } else {
        false
    };

    (
        supports_media_control,
        supports_remote_control,
        can_send_message,
        cmds,
    )
}

// ──────────────────────────────────────────────────────────────────────────────
// 1. GET /streaming/artwork/:itemId
// ──────────────────────────────────────────────────────────────────────────────

pub async fn get_streaming_artwork(Extension(user): Extension<AuthUser>, Path(item_id): Path<String>, Query(mut q): Query<HashMap<String, String>>) -> Response {
    let trimmed = item_id.trim();
    if trimmed.is_empty()
        || trimmed.len() > 128
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "valid itemId is required",
        );
    }

    let provider = q.get("provider").map(|value| value.to_ascii_lowercase()).unwrap_or_else(|| "jellyfin".into());
    if !matches!(provider.as_str(), "jellyfin" | "emby") { return StatusCode::BAD_REQUEST.into_response(); }
    let authorized = (|| -> anyhow::Result<bool> {
        let conn = af_db::get_conn()?;
        let server_id: String = conn.query_row("SELECT server_id FROM streaming_servers WHERE provider=?1 AND enabled=1 AND COALESCE(server_id,'')!=''", [&provider], |row| row.get(0))?;
        if q.get("serverId").is_some_and(|requested| requested != &server_id) { return Ok(false); }
        if user.role == "admin" { return Ok(true); }
        if !q.contains_key("provider") { return Ok(false); }
        let included = crate::streaming_history::inclusion_predicate();
        Ok(conn.query_row(&format!("SELECT EXISTS(SELECT 1 FROM streaming_history h CROSS JOIN streaming_tracking_policies p WHERE p.id=1 AND h.provider=?1 AND h.server_id=?2 AND h.item_id=?3 AND ({included}) AND EXISTS(SELECT 1 FROM streaming_user_links identity WHERE identity.af_user_id=?4 AND identity.provider=h.provider AND identity.server_id=h.server_id AND identity.provider_user_id=h.user_id))"), params![provider, server_id, trimmed, user.user_id], |row| row.get(0))?)
    })().unwrap_or(false);
    if !authorized { return api_error(StatusCode::FORBIDDEN, "artwork_scope_denied", "Artwork is not available in your linked provider/server/item scope"); }
    q.insert("provider".into(), provider);
    let selected_provider = q.get("provider").map(String::as_str).unwrap_or("jellyfin");
    let (_, selected_url, selected_key, _) = if selected_provider == "jellyfin" { get_stored_jellyfin_config() } else { let config = get_stored_emby_config_fail_closed(); (config.name, config.url, config.api_key, config.enabled) };
    if verify_monitor_source(selected_provider, &selected_url, &selected_key).await.is_err() {
        return api_error(StatusCode::CONFLICT, "streaming_identity_changed", "Artwork provider identity is unavailable or changed");
    }
    if let Some(resp) = maybe_handle_emby_artwork(trimmed, &q).await { return resp; }
    let (_, server_url, api_key, enabled) = get_stored_jellyfin_config();
    if !enabled { return StatusCode::NOT_FOUND.into_response(); }
    if api_key.is_empty() {
        return fallback_emby_artwork(trimmed, &q).await;
    }
    let Ok(clean_url) = af_services::validate_server_url(&server_url) else {
        return fallback_emby_artwork(trimmed, &q).await;
    };

    let encoded_id = urlencoding::encode(trimmed);
    let candidates = [
        format!(
            "{}/Items/{}/Images/Primary?maxWidth=480&quality=85",
            clean_url, encoded_id
        ),
        format!(
            "{}/Items/{}/Images/Backdrop/0?maxWidth=480&quality=85",
            clean_url, encoded_id
        ),
    ];

    let clean_token = sanitize_emby_token(&api_key);
    let auth_val = format!(
        "MediaBrowser Client=\"AetherFlow\", Device=\"Nexus\", DeviceId=\"aetherflow-nexus\", Version=\"3.2\", Token=\"{}\"",
        clean_token
    );

    let mut image_bytes: Option<Vec<u8>> = None;
    let mut raw_content_type = String::new();

    for img_url in &candidates {
        let res = JELLYFIN_CLIENT
            .get(img_url)
            .timeout(Duration::from_secs(6))
            .header("X-Emby-Token", &clean_token)
            .header("X-MediaBrowser-Token", &clean_token)
            .header(header::AUTHORIZATION, &auth_val)
            .send()
            .await;

        if let Ok(resp) = res {
            if resp.status() == StatusCode::OK {
                raw_content_type = resp
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("image/jpeg")
                    .to_string();
                if let Ok(bytes) = read_bounded_streaming_body(resp, MAX_ARTWORK_PAYLOAD_SIZE).await {
                    if !bytes.is_empty() && bytes.len() <= MAX_ARTWORK_PAYLOAD_SIZE {
                        image_bytes = Some(bytes);
                        break;
                    }
                }
            }
        }
    }

    let Some(data) = image_bytes else {
        return fallback_emby_artwork(trimmed, &q).await;
    };

    let media_type = match raw_content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase()
        .as_str()
    {
        "image/jpeg" | "image/jpg" => "image/jpeg",
        "image/png" => "image/png",
        "image/webp" => "image/webp",
        "image/gif" => "image/gif",
        "image/avif" => "image/avif",
        _ => "image/jpeg",
    };

    let mut resp = Response::new(Body::from(data));
    *resp.status_mut() = StatusCode::OK;
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(media_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'; img-src 'self'; sandbox"),
    );
    resp
}

use axum::http::HeaderName;

// ──────────────────────────────────────────────────────────────────────────────
// 2. POST /streaming/servers/test
// ──────────────────────────────────────────────────────────────────────────────

pub async fn test_jellyfin_connection(
    server_url: &str,
    api_key: &str,
) -> anyhow::Result<StreamingServerStatus> {
    let clean_url = af_services::validate_server_url(server_url)?;

    let masked_key = if api_key.len() > 4 {
        let tail: String = api_key
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("****{}", tail)
    } else if !api_key.is_empty() {
        "****".to_string()
    } else {
        String::new()
    };

    let mut status = StreamingServerStatus {
        provider: "jellyfin".to_string(),
        name: "Jellyfin".to_string(),
        url: clean_url.clone(),
        api_key_masked: masked_key,
        configured: !api_key.is_empty(),
        enabled: true,
        status: "unconfigured".to_string(),
        support_stage: "active".to_string(),
        server_id: String::new(),
        version: String::new(),
        operating_system: String::new(),
        last_connected_at: String::new(),
        library_counts: StreamingLibraryCounts::default(),
        error_message: String::new(),
    };

    if !api_key.is_empty() {
        let info_res = do_jellyfin_request(
            reqwest::Method::GET,
            &format!("{}/System/Info", clean_url),
            api_key,
            None,
            Duration::from_secs(6),
            MAX_UPSTREAM_PAYLOAD_SIZE,
        )
        .await;

        let (body, code, _) = match info_res {
            Ok(tuple) => tuple,
            Err(e) => {
                status.status = "unreachable".to_string();
                status.error_message = format!("Cannot reach Jellyfin server: {}", e);
                anyhow::bail!("Cannot reach Jellyfin server: {}", e);
            }
        };

        if code == StatusCode::UNAUTHORIZED || code == StatusCode::FORBIDDEN {
            status.status = "unreachable".to_string();
            status.error_message = "Invalid Jellyfin API key (HTTP 401/403)".to_string();
            anyhow::bail!("invalid Jellyfin API key (HTTP {})", code.as_u16());
        }
        if !code.is_success() {
            status.status = "unreachable".to_string();
            status.error_message = format!("Jellyfin returned HTTP {}", code.as_u16());
            anyhow::bail!("unexpected HTTP status {}", code.as_u16());
        }

        let sys_info = serde_json::from_slice::<JellyfinSystemInfo>(&body)?;
        if sys_info.id.trim().is_empty() { anyhow::bail!("Missing Jellyfin server identity"); }
        if let Ok(conn) = af_db::get_conn() {
            let pinned: String = conn.query_row("SELECT COALESCE(server_id,'') FROM streaming_servers WHERE provider='jellyfin' AND RTRIM(url,'/')=?1", [&clean_url], |row| row.get(0)).unwrap_or_default();
            if !pinned.is_empty() && !pinned.eq_ignore_ascii_case(&sys_info.id) {
                anyhow::bail!("Jellyfin server identity changed; explicitly reconfigure the connection");
            }
        }
        {
            if !sys_info.server_name.is_empty() {
                status.name = sys_info.server_name;
            }
            status.version = sys_info.version;
            status.server_id = sys_info.id;
            status.operating_system = sys_info.operating_system;
        }

        if let Ok((counts_body, counts_code, _)) = do_jellyfin_request(
            reqwest::Method::GET,
            &format!("{}/Items/Counts", clean_url),
            api_key,
            None,
            Duration::from_secs(6),
            MAX_UPSTREAM_PAYLOAD_SIZE,
        )
        .await
        {
            if counts_code == StatusCode::OK {
                if let Ok(counts) = serde_json::from_slice::<JellyfinItemCounts>(&counts_body) {
                    status.library_counts = StreamingLibraryCounts {
                        movies: counts.movie_count,
                        series: counts.series_count,
                        episodes: counts.episode_count,
                        audio: counts.song_count,
                    };
                }
            }
        }

        status.status = "connected".to_string();
        status.last_connected_at = Utc::now().to_rfc3339();

        return Ok(status);
    }

    // Unauthenticated public probe (/System/Info/Public)
    match do_jellyfin_request(
        reqwest::Method::GET,
        &format!("{}/System/Info/Public", clean_url),
        "",
        None,
        Duration::from_secs(6),
        MAX_UPSTREAM_PAYLOAD_SIZE,
    )
    .await
    {
        Ok((body, StatusCode::OK, _)) => {
            if let Ok(pub_info) = serde_json::from_slice::<JellyfinSystemInfo>(&body) {
                if !pub_info.server_name.is_empty() {
                    status.name = pub_info.server_name;
                }
                status.version = pub_info.version;
                status.server_id = pub_info.id;
            }
            status.status = "unconfigured".to_string();
            status.error_message = format!(
                "Jellyfin detected at {} — add an API Key to enable telemetry",
                clean_url
            );
            Ok(status)
        }
        _ => {
            status.status = "unconfigured".to_string();
            anyhow::bail!("API key not configured")
        }
    }
}

pub async fn test_streaming_server(Json(req): Json<TestStreamingServerReq>) -> Response {
    if req.provider.eq_ignore_ascii_case("emby") {
        let stored = get_stored_emby_config_fail_closed();
        let target_url = if req.url.trim().is_empty() { stored.url.as_str() } else { req.url.trim() };
        let target_url = match crate::streaming_emby::validate_emby_server_url(target_url) {
            Ok(url) => url,
            Err(error) => {
                let (status, code) = error.http_status_and_code();
                return api_error(status, code, error.to_string());
            }
        };
        let same_server = target_url == stored.url.trim_end_matches('/');
        if req.api_key.trim().starts_with("****") && (!same_server || stored.api_key.is_empty()) {
            return api_error(StatusCode::BAD_REQUEST, "STREAMING_KEY_REQUIRED", "Provide a new API key when testing a different server URL; stored credentials cannot be transferred to another server");
        }
        let target_key = if req.api_key.trim().is_empty() || req.api_key.trim().starts_with("****") {
            if same_server { stored.api_key.as_str() } else { "" }
        } else { req.api_key.trim() };
        return finalize_emby_server_test(&stored, &target_url, target_key, same_server).await;
    }
    if !req.provider.is_empty() && !req.provider.eq_ignore_ascii_case("jellyfin") {
        return api_error(StatusCode::BAD_REQUEST, "unsupported_streaming_provider", "Unsupported streaming provider");
    }
    let (_, stored_url, stored_key, _) = get_stored_jellyfin_config();
    let raw_target_url = if req.url.trim().is_empty() {
        stored_url.clone()
    } else {
        req.url.trim().to_string()
    };

    let clean_target_url = match af_services::validate_server_url(&raw_target_url) {
        Ok(u) => u,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", e.to_string()),
    };

    let raw_key = req.api_key.trim();
    let target_key = if raw_key.is_empty() || raw_key.starts_with("****") {
        if clean_target_url.eq_ignore_ascii_case(stored_url.trim().trim_end_matches('/')) {
            stored_key
        } else {
            String::new()
        }
    } else {
        raw_key.to_string()
    };

    match test_jellyfin_connection(&clean_target_url, &target_key).await {
        Ok(status) => {
            let (_, current_url, current_key, enabled) = get_stored_jellyfin_config();
            if enabled && current_url.trim_end_matches('/') == clean_target_url && current_key == target_key {
                if let Ok(conn) = af_db::get_conn() {
                    if let Err(error) = persist_verified_source_with_key(&conn, "jellyfin", &clean_target_url, &target_key, &status.server_id) {
                        return api_error(StatusCode::CONFLICT, "streaming_identity_changed", error.to_string());
                    }
                }
            }
            let ok = status.status == "connected";
            let msg = if ok {
                format!("Connected to {} (v{})", status.name, status.version)
            } else if !status.error_message.is_empty() {
                status.error_message.clone()
            } else {
                "Jellyfin server is unconfigured".to_string()
            };
            Json(serde_json::json!({
                "ok": ok,
                "message": msg,
                "server": status,
            }))
            .into_response()
        }
        Err(err) => {
            let fallback_status = StreamingServerStatus {
                provider: "jellyfin".to_string(),
                name: "Jellyfin".to_string(),
                url: clean_target_url,
                configured: !target_key.is_empty(),
                enabled: true,
                status: if target_key.is_empty() {
                    "unconfigured".to_string()
                } else {
                    "unreachable".to_string()
                },
                support_stage: "active".to_string(),
                error_message: err.to_string(),
                ..Default::default()
            };
            Json(serde_json::json!({
                "ok": false,
                "message": err.to_string(),
                "server": fallback_status,
            }))
            .into_response()
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. POST /streaming/servers/:provider/sync
// ──────────────────────────────────────────────────────────────────────────────

pub async fn sync_jellyfin_watch_history() -> anyhow::Result<usize> {
    let _flight = SUMMARY_SWEEP_LOCK.try_lock().map_err(|_| anyhow::anyhow!("Jellyfin summary sync is already running"))?;
    tokio::time::timeout(Duration::from_secs(45), sync_jellyfin_summary_batch()).await?
}

static SUMMARY_SWEEP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn sync_jellyfin_summary_batch() -> anyhow::Result<usize> {
    let (server_name, server_url, api_key, enabled) = get_stored_jellyfin_config();
    if !enabled || api_key.is_empty() {
        anyhow::bail!("Jellyfin API key is not configured");
    }
    let clean_url = af_services::validate_server_url(&server_url)?;
    let server_id = verify_monitor_source("jellyfin", &server_url, &api_key).await?;
    let instance_identity = if server_id.is_empty() {
        use sha2::Digest;
        format!("url-{}", hex::encode(sha2::Sha256::digest(clean_url.as_bytes())))
    } else {
        server_id.clone()
    };

    let (users_body, code, _) = do_jellyfin_request(
        reqwest::Method::GET,
        &format!("{}/Users", clean_url),
        &api_key,
        None,
        Duration::from_secs(8),
        MAX_UPSTREAM_PAYLOAD_SIZE,
    )
    .await?;

    if !code.is_success() {
        anyhow::bail!("Jellyfin /Users returned HTTP {}", code.as_u16());
    }

    let users: Vec<JellyfinUserRaw> = serde_json::from_slice(&users_body)?;
    anyhow::ensure!(users.len() <= 1024, "Summary user budget exceeded");
    let mut imported = 0usize;
    let page_size = 100usize;
    let filters = ["IsPlayed", "IsResumable"];
    let mut remaining_pages = 8usize;

    for u in users {
        if u.id.trim().is_empty() {
            continue;
        }
        let encoded_uid = urlencoding::encode(u.id.trim());
        for filter in filters {
            let checkpoint_source = format!("summary:{}:{filter}", u.id);
            let completed = af_db::get_conn()?.query_row("SELECT checkpoint='-1' FROM streaming_import_checkpoints WHERE provider='jellyfin' AND server_id=?1 AND source=?2", params![server_id, checkpoint_source], |row| row.get::<_, bool>(0)).unwrap_or(false);
            if completed { continue; }
            let mut start_index = af_db::get_conn()?.query_row("SELECT checkpoint FROM streaming_import_checkpoints WHERE provider='jellyfin' AND server_id=?1 AND source=?2", params![server_id, checkpoint_source], |row| row.get::<_, String>(0)).ok().and_then(|value| value.parse::<usize>().ok()).unwrap_or(0);
            loop {
                if remaining_pages == 0 { return Ok(imported); }
                remaining_pages -= 1;
                let (_, current_url, current_key, current_enabled) = get_stored_jellyfin_config();
                if !current_enabled || current_url != server_url || current_key != api_key { anyhow::bail!("Summary source changed or disabled"); }
                let items_url = format!(
                    "{}/Users/{}/Items?Recursive=true&Filters={}&IncludeItemTypes=Movie,Episode,Audio&Fields=MediaStreams,Container,ProductionYear&SortBy=DatePlayed&SortOrder=Descending&Limit={}&StartIndex={}",
                    clean_url, encoded_uid, filter, page_size, start_index
                );
                let (items_body, i_code, _) = do_jellyfin_request(
                    reqwest::Method::GET,
                    &items_url,
                    &api_key,
                    None,
                    Duration::from_secs(15),
                    MAX_UPSTREAM_PAYLOAD_SIZE,
                )
                .await?;

                if i_code != StatusCode::OK {
                    anyhow::bail!("Jellyfin history request returned HTTP {}", i_code.as_u16());
                }

                let payload = serde_json::from_slice::<JellyfinItemsEnvelope>(&items_body)?;
                if payload.items.is_empty() {
                    af_db::get_conn()?.execute("INSERT INTO streaming_import_checkpoints(provider,server_id,source,checkpoint,updated_at) VALUES('jellyfin',?1,?2,'-1',CURRENT_TIMESTAMP) ON CONFLICT(provider,server_id,source) DO UPDATE SET checkpoint='-1',updated_at=CURRENT_TIMESTAMP", params![server_id, checkpoint_source])?;
                    break;
                }

                let batch_len = payload.items.len();
                {
                    let mut conn = af_db::get_conn()?;
                    let tx = conn.transaction()?;
                    for item in payload.items {
                        let dur_secs = (item.run_time_ticks / JELLYFIN_TICKS_PER_SECOND).max(0);
                        let mut v_codec = String::new();
                        let mut a_codec = String::new();
                        let mut a_ch = 0i32;
                        let mut w = item.width.max(0);
                        let mut h = item.height.max(0);
                        let mut stream_bitrate = 0i64;

                        for ms in &item.media_streams {
                            if ms.stream_type == "Video" {
                                if v_codec.is_empty() && !ms.codec.is_empty() {
                                    v_codec = ms.codec.to_uppercase();
                                }
                                if ms.width > 0 {
                                    w = ms.width;
                                }
                                if ms.height > 0 {
                                    h = ms.height;
                                }
                                if ms.bit_rate > 0 {
                                    stream_bitrate += ms.bit_rate;
                                }
                            } else if ms.stream_type == "Audio" {
                                if a_codec.is_empty() && !ms.codec.is_empty() {
                                    a_codec = ms.codec.to_uppercase();
                                }
                                if a_ch <= 0 && ms.channels > 0 {
                                    a_ch = ms.channels;
                                }
                                if ms.bit_rate > 0 {
                                    stream_bitrate += ms.bit_rate;
                                }
                            }
                        }

                        let mut bitrate = item.bitrate.max(0);
                        if bitrate <= 0 {
                            bitrate = stream_bitrate.max(0);
                        }

                        let mut watched_secs = 0i64;
                        let mut completion_pct = 0.0f64;
                        let mut played_at = String::new();
                        let mut has_played_date = 0i32;

                        if let Some(ref ud) = item.user_data {
                            if ud.played {
                                completion_pct = 100.0;
                                if dur_secs > 0 {
                                    watched_secs = dur_secs;
                                }
                            } else if ud.playback_position_ticks > 0 {
                                let pos_secs =
                                    (ud.playback_position_ticks / JELLYFIN_TICKS_PER_SECOND).max(0);
                                watched_secs = if dur_secs > 0 {
                                    pos_secs.min(dur_secs)
                                } else {
                                    pos_secs
                                };
                                if dur_secs > 0 {
                                    completion_pct = (((watched_secs as f64 / dur_secs as f64)
                                        * 1000.0)
                                        .round()
                                        / 10.0)
                                        .min(100.0);
                                } else if ud.played_percentage > 0.0 {
                                    completion_pct =
                                        ((ud.played_percentage * 10.0).round() / 10.0).min(100.0);
                                }
                            } else if ud.played_percentage > 0.0 && ud.played_percentage <= 100.0 {
                                completion_pct =
                                    ((ud.played_percentage * 10.0).round() / 10.0).min(100.0);
                                if dur_secs > 0 {
                                    watched_secs = ((dur_secs as f64) * (completion_pct / 100.0))
                                        .round()
                                        as i64;
                                }
                            }

                            let raw_date = ud.last_played_date.trim();
                            if !raw_date.is_empty() {
                                if let Ok(dt) = DateTime::parse_from_rfc3339(raw_date) {
                                    played_at = dt
                                        .with_timezone(&Utc)
                                        .format("%Y-%m-%d %H:%M:%S")
                                        .to_string();
                                    has_played_date = 1;
                                }
                            }
                        }

                        // Actual transfer bytes and play method/device/IP are not reported by
                        // Jellyfin's /Users/{id}/Items endpoint; keep them empty/zero rather
                        // than fabricating measurements.
                        let data_used = 0i64;
                        let session_key = format!("jellyfin:summary:{}:{}:{}", urlencoding::encode(&instance_identity), urlencoding::encode(&u.id), urlencoding::encode(&item.id));
                        let rows = tx.execute(
                                r#"
                                INSERT INTO streaming_history (
                                    session_key, provider, server_name, user_id, user_name,
                                    client_name, device_name, ip_address,
                                    item_id, item_name, item_type, series_name, series_id,
                                    season_number, episode_number, production_year,
                                    play_method, container, video_codec, video_resolution,
                                    audio_codec, audio_channels, bitrate_bps,
                                    duration_secs, watched_secs, data_used_bytes, completion_pct,
                                    started_at, last_seen_at, ended_at, is_active,
                                    provenance, timestamp_certainty, byte_accuracy, server_id
                                ) VALUES (
                                    ?1, 'jellyfin', ?2, ?3, ?4,
                                    '', '', '',
                                    ?5, ?6, ?7, ?8, ?9,
                                    ?10, ?11, ?12,
                                    '', ?13, ?14, ?15,
                                    ?16, ?17, ?18,
                                    ?19, ?20, ?21, ?22,
                                    ?23, ?23, ?23, 0,
                                    'item_summary', CASE WHEN ?24 = 1 THEN 'last_played' ELSE 'unrecorded' END,
                                    'unrecorded', ?25
                                )
                                ON CONFLICT(session_key) DO UPDATE SET
                                    server_name = excluded.server_name,
                                    user_name = excluded.user_name,
                                    item_name = excluded.item_name,
                                    item_type = excluded.item_type,
                                    series_name = excluded.series_name,
                                    series_id = excluded.series_id,
                                    season_number = excluded.season_number,
                                    episode_number = excluded.episode_number,
                                    production_year = excluded.production_year,
                                    container = excluded.container,
                                    video_codec = excluded.video_codec,
                                    video_resolution = excluded.video_resolution,
                                    audio_codec = excluded.audio_codec,
                                    audio_channels = excluded.audio_channels,
                                    bitrate_bps = excluded.bitrate_bps,
                                    duration_secs = excluded.duration_secs,
                                    watched_secs = excluded.watched_secs,
                                    data_used_bytes = excluded.data_used_bytes,
                                    completion_pct = excluded.completion_pct,
                                    started_at = CASE WHEN ?24 = 1 THEN excluded.started_at ELSE streaming_history.started_at END,
                                    last_seen_at = CASE WHEN ?24 = 1 THEN excluded.last_seen_at ELSE streaming_history.last_seen_at END,
                                    ended_at = CASE WHEN ?24 = 1 THEN excluded.ended_at ELSE streaming_history.ended_at END,
                                    timestamp_certainty = CASE WHEN ?24 = 1 THEN excluded.timestamp_certainty ELSE streaming_history.timestamp_certainty END
                                WHERE streaming_history.provenance = 'item_summary' AND (
                                      streaming_history.watched_secs != excluded.watched_secs
                                   OR streaming_history.completion_pct != excluded.completion_pct
                                   OR (?24 = 1 AND streaming_history.last_seen_at != excluded.last_seen_at)
                                   OR streaming_history.item_name != excluded.item_name
                                   OR (?24 = 1 AND streaming_history.timestamp_certainty != excluded.timestamp_certainty))
                                "#,
                                params![
                                    session_key,
                                    server_name,
                                    u.id,
                                    u.name,
                                    item.id,
                                    item.name,
                                    normalize_media_type(&item.item_type),
                                    item.series_name,
                                    item.series_id,
                                    item.parent_index_number,
                                    item.index_number,
                                    item.production_year,
                                    item.container.to_uppercase(),
                                    v_codec,
                                    format_resolution_label(w, h),
                                    a_codec,
                                    a_ch,
                                    bitrate,
                                    dur_secs,
                                    watched_secs,
                                    data_used,
                                    completion_pct,
                                    played_at,
                                    has_played_date,
                                    server_id,
                                ],
                            )?;
                        if rows > 0 {
                            imported += 1;
                        }
                    }
                    let stored_key: String = tx.query_row("SELECT api_key FROM streaming_servers WHERE provider='jellyfin' AND enabled=1 AND url=?1 AND server_id=?2", params![server_url, server_id], |row| row.get(0))?;
                    let current_key = if stored_key.starts_with("enc:v1:") { af_db::decrypt_key(&stored_key)? } else { stored_key };
                    if current_key != api_key { anyhow::bail!("Summary source changed before persistence"); }
                    tx.execute("INSERT INTO streaming_import_checkpoints(provider,server_id,source,checkpoint,updated_at) VALUES('jellyfin',?1,?2,?3,CURRENT_TIMESTAMP) ON CONFLICT(provider,server_id,source) DO UPDATE SET checkpoint=excluded.checkpoint,updated_at=excluded.updated_at", params![server_id, checkpoint_source, (start_index + batch_len).to_string()])?;
                    tx.commit()?;
                }

                start_index += batch_len;
                if start_index >= payload.total_record_count || batch_len < page_size {
                    af_db::get_conn()?.execute("UPDATE streaming_import_checkpoints SET checkpoint='-1',updated_at=CURRENT_TIMESTAMP WHERE provider='jellyfin' AND server_id=?1 AND source=?2", params![server_id, checkpoint_source])?;
                    break;
                }
            }
        }
    }

    af_db::get_conn()?.execute("DELETE FROM streaming_import_checkpoints WHERE provider='jellyfin' AND server_id=?1 AND source LIKE 'summary:%' AND checkpoint='-1'", [&server_id])?;
    Ok(imported)
}

pub async fn sync_streaming_server_history(
    Extension(user): Extension<AuthUser>,
    Path(provider): Path<String>,
    headers: HeaderMap,
) -> Response {
    let prov = provider.trim().to_lowercase();
    if prov == "emby" {
        return api_error(StatusCode::NOT_IMPLEMENTED, "emby_summary_sync_unsupported", "Emby item-summary synchronization is not supported yet; live telemetry is available and summaries are not playback events");
    }
    if !prov.is_empty() && prov != "jellyfin" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Only Jellyfin watch history synchronization is supported",
        );
    }

    let imported = match sync_jellyfin_watch_history().await {
        Ok(count) => count,
        Err(e) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                format!("History sync failed: {}", e),
            )
        }
    };

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        user.user_id,
        &user.username,
        "streaming_history_sync",
        "streaming_server",
        "jellyfin",
        &imported.to_string(),
        &ip,
        ua,
    );

    Json(serde_json::json!({
        "message": "Jellyfin watch history synchronized",
        "imported": imported,
    }))
    .into_response()
}

// ──────────────────────────────────────────────────────────────────────────────
// 4. POST /streaming/sessions/:sessionId/command
// ──────────────────────────────────────────────────────────────────────────────

pub async fn send_jellyfin_session_command(
    session_id: &str,
    command: &str,
    header_text: &str,
    message_text: &str,
) -> anyhow::Result<()> {
    let clean_id = session_id.trim();
    if clean_id.starts_with("demo-") {
        return Ok(());
    }

    let (_, server_url, api_key, _) = get_stored_jellyfin_config();
    if api_key.is_empty() {
        anyhow::bail!("Jellyfin API key is not configured");
    }
    let clean_url = af_services::validate_server_url(&server_url)?;

    let mut target_session: Option<JellyfinSessionRaw> = None;
    let mut sessions_list_loaded = false;
    if let Ok((sess_body, sess_code, _)) = do_jellyfin_request(
        reqwest::Method::GET,
        &format!("{}/Sessions", clean_url),
        &api_key,
        None,
        Duration::from_secs(4),
        MAX_UPSTREAM_PAYLOAD_SIZE,
    )
    .await
    {
        if sess_code.is_success() {
            if let Ok(raw_sessions) = serde_json::from_slice::<Vec<JellyfinSessionRaw>>(&sess_body)
            {
                sessions_list_loaded = true;
                target_session = raw_sessions.into_iter().find(|s| s.id == clean_id);
            }
        }
    }

    if !sessions_list_loaded {
        anyhow::bail!("Fresh session capabilities could not be loaded; command denied");
    }
    if target_session.is_none() {
        anyhow::bail!("session {:?} not found on Jellyfin server", clean_id);
    }

    let mut supports_media_ctrl = false;
    let mut can_send_msg = false;
    let mut has_active_transcode = false;
    let mut device_id = String::new();
    let mut play_session_id = String::new();

    if let Some(ref ts) = target_session {
        let (smc, _, csm, _) = resolve_session_capabilities(ts);
        supports_media_ctrl = smc;
        can_send_msg = csm;
        device_id = ts.device_id.trim().to_string();
        if let Some(ref ps) = ts.play_state {
            play_session_id = ps.play_session_id.trim().to_string();
        }
        has_active_transcode = ts.transcoding_info.is_some()
            || !play_session_id.is_empty()
            || ts
                .play_state
                .as_ref()
                .map(|ps| ps.play_method.eq_ignore_ascii_case("Transcode"))
                .unwrap_or(false);
    }

    if !supports_media_ctrl {
        anyhow::bail!("Fresh session capability evidence does not permit media control (SupportsMediaControl=false or unrecorded)");
    }
    let escaped_id = urlencoding::encode(clean_id);
    let mut json_payload: Option<serde_json::Value> = None;

    let endpoint = match command {
        "pause" => {
            if let Some(ref ts) = target_session {
                if !supports_media_ctrl {
                    anyhow::bail!(
                        "client {:?} ({}) does not have an active remote-control WebSocket connection (SupportsMediaControl=false); ensure WebSocket proxying (/socket) is enabled",
                        ts.client,
                        ts.device_name
                    );
                }
            }
            format!("{}/Sessions/{}/Playing/Pause", clean_url, escaped_id)
        }
        "resume" => {
            if let Some(ref ts) = target_session {
                if !supports_media_ctrl {
                    anyhow::bail!(
                        "client {:?} ({}) does not have an active remote-control WebSocket connection (SupportsMediaControl=false); ensure WebSocket proxying (/socket) is enabled",
                        ts.client,
                        ts.device_name
                    );
                }
            }
            format!("{}/Sessions/{}/Playing/Unpause", clean_url, escaped_id)
        }
        "stop" => format!("{}/Sessions/{}/Playing/Stop", clean_url, escaped_id),
        "message" => {
            if let Some(ref ts) = target_session {
                if !supports_media_ctrl {
                    anyhow::bail!(
                        "client {:?} ({}) does not have an active remote-control WebSocket connection (SupportsMediaControl=false)",
                        ts.client,
                        ts.device_name
                    );
                }
                if !can_send_msg {
                    anyhow::bail!(
                        "client {:?} ({}) does not support on-screen messages (DisplayMessage not in SupportedCommands)",
                        ts.client,
                        ts.device_name
                    );
                }
            }
            let resolved_header = if header_text.trim().is_empty() {
                "AetherFlow Administrator"
            } else {
                header_text.trim()
            };
            // Omit TimeoutMs so jellyfin-web invokes alert({ title: Header, text: Text })
            // rather than toast(), which discards Header and hides after 3.3s.
            json_payload = Some(serde_json::json!({
                "Header": resolved_header,
                "Text": message_text,
            }));
            format!("{}/Sessions/{}/Message", clean_url, escaped_id)
        }
        other => anyhow::bail!("unsupported session command: {}", other),
    };

    let (_, code, _) = do_jellyfin_request(
        reqwest::Method::POST,
        &endpoint,
        &api_key,
        json_payload,
        Duration::from_secs(6),
        MAX_UPSTREAM_PAYLOAD_SIZE,
    )
    .await?;

    if !code.is_success() {
        anyhow::bail!(
            "Jellyfin command {:?} returned HTTP {}",
            command,
            code.as_u16()
        );
    }

    if command == "stop" && !device_id.is_empty() && has_active_transcode {
        let enc_url = if play_session_id.is_empty() {
            format!(
                "{}/Videos/ActiveEncodings?deviceId={}",
                clean_url,
                urlencoding::encode(&device_id)
            )
        } else {
            format!(
                "{}/Videos/ActiveEncodings?deviceId={}&playSessionId={}",
                clean_url,
                urlencoding::encode(&device_id),
                urlencoding::encode(&play_session_id)
            )
        };
        let _ = do_jellyfin_request(
            reqwest::Method::DELETE,
            &enc_url,
            &api_key,
            None,
            Duration::from_secs(4),
            MAX_UPSTREAM_PAYLOAD_SIZE,
        )
        .await;
    }

    Ok(())
}

pub fn get_stored_emby_config_fail_closed() -> crate::streaming_emby::EmbyServerConfig {
    let mut cfg = crate::streaming_emby::get_stored_emby_config();
    if cfg.api_key.starts_with("enc:v1:") {
        tracing::warn!("refusing undecrypted Emby ciphertext API key");
        cfg.api_key.clear();
        return cfg;
    }
    if let Ok(conn) = af_db::get_conn() {
        if let Ok(db_key) = conn.query_row(
            "SELECT api_key FROM streaming_servers WHERE provider = 'emby'",
            [],
            |r| r.get::<_, String>(0),
        ) {
            if db_key.starts_with("enc:v1:") {
                let valid = af_db::decrypt_key(&db_key)
                    .map(|dec| !dec.trim().is_empty() && !dec.starts_with("enc:v1:"))
                    .unwrap_or(false);
                if !valid {
                    tracing::warn!(
                        "stored Emby encrypted API key could not be decrypted; failing closed"
                    );
                    cfg.api_key.clear();
                }
            }
        }
    }
    cfg
}

pub fn save_emby_server_configuration(
    name_raw: &str,
    url_raw: &str,
    api_key_raw: &str,
    enabled: bool,
) -> Result<String, Response> {
    let clean_url = match crate::streaming_emby::validate_emby_server_url(url_raw) {
        Ok(u) => u,
        Err(e) => return Err(api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", e.to_string())),
    };

    let trimmed_key = api_key_raw.trim();
    let is_masked = trimmed_key.starts_with("****");
    let enc_key = if api_key_raw.is_empty() || is_masked {
        String::new()
    } else {
        let clean_token = crate::streaming_emby::sanitize_emby_token(api_key_raw);
        if clean_token.is_empty() {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Valid Emby API key is required",
            ));
        }
        match af_db::encrypt_key(&clean_token) {
            Ok(key) if !af_db::is_encryption_enabled() || key.starts_with("enc:v1:") => key,
            _ => {
                return Err(api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "STREAMING_KEY_STORAGE_FAILED",
                    "Failed to encrypt provider credential; configuration was not changed",
                ));
            }
        }
    };

    let Ok(conn) = af_db::get_conn() else {
        return Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to save Emby server configuration",
        ));
    };

    if enc_key.is_empty() {
        match conn.query_row(
            "SELECT url, api_key FROM streaming_servers WHERE provider = 'emby'",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ) {
            Ok((previous_url, previous_key)) => {
                if previous_url.trim().trim_end_matches('/') != clean_url {
                    return Err(api_error(
                        StatusCode::BAD_REQUEST,
                        "STREAMING_KEY_REQUIRED",
                        "Provide a new API key when changing the provider URL; stored credentials cannot be transferred to another server",
                    ));
                }
                if is_masked {
                    let valid_stored = !previous_key.trim().is_empty()
                        && if previous_key.starts_with("enc:v1:") {
                            af_db::decrypt_key(&previous_key)
                                .map(|d| !d.trim().is_empty() && !d.starts_with("enc:v1:"))
                                .unwrap_or(false)
                        } else {
                            true
                        };
                    if !valid_stored {
                        return Err(api_error(
                            StatusCode::BAD_REQUEST,
                            "STREAMING_KEY_REQUIRED",
                            "Stored Emby API key is missing or cannot be decrypted; provide a new API key",
                        ));
                    }
                }
            }
            Err(_) => {
                if is_masked
                    || clean_url
                        != crate::streaming_emby::resolve_default_emby_url().trim_end_matches('/')
                {
                    return Err(api_error(
                        StatusCode::BAD_REQUEST,
                        "STREAMING_KEY_REQUIRED",
                        "Provide a new API key when configuring or changing the provider URL; stored credentials cannot be transferred to another server",
                    ));
                }
            }
        }
    }

    let name = if name_raw.trim().is_empty() {
        crate::streaming_emby::EMBY_DEFAULT_NAME.to_string()
    } else {
        name_raw.trim().to_string()
    };

    if conn
        .execute(
            r#"
            INSERT INTO streaming_servers (provider, name, url, api_key, enabled, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
            ON CONFLICT(provider) DO UPDATE SET
                name = excluded.name,
                server_id = CASE WHEN RTRIM(streaming_servers.url, '/') != RTRIM(excluded.url, '/') THEN '' ELSE streaming_servers.server_id END,
                server_version = CASE WHEN RTRIM(streaming_servers.url, '/') != RTRIM(excluded.url, '/') THEN '' ELSE streaming_servers.server_version END,
                last_connected_at = CASE WHEN RTRIM(streaming_servers.url, '/') != RTRIM(excluded.url, '/') THEN NULL ELSE streaming_servers.last_connected_at END,
                url = excluded.url,
                api_key = CASE WHEN excluded.api_key != '' THEN excluded.api_key ELSE streaming_servers.api_key END,
                enabled = excluded.enabled,
                updated_at = CURRENT_TIMESTAMP
            "#,
            params![
                crate::streaming_emby::EMBY_PROVIDER_ID,
                name,
                clean_url,
                enc_key,
                enabled
            ],
        )
        .is_err()
    {
        return Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to save Emby server configuration",
        ));
    }

    Ok(clean_url)
}

fn persist_emby_verified_identity(
    status: &StreamingServerStatus,
    clean_url: &str,
    api_key: &str,
) {
    if status.status != "connected"
        || status.server_id.trim().is_empty()
        || api_key.trim().is_empty()
    {
        return;
    }
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let norm_url = clean_url.trim().trim_end_matches('/');
    let Ok(stored_key) = conn.query_row(
        "SELECT api_key FROM streaming_servers WHERE provider = 'emby' AND RTRIM(url, '/') = ?1",
        [norm_url],
        |row| row.get::<_, String>(0),
    ) else {
        return;
    };
    let plaintext = if stored_key.starts_with("enc:v1:") {
        match af_db::decrypt_key(&stored_key) {
            Ok(dec) if !dec.starts_with("enc:v1:") => dec,
            _ => String::new(),
        }
    } else {
        stored_key.clone()
    };
    if !plaintext.is_empty()
        && crate::streaming_emby::sanitize_emby_token(&plaintext)
            == crate::streaming_emby::sanitize_emby_token(api_key)
    {
        let _ = conn.execute(
            "UPDATE streaming_servers \
             SET server_id = ?1, server_version = ?2, last_connected_at = CURRENT_TIMESTAMP \
             WHERE provider = 'emby' AND RTRIM(url, '/') = ?3 AND api_key = ?4 \
               AND enabled=1 AND (COALESCE(server_id, '') = '' OR LOWER(server_id) = LOWER(?1))",
            params![
                status.server_id.trim(),
                status.version.trim(),
                norm_url,
                stored_key
            ],
        );
    }
}

async fn finalize_emby_server_test(
    stored: &crate::streaming_emby::EmbyServerConfig,
    target_url: &str,
    target_key: &str,
    same_server: bool,
) -> Response {
    let expected_sid = if same_server && !stored.expected_server_id.is_empty() {
        Some(stored.expected_server_id.as_str())
    } else {
        None
    };
    match crate::streaming_emby::test_emby_connection(target_url, target_key, expected_sid).await {
        Ok(mut server) => {
            server.enabled = if same_server { stored.enabled } else { false };
            server.support_stage = crate::streaming_emby::EMBY_SUPPORT_STAGE.to_string();
            if same_server && server.status == "connected" && !target_key.is_empty() {
                persist_emby_verified_identity(&server, target_url, target_key);
            }
            Json(serde_json::json!({
                "ok": server.status == "connected",
                "message": "Emby adapter probe only; real-client acceptance is pending",
                "server": server,
            }))
            .into_response()
        }
        Err(error) => {
            let (status, code) = error.http_status_and_code();
            api_error(status, code, error.to_string())
        }
    }
}

fn build_emby_artwork_http_response(art: crate::streaming_emby::EmbyArtworkPayload) -> Response {
    let mut resp = Response::new(Body::from(art.bytes));
    *resp.status_mut() = StatusCode::OK;
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(art.content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'; img-src 'self'; sandbox"),
    );
    resp
}

async fn maybe_handle_emby_artwork(
    item_id: &str,
    q: &HashMap<String, String>,
) -> Option<Response> {
    let explicit_prov = q
        .get("provider")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if !explicit_prov.is_empty() {
        if explicit_prov == "jellyfin" {
            return None;
        }
        if explicit_prov != crate::streaming_emby::EMBY_PROVIDER_ID {
            return Some(api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "unsupported streaming provider",
            ));
        }
        let emby_cfg = get_stored_emby_config_fail_closed();
        if !emby_cfg.enabled || emby_cfg.api_key.is_empty() {
            return Some(StatusCode::NOT_FOUND.into_response());
        }
        return match crate::streaming_emby::fetch_emby_artwork(
            &emby_cfg.url,
            &emby_cfg.api_key,
            item_id,
        )
        .await
        {
            Ok(art) => Some(build_emby_artwork_http_response(art)),
            Err(_) => Some(StatusCode::NOT_FOUND.into_response()),
        };
    }

    let prefers_emby = af_db::get_conn()
        .ok()
        .and_then(|conn| {
            conn.query_row(
                "SELECT provider FROM streaming_history WHERE item_id = ?1 ORDER BY is_active DESC, id DESC LIMIT 1",
                params![item_id],
                |r| r.get::<_, String>(0),
            )
            .ok()
        })
        .map(|p| p.trim().eq_ignore_ascii_case(crate::streaming_emby::EMBY_PROVIDER_ID))
        .unwrap_or(false);

    if prefers_emby {
        let emby_cfg = get_stored_emby_config_fail_closed();
        if emby_cfg.enabled && !emby_cfg.api_key.is_empty() {
            if let Ok(art) = crate::streaming_emby::fetch_emby_artwork(
                &emby_cfg.url,
                &emby_cfg.api_key,
                item_id,
            )
            .await
            {
                return Some(build_emby_artwork_http_response(art));
            }
        }
    }
    None
}

async fn fallback_emby_artwork(item_id: &str, q: &HashMap<String, String>) -> Response {
    if q.get("provider")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let emby_cfg = get_stored_emby_config_fail_closed();
    if emby_cfg.enabled && !emby_cfg.api_key.is_empty() {
        if let Ok(art) = crate::streaming_emby::fetch_emby_artwork(
            &emby_cfg.url,
            &emby_cfg.api_key,
            item_id,
        )
        .await
        {
            return build_emby_artwork_http_response(art);
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

fn enrich_emby_sessions_with_observed_metrics(sessions: &mut [ActiveStreamSession]) {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    for s in sessions.iter_mut() {
        if let Some((tracked_bytes, tracked_start)) = lookup_active_observed_session_metrics(
            &conn,
            crate::streaming_emby::EMBY_PROVIDER_ID,
            &s.session_id,
            &s.play_session_id,
            &s.item_id,
        ) {
            s.session_data_bytes = tracked_bytes.max(0);
            if !tracked_start.is_empty() {
                s.started_at = tracked_start;
            }
        }
    }
}

fn resolve_target_session_provider(
    session_id: &str,
    explicit_provider: &str,
) -> Result<String, Response> {
    let norm_explicit = explicit_provider.trim().to_ascii_lowercase();
    if !norm_explicit.is_empty() {
        if norm_explicit == "jellyfin" || norm_explicit == crate::streaming_emby::EMBY_PROVIDER_ID {
            return Ok(norm_explicit);
        }
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "unsupported_streaming_provider",
            "Unsupported streaming provider",
        ));
    }

    let norm_sess = sanitize_session_key_part(session_id, 96);
    let mut matched_jf = false;
    let mut matched_emby = false;
    if let Ok(conn) = af_db::get_conn() {
        if let Ok(mut stmt) = conn.prepare(
            "SELECT session_key, provider FROM streaming_history \
             WHERE is_active = 1 AND provenance = 'observed_session' \
             ORDER BY id DESC LIMIT 64",
        ) {
            if let Ok(rows) = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            }) {
                for (key, prov) in rows.flatten() {
                    let is_match = parse_observed_session_key(&key)
                        .map(|parsed| parsed.session_id == norm_sess)
                        .unwrap_or(false);
                    if is_match {
                        if prov.trim().eq_ignore_ascii_case("jellyfin") {
                            matched_jf = true;
                        } else if prov
                            .trim()
                            .eq_ignore_ascii_case(crate::streaming_emby::EMBY_PROVIDER_ID)
                        {
                            matched_emby = true;
                        }
                    }
                }
            }
        }
    }

    if matched_jf && matched_emby {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "AMBIGUOUS_SESSION_PROVIDER",
            "Multiple active streaming providers match sessionId; specify provider explicitly",
        ));
    }
    if matched_emby {
        return Ok(crate::streaming_emby::EMBY_PROVIDER_ID.to_string());
    }
    if matched_jf {
        return Ok("jellyfin".to_string());
    }

    let (_, _, jf_key, jf_enabled) = get_stored_jellyfin_config();
    let emby_cfg = get_stored_emby_config_fail_closed();
    let jf_ready = jf_enabled && !jf_key.is_empty();
    let emby_ready = emby_cfg.enabled && !emby_cfg.api_key.is_empty();

    if emby_ready && !jf_ready {
        return Ok(crate::streaming_emby::EMBY_PROVIDER_ID.to_string());
    }
    if jf_ready && emby_ready && !session_id.trim().starts_with("demo-") {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "AMBIGUOUS_SESSION_PROVIDER",
            "Both Jellyfin and Emby are enabled; specify provider explicitly for session control",
        ));
    }
    Ok("jellyfin".to_string())
}

pub async fn control_streaming_session(
    Extension(user): Extension<AuthUser>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<SessionCommandReq>,
) -> Response {
    let clean_session_id = session_id.trim().to_string();
    if clean_session_id.is_empty()
        || clean_session_id.len() > 128
        || clean_session_id.contains('/')
        || clean_session_id.contains('\\')
        || clean_session_id.contains("..")
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "valid sessionId is required",
        );
    }

    let cmd = req.command.trim().to_lowercase();
    if !matches!(cmd.as_str(), "pause" | "resume" | "stop" | "message") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "command must be one of: pause, resume, stop, message",
        );
    }

    let hdr = req.header.trim();
    let msg = req.message.trim();
    if hdr.len() > 120 || msg.len() > 1000 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "header (max 120 chars) or message (max 1000 chars) exceeds maximum length",
        );
    }
    if cmd == "message" && msg.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "message text is required when command is message",
        );
    }

    let target_provider = match resolve_target_session_provider(&clean_session_id, &req.provider) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    if target_provider == crate::streaming_emby::EMBY_PROVIDER_ID {
        let emby_cfg = get_stored_emby_config_fail_closed();
        if !emby_cfg.enabled || emby_cfg.api_key.is_empty() {
            return api_error(
                StatusCode::BAD_REQUEST,
                "emby_unconfigured",
                "Session control command failed: Emby server is not configured or enabled",
            );
        }
        let target = crate::streaming_emby::EmbyCommandTarget {
            provider: crate::streaming_emby::EMBY_PROVIDER_ID.to_string(),
            expected_server_id: emby_cfg.expected_server_id.clone(),
            session_id: clean_session_id.clone(),
            command: cmd.clone(),
            header: hdr.to_string(),
            message: msg.to_string(),
        };
        if let Err(err) = crate::streaming_emby::send_emby_session_command(
            &emby_cfg.url,
            &emby_cfg.api_key,
            &target,
        )
        .await
        {
            let (status, code) = err.http_status_and_code();
            return api_error(
                status,
                code,
                format!("Session control command failed: {}", err),
            );
        }

        let ip = extract_client_ip(&headers);
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        af_db::record_audit(
            user.user_id,
            &user.username,
            &format!("streaming_session_{}", cmd),
            "streaming_session",
            &clean_session_id,
            msg,
            &ip,
            ua,
        );

        return Json(serde_json::json!({
            "message": "Command sent to session",
            "provider": crate::streaming_emby::EMBY_PROVIDER_ID,
            "sessionId": clean_session_id,
            "command": cmd,
        }))
        .into_response();
    }

    if let Err(e) = send_jellyfin_session_command(&clean_session_id, &cmd, hdr, msg).await {
        let err_msg = e.to_string();
        let (status, code) = if err_msg.contains("not found") {
            (StatusCode::NOT_FOUND, "NOT_FOUND")
        } else if err_msg.contains("not configured")
            || err_msg.contains("does not support")
            || err_msg.contains("does not have an active remote-control")
            || err_msg.contains("unsupported session command")
        {
            (StatusCode::BAD_REQUEST, "BAD_REQUEST")
        } else {
            (StatusCode::BAD_GATEWAY, "UPSTREAM_ERROR")
        };
        return api_error(
            status,
            code,
            format!("Session control command failed: {}", err_msg),
        );
    }

    let ip = extract_client_ip(&headers);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    af_db::record_audit(
        user.user_id,
        &user.username,
        &format!("streaming_session_{}", cmd),
        "streaming_session",
        &clean_session_id,
        msg,
        &ip,
        ua,
    );

    Json(serde_json::json!({
        "message": "Command sent to session",
        "sessionId": clean_session_id,
        "command": cmd,
    }))
    .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Background 15-Second Jellyfin Telemetry Poller
// ─────────────────────────────────────────────────────────────────────────────

pub async fn fetch_jellyfin_live_sessions(
    server_name: &str,
    server_url: &str,
    api_key: &str,
) -> anyhow::Result<Vec<ActiveStreamSession>> {
    fetch_jellyfin_live_sessions_for_server(server_name, server_url, api_key, None).await
}

async fn fetch_jellyfin_live_sessions_for_server(
    server_name: &str,
    server_url: &str,
    api_key: &str,
    expected_server_id: Option<&str>,
) -> anyhow::Result<Vec<ActiveStreamSession>> {
    if api_key.is_empty() {
        return Ok(Vec::new());
    }
    let clean_url = af_services::validate_server_url(server_url)?;
    let (body, code, _) = do_jellyfin_request(
        reqwest::Method::GET,
        &format!("{}/Sessions", clean_url),
        api_key,
        None,
        Duration::from_secs(6),
        MAX_UPSTREAM_PAYLOAD_SIZE,
    )
    .await?;

    if !code.is_success() {
        anyhow::bail!("Jellyfin /Sessions returned HTTP {}", code.as_u16());
    }

    let raw_sessions: Vec<JellyfinSessionRaw> = serde_json::from_slice(&body)?;
    if let Some(expected) = expected_server_id {
        if raw_sessions.iter().any(|session| session.now_playing_item.is_some()
            && !session.server_id.trim().eq_ignore_ascii_case(expected)) {
            anyhow::bail!("Jellyfin session server identity is missing or changed");
        }
    }
    let mut active = Vec::new();

    for s in raw_sessions {
        let Some(ref item) = s.now_playing_item else {
            continue;
        };

        let mut pos_secs = 0i64;
        let mut is_paused = false;
        let mut play_method = "DirectPlay".to_string();
        let mut play_session_id = String::new();
        let mut media_source_id = String::new();
        if let Some(ref ps) = s.play_state {
            pos_secs = ps.position_ticks / JELLYFIN_TICKS_PER_SECOND;
            is_paused = ps.is_paused;
            if !ps.play_method.is_empty() {
                play_method = ps.play_method.clone();
            }
            play_session_id = ps.play_session_id.trim().to_string();
            media_source_id = ps.media_source_id.trim().to_string();
        }

        let (supports_media_control, supports_remote_control, can_send_message, supported_commands) =
            resolve_session_capabilities(&s);

        let dur_secs = item.run_time_ticks / JELLYFIN_TICKS_PER_SECOND;
        let progress_pct = if dur_secs > 0 {
            (((pos_secs as f64 / dur_secs as f64) * 1000.0).round() / 10.0).min(100.0)
        } else {
            0.0
        };

        let mut video_codec = String::new();
        let mut video_width = item.width.max(0);
        let mut video_height = item.height.max(0);
        let mut video_range = String::new();
        let mut video_framerate = 0.0f64;
        let mut stream_bitrate_sum = 0i64;

        let mut audio_codec = String::new();
        let mut audio_channels = 0i32;
        let mut audio_layout = String::new();
        let mut audio_language = String::new();
        let mut audio_priority = 0i32;
        let mut audio_bitrate = 0i64;

        let mut subtitle_codec = String::new();
        let mut subtitle_language = String::new();

        for ms in &item.media_streams {
            match ms.stream_type.as_str() {
                "Video" => {
                    if video_codec.is_empty() {
                        video_codec = ms.codec.to_uppercase();
                        if ms.width > 0 {
                            video_width = ms.width;
                        }
                        if ms.height > 0 {
                            video_height = ms.height;
                        }
                        if !ms.video_range.is_empty() {
                            video_range = ms.video_range.clone();
                        }
                        if ms.real_frame_rate > 0.0 {
                            video_framerate = (ms.real_frame_rate * 100.0).round() / 100.0;
                        }
                        if ms.bit_rate > 0 {
                            stream_bitrate_sum += ms.bit_rate;
                        }
                    }
                }
                "Audio" => {
                    let prio = if s.play_state.as_ref().and_then(|ps| ps.audio_stream_index)
                        == Some(ms.index)
                    {
                        3
                    } else if ms.is_default {
                        2
                    } else if audio_priority == 0 {
                        1
                    } else {
                        0
                    };
                    if prio > audio_priority {
                        audio_priority = prio;
                        audio_codec = ms.codec.to_uppercase();
                        audio_channels = ms.channels.max(0);
                        audio_layout = ms.channel_layout.clone();
                        audio_language = ms.language.to_uppercase();
                        stream_bitrate_sum += ms.bit_rate.max(0) - audio_bitrate;
                        audio_bitrate = ms.bit_rate.max(0);
                    }
                }
                "Subtitle" => {
                    if s.play_state
                        .as_ref()
                        .and_then(|ps| ps.subtitle_stream_index)
                        == Some(ms.index)
                    {
                        subtitle_codec = ms.codec.to_uppercase();
                        subtitle_language = ms.language.to_uppercase();
                    }
                }
                _ => {}
            }
        }

        let mut is_video_direct = true;
        let mut is_audio_direct = true;
        let mut target_container = String::new();
        let mut target_video_codec = String::new();
        let mut target_audio_codec = String::new();
        let mut hw_accel = String::new();
        let mut transcode_reasons = Vec::new();
        let mut transcode_progress_pct = 0.0f64;
        let mut transcode_fps = 0.0f64;
        let mut active_bitrate = if item.bitrate > 0 {
            item.bitrate
        } else {
            stream_bitrate_sum.max(0)
        };

        if let Some(ref ti) = s.transcoding_info {
            is_video_direct = ti.is_video_direct;
            is_audio_direct = ti.is_audio_direct;
            target_container = ti.container.to_uppercase();
            if !ti.video_codec.is_empty() {
                target_video_codec = ti.video_codec.to_uppercase();
            }
            if !ti.audio_codec.is_empty() {
                target_audio_codec = ti.audio_codec.to_uppercase();
            }
            if !ti.hardware_acceleration_type.is_empty()
                && !ti.hardware_acceleration_type.eq_ignore_ascii_case("none")
            {
                hw_accel = ti.hardware_acceleration_type.to_uppercase();
            }
            if !ti.transcode_reasons.is_empty() {
                transcode_reasons = ti.transcode_reasons.clone();
            }
            transcode_progress_pct = (ti.completion_percentage * 10.0).round() / 10.0;
            transcode_fps = (ti.framerate * 10.0).round() / 10.0;
            if ti.bitrate > 0 {
                active_bitrate = ti.bitrate;
            }
            if !ti.is_video_direct {
                play_method = "Transcode".to_string();
            } else if play_method == "DirectPlay"
                && (!ti.is_audio_direct || !ti.container.is_empty())
            {
                play_method = "DirectStream".to_string();
            }
        }

        active_bitrate = active_bitrate.max(0);

        let bandwidth_mbps = if is_paused {
            0.0
        } else {
            ((active_bitrate as f64 / 1_000_000.0) * 100.0).round() / 100.0
        };

        let mut artwork_item_id = item.id.clone();
        let mut has_artwork = false;
        if item
            .image_tags
            .get("Primary")
            .map(|t| !t.is_empty())
            .unwrap_or(false)
        {
            has_artwork = true;
        } else if !item.series_id.is_empty() && !item.series_primary_image_tag.is_empty() {
            artwork_item_id = item.series_id.clone();
            has_artwork = true;
        }

        let state_str = if is_paused { "paused" } else { "playing" }.to_string();
        let mut session_data_bytes = 0i64;
        let mut started_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        if let Ok(conn) = af_db::get_conn() {
            if let Some((tracked, tracked_start)) = lookup_active_observed_session_metrics(
                &conn,
                "jellyfin",
                &s.id,
                &play_session_id,
                &item.id,
            ) {
                session_data_bytes = tracked.max(0);
                if !tracked_start.is_empty() {
                    started_at = tracked_start;
                }
            }
        }

        active.push(ActiveStreamSession {
            session_id: s.id,
            provider: "jellyfin".to_string(),
            server_name: server_name.to_string(),
            user_id: s.user_id,
            user_name: s.user_name,
            client_name: s.client,
            device_name: s.device_name,
            device_id: s.device_id,
            app_version: s.application_version,
            ip_address: s.remote_end_point.clone(),
            is_lan: is_private_or_local_ip(&s.remote_end_point),
            item_id: item.id.clone(),
            item_name: item.name.clone(),
            item_type: normalize_media_type(&item.item_type),
            series_name: item.series_name.clone(),
            series_id: item.series_id.clone(),
            season_number: item.parent_index_number,
            episode_number: item.index_number,
            production_year: item.production_year,
            has_artwork,
            artwork_item_id,
            state: state_str,
            position_secs: pos_secs,
            duration_secs: dur_secs,
            progress_pct,
            play_method,
            container: item.container.to_uppercase(),
            target_container,
            video_codec,
            target_video_codec,
            video_resolution: format_resolution_label(video_width, video_height),
            video_range,
            video_framerate,
            is_video_direct,
            audio_codec,
            target_audio_codec,
            audio_channels,
            audio_layout: format_audio_layout(audio_channels, &audio_layout),
            audio_language,
            is_audio_direct,
            subtitle_codec,
            subtitle_language,
            hw_accel,
            transcode_reasons,
            transcode_progress_pct,
            transcode_fps,
            bitrate_bps: active_bitrate,
            bandwidth_mbps,
            session_data_bytes,
            started_at,
            play_session_id,
            media_source_id,
            supports_media_control,
            supports_remote_control,
            can_send_message,
            supported_commands,
        });
    }

    Ok(active)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedObservedSessionKey {
    provider: String,
    server_id: String,
    session_id: String,
    play_session_id: String,
    item_id: String,
    generation: u32,
}

fn sanitize_session_key_part(raw: &str, max_chars: usize) -> String {
    raw.trim()
        .chars()
        .map(|c| if c == ':' { '_' } else { c })
        .take(max_chars.min(96))
        .collect()
}

pub fn format_observed_session_key(
    provider: &str,
    server_id: &str,
    session_id: &str,
    play_session_id: &str,
    item_id: &str,
    generation: u32,
) -> String {
    let p = sanitize_session_key_part(provider, 32);
    let srv = sanitize_session_key_part(server_id, 64);
    let sess = sanitize_session_key_part(session_id, 96);
    let ps = sanitize_session_key_part(play_session_id, 96);
    let item = sanitize_session_key_part(item_id, 96);
    let gen_num = generation.max(1);
    format!("{p}:{srv}:{sess}:{ps}:{item}:g{gen_num}")
}

fn parse_observed_session_key(session_key: &str) -> Option<ParsedObservedSessionKey> {
    let mut parts = session_key.split(':');
    let provider = parts.next()?.to_string();
    let server_id = parts.next()?.to_string();
    let session_id = parts.next()?.to_string();
    let play_session_id = parts.next()?.to_string();
    let item_id = parts.next()?.to_string();
    let gen_part = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let generation = gen_part.strip_prefix('g')?.parse::<u32>().ok()?;
    if generation == 0 {
        return None;
    }
    Some(ParsedObservedSessionKey {
        provider,
        server_id,
        session_id,
        play_session_id,
        item_id,
        generation,
    })
}

fn query_stored_provider_server_id(conn: &rusqlite::Connection, provider: &str) -> String {
    conn.query_row(
        "SELECT COALESCE(server_id, '') FROM streaming_servers WHERE provider = ?1",
        params![provider.trim()],
        |r| r.get::<_, String>(0),
    )
    .unwrap_or_default()
    .trim()
    .to_string()
}

fn query_reconnect_window_secs(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(reconnect_window_secs, 0) FROM streaming_tracking_policies WHERE id = 1",
        [],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(0)
    .clamp(0, 300)
}

fn lookup_active_observed_session_metrics(
    conn: &rusqlite::Connection,
    provider: &str,
    session_id: &str,
    play_session_id: &str,
    item_id: &str,
) -> Option<(i64, String)> {
    let stored_server_id = query_stored_provider_server_id(conn, provider);
    let norm_prov = sanitize_session_key_part(provider, 32);
    let norm_srv = sanitize_session_key_part(&stored_server_id, 64);
    let norm_sess = sanitize_session_key_part(session_id, 96);
    let norm_ps = sanitize_session_key_part(play_session_id, 96);
    let norm_item = sanitize_session_key_part(item_id, 96);

    let mut stmt = conn
        .prepare(
            "SELECT session_key, data_used_bytes, COALESCE(started_at, '') \
             FROM streaming_history \
             WHERE provider = ?1 AND server_id = ?2 AND item_id = ?3 \
               AND is_active = 1 AND provenance = 'observed_session' \
             ORDER BY id DESC LIMIT 32",
        )
        .ok()?;
    let rows: Vec<(String, i64, String)> = stmt
        .query_map(params![provider.trim(), stored_server_id, item_id.trim()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .ok()?
        .flatten()
        .collect();

    for (key, bytes, start) in &rows {
        if let Some(parsed) = parse_observed_session_key(key) {
            if parsed.provider == norm_prov
                && parsed.server_id == norm_srv
                && parsed.session_id == norm_sess
                && parsed.item_id == norm_item
                && parsed.play_session_id == norm_ps
            {
                return Some((*bytes, start.clone()));
            }
        }
    }
    for (key, bytes, start) in rows {
        if let Some(parsed) = parse_observed_session_key(&key) {
            if parsed.provider == norm_prov
                && parsed.server_id == norm_srv
                && parsed.session_id == norm_sess
                && parsed.item_id == norm_item
                && (parsed.play_session_id.is_empty() || norm_ps.is_empty())
            {
                return Some((bytes, start));
            }
        }
    }
    None
}

struct CandidateObservedHistoryRow {
    session_key: String,
    parsed: ParsedObservedSessionKey,
    user_id: String,
    client_name: String,
    device_id: String,
    is_active: bool,
    ended_elapsed_secs: Option<i64>,
}

fn resolve_observed_session_key(
    conn: &rusqlite::Connection,
    provider: &str,
    stored_server_id: &str,
    reconnect_window_secs: i64,
    s: &ActiveStreamSession,
    claimed_keys: &HashSet<String>,
) -> (String, bool) {
    let norm_prov = sanitize_session_key_part(provider, 32);
    let norm_srv = sanitize_session_key_part(stored_server_id, 64);
    let norm_sess = sanitize_session_key_part(&s.session_id, 96);
    let norm_ps = sanitize_session_key_part(&s.play_session_id, 96);
    let norm_item = sanitize_session_key_part(&s.item_id, 96);

    let mut candidates = Vec::new();
    let mut max_seen_gen = 0u32;

    if let Ok(mut stmt) = conn.prepare(
        "SELECT \
            session_key, \
            COALESCE(user_id, ''), \
            COALESCE(client_name, ''), \
            COALESCE(device_id, ''), \
            is_active, \
            COALESCE(provenance, 'legacy_unverified'), \
            CASE \
                WHEN COALESCE(NULLIF(ended_at, ''), NULLIF(last_seen_at, '')) IS NOT NULL \
                THEN CAST(strftime('%s', 'now') AS INTEGER) - CAST(strftime('%s', COALESCE(NULLIF(ended_at, ''), NULLIF(last_seen_at, ''))) AS INTEGER) \
                ELSE NULL \
            END \
         FROM streaming_history \
         WHERE provider = ?1 AND server_id = ?2 AND item_id = ?3 \
         ORDER BY id DESC \
         LIMIT 64",
    ) {
        if let Ok(mapped) = stmt.query_map(
            params![provider.trim(), stored_server_id, s.item_id.trim()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i32>(4)? != 0,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                ))
            },
        ) {
            for row in mapped.flatten() {
                let (key, user_id, client_name, device_id, is_active, provenance, ended_elapsed_secs) = row;
                if provenance != "observed_session" {
                    continue;
                }
                if let Some(parsed) = parse_observed_session_key(&key) {
                    if parsed.provider == norm_prov
                        && parsed.server_id == norm_srv
                        && parsed.session_id == norm_sess
                        && parsed.item_id == norm_item
                    {
                        if parsed.play_session_id == norm_ps {
                            max_seen_gen = max_seen_gen.max(parsed.generation);
                        }
                        candidates.push(CandidateObservedHistoryRow {
                            session_key: key,
                            parsed,
                            user_id,
                            client_name,
                            device_id,
                            is_active,
                            ended_elapsed_secs,
                        });
                    }
                }
            }
        }
    }

    for row in &candidates {
        if row.is_active
            && !claimed_keys.contains(&row.session_key)
            && row.parsed.play_session_id == norm_ps
            && row.user_id.trim() == s.user_id.trim()
        {
            let has_gap = row.ended_elapsed_secs.map(|e| e > 60).unwrap_or(false);
            return (row.session_key.clone(), has_gap);
        }
    }

    for row in &candidates {
        if row.is_active
            && !claimed_keys.contains(&row.session_key)
            && (row.parsed.play_session_id.is_empty() || norm_ps.is_empty())
            && row.user_id.trim() == s.user_id.trim()
            && row.device_id.trim() == s.device_id.trim()
            && row.client_name.trim() == s.client_name.trim()
        {
            let has_gap = row.ended_elapsed_secs.map(|e| e > 60).unwrap_or(false);
            return (row.session_key.clone(), has_gap);
        }
    }

    if reconnect_window_secs > 0 {
        if let Some(latest) = candidates.first() {
            if !latest.is_active
                && !claimed_keys.contains(&latest.session_key)
                && latest.parsed.play_session_id == norm_ps
                && latest.user_id.trim() == s.user_id.trim()
                && latest.device_id.trim() == s.device_id.trim()
                && latest.client_name.trim() == s.client_name.trim()
                && latest
                    .ended_elapsed_secs
                    .map(|elapsed| (0..=reconnect_window_secs).contains(&elapsed))
                    .unwrap_or(false)
            {
                return (latest.session_key.clone(), true);
            }
        }
    }

    let mut next_gen = max_seen_gen.saturating_add(1).max(1);
    for _ in 0..64 {
        let candidate_key = format_observed_session_key(
            provider,
            stored_server_id,
            &s.session_id,
            &s.play_session_id,
            &s.item_id,
            next_gen,
        );
        if !claimed_keys.contains(&candidate_key) {
            let exists = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM streaming_history WHERE session_key = ?1)",
                    params![candidate_key],
                    |r| r.get::<_, bool>(0),
                )
                .unwrap_or(false);
            if !exists {
                return (candidate_key, true);
            }
        }
        next_gen = next_gen.saturating_add(1);
    }

    (
        format_observed_session_key(
            provider,
            stored_server_id,
            &s.session_id,
            &s.play_session_id,
            &s.item_id,
            next_gen,
        ),
        true,
    )
}

pub fn record_live_sessions_snapshot(
    provider: &str,
    sessions: &[ActiveStreamSession],
    interval_secs: i64,
) {
    record_live_sessions_snapshot_for_source(provider, sessions, interval_secs, None);
}

fn record_live_sessions_snapshot_for_source(
    provider: &str,
    sessions: &[ActiveStreamSession],
    interval_secs: i64,
    source: Option<(&str, &str)>,
) {
    if interval_secs <= 0 {
        return;
    }
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let Ok(transaction) = conn.unchecked_transaction() else { return; };
    let conn = &transaction;
    if let Some((server_url, server_id)) = source {
        let matches = conn.query_row("SELECT EXISTS(SELECT 1 FROM streaming_servers WHERE provider=?1 AND RTRIM(url,'/')=RTRIM(?2,'/') AND server_id=?3 AND enabled=1)", params![provider, server_url, server_id], |row| row.get::<_, bool>(0)).unwrap_or(false);
        if !matches { return; }
    }
    let interval = if (1..=60).contains(&interval_secs) {
        interval_secs
    } else {
        0
    };
    let stored_server_id = query_stored_provider_server_id(&conn, provider);
    let reconnect_window_secs = query_reconnect_window_secs(&conn);

    let mut active_keys = HashSet::new();
    let mut direct_play_count = 0i32;
    let mut direct_stream_count = 0i32;
    let mut transcode_count = 0i32;
    let mut total_bitrate_bps = 0i64;
    let mut total_bytes_delta = 0i64;
    let mut new_sample = false;

    for s in sessions {
        if s.session_id.trim().is_empty() || s.item_id.trim().is_empty() {
            continue;
        }
        let (session_key, has_observation_gap) = resolve_observed_session_key(
            &conn,
            provider,
            &stored_server_id,
            reconnect_window_secs,
            s,
            &active_keys,
        );
        active_keys.insert(session_key.clone());

        match s.play_method.as_str() {
            "Transcode" => transcode_count += 1,
            "DirectStream" => direct_stream_count += 1,
            _ => direct_play_count += 1,
        }

        let previous = conn.query_row("SELECT sampled_at, playing FROM streaming_session_samples WHERE history_id=(SELECT id FROM streaming_history WHERE session_key=?1) ORDER BY sampled_at DESC LIMIT 1", [&session_key], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?))).ok();
        let effective_interval = previous.map(|(sampled_at, playing)| {
            let elapsed = Utc::now().timestamp().saturating_sub(sampled_at);
            if has_observation_gap || !playing || elapsed > interval.saturating_mul(2) { 0 } else { elapsed.clamp(0, interval) }
        }).unwrap_or(0);
        let mut delta_secs = 0i64;
        let mut delta_bytes = 0i64;
        if s.state == "playing" {
            let br = s.bitrate_bps.max(0);
            total_bitrate_bps += br;
            delta_secs = effective_interval;
            delta_bytes = (br * effective_interval) / 8;
            total_bytes_delta += delta_bytes;
        }

        let reasons_str = s.transcode_reasons.join(",");

        let _ = conn.execute(
            r#"
            INSERT INTO streaming_history (
                session_key, provider, server_name, user_id, user_name,
                client_name, device_name, device_id, ip_address,
                item_id, item_name, item_type, series_name, series_id,
                season_number, episode_number, production_year,
                play_method, container, video_codec, video_resolution,
                audio_codec, audio_channels, subtitle_codec, hw_accel, transcode_reasons,
                bitrate_bps, duration_secs, watched_secs, data_used_bytes, completion_pct,
                started_at, last_seen_at, is_active,
                provenance, timestamp_certainty, byte_accuracy, server_id
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5,
                ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17,
                ?18, ?19, ?20, ?21,
                ?22, ?23, ?33, ?24, ?25,
                ?26, ?27, ?28, ?29, ?30,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1,
                'observed_session', 'observed', 'estimated',
                ?34
            )
            ON CONFLICT(session_key) DO UPDATE SET
                server_name = CASE WHEN excluded.server_name != '' THEN excluded.server_name ELSE streaming_history.server_name END,
                server_id = CASE WHEN excluded.server_id != '' THEN excluded.server_id ELSE streaming_history.server_id END,
                play_method = excluded.play_method,
                hw_accel = CASE WHEN excluded.hw_accel != '' THEN excluded.hw_accel ELSE streaming_history.hw_accel END,
                transcode_reasons = CASE WHEN excluded.transcode_reasons != '' THEN excluded.transcode_reasons ELSE streaming_history.transcode_reasons END,
                bitrate_bps = excluded.bitrate_bps,
                duration_secs = CASE WHEN excluded.duration_secs > 0 THEN excluded.duration_secs ELSE streaming_history.duration_secs END,
                watched_secs = streaming_history.watched_secs + ?31,
                data_used_bytes = streaming_history.data_used_bytes + ?32,
                completion_pct = MAX(streaming_history.completion_pct, excluded.completion_pct),
                last_seen_at = CURRENT_TIMESTAMP,
                ended_at = NULL,
                is_active = 1
            WHERE streaming_history.provenance = 'observed_session'
            "#,
            params![
                session_key,
                provider,
                s.server_name,
                s.user_id,
                s.user_name,
                s.client_name,
                s.device_name,
                s.device_id,
                s.ip_address,
                s.item_id,
                s.item_name,
                s.item_type,
                s.series_name,
                s.series_id,
                s.season_number,
                s.episode_number,
                s.production_year,
                s.play_method,
                s.container,
                s.video_codec,
                s.video_resolution,
                s.audio_codec,
                s.audio_channels,
                s.hw_accel,
                reasons_str,
                s.bitrate_bps.max(0),
                s.duration_secs,
                delta_secs,
                delta_bytes,
                s.progress_pct,
                delta_secs,
                delta_bytes,
                s.subtitle_codec,
                stored_server_id,
            ],
        );
        if interval > 0 {
            new_sample |= conn.execute(
                "INSERT OR IGNORE INTO streaming_session_samples(history_id, sampled_at, observed_secs, playing, bitrate_bps) SELECT id, CAST(strftime('%s','now') AS INTEGER), ?1, ?2, ?3 FROM streaming_history WHERE session_key = ?4 AND provenance = 'observed_session'",
                params![effective_interval, i64::from(s.state == "playing"), s.bitrate_bps.max(0), session_key],
            ).unwrap_or(0) > 0;
        }
    }

    if active_keys.is_empty() {
        let _ = conn.execute(
            "UPDATE streaming_history SET is_active = 0, ended_at = CURRENT_TIMESTAMP WHERE provider = ?1 AND server_id=?2 AND is_active = 1 AND provenance = 'observed_session'",
            params![provider, stored_server_id],
        );
    } else if let Ok(mut stmt) = conn.prepare(
        "SELECT session_key FROM streaming_history WHERE provider = ?1 AND server_id=?2 AND is_active = 1 AND provenance = 'observed_session'",
    ) {
        let currently_active: Vec<String> = stmt
            .query_map(params![provider, stored_server_id], |r| r.get::<_, String>(0))
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        for key in currently_active {
            if !active_keys.contains(&key) {
                let _ = conn.execute(
                    "UPDATE streaming_history SET is_active = 0, ended_at = CURRENT_TIMESTAMP WHERE session_key = ?1 AND provenance = 'observed_session'",
                    params![key],
                );
            }
        }
    }

    if !sessions.is_empty() && interval > 0 && new_sample {
        let _ = conn.execute(
            r#"
            INSERT INTO streaming_bandwidth_samples (
                provider, active_streams, direct_play_count, direct_stream_count, transcode_count, total_bitrate_bps, bytes_delta
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                provider,
                sessions.len() as i32,
                direct_play_count,
                direct_stream_count,
                transcode_count,
                total_bitrate_bps,
                total_bytes_delta,
            ],
        );
    }

    if interval > 0 {
        let _ = conn.execute(
            "DELETE FROM streaming_session_samples WHERE sampled_at < CAST(strftime('%s','now') AS INTEGER) - 7776000",
            [],
        );
        let _ = conn.execute(
            "DELETE FROM streaming_bandwidth_samples WHERE timestamp < datetime('now', '-90 days')",
            [],
        );
    }
    let _ = transaction.commit();
}

static STREAMING_MONITOR_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn close_disabled_provider(provider: &str) {
    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute("UPDATE streaming_history SET is_active=0 WHERE provider=?1 AND is_active=1 AND provenance='observed_session' AND server_id=COALESCE((SELECT server_id FROM streaming_servers WHERE provider=?1),'') AND NOT EXISTS(SELECT 1 FROM streaming_servers WHERE provider=?1 AND enabled=1 AND api_key!='')", [provider]);
    }
}

fn schedule_live_item_metadata(provider: &str, server_url: &str, api_key: &str, sessions: &[ActiveStreamSession]) {
    if sessions.is_empty() {
        return;
    }
    let item_ids = sessions.iter().map(|session| session.item_id.clone()).collect::<Vec<_>>();
    crate::streaming_metadata::schedule_provider_item_metadata(provider, server_url, api_key, "", &item_ids);
}

fn persist_verified_monitor_source(conn: &rusqlite::Connection, provider: &str, server_url: &str, server_id: &str) -> anyhow::Result<String> {
    if server_id.trim().is_empty() { anyhow::bail!("Missing provider server identity"); }
    let changed = conn.execute("UPDATE streaming_servers SET server_id=CASE WHEN COALESCE(server_id,'')='' THEN ?3 ELSE server_id END WHERE provider=?1 AND RTRIM(url,'/')=RTRIM(?2,'/') AND enabled=1 AND (COALESCE(server_id,'')='' OR LOWER(server_id)=LOWER(?3))", params![provider, server_url, server_id])?;
    if changed != 1 { anyhow::bail!("Provider source changed; verify server configuration"); }
    Ok(query_stored_provider_server_id(conn, provider))
}

fn persist_verified_source_with_key(conn: &rusqlite::Connection, provider: &str, url: &str, key: &str, server_id: &str) -> anyhow::Result<String> {
    let transaction = conn.unchecked_transaction()?;
    let stored_key: String = transaction.query_row("SELECT api_key FROM streaming_servers WHERE provider=?1 AND RTRIM(url,'/')=RTRIM(?2,'/') AND enabled=1", params![provider, url], |row| row.get(0))?;
    let plaintext = if stored_key.starts_with("enc:v1:") { af_db::decrypt_key(&stored_key)? } else { stored_key };
    anyhow::ensure!(!key.is_empty() && plaintext == key, "Provider credentials changed during verification");
    let identity = persist_verified_monitor_source(&transaction, provider, url, server_id)?;
    transaction.commit()?;
    Ok(identity)
}

async fn verify_monitor_source(provider: &str, server_url: &str, api_key: &str) -> anyhow::Result<String> {
    let clean_url = af_services::validate_server_url(server_url)?;
    let (body, status) = crate::streaming_metadata::execute_provider_request(&JELLYFIN_CLIENT, reqwest::Method::GET, &format!("{clean_url}/System/Info/Public"), provider, api_key).await?;
    if !status.is_success() { anyhow::bail!("Provider identity unavailable"); }
    let identity: JellyfinSystemInfo = serde_json::from_slice(&body)?;
    let (_, current_url, current_key, enabled) = if provider == "jellyfin" { get_stored_jellyfin_config() } else { let config = get_stored_emby_config_fail_closed(); (config.name, config.url, config.api_key, config.enabled) };
    if !enabled || current_url.trim_end_matches('/') != clean_url || current_key != api_key { anyhow::bail!("Provider configuration changed during verification"); }
    let provider = provider.to_string();
    let api_key = api_key.to_string();
    tokio::task::spawn_blocking(move || {
        let connection = af_db::get_conn()?;
        persist_verified_source_with_key(&connection, &provider, &clean_url, &api_key, &identity.id)
    }).await?
}

pub fn start_streaming_monitor() {
    if STREAMING_MONITOR_STARTED
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_err()
    {
        return;
    }

    for provider in ["jellyfin", "emby"] {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(15));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let (name, url, key, enabled) = if provider == "jellyfin" {
                    get_stored_jellyfin_config()
                } else {
                    let config = get_stored_emby_config_fail_closed();
                    (config.name, config.url, config.api_key, config.enabled)
                };
                if !enabled || key.is_empty() {
                    close_disabled_provider(provider);
                    continue;
                }
                if let Ok(server_id) = verify_monitor_source(provider, &url, &key).await {
                    let observations = if provider == "jellyfin" {
                        fetch_jellyfin_live_sessions_for_server(&name, &url, &key, Some(&server_id)).await
                    } else {
                        crate::streaming_emby::fetch_emby_live_sessions(&name, &url, &key, Some(&server_id)).await.map_err(anyhow::Error::from)
                    };
                    if let Ok(sessions) = observations {
                        record_live_sessions_snapshot_for_source(provider, &sessions, 15, Some((&url, &server_id)));
                        schedule_live_item_metadata(provider, &url, &key, &sessions);
                    }
                }
            }
        });
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(300));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let _ = sync_jellyfin_watch_history().await;
        }
    });
    tracing::info!(interval = "15s", "streaming telemetry monitor started");
}

// ──────────────────────────────────────────────────────────────────────────────
// 6. Demo Mode Seeder & Full Streaming Dashboard (`GetStreamingDashboard`)
// ──────────────────────────────────────────────────────────────────────────────

pub fn is_demo_mode_active() -> bool {
    if af_services::is_streaming_demo_mode() {
        return true;
    }
    env::var("AETHERFLOW_DEMO_MODE")
        .ok()
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

pub fn get_synthetic_demo_sessions() -> Vec<ActiveStreamSession> {
    let started = (Utc::now() - chrono::Duration::minutes(24)).to_rfc3339();
    vec![
        ActiveStreamSession {
            session_id: "demo-sess-01".to_string(),
            provider: "jellyfin".to_string(),
            server_name: "AetherFlow Media Vault".to_string(),
            user_id: "usr-01".to_string(),
            user_name: "alex".to_string(),
            client_name: "Jellyfin Media Player".to_string(),
            device_name: "Living Room Apple TV 4K".to_string(),
            device_id: "appletv-4k-lr".to_string(),
            app_version: "1.11.1".to_string(),
            ip_address: "192.168.1.42".to_string(),
            is_lan: true,
            item_id: "item-dune-2".to_string(),
            item_name: "Dune: Part Two".to_string(),
            item_type: "Movie".to_string(),
            series_name: String::new(),
            series_id: String::new(),
            season_number: 0,
            episode_number: 0,
            production_year: 2024,
            has_artwork: false,
            artwork_item_id: String::new(),
            state: "playing".to_string(),
            position_secs: 4620,
            duration_secs: 9960,
            progress_pct: 46.4,
            play_method: "DirectPlay".to_string(),
            container: "MKV".to_string(),
            target_container: String::new(),
            video_codec: "HEVC".to_string(),
            target_video_codec: String::new(),
            video_resolution: "4K UHD".to_string(),
            video_range: "HDR10 / Dolby Vision".to_string(),
            video_framerate: 23.98,
            is_video_direct: true,
            audio_codec: "TRUEHD".to_string(),
            target_audio_codec: String::new(),
            audio_channels: 8,
            audio_layout: "7.1 Atmos".to_string(),
            audio_language: "ENG".to_string(),
            is_audio_direct: true,
            subtitle_codec: "PGS".to_string(),
            subtitle_language: "ENG".to_string(),
            hw_accel: String::new(),
            transcode_reasons: Vec::new(),
            transcode_progress_pct: 0.0,
            transcode_fps: 0.0,
            bitrate_bps: 28_400_000,
            bandwidth_mbps: 28.4,
            session_data_bytes: 16_401_000_000,
            started_at: started.clone(),
            play_session_id: String::new(),
            media_source_id: String::new(),
            supports_media_control: true,
            supports_remote_control: true,
            can_send_message: true,
            supported_commands: Vec::new(),
        },
        ActiveStreamSession {
            session_id: "demo-sess-02".to_string(),
            provider: "jellyfin".to_string(),
            server_name: "AetherFlow Media Vault".to_string(),
            user_id: "usr-02".to_string(),
            user_name: "maya".to_string(),
            client_name: "Swiftfin iOS".to_string(),
            device_name: "iPhone 16 Pro".to_string(),
            device_id: "iphone16-maya".to_string(),
            app_version: "1.3.0".to_string(),
            ip_address: "172.56.21.89".to_string(),
            is_lan: false,
            item_id: "item-sev-s02e04".to_string(),
            item_name: "Woe's Hollow".to_string(),
            item_type: "Episode".to_string(),
            series_name: "Severance".to_string(),
            series_id: "ser-severance".to_string(),
            season_number: 2,
            episode_number: 4,
            production_year: 2025,
            has_artwork: false,
            artwork_item_id: String::new(),
            state: "playing".to_string(),
            position_secs: 1890,
            duration_secs: 3120,
            progress_pct: 60.6,
            play_method: "Transcode".to_string(),
            container: "MKV".to_string(),
            target_container: "TS".to_string(),
            video_codec: "HEVC".to_string(),
            target_video_codec: "H264".to_string(),
            video_resolution: "1080p FHD".to_string(),
            video_range: "SDR".to_string(),
            video_framerate: 23.98,
            is_video_direct: false,
            audio_codec: "EAC3".to_string(),
            target_audio_codec: "AAC".to_string(),
            audio_channels: 2,
            audio_layout: "Stereo".to_string(),
            audio_language: "ENG".to_string(),
            is_audio_direct: false,
            subtitle_codec: String::new(),
            subtitle_language: String::new(),
            hw_accel: "NVENC".to_string(),
            transcode_reasons: vec![
                "ContainerBitrateExceedsLimit".to_string(),
                "VideoRangeNotSupported".to_string(),
            ],
            transcode_progress_pct: 74.2,
            transcode_fps: 118.4,
            bitrate_bps: 8_200_000,
            bandwidth_mbps: 8.2,
            session_data_bytes: 1_937_250_000,
            started_at: started.clone(),
            play_session_id: String::new(),
            media_source_id: String::new(),
            supports_media_control: true,
            supports_remote_control: true,
            can_send_message: true,
            supported_commands: Vec::new(),
        },
        ActiveStreamSession {
            session_id: "demo-sess-03".to_string(),
            provider: "jellyfin".to_string(),
            server_name: "AetherFlow Media Vault".to_string(),
            user_id: "usr-03".to_string(),
            user_name: "liam".to_string(),
            client_name: "Jellyfin Web".to_string(),
            device_name: "Firefox 135 (Linux)".to_string(),
            device_id: "ff-linux-liam".to_string(),
            app_version: "10.10.6".to_string(),
            ip_address: "192.168.1.118".to_string(),
            is_lan: true,
            item_id: "item-br2049".to_string(),
            item_name: "Blade Runner 2049".to_string(),
            item_type: "Movie".to_string(),
            series_name: String::new(),
            series_id: String::new(),
            season_number: 0,
            episode_number: 0,
            production_year: 2017,
            has_artwork: false,
            artwork_item_id: String::new(),
            state: "paused".to_string(),
            position_secs: 6410,
            duration_secs: 9840,
            progress_pct: 65.1,
            play_method: "DirectStream".to_string(),
            container: "MKV".to_string(),
            target_container: "MP4".to_string(),
            video_codec: "HEVC".to_string(),
            target_video_codec: String::new(),
            video_resolution: "4K UHD".to_string(),
            video_range: "HDR10".to_string(),
            video_framerate: 23.98,
            is_video_direct: true,
            audio_codec: "EAC3".to_string(),
            target_audio_codec: "AAC".to_string(),
            audio_channels: 6,
            audio_layout: "5.1".to_string(),
            audio_language: "ENG".to_string(),
            is_audio_direct: false,
            subtitle_codec: "SRT".to_string(),
            subtitle_language: "ENG".to_string(),
            hw_accel: String::new(),
            transcode_reasons: vec!["AudioCodecNotSupported".to_string()],
            transcode_progress_pct: 0.0,
            transcode_fps: 0.0,
            bitrate_bps: 18_600_000,
            bandwidth_mbps: 0.0,
            session_data_bytes: 14_903_250_000,
            started_at: started,
            play_session_id: String::new(),
            media_source_id: String::new(),
            supports_media_control: true,
            supports_remote_control: true,
            can_send_message: true,
            supported_commands: Vec::new(),
        },
    ]
}

pub fn seed_streaming_demo_data() -> anyhow::Result<usize> {
    af_services::set_streaming_demo_mode(true);
    let conn = af_db::get_conn()?;

    struct DemoEntry {
        key: &'static str,
        user_id: &'static str,
        user_name: &'static str,
        client_name: &'static str,
        device_name: &'static str,
        ip: &'static str,
        item_id: &'static str,
        item_name: &'static str,
        item_type: &'static str,
        series_name: &'static str,
        season: i32,
        episode: i32,
        year: i32,
        method: &'static str,
        v_codec: &'static str,
        v_res: &'static str,
        a_codec: &'static str,
        a_ch: i32,
        hw: &'static str,
        bitrate: i64,
        dur: i64,
        watched: i64,
        pct: f64,
        hours_ago: i64,
    }

    let entries = [
        DemoEntry {
            key: "demo:hist:01",
            user_id: "usr-01",
            user_name: "alex",
            client_name: "Jellyfin Media Player",
            device_name: "Apple TV 4K",
            ip: "192.168.1.42",
            item_id: "it-01",
            item_name: "Oppenheimer",
            item_type: "Movie",
            series_name: "",
            season: 0,
            episode: 0,
            year: 2023,
            method: "DirectPlay",
            v_codec: "HEVC",
            v_res: "4K UHD",
            a_codec: "TRUEHD",
            a_ch: 8,
            hw: "",
            bitrate: 31_000_000,
            dur: 10800,
            watched: 10650,
            pct: 98.6,
            hours_ago: 3,
        },
        DemoEntry {
            key: "demo:hist:02",
            user_id: "usr-02",
            user_name: "maya",
            client_name: "Swiftfin iOS",
            device_name: "iPhone 16 Pro",
            ip: "172.56.21.89",
            item_id: "it-02",
            item_name: "Hello, Ms. Cobel",
            item_type: "Episode",
            series_name: "Severance",
            season: 2,
            episode: 1,
            year: 2025,
            method: "Transcode",
            v_codec: "H264",
            v_res: "1080p FHD",
            a_codec: "AAC",
            a_ch: 2,
            hw: "NVENC",
            bitrate: 8_500_000,
            dur: 3300,
            watched: 3250,
            pct: 98.5,
            hours_ago: 6,
        },
        DemoEntry {
            key: "demo:hist:03",
            user_id: "usr-03",
            user_name: "liam",
            client_name: "Jellyfin Web",
            device_name: "Firefox 135",
            ip: "192.168.1.118",
            item_id: "it-03",
            item_name: "The Batman",
            item_type: "Movie",
            series_name: "",
            season: 0,
            episode: 0,
            year: 2022,
            method: "DirectStream",
            v_codec: "HEVC",
            v_res: "4K UHD",
            a_codec: "AAC",
            a_ch: 6,
            hw: "",
            bitrate: 22_000_000,
            dur: 10560,
            watched: 10200,
            pct: 96.6,
            hours_ago: 12,
        },
        DemoEntry {
            key: "demo:hist:04",
            user_id: "usr-04",
            user_name: "sophia",
            client_name: "Jellyfin Android TV",
            device_name: "NVIDIA Shield Pro",
            ip: "192.168.1.55",
            item_id: "it-04",
            item_name: "Interstellar",
            item_type: "Movie",
            series_name: "",
            season: 0,
            episode: 0,
            year: 2014,
            method: "DirectPlay",
            v_codec: "HEVC",
            v_res: "4K UHD",
            a_codec: "DTS",
            a_ch: 6,
            hw: "",
            bitrate: 29_500_000,
            dur: 10140,
            watched: 10100,
            pct: 99.6,
            hours_ago: 19,
        },
        DemoEntry {
            key: "demo:hist:05",
            user_id: "usr-01",
            user_name: "alex",
            client_name: "Jellyfin Media Player",
            device_name: "Apple TV 4K",
            ip: "192.168.1.42",
            item_id: "it-05",
            item_name: "Goodbye, Mrs. Selvig",
            item_type: "Episode",
            series_name: "Severance",
            season: 2,
            episode: 2,
            year: 2025,
            method: "DirectPlay",
            v_codec: "HEVC",
            v_res: "4K UHD",
            a_codec: "EAC3",
            a_ch: 6,
            hw: "",
            bitrate: 15_200_000,
            dur: 2940,
            watched: 2900,
            pct: 98.6,
            hours_ago: 27,
        },
        DemoEntry {
            key: "demo:hist:06",
            user_id: "usr-02",
            user_name: "maya",
            client_name: "Swiftfin iOS",
            device_name: "iPad Pro M4",
            ip: "192.168.1.73",
            item_id: "it-06",
            item_name: "Who Is Alive?",
            item_type: "Episode",
            series_name: "Severance",
            season: 2,
            episode: 3,
            year: 2025,
            method: "DirectPlay",
            v_codec: "HEVC",
            v_res: "4K UHD",
            a_codec: "EAC3",
            a_ch: 6,
            hw: "",
            bitrate: 14_800_000,
            dur: 3180,
            watched: 3140,
            pct: 98.7,
            hours_ago: 36,
        },
        DemoEntry {
            key: "demo:hist:07",
            user_id: "usr-05",
            user_name: "noah",
            client_name: "Jellyfin Roku",
            device_name: "Roku Ultra",
            ip: "192.168.1.90",
            item_id: "it-07",
            item_name: "Civil War",
            item_type: "Movie",
            series_name: "",
            season: 0,
            episode: 0,
            year: 2024,
            method: "Transcode",
            v_codec: "H264",
            v_res: "1080p FHD",
            a_codec: "AAC",
            a_ch: 2,
            hw: "NVENC",
            bitrate: 9_800_000,
            dur: 6540,
            watched: 6400,
            pct: 97.9,
            hours_ago: 48,
        },
        DemoEntry {
            key: "demo:hist:08",
            user_id: "usr-04",
            user_name: "sophia",
            client_name: "Finamp",
            device_name: "Pixel 9 Pro",
            ip: "192.168.1.56",
            item_id: "it-08",
            item_name: "Random Access Memories (Track 1)",
            item_type: "Audio",
            series_name: "Daft Punk",
            season: 0,
            episode: 1,
            year: 2013,
            method: "DirectPlay",
            v_codec: "FLAC",
            v_res: "Audio Lossless",
            a_codec: "FLAC",
            a_ch: 2,
            hw: "",
            bitrate: 1_411_000,
            dur: 275,
            watched: 275,
            pct: 100.0,
            hours_ago: 52,
        },
        DemoEntry {
            key: "demo:hist:09",
            user_id: "usr-03",
            user_name: "liam",
            client_name: "Jellyfin Web",
            device_name: "MacBook Pro",
            ip: "192.168.1.119",
            item_id: "it-09",
            item_name: "Arrival",
            item_type: "Movie",
            series_name: "",
            season: 0,
            episode: 0,
            year: 2016,
            method: "DirectPlay",
            v_codec: "HEVC",
            v_res: "1080p FHD",
            a_codec: "EAC3",
            a_ch: 6,
            hw: "",
            bitrate: 11_200_000,
            dur: 6960,
            watched: 6890,
            pct: 99.0,
            hours_ago: 74,
        },
        DemoEntry {
            key: "demo:hist:10",
            user_id: "usr-01",
            user_name: "alex",
            client_name: "Jellyfin Media Player",
            device_name: "Apple TV 4K",
            ip: "192.168.1.42",
            item_id: "it-10",
            item_name: "Dune: Part One",
            item_type: "Movie",
            series_name: "",
            season: 0,
            episode: 0,
            year: 2021,
            method: "DirectPlay",
            v_codec: "HEVC",
            v_res: "4K UHD",
            a_codec: "TRUEHD",
            a_ch: 8,
            hw: "",
            bitrate: 27_600_000,
            dur: 9300,
            watched: 9240,
            pct: 99.4,
            hours_ago: 96,
        },
    ];

    let now = Utc::now();
    for e in &entries {
        let start_ts =
            (now - chrono::Duration::hours(e.hours_ago) - chrono::Duration::seconds(e.watched))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();
        let end_ts = (now - chrono::Duration::hours(e.hours_ago))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let data_bytes = e.watched * (e.bitrate / 8);

        let _ = conn.execute(
            r#"
            INSERT INTO streaming_history (
                session_key, provider, server_name, user_id, user_name,
                client_name, device_name, device_id, ip_address,
                item_id, item_name, item_type, series_name,
                season_number, episode_number, production_year,
                play_method, container, video_codec, video_resolution,
                audio_codec, audio_channels, hw_accel,
                bitrate_bps, duration_secs, watched_secs, data_used_bytes, completion_pct,
                started_at, last_seen_at, ended_at, is_active
            ) VALUES (
                ?1, 'demo', 'AetherFlow Media Vault', ?2, ?3,
                ?4, ?5, ?6, ?7,
                ?8, ?9, ?10, ?11,
                ?12, ?13, ?14,
                ?15, 'MKV', ?16, ?17,
                ?18, ?19, ?20,
                ?21, ?22, ?23, ?24, ?25,
                ?26, ?27, ?27, 0
            )
            ON CONFLICT(session_key) DO UPDATE SET
                watched_secs = excluded.watched_secs,
                data_used_bytes = excluded.data_used_bytes,
                completion_pct = excluded.completion_pct
            "#,
            params![
                e.key,
                e.user_id,
                e.user_name,
                e.client_name,
                e.device_name,
                e.device_name,
                e.ip,
                e.item_id,
                e.item_name,
                e.item_type,
                e.series_name,
                e.season,
                e.episode,
                e.year,
                e.method,
                e.v_codec,
                e.v_res,
                e.a_codec,
                e.a_ch,
                e.hw,
                e.bitrate,
                e.dur,
                e.watched,
                data_bytes,
                e.pct,
                start_ts,
                end_ts,
            ],
        );
    }

    let _ = conn.execute(
        "DELETE FROM streaming_bandwidth_samples WHERE provider = 'demo'",
        [],
    );
    for i in (0..=48).rev() {
        let ts = (now - chrono::Duration::minutes(i * 30))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let active = ((i % 4) + 1) as i32;
        let dp = ((active + 1) / 2).max(1);
        let ds = if active >= 3 { 1 } else { 0 };
        let tc = (active - dp - ds).max(0);
        let bitrate = (dp as i64 * 18_500_000) + (ds as i64 * 14_000_000) + (tc as i64 * 8_200_000);
        let bytes_delta = (bitrate / 8) * 1800;
        let _ = conn.execute(
            r#"
            INSERT INTO streaming_bandwidth_samples (
                timestamp, provider, active_streams, direct_play_count, direct_stream_count, transcode_count, total_bitrate_bps, bytes_delta
            ) VALUES (?1, 'demo', ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![ts, active, dp, ds, tc, bitrate, bytes_delta],
        );
    }

    Ok(entries.len())
}

pub fn clear_streaming_demo_data() -> anyhow::Result<()> {
    af_services::set_streaming_demo_mode(false);
    let conn = af_db::get_conn()?;
    let _ = conn.execute(
        "DELETE FROM streaming_history WHERE provider = 'demo' OR session_key LIKE 'demo:%'",
        [],
    );
    let _ = conn.execute(
        "DELETE FROM streaming_bandwidth_samples WHERE provider = 'demo'",
        [],
    );
    Ok(())
}

pub fn parse_window_days(raw: &str) -> (i32, &'static str) {
    match raw.trim().to_lowercase().as_str() {
        "1" | "24h" | "1d" => (1, "24h"),
        "7" | "7d" => (7, "7d"),
        "14" | "14d" => (14, "14d"),
        "30" | "30d" => (30, "30d"),
        "90" | "90d" => (90, "90d"),
        "365" | "365d" | "1y" => (365, "365d"),
        "0" | "all" => (0, "all"),
        other => {
            if let Ok(days) = other.trim_end_matches('d').parse::<i32>() {
                if (1..=3650).contains(&days) {
                    return (days, "custom");
                }
            }
            (30, "30d")
        }
    }
}

fn query_breakdown(
    conn: &rusqlite::Connection,
    column: &str,
    where_sql: &str,
    args: &[String],
    total_plays: i32,
) -> Vec<BreakdownEntry> {
    if !matches!(column, "item_type" | "video_resolution" | "video_codec") || total_plays <= 0 {
        return Vec::new();
    }

    let sql = format!(
        r#"
        SELECT
            COALESCE(NULLIF({col}, ''), 'Unknown') AS label,
            COUNT(*) AS cnt,
            COALESCE(SUM(watched_secs), 0),
            COALESCE(SUM(data_used_bytes), 0)
        FROM streaming_history
        {where_sql}
        GROUP BY label
        ORDER BY cnt DESC
        "#,
        col = column,
        where_sql = where_sql
    );

    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(&sql) {
        if let Ok(rows) = stmt.query_map(params_from_iter(args.iter()), |r| {
            let count: i32 = r.get(1)?;
            let pct = ((count as f64 / total_plays as f64) * 1000.0).round() / 10.0;
            Ok(BreakdownEntry {
                label: r.get(0)?,
                count,
                pct,
                watch_time_secs: r.get(2)?,
                data_used_bytes: r.get(3)?,
            })
        }) {
            for item in rows.flatten() {
                out.push(item);
            }
        }
    }
    out
}

fn streaming_time_buckets(first_day: NaiveDate, today: NaiveDate) -> (&'static str, Vec<String>) {
    let span_days = (today - first_day).num_days().max(0) + 1;
    let granularity = if span_days <= 3650 {
        "day"
    } else if span_days <= 36500 {
        "month"
    } else {
        "year"
    };
    let mut cursor = match granularity {
        "month" => first_day.with_day(1).unwrap_or(first_day),
        "year" => first_day.with_ordinal(1).unwrap_or(first_day),
        _ => first_day,
    };
    let mut keys = Vec::new();
    while cursor <= today {
        keys.push(cursor.format("%Y-%m-%d").to_string());
        let next = match granularity {
            "month" => cursor.checked_add_months(Months::new(1)),
            "year" => cursor.checked_add_months(Months::new(12)),
            _ => cursor.checked_add_days(Days::new(1)),
        };
        let Some(next) = next else {
            break;
        };
        cursor = next;
    }
    (granularity, keys)
}

fn query_streaming_history_estimates(
    conn: &rusqlite::Connection,
    where_sql: &str,
    args: &[String],
    date_format: &str,
    day_keys: &[String],
) -> rusqlite::Result<Vec<StreamingHistoryEstimate>> {
    let mut estimates = Vec::new();
    let totals_sql = format!(
        "SELECT provenance, COUNT(*), COALESCE(SUM(MAX(COALESCE(watched_secs,0),0)),0), \
         COALESCE(SUM(event_unix IS NULL),0) FROM streaming_history {where_sql} \
         AND provenance IN ('item_summary','legacy_unverified') GROUP BY provenance ORDER BY provenance"
    );
    let mut totals = conn.prepare(&totals_sql)?;
    for estimate in totals.query_map(params_from_iter(args.iter()), |row| {
        Ok(StreamingHistoryEstimate {
            provenance: row.get(0)?,
            records: row.get(1)?,
            reported_watch_time_secs: row.get(2)?,
            undated_records: row.get(3)?,
            time_series: day_keys.iter().map(|date| StreamingTimeSeriesPoint {
                date: date.clone(),
                ..Default::default()
            }).collect(),
        })
    })? {
        estimates.push(estimate?);
    }
    let series_sql = format!(
        "SELECT provenance, strftime('{date_format}',event_unix,'unixepoch'), COUNT(*), \
         COALESCE(SUM(MAX(COALESCE(watched_secs,0),0)),0) FROM streaming_history {where_sql} \
         AND provenance IN ('item_summary','legacy_unverified') AND event_unix IS NOT NULL \
         GROUP BY provenance, 2 ORDER BY 2"
    );
    let mut series = conn.prepare(&series_sql)?;
    let date_indexes: HashMap<&str, usize> = day_keys.iter().enumerate()
        .map(|(index, date)| (date.as_str(), index)).collect();
    for point in series.query_map(params_from_iter(args.iter()), |row| {
        Ok((row.get::<_, String>(0)?, StreamingTimeSeriesPoint {
            date: row.get(1)?,
            plays: row.get(2)?,
            watch_time_secs: row.get(3)?,
            ..Default::default()
        }))
    })? {
        let (provenance, point) = point?;
        if let (Some(estimate), Some(index)) = (
            estimates.iter_mut().find(|estimate| estimate.provenance == provenance),
            date_indexes.get(point.date.as_str()),
        ) {
            estimate.time_series[*index] = point;
        }
    }
    Ok(estimates)
}

pub fn query_streaming_analytics(
    window_days: i32,
    play_method_filter: &str,
    media_type_filter: &str,
    use_demo: bool,
    is_admin: bool,
    live_peak_bandwidth_mbps: f64,
) -> StreamingAnalytics {
    let is_all_time = window_days == 0;
    let resolved_window = if is_all_time {
        0
    } else if window_days < 0 {
        30
    } else {
        window_days
    };

    let now = Utc::now();
    let mut result = StreamingAnalytics {
        window_days: resolved_window,
        peak_bandwidth_mbps: live_peak_bandwidth_mbps,
        media_type_breakdown: Vec::new(),
        resolution_breakdown: Vec::new(),
        codec_breakdown: Vec::new(),
        time_series_granularity: "day".to_string(),
        time_series: Vec::new(),
        top_users: Vec::new(),
        top_titles: Vec::new(),
        recent_history: Vec::new(),
        ..Default::default()
    };

    let Ok(conn) = af_db::get_conn() else {
        let fallback_days = if resolved_window > 0 {
            resolved_window.min(3650) + 1
        } else {
            30
        };
        for i in (0..fallback_days).rev() {
            let d = (now - chrono::Duration::days(i as i64))
                .format("%Y-%m-%d")
                .to_string();
            result.time_series.push(StreamingTimeSeriesPoint {
                date: d,
                ..Default::default()
            });
        }
        return result;
    };

    let mut where_clauses: Vec<String> = vec!["1=1".to_string()];
    let mut args: Vec<String> = Vec::new();

    if !use_demo {
        where_clauses.push("provider != 'demo'".to_string());
        where_clauses.push(format!("id IN (SELECT h.id FROM streaming_history h CROSS JOIN streaming_tracking_policies p WHERE p.id=1 AND ({}))", crate::streaming_history::inclusion_predicate()));
    } else {
        where_clauses.push("provider = 'demo'".into());
    }
    if resolved_window > 0 {
        let cutoff = (now - chrono::Duration::days(resolved_window as i64))
            .timestamp().to_string();
        where_clauses.push("event_unix >= CAST(? AS INTEGER)".to_string());
        args.push(cutoff);
    }
    let pm_trimmed = play_method_filter.trim();
    if !pm_trimmed.is_empty() && !pm_trimmed.eq_ignore_ascii_case("all") {
        if pm_trimmed.eq_ignore_ascii_case("unknown") {
            where_clauses.push(
                "LOWER(TRIM(COALESCE(play_method, ''))) NOT IN ('directplay', 'directstream', 'transcode')".to_string(),
            );
        } else {
            let normalized_pm = normalize_play_method(pm_trimmed);
            where_clauses.push("LOWER(TRIM(play_method)) = LOWER(?)".to_string());
            args.push(normalized_pm);
        }
    }
    let mt_trimmed = media_type_filter.trim();
    if !mt_trimmed.is_empty() && !mt_trimmed.eq_ignore_ascii_case("all") {
        let normalized_mt = normalize_media_type(mt_trimmed);
        where_clauses.push("LOWER(item_type) = LOWER(?)".to_string());
        args.push(normalized_mt);
    }

    let evidence_where_sql = format!("WHERE {}", where_clauses.join(" AND "));
    let where_sql = if use_demo {
        evidence_where_sql.clone()
    } else {
        format!("{evidence_where_sql} AND provenance IN ('observed_session','imported_event')")
    };

    let first_day = if resolved_window > 0 {
        (now - chrono::Duration::days(resolved_window as i64)).date_naive()
    } else {
        let min_day_sql = format!(
            "SELECT COALESCE(MIN(date(event_unix, 'unixepoch')), '') FROM streaming_history {}",
            evidence_where_sql
        );
        let earliest_date = conn
            .query_row(&min_day_sql, params_from_iter(args.iter()), |r| {
                r.get::<_, String>(0)
            })
            .ok()
            .and_then(|s| chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok());

        earliest_date
            .unwrap_or(now.date_naive() - chrono::Duration::days(29))
            .min(now.date_naive() - chrono::Duration::days(29))
    };

    let (granularity, day_keys) = streaming_time_buckets(first_day, now.date_naive());
    result.time_series_granularity = granularity.to_string();
    let date_format = match granularity {
        "month" => "%Y-%m-01",
        "year" => "%Y-01-01",
        _ => "%Y-%m-%d",
    };
    if !use_demo {
        result.historical_estimates = query_streaming_history_estimates(
            &conn, &evidence_where_sql, &args, date_format, &day_keys,
        ).unwrap_or_else(|error| {
            tracing::warn!(%error, "Imported streaming estimate query failed");
            Vec::new()
        });
    }
    let mut daily_map: HashMap<String, StreamingTimeSeriesPoint> = HashMap::new();
    for day in &day_keys {
        daily_map.insert(
            day.clone(),
            StreamingTimeSeriesPoint {
                date: day.clone(),
                ..Default::default()
            },
        );
    }

    // 1. Aggregate summary metrics
    let agg_sql = format!(
        r#"
        SELECT
            COUNT(*),
            COALESCE(SUM(watched_secs), 0),
            COALESCE(SUM(data_used_bytes), 0),
            COUNT(DISTINCT user_name),
            COUNT(DISTINCT item_name),
            COALESCE(AVG(completion_pct), 0),
            COALESCE(MAX(bitrate_bps), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'directplay' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'directstream' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'transcode' THEN 1 ELSE 0 END), 0)
        FROM streaming_history
        {}
        "#,
        where_sql
    );

    if let Ok((
        total_plays,
        total_watch_secs,
        total_data_bytes,
        unique_users,
        unique_titles,
        avg_completion,
        max_bitrate_bps,
        dp_count,
        ds_count,
        tc_count,
    )) = conn.query_row(&agg_sql, params_from_iter(args.iter()), |r| {
        Ok((
            r.get::<_, i32>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i32>(3)?,
            r.get::<_, i32>(4)?,
            r.get::<_, f64>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, i32>(7)?,
            r.get::<_, i32>(8)?,
            r.get::<_, i32>(9)?,
        ))
    }) {
        result.total_plays = total_plays;
        result.total_watch_time_secs = total_watch_secs;
        result.total_data_used_bytes = total_data_bytes;
        result.unique_users = unique_users;
        result.unique_titles = unique_titles;
        result.avg_completion_pct = (avg_completion * 10.0).round() / 10.0;

        let hist_peak_mbps = ((max_bitrate_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;
        if hist_peak_mbps > result.peak_bandwidth_mbps {
            result.peak_bandwidth_mbps = hist_peak_mbps;
        }

        result.stream_types = StreamTypeDistribution {
            direct_play_count: dp_count,
            direct_stream_count: ds_count,
            transcode_count: tc_count,
            direct_play_pct: if total_plays > 0 {
                ((dp_count as f64 / total_plays as f64) * 1000.0).round() / 10.0
            } else {
                0.0
            },
            direct_stream_pct: if total_plays > 0 {
                ((ds_count as f64 / total_plays as f64) * 1000.0).round() / 10.0
            } else {
                0.0
            },
            transcode_pct: if total_plays > 0 {
                ((tc_count as f64 / total_plays as f64) * 1000.0).round() / 10.0
            } else {
                0.0
            },
        };
    }

    let mut bw_clauses: Vec<String> = vec!["1=1".to_string()];
    let mut bw_args: Vec<String> = Vec::new();
    let no_item_filters = (pm_trimmed.is_empty() || pm_trimmed.eq_ignore_ascii_case("all"))
        && (mt_trimmed.is_empty() || mt_trimmed.eq_ignore_ascii_case("all"));

    // Check bandwidth samples for peak aggregate bitrate when no per-item filter is active
    if no_item_filters {
        if !use_demo {
            bw_clauses.push("provider != 'demo'".to_string());
        }
        if resolved_window > 0 {
            let cutoff = (now - chrono::Duration::days(resolved_window as i64))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();
            bw_clauses.push("timestamp >= ?".to_string());
            bw_args.push(cutoff);
        }
        let bw_sql = format!(
            "SELECT COALESCE(MAX(total_bitrate_bps), 0) FROM streaming_bandwidth_samples WHERE {}",
            bw_clauses.join(" AND ")
        );
        if let Ok(sample_peak_bps) =
            conn.query_row(&bw_sql, params_from_iter(bw_args.iter()), |r| {
                r.get::<_, i64>(0)
            })
        {
            let sample_peak_mbps = ((sample_peak_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;
            if sample_peak_mbps > result.peak_bandwidth_mbps {
                result.peak_bandwidth_mbps = sample_peak_mbps;
            }
        }
    }

    // 2. Breakdowns: Media Type, Resolution, Video Codec
    result.media_type_breakdown =
        query_breakdown(&conn, "item_type", &where_sql, &args, result.total_plays);
    result.resolution_breakdown = query_breakdown(
        &conn,
        "video_resolution",
        &where_sql,
        &args,
        result.total_plays,
    );
    result.codec_breakdown =
        query_breakdown(&conn, "video_codec", &where_sql, &args, result.total_plays);

    // 3. Time Series (Daily Plays, Watch Time, Data Usage, Stream Types)
    let ts_sql = format!(
        r#"
        SELECT
            strftime('{date_format}', event_unix, 'unixepoch') AS day,
            COUNT(*),
            COALESCE(SUM(watched_secs), 0),
            COALESCE(SUM(data_used_bytes), 0),
            COALESCE(MAX(bitrate_bps), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'directplay' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'directstream' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'transcode' THEN 1 ELSE 0 END), 0)
        FROM streaming_history
        {} AND event_unix IS NOT NULL
        GROUP BY day
        ORDER BY day ASC
        "#,
        where_sql
    );
    if let Ok(mut stmt) = conn.prepare(&ts_sql) {
        if let Ok(rows) = stmt.query_map(params_from_iter(args.iter()), |r| {
            let max_day_bitrate: i64 = r.get(4)?;
            Ok(StreamingTimeSeriesPoint {
                date: r.get(0)?,
                plays: r.get(1)?,
                watch_time_secs: r.get(2)?,
                data_used_bytes: r.get(3)?,
                peak_bandwidth_mbps: ((max_day_bitrate as f64 / 1_000_000.0) * 100.0).round()
                    / 100.0,
                direct_play_count: r.get(5)?,
                direct_stream_count: r.get(6)?,
                transcode_count: r.get(7)?,
            })
        }) {
            for pt in rows.flatten() {
                daily_map.insert(pt.date.clone(), pt);
            }
        }
    }

    if no_item_filters {
        let bw_daily_sql = format!(
            r#"
            SELECT
                strftime('{date_format}', timestamp) AS day,
                COALESCE(MAX(total_bitrate_bps), 0)
            FROM streaming_bandwidth_samples
            WHERE {} AND timestamp != ''
            GROUP BY day
            "#,
            bw_clauses.join(" AND ")
        );
        if let Ok(mut stmt) = conn.prepare(&bw_daily_sql) {
            if let Ok(rows) = stmt.query_map(params_from_iter(bw_args.iter()), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            }) {
                for (day, peak_bps) in rows.flatten() {
                    let sample_mbps = ((peak_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;
                    if let Some(pt) = daily_map.get_mut(&day) {
                        if sample_mbps > pt.peak_bandwidth_mbps {
                            pt.peak_bandwidth_mbps = sample_mbps;
                        }
                    }
                }
            }
        }
    }

    for d in day_keys {
        if let Some(pt) = daily_map.remove(&d) {
            result.time_series.push(pt);
        }
    }

    // 4. Top Users Leaderboard
    let users_sql = format!(
        r#"
        WITH filtered_history AS (SELECT * FROM streaming_history {where_sql})
        SELECT
            COALESCE(MAX(NULLIF(user_id, '')), '') AS uid,
            user_name,
            COALESCE(MAX(NULLIF(provider, '')), 'jellyfin') AS prov,
            COUNT(*) AS plays,
            COALESCE(SUM(watched_secs), 0) AS watch_secs,
            COALESCE(SUM(data_used_bytes), 0) AS data_bytes,
            COUNT(DISTINCT item_name) AS unique_items,
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'directplay' THEN 1 ELSE 0 END), 0) AS dp_count,
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'transcode' THEN 1 ELSE 0 END), 0) AS tc_count,
            COALESCE(AVG(completion_pct), 0) AS avg_comp,
            COALESCE(
                (
                    SELECT CASE
                        WHEN h2.client_name != '' AND h2.device_name != '' THEN h2.client_name || ' · ' || h2.device_name
                        WHEN h2.client_name != '' THEN h2.client_name
                        ELSE h2.device_name
                    END
                    FROM filtered_history h2
                    WHERE h2.user_name = filtered_history.user_name
                      AND (h2.client_name != '' OR h2.device_name != '')
                    ORDER BY COALESCE(NULLIF(h2.last_seen_at, ''), h2.started_at) DESC, h2.id DESC
                    LIMIT 1
                ),
                ''
            ) AS last_device,
            COALESCE(MAX(CAST(last_seen_at AS TEXT)), '') AS last_seen
        FROM filtered_history
        WHERE user_name != ''
        GROUP BY user_name
        ORDER BY data_bytes DESC, watch_secs DESC, plays DESC
        LIMIT 10
        "#
    );
    if let Ok(mut stmt) = conn.prepare(&users_sql) {
        if let Ok(rows) = stmt.query_map(params_from_iter(args.iter()), |r| {
            let avg_comp: f64 = r.get(9)?;
            Ok(StreamingUserStat {
                user_id: r.get(0)?,
                user_name: r.get(1)?,
                provider: r.get(2)?,
                total_plays: r.get(3)?,
                total_watch_secs: r.get(4)?,
                total_data_bytes: r.get(5)?,
                unique_items: r.get(6)?,
                direct_play_count: r.get(7)?,
                transcode_count: r.get(8)?,
                avg_completion_pct: (avg_comp * 10.0).round() / 10.0,
                last_device: r.get(10)?,
                last_seen_at: r.get(11)?,
            })
        }) {
            for item in rows.flatten() {
                result.top_users.push(item);
            }
        }
    }

    // 5. Top Watched Titles
    let titles_sql = format!(
        r#"
        SELECT
            COALESCE(MAX(NULLIF(item_id, '')), ''),
            CASE WHEN series_name != '' THEN series_name ELSE item_name END AS display_title,
            item_type,
            series_name,
            COALESCE(MAX(production_year), 0),
            COALESCE(MAX(NULLIF(provider, '')), 'jellyfin'),
            COALESCE(MAX(NULLIF(video_resolution, '')), ''),
            COALESCE(MAX(NULLIF(video_codec, '')), ''),
            COUNT(*) AS plays,
            COUNT(DISTINCT user_name) AS viewers,
            COALESCE(SUM(watched_secs), 0) AS watch_secs,
            COALESCE(SUM(data_used_bytes), 0) AS data_bytes,
            COALESCE(AVG(completion_pct), 0) AS avg_comp,
            COALESCE(MAX(CAST(last_seen_at AS TEXT)), '') AS last_watched
        FROM streaming_history
        {} AND item_name != ''
        GROUP BY display_title, item_type
        ORDER BY plays DESC, watch_secs DESC, data_bytes DESC
        LIMIT 10
        "#,
        where_sql
    );
    if let Ok(mut stmt) = conn.prepare(&titles_sql) {
        if let Ok(rows) = stmt.query_map(params_from_iter(args.iter()), |r| {
            let avg_comp: f64 = r.get(12)?;
            Ok(StreamingTitleStat {
                item_id: r.get(0)?,
                item_name: r.get(1)?,
                item_type: r.get(2)?,
                series_name: r.get(3)?,
                production_year: r.get(4)?,
                provider: r.get(5)?,
                video_resolution: r.get(6)?,
                video_codec: r.get(7)?,
                total_plays: r.get(8)?,
                unique_viewers: r.get(9)?,
                total_watch_secs: r.get(10)?,
                total_data_bytes: r.get(11)?,
                avg_completion_pct: (avg_comp * 10.0).round() / 10.0,
                last_watched_at: r.get(13)?,
            })
        }) {
            for item in rows.flatten() {
                result.top_titles.push(item);
            }
        }
    }

    // 6. Recent History Log
    let hist_sql = format!(
        r#"
        SELECT
            id,
            COALESCE(session_key, ''),
            provider,
            server_name,
            user_name,
            client_name,
            device_name,
            ip_address,
            item_id,
            item_name,
            item_type,
            series_name,
            season_number,
            episode_number,
            production_year,
            play_method,
            container,
            video_codec,
            video_resolution,
            audio_codec,
            audio_channels,
            hw_accel,
            bitrate_bps,
            duration_secs,
            watched_secs,
            data_used_bytes,
            completion_pct,
            COALESCE(CAST(started_at AS TEXT), ''),
            COALESCE(CAST(last_seen_at AS TEXT), ''),
            is_active
        FROM streaming_history
        {}
        ORDER BY last_seen_at DESC, id DESC
        LIMIT 500
        "#,
        where_sql
    );
    if let Ok(mut stmt) = conn.prepare(&hist_sql) {
        if let Ok(rows) = stmt.query_map(params_from_iter(args.iter()), |r| {
            let raw_ip: String = r.get(7)?;
            let ip_address = if is_admin { raw_ip } else { String::new() };
            let bitrate_bps: i64 = r.get(22)?;
            let bandwidth_mbps = ((bitrate_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;
            let raw_comp: f64 = r.get(26)?;
            let completion_pct = (raw_comp * 10.0).round() / 10.0;
            let is_act: i32 = r.get(29)?;
            Ok(StreamingHistoryItem {
                id: r.get(0)?,
                session_key: r.get(1)?,
                provider: r.get(2)?,
                server_name: r.get(3)?,
                user_name: r.get(4)?,
                client_name: r.get(5)?,
                device_name: r.get(6)?,
                ip_address,
                item_id: r.get(8)?,
                item_name: r.get(9)?,
                item_type: r.get(10)?,
                series_name: r.get(11)?,
                season_number: r.get(12)?,
                episode_number: r.get(13)?,
                production_year: r.get(14)?,
                play_method: r.get(15)?,
                container: r.get(16)?,
                video_codec: r.get(17)?,
                video_resolution: r.get(18)?,
                audio_codec: r.get(19)?,
                audio_channels: r.get(20)?,
                hw_accel: r.get(21)?,
                bitrate_bps,
                bandwidth_mbps,
                duration_secs: r.get(23)?,
                watched_secs: r.get(24)?,
                data_used_bytes: r.get(25)?,
                completion_pct,
                started_at: r.get(27)?,
                last_seen_at: r.get(28)?,
                is_active: is_act != 0,
            })
        }) {
            for item in rows.flatten() {
                result.recent_history.push(item);
            }
        }
    }

    result
}

#[derive(Clone)]
struct CachedTelemetry {
    fingerprint: String,
    sampled_at: std::time::Instant,
    result: Result<(StreamingServerStatus, Vec<ActiveStreamSession>), String>,
}

static TELEMETRY_CACHE: Lazy<tokio::sync::Mutex<HashMap<String, CachedTelemetry>>> = Lazy::new(|| tokio::sync::Mutex::new(HashMap::new()));

async fn cached_provider_telemetry(provider: &str) -> anyhow::Result<(StreamingServerStatus, Vec<ActiveStreamSession>)> {
    use sha2::Digest;
    let (name, url, key, enabled) = if provider == "jellyfin" { get_stored_jellyfin_config() } else { let config = get_stored_emby_config_fail_closed(); (config.name, config.url, config.api_key, config.enabled) };
    anyhow::ensure!(enabled && !key.is_empty(), "Provider disabled or unconfigured");
    let server_id = {
        let connection = af_db::get_conn()?;
        query_stored_provider_server_id(&connection, provider)
    };
    anyhow::ensure!(!server_id.is_empty(), "Server identity is unverified; test the saved connection first");
    let fingerprint = hex::encode(sha2::Sha256::digest(format!("{name}\0{url}\0{key}\0{server_id}")));
    let mut cache = TELEMETRY_CACHE.lock().await;
    if let Some(entry) = cache.get(provider).filter(|entry| entry.fingerprint == fingerprint && entry.sampled_at.elapsed() < Duration::from_secs(15)) {
        return entry.result.clone().map_err(anyhow::Error::msg);
    }
    let result = async {
        let mut status = if provider == "jellyfin" { test_jellyfin_connection(&url, &key).await? } else { crate::streaming_emby::test_emby_connection(&url, &key, Some(&server_id)).await? };
        anyhow::ensure!(status.server_id.eq_ignore_ascii_case(&server_id), "Provider server identity changed");
        let mut sessions = if provider == "jellyfin" { fetch_jellyfin_live_sessions_for_server(&name, &url, &key, Some(&server_id)).await? } else { crate::streaming_emby::fetch_emby_live_sessions(&name, &url, &key, Some(&server_id)).await? };
        let (_, current_url, current_key, current_enabled) = if provider == "jellyfin" { get_stored_jellyfin_config() } else { let config = get_stored_emby_config_fail_closed(); (config.name, config.url, config.api_key, config.enabled) };
        let current_server_id = {
            let connection = af_db::get_conn()?;
            query_stored_provider_server_id(&connection, provider)
        };
        anyhow::ensure!(current_enabled && current_url == url && current_key == key && current_server_id == server_id, "Provider source changed during telemetry read");
        if provider == "emby" { enrich_emby_sessions_with_observed_metrics(&mut sessions); }
        status.name = name;
        Ok((status, sessions))
    }.await.map_err(|error: anyhow::Error| error.to_string());
    cache.insert(provider.into(), CachedTelemetry { fingerprint, sampled_at: std::time::Instant::now(), result: result.clone() });
    result.map_err(anyhow::Error::msg)
}

pub async fn build_streaming_dashboard(
    window_raw: &str,
    play_method_filter: &str,
    media_type_filter: &str,
    is_admin: bool,
) -> StreamingDashboardResponse {
    let (window_days, _) = parse_window_days(window_raw);
    let (jf_name, jf_url, jf_key, jf_enabled) = get_stored_jellyfin_config();

    let masked_key = if !is_admin {
        String::new()
    } else if jf_key.len() > 4 {
        let tail: String = jf_key
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("****{}", tail)
    } else if !jf_key.is_empty() {
        "****".to_string()
    } else {
        String::new()
    };

    let mut jf_status = StreamingServerStatus {
        provider: "jellyfin".to_string(),
        name: jf_name.clone(),
        url: jf_url.clone(),
        api_key_masked: masked_key,
        configured: !jf_key.is_empty(),
        enabled: jf_enabled,
        status: "unconfigured".to_string(),
        support_stage: "active".to_string(),
        server_id: String::new(),
        version: String::new(),
        operating_system: String::new(),
        library_counts: StreamingLibraryCounts::default(),
        last_connected_at: String::new(),
        error_message: String::new(),
    };

    let emby_cfg = get_stored_emby_config_fail_closed();
    let emby_configured = !emby_cfg.api_key.is_empty();
    let emby_masked_key = if is_admin {
        crate::streaming_emby::mask_emby_api_key(&emby_cfg.api_key)
    } else {
        String::new()
    };
    let mut emby_status = StreamingServerStatus {
        provider: crate::streaming_emby::EMBY_PROVIDER_ID.to_string(),
        name: emby_cfg.name.clone(),
        url: emby_cfg.url.clone(),
        api_key_masked: emby_masked_key,
        configured: emby_configured,
        enabled: emby_cfg.enabled,
        status: if !emby_cfg.enabled && !emby_configured {
            "coming_soon".to_string()
        } else {
            "unconfigured".to_string()
        },
        support_stage: crate::streaming_emby::EMBY_SUPPORT_STAGE.to_string(),
        server_id: emby_cfg.expected_server_id.clone(),
        version: String::new(),
        operating_system: String::new(),
        library_counts: StreamingLibraryCounts::default(),
        last_connected_at: String::new(),
        error_message: String::new(),
    };

    let mut active_sessions: Vec<ActiveStreamSession> = Vec::new();
    let mut use_demo = is_demo_mode_active();
    if emby_cfg.enabled && emby_configured {
        use_demo = false;
    }

    if jf_enabled && !jf_key.is_empty() {
        use_demo = false;
        match cached_provider_telemetry("jellyfin").await {
            Ok((status, sessions)) => { jf_status = status; active_sessions = sessions; }
            Err(error) => { jf_status.status = "unavailable".into(); jf_status.error_message = error.to_string(); }
        }
    } else if use_demo {
        if let Ok(conn) = af_db::get_conn() {
            let demo_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM streaming_history WHERE provider = 'demo'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            drop(conn);
            if demo_count == 0 {
                let _ = seed_streaming_demo_data();
            }
        }
        active_sessions = get_synthetic_demo_sessions();
        jf_status.status = "demo".to_string();
        jf_status.configured = true;
        jf_status.name = format!("{} (Demo Mode)", jf_name);
        jf_status.version = "10.10.6".to_string();
        jf_status.operating_system = "Linux 6.8 (Ubuntu 24.04 LTS)".to_string();
        jf_status.library_counts = StreamingLibraryCounts {
            movies: 1420,
            series: 318,
            episodes: 14890,
            audio: 26400,
        };
    } else {
        jf_status.status = if jf_enabled { "unconfigured" } else { "disabled" }.into();
    }

    if emby_cfg.enabled && emby_configured {
        match cached_provider_telemetry("emby").await {
            Ok((status, sessions)) => { emby_status = status; active_sessions.extend(sessions); }
            Err(error) => { emby_status.status = "unavailable".into(); emby_status.error_message = error.to_string(); }
        }
    }

    if !is_admin {
        jf_status.api_key_masked.clear();
        emby_status.api_key_masked.clear();
        for s in &mut active_sessions {
            s.ip_address.clear();
        }
    }

    let servers = vec![
        jf_status,
        StreamingServerStatus {
            provider: "plex".to_string(),
            name: "Plex Media Server".to_string(),
            url: "http://127.0.0.1:32400".to_string(),
            api_key_masked: String::new(),
            configured: false,
            enabled: false,
            status: "coming_soon".to_string(),
            support_stage: "coming_soon".to_string(),
            server_id: String::new(),
            version: String::new(),
            operating_system: String::new(),
            library_counts: StreamingLibraryCounts::default(),
            last_connected_at: String::new(),
            error_message: String::new(),
        },
        emby_status,
    ];

    // Live summary calculations
    let active_streams = active_sessions.len() as i32;
    let mut direct_play_count = 0i32;
    let mut direct_stream_count = 0i32;
    let mut transcode_count = 0i32;
    let mut total_bitrate_bps = 0i64;
    let mut active_session_bytes = 0i64;
    let mut lan_streams = 0i32;
    let mut wan_streams = 0i32;

    for s in &active_sessions {
        match s.play_method.as_str() {
            "Transcode" => transcode_count += 1,
            "DirectStream" => direct_stream_count += 1,
            _ => direct_play_count += 1,
        }
        if s.state == "playing" {
            total_bitrate_bps += s.bitrate_bps;
        }
        active_session_bytes += s.session_data_bytes;
        if s.is_lan {
            lan_streams += 1;
        } else {
            wan_streams += 1;
        }
    }

    let total_bandwidth_mbps = ((total_bitrate_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;

    let live_summary = StreamingLiveSummary {
        active_streams,
        direct_play_count,
        direct_stream_count,
        transcode_count,
        total_bitrate_bps,
        total_bandwidth_mbps,
        active_session_bytes,
        lan_streams,
        wan_streams,
        is_demo_mode: use_demo,
    };

    let analytics = query_streaming_analytics(
        window_days,
        play_method_filter,
        media_type_filter,
        use_demo,
        is_admin,
        total_bandwidth_mbps,
    );

    StreamingDashboardResponse {
        servers,
        live_summary,
        active_sessions,
        analytics,
        updated_at: Utc::now().to_rfc3339(),
    }
}

pub async fn get_streaming_dashboard_handler(
    Query(q): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    let window = q
        .get("window")
        .or_else(|| q.get("days"))
        .map(|s| s.as_str())
        .unwrap_or("30");
    let play_method = q.get("playMethod").map(|s| s.as_str()).unwrap_or("all");
    let media_type = q.get("mediaType").map(|s| s.as_str()).unwrap_or("all");
    let user = req
        .extensions()
        .get::<AuthUser>()
        .cloned();
    let Some(user) = user else {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Authentication required"}))).into_response();
    };
    if user.role != "admin" {
        return Json(StreamingDashboardResponse {
            updated_at: Utc::now().to_rfc3339(),
            ..Default::default()
        }).into_response();
    }
    let payload = build_streaming_dashboard(window, play_method, media_type, true).await;
    Json(payload).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_STREAMING_DB_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn mark_dashboard_fixtures_as_observed() {
        af_db::get_conn().unwrap().execute("UPDATE streaming_history SET provenance='observed_session', timestamp_certainty='observed', byte_accuracy='estimated' WHERE provider!='demo'", []).unwrap();
    }

    #[test]
    fn test_dashboard_preserves_imported_estimates_without_double_counting_confirmed_time() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = init_isolated_streaming_db("imported_estimates");
        let now = Utc::now();
        let old = (now - chrono::Duration::days(45)).format("%Y-%m-%d %H:%M:%S").to_string();
        let current = now.format("%Y-%m-%d %H:%M:%S").to_string();
        let conn = af_db::get_conn().unwrap();
        for (key, provenance, timestamp, seconds, policy, user) in [
            ("legacy", "legacy_unverified", old.as_str(), 3600, "included", "viewer"),
            ("summary", "item_summary", old.as_str(), 3600, "included", "viewer"),
            ("undated", "item_summary", "", 600, "included", "viewer"),
            ("negative", "legacy_unverified", old.as_str(), -5, "included", "viewer"),
            ("observed", "observed_session", current.as_str(), 120, "included", "viewer"),
            ("event", "imported_event", current.as_str(), 240, "included", "viewer"),
            ("excluded", "legacy_unverified", old.as_str(), 9999, "excluded", "viewer"),
            ("duplicate", "item_summary", old.as_str(), 9999, "duplicate", "viewer"),
            ("hidden-user", "item_summary", old.as_str(), 9999, "included", "hidden"),
        ] {
            conn.execute(
                "INSERT INTO streaming_history (session_key,provider,server_id,user_id,item_id,item_type,started_at,watched_secs,provenance,policy_status) VALUES (?1,'jellyfin','server',?2,'same-item','Movie',?3,?4,?5,?6)",
                params![key,user,timestamp,seconds,provenance,policy],
            ).unwrap();
        }
        conn.execute("UPDATE streaming_tracking_policies SET excluded_users='[{\"provider\":\"jellyfin\",\"serverId\":\"server\",\"id\":\"hidden\"}]'", []).unwrap();
        let before: (i64, i64) = conn.query_row("SELECT COUNT(*),SUM(watched_secs) FROM streaming_history", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        drop(conn);
        let all = query_streaming_analytics(0, "all", "all", false, true, 0.0);
        assert_eq!(all.total_plays, 2);
        assert_eq!(all.total_watch_time_secs, 360);
        assert_eq!(all.total_data_used_bytes, 0);
        assert_eq!(all.historical_estimates.len(), 2);
        let item = all.historical_estimates.iter().find(|estimate| estimate.provenance == "item_summary").unwrap();
        assert_eq!((item.records, item.reported_watch_time_secs, item.undated_records), (2, 4200, 1));
        let legacy = all.historical_estimates.iter().find(|estimate| estimate.provenance == "legacy_unverified").unwrap();
        assert_eq!((legacy.records, legacy.reported_watch_time_secs), (2, 3600));
        for estimate in &all.historical_estimates {
            assert_eq!(estimate.time_series.len(), all.time_series.len());
            assert_eq!(estimate.time_series.iter().map(|point| point.watch_time_secs).sum::<i64>(), 3600);
            assert!(estimate.time_series.iter().any(|point| point.date == old[..10] && point.watch_time_secs == 3600));
            assert!(estimate.time_series.iter().all(|point| point.data_used_bytes == 0 && point.direct_play_count == 0));
        }
        assert!(all.time_series.first().unwrap().date <= old[..10].to_string());
        assert!(query_streaming_analytics(7, "all", "all", false, true, 0.0).historical_estimates.is_empty());
        assert!(query_streaming_analytics(0, "transcode", "all", false, true, 0.0).historical_estimates.is_empty());
        assert!(query_streaming_analytics(0, "all", "episode", false, true, 0.0).historical_estimates.is_empty());
        assert!(query_streaming_analytics(0, "all", "all", true, true, 0.0).historical_estimates.is_empty());
        let conn = af_db::get_conn().unwrap();
        let after: (i64, i64) = conn.query_row("SELECT COUNT(*),SUM(watched_secs) FROM streaming_history", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!(before, after);
        conn.execute("UPDATE streaming_tracking_policies SET minimum_watch_secs=180", []).unwrap();
        drop(conn);
        let threshold = query_streaming_analytics(0, "all", "all", false, true, 0.0);
        assert_eq!(threshold.total_plays, 1);
        assert_eq!(threshold.total_watch_time_secs, 240);
        assert_eq!(threshold.historical_estimates[0].records, 2);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_streaming_distinct_elapsed_accounting_and_disable() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = init_isolated_streaming_db("elapsed_accounting");
        let session = ActiveStreamSession { session_id: "elapsed".into(), item_id: "movie".into(), state: "playing".into(), bitrate_bps: 8_000_000, ..Default::default() };
        record_live_sessions_snapshot("jellyfin", &[session.clone()], 15);
        record_live_sessions_snapshot("jellyfin", &[session.clone()], 15);
        let conn = af_db::get_conn().unwrap();
        assert_eq!(conn.query_row("SELECT watched_secs FROM streaming_history", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM streaming_bandwidth_samples", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
        conn.execute("UPDATE streaming_session_samples SET sampled_at=CAST(strftime('%s','now') AS INTEGER)-15", []).unwrap();
        drop(conn);
        record_live_sessions_snapshot("jellyfin", &[session.clone()], 15);
        let conn = af_db::get_conn().unwrap();
        assert_eq!(conn.query_row("SELECT watched_secs,data_used_bytes FROM streaming_history", [], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))).unwrap(), (15,15_000_000));
        conn.execute("DELETE FROM streaming_session_samples", []).unwrap();
        conn.execute("INSERT INTO streaming_session_samples SELECT id,CAST(strftime('%s','now') AS INTEGER)-600,15,1,8000000 FROM streaming_history", []).unwrap();
        drop(conn);
        record_live_sessions_snapshot("jellyfin", &[session], 15);
        let conn = af_db::get_conn().unwrap();
        assert_eq!(conn.query_row("SELECT watched_secs FROM streaming_history", [], |row| row.get::<_, i64>(0)).unwrap(), 15);
        conn.execute("UPDATE streaming_servers SET enabled=0 WHERE provider='jellyfin'", []).unwrap();
        drop(conn);
        close_disabled_provider("jellyfin");
        let conn = af_db::get_conn().unwrap();
        assert_eq!(conn.query_row("SELECT is_active,ended_at IS NULL FROM streaming_history", [], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?))).unwrap(), (0,true));
        drop(conn);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[tokio::test]
    async fn test_streaming_pinned_cached_degraded_telemetry_and_artwork_denial() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = init_isolated_streaming_db("pinned_degraded");
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let router = axum::Router::new()
            .route("/System/Info", axum::routing::get(move || { let observed = observed.clone(); async move { observed.fetch_add(1, Ordering::SeqCst); Json(serde_json::json!({"Id":"saved","ServerName":"Synthetic"})) } }))
            .route("/Items/Counts", axum::routing::get(|| async { Json(serde_json::json!({})) }))
            .route("/Sessions", axum::routing::get(|| async { StatusCode::SERVICE_UNAVAILABLE }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        af_db::get_conn().unwrap().execute("INSERT OR REPLACE INTO streaming_servers(provider,name,url,api_key,server_id,enabled) VALUES('jellyfin','Synthetic',?1,'fixture-key','saved',1)", [&url]).unwrap();
        assert!(cached_provider_telemetry("jellyfin").await.is_err());
        assert!(cached_provider_telemetry("jellyfin").await.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        af_db::get_conn().unwrap().execute("UPDATE streaming_servers SET server_id='original' WHERE provider='jellyfin'", []).unwrap();
        assert!(test_jellyfin_connection(&url, "fixture-key").await.is_err());
        assert_eq!(af_db::get_conn().unwrap().query_row("SELECT server_id FROM streaming_servers WHERE provider='jellyfin'", [], |row| row.get::<_, String>(0)).unwrap(), "original");
        let viewer = AuthUser { user_id:1, username:"viewer".into(),role:"user".into(),jti:"fixture".into(),plugin_id:None,plugin_scopes:vec![] };
        let response = get_streaming_artwork(Extension(viewer), Path("unknown-item".into()), Query(HashMap::from([("provider".into(),"jellyfin".into())]))).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(count.load(Ordering::SeqCst), 2);
        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[tokio::test]
    async fn test_streaming_json_body_exact_cap_and_overflow() {
        let router = axum::Router::new().route("/exact", axum::routing::get(|| async { "12345678" })).route("/large", axum::routing::get(|| async { "123456789" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        let exact = do_jellyfin_request(reqwest::Method::GET, &format!("{base}/exact"), "", None, Duration::from_secs(2), 8).await.unwrap();
        assert_eq!(exact.0, b"12345678");
        assert!(do_jellyfin_request(reqwest::Method::GET, &format!("{base}/large"), "", None, Duration::from_secs(2), 8).await.is_err());
        server.abort();
        let _ = server.await;
    }

    fn init_isolated_streaming_db(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "af_streaming_test_{}_{}_{}",
            name,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("aetherflow_test.sqlite");
        std::env::set_var("DB_PATH", &db_path);
        std::env::remove_var("AETHERFLOW_DEMO_MODE");
        af_services::set_streaming_demo_mode(false);
        af_db::init_db().expect("init isolated test sqlite db");
        db_path
    }

    #[test]
    fn test_monitor_identity_cold_start_and_stale_source_refuse_writes() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _path = init_isolated_streaming_db("monitor_identity");
        let conn = af_db::get_conn().unwrap();
        conn.execute("INSERT OR REPLACE INTO streaming_servers(provider,name,url,server_id,enabled) VALUES ('jellyfin','Test','http://127.0.0.1:8096','',1)", []).unwrap();
        assert!(persist_verified_monitor_source(&conn, "jellyfin", "http://127.0.0.1:8096", "").is_err());
        assert_eq!(persist_verified_monitor_source(&conn, "jellyfin", "http://127.0.0.1:8096/", "Server-Verified").unwrap(), "Server-Verified");
        assert_eq!(persist_verified_monitor_source(&conn, "jellyfin", "http://127.0.0.1:8096", "server-verified").unwrap(), "Server-Verified");
        assert!(persist_verified_monitor_source(&conn, "jellyfin", "http://127.0.0.1:8096", "different-server").is_err());
        assert!(persist_verified_monitor_source(&conn, "jellyfin", "http://127.0.0.1:9999", "Server-Verified").is_err());
        let session = ActiveStreamSession { session_id: "source-session".to_string(), item_id: "source-item".to_string(), item_name: "Source item".to_string(), ..Default::default() };
        drop(conn);
        record_live_sessions_snapshot_for_source("jellyfin", &[session.clone()], 15, Some(("http://127.0.0.1:8096", "different-server")));
        let conn = af_db::get_conn().unwrap();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
        drop(conn);
        record_live_sessions_snapshot_for_source("jellyfin", &[session.clone()], 15, Some(("http://127.0.0.1:8096", "Server-Verified")));
        let conn = af_db::get_conn().unwrap();
        assert_eq!(conn.query_row("SELECT server_id FROM streaming_history", [], |row| row.get::<_, String>(0)).unwrap(), "Server-Verified");
        conn.execute("UPDATE streaming_servers SET enabled=0 WHERE provider='jellyfin'", []).unwrap();
        assert!(persist_verified_monitor_source(&conn, "jellyfin", "http://127.0.0.1:8096", "Server-Verified").is_err());
        let revision: i64 = conn.query_row("SELECT revision FROM streaming_history_revision WHERE id=1", [], |row| row.get(0)).unwrap();
        drop(conn);
        record_live_sessions_snapshot_for_source("jellyfin", &[], 15, Some(("http://127.0.0.1:8096", "Server-Verified")));
        let conn = af_db::get_conn().unwrap();
        assert_eq!(conn.query_row("SELECT revision FROM streaming_history_revision WHERE id=1", [], |row| row.get::<_, i64>(0)).unwrap(), revision);
    }

    #[test]
    fn test_unrecorded_capabilities_deny_commands_and_messages() {
        let unknown = JellyfinSessionRaw::default();
        let (media, remote, message, commands) = resolve_session_capabilities(&unknown);
        assert!(!media);
        assert!(!remote);
        assert!(!message);
        assert!(commands.is_empty());
        let controlled = JellyfinSessionRaw { supports_media_control: Some(true), ..Default::default() };
        assert!(!resolve_session_capabilities(&controlled).2);
    }

    #[tokio::test]
    async fn test_nonadmin_dashboard_withholds_unscoped_legacy_cohorts() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("dashboard_private_scope");
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute("UPDATE streaming_servers SET enabled = 0", []).unwrap();
            conn.execute("INSERT INTO streaming_history(session_key,user_id,user_name,item_id,item_name,watched_secs,data_used_bytes) VALUES('private-session','another-user','Private Person','private-item','Private Title',900,123456)", []).unwrap();
        }
        let mut request = Request::new(Body::empty());
        request.extensions_mut().insert(AuthUser {
            user_id: 1, username: "unlinked".into(), role: "user".into(), jti: "test".into(), plugin_id: None, plugin_scopes: vec![],
        });
        let response = get_streaming_dashboard_handler(Query(HashMap::new()), request).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!text.contains("Private Person"));
        assert!(!text.contains("Private Title"));
        assert!(!text.contains("private-session"));
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["analytics"]["totalPlays"], 0);
        assert_eq!(json["analytics"]["totalWatchTimeSecs"], 0);
        assert!(json["activeSessions"].as_array().unwrap().is_empty());
        assert!(json["analytics"]["topUsers"].as_array().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[tokio::test]
    async fn test_streaming_dashboard_contract_filters_and_redaction() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("contract_filters");

        // 1. Verify empty state contract (empty arrays [], coming_soon statuses, zero metrics)
        let empty_resp = build_streaming_dashboard("30", "all", "all", false).await;
        let empty_json = serde_json::to_value(&empty_resp).expect("serialize empty dashboard");

        assert!(empty_json.get("activeSessions").unwrap().is_array());
        assert_eq!(empty_json["activeSessions"].as_array().unwrap().len(), 0);
        assert!(empty_json.get("liveSessions").is_none());
        assert!(empty_json.get("updatedAt").unwrap().is_string());
        assert!(empty_json.get("generatedAt").is_none());

        let servers = empty_json["servers"].as_array().expect("servers array");
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0]["provider"], "jellyfin");
        assert_eq!(servers[0]["status"], "unconfigured");
        assert_eq!(servers[1]["provider"], "plex");
        assert_eq!(servers[1]["status"], "coming_soon");
        assert_eq!(servers[1]["supportStage"], "coming_soon");
        assert_eq!(servers[2]["provider"], "emby");
        assert_eq!(servers[2]["status"], "coming_soon");
        assert_eq!(servers[2]["supportStage"], "coming_soon");

        let empty_analytics = &empty_json["analytics"];
        assert_eq!(empty_analytics["windowDays"], 30);
        assert_eq!(empty_analytics["totalPlays"], 0);
        assert_eq!(empty_analytics["totalWatchTimeSecs"], 0);
        assert_eq!(empty_analytics["totalDataUsedBytes"], 0);
        assert!(empty_analytics.get("totalWatchedSecs").is_none());
        assert!(empty_analytics.get("totalDataBytes").is_none());
        assert!(empty_analytics["mediaTypeBreakdown"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(empty_analytics["resolutionBreakdown"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(empty_analytics["codecBreakdown"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(empty_analytics["topUsers"].as_array().unwrap().is_empty());
        assert!(empty_analytics["topTitles"].as_array().unwrap().is_empty());
        assert!(empty_analytics["recentHistory"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(empty_analytics["timeSeries"].as_array().unwrap().len(), 31);

        // 2. Seed realistic production-shaped Jellyfin history rows + bandwidth sample + server config
        let now = Utc::now();
        let recent_ts = (now - chrono::Duration::days(2))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let older_ts = (now - chrono::Duration::days(20))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        {
            let conn = af_db::get_conn().expect("db conn");
            let enc_key = af_db::encrypt_key("abcdef1234567890").unwrap_or_default();
            conn.execute(
                "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Vault Jellyfin', 'http://127.0.0.1:1', ?1, 1)",
                params![enc_key],
            )
            .unwrap();

            // Row 1: DirectPlay Movie 2 days ago (24.5 Mbps)
            conn.execute(
                r#"
                INSERT INTO streaming_history (
                    session_key, provider, server_name, user_id, user_name,
                    client_name, device_name, ip_address,
                    item_id, item_name, item_type, series_name,
                    season_number, episode_number, production_year,
                    play_method, container, video_codec, video_resolution,
                    audio_codec, audio_channels, hw_accel, bitrate_bps,
                    duration_secs, watched_secs, data_used_bytes, completion_pct,
                    started_at, last_seen_at, ended_at, is_active
                ) VALUES (
                    'jf:sess:1', 'jellyfin', 'Vault Jellyfin', 'u1', 'alice',
                    'Jellyfin Media Player', 'Apple TV', '192.168.1.50',
                    'item-1', 'Oppenheimer', 'Movie', '',
                    0, 0, 2023,
                    'DirectPlay', 'MKV', 'HEVC', '4K UHD',
                    'TRUEHD', 8, '', 24500000,
                    10800, 10800, 33075000000, 100.0,
                    ?1, ?1, ?1, 0
                )
                "#,
                params![recent_ts],
            )
            .unwrap();

            // Row 2: Transcode Episode 20 days ago (8.4 Mbps)
            conn.execute(
                r#"
                INSERT INTO streaming_history (
                    session_key, provider, server_name, user_id, user_name,
                    client_name, device_name, ip_address,
                    item_id, item_name, item_type, series_name,
                    season_number, episode_number, production_year,
                    play_method, container, video_codec, video_resolution,
                    audio_codec, audio_channels, hw_accel, bitrate_bps,
                    duration_secs, watched_secs, data_used_bytes, completion_pct,
                    started_at, last_seen_at, ended_at, is_active
                ) VALUES (
                    'jf:sess:2', 'jellyfin', 'Vault Jellyfin', 'u2', 'bob',
                    'Swiftfin', 'iPhone 16', '172.56.10.22',
                    'item-2', 'Hello, Ms. Cobel', 'Episode', 'Severance',
                    1, 1, 2022,
                    'Transcode', 'TS', 'H264', '1080p FHD',
                    'AAC', 2, 'NVENC', 8400000,
                    3300, 1650, 1732500000, 50.0,
                    ?1, ?1, ?1, 0
                )
                "#,
                params![older_ts],
            )
            .unwrap();

            // Bandwidth sample with higher concurrent bitrate (42.0 Mbps)
            conn.execute(
                r#"
                INSERT INTO streaming_bandwidth_samples (
                    provider, timestamp, active_streams, direct_play_count, direct_stream_count, transcode_count, total_bitrate_bps, bytes_delta
                ) VALUES (
                    'jellyfin', ?1, 2, 1, 0, 1, 42000000, 78750000
                )
                "#,
                params![recent_ts],
            )
            .unwrap();
        }

        // 3. Admin query over 30-day window
        mark_dashboard_fixtures_as_observed();
        let admin_resp = build_streaming_dashboard("30", "all", "all", true).await;
        let admin_json = serde_json::to_value(&admin_resp).expect("serialize admin dashboard");

        // Unreachable Jellyfin status (port 1 fails connection) and masked API key for admin
        let jf_srv = &admin_json["servers"][0];
        assert_eq!(jf_srv["status"], "unavailable");
        assert_eq!(jf_srv["apiKeyMasked"], "****7890");

        let an = &admin_json["analytics"];
        assert_eq!(an["totalPlays"], 2);
        assert_eq!(an["totalWatchTimeSecs"], 12450);
        assert_eq!(an["totalDataUsedBytes"], 34807500000i64);
        assert_eq!(an["uniqueUsers"], 2);
        assert_eq!(an["uniqueTitles"], 2);
        assert_eq!(an["avgCompletionPct"], 75.0);
        assert_eq!(an["peakBandwidthMbps"], 42.0);

        let st = &an["streamTypes"];
        assert_eq!(st["directPlayCount"], 1);
        assert_eq!(st["directStreamCount"], 0);
        assert_eq!(st["transcodeCount"], 1);
        assert_eq!(st["directPlayPct"], 50.0);
        assert_eq!(st["transcodePct"], 50.0);
        assert!(st.get("directPlay").is_none());

        // Breakdown entries must have label, count, pct, watchTimeSecs, dataUsedBytes
        let mt_bd = an["mediaTypeBreakdown"].as_array().unwrap();
        assert_eq!(mt_bd.len(), 2);
        assert!(mt_bd[0].get("pct").is_some());
        assert!(mt_bd[0].get("watchTimeSecs").is_some());
        assert!(mt_bd[0].get("dataUsedBytes").is_some());
        assert!(mt_bd[0].get("percentage").is_none());

        // TimeSeries points must have date, plays, watchTimeSecs, dataUsedBytes, peakBandwidthMbps, directPlayCount, directStreamCount, transcodeCount
        let ts_arr = an["timeSeries"].as_array().unwrap();
        assert_eq!(ts_arr.len(), 31);
        let sample_pt = &ts_arr[0];
        assert!(sample_pt.get("date").unwrap().is_string());
        assert!(sample_pt.get("watchTimeSecs").is_some());
        assert!(sample_pt.get("dataUsedBytes").is_some());
        assert!(sample_pt.get("peakBandwidthMbps").is_some());
        assert!(sample_pt.get("directPlayCount").is_some());
        assert!(sample_pt.get("directStreamCount").is_some());
        assert!(sample_pt.get("transcodeCount").is_some());

        // Top users and top titles field names
        let top_users = an["topUsers"].as_array().unwrap();
        assert_eq!(top_users.len(), 2);
        assert_eq!(top_users[0]["userName"], "alice");
        assert_eq!(top_users[0]["totalWatchSecs"], 10800);
        assert_eq!(top_users[0]["totalDataBytes"], 33075000000i64);
        assert_eq!(top_users[0]["uniqueItems"], 1);
        assert_eq!(top_users[0]["directPlayCount"], 1);
        assert_eq!(
            top_users[0]["lastDevice"],
            "Jellyfin Media Player · Apple TV"
        );
        assert!(!top_users[0]["lastSeenAt"].as_str().unwrap().is_empty());

        let top_titles = an["topTitles"].as_array().unwrap();
        assert_eq!(top_titles.len(), 2);
        assert!(top_titles[0].get("uniqueViewers").is_some());
        assert!(top_titles[0].get("totalWatchSecs").is_some());
        assert!(top_titles[0].get("totalDataBytes").is_some());
        assert!(top_titles[0].get("lastWatchedAt").is_some());

        // History items must include sessionKey, bandwidthMbps, lastSeenAt, and IP for admin
        let hist = an["recentHistory"].as_array().unwrap();
        assert_eq!(hist.len(), 2);
        assert_eq!(hist[0]["sessionKey"], "jf:sess:1");
        assert_eq!(hist[0]["bandwidthMbps"], 24.5);
        assert_eq!(hist[0]["ipAddress"], "192.168.1.50");
        assert!(!hist[0]["lastSeenAt"].as_str().unwrap().is_empty());
        assert_eq!(hist[1]["sessionKey"], "jf:sess:2");
        assert_eq!(hist[1]["bandwidthMbps"], 8.4);

        // 4. Non-admin redaction check
        mark_dashboard_fixtures_as_observed();
        let non_admin_resp = build_streaming_dashboard("30", "all", "all", false).await;
        assert_eq!(non_admin_resp.servers[0].api_key_masked, "");
        assert_eq!(non_admin_resp.analytics.recent_history[0].ip_address, "");
        assert_eq!(non_admin_resp.analytics.recent_history[1].ip_address, "");

        // 5. Filter checks: window=7 excludes the 20-day-old row
        mark_dashboard_fixtures_as_observed();
        let win7_resp = build_streaming_dashboard("7", "all", "all", true).await;
        assert_eq!(win7_resp.analytics.window_days, 7);
        assert_eq!(win7_resp.analytics.total_plays, 1);
        assert_eq!(win7_resp.analytics.recent_history.len(), 1);
        assert_eq!(
            win7_resp.analytics.recent_history[0].item_name,
            "Oppenheimer"
        );

        // playMethod=Transcode filter
        mark_dashboard_fixtures_as_observed();
        let tc_resp = build_streaming_dashboard("30", "Transcode", "all", true).await;
        assert_eq!(tc_resp.analytics.total_plays, 1);
        assert_eq!(tc_resp.analytics.recent_history.len(), 1);
        assert_eq!(tc_resp.analytics.recent_history[0].play_method, "Transcode");

        // mediaType=Movie filter
        mark_dashboard_fixtures_as_observed();
        let movie_resp = build_streaming_dashboard("30", "all", "Movie", true).await;
        assert_eq!(movie_resp.analytics.total_plays, 1);
        assert_eq!(movie_resp.analytics.recent_history.len(), 1);
        assert_eq!(movie_resp.analytics.recent_history[0].item_type, "Movie");

        // Let the frontend contract test render actual Rust responses, including
        // both empty history and populated live session cards.
        if let Some(path) = std::env::var_os("AF_STREAMING_CONTRACT_FIXTURE") {
            {
                let conn = af_db::get_conn().unwrap();
                conn.execute("UPDATE streaming_servers SET enabled = 0", [])
                    .unwrap();
            }
            af_services::set_streaming_demo_mode(true);
            let sessions_resp = build_streaming_dashboard("30", "all", "all", true).await;
            assert!(!sessions_resp.active_sessions.is_empty());
            af_services::set_streaming_demo_mode(false);
            let fixtures = serde_json::json!({
                "empty": empty_json,
                "populated": admin_json,
                "sessions": sessions_resp,
            });
            std::fs::write(path, serde_json::to_vec_pretty(&fixtures).unwrap()).unwrap();
        }

        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[tokio::test]
    async fn test_watch_history_sync_does_not_fabricate_metadata_bytes_or_now_timestamps() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("sync_truth");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock jellyfin");
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req_str.lines().next().unwrap_or("");

                    let body = if first_line.contains("GET /System/Info/Public") {
                        serde_json::json!({"Id":"mock-summary-server"}).to_string()
                    } else if first_line.contains("GET /Users ")
                        || first_line.contains("GET /Users?")
                    {
                        serde_json::json!([
                            { "Id": "user-1", "Name": "diana" }
                        ])
                        .to_string()
                    } else if first_line.contains("Filters=IsPlayed") {
                        serde_json::json!({
                            "TotalRecordCount": 2,
                            "Items": [
                                {
                                    "Id": "item-known",
                                    "Name": "Arrival",
                                    "Type": "Movie",
                                    "ProductionYear": 2016,
                                    "RunTimeTicks": 69_600_000_000i64,
                                    "Container": "mkv",
                                    "Bitrate": 16_000_000i64,
                                    "Width": 3840,
                                    "Height": 2160,
                                    "MediaStreams": [
                                        { "Type": "Video", "Codec": "hevc", "Width": 3840, "Height": 2160, "BitRate": 15_000_000 },
                                        { "Type": "Audio", "Codec": "dts", "Channels": 6, "BitRate": 1_000_000 }
                                    ],
                                    "UserData": {
                                        "Played": true,
                                        "PlaybackPositionTicks": 0,
                                        "PlayedPercentage": 100.0,
                                        "LastPlayedDate": "2026-10-15T18:30:00Z"
                                    }
                                },
                                {
                                    "Id": "item-unknown-meta",
                                    "Name": "Mystery Track",
                                    "Type": "Audio",
                                    "RunTimeTicks": 0,
                                    "Container": "",
                                    "Bitrate": 0,
                                    "Width": 0,
                                    "Height": 0,
                                    "MediaStreams": [],
                                    "UserData": {
                                        "Played": true,
                                        "PlaybackPositionTicks": 0,
                                        "PlayedPercentage": 0.0,
                                        "LastPlayedDate": ""
                                    }
                                }
                            ]
                        })
                        .to_string()
                    } else {
                        serde_json::json!({
                            "TotalRecordCount": 0,
                            "Items": []
                        })
                        .to_string()
                    };

                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        {
            let conn = af_db::get_conn().expect("db conn");
            let enc_key = af_db::encrypt_key("test-sync-api-key-9999").unwrap_or_default();
            conn.execute(
                "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Mock Jellyfin', ?1, ?2, 1)",
                params![format!("http://{}", addr), enc_key],
            )
            .unwrap();
        }

        let imported = sync_jellyfin_watch_history()
            .await
            .expect("sync watch history");
        assert_eq!(imported, 2);

        let conn = af_db::get_conn().expect("db conn");
        let (
            client1,
            device1,
            ip1,
            method1,
            v_codec1,
            v_res1,
            a_codec1,
            a_ch1,
            br1,
            dur1,
            watched1,
            bytes1,
            started1,
        ): (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            i32,
            i64,
            i64,
            i64,
            i64,
            String,
        ) = conn
            .query_row(
                r#"
                SELECT client_name, device_name, ip_address, play_method,
                       video_codec, video_resolution, audio_codec, audio_channels,
                       bitrate_bps, duration_secs, watched_secs, data_used_bytes, started_at
                FROM streaming_history
                WHERE provenance = 'item_summary' AND user_id = 'user-1' AND item_id = 'item-known'
                "#,
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                        r.get(11)?,
                        r.get(12)?,
                    ))
                },
            )
            .expect("known item row");

        // Known source metadata is retained, while unmeasured playback fields remain empty/zero
        assert_eq!(client1, "");
        assert_eq!(device1, "");
        assert_eq!(ip1, "");
        assert_eq!(method1, "");
        assert_eq!(v_codec1, "HEVC");
        assert_eq!(v_res1, "4K UHD");
        assert_eq!(a_codec1, "DTS");
        assert_eq!(a_ch1, 6);
        assert_eq!(br1, 16_000_000);
        assert_eq!(dur1, 6960);
        assert_eq!(watched1, 6960);
        assert_eq!(bytes1, 0);
        assert_eq!(started1, "2026-10-15 18:30:00");

        let (
            client2,
            device2,
            ip2,
            method2,
            v_codec2,
            v_res2,
            a_codec2,
            a_ch2,
            br2,
            dur2,
            watched2,
            bytes2,
            started2,
        ): (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            i32,
            i64,
            i64,
            i64,
            i64,
            String,
        ) = conn
            .query_row(
                r#"
                SELECT client_name, device_name, ip_address, play_method,
                       video_codec, video_resolution, audio_codec, audio_channels,
                       bitrate_bps, duration_secs, watched_secs, data_used_bytes, started_at
                FROM streaming_history
                WHERE provenance = 'item_summary' AND user_id = 'user-1' AND item_id = 'item-unknown-meta'
                "#,
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                        r.get(11)?,
                        r.get(12)?,
                    ))
                },
            )
            .expect("unknown meta item row");

        // Missing source metadata and missing LastPlayedDate must NOT fabricate 2700s, 8Mbps, HEVC/EAC3/1080p, or today's timestamp
        assert_eq!(client2, "");
        assert_eq!(device2, "");
        assert_eq!(ip2, "");
        assert_eq!(method2, "");
        assert_eq!(v_codec2, "");
        assert_eq!(v_res2, "");
        assert_eq!(a_codec2, "");
        assert_eq!(a_ch2, 0);
        assert_eq!(br2, 0);
        assert_eq!(dur2, 0);
        assert_eq!(watched2, 0);
        assert_eq!(bytes2, 0);
        assert_eq!(started2, "");

        drop(conn);

        // Verify 7-day window does NOT include the dateless imported row or the 2026-10-15 row
        let win7 = query_streaming_analytics(7, "all", "all", false, true, 0.0);
        assert_eq!(win7.total_plays, 0);

        // Item summaries remain raw evidence, not confirmed dashboard playback events.
        let all_time = query_streaming_analytics(0, "all", "all", false, true, 0.0);
        assert_eq!(all_time.window_days, 0);
        assert_eq!(all_time.total_plays, 0);
        assert_eq!(all_time.stream_types.direct_play_count, 0);
        assert_eq!(all_time.stream_types.direct_play_pct, 0.0);

        {
            let conn = af_db::get_conn().unwrap();
            conn.execute("UPDATE streaming_history SET timestamp_certainty = 'unrecorded' WHERE item_id = 'item-known'", []).unwrap();
        }
        assert_eq!(sync_jellyfin_watch_history().await.unwrap(), 1);
        {
            let conn = af_db::get_conn().unwrap();
            let certainty: String = conn.query_row("SELECT timestamp_certainty FROM streaming_history WHERE item_id = 'item-known'", [], |row| row.get(0)).unwrap();
            assert_eq!(certainty, "last_played");
            conn.execute("UPDATE streaming_history SET provenance = 'legacy_unverified', item_name = 'Preserved legacy' WHERE item_id = 'item-known'", []).unwrap();
        }
        assert_eq!(sync_jellyfin_watch_history().await.unwrap(), 0);
        {
            let conn = af_db::get_conn().unwrap();
            let title: String = conn.query_row("SELECT item_name FROM streaming_history WHERE item_id = 'item-known'", [], |row| row.get(0)).unwrap();
            assert_eq!(title, "Preserved legacy");
            conn.execute("UPDATE streaming_servers SET server_id = 'replacement-server' WHERE provider = 'jellyfin'", []).unwrap();
        }
        assert!(sync_jellyfin_watch_history().await.is_err());
        {
            let conn = af_db::get_conn().unwrap();
            let records: i64 = conn.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| row.get(0)).unwrap();
            assert_eq!(records, 2);
            let records: i64 = conn.query_row("SELECT COUNT(*) FROM streaming_history WHERE server_id = 'replacement-server' AND provenance = 'item_summary'", [], |row| row.get(0)).unwrap();
            assert_eq!(records, 0);
        }
        server_handle.abort();

        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[tokio::test]
    async fn test_live_session_interleaved_snapshots_seek_resume_and_paused_accounting() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("live_interleaved");

        // Session A: user resumes a movie at 1h30m (position_secs = 5400), initially PAUSED
        let mut sess = ActiveStreamSession {
            session_id: "sess-live-1".to_string(),
            provider: "jellyfin".to_string(),
            server_name: "Vault Jellyfin".to_string(),
            user_id: "u-live".to_string(),
            user_name: "marco".to_string(),
            client_name: "Jellyfin Web".to_string(),
            device_name: "Chrome".to_string(),
            device_id: "dev-chrome".to_string(),
            app_version: "10.10.6".to_string(),
            ip_address: "192.168.1.77".to_string(),
            is_lan: true,
            item_id: "item-movie-resume".to_string(),
            item_name: "Interstellar".to_string(),
            item_type: "Movie".to_string(),
            position_secs: 5400, // Resumed at 90 minutes!
            duration_secs: 10000,
            progress_pct: 54.0,
            state: "paused".to_string(),
            play_method: "DirectPlay".to_string(),
            container: "MKV".to_string(),
            video_codec: "HEVC".to_string(),
            video_resolution: "4K UHD".to_string(),
            audio_codec: "EAC3".to_string(),
            audio_channels: 6,
            bitrate_bps: 16_000_000, // 2,000,000 bytes/sec
            bandwidth_mbps: 0.0,
            session_data_bytes: 0,
            supports_media_control: true,
            supports_remote_control: true,
            can_send_message: true,
            ..Default::default()
        };

        let expected_key =
            format_observed_session_key("jellyfin", "", "sess-live-1", "", "item-movie-resume", 1);

        // 1. First observation: dashboard poll (interval = 0) while paused at 5400s
        record_live_sessions_snapshot("jellyfin", &[sess.clone()], 0);
        // 2. Monitor poll (interval = 15) while still paused at 5400s -> must NOT charge bytes or watch time
        record_live_sessions_snapshot("jellyfin", &[sess.clone()], 15);

        {
            let conn = af_db::get_conn().unwrap();
            let (watched, bytes, active): (i64, i64, i32) = conn
                .query_row(
                    "SELECT watched_secs, data_used_bytes, is_active FROM streaming_history WHERE session_key = ?1",
                    params![expected_key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            assert_eq!(watched, 0);
            assert_eq!(bytes, 0);
            assert_eq!(active, 1);
        }

        // 3. User unpauses (state = "playing") and seeks ahead to 7200s (2 hours).
        // Dashboard refreshes twice (interval = 0) before the 15s monitor fires.
        sess.state = "playing".to_string();
        sess.position_secs = 7200;
        sess.progress_pct = 72.0;
        sess.bandwidth_mbps = 16.0;
        record_live_sessions_snapshot("jellyfin", &[sess.clone()], 0);
        record_live_sessions_snapshot("jellyfin", &[sess.clone()], 0);

        {
            let conn = af_db::get_conn().unwrap();
            let (watched, bytes): (i64, i64) = conn
                .query_row(
                    "SELECT watched_secs, data_used_bytes FROM streaming_history WHERE session_key = ?1",
                    params![expected_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            // Zero-interval dashboard refreshes must not accrue or reset anything
            assert_eq!(watched, 0);
            assert_eq!(bytes, 0);
        }

        // 4. Background monitor fires once (interval = 15s) -> accrues exactly 15s and 30,000,000 bytes (15s * 2MB/s), NOT 7200s * 2MB/s!
        record_live_sessions_snapshot("jellyfin", &[sess.clone()], 15);

        // 5. Interleaved dashboard poll (interval = 0) and second monitor tick (interval = 15s)
        record_live_sessions_snapshot("jellyfin", &[sess.clone()], 0);
        sess.position_secs = 7230;
        record_live_sessions_snapshot("jellyfin", &[sess.clone()], 15);
        record_live_sessions_snapshot("jellyfin", &[sess.clone()], 0);

        {
            let conn = af_db::get_conn().unwrap();
            let (watched, bytes): (i64, i64) = conn
                .query_row(
                    "SELECT watched_secs, data_used_bytes FROM streaming_history WHERE session_key = ?1",
                    params![expected_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(watched, 0);
            assert_eq!(bytes, 0);
        }

        // 6. Session ends (empty slice) -> marks session inactive without altering accrued bytes/watch time
        record_live_sessions_snapshot("jellyfin", &[], 15);
        {
            let conn = af_db::get_conn().unwrap();
            let (watched, bytes, active): (i64, i64, i32) = conn
                .query_row(
                    "SELECT watched_secs, data_used_bytes, is_active FROM streaming_history WHERE session_key = ?1",
                    params![expected_key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            assert_eq!(watched, 0);
            assert_eq!(bytes, 0);
            assert_eq!(active, 0);
        }

        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[tokio::test]
    async fn test_watch_history_sync_reports_upstream_item_failures() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("history_sync_failure");
        let app = axum::Router::new()
            .route("/System/Info/Public", axum::routing::get(|| async { Json(serde_json::json!({"Id":"mock-summary-server"})) }))
            .route(
                "/Users",
                axum::routing::get(|| async {
                    Json(serde_json::json!([{ "Id": "viewer", "Name": "Viewer" }]))
                }),
            )
            .route(
                "/Users/:user/Items",
                axum::routing::get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        {
            let conn = af_db::get_conn().unwrap();
            let api_key = af_db::encrypt_key("test-sync-failure-key").unwrap();
            conn.execute(
                "INSERT INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Unavailable History', ?1, ?2, 1)",
                params![server_url, api_key],
            ).unwrap();
        }
        let error = sync_jellyfin_watch_history().await.unwrap_err();
        assert!(error.to_string().contains("503"));
        server.abort();
        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[test]
    fn test_all_time_preserves_older_history_and_reports_bucket_granularity() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("all_time_older_history");
        let now = Utc::now();
        let older_date = (now - chrono::Duration::days(400))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO streaming_history (session_key, started_at, last_seen_at) VALUES ('older-history', ?1, ?1)",
                params![older_date],
            ).unwrap();
        }
        mark_dashboard_fixtures_as_observed();
        let daily = query_streaming_analytics(0, "all", "all", false, true, 0.0);
        assert_eq!(daily.window_days, 0);
        assert_eq!(daily.time_series_granularity, "day");
        assert_eq!(daily.time_series.len(), 401);
        assert_eq!(
            daily
                .time_series
                .iter()
                .map(|point| point.plays)
                .sum::<i32>(),
            daily.total_plays
        );

        let earliest = now
            .date_naive()
            .checked_sub_months(Months::new(144))
            .unwrap();
        let earliest_timestamp = format!("{} 12:00:00", earliest.format("%Y-%m-%d"));
        let earliest_bucket = earliest.with_day(1).unwrap().format("%Y-%m-%d").to_string();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO streaming_history (session_key, started_at, last_seen_at, watched_secs, data_used_bytes) VALUES ('oldest-history', ?1, ?1, 60, 30000000)",
                params![earliest_timestamp],
            ).unwrap();
            conn.execute(
                "INSERT INTO streaming_bandwidth_samples (provider, timestamp, total_bitrate_bps) VALUES ('jellyfin', ?1, 42000000)",
                params![earliest_timestamp],
            ).unwrap();
        }
        mark_dashboard_fixtures_as_observed();
        let monthly = query_streaming_analytics(0, "all", "all", false, true, 0.0);
        assert_eq!(monthly.time_series_granularity, "month");
        assert_eq!(monthly.time_series.len(), 145);
        assert_eq!(
            monthly
                .time_series
                .iter()
                .map(|point| point.plays)
                .sum::<i32>(),
            monthly.total_plays
        );
        let first = monthly.time_series.first().unwrap();
        assert_eq!(first.date, earliest_bucket);
        assert_eq!(first.plays, 1);
        assert_eq!(first.watch_time_secs, 60);
        assert_eq!(first.data_used_bytes, 30000000);
        assert_eq!(first.peak_bandwidth_mbps, 42.0);
        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[test]
    fn test_extreme_all_time_range_uses_bounded_yearly_buckets() {
        let first_day = NaiveDate::from_ymd_opt(1, 1, 1).unwrap();
        let today = NaiveDate::from_ymd_opt(2026, 11, 1).unwrap();
        let (granularity, keys) = streaming_time_buckets(first_day, today);
        assert_eq!(granularity, "year");
        assert_eq!(keys.len(), 2026);
        assert_eq!(keys.first().unwrap(), "0001-01-01");
        assert_eq!(keys.last().unwrap(), "2026-01-01");
    }

    #[test]
    fn test_window_parsing_timeseries_span_and_latest_user_device() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("window_and_leaderboard");

        assert_eq!(parse_window_days("0"), (0, "all"));
        assert_eq!(parse_window_days("all"), (0, "all"));
        assert_eq!(parse_window_days("365"), (365, "365d"));
        assert_eq!(parse_window_days("90d"), (90, "90d"));

        let now = Utc::now();
        let day_120_ago = (now - chrono::Duration::days(120))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let day_2_ago = (now - chrono::Duration::days(2))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let day_2_key = (now - chrono::Duration::days(2))
            .format("%Y-%m-%d")
            .to_string();

        {
            let conn = af_db::get_conn().unwrap();
            // Older row for user "alex" using "Zidoo Player · Z9X" (lexicographically > "Apple TV")
            conn.execute(
                r#"
                INSERT INTO streaming_history (
                    session_key, provider, server_name, user_id, user_name,
                    client_name, device_name, ip_address,
                    item_id, item_name, item_type,
                    play_method, video_codec, video_resolution,
                    bitrate_bps, duration_secs, watched_secs, data_used_bytes, completion_pct,
                    started_at, last_seen_at, ended_at, is_active
                ) VALUES (
                    'jf:old:1', 'jellyfin', 'Vault', 'u-alex', 'alex',
                    'Zidoo Player', 'Z9X', '192.168.1.20',
                    'it-old', 'Old Movie', 'Movie',
                    'DirectPlay', 'HEVC', '4K UHD',
                    20000000, 7200, 7200, 18000000000, 100.0,
                    ?1, ?1, ?1, 0
                )
                "#,
                params![day_120_ago],
            )
            .unwrap();

            // Newer row for user "alex" using "Apple TV · Living Room" (most recent session)
            conn.execute(
                r#"
                INSERT INTO streaming_history (
                    session_key, provider, server_name, user_id, user_name,
                    client_name, device_name, ip_address,
                    item_id, item_name, item_type,
                    play_method, video_codec, video_resolution,
                    bitrate_bps, duration_secs, watched_secs, data_used_bytes, completion_pct,
                    started_at, last_seen_at, ended_at, is_active
                ) VALUES (
                    'jf:new:2', 'jellyfin', 'Vault', 'u-alex', 'alex',
                    'Apple TV', 'Living Room', '192.168.1.21',
                    'it-new', 'New Movie', 'Movie',
                    'DirectPlay', 'HEVC', '4K UHD',
                    15000000, 5400, 5400, 10125000000, 100.0,
                    ?1, ?1, ?1, 0
                )
                "#,
                params![day_2_ago],
            )
            .unwrap();

            // Concurrent bandwidth sample 2 days ago (55.5 Mbps)
            conn.execute(
                r#"
                INSERT INTO streaming_bandwidth_samples (
                    provider, timestamp, active_streams, direct_play_count, direct_stream_count, transcode_count, total_bitrate_bps, bytes_delta
                ) VALUES (
                    'jellyfin', ?1, 3, 3, 0, 0, 55500000, 104062500
                )
                "#,
                params![day_2_ago],
            )
            .unwrap();
        }

        mark_dashboard_fixtures_as_observed();
        let an_365 = query_streaming_analytics(365, "all", "all", false, true, 0.0);
        assert_eq!(an_365.window_days, 365);
        assert_eq!(an_365.time_series.len(), 366);
        assert_eq!(an_365.total_plays, 2);

        // All-time window (0) must preserve window_days = 0 and span back to the 120-day-old play (121 days)
        mark_dashboard_fixtures_as_observed();
        let an_all = query_streaming_analytics(0, "all", "all", false, true, 0.0);
        assert_eq!(an_all.window_days, 0);
        assert_eq!(an_all.total_plays, 2);
        assert_eq!(an_all.time_series.len(), 121);

        // Daily timeSeries point for 2 days ago must reflect the 55.5 Mbps concurrent sample peak
        let pt_day2 = an_all
            .time_series
            .iter()
            .find(|p| p.date == day_2_key)
            .expect("day 2 point in timeSeries");
        assert_eq!(pt_day2.peak_bandwidth_mbps, 55.5);

        // Top users lastDevice must reflect the most recent session ("Apple TV · Living Room"), not lexicographical MAX ("Zidoo Player · Z9X")
        assert_eq!(an_all.top_users.len(), 1);
        assert_eq!(an_all.top_users[0].last_device, "Apple TV · Living Room");

        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[test]
    fn test_unknown_filter_percentages_and_latest_device_respect_the_cohort() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("unknown_and_cohort");
        let now = Utc::now();
        let recent = (now - chrono::Duration::days(2))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let latest = now.format("%Y-%m-%d %H:%M:%S").to_string();
        let old = (now - chrono::Duration::days(10))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO streaming_history (session_key, user_name, play_method, item_type, client_name, started_at, last_seen_at) VALUES ('known', 'alex', ' directplay ', 'Movie', 'Original client', ?1, ?1)",
                params![recent],
            ).unwrap();
            for index in 0..9 {
                let method = match index % 3 {
                    0 => "",
                    1 => "Unknown",
                    _ => "Unavailable",
                };
                conn.execute(
                    "INSERT INTO streaming_history (session_key, user_name, play_method, item_type, started_at, last_seen_at) VALUES (?1, 'alex', ?2, 'Movie', ?3, ?3)",
                    params![format!("jellyfin:sync:{index}"), method, recent],
                ).unwrap();
            }
        }
        mark_dashboard_fixtures_as_observed();
        let all = query_streaming_analytics(7, "all", "all", false, true, 0.0);
        assert_eq!(all.total_plays, 10);
        assert_eq!(all.stream_types.direct_play_count, 1);
        assert_eq!(all.stream_types.direct_play_pct, 10.0);
        mark_dashboard_fixtures_as_observed();
        let unknown = query_streaming_analytics(7, " UnKnOwN ", "movie", false, true, 0.0);
        assert_eq!(unknown.total_plays, 9);
        assert_eq!(unknown.recent_history.len(), 9);
        assert_eq!(unknown.stream_types.direct_play_count, 0);
        assert_eq!(
            unknown
                .time_series
                .iter()
                .map(|point| point.plays)
                .sum::<i32>(),
            9
        );
        assert_eq!(unknown.top_users[0].last_device, "");
        {
            let conn = af_db::get_conn().unwrap();
            for (key, provider, method, media_type, started_at) in [
                (
                    "other-method",
                    "jellyfin",
                    "Transcode",
                    "Movie",
                    latest.as_str(),
                ),
                (
                    "other-media",
                    "jellyfin",
                    "DirectPlay",
                    "Episode",
                    latest.as_str(),
                ),
                ("demo", "demo", "DirectPlay", "Movie", latest.as_str()),
                (
                    "outside-window",
                    "jellyfin",
                    "DirectPlay",
                    "Movie",
                    old.as_str(),
                ),
            ] {
                conn.execute(
                    "INSERT INTO streaming_history (session_key, provider, user_name, play_method, item_type, client_name, started_at, last_seen_at) VALUES (?1, ?2, 'alex', ?3, ?4, ?1, ?5, ?6)",
                    params![key, provider, method, media_type, started_at, latest],
                ).unwrap();
            }
        }
        mark_dashboard_fixtures_as_observed();
        let filtered = query_streaming_analytics(7, "directplay", "movie", false, true, 0.0);
        assert_eq!(filtered.total_plays, 1);
        assert_eq!(filtered.top_users[0].last_device, "Original client");
        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[test]
    fn test_rolling_window_keeps_the_partial_boundary_day() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("rolling_boundary");
        let now = Utc::now();
        let boundary = now - chrono::Duration::days(7) + chrono::Duration::minutes(1);
        let timestamp = boundary.format("%Y-%m-%d %H:%M:%S").to_string();
        let date = boundary.format("%Y-%m-%d").to_string();
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO streaming_history (session_key, started_at, last_seen_at, watched_secs, data_used_bytes) VALUES ('boundary', ?1, ?1, 60, 30000000)",
                params![timestamp],
            ).unwrap();
            conn.execute(
                "INSERT INTO streaming_bandwidth_samples (provider, timestamp, total_bitrate_bps) VALUES ('jellyfin', ?1, 42000000)",
                params![timestamp],
            ).unwrap();
        }
        mark_dashboard_fixtures_as_observed();
        let analytics = query_streaming_analytics(7, "all", "all", false, true, 0.0);
        assert_eq!(analytics.total_plays, 1);
        assert_eq!(analytics.time_series.len(), 8);
        assert_eq!(
            analytics
                .time_series
                .iter()
                .map(|point| point.plays)
                .sum::<i32>(),
            1
        );
        assert_eq!(
            analytics
                .time_series
                .iter()
                .map(|point| point.watch_time_secs)
                .sum::<i64>(),
            60
        );
        assert_eq!(
            analytics
                .time_series
                .iter()
                .map(|point| point.data_used_bytes)
                .sum::<i64>(),
            30000000
        );
        assert_eq!(
            analytics
                .time_series
                .iter()
                .find(|point| point.date == date)
                .unwrap()
                .peak_bandwidth_mbps,
            42.0
        );
        mark_dashboard_fixtures_as_observed();
        let ten_year = query_streaming_analytics(3650, "all", "all", false, true, 0.0);
        assert_eq!(ten_year.window_days, 3650);
        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[test]
    fn test_dashboard_observation_does_not_prune_bandwidth_history() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("pruning");
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT INTO streaming_bandwidth_samples (provider, timestamp) VALUES ('jellyfin', datetime('now', '-91 days'))",
                [],
            ).unwrap();
        }
        record_live_sessions_snapshot("jellyfin", &[], 0);
        let count = || {
            af_db::get_conn()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM streaming_bandwidth_samples",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
        };
        assert_eq!(count(), 1);
        record_live_sessions_snapshot("jellyfin", &[], 15);
        assert_eq!(count(), 0);
        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[tokio::test]
    async fn test_fetch_live_sessions_and_session_command_capabilities() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("live_fetch_and_cmd");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock jellyfin");
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req_str.lines().next().unwrap_or("");

                    let body = if first_line.contains("GET /Sessions") {
                        serde_json::json!([
                            {
                                "Id": "sess-seek",
                                "UserId": "u-1",
                                "UserName": "claire",
                                "Client": "Swiftfin",
                                "DeviceName": "Apple TV",
                                "DeviceId": "atv-1",
                                "ApplicationVersion": "1.2",
                                "LastActivityDate": "2001-01-01T00:00:00Z",
                                "RemoteEndPoint": "192.168.1.99",
                                "SupportsMediaControl": true,
                                "Capabilities": {
                                    "SupportsMediaControl": true,
                                    "SupportedCommands": ["PlayState"]
                                },
                                "PlayState": {
                                    "PositionTicks": 54_000_000_000i64,
                                    "IsPaused": false,
                                    "PlayMethod": "DirectPlay",
                                    "PlaySessionId": "",
                                    "MediaSourceId": "ms-1"
                                },
                                "NowPlayingItem": {
                                    "Id": "item-seek-1",
                                    "Name": "Dune",
                                    "Type": "Movie",
                                    "RunTimeTicks": 90_000_000_000i64,
                                    "Container": "mkv",
                                    "Bitrate": 20_000_000i64,
                                    "Width": 3840,
                                    "Height": 2160,
                                    "MediaStreams": []
                                }
                            },
                            {
                                "Id": "sess-no-ws",
                                "UserId": "u-2",
                                "UserName": "dan",
                                "Client": "Roku",
                                "DeviceName": "Roku Ultra",
                                "DeviceId": "roku-1",
                                "SupportsMediaControl": false,
                                "PlayState": {
                                    "PositionTicks": 10_000_000_000i64,
                                    "IsPaused": false,
                                    "PlayMethod": "DirectPlay"
                                },
                                "NowPlayingItem": {
                                    "Id": "item-audio-1",
                                    "Name": "Track 01",
                                    "Type": "Audio",
                                    "RunTimeTicks": 2_000_000_000i64,
                                    "Container": "flac",
                                    "Bitrate": 0,
                                    "Width": 0,
                                    "Height": 0,
                                    "MediaStreams": []
                                }
                            }
                        ])
                        .to_string()
                    } else {
                        "{}".to_string()
                    };

                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        let server_url = format!("http://{}", addr);
        {
            let conn = af_db::get_conn().unwrap();
            let enc_key = af_db::encrypt_key("test-cmd-key-1234").unwrap_or_default();
            conn.execute(
                "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Mock JF', ?1, ?2, 1)",
                params![server_url, enc_key],
            )
            .unwrap();
        }

        // 1. Fetch live sessions: sess-seek is at 5400s (90m), but no bytes have been tracked in DB yet -> session_data_bytes must be 0, NOT 5400 * 2.5MB
        let live = fetch_jellyfin_live_sessions("Mock JF", &server_url, "test-cmd-key-1234")
            .await
            .expect("fetch live sessions");
        assert_eq!(live.len(), 2);
        assert_eq!(live[0].session_id, "sess-seek");
        assert_eq!(live[0].position_secs, 5400);
        assert_eq!(live[0].session_data_bytes, 0);
        assert_ne!(live[0].started_at, "2001-01-01T00:00:00Z");
        assert!(!live[0].can_send_message); // DisplayMessage not in SupportedCommands

        // Audio session without dimensions/streams must not fabricate H264/AAC/1080p FHD or 4Mbps
        assert_eq!(live[1].session_id, "sess-no-ws");
        assert_eq!(live[1].video_codec, "");
        assert_eq!(live[1].audio_codec, "");
        assert_eq!(live[1].video_resolution, "");
        assert_eq!(live[1].bitrate_bps, 0);

        record_live_sessions_snapshot("jellyfin", &live, 15);
        {
            let conn = af_db::get_conn().unwrap();
            let (watched, bytes): (i64, i64) = conn.query_row("SELECT watched_secs, data_used_bytes FROM streaming_history WHERE item_id = 'item-seek-1' AND provenance = 'observed_session'", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
            assert_eq!((watched, bytes), (0, 0));
            let samples: i64 = conn.query_row("SELECT COUNT(*) FROM streaming_session_samples WHERE observed_secs = 0 AND playing = 1", [], |row| row.get(0)).unwrap();
            assert!(samples > 0);
        }
        record_live_sessions_snapshot("jellyfin", &live, 15);
        {
            let conn = af_db::get_conn().unwrap();
            let seek_key =
                format_observed_session_key("jellyfin", "", "sess-seek", "", "item-seek-1", 1);
            conn.execute(
                "UPDATE streaming_history SET started_at = '2026-10-01 10:00:00' WHERE session_key = ?1",
                params![seek_key],
            ).unwrap();
        }
        let live_after = fetch_jellyfin_live_sessions("Mock JF", &server_url, "test-cmd-key-1234")
            .await
            .expect("fetch live sessions after tick");
        assert_eq!(live_after[0].session_data_bytes, 0);
        assert_eq!(live_after[0].started_at, "2026-10-01 10:00:00");

        // 3. Session command verification: non-existent session, missing DisplayMessage, and SupportsMediaControl=false
        let err_missing = send_jellyfin_session_command("non-existent-id", "pause", "", "")
            .await
            .unwrap_err();
        assert!(err_missing.to_string().contains("not found"));

        let err_no_msg = send_jellyfin_session_command("sess-seek", "message", "Admin", "Hello")
            .await
            .unwrap_err();
        assert!(err_no_msg.to_string().contains("DisplayMessage"));

        let err_no_ws = send_jellyfin_session_command("sess-no-ws", "pause", "", "")
            .await
            .unwrap_err();
        assert!(err_no_ws.to_string().contains("SupportsMediaControl=false"));

        server_handle.abort();
        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[test]
    fn test_observed_session_identity_generations_reconnect_server_and_legacy_isolation() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("observed_identity_generations");

        let colliding_key_g1 = format_observed_session_key(
            "jellyfin",
            "srv-alpha",
            "sess-1",
            "ps-100",
            "item-blade",
            1,
        );
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled, server_id) VALUES ('jellyfin', 'Alpha', 'http://127.0.0.1:8096', 'k', 1, 'srv-alpha')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO streaming_history (session_key, provider, server_id, user_id, user_name, item_id, item_name, watched_secs, data_used_bytes, started_at, last_seen_at, ended_at, is_active, provenance) VALUES ('jellyfin:sess-1:item-blade', 'jellyfin', '', 'u-1', 'nora', 'item-blade', 'Blade Runner', 900, 12000000, '2026-01-01 00:00:00', '2026-01-01 00:15:00', '2026-01-01 00:15:00', 0, 'legacy_unverified')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO streaming_history (session_key, provider, server_id, user_id, user_name, item_id, item_name, watched_secs, data_used_bytes, started_at, last_seen_at, ended_at, is_active, provenance) VALUES (?1, 'jellyfin', 'srv-alpha', 'u-1', 'nora', 'item-blade', 'Blade Runner', 600, 8000000, '2026-01-02 00:00:00', '2026-01-02 00:10:00', '2026-01-02 00:10:00', 0, 'legacy_unverified')",
                params![colliding_key_g1],
            )
            .unwrap();
        }

        let mut s1 = ActiveStreamSession {
            session_id: "sess-1".to_string(),
            play_session_id: "ps-100".to_string(),
            provider: "jellyfin".to_string(),
            server_name: "Alpha".to_string(),
            user_id: "u-1".to_string(),
            user_name: "nora".to_string(),
            client_name: "Infuse".to_string(),
            device_name: "Apple TV".to_string(),
            device_id: "atv-nora".to_string(),
            item_id: "item-blade".to_string(),
            item_name: "Blade Runner".to_string(),
            item_type: "Movie".to_string(),
            state: "playing".to_string(),
            play_method: "DirectPlay".to_string(),
            bitrate_bps: 8_000_000,
            duration_secs: 7000,
            progress_pct: 10.0,
            ..Default::default()
        };

        let rev_before: i64 = af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT revision FROM streaming_history_revision WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        record_live_sessions_snapshot("jellyfin", &[s1.clone()], 0);
        let rev_after_zero: i64 = af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT revision FROM streaming_history_revision WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rev_before, rev_after_zero);

        record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);
        let play1_key = format_observed_session_key(
            "jellyfin",
            "srv-alpha",
            "sess-1",
            "ps-100",
            "item-blade",
            2,
        );
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "UPDATE streaming_history SET started_at = '2026-10-10 12:00:00' WHERE session_key = ?1",
                params![play1_key],
            )
            .unwrap();
            let (legacy_prov1, legacy_watched1): (String, i64) = conn
                .query_row(
                    "SELECT provenance, watched_secs FROM streaming_history WHERE session_key = 'jellyfin:sess-1:item-blade'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(legacy_prov1, "legacy_unverified");
            assert_eq!(legacy_watched1, 900);

            let (legacy_prov2, legacy_watched2): (String, i64) = conn
                .query_row(
                    "SELECT provenance, watched_secs FROM streaming_history WHERE session_key = ?1",
                    params![colliding_key_g1],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(legacy_prov2, "legacy_unverified");
            assert_eq!(legacy_watched2, 600);
        }

        s1.state = "paused".to_string();
        s1.position_secs = 1800;
        record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);
        s1.state = "playing".to_string();
        s1.position_secs = 2400;
        record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);
        record_live_sessions_snapshot("jellyfin", &[s1.clone()], 180);
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "UPDATE streaming_history SET last_seen_at = datetime('now', '-95 seconds') WHERE session_key = ?1",
                params![play1_key],
            )
            .unwrap();
        }
        record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);

        {
            let conn = af_db::get_conn().unwrap();
            let (watched, bytes, started, active, prov): (i64, i64, String, i32, String) = conn
                .query_row(
                    "SELECT watched_secs, data_used_bytes, started_at, is_active, provenance FROM streaming_history WHERE session_key = ?1",
                    params![play1_key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .unwrap();
            assert_eq!(watched, 0);
            assert_eq!(bytes, 0);
            assert_eq!(started, "2026-10-10 12:00:00");
            assert_eq!(active, 1);
            assert_eq!(prov, "observed_session");
        }

        record_live_sessions_snapshot("jellyfin", &[], 15);
        s1.position_secs = 60;
        record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);

        let play2_key = format_observed_session_key(
            "jellyfin",
            "srv-alpha",
            "sess-1",
            "ps-100",
            "item-blade",
            3,
        );
        {
            let conn = af_db::get_conn().unwrap();
            let (w1, act1): (i64, i32) = conn
                .query_row(
                    "SELECT watched_secs, is_active FROM streaming_history WHERE session_key = ?1",
                    params![play1_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(w1, 0);
            assert_eq!(act1, 0);

            let (w2, act2): (i64, i32) = conn
                .query_row(
                    "SELECT watched_secs, is_active FROM streaming_history WHERE session_key = ?1",
                    params![play2_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(w2, 0);
            assert_eq!(act2, 1);

            conn.execute(
                "UPDATE streaming_tracking_policies SET reconnect_window_secs = 60 WHERE id = 1",
                [],
            )
            .unwrap();
        }

        record_live_sessions_snapshot("jellyfin", &[], 15);
        record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);
        {
            let conn = af_db::get_conn().unwrap();
            let (w2, act2): (i64, i32) = conn
                .query_row(
                    "SELECT watched_secs, is_active FROM streaming_history WHERE session_key = ?1",
                    params![play2_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(w2, 0);
            assert_eq!(act2, 1);
        }

        record_live_sessions_snapshot("jellyfin", &[], 15);
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "UPDATE streaming_history SET ended_at = datetime('now', '-120 seconds'), last_seen_at = datetime('now', '-120 seconds') WHERE session_key = ?1",
                params![play2_key],
            )
            .unwrap();
        }
        record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);
        let play3_key = format_observed_session_key(
            "jellyfin",
            "srv-alpha",
            "sess-1",
            "ps-100",
            "item-blade",
            4,
        );
        {
            let conn = af_db::get_conn().unwrap();
            let (w3, act3): (i64, i32) = conn
                .query_row(
                    "SELECT watched_secs, is_active FROM streaming_history WHERE session_key = ?1",
                    params![play3_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(w3, 0);
            assert_eq!(act3, 1);
        }

        let mut s1_new_ps = s1.clone();
        s1_new_ps.play_session_id = "ps-200".to_string();
        let mut s2_concurrent = s1.clone();
        s2_concurrent.session_id = "sess-2".to_string();
        s2_concurrent.play_session_id = "ps-300".to_string();
        record_live_sessions_snapshot("jellyfin", &[s1_new_ps.clone(), s2_concurrent.clone()], 15);

        let ps200_key = format_observed_session_key(
            "jellyfin",
            "srv-alpha",
            "sess-1",
            "ps-200",
            "item-blade",
            1,
        );
        let concurrent_key = format_observed_session_key(
            "jellyfin",
            "srv-alpha",
            "sess-2",
            "ps-300",
            "item-blade",
            1,
        );
        {
            let conn = af_db::get_conn().unwrap();
            let act_old_ps: i32 = conn
                .query_row(
                    "SELECT is_active FROM streaming_history WHERE session_key = ?1",
                    params![play3_key],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(act_old_ps, 0);

            let act_ps200: i32 = conn
                .query_row(
                    "SELECT is_active FROM streaming_history WHERE session_key = ?1",
                    params![ps200_key],
                    |r| r.get(0),
                )
                .unwrap();
            let act_conc: i32 = conn
                .query_row(
                    "SELECT is_active FROM streaming_history WHERE session_key = ?1",
                    params![concurrent_key],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(act_ps200, 1);
            assert_eq!(act_conc, 1);

            conn.execute(
                "UPDATE streaming_servers SET server_id = 'srv-beta' WHERE provider = 'jellyfin'",
                [],
            )
            .unwrap();
        }

        record_live_sessions_snapshot("jellyfin", &[s1_new_ps.clone()], 15);
        let beta_key = format_observed_session_key(
            "jellyfin",
            "srv-beta",
            "sess-1",
            "ps-200",
            "item-blade",
            1,
        );
        {
            let conn = af_db::get_conn().unwrap();
            let act_alpha: i32 = conn
                .query_row(
                    "SELECT is_active FROM streaming_history WHERE session_key = ?1",
                    params![ps200_key],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(act_alpha, 1);

            let (act_beta, srv_beta): (i32, String) = conn
                .query_row(
                    "SELECT is_active, server_id FROM streaming_history WHERE session_key = ?1",
                    params![beta_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(act_beta, 1);
            assert_eq!(srv_beta, "srv-beta");
        }

        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[tokio::test]
    async fn test_emby_server_config_save_guards_and_identity_reset() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("emby_config_guards");

        // 1. Invalid URL rejected
        let bad_url_resp = save_emby_server_configuration(
            "Emby",
            "ftp://emby.local:8096",
            "emby-secret-key-1111",
            true,
        )
        .unwrap_err();
        assert_eq!(bad_url_resp.status(), StatusCode::BAD_REQUEST);

        // 2. Masked key rejected when no existing stored config exists
        let masked_initial_resp =
            save_emby_server_configuration("Emby", "http://127.0.0.1:8096", "****1111", true)
                .unwrap_err();
        assert_eq!(masked_initial_resp.status(), StatusCode::BAD_REQUEST);

        // 3. Valid initial save succeeds and preserves coming_soon support_stage
        let clean_url = save_emby_server_configuration(
            "Primary Emby",
            "http://127.0.0.1:8096/",
            "emby-secret-key-1111",
            false,
        )
        .expect("valid initial emby save");
        assert_eq!(clean_url, "http://127.0.0.1:8096");
        let dash = build_streaming_dashboard("30d", "all", "all", true).await;
        let saved_srv = dash
            .servers
            .iter()
            .find(|s| s.provider == "emby")
            .expect("emby server in dashboard");
        assert_eq!(saved_srv.support_stage, "coming_soon");
        assert_eq!(saved_srv.url, "http://127.0.0.1:8096");
        assert_eq!(saved_srv.api_key_masked, "****1111");

        // Seed verified server identity on the stored Emby row
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "UPDATE streaming_servers SET server_id = 'emby-srv-1', server_version = '4.8.8.0', last_connected_at = datetime('now') WHERE provider = 'emby'",
                [],
            )
            .unwrap();
        }

        // 4. Masked key on the exact same normalized URL preserves both API key and verified identity
        let same_url = save_emby_server_configuration(
            "Primary Emby Renamed",
            "http://127.0.0.1:8096",
            "****1111",
            false,
        )
        .expect("same url masked save");
        assert_eq!(same_url, "http://127.0.0.1:8096");
        {
            let conn = af_db::get_conn().unwrap();
            let (srv_id, srv_ver): (String, String) = conn
                .query_row(
                    "SELECT COALESCE(server_id, ''), COALESCE(server_version, '') FROM streaming_servers WHERE provider = 'emby'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(srv_id, "emby-srv-1");
            assert_eq!(srv_ver, "4.8.8.0");
        }
        let cfg_same = get_stored_emby_config_fail_closed();
        assert_eq!(cfg_same.api_key, "emby-secret-key-1111");

        // 5. Changing URL with masked or empty key is rejected (prevents exfiltrating stored key to a new host)
        let url_change_masked_resp = save_emby_server_configuration(
            "Second Emby",
            "http://127.0.0.1:8097",
            "****1111",
            false,
        )
        .unwrap_err();
        assert_eq!(url_change_masked_resp.status(), StatusCode::BAD_REQUEST);

        // 6. Changing URL with a new explicit API key succeeds and clears server_id, server_version, and last_connected_at
        let changed_url = save_emby_server_configuration(
            "Second Emby",
            "http://127.0.0.1:8097/emby/",
            "emby-secret-key-2222",
            false,
        )
        .expect("url change with new key");
        assert_eq!(changed_url, "http://127.0.0.1:8097/emby");
        {
            let conn = af_db::get_conn().unwrap();
            let (url, srv_id, srv_ver, last_conn): (String, String, String, Option<String>) = conn
                .query_row(
                    "SELECT url, COALESCE(server_id, ''), COALESCE(server_version, ''), last_connected_at FROM streaming_servers WHERE provider = 'emby'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert_eq!(url, "http://127.0.0.1:8097/emby");
            assert_eq!(srv_id, "");
            assert_eq!(srv_ver, "");
            assert!(last_conn.is_none());
        }

        // 7. Undecryptable enc:v1: stored key fails closed and requires a fresh key even on same URL
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute(
                "UPDATE streaming_servers SET api_key = 'enc:v1:corrupted-ciphertext' WHERE provider = 'emby'",
                [],
            )
            .unwrap();
        }
        let cfg_corrupt = get_stored_emby_config_fail_closed();
        assert_eq!(cfg_corrupt.api_key, "");
        let masked_on_corrupt_resp = save_emby_server_configuration(
            "Second Emby",
            "http://127.0.0.1:8097/emby",
            "****2222",
            false,
        )
        .unwrap_err();
        assert_eq!(masked_on_corrupt_resp.status(), StatusCode::BAD_REQUEST);

        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    #[tokio::test]
    async fn test_emby_dashboard_artwork_and_session_control_dispatch() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let db_path = init_isolated_streaming_db("emby_dispatch_integration");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req.lines().next().unwrap_or("");

                    if first_line.starts_with("GET /Items/emby-item-1/Images/Primary") {
                        let img = b"\x89PNG\r\n\x1a\nmock-emby-artwork";
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            img.len()
                        );
                        let _ = stream.write_all(header.as_bytes()).await;
                        let _ = stream.write_all(img).await;
                        return;
                    }

                    if first_line.starts_with("POST /Sessions/emby-sess-1/Playing/Pause") {
                        let resp =
                            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = stream.write_all(resp.as_bytes()).await;
                        return;
                    }

                    let body = if first_line.starts_with("GET /System/Info") {
                        r#"{"ServerName":"Mock Emby","Version":"4.8.10.0","Id":"emby-srv-live"}"#
                            .to_string()
                    } else if first_line.starts_with("GET /Sessions") {
                        r#"[
                            {
                                "Id": "emby-sess-1",
                                "ServerId": "emby-srv-live",
                                "UserId": "emby-u-1",
                                "UserName": "alex",
                                "Client": "Emby Theater",
                                "DeviceName": "Shield TV",
                                "DeviceId": "shield-1",
                                "RemoteEndPoint": "10.10.0.42",
                                "SupportsMediaControl": true,
                                "SupportedCommands": ["Pause"],
                                "PlayState": {
                                    "PositionTicks": 6000000000,
                                    "IsPaused": false,
                                    "PlayMethod": "DirectStream",
                                    "PlaySessionId": "emby-ps-1"
                                },
                                "NowPlayingItem": {
                                    "Id": "emby-item-1",
                                    "Name": "Ex Machina",
                                    "Type": "Movie",
                                    "RunTimeTicks": 64800000000,
                                    "ProductionYear": 2014,
                                    "MediaStreams": [
                                        {"Type": "Video", "Codec": "hevc", "Width": 3840, "Height": 2160, "BitRate": 16000000},
                                        {"Type": "Audio", "Codec": "eac3", "Channels": 6, "Language": "eng", "BitRate": 640000}
                                    ]
                                }
                            }
                        ]"#
                        .to_string()
                    } else {
                        "{}".to_string()
                    };

                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        let server_url = format!("http://{}", addr);
        let admin = crate::auth::AuthUser {
            user_id: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            jti: "test-jti".to_string(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };

        // Save Emby config via save_emby_server_configuration
        let saved_url = save_emby_server_configuration(
            "Mock Emby",
            &server_url,
            "emby-live-key-9876",
            true,
        )
        .expect("save mock emby config");
        assert_eq!(saved_url, server_url);

        // Test connection endpoint with masked key on same URL persists server_id and keeps support_stage = coming_soon
        let test_resp = test_streaming_server(Json(TestStreamingServerReq {
            provider: "emby".to_string(),
            url: server_url.clone(),
            api_key: "****9876".to_string(),
        }))
        .await
        .into_response();
        assert_eq!(test_resp.status(), StatusCode::OK);
        let test_bytes = axum::body::to_bytes(test_resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let test_json: serde_json::Value = serde_json::from_slice(&test_bytes).unwrap();
        assert_eq!(test_json["ok"], true);
        assert_eq!(test_json["server"]["status"], "connected");
        assert_eq!(test_json["server"]["supportStage"], "coming_soon");
        assert_eq!(test_json["server"]["serverId"], "emby-srv-live");
        assert_eq!(test_json["server"]["version"], "4.8.10.0");

        // Record two 15s monitor snapshots so observed session metrics accumulate for Emby
        let live_sessions = crate::streaming_emby::fetch_emby_live_sessions(
            "Mock Emby",
            &server_url,
            "emby-live-key-9876",
            Some("emby-srv-live"),
        )
        .await
        .unwrap();
        record_live_sessions_snapshot("emby", &live_sessions, 15);
        record_live_sessions_snapshot("emby", &live_sessions, 15);

        // Dashboard reflects live Emby session, observed bytes, coming_soon stage, and redacts sensitive fields for non-admin
        let admin_dash = build_streaming_dashboard("30d", "all", "all", true).await;
        let emby_srv = admin_dash
            .servers
            .iter()
            .find(|s| s.provider == "emby")
            .expect("emby server entry");
        assert_eq!(emby_srv.support_stage, "coming_soon");
        assert_eq!(emby_srv.status, "connected");
        assert_eq!(emby_srv.server_id, "emby-srv-live");
        assert_eq!(emby_srv.api_key_masked, "****9876");
        assert_eq!(admin_dash.active_sessions.len(), 1);
        assert_eq!(admin_dash.active_sessions[0].provider, "emby");
        assert_eq!(admin_dash.active_sessions[0].session_id, "emby-sess-1");
        assert_eq!(admin_dash.active_sessions[0].ip_address, "10.10.0.42");
        assert_eq!(admin_dash.active_sessions[0].session_data_bytes, 0);

        let viewer_dash = build_streaming_dashboard("30d", "all", "all", false).await;
        let viewer_emby_srv = viewer_dash
            .servers
            .iter()
            .find(|s| s.provider == "emby")
            .unwrap();
        assert_eq!(viewer_emby_srv.api_key_masked, "");
        assert_eq!(viewer_dash.active_sessions[0].ip_address, "");

        // Artwork proxy dispatches to Emby via explicit provider query or fallback
        let mut art_q = HashMap::new();
        art_q.insert("provider".to_string(), "emby".to_string());
        let art_resp = get_streaming_artwork(Extension(admin.clone()), Path("emby-item-1".to_string()), Query(art_q))
            .await
            .into_response();
        assert_eq!(art_resp.status(), StatusCode::OK);
        let art_bytes = axum::body::to_bytes(art_resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(&art_bytes[..], b"\x89PNG\r\n\x1a\nmock-emby-artwork");

        // Session control: supported Pause command succeeds via observed-session provider resolution
        let pause_resp = control_streaming_session(
            axum::Extension(admin.clone()),
            Path("emby-sess-1".to_string()),
            HeaderMap::new(),
            Json(SessionCommandReq {
                command: "pause".to_string(),
                header: String::new(),
                message: String::new(),
                provider: String::new(),
            }),
        )
        .await
        .into_response();
        assert_eq!(pause_resp.status(), StatusCode::OK);

        // Session control: unsupported DisplayMessage is rejected because SupportedCommands only has ["Pause"]
        let msg_resp = control_streaming_session(
            axum::Extension(admin),
            Path("emby-sess-1".to_string()),
            HeaderMap::new(),
            Json(SessionCommandReq {
                command: "message".to_string(),
                header: "Notice".to_string(),
                message: "Hello".to_string(),
                provider: "emby".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(msg_resp.status(), StatusCode::BAD_REQUEST);

        server_handle.abort();
        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }
}
