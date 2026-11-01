use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use af_services::{
    ActiveStreamSession, BreakdownEntry, StreamTypeDistribution, StreamingAnalytics,
    StreamingDashboardResponse, StreamingHistoryItem, StreamingLibraryCounts,
    StreamingLiveSummary, StreamingServerStatus, StreamingTimeSeriesPoint, StreamingTitleStat,
    StreamingUserStat,
};
use axum::body::Body;
use axum::extract::{Extension, Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
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
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(16)
        .build()
        .unwrap_or_else(|_| Client::new())
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
    last_activity_date: String,
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

    let bytes = resp.bytes().await?;
    let capped = if bytes.len() > max_bytes {
        bytes[..max_bytes].to_vec()
    } else {
        bytes.to_vec()
    };

    Ok((capped, status, content_type))
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
        "1080p FHD".to_string()
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
        _ => "Stereo".to_string(),
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
        "tvchannel" | "livetvchannel" | "livetvprogram" | "program" | "channel" => {
            "LiveTV".to_string()
        }
        "" => "Movie".to_string(),
        _ => raw_type.trim().to_string(),
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
        .unwrap_or(true);

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
        supports_media_control
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

pub async fn get_streaming_artwork(Path(item_id): Path<String>) -> Response {
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

    let (_, server_url, api_key, _) = get_stored_jellyfin_config();
    if api_key.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(clean_url) = af_services::validate_server_url(&server_url) else {
        return StatusCode::NOT_FOUND.into_response();
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
                if let Ok(bytes) = resp.bytes().await {
                    if !bytes.is_empty() && bytes.len() <= MAX_ARTWORK_PAYLOAD_SIZE {
                        image_bytes = Some(bytes.to_vec());
                        break;
                    }
                }
            }
        }
    }

    let Some(data) = image_bytes else {
        return StatusCode::NOT_FOUND.into_response();
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
        HeaderValue::from_static("private, max-age=3600"),
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

        if let Ok(sys_info) = serde_json::from_slice::<JellyfinSystemInfo>(&body) {
            if !sys_info.server_name.is_empty() {
                status.name = sys_info.server_name;
            }
            status.version = sys_info.version;
            status.server_id = sys_info.id;
            status.operating_system = sys_info.operating_system;
        }

        // Probe /Sessions and /Items/Counts with 6s timeout
        let _ = do_jellyfin_request(
            reqwest::Method::GET,
            &format!("{}/Sessions", clean_url),
            api_key,
            None,
            Duration::from_secs(6),
            MAX_UPSTREAM_PAYLOAD_SIZE,
        )
        .await;

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

        if let Ok(conn) = af_db::get_conn() {
            let _ = conn.execute(
                "UPDATE streaming_servers SET server_id = ?1, server_version = ?2, last_connected_at = CURRENT_TIMESTAMP WHERE provider = 'jellyfin'",
                params![status.server_id, status.version],
            );
        }

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
    let (server_name, server_url, api_key, _) = get_stored_jellyfin_config();
    if api_key.is_empty() {
        anyhow::bail!("Jellyfin API key is not configured");
    }
    let clean_url = af_services::validate_server_url(&server_url)?;

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
    let mut imported = 0usize;
    let page_size = 100usize;
    let filters = ["IsPlayed", "IsResumable"];

    for u in users {
        if u.id.trim().is_empty() {
            continue;
        }
        let encoded_uid = urlencoding::encode(u.id.trim());
        for filter in filters {
            let mut start_index = 0usize;
            loop {
                let items_url = format!(
                    "{}/Users/{}/Items?Recursive=true&Filters={}&IncludeItemTypes=Movie,Episode,Audio&Fields=MediaStreams,Container,ProductionYear&SortBy=DatePlayed&SortOrder=Descending&Limit={}&StartIndex={}",
                    clean_url, encoded_uid, filter, page_size, start_index
                );
                let Ok((items_body, i_code, _)) = do_jellyfin_request(
                    reqwest::Method::GET,
                    &items_url,
                    &api_key,
                    None,
                    Duration::from_secs(15),
                    MAX_UPSTREAM_PAYLOAD_SIZE,
                )
                .await
                else {
                    break;
                };

                if i_code != StatusCode::OK {
                    break;
                }

                let Ok(payload) = serde_json::from_slice::<JellyfinItemsEnvelope>(&items_body)
                else {
                    break;
                };
                if payload.items.is_empty() {
                    break;
                }

                let batch_len = payload.items.len();
                if let Ok(mut conn) = af_db::get_conn() {
                    if let Ok(tx) = conn.transaction() {
                    for item in payload.items {
                        let mut dur_secs = item.run_time_ticks / JELLYFIN_TICKS_PER_SECOND;
                        if dur_secs <= 0 {
                            dur_secs = 2700;
                        }
                        let mut v_codec = "HEVC".to_string();
                        let mut a_codec = "EAC3".to_string();
                        let mut a_ch = 6i32;
                        let mut w = item.width;
                        let mut h = item.height;
                        let mut stream_bitrate = 0i64;

                        for ms in &item.media_streams {
                            if ms.stream_type == "Video" {
                                if !ms.codec.is_empty() {
                                    v_codec = ms.codec.to_uppercase();
                                }
                                if ms.width > 0 {
                                    w = ms.width;
                                }
                                if ms.height > 0 {
                                    h = ms.height;
                                }
                                stream_bitrate += ms.bit_rate;
                            } else if ms.stream_type == "Audio" {
                                if !ms.codec.is_empty() {
                                    a_codec = ms.codec.to_uppercase();
                                }
                                if ms.channels > 0 {
                                    a_ch = ms.channels;
                                }
                                stream_bitrate += ms.bit_rate;
                            }
                        }

                        let mut bitrate = item.bitrate;
                        if bitrate <= 0 {
                            bitrate = stream_bitrate;
                        }
                        if bitrate <= 0 {
                            bitrate = 8_000_000;
                        }

                        let mut watched_secs = dur_secs;
                        let mut completion_pct = 100.0f64;
                        if let Some(ref ud) = item.user_data {
                            if !ud.played {
                                if ud.playback_position_ticks > 0 {
                                    let pos_secs =
                                        ud.playback_position_ticks / JELLYFIN_TICKS_PER_SECOND;
                                    if pos_secs > 0 && pos_secs < dur_secs {
                                        watched_secs = pos_secs;
                                        completion_pct =
                                            ((pos_secs as f64 / dur_secs as f64) * 1000.0).round()
                                                / 10.0;
                                    }
                                } else if ud.played_percentage > 0.0 && ud.played_percentage < 100.0
                                {
                                    completion_pct = (ud.played_percentage * 10.0).round() / 10.0;
                                    watched_secs =
                                        ((dur_secs as f64) * (completion_pct / 100.0)).round()
                                            as i64;
                                }
                            }
                        }
                        if watched_secs <= 0 {
                            watched_secs = 60;
                        }

                        let data_used = watched_secs * (bitrate / 8);
                        let mut played_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        let mut has_played_date = 0i32;

                        if let Some(ref ud) = item.user_data {
                            if !ud.last_played_date.trim().is_empty() {
                                if let Ok(dt) =
                                    DateTime::parse_from_rfc3339(ud.last_played_date.trim())
                                {
                                    played_at = dt
                                        .with_timezone(&Utc)
                                        .format("%Y-%m-%d %H:%M:%S")
                                        .to_string();
                                    has_played_date = 1;
                                }
                            }
                        }

                        let session_key = format!("jellyfin:sync:{}:{}", u.id, item.id);
                        let res = tx.execute(
                            r#"
                            INSERT INTO streaming_history (
                                session_key, provider, server_name, user_id, user_name,
                                client_name, device_name, ip_address,
                                item_id, item_name, item_type, series_name, series_id,
                                season_number, episode_number, production_year,
                                play_method, container, video_codec, video_resolution,
                                audio_codec, audio_channels, bitrate_bps,
                                duration_secs, watched_secs, data_used_bytes, completion_pct,
                                started_at, last_seen_at, ended_at, is_active
                            ) VALUES (
                                ?1, 'jellyfin', ?2, ?3, ?4,
                                'Jellyfin Client', 'Smart TV / Web', '192.168.1.10',
                                ?5, ?6, ?7, ?8, ?9,
                                ?10, ?11, ?12,
                                'DirectPlay', ?13, ?14, ?15,
                                ?16, ?17, ?18,
                                ?19, ?20, ?21, ?22,
                                ?23, ?23, ?23, 0
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
                                ended_at = CASE WHEN ?24 = 1 THEN excluded.ended_at ELSE streaming_history.ended_at END
                            WHERE streaming_history.watched_secs != excluded.watched_secs
                               OR streaming_history.completion_pct != excluded.completion_pct
                               OR (?24 = 1 AND streaming_history.last_seen_at != excluded.last_seen_at)
                               OR streaming_history.item_name != excluded.item_name
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
                            ],
                        );
                        if let Ok(rows) = res {
                            if rows > 0 {
                                imported += 1;
                            }
                        }
                    }
                    let _ = tx.commit();
                    }
                }

                start_index += batch_len;
                if start_index >= payload.total_record_count || batch_len < page_size {
                    break;
                }
            }
        }
    }

    Ok(imported)
}

pub async fn sync_streaming_server_history(
    Extension(user): Extension<AuthUser>,
    Path(provider): Path<String>,
    headers: HeaderMap,
) -> Response {
    let prov = provider.trim().to_lowercase();
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
                target_session = raw_sessions.into_iter().find(|s| s.id == clean_id);
            }
        }
    }

    let mut supports_media_ctrl = true;
    let mut can_send_msg = true;
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

    if command == "stop" && !device_id.is_empty() && (has_active_transcode || !play_session_id.is_empty()) {
        let enc_url = format!(
            "{}/Videos/ActiveEncodings?deviceId={}&playSessionId={}",
            clean_url,
            urlencoding::encode(&device_id),
            urlencoding::encode(&play_session_id)
        );
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

pub async fn control_streaming_session(
    Extension(user): Extension<AuthUser>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<SessionCommandReq>,
) -> Response {
    let clean_session_id = session_id.trim().to_string();
    if clean_session_id.is_empty() || clean_session_id.len() > 128 {
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

    if let Err(e) = send_jellyfin_session_command(&clean_session_id, &cmd, hdr, msg).await {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            format!("Session control command failed: {}", e),
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

        let (
            supports_media_control,
            supports_remote_control,
            can_send_message,
            supported_commands,
        ) = resolve_session_capabilities(&s);

        let dur_secs = item.run_time_ticks / JELLYFIN_TICKS_PER_SECOND;
        let progress_pct = if dur_secs > 0 {
            (((pos_secs as f64 / dur_secs as f64) * 1000.0).round() / 10.0).min(100.0)
        } else {
            0.0
        };

        let mut video_codec = String::new();
        let mut video_width = item.width;
        let mut video_height = item.height;
        let mut video_range = "SDR".to_string();
        let mut video_framerate = 0.0f64;
        let mut stream_bitrate_sum = 0i64;

        let mut audio_codec = String::new();
        let mut audio_channels = 2i32;
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
                        stream_bitrate_sum += ms.bit_rate;
                    }
                }
                "Audio" => {
                    let prio = if s
                        .play_state
                        .as_ref()
                        .and_then(|ps| ps.audio_stream_index)
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
                        audio_channels = ms.channels;
                        audio_layout = ms.channel_layout.clone();
                        audio_language = ms.language.to_uppercase();
                        stream_bitrate_sum += ms.bit_rate - audio_bitrate;
                        audio_bitrate = ms.bit_rate;
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

        if video_codec.is_empty() {
            video_codec = "H264".to_string();
        }
        if audio_codec.is_empty() {
            audio_codec = "AAC".to_string();
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
            stream_bitrate_sum
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

        if active_bitrate <= 0 {
            active_bitrate = if video_width >= 3800 {
                24_000_000
            } else if video_width >= 1900 {
                8_500_000
            } else {
                4_000_000
            };
        }

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
        let mut session_data_bytes = pos_secs * (active_bitrate / 8);

        if let Ok(conn) = af_db::get_conn() {
            let session_key = format!("jellyfin:{}:{}", s.id, item.id);
            if let Ok(tracked) = conn.query_row(
                "SELECT data_used_bytes FROM streaming_history WHERE session_key = ?1",
                params![session_key],
                |r| r.get::<_, i64>(0),
            ) {
                if tracked > session_data_bytes {
                    session_data_bytes = tracked;
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
            started_at: s.last_activity_date,
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

pub fn record_live_sessions_snapshot(
    provider: &str,
    sessions: &[ActiveStreamSession],
    interval_secs: i64,
) {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    let interval = interval_secs.max(0);

    let mut active_keys = HashSet::new();
    let mut direct_play_count = 0i32;
    let mut direct_stream_count = 0i32;
    let mut transcode_count = 0i32;
    let mut total_bitrate_bps = 0i64;
    let mut total_bytes_delta = 0i64;

    for s in sessions {
        let session_key = format!("{}:{}:{}", provider, s.session_id, s.item_id);
        active_keys.insert(session_key.clone());

        match s.play_method.as_str() {
            "Transcode" => transcode_count += 1,
            "DirectStream" => direct_stream_count += 1,
            _ => direct_play_count += 1,
        }

        let mut delta_secs = 0i64;
        let mut delta_bytes = 0i64;
        if s.state == "playing" {
            total_bitrate_bps += s.bitrate_bps;
            delta_secs = interval;
            delta_bytes = (s.bitrate_bps / 8) * interval;
            total_bytes_delta += delta_bytes;
        }

        let estimated_from_pos = s.position_secs * (s.bitrate_bps / 8);
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
                started_at, last_seen_at, is_active
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5,
                ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17,
                ?18, ?19, ?20, ?21,
                ?22, ?23, ?33, ?24, ?25,
                ?26, ?27, ?28, ?29, ?30,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1
            )
            ON CONFLICT(session_key) DO UPDATE SET
                play_method = excluded.play_method,
                hw_accel = CASE WHEN excluded.hw_accel != '' THEN excluded.hw_accel ELSE streaming_history.hw_accel END,
                transcode_reasons = CASE WHEN excluded.transcode_reasons != '' THEN excluded.transcode_reasons ELSE streaming_history.transcode_reasons END,
                bitrate_bps = excluded.bitrate_bps,
                duration_secs = CASE WHEN excluded.duration_secs > 0 THEN excluded.duration_secs ELSE streaming_history.duration_secs END,
                watched_secs = MAX(streaming_history.watched_secs + ?31, ?28),
                data_used_bytes = MAX(streaming_history.data_used_bytes + ?32, ?29),
                completion_pct = MAX(streaming_history.completion_pct, excluded.completion_pct),
                last_seen_at = CURRENT_TIMESTAMP,
                ended_at = NULL,
                is_active = 1
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
                s.bitrate_bps,
                s.duration_secs,
                s.position_secs,
                estimated_from_pos,
                s.progress_pct,
                delta_secs,
                delta_bytes,
                s.subtitle_codec,
            ],
        );
    }

    // Transition ended sessions in streaming_history
    if active_keys.is_empty() {
        let _ = conn.execute(
            "UPDATE streaming_history SET is_active = 0, ended_at = CURRENT_TIMESTAMP WHERE provider = ?1 AND is_active = 1",
            params![provider],
        );
    } else if let Ok(mut stmt) = conn.prepare(
        "SELECT session_key FROM streaming_history WHERE provider = ?1 AND is_active = 1",
    ) {
        let currently_active: Vec<String> = stmt
            .query_map(params![provider], |r| r.get::<_, String>(0))
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        for key in currently_active {
            if !active_keys.contains(&key) {
                let _ = conn.execute(
                    "UPDATE streaming_history SET is_active = 0, ended_at = CURRENT_TIMESTAMP WHERE session_key = ?1",
                    params![key],
                );
            }
        }
    }

    if !sessions.is_empty() && interval > 0 {
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

    // Prune bandwidth samples older than 90 days
    let _ = conn.execute(
        "DELETE FROM streaming_bandwidth_samples WHERE timestamp < datetime('now', '-90 days')",
        [],
    );
}

pub fn start_streaming_monitor() {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;

        let (_, _, initial_key, initial_enabled) = get_stored_jellyfin_config();
        if initial_enabled && !initial_key.is_empty() {
            let _ = sync_jellyfin_watch_history().await;
        }

        let mut ticker = tokio::time::interval(Duration::from_secs(15));
        let mut sync_counter = 0u32;

        loop {
            ticker.tick().await;
            let (name, server_url, api_key, enabled) = get_stored_jellyfin_config();
            if enabled && !api_key.is_empty() {
                if let Ok(sessions) =
                    fetch_jellyfin_live_sessions(&name, &server_url, &api_key).await
                {
                    record_live_sessions_snapshot("jellyfin", &sessions, 15);
                }

                sync_counter += 1;
                if sync_counter >= 20 {
                    sync_counter = 0;
                    let _ = sync_jellyfin_watch_history().await;
                }
            }
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
        DemoEntry { key: "demo:hist:01", user_id: "usr-01", user_name: "alex", client_name: "Jellyfin Media Player", device_name: "Apple TV 4K", ip: "192.168.1.42", item_id: "it-01", item_name: "Oppenheimer", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2023, method: "DirectPlay", v_codec: "HEVC", v_res: "4K UHD", a_codec: "TRUEHD", a_ch: 8, hw: "", bitrate: 31_000_000, dur: 10800, watched: 10650, pct: 98.6, hours_ago: 3 },
        DemoEntry { key: "demo:hist:02", user_id: "usr-02", user_name: "maya", client_name: "Swiftfin iOS", device_name: "iPhone 16 Pro", ip: "172.56.21.89", item_id: "it-02", item_name: "Hello, Ms. Cobel", item_type: "Episode", series_name: "Severance", season: 2, episode: 1, year: 2025, method: "Transcode", v_codec: "H264", v_res: "1080p FHD", a_codec: "AAC", a_ch: 2, hw: "NVENC", bitrate: 8_500_000, dur: 3300, watched: 3250, pct: 98.5, hours_ago: 6 },
        DemoEntry { key: "demo:hist:03", user_id: "usr-03", user_name: "liam", client_name: "Jellyfin Web", device_name: "Firefox 135", ip: "192.168.1.118", item_id: "it-03", item_name: "The Batman", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2022, method: "DirectStream", v_codec: "HEVC", v_res: "4K UHD", a_codec: "AAC", a_ch: 6, hw: "", bitrate: 22_000_000, dur: 10560, watched: 10200, pct: 96.6, hours_ago: 12 },
        DemoEntry { key: "demo:hist:04", user_id: "usr-04", user_name: "sophia", client_name: "Jellyfin Android TV", device_name: "NVIDIA Shield Pro", ip: "192.168.1.55", item_id: "it-04", item_name: "Interstellar", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2014, method: "DirectPlay", v_codec: "HEVC", v_res: "4K UHD", a_codec: "DTS", a_ch: 6, hw: "", bitrate: 29_500_000, dur: 10140, watched: 10100, pct: 99.6, hours_ago: 19 },
        DemoEntry { key: "demo:hist:05", user_id: "usr-01", user_name: "alex", client_name: "Jellyfin Media Player", device_name: "Apple TV 4K", ip: "192.168.1.42", item_id: "it-05", item_name: "Goodbye, Mrs. Selvig", item_type: "Episode", series_name: "Severance", season: 2, episode: 2, year: 2025, method: "DirectPlay", v_codec: "HEVC", v_res: "4K UHD", a_codec: "EAC3", a_ch: 6, hw: "", bitrate: 15_200_000, dur: 2940, watched: 2900, pct: 98.6, hours_ago: 27 },
        DemoEntry { key: "demo:hist:06", user_id: "usr-02", user_name: "maya", client_name: "Swiftfin iOS", device_name: "iPad Pro M4", ip: "192.168.1.73", item_id: "it-06", item_name: "Who Is Alive?", item_type: "Episode", series_name: "Severance", season: 2, episode: 3, year: 2025, method: "DirectPlay", v_codec: "HEVC", v_res: "4K UHD", a_codec: "EAC3", a_ch: 6, hw: "", bitrate: 14_800_000, dur: 3180, watched: 3140, pct: 98.7, hours_ago: 36 },
        DemoEntry { key: "demo:hist:07", user_id: "usr-05", user_name: "noah", client_name: "Jellyfin Roku", device_name: "Roku Ultra", ip: "192.168.1.90", item_id: "it-07", item_name: "Civil War", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2024, method: "Transcode", v_codec: "H264", v_res: "1080p FHD", a_codec: "AAC", a_ch: 2, hw: "NVENC", bitrate: 9_800_000, dur: 6540, watched: 6400, pct: 97.9, hours_ago: 48 },
        DemoEntry { key: "demo:hist:08", user_id: "usr-04", user_name: "sophia", client_name: "Finamp", device_name: "Pixel 9 Pro", ip: "192.168.1.56", item_id: "it-08", item_name: "Random Access Memories (Track 1)", item_type: "Audio", series_name: "Daft Punk", season: 0, episode: 1, year: 2013, method: "DirectPlay", v_codec: "FLAC", v_res: "Audio Lossless", a_codec: "FLAC", a_ch: 2, hw: "", bitrate: 1_411_000, dur: 275, watched: 275, pct: 100.0, hours_ago: 52 },
        DemoEntry { key: "demo:hist:09", user_id: "usr-03", user_name: "liam", client_name: "Jellyfin Web", device_name: "MacBook Pro", ip: "192.168.1.119", item_id: "it-09", item_name: "Arrival", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2016, method: "DirectPlay", v_codec: "HEVC", v_res: "1080p FHD", a_codec: "EAC3", a_ch: 6, hw: "", bitrate: 11_200_000, dur: 6960, watched: 6890, pct: 99.0, hours_ago: 74 },
        DemoEntry { key: "demo:hist:10", user_id: "usr-01", user_name: "alex", client_name: "Jellyfin Media Player", device_name: "Apple TV 4K", ip: "192.168.1.42", item_id: "it-10", item_name: "Dune: Part One", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2021, method: "DirectPlay", v_codec: "HEVC", v_res: "4K UHD", a_codec: "TRUEHD", a_ch: 8, hw: "", bitrate: 27_600_000, dur: 9300, watched: 9240, pct: 99.4, hours_ago: 96 },
    ];

    let now = Utc::now();
    for e in &entries {
        let start_ts = (now - chrono::Duration::hours(e.hours_ago) - chrono::Duration::seconds(e.watched))
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
        "0" | "all" => (3650, "all"),
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

pub fn query_streaming_analytics(
    window_days: i32,
    play_method_filter: &str,
    media_type_filter: &str,
    use_demo: bool,
    is_admin: bool,
    live_peak_bandwidth_mbps: f64,
) -> StreamingAnalytics {
    let resolved_window = if window_days <= 0 { 30 } else { window_days };
    let ts_days = if resolved_window <= 0 || resolved_window > 90 {
        30
    } else {
        resolved_window
    };

    let now = Utc::now();
    let mut daily_map: HashMap<String, StreamingTimeSeriesPoint> = HashMap::new();
    let mut day_keys: Vec<String> = Vec::with_capacity(ts_days as usize);
    for i in (0..ts_days).rev() {
        let d = (now - chrono::Duration::days(i as i64))
            .format("%Y-%m-%d")
            .to_string();
        day_keys.push(d.clone());
        daily_map.insert(
            d.clone(),
            StreamingTimeSeriesPoint {
                date: d,
                ..Default::default()
            },
        );
    }

    let mut result = StreamingAnalytics {
        window_days: resolved_window,
        peak_bandwidth_mbps: live_peak_bandwidth_mbps,
        media_type_breakdown: Vec::new(),
        resolution_breakdown: Vec::new(),
        codec_breakdown: Vec::new(),
        time_series: Vec::new(),
        top_users: Vec::new(),
        top_titles: Vec::new(),
        recent_history: Vec::new(),
        ..Default::default()
    };

    let Ok(conn) = af_db::get_conn() else {
        result.time_series = day_keys
            .into_iter()
            .filter_map(|d| daily_map.remove(&d))
            .collect();
        return result;
    };

    let mut where_clauses: Vec<String> = vec!["1=1".to_string()];
    let mut args: Vec<String> = Vec::new();

    if !use_demo {
        where_clauses.push("provider != 'demo'".to_string());
    }
    if resolved_window > 0 && resolved_window < 3650 {
        let cutoff = (now - chrono::Duration::days(resolved_window as i64))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        where_clauses.push("started_at >= ?".to_string());
        args.push(cutoff);
    }
    let pm_trimmed = play_method_filter.trim();
    if !pm_trimmed.is_empty() && !pm_trimmed.eq_ignore_ascii_case("all") {
        where_clauses.push("play_method = ?".to_string());
        args.push(pm_trimmed.to_string());
    }
    let mt_trimmed = media_type_filter.trim();
    if !mt_trimmed.is_empty() && !mt_trimmed.eq_ignore_ascii_case("all") {
        where_clauses.push("item_type = ?".to_string());
        args.push(mt_trimmed.to_string());
    }

    let where_sql = format!("WHERE {}", where_clauses.join(" AND "));

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
            COALESCE(SUM(CASE WHEN play_method = 'DirectPlay' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN play_method = 'DirectStream' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN play_method = 'Transcode' THEN 1 ELSE 0 END), 0)
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

    // Check bandwidth samples for peak aggregate bitrate when no per-item filter is active
    if (pm_trimmed.is_empty() || pm_trimmed.eq_ignore_ascii_case("all"))
        && (mt_trimmed.is_empty() || mt_trimmed.eq_ignore_ascii_case("all"))
    {
        let mut bw_clauses: Vec<String> = vec!["1=1".to_string()];
        let mut bw_args: Vec<String> = Vec::new();
        if !use_demo {
            bw_clauses.push("provider != 'demo'".to_string());
        }
        if resolved_window > 0 && resolved_window < 3650 {
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
        if let Ok(sample_peak_bps) = conn.query_row(
            &bw_sql,
            params_from_iter(bw_args.iter()),
            |r| r.get::<_, i64>(0),
        ) {
            let sample_peak_mbps =
                ((sample_peak_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;
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
            substr(started_at, 1, 10) AS day,
            COUNT(*),
            COALESCE(SUM(watched_secs), 0),
            COALESCE(SUM(data_used_bytes), 0),
            COALESCE(MAX(bitrate_bps), 0),
            COALESCE(SUM(CASE WHEN play_method = 'DirectPlay' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN play_method = 'DirectStream' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN play_method = 'Transcode' THEN 1 ELSE 0 END), 0)
        FROM streaming_history
        {}
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
    for d in day_keys {
        if let Some(pt) = daily_map.remove(&d) {
            result.time_series.push(pt);
        }
    }

    // 4. Top Users Leaderboard
    let users_sql = format!(
        r#"
        SELECT
            user_id,
            user_name,
            provider,
            COUNT(*) AS plays,
            COALESCE(SUM(watched_secs), 0) AS watch_secs,
            COALESCE(SUM(data_used_bytes), 0) AS data_bytes,
            COUNT(DISTINCT item_name) AS unique_items,
            COALESCE(SUM(CASE WHEN play_method = 'DirectPlay' THEN 1 ELSE 0 END), 0) AS dp_count,
            COALESCE(SUM(CASE WHEN play_method = 'Transcode' THEN 1 ELSE 0 END), 0) AS tc_count,
            COALESCE(AVG(completion_pct), 0) AS avg_comp,
            COALESCE(MAX(client_name || ' · ' || device_name), '') AS last_device,
            COALESCE(MAX(CAST(last_seen_at AS TEXT)), '') AS last_seen
        FROM streaming_history
        {} AND user_name != ''
        GROUP BY user_name
        ORDER BY data_bytes DESC, plays DESC
        LIMIT 10
        "#,
        where_sql
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
            item_id,
            CASE WHEN series_name != '' THEN series_name ELSE item_name END AS display_title,
            item_type,
            series_name,
            COALESCE(MAX(production_year), 0),
            provider,
            COALESCE(MAX(video_resolution), ''),
            COALESCE(MAX(video_codec), ''),
            COUNT(*) AS plays,
            COUNT(DISTINCT user_name) AS viewers,
            COALESCE(SUM(watched_secs), 0) AS watch_secs,
            COALESCE(SUM(data_used_bytes), 0) AS data_bytes,
            COALESCE(AVG(completion_pct), 0) AS avg_comp,
            COALESCE(MAX(CAST(last_seen_at AS TEXT)), '') AS last_watched
        FROM streaming_history
        {} AND item_name != ''
        GROUP BY display_title, item_type
        ORDER BY plays DESC, data_bytes DESC
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

    let mut active_sessions: Vec<ActiveStreamSession> = Vec::new();
    let mut use_demo = is_demo_mode_active();

    if jf_enabled && !jf_key.is_empty() {
        use_demo = false;
        match test_jellyfin_connection(&jf_url, &jf_key).await {
            Ok(st) => {
                jf_status = st;
                jf_status.name = jf_name.clone();
                jf_status.enabled = jf_enabled;
                if !is_admin {
                    jf_status.api_key_masked.clear();
                }
                if jf_status.status == "connected" {
                    if let Ok(sessions) =
                        fetch_jellyfin_live_sessions(&jf_name, &jf_url, &jf_key).await
                    {
                        active_sessions = sessions;
                        record_live_sessions_snapshot("jellyfin", &active_sessions, 0);
                    }
                }
            }
            Err(e) => {
                jf_status.status = "unreachable".to_string();
                jf_status.error_message = e.to_string();
            }
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
        // Attempt silent public info discovery so the user sees if a local Jellyfin server is running
        if let Ok(pub_status) = test_jellyfin_connection(&jf_url, "").await {
            if !pub_status.version.is_empty() {
                jf_status.version = pub_status.version;
                jf_status.server_id = pub_status.server_id;
                jf_status.error_message = pub_status.error_message;
            }
        }
    }

    if !is_admin {
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
        StreamingServerStatus {
            provider: "emby".to_string(),
            name: "Emby Server".to_string(),
            url: "http://127.0.0.1:8096".to_string(),
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
    let is_admin = req
        .extensions()
        .get::<AuthUser>()
        .map(|u| u.role == "admin")
        .unwrap_or(false);
    let payload = build_streaming_dashboard(window, play_method, media_type, is_admin).await;
    Json(payload).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_STREAMING_DB_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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

    #[tokio::test]
    async fn test_streaming_dashboard_contract_filters_and_redaction() {
        let _guard = TEST_STREAMING_DB_LOCK.lock().unwrap();
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
        assert!(empty_analytics["mediaTypeBreakdown"].as_array().unwrap().is_empty());
        assert!(empty_analytics["resolutionBreakdown"].as_array().unwrap().is_empty());
        assert!(empty_analytics["codecBreakdown"].as_array().unwrap().is_empty());
        assert!(empty_analytics["topUsers"].as_array().unwrap().is_empty());
        assert!(empty_analytics["topTitles"].as_array().unwrap().is_empty());
        assert!(empty_analytics["recentHistory"].as_array().unwrap().is_empty());
        assert_eq!(empty_analytics["timeSeries"].as_array().unwrap().len(), 30);

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
        let admin_resp = build_streaming_dashboard("30", "all", "all", true).await;
        let admin_json = serde_json::to_value(&admin_resp).expect("serialize admin dashboard");

        // Unreachable Jellyfin status (port 1 fails connection) and masked API key for admin
        let jf_srv = &admin_json["servers"][0];
        assert_eq!(jf_srv["status"], "unreachable");
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
        assert_eq!(ts_arr.len(), 30);
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
        assert_eq!(top_users[0]["lastDevice"], "Jellyfin Media Player · Apple TV");
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
        let non_admin_resp = build_streaming_dashboard("30", "all", "all", false).await;
        assert_eq!(non_admin_resp.servers[0].api_key_masked, "");
        assert_eq!(non_admin_resp.analytics.recent_history[0].ip_address, "");
        assert_eq!(non_admin_resp.analytics.recent_history[1].ip_address, "");

        // 5. Filter checks: window=7 excludes the 20-day-old row
        let win7_resp = build_streaming_dashboard("7", "all", "all", true).await;
        assert_eq!(win7_resp.analytics.window_days, 7);
        assert_eq!(win7_resp.analytics.total_plays, 1);
        assert_eq!(win7_resp.analytics.recent_history.len(), 1);
        assert_eq!(win7_resp.analytics.recent_history[0].item_name, "Oppenheimer");

        // playMethod=Transcode filter
        let tc_resp = build_streaming_dashboard("30", "Transcode", "all", true).await;
        assert_eq!(tc_resp.analytics.total_plays, 1);
        assert_eq!(tc_resp.analytics.recent_history.len(), 1);
        assert_eq!(tc_resp.analytics.recent_history[0].play_method, "Transcode");

        // mediaType=Movie filter
        let movie_resp = build_streaming_dashboard("30", "all", "Movie", true).await;
        assert_eq!(movie_resp.analytics.total_plays, 1);
        assert_eq!(movie_resp.analytics.recent_history.len(), 1);
        assert_eq!(movie_resp.analytics.recent_history[0].item_type, "Movie");

        // Let the frontend contract test render actual Rust responses, including
        // both empty history and populated live session cards.
        if let Some(path) = std::env::var_os("AF_STREAMING_CONTRACT_FIXTURE") {
            {
                let conn = af_db::get_conn().unwrap();
                conn.execute("UPDATE streaming_servers SET enabled = 0", []).unwrap();
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
}
