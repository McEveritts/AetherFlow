use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use af_services::{ActiveStreamSession, StreamingLibraryCounts, StreamingServerStatus};
use axum::body::Body;
use axum::extract::{Extension, Path, Query, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use reqwest::Client;
use rusqlite::params;
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

// ─────────────────────────────────────────────────────────────────────────────
// Request & Upstream Payload Types
// ─────────────────────────────────────────────────────────────────────────────

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
    bit_rate: i64,
    #[serde(default)]
    width: i32,
    #[serde(default)]
    height: i32,
    #[serde(default)]
    video_range: String,
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
    bitrate: i64,
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

fn resolve_session_capabilities(s: &JellyfinSessionRaw) -> (bool, bool, bool) {
    let supports_media_control = s
        .supports_media_control
        .or_else(|| {
            s.capabilities
                .as_ref()
                .and_then(|c| c.supports_media_control)
        })
        .unwrap_or(true);

    let supports_remote_control = s.supports_remote_control.unwrap_or(supports_media_control);

    let cmds: &[String] = if !s.supported_commands.is_empty() {
        &s.supported_commands
    } else if let Some(ref cap) = s.capabilities {
        &cap.supported_commands
    } else {
        &[]
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
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. GET /streaming/artwork/:itemId
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// 2. POST /streaming/servers/test
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// 3. POST /streaming/servers/:provider/sync
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// 4. POST /streaming/sessions/:sessionId/command
// ─────────────────────────────────────────────────────────────────────────────

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
        let (smc, _, csm) = resolve_session_capabilities(ts);
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
                        "client {:?} ({}) does not have an active remote-control WebSocket connection (SupportsMediaControl=false)",
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
                        "client {:?} ({}) does not have an active remote-control WebSocket connection (SupportsMediaControl=false)",
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
            json_payload = Some(serde_json::json!({
                "Header": resolved_header,
                "Text": message_text,
                "TimeoutMs": 8000,
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
        if let Some(ref ps) = s.play_state {
            pos_secs = ps.position_ticks / JELLYFIN_TICKS_PER_SECOND;
            is_paused = ps.is_paused;
            if !ps.play_method.is_empty() {
                play_method = ps.play_method.clone();
            }
            play_session_id = ps.play_session_id.trim().to_string();
        }

        let (supports_media_control, supports_remote_control, can_send_message) =
            resolve_session_capabilities(&s);

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
        let mut stream_bitrate_sum = 0i64;

        let mut audio_codec = String::new();
        let mut audio_channels = 2i32;
        let mut audio_layout = String::new();
        let mut audio_priority = 0i32;
        let mut audio_bitrate = 0i64;

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
                        stream_bitrate_sum += ms.bit_rate - audio_bitrate;
                        audio_bitrate = ms.bit_rate;
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
        let mut hw_accel = String::new();
        let mut transcode_reasons = Vec::new();
        let mut active_bitrate = if item.bitrate > 0 {
            item.bitrate
        } else {
            stream_bitrate_sum
        };

        if let Some(ref ti) = s.transcoding_info {
            is_video_direct = ti.is_video_direct;
            is_audio_direct = ti.is_audio_direct;
            if !ti.hardware_acceleration_type.is_empty()
                && ti.hardware_acceleration_type != "none"
            {
                hw_accel = ti.hardware_acceleration_type.to_uppercase();
            }
            if !ti.transcode_reasons.is_empty() {
                transcode_reasons = ti.transcode_reasons.clone();
            }
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
            video_codec,
            video_resolution: format_resolution_label(video_width, video_height),
            video_range,
            is_video_direct,
            audio_codec,
            audio_channels,
            audio_layout: format_audio_layout(audio_channels, &audio_layout),
            is_audio_direct,
            hw_accel,
            transcode_reasons,
            bitrate_bps: active_bitrate,
            bandwidth_mbps,
            session_data_bytes,
            started_at: s.last_activity_date,
            play_session_id,
            supports_media_control,
            supports_remote_control,
            can_send_message,
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
                ?22, ?23, '', ?24, ?25,
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

// ─────────────────────────────────────────────────────────────────────────────
// 6. Demo Mode Seeder & Full Streaming Dashboard (`GetStreamingDashboard`)
// ─────────────────────────────────────────────────────────────────────────────

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
            video_codec: "HEVC".to_string(),
            video_resolution: "4K".to_string(),
            video_range: "HDR10 / Dolby Vision".to_string(),
            is_video_direct: true,
            audio_codec: "TRUEHD".to_string(),
            audio_channels: 8,
            audio_layout: "7.1 Atmos".to_string(),
            is_audio_direct: true,
            hw_accel: String::new(),
            transcode_reasons: Vec::new(),
            bitrate_bps: 28_400_000,
            bandwidth_mbps: 28.4,
            session_data_bytes: 16_401_000_000,
            started_at: started.clone(),
            play_session_id: String::new(),
            supports_media_control: true,
            supports_remote_control: true,
            can_send_message: true,
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
            container: "TS".to_string(),
            video_codec: "H264".to_string(),
            video_resolution: "1080p".to_string(),
            video_range: "SDR".to_string(),
            is_video_direct: false,
            audio_codec: "AAC".to_string(),
            audio_channels: 2,
            audio_layout: "Stereo".to_string(),
            is_audio_direct: false,
            hw_accel: "NVENC".to_string(),
            transcode_reasons: vec![
                "ContainerBitrateExceedsLimit".to_string(),
                "VideoRangeNotSupported".to_string(),
            ],
            bitrate_bps: 8_200_000,
            bandwidth_mbps: 8.2,
            session_data_bytes: 1_937_250_000,
            started_at: started.clone(),
            play_session_id: String::new(),
            supports_media_control: true,
            supports_remote_control: true,
            can_send_message: true,
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
            container: "MP4".to_string(),
            video_codec: "HEVC".to_string(),
            video_resolution: "4K".to_string(),
            video_range: "HDR10".to_string(),
            is_video_direct: true,
            audio_codec: "AAC".to_string(),
            audio_channels: 6,
            audio_layout: "5.1".to_string(),
            is_audio_direct: false,
            hw_accel: String::new(),
            transcode_reasons: vec!["AudioCodecNotSupported".to_string()],
            bitrate_bps: 18_600_000,
            bandwidth_mbps: 0.0,
            session_data_bytes: 14_903_250_000,
            started_at: started,
            play_session_id: String::new(),
            supports_media_control: true,
            supports_remote_control: true,
            can_send_message: true,
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
        DemoEntry { key: "demo:hist:01", user_id: "usr-01", user_name: "alex", client_name: "Jellyfin Media Player", device_name: "Apple TV 4K", ip: "192.168.1.42", item_id: "it-01", item_name: "Oppenheimer", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2023, method: "DirectPlay", v_codec: "HEVC", v_res: "4K", a_codec: "TRUEHD", a_ch: 8, hw: "", bitrate: 31_000_000, dur: 10800, watched: 10650, pct: 98.6, hours_ago: 3 },
        DemoEntry { key: "demo:hist:02", user_id: "usr-02", user_name: "maya", client_name: "Swiftfin iOS", device_name: "iPhone 16 Pro", ip: "172.56.21.89", item_id: "it-02", item_name: "Hello, Ms. Cobel", item_type: "Episode", series_name: "Severance", season: 2, episode: 1, year: 2025, method: "Transcode", v_codec: "H264", v_res: "1080p", a_codec: "AAC", a_ch: 2, hw: "NVENC", bitrate: 8_500_000, dur: 3300, watched: 3250, pct: 98.5, hours_ago: 6 },
        DemoEntry { key: "demo:hist:03", user_id: "usr-03", user_name: "liam", client_name: "Jellyfin Web", device_name: "Firefox 135", ip: "192.168.1.118", item_id: "it-03", item_name: "The Batman", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2022, method: "DirectStream", v_codec: "HEVC", v_res: "4K", a_codec: "AAC", a_ch: 6, hw: "", bitrate: 22_000_000, dur: 10560, watched: 10200, pct: 96.6, hours_ago: 12 },
        DemoEntry { key: "demo:hist:04", user_id: "usr-04", user_name: "sophia", client_name: "Jellyfin Android TV", device_name: "NVIDIA Shield Pro", ip: "192.168.1.55", item_id: "it-04", item_name: "Interstellar", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2014, method: "DirectPlay", v_codec: "HEVC", v_res: "4K", a_codec: "DTS", a_ch: 6, hw: "", bitrate: 29_500_000, dur: 10140, watched: 10100, pct: 99.6, hours_ago: 19 },
        DemoEntry { key: "demo:hist:05", user_id: "usr-01", user_name: "alex", client_name: "Jellyfin Media Player", device_name: "Apple TV 4K", ip: "192.168.1.42", item_id: "it-05", item_name: "Goodbye, Mrs. Selvig", item_type: "Episode", series_name: "Severance", season: 2, episode: 2, year: 2025, method: "DirectPlay", v_codec: "HEVC", v_res: "4K", a_codec: "EAC3", a_ch: 6, hw: "", bitrate: 15_200_000, dur: 2940, watched: 2900, pct: 98.6, hours_ago: 27 },
        DemoEntry { key: "demo:hist:06", user_id: "usr-02", user_name: "maya", client_name: "Swiftfin iOS", device_name: "iPad Pro M4", ip: "192.168.1.73", item_id: "it-06", item_name: "Who Is Alive?", item_type: "Episode", series_name: "Severance", season: 2, episode: 3, year: 2025, method: "DirectPlay", v_codec: "HEVC", v_res: "4K", a_codec: "EAC3", a_ch: 6, hw: "", bitrate: 14_800_000, dur: 3180, watched: 3140, pct: 98.7, hours_ago: 36 },
        DemoEntry { key: "demo:hist:07", user_id: "usr-05", user_name: "noah", client_name: "Jellyfin Roku", device_name: "Roku Ultra", ip: "192.168.1.90", item_id: "it-07", item_name: "Civil War", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2024, method: "Transcode", v_codec: "H264", v_res: "1080p", a_codec: "AAC", a_ch: 2, hw: "NVENC", bitrate: 9_800_000, dur: 6540, watched: 6400, pct: 97.9, hours_ago: 48 },
        DemoEntry { key: "demo:hist:08", user_id: "usr-04", user_name: "sophia", client_name: "Finamp", device_name: "Pixel 9 Pro", ip: "192.168.1.56", item_id: "it-08", item_name: "Random Access Memories (Track 1)", item_type: "Audio", series_name: "Daft Punk", season: 0, episode: 1, year: 2013, method: "DirectPlay", v_codec: "NONE", v_res: "Audio", a_codec: "FLAC", a_ch: 2, hw: "", bitrate: 1_411_000, dur: 275, watched: 275, pct: 100.0, hours_ago: 52 },
        DemoEntry { key: "demo:hist:09", user_id: "usr-03", user_name: "liam", client_name: "Jellyfin Web", device_name: "MacBook Pro", ip: "192.168.1.119", item_id: "it-09", item_name: "Arrival", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2016, method: "DirectPlay", v_codec: "HEVC", v_res: "1080p", a_codec: "EAC3", a_ch: 6, hw: "", bitrate: 11_200_000, dur: 6960, watched: 6890, pct: 99.0, hours_ago: 74 },
        DemoEntry { key: "demo:hist:10", user_id: "usr-01", user_name: "alex", client_name: "Jellyfin Media Player", device_name: "Apple TV 4K", ip: "192.168.1.42", item_id: "it-10", item_name: "Dune: Part One", item_type: "Movie", series_name: "", season: 0, episode: 0, year: 2021, method: "DirectPlay", v_codec: "HEVC", v_res: "4K", a_codec: "TRUEHD", a_ch: 8, hw: "", bitrate: 27_600_000, dur: 9300, watched: 9240, pct: 99.4, hours_ago: 96 },
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
        "30" | "30d" => (30, "30d"),
        "90" | "90d" => (90, "90d"),
        "365" | "365d" | "1y" => (365, "365d"),
        "0" | "all" => (0, "all"),
        _ => (30, "30d"),
    }
}

pub async fn build_streaming_dashboard(window_raw: &str, is_admin: bool) -> serde_json::Value {
    let (window_days, window_label) = parse_window_days(window_raw);
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

    let mut live_sessions: Vec<ActiveStreamSession> = Vec::new();
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
                    if let Ok(sessions) = fetch_jellyfin_live_sessions(&jf_name, &jf_url, &jf_key).await {
                        live_sessions = sessions;
                        record_live_sessions_snapshot("jellyfin", &live_sessions, 0);
                    }
                }
            }
            Err(e) => {
                jf_status.status = "offline".to_string();
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
        live_sessions = get_synthetic_demo_sessions();
        jf_status.status = "demo".to_string();
        jf_status.configured = true;
        jf_status.name = "AetherFlow Media Vault (Demo)".to_string();
        jf_status.version = "10.10.6".to_string();
        jf_status.operating_system = "Linux 6.8 (Ubuntu 24.04 LTS)".to_string();
        jf_status.library_counts = StreamingLibraryCounts {
            movies: 1420,
            series: 318,
            episodes: 14890,
            audio: 26400,
        };
    }

    if !is_admin {
        for s in &mut live_sessions {
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
            status: "planned".to_string(),
            support_stage: "planned".to_string(),
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
            status: "planned".to_string(),
            support_stage: "planned".to_string(),
            server_id: String::new(),
            version: String::new(),
            operating_system: String::new(),
            library_counts: StreamingLibraryCounts::default(),
            last_connected_at: String::new(),
            error_message: String::new(),
        },
    ];

    // Live summary calculations
    let active_streams = live_sessions.len() as i32;
    let mut direct_play_count = 0i32;
    let mut direct_stream_count = 0i32;
    let mut transcode_count = 0i32;
    let mut hw_transcode_count = 0i32;
    let mut paused_count = 0i32;
    let mut total_bitrate_bps = 0i64;
    let mut active_session_bytes = 0i64;
    let mut lan_streams = 0i32;
    let mut wan_streams = 0i32;
    let mut lan_bitrate_bps = 0i64;
    let mut wan_bitrate_bps = 0i64;

    for s in &live_sessions {
        match s.play_method.as_str() {
            "Transcode" => {
                transcode_count += 1;
                if !s.hw_accel.is_empty() && !s.hw_accel.eq_ignore_ascii_case("none") {
                    hw_transcode_count += 1;
                }
            }
            "DirectStream" => direct_stream_count += 1,
            _ => direct_play_count += 1,
        }
        if s.state == "paused" {
            paused_count += 1;
        } else {
            total_bitrate_bps += s.bitrate_bps;
            if s.is_lan {
                lan_bitrate_bps += s.bitrate_bps;
            } else {
                wan_bitrate_bps += s.bitrate_bps;
            }
        }
        active_session_bytes += s.session_data_bytes;
        if s.is_lan {
            lan_streams += 1;
        } else {
            wan_streams += 1;
        }
    }

    let total_bandwidth_mbps = ((total_bitrate_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;
    let lan_bandwidth_mbps = ((lan_bitrate_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;
    let wan_bandwidth_mbps = ((wan_bitrate_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;

    // Historical Analytics from SQLite
    let mut total_plays = 0i32;
    let mut total_watched_secs = 0i64;
    let mut total_data_bytes = 0i64;
    let mut unique_users = 0i32;
    let mut unique_titles = 0i32;
    let mut avg_completion_pct = 0.0f64;
    let mut peak_concurrent = active_streams;
    let mut peak_bandwidth_mbps = total_bandwidth_mbps;

    let mut st_direct_play = 0i32;
    let mut st_direct_stream = 0i32;
    let mut st_transcode = 0i32;

    let mut media_type_breakdown: Vec<serde_json::Value> = Vec::new();
    let mut resolution_breakdown: Vec<serde_json::Value> = Vec::new();
    let mut codec_breakdown: Vec<serde_json::Value> = Vec::new();
    let mut time_series: Vec<serde_json::Value> = Vec::new();
    let mut top_users: Vec<serde_json::Value> = Vec::new();
    let mut top_titles: Vec<serde_json::Value> = Vec::new();
    let mut top_clients: Vec<serde_json::Value> = Vec::new();
    let mut recent_history: Vec<serde_json::Value> = Vec::new();

    if let Ok(conn) = af_db::get_conn() {
        let mut where_clauses: Vec<String> = Vec::new();
        if !use_demo {
            where_clauses.push("provider != 'demo'".to_string());
        }
        if window_days > 0 {
            where_clauses.push(format!(
                "started_at >= datetime('now', '-{} days')",
                window_days
            ));
        }
        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        // 1. Totals & Aggregates
        let agg_sql = format!(
            r#"
            SELECT
                COUNT(*),
                COALESCE(SUM(watched_secs), 0),
                COALESCE(SUM(data_used_bytes), 0),
                COUNT(DISTINCT CASE WHEN user_name != '' THEN user_name ELSE user_id END),
                COUNT(DISTINCT CASE WHEN series_name != '' THEN series_name ELSE item_name END),
                COALESCE(AVG(completion_pct), 0),
                COALESCE(SUM(CASE WHEN play_method = 'DirectPlay' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN play_method = 'DirectStream' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN play_method = 'Transcode' THEN 1 ELSE 0 END), 0)
            FROM streaming_history
            {}
            "#,
            where_sql
        );
        if let Ok(row) = conn.query_row(&agg_sql, [], |r| {
            Ok((
                r.get::<_, i32>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i32>(3)?,
                r.get::<_, i32>(4)?,
                r.get::<_, f64>(5)?,
                r.get::<_, i32>(6)?,
                r.get::<_, i32>(7)?,
                r.get::<_, i32>(8)?,
            ))
        }) {
            total_plays = row.0;
            total_watched_secs = row.1;
            total_data_bytes = row.2;
            unique_users = row.3;
            unique_titles = row.4;
            avg_completion_pct = (row.5 * 10.0).round() / 10.0;
            st_direct_play = row.6;
            st_direct_stream = row.7;
            st_transcode = row.8;
        }

        // 2. Peak concurrency & bandwidth from streaming_bandwidth_samples
        let mut bw_clauses: Vec<String> = Vec::new();
        if !use_demo {
            bw_clauses.push("provider != 'demo'".to_string());
        }
        if window_days > 0 {
            bw_clauses.push(format!(
                "timestamp >= datetime('now', '-{} days')",
                window_days
            ));
        }
        let bw_where = if bw_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", bw_clauses.join(" AND "))
        };
        let peak_sql = format!(
            "SELECT COALESCE(MAX(active_streams), 0), COALESCE(MAX(total_bitrate_bps), 0) FROM streaming_bandwidth_samples {}",
            bw_where
        );
        if let Ok((p_streams, p_bitrate)) = conn.query_row(&peak_sql, [], |r| {
            Ok((r.get::<_, i32>(0)?, r.get::<_, i64>(1)?))
        }) {
            if p_streams > peak_concurrent {
                peak_concurrent = p_streams;
            }
            let p_mbps = ((p_bitrate as f64 / 1_000_000.0) * 100.0).round() / 100.0;
            if p_mbps > peak_bandwidth_mbps {
                peak_bandwidth_mbps = p_mbps;
            }
        }

        // 3. Breakdown helper
        let query_breakdown = |col_expr: &str| -> Vec<serde_json::Value> {
            let mut out = Vec::new();
            let q = format!(
                "SELECT {col} AS label, COUNT(*) AS cnt FROM streaming_history {where_sql} GROUP BY label ORDER BY cnt DESC LIMIT 8",
                col = col_expr,
                where_sql = where_sql
            );
            if let Ok(mut stmt) = conn.prepare(&q) {
                if let Ok(rows) = stmt.query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i32>(1)?))
                }) {
                    for (label, count) in rows.flatten() {
                        let pct = if total_plays > 0 {
                            ((count as f64 / total_plays as f64) * 1000.0).round() / 10.0
                        } else {
                            0.0
                        };
                        out.push(serde_json::json!({
                            "label": label,
                            "count": count,
                            "percentage": pct,
                        }));
                    }
                }
            }
            out
        };

        media_type_breakdown = query_breakdown("CASE WHEN item_type = '' THEN 'Movie' ELSE item_type END");
        resolution_breakdown = query_breakdown("CASE WHEN video_resolution = '' THEN '1080p' ELSE video_resolution END");
        codec_breakdown = query_breakdown("CASE WHEN video_codec = '' THEN 'H264' ELSE video_codec END");
        top_clients = query_breakdown("CASE WHEN client_name = '' THEN 'Jellyfin Web' ELSE client_name END");

        // 4. Time series
        let bucket_expr = if window_days == 1 {
            "strftime('%Y-%m-%d %H:00', started_at)"
        } else {
            "strftime('%Y-%m-%d', started_at)"
        };
        let ts_sql = format!(
            r#"
            SELECT
                {bucket} AS bucket,
                COUNT(*),
                COALESCE(SUM(CASE WHEN play_method = 'DirectPlay' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN play_method = 'DirectStream' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN play_method = 'Transcode' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(watched_secs), 0),
                COALESCE(SUM(data_used_bytes), 0),
                COALESCE(MAX(bitrate_bps), 0)
            FROM streaming_history
            {where_sql}
            GROUP BY bucket
            ORDER BY bucket ASC
            LIMIT 90
            "#,
            bucket = bucket_expr,
            where_sql = where_sql
        );
        if let Ok(mut stmt) = conn.prepare(&ts_sql) {
            if let Ok(rows) = stmt.query_map([], |r| {
                let max_br: i64 = r.get(7)?;
                let watched_s: i64 = r.get(5)?;
                Ok(serde_json::json!({
                    "bucket": r.get::<_, String>(0)?,
                    "plays": r.get::<_, i32>(1)?,
                    "directPlays": r.get::<_, i32>(2)?,
                    "direct_plays": r.get::<_, i32>(2)?,
                    "directStreams": r.get::<_, i32>(3)?,
                    "direct_streams": r.get::<_, i32>(3)?,
                    "transcodes": r.get::<_, i32>(4)?,
                    "watchedSecs": watched_s,
                    "watched_secs": watched_s,
                    "watchedMins": watched_s / 60,
                    "dataBytes": r.get::<_, i64>(6)?,
                    "data_bytes": r.get::<_, i64>(6)?,
                    "avgMbps": ((max_br as f64 / 1_000_000.0) * 100.0).round() / 100.0,
                    "avg_mbps": ((max_br as f64 / 1_000_000.0) * 100.0).round() / 100.0,
                }))
            }) {
                for item in rows.flatten() {
                    time_series.push(item);
                }
            }
        }

        // 5. Top Users
        let users_sql = format!(
            r#"
            SELECT
                user_id,
                CASE WHEN user_name = '' THEN 'Unknown User' ELSE user_name END AS uname,
                COUNT(*) AS plays,
                COALESCE(SUM(watched_secs), 0) AS wsecs,
                COALESCE(SUM(data_used_bytes), 0) AS dbytes,
                COALESCE(SUM(CASE WHEN play_method = 'DirectPlay' THEN 1 ELSE 0 END), 0) AS dp,
                COALESCE(SUM(CASE WHEN play_method = 'Transcode' THEN 1 ELSE 0 END), 0) AS tc,
                COALESCE(MAX(last_seen_at), '') AS last_seen,
                COALESCE(MAX(device_name), '') AS last_dev
            FROM streaming_history
            {}
            GROUP BY uname
            ORDER BY wsecs DESC, plays DESC
            LIMIT 10
            "#,
            where_sql
        );
        if let Ok(mut stmt) = conn.prepare(&users_sql) {
            if let Ok(rows) = stmt.query_map([], |r| {
                let wsecs: i64 = r.get(3)?;
                Ok(serde_json::json!({
                    "userId": r.get::<_, String>(0)?,
                    "user_id": r.get::<_, String>(0)?,
                    "userName": r.get::<_, String>(1)?,
                    "user_name": r.get::<_, String>(1)?,
                    "playCount": r.get::<_, i32>(2)?,
                    "play_count": r.get::<_, i32>(2)?,
                    "watchedSecs": wsecs,
                    "watched_secs": wsecs,
                    "watchedHours": ((wsecs as f64 / 3600.0) * 10.0).round() / 10.0,
                    "watched_hours": ((wsecs as f64 / 3600.0) * 10.0).round() / 10.0,
                    "dataBytes": r.get::<_, i64>(4)?,
                    "data_bytes": r.get::<_, i64>(4)?,
                    "directPlays": r.get::<_, i32>(5)?,
                    "direct_plays": r.get::<_, i32>(5)?,
                    "transcodes": r.get::<_, i32>(6)?,
                    "lastPlayedAt": r.get::<_, String>(7)?,
                    "last_played_at": r.get::<_, String>(7)?,
                    "lastDevice": r.get::<_, String>(8)?,
                    "last_device": r.get::<_, String>(8)?,
                }))
            }) {
                for item in rows.flatten() {
                    top_users.push(item);
                }
            }
        }

        // 6. Top Titles
        let titles_sql = format!(
            r#"
            SELECT
                MAX(item_id),
                item_name,
                CASE WHEN item_type = '' THEN 'Movie' ELSE item_type END,
                series_name,
                MAX(production_year),
                COUNT(*) AS plays,
                COUNT(DISTINCT CASE WHEN user_name != '' THEN user_name ELSE user_id END) AS uviewers,
                COALESCE(SUM(watched_secs), 0) AS wsecs,
                COALESCE(SUM(data_used_bytes), 0) AS dbytes
            FROM streaming_history
            {}
            GROUP BY item_name, series_name
            ORDER BY plays DESC, wsecs DESC
            LIMIT 10
            "#,
            where_sql
        );
        if let Ok(mut stmt) = conn.prepare(&titles_sql) {
            if let Ok(rows) = stmt.query_map([], |r| {
                let wsecs: i64 = r.get(7)?;
                Ok(serde_json::json!({
                    "itemId": r.get::<_, String>(0)?,
                    "item_id": r.get::<_, String>(0)?,
                    "title": r.get::<_, String>(1)?,
                    "itemType": r.get::<_, String>(2)?,
                    "item_type": r.get::<_, String>(2)?,
                    "seriesName": r.get::<_, String>(3)?,
                    "series_name": r.get::<_, String>(3)?,
                    "year": r.get::<_, i32>(4)?,
                    "playCount": r.get::<_, i32>(5)?,
                    "play_count": r.get::<_, i32>(5)?,
                    "uniqueViewers": r.get::<_, i32>(6)?,
                    "unique_viewers": r.get::<_, i32>(6)?,
                    "watchedSecs": wsecs,
                    "watched_secs": wsecs,
                    "watchedHours": ((wsecs as f64 / 3600.0) * 10.0).round() / 10.0,
                    "watched_hours": ((wsecs as f64 / 3600.0) * 10.0).round() / 10.0,
                    "dataBytes": r.get::<_, i64>(8)?,
                    "data_bytes": r.get::<_, i64>(8)?,
                }))
            }) {
                for item in rows.flatten() {
                    top_titles.push(item);
                }
            }
        }

        // 7. Recent History
        let hist_sql = format!(
            r#"
            SELECT
                id, provider, server_name, user_name, client_name, device_name, ip_address,
                item_id, item_name, item_type, series_name, season_number, episode_number, production_year,
                play_method, container, video_codec, video_resolution, audio_codec, audio_channels, hw_accel,
                bitrate_bps, duration_secs, watched_secs, data_used_bytes, completion_pct,
                COALESCE(CAST(started_at AS TEXT), ''),
                COALESCE(CAST(ended_at AS TEXT), ''),
                is_active
            FROM streaming_history
            {}
            ORDER BY last_seen_at DESC
            LIMIT 35
            "#,
            where_sql
        );
        if let Ok(mut stmt) = conn.prepare(&hist_sql) {
            if let Ok(rows) = stmt.query_map([], |r| {
                let raw_ip: String = r.get(6)?;
                let ip_out = if is_admin { raw_ip } else { String::new() };
                let is_act: i32 = r.get(28)?;
                Ok(serde_json::json!({
                    "id": r.get::<_, i64>(0)?,
                    "provider": r.get::<_, String>(1)?,
                    "serverName": r.get::<_, String>(2)?,
                    "server_name": r.get::<_, String>(2)?,
                    "userName": r.get::<_, String>(3)?,
                    "user_name": r.get::<_, String>(3)?,
                    "clientName": r.get::<_, String>(4)?,
                    "client_name": r.get::<_, String>(4)?,
                    "deviceName": r.get::<_, String>(5)?,
                    "device_name": r.get::<_, String>(5)?,
                    "ipAddress": ip_out,
                    "ip_address": ip_out,
                    "itemId": r.get::<_, String>(7)?,
                    "item_id": r.get::<_, String>(7)?,
                    "itemName": r.get::<_, String>(8)?,
                    "item_name": r.get::<_, String>(8)?,
                    "itemType": r.get::<_, String>(9)?,
                    "item_type": r.get::<_, String>(9)?,
                    "seriesName": r.get::<_, String>(10)?,
                    "series_name": r.get::<_, String>(10)?,
                    "seasonNumber": r.get::<_, i32>(11)?,
                    "season_number": r.get::<_, i32>(11)?,
                    "episodeNumber": r.get::<_, i32>(12)?,
                    "episode_number": r.get::<_, i32>(12)?,
                    "productionYear": r.get::<_, i32>(13)?,
                    "production_year": r.get::<_, i32>(13)?,
                    "playMethod": r.get::<_, String>(14)?,
                    "play_method": r.get::<_, String>(14)?,
                    "container": r.get::<_, String>(15)?,
                    "videoCodec": r.get::<_, String>(16)?,
                    "video_codec": r.get::<_, String>(16)?,
                    "videoResolution": r.get::<_, String>(17)?,
                    "video_resolution": r.get::<_, String>(17)?,
                    "audioCodec": r.get::<_, String>(18)?,
                    "audio_codec": r.get::<_, String>(18)?,
                    "audioChannels": r.get::<_, i32>(19)?,
                    "audio_channels": r.get::<_, i32>(19)?,
                    "hwAccel": r.get::<_, String>(20)?,
                    "hw_accel": r.get::<_, String>(20)?,
                    "bitrateBps": r.get::<_, i64>(21)?,
                    "bitrate_bps": r.get::<_, i64>(21)?,
                    "durationSecs": r.get::<_, i64>(22)?,
                    "duration_secs": r.get::<_, i64>(22)?,
                    "watchedSecs": r.get::<_, i64>(23)?,
                    "watched_secs": r.get::<_, i64>(23)?,
                    "dataUsedBytes": r.get::<_, i64>(24)?,
                    "data_used_bytes": r.get::<_, i64>(24)?,
                    "completionPct": ((r.get::<_, f64>(25)? * 10.0).round() / 10.0),
                    "completion_pct": ((r.get::<_, f64>(25)? * 10.0).round() / 10.0),
                    "startedAt": r.get::<_, String>(26)?,
                    "started_at": r.get::<_, String>(26)?,
                    "endedAt": r.get::<_, String>(27)?,
                    "ended_at": r.get::<_, String>(27)?,
                    "isActive": is_act == 1,
                    "is_active": is_act == 1,
                }))
            }) {
                for item in rows.flatten() {
                    recent_history.push(item);
                }
            }
        }
    }

    let total_watched_hours = ((total_watched_secs as f64 / 3600.0) * 10.0).round() / 10.0;
    let st_total = st_direct_play + st_direct_stream + st_transcode;
    let (dp_pct, ds_pct, tc_pct) = if st_total > 0 {
        (
            ((st_direct_play as f64 / st_total as f64) * 1000.0).round() / 10.0,
            ((st_direct_stream as f64 / st_total as f64) * 1000.0).round() / 10.0,
            ((st_transcode as f64 / st_total as f64) * 1000.0).round() / 10.0,
        )
    } else {
        (0.0, 0.0, 0.0)
    };

    let stream_types = serde_json::json!({
        "directPlay": st_direct_play,
        "direct_play": st_direct_play,
        "directStream": st_direct_stream,
        "direct_stream": st_direct_stream,
        "transcode": st_transcode,
        "directPlayPct": dp_pct,
        "direct_play_pct": dp_pct,
        "directStreamPct": ds_pct,
        "direct_stream_pct": ds_pct,
        "transcodePct": tc_pct,
        "transcode_pct": tc_pct,
    });

    let live_summary = serde_json::json!({
        "activeStreams": active_streams,
        "active_streams": active_streams,
        "directPlayCount": direct_play_count,
        "direct_play_count": direct_play_count,
        "directStreamCount": direct_stream_count,
        "direct_stream_count": direct_stream_count,
        "transcodeCount": transcode_count,
        "transcode_count": transcode_count,
        "hwTranscodeCount": hw_transcode_count,
        "hw_transcode_count": hw_transcode_count,
        "pausedCount": paused_count,
        "paused_count": paused_count,
        "totalBitrateBps": total_bitrate_bps,
        "total_bitrate_bps": total_bitrate_bps,
        "totalBandwidthMbps": total_bandwidth_mbps,
        "total_bandwidth_mbps": total_bandwidth_mbps,
        "lanBandwidthMbps": lan_bandwidth_mbps,
        "lan_bandwidth_mbps": lan_bandwidth_mbps,
        "wanBandwidthMbps": wan_bandwidth_mbps,
        "wan_bandwidth_mbps": wan_bandwidth_mbps,
        "activeSessionBytes": active_session_bytes,
        "active_session_bytes": active_session_bytes,
        "lanStreams": lan_streams,
        "lan_streams": lan_streams,
        "wanStreams": wan_streams,
        "wan_streams": wan_streams,
        "isDemoMode": use_demo,
        "is_demo_mode": use_demo,
    });

    let analytics = serde_json::json!({
        "window": window_label,
        "windowDays": window_days,
        "window_days": window_days,
        "totalPlays": total_plays,
        "total_plays": total_plays,
        "totalWatchedSecs": total_watched_secs,
        "total_watched_secs": total_watched_secs,
        "total_watch_seconds": total_watched_secs,
        "totalWatchedHours": total_watched_hours,
        "total_watched_hours": total_watched_hours,
        "totalDataBytes": total_data_bytes,
        "total_data_bytes": total_data_bytes,
        "uniqueUsers": unique_users,
        "unique_users": unique_users,
        "uniqueTitles": unique_titles,
        "unique_titles": unique_titles,
        "avgCompletionPct": avg_completion_pct,
        "avg_completion_pct": avg_completion_pct,
        "peakConcurrent": peak_concurrent,
        "peak_concurrent": peak_concurrent,
        "peakBandwidthMbps": peak_bandwidth_mbps,
        "peak_bandwidth_mbps": peak_bandwidth_mbps,
        "transcodeRatioPct": tc_pct,
        "transcode_ratio_pct": tc_pct,
        "streamTypes": stream_types,
        "stream_types": stream_types,
        "directPlayBreakdown": stream_types,
        "direct_play_breakdown": stream_types,
        "mediaTypeBreakdown": media_type_breakdown,
        "media_type_breakdown": media_type_breakdown,
        "resolutionBreakdown": resolution_breakdown,
        "resolution_breakdown": resolution_breakdown,
        "codecBreakdown": codec_breakdown,
        "codec_breakdown": codec_breakdown,
        "timeSeries": time_series,
        "time_series": time_series,
        "hourlyActivity": time_series,
        "hourly_activity": time_series,
        "dailyVolume": time_series,
        "daily_volume": time_series,
        "bandwidthTimeline": time_series,
        "bandwidth_timeline": time_series,
        "topUsers": top_users,
        "top_users": top_users,
        "topTitles": top_titles,
        "top_titles": top_titles,
        "topClients": top_clients,
        "top_clients": top_clients,
        "recentHistory": recent_history,
        "recent_history": recent_history,
    });

    let generated_at = Utc::now().to_rfc3339();
    serde_json::json!({
        "servers": servers,
        "liveSessions": live_sessions,
        "live_sessions": live_sessions,
        "liveSummary": live_summary,
        "live_summary": live_summary,
        "analytics": analytics,
        "window": window_label,
        "windowDays": window_days,
        "window_days": window_days,
        "generatedAt": generated_at,
        "generated_at": generated_at,
    })
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
    let is_admin = req
        .extensions()
        .get::<AuthUser>()
        .map(|u| u.role == "admin")
        .unwrap_or(false);
    let payload = build_streaming_dashboard(window, is_admin).await;
    Json(payload).into_response()
}
