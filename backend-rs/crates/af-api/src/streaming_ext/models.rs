use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub(super) const JELLYFIN_TICKS_PER_SECOND: i64 = 10_000_000;
pub(super) const MAX_UPSTREAM_PAYLOAD_SIZE: usize = 4 * 1024 * 1024; // 4 MB cap for JSON responses
pub(super) const MAX_ARTWORK_PAYLOAD_SIZE: usize = 8 * 1024 * 1024; // 8 MB cap for poster/backdrop images

pub(super) static JELLYFIN_CLIENT: Lazy<Client> = Lazy::new(|| {
    af_services::streaming_http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(16)
        .build()
        .expect("guarded streaming HTTP client")
});

// ──────────────────────────────────────────────────────────────────────────────
// Public Request, Config & Sync Types
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JellyfinSummarySyncOutcome {
    pub imported: usize,
    pub complete: bool,
    pub has_more: bool,
    pub remaining_sources: usize,
    pub next_offset: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct PlexServerConfig {
    pub name: String,
    pub url: String,
    pub api_key: String,
    pub enabled: bool,
    pub expected_server_id: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Upstream Jellyfin Payload Deserialization Types
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinSystemInfo {
    #[serde(default)]
    pub(super) server_name: String,
    #[serde(default)]
    pub(super) version: String,
    #[serde(default)]
    pub(super) id: String,
    #[serde(default)]
    pub(super) operating_system: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinItemCounts {
    #[serde(default)]
    pub(super) movie_count: i32,
    #[serde(default)]
    pub(super) series_count: i32,
    #[serde(default)]
    pub(super) episode_count: i32,
    #[serde(default)]
    pub(super) song_count: i32,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinCapabilitiesRaw {
    #[serde(default)]
    pub(super) supports_media_control: Option<bool>,
    #[serde(default)]
    pub(super) supported_commands: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinPlayStateRaw {
    #[serde(default)]
    pub(super) position_ticks: i64,
    #[serde(default)]
    pub(super) is_paused: bool,
    #[serde(default)]
    pub(super) play_method: String,
    #[serde(default)]
    pub(super) play_session_id: String,
    #[serde(default)]
    pub(super) media_source_id: String,
    #[serde(default)]
    pub(super) audio_stream_index: Option<i32>,
    #[serde(default)]
    pub(super) subtitle_stream_index: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinMediaStreamRaw {
    #[serde(default, rename = "Type")]
    pub(super) stream_type: String,
    #[serde(default)]
    pub(super) index: i32,
    #[serde(default)]
    pub(super) codec: String,
    #[serde(default)]
    pub(super) language: String,
    #[serde(default)]
    pub(super) bit_rate: i64,
    #[serde(default)]
    pub(super) width: i32,
    #[serde(default)]
    pub(super) height: i32,
    #[serde(default)]
    pub(super) video_range: String,
    #[serde(default)]
    pub(super) real_frame_rate: f64,
    #[serde(default)]
    pub(super) channels: i32,
    #[serde(default)]
    pub(super) channel_layout: String,
    #[serde(default)]
    pub(super) is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinNowPlayingItemRaw {
    #[serde(default)]
    pub(super) id: String,
    #[serde(default)]
    pub(super) name: String,
    #[serde(default, rename = "Type")]
    pub(super) item_type: String,
    #[serde(default)]
    pub(super) series_name: String,
    #[serde(default)]
    pub(super) series_id: String,
    #[serde(default)]
    pub(super) parent_index_number: i32,
    #[serde(default)]
    pub(super) index_number: i32,
    #[serde(default)]
    pub(super) production_year: i32,
    #[serde(default)]
    pub(super) run_time_ticks: i64,
    #[serde(default)]
    pub(super) container: String,
    #[serde(default)]
    pub(super) bitrate: i64,
    #[serde(default)]
    pub(super) width: i32,
    #[serde(default)]
    pub(super) height: i32,
    #[serde(default)]
    pub(super) image_tags: HashMap<String, String>,
    #[serde(default)]
    pub(super) series_primary_image_tag: String,
    #[serde(default)]
    pub(super) media_streams: Vec<JellyfinMediaStreamRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinTranscodingInfoRaw {
    #[serde(default)]
    pub(super) container: String,
    #[serde(default)]
    pub(super) is_video_direct: bool,
    #[serde(default)]
    pub(super) is_audio_direct: bool,
    #[serde(default)]
    pub(super) video_codec: String,
    #[serde(default)]
    pub(super) audio_codec: String,
    #[serde(default)]
    pub(super) bitrate: i64,
    #[serde(default)]
    pub(super) framerate: f64,
    #[serde(default)]
    pub(super) completion_percentage: f64,
    #[serde(default)]
    pub(super) hardware_acceleration_type: String,
    #[serde(default)]
    pub(super) transcode_reasons: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinSessionRaw {
    #[serde(default)]
    pub(super) id: String,
    #[serde(default)]
    pub(super) server_id: String,
    #[serde(default)]
    pub(super) user_id: String,
    #[serde(default)]
    pub(super) user_name: String,
    #[serde(default)]
    pub(super) client: String,
    #[serde(default)]
    pub(super) device_name: String,
    #[serde(default)]
    pub(super) device_id: String,
    #[serde(default)]
    pub(super) application_version: String,
    #[serde(default)]
    pub(super) remote_end_point: String,
    #[serde(default)]
    pub(super) supports_media_control: Option<bool>,
    #[serde(default)]
    pub(super) supports_remote_control: Option<bool>,
    #[serde(default)]
    pub(super) supported_commands: Vec<String>,
    #[serde(default)]
    pub(super) capabilities: Option<JellyfinCapabilitiesRaw>,
    #[serde(default)]
    pub(super) play_state: Option<JellyfinPlayStateRaw>,
    #[serde(default)]
    pub(super) now_playing_item: Option<JellyfinNowPlayingItemRaw>,
    #[serde(default)]
    pub(super) transcoding_info: Option<JellyfinTranscodingInfoRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinUserRaw {
    #[serde(default)]
    pub(super) id: String,
    #[serde(default)]
    pub(super) name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinUserDataRaw {
    #[serde(default)]
    pub(super) played: bool,
    #[serde(default)]
    pub(super) playback_position_ticks: i64,
    #[serde(default)]
    pub(super) played_percentage: f64,
    #[serde(default)]
    pub(super) last_played_date: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinHistoryItemRaw {
    #[serde(default)]
    pub(super) id: String,
    #[serde(default)]
    pub(super) name: String,
    #[serde(default, rename = "Type")]
    pub(super) item_type: String,
    #[serde(default)]
    pub(super) series_name: String,
    #[serde(default)]
    pub(super) series_id: String,
    #[serde(default)]
    pub(super) parent_index_number: i32,
    #[serde(default)]
    pub(super) index_number: i32,
    #[serde(default)]
    pub(super) production_year: i32,
    #[serde(default)]
    pub(super) run_time_ticks: i64,
    #[serde(default)]
    pub(super) container: String,
    #[serde(default)]
    pub(super) bitrate: i64,
    #[serde(default)]
    pub(super) width: i32,
    #[serde(default)]
    pub(super) height: i32,
    #[serde(default)]
    pub(super) media_streams: Vec<JellyfinMediaStreamRaw>,
    #[serde(default)]
    pub(super) user_data: Option<JellyfinUserDataRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct JellyfinItemsEnvelope {
    #[serde(default)]
    pub(super) total_record_count: usize,
    #[serde(default)]
    pub(super) items: Vec<JellyfinHistoryItemRaw>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Shared Formatting, Sanitization & HTTP Helpers
// ──────────────────────────────────────────────────────────────────────────────

pub(super) fn sanitize_emby_token(api_key: &str) -> String {
    api_key
        .chars()
        .filter(|&c| c != '"' && c != '\r' && c != '\n' && (c as u32) >= 0x20)
        .collect()
}

pub(super) fn mask_api_key(api_key: &str) -> String {
    if api_key.len() > 4 {
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
    }
}

pub(super) async fn read_bounded_streaming_body(
    mut response: reqwest::Response,
    cap: usize,
) -> anyhow::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > cap as u64)
    {
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

pub(super) fn normalize_artwork_content_type(raw_content_type: &str) -> &'static str {
    match raw_content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "image/jpeg" | "image/jpg" => "image/jpeg",
        "image/png" => "image/png",
        "image/webp" => "image/webp",
        "image/gif" => "image/gif",
        "image/avif" => "image/avif",
        _ => "image/jpeg",
    }
}

pub(super) fn build_artwork_http_response(bytes: Vec<u8>, content_type: &'static str) -> Response {
    let mut resp = Response::new(Body::from(bytes));
    *resp.status_mut() = StatusCode::OK;
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
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

pub(super) fn format_resolution_label(width: i32, height: i32) -> String {
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

pub(super) fn format_audio_layout(channels: i32, layout: &str) -> String {
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

pub(super) fn is_private_or_local_ip(ip: &str) -> bool {
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

pub(super) fn normalize_media_type(raw_type: &str) -> String {
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

pub(super) fn normalize_play_method(raw_method: &str) -> String {
    match raw_method.trim().to_lowercase().as_str() {
        "directplay" | "direct_play" | "direct play" => "DirectPlay".to_string(),
        "directstream" | "direct_stream" | "direct stream" => "DirectStream".to_string(),
        "transcode" | "transcoding" => "Transcode".to_string(),
        "" => String::new(),
        _ => raw_method.trim().to_string(),
    }
}

pub(super) fn resolve_session_capabilities(
    s: &JellyfinSessionRaw,
) -> (bool, bool, bool, Vec<String>) {
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
