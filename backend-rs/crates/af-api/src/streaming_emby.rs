use af_services::{
    ActiveStreamSession, StreamingLibraryCounts, StreamingServerStatus,
};
use axum::http::{header, StatusCode};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use reqwest::Client;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::time::Duration;

pub const EMBY_PROVIDER_ID: &str = "emby";
pub const EMBY_DEFAULT_NAME: &str = "Emby Server";
pub const EMBY_DEFAULT_URL: &str = "http://127.0.0.1:8096";
pub const EMBY_SUPPORT_STAGE: &str = "coming_soon";
pub const EMBY_TICKS_PER_SECOND: i64 = 10_000_000;
pub const MAX_EMBY_JSON_PAYLOAD_BYTES: usize = 4 * 1024 * 1024; // 4 MiB hard cap for JSON payloads
pub const MAX_EMBY_ARTWORK_PAYLOAD_BYTES: usize = 8 * 1024 * 1024; // 8 MiB hard cap for artwork images

static EMBY_HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(16)
        .build()
        .unwrap_or_else(|_| Client::new())
});

// ────────────────────────────────────────────────────────────────────────────
// Public Adapter Contracts & Error Taxonomy
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbyServerConfig {
    pub provider: String,
    pub name: String,
    pub url: String,
    pub api_key: String,
    pub enabled: bool,
    pub expected_server_id: String,
}

impl Default for EmbyServerConfig {
    fn default() -> Self {
        Self {
            provider: EMBY_PROVIDER_ID.to_string(),
            name: EMBY_DEFAULT_NAME.to_string(),
            url: EMBY_DEFAULT_URL.to_string(),
            api_key: String::new(),
            enabled: false,
            expected_server_id: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbyCommandKind {
    Pause,
    Resume,
    Stop,
    Message,
}

impl EmbyCommandKind {
    pub fn parse(raw: &str) -> Result<Self, EmbyAdapterError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pause" => Ok(Self::Pause),
            "resume" | "unpause" => Ok(Self::Resume),
            "stop" => Ok(Self::Stop),
            "message" | "displaymessage" => Ok(Self::Message),
            other => Err(EmbyAdapterError::UnsupportedCommand(format!(
                "unsupported Emby session command: {:?}",
                other
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Stop => "stop",
            Self::Message => "message",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbyCommandTarget {
    pub provider: String,
    pub expected_server_id: String,
    pub session_id: String,
    pub command: String,
    pub header: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbyCommandOutcome {
    pub provider: String,
    pub server_id: String,
    pub session_id: String,
    pub command: String,
    pub delivery_endpoint: String,
    pub active_encoding_stopped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EmbySessionCapabilityEvidence {
    pub supports_media_control: bool,
    pub supports_remote_control: bool,
    pub can_pause: bool,
    pub can_resume: bool,
    pub can_stop: bool,
    pub can_send_message: bool,
    pub supported_commands: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbyOptionalEventCapability {
    pub supported: bool,
    pub verified: bool,
    pub plugin_name: Option<String>,
    pub plugin_version: Option<String>,
    pub status: String,
    pub reason: String,
}

impl Default for EmbyOptionalEventCapability {
    fn default() -> Self {
        Self::unsupported_default()
    }
}

impl EmbyOptionalEventCapability {
    pub fn unsupported_default() -> Self {
        Self {
            supported: false,
            verified: false,
            plugin_name: None,
            plugin_version: None,
            status: "unsupported".to_string(),
            reason: "Optional Emby Playback Reporting event import is unsupported unless real-event schema and plugin endpoints are explicitly proven on the target server.".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbyItemSummaryRecord {
    pub session_key: String,
    pub provider: String,
    pub server_id: String,
    pub server_name: String,
    pub user_id: String,
    pub user_name: String,
    pub item_id: String,
    pub item_name: String,
    pub item_type: String,
    pub series_name: String,
    pub series_id: String,
    pub season_number: i32,
    pub episode_number: i32,
    pub production_year: i32,
    pub container: String,
    pub video_codec: String,
    pub video_resolution: String,
    pub audio_codec: String,
    pub audio_channels: i32,
    pub bitrate_bps: i64,
    pub duration_secs: i64,
    pub watched_secs: i64,
    pub data_used_bytes: i64,
    pub completion_pct: f64,
    pub played_at: String,
    pub has_played_date: bool,
    pub provenance: String,
    pub timestamp_certainty: String,
    pub byte_accuracy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbyArtworkPayload {
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbyAdapterError {
    InvalidUrl(String),
    Unconfigured(String),
    AuthenticationFailed { status: u16, message: String },
    Transport(String),
    PayloadTooLarge { limit_bytes: usize },
    InvalidPayload(String),
    UpstreamStatus { status: u16, message: String },
    WrongIdentity(String),
    SessionNotFound(String),
    CapabilityDenied(String),
    UnsupportedCommand(String),
}

impl std::fmt::Display for EmbyAdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(msg) => write!(f, "invalid Emby server URL: {}", msg),
            Self::Unconfigured(msg) => write!(f, "Emby server unconfigured: {}", msg),
            Self::AuthenticationFailed { status, message } => {
                write!(f, "{} (HTTP {})", message, status)
            }
            Self::Transport(msg) => write!(f, "Emby transport error: {}", msg),
            Self::PayloadTooLarge { limit_bytes } => write!(
                f,
                "Emby upstream response exceeded maximum size limit ({} bytes)",
                limit_bytes
            ),
            Self::InvalidPayload(msg) => write!(f, "invalid Emby upstream payload: {}", msg),
            Self::UpstreamStatus { status, message } => {
                write!(f, "{} (HTTP {})", message, status)
            }
            Self::WrongIdentity(msg) => write!(f, "Emby identity mismatch: {}", msg),
            Self::SessionNotFound(msg) => write!(f, "Emby session not found: {}", msg),
            Self::CapabilityDenied(msg) => write!(f, "Emby capability check failed: {}", msg),
            Self::UnsupportedCommand(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for EmbyAdapterError {}

impl EmbyAdapterError {
    pub fn http_status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::InvalidUrl(_)
            | Self::Unconfigured(_)
            | Self::CapabilityDenied(_)
            | Self::UnsupportedCommand(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            Self::WrongIdentity(_) => (StatusCode::CONFLICT, "IDENTITY_MISMATCH"),
            Self::SessionNotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::AuthenticationFailed { .. }
            | Self::Transport(_)
            | Self::PayloadTooLarge { .. }
            | Self::InvalidPayload(_)
            | Self::UpstreamStatus { .. } => (StatusCode::BAD_GATEWAY, "UPSTREAM_ERROR"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Upstream Emby Wire Models (`MediaBrowser.Model.*` / `MediaBrowser.Controller.Session`)
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct EmbySystemInfoRaw {
    #[serde(default)]
    server_name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    operating_system: String,
    #[serde(default)]
    operating_system_display_name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct EmbyItemCountsRaw {
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
struct EmbyClientCapabilitiesRaw {
    #[serde(default)]
    supports_media_control: Option<bool>,
    #[serde(default)]
    supported_commands: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct EmbyPlayStateRaw {
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
struct EmbyMediaStreamRaw {
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
    color_transfer: String,
    #[serde(default)]
    real_frame_rate: f64,
    #[serde(default)]
    average_frame_rate: f64,
    #[serde(default)]
    channels: i32,
    #[serde(default)]
    channel_layout: String,
    #[serde(default)]
    is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct EmbyNowPlayingItemRaw {
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
     primary_image_tag: String,
    #[serde(default)]
    primary_image_item_id: String,
    #[serde(default)]
    series_primary_image_tag: String,
    #[serde(default)]
    backdrop_image_tags: Vec<String>,
    #[serde(default)]
    backdrop_image_tag: String,
    #[serde(default)]
    backdrop_item_id: String,
    #[serde(default)]
    media_streams: Vec<EmbyMediaStreamRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct EmbyTranscodingInfoRaw {
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
    video_encoder_hw_accel: String,
    #[serde(default)]
    video_decoder_hw_accel: String,
    #[serde(default)]
    video_encoder_is_hardware: bool,
    #[serde(default)]
    video_decoder_is_hardware: bool,
    #[serde(default)]
    hardware_acceleration_type: String,
    #[serde(default)]
    transcode_reasons: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct EmbySessionRaw {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub server_id: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub application_version: String,
    #[serde(default)]
    pub remote_end_point: String,
    #[serde(default)]
    pub supports_media_control: Option<bool>,
    #[serde(default)]
    pub supports_remote_control: Option<bool>,
    #[serde(default)]
    pub supported_commands: Vec<String>,
    #[serde(default)]
    capabilities: Option<EmbyClientCapabilitiesRaw>,
    #[serde(default)]
    play_state: Option<EmbyPlayStateRaw>,
    #[serde(default)]
    now_playing_item: Option<EmbyNowPlayingItemRaw>,
    #[serde(default)]
    transcoding_info: Option<EmbyTranscodingInfoRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct EmbyUserRaw {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct EmbyUserDataRaw {
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
struct EmbyHistoryItemRaw {
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
    media_streams: Vec<EmbyMediaStreamRaw>,
    #[serde(default)]
    user_data: Option<EmbyUserDataRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct EmbyItemsEnvelopeRaw {
    #[serde(default)]
    total_record_count: usize,
    #[serde(default)]
    items: Vec<EmbyHistoryItemRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct EmbyPluginInfoRaw {
    #[serde(default)]
    #[allow(dead_code)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
}

// ────────────────────────────────────────────────────────────────────────────
// Configuration & Safe Bounded Transport Helpers
// ────────────────────────────────────────────────────────────────────────────

pub fn resolve_default_emby_url() -> String {
    if let Ok(env_url) = env::var("EMBY_URL") {
        let trimmed = env_url.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(Some(cfg)) = af_db::get_app_ingress_config(EMBY_PROVIDER_ID) {
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
        return format!("https://emby.{}", base_dom);
    }
    EMBY_DEFAULT_URL.to_string()
}

pub fn get_stored_emby_config() -> EmbyServerConfig {
    let mut cfg = EmbyServerConfig {
        provider: EMBY_PROVIDER_ID.to_string(),
        name: EMBY_DEFAULT_NAME.to_string(),
        url: resolve_default_emby_url(),
        api_key: env::var("EMBY_API_KEY")
            .unwrap_or_default()
            .trim()
            .to_string(),
        enabled: false,
        expected_server_id: String::new(),
    };

    if let Ok(conn) = af_db::get_conn() {
        if let Ok((db_name, db_url, db_key, db_enabled, db_srv_id)) = conn.query_row(
            "SELECT name, url, api_key, enabled, COALESCE(server_id, '') FROM streaming_servers WHERE provider = 'emby'",
            [],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        ) {
            if !db_name.trim().is_empty() {
                cfg.name = db_name.trim().to_string();
            }
            if !db_url.trim().is_empty() {
                cfg.url = db_url.trim().trim_end_matches('/').to_string();
            }
            cfg.enabled = db_enabled;
            cfg.expected_server_id = db_srv_id.trim().to_string();
            if !db_key.is_empty() {
                match af_db::decrypt_key(&db_key) {
                    Ok(dec) if !dec.is_empty() => cfg.api_key = dec,
                    _ if !db_key.starts_with("enc:v1:") => cfg.api_key = db_key,
                    _ => {
                        tracing::warn!(
                            "failed to decrypt stored Emby API key; refusing ciphertext fallback"
                        );
                        cfg.api_key.clear();
                    }
                }
            }
        }
    }

    cfg
}

pub fn validate_emby_server_url(raw_url: &str) -> Result<String, EmbyAdapterError> {
    let clean = af_services::validate_server_url(raw_url)
        .map_err(|e| EmbyAdapterError::InvalidUrl(e.to_string()))?;
    let parsed = url::Url::parse(&clean)
        .map_err(|_| EmbyAdapterError::InvalidUrl("Invalid server URL format".to_string()))?;
    let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || !host.contains(':') {
        // Additional defense-in-depth check on path segments (prevent path traversal in base URL)
        if parsed.path().contains("..") || parsed.path().contains('\\') {
            return Err(EmbyAdapterError::InvalidUrl(
                "URL path must not contain traversal sequences".to_string(),
            ));
        }
    }
    Ok(clean.trim_end_matches('/').to_string())
}

pub fn sanitize_emby_token(api_key: &str) -> String {
    api_key
        .chars()
        .filter(|&c| c != '"' && c != '\r' && c != '\n' && (c as u32) >= 0x20)
        .collect::<String>()
        .trim()
        .to_string()
}

pub fn mask_emby_api_key(api_key: &str) -> String {
    let clean = sanitize_emby_token(api_key);
    let char_count = clean.chars().count();
    if char_count > 4 {
        let tail: String = clean
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("****{}", tail)
    } else if !clean.is_empty() {
        "****".to_string()
    } else {
        String::new()
    }
}

fn build_emby_authorization_header(clean_token: &str) -> String {
    format!(
        "Emby Client=\"AetherFlow\", Device=\"Nexus\", DeviceId=\"aetherflow-nexus\", Version=\"4.0\", Token=\"{}\"",
        clean_token
    )
}

async fn do_emby_request(
    method: reqwest::Method,
    full_url: &str,
    api_key: &str,
    json_body: Option<serde_json::Value>,
    timeout: Duration,
    max_bytes: usize,
) -> Result<(Vec<u8>, StatusCode, String), EmbyAdapterError> {
    let mut req = EMBY_HTTP_CLIENT
        .request(method, full_url)
        .timeout(timeout)
        .header(header::ACCEPT, "application/json");

    let clean_token = sanitize_emby_token(api_key);
    if !clean_token.is_empty() {
        let auth_val = build_emby_authorization_header(&clean_token);
        req = req
            .header("X-Emby-Token", &clean_token)
            .header("X-Emby-Authorization", &auth_val)
            .header(header::AUTHORIZATION, auth_val);
    }

    if let Some(body) = json_body {
        req = req.json(&body);
    }

    let mut resp = req
        .send()
        .await
        .map_err(|e| EmbyAdapterError::Transport(e.to_string()))?;

    let status = resp.status();
    if status.is_redirection() {
        return Err(EmbyAdapterError::Transport(format!(
            "Upstream redirect (HTTP {}) is disallowed",
            status.as_u16()
        )));
    }

    if let Some(content_len) = resp.content_length() {
        if content_len > max_bytes as u64 {
            return Err(EmbyAdapterError::PayloadTooLarge {
                limit_bytes: max_bytes,
            });
        }
    }

    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| EmbyAdapterError::Transport(e.to_string()))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(EmbyAdapterError::PayloadTooLarge {
                limit_bytes: max_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }

    Ok((body, status, content_type))
}

// ────────────────────────────────────────────────────────────────────────────
// Normalization & Capability Resolution Helpers
// ────────────────────────────────────────────────────────────────────────────

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

pub fn normalize_emby_media_type(raw_type: &str) -> String {
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

pub fn normalize_emby_play_method(raw_method: &str) -> String {
    match raw_method.trim().to_lowercase().as_str() {
        "directplay" | "direct_play" | "direct play" => "DirectPlay".to_string(),
        "directstream" | "direct_stream" | "direct stream" => "DirectStream".to_string(),
        "transcode" | "transcoding" => "Transcode".to_string(),
        "" => String::new(),
        _ => raw_method.trim().to_string(),
    }
}

fn infer_video_range(video_range: &str, color_transfer: &str) -> String {
    let vr = video_range.trim();
    if !vr.is_empty() {
        return vr.to_string();
    }
    match color_transfer.trim().to_ascii_lowercase().as_str() {
        "smpte2084" => "HDR10".to_string(),
        "arib-std-b67" => "HLG".to_string(),
        "bt709" | "smpte170m" | "bt470bg" => "SDR".to_string(),
        _ => String::new(),
    }
}

fn extract_emby_hw_accel(ti: &EmbyTranscodingInfoRaw) -> String {
    for candidate in [
        ti.video_encoder_hw_accel.trim(),
        ti.video_decoder_hw_accel.trim(),
        ti.hardware_acceleration_type.trim(),
    ] {
        if !candidate.is_empty() && !candidate.eq_ignore_ascii_case("none") {
            return candidate.to_uppercase();
        }
    }
    if ti.video_encoder_is_hardware || ti.video_decoder_is_hardware {
        return "HARDWARE".to_string();
    }
    String::new()
}

/// Evaluates Emby session capabilities strictly fail-closed:
/// - Never guesses or invents `supports_media_control` when upstream omits capability booleans.
/// - `SupportsMediaControl` (or `Capabilities.SupportsMediaControl` or `SupportsRemoteControl`) must
///   be explicitly `Some(true)` on the fresh session payload for any control command.
/// - `can_pause`, `can_resume`, and `can_stop` additionally require an active `NowPlayingItem`.
/// - `can_send_message` requires `supports_media_control && supports_remote_control` AND explicit
///   presence of `"DisplayMessage"` in `SupportedCommands` (never assumed when `SupportedCommands` is empty).
pub fn resolve_emby_session_capabilities(s: &EmbySessionRaw) -> EmbySessionCapabilityEvidence {
    let raw_cmds = if !s.supported_commands.is_empty() {
        &s.supported_commands
    } else if let Some(ref cap) = s.capabilities {
        &cap.supported_commands
    } else {
        &s.supported_commands
    };

    let mut supported_commands = Vec::new();
    for cmd in raw_cmds {
        let trimmed = cmd.trim();
        if !trimmed.is_empty()
            && !supported_commands
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(trimmed))
        {
            supported_commands.push(trimmed.to_string());
        }
    }

    let explicit_media_ctrl = s
        .supports_media_control
        .or_else(|| s.capabilities.as_ref().and_then(|c| c.supports_media_control));

    // In Emby's SessionInfo serializer, `Capabilities` has [IgnoreDataMember] and top-level
    // `SupportsRemoteControl` + `SupportedCommands` are serialized, whereas some Emby builds/proxies
    // also serialize `SupportsMediaControl` or `Capabilities.SupportsMediaControl`.
    // If `SupportsMediaControl` is explicitly false, fail closed even if `SupportsRemoteControl` is true.
    let supports_media_control = match explicit_media_ctrl {
        Some(false) => false,
        Some(true) => s.supports_remote_control.unwrap_or(true),
        None => s.supports_remote_control == Some(true),
    };

    let supports_remote_control = match s.supports_remote_control {
        Some(false) => false,
        Some(true) => explicit_media_ctrl.unwrap_or(true),
        None => explicit_media_ctrl == Some(true),
    };

    let has_active_playing_item = s
        .now_playing_item
        .as_ref()
        .map(|item| !item.id.trim().is_empty() || !item.name.trim().is_empty())
        .unwrap_or(false);

    let can_control_playback =
        supports_media_control && supports_remote_control && has_active_playing_item;

    let has_display_message = supported_commands
        .iter()
        .any(|c| c.eq_ignore_ascii_case("DisplayMessage"));

    let can_send_message =
        supports_media_control && supports_remote_control && has_display_message;

    EmbySessionCapabilityEvidence {
        supports_media_control,
        supports_remote_control,
        can_pause: can_control_playback,
        can_resume: can_control_playback,
        can_stop: can_control_playback,
        can_send_message,
        supported_commands,
    }
}

pub fn normalize_emby_session(
    s: EmbySessionRaw,
    server_name: &str,
    expected_server_id: Option<&str>,
    tracked_lookup: Option<&HashMap<String, (i64, String)>>,
) -> Result<Option<ActiveStreamSession>, EmbyAdapterError> {
    let expected_sid = expected_server_id.unwrap_or("").trim();
    let actual_sid = s.server_id.trim();
    if !expected_sid.is_empty()
        && !actual_sid.is_empty()
        && !actual_sid.eq_ignore_ascii_case(expected_sid)
    {
        return Err(EmbyAdapterError::WrongIdentity(format!(
            "Emby session {:?} reported ServerId {:?}, expected {:?}",
            s.id, actual_sid, expected_sid
        )));
    }

    let Some(ref item) = s.now_playing_item else {
        return Ok(None);
    };
    let clean_session_id = s.id.trim().to_string();
    let clean_item_id = item.id.trim().to_string();
    if clean_session_id.is_empty() || (clean_item_id.is_empty() && item.name.trim().is_empty()) {
        return Ok(None);
    }

    let cap = resolve_emby_session_capabilities(&s);

    let mut pos_secs = 0i64;
    let mut is_paused = false;
    let mut play_method = String::new();
    let mut play_session_id = String::new();
    let mut media_source_id = String::new();
    if let Some(ref ps) = s.play_state {
        pos_secs = (ps.position_ticks / EMBY_TICKS_PER_SECOND).max(0);
        is_paused = ps.is_paused;
        play_method = normalize_emby_play_method(&ps.play_method);
        play_session_id = ps.play_session_id.trim().to_string();
        media_source_id = ps.media_source_id.trim().to_string();
    }

    let dur_secs = (item.run_time_ticks / EMBY_TICKS_PER_SECOND).max(0);
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
        match ms.stream_type.trim() {
            "Video" => {
                if video_codec.is_empty() {
                    video_codec = ms.codec.trim().to_uppercase();
                    if ms.width > 0 {
                        video_width = ms.width;
                    }
                    if ms.height > 0 {
                        video_height = ms.height;
                    }
                    video_range = infer_video_range(&ms.video_range, &ms.color_transfer);
                    let fps = if ms.real_frame_rate > 0.0 {
                        ms.real_frame_rate
                    } else {
                        ms.average_frame_rate
                    };
                    if fps > 0.0 {
                        video_framerate = (fps * 100.0).round() / 100.0;
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
                    audio_codec = ms.codec.trim().to_uppercase();
                    audio_channels = ms.channels.max(0);
                    audio_layout = ms.channel_layout.clone();
                    audio_language = ms.language.trim().to_uppercase();
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
                    subtitle_codec = ms.codec.trim().to_uppercase();
                    subtitle_language = ms.language.trim().to_uppercase();
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
        target_container = ti.container.trim().to_uppercase();
        if !ti.video_codec.trim().is_empty() {
            target_video_codec = ti.video_codec.trim().to_uppercase();
        }
        if !ti.audio_codec.trim().is_empty() {
            target_audio_codec = ti.audio_codec.trim().to_uppercase();
        }
        hw_accel = extract_emby_hw_accel(ti);
        if !ti.transcode_reasons.is_empty() {
            transcode_reasons = ti.transcode_reasons.clone();
        }
        transcode_progress_pct = (ti.completion_percentage.max(0.0) * 10.0).round() / 10.0;
        transcode_fps = (ti.framerate.max(0.0) * 10.0).round() / 10.0;
        if ti.bitrate > 0 {
            active_bitrate = ti.bitrate;
        }
        if !ti.is_video_direct {
            play_method = "Transcode".to_string();
        } else if (play_method.is_empty() || play_method == "DirectPlay")
            && (!ti.is_audio_direct || !target_container.is_empty())
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

    let mut artwork_item_id = clean_item_id.clone();
    let mut has_artwork = false;
    if item
        .image_tags
        .get("Primary")
        .map(|t| !t.trim().is_empty())
        .unwrap_or(false)
    {
        has_artwork = true;
    } else if !item.primary_image_tag.trim().is_empty() {
        if !item.primary_image_item_id.trim().is_empty() {
            artwork_item_id = item.primary_image_item_id.trim().to_string();
        }
        has_artwork = true;
    } else if !item.series_id.trim().is_empty() && !item.series_primary_image_tag.trim().is_empty() {
        artwork_item_id = item.series_id.trim().to_string();
        has_artwork = true;
    } else if !item.backdrop_image_tags.is_empty() || !item.backdrop_image_tag.trim().is_empty() {
        if !item.backdrop_item_id.trim().is_empty() {
            artwork_item_id = item.backdrop_item_id.trim().to_string();
        }
        has_artwork = true;
    }

    let state_str = if is_paused { "paused" } else { "playing" }.to_string();
    let session_key = format!("{}:{}:{}", EMBY_PROVIDER_ID, clean_session_id, clean_item_id);
    let mut session_data_bytes = 0i64;
    let mut started_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    if let Some(map) = tracked_lookup {
        if let Some((tracked_bytes, tracked_start)) = map.get(&session_key) {
            session_data_bytes = (*tracked_bytes).max(0);
            if !tracked_start.trim().is_empty() {
                started_at = tracked_start.clone();
            }
        }
    } else if let Ok(conn) = af_db::get_conn() {
        if let Ok((tracked, tracked_start)) = conn.query_row(
            "SELECT data_used_bytes, COALESCE(started_at, '') FROM streaming_history WHERE session_key = ?1",
            params![session_key],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        ) {
            session_data_bytes = tracked.max(0);
            if !tracked_start.trim().is_empty() {
                started_at = tracked_start;
            }
        }
    }

    let resolved_server_name = if server_name.trim().is_empty() {
        EMBY_DEFAULT_NAME.to_string()
    } else {
        server_name.trim().to_string()
    };

    Ok(Some(ActiveStreamSession {
        session_id: clean_session_id,
        provider: EMBY_PROVIDER_ID.to_string(),
        server_name: resolved_server_name,
        user_id: s.user_id.trim().to_string(),
        user_name: s.user_name.trim().to_string(),
        client_name: s.client.trim().to_string(),
        device_name: s.device_name.trim().to_string(),
        device_id: s.device_id.trim().to_string(),
        app_version: s.application_version.trim().to_string(),
        ip_address: s.remote_end_point.trim().to_string(),
        is_lan: is_private_or_local_ip(&s.remote_end_point),
        item_id: clean_item_id,
        item_name: item.name.trim().to_string(),
        item_type: normalize_emby_media_type(&item.item_type),
        series_name: item.series_name.trim().to_string(),
        series_id: item.series_id.trim().to_string(),
        season_number: item.parent_index_number,
        episode_number: item.index_number,
        production_year: item.production_year,
        has_artwork,
        artwork_item_id: if has_artwork { artwork_item_id } else { String::new() },
        state: state_str,
        position_secs: pos_secs,
        duration_secs: dur_secs,
        progress_pct,
        play_method,
        container: item.container.trim().to_uppercase(),
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
        supports_media_control: cap.supports_media_control,
        supports_remote_control: cap.supports_remote_control,
        can_send_message: cap.can_send_message,
        supported_commands: cap.supported_commands,
    }))
}

// ────────────────────────────────────────────────────────────────────────────
// 1. Server Connection Validation (`/System/Info`, `/Items/Counts`, `/System/Info/Public`)
// ────────────────────────────────────────────────────────────────────────────

/// Validates connectivity and authentication against an Emby server without mutating the database.
/// Keeps `support_stage: "coming_soon"` until real-instance acceptance is completed and authorized.
pub async fn test_emby_connection(
    server_url: &str,
    api_key: &str,
    expected_server_id: Option<&str>,
) -> Result<StreamingServerStatus, EmbyAdapterError> {
    let clean_url = validate_emby_server_url(server_url)?;
    let clean_key = sanitize_emby_token(api_key);
    let masked_key = mask_emby_api_key(&clean_key);
    let expected_sid = expected_server_id.unwrap_or("").trim();

    let mut status = StreamingServerStatus {
        provider: EMBY_PROVIDER_ID.to_string(),
        name: EMBY_DEFAULT_NAME.to_string(),
        url: clean_url.clone(),
        api_key_masked: masked_key,
        configured: !clean_key.is_empty(),
        enabled: false,
        status: "unconfigured".to_string(),
        support_stage: EMBY_SUPPORT_STAGE.to_string(),
        server_id: String::new(),
        version: String::new(),
        operating_system: String::new(),
        last_connected_at: String::new(),
        library_counts: StreamingLibraryCounts::default(),
        error_message: String::new(),
    };

    if !clean_key.is_empty() {
        let (body, code, _) = do_emby_request(
            reqwest::Method::GET,
            &format!("{}/System/Info", clean_url),
            &clean_key,
            None,
            Duration::from_secs(6),
            MAX_EMBY_JSON_PAYLOAD_BYTES,
        )
        .await?;

        if code == StatusCode::UNAUTHORIZED || code == StatusCode::FORBIDDEN {
            return Err(EmbyAdapterError::AuthenticationFailed {
                status: code.as_u16(),
                message: "Invalid Emby API key".to_string(),
            });
        }
        if !code.is_success() {
            return Err(EmbyAdapterError::UpstreamStatus {
                status: code.as_u16(),
                message: "Emby /System/Info request failed".to_string(),
            });
        }

        let sys_info: EmbySystemInfoRaw = serde_json::from_slice(&body).map_err(|e| {
            EmbyAdapterError::InvalidPayload(format!("malformed Emby /System/Info JSON: {}", e))
        })?;

        let actual_sid = sys_info.id.trim();
        if actual_sid.is_empty() {
            return Err(EmbyAdapterError::InvalidPayload(
                "Emby /System/Info response is missing server Id".to_string(),
            ));
        }
        if !expected_sid.is_empty() && !actual_sid.eq_ignore_ascii_case(expected_sid) {
            return Err(EmbyAdapterError::WrongIdentity(format!(
                "expected Emby server_id {:?}, but /System/Info reported {:?}",
                expected_sid, actual_sid
            )));
        }

        if !sys_info.server_name.trim().is_empty() {
            status.name = sys_info.server_name.trim().to_string();
        }
        status.version = sys_info.version.trim().to_string();
        status.server_id = actual_sid.to_string();
        status.operating_system = if !sys_info.operating_system_display_name.trim().is_empty() {
            sys_info.operating_system_display_name.trim().to_string()
        } else {
            sys_info.operating_system.trim().to_string()
        };

        if let Ok((counts_body, StatusCode::OK, _)) = do_emby_request(
            reqwest::Method::GET,
            &format!("{}/Items/Counts", clean_url),
            &clean_key,
            None,
            Duration::from_secs(6),
            MAX_EMBY_JSON_PAYLOAD_BYTES,
        )
        .await
        {
            if let Ok(counts) = serde_json::from_slice::<EmbyItemCountsRaw>(&counts_body) {
                status.library_counts = StreamingLibraryCounts {
                    movies: counts.movie_count.max(0),
                    series: counts.series_count.max(0),
                    episodes: counts.episode_count.max(0),
                    audio: counts.song_count.max(0),
                };
            }
        }

        status.status = "connected".to_string();
        status.last_connected_at = Utc::now().to_rfc3339();
        return Ok(status);
    }

    // Unauthenticated public discovery probe (/System/Info/Public)
    match do_emby_request(
        reqwest::Method::GET,
        &format!("{}/System/Info/Public", clean_url),
        "",
        None,
        Duration::from_secs(6),
        MAX_EMBY_JSON_PAYLOAD_BYTES,
    )
    .await
    {
        Ok((body, StatusCode::OK, _)) => {
            let pub_info: EmbySystemInfoRaw = serde_json::from_slice(&body).map_err(|e| {
                EmbyAdapterError::InvalidPayload(format!(
                    "malformed Emby /System/Info/Public JSON: {}",
                    e
                ))
            })?;
            let actual_sid = pub_info.id.trim();
            if !expected_sid.is_empty()
                && !actual_sid.is_empty()
                && !actual_sid.eq_ignore_ascii_case(expected_sid)
            {
                return Err(EmbyAdapterError::WrongIdentity(format!(
                    "expected Emby server_id {:?}, but /System/Info/Public reported {:?}",
                    expected_sid, actual_sid
                )));
            }
            if !pub_info.server_name.trim().is_empty() {
                status.name = pub_info.server_name.trim().to_string();
            }
            status.version = pub_info.version.trim().to_string();
            status.server_id = actual_sid.to_string();
            status.status = "unconfigured".to_string();
            status.error_message = format!(
                "Emby detected at {} — add an API Key to enable telemetry",
                clean_url
            );
            Ok(status)
        }
        _ => Err(EmbyAdapterError::Unconfigured(
            "Emby API key is not configured".to_string(),
        )),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 2. Live Session Fetching & Normalization (`GET /Sessions`)
// ────────────────────────────────────────────────────────────────────────────

pub async fn fetch_emby_live_sessions(
    server_name: &str,
    server_url: &str,
    api_key: &str,
    expected_server_id: Option<&str>,
) -> Result<Vec<ActiveStreamSession>, EmbyAdapterError> {
    let clean_key = sanitize_emby_token(api_key);
    if clean_key.is_empty() {
        return Err(EmbyAdapterError::Unconfigured(
            "Emby API key is not configured".to_string(),
        ));
    }
    let clean_url = validate_emby_server_url(server_url)?;

    let (body, code, _) = do_emby_request(
        reqwest::Method::GET,
        &format!("{}/Sessions", clean_url),
        &clean_key,
        None,
        Duration::from_secs(6),
        MAX_EMBY_JSON_PAYLOAD_BYTES,
    )
    .await?;

    if code == StatusCode::UNAUTHORIZED || code == StatusCode::FORBIDDEN {
        return Err(EmbyAdapterError::AuthenticationFailed {
            status: code.as_u16(),
            message: "Emby /Sessions rejected API key".to_string(),
        });
    }
    if !code.is_success() {
        return Err(EmbyAdapterError::UpstreamStatus {
            status: code.as_u16(),
            message: "Emby /Sessions request failed".to_string(),
        });
    }

    let raw_sessions: Vec<EmbySessionRaw> = serde_json::from_slice(&body).map_err(|e| {
        EmbyAdapterError::InvalidPayload(format!("malformed Emby /Sessions JSON: {}", e))
    })?;

    let mut active = Vec::new();
    for raw in raw_sessions {
        if let Some(normalized) =
            normalize_emby_session(raw, server_name, expected_server_id, None)?
        {
            active.push(normalized);
        }
    }

    Ok(active)
}

// ────────────────────────────────────────────────────────────────────────────
// 3. Authenticated Fresh Capability-Gated Session Control
// ────────────────────────────────────────────────────────────────────────────

/// Issues a remote control command to an Emby session ONLY after verifying:
/// 1. Target `provider` is explicitly `"emby"`.
/// 2. Target `session_id` is non-empty and never bypasses verification (no `demo-` shortcut).
/// 3. If `expected_server_id` is provided, fresh server/session identity matches before any POST.
/// 4. Fresh authenticated `GET /Sessions` succeeds and contains the exact `session_id`.
/// 5. Command-specific capability evidence on the fresh session explicitly permits the command.
pub async fn send_emby_session_command(
    server_url: &str,
    api_key: &str,
    target: &EmbyCommandTarget,
) -> Result<EmbyCommandOutcome, EmbyAdapterError> {
    if !target.provider.trim().eq_ignore_ascii_case(EMBY_PROVIDER_ID) {
        return Err(EmbyAdapterError::WrongIdentity(format!(
            "target provider {:?} does not match Emby adapter ({:?})",
            target.provider, EMBY_PROVIDER_ID
        )));
    }

    let clean_session_id = target.session_id.trim();
    if clean_session_id.is_empty()
        || clean_session_id.len() > 128
        || clean_session_id.contains('/')
        || clean_session_id.contains('\\')
        || clean_session_id.contains("..")
    {
        return Err(EmbyAdapterError::SessionNotFound(
            "valid Emby session_id is required".to_string(),
        ));
    }

    let cmd_kind = EmbyCommandKind::parse(&target.command)?;
    let hdr = target.header.trim();
    let msg = target.message.trim();
    if hdr.len() > 120 || msg.len() > 1000 {
        return Err(EmbyAdapterError::UnsupportedCommand(
            "header (max 120 chars) or message (max 1000 chars) exceeds maximum length"
                .to_string(),
        ));
    }
    if cmd_kind == EmbyCommandKind::Message && msg.is_empty() {
        return Err(EmbyAdapterError::UnsupportedCommand(
            "message text is required when command is message".to_string(),
        ));
    }

    let clean_key = sanitize_emby_token(api_key);
    if clean_key.is_empty() {
        return Err(EmbyAdapterError::Unconfigured(
            "Emby API key is not configured".to_string(),
        ));
    }
    let clean_url = validate_emby_server_url(server_url)?;
    let expected_sid = target.expected_server_id.trim();

    // Fresh authenticated GET /Sessions capability check (fail closed on any transport/status/parse error)
    let (sess_body, sess_code, _) = do_emby_request(
        reqwest::Method::GET,
        &format!("{}/Sessions", clean_url),
        &clean_key,
        None,
        Duration::from_secs(4),
        MAX_EMBY_JSON_PAYLOAD_BYTES,
    )
    .await?;

    if sess_code == StatusCode::UNAUTHORIZED || sess_code == StatusCode::FORBIDDEN {
        return Err(EmbyAdapterError::AuthenticationFailed {
            status: sess_code.as_u16(),
            message: "Emby /Sessions authentication failed; command denied".to_string(),
        });
    }
    if !sess_code.is_success() {
        return Err(EmbyAdapterError::UpstreamStatus {
            status: sess_code.as_u16(),
            message: "Fresh Emby session capabilities could not be loaded; command denied"
                .to_string(),
        });
    }

    let raw_sessions: Vec<EmbySessionRaw> = serde_json::from_slice(&sess_body).map_err(|e| {
        EmbyAdapterError::InvalidPayload(format!(
            "Fresh Emby /Sessions payload could not be parsed ({}); command denied",
            e
        ))
    })?;

    let Some(target_session) = raw_sessions
        .into_iter()
        .find(|s| s.id.trim() == clean_session_id)
    else {
        return Err(EmbyAdapterError::SessionNotFound(format!(
            "session {:?} not found on Emby server",
            clean_session_id
        )));
    };

    let mut verified_server_id = target_session.server_id.trim().to_string();
    if !expected_sid.is_empty() {
        if !verified_server_id.is_empty() {
            if !verified_server_id.eq_ignore_ascii_case(expected_sid) {
                return Err(EmbyAdapterError::WrongIdentity(format!(
                    "session {:?} belongs to Emby ServerId {:?}, expected {:?}",
                    clean_session_id, verified_server_id, expected_sid
                )));
            }
        } else {
            // Session payload omitted ServerId; verify server identity via /System/Info before sending command
            let (info_body, info_code, _) = do_emby_request(
                reqwest::Method::GET,
                &format!("{}/System/Info", clean_url),
                &clean_key,
                None,
                Duration::from_secs(4),
                MAX_EMBY_JSON_PAYLOAD_BYTES,
            )
            .await?;
            if !info_code.is_success() {
                return Err(EmbyAdapterError::UpstreamStatus {
                    status: info_code.as_u16(),
                    message: "Could not verify Emby ServerId via /System/Info; command denied"
                        .to_string(),
                });
            }
            let sys_info: EmbySystemInfoRaw = serde_json::from_slice(&info_body).map_err(|e| {
                EmbyAdapterError::InvalidPayload(format!(
                    "Malformed Emby /System/Info response during identity check: {}",
                    e
                ))
            })?;
            let actual_info_sid = sys_info.id.trim();
            if actual_info_sid.is_empty() || !actual_info_sid.eq_ignore_ascii_case(expected_sid) {
                return Err(EmbyAdapterError::WrongIdentity(format!(
                    "Emby server reported ServerId {:?}, expected {:?}",
                    actual_info_sid, expected_sid
                )));
            }
            verified_server_id = actual_info_sid.to_string();
        }
    }

    let cap = resolve_emby_session_capabilities(&target_session);
    if !cap.supports_media_control || !cap.supports_remote_control {
        return Err(EmbyAdapterError::CapabilityDenied(format!(
            "client {:?} ({}) does not permit remote media control (SupportsMediaControl/SupportsRemoteControl is false or missing)",
            target_session.client, target_session.device_name
        )));
    }

    let escaped_id = urlencoding::encode(clean_session_id);
    let mut json_payload: Option<serde_json::Value> = None;

    let endpoint = match cmd_kind {
        EmbyCommandKind::Pause => {
            if !cap.can_pause {
                return Err(EmbyAdapterError::CapabilityDenied(format!(
                    "session {:?} has no active NowPlayingItem to pause",
                    clean_session_id
                )));
            }
            format!("{}/Sessions/{}/Playing/Pause", clean_url, escaped_id)
        }
        EmbyCommandKind::Resume => {
            if !cap.can_resume {
                return Err(EmbyAdapterError::CapabilityDenied(format!(
                    "session {:?} has no active NowPlayingItem to resume",
                    clean_session_id
                )));
            }
            format!("{}/Sessions/{}/Playing/Unpause", clean_url, escaped_id)
        }
        EmbyCommandKind::Stop => {
            if !cap.can_stop {
                return Err(EmbyAdapterError::CapabilityDenied(format!(
                    "session {:?} has no active NowPlayingItem to stop",
                    clean_session_id
                )));
            }
            format!("{}/Sessions/{}/Playing/Stop", clean_url, escaped_id)
        }
        EmbyCommandKind::Message => {
            if !cap.can_send_message {
                return Err(EmbyAdapterError::CapabilityDenied(format!(
                    "client {:?} ({}) does not list DisplayMessage in SupportedCommands",
                    target_session.client, target_session.device_name
                )));
            }
            let resolved_header = if hdr.is_empty() {
                "AetherFlow Administrator"
            } else {
                hdr
            };
            json_payload = Some(serde_json::json!({
                "Header": resolved_header,
                "Text": msg,
            }));
            format!("{}/Sessions/{}/Message", clean_url, escaped_id)
        }
    };

    let (_, cmd_code, _) = do_emby_request(
        reqwest::Method::POST,
        &endpoint,
        &clean_key,
        json_payload,
        Duration::from_secs(6),
        MAX_EMBY_JSON_PAYLOAD_BYTES,
    )
    .await?;

    if cmd_code == StatusCode::UNAUTHORIZED || cmd_code == StatusCode::FORBIDDEN {
        return Err(EmbyAdapterError::AuthenticationFailed {
            status: cmd_code.as_u16(),
            message: format!("Emby command {:?} rejected authentication", cmd_kind.as_str()),
        });
    }
    if !cmd_code.is_success() {
        return Err(EmbyAdapterError::UpstreamStatus {
            status: cmd_code.as_u16(),
            message: format!(
                "Emby command {:?} failed",
                cmd_kind.as_str()
            ),
        });
    }

    let device_id = target_session.device_id.trim();
    let play_session_id = target_session
        .play_state
        .as_ref()
        .map(|ps| ps.play_session_id.trim())
        .unwrap_or("");
    let has_active_transcode = target_session.transcoding_info.is_some()
        || !play_session_id.is_empty()
        || target_session
            .play_state
            .as_ref()
            .map(|ps| ps.play_method.eq_ignore_ascii_case("Transcode"))
            .unwrap_or(false);

    let mut active_encoding_stopped = false;
    if cmd_kind == EmbyCommandKind::Stop && !device_id.is_empty() && has_active_transcode {
        let enc_url = if play_session_id.is_empty() {
            format!(
                "{}/Videos/ActiveEncodings?DeviceId={}",
                clean_url,
                urlencoding::encode(device_id)
            )
        } else {
            format!(
                "{}/Videos/ActiveEncodings?DeviceId={}&PlaySessionId={}",
                clean_url,
                urlencoding::encode(device_id),
                urlencoding::encode(play_session_id)
            )
        };
        if let Ok((_, enc_code, _)) = do_emby_request(
            reqwest::Method::DELETE,
            &enc_url,
            &clean_key,
            None,
            Duration::from_secs(4),
            MAX_EMBY_JSON_PAYLOAD_BYTES,
        )
        .await
        {
            active_encoding_stopped = enc_code.is_success();
        }
    }

    Ok(EmbyCommandOutcome {
        provider: EMBY_PROVIDER_ID.to_string(),
        server_id: verified_server_id,
        session_id: clean_session_id.to_string(),
        command: cmd_kind.as_str().to_string(),
        delivery_endpoint: endpoint,
        active_encoding_stopped,
    })
}

// ────────────────────────────────────────────────────────────────────────────
// 4. Artwork Fetching (`GET /Items/{Id}/Images/Primary` & `Backdrop/0`)
// ────────────────────────────────────────────────────────────────────────────

pub async fn fetch_emby_artwork(
    server_url: &str,
    api_key: &str,
    item_id: &str,
) -> Result<EmbyArtworkPayload, EmbyAdapterError> {
    let trimmed = item_id.trim();
    if trimmed.is_empty()
        || trimmed.len() > 128
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return Err(EmbyAdapterError::InvalidPayload(
            "valid itemId is required".to_string(),
        ));
    }

    let clean_key = sanitize_emby_token(api_key);
    if clean_key.is_empty() {
        return Err(EmbyAdapterError::Unconfigured(
            "Emby API key is not configured".to_string(),
        ));
    }
    let clean_url = validate_emby_server_url(server_url)?;
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

    for img_url in &candidates {
        match do_emby_request(
            reqwest::Method::GET,
            img_url,
            &clean_key,
            None,
            Duration::from_secs(6),
            MAX_EMBY_ARTWORK_PAYLOAD_BYTES,
        )
        .await
        {
            Ok((bytes, StatusCode::OK, raw_ct)) if !bytes.is_empty() => {
                let media_type = match raw_ct
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
                };
                return Ok(EmbyArtworkPayload {
                    bytes,
                    content_type: media_type,
                });
            }
            Err(EmbyAdapterError::PayloadTooLarge { limit_bytes }) => {
                return Err(EmbyAdapterError::PayloadTooLarge { limit_bytes });
            }
            _ => continue,
        }
    }

    Err(EmbyAdapterError::UpstreamStatus {
        status: StatusCode::NOT_FOUND.as_u16(),
        message: format!("Emby artwork not found for item {:?}", trimmed),
    })
}

// ────────────────────────────────────────────────────────────────────────────
// 5. Honest Item-Summary History Collection & Optional-Event Capability Probe
// ────────────────────────────────────────────────────────────────────────────

/// Probes whether an Emby server has the Playback Reporting plugin installed, while keeping
/// optional-event import capability `supported: false` unless real-event schema and query
/// contracts are proven on a live Emby instance.
pub async fn probe_emby_optional_event_capability(
    server_url: &str,
    api_key: &str,
) -> EmbyOptionalEventCapability {
    let Ok(clean_url) = validate_emby_server_url(server_url) else {
        return EmbyOptionalEventCapability::unsupported_default();
    };
    let clean_key = sanitize_emby_token(api_key);
    if clean_key.is_empty() {
        return EmbyOptionalEventCapability::unsupported_default();
    }

    let Ok((body, StatusCode::OK, _)) = do_emby_request(
        reqwest::Method::GET,
        &format!("{}/Plugins", clean_url),
        &clean_key,
        None,
        Duration::from_secs(5),
        MAX_EMBY_JSON_PAYLOAD_BYTES,
    )
    .await
    else {
        return EmbyOptionalEventCapability::unsupported_default();
    };

    let Ok(plugins) = serde_json::from_slice::<Vec<EmbyPluginInfoRaw>>(&body) else {
        return EmbyOptionalEventCapability::unsupported_default();
    };

    if let Some(found) = plugins.into_iter().find(|p| {
        let lower = p.name.to_ascii_lowercase();
        lower.contains("playback reporting") || lower.contains("user usage stats")
    }) {
        return EmbyOptionalEventCapability {
            supported: false,
            verified: false,
            plugin_name: Some(found.name),
            plugin_version: if found.version.trim().is_empty() {
                None
            } else {
                Some(found.version)
            },
            status: "unverified_plugin_detected".to_string(),
            reason: "Playback Reporting plugin detected on Emby, but event-level import remains disabled (supported=false) until live Emby query schema and deduplication are verified.".to_string(),
        };
    }

    EmbyOptionalEventCapability::unsupported_default()
}

/// Fetches Emby user item summaries (`/Users` + `/Users/{Id}/Items`) into normalized
/// `EmbyItemSummaryRecord` structs without performing any database writes or fabricating
/// unmeasured fields (client, device, IP, play_method, or data_used_bytes).
pub async fn fetch_emby_item_summaries(
    server_name: &str,
    server_url: &str,
    api_key: &str,
    expected_server_id: Option<&str>,
) -> Result<Vec<EmbyItemSummaryRecord>, EmbyAdapterError> {
    let clean_key = sanitize_emby_token(api_key);
    if clean_key.is_empty() {
        return Err(EmbyAdapterError::Unconfigured(
            "Emby API key is not configured".to_string(),
        ));
    }
    let clean_url = validate_emby_server_url(server_url)?;

    // Verify server identity via /System/Info before importing history
    let (info_body, info_code, _) = do_emby_request(
        reqwest::Method::GET,
        &format!("{}/System/Info", clean_url),
        &clean_key,
        None,
        Duration::from_secs(6),
        MAX_EMBY_JSON_PAYLOAD_BYTES,
    )
    .await?;

    if info_code == StatusCode::UNAUTHORIZED || info_code == StatusCode::FORBIDDEN {
        return Err(EmbyAdapterError::AuthenticationFailed {
            status: info_code.as_u16(),
            message: "Emby /System/Info rejected API key".to_string(),
        });
    }
    if !info_code.is_success() {
        return Err(EmbyAdapterError::UpstreamStatus {
            status: info_code.as_u16(),
            message: "Emby /System/Info failed before history fetch".to_string(),
        });
    }

    let sys_info: EmbySystemInfoRaw = serde_json::from_slice(&info_body).map_err(|e| {
        EmbyAdapterError::InvalidPayload(format!("malformed Emby /System/Info JSON: {}", e))
    })?;
    let server_id = sys_info.id.trim().to_string();
    let expected_sid = expected_server_id.unwrap_or("").trim();
    if !expected_sid.is_empty() && !server_id.eq_ignore_ascii_case(expected_sid) {
        return Err(EmbyAdapterError::WrongIdentity(format!(
            "expected Emby server_id {:?}, got {:?}",
            expected_sid, server_id
        )));
    }

    let resolved_server_name = if !server_name.trim().is_empty() {
        server_name.trim().to_string()
    } else if !sys_info.server_name.trim().is_empty() {
        sys_info.server_name.trim().to_string()
    } else {
        EMBY_DEFAULT_NAME.to_string()
    };

    let (users_body, users_code, _) = do_emby_request(
        reqwest::Method::GET,
        &format!("{}/Users", clean_url),
        &clean_key,
        None,
        Duration::from_secs(8),
        MAX_EMBY_JSON_PAYLOAD_BYTES,
    )
    .await?;

    if !users_code.is_success() {
        return Err(EmbyAdapterError::UpstreamStatus {
            status: users_code.as_u16(),
            message: "Emby /Users request failed".to_string(),
        });
    }

    let users: Vec<EmbyUserRaw> = serde_json::from_slice(&users_body).map_err(|e| {
        EmbyAdapterError::InvalidPayload(format!("malformed Emby /Users JSON: {}", e))
    })?;

    let mut records = Vec::new();
    let page_size = 100usize;
    let filters = ["IsPlayed", "IsResumable"];

    for u in users {
        let uid = u.id.trim();
        if uid.is_empty() {
            continue;
        }
        let encoded_uid = urlencoding::encode(uid);
        for filter in filters {
            let mut start_index = 0usize;
            loop {
                let items_url = format!(
                    "{}/Users/{}/Items?Recursive=true&Filters={}&IncludeItemTypes=Movie,Episode,Audio&Fields=MediaStreams,Container,ProductionYear&SortBy=DatePlayed&SortOrder=Descending&Limit={}&StartIndex={}",
                    clean_url, encoded_uid, filter, page_size, start_index
                );
                let (items_body, i_code, _) = do_emby_request(
                    reqwest::Method::GET,
                    &items_url,
                    &clean_key,
                    None,
                    Duration::from_secs(15),
                    MAX_EMBY_JSON_PAYLOAD_BYTES,
                )
                .await?;

                if i_code != StatusCode::OK {
                    return Err(EmbyAdapterError::UpstreamStatus {
                        status: i_code.as_u16(),
                        message: "Emby history /Users/{Id}/Items request failed".to_string(),
                    });
                }

                let payload: EmbyItemsEnvelopeRaw =
                    serde_json::from_slice(&items_body).map_err(|e| {
                        EmbyAdapterError::InvalidPayload(format!(
                            "malformed Emby /Users/{{Id}}/Items JSON: {}",
                            e
                        ))
                    })?;

                if payload.items.is_empty() {
                    break;
                }

                let batch_len = payload.items.len();
                for item in payload.items {
                    let clean_item_id = item.id.trim();
                    if clean_item_id.is_empty() {
                        continue;
                    }
                    let dur_secs = (item.run_time_ticks / EMBY_TICKS_PER_SECOND).max(0);
                    let mut v_codec = String::new();
                    let mut a_codec = String::new();
                    let mut a_ch = 0i32;
                    let mut w = item.width.max(0);
                    let mut h = item.height.max(0);
                    let mut stream_bitrate = 0i64;

                    for ms in &item.media_streams {
                        if ms.stream_type == "Video" {
                            if v_codec.is_empty() && !ms.codec.trim().is_empty() {
                                v_codec = ms.codec.trim().to_uppercase();
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
                            if a_codec.is_empty() && !ms.codec.trim().is_empty() {
                                a_codec = ms.codec.trim().to_uppercase();
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
                    let mut has_played_date = false;

                    if let Some(ref ud) = item.user_data {
                        if ud.played {
                            completion_pct = 100.0;
                            if dur_secs > 0 {
                                watched_secs = dur_secs;
                            }
                        } else if ud.playback_position_ticks > 0 {
                            let pos_secs =
                                (ud.playback_position_ticks / EMBY_TICKS_PER_SECOND).max(0);
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
                                has_played_date = true;
                            }
                        }
                    }

                    let session_key = if server_id.is_empty() {
                        format!("emby:sync:{}:{}", uid, clean_item_id)
                    } else {
                        format!("emby:{}:sync:{}:{}", server_id, uid, clean_item_id)
                    };

                    records.push(EmbyItemSummaryRecord {
                        session_key,
                        provider: EMBY_PROVIDER_ID.to_string(),
                        server_id: server_id.clone(),
                        server_name: resolved_server_name.clone(),
                        user_id: uid.to_string(),
                        user_name: u.name.trim().to_string(),
                        item_id: clean_item_id.to_string(),
                        item_name: item.name.trim().to_string(),
                        item_type: normalize_emby_media_type(&item.item_type),
                        series_name: item.series_name.trim().to_string(),
                        series_id: item.series_id.trim().to_string(),
                        season_number: item.parent_index_number,
                        episode_number: item.index_number,
                        production_year: item.production_year,
                        container: item.container.trim().to_uppercase(),
                        video_codec: v_codec,
                        video_resolution: format_resolution_label(w, h),
                        audio_codec: a_codec,
                        audio_channels: a_ch,
                        bitrate_bps: bitrate,
                        duration_secs: dur_secs,
                        watched_secs,
                        data_used_bytes: 0,
                        completion_pct,
                        played_at,
                        has_played_date,
                        provenance: "item_summary".to_string(),
                        timestamp_certainty: if has_played_date {
                            "last_played".to_string()
                        } else {
                            "unrecorded".to_string()
                        },
                        byte_accuracy: "unrecorded".to_string(),
                    });
                }

                start_index += batch_len;
                if start_index >= payload.total_record_count || batch_len < page_size {
                    break;
                }
            }
        }
    }

    Ok(records)
}

// ────────────────────────────────────────────────────────────────────────────
// Unit & Mock HTTP Server Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::{delete, get, post},
        Json, Router,
    };
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    #[derive(Default)]
    struct MockEmbyState {
        command_hits: AtomicUsize,
        active_encoding_delete_hits: AtomicUsize,
        sessions_fail: AtomicBool,
    }

    #[test]
    fn test_emby_url_validation_and_token_sanitization() {
        assert_eq!(
            validate_emby_server_url("http://127.0.0.1:8096/emby/").unwrap(),
            "http://127.0.0.1:8096/emby"
        );
        assert!(validate_emby_server_url("ftp://127.0.0.1:8096").is_err());
        assert!(validate_emby_server_url("http://user:pass@127.0.0.1:8096").is_err());
        assert!(validate_emby_server_url("http://127.0.0.1:8096?api_key=secret").is_err());
        assert!(validate_emby_server_url("http://169.254.169.254/latest").is_err());

        let dirty = "  ab\"cd\r\nef\x071234  ";
        assert_eq!(sanitize_emby_token(dirty), "abcdef1234");
        assert_eq!(mask_emby_api_key(dirty), "****1234");
    }

    #[test]
    fn test_capability_resolution_fails_closed_when_missing_or_partial() {
        // 1. Missing both SupportsMediaControl and SupportsRemoteControl -> must fail closed (false)
        let missing_caps: EmbySessionRaw = serde_json::from_value(serde_json::json!({
            "Id": "sess-missing-caps",
            "Client": "Emby Web",
            "DeviceName": "Firefox",
            "SupportedCommands": ["DisplayMessage"],
            "NowPlayingItem": {
                "Id": "item-1",
                "Name": "Dune",
                "Type": "Movie"
            }
        }))
        .unwrap();
        let ev1 = resolve_emby_session_capabilities(&missing_caps);
        assert!(!ev1.supports_media_control);
        assert!(!ev1.supports_remote_control);
        assert!(!ev1.can_pause);
        assert!(!ev1.can_resume);
        assert!(!ev1.can_stop);
        assert!(!ev1.can_send_message);

        // 2. SupportsRemoteControl=true (standard Emby SessionInfo property), SupportedCommands=[], NowPlayingItem present
        // -> Playback controls allowed, but can_send_message MUST be false (never inferred from empty SupportedCommands!)
        let no_msg_cmd: EmbySessionRaw = serde_json::from_value(serde_json::json!({
            "Id": "sess-no-msg",
            "Client": "Emby Theater",
            "DeviceName": "Shield",
            "SupportsRemoteControl": true,
            "SupportedCommands": ["MoveUp", "Select", "Mute"],
            "NowPlayingItem": {
                "Id": "item-2",
                "Name": "Arrival",
                "Type": "Movie"
            }
        }))
        .unwrap();
        let ev2 = resolve_emby_session_capabilities(&no_msg_cmd);
        assert!(ev2.supports_media_control);
        assert!(ev2.supports_remote_control);
        assert!(ev2.can_pause);
        assert!(ev2.can_resume);
        assert!(ev2.can_stop);
        assert!(!ev2.can_send_message);

        // 3. SupportsRemoteControl=true, SupportedCommands=["DisplayMessage"], but NO NowPlayingItem
        // -> can_send_message is true, but playback controls (pause/resume/stop) are false
        let idle_session: EmbySessionRaw = serde_json::from_value(serde_json::json!({
            "Id": "sess-idle",
            "SupportsRemoteControl": true,
            "SupportedCommands": ["DisplayMessage"]
        }))
        .unwrap();
        let ev3 = resolve_emby_session_capabilities(&idle_session);
        assert!(ev3.supports_media_control);
        assert!(!ev3.can_pause);
        assert!(!ev3.can_resume);
        assert!(!ev3.can_stop);
        assert!(ev3.can_send_message);

        // 4. Conflicting flags: SupportsRemoteControl=true, but Capabilities.SupportsMediaControl=false -> fail closed!
        let conflicting: EmbySessionRaw = serde_json::from_value(serde_json::json!({
            "Id": "sess-conflict",
            "SupportsRemoteControl": true,
            "Capabilities": {
                "SupportsMediaControl": false,
                "SupportedCommands": ["DisplayMessage"]
            },
            "NowPlayingItem": {
                "Id": "item-3",
                "Name": "Blade Runner",
                "Type": "Movie"
            }
        }))
        .unwrap();
        let ev4 = resolve_emby_session_capabilities(&conflicting);
        assert!(!ev4.supports_media_control);
        assert!(!ev4.can_pause);
        assert!(!ev4.can_send_message);
    }

    #[test]
    fn test_session_normalization_preserves_emby_fields_and_rejects_wrong_server_id() {
        let raw: EmbySessionRaw = serde_json::from_value(serde_json::json!({
            "Id": "emby-sess-42",
            "ServerId": "srv-emby-prod",
            "UserId": "u-99",
            "UserName": "claire",
            "Client": "Emby for Apple TV",
            "DeviceName": "Living Room Apple TV",
            "DeviceId": "atv-living-room",
            "ApplicationVersion": "2.1.4",
            "RemoteEndPoint": "192.168.10.25",
            "SupportsRemoteControl": true,
            "SupportedCommands": ["DisplayMessage", "Mute"],
            "PlayState": {
                "PositionTicks": 18_000_000_000i64,
                "IsPaused": false,
                "PlayMethod": "Transcode",
                "PlaySessionId": "ps-777",
                "MediaSourceId": "ms-111",
                "AudioStreamIndex": 1,
                "SubtitleStreamIndex": 2
            },
            "NowPlayingItem": {
                "Id": "ep-101",
                "Name": "Theerton",
                "Type": "Episode",
                "SeriesName": "Silo",
                "SeriesId": "ser-silo",
                "ParentIndexNumber": 2,
                "IndexNumber": 5,
                "ProductionYear": 2025,
                "RunTimeTicks": 36_000_000_000i64,
                "Container": "mkv",
                "Bitrate": 20_000_000i64,
                "Width": 3840,
                "Height": 2160,
                "PrimaryImageTag": "tag-ep-primary",
                "PrimaryImageItemId": "ep-101",
                "MediaStreams": [
                    {
                        "Type": "Video",
                        "Index": 0,
                        "Codec": "hevc",
                        "Width": 3840,
                        "Height": 2160,
                        "ColorTransfer": "smpte2084",
                        "AverageFrameRate": 23.976,
                        "BitRate": 18_000_000
                    },
                    {
                        "Type": "Audio",
                        "Index": 1,
                        "Codec": "eac3",
                        "Channels": 6,
                        "ChannelLayout": "5.1",
                        "Language": "eng",
                        "BitRate": 768_000,
                        "IsDefault": true
                    },
                    {
                        "Type": "Subtitle",
                        "Index": 2,
                        "Codec": "subrip",
                        "Language": "eng"
                    }
                ]
            },
            "TranscodingInfo": {
                "Container": "ts",
                "IsVideoDirect": false,
                "IsAudioDirect": false,
                "VideoCodec": "h264",
                "AudioCodec": "aac",
                "Bitrate": 10_500_000,
                "Framerate": 64.2,
                "CompletionPercentage": 48.6,
                "VideoEncoderHwAccel": "vaapi",
                "TranscodeReasons": ["ContainerBitrateExceedsLimit"]
            }
        }))
        .unwrap();

        // Wrong expected_server_id must fail with WrongIdentity
        let mismatch = normalize_emby_session(
            raw.clone(),
            "Emby Vault",
            Some("srv-other-instance"),
            None,
        );
        assert!(matches!(mismatch, Err(EmbyAdapterError::WrongIdentity(_))));

        // Matching expected_server_id normalizes cleanly into ActiveStreamSession
        let mut tracked = HashMap::new();
        tracked.insert(
            "emby:emby-sess-42:ep-101".to_string(),
            (125_000_000i64, "2026-11-01 22:00:00".to_string()),
        );
        let session = normalize_emby_session(
            raw,
            "Emby Vault",
            Some("srv-emby-prod"),
            Some(&tracked),
        )
        .unwrap()
        .expect("active session");

        assert_eq!(session.provider, "emby");
        assert_eq!(session.server_name, "Emby Vault");
        assert_eq!(session.session_id, "emby-sess-42");
        assert_eq!(session.user_id, "u-99");
        assert_eq!(session.user_name, "claire");
        assert!(session.is_lan);
        assert_eq!(session.item_type, "Episode");
        assert_eq!(session.position_secs, 1800);
        assert_eq!(session.duration_secs, 3600);
        assert_eq!(session.progress_pct, 50.0);
        assert_eq!(session.play_method, "Transcode");
        assert_eq!(session.video_codec, "HEVC");
        assert_eq!(session.target_video_codec, "H264");
        assert_eq!(session.video_resolution, "4K UHD");
        assert_eq!(session.video_range, "HDR10");
        assert_eq!(session.video_framerate, 23.98);
        assert_eq!(session.audio_codec, "EAC3");
        assert_eq!(session.target_audio_codec, "AAC");
        assert_eq!(session.audio_layout, "5.1");
        assert_eq!(session.subtitle_codec, "SUBRIP");
        assert_eq!(session.hw_accel, "VAAPI");
        assert_eq!(session.bitrate_bps, 10_500_000);
        assert_eq!(session.bandwidth_mbps, 10.5);
        assert_eq!(session.session_data_bytes, 125_000_000);
        assert_eq!(session.started_at, "2026-11-01 22:00:00");
        assert!(session.has_artwork);
        assert_eq!(session.artwork_item_id, "ep-101");
        assert!(session.supports_media_control);
        assert!(session.supports_remote_control);
        assert!(session.can_send_message);
    }

    #[tokio::test]
    async fn test_mock_http_server_validation_and_coming_soon_support_stage() {
        let app = Router::new()
            .route(
                "/System/Info",
                get(|headers: HeaderMap| async move {
                    let token = headers
                        .get("X-Emby-Token")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let auth = headers
                        .get("X-Emby-Authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    if token != "valid-emby-key-9876" || !auth.contains("Token=\"valid-emby-key-9876\"") {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    Json(serde_json::json!({
                        "Id": "emby-srv-001",
                        "ServerName": "Aether Emby",
                        "Version": "4.8.10.0",
                        "OperatingSystemDisplayName": "Debian GNU/Linux 12 (bookworm)"
                    }))
                    .into_response()
                }),
            )
            .route(
                "/Items/Counts",
                get(|| async {
                    Json(serde_json::json!({
                        "MovieCount": 310,
                        "SeriesCount": 64,
                        "EpisodeCount": 2410,
                        "SongCount": 980
                    }))
                }),
            )
            .route(
                "/System/Info/Public",
                get(|| async {
                    Json(serde_json::json!({
                        "Id": "emby-srv-001",
                        "ServerName": "Aether Emby Public",
                        "Version": "4.8.10.0"
                    }))
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // 1. Authenticated validation succeeds and keeps support_stage = "coming_soon"
        let st = test_emby_connection(&server_url, "valid-emby-key-9876", Some("emby-srv-001"))
            .await
            .expect("valid connection");
        assert_eq!(st.provider, "emby");
        assert_eq!(st.name, "Aether Emby");
        assert_eq!(st.status, "connected");
        assert_eq!(st.support_stage, "coming_soon");
        assert_eq!(st.server_id, "emby-srv-001");
        assert_eq!(st.version, "4.8.10.0");
        assert_eq!(st.operating_system, "Debian GNU/Linux 12 (bookworm)");
        assert_eq!(st.api_key_masked, "****9876");
        assert_eq!(st.library_counts.movies, 310);
        assert_eq!(st.library_counts.series, 64);
        assert_eq!(st.library_counts.episodes, 2410);
        assert_eq!(st.library_counts.audio, 980);

        // 2. Wrong expected_server_id fails closed
        let wrong_id =
            test_emby_connection(&server_url, "valid-emby-key-9876", Some("wrong-srv-id"))
                .await
                .unwrap_err();
        assert!(matches!(wrong_id, EmbyAdapterError::WrongIdentity(_)));

        // 3. Invalid API key fails with AuthenticationFailed
        let bad_key = test_emby_connection(&server_url, "wrong-key", None)
            .await
            .unwrap_err();
        assert!(matches!(
            bad_key,
            EmbyAdapterError::AuthenticationFailed { status: 401, .. }
        ));

        // 4. Public probe without API key reports unconfigured and coming_soon
        let pub_st = test_emby_connection(&server_url, "", Some("emby-srv-001"))
            .await
            .expect("public discovery");
        assert_eq!(pub_st.status, "unconfigured");
        assert_eq!(pub_st.support_stage, "coming_soon");
        assert_eq!(pub_st.server_id, "emby-srv-001");

        server.abort();
    }

    #[tokio::test]
    async fn test_session_commands_enforce_capabilities_identity_and_no_command_on_failure() {
        let state = Arc::new(MockEmbyState::default());
        let app_state = state.clone();

        let app = Router::new()
            .route(
                "/Sessions",
                get(|State(st): State<Arc<MockEmbyState>>, headers: HeaderMap| async move {
                    if headers.get("X-Emby-Token").and_then(|v| v.to_str().ok()) != Some("emby-secret") {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    if st.sessions_fail.load(Ordering::SeqCst) {
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    Json(serde_json::json!([
                        {
                            "Id": "sess-full",
                            "ServerId": "srv-emby-1",
                            "UserId": "u1",
                            "UserName": "alex",
                            "Client": "Emby Web",
                            "DeviceName": "Chrome",
                            "DeviceId": "dev-chrome-1",
                            "SupportsRemoteControl": true,
                            "SupportedCommands": ["DisplayMessage"],
                            "PlayState": {
                                "PositionTicks": 100_000_000,
                                "IsPaused": false,
                                "PlayMethod": "Transcode",
                                "PlaySessionId": "ps-transcode-1"
                            },
                            "NowPlayingItem": {
                                "Id": "item-1",
                                "Name": "Interstellar",
                                "Type": "Movie"
                            },
                            "TranscodingInfo": {
                                "IsVideoDirect": false,
                                "IsAudioDirect": true,
                                "VideoCodec": "h264"
                            }
                        },
                        {
                            "Id": "sess-no-msg",
                            "ServerId": "srv-emby-1",
                            "UserId": "u2",
                            "UserName": "maya",
                            "Client": "Emby Roku",
                            "DeviceName": "Roku Ultra",
                            "DeviceId": "dev-roku",
                            "SupportsRemoteControl": true,
                            "SupportedCommands": ["Mute"],
                            "PlayState": {
                                "PositionTicks": 50_000_000,
                                "IsPaused": false,
                                "PlayMethod": "DirectPlay"
                            },
                            "NowPlayingItem": {
                                "Id": "item-2",
                                "Name": "Silo",
                                "Type": "Episode"
                            }
                        },
                        {
                            "Id": "sess-no-ctrl",
                            "ServerId": "srv-emby-1",
                            "UserId": "u3",
                            "UserName": "liam",
                            "Client": "DLNA",
                            "DeviceName": "TV",
                            "DeviceId": "dev-tv",
                            "SupportsRemoteControl": false,
                            "SupportedCommands": [],
                            "NowPlayingItem": {
                                "Id": "item-3",
                                "Name": "Track 1",
                                "Type": "Audio"
                            }
                        }
                    ]))
                    .into_response()
                }),
            )
            .route(
                "/Sessions/:id/Playing/:cmd",
                post(
                    |State(st): State<Arc<MockEmbyState>>,
                     axum::extract::Path((_id, _cmd)): axum::extract::Path<(String, String)>| async move {
                        st.command_hits.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    },
                ),
            )
            .route(
                "/Sessions/:id/Message",
                post(
                    |State(st): State<Arc<MockEmbyState>>,
                     axum::extract::Path(_id): axum::extract::Path<String>,
                     Json(body): Json<serde_json::Value>| async move {
                        assert_eq!(body["Text"], "Maintenance soon");
                        st.command_hits.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    },
                ),
            )
            .route(
                "/Videos/ActiveEncodings",
                delete(|State(st): State<Arc<MockEmbyState>>| async move {
                    st.active_encoding_delete_hits.fetch_add(1, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }),
            )
            .with_state(app_state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // 1. Wrong provider target -> rejected before any HTTP command
        let err_prov = send_emby_session_command(
            &server_url,
            "emby-secret",
            &EmbyCommandTarget {
                provider: "jellyfin".to_string(),
                expected_server_id: "srv-emby-1".to_string(),
                session_id: "sess-full".to_string(),
                command: "pause".to_string(),
                header: String::new(),
                message: String::new(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err_prov, EmbyAdapterError::WrongIdentity(_)));
        assert_eq!(state.command_hits.load(Ordering::SeqCst), 0);

        // 2. Wrong expected_server_id -> rejected before POST command
        let err_sid = send_emby_session_command(
            &server_url,
            "emby-secret",
            &EmbyCommandTarget {
                provider: "emby".to_string(),
                expected_server_id: "srv-wrong-999".to_string(),
                session_id: "sess-full".to_string(),
                command: "pause".to_string(),
                header: String::new(),
                message: String::new(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err_sid, EmbyAdapterError::WrongIdentity(_)));
        assert_eq!(state.command_hits.load(Ordering::SeqCst), 0);

        // 3. Demo prefix does NOT bypass capability verification (no fake Ok)
        let err_demo = send_emby_session_command(
            &server_url,
            "emby-secret",
            &EmbyCommandTarget {
                provider: "emby".to_string(),
                expected_server_id: "srv-emby-1".to_string(),
                session_id: "demo-sess-01".to_string(),
                command: "pause".to_string(),
                header: String::new(),
                message: String::new(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err_demo, EmbyAdapterError::SessionNotFound(_)));
        assert_eq!(state.command_hits.load(Ordering::SeqCst), 0);

        // 4. Session without DisplayMessage rejects message command without sending POST
        let err_msg = send_emby_session_command(
            &server_url,
            "emby-secret",
            &EmbyCommandTarget {
                provider: "emby".to_string(),
                expected_server_id: "srv-emby-1".to_string(),
                session_id: "sess-no-msg".to_string(),
                command: "message".to_string(),
                header: "Admin".to_string(),
                message: "Hello".to_string(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err_msg, EmbyAdapterError::CapabilityDenied(_)));
        assert_eq!(state.command_hits.load(Ordering::SeqCst), 0);

        // 5. Session with SupportsRemoteControl=false rejects pause command without sending POST
        let err_ctrl = send_emby_session_command(
            &server_url,
            "emby-secret",
            &EmbyCommandTarget {
                provider: "emby".to_string(),
                expected_server_id: "srv-emby-1".to_string(),
                session_id: "sess-no-ctrl".to_string(),
                command: "pause".to_string(),
                header: String::new(),
                message: String::new(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err_ctrl, EmbyAdapterError::CapabilityDenied(_)));
        assert_eq!(state.command_hits.load(Ordering::SeqCst), 0);

        // 6. Valid message command and stop command (with ActiveEncodings cleanup) succeed
        let msg_ok = send_emby_session_command(
            &server_url,
            "emby-secret",
            &EmbyCommandTarget {
                provider: "emby".to_string(),
                expected_server_id: "srv-emby-1".to_string(),
                session_id: "sess-full".to_string(),
                command: "message".to_string(),
                header: "Notice".to_string(),
                message: "Maintenance soon".to_string(),
            },
        )
        .await
        .expect("message command succeeds");
        assert_eq!(msg_ok.command, "message");
        assert_eq!(state.command_hits.load(Ordering::SeqCst), 1);

        let stop_ok = send_emby_session_command(
            &server_url,
            "emby-secret",
            &EmbyCommandTarget {
                provider: "emby".to_string(),
                expected_server_id: "srv-emby-1".to_string(),
                session_id: "sess-full".to_string(),
                command: "stop".to_string(),
                header: String::new(),
                message: String::new(),
            },
        )
        .await
        .expect("stop command succeeds");
        assert!(stop_ok.active_encoding_stopped);
        assert_eq!(state.command_hits.load(Ordering::SeqCst), 2);
        assert_eq!(state.active_encoding_delete_hits.load(Ordering::SeqCst), 1);

        // 7. Upstream HTTP 500 on fresh /Sessions capability check -> fails closed and issues no command
        state.sessions_fail.store(true, Ordering::SeqCst);
        let err_upstream = send_emby_session_command(
            &server_url,
            "emby-secret",
            &EmbyCommandTarget {
                provider: "emby".to_string(),
                expected_server_id: "srv-emby-1".to_string(),
                session_id: "sess-full".to_string(),
                command: "pause".to_string(),
                header: String::new(),
                message: String::new(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err_upstream,
            EmbyAdapterError::UpstreamStatus { status: 500, .. }
        ));
        assert_eq!(state.command_hits.load(Ordering::SeqCst), 2);

        // 8. Transport failure when target port is unreachable -> fails closed and issues no command
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_url = format!("http://{}", closed_listener.local_addr().unwrap());
        drop(closed_listener);

        let err_down = send_emby_session_command(
            &closed_url,
            "emby-secret",
            &EmbyCommandTarget {
                provider: "emby".to_string(),
                expected_server_id: "srv-emby-1".to_string(),
                session_id: "sess-full".to_string(),
                command: "pause".to_string(),
                header: String::new(),
                message: String::new(),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err_down, EmbyAdapterError::Transport(_)));
        assert_eq!(state.command_hits.load(Ordering::SeqCst), 2);

        server.abort();
    }

    #[tokio::test]
    async fn test_optional_event_capability_and_redirect_or_oversized_rejection() {
        let app = Router::new()
            .route(
                "/Plugins",
                get(|| async {
                    Json(serde_json::json!([
                        {
                            "Id": "plg-1",
                            "Name": "Playback Reporting",
                            "Version": "2.1.0.0"
                        }
                    ]))
                }),
            )
            .route(
                "/System/Info",
                get(|| async {
                    (
                        StatusCode::FOUND,
                        [(header::LOCATION, "http://127.0.0.1:9999/evil")],
                    )
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Optional event capability remains supported=false even when plugin is detected
        let ev_cap = probe_emby_optional_event_capability(&server_url, "emby-key").await;
        assert!(!ev_cap.supported);
        assert!(!ev_cap.verified);
        assert_eq!(ev_cap.plugin_name.as_deref(), Some("Playback Reporting"));
        assert_eq!(ev_cap.status, "unverified_plugin_detected");

        // Redirect response on /System/Info is rejected by Policy::none() / status.is_redirection()
        let redir_err = test_emby_connection(&server_url, "emby-key", None)
            .await
            .unwrap_err();
        assert!(matches!(redir_err, EmbyAdapterError::Transport(_)));

        // Oversized payload is rejected before buffering unbounded memory
        let small_limit_err = do_emby_request(
            reqwest::Method::GET,
            &format!("{}/Plugins", server_url),
            "emby-key",
            None,
            Duration::from_secs(3),
            16, // 16-byte limit
        )
        .await
        .unwrap_err();
        assert!(matches!(
            small_limit_err,
            EmbyAdapterError::PayloadTooLarge { limit_bytes: 16 }
        ));

        server.abort();
    }

    #[tokio::test]
    async fn test_mock_http_live_sessions_artwork_and_honest_item_summaries() {
        let app = Router::new()
            .route(
                "/System/Info",
                get(|| async {
                    Json(serde_json::json!({
                        "Id": "emby-srv-hist",
                        "ServerName": "Emby Cinema",
                        "Version": "4.8.10.0"
                    }))
                }),
            )
            .route(
                "/Sessions",
                get(|| async {
                    Json(serde_json::json!([
                        {
                            "Id": "live-1",
                            "ServerId": "emby-srv-hist",
                            "UserId": "usr-1",
                            "UserName": "noah",
                            "Client": "Emby Android",
                            "DeviceName": "Pixel 9",
                            "DeviceId": "px9",
                            "RemoteEndPoint": "10.0.0.42",
                            "SupportsRemoteControl": true,
                            "SupportedCommands": ["DisplayMessage"],
                            "PlayState": {
                                "PositionTicks": 600_000_000i64,
                                "IsPaused": false,
                                "PlayMethod": "DirectPlay"
                            },
                            "NowPlayingItem": {
                                "Id": "mov-99",
                                "Name": "Oppenheimer",
                                "Type": "Movie",
                                "RunTimeTicks": 108_000_000_000i64,
                                "Container": "mkv"
                            }
                        },
                        {
                            "Id": "idle-2",
                            "ServerId": "emby-srv-hist",
                            "UserId": "usr-2",
                            "UserName": "idle-user",
                            "Client": "Emby Web"
                        }
                    ]))
                }),
            )
            .route(
                "/Users",
                get(|| async {
                    Json(serde_json::json!([
                        { "Id": "usr-1", "Name": "noah" }
                    ]))
                }),
            )
            .route(
                "/Users/usr-1/Items",
                get(|axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>| async move {
                    if params.get("Filters").map(String::as_str) == Some("IsPlayed") {
                        Json(serde_json::json!({
                            "TotalRecordCount": 1,
                            "Items": [
                                {
                                    "Id": "mov-99",
                                    "Name": "Oppenheimer",
                                    "Type": "Movie",
                                    "ProductionYear": 2023,
                                    "RunTimeTicks": 108_000_000_000i64,
                                    "Container": "mkv",
                                    "Bitrate": 24_000_000i64,
                                    "Width": 3840,
                                    "Height": 2160,
                                    "UserData": {
                                        "Played": true,
                                        "LastPlayedDate": "2026-10-31T21:30:00Z"
                                    }
                                }
                            ]
                        }))
                    } else {
                        Json(serde_json::json!({
                            "TotalRecordCount": 0,
                            "Items": []
                        }))
                    }
                }),
            )
            .route(
                "/Items/mov-99/Images/Primary",
                get(|| async {
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "image/webp")],
                        vec![0x52u8, 0x49, 0x46, 0x46],
                    )
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let live = fetch_emby_live_sessions(
            "Emby Cinema",
            &server_url,
            "emby-token",
            Some("emby-srv-hist"),
        )
        .await
        .expect("live sessions");
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].session_id, "live-1");
        assert_eq!(live[0].item_name, "Oppenheimer");

        let summaries = fetch_emby_item_summaries(
            "Emby Cinema",
            &server_url,
            "emby-token",
            Some("emby-srv-hist"),
        )
        .await
        .expect("item summaries");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].session_key, "emby:emby-srv-hist:sync:usr-1:mov-99");
        assert_eq!(summaries[0].provenance, "item_summary");
        assert_eq!(summaries[0].timestamp_certainty, "last_played");
        assert_eq!(summaries[0].byte_accuracy, "unrecorded");
        assert_eq!(summaries[0].data_used_bytes, 0);
        assert_eq!(summaries[0].watched_secs, 10800);
        assert_eq!(summaries[0].completion_pct, 100.0);

        let art = fetch_emby_artwork(&server_url, "emby-token", "mov-99")
            .await
            .expect("artwork");
        assert_eq!(art.content_type, "image/webp");
        assert_eq!(art.bytes, vec![0x52, 0x49, 0x46, 0x46]);

        server.abort();
    }
}
