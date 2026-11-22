use super::{EMBY_DEFAULT_NAME, EMBY_DEFAULT_URL, EMBY_PROVIDER_ID};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

#[cfg(test)]
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
pub(super) struct EmbySystemInfoRaw {
    #[serde(default)]
    pub(super) server_name: String,
    #[serde(default)]
    pub(super) version: String,
    #[serde(default)]
    pub(super) id: String,
    #[serde(default)]
    pub(super) operating_system: String,
    #[serde(default)]
    pub(super) operating_system_display_name: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct EmbyItemCountsRaw {
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
pub(super) struct EmbyClientCapabilitiesRaw {
    #[serde(default)]
    pub(super) supports_media_control: Option<bool>,
    #[serde(default)]
    pub(super) supported_commands: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct EmbyPlayStateRaw {
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
pub(super) struct EmbyMediaStreamRaw {
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
    pub(super) color_transfer: String,
    #[serde(default)]
    pub(super) real_frame_rate: f64,
    #[serde(default)]
    pub(super) average_frame_rate: f64,
    #[serde(default)]
    pub(super) channels: i32,
    #[serde(default)]
    pub(super) channel_layout: String,
    #[serde(default)]
    pub(super) is_default: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct EmbyNowPlayingItemRaw {
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
    pub(super) primary_image_tag: String,
    #[serde(default)]
    pub(super) primary_image_item_id: String,
    #[serde(default)]
    pub(super) series_primary_image_tag: String,
    #[serde(default)]
    pub(super) backdrop_image_tags: Vec<String>,
    #[serde(default)]
    pub(super) backdrop_image_tag: String,
    #[serde(default)]
    pub(super) backdrop_item_id: String,
    #[serde(default)]
    pub(super) media_streams: Vec<EmbyMediaStreamRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct EmbyTranscodingInfoRaw {
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
    pub(super) video_encoder_hw_accel: String,
    #[serde(default)]
    pub(super) video_decoder_hw_accel: String,
    #[serde(default)]
    pub(super) video_encoder_is_hardware: bool,
    #[serde(default)]
    pub(super) video_decoder_is_hardware: bool,
    #[serde(default)]
    pub(super) hardware_acceleration_type: String,
    #[serde(default)]
    pub(super) transcode_reasons: Vec<String>,
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
    pub(super) capabilities: Option<EmbyClientCapabilitiesRaw>,
    #[serde(default)]
    pub(super) play_state: Option<EmbyPlayStateRaw>,
    #[serde(default)]
    pub(super) now_playing_item: Option<EmbyNowPlayingItemRaw>,
    #[serde(default)]
    pub(super) transcoding_info: Option<EmbyTranscodingInfoRaw>,
}

#[cfg(test)]
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct EmbyUserRaw {
    #[serde(default)]
    pub(super) id: String,
    #[serde(default)]
    pub(super) name: String,
}

#[cfg(test)]
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct EmbyUserDataRaw {
    #[serde(default)]
    pub(super) played: bool,
    #[serde(default)]
    pub(super) playback_position_ticks: i64,
    #[serde(default)]
    pub(super) played_percentage: f64,
    #[serde(default)]
    pub(super) last_played_date: String,
}

#[cfg(test)]
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct EmbyHistoryItemRaw {
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
    pub(super) media_streams: Vec<EmbyMediaStreamRaw>,
    #[serde(default)]
    pub(super) user_data: Option<EmbyUserDataRaw>,
}

#[cfg(test)]
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct EmbyItemsEnvelopeRaw {
    #[serde(default)]
    pub(super) total_record_count: usize,
    #[serde(default)]
    pub(super) items: Vec<EmbyHistoryItemRaw>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct EmbyPluginInfoRaw {
    #[serde(default)]
    pub(super) name: String,
    #[serde(default)]
    pub(super) version: String,
}
