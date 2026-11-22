use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// Streaming Telemetry Monitor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StreamingLibraryCounts {
    pub movies: i32,
    pub series: i32,
    pub episodes: i32,
    pub audio: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingServerStatus {
    pub provider: String,
    pub name: String,
    pub url: String,
    pub api_key_masked: String,
    pub configured: bool,
    pub enabled: bool,
    pub status: String,
    pub support_stage: String,
    pub server_id: String,
    pub version: String,
    pub operating_system: String,
    pub last_connected_at: String,
    pub library_counts: StreamingLibraryCounts,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub error_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ActiveStreamSession {
    pub session_id: String,
    pub provider: String,
    pub server_name: String,
    pub user_id: String,
    pub user_name: String,
    pub client_name: String,
    pub device_name: String,
    pub device_id: String,
    pub app_version: String,
    pub ip_address: String,
    pub is_lan: bool,
    pub item_id: String,
    pub item_name: String,
    pub item_type: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub series_name: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub series_id: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub season_number: i32,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub episode_number: i32,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub production_year: i32,
    pub has_artwork: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub artwork_item_id: String,
    pub state: String,
    pub position_secs: i64,
    pub duration_secs: i64,
    pub progress_pct: f64,
    pub play_method: String,
    pub container: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub target_container: String,
    pub video_codec: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub target_video_codec: String,
    pub video_resolution: String,
    pub video_range: String,
    #[serde(skip_serializing_if = "is_zero_f64", default)]
    pub video_framerate: f64,
    pub is_video_direct: bool,
    pub audio_codec: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub target_audio_codec: String,
    pub audio_channels: i32,
    pub audio_layout: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub audio_language: String,
    pub is_audio_direct: bool,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub subtitle_codec: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub subtitle_language: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub hw_accel: String,
    #[serde(default)]
    pub transcode_reasons: Vec<String>,
    #[serde(skip_serializing_if = "is_zero_f64", default)]
    pub transcode_progress_pct: f64,
    #[serde(skip_serializing_if = "is_zero_f64", default)]
    pub transcode_fps: f64,
    pub bitrate_bps: i64,
    pub bandwidth_mbps: f64,
    pub session_data_bytes: i64,
    pub started_at: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub play_session_id: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub media_source_id: String,
    pub supports_media_control: bool,
    pub supports_remote_control: bool,
    pub can_send_message: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub supported_commands: Vec<String>,
}

fn is_zero_f64(val: &f64) -> bool {
    *val == 0.0
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingLiveSummary {
    pub active_streams: i32,
    pub direct_play_count: i32,
    pub direct_stream_count: i32,
    pub transcode_count: i32,
    pub total_bitrate_bps: i64,
    pub total_bandwidth_mbps: f64,
    pub active_session_bytes: i64,
    pub lan_streams: i32,
    pub wan_streams: i32,
    pub is_demo_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamTypeDistribution {
    pub direct_play_count: i32,
    pub direct_play_pct: f64,
    pub direct_stream_count: i32,
    pub direct_stream_pct: f64,
    pub transcode_count: i32,
    pub transcode_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BreakdownEntry {
    pub label: String,
    pub count: i32,
    pub pct: f64,
    pub watch_time_secs: i64,
    pub data_used_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingTimeSeriesPoint {
    pub date: String,
    pub plays: i32,
    pub watch_time_secs: i64,
    pub data_used_bytes: i64,
    pub peak_bandwidth_mbps: f64,
    pub direct_play_count: i32,
    pub direct_stream_count: i32,
    pub transcode_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingUserStat {
    pub user_id: String,
    pub user_name: String,
    pub provider: String,
    pub total_plays: i32,
    pub total_watch_secs: i64,
    pub total_data_bytes: i64,
    pub unique_items: i32,
    pub direct_play_count: i32,
    pub transcode_count: i32,
    pub avg_completion_pct: f64,
    pub last_device: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingTitleStat {
    pub item_id: String,
    pub item_name: String,
    pub item_type: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub series_name: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub production_year: i32,
    pub provider: String,
    pub video_resolution: String,
    pub video_codec: String,
    pub total_plays: i32,
    pub unique_viewers: i32,
    pub total_watch_secs: i64,
    pub total_data_bytes: i64,
    pub avg_completion_pct: f64,
    pub last_watched_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingHistoryItem {
    pub id: i64,
    pub session_key: String,
    pub provider: String,
    pub server_name: String,
    pub user_name: String,
    pub client_name: String,
    pub device_name: String,
    pub ip_address: String,
    pub item_id: String,
    pub item_name: String,
    pub item_type: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub series_name: String,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub season_number: i32,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub episode_number: i32,
    #[serde(skip_serializing_if = "is_zero_i32", default)]
    pub production_year: i32,
    pub play_method: String,
    pub container: String,
    pub video_codec: String,
    pub video_resolution: String,
    pub audio_codec: String,
    pub audio_channels: i32,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub hw_accel: String,
    pub bitrate_bps: i64,
    pub bandwidth_mbps: f64,
    pub duration_secs: i64,
    pub watched_secs: i64,
    pub data_used_bytes: i64,
    pub completion_pct: f64,
    pub started_at: String,
    pub last_seen_at: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingHistoryEstimate {
    pub provenance: String,
    pub records: i64,
    pub reported_watch_time_secs: i64,
    pub undated_records: i64,
    pub time_series: Vec<StreamingTimeSeriesPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingAnalytics {
    pub window_days: i32,
    pub total_plays: i32,
    pub total_watch_time_secs: i64,
    pub total_data_used_bytes: i64,
    pub unique_users: i32,
    pub unique_titles: i32,
    pub avg_completion_pct: f64,
    pub peak_bandwidth_mbps: f64,
    pub stream_types: StreamTypeDistribution,
    pub media_type_breakdown: Vec<BreakdownEntry>,
    pub resolution_breakdown: Vec<BreakdownEntry>,
    pub codec_breakdown: Vec<BreakdownEntry>,
    #[serde(default)]
    pub time_series_granularity: String,
    pub time_series: Vec<StreamingTimeSeriesPoint>,
    pub top_users: Vec<StreamingUserStat>,
    pub top_titles: Vec<StreamingTitleStat>,
    pub recent_history: Vec<StreamingHistoryItem>,
    #[serde(default)]
    pub historical_estimates: Vec<StreamingHistoryEstimate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct StreamingDashboardResponse {
    pub servers: Vec<StreamingServerStatus>,
    pub live_summary: StreamingLiveSummary,
    pub active_sessions: Vec<ActiveStreamSession>,
    pub analytics: StreamingAnalytics,
    pub updated_at: String,
}

static DEMO_STREAMING_MODE: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

pub fn set_streaming_demo_mode(enabled: bool) {
    if let Ok(mut guard) = DEMO_STREAMING_MODE.lock() {
        *guard = enabled;
    }
}

pub fn is_streaming_demo_mode() -> bool {
    DEMO_STREAMING_MODE
        .lock()
        .map(|guard| *guard)
        .unwrap_or(false)
}

pub fn validate_server_url(raw_url: &str) -> anyhow::Result<String> {
    let parsed = url::Url::parse(raw_url.trim())
        .map_err(|_| anyhow::anyhow!("Invalid server URL format"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        anyhow::bail!("URL scheme must be http or https");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("URL must not contain credentials");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        anyhow::bail!("URL must not include query parameters or fragments");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL host is required"))?
        .to_lowercase();
    if host
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok_and(forbidden_streaming_ip)
        || host == "metadata.google.internal"
        || host.ends_with(".metadata.google.internal")
        || host == "metadata.goog"
        || host == "instance-data"
    {
        anyhow::bail!("Disallowed target host");
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

pub fn forbidden_streaming_ip(address: std::net::IpAddr) -> bool {
    let block_cgnat = env::var("AETHERFLOW_BLOCK_CGNAT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    match address {
        std::net::IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_unspecified()
                || address.is_link_local()
                || octets[0] == 0
                || (block_cgnat && octets[0] == 100 && (octets[1] & 0xc0) == 64)
                || octets == [168, 63, 129, 16]
                || (octets[0] == 192
                    && ((octets[1] == 0 && (octets[2] == 0 || octets[2] == 2))
                        || (octets[1] == 88 && octets[2] == 99)))
                || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                || octets[0] >= 224
        }
        std::net::IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(|mapped| forbidden_streaming_ip(mapped.into()))
            .unwrap_or_else(|| {
                if address.is_loopback() {
                    return false;
                }
                if address.is_unspecified()
                    || address.is_multicast()
                    || address.is_unicast_link_local()
                {
                    return true;
                }
                let segments = address.segments();
                if (segments[0] & 0xfe00) == 0xfc00 {
                    return segments[..2] == [0xfd00, 0x0ec2];
                }
                if (segments[0] & 0xe000) != 0x2000 {
                    return true;
                }
                (segments[0] == 0x2001 && (segments[1] < 0x0200 || segments[1] == 0x0db8))
                    || segments[0] == 0x2002
                    || (segments[0] == 0x3fff && segments[1] < 0x1000)
            }),
    }
}

struct StreamingResolver;

impl reqwest::dns::Resolve for StreamingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let hostname = name.as_str().to_string();
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((hostname.as_str(), 0))
                .await?
                .collect();
            if addresses.is_empty()
                || addresses
                    .iter()
                    .any(|address| forbidden_streaming_ip(address.ip()))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Disallowed resolved media-server address",
                )
                .into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

pub fn streaming_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(std::sync::Arc::new(StreamingResolver))
}
