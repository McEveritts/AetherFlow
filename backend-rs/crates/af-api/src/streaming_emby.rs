mod client;
mod models;
mod normalize;
mod operations;

#[cfg(test)]
mod tests;

pub const EMBY_PROVIDER_ID: &str = "emby";
pub const EMBY_DEFAULT_NAME: &str = "Emby Server";
pub const EMBY_DEFAULT_URL: &str = "http://127.0.0.1:8097";
pub const EMBY_SUPPORT_STAGE: &str = "coming_soon";
pub const EMBY_TICKS_PER_SECOND: i64 = 10_000_000;
pub const MAX_EMBY_JSON_PAYLOAD_BYTES: usize = 4 * 1024 * 1024; // 4 MiB hard cap for JSON payloads
pub const MAX_EMBY_ARTWORK_PAYLOAD_BYTES: usize = 8 * 1024 * 1024; // 8 MiB hard cap for artwork images

pub use client::{
    get_stored_emby_config, mask_emby_api_key, resolve_default_emby_url, sanitize_emby_token,
    validate_emby_server_url,
};
#[cfg(test)]
pub use models::EmbyItemSummaryRecord;
pub use models::{
    EmbyAdapterError, EmbyArtworkPayload, EmbyCommandKind, EmbyCommandOutcome, EmbyCommandTarget,
    EmbyOptionalEventCapability, EmbyServerConfig, EmbySessionCapabilityEvidence, EmbySessionRaw,
};
pub use normalize::{
    normalize_emby_media_type, normalize_emby_play_method, normalize_emby_session,
    resolve_emby_session_capabilities,
};
#[cfg(test)]
pub use operations::fetch_emby_item_summaries;
pub use operations::{
    fetch_emby_artwork, fetch_emby_live_sessions, probe_emby_optional_event_capability,
    send_emby_session_command, test_emby_connection,
};
