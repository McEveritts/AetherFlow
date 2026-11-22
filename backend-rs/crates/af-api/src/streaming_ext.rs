//! Streaming telemetry, provider connectors (Jellyfin, Emby, Plex), watch-history
//! summary synchronization, analytics cohorts, and HTTP handlers.

mod analytics;
mod config;
mod dashboard;
mod demo;
mod emby;
mod handlers;
mod jellyfin;
mod models;
mod monitor;
mod plex;
mod summary_sync;

#[cfg(test)]
pub(crate) mod tests;

pub use analytics::{parse_window_days, query_streaming_analytics};
pub use config::{
    get_stored_emby_config_fail_closed, get_stored_jellyfin_config,
    get_stored_plex_config_fail_closed,
};
pub use dashboard::build_streaming_dashboard;
pub use demo::{
    clear_streaming_demo_data, get_synthetic_demo_sessions, is_demo_mode_active,
    seed_streaming_demo_data,
};
pub use emby::save_emby_server_configuration;
pub use handlers::{
    control_streaming_session, get_streaming_artwork, get_streaming_dashboard_handler,
    sync_streaming_server_history, test_streaming_server,
};
pub use jellyfin::{
    fetch_jellyfin_live_sessions, send_jellyfin_session_command, test_jellyfin_connection,
};
pub use models::{
    JellyfinSummarySyncOutcome, PlexServerConfig, SessionCommandReq, TestStreamingServerReq,
};
pub use monitor::{
    close_disabled_provider, format_observed_session_key, record_live_sessions_snapshot,
    start_streaming_monitor,
};
pub use plex::{fetch_plex_live_sessions, save_plex_server_configuration, test_plex_connection};
pub use summary_sync::sync_jellyfin_watch_history;
