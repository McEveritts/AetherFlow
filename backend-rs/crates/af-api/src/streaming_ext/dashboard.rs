use super::analytics::{parse_window_days, try_query_streaming_analytics};
use super::config::{
    query_stored_provider_server_id, try_get_stored_emby_config_fail_closed,
    try_get_stored_jellyfin_config, try_get_stored_plex_config_fail_closed,
    try_get_stored_provider_config,
};
use super::demo::{get_synthetic_demo_sessions, is_demo_mode_active, seed_streaming_demo_data};
use super::jellyfin::{fetch_jellyfin_live_sessions_for_server, test_jellyfin_connection};
use super::models::mask_api_key;
use super::monitor::enrich_sessions_with_observed_metrics;
use super::plex::{fetch_plex_live_sessions, test_plex_connection};
use af_services::{
    ActiveStreamSession, StreamingDashboardResponse, StreamingLibraryCounts, StreamingLiveSummary,
    StreamingServerStatus,
};
use chrono::Utc;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Clone)]
struct CachedTelemetry {
    fingerprint: String,
    sampled_at: std::time::Instant,
    result: Result<(StreamingServerStatus, Vec<ActiveStreamSession>), String>,
}

static TELEMETRY_CACHE: Lazy<tokio::sync::Mutex<HashMap<String, CachedTelemetry>>> =
    Lazy::new(|| tokio::sync::Mutex::new(HashMap::new()));

pub(super) async fn cached_provider_telemetry(
    provider: &str,
) -> anyhow::Result<(StreamingServerStatus, Vec<ActiveStreamSession>)> {
    use sha2::Digest;
    let (name, url, key, enabled) = try_get_stored_provider_config(provider)?;
    anyhow::ensure!(
        enabled && !key.is_empty(),
        "Provider disabled or unconfigured"
    );
    let server_id = {
        let connection = af_db::get_conn()?;
        query_stored_provider_server_id(&connection, provider)?
    };
    anyhow::ensure!(
        !server_id.is_empty(),
        "Server identity is unverified; test the saved connection first"
    );
    let fingerprint = hex::encode(sha2::Sha256::digest(format!(
        "{name}\0{url}\0{key}\0{server_id}"
    )));
    let mut cache = TELEMETRY_CACHE.lock().await;
    if let Some(entry) = cache.get(provider).filter(|entry| {
        entry.fingerprint == fingerprint && entry.sampled_at.elapsed() < Duration::from_secs(15)
    }) {
        return entry.result.clone().map_err(anyhow::Error::msg);
    }
    let result = async {
        let mut status = if provider == "jellyfin" {
            test_jellyfin_connection(&url, &key).await?
        } else if provider == "plex" {
            test_plex_connection(&url, &key, Some(&server_id)).await?
        } else {
            crate::streaming_emby::test_emby_connection(&url, &key, Some(&server_id)).await?
        };
        anyhow::ensure!(
            status.server_id.eq_ignore_ascii_case(&server_id),
            "Provider server identity changed"
        );
        let mut sessions = if provider == "jellyfin" {
            fetch_jellyfin_live_sessions_for_server(&name, &url, &key, Some(&server_id)).await?
        } else if provider == "plex" {
            fetch_plex_live_sessions(&name, &url, &key, Some(&server_id)).await?
        } else {
            crate::streaming_emby::fetch_emby_live_sessions(&name, &url, &key, Some(&server_id))
                .await?
        };
        let (_, current_url, current_key, current_enabled) =
            try_get_stored_provider_config(provider)?;
        let current_server_id = {
            let connection = af_db::get_conn()?;
            query_stored_provider_server_id(&connection, provider)?
        };
        anyhow::ensure!(
            current_enabled
                && current_url == url
                && current_key == key
                && current_server_id == server_id,
            "Provider source changed during telemetry read"
        );
        if provider == crate::streaming_emby::EMBY_PROVIDER_ID {
            enrich_sessions_with_observed_metrics(
                crate::streaming_emby::EMBY_PROVIDER_ID,
                &mut sessions,
            );
        } else if provider == "plex" {
            enrich_sessions_with_observed_metrics("plex", &mut sessions);
        }
        status.name = name;
        Ok((status, sessions))
    }
    .await
    .map_err(|error: anyhow::Error| error.to_string());
    cache.insert(
        provider.into(),
        CachedTelemetry {
            fingerprint,
            sampled_at: std::time::Instant::now(),
            result: result.clone(),
        },
    );
    result.map_err(anyhow::Error::msg)
}

pub(super) async fn try_build_streaming_dashboard(
    window_raw: &str,
    play_method_filter: &str,
    media_type_filter: &str,
    is_admin: bool,
) -> anyhow::Result<StreamingDashboardResponse> {
    let (window_days, _) = parse_window_days(window_raw);
    let (jf_name, jf_url, jf_key, jf_enabled) = try_get_stored_jellyfin_config()?;

    let masked_key = if is_admin {
        mask_api_key(&jf_key)
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

    let emby_cfg = try_get_stored_emby_config_fail_closed()?;
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

    let plex_cfg = try_get_stored_plex_config_fail_closed()?;
    let plex_configured = !plex_cfg.api_key.is_empty();
    let plex_masked_key = if is_admin {
        mask_api_key(&plex_cfg.api_key)
    } else {
        String::new()
    };
    let mut plex_status = StreamingServerStatus {
        provider: "plex".to_string(),
        name: plex_cfg.name.clone(),
        url: plex_cfg.url.clone(),
        api_key_masked: plex_masked_key,
        configured: plex_configured,
        enabled: plex_cfg.enabled,
        status: if plex_cfg.enabled {
            "unconfigured".to_string()
        } else {
            "disabled".to_string()
        },
        support_stage: "active".to_string(),
        server_id: plex_cfg.expected_server_id.clone(),
        version: String::new(),
        operating_system: String::new(),
        library_counts: StreamingLibraryCounts::default(),
        last_connected_at: String::new(),
        error_message: String::new(),
    };

    let mut active_sessions: Vec<ActiveStreamSession> = Vec::new();
    let mut use_demo = is_demo_mode_active();
    if (emby_cfg.enabled && emby_configured) || (plex_cfg.enabled && plex_configured) {
        use_demo = false;
    }

    if jf_enabled && !jf_key.is_empty() {
        use_demo = false;
        match cached_provider_telemetry("jellyfin").await {
            Ok((status, sessions)) => {
                jf_status = status;
                active_sessions = sessions;
            }
            Err(error) => {
                jf_status.status = "unavailable".into();
                jf_status.error_message = error.to_string();
            }
        }
    } else if use_demo {
        let should_seed = {
            let conn = af_db::get_read_conn()?;
            let demo_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM streaming_history WHERE provider = 'demo'",
                [],
                |r| r.get(0),
            )?;
            demo_count == 0
        };
        if should_seed {
            let seeded = tokio::time::timeout(
                Duration::from_millis(500),
                tokio::task::spawn_blocking(seed_streaming_demo_data),
            )
            .await;
            match seeded {
                Ok(Ok(Ok(_))) => {}
                Ok(Ok(Err(error))) => return Err(error),
                Ok(Err(join_err)) => anyhow::bail!("Demo seeding task failed: {join_err}"),
                Err(_) => tracing::warn!("Timed out seeding streaming demo data"),
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
        jf_status.status = if jf_enabled {
            "unconfigured"
        } else {
            "disabled"
        }
        .into();
    }

    if plex_cfg.enabled && plex_configured {
        match cached_provider_telemetry("plex").await {
            Ok((status, sessions)) => {
                plex_status = status;
                active_sessions.extend(sessions);
            }
            Err(error) => {
                plex_status.status = "unavailable".into();
                plex_status.error_message = error.to_string();
            }
        }
    }

    if emby_cfg.enabled && emby_configured {
        match cached_provider_telemetry("emby").await {
            Ok((status, sessions)) => {
                emby_status = status;
                active_sessions.extend(sessions);
            }
            Err(error) => {
                emby_status.status = "unavailable".into();
                emby_status.error_message = error.to_string();
            }
        }
    }

    if !is_admin {
        jf_status.api_key_masked.clear();
        plex_status.api_key_masked.clear();
        emby_status.api_key_masked.clear();
        for s in &mut active_sessions {
            s.ip_address.clear();
        }
    }

    let servers = vec![jf_status, plex_status, emby_status];

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

    let analytics = try_query_streaming_analytics(
        window_days,
        play_method_filter,
        media_type_filter,
        use_demo,
        is_admin,
        total_bandwidth_mbps,
    )?;

    Ok(StreamingDashboardResponse {
        servers,
        live_summary,
        active_sessions,
        analytics,
        updated_at: Utc::now().to_rfc3339(),
    })
}

pub async fn build_streaming_dashboard(
    window_raw: &str,
    play_method_filter: &str,
    media_type_filter: &str,
    is_admin: bool,
) -> StreamingDashboardResponse {
    match try_build_streaming_dashboard(window_raw, play_method_filter, media_type_filter, is_admin)
        .await
    {
        Ok(resp) => resp,
        Err(error) => {
            tracing::error!(%error, "failed to build streaming dashboard");
            StreamingDashboardResponse {
                updated_at: Utc::now().to_rfc3339(),
                ..Default::default()
            }
        }
    }
}
