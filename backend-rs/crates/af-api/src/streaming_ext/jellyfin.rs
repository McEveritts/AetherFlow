use super::config::try_get_stored_jellyfin_config;
use super::models::{
    build_artwork_http_response, format_audio_layout, format_resolution_label,
    is_private_or_local_ip, mask_api_key, normalize_artwork_content_type, normalize_media_type,
    read_bounded_streaming_body, resolve_session_capabilities, sanitize_emby_token,
    JellyfinItemCounts, JellyfinSessionRaw, JellyfinSystemInfo, JELLYFIN_CLIENT,
    JELLYFIN_TICKS_PER_SECOND, MAX_ARTWORK_PAYLOAD_SIZE, MAX_UPSTREAM_PAYLOAD_SIZE,
};
use super::monitor::enrich_sessions_with_observed_metrics;
use af_services::{ActiveStreamSession, StreamingLibraryCounts, StreamingServerStatus};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use rusqlite::OptionalExtension;
use std::time::Duration;

pub(super) async fn do_jellyfin_request(
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

pub(super) async fn fetch_jellyfin_artwork_response(
    server_url: &str,
    api_key: &str,
    enabled: bool,
    item_id: &str,
) -> Response {
    if !enabled || api_key.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(clean_url) = af_services::validate_server_url(server_url) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let encoded_id = urlencoding::encode(item_id);
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

    let clean_token = sanitize_emby_token(api_key);
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
                if let Ok(bytes) = read_bounded_streaming_body(resp, MAX_ARTWORK_PAYLOAD_SIZE).await
                {
                    if !bytes.is_empty() && bytes.len() <= MAX_ARTWORK_PAYLOAD_SIZE {
                        image_bytes = Some(bytes);
                        break;
                    }
                }
            }
        }
    }

    let Some(data) = image_bytes else {
        return StatusCode::NOT_FOUND.into_response();
    };

    build_artwork_http_response(data, normalize_artwork_content_type(&raw_content_type))
}

pub async fn test_jellyfin_connection(
    server_url: &str,
    api_key: &str,
) -> anyhow::Result<StreamingServerStatus> {
    let clean_url = af_services::validate_server_url(server_url)?;

    let mut status = StreamingServerStatus {
        provider: "jellyfin".to_string(),
        name: "Jellyfin".to_string(),
        url: clean_url.clone(),
        api_key_masked: mask_api_key(api_key),
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
                anyhow::bail!("Cannot reach Jellyfin server: {}", e);
            }
        };

        if code == StatusCode::UNAUTHORIZED || code == StatusCode::FORBIDDEN {
            anyhow::bail!("invalid Jellyfin API key (HTTP {})", code.as_u16());
        }
        if !code.is_success() {
            anyhow::bail!("unexpected HTTP status {}", code.as_u16());
        }

        let sys_info = serde_json::from_slice::<JellyfinSystemInfo>(&body)?;
        if sys_info.id.trim().is_empty() {
            anyhow::bail!("Missing Jellyfin server identity");
        }
        let conn = af_db::get_conn()?;
        let pinned: Option<String> = conn
            .query_row(
                "SELECT COALESCE(server_id,'') FROM streaming_servers WHERE provider='jellyfin' AND RTRIM(url,'/')=?1",
                [&clean_url],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(pinned) = pinned.filter(|p| !p.is_empty()) {
            if !pinned.eq_ignore_ascii_case(&sys_info.id) {
                anyhow::bail!(
                    "Jellyfin server identity changed; explicitly reconfigure the connection"
                );
            }
        }
        if !sys_info.server_name.is_empty() {
            status.name = sys_info.server_name;
        }
        status.version = sys_info.version;
        status.server_id = sys_info.id;
        status.operating_system = sys_info.operating_system;

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
            anyhow::bail!("API key not configured")
        }
    }
}

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

    let (_, server_url, api_key, _) = try_get_stored_jellyfin_config()?;
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
    let Some(ts) = target_session else {
        anyhow::bail!("session {:?} not found on Jellyfin server", clean_id);
    };

    let (supports_media_ctrl, _, can_send_msg, _) = resolve_session_capabilities(&ts);
    let device_id = ts.device_id.trim().to_string();
    let play_session_id = ts
        .play_state
        .as_ref()
        .map(|ps| ps.play_session_id.trim().to_string())
        .unwrap_or_default();
    let has_active_transcode = ts.transcoding_info.is_some()
        || !play_session_id.is_empty()
        || ts
            .play_state
            .as_ref()
            .map(|ps| ps.play_method.eq_ignore_ascii_case("Transcode"))
            .unwrap_or(false);

    if !supports_media_ctrl {
        anyhow::bail!(
            "Fresh session capability evidence does not permit media control (SupportsMediaControl=false or unrecorded)"
        );
    }

    let escaped_id = urlencoding::encode(clean_id);
    let mut json_payload: Option<serde_json::Value> = None;

    let endpoint = match command {
        "pause" => format!("{}/Sessions/{}/Playing/Pause", clean_url, escaped_id),
        "resume" => format!("{}/Sessions/{}/Playing/Unpause", clean_url, escaped_id),
        "stop" => format!("{}/Sessions/{}/Playing/Stop", clean_url, escaped_id),
        "message" => {
            if !can_send_msg {
                anyhow::bail!(
                    "client {:?} ({}) does not support on-screen messages (DisplayMessage not in SupportedCommands)",
                    ts.client,
                    ts.device_name
                );
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

pub async fn fetch_jellyfin_live_sessions(
    server_name: &str,
    server_url: &str,
    api_key: &str,
) -> anyhow::Result<Vec<ActiveStreamSession>> {
    fetch_jellyfin_live_sessions_for_server(server_name, server_url, api_key, None).await
}

pub(super) async fn fetch_jellyfin_live_sessions_for_server(
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
        if raw_sessions.iter().any(|session| {
            session.now_playing_item.is_some()
                && !session.server_id.trim().eq_ignore_ascii_case(expected)
        }) {
            anyhow::bail!("Jellyfin session server identity is missing or changed");
        }
    }
    let mut active = Vec::new();
    let default_started_at = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

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
                "Subtitle"
                    if s.play_state
                        .as_ref()
                        .and_then(|ps| ps.subtitle_stream_index)
                        == Some(ms.index) =>
                {
                    subtitle_codec = ms.codec.to_uppercase();
                    subtitle_language = ms.language.to_uppercase();
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
            session_data_bytes: 0,
            started_at: default_started_at.clone(),
            play_session_id,
            media_source_id,
            supports_media_control,
            supports_remote_control,
            can_send_message,
            supported_commands,
        });
    }

    enrich_sessions_with_observed_metrics("jellyfin", &mut active);
    Ok(active)
}
