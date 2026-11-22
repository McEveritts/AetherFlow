use super::models::{
    EmbyAdapterError, EmbySessionCapabilityEvidence, EmbySessionRaw, EmbyTranscodingInfoRaw,
};
use super::{EMBY_DEFAULT_NAME, EMBY_PROVIDER_ID, EMBY_TICKS_PER_SECOND};
use af_services::ActiveStreamSession;
use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use std::collections::HashMap;

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

    let explicit_media_ctrl = s.supports_media_control.or_else(|| {
        s.capabilities
            .as_ref()
            .and_then(|c| c.supports_media_control)
    });

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

    let can_send_message = supports_media_control && supports_remote_control && has_display_message;

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
            "Subtitle"
                if s.play_state
                    .as_ref()
                    .and_then(|ps| ps.subtitle_stream_index)
                    == Some(ms.index) =>
            {
                subtitle_codec = ms.codec.trim().to_uppercase();
                subtitle_language = ms.language.trim().to_uppercase();
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
    } else if !item.series_id.trim().is_empty() && !item.series_primary_image_tag.trim().is_empty()
    {
        artwork_item_id = item.series_id.trim().to_string();
        has_artwork = true;
    } else if !item.backdrop_image_tags.is_empty() || !item.backdrop_image_tag.trim().is_empty() {
        if !item.backdrop_item_id.trim().is_empty() {
            artwork_item_id = item.backdrop_item_id.trim().to_string();
        }
        has_artwork = true;
    }

    let state_str = if is_paused { "paused" } else { "playing" }.to_string();
    let session_key = format!(
        "{}:{}:{}",
        EMBY_PROVIDER_ID, clean_session_id, clean_item_id
    );
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
        match conn
            .query_row(
                "SELECT data_used_bytes, COALESCE(started_at, '') FROM streaming_history WHERE session_key = ?1",
                params![session_key],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
        {
            Ok(Some((tracked, tracked_start))) => {
                session_data_bytes = tracked.max(0);
                if !tracked_start.trim().is_empty() {
                    started_at = tracked_start;
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, session_key = %session_key, "failed to load tracked Emby session history");
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
        artwork_item_id: if has_artwork {
            artwork_item_id
        } else {
            String::new()
        },
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
