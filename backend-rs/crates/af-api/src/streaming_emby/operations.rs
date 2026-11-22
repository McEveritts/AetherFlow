use super::client::{
    do_emby_request, mask_emby_api_key, sanitize_emby_token, validate_emby_server_url,
};
use super::models::{
    EmbyAdapterError, EmbyArtworkPayload, EmbyCommandKind, EmbyCommandOutcome, EmbyCommandTarget,
    EmbyItemCountsRaw, EmbyOptionalEventCapability, EmbyPluginInfoRaw, EmbySessionRaw,
    EmbySystemInfoRaw,
};
#[cfg(test)]
use super::models::{EmbyItemSummaryRecord, EmbyItemsEnvelopeRaw, EmbyUserRaw};
#[cfg(test)]
use super::normalize::{format_resolution_label, normalize_emby_media_type};
use super::normalize::{normalize_emby_session, resolve_emby_session_capabilities};
#[cfg(test)]
use super::EMBY_TICKS_PER_SECOND;
use super::{
    EMBY_DEFAULT_NAME, EMBY_PROVIDER_ID, EMBY_SUPPORT_STAGE, MAX_EMBY_ARTWORK_PAYLOAD_BYTES,
    MAX_EMBY_JSON_PAYLOAD_BYTES,
};
use af_services::{ActiveStreamSession, StreamingLibraryCounts, StreamingServerStatus};
use axum::http::StatusCode;
#[cfg(test)]
use chrono::DateTime;
use chrono::Utc;
use std::time::Duration;

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
    if !target
        .provider
        .trim()
        .eq_ignore_ascii_case(EMBY_PROVIDER_ID)
    {
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
            "header (max 120 chars) or message (max 1000 chars) exceeds maximum length".to_string(),
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
            message: format!(
                "Emby command {:?} rejected authentication",
                cmd_kind.as_str()
            ),
        });
    }
    if !cmd_code.is_success() {
        return Err(EmbyAdapterError::UpstreamStatus {
            status: cmd_code.as_u16(),
            message: format!("Emby command {:?} failed", cmd_kind.as_str()),
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
#[cfg(test)]
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
                                completion_pct =
                                    (((watched_secs as f64 / dur_secs as f64) * 1000.0).round()
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
                                watched_secs =
                                    ((dur_secs as f64) * (completion_pct / 100.0)).round() as i64;
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
