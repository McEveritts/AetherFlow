use super::models::{
    build_artwork_http_response, is_private_or_local_ip, mask_api_key,
    normalize_artwork_content_type, read_bounded_streaming_body, sanitize_emby_token,
    JELLYFIN_CLIENT, MAX_ARTWORK_PAYLOAD_SIZE, MAX_UPSTREAM_PAYLOAD_SIZE,
};
use crate::auth::api_error;
use af_services::{ActiveStreamSession, StreamingLibraryCounts, StreamingServerStatus};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use std::time::Duration;

#[allow(clippy::result_large_err)]
pub fn save_plex_server_configuration(
    name_raw: &str,
    url_raw: &str,
    api_key_raw: &str,
    enabled: bool,
) -> Result<String, Response> {
    let clean_url = af_services::validate_server_url(url_raw)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", e.to_string()))?;
    let trimmed_key = api_key_raw.trim();
    let is_masked = trimmed_key.starts_with("****");
    let enc_key = if trimmed_key.is_empty() || is_masked {
        String::new()
    } else {
        let clean_token = sanitize_emby_token(trimmed_key);
        if clean_token.is_empty() {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                "Valid Plex token is required",
            ));
        }
        match af_db::encrypt_key(&clean_token) {
            Ok(key) if !af_db::is_encryption_enabled() || key.starts_with("enc:v1:") => key,
            _ => {
                return Err(api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "STREAMING_KEY_STORAGE_FAILED",
                    "Failed to encrypt Plex token; configuration was not changed",
                ));
            }
        }
    };

    let conn = af_db::get_conn().map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        )
    })?;

    if enc_key.is_empty() {
        let existing = conn
            .query_row(
                "SELECT url, api_key FROM streaming_servers WHERE provider = 'plex'",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to read existing Plex server configuration",
                )
            })?;

        match existing {
            Some((prev_url, prev_key)) => {
                if prev_url.trim().trim_end_matches('/') != clean_url {
                    return Err(api_error(
                        StatusCode::BAD_REQUEST,
                        "STREAMING_KEY_REQUIRED",
                        "Provide a fresh Plex token when changing the server URL; stored credentials cannot be transferred to another server",
                    ));
                }
                if is_masked {
                    let valid_prev = if prev_key.starts_with("enc:v1:") {
                        af_db::decrypt_key(&prev_key)
                            .map(|d| !d.trim().is_empty() && !d.starts_with("enc:v1:"))
                            .unwrap_or(false)
                    } else {
                        !prev_key.trim().is_empty()
                    };
                    if !valid_prev {
                        return Err(api_error(
                            StatusCode::BAD_REQUEST,
                            "STREAMING_KEY_REQUIRED",
                            "Provide a fresh Plex token when replacing an unreadable credential",
                        ));
                    }
                }
            }
            None => {
                if is_masked {
                    return Err(api_error(
                        StatusCode::BAD_REQUEST,
                        "STREAMING_KEY_REQUIRED",
                        "Provide a full Plex token on initial configuration",
                    ));
                }
            }
        }
    }

    let name = if name_raw.trim().is_empty() {
        "Plex Media Server".to_string()
    } else {
        name_raw.trim().to_string()
    };

    conn.execute(
        r#"
        INSERT INTO streaming_servers (provider, name, url, api_key, enabled, updated_at)
        VALUES ('plex', ?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)
        ON CONFLICT(provider) DO UPDATE SET
            name = excluded.name,
            server_id = CASE WHEN RTRIM(streaming_servers.url, '/') != RTRIM(excluded.url, '/') THEN '' ELSE streaming_servers.server_id END,
            server_version = CASE WHEN RTRIM(streaming_servers.url, '/') != RTRIM(excluded.url, '/') THEN '' ELSE streaming_servers.server_version END,
            last_connected_at = CASE WHEN RTRIM(streaming_servers.url, '/') != RTRIM(excluded.url, '/') THEN NULL ELSE streaming_servers.last_connected_at END,
            url = excluded.url,
            api_key = CASE WHEN excluded.api_key != '' THEN excluded.api_key ELSE streaming_servers.api_key END,
            enabled = excluded.enabled,
            updated_at = CURRENT_TIMESTAMP
        "#,
        params![name, clean_url, enc_key, enabled],
    )
    .map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to save Plex server configuration",
        )
    })?;

    Ok(clean_url)
}

pub(super) fn persist_plex_verified_identity(
    status: &StreamingServerStatus,
    clean_url: &str,
    api_key: &str,
) -> anyhow::Result<()> {
    if status.server_id.trim().is_empty() {
        return Ok(());
    }
    let conn = af_db::get_conn()?;
    let norm_url = clean_url.trim_end_matches('/');
    let Some(stored_cipher) = conn
        .query_row(
            "SELECT api_key FROM streaming_servers WHERE provider = 'plex' AND RTRIM(url, '/') = ?1",
            params![norm_url],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    else {
        return Ok(());
    };
    let plaintext = if stored_cipher.starts_with("enc:v1:") {
        match af_db::decrypt_key(&stored_cipher) {
            Ok(dec) if !dec.starts_with("enc:v1:") => dec,
            _ => String::new(),
        }
    } else {
        stored_cipher.clone()
    };
    if !plaintext.is_empty() && sanitize_emby_token(&plaintext) == sanitize_emby_token(api_key) {
        conn.execute(
            "UPDATE streaming_servers \
             SET server_id = CASE WHEN COALESCE(server_id, '') = '' THEN ?1 ELSE server_id END, \
                 server_version = ?2, \
                 last_connected_at = CURRENT_TIMESTAMP \
             WHERE provider = 'plex' AND RTRIM(url, '/') = ?3 AND api_key = ?4 \
               AND (COALESCE(server_id, '') = '' OR LOWER(server_id) = LOWER(?1))",
            params![status.server_id, status.version, norm_url, stored_cipher],
        )?;
    }
    Ok(())
}

async fn do_plex_request(
    url: &str,
    api_key: &str,
    timeout: Duration,
    max_bytes: usize,
) -> anyhow::Result<(Vec<u8>, StatusCode, String)> {
    let mut target = url::Url::parse(url)?;
    target.set_query(None);
    af_services::validate_server_url(target.as_str())?;
    let mut builder = JELLYFIN_CLIENT
        .get(url)
        .timeout(timeout)
        .header(header::ACCEPT, "application/json")
        .header("X-Plex-Client-Identifier", "aetherflow-nexus")
        .header("X-Plex-Product", "AetherFlow")
        .header("X-Plex-Version", "4.0.0");
    let clean_token = sanitize_emby_token(api_key);
    if !clean_token.is_empty() {
        builder = builder.header("X-Plex-Token", clean_token);
    }
    let resp = builder.send().await?;
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = read_bounded_streaming_body(resp, max_bytes).await?;
    Ok((body, status, content_type))
}

pub async fn test_plex_connection(
    server_url: &str,
    api_key: &str,
    expected_server_id: Option<&str>,
) -> anyhow::Result<StreamingServerStatus> {
    let clean_url = af_services::validate_server_url(server_url)?;
    let clean_token = sanitize_emby_token(api_key);

    let mut status = StreamingServerStatus {
        provider: "plex".to_string(),
        name: "Plex Media Server".to_string(),
        url: clean_url.clone(),
        api_key_masked: mask_api_key(&clean_token),
        configured: !clean_token.is_empty(),
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

    let (id_body, id_code, _) = do_plex_request(
        &format!("{}/identity", clean_url),
        &clean_token,
        Duration::from_secs(6),
        MAX_UPSTREAM_PAYLOAD_SIZE,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Cannot reach Plex server: {e}"))?;

    if id_code == StatusCode::UNAUTHORIZED || id_code == StatusCode::FORBIDDEN {
        anyhow::bail!("invalid Plex token (HTTP {})", id_code.as_u16());
    }
    if !id_code.is_success() {
        anyhow::bail!("Plex /identity returned HTTP {}", id_code.as_u16());
    }

    let id_json: serde_json::Value = serde_json::from_slice(&id_body)?;
    let id_mc = id_json.get("MediaContainer").unwrap_or(&id_json);
    let machine_id = id_mc
        .get("machineIdentifier")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let version = id_mc
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    if machine_id.is_empty() {
        anyhow::bail!("Missing Plex server machineIdentifier");
    }
    if let Some(exp) = expected_server_id.filter(|s| !s.trim().is_empty()) {
        if !exp.eq_ignore_ascii_case(&machine_id) {
            anyhow::bail!("Plex server identity changed; explicitly reconfigure the connection");
        }
    }
    let conn = af_db::get_conn()?;
    let pinned: Option<String> = conn
        .query_row(
            "SELECT COALESCE(server_id, '') FROM streaming_servers WHERE provider = 'plex' AND RTRIM(url, '/') = ?1",
            [&clean_url],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(pinned) = pinned.filter(|p| !p.is_empty()) {
        if !pinned.eq_ignore_ascii_case(&machine_id) {
            anyhow::bail!("Plex server identity changed; explicitly reconfigure the connection");
        }
    }

    status.server_id = machine_id;
    status.version = version;

    if clean_token.is_empty() {
        status.status = "unconfigured".to_string();
        status.error_message = format!(
            "Plex Media Server detected at {} — add an X-Plex-Token to enable telemetry",
            clean_url
        );
        return Ok(status);
    }

    // Authenticated probe against `/library/sections` (verifies token + enumerates libraries)
    let (sec_body, sec_code, _) = do_plex_request(
        &format!("{}/library/sections", clean_url),
        &clean_token,
        Duration::from_secs(6),
        MAX_UPSTREAM_PAYLOAD_SIZE,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Cannot query Plex libraries: {e}"))?;

    if sec_code == StatusCode::UNAUTHORIZED || sec_code == StatusCode::FORBIDDEN {
        anyhow::bail!("invalid Plex token (HTTP {})", sec_code.as_u16());
    }
    if !sec_code.is_success() {
        anyhow::bail!("Plex /library/sections returned HTTP {}", sec_code.as_u16());
    }

    let sec_json: serde_json::Value = serde_json::from_slice(&sec_body)?;
    let sec_mc = sec_json.get("MediaContainer").unwrap_or(&sec_json);
    if let Some(title) = sec_mc
        .get("title1")
        .or_else(|| sec_mc.get("friendlyName"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("Plex Library"))
    {
        status.name = title.to_string();
    }

    // Optional root capability query for friendlyName & operating system
    if let Ok((root_body, StatusCode::OK, _)) = do_plex_request(
        &format!("{}/", clean_url),
        &clean_token,
        Duration::from_secs(4),
        MAX_UPSTREAM_PAYLOAD_SIZE,
    )
    .await
    {
        if let Ok(root_json) = serde_json::from_slice::<serde_json::Value>(&root_body) {
            let rmc = root_json.get("MediaContainer").unwrap_or(&root_json);
            if let Some(fname) = rmc
                .get("friendlyName")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                status.name = fname.to_string();
            }
            if let Some(plat) = rmc
                .get("platform")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let pver = rmc
                    .get("platformVersion")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .unwrap_or("");
                status.operating_system = if pver.is_empty() {
                    plat.to_string()
                } else {
                    format!("{plat} {pver}")
                };
            }
        }
    }

    let mut counts = StreamingLibraryCounts::default();
    if let Some(dirs) = sec_mc.get("Directory").and_then(|d| d.as_array()) {
        for dir in dirs.iter().take(24) {
            let sec_type = dir
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let sec_key = dir
                .get("key")
                .and_then(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .or_else(|| v.as_i64().map(|n| n.to_string()))
                })
                .unwrap_or_default();
            let inline_count = dir
                .get("totalSize")
                .or_else(|| dir.get("count"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);

            let resolved_count = if inline_count >= 0 {
                inline_count as i32
            } else if !sec_key.is_empty() && sec_key.chars().all(|c| c.is_ascii_alphanumeric()) {
                if let Ok((c_body, StatusCode::OK, _)) = do_plex_request(
                    &format!(
                        "{}/library/sections/{}/all?X-Plex-Container-Start=0&X-Plex-Container-Size=0",
                        clean_url, sec_key
                    ),
                    &clean_token,
                    Duration::from_secs(4),
                    MAX_UPSTREAM_PAYLOAD_SIZE,
                )
                .await
                {
                    serde_json::from_slice::<serde_json::Value>(&c_body)
                        .ok()
                        .and_then(|v| {
                            let mc = v.get("MediaContainer").unwrap_or(&v);
                            mc.get("totalSize")
                                .or_else(|| mc.get("size"))
                                .and_then(|n| n.as_i64())
                        })
                        .unwrap_or(0) as i32
                } else {
                    0
                }
            } else {
                0
            };

            match sec_type.as_str() {
                "movie" => counts.movies += resolved_count.max(0),
                "show" => counts.series += resolved_count.max(0),
                "artist" => counts.audio += resolved_count.max(0),
                _ => {}
            }
        }
    }
    status.library_counts = counts;
    status.status = "connected".to_string();
    status.last_connected_at = Utc::now().to_rfc3339();
    Ok(status)
}

fn plex_val_str(obj: &serde_json::Value, key: &str) -> String {
    match obj.get(key) {
        Some(serde_json::Value::String(s)) => s.trim().to_string(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

pub async fn fetch_plex_live_sessions(
    server_name: &str,
    server_url: &str,
    api_key: &str,
    expected_server_id: Option<&str>,
) -> anyhow::Result<Vec<ActiveStreamSession>> {
    let clean_url = af_services::validate_server_url(server_url)?;
    let clean_token = sanitize_emby_token(api_key);
    anyhow::ensure!(!clean_token.is_empty(), "Plex token is not configured");

    if let Some(exp_id) = expected_server_id.filter(|s| !s.trim().is_empty()) {
        let (id_body, id_code, _) = do_plex_request(
            &format!("{}/identity", clean_url),
            &clean_token,
            Duration::from_secs(5),
            MAX_UPSTREAM_PAYLOAD_SIZE,
        )
        .await?;
        anyhow::ensure!(
            id_code.is_success(),
            "Plex /identity returned HTTP {}",
            id_code.as_u16()
        );
        let id_json: serde_json::Value = serde_json::from_slice(&id_body)?;
        let live_id = id_json
            .get("MediaContainer")
            .unwrap_or(&id_json)
            .get("machineIdentifier")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        anyhow::ensure!(
            live_id.eq_ignore_ascii_case(exp_id),
            "Plex server machineIdentifier mismatch"
        );
    }

    let (body, code, _) = do_plex_request(
        &format!("{}/status/sessions", clean_url),
        &clean_token,
        Duration::from_secs(8),
        MAX_UPSTREAM_PAYLOAD_SIZE,
    )
    .await?;
    if code == StatusCode::UNAUTHORIZED || code == StatusCode::FORBIDDEN {
        anyhow::bail!("invalid Plex token (HTTP {})", code.as_u16());
    }
    anyhow::ensure!(
        code.is_success(),
        "Plex /status/sessions returned HTTP {}",
        code.as_u16()
    );

    let root: serde_json::Value = serde_json::from_slice(&body)?;
    let mc = root.get("MediaContainer").unwrap_or(&root);
    let Some(metadata) = mc.get("Metadata").and_then(|m| m.as_array()) else {
        return Ok(Vec::new());
    };

    let effective_server_name = if server_name.trim().is_empty() {
        "Plex Media Server"
    } else {
        server_name.trim()
    };

    let mut sessions = Vec::with_capacity(metadata.len());
    for item in metadata {
        let item_id = plex_val_str(item, "ratingKey");
        if item_id.is_empty() {
            continue;
        }
        let session_obj = item.get("Session").unwrap_or(&serde_json::Value::Null);
        let player_obj = item.get("Player").unwrap_or(&serde_json::Value::Null);
        let user_obj = item.get("User").unwrap_or(&serde_json::Value::Null);
        let transcode_obj = item.get("TranscodeSession");

        let mut session_id = plex_val_str(session_obj, "id");
        if session_id.is_empty() {
            session_id = plex_val_str(item, "sessionKey");
        }
        if session_id.is_empty() {
            let p_mid = plex_val_str(player_obj, "machineIdentifier");
            session_id = if p_mid.is_empty() {
                format!("plex-sess-{item_id}")
            } else {
                format!("{p_mid}:{item_id}")
            };
        }

        let user_id_raw = plex_val_str(user_obj, "id");
        let user_name = {
            let t = plex_val_str(user_obj, "title");
            if t.is_empty() {
                if user_id_raw.is_empty() {
                    "Plex User".to_string()
                } else {
                    user_id_raw.clone()
                }
            } else {
                t
            }
        };
        let user_id = if user_id_raw.is_empty() {
            user_name.clone()
        } else {
            user_id_raw
        };

        let item_name = {
            let t = plex_val_str(item, "title");
            if t.is_empty() {
                "Unknown Media".to_string()
            } else {
                t
            }
        };
        let series_name = plex_val_str(item, "grandparentTitle");
        let series_id = plex_val_str(item, "grandparentRatingKey");
        let raw_type = plex_val_str(item, "type").to_ascii_lowercase();
        let item_type = match raw_type.as_str() {
            "movie" => "Movie",
            "episode" => "Episode",
            "track" => "Audio",
            _ => "Video",
        }
        .to_string();

        let season_number = item
            .get("parentIndex")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .max(0) as i32;
        let episode_number = item
            .get("index")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .max(0) as i32;
        let production_year = item
            .get("year")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .max(0) as i32;

        let client_name = {
            let prod = plex_val_str(player_obj, "product");
            if prod.is_empty() {
                plex_val_str(player_obj, "title")
            } else {
                prod
            }
        };
        let device_name = {
            let dev = plex_val_str(player_obj, "device");
            if dev.is_empty() {
                let plat = plex_val_str(player_obj, "platform");
                if plat.is_empty() {
                    plex_val_str(player_obj, "title")
                } else {
                    plat
                }
            } else {
                dev
            }
        };
        let device_id = plex_val_str(player_obj, "machineIdentifier");
        let app_version = plex_val_str(player_obj, "version");
        let ip_address = {
            let addr = plex_val_str(player_obj, "address");
            if addr.is_empty() {
                plex_val_str(player_obj, "remotePublicAddress")
            } else {
                addr
            }
        };
        let loc = plex_val_str(session_obj, "location").to_ascii_lowercase();
        let is_lan = if loc == "lan" {
            true
        } else if loc == "wan" {
            false
        } else {
            player_obj
                .get("local")
                .and_then(|v| v.as_bool())
                .unwrap_or_else(|| is_private_or_local_ip(&ip_address))
        };

        let raw_state = plex_val_str(player_obj, "state").to_ascii_lowercase();
        let state = match raw_state.as_str() {
            "paused" => "paused",
            "buffering" => "buffering",
            _ => "playing",
        }
        .to_string();

        let duration_ms = item
            .get("duration")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .max(0);
        let offset_ms = item
            .get("viewOffset")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .max(0);
        let duration_secs = duration_ms / 1000;
        let position_secs = offset_ms / 1000;
        let progress_pct = if duration_ms > 0 {
            (((offset_ms as f64 / duration_ms as f64) * 1000.0).round() / 10.0).clamp(0.0, 100.0)
        } else {
            0.0
        };

        let first_media = item
            .get("Media")
            .and_then(|m| m.as_array())
            .and_then(|a| a.first());
        let mut container = first_media
            .map(|m| plex_val_str(m, "container").to_uppercase())
            .unwrap_or_default();
        let mut video_codec = first_media
            .map(|m| plex_val_str(m, "videoCodec").to_uppercase())
            .unwrap_or_default();
        let raw_res = first_media
            .map(|m| plex_val_str(m, "videoResolution"))
            .unwrap_or_default();
        let video_resolution = match raw_res.to_ascii_lowercase().as_str() {
            "4k" | "2160" | "2160p" => "4K".to_string(),
            "1080" | "1080p" => "1080p".to_string(),
            "720" | "720p" => "720p".to_string(),
            "480" | "480p" | "sd" => "480p".to_string(),
            "" => String::new(),
            other => other.to_string(),
        };
        let mut audio_codec = first_media
            .map(|m| plex_val_str(m, "audioCodec").to_uppercase())
            .unwrap_or_default();
        let mut audio_channels = first_media
            .and_then(|m| m.get("audioChannels"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .max(0) as i32;
        let media_bitrate_kbps = first_media
            .and_then(|m| m.get("bitrate"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .max(0);

        let mut subtitle_codec = String::new();
        let mut subtitle_language = String::new();
        let mut audio_language = String::new();
        let mut video_range = "SDR".to_string();
        if let Some(streams) = first_media
            .and_then(|m| m.get("Part"))
            .and_then(|p| p.as_array())
            .and_then(|a| a.first())
            .and_then(|part| part.get("Stream"))
            .and_then(|s| s.as_array())
        {
            for st in streams {
                let st_type = st.get("streamType").and_then(|v| v.as_i64()).unwrap_or(0);
                if st_type == 1 {
                    if video_codec.is_empty() {
                        video_codec = plex_val_str(st, "codec").to_uppercase();
                    }
                    let dovi = st
                        .get("DOVIPresent")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let cs = plex_val_str(st, "colorTrc").to_ascii_lowercase();
                    if dovi {
                        video_range = "Dolby Vision".to_string();
                    } else if cs.contains("2084") || cs.contains("arib-std-b67") {
                        video_range = "HDR".to_string();
                    }
                } else if st_type == 2 {
                    if audio_codec.is_empty() {
                        audio_codec = plex_val_str(st, "codec").to_uppercase();
                    }
                    if audio_channels == 0 {
                        audio_channels =
                            st.get("channels").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                    }
                    if audio_language.is_empty() {
                        audio_language = plex_val_str(st, "languageCode");
                    }
                } else if st_type == 3
                    && st
                        .get("selected")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                {
                    subtitle_codec = plex_val_str(st, "codec").to_uppercase();
                    subtitle_language = plex_val_str(st, "languageCode");
                }
            }
        }
        if container.is_empty() {
            container = "MKV".to_string();
        }

        let mut play_method = "DirectPlay".to_string();
        let mut is_video_direct = true;
        let mut is_audio_direct = true;
        let mut target_container = String::new();
        let mut target_video_codec = String::new();
        let mut target_audio_codec = String::new();
        let mut hw_accel = String::new();
        let mut transcode_progress_pct = 0.0;
        let mut transcode_fps = 0.0;
        let mut play_session_id = plex_val_str(session_obj, "id");

        if let Some(ts) = transcode_obj.filter(|v| v.is_object()) {
            let v_dec = plex_val_str(ts, "videoDecision").to_ascii_lowercase();
            let a_dec = plex_val_str(ts, "audioDecision").to_ascii_lowercase();
            is_video_direct = v_dec != "transcode";
            is_audio_direct = a_dec != "transcode";
            if v_dec == "transcode" || a_dec == "transcode" {
                play_method = "Transcode".to_string();
            } else if v_dec == "copy" || a_dec == "copy" {
                play_method = "DirectStream".to_string();
            }
            target_container = plex_val_str(ts, "container").to_uppercase();
            target_video_codec = plex_val_str(ts, "videoCodec").to_uppercase();
            target_audio_codec = plex_val_str(ts, "audioCodec").to_uppercase();
            let hw_enc = plex_val_str(ts, "transcodeHwEncoding");
            let hw_dec = plex_val_str(ts, "transcodeHwDecoding");
            if !hw_enc.is_empty() {
                hw_accel = hw_enc.to_uppercase();
            } else if !hw_dec.is_empty() {
                hw_accel = hw_dec.to_uppercase();
            } else if ts
                .get("transcodeHwRequested")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                hw_accel = "HW".to_string();
            }
            transcode_progress_pct = ts.get("progress").and_then(|v| v.as_f64()).unwrap_or(0.0);
            transcode_fps = ts.get("speed").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let ts_key = plex_val_str(ts, "key");
            if !ts_key.is_empty() {
                play_session_id = ts_key;
            }
        }

        let sess_bw_kbps = session_obj
            .get("bandwidth")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            .max(0);
        let bitrate_bps = if sess_bw_kbps > 0 {
            sess_bw_kbps.saturating_mul(1000)
        } else {
            media_bitrate_kbps.saturating_mul(1000)
        };
        let bandwidth_mbps = ((bitrate_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;

        let has_thumb = !plex_val_str(item, "thumb").is_empty()
            || !plex_val_str(item, "grandparentThumb").is_empty();
        let artwork_item_id =
            if !series_id.is_empty() && !plex_val_str(item, "grandparentThumb").is_empty() {
                series_id.clone()
            } else if has_thumb {
                item_id.clone()
            } else {
                String::new()
            };

        sessions.push(ActiveStreamSession {
            session_id,
            provider: "plex".to_string(),
            server_name: effective_server_name.to_string(),
            user_id,
            user_name,
            client_name,
            device_name,
            device_id,
            app_version,
            ip_address,
            is_lan,
            item_id: item_id.clone(),
            item_name,
            item_type,
            series_name,
            series_id,
            season_number,
            episode_number,
            production_year,
            has_artwork: has_thumb,
            artwork_item_id,
            state,
            position_secs,
            duration_secs,
            progress_pct,
            play_method,
            container,
            target_container,
            video_codec,
            target_video_codec,
            video_resolution,
            video_range,
            video_framerate: 0.0,
            is_video_direct,
            audio_codec,
            target_audio_codec,
            audio_channels,
            audio_layout: if audio_channels >= 6 {
                "5.1".to_string()
            } else if audio_channels >= 2 {
                "stereo".to_string()
            } else {
                String::new()
            },
            audio_language,
            is_audio_direct,
            subtitle_codec,
            subtitle_language,
            hw_accel,
            transcode_reasons: Vec::new(),
            transcode_progress_pct,
            transcode_fps,
            bitrate_bps,
            bandwidth_mbps,
            session_data_bytes: 0,
            started_at: Utc::now().to_rfc3339(),
            play_session_id,
            media_source_id: item_id,
            supports_media_control: false,
            supports_remote_control: false,
            can_send_message: false,
            supported_commands: Vec::new(),
        });
    }

    Ok(sessions)
}

pub(super) async fn fetch_plex_artwork_response(
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
    let thumb_url = format!("{}/library/metadata/{}/thumb", clean_url, encoded_id);
    match do_plex_request(
        &thumb_url,
        api_key,
        Duration::from_secs(6),
        MAX_ARTWORK_PAYLOAD_SIZE,
    )
    .await
    {
        Ok((bytes, StatusCode::OK, raw_ct)) if !bytes.is_empty() => {
            build_artwork_http_response(bytes, normalize_artwork_content_type(&raw_ct))
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}
