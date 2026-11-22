use super::config::try_get_stored_jellyfin_config;
use super::jellyfin::do_jellyfin_request;
use super::models::{
    format_resolution_label, normalize_media_type, JellyfinItemsEnvelope,
    JellyfinSummarySyncOutcome, JellyfinUserRaw, JELLYFIN_TICKS_PER_SECOND,
    MAX_UPSTREAM_PAYLOAD_SIZE,
};
use super::monitor::verify_monitor_source;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};
use std::time::Duration;

static SUMMARY_SWEEP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn sync_jellyfin_watch_history() -> anyhow::Result<JellyfinSummarySyncOutcome> {
    let _flight = SUMMARY_SWEEP_LOCK
        .try_lock()
        .map_err(|_| anyhow::anyhow!("Jellyfin summary sync is already running"))?;
    tokio::time::timeout(Duration::from_secs(45), sync_jellyfin_summary_batch()).await?
}

async fn sync_jellyfin_summary_batch() -> anyhow::Result<JellyfinSummarySyncOutcome> {
    let (server_name, server_url, api_key, enabled) = try_get_stored_jellyfin_config()?;
    if !enabled || api_key.is_empty() {
        anyhow::bail!("Jellyfin API key is not configured");
    }
    let clean_url = af_services::validate_server_url(&server_url)?;
    let server_id = verify_monitor_source("jellyfin", &server_url, &api_key).await?;
    let instance_identity = if server_id.is_empty() {
        use sha2::Digest;
        format!(
            "url-{}",
            hex::encode(sha2::Sha256::digest(clean_url.as_bytes()))
        )
    } else {
        server_id.clone()
    };

    let (users_body, code, _) = do_jellyfin_request(
        reqwest::Method::GET,
        &format!("{}/Users", clean_url),
        &api_key,
        None,
        Duration::from_secs(8),
        MAX_UPSTREAM_PAYLOAD_SIZE,
    )
    .await?;

    if !code.is_success() {
        anyhow::bail!("Jellyfin /Users returned HTTP {}", code.as_u16());
    }

    let users: Vec<JellyfinUserRaw> = serde_json::from_slice(&users_body)?;
    anyhow::ensure!(users.len() <= 1024, "Summary user budget exceeded");
    let mut imported = 0usize;
    let page_size = 100usize;
    let filters = ["IsPlayed", "IsResumable"];
    let mut remaining_pages = 8usize;

    let mut pending_sources: Vec<(JellyfinUserRaw, &'static str, String)> = Vec::new();
    {
        let conn = af_db::get_conn()?;
        for u in users {
            if u.id.trim().is_empty() {
                continue;
            }
            for filter in filters {
                let checkpoint_source = format!("summary:{}:{filter}", u.id);
                let completed = conn
                    .query_row(
                        "SELECT checkpoint='-1' FROM streaming_import_checkpoints WHERE provider='jellyfin' AND server_id=?1 AND source=?2",
                        params![server_id, checkpoint_source],
                        |row| row.get::<_, bool>(0),
                    )
                    .optional()?
                    .unwrap_or(false);
                if !completed {
                    pending_sources.push((u.clone(), filter, checkpoint_source));
                }
            }
        }
    }

    let total_pending = pending_sources.len();
    for (idx, (u, filter, checkpoint_source)) in pending_sources.into_iter().enumerate() {
        let encoded_uid = urlencoding::encode(u.id.trim());
        let mut start_index = af_db::get_conn()?
            .query_row(
                "SELECT checkpoint FROM streaming_import_checkpoints WHERE provider='jellyfin' AND server_id=?1 AND source=?2",
                params![server_id, checkpoint_source],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        loop {
            if remaining_pages == 0 {
                let remaining_sources = total_pending.saturating_sub(idx);
                return Ok(JellyfinSummarySyncOutcome {
                    imported,
                    complete: false,
                    has_more: true,
                    remaining_sources,
                    next_offset: Some(start_index),
                });
            }
            remaining_pages -= 1;
            let (_, current_url, current_key, current_enabled) = try_get_stored_jellyfin_config()?;
            if !current_enabled || current_url != server_url || current_key != api_key {
                anyhow::bail!("Summary source changed or disabled");
            }
            let items_url = format!(
                "{}/Users/{}/Items?Recursive=true&Filters={}&IncludeItemTypes=Movie,Episode,Audio&Fields=MediaStreams,Container,ProductionYear&SortBy=SortName,Id&SortOrder=Ascending&Limit={}&StartIndex={}",
                clean_url, encoded_uid, filter, page_size, start_index
            );
            let (items_body, i_code, _) = do_jellyfin_request(
                reqwest::Method::GET,
                &items_url,
                &api_key,
                None,
                Duration::from_secs(15),
                MAX_UPSTREAM_PAYLOAD_SIZE,
            )
            .await?;

            if i_code != StatusCode::OK {
                anyhow::bail!("Jellyfin history request returned HTTP {}", i_code.as_u16());
            }

            let payload = serde_json::from_slice::<JellyfinItemsEnvelope>(&items_body)?;
            if payload.items.is_empty() {
                af_db::get_conn()?.execute(
                    "INSERT INTO streaming_import_checkpoints(provider,server_id,source,checkpoint,updated_at) VALUES('jellyfin',?1,?2,'-1',CURRENT_TIMESTAMP) ON CONFLICT(provider,server_id,source) DO UPDATE SET checkpoint='-1',updated_at=CURRENT_TIMESTAMP",
                    params![server_id, checkpoint_source],
                )?;
                break;
            }

            let batch_len = payload.items.len();
            {
                let mut conn = af_db::get_conn()?;
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                for item in payload.items {
                    let dur_secs = (item.run_time_ticks / JELLYFIN_TICKS_PER_SECOND).max(0);
                    let mut v_codec = String::new();
                    let mut a_codec = String::new();
                    let mut a_ch = 0i32;
                    let mut w = item.width.max(0);
                    let mut h = item.height.max(0);
                    let mut stream_bitrate = 0i64;

                    for ms in &item.media_streams {
                        if ms.stream_type == "Video" {
                            if v_codec.is_empty() && !ms.codec.is_empty() {
                                v_codec = ms.codec.to_uppercase();
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
                            if a_codec.is_empty() && !ms.codec.is_empty() {
                                a_codec = ms.codec.to_uppercase();
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
                    let mut has_played_date = 0i32;

                    if let Some(ref ud) = item.user_data {
                        if ud.played {
                            completion_pct = 100.0;
                            if dur_secs > 0 {
                                watched_secs = dur_secs;
                            }
                        } else if ud.playback_position_ticks > 0 {
                            let pos_secs =
                                (ud.playback_position_ticks / JELLYFIN_TICKS_PER_SECOND).max(0);
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
                                has_played_date = 1;
                            }
                        }
                    }

                    // Actual transfer bytes and play method/device/IP are not reported by
                    // Jellyfin's /Users/{id}/Items endpoint; keep them empty/zero rather
                    // than fabricating measurements.
                    let data_used = 0i64;
                    let session_key = format!(
                        "jellyfin:summary:{}:{}:{}",
                        urlencoding::encode(&instance_identity),
                        urlencoding::encode(&u.id),
                        urlencoding::encode(&item.id)
                    );
                    let rows = tx.execute(
                        r#"
                        INSERT INTO streaming_history (
                            session_key, provider, server_name, user_id, user_name,
                            client_name, device_name, ip_address,
                            item_id, item_name, item_type, series_name, series_id,
                            season_number, episode_number, production_year,
                            play_method, container, video_codec, video_resolution,
                            audio_codec, audio_channels, bitrate_bps,
                            duration_secs, watched_secs, data_used_bytes, completion_pct,
                            started_at, last_seen_at, ended_at, is_active,
                            provenance, timestamp_certainty, byte_accuracy, server_id
                        ) VALUES (
                            ?1, 'jellyfin', ?2, ?3, ?4,
                            '', '', '',
                            ?5, ?6, ?7, ?8, ?9,
                            ?10, ?11, ?12,
                            '', ?13, ?14, ?15,
                            ?16, ?17, ?18,
                            ?19, ?20, ?21, ?22,
                            ?23, ?23, ?23, 0,
                            'item_summary', CASE WHEN ?24 = 1 THEN 'last_played' ELSE 'unrecorded' END,
                            'unrecorded', ?25
                        )
                        ON CONFLICT(session_key) DO UPDATE SET
                            server_name = excluded.server_name,
                            user_name = excluded.user_name,
                            item_name = excluded.item_name,
                            item_type = excluded.item_type,
                            series_name = excluded.series_name,
                            series_id = excluded.series_id,
                            season_number = excluded.season_number,
                            episode_number = excluded.episode_number,
                            production_year = excluded.production_year,
                            container = excluded.container,
                            video_codec = excluded.video_codec,
                            video_resolution = excluded.video_resolution,
                            audio_codec = excluded.audio_codec,
                            audio_channels = excluded.audio_channels,
                            bitrate_bps = excluded.bitrate_bps,
                            duration_secs = excluded.duration_secs,
                            watched_secs = excluded.watched_secs,
                            data_used_bytes = excluded.data_used_bytes,
                            completion_pct = excluded.completion_pct,
                            started_at = CASE WHEN ?24 = 1 THEN excluded.started_at ELSE streaming_history.started_at END,
                            last_seen_at = CASE WHEN ?24 = 1 THEN excluded.last_seen_at ELSE streaming_history.last_seen_at END,
                            ended_at = CASE WHEN ?24 = 1 THEN excluded.ended_at ELSE streaming_history.ended_at END,
                            timestamp_certainty = CASE WHEN ?24 = 1 THEN excluded.timestamp_certainty ELSE streaming_history.timestamp_certainty END
                        WHERE streaming_history.provenance = 'item_summary' AND (
                              streaming_history.watched_secs != excluded.watched_secs
                           OR streaming_history.completion_pct != excluded.completion_pct
                           OR (?24 = 1 AND streaming_history.last_seen_at != excluded.last_seen_at)
                           OR streaming_history.item_name != excluded.item_name
                           OR (?24 = 1 AND streaming_history.timestamp_certainty != excluded.timestamp_certainty))
                        "#,
                        params![
                            session_key,
                            server_name,
                            u.id,
                            u.name,
                            item.id,
                            item.name,
                            normalize_media_type(&item.item_type),
                            item.series_name,
                            item.series_id,
                            item.parent_index_number,
                            item.index_number,
                            item.production_year,
                            item.container.to_uppercase(),
                            v_codec,
                            format_resolution_label(w, h),
                            a_codec,
                            a_ch,
                            bitrate,
                            dur_secs,
                            watched_secs,
                            data_used,
                            completion_pct,
                            played_at,
                            has_played_date,
                            server_id,
                        ],
                    )?;
                    if rows > 0 {
                        imported += 1;
                    }
                }
                let stored_key: String = tx.query_row(
                    "SELECT api_key FROM streaming_servers WHERE provider='jellyfin' AND enabled=1 AND RTRIM(url,'/')=RTRIM(?1,'/') AND server_id=?2",
                    params![server_url, server_id],
                    |row| row.get(0),
                )?;
                let current_key = if stored_key.starts_with("enc:v1:") {
                    af_db::decrypt_key(&stored_key)?
                } else {
                    stored_key
                };
                if current_key != api_key {
                    anyhow::bail!("Summary source changed before persistence");
                }
                tx.execute(
                    "INSERT INTO streaming_import_checkpoints(provider,server_id,source,checkpoint,updated_at) VALUES('jellyfin',?1,?2,?3,CURRENT_TIMESTAMP) ON CONFLICT(provider,server_id,source) DO UPDATE SET checkpoint=excluded.checkpoint,updated_at=excluded.updated_at",
                    params![server_id, checkpoint_source, (start_index + batch_len).to_string()],
                )?;
                tx.commit()?;
            }

            start_index += batch_len;
            if start_index >= payload.total_record_count || batch_len < page_size {
                af_db::get_conn()?.execute(
                    "UPDATE streaming_import_checkpoints SET checkpoint='-1',updated_at=CURRENT_TIMESTAMP WHERE provider='jellyfin' AND server_id=?1 AND source=?2",
                    params![server_id, checkpoint_source],
                )?;
                break;
            }
        }
    }

    af_db::get_conn()?.execute(
        "DELETE FROM streaming_import_checkpoints WHERE provider='jellyfin' AND server_id=?1 AND source LIKE 'summary:%' AND checkpoint='-1'",
        [&server_id],
    )?;
    Ok(JellyfinSummarySyncOutcome {
        imported,
        complete: true,
        has_more: false,
        remaining_sources: 0,
        next_offset: None,
    })
}
