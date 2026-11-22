use super::config::{
    persist_verified_source_with_key, query_reconnect_window_secs, query_stored_provider_server_id,
    try_get_stored_provider_config,
};
use super::jellyfin::fetch_jellyfin_live_sessions_for_server;
use super::models::{JellyfinSystemInfo, JELLYFIN_CLIENT};
use super::plex::{fetch_plex_live_sessions, test_plex_connection};
use super::summary_sync::sync_jellyfin_watch_history;
use af_services::ActiveStreamSession;
use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ParsedObservedSessionKey {
    pub(super) provider: String,
    pub(super) server_id: String,
    pub(super) session_id: String,
    pub(super) play_session_id: String,
    pub(super) item_id: String,
    pub(super) generation: u32,
}

pub(super) fn sanitize_session_key_part(raw: &str, max_chars: usize) -> String {
    raw.trim()
        .chars()
        .map(|c| if c == ':' { '_' } else { c })
        .take(max_chars.min(96))
        .collect()
}

pub fn format_observed_session_key(
    provider: &str,
    server_id: &str,
    session_id: &str,
    play_session_id: &str,
    item_id: &str,
    generation: u32,
) -> String {
    let p = sanitize_session_key_part(provider, 32);
    let srv = sanitize_session_key_part(server_id, 64);
    let sess = sanitize_session_key_part(session_id, 96);
    let ps = sanitize_session_key_part(play_session_id, 96);
    let item = sanitize_session_key_part(item_id, 96);
    let gen_num = generation.max(1);
    format!("{p}:{srv}:{sess}:{ps}:{item}:g{gen_num}")
}

pub(super) fn parse_observed_session_key(session_key: &str) -> Option<ParsedObservedSessionKey> {
    let mut parts = session_key.split(':');
    let provider = parts.next()?.to_string();
    let server_id = parts.next()?.to_string();
    let session_id = parts.next()?.to_string();
    let play_session_id = parts.next()?.to_string();
    let item_id = parts.next()?.to_string();
    let gen_part = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let generation = gen_part.strip_prefix('g')?.parse::<u32>().ok()?;
    if generation == 0 {
        return None;
    }
    Some(ParsedObservedSessionKey {
        provider,
        server_id,
        session_id,
        play_session_id,
        item_id,
        generation,
    })
}

fn lookup_active_observed_session_metrics(
    conn: &rusqlite::Connection,
    provider: &str,
    session_id: &str,
    play_session_id: &str,
    item_id: &str,
) -> rusqlite::Result<Option<(i64, String)>> {
    let stored_server_id = query_stored_provider_server_id(conn, provider)?;
    let norm_prov = sanitize_session_key_part(provider, 32);
    let norm_srv = sanitize_session_key_part(&stored_server_id, 64);
    let norm_sess = sanitize_session_key_part(session_id, 96);
    let norm_ps = sanitize_session_key_part(play_session_id, 96);
    let norm_item = sanitize_session_key_part(item_id, 96);

    let mut stmt = conn.prepare(
        "SELECT session_key, data_used_bytes, COALESCE(started_at, '') \
         FROM streaming_history \
         WHERE provider = ?1 AND server_id = ?2 AND item_id = ?3 \
           AND is_active = 1 AND provenance = 'observed_session' \
         ORDER BY id DESC LIMIT 32",
    )?;
    let mut rows = Vec::new();
    for row in stmt.query_map(
        params![provider.trim(), stored_server_id, item_id.trim()],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        },
    )? {
        rows.push(row?);
    }

    for (key, bytes, start) in &rows {
        if let Some(parsed) = parse_observed_session_key(key) {
            if parsed.provider == norm_prov
                && parsed.server_id == norm_srv
                && parsed.session_id == norm_sess
                && parsed.item_id == norm_item
                && parsed.play_session_id == norm_ps
            {
                return Ok(Some((*bytes, start.clone())));
            }
        }
    }
    for (key, bytes, start) in rows {
        if let Some(parsed) = parse_observed_session_key(&key) {
            if parsed.provider == norm_prov
                && parsed.server_id == norm_srv
                && parsed.session_id == norm_sess
                && parsed.item_id == norm_item
                && (parsed.play_session_id.is_empty() || norm_ps.is_empty())
            {
                return Ok(Some((bytes, start)));
            }
        }
    }
    Ok(None)
}

pub(super) fn enrich_sessions_with_observed_metrics(
    provider: &str,
    sessions: &mut [ActiveStreamSession],
) {
    if sessions.is_empty() {
        return;
    }
    let conn = match af_db::get_conn() {
        Ok(conn) => conn,
        Err(error) => {
            tracing::warn!(%error, provider, "failed to open DB while enriching live session metrics");
            return;
        }
    };
    for s in sessions.iter_mut() {
        match lookup_active_observed_session_metrics(
            &conn,
            provider,
            &s.session_id,
            &s.play_session_id,
            &s.item_id,
        ) {
            Ok(Some((tracked_bytes, tracked_start))) => {
                s.session_data_bytes = tracked_bytes.max(0);
                if !tracked_start.is_empty() {
                    s.started_at = tracked_start;
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, provider, session_id = %s.session_id, "failed to query observed session metrics");
                break;
            }
        }
    }
}

struct CandidateObservedHistoryRow {
    session_key: String,
    parsed: ParsedObservedSessionKey,
    user_id: String,
    client_name: String,
    device_id: String,
    is_active: bool,
    ended_elapsed_secs: Option<i64>,
}

fn resolve_observed_session_key(
    conn: &rusqlite::Connection,
    provider: &str,
    stored_server_id: &str,
    reconnect_window_secs: i64,
    s: &ActiveStreamSession,
    claimed_keys: &HashSet<String>,
) -> rusqlite::Result<(String, bool)> {
    let norm_prov = sanitize_session_key_part(provider, 32);
    let norm_srv = sanitize_session_key_part(stored_server_id, 64);
    let norm_sess = sanitize_session_key_part(&s.session_id, 96);
    let norm_ps = sanitize_session_key_part(&s.play_session_id, 96);
    let norm_item = sanitize_session_key_part(&s.item_id, 96);

    let mut candidates = Vec::new();
    let mut max_seen_gen = 0u32;

    let mut stmt = conn.prepare(
        "SELECT \
            session_key, \
            COALESCE(user_id, ''), \
            COALESCE(client_name, ''), \
            COALESCE(device_id, ''), \
            is_active, \
            COALESCE(provenance, 'legacy_unverified'), \
            CASE \
                WHEN COALESCE(NULLIF(ended_at, ''), NULLIF(last_seen_at, '')) IS NOT NULL \
                THEN CAST(strftime('%s', 'now') AS INTEGER) - CAST(strftime('%s', COALESCE(NULLIF(ended_at, ''), NULLIF(last_seen_at, ''))) AS INTEGER) \
                ELSE NULL \
            END \
         FROM streaming_history \
         WHERE provider = ?1 AND server_id = ?2 AND item_id = ?3 \
         ORDER BY id DESC \
         LIMIT 64",
    )?;
    for row in stmt.query_map(
        params![provider.trim(), stored_server_id, s.item_id.trim()],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i32>(4)? != 0,
                r.get::<_, String>(5)?,
                r.get::<_, Option<i64>>(6)?,
            ))
        },
    )? {
        let (key, user_id, client_name, device_id, is_active, provenance, ended_elapsed_secs) =
            row?;
        if provenance != "observed_session" {
            continue;
        }
        if let Some(parsed) = parse_observed_session_key(&key) {
            if parsed.provider == norm_prov
                && parsed.server_id == norm_srv
                && parsed.session_id == norm_sess
                && parsed.item_id == norm_item
            {
                if parsed.play_session_id == norm_ps {
                    max_seen_gen = max_seen_gen.max(parsed.generation);
                }
                candidates.push(CandidateObservedHistoryRow {
                    session_key: key,
                    parsed,
                    user_id,
                    client_name,
                    device_id,
                    is_active,
                    ended_elapsed_secs,
                });
            }
        }
    }

    for row in &candidates {
        if row.is_active
            && !claimed_keys.contains(&row.session_key)
            && row.parsed.play_session_id == norm_ps
            && row.user_id.trim() == s.user_id.trim()
        {
            let has_gap = row.ended_elapsed_secs.map(|e| e > 60).unwrap_or(false);
            return Ok((row.session_key.clone(), has_gap));
        }
    }

    for row in &candidates {
        if row.is_active
            && !claimed_keys.contains(&row.session_key)
            && (row.parsed.play_session_id.is_empty() || norm_ps.is_empty())
            && row.user_id.trim() == s.user_id.trim()
            && row.device_id.trim() == s.device_id.trim()
            && row.client_name.trim() == s.client_name.trim()
        {
            let has_gap = row.ended_elapsed_secs.map(|e| e > 60).unwrap_or(false);
            return Ok((row.session_key.clone(), has_gap));
        }
    }

    if reconnect_window_secs > 0 {
        if let Some(latest) = candidates.first() {
            if !latest.is_active
                && !claimed_keys.contains(&latest.session_key)
                && latest.parsed.play_session_id == norm_ps
                && latest.user_id.trim() == s.user_id.trim()
                && latest.device_id.trim() == s.device_id.trim()
                && latest.client_name.trim() == s.client_name.trim()
                && latest
                    .ended_elapsed_secs
                    .map(|elapsed| (0..=reconnect_window_secs).contains(&elapsed))
                    .unwrap_or(false)
            {
                return Ok((latest.session_key.clone(), true));
            }
        }
    }

    let mut next_gen = max_seen_gen.saturating_add(1).max(1);
    for _ in 0..64 {
        let candidate_key = format_observed_session_key(
            provider,
            stored_server_id,
            &s.session_id,
            &s.play_session_id,
            &s.item_id,
            next_gen,
        );
        if !claimed_keys.contains(&candidate_key) {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM streaming_history WHERE session_key = ?1)",
                params![candidate_key],
                |r| r.get(0),
            )?;
            if !exists {
                return Ok((candidate_key, true));
            }
        }
        next_gen = next_gen.saturating_add(1);
    }

    Ok((
        format_observed_session_key(
            provider,
            stored_server_id,
            &s.session_id,
            &s.play_session_id,
            &s.item_id,
            next_gen,
        ),
        true,
    ))
}

pub fn record_live_sessions_snapshot(
    provider: &str,
    sessions: &[ActiveStreamSession],
    interval_secs: i64,
) {
    record_live_sessions_snapshot_for_source(provider, sessions, interval_secs, None);
}

pub(super) fn record_live_sessions_snapshot_for_source(
    provider: &str,
    sessions: &[ActiveStreamSession],
    interval_secs: i64,
    source: Option<(&str, &str)>,
) {
    if let Err(error) =
        record_live_sessions_snapshot_for_source_inner(provider, sessions, interval_secs, source)
    {
        tracing::warn!(%error, provider, "failed to record live streaming sessions snapshot");
    }
}

pub(super) fn record_live_sessions_snapshot_for_source_inner(
    provider: &str,
    sessions: &[ActiveStreamSession],
    interval_secs: i64,
    source: Option<(&str, &str)>,
) -> anyhow::Result<()> {
    if interval_secs <= 0 {
        return Ok(());
    }
    let conn = af_db::get_conn()?;
    let transaction =
        rusqlite::Transaction::new_unchecked(&conn, rusqlite::TransactionBehavior::Immediate)?;
    let conn = &transaction;
    if let Some((server_url, server_id)) = source {
        let matches: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM streaming_servers WHERE provider=?1 AND RTRIM(url,'/')=RTRIM(?2,'/') AND server_id=?3 AND enabled=1)",
            params![provider, server_url, server_id],
            |row| row.get(0),
        )?;
        if !matches {
            return Ok(());
        }
    }
    let interval = if (1..=60).contains(&interval_secs) {
        interval_secs
    } else {
        0
    };
    let stored_server_id = query_stored_provider_server_id(conn, provider)?;
    let reconnect_window_secs = query_reconnect_window_secs(conn)?;

    let mut active_keys = HashSet::new();
    let mut direct_play_count = 0i32;
    let mut direct_stream_count = 0i32;
    let mut transcode_count = 0i32;
    let mut total_bitrate_bps = 0i64;
    let mut total_bytes_delta = 0i64;
    let mut new_sample = false;

    for s in sessions {
        if s.session_id.trim().is_empty() || s.item_id.trim().is_empty() {
            continue;
        }
        let (session_key, has_observation_gap) = resolve_observed_session_key(
            conn,
            provider,
            &stored_server_id,
            reconnect_window_secs,
            s,
            &active_keys,
        )?;
        active_keys.insert(session_key.clone());

        match s.play_method.as_str() {
            "Transcode" => transcode_count += 1,
            "DirectStream" => direct_stream_count += 1,
            _ => direct_play_count += 1,
        }

        let previous = conn
            .query_row(
                "SELECT sampled_at, playing FROM streaming_session_samples WHERE history_id=(SELECT id FROM streaming_history WHERE session_key=?1) ORDER BY sampled_at DESC LIMIT 1",
                [&session_key],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?;
        let effective_interval = previous
            .map(|(sampled_at, playing)| {
                let elapsed = Utc::now().timestamp().saturating_sub(sampled_at);
                if has_observation_gap || !playing || elapsed > interval.saturating_mul(2) {
                    0
                } else {
                    elapsed.clamp(0, interval)
                }
            })
            .unwrap_or(0);
        let mut delta_secs = 0i64;
        let mut delta_bytes = 0i64;
        if s.state == "playing" {
            let br = s.bitrate_bps.max(0);
            total_bitrate_bps += br;
            delta_secs = effective_interval;
            delta_bytes = (br * effective_interval) / 8;
            total_bytes_delta += delta_bytes;
        }

        let reasons_str = s.transcode_reasons.join(",");

        conn.execute(
            r#"
            INSERT INTO streaming_history (
                session_key, provider, server_name, user_id, user_name,
                client_name, device_name, device_id, ip_address,
                item_id, item_name, item_type, series_name, series_id,
                season_number, episode_number, production_year,
                play_method, container, video_codec, video_resolution,
                audio_codec, audio_channels, subtitle_codec, hw_accel, transcode_reasons,
                bitrate_bps, duration_secs, watched_secs, data_used_bytes, completion_pct,
                started_at, last_seen_at, is_active,
                provenance, timestamp_certainty, byte_accuracy, server_id
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5,
                ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17,
                ?18, ?19, ?20, ?21,
                ?22, ?23, ?33, ?24, ?25,
                ?26, ?27, ?28, ?29, ?30,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1,
                'observed_session', 'observed', 'estimated',
                ?34
            )
            ON CONFLICT(session_key) DO UPDATE SET
                server_name = CASE WHEN excluded.server_name != '' THEN excluded.server_name ELSE streaming_history.server_name END,
                server_id = CASE WHEN excluded.server_id != '' THEN excluded.server_id ELSE streaming_history.server_id END,
                play_method = excluded.play_method,
                hw_accel = CASE WHEN excluded.hw_accel != '' THEN excluded.hw_accel ELSE streaming_history.hw_accel END,
                transcode_reasons = CASE WHEN excluded.transcode_reasons != '' THEN excluded.transcode_reasons ELSE streaming_history.transcode_reasons END,
                bitrate_bps = excluded.bitrate_bps,
                duration_secs = CASE WHEN excluded.duration_secs > 0 THEN excluded.duration_secs ELSE streaming_history.duration_secs END,
                watched_secs = streaming_history.watched_secs + ?31,
                data_used_bytes = streaming_history.data_used_bytes + ?32,
                completion_pct = MAX(streaming_history.completion_pct, excluded.completion_pct),
                last_seen_at = CURRENT_TIMESTAMP,
                ended_at = NULL,
                is_active = 1
            WHERE streaming_history.provenance = 'observed_session'
            "#,
            params![
                session_key,
                provider,
                s.server_name,
                s.user_id,
                s.user_name,
                s.client_name,
                s.device_name,
                s.device_id,
                s.ip_address,
                s.item_id,
                s.item_name,
                s.item_type,
                s.series_name,
                s.series_id,
                s.season_number,
                s.episode_number,
                s.production_year,
                s.play_method,
                s.container,
                s.video_codec,
                s.video_resolution,
                s.audio_codec,
                s.audio_channels,
                s.hw_accel,
                reasons_str,
                s.bitrate_bps.max(0),
                s.duration_secs,
                delta_secs,
                delta_bytes,
                s.progress_pct,
                delta_secs,
                delta_bytes,
                s.subtitle_codec,
                stored_server_id,
            ],
        )?;
        if interval > 0 {
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO streaming_session_samples(history_id, sampled_at, observed_secs, playing, bitrate_bps) SELECT id, CAST(strftime('%s','now') AS INTEGER), ?1, ?2, ?3 FROM streaming_history WHERE session_key = ?4 AND provenance = 'observed_session'",
                params![effective_interval, i64::from(s.state == "playing"), s.bitrate_bps.max(0), session_key],
            )?;
            new_sample |= inserted > 0;
        }
    }

    if active_keys.is_empty() {
        conn.execute(
            "UPDATE streaming_history SET is_active = 0, ended_at = CURRENT_TIMESTAMP WHERE provider = ?1 AND server_id=?2 AND is_active = 1 AND provenance = 'observed_session'",
            params![provider, stored_server_id],
        )?;
    } else {
        let mut stmt = conn.prepare(
            "SELECT session_key FROM streaming_history WHERE provider = ?1 AND server_id=?2 AND is_active = 1 AND provenance = 'observed_session'",
        )?;
        let mut currently_active = Vec::new();
        for key in stmt.query_map(params![provider, stored_server_id], |r| {
            r.get::<_, String>(0)
        })? {
            currently_active.push(key?);
        }
        drop(stmt);
        for key in currently_active {
            if !active_keys.contains(&key) {
                conn.execute(
                    "UPDATE streaming_history SET is_active = 0, ended_at = CURRENT_TIMESTAMP WHERE session_key = ?1 AND provenance = 'observed_session'",
                    params![key],
                )?;
            }
        }
    }

    if !sessions.is_empty() && interval > 0 && new_sample {
        conn.execute(
            r#"
            INSERT INTO streaming_bandwidth_samples (
                provider, active_streams, direct_play_count, direct_stream_count, transcode_count, total_bitrate_bps, bytes_delta
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                provider,
                sessions.len() as i32,
                direct_play_count,
                direct_stream_count,
                transcode_count,
                total_bitrate_bps,
                total_bytes_delta,
            ],
        )?;
    }

    if interval > 0 {
        conn.execute(
            "DELETE FROM streaming_session_samples WHERE sampled_at < CAST(strftime('%s','now') AS INTEGER) - 7776000",
            [],
        )?;
        conn.execute(
            "DELETE FROM streaming_bandwidth_samples WHERE replace(CAST(timestamp AS TEXT), 'T', ' ') < datetime('now', '-90 days')",
            [],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

static STREAMING_MONITOR_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn close_disabled_provider(provider: &str) {
    match af_db::get_conn() {
        Ok(conn) => {
            if let Err(error) = conn.execute(
                "UPDATE streaming_history SET is_active=0 WHERE provider=?1 AND is_active=1 AND provenance='observed_session' AND server_id=COALESCE((SELECT server_id FROM streaming_servers WHERE provider=?1),'') AND NOT EXISTS(SELECT 1 FROM streaming_servers WHERE provider=?1 AND enabled=1 AND api_key!='')",
                [provider],
            ) {
                tracing::warn!(%error, provider, "failed to close active sessions for disabled provider");
            }
        }
        Err(error) => {
            tracing::warn!(%error, provider, "failed to open DB while closing disabled provider sessions");
        }
    }
}

fn schedule_live_item_metadata(
    provider: &str,
    server_url: &str,
    api_key: &str,
    sessions: &[ActiveStreamSession],
) {
    if sessions.is_empty() {
        return;
    }
    let item_ids = sessions
        .iter()
        .map(|session| session.item_id.clone())
        .collect::<Vec<_>>();
    crate::streaming_metadata::schedule_provider_item_metadata(
        provider, server_url, api_key, "", &item_ids,
    );
}

pub(super) async fn verify_monitor_source(
    provider: &str,
    server_url: &str,
    api_key: &str,
) -> anyhow::Result<String> {
    let clean_url = af_services::validate_server_url(server_url)?;
    let identity_id = if provider == "plex" {
        let status = test_plex_connection(&clean_url, api_key, None).await?;
        anyhow::ensure!(
            status.status == "connected",
            "Plex provider identity unavailable"
        );
        status.server_id
    } else {
        let (body, status) = crate::streaming_metadata::execute_provider_request(
            &JELLYFIN_CLIENT,
            reqwest::Method::GET,
            &format!("{clean_url}/System/Info/Public"),
            provider,
            api_key,
        )
        .await?;
        if !status.is_success() {
            anyhow::bail!("Provider identity unavailable");
        }
        let identity: JellyfinSystemInfo = serde_json::from_slice(&body)?;
        identity.id
    };
    let (_, current_url, current_key, enabled) = try_get_stored_provider_config(provider)?;
    if !enabled || current_url.trim_end_matches('/') != clean_url || current_key != api_key {
        anyhow::bail!("Provider configuration changed during verification");
    }
    let provider = provider.to_string();
    let api_key = api_key.to_string();
    tokio::task::spawn_blocking(move || {
        let connection = af_db::get_conn()?;
        persist_verified_source_with_key(&connection, &provider, &clean_url, &api_key, &identity_id)
    })
    .await?
}

pub fn start_streaming_monitor() {
    if STREAMING_MONITOR_STARTED
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_err()
    {
        return;
    }

    for provider in ["jellyfin", "emby", "plex"] {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(15));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let (name, url, key, enabled) = match try_get_stored_provider_config(provider) {
                    Ok(cfg) => cfg,
                    Err(error) => {
                        tracing::warn!(%error, provider, "failed to load provider config during monitor tick");
                        continue;
                    }
                };
                if !enabled || key.is_empty() {
                    close_disabled_provider(provider);
                    continue;
                }
                if let Ok(server_id) = verify_monitor_source(provider, &url, &key).await {
                    let observations = if provider == "jellyfin" {
                        fetch_jellyfin_live_sessions_for_server(&name, &url, &key, Some(&server_id))
                            .await
                    } else if provider == "plex" {
                        fetch_plex_live_sessions(&name, &url, &key, Some(&server_id)).await
                    } else {
                        crate::streaming_emby::fetch_emby_live_sessions(
                            &name,
                            &url,
                            &key,
                            Some(&server_id),
                        )
                        .await
                        .map_err(anyhow::Error::from)
                    };
                    if let Ok(sessions) = observations {
                        record_live_sessions_snapshot_for_source(
                            provider,
                            &sessions,
                            15,
                            Some((&url, &server_id)),
                        );
                        if provider != "plex" {
                            schedule_live_item_metadata(provider, &url, &key, &sessions);
                        }
                    }
                }
            }
        });
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(300));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let _ = sync_jellyfin_watch_history().await;
        }
    });
    tracing::info!(interval = "15s", "streaming telemetry monitor started");
}
