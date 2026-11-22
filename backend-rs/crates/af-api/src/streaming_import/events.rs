use super::types::{
    ensure_admin, ImportCheckpointRecord, ImportEventOutcome, ImportEventsBatchRequest,
    ImportEventsBatchResponse, ImportLabelInput, ImportResult, ImportStatusQuery,
    ImportStatusResponse, StreamingImportError, UpstreamEventCapability,
};
use super::validation::{
    bump_history_revision, normalize_media_type, normalize_nonempty_token, normalize_optional_text,
    normalize_play_method, normalize_provider, parse_event_timestamp, record_admin_audit,
};
use super::MAX_IMPORT_BATCH_EVENTS;
use crate::auth::AuthUser;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeSet;

/// Evaluates whether a given provider/server/endpoint can supply true individual playback events.
///
/// Per primary-source audit of Jellyfin & Jellystat:
/// - `/Users/{id}/Items?Filters=IsPlayed,IsResumable` returns per-item `UserData` summaries
///   (`LastPlayedDate`, `PlaybackPositionTicks`, `PlayCount`) — NEVER individual playback events.
/// - `/System/ActivityLog/Entries` returns administrative log entries without reliable media item
///   watch durations, delivery methods, or stream metadata.
/// - Jellyfin's optional third-party `PlaybackReporting` plugin exposes `/user_usage_stats/submit_custom_query`
///   against its internal `PlaybackActivity` SQLite table, which is a raw SQL execution endpoint
///   without stable server-assigned event UUIDs and has known Jellyfin 10.11.9+ `ReplaceUserId`
///   breakage; therefore automatic live upstream fetching is reported unavailable in favor of
///   bounded, schema-validated JSON event batch imports (`POST /api/v1/admin/streaming/imports/events`).
pub fn evaluate_upstream_capability(
    provider: &str,
    server_id: &str,
    endpoint_path: &str,
) -> ImportResult<UpstreamEventCapability> {
    let provider = normalize_provider(provider)?;
    let server_id = normalize_nonempty_token(server_id, "serverId", 128)?;
    let trimmed_path = endpoint_path.trim();
    let lower_path = trimmed_path.to_ascii_lowercase();

    let (classification, reason) = if provider == "plex" {
        if lower_path.contains("/status/sessions/history") || lower_path.contains("tautulli") {
            (
                "plex_history_export_supported".to_string(),
                "Plex /status/sessions/history/all JSON and native CSV/Tautulli watch-history exports are normalized into canonical imported_event records with stable sourceEventId deduplication.".to_string(),
            )
        } else {
            (
                "plex_batch_or_export_import".to_string(),
                "Plex watch history can be imported via structured event batches or native JSON/CSV watch-history exports.".to_string(),
            )
        }
    } else if lower_path.contains("/users/") && lower_path.contains("/items") {
        (
            "item_summary_only".to_string(),
            "Jellyfin/Emby /Users/{id}/Items returns per-item UserData summaries (LastPlayedDate, PlayCount), never individual playback events. Refusing to fabricate imported_event records from item summaries.".to_string(),
        )
    } else if lower_path.contains("activitylog") {
        (
            "activity_log_insufficient".to_string(),
            "Jellyfin/Emby /System/ActivityLog/Entries lacks verified watched durations, delivery methods, and stable playback event semantics. Refusing to treat activity log entries as imported_event records.".to_string(),
        )
    } else if lower_path.contains("user_usage_stats") || lower_path.contains("playback_reporting") {
        (
            "optional_plugin_export_only".to_string(),
            "Jellyfin PlaybackReporting (/user_usage_stats) is an optional plugin whose custom SQL endpoint does not guarantee stable event IDs across server upgrades; export verified records and submit via bounded JSON batch import.".to_string(),
        )
    } else {
        (
            "no_builtin_upstream_event_api".to_string(),
            "Unmodified Jellyfin/Emby servers do not expose a built-in historical playback event stream API; direct upstream event fetching is unavailable. Use bounded JSON batch import with stable sourceEventId values.".to_string(),
        )
    };

    Ok(UpstreamEventCapability {
        provider,
        server_id,
        real_event_import_supported: true,
        json_batch_import_supported: true,
        upstream_direct_fetch_available: false,
        upstream_endpoint_classification: classification,
        reason,
    })
}

pub fn get_import_status(
    conn: &Connection,
    query: ImportStatusQuery,
    user: &AuthUser,
) -> ImportResult<ImportStatusResponse> {
    ensure_admin(user)?;
    let filter_provider = if query.provider.trim().is_empty() {
        None
    } else {
        Some(normalize_provider(&query.provider)?)
    };
    let filter_server_id = if query.server_id.trim().is_empty() {
        None
    } else {
        Some(normalize_nonempty_token(&query.server_id, "serverId", 128)?)
    };

    let mut stmt = conn.prepare(
        "SELECT provider, server_id, source, checkpoint, imported, last_error, updated_at
         FROM streaming_import_checkpoints
         WHERE (?1 IS NULL OR provider = ?1)
           AND (?2 IS NULL OR server_id = ?2)
         ORDER BY provider ASC, server_id ASC, source ASC",
    )?;
    let checkpoints: Vec<ImportCheckpointRecord> = stmt
        .query_map(params![filter_provider, filter_server_id], |row| {
            Ok(ImportCheckpointRecord {
                provider: row.get(0)?,
                server_id: row.get(1)?,
                source: row.get(2)?,
                checkpoint: row.get(3)?,
                imported: row.get(4)?,
                last_error: row.get::<_, Option<String>>(5)?.filter(|s| !s.is_empty()),
                updated_at: row.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;

    let mut capability_keys: BTreeSet<(String, String)> = BTreeSet::new();
    let mut server_stmt = conn.prepare(
        "SELECT lower(trim(provider)), COALESCE(NULLIF(trim(server_id), ''), 'default')
         FROM streaming_servers
         WHERE lower(trim(provider)) IN ('jellyfin', 'emby', 'plex')",
    )?;
    let configured_servers = server_stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for pair in configured_servers {
        let pair = pair?;
        if filter_provider.as_ref().is_none_or(|p| p == &pair.0)
            && filter_server_id.as_ref().is_none_or(|s| s == &pair.1)
        {
            capability_keys.insert(pair);
        }
    }
    for cp in &checkpoints {
        capability_keys.insert((cp.provider.clone(), cp.server_id.clone()));
    }
    if capability_keys.is_empty() {
        let p = filter_provider.unwrap_or_else(|| "jellyfin".to_string());
        let s = filter_server_id.unwrap_or_else(|| "default".to_string());
        capability_keys.insert((p, s));
    }

    let mut capabilities = Vec::with_capacity(capability_keys.len());
    for (provider, server_id) in capability_keys {
        capabilities.push(evaluate_upstream_capability(&provider, &server_id, "")?);
    }

    Ok(ImportStatusResponse {
        max_batch_events: MAX_IMPORT_BATCH_EVENTS,
        checkpoints,
        capabilities,
    })
}

/// Records an import checkpoint error without mutating any `streaming_history` rows.
pub fn record_import_checkpoint_error(
    conn: &Connection,
    provider: &str,
    server_id: &str,
    source: &str,
    error_message: &str,
    now: i64,
) -> ImportResult<()> {
    let provider = normalize_provider(provider)?;
    let server_id = normalize_nonempty_token(server_id, "serverId", 128)?;
    let source = normalize_nonempty_token(source, "source", 128)?;
    let updated_at = DateTime::from_timestamp(now, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339();
    conn.execute(
        "INSERT INTO streaming_import_checkpoints (provider, server_id, source, checkpoint, imported, last_error, updated_at)
         VALUES (?1, ?2, ?3, '', 0, ?4, ?5)
         ON CONFLICT(provider, server_id, source) DO UPDATE SET
             last_error = excluded.last_error,
             updated_at = excluded.updated_at",
        params![provider, server_id, source, error_message, updated_at],
    )?;
    Ok(())
}

#[derive(Clone, Debug)]
struct ObservedCandidate {
    id: i64,
    start_unix: Option<i64>,
    end_unix: Option<i64>,
    watched_secs: i64,
    client_name: String,
    device_name: String,
    device_id: String,
    is_active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum OverlapClassification {
    None,
    ConfirmedDuplicate(Vec<i64>),
    Ambiguous(Vec<i64>),
}

/// Classifies overlap between an incoming imported event and existing `observed_session` rows
/// (and prior imported events within the same batch/archive for the same user+item).
///
/// Rules:
/// - **Confirmed overlap (`policy_status = 'duplicate'`)**:
///   Exactly one non-active `observed_session` for the same `(provider, server_id, user_id, item_id)`
///   overlaps the imported event's time window within `tolerance = max(60, reconnect_window_secs)`,
///   has non-conflicting client/device identity, and has compatible watched duration (within 60s
///   or 25% of the event's watched duration). The observed session remains the primary `'included'`
///   record and the imported event is stored with `policy_status = 'duplicate'` so confirmed plays
///   are never double-counted.
/// - **Ambiguous overlap (`policy_status = 'ambiguous'`)**:
///   - Multiple `observed_session` rows overlap the event window (e.g. concurrent sessions or split
///     polling intervals), OR
///   - An overlapping `observed_session` is still active (`is_active = 1`) or lacks an end timestamp, OR
///   - Client/device metadata conflicts between the observed session and imported event, OR
///   - The gap between the observed session (or another imported event for the same user+item) falls
///     inside a broader reconnect/pause slack window (`tolerance + max(180, reconnect_window_secs)`)
///     or watched duration diverges sharply, making it impossible to distinguish a paused/resumed
///     session from a separate repeat playback with certainty.
#[allow(clippy::too_many_arguments)]
fn classify_event_overlap(
    tx: &Connection,
    provider: &str,
    server_id: &str,
    user_id: &str,
    item_id: &str,
    event_start_unix: i64,
    event_end_unix: i64,
    event_watched_secs: Option<i64>,
    client_name: &str,
    device_name: &str,
    device_id: &str,
    reconnect_window_secs: i64,
) -> rusqlite::Result<OverlapClassification> {
    let core_tolerance = 60_i64.max(reconnect_window_secs);
    let slack_tolerance = core_tolerance + 180_i64.max(reconnect_window_secs);
    let search_from = event_start_unix - slack_tolerance;
    let search_until = event_end_unix + slack_tolerance;

    let mut stmt = tx.prepare(
        "SELECT id,
                event_unix,
                COALESCE(
                    CAST(strftime('%s', NULLIF(ended_at, '')) AS INTEGER),
                    CAST(strftime('%s', NULLIF(last_seen_at, '')) AS INTEGER)
                ) AS finish_unix,
                COALESCE(watched_secs, 0),
                COALESCE(client_name, ''),
                COALESCE(device_name, ''),
                COALESCE(device_id, ''),
                COALESCE(is_active, 0)
         FROM streaming_history
         WHERE provider = ?1
           AND server_id = ?2
           AND user_id = ?3
           AND item_id = ?4
           AND provenance = 'observed_session'
           AND (
               event_unix IS NULL
               OR (
                   event_unix <= ?6
                   AND COALESCE(
                       CAST(strftime('%s', NULLIF(ended_at, '')) AS INTEGER),
                       CAST(strftime('%s', NULLIF(last_seen_at, '')) AS INTEGER),
                       event_unix + MAX(COALESCE(watched_secs, 0), 0)
                   ) >= ?5
               )
           )
         ORDER BY id ASC",
    )?;

    let candidates: Vec<ObservedCandidate> = stmt
        .query_map(
            params![
                provider,
                server_id,
                user_id,
                item_id,
                search_from,
                search_until
            ],
            |row| {
                Ok(ObservedCandidate {
                    id: row.get(0)?,
                    start_unix: row.get(1)?,
                    end_unix: row.get(2)?,
                    watched_secs: row.get(3)?,
                    client_name: row.get(4)?,
                    device_name: row.get(5)?,
                    device_id: row.get(6)?,
                    is_active: row.get::<_, i64>(7)? != 0,
                })
            },
        )?
        .collect::<rusqlite::Result<_>>()?;

    if !candidates.is_empty() {
        let matched_ids: Vec<i64> = candidates.iter().map(|c| c.id).collect();
        if candidates.len() > 1 {
            return Ok(OverlapClassification::Ambiguous(matched_ids));
        }
        let candidate = &candidates[0];
        let Some(obs_start) = candidate.start_unix else {
            return Ok(OverlapClassification::Ambiguous(matched_ids));
        };
        let Some(obs_end_raw) = candidate.end_unix else {
            return Ok(OverlapClassification::Ambiguous(matched_ids));
        };
        if candidate.is_active {
            return Ok(OverlapClassification::Ambiguous(matched_ids));
        }
        let obs_end = obs_end_raw.max(obs_start + candidate.watched_secs.max(0));

        // Check direct temporal overlap within core_tolerance
        let directly_overlaps = event_start_unix <= obs_end + core_tolerance
            && event_end_unix >= obs_start - core_tolerance;
        if !directly_overlaps {
            // Within slack_tolerance (e.g. pause/poll gap or rapid repeat play) -> ambiguous!
            return Ok(OverlapClassification::Ambiguous(matched_ids));
        }

        // Check client/device identity compatibility
        let client_conflict = !client_name.is_empty()
            && !candidate.client_name.trim().is_empty()
            && !client_name.eq_ignore_ascii_case(candidate.client_name.trim());
        let device_conflict = !device_name.is_empty()
            && !candidate.device_name.trim().is_empty()
            && !device_name.eq_ignore_ascii_case(candidate.device_name.trim());
        let device_id_conflict = !device_id.is_empty()
            && !candidate.device_id.trim().is_empty()
            && !device_id.eq_ignore_ascii_case(candidate.device_id.trim());

        if client_conflict || device_conflict || device_id_conflict {
            return Ok(OverlapClassification::Ambiguous(matched_ids));
        }

        // Check watched duration agreement if event has watched_secs
        let duration_compatible = match event_watched_secs {
            Some(ev_watched) if ev_watched > 0 && candidate.watched_secs > 0 => {
                let diff = (ev_watched - candidate.watched_secs).abs();
                let allowed = 60_i64.max((ev_watched.max(candidate.watched_secs)) / 4);
                diff <= allowed
            }
            _ => true,
        };

        let start_diff = (event_start_unix - obs_start).abs();
        if duration_compatible && start_diff <= core_tolerance {
            return Ok(OverlapClassification::ConfirmedDuplicate(matched_ids));
        }
        return Ok(OverlapClassification::Ambiguous(matched_ids));
    }

    // Also check if another imported_event for the same (provider, server_id, user_id, item_id)
    // has overlapping or reconnect-window-adjacent timestamps with a DIFFERENT source_event_id
    // (e.g. split session vs rapid repeat playback within reconnect_window_secs).
    {
        let mut imp_stmt = tx.prepare(
            "SELECT id
             FROM streaming_history
             WHERE provider = ?1
               AND server_id = ?2
               AND user_id = ?3
               AND item_id = ?4
               AND provenance = 'imported_event'
               AND event_unix IS NOT NULL
               AND event_unix <= ?6
               AND COALESCE(
                   CAST(strftime('%s', NULLIF(ended_at, '')) AS INTEGER),
                   event_unix + MAX(COALESCE(watched_secs, 0), 0)
               ) >= ?5
             ORDER BY id ASC",
        )?;
        let near_imported: Vec<i64> = imp_stmt
            .query_map(
                params![
                    provider,
                    server_id,
                    user_id,
                    item_id,
                    event_start_unix - reconnect_window_secs,
                    event_end_unix + reconnect_window_secs
                ],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<_>>()?;
        if !near_imported.is_empty() {
            return Ok(OverlapClassification::Ambiguous(near_imported));
        }
    }

    Ok(OverlapClassification::None)
}

fn upsert_history_labels(
    tx: &Connection,
    history_id: i64,
    libraries: &[ImportLabelInput],
    genres: &[String],
) -> ImportResult<()> {
    for lib in libraries {
        let lib_id = normalize_nonempty_token(&lib.id, "libraries[].id", 128)?;
        let lib_name = if lib.name.trim().is_empty() {
            lib_id.clone()
        } else {
            normalize_nonempty_token(&lib.name, "libraries[].name", 256)?
        };
        tx.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name)
             VALUES (?1, 'library', ?2, ?3)
             ON CONFLICT(history_id, kind, value) DO UPDATE SET name = excluded.name",
            params![history_id, lib_id, lib_name],
        )?;
    }
    for raw_genre in genres {
        let genre = normalize_nonempty_token(raw_genre, "genres[]", 128)?;
        tx.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name)
             VALUES (?1, 'genre', ?2, ?2)
             ON CONFLICT(history_id, kind, value) DO UPDATE SET name = excluded.name",
            params![history_id, genre],
        )?;
    }
    Ok(())
}

/// Atomically validates and imports a bounded batch of real playback events and updates the
/// `(provider, server_id, source)` checkpoint inside a single `BEGIN IMMEDIATE` transaction.
pub fn import_events_batch(
    conn: &Connection,
    request: ImportEventsBatchRequest,
    user: &AuthUser,
    now: i64,
) -> ImportResult<ImportEventsBatchResponse> {
    ensure_admin(user)?;

    let provider = normalize_provider(&request.provider)?;
    let server_id = normalize_nonempty_token(&request.server_id, "serverId", 128)?;
    let source = normalize_nonempty_token(&request.source, "source", 128)?;
    let checkpoint = normalize_nonempty_token(&request.checkpoint, "checkpoint", 512)?;
    let server_name = match &request.server_name {
        Some(name) if !name.trim().is_empty() => normalize_nonempty_token(name, "serverName", 128)?,
        _ => match provider.as_str() {
            "jellyfin" => "Jellyfin".to_string(),
            "plex" => "Plex".to_string(),
            _ => "Emby".to_string(),
        },
    };

    // Guard against callers attempting to pass item_summary or activity_log sources as events.
    let lower_source = source.to_ascii_lowercase();
    if lower_source.contains("item_summary")
        || lower_source.contains("userdata")
        || lower_source.contains("activity_log")
        || lower_source.contains("activitylog")
    {
        return Err(StreamingImportError::unprocessable(
            "summary_source_forbidden",
            "Item summaries (/Users/{id}/Items) and ActivityLog entries cannot be imported as real playback events",
        ));
    }

    if request.events.is_empty() || request.events.len() > MAX_IMPORT_BATCH_EVENTS {
        return Err(StreamingImportError::bad_request(
            "invalid_batch_size",
            format!("events batch must contain between 1 and {MAX_IMPORT_BATCH_EVENTS} events"),
        ));
    }

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> ImportResult<ImportEventsBatchResponse> {
        let previous_checkpoint: Option<String> = conn.query_row(
            "SELECT checkpoint FROM streaming_import_checkpoints WHERE provider = ?1 AND server_id = ?2 AND source = ?3",
            params![provider, server_id, source],
            |row| row.get(0),
        ).optional()?.filter(|value: &String| !value.is_empty());
        if previous_checkpoint != request.expected_checkpoint
            && previous_checkpoint.as_deref() != Some(checkpoint.as_str())
        {
            return Err(StreamingImportError::conflict("import_checkpoint_changed", "Checkpoint changed; refresh import status and provide expectedCheckpoint before resuming"));
        }
        let retry_only = previous_checkpoint.as_deref() == Some(checkpoint.as_str());
        let reconnect_window_secs: i64 = conn
            .query_row(
                "SELECT reconnect_window_secs FROM streaming_tracking_policies WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);

        let mut inserted_included = 0usize;
        let mut deduplicated_retries = 0usize;
        let mut confirmed_overlap_duplicates = 0usize;
        let mut ambiguous_overlaps = 0usize;
        let mut newly_imported_count = 0i64;
        let mut outcomes = Vec::with_capacity(request.events.len());

        for event in &request.events {
            let source_event_id =
                normalize_nonempty_token(&event.source_event_id, "sourceEventId", 256)?;
            let persisted_event_id = format!("{}:{}{}", source.len(), source, source_event_id);
            let user_id = normalize_nonempty_token(&event.user_id, "userId", 128)?;
            let user_name = if event.user_name.trim().is_empty() {
                user_id.clone()
            } else {
                normalize_nonempty_token(&event.user_name, "userName", 256)?
            };
            let item_id = normalize_nonempty_token(&event.item_id, "itemId", 128)?;
            let item_name = normalize_nonempty_token(&event.item_name, "itemName", 512)?;
            let item_type = normalize_media_type(&event.item_type)?;
            let play_method = normalize_play_method(&event.play_method)?;
            let series_name = normalize_optional_text(&event.series_name, 512)?;
            let series_id = normalize_optional_text(&event.series_id, 128)?;
            let client_name = normalize_optional_text(&event.client_name, 256)?;
            let device_name = normalize_optional_text(&event.device_name, 256)?;
            let device_id = normalize_optional_text(&event.device_id, 256)?;
            let ip_address = normalize_optional_text(&event.ip_address, 128)?;
            let container = normalize_optional_text(&event.container, 64)?;
            let video_codec = normalize_optional_text(&event.video_codec, 64)?;
            let video_resolution = normalize_optional_text(&event.video_resolution, 64)?;
            let audio_codec = normalize_optional_text(&event.audio_codec, 64)?;
            let subtitle_codec = normalize_optional_text(&event.subtitle_codec, 64)?;
            let hw_accel = normalize_optional_text(&event.hw_accel, 64)?;

            let (started_sql, start_unix) = parse_event_timestamp(&event.started_at, "startedAt")?;

            let watched_secs = match event.watched_secs {
                Some(w) if !(0..=86_400 * 7).contains(&w) => {
                    return Err(StreamingImportError::bad_request(
                        "invalid_watched_secs",
                        "watchedSecs must be between 0 and 604800 seconds",
                    ));
                }
                Some(w) => Some(w),
                None => None,
            };

            let duration_secs = match event.duration_secs {
                Some(d) if d <= 0 || d > 86_400 * 7 => {
                    return Err(StreamingImportError::bad_request(
                        "invalid_duration_secs",
                        "durationSecs must be positive when provided",
                    ));
                }
                Some(d) => d,
                None => 0,
            };

            let (ended_sql_opt, end_unix) = match &event.ended_at {
                Some(raw_end) if !raw_end.trim().is_empty() => {
                    let (end_sql, end_ts) = parse_event_timestamp(raw_end, "endedAt")?;
                    if end_ts < start_unix {
                        return Err(StreamingImportError::bad_request(
                            "invalid_timestamp_order",
                            "endedAt must not be earlier than startedAt",
                        ));
                    }
                    (Some(end_sql), end_ts)
                }
                _ => (None, start_unix + watched_secs.unwrap_or(0).max(0)),
            };

            let (data_used_bytes, byte_accuracy) = match event.estimated_bytes {
                Some(bytes) if bytes < 0 => {
                    return Err(StreamingImportError::bad_request(
                        "invalid_estimated_bytes",
                        "estimatedBytes must be non-negative when provided",
                    ));
                }
                Some(bytes) => (bytes, "estimated"),
                None => (0_i64, "unrecorded"),
            };

            let bitrate_bps = event.bitrate_bps.unwrap_or(0).max(0);
            let season_number = event.season_number.unwrap_or(0).max(0);
            let episode_number = event.episode_number.unwrap_or(0).max(0);
            let production_year = event.production_year.unwrap_or(0).max(0);
            let audio_channels = event.audio_channels.unwrap_or(0).max(0);
            let completion_pct = match (watched_secs, duration_secs) {
                (Some(w), d) if d > 0 => ((w as f64 / d as f64) * 100.0).clamp(0.0, 100.0),
                _ => 0.0,
            };

            // 1. Check idempotent retry by (provider, server_id, source_event_id)
            let existing: Option<(i64, String)> = conn
                .query_row(
                    "SELECT id, policy_status
                     FROM streaming_history
                     WHERE provider = ?1 AND server_id = ?2 AND source_event_id = ?3",
                    params![provider, server_id, persisted_event_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;

            if let Some((existing_id, existing_policy_status)) = existing {
                upsert_history_labels(conn, existing_id, &event.libraries, &event.genres)?;
                deduplicated_retries += 1;
                outcomes.push(ImportEventOutcome {
                    source_event_id,
                    history_id: existing_id,
                    disposition: "deduplicated_retry".to_string(),
                    policy_status: existing_policy_status,
                    matched_observed_ids: Vec::new(),
                });
                continue;
            }

            if retry_only {
                return Err(StreamingImportError::conflict(
                    "import_checkpoint_reused",
                    "A committed checkpoint only permits existing event retries; use a new checkpoint for new events",
                ));
            }

            // 2. Classify overlap with observed sessions / adjacent reconnect events
            let overlap = classify_event_overlap(
                conn,
                &provider,
                &server_id,
                &user_id,
                &item_id,
                start_unix,
                end_unix,
                watched_secs,
                &client_name,
                &device_name,
                &device_id,
                reconnect_window_secs,
            )?;

            let (disposition, policy_status, matched_observed_ids) = match overlap {
                OverlapClassification::None => {
                    inserted_included += 1;
                    ("inserted", "included", Vec::new())
                }
                OverlapClassification::ConfirmedDuplicate(ids) => {
                    confirmed_overlap_duplicates += 1;
                    ("duplicate_observed_overlap", "duplicate", ids)
                }
                OverlapClassification::Ambiguous(ids) => {
                    ambiguous_overlaps += 1;
                    ("ambiguous_overlap", "ambiguous", ids)
                }
            };

            let session_key = format!(
                "import:{}",
                serde_json::to_string(&(&provider, &server_id, &persisted_event_id))
                    .map_err(|error| StreamingImportError::internal(error.to_string()))?
            );
            let last_seen_sql = ended_sql_opt.clone().unwrap_or_else(|| started_sql.clone());

            conn.execute(
                "INSERT INTO streaming_history (
                    session_key, provider, server_name, server_id, source_event_id,
                    user_id, user_name, client_name, device_name, device_id, ip_address,
                    item_id, item_name, item_type, series_name, series_id,
                    season_number, episode_number, production_year,
                    play_method, container, video_codec, video_resolution,
                    audio_codec, audio_channels, subtitle_codec, hw_accel, transcode_reasons,
                    bitrate_bps, duration_secs, watched_secs, data_used_bytes, completion_pct,
                    started_at, last_seen_at, ended_at, is_active,
                    provenance, timestamp_certainty, byte_accuracy, policy_status
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5,
                    ?6, ?7, ?8, ?9, ?10, ?11,
                    ?12, ?13, ?14, ?15, ?16,
                    ?17, ?18, ?19,
                    ?20, ?21, ?22, ?23,
                    ?24, ?25, ?26, ?27, '',
                    ?28, ?29, ?30, ?31, ?32,
                    ?33, ?34, ?35, 0,
                    'imported_event', 'source_event', ?36, ?37
                )",
                params![
                    session_key,
                    provider,
                    server_name,
                    server_id,
                    persisted_event_id,
                    user_id,
                    user_name,
                    client_name,
                    device_name,
                    device_id,
                    ip_address,
                    item_id,
                    item_name,
                    item_type,
                    series_name,
                    series_id,
                    season_number,
                    episode_number,
                    production_year,
                    play_method,
                    container,
                    video_codec,
                    video_resolution,
                    audio_codec,
                    audio_channels,
                    subtitle_codec,
                    hw_accel,
                    bitrate_bps,
                    duration_secs,
                    watched_secs,
                    data_used_bytes,
                    completion_pct,
                    started_sql,
                    last_seen_sql,
                    ended_sql_opt,
                    byte_accuracy,
                    policy_status,
                ],
            )?;
            let history_id = conn.last_insert_rowid();
            upsert_history_labels(conn, history_id, &event.libraries, &event.genres)?;
            newly_imported_count += 1;

            outcomes.push(ImportEventOutcome {
                source_event_id,
                history_id,
                disposition: disposition.to_string(),
                policy_status: policy_status.to_string(),
                matched_observed_ids,
            });
        }

        let updated_at = DateTime::from_timestamp(now, 0)
            .unwrap_or_else(Utc::now)
            .to_rfc3339();
        conn.execute(
            "INSERT INTO streaming_import_checkpoints (
                provider, server_id, source, checkpoint, imported, last_error, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)
             ON CONFLICT(provider, server_id, source) DO UPDATE SET
                checkpoint = excluded.checkpoint,
                imported = streaming_import_checkpoints.imported + excluded.imported,
                last_error = NULL,
                updated_at = excluded.updated_at",
            params![
                provider,
                server_id,
                source,
                checkpoint,
                newly_imported_count,
                updated_at
            ],
        )?;

        let cumulative_imported: i64 = conn.query_row(
            "SELECT imported FROM streaming_import_checkpoints
             WHERE provider = ?1 AND server_id = ?2 AND source = ?3",
            params![provider, server_id, source],
            |row| row.get(0),
        )?;

        let revision = bump_history_revision(conn)?;
        record_admin_audit(
            conn,
            user,
            "streaming.import.events",
            "streaming_import_checkpoints",
            &format!("{provider}:{server_id}:{source}"),
            &format!(
                "checkpoint={checkpoint} batch={} inserted={} dedup={} overlap_dup={} ambiguous={}",
                request.events.len(),
                inserted_included,
                deduplicated_retries,
                confirmed_overlap_duplicates,
                ambiguous_overlaps
            ),
        )?;

        Ok(ImportEventsBatchResponse {
            provider,
            server_id,
            source,
            checkpoint,
            batch_size: request.events.len(),
            inserted_included,
            deduplicated_retries,
            confirmed_overlap_duplicates,
            ambiguous_overlaps,
            cumulative_imported,
            revision,
            outcomes,
        })
    })();

    match result {
        Ok(resp) => {
            conn.execute_batch("COMMIT")?;
            Ok(resp)
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}
