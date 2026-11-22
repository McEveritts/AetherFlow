use super::events::import_events_batch;
use super::types::{
    ensure_admin, ImportEventsBatchRequest, ImportEventsBatchResponse, ImportLabelInput,
    ImportResult, ImportedEventInput, NativeExportImportRequest, StreamingImportError,
};
use super::validation::normalize_provider;
use super::MAX_IMPORT_BATCH_EVENTS;
use crate::auth::AuthUser;
use rusqlite::Connection;

fn json_value_to_string(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn json_field_str(
    obj: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    for &key in keys {
        if let Some(v) = obj.get(key).and_then(json_value_to_string) {
            return Some(v);
        }
        if let Some((_, v)) = obj.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)) {
            if let Some(s) = json_value_to_string(v) {
                return Some(s);
            }
        }
    }
    None
}

fn json_field_i64(obj: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> Option<i64> {
    for &key in keys {
        if let Some(v) = obj.get(key) {
            if let Some(i) = v.as_i64() {
                return Some(i);
            }
            if let Some(s) = v.as_str().and_then(|s| s.trim().parse::<i64>().ok()) {
                return Some(s);
            }
        }
        if let Some((_, v)) = obj.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)) {
            if let Some(i) = v.as_i64() {
                return Some(i);
            }
            if let Some(s) = v.as_str().and_then(|s| s.trim().parse::<i64>().ok()) {
                return Some(s);
            }
        }
    }
    None
}

fn normalize_plex_record_map(
    obj: &serde_json::Map<String, serde_json::Value>,
    is_native_media_container: bool,
) -> ImportResult<ImportedEventInput> {
    let item_id = json_field_str(obj, &["ratingKey", "rating_key", "itemId", "item_id"])
        .ok_or_else(|| {
            StreamingImportError::bad_request(
                "invalid_plex_export",
                "Plex export record missing ratingKey / itemId",
            )
        })?;
    let item_name = json_field_str(obj, &["title", "itemName", "item_name", "full_title"])
        .ok_or_else(|| {
            StreamingImportError::bad_request(
                "invalid_plex_export",
                "Plex export record missing title / itemName",
            )
        })?;
    let user_id = json_field_str(
        obj,
        &["accountID", "account_id", "user_id", "userId", "user"],
    )
    .unwrap_or_else(|| "plex-default-user".to_string());
    let user_name = json_field_str(
        obj,
        &["user", "friendly_name", "userName", "user_name", "username"],
    )
    .unwrap_or_else(|| user_id.clone());

    let started_at = json_field_str(
        obj,
        &[
            "startedAt",
            "started_at",
            "started",
            "viewedAt",
            "viewed_at",
            "date",
        ],
    )
    .ok_or_else(|| {
        StreamingImportError::bad_request(
            "invalid_plex_export",
            "Plex export record missing viewedAt / startedAt timestamp",
        )
    })?;
    let ended_at = json_field_str(obj, &["endedAt", "ended_at", "stopped"]);

    let source_event_id = json_field_str(
        obj,
        &[
            "sourceEventId",
            "source_event_id",
            "historyKey",
            "history_key",
            "reference_id",
            "row_id",
            "id",
        ],
    )
    .unwrap_or_else(|| format!("plex:{}:{}:{}", user_id, item_id, started_at));

    let raw_duration = json_field_i64(obj, &["duration_secs", "durationSecs", "duration"]);
    let duration_secs = raw_duration.and_then(|d| {
        let secs = if is_native_media_container && d >= 10_000 {
            d / 1000
        } else {
            d
        };
        (secs > 0).then_some(secs)
    });

    let watched_secs = if let Some(explicit_secs) = json_field_i64(
        obj,
        &[
            "watched_secs",
            "watchedSecs",
            "play_duration",
            "watched_duration",
        ],
    ) {
        Some(explicit_secs.max(0))
    } else if let Some(offset) = json_field_i64(obj, &["viewOffset", "view_offset"]) {
        Some(if is_native_media_container {
            (offset / 1000).max(0)
        } else {
            offset.max(0)
        })
    } else {
        duration_secs
    };

    let item_type = json_field_str(obj, &["type", "media_type", "itemType", "item_type"]);
    let series_name = json_field_str(
        obj,
        &[
            "grandparentTitle",
            "grandparent_title",
            "seriesName",
            "series_name",
        ],
    );
    let series_id = json_field_str(
        obj,
        &[
            "grandparentRatingKey",
            "grandparent_rating_key",
            "seriesId",
            "series_id",
        ],
    );
    let season_number = json_field_i64(
        obj,
        &[
            "parentIndex",
            "parent_index",
            "seasonNumber",
            "season_number",
        ],
    );
    let episode_number = json_field_i64(obj, &["index", "episodeNumber", "episode_number"]);
    let production_year = json_field_i64(obj, &["year", "productionYear", "production_year"]);
    let play_method = json_field_str(
        obj,
        &[
            "playMethod",
            "play_method",
            "transcode_decision",
            "videoDecision",
            "video_decision",
        ],
    );
    let client_name = json_field_str(obj, &["player", "clientName", "client_name", "product"]);
    let device_name = json_field_str(obj, &["device", "platform", "deviceName", "device_name"]);
    let device_id = json_field_str(obj, &["machineIdentifier", "deviceId", "device_id"]);
    let ip_address = json_field_str(obj, &["ip_address", "ipAddress"]);
    let container = json_field_str(obj, &["container", "stream_container"]);
    let video_codec = json_field_str(obj, &["videoCodec", "video_codec", "stream_video_codec"]);
    let video_resolution = json_field_str(
        obj,
        &[
            "videoResolution",
            "video_resolution",
            "stream_video_resolution",
        ],
    );
    let audio_codec = json_field_str(obj, &["audioCodec", "audio_codec", "stream_audio_codec"]);
    let audio_channels = json_field_i64(
        obj,
        &["audioChannels", "audio_channels", "stream_audio_channels"],
    );
    let subtitle_codec = json_field_str(obj, &["subtitleCodec", "subtitle_codec"]);
    let hw_accel = json_field_str(obj, &["hwAccel", "hw_accel"]);
    let bitrate_bps = json_field_i64(obj, &["bitrateBps", "bitrate_bps"]).or_else(|| {
        json_field_i64(obj, &["bandwidth", "bitrate"]).map(|kbps| kbps.saturating_mul(1000))
    });
    let estimated_bytes = json_field_i64(obj, &["estimatedBytes", "estimated_bytes"]);

    let mut libraries = Vec::new();
    if let Some(sec_id) = json_field_str(obj, &["librarySectionID", "section_id", "library_id"]) {
        let sec_name = json_field_str(
            obj,
            &["librarySectionTitle", "section_name", "library_name"],
        )
        .unwrap_or_else(|| sec_id.clone());
        libraries.push(ImportLabelInput {
            id: sec_id,
            name: sec_name,
        });
    }

    Ok(ImportedEventInput {
        source_event_id,
        user_id,
        user_name,
        item_id,
        item_name,
        item_type,
        series_name,
        series_id,
        season_number,
        episode_number,
        production_year,
        started_at,
        ended_at,
        watched_secs,
        duration_secs,
        play_method,
        client_name,
        device_name,
        device_id,
        ip_address,
        container,
        video_codec,
        video_resolution,
        audio_codec,
        audio_channels,
        subtitle_codec,
        hw_accel,
        bitrate_bps,
        estimated_bytes,
        libraries,
        genres: Vec::new(),
    })
}

/// Normalizes a native Plex JSON watch-history export (`MediaContainer.Metadata`, Tautulli
/// `response.data.data`, or JSON array of history objects) into canonical [`ImportedEventInput`] items.
pub fn parse_plex_json_export(
    payload: &serde_json::Value,
) -> ImportResult<Vec<ImportedEventInput>> {
    let (records, is_native_container) = if let Some(arr) = payload
        .get("MediaContainer")
        .or_else(|| payload.get("mediaContainer"))
        .and_then(|mc| mc.get("Metadata").or_else(|| mc.get("metadata")))
        .and_then(|m| m.as_array())
    {
        (arr, true)
    } else if let Some(arr) = payload
        .get("response")
        .and_then(|r| r.get("data"))
        .and_then(|d| d.get("data").or(Some(d)))
        .and_then(|a| a.as_array())
    {
        (arr, false)
    } else if let Some(arr) = payload.as_array() {
        (arr, false)
    } else {
        return Err(StreamingImportError::bad_request(
            "invalid_plex_json_export",
            "Expected Plex MediaContainer.Metadata array, Tautulli response.data.data, or JSON array",
        ));
    };

    if records.is_empty() || records.len() > MAX_IMPORT_BATCH_EVENTS {
        return Err(StreamingImportError::bad_request(
            "invalid_batch_size",
            format!(
                "Plex export batch must contain between 1 and {MAX_IMPORT_BATCH_EVENTS} records"
            ),
        ));
    }

    let mut out = Vec::with_capacity(records.len());
    for rec in records {
        let obj = rec.as_object().ok_or_else(|| {
            StreamingImportError::bad_request(
                "invalid_plex_json_export",
                "Each Plex export entry must be a JSON object",
            )
        })?;
        out.push(normalize_plex_record_map(obj, is_native_container)?);
    }
    Ok(out)
}

fn parse_csv_rows(csv_text: &str) -> ImportResult<Vec<Vec<String>>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut current_row: Vec<String> = Vec::new();
    let mut current_field = String::new();
    let mut in_quotes = false;
    let mut chars = csv_text.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    let _ = chars.next();
                    current_field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                current_field.push(ch);
            }
        } else {
            match ch {
                '"' => in_quotes = true,
                ',' => {
                    current_row.push(current_field.trim().to_string());
                    current_field.clear();
                }
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        let _ = chars.next();
                    }
                    current_row.push(current_field.trim().to_string());
                    current_field.clear();
                    if current_row.iter().any(|c| !c.is_empty()) {
                        rows.push(std::mem::take(&mut current_row));
                    } else {
                        current_row.clear();
                    }
                }
                '\n' => {
                    current_row.push(current_field.trim().to_string());
                    current_field.clear();
                    if current_row.iter().any(|c| !c.is_empty()) {
                        rows.push(std::mem::take(&mut current_row));
                    } else {
                        current_row.clear();
                    }
                }
                _ => current_field.push(ch),
            }
        }
    }
    if in_quotes {
        return Err(StreamingImportError::bad_request(
            "invalid_plex_csv_export",
            "Unterminated quoted field in CSV export",
        ));
    }
    if !current_field.trim().is_empty() || !current_row.is_empty() {
        current_row.push(current_field.trim().to_string());
        if current_row.iter().any(|c| !c.is_empty()) {
            rows.push(current_row);
        }
    }
    Ok(rows)
}

/// Normalizes a Plex / Tautulli CSV watch-history export into canonical [`ImportedEventInput`] items.
pub fn parse_plex_csv_export(csv_text: &str) -> ImportResult<Vec<ImportedEventInput>> {
    let rows = parse_csv_rows(csv_text.trim_start_matches('\u{feff}'))?;
    if rows.len() < 2 {
        return Err(StreamingImportError::bad_request(
            "invalid_plex_csv_export",
            "CSV export must contain a header row and at least one event row",
        ));
    }
    if rows.len() - 1 > MAX_IMPORT_BATCH_EVENTS {
        return Err(StreamingImportError::bad_request(
            "invalid_batch_size",
            format!("CSV export batch must contain between 1 and {MAX_IMPORT_BATCH_EVENTS} rows"),
        ));
    }
    let headers = &rows[0];
    let mut out = Vec::with_capacity(rows.len() - 1);
    for row in &rows[1..] {
        if row.len() > headers.len() {
            return Err(StreamingImportError::bad_request(
                "invalid_plex_csv_export",
                "CSV row has more columns than the header row",
            ));
        }
        let mut map = serde_json::Map::new();
        for (idx, header_name) in headers.iter().enumerate() {
            let key = header_name.trim();
            if !key.is_empty() {
                if let Some(val) = row.get(idx).filter(|s| !s.is_empty()) {
                    map.insert(key.to_string(), serde_json::Value::String(val.clone()));
                }
            }
        }
        out.push(normalize_plex_record_map(&map, false)?);
    }
    Ok(out)
}

/// Validates and imports a native JSON or CSV watch-history export via [`import_events_batch`].
pub fn import_native_export_batch(
    conn: &Connection,
    request: NativeExportImportRequest,
    user: &AuthUser,
    now: i64,
) -> ImportResult<ImportEventsBatchResponse> {
    ensure_admin(user)?;
    let provider = normalize_provider(&request.provider)?;
    let fmt = request.format.trim().to_ascii_lowercase();
    let events = match fmt.as_str() {
        "json" => parse_plex_json_export(&request.payload)?,
        "csv" => {
            let csv_str = request.payload.as_str().ok_or_else(|| {
                StreamingImportError::bad_request(
                    "invalid_plex_csv_export",
                    "CSV export payload must be a string",
                )
            })?;
            parse_plex_csv_export(csv_str)?
        }
        _ => {
            return Err(StreamingImportError::bad_request(
                "invalid_export_format",
                "format must be 'json' or 'csv'",
            ))
        }
    };

    import_events_batch(
        conn,
        ImportEventsBatchRequest {
            provider,
            server_id: request.server_id,
            server_name: request.server_name,
            source: request.source,
            checkpoint: request.checkpoint,
            expected_checkpoint: request.expected_checkpoint,
            events,
        },
        user,
        now,
    )
}
