use super::types::{ImportResult, StreamingImportError};
use crate::auth::AuthUser;
use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::{params, Connection};

pub(super) fn normalize_provider(raw: &str) -> ImportResult<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if matches!(normalized.as_str(), "jellyfin" | "emby" | "plex") {
        Ok(normalized)
    } else {
        Err(StreamingImportError::bad_request(
            "invalid_provider",
            "provider must be 'jellyfin', 'emby', or 'plex'",
        ))
    }
}

pub(super) fn normalize_nonempty_token(
    raw: &str,
    field: &'static str,
    max_len: usize,
) -> ImportResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(StreamingImportError::bad_request(
            "invalid_import_field",
            format!("{field} must not be empty"),
        ));
    }
    if trimmed.len() > max_len || trimmed.chars().any(char::is_control) {
        return Err(StreamingImportError::bad_request(
            "invalid_import_field",
            format!("{field} must be at most {max_len} bytes without control characters"),
        ));
    }
    Ok(trimmed.to_string())
}

pub(super) fn normalize_optional_text(
    raw: &Option<String>,
    max_len: usize,
) -> ImportResult<String> {
    let Some(value) = raw else {
        return Ok(String::new());
    };
    let trimmed = value.trim();
    if trimmed.len() > max_len || trimmed.chars().any(char::is_control) {
        return Err(StreamingImportError::bad_request(
            "invalid_import_field",
            format!("Optional text field exceeds {max_len} bytes or contains control characters"),
        ));
    }
    Ok(trimmed.to_string())
}

pub(super) fn normalize_play_method(raw: &Option<String>) -> ImportResult<String> {
    let Some(value) = raw else {
        return Ok(String::new());
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    match trimmed
        .to_ascii_lowercase()
        .replace([' ', '_', '-'], "")
        .as_str()
    {
        "directplay" => Ok("DirectPlay".to_string()),
        "directstream" | "copy" => Ok("DirectStream".to_string()),
        "transcode" => Ok("Transcode".to_string()),
        "unknown" => Ok(String::new()),
        _ => Err(StreamingImportError::bad_request(
            "invalid_play_method",
            "playMethod must be DirectPlay, DirectStream, Transcode, or omitted when unrecorded",
        )),
    }
}

pub(super) fn normalize_media_type(raw: &Option<String>) -> ImportResult<String> {
    let Some(value) = raw else {
        return Ok(String::new());
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "movie" => Ok("Movie".to_string()),
        "episode" => Ok("Episode".to_string()),
        "audio" | "track" => Ok("Audio".to_string()),
        "video" | "clip" => Ok("Video".to_string()),
        "unknown" => Ok(String::new()),
        _ => Err(StreamingImportError::bad_request(
            "invalid_media_type",
            "itemType must be Movie, Episode, Audio, Video, or omitted when unrecorded",
        )),
    }
}

/// Parses an RFC3339 timestamp, SQL UTC timestamp (`YYYY-MM-DD HH:MM:SS`), or Unix epoch seconds into `(sql_utc, unix_secs)`.
pub(super) fn parse_event_timestamp(raw: &str, field: &'static str) -> ImportResult<(String, i64)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(StreamingImportError::bad_request(
            "invalid_timestamp",
            format!("{field} is required for real playback events"),
        ));
    }
    if let Ok(raw_epoch) = trimmed.parse::<i64>() {
        let secs = if raw_epoch > 100_000_000_000 {
            raw_epoch / 1000
        } else {
            raw_epoch
        };
        if secs <= 0 {
            return Err(StreamingImportError::bad_request(
                "invalid_timestamp",
                format!("{field} must be after the Unix epoch"),
            ));
        }
        if let Some(utc) = DateTime::from_timestamp(secs, 0) {
            return Ok((utc.format("%Y-%m-%d %H:%M:%S").to_string(), secs));
        }
    }
    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        let utc = parsed.with_timezone(&Utc);
        let ts = utc.timestamp();
        if ts <= 0 {
            return Err(StreamingImportError::bad_request(
                "invalid_timestamp",
                format!("{field} must be after the Unix epoch"),
            ));
        }
        return Ok((utc.format("%Y-%m-%d %H:%M:%S").to_string(), ts));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        let utc = naive.and_utc();
        let ts = utc.timestamp();
        if ts <= 0 {
            return Err(StreamingImportError::bad_request(
                "invalid_timestamp",
                format!("{field} must be after the Unix epoch"),
            ));
        }
        return Ok((utc.format("%Y-%m-%d %H:%M:%S").to_string(), ts));
    }
    Err(StreamingImportError::bad_request(
        "invalid_timestamp",
        format!("{field} must be an RFC3339 timestamp or 'YYYY-MM-DD HH:MM:SS' UTC string"),
    ))
}

pub(super) fn current_history_revision(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT revision FROM streaming_history_revision WHERE id = 1",
        [],
        |row| row.get(0),
    )
}

pub(super) fn bump_history_revision(conn: &Connection) -> rusqlite::Result<i64> {
    conn.execute(
        "UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1",
        [],
    )?;
    current_history_revision(conn)
}

pub(super) fn record_admin_audit(
    conn: &Connection,
    user: &AuthUser,
    action: &str,
    target_type: &str,
    target_id: &str,
    detail: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO admin_audit_log (user_id, username, action, target_type, target_id, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            user.user_id,
            user.username,
            action,
            target_type,
            target_id,
            detail
        ],
    )?;
    Ok(())
}
