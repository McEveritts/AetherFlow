use crate::auth::{api_error, AuthUser};
use axum::body::Body;
use axum::extract::{Extension, Query};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Datelike, TimeZone, Utc};
use chrono_tz::Tz;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::{params_from_iter, types::Value, Connection, Row};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

#[cfg(test)]
#[path = "streaming_history_tests.rs"]
mod tests;

const CURSOR_TTL_SECS: i64 = 900;
const INCLUDED: &str = "h.policy_status = 'included' AND (h.provenance NOT IN ('observed_session','imported_event') OR COALESCE(h.watched_secs,0) >= p.minimum_watch_secs) AND NOT EXISTS (SELECT 1 FROM json_each(p.excluded_users) e WHERE json_extract(e.value,'$.provider') = h.provider AND json_extract(e.value,'$.serverId') = h.server_id AND json_extract(e.value,'$.id') = h.user_id) AND NOT EXISTS (SELECT 1 FROM streaming_history_labels l JOIN json_each(p.excluded_libraries) e ON json_extract(e.value,'$.id') = l.value WHERE l.history_id = h.id AND l.kind = 'library' AND json_extract(e.value,'$.provider') = h.provider AND json_extract(e.value,'$.serverId') = h.server_id)";
const FROM_HISTORY: &str = "FROM streaming_history h CROSS JOIN streaming_tracking_policies p";
static CURSOR_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
});

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct HistoryQuery {
    pub window: String,
    pub from: String,
    pub until: String,
    pub timezone: String,
    pub provider: String,
    pub server_id: String,
    pub user_id: String,
    pub client: String,
    pub device: String,
    pub item_id: String,
    pub library_id: String,
    pub genre: String,
    pub media_type: String,
    pub play_method: String,
    pub provenance: String,
    pub search: String,
    pub sort: String,
    pub page_size: usize,
    pub include_excluded: bool,
    #[serde(skip_serializing)]
    pub cursor: Option<String>,
    #[serde(skip_serializing)]
    pub snapshot: Option<String>,
}

impl Default for HistoryQuery {
    fn default() -> Self {
        Self {
            window: "all".into(), from: String::new(), until: String::new(), timezone: "UTC".into(),
            provider: "all".into(), server_id: String::new(), user_id: String::new(),
            client: String::new(), device: String::new(), item_id: String::new(),
            library_id: String::new(), genre: String::new(), media_type: "all".into(),
            play_method: "all".into(), provenance: "all".into(), search: String::new(),
            sort: "startedDesc".into(), page_size: 50, include_excluded: false,
            cursor: None, snapshot: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HistoryCounts {
    pub available_records: i64,
    pub matching_records: i64,
    pub undated_records: i64,
    pub confirmed_plays: i64,
    pub item_summaries: i64,
    pub legacy_records: i64,
    pub watch_time_secs: i64,
    pub estimated_bytes: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryItem {
    pub id: i64, pub provider: String, pub server_id: String,
    pub source_event_id: Option<String>, pub provenance: String,
    pub timestamp_certainty: String, pub byte_accuracy: String,
    pub user_id: String, pub user_name: String,
    pub client_name: Option<String>, pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    pub item_id: String, pub item_name: String, pub item_type: Option<String>,
    pub series_name: Option<String>, pub play_method: Option<String>,
    pub watched_secs: Option<i64>, pub duration_secs: Option<i64>,
    pub estimated_bytes: Option<i64>, pub started_at: Option<String>,
    pub last_seen_at: Option<String>, pub ended_at: Option<String>,
    pub is_active: bool, pub included: bool, pub policy_status: String,
    pub library_ids: Vec<String>, pub genres: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryScope {
    pub snapshot_token: String, pub watermark: i64, pub revision: i64,
    pub as_of: String, pub expires_at: String, pub timezone: String,
    pub permission_scope: String, pub sample_retention_days: i32,
    pub date_semantics: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPage {
    pub schema_version: u8, pub query: HistoryQuery, pub scope: HistoryScope,
    pub counts: HistoryCounts, pub items: Vec<HistoryItem>, pub next_cursor: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HistoryError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: &'static str,
}

impl HistoryError {
    pub fn invalid(message: &'static str) -> Self {
        Self { status: StatusCode::BAD_REQUEST, code: "invalid_history_query", message }
    }
    pub fn stale() -> Self {
        Self { status: StatusCode::CONFLICT, code: "history_snapshot_changed", message: "History changed or the snapshot expired. Restart this query." }
    }
}

impl From<rusqlite::Error> for HistoryError {
    fn from(error: rusqlite::Error) -> Self {
        tracing::error!(%error, "Streaming archive database operation failed");
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, code: "history_unavailable", message: "History is temporarily unavailable" }
    }
}

impl IntoResponse for HistoryError {
    fn into_response(self) -> Response { api_error(self.status, self.code, self.message) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Anchor { missing: i64, timestamp: i64, id: i64 }

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Snapshot {
    version: u8, watermark: i64, revision: i64, as_of: i64, expires_at: i64,
    fingerprint: String, counts: HistoryCounts, anchor: Option<Anchor>,
}

type HistoryResult<T> = Result<T, HistoryError>;

fn sign(snapshot: &Snapshot) -> String {
    let payload = serde_json::to_vec(snapshot).expect("serializable history cursor");
    let mut mac = Hmac::<Sha256>::new_from_slice(&*CURSOR_KEY).expect("fixed-size HMAC key");
    mac.update(&payload);
    format!("{}.{}", URL_SAFE_NO_PAD.encode(&payload), URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn decode(token: &str, now: i64) -> HistoryResult<Snapshot> {
    if token.len() > 8192 { return Err(HistoryError::invalid("History cursor is too long")); }
    let (payload, signature) = token.split_once('.').ok_or_else(|| HistoryError::invalid("Malformed history cursor"))?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| HistoryError::invalid("Malformed history cursor"))?;
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| HistoryError::invalid("Malformed history cursor"))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&*CURSOR_KEY).expect("fixed-size HMAC key");
    mac.update(&bytes);
    mac.verify_slice(&signature).map_err(|_| HistoryError::invalid("Invalid history cursor signature"))?;
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| HistoryError::invalid("Malformed history cursor"))?;
    if snapshot.version != 1 || now >= snapshot.expires_at { return Err(HistoryError::stale()); }
    Ok(snapshot)
}

pub fn normalize(mut query: HistoryQuery, admin: bool) -> HistoryResult<HistoryQuery> {
    if query.cursor.is_some() && query.snapshot.is_some() { return Err(HistoryError::invalid("Use cursor or snapshot, not both")); }
    if !(1..=200).contains(&query.page_size) { return Err(HistoryError::invalid("pageSize must be between 1 and 200")); }
    if query.include_excluded && !admin {
        return Err(HistoryError { status: StatusCode::FORBIDDEN, code: "admin_required", message: "Excluded history requires administrative access" });
    }
    for value in [&mut query.provider, &mut query.server_id, &mut query.user_id, &mut query.client,
        &mut query.device, &mut query.item_id, &mut query.library_id, &mut query.genre, &mut query.search] {
        *value = value.trim().to_string();
        if value.len() > 256 || value.chars().any(char::is_control) { return Err(HistoryError::invalid("Filter values must be at most 256 bytes without control characters")); }
    }
    query.provider = query.provider.to_ascii_lowercase();
    query.media_type = query.media_type.trim().to_ascii_lowercase();
    query.play_method = query.play_method.trim().to_ascii_lowercase().replace([' ', '_'], "");
    if !["all", "jellyfin", "emby"].contains(&query.provider.as_str()) { return Err(HistoryError::invalid("Unsupported history provider")); }
    if !["all", "movie", "episode", "audio", "video", "unknown"].contains(&query.media_type.as_str()) { return Err(HistoryError::invalid("Unsupported media type")); }
    if !["all", "directplay", "directstream", "transcode", "unknown"].contains(&query.play_method.as_str()) { return Err(HistoryError::invalid("Unsupported delivery method")); }
    if !["all", "legacy_unverified", "observed_session", "imported_event", "item_summary"].contains(&query.provenance.as_str()) { return Err(HistoryError::invalid("Unsupported provenance")); }
    if !["startedDesc", "startedAsc"].contains(&query.sort.as_str()) { return Err(HistoryError::invalid("Unsupported history ordering")); }
    if !["all", "7d", "30d", "90d", "365d", "today", "month", "year", "custom"].contains(&query.window.as_str()) { return Err(HistoryError::invalid("Unsupported history window")); }
    query.timezone.parse::<Tz>().map_err(|_| HistoryError::invalid("timezone must be an IANA timezone"))?;
    if query.from.len() > 64 || query.until.len() > 64 || query.timezone.len() > 128 { return Err(HistoryError::invalid("Invalid date or timezone")); }
    if query.window != "custom" && (!query.from.is_empty() || !query.until.is_empty()) { return Err(HistoryError::invalid("from/until require the custom window")); }
    Ok(query)
}

pub(crate) fn bounds(query: &HistoryQuery, as_of: i64) -> HistoryResult<(Option<i64>, Option<i64>)> {
    let now = DateTime::from_timestamp(as_of, 0).ok_or_else(|| HistoryError::invalid("Invalid reference timestamp"))?;
    let timezone: Tz = query.timezone.parse().map_err(|_| HistoryError::invalid("Invalid timezone"))?;
    let local = now.with_timezone(&timezone);
    let start = match query.window.as_str() {
        "all" => return Ok((None, None)),
        "custom" => {
            let start = DateTime::parse_from_rfc3339(&query.from).map_err(|_| HistoryError::invalid("from must include an RFC3339 UTC offset"))?.timestamp();
            let end = DateTime::parse_from_rfc3339(&query.until).map_err(|_| HistoryError::invalid("until must include an RFC3339 UTC offset"))?.timestamp();
            if start >= end { return Err(HistoryError::invalid("from must be earlier than until")); }
            return Ok((Some(start), Some(end)));
        }
        "7d" => return Ok((Some(as_of - 7 * 86400), Some(as_of))),
        "30d" => return Ok((Some(as_of - 30 * 86400), Some(as_of))),
        "90d" => return Ok((Some(as_of - 90 * 86400), Some(as_of))),
        "365d" => return Ok((Some(as_of - 365 * 86400), Some(as_of))),
        "today" => local.date_naive(),
        "month" => local.date_naive().with_day(1).ok_or_else(|| HistoryError::invalid("Invalid calendar date"))?,
        "year" => local.date_naive().with_ordinal(1).ok_or_else(|| HistoryError::invalid("Invalid calendar date"))?,
        _ => return Err(HistoryError::invalid("Unsupported window")),
    };
    let midnight = start.and_hms_opt(0, 0, 0).ok_or_else(|| HistoryError::invalid("Invalid midnight"))?;
    let start = timezone.from_local_datetime(&midnight).earliest().ok_or_else(|| HistoryError::invalid("This calendar boundary does not exist in the selected timezone"))?.timestamp();
    Ok((Some(start), Some(as_of)))
}

fn fingerprint(query: &HistoryQuery, user: &AuthUser) -> String {
    let mut hash = Sha256::new();
    hash.update(serde_json::to_vec(query).expect("serializable history query"));
    hash.update(format!("|{}|{}", user.user_id, user.role));
    hex::encode(hash.finalize())
}

pub(crate) fn resolve_query_scope(conn: &Connection, raw: HistoryQuery, user: &AuthUser, now: i64) -> HistoryResult<(HistoryQuery, i64, i64, i64)> {
    let mut query = normalize(raw, user.role == "admin")?;
    if query.cursor.is_some() { return Err(HistoryError::invalid("Analytics accepts a snapshot, not a page cursor")); }
    let token = query.snapshot.take();
    let revision = read_revision(conn)?;
    if let Some(token) = token {
        let snapshot = decode(&token, now)?;
        if snapshot.anchor.is_some() || snapshot.fingerprint != fingerprint(&query, user) {
            return Err(HistoryError::invalid("Snapshot belongs to another query or viewer"));
        }
        if snapshot.revision != revision { return Err(HistoryError::stale()); }
        return Ok((query, snapshot.watermark, revision, snapshot.as_of));
    }
    let watermark = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM streaming_history", [], |row| row.get(0))?;
    Ok((query, watermark, revision, now))
}

pub(crate) fn inclusion_predicate() -> &'static str { INCLUDED }

fn read_revision(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT revision FROM streaming_history_read_revision WHERE id=1", [], |row| row.get(0))
        .or_else(|_| conn.query_row("SELECT revision FROM streaming_history_revision WHERE id=1", [], |row| row.get(0)))
}

pub(crate) fn scope_filters(query: &HistoryQuery, user: &AuthUser, watermark: i64) -> (Vec<String>, Vec<Value>) {
    let mut clauses = vec!["p.id = 1".into(), "h.provider != 'demo'".into(), "h.id <= ?".into()];
    let mut values = vec![Value::Integer(watermark)];
    if user.role != "admin" {
        clauses.push("EXISTS (SELECT 1 FROM streaming_user_links identity WHERE identity.af_user_id = ? AND identity.provider = h.provider AND identity.server_id = h.server_id AND identity.provider_user_id = h.user_id)".into());
        values.push(Value::Integer(user.user_id));
    }
    if !query.include_excluded { clauses.push(format!("({INCLUDED})")); }
    (clauses, values)
}

pub(crate) fn query_filters(query: &HistoryQuery, as_of: i64, clauses: &mut Vec<String>, values: &mut Vec<Value>) -> HistoryResult<()> {
    let (start, end) = bounds(query, as_of)?;
    if let Some(start) = start { clauses.push("h.event_unix >= ?".into()); values.push(Value::Integer(start)); }
    if let Some(end) = end { clauses.push("h.event_unix < ?".into()); values.push(Value::Integer(end)); }
    for (value, field, all) in [(&query.provider, "h.provider", true), (&query.server_id, "h.server_id", false),
        (&query.user_id, "h.user_id", false), (&query.item_id, "h.item_id", false),
        (&query.provenance, "h.provenance", true)] {
        if !value.is_empty() && (!all || value != "all") { clauses.push(format!("{field} = ?")); values.push(Value::Text(value.clone())); }
    }
    for (value, field) in [(&query.client, "h.client_name"), (&query.device, "h.device_name")] {
        if !value.is_empty() {
            clauses.push(format!("lower(COALESCE(NULLIF(trim({field}), ''), 'Unknown')) = lower(?)"));
            values.push(Value::Text(value.clone()));
        }
    }
    if query.media_type != "all" {
        clauses.push("lower(COALESCE(NULLIF(trim(h.item_type), ''), 'unknown')) = ?".into());
        values.push(Value::Text(query.media_type.clone()));
    }
    if query.play_method != "all" {
        clauses.push("CASE WHEN lower(replace(replace(trim(COALESCE(h.play_method,'')), ' ', ''), '_', '')) IN ('directplay','directstream','transcode') THEN lower(replace(replace(trim(h.play_method), ' ', ''), '_', '')) ELSE 'unknown' END = ?".into());
        values.push(Value::Text(query.play_method.clone()));
    }
    for (value, kind) in [(&query.library_id, "library"), (&query.genre, "genre")] {
        if !value.is_empty() { clauses.push("EXISTS (SELECT 1 FROM streaming_history_labels label WHERE label.history_id = h.id AND label.kind = ? AND label.value = ?)".into()); values.push(Value::Text(kind.into())); values.push(Value::Text(value.clone())); }
    }
    if !query.search.is_empty() {
        let pattern = format!("%{}%", query.search.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
        clauses.push(r"(h.item_name LIKE ? ESCAPE '\' OR h.series_name LIKE ? ESCAPE '\' OR h.user_name LIKE ? ESCAPE '\' OR h.client_name LIKE ? ESCAPE '\' OR h.device_name LIKE ? ESCAPE '\')".into());
        for _ in 0..5 { values.push(Value::Text(pattern.clone())); }
    }
    Ok(())
}

fn count_history(conn: &Connection, clauses: &[String], values: &[Value]) -> HistoryResult<HistoryCounts> {
    let confirmed = format!("({INCLUDED}) AND h.provenance IN ('observed_session','imported_event')");
    let sql = format!("SELECT COUNT(*), COALESCE(SUM(h.event_unix IS NULL),0), COALESCE(SUM(CASE WHEN {confirmed} THEN 1 ELSE 0 END),0), COALESCE(SUM(h.provenance = 'item_summary'),0), COALESCE(SUM(h.provenance = 'legacy_unverified'),0), COALESCE(SUM(CASE WHEN {confirmed} THEN MAX(COALESCE(h.watched_secs,0),0) ELSE 0 END),0), COALESCE(SUM(CASE WHEN {confirmed} AND h.byte_accuracy = 'estimated' THEN MAX(COALESCE(h.data_used_bytes,0),0) ELSE 0 END),0) {FROM_HISTORY} WHERE {}", clauses.join(" AND "));
    Ok(conn.query_row(&sql, params_from_iter(values), |row| Ok(HistoryCounts {
        available_records: 0, matching_records: row.get(0)?, undated_records: row.get(1)?,
        confirmed_plays: row.get(2)?, item_summaries: row.get(3)?, legacy_records: row.get(4)?,
        watch_time_secs: row.get(5)?, estimated_bytes: row.get(6)?,
    }))?)
}

fn iso_timestamp(timestamp: Option<i64>) -> Option<String> {
    timestamp.and_then(|value| DateTime::from_timestamp(value, 0)).map(|value| value.to_rfc3339())
}

fn read_item(row: &Row<'_>, admin: bool) -> rusqlite::Result<HistoryItem> {
    let optional_text = |index| -> rusqlite::Result<Option<String>> { Ok(row.get::<_, Option<String>>(index)?.filter(|value| !value.trim().is_empty())) };
    let provenance: String = row.get(4)?;
    let byte_accuracy: String = row.get(6)?;
    let method = optional_text(17)?.and_then(|value| {
        match value.trim().to_ascii_lowercase().replace(['_', ' '], "").as_str() {
            "directplay" => Some("DirectPlay".into()),
            "directstream" => Some("DirectStream".into()),
            "transcode" => Some("Transcode".into()),
            _ => None,
        }
    });
    let watched_secs = if provenance == "item_summary" { None } else { row.get::<_, Option<i64>>(18)?.filter(|value| *value >= 0) };
    let duration: Option<i64> = row.get(19)?;
    let bytes: Option<i64> = row.get(20)?;
    Ok(HistoryItem {
        id: row.get(0)?, provider: row.get(1)?, server_id: row.get(2)?, source_event_id: optional_text(3)?,
        provenance, timestamp_certainty: row.get(5)?, byte_accuracy: byte_accuracy.clone(),
        user_id: row.get(7)?, user_name: row.get(8)?, client_name: optional_text(9)?, device_name: optional_text(10)?,
        device_id: if admin { optional_text(11)? } else { None }, ip_address: if admin { optional_text(12)? } else { None },
        item_id: row.get(13)?, item_name: row.get(14)?, item_type: optional_text(15)?, series_name: optional_text(16)?,
        play_method: method, watched_secs,
        duration_secs: duration.filter(|value| *value > 0),
        estimated_bytes: if byte_accuracy == "estimated" { bytes.filter(|value| *value >= 0) } else { None },
        started_at: iso_timestamp(row.get(21)?), last_seen_at: iso_timestamp(row.get(22)?), ended_at: iso_timestamp(row.get(23)?),
        is_active: row.get::<_, i64>(24)? != 0, included: row.get::<_, i64>(25)? != 0, policy_status: row.get(26)?,
        library_ids: serde_json::from_str(&row.get::<_, String>(27)?).unwrap_or_default(),
        genres: serde_json::from_str(&row.get::<_, String>(28)?).unwrap_or_default(),
    })
}

pub fn query_history(conn: &Connection, raw: HistoryQuery, user: &AuthUser, now: i64) -> HistoryResult<HistoryPage> {
    query_history_batch(conn, raw, user, now, None)
}

fn query_history_batch(conn: &Connection, raw: HistoryQuery, user: &AuthUser, now: i64, batch_size: Option<usize>) -> HistoryResult<HistoryPage> {
    let mut query = normalize(raw, user.role == "admin")?;
    let page_size = batch_size.unwrap_or(query.page_size).clamp(1, 1000);
    let cursor_requested = query.cursor.is_some();
    let token = query.cursor.take().or_else(|| query.snapshot.take());
    let expected_fingerprint = fingerprint(&query, user);
    let tx = conn.unchecked_transaction()?;
    let revision = read_revision(&tx)?;
    let mut snapshot = if let Some(token) = token {
        let snapshot = decode(&token, now)?;
        if cursor_requested != snapshot.anchor.is_some() {
            return Err(HistoryError::invalid("Use a page cursor for pagination and an unanchored snapshot for the full query"));
        }
        if snapshot.fingerprint != expected_fingerprint { return Err(HistoryError::invalid("Cursor belongs to another query or viewer")); }
        if snapshot.revision != revision { return Err(HistoryError::stale()); }
        snapshot
    } else {
        Snapshot { version: 1, watermark: tx.query_row("SELECT COALESCE(MAX(id),0) FROM streaming_history", [], |row| row.get(0))?,
            revision, as_of: now, expires_at: now + CURSOR_TTL_SECS, fingerprint: expected_fingerprint,
            counts: HistoryCounts::default(), anchor: None }
    };
    let (mut clauses, mut values) = scope_filters(&query, user, snapshot.watermark);
    let base_clauses = clauses.clone();
    let base_values = values.clone();
    query_filters(&query, snapshot.as_of, &mut clauses, &mut values)?;
    if snapshot.counts == HistoryCounts::default() && snapshot.anchor.is_none() {
        let available: i64 = tx.query_row(&format!("SELECT COUNT(*) {FROM_HISTORY} WHERE {}", base_clauses.join(" AND ")), params_from_iter(&base_values), |row| row.get(0))?;
        snapshot.counts = count_history(&tx, &clauses, &values)?;
        snapshot.counts.available_records = available;
    }
    let ascending = query.sort == "startedAsc";
    let comparison = if ascending { ">" } else { "<" };
    let direction = if ascending { "ASC" } else { "DESC" };
    let filtered_clauses = clauses;
    let filtered_values = values;
    let mut items = Vec::with_capacity(page_size + 1);
    for missing in [0, 1] {
        if snapshot.anchor.as_ref().is_some_and(|anchor| anchor.missing > missing) { continue; }
        let mut clauses = filtered_clauses.clone();
        let mut values = filtered_values.clone();
        clauses.push(format!("h.event_missing = {missing}"));
        if missing == 1 { clauses.push("h.event_unix IS NULL".into()); }
        if let Some(anchor) = snapshot.anchor.as_ref().filter(|anchor| anchor.missing == missing) {
            if missing == 0 {
                clauses.push(format!("(h.event_unix,h.id) {comparison} (?,?)"));
                values.extend([Value::Integer(anchor.timestamp), Value::Integer(anchor.id)]);
            } else {
                clauses.push(format!("h.id {comparison} ?"));
                values.push(Value::Integer(anchor.id));
            }
        }
    let sql = format!("SELECT h.id,h.provider,h.server_id,h.source_event_id,h.provenance,h.timestamp_certainty,h.byte_accuracy,h.user_id,h.user_name,NULLIF(h.client_name,''),NULLIF(h.device_name,''),h.device_id,h.ip_address,h.item_id,h.item_name,NULLIF(h.item_type,''),NULLIF(h.series_name,''),h.play_method,h.watched_secs,h.duration_secs,h.data_used_bytes,h.event_unix,CAST(strftime('%s',NULLIF(h.last_seen_at,'')) AS INTEGER),CAST(strftime('%s',NULLIF(h.ended_at,'')) AS INTEGER),(h.is_active AND CAST(strftime('%s',h.last_seen_at) AS INTEGER)>=CAST(strftime('%s','now') AS INTEGER)-60),({INCLUDED}),h.policy_status,COALESCE((SELECT json_group_array(value) FROM streaming_history_labels WHERE history_id=h.id AND kind='library'),'[]'),COALESCE((SELECT json_group_array(value) FROM streaming_history_labels WHERE history_id=h.id AND kind='genre'),'[]') {FROM_HISTORY} WHERE {} ORDER BY h.event_missing ASC,h.event_unix {direction},h.id {direction} LIMIT ?", clauses.join(" AND "));
        values.push(Value::Integer((page_size + 1 - items.len()) as i64));
        let batch: Vec<HistoryItem> = tx.prepare(&sql)?.query_map(params_from_iter(&values), |row| read_item(row, user.role == "admin"))?.collect::<rusqlite::Result<_>>()?;
        items.extend(batch);
        if items.len() > page_size { break; }
    }
    let has_more = items.len() > page_size;
    items.truncate(page_size);
    let mut first_snapshot = snapshot.clone();
    first_snapshot.anchor = None;
    let next_cursor = if has_more {
        let last = items.last().expect("nonempty page when more rows exist");
        let timestamp = last.started_at.as_ref().and_then(|value| DateTime::parse_from_rfc3339(value).ok()).map(|value| value.timestamp());
        snapshot.anchor = Some(Anchor { missing: i64::from(timestamp.is_none()), timestamp: timestamp.unwrap_or(0), id: last.id });
        Some(sign(&snapshot))
    } else { None };
    tx.commit()?;
    Ok(HistoryPage { schema_version: 1, query: query.clone(),
        scope: HistoryScope { snapshot_token: sign(&first_snapshot), watermark: snapshot.watermark, revision,
            as_of: iso_timestamp(Some(snapshot.as_of)).unwrap_or_default(), expires_at: iso_timestamp(Some(snapshot.expires_at)).unwrap_or_default(),
            timezone: query.timezone.clone(), permission_scope: if user.role == "admin" { "administrative" } else { "linked_user" }.into(),
            sample_retention_days: 90, date_semantics: "UTC half-open windows; undated records only in all-time; mutations invalidate snapshots".into() },
        counts: snapshot.counts, items, next_cursor })
}

fn csv_cell(value: &str) -> String {
    let dangerous = value.trim_start().starts_with(['=', '+', '-', '@'])
        || value.chars().take_while(|character| character.is_whitespace()).any(|character| matches!(character, '\t' | '\r' | '\n'));
    format!("\"{}{}\"", if dangerous { "'" } else { "" }, value.replace('"', "\"\""))
}

pub(crate) fn csv_page(items: &[HistoryItem], admin: bool) -> String {
    let mut result = String::new();
    for item in items {
        let mut cells = vec![item.id.to_string(), item.provider.clone(), item.server_id.clone(), item.user_id.clone(),
            item.user_name.clone(), item.item_id.clone(), item.item_name.clone(), item.provenance.clone(),
            item.timestamp_certainty.clone(), item.started_at.clone().unwrap_or_default(), item.ended_at.clone().unwrap_or_default(),
            item.client_name.clone().unwrap_or_default(), item.device_name.clone().unwrap_or_default(),
            item.play_method.clone().unwrap_or_default(), item.watched_secs.map(|value| value.to_string()).unwrap_or_default(),
            item.estimated_bytes.map(|value| value.to_string()).unwrap_or_default(), item.byte_accuracy.clone(),
            item.included.to_string(), item.library_ids.join(";"), item.genres.join(";")];
        if admin { cells.extend([item.ip_address.clone().unwrap_or_default(), item.device_id.clone().unwrap_or_default()]); }
        result.push_str(&cells.iter().map(|cell| csv_cell(cell)).collect::<Vec<_>>().join(","));
        result.push_str("\r\n");
    }
    result
}

async fn load_page(query: HistoryQuery, user: AuthUser) -> HistoryResult<HistoryPage> {
    load_page_batch(query, user, false).await
}

async fn load_page_batch(query: HistoryQuery, user: AuthUser, export: bool) -> HistoryResult<HistoryPage> {
    tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| HistoryError { status: StatusCode::SERVICE_UNAVAILABLE, code: "history_unavailable", message: "History database is unavailable" })?;
        query_history_batch(&conn, query, &user, Utc::now().timestamp(), export.then_some(1000))
    }).await.map_err(|_| HistoryError { status: StatusCode::INTERNAL_SERVER_ERROR, code: "history_unavailable", message: "History query failed" })?
}

pub async fn history_handler(Query(query): Query<HistoryQuery>, Extension(user): Extension<AuthUser>) -> Response {
    match load_page(query, user).await {
        Ok(page) => ([(header::CACHE_CONTROL, "no-store")], Json(page)).into_response(),
        Err(error) => error.into_response(),
    }
}

pub async fn history_export_handler(Query(mut query): Query<HistoryQuery>, Extension(user): Extension<AuthUser>) -> Response {
    if query.cursor.is_some() { return HistoryError::invalid("Full-query export accepts snapshot, not a page cursor").into_response(); }
    let first = match load_page_batch(query.clone(), user.clone(), true).await { Ok(page) => page, Err(error) => return error.into_response() };
    let expected_rows = first.counts.matching_records;
    let admin = user.role == "admin";
    query.snapshot = None;
    let stream = async_stream::try_stream! {
        let started = Instant::now();
        let mut page = first;
        let mut sent = 0i64;
        let mut header = "Id,Provider,ServerId,UserId,User,ItemId,Title,Provenance,TimestampCertainty,StartedAt,EndedAt,Client,Device,DeliveryMethod,WatchSeconds,EstimatedBytes,ByteAccuracy,Included,LibraryIds,Genres".to_string();
        if admin { header.push_str(",IPAddress,DeviceId"); }
        header.push_str("\r\n");
        yield header.into_bytes();
        loop {
            if started.elapsed() > Duration::from_secs(30) { Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "History export exceeded its time budget"))?; }
            sent += page.items.len() as i64;
            yield csv_page(&page.items, admin).into_bytes();
            match page.next_cursor.take() {
                Some(cursor) => {
                    query.cursor = Some(cursor);
                    page = load_page_batch(query.clone(), user.clone(), true).await.map_err(|error| std::io::Error::other(error.message))?;
                }
                None => break,
            }
        }
        if sent != expected_rows { Err(std::io::Error::other("History export row count changed"))?; }
    };
    let stream: std::pin::Pin<Box<dyn futures::Stream<Item = Result<Vec<u8>, std::io::Error>> + Send>> = Box::pin(stream);
    ([(header::CONTENT_TYPE, "text/csv; charset=utf-8"), (header::CONTENT_DISPOSITION, "attachment; filename=\"streaming-history.csv\""), (header::CACHE_CONTROL, "no-store"), (header::HeaderName::from_static("x-streaming-expected-rows"), &expected_rows.to_string())], Body::from_stream(stream)).into_response()
}
