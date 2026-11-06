//! Phase 4: Streaming history bounded event import, tracking policies, explicit user-link
//! mapping, and guarded legacy reconciliation (preview + signed, backup-verified apply).
//!
//! All handlers in this module require an authenticated administrator (`AuthUser.role == "admin"`).
//! Every database operation is exposed both as a pure `&rusqlite::Connection` core function (for
//! isolated in-memory / temp-file unit tests without global pool state) and as an Axum HTTP handler.

use crate::auth::{api_error, AuthUser};
use crate::streaming_history::{
    inclusion_predicate, query_filters, resolve_query_scope, scope_filters, HistoryCounts,
    HistoryQuery,
};
use axum::extract::{Extension, Json, Query};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// ─────────────────────────────────────────────────────────────────────────────
// Public Route Constants (for parent route wiring in `routes.rs`)
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /api/v1/admin/streaming/imports/status` — list import checkpoints & upstream capabilities.
pub const ROUTE_ADMIN_STREAMING_IMPORT_STATUS: &str = "/api/v1/admin/streaming/imports/status";
/// `POST /api/v1/admin/streaming/imports/events` — bounded real-event JSON batch import.
pub const ROUTE_ADMIN_STREAMING_IMPORT_EVENTS: &str = "/api/v1/admin/streaming/imports/events";
/// `POST /api/v1/admin/streaming/imports/upstream-probe` — capability-aware upstream source check.
pub const ROUTE_ADMIN_STREAMING_IMPORT_UPSTREAM_PROBE: &str =
    "/api/v1/admin/streaming/imports/upstream-probe";
/// `GET` / `PUT /api/v1/admin/streaming/policies` — read or update `streaming_tracking_policies`.
pub const ROUTE_ADMIN_STREAMING_POLICIES: &str = "/api/v1/admin/streaming/policies";
/// `GET` / `PUT` / `DELETE /api/v1/admin/streaming/user-links` — explicit user identity links.
pub const ROUTE_ADMIN_STREAMING_USER_LINKS: &str = "/api/v1/admin/streaming/user-links";
/// `POST /api/v1/admin/streaming/reconciliation/preview` — read-only legacy reconciliation preview.
pub const ROUTE_ADMIN_STREAMING_RECONCILIATION_PREVIEW: &str =
    "/api/v1/admin/streaming/reconciliation/preview";
/// `POST /api/v1/admin/streaming/reconciliation/apply` — verified-backup, token-bound apply.
pub const ROUTE_ADMIN_STREAMING_RECONCILIATION_APPLY: &str =
    "/api/v1/admin/streaming/reconciliation/apply";

/// Maximum events accepted in a single bounded JSON import batch.
pub const MAX_IMPORT_BATCH_EVENTS: usize = 500;
/// Approval token validity window in seconds (15 minutes).
pub const RECONCILIATION_TOKEN_TTL_SECS: i64 = 900;

static RECONCILIATION_SIGNING_KEY: Lazy<[u8; 32]> = Lazy::new(|| {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
});

// ─────────────────────────────────────────────────────────────────────────────
// Error Contract
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamingImportError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl StreamingImportError {
    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: message.into(),
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "admin_required",
            message: message.into(),
        }
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: message.into(),
        }
    }

    pub fn unprocessable(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code,
            message: message.into(),
        }
    }

    pub fn unavailable(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "streaming_import_internal_error",
            message: message.into(),
        }
    }
}

impl From<rusqlite::Error> for StreamingImportError {
    fn from(error: rusqlite::Error) -> Self {
        tracing::error!(%error, "Streaming import/reconciliation SQLite error");
        Self::internal(format!("Database operation failed: {error}"))
    }
}

impl IntoResponse for StreamingImportError {
    fn into_response(self) -> Response {
        api_error(self.status, self.code, &self.message)
    }
}

pub type ImportResult<T> = Result<T, StreamingImportError>;

fn ensure_admin(user: &AuthUser) -> ImportResult<()> {
    if user.role == "admin" {
        Ok(())
    } else {
        Err(StreamingImportError::forbidden(
            "Administrative privileges are required for streaming import, policy, and reconciliation endpoints",
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Bounded Real-Event Import & Upstream Capability Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ImportStatusQuery {
    pub provider: String,
    pub server_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportCheckpointRecord {
    pub provider: String,
    pub server_id: String,
    pub source: String,
    pub checkpoint: String,
    pub imported: i64,
    pub last_error: Option<String>,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamEventCapability {
    pub provider: String,
    pub server_id: String,
    pub real_event_import_supported: bool,
    pub json_batch_import_supported: bool,
    pub upstream_direct_fetch_available: bool,
    pub upstream_endpoint_classification: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportStatusResponse {
    pub max_batch_events: usize,
    pub checkpoints: Vec<ImportCheckpointRecord>,
    pub capabilities: Vec<UpstreamEventCapability>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpstreamProbeRequest {
    pub provider: String,
    pub server_id: String,
    /// Optional upstream endpoint path or plugin identifier inspected by the caller
    /// (e.g. `"/Users/{id}/Items"`, `"/System/ActivityLog/Entries"`,
    /// `"/user_usage_stats/submit_custom_query"`).
    #[serde(default)]
    pub endpoint_path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportLabelInput {
    pub id: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ImportedEventInput {
    /// Stable event ID from the upstream event source (`source_event_id`).
    pub source_event_id: String,
    pub user_id: String,
    #[serde(default)]
    pub user_name: String,
    pub item_id: String,
    pub item_name: String,
    #[serde(default)]
    pub item_type: Option<String>,
    #[serde(default)]
    pub series_name: Option<String>,
    #[serde(default)]
    pub series_id: Option<String>,
    #[serde(default)]
    pub season_number: Option<i64>,
    #[serde(default)]
    pub episode_number: Option<i64>,
    #[serde(default)]
    pub production_year: Option<i64>,
    /// RFC3339 or SQL UTC (`YYYY-MM-DD HH:MM:SS`) playback start timestamp.
    pub started_at: String,
    /// Optional RFC3339 or SQL UTC playback end timestamp.
    #[serde(default)]
    pub ended_at: Option<String>,
    /// Confirmed watched duration in seconds (`>= 0`).
    #[serde(default)]
    pub watched_secs: Option<i64>,
    /// Media runtime duration in seconds (`> 0`).
    #[serde(default)]
    pub duration_secs: Option<i64>,
    /// Delivery method (`DirectPlay`, `DirectStream`, `Transcode`), or `None` if unrecorded.
    #[serde(default)]
    pub play_method: Option<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub container: Option<String>,
    #[serde(default)]
    pub video_codec: Option<String>,
    #[serde(default)]
    pub video_resolution: Option<String>,
    #[serde(default)]
    pub audio_codec: Option<String>,
    #[serde(default)]
    pub audio_channels: Option<i64>,
    #[serde(default)]
    pub subtitle_codec: Option<String>,
    #[serde(default)]
    pub hw_accel: Option<String>,
    #[serde(default)]
    pub bitrate_bps: Option<i64>,
    /// Optional estimated bytes. If omitted, `byte_accuracy` is stored as `'unrecorded'`.
    #[serde(default)]
    pub estimated_bytes: Option<i64>,
    #[serde(default)]
    pub libraries: Vec<ImportLabelInput>,
    #[serde(default)]
    pub genres: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ImportEventsBatchRequest {
    pub provider: String,
    pub server_id: String,
    #[serde(default)]
    pub server_name: Option<String>,
    pub source: String,
    /// Opaque resumable checkpoint token/cursor for `(provider, server_id, source)`.
    pub checkpoint: String,
    #[serde(default)]
    pub expected_checkpoint: Option<String>,
    pub events: Vec<ImportedEventInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportEventOutcome {
    pub source_event_id: String,
    pub history_id: i64,
    /// `"inserted"`, `"deduplicated_retry"`, `"duplicate_observed_overlap"`, or `"ambiguous_overlap"`.
    pub disposition: String,
    pub policy_status: String,
    pub matched_observed_ids: Vec<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportEventsBatchResponse {
    pub provider: String,
    pub server_id: String,
    pub source: String,
    pub checkpoint: String,
    pub batch_size: usize,
    pub inserted_included: usize,
    pub deduplicated_retries: usize,
    pub confirmed_overlap_duplicates: usize,
    pub ambiguous_overlaps: usize,
    pub cumulative_imported: i64,
    pub revision: i64,
    pub outcomes: Vec<ImportEventOutcome>,
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Tracking Policy & Explicit User-Link Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyScopeTarget {
    pub provider: String,
    pub server_id: String,
    pub id: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyScopeSemantics {
    pub minimum_watch_secs_effect: &'static str,
    pub excluded_users_effect: &'static str,
    pub excluded_libraries_effect: &'static str,
    pub reconnect_window_secs_effect: &'static str,
    pub raw_evidence_preserved: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrackingPolicyResponse {
    pub minimum_watch_secs: i64,
    pub reconnect_window_secs: i64,
    pub excluded_users: Vec<PolicyScopeTarget>,
    pub excluded_libraries: Vec<PolicyScopeTarget>,
    pub policy_revision: i64,
    pub history_revision: i64,
    pub semantics: PolicyScopeSemantics,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateTrackingPolicyRequest {
    pub minimum_watch_secs: i64,
    pub reconnect_window_secs: i64,
    #[serde(default)]
    pub excluded_users: Vec<PolicyScopeTarget>,
    #[serde(default)]
    pub excluded_libraries: Vec<PolicyScopeTarget>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StreamingUserLinkRecord {
    pub af_user_id: i64,
    pub af_username: Option<String>,
    pub provider: String,
    pub server_id: String,
    pub provider_user_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpsertStreamingUserLinkRequest {
    pub af_user_id: i64,
    pub provider: String,
    pub server_id: String,
    pub provider_user_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeleteStreamingUserLinkRequest {
    pub af_user_id: i64,
    pub provider: String,
    pub server_id: String,
    pub provider_user_id: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StreamingUserLinksResponse {
    pub links: Vec<StreamingUserLinkRecord>,
    pub history_revision: i64,
    pub identity_semantics: &'static str,
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Legacy Reconciliation Preview & Apply Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ReconciliationPreviewRequest {
    /// Optional subset of row IDs to inspect; if empty, inspects all candidate legacy rows.
    pub candidate_ids: Vec<i64>,
    /// Maximum candidate rows to include in a single preview (1..=1000, default 500).
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationRowState {
    pub id: i64,
    pub session_key: String,
    pub provider: String,
    pub server_id: String,
    pub source_event_id: Option<String>,
    pub user_id: String,
    pub user_name: String,
    pub item_id: String,
    pub item_name: String,
    pub item_type: String,
    pub play_method: String,
    pub client_name: String,
    pub device_name: String,
    pub device_id: String,
    pub ip_address: String,
    pub duration_secs: i64,
    pub watched_secs: i64,
    pub data_used_bytes: i64,
    pub bitrate_bps: i64,
    pub started_at: String,
    pub last_seen_at: String,
    pub ended_at: Option<String>,
    pub provenance: String,
    pub timestamp_certainty: String,
    pub byte_accuracy: String,
    pub policy_status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationFieldChange {
    pub field: String,
    pub before: String,
    pub after: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationRowChange {
    pub id: i64,
    pub session_key: String,
    pub classification: String,
    pub row_fingerprint: String,
    pub before: ReconciliationRowState,
    pub after: ReconciliationRowState,
    pub changes: Vec<ReconciliationFieldChange>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationPreviewResponse {
    pub preview_hash: String,
    pub approval_token: String,
    pub actor_id: i64,
    pub history_revision: i64,
    pub issued_at: String,
    pub expires_at: String,
    pub total_affected_rows: usize,
    pub counts_before: HistoryCounts,
    pub counts_after: HistoryCounts,
    pub affected_rows: Vec<ReconciliationRowChange>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReconciliationApplyRequest {
    pub preview_hash: String,
    pub approval_token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationApplyResponse {
    pub audit_id: i64,
    pub preview_hash: String,
    pub applied_rows: usize,
    pub backup_path: Option<String>,
    pub history_revision: i64,
    pub counts_before: HistoryCounts,
    pub counts_after: HistoryCounts,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SignedApprovalTokenPayload {
    version: u8,
    actor_id: i64,
    preview_hash: String,
    history_revision: i64,
    history_rows: i64,
    candidate_ids: Vec<i64>,
    issued_at: i64,
    expires_at: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation & Normalization Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn normalize_provider(raw: &str) -> ImportResult<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if matches!(normalized.as_str(), "jellyfin" | "emby") {
        Ok(normalized)
    } else {
        Err(StreamingImportError::bad_request(
            "invalid_provider",
            "provider must be 'jellyfin' or 'emby'",
        ))
    }
}

fn normalize_nonempty_token(
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

fn normalize_optional_text(raw: &Option<String>, max_len: usize) -> ImportResult<String> {
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

fn normalize_play_method(raw: &Option<String>) -> ImportResult<String> {
    let Some(value) = raw else {
        return Ok(String::new());
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    match trimmed
        .to_ascii_lowercase()
        .replace([' ', '_'], "")
        .as_str()
    {
        "directplay" => Ok("DirectPlay".to_string()),
        "directstream" => Ok("DirectStream".to_string()),
        "transcode" => Ok("Transcode".to_string()),
        "unknown" => Ok(String::new()),
        _ => Err(StreamingImportError::bad_request(
            "invalid_play_method",
            "playMethod must be DirectPlay, DirectStream, Transcode, or omitted when unrecorded",
        )),
    }
}

fn normalize_media_type(raw: &Option<String>) -> ImportResult<String> {
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
        "audio" => Ok("Audio".to_string()),
        "video" => Ok("Video".to_string()),
        "unknown" => Ok(String::new()),
        _ => Err(StreamingImportError::bad_request(
            "invalid_media_type",
            "itemType must be Movie, Episode, Audio, Video, or omitted when unrecorded",
        )),
    }
}

/// Parses an RFC3339 timestamp or SQL UTC timestamp (`YYYY-MM-DD HH:MM:SS`) into `(sql_utc, unix_secs)`.
fn parse_event_timestamp(raw: &str, field: &'static str) -> ImportResult<(String, i64)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(StreamingImportError::bad_request(
            "invalid_timestamp",
            format!("{field} is required for real playback events"),
        ));
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

fn current_history_revision(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT revision FROM streaming_history_revision WHERE id = 1",
        [],
        |row| row.get(0),
    )
}

fn bump_history_revision(conn: &Connection) -> rusqlite::Result<i64> {
    conn.execute(
        "UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1",
        [],
    )?;
    current_history_revision(conn)
}

fn record_admin_audit(
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

// ─────────────────────────────────────────────────────────────────────────────
// 1. Upstream Capability Probe & Import Checkpoints Core
// ─────────────────────────────────────────────────────────────────────────────

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

    let (classification, reason) = if lower_path.contains("/users/")
        && lower_path.contains("/items")
    {
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
         WHERE lower(trim(provider)) IN ('jellyfin', 'emby')",
    )?;
    let configured_servers = server_stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for pair in configured_servers.flatten() {
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
        _ => {
            if provider == "jellyfin" {
                "Jellyfin".to_string()
            } else {
                "Emby".to_string()
            }
        }
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
                Some(w) if w < 0 || w > 86_400 * 7 => {
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

// ─────────────────────────────────────────────────────────────────────────────
// 2. Tracking Policy & Explicit User-Link Mapping Core
// ─────────────────────────────────────────────────────────────────────────────

const POLICY_SEMANTICS: PolicyScopeSemantics = PolicyScopeSemantics {
    minimum_watch_secs_effect: "Applies dynamically to analytical inclusion of observed_session and imported_event rows (COALESCE(watched_secs, 0) >= minimum_watch_secs). Item summaries and raw stored rows are never deleted.",
    excluded_users_effect: "Excludes matching (provider, serverId, userId) rows from standard analytics and included cohorts while preserving raw rows for admin includeExcluded inspection.",
    excluded_libraries_effect: "Excludes rows tagged in streaming_history_labels with matching (provider, serverId, libraryId) from standard analytics while preserving raw rows.",
    reconnect_window_secs_effect: "Configures the session-continuity window (0..=300s) used to merge/classify brief collector disconnects and imported event overlap windows.",
    raw_evidence_preserved: true,
};

fn normalize_policy_targets(
    raw: Vec<PolicyScopeTarget>,
    field: &'static str,
) -> ImportResult<Vec<PolicyScopeTarget>> {
    if raw.len() > 500 {
        return Err(StreamingImportError::bad_request(
            "policy_targets_too_large",
            format!("{field} cannot exceed 500 entries"),
        ));
    }
    let mut dedup: BTreeMap<(String, String, String), PolicyScopeTarget> = BTreeMap::new();
    for item in raw {
        let provider = normalize_provider(&item.provider)?;
        let server_id = normalize_nonempty_token(&item.server_id, "serverId", 128)?;
        let id = normalize_nonempty_token(&item.id, "id", 128)?;
        let name = if item.name.trim().is_empty() {
            id.clone()
        } else {
            normalize_nonempty_token(&item.name, "name", 256)?
        };
        dedup.insert(
            (provider.clone(), server_id.clone(), id.clone()),
            PolicyScopeTarget {
                provider,
                server_id,
                id,
                name,
            },
        );
    }
    Ok(dedup.into_values().collect())
}

pub fn get_tracking_policy(
    conn: &Connection,
    user: &AuthUser,
) -> ImportResult<TrackingPolicyResponse> {
    ensure_admin(user)?;
    let (min_watch, excluded_users_json, excluded_libs_json, reconnect_window, policy_rev): (
        i64,
        String,
        String,
        i64,
        i64,
    ) = conn.query_row(
        "SELECT minimum_watch_secs, excluded_users, excluded_libraries, reconnect_window_secs, revision
         FROM streaming_tracking_policies
         WHERE id = 1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let excluded_users: Vec<PolicyScopeTarget> =
        serde_json::from_str(&excluded_users_json).unwrap_or_default();
    let excluded_libraries: Vec<PolicyScopeTarget> =
        serde_json::from_str(&excluded_libs_json).unwrap_or_default();
    let history_revision = current_history_revision(conn)?;

    Ok(TrackingPolicyResponse {
        minimum_watch_secs: min_watch,
        reconnect_window_secs: reconnect_window,
        excluded_users,
        excluded_libraries,
        policy_revision: policy_rev,
        history_revision,
        semantics: POLICY_SEMANTICS,
    })
}

pub fn update_tracking_policy(
    conn: &Connection,
    request: UpdateTrackingPolicyRequest,
    user: &AuthUser,
) -> ImportResult<TrackingPolicyResponse> {
    ensure_admin(user)?;
    if !(0..=86_400).contains(&request.minimum_watch_secs) {
        return Err(StreamingImportError::bad_request(
            "invalid_minimum_watch_secs",
            "minimumWatchSecs must be between 0 and 86400",
        ));
    }
    if !(0..=300).contains(&request.reconnect_window_secs) {
        return Err(StreamingImportError::bad_request(
            "invalid_reconnect_window_secs",
            "reconnectWindowSecs must be between 0 and 300",
        ));
    }
    let excluded_users = normalize_policy_targets(request.excluded_users, "excludedUsers")?;
    let excluded_libraries =
        normalize_policy_targets(request.excluded_libraries, "excludedLibraries")?;

    let excluded_users_json = serde_json::to_string(&excluded_users)
        .map_err(|e| StreamingImportError::internal(e.to_string()))?;
    let excluded_libraries_json = serde_json::to_string(&excluded_libraries)
        .map_err(|e| StreamingImportError::internal(e.to_string()))?;

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let res = (|| -> ImportResult<()> {
        conn.execute(
            "UPDATE streaming_tracking_policies
             SET minimum_watch_secs = ?1,
                 excluded_users = ?2,
                 excluded_libraries = ?3,
                 reconnect_window_secs = ?4,
                 revision = revision + 1
             WHERE id = 1",
            params![
                request.minimum_watch_secs,
                excluded_users_json,
                excluded_libraries_json,
                request.reconnect_window_secs
            ],
        )?;
        record_admin_audit(
            conn,
            user,
            "streaming.policy.update",
            "streaming_tracking_policies",
            "1",
            &format!(
                "min_watch={} reconnect={} excluded_users={} excluded_libraries={}",
                request.minimum_watch_secs,
                request.reconnect_window_secs,
                excluded_users.len(),
                excluded_libraries.len()
            ),
        )?;
        Ok(())
    })();
    match res {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }

    get_tracking_policy(conn, user)
}

pub fn list_user_links(
    conn: &Connection,
    user: &AuthUser,
) -> ImportResult<StreamingUserLinksResponse> {
    ensure_admin(user)?;
    let mut stmt = conn.prepare(
        "SELECT l.af_user_id, u.username, l.provider, l.server_id, l.provider_user_id
         FROM streaming_user_links l
         LEFT JOIN users u ON u.id = l.af_user_id
         ORDER BY l.af_user_id ASC, l.provider ASC, l.server_id ASC, l.provider_user_id ASC",
    )?;
    let links: Vec<StreamingUserLinkRecord> = stmt
        .query_map([], |row| {
            Ok(StreamingUserLinkRecord {
                af_user_id: row.get(0)?,
                af_username: row.get(1)?,
                provider: row.get(2)?,
                server_id: row.get(3)?,
                provider_user_id: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    let history_revision = current_history_revision(conn)?;

    Ok(StreamingUserLinksResponse {
        links,
        history_revision,
        identity_semantics: "Non-admin users can view only rows matching an explicit (af_user_id, provider, server_id, provider_user_id) link; display names are never used for implicit matching.",
    })
}

pub fn upsert_user_link(
    conn: &Connection,
    request: UpsertStreamingUserLinkRequest,
    user: &AuthUser,
) -> ImportResult<StreamingUserLinksResponse> {
    ensure_admin(user)?;
    if request.af_user_id <= 0 {
        return Err(StreamingImportError::bad_request(
            "invalid_af_user_id",
            "afUserId must be a positive user ID",
        ));
    }
    let provider = normalize_provider(&request.provider)?;
    let server_id = normalize_nonempty_token(&request.server_id, "serverId", 128)?;
    let provider_user_id =
        normalize_nonempty_token(&request.provider_user_id, "providerUserId", 128)?;

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let res = (|| -> ImportResult<()> {
        let user_exists: Option<i64> = conn
            .query_row(
                "SELECT id FROM users WHERE id = ?1",
                params![request.af_user_id],
                |row| row.get(0),
            )
            .optional()?;
        if user_exists.is_none() {
            return Err(StreamingImportError::bad_request(
                "unknown_af_user",
                format!("AetherFlow user id={} does not exist", request.af_user_id),
            ));
        }
        conn.execute(
            "INSERT INTO streaming_user_links (af_user_id, provider, server_id, provider_user_id)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(af_user_id, provider, server_id, provider_user_id) DO NOTHING",
            params![request.af_user_id, provider, server_id, provider_user_id],
        )?;
        record_admin_audit(
            conn,
            user,
            "streaming.user_link.upsert",
            "streaming_user_links",
            &format!(
                "{}:{}:{}:{}",
                request.af_user_id, provider, server_id, provider_user_id
            ),
            "Explicit streaming provider identity link configured",
        )?;
        Ok(())
    })();
    match res {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }

    list_user_links(conn, user)
}

pub fn delete_user_link(
    conn: &Connection,
    request: DeleteStreamingUserLinkRequest,
    user: &AuthUser,
) -> ImportResult<StreamingUserLinksResponse> {
    ensure_admin(user)?;
    let provider = normalize_provider(&request.provider)?;
    let server_id = normalize_nonempty_token(&request.server_id, "serverId", 128)?;
    let provider_user_id =
        normalize_nonempty_token(&request.provider_user_id, "providerUserId", 128)?;

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let res = (|| -> ImportResult<()> {
        conn.execute(
            "DELETE FROM streaming_user_links
             WHERE af_user_id = ?1 AND provider = ?2 AND server_id = ?3 AND provider_user_id = ?4",
            params![request.af_user_id, provider, server_id, provider_user_id],
        )?;
        record_admin_audit(
            conn,
            user,
            "streaming.user_link.delete",
            "streaming_user_links",
            &format!(
                "{}:{}:{}:{}",
                request.af_user_id, provider, server_id, provider_user_id
            ),
            "Explicit streaming provider identity link removed",
        )?;
        Ok(())
    })();
    match res {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }

    list_user_links(conn, user)
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Guarded Legacy Reconciliation Preview & Apply Core
// ─────────────────────────────────────────────────────────────────────────────

fn hash_row_state(state: &ReconciliationRowState) -> String {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(state).expect("serializable ReconciliationRowState"));
    hex::encode(hasher.finalize())
}

fn compute_preview_hash(
    history_revision: i64,
    history_rows: i64,
    rows: &[ReconciliationRowChange],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("rev:{history_revision}|").as_bytes());
    hasher.update(format!("rows:{history_rows}|").as_bytes());
    for row in rows {
        hasher.update(serde_json::to_vec(row).expect("serializable ReconciliationRowChange"));
        hasher.update(b"|");
    }
    hex::encode(hasher.finalize())
}

fn sign_approval_token(payload: &SignedApprovalTokenPayload) -> String {
    let bytes = serde_json::to_vec(payload).expect("serializable SignedApprovalTokenPayload");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&*RECONCILIATION_SIGNING_KEY).expect("32-byte HMAC key");
    mac.update(&bytes);
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&bytes),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn verify_approval_token(
    token: &str,
    expected_actor_id: i64,
    expected_preview_hash: &str,
    now: i64,
) -> ImportResult<SignedApprovalTokenPayload> {
    if token.len() > 16_384 {
        return Err(StreamingImportError::bad_request(
            "invalid_approval_token",
            "approvalToken exceeds maximum length",
        ));
    }
    let (encoded_payload, encoded_sig) = token.split_once('.').ok_or_else(|| {
        StreamingImportError::bad_request("invalid_approval_token", "Malformed approvalToken")
    })?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(encoded_payload).map_err(|_| {
        StreamingImportError::bad_request("invalid_approval_token", "Malformed approvalToken")
    })?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(encoded_sig).map_err(|_| {
        StreamingImportError::bad_request("invalid_approval_token", "Malformed approvalToken")
    })?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&*RECONCILIATION_SIGNING_KEY).expect("32-byte HMAC key");
    mac.update(&payload_bytes);
    mac.verify_slice(&sig_bytes).map_err(|_| {
        StreamingImportError::bad_request(
            "invalid_approval_token_signature",
            "approvalToken signature verification failed",
        )
    })?;
    let payload: SignedApprovalTokenPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| {
            StreamingImportError::bad_request("invalid_approval_token", "Malformed approvalToken")
        })?;
    if payload.version != 1 {
        return Err(StreamingImportError::bad_request(
            "invalid_approval_token",
            "Unsupported approvalToken version",
        ));
    }
    if payload.actor_id != expected_actor_id {
        return Err(StreamingImportError::forbidden(
            "approvalToken was issued to a different administrator",
        ));
    }
    if payload.preview_hash != expected_preview_hash {
        return Err(StreamingImportError::bad_request(
            "preview_hash_mismatch",
            "previewHash does not match the signed approvalToken",
        ));
    }
    if now >= payload.expires_at {
        return Err(StreamingImportError::conflict(
            "approval_token_expired",
            "Reconciliation approvalToken has expired; generate a fresh preview",
        ));
    }
    Ok(payload)
}

fn read_reconciliation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReconciliationRowState> {
    Ok(ReconciliationRowState {
        id: row.get(0)?,
        session_key: row.get(1)?,
        provider: row.get(2)?,
        server_id: row.get(3)?,
        source_event_id: row.get(4)?,
        user_id: row.get(5)?,
        user_name: row.get(6)?,
        item_id: row.get(7)?,
        item_name: row.get(8)?,
        item_type: row.get(9)?,
        play_method: row.get(10)?,
        client_name: row.get(11)?,
        device_name: row.get(12)?,
        device_id: row.get(13)?,
        ip_address: row.get(14)?,
        duration_secs: row.get(15)?,
        watched_secs: row.get(16)?,
        data_used_bytes: row.get(17)?,
        bitrate_bps: row.get(18)?,
        started_at: row.get(19)?,
        last_seen_at: row.get(20)?,
        ended_at: row.get(21)?,
        provenance: row.get(22)?,
        timestamp_certainty: row.get(23)?,
        byte_accuracy: row.get(24)?,
        policy_status: row.get(25)?,
    })
}

fn propose_reconciliation_for_row(
    before: &ReconciliationRowState,
) -> Option<ReconciliationRowChange> {
    if before.provenance != "legacy_unverified" {
        return None;
    }

    let mut after = before.clone();
    let mut changes = Vec::new();
    let mut classifications = Vec::new();

    let is_sync_summary =
        before.session_key.contains(":sync:") || before.session_key.starts_with("sync:");
    let has_epoch_timestamp = before.started_at.trim().starts_with("1970-01-01");
    let has_empty_timestamp = before.started_at.trim().is_empty();
    let no_session_telemetry = before.client_name.trim().is_empty()
        && before.device_name.trim().is_empty()
        && before.device_id.trim().is_empty()
        && before.ip_address.trim().is_empty();

    if is_sync_summary {
        classifications.push("legacy_sync_item_summary");
        after.provenance = "item_summary".to_string();
        changes.push(ReconciliationFieldChange {
            field: "provenance".to_string(),
            before: before.provenance.clone(),
            after: after.provenance.clone(),
            reason: "Session key resembles an old item-summary sync; key shape alone does not establish provenance".to_string(),
        });

        let target_ts_certainty = if has_epoch_timestamp || has_empty_timestamp {
            "unrecorded"
        } else {
            before.timestamp_certainty.as_str()
        };
        if after.timestamp_certainty != target_ts_certainty {
            changes.push(ReconciliationFieldChange {
                field: "timestampCertainty".to_string(),
                before: before.timestamp_certainty.clone(),
                after: target_ts_certainty.to_string(),
                reason: "Historical summary timestamp certainty is unverified".to_string(),
            });
            after.timestamp_certainty = target_ts_certainty.to_string();
        }

        if has_epoch_timestamp {
            after.started_at = String::new();
            changes.push(ReconciliationFieldChange {
                field: "startedAt".to_string(),
                before: before.started_at.clone(),
                after: String::new(),
                reason: "Cleared synthetic 1970-01-01 epoch fallback timestamp".to_string(),
            });
        }

        if no_session_telemetry && !before.play_method.trim().is_empty() {
            after.play_method = String::new();
            changes.push(ReconciliationFieldChange {
                field: "playMethod".to_string(),
                before: before.play_method.clone(),
                after: String::new(),
                reason: "Cleared default play_method on item summary row with no session client/device telemetry".to_string(),
            });
        }

        if before.data_used_bytes != 0 || before.byte_accuracy != "unrecorded" {
            after.data_used_bytes = 0;
            after.byte_accuracy = "unrecorded".to_string();
            changes.push(ReconciliationFieldChange {
                field: "dataUsedBytes".to_string(),
                before: format!("{} ({})", before.data_used_bytes, before.byte_accuracy),
                after: "0 (unrecorded)".to_string(),
                reason: "Item summaries do not carry per-session transfer byte measurements"
                    .to_string(),
            });
        }
    } else {
        if has_epoch_timestamp {
            classifications.push("legacy_epoch_timestamp");
            after.started_at = String::new();
            after.timestamp_certainty = "unrecorded".to_string();
            changes.push(ReconciliationFieldChange {
                field: "startedAt".to_string(),
                before: before.started_at.clone(),
                after: String::new(),
                reason: "Cleared synthetic 1970-01-01 epoch fallback timestamp".to_string(),
            });
            changes.push(ReconciliationFieldChange {
                field: "timestampCertainty".to_string(),
                before: before.timestamp_certainty.clone(),
                after: "unrecorded".to_string(),
                reason: "Timestamp was synthetic epoch fallback".to_string(),
            });
        } else if has_empty_timestamp && before.timestamp_certainty != "unrecorded" {
            classifications.push("legacy_missing_timestamp");
            after.timestamp_certainty = "unrecorded".to_string();
            changes.push(ReconciliationFieldChange {
                field: "timestampCertainty".to_string(),
                before: before.timestamp_certainty.clone(),
                after: "unrecorded".to_string(),
                reason: "Empty started_at marked as unrecorded timestamp certainty".to_string(),
            });
        }

        // Check for unverified or implausibly inflated byte counters on legacy rows
        if before.data_used_bytes > 0 && before.byte_accuracy == "legacy_unverified" {
            let implausible_bytes = if before.watched_secs <= 0 || before.bitrate_bps <= 0 {
                true
            } else {
                let expected = (before.watched_secs as i128) * ((before.bitrate_bps as i128) / 8);
                (before.data_used_bytes as i128) > expected.saturating_mul(4)
            };
            if implausible_bytes {
                classifications.push("legacy_inflated_bytes");
                after.data_used_bytes = 0;
                after.byte_accuracy = "unrecorded".to_string();
                changes.push(ReconciliationFieldChange {
                    field: "dataUsedBytes".to_string(),
                    before: format!("{} ({})", before.data_used_bytes, before.byte_accuracy),
                    after: "0 (unrecorded)".to_string(),
                    reason: "Cleared legacy unverified byte total lacking supporting bitrate/watch-time evidence".to_string(),
                });
            }
        }
    }

    if changes.is_empty() {
        return None;
    }

    let classification = if classifications.is_empty() {
        "suspected_legacy_reconciliation".to_string()
    } else {
        format!("suspected_{}", classifications.join("+suspected_"))
    };
    for change in &mut changes {
        change.reason = format!(
            "Unverified proposal requiring source review: {}",
            change.reason
        );
    }

    Some(ReconciliationRowChange {
        id: before.id,
        session_key: before.session_key.clone(),
        classification,
        row_fingerprint: hash_row_state(before),
        before: before.clone(),
        after,
        changes,
    })
}

fn collect_reconciliation_candidates(
    conn: &Connection,
    candidate_ids: &[i64],
    limit: usize,
) -> ImportResult<Vec<ReconciliationRowChange>> {
    let base_select = "SELECT id, session_key, provider, server_id, source_event_id,
                              user_id, user_name, item_id, item_name, item_type,
                              play_method, client_name, device_name, device_id, ip_address,
                              COALESCE(duration_secs, 0), COALESCE(watched_secs, 0),
                              COALESCE(data_used_bytes, 0), COALESCE(bitrate_bps, 0),
                              COALESCE(started_at, ''), COALESCE(last_seen_at, ''), ended_at,
                              provenance, timestamp_certainty, byte_accuracy, policy_status
                       FROM streaming_history
                       WHERE provenance = 'legacy_unverified'
                       ORDER BY id ASC";
    let filter_set: Option<BTreeSet<i64>> = if candidate_ids.is_empty() {
        None
    } else {
        Some(candidate_ids.iter().copied().collect())
    };

    let mut stmt = conn.prepare(base_select)?;
    let rows = stmt.query_map([], read_reconciliation_row)?;

    let mut proposed = Vec::new();
    for row in rows {
        let state = row?;
        if let Some(ref set) = filter_set {
            if !set.contains(&state.id) {
                continue;
            }
        }
        if let Some(change) = propose_reconciliation_for_row(&state) {
            proposed.push(change);
            if proposed.len() >= limit {
                break;
            }
        }
    }
    Ok(proposed)
}

fn compute_canonical_counts(
    conn: &Connection,
    user: &AuthUser,
    now: i64,
) -> ImportResult<HistoryCounts> {
    let (query, watermark, _revision, as_of) =
        resolve_query_scope(conn, HistoryQuery::default(), user, now).map_err(|e| {
            StreamingImportError::internal(format!(
                "Failed to resolve canonical history scope: {}",
                e.message
            ))
        })?;
    let (mut clauses, mut values) = scope_filters(&query, user, watermark);
    let base_clauses = clauses.clone();
    let base_values = values.clone();
    query_filters(&query, as_of, &mut clauses, &mut values).map_err(|e| {
        StreamingImportError::internal(format!(
            "Failed to build canonical history filters: {}",
            e.message
        ))
    })?;
    let from_history = "FROM streaming_history h CROSS JOIN streaming_tracking_policies p";
    let available: i64 = conn.query_row(
        &format!(
            "SELECT COUNT(*) {from_history} WHERE {}",
            base_clauses.join(" AND ")
        ),
        params_from_iter(&base_values),
        |row| row.get(0),
    )?;
    let inc = inclusion_predicate();
    let confirmed = format!("({inc}) AND h.provenance IN ('observed_session','imported_event')");
    let sql = format!(
        "SELECT COUNT(*),
                COALESCE(SUM(h.event_unix IS NULL),0),
                COALESCE(SUM(CASE WHEN {confirmed} THEN 1 ELSE 0 END),0),
                COALESCE(SUM(h.provenance = 'item_summary'),0),
                COALESCE(SUM(h.provenance = 'legacy_unverified'),0),
                COALESCE(SUM(CASE WHEN {confirmed} THEN MAX(COALESCE(h.watched_secs,0),0) ELSE 0 END),0),
                COALESCE(SUM(CASE WHEN {confirmed} AND h.byte_accuracy = 'estimated' THEN MAX(COALESCE(h.data_used_bytes,0),0) ELSE 0 END),0)
         {from_history} WHERE {}",
        clauses.join(" AND ")
    );
    let mut counts = conn.query_row(&sql, params_from_iter(&values), |row| {
        Ok(HistoryCounts {
            available_records: 0,
            matching_records: row.get(0)?,
            undated_records: row.get(1)?,
            confirmed_plays: row.get(2)?,
            item_summaries: row.get(3)?,
            legacy_records: row.get(4)?,
            watch_time_secs: row.get(5)?,
            estimated_bytes: row.get(6)?,
        })
    })?;
    counts.available_records = available;
    Ok(counts)
}

fn compute_projected_counts(
    conn: &Connection,
    user: &AuthUser,
    now: i64,
    proposed: &[ReconciliationRowChange],
) -> ImportResult<(HistoryCounts, HistoryCounts)> {
    let counts_before = compute_canonical_counts(conn, user, now)?;
    conn.execute_batch("SAVEPOINT streaming_count_projection")?;
    let projected = (|| -> ImportResult<HistoryCounts> {
        for change in proposed {
            let after = &change.after;
            conn.execute("UPDATE streaming_history SET server_id=?1,play_method=?2,data_used_bytes=?3,started_at=?4,provenance=?5,timestamp_certainty=?6,byte_accuracy=?7,policy_status=?8 WHERE id=?9 AND provenance='legacy_unverified'", params![after.server_id, after.play_method, after.data_used_bytes, after.started_at, after.provenance, after.timestamp_certainty, after.byte_accuracy, after.policy_status, change.id])?;
        }
        compute_canonical_counts(conn, user, now)
    })();
    conn.execute_batch(
        "ROLLBACK TO streaming_count_projection; RELEASE streaming_count_projection",
    )?;
    let counts_after = projected?;

    Ok((counts_before, counts_after))
}

/// Generates a read-only legacy reconciliation preview and a signed 15-minute approval token
/// bound to `user.user_id`, `history_revision`, and the exact per-row state fingerprints.
pub fn preview_legacy_reconciliation(
    conn: &Connection,
    request: ReconciliationPreviewRequest,
    user: &AuthUser,
    now: i64,
) -> ImportResult<ReconciliationPreviewResponse> {
    ensure_admin(user)?;
    let _transaction = conn.unchecked_transaction()?;
    let limit = request.limit.unwrap_or(500);
    if !(1..=1000).contains(&limit) {
        return Err(StreamingImportError::bad_request(
            "invalid_preview_limit",
            "limit must be between 1 and 1000",
        ));
    }

    let history_revision = current_history_revision(conn)?;
    let history_rows: i64 =
        conn.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| {
            row.get(0)
        })?;
    let affected_rows = collect_reconciliation_candidates(conn, &request.candidate_ids, limit)?;
    let preview_hash = compute_preview_hash(history_revision, history_rows, &affected_rows);
    let candidate_ids: Vec<i64> = affected_rows.iter().map(|r| r.id).collect();
    let expires_at_unix = now + RECONCILIATION_TOKEN_TTL_SECS;

    let approval_token = sign_approval_token(&SignedApprovalTokenPayload {
        version: 1,
        actor_id: user.user_id,
        preview_hash: preview_hash.clone(),
        history_revision,
        history_rows,
        candidate_ids,
        issued_at: now,
        expires_at: expires_at_unix,
    });

    let (counts_before, counts_after) = compute_projected_counts(conn, user, now, &affected_rows)?;

    let issued_at = DateTime::from_timestamp(now, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339();
    let expires_at = DateTime::from_timestamp(expires_at_unix, 0)
        .unwrap_or_else(Utc::now)
        .to_rfc3339();

    Ok(ReconciliationPreviewResponse {
        preview_hash,
        approval_token,
        actor_id: user.user_id,
        history_revision,
        issued_at,
        expires_at,
        total_affected_rows: affected_rows.len(),
        counts_before,
        counts_after,
        affected_rows,
    })
}

/// Applies a previously previewed legacy reconciliation after:
/// 1. Verifying the admin actor and HMAC-signed `approval_token` + `preview_hash`,
/// 2. Creating and verifying a consistent SQLite backup (`af_db::streaming::verified_backup`)
///    before beginning the write transaction,
/// 3. Opening a `BEGIN IMMEDIATE` transaction, re-verifying `streaming_history_revision` and
///    every candidate row's exact fingerprint against `preview_hash`,
/// 4. Applying only the approved updates and writing a full before/after JSON audit entry to
///    `streaming_history_audit`.
pub fn apply_legacy_reconciliation_with_db_path(
    conn: &Connection,
    db_path: &str,
    request: ReconciliationApplyRequest,
    user: &AuthUser,
    now: i64,
) -> ImportResult<ReconciliationApplyResponse> {
    ensure_admin(user)?;
    let token_payload = verify_approval_token(
        &request.approval_token,
        user.user_id,
        &request.preview_hash,
        now,
    )?;
    if token_payload.candidate_ids.is_empty() {
        return Err(StreamingImportError::bad_request(
            "no_reconciliation_changes",
            "Preview contains no approved changes",
        ));
    }

    // Fast pre-check before running expensive VACUUM INTO backup: verify revision hasn't drifted.
    let pre_revision = current_history_revision(conn)?;
    let pre_rows: i64 = conn.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| {
        row.get(0)
    })?;
    if pre_revision != token_payload.history_revision || pre_rows != token_payload.history_rows {
        return Err(StreamingImportError::conflict(
            "reconciliation_stale",
            "Streaming history changed since the preview was generated; run preview again",
        ));
    }

    // Verified backup before mutating any rows.
    let backup_path_buf = af_db::streaming::verified_backup(conn, db_path).map_err(|err| {
        StreamingImportError::unavailable(
            "backup_verification_failed",
            format!(
                "Refusing to apply legacy reconciliation without a verified SQLite backup: {err}"
            ),
        )
    })?;
    let backup_path = Some(
        backup_path_buf
            .ok_or_else(|| {
                StreamingImportError::conflict(
                    "streaming_backup_required",
                    "Legacy reconciliation requires a verified on-disk SQLite backup",
                )
            })?
            .to_string_lossy()
            .into_owned(),
    );

    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> ImportResult<ReconciliationApplyResponse> {
        let current_rev = current_history_revision(conn)?;
        let current_rows: i64 =
            conn.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| {
                row.get(0)
            })?;
        if current_rev != token_payload.history_revision
            || current_rows != token_payload.history_rows
        {
            return Err(StreamingImportError::conflict(
                "reconciliation_stale",
                "Streaming history revision changed before reconciliation lock was acquired",
            ));
        }

        // Recompute candidate changes inside the IMMEDIATE transaction and verify exact hash match.
        let limit = token_payload.candidate_ids.len().max(1);
        let current_candidates =
            collect_reconciliation_candidates(conn, &token_payload.candidate_ids, limit)?;
        if current_candidates.len() != token_payload.candidate_ids.len() {
            return Err(StreamingImportError::conflict(
                "reconciliation_stale",
                "Candidate row set changed since the preview was generated",
            ));
        }

        let recomputed_hash = compute_preview_hash(current_rev, current_rows, &current_candidates);
        if recomputed_hash != request.preview_hash {
            return Err(StreamingImportError::conflict(
                "reconciliation_stale",
                "One or more candidate rows changed since the preview was generated",
            ));
        }

        let (counts_before, _) = compute_projected_counts(conn, user, now, &current_candidates)?;

        let before_states: Vec<&ReconciliationRowState> =
            current_candidates.iter().map(|c| &c.before).collect();
        let after_states: Vec<&ReconciliationRowState> =
            current_candidates.iter().map(|c| &c.after).collect();
        let before_json = serde_json::to_string(&before_states)
            .map_err(|e| StreamingImportError::internal(e.to_string()))?;
        let after_json = serde_json::to_string(&after_states)
            .map_err(|e| StreamingImportError::internal(e.to_string()))?;

        for row_change in &current_candidates {
            let after = &row_change.after;
            let updated = conn.execute(
                "UPDATE streaming_history
                 SET server_id = ?1,
                     play_method = ?2,
                     data_used_bytes = ?3,
                     started_at = ?4,
                     provenance = ?5,
                     timestamp_certainty = ?6,
                     byte_accuracy = ?7,
                     policy_status = ?8
                 WHERE id = ?9 AND provenance = 'legacy_unverified'",
                params![
                    after.server_id,
                    after.play_method,
                    after.data_used_bytes,
                    after.started_at,
                    after.provenance,
                    after.timestamp_certainty,
                    after.byte_accuracy,
                    after.policy_status,
                    row_change.id,
                ],
            )?;
            if updated != 1 {
                return Err(StreamingImportError::conflict(
                    "reconciliation_stale",
                    format!("Row id={} could not be updated as expected", row_change.id),
                ));
            }
        }

        let created_at = DateTime::from_timestamp(now, 0)
            .unwrap_or_else(Utc::now)
            .to_rfc3339();
        conn.execute(
            "INSERT INTO streaming_history_audit (
                actor_id, operation, preview_hash, before_json, after_json, created_at
             ) VALUES (?1, 'legacy_reconciliation', ?2, ?3, ?4, ?5)",
            params![
                user.user_id,
                request.preview_hash,
                before_json,
                after_json,
                created_at
            ],
        )?;
        let audit_id = conn.last_insert_rowid();

        let counts_after = compute_canonical_counts(conn, user, now)?;
        let history_revision = current_history_revision(conn)?;

        record_admin_audit(
            conn,
            user,
            "streaming.reconciliation.apply",
            "streaming_history_audit",
            &audit_id.to_string(),
            &format!(
                "preview_hash={} applied_rows={} backup={}",
                request.preview_hash,
                current_candidates.len(),
                backup_path.as_deref().unwrap_or("in-memory")
            ),
        )?;

        Ok(ReconciliationApplyResponse {
            audit_id,
            preview_hash: request.preview_hash,
            applied_rows: current_candidates.len(),
            backup_path,
            history_revision,
            counts_before,
            counts_after,
            created_at,
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

// ─────────────────────────────────────────────────────────────────────────────
// Axum HTTP Handlers (Admin-Only)
// ─────────────────────────────────────────────────────────────────────────────

fn acquire_pool_conn(
    user: &AuthUser,
) -> ImportResult<r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>> {
    ensure_admin(user)?;
    af_db::get_conn().map_err(|_| {
        StreamingImportError::unavailable(
            "streaming_db_unavailable",
            "Streaming history database is temporarily unavailable",
        )
    })
}

/// `GET /api/v1/admin/streaming/imports/status`
pub async fn get_streaming_import_status_handler(
    Query(query): Query<ImportStatusQuery>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        get_import_status(&conn, query, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("Import status task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `POST /api/v1/admin/streaming/imports/upstream-probe`
pub async fn probe_upstream_event_source_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<UpstreamProbeRequest>,
) -> Response {
    if let Err(err) = ensure_admin(&user) {
        return err.into_response();
    }
    match evaluate_upstream_capability(
        &request.provider,
        &request.server_id,
        &request.endpoint_path,
    ) {
        Ok(cap) => ([(header::CACHE_CONTROL, "no-store")], Json(cap)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `POST /api/v1/admin/streaming/imports/events`
pub async fn import_streaming_events_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<ImportEventsBatchRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        import_events_batch(&conn, request, &user, Utc::now().timestamp())
    })
    .await
    .map_err(|_| StreamingImportError::internal("Event import task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `GET /api/v1/admin/streaming/policies`
pub async fn get_streaming_policy_handler(Extension(user): Extension<AuthUser>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        get_tracking_policy(&conn, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("Get policy task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `PUT /api/v1/admin/streaming/policies`
pub async fn update_streaming_policy_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<UpdateTrackingPolicyRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        update_tracking_policy(&conn, request, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("Update policy task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `GET /api/v1/admin/streaming/user-links`
pub async fn list_streaming_user_links_handler(Extension(user): Extension<AuthUser>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        list_user_links(&conn, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("List user links task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `PUT /api/v1/admin/streaming/user-links`
pub async fn upsert_streaming_user_link_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<UpsertStreamingUserLinkRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        upsert_user_link(&conn, request, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("Upsert user link task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `DELETE /api/v1/admin/streaming/user-links`
pub async fn delete_streaming_user_link_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<DeleteStreamingUserLinkRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        delete_user_link(&conn, request, &user)
    })
    .await
    .map_err(|_| StreamingImportError::internal("Delete user link task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `POST /api/v1/admin/streaming/reconciliation/preview`
pub async fn preview_legacy_reconciliation_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<ReconciliationPreviewRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        preview_legacy_reconciliation(&conn, request, &user, Utc::now().timestamp())
    })
    .await
    .map_err(|_| StreamingImportError::internal("Reconciliation preview task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `POST /api/v1/admin/streaming/reconciliation/apply`
pub async fn apply_legacy_reconciliation_handler(
    Extension(user): Extension<AuthUser>,
    Json(request): Json<ReconciliationApplyRequest>,
) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let conn = acquire_pool_conn(&user)?;
        let db_path = af_db::get_db_path();
        apply_legacy_reconciliation_with_db_path(
            &conn,
            &db_path,
            request,
            &user,
            Utc::now().timestamp(),
        )
    })
    .await
    .map_err(|_| StreamingImportError::internal("Reconciliation apply task panicked"))
    .and_then(|r| r);

    match result {
        Ok(body) => ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response(),
        Err(err) => err.into_response(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal Unit Tests (Isolated in-memory + disposable temp file SQLite v19+v20)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming_history::{query_history, HistoryQuery};

    const V19_STREAMING_DDL: &str = r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE schema_versions (
            version INTEGER PRIMARY KEY,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            description TEXT
        );
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE admin_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL DEFAULT '',
            target_id TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE streaming_servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL DEFAULT 'Jellyfin',
            url TEXT NOT NULL DEFAULT 'http://127.0.0.1:8096',
            api_key TEXT NOT NULL DEFAULT '',
            enabled BOOLEAN DEFAULT 1,
            server_id TEXT DEFAULT '',
            server_version TEXT DEFAULT '',
            last_connected_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE streaming_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_key TEXT UNIQUE NOT NULL,
            provider TEXT NOT NULL DEFAULT 'jellyfin',
            server_name TEXT NOT NULL DEFAULT 'Jellyfin',
            user_id TEXT NOT NULL DEFAULT '',
            user_name TEXT NOT NULL DEFAULT '',
            client_name TEXT NOT NULL DEFAULT '',
            device_name TEXT NOT NULL DEFAULT '',
            device_id TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            item_id TEXT NOT NULL DEFAULT '',
            item_name TEXT NOT NULL DEFAULT '',
            item_type TEXT NOT NULL DEFAULT 'Movie',
            series_name TEXT NOT NULL DEFAULT '',
            series_id TEXT NOT NULL DEFAULT '',
            season_number INTEGER DEFAULT 0,
            episode_number INTEGER DEFAULT 0,
            production_year INTEGER DEFAULT 0,
            play_method TEXT NOT NULL DEFAULT 'DirectPlay',
            container TEXT NOT NULL DEFAULT '',
            video_codec TEXT NOT NULL DEFAULT '',
            video_resolution TEXT NOT NULL DEFAULT '',
            audio_codec TEXT NOT NULL DEFAULT '',
            audio_channels INTEGER DEFAULT 0,
            subtitle_codec TEXT NOT NULL DEFAULT '',
            hw_accel TEXT NOT NULL DEFAULT '',
            transcode_reasons TEXT NOT NULL DEFAULT '',
            bitrate_bps INTEGER DEFAULT 0,
            duration_secs INTEGER DEFAULT 0,
            watched_secs INTEGER DEFAULT 0,
            data_used_bytes INTEGER DEFAULT 0,
            completion_pct REAL DEFAULT 0,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            ended_at DATETIME,
            is_active BOOLEAN DEFAULT 0
        );
        INSERT INTO schema_versions(version, description) VALUES (19, 'Streaming analytics');
    "#;

    const V20_MIGRATION_SQL: &str =
        include_str!("../../af-db/src/migrations/020_streaming_history.sql");

    fn setup_isolated_db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory SQLite");
        conn.execute_batch(V19_STREAMING_DDL).expect("v19 DDL");
        conn.execute_batch(V20_MIGRATION_SQL).expect("v20 DDL");
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'alice', 'user'), (3, 'bob', 'user')",
            [],
        )
        .expect("seed users");
        conn.execute(
            "INSERT INTO streaming_servers (provider, name, server_id) VALUES ('jellyfin', 'Main Jellyfin', 'srv-main')",
            [],
        )
        .expect("seed streaming_servers");
        conn
    }

    fn admin_user() -> AuthUser {
        AuthUser {
            user_id: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            jti: "jti-admin-1".to_string(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }
    }

    fn alice_user() -> AuthUser {
        AuthUser {
            user_id: 2,
            username: "alice".to_string(),
            role: "user".to_string(),
            jti: "jti-user-2".to_string(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn http_handlers_deny_nonadmin_before_database_or_body_access() {
        let user = alice_user();
        let responses = [
            get_streaming_import_status_handler(
                Query(ImportStatusQuery::default()),
                Extension(user.clone()),
            )
            .await,
            get_streaming_policy_handler(Extension(user.clone())).await,
            list_streaming_user_links_handler(Extension(user.clone())).await,
            apply_legacy_reconciliation_handler(
                Extension(user.clone()),
                Json(ReconciliationApplyRequest {
                    preview_hash: "not-approved".to_string(),
                    approval_token: "not-approved".to_string(),
                }),
            )
            .await,
            crate::streaming_portability::export_handler(Extension(user.clone())).await,
            crate::streaming_portability::preview_handler(
                Extension(user.clone()),
                axum::http::Request::new(axum::body::Body::empty()),
            )
            .await,
            crate::streaming_portability::restore_handler(
                Extension(user),
                axum::http::Request::new(axum::body::Body::empty()),
            )
            .await,
        ];
        for response in responses {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
    }

    fn sample_event(source_event_id: &str, started_at: &str) -> ImportedEventInput {
        ImportedEventInput {
            source_event_id: source_event_id.to_string(),
            user_id: "jf-alice".to_string(),
            user_name: "Alice".to_string(),
            item_id: "item-dune".to_string(),
            item_name: "Dune: Part Two".to_string(),
            item_type: Some("Movie".to_string()),
            series_name: None,
            series_id: None,
            season_number: None,
            episode_number: None,
            production_year: Some(2024),
            started_at: started_at.to_string(),
            ended_at: Some("2026-03-01T21:00:00Z".to_string()),
            watched_secs: Some(3600),
            duration_secs: Some(9900),
            play_method: None, // unknown stays unknown!
            client_name: None,
            device_name: None,
            device_id: None,
            ip_address: None,
            container: None,
            video_codec: None,
            video_resolution: None,
            audio_codec: None,
            audio_channels: None,
            subtitle_codec: None,
            hw_accel: None,
            bitrate_bps: None,
            estimated_bytes: None,
            libraries: vec![ImportLabelInput {
                id: "lib-movies".to_string(),
                name: "Movies".to_string(),
            }],
            genres: vec!["Sci-Fi".to_string()],
        }
    }

    #[test]
    fn checkpoint_compare_and_swap_and_feed_namespaces_prevent_stale_retries() {
        let conn = setup_isolated_db();
        let admin = admin_user();
        let now = 1_772_400_000_i64;
        let first_batch = ImportEventsBatchRequest {
            provider: "jellyfin".to_string(),
            server_id: "srv-main".to_string(),
            server_name: None,
            source: "feed-one".to_string(),
            checkpoint: "batch-one".to_string(),
            expected_checkpoint: None,
            events: vec![sample_event("shared-id", "2026-03-01T20:00:00Z")],
        };
        import_events_batch(&conn, first_batch.clone(), &admin, now).unwrap();
        let retry = import_events_batch(&conn, first_batch.clone(), &admin, now).unwrap();
        assert_eq!(retry.deduplicated_retries, 1);
        let mut reused_checkpoint = first_batch.clone();
        reused_checkpoint
            .events
            .push(sample_event("unexpected-id", "2026-03-01T21:00:00Z"));
        for expected_checkpoint in [
            None,
            Some("batch-one".to_string()),
            Some("stale".to_string()),
        ] {
            reused_checkpoint.expected_checkpoint = expected_checkpoint;
            let error =
                import_events_batch(&conn, reused_checkpoint.clone(), &admin, now).unwrap_err();
            assert_eq!(error.code, "import_checkpoint_reused");
        }
        let mut second_batch = first_batch.clone();
        second_batch.checkpoint = "batch-two".to_string();
        second_batch.expected_checkpoint = Some("batch-one".to_string());
        second_batch.events[0].source_event_id = "another-id".to_string();
        second_batch.events[0].user_id = "other-viewer".to_string();
        import_events_batch(&conn, second_batch, &admin, now + 1).unwrap();
        let stale = import_events_batch(&conn, first_batch.clone(), &admin, now + 2).unwrap_err();
        assert_eq!(stale.code, "import_checkpoint_changed");
        let mut other_feed = first_batch;
        other_feed.source = "feed-two".to_string();
        other_feed.events[0].user_id = "third-viewer".to_string();
        let imported = import_events_batch(&conn, other_feed, &admin, now + 3).unwrap();
        assert_eq!(imported.deduplicated_retries, 0);
        assert_eq!(imported.inserted_included, 1);
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT source_event_id) FROM streaming_history",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);
        let checkpoint: String = conn
            .query_row(
                "SELECT checkpoint FROM streaming_import_checkpoints WHERE source = 'feed-one'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(checkpoint, "batch-two");
    }

    #[test]
    fn cross_source_overlaps_are_ambiguous_with_zero_reconnect_window() {
        let conn = setup_isolated_db();
        let admin = admin_user();
        conn.execute(
            "UPDATE streaming_tracking_policies SET reconnect_window_secs=0 WHERE id=1",
            [],
        )
        .unwrap();
        let mut batch = ImportEventsBatchRequest {
            provider: "jellyfin".to_string(),
            server_id: "srv-main".to_string(),
            server_name: None,
            source: "feed-one".to_string(),
            checkpoint: "batch-one".to_string(),
            expected_checkpoint: None,
            events: vec![sample_event("event-one", "2026-03-01T20:00:00Z")],
        };
        import_events_batch(&conn, batch.clone(), &admin, 1_772_400_000).unwrap();
        batch.source = "feed-two".to_string();
        let response = import_events_batch(&conn, batch, &admin, 1_772_400_001).unwrap();
        assert_eq!(response.inserted_included, 0);
        assert_eq!(response.ambiguous_overlaps, 1);
        let included: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM streaming_history WHERE policy_status='included'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(included, 1);
    }

    #[test]
    fn reconciliation_requires_a_real_disk_backup() {
        let conn = setup_isolated_db();
        let admin = admin_user();
        conn.execute("INSERT INTO streaming_history(session_key,started_at) VALUES ('jellyfin:sync:old:item','1970-01-01 00:00:00')", []).unwrap();
        let revision = current_history_revision(&conn).unwrap();
        let preview = preview_legacy_reconciliation(
            &conn,
            ReconciliationPreviewRequest::default(),
            &admin,
            1000,
        )
        .unwrap();
        let error = apply_legacy_reconciliation_with_db_path(
            &conn,
            ":memory:",
            ReconciliationApplyRequest {
                preview_hash: preview.preview_hash,
                approval_token: preview.approval_token,
            },
            &admin,
            1001,
        )
        .unwrap_err();
        assert_eq!(error.code, "streaming_backup_required");
        assert_eq!(current_history_revision(&conn).unwrap(), revision);
        let provenance: String = conn
            .query_row("SELECT provenance FROM streaming_history", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(provenance, "legacy_unverified");
    }

    #[test]
    fn reconciliation_rejects_insert_only_drift_without_invalidating_archive_watermarks() {
        let conn = setup_isolated_db();
        let admin = admin_user();
        let now = 1_772_400_000_i64;
        conn.execute("INSERT INTO streaming_history(session_key, started_at) VALUES ('jellyfin:sync:legacy-user:legacy-item', '1970-01-01 00:00:00')", []).unwrap();
        let preview = preview_legacy_reconciliation(
            &conn,
            ReconciliationPreviewRequest::default(),
            &admin,
            now,
        )
        .unwrap();
        assert_eq!(preview.total_affected_rows, 1);
        conn.execute("INSERT INTO streaming_history(session_key, provenance, started_at) VALUES ('new-observed-evidence', 'observed_session', '2026-03-01 20:00:00')", []).unwrap();
        assert_eq!(
            current_history_revision(&conn).unwrap(),
            preview.history_revision
        );
        let error = apply_legacy_reconciliation_with_db_path(
            &conn,
            ":memory:",
            ReconciliationApplyRequest {
                preview_hash: preview.preview_hash,
                approval_token: preview.approval_token,
            },
            &admin,
            now + 1,
        )
        .unwrap_err();
        assert_eq!(error.code, "reconciliation_stale");
        let provenance: String = conn.query_row("SELECT provenance FROM streaming_history WHERE session_key = 'jellyfin:sync:legacy-user:legacy-item'", [], |row| row.get(0)).unwrap();
        assert_eq!(provenance, "legacy_unverified");
    }

    #[test]
    fn event_import_idempotent_retry_checkpoint_and_unknown_details_preserved() {
        let conn = setup_isolated_db();
        let admin = admin_user();
        let now = 1_772_400_000_i64;

        let req = ImportEventsBatchRequest {
            provider: "jellyfin".to_string(),
            server_id: "srv-main".to_string(),
            server_name: Some("Main Jellyfin".to_string()),
            source: "playback_reporting_export".to_string(),
            checkpoint: "cursor-batch-1".to_string(),
            expected_checkpoint: None,
            events: vec![sample_event("evt-1001", "2026-03-01T20:00:00Z")],
        };

        let first = import_events_batch(&conn, req.clone(), &admin, now).expect("first import");
        assert_eq!(first.inserted_included, 1);
        assert_eq!(first.deduplicated_retries, 0);
        assert_eq!(first.cumulative_imported, 1);

        // Retrying the exact same event with a new checkpoint must deduplicate without double counting
        let mut retry_req = req;
        retry_req.expected_checkpoint = Some(retry_req.checkpoint.clone());
        retry_req.checkpoint = "cursor-batch-1-retry".to_string();
        let second = import_events_batch(&conn, retry_req, &admin, now + 10).expect("retry import");
        assert_eq!(second.inserted_included, 0);
        assert_eq!(second.deduplicated_retries, 1);
        assert_eq!(second.cumulative_imported, 1);

        // Verify canonical history query surfaces the event with unknown playMethod/client/device/estimatedBytes as None
        let page = query_history(&conn, HistoryQuery::default(), &admin, now + 20)
            .expect("canonical history query");
        assert_eq!(page.counts.confirmed_plays, 1);
        assert_eq!(page.counts.watch_time_secs, 3600);
        assert_eq!(page.counts.estimated_bytes, 0);
        assert_eq!(page.items.len(), 1);
        let item = &page.items[0];
        assert_eq!(item.provenance, "imported_event");
        assert_eq!(item.timestamp_certainty, "source_event");
        assert_eq!(item.byte_accuracy, "unrecorded");
        assert_eq!(item.play_method, None);
        assert_eq!(item.client_name, None);
        assert_eq!(item.device_name, None);
        assert_eq!(item.estimated_bytes, None);
        assert_eq!(item.library_ids, vec!["lib-movies".to_string()]);
        assert_eq!(item.genres, vec!["Sci-Fi".to_string()]);

        // Verify checkpoint status endpoint contract
        let status =
            get_import_status(&conn, ImportStatusQuery::default(), &admin).expect("import status");
        assert_eq!(status.checkpoints.len(), 1);
        assert_eq!(status.checkpoints[0].checkpoint, "cursor-batch-1-retry");
        assert_eq!(status.checkpoints[0].imported, 1);
        assert!(!status.capabilities[0].upstream_direct_fetch_available);
    }

    #[test]
    fn confirmed_overlap_deduplicates_while_ambiguous_overlap_and_concurrent_sessions_stay_conservative(
    ) {
        let conn = setup_isolated_db();
        let admin = admin_user();
        let now = 1_772_400_000_i64;

        // 1. Seed a completed observed_session for Alice watching item-dune from 20:00:00 to 21:00:00
        conn.execute(
            "INSERT INTO streaming_history (
                session_key, provider, server_id, user_id, user_name, client_name, device_name,
                item_id, item_name, item_type, play_method, watched_secs, duration_secs,
                started_at, last_seen_at, ended_at, is_active,
                provenance, timestamp_certainty, byte_accuracy, policy_status
             ) VALUES (
                'jf:srv-main:obs-1', 'jellyfin', 'srv-main', 'jf-alice', 'Alice', 'Jellyfin Web', 'Firefox',
                'item-dune', 'Dune: Part Two', 'Movie', 'DirectPlay', 3580, 9900,
                '2026-03-01 20:00:10', '2026-03-01 21:00:05', '2026-03-01 21:00:05', 0,
                'observed_session', 'observed', 'estimated', 'included'
             )",
            [],
        )
        .expect("insert observed_session 1");

        // 2. Seed an observed_session with a pause/poll gap or conflicting client for item-arrival
        conn.execute(
            "INSERT INTO streaming_history (
                session_key, provider, server_id, user_id, user_name, client_name, device_name,
                item_id, item_name, item_type, play_method, watched_secs, duration_secs,
                started_at, last_seen_at, ended_at, is_active,
                provenance, timestamp_certainty, byte_accuracy, policy_status
             ) VALUES (
                'jf:srv-main:obs-2', 'jellyfin', 'srv-main', 'jf-alice', 'Alice', 'Swiftfin', 'Apple TV',
                'item-arrival', 'Arrival', 'Movie', 'DirectPlay', 1800, 6960,
                '2026-03-01 22:00:00', '2026-03-01 22:30:00', '2026-03-01 22:30:00', 0,
                'observed_session', 'observed', 'estimated', 'included'
             )",
            [],
        )
        .expect("insert observed_session 2");

        let mut confirmed_dup_evt = sample_event("evt-dup-1", "2026-03-01T20:00:00Z");
        confirmed_dup_evt.client_name = Some("Jellyfin Web".to_string());
        confirmed_dup_evt.device_name = Some("Firefox".to_string());

        // Ambiguous overlap: same user+item+window as obs-2, but conflicting client ("Infuse" vs "Swiftfin")
        let mut ambiguous_evt = sample_event("evt-ambig-1", "2026-03-01T22:00:15Z");
        ambiguous_evt.item_id = "item-arrival".to_string();
        ambiguous_evt.item_name = "Arrival".to_string();
        ambiguous_evt.ended_at = Some("2026-03-01T22:30:10Z".to_string());
        ambiguous_evt.watched_secs = Some(1800);
        ambiguous_evt.client_name = Some("Infuse".to_string());
        ambiguous_evt.device_name = Some("iPad".to_string());

        // Repeat play of item-dune 3 hours later (no overlap) -> must be included as a separate play!
        let mut repeat_play_evt = sample_event("evt-repeat-1", "2026-03-02T00:30:00Z");
        repeat_play_evt.ended_at = Some("2026-03-02T01:30:00Z".to_string());

        let batch = ImportEventsBatchRequest {
            provider: "jellyfin".to_string(),
            server_id: "srv-main".to_string(),
            server_name: None,
            source: "playback_reporting_export".to_string(),
            checkpoint: "cp-overlap".to_string(),
            expected_checkpoint: None,
            events: vec![confirmed_dup_evt, ambiguous_evt, repeat_play_evt],
        };

        let resp = import_events_batch(&conn, batch, &admin, now).expect("import overlap batch");
        assert_eq!(resp.confirmed_overlap_duplicates, 1);
        assert_eq!(resp.ambiguous_overlaps, 1);
        assert_eq!(resp.inserted_included, 1);

        // Confirmed plays count: 2 original observed_sessions + 1 non-overlapping repeat play = 3.
        // Neither the confirmed duplicate nor the ambiguous overlap is double-counted in confirmed_plays!
        let page = query_history(&conn, HistoryQuery::default(), &admin, now + 5)
            .expect("query included history");
        assert_eq!(page.counts.confirmed_plays, 3);
        assert_eq!(page.counts.matching_records, 3);

        // Admin with include_excluded = true can inspect all 5 records including duplicate and ambiguous
        let all_page = query_history(
            &conn,
            HistoryQuery {
                include_excluded: true,
                ..HistoryQuery::default()
            },
            &admin,
            now + 5,
        )
        .expect("query with includeExcluded");
        assert_eq!(all_page.counts.matching_records, 5);
    }

    #[test]
    fn policies_and_explicit_user_links_control_cohorts_and_privacy() {
        let conn = setup_isolated_db();
        let admin = admin_user();
        let alice = alice_user();
        let now = 1_772_400_000_i64;

        // Import two events: one for jf-alice (3600s, lib-movies) and one for jf-bob (120s, lib-kids)
        let mut bob_evt = sample_event("evt-bob-1", "2026-03-01T18:00:00Z");
        bob_evt.user_id = "jf-bob".to_string();
        bob_evt.user_name = "Alice".to_string(); // Display name intentionally collides with "Alice"!
        bob_evt.watched_secs = Some(120);
        bob_evt.ended_at = Some("2026-03-01T18:02:00Z".to_string());
        bob_evt.libraries = vec![ImportLabelInput {
            id: "lib-kids".to_string(),
            name: "Kids".to_string(),
        }];

        import_events_batch(
            &conn,
            ImportEventsBatchRequest {
                provider: "jellyfin".to_string(),
                server_id: "srv-main".to_string(),
                server_name: None,
                source: "verified_json".to_string(),
                checkpoint: "cp-1".to_string(),
                expected_checkpoint: None,
                events: vec![sample_event("evt-alice-1", "2026-03-01T20:00:00Z"), bob_evt],
            },
            &admin,
            now,
        )
        .expect("import alice and bob");

        // Before linking Alice's account, Alice sees 0 records even though bob's display name is "Alice"
        let alice_unlinked =
            query_history(&conn, HistoryQuery::default(), &alice, now + 1).expect("unlinked query");
        assert_eq!(alice_unlinked.counts.matching_records, 0);

        // Link Alice (af_user_id=2) explicitly to ('jellyfin', 'srv-main', 'jf-alice')
        upsert_user_link(
            &conn,
            UpsertStreamingUserLinkRequest {
                af_user_id: 2,
                provider: "jellyfin".to_string(),
                server_id: "srv-main".to_string(),
                provider_user_id: "jf-alice".to_string(),
            },
            &admin,
        )
        .expect("link alice");

        let alice_linked =
            query_history(&conn, HistoryQuery::default(), &alice, now + 2).expect("linked query");
        assert_eq!(alice_linked.counts.matching_records, 1);
        assert_eq!(alice_linked.items[0].user_id, "jf-alice");

        // Update tracking policy: minimum_watch_secs = 300 excludes bob's 120s play from standard analytics
        let policy_resp = update_tracking_policy(
            &conn,
            UpdateTrackingPolicyRequest {
                minimum_watch_secs: 300,
                reconnect_window_secs: 60,
                excluded_users: Vec::new(),
                excluded_libraries: Vec::new(),
            },
            &admin,
        )
        .expect("update policy min watch");
        assert_eq!(policy_resp.minimum_watch_secs, 300);

        let admin_filtered =
            query_history(&conn, HistoryQuery::default(), &admin, now + 3).expect("admin query");
        assert_eq!(admin_filtered.counts.confirmed_plays, 1);

        // Excluding library 'lib-movies' excludes Alice's movie from standard analytics while preserving raw row
        update_tracking_policy(
            &conn,
            UpdateTrackingPolicyRequest {
                minimum_watch_secs: 0,
                reconnect_window_secs: 60,
                excluded_users: Vec::new(),
                excluded_libraries: vec![PolicyScopeTarget {
                    provider: "jellyfin".to_string(),
                    server_id: "srv-main".to_string(),
                    id: "lib-movies".to_string(),
                    name: "Movies".to_string(),
                }],
            },
            &admin,
        )
        .expect("exclude library");

        let after_lib_exclude =
            query_history(&conn, HistoryQuery::default(), &admin, now + 4).expect("after exclude");
        assert_eq!(after_lib_exclude.counts.confirmed_plays, 1); // only bob's lib-kids remains
        assert_eq!(after_lib_exclude.items[0].user_id, "jf-bob");
    }

    #[test]
    fn legacy_reconciliation_preview_is_conservative_and_apply_requires_backup_and_fresh_state() {
        // Use a disposable temporary file SQLite database so `verified_backup` (VACUUM INTO) is exercised!
        let temp_dir = std::env::temp_dir().join(format!(
            "af-streaming-reconcile-test-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&temp_dir).expect("create temp test dir");
        let db_file = temp_dir.join("test-reconcile.sqlite");
        let db_path = db_file.to_string_lossy().into_owned();

        let conn = Connection::open(&db_file).expect("open temp file sqlite");
        conn.execute_batch(V19_STREAMING_DDL).expect("v19 DDL");
        conn.execute_batch(V20_MIGRATION_SQL).expect("v20 DDL");
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'alice', 'user')",
            [],
        )
        .expect("seed users");
        conn.execute(
            "INSERT INTO streaming_servers (provider, name, server_id) VALUES ('jellyfin', 'Main Jellyfin', 'srv-main')",
            [],
        )
        .expect("seed server");

        // Row 1: Legacy pre-migration `:sync:` item summary with synthetic 1970 timestamp, default DirectPlay, and inflated bytes
        conn.execute(
            "INSERT INTO streaming_history (
                id, session_key, provider, server_id, user_id, user_name,
                client_name, device_name, item_id, item_name, item_type, play_method,
                watched_secs, duration_secs, data_used_bytes, started_at, last_seen_at,
                provenance, timestamp_certainty, byte_accuracy, policy_status
             ) VALUES (
                10, 'jellyfin:sync:u1:item-1', 'jellyfin', '', 'jf-alice', 'Alice',
                '', '', 'item-1', 'Legacy Synced Movie', 'Movie', 'DirectPlay',
                7200, 7200, 999999999, '1970-01-01 00:00:00', '2026-02-01 12:00:00',
                'legacy_unverified', 'legacy_unverified', 'legacy_unverified', 'included'
             )",
            [],
        )
        .expect("seed legacy sync row");

        // Row 2: Legitimate legacy row with real client/device and valid timestamp + DirectPlay/Movie
        // MUST NOT be falsely flagged just because play_method='DirectPlay' and item_type='Movie'!
        conn.execute(
            "INSERT INTO streaming_history (
                id, session_key, provider, server_id, user_id, user_name,
                client_name, device_name, item_id, item_name, item_type, play_method,
                watched_secs, duration_secs, data_used_bytes, bitrate_bps, started_at, last_seen_at,
                provenance, timestamp_certainty, byte_accuracy, policy_status
             ) VALUES (
                11, 'jellyfin:live:session-99', 'jellyfin', 'srv-main', 'jf-alice', 'Alice',
                'Jellyfin Media Player', 'Desktop-PC', 'item-2', 'Valid Legacy Movie', 'Movie', 'DirectPlay',
                3600, 7200, 0, 8000000, '2026-02-15 20:00:00', '2026-02-15 21:00:00',
                'legacy_unverified', 'legacy_unverified', 'legacy_unverified', 'included'
             )",
            [],
        )
        .expect("seed valid legacy row");

        let admin = admin_user();
        let alice = alice_user();
        let now = 1_772_400_000_i64;

        // Non-admin must be rejected
        let non_admin_err = preview_legacy_reconciliation(
            &conn,
            ReconciliationPreviewRequest::default(),
            &alice,
            now,
        )
        .unwrap_err();
        assert_eq!(non_admin_err.status, StatusCode::FORBIDDEN);

        // Preview identifies ONLY Row 10, leaving Row 11 untouched
        let preview = preview_legacy_reconciliation(
            &conn,
            ReconciliationPreviewRequest::default(),
            &admin,
            now,
        )
        .expect("preview reconciliation");
        assert_eq!(preview.total_affected_rows, 1);
        assert_eq!(preview.affected_rows[0].id, 10);
        assert_eq!(preview.affected_rows[0].after.provenance, "item_summary");
        assert_eq!(
            preview.affected_rows[0].after.timestamp_certainty,
            "unrecorded"
        );
        assert_eq!(preview.affected_rows[0].after.started_at, "");
        assert_eq!(preview.affected_rows[0].after.play_method, "");
        assert_eq!(preview.affected_rows[0].after.data_used_bytes, 0);
        assert_eq!(preview.affected_rows[0].after.byte_accuracy, "unrecorded");
        assert_eq!(preview.affected_rows[0].after.server_id, "");
        assert!(preview.affected_rows[0]
            .classification
            .starts_with("suspected_"));
        assert!(preview.affected_rows[0]
            .changes
            .iter()
            .all(|change| change.reason.starts_with("Unverified proposal")));
        assert_eq!(preview.counts_before.legacy_records, 2);
        assert_eq!(preview.counts_after.legacy_records, 1);
        assert_eq!(preview.counts_after.item_summaries, 1);

        // Verify backup failure aborts apply before any mutation (e.g. invalid file: URI path)
        let backup_fail = apply_legacy_reconciliation_with_db_path(
            &conn,
            "file:///invalid-uri-for-backup",
            ReconciliationApplyRequest {
                preview_hash: preview.preview_hash.clone(),
                approval_token: preview.approval_token.clone(),
            },
            &admin,
            now + 5,
        )
        .unwrap_err();
        assert_eq!(backup_fail.status, StatusCode::SERVICE_UNAVAILABLE);

        // Verify expired token is rejected
        let expired_err = apply_legacy_reconciliation_with_db_path(
            &conn,
            &db_path,
            ReconciliationApplyRequest {
                preview_hash: preview.preview_hash.clone(),
                approval_token: preview.approval_token.clone(),
            },
            &admin,
            now + RECONCILIATION_TOKEN_TTL_SECS + 1,
        )
        .unwrap_err();
        assert_eq!(expired_err.status, StatusCode::CONFLICT);
        assert_eq!(expired_err.code, "approval_token_expired");

        // Apply with valid token and real file-backed DB path -> creates verified backup, updates row 10, writes audit
        let applied = apply_legacy_reconciliation_with_db_path(
            &conn,
            &db_path,
            ReconciliationApplyRequest {
                preview_hash: preview.preview_hash.clone(),
                approval_token: preview.approval_token.clone(),
            },
            &admin,
            now + 10,
        )
        .expect("apply reconciliation");
        assert_eq!(applied.applied_rows, 1);
        assert!(applied.backup_path.is_some());
        assert_eq!(applied.counts_after.legacy_records, 1);
        assert_eq!(applied.counts_after.item_summaries, 1);

        // Re-applying the same preview token now fails with 409 Conflict (stale revision/state)
        let replay_err = apply_legacy_reconciliation_with_db_path(
            &conn,
            &db_path,
            ReconciliationApplyRequest {
                preview_hash: preview.preview_hash,
                approval_token: preview.approval_token,
            },
            &admin,
            now + 15,
        )
        .unwrap_err();
        assert_eq!(replay_err.status, StatusCode::CONFLICT);
        assert_eq!(replay_err.code, "reconciliation_stale");

        // Verify streaming_history_audit row was recorded with before and after JSON
        let (op, before_json, after_json): (String, String, String) = conn
            .query_row(
                "SELECT operation, before_json, after_json FROM streaming_history_audit WHERE id = ?1",
                params![applied.audit_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("audit record");
        assert_eq!(op, "legacy_reconciliation");
        assert!(before_json.contains("legacy_unverified"));
        assert!(after_json.contains("item_summary"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn atomic_batch_rollback_and_upstream_capability_rejection() {
        let conn = setup_isolated_db();
        let admin = admin_user();
        let now = 1_772_400_000_i64;

        // 1. Upstream capability probe must classify /Users/{id}/Items as item_summary_only
        // and /System/ActivityLog/Entries as activity_log_insufficient
        let summary_cap =
            evaluate_upstream_capability("jellyfin", "srv-main", "/Users/u1/Items").unwrap();
        assert_eq!(
            summary_cap.upstream_endpoint_classification,
            "item_summary_only"
        );
        assert!(!summary_cap.upstream_direct_fetch_available);

        let activity_cap =
            evaluate_upstream_capability("jellyfin", "srv-main", "/System/ActivityLog/Entries")
                .unwrap();
        assert_eq!(
            activity_cap.upstream_endpoint_classification,
            "activity_log_insufficient"
        );
        assert!(!activity_cap.upstream_direct_fetch_available);

        // 2. Attempting to import an item_summary source via the event import endpoint is rejected
        let summary_source_err = import_events_batch(
            &conn,
            ImportEventsBatchRequest {
                provider: "jellyfin".to_string(),
                server_id: "srv-main".to_string(),
                server_name: None,
                source: "jellyfin_item_summary_sync".to_string(),
                checkpoint: "cp-bad".to_string(),
                expected_checkpoint: None,
                events: vec![sample_event("evt-1", "2026-03-01T20:00:00Z")],
            },
            &admin,
            now,
        )
        .unwrap_err();
        assert_eq!(summary_source_err.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(summary_source_err.code, "summary_source_forbidden");

        // 3. Multi-event batch where second event has invalid timestamp rolls back the entire batch
        let valid_first = sample_event("evt-valid-1", "2026-03-01T20:00:00Z");
        let mut invalid_second = sample_event("evt-invalid-2", "1970-01-01T00:00:00Z");
        invalid_second.ended_at = None;

        let batch_err = import_events_batch(
            &conn,
            ImportEventsBatchRequest {
                provider: "jellyfin".to_string(),
                server_id: "srv-main".to_string(),
                server_name: None,
                source: "playback_reporting_export".to_string(),
                checkpoint: "cp-atomic-fail".to_string(),
                expected_checkpoint: None,
                events: vec![valid_first, invalid_second],
            },
            &admin,
            now,
        )
        .unwrap_err();
        assert_eq!(batch_err.status, StatusCode::BAD_REQUEST);

        let history_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM streaming_history", [], |r| r.get(0))
            .unwrap();
        assert_eq!(history_count, 0, "first event must be rolled back");

        let cp_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM streaming_import_checkpoints",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(cp_count, 0, "checkpoint must not advance on failed batch");

        // 4. Recording checkpoint error stores last_error without touching streaming_history
        record_import_checkpoint_error(
            &conn,
            "jellyfin",
            "srv-main",
            "playback_reporting_export",
            "Malformed upstream export payload at line 42",
            now + 5,
        )
        .expect("record checkpoint error");

        let status =
            get_import_status(&conn, ImportStatusQuery::default(), &admin).expect("status");
        assert_eq!(status.checkpoints.len(), 1);
        assert_eq!(
            status.checkpoints[0].last_error.as_deref(),
            Some("Malformed upstream export payload at line 42")
        );
    }
}
