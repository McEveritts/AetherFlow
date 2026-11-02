#![allow(dead_code)]

use crate::auth::AuthUser;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path as AxumPath, Query};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::McBrowserError;

pub(super) const MAX_EVENTS_BODY_BYTES: usize = 16_384;
pub(super) const DEFAULT_AUDIT_LIST_LIMIT: usize = 100;
pub(super) const MAX_AUDIT_LIST_LIMIT: usize = 500;
pub(super) const DEFAULT_QUEUE_LIST_LIMIT: usize = 100;
pub(super) const MAX_QUEUE_LIST_LIMIT: usize = 500;
pub(super) const MAX_FAILURE_REASON_BYTES: usize = 512;
pub(super) const MAX_USERNAME_BYTES: usize = 255;

const STAGING_DIR_SEGMENT: &str = ".af-upload-staging";
const STAGING_TMP_PREFIX: &str = ".af-upload-tmp.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum McBrowserEventTrigger {
    UploadCompleted,
    EntryDeleted,
    FileSaved,
    EntryCopied,
    EntryRenamed,
    ShareCreated,
    ShareRevoked,
}

impl McBrowserEventTrigger {
    pub(super) const ALL: [Self; 7] = [
        Self::UploadCompleted,
        Self::EntryDeleted,
        Self::FileSaved,
        Self::EntryCopied,
        Self::EntryRenamed,
        Self::ShareCreated,
        Self::ShareRevoked,
    ];

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::UploadCompleted => "upload_completed",
            Self::EntryDeleted => "entry_deleted",
            Self::FileSaved => "file_saved",
            Self::EntryCopied => "entry_copied",
            Self::EntryRenamed => "entry_renamed",
            Self::ShareCreated => "share_created",
            Self::ShareRevoked => "share_revoked",
        }
    }

    pub(super) const fn pascal_name(self) -> &'static str {
        match self {
            Self::UploadCompleted => "UploadCompleted",
            Self::EntryDeleted => "EntryDeleted",
            Self::FileSaved => "FileSaved",
            Self::EntryCopied => "EntryCopied",
            Self::EntryRenamed => "EntryRenamed",
            Self::ShareCreated => "ShareCreated",
            Self::ShareRevoked => "ShareRevoked",
        }
    }

    pub(super) const fn requires_destination_path(self) -> bool {
        matches!(self, Self::EntryCopied | Self::EntryRenamed)
    }

    pub(super) fn parse(raw: &str) -> Result<Self, McBrowserError> {
        let trimmed = raw.trim();
        match trimmed {
            "upload_completed" | "UploadCompleted" => Ok(Self::UploadCompleted),
            "entry_deleted" | "EntryDeleted" => Ok(Self::EntryDeleted),
            "file_saved" | "FileSaved" => Ok(Self::FileSaved),
            "entry_copied" | "EntryCopied" => Ok(Self::EntryCopied),
            "entry_renamed" | "EntryRenamed" => Ok(Self::EntryRenamed),
            "share_created" | "ShareCreated" => Ok(Self::ShareCreated),
            "share_revoked" | "ShareRevoked" => Ok(Self::ShareRevoked),
            _ => Err(McBrowserError::BadRequest(
                "Invalid McBrowser event trigger".to_string(),
            )),
        }
    }

    fn from_db_str(raw: &str) -> Result<Self, McBrowserError> {
        Self::parse(raw).map_err(|_| {
            McBrowserError::Internal("Persisted McBrowser audit trigger is invalid".to_string())
        })
    }
}

impl Serialize for McBrowserEventTrigger {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for McBrowserEventTrigger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(|_| de::Error::custom("invalid McBrowser event trigger"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum AuditEventStatus {
    Pending,
    Completed,
    Failed,
}

impl AuditEventStatus {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub(super) fn parse(raw: &str) -> Result<Self, McBrowserError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(McBrowserError::BadRequest(
                "Invalid audit event status: expected 'pending', 'completed', or 'failed'"
                    .to_string(),
            )),
        }
    }

    fn from_db_str(raw: &str) -> Result<Self, McBrowserError> {
        Self::parse(raw).map_err(|_| {
            McBrowserError::Internal("Persisted McBrowser audit status is invalid".to_string())
        })
    }
}

impl Serialize for AuditEventStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AuditEventStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(|_| de::Error::custom("invalid audit event status"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct McBrowserAuditEvent {
    pub event_id: String,
    pub timestamp: String,
    pub user_id: i64,
    pub username: String,
    pub trigger: McBrowserEventTrigger,
    pub relative_path: String,
    pub destination_path: Option<String>,
    pub byte_delta: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct McBrowserAuditRecord {
    #[serde(flatten)]
    pub event: McBrowserAuditEvent,
    pub status: AuditEventStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingAuditIntent {
    pub event: McBrowserAuditEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PostPublicationAuditOutcome {
    Finalized(McBrowserAuditRecord),
    RetainedPending { event_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum EventQueueStatus {
    Queued,
    Acknowledged,
}

impl EventQueueStatus {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Acknowledged => "acknowledged",
        }
    }

    pub(super) fn parse(raw: &str) -> Result<Self, McBrowserError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "queued" | "pending" => Ok(Self::Queued),
            "acknowledged" | "acked" | "completed" => Ok(Self::Acknowledged),
            _ => Err(McBrowserError::BadRequest(
                "Invalid event queue status: expected 'queued' or 'acknowledged'".to_string(),
            )),
        }
    }

    fn from_db_str(raw: &str) -> Result<Self, McBrowserError> {
        match raw {
            "queued" => Ok(Self::Queued),
            "acknowledged" => Ok(Self::Acknowledged),
            _ => Err(McBrowserError::Internal(
                "Persisted event queue status is invalid".to_string(),
            )),
        }
    }
}

impl Serialize for EventQueueStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EventQueueStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(|_| de::Error::custom("invalid event queue status"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct McBrowserQueuedEventTask {
    pub queue_id: i64,
    pub event_id: String,
    pub status: EventQueueStatus,
    pub event: McBrowserAuditEvent,
    pub enqueued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct EventSettingsDocument {
    pub enabled: bool,
}

impl Serialize for EventSettingsDocument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("EventSettingsDocument", 2)?;
        st.serialize_field("enabled", &self.enabled)?;
        st.serialize_field("queue_enabled", &self.enabled)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for EventSettingsDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawSettings {
            enabled: Option<bool>,
            queue_enabled: Option<bool>,
        }

        let raw = RawSettings::deserialize(deserializer)?;
        match (raw.enabled, raw.queue_enabled) {
            (Some(a), Some(b)) if a != b => Err(de::Error::custom(
                "conflicting 'enabled' and 'queue_enabled' boolean values",
            )),
            (Some(v), _) | (None, Some(v)) => Ok(Self { enabled: v }),
            (None, None) => Err(de::Error::custom(
                "missing required 'enabled' (or 'queue_enabled') boolean field",
            )),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuditListQuery {
    pub limit: Option<String>,
    pub status: Option<String>,
    pub trigger: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AuditEventsListResponse {
    pub events: Vec<McBrowserAuditRecord>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EventQueueListQuery {
    pub limit: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct EventQueueListResponse {
    pub enabled: bool,
    pub queue_enabled: bool,
    pub tasks: Vec<McBrowserQueuedEventTask>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AcknowledgeQueueTaskResponse {
    pub success: bool,
    pub task: McBrowserQueuedEventTask,
}

pub(super) fn router() -> Router {
    Router::new()
        .route("/mcbrowser/events", get(get_admin_audit_events))
        .route("/mcbrowser/audit-events", get(get_admin_audit_events))
        .route(
            "/mcbrowser/events/settings",
            get(get_admin_event_settings).put(put_admin_event_settings),
        )
        .route("/mcbrowser/events/queue", get(get_admin_event_queue))
        .route(
            "/mcbrowser/events/queue/:event_id/ack",
            post(post_admin_ack_event_queue_task),
        )
        .layer(DefaultBodyLimit::max(MAX_EVENTS_BODY_BYTES))
}

fn no_store_json<T: Serialize>(status: StatusCode, payload: T) -> Response {
    let mut resp = (status, Json(payload)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn no_store_error(err: McBrowserError) -> Response {
    let mut resp = err.into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn extract_auth_user(ext: Option<Extension<AuthUser>>) -> Result<AuthUser, McBrowserError> {
    match ext {
        Some(Extension(user)) => Ok(user),
        None => Err(McBrowserError::Unauthorized(
            "Authentication required".to_string(),
        )),
    }
}

pub(super) fn ensure_events_tables(conn: &Connection) -> Result<(), McBrowserError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS mcbrowser_audit_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            timestamp_unix INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            trigger TEXT NOT NULL CHECK (trigger IN (
                'upload_completed',
                'entry_deleted',
                'file_saved',
                'entry_copied',
                'entry_renamed',
                'share_created',
                'share_revoked'
            )),
            relative_path TEXT NOT NULL,
            destination_path TEXT DEFAULT NULL,
            byte_delta INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed')),
            error_code TEXT DEFAULT NULL,
            updated_at TEXT NOT NULL,
            updated_at_unix INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_mcbrowser_audit_events_seq
            ON mcbrowser_audit_events(seq DESC);
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_audit_events_status_seq
            ON mcbrowser_audit_events(status, seq DESC);
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_audit_events_user_seq
            ON mcbrowser_audit_events(user_id, seq DESC);
        CREATE INDEX IF NOT EXISTS idx_mcbrowser_audit_events_trigger_seq
            ON mcbrowser_audit_events(trigger, seq DESC);

        CREATE TABLE IF NOT EXISTS mcbrowser_event_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            queue_enabled INTEGER NOT NULL DEFAULT 0 CHECK (queue_enabled IN (0, 1)),
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS mcbrowser_event_queue (
            queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'acknowledged')),
            enqueued_at TEXT NOT NULL,
            enqueued_at_unix INTEGER NOT NULL,
            acknowledged_at TEXT DEFAULT NULL,
            acknowledged_at_unix INTEGER DEFAULT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_mcbrowser_event_queue_status_id
            ON mcbrowser_event_queue(status, queue_id ASC);
        "#,
    )
    .map_err(|_| {
        McBrowserError::Internal("Failed to initialize McBrowser audit event tables".to_string())
    })
}

pub(super) fn validate_event_relative_path(raw: &str) -> Result<String, McBrowserError> {
    let normalized = super::policy::normalize_target_path(raw, false)?;
    if normalized.as_bytes().get(1) == Some(&b':') && normalized.as_bytes()[0].is_ascii_alphabetic()
    {
        return Err(McBrowserError::BadRequest(
            "Invalid path: host drive prefixes are not allowed".to_string(),
        ));
    }
    for segment in normalized.split('/') {
        if segment.eq_ignore_ascii_case(STAGING_DIR_SEGMENT)
            || segment.starts_with(STAGING_TMP_PREFIX)
        {
            return Err(McBrowserError::BadRequest(
                "Invalid path: private upload staging paths are not allowed".to_string(),
            ));
        }
    }
    Ok(normalized)
}

pub(super) fn validate_event_paths_for_trigger(
    trigger: McBrowserEventTrigger,
    raw_relative_path: &str,
    raw_destination_path: Option<&str>,
) -> Result<(String, Option<String>), McBrowserError> {
    let relative_path = validate_event_relative_path(raw_relative_path)?;
    match (trigger.requires_destination_path(), raw_destination_path) {
        (true, Some(dst)) => {
            let destination_path = validate_event_relative_path(dst)?;
            Ok((relative_path, Some(destination_path)))
        }
        (true, None) => Err(McBrowserError::BadRequest(format!(
            "Trigger '{}' requires a destination_path",
            trigger.as_str()
        ))),
        (false, Some(_)) => Err(McBrowserError::BadRequest(format!(
            "Trigger '{}' does not accept a destination_path",
            trigger.as_str()
        ))),
        (false, None) => Ok((relative_path, None)),
    }
}

pub(super) fn validate_event_uuid(raw_id: &str) -> Result<String, McBrowserError> {
    let trimmed = raw_id.trim();
    let parsed = Uuid::parse_str(trimmed).map_err(|_| {
        McBrowserError::BadRequest("Invalid event_id: must be a canonical UUID".to_string())
    })?;
    Ok(parsed.hyphenated().to_string())
}

fn validate_event_username(raw_username: &str) -> Result<String, McBrowserError> {
    let trimmed = raw_username.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_USERNAME_BYTES
        || trimmed.chars().any(char::is_control)
        || trimmed.starts_with("plugin:")
    {
        return Err(McBrowserError::BadRequest(
            "Invalid username for McBrowser audit event".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_event_timestamp(raw_ts: &str) -> Result<(String, i64), McBrowserError> {
    let parsed = DateTime::parse_from_rfc3339(raw_ts.trim()).map_err(|_| {
        McBrowserError::BadRequest("Invalid event timestamp: expected RFC3339".to_string())
    })?;
    let utc = parsed.with_timezone(&Utc);
    Ok((utc.to_rfc3339(), utc.timestamp()))
}

fn sanitize_error_code(raw: Option<&str>) -> Option<String> {
    let trimmed = raw.map(str::trim).filter(|s| !s.is_empty())?;
    let clean: String = trimmed
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_FAILURE_REASON_BYTES)
        .collect();
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

fn validate_persisted_audit_event(
    event: McBrowserAuditEvent,
) -> Result<McBrowserAuditEvent, McBrowserError> {
    let event_id = validate_event_uuid(&event.event_id)
        .map_err(|_| McBrowserError::Internal("Persisted audit event_id is invalid".to_string()))?;
    let (timestamp, _) = validate_event_timestamp(&event.timestamp).map_err(|_| {
        McBrowserError::Internal("Persisted audit timestamp is invalid".to_string())
    })?;
    if event.user_id <= 0 {
        return Err(McBrowserError::Internal(
            "Persisted audit user_id is invalid".to_string(),
        ));
    }
    let username = validate_event_username(&event.username)
        .map_err(|_| McBrowserError::Internal("Persisted audit username is invalid".to_string()))?;
    let (relative_path, destination_path) = validate_event_paths_for_trigger(
        event.trigger,
        &event.relative_path,
        event.destination_path.as_deref(),
    )
    .map_err(|_| McBrowserError::Internal("Persisted audit event path is invalid".to_string()))?;

    Ok(McBrowserAuditEvent {
        event_id,
        timestamp,
        user_id: event.user_id,
        username,
        trigger: event.trigger,
        relative_path,
        destination_path,
        byte_delta: event.byte_delta,
    })
}

fn verify_live_actor_with_conn(
    conn: &Connection,
    actor: &AuthUser,
) -> Result<(i64, String), McBrowserError> {
    let user_id = super::validate_mcbrowser_user(actor)?;

    let user_row: Option<(String, String)> = conn
        .query_row(
            "SELECT username, COALESCE(role, 'user') FROM users WHERE id = ?1",
            params![user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to verify user account state".to_string()))?;

    let Some((live_username, live_role)) = user_row else {
        return Err(McBrowserError::Unauthorized(
            "User account not found".to_string(),
        ));
    };

    if live_role.eq_ignore_ascii_case("plugin") || live_username.starts_with("plugin:") {
        return Err(McBrowserError::Forbidden(
            "Plugin accounts are not permitted to access McBrowser".to_string(),
        ));
    }

    let quota_status: Option<String> = conn
        .query_row(
            "SELECT COALESCE(status, 'active') FROM user_quotas WHERE user_id = ?1",
            params![user_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to read user storage quota".to_string()))?;

    if let Some(raw_status) = quota_status {
        let clean = raw_status.trim();
        if !clean.is_empty() && !clean.eq_ignore_ascii_case("active") {
            return Err(McBrowserError::Forbidden(format!(
                "Storage operations are disabled because user quota status is '{clean}'"
            )));
        }
    }

    let validated_username = validate_event_username(&live_username).map_err(|_| {
        McBrowserError::Internal("Live account username failed validation".to_string())
    })?;

    Ok((user_id, validated_username))
}

pub(super) fn verify_live_admin_with_conn(
    conn: &Connection,
    caller: &AuthUser,
) -> Result<i64, McBrowserError> {
    let caller_id = super::validate_mcbrowser_user(caller)?;
    if !caller.role.eq_ignore_ascii_case("admin") {
        return Err(McBrowserError::Forbidden(
            "Admin access required for McBrowser audit events".to_string(),
        ));
    }

    let user_row: Option<(String, String)> = conn
        .query_row(
            "SELECT username, COALESCE(role, 'user') FROM users WHERE id = ?1",
            params![caller_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| {
            McBrowserError::Internal("Failed to verify admin account state".to_string())
        })?;

    let Some((live_username, live_role)) = user_row else {
        return Err(McBrowserError::Unauthorized(
            "User account not found".to_string(),
        ));
    };

    if live_role.eq_ignore_ascii_case("plugin")
        || live_username.starts_with("plugin:")
        || !live_role.eq_ignore_ascii_case("admin")
    {
        return Err(McBrowserError::Forbidden(
            "Admin access required for McBrowser audit events".to_string(),
        ));
    }

    let quota_status: Option<String> = conn
        .query_row(
            "SELECT COALESCE(status, 'active') FROM user_quotas WHERE user_id = ?1",
            params![caller_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to verify admin quota status".to_string()))?;

    if let Some(raw_status) = quota_status {
        let clean = raw_status.trim();
        if !clean.is_empty() && !clean.eq_ignore_ascii_case("active") {
            return Err(McBrowserError::Forbidden(format!(
                "Admin account is not active (quota status '{clean}')"
            )));
        }
    }

    Ok(caller_id)
}

fn is_event_queue_enabled_raw(conn: &Connection) -> Result<bool, McBrowserError> {
    ensure_events_tables(conn)?;
    let flag: Option<i64> = conn
        .query_row(
            "SELECT queue_enabled FROM mcbrowser_event_settings WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| {
            McBrowserError::Internal("Failed to read McBrowser event queue settings".to_string())
        })?;
    Ok(flag.unwrap_or(0) != 0)
}

const AUDIT_SELECT_COLUMNS: &str = "\
    event_id, timestamp, user_id, username, trigger, relative_path, \
    destination_path, byte_delta, status, error_code, updated_at";

fn row_to_audit_record(row: &rusqlite::Row<'_>) -> Result<McBrowserAuditRecord, McBrowserError> {
    let raw_event_id: String = row
        .get(0)
        .map_err(|_| McBrowserError::Internal("Failed to decode audit event_id".to_string()))?;
    let raw_timestamp: String = row
        .get(1)
        .map_err(|_| McBrowserError::Internal("Failed to decode audit timestamp".to_string()))?;
    let user_id: i64 = row
        .get(2)
        .map_err(|_| McBrowserError::Internal("Failed to decode audit user_id".to_string()))?;
    let raw_username: String = row
        .get(3)
        .map_err(|_| McBrowserError::Internal("Failed to decode audit username".to_string()))?;
    let raw_trigger: String = row
        .get(4)
        .map_err(|_| McBrowserError::Internal("Failed to decode audit trigger".to_string()))?;
    let raw_rel_path: String = row.get(5).map_err(|_| {
        McBrowserError::Internal("Failed to decode audit relative_path".to_string())
    })?;
    let raw_dst_path: Option<String> = row.get(6).map_err(|_| {
        McBrowserError::Internal("Failed to decode audit destination_path".to_string())
    })?;
    let byte_delta: i64 = row
        .get(7)
        .map_err(|_| McBrowserError::Internal("Failed to decode audit byte_delta".to_string()))?;
    let raw_status: String = row
        .get(8)
        .map_err(|_| McBrowserError::Internal("Failed to decode audit status".to_string()))?;
    let raw_error_code: Option<String> = row
        .get(9)
        .map_err(|_| McBrowserError::Internal("Failed to decode audit error_code".to_string()))?;
    let raw_updated_at: String = row
        .get(10)
        .map_err(|_| McBrowserError::Internal("Failed to decode audit updated_at".to_string()))?;

    let trigger = McBrowserEventTrigger::from_db_str(&raw_trigger)?;
    let status = AuditEventStatus::from_db_str(&raw_status)?;
    let (updated_at, _) = validate_event_timestamp(&raw_updated_at).map_err(|_| {
        McBrowserError::Internal("Persisted audit updated_at timestamp is invalid".to_string())
    })?;

    let event = validate_persisted_audit_event(McBrowserAuditEvent {
        event_id: raw_event_id,
        timestamp: raw_timestamp,
        user_id,
        username: raw_username,
        trigger,
        relative_path: raw_rel_path,
        destination_path: raw_dst_path,
        byte_delta,
    })?;

    Ok(McBrowserAuditRecord {
        event,
        status,
        error_code: sanitize_error_code(raw_error_code.as_deref()),
        updated_at,
    })
}

pub(super) fn load_audit_record_by_id_with_conn(
    conn: &Connection,
    event_id: &str,
) -> Result<Option<McBrowserAuditRecord>, McBrowserError> {
    let valid_id = validate_event_uuid(event_id)?;
    ensure_events_tables(conn)?;
    let sql =
        format!("SELECT {AUDIT_SELECT_COLUMNS} FROM mcbrowser_audit_events WHERE event_id = ?1");
    let mut stmt = conn.prepare(&sql).map_err(|_| {
        McBrowserError::Internal("Failed to prepare audit event lookup".to_string())
    })?;
    let mut rows = stmt
        .query(params![valid_id])
        .map_err(|_| McBrowserError::Internal("Failed to query audit event by id".to_string()))?;
    let Some(row) = rows
        .next()
        .map_err(|_| McBrowserError::Internal("Failed to read audit event row".to_string()))?
    else {
        return Ok(None);
    };
    row_to_audit_record(row).map(Some)
}

pub(super) fn record_pending_intent_with_conn(
    conn: &Connection,
    actor: &AuthUser,
    trigger: McBrowserEventTrigger,
    relative_path: &str,
    destination_path: Option<&str>,
    expected_byte_delta: i64,
) -> Result<PendingAuditIntent, McBrowserError> {
    let (user_id, live_username) = verify_live_actor_with_conn(conn, actor)?;
    let (norm_rel, norm_dst) =
        validate_event_paths_for_trigger(trigger, relative_path, destination_path)?;

    ensure_events_tables(conn)?;

    let now = Utc::now();
    let timestamp = now.to_rfc3339();
    let timestamp_unix = now.timestamp();
    let event_id = Uuid::new_v4().hyphenated().to_string();

    conn.execute_batch("SAVEPOINT mcbrowser_audit_pending")
        .map_err(|_| {
            McBrowserError::Internal("Failed to begin pending audit intent savepoint".to_string())
        })?;

    let insert_res = conn.execute(
        "INSERT INTO mcbrowser_audit_events (
            event_id, timestamp, timestamp_unix, user_id, username, trigger,
            relative_path, destination_path, byte_delta, status, error_code,
            updated_at, updated_at_unix
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', NULL, ?10, ?11)",
        params![
            &event_id,
            &timestamp,
            timestamp_unix,
            user_id,
            &live_username,
            trigger.as_str(),
            &norm_rel,
            norm_dst.as_deref(),
            expected_byte_delta,
            &timestamp,
            timestamp_unix,
        ],
    );

    if insert_res.is_err() {
        let _ = conn
            .execute_batch("ROLLBACK TO mcbrowser_audit_pending; RELEASE mcbrowser_audit_pending");
        return Err(McBrowserError::Internal(
            "Failed to persist pending audit event intent".to_string(),
        ));
    }

    conn.execute_batch("RELEASE mcbrowser_audit_pending")
        .map_err(|_| {
            let _ = conn.execute_batch(
                "ROLLBACK TO mcbrowser_audit_pending; RELEASE mcbrowser_audit_pending",
            );
            McBrowserError::Internal("Failed to commit pending audit event intent".to_string())
        })?;

    Ok(PendingAuditIntent {
        event: McBrowserAuditEvent {
            event_id,
            timestamp,
            user_id,
            username: live_username,
            trigger,
            relative_path: norm_rel,
            destination_path: norm_dst,
            byte_delta: expected_byte_delta,
        },
    })
}

pub(super) fn record_pending_intent(
    actor: &AuthUser,
    trigger: McBrowserEventTrigger,
    relative_path: &str,
    destination_path: Option<&str>,
    expected_byte_delta: i64,
) -> Result<PendingAuditIntent, McBrowserError> {
    let conn = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for audit intent recording".to_string())
    })?;
    record_pending_intent_with_conn(
        &conn,
        actor,
        trigger,
        relative_path,
        destination_path,
        expected_byte_delta,
    )
}

pub(super) fn finalize_event_completed_with_conn(
    conn: &Connection,
    event_id: &str,
    final_relative_path: Option<&str>,
    final_destination_path: Option<&str>,
    final_byte_delta: i64,
) -> Result<McBrowserAuditRecord, McBrowserError> {
    let valid_id = validate_event_uuid(event_id)?;
    ensure_events_tables(conn)?;

    conn.execute_batch("SAVEPOINT mcbrowser_audit_complete")
        .map_err(|_| {
            McBrowserError::Internal("Failed to begin audit completion transaction".to_string())
        })?;

    let result = (|| -> Result<McBrowserAuditRecord, McBrowserError> {
        let Some(existing) = load_audit_record_by_id_with_conn(conn, &valid_id)? else {
            return Err(McBrowserError::NotFound(
                "Pending audit event intent not found".to_string(),
            ));
        };

        match existing.status {
            AuditEventStatus::Completed => {
                return Ok(existing);
            }
            AuditEventStatus::Failed => {
                return Err(McBrowserError::Conflict(
                    "Cannot mark an already-failed audit event as completed".to_string(),
                ));
            }
            AuditEventStatus::Pending => {}
        }

        let effective_rel = final_relative_path.unwrap_or(&existing.event.relative_path);
        let effective_dst = match final_destination_path {
            Some(dst) => Some(dst),
            None => existing.event.destination_path.as_deref(),
        };
        let (norm_rel, norm_dst) =
            validate_event_paths_for_trigger(existing.event.trigger, effective_rel, effective_dst)?;

        let now = Utc::now();
        let now_rfc3339 = now.to_rfc3339();
        let now_unix = now.timestamp();

        let completed_event = McBrowserAuditEvent {
            event_id: existing.event.event_id.clone(),
            timestamp: existing.event.timestamp.clone(),
            user_id: existing.event.user_id,
            username: existing.event.username.clone(),
            trigger: existing.event.trigger,
            relative_path: norm_rel.clone(),
            destination_path: norm_dst.clone(),
            byte_delta: final_byte_delta,
        };

        let updated = conn
            .execute(
                "UPDATE mcbrowser_audit_events
                 SET relative_path = ?1,
                     destination_path = ?2,
                     byte_delta = ?3,
                     status = 'completed',
                     error_code = NULL,
                     updated_at = ?4,
                     updated_at_unix = ?5
                 WHERE event_id = ?6 AND status = 'pending'",
                params![
                    &norm_rel,
                    norm_dst.as_deref(),
                    final_byte_delta,
                    &now_rfc3339,
                    now_unix,
                    &valid_id,
                ],
            )
            .map_err(|_| {
                McBrowserError::Internal("Failed to finalize audit event completion".to_string())
            })?;

        if updated == 0 {
            return Err(McBrowserError::Conflict(
                "Audit event state changed concurrently during completion".to_string(),
            ));
        }

        if is_event_queue_enabled_raw(conn)? {
            let payload_json = serde_json::to_string(&completed_event).map_err(|_| {
                McBrowserError::Internal(
                    "Failed to serialize completed event for queue".to_string(),
                )
            })?;
            conn.execute(
                "INSERT INTO mcbrowser_event_queue (
                    event_id, payload_json, status, enqueued_at, enqueued_at_unix
                 ) VALUES (?1, ?2, 'queued', ?3, ?4)
                 ON CONFLICT(event_id) DO NOTHING",
                params![&valid_id, &payload_json, &now_rfc3339, now_unix],
            )
            .map_err(|_| {
                McBrowserError::Internal(
                    "Failed to enqueue completed McBrowser event task".to_string(),
                )
            })?;
        }

        Ok(McBrowserAuditRecord {
            event: completed_event,
            status: AuditEventStatus::Completed,
            error_code: None,
            updated_at: now_rfc3339,
        })
    })();

    match result {
        Ok(record) => {
            conn.execute_batch("RELEASE mcbrowser_audit_complete")
                .map_err(|_| {
                    let _ = conn.execute_batch(
                        "ROLLBACK TO mcbrowser_audit_complete; RELEASE mcbrowser_audit_complete",
                    );
                    McBrowserError::Internal(
                        "Failed to commit audit event completion savepoint".to_string(),
                    )
                })?;
            Ok(record)
        }
        Err(err) => {
            let _ = conn.execute_batch(
                "ROLLBACK TO mcbrowser_audit_complete; RELEASE mcbrowser_audit_complete",
            );
            Err(err)
        }
    }
}

pub(super) fn finalize_event_completed(
    event_id: &str,
    final_relative_path: Option<&str>,
    final_destination_path: Option<&str>,
    final_byte_delta: i64,
) -> Result<McBrowserAuditRecord, McBrowserError> {
    let conn = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for audit completion".to_string())
    })?;
    finalize_event_completed_with_conn(
        &conn,
        event_id,
        final_relative_path,
        final_destination_path,
        final_byte_delta,
    )
}

pub(super) fn finalize_published_mutation_with_conn(
    conn: &Connection,
    pending: &PendingAuditIntent,
    final_relative_path: Option<&str>,
    final_destination_path: Option<&str>,
    final_byte_delta: i64,
) -> PostPublicationAuditOutcome {
    match finalize_event_completed_with_conn(
        conn,
        &pending.event.event_id,
        final_relative_path,
        final_destination_path,
        final_byte_delta,
    ) {
        Ok(record) => PostPublicationAuditOutcome::Finalized(record),
        Err(err) => {
            tracing::warn!(
                event_id = %pending.event.event_id,
                trigger = %pending.event.trigger.as_str(),
                error = ?err,
                "Filesystem mutation published on disk but audit finalization failed; retaining durable pending audit intent"
            );
            PostPublicationAuditOutcome::RetainedPending {
                event_id: pending.event.event_id.clone(),
            }
        }
    }
}

pub(super) fn finalize_published_mutation(
    pending: &PendingAuditIntent,
    final_relative_path: Option<&str>,
    final_destination_path: Option<&str>,
    final_byte_delta: i64,
) -> PostPublicationAuditOutcome {
    let Ok(conn) = af_db::get_conn() else {
        tracing::warn!(
            event_id = %pending.event.event_id,
            trigger = %pending.event.trigger.as_str(),
            "Database unavailable after filesystem publication; retaining durable pending audit intent"
        );
        return PostPublicationAuditOutcome::RetainedPending {
            event_id: pending.event.event_id.clone(),
        };
    };
    finalize_published_mutation_with_conn(
        &conn,
        pending,
        final_relative_path,
        final_destination_path,
        final_byte_delta,
    )
}

pub(super) fn finalize_event_failed_with_conn(
    conn: &Connection,
    event_id: &str,
    error_code: Option<&str>,
) -> Result<McBrowserAuditRecord, McBrowserError> {
    let valid_id = validate_event_uuid(event_id)?;
    let clean_error = sanitize_error_code(error_code);
    ensure_events_tables(conn)?;

    conn.execute_batch("SAVEPOINT mcbrowser_audit_fail")
        .map_err(|_| {
            McBrowserError::Internal("Failed to begin audit failure savepoint".to_string())
        })?;

    let result = (|| -> Result<McBrowserAuditRecord, McBrowserError> {
        let Some(existing) = load_audit_record_by_id_with_conn(conn, &valid_id)? else {
            return Err(McBrowserError::NotFound(
                "Pending audit event intent not found".to_string(),
            ));
        };

        match existing.status {
            AuditEventStatus::Failed => return Ok(existing),
            AuditEventStatus::Completed => {
                return Err(McBrowserError::Conflict(
                    "Cannot mark an already-completed audit event as failed".to_string(),
                ));
            }
            AuditEventStatus::Pending => {}
        }

        let now = Utc::now();
        let now_rfc3339 = now.to_rfc3339();
        let now_unix = now.timestamp();

        let updated = conn
            .execute(
                "UPDATE mcbrowser_audit_events
                 SET byte_delta = 0,
                     status = 'failed',
                     error_code = ?1,
                     updated_at = ?2,
                     updated_at_unix = ?3
                 WHERE event_id = ?4 AND status = 'pending'",
                params![clean_error.as_deref(), &now_rfc3339, now_unix, &valid_id],
            )
            .map_err(|_| {
                McBrowserError::Internal("Failed to record failed audit event status".to_string())
            })?;

        if updated == 0 {
            return Err(McBrowserError::Conflict(
                "Audit event state changed concurrently".to_string(),
            ));
        }

        let mut failed_event = existing.event;
        failed_event.byte_delta = 0;

        Ok(McBrowserAuditRecord {
            event: failed_event,
            status: AuditEventStatus::Failed,
            error_code: clean_error,
            updated_at: now_rfc3339,
        })
    })();

    match result {
        Ok(record) => {
            conn.execute_batch("RELEASE mcbrowser_audit_fail")
                .map_err(|_| {
                    let _ = conn.execute_batch(
                        "ROLLBACK TO mcbrowser_audit_fail; RELEASE mcbrowser_audit_fail",
                    );
                    McBrowserError::Internal("Failed to commit audit failure savepoint".to_string())
                })?;
            Ok(record)
        }
        Err(err) => {
            let _ = conn
                .execute_batch("ROLLBACK TO mcbrowser_audit_fail; RELEASE mcbrowser_audit_fail");
            Err(err)
        }
    }
}

pub(super) fn finalize_event_failed(
    event_id: &str,
    error_code: Option<&str>,
) -> Result<McBrowserAuditRecord, McBrowserError> {
    let conn = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for audit failure update".to_string())
    })?;
    finalize_event_failed_with_conn(&conn, event_id, error_code)
}

pub(super) fn execute_with_audit_intent_conn<T, F>(
    conn: &Connection,
    actor: &AuthUser,
    trigger: McBrowserEventTrigger,
    initial_relative_path: &str,
    initial_destination_path: Option<&str>,
    expected_byte_delta: i64,
    op: F,
) -> Result<(T, PostPublicationAuditOutcome), McBrowserError>
where
    F: FnOnce(
        &Connection,
        &PendingAuditIntent,
    ) -> Result<(Option<String>, Option<String>, i64, T, bool), McBrowserError>,
{
    let pending = record_pending_intent_with_conn(
        conn,
        actor,
        trigger,
        initial_relative_path,
        initial_destination_path,
        expected_byte_delta,
    )?;

    match op(conn, &pending) {
        Ok((final_rel, final_dst, final_byte_delta, output, accounting_complete)) => {
            let outcome = if accounting_complete {
                finalize_published_mutation_with_conn(
                    conn,
                    &pending,
                    final_rel.as_deref(),
                    final_dst.as_deref(),
                    final_byte_delta,
                )
            } else {
                PostPublicationAuditOutcome::RetainedPending {
                    event_id: pending.event.event_id.clone(),
                }
            };
            Ok((output, outcome))
        }
        Err(err) => {
            if !matches!(err, McBrowserError::AccountingPending(_)) {
                let code = error_variant_code(&err);
                let _ = finalize_event_failed_with_conn(conn, &pending.event.event_id, Some(code));
            }
            Err(err)
        }
    }
}

fn error_variant_code(err: &McBrowserError) -> &'static str {
    match err {
        McBrowserError::BadRequest(_) => "BAD_REQUEST",
        McBrowserError::Unauthorized(_) => "UNAUTHORIZED",
        McBrowserError::Forbidden(_) => "FORBIDDEN",
        McBrowserError::NotFound(_) => "NOT_FOUND",
        McBrowserError::Conflict(_) => "CONFLICT",
        McBrowserError::PayloadTooLarge(_) => "PAYLOAD_TOO_LARGE",
        McBrowserError::QuotaExceeded(_) => "QUOTA_EXCEEDED",
        McBrowserError::InsufficientStorage(_) => "INSUFFICIENT_STORAGE",
        McBrowserError::RangeNotSatisfiable(_) => "RANGE_NOT_SATISFIABLE",
        McBrowserError::RequestTimeout(_) => "REQUEST_TIMEOUT",
        McBrowserError::AccountingPending(_) => "ACCOUNTING_PENDING",
        McBrowserError::Internal(_) => "INTERNAL_ERROR",
    }
}

fn parse_bounded_limit(
    raw: Option<&str>,
    default_limit: usize,
    max_limit: usize,
) -> Result<usize, McBrowserError> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(default_limit);
    };
    let parsed: usize = s.parse().map_err(|_| {
        McBrowserError::BadRequest(format!("Invalid limit parameter: must be 1..={max_limit}"))
    })?;
    if parsed == 0 || parsed > max_limit {
        return Err(McBrowserError::BadRequest(format!(
            "Invalid limit parameter: must be between 1 and {max_limit}"
        )));
    }
    Ok(parsed)
}

fn parse_optional_user_id(raw: Option<&str>) -> Result<Option<i64>, McBrowserError> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let uid: i64 = s
        .parse()
        .map_err(|_| McBrowserError::BadRequest("Invalid user_id filter".to_string()))?;
    if uid <= 0 {
        return Err(McBrowserError::BadRequest(
            "Invalid user_id filter: must be a positive integer".to_string(),
        ));
    }
    Ok(Some(uid))
}

pub(super) fn list_audit_events_for_admin_with_conn(
    conn: &Connection,
    caller: &AuthUser,
    query: &AuditListQuery,
) -> Result<AuditEventsListResponse, McBrowserError> {
    verify_live_admin_with_conn(conn, caller)?;
    ensure_events_tables(conn)?;

    let limit = parse_bounded_limit(
        query.limit.as_deref(),
        DEFAULT_AUDIT_LIST_LIMIT,
        MAX_AUDIT_LIST_LIMIT,
    )?;
    let status_filter = match query
        .status
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(AuditEventStatus::parse(raw)?),
        None => None,
    };
    let trigger_filter = match query
        .trigger
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(McBrowserEventTrigger::parse(raw)?),
        None => None,
    };
    let user_id_filter = parse_optional_user_id(query.user_id.as_deref())?;

    let fetch_cap = (limit + 1) as i64;
    let status_param = status_filter.map(|s| s.as_str().to_string());
    let trigger_param = trigger_filter.map(|t| t.as_str().to_string());

    let sql = format!(
        "SELECT {AUDIT_SELECT_COLUMNS}
         FROM mcbrowser_audit_events
         WHERE (?1 IS NULL OR status = ?1)
           AND (?2 IS NULL OR trigger = ?2)
           AND (?3 IS NULL OR user_id = ?3)
         ORDER BY seq DESC
         LIMIT ?4"
    );

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|_| McBrowserError::Internal("Failed to prepare audit list query".to_string()))?;

    let mut rows = stmt
        .query(params![
            status_param.as_deref(),
            trigger_param.as_deref(),
            user_id_filter,
            fetch_cap,
        ])
        .map_err(|_| McBrowserError::Internal("Failed to query audit events".to_string()))?;

    let mut records = Vec::with_capacity(limit.min(64));
    while let Some(row) = rows
        .next()
        .map_err(|_| McBrowserError::Internal("Failed to read audit event row".to_string()))?
    {
        records.push(row_to_audit_record(row)?);
    }

    let truncated = records.len() > limit;
    if truncated {
        records.truncate(limit);
    }

    Ok(AuditEventsListResponse {
        events: records,
        truncated,
    })
}

pub(super) fn load_event_settings_for_admin_with_conn(
    conn: &Connection,
    caller: &AuthUser,
) -> Result<EventSettingsDocument, McBrowserError> {
    verify_live_admin_with_conn(conn, caller)?;
    let enabled = is_event_queue_enabled_raw(conn)?;
    Ok(EventSettingsDocument { enabled })
}

pub(super) fn save_event_settings_for_admin_with_conn(
    conn: &Connection,
    caller: &AuthUser,
    settings: EventSettingsDocument,
) -> Result<EventSettingsDocument, McBrowserError> {
    let caller_id = super::validate_mcbrowser_user(caller)?;
    if !caller.role.eq_ignore_ascii_case("admin") {
        return Err(McBrowserError::Forbidden(
            "Admin access required to configure McBrowser event settings".to_string(),
        ));
    }
    ensure_events_tables(conn)?;

    conn.execute_batch("SAVEPOINT mcbrowser_event_settings_update")
        .map_err(|_| {
            McBrowserError::Internal("Failed to begin event settings savepoint".to_string())
        })?;

    let res = (|| -> Result<EventSettingsDocument, McBrowserError> {
        let _ = verify_live_admin_with_conn(conn, caller)?;
        let _ = caller_id;
        let now_rfc3339 = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO mcbrowser_event_settings (id, queue_enabled, updated_at)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
                queue_enabled = excluded.queue_enabled,
                updated_at = excluded.updated_at",
            params![i64::from(settings.enabled), &now_rfc3339],
        )
        .map_err(|_| {
            McBrowserError::Internal("Failed to persist McBrowser event settings".to_string())
        })?;
        Ok(settings)
    })();

    match res {
        Ok(saved) => {
            conn.execute_batch("RELEASE mcbrowser_event_settings_update")
                .map_err(|_| {
                    let _ = conn.execute_batch(
                        "ROLLBACK TO mcbrowser_event_settings_update; RELEASE mcbrowser_event_settings_update",
                    );
                    McBrowserError::Internal(
                        "Failed to commit McBrowser event settings update".to_string(),
                    )
                })?;
            Ok(saved)
        }
        Err(err) => {
            let _ = conn.execute_batch(
                "ROLLBACK TO mcbrowser_event_settings_update; RELEASE mcbrowser_event_settings_update",
            );
            Err(err)
        }
    }
}

fn row_to_queued_task(row: &rusqlite::Row<'_>) -> Result<McBrowserQueuedEventTask, McBrowserError> {
    let queue_id: i64 = row
        .get(0)
        .map_err(|_| McBrowserError::Internal("Failed to decode queue_id".to_string()))?;
    let raw_event_id: String = row
        .get(1)
        .map_err(|_| McBrowserError::Internal("Failed to decode queued event_id".to_string()))?;
    let payload_json: String = row.get(2).map_err(|_| {
        McBrowserError::Internal("Failed to decode queued payload_json".to_string())
    })?;
    let raw_status: String = row
        .get(3)
        .map_err(|_| McBrowserError::Internal("Failed to decode queued status".to_string()))?;
    let raw_enqueued_at: String = row
        .get(4)
        .map_err(|_| McBrowserError::Internal("Failed to decode enqueued_at".to_string()))?;
    let raw_ack_at: Option<String> = row
        .get(5)
        .map_err(|_| McBrowserError::Internal("Failed to decode acknowledged_at".to_string()))?;

    let event_id = validate_event_uuid(&raw_event_id).map_err(|_| {
        McBrowserError::Internal("Persisted queued event_id is invalid".to_string())
    })?;
    let status = EventQueueStatus::from_db_str(&raw_status)?;
    let (enqueued_at, _) = validate_event_timestamp(&raw_enqueued_at).map_err(|_| {
        McBrowserError::Internal("Persisted queue enqueued_at is invalid".to_string())
    })?;
    let acknowledged_at = match raw_ack_at {
        Some(raw) => {
            let (ts, _) = validate_event_timestamp(&raw).map_err(|_| {
                McBrowserError::Internal("Persisted queue acknowledged_at is invalid".to_string())
            })?;
            Some(ts)
        }
        None => None,
    };

    let parsed_event: McBrowserAuditEvent = serde_json::from_str(&payload_json).map_err(|_| {
        McBrowserError::Internal("Persisted queue payload_json is invalid".to_string())
    })?;
    let validated_event = validate_persisted_audit_event(parsed_event)?;
    if validated_event.event_id != event_id {
        return Err(McBrowserError::Internal(
            "Persisted queue payload event_id mismatch".to_string(),
        ));
    }

    Ok(McBrowserQueuedEventTask {
        queue_id,
        event_id,
        status,
        event: validated_event,
        enqueued_at,
        acknowledged_at,
    })
}

pub(super) fn list_event_queue_for_admin_with_conn(
    conn: &Connection,
    caller: &AuthUser,
    query: &EventQueueListQuery,
) -> Result<EventQueueListResponse, McBrowserError> {
    verify_live_admin_with_conn(conn, caller)?;
    ensure_events_tables(conn)?;

    let limit = parse_bounded_limit(
        query.limit.as_deref(),
        DEFAULT_QUEUE_LIST_LIMIT,
        MAX_QUEUE_LIST_LIMIT,
    )?;
    let status_filter = match query
        .status
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(EventQueueStatus::parse(raw)?),
        None => None,
    };

    let enabled = is_event_queue_enabled_raw(conn)?;
    let fetch_cap = (limit + 1) as i64;
    let status_param = status_filter.map(|s| s.as_str().to_string());

    let mut stmt = conn
        .prepare(
            "SELECT queue_id, event_id, payload_json, status, enqueued_at, acknowledged_at
             FROM mcbrowser_event_queue
             WHERE (?1 IS NULL OR status = ?1)
             ORDER BY queue_id ASC
             LIMIT ?2",
        )
        .map_err(|_| McBrowserError::Internal("Failed to prepare event queue query".to_string()))?;

    let mut rows = stmt
        .query(params![status_param.as_deref(), fetch_cap])
        .map_err(|_| McBrowserError::Internal("Failed to query event queue".to_string()))?;

    let mut tasks = Vec::with_capacity(limit.min(64));
    while let Some(row) = rows
        .next()
        .map_err(|_| McBrowserError::Internal("Failed to read event queue row".to_string()))?
    {
        tasks.push(row_to_queued_task(row)?);
    }

    let truncated = tasks.len() > limit;
    if truncated {
        tasks.truncate(limit);
    }

    Ok(EventQueueListResponse {
        enabled,
        queue_enabled: enabled,
        tasks,
        truncated,
    })
}

pub(super) fn acknowledge_event_queue_task_for_admin_with_conn(
    conn: &Connection,
    caller: &AuthUser,
    raw_event_id: &str,
) -> Result<McBrowserQueuedEventTask, McBrowserError> {
    let valid_id = validate_event_uuid(raw_event_id)?;
    ensure_events_tables(conn)?;

    conn.execute_batch("SAVEPOINT mcbrowser_event_queue_ack")
        .map_err(|_| {
            McBrowserError::Internal("Failed to begin queue acknowledgment savepoint".to_string())
        })?;

    let res = (|| -> Result<McBrowserQueuedEventTask, McBrowserError> {
        verify_live_admin_with_conn(conn, caller)?;

        let now = Utc::now();
        let now_rfc3339 = now.to_rfc3339();
        let now_unix = now.timestamp();

        conn.execute(
            "UPDATE mcbrowser_event_queue
             SET status = 'acknowledged',
                 acknowledged_at = COALESCE(acknowledged_at, ?1),
                 acknowledged_at_unix = COALESCE(acknowledged_at_unix, ?2)
             WHERE event_id = ?3",
            params![&now_rfc3339, now_unix, &valid_id],
        )
        .map_err(|_| {
            McBrowserError::Internal("Failed to acknowledge queued event task".to_string())
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT queue_id, event_id, payload_json, status, enqueued_at, acknowledged_at
                 FROM mcbrowser_event_queue
                 WHERE event_id = ?1",
            )
            .map_err(|_| {
                McBrowserError::Internal("Failed to prepare queued task lookup".to_string())
            })?;

        let mut rows = stmt.query(params![&valid_id]).map_err(|_| {
            McBrowserError::Internal("Failed to query acknowledged event task".to_string())
        })?;

        let Some(row) = rows.next().map_err(|_| {
            McBrowserError::Internal("Failed to read acknowledged event task".to_string())
        })?
        else {
            return Err(McBrowserError::NotFound(
                "Queued event task not found".to_string(),
            ));
        };

        row_to_queued_task(row)
    })();

    match res {
        Ok(task) => {
            conn.execute_batch("RELEASE mcbrowser_event_queue_ack")
                .map_err(|_| {
                    let _ = conn.execute_batch(
                        "ROLLBACK TO mcbrowser_event_queue_ack; RELEASE mcbrowser_event_queue_ack",
                    );
                    McBrowserError::Internal(
                        "Failed to commit queue acknowledgment savepoint".to_string(),
                    )
                })?;
            Ok(task)
        }
        Err(err) => {
            let _ = conn.execute_batch(
                "ROLLBACK TO mcbrowser_event_queue_ack; RELEASE mcbrowser_event_queue_ack",
            );
            Err(err)
        }
    }
}

async fn get_admin_audit_events(
    auth_ext: Option<Extension<AuthUser>>,
    query_res: Result<Query<AuditListQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let auth_user = match extract_auth_user(auth_ext) {
        Ok(u) => u,
        Err(e) => return no_store_error(e),
    };
    if let Err(e) = super::validate_mcbrowser_user(&auth_user) {
        return no_store_error(e);
    }
    if !auth_user.role.eq_ignore_ascii_case("admin") {
        return no_store_error(McBrowserError::Forbidden(
            "Admin access required to view McBrowser audit events".to_string(),
        ));
    }
    let Query(query) = match query_res {
        Ok(q) => q,
        Err(_) => {
            return no_store_error(McBrowserError::BadRequest(
                "Invalid query parameters for audit events".to_string(),
            ))
        }
    };

    let res =
        tokio::task::spawn_blocking(move || -> Result<AuditEventsListResponse, McBrowserError> {
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal("Database unavailable for audit event listing".to_string())
            })?;
            list_audit_events_for_admin_with_conn(&conn, &auth_user, &query)
        })
        .await;

    match res {
        Ok(Ok(list)) => no_store_json(StatusCode::OK, list),
        Ok(Err(e)) => no_store_error(e),
        Err(_) => no_store_error(McBrowserError::Internal(
            "Audit event listing task failed".to_string(),
        )),
    }
}

async fn get_admin_event_settings(auth_ext: Option<Extension<AuthUser>>) -> Response {
    let auth_user = match extract_auth_user(auth_ext) {
        Ok(u) => u,
        Err(e) => return no_store_error(e),
    };
    if let Err(e) = super::validate_mcbrowser_user(&auth_user) {
        return no_store_error(e);
    }
    if !auth_user.role.eq_ignore_ascii_case("admin") {
        return no_store_error(McBrowserError::Forbidden(
            "Admin access required to inspect McBrowser event settings".to_string(),
        ));
    }

    let res =
        tokio::task::spawn_blocking(move || -> Result<EventSettingsDocument, McBrowserError> {
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal(
                    "Database unavailable for event settings lookup".to_string(),
                )
            })?;
            load_event_settings_for_admin_with_conn(&conn, &auth_user)
        })
        .await;

    match res {
        Ok(Ok(doc)) => no_store_json(StatusCode::OK, doc),
        Ok(Err(e)) => no_store_error(e),
        Err(_) => no_store_error(McBrowserError::Internal(
            "Event settings lookup task failed".to_string(),
        )),
    }
}

async fn put_admin_event_settings(auth_ext: Option<Extension<AuthUser>>, body: Bytes) -> Response {
    let auth_user = match extract_auth_user(auth_ext) {
        Ok(u) => u,
        Err(e) => return no_store_error(e),
    };
    let caller_id = match super::validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return no_store_error(e),
    };
    if !auth_user.role.eq_ignore_ascii_case("admin") {
        return no_store_error(McBrowserError::Forbidden(
            "Admin access required to update McBrowser event settings".to_string(),
        ));
    }

    if body.len() > MAX_EVENTS_BODY_BYTES {
        return no_store_error(McBrowserError::PayloadTooLarge(
            "Event settings request body is too large".to_string(),
        ));
    }

    let parsed: EventSettingsDocument = match serde_json::from_slice(&body) {
        Ok(doc) => doc,
        Err(_) => {
            return no_store_error(McBrowserError::BadRequest(
                "Invalid event settings JSON payload or unsupported fields".to_string(),
            ))
        }
    };

    let guard = super::user_mutation_stripe(caller_id).lock_owned().await;

    let res =
        tokio::task::spawn_blocking(move || -> Result<EventSettingsDocument, McBrowserError> {
            let _guard = guard;
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal(
                    "Database unavailable for event settings update".to_string(),
                )
            })?;
            save_event_settings_for_admin_with_conn(&conn, &auth_user, parsed)
        })
        .await;

    match res {
        Ok(Ok(saved)) => no_store_json(StatusCode::OK, saved),
        Ok(Err(e)) => no_store_error(e),
        Err(_) => no_store_error(McBrowserError::Internal(
            "Event settings update task failed".to_string(),
        )),
    }
}

async fn get_admin_event_queue(
    auth_ext: Option<Extension<AuthUser>>,
    query_res: Result<Query<EventQueueListQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let auth_user = match extract_auth_user(auth_ext) {
        Ok(u) => u,
        Err(e) => return no_store_error(e),
    };
    if let Err(e) = super::validate_mcbrowser_user(&auth_user) {
        return no_store_error(e);
    }
    if !auth_user.role.eq_ignore_ascii_case("admin") {
        return no_store_error(McBrowserError::Forbidden(
            "Admin access required to inspect McBrowser event queue".to_string(),
        ));
    }
    let Query(query) = match query_res {
        Ok(q) => q,
        Err(_) => {
            return no_store_error(McBrowserError::BadRequest(
                "Invalid query parameters for event queue".to_string(),
            ))
        }
    };

    let res =
        tokio::task::spawn_blocking(move || -> Result<EventQueueListResponse, McBrowserError> {
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal("Database unavailable for event queue listing".to_string())
            })?;
            list_event_queue_for_admin_with_conn(&conn, &auth_user, &query)
        })
        .await;

    match res {
        Ok(Ok(list)) => no_store_json(StatusCode::OK, list),
        Ok(Err(e)) => no_store_error(e),
        Err(_) => no_store_error(McBrowserError::Internal(
            "Event queue listing task failed".to_string(),
        )),
    }
}

async fn post_admin_ack_event_queue_task(
    auth_ext: Option<Extension<AuthUser>>,
    AxumPath(raw_event_id): AxumPath<String>,
    body: Bytes,
) -> Response {
    let auth_user = match extract_auth_user(auth_ext) {
        Ok(u) => u,
        Err(e) => return no_store_error(e),
    };
    let caller_id = match super::validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return no_store_error(e),
    };
    if !auth_user.role.eq_ignore_ascii_case("admin") {
        return no_store_error(McBrowserError::Forbidden(
            "Admin access required to acknowledge McBrowser event queue tasks".to_string(),
        ));
    }

    if body.len() > MAX_EVENTS_BODY_BYTES {
        return no_store_error(McBrowserError::PayloadTooLarge(
            "Queue acknowledgment request body is too large".to_string(),
        ));
    }
    if !body.is_empty() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EmptyAckBody {}
        let trimmed = std::str::from_utf8(&body).unwrap_or("").trim();
        if !trimmed.is_empty() && serde_json::from_str::<EmptyAckBody>(trimmed).is_err() {
            return no_store_error(McBrowserError::BadRequest(
                "Invalid queue acknowledgment payload".to_string(),
            ));
        }
    }

    let valid_id = match validate_event_uuid(&raw_event_id) {
        Ok(id) => id,
        Err(e) => return no_store_error(e),
    };

    let guard = super::user_mutation_stripe(caller_id).lock_owned().await;

    let res = tokio::task::spawn_blocking(
        move || -> Result<McBrowserQueuedEventTask, McBrowserError> {
            let _guard = guard;
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal(
                    "Database unavailable for event queue acknowledgment".to_string(),
                )
            })?;
            acknowledge_event_queue_task_for_admin_with_conn(&conn, &auth_user, &valid_id)
        },
    )
    .await;

    match res {
        Ok(Ok(task)) => no_store_json(
            StatusCode::OK,
            AcknowledgeQueueTaskResponse {
                success: true,
                task,
            },
        ),
        Ok(Err(e)) => no_store_error(e),
        Err(_) => no_store_error(McBrowserError::Internal(
            "Event queue acknowledgment task failed".to_string(),
        )),
    }
}

#[cfg(test)]
#[path = "events_tests.rs"]
mod events_tests;
