use crate::auth::{api_error, AuthUser};
use crate::streaming_history::HistoryCounts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

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

pub(super) fn ensure_admin(user: &AuthUser) -> ImportResult<()> {
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NativeExportImportRequest {
    pub provider: String,
    pub server_id: String,
    #[serde(default)]
    pub server_name: Option<String>,
    pub source: String,
    pub checkpoint: String,
    #[serde(default)]
    pub expected_checkpoint: Option<String>,
    /// `"json"` or `"csv"`.
    pub format: String,
    /// Raw JSON export payload (`MediaContainer.Metadata` or array) or CSV text string.
    pub payload: serde_json::Value,
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
pub(super) struct SignedApprovalTokenPayload {
    pub(super) version: u8,
    pub(super) actor_id: i64,
    pub(super) preview_hash: String,
    pub(super) history_revision: i64,
    pub(super) history_rows: i64,
    pub(super) candidate_ids: Vec<i64>,
    pub(super) issued_at: i64,
    pub(super) expires_at: i64,
}
