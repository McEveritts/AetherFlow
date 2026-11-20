use crate::auth::{api_error, AuthUser};
use axum::body::{to_bytes, Body};
use axum::extract::Extension;
use axum::http::{header, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{SecondsFormat, TimeZone, Utc};
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::{params, Connection, Row, Statement, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

pub const EXPORT_ROUTE: &str = "/streaming/portability/export";
pub const PREVIEW_ROUTE: &str = "/streaming/portability/preview";
pub const RESTORE_ROUTE: &str = "/streaming/portability/restore";

pub(crate) const HEADER_ARCHIVE_TELEMETRY: &str = "x-aetherflow-archive-telemetry";
pub(crate) const HEADER_OMITTED_SESSION_SAMPLES: &str = "x-aetherflow-omitted-session-samples";
pub(crate) const HEADER_OMITTED_BANDWIDTH_SAMPLES: &str = "x-aetherflow-omitted-bandwidth-samples";

const ARCHIVE_FORMAT: &str = "aetherflow.streaming-history";
const ARCHIVE_FORMAT_VERSION: u16 = 1;
const DATABASE_SCHEMA_VERSION: u16 = 20;
const PROVENANCE_VERSION: u16 = 1;
pub const MAX_ARCHIVE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PORTABILITY_BODY_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_REQUEST_BODY_BYTES: usize = MAX_PORTABILITY_BODY_BYTES;
const MAX_BODY_BYTES: usize = MAX_ARCHIVE_BYTES;
const MAX_PORTABLE_ROWS: usize = 100_000;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_APPROVALS: usize = 512;
const APPROVAL_TTL_SECS: i64 = 300;

const REDACTED_FIELDS: &[&str] = &[
    "streaming_history.device_name",
    "streaming_history.device_id",
    "streaming_history.ip_address",
    "streaming_servers.api_key",
];
const OMITTED_TABLES: &[&str] = &[
    "streaming_servers (connection settings and credentials)",
    "streaming_user_links (AetherFlow-local user IDs)",
    "streaming_import_checkpoints (destination-specific cursors)",
    "streaming_history_audit (destination-local audit trail)",
    "streaming_history_revision (destination-local revision counter)",
];

type PortabilityResult<T> = Result<T, PortabilityError>;

#[derive(Clone, Copy, Debug)]
struct PortabilityError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl PortabilityError {
    const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }

    const fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "admin_required",
            "Admin access required",
        )
    }

    const fn invalid() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_streaming_archive",
            "The streaming archive is malformed or invalid",
        )
    }

    const fn unsupported() -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_streaming_archive",
            "The streaming archive version is not supported",
        )
    }

    const fn too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "streaming_archive_too_large",
            "The streaming archive exceeds the configured size or row limit",
        )
    }

    const fn unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "streaming_portability_unavailable",
            "Streaming portability is temporarily unavailable",
        )
    }

    const fn stale_preview() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "streaming_preview_changed",
            "Streaming data changed after preview; create and approve a new preview",
        )
    }

    const fn invalid_approval() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "streaming_approval_invalid",
            "The approval token is invalid, expired, already used, or belongs to another actor",
        )
    }
}

impl IntoResponse for PortabilityError {
    fn into_response(self) -> Response {
        api_error(self.status, self.code, self.message)
    }
}

impl From<rusqlite::Error> for PortabilityError {
    fn from(error: rusqlite::Error) -> Self {
        tracing::error!(%error, "Streaming portability database operation failed");
        Self::unavailable()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RecordCounts {
    history: usize,
    labels: usize,
    session_samples: usize,
    bandwidth_samples: usize,
    tracking_policies: usize,
}

impl RecordCounts {
    fn total(&self) -> Option<usize> {
        self.history
            .checked_add(self.labels)?
            .checked_add(self.session_samples)?
            .checked_add(self.bandwidth_samples)?
            .checked_add(self.tracking_policies)
    }

    fn zero() -> Self {
        Self {
            history: 0,
            labels: 0,
            session_samples: 0,
            bandwidth_samples: 0,
            tracking_policies: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HistoryRecord {
    id: i64,
    session_key: String,
    provider: String,
    server_name: String,
    user_id: String,
    user_name: String,
    client_name: String,
    item_id: String,
    item_name: String,
    item_type: String,
    series_name: String,
    series_id: String,
    season_number: Option<i64>,
    episode_number: Option<i64>,
    production_year: Option<i64>,
    play_method: String,
    container: String,
    video_codec: String,
    video_resolution: String,
    audio_codec: String,
    audio_channels: Option<i64>,
    subtitle_codec: String,
    hw_accel: String,
    transcode_reasons: String,
    bitrate_bps: Option<i64>,
    duration_secs: Option<i64>,
    watched_secs: Option<i64>,
    data_used_bytes: Option<i64>,
    completion_pct: Option<f64>,
    started_at: Option<String>,
    last_seen_at: Option<String>,
    ended_at: Option<String>,
    is_active: Option<i64>,
    provenance: String,
    server_id: String,
    source_event_id: Option<String>,
    timestamp_certainty: String,
    byte_accuracy: String,
    policy_status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HistoryLabel {
    history_id: i64,
    kind: String,
    value: String,
    name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SessionSample {
    history_id: i64,
    sampled_at: i64,
    observed_secs: i64,
    playing: bool,
    bitrate_bps: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BandwidthSample {
    id: i64,
    timestamp: Option<String>,
    provider: String,
    active_streams: Option<i64>,
    direct_play_count: Option<i64>,
    direct_stream_count: Option<i64>,
    transcode_count: Option<i64>,
    total_bitrate_bps: Option<i64>,
    bytes_delta: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TrackingPolicy {
    minimum_watch_secs: i64,
    excluded_users: String,
    excluded_libraries: String,
    reconnect_window_secs: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ArchiveData {
    history: Vec<HistoryRecord>,
    labels: Vec<HistoryLabel>,
    session_samples: Vec<SessionSample>,
    bandwidth_samples: Vec<BandwidthSample>,
    tracking_policy: TrackingPolicy,
}

impl ArchiveData {
    fn counts(&self) -> RecordCounts {
        RecordCounts {
            history: self.history.len(),
            labels: self.labels.len(),
            session_samples: self.session_samples.len(),
            bandwidth_samples: self.bandwidth_samples.len(),
            tracking_policies: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct OmittedSamples {
    session_samples: usize,
    bandwidth_samples: usize,
}

impl OmittedSamples {
    fn is_empty(&self) -> bool {
        self.session_samples == 0 && self.bandwidth_samples == 0
    }
}

fn deserialize_present_omitted_samples<'de, D>(
    deserializer: D,
) -> Result<Option<OmittedSamples>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    OmittedSamples::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ArchiveManifest {
    format: String,
    format_version: u16,
    schema_version: u16,
    provenance_version: u16,
    exported_at: String,
    record_counts: RecordCounts,
    #[serde(
        default,
        deserialize_with = "deserialize_present_omitted_samples",
        skip_serializing_if = "Option::is_none"
    )]
    omitted_samples: Option<OmittedSamples>,
    redacted_fields: Vec<String>,
    omitted_tables: Vec<String>,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StreamingArchive {
    manifest: ArchiveManifest,
    data: ArchiveData,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArchiveDigestView<'a> {
    format: &'a str,
    format_version: u16,
    schema_version: u16,
    provenance_version: u16,
    exported_at: &'a str,
    record_counts: &'a RecordCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    omitted_samples: Option<&'a OmittedSamples>,
    redacted_fields: &'a [String],
    omitted_tables: &'a [String],
    data: &'a ArchiveData,
}

impl StreamingArchive {
    fn digest(&self) -> PortabilityResult<String> {
        let view = ArchiveDigestView {
            format: &self.manifest.format,
            format_version: self.manifest.format_version,
            schema_version: self.manifest.schema_version,
            provenance_version: self.manifest.provenance_version,
            exported_at: &self.manifest.exported_at,
            record_counts: &self.manifest.record_counts,
            omitted_samples: self.manifest.omitted_samples.as_ref(),
            redacted_fields: &self.manifest.redacted_fields,
            omitted_tables: &self.manifest.omitted_tables,
            data: &self.data,
        };
        let bytes = serde_json::to_vec(&view).map_err(|_| PortabilityError::invalid())?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    fn validate(&self) -> PortabilityResult<()> {
        if self.manifest.format != ARCHIVE_FORMAT
            || self.manifest.format_version != ARCHIVE_FORMAT_VERSION
            || self.manifest.schema_version != DATABASE_SCHEMA_VERSION
            || self.manifest.provenance_version != PROVENANCE_VERSION
        {
            return Err(PortabilityError::unsupported());
        }
        let expected_redactions = REDACTED_FIELDS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        let expected_omitted = OMITTED_TABLES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        if self.manifest.redacted_fields != expected_redactions
            || self.manifest.omitted_tables != expected_omitted
            || DateTimeCheck::is_invalid(&self.manifest.exported_at)
            || self
                .manifest
                .omitted_samples
                .as_ref()
                .is_some_and(OmittedSamples::is_empty)
        {
            return Err(PortabilityError::invalid());
        }
        let counts = self.data.counts();
        if self.manifest.record_counts != counts
            || counts
                .total()
                .filter(|total| *total <= MAX_PORTABLE_ROWS)
                .is_none()
        {
            return Err(PortabilityError::too_large());
        }
        self.validate_rows()?;
        if self.manifest.sha256.len() != 64
            || !self
                .manifest
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.digest()? != self.manifest.sha256.to_ascii_lowercase()
        {
            return Err(PortabilityError::invalid());
        }
        Ok(())
    }

    fn validate_rows(&self) -> PortabilityResult<()> {
        let mut history_ids = HashSet::with_capacity(self.data.history.len());
        let mut session_keys = HashSet::with_capacity(self.data.history.len());
        let mut event_keys = HashSet::with_capacity(self.data.history.len());
        for row in &self.data.history {
            if !history_ids.insert(row.id)
                || !session_keys.insert(row.session_key.clone())
                || !valid_history_text(row)
                || !matches!(
                    row.provenance.as_str(),
                    "legacy_unverified" | "observed_session" | "imported_event" | "item_summary"
                )
                || !matches!(
                    row.timestamp_certainty.as_str(),
                    "legacy_unverified"
                        | "observed"
                        | "source_event"
                        | "last_played"
                        | "unrecorded"
                )
                || !matches!(
                    row.byte_accuracy.as_str(),
                    "legacy_unverified" | "estimated" | "unrecorded"
                )
                || !matches!(
                    row.policy_status.as_str(),
                    "included" | "excluded" | "duplicate" | "ambiguous"
                )
                || row.completion_pct.is_some_and(|value| !value.is_finite())
            {
                return Err(PortabilityError::invalid());
            }
            if let Some(source_event_id) = row
                .source_event_id
                .as_deref()
                .filter(|value| !value.is_empty())
            {
                let event_key = (
                    row.provider.clone(),
                    row.server_id.clone(),
                    source_event_id.to_owned(),
                );
                if !event_keys.insert(event_key) {
                    return Err(PortabilityError::invalid());
                }
            }
        }

        let mut label_keys = HashSet::with_capacity(self.data.labels.len());
        for label in &self.data.labels {
            if !history_ids.contains(&label.history_id)
                || !matches!(label.kind.as_str(), "library" | "genre")
                || !valid_text(&label.value, MAX_TEXT_BYTES)
                || !valid_text(&label.name, MAX_TEXT_BYTES)
                || !label_keys.insert((label.history_id, label.kind.clone(), label.value.clone()))
            {
                return Err(PortabilityError::invalid());
            }
        }

        let mut sample_keys = HashSet::with_capacity(self.data.session_samples.len());
        for sample in &self.data.session_samples {
            if !history_ids.contains(&sample.history_id)
                || !(0..=60).contains(&sample.observed_secs)
                || sample.bitrate_bps < 0
                || !sample_keys.insert((sample.history_id, sample.sampled_at))
            {
                return Err(PortabilityError::invalid());
            }
        }

        let mut bandwidth_ids = HashSet::with_capacity(self.data.bandwidth_samples.len());
        for sample in &self.data.bandwidth_samples {
            if !bandwidth_ids.insert(sample.id)
                || !valid_text(&sample.provider, 256)
                || sample
                    .timestamp
                    .as_deref()
                    .is_some_and(|value| !valid_text(value, MAX_TEXT_BYTES))
            {
                return Err(PortabilityError::invalid());
            }
        }

        let policy = &self.data.tracking_policy;
        if !(0..=86_400).contains(&policy.minimum_watch_secs)
            || !(0..=300).contains(&policy.reconnect_window_secs)
            || !valid_text(&policy.excluded_users, MAX_TEXT_BYTES)
            || !valid_text(&policy.excluded_libraries, MAX_TEXT_BYTES)
            || !json_array(&policy.excluded_users)
            || !json_array(&policy.excluded_libraries)
        {
            return Err(PortabilityError::invalid());
        }
        Ok(())
    }
}

struct DateTimeCheck;

impl DateTimeCheck {
    fn is_invalid(value: &str) -> bool {
        chrono::DateTime::parse_from_rfc3339(value).is_err() || !valid_text(value, 128)
    }
}

fn valid_history_text(row: &HistoryRecord) -> bool {
    [
        row.session_key.as_str(),
        row.provider.as_str(),
        row.server_name.as_str(),
        row.user_id.as_str(),
        row.user_name.as_str(),
        row.client_name.as_str(),
        row.item_id.as_str(),
        row.item_name.as_str(),
        row.item_type.as_str(),
        row.series_name.as_str(),
        row.series_id.as_str(),
        row.play_method.as_str(),
        row.container.as_str(),
        row.video_codec.as_str(),
        row.video_resolution.as_str(),
        row.audio_codec.as_str(),
        row.subtitle_codec.as_str(),
        row.hw_accel.as_str(),
        row.transcode_reasons.as_str(),
        row.server_id.as_str(),
        row.provenance.as_str(),
        row.timestamp_certainty.as_str(),
        row.byte_accuracy.as_str(),
        row.policy_status.as_str(),
    ]
    .iter()
    .all(|value| valid_text(value, MAX_TEXT_BYTES))
        && row
            .started_at
            .as_deref()
            .is_none_or(|value| valid_text(value, 128))
        && row
            .last_seen_at
            .as_deref()
            .is_none_or(|value| valid_text(value, 128))
        && row
            .ended_at
            .as_deref()
            .is_none_or(|value| valid_text(value, 128))
        && row
            .source_event_id
            .as_deref()
            .is_none_or(|value| valid_text(value, MAX_TEXT_BYTES))
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes && !value.contains('\0')
}

fn json_array(value: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(value)
        .ok()
        .is_some_and(|parsed| parsed.is_array())
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum RestoreMode {
    Merge,
    Replace,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PreviewRequest {
    mode: RestoreMode,
    archive: StreamingArchive,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RestoreRequest {
    mode: RestoreMode,
    archive: StreamingArchive,
    approval_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Conflict {
    table: String,
    archive_key: String,
    existing_key: Option<String>,
    reason: String,
    action: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PlanCounts {
    insert: RecordCounts,
    exact_duplicate: RecordCounts,
    conflict: RecordCounts,
}

impl Default for RecordCounts {
    fn default() -> Self {
        Self::zero()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PreviewResponse {
    mode: RestoreMode,
    archive_sha256: String,
    preview_sha256: String,
    expires_at: String,
    archive_counts: RecordCounts,
    target_counts: RecordCounts,
    plan: PlanCounts,
    replacement_counts: Option<RecordCounts>,
    replacement_notice: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    omitted_samples: Option<OmittedSamples>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    partial_telemetry_notice: Option<String>,
    conflicts: Vec<Conflict>,
    approval_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RestoreResponse {
    mode: RestoreMode,
    archive_sha256: String,
    preview_sha256: String,
    backup_verified: bool,
    archive_counts: RecordCounts,
    resulting_counts: RecordCounts,
    plan: PlanCounts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    omitted_samples: Option<OmittedSamples>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    partial_telemetry_notice: Option<String>,
    conflicts: Vec<Conflict>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditSummary<'a> {
    counts: &'a RecordCounts,
    snapshot_sha256: &'a str,
}

#[derive(Clone, Debug)]
struct Approval {
    actor_id: i64,
    mode: RestoreMode,
    archive_sha256: String,
    preview_sha256: String,
    expires_at: i64,
}

static APPROVALS: Lazy<Mutex<HashMap<String, Approval>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn issue_approval(
    actor_id: i64,
    mode: RestoreMode,
    archive_sha256: &str,
    preview_sha256: &str,
    now: i64,
) -> PortabilityResult<(String, i64)> {
    let expires_at = now
        .checked_add(APPROVAL_TTL_SECS)
        .ok_or_else(PortabilityError::invalid)?;
    let mut approvals = APPROVALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    approvals.retain(|_, approval| approval.expires_at > now);
    if approvals.len() >= MAX_APPROVALS {
        return Err(PortabilityError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_streaming_previews",
            "Too many pending streaming restore previews; retry after they expire",
        ));
    }
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let token = URL_SAFE_NO_PAD.encode(random);
    approvals.insert(
        token.clone(),
        Approval {
            actor_id,
            mode,
            archive_sha256: archive_sha256.to_owned(),
            preview_sha256: preview_sha256.to_owned(),
            expires_at,
        },
    );
    Ok((token, expires_at))
}

fn revoke_approval(token: &str) {
    APPROVALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(token);
}

fn consume_approval(
    token: &str,
    actor_id: i64,
    mode: RestoreMode,
    archive_sha256: &str,
    now: i64,
) -> PortabilityResult<Approval> {
    if token.len() > 128 {
        return Err(PortabilityError::invalid_approval());
    }
    let mut approvals = APPROVALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let approval = approvals
        .get(token)
        .cloned()
        .ok_or_else(PortabilityError::invalid_approval)?;
    if approval.expires_at <= now {
        approvals.remove(token);
        return Err(PortabilityError::invalid_approval());
    }
    if approval.actor_id != actor_id
        || approval.mode != mode
        || approval.archive_sha256 != archive_sha256
    {
        return Err(PortabilityError::invalid_approval());
    }
    approvals.remove(token);
    Ok(approval)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PortableSnapshot {
    history: Vec<HistoryRecord>,
    labels: Vec<HistoryLabel>,
    session_samples: Vec<SessionSample>,
    bandwidth_samples: Vec<BandwidthSample>,
    tracking_policy: TrackingPolicy,
}

impl PortableSnapshot {
    fn counts(&self) -> RecordCounts {
        RecordCounts {
            history: self.history.len(),
            labels: self.labels.len(),
            session_samples: self.session_samples.len(),
            bandwidth_samples: self.bandwidth_samples.len(),
            tracking_policies: 1,
        }
    }

    fn into_data(self) -> ArchiveData {
        ArchiveData {
            history: self.history,
            labels: self.labels,
            session_samples: self.session_samples,
            bandwidth_samples: self.bandwidth_samples,
            tracking_policy: self.tracking_policy,
        }
    }

    fn digest(&self) -> PortabilityResult<String> {
        let bytes = serde_json::to_vec(self).map_err(|_| PortabilityError::invalid())?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

struct LoadedSnapshot {
    snapshot: PortableSnapshot,
    omitted_samples: Option<OmittedSamples>,
}

fn load_snapshot(conn: &Connection) -> PortabilityResult<LoadedSnapshot> {
    load_snapshot_with_budget(conn, MAX_PORTABLE_ROWS)
}

fn load_snapshot_with_budget(
    conn: &Connection,
    max_portable_rows: usize,
) -> PortabilityResult<LoadedSnapshot> {
    let budget = max_portable_rows.min(MAX_PORTABLE_ROWS);
    ensure_snapshot_bounds(conn, budget)?;
    let history = load_rows(conn, "SELECT id,session_key,provider,server_name,user_id,user_name,client_name,item_id,item_name,item_type,series_name,series_id,season_number,episode_number,production_year,play_method,container,video_codec,video_resolution,audio_codec,audio_channels,subtitle_codec,hw_accel,transcode_reasons,bitrate_bps,duration_secs,watched_secs,data_used_bytes,completion_pct,started_at,last_seen_at,ended_at,is_active,provenance,server_id,source_event_id,timestamp_certainty,byte_accuracy,policy_status FROM streaming_history ORDER BY id", read_history)?;
    let labels = load_rows(conn, "SELECT history_id,kind,value,name FROM streaming_history_labels ORDER BY history_id,kind,value", read_label)?;
    let base_used = history
        .len()
        .checked_add(labels.len())
        .and_then(|n| n.checked_add(1))
        .filter(|&n| n <= budget)
        .ok_or_else(PortabilityError::too_large)?;
    let remaining_sample_budget = budget - base_used;
    let half_budget = remaining_sample_budget / 2;

    let session_count: usize = conn
        .query_row("SELECT COUNT(*) FROM streaming_session_samples", [], |r| {
            r.get::<_, i64>(0)
        })?
        .max(0) as usize;
    let bw_count: usize = conn
        .query_row(
            "SELECT COUNT(*) FROM streaming_bandwidth_samples",
            [],
            |r| r.get::<_, i64>(0),
        )?
        .max(0) as usize;

    let (session_cap, bw_cap) = if session_count.saturating_add(bw_count) <= remaining_sample_budget
    {
        (session_count, bw_count)
    } else if session_count <= half_budget {
        (session_count, remaining_sample_budget - session_count)
    } else if bw_count <= remaining_sample_budget - half_budget {
        (remaining_sample_budget - bw_count, bw_count)
    } else {
        (half_budget, remaining_sample_budget - half_budget)
    };

    let session_samples = if session_count <= session_cap {
        load_rows(
            conn,
            "SELECT history_id,sampled_at,observed_secs,playing,bitrate_bps FROM streaming_session_samples ORDER BY history_id,sampled_at",
            read_sample,
        )?
    } else {
        load_rows(
            conn,
            &format!(
                "SELECT history_id,sampled_at,observed_secs,playing,bitrate_bps FROM (SELECT history_id,sampled_at,observed_secs,playing,bitrate_bps FROM streaming_session_samples ORDER BY sampled_at DESC, history_id DESC LIMIT {session_cap}) ORDER BY history_id,sampled_at"
            ),
            read_sample,
        )?
    };
    let bandwidth_samples = if bw_count <= bw_cap {
        load_rows(
            conn,
            "SELECT id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta FROM streaming_bandwidth_samples ORDER BY id",
            read_bandwidth_sample,
        )?
    } else {
        load_rows(
            conn,
            &format!(
                "SELECT id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta FROM (SELECT id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta FROM streaming_bandwidth_samples ORDER BY julianday(timestamp) DESC, id DESC LIMIT {bw_cap}) ORDER BY id"
            ),
            read_bandwidth_sample,
        )?
    };
    let tracking_policy = conn.query_row(
        "SELECT minimum_watch_secs,excluded_users,excluded_libraries,reconnect_window_secs FROM streaming_tracking_policies WHERE id=1",
        [],
        |row| Ok(TrackingPolicy {
            minimum_watch_secs: row.get(0)?,
            excluded_users: row.get(1)?,
            excluded_libraries: row.get(2)?,
            reconnect_window_secs: row.get(3)?,
        }),
    )?;
    let omitted_session_samples = session_count.saturating_sub(session_samples.len());
    let omitted_bandwidth_samples = bw_count.saturating_sub(bandwidth_samples.len());
    let omitted_samples =
        (omitted_session_samples > 0 || omitted_bandwidth_samples > 0).then_some(OmittedSamples {
            session_samples: omitted_session_samples,
            bandwidth_samples: omitted_bandwidth_samples,
        });
    let snapshot = PortableSnapshot {
        history,
        labels,
        session_samples,
        bandwidth_samples,
        tracking_policy,
    };
    if snapshot
        .counts()
        .total()
        .filter(|total| *total <= budget)
        .is_none()
    {
        return Err(PortabilityError::too_large());
    }
    Ok(LoadedSnapshot {
        snapshot,
        omitted_samples,
    })
}

fn ensure_snapshot_bounds(conn: &Connection, max_portable_rows: usize) -> PortabilityResult<()> {
    let (history_rows, label_rows, policy_rows) = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM streaming_history),(SELECT COUNT(*) FROM streaming_history_labels),(SELECT COUNT(*) FROM streaming_tracking_policies)",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?.max(0) as usize,
                row.get::<_, i64>(1)?.max(0) as usize,
                row.get::<_, i64>(2)?.max(0) as usize,
            ))
        },
    )?;
    if policy_rows != 1 {
        return Err(PortabilityError::unavailable());
    }
    if history_rows
        .checked_add(label_rows)
        .and_then(|n| n.checked_add(policy_rows))
        .filter(|total| *total <= max_portable_rows)
        .is_none()
    {
        return Err(PortabilityError::too_large());
    }
    let text_bytes: f64 = conn.query_row(
        "SELECT
            (SELECT total(length(CAST(COALESCE(session_key,'') AS BLOB))+length(CAST(COALESCE(provider,'') AS BLOB))+length(CAST(COALESCE(server_name,'') AS BLOB))+length(CAST(COALESCE(user_id,'') AS BLOB))+length(CAST(COALESCE(user_name,'') AS BLOB))+length(CAST(COALESCE(client_name,'') AS BLOB))+length(CAST(COALESCE(item_id,'') AS BLOB))+length(CAST(COALESCE(item_name,'') AS BLOB))+length(CAST(COALESCE(item_type,'') AS BLOB))+length(CAST(COALESCE(series_name,'') AS BLOB))+length(CAST(COALESCE(series_id,'') AS BLOB))+length(CAST(COALESCE(play_method,'') AS BLOB))+length(CAST(COALESCE(container,'') AS BLOB))+length(CAST(COALESCE(video_codec,'') AS BLOB))+length(CAST(COALESCE(video_resolution,'') AS BLOB))+length(CAST(COALESCE(audio_codec,'') AS BLOB))+length(CAST(COALESCE(subtitle_codec,'') AS BLOB))+length(CAST(COALESCE(hw_accel,'') AS BLOB))+length(CAST(COALESCE(transcode_reasons,'') AS BLOB))+length(CAST(COALESCE(started_at,'') AS BLOB))+length(CAST(COALESCE(last_seen_at,'') AS BLOB))+length(CAST(COALESCE(ended_at,'') AS BLOB))+length(CAST(COALESCE(provenance,'') AS BLOB))+length(CAST(COALESCE(server_id,'') AS BLOB))+length(CAST(COALESCE(source_event_id,'') AS BLOB))+length(CAST(COALESCE(timestamp_certainty,'') AS BLOB))+length(CAST(COALESCE(byte_accuracy,'') AS BLOB))+length(CAST(COALESCE(policy_status,'') AS BLOB))) FROM streaming_history) +
            (SELECT total(length(CAST(COALESCE(device_name,'') AS BLOB))+length(CAST(COALESCE(device_id,'') AS BLOB))+length(CAST(COALESCE(ip_address,'') AS BLOB))) FROM streaming_history) +
            (SELECT total(length(CAST(COALESCE(kind,'') AS BLOB))+length(CAST(COALESCE(value,'') AS BLOB))+length(CAST(COALESCE(name,'') AS BLOB))) FROM streaming_history_labels) +
            (SELECT total(length(CAST(COALESCE(excluded_users,'') AS BLOB))+length(CAST(COALESCE(excluded_libraries,'') AS BLOB))) FROM streaming_tracking_policies)",
        [],
        |row| row.get(0),
    )?;
    if !text_bytes.is_finite() || text_bytes > MAX_ARCHIVE_BYTES as f64 {
        return Err(PortabilityError::too_large());
    }
    Ok(())
}

fn load_rows<T>(
    conn: &Connection,
    sql: &str,
    decode: fn(&Row<'_>) -> rusqlite::Result<T>,
) -> PortabilityResult<Vec<T>> {
    let mut statement = conn.prepare(sql)?;
    let mut rows = statement.query([])?;
    let mut values = Vec::new();
    while let Some(row) = rows.next()? {
        if values.len() >= MAX_PORTABLE_ROWS {
            return Err(PortabilityError::too_large());
        }
        values.push(decode(row)?);
    }
    Ok(values)
}

fn read_history(row: &Row<'_>) -> rusqlite::Result<HistoryRecord> {
    Ok(HistoryRecord {
        id: row.get(0)?,
        session_key: row.get(1)?,
        provider: row.get(2)?,
        server_name: row.get(3)?,
        user_id: row.get(4)?,
        user_name: row.get(5)?,
        client_name: row.get(6)?,
        item_id: row.get(7)?,
        item_name: row.get(8)?,
        item_type: row.get(9)?,
        series_name: row.get(10)?,
        series_id: row.get(11)?,
        season_number: row.get(12)?,
        episode_number: row.get(13)?,
        production_year: row.get(14)?,
        play_method: row.get(15)?,
        container: row.get(16)?,
        video_codec: row.get(17)?,
        video_resolution: row.get(18)?,
        audio_codec: row.get(19)?,
        audio_channels: row.get(20)?,
        subtitle_codec: row.get(21)?,
        hw_accel: row.get(22)?,
        transcode_reasons: row.get(23)?,
        bitrate_bps: row.get(24)?,
        duration_secs: row.get(25)?,
        watched_secs: row.get(26)?,
        data_used_bytes: row.get(27)?,
        completion_pct: row.get(28)?,
        started_at: row.get(29)?,
        last_seen_at: row.get(30)?,
        ended_at: row.get(31)?,
        is_active: row.get(32)?,
        provenance: row.get(33)?,
        server_id: row.get(34)?,
        source_event_id: row.get(35)?,
        timestamp_certainty: row.get(36)?,
        byte_accuracy: row.get(37)?,
        policy_status: row.get(38)?,
    })
}

fn read_label(row: &Row<'_>) -> rusqlite::Result<HistoryLabel> {
    Ok(HistoryLabel {
        history_id: row.get(0)?,
        kind: row.get(1)?,
        value: row.get(2)?,
        name: row.get(3)?,
    })
}

fn read_sample(row: &Row<'_>) -> rusqlite::Result<SessionSample> {
    Ok(SessionSample {
        history_id: row.get(0)?,
        sampled_at: row.get(1)?,
        observed_secs: row.get(2)?,
        playing: row.get::<_, i64>(3)? != 0,
        bitrate_bps: row.get(4)?,
    })
}

fn read_bandwidth_sample(row: &Row<'_>) -> rusqlite::Result<BandwidthSample> {
    Ok(BandwidthSample {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        provider: row.get(2)?,
        active_streams: row.get(3)?,
        direct_play_count: row.get(4)?,
        direct_stream_count: row.get(5)?,
        transcode_count: row.get(6)?,
        total_bitrate_bps: row.get(7)?,
        bytes_delta: row.get(8)?,
    })
}

fn build_archive(conn: &Connection, now: i64) -> PortabilityResult<StreamingArchive> {
    build_archive_with_budget(conn, now, MAX_PORTABLE_ROWS)
}

fn build_archive_with_budget(
    conn: &Connection,
    now: i64,
    max_portable_rows: usize,
) -> PortabilityResult<StreamingArchive> {
    let tx = conn.unchecked_transaction()?;
    let loaded = load_snapshot_with_budget(&tx, max_portable_rows)?;
    let data = loaded.snapshot.into_data();
    let record_counts = data.counts();
    let mut archive = StreamingArchive {
        manifest: ArchiveManifest {
            format: ARCHIVE_FORMAT.to_owned(),
            format_version: ARCHIVE_FORMAT_VERSION,
            schema_version: DATABASE_SCHEMA_VERSION,
            provenance_version: PROVENANCE_VERSION,
            exported_at: Utc
                .timestamp_opt(now, 0)
                .single()
                .ok_or_else(PortabilityError::invalid)?
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            record_counts,
            omitted_samples: loaded.omitted_samples,
            redacted_fields: REDACTED_FIELDS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            omitted_tables: OMITTED_TABLES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            sha256: String::new(),
        },
        data,
    };
    archive.manifest.sha256 = archive.digest()?;
    archive.validate()?;
    let bytes = serde_json::to_vec(&archive).map_err(|_| PortabilityError::invalid())?;
    if bytes.len() > MAX_BODY_BYTES {
        return Err(PortabilityError::too_large());
    }
    tx.commit()?;
    Ok(archive)
}

#[cfg(test)]
pub(crate) fn export_archive_json_with_budget(
    conn: &Connection,
    now: i64,
    max_portable_rows: usize,
) -> serde_json::Value {
    let archive = build_archive_with_budget(conn, now, max_portable_rows).unwrap();
    serde_json::to_value(&archive).unwrap()
}

#[cfg(test)]
fn validate_archive_bytes(bytes: &[u8]) -> PortabilityResult<StreamingArchive> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(PortabilityError::too_large());
    }
    let archive: StreamingArchive =
        serde_json::from_slice(bytes).map_err(|_| PortabilityError::invalid())?;
    archive.validate()?;
    Ok(archive)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewFingerprint<'a> {
    archive_sha256: &'a str,
    mode: RestoreMode,
    target_snapshot_sha256: &'a str,
    plan: &'a PlanCounts,
    replacement_counts: &'a Option<RecordCounts>,
    conflicts: &'a [Conflict],
}

#[derive(Clone, Debug)]
struct MergePlan {
    counts: PlanCounts,
    conflicts: Vec<Conflict>,
    history_map: BTreeMap<i64, Option<i64>>,
    history_inserts: Vec<HistoryRecord>,
    label_inserts: Vec<HistoryLabel>,
    sample_inserts: Vec<SessionSample>,
    bandwidth_inserts: Vec<BandwidthSample>,
}

#[derive(Clone, Debug)]
struct RestorePreview {
    mode: RestoreMode,
    archive_sha256: String,
    preview_sha256: String,
    archive_counts: RecordCounts,
    target_counts: RecordCounts,
    plan: PlanCounts,
    replacement_counts: Option<RecordCounts>,
    omitted_samples: Option<OmittedSamples>,
    conflicts: Vec<Conflict>,
    merge_plan: Option<MergePlan>,
}

fn inspect_restore(
    conn: &Connection,
    archive: &StreamingArchive,
    mode: RestoreMode,
) -> PortabilityResult<RestorePreview> {
    let tx = conn.unchecked_transaction()?;
    let preview = inspect_restore_in_snapshot(&tx, archive, mode)?;
    tx.commit()?;
    Ok(preview)
}

fn hash_json_record<T: Serialize>(hasher: &mut Sha256, value: &T) -> PortabilityResult<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| PortabilityError::invalid())?;
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(&bytes);
    Ok(())
}

fn query_target_counts_and_digest_sql(
    conn: &Connection,
) -> PortabilityResult<(RecordCounts, String)> {
    let counts = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM streaming_history),(SELECT COUNT(*) FROM streaming_history_labels),(SELECT COUNT(*) FROM streaming_session_samples),(SELECT COUNT(*) FROM streaming_bandwidth_samples),(SELECT COUNT(*) FROM streaming_tracking_policies)",
        [],
        |row| {
            Ok(RecordCounts {
                history: row.get::<_, i64>(0)?.max(0) as usize,
                labels: row.get::<_, i64>(1)?.max(0) as usize,
                session_samples: row.get::<_, i64>(2)?.max(0) as usize,
                bandwidth_samples: row.get::<_, i64>(3)?.max(0) as usize,
                tracking_policies: row.get::<_, i64>(4)?.max(0) as usize,
            })
        },
    )?;
    if counts.tracking_policies != 1 {
        return Err(PortabilityError::unavailable());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"af-streaming-sql-target-v1");
    hash_json_record(&mut hasher, &counts)?;

    {
        let mut stmt = conn.prepare(
            "SELECT id,session_key,provider,server_name,user_id,user_name,client_name,item_id,item_name,item_type,series_name,series_id,season_number,episode_number,production_year,play_method,container,video_codec,video_resolution,audio_codec,audio_channels,subtitle_codec,hw_accel,transcode_reasons,bitrate_bps,duration_secs,watched_secs,data_used_bytes,completion_pct,started_at,last_seen_at,ended_at,is_active,provenance,server_id,source_event_id,timestamp_certainty,byte_accuracy,policy_status,device_name,device_id,ip_address FROM streaming_history ORDER BY id",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let rec = read_history(row)?;
            hash_json_record(&mut hasher, &rec)?;
            for index in 39..=41 {
                let value: Option<String> = row.get(index)?;
                match value {
                    Some(v) => {
                        hasher.update([1]);
                        hasher.update((v.len() as u64).to_be_bytes());
                        hasher.update(v.as_bytes());
                    }
                    None => hasher.update([0]),
                }
            }
        }
    }
    {
        let mut stmt = conn.prepare(
            "SELECT history_id,kind,value,name FROM streaming_history_labels ORDER BY history_id,kind,value",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let rec = read_label(row)?;
            hash_json_record(&mut hasher, &rec)?;
        }
    }
    {
        let mut stmt = conn.prepare(
            "SELECT history_id,sampled_at,observed_secs,playing,bitrate_bps FROM streaming_session_samples ORDER BY history_id,sampled_at",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let rec = read_sample(row)?;
            hash_json_record(&mut hasher, &rec)?;
        }
    }
    {
        let mut stmt = conn.prepare(
            "SELECT id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta FROM streaming_bandwidth_samples ORDER BY id",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let rec = read_bandwidth_sample(row)?;
            hash_json_record(&mut hasher, &rec)?;
        }
    }
    let tracking_policy = conn.query_row(
        "SELECT minimum_watch_secs,excluded_users,excluded_libraries,reconnect_window_secs FROM streaming_tracking_policies WHERE id=1",
        [],
        |row| {
            Ok(TrackingPolicy {
                minimum_watch_secs: row.get(0)?,
                excluded_users: row.get(1)?,
                excluded_libraries: row.get(2)?,
                reconnect_window_secs: row.get(3)?,
            })
        },
    )?;
    hash_json_record(&mut hasher, &tracking_policy)?;

    Ok((counts, hex::encode(hasher.finalize())))
}

fn inspect_restore_in_snapshot(
    conn: &Connection,
    archive: &StreamingArchive,
    mode: RestoreMode,
) -> PortabilityResult<RestorePreview> {
    let archive_sha256 = archive.manifest.sha256.clone();
    let (target_counts, target_snapshot_sha256, plan, conflicts, replacement_counts, merge_plan) =
        match mode {
            RestoreMode::Merge => {
                let target = load_snapshot(conn)?.snapshot;
                let target_counts = target.counts();
                let target_snapshot_sha256 = target_snapshot_digest(conn, &target)?;
                let merge = plan_merge(&target, &archive.data);
                (
                    target_counts,
                    target_snapshot_sha256,
                    merge.counts.clone(),
                    merge.conflicts.clone(),
                    None,
                    Some(merge),
                )
            }
            RestoreMode::Replace => {
                let (target_counts, target_snapshot_sha256) =
                    query_target_counts_and_digest_sql(conn)?;
                let plan = PlanCounts {
                    insert: archive.data.counts(),
                    ..Default::default()
                };
                let replacement_counts = Some(target_counts.clone());
                (
                    target_counts,
                    target_snapshot_sha256,
                    plan,
                    Vec::new(),
                    replacement_counts,
                    None,
                )
            }
        };
    let fingerprint = PreviewFingerprint {
        archive_sha256: &archive_sha256,
        mode,
        target_snapshot_sha256: &target_snapshot_sha256,
        plan: &plan,
        replacement_counts: &replacement_counts,
        conflicts: &conflicts,
    };
    let bytes = serde_json::to_vec(&fingerprint).map_err(|_| PortabilityError::invalid())?;
    let preview_sha256 = hex::encode(Sha256::digest(bytes));
    Ok(RestorePreview {
        mode,
        archive_sha256,
        preview_sha256,
        archive_counts: archive.data.counts(),
        target_counts,
        plan,
        replacement_counts,
        omitted_samples: archive.manifest.omitted_samples.clone(),
        conflicts,
        merge_plan,
    })
}

fn target_snapshot_digest(
    conn: &Connection,
    snapshot: &PortableSnapshot,
) -> PortabilityResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(snapshot.digest()?.as_bytes());
    let mut statement = conn
        .prepare("SELECT id,device_name,device_id,ip_address FROM streaming_history ORDER BY id")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        hasher.update(row.get::<_, i64>(0)?.to_be_bytes());
        for index in 1..=3 {
            let value: Option<String> = row.get(index)?;
            match value {
                Some(value) => {
                    hasher.update([1]);
                    hasher.update((value.len() as u64).to_be_bytes());
                    hasher.update(value.as_bytes());
                }
                None => hasher.update([0]),
            }
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

fn event_key(row: &HistoryRecord) -> Option<(String, String, String)> {
    row.source_event_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|event_id| {
            (
                row.provider.clone(),
                row.server_id.clone(),
                event_id.to_owned(),
            )
        })
}

fn history_equivalent(left: &HistoryRecord, right: &HistoryRecord) -> bool {
    left.session_key == right.session_key
        && left.provider == right.provider
        && left.server_name == right.server_name
        && left.user_id == right.user_id
        && left.user_name == right.user_name
        && left.client_name == right.client_name
        && left.item_id == right.item_id
        && left.item_name == right.item_name
        && left.item_type == right.item_type
        && left.series_name == right.series_name
        && left.series_id == right.series_id
        && left.season_number == right.season_number
        && left.episode_number == right.episode_number
        && left.production_year == right.production_year
        && left.play_method == right.play_method
        && left.container == right.container
        && left.video_codec == right.video_codec
        && left.video_resolution == right.video_resolution
        && left.audio_codec == right.audio_codec
        && left.audio_channels == right.audio_channels
        && left.subtitle_codec == right.subtitle_codec
        && left.hw_accel == right.hw_accel
        && left.transcode_reasons == right.transcode_reasons
        && left.bitrate_bps == right.bitrate_bps
        && left.duration_secs == right.duration_secs
        && left.watched_secs == right.watched_secs
        && left.data_used_bytes == right.data_used_bytes
        && left.completion_pct == right.completion_pct
        && left.started_at == right.started_at
        && left.last_seen_at == right.last_seen_at
        && left.ended_at == right.ended_at
        && left.is_active == right.is_active
        && left.provenance == right.provenance
        && left.server_id == right.server_id
        && left.source_event_id == right.source_event_id
        && left.timestamp_certainty == right.timestamp_certainty
        && left.byte_accuracy == right.byte_accuracy
        && left.policy_status == right.policy_status
}

fn conflict(
    table: &str,
    archive_key: String,
    existing_key: Option<String>,
    reason: &str,
) -> Conflict {
    Conflict {
        table: table.to_owned(),
        archive_key,
        existing_key,
        reason: reason.to_owned(),
        action: "skip".to_owned(),
    }
}

fn plan_merge(target: &PortableSnapshot, archive: &ArchiveData) -> MergePlan {
    let mut result = MergePlan {
        counts: PlanCounts::default(),
        conflicts: Vec::new(),
        history_map: BTreeMap::new(),
        history_inserts: Vec::new(),
        label_inserts: Vec::new(),
        sample_inserts: Vec::new(),
        bandwidth_inserts: Vec::new(),
    };

    let mut occupied_history_ids = target
        .history
        .iter()
        .chain(archive.history.iter())
        .map(|row| row.id)
        .collect::<HashSet<_>>();
    let target_history_ids = target
        .history
        .iter()
        .map(|row| row.id)
        .collect::<HashSet<_>>();
    let mut next_history_id = 1_i64;
    let target_session_keys = target
        .history
        .iter()
        .map(|row| (row.session_key.as_str(), row))
        .collect::<HashMap<_, _>>();
    let target_event_keys = target
        .history
        .iter()
        .filter_map(|row| event_key(row).map(|key| (key, row)))
        .collect::<HashMap<_, _>>();

    for row in &archive.history {
        let mut matches = HashMap::<i64, &HistoryRecord>::new();
        if let Some(existing) = target_session_keys.get(row.session_key.as_str()) {
            matches.insert(existing.id, *existing);
        }
        if let Some(key) = event_key(row) {
            if let Some(existing) = target_event_keys.get(&key) {
                matches.insert(existing.id, *existing);
            }
        }
        let mut ids = matches.keys().copied().collect::<Vec<_>>();
        ids.sort_unstable();
        match ids.as_slice() {
            [] => {
                let mut mapped = row.clone();
                if target_history_ids.contains(&row.id) {
                    while occupied_history_ids.contains(&next_history_id) {
                        next_history_id += 1;
                    }
                    mapped.id = next_history_id;
                    occupied_history_ids.insert(mapped.id);
                }
                result.history_map.insert(row.id, Some(mapped.id));
                result.history_inserts.push(mapped);
                result.counts.insert.history += 1;
            }
            [existing_id] => {
                let existing = matches[existing_id];
                if history_equivalent(existing, row) {
                    result.history_map.insert(row.id, Some(*existing_id));
                    result.counts.exact_duplicate.history += 1;
                } else {
                    result.history_map.insert(row.id, None);
                    result.counts.conflict.history += 1;
                    result.conflicts.push(conflict(
                        "streaming_history",
                        row.id.to_string(),
                        Some(existing_id.to_string()),
                        "history_identity_collision",
                    ));
                }
            }
            _ => {
                result.history_map.insert(row.id, None);
                result.counts.conflict.history += 1;
                result.conflicts.push(conflict(
                    "streaming_history",
                    row.id.to_string(),
                    Some(ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",")),
                    "unique_identities_match_different_rows",
                ));
            }
        }
    }

    let target_labels = target
        .labels
        .iter()
        .map(|label| {
            (
                (label.history_id, label.kind.as_str(), label.value.as_str()),
                label.name.as_str(),
            )
        })
        .collect::<HashMap<_, _>>();
    for label in &archive.labels {
        let Some(mapped_id) = result.history_map.get(&label.history_id).copied().flatten() else {
            result.counts.conflict.labels += 1;
            result.conflicts.push(conflict(
                "streaming_history_labels",
                format!("{}:{}:{}", label.history_id, label.kind, label.value),
                None,
                "parent_history_conflict",
            ));
            continue;
        };
        match target_labels.get(&(mapped_id, label.kind.as_str(), label.value.as_str())) {
            None => {
                let mut mapped = label.clone();
                mapped.history_id = mapped_id;
                result.label_inserts.push(mapped);
                result.counts.insert.labels += 1;
            }
            Some(existing_name) if *existing_name == label.name => {
                result.counts.exact_duplicate.labels += 1;
            }
            Some(_) => {
                result.counts.conflict.labels += 1;
                result.conflicts.push(conflict(
                    "streaming_history_labels",
                    format!("{}:{}:{}", label.history_id, label.kind, label.value),
                    Some(format!("{}:{}:{}", mapped_id, label.kind, label.value)),
                    "label_name_collision",
                ));
            }
        }
    }

    let target_samples = target
        .session_samples
        .iter()
        .map(|sample| {
            (
                (sample.history_id, sample.sampled_at),
                (sample.observed_secs, sample.playing, sample.bitrate_bps),
            )
        })
        .collect::<HashMap<_, _>>();
    for sample in &archive.session_samples {
        let Some(mapped_id) = result
            .history_map
            .get(&sample.history_id)
            .copied()
            .flatten()
        else {
            result.counts.conflict.session_samples += 1;
            result.conflicts.push(conflict(
                "streaming_session_samples",
                format!("{}:{}", sample.history_id, sample.sampled_at),
                None,
                "parent_history_conflict",
            ));
            continue;
        };
        let key = (mapped_id, sample.sampled_at);
        match target_samples.get(&key) {
            None => {
                let mut mapped = sample.clone();
                mapped.history_id = mapped_id;
                result.sample_inserts.push(mapped);
                result.counts.insert.session_samples += 1;
            }
            Some(existing)
                if *existing == (sample.observed_secs, sample.playing, sample.bitrate_bps) =>
            {
                result.counts.exact_duplicate.session_samples += 1;
            }
            Some(_) => {
                result.counts.conflict.session_samples += 1;
                result.conflicts.push(conflict(
                    "streaming_session_samples",
                    format!("{}:{}", sample.history_id, sample.sampled_at),
                    Some(format!("{}:{}", mapped_id, sample.sampled_at)),
                    "sample_value_collision",
                ));
            }
        }
    }

    let bandwidth_values = |sample: &BandwidthSample| {
        (
            sample.active_streams,
            sample.direct_play_count,
            sample.direct_stream_count,
            sample.transcode_count,
            sample.total_bitrate_bps,
            sample.bytes_delta,
        )
    };
    let mut target_bandwidth = HashMap::with_capacity(target.bandwidth_samples.len());
    for sample in &target.bandwidth_samples {
        target_bandwidth
            .entry((sample.timestamp.as_deref(), sample.provider.as_str()))
            .or_insert_with(|| (sample.id, bandwidth_values(sample)));
    }
    for sample in &archive.bandwidth_samples {
        let natural_key = (sample.timestamp.as_deref(), sample.provider.as_str());
        match target_bandwidth.get(&natural_key) {
            None => {
                target_bandwidth.insert(natural_key, (sample.id, bandwidth_values(sample)));
                result.bandwidth_inserts.push(sample.clone());
                result.counts.insert.bandwidth_samples += 1;
            }
            Some((_, existing_vals)) if *existing_vals == bandwidth_values(sample) => {
                result.counts.exact_duplicate.bandwidth_samples += 1;
            }
            Some((existing_id, _)) => {
                let key_label = format!(
                    "{}:{}",
                    sample.provider,
                    sample.timestamp.as_deref().unwrap_or("null")
                );
                result.counts.conflict.bandwidth_samples += 1;
                result.conflicts.push(conflict(
                    "streaming_bandwidth_samples",
                    key_label,
                    Some(existing_id.to_string()),
                    "bandwidth_sample_collision",
                ));
            }
        }
    }

    if target.tracking_policy == archive.tracking_policy {
        result.counts.exact_duplicate.tracking_policies = 1;
    } else {
        result.counts.conflict.tracking_policies = 1;
        result.conflicts.push(conflict(
            "streaming_tracking_policies",
            "1".to_owned(),
            Some("1".to_owned()),
            "tracking_policy_collision",
        ));
    }
    result
}

fn partial_telemetry_notice(mode: RestoreMode, omitted: &OmittedSamples) -> String {
    match mode {
        RestoreMode::Replace => format!(
            "Partial telemetry archive: {} earlier session sample(s) and {} earlier bandwidth sample(s) were omitted during export. Replacement deletes existing destination samples and restores only the retained sample subset.",
            omitted.session_samples, omitted.bandwidth_samples
        ),
        RestoreMode::Merge => format!(
            "Partial telemetry archive: {} earlier session sample(s) and {} earlier bandwidth sample(s) were omitted during export. Merge will not restore those omitted earlier samples.",
            omitted.session_samples, omitted.bandwidth_samples
        ),
    }
}

fn response_from_preview(
    preview: &RestorePreview,
    approval_token: String,
    expires_at: i64,
) -> PreviewResponse {
    PreviewResponse {
        mode: preview.mode,
        archive_sha256: preview.archive_sha256.clone(),
        preview_sha256: preview.preview_sha256.clone(),
        expires_at: Utc
            .timestamp_opt(expires_at, 0)
            .single()
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true))
            .unwrap_or_default(),
        archive_counts: preview.archive_counts.clone(),
        target_counts: preview.target_counts.clone(),
        plan: preview.plan.clone(),
        replacement_counts: preview.replacement_counts.clone(),
        replacement_notice: preview.replacement_counts.as_ref().map(|_| {
            let base = "Replacement clears destination device names, device IDs, and IP addresses because they are intentionally omitted from this archive. Server credentials, local identity links, import checkpoints, and existing audit records are not replaced; a restore audit entry is added.";
            match &preview.omitted_samples {
                Some(omitted) => format!(
                    "{base} {}",
                    partial_telemetry_notice(RestoreMode::Replace, omitted)
                ),
                None => base.to_owned(),
            }
        }),
        omitted_samples: preview.omitted_samples.clone(),
        partial_telemetry_notice: preview
            .omitted_samples
            .as_ref()
            .map(|omitted| partial_telemetry_notice(preview.mode, omitted)),
        conflicts: preview.conflicts.clone(),
        approval_token,
    }
}

const INSERT_HISTORY_SQL: &str = "INSERT INTO streaming_history (id,session_key,provider,server_name,user_id,user_name,client_name,device_name,device_id,ip_address,item_id,item_name,item_type,series_name,series_id,season_number,episode_number,production_year,play_method,container,video_codec,video_resolution,audio_codec,audio_channels,subtitle_codec,hw_accel,transcode_reasons,bitrate_bps,duration_secs,watched_secs,data_used_bytes,completion_pct,started_at,last_seen_at,ended_at,is_active,provenance,server_id,source_event_id,timestamp_certainty,byte_accuracy,policy_status) VALUES (?1,?2,?3,?4,?5,?6,?7,'','','',?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39)";
const INSERT_LABEL_SQL: &str =
    "INSERT INTO streaming_history_labels(history_id,kind,value,name) VALUES (?1,?2,?3,?4)";
const INSERT_SESSION_SAMPLE_SQL: &str = "INSERT INTO streaming_session_samples(history_id,sampled_at,observed_secs,playing,bitrate_bps) VALUES (?1,?2,?3,?4,?5)";
const INSERT_BANDWIDTH_SAMPLE_SQL: &str = "INSERT INTO streaming_bandwidth_samples(id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)";
const INSERT_BANDWIDTH_SAMPLE_MERGE_SQL: &str = "INSERT INTO streaming_bandwidth_samples(timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) SELECT ?1,?2,?3,?4,?5,?6,?7,?8 WHERE NOT EXISTS (SELECT 1 FROM streaming_bandwidth_samples s WHERE s.timestamp IS ?1 AND s.provider = ?2)";

fn insert_history_with(
    statement: &mut Statement<'_>,
    row: &HistoryRecord,
) -> PortabilityResult<()> {
    statement.execute(params![
        row.id,
        row.session_key,
        row.provider,
        row.server_name,
        row.user_id,
        row.user_name,
        row.client_name,
        row.item_id,
        row.item_name,
        row.item_type,
        row.series_name,
        row.series_id,
        row.season_number,
        row.episode_number,
        row.production_year,
        row.play_method,
        row.container,
        row.video_codec,
        row.video_resolution,
        row.audio_codec,
        row.audio_channels,
        row.subtitle_codec,
        row.hw_accel,
        row.transcode_reasons,
        row.bitrate_bps,
        row.duration_secs,
        row.watched_secs,
        row.data_used_bytes,
        row.completion_pct,
        row.started_at,
        row.last_seen_at,
        row.ended_at,
        row.is_active,
        row.provenance,
        row.server_id,
        row.source_event_id,
        row.timestamp_certainty,
        row.byte_accuracy,
        row.policy_status,
    ])?;
    Ok(())
}

#[cfg(test)]
fn insert_history(conn: &Connection, row: &HistoryRecord) -> PortabilityResult<()> {
    let mut statement = conn.prepare(INSERT_HISTORY_SQL)?;
    insert_history_with(&mut statement, row)
}

fn insert_histories(conn: &Connection, rows: &[HistoryRecord]) -> PortabilityResult<()> {
    let mut statement = conn.prepare(INSERT_HISTORY_SQL)?;
    for row in rows {
        insert_history_with(&mut statement, row)?;
    }
    Ok(())
}

fn insert_labels(conn: &Connection, labels: &[HistoryLabel]) -> PortabilityResult<()> {
    let mut statement = conn.prepare(INSERT_LABEL_SQL)?;
    for label in labels {
        statement.execute(params![
            label.history_id,
            label.kind,
            label.value,
            label.name
        ])?;
    }
    Ok(())
}

fn insert_session_samples(conn: &Connection, samples: &[SessionSample]) -> PortabilityResult<()> {
    let mut statement = conn.prepare(INSERT_SESSION_SAMPLE_SQL)?;
    for sample in samples {
        statement.execute(params![
            sample.history_id,
            sample.sampled_at,
            sample.observed_secs,
            if sample.playing { 1i64 } else { 0i64 },
            sample.bitrate_bps,
        ])?;
    }
    Ok(())
}

fn insert_bandwidth_samples(
    conn: &Connection,
    samples: &[BandwidthSample],
) -> PortabilityResult<()> {
    let mut statement = conn.prepare(INSERT_BANDWIDTH_SAMPLE_SQL)?;
    for sample in samples {
        statement.execute(params![
            sample.id,
            sample.timestamp,
            sample.provider,
            sample.active_streams,
            sample.direct_play_count,
            sample.direct_stream_count,
            sample.transcode_count,
            sample.total_bitrate_bps,
            sample.bytes_delta,
        ])?;
    }
    Ok(())
}

fn insert_bandwidth_samples_merge(
    conn: &Connection,
    samples: &[BandwidthSample],
) -> PortabilityResult<usize> {
    let mut statement = conn.prepare(INSERT_BANDWIDTH_SAMPLE_MERGE_SQL)?;
    let mut inserted = 0usize;
    for sample in samples {
        inserted += statement.execute(params![
            sample.timestamp,
            sample.provider,
            sample.active_streams,
            sample.direct_play_count,
            sample.direct_stream_count,
            sample.transcode_count,
            sample.total_bitrate_bps,
            sample.bytes_delta,
        ])?;
    }
    Ok(inserted)
}

fn update_policy(conn: &Connection, policy: &TrackingPolicy) -> PortabilityResult<()> {
    let changed = conn.execute(
        "UPDATE streaming_tracking_policies SET minimum_watch_secs=?1,excluded_users=?2,excluded_libraries=?3,reconnect_window_secs=?4,revision=revision+1 WHERE id=1",
        params![policy.minimum_watch_secs, policy.excluded_users, policy.excluded_libraries, policy.reconnect_window_secs],
    )?;
    if changed == 0 {
        conn.execute(
            "INSERT INTO streaming_tracking_policies(id,minimum_watch_secs,excluded_users,excluded_libraries,reconnect_window_secs,revision) VALUES (1,?1,?2,?3,?4,0)",
            params![policy.minimum_watch_secs, policy.excluded_users, policy.excluded_libraries, policy.reconnect_window_secs],
        )?;
    }
    Ok(())
}

fn apply_merge(conn: &Connection, plan: &MergePlan) -> PortabilityResult<bool> {
    insert_histories(conn, &plan.history_inserts)?;
    insert_labels(conn, &plan.label_inserts)?;
    insert_session_samples(conn, &plan.sample_inserts)?;
    let bw_inserted = insert_bandwidth_samples_merge(conn, &plan.bandwidth_inserts)?;
    Ok(!plan.history_inserts.is_empty()
        || !plan.label_inserts.is_empty()
        || !plan.sample_inserts.is_empty()
        || bw_inserted > 0)
}

fn apply_replace(conn: &Connection, archive: &ArchiveData) -> PortabilityResult<()> {
    conn.execute("DELETE FROM streaming_session_samples", [])?;
    conn.execute("DELETE FROM streaming_history_labels", [])?;
    conn.execute("DELETE FROM streaming_history", [])?;
    conn.execute("DELETE FROM streaming_bandwidth_samples", [])?;
    insert_histories(conn, &archive.history)?;
    insert_labels(conn, &archive.labels)?;
    insert_session_samples(conn, &archive.session_samples)?;
    insert_bandwidth_samples(conn, &archive.bandwidth_samples)?;
    update_policy(conn, &archive.tracking_policy)?;
    Ok(())
}

fn restore_connection(
    conn: &mut Connection,
    db_path: &str,
    actor_id: i64,
    mode: RestoreMode,
    archive: &StreamingArchive,
    approval_token: &str,
    now: i64,
) -> PortabilityResult<RestoreResponse> {
    archive.validate()?;
    let approval = consume_approval(
        approval_token,
        actor_id,
        mode,
        &archive.manifest.sha256,
        now,
    )?;
    let backup = af_db::streaming::verified_backup(conn, db_path).map_err(|error| {
        tracing::error!(%error, "Failed to create verified private backup before streaming restore");
        PortabilityError::new(
            StatusCode::CONFLICT,
            "streaming_backup_failed",
            "A verified private database backup is required before restore",
        )
    })?;
    if backup.is_none() {
        return Err(PortabilityError::new(
            StatusCode::CONFLICT,
            "streaming_backup_required",
            "Restore requires a file-backed database so a verified private backup can be created",
        ));
    }

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current_preview = inspect_restore_in_snapshot(&tx, archive, mode)?;
    if current_preview.preview_sha256 != approval.preview_sha256 {
        tx.rollback()?;
        return Err(PortabilityError::stale_preview());
    }
    let (before_counts, before_hash) = match mode {
        RestoreMode::Merge => {
            let before = load_snapshot(&tx)?.snapshot;
            (before.counts(), before.digest()?)
        }
        RestoreMode::Replace => query_target_counts_and_digest_sql(&tx)?,
    };
    let modified = match mode {
        RestoreMode::Merge => {
            let merge = current_preview
                .merge_plan
                .as_ref()
                .ok_or_else(PortabilityError::invalid)?;
            apply_merge(&tx, merge)?
        }
        RestoreMode::Replace => {
            apply_replace(&tx, &archive.data)?;
            true
        }
    };
    if modified {
        tx.execute(
            "UPDATE streaming_history_revision SET revision=revision+1 WHERE id=1",
            [],
        )?;
    }
    let (after_counts, after_hash) = match mode {
        RestoreMode::Merge => {
            let after = load_snapshot(&tx)?.snapshot;
            (after.counts(), after.digest()?)
        }
        RestoreMode::Replace => query_target_counts_and_digest_sql(&tx)?,
    };
    let before_json = serde_json::to_string(&AuditSummary {
        counts: &before_counts,
        snapshot_sha256: &before_hash,
    })
    .map_err(|_| PortabilityError::invalid())?;
    let after_json = serde_json::to_string(&AuditSummary {
        counts: &after_counts,
        snapshot_sha256: &after_hash,
    })
    .map_err(|_| PortabilityError::invalid())?;
    let operation = match mode {
        RestoreMode::Merge => "streaming_portability_merge",
        RestoreMode::Replace => "streaming_portability_replace",
    };
    tx.execute(
        "INSERT INTO streaming_history_audit(actor_id,operation,preview_hash,before_json,after_json,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
        params![actor_id, operation, approval.preview_sha256, before_json, after_json, Utc.timestamp_opt(now, 0).single().ok_or_else(PortabilityError::invalid)?.to_rfc3339_opts(SecondsFormat::Secs, true)],
    )?;
    tx.commit()?;
    drop(backup);

    Ok(RestoreResponse {
        mode,
        archive_sha256: archive.manifest.sha256.clone(),
        preview_sha256: approval.preview_sha256,
        backup_verified: true,
        archive_counts: archive.data.counts(),
        resulting_counts: after_counts,
        plan: current_preview.plan,
        omitted_samples: current_preview.omitted_samples.clone(),
        partial_telemetry_notice: current_preview
            .omitted_samples
            .as_ref()
            .map(|omitted| partial_telemetry_notice(mode, omitted)),
        conflicts: current_preview.conflicts,
    })
}

async fn read_request_body(request: Request<Body>) -> PortabilityResult<Vec<u8>> {
    let bytes = to_bytes(request.into_body(), MAX_PORTABILITY_BODY_BYTES)
        .await
        .map_err(|_| PortabilityError::too_large())?;
    if bytes.len() > MAX_PORTABILITY_BODY_BYTES {
        return Err(PortabilityError::too_large());
    }
    Ok(bytes.to_vec())
}

fn ensure_archive_within_byte_limit(archive: &StreamingArchive) -> PortabilityResult<()> {
    let encoded = serde_json::to_vec(archive).map_err(|_| PortabilityError::invalid())?;
    if encoded.len() > MAX_ARCHIVE_BYTES {
        return Err(PortabilityError::too_large());
    }
    Ok(())
}

fn build_export_response(archive: &StreamingArchive) -> Response {
    let bytes = match serde_json::to_vec(archive) {
        Ok(bytes) => bytes,
        Err(_) => return PortabilityError::invalid().into_response(),
    };
    let mut response = (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"streaming-history-backup.json\"",
            ),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Body::from(bytes),
    )
        .into_response();
    let headers = response.headers_mut();
    if let Some(omitted) = &archive.manifest.omitted_samples {
        headers.insert(
            header::HeaderName::from_static(HEADER_ARCHIVE_TELEMETRY),
            header::HeaderValue::from_static("partial"),
        );
        if let Ok(value) = header::HeaderValue::from_str(&omitted.session_samples.to_string()) {
            headers.insert(
                header::HeaderName::from_static(HEADER_OMITTED_SESSION_SAMPLES),
                value,
            );
        }
        if let Ok(value) = header::HeaderValue::from_str(&omitted.bandwidth_samples.to_string()) {
            headers.insert(
                header::HeaderName::from_static(HEADER_OMITTED_BANDWIDTH_SAMPLES),
                value,
            );
        }
    } else {
        headers.insert(
            header::HeaderName::from_static(HEADER_ARCHIVE_TELEMETRY),
            header::HeaderValue::from_static("complete"),
        );
    }
    response
}

pub async fn export_handler(Extension(user): Extension<AuthUser>) -> Response {
    if user.role != "admin" {
        return PortabilityError::forbidden().into_response();
    }
    let result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| PortabilityError::unavailable())?;
        build_archive(&conn, Utc::now().timestamp())
    })
    .await;
    let archive = match result {
        Ok(Ok(archive)) => archive,
        Ok(Err(error)) => return error.into_response(),
        Err(_) => return PortabilityError::unavailable().into_response(),
    };
    build_export_response(&archive)
}

pub async fn preview_handler(
    Extension(user): Extension<AuthUser>,
    request: Request<Body>,
) -> Response {
    if user.role != "admin" {
        return PortabilityError::forbidden().into_response();
    }
    let bytes = match read_request_body(request).await {
        Ok(bytes) => bytes,
        Err(error) => return error.into_response(),
    };
    let request: PreviewRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(_) => return PortabilityError::invalid().into_response(),
    };
    if let Err(error) = ensure_archive_within_byte_limit(&request.archive) {
        return error.into_response();
    }
    if let Err(error) = request.archive.validate() {
        return error.into_response();
    }
    let actor_id = user.user_id;
    let mode = request.mode;
    let archive = request.archive;
    let preview_result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| PortabilityError::unavailable())?;
        inspect_restore(&conn, &archive, mode)
    })
    .await;
    let preview = match preview_result {
        Ok(Ok(preview)) => preview,
        Ok(Err(error)) => return error.into_response(),
        Err(_) => return PortabilityError::unavailable().into_response(),
    };
    let now = Utc::now().timestamp();
    let (token, expires_at) = match issue_approval(
        actor_id,
        mode,
        &preview.archive_sha256,
        &preview.preview_sha256,
        now,
    ) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let body = response_from_preview(&preview, token, expires_at);
    let encoded = match serde_json::to_vec(&body) {
        Ok(encoded) => encoded,
        Err(_) => {
            revoke_approval(&body.approval_token);
            return PortabilityError::invalid().into_response();
        }
    };
    if encoded.len() > MAX_BODY_BYTES {
        revoke_approval(&body.approval_token);
        return PortabilityError::too_large().into_response();
    }
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(body),
    )
        .into_response()
}

pub async fn restore_handler(
    Extension(user): Extension<AuthUser>,
    request: Request<Body>,
) -> Response {
    if user.role != "admin" {
        return PortabilityError::forbidden().into_response();
    }
    let bytes = match read_request_body(request).await {
        Ok(bytes) => bytes,
        Err(error) => return error.into_response(),
    };
    let request: RestoreRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(_) => return PortabilityError::invalid().into_response(),
    };
    if let Err(error) = ensure_archive_within_byte_limit(&request.archive) {
        return error.into_response();
    }
    if let Err(error) = request.archive.validate() {
        return error.into_response();
    }
    let actor_id = user.user_id;
    let result = tokio::task::spawn_blocking(move || {
        let mut conn = af_db::get_conn().map_err(|_| PortabilityError::unavailable())?;
        let db_path = af_db::get_db_path();
        restore_connection(
            &mut conn,
            &db_path,
            actor_id,
            request.mode,
            &request.archive,
            &request.approval_token,
            Utc::now().timestamp(),
        )
    })
    .await;
    match result {
        Ok(Ok(response)) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            axum::Json(response),
        )
            .into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => PortabilityError::unavailable().into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    const AF_DB_LIB: &str = include_str!("../../af-db/src/lib.rs");
    const MIGRATION_20: &str = include_str!("../../af-db/src/migrations/020_streaming_history.sql");

    struct DisposableDb {
        connection: Connection,
        database_path: PathBuf,
        root: PathBuf,
    }

    impl Drop for DisposableDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn raw_migration_19_table(migration_start: usize, marker: &str) -> String {
        let migration = &AF_DB_LIB[migration_start..];
        let literal_start = migration.find(marker).expect("migration 19 raw SQL marker") + 3;
        let literal_end = migration[literal_start..]
            .find("\"#")
            .expect("raw SQL terminator");
        migration[literal_start..literal_start + literal_end].to_owned()
    }

    fn disposable_db() -> DisposableDb {
        let root = std::env::temp_dir().join(format!(
            "aetherflow-streaming-portability-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let database_path = root.join("streaming.sqlite");
        let connection = Connection::open(&database_path).unwrap();
        connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        let migration_start = AF_DB_LIB.find("        19,\n        \"Add streaming_servers, streaming_history, and streaming_bandwidth_samples tables\"")
            .expect("migration 19 registration");
        for marker in [
            "r#\"CREATE TABLE IF NOT EXISTS streaming_servers",
            "r#\"CREATE TABLE IF NOT EXISTS streaming_history",
            "r#\"CREATE TABLE IF NOT EXISTS streaming_bandwidth_samples",
        ] {
            connection
                .execute_batch(&raw_migration_19_table(migration_start, marker))
                .unwrap();
        }
        connection.execute_batch(MIGRATION_20).unwrap();
        DisposableDb {
            connection,
            database_path,
            root,
        }
    }

    fn seed_sensitive_data(connection: &Connection) {
        connection.execute(
            "INSERT INTO streaming_servers(provider,name,url,api_key,enabled,server_id,server_version) VALUES ('jellyfin','Media','http://media.local','provider-secret-should-never-export',1,'server-a','10.9')",
            [],
        ).unwrap();
        connection.execute(
            "INSERT INTO streaming_history(id,session_key,provider,server_name,user_id,user_name,client_name,device_name,device_id,ip_address,item_id,item_name,item_type,series_name,series_id,season_number,episode_number,production_year,play_method,container,video_codec,video_resolution,audio_codec,audio_channels,subtitle_codec,hw_accel,transcode_reasons,bitrate_bps,duration_secs,watched_secs,data_used_bytes,completion_pct,started_at,last_seen_at,ended_at,is_active,provenance,server_id,source_event_id,timestamp_certainty,byte_accuracy,policy_status) VALUES (7,'jellyfin:session-7:item-2','jellyfin','Media','provider-user-2','Sam','TV','Living Room','device-secret-should-never-export','192.0.2.8','item-2','Example','Movie','','',NULL,NULL,NULL,'DirectPlay','','','','',NULL,'','','',NULL,NULL,NULL,NULL,NULL,'2026-10-01T12:00:00Z','2026-10-01T12:30:00Z',NULL,0,'imported_event','server-a','event-7','source_event','unrecorded','included')",
            [],
        ).unwrap();
        connection.execute(
            "INSERT INTO streaming_history_labels(history_id,kind,value,name) VALUES (7,'library','library-3','Films')",
            [],
        ).unwrap();
        connection.execute(
            "INSERT INTO streaming_session_samples(history_id,sampled_at,observed_secs,playing,bitrate_bps) VALUES (7,1790856000,30,1,1200000)",
            [],
        ).unwrap();
        connection.execute(
            "INSERT INTO streaming_bandwidth_samples(id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) VALUES (4,NULL,'jellyfin',1,1,0,0,1200000,NULL)",
            [],
        ).unwrap();
        connection.execute(
            "UPDATE streaming_tracking_policies SET minimum_watch_secs=45,excluded_users='[]',excluded_libraries='[]',reconnect_window_secs=30 WHERE id=1",
            [],
        ).unwrap();
    }

    fn export_archive(connection: &Connection) -> StreamingArchive {
        build_archive(connection, 1_798_876_800).unwrap()
    }

    fn preview_and_token(
        connection: &Connection,
        archive: &StreamingArchive,
        mode: RestoreMode,
        actor_id: i64,
        now: i64,
    ) -> (RestorePreview, String) {
        let preview = inspect_restore(connection, archive, mode).unwrap();
        let (token, _) = issue_approval(
            actor_id,
            mode,
            &preview.archive_sha256,
            &preview.preview_sha256,
            now,
        )
        .unwrap();
        (preview, token)
    }

    fn query_counts(connection: &Connection) -> (i64, i64, i64, i64, i64) {
        connection.query_row(
            "SELECT (SELECT COUNT(*) FROM streaming_history),(SELECT COUNT(*) FROM streaming_history_labels),(SELECT COUNT(*) FROM streaming_session_samples),(SELECT COUNT(*) FROM streaming_bandwidth_samples),(SELECT COUNT(*) FROM streaming_history_audit)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).unwrap()
    }

    fn assert_private_backup_exists(root: &Path) {
        let backup_dir = std::fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.is_dir()
                    && path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("streaming-backup-")
            })
            .expect("verified_backup created a private backup directory");
        let backup = backup_dir.join("before-migration.sqlite");
        assert!(backup.is_file());
        let verification =
            Connection::open_with_flags(&backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        assert_eq!(
            verification
                .query_row::<String, _, _>("PRAGMA quick_check", [], |row| row.get(0))
                .unwrap(),
            "ok"
        );
    }

    #[test]
    fn archive_round_trip_is_secret_free_and_preserves_provenance_and_nulls() {
        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        source
            .connection
            .execute("CREATE TABLE unrelated_sentinel(value TEXT NOT NULL)", [])
            .unwrap();
        source
            .connection
            .execute(
                "INSERT INTO unrelated_sentinel VALUES ('leave-me-alone')",
                [],
            )
            .unwrap();
        let archive = export_archive(&source.connection);
        let encoded = serde_json::to_string(&archive).unwrap();
        assert!(!encoded.contains("provider-secret-should-never-export"));
        assert!(!encoded.contains("device-secret-should-never-export"));
        assert!(!encoded.contains("Living Room"));
        assert!(!encoded.contains("192.0.2.8"));
        assert_eq!(archive.data.history[0].provenance, "imported_event");
        assert_eq!(
            archive.data.history[0].source_event_id.as_deref(),
            Some("event-7")
        );
        assert_eq!(archive.data.history[0].season_number, None);
        assert_eq!(archive.data.bandwidth_samples[0].timestamp, None);
        assert_eq!(archive.data.bandwidth_samples[0].bytes_delta, None);

        let mut target = disposable_db();
        target
            .connection
            .execute("CREATE TABLE unrelated_sentinel(value TEXT NOT NULL)", [])
            .unwrap();
        target
            .connection
            .execute(
                "INSERT INTO unrelated_sentinel VALUES ('leave-me-alone')",
                [],
            )
            .unwrap();
        target.connection.execute(
            "INSERT INTO streaming_servers(provider,name,url,api_key,server_id) VALUES ('jellyfin','Local','http://local','keep-target-secret','target-server')",
            [],
        ).unwrap();
        let (preview, token) = preview_and_token(
            &target.connection,
            &archive,
            RestoreMode::Replace,
            44,
            1_798_876_800,
        );
        let restored = restore_connection(
            &mut target.connection,
            target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Replace,
            &archive,
            &token,
            1_798_876_800,
        )
        .unwrap();
        assert_eq!(restored.archive_counts, archive.data.counts());
        assert_eq!(restored.preview_sha256, preview.preview_sha256);
        assert_eq!(query_counts(&target.connection), (1, 1, 1, 1, 1));
        let device_name: String = target
            .connection
            .query_row(
                "SELECT device_name FROM streaming_history WHERE id=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let ip_address: String = target
            .connection
            .query_row(
                "SELECT ip_address FROM streaming_history WHERE id=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(device_name.is_empty());
        assert!(ip_address.is_empty());
        let sentinel: String = target
            .connection
            .query_row("SELECT value FROM unrelated_sentinel", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sentinel, "leave-me-alone");
        let api_key: String = target
            .connection
            .query_row(
                "SELECT api_key FROM streaming_servers WHERE provider='jellyfin'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(api_key, "keep-target-secret");
        assert_private_backup_exists(&target.root);
        if let Ok(path) = std::env::var("AF_STREAMING_PORTABILITY_FIXTURE") {
            let preview = response_from_preview(&preview, token, 1_798_876_800 + APPROVAL_TTL_SECS);
            let fixture =
                serde_json::json!({ "archive": archive, "preview": preview, "restored": restored });
            std::fs::write(path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
        }
    }

    #[test]
    fn merge_remaps_instance_local_ids_and_preserves_parent_links() {
        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        let archive = export_archive(&source.connection);
        let mut target = disposable_db();
        let mut unrelated = archive.data.history[0].clone();
        unrelated.session_key = "other-instance-session".to_string();
        unrelated.source_event_id = Some("other-instance-event".to_string());
        insert_history(&target.connection, &unrelated).unwrap();
        let (preview, token) =
            preview_and_token(&target.connection, &archive, RestoreMode::Merge, 44, 1000);
        assert_eq!(preview.plan.insert.history, 1);
        assert_eq!(preview.plan.conflict.history, 0);
        let response = restore_connection(
            &mut target.connection,
            target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Merge,
            &archive,
            &token,
            1001,
        )
        .unwrap();
        assert_eq!(response.resulting_counts.history, 2);
        let mapped_id: i64 = target
            .connection
            .query_row(
                "SELECT id FROM streaming_history WHERE session_key=?1",
                [&archive.data.history[0].session_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(mapped_id, unrelated.id);
        let label_parent: i64 = target
            .connection
            .query_row(
                "SELECT history_id FROM streaming_history_labels",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let sample_parent: i64 = target
            .connection
            .query_row(
                "SELECT history_id FROM streaming_session_samples",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(label_parent, mapped_id);
        assert_eq!(sample_parent, mapped_id);
        let target_snapshot = load_snapshot(&target.connection).unwrap().snapshot;
        let repeat = plan_merge(&target_snapshot, &archive.data);
        assert_eq!(repeat.counts.insert.history, 0);
        assert_eq!(repeat.counts.exact_duplicate.history, 1);
    }

    #[test]
    fn merge_maps_matching_source_event_and_skips_conflicting_identity() {
        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        let archive = export_archive(&source.connection);
        let mut target = disposable_db();
        let mut mapped_record = archive.data.history[0].clone();
        mapped_record.id = 99;
        insert_history(&target.connection, &mapped_record).unwrap();
        target.connection.execute(
            "INSERT INTO streaming_history_labels(history_id,kind,value,name) VALUES (99,'library','library-3','Films')",
            [],
        ).unwrap();
        target.connection.execute(
            "INSERT INTO streaming_session_samples(history_id,sampled_at,observed_secs,playing,bitrate_bps) VALUES (99,1790856000,30,1,1200000)",
            [],
        ).unwrap();
        target.connection.execute(
            "UPDATE streaming_tracking_policies SET minimum_watch_secs=45,reconnect_window_secs=30 WHERE id=1",
            [],
        ).unwrap();
        let (preview, token) = preview_and_token(
            &target.connection,
            &archive,
            RestoreMode::Merge,
            44,
            1_798_876_800,
        );
        assert_eq!(preview.plan.exact_duplicate.history, 1);
        assert!(preview.conflicts.is_empty());
        let response = restore_connection(
            &mut target.connection,
            target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Merge,
            &archive,
            &token,
            1_798_876_800,
        )
        .unwrap();
        assert_eq!(response.resulting_counts.history, 1);
        assert_eq!(response.resulting_counts.labels, 1);
        assert_eq!(response.resulting_counts.session_samples, 1);
        assert_eq!(response.resulting_counts.bandwidth_samples, 1);
        let sample_history_id: i64 = target
            .connection
            .query_row(
                "SELECT history_id FROM streaming_session_samples",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(sample_history_id, 99);
        assert_eq!(query_counts(&target.connection).4, 1);
    }

    #[test]
    fn merge_preview_reports_event_and_policy_conflicts_without_overwriting() {
        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        let archive = export_archive(&source.connection);
        let mut target = disposable_db();
        target.connection.execute(
            "INSERT INTO streaming_history(id,session_key,provider,server_name,user_id,user_name,item_id,item_name,started_at,last_seen_at,provenance,server_id,source_event_id,timestamp_certainty,byte_accuracy,policy_status) VALUES (7,'jellyfin:session-7:item-2','jellyfin','Different','provider-user-2','Sam','item-2','Example','2026-10-01T12:00:00Z','2026-10-01T12:30:00Z','imported_event','server-a','event-7','source_event','unrecorded','included')",
            [],
        ).unwrap();
        target
            .connection
            .execute(
                "UPDATE streaming_tracking_policies SET minimum_watch_secs=99 WHERE id=1",
                [],
            )
            .unwrap();
        let (preview, token) = preview_and_token(
            &target.connection,
            &archive,
            RestoreMode::Merge,
            44,
            1_798_876_800,
        );
        assert_eq!(preview.conflicts.len(), 4);
        assert!(preview
            .conflicts
            .iter()
            .any(|entry| entry.reason == "history_identity_collision"));
        assert!(preview
            .conflicts
            .iter()
            .any(|entry| entry.reason == "parent_history_conflict"));
        assert!(preview
            .conflicts
            .iter()
            .any(|entry| entry.reason == "tracking_policy_collision"));
        let response = restore_connection(
            &mut target.connection,
            target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Merge,
            &archive,
            &token,
            1_798_876_800,
        )
        .unwrap();
        assert_eq!(response.conflicts, preview.conflicts);
        assert_eq!(response.resulting_counts.history, 1);
        let server_name: String = target
            .connection
            .query_row(
                "SELECT server_name FROM streaming_history WHERE id=7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(server_name, "Different");
        let policy: i64 = target
            .connection
            .query_row(
                "SELECT minimum_watch_secs FROM streaming_tracking_policies WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(policy, 99);
    }

    #[test]
    fn approval_is_actor_bound_expiring_one_time_and_preview_is_revalidated() {
        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        let archive = export_archive(&source.connection);
        let mut target = disposable_db();
        let (_, wrong_actor_token) =
            preview_and_token(&target.connection, &archive, RestoreMode::Merge, 44, 1000);
        assert!(consume_approval(
            &wrong_actor_token,
            45,
            RestoreMode::Merge,
            &archive.manifest.sha256,
            1001
        )
        .is_err());

        let (_, expired_token) =
            preview_and_token(&target.connection, &archive, RestoreMode::Merge, 44, 1000);
        assert!(consume_approval(
            &expired_token,
            44,
            RestoreMode::Merge,
            &archive.manifest.sha256,
            1301
        )
        .is_err());

        let (preview, stale_token) =
            preview_and_token(&target.connection, &archive, RestoreMode::Replace, 44, 2000);
        target
            .connection
            .execute(
                "INSERT INTO streaming_bandwidth_samples(id,provider) VALUES (123,'jellyfin')",
                [],
            )
            .unwrap();
        let stale = restore_connection(
            &mut target.connection,
            target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Replace,
            &archive,
            &stale_token,
            2001,
        );
        assert!(stale.is_err());
        assert_eq!(query_counts(&target.connection).3, 1);
        assert_eq!(query_counts(&target.connection).4, 0);
        assert!(!preview.preview_sha256.is_empty());
    }

    #[test]
    fn redacted_private_field_change_invalidates_replacement_preview() {
        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        let archive = export_archive(&source.connection);
        let mut target = disposable_db();
        target.connection.execute(
            "INSERT INTO streaming_history(id,session_key,device_name,device_id,ip_address) VALUES (55,'local-session','Old Device','old-device','198.51.100.7')",
            [],
        ).unwrap();
        let (_, token) =
            preview_and_token(&target.connection, &archive, RestoreMode::Replace, 44, 2500);
        target
            .connection
            .execute(
                "UPDATE streaming_history SET ip_address='198.51.100.8' WHERE id=55",
                [],
            )
            .unwrap();
        let result = restore_connection(
            &mut target.connection,
            target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Replace,
            &archive,
            &token,
            2501,
        );
        assert!(result.is_err());
        assert_eq!(query_counts(&target.connection), (1, 0, 0, 0, 0));
        let ip_address: String = target
            .connection
            .query_row(
                "SELECT ip_address FROM streaming_history WHERE id=55",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ip_address, "198.51.100.8");
    }

    #[test]
    fn audit_failure_rolls_back_restore_and_preserves_unrelated_data() {
        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        let archive = export_archive(&source.connection);
        let mut target = disposable_db();
        target
            .connection
            .execute("CREATE TABLE unrelated_sentinel(value TEXT NOT NULL)", [])
            .unwrap();
        target
            .connection
            .execute("INSERT INTO unrelated_sentinel VALUES ('stable')", [])
            .unwrap();
        target.connection.execute_batch(
            "CREATE TRIGGER reject_portability_audit BEFORE INSERT ON streaming_history_audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;",
        ).unwrap();
        let (_, token) =
            preview_and_token(&target.connection, &archive, RestoreMode::Replace, 44, 3000);
        let result = restore_connection(
            &mut target.connection,
            target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Replace,
            &archive,
            &token,
            3001,
        );
        assert!(result.is_err());
        assert_eq!(query_counts(&target.connection), (0, 0, 0, 0, 0));
        let sentinel: String = target
            .connection
            .query_row("SELECT value FROM unrelated_sentinel", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sentinel, "stable");
    }

    #[test]
    fn rejects_unknown_fields_bad_hash_duplicate_event_identity_and_size() {
        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        let archive = export_archive(&source.connection);
        let mut tampered = archive.clone();
        tampered.data.history[0].item_name = "tampered".to_owned();
        assert!(tampered.validate().is_err());
        let mut duplicate = archive.clone();
        let mut duplicate_row = duplicate.data.history[0].clone();
        duplicate_row.id = 8;
        duplicate_row.session_key = "different-session".to_owned();
        duplicate.data.history.push(duplicate_row);
        duplicate.manifest.record_counts.history = 2;
        duplicate.manifest.sha256 = duplicate.digest().unwrap();
        assert!(duplicate.validate().is_err());
        assert!(validate_archive_bytes(&vec![b' '; MAX_BODY_BYTES + 1]).is_err());
        let encoded = serde_json::to_vec(&archive).unwrap();
        let mut with_unknown = serde_json::from_slice::<serde_json::Value>(&encoded).unwrap();
        with_unknown["data"]["history"][0]["ipAddress"] =
            serde_json::Value::String("private".to_owned());
        let bytes = serde_json::to_vec(&with_unknown).unwrap();
        assert!(validate_archive_bytes(&bytes).is_err());
    }

    #[test]
    fn replace_mode_succeeds_when_existing_db_has_over_ten_thousand_rows_and_body_headroom_exists()
    {
        const { assert!(MAX_REQUEST_BODY_BYTES >= MAX_ARCHIVE_BYTES + 1024 * 1024) };
        const { assert!(MAX_PORTABLE_ROWS >= 100_000) };

        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        let archive = export_archive(&source.connection);

        let mut target = disposable_db();
        let tx = target.connection.unchecked_transaction().unwrap();
        {
            let mut stmt = tx
                .prepare("INSERT INTO streaming_bandwidth_samples(id,provider,active_streams) VALUES (?1,'jellyfin',1)")
                .unwrap();
            for id in 1..=12_000_i64 {
                stmt.execute([id]).unwrap();
            }
        }
        tx.commit().unwrap();

        let (preview, token) =
            preview_and_token(&target.connection, &archive, RestoreMode::Replace, 44, 4000);
        assert_eq!(preview.target_counts.bandwidth_samples, 12_000);
        let restored = restore_connection(
            &mut target.connection,
            target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Replace,
            &archive,
            &token,
            4001,
        )
        .unwrap();
        assert_eq!(restored.resulting_counts.bandwidth_samples, 1);
    }

    #[tokio::test]
    async fn archive_boundary_near_seven_point_five_mib_succeeds_and_above_eight_mib_is_rejected() {
        assert_eq!(MAX_ARCHIVE_BYTES, 8 * 1024 * 1024);
        assert_eq!(MAX_PORTABILITY_BODY_BYTES, 10 * 1024 * 1024);
        assert_eq!(MAX_REQUEST_BODY_BYTES, MAX_PORTABILITY_BODY_BYTES);

        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        let base_archive = export_archive(&source.connection);
        let template_row = base_archive.data.history[0].clone();

        // Build a valid ~7.5 MiB archive (~7,864,320 bytes)
        let mut near_limit = base_archive.clone();
        near_limit.data.history.clear();
        near_limit.data.labels.clear();
        near_limit.data.session_samples.clear();
        let pad = "x".repeat(15_200);
        for idx in 1..=500_i64 {
            let mut row = template_row.clone();
            row.id = idx;
            row.session_key = format!("plex:srv-1:sess-{idx}");
            row.provider = "plex".to_string();
            row.source_event_id = Some(format!("plex-evt-{idx}"));
            row.item_name = pad.clone();
            near_limit.data.history.push(row);
        }
        near_limit.manifest.record_counts = near_limit.data.counts();
        near_limit.manifest.sha256 = near_limit.digest().unwrap();

        let near_bytes = serde_json::to_vec(&near_limit).unwrap();
        assert!(
            near_bytes.len() >= 7 * 1024 * 1024 && near_bytes.len() <= MAX_ARCHIVE_BYTES,
            "expected ~7.5 MiB archive, got {} bytes",
            near_bytes.len()
        );
        ensure_archive_within_byte_limit(&near_limit).unwrap();
        validate_archive_bytes(&near_bytes).unwrap();

        // Request wrapper (`{"mode":"merge","archive":...}`) fits well within 10 MiB body limit
        let envelope = serde_json::json!({
            "mode": "merge",
            "archive": near_limit,
        });
        let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
        assert!(envelope_bytes.len() <= MAX_PORTABILITY_BODY_BYTES);
        let req = Request::builder()
            .method("POST")
            .uri(PREVIEW_ROUTE)
            .body(Body::from(envelope_bytes))
            .unwrap();
        let read_back = read_request_body(req).await.unwrap();
        let parsed_req: PreviewRequest = serde_json::from_slice(&read_back).unwrap();
        ensure_archive_within_byte_limit(&parsed_req.archive).unwrap();

        // Exceeding 8 MiB archive limit (~8.3 MiB) is rejected even though < 10 MiB body limit
        let mut over_archive = parsed_req.archive;
        for idx in 501..=555_i64 {
            let mut row = template_row.clone();
            row.id = idx;
            row.session_key = format!("plex:srv-1:sess-{idx}");
            row.provider = "plex".to_string();
            row.source_event_id = Some(format!("plex-evt-{idx}"));
            row.item_name = pad.clone();
            over_archive.data.history.push(row);
        }
        over_archive.manifest.record_counts = over_archive.data.counts();
        over_archive.manifest.sha256 = over_archive.digest().unwrap();
        assert!(ensure_archive_within_byte_limit(&over_archive).is_err());

        // Exceeding 10 MiB body limit is rejected by `read_request_body`
        let over_body_req = Request::builder()
            .method("POST")
            .uri(PREVIEW_ROUTE)
            .body(Body::from(vec![b' '; MAX_PORTABILITY_BODY_BYTES + 1]))
            .unwrap();
        assert!(read_request_body(over_body_req).await.is_err());
    }

    #[test]
    fn merge_mode_deduplicates_bandwidth_samples_by_natural_key_when_target_has_existing_ids() {
        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        source
            .connection
            .execute("DELETE FROM streaming_bandwidth_samples", [])
            .unwrap();
        for (id, ts, prov, streams, br) in [
            (
                1_i64,
                "2026-10-01T10:00:00Z",
                "jellyfin",
                1_i64,
                4_000_000_i64,
            ),
            (
                2_i64,
                "2026-10-01T10:01:00Z",
                "jellyfin",
                2_i64,
                8_000_000_i64,
            ),
            (3_i64, "2026-10-01T10:02:00Z", "plex", 1_i64, 5_000_000_i64),
        ] {
            source.connection.execute(
                "INSERT INTO streaming_bandwidth_samples(id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) VALUES (?1,?2,?3,?4,1,0,0,?5,1024)",
                params![id, ts, prov, streams, br],
            ).unwrap();
        }
        let archive = export_archive(&source.connection);

        // Target DB ALREADY has rows id = 1..3 (with id=2 matching archive's 10:00:00Z natural key!)
        let mut target = disposable_db();
        target.connection.execute(
            "UPDATE streaming_tracking_policies SET minimum_watch_secs=45,excluded_users='[]',excluded_libraries='[]',reconnect_window_secs=30 WHERE id=1",
            [],
        ).unwrap();
        for (id, ts, prov, streams, br) in [
            (
                1_i64,
                "2026-09-30T09:00:00Z",
                "jellyfin",
                1_i64,
                2_000_000_i64,
            ),
            (
                2_i64,
                "2026-10-01T10:00:00Z",
                "jellyfin",
                1_i64,
                4_000_000_i64,
            ),
            (3_i64, "2026-09-30T09:05:00Z", "emby", 1_i64, 3_000_000_i64),
        ] {
            target.connection.execute(
                "INSERT INTO streaming_bandwidth_samples(id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) VALUES (?1,?2,?3,?4,1,0,0,?5,1024)",
                params![id, ts, prov, streams, br],
            ).unwrap();
        }

        let (preview, token) =
            preview_and_token(&target.connection, &archive, RestoreMode::Merge, 44, 5000);
        assert_eq!(preview.plan.exact_duplicate.bandwidth_samples, 1);
        assert_eq!(preview.plan.insert.bandwidth_samples, 2);
        assert_eq!(preview.plan.conflict.bandwidth_samples, 0);

        let restored = restore_connection(
            &mut target.connection,
            target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Merge,
            &archive,
            &token,
            5001,
        )
        .expect("merge into target with existing bandwidth_samples id=1..3 must succeed without UNIQUE id conflict");
        assert_eq!(restored.resulting_counts.bandwidth_samples, 5);

        // Repeat merge preview sees all 3 archive bandwidth samples as exact duplicates!
        let repeat_preview =
            inspect_restore(&target.connection, &archive, RestoreMode::Merge).unwrap();
        assert_eq!(repeat_preview.plan.insert.bandwidth_samples, 0);
        assert_eq!(repeat_preview.plan.exact_duplicate.bandwidth_samples, 3);
    }

    #[test]
    fn legacy_full_v1_archive_keeps_exact_digest_and_omits_partial_fields() {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct LegacyV1DigestView<'a> {
            format: &'a str,
            format_version: u16,
            schema_version: u16,
            provenance_version: u16,
            exported_at: &'a str,
            record_counts: &'a RecordCounts,
            redacted_fields: &'a [String],
            omitted_tables: &'a [String],
            data: &'a ArchiveData,
        }

        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        let archive = export_archive(&source.connection);
        assert_eq!(archive.manifest.omitted_samples, None);

        let encoded = serde_json::to_vec(&archive).unwrap();
        let encoded_json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert!(encoded_json["manifest"].get("omittedSamples").is_none());

        let legacy_digest_input = LegacyV1DigestView {
            format: &archive.manifest.format,
            format_version: archive.manifest.format_version,
            schema_version: archive.manifest.schema_version,
            provenance_version: archive.manifest.provenance_version,
            exported_at: &archive.manifest.exported_at,
            record_counts: &archive.manifest.record_counts,
            redacted_fields: &archive.manifest.redacted_fields,
            omitted_tables: &archive.manifest.omitted_tables,
            data: &archive.data,
        };
        let expected_sha256 = hex::encode(Sha256::digest(
            serde_json::to_vec(&legacy_digest_input).unwrap(),
        ));
        assert_eq!(archive.manifest.sha256, expected_sha256);

        let parsed = validate_archive_bytes(&encoded).unwrap();
        assert_eq!(parsed, archive);

        // Explicit null omission metadata is rejected; only absent metadata is valid for full archives.
        let mut with_null = encoded_json.clone();
        with_null["manifest"]["omittedSamples"] = serde_json::Value::Null;
        assert!(validate_archive_bytes(&serde_json::to_vec(&with_null).unwrap()).is_err());

        let export_resp = build_export_response(&archive);
        assert_eq!(
            export_resp.headers().get(HEADER_ARCHIVE_TELEMETRY).unwrap(),
            "complete"
        );
        assert!(export_resp
            .headers()
            .get(HEADER_OMITTED_SESSION_SAMPLES)
            .is_none());
        assert!(export_resp
            .headers()
            .get(HEADER_OMITTED_BANDWIDTH_SAMPLES)
            .is_none());

        let mut target = disposable_db();
        let (preview, token) =
            preview_and_token(&target.connection, &parsed, RestoreMode::Replace, 44, 6000);
        let preview_resp = response_from_preview(&preview, token.clone(), 6300);
        let preview_json = serde_json::to_value(&preview_resp).unwrap();
        assert!(preview_json.get("omittedSamples").is_none());
        assert!(preview_json.get("partialTelemetryNotice").is_none());

        let restored = restore_connection(
            &mut target.connection,
            target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Replace,
            &parsed,
            &token,
            6001,
        )
        .unwrap();
        let restored_json = serde_json::to_value(&restored).unwrap();
        assert!(restored_json.get("omittedSamples").is_none());
        assert!(restored_json.get("partialTelemetryNotice").is_none());
        assert_private_backup_exists(&target.root);
    }

    #[test]
    fn truncated_export_binds_omitted_samples_and_surfaces_in_export_preview_and_restore() {
        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        for ts in [
            1_790_856_060_i64,
            1_790_856_120,
            1_790_856_180,
            1_790_856_240,
        ] {
            source
                .connection
                .execute(
                    "INSERT INTO streaming_session_samples(history_id,sampled_at,observed_secs,playing,bitrate_bps) VALUES (7,?1,30,1,1200000)",
                    [ts],
                )
                .unwrap();
        }
        source
            .connection
            .execute(
                "UPDATE streaming_bandwidth_samples SET timestamp = '2026-10-01 12:30:00' WHERE id = 4",
                [],
            )
            .unwrap();
        for (id, timestamp) in [
            (5_i64, "2026-10-01T12:20:00Z"),
            (6, "2026-10-01 12:10:00"),
            (7, "2026-10-01T12:00:00Z"),
        ] {
            source
                .connection
                .execute(
                    "INSERT INTO streaming_bandwidth_samples(id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) VALUES (?1,?2,'jellyfin',1,1,0,0,1200000,1024)",
                    params![id, timestamp],
                )
                .unwrap();
        }

        // Total rows = 1 history + 1 label + 1 policy + 5 session + 4 bw = 12.
        // With budget = 8: remaining_sample_budget = 5, half_budget = 2 -> retains 2 session + 3 bw.
        let archive = build_archive_with_budget(&source.connection, 1_798_876_800, 8).unwrap();
        assert_eq!(
            archive.manifest.omitted_samples,
            Some(OmittedSamples {
                session_samples: 3,
                bandwidth_samples: 1,
            })
        );
        assert_eq!(archive.manifest.record_counts.total(), Some(8));
        assert_eq!(archive.manifest.record_counts.history, 1);
        assert_eq!(archive.manifest.record_counts.labels, 1);
        assert_eq!(
            archive
                .data
                .bandwidth_samples
                .iter()
                .map(|sample| sample.id)
                .collect::<Vec<_>>(),
            [4, 5, 6]
        );

        let encoded_str = serde_json::to_string(&archive).unwrap();
        for secret in [
            "provider-secret-should-never-export",
            "device-secret-should-never-export",
            "Living Room",
            "192.0.2.8",
        ] {
            assert!(!encoded_str.contains(secret));
        }

        let export_resp = build_export_response(&archive);
        assert_eq!(
            export_resp.headers().get(HEADER_ARCHIVE_TELEMETRY).unwrap(),
            "partial"
        );
        assert_eq!(
            export_resp
                .headers()
                .get(HEADER_OMITTED_SESSION_SAMPLES)
                .unwrap(),
            "3"
        );
        assert_eq!(
            export_resp
                .headers()
                .get(HEADER_OMITTED_BANDWIDTH_SAMPLES)
                .unwrap(),
            "1"
        );

        // Integrity checks on omittedSamples: stripping, nulling, tampering, zeroing, unknown fields all fail.
        let encoded = serde_json::to_vec(&archive).unwrap();
        let mut stripped: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        stripped["manifest"]
            .as_object_mut()
            .unwrap()
            .remove("omittedSamples");
        assert!(validate_archive_bytes(&serde_json::to_vec(&stripped).unwrap()).is_err());

        let mut nulled: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        nulled["manifest"]["omittedSamples"] = serde_json::Value::Null;
        assert!(validate_archive_bytes(&serde_json::to_vec(&nulled).unwrap()).is_err());

        let mut tampered = archive.clone();
        tampered.manifest.omitted_samples = Some(OmittedSamples {
            session_samples: 1,
            bandwidth_samples: 1,
        });
        assert!(tampered.validate().is_err());

        let mut zeroed = archive.clone();
        zeroed.manifest.omitted_samples = Some(OmittedSamples {
            session_samples: 0,
            bandwidth_samples: 0,
        });
        zeroed.manifest.sha256 = zeroed.digest().unwrap();
        assert!(zeroed.validate().is_err());

        let mut with_extra: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        with_extra["manifest"]["omittedSamples"]["extra"] = serde_json::json!(1);
        assert!(validate_archive_bytes(&serde_json::to_vec(&with_extra).unwrap()).is_err());

        // Merge preview + restore explicitly surface omitted samples, notice, and backup verification.
        let mut merge_target = disposable_db();
        let (merge_preview, merge_token) = preview_and_token(
            &merge_target.connection,
            &archive,
            RestoreMode::Merge,
            44,
            7000,
        );
        let merge_preview_resp = response_from_preview(&merge_preview, merge_token.clone(), 7300);
        assert_eq!(
            merge_preview_resp.omitted_samples,
            archive.manifest.omitted_samples
        );
        assert!(merge_preview_resp
            .partial_telemetry_notice
            .as_deref()
            .is_some_and(|n| n.contains("3 earlier session") && n.contains("1 earlier bandwidth")));
        // Approval issued for merge cannot be replayed in replace mode.
        assert!(restore_connection(
            &mut merge_target.connection,
            merge_target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Replace,
            &archive,
            &merge_token,
            7001,
        )
        .is_err());
        let merge_restored = restore_connection(
            &mut merge_target.connection,
            merge_target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Merge,
            &archive,
            &merge_token,
            7001,
        )
        .unwrap();
        assert!(merge_restored.backup_verified);
        assert_eq!(
            merge_restored.omitted_samples,
            archive.manifest.omitted_samples
        );
        assert!(merge_restored.partial_telemetry_notice.is_some());
        assert_private_backup_exists(&merge_target.root);

        // Replace preview + restore explicitly warn about deleting destination samples & restoring retained subset.
        let mut replace_target = disposable_db();
        let (replace_preview, replace_token) = preview_and_token(
            &replace_target.connection,
            &archive,
            RestoreMode::Replace,
            44,
            8000,
        );
        let replace_preview_resp =
            response_from_preview(&replace_preview, replace_token.clone(), 8300);
        assert_eq!(
            replace_preview_resp.omitted_samples,
            archive.manifest.omitted_samples
        );
        assert!(replace_preview_resp
            .partial_telemetry_notice
            .as_deref()
            .is_some_and(|n| n.contains("Replacement deletes existing destination samples")));
        assert!(replace_preview_resp
            .replacement_notice
            .as_deref()
            .is_some_and(|n| n.contains("3 earlier session")));
        let replace_restored = restore_connection(
            &mut replace_target.connection,
            replace_target.database_path.to_str().unwrap(),
            44,
            RestoreMode::Replace,
            &archive,
            &replace_token,
            8001,
        )
        .unwrap();
        assert!(replace_restored.backup_verified);
        assert_eq!(
            replace_restored.omitted_samples,
            archive.manifest.omitted_samples
        );
        assert!(replace_restored.partial_telemetry_notice.is_some());
        assert_private_backup_exists(&replace_target.root);
    }

    #[test]
    fn history_and_labels_are_never_dropped_when_budget_is_exhausted() {
        let source = disposable_db();
        seed_sensitive_data(&source.connection);
        // Base rows = 1 history + 1 label + 1 policy = 3.
        // Budget = 3 leaves zero sample budget: preserves history/labels and explicitly omits all samples.
        let zero_sample_archive =
            build_archive_with_budget(&source.connection, 1_798_876_800, 3).unwrap();
        assert_eq!(zero_sample_archive.manifest.record_counts.history, 1);
        assert_eq!(zero_sample_archive.manifest.record_counts.labels, 1);
        assert_eq!(
            zero_sample_archive.manifest.record_counts.session_samples,
            0
        );
        assert_eq!(
            zero_sample_archive.manifest.record_counts.bandwidth_samples,
            0
        );
        assert_eq!(
            zero_sample_archive.manifest.omitted_samples,
            Some(OmittedSamples {
                session_samples: 1,
                bandwidth_samples: 1,
            })
        );

        // Budget below history + labels + policy fails closed rather than dropping history or labels.
        let err = build_archive_with_budget(&source.connection, 1_798_876_800, 2).unwrap_err();
        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(err.code, "streaming_archive_too_large");
    }

    #[test]
    fn real_hundred_thousand_row_cap_marks_omitted_session_samples_and_preserves_history() {
        let source = disposable_db();
        source
            .connection
            .execute(
                "INSERT INTO streaming_history(id,session_key,provider,server_name,user_id,user_name,item_id,item_name,provenance,server_id,timestamp_certainty,byte_accuracy,policy_status) VALUES (1,'s-1','plex','Plex','u1','Alice','i1','Film','observed_session','srv-1','observed','estimated','included')",
                [],
            )
            .unwrap();
        source
            .connection
            .execute(
                "INSERT INTO streaming_history_labels(history_id,kind,value,name) VALUES (1,'library','lib-1','Movies')",
                [],
            )
            .unwrap();
        let tx = source.connection.unchecked_transaction().unwrap();
        {
            let mut stmt = tx
                .prepare("INSERT INTO streaming_session_samples(history_id,sampled_at,observed_secs,playing,bitrate_bps) VALUES (1,?1,1,1,0)")
                .unwrap();
            for ts in 1..=100_005_i64 {
                stmt.execute([ts]).unwrap();
            }
        }
        tx.commit().unwrap();

        let archive = build_archive(&source.connection, 1_798_876_800).unwrap();
        assert_eq!(archive.manifest.record_counts.history, 1);
        assert_eq!(archive.manifest.record_counts.labels, 1);
        assert_eq!(
            archive.manifest.record_counts.session_samples,
            MAX_PORTABLE_ROWS - 3
        );
        assert_eq!(
            archive.manifest.omitted_samples,
            Some(OmittedSamples {
                session_samples: 8,
                bandwidth_samples: 0,
            })
        );
        // Oldest 8 samples (1..=8) were dropped; newest 99,997 (9..=100,005) are retained.
        assert_eq!(archive.data.session_samples.first().unwrap().sampled_at, 9);
        assert_eq!(
            archive.data.session_samples.last().unwrap().sampled_at,
            100_005
        );
        assert!(ensure_archive_within_byte_limit(&archive).is_ok());
    }
}
