use super::{
    ARCHIVE_FORMAT, ARCHIVE_FORMAT_VERSION, DATABASE_SCHEMA_VERSION, MAX_PORTABLE_ROWS,
    MAX_TEXT_BYTES, OMITTED_TABLES, PROVENANCE_VERSION, REDACTED_FIELDS,
};
use crate::auth::api_error;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(super) type PortabilityResult<T> = Result<T, PortabilityError>;

#[derive(Clone, Copy, Debug)]
pub(super) struct PortabilityError {
    pub(super) status: StatusCode,
    pub(super) code: &'static str,
    pub(super) message: &'static str,
}

impl PortabilityError {
    pub(super) const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }

    pub(super) const fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "admin_required",
            "Admin access required",
        )
    }

    pub(super) const fn invalid() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_streaming_archive",
            "The streaming archive is malformed or invalid",
        )
    }

    pub(super) const fn unsupported() -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_streaming_archive",
            "The streaming archive version is not supported",
        )
    }

    pub(super) const fn too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "streaming_archive_too_large",
            "The streaming archive exceeds the configured size or row limit",
        )
    }

    pub(super) const fn unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "streaming_portability_unavailable",
            "Streaming portability is temporarily unavailable",
        )
    }

    pub(super) const fn stale_preview() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "streaming_preview_changed",
            "Streaming data changed after preview; create and approve a new preview",
        )
    }

    pub(super) const fn invalid_approval() -> Self {
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
pub(super) struct RecordCounts {
    pub(super) history: usize,
    pub(super) labels: usize,
    pub(super) session_samples: usize,
    pub(super) bandwidth_samples: usize,
    pub(super) tracking_policies: usize,
}

impl RecordCounts {
    pub(super) fn total(&self) -> Option<usize> {
        self.history
            .checked_add(self.labels)?
            .checked_add(self.session_samples)?
            .checked_add(self.bandwidth_samples)?
            .checked_add(self.tracking_policies)
    }

    pub(super) fn zero() -> Self {
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
pub(super) struct HistoryRecord {
    pub(super) id: i64,
    pub(super) session_key: String,
    pub(super) provider: String,
    pub(super) server_name: String,
    pub(super) user_id: String,
    pub(super) user_name: String,
    pub(super) client_name: String,
    pub(super) item_id: String,
    pub(super) item_name: String,
    pub(super) item_type: String,
    pub(super) series_name: String,
    pub(super) series_id: String,
    pub(super) season_number: Option<i64>,
    pub(super) episode_number: Option<i64>,
    pub(super) production_year: Option<i64>,
    pub(super) play_method: String,
    pub(super) container: String,
    pub(super) video_codec: String,
    pub(super) video_resolution: String,
    pub(super) audio_codec: String,
    pub(super) audio_channels: Option<i64>,
    pub(super) subtitle_codec: String,
    pub(super) hw_accel: String,
    pub(super) transcode_reasons: String,
    pub(super) bitrate_bps: Option<i64>,
    pub(super) duration_secs: Option<i64>,
    pub(super) watched_secs: Option<i64>,
    pub(super) data_used_bytes: Option<i64>,
    pub(super) completion_pct: Option<f64>,
    pub(super) started_at: Option<String>,
    pub(super) last_seen_at: Option<String>,
    pub(super) ended_at: Option<String>,
    pub(super) is_active: Option<i64>,
    pub(super) provenance: String,
    pub(super) server_id: String,
    pub(super) source_event_id: Option<String>,
    pub(super) timestamp_certainty: String,
    pub(super) byte_accuracy: String,
    pub(super) policy_status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct HistoryLabel {
    pub(super) history_id: i64,
    pub(super) kind: String,
    pub(super) value: String,
    pub(super) name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct SessionSample {
    pub(super) history_id: i64,
    pub(super) sampled_at: i64,
    pub(super) observed_secs: i64,
    pub(super) playing: bool,
    pub(super) bitrate_bps: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct BandwidthSample {
    pub(super) id: i64,
    pub(super) timestamp: Option<String>,
    pub(super) provider: String,
    pub(super) active_streams: Option<i64>,
    pub(super) direct_play_count: Option<i64>,
    pub(super) direct_stream_count: Option<i64>,
    pub(super) transcode_count: Option<i64>,
    pub(super) total_bitrate_bps: Option<i64>,
    pub(super) bytes_delta: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct TrackingPolicy {
    pub(super) minimum_watch_secs: i64,
    pub(super) excluded_users: String,
    pub(super) excluded_libraries: String,
    pub(super) reconnect_window_secs: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ArchiveData {
    pub(super) history: Vec<HistoryRecord>,
    pub(super) labels: Vec<HistoryLabel>,
    pub(super) session_samples: Vec<SessionSample>,
    pub(super) bandwidth_samples: Vec<BandwidthSample>,
    pub(super) tracking_policy: TrackingPolicy,
}

impl ArchiveData {
    pub(super) fn counts(&self) -> RecordCounts {
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
pub(super) struct OmittedSamples {
    pub(super) session_samples: usize,
    pub(super) bandwidth_samples: usize,
}

impl OmittedSamples {
    pub(super) fn is_empty(&self) -> bool {
        self.session_samples == 0 && self.bandwidth_samples == 0
    }
}

pub(super) fn deserialize_present_omitted_samples<'de, D>(
    deserializer: D,
) -> Result<Option<OmittedSamples>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    OmittedSamples::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct ArchiveManifest {
    pub(super) format: String,
    pub(super) format_version: u16,
    pub(super) schema_version: u16,
    pub(super) provenance_version: u16,
    pub(super) exported_at: String,
    pub(super) record_counts: RecordCounts,
    #[serde(
        default,
        deserialize_with = "deserialize_present_omitted_samples",
        skip_serializing_if = "Option::is_none"
    )]
    pub(super) omitted_samples: Option<OmittedSamples>,
    pub(super) redacted_fields: Vec<String>,
    pub(super) omitted_tables: Vec<String>,
    pub(super) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct StreamingArchive {
    pub(super) manifest: ArchiveManifest,
    pub(super) data: ArchiveData,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ArchiveDigestView<'a> {
    pub(super) format: &'a str,
    pub(super) format_version: u16,
    pub(super) schema_version: u16,
    pub(super) provenance_version: u16,
    pub(super) exported_at: &'a str,
    pub(super) record_counts: &'a RecordCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) omitted_samples: Option<&'a OmittedSamples>,
    pub(super) redacted_fields: &'a [String],
    pub(super) omitted_tables: &'a [String],
    pub(super) data: &'a ArchiveData,
}

impl StreamingArchive {
    pub(super) fn digest(&self) -> PortabilityResult<String> {
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

    pub(super) fn validate(&self) -> PortabilityResult<()> {
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

    pub(super) fn validate_rows(&self) -> PortabilityResult<()> {
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

pub(super) struct DateTimeCheck;

impl DateTimeCheck {
    pub(super) fn is_invalid(value: &str) -> bool {
        chrono::DateTime::parse_from_rfc3339(value).is_err() || !valid_text(value, 128)
    }
}

pub(super) fn valid_history_text(row: &HistoryRecord) -> bool {
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

pub(super) fn valid_text(value: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes && !value.contains('\0')
}

pub(super) fn json_array(value: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(value)
        .ok()
        .is_some_and(|parsed| parsed.is_array())
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum RestoreMode {
    Merge,
    Replace,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct PreviewRequest {
    pub(super) mode: RestoreMode,
    pub(super) archive: StreamingArchive,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RestoreRequest {
    pub(super) mode: RestoreMode,
    pub(super) archive: StreamingArchive,
    pub(super) approval_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Conflict {
    pub(super) table: String,
    pub(super) archive_key: String,
    pub(super) existing_key: Option<String>,
    pub(super) reason: String,
    pub(super) action: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct PlanCounts {
    pub(super) insert: RecordCounts,
    pub(super) exact_duplicate: RecordCounts,
    pub(super) conflict: RecordCounts,
}

impl Default for RecordCounts {
    fn default() -> Self {
        Self::zero()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct PreviewResponse {
    pub(super) mode: RestoreMode,
    pub(super) archive_sha256: String,
    pub(super) preview_sha256: String,
    pub(super) expires_at: String,
    pub(super) archive_counts: RecordCounts,
    pub(super) target_counts: RecordCounts,
    pub(super) plan: PlanCounts,
    pub(super) replacement_counts: Option<RecordCounts>,
    pub(super) replacement_notice: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) omitted_samples: Option<OmittedSamples>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) partial_telemetry_notice: Option<String>,
    pub(super) conflicts: Vec<Conflict>,
    pub(super) approval_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct RestoreResponse {
    pub(super) mode: RestoreMode,
    pub(super) archive_sha256: String,
    pub(super) preview_sha256: String,
    pub(super) backup_verified: bool,
    pub(super) archive_counts: RecordCounts,
    pub(super) resulting_counts: RecordCounts,
    pub(super) plan: PlanCounts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) omitted_samples: Option<OmittedSamples>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) partial_telemetry_notice: Option<String>,
    pub(super) conflicts: Vec<Conflict>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuditSummary<'a> {
    pub(super) counts: &'a RecordCounts,
    pub(super) snapshot_sha256: &'a str,
}
