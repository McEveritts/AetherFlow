//! Version-tolerant wire records. Unknown metadata survives details and exports.
use crate::tabs::contracts::{nullable, number, string, StreamingSummaryContract};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct ProviderStatus {
    pub provider: String,
    pub name: String,
    pub status: String,
    #[serde(deserialize_with = "string")]
    pub server_id: String,
    #[serde(deserialize_with = "string")]
    pub version: String,
    pub url: String,
    pub enabled: Option<bool>,
    pub error_message: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl ProviderStatus {
    pub fn status_key(&self) -> &str {
        match self.status.as_str() {
            "coming_soon" | "Coming soon" => "Coming soon",
            "unconfigured" | "Unconfigured" => "Unconfigured",
            "configured" => "Configured",
            "connected" => "Connected",
            "degraded" => "Degraded",
            "offline" => "Offline",
            "unreachable" => "Unreachable",
            "unavailable" => "Unavailable",
            "disabled" => "Disabled",
            "" => "Unrecorded",
            other => other,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct PlaybackSession {
    pub provider: String,
    pub session_id: String,
    #[serde(deserialize_with = "string")]
    pub server_id: String,
    pub server_name: String,
    pub item_name: String,
    pub user_name: String,
    #[serde(deserialize_with = "string")]
    pub series_name: String,
    #[serde(deserialize_with = "string")]
    pub season_number: String,
    #[serde(deserialize_with = "string")]
    pub episode_number: String,
    #[serde(deserialize_with = "string")]
    pub play_method: String,
    pub state: String,
    #[serde(deserialize_with = "number")]
    pub progress_pct: Option<f64>,
    #[serde(deserialize_with = "number")]
    pub position_secs: Option<f64>,
    #[serde(deserialize_with = "number")]
    pub duration_secs: Option<f64>,
    #[serde(deserialize_with = "string")]
    pub video_resolution: String,
    #[serde(deserialize_with = "string")]
    pub video_codec: String,
    #[serde(deserialize_with = "string")]
    pub audio_codec: String,
    #[serde(deserialize_with = "string")]
    pub audio_channels: String,
    #[serde(deserialize_with = "string")]
    pub container: String,
    #[serde(deserialize_with = "string")]
    pub bandwidth_mbps: String,
    #[serde(deserialize_with = "string")]
    pub bitrate_bps: String,
    #[serde(deserialize_with = "string")]
    pub client_name: String,
    #[serde(deserialize_with = "string")]
    pub device_name: String,
    pub supports_media_control: bool,
    pub can_send_message: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl PlaybackSession {
    pub fn controllable(&self) -> bool {
        self.provider == "jellyfin" && self.supports_media_control && !self.session_id.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct Dashboard {
    #[serde(deserialize_with = "nullable")]
    pub servers: Vec<ProviderStatus>,
    #[serde(deserialize_with = "nullable")]
    pub active_sessions: Vec<PlaybackSession>,
    #[serde(deserialize_with = "nullable")]
    pub live_summary: StreamingSummaryContract,
    pub updated_at: String,
    #[serde(deserialize_with = "nullable")]
    pub analytics: DashboardAnalytics,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct DashboardAnalytics {
    #[serde(deserialize_with = "nullable")]
    pub recent_history: Vec<HistoryItem>,
    #[serde(deserialize_with = "nullable")]
    pub historical_estimates: Vec<HistoryEstimate>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct HistoryEstimate {
    pub provenance: String,
    #[serde(deserialize_with = "string")]
    pub records: String,
    #[serde(deserialize_with = "string")]
    pub undated_records: String,
    #[serde(deserialize_with = "number")]
    pub reported_watch_time_secs: Option<f64>,
    #[serde(deserialize_with = "nullable")]
    pub time_series: Vec<EstimatePoint>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct EstimatePoint {
    pub date: String,
    #[serde(deserialize_with = "number")]
    pub watch_time_secs: Option<f64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct HistoryItem {
    pub id: i64,
    pub provider: String,
    pub server_id: String,
    pub user_id: String,
    pub user_name: String,
    pub item_id: String,
    pub item_name: String,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    pub last_seen_at: Option<String>,
    pub provenance: String,
    pub policy_status: String,
    #[serde(deserialize_with = "number")]
    pub watched_secs: Option<f64>,
    pub included: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct HistoryScope {
    pub snapshot_token: String,
    pub as_of: String,
    pub expires_at: String,
    pub permission_scope: String,
    pub date_semantics: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct HistoryPage {
    #[serde(deserialize_with = "nullable")]
    pub scope: HistoryScope,
    #[serde(deserialize_with = "nullable")]
    pub items: Vec<HistoryItem>,
    pub next_cursor: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub counts: HistoryCounts,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct ImportCapability {
    pub provider: String,
    pub server_id: String,
    pub json_batch_import_supported: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct HistoryCounts {
    #[serde(alias = "matching_records", deserialize_with = "number")]
    pub matching_records: Option<f64>,
    #[serde(alias = "available_records", deserialize_with = "number")]
    pub available_records: Option<f64>,
    #[serde(alias = "confirmed_plays", deserialize_with = "number")]
    pub confirmed_plays: Option<f64>,
    #[serde(alias = "watch_time_secs", deserialize_with = "number")]
    pub watch_time_secs: Option<f64>,
    #[serde(alias = "undated_records", deserialize_with = "number")]
    pub undated_records: Option<f64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct ImportCheckpoint {
    pub provider: String,
    pub server_id: String,
    pub source: String,
    pub checkpoint: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct ImportStatus {
    pub max_batch_events: Option<usize>,
    #[serde(deserialize_with = "nullable")]
    pub capabilities: Vec<ImportCapability>,
    #[serde(deserialize_with = "nullable")]
    pub checkpoints: Vec<ImportCheckpoint>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

// Required identity fields deliberately have no defaults: malformed events fail closed.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ImportEvent {
    pub source_event_id: String,
    pub user_id: String,
    pub item_id: String,
    pub item_name: String,
    pub started_at: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ImportBatch {
    pub provider: String,
    pub server_id: String,
    pub server_name: Option<String>,
    pub source: String,
    pub checkpoint: String,
    pub expected_checkpoint: Option<String>,
    pub events: Vec<ImportEvent>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct PolicyTarget {
    pub provider: String,
    pub server_id: String,
    pub id: String,
    pub name: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct TrackingPolicy {
    pub minimum_watch_secs: i64,
    pub reconnect_window_secs: i64,
    #[serde(deserialize_with = "nullable")]
    pub excluded_users: Vec<PolicyTarget>,
    #[serde(deserialize_with = "nullable")]
    pub excluded_libraries: Vec<PolicyTarget>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct UserBinding {
    pub af_user_id: i64,
    pub provider: String,
    pub server_id: String,
    pub provider_user_id: String,
    pub af_username: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct UserBindings {
    #[serde(deserialize_with = "nullable")]
    pub links: Vec<UserBinding>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct ArchivePreview {
    pub mode: String,
    pub approval_token: String,
    pub expires_at: String,
    pub archive_counts: BTreeMap<String, u64>,
    pub target_counts: BTreeMap<String, u64>,
    pub plan: BTreeMap<String, BTreeMap<String, u64>>,
    pub replacement_counts: Option<BTreeMap<String, u64>>,
    pub replacement_notice: Option<String>,
    #[serde(deserialize_with = "nullable")]
    pub conflicts: Vec<Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(super) struct ReconciliationPreview {
    pub preview_hash: String,
    pub approval_token: String,
    pub expires_at: String,
    pub total_affected_rows: u64,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct PortableArchive {
    pub manifest: ArchiveManifest,
    pub data: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ArchiveManifest {
    pub format: String,
    #[serde(default)]
    pub record_counts: BTreeMap<String, u64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn provider_tokens_have_human_translation_keys_and_keep_future_metadata() {
        for (token, key) in [
            ("coming_soon", "Coming soon"),
            ("unconfigured", "Unconfigured"),
            ("connected", "Connected"),
            ("degraded", "Degraded"),
            ("offline", "Offline"),
            ("configured", "Configured"),
        ] {
            let record: ProviderStatus =
                serde_json::from_value(json!({"status":token,"future":{"enabled":true}})).unwrap();
            assert_eq!(record.status_key(), key);
            assert_eq!(
                serde_json::to_value(record).unwrap()["future"]["enabled"],
                true
            );
        }
    }

    #[test]
    fn optional_live_counters_and_unknown_session_metadata_survive() {
        let dashboard: Dashboard = serde_json::from_value(json!({"servers":null,"liveSummary":null,"analytics":null,"activeSessions":[{"provider":"jellyfin","sessionId":"live","supportsMediaControl":true,"progressPct":"25.5","audioChannels":6,"futureCodec":"av2"}]})).unwrap();
        let session = &dashboard.active_sessions[0];
        assert!(dashboard.servers.is_empty());
        assert!(session.controllable());
        assert_eq!(session.progress_pct, Some(25.5));
        assert_eq!(session.audio_channels, "6");
        assert_eq!(serde_json::to_value(session).unwrap()["futureCodec"], "av2");
        assert!(!PlaybackSession::default().controllable());
    }

    #[test]
    fn history_snapshot_keeps_cursor_scope_and_unrecognized_evidence() {
        let page: HistoryPage = serde_json::from_value(json!({"scope":{"snapshotToken":"scope-1","revision":8},"nextCursor":"next-1","items":[{"id":42,"watchedSecs":null,"customEvidence":{"source":"upstream"}}]})).unwrap();
        assert_eq!(page.scope.snapshot_token, "scope-1");
        assert_eq!(page.next_cursor.as_deref(), Some("next-1"));
        assert_eq!(page.items[0].id, 42);
        assert_eq!(page.items[0].watched_secs, None);
        let value = serde_json::to_value(page).unwrap();
        assert_eq!(value["items"][0]["customEvidence"]["source"], "upstream");
        assert_eq!(value["scope"]["revision"], 8);
    }

    #[test]
    fn import_permissions_fail_closed_and_required_event_identity_is_strict() {
        let status: ImportStatus = serde_json::from_value(
            json!({"capabilities":[{"provider":"plex","serverId":"s"}],"checkpoints":null}),
        )
        .unwrap();
        assert!(!status.capabilities[0].json_batch_import_supported);
        assert!(status.checkpoints.is_empty());
        assert!(serde_json::from_value::<ImportEvent>(json!({"itemName":"Only a name"})).is_err());
        let event: ImportEvent = serde_json::from_value(json!({"sourceEventId":"event-1","userId":"u","itemId":"i","itemName":"Title","startedAt":"2026-11-16T00:00:00Z","codec":"h264"})).unwrap();
        assert_eq!(serde_json::to_value(event).unwrap()["codec"], "h264");
    }

    #[test]
    fn import_preview_round_trips_identity_and_opaque_checkpoint_without_inventing_fields() {
        let preview: ImportBatch = serde_json::from_value(json!({"provider":"jellyfin","serverId":"verified","serverName":"Media","source":"json","checkpoint":"opaque-next","expectedCheckpoint":null,"events":[{"sourceEventId":"e1","userId":"u","itemId":"i","itemName":"Title","startedAt":"2026-11-16T00:00:00Z"}],"futureReceipt":"v2"})).unwrap();
        assert_eq!(preview.server_id, "verified");
        assert!(preview.expected_checkpoint.is_none());
        assert_eq!(preview.events[0].source_event_id, "e1");
        let value = serde_json::to_value(preview).unwrap();
        assert_eq!(value["checkpoint"], "opaque-next");
        assert_eq!(value["futureReceipt"], "v2");
        assert!(
            serde_json::from_value::<ImportBatch>(json!({"provider":"jellyfin","events":[]}))
                .is_err()
        );
    }

    #[test]
    fn policy_binding_and_archive_summaries_preserve_versioned_fields() {
        let policy: TrackingPolicy = serde_json::from_value(json!({"minimumWatchSecs":30,"excludedUsers":[{"provider":"jellyfin","serverId":"s","id":"u"}],"historyRevision":9})).unwrap();
        assert_eq!(policy.excluded_users[0].id, "u");
        assert_eq!(serde_json::to_value(policy).unwrap()["historyRevision"], 9);
        let links: UserBindings = serde_json::from_value(
            json!({"links":[{"afUserId":3,"providerUserId":"remote","serverId":"s"}]}),
        )
        .unwrap();
        assert_eq!(links.links[0].af_user_id, 3);
        let preview: ArchivePreview = serde_json::from_value(
            json!({"approvalToken":"receipt","archiveCounts":{"history":2},"plan":{"insert":{"history":2}}}),
        )
        .unwrap();
        assert_eq!(preview.archive_counts["history"], 2);
        assert_eq!(
            serde_json::to_value(preview).unwrap()["plan"]["insert"]["history"],
            2
        );
    }
    #[test]
    fn history_counts_accept_live_snake_case_and_versioned_camel_case_fields() {
        for value in [
            json!({"matching_records":5,"confirmed_plays":2,"watch_time_secs":60}),
            json!({"matchingRecords":5,"confirmedPlays":2,"watchTimeSecs":60}),
        ] {
            let counts: HistoryCounts = serde_json::from_value(value).unwrap();
            assert_eq!(counts.matching_records, Some(5.0));
            assert_eq!(counts.confirmed_plays, Some(2.0));
            assert_eq!(counts.watch_time_secs, Some(60.0));
            assert_eq!(counts.undated_records, None);
        }
    }

    #[test]
    fn archive_summary_requires_manifest_and_object_data_but_keeps_extensions() {
        let archive: PortableArchive = serde_json::from_value(json!({"manifest":{"format":"aetherflow.streaming-history","formatVersion":1,"recordCounts":{"history":2}},"data":{"history":[]},"futureReceipt":true})).unwrap();
        assert_eq!(archive.manifest.record_counts["history"], 2);
        assert_eq!(
            serde_json::to_value(archive).unwrap()["futureReceipt"],
            true
        );
        assert!(serde_json::from_value::<PortableArchive>(
            json!({"manifest":{"format":"aetherflow.streaming-history"},"data":[]})
        )
        .is_err());
    }
}
