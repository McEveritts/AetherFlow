use super::snapshot::{
    load_snapshot, read_bandwidth_sample, read_history, read_label, read_sample, PortableSnapshot,
};
use super::types::{
    ArchiveData, BandwidthSample, Conflict, HistoryLabel, HistoryRecord, OmittedSamples,
    PlanCounts, PortabilityError, PortabilityResult, PreviewResponse, RecordCounts, RestoreMode,
    SessionSample, StreamingArchive, TrackingPolicy,
};
use chrono::{SecondsFormat, TimeZone, Utc};
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PreviewFingerprint<'a> {
    pub(super) archive_sha256: &'a str,
    pub(super) mode: RestoreMode,
    pub(super) target_snapshot_sha256: &'a str,
    pub(super) plan: &'a PlanCounts,
    pub(super) replacement_counts: &'a Option<RecordCounts>,
    pub(super) conflicts: &'a [Conflict],
}

#[derive(Clone, Debug)]
pub(super) struct MergePlan {
    pub(super) counts: PlanCounts,
    pub(super) conflicts: Vec<Conflict>,
    pub(super) history_map: BTreeMap<i64, Option<i64>>,
    pub(super) history_inserts: Vec<HistoryRecord>,
    pub(super) label_inserts: Vec<HistoryLabel>,
    pub(super) sample_inserts: Vec<SessionSample>,
    pub(super) bandwidth_inserts: Vec<BandwidthSample>,
}

#[derive(Clone, Debug)]
pub(super) struct RestorePreview {
    pub(super) mode: RestoreMode,
    pub(super) archive_sha256: String,
    pub(super) preview_sha256: String,
    pub(super) archive_counts: RecordCounts,
    pub(super) target_counts: RecordCounts,
    pub(super) plan: PlanCounts,
    pub(super) replacement_counts: Option<RecordCounts>,
    pub(super) omitted_samples: Option<OmittedSamples>,
    pub(super) conflicts: Vec<Conflict>,
    pub(super) merge_plan: Option<MergePlan>,
}

pub(super) fn inspect_restore(
    conn: &Connection,
    archive: &StreamingArchive,
    mode: RestoreMode,
) -> PortabilityResult<RestorePreview> {
    let tx = conn.unchecked_transaction()?;
    let preview = inspect_restore_in_snapshot(&tx, archive, mode)?;
    tx.commit()?;
    Ok(preview)
}

pub(super) fn hash_json_record<T: Serialize>(
    hasher: &mut Sha256,
    value: &T,
) -> PortabilityResult<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| PortabilityError::invalid())?;
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(&bytes);
    Ok(())
}

pub(super) fn query_target_counts_and_digest_sql(
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

pub(super) fn inspect_restore_in_snapshot(
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

pub(super) fn target_snapshot_digest(
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

pub(super) fn event_key(row: &HistoryRecord) -> Option<(String, String, String)> {
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

pub(super) fn history_equivalent(left: &HistoryRecord, right: &HistoryRecord) -> bool {
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

pub(super) fn conflict(
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

pub(super) fn plan_merge(target: &PortableSnapshot, archive: &ArchiveData) -> MergePlan {
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

pub(super) fn partial_telemetry_notice(mode: RestoreMode, omitted: &OmittedSamples) -> String {
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

pub(super) fn response_from_preview(
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
