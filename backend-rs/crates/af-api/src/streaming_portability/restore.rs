use super::approvals::consume_approval;
use super::planning::{
    inspect_restore_in_snapshot, partial_telemetry_notice, query_target_counts_and_digest_sql,
    MergePlan,
};
use super::snapshot::load_snapshot;
use super::types::{
    ArchiveData, AuditSummary, BandwidthSample, HistoryLabel, HistoryRecord, PortabilityError,
    PortabilityResult, RestoreMode, RestoreResponse, SessionSample, StreamingArchive,
    TrackingPolicy,
};
use axum::http::StatusCode;
use chrono::{SecondsFormat, TimeZone, Utc};
use rusqlite::{params, Connection, Statement, TransactionBehavior};

pub(super) const INSERT_HISTORY_SQL: &str = "INSERT INTO streaming_history (id,session_key,provider,server_name,user_id,user_name,client_name,device_name,device_id,ip_address,item_id,item_name,item_type,series_name,series_id,season_number,episode_number,production_year,play_method,container,video_codec,video_resolution,audio_codec,audio_channels,subtitle_codec,hw_accel,transcode_reasons,bitrate_bps,duration_secs,watched_secs,data_used_bytes,completion_pct,started_at,last_seen_at,ended_at,is_active,provenance,server_id,source_event_id,timestamp_certainty,byte_accuracy,policy_status) VALUES (?1,?2,?3,?4,?5,?6,?7,'','','',?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39)";
pub(super) const INSERT_LABEL_SQL: &str =
    "INSERT INTO streaming_history_labels(history_id,kind,value,name) VALUES (?1,?2,?3,?4)";
pub(super) const INSERT_SESSION_SAMPLE_SQL: &str = "INSERT INTO streaming_session_samples(history_id,sampled_at,observed_secs,playing,bitrate_bps) VALUES (?1,?2,?3,?4,?5)";
pub(super) const INSERT_BANDWIDTH_SAMPLE_SQL: &str = "INSERT INTO streaming_bandwidth_samples(id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)";
pub(super) const INSERT_BANDWIDTH_SAMPLE_MERGE_SQL: &str = "INSERT INTO streaming_bandwidth_samples(timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) SELECT ?1,?2,?3,?4,?5,?6,?7,?8 WHERE NOT EXISTS (SELECT 1 FROM streaming_bandwidth_samples s WHERE s.timestamp IS ?1 AND s.provider = ?2)";

pub(super) fn insert_history_with(
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
pub(super) fn insert_history(conn: &Connection, row: &HistoryRecord) -> PortabilityResult<()> {
    let mut statement = conn.prepare(INSERT_HISTORY_SQL)?;
    insert_history_with(&mut statement, row)
}

pub(super) fn insert_histories(conn: &Connection, rows: &[HistoryRecord]) -> PortabilityResult<()> {
    let mut statement = conn.prepare(INSERT_HISTORY_SQL)?;
    for row in rows {
        insert_history_with(&mut statement, row)?;
    }
    Ok(())
}

pub(super) fn insert_labels(conn: &Connection, labels: &[HistoryLabel]) -> PortabilityResult<()> {
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

pub(super) fn insert_session_samples(
    conn: &Connection,
    samples: &[SessionSample],
) -> PortabilityResult<()> {
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

pub(super) fn insert_bandwidth_samples(
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

pub(super) fn insert_bandwidth_samples_merge(
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

pub(super) fn update_policy(conn: &Connection, policy: &TrackingPolicy) -> PortabilityResult<()> {
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

pub(super) fn apply_merge(conn: &Connection, plan: &MergePlan) -> PortabilityResult<bool> {
    insert_histories(conn, &plan.history_inserts)?;
    insert_labels(conn, &plan.label_inserts)?;
    insert_session_samples(conn, &plan.sample_inserts)?;
    let bw_inserted = insert_bandwidth_samples_merge(conn, &plan.bandwidth_inserts)?;
    Ok(!plan.history_inserts.is_empty()
        || !plan.label_inserts.is_empty()
        || !plan.sample_inserts.is_empty()
        || bw_inserted > 0)
}

pub(super) fn apply_replace(conn: &Connection, archive: &ArchiveData) -> PortabilityResult<()> {
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

pub(super) fn restore_connection(
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
