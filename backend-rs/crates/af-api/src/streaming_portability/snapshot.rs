use super::types::{
    ArchiveData, ArchiveManifest, BandwidthSample, HistoryLabel, HistoryRecord, OmittedSamples,
    PortabilityError, PortabilityResult, RecordCounts, SessionSample, StreamingArchive,
    TrackingPolicy,
};
use super::{
    ARCHIVE_FORMAT, ARCHIVE_FORMAT_VERSION, DATABASE_SCHEMA_VERSION, MAX_ARCHIVE_BYTES,
    MAX_BODY_BYTES, MAX_PORTABLE_ROWS, OMITTED_TABLES, PROVENANCE_VERSION, REDACTED_FIELDS,
};
use chrono::{SecondsFormat, TimeZone, Utc};
use rusqlite::{Connection, Row};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct PortableSnapshot {
    pub(super) history: Vec<HistoryRecord>,
    pub(super) labels: Vec<HistoryLabel>,
    pub(super) session_samples: Vec<SessionSample>,
    pub(super) bandwidth_samples: Vec<BandwidthSample>,
    pub(super) tracking_policy: TrackingPolicy,
}

impl PortableSnapshot {
    pub(super) fn counts(&self) -> RecordCounts {
        RecordCounts {
            history: self.history.len(),
            labels: self.labels.len(),
            session_samples: self.session_samples.len(),
            bandwidth_samples: self.bandwidth_samples.len(),
            tracking_policies: 1,
        }
    }

    pub(super) fn into_data(self) -> ArchiveData {
        ArchiveData {
            history: self.history,
            labels: self.labels,
            session_samples: self.session_samples,
            bandwidth_samples: self.bandwidth_samples,
            tracking_policy: self.tracking_policy,
        }
    }

    pub(super) fn digest(&self) -> PortabilityResult<String> {
        let bytes = serde_json::to_vec(self).map_err(|_| PortabilityError::invalid())?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

pub(super) struct LoadedSnapshot {
    pub(super) snapshot: PortableSnapshot,
    pub(super) omitted_samples: Option<OmittedSamples>,
}

pub(super) fn load_snapshot(conn: &Connection) -> PortabilityResult<LoadedSnapshot> {
    load_snapshot_with_budget(conn, MAX_PORTABLE_ROWS)
}

pub(super) fn load_snapshot_with_budget(
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

pub(super) fn ensure_snapshot_bounds(
    conn: &Connection,
    max_portable_rows: usize,
) -> PortabilityResult<()> {
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

pub(super) fn load_rows<T>(
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

pub(super) fn read_history(row: &Row<'_>) -> rusqlite::Result<HistoryRecord> {
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

pub(super) fn read_label(row: &Row<'_>) -> rusqlite::Result<HistoryLabel> {
    Ok(HistoryLabel {
        history_id: row.get(0)?,
        kind: row.get(1)?,
        value: row.get(2)?,
        name: row.get(3)?,
    })
}

pub(super) fn read_sample(row: &Row<'_>) -> rusqlite::Result<SessionSample> {
    Ok(SessionSample {
        history_id: row.get(0)?,
        sampled_at: row.get(1)?,
        observed_secs: row.get(2)?,
        playing: row.get::<_, i64>(3)? != 0,
        bitrate_bps: row.get(4)?,
    })
}

pub(super) fn read_bandwidth_sample(row: &Row<'_>) -> rusqlite::Result<BandwidthSample> {
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

pub(super) fn build_archive(conn: &Connection, now: i64) -> PortabilityResult<StreamingArchive> {
    build_archive_with_budget(conn, now, MAX_PORTABLE_ROWS)
}

pub(super) fn build_archive_with_budget(
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
pub(super) fn validate_archive_bytes(bytes: &[u8]) -> PortabilityResult<StreamingArchive> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(PortabilityError::too_large());
    }
    let archive: StreamingArchive =
        serde_json::from_slice(bytes).map_err(|_| PortabilityError::invalid())?;
    archive.validate()?;
    Ok(archive)
}
