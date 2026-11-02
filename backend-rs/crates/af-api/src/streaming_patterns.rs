use crate::auth::{api_error, AuthUser};
use crate::streaming_history::{
    bounds, inclusion_predicate, query_filters, resolve_query_scope, scope_filters, HistoryError, HistoryQuery,
};
use axum::extract::{Extension, Query};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Datelike, Offset, Timelike, Utc};
use chrono_tz::Tz;
use rusqlite::{params_from_iter, types::Value, Connection};
use serde::{Deserialize, Serialize};

pub const RETENTION_DAYS: i32 = 90;
pub const MAX_TIMESERIES_BUCKETS: usize = 365;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HourlyActivity {
    pub hour: u8,
    pub play_count: i64,
    pub watch_time_secs: i64,
    pub estimated_bytes: i64,
    pub percentage_of_plays: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WeekdayActivity {
    pub weekday: u8,
    pub weekday_name: String,
    pub play_count: i64,
    pub watch_time_secs: i64,
    pub estimated_bytes: i64,
    pub percentage_of_plays: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ActivityTimeseriesBucket {
    pub bucket_start: String,
    pub bucket_end: String,
    pub play_count: i64,
    pub watch_time_secs: i64,
    pub estimated_bytes: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ActivityReport {
    pub timezone: String,
    pub window: String,
    pub from: Option<String>,
    pub until: Option<String>,
    pub total_confirmed_plays: i64,
    pub total_watch_time_secs: i64,
    pub total_estimated_bytes: i64,
    pub undated_records: i64,
    pub hourly_breakdown: Vec<HourlyActivity>,
    pub weekday_breakdown: Vec<WeekdayActivity>,
    pub timeseries: Vec<ActivityTimeseriesBucket>,
    pub dst_transitions_observed: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConcurrencyBucketStatus {
    Available,
    NoActivity,
    Gap,
    RetentionExpired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConcurrencyBucket {
    pub bucket_start: String,
    pub bucket_end: String,
    pub peak_concurrency: Option<i64>,
    pub avg_concurrency: Option<f64>,
    pub peak_bitrate_bps: Option<i64>,
    pub sample_count: i64,
    pub status: ConcurrencyBucketStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConcurrencyReport {
    pub window: String,
    pub from: Option<String>,
    pub until: Option<String>,
    pub timezone: String,
    pub retention_days: i32,
    pub retention_cutoff: String,
    pub retention_limited: bool,
    pub peak_concurrency: Option<i64>,
    pub peak_concurrency_at: Option<String>,
    pub avg_concurrency: Option<f64>,
    pub peak_bitrate_bps: Option<i64>,
    pub total_samples_analyzed: i64,
    pub buckets: Vec<ConcurrencyBucket>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PatternsSummaryReport {
    pub activity: ActivityReport,
    pub concurrency: ConcurrencyReport,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UserDrilldownItem {
    pub provider: String,
    pub server_id: String,
    pub user_id: String,
    pub user_name: String,
    pub play_count: i64,
    pub watch_time_secs: i64,
    pub estimated_bytes: i64,
    pub distinct_items: i64,
    pub last_played_at: Option<String>,
    pub direct_play_count: i64,
    pub direct_stream_count: i64,
    pub transcode_count: i64,
    pub unknown_method_count: i64,
    pub percentage_of_plays: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClientDrilldownItem {
    pub client_name: String,
    pub device_name: String,
    pub play_count: i64,
    pub watch_time_secs: i64,
    pub estimated_bytes: i64,
    pub distinct_users: i64,
    pub direct_play_count: i64,
    pub direct_stream_count: i64,
    pub transcode_count: i64,
    pub unknown_method_count: i64,
    pub percentage_of_plays: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ItemDrilldownItem {
    pub provider: String,
    pub server_id: String,
    pub item_id: String,
    pub item_name: String,
    pub item_type: Option<String>,
    pub series_name: Option<String>,
    pub play_count: i64,
    pub watch_time_secs: i64,
    pub estimated_bytes: i64,
    pub distinct_viewers: i64,
    pub last_played_at: Option<String>,
    pub percentage_of_plays: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LibraryDrilldownItem {
    pub provider: String,
    pub server_id: String,
    pub library_id: String,
    pub library_name: String,
    pub play_count: i64,
    pub watch_time_secs: i64,
    pub estimated_bytes: i64,
    pub distinct_viewers: i64,
    pub distinct_items: i64,
    pub percentage_of_plays: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GenreDrilldownItem {
    pub genre: String,
    pub play_count: i64,
    pub watch_time_secs: i64,
    pub estimated_bytes: i64,
    pub distinct_viewers: i64,
    pub distinct_items: i64,
    pub percentage_of_plays: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelMetrics {
    pub cohort_distinct_plays: i64,
    pub sum_of_label_plays: i64,
    pub is_overlapping: bool,
    pub unlabeled_plays: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DrilldownReport {
    pub cohort_distinct_plays: i64,
    pub cohort_total_watch_time_secs: i64,
    pub cohort_total_estimated_bytes: i64,
    pub cohort_distinct_users: i64,
    pub cohort_distinct_items: i64,
    pub users: Vec<UserDrilldownItem>,
    pub clients: Vec<ClientDrilldownItem>,
    pub items: Vec<ItemDrilldownItem>,
    pub libraries: Vec<LibraryDrilldownItem>,
    pub library_metrics: LabelMetrics,
    pub genres: Vec<GenreDrilldownItem>,
    pub genre_metrics: LabelMetrics,
}

fn detect_dst_transitions(start_unix: i64, end_unix: i64, tz: &Tz) -> Vec<String> {
    let mut notes = Vec::new();
    let get_offset = |ts: i64| -> Option<i32> {
        DateTime::from_timestamp(ts, 0).map(|dt| dt.with_timezone(tz).offset().fix().local_minus_utc())
    };
    let mut prev_offset = match get_offset(start_unix) {
        Some(off) => off,
        None => return notes,
    };
    let span_secs = (end_unix - start_unix).max(0);
    if span_secs == 0 {
        return notes;
    }
    let step_secs = if span_secs <= 7 * 86400 {
        3600i64
    } else {
        86400i64
    };
    let mut cur = start_unix;
    while cur < end_unix {
        let next = (cur + step_secs).min(end_unix);
        if let Some(next_offset) = get_offset(next) {
            if next_offset != prev_offset {
                let diff_minutes = (next_offset - prev_offset) / 60;
                let direction = if diff_minutes > 0 {
                    "spring forward (+offset)"
                } else {
                    "fall back (-offset)"
                };
                notes.push(format!(
                    "Observed DST transition in window: local UTC offset changed by {} minutes ({})",
                    diff_minutes, direction
                ));
                prev_offset = next_offset;
            }
        }
        cur = next;
    }
    notes
}

fn iso_timestamp(timestamp: Option<i64>) -> Option<String> {
    timestamp
        .and_then(|val| DateTime::from_timestamp(val, 0))
        .map(|val| val.to_rfc3339())
}

pub fn query_activity_patterns(
    conn: &Connection,
    raw: HistoryQuery,
    user: &AuthUser,
    now: i64,
) -> Result<ActivityReport, HistoryError> {
    let tx = conn.unchecked_transaction()?;
    let (query, watermark, _revision, as_of) = resolve_query_scope(&tx, raw, user, now)?;
    let report = query_activity_patterns_impl(&tx, &query, watermark, as_of, user)?;
    tx.commit()?;
    Ok(report)
}

fn query_activity_patterns_impl(
    conn: &Connection,
    query: &HistoryQuery,
    watermark: i64,
    as_of: i64,
    user: &AuthUser,
) -> Result<ActivityReport, HistoryError> {
    let tz: Tz = query
        .timezone
        .parse()
        .map_err(|_| HistoryError::invalid("timezone must be an IANA timezone"))?;
    let (start_opt, end_opt) = bounds(query, as_of)?;

    let (mut clauses, mut values) = scope_filters(query, user, watermark);
    query_filters(query, as_of, &mut clauses, &mut values)?;

    clauses.push("h.provenance IN ('observed_session', 'imported_event')".into());
    clauses.push(format!("({})", inclusion_predicate()));

    let sql = format!(
        "SELECT h.id, h.event_unix, COALESCE(h.watched_secs, 0), \
         CASE WHEN h.byte_accuracy = 'estimated' THEN COALESCE(h.data_used_bytes, 0) ELSE 0 END \
         FROM streaming_history h CROSS JOIN streaming_tracking_policies p \
         WHERE {}",
        clauses.join(" AND ")
    );

    let effective_end = end_opt.unwrap_or(as_of);
    let effective_start = match start_opt {
        Some(s) => s,
        None => {
            let min_sql = format!(
                "SELECT MIN(h.event_unix) FROM streaming_history h CROSS JOIN streaming_tracking_policies p WHERE {} AND h.event_unix IS NOT NULL",
                clauses.join(" AND ")
            );
            let min_ts: Option<i64> = conn
                .query_row(&min_sql, params_from_iter(&values), |row| row.get(0))
                .unwrap_or(None);
            min_ts.unwrap_or(effective_end - 7 * 86400)
        }
    };

    let span_secs = (effective_end - effective_start).max(0);
    let step_secs = if span_secs <= 7 * 86400 {
        3600i64
    } else {
        ((span_secs + 365 * 86400 - 1) / (365 * 86400)).max(1) * 86400
    };

    let mut timeseries = Vec::new();
    let mut bucket_bounds = Vec::new();
    if span_secs > 0 {
        let mut cur = effective_start;
        while cur < effective_end && timeseries.len() < MAX_TIMESERIES_BUCKETS {
            let next = (cur + step_secs).min(effective_end);
            bucket_bounds.push((cur, next));
            timeseries.push(ActivityTimeseriesBucket {
                bucket_start: iso_timestamp(Some(cur)).unwrap_or_default(),
                bucket_end: iso_timestamp(Some(next)).unwrap_or_default(),
                play_count: 0,
                watch_time_secs: 0,
                estimated_bytes: 0,
            });
            cur = next;
        }
    }

    let mut hourly = vec![
        HourlyActivity {
            hour: 0,
            play_count: 0,
            watch_time_secs: 0,
            estimated_bytes: 0,
            percentage_of_plays: 0.0,
        };
        24
    ];
    for (i, item) in hourly.iter_mut().enumerate() {
        item.hour = i as u8;
    }

    let day_names = [
        "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
    ];
    let mut weekday = (0..7)
        .map(|d| WeekdayActivity {
            weekday: d as u8,
            weekday_name: day_names[d].into(),
            play_count: 0,
            watch_time_secs: 0,
            estimated_bytes: 0,
            percentage_of_plays: 0.0,
        })
        .collect::<Vec<_>>();

    let mut total_confirmed_plays = 0i64;
    let mut total_watch_time_secs = 0i64;
    let mut total_estimated_bytes = 0i64;
    let mut undated_records = 0i64;

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params_from_iter(&values))?;

    while let Some(row) = rows.next()? {
        let event_unix: Option<i64> = row.get(1)?;
        let watched_secs: i64 = row.get(2)?;
        let data_used_bytes: i64 = row.get(3)?;

        total_confirmed_plays += 1;
        total_watch_time_secs += watched_secs;
        total_estimated_bytes += data_used_bytes;

        match event_unix {
            Some(ts) => {
                if let Some(dt) = DateTime::from_timestamp(ts, 0) {
                    let local_dt = dt.with_timezone(&tz);
                    let h = local_dt.hour() as usize;
                    if h < 24 {
                        hourly[h].play_count += 1;
                        hourly[h].watch_time_secs += watched_secs;
                        hourly[h].estimated_bytes += data_used_bytes;
                    }
                    let w = local_dt.weekday().num_days_from_monday() as usize;
                    if w < 7 {
                        weekday[w].play_count += 1;
                        weekday[w].watch_time_secs += watched_secs;
                        weekday[w].estimated_bytes += data_used_bytes;
                    }
                }

                if ts >= effective_start && ts < effective_end && !bucket_bounds.is_empty() {
                    let idx = ((ts - effective_start) / step_secs) as usize;
                    if idx < bucket_bounds.len()
                        && ts >= bucket_bounds[idx].0
                        && ts < bucket_bounds[idx].1
                    {
                        timeseries[idx].play_count += 1;
                        timeseries[idx].watch_time_secs += watched_secs;
                        timeseries[idx].estimated_bytes += data_used_bytes;
                    } else {
                        for (b_idx, &(b_start, b_end)) in bucket_bounds.iter().enumerate() {
                            if ts >= b_start && ts < b_end {
                                timeseries[b_idx].play_count += 1;
                                timeseries[b_idx].watch_time_secs += watched_secs;
                                timeseries[b_idx].estimated_bytes += data_used_bytes;
                                break;
                            }
                        }
                    }
                }
            }
            None => {
                undated_records += 1;
            }
        }
    }

    if total_confirmed_plays > 0 {
        for h in &mut hourly {
            h.percentage_of_plays = (h.play_count as f64 / total_confirmed_plays as f64) * 100.0;
        }
        for w in &mut weekday {
            w.percentage_of_plays = (w.play_count as f64 / total_confirmed_plays as f64) * 100.0;
        }
    }

    let transition_start = effective_start.max(effective_end - 366 * 86400);
    let mut dst_notes = detect_dst_transitions(transition_start, effective_end, &tz);
    if transition_start > effective_start { dst_notes.push("DST transition listing is limited to the latest 366 days; activity buckets retain the full query window.".into()); }

    Ok(ActivityReport {
        timezone: query.timezone.clone(),
        window: query.window.clone(),
        from: iso_timestamp(start_opt),
        until: iso_timestamp(end_opt),
        total_confirmed_plays,
        total_watch_time_secs,
        total_estimated_bytes,
        undated_records,
        hourly_breakdown: hourly,
        weekday_breakdown: weekday,
        timeseries,
        dst_transitions_observed: dst_notes,
    })
}

pub fn query_concurrency_patterns(
    conn: &Connection,
    raw: HistoryQuery,
    user: &AuthUser,
    now: i64,
) -> Result<ConcurrencyReport, HistoryError> {
    let tx = conn.unchecked_transaction()?;
    let (query, watermark, _revision, as_of) = resolve_query_scope(&tx, raw, user, now)?;
    let report = query_concurrency_patterns_impl(&tx, &query, watermark, as_of, user)?;
    tx.commit()?;
    Ok(report)
}

fn query_concurrency_patterns_impl(
    conn: &Connection,
    query: &HistoryQuery,
    watermark: i64,
    as_of: i64,
    user: &AuthUser,
) -> Result<ConcurrencyReport, HistoryError> {
    let (start_opt, end_opt) = bounds(query, as_of)?;

    let retention_cutoff = as_of - (RETENTION_DAYS as i64 * 86400);
    let retention_limited = match start_opt {
        Some(s) => s < retention_cutoff,
        None => true,
    };

    let (mut clauses, mut values) = scope_filters(query, user, watermark);
    query_filters(query, as_of, &mut clauses, &mut values)?;
    clauses.push("h.provenance = 'observed_session'".into());
    clauses.push(format!("({})", inclusion_predicate()));

    let effective_end = end_opt.unwrap_or(as_of);
    let requested_start = start_opt.unwrap_or(retention_cutoff);

    let span_secs = (effective_end - requested_start).max(0);
    let step_secs = if span_secs <= 7 * 86400 {
        3600i64
    } else {
        ((span_secs + 365 * 86400 - 1) / (365 * 86400)).max(1) * 86400
    };

    let sample_query_start = requested_start.max(retention_cutoff);
    let mut sample_clauses = clauses.clone();
    let mut sample_values = values.clone();

    sample_clauses.push("s.sampled_at >= ?".into());
    sample_values.push(Value::Integer(sample_query_start));
    sample_clauses.push("s.sampled_at < ?".into());
    sample_values.push(Value::Integer(effective_end));

    let sample_sql = format!(
        "SELECT s.sampled_at, \
         COUNT(DISTINCT CASE WHEN s.playing = 1 THEN s.history_id END) AS active_sessions, \
         COALESCE(SUM(CASE WHEN s.playing = 1 THEN s.bitrate_bps ELSE 0 END), 0) AS total_bitrate \
         FROM streaming_session_samples s \
         JOIN streaming_history h ON s.history_id = h.id \
         CROSS JOIN streaming_tracking_policies p \
         WHERE {} \
         GROUP BY s.sampled_at \
         ORDER BY s.sampled_at ASC",
        sample_clauses.join(" AND ")
    );

    struct BucketAcc {
        start: i64,
        end: i64,
        start_str: String,
        end_str: String,
        is_expired: bool,
        sample_count: i64,
        active_sessions_sum: i64,
        peak_concurrency: i64,
        peak_bitrate_bps: i64,
    }

    let mut buckets_acc = Vec::new();
    let mut cur = requested_start;
    while cur < effective_end && buckets_acc.len() < MAX_TIMESERIES_BUCKETS {
        let next = (cur + step_secs).min(effective_end);
        let b_start_str = iso_timestamp(Some(cur)).unwrap_or_default();
        let b_end_str = iso_timestamp(Some(next)).unwrap_or_default();
        let is_expired = next <= retention_cutoff;
        buckets_acc.push(BucketAcc {
            start: cur,
            end: next,
            start_str: b_start_str,
            end_str: b_end_str,
            is_expired,
            sample_count: 0,
            active_sessions_sum: 0,
            peak_concurrency: 0,
            peak_bitrate_bps: 0,
        });
        cur = next;
    }

    let mut overall_peak_concurrency = 0i64;
    let mut overall_peak_at = None;
    let mut overall_peak_bitrate = 0i64;
    let mut total_session_ticks = 0i64;
    let mut total_samples_analyzed = 0i64;

    let mut stmt = conn.prepare(&sample_sql)?;
    let mut rows = stmt.query(params_from_iter(&sample_values))?;

    while let Some(row) = rows.next()? {
        let sampled_at: i64 = row.get(0)?;
        let active_sessions: i64 = row.get(1)?;
        let total_bitrate: i64 = row.get(2)?;

        total_samples_analyzed += 1;
        total_session_ticks += active_sessions;
        if active_sessions > overall_peak_concurrency {
            overall_peak_concurrency = active_sessions;
            overall_peak_at = Some(sampled_at);
        }
        if total_bitrate > overall_peak_bitrate {
            overall_peak_bitrate = total_bitrate;
        }

        if sampled_at >= requested_start && sampled_at < effective_end && !buckets_acc.is_empty() {
            let idx = ((sampled_at - requested_start) / step_secs) as usize;
            if idx < buckets_acc.len()
                && sampled_at >= buckets_acc[idx].start
                && sampled_at < buckets_acc[idx].end
            {
                let b = &mut buckets_acc[idx];
                b.sample_count += 1;
                b.active_sessions_sum += active_sessions;
                if active_sessions > b.peak_concurrency {
                    b.peak_concurrency = active_sessions;
                }
                if total_bitrate > b.peak_bitrate_bps {
                    b.peak_bitrate_bps = total_bitrate;
                }
            } else {
                for b in &mut buckets_acc {
                    if sampled_at >= b.start && sampled_at < b.end {
                        b.sample_count += 1;
                        b.active_sessions_sum += active_sessions;
                        if active_sessions > b.peak_concurrency {
                            b.peak_concurrency = active_sessions;
                        }
                        if total_bitrate > b.peak_bitrate_bps {
                            b.peak_bitrate_bps = total_bitrate;
                        }
                        break;
                    }
                }
            }
        }
    }

    let buckets = buckets_acc
        .into_iter()
        .map(|b| {
            if b.is_expired {
                ConcurrencyBucket {
                    bucket_start: b.start_str,
                    bucket_end: b.end_str,
                    peak_concurrency: None,
                    avg_concurrency: None,
                    peak_bitrate_bps: None,
                    sample_count: 0,
                    status: ConcurrencyBucketStatus::RetentionExpired,
                }
            } else if b.sample_count == 0 {
                ConcurrencyBucket {
                    bucket_start: b.start_str,
                    bucket_end: b.end_str,
                    peak_concurrency: None,
                    avg_concurrency: None,
                    peak_bitrate_bps: None,
                    sample_count: 0,
                    status: ConcurrencyBucketStatus::Gap,
                }
            } else {
                let status = if b.peak_concurrency > 0 {
                    ConcurrencyBucketStatus::Available
                } else {
                    ConcurrencyBucketStatus::NoActivity
                };
                let avg = b.active_sessions_sum as f64 / b.sample_count as f64;
                ConcurrencyBucket {
                    bucket_start: b.start_str,
                    bucket_end: b.end_str,
                    peak_concurrency: Some(b.peak_concurrency),
                    avg_concurrency: Some(avg),
                    peak_bitrate_bps: Some(b.peak_bitrate_bps),
                    sample_count: b.sample_count,
                    status,
                }
            }
        })
        .collect();

    let (peak_c, avg_c, peak_b) = if total_samples_analyzed > 0 {
        (
            Some(overall_peak_concurrency),
            Some(total_session_ticks as f64 / total_samples_analyzed as f64),
            Some(overall_peak_bitrate),
        )
    } else {
        (None, None, None)
    };

    let limitations = vec![
        "Concurrency is derived exclusively from active samples in streaming_session_samples (playing = 1); item summaries and legacy unverified records are never counted as concurrent streams.".into(),
        "Detailed session samples are retained for at most 90 days; older periods are classified as retention_expired.".into(),
        "Intervals without session samples are classified as gap/unknown rather than assumed zero activity.".into(),
    ];

    Ok(ConcurrencyReport {
        window: query.window.clone(),
        from: iso_timestamp(start_opt),
        until: iso_timestamp(end_opt),
        timezone: query.timezone.clone(),
        retention_days: RETENTION_DAYS,
        retention_cutoff: iso_timestamp(Some(retention_cutoff)).unwrap_or_default(),
        retention_limited,
        peak_concurrency: peak_c,
        peak_concurrency_at: iso_timestamp(overall_peak_at),
        avg_concurrency: avg_c,
        peak_bitrate_bps: peak_b,
        total_samples_analyzed,
        buckets,
        limitations,
    })
}

pub fn query_patterns_summary(
    conn: &Connection,
    raw: HistoryQuery,
    user: &AuthUser,
    now: i64,
) -> Result<PatternsSummaryReport, HistoryError> {
    let tx = conn.unchecked_transaction()?;
    let (query, watermark, _revision, as_of) = resolve_query_scope(&tx, raw, user, now)?;
    let activity = query_activity_patterns_impl(&tx, &query, watermark, as_of, user)?;
    let concurrency = query_concurrency_patterns_impl(&tx, &query, watermark, as_of, user)?;
    tx.commit()?;
    Ok(PatternsSummaryReport {
        activity,
        concurrency,
    })
}

pub fn query_drilldown(
    conn: &Connection,
    raw: HistoryQuery,
    user: &AuthUser,
    now: i64,
) -> Result<DrilldownReport, HistoryError> {
    let tx = conn.unchecked_transaction()?;
    let (query, watermark, _revision, as_of) = resolve_query_scope(&tx, raw, user, now)?;
    let report = query_drilldown_impl(&tx, &query, watermark, as_of, user)?;
    tx.commit()?;
    Ok(report)
}

fn query_drilldown_impl(
    conn: &Connection,
    query: &HistoryQuery,
    watermark: i64,
    as_of: i64,
    user: &AuthUser,
) -> Result<DrilldownReport, HistoryError> {
    let limit = query.page_size.clamp(1, 200) as i64;
    let (mut clauses, mut values) = scope_filters(query, user, watermark);
    query_filters(query, as_of, &mut clauses, &mut values)?;

    clauses.push("h.provenance IN ('observed_session', 'imported_event')".into());
    clauses.push(format!("({})", inclusion_predicate()));

    let where_clause = clauses.join(" AND ");

    let totals_sql = format!(
        "SELECT COUNT(DISTINCT h.id), \
         COALESCE(SUM(MAX(COALESCE(h.watched_secs, 0), 0)), 0), \
         COALESCE(SUM(CASE WHEN h.byte_accuracy = 'estimated' THEN MAX(COALESCE(h.data_used_bytes, 0), 0) ELSE 0 END), 0), \
         COUNT(DISTINCT (h.provider || char(0) || h.server_id || char(0) || h.user_id)), \
         COUNT(DISTINCT (h.provider || char(0) || h.server_id || char(0) || h.item_id)) \
         FROM streaming_history h CROSS JOIN streaming_tracking_policies p \
         WHERE {}",
        where_clause
    );

    let (cohort_distinct_plays, cohort_watch_time, cohort_bytes, cohort_users, cohort_items): (
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = conn.query_row(&totals_sql, params_from_iter(&values), |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })?;

    let users_sql = format!(
        "SELECT h.provider, h.server_id, h.user_id, \
         COALESCE(NULLIF(trim(h.user_name), ''), 'Unknown') AS u_name, \
         COUNT(DISTINCT h.id) AS play_count, \
         COALESCE(SUM(MAX(COALESCE(h.watched_secs, 0), 0)), 0) AS watch_time, \
         COALESCE(SUM(CASE WHEN h.byte_accuracy = 'estimated' THEN MAX(COALESCE(h.data_used_bytes, 0), 0) ELSE 0 END), 0) AS bytes, \
         COUNT(DISTINCT (h.provider || char(0) || h.server_id || char(0) || h.item_id)) AS distinct_items, \
         MAX(h.event_unix) AS last_played, \
         SUM(CASE WHEN lower(replace(replace(trim(COALESCE(h.play_method,'')), ' ', ''), '_', '')) = 'directplay' THEN 1 ELSE 0 END) AS dp, \
         SUM(CASE WHEN lower(replace(replace(trim(COALESCE(h.play_method,'')), ' ', ''), '_', '')) = 'directstream' THEN 1 ELSE 0 END) AS ds, \
         SUM(CASE WHEN lower(replace(replace(trim(COALESCE(h.play_method,'')), ' ', ''), '_', '')) = 'transcode' THEN 1 ELSE 0 END) AS tc, \
         SUM(CASE WHEN lower(replace(replace(trim(COALESCE(h.play_method,'')), ' ', ''), '_', '')) NOT IN ('directplay','directstream','transcode') THEN 1 ELSE 0 END) AS unk \
         FROM streaming_history h CROSS JOIN streaming_tracking_policies p \
         WHERE {} \
         GROUP BY h.provider, h.server_id, h.user_id \
         ORDER BY play_count DESC, watch_time DESC, h.server_id ASC, h.user_id ASC \
         LIMIT ?",
        where_clause
    );

    let mut user_values = values.clone();
    user_values.push(Value::Integer(limit));
    let mut stmt = conn.prepare(&users_sql)?;
    let user_rows = stmt.query_map(params_from_iter(&user_values), |row| {
        let play_count: i64 = row.get(4)?;
        let pct = if cohort_distinct_plays > 0 {
            (play_count as f64 / cohort_distinct_plays as f64) * 100.0
        } else {
            0.0
        };
        Ok(UserDrilldownItem {
            provider: row.get(0)?,
            server_id: row.get(1)?,
            user_id: row.get(2)?,
            user_name: row.get(3)?,
            play_count,
            watch_time_secs: row.get(5)?,
            estimated_bytes: row.get(6)?,
            distinct_items: row.get(7)?,
            last_played_at: iso_timestamp(row.get(8)?),
            direct_play_count: row.get(9)?,
            direct_stream_count: row.get(10)?,
            transcode_count: row.get(11)?,
            unknown_method_count: row.get(12)?,
            percentage_of_plays: pct,
        })
    })?;
    let users = user_rows.collect::<Result<Vec<_>, _>>()?;

    let client_sql = format!(
        "SELECT \
         COALESCE(NULLIF(trim(h.client_name), ''), 'Unknown') AS c_name, \
         COALESCE(NULLIF(trim(h.device_name), ''), 'Unknown') AS d_name, \
         COUNT(DISTINCT h.id) AS play_count, \
         COALESCE(SUM(MAX(COALESCE(h.watched_secs, 0), 0)), 0) AS watch_time, \
         COALESCE(SUM(CASE WHEN h.byte_accuracy = 'estimated' THEN MAX(COALESCE(h.data_used_bytes, 0), 0) ELSE 0 END), 0) AS bytes, \
         COUNT(DISTINCT (h.provider || char(0) || h.server_id || char(0) || h.user_id)) AS distinct_users, \
         SUM(CASE WHEN lower(replace(replace(trim(COALESCE(h.play_method,'')), ' ', ''), '_', '')) = 'directplay' THEN 1 ELSE 0 END) AS dp, \
         SUM(CASE WHEN lower(replace(replace(trim(COALESCE(h.play_method,'')), ' ', ''), '_', '')) = 'directstream' THEN 1 ELSE 0 END) AS ds, \
         SUM(CASE WHEN lower(replace(replace(trim(COALESCE(h.play_method,'')), ' ', ''), '_', '')) = 'transcode' THEN 1 ELSE 0 END) AS tc, \
         SUM(CASE WHEN lower(replace(replace(trim(COALESCE(h.play_method,'')), ' ', ''), '_', '')) NOT IN ('directplay','directstream','transcode') THEN 1 ELSE 0 END) AS unk \
         FROM streaming_history h CROSS JOIN streaming_tracking_policies p \
         WHERE {} \
         GROUP BY c_name, d_name \
         ORDER BY play_count DESC, watch_time DESC \
         LIMIT ?",
        where_clause
    );

    let mut client_values = values.clone();
    client_values.push(Value::Integer(limit));
    let mut stmt = conn.prepare(&client_sql)?;
    let client_rows = stmt.query_map(params_from_iter(&client_values), |row| {
        let play_count: i64 = row.get(2)?;
        let pct = if cohort_distinct_plays > 0 {
            (play_count as f64 / cohort_distinct_plays as f64) * 100.0
        } else {
            0.0
        };
        Ok(ClientDrilldownItem {
            client_name: row.get(0)?,
            device_name: row.get(1)?,
            play_count,
            watch_time_secs: row.get(3)?,
            estimated_bytes: row.get(4)?,
            distinct_users: row.get(5)?,
            direct_play_count: row.get(6)?,
            direct_stream_count: row.get(7)?,
            transcode_count: row.get(8)?,
            unknown_method_count: row.get(9)?,
            percentage_of_plays: pct,
        })
    })?;
    let clients = client_rows.collect::<Result<Vec<_>, _>>()?;

    let item_sql = format!(
        "SELECT h.provider, h.server_id, h.item_id, \
         COALESCE(NULLIF(trim(h.item_name), ''), 'Unknown') AS i_name, \
         NULLIF(trim(h.item_type), '') AS i_type, \
         NULLIF(trim(h.series_name), '') AS s_name, \
         COUNT(DISTINCT h.id) AS play_count, \
         COALESCE(SUM(MAX(COALESCE(h.watched_secs, 0), 0)), 0) AS watch_time, \
         COALESCE(SUM(CASE WHEN h.byte_accuracy = 'estimated' THEN MAX(COALESCE(h.data_used_bytes, 0), 0) ELSE 0 END), 0) AS bytes, \
         COUNT(DISTINCT (h.provider || char(0) || h.server_id || char(0) || h.user_id)) AS distinct_viewers, \
         MAX(h.event_unix) AS last_played \
         FROM streaming_history h CROSS JOIN streaming_tracking_policies p \
         WHERE {} \
         GROUP BY h.provider, h.server_id, h.item_id \
         ORDER BY play_count DESC, watch_time DESC, h.server_id ASC, h.item_id ASC \
         LIMIT ?",
        where_clause
    );

    let mut item_values = values.clone();
    item_values.push(Value::Integer(limit));
    let mut stmt = conn.prepare(&item_sql)?;
    let item_rows = stmt.query_map(params_from_iter(&item_values), |row| {
        let play_count: i64 = row.get(6)?;
        let pct = if cohort_distinct_plays > 0 {
            (play_count as f64 / cohort_distinct_plays as f64) * 100.0
        } else {
            0.0
        };
        Ok(ItemDrilldownItem {
            provider: row.get(0)?,
            server_id: row.get(1)?,
            item_id: row.get(2)?,
            item_name: row.get(3)?,
            item_type: row.get(4)?,
            series_name: row.get(5)?,
            play_count,
            watch_time_secs: row.get(7)?,
            estimated_bytes: row.get(8)?,
            distinct_viewers: row.get(9)?,
            last_played_at: iso_timestamp(row.get(10)?),
            percentage_of_plays: pct,
        })
    })?;
    let items = item_rows.collect::<Result<Vec<_>, _>>()?;

    let lib_sql = format!(
        "SELECT h.provider, h.server_id, l.value AS lib_id, \
         COALESCE(NULLIF(trim(l.name), ''), l.value) AS lib_name, \
         COUNT(DISTINCT h.id) AS play_count, \
         COALESCE(SUM(MAX(COALESCE(h.watched_secs, 0), 0)), 0) AS watch_time, \
         COALESCE(SUM(CASE WHEN h.byte_accuracy = 'estimated' THEN MAX(COALESCE(h.data_used_bytes, 0), 0) ELSE 0 END), 0) AS bytes, \
         COUNT(DISTINCT (h.provider || char(0) || h.server_id || char(0) || h.user_id)) AS distinct_viewers, \
         COUNT(DISTINCT (h.provider || char(0) || h.server_id || char(0) || h.item_id)) AS distinct_items \
         FROM streaming_history_labels l \
         JOIN streaming_history h ON l.history_id = h.id \
         CROSS JOIN streaming_tracking_policies p \
         WHERE l.kind = 'library' AND {} \
         GROUP BY h.provider, h.server_id, l.value, lib_name \
         ORDER BY play_count DESC, watch_time DESC \
         LIMIT ?",
        where_clause
    );

    let mut lib_values = values.clone();
    lib_values.push(Value::Integer(limit));
    let mut stmt = conn.prepare(&lib_sql)?;
    let lib_rows = stmt.query_map(params_from_iter(&lib_values), |row| {
        let play_count: i64 = row.get(4)?;
        let pct = if cohort_distinct_plays > 0 {
            (play_count as f64 / cohort_distinct_plays as f64) * 100.0
        } else {
            0.0
        };
        Ok(LibraryDrilldownItem {
            provider: row.get(0)?,
            server_id: row.get(1)?,
            library_id: row.get(2)?,
            library_name: row.get(3)?,
            play_count,
            watch_time_secs: row.get(5)?,
            estimated_bytes: row.get(6)?,
            distinct_viewers: row.get(7)?,
            distinct_items: row.get(8)?,
            percentage_of_plays: pct,
        })
    })?;
    let libraries = lib_rows.collect::<Result<Vec<_>, _>>()?;

    let unlabeled_libs_sql = format!(
        "SELECT COUNT(DISTINCT h.id) \
         FROM streaming_history h CROSS JOIN streaming_tracking_policies p \
         WHERE {} AND NOT EXISTS (\
             SELECT 1 FROM streaming_history_labels l WHERE l.history_id = h.id AND l.kind = 'library'\
         )",
        where_clause
    );
    let unlabeled_lib_plays: i64 =
        conn.query_row(&unlabeled_libs_sql, params_from_iter(&values), |row| {
            row.get(0)
        })?;

    let sum_lib_plays_sql = format!(
        "SELECT COUNT(*) \
         FROM streaming_history_labels l \
         JOIN streaming_history h ON l.history_id = h.id \
         CROSS JOIN streaming_tracking_policies p \
         WHERE l.kind = 'library' AND {}",
        where_clause
    );
    let sum_lib_plays: i64 =
        conn.query_row(&sum_lib_plays_sql, params_from_iter(&values), |row| {
            row.get(0)
        })?;

    let library_metrics = LabelMetrics {
        cohort_distinct_plays,
        sum_of_label_plays: sum_lib_plays,
        is_overlapping: sum_lib_plays > cohort_distinct_plays,
        unlabeled_plays: unlabeled_lib_plays,
    };

    let genre_sql = format!(
        "SELECT \
         COALESCE(NULLIF(trim(l.name), ''), l.value) AS genre_name, \
         COUNT(DISTINCT h.id) AS play_count, \
         COALESCE(SUM(MAX(COALESCE(h.watched_secs, 0), 0)), 0) AS watch_time, \
         COALESCE(SUM(CASE WHEN h.byte_accuracy = 'estimated' THEN MAX(COALESCE(h.data_used_bytes, 0), 0) ELSE 0 END), 0) AS bytes, \
         COUNT(DISTINCT (h.provider || char(0) || h.server_id || char(0) || h.user_id)) AS distinct_viewers, \
         COUNT(DISTINCT (h.provider || char(0) || h.server_id || char(0) || h.item_id)) AS distinct_items \
         FROM streaming_history_labels l \
         JOIN streaming_history h ON l.history_id = h.id \
         CROSS JOIN streaming_tracking_policies p \
         WHERE l.kind = 'genre' AND {} \
         GROUP BY genre_name \
         ORDER BY play_count DESC, watch_time DESC \
         LIMIT ?",
        where_clause
    );

    let mut genre_values = values.clone();
    genre_values.push(Value::Integer(limit));
    let mut stmt = conn.prepare(&genre_sql)?;
    let genre_rows = stmt.query_map(params_from_iter(&genre_values), |row| {
        let play_count: i64 = row.get(1)?;
        let pct = if cohort_distinct_plays > 0 {
            (play_count as f64 / cohort_distinct_plays as f64) * 100.0
        } else {
            0.0
        };
        Ok(GenreDrilldownItem {
            genre: row.get(0)?,
            play_count,
            watch_time_secs: row.get(2)?,
            estimated_bytes: row.get(3)?,
            distinct_viewers: row.get(4)?,
            distinct_items: row.get(5)?,
            percentage_of_plays: pct,
        })
    })?;
    let genres = genre_rows.collect::<Result<Vec<_>, _>>()?;

    let unlabeled_genre_sql = format!(
        "SELECT COUNT(DISTINCT h.id) \
         FROM streaming_history h CROSS JOIN streaming_tracking_policies p \
         WHERE {} AND NOT EXISTS (\
             SELECT 1 FROM streaming_history_labels l WHERE l.history_id = h.id AND l.kind = 'genre'\
         )",
        where_clause
    );
    let unlabeled_genre_plays: i64 =
        conn.query_row(&unlabeled_genre_sql, params_from_iter(&values), |row| {
            row.get(0)
        })?;

    let sum_genre_plays_sql = format!(
        "SELECT COUNT(*) \
         FROM streaming_history_labels l \
         JOIN streaming_history h ON l.history_id = h.id \
         CROSS JOIN streaming_tracking_policies p \
         WHERE l.kind = 'genre' AND {}",
        where_clause
    );
    let sum_genre_plays: i64 =
        conn.query_row(&sum_genre_plays_sql, params_from_iter(&values), |row| {
            row.get(0)
        })?;

    let genre_metrics = LabelMetrics {
        cohort_distinct_plays,
        sum_of_label_plays: sum_genre_plays,
        is_overlapping: sum_genre_plays > cohort_distinct_plays,
        unlabeled_plays: unlabeled_genre_plays,
    };

    Ok(DrilldownReport {
        cohort_distinct_plays,
        cohort_total_watch_time_secs: cohort_watch_time,
        cohort_total_estimated_bytes: cohort_bytes,
        cohort_distinct_users: cohort_users,
        cohort_distinct_items: cohort_items,
        users,
        clients,
        items,
        libraries,
        library_metrics,
        genres,
        genre_metrics,
    })
}

pub async fn activity_handler(
    Query(query): Query<HistoryQuery>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let now = Utc::now().timestamp();
    let result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| HistoryError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "history_unavailable",
            message: "History database is unavailable",
        })?;
        query_activity_patterns(&conn, query, &user, now)
    })
    .await;

    match result {
        Ok(Ok(report)) => ([(header::CACHE_CONTROL, "no-store")], Json(report)).into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "patterns_unavailable",
            "Activity patterns query failed",
        ),
    }
}

pub async fn concurrency_handler(
    Query(query): Query<HistoryQuery>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let now = Utc::now().timestamp();
    let result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| HistoryError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "history_unavailable",
            message: "History database is unavailable",
        })?;
        query_concurrency_patterns(&conn, query, &user, now)
    })
    .await;

    match result {
        Ok(Ok(report)) => ([(header::CACHE_CONTROL, "no-store")], Json(report)).into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "patterns_unavailable",
            "Concurrency patterns query failed",
        ),
    }
}

pub async fn patterns_handler(
    Query(query): Query<HistoryQuery>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let now = Utc::now().timestamp();
    let result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| HistoryError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "history_unavailable",
            message: "History database is unavailable",
        })?;
        query_patterns_summary(&conn, query, &user, now)
    })
    .await;

    match result {
        Ok(Ok(report)) => ([(header::CACHE_CONTROL, "no-store")], Json(report)).into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "patterns_unavailable",
            "Patterns summary query failed",
        ),
    }
}

pub async fn drilldown_handler(
    Query(query): Query<HistoryQuery>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let now = Utc::now().timestamp();
    let result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| HistoryError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "history_unavailable",
            message: "History database is unavailable",
        })?;
        query_drilldown(&conn, query, &user, now)
    })
    .await;

    match result {
        Ok(Ok(report)) => ([(header::CACHE_CONTROL, "no-store")], Json(report)).into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "drilldown_unavailable",
            "Drilldown query failed",
        ),
    }
}

pub async fn drilldown_users_handler(
    Query(query): Query<HistoryQuery>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let now = Utc::now().timestamp();
    let result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| HistoryError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "history_unavailable",
            message: "History database is unavailable",
        })?;
        query_drilldown(&conn, query, &user, now).map(|r| r.users)
    })
    .await;

    match result {
        Ok(Ok(users)) => ([(header::CACHE_CONTROL, "no-store")], Json(users)).into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "drilldown_unavailable",
            "User drilldown query failed",
        ),
    }
}

pub async fn drilldown_clients_handler(
    Query(query): Query<HistoryQuery>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let now = Utc::now().timestamp();
    let result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| HistoryError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "history_unavailable",
            message: "History database is unavailable",
        })?;
        query_drilldown(&conn, query, &user, now).map(|r| r.clients)
    })
    .await;

    match result {
        Ok(Ok(clients)) => ([(header::CACHE_CONTROL, "no-store")], Json(clients)).into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "drilldown_unavailable",
            "Client drilldown query failed",
        ),
    }
}

pub async fn drilldown_items_handler(
    Query(query): Query<HistoryQuery>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let now = Utc::now().timestamp();
    let result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| HistoryError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "history_unavailable",
            message: "History database is unavailable",
        })?;
        query_drilldown(&conn, query, &user, now).map(|r| r.items)
    })
    .await;

    match result {
        Ok(Ok(items)) => ([(header::CACHE_CONTROL, "no-store")], Json(items)).into_response(),
        Ok(Err(error)) => error.into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "drilldown_unavailable",
            "Item drilldown query failed",
        ),
    }
}

pub async fn drilldown_libraries_handler(
    Query(query): Query<HistoryQuery>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let now = Utc::now().timestamp();
    let result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| HistoryError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "history_unavailable",
            message: "History database is unavailable",
        })?;
        query_drilldown(&conn, query, &user, now).map(|r| (r.libraries, r.library_metrics))
    })
    .await;

    match result {
        Ok(Ok((libraries, metrics))) => {
            let body = serde_json::json!({
                "libraries": libraries,
                "metrics": metrics
            });
            ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
        }
        Ok(Err(error)) => error.into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "drilldown_unavailable",
            "Library drilldown query failed",
        ),
    }
}

pub async fn drilldown_genres_handler(
    Query(query): Query<HistoryQuery>,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let now = Utc::now().timestamp();
    let result = tokio::task::spawn_blocking(move || {
        let conn = af_db::get_conn().map_err(|_| HistoryError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "history_unavailable",
            message: "History database is unavailable",
        })?;
        query_drilldown(&conn, query, &user, now).map(|r| (r.genres, r.genre_metrics))
    })
    .await;

    match result {
        Ok(Ok((genres, metrics))) => {
            let body = serde_json::json!({
                "genres": genres,
                "metrics": metrics
            });
            ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
        }
        Ok(Err(error)) => error.into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "drilldown_unavailable",
            "Genre drilldown query failed",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming_history::query_history;
    use rusqlite::Connection;

    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL DEFAULT 'user'
            );
            CREATE TABLE streaming_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_key TEXT NOT NULL UNIQUE,
                provider TEXT NOT NULL,
                server_id TEXT NOT NULL DEFAULT '',
                source_event_id TEXT,
                provenance TEXT NOT NULL DEFAULT 'legacy_unverified'
                    CHECK(provenance IN ('legacy_unverified', 'observed_session', 'imported_event', 'item_summary')),
                timestamp_certainty TEXT NOT NULL DEFAULT 'legacy_unverified'
                    CHECK(timestamp_certainty IN ('legacy_unverified', 'observed', 'source_event', 'last_played', 'unrecorded')),
                byte_accuracy TEXT NOT NULL DEFAULT 'legacy_unverified'
                    CHECK(byte_accuracy IN ('legacy_unverified', 'estimated', 'unrecorded')),
                policy_status TEXT NOT NULL DEFAULT 'included'
                    CHECK(policy_status IN ('included', 'excluded', 'duplicate', 'ambiguous')),
                user_id TEXT NOT NULL DEFAULT '',
                user_name TEXT NOT NULL DEFAULT '',
                client_name TEXT,
                device_name TEXT,
                device_id TEXT,
                ip_address TEXT,
                item_id TEXT NOT NULL DEFAULT '',
                item_name TEXT NOT NULL DEFAULT '',
                item_type TEXT,
                series_name TEXT,
                play_method TEXT,
                watched_secs INTEGER,
                duration_secs INTEGER,
                data_used_bytes INTEGER,
                completion_pct REAL,
                started_at TEXT,
                last_seen_at TEXT,
                ended_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 0,
                event_unix INTEGER GENERATED ALWAYS AS (CAST(strftime('%s', NULLIF(started_at, '')) AS INTEGER)) VIRTUAL,
                event_missing INTEGER GENERATED ALWAYS AS (CASE WHEN event_unix IS NULL THEN 1 ELSE 0 END) VIRTUAL
            );
            CREATE TABLE streaming_history_revision (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                revision INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO streaming_history_revision(id, revision) VALUES(1, 0);
            CREATE TABLE streaming_history_labels (\
                history_id INTEGER NOT NULL REFERENCES streaming_history(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK(kind IN ('library', 'genre')),
                value TEXT NOT NULL,
                name TEXT NOT NULL,
                PRIMARY KEY(history_id, kind, value)
            );
            CREATE TABLE streaming_user_links (
                af_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                provider TEXT NOT NULL,
                server_id TEXT NOT NULL DEFAULT '',
                provider_user_id TEXT NOT NULL,
                PRIMARY KEY(af_user_id, provider, server_id, provider_user_id)
            );
            CREATE TABLE streaming_tracking_policies (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                minimum_watch_secs INTEGER NOT NULL DEFAULT 0 CHECK(minimum_watch_secs BETWEEN 0 AND 86400),
                excluded_users TEXT NOT NULL DEFAULT '[]',
                excluded_libraries TEXT NOT NULL DEFAULT '[]',
                reconnect_window_secs INTEGER NOT NULL DEFAULT 0 CHECK(reconnect_window_secs BETWEEN 0 AND 300),
                revision INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO streaming_tracking_policies(id) VALUES(1);
            CREATE TABLE streaming_session_samples (
                history_id INTEGER NOT NULL REFERENCES streaming_history(id) ON DELETE CASCADE,
                sampled_at INTEGER NOT NULL,
                observed_secs INTEGER NOT NULL CHECK(observed_secs BETWEEN 0 AND 60),
                playing INTEGER NOT NULL CHECK(playing IN (0, 1)),
                bitrate_bps INTEGER NOT NULL CHECK(bitrate_bps >= 0),
                PRIMARY KEY(history_id, sampled_at)
            );",
        )
        .expect("tables created");
        conn
    }

    fn admin_user() -> AuthUser {
        AuthUser {
            user_id: 1,
            username: "admin".into(),
            role: "admin".into(),
            jti: "jti-admin-1".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }
    }

    fn regular_user(id: i64) -> AuthUser {
        AuthUser {
            user_id: id,
            username: format!("user{}", id),
            role: "user".into(),
            jti: format!("jti-user-{}", id),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }
    }

    #[test]
    fn test_dst_transitions_and_timezone_aware_activity() {
        let conn = setup_test_db();
        let admin = admin_user();

        conn.execute(
            "INSERT INTO streaming_history (
                session_key, provider, server_id, provenance, timestamp_certainty, byte_accuracy,
                policy_status, user_id, user_name, item_id, item_name, started_at, watched_secs
            ) VALUES
            ('s1', 'jellyfin', 'srv1', 'observed_session', 'observed', 'estimated', 'included', 'u1', 'Alice', 'm1', 'Movie 1', '2026-03-08T06:30:00Z', 1800),
            ('s2', 'jellyfin', 'srv1', 'observed_session', 'observed', 'estimated', 'included', 'u1', 'Alice', 'm2', 'Movie 2', '2026-03-08T07:30:00Z', 1800)",
            [],
        )
        .unwrap();

        let query = HistoryQuery {
            window: "custom".into(),
            from: "2026-03-08T00:00:00Z".into(),
            until: "2026-03-09T00:00:00Z".into(),
            timezone: "America/New_York".into(),
            ..HistoryQuery::default()
        };

        let as_of = 1773060000;
        let report = query_activity_patterns(&conn, query, &admin, as_of).expect("activity report");

        assert_eq!(report.total_confirmed_plays, 2);
        assert_eq!(report.hourly_breakdown[1].play_count, 1);
        assert_eq!(report.hourly_breakdown[2].play_count, 0);
        assert_eq!(report.hourly_breakdown[3].play_count, 1);
        assert_eq!(report.weekday_breakdown[6].play_count, 2);
        assert!(!report.dst_transitions_observed.is_empty());
    }

    #[test]
    fn test_unknown_and_gaps_in_concurrency_and_retention() {
        let conn = setup_test_db();
        let admin = admin_user();
        let now = 1793500000;
        let retention_cutoff = now - (RETENTION_DAYS as i64 * 86400);

        let t_recent = now - 2 * 86400;
        let t_old = retention_cutoff - 5 * 86400;

        conn.execute(
            "INSERT INTO streaming_history (
                id, session_key, provider, server_id, provenance, timestamp_certainty, byte_accuracy,
                policy_status, user_id, user_name, item_id, item_name, started_at
            ) VALUES
            (1, 's1', 'jellyfin', 'srv1', 'observed_session', 'observed', 'estimated', 'included', 'u1', 'Alice', 'm1', 'Movie 1', '2026-10-30T10:00:00Z'),
            (2, 's2', 'jellyfin', 'srv1', 'observed_session', 'observed', 'estimated', 'included', 'u2', 'Bob', 'm2', 'Movie 2', '2026-07-01T10:00:00Z'),
            (3, 's3', 'jellyfin', 'srv1', 'item_summary', 'last_played', 'unrecorded', 'included', 'u3', 'Charlie', 'm3', 'Movie 3', '2026-10-30T10:00:00Z')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO streaming_session_samples (history_id, sampled_at, observed_secs, playing, bitrate_bps)
             VALUES (1, ?1, 5, 1, 4000000)",
            [t_recent],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO streaming_session_samples (history_id, sampled_at, observed_secs, playing, bitrate_bps)
             VALUES (2, ?1, 5, 1, 3000000)",
            [t_old],
        )
        .unwrap();

        let query = HistoryQuery {
            window: "custom".into(),
            from: DateTime::from_timestamp(retention_cutoff - 10 * 86400, 0)
                .unwrap()
                .to_rfc3339(),
            until: DateTime::from_timestamp(now, 0).unwrap().to_rfc3339(),
            ..HistoryQuery::default()
        };

        let report =
            query_concurrency_patterns(&conn, query, &admin, now).expect("concurrency report");
        assert!(report.retention_limited);
        assert_eq!(report.peak_concurrency, Some(1));
        assert_eq!(report.peak_bitrate_bps, Some(4000000));

        let expired_buckets: Vec<_> = report
            .buckets
            .iter()
            .filter(|b| b.status == ConcurrencyBucketStatus::RetentionExpired)
            .collect();
        assert!(!expired_buckets.is_empty());
        assert!(expired_buckets.iter().all(|b| b.peak_concurrency.is_none()));

        let gap_buckets: Vec<_> = report
            .buckets
            .iter()
            .filter(|b| b.status == ConcurrencyBucketStatus::Gap)
            .collect();
        assert!(!gap_buckets.is_empty());
        assert!(gap_buckets.iter().all(|b| b.peak_concurrency.is_none()));
    }

    #[test]
    fn test_overlapping_labels_and_honest_distinct_denominators() {
        let conn = setup_test_db();
        let admin = admin_user();

        conn.execute(
            "INSERT INTO streaming_history (
                id, session_key, provider, server_id, provenance, policy_status, user_id, user_name, item_id, item_name, started_at, watched_secs
            ) VALUES
            (10, 's10', 'jellyfin', 'srv1', 'observed_session', 'included', 'u1', 'Alice', 'm1', 'Matrix', '2026-10-31T10:00:00Z', 7200),
            (20, 's20', 'jellyfin', 'srv1', 'observed_session', 'included', 'u2', 'Bob', 'm2', 'Die Hard', '2026-10-31T12:00:00Z', 6000),
            (30, 's30', 'jellyfin', 'srv1', 'observed_session', 'included', 'u3', 'Charlie', 'm3', 'Indie', '2026-10-31T14:00:00Z', 3600)",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES (10, 'genre', 'g_action', 'Action')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES (10, 'genre', 'g_scifi', 'Sci-Fi')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES (10, 'library', 'lib_mov', 'Movies')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES (10, 'library', 'lib_4k', '4K UHD')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES (20, 'genre', 'g_action', 'Action')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES (20, 'library', 'lib_mov', 'Movies')",
            [],
        )
        .unwrap();

        let query = HistoryQuery::default();
        let report = query_drilldown(&conn, query, &admin, 1793500000).expect("drilldown report");

        assert_eq!(report.cohort_distinct_plays, 3);

        let action = report
            .genres
            .iter()
            .find(|g| g.genre == "Action")
            .expect("Action genre");
        assert_eq!(action.play_count, 2);
        assert!((action.percentage_of_plays - 66.666).abs() < 0.1);

        let scifi = report
            .genres
            .iter()
            .find(|g| g.genre == "Sci-Fi")
            .expect("Sci-Fi genre");
        assert_eq!(scifi.play_count, 1);
        assert!((scifi.percentage_of_plays - 33.333).abs() < 0.1);

        assert_eq!(report.genre_metrics.unlabeled_plays, 1);
        assert_eq!(report.genre_metrics.sum_of_label_plays, 3);
        assert_eq!(report.genre_metrics.cohort_distinct_plays, 3);

        let movies = report
            .libraries
            .iter()
            .find(|l| l.library_id == "lib_mov")
            .expect("Movies library");
        assert_eq!(movies.play_count, 2);
        assert_eq!(movies.provider, "jellyfin");
        assert_eq!(movies.server_id, "srv1");
        let uhd = report
            .libraries
            .iter()
            .find(|l| l.library_id == "lib_4k")
            .expect("4K library");
        assert_eq!(uhd.play_count, 1);
        assert_eq!(uhd.provider, "jellyfin");
        assert_eq!(uhd.server_id, "srv1");

        assert_eq!(report.library_metrics.cohort_distinct_plays, 3);
        assert_eq!(report.library_metrics.sum_of_label_plays, 3);
        assert_eq!(report.library_metrics.unlabeled_plays, 1);
    }

    #[test]
    fn test_duplicate_names_preserve_stable_identities() {
        let conn = setup_test_db();
        let admin = admin_user();

        conn.execute(
            "INSERT INTO streaming_history (
                session_key, provider, server_id, provenance, policy_status, user_id, user_name, item_id, item_name, started_at
            ) VALUES
            ('s1', 'jellyfin', 'server_a', 'observed_session', 'included', 'user_101', 'Alex', 'item_1984', 'Dune', '2026-10-31T10:00:00Z'),
            ('s2', 'jellyfin', 'server_b', 'observed_session', 'included', 'user_202', 'Alex', 'item_2021', 'Dune', '2026-10-31T11:00:00Z')",
            [],
        )
        .unwrap();

        let query = HistoryQuery::default();
        let report = query_drilldown(&conn, query, &admin, 1793500000).expect("drilldown report");

        assert_eq!(report.users.len(), 2);
        let u1 = report
            .users
            .iter()
            .find(|u| u.user_id == "user_101" && u.server_id == "server_a");
        let u2 = report
            .users
            .iter()
            .find(|u| u.user_id == "user_202" && u.server_id == "server_b");
        assert!(u1.is_some());
        assert!(u2.is_some());

        assert_eq!(report.items.len(), 2);
        let i1 = report
            .items
            .iter()
            .find(|i| i.item_id == "item_1984" && i.server_id == "server_a");
        let i2 = report
            .items
            .iter()
            .find(|i| i.item_id == "item_2021" && i.server_id == "server_b");
        assert!(i1.is_some());
        assert!(i2.is_some());
    }

    #[test]
    fn test_unauthorized_scope_and_privacy_redaction() {
        let conn = setup_test_db();
        let unlinked_user = regular_user(42);
        let linked_user = regular_user(99);

        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (42, 'unlinked', 'user'), (99, 'linked', 'user')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO streaming_history (
                session_key, provider, server_id, provenance, policy_status, user_id, user_name, item_id, item_name, started_at
            ) VALUES
            ('s1', 'jellyfin', 'srv1', 'observed_session', 'included', 'user_alice', 'Alice', 'm1', 'Movie 1', '2026-10-31T10:00:00Z'),
            ('s2', 'jellyfin', 'srv1', 'observed_session', 'included', 'user_bob', 'Bob', 'm2', 'Movie 2', '2026-10-31T11:00:00Z')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO streaming_user_links (af_user_id, provider, server_id, provider_user_id)
             VALUES (99, 'jellyfin', 'srv1', 'user_alice')",
            [],
        )
        .unwrap();

        let query = HistoryQuery::default();

        let drill_unlinked =
            query_drilldown(&conn, query.clone(), &unlinked_user, 1793500000).expect("drilldown query");
        assert_eq!(drill_unlinked.cohort_distinct_plays, 0);
        assert!(drill_unlinked.users.is_empty());

        let drill_linked =
            query_drilldown(&conn, query.clone(), &linked_user, 1793500000).expect("drilldown query");
        assert_eq!(drill_linked.cohort_distinct_plays, 1);
        assert_eq!(drill_linked.users.len(), 1);
        assert_eq!(drill_linked.users[0].user_id, "user_alice");

        let excluded_query = HistoryQuery {
            include_excluded: true,
            ..HistoryQuery::default()
        };
        let err = query_drilldown(&conn, excluded_query, &linked_user, 1793500000).unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.code, "admin_required");
    }

    #[test]
    fn test_dst_transitions_across_full_year_detects_both_changes() {
        let conn = setup_test_db();
        let admin = admin_user();

        let query = HistoryQuery {
            window: "custom".into(),
            from: "2026-01-01T00:00:00Z".into(),
            until: "2026-12-31T00:00:00Z".into(),
            timezone: "America/New_York".into(),
            ..HistoryQuery::default()
        };

        let as_of = 1798761600;
        let report = query_activity_patterns(&conn, query, &admin, as_of).expect("activity report");

        assert_eq!(report.dst_transitions_observed.len(), 2);
        assert!(report.dst_transitions_observed[0].contains("spring forward"));
        assert!(report.dst_transitions_observed[1].contains("fall back"));
    }

    #[test]
    fn test_concurrency_paused_samples_and_nullable_unknowns() {
        let conn = setup_test_db();
        let admin = admin_user();
        let now = 1793500000;
        let t_sample = now - 86400;

        conn.execute(
            "INSERT INTO streaming_history (
                id, session_key, provider, server_id, provenance, policy_status, user_id, user_name, item_id, item_name, started_at
            ) VALUES
            (1, 's1', 'jellyfin', 'srv1', 'observed_session', 'included', 'u1', 'Alice', 'm1', 'Movie 1', '2026-10-31T10:00:00Z')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO streaming_session_samples (history_id, sampled_at, observed_secs, playing, bitrate_bps)
             VALUES (1, ?1, 5, 0, 0)",
            [t_sample],
        )
        .unwrap();

        let query = HistoryQuery {
            window: "7d".into(),
            ..HistoryQuery::default()
        };

        let report =
            query_concurrency_patterns(&conn, query, &admin, now).expect("concurrency report");
        assert_eq!(report.total_samples_analyzed, 1);
        assert_eq!(report.peak_concurrency, Some(0));
        assert_eq!(report.avg_concurrency, Some(0.0));

        let active_bucket = report
            .buckets
            .iter()
            .find(|b| b.sample_count > 0)
            .expect("bucket with paused sample");
        assert_eq!(active_bucket.status, ConcurrencyBucketStatus::NoActivity);
        assert_eq!(active_bucket.peak_concurrency, Some(0));
        assert_eq!(active_bucket.avg_concurrency, Some(0.0));

        let gap_bucket = report
            .buckets
            .iter()
            .find(|b| b.sample_count == 0)
            .expect("bucket without samples");
        assert_eq!(gap_bucket.status, ConcurrencyBucketStatus::Gap);
        assert!(gap_bucket.peak_concurrency.is_none());
        assert!(gap_bucket.avg_concurrency.is_none());
    }

    #[test]
    fn test_cross_server_distinct_identities_and_keys() {
        let conn = setup_test_db();
        let admin = admin_user();

        conn.execute(
            "INSERT INTO streaming_history (
                id, session_key, provider, server_id, provenance, policy_status, user_id, user_name, item_id, item_name, started_at
            ) VALUES
            (1, 's1', 'jellyfin', 'server_a', 'observed_session', 'included', 'u1', 'Alice', 'item_1', 'Matrix', '2026-10-31T10:00:00Z'),
            (2, 's2', 'jellyfin', 'server_b', 'observed_session', 'included', 'u1', 'Alice', 'item_1', 'Matrix', '2026-10-31T11:00:00Z')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES
             (1, 'library', 'lib_same', 'Movies'),
             (2, 'library', 'lib_same', 'Movies')",
            [],
        )
        .unwrap();

        let query = HistoryQuery::default();
        let report = query_drilldown(&conn, query, &admin, 1793500000).expect("drilldown report");

        assert_eq!(report.cohort_distinct_users, 2);
        assert_eq!(report.cohort_distinct_items, 2);

        assert_eq!(report.items.len(), 2);
        let srv_a_item = report
            .items
            .iter()
            .find(|i| i.item_id == "item_1" && i.server_id == "server_a");
        let srv_b_item = report
            .items
            .iter()
            .find(|i| i.item_id == "item_1" && i.server_id == "server_b");
        assert!(srv_a_item.is_some());
        assert!(srv_b_item.is_some());

        assert_eq!(report.libraries.len(), 2);
        let srv_a_lib = report
            .libraries
            .iter()
            .find(|l| l.library_id == "lib_same" && l.server_id == "server_a");
        let srv_b_lib = report
            .libraries
            .iter()
            .find(|l| l.library_id == "lib_same" && l.server_id == "server_b");
        assert!(srv_a_lib.is_some());
        assert!(srv_b_lib.is_some());
    }

    #[test]
    fn test_accurate_label_metrics_full_denominator_beyond_page_size() {
        let conn = setup_test_db();
        let admin = admin_user();

        conn.execute(
            "INSERT INTO streaming_history (
                id, session_key, provider, server_id, provenance, policy_status, user_id, user_name, item_id, item_name, started_at
            ) VALUES
            (1, 's1', 'jellyfin', 'srv1', 'observed_session', 'included', 'u1', 'Alice', 'm1', 'Movie 1', '2026-10-31T10:00:00Z'),
            (2, 's2', 'jellyfin', 'srv1', 'observed_session', 'included', 'u1', 'Alice', 'm2', 'Movie 2', '2026-10-31T11:00:00Z'),
            (3, 's3', 'jellyfin', 'srv1', 'observed_session', 'included', 'u1', 'Alice', 'm3', 'Movie 3', '2026-10-31T12:00:00Z'),
            (4, 's4', 'jellyfin', 'srv1', 'observed_session', 'included', 'u1', 'Alice', 'm4', 'Movie 4', '2026-10-31T13:00:00Z')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES
             (1, 'library', 'lib_1', 'Library 1'),
             (2, 'library', 'lib_2', 'Library 2'),
             (3, 'library', 'lib_3', 'Library 3'),
             (4, 'library', 'lib_4', 'Library 4')",
            [],
        )
        .unwrap();

        let query = HistoryQuery {
            page_size: 2,
            ..HistoryQuery::default()
        };

        let report = query_drilldown(&conn, query, &admin, 1793500000).expect("drilldown report");

        assert_eq!(report.libraries.len(), 2);
        assert_eq!(report.library_metrics.cohort_distinct_plays, 4);
        assert_eq!(report.library_metrics.sum_of_label_plays, 4);
    }

    #[test]
    fn test_snapshot_and_cursor_validation_with_transactions() {
        let conn = setup_test_db();
        let admin = admin_user();
        let now = 1793500000;

        let cursor_query = HistoryQuery {
            cursor: Some("unsupported_cursor".into()),
            ..HistoryQuery::default()
        };
        let err = query_activity_patterns(&conn, cursor_query, &admin, now).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "invalid_history_query");

        let base_query = HistoryQuery::default();
        let page = query_history(&conn, base_query.clone(), &admin, now).expect("history page");
        let valid_snapshot = page.scope.snapshot_token;

        let snapshot_query = HistoryQuery {
            snapshot: Some(valid_snapshot.clone()),
            ..base_query.clone()
        };
        let act_report = query_activity_patterns(&conn, snapshot_query, &admin, now)
            .expect("activity with snapshot");
        assert_eq!(act_report.total_confirmed_plays, 0);

        conn.execute(
            "UPDATE streaming_history_revision SET revision = revision + 1 WHERE id = 1",
            [],
        )
        .unwrap();

        let stale_query = HistoryQuery {
            snapshot: Some(valid_snapshot),
            ..base_query
        };
        let stale_err = query_activity_patterns(&conn, stale_query, &admin, now).unwrap_err();
        assert_eq!(stale_err.status, StatusCode::CONFLICT);
        assert_eq!(stale_err.code, "history_snapshot_changed");
    }
}
