use super::models::{normalize_media_type, normalize_play_method};
use af_services::{
    BreakdownEntry, StreamTypeDistribution, StreamingAnalytics, StreamingHistoryEstimate,
    StreamingHistoryItem, StreamingTimeSeriesPoint, StreamingTitleStat, StreamingUserStat,
};
use chrono::{Datelike, Days, Months, NaiveDate, Utc};
use rusqlite::params_from_iter;
use std::collections::HashMap;

pub fn parse_window_days(raw: &str) -> (i32, &'static str) {
    match raw.trim().to_lowercase().as_str() {
        "1" | "24h" | "1d" => (1, "24h"),
        "7" | "7d" => (7, "7d"),
        "14" | "14d" => (14, "14d"),
        "30" | "30d" => (30, "30d"),
        "90" | "90d" => (90, "90d"),
        "365" | "365d" | "1y" => (365, "365d"),
        "0" | "all" => (0, "all"),
        other => {
            if let Ok(days) = other.trim_end_matches('d').parse::<i32>() {
                if (1..=3650).contains(&days) {
                    return (days, "custom");
                }
            }
            (30, "30d")
        }
    }
}

fn query_breakdown(
    conn: &rusqlite::Connection,
    column: &str,
    where_sql: &str,
    args: &[String],
    total_plays: i32,
) -> rusqlite::Result<Vec<BreakdownEntry>> {
    if !matches!(column, "item_type" | "video_resolution" | "video_codec") || total_plays <= 0 {
        return Ok(Vec::new());
    }

    let sql = format!(
        r#"
        SELECT
            COALESCE(NULLIF({col}, ''), 'Unknown') AS label,
            COUNT(*) AS cnt,
            COALESCE(SUM(watched_secs), 0),
            COALESCE(SUM(data_used_bytes), 0)
        FROM streaming_history
        {where_sql}
        GROUP BY label
        ORDER BY cnt DESC
        "#,
        col = column,
        where_sql = where_sql
    );

    let mut out = Vec::new();
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
        let count: i32 = r.get(1)?;
        let pct = ((count as f64 / total_plays as f64) * 1000.0).round() / 10.0;
        Ok(BreakdownEntry {
            label: r.get(0)?,
            count,
            pct,
            watch_time_secs: r.get(2)?,
            data_used_bytes: r.get(3)?,
        })
    })?;
    for item in rows {
        out.push(item?);
    }
    Ok(out)
}

pub(super) fn streaming_time_buckets(
    first_day: NaiveDate,
    today: NaiveDate,
) -> (&'static str, Vec<String>) {
    let span_days = (today - first_day).num_days().max(0) + 1;
    let granularity = if span_days <= 3650 {
        "day"
    } else if span_days <= 36500 {
        "month"
    } else {
        "year"
    };
    let mut cursor = match granularity {
        "month" => first_day.with_day(1).unwrap_or(first_day),
        "year" => first_day.with_ordinal(1).unwrap_or(first_day),
        _ => first_day,
    };
    let mut keys = Vec::new();
    while cursor <= today {
        keys.push(cursor.format("%Y-%m-%d").to_string());
        let next = match granularity {
            "month" => cursor.checked_add_months(Months::new(1)),
            "year" => cursor.checked_add_months(Months::new(12)),
            _ => cursor.checked_add_days(Days::new(1)),
        };
        let Some(next) = next else {
            break;
        };
        cursor = next;
    }
    (granularity, keys)
}

fn query_streaming_history_estimates(
    conn: &rusqlite::Connection,
    where_sql: &str,
    args: &[String],
    date_format: &str,
    day_keys: &[String],
) -> rusqlite::Result<Vec<StreamingHistoryEstimate>> {
    let mut estimates = Vec::new();
    let totals_sql = format!(
        "SELECT provenance, COUNT(*), COALESCE(SUM(MAX(COALESCE(watched_secs,0),0)),0), \
         COALESCE(SUM(event_unix IS NULL),0) FROM streaming_history {where_sql} \
         AND provenance IN ('item_summary','legacy_unverified') GROUP BY provenance ORDER BY provenance"
    );
    let mut totals = conn.prepare(&totals_sql)?;
    for estimate in totals.query_map(params_from_iter(args.iter()), |row| {
        Ok(StreamingHistoryEstimate {
            provenance: row.get(0)?,
            records: row.get(1)?,
            reported_watch_time_secs: row.get(2)?,
            undated_records: row.get(3)?,
            time_series: day_keys
                .iter()
                .map(|date| StreamingTimeSeriesPoint {
                    date: date.clone(),
                    ..Default::default()
                })
                .collect(),
        })
    })? {
        estimates.push(estimate?);
    }
    let series_sql = format!(
        "SELECT provenance, strftime('{date_format}',event_unix,'unixepoch'), COUNT(*), \
         COALESCE(SUM(MAX(COALESCE(watched_secs,0),0)),0) FROM streaming_history {where_sql} \
         AND provenance IN ('item_summary','legacy_unverified') AND event_unix IS NOT NULL \
         GROUP BY provenance, 2 ORDER BY 2"
    );
    let mut series = conn.prepare(&series_sql)?;
    let date_indexes: HashMap<&str, usize> = day_keys
        .iter()
        .enumerate()
        .map(|(index, date)| (date.as_str(), index))
        .collect();
    for point in series.query_map(params_from_iter(args.iter()), |row| {
        Ok((
            row.get::<_, String>(0)?,
            StreamingTimeSeriesPoint {
                date: row.get(1)?,
                plays: row.get(2)?,
                watch_time_secs: row.get(3)?,
                ..Default::default()
            },
        ))
    })? {
        let (provenance, point) = point?;
        if let (Some(estimate), Some(index)) = (
            estimates
                .iter_mut()
                .find(|estimate| estimate.provenance == provenance),
            date_indexes.get(point.date.as_str()),
        ) {
            estimate.time_series[*index] = point;
        }
    }
    Ok(estimates)
}

fn empty_fallback_analytics(
    resolved_window: i32,
    live_peak_bandwidth_mbps: f64,
    now: chrono::DateTime<Utc>,
) -> StreamingAnalytics {
    let mut result = StreamingAnalytics {
        window_days: resolved_window,
        peak_bandwidth_mbps: live_peak_bandwidth_mbps,
        media_type_breakdown: Vec::new(),
        resolution_breakdown: Vec::new(),
        codec_breakdown: Vec::new(),
        time_series_granularity: "day".to_string(),
        time_series: Vec::new(),
        top_users: Vec::new(),
        top_titles: Vec::new(),
        recent_history: Vec::new(),
        ..Default::default()
    };
    let fallback_days = if resolved_window > 0 {
        resolved_window.min(3650) + 1
    } else {
        30
    };
    for i in (0..fallback_days).rev() {
        let d = (now - chrono::Duration::days(i as i64))
            .format("%Y-%m-%d")
            .to_string();
        result.time_series.push(StreamingTimeSeriesPoint {
            date: d,
            ..Default::default()
        });
    }
    result
}

pub(super) fn try_query_streaming_analytics(
    window_days: i32,
    play_method_filter: &str,
    media_type_filter: &str,
    use_demo: bool,
    is_admin: bool,
    live_peak_bandwidth_mbps: f64,
) -> anyhow::Result<StreamingAnalytics> {
    let is_all_time = window_days == 0;
    let resolved_window = if is_all_time {
        0
    } else if window_days < 0 {
        30
    } else {
        window_days
    };

    let now = Utc::now();
    let mut result = StreamingAnalytics {
        window_days: resolved_window,
        peak_bandwidth_mbps: live_peak_bandwidth_mbps,
        media_type_breakdown: Vec::new(),
        resolution_breakdown: Vec::new(),
        codec_breakdown: Vec::new(),
        time_series_granularity: "day".to_string(),
        time_series: Vec::new(),
        top_users: Vec::new(),
        top_titles: Vec::new(),
        recent_history: Vec::new(),
        ..Default::default()
    };

    let conn = af_db::get_read_conn()?;

    let mut where_clauses: Vec<String> = vec!["1=1".to_string()];
    let mut args: Vec<String> = Vec::new();

    if !use_demo {
        where_clauses.push("provider != 'demo'".to_string());
        where_clauses.push(format!(
            "id IN (SELECT h.id FROM streaming_history h CROSS JOIN streaming_tracking_policies p WHERE p.id=1 AND ({}))",
            crate::streaming_history::inclusion_predicate()
        ));
    } else {
        where_clauses.push("provider = 'demo'".into());
    }
    if resolved_window > 0 {
        let cutoff = (now - chrono::Duration::days(resolved_window as i64))
            .timestamp()
            .to_string();
        where_clauses.push("event_unix >= CAST(? AS INTEGER)".to_string());
        args.push(cutoff);
    }
    let pm_trimmed = play_method_filter.trim();
    if !pm_trimmed.is_empty() && !pm_trimmed.eq_ignore_ascii_case("all") {
        if pm_trimmed.eq_ignore_ascii_case("unknown") {
            where_clauses.push(
                "LOWER(TRIM(COALESCE(play_method, ''))) NOT IN ('directplay', 'directstream', 'transcode')".to_string(),
            );
        } else {
            let normalized_pm = normalize_play_method(pm_trimmed);
            where_clauses.push("LOWER(TRIM(play_method)) = LOWER(?)".to_string());
            args.push(normalized_pm);
        }
    }
    let mt_trimmed = media_type_filter.trim();
    if !mt_trimmed.is_empty() && !mt_trimmed.eq_ignore_ascii_case("all") {
        let normalized_mt = normalize_media_type(mt_trimmed);
        where_clauses.push("LOWER(item_type) = LOWER(?)".to_string());
        args.push(normalized_mt);
    }

    let evidence_where_sql = format!("WHERE {}", where_clauses.join(" AND "));
    let where_sql = if use_demo {
        evidence_where_sql.clone()
    } else {
        format!("{evidence_where_sql} AND provenance IN ('observed_session','imported_event')")
    };

    let first_day = if resolved_window > 0 {
        (now - chrono::Duration::days(resolved_window as i64)).date_naive()
    } else {
        let min_day_sql = format!(
            "SELECT COALESCE(MIN(date(event_unix, 'unixepoch')), '') FROM streaming_history {}",
            evidence_where_sql
        );
        let earliest_raw: String =
            conn.query_row(&min_day_sql, params_from_iter(args.iter()), |r| {
                r.get::<_, String>(0)
            })?;
        let earliest_date = chrono::NaiveDate::parse_from_str(earliest_raw.trim(), "%Y-%m-%d").ok();

        earliest_date
            .unwrap_or(now.date_naive() - chrono::Duration::days(29))
            .min(now.date_naive() - chrono::Duration::days(29))
    };

    let (granularity, day_keys) = streaming_time_buckets(first_day, now.date_naive());
    result.time_series_granularity = granularity.to_string();
    let date_format = match granularity {
        "month" => "%Y-%m-01",
        "year" => "%Y-01-01",
        _ => "%Y-%m-%d",
    };
    if !use_demo {
        result.historical_estimates = query_streaming_history_estimates(
            &conn,
            &evidence_where_sql,
            &args,
            date_format,
            &day_keys,
        )?;
    }
    let mut daily_map: HashMap<String, StreamingTimeSeriesPoint> = HashMap::new();
    for day in &day_keys {
        daily_map.insert(
            day.clone(),
            StreamingTimeSeriesPoint {
                date: day.clone(),
                ..Default::default()
            },
        );
    }

    // 1. Aggregate summary metrics
    let agg_sql = format!(
        r#"
        SELECT
            COUNT(*),
            COALESCE(SUM(watched_secs), 0),
            COALESCE(SUM(data_used_bytes), 0),
            COUNT(DISTINCT user_name),
            COUNT(DISTINCT item_name),
            COALESCE(AVG(completion_pct), 0),
            COALESCE(MAX(bitrate_bps), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'directplay' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'directstream' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'transcode' THEN 1 ELSE 0 END), 0)
        FROM streaming_history
        {}
        "#,
        where_sql
    );

    let (
        total_plays,
        total_watch_secs,
        total_data_bytes,
        unique_users,
        unique_titles,
        avg_completion,
        max_bitrate_bps,
        dp_count,
        ds_count,
        tc_count,
    ) = conn.query_row(&agg_sql, params_from_iter(args.iter()), |r| {
        Ok((
            r.get::<_, i32>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i32>(3)?,
            r.get::<_, i32>(4)?,
            r.get::<_, f64>(5)?,
            r.get::<_, i64>(6)?,
            r.get::<_, i32>(7)?,
            r.get::<_, i32>(8)?,
            r.get::<_, i32>(9)?,
        ))
    })?;
    result.total_plays = total_plays;
    result.total_watch_time_secs = total_watch_secs;
    result.total_data_used_bytes = total_data_bytes;
    result.unique_users = unique_users;
    result.unique_titles = unique_titles;
    result.avg_completion_pct = (avg_completion * 10.0).round() / 10.0;

    let hist_peak_mbps = ((max_bitrate_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;
    if hist_peak_mbps > result.peak_bandwidth_mbps {
        result.peak_bandwidth_mbps = hist_peak_mbps;
    }

    result.stream_types = StreamTypeDistribution {
        direct_play_count: dp_count,
        direct_stream_count: ds_count,
        transcode_count: tc_count,
        direct_play_pct: if total_plays > 0 {
            ((dp_count as f64 / total_plays as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        },
        direct_stream_pct: if total_plays > 0 {
            ((ds_count as f64 / total_plays as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        },
        transcode_pct: if total_plays > 0 {
            ((tc_count as f64 / total_plays as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        },
    };

    let mut bw_clauses: Vec<String> = vec!["1=1".to_string()];
    let mut bw_args: Vec<String> = Vec::new();
    let no_item_filters = (pm_trimmed.is_empty() || pm_trimmed.eq_ignore_ascii_case("all"))
        && (mt_trimmed.is_empty() || mt_trimmed.eq_ignore_ascii_case("all"));

    // Check bandwidth samples for peak aggregate bitrate when no per-item filter is active
    if no_item_filters {
        if !use_demo {
            bw_clauses.push("provider != 'demo'".to_string());
        } else {
            bw_clauses.push("provider = 'demo'".to_string());
        }
        if resolved_window > 0 {
            let cutoff = (now - chrono::Duration::days(resolved_window as i64))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();
            bw_clauses.push("timestamp >= ?".to_string());
            bw_args.push(cutoff);
        }
        let bw_sql = format!(
            "SELECT COALESCE(MAX(total_bitrate_bps), 0) FROM streaming_bandwidth_samples WHERE {}",
            bw_clauses.join(" AND ")
        );
        let sample_peak_bps: i64 =
            conn.query_row(&bw_sql, params_from_iter(bw_args.iter()), |r| r.get(0))?;
        let sample_peak_mbps = ((sample_peak_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;
        if sample_peak_mbps > result.peak_bandwidth_mbps {
            result.peak_bandwidth_mbps = sample_peak_mbps;
        }
    }

    // 2. Breakdowns: Media Type, Resolution, Video Codec
    result.media_type_breakdown =
        query_breakdown(&conn, "item_type", &where_sql, &args, result.total_plays)?;
    result.resolution_breakdown = query_breakdown(
        &conn,
        "video_resolution",
        &where_sql,
        &args,
        result.total_plays,
    )?;
    result.codec_breakdown =
        query_breakdown(&conn, "video_codec", &where_sql, &args, result.total_plays)?;

    // 3. Time Series (Daily Plays, Watch Time, Data Usage, Stream Types)
    let ts_sql = format!(
        r#"
        SELECT
            strftime('{date_format}', event_unix, 'unixepoch') AS day,
            COUNT(*),
            COALESCE(SUM(watched_secs), 0),
            COALESCE(SUM(data_used_bytes), 0),
            COALESCE(MAX(bitrate_bps), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'directplay' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'directstream' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'transcode' THEN 1 ELSE 0 END), 0)
        FROM streaming_history
        {} AND event_unix IS NOT NULL
        GROUP BY day
        ORDER BY day ASC
        "#,
        where_sql
    );
    {
        let mut stmt = conn.prepare(&ts_sql)?;
        let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
            let max_day_bitrate: i64 = r.get(4)?;
            Ok(StreamingTimeSeriesPoint {
                date: r.get(0)?,
                plays: r.get(1)?,
                watch_time_secs: r.get(2)?,
                data_used_bytes: r.get(3)?,
                peak_bandwidth_mbps: ((max_day_bitrate as f64 / 1_000_000.0) * 100.0).round()
                    / 100.0,
                direct_play_count: r.get(5)?,
                direct_stream_count: r.get(6)?,
                transcode_count: r.get(7)?,
            })
        })?;
        for pt in rows {
            let pt = pt?;
            daily_map.insert(pt.date.clone(), pt);
        }
    }

    if no_item_filters {
        let bw_daily_sql = format!(
            r#"
            SELECT
                strftime('{date_format}', timestamp) AS day,
                COALESCE(MAX(total_bitrate_bps), 0)
            FROM streaming_bandwidth_samples
            WHERE {} AND timestamp != ''
            GROUP BY day
            "#,
            bw_clauses.join(" AND ")
        );
        let mut stmt = conn.prepare(&bw_daily_sql)?;
        let rows = stmt.query_map(params_from_iter(bw_args.iter()), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (day, peak_bps) = row?;
            let sample_mbps = ((peak_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;
            if let Some(pt) = daily_map.get_mut(&day) {
                if sample_mbps > pt.peak_bandwidth_mbps {
                    pt.peak_bandwidth_mbps = sample_mbps;
                }
            }
        }
    }

    for d in day_keys {
        if let Some(pt) = daily_map.remove(&d) {
            result.time_series.push(pt);
        }
    }

    // 4. Top Users Leaderboard
    let users_sql = format!(
        r#"
        WITH filtered_history AS (SELECT * FROM streaming_history {where_sql})
        SELECT
            COALESCE(MAX(NULLIF(user_id, '')), '') AS uid,
            user_name,
            COALESCE(MAX(NULLIF(provider, '')), 'jellyfin') AS prov,
            COUNT(*) AS plays,
            COALESCE(SUM(watched_secs), 0) AS watch_secs,
            COALESCE(SUM(data_used_bytes), 0) AS data_bytes,
            COUNT(DISTINCT item_name) AS unique_items,
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'directplay' THEN 1 ELSE 0 END), 0) AS dp_count,
            COALESCE(SUM(CASE WHEN LOWER(TRIM(play_method)) = 'transcode' THEN 1 ELSE 0 END), 0) AS tc_count,
            COALESCE(AVG(completion_pct), 0) AS avg_comp,
            COALESCE(
                (
                    SELECT CASE
                        WHEN h2.client_name != '' AND h2.device_name != '' THEN h2.client_name || ' · ' || h2.device_name
                        WHEN h2.client_name != '' THEN h2.client_name
                        ELSE h2.device_name
                    END
                    FROM filtered_history h2
                    WHERE h2.user_name = filtered_history.user_name
                      AND (h2.client_name != '' OR h2.device_name != '')
                    ORDER BY COALESCE(NULLIF(h2.last_seen_at, ''), h2.started_at) DESC, h2.id DESC
                    LIMIT 1
                ),
                ''
            ) AS last_device,
            COALESCE(MAX(CAST(last_seen_at AS TEXT)), '') AS last_seen
        FROM filtered_history
        WHERE user_name != ''
        GROUP BY user_name
        ORDER BY data_bytes DESC, watch_secs DESC, plays DESC
        LIMIT 10
        "#
    );
    {
        let mut stmt = conn.prepare(&users_sql)?;
        let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
            let avg_comp: f64 = r.get(9)?;
            Ok(StreamingUserStat {
                user_id: r.get(0)?,
                user_name: r.get(1)?,
                provider: r.get(2)?,
                total_plays: r.get(3)?,
                total_watch_secs: r.get(4)?,
                total_data_bytes: r.get(5)?,
                unique_items: r.get(6)?,
                direct_play_count: r.get(7)?,
                transcode_count: r.get(8)?,
                avg_completion_pct: (avg_comp * 10.0).round() / 10.0,
                last_device: r.get(10)?,
                last_seen_at: r.get(11)?,
            })
        })?;
        for item in rows {
            result.top_users.push(item?);
        }
    }

    // 5. Top Watched Titles
    let titles_sql = format!(
        r#"
        SELECT
            COALESCE(MAX(NULLIF(item_id, '')), ''),
            CASE WHEN series_name != '' THEN series_name ELSE item_name END AS display_title,
            item_type,
            series_name,
            COALESCE(MAX(production_year), 0),
            COALESCE(MAX(NULLIF(provider, '')), 'jellyfin'),
            COALESCE(MAX(NULLIF(video_resolution, '')), ''),
            COALESCE(MAX(NULLIF(video_codec, '')), ''),
            COUNT(*) AS plays,
            COUNT(DISTINCT user_name) AS viewers,
            COALESCE(SUM(watched_secs), 0) AS watch_secs,
            COALESCE(SUM(data_used_bytes), 0) AS data_bytes,
            COALESCE(AVG(completion_pct), 0) AS avg_comp,
            COALESCE(MAX(CAST(last_seen_at AS TEXT)), '') AS last_watched
        FROM streaming_history
        {} AND item_name != ''
        GROUP BY display_title, item_type
        ORDER BY plays DESC, watch_secs DESC, data_bytes DESC
        LIMIT 10
        "#,
        where_sql
    );
    {
        let mut stmt = conn.prepare(&titles_sql)?;
        let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
            let avg_comp: f64 = r.get(12)?;
            Ok(StreamingTitleStat {
                item_id: r.get(0)?,
                item_name: r.get(1)?,
                item_type: r.get(2)?,
                series_name: r.get(3)?,
                production_year: r.get(4)?,
                provider: r.get(5)?,
                video_resolution: r.get(6)?,
                video_codec: r.get(7)?,
                total_plays: r.get(8)?,
                unique_viewers: r.get(9)?,
                total_watch_secs: r.get(10)?,
                total_data_bytes: r.get(11)?,
                avg_completion_pct: (avg_comp * 10.0).round() / 10.0,
                last_watched_at: r.get(13)?,
            })
        })?;
        for item in rows {
            result.top_titles.push(item?);
        }
    }

    // 6. Recent History Log
    let hist_sql = format!(
        r#"
        SELECT
            id,
            COALESCE(session_key, ''),
            provider,
            server_name,
            user_name,
            client_name,
            device_name,
            ip_address,
            item_id,
            item_name,
            item_type,
            series_name,
            season_number,
            episode_number,
            production_year,
            play_method,
            container,
            video_codec,
            video_resolution,
            audio_codec,
            audio_channels,
            hw_accel,
            bitrate_bps,
            duration_secs,
            watched_secs,
            data_used_bytes,
            completion_pct,
            COALESCE(CAST(started_at AS TEXT), ''),
            COALESCE(CAST(last_seen_at AS TEXT), ''),
            is_active
        FROM streaming_history
        {}
        ORDER BY last_seen_at DESC, id DESC
        LIMIT 500
        "#,
        where_sql
    );
    {
        let mut stmt = conn.prepare(&hist_sql)?;
        let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
            let raw_ip: String = r.get(7)?;
            let ip_address = if is_admin { raw_ip } else { String::new() };
            let bitrate_bps: i64 = r.get(22)?;
            let bandwidth_mbps = ((bitrate_bps as f64 / 1_000_000.0) * 100.0).round() / 100.0;
            let raw_comp: f64 = r.get(26)?;
            let completion_pct = (raw_comp * 10.0).round() / 10.0;
            let is_act: i32 = r.get(29)?;
            Ok(StreamingHistoryItem {
                id: r.get(0)?,
                session_key: r.get(1)?,
                provider: r.get(2)?,
                server_name: r.get(3)?,
                user_name: r.get(4)?,
                client_name: r.get(5)?,
                device_name: r.get(6)?,
                ip_address,
                item_id: r.get(8)?,
                item_name: r.get(9)?,
                item_type: r.get(10)?,
                series_name: r.get(11)?,
                season_number: r.get(12)?,
                episode_number: r.get(13)?,
                production_year: r.get(14)?,
                play_method: r.get(15)?,
                container: r.get(16)?,
                video_codec: r.get(17)?,
                video_resolution: r.get(18)?,
                audio_codec: r.get(19)?,
                audio_channels: r.get(20)?,
                hw_accel: r.get(21)?,
                bitrate_bps,
                bandwidth_mbps,
                duration_secs: r.get(23)?,
                watched_secs: r.get(24)?,
                data_used_bytes: r.get(25)?,
                completion_pct,
                started_at: r.get(27)?,
                last_seen_at: r.get(28)?,
                is_active: is_act != 0,
            })
        })?;
        for item in rows {
            result.recent_history.push(item?);
        }
    }

    Ok(result)
}

pub fn query_streaming_analytics(
    window_days: i32,
    play_method_filter: &str,
    media_type_filter: &str,
    use_demo: bool,
    is_admin: bool,
    live_peak_bandwidth_mbps: f64,
) -> StreamingAnalytics {
    match try_query_streaming_analytics(
        window_days,
        play_method_filter,
        media_type_filter,
        use_demo,
        is_admin,
        live_peak_bandwidth_mbps,
    ) {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(%error, "streaming analytics query failed");
            let resolved_window = if window_days == 0 {
                0
            } else if window_days < 0 {
                30
            } else {
                window_days
            };
            empty_fallback_analytics(resolved_window, live_peak_bandwidth_mbps, Utc::now())
        }
    }
}
