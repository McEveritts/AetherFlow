use super::ai_providers::{call_configured_ai, clean_json_fence, resolve_provider_settings};
use crate::auth::{api_error, AuthUser};
use axum::extract::{Query, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use chrono::{Duration, Utc};
use rusqlite::params;
use std::collections::HashMap;

pub fn get_system_metrics_context() -> String {
    let m = af_hardware::get_system_metrics_core();
    let mut sb = String::from("=== CURRENT SYSTEM METRICS ===\n");
    sb.push_str(&format!("CPU Usage: {:.1}%\n", m.cpu_usage));
    sb.push_str(&format!("CPU Frequency: {:.0} MHz\n", m.cpu_freq_mhz));
    if let (Some(&used), Some(&total)) = (m.memory.get("used"), m.memory.get("total")) {
        let pct = if total > 0.0 {
            (used / total) * 100.0
        } else {
            0.0
        };
        sb.push_str(&format!(
            "Memory: {:.2} / {:.2} GB ({:.1}%)\n",
            used, total, pct
        ));
    }
    for disk in &m.disks {
        sb.push_str(&format!(
            "Disk {} ({}): {:.1} / {:.1} GB ({:.1}% used)\n",
            disk.mount_point, disk.device, disk.used_gb, disk.total_gb, disk.used_pct
        ));
    }
    sb.push_str(&format!("Uptime: {}\n", m.uptime));
    if m.load_average.len() >= 3 {
        sb.push_str(&format!(
            "Load Average: {:.2} / {:.2} / {:.2}\n",
            m.load_average[0], m.load_average[1], m.load_average[2]
        ));
    }
    sb.push_str("=== END METRICS ===\n");
    sb
}

fn compute_linear_slope(values: &[f64]) -> f64 {
    let n = values.len();
    if n < 2 {
        return 0.0;
    }
    let nf = n as f64;
    let mut sum_x = 0.0;
    let mut sum_y = 0.0;
    let mut sum_xy = 0.0;
    let mut sum_x2 = 0.0;
    for (i, &v) in values.iter().enumerate() {
        let x = i as f64;
        sum_x += x;
        sum_y += v;
        sum_xy += x * v;
        sum_x2 += x * x;
    }
    let denom = nf * sum_x2 - sum_x * sum_x;
    if denom.abs() < 1e-12 {
        return 0.0;
    }
    (nf * sum_xy - sum_x * sum_y) / denom
}

fn classify_metric_trend(
    slope: f64,
    avg_val: f64,
    max_val: f64,
    crit_threshold: f64,
) -> &'static str {
    if max_val >= crit_threshold || avg_val >= crit_threshold * 0.95 {
        "critical"
    } else if slope > 0.05 {
        "increasing"
    } else if slope < -0.05 {
        "decreasing"
    } else {
        "stable"
    }
}

async fn build_resource_predictions(invoke_ai: bool) -> Response {
    #[derive(Clone)]
    struct HistPoint {
        cpu_avg: f64,
        mem_used_gb: f64,
        mem_total_gb: f64,
        disk_write_bps: f64,
        net_rx_bytes: i64,
        net_tx_bytes: i64,
        load_avg_1: f64,
    }

    enum HistoryLoadError {
        Unavailable(String),
        Query(String),
    }

    let history =
        match tokio::task::spawn_blocking(move || -> Result<Vec<HistPoint>, HistoryLoadError> {
            let conn = af_db::get_read_conn()
                .map_err(|err| HistoryLoadError::Unavailable(err.to_string()))?;
            let cutoff = (Utc::now() - Duration::days(30))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();
            let mut stmt = conn
                .prepare(METRICS_PREDICTIONS_HISTORY_SQL)
                .map_err(|err| HistoryLoadError::Query(err.to_string()))?;
            let rows = stmt
                .query_map(params![cutoff], |row| {
                    Ok(HistPoint {
                        cpu_avg: row.get(1)?,
                        mem_used_gb: row.get(2)?,
                        mem_total_gb: row.get(3)?,
                        disk_write_bps: row.get(5)?,
                        net_rx_bytes: row.get(6)?,
                        net_tx_bytes: row.get(7)?,
                        load_avg_1: row.get(8)?,
                    })
                })
                .map_err(|err| HistoryLoadError::Query(err.to_string()))?;
            let mut points: Vec<HistPoint> = rows
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|err| HistoryLoadError::Query(err.to_string()))?;
            points.reverse();
            Ok(points)
        })
        .await
        {
            Ok(Ok(points)) => points,
            Ok(Err(HistoryLoadError::Unavailable(err))) => {
                tracing::warn!(%err, "Database unavailable while building resource predictions");
                return api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "PREDICTIONS_UNAVAILABLE",
                    "Metrics history is temporarily unavailable for predictions",
                );
            }
            Ok(Err(HistoryLoadError::Query(err))) => {
                tracing::warn!(%err, "Failed to query metrics history for predictions");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DATABASE_ERROR",
                    "Failed to load metrics history for predictions",
                );
            }
            Err(err) => {
                tracing::warn!(%err, "Metrics history prediction worker panicked");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to load metrics history for predictions",
                );
            }
        };

    let m = af_hardware::get_system_metrics_core();
    let disk_pct = m.disks.first().map(|d| d.used_pct).unwrap_or(0.0);
    let disk_free_gb = m
        .disks
        .first()
        .map(|d| (d.total_gb - d.used_gb).max(0.0))
        .unwrap_or(100.0);

    let mut cpu_vals = Vec::with_capacity(history.len().max(1));
    let mut mem_pcts = Vec::with_capacity(history.len().max(1));
    let mut disk_writes = Vec::with_capacity(history.len().max(1));
    let mut net_totals = Vec::with_capacity(history.len().max(1));
    let mut anomalies: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    if history.is_empty() {
        cpu_vals.push(m.cpu_usage);
        let used = m.memory.get("used").copied().unwrap_or(0.0);
        let total = m.memory.get("total").copied().unwrap_or(0.0);
        mem_pcts.push(if total > 0.0 {
            (used / total) * 100.0
        } else {
            0.0
        });
        disk_writes.push(m.disk_io.get("write_bytes_sec").copied().unwrap_or(0.0));
        net_totals.push(
            (m.total_net_bytes.get("rx").copied().unwrap_or(0)
                + m.total_net_bytes.get("tx").copied().unwrap_or(0)) as f64,
        );
    } else {
        for pt in &history {
            cpu_vals.push(pt.cpu_avg);
            let mp = if pt.mem_total_gb > 0.0 {
                (pt.mem_used_gb / pt.mem_total_gb) * 100.0
            } else {
                0.0
            };
            mem_pcts.push(mp);
            disk_writes.push(pt.disk_write_bps);
            net_totals.push((pt.net_rx_bytes.saturating_add(pt.net_tx_bytes)) as f64);
        }
    }

    let n = cpu_vals.len() as f64;
    let cpu_avg = cpu_vals.iter().sum::<f64>() / n;
    let cpu_max = cpu_vals.iter().copied().fold(0.0_f64, f64::max);
    let mem_avg = mem_pcts.iter().sum::<f64>() / n;
    let mem_max = mem_pcts.iter().copied().fold(0.0_f64, f64::max);
    let disk_write_avg = disk_writes.iter().sum::<f64>() / n;
    let load_avg = if history.is_empty() {
        m.load_average.first().copied().unwrap_or(0.0)
    } else {
        history.iter().map(|h| h.load_avg_1).sum::<f64>() / (history.len() as f64)
    };

    let cpu_slope = compute_linear_slope(&cpu_vals);
    let mem_slope = compute_linear_slope(&mem_pcts);
    let disk_io_slope = compute_linear_slope(&disk_writes);
    let net_slope = compute_linear_slope(&net_totals);

    let cpu_trend = classify_metric_trend(cpu_slope, cpu_avg, cpu_max, 90.0);
    let memory_trend = classify_metric_trend(mem_slope, mem_avg, mem_max, 92.0);
    let disk_trend = if disk_pct >= 92.0 {
        "critical"
    } else if disk_pct > 80.0 || disk_io_slope > 1024.0 {
        "increasing"
    } else if disk_io_slope < -1024.0 {
        "decreasing"
    } else {
        "stable"
    };
    let disk_io_trend = if disk_write_avg > 100.0 * 1024.0 * 1024.0 {
        "critical"
    } else if disk_io_slope > 1024.0 {
        "increasing"
    } else if disk_io_slope < -1024.0 {
        "decreasing"
    } else {
        "stable"
    };
    let network_trend = if net_slope > 10_000.0 {
        "increasing"
    } else if net_slope < -10_000.0 {
        "decreasing"
    } else {
        "stable"
    };

    // Estimate days until disk full from observed write rate or remaining capacity percentage
    let daily_write_gb = (disk_write_avg * 86_400.0) / (1024.0 * 1024.0 * 1024.0);
    let days_until_full = if disk_pct >= 99.0 {
        1
    } else if daily_write_gb > 0.5 && disk_free_gb > 0.0 {
        ((disk_free_gb / daily_write_gb).round() as i64).clamp(1, 365)
    } else {
        ((100.0 - disk_pct) * 3.5).round() as i64
    };

    if cpu_max > 85.0 {
        let msg = format!(
            "CPU utilization peaked at {:.1}% (average {:.1}%)",
            cpu_max, cpu_avg
        );
        anomalies.push(msg.clone());
        warnings.push(msg);
    }
    if mem_max > 90.0 {
        let msg = format!(
            "Memory pressure reached {:.1}% (average {:.1}%)",
            mem_max, mem_avg
        );
        anomalies.push(msg.clone());
        warnings.push(msg);
    }
    if load_avg > 4.0 {
        let msg = format!("Sustained 1m load average is elevated at {:.2}", load_avg);
        anomalies.push(msg.clone());
        warnings.push(msg);
    }
    if disk_pct > 85.0 {
        let msg = format!(
            "Primary storage utilization is at {:.1}% (~{} days remaining)",
            disk_pct, days_until_full
        );
        anomalies.push(msg.clone());
        warnings.push(msg);
    }

    let mut recommendations = Vec::new();
    if cpu_trend == "increasing" || cpu_trend == "critical" {
        recommendations.push(
            "Enable hardware-accelerated transcoding (NVENC/VAAPI/QSV) in MediaFlow to offload CPU spikes."
                .to_string(),
        );
    }
    if memory_trend == "increasing" || memory_trend == "critical" {
        recommendations.push(
            "Review memory-intensive services and configure swap or container memory limits."
                .to_string(),
        );
    }
    if disk_pct > 80.0 {
        recommendations.push(
            "Run MediaFlow HEVC/AV1 transcode optimization or prune old backups to reclaim storage."
                .to_string(),
        );
    }
    if recommendations.is_empty() {
        recommendations
            .push("Storage utilization is within healthy operational bounds.".to_string());
        recommendations.push("SQLite WAL retention pruning is active.".to_string());
    }

    let predicted_bottleneck = if disk_pct > 85.0 {
        "disk"
    } else if mem_max > 90.0 || memory_trend == "increasing" {
        "memory"
    } else if cpu_max > 85.0 || cpu_trend == "increasing" {
        "cpu"
    } else {
        "none"
    };

    let confidence_score = if history.len() >= 100 {
        0.92
    } else if history.len() >= 10 {
        0.80
    } else {
        0.65
    };

    let trend_summary = format!(
        "Analyzed {} telemetry snapshot(s): CPU avg {:.1}% (peak {:.1}%, trend {}), Memory avg {:.1}% (peak {:.1}%, trend {}), Disk {:.1}% used (~{} days until full).",
        history.len(),
        cpu_avg,
        cpu_max,
        cpu_trend,
        mem_avg,
        mem_max,
        memory_trend,
        disk_pct,
        days_until_full
    );

    if invoke_ai && history.len() >= 10 {
        let ps = resolve_provider_settings();
        let prompt = format!(
            "Analyze the following system metrics history and provide a resource prediction report.\n\n{}\n\nStatistical Summary:\n- Data points: {}\n- CPU Avg: {:.1}%, Max: {:.1}%, Linear Trend Slope: {:.4}\n- Memory Avg: {:.1}%, Max: {:.1}%, Linear Trend Slope: {:.4}\n- Avg 1m Load: {:.2}\n- Avg Disk Write: {:.0} B/s\n\nRespond ONLY with valid JSON in this exact format:\n{{\n  \"trend_summary\": \"2-3 sentence executive summary\",\n  \"cpu_trend\": \"increasing|decreasing|stable|critical\",\n  \"memory_trend\": \"increasing|decreasing|stable|critical\",\n  \"disk_io_trend\": \"increasing|decreasing|stable|critical\",\n  \"network_trend\": \"increasing|decreasing|stable|critical\",\n  \"warnings\": [\"warning 1\"],\n  \"recommendations\": [\"recommendation 1\"],\n  \"predicted_bottleneck\": \"cpu|memory|disk|network|none\",\n  \"confidence_score\": 0.85\n}}",
            get_system_metrics_context(),
            history.len(),
            cpu_avg,
            cpu_max,
            cpu_slope,
            mem_avg,
            mem_max,
            mem_slope,
            load_avg,
            disk_write_avg
        );
        if let Ok(ai_raw) = call_configured_ai(
            &ps,
            "You are FlowAI's predictive analytics engine for AetherFlow server management.",
            &prompt,
        )
        .await
        {
            let cleaned = clean_json_fence(&ai_raw);
            if let Ok(mut ai_val) = serde_json::from_str::<serde_json::Value>(&cleaned) {
                if let Some(obj) = ai_val.as_object_mut() {
                    obj.entry("disk_trend".to_string())
                        .or_insert_with(|| serde_json::json!(disk_trend));
                    obj.entry("days_until_disk_full".to_string())
                        .or_insert_with(|| serde_json::json!(days_until_full));
                    obj.entry("anomalies".to_string())
                        .or_insert_with(|| serde_json::json!(anomalies));
                    obj.entry("generated_at".to_string())
                        .or_insert_with(|| serde_json::json!(Utc::now().to_rfc3339()));
                    return Json(ai_val).into_response();
                }
            }
        }
    }

    Json(serde_json::json!({
        "trend_summary": trend_summary,
        "cpu_trend": cpu_trend,
        "memory_trend": memory_trend,
        "disk_trend": disk_trend,
        "disk_io_trend": disk_io_trend,
        "network_trend": network_trend,
        "days_until_disk_full": days_until_full,
        "anomalies": anomalies,
        "warnings": warnings,
        "recommendations": recommendations,
        "predicted_bottleneck": predicted_bottleneck,
        "confidence_score": confidence_score,
        "generated_at": Utc::now().to_rfc3339(),
    }))
    .into_response()
}

pub async fn get_predictions() -> Response {
    build_resource_predictions(false).await
}

pub async fn analyze_predictions() -> Response {
    build_resource_predictions(true).await
}

pub fn resolve_metrics_history_window_and_limit(
    q: &HashMap<String, String>,
) -> (Duration, i64, Option<usize>) {
    let mut default_limit: i64 = 2000;
    let window_dur = if let Some(win_raw) = q
        .get("window")
        .or_else(|| q.get("range"))
        .or_else(|| q.get("timeWindow"))
    {
        let w = win_raw.trim().to_ascii_lowercase();
        match w.as_str() {
            "1m" => Duration::minutes(1),
            "5m" => Duration::minutes(5),
            "15m" => Duration::minutes(15),
            "1h" => Duration::hours(1),
            "6h" => Duration::hours(6),
            "24h" | "1d" => {
                default_limit = 2400;
                Duration::hours(24)
            }
            "7d" => Duration::days(7),
            "30d" => Duration::days(30),
            "90d" => Duration::days(90),
            _ => {
                if let Some(num) = w.strip_suffix('m').and_then(|s| s.parse::<i64>().ok()) {
                    Duration::minutes(num.clamp(1, 60 * 24 * 365))
                } else if let Some(num) = w.strip_suffix('h').and_then(|s| s.parse::<i64>().ok()) {
                    Duration::hours(num.clamp(1, 24 * 365))
                } else if let Some(num) = w.strip_suffix('d').and_then(|s| s.parse::<i64>().ok()) {
                    Duration::days(num.clamp(1, 365))
                } else {
                    Duration::days(90)
                }
            }
        }
    } else if let Some(mins) = q
        .get("minutes")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&m| m > 0)
    {
        Duration::minutes(mins.clamp(1, 60 * 24 * 365))
    } else if let Some(hrs) = q
        .get("hours")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&h| h > 0)
    {
        if hrs <= 24 {
            default_limit = 2400;
        }
        Duration::hours(hrs.clamp(1, 24 * 365))
    } else {
        let days = q
            .get("days")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&d| d > 0)
            .unwrap_or(90)
            .clamp(1, 365);
        if days == 1 {
            default_limit = 2400;
        }
        Duration::days(days)
    };

    let limit = q
        .get("limit")
        .or_else(|| q.get("max_points"))
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&l| l > 0)
        .map(|l| l.clamp(1, 10_000))
        .unwrap_or(default_limit);

    let downsample_target = if q
        .get("downsample")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        let target = q
            .get("target_points")
            .or_else(|| q.get("downsample_points"))
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n >= 2)
            .unwrap_or(360);
        Some(target)
    } else {
        None
    };

    (window_dur, limit, downsample_target)
}

pub const METRICS_PREDICTIONS_HISTORY_SQL: &str = "SELECT COALESCE(CAST(timestamp AS TEXT), ''), COALESCE(cpu_avg, 0), COALESCE(mem_used_gb, 0), COALESCE(mem_total_gb, 0), \
     COALESCE(disk_read_bps, 0), COALESCE(disk_write_bps, 0), COALESCE(net_rx_bytes, 0), COALESCE(net_tx_bytes, 0), \
     COALESCE(load_avg_1, 0), COALESCE(active_conns, 0) \
     FROM metrics_history WHERE replace(CAST(timestamp AS TEXT), 'T', ' ') >= ?1 \
     ORDER BY replace(CAST(timestamp AS TEXT), 'T', ' ') DESC, id DESC LIMIT 2000";

pub const METRICS_HISTORY_QUERY_SQL: &str = "SELECT id, COALESCE(CAST(timestamp AS TEXT), ''), COALESCE(cpu_avg, 0), COALESCE(mem_used_gb, 0), COALESCE(mem_total_gb, 0), \
     COALESCE(disk_read_bps, 0), COALESCE(disk_write_bps, 0), COALESCE(net_rx_bytes, 0), COALESCE(net_tx_bytes, 0), \
     COALESCE(load_avg_1, 0), COALESCE(active_conns, 0) \
     FROM metrics_history WHERE replace(CAST(timestamp AS TEXT), 'T', ' ') >= ?1 \
     ORDER BY replace(CAST(timestamp AS TEXT), 'T', ' ') DESC, id DESC LIMIT ?2";

fn query_metrics_history_rows_checked(
    conn: &rusqlite::Connection,
    query_params: &HashMap<String, String>,
) -> rusqlite::Result<Vec<serde_json::Value>> {
    let (window_dur, limit, downsample_target) =
        resolve_metrics_history_window_and_limit(query_params);
    let cutoff = (Utc::now() - window_dur)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    let mut stmt = conn.prepare(METRICS_HISTORY_QUERY_SQL)?;
    let rows = stmt.query_map(params![cutoff, limit], |row| {
        let id: i64 = row.get(0)?;
        let timestamp: String = row.get(1)?;
        let cpu_avg: f64 = row.get(2)?;
        let mem_used_gb: f64 = row.get(3)?;
        let mem_total_gb: f64 = row.get(4)?;
        let disk_read_bps: f64 = row.get(5)?;
        let disk_write_bps: f64 = row.get(6)?;
        let net_rx_bytes: i64 = row.get(7)?;
        let net_tx_bytes: i64 = row.get(8)?;
        let load_avg_1: f64 = row.get(9)?;
        let active_conns: i64 = row.get(10)?;
        Ok(serde_json::json!({
            "id": id,
            "timestamp": timestamp,
            "recorded_at": timestamp,
            "cpu_avg": cpu_avg,
            "cpu_usage": cpu_avg,
            "mem_used_gb": mem_used_gb,
            "mem_total_gb": mem_total_gb,
            "disk_read_bps": disk_read_bps,
            "disk_write_bps": disk_write_bps,
            "net_rx_bytes": net_rx_bytes,
            "net_tx_bytes": net_tx_bytes,
            "load_avg_1": load_avg_1,
            "load_1m": load_avg_1,
            "active_conns": active_conns,
        }))
    })?;
    let mut snapshots: Vec<serde_json::Value> = rows.collect::<rusqlite::Result<Vec<_>>>()?;

    // Reverse newest-first rows into chronological ASC order (`oldest -> newest` within the latest bounded slice)
    snapshots.reverse();

    if let Some(target_pts) = downsample_target {
        if snapshots.len() > target_pts && target_pts >= 2 {
            let total = snapshots.len();
            let mut sampled = Vec::with_capacity(target_pts);
            for i in 0..target_pts {
                let idx = if i + 1 == target_pts {
                    total - 1
                } else {
                    (i * (total - 1)) / (target_pts - 1)
                };
                sampled.push(snapshots[idx].clone());
            }
            return Ok(sampled);
        }
    }

    Ok(snapshots)
}

pub fn query_metrics_history_rows(
    conn: &rusqlite::Connection,
    query_params: &HashMap<String, String>,
) -> Vec<serde_json::Value> {
    match query_metrics_history_rows_checked(conn, query_params) {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(%err, "Failed to query metrics history rows");
            Vec::new()
        }
    }
}

pub async fn get_metrics_history(Query(q): Query<HashMap<String, String>>) -> Response {
    if let Some(mode) = q.get("aggregate") {
        let daily = match mode.as_str() {
            "daily_transfer" => true,
            "capacity" => false,
            _ => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_AGGREGATE",
                    "Unknown history aggregation",
                )
            }
        };
        let days = q
            .get("days")
            .and_then(|d| d.parse::<i64>().ok())
            .unwrap_or(30)
            .clamp(1, 90);
        let now = Utc::now();
        let start = (now.date_naive() - Duration::days(days - 1))
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let db = af_db::get_read_conn()?;
            Ok(if daily {
                crate::metrics_rollup::daily_transfer(&db, start, now.timestamp())?
            } else {
                crate::metrics_rollup::capacity(&db, start, now.timestamp())?
            })
        })
        .await;
        return match result {
            Ok(Ok(value)) => Json(value).into_response(),
            _ => api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "HISTORY_UNAVAILABLE",
                "Metrics history unavailable",
            ),
        };
    }

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<serde_json::Value>> {
        let conn = af_db::get_read_conn()?;
        Ok(query_metrics_history_rows_checked(&conn, &q)?)
    })
    .await;
    match result {
        Ok(Ok(snapshots)) => Json(snapshots).into_response(),
        Ok(Err(err)) => {
            tracing::warn!(%err, "Metrics history unavailable");
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "HISTORY_UNAVAILABLE",
                "Metrics history unavailable",
            )
        }
        Err(err) => {
            tracing::warn!(%err, "Metrics history worker failed");
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "HISTORY_UNAVAILABLE",
                "Metrics history unavailable",
            )
        }
    }
}

pub async fn get_auth_metrics_history(Query(q): Query<HashMap<String, String>>) -> Response {
    get_metrics_history(Query(q)).await
}

pub async fn get_system_topology() -> Response {
    let (inventory, runner_online, db_online) = tokio::join!(
        crate::routes::read_service_inventory(),
        af_runner::runner_is_ready(),
        crate::routes::database_is_ready()
    );
    let Some(inventory) = inventory else {
        return crate::routes::service_inventory_unavailable();
    };
    Json(topology_from_inventory(inventory, runner_online, db_online)).into_response()
}

pub(super) fn topology_from_inventory(
    inventory: HashMap<String, af_services::ServiceStatusItem>,
    runner_online: bool,
    db_online: bool,
) -> serde_json::Value {
    use serde_json::json;
    let mut links = Vec::new();
    let label_for = |id: &str| {
        inventory
            .iter()
            .find(|(_, item)| item.id == id)
            .map(|(label, _)| label.clone())
    };
    let api = label_for("aetherflow-api");
    let gateway = label_for("apache2");
    let runner = label_for("aetherflow-runner").unwrap_or_else(|| "Runner Daemon".into());
    let mut nodes = vec![
        json!({"id":runner,"service_id":"aetherflow-runner","group":1,"status":if runner_online {"running"} else {"unknown"},"details":"Privileged runner socket"}),
        json!({"id":"SQLite WAL","group":2,"status":if db_online {"running"} else {"unknown"},"details":"SQLite (WAL mode)"}),
    ];
    if let Some(api) = &api {
        for target in [runner.as_str(), "SQLite WAL"] {
            links.push(json!({"source": api, "target": target, "value": 1}));
        }
        if let Some(gateway) = &gateway {
            links.push(json!({"source": gateway, "target": api, "value": 1}));
        }
    }
    let mut inventory: Vec<_> = inventory.into_iter().collect();
    inventory.sort_by(|a, b| a.0.cmp(&b.0));
    for (label, item) in inventory {
        if item.id == "aetherflow-runner" {
            continue;
        }
        let group = match item.id.as_str() {
            "aetherflow-api" | "aetherflow-frontend" => 1,
            "apache2" => 3,
            _ => 4,
        };
        // Keep graph metadata limited to operational information.
        let mut details = item.status.clone();
        if item.active_port > 0 {
            details = format!("Port {}", item.active_port);
            if !item.public_domain.is_empty() {
                details.push_str(&format!(" | {}", item.public_domain));
            }
        } else if item.default_port > 0 {
            details = format!("Port {} (blueprint)", item.default_port);
        }
        nodes.push(json!({"id":label,"service_id":item.id,"group":group,"status":item.status,"details":details}));
        if group == 4
            && (item.control_scope == "shared-vhost"
                || (item.external_access_enabled && !item.public_domain.is_empty()))
        {
            if let Some(gateway) = &gateway {
                links.push(json!({"source":gateway,"target":label,"value":1}));
            }
        } else if item.id == "aetherflow-frontend" {
            if let Some(api) = &api {
                links.push(json!({"source":api,"target":label,"value":1}));
            }
        }
    }
    json!({"nodes":nodes,"links":links})
}

pub(crate) fn infer_log_level(line: &str) -> &'static str {
    let lower = line.to_lowercase();
    if lower.contains("fatal") || lower.contains("panic") || lower.contains("crit") {
        "CRIT"
    } else if lower.contains("error") || lower.contains("err") || lower.contains("failed") {
        "ERROR"
    } else if lower.contains("warn") || lower.contains("warning") {
        "WARN"
    } else if lower.contains("debug") {
        "DEBUG"
    } else {
        "INFO"
    }
}

pub(crate) const AUDIT_LOG_FALLBACK_SQL: &str =
    "SELECT COALESCE(CAST(created_at AS TEXT), ''), COALESCE(action, 'event'), COALESCE(target_type, 'system'), COALESCE(detail, '') FROM admin_audit_log ORDER BY id DESC LIMIT ?1";

pub(crate) fn filter_log_entries(
    raw_entries: Vec<serde_json::Value>,
    unit: &str,
    level_filter: &str,
    search: &str,
    offset: usize,
    limit: usize,
) -> Vec<serde_json::Value> {
    let unit_lower = unit.trim().to_lowercase();
    let unit_base = unit_lower.trim_end_matches(".service");
    let level_upper = level_filter.trim().to_uppercase();
    let search_lower = search.trim().to_lowercase();

    raw_entries
        .into_iter()
        .filter(|entry| {
            if !unit_lower.is_empty() {
                let entry_source = entry.get("source").and_then(|v| v.as_str()).unwrap_or("");
                if !entry_source.eq_ignore_ascii_case("journald") {
                    let svc = entry
                        .get("service")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    let msg = entry
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    let matches_unit = svc.contains(&unit_lower)
                        || msg.contains(&unit_lower)
                        || (!unit_base.is_empty()
                            && (svc.contains(unit_base) || msg.contains(unit_base)));
                    if !matches_unit {
                        return false;
                    }
                }
            }
            if !level_upper.is_empty() {
                let lvl = entry
                    .get("level")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_uppercase();
                if !lvl.contains(&level_upper) {
                    return false;
                }
            }
            if !search_lower.is_empty() {
                let msg = entry
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let svc = entry
                    .get("service")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                if !msg.contains(&search_lower) && !svc.contains(&search_lower) {
                    return false;
                }
            }
            true
        })
        .skip(offset)
        .take(limit)
        .collect()
}

pub async fn get_log_sources() -> Response {
    Json(serde_json::json!({
        "sources": ["journald", "syslog", "apache", "application"]
    }))
    .into_response()
}

pub async fn bookmark_log(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 64 * 1024).await else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid body");
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON");
    };
    let log_source = body
        .get("log_source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let log_line = body.get("log_line").and_then(|v| v.as_str()).unwrap_or("");
    let timestamp = body.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
    let note = body.get("note").and_then(|v| v.as_str()).unwrap_or("");
    if log_source.is_empty() || log_line.is_empty() || timestamp.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "log_source, log_line, and timestamp are required",
        );
    }

    let conn = match af_db::get_conn() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(%err, "Database unavailable while bookmarking log");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "DATABASE_UNAVAILABLE",
                "Failed to bookmark log",
            );
        }
    };
    if let Err(err) = conn.execute(
        "INSERT INTO log_bookmarks (user_id, log_source, log_line, timestamp, note) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![user.user_id, log_source, log_line, timestamp, note],
    ) {
        tracing::warn!(%err, "Failed to insert log bookmark");
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to bookmark log",
        );
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "message": "Log bookmarked" })),
    )
        .into_response()
}

pub async fn get_bookmarks(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let conn = match af_db::get_read_conn() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(%err, "Database unavailable while fetching log bookmarks");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "DATABASE_UNAVAILABLE",
                "Failed to fetch bookmarks",
            );
        }
    };
    let mut stmt = match conn.prepare(
        "SELECT id, log_source, log_line, timestamp, COALESCE(note, ''), COALESCE(created_at, '') \
         FROM log_bookmarks WHERE user_id = ?1 ORDER BY created_at DESC",
    ) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(%err, "Failed to prepare log bookmarks query");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to fetch bookmarks",
            );
        }
    };
    let rows = match stmt.query_map(params![user.user_id], |r| {
        Ok(serde_json::json!({
            "id": r.get::<_, i64>(0)?,
            "log_source": r.get::<_, String>(1)?,
            "log_line": r.get::<_, String>(2)?,
            "timestamp": r.get::<_, String>(3)?,
            "note": r.get::<_, String>(4)?,
            "created_at": r.get::<_, String>(5)?,
        }))
    }) {
        Ok(iter) => iter,
        Err(err) => {
            tracing::warn!(%err, "Failed to execute log bookmarks query");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to fetch bookmarks",
            );
        }
    };
    let bookmarks: Vec<serde_json::Value> = match rows.collect::<rusqlite::Result<Vec<_>>>() {
        Ok(items) => items,
        Err(err) => {
            tracing::warn!(%err, "Failed to decode log bookmark row");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to fetch bookmarks",
            );
        }
    };
    Json(serde_json::json!({ "bookmarks": bookmarks })).into_response()
}
