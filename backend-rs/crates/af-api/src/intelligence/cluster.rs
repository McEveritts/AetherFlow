use crate::auth::{api_error, AuthUser};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use rusqlite::{params, OptionalExtension as _};
use std::collections::HashMap;

pub async fn get_cluster_nodes() -> Response {
    af_services::cluster_daemon::ensure_cluster_schema();
    let conn = match af_db::get_read_conn() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(%err, "Database unavailable while fetching cluster nodes");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "CLUSTER_UNAVAILABLE",
                "Cluster node inventory is temporarily unavailable",
            );
        }
    };

    let mut stmt = match conn.prepare(
        "SELECT id, hostname, address, COALESCE(role, 'worker'), COALESCE(status, 'offline'), \
         COALESCE(last_heartbeat, ''), COALESCE(enrolled_at, ''), \
         COALESCE(cpu_usage, 0.0), COALESCE(ram_usage, 0.0), COALESCE(disk_usage, 0.0) \
         FROM cluster_nodes",
    ) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(%err, "Failed to prepare cluster_nodes query");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to query cluster nodes",
            );
        }
    };

    let rows_iter = match stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, f64>(7).unwrap_or(0.0),
            r.get::<_, f64>(8).unwrap_or(0.0),
            r.get::<_, f64>(9).unwrap_or(0.0),
        ))
    }) {
        Ok(iter) => iter,
        Err(err) => {
            tracing::warn!(%err, "Failed to execute cluster_nodes query");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to query cluster nodes",
            );
        }
    };

    let raw_nodes = match rows_iter.collect::<rusqlite::Result<Vec<_>>>() {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(%err, "Failed to decode cluster_nodes row");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to query cluster nodes",
            );
        }
    };

    let mut nodes = Vec::with_capacity(raw_nodes.len());
    let mut online = 0usize;
    let mut degraded = 0usize;
    let mut offline = 0usize;
    let mut cpu_sum = 0.0f64;
    let mut cpu_count = 0usize;
    let mut total_mem_used = 0.0f64;
    let mut total_mem_total = 0.0f64;
    let mut total_disk_used = 0.0f64;
    let mut total_disk_total = 0.0f64;

    for (
        id,
        hostname,
        address,
        role,
        status,
        last_heartbeat,
        enrolled_at,
        db_cpu,
        db_ram,
        db_disk,
    ) in raw_nodes
    {
        let cached = af_services::cluster_daemon::get_cached_worker_metrics(&id);
        let version = cached
            .as_ref()
            .and_then(|c| c.get("version"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("4.0.0")
            .to_string();

        let metrics_obj = cached.as_ref().and_then(|c| c.get("metrics"));
        let sys_info_obj = cached.as_ref().and_then(|c| c.get("system_info"));

        let cpu = af_hardware::sanitize_f64(
            cached
                .as_ref()
                .and_then(|c| c.get("cpu_usage"))
                .and_then(|v| v.as_f64())
                .or_else(|| {
                    metrics_obj
                        .and_then(|m| m.get("cpu_usage"))
                        .and_then(|v| v.as_f64())
                })
                .unwrap_or(db_cpu),
        );
        let ram_pct = af_hardware::sanitize_f64(
            cached
                .as_ref()
                .and_then(|c| c.get("ram_usage"))
                .and_then(|v| v.as_f64())
                .unwrap_or(db_ram),
        );
        let disk_pct = af_hardware::sanitize_f64(
            cached
                .as_ref()
                .and_then(|c| c.get("disk_usage"))
                .and_then(|v| v.as_f64())
                .unwrap_or(db_disk),
        );

        let mem_total_gb = af_hardware::sanitize_f64(
            metrics_obj
                .and_then(|m| {
                    m.get("mem_total_gb").and_then(|v| v.as_f64()).or_else(|| {
                        m.get("memory")
                            .and_then(|x| x.get("total"))
                            .and_then(|v| v.as_f64())
                    })
                })
                .or_else(|| {
                    sys_info_obj
                        .and_then(|s| s.get("total_memory_bytes"))
                        .and_then(|v| v.as_f64())
                        .filter(|&b| b > 0.0)
                        .map(|b| b / (1024.0 * 1024.0 * 1024.0))
                })
                .unwrap_or(0.0),
        );
        let mem_used_gb = af_hardware::sanitize_f64(
            metrics_obj
                .and_then(|m| {
                    m.get("mem_used_gb").and_then(|v| v.as_f64()).or_else(|| {
                        m.get("memory")
                            .and_then(|x| x.get("used"))
                            .and_then(|v| v.as_f64())
                    })
                })
                .or_else(|| {
                    if mem_total_gb > 0.0 && ram_pct > 0.0 {
                        Some((mem_total_gb * ram_pct / 100.0 * 100.0).round() / 100.0)
                    } else {
                        None
                    }
                })
                .unwrap_or(0.0),
        );

        let disk_total_gb = af_hardware::sanitize_f64(
            metrics_obj
                .and_then(|m| {
                    m.get("disk_total_gb").and_then(|v| v.as_f64()).or_else(|| {
                        m.get("disk_space")
                            .and_then(|x| x.get("total"))
                            .and_then(|v| v.as_f64())
                    })
                })
                .or_else(|| {
                    sys_info_obj
                        .and_then(|s| s.get("total_disk_bytes"))
                        .and_then(|v| v.as_f64())
                        .filter(|&b| b > 0.0)
                        .map(|b| b / (1024.0 * 1024.0 * 1024.0))
                })
                .unwrap_or(0.0),
        );
        let disk_used_gb = af_hardware::sanitize_f64(
            metrics_obj
                .and_then(|m| {
                    m.get("disk_used_gb").and_then(|v| v.as_f64()).or_else(|| {
                        m.get("disk_space")
                            .and_then(|x| x.get("used"))
                            .and_then(|v| v.as_f64())
                    })
                })
                .or_else(|| {
                    if disk_total_gb > 0.0 && disk_pct > 0.0 {
                        Some((disk_total_gb * disk_pct / 100.0 * 100.0).round() / 100.0)
                    } else {
                        None
                    }
                })
                .unwrap_or(0.0),
        );

        let net_rx_speed = metrics_obj
            .and_then(|m| m.get("net_rx_speed"))
            .and_then(|v| v.as_str())
            .unwrap_or("0 B/s");
        let net_tx_speed = metrics_obj
            .and_then(|m| m.get("net_tx_speed"))
            .and_then(|v| v.as_str())
            .unwrap_or("0 B/s");
        let uptime = metrics_obj
            .and_then(|m| m.get("uptime"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let load_average = metrics_obj
            .and_then(|m| m.get("load_average"))
            .filter(|v| v.is_array())
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        match status.as_str() {
            "online" => {
                online += 1;
                cpu_sum += cpu;
                cpu_count += 1;
                total_mem_used += mem_used_gb;
                total_mem_total += mem_total_gb;
                total_disk_used += disk_used_gb;
                total_disk_total += disk_total_gb;
            }
            "degraded" => {
                degraded += 1;
                cpu_sum += cpu;
                cpu_count += 1;
                total_mem_used += mem_used_gb;
                total_mem_total += mem_total_gb;
                total_disk_used += disk_used_gb;
                total_disk_total += disk_total_gb;
            }
            _ => {
                offline += 1;
            }
        }

        let node_metrics = serde_json::json!({
            "cpu_usage": cpu,
            "ram_usage": ram_pct,
            "disk_usage": disk_pct,
            "mem_used_gb": mem_used_gb,
            "mem_total_gb": mem_total_gb,
            "disk_used_gb": disk_used_gb,
            "disk_total_gb": disk_total_gb,
            "net_rx_speed": net_rx_speed,
            "net_tx_speed": net_tx_speed,
            "uptime": uptime,
            "load_average": load_average,
        });

        nodes.push(serde_json::json!({
            "id": id,
            "hostname": hostname,
            "address": address,
            "role": role,
            "status": status,
            "version": version,
            "last_heartbeat": last_heartbeat,
            "enrolled_at": enrolled_at,
            "cpu_usage": cpu,
            "ram_usage": ram_pct,
            "disk_usage": disk_pct,
            "metrics": node_metrics,
            "services": cached.as_ref().and_then(|c| c.get("services")).cloned().unwrap_or(serde_json::Value::Null),
            "services_status": cached.as_ref().and_then(|c| c.get("services_status")).and_then(|v| v.as_str()).unwrap_or("unknown"),
            "services_observed_at": cached.as_ref().and_then(|c| c.get("services_observed_at")).cloned().unwrap_or(serde_json::Value::Null),
            "system_info": sys_info_obj.cloned().unwrap_or(serde_json::Value::Null),
        }));
    }

    let total_cpu_avg = if cpu_count > 0 {
        af_hardware::sanitize_f64(((cpu_sum / (cpu_count as f64)) * 100.0).round() / 100.0)
    } else {
        0.0
    };

    Json(serde_json::json!({
        "nodes": nodes,
        "summary": {
            "total_nodes": nodes.len(),
            "online": online,
            "offline": offline,
            "online_nodes": online,
            "degraded_nodes": degraded,
            "offline_nodes": offline,
            "healthy": offline == 0 && degraded == 0,
            "total_cpu_avg": total_cpu_avg,
            "total_mem_used": af_hardware::sanitize_f64((total_mem_used * 100.0).round() / 100.0),
            "total_mem_total": af_hardware::sanitize_f64((total_mem_total * 100.0).round() / 100.0),
            "total_disk_used": af_hardware::sanitize_f64((total_disk_used * 100.0).round() / 100.0),
            "total_disk_total": af_hardware::sanitize_f64((total_disk_total * 100.0).round() / 100.0),
        }
    }))
    .into_response()
}

pub async fn enroll_worker(
    axum::extract::Extension(auth_user): axum::extract::Extension<AuthUser>,
) -> Response {
    if auth_user.role != "admin" {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    let token = match af_services::cluster_daemon::issue_cluster_enrollment_token() {
        Ok(tok) => tok,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                format!("Failed to persist cluster enrollment token: {e}"),
            );
        }
    };
    let bind_cfg = af_services::cluster_daemon::resolve_master_bind_config();
    Json(serde_json::json!({
        "enrollment_token": token,
        "instructions": format!(
            "Configure /etc/aetherflow/aetherflow.env on the worker node with mTLS certificates:\nCLUSTER_MODE=worker\nCLUSTER_MASTER_ADDR=https://<this-server>:{}\nCLUSTER_CA_CERT=/etc/aetherflow/certs/ca.crt\nCLUSTER_CLIENT_CERT=/etc/aetherflow/certs/worker.crt\nCLUSTER_CLIENT_KEY=/etc/aetherflow/certs/worker.key\nCLUSTER_PSK={}\nThen restart aetherflow-api.service.",
            bind_cfg.port, token
        ),
    }))
    .into_response()
}

pub async fn remove_worker(
    axum::extract::Extension(auth_user): axum::extract::Extension<AuthUser>,
    Path(node_id): Path<String>,
) -> Response {
    if auth_user.role != "admin" {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    if node_id.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Node ID is required",
        );
    }
    let conn = match af_db::get_conn() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(%err, %node_id, "Database unavailable while removing cluster worker");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "DATABASE_UNAVAILABLE",
                "Database unavailable",
            );
        }
    };
    let affected = match conn.execute("DELETE FROM cluster_nodes WHERE id = ?1", params![node_id]) {
        Ok(count) => count,
        Err(err) => {
            tracing::warn!(%err, %node_id, "Failed to delete cluster worker node");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to remove cluster node",
            );
        }
    };
    if affected == 0 {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Node not found");
    }
    af_services::cluster_daemon::remove_cached_worker_metrics(&node_id);
    Json(serde_json::json!({
        "message": "Node removed successfully",
        "node_id": node_id,
    }))
    .into_response()
}

pub async fn dispatch_worker_command(
    axum::extract::Extension(auth_user): axum::extract::Extension<AuthUser>,
    Path(node_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    if auth_user.role != "admin" {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    let clean_node = node_id.trim();
    if clean_node.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Node ID is required",
        );
    }
    let conn = match af_db::get_read_conn() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(%err, node_id = clean_node, "Database unavailable while verifying cluster worker");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "DATABASE_UNAVAILABLE",
                "Database unavailable",
            );
        }
    };
    let node_exists = match conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM cluster_nodes WHERE id = ?1)",
        params![clean_node],
        |r| r.get::<_, bool>(0),
    ) {
        Ok(exists) => exists,
        Err(err) => {
            tracing::warn!(%err, node_id = clean_node, "Failed to verify cluster worker existence");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to verify cluster node",
            );
        }
    };
    if !node_exists {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Node not found");
    }

    let cmd_type = req
        .get("cmd_type")
        .or_else(|| req.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let target = req
        .get("target")
        .or_else(|| req.get("service"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match af_services::cluster_daemon::enqueue_cluster_command(clean_node, cmd_type, target) {
        Ok(record) => {
            af_db::record_audit(
                auth_user.user_id,
                &auth_user.username,
                "cluster_command_dispatched",
                "cluster_node",
                clean_node,
                &format!(
                    "id={} cmd_type={} target={}",
                    record.id, record.cmd_type, record.target
                ),
                "",
                "",
            );
            Json(serde_json::json!({
                "message": "Cluster command queued",
                "command": record,
            }))
            .into_response()
        }
        Err(err) => api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", err.to_string()),
    }
}

pub async fn list_worker_commands(
    axum::extract::Extension(auth_user): axum::extract::Extension<AuthUser>,
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    if auth_user.role != "admin" {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    let node_id = q
        .get("node_id")
        .or_else(|| q.get("nodeId"))
        .map(String::as_str);
    let limit = q
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50);
    match af_services::cluster_daemon::list_cluster_commands(node_id, limit) {
        Ok(commands) => Json(serde_json::json!({ "commands": commands })).into_response(),
        Err(err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            err.to_string(),
        ),
    }
}

pub async fn get_worker_metrics(Path(node_id): Path<String>) -> Response {
    if let Some(cached) = af_services::cluster_daemon::get_cached_worker_metrics(&node_id) {
        return Json(cached).into_response();
    }
    let conn = match af_db::get_read_conn() {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(%err, %node_id, "Database unavailable while fetching worker metrics");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "DATABASE_UNAVAILABLE",
                "Database unavailable",
            );
        }
    };
    let row = match conn
        .query_row(
            "SELECT hostname, COALESCE(status, 'offline'), COALESCE(last_heartbeat, '') FROM cluster_nodes WHERE id = ?1",
            params![node_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
        )
        .optional()
    {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(%err, %node_id, "Failed to query worker metrics from SQLite");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Failed to load worker node metrics",
            );
        }
    };
    let Some((hostname, status, last_hb)) = row else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Node not found");
    };

    Json(serde_json::json!({
        "node_id": node_id,
        "hostname": hostname,
        "status": status,
        "metrics": null,
        "services": null,
        "services_status": "unknown",
        "services_observed_at": null,
        "system_info": null,
        "last_heartbeat": last_hb,
    }))
    .into_response()
}
