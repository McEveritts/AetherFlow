use super::{OPENAPI_YAML, START_TIME};
use crate::auth::api_error;
use crate::ws::{extract_client_ip, extract_client_ip_for_peer};
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rusqlite::params;
use std::env;

pub(super) async fn health_check() -> Json<serde_json::Value> {
    let check_res = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::task::spawn_blocking(af_db::db_health_check),
    )
    .await;
    let (status, db_status, latency_ms) = match check_res {
        Ok(Ok(Ok(val))) => (
            "ok",
            "ok",
            val.get("latency_ms").and_then(|v| v.as_i64()).unwrap_or(0),
        ),
        _ => ("degraded", "unreachable", 0),
    };
    let transcode_caps = crate::peers::transcode::cached_local_capabilities_snapshot_only(
        &crate::peers::PeerRuntime::global(),
    );
    Json(serde_json::json!({
        "status": status,
        "uptime": format!("{:.1}s", START_TIME.elapsed().as_secs_f64()),
        "version": af_runner::af_release::runtime::runtime_identity().version,
        "database": db_status,
        "db_latency_ms": latency_ms,
        "peer_protocol": crate::peers::PEER_PROTOCOL_VERSION,
        "capabilities": crate::peers::capabilities(),
        "transcode": transcode_caps,
    }))
}

pub(super) async fn health_live() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "alive" }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReadinessStatus {
    http_status: StatusCode,
    status: &'static str,
    database: &'static str,
    runner: &'static str,
}

pub(super) fn privileged_runner_is_enabled() -> bool {
    env::var("PRIVILEGED_RUNNER_ENABLED").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        )
    })
}

pub(super) async fn evaluate_readiness() -> ReadinessStatus {
    let runner_enabled = privileged_runner_is_enabled();
    let (db_ready, runner_state) = if runner_enabled {
        let (db_ready, runner_ready) =
            tokio::join!(database_is_ready(), af_runner::runner_is_ready());
        (db_ready, if runner_ready { "ok" } else { "unreachable" })
    } else {
        (database_is_ready().await, "disabled")
    };

    let ready = db_ready && (!runner_enabled || runner_state == "ok");
    ReadinessStatus {
        http_status: if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        status: if ready { "ready" } else { "not_ready" },
        database: if db_ready { "ok" } else { "unreachable" },
        runner: runner_state,
    }
}

pub(super) async fn health_ready() -> Response {
    let readiness = evaluate_readiness().await;
    (
        readiness.http_status,
        Json(serde_json::json!({
            "database": readiness.database,
            "runner": readiness.runner,
            "redis": "disabled",
            "uptime": format!("{:.1}s", START_TIME.elapsed().as_secs_f64()),
            "status": readiness.status,
            "version": af_runner::af_release::runtime::runtime_identity().version,
        })),
    )
        .into_response()
}

pub(crate) async fn database_is_ready() -> bool {
    let ready = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::task::spawn_blocking(|| af_db::db_readiness_check().map(|_| ())),
    )
    .await;
    matches!(ready, Ok(Ok(Ok(()))))
}

pub(super) async fn authenticated_ready() -> Response {
    let readiness = evaluate_readiness().await;
    (
        readiness.http_status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "service": "aetherflow-api",
            "status": readiness.status,
            "database": readiness.database,
            "runner": readiness.runner,
        })),
    )
        .into_response()
}

pub(super) fn parse_forwarded_ip_token(raw: &str) -> Option<std::net::IpAddr> {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(sock) = trimmed.parse::<std::net::SocketAddr>() {
        return Some(sock.ip().to_canonical());
    }
    let clean = trimmed
        .strip_prefix('[')
        .and_then(|s| s.split_once(']').map(|(h, _)| h))
        .unwrap_or(trimmed);
    clean
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_canonical())
}

pub(super) fn forwarded_headers_exclusively_loopback(headers: &axum::http::HeaderMap) -> bool {
    let mut saw_any_client_ip = false;

    for val in headers.get_all("x-forwarded-for") {
        let Ok(raw) = val.to_str() else {
            return false;
        };
        for hop in raw.split(',') {
            let Some(ip) = parse_forwarded_ip_token(hop) else {
                return false;
            };
            if !ip.is_loopback() {
                return false;
            }
            saw_any_client_ip = true;
        }
    }

    for val in headers.get_all("x-real-ip") {
        let Ok(raw) = val.to_str() else {
            return false;
        };
        let Some(ip) = parse_forwarded_ip_token(raw) else {
            return false;
        };
        if !ip.is_loopback() {
            return false;
        }
        saw_any_client_ip = true;
    }

    for val in headers.get_all("forwarded") {
        let Ok(raw) = val.to_str() else {
            return false;
        };
        let mut saw_for_in_header = false;
        for element in raw.split(',') {
            for pair in element.split(';') {
                if let Some((k, v)) = pair.trim().split_once('=') {
                    if k.trim().eq_ignore_ascii_case("for") {
                        let Some(ip) = parse_forwarded_ip_token(v) else {
                            return false;
                        };
                        if !ip.is_loopback() {
                            return false;
                        }
                        saw_for_in_header = true;
                        saw_any_client_ip = true;
                    }
                }
            }
        }
        if !saw_for_in_header {
            return false;
        }
    }

    saw_any_client_ip
}

pub(super) async fn is_metrics_request_authorized(req: Request) -> bool {
    let (parts, _body) = req.into_parts();
    drop(_body);

    if env::var("METRICS_PUBLIC")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true"))
        .unwrap_or(false)
    {
        return true;
    }

    let peer_ip = parts
        .extensions
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::connect_info::ConnectInfo(addr)| addr.ip().to_canonical());
    let had_proxy_headers = parts
        .extensions
        .get::<crate::ws::InboundProxyForwarded>()
        .map(|f| f.0)
        .unwrap_or_else(|| {
            parts.headers.contains_key("x-forwarded-for")
                || parts.headers.contains_key("x-real-ip")
                || parts.headers.contains_key("forwarded")
        });

    if peer_ip.is_none_or(|ip| ip.is_loopback())
        && (!had_proxy_headers || forwarded_headers_exclusively_loopback(&parts.headers))
    {
        return true;
    }

    let bearer = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(presented) = bearer {
        if let Ok(expected) = env::var("METRICS_BEARER_TOKEN") {
            let expected = expected.trim();
            if !expected.is_empty()
                && af_models::constant_time_eq(presented.as_bytes(), expected.as_bytes())
            {
                return true;
            }
        }
    }

    let Some(raw_token) = crate::auth::resolve_raw_token(&parts.headers) else {
        return false;
    };
    let Ok(claims) = crate::auth::decode_session_claims(&raw_token, false) else {
        return false;
    };
    if !claims.plugin_id.trim().is_empty() || !claims.plugin_scopes.is_empty() {
        return false;
    }
    let ua = parts
        .headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let client_ip = extract_client_ip_for_peer(&parts.headers, peer_ip);
    let hdr_ip = extract_client_ip(&parts.headers);
    if !crate::auth::matches_client_fingerprint(&claims.cfp, &client_ip, &ua)
        && !crate::auth::matches_client_fingerprint(&claims.cfp, &hdr_ip, &ua)
    {
        return false;
    }
    crate::auth::blocking_auth_work(move || {
        if crate::auth::is_session_token_revoked_beyond_grace(&claims.jti, claims.user_id) {
            return false;
        }
        let Ok(conn) = af_db::get_read_conn() else {
            return false;
        };
        let Ok(subj) = crate::auth::load_active_human_subject(&conn, claims.user_id) else {
            return false;
        };
        if !subj.role.eq_ignore_ascii_case("admin") {
            return false;
        }
        if claims.ver < subj.sessions_revoked_after {
            return false;
        }
        if crate::auth::table_exists(&conn, "active_sessions").unwrap_or(false) {
            let resolved_jti = crate::auth::resolve_current_session_jti(&claims.jti);
            let session_exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM active_sessions WHERE user_id = ?1 AND (jti = ?2 OR jti = ?3))",
                    params![claims.user_id, claims.jti, resolved_jti],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            if !session_exists {
                return false;
            }
        }
        true
    })
    .await
    .unwrap_or(false)
}

pub(super) async fn prometheus_metrics(req: Request) -> Response {
    if !is_metrics_request_authorized(req).await {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    }

    let Ok(m) = tokio::task::spawn_blocking(af_hardware::get_system_metrics_core).await else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to collect system metrics",
        );
    };
    let mem_total_gb = m.memory.get("total").copied().unwrap_or(0.0);
    let mem_used_gb = m.memory.get("used").copied().unwrap_or(0.0);
    let mem_pct = if mem_total_gb > 0.0 {
        (mem_used_gb / mem_total_gb) * 100.0
    } else {
        0.0
    };
    let disk_total_gb = m.disk_space.get("total").copied().unwrap_or(0.0);
    let disk_used_gb = m.disk_space.get("used").copied().unwrap_or(0.0);
    let disk_pct = if disk_total_gb > 0.0 {
        (disk_used_gb / disk_total_gb) * 100.0
    } else {
        0.0
    };

    let version = af_runner::af_release::runtime::runtime_identity()
        .version
        .clone();
    let body = format!(
        "# HELP aetherflow_process_uptime_seconds Process uptime in seconds\n\
         # TYPE aetherflow_process_uptime_seconds gauge\n\
         aetherflow_process_uptime_seconds {:.2}\n\
         # HELP aetherflow_system_cpu_percent Host CPU usage percentage\n\
         # TYPE aetherflow_system_cpu_percent gauge\n\
         aetherflow_system_cpu_percent {:.2}\n\
         # HELP aetherflow_system_memory_total_bytes Total physical memory in bytes\n\
         # TYPE aetherflow_system_memory_total_bytes gauge\n\
         aetherflow_system_memory_total_bytes {:.0}\n\
         # HELP aetherflow_system_memory_used_bytes Used physical memory in bytes\n\
         # TYPE aetherflow_system_memory_used_bytes gauge\n\
         aetherflow_system_memory_used_bytes {:.0}\n\
         # HELP aetherflow_system_memory_percent Memory usage percentage\n\
         # TYPE aetherflow_system_memory_percent gauge\n\
         aetherflow_system_memory_percent {:.2}\n\
         # HELP aetherflow_system_disk_percent Root disk usage percentage\n\
         # TYPE aetherflow_system_disk_percent gauge\n\
         aetherflow_system_disk_percent {:.2}\n\
         # HELP aetherflow_build_info Build metadata\n\
         # TYPE aetherflow_build_info gauge\n\
         aetherflow_build_info{{runtime=\"rust\",version=\"{}\",os=\"{}\",arch=\"{}\"}} 1\n",
        START_TIME.elapsed().as_secs_f64(),
        m.cpu_usage,
        mem_total_gb * 1073741824.0,
        mem_used_gb * 1073741824.0,
        mem_pct,
        disk_pct,
        version,
        env::consts::OS,
        env::consts::ARCH
    );

    let mut resp = body.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    resp
}

pub(super) async fn get_openapi_spec() -> Response {
    let mut resp = OPENAPI_YAML.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/yaml; charset=utf-8"),
    );
    resp
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardware, Metrics, Services & Marketplace
// ─────────────────────────────────────────────────────────────────────────────

pub(super) async fn get_system_metrics() -> Json<af_models::SystemMetrics> {
    Json(af_hardware::get_system_metrics_core())
}

pub(super) async fn get_hardware_info() -> Json<af_models::HardwareReport> {
    Json(af_hardware::get_detailed_hardware())
}
