use super::ai_providers::{call_configured_ai, clean_json_fence, resolve_provider_settings};
use super::telemetry::get_system_metrics_context;
use crate::auth::api_error;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::Mutex;

pub async fn bandwidth_analyze() -> Response {
    let ps = resolve_provider_settings();
    let m = af_hardware::get_system_metrics_core();
    let active_services = match tokio::task::spawn_blocking(af_services::get_active_services)
        .await
        .map_err(anyhow::Error::from)
        .and_then(|services| services)
    {
        Ok(services) => services,
        Err(error) => {
            tracing::warn!(%error, "Bandwidth analysis service state unavailable");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "Service state is temporarily unavailable. Retry shortly."
                })),
            )
                .into_response();
        }
    };
    let live_streaming = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        crate::streaming_ext::build_streaming_dashboard("30", "all", "all", false),
    )
    .await
    .ok();
    let active_streams = live_streaming
        .as_ref()
        .map(|d| d.live_summary.active_streams)
        .unwrap_or(0);
    let active_transcodes = live_streaming
        .as_ref()
        .map(|d| d.live_summary.transcode_count)
        .unwrap_or(0);

    let mem_used = m.memory.get("used").copied().unwrap_or(0.0);
    let mem_total = m.memory.get("total").copied().unwrap_or(0.0);
    let mem_pct = if mem_total > 0.0 {
        (mem_used / mem_total) * 100.0
    } else {
        0.0
    };
    let disk_read_bps = m.disk_io.get("read_bytes_sec").copied().unwrap_or(0.0);
    let disk_write_bps = m.disk_io.get("write_bytes_sec").copied().unwrap_or(0.0);
    let disk_io_mb_s = (disk_read_bps + disk_write_bps) / (1024.0 * 1024.0);

    // Dynamic bandwidth calculation scaled by CPU, disk I/O, and active media streams
    let base_down_kbps: i64 = 102_400; // 100 MB/s baseline
    let base_up_kbps: i64 = 51_200; // 50 MB/s baseline

    let load_factor = if m.cpu_usage > 85.0 || disk_io_mb_s > 250.0 {
        0.45
    } else if m.cpu_usage > 65.0 || active_transcodes > 0 {
        0.70
    } else if m.cpu_usage < 25.0 && active_streams == 0 {
        1.25
    } else {
        1.0
    };

    let stream_headroom_kbps = (active_streams as i64) * 6_000 + (active_transcodes as i64) * 8_000;
    let recommended_download_kbps =
        (((base_down_kbps as f64) * load_factor) as i64 - stream_headroom_kbps).max(10_240);
    let recommended_upload_kbps =
        (((base_up_kbps as f64) * load_factor) as i64 - stream_headroom_kbps).max(5_120);

    let swarm_health = if m.cpu_usage > 85.0 || mem_pct > 90.0 || disk_io_mb_s > 250.0 {
        "congested"
    } else if m.cpu_usage < 25.0 && active_streams == 0 {
        "underutilized"
    } else {
        "healthy"
    };

    let mut suggestions = vec![
        "Maintain 20% egress headroom for Jellyfin direct-stream spikes".to_string(),
        "Enable alternative speed limits during active transcoding sessions".to_string(),
    ];
    if active_streams > 0 {
        suggestions.push(format!(
            "Reserved {} kbps egress headroom for {} active media stream(s)",
            stream_headroom_kbps, active_streams
        ));
    }
    if disk_io_mb_s > 100.0 {
        suggestions.push(format!(
            "Disk I/O throughput is {:.1} MB/s; throttle concurrent torrent writes to reduce seek contention",
            disk_io_mb_s
        ));
    }

    let prompt = format!(
        "Analyze the current server state and recommend optimal torrent bandwidth limits.\n\n{}\n\nActive Streams: {} (Transcodes: {})\nDisk I/O: {:.2} MB/s\n\nReturn a JSON object with these exact fields:\n- \"recommended_upload_kbps\": integer (in KB/s)\n- \"recommended_download_kbps\": integer (in KB/s)\n- \"reasoning\": string (1-2 sentences explaining why)\n- \"confidence\": float (0.0-1.0)\n- \"swarm_health\": string (\"healthy\", \"congested\", or \"underutilized\")\n- \"suggestions\": array of strings (2-3 actionable tips)\n\nOnly return valid JSON, no markdown fences.",
        get_system_metrics_context(),
        active_streams,
        active_transcodes,
        disk_io_mb_s
    );

    if let Ok(ai_text) = call_configured_ai(
        &ps,
        "You are an expert network traffic engineer for a media server running torrent clients alongside streaming services (Plex/Jellyfin).",
        &prompt,
    )
    .await
    {
        let cleaned = clean_json_fence(&ai_text);
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&cleaned) {
            if parsed.get("recommended_upload_kbps").is_some()
                && parsed.get("recommended_download_kbps").is_some()
            {
                return Json(parsed).into_response();
            }
        }
    }

    Json(serde_json::json!({
        "recommended_upload_kbps": recommended_upload_kbps,
        "recommended_download_kbps": recommended_download_kbps,
        "reasoning": format!(
            "Evaluated live CPU load ({:.1}%), memory utilization ({:.1}%), disk I/O ({:.1} MB/s), and {} active service(s) / {} active stream(s).",
            m.cpu_usage,
            mem_pct,
            disk_io_mb_s,
            active_services.len(),
            active_streams
        ),
        "confidence": 0.89,
        "swarm_health": swarm_health,
        "suggestions": suggestions,
    }))
    .into_response()
}

fn resolve_torrent_runtime_path(raw: &str) -> PathBuf {
    if let Ok(root) = env::var("AETHERFLOW_FS_ROOT") {
        let trimmed = root.trim();
        if !trimmed.is_empty() && trimmed != "/" {
            return PathBuf::from(trimmed).join(raw.trim_start_matches('/'));
        }
    }
    PathBuf::from(raw)
}

fn load_master_torrent_credentials() -> Option<(String, String)> {
    let creds_path = env::var("AETHERFLOW_MASTER_CREDS_FILE")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| resolve_torrent_runtime_path("/var/lib/aetherflow/.master.creds"));
    let raw = std::fs::read_to_string(creds_path).ok()?;
    let val: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let user = val.get("username")?.as_str()?.trim().to_string();
    let enc_pw = val.get("password")?.as_str()?.trim();
    if user.is_empty() || enc_pw.is_empty() {
        return None;
    }
    let pw = af_db::decrypt_secret_if_needed(enc_pw).ok()?;
    if pw.is_empty() {
        return None;
    }
    Some((user, pw))
}

pub(super) const TRANSMISSION_SETTINGS_CANDIDATES: [&str; 3] = [
    "/etc/transmission-daemon/settings.json",
    "/var/lib/transmission-daemon/info/settings.json",
    "/var/lib/transmission-daemon/.config/transmission-daemon/settings.json",
];

pub(super) fn load_transmission_rpc_credentials_from_paths(
    paths: &[PathBuf],
) -> Option<(String, String)> {
    for path in paths {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&contents) {
                let user = val
                    .get("rpc-username")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let pass = val
                    .get("rpc-password")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !user.is_empty() && !pass.is_empty() && !pass.starts_with('{') {
                    return Some((user, pass));
                }
            }
        }
    }
    None
}

fn load_transmission_rpc_credentials() -> Option<(String, String)> {
    if let Some(creds) = load_master_torrent_credentials() {
        return Some(creds);
    }
    let resolved: Vec<PathBuf> = TRANSMISSION_SETTINGS_CANDIDATES
        .iter()
        .map(|raw| resolve_torrent_runtime_path(raw))
        .collect();
    load_transmission_rpc_credentials_from_paths(&resolved)
}

fn resolve_torrent_client_port(client_name: &str, default_port: i32) -> i32 {
    if let Ok(Some(cfg)) = af_db::get_app_ingress_config(client_name) {
        if (1..=65535).contains(&cfg.listen_port) {
            return cfg.listen_port;
        }
    }
    let meta_port = af_services::mutators::get_app_runtime_meta(client_name).configured_port;
    if (1..=65535).contains(&meta_port) {
        return meta_port;
    }
    if let Some(bp) = af_services::get_blueprint(client_name) {
        if (1..=65535).contains(&bp.default_port) {
            return bp.default_port;
        }
    }
    default_port
}

#[derive(Clone, Debug)]
pub(super) struct TorrentRpcApplyError {
    pub(super) status: StatusCode,
    pub(super) code: &'static str,
    pub(super) message: String,
    pub(super) mutated: bool,
    pub(super) outcome_unknown: bool,
    pub(super) partial_apply: bool,
    pub(super) rollback_verified: Option<bool>,
}

impl TorrentRpcApplyError {
    fn unmutated(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            mutated: false,
            outcome_unknown: false,
            partial_apply: false,
            rollback_verified: None,
        }
    }

    fn unknown_outcome(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            mutated: true,
            outcome_unknown: true,
            partial_apply: false,
            rollback_verified: None,
        }
    }
}

pub(super) async fn apply_transmission_bandwidth_to_url(
    rpc_url: &str,
    upload_kbps: i64,
    download_kbps: i64,
    creds: Option<&(String, String)>,
) -> Result<String, TorrentRpcApplyError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|_| {
            TorrentRpcApplyError::unmutated(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to construct HTTP client",
            )
        })?;

    let down_enabled = download_kbps > 0;
    let up_enabled = upload_kbps > 0;
    let alt_enabled = down_enabled || up_enabled;
    let payload = serde_json::json!({
        "method": "session-set",
        "arguments": {
            "speed-limit-down": download_kbps,
            "speed-limit-down-enabled": down_enabled,
            "speed-limit-up": upload_kbps,
            "speed-limit-up-enabled": up_enabled,
            "alt-speed-down": download_kbps,
            "alt-speed-up": upload_kbps,
            "alt-speed-enabled": alt_enabled,
        }
    });

    let send_rpc = |session_id: Option<&str>| {
        let mut req = client.post(rpc_url).json(&payload);
        if let Some((user, pass)) = creds {
            req = req.basic_auth(user, Some(pass));
        }
        if let Some(sid) = session_id {
            req = req.header("X-Transmission-Session-Id", sid);
        }
        req.send()
    };

    let map_send_err = |err: reqwest::Error| {
        if !err.is_connect() {
            TorrentRpcApplyError::unknown_outcome(
                StatusCode::GATEWAY_TIMEOUT,
                "GATEWAY_TIMEOUT",
                "Transmission RPC timed out or reset after sending session-set; outcome is unknown",
            )
        } else {
            TorrentRpcApplyError::unmutated(
                StatusCode::GATEWAY_TIMEOUT,
                "GATEWAY_TIMEOUT",
                "Torrent daemon RPC timeout or unreachable",
            )
        }
    };

    let mut resp = send_rpc(None).await.map_err(map_send_err)?;

    if resp.status() == reqwest::StatusCode::CONFLICT {
        let session_id = resp
            .headers()
            .get("X-Transmission-Session-Id")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                TorrentRpcApplyError::unmutated(
                    StatusCode::BAD_GATEWAY,
                    "BAD_GATEWAY",
                    "Transmission 409 response missing X-Transmission-Session-Id header",
                )
            })?;
        resp = send_rpc(Some(&session_id)).await.map_err(map_send_err)?;
    }

    let status = resp.status();
    if status != reqwest::StatusCode::OK {
        return Err(TorrentRpcApplyError::unmutated(
            StatusCode::BAD_GATEWAY,
            "BAD_GATEWAY",
            "Torrent daemon rejected RPC request",
        ));
    }
    let text = resp.text().await.map_err(|_| {
        TorrentRpcApplyError::unknown_outcome(
            StatusCode::GATEWAY_TIMEOUT,
            "GATEWAY_TIMEOUT",
            "Transmission RPC connection reset while reading response; outcome is unknown",
        )
    })?;
    let parsed: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
        TorrentRpcApplyError::unknown_outcome(
            StatusCode::BAD_GATEWAY,
            "BAD_GATEWAY",
            "Transmission RPC returned malformed JSON after mutation; outcome is unknown",
        )
    })?;
    if parsed.get("result").and_then(|v| v.as_str()) != Some("success") {
        return Err(TorrentRpcApplyError::unmutated(
            StatusCode::BAD_GATEWAY,
            "BAD_GATEWAY",
            "Transmission RPC did not report result == \"success\"",
        ));
    }
    Ok(text)
}

fn extract_cookie_header(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let pairs: Vec<&str> = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|val| val.to_str().ok())
        .filter_map(|raw| raw.split(';').next().map(str::trim))
        .filter(|pair| !pair.is_empty() && pair.contains('='))
        .collect();
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.join("; "))
    }
}

static QBITTORRENT_MUTATION_LOCKS: Lazy<
    Mutex<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));

fn acquire_qbittorrent_endpoint_mutex(base: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    let key = base.trim().trim_end_matches('/').to_ascii_lowercase();
    let mut map = QBITTORRENT_MUTATION_LOCKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::sync::Arc::clone(
        map.entry(key)
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(()))),
    )
}

async fn read_qbittorrent_limit_bytes(
    client: &reqwest::Client,
    base: &str,
    path_suffix: &str,
    cookie_header: Option<&str>,
) -> Option<i64> {
    let mut req = client.get(format!("{base}{path_suffix}"));
    if let Some(cookie) = cookie_header {
        req = req.header(reqwest::header::COOKIE, cookie);
    }
    let resp = req.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text()
        .await
        .ok()
        .and_then(|t| t.trim().parse::<i64>().ok())
        .filter(|&v| v >= 0)
}

async fn rollback_and_verify_qbittorrent_limits(
    client: &reqwest::Client,
    base: &str,
    referer: &str,
    cookie_header: Option<&str>,
    prior_down_bytes: i64,
    prior_up_bytes: i64,
) -> bool {
    let down_str = prior_down_bytes.to_string();
    let up_str = prior_up_bytes.to_string();

    let mut rb_down = client
        .post(format!("{base}/api/v2/transfer/setDownloadLimit"))
        .header(reqwest::header::ORIGIN, base)
        .header(reqwest::header::REFERER, referer)
        .form(&[("limit", down_str.as_str())]);
    if let Some(cookie) = cookie_header {
        rb_down = rb_down.header(reqwest::header::COOKIE, cookie);
    }
    let rb_down_ok = matches!(rb_down.send().await, Ok(r) if r.status().is_success());

    let mut rb_up = client
        .post(format!("{base}/api/v2/transfer/setUploadLimit"))
        .header(reqwest::header::ORIGIN, base)
        .header(reqwest::header::REFERER, referer)
        .form(&[("limit", up_str.as_str())]);
    if let Some(cookie) = cookie_header {
        rb_up = rb_up.header(reqwest::header::COOKIE, cookie);
    }
    let _ = rb_up.send().await;

    let read_down = read_qbittorrent_limit_bytes(
        client,
        base,
        "/api/v2/transfer/downloadLimit",
        cookie_header,
    )
    .await;
    let read_up =
        read_qbittorrent_limit_bytes(client, base, "/api/v2/transfer/uploadLimit", cookie_header)
            .await;

    rb_down_ok && read_down == Some(prior_down_bytes) && read_up == Some(prior_up_bytes)
}

pub(super) async fn apply_qbittorrent_bandwidth_inner(
    base_url: &str,
    upload_kbps: i64,
    download_kbps: i64,
    creds: Option<&(String, String)>,
) -> Result<String, TorrentRpcApplyError> {
    let base = base_url.trim_end_matches('/');
    let endpoint_mutex = acquire_qbittorrent_endpoint_mutex(base);
    let _endpoint_guard = endpoint_mutex.lock().await;

    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|_| {
            TorrentRpcApplyError::unmutated(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to construct HTTP client",
            )
        })?;

    let referer = format!("{base}/");
    let mut cookie_header: Option<String> = None;
    if let Some((user, pass)) = creds {
        let login_resp = client
            .post(format!("{base}/api/v2/auth/login"))
            .header(reqwest::header::ORIGIN, base)
            .header(reqwest::header::REFERER, &referer)
            .form(&[("username", user.as_str()), ("password", pass.as_str())])
            .send()
            .await
            .map_err(|_| {
                TorrentRpcApplyError::unmutated(
                    StatusCode::GATEWAY_TIMEOUT,
                    "GATEWAY_TIMEOUT",
                    "qBittorrent WebUI timeout or unreachable",
                )
            })?;
        let login_status = login_resp.status();
        cookie_header = extract_cookie_header(login_resp.headers());
        let login_body = login_resp.text().await.unwrap_or_default();
        if !login_status.is_success() || login_body.trim() == "Fails." {
            return Err(TorrentRpcApplyError::unmutated(
                StatusCode::BAD_GATEWAY,
                "BAD_GATEWAY",
                "qBittorrent WebUI authentication failed",
            ));
        }
    }

    // Fail closed unless BOTH prior download and upload limits are read before mutating (NEVER default rollback to 0!).
    let Some(prior_down_bytes) = read_qbittorrent_limit_bytes(
        &client,
        base,
        "/api/v2/transfer/downloadLimit",
        cookie_header.as_deref(),
    )
    .await
    else {
        return Err(TorrentRpcApplyError::unmutated(
            StatusCode::BAD_GATEWAY,
            "BAD_GATEWAY",
            "Failed to read prior qBittorrent downloadLimit before mutation",
        ));
    };
    let Some(prior_up_bytes) = read_qbittorrent_limit_bytes(
        &client,
        base,
        "/api/v2/transfer/uploadLimit",
        cookie_header.as_deref(),
    )
    .await
    else {
        return Err(TorrentRpcApplyError::unmutated(
            StatusCode::BAD_GATEWAY,
            "BAD_GATEWAY",
            "Failed to read prior qBittorrent uploadLimit before mutation",
        ));
    };

    let down_bytes = if download_kbps <= 0 {
        "0".to_string()
    } else {
        download_kbps.saturating_mul(1024).to_string()
    };
    let up_bytes = if upload_kbps <= 0 {
        "0".to_string()
    } else {
        upload_kbps.saturating_mul(1024).to_string()
    };

    let mut down_req = client
        .post(format!("{base}/api/v2/transfer/setDownloadLimit"))
        .header(reqwest::header::ORIGIN, base)
        .header(reqwest::header::REFERER, &referer)
        .form(&[("limit", down_bytes.as_str())]);
    if let Some(ref cookie) = cookie_header {
        down_req = down_req.header(reqwest::header::COOKIE, cookie);
    }
    let down_resp = match down_req.send().await {
        Ok(resp) => resp,
        Err(err) if err.is_connect() => {
            return Err(TorrentRpcApplyError::unmutated(
                StatusCode::GATEWAY_TIMEOUT,
                "GATEWAY_TIMEOUT",
                "qBittorrent WebUI unreachable",
            ));
        }
        Err(_) => {
            let rb_verified = rollback_and_verify_qbittorrent_limits(
                &client,
                base,
                &referer,
                cookie_header.as_deref(),
                prior_down_bytes,
                prior_up_bytes,
            )
            .await;
            let detail = if rb_verified {
                format!(
                    "qBittorrent WebUI timed out or reset during setDownloadLimit (rollback_verified=true: verified downloadLimit={prior_down_bytes} B/s, uploadLimit={prior_up_bytes} B/s)"
                )
            } else {
                format!(
                    "qBittorrent WebUI timed out or reset during setDownloadLimit (outcome_unknown=true, rollback_verified=false: failed to verify downloadLimit={prior_down_bytes} B/s and uploadLimit={prior_up_bytes} B/s)"
                )
            };
            return Err(TorrentRpcApplyError {
                status: StatusCode::GATEWAY_TIMEOUT,
                code: "GATEWAY_TIMEOUT",
                message: detail,
                mutated: true,
                outcome_unknown: !rb_verified,
                partial_apply: !rb_verified,
                rollback_verified: Some(rb_verified),
            });
        }
    };
    if !down_resp.status().is_success() {
        return Err(TorrentRpcApplyError::unmutated(
            StatusCode::BAD_GATEWAY,
            "BAD_GATEWAY",
            "qBittorrent rejected setDownloadLimit",
        ));
    }

    let mut up_req = client
        .post(format!("{base}/api/v2/transfer/setUploadLimit"))
        .header(reqwest::header::ORIGIN, base)
        .header(reqwest::header::REFERER, &referer)
        .form(&[("limit", up_bytes.as_str())]);
    if let Some(ref cookie) = cookie_header {
        up_req = up_req.header(reqwest::header::COOKIE, cookie);
    }
    let up_outcome = match up_req.send().await {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(_) => Err((
            StatusCode::BAD_GATEWAY,
            "BAD_GATEWAY",
            "qBittorrent rejected setUploadLimit",
        )),
        Err(_) => Err((
            StatusCode::GATEWAY_TIMEOUT,
            "GATEWAY_TIMEOUT",
            "qBittorrent WebUI timeout during setUploadLimit",
        )),
    };

    if let Err((status, code, base_msg)) = up_outcome {
        let rb_verified = rollback_and_verify_qbittorrent_limits(
            &client,
            base,
            &referer,
            cookie_header.as_deref(),
            prior_down_bytes,
            prior_up_bytes,
        )
        .await;
        let detail = if rb_verified {
            format!(
                "{base_msg} (rollback_verified=true: restored downloadLimit to {prior_down_bytes} B/s and uploadLimit to {prior_up_bytes} B/s)"
            )
        } else {
            format!(
                "{base_msg} (partial_apply=true, outcome_unknown=true, rollback_verified=false: failed to verify restoration of downloadLimit={prior_down_bytes} B/s and uploadLimit={prior_up_bytes} B/s)"
            )
        };
        return Err(TorrentRpcApplyError {
            status,
            code,
            message: detail,
            mutated: true,
            outcome_unknown: !rb_verified,
            partial_apply: !rb_verified,
            rollback_verified: Some(rb_verified),
        });
    }

    Ok("ok".to_string())
}

pub(super) async fn apply_deluge_bandwidth_to_url(
    rpc_url: &str,
    upload_kbps: i64,
    download_kbps: i64,
    password: Option<&str>,
) -> Result<String, TorrentRpcApplyError> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|_| {
            TorrentRpcApplyError::unmutated(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to construct HTTP client",
            )
        })?;

    let mut cookie_header: Option<String> = None;
    if let Some(pw) = password {
        let login_resp = client
            .post(rpc_url)
            .json(&serde_json::json!({
                "method": "auth.login",
                "params": [pw],
                "id": 1
            }))
            .send()
            .await
            .map_err(|_| {
                TorrentRpcApplyError::unmutated(
                    StatusCode::GATEWAY_TIMEOUT,
                    "GATEWAY_TIMEOUT",
                    "Deluge WebUI timeout or unreachable",
                )
            })?;
        let login_status = login_resp.status();
        cookie_header = extract_cookie_header(login_resp.headers());
        let login_text = login_resp.text().await.unwrap_or_default();
        if !login_status.is_success() {
            return Err(TorrentRpcApplyError::unmutated(
                StatusCode::BAD_GATEWAY,
                "BAD_GATEWAY",
                "Deluge WebUI authentication failed",
            ));
        }
        let login_json: serde_json::Value = serde_json::from_str(&login_text).map_err(|_| {
            TorrentRpcApplyError::unmutated(
                StatusCode::BAD_GATEWAY,
                "BAD_GATEWAY",
                "Deluge auth.login returned malformed JSON-RPC response",
            )
        })?;
        let login_err_null = login_json.get("error").is_none_or(|e| e.is_null());
        let login_ok = login_json.get("result").and_then(|v| v.as_bool()) == Some(true);
        if !login_err_null || !login_ok {
            return Err(TorrentRpcApplyError::unmutated(
                StatusCode::BAD_GATEWAY,
                "BAD_GATEWAY",
                "Deluge WebUI authentication rejected credentials",
            ));
        }
    }

    let deluge_down: f64 = if download_kbps <= 0 {
        -1.0
    } else {
        download_kbps as f64
    };
    let deluge_up: f64 = if upload_kbps <= 0 {
        -1.0
    } else {
        upload_kbps as f64
    };
    let mut set_req = client.post(rpc_url).json(&serde_json::json!({
        "method": "core.set_config",
        "params": [{
            "max_download_speed": deluge_down,
            "max_upload_speed": deluge_up
        }],
        "id": 2
    }));
    if let Some(ref cookie) = cookie_header {
        set_req = set_req.header(reqwest::header::COOKIE, cookie);
    }
    let set_resp = set_req.send().await.map_err(|err| {
        if !err.is_connect() {
            TorrentRpcApplyError::unknown_outcome(
                StatusCode::GATEWAY_TIMEOUT,
                "GATEWAY_TIMEOUT",
                "Deluge WebUI timed out or reset after sending core.set_config; outcome is unknown",
            )
        } else {
            TorrentRpcApplyError::unmutated(
                StatusCode::GATEWAY_TIMEOUT,
                "GATEWAY_TIMEOUT",
                "Deluge WebUI timeout or unreachable",
            )
        }
    })?;
    let status = set_resp.status();
    if !status.is_success() {
        return Err(TorrentRpcApplyError::unmutated(
            StatusCode::BAD_GATEWAY,
            "BAD_GATEWAY",
            "Deluge WebUI rejected RPC request",
        ));
    }
    let text = set_resp.text().await.map_err(|_| {
        TorrentRpcApplyError::unknown_outcome(
            StatusCode::GATEWAY_TIMEOUT,
            "GATEWAY_TIMEOUT",
            "Deluge WebUI connection reset while reading core.set_config response; outcome is unknown",
        )
    })?;
    let set_json: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
        TorrentRpcApplyError::unknown_outcome(
            StatusCode::BAD_GATEWAY,
            "BAD_GATEWAY",
            "Deluge core.set_config returned malformed JSON-RPC response after mutation",
        )
    })?;
    if !set_json.get("error").is_none_or(|e| e.is_null()) {
        return Err(TorrentRpcApplyError::unmutated(
            StatusCode::BAD_GATEWAY,
            "BAD_GATEWAY",
            "Deluge core.set_config returned a JSON-RPC error",
        ));
    }
    Ok(text)
}

pub async fn bandwidth_apply(Json(req): Json<serde_json::Value>) -> Response {
    let upload_kbps = req.get("upload_kbps").and_then(|v| v.as_i64()).unwrap_or(0);
    let download_kbps = req
        .get("download_kbps")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if upload_kbps < 0 || download_kbps < 0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "upload_kbps and download_kbps must be non-negative",
        );
    }

    let raw_client = req
        .get("client")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("auto")
        .to_ascii_lowercase();
    if !matches!(
        raw_client.as_str(),
        "" | "auto" | "transmission" | "qbittorrent" | "deluge"
    ) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Unsupported torrent client. Allowed: auto, transmission, qbittorrent, deluge",
        );
    }

    let candidates: Vec<&'static str> = match raw_client.as_str() {
        "transmission" => vec!["transmission"],
        "qbittorrent" => vec!["qbittorrent"],
        "deluge" => vec!["deluge"],
        _ => {
            let active = tokio::task::spawn_blocking(af_services::get_active_services)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default();
            let mut order = Vec::new();
            for (name, aliases) in [
                ("transmission", &["transmission", "transmission-daemon"][..]),
                ("qbittorrent", &["qbittorrent", "qbittorrent-nox"][..]),
                ("deluge", &["deluge", "deluged", "deluge-web"][..]),
            ] {
                let is_running = active.iter().any(|(label, item)| {
                    item.status == "running"
                        && aliases.iter().any(|alias| {
                            label.eq_ignore_ascii_case(alias)
                                || item.id.eq_ignore_ascii_case(alias)
                                || item.process.eq_ignore_ascii_case(alias)
                        })
                });
                if is_running {
                    order.push(name);
                }
            }
            for fallback in ["transmission", "qbittorrent", "deluge"] {
                if !order.contains(&fallback) {
                    order.push(fallback);
                }
            }
            order
        }
    };

    let mut last_err = TorrentRpcApplyError::unmutated(
        StatusCode::GATEWAY_TIMEOUT,
        "GATEWAY_TIMEOUT",
        "Torrent daemon RPC timeout or unreachable",
    );

    for client_name in candidates {
        let outcome: Result<String, TorrentRpcApplyError> = match client_name {
            "transmission" => {
                let port = resolve_torrent_client_port("transmission", 9091);
                let creds = load_transmission_rpc_credentials();
                let url = format!("http://127.0.0.1:{port}/transmission/rpc");
                apply_transmission_bandwidth_to_url(
                    &url,
                    upload_kbps,
                    download_kbps,
                    creds.as_ref(),
                )
                .await
            }
            "qbittorrent" => {
                let port = resolve_torrent_client_port("qbittorrent", 8180);
                let creds = load_master_torrent_credentials();
                let url = format!("http://127.0.0.1:{port}");
                apply_qbittorrent_bandwidth_inner(&url, upload_kbps, download_kbps, creds.as_ref())
                    .await
            }
            "deluge" => {
                let port = resolve_torrent_client_port("deluge", 8112);
                let creds = load_master_torrent_credentials();
                let pw = creds.as_ref().map(|(_, p)| p.as_str());
                let url = format!("http://127.0.0.1:{port}/json");
                apply_deluge_bandwidth_to_url(&url, upload_kbps, download_kbps, pw).await
            }
            _ => continue,
        };

        match outcome {
            Ok(rpc_text) => {
                return Json(serde_json::json!({
                    "message": format!("Limits applied successfully to {} via RPC", client_name),
                    "client": client_name,
                    "applied_client": client_name,
                    "upload_kbps": upload_kbps,
                    "download_kbps": download_kbps,
                    "upload_limit_kbps": upload_kbps,
                    "download_limit_kbps": download_kbps,
                    "rpc_response": rpc_text,
                }))
                .into_response();
            }
            Err(err) => {
                let stop_fallback = err.mutated || err.outcome_unknown;
                last_err = err;
                if stop_fallback {
                    // Never fall through in auto mode to mutate a second client while the first client's state is mutated or uncertain!
                    break;
                }
            }
        }
    }

    if last_err.outcome_unknown || last_err.partial_apply || last_err.rollback_verified.is_some() {
        return (
            last_err.status,
            Json(serde_json::json!({
                "error": {
                    "code": last_err.code,
                    "message": last_err.message,
                    "outcome_unknown": last_err.outcome_unknown,
                    "partial_apply": last_err.partial_apply,
                    "rollback_verified": last_err.rollback_verified,
                }
            })),
        )
            .into_response();
    }

    api_error(last_err.status, last_err.code, last_err.message)
}
