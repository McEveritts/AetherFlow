use super::proxy::{extract_client_ip_for_peer, is_trusted_proxy_peer};
use super::telemetry::package_diagnostics_allowed;
use super::tickets::{
    classify_revocation_recv, consume_live_ws_ticket_for_context, current_ws_authorization,
    current_ws_authorization_ex, ticket_client_ip_matches, PeerIp, RevocationWakeOutcome,
    WsPeerBinding, WsPeerScope, WsTicketEntry, WsTicketQuery,
};
use crate::auth::{AuthUser, PeerPrincipal};
use crate::peers::{PeerListenerRuntime, PeerRuntime, PeerWsPermit};
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::extract::{Extension, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;
use std::time::{Duration, Instant};
use tokio::time::MissedTickBehavior;

#[derive(Deserialize, Default, Clone)]
struct WsLogFilter {
    #[serde(default)]
    source: String,
    #[serde(default)]
    unit: String,
    #[serde(default)]
    priority: String,
    #[serde(default)]
    keyword: String,
}

fn parse_live_log_line(line: &str, default_source: &str) -> serde_json::Value {
    let trimmed = line.trim();
    // Format from `journalctl -o short-iso`: `<ISO-timestamp> <host> <unit>[pid]: <message>`
    let mut parts = trimmed.splitn(3, ' ');
    let first = parts.next().unwrap_or("");
    let (timestamp, host, remainder) = if first.len() >= 19 && first.contains('T') {
        let host = parts.next().unwrap_or("localhost");
        let rest = parts.next().unwrap_or(trimmed);
        (first.to_string(), host.to_string(), rest)
    } else {
        (
            chrono::Utc::now().to_rfc3339(),
            "localhost".to_string(),
            trimmed,
        )
    };

    let (unit, message) = if let Some((prefix, msg)) = remainder.split_once(": ") {
        let clean_unit = prefix.split('[').next().unwrap_or(prefix).trim();
        (clean_unit.to_string(), msg.to_string())
    } else {
        ("system".to_string(), remainder.to_string())
    };

    let lower = message.to_lowercase();
    let priority = if lower.contains("error") || lower.contains("fatal") || lower.contains("failed")
    {
        "err"
    } else if lower.contains("warn") {
        "warning"
    } else {
        "info"
    };

    let safe_message = af_services::redact_secrets(&message);
    serde_json::json!({
        "timestamp": timestamp,
        "source": default_source,
        "unit": unit,
        "priority": priority,
        "message": safe_message,
        "hostname": host,
    })
}

fn log_entry_matches_filter(entry: &serde_json::Value, filter: &WsLogFilter) -> bool {
    if !filter.source.is_empty() {
        let src = entry.get("source").and_then(|v| v.as_str()).unwrap_or("");
        if !src.eq_ignore_ascii_case(filter.source.trim()) {
            return false;
        }
    }
    if !filter.unit.is_empty() {
        let unit = entry
            .get("unit")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .trim_end_matches(".service");
        let f_unit = filter.unit.trim().trim_end_matches(".service");
        if !unit.eq_ignore_ascii_case(f_unit) {
            return false;
        }
    }
    if !filter.priority.is_empty() {
        let prio = entry.get("priority").and_then(|v| v.as_str()).unwrap_or("");
        if !prio.eq_ignore_ascii_case(filter.priority.trim()) {
            return false;
        }
    }
    if !filter.keyword.is_empty() {
        let msg = entry
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        if !msg.contains(&filter.keyword.trim().to_lowercase()) {
            return false;
        }
    }
    true
}

fn is_valid_ws_host_authority(raw_host: &str) -> bool {
    let trimmed = raw_host.trim();
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed.bytes().any(|b| b <= 0x20 || b >= 0x7f)
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('@')
    {
        return false;
    }
    if trimmed.starts_with('[') {
        let Some((ipv6, rest)) = trimmed.strip_prefix('[').and_then(|s| s.split_once(']')) else {
            return false;
        };
        if ipv6.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        return rest.is_empty()
            || rest
                .strip_prefix(':')
                .is_some_and(|p| p.parse::<u16>().is_ok());
    }
    let (host, port) = trimmed
        .split_once(':')
        .map_or((trimmed, None), |(h, p)| (h, Some(p)));
    if let Some(p) = port {
        if p.parse::<u16>().is_err() {
            return false;
        }
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

pub(crate) fn websocket_origin_matches_host(
    headers: &HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
    cookie_authenticated: bool,
) -> bool {
    let Some(origin_hv) = headers.get(axum::http::header::ORIGIN) else {
        // Non-browser Bearer/ticket clients do not send Origin; browser cookie upgrades must.
        return !cookie_authenticated;
    };
    let Ok(origin_raw) = origin_hv.to_str() else {
        return false;
    };
    let Ok(origin_url) = url::Url::parse(origin_raw.trim()) else {
        return false;
    };
    if !origin_url.username().is_empty()
        || origin_url.password().is_some()
        || origin_url.query().is_some()
        || origin_url.fragment().is_some()
        || origin_url.path() != "/"
    {
        return false;
    }
    let origin_scheme = match origin_url.scheme() {
        "http" | "ws" => "http",
        "https" | "wss" => "https",
        _ => return false,
    };
    let Some(origin_host) = origin_url
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
    else {
        return false;
    };
    let Some(origin_port) = origin_url.port_or_known_default() else {
        return false;
    };

    let trust_forwarded = peer_ip.is_none_or(is_trusted_proxy_peer);
    let expected_scheme = if trust_forwarded {
        if let Some(proto) = headers
            .get("X-Forwarded-Proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            if proto.eq_ignore_ascii_case("https") {
                "https"
            } else if proto.eq_ignore_ascii_case("http") {
                "http"
            } else {
                return false;
            }
        } else if headers
            .get("X-Forwarded-Port")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .is_some_and(|p| p.trim() == "443")
        {
            "https"
        } else {
            "http"
        }
    } else {
        "http"
    };

    let forwarded_host = if trust_forwarded {
        headers
            .get("X-Forwarded-Host")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
    } else {
        None
    };
    let Some(raw_request_host) = forwarded_host.or_else(|| {
        headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
    }) else {
        return false;
    };
    if !is_valid_ws_host_authority(raw_request_host) {
        return false;
    }
    let Ok(mut expected_url) = url::Url::parse(&format!("{expected_scheme}://{raw_request_host}"))
    else {
        return false;
    };
    if trust_forwarded && expected_url.port().is_none() {
        if let Some(xf_port) = headers
            .get("X-Forwarded-Port")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|p| p.trim().parse::<u16>().ok())
            .filter(|p| *p > 0)
        {
            if expected_url.set_port(Some(xf_port)).is_err() {
                return false;
            }
        }
    }
    let Some(expected_host) = expected_url
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
    else {
        return false;
    };
    let Some(expected_port) = expected_url.port_or_known_default() else {
        return false;
    };

    if origin_scheme == expected_scheme
        && origin_host == expected_host
        && origin_port == expected_port
    {
        return true;
    }

    if let Ok(allowed_cors) = std::env::var("ALLOWED_CORS_ORIGIN") {
        for candidate in allowed_cors
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != "*")
        {
            if let Ok(allowed_url) = url::Url::parse(candidate) {
                let allowed_scheme = allowed_url.scheme();
                let allowed_host = allowed_url
                    .host_str()
                    .map(|h| h.trim_end_matches('.').to_ascii_lowercase());
                let allowed_port = allowed_url.port_or_known_default();
                if allowed_scheme == origin_scheme
                    && allowed_host.as_deref() == Some(origin_host.as_str())
                    && allowed_port == Some(origin_port)
                {
                    return true;
                }
            }
        }
    }

    false
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_log_websocket(
    Extension(user): Extension<AuthUser>,
    Query(q): Query<WsTicketQuery>,
    peer: Option<Extension<PeerPrincipal>>,
    peer_runtime: Option<Extension<PeerListenerRuntime>>,
    peer_ws_permit: Option<Extension<PeerWsPermit>>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !package_diagnostics_allowed(&user) {
        return crate::auth::api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }

    let peer_principal = peer.map(|Extension(p)| p);
    let client_ip = extract_client_ip_for_peer(&headers, peer_ip);

    let mut authorization = if let Some(principal) = peer_principal {
        if user.user_id <= 0
            || user.user_id != principal.run_as_user_id
            || !principal.access.services.allows_read()
        {
            return crate::auth::api_error(
                StatusCode::FORBIDDEN,
                "PEER_SCOPE_DENIED",
                "Peer live logs require an active services:read grant",
            );
        }
        let runtime = peer_runtime
            .map(|Extension(r)| r.0)
            .unwrap_or_else(PeerRuntime::global);
        if !q.ticket.is_empty() {
            let Some(entry) = consume_live_ws_ticket_for_context(
                &q.ticket,
                Some(&principal),
                Some(runtime),
                None,
                WsPeerScope::Logs,
            )
            .await
            else {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "code": "WS_INVALID_TICKET",
                        "message": "Invalid or expired ticket"
                    })),
                )
                    .into_response();
            };
            if !ticket_client_ip_matches(&entry.client_ip, &client_ip) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "code": "WS_IP_MISMATCH",
                        "message": "Ticket IP mismatch"
                    })),
                )
                    .into_response();
            }
            entry
        } else {
            WsTicketEntry {
                user_id: principal.run_as_user_id,
                session_jti: format!("peer-grant:{}", principal.grant_id),
                session_ver: None,
                client_ip,
                expires_at: Instant::now(),
                diagnostics_allowed: true,
                peer: Some(WsPeerBinding {
                    link_id: principal.link_id,
                    grant_id: principal.grant_id,
                    run_as_user_id: principal.run_as_user_id,
                    access: principal.access,
                }),
                peer_runtime: Some(runtime),
            }
        }
    } else {
        let cookie_authenticated = headers.contains_key(axum::http::header::COOKIE)
            && !headers.contains_key(axum::http::header::AUTHORIZATION);
        if !websocket_origin_matches_host(&headers, peer_ip, cookie_authenticated) {
            return crate::auth::api_error(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Cross-origin WebSocket upgrade rejected",
            );
        }
        if !q.ticket.is_empty() {
            let Some(entry) = consume_live_ws_ticket_for_context(
                &q.ticket,
                None,
                None,
                Some(user.user_id),
                WsPeerScope::Logs,
            )
            .await
            else {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "code": "WS_INVALID_TICKET",
                        "message": "Invalid or expired ticket"
                    })),
                )
                    .into_response();
            };
            if !entry.diagnostics_allowed {
                return crate::auth::api_error(
                    StatusCode::FORBIDDEN,
                    "FORBIDDEN",
                    "Admin access required",
                );
            }
            if !ticket_client_ip_matches(&entry.client_ip, &client_ip) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "code": "WS_IP_MISMATCH",
                        "message": "Ticket IP mismatch"
                    })),
                )
                    .into_response();
            }
            entry
        } else {
            let effective_jti = if user.jti.trim().is_empty() {
                let mut nonce = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
                format!("ws-anon-{}", hex::encode(nonce))
            } else {
                user.jti.clone()
            };
            WsTicketEntry {
                user_id: user.user_id,
                session_jti: effective_jti,
                session_ver: None,
                client_ip,
                expires_at: Instant::now(),
                diagnostics_allowed: true,
                peer: None,
                peer_runtime: None,
            }
        }
    };

    // Subscribe to peer revocations BEFORE entering `on_upgrade` so revocations between upgrade
    // acceptance and stream startup cannot be missed; immediate recheck runs inside `on_upgrade`.
    let mut revocation_rx = authorization
        .peer_runtime
        .as_ref()
        .map(|rt| rt.subscribe_revocations());
    let held_ws_permit = peer_ws_permit.and_then(|Extension(p)| p.take());
    let is_peer = authorization.peer.is_some();

    ws.max_message_size(64 * 1024)
        .max_frame_size(16 * 1024)
        .on_upgrade(move |mut socket| async move {
            let _held_ws_permit = held_ws_permit;
            // Upgrading a connection does not grant a lasting raw-log capability.
            let initial_allowed = if is_peer {
                current_ws_authorization_ex(&mut authorization, WsPeerScope::Logs)
                    .await
                    .is_some()
            } else {
                current_ws_authorization(&mut authorization).await == Some(true)
            };
            if !initial_allowed {
                let _ = socket.send(Message::Close(None)).await;
                return;
            }
            let welcome = serde_json::json!({
                "type": "LOG_ENTRY",
                "data": {
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "source": "aetherflow-api",
                    "unit": "aetherflow-api.service",
                    "priority": "info",
                    "message": "Connected to AetherFlow Rust log stream"
                }
            });
            if let Ok(txt) = serde_json::to_string(&welcome) {
                if socket.send(Message::Text(txt)).await.is_err() {
                    return;
                }
            }

            let (tx, mut rx) = tokio::sync::mpsc::channel::<serde_json::Value>(128);
            let reader_task = tokio::spawn(async move {
                use std::process::Stdio;
                use tokio::io::{AsyncBufReadExt, BufReader};
                use tokio::process::Command;

                // Try journalctl first on Linux, then fall back to tailing system/deploy log files
                let mut spawned: Option<(tokio::process::Child, &'static str)> = None;
                if cfg!(target_os = "linux") {
                    if let Ok(child) = Command::new("journalctl")
                        .args(["-f", "-n", "50", "--no-pager", "-o", "short-iso"])
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .kill_on_drop(true)
                        .spawn()
                    {
                        spawned = Some((child, "journald"));
                    }
                }

                if let Some((mut child, source_name)) = spawned {
                    if let Some(stdout) = child.stdout.take() {
                        let mut lines = BufReader::new(stdout).lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            if line.trim().is_empty() {
                                continue;
                            }
                            let entry = parse_live_log_line(&line, source_name);
                            if tx.send(entry).await.is_err() {
                                break;
                            }
                        }
                    }
                    let _ = child.kill().await;
                } else {
                    let fallback_files = [
                        ("/var/log/aetherflow/deploy.log", "deploy"),
                        ("/var/log/aetherflow-deploy.log", "deploy"),
                        ("/var/log/syslog", "syslog"),
                        ("/var/log/messages", "syslog"),
                    ];
                    let mut opened_fallback: Option<(std::fs::File, &'static str)> = None;
                    for (path_str, source_name) in fallback_files {
                        if let Some(file) =
                            open_confined_live_log_file(std::path::Path::new(path_str))
                        {
                            opened_fallback = Some((file, source_name));
                            break;
                        }
                    }
                    if let Some((std_file, source_name)) = opened_fallback {
                        tail_open_log_file_to_channel(std_file, source_name, &tx).await;
                    } else {
                        // Keep channel alive if no external log source binary or confined log file is available
                        std::future::pending::<()>().await;
                    }
                }
            });

            let mut filter = WsLogFilter::default();
            let mut ping_interval = tokio::time::interval(Duration::from_secs(54));
            ping_interval.tick().await;
            let mut auth_interval = tokio::time::interval(if is_peer {
                Duration::from_millis(500)
            } else {
                Duration::from_secs(5)
            });
            auth_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            auth_interval.tick().await;

            loop {
                tokio::select! {
                    recv = async {
                        match revocation_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        if let Some(ref binding) = authorization.peer {
                            match classify_revocation_recv(recv, binding) {
                                RevocationWakeOutcome::CloseNow => {
                                    let _ = socket.send(Message::Close(None)).await;
                                    break;
                                }
                                RevocationWakeOutcome::RecheckDb => {
                                    if current_ws_authorization_ex(&mut authorization, WsPeerScope::Logs)
                                        .await
                                        .is_none()
                                    {
                                        let _ = socket.send(Message::Close(None)).await;
                                        break;
                                    }
                                }
                                RevocationWakeOutcome::Ignore => {}
                            }
                        }
                    }
                    msg_opt = socket.recv() => {
                        match msg_opt {
                            Some(Ok(Message::Text(text))) => {
                                if let Ok(new_filter) = serde_json::from_str::<WsLogFilter>(&text) {
                                    filter = new_filter;
                                }
                            }
                            Some(Ok(Message::Ping(payload))) => {
                                if socket.send(Message::Pong(payload)).await.is_err() {
                                    break;
                                }
                            }
                            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                                break;
                            }
                            _ => {}
                        }
                    }
                    _ = auth_interval.tick() => {
                        let still_allowed = if is_peer {
                            current_ws_authorization_ex(&mut authorization, WsPeerScope::Logs)
                                .await
                                .is_some()
                        } else {
                            current_ws_authorization(&mut authorization).await == Some(true)
                        };
                        if !still_allowed {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Some(entry) = rx.recv() => {
                        let still_allowed = if is_peer {
                            current_ws_authorization_ex(&mut authorization, WsPeerScope::Logs)
                                .await
                                .is_some()
                        } else {
                            current_ws_authorization(&mut authorization).await == Some(true)
                        };
                        if !still_allowed {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                        if !log_entry_matches_filter(&entry, &filter) {
                            continue;
                        }
                        let payload = serde_json::json!({
                            "type": "LOG_ENTRY",
                            "data": entry,
                        });
                        if let Ok(txt) = serde_json::to_string(&payload) {
                            if socket.send(Message::Text(txt)).await.is_err() {
                                break;
                            }
                        }
                    }
                    _ = ping_interval.tick() => {
                        let still_allowed = if is_peer {
                            current_ws_authorization_ex(&mut authorization, WsPeerScope::Logs)
                                .await
                                .is_some()
                        } else {
                            current_ws_authorization(&mut authorization).await == Some(true)
                        };
                        if !still_allowed {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                        if socket.send(Message::Ping(Vec::new())).await.is_err() {
                            break;
                        }
                    }
                }
            }

            reader_task.abort();
            let _ = reader_task.await;
        })
}

pub(super) fn open_confined_live_log_file(path: &std::path::Path) -> Option<std::fs::File> {
    let mut current = std::path::PathBuf::new();
    for component in path.parent()?.components() {
        current.push(component);
        let meta = std::fs::symlink_metadata(&current).ok()?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return None;
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return None;
        }
        unsafe {
            let flags = libc::fcntl(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::F_GETFL);
            if flags >= 0 {
                let _ = libc::fcntl(
                    std::os::unix::io::AsRawFd::as_raw_fd(&file),
                    libc::F_SETFL,
                    flags & !libc::O_NONBLOCK,
                );
            }
        }
    }
    Some(file)
}

async fn tail_open_log_file_to_channel(
    std_file: std::fs::File,
    source_name: &'static str,
    tx: &tokio::sync::mpsc::Sender<serde_json::Value>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};
    let mut file = tokio::fs::File::from_std(std_file);
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let start_offset = len.saturating_sub(64 * 1024);
    let _ = file.seek(std::io::SeekFrom::Start(start_offset)).await;
    let mut initial_buf = Vec::new();
    let _ = file.read_to_end(&mut initial_buf).await;
    let mut pos = start_offset + initial_buf.len() as u64;
    let initial_text = String::from_utf8_lossy(&initial_buf);
    let mut initial_lines: Vec<&str> = initial_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    if start_offset > 0 && !initial_lines.is_empty() {
        initial_lines.remove(0);
    }
    let skip = initial_lines.len().saturating_sub(50);
    for line in initial_lines.into_iter().skip(skip) {
        if tx
            .send(parse_live_log_line(line, source_name))
            .await
            .is_err()
        {
            return;
        }
    }
    let mut reader = BufReader::new(file);
    let mut line_buf = String::new();
    let mut poll = tokio::time::interval(Duration::from_millis(250));
    poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tx.closed() => break,
            _ = poll.tick() => {
                if let Ok(meta) = reader.get_ref().metadata().await {
                    if meta.len() < pos {
                        let _ = reader.seek(std::io::SeekFrom::Start(0)).await;
                        pos = 0;
                    }
                }
                loop {
                    line_buf.clear();
                    match reader.read_line(&mut line_buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            pos = pos.saturating_add(n as u64);
                            let trimmed = line_buf.trim_end_matches(['\r', '\n']);
                            if !trimmed.trim().is_empty()
                                && tx.send(parse_live_log_line(trimmed, source_name)).await.is_err()
                            {
                                return;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }
}
