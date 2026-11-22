use super::auth::{
    authorize_cluster_control_plane, constant_time_eq, verify_cluster_psk, PeerTransportAuth,
};
use super::commands::{
    acknowledge_worker_command, enqueue_cluster_command_with_action, get_cached_worker_metrics,
    list_cluster_commands, normalize_cluster_command, queue_worker_command_checked,
    truncate_diagnostic_utf8, ClusterCommandEnqueueError,
};
use super::grpc::{
    build_grpc_trailers, cached_snapshot_to_proto_metrics, decode_proto_command_request,
    decode_proto_heartbeat_ping, decode_proto_metrics_request, decode_proto_register_request,
    encode_grpc_data_frame, encode_proto_command_response, encode_proto_heartbeat_pong,
    encode_proto_metrics_response, encode_proto_register_response, extract_psk_from_headers,
    grpc_error_response, grpc_unary_ok_response, heartbeat_request_from_proto, inspect_mtls_peer,
    ClusterBody, GrpcError, GrpcFrameDecoder,
};
use super::membership::{
    is_enrolled_cluster_node, process_worker_heartbeat_with_peer, register_worker_node_with_peer,
};
use super::transport::{
    MasterTransportSecurity, HTTP2_KEEP_ALIVE_INTERVAL, HTTP2_KEEP_ALIVE_TIMEOUT,
    HTTP_HEADER_READ_TIMEOUT, MAX_JSON_BODY_BYTES, MAX_PREAUTH_HEADER_BYTES, TLS_HANDSHAKE_TIMEOUT,
};
use super::types::{
    PendingWorkerCommand, RegisterWorkerRequest, WorkerCommandAckRequest, WorkerHeartbeatRequest,
};
use anyhow::Context;
use axum::body::Bytes;
use axum::http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use rusqlite::params;
use std::convert::Infallible;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

async fn handle_grpc_request(
    path: &str,
    header_psk: String,
    incoming: Incoming,
    peer_auth: PeerTransportAuth,
) -> Response<ClusterBody> {
    match path {
        "/cluster.ClusterService/RegisterWorker" => {
            let mut decoder = GrpcFrameDecoder::new(incoming);
            let payload = match decoder.next_message().await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    return grpc_error_response(GrpcError::invalid_argument(
                        "missing RegisterRequest frame",
                    ))
                }
                Err(err) => return grpc_error_response(err),
            };
            let mut req = match decode_proto_register_request(&payload) {
                Ok(parsed) => parsed,
                Err(e) => return grpc_error_response(GrpcError::invalid_argument(e.to_string())),
            };
            if req.psk.is_empty() && !header_psk.is_empty() {
                req.psk = header_psk;
            }
            match register_worker_node_with_peer(&req, &peer_auth) {
                Ok(resp) => {
                    let encoded = encode_proto_register_response(&resp);
                    grpc_unary_ok_response(&encoded)
                }
                Err(e) => {
                    grpc_error_response(GrpcError::internal(format!("enrollment failed: {}", e)))
                }
            }
        }
        "/cluster.ClusterService/Heartbeat" => {
            let (tx, rx) = mpsc::channel(16);
            tokio::spawn(async move {
                let mut decoder = GrpcFrameDecoder::new(incoming);
                loop {
                    match decoder.next_message().await {
                        Ok(Some(payload)) => {
                            let ping = match decode_proto_heartbeat_ping(&payload) {
                                Ok(p) => p,
                                Err(e) => {
                                    let _ = tx
                                        .send(Ok(Frame::trailers(build_grpc_trailers(
                                            3,
                                            Some(&e.to_string()),
                                        ))))
                                        .await;
                                    return;
                                }
                            };
                            let hb_req = heartbeat_request_from_proto(ping, &header_psk);
                            match process_worker_heartbeat_with_peer(&hb_req, &peer_auth) {
                                Ok(pong) => {
                                    let encoded = encode_proto_heartbeat_pong(&pong);
                                    if tx
                                        .send(Ok(Frame::data(encode_grpc_data_frame(&encoded))))
                                        .await
                                        .is_err()
                                    {
                                        return;
                                    }
                                }
                                Err(e) => {
                                    let _ = tx
                                        .send(Ok(Frame::trailers(build_grpc_trailers(
                                            16,
                                            Some(&e.to_string()),
                                        ))))
                                        .await;
                                    return;
                                }
                            }
                        }
                        Ok(None) => {
                            let _ = tx
                                .send(Ok(Frame::trailers(build_grpc_trailers(0, None))))
                                .await;
                            return;
                        }
                        Err(err) => {
                            let _ = tx
                                .send(Ok(Frame::trailers(build_grpc_trailers(
                                    err.code,
                                    Some(&err.message),
                                ))))
                                .await;
                            return;
                        }
                    }
                }
            });
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/grpc")
                .body(ClusterBody::Grpc(rx))
                .unwrap()
        }
        "/cluster.ClusterService/GetMetrics" => {
            let mut decoder = GrpcFrameDecoder::new(incoming);
            let payload = match decoder.next_message().await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => Vec::new(),
                Err(err) => return grpc_error_response(err),
            };
            let req = match decode_proto_metrics_request(&payload) {
                Ok(parsed) => parsed,
                Err(e) => return grpc_error_response(GrpcError::invalid_argument(e.to_string())),
            };
            if let Err(msg) = authorize_cluster_control_plane(&header_psk, &peer_auth) {
                return grpc_error_response(GrpcError::unauthenticated(msg));
            }
            let encoded = if let Some(snapshot) = get_cached_worker_metrics(&req.node_id) {
                let (m, svcs) = cached_snapshot_to_proto_metrics(&snapshot);
                encode_proto_metrics_response(&req.node_id, m.as_ref(), &svcs)
            } else {
                encode_proto_metrics_response(&req.node_id, None, &[])
            };
            grpc_unary_ok_response(&encoded)
        }
        "/cluster.ClusterService/ExecuteCommand" => {
            let mut decoder = GrpcFrameDecoder::new(incoming);
            let payload = match decoder.next_message().await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => {
                    return grpc_error_response(GrpcError::invalid_argument(
                        "missing CommandRequest frame",
                    ))
                }
                Err(err) => return grpc_error_response(err),
            };
            let req = match decode_proto_command_request(&payload) {
                Ok(parsed) => parsed,
                Err(e) => return grpc_error_response(GrpcError::invalid_argument(e.to_string())),
            };
            if let Err(msg) = authorize_cluster_control_plane(&header_psk, &peer_auth) {
                return grpc_error_response(GrpcError::unauthenticated(msg));
            }
            let target = req
                .params
                .get("service")
                .or_else(|| req.params.get("target"))
                .map(String::as_str)
                .unwrap_or("");
            let action = req.params.get("action").map(String::as_str);
            if let Err(err) = normalize_cluster_command(&req.node_id, &req.cmd_type, target, action)
            {
                return grpc_error_response(GrpcError::invalid_argument(err.to_string()));
            }
            let known_worker = is_enrolled_cluster_node(&req.node_id);
            if !known_worker {
                let encoded = encode_proto_command_response(
                    &req.command_id,
                    false,
                    "",
                    "worker not found or command queue full",
                );
                return grpc_unary_ok_response(&encoded);
            }
            let cmd = PendingWorkerCommand {
                id: req.command_id.clone(),
                cmd_type: req.cmd_type,
                params: req.params,
                lease_generation: 0,
            };
            let encoded = match queue_worker_command_checked(&req.node_id, cmd) {
                Ok(true) => encode_proto_command_response(
                    &req.command_id,
                    true,
                    "command queued for delivery",
                    "",
                ),
                Ok(false) | Err(ClusterCommandEnqueueError::QueueFull(_)) => {
                    encode_proto_command_response(
                        &req.command_id,
                        false,
                        "",
                        "worker not found or command queue full",
                    )
                }
                Err(ClusterCommandEnqueueError::InvalidInput(msg)) => {
                    return grpc_error_response(GrpcError::invalid_argument(msg));
                }
                Err(ClusterCommandEnqueueError::Storage(msg)) => {
                    return grpc_error_response(GrpcError::internal(msg));
                }
            };
            grpc_unary_ok_response(&encoded)
        }
        _ => grpc_error_response(GrpcError::unimplemented(format!(
            "unknown gRPC method {}",
            path
        ))),
    }
}

pub(super) async fn read_bounded_http_body(
    mut incoming: Incoming,
    max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(frame_res) =
        tokio::time::timeout(Duration::from_secs(10), incoming.frame()).await?
    {
        let frame = frame_res?;
        if let Ok(data) = frame.into_data() {
            if out.len().saturating_add(data.len()) > max_bytes {
                anyhow::bail!("HTTP request body exceeds {} bytes", max_bytes);
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

async fn handle_hyper_cluster_request(
    req: Request<Incoming>,
    peer_auth: PeerTransportAuth,
) -> Result<Response<ClusterBody>, Infallible> {
    let method = req.method().as_str().to_uppercase();
    let path = req.uri().path().to_string();
    let raw_target = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| path.clone());
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let header_psk = extract_psk_from_headers(req.headers());

    if content_type.starts_with("application/grpc") || path.starts_with("/cluster.ClusterService/")
    {
        return Ok(handle_grpc_request(&path, header_psk, req.into_body(), peer_auth).await);
    }

    let body_bytes = match read_bounded_http_body(req.into_body(), MAX_JSON_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            let err_json = serde_json::to_vec(&serde_json::json!({
                "error": format!("invalid request body: {}", e),
            }))
            .unwrap_or_default();
            return Ok(Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header("content-type", "application/json")
                .body(ClusterBody::Json(Full::new(Bytes::from(err_json))))
                .unwrap());
        }
    };

    let (status_code, _status_text, response_json) = route_cluster_http_request(
        &method,
        &path,
        &raw_target,
        &header_psk,
        &body_bytes,
        &peer_auth,
    );
    let payload_bytes = serde_json::to_vec(&response_json).unwrap_or_default();
    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(ClusterBody::Json(Full::new(Bytes::from(payload_bytes))))
        .unwrap())
}

fn build_cluster_auto_conn_builder() -> AutoConnBuilder<TokioExecutor> {
    let mut builder = AutoConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HTTP_HEADER_READ_TIMEOUT)
        .max_buf_size(64 * 1024);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(32)
        .max_header_list_size(16 * 1024)
        .max_frame_size(16 * 1024)
        .max_send_buf_size(64 * 1024)
        .keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT);
    builder
}

async fn read_bounded_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> anyhow::Result<Option<String>> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
            let take_len = newline_pos + 1;
            if buf.len() + take_len > max_len {
                anyhow::bail!("cluster request line exceeds {} bytes", max_len);
            }
            buf.extend_from_slice(&available[..take_len]);
            reader.consume(take_len);
            break;
        }
        let chunk_len = available.len();
        if buf.len() + chunk_len > max_len {
            anyhow::bail!("cluster request line exceeds {} bytes", max_len);
        }
        buf.extend_from_slice(available);
        reader.consume(chunk_len);
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

pub async fn serve_cluster_master_connection(
    mut stream: TcpStream,
    security: MasterTransportSecurity,
) -> anyhow::Result<()> {
    match security {
        MasterTransportSecurity::Mtls {
            acceptor,
            admin_cert_sha256,
        } => {
            let tls_stream = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                .await
                .context("cluster mTLS handshake timed out")?
                .context("cluster mTLS handshake failed")?;
            let peer_auth = inspect_mtls_peer(&tls_stream, admin_cert_sha256.as_deref())?;
            let builder = build_cluster_auto_conn_builder();
            let svc = service_fn(move |req| {
                let auth = peer_auth.clone();
                handle_hyper_cluster_request(req, auth)
            });
            builder
                .serve_connection(TokioIo::new(tls_stream), svc)
                .await
                .map_err(|e| anyhow::anyhow!("cluster mTLS connection error: {}", e))?;
            Ok(())
        }
        MasterTransportSecurity::InsecureLoopback => {
            let mut peek_byte = [0u8; 1];
            let n = tokio::time::timeout(Duration::from_secs(10), stream.peek(&mut peek_byte))
                .await
                .context("cluster loopback peek timed out")??;
            if n == 0 {
                return Ok(());
            }
            if peek_byte[0] == b'{' {
                let mut reader = BufReader::new(&mut stream);
                if let Some(line) = tokio::time::timeout(
                    Duration::from_secs(10),
                    read_bounded_line(&mut reader, MAX_PREAUTH_HEADER_BYTES),
                )
                .await??
                {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        let resp_val = handle_raw_json_rpc(trimmed);
                        let mut out = serde_json::to_vec(&resp_val)?;
                        out.push(b'\n');
                        stream.write_all(&out).await?;
                        stream.flush().await?;
                    }
                }
                return Ok(());
            }
            let builder = build_cluster_auto_conn_builder();
            let svc = service_fn(|req| {
                handle_hyper_cluster_request(req, PeerTransportAuth::InsecureLoopback)
            });
            builder
                .serve_connection(TokioIo::new(stream), svc)
                .await
                .map_err(|e| anyhow::anyhow!("cluster loopback connection error: {}", e))?;
            Ok(())
        }
    }
}

pub(super) fn route_cluster_http_request(
    method: &str,
    path: &str,
    raw_target: &str,
    header_psk: &str,
    body_bytes: &[u8],
    peer_auth: &PeerTransportAuth,
) -> (u16, &'static str, serde_json::Value) {
    match (method, path) {
        ("POST", "/cluster/v1/register") | ("POST", "/api/v1/admin/cluster/enroll") => {
            let mut req: RegisterWorkerRequest =
                serde_json::from_slice(body_bytes).unwrap_or_default();
            if req.psk.is_empty() && !header_psk.is_empty() {
                req.psk = header_psk.to_string();
            }
            match register_worker_node_with_peer(&req, peer_auth) {
                Ok(resp) if resp.accepted => {
                    (200, "OK", serde_json::to_value(resp).unwrap_or_default())
                }
                Ok(resp) => (
                    401,
                    "Unauthorized",
                    serde_json::to_value(resp).unwrap_or_default(),
                ),
                Err(e) => (
                    500,
                    "Internal Server Error",
                    serde_json::json!({
                        "accepted": false,
                        "message": format!("enrollment failed: {}", e),
                    }),
                ),
            }
        }
        ("POST", "/cluster/v1/heartbeat") => {
            let mut req: WorkerHeartbeatRequest =
                serde_json::from_slice(body_bytes).unwrap_or_default();
            if req.psk.is_empty() && !header_psk.is_empty() {
                req.psk = header_psk.to_string();
            }
            match process_worker_heartbeat_with_peer(&req, peer_auth) {
                Ok(resp) => (200, "OK", serde_json::to_value(resp).unwrap_or_default()),
                Err(e) => {
                    let err_str = truncate_diagnostic_utf8(&e.to_string(), 512);
                    let (code, reason) = if err_str.contains("not enrolled or has been deleted") {
                        (403, "Forbidden")
                    } else {
                        (401, "Unauthorized")
                    };
                    (
                        code,
                        reason,
                        serde_json::json!({
                            "acknowledged": false,
                            "error": err_str,
                        }),
                    )
                }
            }
        }
        ("POST", "/cluster/v1/commands/ack") => {
            let mut req: WorkerCommandAckRequest =
                serde_json::from_slice(body_bytes).unwrap_or_default();
            if req.psk.is_empty() && !header_psk.is_empty() {
                req.psk = header_psk.to_string();
            }
            let node_id = req.node_id.trim();
            if node_id.is_empty() {
                return (
                    400,
                    "Bad Request",
                    serde_json::json!({ "acknowledged": false, "error": "node_id is required" }),
                );
            }
            if !is_enrolled_cluster_node(node_id) {
                return (
                    403,
                    "Forbidden",
                    serde_json::json!({
                        "acknowledged": false,
                        "error": "cluster worker is not enrolled or has been deleted",
                    }),
                );
            }
            if let Err(msg) = verify_cluster_psk(node_id, &req.psk) {
                return (
                    401,
                    "Unauthorized",
                    serde_json::json!({ "acknowledged": false, "error": msg }),
                );
            }
            if let Some(incoming_fp) = peer_auth.mtls_cert_sha256() {
                if let Ok(conn) = af_db::get_conn() {
                    let pinned: String = conn
                        .query_row(
                            "SELECT COALESCE(peer_cert_sha256, '') FROM cluster_nodes WHERE id = ?1",
                            params![node_id],
                            |r| r.get(0),
                        )
                        .unwrap_or_default();
                    if !pinned.is_empty()
                        && !constant_time_eq(pinned.as_bytes(), incoming_fp.as_bytes())
                    {
                        return (
                            401,
                            "Unauthorized",
                            serde_json::json!({ "acknowledged": false, "error": "peer certificate mismatch" }),
                        );
                    }
                }
            }
            let mut confirmed_command_ids = Vec::new();
            let mut persistence_error: Option<String> = None;
            for ack in &req.acks {
                match acknowledge_worker_command(node_id, ack) {
                    Ok(true) => confirmed_command_ids.push(ack.id.trim().to_string()),
                    Ok(false) => {}
                    Err(err) => {
                        persistence_error = Some(truncate_diagnostic_utf8(&err.to_string(), 512));
                    }
                }
            }
            if let Some(err_msg) = persistence_error {
                return (
                    503,
                    "Service Unavailable",
                    serde_json::json!({
                        "acknowledged": false,
                        "processed": confirmed_command_ids.len(),
                        "confirmed_command_ids": confirmed_command_ids,
                        "error": err_msg,
                    }),
                );
            }
            (
                200,
                "OK",
                serde_json::json!({
                    "acknowledged": true,
                    "processed": confirmed_command_ids.len(),
                    "confirmed_command_ids": confirmed_command_ids,
                }),
            )
        }
        ("POST", "/cluster/v1/commands") => {
            if let Err(msg) = authorize_cluster_control_plane(header_psk, peer_auth) {
                return (401, "Unauthorized", serde_json::json!({ "error": msg }));
            }
            let val: serde_json::Value = serde_json::from_slice(body_bytes).unwrap_or_default();
            let node_id = val.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
            let cmd_type = val
                .get("cmd_type")
                .or_else(|| val.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let params_obj = val.get("params");
            let target = val
                .get("target")
                .or_else(|| val.get("service"))
                .or_else(|| params_obj.and_then(|p| p.get("service").or_else(|| p.get("target"))))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let action = val
                .get("action")
                .or_else(|| params_obj.and_then(|p| p.get("action")))
                .and_then(|v| v.as_str());
            match enqueue_cluster_command_with_action(node_id, cmd_type, target, action) {
                Ok(rec) => (200, "OK", serde_json::to_value(rec).unwrap_or_default()),
                Err(e) => match e.downcast_ref::<ClusterCommandEnqueueError>() {
                    Some(ClusterCommandEnqueueError::InvalidInput(msg)) => {
                        (400, "Bad Request", serde_json::json!({ "error": msg }))
                    }
                    Some(ClusterCommandEnqueueError::QueueFull(msg)) => (
                        429,
                        "Too Many Requests",
                        serde_json::json!({ "error": msg }),
                    ),
                    Some(ClusterCommandEnqueueError::Storage(msg)) => (
                        500,
                        "Internal Server Error",
                        serde_json::json!({ "error": msg }),
                    ),
                    None => (
                        500,
                        "Internal Server Error",
                        serde_json::json!({ "error": e.to_string() }),
                    ),
                },
            }
        }
        ("GET", "/cluster/v1/commands") => {
            if let Err(msg) = authorize_cluster_control_plane(header_psk, peer_auth) {
                return (401, "Unauthorized", serde_json::json!({ "error": msg }));
            }
            let node_id = raw_target.split_once('?').and_then(|(_, q)| {
                url::form_urlencoded::parse(q.as_bytes())
                    .find(|(k, _)| k == "node_id" || k == "id")
                    .map(|(_, v)| v.into_owned())
            });
            match list_cluster_commands(node_id.as_deref(), 100) {
                Ok(items) => (200, "OK", serde_json::json!({ "commands": items })),
                Err(e) => (
                    500,
                    "Internal Server Error",
                    serde_json::json!({ "error": e.to_string() }),
                ),
            }
        }
        ("GET", "/cluster/v1/metrics") => {
            let node_id = raw_target
                .split_once('?')
                .and_then(|(_, q)| {
                    url::form_urlencoded::parse(q.as_bytes())
                        .find(|(k, _)| k == "node_id" || k == "id")
                        .map(|(_, v)| v.into_owned())
                })
                .unwrap_or_default();
            if node_id.is_empty() {
                return (
                    400,
                    "Bad Request",
                    serde_json::json!({ "error": "node_id is required" }),
                );
            }
            if let Err(msg) = authorize_cluster_control_plane(header_psk, peer_auth) {
                return (
                    401,
                    "Unauthorized",
                    serde_json::json!({ "error": msg, "node_id": node_id }),
                );
            }
            if let Some(metrics) = get_cached_worker_metrics(&node_id) {
                (200, "OK", metrics)
            } else {
                (
                    404,
                    "Not Found",
                    serde_json::json!({ "error": "Worker metrics not found", "node_id": node_id }),
                )
            }
        }
        _ => (
            404,
            "Not Found",
            serde_json::json!({ "error": "Unknown cluster RPC endpoint", "path": path }),
        ),
    }
}

fn handle_raw_json_rpc(raw_line: &str) -> serde_json::Value {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(raw_line) else {
        return serde_json::json!({ "error": "Invalid JSON payload" });
    };
    let method = val
        .get("method")
        .or_else(|| val.get("action"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let params_val = val.get("params").cloned().unwrap_or_else(|| val.clone());
    let peer_auth = PeerTransportAuth::InsecureLoopback;

    match method {
        "register" | "/cluster/v1/register" | "RegisterWorker" => {
            let req: RegisterWorkerRequest = serde_json::from_value(params_val).unwrap_or_default();
            match register_worker_node_with_peer(&req, &peer_auth) {
                Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                Err(e) => serde_json::json!({ "accepted": false, "message": e.to_string() }),
            }
        }
        "heartbeat" | "/cluster/v1/heartbeat" | "Heartbeat" => {
            let req: WorkerHeartbeatRequest =
                serde_json::from_value(params_val).unwrap_or_default();
            match process_worker_heartbeat_with_peer(&req, &peer_auth) {
                Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                Err(e) => serde_json::json!({ "acknowledged": false, "error": e.to_string() }),
            }
        }
        _ => {
            if val.get("metrics").is_some() || val.get("cpu_usage").is_some() {
                let req: WorkerHeartbeatRequest = serde_json::from_value(val).unwrap_or_default();
                match process_worker_heartbeat_with_peer(&req, &peer_auth) {
                    Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                    Err(e) => serde_json::json!({ "acknowledged": false, "error": e.to_string() }),
                }
            } else {
                let req: RegisterWorkerRequest = serde_json::from_value(val).unwrap_or_default();
                match register_worker_node_with_peer(&req, &peer_auth) {
                    Ok(resp) => serde_json::to_value(resp).unwrap_or_default(),
                    Err(e) => serde_json::json!({ "accepted": false, "message": e.to_string() }),
                }
            }
        }
    }
}
