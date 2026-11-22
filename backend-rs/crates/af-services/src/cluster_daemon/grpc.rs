use super::auth::{constant_time_eq, PeerTransportAuth};
use super::commands::truncate_diagnostic_utf8;
use super::transport::{GRPC_STREAM_IDLE_TIMEOUT, MAX_GRPC_MESSAGE_BYTES};
use super::types::{
    PendingWorkerCommand, RegisterWorkerRequest, RegisterWorkerResponse, WorkerHeartbeatRequest,
    WorkerHeartbeatResponse, WorkerService, WorkerSystemInfo,
};
use anyhow::Context;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HyperBody, Frame, Incoming, SizeHint};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

// ─────────────────────────────────────────────────────────────────────────────
// Pure-Rust `cluster.proto` Wire Codec & gRPC HTTP/2 Framing
// ─────────────────────────────────────────────────────────────────────────────

pub(super) enum ClusterBody {
    Json(Full<Bytes>),
    Grpc(mpsc::Receiver<Result<Frame<Bytes>, Infallible>>),
}

impl HyperBody for ClusterBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ClusterBody::Json(full) => Pin::new(full).poll_frame(cx),
            ClusterBody::Grpc(rx) => rx.poll_recv(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ClusterBody::Json(full) => full.is_end_stream(),
            ClusterBody::Grpc(_) => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            ClusterBody::Json(full) => full.size_hint(),
            ClusterBody::Grpc(_) => SizeHint::default(),
        }
    }
}

#[derive(Debug)]
pub(super) struct GrpcError {
    pub(super) code: u8,
    pub(super) message: String,
}

impl GrpcError {
    pub(super) fn invalid_argument(msg: impl Into<String>) -> Self {
        Self {
            code: 3,
            message: msg.into(),
        }
    }
    pub(super) fn resource_exhausted(msg: impl Into<String>) -> Self {
        Self {
            code: 8,
            message: msg.into(),
        }
    }
    pub(super) fn unimplemented(msg: impl Into<String>) -> Self {
        Self {
            code: 12,
            message: msg.into(),
        }
    }
    pub(super) fn internal(msg: impl Into<String>) -> Self {
        Self {
            code: 13,
            message: msg.into(),
        }
    }
    pub(super) fn unauthenticated(msg: impl Into<String>) -> Self {
        Self {
            code: 16,
            message: msg.into(),
        }
    }
}

pub(super) fn encode_grpc_data_frame(proto_bytes: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(5 + proto_bytes.len());
    out.push(0u8);
    out.extend_from_slice(&(proto_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(proto_bytes);
    Bytes::from(out)
}

pub(super) fn build_grpc_trailers(code: u8, message: Option<&str>) -> HeaderMap {
    let mut trailers = HeaderMap::new();
    let code_str = code.to_string();
    if let Ok(val) = HeaderValue::from_str(&code_str) {
        trailers.insert("grpc-status", val);
    }
    if let Some(msg) = message {
        let bounded = truncate_diagnostic_utf8(msg, 512);
        if !bounded.is_empty() {
            let mut ascii_encoded = String::with_capacity(bounded.len());
            for ch in bounded.chars() {
                if ch.is_ascii() && !ch.is_ascii_control() && ch != '%' {
                    if ascii_encoded.len() + 1 > 512 {
                        break;
                    }
                    ascii_encoded.push(ch);
                } else {
                    let mut utf8_buf = [0u8; 4];
                    let bytes = ch.encode_utf8(&mut utf8_buf).as_bytes();
                    if ascii_encoded.len() + bytes.len() * 3 > 512 {
                        break;
                    }
                    for b in bytes {
                        ascii_encoded.push_str(&format!("%{b:02X}"));
                    }
                }
            }
            if !ascii_encoded.is_empty() {
                if let Ok(val) = HeaderValue::from_str(&ascii_encoded) {
                    trailers.insert("grpc-message", val);
                }
            }
        }
    }
    trailers
}

pub(super) fn grpc_unary_ok_response(proto_bytes: &[u8]) -> Response<ClusterBody> {
    let (tx, rx) = mpsc::channel(2);
    let data_frame = encode_grpc_data_frame(proto_bytes);
    let _ = tx.try_send(Ok(Frame::data(data_frame)));
    let _ = tx.try_send(Ok(Frame::trailers(build_grpc_trailers(0, None))));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(ClusterBody::Grpc(rx))
        .unwrap()
}

pub(super) fn grpc_error_response(err: GrpcError) -> Response<ClusterBody> {
    let (tx, rx) = mpsc::channel(1);
    let _ = tx.try_send(Ok(Frame::trailers(build_grpc_trailers(
        err.code,
        Some(&err.message),
    ))));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(ClusterBody::Grpc(rx))
        .unwrap()
}

pub(super) struct GrpcFrameDecoder {
    incoming: Incoming,
    buf: Vec<u8>,
}

impl GrpcFrameDecoder {
    pub(super) fn new(incoming: Incoming) -> Self {
        Self {
            incoming,
            buf: Vec::new(),
        }
    }

    pub(super) async fn next_message(&mut self) -> Result<Option<Vec<u8>>, GrpcError> {
        loop {
            if self.buf.len() >= 5 {
                let compressed = self.buf[0];
                if compressed != 0 {
                    return Err(GrpcError::unimplemented(
                        "compressed gRPC frames are not supported",
                    ));
                }
                let msg_len =
                    u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]])
                        as usize;
                if msg_len > MAX_GRPC_MESSAGE_BYTES {
                    return Err(GrpcError::resource_exhausted(
                        "gRPC frame exceeds 4 MiB limit",
                    ));
                }
                if self.buf.len() >= 5 + msg_len {
                    let payload = self.buf[5..5 + msg_len].to_vec();
                    self.buf.drain(..5 + msg_len);
                    return Ok(Some(payload));
                }
            }

            let next_frame = tokio::time::timeout(GRPC_STREAM_IDLE_TIMEOUT, self.incoming.frame())
                .await
                .map_err(|_| GrpcError::internal("gRPC stream read timed out"))?;

            match next_frame {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if self.buf.len().saturating_add(data.len())
                            > MAX_GRPC_MESSAGE_BYTES + 64 * 1024
                        {
                            return Err(GrpcError::resource_exhausted(
                                "gRPC buffer exceeds maximum size",
                            ));
                        }
                        self.buf.extend_from_slice(&data);
                    }
                }
                Some(Err(e)) => {
                    return Err(GrpcError::internal(format!("gRPC transport error: {}", e)));
                }
                None => {
                    if self.buf.is_empty() {
                        return Ok(None);
                    }
                    return Err(GrpcError::invalid_argument("truncated gRPC frame"));
                }
            }
        }
    }
}

fn pb_encode_varint(buf: &mut Vec<u8>, mut val: u64) {
    while val >= 0x80 {
        buf.push(((val as u8) & 0x7f) | 0x80);
        val >>= 7;
    }
    buf.push(val as u8);
}

fn pb_encode_tag(buf: &mut Vec<u8>, field_num: u32, wire_type: u8) {
    pb_encode_varint(buf, ((field_num as u64) << 3) | (wire_type as u64));
}

pub(super) fn pb_encode_string(buf: &mut Vec<u8>, field_num: u32, val: &str) {
    if !val.is_empty() {
        pb_encode_tag(buf, field_num, 2);
        pb_encode_varint(buf, val.len() as u64);
        buf.extend_from_slice(val.as_bytes());
    }
}

fn pb_encode_bool(buf: &mut Vec<u8>, field_num: u32, val: bool) {
    if val {
        pb_encode_tag(buf, field_num, 0);
        buf.push(1u8);
    }
}

pub(super) fn pb_encode_int64(buf: &mut Vec<u8>, field_num: u32, val: i64) {
    if val != 0 {
        pb_encode_tag(buf, field_num, 0);
        pb_encode_varint(buf, val as u64);
    }
}

#[cfg(test)]
pub(super) fn pb_encode_int32(buf: &mut Vec<u8>, field_num: u32, val: i32) {
    if val != 0 {
        pb_encode_tag(buf, field_num, 0);
        pb_encode_varint(buf, (val as i64) as u64);
    }
}

fn pb_encode_f64(buf: &mut Vec<u8>, field_num: u32, val: f64) {
    if val != 0.0 {
        pb_encode_tag(buf, field_num, 1);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

pub(super) fn pb_encode_message_field(buf: &mut Vec<u8>, field_num: u32, msg_bytes: &[u8]) {
    pb_encode_tag(buf, field_num, 2);
    pb_encode_varint(buf, msg_bytes.len() as u64);
    buf.extend_from_slice(msg_bytes);
}

pub(super) fn pb_decode_varint(input: &[u8], pos: &mut usize) -> anyhow::Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        if *pos >= input.len() {
            anyhow::bail!("unexpected EOF decoding protobuf varint");
        }
        let byte = input[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    anyhow::bail!("protobuf varint overflow")
}

fn pb_decode_f64(input: &[u8], pos: &mut usize) -> anyhow::Result<f64> {
    let end = pos
        .checked_add(8)
        .ok_or_else(|| anyhow::anyhow!("protobuf f64 offset overflow"))?;
    if end > input.len() {
        anyhow::bail!("unexpected EOF decoding protobuf double");
    }
    let bytes: [u8; 8] = input[*pos..end].try_into()?;
    *pos = end;
    Ok(f64::from_le_bytes(bytes))
}

pub(super) fn pb_decode_bytes<'a>(input: &'a [u8], pos: &mut usize) -> anyhow::Result<&'a [u8]> {
    let len = usize::try_from(pb_decode_varint(input, pos)?)
        .map_err(|_| anyhow::anyhow!("protobuf length exceeds usize"))?;
    let end = pos
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("protobuf slice overflow"))?;
    if end > input.len() {
        anyhow::bail!("unexpected EOF decoding protobuf length-delimited field");
    }
    let slice = &input[*pos..end];
    *pos = end;
    Ok(slice)
}

pub(super) fn pb_decode_string(input: &[u8], pos: &mut usize) -> anyhow::Result<String> {
    let raw = pb_decode_bytes(input, pos)?;
    Ok(std::str::from_utf8(raw)
        .context("invalid UTF-8 in protobuf string")?
        .to_string())
}

pub(super) fn pb_skip_field(input: &[u8], pos: &mut usize, wire_type: u8) -> anyhow::Result<()> {
    match wire_type {
        0 => {
            let _ = pb_decode_varint(input, pos)?;
        }
        1 => {
            let end = pos
                .checked_add(8)
                .ok_or_else(|| anyhow::anyhow!("protobuf skip64 overflow"))?;
            if end > input.len() {
                anyhow::bail!("unexpected EOF skipping 64-bit protobuf field");
            }
            *pos = end;
        }
        2 => {
            let _ = pb_decode_bytes(input, pos)?;
        }
        5 => {
            let end = pos
                .checked_add(4)
                .ok_or_else(|| anyhow::anyhow!("protobuf skip32 overflow"))?;
            if end > input.len() {
                anyhow::bail!("unexpected EOF skipping 32-bit protobuf field");
            }
            *pos = end;
        }
        other => anyhow::bail!("unsupported protobuf wire type {}", other),
    }
    Ok(())
}

fn decode_proto_system_info(input: &[u8]) -> anyhow::Result<WorkerSystemInfo> {
    let mut info = WorkerSystemInfo::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => info.os = pb_decode_string(input, &mut pos)?,
            (2, 2) => info.arch = pb_decode_string(input, &mut pos)?,
            (3, 0) => info.cpu_cores = pb_decode_varint(input, &mut pos)? as i32,
            (4, 0) => info.total_memory_bytes = pb_decode_varint(input, &mut pos)? as i64,
            (5, 0) => info.total_disk_bytes = pb_decode_varint(input, &mut pos)? as i64,
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(info)
}

pub(super) fn decode_proto_register_request(input: &[u8]) -> anyhow::Result<RegisterWorkerRequest> {
    let mut req = RegisterWorkerRequest::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => req.hostname = pb_decode_string(input, &mut pos)?,
            (2, 2) => req.address = pb_decode_string(input, &mut pos)?,
            (3, 2) => req.psk = pb_decode_string(input, &mut pos)?,
            (4, 2) => req.version = pb_decode_string(input, &mut pos)?,
            (5, 2) => {
                let sub = pb_decode_bytes(input, &mut pos)?;
                req.system_info = Some(decode_proto_system_info(sub)?);
            }
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(req)
}

pub(super) fn encode_proto_register_response(resp: &RegisterWorkerResponse) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_string(&mut buf, 1, &resp.node_id);
    pb_encode_bool(&mut buf, 2, resp.accepted);
    pb_encode_string(&mut buf, 3, &resp.message);
    buf
}

#[derive(Debug, Clone, Default)]
pub(super) struct ProtoWorkerMetrics {
    pub(super) cpu_usage: f64,
    pub(super) memory_used_gb: f64,
    pub(super) memory_total_gb: f64,
    pub(super) disk_used_gb: f64,
    pub(super) disk_total_gb: f64,
    pub(super) network_rx_speed: String,
    pub(super) network_tx_speed: String,
    pub(super) uptime: String,
    pub(super) load_average: Vec<f64>,
}

fn decode_proto_worker_metrics(input: &[u8]) -> anyhow::Result<ProtoWorkerMetrics> {
    let mut m = ProtoWorkerMetrics::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 1) => m.cpu_usage = pb_decode_f64(input, &mut pos)?,
            (2, 1) => m.memory_used_gb = pb_decode_f64(input, &mut pos)?,
            (3, 1) => m.memory_total_gb = pb_decode_f64(input, &mut pos)?,
            (4, 1) => m.disk_used_gb = pb_decode_f64(input, &mut pos)?,
            (5, 1) => m.disk_total_gb = pb_decode_f64(input, &mut pos)?,
            (6, 2) => m.network_rx_speed = pb_decode_string(input, &mut pos)?,
            (7, 2) => m.network_tx_speed = pb_decode_string(input, &mut pos)?,
            (8, 2) => m.uptime = pb_decode_string(input, &mut pos)?,
            (9, 2) => {
                let packed = pb_decode_bytes(input, &mut pos)?;
                let mut sub_pos = 0usize;
                while sub_pos < packed.len() && m.load_average.len() < 16 {
                    m.load_average.push(pb_decode_f64(packed, &mut sub_pos)?);
                }
            }
            (9, 1) => {
                if m.load_average.len() < 16 {
                    m.load_average.push(pb_decode_f64(input, &mut pos)?);
                } else {
                    let _ = pb_decode_f64(input, &mut pos)?;
                }
            }
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(m)
}

pub(super) fn encode_proto_worker_metrics(m: &ProtoWorkerMetrics) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_f64(&mut buf, 1, m.cpu_usage);
    pb_encode_f64(&mut buf, 2, m.memory_used_gb);
    pb_encode_f64(&mut buf, 3, m.memory_total_gb);
    pb_encode_f64(&mut buf, 4, m.disk_used_gb);
    pb_encode_f64(&mut buf, 5, m.disk_total_gb);
    pb_encode_string(&mut buf, 6, &m.network_rx_speed);
    pb_encode_string(&mut buf, 7, &m.network_tx_speed);
    pb_encode_string(&mut buf, 8, &m.uptime);
    if !m.load_average.is_empty() {
        pb_encode_tag(&mut buf, 9, 2);
        pb_encode_varint(&mut buf, (m.load_average.len() * 8) as u64);
        for &val in &m.load_average {
            buf.extend_from_slice(&val.to_le_bytes());
        }
    }
    buf
}

fn decode_proto_service_status(input: &[u8]) -> anyhow::Result<WorkerService> {
    let mut svc = WorkerService::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => svc.name = pb_decode_string(input, &mut pos)?,
            (2, 2) => svc.status = pb_decode_string(input, &mut pos)?,
            (3, 2) => svc.uptime = pb_decode_string(input, &mut pos)?,
            (4, 2) => svc.managed_by = pb_decode_string(input, &mut pos)?,
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(svc)
}

pub(super) fn encode_proto_service_status(svc: &WorkerService) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_string(&mut buf, 1, &svc.name);
    pb_encode_string(&mut buf, 2, &svc.status);
    pb_encode_string(&mut buf, 3, &svc.uptime);
    pb_encode_string(&mut buf, 4, &svc.managed_by);
    buf
}

#[derive(Debug, Default)]
pub(super) struct ProtoHeartbeatPing {
    pub(super) node_id: String,
    pub(super) timestamp: i64,
    pub(super) metrics: Option<ProtoWorkerMetrics>,
    pub(super) services: Vec<WorkerService>,
}

pub(super) fn decode_proto_heartbeat_ping(input: &[u8]) -> anyhow::Result<ProtoHeartbeatPing> {
    let mut ping = ProtoHeartbeatPing::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => ping.node_id = pb_decode_string(input, &mut pos)?,
            (2, 0) => ping.timestamp = pb_decode_varint(input, &mut pos)? as i64,
            (3, 2) => {
                let sub = pb_decode_bytes(input, &mut pos)?;
                ping.metrics = Some(decode_proto_worker_metrics(sub)?);
            }
            (4, 2) => {
                let sub = pb_decode_bytes(input, &mut pos)?;
                if ping.services.len() < 256 {
                    ping.services.push(decode_proto_service_status(sub)?);
                }
            }
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(ping)
}

fn encode_proto_remote_command(cmd: &PendingWorkerCommand) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_string(&mut buf, 1, &cmd.id);
    pb_encode_string(&mut buf, 2, &cmd.cmd_type);
    let mut keys: Vec<&String> = cmd.params.keys().collect();
    keys.sort();
    for k in keys {
        if let Some(v) = cmd.params.get(k) {
            let mut entry = Vec::new();
            pb_encode_string(&mut entry, 1, k);
            pb_encode_string(&mut entry, 2, v);
            pb_encode_message_field(&mut buf, 3, &entry);
        }
    }
    buf
}

pub(super) fn encode_proto_heartbeat_pong(resp: &WorkerHeartbeatResponse) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_int64(&mut buf, 1, resp.timestamp);
    pb_encode_bool(&mut buf, 2, resp.acknowledged);
    if let Some(cmd) = &resp.command {
        let cmd_bytes = encode_proto_remote_command(cmd);
        pb_encode_message_field(&mut buf, 3, &cmd_bytes);
    }
    buf
}

fn decode_proto_map_entry(input: &[u8]) -> anyhow::Result<(String, String)> {
    let mut k = String::new();
    let mut v = String::new();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => k = pb_decode_string(input, &mut pos)?,
            (2, 2) => v = pb_decode_string(input, &mut pos)?,
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok((k, v))
}

#[derive(Debug, Default)]
pub(super) struct ProtoMetricsRequest {
    pub(super) node_id: String,
}

pub(super) fn decode_proto_metrics_request(input: &[u8]) -> anyhow::Result<ProtoMetricsRequest> {
    let mut req = ProtoMetricsRequest::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => req.node_id = pb_decode_string(input, &mut pos)?,
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(req)
}

pub(super) fn encode_proto_metrics_response(
    node_id: &str,
    metrics: Option<&ProtoWorkerMetrics>,
    services: &[WorkerService],
) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_string(&mut buf, 1, node_id);
    if let Some(m) = metrics {
        let m_bytes = encode_proto_worker_metrics(m);
        pb_encode_message_field(&mut buf, 2, &m_bytes);
    }
    for svc in services {
        let svc_bytes = encode_proto_service_status(svc);
        pb_encode_message_field(&mut buf, 3, &svc_bytes);
    }
    buf
}

#[derive(Debug, Default)]
pub(super) struct ProtoCommandRequest {
    pub(super) node_id: String,
    pub(super) command_id: String,
    pub(super) cmd_type: String,
    pub(super) params: HashMap<String, String>,
}

pub(super) fn decode_proto_command_request(input: &[u8]) -> anyhow::Result<ProtoCommandRequest> {
    let mut req = ProtoCommandRequest::default();
    let mut pos = 0usize;
    while pos < input.len() {
        let tag = pb_decode_varint(input, &mut pos)?;
        let field_num = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        match (field_num, wire_type) {
            (1, 2) => req.node_id = pb_decode_string(input, &mut pos)?,
            (2, 2) => req.command_id = pb_decode_string(input, &mut pos)?,
            (3, 2) => req.cmd_type = pb_decode_string(input, &mut pos)?,
            (4, 2) => {
                let sub = pb_decode_bytes(input, &mut pos)?;
                if req.params.len() < 64 {
                    let (k, v) = decode_proto_map_entry(sub)?;
                    req.params.insert(k, v);
                }
            }
            _ => pb_skip_field(input, &mut pos, wire_type)?,
        }
    }
    Ok(req)
}

pub(super) fn encode_proto_command_response(
    command_id: &str,
    success: bool,
    output: &str,
    error: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    pb_encode_string(&mut buf, 1, command_id);
    pb_encode_bool(&mut buf, 2, success);
    pb_encode_string(&mut buf, 3, output);
    pb_encode_string(&mut buf, 4, error);
    buf
}

pub(super) fn extract_psk_from_headers(headers: &HeaderMap) -> String {
    if let Some(val) = headers.get("x-cluster-psk").and_then(|v| v.to_str().ok()) {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(val) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = val
            .trim()
            .strip_prefix("Bearer ")
            .or_else(|| val.trim().strip_prefix("bearer "))
        {
            return token.trim().to_string();
        }
    }
    String::new()
}

pub(super) fn heartbeat_request_from_proto(
    ping: ProtoHeartbeatPing,
    header_psk: &str,
) -> WorkerHeartbeatRequest {
    let (cpu_usage, ram_usage, disk_usage, metrics_json) = if let Some(m) = &ping.metrics {
        let ram_pct = if m.memory_total_gb > 0.0 {
            af_hardware::sanitize_f64(
                ((m.memory_used_gb / m.memory_total_gb) * 1000.0).round() / 10.0,
            )
        } else {
            0.0
        };
        let disk_pct = if m.disk_total_gb > 0.0 {
            af_hardware::sanitize_f64(((m.disk_used_gb / m.disk_total_gb) * 1000.0).round() / 10.0)
        } else {
            0.0
        };
        let cpu = af_hardware::sanitize_f64(m.cpu_usage);
        let metrics_val = serde_json::json!({
            "cpu_usage": cpu,
            "ram_usage": ram_pct,
            "disk_usage": disk_pct,
            "mem_used_gb": af_hardware::sanitize_f64(m.memory_used_gb),
            "mem_total_gb": af_hardware::sanitize_f64(m.memory_total_gb),
            "disk_used_gb": af_hardware::sanitize_f64(m.disk_used_gb),
            "disk_total_gb": af_hardware::sanitize_f64(m.disk_total_gb),
            "memory": {
                "used": af_hardware::sanitize_f64(m.memory_used_gb),
                "total": af_hardware::sanitize_f64(m.memory_total_gb),
            },
            "disk_space": {
                "used": af_hardware::sanitize_f64(m.disk_used_gb),
                "total": af_hardware::sanitize_f64(m.disk_total_gb),
            },
            "net_rx_speed": m.network_rx_speed,
            "net_tx_speed": m.network_tx_speed,
            "uptime": m.uptime,
            "load_average": m.load_average,
        });
        (Some(cpu), Some(ram_pct), Some(disk_pct), metrics_val)
    } else {
        (None, None, None, serde_json::Value::Null)
    };

    let (services, services_status, services_observed_at) = if ping.services.is_empty() {
        (None, Some("unknown".to_string()), None)
    } else {
        let obs_ts = if ping.timestamp > 0 {
            ping.timestamp
        } else {
            Utc::now().timestamp()
        };
        (Some(ping.services), Some("fresh".to_string()), Some(obs_ts))
    };

    WorkerHeartbeatRequest {
        node_id: ping.node_id,
        psk: header_psk.to_string(),
        timestamp: ping.timestamp,
        cpu_usage,
        ram_usage,
        disk_usage,
        metrics: metrics_json,
        services,
        services_status,
        services_observed_at,
        ..Default::default()
    }
}

pub(super) fn cached_snapshot_to_proto_metrics(
    snapshot: &serde_json::Value,
) -> (Option<ProtoWorkerMetrics>, Vec<WorkerService>) {
    let metrics_obj = snapshot.get("metrics");
    let proto_metrics = metrics_obj.map(|m| ProtoWorkerMetrics {
        cpu_usage: snapshot
            .get("cpu_usage")
            .and_then(|v| v.as_f64())
            .or_else(|| m.get("cpu_usage").and_then(|v| v.as_f64()))
            .unwrap_or(0.0),
        memory_used_gb: m
            .get("mem_used_gb")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                m.get("memory")
                    .and_then(|x| x.get("used"))
                    .and_then(|v| v.as_f64())
            })
            .unwrap_or(0.0),
        memory_total_gb: m
            .get("mem_total_gb")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                m.get("memory")
                    .and_then(|x| x.get("total"))
                    .and_then(|v| v.as_f64())
            })
            .unwrap_or(0.0),
        disk_used_gb: m
            .get("disk_used_gb")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                m.get("disk_space")
                    .and_then(|x| x.get("used"))
                    .and_then(|v| v.as_f64())
            })
            .unwrap_or(0.0),
        disk_total_gb: m
            .get("disk_total_gb")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                m.get("disk_space")
                    .and_then(|x| x.get("total"))
                    .and_then(|v| v.as_f64())
            })
            .unwrap_or(0.0),
        network_rx_speed: m
            .get("net_rx_speed")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        network_tx_speed: m
            .get("net_tx_speed")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        uptime: m
            .get("uptime")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        load_average: m
            .get("load_average")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_f64()).collect())
            .unwrap_or_default(),
    });

    let services = snapshot
        .get("services")
        .and_then(|v| serde_json::from_value::<Vec<WorkerService>>(v.clone()).ok())
        .unwrap_or_default();

    (proto_metrics, services)
}

fn der_read_tlv<'a>(input: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    if *pos >= input.len() {
        return None;
    }
    let tag = input[*pos];
    *pos += 1;
    if (tag & 0x1f) == 0x1f {
        // High-tag-number form is never used in X.509 TBSCertificate / Subject Name headers
        return None;
    }
    if *pos >= input.len() {
        return None;
    }
    let first_len = input[*pos];
    *pos += 1;
    let len = if (first_len & 0x80) == 0 {
        first_len as usize
    } else {
        let num_octets = (first_len & 0x7f) as usize;
        if num_octets == 0 || num_octets > 4 || *pos + num_octets > input.len() {
            return None;
        }
        let mut acc = 0usize;
        for &b in &input[*pos..*pos + num_octets] {
            acc = (acc << 8) | (b as usize);
        }
        *pos += num_octets;
        acc
    };
    let end = pos.checked_add(len)?;
    if end > input.len() {
        return None;
    }
    let val = &input[*pos..end];
    *pos = end;
    Some((tag, val))
}

/// Extracts the leaf certificate's X.509 `TBSCertificate.subject` CommonName (`OID 2.5.4.3`),
/// strictly skipping `issuer` and `extensions` so neither CA CNs nor SANs can be confused for Subject CN.
fn extract_x509_subject_cn(cert_der: &[u8]) -> Option<String> {
    let mut top_pos = 0usize;
    let (cert_tag, cert_body) = der_read_tlv(cert_der, &mut top_pos)?;
    if cert_tag != 0x30 {
        return None;
    }
    let mut cert_pos = 0usize;
    let (tbs_tag, tbs_body) = der_read_tlv(cert_body, &mut cert_pos)?;
    if tbs_tag != 0x30 {
        return None;
    }
    let mut tbs_pos = 0usize;
    let (first_tag, _) = der_read_tlv(tbs_body, &mut tbs_pos)?;
    if first_tag == 0xa0 {
        // Explicit v3 [0] version present; next 4 elements are serialNumber, signature, issuer, validity
        let _serial = der_read_tlv(tbs_body, &mut tbs_pos)?;
    }
    // Skip signature, issuer, validity
    let _sig = der_read_tlv(tbs_body, &mut tbs_pos)?;
    let _issuer = der_read_tlv(tbs_body, &mut tbs_pos)?;
    let _validity = der_read_tlv(tbs_body, &mut tbs_pos)?;
    let (subj_tag, subj_body) = der_read_tlv(tbs_body, &mut tbs_pos)?;
    if subj_tag != 0x30 {
        return None;
    }

    let mut rdn_pos = 0usize;
    let mut last_cn: Option<String> = None;
    while rdn_pos < subj_body.len() {
        let (set_tag, set_body) = der_read_tlv(subj_body, &mut rdn_pos)?;
        if set_tag != 0x31 {
            continue;
        }
        let mut attr_pos = 0usize;
        while attr_pos < set_body.len() {
            let (seq_tag, seq_body) = der_read_tlv(set_body, &mut attr_pos)?;
            if seq_tag != 0x30 {
                continue;
            }
            let mut kv_pos = 0usize;
            let Some((oid_tag, oid_bytes)) = der_read_tlv(seq_body, &mut kv_pos) else {
                continue;
            };
            let Some((val_tag, val_bytes)) = der_read_tlv(seq_body, &mut kv_pos) else {
                continue;
            };
            // OID 2.5.4.3 (id-at-commonName) == 55 04 03
            if oid_tag == 0x06
                && oid_bytes == [0x55, 0x04, 0x03]
                && matches!(val_tag, 0x0c | 0x13 | 0x14 | 0x16)
            {
                if let Ok(s) = std::str::from_utf8(val_bytes) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        last_cn = Some(trimmed.to_string());
                    }
                }
            }
        }
    }
    last_cn
}

pub(super) fn inspect_mtls_peer(
    tls_stream: &tokio_rustls::server::TlsStream<TcpStream>,
    pinned_admin_sha256: Option<&str>,
) -> anyhow::Result<PeerTransportAuth> {
    let (_, server_conn) = tls_stream.get_ref();
    let certs = server_conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("missing peer certificate chain after mTLS handshake"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty peer certificate chain after mTLS handshake"))?;
    let cert_sha256 = hex::encode(Sha256::digest(leaf.as_ref()));
    let subject_cn = extract_x509_subject_cn(leaf.as_ref());

    let is_admin_cert = if let Some(expected) = pinned_admin_sha256 {
        constant_time_eq(cert_sha256.as_bytes(), expected.as_bytes())
    } else {
        subject_cn.as_deref().is_some_and(|cn| {
            cn.eq_ignore_ascii_case("aetherflow-master")
                || cn.eq_ignore_ascii_case("aetherflow-control-plane")
                || cn.eq_ignore_ascii_case("aetherflow-admin")
        })
    };

    Ok(PeerTransportAuth::Mtls {
        cert_sha256,
        subject_cn,
        is_admin_cert,
    })
}
