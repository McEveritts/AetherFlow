//! Privileged runner Unix domain socket (`AF_UNIX`) client and mockable transport layer for `af-cli`.
//!
//! Communicates with `af-runner` over `/run/aetherflow/runner.sock` (or `--socket <path>`) using
//! the canonical `af-models` wire structs (`PackageRunnerRequest`, `SystemctlRequest`,
//! `QuotaRunnerRequest`, `SandboxRunnerRequest`, `SelfUpdateRequest`, `RunnerResponse`).

use crate::error::{CliError, CliResult};
use af_models::{
    PackageRunnerRequest, QuotaRunnerRequest, RunnerResponse, SandboxRunnerRequest,
    SelfUpdateRequest, SystemctlRequest,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Maximum partial-line carry buffer (16 KiB) when incrementally parsing `/v1/package` stream chunks.
pub const MAX_PACKAGE_STREAM_LINE_CARRY_BYTES: usize = 16 * 1024;

/// Maximum number of log lines retained in memory in [`PackageExecutionReceipt::log_lines`].
pub const MAX_RETAINED_PACKAGE_LOG_LINES: usize = 512;

/// Structured progress event parsed from `/v1/package` streaming output (`[PROGRESS:<pct>] <msg>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageStreamEvent {
    /// Optional progress percentage (`0..=100`) when a line begins with `[PROGRESS:<pct>]`.
    pub progress_percent: Option<u8>,
    /// Cleaned log message for the line.
    pub message: String,
    /// Raw line emitted by `af-runner`.
    pub raw_line: String,
}

/// Summary report returned after a `/v1/package` stream finishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageExecutionReceipt {
    pub action: String,
    pub package_id: String,
    pub script_name: String,
    pub app_port: i32,
    pub last_progress_percent: Option<u8>,
    pub log_lines: Vec<String>,
    #[serde(default)]
    pub total_log_lines: usize,
    #[serde(default)]
    pub truncated_log_lines: usize,
}

/// Formats a [`PackageStreamEvent`] for live human CLI progress output (`stdout` when `--json` is false).
pub fn format_human_progress_line(package_id: &str, ev: &PackageStreamEvent) -> String {
    match ev.progress_percent {
        Some(pct) => {
            if ev.message.is_empty() {
                format!("[{:>3}%] {}", pct, package_id)
            } else {
                format!("[{:>3}%] {}: {}", pct, package_id, ev.message)
            }
        }
        None => format!("       {}: {}", package_id, ev.message),
    }
}

/// Incremental line-by-line parser for `/v1/package` chunked HTTP response bodies with
/// a bounded partial-line carry buffer (`MAX_PACKAGE_STREAM_LINE_CARRY_BYTES`) and bounded
/// log line retention (`MAX_RETAINED_PACKAGE_LOG_LINES`).
#[derive(Debug, Default)]
pub struct PackageStreamAccumulator {
    carry: Vec<u8>,
    log_ring: VecDeque<String>,
    total_log_lines: usize,
    truncated_log_lines: usize,
    last_progress: Option<u8>,
    exit_error: Option<String>,
}

impl PackageStreamAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a raw byte chunk from the HTTP body stream and invokes `on_event` immediately
    /// for each complete line or bounded carry overflow.
    pub fn push_chunk<F>(&mut self, chunk: &[u8], mut on_event: F)
    where
        F: FnMut(&PackageStreamEvent),
    {
        let mut remaining = chunk;
        while !remaining.is_empty() {
            if let Some(nl_pos) = remaining.iter().position(|&b| b == b'\n') {
                let before = &remaining[..nl_pos];
                remaining = &remaining[nl_pos + 1..];

                if self.carry.is_empty() && before.len() <= MAX_PACKAGE_STREAM_LINE_CARRY_BYTES {
                    let line = String::from_utf8_lossy(before);
                    self.process_complete_line(&line, &mut on_event);
                } else {
                    let space = MAX_PACKAGE_STREAM_LINE_CARRY_BYTES.saturating_sub(self.carry.len());
                    let take = before.len().min(space);
                    self.carry.extend_from_slice(&before[..take]);
                    let line = String::from_utf8_lossy(&self.carry).into_owned();
                    self.carry.clear();
                    self.process_complete_line(&line, &mut on_event);
                }
            } else {
                let space = MAX_PACKAGE_STREAM_LINE_CARRY_BYTES.saturating_sub(self.carry.len());
                let take = remaining.len().min(space);
                self.carry.extend_from_slice(&remaining[..take]);
                remaining = &remaining[take..];

                if self.carry.len() >= MAX_PACKAGE_STREAM_LINE_CARRY_BYTES {
                    let line = String::from_utf8_lossy(&self.carry).into_owned();
                    self.carry.clear();
                    self.process_complete_line(&line, &mut on_event);
                }
            }
        }
    }

    fn process_complete_line<F>(&mut self, raw_line: &str, on_event: &mut F)
    where
        F: FnMut(&PackageStreamEvent),
    {
        let line = raw_line.trim();
        if line.is_empty() {
            return;
        }
        if let Some(err_msg) = line.strip_prefix("__RUNNER_EXIT_ERROR__:") {
            let detail = err_msg.trim();
            self.exit_error = Some(if detail.is_empty() {
                "runner reported package execution failure".to_string()
            } else {
                detail.to_string()
            });
            return;
        }

        let ev = parse_package_stream_line(line);
        if let Some(pct) = ev.progress_percent {
            self.last_progress = Some(pct);
        }
        self.total_log_lines += 1;
        if self.log_ring.len() >= MAX_RETAINED_PACKAGE_LOG_LINES {
            self.log_ring.pop_front();
            self.truncated_log_lines += 1;
        }
        self.log_ring.push_back(ev.raw_line.clone());
        on_event(&ev);
    }

    /// Flushes any trailing un-terminated line in the carry buffer and finalizes the
    /// [`PackageExecutionReceipt`], returning [`CliError::RunnerIpc`] if `__RUNNER_EXIT_ERROR__:`
    /// was reported.
    pub fn finish<F>(mut self, req: &PackageRunnerRequest, mut on_event: F) -> CliResult<PackageExecutionReceipt>
    where
        F: FnMut(&PackageStreamEvent),
    {
        if !self.carry.is_empty() {
            let tail = String::from_utf8_lossy(&self.carry).into_owned();
            self.carry.clear();
            self.process_complete_line(&tail, &mut on_event);
        }

        if let Some(err) = self.exit_error {
            return Err(CliError::RunnerIpc {
                endpoint: "/v1/package".to_string(),
                message: format!(
                    "{} {} ({}) failed: {}",
                    req.action, req.package_id, req.script_name, err
                ),
            });
        }

        Ok(PackageExecutionReceipt {
            action: req.action.clone(),
            package_id: req.package_id.clone(),
            script_name: req.script_name.clone(),
            app_port: req.app_port,
            last_progress_percent: self.last_progress,
            log_lines: self.log_ring.into_iter().collect(),
            total_log_lines: self.total_log_lines,
            truncated_log_lines: self.truncated_log_lines,
        })
    }
}

/// Parses a single `/v1/package` output line into a [`PackageStreamEvent`].
pub fn parse_package_stream_line(line: &str) -> PackageStreamEvent {
    let trimmed = line.trim();
    if let Some(after_prefix) = trimmed.strip_prefix("[PROGRESS:") {
        if let Some((num_str, rest)) = after_prefix.split_once(']') {
            if let Ok(pct) = num_str.trim().parse::<u8>() {
                return PackageStreamEvent {
                    progress_percent: Some(pct.min(100)),
                    message: rest.trim().to_string(),
                    raw_line: trimmed.to_string(),
                };
            }
        }
    }

    PackageStreamEvent {
        progress_percent: None,
        message: trimmed.to_string(),
        raw_line: trimmed.to_string(),
    }
}

/// Consumes a text body returned by `af-runner`'s `/v1/package` endpoint using
/// [`PackageStreamAccumulator`], extracting `[PROGRESS:<pct>]` events and failing with
/// [`CliError::RunnerIpc`] if a `__RUNNER_EXIT_ERROR__:<reason>` marker is encountered.
pub fn parse_package_stream_body(
    req: &PackageRunnerRequest,
    body_text: &str,
) -> CliResult<(PackageExecutionReceipt, Vec<PackageStreamEvent>)> {
    let mut events = Vec::new();
    let mut acc = PackageStreamAccumulator::new();
    acc.push_chunk(body_text.as_bytes(), |ev| {
        events.push(ev.clone());
    });
    let receipt = acc.finish(req, |ev| {
        events.push(ev.clone());
    })?;
    Ok((receipt, events))
}

/// Transport abstraction over the `af-runner` Unix domain socket so CLI commands can be
/// tested deterministically in isolated environments without touching a live root daemon.
pub trait RunnerClientTransport: Send + Sync {
    /// Checks `/v1/health` on the runner socket.
    fn check_health(&self) -> CliResult<RunnerResponse>;

    /// Dispatches `POST /v1/package` and returns the parsed execution receipt.
    fn execute_package(&self, req: &PackageRunnerRequest) -> CliResult<PackageExecutionReceipt>;

    /// Dispatches `POST /v1/package` with optional live human progress output (`emit_human_progress = !json`).
    /// When `emit_human_progress` is `false` (`--json` mode), no incremental lines are written to stdout
    /// so the final JSON envelope remains strictly valid.
    fn execute_package_streaming(
        &self,
        req: &PackageRunnerRequest,
        emit_human_progress: bool,
    ) -> CliResult<PackageExecutionReceipt> {
        let receipt = self.execute_package(req)?;
        if emit_human_progress {
            for raw in &receipt.log_lines {
                let ev = parse_package_stream_line(raw);
                println!("{}", format_human_progress_line(&req.package_id, &ev));
            }
            let _ = io::stdout().flush();
        }
        Ok(receipt)
    }

    /// Dispatches `POST /v1/package/cancel` to request cooperative cancellation of an in-flight package operation.
    fn cancel_package(&self, req: &SandboxRunnerRequest) -> CliResult<RunnerResponse>;

    /// Dispatches `POST /v1/systemctl`.
    fn execute_systemctl(&self, req: &SystemctlRequest) -> CliResult<RunnerResponse>;

    /// Dispatches `POST /v1/quota`.
    fn execute_quota(&self, req: &QuotaRunnerRequest) -> CliResult<RunnerResponse>;

    /// Dispatches `POST /v1/sandbox`.
    fn execute_sandbox(&self, req: &SandboxRunnerRequest) -> CliResult<RunnerResponse>;

    /// Dispatches `POST /v1/self-update`.
    fn execute_self_update(&self, req: &SelfUpdateRequest) -> CliResult<RunnerResponse>;
}

/// Production Unix domain socket (`AF_UNIX`) client for `/run/aetherflow/runner.sock`.
#[derive(Debug, Clone)]
pub struct UnixSocketRunnerClient {
    socket_path: PathBuf,
}

impl UnixSocketRunnerClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    fn run_async<F, T>(fut: F) -> CliResult<T>
    where
        F: std::future::Future<Output = CliResult<T>>,
    {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            tokio::task::block_in_place(|| handle.block_on(fut))
        } else {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| CliError::Execution(format!("failed to build tokio runtime: {}", e)))?;
            rt.block_on(fut)
        }
    }

    #[cfg(unix)]
    async fn post_json_async<T: Serialize + ?Sized>(
        &self,
        endpoint: &str,
        payload: &T,
        timeout: Duration,
    ) -> CliResult<RunnerResponse> {
        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;
        use hyper_util::rt::TokioIo;

        let body_bytes = serde_json::to_vec(payload).map_err(|e| {
            CliError::Execution(format!("failed to serialize runner request for {}: {}", endpoint, e))
        })?;
        let sock_path = self.socket_path.clone();

        let fut = async move {
            let stream = tokio::net::UnixStream::connect(&sock_path)
                .await
                .map_err(|e| CliError::RunnerIpc {
                    endpoint: endpoint.to_string(),
                    message: format!(
                        "failed to connect to runner socket {}: {}",
                        sock_path.display(),
                        e
                    ),
                })?;
            let io = TokioIo::new(stream);
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(|e| CliError::RunnerIpc {
                        endpoint: endpoint.to_string(),
                        message: format!("HTTP/1.1 handshake over runner socket failed: {}", e),
                    })?;
            tokio::spawn(async move {
                let _ = conn.await;
            });

            let req = hyper::Request::builder()
                .method(hyper::Method::POST)
                .uri(format!("http://unix{}", endpoint))
                .header("Host", "unix")
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body_bytes)))
                .map_err(|e| CliError::RunnerIpc {
                    endpoint: endpoint.to_string(),
                    message: format!("failed to build HTTP request: {}", e),
                })?;

            let resp = sender.send_request(req).await.map_err(|e| CliError::RunnerIpc {
                endpoint: endpoint.to_string(),
                message: format!("runner socket request failed: {}", e),
            })?;
            let status = resp.status();
            let collected = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| CliError::RunnerIpc {
                    endpoint: endpoint.to_string(),
                    message: format!("failed reading runner response body: {}", e),
                })?
                .to_bytes();

            let decoded: RunnerResponse =
                serde_json::from_slice(&collected).map_err(|e| CliError::RunnerIpc {
                    endpoint: endpoint.to_string(),
                    message: format!(
                        "malformed JSON from runner (HTTP {}): {}",
                        status.as_u16(),
                        e
                    ),
                })?;

            if !decoded.success {
                return Err(CliError::RunnerIpc {
                    endpoint: endpoint.to_string(),
                    message: if decoded.error.trim().is_empty() {
                        format!("runner rejected request (HTTP {})", status.as_u16())
                    } else if decoded.output.trim().is_empty() {
                        decoded.error
                    } else {
                        format!("{} ({})", decoded.error, decoded.output.trim())
                    },
                });
            }

            Ok(decoded)
        };

        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| CliError::RunnerIpc {
                endpoint: endpoint.to_string(),
                message: format!("runner socket request timed out after {:?}", timeout),
            })?
    }

    #[cfg(not(unix))]
    async fn post_json_async<T: Serialize + ?Sized>(
        &self,
        endpoint: &str,
        _payload: &T,
        _timeout: Duration,
    ) -> CliResult<RunnerResponse> {
        Err(CliError::RunnerIpc {
            endpoint: endpoint.to_string(),
            message: format!(
                "UNIX domain socket runner client ({}) requires a Linux/Unix host",
                self.socket_path.display()
            ),
        })
    }

    #[cfg(unix)]
    async fn post_package_stream_async(
        &self,
        req_payload: &PackageRunnerRequest,
        timeout: Duration,
        emit_human_progress: bool,
    ) -> CliResult<PackageExecutionReceipt> {
        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;
        use hyper_util::rt::TokioIo;

        let body_bytes = serde_json::to_vec(req_payload).map_err(|e| {
            CliError::Execution(format!("failed to serialize PackageRunnerRequest: {}", e))
        })?;
        let sock_path = self.socket_path.clone();
        let pkg_id = req_payload.package_id.clone();

        let fut = async move {
            let stream = tokio::net::UnixStream::connect(&sock_path)
                .await
                .map_err(|e| CliError::RunnerIpc {
                    endpoint: "/v1/package".to_string(),
                    message: format!(
                        "failed to connect to runner socket {}: {}",
                        sock_path.display(),
                        e
                    ),
                })?;
            let io = TokioIo::new(stream);
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(|e| CliError::RunnerIpc {
                        endpoint: "/v1/package".to_string(),
                        message: format!("HTTP/1.1 handshake over runner socket failed: {}", e),
                    })?;
            tokio::spawn(async move {
                let _ = conn.await;
            });

            let req = hyper::Request::builder()
                .method(hyper::Method::POST)
                .uri("http://unix/v1/package")
                .header("Host", "unix")
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body_bytes)))
                .map_err(|e| CliError::RunnerIpc {
                    endpoint: "/v1/package".to_string(),
                    message: format!("failed to build HTTP request: {}", e),
                })?;

            let resp = sender.send_request(req).await.map_err(|e| CliError::RunnerIpc {
                endpoint: "/v1/package".to_string(),
                message: format!("runner socket package request failed: {}", e),
            })?;
            let status = resp.status();
            let mut body = resp.into_body();

            if status != hyper::StatusCode::OK {
                let mut err_buf = Vec::new();
                while let Some(frame_res) = body.frame().await {
                    let frame = frame_res.map_err(|e| CliError::RunnerIpc {
                        endpoint: "/v1/package".to_string(),
                        message: format!("failed reading package error stream frame: {}", e),
                    })?;
                    if let Ok(data) = frame.into_data() {
                        let space = MAX_PACKAGE_STREAM_LINE_CARRY_BYTES.saturating_sub(err_buf.len());
                        if space == 0 {
                            break;
                        }
                        let take = data.len().min(space);
                        err_buf.extend_from_slice(&data[..take]);
                    }
                }
                let body_text = String::from_utf8_lossy(&err_buf);
                return Err(CliError::RunnerIpc {
                    endpoint: "/v1/package".to_string(),
                    message: format!(
                        "runner rejected package action (HTTP {}): {}",
                        status.as_u16(),
                        body_text.trim()
                    ),
                });
            }

            let mut accumulator = PackageStreamAccumulator::new();
            let mut emit_cb = |ev: &PackageStreamEvent| {
                if emit_human_progress {
                    println!("{}", format_human_progress_line(&pkg_id, ev));
                    let _ = io::stdout().flush();
                }
            };

            while let Some(frame_res) = body.frame().await {
                let frame = frame_res.map_err(|e| CliError::RunnerIpc {
                    endpoint: "/v1/package".to_string(),
                    message: format!("failed reading package stream frame: {}", e),
                })?;
                if let Ok(data) = frame.into_data() {
                    accumulator.push_chunk(data.as_ref(), &mut emit_cb);
                }
            }

            accumulator.finish(req_payload, &mut emit_cb)
        };

        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| CliError::RunnerIpc {
                endpoint: "/v1/package".to_string(),
                message: format!("runner package request timed out after {:?}", timeout),
            })?
    }

    #[cfg(not(unix))]
    async fn post_package_stream_async(
        &self,
        _req_payload: &PackageRunnerRequest,
        _timeout: Duration,
        _emit_human_progress: bool,
    ) -> CliResult<PackageExecutionReceipt> {
        Err(CliError::RunnerIpc {
            endpoint: "/v1/package".to_string(),
            message: format!(
                "UNIX domain socket runner client ({}) requires a Linux/Unix host",
                self.socket_path.display()
            ),
        })
    }
}

impl RunnerClientTransport for UnixSocketRunnerClient {
    fn check_health(&self) -> CliResult<RunnerResponse> {
        Self::run_async(self.post_json_async(
            "/v1/health",
            &serde_json::json!({}),
            Duration::from_secs(5),
        ))
    }

    fn execute_package(&self, req: &PackageRunnerRequest) -> CliResult<PackageExecutionReceipt> {
        Self::run_async(self.post_package_stream_async(req, Duration::from_secs(30 * 60), false))
    }

    fn execute_package_streaming(
        &self,
        req: &PackageRunnerRequest,
        emit_human_progress: bool,
    ) -> CliResult<PackageExecutionReceipt> {
        Self::run_async(self.post_package_stream_async(
            req,
            Duration::from_secs(30 * 60),
            emit_human_progress,
        ))
    }

    fn cancel_package(&self, req: &SandboxRunnerRequest) -> CliResult<RunnerResponse> {
        Self::run_async(self.post_json_async("/v1/package/cancel", req, Duration::from_secs(5)))
    }

    fn execute_systemctl(&self, req: &SystemctlRequest) -> CliResult<RunnerResponse> {
        Self::run_async(self.post_json_async("/v1/systemctl", req, Duration::from_secs(45)))
    }

    fn execute_quota(&self, req: &QuotaRunnerRequest) -> CliResult<RunnerResponse> {
        Self::run_async(self.post_json_async("/v1/quota", req, Duration::from_secs(30)))
    }

    fn execute_sandbox(&self, req: &SandboxRunnerRequest) -> CliResult<RunnerResponse> {
        Self::run_async(self.post_json_async("/v1/sandbox", req, Duration::from_secs(30)))
    }

    fn execute_self_update(&self, req: &SelfUpdateRequest) -> CliResult<RunnerResponse> {
        Self::run_async(self.post_json_async("/v1/self-update", req, Duration::from_secs(30)))
    }
}
