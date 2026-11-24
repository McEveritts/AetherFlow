use super::*;

/// Retryable lifecycle exclusion, kept typed across runner and API boundaries.
#[derive(Debug, thiserror::Error)]
#[error("Application lifecycle or system maintenance is busy. Retry after the active operation completes.")]
pub struct LifecycleBusy;

pub fn is_lifecycle_busy(error: &anyhow::Error) -> bool {
    error.is::<LifecycleBusy>()
        || matches!(
            error.downcast_ref::<af_release::ReleaseError>(),
            Some(af_release::ReleaseError::LockBusy { .. })
        )
}

#[cfg(unix)]
pub(crate) async fn post_runner_json<T: Serialize + ?Sized>(
    endpoint: &str,
    payload: &T,
    timeout: Duration,
) -> anyhow::Result<RunnerResponse> {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    let sock_path = resolve_runner_socket_path();
    let body_bytes = serde_json::to_vec(payload)?;

    let fut = async {
        let stream = tokio::net::UnixStream::connect(&sock_path).await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(endpoint)
            .header("Host", "unix")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))?;

        let resp = sender.send_request(req).await?;
        if matches!(endpoint, "/v1/systemctl" | "/v1/blueprint/apply")
            && resp.status() == StatusCode::CONFLICT
        {
            return Err(LifecycleBusy.into());
        }
        if endpoint == "/v1/health" && !resp.status().is_success() {
            anyhow::bail!(
                "runner health probe returned non-success status {}",
                resp.status()
            );
        }
        let collected = resp.into_body().collect().await?.to_bytes();
        let decoded: RunnerResponse = serde_json::from_slice(&collected)?;
        Ok::<RunnerResponse, anyhow::Error>(decoded)
    };

    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow::anyhow!("runner socket request timed out ({})", endpoint))?
}

#[cfg(not(unix))]
pub(crate) async fn post_runner_json<T: Serialize + ?Sized>(
    endpoint: &str,
    _payload: &T,
    _timeout: Duration,
) -> anyhow::Result<RunnerResponse> {
    anyhow::bail!(
        "UNIX domain socket runner client is only supported on Unix hosts ({})",
        endpoint
    )
}

/// Ask the running daemon itself. A socket path can survive a daemon crash.
pub async fn runner_is_ready() -> bool {
    post_runner_json("/v1/health", &(), Duration::from_secs(2))
        .await
        .is_ok_and(|response| response.success && response.output == "ready")
}

#[cfg(unix)]
async fn post_runner_plugin_json<T: Serialize + ?Sized>(
    endpoint: &str,
    payload: &T,
    timeout: Duration,
) -> Result<(StatusCode, RunnerResponse), PluginRunnerError> {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    let sock_path = resolve_runner_socket_path();
    let body_bytes = serde_json::to_vec(payload)
        .map_err(|err| PluginRunnerError::InvalidRequest(format!("Serialization error: {err}")))?;

    let fut = async {
        let stream = tokio::net::UnixStream::connect(&sock_path)
            .await
            .map_err(|err| {
                PluginRunnerError::IsolationUnavailable(format!(
                    "Managed plugin isolation is unavailable: cannot connect to aetherflow-runner socket '{}' ({err}). Start aetherflow-runner.service on a systemd-managed Linux host or run this plugin as an external backend.",
                    sock_path
                ))
            })?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|err| {
                PluginRunnerError::IsolationUnavailable(format!(
                    "Managed plugin isolation is unavailable: runner IPC handshake failed on '{}' ({err}).",
                    sock_path
                ))
            })?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(endpoint)
            .header("Host", "unix")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|err| {
                PluginRunnerError::Runtime(format!("Failed to build runner request: {err}"))
            })?;

        let resp = sender.send_request(req).await.map_err(|err| {
            PluginRunnerError::Runtime(format!("Runner request failed ({endpoint}): {err}"))
        })?;
        let status = resp.status();
        let collected = resp
            .into_body()
            .collect()
            .await
            .map_err(|err| {
                PluginRunnerError::Runtime(format!(
                    "Failed to read runner response ({endpoint}): {err}"
                ))
            })?
            .to_bytes();
        let decoded: RunnerResponse = serde_json::from_slice(&collected).map_err(|err| {
            PluginRunnerError::Runtime(format!(
                "Invalid JSON response from runner ({endpoint}, HTTP {}): {err}",
                status.as_u16()
            ))
        })?;
        Ok((status, decoded))
    };

    tokio::time::timeout(timeout, fut).await.map_err(|_| {
        PluginRunnerError::Runtime(format!("Runner plugin request timed out ({endpoint})"))
    })?
}

#[cfg(not(unix))]
async fn post_runner_plugin_json<T: Serialize + ?Sized>(
    endpoint: &str,
    _payload: &T,
    _timeout: Duration,
) -> Result<(StatusCode, RunnerResponse), PluginRunnerError> {
    Err(PluginRunnerError::IsolationUnavailable(format!(
        "Managed plugin isolation is unavailable: UNIX domain socket runner requires Linux/Unix ({endpoint})."
    )))
}

fn map_plugin_runner_failure(status: StatusCode, resp: RunnerResponse) -> PluginRunnerError {
    let msg = if resp.error.trim().is_empty() {
        format!("Runner returned HTTP {}", status.as_u16())
    } else {
        resp.error
    };
    match status {
        StatusCode::SERVICE_UNAVAILABLE => PluginRunnerError::IsolationUnavailable(msg),
        StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN => PluginRunnerError::InvalidRequest(msg),
        _ => PluginRunnerError::Runtime(msg),
    }
}

pub async fn dispatch_plugin_start(
    req: &PluginRunnerStartRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let (status, resp) =
        post_runner_plugin_json("/v1/plugins/start", req, Duration::from_secs(25)).await?;
    if status != StatusCode::OK || !resp.success {
        return Err(map_plugin_runner_failure(status, resp));
    }
    serde_json::from_str(&resp.output).map_err(|err| {
        PluginRunnerError::Runtime(format!("Invalid plugin start response payload: {err}"))
    })
}

pub async fn dispatch_plugin_stop(
    req: &PluginRunnerStopRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let (status, resp) =
        post_runner_plugin_json("/v1/plugins/stop", req, Duration::from_secs(30)).await?;
    if status != StatusCode::OK || !resp.success {
        return Err(map_plugin_runner_failure(status, resp));
    }
    serde_json::from_str(&resp.output).map_err(|err| {
        PluginRunnerError::Runtime(format!("Invalid plugin stop response payload: {err}"))
    })
}

pub async fn dispatch_plugin_status(
    req: &PluginRunnerStatusRequest,
) -> Result<PluginRunnerStatusResponse, PluginRunnerError> {
    let (status, resp) =
        post_runner_plugin_json("/v1/plugins/status", req, Duration::from_secs(10)).await?;
    if status != StatusCode::OK || !resp.success {
        return Err(map_plugin_runner_failure(status, resp));
    }
    serde_json::from_str(&resp.output).map_err(|err| {
        PluginRunnerError::Runtime(format!("Invalid plugin status response payload: {err}"))
    })
}

pub async fn dispatch_plugin_token_rotate(
    req: &PluginRunnerTokenRotateRequest,
) -> Result<(), PluginRunnerError> {
    let (status, resp) =
        post_runner_plugin_json("/v1/plugins/token", req, Duration::from_secs(10)).await?;
    if status != StatusCode::OK || !resp.success {
        return Err(map_plugin_runner_failure(status, resp));
    }
    Ok(())
}

pub async fn dispatch_heal_restart(service_name: &str) -> anyhow::Result<bool> {
    let req = SystemctlRequest {
        service: service_name.to_string(),
        action: "heal".to_string(),
        lifecycle_job_id: String::new(),
    };
    let result = if is_runner_available() {
        post_runner_json("/v1/systemctl", &req, Duration::from_secs(45)).await?
    } else {
        let (_, Json(result)) = handle_systemctl(Json(req)).await;
        result
    };
    if !result.success {
        anyhow::bail!(
            "runner recovery error: {} ({})",
            result.error,
            result.output
        );
    }
    Ok(result.output != "skipped")
}

pub async fn dispatch_systemctl(service_name: &str, action: &str) -> anyhow::Result<()> {
    let req = SystemctlRequest {
        service: service_name.to_string(),
        action: action.to_string(),
        lifecycle_job_id: current_package_job_id(),
    };
    let result = post_runner_json("/v1/systemctl", &req, Duration::from_secs(45)).await?;
    if !result.success {
        anyhow::bail!(
            "runner systemctl error: {} ({})",
            result.error,
            result.output
        );
    }
    Ok(())
}

pub async fn dispatch_core_restart(service_name: &str) -> anyhow::Result<String> {
    let req = SystemctlRequest {
        service: service_name.into(),
        action: "restart-deferred".into(),
        lifecycle_job_id: String::new(),
    };
    let result = post_runner_json("/v1/systemctl", &req, Duration::from_secs(45)).await?;
    anyhow::ensure!(
        result.success,
        "runner core restart error: {}",
        result.error
    );
    let payload: serde_json::Value = serde_json::from_str(&result.output)?;
    let unit = payload
        .get("job_unit")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    anyhow::ensure!(
        af_models::is_valid_self_update_job_unit_name(unit),
        "Core restart acknowledgment is missing its receipt identity"
    );
    Ok(unit.into())
}

pub(crate) const MAX_PACKAGE_STREAM_LINE_BYTES: usize = 64 * 1024;

#[derive(Default)]
pub(crate) struct IncrementalPackageLineDecoder {
    pub(crate) pending: Vec<u8>,
    discarding_overlong: bool,
    exit_error: Option<String>,
}

impl IncrementalPackageLineDecoder {
    fn handle_line_bytes<F>(&mut self, raw_bytes: &[u8], on_line: &mut F)
    where
        F: FnMut(String),
    {
        let raw_line = String::from_utf8_lossy(raw_bytes);
        let line = raw_line.trim();
        if let Some(message) = line.strip_prefix("__RUNNER_EXIT_ERROR__:") {
            self.exit_error = Some(if message.trim().is_empty() {
                "runner reported package execution failure".to_string()
            } else {
                message.trim().to_string()
            });
        } else if !line.is_empty() {
            on_line(line.to_string());
        }
    }

    pub(crate) fn push_bytes<F>(&mut self, chunk: &[u8], on_line: &mut F)
    where
        F: FnMut(String),
    {
        let mut rest = chunk;
        while !rest.is_empty() {
            if self.discarding_overlong {
                if let Some(nl_pos) = rest.iter().position(|&b| b == b'\n') {
                    self.discarding_overlong = false;
                    let drained = std::mem::take(&mut self.pending);
                    self.handle_line_bytes(&drained, on_line);
                    rest = &rest[nl_pos + 1..];
                } else {
                    return;
                }
            } else if let Some(nl_pos) = rest.iter().position(|&b| b == b'\n') {
                let to_take = &rest[..nl_pos];
                let room = MAX_PACKAGE_STREAM_LINE_BYTES.saturating_sub(self.pending.len());
                self.pending
                    .extend_from_slice(&to_take[..to_take.len().min(room)]);
                let drained = std::mem::take(&mut self.pending);
                self.handle_line_bytes(&drained, on_line);
                rest = &rest[nl_pos + 1..];
            } else {
                let room = MAX_PACKAGE_STREAM_LINE_BYTES.saturating_sub(self.pending.len());
                let take_len = rest.len().min(room);
                self.pending.extend_from_slice(&rest[..take_len]);
                if self.pending.len() >= MAX_PACKAGE_STREAM_LINE_BYTES && rest.len() > take_len {
                    self.discarding_overlong = true;
                }
                return;
            }
        }
    }

    pub(crate) fn finish<F>(mut self, on_line: &mut F) -> anyhow::Result<()>
    where
        F: FnMut(String),
    {
        if !self.pending.is_empty() {
            let drained = std::mem::take(&mut self.pending);
            self.handle_line_bytes(&drained, on_line);
        }
        if let Some(error) = self.exit_error {
            anyhow::bail!("{}", error);
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn consume_package_output<F>(body_text: &str, mut on_line: F) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    let mut decoder = IncrementalPackageLineDecoder::default();
    decoder.push_bytes(body_text.as_bytes(), &mut on_line);
    decoder.finish(&mut on_line)
}

pub async fn dispatch_package_action<F>(
    action: &str,
    pkg_id: &str,
    script_name: &str,
    app_port: i32,
    on_line: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    dispatch_package_action_with_options(action, pkg_id, script_name, app_port, false, on_line)
        .await
}

/// Dispatches a package operation through the runner socket. `delete_data` is
/// only honored for `remove`; it is the sole way to request a destructive purge.
pub async fn dispatch_package_action_with_options<F>(
    action: &str,
    pkg_id: &str,
    script_name: &str,
    app_port: i32,
    delete_data: bool,
    on_line: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    dispatch_package_action_with_target(
        action,
        pkg_id,
        script_name,
        app_port,
        delete_data,
        None,
        on_line,
    )
    .await
}

pub async fn dispatch_package_action_with_target<F>(
    action: &str,
    pkg_id: &str,
    script_name: &str,
    app_port: i32,
    delete_data: bool,
    expected_target_version: Option<String>,
    mut on_line: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    if delete_data && action != "remove" {
        anyhow::bail!("data purge is only valid for package removal");
    }
    #[cfg(unix)]
    {
        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;
        use hyper_util::rt::TokioIo;

        let sock_path = resolve_runner_socket_path();
        let req_payload = PackageRunnerRequest {
            action: action.to_string(),
            package_id: pkg_id.to_string(),
            script_name: script_name.to_string(),
            lifecycle_job_id: current_package_job_id(),
            app_port,
            secondary_port: 0,
            delete_data,
            expected_target_version,
            achieved_version: None,
        };
        let body_bytes = serde_json::to_vec(&req_payload)?;

        let fut = async {
            let stream = tokio::net::UnixStream::connect(&sock_path).await?;
            let io = TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });

            let req = hyper::Request::builder()
                .method(hyper::Method::POST)
                .uri("http://unix/v1/package")
                .header("Host", "unix")
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body_bytes)))?;

            let resp = sender.send_request(req).await?;
            let status = resp.status();
            let mut body = resp.into_body();

            if status != StatusCode::OK {
                let mut err_buf = Vec::new();
                while let Some(frame_res) = body.frame().await {
                    let frame = frame_res?;
                    if let Some(data) = frame.data_ref() {
                        let room = (64 * 1024usize).saturating_sub(err_buf.len());
                        if room == 0 {
                            break;
                        }
                        err_buf.extend_from_slice(&data[..data.len().min(room)]);
                    }
                }
                let body_text = String::from_utf8_lossy(&err_buf);
                anyhow::bail!(
                    "runner rejected package action (HTTP {}): {}",
                    status.as_u16(),
                    body_text.trim()
                );
            }

            let mut decoder = IncrementalPackageLineDecoder::default();
            while let Some(frame_res) = body.frame().await {
                let frame = frame_res?;
                if let Some(data) = frame.data_ref() {
                    decoder.push_bytes(data, &mut on_line);
                }
            }
            decoder.finish(&mut on_line)
        };

        tokio::time::timeout(Duration::from_secs(30 * 60), fut)
            .await
            .map_err(|_| anyhow::anyhow!("runner socket package request timed out"))?
    }
    #[cfg(not(unix))]
    {
        let _ = (
            action,
            pkg_id,
            script_name,
            app_port,
            delete_data,
            &mut on_line,
        );
        anyhow::bail!("UNIX domain socket runner client is only supported on Unix hosts")
    }
}

pub async fn dispatch_package_stream<F>(
    action: &str,
    pkg_id: &str,
    script_name: &str,
    app_port: i32,
    on_line: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    dispatch_package_action(action, pkg_id, script_name, app_port, on_line).await
}

/// Requests cooperative cancellation of an in-flight package operation (`install`, `update`, or `remove`)
/// via the runner socket if available, or directly in-process.
pub async fn dispatch_package_cancel(pkg_id: &str) -> anyhow::Result<bool> {
    if !SAFE_PKG_ID.is_match(pkg_id) || pkg_id.contains("..") {
        anyhow::bail!("invalid package identifier");
    }
    if cancel_package_execution(pkg_id) {
        return Ok(true);
    }
    if is_runner_available() {
        let req = SandboxRunnerRequest {
            package: pkg_id.to_string(),
            package_id: pkg_id.to_string(),
            lifecycle_job_id: current_package_job_id(),
        };
        let result = post_runner_json("/v1/package/cancel", &req, Duration::from_secs(5)).await?;
        return Ok(result.success && result.output.starts_with("cancellation signalled"));
    }
    Ok(false)
}

pub async fn dispatch_package_lifecycle_snapshot_capture(
    pkg_id: &str,
    units: &[String],
) -> anyhow::Result<()> {
    let job_id = current_package_job_id();
    anyhow::ensure!(
        !job_id.trim().is_empty(),
        "lifecycle_job_id is required to capture a runner lifecycle snapshot"
    );
    let req = PackageLifecycleSnapshotRequest {
        action: "capture".to_string(),
        package_id: pkg_id.to_string(),
        lifecycle_job_id: job_id,
        units: units.to_vec(),
        preserve_backup: false,
    };
    let resp = post_runner_json(
        "/v1/package/lifecycle-snapshot",
        &req,
        Duration::from_secs(10 * 60),
    )
    .await?;
    anyhow::ensure!(
        resp.success,
        "runner lifecycle snapshot capture failed: {}",
        resp.error
    );
    Ok(())
}

pub async fn dispatch_package_lifecycle_snapshot_restore(pkg_id: &str) -> anyhow::Result<()> {
    let job_id = current_package_job_id();
    anyhow::ensure!(
        !job_id.trim().is_empty(),
        "lifecycle_job_id is required to restore a runner lifecycle snapshot"
    );
    let req = PackageLifecycleSnapshotRequest {
        action: "restore".to_string(),
        package_id: pkg_id.to_string(),
        lifecycle_job_id: job_id,
        units: Vec::new(),
        preserve_backup: false,
    };
    let resp = post_runner_json(
        "/v1/package/lifecycle-snapshot",
        &req,
        Duration::from_secs(10 * 60),
    )
    .await?;
    anyhow::ensure!(
        resp.success,
        "runner lifecycle snapshot restore failed: {}",
        resp.error
    );
    Ok(())
}

pub async fn dispatch_package_lifecycle_snapshot_discard_for_job(
    pkg_id: &str,
    job_id: &str,
    preserve_backup: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !job_id.trim().is_empty(),
        "lifecycle_job_id is required to discard a runner lifecycle snapshot"
    );
    let req = PackageLifecycleSnapshotRequest {
        action: "discard".to_string(),
        package_id: pkg_id.to_string(),
        lifecycle_job_id: job_id.to_string(),
        units: Vec::new(),
        preserve_backup,
    };
    let resp = post_runner_json(
        "/v1/package/lifecycle-snapshot",
        &req,
        Duration::from_secs(60),
    )
    .await?;
    anyhow::ensure!(
        resp.success,
        "runner lifecycle snapshot discard failed: {}",
        resp.error
    );
    Ok(())
}

pub async fn dispatch_package_lifecycle_snapshot_discard(
    pkg_id: &str,
    preserve_backup: bool,
) -> anyhow::Result<()> {
    let job_id = current_package_job_id();
    dispatch_package_lifecycle_snapshot_discard_for_job(pkg_id, &job_id, preserve_backup).await
}

/// Executes a package operation locally in-process (for CLI/provisioner or direct root execution),
/// streaming newline-delimited progress/log lines to `on_line`.
pub async fn execute_package_local<F>(
    action: &str,
    pkg_id: &str,
    script_name: &str,
    app_port: i32,
    mut on_line: F,
) -> anyhow::Result<()>
where
    F: FnMut(String),
{
    use futures::StreamExt;

    if !matches!(action, "install" | "remove" | "update") {
        anyhow::bail!("disallowed package action");
    }
    if !SAFE_SCRIPT_NAME.is_match(script_name) || !SAFE_SCRIPT_NAME.is_match(pkg_id) {
        anyhow::bail!("invalid script or package identifier");
    }
    if app_port != 0 && !(1024..=65535).contains(&app_port) {
        anyhow::bail!("invalid application port");
    }
    if !script_matches_package_identity(action, pkg_id, script_name) {
        anyhow::bail!("script_name does not match package_id and action");
    }
    if !can_resolve_package_operation(action, pkg_id, script_name) {
        anyhow::bail!("package script not found");
    }

    let req = PackageRunnerRequest {
        action: action.to_string(),
        package_id: pkg_id.to_string(),
        script_name: script_name.to_string(),
        lifecycle_job_id: current_package_job_id(),
        app_port,
        delete_data: false,
        ..Default::default()
    };
    let stream = execute_package_request_stream(req);
    futures::pin_mut!(stream);
    let mut decoder = IncrementalPackageLineDecoder::default();
    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res?;
        decoder.push_bytes(chunk.as_bytes(), &mut on_line);
    }
    decoder.finish(&mut on_line)
}

pub async fn dispatch_self_update_request(
    req: &SelfUpdateRequest,
) -> anyhow::Result<RunnerResponse> {
    if is_runner_available() {
        let result = post_runner_json("/v1/self-update", req, Duration::from_secs(15)).await?;
        if !result.success {
            anyhow::bail!("runner self-update error: {}", result.error);
        }
        return Ok(result);
    }
    let (status, resp) = execute_self_update_request(req, true).await;
    if status != StatusCode::OK || !resp.success {
        anyhow::bail!(
            "self-update failed (HTTP {}): {}",
            status.as_u16(),
            resp.error
        );
    }
    Ok(resp)
}

pub async fn dispatch_self_update_status_request(
    req: &SelfUpdateStatusRequest,
) -> anyhow::Result<SelfUpdateJobStatus> {
    if is_runner_available() {
        let result =
            post_runner_json("/v1/self-update/status", req, Duration::from_secs(10)).await?;
        if !result.success {
            anyhow::bail!("runner self-update status error: {}", result.error);
        }
        let parsed: SelfUpdateJobStatus = serde_json::from_str(&result.output)?;
        return Ok(parsed);
    }
    query_self_update_status_local(&req.job_unit)
        .await
        .map_err(|(_, msg)| anyhow::anyhow!(msg))
}

pub async fn start_self_update(command: &str, channel: &str) -> anyhow::Result<String> {
    let response = dispatch_self_update_request(&SelfUpdateRequest {
        command: command.to_string(),
        channel: channel.to_string(),
    })
    .await?;
    let payload: Value = serde_json::from_str(&response.output)?;
    let job_unit = payload["job_unit"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("updater launch did not acknowledge a job unit"))?;
    validate_self_update_job_unit_name(job_unit)
        .map_err(|(_, message)| anyhow::anyhow!(message))?;
    Ok(job_unit.to_string())
}

pub async fn dispatch_self_update(command: &str, channel: &str) -> anyhow::Result<()> {
    start_self_update(command, channel).await.map(|_| ())
}

pub async fn dispatch_sandbox_apply(pkg_id: &str) -> anyhow::Result<()> {
    let req = SandboxRunnerRequest {
        package: pkg_id.to_string(),
        package_id: pkg_id.to_string(),
        lifecycle_job_id: current_package_job_id(),
    };
    let result = post_runner_json("/v1/sandbox", &req, Duration::from_secs(30)).await?;
    if !result.success {
        anyhow::bail!("runner sandbox error: {}", result.error);
    }
    Ok(())
}

pub async fn dispatch_sandbox(pkg_id: &str) -> anyhow::Result<()> {
    dispatch_sandbox_apply(pkg_id).await
}

pub async fn dispatch_hosts_request(req: &HostsUpdateRequest) -> anyhow::Result<()> {
    let result = post_runner_json("/v1/hosts", req, Duration::from_secs(45)).await?;
    if !result.success {
        anyhow::bail!("runner hosts error: {}", result.error);
    }
    Ok(())
}

pub async fn dispatch_hosts_update(domains: &[String]) -> anyhow::Result<()> {
    let req = HostsUpdateRequest {
        action: "update".to_string(),
        domains: domains.to_vec(),
        ..Default::default()
    };
    dispatch_hosts_request(&req).await
}

pub async fn dispatch_hosts_update_with_provider(
    domains: &[String],
    provider_ip: Option<&str>,
    provider_domains: Option<&[String]>,
) -> anyhow::Result<()> {
    let req = HostsUpdateRequest {
        action: "update".to_string(),
        domains: domains.to_vec(),
        provider_ip: provider_ip.map(|s| s.to_string()),
        provider_domains: provider_domains.map(|d| d.to_vec()),
        ..Default::default()
    };
    dispatch_hosts_request(&req).await
}

pub async fn dispatch_hosts_remove(domains: &[String]) -> anyhow::Result<()> {
    let req = HostsUpdateRequest {
        action: "remove".to_string(),
        domains: domains.to_vec(),
        ..Default::default()
    };
    dispatch_hosts_request(&req).await
}

pub async fn update_hosts_file_via_runner(domains: &[String]) -> anyhow::Result<()> {
    dispatch_hosts_update(domains).await
}

pub async fn remove_hosts_file_via_runner(domains: &[String]) -> anyhow::Result<()> {
    dispatch_hosts_remove(domains).await
}

pub async fn dispatch_hosts_reconcile(domains: &[String], ip: &str) -> anyhow::Result<()> {
    let req = HostsUpdateRequest {
        action: "reconcile".to_string(),
        domains: domains.to_vec(),
        ip: ip.to_string(),
        ..Default::default()
    };
    dispatch_hosts_request(&req).await
}

pub async fn dispatch_hosts_reconcile_with_provider(
    domains: &[String],
    ip: &str,
    provider_ip: Option<&str>,
    provider_domains: Option<&[String]>,
) -> anyhow::Result<()> {
    let req = HostsUpdateRequest {
        action: "reconcile".to_string(),
        domains: domains.to_vec(),
        ip: ip.to_string(),
        provider_ip: provider_ip.map(|s| s.to_string()),
        provider_domains: provider_domains.map(|d| d.to_vec()),
        ..Default::default()
    };
    dispatch_hosts_request(&req).await
}

pub async fn reconcile_hosts_file_via_runner(domains: &[String], ip: &str) -> anyhow::Result<()> {
    dispatch_hosts_reconcile(domains, ip).await
}

pub async fn dispatch_network_control(
    req: &NetworkRunnerRequest,
) -> anyhow::Result<RunnerResponse> {
    let result = post_runner_json("/v1/network", req, Duration::from_secs(60)).await?;
    if !result.success {
        anyhow::bail!("runner network error: {} ({})", result.error, result.output);
    }
    Ok(result)
}

pub async fn dispatch_network_action(req: &NetworkRunnerRequest) -> anyhow::Result<RunnerResponse> {
    dispatch_network_control(req).await
}

#[cfg(unix)]
const MAX_PEER_RUNNER_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[cfg(unix)]
struct ZeroizingByteBuf(Vec<u8>);

#[cfg(unix)]
impl Drop for ZeroizingByteBuf {
    fn drop(&mut self) {
        peer_network::zeroize_bytes(&mut self.0);
        self.0.clear();
    }
}

#[cfg(unix)]
async fn post_runner_peer_network_json(
    req: &PeerNetworkRequest,
    timeout: Duration,
) -> Result<PeerNetworkResponse, PeerNetworkError> {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    const ENDPOINT: &str = "/v1/peer-network";
    let sock_path = resolve_runner_socket_path();
    let body_bytes = serde_json::to_vec(req).map_err(|_| {
        PeerNetworkError::InvalidInput("Failed to serialize peer-network request".to_string())
    })?;

    let fut = async {
        let stream = tokio::net::UnixStream::connect(&sock_path)
            .await
            .map_err(|err| {
                PeerNetworkError::Runtime(format!(
                    "Cannot connect to aetherflow-runner socket '{sock_path}': {err}"
                ))
            })?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|err| {
                    PeerNetworkError::Runtime(format!(
                        "Runner IPC handshake failed on '{sock_path}': {err}"
                    ))
                })?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let http_req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(ENDPOINT)
            .header("Host", "unix")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|err| {
                PeerNetworkError::Runtime(format!("Failed to build peer-network request: {err}"))
            })?;

        let resp = sender.send_request(http_req).await.map_err(|err| {
            PeerNetworkError::Runtime(format!("Runner peer-network request failed: {err}"))
        })?;
        let status = resp.status();
        let error_code = resp
            .headers()
            .get(peer_network::PEER_ERROR_CODE_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        let mut body = resp.into_body();
        let mut raw_body = ZeroizingByteBuf(Vec::new());
        while let Some(frame_res) = body.frame().await {
            let frame = frame_res.map_err(|err| {
                PeerNetworkError::Runtime(format!("Failed reading peer-network response: {err}"))
            })?;
            if let Some(data) = frame.data_ref() {
                if data.len() > MAX_PEER_RUNNER_RESPONSE_BYTES.saturating_sub(raw_body.0.len()) {
                    return Err(PeerNetworkError::Runtime(
                        "Runner peer-network response exceeded maximum size".to_string(),
                    ));
                }
                raw_body.0.extend_from_slice(data);
            }
        }

        let mut decoded: RunnerResponse = serde_json::from_slice(&raw_body.0).map_err(|_| {
            PeerNetworkError::Runtime(format!(
                "Invalid JSON response from runner ({ENDPOINT}, HTTP {})",
                status.as_u16()
            ))
        })?;
        drop(raw_body);

        if status != StatusCode::OK || !decoded.success {
            peer_network::zeroize_string(&mut decoded.output);
            return Err(PeerNetworkError::from_http_response(
                status,
                error_code.as_deref(),
                decoded.error,
            ));
        }

        let typed = peer_network::decode_peer_network_response(req, &decoded.output);
        peer_network::zeroize_string(&mut decoded.output);
        typed
    };

    tokio::time::timeout(timeout, fut).await.map_err(|_| {
        PeerNetworkError::Runtime(format!(
            "Runner peer-network request timed out after {}s ({ENDPOINT})",
            timeout.as_secs()
        ))
    })?
}

#[cfg(not(unix))]
async fn post_runner_peer_network_json(
    _req: &PeerNetworkRequest,
    _timeout: Duration,
) -> Result<PeerNetworkResponse, PeerNetworkError> {
    Err(PeerNetworkError::Runtime(
        "UNIX domain socket runner client is only supported on Unix hosts (/v1/peer-network)"
            .to_string(),
    ))
}

pub async fn dispatch_peer_network(
    req: &PeerNetworkRequest,
) -> Result<PeerNetworkResponse, PeerNetworkError> {
    let timeout = peer_network::client_timeout_for_request(req);
    post_runner_peer_network_json(req, timeout).await
}

#[cfg(unix)]
async fn post_runner_peer_storage_json(
    req: &PeerStorageRequest,
    timeout: Duration,
) -> Result<PeerStorageResponse, PeerStorageError> {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    const ENDPOINT: &str = "/v1/peer-storage";
    let sock_path = resolve_runner_socket_path();
    let body_bytes = serde_json::to_vec(req).map_err(|_| {
        PeerStorageError::InvalidInput("Failed to serialize peer-storage request".to_string())
    })?;

    let fut = async {
        let stream = tokio::net::UnixStream::connect(&sock_path)
            .await
            .map_err(|err| {
                PeerStorageError::Runtime(format!(
                    "Cannot connect to aetherflow-runner socket '{sock_path}': {err}"
                ))
            })?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|err| {
                    PeerStorageError::Runtime(format!(
                        "Runner IPC handshake failed on '{sock_path}': {err}"
                    ))
                })?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let http_req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(ENDPOINT)
            .header("Host", "unix")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|err| {
                PeerStorageError::Runtime(format!("Failed to build peer-storage request: {err}"))
            })?;

        let resp = sender.send_request(http_req).await.map_err(|err| {
            PeerStorageError::Runtime(format!("Runner peer-storage request failed: {err}"))
        })?;
        let status = resp.status();
        let error_code = resp
            .headers()
            .get(peer_network::PEER_ERROR_CODE_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        let mut body = resp.into_body();
        let mut raw_body = Vec::new();
        while let Some(frame_res) = body.frame().await {
            let frame = frame_res.map_err(|err| {
                PeerStorageError::Runtime(format!("Failed reading peer-storage response: {err}"))
            })?;
            if let Some(data) = frame.data_ref() {
                if data.len() > MAX_PEER_RUNNER_RESPONSE_BYTES.saturating_sub(raw_body.len()) {
                    return Err(PeerStorageError::Runtime(
                        "Runner peer-storage response exceeded maximum size".to_string(),
                    ));
                }
                raw_body.extend_from_slice(data);
            }
        }

        let decoded: RunnerResponse = serde_json::from_slice(&raw_body).map_err(|_| {
            PeerStorageError::Runtime(format!(
                "Invalid JSON response from runner ({ENDPOINT}, HTTP {})",
                status.as_u16()
            ))
        })?;

        if status != StatusCode::OK || !decoded.success {
            return Err(PeerStorageError::from_http_response(
                status,
                error_code.as_deref(),
                decoded.error,
            ));
        }

        peer_storage::decode_peer_storage_response(req, &decoded.output)
    };

    tokio::time::timeout(timeout, fut).await.map_err(|_| {
        PeerStorageError::Runtime(format!(
            "Runner peer-storage request timed out after {}s ({ENDPOINT})",
            timeout.as_secs()
        ))
    })?
}

#[cfg(not(unix))]
async fn post_runner_peer_storage_json(
    _req: &PeerStorageRequest,
    _timeout: Duration,
) -> Result<PeerStorageResponse, PeerStorageError> {
    Err(PeerStorageError::Runtime(
        "UNIX domain socket runner client is only supported on Unix hosts (/v1/peer-storage)"
            .to_string(),
    ))
}

pub async fn dispatch_peer_storage(
    req: &PeerStorageRequest,
) -> Result<PeerStorageResponse, PeerStorageError> {
    let timeout = peer_storage::client_timeout_for_request(req);
    post_runner_peer_storage_json(req, timeout).await
}

#[cfg(unix)]
async fn post_runner_peer_transcode_json(
    req: &PeerTranscodeRequest,
    timeout: Duration,
) -> Result<PeerTranscodeResponse, PeerTranscodeError> {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;

    const ENDPOINT: &str = "/v1/peer-transcode";
    let sock_path = resolve_runner_socket_path();
    let body_bytes = serde_json::to_vec(req).map_err(|_| {
        PeerTranscodeError::InvalidInput("Failed to serialize peer-transcode request".to_string())
    })?;

    let fut = async {
        let stream = tokio::net::UnixStream::connect(&sock_path)
            .await
            .map_err(|err| {
                PeerTranscodeError::Runtime(format!(
                    "Cannot connect to aetherflow-runner socket '{sock_path}': {err}"
                ))
            })?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|err| {
                    PeerTranscodeError::Runtime(format!(
                        "Runner IPC handshake failed on '{sock_path}': {err}"
                    ))
                })?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let http_req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(ENDPOINT)
            .header("Host", "unix")
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|err| {
                PeerTranscodeError::Runtime(format!(
                    "Failed to build peer-transcode request: {err}"
                ))
            })?;

        let resp = sender.send_request(http_req).await.map_err(|err| {
            PeerTranscodeError::Runtime(format!("Runner peer-transcode request failed: {err}"))
        })?;
        let status = resp.status();
        let error_code = resp
            .headers()
            .get(peer_network::PEER_ERROR_CODE_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        let mut body = resp.into_body();
        let mut raw_body = Vec::new();
        while let Some(frame_res) = body.frame().await {
            let frame = frame_res.map_err(|err| {
                PeerTranscodeError::Runtime(format!(
                    "Failed reading peer-transcode response: {err}"
                ))
            })?;
            if let Some(data) = frame.data_ref() {
                if data.len() > MAX_PEER_RUNNER_RESPONSE_BYTES.saturating_sub(raw_body.len()) {
                    return Err(PeerTranscodeError::Runtime(
                        "Runner peer-transcode response exceeded maximum size".to_string(),
                    ));
                }
                raw_body.extend_from_slice(data);
            }
        }

        let decoded: RunnerResponse = serde_json::from_slice(&raw_body).map_err(|_| {
            PeerTranscodeError::Runtime(format!(
                "Invalid JSON response from runner ({ENDPOINT}, HTTP {})",
                status.as_u16()
            ))
        })?;

        if status != StatusCode::OK || !decoded.success {
            return Err(PeerTranscodeError::from_http_response(
                status,
                error_code.as_deref(),
                decoded.error,
            ));
        }

        peer_transcode::decode_peer_transcode_response(req, &decoded.output)
    };

    tokio::time::timeout(timeout, fut).await.map_err(|_| {
        PeerTranscodeError::Runtime(format!(
            "Runner peer-transcode request timed out after {}s ({ENDPOINT})",
            timeout.as_secs()
        ))
    })?
}

#[cfg(not(unix))]
async fn post_runner_peer_transcode_json(
    _req: &PeerTranscodeRequest,
    _timeout: Duration,
) -> Result<PeerTranscodeResponse, PeerTranscodeError> {
    Err(PeerTranscodeError::Runtime(
        "UNIX domain socket runner client is only supported on Unix hosts (/v1/peer-transcode)"
            .to_string(),
    ))
}

pub async fn dispatch_peer_transcode(
    req: &PeerTranscodeRequest,
) -> Result<PeerTranscodeResponse, PeerTranscodeError> {
    let timeout = peer_transcode::client_timeout_for_request(req);
    post_runner_peer_transcode_json(req, timeout).await
}

pub async fn dispatch_quota_set(username: &str, size: &str) -> anyhow::Result<()> {
    let req = QuotaRunnerRequest {
        username: username.to_string(),
        size: size.to_string(),
    };
    let result = post_runner_json("/v1/quota", &req, Duration::from_secs(30)).await?;
    if !result.success {
        anyhow::bail!("runner quota error: {} ({})", result.error, result.output);
    }
    Ok(())
}

pub async fn dispatch_set_quota(username: &str, size: &str) -> anyhow::Result<()> {
    dispatch_quota_set(username, size).await
}

pub async fn dispatch_app_meta(app_name: &str) -> anyhow::Result<AppRuntimeMeta> {
    let req = AppMetaRunnerRequest {
        app_name: app_name.to_string(),
    };
    let result = post_runner_json("/v1/app-meta", &req, Duration::from_secs(3)).await?;
    if !result.success {
        anyhow::bail!("runner app-meta error: {}", result.error);
    }
    if result.output.trim().is_empty() {
        return Ok(AppRuntimeMeta::default());
    }
    let mut meta: AppRuntimeMeta = serde_json::from_str(&result.output)?;
    meta.url_base =
        af_models::app_metadata::validate_app_web_path(&meta.url_base).unwrap_or_default();
    Ok(meta)
}
