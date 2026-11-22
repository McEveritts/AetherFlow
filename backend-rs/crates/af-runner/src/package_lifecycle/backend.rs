use super::admitted_snapshots::{
    package_definition, package_service_units, LifecycleReceipt, JOB_MARKER, RECEIPT_MARKER,
};
use super::coordinator::CoordinatedOperation;
use af_models::{PackageRunnerRequest, SystemctlRequest};
use af_release::lifecycle;
use anyhow::{Context, Result};
use futures::{future::BoxFuture, StreamExt};
use rusqlite::Connection;
use std::time::Duration;
use tokio::sync::mpsc;

pub(super) async fn run_direct(
    request: PackageRunnerRequest,
    sender: &mpsc::Sender<String>,
) -> Result<LifecycleReceipt> {
    let package = package_definition(&request.package_id)?;
    let units = package_service_units(&request.package_id)?;
    let environment = crate::PackageExecutionEnv::default();
    let root = environment.fs_root.as_deref();
    let conf = af_release::resolve_release_manager_conf_for_root(root);
    let cfg = af_release::ReleaseConfig::load_for_root_from_process_env(root, conf.as_deref())?;
    let database = af_release::config::try_resolve_db_path(&cfg, None)?.path;
    let guard = crate::acquire_package_maintenance_guard(
        root,
        lifecycle::ReservationTarget::Package(&request.package_id),
        "",
        Some(&request.action),
    )
    .await?;
    if request.action == "update" {
        let installed = af_models::inspect_canonical_package_receipt(
            &package.name,
            Some(&package.lock_file),
            environment.fs_root.as_deref(),
        )
        .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            installed,
            "Package must be installed before it can be updated"
        );
    }
    let conn = Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    if request.action == "remove" && request.delete_data {
        let inspection = crate::inspect_package_purge_state_with_conn(
            &package.name,
            Some(&package.lock_file),
            environment.fs_root.as_deref(),
            Some(&conn),
        )
        .map_err(anyhow::Error::msg)?;
        match inspection.eligibility {
            crate::PackagePurgeEligibility::Installed
            | crate::PackagePurgeEligibility::RetainedProven => {}
            crate::PackagePurgeEligibility::AmbiguousMarkerless => {
                anyhow::bail!("{}", crate::format_ambiguous_purge_error(&inspection));
            }
            crate::PackagePurgeEligibility::NotPresent => {
                anyhow::bail!(
                    "Package '{}' is not installed and has no recognized retained AetherFlow installation to purge",
                    package.name
                );
            }
        }
    }
    let mut operation = CoordinatedOperation::admit(conn, request, package, units)?;
    drop(guard);
    let identity = serde_json::json!({
        "job_id": operation.request.lifecycle_job_id,
        "package_id": operation.request.package_id,
        "action": operation.request.action,
    });
    let _ = sender.send(format!("{JOB_MARKER}{identity}\n")).await;
    operation.execute(&HostBackend, sender).await
}

pub(super) trait LifecycleBackend: Send + Sync {
    fn runtime_port(&self, package: &str) -> i32;
    fn available_port(&self, port: i32) -> bool;
    fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>>;
    fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move { Ok(!self.active(unit).await?) })
    }
    fn control<'a>(
        &'a self,
        unit: &'a str,
        action: &'a str,
        identity: &'a str,
    ) -> BoxFuture<'a, Result<()>>;
    fn script<'a>(
        &'a self,
        request: &'a PackageRunnerRequest,
        sender: &'a mpsc::Sender<String>,
    ) -> BoxFuture<'a, Result<()>>;
}

pub(super) struct HostBackend;

impl LifecycleBackend for HostBackend {
    fn runtime_port(&self, package: &str) -> i32 {
        crate::extract_app_runtime_meta_local(package).configured_port
    }

    fn available_port(&self, port: i32) -> bool {
        (1024..=65535).contains(&port)
            && std::net::TcpListener::bind(("127.0.0.1", port as u16)).is_ok()
    }

    fn active<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            use tokio::io::AsyncReadExt;
            let mut child = tokio::process::Command::new("systemctl")
                .args(["show", "--property=ActiveState", "--value", "--", unit])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let mut stdout = child
                .stdout
                .take()
                .context("Application status pipe missing")?
                .take(65);
            let mut bytes = Vec::new();
            let read = tokio::time::timeout(Duration::from_secs(5), async {
                stdout.read_to_end(&mut bytes).await?;
                child.wait().await
            })
            .await;
            let status = match read {
                Ok(Ok(status)) => status,
                error => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    anyhow::bail!("Cannot confirm application service state: {error:?}");
                }
            };
            anyhow::ensure!(
                status.success() && bytes.len() < 65,
                "Cannot inspect application service state"
            );
            let status = String::from_utf8(bytes)?;
            parse_systemd_active_state(&status)
        })
    }

    fn quiescent<'a>(&'a self, unit: &'a str) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            let output = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::process::Command::new("systemctl")
                    .args(["is-active", "--", unit])
                    .output(),
            )
            .await;
            let output = match output {
                Ok(Ok(out)) => out,
                error => {
                    anyhow::bail!("Cannot confirm application service state: {error:?}");
                }
            };
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            let status = stdout_str.trim();
            if !status.is_empty() {
                if let Ok(quiesced) = parse_systemd_quiesced_state(status) {
                    return Ok(quiesced);
                }
            }
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            let stderr_lower = stderr_str.to_ascii_lowercase();
            if status.is_empty()
                && (stderr_lower.contains("not found")
                    || stderr_lower.contains("not-found")
                    || stderr_lower.contains("not loaded")
                    || stderr_lower.contains("could not be found")
                    || stderr_lower.contains("no such file"))
            {
                if let Ok(Ok(show_out)) = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::process::Command::new("systemctl")
                        .args([
                            "show",
                            "--property=LoadState,ActiveState",
                            "--value",
                            "--",
                            unit,
                        ])
                        .output(),
                )
                .await
                {
                    if show_out.status.success() {
                        let text = String::from_utf8_lossy(&show_out.stdout);
                        let lines: Vec<&str> = text
                            .lines()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .collect();
                        if (lines.first() == Some(&"not-found")
                            || text.contains("LoadState=not-found"))
                            && (lines.get(1) == Some(&"inactive")
                                || text.contains("ActiveState=inactive"))
                        {
                            return Ok(true);
                        }
                    }
                }
            }
            parse_systemd_quiesced_state(status)
        })
    }

    fn control<'a>(
        &'a self,
        unit: &'a str,
        action: &'a str,
        identity: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let (_, axum::Json(response)) = crate::handle_systemctl(axum::Json(SystemctlRequest {
                action: action.into(),
                service: unit.into(),
                lifecycle_job_id: identity.into(),
            }))
            .await;
            if !response.success {
                if action == "stop" {
                    if let Ok(Ok(output)) = tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::process::Command::new("systemctl")
                            .args([
                                "show",
                                "--property=LoadState,ActiveState,SubState",
                                "--value",
                                "--",
                                unit,
                            ])
                            .output(),
                    )
                    .await
                    {
                        if output.status.success() {
                            let text = String::from_utf8_lossy(&output.stdout);
                            let lines: Vec<&str> = text
                                .lines()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .collect();
                            if lines.len() >= 2
                                && (lines[0] == "not-found" || text.contains("LoadState=not-found"))
                                && (lines[1] == "inactive" || text.contains("ActiveState=inactive"))
                                && (lines.len() < 3
                                    || lines[2] == "dead"
                                    || text.contains("SubState=dead"))
                            {
                                return Ok(());
                            }
                        }
                    }
                }
                anyhow::bail!("Application service {action} failed: {}", response.error);
            }
            Ok(())
        })
    }

    fn script<'a>(
        &'a self,
        request: &'a PackageRunnerRequest,
        sender: &'a mpsc::Sender<String>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let stream = crate::execute_package_request_stream(request.clone());
            tokio::pin!(stream);
            let mut error = None;
            while let Some(line) = stream.next().await {
                let line = line?;
                if let Some(reason) = line.trim().strip_prefix("__RUNNER_EXIT_ERROR__:") {
                    error = Some(reason.to_owned());
                } else {
                    let line = if line.trim().starts_with(JOB_MARKER)
                        || line.trim().starts_with(RECEIPT_MARKER)
                    {
                        format!("[LOG] {line}")
                    } else {
                        line
                    };
                    let _ = sender.try_send(line);
                }
            }
            if let Some(error) = error {
                anyhow::bail!("{error}");
            }
            Ok(())
        })
    }
}

pub(crate) fn parse_systemd_active_state(status: &str) -> Result<bool> {
    match status.trim() {
        "active" => Ok(true),
        "inactive" | "failed" | "activating" | "deactivating" | "reloading" => Ok(false),
        _ => anyhow::bail!("Application service state is unknown"),
    }
}

pub(crate) fn parse_systemd_quiesced_state(status: &str) -> Result<bool> {
    match status.trim() {
        "inactive" | "failed" => Ok(true),
        "active" | "reloading" | "activating" | "deactivating" => Ok(false),
        _ => anyhow::bail!("Application service state is unknown"),
    }
}

pub fn is_incomplete_rollback_error(err_msg: &str) -> bool {
    let lower = err_msg.to_ascii_lowercase();
    lower.contains("incomplete rollback")
        || lower.contains("incomplete-rollback")
        || lower.contains("incomplete_rollback")
        || lower.contains("incomplete recovery")
        || lower.contains("recovery backup preserved")
        || lower.contains("failed to stop")
}
