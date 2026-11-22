use super::*;

#[cfg(unix)]
pub(crate) const RUNNER_SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(45);

#[cfg(unix)]
pub(crate) async fn dispatch_runner_systemctl_unix(
    action: &str,
    unit: &str,
) -> Option<anyhow::Result<()>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let sock_path = af_runner::runner_socket_path();
    if !Path::new(&sock_path).exists() {
        return None;
    }
    let mut stream =
        match tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(&sock_path)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

    let body = serde_json::to_string(&af_models::SystemctlRequest {
        action: action.to_string(),
        service: unit.to_string(),
        lifecycle_job_id: af_runner::current_package_job_id(),
    })
    .ok()?;
    let req = format!(
        "POST /v1/systemctl HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    match tokio::time::timeout(Duration::from_secs(5), stream.write_all(req.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return Some(Err(anyhow::Error::from(error).context(
                "runner request transmission failed; service state is unconfirmed",
            )))
        }
        Err(_) => {
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "runner request transmission timed out; service state is unconfirmed",
            )
            .into()))
        }
    }

    let mut resp = String::new();
    match tokio::time::timeout(
        RUNNER_SYSTEMCTL_TIMEOUT,
        stream.take(1024 * 1024 + 1).read_to_string(&mut resp),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Some(Err(anyhow::anyhow!(
                "runner socket read error for systemctl {} {}: {}",
                action,
                unit,
                e
            )));
        }
        Err(_) => {
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("runner socket timed out after {}s waiting for systemctl {} {}; resulting state is unconfirmed", RUNNER_SYSTEMCTL_TIMEOUT.as_secs(), action, unit),
            ).into()));
        }
    }

    Some(validate_runner_systemctl_response(&resp))
}

#[cfg(unix)]
pub(crate) fn validate_runner_systemctl_response(response: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        response.len() <= 1024 * 1024,
        "runner response exceeds acknowledgement limit; service state is unconfirmed"
    );
    let (headers, json_body) = response.split_once("\r\n\r\n").ok_or_else(|| {
        anyhow::anyhow!("malformed runner response; service state is unconfirmed")
    })?;
    let mut lines = headers.split("\r\n");
    let mut status_line = lines.next().unwrap_or_default().split_whitespace();
    anyhow::ensure!(
        matches!(status_line.next(), Some("HTTP/1.0" | "HTTP/1.1")),
        "invalid runner HTTP version; service state is unconfirmed"
    );
    let status = status_line.next().unwrap_or_default();
    anyhow::ensure!(
        status.len() == 3 && status.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid runner HTTP status; service state is unconfirmed"
    );
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("malformed runner header; service state is unconfirmed")
        })?;
        anyhow::ensure!(
            !name.eq_ignore_ascii_case("transfer-encoding"),
            "unsupported runner acknowledgement framing; service state is unconfirmed"
        );
        if name.eq_ignore_ascii_case("content-length") {
            anyhow::ensure!(
                content_length.is_none(),
                "duplicate runner content length; service state is unconfirmed"
            );
            content_length = Some(value.trim().parse::<usize>()?);
        }
    }
    anyhow::ensure!(
        content_length == Some(json_body.len()),
        "missing or incomplete runner acknowledgement body; service state is unconfirmed"
    );
    if status == "504" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "runner service control timed out; resulting state is unconfirmed",
        )
        .into());
    }
    if status == "409" {
        return Err(af_runner::LifecycleBusy.into());
    }
    let parsed: af_models::RunnerResponse = serde_json::from_str(json_body).map_err(|error| {
        anyhow::anyhow!("invalid runner acknowledgement; service state is unconfirmed: {error}")
    })?;
    anyhow::ensure!(
        status == "200" && parsed.success && parsed.error.trim().is_empty(),
        "runner service control refused (HTTP {}): {} {}",
        status,
        parsed.error.trim(),
        parsed.output.trim()
    );
    Ok(())
}

pub(crate) fn guarded_service_command(
    guard: &af_release::ReleaseLockGuard,
    program: &str,
    arguments: &[&str],
) -> anyhow::Result<Command> {
    #[cfg(unix)]
    {
        let mut command = Command::new("/bin/bash");
        command
            .args([
                "-c",
                "(exec {AF_MAINTENANCE_GUARD_FD}>&-; exec \"$@\"); result=$?; exit \"$result\"",
                "af-service-control",
            ])
            .arg(program)
            .args(arguments);
        let descriptor = guard.preserve_in_child(command.as_std_mut())?;
        command.env("AF_MAINTENANCE_GUARD_FD", descriptor.to_string());
        Ok(command)
    }
    #[cfg(not(unix))]
    {
        let _ = guard;
        let mut command = Command::new(program);
        command.args(arguments);
        Ok(command)
    }
}

pub(crate) const SERVICE_CONTROL_BUDGET: Duration = Duration::from_secs(20);

pub fn is_service_control_timeout(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
    })
}

pub(crate) async fn service_command_output(
    command: Command,
    budget: Duration,
) -> std::io::Result<std::process::Output> {
    let result = af_runner::bounded_command::output(command, budget, 1024 * 1024).await;
    clear_service_status_cache();
    result
}

pub(crate) fn is_absent_systemd_unit_error(err_msg: &str) -> bool {
    let lower = err_msg.to_ascii_lowercase();
    lower.contains("not loaded")
        || lower.contains("not-found")
        || lower.contains("not found")
        || lower.contains("no such file")
        || lower.contains("could not be found")
        || lower.contains("exit status: 5")
        || lower.contains("exit code 5")
}

pub(crate) async fn confirm_systemd_unit_not_found(unit: &str, timeout: Duration) -> bool {
    #[cfg(target_os = "linux")]
    {
        if timeout.is_zero() {
            return false;
        }
        match async_status_command_output(
            "systemctl",
            &["show", unit, "--property=LoadState,ActiveState,SubState"],
            timeout.min(Duration::from_secs(2)),
        )
        .await
        {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                classify_systemd_unit_show_output(&stdout, "optional").0 == "not-found"
            }
            _ => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (unit, timeout);
        false
    }
}

pub async fn control_service_with_manager(
    service_name: &str,
    action: &str,
    managed_by: &str,
) -> anyhow::Result<()> {
    control_service_with_budget(service_name, action, managed_by, SERVICE_CONTROL_BUDGET).await
}

pub(crate) async fn control_service_with_budget(
    service_name: &str,
    action: &str,
    managed_by: &str,
    budget: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + budget;
    let valid_name = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9@._-]{0,63}$").unwrap();
    if !valid_name.is_match(service_name) {
        anyhow::bail!("invalid service name: {}", service_name);
    }
    if !matches!(action, "start" | "stop" | "restart" | "reload" | "status") {
        anyhow::bail!("disallowed action: {}", action);
    }

    if managed_by.eq_ignore_ascii_case("pm2") {
        let _guard = af_runner::acquire_service_maintenance_guard(service_name, action).await?;
        let command = guarded_service_command(&_guard, "pm2", &[action, service_name])?;
        let out =
            service_command_output(command, deadline.saturating_duration_since(Instant::now()))
                .await?;
        clear_service_status_cache();
        if out.status.success() {
            return Ok(());
        }
        anyhow::bail!(
            "pm2 {} {} failed: {}",
            action,
            service_name,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let canonical = resolve_canonical_service_id(service_name);
    if resolve_service_control_scope(&canonical) == "shared-vhost" {
        anyhow::bail!(
            "{} is hosted as a shared Apache virtual host; use the Apache2 Web Server card for daemon-wide controls",
            service_name
        );
    }
    let allow_absent_legacy_companion = managed_by != "systemd-unit";
    let units = if managed_by == "systemd-unit" {
        vec![service_name.to_string()]
    } else {
        let mut resolved = resolve_controllable_service_units(&canonical, action);
        if canonical != "apache2" {
            resolved.retain(|u| {
                !u.trim_end_matches(".service")
                    .eq_ignore_ascii_case("apache2")
            });
        }
        if resolved.is_empty() {
            anyhow::bail!(
                "{} has no independent systemd unit to {}",
                service_name,
                action
            );
        }
        resolved
    };
    for unit in units {
        if !valid_name.is_match(&unit) {
            anyhow::bail!("invalid resolved unit name: {}", unit);
        }

        #[cfg(unix)]
        match dispatch_runner_systemctl_unix(action, &unit).await {
            Some(Ok(())) => continue,
            Some(Err(err_msg)) => {
                if allow_absent_legacy_companion
                    && af_release::lifecycle::is_legacy_optional_companion_unit(&unit)
                    && is_absent_systemd_unit_error(&err_msg.to_string())
                    && confirm_systemd_unit_not_found(
                        &unit,
                        deadline.saturating_duration_since(Instant::now()),
                    )
                    .await
                {
                    continue;
                }
                clear_service_status_cache();
                let detail = format!("systemctl {} {} failed: {}", action, unit, err_msg);
                return Err(err_msg.context(detail));
            }
            None => {}
        }

        let _guard = af_runner::acquire_service_maintenance_guard(&unit, action).await?;
        let command =
            guarded_service_command(&_guard, "sudo", &["-n", "systemctl", action, "--", &unit])?;
        let out =
            service_command_output(command, deadline.saturating_duration_since(Instant::now()))
                .await;
        match out {
            Ok(o) if o.status.success() => continue,
            // Timeout/output overflow is an unconfirmed mutation, not permission
            // failure. Do not execute the same action again through fallback.
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            Ok(o)
                if allow_absent_legacy_companion
                    && af_release::lifecycle::is_legacy_optional_companion_unit(&unit)
                    && (o.status.code() == Some(5)
                        || is_absent_systemd_unit_error(&String::from_utf8_lossy(&o.stderr)))
                    && confirm_systemd_unit_not_found(
                        &unit,
                        deadline.saturating_duration_since(Instant::now()),
                    )
                    .await =>
            {
                continue;
            }
            _ => {
                let command =
                    guarded_service_command(&_guard, "systemctl", &[action, "--", &unit])?;
                let direct = service_command_output(
                    command,
                    deadline.saturating_duration_since(Instant::now()),
                )
                .await?;
                if !direct.status.success() {
                    let stderr_str = String::from_utf8_lossy(&direct.stderr);
                    if allow_absent_legacy_companion
                        && af_release::lifecycle::is_legacy_optional_companion_unit(&unit)
                        && (direct.status.code() == Some(5)
                            || is_absent_systemd_unit_error(&stderr_str))
                        && confirm_systemd_unit_not_found(
                            &unit,
                            deadline.saturating_duration_since(Instant::now()),
                        )
                        .await
                    {
                        continue;
                    }
                    clear_service_status_cache();
                    anyhow::bail!("systemctl {} {} failed: {}", action, unit, stderr_str);
                }
            }
        }
    }

    clear_service_status_cache();
    Ok(())
}

pub async fn control_service(service_name: &str, action: &str) -> anyhow::Result<()> {
    let managed_by = get_package_catalog()
        .unwrap_or_default()
        .into_iter()
        .find(|p| {
            p.name.eq_ignore_ascii_case(service_name)
                || p.service_name.eq_ignore_ascii_case(service_name)
        })
        .map(|p| {
            if p.service_type == "pm2" {
                "pm2".to_string()
            } else {
                "systemd".to_string()
            }
        })
        .unwrap_or_else(|| "systemd".to_string());

    control_service_with_manager(service_name, action, &managed_by).await
}

pub async fn runner_systemctl(action: &str, unit: &str) -> anyhow::Result<()> {
    control_service_with_manager(unit, action, "systemd-unit").await
}
