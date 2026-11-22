use super::*;

/// Schedule core restarts independently so killing the API/runner does not kill
/// the response reporting acceptance. Completion remains a status/readiness check.
pub(crate) fn deferred_restart_arguments(service: &str) -> Result<Vec<String>, String> {
    let service = service.trim_end_matches(".service");
    if !matches!(service, "aetherflow-api" | "aetherflow-runner") {
        return Err("Deferred restart is restricted to core API/runner services".into());
    }
    Ok(vec![
        format!(
            "--unit={}",
            build_self_update_transient_unit_name("restart", service)
        ),
        "--on-active=2s".into(),
        "--timer-property=AccuracySec=100ms".into(),
        "--timer-property=RemainAfterElapse=no".into(),
        "--collect".into(),
        "--quiet".into(),
        "--".into(),
        "/bin/bash".into(),
        "-c".into(),
        include_str!("core_restart_worker.sh").into(),
        "aetherflow-core-restart".into(),
        service.into(),
    ])
}

pub fn is_managed_runner_systemd_unit(raw_unit: &str) -> bool {
    let trimmed = raw_unit.trim();
    if trimmed.is_empty() || !SAFE_SERVICE_NAME.is_match(trimmed) || trimmed.contains("..") {
        return false;
    }
    let strip_suffixes = |s: &str| -> String {
        s.trim()
            .trim_end_matches(".service")
            .trim_end_matches(".timer")
            .trim_end_matches(".socket")
            .to_ascii_lowercase()
    };
    let lower = strip_suffixes(trimmed);
    if lower.is_empty() {
        return false;
    }

    if let Some((prefix, instance)) = lower.split_once('@') {
        // Marketplace ships exactly this Home Assistant instance.
        if matches!(
            trimmed,
            "home-assistant@homeassistant" | "home-assistant@homeassistant.service"
        ) {
            return true;
        }
        if instance.is_empty() {
            return false;
        }
        return matches!(
            prefix,
            "wg-quick"
                | "rtorrent"
                | "deluged"
                | "deluge-web"
                | "qbittorrent-nox"
                | "syncthing"
                | "irssi"
                | "flood"
        );
    }

    if matches!(
        lower.as_str(),
        "aetherflow-api"
            | "aetherflow-runner"
            | "aetherflow-frontend"
            | "apache2"
            | "nginx"
            | "fail2ban"
            | "pihole-ftl"
            | "netdata"
            | "node_exporter"
            | "prometheus"
            | "mariadb"
            | "mysql"
            | "postgresql"
            | "redis"
            | "redis-server"
            | "tailscale"
            | "tailscaled"
            | "wireguard"
            | "mergerfs"
            | "rclone"
            | "rclone-vfs"
            | "deluge"
            | "deluged"
            | "deluge-web"
            | "qbittorrent"
            | "qbittorrent-nox"
            | "rtorrent"
            | "transmission-daemon"
            | "paperless"
            | "paperless-ngx"
            | "paperless-webserver"
            | "paperless-worker"
            | "paperless-scheduler"
            | "scrutiny"
            | "scrutiny-collector"
            | "recyclarr"
            | "dispatcharr"
            | "dispatcharr-celery"
            | "dispatcharr-celerybeat"
            | "novnc"
            | "novnc-xvnc"
            | "novnc-session"
            | "x2goserver"
            | "xrdp"
            | "xrdp-sesman"
            | "vsftpd"
            | "proftpd"
            | "znc"
            | "thelounge"
            | "quasselcore"
            | "syncthing"
            | "maintainerr"
            | "af-maintainerr"
            | "palate"
            | "af-palate"
            | "kasmvnc"
            | "af-kasmvnc"
            | "mcvnc"
            | "af-mcvnc"
    ) {
        return true;
    }

    let Ok(raw_pkgs) = try_load_runner_config_or_embedded(
        "AETHERFLOW_PACKAGES_CONFIG",
        "packages.json",
        EMBEDDED_PACKAGES_JSON,
    ) else {
        return false;
    };
    if let Ok(pkgs) = serde_json::from_str::<Vec<Package>>(&raw_pkgs) {
        for p in &pkgs {
            if strip_suffixes(&p.name) == lower
                || (!p.service_name.trim().is_empty() && strip_suffixes(&p.service_name) == lower)
                || p.sandbox_service_ids
                    .iter()
                    .any(|u| strip_suffixes(u) == lower)
            {
                return true;
            }
        }
    }

    let Ok(raw_auto) = try_load_runner_config_or_embedded(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        "package_automation.json",
        EMBEDDED_AUTOMATION_JSON,
    ) else {
        return false;
    };
    if let Ok(auto_map) = serde_json::from_str::<HashMap<String, PackageAutomation>>(&raw_auto) {
        for (pkg_id, auto) in &auto_map {
            if strip_suffixes(pkg_id) == lower
                || auto
                    .sandbox_service_ids
                    .iter()
                    .any(|u| strip_suffixes(u) == lower)
            {
                return true;
            }
        }
    }

    false
}

pub(crate) async fn handle_systemctl(
    Json(req): Json<SystemctlRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    if !ALLOWED_SERVICE_ACTIONS.contains(req.action.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "disallowed systemctl action".to_string(),
            }),
        );
    }
    if !SAFE_SERVICE_NAME.is_match(&req.service) || req.service.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid service name".to_string(),
            }),
        );
    }
    if !is_managed_runner_systemd_unit(&req.service) {
        return (
            StatusCode::FORBIDDEN,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "unmanaged systemd unit".to_string(),
            }),
        );
    }

    // Automatic recovery shares both locks with privileged package execution.
    // The persistent flock file's existence alone never means a job is active.
    let _heal_mutex;
    let _heal_flock;
    let action = if req.action != "status" {
        _heal_mutex = match PACKAGE_MUTEX.try_lock() {
            Ok(guard) => Some(guard),
            Err(_) => {
                return (
                    if req.action == "heal" {
                        StatusCode::OK
                    } else {
                        StatusCode::CONFLICT
                    },
                    Json(RunnerResponse {
                        success: req.action == "heal",
                        output: if req.action == "heal" { "skipped" } else { "" }.into(),
                        error: if req.action == "heal" {
                            ""
                        } else {
                            "Package lifecycle operation is active"
                        }
                        .into(),
                    }),
                )
            }
        };
        _heal_flock = match package_executor::CrossProcessLockGuard::try_acquire(
            &PackageExecutionEnv::default(),
            "af-heal",
        ) {
            Ok(guard) => Some(guard),
            Err(PackageExecutorError::LockConflict(_)) => {
                return (
                    if req.action == "heal" {
                        StatusCode::OK
                    } else {
                        StatusCode::CONFLICT
                    },
                    Json(RunnerResponse {
                        success: req.action == "heal",
                        output: if req.action == "heal" { "skipped" } else { "" }.into(),
                        error: if req.action == "heal" {
                            ""
                        } else {
                            "Package lifecycle operation is active"
                        }
                        .into(),
                    }),
                )
            }
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: error.to_string(),
                    }),
                )
            }
        };
        if req.action == "heal" {
            "restart"
        } else {
            req.action.as_str()
        }
    } else {
        _heal_mutex = None;
        _heal_flock = None;
        req.action.as_str()
    };

    let _maintenance_guard = if action != "status" {
        match acquire_package_maintenance_guard(
            PackageExecutionEnv::default().fs_root.as_deref(),
            service_reservation_target(&req.service, action),
            &req.lifecycle_job_id,
            None,
        )
        .await
        {
            Ok(guard) => Some(guard),
            Err(error) => {
                return (
                    StatusCode::CONFLICT,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: error.to_string(),
                    }),
                )
            }
        }
    } else {
        None
    };
    if action == "restart-deferred" {
        let mut args = match deferred_restart_arguments(&req.service) {
            Ok(args) => args,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error,
                    }),
                )
            }
        };
        let cfg = match resolve_validated_self_update_config(af_release::ReleaseChannel::Stable) {
            Ok((cfg, _, _)) => cfg,
            Err((code, error)) => {
                return (
                    code,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error,
                    }),
                )
            }
        };
        let lock_path = match resolve_self_update_lock_path_for_cfg(&cfg) {
            Ok(path) => path,
            Err((code, error)) => {
                return (
                    code,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error,
                    }),
                )
            }
        };
        let unit = args[0].trim_start_matches("--unit=").to_string();
        let jobs_dir = match resolve_self_update_jobs_dir_for_cfg(&cfg) {
            Ok(dir) => dir,
            Err((code, error)) => {
                return (
                    code,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error,
                    }),
                )
            }
        };
        let path = jobs_dir.join(format!("{unit}.json"));
        let _launch_owner = match job_receipts::begin_launch(&path) {
            Ok(owner) => owner,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: error.to_string(),
                    }),
                )
            }
        };
        let initial = SelfUpdateJobStatus {
            status: "launching".into(),
            completed: false,
            success: false,
            job_unit: unit.clone(),
            error: String::new(),
            exit_code: None,
        };
        if let Err(error) = write_self_update_job_status_atomic(&path, &initial) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: error.to_string(),
                }),
            );
        }
        args.extend([
            path.to_string_lossy().into_owned(),
            unit.clone(),
            lock_path.to_string_lossy().into_owned(),
            env::var("AETHERFLOW_SYSTEMCTL_BIN").unwrap_or_else(|_| "/usr/bin/systemctl".into()),
        ]);
        #[cfg(unix)]
        match _maintenance_guard.as_ref().unwrap().file_identity() {
            Ok((device, inode)) => args.extend([device.to_string(), inode.to_string()]),
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: error.to_string(),
                    }),
                )
            }
        }
        match _launch_owner.directory_identity() {
            Ok((device, inode)) => args.extend([device.to_string(), inode.to_string()]),
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RunnerResponse {
                        success: false,
                        output: String::new(),
                        error: error.to_string(),
                    }),
                )
            }
        }
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            Command::new("systemd-run")
                .args(args)
                .kill_on_drop(true)
                .output(),
        )
        .await;
        if let Ok(Ok(output)) = &result {
            if output.status.success() {
                let mut running = initial.clone();
                running.status = "running".into();
                let observed = match job_receipts::compare_exchange(&path, &initial, &running) {
                    Ok(observed) => observed,
                    Err(error) => {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(RunnerResponse {
                                success: false,
                                output: String::new(),
                                error: error.to_string(),
                            }),
                        );
                    }
                };
                if observed.completed && !observed.success {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(RunnerResponse {
                            success: false,
                            output: String::new(),
                            error:
                                "Core restart already failed; inspect its receipt and service logs."
                                    .into(),
                        }),
                    );
                }
                return (
                    StatusCode::ACCEPTED,
                    Json(RunnerResponse {
                        success: true,
                        output: json!({
                            "status": if observed.completed { observed.status.as_str() } else { "accepted" },
                            "job_unit": unit,
                            "completed": observed.completed,
                            "success": observed.success,
                        }).to_string(),
                        error: String::new(),
                    }),
                );
            }
        }
        let error = format!("Could not schedule core restart: {:?}", result);
        if result.is_ok() {
            let failure = SelfUpdateJobStatus {
                status: "failed".into(),
                completed: true,
                success: false,
                job_unit: unit,
                error: error.clone(),
                exit_code: Some(1),
            };
            let _ = job_receipts::compare_exchange(&path, &initial, &failure);
        }
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error,
            }),
        );
    }

    let mut command = Command::new("systemctl");
    command
        .arg(action)
        .arg("--")
        .arg(&req.service)
        .kill_on_drop(true);
    #[cfg(unix)]
    if let Some(guard) = &_maintenance_guard {
        if let Err(error) = guard.preserve_in_child(command.as_std_mut()) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: error.to_string(),
                }),
            );
        }
    }
    match bounded_command::output(command, Duration::from_secs(40), 1024 * 1024).await {
        Ok(out) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if out.status.success() {
                (
                    StatusCode::OK,
                    Json(RunnerResponse {
                        success: true,
                        output: combined,
                        error: String::new(),
                    }),
                )
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RunnerResponse {
                        success: false,
                        output: combined,
                        error: format!("exit status: {}", out.status),
                    }),
                )
            }
        }
        Err(error) => (
            if error.kind() == std::io::ErrorKind::TimedOut {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            },
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: error.to_string(),
            }),
        ),
    }
}

pub(crate) async fn handle_package(Json(req): Json<PackageRunnerRequest>) -> Response {
    if !matches!(
        req.action.as_str(),
        "install" | "reinstall" | "remove" | "update"
    ) {
        return (StatusCode::BAD_REQUEST, "disallowed package action").into_response();
    }
    if !SAFE_SCRIPT_NAME.is_match(&req.script_name) || !SAFE_SCRIPT_NAME.is_match(&req.package_id) {
        return (
            StatusCode::BAD_REQUEST,
            "invalid script or package identifier",
        )
            .into_response();
    }
    if req.app_port != 0 && !(1024..=65535).contains(&req.app_port) {
        return (StatusCode::BAD_REQUEST, "invalid application port").into_response();
    }
    if req.secondary_port != 0
        && (!(1..=65535).contains(&req.secondary_port)
            || req.package_id != "rclone"
            || req.action == "remove"
            || (req.app_port != 0 && req.secondary_port == req.app_port))
    {
        return (StatusCode::BAD_REQUEST, "invalid secondary port").into_response();
    }
    if req.delete_data && req.action != "remove" {
        return (
            StatusCode::BAD_REQUEST,
            "data purge is only valid for package removal",
        )
            .into_response();
    }
    if !script_matches_package_identity(&req.action, &req.package_id, &req.script_name) {
        return (
            StatusCode::BAD_REQUEST,
            "script_name does not match package_id and action",
        )
            .into_response();
    }

    if !can_resolve_package_operation(&req.action, &req.package_id, &req.script_name) {
        return (StatusCode::NOT_FOUND, "package script not found").into_response();
    }

    let engine = select_package_engine(&req.package_id);
    let stream = package_lifecycle::execute_coordinated_package_stream(req);

    let mut resp = Response::new(Body::from_stream(stream));
    resp.headers_mut().insert(
        "Content-Type",
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.headers_mut().insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    resp.headers_mut().insert(
        "X-AetherFlow-Package-Engine",
        HeaderValue::from_static(match engine {
            PackageEngineMode::DeclarativeRust => "declarative_rust",
            PackageEngineMode::LegacyBashFallback => "legacy_bash_fallback",
        }),
    );
    resp
}

pub(crate) async fn handle_package_cancel(
    Json(req): Json<SandboxRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let pkg = if !req.package_id.trim().is_empty() {
        req.package_id.trim().to_string()
    } else {
        req.package.trim().to_string()
    };
    if !SAFE_PKG_ID.is_match(&pkg) || pkg.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid package identifier".to_string(),
            }),
        );
    }

    let signalled = cancel_package_execution(&pkg);
    (
        StatusCode::OK,
        Json(RunnerResponse {
            success: true,
            output: if signalled {
                format!("cancellation signalled for {}", pkg)
            } else {
                format!("no active package execution for {}", pkg)
            },
            error: String::new(),
        }),
    )
}

pub(crate) async fn handle_package_lifecycle_snapshot(
    Json(req): Json<PackageLifecycleSnapshotRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    let pkg = req.package_id.trim();
    let job_id = req.lifecycle_job_id.trim();
    let action = req.action.trim();
    if pkg.is_empty() || !SAFE_PKG_ID.is_match(pkg) || pkg.contains("..") {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid package identifier".into(),
            }),
        );
    }
    if job_id.is_empty()
        || job_id.len() > 128
        || job_id.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid lifecycle_job_id".into(),
            }),
        );
    }
    if req
        .units
        .iter()
        .any(|u| u.trim().is_empty() || !SAFE_SERVICE_NAME.is_match(u.trim()) || u.contains(".."))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(RunnerResponse {
                success: false,
                output: String::new(),
                error: "invalid systemd unit name in snapshot request".into(),
            }),
        );
    }

    let result = match action {
        "capture" => {
            package_lifecycle::capture_admitted_lifecycle_snapshot(pkg, job_id, &req.units)
                .await
                .map(|()| "snapshot captured".to_string())
        }
        "restore" => package_lifecycle::restore_admitted_lifecycle_snapshot(pkg, job_id)
            .await
            .map(|()| "snapshot restored".to_string()),
        "discard" => {
            package_lifecycle::discard_admitted_lifecycle_snapshot(pkg, job_id, req.preserve_backup)
                .await
                .map(|discarded| {
                    if discarded {
                        "snapshot discarded".to_string()
                    } else {
                        "no active snapshot".to_string()
                    }
                })
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: "disallowed lifecycle snapshot action".into(),
                }),
            );
        }
    };

    match result {
        Ok(output) => (
            StatusCode::OK,
            Json(RunnerResponse {
                success: true,
                output,
                error: String::new(),
            }),
        ),
        Err(err) => {
            let status = if is_lifecycle_busy(&err) {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: af_models::secret_redaction::redact_diagnostic(&err.to_string())
                        .into_owned(),
                }),
            )
        }
    }
}
