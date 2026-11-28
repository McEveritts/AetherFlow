use super::*;

/// Authorizes a UNIX domain socket peer (`SO_PEERCRED` / `UCred`) connecting to the privileged runner.
///
/// Permits:
/// - `uid == 0` (root)
/// - `uid == euid` (same effective user running the runner process)
/// - the `aetherflow` service user UID resolved via thread-safe `getpwnam_r` on Unix
/// - any explicit UID listed in `AETHERFLOW_ALLOWED_RUNNER_UIDS` (comma-separated)
///
/// Furthermore, destructive endpoints (`/v1/self-update`, `/v1/backup` with `restore_execute` or `delete`)
/// require either `uid == 0`, `uid == euid`, the `aetherflow` service account, or an explicitly authorized UID.
#[cfg(unix)]
pub(crate) fn lookup_passwd_uid_reentrant(username: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(username).ok()?;
    let mut buf_len = 1024usize;
    const MAX_BUF_LEN: usize = 16 * 1024;
    while buf_len <= MAX_BUF_LEN {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; buf_len];
        let rc = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut res,
            )
        };
        if rc == 0 {
            if res.is_null() {
                return None;
            }
            return Some(pwd.pw_uid as u32);
        }
        if rc == libc::ERANGE {
            buf_len *= 2;
            continue;
        }
        return None;
    }
    None
}

pub fn authorize_runner_peer_credentials(
    peer_uid: u32,
    peer_gid: u32,
    endpoint_path: &str,
) -> Result<(), (StatusCode, String)> {
    #[cfg(unix)]
    let self_euid = unsafe { libc::geteuid() as u32 };
    #[cfg(not(unix))]
    let self_euid = 0u32;

    if peer_uid == 0 || peer_uid == self_euid {
        return Ok(());
    }

    if let Ok(raw_uids) = env::var("AETHERFLOW_ALLOWED_RUNNER_UIDS") {
        for token in raw_uids.split(',') {
            if let Ok(allowed_uid) = token.trim().parse::<u32>() {
                if peer_uid == allowed_uid {
                    return Ok(());
                }
            }
        }
    }

    #[cfg(unix)]
    {
        if let Some(af_uid) = lookup_passwd_uid_reentrant("aetherflow") {
            if peer_uid == af_uid {
                return Ok(());
            }
        }
    }

    Err((
        StatusCode::FORBIDDEN,
        format!(
            "unauthorized unix socket peer uid={} gid={} for endpoint {}",
            peer_uid, peer_gid, endpoint_path
        ),
    ))
}

#[cfg(unix)]
pub(crate) fn authorize_runner_socket_peer(
    uid: u32,
    gid: u32,
    pid: Option<i32>,
    endpoint: &str,
) -> Result<(), (StatusCode, String)> {
    authorize_runner_peer_credentials(uid, gid, endpoint)?;
    #[cfg(target_os = "linux")]
    if uid != 0 && !pid.is_some_and(trusted_runner_peer_exe) {
        return Err((
            StatusCode::FORBIDDEN,
            "untrusted runner peer executable".into(),
        ));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = pid;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn trusted_runner_peer_exe(pid: i32) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    if exe
        .components()
        .any(|component| component.as_os_str() == "plugins")
    {
        return false;
    }
    let Some(name) = exe.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if name.starts_with("python") || matches!(name, "bash" | "sh" | "dash" | "node") {
        return false;
    }
    if env::current_exe()
        .and_then(fs::canonicalize)
        .is_ok_and(|path| path == exe)
    {
        return true;
    }
    #[cfg(test)]
    if exe
        .components()
        .any(|component| component.as_os_str() == "deps")
    {
        return true;
    }
    // A basename alone can be chosen by an unprivileged caller. Require a
    // root-owned executable and directory chain for the named control-plane binaries.
    matches!(name, "aetherflow-api" | "af")
        && exe.is_absolute()
        && exe.ancestors().all(|path| {
            fs::symlink_metadata(path).is_ok_and(|meta| {
                !meta.file_type().is_symlink() && meta.uid() == 0 && meta.mode() & 0o022 == 0
            })
        })
}

/// Register both termination signals before serving requests. Shared by API and runner.
pub fn shutdown_signal() -> anyhow::Result<impl std::future::Future<Output = ()> + Send> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        Ok(async move {
            tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        })
    }
    #[cfg(not(unix))]
    {
        Ok(async {
            let _ = tokio::signal::ctrl_c().await;
        })
    }
}

/// Total daemon shutdown drain budget (`SEC-02`), strictly below systemd's
/// `TimeoutStopSec=30s` so both active connections and tracked process-group
/// supervisors finish reaping before `SIGKILL`.
#[cfg(unix)]
pub(crate) const RUNNER_DRAIN_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(unix)]
const RUNNER_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(15);

/// Runs the Privileged Root Daemon (`aetherflow-api runner` / `--runner`) over `/run/aetherflow/runner.sock`.
#[cfg(unix)]
pub async fn run_privileged_daemon() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let sock_path = runner_socket_path();
    if let Some(dir) = Path::new(&sock_path).parent() {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        if unsafe { libc::geteuid() == 0 } {
            // Keep /run/aetherflow non-group-writable (0750 root:aetherflow) to prevent lock DoS,
            // and pre-create shared 0660 root:aetherflow lockfiles for aetherflow-api access.
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o750));
            for lock_name in [".snapshot.lock", "hosts.lock"] {
                let lock_path = dir.join(lock_name);
                if let Ok(_guard) =
                    af_host::HostMaintenanceLockGuard::acquire(&lock_path, Duration::from_secs(1))
                {
                    let _ = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o660));
                }
            }
        }
    }
    let _ = fs::remove_file(&sock_path);

    let listener = tokio::net::UnixListener::bind(&sock_path)?;
    let _ = fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o660));

    tracing::info!(socket = %sock_path, "AetherFlow Privileged Runner listening");
    let app = build_runner_router();

    serve_runner_connections_with_registry(
        listener,
        app,
        shutdown_signal()?,
        Some(af_release::process_group::global_registry()),
    )
    .await?;
    let _ = fs::remove_file(&sock_path);
    Ok(())
}

/// Serves runner Unix-socket connections without shutting down the process-wide
/// supervisor registry (used by in-process tests that spin up temporary
/// listeners; production [`run_privileged_daemon`] passes
/// `Some(af_release::process_group::global_registry())`).
#[cfg(all(test, unix))]
pub(crate) async fn serve_runner_connections(
    listener: tokio::net::UnixListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    serve_runner_connections_with_registry(listener, app, shutdown, None).await
}

#[cfg(unix)]
pub(crate) async fn serve_runner_connections_with_registry(
    listener: tokio::net::UnixListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()>,
    supervisor_registry: Option<&af_release::process_group::SupervisorRegistry>,
) -> anyhow::Result<()> {
    use hyper::service::Service;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;
    let mut connections = tokio::task::JoinSet::new();
    let (drain, drain_rx) = tokio::sync::watch::channel(false);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result { tracing::warn!(%error, "Runner connection task failed"); }
            }
            accept_res = listener.accept() => {
                let (stream, _) = accept_res?;
                let (peer_uid, peer_gid, peer_pid) = match stream.peer_cred() {
                    Ok(cred) => (cred.uid(), cred.gid(), cred.pid()),
                    Err(err) => {
                        tracing::warn!(error = %err, "Rejecting runner connection without SO_PEERCRED");
                        continue;
                    }
                };
                let initial_auth = authorize_runner_socket_peer(peer_uid, peer_gid, peer_pid, "/v1/*");
                let io = TokioIo::new(stream);
                let tower_service = TowerToHyperService::new(app.clone());
                let mut drain_rx = drain_rx.clone();
                connections.spawn(async move {
                    let hyper_service = hyper::service::service_fn(
                        move |request: hyper::Request<hyper::body::Incoming>| {
                            let req_path = request.uri().path().to_string();
                            let auth_res = initial_auth.clone().and_then(|()| {
                                authorize_runner_socket_peer(peer_uid, peer_gid, peer_pid, &req_path)
                            });
                            let svc = tower_service.clone();
                            async move {
                                if let Err((code, msg)) = auth_res {
                                    let body = serde_json::to_string(&RunnerResponse {
                                        success: false,
                                        output: String::new(),
                                        error: msg,
                                    }).unwrap_or_default();
                                    return Ok(Response::builder()
                                        .status(code)
                                        .header("Content-Type", "application/json")
                                        .body(Body::from(body))
                                        .unwrap());
                                }
                                let mut req = request.map(axum::body::Body::new);
                                req.extensions_mut().insert(RunnerPeerCred {
                                    uid: peer_uid,
                                    gid: peer_gid,
                                    pid: peer_pid,
                                });
                                svc.call(req).await
                            }
                        },
                    );
                    let builder = Builder::new(TokioExecutor::new());
                    let connection = builder.serve_connection(io, hyper_service);
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = drain_rx.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    tracing::info!("Privileged Runner draining active requests");
    let _ = drain.send(true);
    let drain_deadline = tokio::time::Instant::now() + RUNNER_DRAIN_TIMEOUT;
    let connection_deadline = tokio::time::Instant::now() + RUNNER_CONNECTION_DRAIN_TIMEOUT;
    let draining = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout_at(connection_deadline, draining)
        .await
        .is_err()
    {
        tracing::warn!("Runner drain deadline exceeded; terminating remaining connections");
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    if let Some(registry) = supervisor_registry {
        let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
        let report = registry.shutdown(remaining).await;
        if !report.drained {
            tracing::warn!(
                remaining_supervisors = report.remaining,
                "Runner process-group supervisor drain deadline exceeded"
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn run_privileged_daemon() -> anyhow::Result<()> {
    tracing::warn!("UNIX domain socket runner mode requires a Unix/Linux host");
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn runner_drain_timeout_is_strictly_below_systemd_timeout_stop_sec() {
        assert_eq!(RUNNER_DRAIN_TIMEOUT, Duration::from_secs(20));
        assert!(RUNNER_CONNECTION_DRAIN_TIMEOUT < RUNNER_DRAIN_TIMEOUT);
        assert!(RUNNER_DRAIN_TIMEOUT < Duration::from_secs(30));
    }

    #[tokio::test]
    async fn daemon_shutdown_cancels_and_reaps_tracked_supervisors_before_exit() {
        let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let root = PathBuf::from("/tmp").join(format!("af-dd-{short_id}"));
        fs::create_dir_all(&root).unwrap();
        let sock_path = root.join("r.sock");
        let pid_file = root.join("descendant.pid");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let registry = af_release::process_group::SupervisorRegistry::new();

        let mut cmd = Command::new("/bin/bash");
        cmd.args(["-c", "sleep 60 & echo $! > \"$AF_PID_FILE\"; wait"])
            .env("AF_PID_FILE", &pid_file);
        let reg_for_task = registry.clone();
        let child_task = tokio::spawn(async move {
            af_release::process_group::output_in(&reg_for_task, cmd, Duration::from_secs(60), 1024)
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            while !pid_file.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let descendant_pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(registry.active(), 1);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let reg_for_server = registry.clone();
        let server = tokio::spawn(async move {
            serve_runner_connections_with_registry(
                listener,
                Router::new(),
                async {
                    let _ = shutdown_rx.await;
                },
                Some(&reg_for_server),
            )
            .await
        });
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert!(registry.is_shutting_down());
        assert_eq!(registry.active(), 0);
        assert!(
            !af_release::process_group::group_is_live(Some(descendant_pid as u32)),
            "tracked descendant pid={descendant_pid} must be reaped before daemon exit"
        );
        let err = child_task.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);
        let _ = fs::remove_dir_all(&root);
    }
}
