use af_librespeed::config::{parse_env_cli, CliAction, Config, VERSION_STRING};
use af_librespeed::db::TelemetryVault;
use af_librespeed::routes::build_router;
use af_librespeed::tls::{adopt_systemd_socket_fd, build_tls_acceptor, serve_http, serve_tls};
use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::process;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info, warn};

struct SystemdListenEnv {
    pid: Option<String>,
    fds: Option<String>,
}

/// Captures and removes systemd `LISTEN_*` environment variables while the process is
/// guaranteed single-threaded (prior to `tracing_subscriber` and Tokio worker creation),
/// and closes any extra inherited activation socket descriptors beyond primary `fd = 3`.
fn capture_and_clear_systemd_listen_env() -> SystemdListenEnv {
    let pid = std::env::var("LISTEN_PID").ok();
    let fds = std::env::var("LISTEN_FDS").ok();
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");

    if let (Some(pid_raw), Some(fds_raw)) = (pid.as_deref(), fds.as_deref()) {
        if let (Ok(target_pid), Ok(fd_count)) = (
            pid_raw.trim().parse::<u32>(),
            fds_raw.trim().parse::<usize>(),
        ) {
            if target_pid == process::id() && fd_count > 1 {
                let end_fd = 3usize.saturating_add(fd_count.min(64));
                for extra_fd in 4..end_fd {
                    let Ok(raw_fd) = libc::c_int::try_from(extra_fd) else {
                        break;
                    };
                    // SAFETY: `fstat` inspects `raw_fd` into a stack-zeroed `libc::stat` while single-threaded;
                    // only socket descriptors passed beyond primary fd 3 are closed.
                    unsafe {
                        let mut st: libc::stat = std::mem::zeroed();
                        if libc::fstat(raw_fd, &mut st) == 0
                            && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK
                        {
                            let _ = libc::close(raw_fd);
                        }
                    }
                }
            }
        }
    }

    SystemdListenEnv { pid, fds }
}

fn main() {
    let systemd_env = capture_and_clear_systemd_listen_env();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            error!(error = %err, "failed initializing Tokio runtime");
            eprintln!("Error: failed initializing Tokio runtime: {err:#}");
            process::exit(1);
        }
    };

    if let Err(err) = runtime.block_on(run(systemd_env)) {
        error!(error = %err, "speedtest-backend exiting with error");
        eprintln!("Error: {err:#}");
        process::exit(1);
    }
}

async fn run(systemd_env: SystemdListenEnv) -> Result<()> {
    let action = match parse_env_cli() {
        Ok(action) => action,
        Err(err) => {
            eprintln!("Usage error: {err}");
            eprintln!("Try 'speedtest-backend --help' for usage information.");
            process::exit(2);
        }
    };

    let config_path = match action {
        CliAction::PrintVersion => {
            println!("{VERSION_STRING}");
            return Ok(());
        }
        CliAction::PrintHelp => {
            println!("{VERSION_STRING}");
            println!("Usage: speedtest-backend [-c <path> | --config <path>] [-v | --version]");
            return Ok(());
        }
        CliAction::Run { config_path } => config_path,
    };

    let config = Config::load_from_path(&config_path)?;
    config.validate_listener_security()?;
    if config.trusted_proxies.iter().any(|ip| ip.is_loopback())
        && config.trusted_proxy_secret.trim().is_empty()
    {
        warn!(
            "Loopback address configured in trusted_proxies without trusted_proxy_secret; set trusted_proxy_secret in settings.toml to prevent local X-Forwarded-For spoofing"
        );
    }
    let tls_acceptor = if config.enable_tls {
        Some(build_tls_acceptor(&config)?)
    } else {
        None
    };

    let vault = if config.telemetry_enabled() {
        let opened = if config.database_type.trim().eq_ignore_ascii_case("memory") {
            let mem = TelemetryVault::open_in_memory(config.max_telemetry_rows)?;
            info!(
                max_rows = config.max_telemetry_rows,
                "Initialized in-memory SQLite telemetry vault"
            );
            mem
        } else {
            let disk = TelemetryVault::open_with_max_rows(
                &config.database_file,
                config.max_telemetry_rows,
            )?;
            info!(
                db_path = %disk.path().display(),
                max_rows = config.max_telemetry_rows,
                "Initialized SQLite WAL telemetry vault"
            );
            disk
        };
        Some(opened)
    } else {
        info!("Telemetry storage disabled via database_type=none");
        None
    };

    let configured_addr = config.socket_addr()?;
    let (listener, bind_addr, socket_activated) =
        acquire_tcp_listener(configured_addr, systemd_env).await?;

    let app = build_router(config.clone(), vault);
    if let Some(acceptor) = tls_acceptor {
        info!(
            addr = %bind_addr,
            socket_activated,
            url_base = %config.url_base,
            assets = %config.assets_path.display(),
            cert = %config.tls_cert_file.display(),
            "Starting native Rust LibreSpeed HTTPS backend (TLS 1.2/1.3)"
        );
        serve_tls(listener, acceptor, app, shutdown_signal())
            .await
            .context("HTTPS server terminated unexpectedly")?;
    } else {
        info!(
            addr = %bind_addr,
            socket_activated,
            url_base = %config.url_base,
            assets = %config.assets_path.display(),
            "Starting native Rust LibreSpeed HTTP backend"
        );
        serve_http(listener, app, shutdown_signal())
            .await
            .context("HTTP server terminated unexpectedly")?;
    }

    Ok(())
}

async fn acquire_tcp_listener(
    configured_addr: SocketAddr,
    systemd_env: SystemdListenEnv,
) -> Result<(TcpListener, SocketAddr, bool)> {
    if let (Some(pid_raw), Some(fds_raw)) = (systemd_env.pid, systemd_env.fds) {
        let target_pid: u32 = pid_raw
            .trim()
            .parse()
            .with_context(|| format!("invalid LISTEN_PID {pid_raw:?}"))?;
        if target_pid == process::id() {
            let fd_count: usize = fds_raw
                .trim()
                .parse()
                .with_context(|| format!("invalid LISTEN_FDS {fds_raw:?}"))?;
            if fd_count == 0 {
                bail!("LISTEN_FDS=0 with matching LISTEN_PID={target_pid}");
            }
            if fd_count > 1 {
                warn!(
                    listen_fds = fd_count,
                    "Multiple systemd activation sockets passed; extra descriptors closed and adopting primary fd 3"
                );
            }
            let (listener, local_addr) = adopt_systemd_socket_fd(3, false)?;
            return Ok((listener, local_addr, true));
        }
    }

    let listener = TcpListener::bind(configured_addr)
        .await
        .with_context(|| format!("failed to bind {configured_addr}"))?;
    let actual_addr = listener.local_addr().unwrap_or(configured_addr);
    Ok((listener, actual_addr, false))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            sigterm.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Shutdown signal received, draining active LibreSpeed connections");
}
