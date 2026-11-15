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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(err) = run().await {
        error!(error = %err, "speedtest-backend exiting with error");
        eprintln!("Error: {err:#}");
        process::exit(1);
    }
}

async fn run() -> Result<()> {
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
    let (listener, bind_addr, socket_activated) = acquire_tcp_listener(configured_addr).await?;

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
) -> Result<(TcpListener, SocketAddr, bool)> {
    let listen_pid = std::env::var("LISTEN_PID").ok();
    let listen_fds = std::env::var("LISTEN_FDS").ok();
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");

    if let (Some(pid_raw), Some(fds_raw)) = (listen_pid, listen_fds) {
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
                    "Multiple systemd activation sockets passed; adopting primary fd 3"
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
