use af_librespeed::config::{parse_env_cli, CliAction, Config, VERSION_STRING};
use af_librespeed::db::TelemetryVault;
use af_librespeed::routes::build_router;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::process;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info};

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
    let vault = if config.telemetry_enabled() {
        let opened = TelemetryVault::open(&config.database_file)?;
        info!(
            db_path = %opened.path().display(),
            "Initialized SQLite WAL telemetry vault"
        );
        Some(opened)
    } else {
        info!("Telemetry storage disabled via database_type=none");
        None
    };

    let bind_addr = config.socket_addr()?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    let app = build_router(config.clone(), vault);
    info!(
        addr = %bind_addr,
        url_base = %config.url_base,
        assets = %config.assets_path.display(),
        "Starting native Rust LibreSpeed backend"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("HTTP server terminated unexpectedly")?;

    Ok(())
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
