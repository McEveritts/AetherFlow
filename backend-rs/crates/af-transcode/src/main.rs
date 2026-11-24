use af_transcode::capabilities::{probe_capabilities, CapabilitiesConfig};
use af_transcode::shim::{run_shim, ShimConfig};
use af_transcode::worker::{run_worker, WorkerConfig};
use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

fn invoked_as_ffmpeg(argv0: Option<&OsStr>) -> bool {
    argv0
        .and_then(|raw| Path::new(raw).file_name())
        .is_some_and(|name| name == "ffmpeg")
}

fn register_worker_shutdown_signals(
) -> anyhow::Result<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)> {
    use tokio::signal::unix::{signal, SignalKind};
    let sigint = signal(SignalKind::interrupt())?;
    let sigterm = signal(SignalKind::terminate())?;
    Ok((sigint, sigterm))
}

async fn wait_for_worker_shutdown(
    mut sigint: tokio::signal::unix::Signal,
    mut sigterm: tokio::signal::unix::Signal,
) {
    tokio::select! {
        _ = sigint.recv() => {},
        _ = sigterm.recv() => {},
    }
}

fn init_worker_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[tokio::main]
async fn main() -> ExitCode {
    let raw_args: Vec<_> = env::args_os().collect();
    let argv0 = raw_args.first().map(|arg| arg.as_os_str());

    if invoked_as_ffmpeg(argv0) {
        let code = run_shim(&raw_args[1..], ShimConfig::from_env()).await;
        return ExitCode::from((code & 0xff) as u8);
    }

    match raw_args.get(1).and_then(|arg| arg.to_str()) {
        Some("shim") => {
            let code = run_shim(&raw_args[2..], ShimConfig::from_env()).await;
            ExitCode::from((code & 0xff) as u8)
        }
        Some("--version") | Some("-V") => {
            println!("af-transcode {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("worker") => {
            init_worker_tracing();
            let config = match WorkerConfig::from_env() {
                Ok(cfg) => cfg,
                Err(err) => {
                    eprintln!("af-transcode worker: invalid configuration: {err}");
                    return ExitCode::from(2);
                }
            };
            let (sigint, sigterm) = match register_worker_shutdown_signals() {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::error!(error = %err, "failed to register worker signal handlers");
                    eprintln!("af-transcode worker: failed to register signal handlers: {err}");
                    return ExitCode::from(1);
                }
            };
            let shutdown = wait_for_worker_shutdown(sigint, sigterm);
            if let Err(err) = run_worker(config, shutdown).await {
                eprintln!("af-transcode worker: {err:#}");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Some("capabilities") => {
            let config = CapabilitiesConfig::from_env();
            match probe_capabilities(&config).await {
                Ok(report) => match serde_json::to_string_pretty(&report) {
                    Ok(json) => {
                        println!("{json}");
                        ExitCode::SUCCESS
                    }
                    Err(err) => {
                        eprintln!("af-transcode capabilities: serialization failed: {err}");
                        ExitCode::from(1)
                    }
                },
                Err(err) => {
                    eprintln!("af-transcode capabilities: {err:#}");
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  ffmpeg <args...>              (shim mode when invoked as argv[0]=ffmpeg)");
            eprintln!("  af-transcode shim <args...>   (explicit shim mode)");
            eprintln!("  af-transcode worker           (Unix socket worker daemon)");
            eprintln!(
                "  af-transcode capabilities     (print local ffmpeg & DRM render node JSON)"
            );
            ExitCode::from(2)
        }
    }
}
