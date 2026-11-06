#![recursion_limit = "256"]

pub mod auth;
pub mod embed;
pub mod intelligence;
pub mod mcbrowser;
#[cfg(test)]
mod mcbrowser_integration_tests;
pub mod middlewares;
pub mod network;
pub mod notifications_ext;
pub mod oidc;
pub mod plugins;
#[cfg(test)]
mod plugins_router_tests;
pub mod routes;
mod service_logs;
pub mod storage;
pub mod streaming_emby;
pub mod streaming_ext;
pub mod streaming_history;
#[cfg(test)]
mod streaming_http_tests;
pub mod streaming_import;
pub mod streaming_metadata;
pub mod streaming_patterns;
pub mod streaming_portability;
pub mod ws;

use axum::http::{header, HeaderName, HeaderValue, Method};
use std::env;
use std::path::Path;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};

fn env_flag_enabled(name: &str) -> bool {
    env::var(name)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn load_env_files() {
    if env_flag_enabled("AETHERFLOW_SKIP_ENV_FILES") || env_flag_enabled("AETHERFLOW_E2E_ISOLATED")
    {
        if let Ok(explicit) = env::var("AETHERFLOW_ENV_FILE") {
            let trimmed = explicit.trim();
            if !trimmed.is_empty() && Path::new(trimmed).is_file() {
                let _ = dotenvy::from_path(trimmed);
            }
        }
        return;
    }

    if let Ok(explicit) = env::var("AETHERFLOW_ENV_FILE") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            if Path::new(trimmed).is_file() {
                let _ = dotenvy::from_path(trimmed);
            }
            return;
        }
    }

    let candidates = ["/etc/aetherflow/aetherflow.env", "../.env", ".env"];
    for path in candidates {
        if Path::new(path).is_file() {
            let _ = dotenvy::from_path(path);
        }
    }
}

fn build_cors_layer() -> CorsLayer {
    let allowed_methods = [
        Method::GET,
        Method::HEAD,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
    ];
    let allowed_headers = [
        header::ORIGIN,
        header::RANGE,
        header::CONTENT_TYPE,
        header::ACCEPT,
        header::AUTHORIZATION,
        HeaderName::from_static("x-api-version"),
        HeaderName::from_static("x-csrf-token"),
        HeaderName::from_static("tus-resumable"),
        HeaderName::from_static("upload-length"),
        HeaderName::from_static("upload-offset"),
        HeaderName::from_static("upload-metadata"),
        HeaderName::from_static("upload-conflict"),
        HeaderName::from_static("x-upload-conflict"),
        header::CACHE_CONTROL,
        HeaderName::from_static("x-mcbrowser-share-token"),
        HeaderName::from_static("x-requested-with"),
        HeaderName::from_static("rsc"),
    ];
    let expose_headers = [
        header::CONTENT_LENGTH,
        header::CONTENT_DISPOSITION,
        header::CONTENT_RANGE,
        header::ACCEPT_RANGES,
        header::LOCATION,
        HeaderName::from_static("tus-resumable"),
        HeaderName::from_static("tus-version"),
        HeaderName::from_static("tus-extension"),
        HeaderName::from_static("tus-max-size"),
        HeaderName::from_static("upload-length"),
        HeaderName::from_static("upload-offset"),
        HeaderName::from_static("upload-metadata"),
        HeaderName::from_static("upload-expires"),
        HeaderName::from_static("upload-status"),
        HeaderName::from_static("upload-skipped"),
        HeaderName::from_static("upload-fingerprint"),
        HeaderName::from_static("upload-path"),
        HeaderName::from_static("x-api-version"),
        HeaderName::from_static("deprecation"),
        header::LINK,
    ];

    let origins: Vec<HeaderValue> = if let Ok(custom) = env::var("ALLOWED_CORS_ORIGIN") {
        custom
            .split(',')
            .filter_map(|s| {
                let t = s.trim();
                if t.is_empty() {
                    None
                } else {
                    HeaderValue::from_str(t).ok()
                }
            })
            .collect()
    } else {
        [
            "http://localhost",
            "https://localhost",
            "http://localhost:3000",
            "http://localhost:8080",
            "http://127.0.0.1",
            "https://127.0.0.1",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8080",
        ]
        .iter()
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect()
    };

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods(allowed_methods)
        .allow_headers(allowed_headers)
        .expose_headers(expose_headers)
        .allow_credentials(true)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    load_env_files();
    let _ = af_runner::af_release::runtime::runtime_identity();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Privileged Root Socket Runner Mode (`aetherflow-api runner` / `--runner`)
    if let Some(first_arg) = std::env::args().nth(1) {
        if first_arg == "runner" || first_arg == "--runner" {
            return af_runner::run_privileged_daemon().await;
        }
    }

    // Initialize SQLite WAL Database & AES-256-GCM Secret Encryption
    af_db::init_db()?;
    af_services::initialize_package_jobs(rusqlite::Connection::open(af_db::get_db_path())?)?;
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;
            match tokio::task::spawn_blocking(af_services::reconcile_package_jobs).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(%error, "package lifecycle reconciliation failed"),
                Err(error) => tracing::warn!(%error, "package lifecycle reconciliation task failed"),
            }
        }
    });
    af_db::init_aes_key()?;
    if let Err(e) = af_db::migrate_legacy_secrets() {
        tracing::warn!(error = %e, "failed to migrate legacy secrets");
    }

    let disable_workers = env_flag_enabled("AETHERFLOW_DISABLE_BACKGROUND_WORKERS")
        || env_flag_enabled("AETHERFLOW_DISABLE_WORKERS")
        || env_flag_enabled("AETHERFLOW_E2E_ISOLATED");
    let disable_autoheal = disable_workers || env_flag_enabled("AETHERFLOW_DISABLE_AUTOHEAL");

    // Background 15-minute expired data pruning loop
    if !disable_workers {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut interval = tokio::time::interval(Duration::from_secs(900));
            loop {
                interval.tick().await;
                af_db::prune_expired_data();
            }
        });
    }

    // Background 1 Hz WebSocket telemetry loop
    if !env_flag_enabled("AETHERFLOW_DISABLE_WS_BROADCAST") {
        ws::start_metrics_broadcast_loop();
    }

    // Background Subsystems: Metrics Recorder, Auto-Heal, Smart Backup, App Update Watcher,
    // Cluster Master/Worker Runtime, Notification Rule Engine, and Jellyfin Streaming Poller
    if !disable_workers {
        af_services::lifecycle_cache::start_worker();
        af_services::workers::start_metrics_recorder();
        if !disable_autoheal {
            af_services::workers::start_heal_worker(10);
        }
        af_services::workers::start_smart_backup_scheduler();
        af_services::workers::start_app_update_watcher();
        af_services::workers::start_mediaflow_poller();
        af_services::cluster_daemon::start_cluster_runtime();
        notifications_ext::start_notification_engine();
        streaming_ext::start_streaming_monitor();
        tokio::spawn(async move {
            af_services::mutators::provision_all_installed_app_subdomains().await;
        });
    } else {
        tracing::info!(
            "Background mutating workers disabled via AETHERFLOW_DISABLE_BACKGROUND_WORKERS / AETHERFLOW_DISABLE_WORKERS / AETHERFLOW_E2E_ISOLATED"
        );
    }

    let bind_addr = resolve_bind_addr(
        env::var("BIND_ADDR")
            .or_else(|_| env::var("AETHERFLOW_BIND_ADDR"))
            .ok()
            .as_deref(),
        env::var("PORT").ok().as_deref(),
        env_flag_enabled("AETHERFLOW_E2E_ISOLATED"),
    );

    let app = routes::build_router()
        .layer(build_cors_layer())
        .layer(axum::middleware::from_fn(
            middlewares::app_subdomain_proxy_middleware,
        ));

    tracing::info!(
        addr = %bind_addr,
        version = "4.0.0",
        runtime = "rust",
        "AetherFlow Rust backend starting"
    );

    let shutdown = af_runner::shutdown_signal()?;
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        tracing::info!("shutdown signal received, draining connections");
    })
    .await?;

    Ok(())
}

pub fn resolve_bind_addr(
    bind_host_env: Option<&str>,
    port_env: Option<&str>,
    isolated_mode: bool,
) -> String {
    let port = port_env
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("8080");
    let bind_host = bind_host_env
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(if isolated_mode {
            "127.0.0.1"
        } else {
            "0.0.0.0"
        });

    // IPv6 bracketed literal without port (`[::1]`) -> `[::1]:8080`
    if bind_host.starts_with('[') && bind_host.ends_with(']') {
        return format!("{}:{}", bind_host, port);
    }
    // Unbracketed IPv6 literal (`::1` or `::`) -> `[::1]:8080`
    if bind_host.matches(':').count() > 1 && !bind_host.starts_with('[') {
        return format!("[{}]:{}", bind_host, port);
    }
    if bind_host.contains(':') {
        bind_host.to_string()
    } else {
        format!("{}:{}", bind_host, port)
    }
}

#[cfg(test)]
mod main_isolation_tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn api_sigterm_drains_inflight_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const ENV: &str = "AETHERFLOW_API_DRAIN_TEST";
        if env::var_os(ENV).is_none() {
            let status = std::process::Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "main_isolation_tests::api_sigterm_drains_inflight_response",
                    "--nocapture",
                ])
                .env(ENV, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let shutdown = af_runner::shutdown_signal().unwrap();
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let enter_handler = entered.clone();
        let release_handler = release.clone();
        let app = axum::Router::new().route(
            "/drain-test",
            axum::routing::get(move || {
                let entered = enter_handler.clone();
                let release = release_handler.clone();
                async move {
                    entered.notify_one();
                    release.notified().await;
                    "completed-before-exit"
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await
                .unwrap();
        });
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /drain-test HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        assert_eq!(
            unsafe { libc::kill(std::process::id() as i32, libc::SIGTERM) },
            0
        );
        tokio::task::yield_now().await;
        assert!(!server.is_finished());
        release.notify_one();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.contains("completed-before-exit"));
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn resolve_bind_addr_honors_bind_addr_port_and_isolated_defaults() {
        assert_eq!(resolve_bind_addr(None, None, false), "0.0.0.0:8080");
        assert_eq!(
            resolve_bind_addr(None, Some("18080"), true),
            "127.0.0.1:18080"
        );
        assert_eq!(
            resolve_bind_addr(Some("127.0.0.1"), Some("18080"), false),
            "127.0.0.1:18080"
        );
        assert_eq!(
            resolve_bind_addr(Some("127.0.0.1:19090"), Some("18080"), false),
            "127.0.0.1:19090"
        );
        assert_eq!(
            resolve_bind_addr(Some("::1"), Some("18080"), false),
            "[::1]:18080"
        );
    }
}
