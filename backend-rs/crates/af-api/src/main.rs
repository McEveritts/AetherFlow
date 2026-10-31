pub mod auth;
pub mod embed;
pub mod intelligence;
pub mod middlewares;
pub mod notifications_ext;
pub mod oidc;
pub mod routes;
pub mod storage;
pub mod streaming_ext;
pub mod ws;

use std::env;
use std::path::Path;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};
use axum::http::{header, HeaderName, HeaderValue, Method};

fn load_env_files() {
    let candidates = [
        "/etc/aetherflow/aetherflow.env",
        "../.env",
        ".env",
    ];
    for path in candidates {
        if Path::new(path).is_file() {
            let _ = dotenvy::from_path(path);
        }
    }
}

fn build_cors_layer() -> CorsLayer {
    let allowed_methods = [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
    ];
    let allowed_headers = [
        header::ORIGIN,
        header::CONTENT_TYPE,
        header::ACCEPT,
        header::AUTHORIZATION,
        HeaderName::from_static("x-api-version"),
        HeaderName::from_static("x-csrf-token"),
        HeaderName::from_static("x-requested-with"),
        HeaderName::from_static("x-aetherflow-signature"),
        HeaderName::from_static("x-whmcs-signature"),
        HeaderName::from_static("x-blesta-signature"),
        HeaderName::from_static("rsc"),
    ];
    let expose_headers = [
        header::CONTENT_LENGTH,
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

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Privileged Root Socket Runner Mode (`aetherflow-api runner` / `--runner`)
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && (args[1] == "runner" || args[1] == "--runner") {
        return af_runner::run_privileged_daemon().await;
    }

    // Initialize SQLite WAL Database & AES-256-GCM Secret Encryption
    af_db::init_db()?;
    af_db::init_aes_key()?;
    if let Err(e) = af_db::migrate_legacy_secrets() {
        tracing::warn!(error = %e, "failed to migrate legacy secrets");
    }

    // Background 15-minute expired data pruning loop
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let mut interval = tokio::time::interval(Duration::from_secs(900));
        loop {
            interval.tick().await;
            af_db::prune_expired_data();
        }
    });

    // Background 1 Hz WebSocket telemetry loop
    ws::start_metrics_broadcast_loop();

    // Background Subsystems: Metrics Recorder, Auto-Heal, Smart Backup, App Update Watcher,
    // Cluster Master/Worker Runtime, Notification Rule Engine, and Jellyfin Streaming Poller
    af_services::workers::start_metrics_recorder();
    af_services::workers::start_heal_worker(10);
    af_services::workers::start_smart_backup_scheduler();
    af_services::workers::start_app_update_watcher();
    af_services::cluster_daemon::start_cluster_runtime();
    notifications_ext::start_notification_engine();
    streaming_ext::start_streaming_monitor();

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_addr = format!("0.0.0.0:{}", port);

    let app = routes::build_router()
        .layer(build_cors_layer())
        .layer(axum::middleware::from_fn(
            middlewares::app_subdomain_proxy_middleware,
        ));

    tracing::info!(
        addr = %bind_addr,
        version = "4.0.0-rc1",
        runtime = "rust",
        "AetherFlow Rust backend starting"
    );

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received, draining connections");
        })
        .await?;

    Ok(())
}
