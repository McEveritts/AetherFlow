#![recursion_limit = "256"]

pub mod auth;
pub mod embed;
pub mod intelligence;
pub mod middlewares;
pub mod mcbrowser;
#[cfg(test)]
mod mcbrowser_integration_tests;
pub mod notifications_ext;
pub mod network;
pub mod oidc;
pub mod routes;
pub mod storage;
pub mod streaming_ext;
pub mod streaming_history;
pub mod streaming_patterns;
pub mod streaming_emby;
pub mod streaming_portability;
pub mod streaming_import;
pub mod streaming_metadata;
#[cfg(test)]
mod streaming_http_tests;
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
        HeaderName::from_static("x-aetherflow-signature"),
        HeaderName::from_static("x-whmcs-signature"),
        HeaderName::from_static("x-blesta-signature"),
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
    af_services::workers::start_mediaflow_poller();
    af_services::cluster_daemon::start_cluster_runtime();
    notifications_ext::start_notification_engine();
    streaming_ext::start_streaming_monitor();
    tokio::spawn(async move {
        af_services::mutators::provision_all_installed_app_subdomains().await;
    });

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_addr = format!("0.0.0.0:{}", port);

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

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown signal received, draining connections");
    })
    .await?;

    Ok(())
}
