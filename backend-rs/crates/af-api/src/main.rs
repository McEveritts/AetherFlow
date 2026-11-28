#![recursion_limit = "256"]

mod account_cleanup;
mod app_launch;
pub mod auth;
pub mod embed;
pub mod intelligence;
pub mod mcbrowser;
#[cfg(test)]
mod mcbrowser_integration_tests;
mod metrics_rollup;
pub mod middlewares;
pub mod network;
pub mod notifications_ext;
pub mod oidc;
pub mod openapi_ui;
pub mod peers;
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

use axum::extract::Request;
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::Response;
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
        HeaderName::from_static("x-aetherflow-setup-token"),
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
        HeaderName::from_static("x-aetherflow-inventory-mode"),
        HeaderName::from_static("x-aetherflow-inventory-authenticated"),
        HeaderName::from_static(crate::streaming_portability::HEADER_ARCHIVE_TELEMETRY),
        HeaderName::from_static(crate::streaming_portability::HEADER_OMITTED_SESSION_SAMPLES),
        HeaderName::from_static(crate::streaming_portability::HEADER_OMITTED_BANDWIDTH_SAMPLES),
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
        let port = env::var("PORT")
            .ok()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "8080".to_string());
        let mut defaults = vec![
            "http://localhost:3000".to_string(),
            "http://localhost:8080".to_string(),
            "http://127.0.0.1:3000".to_string(),
            "http://127.0.0.1:8080".to_string(),
        ];
        let custom_local = format!("http://localhost:{}", port);
        if !defaults.contains(&custom_local) {
            defaults.push(custom_local);
        }
        let custom_loopback = format!("http://127.0.0.1:{}", port);
        if !defaults.contains(&custom_loopback) {
            defaults.push(custom_loopback);
        }
        defaults
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

/// Outermost request middleware (`SEC-09`).
///
/// `app_subdomain_proxy_middleware` (and the legacy `app_launch` handoff it calls) runs outside
/// `routes::build_router()`, i.e. before the router's own forwarding normalisation. Normalising
/// here first strips client-supplied `Forwarded`/`X-Forwarded-*`/`X-Real-IP` headers from
/// untrusted TCP peers (pinning `X-Real-IP` to the peer address), so every client-IP lookup on
/// the subdomain path resolves the same address as `extract_client_ip_for_peer`. The helper is
/// idempotent, so the router's inner pass is a no-op.
async fn normalize_peer_forwarding_middleware(mut req: Request, next: Next) -> Response {
    ws::normalize_request_forwarding_for_peer(&mut req);
    next.run(req).await
}

fn main() -> anyhow::Result<()> {
    // Populate process environment before spawning multi-threaded Tokio worker threads
    // so `dotenvy::from_path` (`setenv`) executes strictly single-threaded.
    load_env_files();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

#[cfg(target_os = "linux")]
fn warn_if_mcbrowser_home_root_is_read_only() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let Ok(configured) = env::var("AF_MCBROWSER_ROOT") else {
        return;
    };
    let Ok(root) = mcbrowser::resolve_configured_base_root(Some(&configured)) else {
        return;
    };
    if !root.starts_with("/home") {
        return;
    }
    // A root that has not been created yet will reside on its nearest existing
    // ancestor's filesystem.
    for ancestor in root
        .ancestors()
        .take_while(|path| path.starts_with("/home"))
    {
        let Ok(path) = CString::new(ancestor.as_os_str().as_bytes()) else {
            return;
        };
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } == 0 {
            let stats = unsafe { stats.assume_init() };
            if stats.f_flag & libc::ST_RDONLY != 0 {
                tracing::warn!(
                    code = "MCBROWSER_ROOT_READ_ONLY",
                    root = %root.display(),
                    "AF_MCBROWSER_ROOT is on a read-only /home mount. Set it to a writable service-owned directory or grant the service write access through its mount sandbox."
                );
            }
            return;
        }
    }
}

fn log_format_is_json(raw: Option<&str>) -> bool {
    raw.is_some_and(|value| value.trim().eq_ignore_ascii_case("json"))
}

fn build_tracing_env_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
}

fn init_tracing() {
    let env_filter = build_tracing_env_filter();
    if log_format_is_json(env::var("AF_LOG_FORMAT").ok().as_deref()) {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }
}

async fn async_main() -> anyhow::Result<()> {
    let _ = af_runner::af_release::runtime::runtime_identity();

    init_tracing();

    // Privileged Root Socket Runner Mode (`aetherflow-api runner` / `--runner`)
    if let Some(first_arg) = std::env::args().nth(1) {
        if first_arg == "runner" || first_arg == "--runner" {
            return af_runner::run_privileged_daemon().await;
        }
    }

    // Fail closed if JWT_SECRET is missing or too short when starting the HTTP control plane
    auth::validate_startup_jwt_secret()?;
    #[cfg(target_os = "linux")]
    warn_if_mcbrowser_home_root_is_read_only();

    let disable_workers = env_flag_enabled("AETHERFLOW_DISABLE_BACKGROUND_WORKERS")
        || env_flag_enabled("AETHERFLOW_DISABLE_WORKERS")
        || env_flag_enabled("AETHERFLOW_E2E_ISOLATED");
    let disable_autoheal = disable_workers || env_flag_enabled("AETHERFLOW_DISABLE_AUTOHEAL");

    // Initialize SQLite WAL Database & AES-256-GCM Secret Encryption
    af_db::init_db()?;
    auth::ensure_setup_bootstrap_token();
    let init_conn = rusqlite::Connection::open(af_db::get_db_path())?;
    init_conn.busy_timeout(Duration::from_secs(5))?;
    af_services::initialize_package_jobs(init_conn)?;
    if !disable_workers {
        tokio::spawn(async {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                interval.tick().await;
                match tokio::task::spawn_blocking(af_services::reconcile_package_jobs).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "package lifecycle reconciliation failed")
                    }
                    Err(error) => {
                        tracing::warn!(%error, "package lifecycle reconciliation task failed")
                    }
                }
            }
        });
    }
    af_db::init_aes_key()?;
    if let Err(e) = af_db::migrate_legacy_secrets() {
        tracing::warn!(error = %e, "failed to migrate legacy secrets");
    }

    // Background 15-minute expired data pruning loop
    if !disable_workers {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut interval = tokio::time::interval(Duration::from_secs(900));
            loop {
                interval.tick().await;
                let _ = tokio::task::spawn_blocking(|| {
                    af_db::prune_expired_data();
                    storage::maintain_backup_upload_staging();
                })
                .await;
                let _ =
                    peers::transcode::prune_old_transcode_jobs(&peers::PeerRuntime::global()).await;
                storage::recover_fileshare_pending_publishes().await;
                account_cleanup::recover().await;
            }
        });
    }

    // Background 1 Hz WebSocket telemetry loop
    if !env_flag_enabled("AETHERFLOW_DISABLE_WS_BROADCAST") {
        ws::start_metrics_broadcast_loop();
    }

    // Background Subsystems: Metrics Recorder, Auto-Heal, Smart Backup, App Update Watcher,
    // Peer Clustering Runtime, Notification Rule Engine, and Jellyfin Streaming Poller
    if !disable_workers {
        af_services::lifecycle_cache::start_worker();
        af_services::workers::start_metrics_recorder();
        if !disable_autoheal {
            af_services::workers::start_heal_worker(10);
        }
        af_services::workers::start_smart_backup_scheduler();
        af_services::workers::start_app_update_watcher();
        af_services::workers::start_mediaflow_poller();
        peers::start().await;
        notifications_ext::start_notification_engine();
        streaming_ext::start_streaming_monitor();
        tokio::spawn(async move {
            af_services::mutators::provision_all_installed_app_subdomains().await;
        });
        tokio::spawn(async move {
            plugins::reconcile_managed_plugins_on_startup().await;
        });
        tokio::spawn(storage::recover_quota_rollbacks());
        tokio::spawn(storage::recover_fileshare_pending_publishes());
        tokio::spawn(account_cleanup::recover());
    } else {
        tracing::info!(
            "Background mutating workers disabled via AETHERFLOW_DISABLE_BACKGROUND_WORKERS / AETHERFLOW_DISABLE_WORKERS / AETHERFLOW_E2E_ISOLATED"
        );
    }

    // SEC-01: 60 s idle sweep of expired in-memory session-rotation state. Inserts already prune
    // on the hot path; this bounds memory held by idle entries. Cancelled on graceful shutdown.
    let (rotation_sweep_shutdown, rotation_sweep_rx) = tokio::sync::watch::channel(false);
    let rotation_sweeper =
        (!disable_workers).then(|| auth::spawn_rotation_state_sweeper(rotation_sweep_rx));

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
        ))
        .layer(axum::middleware::from_fn(
            normalize_peer_forwarding_middleware,
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

    let _ = rotation_sweep_shutdown.send(true);
    if let Some(sweeper) = rotation_sweeper {
        let _ = tokio::time::timeout(Duration::from_secs(5), sweeper).await;
    }
    peers::shutdown().await;
    plugins::shutdown_managed_plugins().await;

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

    #[derive(Clone, Default)]
    struct SharedLogBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    struct SharedLogWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedLogWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLogBuffer {
        type Writer = SharedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedLogWriter(self.0.clone())
        }
    }

    impl SharedLogBuffer {
        fn take_string(&self) -> String {
            let mut guard = self.0.lock().unwrap();
            let out = String::from_utf8(guard.clone()).unwrap();
            guard.clear();
            out
        }
    }

    fn build_test_dispatch(
        env_filter: tracing_subscriber::EnvFilter,
        log_format: Option<&str>,
        buffer: SharedLogBuffer,
    ) -> tracing::Dispatch {
        if log_format_is_json(log_format) {
            tracing::Dispatch::new(
                tracing_subscriber::fmt()
                    .with_env_filter(env_filter)
                    .with_writer(buffer)
                    .json()
                    .finish(),
            )
        } else {
            tracing::Dispatch::new(
                tracing_subscriber::fmt()
                    .with_env_filter(env_filter)
                    .with_writer(buffer)
                    .finish(),
            )
        }
    }

    #[test]
    fn log_format_is_json_honors_json_setting_and_defaults_to_text() {
        assert!(log_format_is_json(Some("json")));
        assert!(log_format_is_json(Some("JSON")));
        assert!(log_format_is_json(Some("  json  ")));
        assert!(!log_format_is_json(None));
        assert!(!log_format_is_json(Some("")));
        assert!(!log_format_is_json(Some("text")));
        assert!(!log_format_is_json(Some("pretty")));
    }

    #[test]
    fn tracing_subscriber_respects_format_and_env_filter() {
        let json_buf = SharedLogBuffer::default();
        let json_dispatch = build_test_dispatch(
            tracing_subscriber::EnvFilter::new("warn"),
            Some("json"),
            json_buf.clone(),
        );
        tracing::dispatcher::with_default(&json_dispatch, || {
            let span = tracing::info_span!("http_request", request_id = "json-filter-1");
            let _entered = span.enter();
            tracing::info!("filtered_info_event");
            tracing::warn!("visible_warn_event");
        });
        let json_output = json_buf.take_string();
        assert!(!json_output.contains("filtered_info_event"));
        let json_lines: Vec<serde_json::Value> = json_output
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("expected valid JSON log line"))
            .collect();
        assert_eq!(json_lines.len(), 1);
        assert_eq!(json_lines[0]["level"], "WARN");
        assert_eq!(json_lines[0]["fields"]["message"], "visible_warn_event");

        let text_buf = SharedLogBuffer::default();
        let text_dispatch = build_test_dispatch(
            tracing_subscriber::EnvFilter::new("info"),
            None,
            text_buf.clone(),
        );
        tracing::dispatcher::with_default(&text_dispatch, || {
            let span = tracing::info_span!("http_request", request_id = "text-default-1");
            let _entered = span.enter();
            tracing::debug!("filtered_debug_event");
            tracing::info!("visible_text_event");
        });
        let text_output = text_buf.take_string();
        assert!(!text_output.contains("filtered_debug_event"));
        assert!(text_output.contains("visible_text_event"));
        assert!(text_output.contains("text-default-1"));
        assert!(serde_json::from_str::<serde_json::Value>(text_output.trim()).is_err());
    }

    #[test]
    fn init_tracing_emits_json_and_text_request_id_logs_by_af_log_format() {
        use tower::ServiceExt;

        const MODE_ENV: &str = "AETHERFLOW_TRACING_SUBPROCESS_MODE";
        if let Ok(mode) = env::var(MODE_ENV) {
            init_tracing();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let req_id = format!("subprocess-{mode}-req-id");
            let response = rt.block_on(
                routes::build_router().oneshot(
                    axum::http::Request::builder()
                        .uri("/health/live")
                        .header(header::HOST, "localhost")
                        .header("X-Request-ID", &req_id)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                ),
            );
            let response = response.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            assert_eq!(response.headers()["X-Request-ID"], req_id);
            return;
        }

        let json_out = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "main_isolation_tests::init_tracing_emits_json_and_text_request_id_logs_by_af_log_format",
                "--nocapture",
            ])
            .env(MODE_ENV, "json")
            .env("AF_LOG_FORMAT", "json")
            .env_remove("RUST_LOG")
            .output()
            .unwrap();
        assert!(
            json_out.status.success(),
            "json subprocess failed: {}",
            String::from_utf8_lossy(&json_out.stderr)
        );
        let extract_json_event = |line: &str| -> Option<serde_json::Value> {
            let trimmed = line.trim();
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
                return Some(value);
            }
            trimmed
                .split_once(" ... ")
                .and_then(|(_, rest)| serde_json::from_str::<serde_json::Value>(rest.trim()).ok())
        };
        let json_stdout = String::from_utf8_lossy(&json_out.stdout);
        let parsed_json_events: Vec<serde_json::Value> =
            json_stdout.lines().filter_map(extract_json_event).collect();
        assert!(
            parsed_json_events.iter().any(|event| {
                event["level"] == "INFO"
                    && event["fields"]["status"] == 200
                    && event["span"]["request_id"] == "subprocess-json-req-id"
            }),
            "expected JSON log event with request_id in stdout: {json_stdout}"
        );

        let text_out = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "main_isolation_tests::init_tracing_emits_json_and_text_request_id_logs_by_af_log_format",
                "--nocapture",
            ])
            .env(MODE_ENV, "text")
            .env_remove("AF_LOG_FORMAT")
            .env_remove("RUST_LOG")
            .output()
            .unwrap();
        assert!(
            text_out.status.success(),
            "text subprocess failed: {}",
            String::from_utf8_lossy(&text_out.stderr)
        );
        let text_stdout = String::from_utf8_lossy(&text_out.stdout);
        assert!(
            text_stdout.contains("subprocess-text-req-id"),
            "expected text log line with request_id in stdout: {text_stdout}"
        );
        assert!(
            !text_stdout.lines().any(|line| {
                extract_json_event(line)
                    .is_some_and(|v| v["span"]["request_id"] == "subprocess-text-req-id")
            }),
            "default text mode must not emit JSON log lines: {text_stdout}"
        );
    }
}

#[cfg(test)]
mod sec09_forwarding_tests {
    use super::normalize_peer_forwarding_middleware;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{HeaderMap, Request};
    use axum::routing::get;
    use axum::Router;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    async fn resolved_ip(peer: &str, xff: &str) -> String {
        // Mirrors the production stack: the subdomain middleware layer only sees `HeaderMap`
        // (like `app_launch::authenticated_admin`) and sits inside the outer normalisation layer.
        let app = Router::new()
            .route(
                "/probe",
                get(|headers: HeaderMap| async move { crate::ws::extract_client_ip(&headers) }),
            )
            .layer(axum::middleware::from_fn(
                normalize_peer_forwarding_middleware,
            ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/probe")
                    .header("x-forwarded-for", xff)
                    .header("x-real-ip", xff)
                    .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn sec09_outer_layer_strips_spoofed_forwarding_from_untrusted_peers() {
        if std::env::var("TRUSTED_PROXIES").is_ok_and(|v| !v.trim().is_empty()) {
            return;
        }
        assert_eq!(
            resolved_ip("203.0.113.50:4000", "10.9.8.7").await,
            "203.0.113.50"
        );
        assert_eq!(
            resolved_ip("127.0.0.1:4000", "198.51.100.8").await,
            "198.51.100.8"
        );
    }
}
