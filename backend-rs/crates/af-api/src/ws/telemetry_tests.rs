use super::Telemetry;
use serde_json::{json, Value};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::task::Poll;
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};

#[test]
fn ordinary_and_plugin_services_frames_do_not_expose_update_diagnostics() {
    let frame = json!({"type":"METRICS_UPDATE", "data":{"services": {
        "Fixture": {"id":"fixture", "status":"running", "update_error":"SYNTHETIC_PRIVATE_DIAGNOSTIC /etc/private/config"}
    }}});
    let serialized = super::websocket_message_for_session(frame.to_string(), false).unwrap();
    assert!(!serialized.contains("SYNTHETIC_PRIVATE_DIAGNOSTIC"));
    let safe: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(
        safe["data"]["services"]["Fixture"]["update_error"],
        "Update status could not be confirmed"
    );
    assert_eq!(safe["data"]["services"]["Fixture"]["status"], "running");
}

#[test]
fn admin_package_progress_redacts_raw_secrets() {
    let frame = json!({
        "type": "package:progress",
        "package_id": "radarr",
        "action": "install",
        "status": "installing",
        "line": "Configuring secret AF_PASS=supersecretpassword123 for installation",
        "progress": 50,
    });
    let serialized = super::websocket_message_for_session(frame.to_string(), true).unwrap();
    assert!(!serialized.contains("supersecretpassword123"));
    assert!(serialized.contains("[REDACTED]"));
}

#[test]
fn admin_ws_metrics_and_marketplace_snapshot_redacts_diagnostic_secrets() {
    let frame = json!({
        "type": "METRICS_UPDATE",
        "data": {
            "services": {
                "sonarr": {
                    "id": "sonarr",
                    "status": "running",
                    "log_line": "Starting service with admin_passwd=supersecretpassword123",
                    "last_job": {
                        "job_id": "job-1",
                        "action": "update",
                        "status": "failed",
                        "message": "failed with auth_token=secret_auth_token_999",
                        "sanitized_summary": "failure details: db_secret=secret_db_pass_888",
                        "error": "encountered rclone_rc_pass=super_secret_rc_pass",
                        "output": "curl -H 'Authorization: Bearer my_super_secret_bearer_token'"
                    }
                }
            }
        }
    });
    let serialized = super::websocket_message_for_session(frame.to_string(), true).unwrap();
    assert!(!serialized.contains("supersecretpassword123"));
    assert!(!serialized.contains("secret_auth_token_999"));
    assert!(!serialized.contains("secret_db_pass_888"));
    assert!(!serialized.contains("super_secret_rc_pass"));
    assert!(!serialized.contains("my_super_secret_bearer_token"));
    assert!(serialized.contains("[REDACTED]"));
}

#[test]
fn admin_ws_projections_redact_basic_auth_curl_and_json_boundary_secrets() {
    let frame = json!({
        "type": "package:progress",
        "package_id": "radarr",
        "action": "install",
        "status": "installing",
        "line": "Executing curl -u admin:mysecret123 http://repo.local with --pass pass_val_456 and Authorization: Basic dXNlcjpwYXNz and password={\"raw\":\"boundary_pass_789\"}",
        "progress": 70,
    });
    let serialized = super::websocket_message_for_session(frame.to_string(), true).unwrap();
    assert!(!serialized.contains("mysecret123"));
    assert!(!serialized.contains("pass_val_456"));
    assert!(!serialized.contains("dXNlcjpwYXNz"));
    assert!(!serialized.contains("boundary_pass_789"));
    assert!(serialized.contains("curl -u [REDACTED]"));
    assert!(serialized.contains("--pass [REDACTED]"));
    assert!(serialized.contains("Basic [REDACTED]"));
    assert!(serialized.contains("[REDACTED]"));
}

#[tokio::test]
async fn admin_ws_final_gate_fragments_and_marked_headers_are_masked() {
    let long_key = format!(
        r#""{}Pass\u0077ordEncoded":"FRAGMENT_CANARY""#,
        "x".repeat(125)
    );
    for line in [
        long_key.as_str(),
        r#""databaseCookieEncoded":"FRAGMENT_CANARY""#,
        r#""databaseSessionEncoded":"FRAGMENT_CANARY""#,
        r#""incomingWebhookEncoded":"FRAGMENT_CANARY""#,
        r#""databasePass\u0077ordEncoded":"FRAGMENT_CANARY""#,
        "Cookie: [REDACTED] sid=FRAGMENT_CANARY",
        "Authorization: [REDACTED] FRAGMENT_CANARY",
    ] {
        let mut input = line.to_string();
        for _ in 0..3 {
            let frame = json!({
                "type": "package:progress", "package_id": "sonarr",
                "action": "update", "status": "updating", "line": input,
                "progress": 50,
            })
            .to_string();
            for privileged in [true, false] {
                let projected =
                    super::websocket_message_for_session(frame.clone(), privileged).unwrap();
                assert!(!projected.contains("FRAGMENT_CANARY"), "{projected}");
                let repeated = super::websocket_message_for_session(projected, privileged).unwrap();
                assert!(!repeated.contains("FRAGMENT_CANARY"), "{repeated}");
            }
            input = format!("AF_DIAG_FAILURE={}", json!({"summary": input}));
        }
    }
}

#[tokio::test]
async fn failed_service_snapshot_preserves_known_inventory_until_recovery() {
    let telemetry = Arc::new(Telemetry::new());
    let known = json!({"Fixture": {"status": "running"}});
    let refresh = telemetry
        .try_start_service_refresh({
            let known = known.clone();
            move || Ok(known)
        })
        .unwrap();
    watchdog(refresh).await.unwrap();
    telemetry.services.lock().unwrap().last_finished = None;
    let failed = telemetry
        .try_start_service_refresh(|| anyhow::bail!("journal unavailable"))
        .unwrap();
    watchdog(failed).await.unwrap();
    let frame = telemetry.metrics_message(json!({"cpu_usage": 12.0}));
    assert_eq!(frame["data"]["services"], known);
    telemetry.services.lock().unwrap().last_finished = None;
    let recovered = json!({"Fixture": {"status": "stopped"}});
    let refresh = telemetry
        .try_start_service_refresh({
            let recovered = recovered.clone();
            move || Ok(recovered)
        })
        .unwrap();
    watchdog(refresh).await.unwrap();
    assert_eq!(
        telemetry.metrics_message(Value::Null)["data"]["services"],
        recovered
    );
    let initial = Arc::new(Telemetry::new());
    watchdog(
        initial
            .try_start_service_refresh(|| anyhow::bail!("journal unavailable"))
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(initial.metrics_message(Value::Null)["data"]["services"].is_null());
}

async fn watchdog<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("telemetry operation did not make progress")
}

async fn receive_message(receiver: &mut broadcast::Receiver<String>) -> Value {
    let text = watchdog(receiver.recv()).await.expect("broadcast closed");
    serde_json::from_str(&text).expect("valid telemetry JSON")
}

#[test]
fn stalled_services_do_not_block_metrics_or_initial_snapshot() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .expect("test runtime");
    runtime.block_on(assert_stalled_services_do_not_block_metrics_or_initial_snapshot());
}

async fn assert_stalled_services_do_not_block_metrics_or_initial_snapshot() {
    let telemetry = Arc::new(Telemetry::new());
    let mut receiver = telemetry.broadcast.subscribe();
    let (started_sender, started_receiver) = oneshot::channel();
    let (release_sender, release_receiver) = mpsc::channel();
    let service_value = json!({
        "Apache2 Web Server": {
            "id": "apache2",
            "status": "running",
            "uptime": "Active",
            "version": "system",
            "managed_by": "systemd",
            "process": "apache2",
            "units": ["apache2"]
        }
    });
    let expected_services = service_value.clone();
    let refresh = telemetry
        .try_start_service_refresh(move || {
            started_sender.send(()).expect("start receiver open");
            release_receiver.recv().expect("release sender open");
            Ok(service_value)
        })
        .expect("first scan starts");
    watchdog(started_receiver).await.expect("scan started");

    for _attempt in 0..32 {
        assert!(telemetry
            .try_start_service_refresh(|| panic!("overlapping scan started"))
            .is_none());
    }

    let snapshot = telemetry.initial_snapshot();
    tokio::pin!(snapshot);
    assert!(matches!(futures::poll!(&mut snapshot), Poll::Pending));

    let metrics = serde_json::to_value(af_models::SystemMetrics::default()).unwrap();
    let collected_metrics = metrics.clone();
    let metrics_loop =
        tokio::spawn(Arc::clone(&telemetry).metrics_loop(move || collected_metrics.clone()));
    let first_broadcast = receive_message(&mut receiver).await;
    let first_snapshot = watchdog(snapshot).await;
    assert_eq!(first_snapshot, first_broadcast);
    assert_eq!(first_snapshot["type"], "METRICS_UPDATE");
    assert_eq!(first_snapshot["data"]["system"], metrics);
    assert!(first_snapshot["data"]["services"].is_null());

    metrics_loop.abort();
    let _ = metrics_loop.await;
    let mut receiver = telemetry.broadcast.subscribe();
    watchdog(telemetry.collect_metrics(|| json!({"cpu_usage": 42.0}))).await;
    let next_broadcast = receive_message(&mut receiver).await;
    assert_eq!(next_broadcast["data"]["system"]["cpu_usage"], 42.0);
    assert!(next_broadcast["data"]["services"].is_null());

    release_sender.send(()).expect("scan still waiting");
    watchdog(refresh).await.expect("scan task completed");
    assert!(telemetry
        .try_start_service_refresh(|| panic!("fresh cache was rescanned"))
        .is_none());
    watchdog(telemetry.collect_metrics(|| json!({"cpu_usage": 43.0}))).await;
    let updated_broadcast = receive_message(&mut receiver).await;
    assert_eq!(updated_broadcast["data"]["system"]["cpu_usage"], 43.0);
    assert_eq!(updated_broadcast["data"]["services"], expected_services);
    assert_eq!(
        watchdog(telemetry.initial_snapshot()).await["data"]["services"],
        expected_services
    );
}

#[test]
fn unknown_and_empty_service_caches_have_distinct_payloads() {
    let telemetry = Telemetry::new();
    let initial = telemetry.metrics_message(json!({}));
    assert!(initial["data"]["services"].is_null());

    telemetry.services.lock().unwrap().value = Some(json!({}));
    let completed = telemetry.metrics_message(json!({}));
    assert_eq!(completed["data"]["services"], json!({}));
}

#[tokio::test(flavor = "current_thread")]
async fn metrics_warm_once_without_subscribers() {
    let telemetry = Arc::new(Telemetry::new());
    assert!(telemetry.needs_metrics());
    watchdog(telemetry.collect_metrics(|| json!({"cpu_usage": 1.0}))).await;
    assert!(!telemetry.needs_metrics());

    let receiver = telemetry.broadcast.subscribe();
    assert!(telemetry.needs_metrics());
    drop(receiver);
    assert!(!telemetry.needs_metrics());
}

#[tokio::test(flavor = "current_thread")]
async fn subscriber_demand_starts_and_publishes_service_refresh() {
    let telemetry = Arc::new(Telemetry::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let (started_sender, started_receiver) = oneshot::channel();
    let started_sender = Arc::new(Mutex::new(Some(started_sender)));
    let (release_sender, release_receiver) = mpsc::channel();
    let release_receiver = Arc::new(Mutex::new(release_receiver));
    let collector = {
        let calls = Arc::clone(&calls);
        let started_sender = Arc::clone(&started_sender);
        let release_receiver = Arc::clone(&release_receiver);
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            if let Some(sender) = started_sender.lock().unwrap().take() {
                let _ = sender.send(());
            }
            release_receiver.lock().unwrap().recv().unwrap();
            Ok(json!({"apache2": {"status": "running"}}))
        }
    };
    let services_loop = tokio::spawn(Arc::clone(&telemetry).services_loop(collector));
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let mut receiver = telemetry.broadcast.subscribe();
    telemetry.service_refresh.notify_one();
    watchdog(started_receiver).await.expect("scan started");
    for _attempt in 0..32 {
        telemetry.service_refresh.notify_one();
        assert!(telemetry
            .try_start_service_refresh(|| panic!("overlapping scan started"))
            .is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let metrics_loop =
        tokio::spawn(Arc::clone(&telemetry).metrics_loop(|| json!({"cpu_usage": 42.0})));
    release_sender.send(()).expect("scan still waiting");
    let expected_services = json!({"apache2": {"status": "running"}});
    let published = watchdog(async {
        loop {
            let message = receive_message(&mut receiver).await;
            if message["data"]["services"] == expected_services {
                break message;
            }
        }
    })
    .await;
    assert_eq!(published["type"], "METRICS_UPDATE");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    services_loop.abort();
    metrics_loop.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn unwinding_service_refresh_preserves_cache_and_releases_single_flight() {
    let telemetry = Arc::new(Telemetry::new());
    let refresh = telemetry
        .try_start_service_refresh(|| Ok(json!({"apache2": {"status": "running"}})))
        .expect("first scan starts");
    watchdog(refresh).await.expect("first scan completed");
    {
        let mut services = telemetry.services.lock().unwrap();
        services.last_finished = None;
    }

    let refresh = telemetry
        .try_start_service_refresh(|| panic!("simulated collector failure"))
        .expect("retry starts");
    watchdog(refresh).await.expect("failed scan was observed");
    let services = telemetry.services.lock().unwrap();
    assert!(!services.in_flight);
    assert!(services.last_finished.is_some());
    assert_eq!(
        services.value,
        Some(json!({"apache2": {"status": "running"}}))
    );
}
