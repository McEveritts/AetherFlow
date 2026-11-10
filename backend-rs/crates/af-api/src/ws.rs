use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, oneshot, watch, Notify};
use tokio::time::MissedTickBehavior;

#[derive(Clone, Debug)]
struct WsTicketEntry {
    user_id: i64,
    client_ip: String,
    expires_at: Instant,
    diagnostics_allowed: bool,
}

static WS_TICKETS: Lazy<Mutex<HashMap<String, WsTicketEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const METRICS_INTERVAL: Duration = Duration::from_secs(1);
const SERVICES_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Default)]
struct ServiceCache {
    value: Option<serde_json::Value>,
    in_flight: bool,
    last_finished: Option<Instant>,
}

struct Telemetry {
    broadcast: broadcast::Sender<String>,
    metrics: watch::Sender<Option<serde_json::Value>>,
    services: Mutex<ServiceCache>,
    service_refresh: Notify,
}

impl Telemetry {
    fn new() -> Self {
        let (broadcast, _) = broadcast::channel(256);
        let (metrics, _) = watch::channel(None);
        Self {
            broadcast,
            metrics,
            services: Mutex::new(ServiceCache::default()),
            service_refresh: Notify::new(),
        }
    }

    fn metrics_message(&self, metrics: serde_json::Value) -> serde_json::Value {
        let services = self
            .services
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .value
            .clone()
            .unwrap_or(serde_json::Value::Null);
        serde_json::json!({
            "type": "METRICS_UPDATE",
            "data": {
                "system": metrics,
                "services": services,
            }
        })
    }

    fn broadcast_message(&self, payload: &serde_json::Value) {
        if let Ok(text) = serde_json::to_string(payload) {
            let _ = self.broadcast.send(text);
        }
    }

    fn needs_metrics(&self) -> bool {
        self.broadcast.receiver_count() > 0 || self.metrics.borrow().is_none()
    }

    async fn collect_metrics<F>(&self, collector: F)
    where
        F: FnOnce() -> serde_json::Value + Send + 'static,
    {
        match tokio::task::spawn_blocking(collector).await {
            Ok(metrics) => {
                self.metrics.send_replace(Some(metrics.clone()));
                if self.broadcast.receiver_count() > 0 {
                    self.broadcast_message(&self.metrics_message(metrics));
                }
            }
            Err(error) => tracing::warn!(%error, "WebSocket metrics collection failed"),
        }
    }

    async fn metrics_loop<F>(self: Arc<Self>, collector: F)
    where
        F: Fn() -> serde_json::Value + Clone + Send + 'static,
    {
        let mut tick = tokio::time::interval(METRICS_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if self.needs_metrics() {
                self.collect_metrics(collector.clone()).await;
            }
        }
    }

    fn try_start_service_refresh<F>(self: &Arc<Self>, collector: F) -> Option<oneshot::Receiver<()>>
    where
        F: FnOnce() -> anyhow::Result<serde_json::Value> + Send + 'static,
    {
        {
            let mut services = self
                .services
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if services.in_flight
                || services
                    .last_finished
                    .is_some_and(|finished| finished.elapsed() < SERVICES_INTERVAL)
            {
                return None;
            }
            services.in_flight = true;
        }

        let telemetry = Arc::clone(self);
        let (finished_sender, finished_receiver) = oneshot::channel();
        match std::thread::Builder::new()
            .name("ws-services".to_string())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(collector));
                let failed = !matches!(&result, Ok(Ok(_)));
                {
                    let mut services = telemetry
                        .services
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    services.in_flight = false;
                    services.last_finished = Some(Instant::now());
                    if let Ok(Ok(value)) = result {
                        services.value = Some(value);
                    }
                }
                if failed {
                    tracing::warn!("WebSocket service collection failed");
                }
                let _ = finished_sender.send(());
            }) {
            Ok(_) => Some(finished_receiver),
            Err(error) => {
                {
                    let mut services = self
                        .services
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    services.in_flight = false;
                    services.last_finished = Some(Instant::now());
                }
                tracing::warn!(%error, "Could not start WebSocket service collector");
                None
            }
        }
    }

    async fn services_loop<F>(self: Arc<Self>, collector: F)
    where
        F: Fn() -> anyhow::Result<serde_json::Value> + Clone + Send + 'static,
    {
        let mut tick = tokio::time::interval(SERVICES_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = tick.tick() => {}
                _ = self.service_refresh.notified() => {}
            }
            if self.broadcast.receiver_count() == 0 {
                continue;
            }
            if let Some(refresh) = self.try_start_service_refresh(collector.clone()) {
                let _ = refresh.await;
                tick.reset();
            }
        }
    }

    async fn initial_snapshot(&self) -> serde_json::Value {
        let mut metrics = self.metrics.subscribe();
        loop {
            let cached = metrics.borrow_and_update().clone();
            if let Some(cached) = cached {
                return self.metrics_message(cached);
            }
            if metrics.changed().await.is_err() {
                return self.metrics_message(serde_json::Value::Null);
            }
        }
    }
}

static TELEMETRY: Lazy<Arc<Telemetry>> = Lazy::new(|| Arc::new(Telemetry::new()));

pub fn broadcast_ws_message(payload: &serde_json::Value) {
    TELEMETRY.broadcast_message(payload);
}

pub(crate) fn package_diagnostics_allowed(user: &crate::auth::AuthUser) -> bool {
    user.role == "admin" && user.plugin_id.is_none() && user.plugin_scopes.is_empty()
}

/// Shared HTTP/WebSocket projection for ordinary and plugin status viewers.
/// New internal fields are private until explicitly added to this allowlist.
pub(crate) fn sanitize_services_for_viewer(services: &mut serde_json::Value) {
    let Some(services) = services.as_object_mut() else {
        return;
    };
    for service in services.values_mut() {
        let Some(service) = service.as_object_mut() else {
            continue;
        };
        service.retain(|field, _| {
            matches!(
                field.as_str(),
                "id" | "status"
                    | "uptime"
                    | "version"
                    | "managed_by"
                    | "process"
                    | "default_port"
                    | "active_port"
                    | "internal_domain"
                    | "public_domain"
                    | "external_access_enabled"
                    | "tls_enabled"
                    | "web_path"
                    | "web_scheme"
                    | "bind_scope"
                    | "control_scope"
                    | "components"
                    | "units"
                    | "installed_version"
                    | "latest_version"
                    | "update_available"
                    | "update_checked_at"
                    | "update_url"
                    | "update_error"
                    | "job_status"
                    | "job_id"
                    | "progress"
                    | "log_line"
                    | "started_at"
                    | "last_job"
            )
        });
        if let Some(error) = service.get_mut("update_error") {
            *error = af_services::workers::public_update_error(error.as_str().unwrap_or("")).into();
        }
        let summary = af_services::package_job_progress_summary(
            service
                .get("job_status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        );
        if service
            .get("log_line")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|line| !line.is_empty())
        {
            service.insert("log_line".into(), summary.into());
        }
        if let Some(outcome) = service
            .get_mut("last_job")
            .and_then(serde_json::Value::as_object_mut)
        {
            outcome.retain(|field, _| {
                matches!(
                    field.as_str(),
                    "job_id" | "package_id" | "action" | "status" | "started_at" | "finished_at" | "expected_target_version" | "achieved_version"
                )
            });
        }
    }
}

pub fn sanitize_log_line(line: &str) -> String {
    af_services::redact_secrets(line)
}

pub fn sanitize_diagnostic_text_fields(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if matches!(
                    k.as_str(),
                    "sanitized_summary"
                        | "message"
                        | "error"
                        | "log_line"
                        | "line"
                        | "output"
                        | "update_error"
                        | "stderr"
                        | "stdout"
                ) {
                    if let Some(s) = v.as_str() {
                        *v = sanitize_log_line(s).into();
                    }
                }
                sanitize_diagnostic_text_fields(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                sanitize_diagnostic_text_fields(item);
            }
        }
        _ => {}
    }
}

fn websocket_message_for_session(message: String, diagnostics_allowed: bool) -> Option<String> {
    let mut payload: serde_json::Value = serde_json::from_str(&message).ok()?;
    match payload.get("type").and_then(serde_json::Value::as_str) {
        Some("package:progress") => {
            if diagnostics_allowed {
                sanitize_diagnostic_text_fields(&mut payload);
                return serde_json::to_string(&payload).ok();
            }
            let mut sanitized = serde_json::json!({"type": "package:progress"});
            for field in [
                "package_id",
                "job_id",
                "action",
                "status",
                "started_at",
                "finished_at",
                "expected_target_version",
                "achieved_version",
            ] {
                if let Some(value) = payload.get(field).and_then(serde_json::Value::as_str) {
                    sanitized[field] = value.into();
                }
            }
            sanitized["progress"] = payload
                .get("progress")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0)
                .clamp(0, 100)
                .into();
            sanitized["line"] = af_services::package_job_progress_summary(
                payload
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            )
            .into();
            payload = sanitized;
        }
        Some("METRICS_UPDATE") => {
            if !diagnostics_allowed {
                if let Some(services) = payload
                    .get_mut("data")
                    .and_then(|data| data.get_mut("services"))
                {
                    sanitize_services_for_viewer(services);
                }
            }
        }
        _ => {
            if let Some(line) = payload.get("line").and_then(serde_json::Value::as_str) {
                payload["line"] = sanitize_log_line(line).into();
            }
            if let Some(log) = payload.get("log").and_then(serde_json::Value::as_str) {
                payload["log"] = sanitize_log_line(log).into();
            }
        }
    }
    sanitize_diagnostic_text_fields(&mut payload);
    serde_json::to_string(&payload).ok()
}

pub fn start_metrics_broadcast_loop() {
    let telemetry = Arc::clone(&TELEMETRY);
    tokio::spawn(telemetry.metrics_loop(|| {
        serde_json::to_value(af_hardware::get_system_metrics_core()).unwrap_or_default()
    }));

    let telemetry = Arc::clone(&TELEMETRY);
    tokio::spawn(telemetry.services_loop(|| {
        Ok(serde_json::to_value(af_services::get_active_services()?)?)
    }));
}

#[cfg(test)]
mod telemetry_tests {
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
        assert_eq!(safe["data"]["services"]["Fixture"]["update_error"], "Update status could not be confirmed");
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
        let long_key = format!(r#""{}Pass\u0077ordEncoded":"FRAGMENT_CANARY""#, "x".repeat(125));
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
                }).to_string();
                for privileged in [true, false] {
                    let projected = super::websocket_message_for_session(frame.clone(), privileged).unwrap();
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
}

pub fn issue_ws_ticket_for_user(user_id: i64, client_ip: &str) -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let ticket = hex::encode(b);

    if let Ok(mut map) = WS_TICKETS.lock() {
        map.retain(|_, v| v.expires_at > Instant::now());
        map.insert(
            ticket.clone(),
            WsTicketEntry {
                user_id,
                client_ip: client_ip.to_string(),
                expires_at: Instant::now() + Duration::from_secs(90),
                diagnostics_allowed: false,
            },
        );
    }
    ticket
}

fn is_loopback_ip(ip: &str) -> bool {
    matches!(ip, "127.0.0.1" | "::1" | "localhost" | "")
}

#[derive(Deserialize)]
pub struct WsTicketQuery {
    #[serde(default)]
    pub ticket: String,
}

fn consume_live_ws_ticket(
    connection: &rusqlite::Connection,
    ticket: &str,
) -> Option<WsTicketEntry> {
    let mut entry = WS_TICKETS.lock().ok().and_then(|mut map| {
        map.retain(|_, value| value.expires_at > Instant::now());
        map.remove(ticket)
    })?;
    let role: String = connection
        .query_row(
            "SELECT role FROM users WHERE id = ?1",
            [entry.user_id],
            |row| row.get(0),
        )
        .ok()?;
    entry.diagnostics_allowed = role == "admin";
    Some(entry)
}

#[cfg(test)]
mod lifecycle_tests {
    use super::{consume_live_ws_ticket, issue_ws_ticket_for_user, websocket_message_for_session};

    #[test]
    fn websocket_progress_filters_installer_output_per_recipient() {
        let message = serde_json::json!({
            "type": "package:progress", "package_id": "sonarr", "job_id": "job-42",
            "action": "update", "status": "updating", "progress": 42,
            "started_at": "fixture", "line": "PASSWORD=private-installer-output",
            "message": "PASSWORD=private-installer-output", "stderr": "TOKEN=private-installer-output",
        })
        .to_string();
        let admin = websocket_message_for_session(message.clone(), true).unwrap();
        assert!(!admin.contains("private-installer-output"), "raw secrets must be redacted for admin");
        assert!(admin.contains("[REDACTED]"), "sanitized secrets must be marked REDACTED");
        let admin_val: serde_json::Value = serde_json::from_str(&admin).unwrap();
        assert_eq!(admin_val["job_id"], "job-42");
        assert_eq!(admin_val["package_id"], "sonarr");
        assert_eq!(admin_val["status"], "updating");
        assert_eq!(admin_val["progress"], 42);
        assert_eq!(admin_val["line"], "PASSWORD=[REDACTED]");

        let ordinary = websocket_message_for_session(message, false).unwrap();
        assert!(!ordinary.contains("private-installer-output"));
        let ordinary: serde_json::Value = serde_json::from_str(&ordinary).unwrap();
        assert_eq!(ordinary["job_id"], "job-42");
        assert_eq!(ordinary["package_id"], "sonarr");
        assert_eq!(ordinary["status"], "updating");
        assert_eq!(ordinary["progress"], 42);
        assert_eq!(ordinary["line"], "Updating application.");
        assert!(ordinary.get("stderr").is_none());
        assert!(ordinary.get("message").is_none());
    }

    #[test]
    fn test_websocket_progress_escaped_quote_and_nested_json_redaction() {
        let message = serde_json::json!({
            "type": "package:progress", "package_id": "sonarr", "job_id": "job-99",
            "action": "install", "status": "installing", "progress": 50,
            "line": "{\"password\": \"my\\\"super\\\\secret\"}",
            "message": "auth config: {\"credentials\": {\"token\": \"nested\\\"token\\\"val\"}}",
            "stderr": "error: password=\"truncated\\\"pass",
        })
        .to_string();

        let admin = websocket_message_for_session(message, true).unwrap();
        assert!(!admin.contains("super\\secret"));
        assert!(!admin.contains("nested\\\"token"));
        assert!(!admin.contains("truncated\\\"pass"));
        assert!(admin.contains("[REDACTED]"));
    }

    #[test]
    fn websocket_service_snapshots_cannot_bypass_progress_sanitization() {
        let message = serde_json::json!({
            "type": "METRICS_UPDATE", "data": {
                "system": {"cpu_usage": 20}, "services": {"sonarr": {
                    "job_id": "job-42", "job_status": "updating", "progress": 42,
                    "api_key": "synthetic-service-credential",
                    "future_private_field": "synthetic-private-config",
                    "log_line": "STEP=private-installer-output",
                    "last_job": {"job_id": "old-job", "status": "failed", "message": "private-installer-output"},
                }}
            }
        }).to_string();
        assert_eq!(
            websocket_message_for_session(message.clone(), true).unwrap(),
            message
        );
        let ordinary = websocket_message_for_session(message, false).unwrap();
        assert!(!ordinary.contains("private-installer-output"));
        let ordinary: serde_json::Value = serde_json::from_str(&ordinary).unwrap();
        assert!(!ordinary
            .to_string()
            .contains("synthetic-service-credential"));
        assert!(!ordinary.to_string().contains("synthetic-private-config"));
        assert!(ordinary["data"]["services"]["sonarr"]
            .get("api_key")
            .is_none());
        assert_eq!(ordinary["data"]["services"]["sonarr"]["job_id"], "job-42");
        assert_eq!(ordinary["data"]["services"]["sonarr"]["progress"], 42);
        assert_eq!(ordinary["data"]["system"]["cpu_usage"], 20);
    }

    #[test]
    fn established_websocket_privileges_are_revoked_and_never_promoted() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, role TEXT NOT NULL); INSERT INTO users VALUES (1, 'admin');",
        ).unwrap();
        let ticket = issue_ws_ticket_for_user(1, "127.0.0.1");
        let mut entry = consume_live_ws_ticket(&connection, &ticket).unwrap();
        assert_eq!(
            super::refresh_ws_authorization(&connection, &mut entry),
            Some(true)
        );
        connection
            .execute("UPDATE users SET role='user' WHERE id=1", [])
            .unwrap();
        assert_eq!(
            super::refresh_ws_authorization(&connection, &mut entry),
            Some(false)
        );
        connection
            .execute("UPDATE users SET role='admin' WHERE id=1", [])
            .unwrap();
        assert_eq!(
            super::refresh_ws_authorization(&connection, &mut entry),
            Some(false)
        );
        connection.execute("DELETE FROM users", []).unwrap();
        assert_eq!(
            super::refresh_ws_authorization(&connection, &mut entry),
            None
        );
        connection.execute_batch("DROP TABLE users").unwrap();
        assert_eq!(
            super::refresh_ws_authorization(&connection, &mut entry),
            None
        );
    }

    #[test]
    fn issued_websocket_tickets_are_single_use_and_reject_deleted_users() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, role TEXT NOT NULL); INSERT INTO users VALUES (1, 'admin'), (2, 'user');",
            )
            .unwrap();
        let ticket = issue_ws_ticket_for_user(1, "127.0.0.1");
        assert_eq!(
            consume_live_ws_ticket(&connection, &ticket)
                .unwrap()
                .user_id,
            1
        );
        assert!(consume_live_ws_ticket(&connection, &ticket).is_none());
        let demoted_ticket = issue_ws_ticket_for_user(1, "127.0.0.1");
        connection
            .execute("UPDATE users SET role='user' WHERE id=1", [])
            .unwrap();
        assert!(
            !consume_live_ws_ticket(&connection, &demoted_ticket)
                .unwrap()
                .diagnostics_allowed
        );
        let admin_ticket = issue_ws_ticket_for_user(1, "127.0.0.1");
        connection
            .execute("UPDATE users SET role='admin' WHERE id=1", [])
            .unwrap();
        assert!(
            consume_live_ws_ticket(&connection, &admin_ticket)
                .unwrap()
                .diagnostics_allowed
        );
        let deleted_ticket = issue_ws_ticket_for_user(1, "127.0.0.1");
        let live_ticket = issue_ws_ticket_for_user(2, "127.0.0.1");
        connection
            .execute("DELETE FROM users WHERE id = 1", [])
            .unwrap();
        assert!(consume_live_ws_ticket(&connection, &deleted_ticket).is_none());
        assert_eq!(
            consume_live_ws_ticket(&connection, &live_ticket)
                .unwrap()
                .user_id,
            2
        );
        connection.execute("DROP TABLE users", []).unwrap();
        let unavailable_ticket = issue_ws_ticket_for_user(2, "127.0.0.1");
        assert!(consume_live_ws_ticket(&connection, &unavailable_ticket).is_none());
    }
}

pub async fn handle_websocket(
    Query(q): Query<WsTicketQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if q.ticket.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "code": "WS_MISSING_TICKET",
                "message": "Missing ticket"
            })),
        )
            .into_response();
    }

    let entry_opt = tokio::task::spawn_blocking(move || {
        let connection = af_db::get_read_conn().ok()?;
        consume_live_ws_ticket(&connection, &q.ticket)
    }).await.ok().flatten();

    let Some(entry) = entry_opt else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "code": "WS_INVALID_TICKET",
                "message": "Invalid or expired ticket"
            })),
        )
            .into_response();
    };

    let client_ip = extract_client_ip(&headers);
    if !entry.client_ip.is_empty()
        && !client_ip.is_empty()
        && entry.client_ip != client_ip
        && !(is_loopback_ip(&entry.client_ip) && is_loopback_ip(&client_ip))
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "code": "WS_IP_MISMATCH",
                "message": "Ticket IP mismatch"
            })),
        )
            .into_response();
    }

    ws.on_upgrade(move |socket| handle_ws_socket(socket, entry))
}

// A ticket authorizes the upgrade only. Existing sockets must not keep a stale
// administrative capability after the account is demoted or removed.
fn refresh_ws_authorization(
    connection: &rusqlite::Connection,
    entry: &mut WsTicketEntry,
) -> Option<bool> {
    let role: String = connection
        .query_row(
            "SELECT role FROM users WHERE id = ?1",
            [entry.user_id],
            |row| row.get(0),
        )
        .ok()?;
    entry.diagnostics_allowed &= role == "admin";
    Some(entry.diagnostics_allowed)
}

async fn current_ws_authorization(entry: &mut WsTicketEntry) -> Option<bool> {
    let mut checked = entry.clone();
    let allowed = tokio::task::spawn_blocking(move || {
        let connection = af_db::get_read_conn().ok()?;
        refresh_ws_authorization(&connection, &mut checked)
    })
    .await
    .ok()??;
    entry.diagnostics_allowed = allowed;
    Some(allowed)
}

async fn handle_ws_socket(socket: WebSocket, mut entry: WsTicketEntry) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = TELEMETRY.broadcast.subscribe();
    TELEMETRY.service_refresh.notify_one();

    let init_payload = TELEMETRY.initial_snapshot().await;
    let Some(diagnostics_allowed) = current_ws_authorization(&mut entry).await else {
        let _ = sender.send(Message::Close(None)).await;
        return;
    };
    if let Some(text) = serde_json::to_string(&init_payload)
        .ok()
        .and_then(|text| websocket_message_for_session(text, diagnostics_allowed))
    {
        let _ = sender.send(Message::Text(text)).await;
    }

    let mut write_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval(Duration::from_secs(54));
        loop {
            tokio::select! {
                Ok(msg) = rx.recv() => {
                    let Some(diagnostics_allowed) = current_ws_authorization(&mut entry).await else {
                        let _ = sender.send(Message::Close(None)).await;
                        break;
                    };
                    if let Some(message) = websocket_message_for_session(msg, diagnostics_allowed) {
                        if sender.send(Message::Text(message)).await.is_err() {
                            break;
                        }
                    }
                }
                _ = ping_interval.tick() => {
                    if current_ws_authorization(&mut entry).await.is_none() {
                        let _ = sender.send(Message::Close(None)).await;
                        break;
                    }
                    if sender.send(Message::Ping(Vec::new())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut read_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    });

    tokio::select! {
        _ = (&mut write_task) => read_task.abort(),
        _ = (&mut read_task) => write_task.abort(),
    }
}

#[derive(Deserialize, Default, Clone)]
struct WsLogFilter {
    #[serde(default)]
    source: String,
    #[serde(default)]
    unit: String,
    #[serde(default)]
    priority: String,
    #[serde(default)]
    keyword: String,
}

fn parse_live_log_line(line: &str, default_source: &str) -> serde_json::Value {
    let trimmed = line.trim();
    // Format from `journalctl -o short-iso`: `<ISO-timestamp> <host> <unit>[pid]: <message>`
    let mut parts = trimmed.splitn(3, ' ');
    let first = parts.next().unwrap_or("");
    let (timestamp, host, remainder) = if first.len() >= 19 && first.contains('T') {
        let host = parts.next().unwrap_or("localhost");
        let rest = parts.next().unwrap_or(trimmed);
        (first.to_string(), host.to_string(), rest)
    } else {
        (chrono::Utc::now().to_rfc3339(), "localhost".to_string(), trimmed)
    };

    let (unit, message) = if let Some((prefix, msg)) = remainder.split_once(": ") {
        let clean_unit = prefix.split('[').next().unwrap_or(prefix).trim();
        (clean_unit.to_string(), msg.to_string())
    } else {
        ("system".to_string(), remainder.to_string())
    };

    let lower = message.to_lowercase();
    let priority = if lower.contains("error") || lower.contains("fatal") || lower.contains("failed") {
        "err"
    } else if lower.contains("warn") {
        "warning"
    } else {
        "info"
    };

    serde_json::json!({
        "timestamp": timestamp,
        "source": default_source,
        "unit": unit,
        "priority": priority,
        "message": message,
        "hostname": host,
    })
}

fn log_entry_matches_filter(entry: &serde_json::Value, filter: &WsLogFilter) -> bool {
    if !filter.source.is_empty() {
        let src = entry.get("source").and_then(|v| v.as_str()).unwrap_or("");
        if !src.eq_ignore_ascii_case(filter.source.trim()) {
            return false;
        }
    }
    if !filter.unit.is_empty() {
        let unit = entry
            .get("unit")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .trim_end_matches(".service");
        let f_unit = filter.unit.trim().trim_end_matches(".service");
        if !unit.eq_ignore_ascii_case(f_unit) {
            return false;
        }
    }
    if !filter.priority.is_empty() {
        let prio = entry.get("priority").and_then(|v| v.as_str()).unwrap_or("");
        if !prio.eq_ignore_ascii_case(filter.priority.trim()) {
            return false;
        }
    }
    if !filter.keyword.is_empty() {
        let msg = entry
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        if !msg.contains(&filter.keyword.trim().to_lowercase()) {
            return false;
        }
    }
    true
}

fn websocket_origin_matches_host(headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    else {
        // Non-browser clients do not send Origin.
        return true;
    };
    let origin_host = origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(origin)
        .trim_end_matches('/');
    let request_host = headers
        .get("X-Forwarded-Host")
        .or_else(|| headers.get(axum::http::header::HOST))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim())
        .unwrap_or("");
    !request_host.is_empty() && origin_host.eq_ignore_ascii_case(request_host)
}

pub async fn handle_log_websocket(
    axum::Extension(user): axum::Extension<crate::auth::AuthUser>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !package_diagnostics_allowed(&user) {
        return crate::auth::api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    if !websocket_origin_matches_host(&headers) {
        return crate::auth::api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Cross-origin WebSocket upgrade rejected",
        );
    }
    let mut authorization = WsTicketEntry {
        user_id: user.user_id,
        client_ip: extract_client_ip(&headers),
        expires_at: Instant::now(),
        diagnostics_allowed: true,
    };
    ws.on_upgrade(move |mut socket| async move {
        // Upgrading a connection does not grant a lasting raw-log capability.
        if current_ws_authorization(&mut authorization).await != Some(true) {
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
        let welcome = serde_json::json!({
            "type": "LOG_ENTRY",
            "data": {
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "source": "aetherflow-api",
                "unit": "aetherflow-api.service",
                "priority": "info",
                "message": "Connected to AetherFlow Rust log stream"
            }
        });
        if let Ok(txt) = serde_json::to_string(&welcome) {
            if socket.send(Message::Text(txt)).await.is_err() {
                return;
            }
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<serde_json::Value>(128);
        let reader_task = tokio::spawn(async move {
            use std::process::Stdio;
            use tokio::io::{AsyncBufReadExt, BufReader};
            use tokio::process::Command;

            // Try journalctl first on Linux, then fall back to tailing system/deploy log files
            let mut spawned: Option<(tokio::process::Child, &'static str)> = None;
            if cfg!(target_os = "linux") {
                if let Ok(child) = Command::new("journalctl")
                    .args(["-f", "-n", "50", "--no-pager", "-o", "short-iso"])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()
                {
                    spawned = Some((child, "journald"));
                }
            }

            if spawned.is_none() {
                let fallback_files = [
                    ("/var/log/aetherflow-deploy.log", "deploy"),
                    ("/var/log/syslog", "syslog"),
                    ("/var/log/messages", "syslog"),
                ];
                for (path, source_name) in fallback_files {
                    if std::path::Path::new(path).exists() {
                        if let Ok(child) = Command::new("tail")
                            .args(["-f", "-n", "50", path])
                            .stdout(Stdio::piped())
                            .stderr(Stdio::null())
                            .kill_on_drop(true)
                            .spawn()
                        {
                            spawned = Some((child, source_name));
                            break;
                        }
                    }
                }
            }

            if let Some((mut child, source_name)) = spawned {
                if let Some(stdout) = child.stdout.take() {
                    let mut lines = BufReader::new(stdout).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        if line.trim().is_empty() {
                            continue;
                        }
                        let entry = parse_live_log_line(&line, source_name);
                        if tx.send(entry).await.is_err() {
                            break;
                        }
                    }
                }
                let _ = child.kill().await;
            } else {
                // Keep channel alive if no external log source binary is available
                std::future::pending::<()>().await;
            }
        });

        let mut filter = WsLogFilter::default();
        let mut ping_interval = tokio::time::interval(Duration::from_secs(54));
        ping_interval.tick().await;

        loop {
            tokio::select! {
                msg_opt = socket.recv() => {
                    match msg_opt {
                        Some(Ok(Message::Text(text))) => {
                            if let Ok(new_filter) = serde_json::from_str::<WsLogFilter>(&text) {
                                filter = new_filter;
                            }
                        }
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                            break;
                        }
                        _ => {}
                    }
                }
                Some(entry) = rx.recv() => {
                    if current_ws_authorization(&mut authorization).await != Some(true) {
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                    if !log_entry_matches_filter(&entry, &filter) {
                        continue;
                    }
                    let payload = serde_json::json!({
                        "type": "LOG_ENTRY",
                        "data": entry,
                    });
                    if let Ok(txt) = serde_json::to_string(&payload) {
                        if socket.send(Message::Text(txt)).await.is_err() {
                            break;
                        }
                    }
                }
                _ = ping_interval.tick() => {
                    if current_ws_authorization(&mut authorization).await != Some(true) {
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                    if socket.send(Message::Ping(Vec::new())).await.is_err() {
                        break;
                    }
                }
            }
        }

        reader_task.abort();
        let _ = reader_task.await;
    })
}

pub fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(xff) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        // The rightmost entry is the one appended by our trusted reverse proxy; entries to its
        // left are client-controlled and must never be used for rate limiting or session binding.
        if let Some(last) = xff
            .rsplit(',')
            .map(|hop| hop.trim().trim_matches(['[', ']']))
            .find(|hop| hop.parse::<std::net::IpAddr>().is_ok())
        {
            return last.to_string();
        }
    }
    if let Some(real_ip) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "127.0.0.1".to_string()
}

pub fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    for val in headers.get_all(axum::http::header::COOKIE) {
        if let Ok(raw) = val.to_str() {
            for part in raw.split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    if k.trim() == cookie_name {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

pub fn build_set_cookie(
    name: &str,
    value: &str,
    max_age: i64,
    same_site: &str,
    secure: bool,
    http_only: bool,
) -> String {
    let mut parts = vec![
        format!("{}={}", name, value),
        "Path=/".to_string(),
        format!("Max-Age={}", max_age),
        format!("SameSite={}", same_site),
    ];
    if secure {
        parts.push("Secure".to_string());
    }
    if http_only {
        parts.push("HttpOnly".to_string());
    }
    parts.join("; ")
}

#[cfg(all(test, target_os = "linux"))]
#[path = "log_authorization_regressions.rs"]
mod log_authorization_regressions;
