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

#[derive(Clone, Copy, Debug, Default)]
pub struct PeerIp(pub Option<std::net::IpAddr>);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for PeerIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|axum::extract::ConnectInfo(addr)| addr.ip());
        Ok(Self(ip))
    }
}

#[derive(Clone, Debug)]
struct WsTicketEntry {
    user_id: i64,
    session_jti: String,
    session_ver: Option<i64>,
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
                    "job_id"
                        | "package_id"
                        | "action"
                        | "status"
                        | "started_at"
                        | "finished_at"
                        | "expected_target_version"
                        | "achieved_version"
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
    tokio::spawn(
        telemetry.services_loop(|| Ok(serde_json::to_value(af_services::get_active_services()?)?)),
    );
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
                    let repeated =
                        super::websocket_message_for_session(projected, privileged).unwrap();
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

pub fn issue_ws_ticket_for_session(user_id: i64, session_jti: &str, client_ip: &str) -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let ticket = hex::encode(b);

    let effective_jti = if session_jti.trim().is_empty() {
        let mut anon = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut anon);
        format!("ws-anon-{}", hex::encode(anon))
    } else {
        session_jti.trim().to_string()
    };

    let initial_ver = af_db::get_read_conn()
        .ok()
        .and_then(|c| crate::auth::load_active_human_subject(&c, user_id).ok())
        .map(|s| s.sessions_revoked_after);

    if let Ok(mut map) = WS_TICKETS.lock() {
        map.retain(|_, v| v.expires_at > Instant::now());
        map.insert(
            ticket.clone(),
            WsTicketEntry {
                user_id,
                session_jti: effective_jti,
                session_ver: initial_ver,
                client_ip: client_ip.to_string(),
                expires_at: Instant::now() + Duration::from_secs(30),
                diagnostics_allowed: false,
            },
        );
    }
    ticket
}

pub fn issue_ws_ticket_for_user(user_id: i64, client_ip: &str) -> String {
    issue_ws_ticket_for_session(user_id, "", client_ip)
}

fn is_loopback_ip(ip: &str) -> bool {
    matches!(ip, "127.0.0.1" | "::1" | "localhost" | "")
}

#[derive(Deserialize)]
pub struct WsTicketQuery {
    #[serde(default)]
    pub ticket: String,
}

fn check_ws_jti_revocation(connection: &rusqlite::Connection, entry: &mut WsTicketEntry) -> bool {
    if entry.session_jti.is_empty() {
        return false;
    }
    if entry.session_jti.starts_with("ws-anon-")
        && !crate::auth::table_exists(connection, "revoked_tokens").unwrap_or(false)
    {
        return true;
    }
    !crate::auth::is_session_token_revoked_beyond_grace_with_conn(
        connection,
        &entry.session_jti,
        entry.user_id,
    )
}

fn consume_live_ws_ticket(
    connection: &rusqlite::Connection,
    ticket: &str,
) -> Option<WsTicketEntry> {
    let mut entry = WS_TICKETS.lock().ok().and_then(|mut map| {
        map.retain(|_, value| value.expires_at > Instant::now());
        map.remove(ticket)
    })?;
    if !check_ws_jti_revocation(connection, &mut entry) {
        return None;
    }
    let subj = crate::auth::load_active_human_subject(connection, entry.user_id).ok()?;
    if let Some(issued_ver) = entry.session_ver {
        if subj.sessions_revoked_after > issued_ver {
            return None;
        }
    } else {
        entry.session_ver = Some(subj.sessions_revoked_after);
    }
    entry.diagnostics_allowed = subj.role == "admin";
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
        assert!(
            !admin.contains("private-installer-output"),
            "raw secrets must be redacted for admin"
        );
        assert!(
            admin.contains("[REDACTED]"),
            "sanitized secrets must be marked REDACTED"
        );
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

    #[test]
    fn websocket_jti_revocation_does_not_rebind_after_grace_expires() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL DEFAULT 'admin', role TEXT NOT NULL, sessions_revoked_after INTEGER NOT NULL DEFAULT 0);
                 CREATE TABLE revoked_tokens (jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
                 INSERT INTO users VALUES (1, 'admin', 'admin', 0);
                 INSERT INTO revoked_tokens VALUES ('jti-rotated-old', datetime('now', '+1 hour'));",
            )
            .unwrap();
        let mut entry = super::WsTicketEntry {
            user_id: 1,
            client_ip: "127.0.0.1".to_string(),
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(30),
            diagnostics_allowed: true,
            session_jti: "jti-rotated-old".to_string(),
            session_ver: Some(0),
        };
        assert_eq!(
            super::refresh_ws_authorization(&connection, &mut entry),
            None
        );
    }
}

pub async fn handle_websocket(
    Query(q): Query<WsTicketQuery>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !websocket_origin_matches_host(&headers, peer_ip, false) {
        return crate::auth::api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Cross-origin WebSocket upgrade rejected",
        );
    }
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
    })
    .await
    .ok()
    .flatten();

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

    let client_ip = extract_client_ip_for_peer(&headers, peer_ip);
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

    ws.max_message_size(64 * 1024)
        .max_frame_size(16 * 1024)
        .on_upgrade(move |socket| handle_ws_socket(socket, entry))
}

// A ticket authorizes the upgrade only. Existing sockets must not keep a stale
// administrative capability after the account is demoted, removed, or logged out.
fn refresh_ws_authorization(
    connection: &rusqlite::Connection,
    entry: &mut WsTicketEntry,
) -> Option<bool> {
    if !check_ws_jti_revocation(connection, entry) {
        return None;
    }
    let subj = crate::auth::load_active_human_subject(connection, entry.user_id).ok()?;
    if let Some(issued_ver) = entry.session_ver {
        if subj.sessions_revoked_after > issued_ver {
            return None;
        }
    } else {
        entry.session_ver = Some(subj.sessions_revoked_after);
    }
    entry.diagnostics_allowed &= subj.role == "admin";
    Some(entry.diagnostics_allowed)
}

async fn current_ws_authorization(entry: &mut WsTicketEntry) -> Option<bool> {
    let mut checked = entry.clone();
    let (allowed, updated_jti, updated_ver) = tokio::task::spawn_blocking(move || {
        let connection = af_db::get_read_conn().ok()?;
        let allowed = refresh_ws_authorization(&connection, &mut checked)?;
        Some((allowed, checked.session_jti, checked.session_ver))
    })
    .await
    .ok()??;
    entry.diagnostics_allowed = allowed;
    entry.session_jti = updated_jti;
    entry.session_ver = updated_ver;
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
        let mut auth_interval = tokio::time::interval(Duration::from_secs(5));
        auth_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        auth_interval.tick().await;
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
                _ = auth_interval.tick() => {
                    if current_ws_authorization(&mut entry).await.is_none() {
                        let _ = sender.send(Message::Close(None)).await;
                        break;
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
        (
            chrono::Utc::now().to_rfc3339(),
            "localhost".to_string(),
            trimmed,
        )
    };

    let (unit, message) = if let Some((prefix, msg)) = remainder.split_once(": ") {
        let clean_unit = prefix.split('[').next().unwrap_or(prefix).trim();
        (clean_unit.to_string(), msg.to_string())
    } else {
        ("system".to_string(), remainder.to_string())
    };

    let lower = message.to_lowercase();
    let priority = if lower.contains("error") || lower.contains("fatal") || lower.contains("failed")
    {
        "err"
    } else if lower.contains("warn") {
        "warning"
    } else {
        "info"
    };

    let safe_message = af_services::redact_secrets(&message);
    serde_json::json!({
        "timestamp": timestamp,
        "source": default_source,
        "unit": unit,
        "priority": priority,
        "message": safe_message,
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

fn is_valid_ws_host_authority(raw_host: &str) -> bool {
    let trimmed = raw_host.trim();
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed.bytes().any(|b| b <= 0x20 || b >= 0x7f)
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('@')
    {
        return false;
    }
    if trimmed.starts_with('[') {
        let Some((ipv6, rest)) = trimmed.strip_prefix('[').and_then(|s| s.split_once(']')) else {
            return false;
        };
        if ipv6.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        return rest.is_empty()
            || rest
                .strip_prefix(':')
                .is_some_and(|p| p.parse::<u16>().is_ok());
    }
    let (host, port) = trimmed
        .split_once(':')
        .map_or((trimmed, None), |(h, p)| (h, Some(p)));
    if let Some(p) = port {
        if p.parse::<u16>().is_err() {
            return false;
        }
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn websocket_origin_matches_host(
    headers: &HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
    cookie_authenticated: bool,
) -> bool {
    let Some(origin_hv) = headers.get(axum::http::header::ORIGIN) else {
        // Non-browser Bearer/ticket clients do not send Origin; browser cookie upgrades must.
        return !cookie_authenticated;
    };
    let Ok(origin_raw) = origin_hv.to_str() else {
        return false;
    };
    let Ok(origin_url) = url::Url::parse(origin_raw.trim()) else {
        return false;
    };
    if !origin_url.username().is_empty()
        || origin_url.password().is_some()
        || origin_url.query().is_some()
        || origin_url.fragment().is_some()
        || origin_url.path() != "/"
    {
        return false;
    }
    let origin_scheme = match origin_url.scheme() {
        "http" | "ws" => "http",
        "https" | "wss" => "https",
        _ => return false,
    };
    let Some(origin_host) = origin_url
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
    else {
        return false;
    };
    let Some(origin_port) = origin_url.port_or_known_default() else {
        return false;
    };

    let trust_forwarded = peer_ip.is_none_or(is_trusted_proxy_peer);
    let expected_scheme = if trust_forwarded {
        if let Some(proto) = headers
            .get("X-Forwarded-Proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            if proto.eq_ignore_ascii_case("https") {
                "https"
            } else if proto.eq_ignore_ascii_case("http") {
                "http"
            } else {
                return false;
            }
        } else if headers
            .get("X-Forwarded-Port")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .is_some_and(|p| p.trim() == "443")
        {
            "https"
        } else {
            "http"
        }
    } else {
        "http"
    };

    let forwarded_host = if trust_forwarded {
        headers
            .get("X-Forwarded-Host")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
    } else {
        None
    };
    let Some(raw_request_host) = forwarded_host.or_else(|| {
        headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
    }) else {
        return false;
    };
    if !is_valid_ws_host_authority(raw_request_host) {
        return false;
    }
    let Ok(mut expected_url) = url::Url::parse(&format!("{expected_scheme}://{raw_request_host}"))
    else {
        return false;
    };
    if trust_forwarded && expected_url.port().is_none() {
        if let Some(xf_port) = headers
            .get("X-Forwarded-Port")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|p| p.trim().parse::<u16>().ok())
            .filter(|p| *p > 0)
        {
            if expected_url.set_port(Some(xf_port)).is_err() {
                return false;
            }
        }
    }
    let Some(expected_host) = expected_url
        .host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
    else {
        return false;
    };
    let Some(expected_port) = expected_url.port_or_known_default() else {
        return false;
    };

    if origin_scheme == expected_scheme
        && origin_host == expected_host
        && origin_port == expected_port
    {
        return true;
    }

    if let Ok(allowed_cors) = std::env::var("ALLOWED_CORS_ORIGIN") {
        for candidate in allowed_cors
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != "*")
        {
            if let Ok(allowed_url) = url::Url::parse(candidate) {
                let allowed_scheme = allowed_url.scheme();
                let allowed_host = allowed_url
                    .host_str()
                    .map(|h| h.trim_end_matches('.').to_ascii_lowercase());
                let allowed_port = allowed_url.port_or_known_default();
                if allowed_scheme == origin_scheme
                    && allowed_host.as_deref() == Some(origin_host.as_str())
                    && allowed_port == Some(origin_port)
                {
                    return true;
                }
            }
        }
    }

    false
}

pub async fn handle_log_websocket(
    axum::Extension(user): axum::Extension<crate::auth::AuthUser>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !package_diagnostics_allowed(&user) {
        return crate::auth::api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    let cookie_authenticated = headers.contains_key(axum::http::header::COOKIE)
        && !headers.contains_key(axum::http::header::AUTHORIZATION);
    if !websocket_origin_matches_host(&headers, peer_ip, cookie_authenticated) {
        return crate::auth::api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Cross-origin WebSocket upgrade rejected",
        );
    }
    let effective_jti = if user.jti.trim().is_empty() {
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        format!("ws-anon-{}", hex::encode(nonce))
    } else {
        user.jti.clone()
    };
    let mut authorization = WsTicketEntry {
        user_id: user.user_id,
        session_jti: effective_jti,
        session_ver: None,
        client_ip: extract_client_ip_for_peer(&headers, peer_ip),
        expires_at: Instant::now(),
        diagnostics_allowed: true,
    };
    ws.max_message_size(64 * 1024)
        .max_frame_size(16 * 1024)
        .on_upgrade(move |mut socket| async move {
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
                    let fallback_files = [
                        ("/var/log/aetherflow/deploy.log", "deploy"),
                        ("/var/log/aetherflow-deploy.log", "deploy"),
                        ("/var/log/syslog", "syslog"),
                        ("/var/log/messages", "syslog"),
                    ];
                    let mut opened_fallback: Option<(std::fs::File, &'static str)> = None;
                    for (path_str, source_name) in fallback_files {
                        if let Some(file) =
                            open_confined_live_log_file(std::path::Path::new(path_str))
                        {
                            opened_fallback = Some((file, source_name));
                            break;
                        }
                    }
                    if let Some((std_file, source_name)) = opened_fallback {
                        tail_open_log_file_to_channel(std_file, source_name, &tx).await;
                    } else {
                        // Keep channel alive if no external log source binary or confined log file is available
                        std::future::pending::<()>().await;
                    }
                }
            });

            let mut filter = WsLogFilter::default();
            let mut ping_interval = tokio::time::interval(Duration::from_secs(54));
            ping_interval.tick().await;
            let mut auth_interval = tokio::time::interval(Duration::from_secs(5));
            auth_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            auth_interval.tick().await;

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
                    _ = auth_interval.tick() => {
                        if current_ws_authorization(&mut authorization).await != Some(true) {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
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

fn open_confined_live_log_file(path: &std::path::Path) -> Option<std::fs::File> {
    let mut current = std::path::PathBuf::new();
    for component in path.parent()?.components() {
        current.push(component);
        let meta = std::fs::symlink_metadata(&current).ok()?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return None;
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return None;
        }
        unsafe {
            let flags = libc::fcntl(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::F_GETFL);
            if flags >= 0 {
                let _ = libc::fcntl(
                    std::os::unix::io::AsRawFd::as_raw_fd(&file),
                    libc::F_SETFL,
                    flags & !libc::O_NONBLOCK,
                );
            }
        }
    }
    Some(file)
}

async fn tail_open_log_file_to_channel(
    std_file: std::fs::File,
    source_name: &'static str,
    tx: &tokio::sync::mpsc::Sender<serde_json::Value>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};
    let mut file = tokio::fs::File::from_std(std_file);
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let start_offset = len.saturating_sub(64 * 1024);
    let _ = file.seek(std::io::SeekFrom::Start(start_offset)).await;
    let mut initial_buf = Vec::new();
    let _ = file.read_to_end(&mut initial_buf).await;
    let mut pos = start_offset + initial_buf.len() as u64;
    let initial_text = String::from_utf8_lossy(&initial_buf);
    let mut initial_lines: Vec<&str> = initial_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    if start_offset > 0 && !initial_lines.is_empty() {
        initial_lines.remove(0);
    }
    let skip = initial_lines.len().saturating_sub(50);
    for line in initial_lines.into_iter().skip(skip) {
        if tx
            .send(parse_live_log_line(line, source_name))
            .await
            .is_err()
        {
            return;
        }
    }
    let mut reader = BufReader::new(file);
    let mut line_buf = String::new();
    let mut poll = tokio::time::interval(Duration::from_millis(250));
    poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tx.closed() => break,
            _ = poll.tick() => {
                if let Ok(meta) = reader.get_ref().metadata().await {
                    if meta.len() < pos {
                        let _ = reader.seek(std::io::SeekFrom::Start(0)).await;
                        pos = 0;
                    }
                }
                loop {
                    line_buf.clear();
                    match reader.read_line(&mut line_buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            pos = pos.saturating_add(n as u64);
                            let trimmed = line_buf.trim_end_matches(['\r', '\n']);
                            if !trimmed.trim().is_empty()
                                && tx.send(parse_live_log_line(trimmed, source_name)).await.is_err()
                            {
                                return;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }
}

fn ip_matches_cidr_or_host(ip: std::net::IpAddr, raw_entry: &str) -> bool {
    let trimmed = raw_entry.trim();
    if trimmed.is_empty() {
        return false;
    }
    if let Some((net_part, mask_part)) = trimmed.split_once('/') {
        let Ok(prefix_len) = mask_part.trim().parse::<u32>() else {
            return false;
        };
        let Ok(net_ip) = net_part
            .trim()
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
        else {
            return false;
        };
        match (ip, net_ip) {
            (std::net::IpAddr::V4(v4), std::net::IpAddr::V4(net_v4)) if prefix_len <= 32 => {
                if prefix_len == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - prefix_len);
                (u32::from(v4) & mask) == (u32::from(net_v4) & mask)
            }
            (std::net::IpAddr::V6(v6), std::net::IpAddr::V6(net_v6)) if prefix_len <= 128 => {
                if prefix_len == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - prefix_len);
                (u128::from(v6) & mask) == (u128::from(net_v6) & mask)
            }
            _ => false,
        }
    } else if let Ok(exact_ip) = trimmed.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        ip == exact_ip
    } else {
        false
    }
}

fn is_private_or_link_local(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub fn is_trusted_proxy_peer(ip: std::net::IpAddr) -> bool {
    if let Ok(raw) = std::env::var("TRUSTED_PROXIES") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return trimmed
                .split(',')
                .any(|entry| ip_matches_cidr_or_host(ip, entry));
        }
    }
    if let Ok(flag) = std::env::var("TRUST_PROXY_HEADERS") {
        let f = flag.trim();
        if f.eq_ignore_ascii_case("false") || f == "0" {
            return false;
        }
        if f.eq_ignore_ascii_case("true") || f == "1" {
            return ip.is_loopback() || is_private_or_link_local(&ip);
        }
    }
    ip.is_loopback()
}

fn is_trusted_proxy_hop(ip: &std::net::IpAddr) -> bool {
    if let Ok(raw) = std::env::var("TRUSTED_PROXIES") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return trimmed
                .split(',')
                .any(|entry| ip_matches_cidr_or_host(*ip, entry));
        }
    }
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let trust_private = std::env::var("TRUST_PROXY_HEADERS")
        .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
        .unwrap_or(false);
    if !trust_private {
        return false;
    }
    is_private_or_link_local(ip)
}

fn extract_forwarded_ip_from_trusted_headers(headers: &HeaderMap) -> Option<std::net::IpAddr> {
    if let Some(xff) = headers.get("X-Forwarded-For").and_then(|v| v.to_str().ok()) {
        // Walk right-to-left: skip trailing trusted proxy hops added locally, then pick the
        // rightmost untrusted client hop rather than any client-spoofable leftmost value.
        let mut rightmost_valid: Option<std::net::IpAddr> = None;
        for hop in xff.rsplit(',') {
            let trimmed = hop.trim().trim_matches(['[', ']']);
            let Ok(ip) = trimmed.parse::<std::net::IpAddr>() else {
                continue;
            };
            if rightmost_valid.is_none() {
                rightmost_valid = Some(ip);
            }
            if !is_trusted_proxy_hop(&ip) {
                return Some(ip);
            }
        }
        if let Some(fallback_ip) = rightmost_valid {
            return Some(fallback_ip);
        }
    }
    if let Some(real_ip) = headers.get("X-Real-IP").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim().trim_matches(['[', ']']);
        if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
            return Some(ip);
        }
    }
    None
}

pub fn extract_client_ip(headers: &HeaderMap) -> String {
    extract_forwarded_ip_from_trusted_headers(headers)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

pub fn extract_client_ip_for_peer(
    headers: &HeaderMap,
    peer_ip: Option<std::net::IpAddr>,
) -> String {
    let Some(peer) = peer_ip else {
        return extract_client_ip(headers);
    };
    if !is_trusted_proxy_peer(peer) {
        return peer.to_string();
    }
    extract_forwarded_ip_from_trusted_headers(headers)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| peer.to_string())
}

pub fn normalize_request_forwarding_for_peer(req: &mut axum::extract::Request) {
    let Some(peer) = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|axum::extract::ConnectInfo(addr)| addr.ip())
    else {
        return;
    };
    let trusted = is_trusted_proxy_peer(peer);
    let headers = req.headers_mut();
    if !trusted {
        for name in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-forwarded-server",
            "x-real-ip",
        ] {
            headers.remove(name);
        }
        if let Ok(hv) = axum::http::HeaderValue::from_str(&peer.to_string()) {
            headers.insert(axum::http::header::HeaderName::from_static("x-real-ip"), hv);
        }
    } else if extract_forwarded_ip_from_trusted_headers(headers).is_none() {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&peer.to_string()) {
            headers.insert(axum::http::header::HeaderName::from_static("x-real-ip"), hv);
        }
    }
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

#[cfg(test)]
mod client_ip_tests {
    use super::extract_client_ip;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn extract_client_ip_skips_trailing_trusted_proxies_and_validates_real_ip() {
        let mut h1 = HeaderMap::new();
        h1.insert(
            "X-Forwarded-For",
            HeaderValue::from_static("10.0.0.1, 203.0.113.42, 127.0.0.1"),
        );
        assert_eq!(extract_client_ip(&h1), "203.0.113.42");

        let mut h2 = HeaderMap::new();
        h2.insert(
            "X-Forwarded-For",
            HeaderValue::from_static("198.51.100.1, 203.0.113.9"),
        );
        assert_eq!(extract_client_ip(&h2), "203.0.113.9");

        let mut h3 = HeaderMap::new();
        h3.insert("X-Real-IP", HeaderValue::from_static("not-an-ip"));
        assert_eq!(extract_client_ip(&h3), "127.0.0.1");

        let mut h4 = HeaderMap::new();
        h4.insert("X-Real-IP", HeaderValue::from_static("[2001:db8::5]"));
        assert_eq!(extract_client_ip(&h4), "2001:db8::5");
    }

    #[test]
    fn websocket_origin_enforces_scheme_host_port_and_cookie_origin_presence() {
        use super::websocket_origin_matches_host;
        use axum::http::header;

        // Cookie-authenticated browser upgrade without Origin must be rejected; non-cookie allowed.
        let mut h_no_origin = HeaderMap::new();
        h_no_origin.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8080"));
        assert!(websocket_origin_matches_host(&h_no_origin, None, false));
        assert!(!websocket_origin_matches_host(&h_no_origin, None, true));

        // Exact http match and port/scheme mismatch rejection.
        let mut h_http = h_no_origin.clone();
        h_http.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:8080"),
        );
        assert!(websocket_origin_matches_host(&h_http, None, true));
        h_http.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://127.0.0.1:8080"),
        );
        assert!(!websocket_origin_matches_host(&h_http, None, true));
        h_http.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:9999"),
        );
        assert!(!websocket_origin_matches_host(&h_http, None, true));
        h_http.insert(header::ORIGIN, HeaderValue::from_static("null"));
        assert!(!websocket_origin_matches_host(&h_http, None, true));

        // Trusted loopback reverse proxy with X-Forwarded-Proto=https vs untrusted public peer spoofing X-Forwarded-Host.
        let mut h_tls = HeaderMap::new();
        h_tls.insert(header::HOST, HeaderValue::from_static("mcflow.stream"));
        h_tls.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://mcflow.stream"),
        );
        h_tls.insert("X-Forwarded-Proto", HeaderValue::from_static("https"));
        h_tls.insert("X-Forwarded-Port", HeaderValue::from_static("443"));
        assert!(websocket_origin_matches_host(
            &h_tls,
            Some("127.0.0.1".parse().unwrap()),
            true
        ));

        let mut h_spoof = HeaderMap::new();
        h_spoof.insert(header::HOST, HeaderValue::from_static("mcflow.stream"));
        h_spoof.insert(
            "X-Forwarded-Host",
            HeaderValue::from_static("evil.attacker.test"),
        );
        h_spoof.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://evil.attacker.test"),
        );
        assert!(!websocket_origin_matches_host(
            &h_spoof,
            Some("203.0.113.99".parse().unwrap()),
            true
        ));
    }

    #[test]
    fn open_confined_live_log_file_rejects_symlinks_and_hardlinks() {
        let dir = std::env::temp_dir().join(format!("af-ws-log-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let real_log = dir.join("syslog.log");
        std::fs::write(&real_log, b"line1\n").unwrap();
        assert!(super::open_confined_live_log_file(&real_log).is_some());

        let sym_log = dir.join("sym.log");
        std::os::unix::fs::symlink(&real_log, &sym_log).unwrap();
        assert!(
            super::open_confined_live_log_file(&sym_log).is_none(),
            "symlinked log file must be rejected by O_NOFOLLOW"
        );

        let hard_log = dir.join("hard.log");
        std::fs::hard_link(&real_log, &hard_log).unwrap();
        assert!(
            super::open_confined_live_log_file(&hard_log).is_none(),
            "hardlinked log file (nlink > 1) must be rejected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
