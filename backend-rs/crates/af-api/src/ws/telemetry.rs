use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, oneshot, watch, Notify};
use tokio::time::MissedTickBehavior;

const METRICS_INTERVAL: Duration = Duration::from_secs(1);
const SERVICES_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Default)]
pub(super) struct ServiceCache {
    pub(super) value: Option<serde_json::Value>,
    pub(super) in_flight: bool,
    pub(super) last_finished: Option<Instant>,
}

pub(super) struct Telemetry {
    pub(super) broadcast: broadcast::Sender<String>,
    pub(super) metrics: watch::Sender<Option<serde_json::Value>>,
    pub(super) services: Mutex<ServiceCache>,
    pub(super) service_refresh: Notify,
}

impl Telemetry {
    pub(super) fn new() -> Self {
        let (broadcast, _) = broadcast::channel(256);
        let (metrics, _) = watch::channel(None);
        Self {
            broadcast,
            metrics,
            services: Mutex::new(ServiceCache::default()),
            service_refresh: Notify::new(),
        }
    }

    pub(super) fn metrics_message(&self, metrics: serde_json::Value) -> serde_json::Value {
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

    pub(super) fn broadcast_message(&self, payload: &serde_json::Value) {
        if let Ok(text) = serde_json::to_string(payload) {
            let _ = self.broadcast.send(text);
        }
    }

    pub(super) fn needs_metrics(&self) -> bool {
        self.broadcast.receiver_count() > 0 || self.metrics.borrow().is_none()
    }

    pub(super) async fn collect_metrics<F>(&self, collector: F)
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

    pub(super) async fn metrics_loop<F>(self: Arc<Self>, collector: F)
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

    pub(super) fn try_start_service_refresh<F>(
        self: &Arc<Self>,
        collector: F,
    ) -> Option<oneshot::Receiver<()>>
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

    pub(super) async fn services_loop<F>(self: Arc<Self>, collector: F)
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

    pub(super) fn cached_snapshot(&self) -> Option<serde_json::Value> {
        self.metrics
            .borrow()
            .clone()
            .map(|cached| self.metrics_message(cached))
    }

    pub(super) fn subscribe_metrics(&self) -> watch::Receiver<Option<serde_json::Value>> {
        self.metrics.subscribe()
    }

    #[cfg(test)]
    pub(super) async fn initial_snapshot(&self) -> serde_json::Value {
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

pub(super) static TELEMETRY: Lazy<Arc<Telemetry>> = Lazy::new(|| Arc::new(Telemetry::new()));

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
                    | "launch_url"
                    | "launch_scope"
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

pub(super) fn websocket_message_for_session(
    message: String,
    diagnostics_allowed: bool,
) -> Option<String> {
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

/// Filters and sanitizes telemetry broadcast frames according to a verified peer grant's
/// `AccessMap` so peers without `services: read` or `marketplace: read` do not receive
/// unauthorized service inventory or package job progress frames.
pub(super) fn websocket_message_for_peer_session(
    message: String,
    access: &af_db::peers::AccessMap,
) -> Option<String> {
    if !access.has_any_access() {
        return None;
    }
    let mut payload: serde_json::Value = serde_json::from_str(&message).ok()?;
    match payload.get("type").and_then(serde_json::Value::as_str) {
        Some("package:progress") => {
            if !access.marketplace.allows_read() {
                return None;
            }
            sanitize_diagnostic_text_fields(&mut payload);
            serde_json::to_string(&payload).ok()
        }
        Some("METRICS_UPDATE") => {
            if let Some(services) = payload
                .get_mut("data")
                .and_then(|data| data.get_mut("services"))
            {
                if !access.services.allows_read() {
                    *services = serde_json::Value::Null;
                } else if !access.marketplace.allows_read() {
                    sanitize_services_for_viewer(services);
                }
            }
            sanitize_diagnostic_text_fields(&mut payload);
            serde_json::to_string(&payload).ok()
        }
        _ => websocket_message_for_session(
            message,
            access.services.allows_read() && access.marketplace.allows_read(),
        ),
    }
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
