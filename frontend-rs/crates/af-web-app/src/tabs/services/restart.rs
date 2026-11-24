//! Persisted core restart receipt tracking, job polling, and API/database readiness verification.
use crate::tabs::l10n::{tt, tt_with};
use af_web_core::api::{storage_get, storage_set, ApiClient};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use wasm_bindgen_futures::spawn_local;

pub(super) const CORE_RESTART_STORAGE_KEY: &str = "af-core-restart-receipts";
pub(super) const CORE_RESTART_TIMEOUT_MS: f64 = 180_000.0;
pub(super) const CORE_RESTART_POLL_MS: u32 = 1_500;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CoreRestartPhase {
    #[default]
    WaitingForJob,
    WaitingForReadiness,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct CoreRestartReceipt {
    pub key: String,
    pub target: String,
    pub label: String,
    pub job_unit: String,
    pub started_at_ms: f64,
    pub deadline_ms: f64,
    #[serde(default)]
    pub phase: CoreRestartPhase,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RestartJobOutcome {
    Pending,
    JobSucceeded,
    JobFailed(String),
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct ServiceControlReceipt {
    status: String,
    job_unit: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct CoreRestartStatusResponse {
    state: String,
    #[serde(rename = "operationId")]
    operation_id: Option<String>,
    job_unit: String,
    status: String,
    completed: bool,
    success: bool,
    error: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct ApiReadyResponse {
    service: String,
    status: String,
    database: String,
}

pub(super) fn is_valid_restart_unit(unit: &str) -> bool {
    let trimmed = unit.trim();
    trimmed.starts_with("aetherflow-self-update-restart-")
        && af_models::is_valid_self_update_job_unit_name(trimmed)
}

pub(super) fn validate_restart_receipt(receipt: &Value) -> Result<String, &'static str> {
    let parsed: ServiceControlReceipt = serde_json::from_value(receipt.clone()).unwrap_or_default();
    let unit = parsed.job_unit.as_deref().map(str::trim).unwrap_or("");
    if is_valid_restart_unit(unit) {
        Ok(unit.to_string())
    } else {
        Err("Restart was accepted without a valid receipt identity. Check service logs before retrying.")
    }
}

pub(super) fn evaluate_restart_status(expected_unit: &str, status: &Value) -> RestartJobOutcome {
    let Ok(parsed) = serde_json::from_value::<CoreRestartStatusResponse>(status.clone()) else {
        return RestartJobOutcome::Pending;
    };
    let observed_unit = if !parsed.job_unit.is_empty() {
        parsed.job_unit.as_str()
    } else {
        parsed.operation_id.as_deref().unwrap_or("")
    };
    if observed_unit != expected_unit {
        return RestartJobOutcome::Pending;
    }

    if (parsed.completed && !parsed.success)
        || parsed.status == "failed"
        || matches!(parsed.state.as_str(), "failed" | "interrupted")
    {
        let detail = parsed.error.trim();
        let message = if detail.is_empty() {
            "Check service logs."
        } else {
            detail
        };
        return RestartJobOutcome::JobFailed(message.to_string());
    }

    if parsed.completed
        && parsed.success
        && (parsed.status == "succeeded" || parsed.state == "complete")
    {
        return RestartJobOutcome::JobSucceeded;
    }

    RestartJobOutcome::Pending
}

pub(super) fn is_api_database_ready(readiness: &Value) -> bool {
    let Ok(parsed) = serde_json::from_value::<ApiReadyResponse>(readiness.clone()) else {
        return false;
    };
    parsed.service == "aetherflow-api" && parsed.status == "ready" && parsed.database == "ok"
}

pub(super) fn is_fatal_receipt_status_error(status: u16) -> bool {
    status == 400
}

pub(super) fn load_persisted_receipts(raw: Option<&str>) -> BTreeMap<String, CoreRestartReceipt> {
    let Some(raw) = raw.map(str::trim).filter(|text| !text.is_empty()) else {
        return BTreeMap::new();
    };
    let Ok(parsed) = serde_json::from_str::<BTreeMap<String, CoreRestartReceipt>>(raw) else {
        return BTreeMap::new();
    };
    parsed
        .into_iter()
        .filter(|(key, receipt)| {
            !key.trim().is_empty()
                && receipt.key == *key
                && is_valid_restart_unit(&receipt.job_unit)
                && receipt.deadline_ms.is_finite()
        })
        .collect()
}

pub(super) fn serialize_persisted_receipts(
    receipts: &BTreeMap<String, CoreRestartReceipt>,
) -> String {
    if receipts.is_empty() {
        String::new()
    } else {
        serde_json::to_string(receipts).unwrap_or_default()
    }
}

pub(super) fn restart_storage_key(server_id: Option<&str>) -> String {
    match server_id.map(str::trim).filter(|id| !id.is_empty()) {
        Some(id) => format!("{CORE_RESTART_STORAGE_KEY}:peer:{id}"),
        None => CORE_RESTART_STORAGE_KEY.to_string(),
    }
}

pub(super) fn persist_receipts_for_server(
    server_id: Option<&str>,
    receipts: &BTreeMap<String, CoreRestartReceipt>,
) {
    storage_set(
        &restart_storage_key(server_id),
        &serialize_persisted_receipts(receipts),
    );
}

pub(super) fn restore_persisted_receipts_for_server(
    server_id: Option<&str>,
) -> BTreeMap<String, CoreRestartReceipt> {
    load_persisted_receipts(storage_get(&restart_storage_key(server_id)).as_deref())
}

#[allow(dead_code)]
pub(super) fn persist_receipts(receipts: &BTreeMap<String, CoreRestartReceipt>) {
    persist_receipts_for_server(None, receipts);
}

#[allow(dead_code)]
pub(super) fn restore_persisted_receipts() -> BTreeMap<String, CoreRestartReceipt> {
    restore_persisted_receipts_for_server(None)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CoreRestartNotice {
    pub message: String,
    pub is_error: bool,
}

#[derive(Clone, Copy)]
pub(super) struct CoreRestartTracker {
    pub receipts: RwSignal<BTreeMap<String, CoreRestartReceipt>>,
    pub notice: RwSignal<Option<CoreRestartNotice>>,
}

impl CoreRestartTracker {
    pub fn start_polling(context: crate::state::AppContext, refresh: Callback<()>) -> Self {
        let receipts = RwSignal::new(BTreeMap::new());
        let restored_for = RwSignal::new(None::<(u64, Option<String>, u64)>);
        let notice = RwSignal::new(None::<CoreRestartNotice>);
        let in_flight = RwSignal::new(false);
        let interval = StoredValue::new_local(None::<gloo_timers::callback::Interval>);

        Effect::new(move |_| {
            let loading = context.auth_loading.get();
            let admin = context.is_admin();
            let can_read_services = context.can_read_area(crate::state::PeerArea::Services);
            let services_grant = context.area_revocation_epoch(crate::state::PeerArea::Services);
            let server_epoch = context.server_epoch.get();
            let server_id = context.active_server_id.get();
            if loading || !admin || !can_read_services {
                interval.set_value(None);
                restored_for.set(None);
                receipts.set(BTreeMap::new());
                notice.set(None);
                return;
            }
            let target_key = (server_epoch, server_id.clone(), services_grant);
            if restored_for.get_untracked().as_ref() != Some(&target_key) {
                interval.set_value(None);
                restored_for.set(Some(target_key));
                notice.set(None);
                let saved = restore_persisted_receipts_for_server(server_id.as_deref());
                receipts.set(saved);
            }
            let current = receipts.get();
            persist_receipts_for_server(server_id.as_deref(), &current);
            if current.is_empty() {
                interval.set_value(None);
                return;
            }
            if interval.with_value(Option::is_some) {
                return;
            }
            interval.set_value(Some(gloo_timers::callback::Interval::new(
                CORE_RESTART_POLL_MS,
                move || {
                    if !context.is_admin_untracked()
                        || !context.can_read_area_untracked(crate::state::PeerArea::Services)
                        || in_flight.get_untracked()
                        || receipts.with_untracked(BTreeMap::is_empty)
                    {
                        return;
                    }
                    let snapshot = receipts.get_untracked();
                    let epoch = context.session_epoch.get_untracked();
                    let poll_server_epoch = context.server_epoch.get_untracked();
                    let poll_services_grant =
                        context.area_revocation_epoch_untracked(crate::state::PeerArea::Services);
                    in_flight.set(true);
                    let mut busy_guard = crate::tabs::busy::BusyGuard::new(in_flight);
                    spawn_local(async move {
                        poll_active_restarts(
                            context,
                            epoch,
                            poll_server_epoch,
                            poll_services_grant,
                            snapshot,
                            receipts,
                            notice,
                            refresh,
                        )
                        .await;
                        if in_flight.try_get_untracked().is_some() {
                            busy_guard.release();
                        }
                    });
                },
            )));
        });

        on_cleanup(move || interval.set_value(None));

        Self { receipts, notice }
    }

    pub fn track_accepted(
        self,
        context: crate::state::AppContext,
        key: String,
        target: String,
        label: String,
        receipt: &Value,
        refresh: Callback<()>,
    ) {
        let display_name = if label.is_empty() {
            target.clone()
        } else {
            label
        };
        match validate_restart_receipt(receipt) {
            Ok(job_unit) => {
                let now = js_sys::Date::now();
                let entry = CoreRestartReceipt {
                    key: key.clone(),
                    target,
                    label: display_name.clone(),
                    job_unit,
                    started_at_ms: now,
                    deadline_ms: now + CORE_RESTART_TIMEOUT_MS,
                    phase: CoreRestartPhase::WaitingForJob,
                };
                self.receipts.update(|map| {
                    map.insert(key, entry);
                });
                let message = tt_with(
                    context,
                    "{service}: restart scheduled; waiting for its receipt and API readiness.",
                    &[("service", &display_name)],
                );
                self.notice.set(Some(CoreRestartNotice {
                    message: message.clone(),
                    is_error: false,
                }));
                context.toast(message, false);
                refresh.run(());
            }
            Err(error_key) => {
                let message = tt(context, error_key);
                self.notice.set(Some(CoreRestartNotice {
                    message: message.clone(),
                    is_error: true,
                }));
                context.toast(message, true);
                refresh.run(());
            }
        }
    }

    pub fn is_restarting(self, key: &str) -> bool {
        self.receipts.with(|map| map.contains_key(key))
    }
}

#[allow(clippy::too_many_arguments)]
async fn poll_active_restarts(
    context: crate::state::AppContext,
    epoch: u64,
    server_epoch: u64,
    services_grant: u64,
    snapshot: BTreeMap<String, CoreRestartReceipt>,
    receipts: RwSignal<BTreeMap<String, CoreRestartReceipt>>,
    notice: RwSignal<Option<CoreRestartNotice>>,
    refresh: Callback<()>,
) {
    let still_valid = || {
        receipts.try_get_untracked().is_some()
            && context.session_epoch.try_get_untracked() == Some(epoch)
            && context.server_epoch.try_get_untracked() == Some(server_epoch)
            && context.area_revocation_epoch_untracked(crate::state::PeerArea::Services)
                == services_grant
            && context.is_admin_untracked()
            && context.can_read_area_untracked(crate::state::PeerArea::Services)
    };
    let now = js_sys::Date::now();
    for (key, receipt) in snapshot {
        if !still_valid() {
            return;
        }
        if now >= receipt.deadline_ms {
            finish_restart(
                context,
                receipts,
                notice,
                refresh,
                &key,
                &receipt.job_unit,
                tt_with(
                    context,
                    "{service}: restart outcome or readiness could not be confirmed. Check service state and logs before retrying.",
                    &[("service", &receipt.label)],
                ),
                true,
            );
            continue;
        }

        let mut phase = receipt.phase;
        if phase == CoreRestartPhase::WaitingForJob {
            let encoded_unit = js_sys::encode_uri_component(&receipt.job_unit)
                .as_string()
                .unwrap_or_default();
            let path = format!("/api/v1/admin/services/restart/status?job_unit={encoded_unit}");
            let status_result = ApiClient.get(&path).await;
            if !still_valid() {
                return;
            }
            match status_result {
                Ok(status) => match evaluate_restart_status(&receipt.job_unit, &status) {
                    RestartJobOutcome::Pending => {}
                    RestartJobOutcome::JobFailed(detail) => {
                        finish_restart(
                            context,
                            receipts,
                            notice,
                            refresh,
                            &key,
                            &receipt.job_unit,
                            tt_with(
                                context,
                                "{service}: restart failed. {detail}",
                                &[
                                    ("service", &receipt.label),
                                    ("detail", &tt(context, &detail)),
                                ],
                            ),
                            true,
                        );
                        continue;
                    }
                    RestartJobOutcome::JobSucceeded => {
                        phase = CoreRestartPhase::WaitingForReadiness;
                        receipts.update(|map| {
                            if let Some(current) = map.get_mut(&key) {
                                if current.job_unit == receipt.job_unit {
                                    current.phase = CoreRestartPhase::WaitingForReadiness;
                                }
                            }
                        });
                    }
                },
                Err(error) => {
                    if is_fatal_receipt_status_error(error.status) {
                        finish_restart(
                            context,
                            receipts,
                            notice,
                            refresh,
                            &key,
                            &receipt.job_unit,
                            tt_with(
                                context,
                                "{service}: restart failed. {detail}",
                                &[
                                    ("service", &receipt.label),
                                    ("detail", &tt(context, &error.message)),
                                ],
                            ),
                            true,
                        );
                    }
                    continue;
                }
            }
        }

        if phase == CoreRestartPhase::WaitingForReadiness {
            if let Ok(readiness) = ApiClient.get("/api/v1/auth/ready").await {
                if !still_valid() {
                    return;
                }
                if is_api_database_ready(&readiness) {
                    finish_restart(
                        context,
                        receipts,
                        notice,
                        refresh,
                        &key,
                        &receipt.job_unit,
                        tt_with(
                            context,
                            "{service}: restart completed; service activation and API readiness confirmed.",
                            &[("service", &receipt.label)],
                        ),
                        false,
                    );
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_restart(
    context: crate::state::AppContext,
    receipts: RwSignal<BTreeMap<String, CoreRestartReceipt>>,
    notice: RwSignal<Option<CoreRestartNotice>>,
    refresh: Callback<()>,
    key: &str,
    expected_unit: &str,
    message: String,
    is_error: bool,
) {
    let removed = receipts
        .try_update(|map| {
            if map
                .get(key)
                .is_some_and(|item| item.job_unit == expected_unit)
            {
                map.remove(key).is_some()
            } else {
                false
            }
        })
        .unwrap_or(false);
    if !removed {
        return;
    }
    notice.set(Some(CoreRestartNotice {
        message: message.clone(),
        is_error,
    }));
    context.toast(message, is_error);
    refresh.run(());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VALID_UNIT: &str =
        "aetherflow-self-update-restart-aetherflow-api-1234567890abcdef1234567890abcdef.service";
    const OTHER_UNIT: &str =
        "aetherflow-self-update-restart-aetherflow-runner-fedcba0987654321fedcba0987654321.service";

    #[test]
    fn restart_receipt_requires_aetherflow_restart_job_unit() {
        assert_eq!(
            validate_restart_receipt(&json!({
                "status": "accepted",
                "job_unit": VALID_UNIT
            })),
            Ok(VALID_UNIT.into())
        );
        for bad in [
            json!({"status": "accepted"}),
            json!({"status": "accepted", "job_unit": null}),
            json!({"status": "accepted", "job_unit": ""}),
            json!({"status": "accepted", "job_unit": "aetherflow-self-update-deploy-stable-1234567890abcdef.service"}),
            json!({"status": "accepted", "job_unit": "aetherflow-self-update-restart-101.service"}),
            json!({"status": "accepted", "job_unit": "aetherflow-self-update-restart-"}),
            json!({"status": "accepted", "job_unit": "aetherflow-self-update-restart-../bad"}),
        ] {
            assert!(validate_restart_receipt(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn restart_status_evaluates_terminal_success_failure_and_mismatch() {
        let unit = VALID_UNIT;
        assert_eq!(
            evaluate_restart_status(
                unit,
                &json!({
                    "job_unit": OTHER_UNIT,
                    "completed": true,
                    "success": true,
                    "status": "succeeded",
                    "state": "complete"
                })
            ),
            RestartJobOutcome::Pending
        );
        assert_eq!(
            evaluate_restart_status(
                unit,
                &json!({
                    "job_unit": unit,
                    "completed": false,
                    "success": false,
                    "status": "running",
                    "state": "running"
                })
            ),
            RestartJobOutcome::Pending
        );
        assert_eq!(
            evaluate_restart_status(
                unit,
                &json!({
                    "job_unit": unit,
                    "completed": true,
                    "success": true,
                    "status": "succeeded",
                    "state": "complete"
                })
            ),
            RestartJobOutcome::JobSucceeded
        );
        assert_eq!(
            evaluate_restart_status(
                unit,
                &json!({
                    "job_unit": unit,
                    "completed": true,
                    "success": false,
                    "status": "failed",
                    "state": "failed",
                    "error": "System update failed; inspect authenticated updater diagnostics"
                })
            ),
            RestartJobOutcome::JobFailed(
                "System update failed; inspect authenticated updater diagnostics".into()
            )
        );
        assert_eq!(
            evaluate_restart_status(
                unit,
                &json!({
                    "job_unit": unit,
                    "completed": false,
                    "success": false,
                    "status": "recovery_required",
                    "state": "interrupted"
                })
            ),
            RestartJobOutcome::JobFailed("Check service logs.".into())
        );
    }

    #[test]
    fn readiness_requires_api_service_ready_and_database_ok() {
        assert!(is_api_database_ready(&json!({
            "service": "aetherflow-api",
            "status": "ready",
            "database": "ok"
        })));
        for not_ready in [
            json!({"service": "aetherflow-api", "status": "not_ready", "database": "unreachable"}),
            json!({"service": "aetherflow-api", "status": "ready", "database": "unreachable"}),
            json!({"service": "other", "status": "ready", "database": "ok"}),
            json!({}),
        ] {
            assert!(!is_api_database_ready(&not_ready), "{not_ready}");
        }
    }

    #[test]
    fn persisted_receipts_round_trip_and_reject_invalid_entries() {
        let mut map = BTreeMap::new();
        map.insert(
            "aetherflow-api".into(),
            CoreRestartReceipt {
                key: "aetherflow-api".into(),
                target: "aetherflow-api".into(),
                label: "AetherFlow API".into(),
                job_unit: VALID_UNIT.into(),
                started_at_ms: 1000.0,
                deadline_ms: 181_000.0,
                phase: CoreRestartPhase::WaitingForReadiness,
            },
        );
        let serialized = serialize_persisted_receipts(&map);
        assert_eq!(load_persisted_receipts(Some(&serialized)), map);

        assert!(load_persisted_receipts(Some("not-json")).is_empty());
        assert!(load_persisted_receipts(Some(
            r#"{"bad":{"key":"mismatch","target":"a","label":"A","job_unit":"aetherflow-self-update-restart-1","started_at_ms":1,"deadline_ms":2}}"#
        ))
        .is_empty());
        assert!(load_persisted_receipts(Some(
            r#"{"a":{"key":"a","target":"a","label":"A","job_unit":"invalid-unit","started_at_ms":1,"deadline_ms":2}}"#
        ))
        .is_empty());
        assert_eq!(serialize_persisted_receipts(&BTreeMap::new()), "");
    }
}
