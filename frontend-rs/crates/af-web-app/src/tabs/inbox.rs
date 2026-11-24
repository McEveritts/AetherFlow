//! Explicit human decisions; the backend owns execution and audit timestamps.
use super::contracts::{use_api_typed_when, PendingCount};
use crate::state::{
    app, owned_resource_reads, run_resource_read, use_api_when, PeerArea, ResourceReads,
};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{Badge, ConfirmDialog, EmptyState, Modal, ObsCard, TabPanel, TabsBar};
use af_web_core::{api::ApiClient, draft::FormDraft};
use af_web_ui::SkeletonBox;
use leptos::prelude::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use wasm_bindgen_futures::spawn_local;

const ENVELOPE_KEYS: &[&str] = &[
    "id",
    "action",
    "status",
    "source",
    "reason",
    "risk_level",
    "riskLevel",
    "classification",
    "created_at",
    "resolved_at",
    "resolved_by",
    "executed_at",
    "execution_log",
    "job_unit",
    "parameters",
    "payload",
];

fn text(value: &Value, key: &str) -> String {
    match &value[key] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        v => v.to_string(),
    }
}

fn risk(value: &Value) -> &'static str {
    let action = super::contracts::decode::<super::contracts::ActionApprovalRequest>(value);
    let level = if action.risk_level.is_empty() {
        action.classification
    } else {
        action.risk_level
    };
    match level.to_ascii_lowercase().as_str() {
        "low" | "safe" => "LOW",
        "high" => "HIGH",
        "critical" => "CRITICAL",
        _ => "MEDIUM",
    }
}

fn risk_tone(classification: &str) -> &'static str {
    match classification {
        "LOW" => "success",
        "HIGH" | "CRITICAL" => "danger",
        _ => "warning",
    }
}

fn status_tone(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "executed" => "success",
        "queued" | "working" | "running" | "accepted" | "approved" => "indigo",
        "rejected" | "failed" => "danger",
        "pending" | "unavailable" => "warning",
        _ => "neutral",
    }
}

fn matches_inbox_filter(filter: &str, status: &str) -> bool {
    match filter {
        "pending" => status == "pending",
        "approved" => matches!(
            status,
            "approved" | "queued" | "executed" | "failed" | "unavailable"
        ),
        "rejected" => status == "rejected",
        _ => true,
    }
}

fn is_valid_core_restart_unit(unit: &str) -> bool {
    let trimmed = unit.trim();
    trimmed.starts_with("aetherflow-self-update-restart-")
        && af_models::is_valid_self_update_job_unit_name(trimmed)
}

fn action_job_unit(action: &Value, response: Option<&Value>) -> Option<String> {
    let from_action = action
        .get("job_unit")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let from_response = response
        .and_then(|resp| resp.get("job_unit"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    from_action.or(from_response).map(str::to_string)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ApprovalFeedbackKind {
    Executed,
    Queued { job_unit: String },
    QueuedMissingReceipt,
    Unavailable,
    ApprovedUnconfirmed,
    ApprovedSubsystem,
    Failed(String),
    Rejected,
}

fn classify_approval_decision(
    verb: &str,
    action: &Value,
    response: &Value,
) -> ApprovalFeedbackKind {
    if verb == "reject" {
        return ApprovalFeedbackKind::Rejected;
    }
    let status = action
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| response.get("status").and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match status.as_str() {
        "failed" => ApprovalFeedbackKind::Failed(text(action, "execution_log")),
        "executed" => ApprovalFeedbackKind::Executed,
        "queued" | "accepted" => match action_job_unit(action, Some(response)) {
            Some(unit) if is_valid_core_restart_unit(&unit) => {
                ApprovalFeedbackKind::Queued { job_unit: unit }
            }
            _ => ApprovalFeedbackKind::QueuedMissingReceipt,
        },
        "unavailable" => ApprovalFeedbackKind::Unavailable,
        "approved" => {
            if analyze_action(action).executable_gate {
                ApprovalFeedbackKind::ApprovedUnconfirmed
            } else {
                ApprovalFeedbackKind::ApprovedSubsystem
            }
        }
        _ => ApprovalFeedbackKind::Unavailable,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedServiceGate {
    service: String,
    operation: String,
    manager: Option<String>,
}

fn parse_service_gate_command(raw_action: &str) -> Option<ParsedServiceGate> {
    let trimmed = raw_action.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    for (prefix, operation) in [
        ("restart_service:", "restart"),
        ("start_service:", "start"),
        ("stop_service:", "stop"),
        ("service_restart:", "restart"),
        ("service_start:", "start"),
        ("service_stop:", "stop"),
        ("restart:", "restart"),
        ("start:", "start"),
        ("stop:", "stop"),
    ] {
        if lower.starts_with(prefix) {
            let rest = trimmed[prefix.len()..].trim();
            if rest.is_empty() {
                return None;
            }
            if let Some((svc, mgr)) = rest.split_once(':') {
                let svc = svc.trim();
                let mgr = mgr.trim();
                if svc.is_empty() || svc.contains(':') || mgr.contains(':') {
                    return None;
                }
                return Some(ParsedServiceGate {
                    service: svc.to_string(),
                    operation: operation.to_string(),
                    manager: (!mgr.is_empty()).then(|| mgr.to_string()),
                });
            }
            return Some(ParsedServiceGate {
                service: rest.to_string(),
                operation: operation.to_string(),
                manager: None,
            });
        }
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() == 2 {
        let verb = parts[0].to_ascii_lowercase();
        if matches!(verb.as_str(), "restart" | "start" | "stop") {
            return Some(ParsedServiceGate {
                service: parts[1].to_string(),
                operation: verb,
                manager: None,
            });
        }
    }
    if parts.len() == 3 && parts[0].eq_ignore_ascii_case("systemctl") {
        let verb = parts[1].to_ascii_lowercase();
        if matches!(verb.as_str(), "restart" | "start" | "stop") {
            return Some(ParsedServiceGate {
                service: parts[2].to_string(),
                operation: verb,
                manager: Some("systemd".to_string()),
            });
        }
    }
    None
}

fn is_core_deferred_restart(operation: &str, target: &str) -> bool {
    operation.eq_ignore_ascii_case("restart")
        && matches!(
            target.trim().trim_end_matches(".service"),
            "aetherflow-api" | "aetherflow-runner"
        )
}

fn target_summary(value: &Value) -> String {
    let action = super::contracts::decode::<super::contracts::ActionApprovalRequest>(value);
    let payload = super::contracts::decode::<super::contracts::ActionScope>(&action.payload);
    let parameters = super::contracts::decode::<super::contracts::ActionScope>(&action.parameters);
    let candidates = [
        (&action.target, &payload.target, &parameters.target),
        (&action.resource, &payload.resource, &parameters.resource),
        (&action.service, &payload.service, &parameters.service),
        (&action.targets, &payload.targets, &parameters.targets),
    ];
    for (direct, payload, parameters) in candidates {
        if let Some(target) = [direct, payload, parameters]
            .into_iter()
            .flatten()
            .find(|value| !value.is_null())
        {
            return match target {
                Value::String(s) => s.clone(),
                value => value.to_string(),
            };
        }
    }
    if let Some(parsed) = parse_service_gate_command(&action.action) {
        return parsed.service;
    }
    if let Some((_, target)) = action.action.split_once(':') {
        return target.trim().into();
    }
    let parts = action.action.split_whitespace().collect::<Vec<_>>();
    if parts.len() == 2 || (parts.len() == 3 && parts[0] == "systemctl") {
        return parts.last().unwrap_or(&"").to_string();
    }
    "Scope is defined by the complete action payload below; inspect it before approval.".into()
}

fn format_parameter_value(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(s) => {
            let trimmed = s.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        Value::Array(items) if items.is_empty() => None,
        Value::Array(items) => {
            if items.iter().all(Value::is_string) {
                let joined = items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(", ");
                (!joined.is_empty()).then_some(joined)
            } else {
                serde_json::to_string(value).ok()
            }
        }
        Value::Object(map) if map.is_empty() => None,
        Value::Object(_) => serde_json::to_string(value).ok(),
        other => Some(other.to_string()),
    }
}

fn extract_action_parameters(value: &Value) -> Vec<(String, String)> {
    let mut entries = BTreeMap::<String, String>::new();
    if let Some(params) = value.get("parameters") {
        match params {
            Value::Object(map) => {
                for (k, v) in map {
                    if let Some(formatted) = format_parameter_value(v) {
                        entries.insert(k.clone(), formatted);
                    }
                }
            }
            other => {
                if let Some(formatted) = format_parameter_value(other) {
                    entries.insert("parameters".into(), formatted);
                }
            }
        }
    }
    if let Some(payload) = value.get("payload") {
        match payload {
            Value::Object(map) => {
                for (k, v) in map {
                    if let Some(formatted) = format_parameter_value(v) {
                        let key = if entries.contains_key(k) {
                            format!("payload.{k}")
                        } else {
                            k.clone()
                        };
                        entries.insert(key, formatted);
                    }
                }
            }
            other => {
                if let Some(formatted) = format_parameter_value(other) {
                    entries.insert("payload".into(), formatted);
                }
            }
        }
    }
    if let Some(root) = value.as_object() {
        for (k, v) in root {
            if ENVELOPE_KEYS.contains(&k.as_str()) {
                continue;
            }
            if !entries.contains_key(k) {
                if let Some(formatted) = format_parameter_value(v) {
                    entries.insert(k.clone(), formatted);
                }
            }
        }
    }
    if entries.is_empty() {
        if let Some(parsed) = parse_service_gate_command(&text(value, "action")) {
            entries.insert("operation".into(), parsed.operation);
            entries.insert("service".into(), parsed.service);
            if let Some(mgr) = parsed.manager {
                entries.insert("manager".into(), mgr);
            }
        }
    }
    entries.into_iter().collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActionBreakdown {
    risk_level: &'static str,
    raw_classification: String,
    operation: String,
    target: String,
    manager: Option<String>,
    executable_gate: bool,
    core_impact: bool,
    parameters: Vec<(String, String)>,
}

fn analyze_action(value: &Value) -> ActionBreakdown {
    let risk_level = risk(value);
    let raw_classification = text(value, "classification");
    let raw_action = text(value, "action");
    let gate = parse_service_gate_command(&raw_action);
    let target = target_summary(value);
    let (operation, manager, executable_gate) = match gate {
        Some(parsed) => {
            let mgr = parsed.manager.or_else(|| {
                let explicit = text(value, "managed_by");
                (!explicit.trim().is_empty()).then_some(explicit)
            });
            (parsed.operation, mgr, true)
        }
        None => {
            let explicit_op = value
                .pointer("/parameters/operation")
                .or_else(|| value.pointer("/parameters/action"))
                .or_else(|| value.pointer("/payload/operation"))
                .or_else(|| value.pointer("/payload/action"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| {
                    raw_action
                        .split_once(':')
                        .map(|(verb, _)| verb.trim().to_string())
                        .filter(|s| !s.is_empty())
                })
                .unwrap_or_else(|| raw_action.clone());
            let explicit_mgr = text(value, "managed_by");
            (
                explicit_op,
                (!explicit_mgr.trim().is_empty()).then_some(explicit_mgr),
                false,
            )
        }
    };
    let core_impact = executable_gate && is_core_deferred_restart(&operation, &target);
    let parameters = extract_action_parameters(value);
    ActionBreakdown {
        risk_level,
        raw_classification,
        operation,
        target,
        manager,
        executable_gate,
        core_impact,
        parameters,
    }
}

#[component]
pub fn InboxTab() -> impl IntoView {
    let context = app();
    view! {
        <Show
            when=move || context.is_admin()
            fallback=move || {
                view! {
                    <EmptyState
                        title="Common.adminRequired"
                        description="Only administrators can inspect and resolve infrastructure actions."
                    />
                }
            }
        >
            <ApprovalInbox />
        </Show>
    }
}

#[component]
fn ApprovalInbox() -> impl IntoView {
    let context = app();
    const PAGE_SIZE: usize = 50;
    let filter = RwSignal::new("pending".to_string());
    let page = RwSignal::new(0usize);
    Effect::new(move |_| {
        filter.track();
        page.set(0);
    });
    let can_read_services = Signal::derive(move || context.can_read_area(PeerArea::Services));
    let resource = use_api_when(
        can_read_services,
        Signal::derive(move || {
            let filter = filter.get();
            let api_status = match filter.as_str() {
                "approved" => "approved_history",
                "pending" => "pending",
                "rejected" => "rejected",
                _ => "all",
            };
            format!(
                "/api/v1/admin/actions/pending?status={api_status}&limit={PAGE_SIZE}&offset={}",
                page.get() * PAGE_SIZE
            )
        }),
    );
    let pending = use_api_typed_when::<PendingCount>(
        can_read_services,
        Signal::derive(|| "/api/v1/admin/actions/pending?status=pending&limit=1".to_string()),
    );
    let total = Memo::new(move |_| {
        resource.data.with(|data| {
            data["total"].as_u64().unwrap_or_else(|| {
                super::contracts::grid_rows::<super::contracts::ActionApprovalRequest>(data).len()
                    as u64
            }) as usize
        })
    });
    let selected = RwSignal::new(Value::Null);
    let open = RwSignal::new(false);
    let detail_loading = RwSignal::new(false);
    let detail_error = RwSignal::new(None::<String>);
    let generation = RwSignal::new(0u64);
    let detail_reads = owned_resource_reads();
    let last_epochs = StoredValue::new((
        context.session_epoch.get_untracked(),
        context.server_epoch.get_untracked(),
        context.area_revocation_epoch_untracked(PeerArea::Services),
    ));
    Effect::new(move |_| {
        let next = (
            context.session_epoch.get(),
            context.server_epoch.get(),
            context.area_revocation_epoch(PeerArea::Services),
        );
        if last_epochs.get_value() == next && can_read_services.get() {
            return;
        }
        last_epochs.set_value(next);
        detail_reads.with_value(ResourceReads::cancel);
        generation.update(|g| *g += 1);
        open.set(false);
        selected.set(Value::Null);
        detail_loading.set(false);
        detail_error.set(None);
        page.set(0);
    });
    Effect::new(move |_| {
        if !can_read_services.get() {
            return;
        }
        if let Some(total) = pending.data.get().reported_total() {
            context.pending.set(total as usize);
        }
    });
    let rows = Memo::new(move |_| {
        let filter = filter.get();
        super::contracts::grid_rows::<super::contracts::ActionApprovalRequest>(&resource.data.get())
            .into_iter()
            .filter(|a| matches_inbox_filter(&filter, a["status"].as_str().unwrap_or("")))
            .collect::<Vec<_>>()
    });
    let refresh_selected = Callback::new(move |id: i64| {
        if !open.get_untracked()
            || !context.can_read_area_untracked(PeerArea::Services)
            || selected.with_untracked(|a| a["id"].as_i64() != Some(id))
        {
            return;
        }
        let epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let services_grant = context.area_revocation_epoch_untracked(PeerArea::Services);
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        let Some(job) = detail_reads.try_update_value(ResourceReads::next) else {
            return;
        };
        spawn_local(async move {
            let Some(result) =
                run_resource_read(job, ApiClient.get(&format!("/api/v1/admin/actions/{id}"))).await
            else {
                return;
            };
            if generation.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Services) != services_grant
                || !context.can_read_area_untracked(PeerArea::Services)
            {
                return;
            }
            if let Ok(value) = result {
                let updated = if value["action"].is_object() {
                    value["action"].clone()
                } else {
                    value
                };
                if updated["id"].as_i64() == Some(id) {
                    selected.set(updated);
                }
            }
        });
    });
    let interval = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        15_000,
        move || {
            if !context.can_read_area_untracked(PeerArea::Services) {
                return;
            }
            if !resource.loading.get_untracked() {
                resource.refresh();
            }
            if !pending.loading.get_untracked() {
                pending.refresh();
            }
            if open.get_untracked() && !detail_loading.get_untracked() {
                let receipt_action = selected.with_untracked(|action| {
                    if matches!(action["status"].as_str(), Some("queued" | "unavailable"))
                        && action_job_unit(action, None).is_some()
                    {
                        action["id"].as_i64()
                    } else {
                        None
                    }
                });
                if let Some(id) = receipt_action {
                    refresh_selected.run(id);
                }
            }
        },
    )));
    on_cleanup(move || interval.set_value(None));
    let risk_counts = Memo::new(move |_| {
        let mut critical_high = 0usize;
        let mut medium = 0usize;
        let mut low = 0usize;
        for row in rows.get() {
            match risk(&row) {
                "CRITICAL" | "HIGH" => critical_high += 1,
                "LOW" => low += 1,
                _ => medium += 1,
            }
        }
        (critical_high, medium, low)
    });
    let inspect = Callback::new(move |action: Value| {
        if !context.can_read_area_untracked(PeerArea::Services) {
            return;
        }
        let Some(id) = action["id"].as_i64() else {
            return;
        };
        let epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let services_grant = context.area_revocation_epoch_untracked(PeerArea::Services);
        selected.set(action);
        open.set(true);
        detail_loading.set(true);
        detail_error.set(None);
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        let Some(job) = detail_reads.try_update_value(ResourceReads::next) else {
            return;
        };
        spawn_local(async move {
            let Some(result) =
                run_resource_read(job, ApiClient.get(&format!("/api/v1/admin/actions/{id}"))).await
            else {
                return;
            };
            if generation.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Services) != services_grant
                || !context.can_read_area_untracked(PeerArea::Services)
            {
                return;
            }
            match result {
                Ok(value) => {
                    let action = if value["action"].is_object() {
                        value["action"].clone()
                    } else {
                        value
                    };
                    if action["id"].as_i64() == Some(id) {
                        selected.set(action);
                    } else {
                        detail_error.set(Some(
                            "Action detail response did not match the requested action.".into(),
                        ));
                    }
                }
                Err(error)
                    if matches!(
                        error.code.as_deref(),
                        Some("SERVER_CHANGED" | "SESSION_CHANGED" | "ABORTED")
                    ) =>
                {
                    return;
                }
                Err(error) => detail_error.set(Some(error.message)),
            }
            detail_loading.set(false);
        });
    });
    let resolved = Callback::new(move |action: Value| {
        if action["status"] == "queued" {
            filter.set("approved".to_string());
        }
        resource.data.update(|data| {
            if let Some(rows) = data["actions"].as_array_mut() {
                if let Some(row) = rows.iter_mut().find(|r| r["id"] == action["id"]) {
                    *row = action;
                }
            }
        });
        context.pending.update(|n| *n = n.saturating_sub(1));
        if context.can_read_area_untracked(PeerArea::Services) {
            resource.refresh();
            pending.refresh();
        }
    });
    view! {
        <section class="space-y-5 py-5 min-w-0 max-w-full">
            <div class="flex flex-wrap justify-between gap-3">
                <div>
                    <h2 class="text-xl font-semibold">
                        {move || tt(context, "Tabs.inboxHeading")}
                    </h2>
                    <p class="text-sm text-slate-400">
                        {move || tt(
                            context,
                            "Review scope and risk before authorizing an infrastructure change.",
                        )}
                    </p>
                </div>
                <button
                    class="glass-button px-4 py-2"
                    disabled=move || resource.loading.get() || !can_read_services.get()
                    title=move || {
                        context
                            .area_block_reason(PeerArea::Services, false)
                            .unwrap_or_default()
                    }
                    on:click=move |_| {
                        if context.can_read_area_untracked(PeerArea::Services) {
                            resource.refresh();
                            pending.refresh();
                        }
                    }
                    aria-label=move || tt(context, "Refresh")
                >
                    {move || tt(context, "Common.refresh")}
                </button>
            </div>
            <Show when=move || !can_read_services.get()>
                <p
                    role="status"
                    class="rounded-xl border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
                >
                    {move || {
                        context
                            .area_block_reason(PeerArea::Services, false)
                            .unwrap_or_default()
                    }}
                </p>
            </Show>
            <p role="status" class="text-sm text-amber-300">
                {move || tt_with(context, "Inbox.awaitingApprovalCount", &[("count", &context.pending.get().to_string())])}
            </p>
            <div
                role="region"
                aria-label=move || tt(context, "Inbox.summaryRegion")
                class="grid grid-cols-2 xl:grid-cols-4 gap-3 min-w-0"
            >
                <div class="glass-card p-4 min-w-0">
                    <span class="text-xs uppercase tracking-wider text-slate-400 block break-words">
                        {move || tt(context, "Inbox.summaryMatching")}
                    </span>
                    <div class="text-xl font-bold font-mono text-slate-100 mt-1">
                        {move || total.get()}
                    </div>
                </div>
                <div class="glass-card p-4 min-w-0">
                    <span class="text-xs uppercase tracking-wider text-slate-400 block break-words">
                        {move || tt(context, "Inbox.summaryCriticalHigh")}
                    </span>
                    <div class="text-xl font-bold font-mono text-rose-300 mt-1">
                        {move || risk_counts.get().0}
                    </div>
                </div>
                <div class="glass-card p-4 min-w-0">
                    <span class="text-xs uppercase tracking-wider text-slate-400 block break-words">
                        {move || tt(context, "Inbox.summaryMedium")}
                    </span>
                    <div class="text-xl font-bold font-mono text-amber-300 mt-1">
                        {move || risk_counts.get().1}
                    </div>
                </div>
                <div class="glass-card p-4 min-w-0">
                    <span class="text-xs uppercase tracking-wider text-slate-400 block break-words">
                        {move || tt(context, "Inbox.summaryLow")}
                    </span>
                    <div class="text-xl font-bold font-mono text-emerald-300 mt-1">
                        {move || risk_counts.get().2}
                    </div>
                </div>
            </div>
            <TabsBar
                id_prefix="inbox"
                tabs=vec![
                    ("pending".into(), "Pending Approval".into()),
                    ("approved".into(), "Approved / Executed".into()),
                    ("rejected".into(), "Rejected".into()),
                    ("all".into(), "All".into()),
                ]
                active=filter
            />
            <TabPanel id_prefix="inbox" id=Signal::derive(move || filter.get())>
                {move || {
                    resource
                        .error
                        .get()
                        .map(|error| {
                            view! {
                                <p role="alert" class="text-rose-300">
                                    {move || tt(context, &error.message)}
                                </p>
                            }
                        })
                }}
                {move || {
                    pending
                        .error
                        .get()
                        .map(|error| {
                            view! {
                                <p role="alert" class="text-rose-300">
                                    {move || tt_with(context, "Pending count unavailable: {error}", &[("error", &(error.message).to_string())])}
                                </p>
                            }
                        })
                }}
                <Show when=move || resource.loading.get() && resource.data.with(Value::is_null)>
                    <SkeletonBox class="h-48" />
                </Show>
                <Show when=move || {
                    !resource.loading.get() && resource.error.with(Option::is_none)
                        && rows.with(Vec::is_empty)
                }>
                    <EmptyState
                        title="No actions in this view"
                        description="New FlowAI, operator and watchdog proposals appear here."
                    />
                </Show>
                <div class="space-y-3">
                    {move || {
                        rows.get()
                            .into_iter()
                            .map(|action| {
                                let classification = risk(&action);
                                let status_str = text(&action, "status");
                                let exec_log = text(&action, "execution_log");
                                let job_unit = text(&action, "job_unit");
                                let review = action.clone();
                                let source_action = action.clone();
                                view! {
                                    <ObsCard>
                                        <div class="flex flex-wrap items-start justify-between gap-4">
                                            <div class="min-w-0 flex-1 space-y-2">
                                                <h3 class="font-semibold break-words">
                                                    {text(&action, "action")}
                                                </h3>
                                                <div class="flex flex-wrap gap-2 items-center text-xs">
                                                    <Badge
                                                        label=classification
                                                        tone=risk_tone(classification)
                                                    />
                                                    <Badge
                                                        label=status_str.clone()
                                                        tone=status_tone(&status_str)
                                                    />
                                                    <span>
                                                        {move || format!(
                                                            "{} · #{}",
                                                            tt(context, &text(&source_action, "source")),
                                                            text(&source_action, "id"),
                                                        )}
                                                    </span>
                                                </div>
                                                <p class="text-sm text-slate-400 break-words">
                                                    {text(&action, "reason")}
                                                </p>
                                                <p class="text-xs text-slate-400">
                                                    {move || tt_with(context, "Created {created} · Target: {target}", &[("created", &(text(&action, "created_at")).to_string()), ("target", &tt(context, &target_summary(&action)))])}
                                                </p>
                                                {(!job_unit.trim().is_empty()).then(|| view! {
                                                    <p class="text-xs font-mono text-indigo-300 break-all">
                                                        {move || format!("{}: {}", tt(context, "Inbox.receiptLabel"), job_unit)}
                                                    </p>
                                                })}
                                                {(!exec_log.trim().is_empty()).then(|| view! {
                                                    <div class="bg-slate-950/80 rounded-lg p-2.5 border border-white/10">
                                                        <p class="text-xs font-semibold text-slate-400 mb-1">
                                                            {move || tt(context, "Inbox.executionLogHeading")}
                                                        </p>
                                                        <pre class="text-xs font-mono text-slate-300 whitespace-pre-wrap break-all">
                                                            {exec_log}
                                                        </pre>
                                                    </div>
                                                })}
                                            </div>
                                            <button
                                                class="glass-button-primary px-4 py-2 shrink-0"
                                                on:click=move |_| inspect.run(review.clone())
                                            >
                                                {move || tt(context, "Inspect action")}
                                            </button>
                                        </div>
                                    </ObsCard>
                                }
                            })
                            .collect_view()
                    }}
                </div>
                <p role="status" class="text-sm text-slate-400">
                    {move || tt_with(context, "{count} matching records", &[("count", &total.get().to_string())])}
                </p>
                <Show when=move || { total.get() > PAGE_SIZE }>
                    <nav class="flex flex-wrap items-center justify-between gap-3" aria-label=move || tt(context, "Approval inbox pagination")>
                        <button
                            type="button"
                            class="glass-button px-4 py-2"
                            disabled=move || page.get() == 0 || resource.loading.get()
                            on:click=move |_| page.update(|page| *page = page.saturating_sub(1))
                        >
                            {move || tt(context, "Previous")}
                        </button>
                        <span class="text-sm text-slate-400">
                            {move || tt_with(context, "Page {page} of {pages}", &[("page", &(page.get() + 1).to_string()), ("pages", &total.get().div_ceil(PAGE_SIZE).to_string())])}
                        </span>
                        <button
                            type="button"
                            class="glass-button px-4 py-2"
                            disabled=move || { (page.get() + 1) * PAGE_SIZE >= total.get() || resource.loading.get() }
                            on:click=move |_| page.update(|page| *page += 1)
                        >
                            {move || tt(context, "Next")}
                        </button>
                    </nav>
                </Show>
                <p class="text-xs text-slate-400">
                    {move || {
                        tt_with(context, "{count} records loaded. Execution results and resolver identity come from the audit record.", &[("count", &super::contracts::grid_rows::<super::contracts::ActionApprovalRequest>(&resource.data.get()).len().to_string())])
                    }}
                </p>
            </TabPanel>
            <ActionDetailModal
                open
                action=selected
                loading=detail_loading
                error=detail_error
                on_resolved=resolved
                on_refresh_action=refresh_selected
            />
        </section>
    }
}

#[component]
fn ActionDetailModal(
    open: RwSignal<bool>,
    action: RwSignal<Value>,
    loading: RwSignal<bool>,
    error: RwSignal<Option<String>>,
    on_resolved: Callback<Value>,
    on_refresh_action: Callback<i64>,
) -> impl IntoView {
    let context = app();
    let draft = RwSignal::new(FormDraft::new(json!({"reason":""})));
    let draft_id = RwSignal::new(Value::Null);
    let busy = RwSignal::new(false);
    let exec_ticket = RwSignal::new(0u64);
    let confirm = RwSignal::new(false);
    let decision = RwSignal::new("approve".to_string());
    let outcome = RwSignal::new(None::<String>);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(crate::state::PeerArea::Services);
        exec_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        open.set(false);
        busy.set(false);
        confirm.set(false);
        outcome.set(None);
        draft.set(FormDraft::new(json!({"reason":""})));
        draft_id.set(Value::Null);
    });
    Effect::new(move |_| {
        if !context.can_write_area(crate::state::PeerArea::Services) {
            exec_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            busy.set(false);
            confirm.set(false);
        }
    });
    Effect::new(move |_| {
        let id = action.get()["id"].clone();
        if id != draft_id.get_untracked() {
            draft.set(FormDraft::new(json!({"reason":""})));
            draft_id.set(id);
            outcome.set(None);
            confirm.set(false);
        }
        if !open.get() {
            confirm.set(false);
        }
    });
    let execute = Callback::new(move |(): ()| {
        if busy.get_untracked()
            || loading.get_untracked()
            || error.with_untracked(Option::is_some)
            || !context.is_admin_untracked()
            || !context.can_write_area_untracked(crate::state::PeerArea::Services)
        {
            return;
        }
        let record = action.get_untracked();
        if record["status"] != "pending" {
            return;
        }
        let Some(id) = record["id"].as_i64() else {
            return;
        };
        let verb = decision.get_untracked();
        if !matches!(verb.as_str(), "approve" | "reject") {
            return;
        }
        exec_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = exec_ticket.get_untracked();
        let fence = crate::tabs::busy::AreaFence::capture(
            context,
            crate::state::PeerArea::Services,
            true,
            true,
            exec_ticket,
            ticket,
        );
        busy.set(true);
        outcome.set(None);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(busy, exec_ticket, ticket);
        spawn_local(async move {
            let result = ApiClient
                .post(&format!("/api/v1/admin/actions/{id}/{verb}"), None)
                .await;
            if busy.try_get_untracked().is_none() || !fence.is_valid() {
                return;
            }
            busy_guard.release();
            match result {
                Ok(data) => {
                    let updated = data["action"].clone();
                    if updated["id"].as_i64() != Some(id) {
                        outcome.set(Some(
                            "Unexpected action response. Refresh the inbox to confirm the result."
                                .into(),
                        ));
                    } else {
                        on_resolved.run(updated.clone());
                        if action.with_untracked(|a| a["id"].as_i64() == Some(id)) {
                            action.set(updated.clone());
                        }
                        let feedback = classify_approval_decision(&verb, &updated, &data);
                        let (message, is_error) = match feedback {
                            ApprovalFeedbackKind::Failed(err_log) => (
                                tt_with(
                                    context,
                                    "Execution failed: {error}",
                                    &[("error", &err_log)],
                                ),
                                true,
                            ),
                            ApprovalFeedbackKind::Rejected => (tt(context, "Action rejected."), false),
                            ApprovalFeedbackKind::Executed => {
                                (tt(context, "Action approved and executed."), false)
                            }
                            ApprovalFeedbackKind::Queued { job_unit } => (
                                tt_with(
                                    context,
                                    "Inbox.queuedBanner",
                                    &[("receipt", &job_unit)],
                                ),
                                false,
                            ),
                            ApprovalFeedbackKind::QueuedMissingReceipt => (
                                tt(
                                    context,
                                    "Restart was accepted without a valid receipt identity. Check service logs before retrying.",
                                ),
                                true,
                            ),
                            ApprovalFeedbackKind::Unavailable => {
                                (tt(context, "Inbox.unavailableBanner"), true)
                            }
                            ApprovalFeedbackKind::ApprovedUnconfirmed => {
                                (tt(context, "Inbox.approvedUnconfirmed"), true)
                            }
                            ApprovalFeedbackKind::ApprovedSubsystem => (
                                tt(
                                    context,
                                    "Action approved; execution is owned by the originating subsystem.",
                                ),
                                false,
                            ),
                        };
                        if updated["status"] != "queued"
                            && action.with_untracked(|a| a["id"].as_i64() == Some(id))
                        {
                            outcome.set(Some(message.clone()));
                        }
                        context.toast(message, is_error);
                    }
                }
                Err(error) => {
                    if action.with_untracked(|a| a["id"].as_i64() == Some(id)) {
                        outcome.set(Some(error.message.clone()));
                    }
                    context.toast(tt(context, &error.message), true);
                    on_refresh_action.run(id);
                }
            }
            confirm.set(false);
        });
    });
    let request = Callback::new(move |verb: String| {
        if busy.get_untracked()
            || loading.get_untracked()
            || error.with_untracked(Option::is_some)
            || !context.is_admin_untracked()
            || !context.can_write_area_untracked(crate::state::PeerArea::Services)
        {
            return;
        }
        decision.set(verb);
        if matches!(risk(&action.get_untracked()), "HIGH" | "CRITICAL") {
            confirm.set(true);
        } else {
            execute.run(());
        }
    });
    view! {
        <Modal open title="Action details">
            <div class="space-y-4 min-w-0">
                <Show when=move || loading.get()>
                    <p role="status">{move || tt(context, "Verifying current action…")}</p>
                </Show>
                {move || {
                    error
                        .get()
                        .map(|e| {
                            view! {
                                <p role="alert" class="text-rose-300">
                                    {move || tt(context, &e)}
                                </p>
                            }
                        })
                }}
                <h3 class="text-lg font-semibold break-words">
                    {move || text(&action.get(), "action")}
                </h3>
                {move || {
                    let current = action.get();
                    let breakdown = analyze_action(&current);
                    let status_str = text(&current, "status");
                    let action_id = text(&current, "id");
                    let reason_str = text(&current, "reason");
                    let exec_log = text(&current, "execution_log");
                    let job_unit = text(&current, "job_unit");
                    let resolved_by = text(&current, "resolved_by");
                    let resolved_at = text(&current, "resolved_at");
                    let raw_class = breakdown.raw_classification.clone();
                    let show_raw_class = !raw_class.trim().is_empty()
                        && !raw_class.eq_ignore_ascii_case(breakdown.risk_level);
                    let target_for_warn = breakdown.target.clone();
                    let job_unit_for_banner = job_unit.clone();
                    let manager_display = breakdown
                        .manager
                        .clone()
                        .unwrap_or_else(|| tt(context, "Inbox.defaultManager"));
                    let is_queued = status_str.eq_ignore_ascii_case("queued");
                    let is_unavailable = status_str.eq_ignore_ascii_case("unavailable");
                    let is_approved_unconfirmed =
                        status_str.eq_ignore_ascii_case("approved") && breakdown.executable_gate;
                    view! {
                        <div class="space-y-4 min-w-0">
                            <div class="flex flex-wrap items-center gap-2 text-xs">
                                <Badge
                                    label=breakdown.risk_level
                                    tone=risk_tone(breakdown.risk_level)
                                />
                                {show_raw_class.then(|| view! {
                                    <Badge
                                        label=raw_class
                                        tone=risk_tone(breakdown.risk_level)
                                    />
                                })}
                                {(!status_str.is_empty()).then(|| view! {
                                    <Badge
                                        label=status_str.clone()
                                        tone=status_tone(&status_str)
                                    />
                                })}
                                <Badge
                                    label=tt(
                                        context,
                                        if breakdown.executable_gate {
                                            "Inbox.executableGate"
                                        } else {
                                            "Inbox.subsystemGate"
                                        },
                                    )
                                    tone=if breakdown.executable_gate { "indigo" } else { "muted" }
                                />
                                {(!action_id.is_empty()).then(|| view! {
                                    <span class="font-mono text-slate-400">{format!("#{action_id}")}</span>
                                })}
                            </div>

                            {breakdown.core_impact.then(|| view! {
                                <div role="alert" class="af-danger-banner text-xs">
                                    {tt_with(
                                        context,
                                        "Inbox.coreImpactWarning",
                                        &[("target", &target_for_warn)],
                                    )}
                                </div>
                            })}

                            {is_queued.then(|| view! {
                                <p role="status" class="bg-indigo-500/10 border border-indigo-400/30 rounded-xl p-3 text-xs text-indigo-200 break-all">
                                    {tt_with(context, "Inbox.queuedBanner", &[("receipt", &job_unit_for_banner)])}
                                </p>
                            })}

                            {is_unavailable.then(|| view! {
                                <div role="alert" class="af-danger-banner text-xs">
                                    {tt(context, "Inbox.unavailableBanner")}
                                </div>
                            })}

                            {is_approved_unconfirmed.then(|| view! {
                                <div role="alert" class="af-danger-banner text-xs">
                                    {tt(context, "Inbox.approvedUnconfirmed")}
                                </div>
                            })}

                            <p class="text-sm text-amber-300">
                                {tt_with(
                                    context,
                                    "{risk} RISK · {source} · Target / blast radius: {target}",
                                    &[
                                        ("risk", &tt(context, breakdown.risk_level)),
                                        ("source", &tt(context, &text(&current, "source"))),
                                        ("target", &tt(context, &breakdown.target)),
                                    ],
                                )}
                            </p>

                            <div class="bg-white/5 rounded-xl p-3.5 border border-white/10 space-y-3">
                                <h4 class="text-xs font-semibold uppercase tracking-wider text-slate-300">
                                    {tt(context, "Inbox.commandBreakdownHeading")}
                                </h4>
                                <dl class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                                    <div>
                                        <dt class="text-xs text-slate-400">{tt(context, "Inbox.operationLabel")}</dt>
                                        <dd class="font-mono text-slate-100 break-words">{breakdown.operation}</dd>
                                    </div>
                                    <div>
                                        <dt class="text-xs text-slate-400">{tt(context, "Inbox.targetLabel")}</dt>
                                        <dd class="font-mono text-slate-100 break-words">{tt(context, &breakdown.target)}</dd>
                                    </div>
                                    <div>
                                        <dt class="text-xs text-slate-400">{tt(context, "Inbox.managerLabel")}</dt>
                                        <dd class="font-mono text-slate-200 break-words">{manager_display}</dd>
                                    </div>
                                    <div>
                                        <dt class="text-xs text-slate-400">{tt(context, "Inbox.riskLabel")}</dt>
                                        <dd class="text-slate-200 break-words">{tt(context, breakdown.risk_level)}</dd>
                                    </div>
                                </dl>
                            </div>

                            {(!breakdown.parameters.is_empty()).then(|| view! {
                                <div class="bg-white/5 rounded-xl p-3.5 border border-white/10 space-y-2.5">
                                    <h4 class="text-xs font-semibold uppercase tracking-wider text-slate-300">
                                        {tt(context, "Inbox.parametersHeading")}
                                    </h4>
                                    <dl class="divide-y divide-white/10 text-sm">
                                        {breakdown
                                            .parameters
                                            .into_iter()
                                            .map(|(key, val)| {
                                                view! {
                                                    <div class="py-2 flex flex-col sm:flex-row sm:items-baseline sm:justify-between gap-1 sm:gap-4 min-w-0">
                                                        <dt class="font-mono text-xs text-slate-400 shrink-0">{key}</dt>
                                                        <dd class="font-mono text-xs text-slate-100 break-all">{val}</dd>
                                                    </div>
                                                }
                                            })
                                            .collect_view()}
                                    </dl>
                                </div>
                            })}

                            <dl class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                                <div>
                                    <dt class="text-slate-400">{tt(context, "Status")}</dt>
                                    <dd class="break-words">{tt(context, &status_str)}</dd>
                                </div>
                                <div>
                                    <dt class="text-slate-400">{tt(context, "Source")}</dt>
                                    <dd class="break-words">{tt(context, &text(&current, "source"))}</dd>
                                </div>
                                <div>
                                    <dt class="text-slate-400">{tt(context, "Created at")}</dt>
                                    <dd class="break-words">{text(&current, "created_at")}</dd>
                                </div>
                                <div>
                                    <dt class="text-slate-400">{tt(context, "Resolved by")}</dt>
                                    <dd class="break-words">
                                        {if resolved_by.trim().is_empty() {
                                            tt(context, "Inbox.unresolved")
                                        } else {
                                            resolved_by
                                        }}
                                    </dd>
                                </div>
                                {(!resolved_at.trim().is_empty()).then(|| view! {
                                    <div>
                                        <dt class="text-slate-400">{tt(context, "Resolved at")}</dt>
                                        <dd class="break-words">{resolved_at}</dd>
                                    </div>
                                })}
                                {(!job_unit.trim().is_empty()).then(|| view! {
                                    <div class="sm:col-span-2">
                                        <dt class="text-slate-400">{tt(context, "Inbox.receiptLabel")}</dt>
                                        <dd class="font-mono text-xs text-indigo-200 break-all">{job_unit}</dd>
                                    </div>
                                })}
                            </dl>

                            {(!reason_str.trim().is_empty()).then(|| view! {
                                <div class="bg-white/5 rounded-xl p-3.5 border border-white/10">
                                    <h4 class="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                                        {tt(context, "Reason")}
                                    </h4>
                                    <p class="text-sm text-slate-200 break-words">{reason_str}</p>
                                </div>
                            })}

                            {(!exec_log.trim().is_empty()).then(|| view! {
                                <div class="bg-slate-950 rounded-xl p-3.5 border border-white/10 space-y-1.5">
                                    <h4 class="text-xs font-semibold uppercase tracking-wider text-slate-400">
                                        {tt(context, "Inbox.executionLogHeading")}
                                    </h4>
                                    <pre class="text-xs font-mono text-slate-200 whitespace-pre-wrap break-all max-h-48 overflow-auto">
                                        {exec_log}
                                    </pre>
                                </div>
                            })}
                        </div>
                    }
                }}
                <details>
                    <summary class="cursor-pointer font-semibold text-sm text-slate-300">
                        {move || tt(context, "Full payload and command parameters")}
                    </summary>
                    <pre class="bg-slate-950 rounded-xl p-3 mt-2 text-xs whitespace-pre-wrap break-all max-h-80 overflow-auto">
                        {move || serde_json::to_string_pretty(&action.get()).unwrap_or_default()}
                    </pre>
                </details>
                <Show when=move || action.with(|a| a["status"] == "pending")>
                    <label class="block text-sm space-y-2">
                        {move || tt(context, "Operator reason note (local draft)")}
                        <textarea
                            rows="3"
                            maxlength="2000"
                            class="glass-input p-3 w-full"
                            prop:value=move || {
                                draft
                                    .with(|d| {
                                        d.value().map(|v| text(&v, "reason")).unwrap_or_default()
                                    })
                            }
                            on:input=move |e| {
                                let value = event_target_value(&e);
                                draft
                                    .update(|d| {
                                        let _ = d.edit("reason", json!(value));
                                    });
                            }
                        ></textarea>
                    </label>
                    <p class="text-xs text-slate-400">
                        {move || tt(
                            context,
                            "The current decision API records the operator and timestamp, but does not persist reason notes.",
                        )}
                    </p>
                    <div class="flex flex-wrap gap-3">
                        <button
                            class="glass-button-primary px-4 py-2"
                            disabled=move || {
                                busy.get()
                                    || loading.get()
                                    || error.with(Option::is_some)
                                    || !context.can_write_area(crate::state::PeerArea::Services)
                            }
                            title=move || {
                                context
                                    .area_block_reason(crate::state::PeerArea::Services, true)
                                    .unwrap_or_default()
                            }
                            on:click=move |_| request.run("approve".into())
                        >
                            {move || {
                                if action.with(|a| analyze_action(a).core_impact) {
                                    tt(context, "Inbox.approveQueueRestart")
                                } else {
                                    tt(context, "Approve & Execute")
                                }
                            }}
                        </button>
                        <button
                            class="glass-button px-4 py-2 text-rose-300"
                            disabled=move || {
                                busy.get()
                                    || loading.get()
                                    || error.with(Option::is_some)
                                    || !context.can_write_area(crate::state::PeerArea::Services)
                            }
                            title=move || {
                                context
                                    .area_block_reason(crate::state::PeerArea::Services, true)
                                    .unwrap_or_default()
                            }
                            on:click=move |_| request.run("reject".into())
                        >
                            {move || tt(context, "Reject")}
                        </button>
                    </div>
                </Show>
                {move || {
                    outcome
                        .get()
                        .map(|message| {
                            view! {
                                <p role="status" class="text-sm">
                                    {move || tt(context, &message)}
                                </p>
                            }
                        })
                }}
            </div>
        </Modal>
        {move || {
            view! {
                <ConfirmDialog
                    open=confirm
                    title=if decision.get() == "approve" {
                        "Approve and execute high-risk action?"
                    } else {
                        "Reject high-risk action?"
                    }
                    message=Signal::derive(move || tt_with(context, "{verb} action #{id}: {action}. Target / blast radius: {target}. Confirm after reviewing the full command and parameters.", &[("verb", &(tt(context, &(decision.get()).to_string())).to_string()), ("id", &(text(&action.get(), "id")).to_string()), ("action", &(tt(context, &(text(&action.get(), "action")).to_string())).to_string()), ("target", &tt(context, &target_summary(&action.get())))]))
                    busy=Signal::derive(move || busy.get())
                    on_confirm=execute
                />
            }
        }}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_risk_and_tones_support_canonical_and_legacy_classifications() {
        assert_eq!(
            risk(&json!({"risk_level":"CRITICAL","classification":"low"})),
            "CRITICAL"
        );
        assert_eq!(risk(&json!({"riskLevel":"high"})), "HIGH");
        assert_eq!(risk(&json!({"classification":"safe"})), "LOW");
        assert_eq!(risk(&json!({"risk_level":"unknown"})), "MEDIUM");
        assert_eq!(risk(&Value::Null), "MEDIUM");

        assert_eq!(risk_tone("LOW"), "success");
        assert_eq!(risk_tone("MEDIUM"), "warning");
        assert_eq!(risk_tone("HIGH"), "danger");
        assert_eq!(risk_tone("CRITICAL"), "danger");

        assert_eq!(status_tone("executed"), "success");
        assert_eq!(status_tone("approved"), "indigo");
        assert_eq!(status_tone("queued"), "indigo");
        assert_eq!(status_tone("unavailable"), "warning");
        assert_eq!(status_tone("pending"), "warning");
        assert_eq!(status_tone("rejected"), "danger");
        assert_eq!(status_tone("failed"), "danger");
    }

    #[test]
    fn inbox_history_filter_includes_queued_and_unavailable_deferred_restarts() {
        for status in ["approved", "queued", "executed", "failed", "unavailable"] {
            assert!(
                matches_inbox_filter("approved", status),
                "approved history should include {status}"
            );
        }
        assert!(!matches_inbox_filter("approved", "pending"));
        assert!(!matches_inbox_filter("approved", "rejected"));
        assert!(matches_inbox_filter("pending", "pending"));
        assert!(!matches_inbox_filter("pending", "queued"));
        assert!(matches_inbox_filter("rejected", "rejected"));
        assert!(matches_inbox_filter("all", "queued"));
        assert!(matches_inbox_filter("all", "unavailable"));
    }

    #[test]
    fn deferred_restart_decisions_report_the_server_state() {
        let valid_unit = "aetherflow-self-update-restart-aetherflow-api-0123456789abcdef.service";

        // Queued deferred core restart with valid receipt never claims executed.
        let queued_action = json!({
            "id": 41,
            "action": "restart_service:aetherflow-api:systemd",
            "status": "queued",
            "job_unit": valid_unit
        });
        assert_eq!(
            classify_approval_decision(
                "approve",
                &queued_action,
                &json!({"status": "queued", "job_unit": valid_unit, "action": queued_action})
            ),
            ApprovalFeedbackKind::Queued {
                job_unit: valid_unit.into(),
            }
        );

        // Queued response missing or invalid receipt identity flags missing receipt.
        let missing_receipt = json!({
            "id": 41,
            "action": "restart_service:aetherflow-api:systemd",
            "status": "queued"
        });
        assert_eq!(
            classify_approval_decision("approve", &missing_receipt, &json!({"status": "queued"})),
            ApprovalFeedbackKind::QueuedMissingReceipt
        );

        // Unavailable outcome never claims executed.
        let unavail = json!({
            "id": 41,
            "action": "restart_service:aetherflow-api:systemd",
            "status": "unavailable",
            "job_unit": valid_unit
        });
        assert_eq!(
            classify_approval_decision("approve", &unavail, &json!({})),
            ApprovalFeedbackKind::Unavailable
        );

        // Executable gate stuck in `approved` without receipt warns unconfirmed.
        let interrupted = json!({
            "id": 41,
            "action": "restart_service:aetherflow-api:systemd",
            "status": "approved"
        });
        assert_eq!(
            classify_approval_decision("approve", &interrupted, &json!({})),
            ApprovalFeedbackKind::ApprovedUnconfirmed
        );

        // Non-executable subsystem proposal keeps subsystem ownership message.
        let subsystem = json!({
            "id": 42,
            "action": "Apply egress bandwidth throttle",
            "status": "approved"
        });
        assert_eq!(
            classify_approval_decision("approve", &subsystem, &json!({})),
            ApprovalFeedbackKind::ApprovedSubsystem
        );

        // Synchronous action confirmed executed stays executed.
        let sync_done = json!({
            "id": 43,
            "action": "restart_service:sonarr:systemd",
            "status": "executed"
        });
        assert_eq!(
            classify_approval_decision("approve", &sync_done, &json!({"status": "executed"})),
            ApprovalFeedbackKind::Executed
        );

        // Failed and rejected actions classify accurately.
        assert_eq!(
            classify_approval_decision(
                "approve",
                &json!({"id": 44, "status": "failed", "execution_log": "unit failed"}),
                &json!({})
            ),
            ApprovalFeedbackKind::Failed("unit failed".into())
        );
        assert_eq!(
            classify_approval_decision(
                "reject",
                &json!({"id": 45, "status": "rejected"}),
                &json!({})
            ),
            ApprovalFeedbackKind::Rejected
        );

        // Envelope key `job_unit` is excluded from generic extracted parameters.
        let extracted = extract_action_parameters(&queued_action);
        assert!(!extracted.iter().any(|(k, _)| k == "job_unit"));
    }

    #[test]
    fn approval_scope_prefers_explicit_targets_and_parses_service_gate_managers() {
        assert_eq!(
            target_summary(&json!({"target":"sonarr","action":"restart:radarr"})),
            "sonarr"
        );
        assert_eq!(
            target_summary(&json!({"parameters":{"service":"jellyfin"}})),
            "jellyfin"
        );
        assert_eq!(
            target_summary(&json!({"payload":{"targets":["sonarr","radarr"]}})),
            r#"["sonarr","radarr"]"#
        );
        assert_eq!(
            target_summary(&json!({"action":"systemctl restart jellyfin.service"})),
            "jellyfin.service"
        );
        assert_eq!(
            target_summary(&json!({"action":"restart_service:jellyfin:systemd"})),
            "jellyfin"
        );
        assert_eq!(
            target_summary(&json!({"action":"restart: radarr"})),
            "radarr"
        );
        assert!(target_summary(&json!({"action":"unstructured"}))
            .contains("inspect it before approval"));
    }

    #[test]
    fn analyze_action_extracts_structured_parameters_gate_manager_and_core_impact() {
        let core = analyze_action(&json!({
            "id": 9,
            "action": "restart_service:aetherflow-api:systemd",
            "classification": "critical",
            "source": "FlowAI",
            "status": "pending",
            "reason": "Recycle API worker"
        }));
        assert_eq!(core.risk_level, "CRITICAL");
        assert_eq!(core.operation, "restart");
        assert_eq!(core.target, "aetherflow-api");
        assert_eq!(core.manager.as_deref(), Some("systemd"));
        assert!(core.executable_gate);
        assert!(core.core_impact);
        assert_eq!(
            core.parameters,
            vec![
                ("manager".into(), "systemd".into()),
                ("operation".into(), "restart".into()),
                ("service".into(), "aetherflow-api".into()),
            ]
        );

        let rich = analyze_action(&json!({
            "id": 12,
            "action": "Apply bandwidth throttle",
            "classification": "warn",
            "source": "SecurityGateway",
            "status": "pending",
            "parameters": {
                "interface": "eth0",
                "rate_mbps": 250,
                "targets": ["198.51.100.82", "198.51.100.99"]
            },
            "payload": {
                "burst_kb": 64
            },
            "timeout_secs": 30
        }));
        assert_eq!(rich.risk_level, "MEDIUM");
        assert!(!rich.executable_gate);
        assert!(!rich.core_impact);
        assert_eq!(
            rich.parameters,
            vec![
                ("burst_kb".into(), "64".into()),
                ("interface".into(), "eth0".into()),
                ("rate_mbps".into(), "250".into()),
                ("targets".into(), "198.51.100.82, 198.51.100.99".into()),
                ("timeout_secs".into(), "30".into()),
            ]
        );
    }
}
