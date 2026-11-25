use super::settings::{download_text, poll_resource_when, text, ResourceFeedback};
use crate::state::{
    app, owned_resource_reads, run_resource_read, use_api_when, PeerArea, ResourceReads,
};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{DataGrid, Drawer, EmptyState, ObsCard, SearchInput};
use crate::tabs::services::ServiceLogsModal;
use af_web_core::api::ApiClient;
use af_web_core::worker::{execute_worker_request, WorkerRequest, WorkerResponse};
use af_web_ui::{use_worker_rows, GridColumn};
use leptos::prelude::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use wasm_bindgen_futures::spawn_local;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AuditKpiCounts {
    pub total: u64,
    pub operator_approvals: usize,
    pub ai_proposed: usize,
    pub system_and_auth: usize,
}

pub(crate) fn audit_kpi_counts(total: u64, rows: &[Value]) -> AuditKpiCounts {
    let mut counts = AuditKpiCounts {
        total,
        ..Default::default()
    };
    for row in rows {
        let action = text(row, "action");
        if action.starts_with("action_") {
            counts.operator_approvals += 1;
        }
        if action.contains("ai_") {
            counts.ai_proposed += 1;
        }
        if action.contains("service_") || action.contains("system") || action.contains("user_") {
            counts.system_and_auth += 1;
        }
    }
    counts
}

fn event_time(value: &Value) -> f64 {
    let timestamp = super::contracts::decode::<super::contracts::AuditLog>(value).created_at;
    let timestamp = if timestamp.contains('T') {
        timestamp
    } else {
        format!("{}Z", timestamp.replace(' ', "T"))
    };
    js_sys::Date::parse(&timestamp)
}
fn in_range(value: &Value, start: &str, end: &str) -> bool {
    let timestamp = event_time(value);
    if start.is_empty() && end.is_empty() {
        return true;
    }
    timestamp.is_finite()
        && (start.is_empty() || timestamp >= js_sys::Date::parse(start))
        && (end.is_empty() || timestamp <= js_sys::Date::parse(end))
}
fn export_request(rows: &[Value], format: &str) -> WorkerRequest {
    WorkerRequest::BuildExportPayload {
        rows: rows
            .iter()
            .filter_map(|row| row.as_object())
            .map(|row| {
                row.iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<BTreeMap<String, Value>>()
            })
            .collect(),
        format: format.to_owned(),
    }
}
fn audit_path(page: usize, actor: &str, action: &str) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("limit", "200")
        .append_pair("offset", &(page * 200).to_string());
    for (key, value) in [("username", actor), ("action", action)] {
        if !value.trim().is_empty() {
            query.append_pair(key, value);
        }
    }
    format!("/api/v1/admin/audit-log?{}", query.finish())
}

#[component]
pub fn AuditTab() -> impl IntoView {
    let context = app();
    view! {
        <Show
            when=move || context.is_admin()
            fallback=move || {
                view! {
                    <EmptyState title="Common.adminRequired" />
                }
            }
        >
            <AuditAdminContent />
        </Show>
    }
}

#[component]
fn AuditAdminContent() -> impl IntoView {
    let context = app();
    let page = RwSignal::new(0usize);
    let actor = RwSignal::new(String::new());
    let action = RwSignal::new(String::new());
    let category = RwSignal::new(String::new());
    let severity = RwSignal::new(String::new());
    let start = RwSignal::new(String::new());
    let end = RwSignal::new(String::new());
    let query = RwSignal::new(String::new());
    let can_read_settings = Signal::derive(move || context.can_read_area(PeerArea::Settings));
    let path = Signal::derive(move || audit_path(page.get(), &actor.get(), &action.get()));
    let audit = use_api_when(can_read_settings, path);
    poll_resource_when(audit, 30_000, move || {
        context.can_read_area_untracked(PeerArea::Settings)
    });
    let selected = RwSignal::new(Value::Null);
    let drawer = RwSignal::new(false);
    let detail_action = RwSignal::new(None::<Value>);
    let detail_loading = RwSignal::new(false);
    let detail_error = RwSignal::new(None::<String>);
    let detail_ticket = RwSignal::new(0u64);
    let detail_reads = owned_resource_reads();
    let log_service = RwSignal::new(None::<Value>);
    let log_open = RwSignal::new(false);
    let export_busy = RwSignal::new(false);
    let last_epochs = StoredValue::new((
        context.session_epoch.get_untracked(),
        context.server_epoch.get_untracked(),
        context.area_revocation_epoch_untracked(PeerArea::Settings),
    ));
    Effect::new(move |_| {
        let next = (
            context.session_epoch.get(),
            context.server_epoch.get(),
            context.area_revocation_epoch(PeerArea::Settings),
        );
        if last_epochs.get_value() == next && can_read_settings.get() {
            return;
        }
        last_epochs.set_value(next);
        detail_reads.with_value(ResourceReads::cancel);
        detail_ticket.update(|n| *n = n.wrapping_add(1));
        drawer.set(false);
        selected.set(Value::Null);
        detail_action.set(None);
        detail_loading.set(false);
        detail_error.set(None);
        log_open.set(false);
        log_service.set(None);
        export_busy.set(false);
        page.set(0);
    });
    Effect::new(move |_| {
        context.area_revocation_epoch(PeerArea::Services);
        if !context.can_read_area(PeerArea::Services) {
            detail_reads.with_value(ResourceReads::cancel);
            detail_ticket.update(|n| *n = n.wrapping_add(1));
            detail_action.set(None);
            detail_loading.set(false);
            detail_error.set(None);
            log_open.set(false);
            log_service.set(None);
        }
    });
    let kpis = Signal::derive(move || {
        let total = audit.data.with(|v| v["total"].as_u64().unwrap_or(0));
        let current = super::contracts::grid_rows::<super::contracts::AuditLog>(&audit.data.get());
        audit_kpi_counts(total, &current)
    });
    let inspect_action = move |id: i64| {
        if !context.is_admin() || !context.can_read_area_untracked(PeerArea::Services) || id <= 0 {
            return;
        }
        let session_epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let services_grant = context.area_revocation_epoch_untracked(PeerArea::Services);
        detail_ticket.update(|n| *n = n.wrapping_add(1));
        let ticket = detail_ticket.get_untracked();
        detail_loading.set(true);
        detail_error.set(None);
        detail_action.set(None);
        let Some(job) = detail_reads.try_update_value(ResourceReads::next) else {
            return;
        };
        spawn_local(async move {
            let Some(result) =
                run_resource_read(job, ApiClient.get(&format!("/api/v1/admin/actions/{id}"))).await
            else {
                return;
            };
            if detail_ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Services) != services_grant
                || !context.is_admin_untracked()
                || !context.can_read_area_untracked(PeerArea::Services)
            {
                return;
            }
            detail_loading.set(false);
            match result {
                Ok(value) => {
                    let action = if value["action"].is_object() {
                        value["action"].clone()
                    } else {
                        value
                    };
                    detail_action.set(Some(action));
                }
                Err(error)
                    if matches!(
                        error.code.as_deref(),
                        Some("SERVER_CHANGED" | "SESSION_CHANGED" | "ABORTED")
                    ) => {}
                Err(error) => detail_error.set(Some(error.message)),
            }
        });
    };
    Effect::new(move |_| {
        actor.track();
        action.track();
        page.set(0);
    });
    let candidates = Signal::derive(move || {
        let category = category.get();
        let severity = severity.get();
        let start = start.get();
        let end = end.get();
        super::contracts::grid_rows::<super::contracts::AuditLog>(&audit.data.get())
            .into_iter()
            .filter(|row| {
                (category.is_empty() || text(row, "target_type") == category)
                    && (severity.is_empty()
                        || text(row, "severity") == severity
                        || (severity == "unrecorded" && row["severity"].is_null()))
                    && in_range(row, &start, &end)
            })
            .collect::<Vec<_>>()
    });
    let filtered = use_worker_rows(
        candidates,
        query.into(),
        vec![
            "username".into(),
            "action".into(),
            "target_type".into(),
            "target_id".into(),
            "detail".into(),
            "ip_address".into(),
            "created_at".into(),
        ],
    );
    let export = move |format: &'static str| {
        if export_busy.get_untracked() {
            return;
        }
        let session_epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let request = export_request(&filtered.get_untracked(), format);
        export_busy.set(true);
        spawn_local(async move {
            let response = crate::state::worker_pool().execute(request.clone()).await;
            if export_busy.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
            {
                return;
            }
            // The same serializer also handles unavailable or failed workers.
            let response = if matches!(response, WorkerResponse::Export { .. }) {
                response
            } else {
                execute_worker_request(request)
            };
            let payload = match response {
                WorkerResponse::Export {
                    content,
                    mime,
                    extension,
                } => Ok((content, mime, extension)),
                WorkerResponse::Error { message } => Err(message),
                _ => Err("Unexpected audit export worker response".to_owned()),
            };
            if export_busy.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
            {
                return;
            }
            let result = payload.and_then(|(content, mime, extension)| {
                download_text(&content, &format!("aetherflow-audit.{extension}"), &mime)
            });
            export_busy.set(false);
            if let Err(error) = result {
                context.toast(tt(context, &error), true);
            }
        });
    };
    view! {
        <section class="space-y-6 py-5 min-w-0 max-w-full">
            <Show
                when=move || context.is_admin()
                fallback=move || {
                    view! {
                        <EmptyState title="Common.adminRequired" />
                    }
                }
            >
                <header class="af-canvas-section pb-4 space-y-2">
                    <h2 class="text-2xl font-semibold">
                        {move || tt(context, "Tabs.auditHeading")}
                    </h2>
                    <p class="text-sm text-slate-400">
                        {move || tt(
                            context,
                            "Operator actions are read-only. Actor and action filters search the server; category, severity, time, and worker search narrow the current page. Exports contain the filtered page.",
                        )}
                    </p>
                </header>
                <section
                    aria-label=move || tt(context, "Audit summary")
                    class="af-hairline-grid grid sm:grid-cols-2 xl:grid-cols-4 min-w-0"
                >
                    <div class="p-4 min-w-0">
                        <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-400">
                            {move || tt(context, "Total Events")}
                        </h3>
                        <p class="text-2xl font-bold tabular-nums mt-1">{move || kpis.get().total}</p>
                        <p class="text-xs text-slate-400 mt-1">{move || tt(context, "Recorded audit entries")}</p>
                    </div>
                    <div class="p-4 min-w-0">
                        <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-400">
                            {move || tt(context, "Operator Approvals")}
                        </h3>
                        <p class="text-2xl font-bold tabular-nums text-emerald-400 mt-1">{move || kpis.get().operator_approvals}</p>
                        <p class="text-xs text-slate-400 mt-1">{move || tt(context, "Manual operator authorizations")}</p>
                    </div>
                    <div class="p-4 min-w-0">
                        <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-400">
                            {move || tt(context, "AI Proposed")}
                        </h3>
                        <p class="text-2xl font-bold tabular-nums text-indigo-300 mt-1">{move || kpis.get().ai_proposed}</p>
                        <p class="text-xs text-slate-400 mt-1">{move || tt(context, "FlowAI action proposals")}</p>
                    </div>
                    <div class="p-4 min-w-0">
                        <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-400">
                            {move || tt(context, "System & Auth")}
                        </h3>
                        <p class="text-2xl font-bold tabular-nums text-purple-300 mt-1">{move || kpis.get().system_and_auth}</p>
                        <p class="text-xs text-slate-400 mt-1">{move || tt(context, "Service, user, and system changes")}</p>
                    </div>
                </section>
                <ObsCard>
                    <div class="grid sm:grid-cols-2 xl:grid-cols-3 gap-4 mb-5">
                        <label class="text-sm space-y-2">
                            <span>{move || tt(context, "Actor")}</span>
                            <input
                                class="af-input w-full px-3 py-2"
                                type="search"
                                placeholder=move || tt(context, "Filter by actor")
                                prop:value=move || actor.get()
                                on:input=move |event| actor.set(event_target_value(&event))
                            />
                        </label>
                        <label class="text-sm space-y-2">
                            <span>{move || tt(context, "Action")}</span>
                            <input
                                class="af-input w-full px-3 py-2"
                                type="search"
                                placeholder=move || tt(context, "Filter by action")
                                prop:value=move || action.get()
                                on:input=move |event| action.set(event_target_value(&event))
                            />
                        </label>
                        <label class="text-sm space-y-2">
                            <span>{move || tt(context, "Category")}</span>
                            <select
                                class="af-input w-full px-3 py-2"
                                prop:value=move || category.get()
                                on:change=move |event| category.set(event_target_value(&event))
                            >
                                <option value="">{move || tt(context, "All categories")}</option>
                                {move || {
                                    let mut categories = super::contracts::grid_rows::<
                                        super::contracts::AuditLog,
                                    >(&audit.data.get())
                                        .iter()
                                        .map(|row| text(row, "target_type"))
                                        .filter(|s| !s.is_empty())
                                        .collect::<Vec<_>>();
                                    categories.sort();
                                    categories.dedup();
                                    categories
                                        .into_iter()
                                        .map(|category| {
                                            view! {
                                                <option value=category.clone()>{category.clone()}</option>
                                            }
                                        })
                                        .collect_view()
                                }}
                            </select>
                        </label>
                        <label class="text-sm space-y-2">
                            <span>{move || tt(context, "Severity")}</span>
                            <select
                                class="af-input w-full px-3 py-2"
                                prop:value=move || severity.get()
                                on:change=move |event| severity.set(event_target_value(&event))
                            >
                                <option value="">{move || tt(context, "All severities")}</option>
                                <option value="info">{move || tt(context, "Info")}</option>
                                <option value="warning">{move || tt(context, "Warning")}</option>
                                <option value="critical">{move || tt(context, "Critical")}</option>
                                <option value="unrecorded">
                                    {move || tt(context, "Not recorded")}
                                </option>
                            </select>
                        </label>
                        <label class="text-sm space-y-2">
                            <span>{move || tt(context, "From (local time)")}</span>
                            <input
                                type="datetime-local"
                                class="af-input w-full px-3 py-2"
                                placeholder=move || tt(context, "Start date and time")
                                prop:value=move || start.get()
                                on:change=move |event| start.set(event_target_value(&event))
                            />
                        </label>
                        <label class="text-sm space-y-2">
                            <span>{move || tt(context, "Until (local time)")}</span>
                            <input
                                type="datetime-local"
                                class="af-input w-full px-3 py-2"
                                placeholder=move || tt(context, "End date and time")
                                prop:value=move || end.get()
                                on:change=move |event| end.set(event_target_value(&event))
                            />
                        </label>
                    </div>
                    <SearchInput
                        value=query
                        placeholder="Worker search: actor, action, target, detail or IP"
                    />
                    <Show when=move || !can_read_settings.get()>
                        <p
                            role="status"
                            class="af-warning-banner text-sm mb-4"
                        >
                            {move || {
                                context
                                    .area_block_reason(PeerArea::Settings, false)
                                    .unwrap_or_default()
                            }}
                        </p>
                    </Show>
                    <div class="flex flex-wrap items-center gap-3 my-5">
                        <button
                            type="button"
                            class="af-btn px-4 py-2"
                            disabled=move || !can_read_settings.get()
                            title=move || {
                                context
                                    .area_block_reason(PeerArea::Settings, false)
                                    .unwrap_or_default()
                            }
                            on:click=move |_| {
                                if context.can_read_area_untracked(PeerArea::Settings) {
                                    audit.refresh();
                                }
                            }
                            aria-label=move || tt(context, "Refresh log")
                        >
                            {move || tt(context, "Common.refresh")}
                        </button>
                        <button
                            type="button"
                            class="af-btn px-4 py-2"
                            disabled=move || export_busy.get()
                            on:click=move |_| export("csv")
                        >
                            {move || tt(context, "Export CSV")}
                        </button>
                        <button
                            type="button"
                            class="af-btn px-4 py-2"
                            disabled=move || export_busy.get()
                            on:click=move |_| export("json")
                        >
                            {move || tt(context, "Export JSON")}
                        </button>
                    </div>
                    <ResourceFeedback resource=audit />
                    <DataGrid
                        searchable=false
                        label="Administrator audit events"
                        rows=Signal::derive(move || {
                            context.locale.get();
                            context.catalog_revision.get();
                            filtered.get().into_iter().map(|mut row| {
                                for field in ["action", "target_type", "severity"] {
                                    row[format!("{field}_label")] = serde_json::json!(tt(context, &text(&row, field)));
                                }
                                row
                            }).collect::<Vec<_>>()
                        })
                        columns=vec![
                            GridColumn::new("created_at", "Timestamp"),
                            GridColumn::new("username", "Actor"),
                            GridColumn::new("action_label", "Action"),
                            GridColumn::new("target_type_label", "Category"),
                            GridColumn::new("target_id", "Target"),
                            GridColumn::new("detail", "Detail"),
                            GridColumn::new("ip_address", "IP address"),
                        ]
                        on_select=Callback::new(move |row: Value| {
                            let mut raw = row;
                            if let Some(fields) = raw.as_object_mut() {
                                for key in ["action_label", "target_type_label", "severity_label"] {
                                    fields.remove(key);
                                }
                            }
                            let target_type = text(&raw, "target_type");
                            let target_id = text(&raw, "target_id");
                            detail_ticket.update(|n| *n = n.wrapping_add(1));
                            detail_loading.set(false);
                            detail_error.set(None);
                            detail_action.set(None);
                            selected.set(raw);
                            drawer.set(true);
                            if target_type == "pending_action" {
                                if let Ok(action_id) = target_id.trim().parse::<i64>() {
                                    inspect_action(action_id);
                                }
                            }
                        })
                    />
                    <div class="flex flex-wrap justify-between items-center gap-3 mt-5 text-sm">
                        <span class="text-slate-400">
                            {move || {
                                tt_with(
                                    context,
                                    "Audit.paginationSummary",
                                    &[
                                        ("page", &(page.get() + 1).to_string()),
                                        ("matching", &filtered.with(Vec::len).to_string()),
                                        ("total", &audit.data.with(|v| text(v, "total"))),
                                    ],
                                )
                            }}
                        </span>
                        <div class="flex gap-3">
                            <button
                                type="button"
                                class="af-btn px-4 py-2"
                                disabled=move || page.get() == 0 || audit.loading.get()
                                on:click=move |_| page.update(|p| *p = p.saturating_sub(1))
                            >
                                {move || tt(context, "Previous")}
                            </button>
                            <button
                                type="button"
                                class="af-btn px-4 py-2"
                                disabled=move || {
                                    audit.loading.get()
                                        || ((page.get() + 1) * 200)
                                            >= audit
                                                .data
                                                .with(|v| v["total"].as_u64().unwrap_or(0) as usize)
                                }
                                on:click=move |_| page.update(|p| *p += 1)
                            >
                                {move || tt(context, "Next")}
                            </button>
                        </div>
                    </div>
                </ObsCard>
            </Show>
            <Drawer open=drawer title="Audit event details">
                <div class="space-y-4">
                    <Show when=move || selected.with(|v| text(v, "target_type") == "service" && !text(v, "target_id").is_empty())>
                        <button
                            type="button"
                            class="af-btn-primary px-4 py-2 min-h-11"
                            disabled=move || !context.can_read_area(PeerArea::Services)
                            title=move || {
                                context
                                    .area_block_reason(PeerArea::Services, false)
                                    .unwrap_or_default()
                            }
                            on:click=move |_| {
                                let target = selected.with_untracked(|v| text(v, "target_id"));
                                if !target.is_empty()
                                    && context.is_admin()
                                    && context.can_read_area(PeerArea::Services)
                                {
                                    log_service.set(Some(json!({
                                        "id": target.clone(),
                                        "name": target.clone(),
                                        "process": target,
                                    })));
                                    drawer.set(false);
                                    log_open.set(true);
                                }
                            }
                        >
                            {move || tt(context, "Open service logs")}
                        </button>
                    </Show>
                    <Show when=move || {
                        selected.with(|v| text(v, "target_type") == "pending_action")
                            && !context.can_read_area(PeerArea::Services)
                    }>
                        <p role="status" class="text-xs text-amber-300">
                            {move || {
                                context
                                    .area_block_reason(PeerArea::Services, false)
                                    .unwrap_or_default()
                            }}
                        </p>
                    </Show>
                    <Show when=move || detail_loading.get()>
                        <p role="status" class="text-xs text-indigo-300">
                            {move || tt(context, "Loading action details…")}
                        </p>
                    </Show>
                    <Show when=move || detail_error.with(Option::is_some)>
                        <p role="alert" class="text-xs text-rose-300">
                            {move || detail_error.get().unwrap_or_default()}
                        </p>
                    </Show>
                    <Show when=move || detail_action.with(Option::is_some)>
                        <div class="space-y-2 border-t border-[var(--af-border-hairline)] pt-3">
                            <h3 class="text-sm font-semibold">
                                {move || tt(context, "Linked approval action")}
                            </h3>
                            <pre class="af-surface-inset p-3 text-xs whitespace-pre-wrap break-all max-h-60 overflow-auto">
                                {move || serde_json::to_string_pretty(&detail_action.get().unwrap_or(Value::Null)).unwrap_or_default()}
                            </pre>
                        </div>
                    </Show>
                    <p class="text-sm text-slate-400">
                        {move || tt(context, "Original immutable event payload")}
                    </p>
                    <pre class="af-surface-inset p-3 text-xs whitespace-pre-wrap break-all max-h-[55vh] overflow-auto">
                        {move || serde_json::to_string_pretty(&selected.get()).unwrap_or_default()}
                    </pre>
                </div>
            </Drawer>
            <Show when=move || {
                log_open.get()
                    && log_service.with(Option::is_some)
                    && context.is_admin()
                    && context.can_read_area(PeerArea::Services)
            }>
                <ServiceLogsModal open=log_open service=log_service />
            </Show>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audit_filters_reach_the_server_with_encoded_values_and_no_empty_filters() {
        assert_eq!(
            audit_path(0, "", " "),
            "/api/v1/admin/audit-log?limit=200&offset=0"
        );
        let path = audit_path(2, "opérateur & helper", "file/create?target=a+b");
        let parsed = url::Url::parse(&format!("https://example.com{path}")).unwrap();
        let query = parsed.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(query["offset"], "400");
        assert_eq!(query["username"], "opérateur & helper");
        assert_eq!(query["action"], "file/create?target=a+b");
        assert_eq!(query.len(), 4);
    }

    #[test]
    fn json_export_preserves_typed_fields_and_server_extensions() {
        let rows = vec![
            json!({"id": 7, "username": "operator", "read": false, "extra": {"receipt": "abc"}}),
        ];
        let response = execute_worker_request(export_request(&rows, "json"));
        let WorkerResponse::Export {
            content,
            mime,
            extension,
        } = response
        else {
            panic!("Expected an audit export payload");
        };
        assert_eq!(mime, "application/json");
        assert_eq!(extension, "json");
        assert_eq!(
            serde_json::from_str::<Value>(&content).unwrap(),
            json!(rows)
        );
    }

    #[test]
    fn csv_export_escapes_formulas_and_quoted_multiline_details() {
        let rows = vec![
            json!({"id": 7, "username": "=IMPORTDATA(\"host\")", "detail": "first,\n\"second\""}),
        ];
        let WorkerResponse::Export {
            content,
            mime,
            extension,
        } = execute_worker_request(export_request(&rows, "csv"))
        else {
            panic!("Expected an audit export payload");
        };
        assert_eq!(mime, "text/csv;charset=utf-8");
        assert_eq!(extension, "csv");
        assert!(content.contains("\"'=IMPORTDATA(\"\"host\"\")\""));
        assert!(content.contains("\"first,\n\"\"second\"\"\""));
    }

    #[test]
    fn kpi_counts_group_operator_ai_and_system_audit_entries() {
        let rows = vec![
            json!({"action": "action_approve"}),
            json!({"action": "action_reject"}),
            json!({"action": "ai_action_proposed"}),
            json!({"action": "service_restart"}),
            json!({"action": "user_role_change"}),
            json!({"action": "system_update"}),
        ];
        let kpis = audit_kpi_counts(42, &rows);
        assert_eq!(kpis.total, 42);
        assert_eq!(kpis.operator_approvals, 2);
        assert_eq!(kpis.ai_proposed, 1);
        assert_eq!(kpis.system_and_auth, 3);
    }
}
