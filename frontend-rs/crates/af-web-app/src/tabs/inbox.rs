//! Explicit human decisions; the backend owns execution and audit timestamps.
use super::contracts::{use_api_typed, PendingCount};
use crate::state::{app, use_api};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{Badge, ConfirmDialog, EmptyState, Modal, ObsCard, TabPanel, TabsBar};
use af_web_core::{api::ApiClient, draft::FormDraft};
use af_web_ui::SkeletonBox;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

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
    if let Some((_, target)) = action.action.split_once(':') {
        return target.trim().into();
    }
    let parts = action.action.split_whitespace().collect::<Vec<_>>();
    if parts.len() == 2 || (parts.len() == 3 && parts[0] == "systemctl") {
        return parts.last().unwrap_or(&"").to_string();
    }
    "Scope is defined by the complete action payload below; inspect it before approval.".into()
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
    let resource = use_api(Signal::derive(move || {
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
    }));
    let pending = use_api_typed::<PendingCount>(Signal::derive(|| {
        "/api/v1/admin/actions/pending?status=pending&limit=1".to_string()
    }));
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
    Effect::new(move |_| {
        if let Some(total) = pending.data.get().reported_total() {
            context.pending.set(total as usize);
        }
    });
    let interval = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        15_000,
        move || {
            if !resource.loading.get_untracked() {
                resource.refresh();
            }
            if !pending.loading.get_untracked() {
                pending.refresh();
            }
        },
    )));
    on_cleanup(move || interval.set_value(None));
    let rows = Memo::new(move |_| {
        let filter = filter.get();
        super::contracts::grid_rows::<super::contracts::ActionApprovalRequest>(&resource.data.get())
            .into_iter()
            .filter(|a| match filter.as_str() {
                "pending" => a["status"] == "pending",
                "approved" => matches!(
                    a["status"].as_str(),
                    Some("approved" | "executed" | "failed")
                ),
                "rejected" => a["status"] == "rejected",
                _ => true,
            })
            .collect::<Vec<_>>()
    });
    let inspect = Callback::new(move |action: Value| {
        let Some(id) = action["id"].as_i64() else {
            return;
        };
        selected.set(action);
        open.set(true);
        detail_loading.set(true);
        detail_error.set(None);
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        spawn_local(async move {
            let result = ApiClient.get(&format!("/api/v1/admin/actions/{id}")).await;
            if generation.try_get_untracked() != Some(ticket) {
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
                Err(error) => detail_error.set(Some(error.message)),
            }
            detail_loading.set(false);
        });
    });
    let resolved = Callback::new(move |action: Value| {
        resource.data.update(|data| {
            if let Some(rows) = data["actions"].as_array_mut() {
                if let Some(row) = rows.iter_mut().find(|r| r["id"] == action["id"]) {
                    *row = action;
                }
            }
        });
        context.pending.update(|n| *n = n.saturating_sub(1));
        resource.refresh();
        pending.refresh();
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
                    disabled=move || resource.loading.get()
                    on:click=move |_| {
                        resource.refresh();
                        pending.refresh();
                    }
                    aria-label=move || tt(context, "Refresh")
                >
                    {move || tt(context, "Common.refresh")}
                </button>
            </div>
            <p role="status" class="text-sm text-amber-300">
                {move || tt_with(context, "Inbox.awaitingApprovalCount", &[("count", &context.pending.get().to_string())])}
            </p>
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
                                let review = action.clone();
                                let source_action = action.clone();
                                view! {
                                    <ObsCard>
                                        <div class="flex flex-wrap items-start justify-between gap-4">
                                            <div class="min-w-0 space-y-2">
                                                <h3 class="font-semibold break-words">
                                                    {text(&action, "action")}
                                                </h3>
                                                <div class="flex flex-wrap gap-2 items-center text-xs">
                                                    <Badge
                                                        label=classification
                                                        tone=if matches!(classification, "HIGH" | "CRITICAL") {
                                                            "danger"
                                                        } else {
                                                            "warning"
                                                        }
                                                    />
                                                    <Badge label=text(&action, "status") />
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
                                            </div>
                                            <button
                                                class="glass-button-primary px-4 py-2"
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
            />
        </section>
    }
}

#[component]
pub fn ActionDetailModal(
    open: RwSignal<bool>,
    action: RwSignal<Value>,
    loading: RwSignal<bool>,
    error: RwSignal<Option<String>>,
    on_resolved: Callback<Value>,
) -> impl IntoView {
    let context = app();
    let draft = RwSignal::new(FormDraft::new(json!({"reason":""})));
    let draft_id = RwSignal::new(Value::Null);
    let busy = RwSignal::new(false);
    let confirm = RwSignal::new(false);
    let decision = RwSignal::new("approve".to_string());
    let outcome = RwSignal::new(None::<String>);
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
            || !context.is_admin()
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
        busy.set(true);
        outcome.set(None);
        spawn_local(async move {
            let result = ApiClient
                .post(&format!("/api/v1/admin/actions/{id}/{verb}"), None)
                .await;
            if busy.try_get_untracked().is_none() {
                return;
            }
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
                        let failed = updated["status"] == "failed";
                        let message = if failed {
                            tt_with(
                                context,
                                "Execution failed: {error}",
                                &[("error", &(text(&updated, "execution_log")).to_string())],
                            )
                        } else if verb == "reject" {
                            tt(context, "Action rejected.")
                        } else if updated["status"] == "executed" {
                            tt(context, "Action approved and executed.")
                        } else {
                            tt(
                                context,
                                "Action approved; execution is owned by the originating subsystem.",
                            )
                        };
                        if action.with_untracked(|a| a["id"].as_i64() == Some(id)) {
                            outcome.set(Some(message.clone()));
                        }
                        context.toast(tt(context, &message), failed);
                    }
                }
                Err(error) => {
                    if action.with_untracked(|a| a["id"].as_i64() == Some(id)) {
                        outcome.set(Some(error.message.clone()));
                    }
                    context.toast(tt(context, &error.message), true);
                }
            }
            confirm.set(false);
            busy.set(false);
        });
    });
    let request = Callback::new(move |verb: String| {
        if busy.get_untracked() || loading.get_untracked() || error.with_untracked(Option::is_some)
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
                <p class="text-sm text-amber-300">
                    {move || {
                        tt_with(context, "{risk} RISK · {source} · Target / blast radius: {target}", &[("risk", &(tt(context, risk(&action.get()))).to_string()), ("source", &(tt(context, &(text(&action.get(), "source")).to_string())).to_string()), ("target", &tt(context, &target_summary(&action.get())))])
                    }}
                </p>
                <dl class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                    {[
                        ("status", "Status"),
                        ("source", "Source"),
                        ("reason", "Reason"),
                        ("created_at", "Created at"),
                        ("resolved_at", "Resolved at"),
                        ("resolved_by", "Resolved by"),
                        ("executed_at", "Executed at"),
                    ]
                        .into_iter()
                        .map(|(key, label)| {
                            view! {
                                <div>
                                    <dt class="text-slate-400">{move || tt(context, label)}</dt>
                                    <dd class="break-words">{move || tt(context, &text(&action.get(), key))}</dd>
                                </div>
                            }
                        })
                        .collect_view()}
                </dl>
                <details open>
                    <summary class="cursor-pointer font-semibold">
                        {move || tt(context, "Full payload and command parameters")}
                    </summary>
                    <pre class="bg-slate-950 rounded-xl p-3 text-xs whitespace-pre-wrap break-all max-h-80 overflow-auto">
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
                                busy.get() || loading.get() || error.with(Option::is_some)
                            }
                            on:click=move |_| request.run("approve".into())
                        >
                            {move || tt(context, "Approve & Execute")}
                        </button>
                        <button
                            class="glass-button px-4 py-2 text-rose-300"
                            disabled=move || {
                                busy.get() || loading.get() || error.with(Option::is_some)
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
    fn approval_risk_supports_canonical_and_legacy_classifications() {
        assert_eq!(
            risk(&json!({"risk_level":"CRITICAL","classification":"low"})),
            "CRITICAL"
        );
        assert_eq!(risk(&json!({"riskLevel":"high"})), "HIGH");
        assert_eq!(risk(&json!({"classification":"safe"})), "LOW");
        assert_eq!(risk(&json!({"risk_level":"unknown"})), "MEDIUM");
        assert_eq!(risk(&Value::Null), "MEDIUM");
    }

    #[test]
    fn approval_scope_prefers_explicit_targets_and_preserves_multi_target_context() {
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
            target_summary(&json!({"action":"restart: radarr"})),
            "radarr"
        );
        assert!(target_summary(&json!({"action":"unstructured"}))
            .contains("inspect it before approval"));
    }
}
