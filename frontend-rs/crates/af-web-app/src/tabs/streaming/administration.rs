//! History policies, user bindings, and reviewed administration requests.
use super::common::*;
use super::types::*;
use super::{
    imports::HistoryEventImport, portability::HistoryPortability,
    reconciliation::HistoryReconciliation,
};
use crate::state::{app, use_api};
use crate::tabs::contracts;
use crate::tabs::l10n::{tt, Modal, ObsCard};
use af_web_core::api::ApiClient;
use af_web_core::draft::FormDraft;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;
#[component]
pub(super) fn HistoryAdministration(
    servers: Signal<Vec<ProviderStatus>>,
    on_changed: Callback<()>,
) -> impl IntoView {
    let context = app();
    let status = use_api(Signal::derive(|| {
        "/api/v1/admin/streaming/imports/status".to_string()
    }));
    let policies = use_api(Signal::derive(|| {
        "/api/v1/admin/streaming/policies".to_string()
    }));
    let links = use_api(Signal::derive(|| {
        "/api/v1/admin/streaming/user-links".to_string()
    }));
    let changed = Callback::new(move |(): ()| {
        status.refresh();
        policies.refresh();
        links.refresh();
        on_changed.run(());
    });
    let policy_body = Signal::derive(move || {
        let data = policies.data.get();
        if data.is_null() {
            Value::Null
        } else {
            let policy = contracts::decode::<TrackingPolicy>(&data);
            json!({"minimumWatchSecs":policy.minimum_watch_secs,"reconnectWindowSecs":policy.reconnect_window_secs,"excludedUsers":policy.excluded_users,"excludedLibraries":policy.excluded_libraries})
        }
    });
    view! {
        <ObsCard title="History administration">
            <div class="space-y-5">
                <p class="text-sm text-slate-400">
                    {move || tt(
                        context,
                        "Administrative imports preserve provenance and stable server/user identities. Review every mutation before applying it.",
                    )}
                </p>
                {move || {
                    status
                        .error
                        .get()
                        .map(|e| {
                            view! {
                                <p role="alert" class="text-rose-300">
                                    {move || tt(context, &e.message)}
                                </p>
                            }
                        })
                }}
                <details>
                    <summary class="cursor-pointer py-2 font-semibold">
                        {move || tt(context, "Jellystat / Tautulli / JSON event import")}
                    </summary>
                    <HistoryEventImport
                        servers
                        status=Signal::derive(move || status.data.get())
                        on_changed=changed
                    />
                </details>
                <details>
                    <summary class="cursor-pointer py-2 font-semibold">
                        {move || tt(context, "Tracking policy and exclusions")}
                    </summary>
                    {move || {
                        policies
                            .error
                            .get()
                            .map(|e| {
                                view! {
                                    <p role="alert" class="text-rose-300">
                                        {move || tt(context, &e.message)}
                                    </p>
                                }
                            })
                    }}
                    <JsonAdminEditor
                        title="Tracking policy"
                        endpoint="/api/v1/admin/streaming/policies"
                        method="PUT"
                        initial=policy_body
                        on_changed=changed
                    />
                    <p class="text-xs text-slate-400">
                        {move || tt(
                            context,
                            "Policy targets require provider, serverId, stable user/library id and name. Refreshes preserve unsaved edits.",
                        )}
                    </p>
                </details>
                <details>
                    <summary class="cursor-pointer py-2 font-semibold">
                        {move || tt(context, "Explicit provider user bindings")}
                    </summary>
                    {move || {
                        links
                            .error
                            .get()
                            .map(|e| {
                                view! {
                                    <p role="alert" class="text-rose-300">
                                        {move || tt(context, &e.message)}
                                    </p>
                                }
                            })
                    }}
                    <pre class="text-xs whitespace-pre-wrap break-all max-h-64 overflow-auto">
                        {move || {
                            serde_json::to_string_pretty(&contracts::decode::<UserBindings>(&links.data.get())).unwrap_or_default()
                        }}
                    </pre>
                    <p class="text-xs text-slate-400">
                        {move || tt(
                            context,
                            "Bindings require afUserId, provider, serverId and providerUserId. Display names are never used for identity matching.",
                        )}
                    </p>
                    <JsonAdminEditor
                        title="Add / update user binding"
                        endpoint="/api/v1/admin/streaming/user-links"
                        method="PUT"
                        initial=Signal::stored(Value::Null)
                        on_changed=changed
                    />
                    <JsonAdminEditor
                        title="Remove user binding"
                        endpoint="/api/v1/admin/streaming/user-links"
                        method="DELETE"
                        initial=Signal::stored(Value::Null)
                        on_changed=changed
                    />
                </details>
                <details>
                    <summary class="cursor-pointer py-2 font-semibold">
                        {move || tt(context, "Legacy history reconciliation")}
                    </summary>
                    <HistoryReconciliation on_changed=changed />
                </details>
                <details>
                    <summary class="cursor-pointer py-2 font-semibold">
                        {move || tt(context, "Portable archive export / restore")}
                    </summary>
                    <HistoryPortability on_changed=changed />
                </details>
            </div>
        </ObsCard>
    }
}

#[component]
fn JsonAdminEditor(
    title: &'static str,
    endpoint: &'static str,
    method: &'static str,
    initial: Signal<Value>,
    on_changed: Callback<()>,
) -> impl IntoView {
    let context = app();
    let draft = RwSignal::new(FormDraft::new(json!({"payload":""})));
    let prepared = RwSignal::new(Value::Null);
    let busy = RwSignal::new(false);
    let confirm = RwSignal::new(false);
    let result = RwSignal::new(None::<String>);
    Effect::new(move |_| {
        let value = initial.get();
        if !value.is_null() {
            draft.update(|d| {
                d.apply_server_refresh(
                    json!({"payload":serde_json::to_string_pretty(&value).unwrap_or_default()}),
                )
            });
        }
    });
    let review = Callback::new(move |(): ()| {
        if busy.get_untracked() {
            return;
        }
        let raw =
            draft.with_untracked(|d| d.value().map(|v| text(&v, "payload")).unwrap_or_default());
        match serde_json::from_str::<Value>(&raw) {
            Ok(value) if value.is_object() => {
                prepared.set(value);
                confirm.set(true);
                result.set(None);
            }
            _ => result.set(Some(
                "Enter a valid JSON request object before review.".into(),
            )),
        }
    });
    let execute = Callback::new(move |(): ()| {
        if busy.get_untracked() || !context.is_admin() || !prepared.with_untracked(Value::is_object)
        {
            return;
        }
        let body = prepared.get_untracked();
        busy.set(true);
        spawn_local(async move {
            let response = ApiClient.request(endpoint, method, Some(&body)).await;
            if busy.try_get_untracked().is_none() {
                return;
            }
            match response {
                Ok(data) => {
                    draft.update(|draft|draft.mark_saved(json!({"payload":serde_json::to_string_pretty(&body).unwrap_or_default()})));
                    result.set(Some(
                        serde_json::to_string_pretty(&data).unwrap_or_default(),
                    ));
                    on_changed.run(());
                    context.toast(tt(context, "History administration change saved."), false);
                }
                Err(e) => {
                    result.set(Some(e.message.clone()));
                    context.toast(tt(context, &e.message), true);
                }
            }
            busy.set(false);
            confirm.set(false);
        });
    });
    view! {
        <div class="space-y-3 pt-3">
            <h4 class="text-sm font-semibold">{move || tt(context, title)}</h4>
            <textarea
                rows="6"
                aria-label=move || tt(context, title)
                class="glass-input p-3 w-full text-xs font-mono"
                disabled=move || busy.get()
                prop:value=move || {
                    draft.with(|d| d.value().map(|v| text(&v, "payload")).unwrap_or_default())
                }
                on:input=move |e| {
                    draft
                        .update(|d| {
                            let _ = d.edit("payload", json!(event_target_value(&e)));
                        });
                    confirm.set(false);
                    prepared.set(Value::Null);
                }
            ></textarea>
            <button
                class="glass-button px-4 py-2"
                disabled=move || busy.get()
                on:click=move |_| review.run(())
            >
                {move || tt(context, "Review change")}
            </button>
            {move || {
                result
                    .get()
                    .map(|message| {
                        view! {
                            <pre
                                role="status"
                                class="text-xs whitespace-pre-wrap break-all max-h-48 overflow-auto"
                            >
                                {move || tt(context, &message)}
                            </pre>
                        }
                    })
            }}
            <Modal open=confirm title="Review exact administrative request">
                <div class="space-y-3">
                    <p class="text-sm">{format!("{method} {endpoint}")}</p>
                    <pre class="text-xs whitespace-pre-wrap break-all max-h-64 overflow-auto">
                        {move || serde_json::to_string_pretty(&prepared.get()).unwrap_or_default()}
                    </pre>
                    <button
                        class="glass-button-primary px-4 py-2"
                        disabled=move || busy.get()
                        on:click=move |_| execute.run(())
                    >
                        {move || tt(context, "Apply reviewed change")}
                    </button>
                </div>
            </Modal>
        </div>
    }
}
