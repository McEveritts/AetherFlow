//! History policies, user bindings, and reviewed administration requests.
use super::common::*;
use super::types::*;
use super::{
    imports::HistoryEventImport, portability::HistoryPortability,
    reconciliation::HistoryReconciliation,
};
use crate::state::{app, use_api_when, PeerArea};
use crate::tabs::contracts;
use crate::tabs::l10n::{tt, tt_with, Modal, ObsCard};
use crate::tabs::GrantInvalidationBoundary;
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
    let can_read_services = Signal::derive(move || context.can_read_area(PeerArea::Services));
    let can_read_settings = Signal::derive(move || context.can_read_area(PeerArea::Settings));
    let can_read_users = Signal::derive(move || context.can_read_area(PeerArea::Users));
    let status = use_api_when(
        can_read_services,
        Signal::derive(|| "/api/v1/admin/streaming/imports/status".to_string()),
    );
    let policies = use_api_when(
        can_read_settings,
        Signal::derive(|| "/api/v1/admin/streaming/policies".to_string()),
    );
    let links = use_api_when(
        can_read_users,
        Signal::derive(|| "/api/v1/admin/streaming/user-links".to_string()),
    );
    let changed = Callback::new(move |(): ()| {
        if context.can_read_area_untracked(PeerArea::Services) {
            status.refresh();
        }
        if context.can_read_area_untracked(PeerArea::Settings) {
            policies.refresh();
        }
        if context.can_read_area_untracked(PeerArea::Users) {
            links.refresh();
        }
        on_changed.run(());
    });
    let decoded_policy =
        Signal::derive(move || contracts::decode::<TrackingPolicy>(&policies.data.get()));
    let decoded_links =
        Signal::derive(move || contracts::decode::<UserBindings>(&links.data.get()));
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
                    <Show when=move || !can_read_services.get()>
                        <p role="status" class="text-xs text-amber-300 mt-2">
                            {move || {
                                context
                                    .area_block_reason(PeerArea::Services, false)
                                    .unwrap_or_default()
                            }}
                        </p>
                    </Show>
                    <GrantInvalidationBoundary areas=&[PeerArea::Services]>
                        <HistoryEventImport
                            servers
                            status=Signal::derive(move || status.data.get())
                            on_changed=changed
                        />
                    </GrantInvalidationBoundary>
                </details>
                <details>
                    <summary class="cursor-pointer py-2 font-semibold">
                        {move || tt(context, "Tracking policy and exclusions")}
                    </summary>
                    <Show when=move || !can_read_settings.get()>
                        <p role="status" class="text-xs text-amber-300 mt-2">
                            {move || {
                                context
                                    .area_block_reason(PeerArea::Settings, false)
                                    .unwrap_or_default()
                            }}
                        </p>
                    </Show>
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
                    <GrantInvalidationBoundary areas=&[PeerArea::Settings]>
                        <StructuredPolicyEditor policy=decoded_policy on_changed=changed />
                    </GrantInvalidationBoundary>
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
                    <Show when=move || !can_read_users.get()>
                        <p role="status" class="text-xs text-amber-300 mt-2">
                            {move || {
                                context
                                    .area_block_reason(PeerArea::Users, false)
                                    .unwrap_or_default()
                            }}
                        </p>
                    </Show>
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
                    <p class="text-xs text-slate-400">
                        {move || tt(
                            context,
                            "Bindings require afUserId, provider, serverId and providerUserId. Display names are never used for identity matching.",
                        )}
                    </p>
                    <GrantInvalidationBoundary areas=&[PeerArea::Users]>
                        <StructuredUserBindingsEditor links=decoded_links servers on_changed=changed />
                    </GrantInvalidationBoundary>
                </details>
                <details>
                    <summary class="cursor-pointer py-2 font-semibold">
                        {move || tt(context, "Legacy history reconciliation")}
                    </summary>
                    <GrantInvalidationBoundary areas=&[PeerArea::Services]>
                        <HistoryReconciliation on_changed=changed />
                    </GrantInvalidationBoundary>
                </details>
                <details>
                    <summary class="cursor-pointer py-2 font-semibold">
                        {move || tt(context, "Portable archive export / restore")}
                    </summary>
                    <GrantInvalidationBoundary areas=&[PeerArea::Settings]>
                        <HistoryPortability on_changed=changed />
                    </GrantInvalidationBoundary>
                </details>
            </div>
        </ObsCard>
    }
}

fn validate_policy_payload(
    minimum_watch_raw: &str,
    reconnect_window_raw: &str,
    excluded_users_raw: &str,
    excluded_libraries_raw: &str,
) -> Result<Value, String> {
    let minimum: i64 = minimum_watch_raw
        .trim()
        .parse()
        .map_err(|_| "minimumWatchSecs must be an integer between 0 and 86400.".to_string())?;
    let reconnect: i64 = reconnect_window_raw
        .trim()
        .parse()
        .map_err(|_| "reconnectWindowSecs must be an integer between 0 and 3600.".to_string())?;
    if !(0..=86400).contains(&minimum) {
        return Err("minimumWatchSecs must be an integer between 0 and 86400.".into());
    }
    if !(0..=3600).contains(&reconnect) {
        return Err("reconnectWindowSecs must be an integer between 0 and 3600.".into());
    }
    let parse_targets = |raw: &str, field: &str| -> Result<Vec<PolicyTarget>, String> {
        let trimmed = raw.trim();
        let list: Vec<PolicyTarget> = if trimmed.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(trimmed).map_err(|e| format!("{field}: {e}"))?
        };
        for target in &list {
            if !matches!(target.provider.as_str(), "jellyfin" | "emby" | "plex")
                || target.server_id.trim().is_empty()
                || target.id.trim().is_empty()
            {
                return Err(format!(
                    "{field} entries require provider (jellyfin/emby/plex), serverId, and stable id."
                ));
            }
        }
        Ok(list)
    };
    let excluded_users = parse_targets(excluded_users_raw, "excludedUsers")?;
    let excluded_libraries = parse_targets(excluded_libraries_raw, "excludedLibraries")?;
    Ok(json!({
        "minimumWatchSecs": minimum,
        "reconnectWindowSecs": reconnect,
        "excludedUsers": excluded_users,
        "excludedLibraries": excluded_libraries,
    }))
}

#[component]
fn StructuredPolicyEditor(
    policy: Signal<TrackingPolicy>,
    on_changed: Callback<()>,
) -> impl IntoView {
    let context = app();
    let draft = RwSignal::new(FormDraft::new(json!({
        "minimumWatchSecs": "0",
        "reconnectWindowSecs": "0",
        "excludedUsers": "[]",
        "excludedLibraries": "[]",
    })));
    let prepared = RwSignal::new(Value::Null);
    let confirm = RwSignal::new(false);
    let confirm_captured = crate::tabs::l10n::guard_modal_server_switch(confirm);
    let busy = RwSignal::new(false);
    let exec_ticket = RwSignal::new(0u64);
    let error_msg = RwSignal::new(None::<String>);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Settings);
        exec_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        busy.set(false);
        confirm.set(false);
        prepared.set(Value::Null);
        error_msg.set(None);
    });
    Effect::new(move |_| {
        if !context.can_write_area(PeerArea::Settings) {
            exec_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            busy.set(false);
            confirm.set(false);
        }
    });
    Effect::new(move |_| {
        let current = policy.get();
        draft.update(|d| {
            d.apply_server_refresh(json!({
                "minimumWatchSecs": current.minimum_watch_secs.to_string(),
                "reconnectWindowSecs": current.reconnect_window_secs.to_string(),
                "excludedUsers": serde_json::to_string_pretty(&current.excluded_users).unwrap_or_else(|_| "[]".into()),
                "excludedLibraries": serde_json::to_string_pretty(&current.excluded_libraries).unwrap_or_else(|_| "[]".into()),
            }));
        });
    });
    let review = move |_| {
        if busy.get_untracked() || !context.can_write_area(crate::state::PeerArea::Settings) {
            return;
        }
        let val = draft.with_untracked(|d| d.value()).unwrap_or_default();
        match validate_policy_payload(
            &text(&val, "minimumWatchSecs"),
            &text(&val, "reconnectWindowSecs"),
            &text(&val, "excludedUsers"),
            &text(&val, "excludedLibraries"),
        ) {
            Ok(body) => {
                prepared.set(body);
                confirm.set(true);
                error_msg.set(None);
            }
            Err(message) => error_msg.set(Some(message)),
        }
    };
    let execute = move |_| {
        if busy.get_untracked()
            || !context.is_admin()
            || !context.can_write_area(crate::state::PeerArea::Settings)
            || !prepared.with_untracked(Value::is_object)
        {
            return;
        }
        let server_epoch = context.server_epoch.get_untracked();
        let current_server = context.active_server_id.get_untracked();
        if let Some(captured) = confirm_captured.get_untracked() {
            if captured.server_epoch != server_epoch || captured.server_id != current_server {
                confirm.set(false);
                context.toast(tt(context, "PeerSwitch.staleConfirmBlocked"), true);
                return;
            }
        }
        let body = prepared.get_untracked();
        let session_epoch = context.session_epoch.get_untracked();
        let settings_grant = context.area_revocation_epoch_untracked(PeerArea::Settings);
        exec_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = exec_ticket.get_untracked();
        busy.set(true);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(busy, exec_ticket, ticket);
        spawn_local(async move {
            let response = ApiClient
                .request("/api/v1/admin/streaming/policies", "PUT", Some(&body))
                .await;
            if busy.try_get_untracked().is_none()
                || exec_ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Settings) != settings_grant
                || !context.can_write_area_untracked(PeerArea::Settings)
            {
                return;
            }
            match response {
                Ok(_) => {
                    draft.update(|d| {
                        d.mark_saved(json!({
                            "minimumWatchSecs": body["minimumWatchSecs"].to_string(),
                            "reconnectWindowSecs": body["reconnectWindowSecs"].to_string(),
                            "excludedUsers": serde_json::to_string_pretty(&body["excludedUsers"]).unwrap_or_else(|_| "[]".into()),
                            "excludedLibraries": serde_json::to_string_pretty(&body["excludedLibraries"]).unwrap_or_else(|_| "[]".into()),
                        }));
                    });
                    on_changed.run(());
                    context.toast(tt(context, "Tracking policy updated."), false);
                    error_msg.set(None);
                }
                Err(e) => {
                    error_msg.set(Some(e.message.clone()));
                    context.toast(tt(context, &e.message), true);
                }
            }
            busy_guard.release();
            confirm.set(false);
        });
    };
    view! {
        <div class="space-y-4 pt-3">
            <div class="grid sm:grid-cols-2 gap-3">
                <label class="text-xs text-slate-400 space-y-1">
                    <span class="block">{move || tt(context, "Minimum Watch (secs)")}</span>
                    <input
                        type="number"
                        min="0"
                        max="86400"
                        class="glass-input p-2 w-full"
                        disabled=move || busy.get()
                        prop:value=move || draft.with(|d| d.value().map(|v| text(&v, "minimumWatchSecs")).unwrap_or_default())
                        on:input=move |e| {
                            let val = event_target_value(&e);
                            draft.update(|d| { let _ = d.edit("minimumWatchSecs", json!(val)); });
                        }
                    />
                </label>
                <label class="text-xs text-slate-400 space-y-1">
                    <span class="block">{move || tt(context, "Reconnect Window (secs)")}</span>
                    <input
                        type="number"
                        min="0"
                        max="3600"
                        class="glass-input p-2 w-full"
                        disabled=move || busy.get()
                        prop:value=move || draft.with(|d| d.value().map(|v| text(&v, "reconnectWindowSecs")).unwrap_or_default())
                        on:input=move |e| {
                            let val = event_target_value(&e);
                            draft.update(|d| { let _ = d.edit("reconnectWindowSecs", json!(val)); });
                        }
                    />
                </label>
                <label class="text-xs text-slate-400 space-y-1">
                    <span class="block">{move || tt(context, "Excluded Users JSON")}</span>
                    <textarea
                        rows="4"
                        class="glass-input p-2 w-full text-xs font-mono"
                        disabled=move || busy.get()
                        prop:value=move || draft.with(|d| d.value().map(|v| text(&v, "excludedUsers")).unwrap_or_default())
                        on:input=move |e| {
                            let val = event_target_value(&e);
                            draft.update(|d| { let _ = d.edit("excludedUsers", json!(val)); });
                        }
                    ></textarea>
                </label>
                <label class="text-xs text-slate-400 space-y-1">
                    <span class="block">{move || tt(context, "Excluded Libraries JSON")}</span>
                    <textarea
                        rows="4"
                        class="glass-input p-2 w-full text-xs font-mono"
                        disabled=move || busy.get()
                        prop:value=move || draft.with(|d| d.value().map(|v| text(&v, "excludedLibraries")).unwrap_or_default())
                        on:input=move |e| {
                            let val = event_target_value(&e);
                            draft.update(|d| { let _ = d.edit("excludedLibraries", json!(val)); });
                        }
                    ></textarea>
                </label>
            </div>
            {move || {
                error_msg.get().map(|msg| view! {
                    <p role="alert" class="text-xs text-rose-300">{msg}</p>
                })
            }}
            <button
                type="button"
                class="glass-button px-4 py-2"
                disabled=move || {
                    busy.get() || !context.can_write_area(crate::state::PeerArea::Settings)
                }
                title=move || {
                    context
                        .area_block_reason(crate::state::PeerArea::Settings, true)
                        .unwrap_or_default()
                }
                on:click=review
            >
                {move || tt(context, "Save Tracking Policy")}
            </button>
            <Modal
                open=confirm
                title=Signal::derive(move || {
                    let server = confirm_captured
                        .get()
                        .and_then(|c| c.server_name)
                        .or_else(|| context.active_server_name());
                    crate::tabs::l10n::confirm_dialog_title(
                        context,
                        "Review exact administrative request",
                        server.as_deref(),
                    )
                })
            >
                <div class="space-y-3">
                    <p class="text-sm">{"PUT /api/v1/admin/streaming/policies"}</p>
                    <pre class="text-xs whitespace-pre-wrap break-all max-h-64 overflow-auto">
                        {move || serde_json::to_string_pretty(&prepared.get()).unwrap_or_default()}
                    </pre>
                    <button
                        type="button"
                        class="glass-button-primary px-4 py-2"
                        disabled=move || busy.get()
                        on:click=execute
                    >
                        {move || tt(context, "Apply reviewed change")}
                    </button>
                </div>
            </Modal>
        </div>
    }
}

fn validate_user_binding_input(
    af_user_id_raw: &str,
    provider: &str,
    server_id: &str,
    provider_user_id: &str,
) -> Result<Value, String> {
    let af_user_id: i64 = af_user_id_raw
        .trim()
        .parse()
        .map_err(|_| "afUserId must be a positive integer.".to_string())?;
    if af_user_id <= 0 {
        return Err("afUserId must be a positive integer.".into());
    }
    let clean_provider = provider.trim().to_ascii_lowercase();
    if !matches!(clean_provider.as_str(), "jellyfin" | "emby" | "plex") {
        return Err("provider must be jellyfin, emby, or plex.".into());
    }
    let clean_server = server_id.trim();
    let clean_remote = provider_user_id.trim();
    if clean_server.is_empty() || clean_remote.is_empty() {
        return Err("serverId and providerUserId are required.".into());
    }
    Ok(json!({
        "afUserId": af_user_id,
        "provider": clean_provider,
        "serverId": clean_server,
        "providerUserId": clean_remote,
    }))
}

#[component]
fn StructuredUserBindingsEditor(
    links: Signal<UserBindings>,
    servers: Signal<Vec<ProviderStatus>>,
    on_changed: Callback<()>,
) -> impl IntoView {
    let context = app();
    let af_user_id = RwSignal::new(String::new());
    let provider = RwSignal::new("jellyfin".to_string());
    let server_id = RwSignal::new(String::new());
    let provider_user_id = RwSignal::new(String::new());
    let pending_request = RwSignal::new(None::<(&'static str, Value)>);
    let confirm = RwSignal::new(false);
    let confirm_captured = crate::tabs::l10n::guard_modal_server_switch(confirm);
    let busy = RwSignal::new(false);
    let exec_ticket = RwSignal::new(0u64);
    let error_msg = RwSignal::new(None::<String>);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Users);
        exec_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        busy.set(false);
        confirm.set(false);
        pending_request.set(None);
        error_msg.set(None);
    });
    Effect::new(move |_| {
        if !context.can_write_area(PeerArea::Users) {
            exec_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            busy.set(false);
            confirm.set(false);
        }
    });
    let review_upsert = move |_| {
        if busy.get_untracked() || !context.can_write_area(crate::state::PeerArea::Users) {
            return;
        }
        match validate_user_binding_input(
            &af_user_id.get_untracked(),
            &provider.get_untracked(),
            &server_id.get_untracked(),
            &provider_user_id.get_untracked(),
        ) {
            Ok(body) => {
                pending_request.set(Some(("PUT", body)));
                confirm.set(true);
                error_msg.set(None);
            }
            Err(message) => error_msg.set(Some(message)),
        }
    };
    let execute = move |_| {
        let Some((method, body)) = pending_request.get_untracked() else {
            return;
        };
        if busy.get_untracked()
            || !context.is_admin()
            || !context.can_write_area(crate::state::PeerArea::Users)
        {
            return;
        }
        let server_epoch = context.server_epoch.get_untracked();
        let current_server = context.active_server_id.get_untracked();
        if let Some(captured) = confirm_captured.get_untracked() {
            if captured.server_epoch != server_epoch || captured.server_id != current_server {
                confirm.set(false);
                context.toast(tt(context, "PeerSwitch.staleConfirmBlocked"), true);
                return;
            }
        }
        let session_epoch = context.session_epoch.get_untracked();
        let users_grant = context.area_revocation_epoch_untracked(PeerArea::Users);
        exec_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = exec_ticket.get_untracked();
        busy.set(true);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(busy, exec_ticket, ticket);
        spawn_local(async move {
            let response = ApiClient
                .request("/api/v1/admin/streaming/user-links", method, Some(&body))
                .await;
            if busy.try_get_untracked().is_none()
                || exec_ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Users) != users_grant
                || !context.can_write_area_untracked(PeerArea::Users)
            {
                return;
            }
            match response {
                Ok(_) => {
                    if method == "PUT" {
                        provider_user_id.set(String::new());
                    }
                    on_changed.run(());
                    context.toast(
                        tt(
                            context,
                            if method == "DELETE" {
                                "User identity link removed."
                            } else {
                                "Explicit user identity link saved."
                            },
                        ),
                        false,
                    );
                    error_msg.set(None);
                }
                Err(e) => {
                    error_msg.set(Some(e.message.clone()));
                    context.toast(tt(context, &e.message), true);
                }
            }
            busy_guard.release();
            confirm.set(false);
            pending_request.set(None);
        });
    };
    view! {
        <div class="space-y-4 pt-3">
            <div class="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 items-end">
                <label class="text-xs text-slate-400 space-y-1">
                    <span class="block">{move || tt(context, "AF User ID")}</span>
                    <input
                        type="number"
                        min="1"
                        class="glass-input p-2 w-full"
                        disabled=move || busy.get()
                        prop:value=move || af_user_id.get()
                        on:input=move |e| af_user_id.set(event_target_value(&e))
                    />
                </label>
                <label class="text-xs text-slate-400 space-y-1">
                    <span class="block">{move || tt(context, "Provider")}</span>
                    <select
                        class="glass-input p-2 w-full"
                        disabled=move || busy.get()
                        prop:value=move || provider.get()
                        on:change=move |e| provider.set(event_target_value(&e))
                    >
                        <option value="jellyfin">{"jellyfin"}</option>
                        <option value="emby">{"emby"}</option>
                        <option value="plex">{"plex"}</option>
                    </select>
                </label>
                <label class="text-xs text-slate-400 space-y-1">
                    <span class="block">{move || tt(context, "Server ID")}</span>
                    <input
                        type="text"
                        list="streaming-user-link-servers"
                        class="glass-input p-2 w-full"
                        disabled=move || busy.get()
                        prop:value=move || server_id.get()
                        on:input=move |e| server_id.set(event_target_value(&e))
                    />
                    <datalist id="streaming-user-link-servers">
                        {move || {
                            servers
                                .get()
                                .into_iter()
                                .filter(|s| !s.server_id.is_empty())
                                .map(|s| view! { <option value=s.server_id /> })
                                .collect_view()
                        }}
                    </datalist>
                </label>
                <label class="text-xs text-slate-400 space-y-1">
                    <span class="block">{move || tt(context, "Provider User ID")}</span>
                    <input
                        type="text"
                        class="glass-input p-2 w-full"
                        disabled=move || busy.get()
                        prop:value=move || provider_user_id.get()
                        on:input=move |e| provider_user_id.set(event_target_value(&e))
                    />
                </label>
            </div>
            {move || {
                error_msg.get().map(|msg| view! {
                    <p role="alert" class="text-xs text-rose-300">{msg}</p>
                })
            }}
            <button
                type="button"
                class="glass-button px-4 py-2"
                disabled=move || {
                    busy.get() || !context.can_write_area(crate::state::PeerArea::Users)
                }
                title=move || {
                    context
                        .area_block_reason(crate::state::PeerArea::Users, true)
                        .unwrap_or_default()
                }
                on:click=review_upsert
            >
                {move || tt(context, "Save Link")}
            </button>
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs border-collapse">
                    <thead>
                        <tr class="border-b border-white/10 text-slate-400">
                            <th class="py-2 pr-3">{move || tt(context, "AF User ID")}</th>
                            <th class="py-2 pr-3">{move || tt(context, "Provider")}</th>
                            <th class="py-2 pr-3">{move || tt(context, "Server ID")}</th>
                            <th class="py-2 pr-3">{move || tt(context, "Provider User ID")}</th>
                            <th class="py-2 text-right">{move || tt(context, "Actions")}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {move || {
                            let rows = links.with(|b| b.links.clone());
                            if rows.is_empty() {
                                vec![view! {
                                    <tr>
                                        <td colspan="5" class="py-3 text-slate-500">
                                            {move || tt(context, "No explicit user identity links configured.")}
                                        </td>
                                    </tr>
                                }
                                .into_any()]
                            } else {
                                rows.into_iter()
                                    .map(|lnk: UserBinding| {
                                        let payload = json!({
                                            "afUserId": lnk.af_user_id,
                                            "provider": lnk.provider.clone(),
                                            "serverId": lnk.server_id.clone(),
                                            "providerUserId": lnk.provider_user_id.clone(),
                                        });
                                        let user_display = lnk
                                            .af_username
                                            .as_deref()
                                            .filter(|s| !s.is_empty())
                                            .map(|name| format!("#{} ({name})", lnk.af_user_id))
                                            .unwrap_or_else(|| format!("#{}", lnk.af_user_id));
                                        let remove_label = tt_with(
                                            context,
                                            "Delete binding for {user}",
                                            &[("user", &user_display)],
                                        );
                                        view! {
                                            <tr class="border-b border-white/[0.06]">
                                                <td class="py-2 pr-3 font-mono">{user_display}</td>
                                                <td class="py-2 pr-3">{lnk.provider}</td>
                                                <td class="py-2 pr-3 font-mono">{lnk.server_id}</td>
                                                <td class="py-2 pr-3 font-mono">{lnk.provider_user_id}</td>
                                                <td class="py-2 text-right">
                                                    <button
                                                        type="button"
                                                        class="glass-button px-2.5 py-1 text-xs text-rose-300"
                                                        aria-label=remove_label
                                                        disabled=move || {
                                                            busy.get()
                                                                || !context.can_write_area(
                                                                    crate::state::PeerArea::Users,
                                                                )
                                                        }
                                                        title=move || {
                                                            context
                                                                .area_block_reason(
                                                                    crate::state::PeerArea::Users,
                                                                    true,
                                                                )
                                                                .unwrap_or_default()
                                                        }
                                                        on:click=move |_| {
                                                            pending_request.set(Some(("DELETE", payload.clone())));
                                                            confirm.set(true);
                                                        }
                                                    >
                                                        {move || tt(context, "Remove")}
                                                    </button>
                                                </td>
                                            </tr>
                                        }
                                        .into_any()
                                    })
                                    .collect::<Vec<_>>()
                            }
                        }}
                    </tbody>
                </table>
            </div>
            <Modal
                open=confirm
                title=Signal::derive(move || {
                    let server = confirm_captured
                        .get()
                        .and_then(|c| c.server_name)
                        .or_else(|| context.active_server_name());
                    crate::tabs::l10n::confirm_dialog_title(
                        context,
                        "Review exact administrative request",
                        server.as_deref(),
                    )
                })
            >
                <div class="space-y-3">
                    <p class="text-sm">
                        {move || {
                            pending_request
                                .get()
                                .map(|(method, _)| format!("{method} /api/v1/admin/streaming/user-links"))
                                .unwrap_or_default()
                        }}
                    </p>
                    <pre class="text-xs whitespace-pre-wrap break-all max-h-64 overflow-auto">
                        {move || {
                            pending_request
                                .get()
                                .and_then(|(_, body)| serde_json::to_string_pretty(&body).ok())
                                .unwrap_or_default()
                        }}
                    </pre>
                    <button
                        type="button"
                        class="glass-button-primary px-4 py-2"
                        disabled=move || busy.get()
                        on:click=execute
                    >
                        {move || tt(context, "Apply reviewed change")}
                    </button>
                </div>
            </Modal>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_and_user_binding_validation_enforce_strict_identities_and_bounds() {
        assert!(validate_policy_payload("30", "120", "[]", "[]").is_ok());
        assert!(validate_policy_payload("-1", "0", "[]", "[]").is_err());
        assert!(validate_policy_payload("0", "5000", "[]", "[]").is_err());
        assert!(validate_policy_payload(
            "0",
            "0",
            r#"[{"provider":"jellyfin","serverId":"","id":"u1"}]"#,
            "[]",
        )
        .is_err());

        assert!(validate_policy_payload(
            "0",
            "0",
            r#"[{"provider":"plex","serverId":"srv-plex","id":"u1"}]"#,
            r#"[{"provider":"emby","serverId":"srv-emby","id":"lib-1"}]"#,
        )
        .is_ok());

        assert!(validate_user_binding_input("2", "jellyfin", "srv-1", "jf-user-1").is_ok());
        assert!(validate_user_binding_input("2", "emby", "srv-1", "emby-user-1").is_ok());
        assert!(validate_user_binding_input("2", "plex", "srv-1", "u1").is_ok());
        assert!(validate_user_binding_input("0", "jellyfin", "srv-1", "jf-user-1").is_err());
        assert!(validate_user_binding_input("2", "demo", "srv-1", "u1").is_err());
        assert!(validate_user_binding_input("2", "emby", "", "u1").is_err());
    }
}
