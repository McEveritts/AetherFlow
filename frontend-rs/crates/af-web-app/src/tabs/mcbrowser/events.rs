use super::*;

#[component]
pub(super) fn EventsAdmin() -> impl IntoView {
    let context = app();
    let status = RwSignal::new(String::new());
    let trigger = RwSignal::new(String::new());
    let user = RwSignal::new(String::new());
    let limit = RwSignal::new("100".to_owned());
    let audit = use_api(Signal::derive(move || {
        let mut url = format!("{BASE}/events?limit={}", encode(&limit.get()));
        if !status.get().is_empty() {
            url.push_str(&format!("&status={}", encode(&status.get())));
        }
        if !trigger.get().is_empty() {
            url.push_str(&format!("&trigger={}", encode(&trigger.get())));
        }
        if !user.get().is_empty() {
            url.push_str(&format!("&user_id={}", encode(&user.get())));
        }
        url
    }));
    let queue = use_api(format!("{BASE}/events/queue?limit=100"));
    let settings = use_api(format!("{BASE}/events/settings"));
    let settings_draft = RwSignal::new(None::<FormDraft<Value>>);
    let busy = RwSignal::new(false);
    let failure = RwSignal::new(String::new());
    let selected = RwSignal::new(Value::Null);
    Effect::new(move |_| {
        let server = settings.data.get();
        if !server["enabled"].is_boolean() {
            return;
        }
        settings_draft.update(|draft| {
            if let Some(draft) = draft {
                draft.apply_server_refresh(server);
            } else {
                *draft = Some(FormDraft::new(server));
            }
        });
    });
    let save = move |_| {
        if busy.get_untracked() {
            return;
        }
        let sent = draft_value(settings_draft);
        if !sent["enabled"].is_boolean() {
            return;
        }
        busy.set(true);
        let auth = context.session_epoch.get_untracked();
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            let result = ApiClient
                .put(&format!("{BASE}/events/settings"), Some(&sent))
                .await;
            if busy.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(auth)
            {
                return;
            }
            busy_guard.release();
            match result {
                Ok(server) => {
                    settings_draft.update(|draft| {
                        if let Some(draft) = draft {
                            let _ = draft.acknowledge_saved(&sent, server);
                        }
                    });
                    queue.refresh();
                    context.toast(tt(context, "Event settings saved"), false);
                }
                Err(error) => failure.set(error.to_string()),
            }
        });
    };
    let acknowledge = move |_| {
        if busy.get_untracked() {
            return;
        }
        let id = text(&selected.get_untracked(), "event_id");
        if id.is_empty() {
            return;
        }
        busy.set(true);
        let auth = context.session_epoch.get_untracked();
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            let result = ApiClient
                .post(
                    &format!("{BASE}/events/queue/{}/ack", encode(&id)),
                    Some(&json!({})),
                )
                .await;
            if busy.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(auth)
            {
                return;
            }
            busy_guard.release();
            match result {
                Ok(_) => {
                    selected.set(Value::Null);
                    queue.refresh();
                    context.toast(tt(context, "Event acknowledged"), false);
                }
                Err(error) => failure.set(error.to_string()),
            }
        });
    };
    let queue_rows = Signal::derive(move || {
        queue.data.get()["tasks"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|task| {
                let mut row = task["event"].clone();
                if !row.is_object() {
                    row = json!({});
                }
                for key in ["event_id", "status", "enqueued_at", "acknowledged_at"] {
                    row[key] = task[key].clone();
                }
                row
            })
            .collect::<Vec<_>>()
    });
    view! {
        <div class="space-y-5">
            <ObsCard title=Signal::derive(move || tt(context, "McBrowser.auditEventsTitle"))>
                <div class="flex flex-wrap gap-3 mb-4">
                    <label class="text-xs">
                        {move || tt(context, "Status")}
                        <select
                            class=FORM
                            prop:value=move || status.get()
                            on:change=move |event| status.set(event_target_value(&event))
                        >
                            <option value="">{move || tt(context, "All")}</option>
                            <option value="pending">{move || tt(context, "Pending")}</option>
                            <option value="completed">{move || tt(context, "Completed")}</option>
                            <option value="failed">{move || tt(context, "Failed")}</option>
                        </select>
                    </label>
                    <label class="text-xs">
                        {move || tt(context, "Trigger")}
                        <select
                            class=FORM
                            prop:value=move || trigger.get()
                            on:change=move |event| trigger.set(event_target_value(&event))
                        >
                            <option value="">{move || tt(context, "All mutations")}</option>
                            {[
                                "upload_completed",
                                "entry_deleted",
                                "file_saved",
                                "entry_copied",
                                "entry_renamed",
                                "share_created",
                                "share_revoked",
                            ]
                                .into_iter()
                                .map(|key| {
                                    view! {
                                        <option value=key>
                                            {move || tt(context, &key.replace('_', " "))}
                                        </option>
                                    }
                                })
                                .collect_view()}
                        </select>
                    </label>
                    <label class="text-xs">
                        {move || tt(context, "User ID")}
                        <input
                            class=FORM
                            type="number"
                            min="1"
                            prop:value=move || user.get()
                            on:change=move |event| user.set(event_target_value(&event))
                        />
                    </label>
                    <label class="text-xs">
                        {move || tt(context, "Limit")}
                        <select
                            class=FORM
                            prop:value=move || limit.get()
                            on:change=move |event| limit.set(event_target_value(&event))
                        >
                            <option value="100">{move || tt(context, "100")}</option>
                            <option value="250">{move || tt(context, "250")}</option>
                            <option value="500">{move || tt(context, "500")}</option>
                        </select>
                    </label>
                    <button
                        type="button"
                        class="glass-button px-4 py-2 self-end"
                        on:click=move |_| {
                            audit.refresh();
                            queue.refresh();
                            settings.refresh();
                        }
                        aria-label=move || tt(context, "Refresh")
                    >
                        {move || tt(context, "Common.refresh")}
                    </button>
                </div>
                <Show when=move || audit.loading.get()>
                    <SkeletonBox class="h-24" />
                </Show>
                <p role="alert" class="text-sm text-rose-300">
                    {move || audit.error.get().map(|error| tt(context, &error.to_string()))}
                </p>
                <Show when=move || audit.data.get()["truncated"] == true>
                    <p class="text-xs text-amber-200">
                        {move || tt(
                            context,
                            "More events exist. Narrow the filters or increase the limit.",
                        )}
                    </p>
                </Show>
                <DataGrid
                    label="McBrowser audit events"
                    columns=vec![
                        GridColumn::new("timestamp", "Time"),
                        GridColumn::new("username", "User"),
                        GridColumn::new("trigger", "Trigger"),
                        GridColumn::new("relative_path", "Path"),
                        GridColumn::new("destination_path", "Destination"),
                        GridColumn::numeric("byte_delta", "Byte delta"),
                        GridColumn::new("status", "Status"),
                        GridColumn::new("error_code", "Error"),
                    ]
                    rows=Signal::derive(move || {
                        audit.data.get()["events"].as_array().cloned().unwrap_or_default()
                    })
                />
            </ObsCard>
            <ObsCard title="Event delivery queue">
                <div class="flex flex-wrap gap-3 items-center mb-4">
                    <label class="flex gap-2 text-sm">
                        <input
                            type="checkbox"
                            disabled=move || {
                                busy.get() || settings.loading.get()
                                    || settings_draft.with(Option::is_none)
                            }
                            prop:checked=move || draft_value(settings_draft)["enabled"] == true
                            on:change=move |event| {
                                let enabled = event_target_checked(&event);
                                draft_edit(settings_draft, "enabled", json!(enabled));
                                draft_edit(settings_draft, "queue_enabled", json!(enabled));
                            }
                        />
                        {move || tt(context, "Enable event queue")}
                    </label>
                    <button
                        type="button"
                        class="glass-button px-3 py-2"
                        disabled=move || {
                            busy.get()
                                || !settings_draft
                                    .with(|draft| draft.as_ref().is_some_and(FormDraft::is_dirty))
                        }
                        on:click=save
                    >
                        {move || tt(context, "Save event settings")}
                    </button>
                    <button
                        type="button"
                        class="glass-button px-3 py-2"
                        disabled=move || busy.get() || selected.get()["status"] != "queued"
                        on:click=acknowledge
                    >
                        {move || tt(context, "Acknowledge selected task")}
                    </button>
                </div>
                <p role="alert" class="text-sm text-rose-300">
                    {move || tt(context, &failure.get())}
                </p>
                <p role="alert" class="text-sm text-rose-300">
                    {move || {
                        settings
                            .error
                            .get()
                            .or_else(|| queue.error.get())
                            .map(|error| tt(context, &error.to_string()))
                    }}
                </p>
                <DataGrid
                    label="Queued McBrowser event tasks"
                    columns=vec![
                        GridColumn::new("event_id", "Event"),
                        GridColumn::new("trigger", "Trigger"),
                        GridColumn::new("relative_path", "Path"),
                        GridColumn::new("status", "Status"),
                        GridColumn::new("enqueued_at", "Queued at"),
                    ]
                    rows=queue_rows
                    on_select=Callback::new(move |row| selected.set(row))
                />
            </ObsCard>
        </div>
    }
}
