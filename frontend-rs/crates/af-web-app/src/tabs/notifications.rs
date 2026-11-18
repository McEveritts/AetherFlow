use super::settings::{
    draft_value, encode, poll_resource, text, DraftButtons, DraftCheck, DraftInput, DraftSelect,
    ResourceFeedback,
};
use crate::state::{app, json_rows, use_api, ApiResource};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{ConfirmDialog, DataGrid, EmptyState, Modal, ObsCard};
use af_web_core::{api::ApiClient, draft::FormDraft};
use af_web_ui::GridColumn;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

fn channel_form() -> Value {
    json!({"name":"","type":"discord","webhook_url":"","bot_token":"","chat_id":"","token":"","enabled":true})
}
fn rule_form() -> Value {
    json!({"name":"","condition_type":"service_down","condition_value":"","level":"warning","enabled":true})
}
fn saved_rule(previous_id: Option<i64>, sent: &Value, response: &Value) -> Option<(i64, Value)> {
    let id = previous_id
        .or_else(|| response["id"].as_i64())
        .filter(|id| *id > 0)?;
    let mut baseline = sent.clone();
    if previous_id.is_none() {
        // The create endpoint returns an ID and normalizes these fields;
        // subsequent updates preserve the values in their submitted body.
        baseline["name"] = json!(text(sent, "name").trim());
        baseline["condition_value"] = json!(text(sent, "condition_value").trim());
        let level = text(sent, "level");
        baseline["level"] = json!(if level.trim().is_empty() {
            "warning"
        } else {
            level.trim()
        });
        baseline["enabled"] = json!(true);
    }
    Some((id, baseline))
}
fn validate_rule(value: &Value) -> Result<(), &'static str> {
    let rule = super::contracts::decode::<super::contracts::NotificationRule>(value);
    if rule.name.trim().is_empty() || rule.condition_value.trim().is_empty() {
        return Err("Rule name and condition value are required");
    }
    if rule.condition_type != "service_down"
        && !rule
            .condition_value
            .trim()
            .parse::<f64>()
            .is_ok_and(|v| v.is_finite() && v > 0.0 && v <= 100.0)
    {
        return Err("Choose a percentage threshold between 0 and 100");
    }
    Ok(())
}
fn notification_row(context: crate::state::AppContext, mut row: Value) -> Value {
    let level = row["level"]
        .as_str()
        .or_else(|| row["severity"].as_str())
        .unwrap_or_default();
    row["level_label"] = json!(tt(context, level));
    let read = match &row["read"] {
        Value::Bool(true) => "read",
        Value::Bool(false) => "unread",
        Value::Number(value) => {
            if value.as_u64() == Some(1) {
                "read"
            } else {
                "unread"
            }
        }
        Value::String(value) => match value.as_str() {
            "true" | "1" => "read",
            "false" | "0" => "unread",
            other => other,
        },
        _ => row["status"].as_str().unwrap_or("unread"),
    };
    row["read_label"] = json!(tt(context, read));
    row
}
#[component]
pub fn NotificationsTab() -> impl IntoView {
    let context = app();
    let events = use_api("/api/v1/auth/notifications?limit=100&offset=0".to_string());
    poll_resource(events, 15_000);
    let activity = Memo::new(move |_| {
        context.locale.get();
        context.catalog_revision.get();
        let data = events.data.get();
        let rows = if data.is_null() {
            context.notifications.get()
        } else {
            json_rows(&data)
        };
        rows.into_iter()
            .map(|row| notification_row(context, row))
            .collect::<Vec<_>>()
    });
    view! {
        <section class="space-y-6 py-5 min-w-0 max-w-full">
            <ObsCard>
                <h2 class="text-lg font-semibold mb-4">
                    {move || tt(context, "Tabs.notificationsHeading")}
                </h2>
                <button
                    type="button"
                    class="glass-button px-4 py-2 mb-4"
                    on:click=move |_| events.refresh()
                    aria-label=move || tt(context, "Refresh activity")
                >
                    {move || tt(context, "Common.refresh")}
                </button>
                <ResourceFeedback resource=events />
                <Show when=move || events.loading.get() || !activity.with(Vec::is_empty)>
                <DataGrid
                    label="Recent notifications"
                    columns=vec![
                        GridColumn::new("created_at", "Time"),
                        GridColumn::new("title", "Title"),
                        GridColumn::new("message", "Message"),
                        GridColumn::new("level_label", "Severity"),
                        GridColumn::new("read_label", "Read"),
                    ]
                    rows=Signal::derive(move || activity.get())
                />
                </Show>
                <Show when=move || !events.loading.get() && activity.with(Vec::is_empty)>
                    <EmptyState title="No recent notifications" />
                </Show>
            </ObsCard>
            <Show when=move || context.is_admin()>
                <NotificationsAdminContent events />
            </Show>
        </section>
    }
}

#[component]
fn NotificationsAdminContent(events: ApiResource) -> impl IntoView {
    let context = app();
    let channels = use_api("/api/v1/admin/notifications/channels".to_string());
    let rules = use_api("/api/v1/admin/notifications/rules".to_string());
    poll_resource(channels, 15_000);
    poll_resource(rules, 15_000);
    let channel = RwSignal::new(FormDraft::new(channel_form()));
    let rule = RwSignal::new(FormDraft::new(rule_form()));
    let channel_open = RwSignal::new(false);
    let rule_open = RwSignal::new(false);
    let rule_id = RwSignal::new(None::<i64>);
    let busy = RwSignal::new(false);
    let selected = RwSignal::new(Value::Null);
    let remove = RwSignal::new(false);
    let delivery = RwSignal::new(Vec::<Value>::new());
    Effect::new(move |_| {
        let id = rule_id.get();
        if let Some(id) = id {
            if let Some(value) = rules.data.get()["rules"]
                .as_array()
                .and_then(|values| values.iter().find(|v| v["id"] == id))
                .cloned()
            {
                let baseline = json!({"name":value["name"],"condition_type":value["condition_type"],"condition_value":value["condition_value"],"level":value["level"],"enabled":value["enabled"]});
                rule.update(|d| d.apply_server_refresh(baseline));
            }
        }
    });
    Effect::new(move |_| {
        if !channel_open.get() {
            channel.update(|d| {
                if !d.is_dirty() {
                    d.mark_saved(channel_form());
                }
            });
        }
    });
    let create_channel = Callback::new(move |()| {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let sent = draft_value(channel);
        let kind = text(&sent, "type");
        let mut config = json!({});
        if kind == "telegram" {
            if text(&sent, "bot_token").trim().is_empty()
                || text(&sent, "chat_id").trim().is_empty()
            {
                context.toast(
                    tt(context, "Telegram bot token and chat ID are required"),
                    true,
                );
                return;
            }
            config["bot_token"] = json!(text(&sent, "bot_token").trim());
            config["chat_id"] = json!(text(&sent, "chat_id").trim());
        } else {
            let target = text(&sent, "webhook_url");
            if !url::Url::parse(target.trim()).is_ok_and(|v| matches!(v.scheme(), "http" | "https"))
            {
                context.toast(
                    tt(context, "Enter a valid HTTP or HTTPS delivery URL"),
                    true,
                );
                return;
            }
            config["webhook_url"] = json!(target.trim());
            if kind == "gotify" {
                config["token"] = json!(text(&sent, "token").trim());
            }
            if kind == "ntfy" {
                config["service"] = json!("ntfy");
            }
        }
        if text(&sent, "name").trim().is_empty() {
            context.toast(tt(context, "Channel name is required"), true);
            return;
        }
        let payload = json!({"name":text(&sent,"name").trim(),"type":if kind=="ntfy"{"webhook"}else{&kind},"config":config,"enabled":sent["enabled"]});
        busy.set(true);
        spawn_local(async move {
            match ApiClient
                .post("/api/v1/admin/notifications/channels", Some(&payload))
                .await
            {
                Ok(_) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    let mut has_newer_edits = false;
                    channel.update(|d| {
                        let _ = d.acknowledge_saved(&sent, channel_form());
                        has_newer_edits = d.is_dirty();
                    });
                    if !has_newer_edits {
                        channel_open.set(false);
                    }
                    channels.refresh();
                    context.toast(tt(context, "Delivery channel created"), false);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy.set(false);
            }
        });
    });
    let save_rule = Callback::new(move |()| {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let sent = draft_value(rule);
        let id = rule_id.get_untracked();
        if let Err(error) = validate_rule(&sent) {
            context.toast(tt(context, error), true);
            return;
        }
        let mut payload = sent.clone();
        if id.is_none() {
            if let Some(fields) = payload.as_object_mut() {
                fields.remove("enabled");
            }
        }
        busy.set(true);
        spawn_local(async move {
            let path = id
                .map(|id| format!("/api/v1/admin/notifications/rules/{id}"))
                .unwrap_or_else(|| "/api/v1/admin/notifications/rules".into());
            match ApiClient
                .request(
                    &path,
                    if id.is_some() { "PUT" } else { "POST" },
                    Some(&payload),
                )
                .await
            {
                Ok(response) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    let Some((saved_id, baseline)) = saved_rule(id, &sent, &response) else {
                        // A create succeeded, so retrying POST could duplicate
                        // it. Return to the listing if its identity is missing.
                        rule_open.set(false);
                        rules.refresh();
                        busy.set(false);
                        context.toast(
                            tt_with(
                                context,
                                "Invalid server response (HTTP {status})",
                                &[("status", "201")],
                            ),
                            true,
                        );
                        return;
                    };
                    let mut has_newer_edits = false;
                    rule.update(|d| {
                        let _ = d.acknowledge_saved(&sent, baseline.clone());
                        has_newer_edits = d.is_dirty();
                    });
                    let mut saved = baseline;
                    saved["id"] = json!(saved_id);
                    if id.is_some() {
                        // Replace the cached row before rule_id can re-enter the
                        // draft effect. Preserve other server fields and rows.
                        let mut cached = rules.data.get_untracked();
                        if !cached.is_object() {
                            cached = json!({});
                        }
                        if !cached["rules"].is_array() {
                            cached["rules"] = json!([]);
                        }
                        if let Some(rows) = cached["rules"].as_array_mut() {
                            if let Some(row) = rows.iter_mut().find(|row| row["id"] == saved_id) {
                                if let (Some(fields), Some(saved_fields)) =
                                    (row.as_object_mut(), saved.as_object())
                                {
                                    fields.extend(saved_fields.clone());
                                }
                            } else {
                                rows.push(saved.clone());
                            }
                        }
                        // commit invalidates old reads before publishing the row
                        // and starts the usual revalidation.
                        rules.commit(cached);
                    }
                    rule_id.set(Some(saved_id));
                    selected.set(saved);
                    if !has_newer_edits {
                        rule_open.set(false);
                    }
                    if id.is_none() {
                        rules.refresh();
                    }
                    context.toast(tt(context, "Alert rule saved"), false);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy.set(false);
            }
        });
    });
    let test_channel = move |value: Value| {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let id = text(&value, "id");
        let name = text(&value, "name");
        busy.set(true);
        spawn_local(async move {
            let result = ApiClient
                .post(
                    &format!("/api/v1/admin/notifications/channels/{}/test", encode(&id)),
                    None,
                )
                .await;
            let (state, message) = match result {
                Ok(value) => (
                    "delivered",
                    value["message"]
                        .as_str()
                        .unwrap_or("Test delivered")
                        .to_string(),
                ),
                Err(error) => ("failed", error.message),
            };
            context.toast(tt(context, &message.clone()), state == "failed");
            if delivery.try_get_untracked().is_none() {
                return;
            }
            delivery.update(|items|{
                items.insert(0,json!({"channel":name,"status":state,"message":message,"timestamp":js_sys::Date::new_0().to_iso_string().as_string().unwrap_or_default()}));
                items.truncate(100);
            });
            events.refresh();
            busy.set(false);
        });
    };
    let delete = Callback::new(move |()| {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let target = selected.get_untracked();
        let id = text(&target, "id");
        let kind = if target["target_kind"] == "rule" {
            "rules"
        } else {
            "channels"
        };
        busy.set(true);
        spawn_local(async move {
            match ApiClient
                .delete(
                    &format!("/api/v1/admin/notifications/{kind}/{}", encode(&id)),
                    None,
                )
                .await
            {
                Ok(_) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    remove.set(false);
                    if kind == "rules" {
                        rule_open.set(false);
                        rule_id.set(None);
                    }
                    channels.refresh();
                    rules.refresh();
                    context.toast(tt(context, "Notification configuration removed"), false);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy.set(false);
            }
        });
    });
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
                <ObsCard title="Notification channels">
                    <div class="flex flex-wrap gap-3 mb-5">
                        <button
                            type="button"
                            class="glass-button-primary px-4 py-2"
                            disabled=move || busy.get()
                            on:click=move |_| channel_open.set(true)
                        >
                            {move || tt(context, "Add channel")}
                        </button>
                        <button
                            type="button"
                            class="glass-button px-4 py-2"
                            on:click=move |_| {
                                channels.refresh();
                                rules.refresh();
                                events.refresh();
                            }
                            aria-label=move || tt(context, "Refresh notifications")
                        >
                            {move || tt(context, "Common.refresh")}
                        </button>
                    </div>
                    <ResourceFeedback resource=channels />
                    <div class="space-y-4">
                        {move || {
                            super::contracts::grid_rows::<
                                super::contracts::NotificationChannel,
                            >(&channels.data.get()["channels"])
                                .into_iter()
                                .map(move |channel| {
                                    let test = channel.clone();
                                    let mut target = channel.clone();
                                    target["target_kind"] = json!("channel");
                                    view! {
                                        <div class="flex flex-wrap items-center justify-between gap-4 py-4 border-t border-white/10">
                                            <div class="min-w-0">
                                                <h3 class="font-semibold break-all">
                                                    {text(&channel, "name")}
                                                </h3>
                                                <p class="text-sm text-slate-400">
                                                    {move || format!(
                                                        "{} · {}",
                                                        tt(context, match channel["type"].as_str().unwrap_or_default() {
                                                            "email" => "Email",
                                                            "discord" => "Discord",
                                                            "gotify" => "Gotify",
                                                            "telegram" => "Telegram",
                                                            other => other,
                                                        }),
                                                        tt(context, if channel["enabled"] == true {
                                                            "Enabled"
                                                        } else {
                                                            "Disabled"
                                                        }),
                                                    )}
                                                </p>
                                            </div>
                                            <div class="flex flex-wrap gap-3">
                                                <button
                                                    type="button"
                                                    class="glass-button px-4 py-2"
                                                    disabled=move || busy.get()
                                                    on:click=move |_| test_channel(test.clone())
                                                >
                                                    {move || tt(context, "Send Test Notification")}
                                                </button>
                                                <button
                                                    type="button"
                                                    class="glass-button px-4 py-2 text-rose-300"
                                                    disabled=move || busy.get()
                                                    on:click=move |_| {
                                                        selected.set(target.clone());
                                                        remove.set(true);
                                                    }
                                                >
                                                    {move || tt(context, "Delete channel")}
                                                </button>
                                            </div>
                                        </div>
                                    }
                                })
                                .collect_view()
                        }}
                    </div>
                    <p class="text-xs text-slate-400 mt-4">
                        {move || tt(
                            context,
                            "To change a channel, add and test its replacement before deleting the old channel. This server has no channel update API. Email uses an HTTP relay; direct SMTP is unavailable.",
                        )}
                    </p>
                </ObsCard>
                <ObsCard title="Alert rules & event triggers">
                    <p class="text-sm text-slate-400 mb-4">
                        {move || tt(
                            context,
                            "Service failures and CPU, memory, or disk thresholds dispatch to enabled channels. Login anomaly and package lifecycle triggers are not configurable on this server.",
                        )}
                    </p>
                    <div class="flex flex-wrap gap-5 text-sm mb-5">
                        {["Service failure", "Disk threshold", "CPU threshold", "Memory threshold"]
                            .into_iter()
                            .zip(["service_down", "disk_usage", "cpu_usage", "memory_usage"])
                            .map(move |(label, kind)| {
                                view! {
                                    <label class="flex gap-2 items-center">
                                        <input
                                            type="checkbox"
                                            disabled
                                            prop:checked=move || {
                                                rules
                                                    .data
                                                    .get()["rules"]
                                                    .as_array()
                                                    .is_some_and(|rows| {
                                                        rows.iter()
                                                            .any(|r| {
                                                                r["condition_type"] == kind && r["enabled"] == true
                                                            })
                                                    })
                                            }
                                        />
                                        <span>{move || tt(context, label)}</span>
                                    </label>
                                }
                            })
                            .collect_view()}
                    </div>
                    <button
                        type="button"
                        class="glass-button-primary px-4 py-2 mb-5"
                        disabled=move || busy.get()
                        on:click=move |_| {
                            rule_id.set(None);
                            rule.update(|d| d.mark_saved(rule_form()));
                            rule_open.set(true);
                        }
                    >
                        {move || tt(context, "Add alert rule")}
                    </button>
                    <ResourceFeedback resource=rules />
                    <DataGrid
                        label="Notification alert rules"
                        columns=vec![
                            GridColumn::new("name", "Rule"),
                            GridColumn::new("condition_type", "Trigger"),
                            GridColumn::new("condition_value", "Threshold / service"),
                            GridColumn::new("level", "Severity"),
                            GridColumn::new("enabled", "Enabled"),
                        ]
                        rows=Signal::derive(move || super::contracts::grid_rows::<
                            super::contracts::NotificationRule,
                        >(&rules.data.get()["rules"]).into_iter().map(|mut row| {
                            row["condition_type"] = json!(tt(context, match row["condition_type"].as_str().unwrap_or_default() {
                                "service_down" => "Service failure",
                                "disk_usage" => "Disk threshold",
                                "cpu_usage" => "CPU threshold",
                                "memory_usage" => "Memory threshold",
                                other => other,
                            }));
                            row["level"] = json!(tt(context, match row["level"].as_str().unwrap_or_default() {
                                "info" => "Info",
                                "warning" => "Warning",
                                "critical" => "Critical",
                                other => other,
                            }));
                            row
                        }).collect::<Vec<_>>())
                        on_select=Callback::new(move |value: Value| {
                            if busy.get_untracked() {
                                return;
                            }
                            // Display labels are localized; edit the original API record.
                            let Some(value) = super::contracts::grid_rows::<super::contracts::NotificationRule>(
                                &rules.data.get_untracked()["rules"],
                            ).into_iter().find(|row| row["id"] == value["id"]) else { return; };
                            rule_id.set(value["id"].as_i64());
                            rule.update(|d| {
                                d.mark_saved(
                                    json!(
                                        {"name":value["name"],"condition_type":value["condition_type"],"condition_value":value["condition_value"],"level":value["level"],"enabled":value["enabled"]}
                                    ),
                                )
                            });
                            selected.set(value);
                            rule_open.set(true);
                        })
                    />
                    <p class="text-xs text-slate-400 mt-3">
                        {move || tt(
                            context,
                            "Select a rule to edit its trigger, threshold, severity, or enabled state.",
                        )}
                    </p>
                </ObsCard>
                <ObsCard title="Notification delivery tests">
                    <h3 class="font-semibold my-4">
                        {move || tt(context, "Delivery tests from this view")}
                    </h3>
                    <DataGrid
                        label="Notification test delivery log"
                        columns=vec![
                            GridColumn::new("timestamp", "Time"),
                            GridColumn::new("channel", "Channel"),
                            GridColumn::new("status", "Delivery"),
                            GridColumn::new("message", "Result"),
                        ]
                        rows=Signal::derive(move || delivery.get().into_iter().map(|mut row| {
                            for field in ["status", "message"] {
                                row[field] = json!(tt(context, row[field].as_str().unwrap_or_default()));
                            }
                            row
                        }).collect::<Vec<_>>())
                    />
                    <p class="text-xs text-slate-400 mt-3">
                        {move || tt(
                            context,
                            "Historical channel delivery receipts are not exposed by this server. The test log above records actual responses from this view.",
                        )}
                    </p>
                </ObsCard>
            </Show>
            <Modal open=channel_open title="Configure delivery channel">
                <div class="grid sm:grid-cols-2 gap-4">
                    <DraftInput draft=channel field="name" label="Channel name" required=true />
                    <DraftSelect
                        draft=channel
                        field="type"
                        label="Delivery provider"
                        options=vec![
                            ("discord", "Discord"),
                            ("slack", "Slack"),
                            ("telegram", "Telegram"),
                            ("gotify", "Gotify"),
                            ("ntfy", "Ntfy (webhook)"),
                            ("webhook", "Generic webhook"),
                            ("email", "Email relay webhook"),
                        ]
                    />
                    <Show when=move || draft_value(channel)["type"] != "telegram">
                        <DraftInput
                            draft=channel
                            field="webhook_url"
                            label="Delivery URL"
                            kind="url"
                            required=true
                        />
                    </Show>
                    <Show when=move || draft_value(channel)["type"] == "gotify">
                        <DraftInput
                            draft=channel
                            field="token"
                            label="Gotify application token"
                            kind="password"
                        />
                    </Show>
                    <Show when=move || draft_value(channel)["type"] == "telegram">
                        <DraftInput
                            draft=channel
                            field="bot_token"
                            label="Telegram bot token"
                            kind="password"
                            required=true
                        />
                        <DraftInput
                            draft=channel
                            field="chat_id"
                            label="Telegram chat ID"
                            required=true
                        />
                    </Show>
                </div>
                <DraftCheck draft=channel field="enabled" label="Enable channel" />
                <DraftButtons draft=channel busy on_save=create_channel label="Create channel" />
            </Modal>
            <Modal open=rule_open title="Configure alert rule">
                <div class="grid sm:grid-cols-2 gap-4">
                    <DraftInput draft=rule field="name" label="Rule name" required=true />
                    <DraftSelect
                        draft=rule
                        field="condition_type"
                        label="Event trigger"
                        options=vec![
                            ("service_down", "Service failure"),
                            ("disk_usage", "Disk threshold"),
                            ("cpu_usage", "CPU threshold"),
                            ("memory_usage", "Memory threshold"),
                        ]
                    />
                    <DraftInput
                        draft=rule
                        field="condition_value"
                        label="Service name or percentage threshold"
                        required=true
                    />
                    <DraftSelect
                        draft=rule
                        field="level"
                        label="Severity"
                        options=vec![
                            ("info", "Info"),
                            ("warning", "Warning"),
                            ("critical", "Critical"),
                        ]
                    />
                </div>
                <Show when=move || rule_id.get().is_some()>
                    <DraftCheck draft=rule field="enabled" label="Enable alert rule" />
                </Show>
                <DraftButtons draft=rule busy on_save=save_rule label="Save alert rule" />
                <Show when=move || rule_id.get().is_some()>
                    <button
                        type="button"
                        class="glass-button px-4 py-2 mt-5 text-rose-300"
                        disabled=move || busy.get()
                        on:click=move |_| {
                            let mut value = selected.get_untracked();
                            value["target_kind"] = json!("rule");
                            selected.set(value);
                            remove.set(true);
                        }
                    >
                        {move || tt(context, "Delete alert rule")}
                    </button>
                </Show>
            </Modal>
            <ConfirmDialog
                open=remove
                title="Delete notification configuration?"
                message="The selected channel or alert rule will be permanently removed."
                busy
                on_confirm=delete
            />
        </section>
    }
}

#[cfg(test)]
mod tests;
