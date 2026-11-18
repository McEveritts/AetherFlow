//! Service inventory and guarded administrator controls.
mod helpers;
mod logs;

use self::helpers::*;
use self::logs::ServiceLogsModal;
use crate::state::{app, run_resource_read, ApiResource, ResourceReads};
use crate::tabs::l10n::{tt, tt_with, Badge, EmptyState, ObsCard, SearchInput};
use af_web_core::api::ApiClient;
use af_web_ui::use_worker_rows;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

fn use_services_inventory() -> ApiResource {
    let context = app();
    let resource = ApiResource {
        data: RwSignal::new(Value::Null),
        loading: RwSignal::new(true),
        error: RwSignal::new(None),
        revision: RwSignal::new(0),
    };
    let generation = RwSignal::new(0u64);
    let reads = StoredValue::new_local(ResourceReads::default());
    on_cleanup(move || reads.update_value(|reads| reads.cancel()));
    Effect::new(move |_| {
        let epoch = context.session_epoch.get();
        let revision = resource.revision.get();
        generation.update(|generation| *generation = generation.wrapping_add(1));
        let ticket = generation.get_untracked();
        let request = context.begin_services_request();
        resource.loading.set(true);
        let Some(job) = reads.try_update_value(ResourceReads::next) else {
            return;
        };
        spawn_local(async move {
            let work = async {
                if generation.try_get_untracked() != Some(ticket)
                    || resource.revision.try_get_untracked() != Some(revision)
                    || context.session_epoch.try_get_untracked() != Some(epoch)
                {
                    return None;
                }
                Some(ApiClient.get("/api/v1/auth/services").await)
            };
            let Some(Some(result)) = run_resource_read(job, work).await else {
                return;
            };
            if generation.try_get_untracked() != Some(ticket)
                || resource.revision.try_get_untracked() != Some(revision)
                || context.session_epoch.try_get_untracked() != Some(epoch)
            {
                return;
            }
            match result {
                Ok(value) => {
                    if context.finish_services_request(request, value.clone()) {
                        resource.data.set(value);
                    }
                    resource.error.set(None);
                }
                Err(error) => resource.error.set(Some(error)),
            }
            resource.loading.set(false);
        });
    });
    resource
}

#[component]
pub fn ServicesTab() -> impl IntoView {
    let context = app();
    let inventory = use_services_inventory();
    let query = RwSignal::new(String::new());
    let status = RwSignal::new("all".to_string());
    let selected = RwSignal::new(None::<Value>);
    let logs_open = RwSignal::new(false);
    let rows = Signal::derive(move || context.services.with(service_rows));
    let searched = use_worker_rows(
        rows,
        query.into(),
        vec![
            "name".into(),
            "id".into(),
            "status".into(),
            "version".into(),
        ],
    );
    let filtered = Memo::new(move |_| {
        let status = status.get();
        searched
            .get()
            .into_iter()
            .filter(|v| match status.as_str() {
                "core" => core_service(v),
                "attention" => attention(v),
                "running" => running(v),
                "stopped" => !running(v) && !attention(v),
                _ => true,
            })
            .collect::<Vec<_>>()
    });
    let refresh = Callback::new(move |()| inventory.refresh());
    view! {
        <section class="py-5 space-y-5 min-w-0 max-w-full">
            <header class="flex flex-wrap justify-between gap-4 pb-4 border-b border-white/10">
                <div>
                    <h2 class="text-2xl font-semibold">
                        {move || tt(context, "Tabs.servicesHeading")}
                    </h2>
                    <p class="text-slate-400 text-sm mt-2">
                        {move || tt(context, "Services.subtitle")}
                    </p>
                </div>
                <button
                    type="button"
                    class="glass-button px-4 py-2 min-h-11"
                    disabled=move || inventory.loading.get()
                    on:click=move |_| inventory.refresh()
                    aria-label=move || tt(context, "Refresh services")
                >
                    {move || tt(context, "Common.refresh")}
                </button>
            </header>
            <SearchInput value=query placeholder="Search services" />
            <div
                role="group"
                aria-label=move || tt(context, "Service status filters")
                class="flex flex-wrap gap-2"
            >
                {[
                    ("all", "Common.all"),
                    ("running", "Common.running"),
                    ("stopped", "Common.stopped"),
                    ("attention", "Services.attentionFailed"),
                    ("core", "Services.core"),
                ]
                    .into_iter()
                    .map(|(key, label)| {
                        view! {
                            <button
                                type="button"
                                class="obs-tab-pill px-4 py-2 min-h-11"
                                class:obs-tab-pill-active=move || status.get() == key
                                aria-pressed=move || (status.get() == key).to_string()
                                on:click=move |_| status.set(key.into())
                            >
                                {move || tt(context, label)}
                            </button>
                        }
                    })
                    .collect_view()}
            </div>
            <Show when=move || inventory.error.get().is_some()>
                <p role="alert" class="af-danger-banner">
                    {move || inventory.error.get().map(|e| tt(context, &e.message))}
                    <button class="ml-3 underline" on:click=move |_| inventory.refresh()>
                        {move || tt(context, "Retry")}
                    </button>
                </p>
            </Show>
            <Show when=move || inventory.loading.get() && rows.with(Vec::is_empty)>
                <p role="status" class="text-slate-400">
                    {move || tt(context, "Services.loading")}
                </p>
            </Show>
            {[
                ("core", "Services.corePlatform"),
                ("running", "Services.managedApplications"),
                ("attention", "Services.needsAttention"),
                ("stopped", "Services.inactiveUnits"),
            ]
                .into_iter()
                .map(|(key, title)| {
                    view! {
                        <ObsCard title=Signal::derive(move || tt(context, title))>
                            <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                                <For
                                    each=move || {
                                        filtered
                                            .get()
                                            .into_iter()
                                            .filter(|v| group(v) == key)
                                            .collect::<Vec<_>>()
                                    }
                                    key=|v| field(v, &["slug", "id", "name"])
                                    children=move |row| {
                                        let id = field(&row, &["slug", "id", "name"]);
                                        view! { <ServiceCard id rows refresh selected logs_open /> }
                                    }
                                />
                            </div>
                            <Show when=move || {
                                !filtered.with(|rows| rows.iter().any(|v| group(v) == key))
                            }>
                                <p class="text-xs text-slate-500 py-3">
                                    {move || tt(
                                        context,
                                        "No services in this group match the current filters.",
                                    )}
                                </p>
                            </Show>
                        </ObsCard>
                    }
                })
                .collect_view()}
            <Show when=move || !inventory.loading.get() && filtered.with(Vec::is_empty)>
                <EmptyState
                    title="No matching services"
                    description="Change the search or status filter, or refresh the inventory."
                />
            </Show>
            <Show when=move || {
                logs_open.get() && selected.with(Option::is_some) && context.is_admin()
            }>
                <ServiceLogsModal open=logs_open service=selected />
            </Show>
        </section>
    }
}

#[component]
fn ServiceCard(
    id: String,
    rows: Signal<Vec<Value>>,
    refresh: Callback<()>,
    selected: RwSignal<Option<Value>>,
    logs_open: RwSignal<bool>,
) -> impl IntoView {
    let context = app();
    let id = StoredValue::new(id);
    let info = Signal::derive(move || {
        rows.with(|rows| {
            rows.iter()
                .find(|v| field(v, &["slug", "id", "name"]) == id.get_value())
                .cloned()
                .unwrap_or(Value::Null)
        })
    });
    let busy = RwSignal::new(String::new());
    let action = move |action: &'static str| {
        if !context.is_admin() || !busy.get_untracked().is_empty() {
            return;
        }
        let row = info.get_untracked();
        if shared_vhost(&row) || row["managed_by"] == "embedded" {
            return;
        }
        let target = field(&row, &["id", "process", "slug"]);
        let process = field(&row, &["id", "process", "slug"]);
        let manager = field(&row, &["managed_by"]);
        let manager = if manager.is_empty() {
            "systemd".into()
        } else {
            manager
        };
        busy.set(action.into());
        spawn_local(async move {
            let result = ApiClient
                .post(
                    &format!(
                        "/api/v1/admin/services/{}/control",
                        js_sys::encode_uri_component(&target)
                    ),
                    Some(&json!({"action":action,"managed_by":manager,"process":process})),
                )
                .await;
            if busy.is_disposed() {
                return;
            }
            match result {
                Ok(receipt) => {
                    context.toast(if receipt["status"]=="accepted"{tt_with(context, "Restart scheduled for {target}; reconnecting to confirm runtime health.", &[("target", &(target).to_string())])}else{tt_with(context, "{action} completed for {target}", &[("action", &(tt(context, action)).to_string()), ("target", &(target).to_string())])},false);
                    refresh.run(());
                }
                Err(e) => {
                    context.toast(tt(context, &e.message), true);
                    refresh.run(());
                }
            }
            busy.set(String::new());
        });
    };
    let launch = Signal::derive(move || {
        info.with(|v| context.settings.with(|settings| launch_url(v, settings)))
    });
    let status_label = Signal::derive(move || {
        if busy.get().is_empty() {
            info.with(|value| {
                let status = field(value, &["status"]);
                tt(
                    context,
                    match status.as_str() {
                        "running" => "Services.statusRunning",
                        "stopped" => "Services.statusStopped",
                        "failed" => "Services.statusFailed",
                        "Integrated" | "integrated" => "Services.badgeIntegrated",
                        _ => &status,
                    },
                )
            })
        } else {
            let label = match busy.get().as_str() {
                "start" => "Start",
                "stop" => "Stop",
                _ => "Restart",
            };
            format!("{}…", tt(context, label))
        }
    });
    view! {
        <article class="af-service-tile min-w-0 rounded-xl p-4 border border-white/5 space-y-4">
            <div class="flex gap-3 justify-between items-start">
                <div class="min-w-0">
                    <h3 class="font-semibold break-words">
                        {move || info.with(|v| field(v, &["name", "slug", "id"]))}
                    </h3>
                    <p class="text-xs text-slate-500 break-all mt-1">
                        {move || info.with(|value| {
                            service_subtitle(value).split(" · ")
                                .map(|label| tt(context, label))
                                .collect::<Vec<_>>().join(" · ")
                        })}
                    </p>
                    <Show when=move || info.with(|value| value["managed_by"] == "embedded")>
                        <Badge
                            label=Signal::derive(move || tt(context, "Services.badgeIntegrated"))
                            tone="indigo"
                        />
                    </Show>
                </div>
                <span class="flex items-center gap-2 shrink-0">
                    <span
                        aria-hidden="true"
                        class=move || {
                            if info.with(running) {
                                "obs-beacon-live"
                            } else if info.with(attention) {
                                "obs-beacon-reconnecting"
                            } else {
                                "obs-beacon-offline"
                            }
                        }
                    ></span>
                    <Show when=move || info.with(|value| attention(value) && !running(value))>
                        <Badge label=status_label tone="danger" />
                    </Show>
                    <Show when=move || info.with(running)>
                        <Badge label=status_label tone="success" />
                    </Show>
                    <Show when=move || info.with(|value| running(value) && attention(value))>
                        <Badge label=Signal::derive(move || tt(context, "Needs attention")) tone="warning" />
                    </Show>
                    <Show when=move || info.with(|value| !attention(value) && !running(value))>
                        <Badge label=status_label tone="muted" />
                    </Show>
                </span>
            </div>
            <dl class="grid grid-cols-2 gap-3 text-xs">
                <div>
                    <dt class="text-slate-500">{move || tt(context, "Version")}</dt>
                    <dd class="text-slate-300 mt-1 break-all">
                        {move || {
                            info.with(|v| {
                                let version = field(v, &["installed_version", "version"]);
                                if version.is_empty() { tt(context, "Unreported") } else { tt(context, &version) }
                            })
                        }}
                    </dd>
                </div>
                <div>
                    <dt class="text-slate-500">{move || tt(context, "Uptime")}</dt>
                    <dd class="text-slate-300 mt-1">{move || info.with(|info| uptime_text(&crate::tabs::l10n::locale(context), info))}</dd>
                </div>
                {move || {
                    info.with(|v| {
                        resource_metrics(v)
                            .into_iter()
                            .map(|(label, value)| {
                                view! {
                                    <div>
                                        <dt class="text-slate-500">{move || tt(context, label)}</dt>
                                        <dd class="text-slate-300 mt-1">{move || tt(context, &value)}</dd>
                                    </div>
                                }
                            })
                            .collect_view()
                    })
                }}
            </dl>
            {move || {
                launch
                    .get()
                    .map(|url| {
                        view! {
                            <a
                                class="inline-flex glass-button px-3 py-2 min-h-11 items-center text-xs max-w-full break-all"
                                href=url
                                target="_blank"
                                rel="noopener noreferrer"
                            >
                                {move || tt(context, "Open App")}
                            </a>
                        }
                    })
            }}
            <Show when=move || context.is_admin()>
                <div class="flex flex-wrap gap-2 border-t border-white/5 pt-3">
                    {[("start", "Start"), ("stop", "Stop"), ("restart", "Restart")]
                        .into_iter()
                        .map(|(key, label)| {
                            view! {
                                <button
                                    type="button"
                                    class="glass-button px-3 py-2 text-xs min-h-11"
                                    disabled=move || {
                                        !busy.get().is_empty()
                                            || info
                                                .with(|v| shared_vhost(v) || v["managed_by"] == "embedded")
                                    }
                                    title=move || tt(context,
                                        if info.with(shared_vhost) {
                                            "Shared gateway: use the Apache service controls"
                                        } else if info.with(|v| v["managed_by"] == "embedded") {
                                            "Runs inside the API process"
                                        } else {
                                            "Control service"
                                        }
                                    )
                                    on:click=move |_| action(key)
                                >
                                    {move || tt(context, label)}
                                </button>
                            }
                        })
                        .collect_view()}
                    <button
                        type="button"
                        class="glass-button px-3 py-2 text-xs min-h-11"
                        on:click=move |_| {
                            if context.is_admin() {
                                selected.set(Some(info.get_untracked()));
                                logs_open.set(true);
                            }
                        }
                    >
                        {move || tt(context, "Logs")}
                    </button>
                </div>
                <Show when=move || info.with(|v| v["enabled"].is_boolean())>
                    <p
                        class="text-xs text-slate-500"
                        title=move || tt(
                            context,
                            "The service API supports start, stop, and restart. Boot policy is managed on the host.",
                        )
                    >
                        {move || {
                            info.with(|v| tt(context,
                                if v["enabled"] == true {
                                    "Enabled at boot"
                                } else {
                                    "Disabled at boot"
                                }
                            ))
                        }}
                    </p>
                </Show>
                <ServiceCredentials info />
            </Show>
        </article>
    }
}

#[component]
fn ServiceCredentials(info: Signal<Value>) -> impl IntoView {
    let context = app();
    let reveal = RwSignal::new(false);
    let credentials = Signal::derive(move || {
        if !context.is_admin() {
            return Vec::new();
        }
        info.with(|v| {
            [
                (
                    "API key",
                    v.get("api_key").or_else(|| v["credentials"].get("api_key")),
                ),
                (
                    "Username",
                    v.get("username")
                        .or_else(|| v["credentials"].get("username")),
                ),
                (
                    "Password",
                    v.get("password")
                        .or_else(|| v["credentials"].get("password")),
                ),
            ]
            .into_iter()
            .filter_map(|(label, value)| {
                value
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(|s| (label.to_string(), s.to_string()))
            })
            .collect::<Vec<_>>()
        })
    });
    Effect::new(move |_| {
        if !context.is_admin() {
            reveal.set(false);
        }
    });
    view! {
        <Show when=move || context.is_admin() && !credentials.with(Vec::is_empty)>
            <div class="border-t border-white/5 pt-3 space-y-2">
                <button
                    type="button"
                    class="text-xs text-indigo-300 min-h-11"
                    aria-pressed=move || reveal.get().to_string()
                    on:click=move |_| {
                        if context.is_admin() {
                            reveal.update(|v| *v = !*v);
                        }
                    }
                >
                    {move || tt(
                        context,
                        if reveal.get() { "Hide credentials" } else { "Reveal credentials" },
                    )}
                </button>
                {move || {
                    credentials
                        .get()
                        .into_iter()
                        .map(|(label, value)| {
                            let shown = value.clone();
                            view! {
                                <div class="flex flex-wrap gap-2 items-center min-w-0">
                                    <span class="text-xs text-slate-500">
                                        {move || tt(context, &label)}
                                    </span>
                                    <code class="text-xs text-slate-300 break-all">
                                        {move || {
                                            if context.is_admin() && reveal.get() {
                                                shown.clone()
                                            } else {
                                                "••••••••".into()
                                            }
                                        }}
                                    </code>
                                    <button
                                        type="button"
                                        class="glass-button text-xs px-2 py-2 min-h-11"
                                        on:click=move |_| {
                                            if !context.is_admin() {
                                                return;
                                            }
                                            let value = value.clone();
                                            spawn_local(async move {
                                                match copy_text(&value).await {
                                                    Ok(()) => {
                                                        context.toast(tt(context, "Credential copied"), false)
                                                    }
                                                    Err(e) => context.toast(tt(context, &e), true),
                                                }
                                            });
                                        }
                                    >
                                        {move || tt(context, "Copy")}
                                    </button>
                                </div>
                            }
                        })
                        .collect_view()
                }}
            </div>
        </Show>
    }
}
