//! Service inventory and guarded administrator controls.
mod helpers;
mod launch;
mod logs;
mod restart;

use self::helpers::*;
pub(crate) use self::helpers::{external_access_target, launch_url_with_host, safe_release_url};
pub(crate) use self::launch::launch_app;
pub(crate) use self::logs::ServiceLogsModal;
use self::restart::{CoreRestartPhase, CoreRestartTracker};
use crate::state::{app, run_resource_read, ApiResource, ResourceReads, TabId};
use crate::tabs::l10n::{tt, tt_with, Badge, ConfirmDialog, EmptyState, ObsCard, SearchInput};
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
    let status = RwSignal::new(
        context
            .take_pending_subtab(TabId::Services)
            .unwrap_or_else(|| "all".to_string()),
    );
    Effect::new(move |_| {
        context.pending_subtab.track();
        if let Some(target) = context.take_pending_subtab(TabId::Services) {
            status.set(target);
        }
    });
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
                "updates" => has_available_update(v),
                _ => true,
            })
            .collect::<Vec<_>>()
    });
    let updates_count = Signal::derive(move || {
        rows.with(|list| list.iter().filter(|v| has_available_update(v)).count())
    });
    let checking_updates = RwSignal::new(false);
    let checking_unit = RwSignal::new(None::<String>);
    let updating_unit = RwSignal::new(None::<String>);
    let refresh = Callback::new(move |()| inventory.refresh());
    let restarts = CoreRestartTracker::start_polling(context, refresh);
    let check_all_updates = move |_| {
        if !context.is_admin() || checking_updates.get_untracked() {
            return;
        }
        checking_updates.set(true);
        spawn_local(async move {
            let result = ApiClient
                .post("/api/v1/admin/packages/updates/check", None)
                .await;
            if checking_updates.is_disposed() {
                return;
            }
            checking_updates.set(false);
            match result {
                Ok(payload) => {
                    let count = payload["updates_available"].as_u64().unwrap_or_else(|| {
                        payload["updates"]
                            .as_array()
                            .map(|items| {
                                items
                                    .iter()
                                    .filter(|item| item["update_available"] == true)
                                    .count() as u64
                            })
                            .unwrap_or(0)
                    });
                    if count > 0 {
                        context.toast(
                            tt_with(
                                context,
                                "{count} application updates available.",
                                &[("count", &count.to_string())],
                            ),
                            false,
                        );
                    } else {
                        context.toast(
                            tt(context, "All installed applications are up to date."),
                            false,
                        );
                    }
                    inventory.refresh();
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
        });
    };
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
                <div class="flex flex-wrap gap-3">
                    <Show when=move || context.is_admin()>
                        <button
                            type="button"
                            class="glass-button px-4 py-2 min-h-11"
                            disabled=move || checking_updates.get()
                            on:click=check_all_updates
                        >
                            {move || {
                                if checking_updates.get() {
                                    tt(context, "Marketplace.checkingUpdates")
                                } else {
                                    tt(context, "Marketplace.checkUpdates")
                                }
                            }}
                        </button>
                    </Show>
                    <button
                        type="button"
                        class="glass-button px-4 py-2 min-h-11"
                        disabled=move || inventory.loading.get()
                        on:click=move |_| inventory.refresh()
                        aria-label=move || tt(context, "Refresh services")
                    >
                        {move || tt(context, "Common.refresh")}
                    </button>
                </div>
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
                    ("updates", "Services.updates"),
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
                                {if key == "updates" {
                                    Some(view! {
                                        <Show when=move || { updates_count.get() > 0 }>
                                            <span class="ml-1.5 text-xs font-mono text-amber-300">
                                                {move || format!("({})", updates_count.get())}
                                            </span>
                                        </Show>
                                    })
                                } else {
                                    None
                                }}
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
            <Show when=move || {
                context.is_admin()
                    && (!restarts.receipts.with(std::collections::BTreeMap::is_empty)
                        || restarts.notice.get().is_some())
            }>
                <div class="rounded-xl border border-indigo-400/20 bg-indigo-500/5 p-4 space-y-2 text-sm">
                    {move || {
                        restarts
                            .notice
                            .get()
                            .map(|notice| {
                                if notice.is_error {
                                    view! {
                                        <p role="alert" class="text-rose-300">
                                            {notice.message}
                                        </p>
                                    }
                                    .into_any()
                                } else {
                                    view! {
                                        <p role="status" class="text-cyan-300">
                                            {notice.message}
                                        </p>
                                    }
                                    .into_any()
                                }
                            })
                    }}
                    {move || {
                        restarts
                            .receipts
                            .get()
                            .into_values()
                            .map(|entry| {
                                let phase_key = match entry.phase {
                                    CoreRestartPhase::WaitingForJob => {
                                        "Waiting for systemd restart job completion"
                                    }
                                    CoreRestartPhase::WaitingForReadiness => {
                                        "Confirming API and database readiness"
                                    }
                                };
                                view! {
                                    <p class="text-xs text-slate-300 break-all">
                                        {tt_with(
                                            context,
                                            "{service} · Receipt: {receipt} · {phase}",
                                            &[
                                                ("service", &entry.label),
                                                ("receipt", &entry.job_unit),
                                                ("phase", &tt(context, phase_key)),
                                            ],
                                        )}
                                    </p>
                                }
                            })
                            .collect_view()
                    }}
                </div>
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
                                        view! {
                                            <ServiceCard
                                                id
                                                rows
                                                refresh
                                                selected
                                                logs_open
                                                restarts
                                                checking_unit
                                                updating_unit
                                            />
                                        }
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
    restarts: CoreRestartTracker,
    checking_unit: RwSignal<Option<String>>,
    updating_unit: RwSignal<Option<String>>,
) -> impl IntoView {
    let context = app();
    let id = StoredValue::new(id);
    let is_restarting = Signal::derive(move || restarts.is_restarting(&id.get_value()));
    let info = Signal::derive(move || {
        rows.with(|rows| {
            rows.iter()
                .find(|v| field(v, &["slug", "id", "name"]) == id.get_value())
                .cloned()
                .unwrap_or(Value::Null)
        })
    });
    let busy = RwSignal::new(String::new());
    let img_failed = RwSignal::new(false);
    let confirm_action = RwSignal::new(None::<&'static str>);
    let confirm_open = RwSignal::new(false);
    Effect::new(move |_| {
        if !confirm_open.get() {
            confirm_action.set(None);
        }
    });
    Effect::new(move |_| {
        info.with(|v| field(v, &["id"]));
        img_failed.set(false);
    });
    let action = move |action: &'static str| {
        if !context.is_admin() || !busy.get_untracked().is_empty() || is_restarting.get_untracked()
        {
            return;
        }
        let row = info.get_untracked();
        if shared_vhost(&row) || row["managed_by"] == "embedded" {
            return;
        }
        let target = field(&row, &["id", "process", "slug"]);
        let label = field(&row, &["name", "slug", "id"]);
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
                    if receipt["status"] == "accepted" {
                        restarts.track_accepted(
                            context,
                            id.get_value(),
                            target,
                            label,
                            &receipt,
                            refresh,
                        );
                    } else {
                        context.toast(
                            tt_with(
                                context,
                                "{action} completed for {target}",
                                &[
                                    ("action", &(tt(context, action)).to_string()),
                                    ("target", &(target).to_string()),
                                ],
                            ),
                            false,
                        );
                        refresh.run(());
                    }
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
        if is_restarting.get() {
            format!("{}…", tt(context, "Restart"))
        } else if busy.get().is_empty() {
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
    let trigger_check_update = move |_| {
        let pkg_id = info.with_untracked(|v| field(v, &["id"]));
        if !context.is_admin()
            || pkg_id.is_empty()
            || info.with_untracked(core_service)
            || checking_unit.with_untracked(|c| c.as_deref() == Some(pkg_id.as_str()))
        {
            return;
        }
        checking_unit.set(Some(pkg_id.clone()));
        spawn_local(async move {
            let result = ApiClient
                .post(
                    &format!(
                        "/api/v1/admin/packages/{}/check-update",
                        js_sys::encode_uri_component(&pkg_id)
                    ),
                    None,
                )
                .await;
            if checking_unit.is_disposed() {
                return;
            }
            checking_unit.set(None);
            match result {
                Ok(data) => {
                    if !field(&data, &["error", "last_error"]).is_empty() {
                        context.toast(tt(context, &field(&data, &["error", "last_error"])), true);
                    } else if data["update_available"] == true {
                        let latest = field(&data, &["latest_version"]);
                        context.toast(
                            tt_with(
                                context,
                                "Update available for {id}: {version}",
                                &[
                                    ("id", &pkg_id),
                                    (
                                        "version",
                                        &format!("v{}", latest.trim_start_matches(['v', 'V'])),
                                    ),
                                ],
                            ),
                            false,
                        );
                    } else {
                        context.toast(
                            tt_with(context, "{id} is up to date.", &[("id", &pkg_id)]),
                            false,
                        );
                    }
                    refresh.run(());
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
        });
    };
    let trigger_update = move |_| {
        let pkg_id = info.with_untracked(|v| field(v, &["id"]));
        if !context.is_admin()
            || pkg_id.is_empty()
            || info.with_untracked(core_service)
            || updating_unit.with_untracked(|u| u.as_deref() == Some(pkg_id.as_str()))
        {
            return;
        }
        let target_version = info.with_untracked(|v| field(v, &["latest_version"]));
        updating_unit.set(Some(pkg_id.clone()));
        spawn_local(async move {
            let body = if target_version.is_empty() {
                Value::Null
            } else {
                json!({ "expected_target_version": target_version })
            };
            let result = ApiClient
                .post(
                    &format!(
                        "/api/v1/admin/packages/{}/update",
                        js_sys::encode_uri_component(&pkg_id)
                    ),
                    (!body.is_null()).then_some(&body),
                )
                .await;
            if updating_unit.is_disposed() {
                return;
            }
            updating_unit.set(None);
            match result {
                Ok(_) => {
                    context.toast(
                        tt_with(context, "Update started for {id}", &[("id", &pkg_id)]),
                        false,
                    );
                    refresh.run(());
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
        });
    };
    let on_confirm_control = Callback::new(move |(): ()| {
        if let Some(op) = confirm_action.get_untracked() {
            confirm_open.set(false);
            confirm_action.set(None);
            action(op);
        }
    });
    view! {
        <article class="af-service-tile min-w-0 rounded-xl p-4 border border-white/5 space-y-4">
            <div class="flex gap-3 justify-between items-start">
                <div class="flex items-start gap-3 min-w-0">
                    {move || {
                        info.with(safe_service_icon).filter(|_| !img_failed.get()).map(|src| {
                            let alt = info.with(|v| field(v, &["name", "slug", "id"]));
                            view! {
                                <img
                                    src=src
                                    alt=alt
                                    class="h-8 w-8 rounded-lg object-contain bg-white/[0.04] border border-white/10 p-1 shrink-0"
                                    on:error=move |_| img_failed.set(true)
                                />
                            }
                        })
                    }}
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
                    <dt class="text-slate-500 flex items-center justify-between gap-2">
                        <span>{move || tt(context, "Version")}</span>
                        <Show when=move || context.is_admin() && info.with(|v| !core_service(v) && !field(v, &["id"]).is_empty())>
                            <button
                                type="button"
                                class="text-indigo-300 hover:text-indigo-200 underline text-xs"
                                disabled=move || checking_unit.with(|c| c.as_deref() == Some(info.with(|v| field(v, &["id"])).as_str()))
                                on:click=trigger_check_update
                            >
                                {move || {
                                    let pid = info.with(|v| field(v, &["id"]));
                                    if checking_unit.with(|c| c.as_deref() == Some(pid.as_str())) {
                                        tt(context, "Checking…")
                                    } else {
                                        tt(context, "Check update")
                                    }
                                }}
                            </button>
                        </Show>
                    </dt>
                    <dd class="text-slate-300 mt-1 break-all flex flex-wrap items-center gap-1.5">
                        <span>
                            {move || {
                                info.with(|v| {
                                    let version = field(v, &["installed_version", "version"]);
                                    if version.is_empty() { tt(context, "Unreported") } else { tt(context, &version) }
                                })
                            }}
                        </span>
                        <Show when=move || info.with(has_available_update)>
                            {move || {
                                info.with(|v| {
                                    let latest = field(v, &["latest_version"]);
                                    let badge_text = if latest.is_empty() {
                                        tt(context, "Update available")
                                    } else {
                                        tt_with(
                                            context,
                                            "Update {version}",
                                            &[("version", &format!("v{}", latest.trim_start_matches(['v', 'V'])))],
                                        )
                                    };
                                    match safe_release_url(v) {
                                        Some(url) => view! {
                                            <a
                                                href=url
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                title=move || tt(context, "View release notes")
                                                class="text-amber-300 underline hover:text-amber-200 font-semibold"
                                            >
                                                {badge_text}
                                            </a>
                                        }
                                        .into_any(),
                                        None => view! {
                                            <span class="text-amber-300 font-semibold">{badge_text}</span>
                                        }
                                        .into_any(),
                                    }
                                })
                            }}
                        </Show>
                    </dd>
                </div>
                <div>
                    <dt class="text-slate-500">{move || tt(context, "Uptime")}</dt>
                    <dd class="text-slate-300 mt-1">{move || info.with(|info| uptime_text(&crate::tabs::l10n::locale(context), info))}</dd>
                </div>
                {move || {
                    info.with(|v| {
                        let reassigned = reassigned_default_port(v);
                        resource_metrics(v)
                            .into_iter()
                            .map(|(label, value)| {
                                let default_badge = if label == "Port" {
                                    reassigned.map(|(_, def)| format!("def :{def}"))
                                } else {
                                    None
                                };
                                view! {
                                    <div>
                                        <dt class="text-slate-500">{move || tt(context, label)}</dt>
                                        <dd class="text-slate-300 mt-1 flex flex-wrap items-center gap-1.5">
                                            <span>{move || tt(context, &value)}</span>
                                            {default_badge.map(|badge| view! {
                                                <span
                                                    class="text-xs px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono"
                                                    title=move || tt(context, "Dynamically reassigned from default port")
                                                >
                                                    {badge}
                                                </span>
                                            })}
                                        </dd>
                                    </div>
                                }
                            })
                            .collect_view()
                    })
                }}
            </dl>
            <Show when=move || info.with(|v| !core_service(v) && !field(v, &["update_error"]).is_empty())>
                <p role="note" class="text-xs text-rose-300 break-words">
                    {move || info.with(|v| {
                        tt_with(
                            context,
                            "Update check failed: {error}",
                            &[("error", &field(v, &["update_error"]))],
                        )
                    })}
                </p>
            </Show>
            <Show when=move || info.with(is_failed_install)>
                <div role="status" class="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200 space-y-1">
                    <p class="font-semibold">
                        {move || tt(context, "Install failed — rollback or recovery is unconfirmed.")}
                    </p>
                    <p class="break-words">
                        {move || info.with(|v| {
                            let msg = field(&v["last_job"], &["sanitized_summary", "message"]);
                            if msg.is_empty() {
                                tt(context, "Inspect installation failure logs before starting or restarting.")
                            } else {
                                msg
                            }
                        })}
                    </p>
                </div>
            </Show>
            <Show when=move || info.with(|v| {
                !is_failed_install(v)
                    && !field(&v["last_job"], &["status"]).is_empty()
                    && field(&v["last_job"], &["status"]) != "completed"
            })>
                <p role="status" class="text-xs text-rose-300 break-words">
                    {move || info.with(|v| {
                        let last = &v["last_job"];
                        let act = field(last, &["action"]);
                        let st = field(last, &["status"]);
                        let msg = field(last, &["sanitized_summary", "message"]);
                        if msg.is_empty() {
                            tt_with(context, "Last {action}: {status}", &[("action", &tt(context, &act)), ("status", &tt(context, &st))])
                        } else {
                            tt_with(context, "Last {action}: {status} — {message}", &[("action", &tt(context, &act)), ("status", &tt(context, &st)), ("message", &msg)])
                        }
                    })}
                </p>
            </Show>
            <Show when=move || info.with(|v| v["components"].as_array().is_some_and(|c| c.len() > 1))>
                <ul
                    aria-label=move || tt(context, "Service components")
                    class="divide-y divide-white/[0.06] text-xs text-slate-400 border-t border-white/5 pt-2"
                >
                    {move || {
                        info.with(|v| {
                            v["components"]
                                .as_array()
                                .cloned()
                                .unwrap_or_default()
                                .into_iter()
                                .map(|component| {
                                    let comp_unit = field(&component, &["unit"]);
                                    let comp_status = field(&component, &["status"]);
                                    let comp_role = field(&component, &["role"]);
                                    let unit_for_logs = comp_unit.clone();
                                    let unit_title = tt_with(
                                        context,
                                        "View logs for {unit}",
                                        &[("unit", &comp_unit)],
                                    );
                                    view! {
                                        <li class="flex items-center justify-between gap-2 py-1.5 min-w-0">
                                            <span class="break-all">
                                                {format!(
                                                    "{}: {} ({})",
                                                    comp_unit,
                                                    if comp_status.is_empty() { "unknown" } else { &comp_status },
                                                    if comp_role.is_empty() { "required" } else { &comp_role },
                                                )}
                                            </span>
                                            {context.is_admin().then(|| view! {
                                                <button
                                                    type="button"
                                                    class="glass-button px-2.5 py-1 text-xs shrink-0"
                                                    title=unit_title.clone()
                                                    on:click=move |_| {
                                                        let mut row = info.get_untracked();
                                                        row["initial_unit"] = json!(unit_for_logs.clone());
                                                        selected.set(Some(row));
                                                        logs_open.set(true);
                                                    }
                                                >
                                                    {move || tt(context, "Logs")}
                                                </button>
                                            })}
                                        </li>
                                    }
                                })
                                .collect_view()
                        })
                    }}
                </ul>
            </Show>
            <div class="flex flex-wrap gap-2 items-center">
                {move || {
                    launch
                        .get()
                        .map(|url| {
                            let destination = url.clone();
                            view! {
                                <a
                                    class="inline-flex glass-button px-3 py-2 min-h-11 items-center text-xs max-w-full break-all"
                                    href=url
                                    on:click=move |event| info.with_untracked(|service| {
                                        launch_app(context, event, service, &destination);
                                    })
                                    target="_blank"
                                    rel="noopener noreferrer"
                                >
                                    {move || tt(context, "Open App")}
                                </a>
                            }
                        })
                }}
                <Show when=move || {
                    context.is_admin() && info.with(external_access_target).is_some()
                }>
                    <button
                        type="button"
                        class="inline-flex glass-button px-3 py-2 min-h-11 items-center text-xs"
                        title=move || {
                            let name = info.with(|v| field(v, &["name", "slug", "id"]));
                            tt_with(context, "Configure external access for {name}", &[("name", &name)])
                        }
                        on:click=move |_| {
                            if let Some(target) = info.with_untracked(external_access_target) {
                                context.navigate_to_subtab(TabId::Network, target);
                            }
                        }
                    >
                        {move || tt(context, "External access")}
                    </button>
                </Show>
            </div>
            <Show when=move || context.is_admin()>
                <Show when=move || info.with(has_available_update)>
                    <button
                        type="button"
                        class="glass-button-primary w-full px-3 py-2 text-xs min-h-11"
                        disabled=move || {
                            !busy.get().is_empty()
                                || is_restarting.get()
                                || updating_unit.with(|u| u.as_deref() == Some(info.with(|v| field(v, &["id"])).as_str()))
                        }
                        on:click=trigger_update
                    >
                        {move || {
                            let pid = info.with(|v| field(v, &["id"]));
                            let name = info.with(|v| field(v, &["name", "slug", "id"]));
                            if updating_unit.with(|u| u.as_deref() == Some(pid.as_str())) {
                                tt(context, "Updating…")
                            } else {
                                tt_with(context, "Update {name}", &[("name", &name)])
                            }
                        }}
                    </button>
                </Show>
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
                                            || is_restarting.get()
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
                                    on:click=move |_| {
                                        if key == "stop" || info.with_untracked(is_failed_install) {
                                            confirm_action.set(Some(key));
                                            confirm_open.set(true);
                                        } else {
                                            action(key);
                                        }
                                    }
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
                <ConfirmDialog
                    open=confirm_open
                    title=Signal::derive(move || {
                        let name = info.with(|v| field(v, &["name", "slug", "id"]));
                        match confirm_action.get() {
                            Some("stop") => tt_with(context, "Stop {name}?", &[("name", &name)]),
                            Some("start") => tt_with(
                                context,
                                "Start {name} after failed install?",
                                &[("name", &name)],
                            ),
                            _ => tt_with(
                                context,
                                "Restart {name} after failed install?",
                                &[("name", &name)],
                            ),
                        }
                    })
                    message=Signal::derive(move || match confirm_action.get() {
                        Some("stop") => tt(
                            context,
                            "Stopping this service interrupts active connections until started again.",
                        ),
                        _ => tt(
                            context,
                            "The previous install failed and recovery state is unconfirmed. Review installation logs before continuing.",
                        ),
                    })
                    on_confirm=on_confirm_control
                />
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
