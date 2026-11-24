//! Installed media pipeline, configuration evidence and human-gated transcodes.
use super::contracts::MediaFlowLiveProgress;
use crate::state::{app, json_rows, use_api_when, PeerArea, TabId};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{Badge, ConfirmDialog, EmptyState, ObsCard};
use crate::tabs::GrantInvalidationBoundary;
use af_web_core::api::{api_url, ApiClient};
use af_web_ui::SkeletonBox;
use gloo_events::EventListener;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

mod helpers;
use helpers::*;

const MEDIAFLOW_STREAM_REQS: [(PeerArea, bool); 2] = [
    (PeerArea::Transcoding, false),
    (PeerArea::Marketplace, false),
];

#[component]
pub fn MediaflowTab() -> impl IntoView {
    let context = app();
    let can_read_services = Signal::derive(move || context.can_read_area(PeerArea::Services));
    let can_read_marketplace = Signal::derive(move || context.can_read_area(PeerArea::Marketplace));
    let can_read_transcoding = Signal::derive(move || context.can_read_area(PeerArea::Transcoding));
    let resource = use_api_when(
        can_read_services,
        Signal::derive(|| "/api/v1/auth/services".to_string()),
    );
    let can_read_blueprints =
        Signal::derive(move || context.is_admin() && can_read_marketplace.get());
    let blueprints = use_api_when(
        can_read_blueprints,
        Signal::derive(|| "/api/v1/auth/blueprints".to_string()),
    );
    let refresh_blueprints = move || {
        if context.is_admin_untracked() && context.can_read_area_untracked(PeerArea::Marketplace) {
            blueprints.refresh();
        }
    };
    let rows = Memo::new(move |_| services(&resource.data.get()));
    let busy = RwSignal::new(false);
    let syncing = RwSignal::new(None::<String>);
    let sync_ticket = RwSignal::new(0u64);
    let stream_requested = RwSignal::new(false);
    let queue_summary = RwSignal::new(None::<super::contracts::MediaFlowQueueSummary>);
    let sync_results = RwSignal::new(std::collections::BTreeMap::<String, Value>::new());
    let blueprint_sync_reqs = [(PeerArea::Marketplace, true), (PeerArea::Network, true)];
    let sync = Callback::new(move |id: String| {
        if syncing.with_untracked(Option::is_some)
            || !context.is_admin()
            || !context.can_all_areas(&blueprint_sync_reqs)
        {
            return;
        }
        let session_epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let sync_grant =
            context.areas_revocation_epoch_untracked(&[PeerArea::Marketplace, PeerArea::Network]);
        sync_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = sync_ticket.get_untracked();
        syncing.set(Some(id.clone()));
        spawn_local(async move {
            let is_current = || {
                sync_ticket.try_get_untracked() == Some(ticket)
                    && context.session_epoch.try_get_untracked() == Some(session_epoch)
                    && context.server_epoch.try_get_untracked() == Some(server_epoch)
                    && context.areas_revocation_epoch_untracked(&[
                        PeerArea::Marketplace,
                        PeerArea::Network,
                    ]) == sync_grant
                    && context.can_all_areas_untracked(&blueprint_sync_reqs)
            };
            if !is_current() {
                return;
            }
            let response = ApiClient
                .fetch(
                    &format!(
                        "/api/v1/admin/blueprints/{}/sync",
                        js_sys::encode_uri_component(&id)
                            .as_string()
                            .unwrap_or_default()
                    ),
                    "POST",
                    None,
                )
                .await;
            if !is_current() {
                return;
            }
            match response {
                Ok(raw) => {
                    let ok = raw.ok();
                    let body = raw.text().await;
                    if !is_current() {
                        return;
                    }
                    match body {
                        Ok(body) => {
                            let data: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                            if data["result"].is_object() {
                                sync_results.update(|results| {
                                    results.insert(id, data["result"].clone());
                                });
                            }
                            if ok {
                                if context.can_all_areas_untracked(&MEDIAFLOW_STREAM_REQS) {
                                    stream_requested.set(true);
                                }
                                let has_warnings = data["result"]["warnings"]
                                    .as_array()
                                    .is_some_and(|warnings| !warnings.is_empty());
                                let message = if has_warnings {
                                    data["message"]
                                        .as_str()
                                        .unwrap_or("Application configuration synchronized.")
                                } else {
                                    "Application configuration synchronized."
                                };
                                context.toast(tt(context, message), false);
                                if context.can_read_area_untracked(PeerArea::Services) {
                                    resource.refresh();
                                }
                                refresh_blueprints();
                            } else {
                                if data["partial_commit"].as_bool() == Some(true) {
                                    if context.can_read_area_untracked(PeerArea::Services) {
                                        resource.refresh();
                                    }
                                    refresh_blueprints();
                                }
                                let message = data["message"]
                                    .as_str()
                                    .or_else(|| data["error"].as_str())
                                    .unwrap_or("Request failed");
                                context.toast(tt(context, message), true);
                            }
                        }
                        Err(e) => context.toast(tt(context, &e.message), true),
                    }
                }
                Err(e) => context.toast(tt(context, &e.message), true),
            }
            if sync_ticket.try_get_untracked() == Some(ticket) {
                let _ = syncing.try_set(None);
            }
        });
    });
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        sync_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        syncing.set(None);
        sync_results.set(std::collections::BTreeMap::new());
        queue_summary.set(None);
        stream_requested.set(false);
    });
    Effect::new(move |_| {
        context.area_revocation_epoch(PeerArea::Transcoding);
        if !can_read_transcoding.get() {
            queue_summary.set(None);
            stream_requested.set(false);
        }
    });
    Effect::new(move |_| {
        context.areas_revocation_epoch(&[PeerArea::Marketplace, PeerArea::Network]);
        if !context.can_all_areas(&blueprint_sync_reqs) {
            sync_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            syncing.set(None);
            sync_results.set(std::collections::BTreeMap::new());
        }
    });
    let refresh = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        10_000,
        move || {
            if context.can_read_area_untracked(PeerArea::Services)
                && !resource.loading.get_untracked()
            {
                resource.refresh();
            }
        },
    )));
    on_cleanup(move || refresh.set_value(None));
    view! {
        <section class="space-y-5 py-5 min-w-0 max-w-full">
            <div class="flex flex-wrap justify-between gap-3 items-center">
                <div>
                    <h2 class="text-xl font-semibold">
                        {move || tt(context, "Tabs.mediaflowHeading")}
                    </h2>
                    <p class="text-sm text-slate-400">
                        {move || tt(
                            context,
                            "Request → Indexer → Downloader → Automation → Media Server",
                        )}
                    </p>
                </div>
                <button
                    class="glass-button px-4 py-2"
                    disabled=move || {
                        resource.loading.get()
                            || (!can_read_services.get() && !can_read_blueprints.get())
                    }
                    title=move || {
                        if !can_read_services.get() && !can_read_blueprints.get() {
                            context
                                .area_block_reason(PeerArea::Services, false)
                                .unwrap_or_default()
                        } else {
                            String::new()
                        }
                    }
                    on:click=move |_| {
                        if context.can_read_area_untracked(PeerArea::Services) {
                            resource.refresh();
                        }
                        refresh_blueprints();
                    }
                    aria-label=move || tt(context, "Refresh pipeline")
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
            <Show when=move || context.is_admin() && !can_read_marketplace.get()>
                <p
                    role="status"
                    class="rounded-xl border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
                >
                    {move || {
                        context
                            .area_block_reason(PeerArea::Marketplace, false)
                            .unwrap_or_default()
                    }}
                </p>
            </Show>
            {move || {
                resource
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
            {move || {
                blueprints
                    .error
                    .get()
                    .map(|e| {
                        view! {
                            <p role="alert" class="text-rose-300">
                                {move || tt_with(context, "Wiring evidence unavailable: {error}", &[("error", &(e.message).to_string())])}
                            </p>
                        }
                    })
            }}
            <Show when=move || resource.loading.get() && resource.data.with(Value::is_null)>
                <SkeletonBox class="h-60" />
            </Show>
            <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-3">
                {STAGES
                    .into_iter()
                    .map(|(stage, ids)| {
                        view! {
                            <ObsCard title=stage>
                                <div class="space-y-4">
                                    {move || {
                                        let apps = rows
                                            .get()
                                            .into_iter()
                                            .filter(|service| {
                                                ids
                                                    .contains(
                                                        &text(service, "id").to_ascii_lowercase().as_str(),
                                                    ) && installed(service)
                                            })
                                            .collect::<Vec<_>>();
                                        if apps.is_empty() {
                                            return view! {
                                                <div class="space-y-3">
                                                    <p class="text-sm text-slate-400">
                                                        {move || tt(
                                                            context,
                                                            "No installed application in this stage.",
                                                        )}
                                                    </p>
                                                    <p class="text-xs text-slate-500">{ids.join(" / ")}</p>
                                                    <button
                                                        class="glass-button-primary px-3 py-2 text-sm"
                                                        on:click=move |_| context.select_tab(TabId::Marketplace)
                                                    >
                                                        {move || tt(context, "Provision in Marketplace")}
                                                    </button>
                                                </div>
                                            }
                                                .into_any();
                                        }
                                        apps.into_iter()
                                            .map(|service| {
                                                let id = text(&service, "id");
                                                let sync_id = id.clone();
                                                let lookup_id = id.clone();
                                                let blueprint = blueprints
                                                    .data
                                                    .with(|v| {
                                                        v["blueprints"]
                                                            .as_array()
                                                            .and_then(|all| {
                                                                all.iter()
                                                                    .find(|b| {
                                                                        b["blueprint"]["app_name"] == id
                                                                            || b["blueprint"]["appName"] == id || b["app_name"] == id
                                                                            || b["appName"] == id
                                                                    })
                                                            })
                                                            .cloned()
                                                    })
                                                    .unwrap_or(Value::Null);
                                                let contract = super::contracts::decode::<super::contracts::MediaFlowServiceContract>(&service);
                                                let wired = contract.wired.or(contract.auto_configured).or_else(|| blueprint["config_applied"].as_bool());
                                                let has_key = contract.api_key.as_deref().is_some_and(|key| !key.is_empty());
                                                let running = matches!(contract.status.as_str(), "running" | "active");
                                                let is_remote = context.is_remote();
                                                let launch_settings = if !is_remote
                                                    || context.can_read_area(PeerArea::Settings)
                                                {
                                                    context.settings.get()
                                                } else {
                                                    Value::Null
                                                };
                                                view! {
                                                    <article class="space-y-2 border-t border-white/10 pt-3 min-w-0">
                                                        <h3 class="font-semibold break-words">
                                                            {text(&service, "name")}
                                                        </h3>
                                                        <Badge
                                                            label=text(&service, "status")
                                                            tone=if running { "success" } else { "warning" }
                                                        />
                                                        <p class="text-xs text-slate-400">
                                                            {move || tt(
                                                                context,
                                                                if wired == Some(true) {
                                                                    "API wiring confirmed by configuration status"
                                                                } else if wired == Some(false) {
                                                                    "API wiring requires configuration"
                                                                } else if has_key {
                                                                    "API credential detected · wiring unverified"
                                                                } else {
                                                                    "API wiring status not reported"
                                                                },
                                                            )}
                                                        </p>
                                                        {safe_launch_url_for_server(
                                                            &service,
                                                            &launch_settings,
                                                            is_remote,
                                                        )
                                                            .map(|url| {
                                                                view! {
                                                                    <a
                                                                        class="glass-button inline-block px-3 py-2 text-sm"
                                                                        href=url
                                                                        target="_blank"
                                                                        rel="noopener noreferrer"
                                                                    >
                                                                        {move || tt(context, "Launch")}
                                                                    </a>
                                                                }
                                                            })}
                                                        <button
                                                            class="glass-button px-3 py-2 text-sm"
                                                            on:click=move |_| context.select_tab(TabId::Services)
                                                        >
                                                            {move || tt(context, "Configure in Services")}
                                                        </button>
                                                        {(!blueprint.is_null() && context.is_admin())
                                                            .then(|| {
                                                                view! {
                                                                    <button
                                                                        class="glass-button px-3 py-2 text-sm"
                                                                        disabled=move || {
                                                                            syncing.with(Option::is_some)
                                                                                || !context.can_all_areas(&blueprint_sync_reqs)
                                                                        }
                                                                        title=move || {
                                                                            context
                                                                                .areas_block_reason(&blueprint_sync_reqs)
                                                                                .unwrap_or_default()
                                                                        }
                                                                        on:click=move |_| sync.run(sync_id.clone())
                                                                    >
                                                                        {move || tt(context, "Sync Zero-Touch configuration")}
                                                                    </button>
                                                                }
                                                            })}
                                                        {move || {
                                                            sync_results
                                                                .with(|all| all.get(&lookup_id).cloned())
                                                                .map(|result| {
                                                                    view! {
                                                                        <p class="text-xs text-indigo-300">
                                                                            {move || tt_with(context, "Configuration: {configuration} · ingress: {ingress} · hosts: {hosts} · DNS: {dns}", &[("configuration", &(tt(context, &(result["config_applied"]).to_string())).to_string()), ("ingress", &(tt(context, &(result["ingress_synced"]).to_string())).to_string()), ("hosts", &(tt(context, &(result["hosts_synced"]).to_string())).to_string()), ("dns", &(tt(context, &(result["network_dns_synced"]).to_string())).to_string())])}
                                                                        </p>
                                                                    }
                                                                })
                                                        }}
                                                    </article>
                                                }
                                            })
                                            .collect_view()
                                            .into_any()
                                    }}
                                </div>
                            </ObsCard>
                        }
                    })
                    .collect_view()}
            </div>
            <ObsCard title="Pipeline service & queue telemetry">
                <div class="grid sm:grid-cols-3 gap-4">
                    {[
                        ("Installed download clients", DOWNLOAD_CLIENT_IDS),
                        ("Installed automation apps", AUTOMATION_APP_IDS),
                    ]
                        .into_iter()
                        .map(|(label, ids)| {
                            view! {
                                <div>
                                    <p class="text-sm text-slate-400">
                                        {move || tt(context, label)}
                                    </p>
                                    <p class="text-xl font-semibold">
                                        {move || {
                                            let (active, installed_count) =
                                                pipeline_service_counts(&rows.get(), ids);
                                            if installed_count == 0 {
                                                tt(context, "None installed")
                                            } else {
                                                tt_with(
                                                    context,
                                                    "{active} active / {installed} installed",
                                                    &[
                                                        ("active", &active.to_string()),
                                                        ("installed", &installed_count.to_string()),
                                                    ],
                                                )
                                            }
                                        }}
                                    </p>
                                </div>
                            }
                        })
                        .collect_view()}
                    <div>
                        <p class="text-sm text-slate-400">
                            {move || tt(context, "Transcode queue")}
                        </p>
                        <p class="text-xl font-semibold">
                            {move || {
                                if !context.is_admin() {
                                    tt(context, "Common.adminRequired")
                                } else if !can_read_transcoding.get() {
                                    context
                                        .area_block_reason(PeerArea::Transcoding, false)
                                        .unwrap_or_default()
                                } else if let Some(summary) = queue_summary.get() {
                                    tt_with(
                                        context,
                                        "{queued} queued · {pending} pending approval · {processing} processing · {saved} saved",
                                        &[
                                            ("queued", &summary.queued.to_string()),
                                            ("pending", &summary.pending.to_string()),
                                            ("processing", &summary.processing.to_string()),
                                            ("saved", &bytes(summary.saved_bytes)),
                                        ],
                                    )
                                } else {
                                    tt(context, "Loading")
                                }
                            }}
                        </p>
                    </div>
                </div>
            </ObsCard>
            <Show
                when=move || context.is_admin()
                fallback=move || {
                    view! {
                        <EmptyState title="Common.adminRequired" />
                    }
                }
            >
                <GrantInvalidationBoundary areas=&[PeerArea::Transcoding]>
                    <MediaflowQueue busy stream_requested queue_summary />
                </GrantInvalidationBoundary>
            </Show>
        </section>
    }
}

fn deploy_stream_url() -> String {
    api_url("/api/v1/auth/deploy/stream?appName=mediaflow_engine")
}

#[component]
fn MediaflowQueue(
    busy: RwSignal<bool>,
    stream_requested: RwSignal<bool>,
    queue_summary: RwSignal<Option<super::contracts::MediaFlowQueueSummary>>,
) -> impl IntoView {
    let context = app();
    let can_read_transcoding = Signal::derive(move || context.can_read_area(PeerArea::Transcoding));
    let can_open_stream = Signal::derive(move || context.can_all_areas(&MEDIAFLOW_STREAM_REQS));
    let queue = use_api_when(
        can_read_transcoding,
        Signal::derive(|| "/api/v1/admin/mediaflow/queue".to_string()),
    );
    let directory = RwSignal::new(DEFAULT_SCAN_DIRECTORY.to_string());
    let progress = RwSignal::new(Value::Null);
    let connected = RwSignal::new(false);
    let stream_error = RwSignal::new(None::<String>);
    let source = StoredValue::new_local(
        None::<(
            web_sys::EventSource,
            EventListener,
            EventListener,
            EventListener,
        )>,
    );
    let connect = Callback::new(move |()| {
        source.update_value(|source| {
            if let Some((events, _, _, _)) = source.take() {
                events.close();
            }
        });
        if !context.can_all_areas_untracked(&MEDIAFLOW_STREAM_REQS) {
            connected.set(false);
            stream_requested.set(false);
            return;
        }
        stream_error.set(None);
        let origin_session_epoch = context.session_epoch.get_untracked();
        let origin_server_epoch = context.server_epoch.get_untracked();
        let origin_grant_epoch = context
            .areas_revocation_epoch_untracked(&[PeerArea::Transcoding, PeerArea::Marketplace]);
        let stream_url = deploy_stream_url();
        let Ok(events) = web_sys::EventSource::new(&stream_url) else {
            stream_error.set(Some("Live transcode stream could not be opened.".into()));
            stream_requested.set(false);
            return;
        };
        let completed_events = events.clone();
        let message = EventListener::new(&events, "message", move |event| {
            if context.session_epoch.try_get_untracked() != Some(origin_session_epoch)
                || context.server_epoch.try_get_untracked() != Some(origin_server_epoch)
                || context.areas_revocation_epoch_untracked(&[
                    PeerArea::Transcoding,
                    PeerArea::Marketplace,
                ]) != origin_grant_epoch
                || !context.can_all_areas_untracked(&MEDIAFLOW_STREAM_REQS)
            {
                completed_events.close();
                return;
            }
            if let Some(data) = event
                .dyn_ref::<web_sys::MessageEvent>()
                .and_then(|e| e.data().as_string())
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            {
                let terminal =
                    is_terminal_mediaflow_event(data["status"].as_str().unwrap_or_default());
                progress.set(data);
                connected.set(!terminal);
                stream_error.set(None);
                if terminal {
                    completed_events.close();
                    stream_requested.set(false);
                    if context.can_read_area_untracked(PeerArea::Transcoding) {
                        queue.refresh();
                    }
                }
            }
        });
        let opened_events = events.clone();
        let opened = EventListener::new(&events, "open", move |_| {
            if context.session_epoch.try_get_untracked() != Some(origin_session_epoch)
                || context.server_epoch.try_get_untracked() != Some(origin_server_epoch)
                || context.areas_revocation_epoch_untracked(&[
                    PeerArea::Transcoding,
                    PeerArea::Marketplace,
                ]) != origin_grant_epoch
                || !context.can_all_areas_untracked(&MEDIAFLOW_STREAM_REQS)
            {
                opened_events.close();
                return;
            }
            connected.set(true);
            stream_error.set(None);
        });
        let failed_events = events.clone();
        let error = EventListener::new(&events, "error", move |_| {
            failed_events.close();
            if context.session_epoch.try_get_untracked() != Some(origin_session_epoch)
                || context.server_epoch.try_get_untracked() != Some(origin_server_epoch)
                || context.areas_revocation_epoch_untracked(&[
                    PeerArea::Transcoding,
                    PeerArea::Marketplace,
                ]) != origin_grant_epoch
                || !context.can_all_areas_untracked(&MEDIAFLOW_STREAM_REQS)
            {
                return;
            }
            connected.set(false);
            stream_requested.set(false);
            stream_error.set(Some(
                "No active deployment stream. Connect again after starting work.".into(),
            ));
        });
        source.set_value(Some((events, message, opened, error)));
    });
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.areas_revocation_epoch(&[PeerArea::Transcoding, PeerArea::Marketplace]);
        let allowed = can_open_stream.get();
        if !allowed {
            stream_requested.set(false);
        }
        source.update_value(|source| {
            if let Some((events, _, _, _)) = source.take() {
                events.close();
            }
        });
        progress.set(Value::Null);
        connected.set(false);
        stream_error.set(None);
    });
    Effect::new(move |_| {
        if stream_requested.get() && can_open_stream.get() {
            connect.run(());
        }
    });
    on_cleanup(move || {
        source.update_value(|source| {
            if let Some((events, _, _, _)) = source.take() {
                events.close();
            }
        })
    });
    let refresh = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        10_000,
        move || {
            if context.can_read_area_untracked(PeerArea::Transcoding)
                && !queue.loading.get_untracked()
            {
                queue.refresh();
            }
        },
    )));
    on_cleanup(move || refresh.set_value(None));
    let rows = Memo::new(move |_| {
        super::contracts::grid_rows::<super::contracts::MediaFlowQueueRecord>(&queue.data.get())
    });
    Effect::new(move |_| {
        if !can_read_transcoding.get() || queue.data.with(Value::is_null) {
            queue_summary.set(None);
        } else {
            queue_summary.set(Some(super::contracts::MediaFlowQueueSummary::from_jobs(
                &rows.get(),
            )));
        }
    });
    let candidate = RwSignal::new(None::<(i64, String, Value)>);
    let confirm = RwSignal::new(false);
    let action_ticket = RwSignal::new(0u64);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Transcoding);
        if !context.can_write_area(PeerArea::Transcoding) {
            action_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            busy.set(false);
            confirm.set(false);
        }
    });
    let decide = Callback::new(move |(): ()| {
        if busy.get_untracked()
            || !context.is_admin()
            || !context.can_write_area(PeerArea::Transcoding)
        {
            return;
        }
        let Some((id, verb, row)) = candidate.get_untracked() else {
            return;
        };
        let session_epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let transcode_grant = context.area_revocation_epoch_untracked(PeerArea::Transcoding);
        action_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = action_ticket.get_untracked();
        let (endpoint, payload) = decision_endpoint_and_payload(id, &verb, &row);
        busy.set(true);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(busy, action_ticket, ticket);
        spawn_local(async move {
            let result = ApiClient.post(&endpoint, payload.as_ref()).await;
            if busy.try_get_untracked().is_none()
                || action_ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Transcoding) != transcode_grant
                || !context.can_write_area_untracked(PeerArea::Transcoding)
            {
                return;
            }
            match result {
                Ok(data) => {
                    if verb == "approve" && context.can_all_areas_untracked(&MEDIAFLOW_STREAM_REQS)
                    {
                        stream_requested.set(true);
                    }
                    let fallback = if verb == "approve" {
                        "Transcode approved and queued."
                    } else if verb == "cancel" {
                        "Transcode cancelled."
                    } else {
                        "Transcode declined."
                    };
                    let msg = data["message"]
                        .as_str()
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or(fallback);
                    context.toast(tt(context, msg), false);
                    if context.can_read_area_untracked(PeerArea::Transcoding) {
                        queue.refresh();
                    }
                }
                Err(e) => {
                    context.toast(tt(context, &e.message), true);
                    if context.can_read_area_untracked(PeerArea::Transcoding) {
                        queue.refresh();
                    }
                }
            }
            busy_guard.release();
            confirm.set(false);
        });
    });
    let scan = Callback::new(move |(): ()| {
        if busy.get_untracked() || !context.can_write_area(PeerArea::Transcoding) {
            return;
        }
        let path = directory.get_untracked().trim().to_string();
        if !path.starts_with('/') || path.contains('\0') {
            context.toast(tt(context, "Choose an absolute scan directory."), true);
            return;
        }
        let session_epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let transcode_grant = context.area_revocation_epoch_untracked(PeerArea::Transcoding);
        action_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = action_ticket.get_untracked();
        busy.set(true);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(busy, action_ticket, ticket);
        spawn_local(async move {
            let result = ApiClient
                .post(
                    "/api/v1/admin/mediaflow/scan",
                    Some(&json!({"directory":path})),
                )
                .await;
            if busy.try_get_untracked().is_none()
                || action_ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Transcoding) != transcode_grant
                || !context.can_write_area_untracked(PeerArea::Transcoding)
            {
                return;
            }
            match result {
                Ok(_) => {
                    if context.can_all_areas_untracked(&MEDIAFLOW_STREAM_REQS) {
                        stream_requested.set(true);
                    }
                    context.toast(tt(context, "MediaFlow background scan requested."), false);
                    if context.can_read_area_untracked(PeerArea::Transcoding) {
                        queue.refresh();
                    }
                }
                Err(e) => context.toast(tt(context, &e.message), true),
            }
            busy_guard.release();
        });
    });
    view! {
        <ObsCard title="Human-gated transcode queue">
            <div class="space-y-4">
                <Show when=move || !can_read_transcoding.get()>
                    <p
                        role="status"
                        class="rounded-xl border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
                    >
                        {move || {
                            context
                                .area_block_reason(PeerArea::Transcoding, false)
                                .unwrap_or_default()
                        }}
                    </p>
                </Show>
                <form
                    class="flex flex-wrap gap-3"
                    on:submit=move |e| {
                        e.prevent_default();
                        scan.run(());
                    }
                >
                    <label class="flex-1 min-w-0 text-sm">
                        {move || tt(context, "Scan directory")}
                        <input
                            class="glass-input p-3 w-full"
                            prop:value=move || directory.get()
                            on:input=move |e| directory.set(event_target_value(&e))
                        />
                    </label>
                    <button
                        type="submit"
                        class="glass-button-primary px-4 py-2"
                        disabled=move || {
                            busy.get() || !context.can_write_area(PeerArea::Transcoding)
                        }
                        title=move || {
                            context
                                .area_block_reason(PeerArea::Transcoding, true)
                                .unwrap_or_default()
                        }
                    >
                        {move || tt(context, "Scan for candidates")}
                    </button>
                </form>
                <p class="text-sm text-slate-400">
                    {move || {
                        let summary = super::contracts::MediaFlowQueueSummary::from_jobs(&rows.get());
                        tt_with(context, "{queued} queued · {pending} pending approval · {processing} processing · {saved} saved", &[("queued", &(summary.queued).to_string()), ("pending", &(summary.pending).to_string()), ("processing", &(summary.processing).to_string()), ("saved", &(bytes(summary.saved_bytes)).to_string())])
                    }}
                </p>
                <div class="flex flex-wrap gap-3 items-center">
                    <p role="status" class="text-xs text-slate-400">
                        {move || tt(context, if connected.get() {
                                "Live transcode telemetry connected"
                            } else if stream_requested.get() {
                                "Live transcode telemetry connecting"
                            } else {
                                "Live transcode telemetry idle"
                            })}
                    </p>
                    <button
                        type="button"
                        class="glass-button px-4 py-2"
                        disabled=move || {
                            connected.get() || stream_requested.get() || !can_open_stream.get()
                        }
                        title=move || {
                            context
                                .areas_block_reason(&MEDIAFLOW_STREAM_REQS)
                                .unwrap_or_default()
                        }
                        on:click=move |_| {
                            if context.can_all_areas_untracked(&MEDIAFLOW_STREAM_REQS) {
                                stream_requested.set(true);
                            }
                        }
                    >
                        {move || tt(context, "Connect Live Stream")}
                    </button>
                </div>
                {move || {
                    stream_error
                        .get()
                        .map(|e| {
                            view! {
                                <p role="status" class="text-amber-300 text-sm">
                                    {move || tt(context, &e)}
                                </p>
                            }
                        })
                }}
                <Show when=move || progress.with(|v| v["status"] == "PROCESSING")>
                    <div class="rounded-xl border border-indigo-500/30 p-3 text-sm">
                        <p class="break-all">{move || text(&progress.get(), "filePath")}</p>
                        <p>
                            {move || {
                                let item = super::contracts::decode::<MediaFlowLiveProgress>(&progress.get());
                                format_live_transcode_metrics(&crate::tabs::l10n::locale(context), &item)
                            }}
                        </p>
                    </div>
                </Show>
                {move || {
                    queue
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
                <Show when=move || queue.loading.get() && queue.data.with(Value::is_null)>
                    <SkeletonBox class="h-48" />
                </Show>
                <Show when=move || {
                    !queue.loading.get() && queue.error.with(Option::is_none)
                        && rows.with(Vec::is_empty)
                }>
                    <EmptyState
                        title="No transcode candidates"
                        description="Scan a media directory to inspect potential savings before approving work."
                    />
                </Show>
                <div class="space-y-3">
                    {move || {
                        rows.get()
                            .into_iter()
                            .map(|row| {
                                let id = row["id"].as_i64();
                                let status = text(&row, "status");
                                let fp_short = short_source_fingerprint(&row);
                                let approval = row.clone();
                                let rejection = row.clone();
                                let cancellation = row.clone();
                                view! {
                                    <article class="p-4 border border-white/10 rounded-xl space-y-2">
                                        <p class="text-sm font-semibold break-all">
                                            {text(&row, "filePath")}
                                        </p>
                                        <Badge
                                            label=status.clone()
                                            tone=queue_status_tone(&status)
                                        />
                                        <p class="text-xs text-slate-400">
                                            {format!(
                                                "{} ({}) → {} ({}) · {}",
                                                text(&row, "originalCodec"),
                                                bytes(row["originalSize"].as_f64().unwrap_or(0.0)),
                                                text(&row, "newCodec"),
                                                bytes(row["newSize"].as_f64().unwrap_or(0.0)),
                                                text(&row, "createdAt"),
                                            )}
                                        </p>
                                        {fp_short.map(|fp| {
                                            view! {
                                                <p class="text-xs text-slate-500 font-mono break-all">
                                                    {format!("Source: {fp}")}
                                                </p>
                                            }
                                        })}
                                        <p class="text-xs text-rose-300 break-words">
                                            {text(&row, "errorLog")}
                                        </p>
                                        {(status == "PENDING_APPROVAL")
                                            .then(|| {
                                                view! {
                                                    <div class="flex gap-3">
                                                        <button
                                                            class="glass-button-primary px-4 py-2"
                                                            disabled=move || {
                                                                busy.get()
                                                                    || id.is_none()
                                                                    || !context.can_write_area(PeerArea::Transcoding)
                                                            }
                                                            title=move || {
                                                                context
                                                                    .area_block_reason(PeerArea::Transcoding, true)
                                                                    .unwrap_or_default()
                                                            }
                                                            on:click=move |_| {
                                                                candidate
                                                                    .set(id.map(|id| (id, "approve".into(), approval.clone())));
                                                                confirm.set(true);
                                                            }
                                                        >
                                                            {move || tt(context, "Approve transcode")}
                                                        </button>
                                                        <button
                                                            class="glass-button px-4 py-2"
                                                            disabled=move || {
                                                                busy.get()
                                                                    || id.is_none()
                                                                    || !context.can_write_area(PeerArea::Transcoding)
                                                            }
                                                            title=move || {
                                                                context
                                                                    .area_block_reason(PeerArea::Transcoding, true)
                                                                    .unwrap_or_default()
                                                            }
                                                            on:click=move |_| {
                                                                candidate
                                                                    .set(
                                                                        id.map(|id| (id, "decline".into(), rejection.clone())),
                                                                    );
                                                                confirm.set(true);
                                                            }
                                                        >
                                                            {move || tt(context, "Decline")}
                                                        </button>
                                                    </div>
                                                }
                                            })}
                                        {(status == "APPROVED" || status == "PROCESSING")
                                            .then(|| {
                                                view! {
                                                    <div class="flex gap-3">
                                                        <button
                                                            class="glass-button px-4 py-2"
                                                            disabled=move || {
                                                                busy.get()
                                                                    || id.is_none()
                                                                    || !context.can_write_area(PeerArea::Transcoding)
                                                            }
                                                            title=move || {
                                                                context
                                                                    .area_block_reason(PeerArea::Transcoding, true)
                                                                    .unwrap_or_default()
                                                            }
                                                            on:click=move |_| {
                                                                candidate.set(id.map(|id| {
                                                                    (id, "cancel".into(), cancellation.clone())
                                                                }));
                                                                confirm.set(true);
                                                            }
                                                        >
                                                            {move || tt(context, "Cancel")}
                                                        </button>
                                                    </div>
                                                }
                                            })}
                                    </article>
                                }
                            })
                            .collect_view()
                    }}
                </div>
                {move || {
                    let selected = candidate.get();
                    let message = selected
                        .map(|(id, verb, row)| {
                            if verb == "cancel" {
                                format!(
                                    "Cancel job #{id}: {}. In-flight transcodes stop without publishing or modifying the source file.",
                                    text(&row, "filePath")
                                )
                            } else {
                                let base = tt_with(
                                    context,
                                    "{verb} job #{id}: {path}. Codec {source} → {target}. Approval queues this file for transcoding; decline rejects this candidate.",
                                    &[
                                        ("verb", &(tt(context, &(verb).to_string())).to_string()),
                                        ("id", &(id).to_string()),
                                        ("path", &(text(&row, "filePath")).to_string()),
                                        (
                                            "source",
                                            &(tt(context, &(text(&row, "originalCodec")).to_string())).to_string(),
                                        ),
                                        ("target", &(text(&row, "newCodec")).to_string()),
                                    ],
                                );
                                match short_source_fingerprint(&row) {
                                    Some(fp) => format!("{base} ({fp})"),
                                    None => base,
                                }
                            }
                        })
                        .unwrap_or_default();
                    view! {
                        <ConfirmDialog
                            open=confirm
                            title="Confirm transcode decision"
                            message
                            busy=Signal::derive(move || busy.get())
                            on_confirm=decide
                        />
                    }
                }}
            </div>
        </ObsCard>
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod stream_url_tests {
    use super::*;
    use af_web_core::api::set_active_server;

    struct ActiveServerGuard;
    impl ActiveServerGuard {
        fn new(server: Option<&str>) -> Self {
            set_active_server(server.map(str::to_string));
            Self
        }
    }
    impl Drop for ActiveServerGuard {
        fn drop(&mut self) {
            set_active_server(None);
        }
    }

    #[test]
    fn deploy_stream_url_preserves_query_locally_and_routes_active_peer() {
        let _guard = ActiveServerGuard::new(None);
        assert_eq!(
            deploy_stream_url(),
            "/api/v1/auth/deploy/stream?appName=mediaflow_engine"
        );

        set_active_server(Some("media-2".into()));
        assert_eq!(
            deploy_stream_url(),
            "/api/v1/peers/media-2/auth/deploy/stream?appName=mediaflow_engine"
        );

        set_active_server(Some("peer/a b".into()));
        assert_eq!(
            deploy_stream_url(),
            "/api/v1/peers/peer%2Fa%20b/auth/deploy/stream?appName=mediaflow_engine"
        );
    }
}
