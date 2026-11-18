//! Installed media pipeline, configuration evidence and human-gated transcodes.
use super::contracts::MediaFlowLiveProgress;
use crate::state::{app, json_rows, use_api, TabId};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{Badge, ConfirmDialog, EmptyState, ObsCard};
use af_web_core::api::ApiClient;
use af_web_ui::SkeletonBox;
use gloo_events::EventListener;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

mod helpers;
use helpers::*;

#[component]
pub fn MediaflowTab() -> impl IntoView {
    let context = app();
    let resource = use_api(Signal::derive(|| "/api/v1/auth/services".to_string()));
    let blueprints = use_api(Signal::derive(|| "/api/v1/auth/blueprints".to_string()));
    let rows = Memo::new(move |_| services(&resource.data.get()));
    let busy = RwSignal::new(false);
    let syncing = RwSignal::new(None::<String>);
    let stream_requested = RwSignal::new(false);
    let sync_results = RwSignal::new(std::collections::BTreeMap::<String, Value>::new());
    let sync = Callback::new(move |id: String| {
        if syncing.with_untracked(Option::is_some) || !context.is_admin() {
            return;
        }
        syncing.set(Some(id.clone()));
        spawn_local(async move {
            let result = ApiClient
                .post(
                    &format!(
                        "/api/v1/admin/blueprints/{}/sync",
                        js_sys::encode_uri_component(&id)
                            .as_string()
                            .unwrap_or_default()
                    ),
                    None,
                )
                .await;
            if syncing.try_get_untracked().is_none() {
                return;
            }
            match result {
                Ok(data) => {
                    stream_requested.set(true);
                    sync_results.update(|results| {
                        results.insert(id, data["result"].clone());
                    });
                    context.toast(
                        tt(context, "Application configuration synchronized."),
                        false,
                    );
                    resource.refresh();
                    blueprints.refresh();
                }
                Err(e) => context.toast(tt(context, &e.message), true),
            }
            syncing.set(None);
        });
    });
    let refresh = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        10_000,
        move || {
            if !resource.loading.get_untracked() {
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
                    disabled=move || resource.loading.get()
                    on:click=move |_| {
                        resource.refresh();
                        blueprints.refresh();
                    }
                    aria-label=move || tt(context, "Refresh pipeline")
                >
                    {move || tt(context, "Common.refresh")}
                </button>
            </div>
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
                                                            .unwrap_or(Value::Null)
                                                    });
                                                let contract = super::contracts::decode::<super::contracts::MediaFlowServiceContract>(&service);
                                                let wired = contract.wired.or(contract.auto_configured).or_else(|| blueprint["config_applied"].as_bool());
                                                let has_key = contract.api_key.as_deref().is_some_and(|key| !key.is_empty());
                                                let running = matches!(contract.status.as_str(), "running" | "active");
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
                                                        {safe_launch_url(&service)
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
                                                                        disabled=move || syncing.with(Option::is_some)
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
            <ObsCard title="Download and import telemetry">
                <div class="grid sm:grid-cols-2 gap-4">
                    {[
                        (
                            &["qbittorrent", "sabnzbd", "nzbget", "transmission", "deluge"][..],
                            "Active downloads",
                            &["active_downloads", "activeDownloads"][..],
                        ),
                        (
                            &["sonarr", "radarr", "lidarr"][..],
                            "Import queue depth",
                            &["queue_depth", "queueDepth"][..],
                        ),
                    ]
                        .into_iter()
                        .map(|(ids, label, keys)| {
                            view! {
                                <div>
                                    <p class="text-sm text-slate-400">
                                        {move || tt(context, label)}
                                    </p>
                                    <p class="text-xl font-semibold">
                                        {move || {
                                            let values = rows
                                                .get()
                                                .into_iter()
                                                .filter(|s| {
                                                    ids.contains(&text(s, "id").as_str()) && installed(s)
                                                })
                                                .filter_map(|s| {
                                                    keys.iter().find_map(|key| s[*key].as_u64())
                                                })
                                                .collect::<Vec<_>>();
                                            if values.is_empty() {
                                                tt(context, "Not reported by service telemetry")
                                            } else {
                                                values.iter().sum::<u64>().to_string()
                                            }
                                        }}
                                    </p>
                                </div>
                            }
                        })
                        .collect_view()}
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
                <MediaflowQueue busy stream_requested />
            </Show>
        </section>
    }
}

#[component]
fn MediaflowQueue(busy: RwSignal<bool>, stream_requested: RwSignal<bool>) -> impl IntoView {
    let context = app();
    let queue = use_api(Signal::derive(|| {
        "/api/v1/admin/mediaflow/queue".to_string()
    }));
    let directory = RwSignal::new("/home/hdd".to_string());
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
        stream_error.set(None);
        let Ok(events) =
            web_sys::EventSource::new("/api/v1/auth/deploy/stream?appName=mediaflow_engine")
        else {
            stream_error.set(Some("Live transcode stream could not be opened.".into()));
            stream_requested.set(false);
            return;
        };
        let completed_events = events.clone();
        let message = EventListener::new(&events, "message", move |event| {
            if let Some(data) = event
                .dyn_ref::<web_sys::MessageEvent>()
                .and_then(|e| e.data().as_string())
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            {
                let terminal = matches!(
                    data["status"]
                        .as_str()
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                        .as_str(),
                    "complete" | "completed" | "failed" | "error" | "success" | "done"
                );
                progress.set(data);
                connected.set(!terminal);
                stream_error.set(None);
                if terminal {
                    completed_events.close();
                    stream_requested.set(false);
                    queue.refresh();
                }
            }
        });
        let opened = EventListener::new(&events, "open", move |_| {
            connected.set(true);
            stream_error.set(None);
        });
        let failed_events = events.clone();
        let error = EventListener::new(&events, "error", move |_| {
            failed_events.close();
            connected.set(false);
            stream_requested.set(false);
            stream_error.set(Some(
                "No active deployment stream. Connect again after starting work.".into(),
            ));
        });
        source.set_value(Some((events, message, opened, error)));
    });
    Effect::new(move |_| {
        if stream_requested.get() {
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
            if !queue.loading.get_untracked() {
                queue.refresh();
            }
        },
    )));
    on_cleanup(move || refresh.set_value(None));
    let rows = Memo::new(move |_| {
        super::contracts::grid_rows::<super::contracts::MediaFlowQueueRecord>(&queue.data.get())
    });
    let candidate = RwSignal::new(None::<(i64, String, Value)>);
    let confirm = RwSignal::new(false);
    let decide = Callback::new(move |(): ()| {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let Some((id, verb, _)) = candidate.get_untracked() else {
            return;
        };
        busy.set(true);
        spawn_local(async move {
            let result = ApiClient
                .post(&format!("/api/v1/admin/mediaflow/{verb}/{id}"), None)
                .await;
            if busy.try_get_untracked().is_none() {
                return;
            }
            match result {
                Ok(_) => {
                    if verb == "approve" {
                        stream_requested.set(true);
                    }
                    context.toast(
                        tt(
                            context,
                            if verb == "approve" {
                                "Transcode approved and queued."
                            } else {
                                "Transcode declined."
                            },
                        ),
                        false,
                    );
                    queue.refresh();
                }
                Err(e) => context.toast(tt(context, &e.message), true),
            }
            busy.set(false);
            confirm.set(false);
        });
    });
    let scan = Callback::new(move |(): ()| {
        if busy.get_untracked() {
            return;
        }
        let path = directory.get_untracked().trim().to_string();
        if !path.starts_with('/') || path.contains('\0') {
            context.toast(tt(context, "Choose an absolute scan directory."), true);
            return;
        }
        busy.set(true);
        spawn_local(async move {
            let result = ApiClient
                .post(
                    "/api/v1/admin/mediaflow/scan",
                    Some(&json!({"directory":path})),
                )
                .await;
            if busy.try_get_untracked().is_none() {
                return;
            }
            match result {
                Ok(_) => {
                    stream_requested.set(true);
                    context.toast(tt(context, "MediaFlow background scan requested."), false);
                    queue.refresh();
                }
                Err(e) => context.toast(tt(context, &e.message), true),
            }
            busy.set(false);
        });
    });
    view! {
        <ObsCard title="Human-gated transcode queue">
            <div class="space-y-4">
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
                        disabled=move || busy.get()
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
                        disabled=move || connected.get() || stream_requested.get()
                        on:click=move |_| stream_requested.set(true)
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
                                let approval = row.clone();
                                let rejection = row.clone();
                                view! {
                                    <article class="p-4 border border-white/10 rounded-xl space-y-2">
                                        <p class="text-sm font-semibold break-all">
                                            {text(&row, "filePath")}
                                        </p>
                                        <Badge label=text(&row, "status") />
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
                                        <p class="text-xs text-rose-300 break-words">
                                            {text(&row, "errorLog")}
                                        </p>
                                        {(row["status"] == "PENDING_APPROVAL")
                                            .then(|| {
                                                view! {
                                                    <div class="flex gap-3">
                                                        <button
                                                            class="glass-button-primary px-4 py-2"
                                                            disabled=move || busy.get() || id.is_none()
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
                                                            disabled=move || busy.get() || id.is_none()
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
                            tt_with(context, "{verb} job #{id}: {path}. Codec {source} → {target}. Approval queues this file for transcoding; decline rejects this candidate.", &[("verb", &(tt(context, &(verb).to_string())).to_string()), ("id", &(id).to_string()), ("path", &(text(&row, "filePath")).to_string()), ("source", &(tt(context, &(text(&row, "originalCodec")).to_string())).to_string()), ("target", &(text(&row, "newCodec")).to_string())])
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
