//! Live streaming, canonical history, and administrative subtab orchestration.
use self::common::*;
use self::types::*;
use crate::state::{app, use_api};
use crate::tabs::contracts;
use crate::tabs::l10n::{tt, tt_with, TabPanel, TabsBar};
use af_web_ui::SkeletonBox;
use leptos::prelude::*;
use serde_json::Value;
mod administration;
mod analytics;
mod common;
mod connections;
mod history;
mod imports;
mod live;
mod portability;
mod reconciliation;
mod types;
use administration::HistoryAdministration;
use analytics::{DashboardDistributions, ImportedEstimates};
use connections::StreamingServerSettings;
use history::CanonicalHistory;
use live::{ActiveSessions, DemoTelemetryBanner, ProviderCards, StreamingDetails};
#[component]
pub fn StreamingTab() -> impl IntoView {
    let context = app();
    let active = RwSignal::new("live".to_owned());
    let window = RwSignal::new("30".to_string());
    let play_method = RwSignal::new("all".to_string());
    let media_type = RwSignal::new("all".to_string());
    let dashboard = use_api(Signal::derive(move || {
        format!(
            "/api/v1/auth/streaming/dashboard?window={}&playMethod={}&mediaType={}",
            window.get(),
            play_method.get(),
            media_type.get()
        )
    }));
    let poll = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        5000,
        move || {
            let visible = web_sys::window()
                .and_then(|w| w.document())
                .is_none_or(|d| !d.hidden());
            if visible
                && active.with_untracked(|tab| tab == "live")
                && !dashboard.loading.get_untracked()
            {
                dashboard.refresh();
            }
        },
    )));
    on_cleanup(move || poll.set_value(None));
    let detail = RwSignal::new(Value::Null);
    let detail_open = RwSignal::new(false);
    let config = RwSignal::new(ProviderStatus::default());
    let config_open = RwSignal::new(false);
    let inspect = Callback::new(move |row: Value| {
        let mut full = row.clone();
        if let Some(extra) = dashboard.data.with_untracked(|d| {
            let id = text(&row, "id");
            contracts::decode::<Dashboard>(d)
                .analytics
                .recent_history
                .into_iter()
                .find(|record| !id.is_empty() && record.id.to_string() == id)
                .and_then(|record| serde_json::to_value(record).ok())
        }) {
            full = extra;
            if let (Some(target), Some(source)) = (full.as_object_mut(), row.as_object()) {
                target.extend(source.clone());
            }
        }
        detail.set(full);
        detail_open.set(true);
    });
    let changed = Callback::new(move |(): ()| {
        dashboard.refresh();
        context.history_revision.update(|n| *n += 1);
    });
    let servers = Signal::derive(move || {
        dashboard
            .data
            .with(|d| contracts::decode::<Dashboard>(d).servers)
    });
    view! {
        <section class="space-y-5 py-5 min-w-0 max-w-full">
            <div class="flex flex-wrap justify-between gap-3">
                <div>
                    <h2 class="text-xl font-semibold">
                        {move || tt(context, "Tabs.streamingHeading")}
                    </h2>
                    <p class="text-sm text-slate-400">
                        {move || tt(context, "Live playback and canonical playback history.")}
                    </p>
                </div>
                <button
                    class="glass-button px-4 py-2"
                    disabled=move || dashboard.loading.get()
                    on:click=move |_| dashboard.refresh()
                    aria-label=move || tt(context, "Refresh live sessions")
                >
                    {move || tt(context, "Common.refresh")}
                </button>
            </div>
            {move || {
                dashboard
                    .error
                    .get()
                    .map(|e| {
                        view! {
                            <p role="alert" class="text-rose-300">
                                {move || tt_with(context, "Live telemetry: {error}", &[("error", &(e.message).to_string())])}
                            </p>
                        }
                    })
            }}
            <Show when=move || {
                active.with(|tab| tab == "live")
                    && dashboard.loading.get()
                    && dashboard.data.with(Value::is_null)
                    && dashboard.error.with(Option::is_none)
            }>
                <SkeletonBox class="h-32" />
            </Show>
            <TabsBar
                id_prefix="streaming"
                active
                tabs=Signal::derive(move || {
                    let mut tabs = vec![
                        ("live".into(), tt(context, "Active playback sessions")),
                        ("history".into(), tt(context, "Canonical playback history")),
                    ];
                    if context.is_admin() {
                        tabs.push(("administration".into(), tt(context, "History administration")));
                    }
                    tabs
                })
            />
            <TabPanel id_prefix="streaming" id=Signal::derive(move || active.get())>
                <Show when=move || active.get() == "live">
                    <div class="space-y-5">
                    <DemoTelemetryBanner dashboard servers on_changed=changed />
                    <div class="grid sm:grid-cols-3 gap-3" role="group" aria-label=move || tt(context, "Telemetry filters")>
                        <label class="text-xs text-slate-400 space-y-1">
                            <span class="block">{move || tt(context, "Estimate window ")}</span>
                            <select
                                class="glass-input p-2 w-full"
                                prop:value=move || window.get()
                                on:change=move |e| window.set(event_target_value(&e))
                            >
                                <option value="7">{move || tt(context, "7 days")}</option>
                                <option value="30">{move || tt(context, "30 days")}</option>
                                <option value="90">{move || tt(context, "90 days")}</option>
                                <option value="all">{move || tt(context, "All time")}</option>
                            </select>
                        </label>
                        <label class="text-xs text-slate-400 space-y-1">
                            <span class="block">{move || tt(context, "Play method")}</span>
                            <select
                                class="glass-input p-2 w-full"
                                prop:value=move || play_method.get()
                                on:change=move |e| play_method.set(event_target_value(&e))
                            >
                                <option value="all">{move || tt(context, "All Methods")}</option>
                                <option value="DirectPlay">{move || tt(context, "Direct Play")}</option>
                                <option value="DirectStream">{move || tt(context, "Direct Stream")}</option>
                                <option value="Transcode">{move || tt(context, "Transcode")}</option>
                                <option value="Unknown">{move || tt(context, "Unknown")}</option>
                            </select>
                        </label>
                        <label class="text-xs text-slate-400 space-y-1">
                            <span class="block">{move || tt(context, "Media type")}</span>
                            <select
                                class="glass-input p-2 w-full"
                                prop:value=move || media_type.get()
                                on:change=move |e| media_type.set(event_target_value(&e))
                            >
                                <option value="all">{move || tt(context, "All Media")}</option>
                                <option value="Movie">{move || tt(context, "Movies")}</option>
                                <option value="Episode">{move || tt(context, "Episodes")}</option>
                                <option value="Audio">{move || tt(context, "Audio")}</option>
                            </select>
                        </label>
                    </div>
                    <ProviderCards servers config config_open />
                    <ActiveSessions dashboard servers on_inspect=inspect />
                    <DashboardDistributions dashboard />
                    </div>
                </Show>
                <Show when=move || active.get() == "history">
                    <div class="space-y-5">
                    <CanonicalHistory on_inspect=inspect />
                    <ImportedEstimates dashboard window />
                    </div>
                </Show>
                <Show when=move || active.get() == "administration" && context.is_admin()>
                    <HistoryAdministration servers on_changed=changed />
                </Show>
            </TabPanel>
            <StreamingDetails
                open=detail_open
                session=detail
                servers
                on_changed=Callback::new(move |()| dashboard.refresh())
            />
            <Show when=move || context.is_admin()>
                <StreamingServerSettings open=config_open server=config on_changed=changed />
            </Show>
        </section>
    }
}
