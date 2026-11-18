//! Typed provider cards, active playback, and session inspection and controls.
use super::common::*;
use super::types::*;
use crate::state::app;
use crate::tabs::contracts;
use crate::tabs::l10n::{tt, tt_with, Badge, ConfirmDialog, Drawer, EmptyState, ObsCard};
use af_web_core::api::ApiClient;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;
#[component]
fn LiveSession(session: Signal<PlaybackSession>, on_inspect: Callback<Value>) -> impl IntoView {
    let context = app();
    view! {
        <article class="rounded-xl border border-white/10 p-4 space-y-3 min-w-0">
            <div class="flex flex-wrap justify-between gap-2">
                <h3 class="font-semibold break-words">
                    {move || display(context, &session.get().item_name)}
                </h3>
                {move || {
                    view! {
                        <Badge
                            label=display(context, &session.get().play_method)
                            tone=if session.with(|s| s.play_method == "Transcode") {
                                "warning"
                            } else {
                                "success"
                            }
                        />
                    }
                }}
            </div>
            <p class="text-sm text-slate-400">
                {move || {
                    session
                        .with(|s| {
                            tt_with(context, "{user} · {series} · S{season} E{episode} · {state}", &[("user", &(display(context, &s.user_name)).to_string()), ("series", &(s.series_name.clone()).to_string()), ("season", &(s.season_number.clone()).to_string()), ("episode", &(s.episode_number.clone()).to_string()), ("state", &(tt(context, &display(context, &s.state))).to_string())])
                        })
                }}
            </p>
            <progress
                class="w-full"
                max="100"
                value=move || {
                    session.with(|s| s.progress_pct.unwrap_or(0.0).clamp(0.0, 100.0))
                }
                aria-label=move || tt(context, "Playback progress")
            ></progress>
            <p class="text-xs text-slate-400">
                {move || {
                    session
                        .with(|s| {
                            tt_with(context, "{position} / {duration} · {resolution} · {video} · {audio} · {channels} channels · {container} · {bandwidth} Mbps", &[("position", &(duration(&crate::tabs::l10n::locale(context), s.position_secs)).to_string()), ("duration", &(duration(&crate::tabs::l10n::locale(context), s.duration_secs)).to_string()), ("resolution", &(display(context, &s.video_resolution)).to_string()), ("video", &(display(context, &s.video_codec)).to_string()), ("audio", &(display(context, &s.audio_codec)).to_string()), ("channels", &(display(context, &s.audio_channels)).to_string()), ("container", &(display(context, &s.container)).to_string()), ("bandwidth", &(display(context, &s.bandwidth_mbps)).to_string())])
                        })
                }}
            </p>
            <p class="text-xs text-slate-400">
                {move || {
                    session
                        .with(|s| {
                            tt_with(context, "{client} · {device} · {server} · {bitrate} bps", &[("client", &(display(context, &s.client_name)).to_string()), ("device", &(display(context, &s.device_name)).to_string()), ("server", &(display(context, &s.server_name)).to_string()), ("bitrate", &(display(context, &s.bitrate_bps)).to_string())])
                        })
                }}
            </p>
            <button
                class="glass-button px-3 py-2 text-sm"
                on:click=move |_| on_inspect.run(serde_json::to_value(session.get_untracked()).unwrap_or_default())
            >
                {move || tt(context, "Playback details")}
            </button>
        </article>
    }
}

#[component]
pub(super) fn StreamingDetails(
    open: RwSignal<bool>,
    session: RwSignal<Value>,
    servers: Signal<Vec<ProviderStatus>>,
    on_changed: Callback<()>,
) -> impl IntoView {
    let context = app();
    let busy = RwSignal::new(false);
    let stop_confirm = RwSignal::new(false);
    let message = RwSignal::new(String::new());
    let controllable = move || {
        context.is_admin()
            && session.with(|s| contracts::decode::<PlaybackSession>(s).controllable())
    };
    let command = Callback::new(move |command: String| {
        if busy.get_untracked() || !controllable() {
            return;
        }
        let row = session.get_untracked();
        if command == "message"
            && (row["canSendMessage"] != true || message.get_untracked().trim().is_empty())
        {
            return;
        }
        let id = text(&row, "sessionId");
        let body = json!({"command":command,"provider":row["provider"],"header":"AetherFlow Notice","message":message.get_untracked()});
        busy.set(true);
        spawn_local(async move {
            let result = ApiClient
                .post(
                    &format!(
                        "/api/v1/admin/streaming/sessions/{}/command",
                        js_sys::encode_uri_component(&id)
                            .as_string()
                            .unwrap_or_default()
                    ),
                    Some(&body),
                )
                .await;
            if busy.try_get_untracked().is_none() {
                return;
            }
            match result {
                Ok(_) => {
                    context.toast(tt(context, "Playback command accepted."), false);
                    on_changed.run(());
                    if command == "message" {
                        message.set(String::new());
                    } else {
                        open.set(false);
                    }
                }
                Err(e) => context.toast(tt(context, &e.message), true),
            }
            busy.set(false);
            stop_confirm.set(false);
        });
    });
    view! {
        <Drawer open title="Playback session details">
            <div class="space-y-4 min-w-0">
                <h3 class="text-lg font-semibold break-words">
                    {move || recorded(&crate::tabs::l10n::locale(context), &session.get(), "itemName")}
                </h3>
                <p class="text-sm text-indigo-300">
                    {move || {
                        let row = session.get();
                        let id = text(&row, "serverId");
                        let provider = text(&row, "provider");
                        if id.is_empty() {
                            return tt(context, "Server identity is unrecorded for this playback record.");
                        }
                        match servers
                            .get()
                            .into_iter()
                            .find(|s| s.provider == provider && s.server_id == id)
                        {
                            Some(server) => {
                                tt_with(context, "Server identity matches {name} ({id}) · current status {status}", &[("name", &(server.name.clone()).to_string()), ("id", &(id).to_string()), ("status", &(tt(context, server.status_key())).to_string())])
                            }
                            None => {
                                tt_with(context, "Server identity {id} does not match a currently verified server. Check its binding before importing history.", &[("id", &(id).to_string())])
                            }
                        }
                    }}
                </p>
                <dl class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                    {[
                        "provider",
                        "serverName",
                        "serverId",
                        "userName",
                        "itemType",
                        "seriesName",
                        "seasonNumber",
                        "episodeNumber",
                        "clientName",
                        "deviceName",
                        "ipAddress",
                        "playMethod",
                        "container",
                        "targetContainer",
                        "videoCodec",
                        "targetVideoCodec",
                        "videoResolution",
                        "audioCodec",
                        "targetAudioCodec",
                        "audioChannels",
                        "audioLanguage",
                        "subtitleCodec",
                        "hwAccel",
                        "bitrateBps",
                        "bandwidthMbps",
                        "watchedSecs",
                        "durationSecs",
                        "startedAt",
                        "lastSeenAt",
                        "provenance",
                        "timestampCertainty",
                        "byteAccuracy",
                        "policyStatus",
                    ]
                        .into_iter()
                        .map(|key| {
                            view! {
                                <div>
                                    <dt class="text-slate-400">{move || tt(context, key)}</dt>
                                    <dd class="break-words">
                                        {move || recorded(&crate::tabs::l10n::locale(context), &session.get(), key)}
                                    </dd>
                                </div>
                            }
                        })
                        .collect_view()}
                </dl>
                <p class="text-sm text-amber-300">
                    {move || {
                        tt_with(context, "Transcode reasons: {reasons}", &[("reasons", &(recorded(&crate::tabs::l10n::locale(context), &session.get(), "transcodeReasons")).to_string())])
                    }}
                </p>
                <details>
                    <summary class="cursor-pointer">
                        {move || tt(context, "Full playback metadata")}
                    </summary>
                    <pre class="text-xs whitespace-pre-wrap break-all max-h-80 overflow-auto">
                        {move || serde_json::to_string_pretty(&session.get()).unwrap_or_default()}
                    </pre>
                </details>
                <Show when=controllable>
                    <div class="space-y-3">
                        <div class="flex gap-2">
                            <button
                                class="glass-button px-3 py-2"
                                disabled=move || busy.get()
                                on:click=move |_| command.run("pause".into())
                            >
                                {move || tt(context, "Pause")}
                            </button>
                            <button
                                class="glass-button px-3 py-2"
                                disabled=move || busy.get()
                                on:click=move |_| command.run("resume".into())
                            >
                                {move || tt(context, "Resume")}
                            </button>
                            <button
                                class="glass-button px-3 py-2 text-rose-300"
                                disabled=move || busy.get()
                                on:click=move |_| stop_confirm.set(true)
                            >
                                {move || tt(context, "Stop")}
                            </button>
                        </div>
                        <Show when=move || session.with(|s| s["canSendMessage"] == true)>
                            <label class="text-sm">
                                {move || tt(context, "Message viewer")}
                                <input
                                    class="glass-input p-2 w-full"
                                    prop:value=move || message.get()
                                    on:input=move |e| message.set(event_target_value(&e))
                                />
                            </label>
                            <button
                                class="glass-button px-3 py-2"
                                disabled=move || busy.get() || message.get().trim().is_empty()
                                on:click=move |_| command.run("message".into())
                            >
                                {move || tt(context, "Send on-screen message")}
                            </button>
                        </Show>
                    </div>
                </Show>
            </div>
        </Drawer>
        <ConfirmDialog
            open=stop_confirm
            title="Stop this playback session?"
            message="This immediately stops the selected viewer's playback. Verify the viewer and media title before confirming."
            busy=Signal::derive(move || busy.get())
            on_confirm=Callback::new(move |()| command.run("stop".into()))
        />
    }
}

#[component]
pub(super) fn ProviderCards(
    servers: Signal<Vec<ProviderStatus>>,
    config: RwSignal<ProviderStatus>,
    config_open: RwSignal<bool>,
) -> impl IntoView {
    let context = app();
    view! {
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
                {move || {
                    servers
                        .get()
                        .into_iter()
                        .map(|server| {
                            let selected = server.clone();
                            let server = StoredValue::new(server);
                            view! {
                                <ObsCard>
                                    <div class="space-y-2">
                                        <div class="flex flex-wrap justify-between gap-2">
                                            <h3 class="font-semibold">{move || server.with_value(|server| if server.name.trim().is_empty() { tt(context, "Unnamed server") } else { server.name.clone() })}</h3>
                                            <Badge label=Signal::derive(move || server.with_value(|server| tt(context, server.status_key()))) />
                                        </div>
                                        <p class="text-xs text-slate-400 break-all">
                                            {move || server.with_value(|server| format!(
                                                "{} · {} · {}",
                                                server.provider.clone(),
                                                display(context, &server.version),
                                                display(context, &server.server_id),
                                            ))}
                                        </p>
                                        <p role="status" class="text-xs text-amber-300">
                                            {move || server.with_value(|server| tt(context, server.error_message.as_deref().unwrap_or_default()))}
                                        </p>
                                        {context
                                            .is_admin()
                                            .then(|| {
                                                view! {
                                                    <button
                                                        class="glass-button px-3 py-2 text-sm"
                                                        on:click=move |_| {
                                                            config.set(selected.clone());
                                                            config_open.set(true);
                                                        }
                                                    >
                                                        {move || tt(context, "Connection & identity")}
                                                    </button>
                                                }
                                            })}
                                    </div>
                                </ObsCard>
                            }
                        })
                        .collect_view()
                }}
            </div>
    }
}
#[component]
pub(super) fn ActiveSessions(
    dashboard: crate::state::ApiResource,
    on_inspect: Callback<Value>,
) -> impl IntoView {
    let context = app();
    let inspect = on_inspect;
    view! {
            <ObsCard title="Active playback sessions">
                <div class="space-y-4">
                    <p class="text-sm text-slate-400" role="status">
                        {move || {
                            dashboard
                                .data
                                .with(|d| {
                                    let record = contracts::decode::<Dashboard>(d);
                                    let s = record.live_summary;
                                    let counter = |value: Option<f64>| value.map(|v| v.to_string()).unwrap_or_else(|| tt(context, "Unrecorded"));
                                    tt_with(context, "{active} active · {direct_play} Direct Play · {direct_stream} Direct Stream · {transcode} Transcode · {bandwidth} Mbps · updated {updated}", &[("active", &counter(s.active_sessions)), ("direct_play", &counter(s.direct_play)), ("direct_stream", &counter(s.direct_stream)), ("transcode", &counter(s.transcode)), ("bandwidth", &counter(s.total_bandwidth_mbps)), ("updated", &if s.updated_at.is_empty() { record.updated_at } else { s.updated_at })])
                                })
                        }}
                    </p>
                    <div class="grid md:grid-cols-2 gap-4">
                        <For
                            each=move || {
                                dashboard
                                    .data
                                    .with(|d| {
                                        contracts::decode::<Dashboard>(d).active_sessions
                                            .into_iter().map(|r| (r.provider, r.session_id)).collect::<Vec<_>>()
                                    })
                            }
                            key=|key| key.clone()
                            children=move |(provider, id)| {
                                let session = Signal::derive(move || {
                                    dashboard
                                        .data
                                        .with(|d| {
                                            contracts::decode::<Dashboard>(d).active_sessions
                                                .into_iter().find(|s| s.session_id == id && s.provider == provider)
                                                .unwrap_or_default()
                                        })
                                });
                                view! { <LiveSession session on_inspect=inspect /> }
                            }
                        />
                    </div>
                    <Show when=move || {
                        !dashboard.loading.get() && dashboard.error.with(Option::is_none)
                            && dashboard.data.with(|d| !d.is_null() && contracts::decode::<Dashboard>(d).active_sessions.is_empty())
                    }>
                        <EmptyState
                            title="No active playback sessions"
                            description="Live sessions refresh every five seconds while this page is visible."
                        />
                    </Show>
                </div>
            </ObsCard>
    }
}
