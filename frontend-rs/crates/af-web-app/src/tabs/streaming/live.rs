//! Typed provider cards, active playback, and session inspection and controls.
use super::common::*;
use super::types::*;
use crate::state::app;
use crate::tabs::contracts;
use crate::tabs::l10n::{tt, tt_with, Badge, ConfirmDialog, Drawer, EmptyState, Modal, ObsCard};
use af_web_core::api::{percent_encode_header_component, ApiClient};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StreamingDemoRequest<'a> {
    action: &'a str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct StreamingDemoResponse {
    message: String,
    demo_mode: bool,
    history_seeded: Option<u64>,
    predictions_seeded: Option<u64>,
}

pub(super) fn session_artwork_url(
    session: &PlaybackSession,
    servers: &[ProviderStatus],
) -> Option<String> {
    if !session.has_artwork {
        return None;
    }
    let item_id = session.artwork_item_id.trim();
    if item_id.is_empty()
        || item_id.len() > 128
        || item_id.contains("..")
        || item_id.contains('/')
        || item_id.contains('\\')
    {
        return None;
    }
    let provider = session.provider.trim().to_ascii_lowercase();
    if !matches!(provider.as_str(), "jellyfin" | "emby") {
        return None;
    }
    let resolved_server_id = if !session.server_id.trim().is_empty() {
        session.server_id.trim().to_string()
    } else {
        let matching: Vec<&ProviderStatus> = servers
            .iter()
            .filter(|server| server.provider.eq_ignore_ascii_case(&provider))
            .collect();
        if matching.len() != 1 {
            return None;
        }
        let inferred = matching[0].server_id.trim();
        if inferred.is_empty() {
            return None;
        }
        inferred.to_string()
    };
    let encoded_item = percent_encode_header_component(item_id);
    let encoded_provider = percent_encode_header_component(&provider);
    let encoded_server = percent_encode_header_component(&resolved_server_id);
    Some(format!(
        "/api/v1/auth/streaming/artwork/{encoded_item}?provider={encoded_provider}&serverId={encoded_server}"
    ))
}

pub(super) fn has_connected_live_provider(servers: &[ProviderStatus]) -> bool {
    servers.iter().any(|server| {
        matches!(server.provider.as_str(), "jellyfin" | "emby") && server.status == "connected"
    })
}

pub(super) fn demo_controls_visible(
    is_admin: bool,
    servers: &[ProviderStatus],
    is_demo_mode: bool,
) -> bool {
    if !is_admin {
        return false;
    }
    is_demo_mode || !has_connected_live_provider(servers)
}

pub(super) fn demo_submission_block_reason(
    is_admin: bool,
    dashboard_loaded: bool,
    dashboard_has_error: bool,
    servers: &[ProviderStatus],
    is_demo_mode: bool,
    pending_action: &str,
) -> Option<&'static str> {
    if !is_admin {
        return Some("Administrator privileges are required to modify demo telemetry.");
    }
    if !dashboard_loaded || dashboard_has_error {
        return Some(
            "Live telemetry status is unavailable or failed to refresh; retry before changing demo mode.",
        );
    }
    match pending_action {
        "seed" => {
            if has_connected_live_provider(servers) {
                return Some(
                    "A live Jellyfin or Emby provider is connected; demo telemetry cannot be loaded.",
                );
            }
            if is_demo_mode {
                return Some("Demo telemetry is already active.");
            }
            None
        }
        "clear" => {
            if !is_demo_mode {
                return Some("Demo telemetry is no longer active.");
            }
            None
        }
        _ => Some("Unsupported demo telemetry action."),
    }
}

pub(super) fn demo_confirmation_phrase(action: &str) -> &'static str {
    if action == "clear" {
        "CLEAR"
    } else {
        "SEED"
    }
}

pub(super) fn demo_action_confirmed(action: &str, typed: &str) -> bool {
    matches!(action, "seed" | "clear") && typed.trim() == demo_confirmation_phrase(action)
}

pub(super) fn session_subtitle(locale: &str, session: &PlaybackSession) -> String {
    let mut parts = Vec::new();
    let user = if session.user_name.trim().is_empty() {
        af_web_core::i18n::translate(locale, "Unrecorded")
    } else {
        session.user_name.trim().to_string()
    };
    parts.push(user);

    let series = session.series_name.trim();
    let season = session.season_number.trim();
    let episode = session.episode_number.trim();
    if !series.is_empty() {
        parts.push(series.to_string());
    }
    if !season.is_empty() && !episode.is_empty() {
        parts.push(format!("S{season} E{episode}"));
    } else if !season.is_empty() {
        parts.push(format!("S{season}"));
    } else if !episode.is_empty() {
        parts.push(format!("E{episode}"));
    } else if series.is_empty() && !session.item_type.trim().is_empty() {
        parts.push(af_web_core::i18n::translate(
            locale,
            session.item_type.trim(),
        ));
    }

    let state = if session.state.trim().is_empty() {
        af_web_core::i18n::translate(locale, "Unrecorded")
    } else {
        af_web_core::i18n::translate(locale, session.state.trim())
    };
    parts.push(state);
    parts.join(" · ")
}

#[component]
fn LiveSession(
    session: Signal<PlaybackSession>,
    servers: Signal<Vec<ProviderStatus>>,
    on_inspect: Callback<Value>,
) -> impl IntoView {
    let context = app();
    let artwork_url =
        Signal::derive(move || session.with(|s| servers.with(|list| session_artwork_url(s, list))));
    let artwork_failed = RwSignal::new(false);
    Effect::new(move |_| {
        artwork_url.track();
        artwork_failed.set(false);
    });
    view! {
        <article class="rounded-xl border border-white/10 p-4 space-y-3 min-w-0">
            <div class="flex items-start gap-3">
                <div class="w-16 h-24 rounded-xl border border-white/10 bg-white/5 overflow-hidden shrink-0 flex items-center justify-center">
                    {move || {
                        let item_name = session.with(|s| display(context, &s.item_name));
                        match artwork_url.get() {
                            Some(url) if !artwork_failed.get() => view! {
                                <img
                                    src=url
                                    alt=item_name
                                    class="w-full h-full object-cover"
                                    on:error=move |_| artwork_failed.set(true)
                                />
                            }
                            .into_any(),
                            _ => view! {
                                <span
                                    role="img"
                                    aria-label=tt_with(
                                        context,
                                        "Artwork unavailable for {item}",
                                        &[("item", &item_name)],
                                    )
                                    class="text-xs text-slate-400 px-1 text-center"
                                >
                                    {move || {
                                        let kind = session.with(|s| s.item_type.clone());
                                        if kind.eq_ignore_ascii_case("Audio") {
                                            tt(context, "Audio")
                                        } else {
                                            tt(context, "Media")
                                        }
                                    }}
                                </span>
                            }
                            .into_any(),
                        }
                    }}
                </div>
                <div class="flex-1 min-w-0 space-y-2">
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
                {move || session.with(|s| session_subtitle(&crate::tabs::l10n::locale(context), s))}
            </p>
                </div>
            </div>
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
pub(super) fn DemoTelemetryBanner(
    dashboard: crate::state::ApiResource,
    servers: Signal<Vec<ProviderStatus>>,
    on_changed: Callback<()>,
) -> impl IntoView {
    let context = app();
    let is_demo_mode = Signal::derive(move || {
        dashboard
            .data
            .with(|d| contracts::decode::<Dashboard>(d).live_summary.is_demo_mode)
    });
    let show_banner = Signal::derive(move || {
        !dashboard.data.with(Value::is_null)
            && servers
                .with(|list| demo_controls_visible(context.is_admin(), list, is_demo_mode.get()))
    });
    let confirm_open = RwSignal::new(false);
    let pending_action = RwSignal::new(String::new());
    let typed_confirmation = RwSignal::new(String::new());
    let stale_error = RwSignal::new(None::<&'static str>);
    let busy = RwSignal::new(false);

    let block_reason = Signal::derive(move || {
        let action = pending_action.get();
        if action.is_empty() {
            return None;
        }
        let loaded = !dashboard.data.with(Value::is_null);
        let has_error = dashboard.error.with(Option::is_some);
        let demo = is_demo_mode.get();
        servers.with(|list| {
            demo_submission_block_reason(context.is_admin(), loaded, has_error, list, demo, &action)
        })
    });

    Effect::new(move |_| {
        if !confirm_open.get() {
            typed_confirmation.set(String::new());
            stale_error.set(None);
        }
    });

    let open_confirm = move |action: &'static str| {
        if !context.is_admin()
            || busy.get_untracked()
            || dashboard.data.with_untracked(Value::is_null)
            || dashboard.error.with_untracked(Option::is_some)
        {
            return;
        }
        let demo = is_demo_mode.get_untracked();
        if servers.with_untracked(|list| {
            demo_submission_block_reason(context.is_admin(), true, false, list, demo, action)
                .is_some()
        }) {
            return;
        }
        stale_error.set(None);
        pending_action.set(action.into());
        typed_confirmation.set(String::new());
        confirm_open.set(true);
    };

    let submit_demo = Callback::new(move |()| {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let action = pending_action.get_untracked();
        let typed = typed_confirmation.get_untracked();
        if !demo_action_confirmed(&action, &typed) {
            return;
        }
        let loaded = !dashboard.data.with_untracked(Value::is_null);
        let has_error = dashboard.error.with_untracked(Option::is_some);
        let demo = is_demo_mode.get_untracked();
        let blocked = servers.with_untracked(|list| {
            demo_submission_block_reason(context.is_admin(), loaded, has_error, list, demo, &action)
        });
        if let Some(reason) = blocked {
            stale_error.set(Some(reason));
            context.toast(tt(context, reason), true);
            return;
        }
        stale_error.set(None);
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            let body =
                serde_json::to_value(StreamingDemoRequest { action: &action }).unwrap_or_default();
            match ApiClient
                .post("/api/v1/admin/streaming/demo", Some(&body))
                .await
            {
                Ok(value) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    let _response = contracts::decode::<StreamingDemoResponse>(&value);
                    confirm_open.set(false);
                    typed_confirmation.set(String::new());
                    stale_error.set(None);
                    on_changed.run(());
                    let fallback = if action == "clear" {
                        "Demo telemetry cleared."
                    } else {
                        "Demo Jellyfin streams, codecs, and bandwidth telemetry loaded."
                    };
                    context.toast(tt(context, fallback), false);
                }
                Err(error) => {
                    context.toast(tt(context, &error.message), true);
                }
            }
            if busy.try_get_untracked().is_some() {
                busy_guard.release();
            }
        });
    });

    view! {
        <Show when=move || show_banner.get()>
            <ObsCard>
                <div class="flex flex-wrap items-center justify-between gap-4">
                    <div class="space-y-1 min-w-0">
                        <h3 class="text-sm font-semibold">
                            {move || {
                                if is_demo_mode.get() {
                                    tt(
                                        context,
                                        "Demo Telemetry Active — Connect Your Jellyfin Server Anytime",
                                    )
                                } else {
                                    tt(
                                        context,
                                        "Connect Jellyfin to Track Live Streams, Bandwidth & Play Statistics",
                                    )
                                }
                            }}
                        </h3>
                        <p class="text-xs text-slate-400">
                            {move || tt(
                                context,
                                "Demo telemetry writes synthetic Jellyfin session and history entries for previewing charts without a live server.",
                            )}
                        </p>
                    </div>
                    <div class="flex flex-wrap gap-2">
                        <Show
                            when=move || is_demo_mode.get()
                            fallback=move || {
                                view! {
                                    <button
                                        type="button"
                                        class="glass-button px-4 py-2 text-sm"
                                        disabled=move || {
                                            busy.get() || dashboard.error.with(Option::is_some)
                                        }
                                        on:click=move |_| open_confirm("seed")
                                    >
                                        {move || tt(context, "Load Demo Telemetry")}
                                    </button>
                                }
                            }
                        >
                            <button
                                type="button"
                                class="glass-button px-4 py-2 text-sm text-amber-300"
                                disabled=move || {
                                    busy.get() || dashboard.error.with(Option::is_some)
                                }
                                on:click=move |_| open_confirm("clear")
                            >
                                {move || tt(context, "Clear Demo Data")}
                            </button>
                        </Show>
                    </div>
                </div>
            </ObsCard>
        </Show>
        <Modal
            open=confirm_open
            title=Signal::derive(move || {
                if pending_action.get() == "clear" {
                    tt(context, "Clear streaming demo telemetry?")
                } else {
                    tt(context, "Load streaming demo telemetry?")
                }
            })
        >
            <div class="space-y-4">
                <p class="text-sm text-slate-300">
                    {move || {
                        if pending_action.get() == "clear" {
                            tt(
                                context,
                                "This removes synthetic demo streaming history and disables demo mode.",
                            )
                        } else {
                            tt(
                                context,
                                "This seeds synthetic Jellyfin streams and demo history into the streaming database.",
                            )
                        }
                    }}
                </p>
                {move || {
                    block_reason
                        .get()
                        .or_else(|| stale_error.get())
                        .map(|reason| {
                            view! {
                                <p role="alert" class="text-sm text-amber-300">
                                    {move || tt(context, reason)}
                                </p>
                            }
                        })
                }}
                <label class="block text-sm space-y-2">
                    <span>
                        {move || {
                            let act = pending_action.get();
                            tt_with(
                                context,
                                "Type {phrase} to confirm demo telemetry change",
                                &[("phrase", demo_confirmation_phrase(&act))],
                            )
                        }}
                    </span>
                    <input
                        type="text"
                        class="glass-input w-full px-3 py-2"
                        autocomplete="off"
                        spellcheck="false"
                        disabled=move || busy.get()
                        prop:value=move || typed_confirmation.get()
                        on:input=move |event| typed_confirmation.set(event_target_value(&event))
                    />
                </label>
                <div class="flex gap-3 justify-end">
                    <button
                        type="button"
                        class="glass-button px-4 py-2"
                        disabled=move || busy.get()
                        on:click=move |_| confirm_open.set(false)
                    >
                        {move || tt(context, "Common.cancel")}
                    </button>
                    <button
                        type="button"
                        class="glass-button-primary px-4 py-2"
                        disabled=move || {
                            busy.get()
                                || block_reason.get().is_some()
                                || !demo_action_confirmed(
                                    &pending_action.get(),
                                    &typed_confirmation.get(),
                                )
                        }
                        on:click=move |_| submit_demo.run(())
                    >
                        {move || tt(context, "Common.confirm")}
                    </button>
                </div>
            </div>
        </Modal>
    }
}

#[component]
pub(super) fn ActiveSessions(
    dashboard: crate::state::ApiResource,
    servers: Signal<Vec<ProviderStatus>>,
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
                                view! { <LiveSession session servers on_inspect=inspect /> }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_artwork_url_uses_session_or_unambiguous_server_and_rejects_ambiguous_or_unsafe() {
        let servers = vec![ProviderStatus {
            provider: "jellyfin".into(),
            server_id: "srv-jf-1".into(),
            status: "connected".into(),
            ..Default::default()
        }];
        let mut session = PlaybackSession {
            provider: "jellyfin".into(),
            has_artwork: true,
            artwork_item_id: "item 123".into(),
            ..Default::default()
        };
        assert_eq!(
            session_artwork_url(&session, &servers).as_deref(),
            Some("/api/v1/auth/streaming/artwork/item%20123?provider=jellyfin&serverId=srv-jf-1")
        );

        let ambiguous_servers = vec![
            ProviderStatus {
                provider: "jellyfin".into(),
                server_id: "srv-jf-1".into(),
                status: "connected".into(),
                ..Default::default()
            },
            ProviderStatus {
                provider: "jellyfin".into(),
                server_id: "srv-jf-2".into(),
                status: "connected".into(),
                ..Default::default()
            },
        ];
        // Multiple servers for the same provider without session.server_id -> ambiguous.
        assert_eq!(session_artwork_url(&session, &ambiguous_servers), None);

        // Explicit session.server_id resolves ambiguity cleanly.
        session.server_id = "explicit-srv".into();
        assert_eq!(
            session_artwork_url(&session, &ambiguous_servers).as_deref(),
            Some(
                "/api/v1/auth/streaming/artwork/item%20123?provider=jellyfin&serverId=explicit-srv"
            )
        );

        // Missing server_id with no matching server or empty server_id cannot infer unambiguously.
        session.server_id.clear();
        assert_eq!(session_artwork_url(&session, &[]), None);
        assert_eq!(
            session_artwork_url(
                &session,
                &[ProviderStatus {
                    provider: "jellyfin".into(),
                    server_id: String::new(),
                    status: "unconfigured".into(),
                    ..Default::default()
                }],
            ),
            None
        );

        for bad in ["", "../secret", "a/b", "a\\b"] {
            session.artwork_item_id = bad.into();
            assert_eq!(session_artwork_url(&session, &servers), None, "{bad}");
        }

        session.artwork_item_id = "ok-1".into();
        session.has_artwork = false;
        assert_eq!(session_artwork_url(&session, &servers), None);

        session.has_artwork = true;
        session.provider = "demo".into();
        assert_eq!(session_artwork_url(&session, &servers), None);
    }

    #[test]
    fn demo_controls_and_submission_guard_reject_stale_and_unprivileged_state() {
        let unconfigured = vec![ProviderStatus {
            provider: "jellyfin".into(),
            status: "unconfigured".into(),
            ..Default::default()
        }];
        let connected = vec![ProviderStatus {
            provider: "jellyfin".into(),
            status: "connected".into(),
            ..Default::default()
        }];
        let emby_connected = vec![ProviderStatus {
            provider: "emby".into(),
            status: "connected".into(),
            ..Default::default()
        }];

        assert!(!demo_controls_visible(false, &unconfigured, false));
        assert!(!demo_controls_visible(false, &unconfigured, true));
        assert!(demo_controls_visible(true, &unconfigured, false));
        assert!(!demo_controls_visible(true, &connected, false));
        assert!(!demo_controls_visible(true, &emby_connected, false));
        assert!(demo_controls_visible(true, &connected, true));

        assert!(!demo_action_confirmed("seed", ""));
        assert!(!demo_action_confirmed("seed", "CLEAR"));
        assert!(demo_action_confirmed("seed", "SEED"));
        assert!(!demo_action_confirmed("clear", "SEED"));
        assert!(demo_action_confirmed("clear", " CLEAR "));
        assert!(!demo_action_confirmed("other", "SEED"));

        assert_eq!(
            demo_submission_block_reason(true, true, false, &unconfigured, false, "seed"),
            None
        );
        assert_eq!(
            demo_submission_block_reason(true, true, false, &unconfigured, true, "clear"),
            None
        );
        assert!(
            demo_submission_block_reason(false, true, false, &unconfigured, false, "seed")
                .is_some()
        );
        assert!(
            demo_submission_block_reason(true, false, false, &unconfigured, false, "seed")
                .is_some()
        );
        assert!(
            demo_submission_block_reason(true, true, true, &unconfigured, false, "seed").is_some()
        );
        assert!(
            demo_submission_block_reason(true, true, true, &unconfigured, true, "clear").is_some()
        );
        assert!(
            demo_submission_block_reason(true, true, false, &connected, false, "seed").is_some()
        );
        assert!(
            demo_submission_block_reason(true, true, false, &emby_connected, false, "seed")
                .is_some()
        );
        assert!(
            demo_submission_block_reason(true, true, false, &unconfigured, true, "seed").is_some()
        );
        assert!(
            demo_submission_block_reason(true, true, false, &unconfigured, false, "clear")
                .is_some()
        );
    }

    #[test]
    fn session_subtitle_omits_empty_series_tokens_for_movies_and_audio() {
        let movie = PlaybackSession {
            user_name: "alice".into(),
            item_name: "Inception".into(),
            item_type: "Movie".into(),
            state: "playing".into(),
            ..Default::default()
        };
        assert_eq!(session_subtitle("en", &movie), "alice · Movie · playing");

        let audio = PlaybackSession {
            user_name: "bob".into(),
            item_name: "Track 1".into(),
            item_type: "Audio".into(),
            state: "paused".into(),
            ..Default::default()
        };
        assert_eq!(session_subtitle("en", &audio), "bob · Audio · paused");

        let episode = PlaybackSession {
            user_name: "carol".into(),
            item_name: "Pilot".into(),
            item_type: "Episode".into(),
            series_name: "Andor".into(),
            season_number: "1".into(),
            episode_number: "3".into(),
            state: "playing".into(),
            ..Default::default()
        };
        assert_eq!(
            session_subtitle("en", &episode),
            "carol · Andor · S1 E3 · playing"
        );
    }
}
