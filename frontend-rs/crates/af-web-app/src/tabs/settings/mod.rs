use crate::state::{
    app, json_rows, run_resource_read, use_api_when, ApiResource, PeerArea, ResourceReads, TabId,
};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{ConfirmDialog, DataGrid, EmptyState, Modal, ObsCard, TabPanel, TabsBar};
use crate::tabs::GrantInvalidationBoundary;
use af_web_core::{
    api::{storage_get, storage_set, ApiClient},
    draft::FormDraft,
    i18n::LOCALES,
    models::SelfUpdateJobStatus,
};
use af_web_ui::{GridColumn, QrCodeSvg};
use futures::future::{select, Either};
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

mod forms;
pub use forms::*;
mod updates;
use updates::*;
mod providers;
use providers::*;
mod security;
use security::*;
mod backups_oidc;
use backups_oidc::*;
mod oidc;
use oidc::*;
mod metadata;
use metadata::*;

fn settings_value(server: Value) -> Value {
    let mut value = json!({
        "aiModel":"", "localProvider":"", "localModel":"", "systemPrompt":"",
        "language":"en", "timezone":"UTC", "updateChannel":"stable", "defaultDashboard":"overview",
        "setupCompleted":false, "baseDomain":"", "geminiApiKey":"", "openaiApiKey":"",
        "lmStudioEndpoint":"", "ollamaEndpoint":"", "anthropicApiKey":"", "anthropicEndpoint":""
    });
    if let Some(fields) = server.as_object() {
        for (key, field) in fields {
            value[key] = field.clone();
        }
    }
    for key in ["geminiApiKey", "openaiApiKey", "anthropicApiKey"] {
        let stored = text(&value, key);
        if !stored.is_empty() {
            // Server-provided credentials are only ever presented as configured.
            value[key] = json!("****");
        }
    }
    value
}

fn use_settings_resource(can_read: Signal<bool>) -> ApiResource {
    let context = app();
    let resource = ApiResource {
        data: RwSignal::new(Value::Null),
        loading: RwSignal::new(false),
        error: RwSignal::new(None),
        revision: RwSignal::new(0),
    };
    let generation = RwSignal::new(0u64);
    let reads = StoredValue::new_local(ResourceReads::default());
    on_cleanup(move || reads.update_value(|reads| reads.cancel()));
    Effect::new(move |_| {
        let epoch = context.session_epoch.get();
        let server_epoch = context.server_epoch.get();
        let allowed = can_read.get();
        let grant_epoch = context.area_revocation_epoch(PeerArea::Settings);
        let revision = resource.revision.get();
        generation.update(|value| *value = value.wrapping_add(1));
        let ticket = generation.get_untracked();
        if !allowed {
            reads.update_value(|reads| reads.cancel());
            resource.data.set(Value::Null);
            resource.error.set(None);
            resource.loading.set(false);
            return;
        }
        let request = context.begin_settings_request();
        resource.loading.set(true);
        resource.error.set(None);
        let Some(job) = reads.try_update_value(ResourceReads::next) else {
            return;
        };
        spawn_local(async move {
            let work = async {
                if generation.try_get_untracked() != Some(ticket)
                    || resource.revision.try_get_untracked() != Some(revision)
                    || context.session_epoch.try_get_untracked() != Some(epoch)
                    || context.server_epoch.try_get_untracked() != Some(server_epoch)
                    || context.area_revocation_epoch_untracked(PeerArea::Settings) != grant_epoch
                    || !context.can_read_area_untracked(PeerArea::Settings)
                {
                    return None;
                }
                Some(ApiClient.get("/api/v1/auth/settings").await)
            };
            let Some(Some(result)) = run_resource_read(job, work).await else {
                return;
            };
            if generation.try_get_untracked() != Some(ticket)
                || resource.revision.try_get_untracked() != Some(revision)
                || context.session_epoch.try_get_untracked() != Some(epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Settings) != grant_epoch
                || !context.can_read_area_untracked(PeerArea::Settings)
            {
                return;
            }
            match result {
                Ok(value) => {
                    let normalized = settings_value(value);
                    if context.finish_settings_request(request, normalized.clone()) {
                        resource.data.set(normalized);
                    }
                    resource.error.set(None);
                }
                Err(error) => {
                    if !matches!(
                        error.code.as_deref(),
                        Some("SERVER_CHANGED" | "SESSION_CHANGED" | "ABORTED")
                    ) {
                        resource.error.set(Some(error));
                    }
                }
            }
            resource.loading.set(false);
        });
    });
    resource
}

#[component]
pub fn SettingsTab() -> impl IntoView {
    let context = app();
    let can_read_settings = Signal::derive(move || context.can_read_area(PeerArea::Settings));
    let settings = use_settings_resource(can_read_settings);
    poll_resource_when(settings, 30_000, move || {
        context.can_read_area_untracked(PeerArea::Settings)
    });
    let draft = RwSignal::new(FormDraft::new(settings_value(
        if can_read_settings.get_untracked() {
            context.settings.get_untracked()
        } else {
            Value::Null
        },
    )));
    let busy = RwSignal::new(false);
    let save_ticket = RwSignal::new(0u64);
    let active = RwSignal::new(
        context
            .take_pending_subtab(TabId::Settings)
            .unwrap_or_else(|| "general".to_string()),
    );
    Effect::new(move |_| {
        context.pending_subtab.track();
        if let Some(target) = context.take_pending_subtab(TabId::Settings) {
            active.set(target);
        }
    });
    let preferences = RwSignal::new(FormDraft::new(json!({
        "sidebarPinned":storage_get("aetherflow-sidebar-pinned").as_deref() == Some("true")
    })));
    let pref_busy = RwSignal::new(false);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Settings);
        let allowed = can_read_settings.get();
        save_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        busy.set(false);
        draft.set(FormDraft::new(settings_value(if allowed {
            context.settings.get_untracked()
        } else {
            Value::Null
        })));
    });
    Effect::new(move |_| {
        if !context.can_write_area(PeerArea::Settings) {
            save_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            busy.set(false);
        }
    });
    Effect::new(move |_| {
        if !can_read_settings.get() {
            return;
        }
        let value = settings.data.get();
        if value.is_object() {
            let value = settings_value(value);
            draft.update(|draft| draft.apply_server_refresh(value));
        }
    });
    let save = Callback::new(move |()| {
        if busy.get_untracked()
            || !context.is_admin()
            || !context.can_write_area(PeerArea::Settings)
        {
            return;
        }
        let sent = draft_value(draft);
        let fields =
            draft.with_untracked(|d| d.dirty_fields().map(str::to_string).collect::<Vec<_>>());
        if fields.iter().any(|field| field == "/aiModel")
            && !crate::tabs::ai_chat::valid_model(&text(&sent, "aiModel"))
        {
            context.toast(tt(context, "Enter a model identifier"), true);
            return;
        }
        let session_epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let settings_grant = context.area_revocation_epoch_untracked(PeerArea::Settings);
        save_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = save_ticket.get_untracked();
        busy.set(true);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(busy, save_ticket, ticket);
        spawn_local(async move {
            let result = async {
                // The backend accepts the complete schema. Merge only dirty fields
                // into a fresh server snapshot to preserve concurrent operator saves.
                let mut payload = settings_value(ApiClient.get("/api/v1/auth/settings").await?);
                if save_ticket.try_get_untracked() != Some(ticket)
                    || context.session_epoch.try_get_untracked() != Some(session_epoch)
                    || context.server_epoch.try_get_untracked() != Some(server_epoch)
                    || context.area_revocation_epoch_untracked(PeerArea::Settings) != settings_grant
                    || !context.is_admin_untracked()
                    || !context.can_write_area_untracked(PeerArea::Settings)
                {
                    return Err(af_web_core::api::ApiError {
                        status: 0,
                        code: Some("SERVER_CHANGED".into()),
                        message: "Server changed; request cancelled".into(),
                    });
                }
                for field in fields {
                    if let (Some(target), Some(value)) =
                        (payload.pointer_mut(&field), sent.pointer(&field))
                    {
                        *target = value.clone();
                    }
                }
                ApiClient
                    .put("/api/v1/admin/settings", Some(&payload))
                    .await?;
                ApiClient.get("/api/v1/auth/settings").await
            }
            .await;
            if draft.try_get_untracked().is_none()
                || save_ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Settings) != settings_grant
                || !context.is_admin_untracked()
                || !context.can_read_area_untracked(PeerArea::Settings)
                || !context.can_write_area_untracked(PeerArea::Settings)
            {
                return;
            }
            match result {
                Ok(server) => {
                    let server = settings_value(server);
                    draft.update(|draft| {
                        let _ = draft.acknowledge_saved(&sent, server.clone());
                    });
                    context.publish_settings_save(server.clone());
                    settings.commit(server);
                    context.toast(tt(context, "Settings saved"), false);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            busy_guard.release();
        });
    });
    let save_preferences = Callback::new(move |()| {
        let sent = draft_value(preferences);
        storage_set(
            "aetherflow-sidebar-pinned",
            if sent["sidebarPinned"] == true {
                "true"
            } else {
                "false"
            },
        );
        if let Some(window) = web_sys::window() {
            if let Ok(event) = web_sys::CustomEvent::new("af:preferences-changed") {
                let _ = window.dispatch_event(&event);
            }
        }
        preferences.update(|draft| draft.mark_saved(sent));
        context.toast(tt(context, "UI preferences saved"), false);
    });
    view! {
        <section class="space-y-6 py-5 min-w-0 max-w-full">
            <h2 class="text-2xl font-semibold">{move || tt(context, "Settings.title")}</h2>
            <TabsBar
                id_prefix="settings"
                active
                tabs=Signal::derive(move || {
                    vec![
                        ("general".into(), tt(context, "Settings.generalLocalization")),
                        ("providers".into(), tt(context, "Settings.flowAIProviders")),
                        ("profile".into(), tt(context, "Settings.security2fa")),
                        ("backups".into(), tt(context, "Settings.backupsRestore")),
                        ("oidc".into(), tt(context, "Settings.oidcClients")),
                        ("metadata".into(), tt(context, "Settings.metadata")),
                    ]
                })
            />
            <Show when=move || !can_read_settings.get()>
                <p
                    role="status"
                    class="rounded-xl border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
                >
                    {move || {
                        context
                            .area_block_reason(PeerArea::Settings, false)
                            .unwrap_or_default()
                    }}
                </p>
            </Show>
            <ResourceFeedback resource=settings />
            <TabPanel id_prefix="settings" id=Signal::derive(move || active.get())>
                <div class="space-y-6">
                    <Show when=move || active.get() == "general">
                        <ObsCard title=Signal::derive(move || tt(
                            context,
                            "Settings.navigationLocalization",
                        ))>
                            <div class="grid sm:grid-cols-2 gap-5">
                                <label class="text-sm space-y-2">
                                    <span>{move || tt(context, "Settings.displayTheme")}</span>
                                    <select
                                        class="glass-input px-3 py-2 block w-full"
                                        prop:value=move || context.theme.get()
                                        on:change=move |event| {
                                            context.set_theme(&event_target_value(&event));
                                        }
                                    >
                                        <option value="system">
                                            {move || tt(context, "Settings.themeSystem")}
                                        </option>
                                        <option value="dark">
                                            {move || tt(context, "Settings.themeDark")}
                                        </option>
                                        <option value="light">
                                            {move || tt(context, "Settings.themeLight")}
                                        </option>
                                    </select>
                                </label>
                                <label class="text-sm space-y-2">
                                    <span>{move || tt(context, "Settings.language")}</span>
                                    <select
                                        class="glass-input px-3 py-2 block w-full"
                                        prop:value=move || context.locale.get()
                                        on:change=move |event| {
                                            let locale = event_target_value(&event);
                                            context.set_locale(&locale);
                                            edit(draft, "language", json!(locale));
                                        }
                                    >
                                        {LOCALES
                                            .iter()
                                            .map(|id| {
                                                view! {
                                                    <option value=*id>
                                                        {move || tt(
                                                            context,
                                                            match *id {
                                                                "en" => "English",
                                                                "de" => "Deutsch",
                                                                "dk" => "Dansk",
                                                                "es" => "Español",
                                                                "fr" => "Français",
                                                                _ => "中文",
                                                            },
                                                        )}
                                                    </option>
                                                }
                                            })
                                            .collect_view()}
                                    </select>
                                </label>
                                <DraftInput
                                    draft
                                    field="timezone"
                                    label=move || tt(context, "Settings.timezone")
                                    placeholder="Europe/Berlin"
                                />
                                <DraftSelect
                                    draft
                                    field="defaultDashboard"
                                    label=move || tt(context, "Settings.defaultDashboard")
                                    options=TabId::ALL
                                        .into_iter()
                                        .filter(|tab| !tab.is_admin_only() || context.is_admin())
                                        .map(|tab| (tab.key(), tab.label()))
                                        .collect()
                                />
                                <DraftInput
                                    draft
                                    field="baseDomain"
                                    label=move || tt(context, "Settings.baseDomain")
                                    placeholder="example.com"
                                />
                            </div>
                            <nav
                                aria-label=move || tt(context, "Related settings")
                                class="mt-5 border-t border-white/10 pt-4 flex flex-wrap items-center gap-3"
                            >
                                <button
                                    type="button"
                                    class="obs-tab-pill px-4 py-2"
                                    on:click=move |_| context.select_tab(TabId::Notifications)
                                >
                                    {move || tt(context, "Navigation.notifications")}
                                </button>
                                <button
                                    type="button"
                                    class="obs-tab-pill px-4 py-2"
                                    on:click=move |_| {
                                        if context.is_admin() {
                                            context.navigate_to_subtab(TabId::McBrowser, "policy");
                                        } else {
                                            context.select_tab(TabId::McBrowser);
                                        }
                                    }
                                >
                                    {move || tt(context, "Settings.mcbrowserPolicy")}
                                </button>
                            </nav>
                            <Show when=move || !context.is_admin()>
                                <p class="text-sm text-slate-400 mt-4">
                                    {move || tt(context, "Settings.nonAdminSettings")}
                                </p>
                            </Show>
                            <Show when=move || context.is_admin()>
                                <DraftButtons
                                    draft
                                    busy
                                    on_save=save
                                    label=move || tt(context, "Settings.saveSettings")
                                    disabled=Signal::derive(move || {
                                        !context.can_write_area(crate::state::PeerArea::Settings)
                                    })
                                    title=Signal::derive(move || {
                                        context
                                            .area_block_reason(
                                                crate::state::PeerArea::Settings,
                                                true,
                                            )
                                            .unwrap_or_default()
                                    })
                                />
                            </Show>
                        </ObsCard>
                        <ObsCard>
                            <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
                                <h2 class="text-lg font-semibold">
                                    {move || tt(context, "Settings.interfacePreferences")}
                                </h2>
                                <div class="flex flex-wrap items-center gap-2">
                                    <span
                                        data-testid="settings-display-status"
                                        class=move || {
                                            if context.is_high_refresh_active() {
                                                "af-badge af-badge-indigo font-mono"
                                            } else {
                                                "af-badge font-mono"
                                            }
                                        }
                                    >
                                        {move || {
                                            let hz = context.detected_refresh_rate.get().to_string();
                                            if context.is_high_refresh_active() {
                                                tt_with(
                                                    context,
                                                    "Settings.displayStatusActive120",
                                                    &[("hz", &hz)],
                                                )
                                            } else {
                                                tt_with(
                                                    context,
                                                    "Settings.displayStatusStandard",
                                                    &[("hz", &hz)],
                                                )
                                            }
                                        }}
                                    </span>
                                    <span
                                        data-testid="settings-input-status"
                                        class=move || {
                                            if context.is_touch_mode_active() {
                                                "af-badge af-badge-indigo font-mono"
                                            } else {
                                                "af-badge font-mono"
                                            }
                                        }
                                    >
                                        {move || {
                                            if context.is_touch_mode_active() {
                                                tt(context, "Settings.inputStatusTouch")
                                            } else {
                                                tt(context, "Settings.inputStatusFine")
                                            }
                                        }}
                                    </span>
                                </div>
                            </div>

                            <div class="space-y-4 pb-4 border-b border-white/10">
                                <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-400">
                                    {move || tt(context, "Settings.displayEngineTitle")}
                                </h3>
                                <div class="grid md:grid-cols-2 gap-4">
                                    <div class="space-y-1.5">
                                        <label
                                            for="settings-high-refresh-mode"
                                            class="text-sm font-medium block"
                                        >
                                            {move || tt(context, "Settings.highRefreshCadence")}
                                        </label>
                                        <p
                                            id="settings-high-refresh-desc"
                                            class="text-xs text-slate-400"
                                        >
                                            {move || tt(context, "Settings.highRefreshDescription")}
                                        </p>
                                        <select
                                            id="settings-high-refresh-mode"
                                            aria-describedby="settings-high-refresh-desc"
                                            class="glass-input px-3 py-2 block w-full"
                                            prop:value=move || context.high_refresh_mode.get()
                                            on:change=move |event| {
                                                context.set_high_refresh_mode(&event_target_value(&event));
                                                context.haptic(6);
                                            }
                                        >
                                            <option value="auto">
                                                {move || {
                                                    let hz = context
                                                        .detected_refresh_rate
                                                        .get()
                                                        .to_string();
                                                    tt_with(
                                                        context,
                                                        "Settings.highRefreshAuto",
                                                        &[("hz", &hz)],
                                                    )
                                                }}
                                            </option>
                                            <option value="standard">
                                                {move || tt(context, "Settings.highRefresh60")}
                                            </option>
                                            <option value="120hz">
                                                {move || tt(context, "Settings.highRefresh120")}
                                            </option>
                                        </select>
                                    </div>

                                    <div class="space-y-1.5">
                                        <label
                                            for="settings-touch-mode"
                                            class="text-sm font-medium block"
                                        >
                                            {move || tt(context, "Settings.touchMode")}
                                        </label>
                                        <p
                                            id="settings-touch-mode-desc"
                                            class="text-xs text-slate-400"
                                        >
                                            {move || tt(context, "Settings.touchModeDescription")}
                                        </p>
                                        <select
                                            id="settings-touch-mode"
                                            aria-describedby="settings-touch-mode-desc"
                                            class="glass-input px-3 py-2 block w-full"
                                            prop:value=move || context.touch_mode.get()
                                            on:change=move |event| {
                                                context.set_touch_mode(&event_target_value(&event));
                                                context.haptic(6);
                                            }
                                        >
                                            <option value="auto">
                                                {move || {
                                                    if context.detected_touch_device.get() {
                                                        tt(context, "Settings.touchModeAutoTouch")
                                                    } else {
                                                        tt(context, "Settings.touchModeAutoFine")
                                                    }
                                                }}
                                            </option>
                                            <option value="on">
                                                {move || tt(context, "Settings.touchModeOn")}
                                            </option>
                                            <option value="off">
                                                {move || tt(context, "Settings.touchModeOff")}
                                            </option>
                                        </select>
                                    </div>
                                </div>
                            </div>

                            <div class="space-y-3 py-4 border-b border-white/10">
                                <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-400">
                                    {move || tt(context, "Settings.atmosphereTitle")}
                                </h3>
                                <div class="space-y-1.5">
                                    <div class="flex items-center justify-between gap-3">
                                        <label
                                            for="settings-aurora-opacity"
                                            class="text-sm font-medium"
                                        >
                                            {move || tt(context, "Settings.auroraOpacity")}
                                        </label>
                                        <output
                                            for="settings-aurora-opacity"
                                            data-testid="settings-aurora-opacity-value"
                                            class="text-xs font-mono font-semibold text-indigo-300"
                                        >
                                            {move || format!("{}%", context.aurora_opacity.get())}
                                        </output>
                                    </div>
                                    <p
                                        id="settings-aurora-opacity-desc"
                                        class="text-xs text-slate-400"
                                    >
                                        {move || tt(context, "Settings.auroraOpacityDescription")}
                                    </p>
                                    <input
                                        id="settings-aurora-opacity"
                                        type="range"
                                        min="0"
                                        max="100"
                                        step="5"
                                        aria-describedby="settings-aurora-opacity-desc"
                                        aria-valuetext=move || format!("{}%", context.aurora_opacity.get())
                                        class="obs-touch-target-standard w-full accent-indigo-500 cursor-pointer"
                                        prop:value=move || context.aurora_opacity.get().to_string()
                                        on:input=move |event| {
                                            context.set_aurora_opacity_str(&event_target_value(&event));
                                        }
                                        on:change=move |event| {
                                            context.set_aurora_opacity_str(&event_target_value(&event));
                                        }
                                    />
                                </div>

                                <div class="py-1">
                                    <label class="flex items-center gap-3 text-sm cursor-pointer">
                                        <input
                                            id="settings-aurora-animation"
                                            type="checkbox"
                                            class="obs-checkbox"
                                            aria-describedby="settings-aurora-animation-desc"
                                            prop:checked=move || context.aurora_animation.get()
                                            on:change=move |event| {
                                                context.set_aurora_animation(event_target_checked(&event));
                                                context.haptic(6);
                                            }
                                        />
                                        <span class="font-medium">
                                            {move || tt(context, "Settings.auroraAnimation")}
                                        </span>
                                    </label>
                                    <p
                                        id="settings-aurora-animation-desc"
                                        class="text-xs text-slate-400 mt-1 pl-7"
                                    >
                                        {move || tt(context, "Settings.auroraAnimationDescription")}
                                    </p>
                                </div>

                                <div class="py-1">
                                    <label class="flex items-center gap-3 text-sm cursor-pointer">
                                        <input
                                            id="settings-grain-display"
                                            type="checkbox"
                                            class="obs-checkbox"
                                            aria-describedby="settings-grain-display-desc"
                                            prop:checked=move || context.grain_display.get()
                                            on:change=move |event| {
                                                context.set_grain_display(event_target_checked(&event));
                                                context.haptic(6);
                                            }
                                        />
                                        <span class="font-medium">
                                            {move || tt(context, "Settings.grainDisplay")}
                                        </span>
                                    </label>
                                    <p
                                        id="settings-grain-display-desc"
                                        class="text-xs text-slate-400 mt-1 pl-7"
                                    >
                                        {move || tt(context, "Settings.grainDisplayDescription")}
                                    </p>
                                </div>

                                <div class="py-1">
                                    <label class="flex items-center gap-3 text-sm cursor-pointer">
                                        <input
                                            id="settings-card-lift"
                                            type="checkbox"
                                            class="obs-checkbox"
                                            aria-describedby="settings-card-lift-desc"
                                            prop:checked=move || context.card_lift.get() != 0
                                            on:change=move |event| {
                                                context.set_card_lift_enabled(event_target_checked(&event));
                                                context.haptic(6);
                                            }
                                        />
                                        <span class="font-medium">
                                            {move || tt(context, "Settings.cardLift")}
                                        </span>
                                    </label>
                                    <p
                                        id="settings-card-lift-desc"
                                        class="text-xs text-slate-400 mt-1 pl-7"
                                    >
                                        {move || tt(context, "Settings.cardLiftDescription")}
                                    </p>
                                </div>

                                <Show when=move || context.effective_reduced_motion()>
                                    <p
                                        role="status"
                                        data-testid="settings-reduced-motion-hint"
                                        class="text-xs text-amber-300 bg-amber-950/30 border border-amber-500/30 rounded-lg px-3 py-2"
                                    >
                                        {move || tt(context, "Settings.reducedMotionActiveHint")}
                                    </p>
                                </Show>

                                <div class="pt-1">
                                    <button
                                        type="button"
                                        data-testid="settings-atmosphere-reset"
                                        class="glass-button px-3 py-1.5 text-xs"
                                        on:click=move |_| {
                                            context.reset_atmosphere_defaults();
                                            context.haptic(8);
                                        }
                                    >
                                        {move || tt(context, "Reset atmosphere defaults")}
                                    </button>
                                </div>
                            </div>

                            <div class="pt-3">
                                <DraftCheck
                                    draft=preferences
                                    field="sidebarPinned"
                                    label=move || tt(context, "Settings.pinSidebar")
                                />
                                <label class="flex items-center gap-3 text-sm py-2">
                                    <input
                                        type="checkbox"
                                        class="obs-checkbox"
                                        prop:checked=move || context.haptic_feedback.get()
                                        on:change=move |event| {
                                            context.set_haptic_feedback(event_target_checked(&event))
                                        }
                                    />
                                    <span>{move || tt(context, "Settings.hapticFeedback")}</span>
                                </label>
                                <label class="flex items-center gap-3 text-sm py-2">
                                    <input
                                        type="checkbox"
                                        class="obs-checkbox"
                                        prop:checked=move || context.reduced_motion.get()
                                        on:change=move |event| {
                                            context.set_reduced_motion(event_target_checked(&event))
                                        }
                                    />
                                    <span>{move || tt(context, "Settings.reducedMotion")}</span>
                                </label>
                                <label class="flex items-center gap-3 text-sm py-2">
                                    <input
                                        type="checkbox"
                                        class="obs-checkbox"
                                        prop:checked=move || context.immersive_overview.get()
                                        on:change=move |event| context.set_immersive_overview(event_target_checked(&event))
                                    />
                                    <span>{move || tt(context, "Immersive dashboard layout")}</span>
                                </label>
                                <label class="flex items-center gap-3 text-sm py-2">
                                    <input
                                        type="checkbox"
                                        class="obs-checkbox"
                                        prop:checked=move || context.show_gpu.get()
                                        on:change=move |event| context.set_show_gpu(event_target_checked(&event))
                                    />
                                    <span>{move || tt(context, "Show GPU telemetry")}</span>
                                </label>
                                <label class="flex items-center gap-3 text-sm py-2">
                                    <input
                                        type="checkbox"
                                        class="obs-checkbox"
                                        prop:checked=move || context.show_transfer_history.get()
                                        on:change=move |event| context.set_show_transfer_history(event_target_checked(&event))
                                    />
                                    <span>{move || tt(context, "Show transfer history")}</span>
                                </label>
                            </div>
                            <DraftButtons draft=preferences busy=pref_busy on_save=save_preferences />
                        </ObsCard>
                    </Show>
                    <Show when=move || active.get() == "providers" && context.is_admin()>
                        <ProviderSettings draft busy on_save=save />
                    </Show>
                    <Show when=move || active.get() == "general" && context.is_admin()>
                        <GrantInvalidationBoundary areas=&[PeerArea::Updates]>
                            <SystemUpdates draft settings_busy=busy />
                        </GrantInvalidationBoundary>
                    </Show>
                    <Show when=move || active.get() == "profile">
                        <ProfileSecurity />
                    </Show>
                    <Show when=move || active.get() == "backups" && context.is_admin()>
                        <GrantInvalidationBoundary areas=&[PeerArea::Settings]>
                            <BackupsSettings />
                        </GrantInvalidationBoundary>
                    </Show>
                    <Show when=move || active.get() == "oidc" && context.is_admin()>
                        <GrantInvalidationBoundary areas=&[PeerArea::Settings]>
                            <OidcSettings />
                        </GrantInvalidationBoundary>
                    </Show>
                    <Show when=move || active.get() == "metadata" && context.is_admin()>
                        <GrantInvalidationBoundary areas=&[PeerArea::Settings]>
                            <MetadataSettings />
                        </GrantInvalidationBoundary>
                    </Show>
                    <Show when=move || {
                        !context.is_admin()
                            && matches!(
                                active.get().as_str(),
                                "providers" | "backups" | "oidc" | "metadata"
                            )
                    }>
                        <EmptyState title="Common.adminRequired" />
                    </Show>
                </div>
            </TabPanel>
        </section>
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_refresh_masks_credentials_and_preserves_extra_fields() {
        let value = settings_value(
            json!({"language":"de","geminiApiKey":"secret-gemini","openaiApiKey":"enc:v1:opaque","anthropicApiKey":"secret-claude","futureOption":{"enabled":true}}),
        );
        for field in ["geminiApiKey", "openaiApiKey", "anthropicApiKey"] {
            assert_eq!(value[field], "****");
        }
        assert_eq!(value["language"], "de");
        assert_eq!(value["futureOption"]["enabled"], true);
        assert_eq!(value["updateChannel"], "stable");
        assert_eq!(settings_value(Value::Null)["geminiApiKey"], "");
    }

    #[test]
    fn typed_update_receipts_normalize_without_overwriting_api_evidence() {
        let receipt = SelfUpdateJobStatus {
            status: "succeeded".into(),
            completed: true,
            success: true,
            job_unit: "aetherflow-self-update-deploy-stable-0123456789abcdef.service".into(),
            exit_code: Some(0),
            ..Default::default()
        };
        let mut value = serde_json::to_value(receipt).unwrap();
        value["phase"] = json!("verified");
        let normalized = update_status(&value);
        assert_eq!(normalized["state"], "complete");
        assert_eq!(normalized["operationId"], value["job_unit"]);
        assert_eq!(normalized["phase"], "verified");
        value["state"] = json!("interrupted");
        assert_eq!(update_status(&value)["state"], "interrupted");
        let legacy = json!({"state":"running","operationId":"legacy-job","extra":true});
        assert_eq!(update_status(&legacy), legacy);
    }

    #[test]
    fn translated_update_heading_keeps_the_navigation_contract() {
        assert_eq!(
            af_web_core::i18n::translate("en", "Settings.systemUpdates"),
            "System Updates"
        );
        assert_ne!(
            af_web_core::i18n::translate("de", "Settings.systemUpdates"),
            "System Updates"
        );
        assert_eq!(bytes(1_048_576.0), "1.0 MiB");
        assert_eq!(bytes(-1.0), "Unknown");
    }
}
