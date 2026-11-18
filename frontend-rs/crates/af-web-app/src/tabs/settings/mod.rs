use crate::state::{app, json_rows, use_api, ApiResource, TabId};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{ConfirmDialog, DataGrid, EmptyState, Modal, ObsCard, TabPanel, TabsBar};
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

#[component]
pub fn SettingsTab() -> impl IntoView {
    let context = app();
    let settings = use_api("/api/v1/auth/settings".to_string());
    poll_resource(settings, 30_000);
    let draft = RwSignal::new(FormDraft::new(settings_value(
        context.settings.get_untracked(),
    )));
    let busy = RwSignal::new(false);
    let active = RwSignal::new("general".to_string());
    let preferences = RwSignal::new(FormDraft::new(json!({
        "sidebarPinned":storage_get("aetherflow-sidebar-pinned").as_deref() == Some("true")
    })));
    let pref_busy = RwSignal::new(false);
    Effect::new(move |_| {
        let value = settings.data.get();
        if value.is_object() {
            let value = settings_value(value);
            draft.update(|draft| draft.apply_server_refresh(value.clone()));
            context.settings.set(value);
        }
    });
    let save = Callback::new(move |()| {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let sent = draft_value(draft);
        let fields =
            draft.with_untracked(|d| d.dirty_fields().map(str::to_string).collect::<Vec<_>>());
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            let result = async {
                // The backend accepts the complete schema. Merge only dirty fields
                // into a fresh server snapshot to preserve concurrent operator saves.
                let mut payload = settings_value(ApiClient.get("/api/v1/auth/settings").await?);
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
            if draft.try_get_untracked().is_none() {
                return;
            }
            match result {
                Ok(server) => {
                    let server = settings_value(server);
                    draft.update(|draft| {
                        let _ = draft.acknowledge_saved(&sent, server.clone());
                    });
                    context.settings.set(server.clone());
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
                                    on:click=move |_| context.select_tab(TabId::McBrowser)
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
                                />
                            </Show>
                        </ObsCard>
                        <ObsCard>
                            <h2 class="text-lg font-semibold mb-4">
                                {move || tt(context, "Settings.interfacePreferences")}
                            </h2>
                            <DraftCheck
                                draft=preferences
                                field="sidebarPinned"
                                label=move || tt(context, "Settings.pinSidebar")
                            />
                            <label class="flex items-center gap-3 text-sm py-2">
                                <input
                                    type="checkbox"
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
                                    prop:checked=move || context.reduced_motion.get()
                                    on:change=move |event| {
                                        context.set_reduced_motion(event_target_checked(&event))
                                    }
                                />
                                <span>{move || tt(context, "Settings.reducedMotion")}</span>
                            </label>
                            <DraftButtons draft=preferences busy=pref_busy on_save=save_preferences />
                        </ObsCard>
                    </Show>
                    <Show when=move || active.get() == "providers" && context.is_admin()>
                        <ProviderSettings draft busy on_save=save />
                    </Show>
                    <Show when=move || active.get() == "general" && context.is_admin()>
                        <SystemUpdates draft settings_busy=busy />
                    </Show>
                    <Show when=move || active.get() == "profile">
                        <ProfileSecurity />
                    </Show>
                    <Show when=move || active.get() == "backups" && context.is_admin()>
                        <BackupsSettings />
                    </Show>
                    <Show when=move || active.get() == "oidc" && context.is_admin()>
                        <OidcSettings />
                    </Show>
                    <Show when=move || active.get() == "metadata" && context.is_admin()>
                        <MetadataSettings />
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
