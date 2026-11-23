mod preferences;
mod resources;
mod session;
mod tabs;

pub(crate) use preferences::hydrate_preferences_with;
#[allow(unused_imports)]
pub(crate) use preferences::HydratedPreferences;
pub use preferences::{
    apply_display_preferences_dom, apply_locale_dom, apply_theme_dom, detect_browser_locale,
    format_aurora_opacity_unit, normalize_aurora_opacity_pct, normalize_card_lift,
    normalize_high_refresh_mode, normalize_touch_mode, quantize_aurora_opacity_pct,
    quantize_refresh_rate, resolve_high_refresh_active, resolve_touch_mode_active,
};
use preferences::{
    detect_reduced_motion_preference, detect_touch_device, initial_preference,
    legacy_storage_envelope, legacy_touch_mode_value, normalize_theme, theme_is_light,
};
#[allow(unused_imports)]
pub(crate) use resources::ResourceReadJob;
pub use resources::{
    json_rows, use_api, use_api_typed, use_typed_api, ApiResource, TypedApiResource,
};
pub(crate) use resources::{owned_resource_reads, run_resource_read, ResourceReads};
#[cfg(any(test, target_arch = "wasm32"))]
use session::is_spa_fallback_path;
pub use session::{app, current_path, install_session, navigate, query_param, worker_pool};
use session::{
    confirmed_session_identity, deserialize_metrics, deserialize_user, purge_ai_sessions,
    same_authenticated_identity, suspend_shell_interaction,
};
pub use tabs::{clamp_tab_for_role, stroke_icon, TabId};

use af_web_core::{
    api::{storage_set, ApiClient, ApiError},
    ws::ConnectionState,
};
use leptos::prelude::*;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

static NEXT_TOAST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct Toast {
    pub id: u64,
    pub message: String,
    pub params: Vec<(String, String)>,
    pub error: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct ServicesRequest {
    epoch: u64,
    generation: u64,
}

#[derive(Clone, Copy, Default)]
struct ServicesOrder {
    issued: u64,
    accepted: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferSummary {
    pub id: u64,
    pub path: String,
    pub sent: u64,
    pub size: u64,
    pub status: String,
    pub active: bool,
}

#[derive(Clone, Copy)]
pub struct AppContext {
    pub user: RwSignal<Option<Value>>,
    pub auth_loading: RwSignal<bool>,
    auth_generation: RwSignal<u64>,
    pub session_epoch: RwSignal<u64>,
    pub authenticated_at: RwSignal<f64>,
    pub tab: RwSignal<TabId>,
    pub pending_subtab: RwSignal<Option<(TabId, String)>>,
    pub locale: RwSignal<String>,
    pub catalog_revision: RwSignal<u32>,
    pub theme: RwSignal<String>,
    pub immersive_overview: RwSignal<bool>,
    pub show_gpu: RwSignal<bool>,
    pub show_transfer_history: RwSignal<bool>,
    pub reduced_motion: RwSignal<bool>,
    pub system_reduced_motion: RwSignal<bool>,
    pub haptic_feedback: RwSignal<bool>,
    pub high_refresh_mode: RwSignal<String>,
    pub detected_refresh_rate: RwSignal<u32>,
    pub touch_mode: RwSignal<String>,
    pub detected_touch_device: RwSignal<bool>,
    pub aurora_opacity: RwSignal<u8>,
    pub aurora_animation: RwSignal<bool>,
    pub grain_display: RwSignal<bool>,
    pub card_lift: RwSignal<i8>,
    pub settings: RwSignal<Value>,
    pub metrics: RwSignal<Value>,
    pub services: RwSignal<Value>,
    services_order: RwSignal<ServicesOrder>,
    pub(crate) live_samples: RwSignal<Vec<crate::tabs::overview::Sample>>,
    pub connection: RwSignal<ConnectionState>,
    pub pending: RwSignal<usize>,
    pub notifications: RwSignal<Vec<Value>>,
    pub transfers: RwSignal<Vec<TransferSummary>>,
    pub toasts: RwSignal<Vec<Toast>>,
    pub banners: RwSignal<Vec<String>>,
    pub command_open: RwSignal<bool>,
    pub notifications_open: RwSignal<bool>,
    pub mobile_open: RwSignal<bool>,
    pub history_revision: RwSignal<u64>,
    pub marketplace_revision: RwSignal<u64>,
}
impl AppContext {
    pub fn new() -> Self {
        #[cfg(target_arch = "wasm32")]
        let tab = web_sys::window()
            .and_then(|w| w.location().search().ok())
            .and_then(|q| web_sys::UrlSearchParams::new_with_str(&q).ok())
            .and_then(|q| q.get("tab"))
            .map(|s| TabId::from_key(&s))
            .unwrap_or_default();
        #[cfg(not(target_arch = "wasm32"))]
        let tab = TabId::default();
        let hydrated = hydrate_preferences_with(initial_preference);
        let locale = hydrated.locale.clone().unwrap_or_else(|| {
            #[cfg(target_arch = "wasm32")]
            let language = web_sys::window().and_then(|window| window.navigator().language());
            #[cfg(not(target_arch = "wasm32"))]
            let language: Option<String> = None;
            detect_browser_locale(language.as_deref()).into()
        });
        #[cfg(target_arch = "wasm32")]
        apply_locale_dom(&locale);
        let context = Self {
            user: RwSignal::new(None),
            auth_loading: RwSignal::new(true),
            auth_generation: RwSignal::new(0),
            session_epoch: RwSignal::new(0),
            authenticated_at: RwSignal::new(0.0),
            tab: RwSignal::new(tab),
            pending_subtab: RwSignal::new(None),
            locale: RwSignal::new(locale),
            catalog_revision: RwSignal::new(0),
            theme: RwSignal::new(hydrated.theme),
            immersive_overview: RwSignal::new(hydrated.immersive_overview),
            show_gpu: RwSignal::new(hydrated.show_gpu),
            show_transfer_history: RwSignal::new(hydrated.show_transfer_history),
            reduced_motion: RwSignal::new(hydrated.reduced_motion),
            system_reduced_motion: RwSignal::new(detect_reduced_motion_preference()),
            haptic_feedback: RwSignal::new(hydrated.haptic_feedback),
            high_refresh_mode: RwSignal::new(hydrated.high_refresh_mode),
            detected_refresh_rate: RwSignal::new(60),
            touch_mode: RwSignal::new(hydrated.touch_mode),
            detected_touch_device: RwSignal::new(detect_touch_device()),
            aurora_opacity: RwSignal::new(hydrated.aurora_opacity),
            aurora_animation: RwSignal::new(hydrated.aurora_animation),
            grain_display: RwSignal::new(hydrated.grain_display),
            card_lift: RwSignal::new(hydrated.card_lift),
            settings: RwSignal::new(Value::Null),
            metrics: RwSignal::new(Value::Null),
            services: RwSignal::new(Value::Null),
            services_order: RwSignal::new(ServicesOrder::default()),
            live_samples: RwSignal::new(vec![]),
            connection: RwSignal::new(ConnectionState::Connecting),
            pending: RwSignal::new(0),
            notifications: RwSignal::new(vec![]),
            transfers: RwSignal::new(vec![]),
            toasts: RwSignal::new(vec![]),
            banners: RwSignal::new(vec![]),
            command_open: RwSignal::new(false),
            notifications_open: RwSignal::new(false),
            mobile_open: RwSignal::new(false),
            history_revision: RwSignal::new(0),
            marketplace_revision: RwSignal::new(0),
        };
        provide_context(af_web_ui::UiLocale(Signal::derive(move || {
            context.catalog_revision.get();
            context.locale.get()
        })));
        context.load_locale(context.locale.get_untracked());
        context
    }
    pub fn is_admin(self) -> bool {
        self.typed_user().is_some_and(|user| user.role == "admin")
    }
    pub fn t(self, key: &str) -> String {
        self.catalog_revision.get();
        af_web_core::i18n::translate(&self.locale.get(), key)
    }
    pub fn t_with(self, key: &str, vars: &[(&str, &str)]) -> String {
        self.catalog_revision.get();
        af_web_core::i18n::translate_with(&self.locale.get(), key, vars)
    }
    pub fn set_locale(self, locale: &str) {
        if af_web_core::i18n::LOCALES.contains(&locale) {
            storage_set("aetherflow-language", locale);
            self.locale.set(locale.into());
            self.sync_legacy_system_storage();
            apply_locale_dom(locale);
            self.load_locale(locale.to_string());
        }
    }
    pub(super) fn load_locale(self, locale: String) {
        #[cfg(target_arch = "wasm32")]
        if locale != "en" {
            spawn_local(async move {
                match af_web_core::i18n::ensure_locale_loaded(&locale).await {
                    Ok(true) => {
                        let _ = self.catalog_revision.try_update(|revision| {
                            *revision = revision.wrapping_add(1);
                        });
                        // Shell navigation also has direct locale subscribers.
                        // Notify them when their deferred catalog becomes usable.
                        if self.locale.try_get_untracked().as_deref() == Some(locale.as_str()) {
                            let _ = self.locale.try_update(|_| {});
                        }
                    }
                    Ok(false) => {}
                    Err(error) => web_sys::console::warn_1(&error.into()),
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = locale;
    }
    pub fn typed_user(self) -> Option<af_web_core::models::User> {
        self.user
            .with(|user| user.as_ref().and_then(deserialize_user))
    }
    /// Tracks the existing JSON signal while exposing the shared domain model.
    pub fn typed_metrics(self) -> af_web_core::models::SystemMetrics {
        self.metrics.with(deserialize_metrics)
    }
    /// All HTTP service writers share an ordering with live telemetry. A newer
    /// accepted snapshot or account reset invalidates an older HTTP snapshot.
    pub(crate) fn begin_services_request(self) -> ServicesRequest {
        self.services_order.update(|order| order.issued += 1);
        ServicesRequest {
            epoch: self.session_epoch.get_untracked(),
            generation: self.services_order.get_untracked().issued,
        }
    }
    pub(crate) fn finish_services_request(self, request: ServicesRequest, value: Value) -> bool {
        if self.session_epoch.try_get_untracked() != Some(request.epoch)
            || self
                .services_order
                .try_get_untracked()
                .is_none_or(|order| order.accepted > request.generation)
            || self.user.try_get_untracked().flatten().is_none()
        {
            return false;
        }
        self.services_order
            .update(|order| order.accepted = request.generation);
        self.services.set(value);
        true
    }
    pub(crate) fn publish_metrics(self, metrics: Value) {
        self.live_samples
            .update(|samples| crate::tabs::overview::Sample::record_live(samples, &metrics));
        self.metrics.set(metrics);
    }

    pub(crate) fn publish_live_services(self, value: Value) {
        self.services_order.update(|order| {
            order.issued += 1;
            order.accepted = order.issued;
        });
        self.services.set(value);
    }
    fn sync_legacy_system_storage(self) {
        let mut state_obj = initial_preference("aetherflow-system-storage")
            .as_deref()
            .and_then(|raw| legacy_storage_envelope(Some(raw)))
            .and_then(|val| val.as_object().cloned())
            .unwrap_or_default();
        let opacity_pct =
            quantize_aurora_opacity_pct(f64::from(self.aurora_opacity.get_untracked()));
        let opacity_unit = (f64::from(opacity_pct) / 100.0 * 100.0).round() / 100.0;
        state_obj.insert("theme".into(), Value::String(self.theme.get_untracked()));
        state_obj.insert(
            "language".into(),
            Value::String(self.locale.get_untracked()),
        );
        state_obj.insert("auroraOpacity".into(), serde_json::json!(opacity_unit));
        state_obj.insert(
            "auroraAnimation".into(),
            Value::Bool(self.aurora_animation.get_untracked()),
        );
        state_obj.insert(
            "grainDisplay".into(),
            Value::Bool(self.grain_display.get_untracked()),
        );
        state_obj.insert(
            "cardLift".into(),
            serde_json::json!(self.card_lift.get_untracked()),
        );
        state_obj.insert(
            "highRefreshMode".into(),
            Value::String(
                normalize_high_refresh_mode(&self.high_refresh_mode.get_untracked()).into(),
            ),
        );
        state_obj.insert(
            "touchMode".into(),
            Value::String(legacy_touch_mode_value(&self.touch_mode.get_untracked()).into()),
        );
        state_obj.insert(
            "hapticFeedback".into(),
            Value::Bool(self.haptic_feedback.get_untracked()),
        );
        state_obj.insert(
            "reducedMotion".into(),
            Value::Bool(self.reduced_motion.get_untracked()),
        );
        state_obj.insert(
            "dashboardDensity".into(),
            Value::String(
                if self.immersive_overview.get_untracked() {
                    "immersive"
                } else {
                    "compact"
                }
                .into(),
            ),
        );
        state_obj.insert(
            "showGpuWidget".into(),
            Value::Bool(self.show_gpu.get_untracked()),
        );
        state_obj.insert(
            "showDataUsageWidget".into(),
            Value::Bool(self.show_transfer_history.get_untracked()),
        );
        let envelope = serde_json::json!({
            "state": state_obj,
            "version": 0,
        });
        if let Ok(serialized) = serde_json::to_string(&envelope) {
            storage_set("aetherflow-system-storage", &serialized);
        }
    }
    pub fn effective_reduced_motion(self) -> bool {
        self.reduced_motion.get() || self.system_reduced_motion.get()
    }
    pub fn is_high_refresh_active(self) -> bool {
        !self.effective_reduced_motion()
            && resolve_high_refresh_active(
                &self.high_refresh_mode.get(),
                self.detected_refresh_rate.get(),
            )
    }
    pub fn is_touch_mode_active(self) -> bool {
        resolve_touch_mode_active(&self.touch_mode.get(), self.detected_touch_device.get())
    }
    pub fn is_light(self) -> bool {
        theme_is_light(&self.theme.get())
    }
    pub fn set_theme(self, pref: &str) {
        let pref = normalize_theme(pref);
        storage_set("aetherflow-theme", pref);
        self.theme.set(pref.into());
        self.sync_legacy_system_storage();
    }
    pub fn toggle_theme(self) {
        let light = theme_is_light(&self.theme.get_untracked());
        self.set_theme(if light { "dark" } else { "light" });
        self.haptic(10);
    }
    pub fn set_immersive_overview(self, enabled: bool) {
        storage_set(
            "aetherflow-immersive-overview",
            if enabled { "true" } else { "false" },
        );
        storage_set(
            "aetherflow-dashboard-density",
            if enabled { "immersive" } else { "compact" },
        );
        self.immersive_overview.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_show_gpu(self, enabled: bool) {
        storage_set(
            "aetherflow-show-gpu",
            if enabled { "true" } else { "false" },
        );
        self.show_gpu.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_show_transfer_history(self, enabled: bool) {
        storage_set(
            "aetherflow-show-transfer-history",
            if enabled { "true" } else { "false" },
        );
        self.show_transfer_history.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_reduced_motion(self, enabled: bool) {
        storage_set(
            "aetherflow-reduced-motion",
            if enabled { "true" } else { "false" },
        );
        self.reduced_motion.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_haptic_feedback(self, enabled: bool) {
        storage_set(
            "aetherflow-haptic-feedback",
            if enabled { "true" } else { "false" },
        );
        self.haptic_feedback.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_high_refresh_mode(self, mode: &str) {
        let normalized = normalize_high_refresh_mode(mode);
        storage_set("aetherflow-high-refresh-mode", normalized);
        self.high_refresh_mode.set(normalized.into());
        self.sync_legacy_system_storage();
    }
    pub fn set_touch_mode(self, mode: &str) {
        let normalized = normalize_touch_mode(mode);
        storage_set("aetherflow-touch-mode", normalized);
        self.touch_mode.set(normalized.into());
        self.sync_legacy_system_storage();
    }
    pub fn set_aurora_opacity(self, pct: u8) {
        let quantized = quantize_aurora_opacity_pct(f64::from(pct));
        storage_set(
            "aetherflow-aurora-opacity",
            &format_aurora_opacity_unit(quantized),
        );
        self.aurora_opacity.set(quantized);
        self.sync_legacy_system_storage();
    }
    pub fn set_aurora_opacity_str(self, raw: &str) {
        self.set_aurora_opacity(normalize_aurora_opacity_pct(raw));
    }
    pub fn set_aurora_animation(self, enabled: bool) {
        storage_set(
            "aetherflow-aurora-animation",
            if enabled { "true" } else { "false" },
        );
        self.aurora_animation.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_grain_display(self, enabled: bool) {
        let flag = if enabled { "true" } else { "false" };
        storage_set("aetherflow-grain-display", flag);
        storage_set("aetherflow-grain", flag);
        self.grain_display.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_card_lift(self, lift_px: i8) {
        let normalized = normalize_card_lift(&lift_px.to_string());
        storage_set("aetherflow-card-lift", &normalized.to_string());
        self.card_lift.set(normalized);
        self.sync_legacy_system_storage();
    }
    pub fn set_card_lift_enabled(self, enabled: bool) {
        self.set_card_lift(if enabled { -4 } else { 0 });
    }
    pub fn reset_atmosphere_defaults(self) {
        self.set_theme("dark");
        self.set_aurora_opacity(55);
        self.set_aurora_animation(false);
        self.set_grain_display(true);
        self.set_card_lift(-4);
    }
    pub fn haptic(self, ms: u32) {
        if !self.haptic_feedback.get_untracked()
            || self.reduced_motion.get_untracked()
            || self.system_reduced_motion.get_untracked()
        {
            return;
        }
        if let Some(window) = web_sys::window() {
            let navigator = window.navigator();
            if let Some(vibrate) = js_sys::Reflect::get(&navigator, &"vibrate".into())
                .ok()
                .and_then(|vibrate| vibrate.dyn_into::<js_sys::Function>().ok())
            {
                let _ = vibrate.call1(&navigator, &ms.into());
            }
        }
    }
    pub fn select_tab(self, tab: TabId) {
        let tab = clamp_tab_for_role(tab, self.is_admin());
        self.tab.set(tab);
        self.mobile_open.set(false);
        #[cfg(target_arch = "wasm32")]
        {
            if self.normalize_fallback_url(tab) {
                return;
            }
            if let Some(window) =
                web_sys::window().filter(|w| w.location().pathname().ok().as_deref() == Some("/"))
            {
                if let Ok(params) = web_sys::UrlSearchParams::new_with_str(
                    &window.location().search().unwrap_or_default(),
                ) {
                    if tab == TabId::Overview {
                        params.delete("tab");
                    } else {
                        params.set("tab", tab.key());
                    }
                    let query = String::from(params.to_string());
                    let target = format!(
                        "/{}{}",
                        if query.is_empty() {
                            String::new()
                        } else {
                            format!("?{query}")
                        },
                        window.location().hash().unwrap_or_default()
                    );
                    if current_path() != target {
                        if let Ok(history) = window.history() {
                            let _ = history.push_state_with_url(
                                &wasm_bindgen::JsValue::NULL,
                                "",
                                Some(&target),
                            );
                        }
                    }
                }
            }
        }
    }
    pub fn navigate_to_subtab(self, tab: TabId, subtab: impl Into<String>) {
        let clamped = clamp_tab_for_role(tab, self.is_admin());
        if clamped == tab {
            self.pending_subtab.set(Some((clamped, subtab.into())));
        } else {
            self.pending_subtab.set(None);
        }
        if self.tab.get_untracked() != clamped {
            self.select_tab(clamped);
        } else {
            self.mobile_open.set(false);
        }
    }
    pub fn take_pending_subtab(self, tab: TabId) -> Option<String> {
        let matched = self.pending_subtab.with_untracked(|pending| {
            pending
                .as_ref()
                .filter(|(target, _)| *target == tab)
                .map(|(_, subtab)| subtab.clone())
        });
        if matched.is_some() {
            self.pending_subtab.set(None);
        }
        matched
    }
    pub fn normalize_fallback_url(self, tab: TabId) -> bool {
        #[cfg(target_arch = "wasm32")]
        {
            if let Some(window) = web_sys::window().filter(|window| {
                window
                    .location()
                    .pathname()
                    .ok()
                    .is_some_and(|path| is_spa_fallback_path(&path))
            }) {
                if let Ok(history) = window.history() {
                    return history
                        .replace_state_with_url(
                            &wasm_bindgen::JsValue::NULL,
                            "",
                            Some(&format!("/?tab={}", tab.key())),
                        )
                        .is_ok();
                }
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = tab;
        false
    }
    pub fn replace_tab_url(self, tab: TabId) {
        if self.normalize_fallback_url(tab) {
            return;
        }
        if let Some(window) =
            web_sys::window().filter(|w| w.location().pathname().ok().as_deref() == Some("/"))
        {
            if let Ok(url) = web_sys::Url::new(&window.location().href().unwrap_or_default()) {
                if tab == TabId::Overview {
                    url.search_params().delete("tab");
                } else {
                    url.search_params().set("tab", tab.key());
                }
                if let Ok(history) = window.history() {
                    let _ = history.replace_state_with_url(
                        &wasm_bindgen::JsValue::NULL,
                        "",
                        Some(&format!("{}{}{}", url.pathname(), url.search(), url.hash())),
                    );
                }
            }
        }
    }
    pub fn toast(self, message: impl Into<String>, error: bool) {
        self.toast_with(message, &[], error);
    }
    pub fn toast_with(self, key: impl Into<String>, params: &[(&str, &str)], error: bool) {
        let id = NEXT_TOAST_ID.fetch_add(1, Ordering::Relaxed);
        let message = key.into();
        let params = params
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();
        self.toasts.update(|toasts| {
            toasts.push(Toast {
                id,
                message,
                params,
                error,
            });
            if toasts.len() > 8 {
                toasts.remove(0);
            }
        });
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(6000).await;
            if self.toasts.try_get_untracked().is_some() {
                self.toasts.update(|toasts| toasts.retain(|t| t.id != id));
            }
        });
    }
    pub fn render_toast(&self, toast: &Toast) -> String {
        if toast.params.is_empty() {
            self.t(&toast.message)
        } else {
            let borrowed = toast
                .params
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            self.t_with(&toast.message, &borrowed)
        }
    }
    pub fn refresh_session(self) {
        self.auth_generation.update(|g| *g += 1);
        let generation = self.auth_generation.get_untracked();
        let epoch = self.session_epoch.get_untracked();
        let transport_epoch = af_web_core::api::current_auth_epoch();
        spawn_local(async move {
            let consent = web_sys::window()
                .and_then(|w| w.location().pathname().ok())
                .is_some_and(|p| p.trim_end_matches('/') == "/oauth/consent");
            let result = if consent {
                ApiClient.probe_session().await
            } else {
                ApiClient.get("/api/v1/auth/session").await
            };
            if self.auth_generation.try_get_untracked() != Some(generation)
                || self.session_epoch.try_get_untracked() != Some(epoch)
                || af_web_core::api::current_auth_epoch() != transport_epoch
            {
                return;
            }
            let result = result.and_then(|user| {
                if af_web_core::api::auth_revalidation_pending()
                    && !confirmed_session_identity(&user)
                {
                    Err(ApiError {
                        status: 401,
                        code: Some("SESSION_UNCONFIRMED".into()),
                        message: "Session identity could not be confirmed".into(),
                    })
                } else {
                    Ok(user)
                }
            });
            let prev_user = self.user.get_untracked();
            match result {
                Ok(next_user) => {
                    let revalidating = af_web_core::api::auth_revalidation_pending();
                    if !revalidating
                        && !same_authenticated_identity(prev_user.as_ref(), Some(&next_user))
                    {
                        if prev_user.is_some() {
                            self.reset_account_scoped_state();
                        } else if self.session_epoch.get_untracked() > 0 {
                            af_web_core::api::bump_auth_epoch_and_abort();
                        }
                        if prev_user.is_some() || self.session_epoch.get_untracked() > 0 {
                            self.session_epoch.update(|epoch| *epoch += 1);
                        }
                    }
                    let tab = self.tab.get_untracked();
                    let is_admin =
                        deserialize_user(&next_user).is_some_and(|user| user.role == "admin");
                    let clamped = clamp_tab_for_role(tab, is_admin);
                    if tab != clamped {
                        self.tab.set(clamped);
                        self.replace_tab_url(clamped);
                    }
                    self.authenticated_at.set(js_sys::Date::now());
                    self.user.set(Some(next_user));
                    if revalidating
                        && !af_web_core::api::resume_after_auth_revalidation(transport_epoch)
                    {
                        return;
                    }
                }
                Err(_) => {
                    if prev_user.is_some() {
                        self.reset_account_scoped_state();
                        self.session_epoch.update(|epoch| *epoch += 1);
                    }
                    af_web_core::api::clear_csrf_token();
                    self.user.set(None);
                }
            }
            self.auth_loading.set(false);
        });
    }
    pub(super) fn revalidate_external_session(self) {
        // The cookie may already belong to another account. Close the transport
        // gate and invalidate the old shell before starting any async work.
        af_web_core::api::suspend_for_auth_revalidation();
        suspend_shell_interaction();
        self.auth_loading.set(true);
        self.clear_account_scoped_state();
        self.session_epoch.update(|epoch| *epoch += 1);
        self.refresh_session();
    }
    pub(super) fn reset_account_scoped_state(self) {
        af_web_core::api::bump_auth_epoch_and_abort();
        self.clear_account_scoped_state();
    }
    fn clear_account_scoped_state(self) {
        purge_ai_sessions();
        self.settings.set(Value::Null);
        self.metrics.set(Value::Null);
        self.services_order.update(|order| {
            order.issued += 1;
            order.accepted = order.issued;
        });
        self.services.set(Value::Null);
        self.live_samples.set(vec![]);
        self.pending.set(0);
        self.pending_subtab.set(None);
        self.notifications.set(vec![]);
        self.transfers.set(vec![]);
        self.toasts.set(vec![]);
        self.banners.set(vec![]);
        self.mobile_open.set(false);
        self.command_open.set(false);
        self.notifications_open.set(false);
    }
    pub fn logout(self) {
        af_web_core::api::bump_auth_epoch_and_abort();
        self.auth_generation.update(|generation| *generation += 1);
        let origin_epoch = af_web_core::api::current_auth_epoch();
        spawn_local(async move {
            let mut revoked = false;
            for _ in 0..2 {
                let result = ApiClient.request("/api/v1/auth/logout", "POST", None).await;
                if af_web_core::api::current_auth_epoch() != origin_epoch {
                    return;
                }
                match result {
                    Ok(_) => {
                        revoked = true;
                        break;
                    }
                    Err(error) if error.status == 401 => {
                        let session = ApiClient.get("/api/v1/auth/session").await;
                        if af_web_core::api::current_auth_epoch() != origin_epoch {
                            return;
                        }
                        if session.is_err_and(|error| error.status == 401) {
                            revoked = true;
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
            if !revoked {
                let session = ApiClient.get("/api/v1/auth/session").await;
                if af_web_core::api::current_auth_epoch() != origin_epoch {
                    return;
                }
                match session {
                    Ok(_) => {
                        self.toast("Auth.signOutFailed", true);
                        return;
                    }
                    Err(error) if error.status != 401 => {
                        self.toast("Auth.signOutUnconfirmed", true);
                        return;
                    }
                    _ => {}
                }
            }
            self.reset_account_scoped_state();
            self.session_epoch.update(|epoch| *epoch += 1);
            storage_set("af_logout_sync", &js_sys::Date::now().to_string());
            self.user.set(None);
            navigate("/login");
        });
    }
}
impl Default for AppContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
