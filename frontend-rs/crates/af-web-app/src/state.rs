use af_web_core::{
    api::{storage_get, storage_set, ApiClient, ApiError},
    charts::Point,
    ws::ConnectionState,
};
use futures::{
    channel::oneshot,
    future::{AbortHandle, AbortRegistration, Abortable},
};
use gloo_events::EventListener;
use leptos::prelude::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

static NEXT_TOAST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TabId {
    #[default]
    Overview,
    Services,
    Marketplace,
    McBrowser,
    Fileshare,
    Streaming,
    Mediaflow,
    AiChat,
    Inbox,
    Network,
    Cluster,
    Users,
    Audit,
    Settings,
    Notifications,
    Quotas,
}
impl TabId {
    pub const ALL: [Self; 16] = [
        Self::Overview,
        Self::Inbox,
        Self::Services,
        Self::Marketplace,
        Self::McBrowser,
        Self::Fileshare,
        Self::Streaming,
        Self::Mediaflow,
        Self::AiChat,
        Self::Network,
        Self::Cluster,
        Self::Users,
        Self::Audit,
        Self::Settings,
        Self::Notifications,
        Self::Quotas,
    ];
    pub fn key(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Services => "services",
            Self::Marketplace => "marketplace",
            Self::McBrowser => "mcbrowser",
            Self::Fileshare => "fileshare",
            Self::Streaming => "streaming",
            Self::Mediaflow => "mediaflow",
            Self::AiChat => "ai",
            Self::Inbox => "inbox",
            Self::Network => "network",
            Self::Cluster => "cluster",
            Self::Users => "users",
            Self::Audit => "audit",
            Self::Settings => "settings",
            Self::Notifications => "notifications",
            Self::Quotas => "quotas",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Services => "Services",
            Self::Marketplace => "Marketplace",
            Self::McBrowser => "McBrowser",
            Self::Fileshare => "File Share",
            Self::Streaming => "Streaming",
            Self::Mediaflow => "MediaFlow",
            Self::AiChat => "FlowAI",
            Self::Inbox => "Approval Inbox",
            Self::Network => "Network",
            Self::Cluster => "Cluster",
            Self::Users => "Users",
            Self::Audit => "Audit Trail",
            Self::Settings => "Settings",
            Self::Notifications => "Notifications",
            Self::Quotas => "Quotas",
        }
    }
    pub fn icon(self) -> &'static str {
        match self {
            Self::Overview => "◇",
            Self::Services => "▤",
            Self::Marketplace => "◈",
            Self::McBrowser => "▱",
            Self::Fileshare => "↥",
            Self::Streaming => "▣",
            Self::Mediaflow => "▷",
            Self::AiChat => "✧",
            Self::Inbox => "✉",
            Self::Network => "◎",
            Self::Cluster => "⬡",
            Self::Users => "◎",
            Self::Audit => "≡",
            Self::Settings => "⚙",
            Self::Notifications => "◉",
            Self::Quotas => "◴",
        }
    }
    pub fn icon_svg(self) -> AnyView {
        stroke_icon(match self {
            Self::Overview => "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
            Self::Services => "M4 3h16v7H4z M4 14h16v7H4z M7 6.5h.01 M7 17.5h.01 M11 6.5h6 M11 17.5h6",
            Self::Marketplace => "M3 9 5 3h14l2 6 M3 9h18v3a3 3 0 0 1-6 0 3 3 0 0 1-6 0 3 3 0 0 1-6 0V9 M5 15v6h14v-6 M10 21v-5h4v5",
            Self::McBrowser => "M3 7V5a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z",
            Self::Fileshare => "M8 12h8 M15 6l3-3 3 3 M18 3v12 M6 3H4a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2 M6 7h5 M6 16h6",
            Self::Streaming => "M3 5h18v14H3z M8 22h8 M12 19v3 M10 9l5 3-5 3V9Z",
            Self::Mediaflow => "M4 3h16v18H4z M4 7h4 M4 12h4 M4 17h4 M16 7h4 M16 12h4 M16 17h4 M8 3v18 M16 3v18",
            Self::AiChat => "m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5L12 3Z M20 2v4 M18 4h4",
            Self::Inbox => "M3 13 6 4h12l3 9v7H3v-7Z M3 13h5l2 3h4l2-3h5",
            Self::Network => "M12 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z M5 16a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z M19 16a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z M12 9v3 M5 16v-4h14v4",
            Self::Cluster => "m12 2 9 5-9 5-9-5 9-5Z M3 12l9 5 9-5 M3 17l9 5 9-5",
            Self::Users => "M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z M2 21v-2a6 6 0 0 1 12 0v2 M17 3a4 4 0 0 1 0 8 M22 21v-2a6 6 0 0 0-4-5.66",
            Self::Audit => "M8 4H5v18h14V4h-3 M8 2h8v5H8z M8 12h8 M8 16h5",
            Self::Settings => "m9 3-1 3-3 1-2 3 2 2-1 3 3 2 1 3h4l1-3 3-1 2-3-2-2 1-3-3-2-1-3H9Z M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z",
            Self::Notifications => "M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9 M10 21h4",
            Self::Quotas => "M21 12a9 9 0 1 1-9-9v9h9Z M16 3a9 9 0 0 1 5 5h-5V3Z",
        })
    }
    pub fn localized_label(self, locale: &str) -> String {
        af_web_core::i18n::translate(locale, &format!("Navigation.{}", self.key()))
    }
    pub fn is_admin_only(self) -> bool {
        matches!(
            self,
            Self::Inbox | Self::Network | Self::Cluster | Self::Users | Self::Audit | Self::Quotas
        )
    }
    pub fn from_key(key: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|t| t.key() == key)
            .unwrap_or_default()
    }
}
pub fn stroke_icon(path: &'static str) -> AnyView {
    view! {<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d=path/></svg>}.into_any()
}

pub fn clamp_tab_for_role(tab: TabId, is_admin: bool) -> TabId {
    if tab.is_admin_only() && !is_admin {
        TabId::Overview
    } else {
        tab
    }
}

fn normalize_theme(pref: &str) -> &'static str {
    match pref {
        "system" => "system",
        "light" => "light",
        _ => "dark",
    }
}

fn color_scheme_query() -> Option<wasm_bindgen::JsValue> {
    let window = web_sys::window()?;
    js_sys::Reflect::get(&window, &"matchMedia".into())
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?
        .call1(&window, &"(prefers-color-scheme: light)".into())
        .ok()
}

fn theme_is_light(pref: &str) -> bool {
    pref == "light"
        || (pref == "system"
            && color_scheme_query()
                .and_then(|query| js_sys::Reflect::get(&query, &"matches".into()).ok())
                .and_then(|matches| matches.as_bool())
                == Some(true))
}

pub fn apply_theme_dom(pref: &str) {
    let mode = if theme_is_light(pref) {
        "light"
    } else {
        "dark"
    };
    if let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    {
        // Keep unrelated root classes while replacing the effective theme.
        let classes = root.class_name();
        let mut classes: Vec<_> = classes
            .split_whitespace()
            .filter(|class| !matches!(*class, "dark" | "light"))
            .collect();
        classes.push(mode);
        let _ = root.set_attribute("class", &classes.join(" "));
        let _ = root.set_attribute("data-theme", mode);
    }
}

pub fn apply_reduced_motion_dom(enabled: bool) {
    if let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    {
        if enabled {
            let _ = root.set_attribute("data-reduced-motion", "true");
        } else {
            let _ = root.remove_attribute("data-reduced-motion");
        }
    }
}

pub fn apply_locale_dom(locale: &str) {
    if let Some(document) = web_sys::window().and_then(|window| window.document()) {
        if let Some(root) = document.document_element() {
            let _ = root.set_attribute("lang", af_web_core::i18n::bcp47_tag(locale));
        }
        // The root owns this link outside the shell, including public routes.
        if let Ok(Some(link)) = document.query_selector(".af-skip-link") {
            link.set_text_content(Some(&af_web_core::i18n::translate(
                locale,
                "Shell.skipToContent",
            )));
        }
    }
}

fn is_spa_fallback_path(path: &str) -> bool {
    !matches!(
        path.trim_end_matches('/'),
        "" | "/login" | "/oauth/consent" | "/share"
    )
}

fn purge_ai_sessions() {
    if let Some(window) = web_sys::window() {
        for storage in [window.session_storage(), window.local_storage()]
            .into_iter()
            .filter_map(Result::ok)
            .flatten()
        {
            // Remove backwards so deleting an entry never skips its successor.
            for index in (0..storage.length().unwrap_or(0)).rev() {
                if let Ok(Some(key)) = storage.key(index) {
                    if key.starts_with("aetherflow-ai-sessions") {
                        let _ = storage.remove_item(&key);
                    }
                }
            }
        }
    }
}

fn suspend_shell_interaction() {
    if let Some(document) = web_sys::window().and_then(|window| window.document()) {
        // A modal dialog can escape an ancestor's inertness, so suspend both
        // the shell and any open dialogs until the reactive shell is disposed.
        if let Ok(nodes) = document.query_selector_all(".af-shell, .af-shell dialog[open]") {
            for index in 0..nodes.length() {
                if let Some(element) = nodes
                    .item(index)
                    .and_then(|node| node.dyn_into::<web_sys::Element>().ok())
                {
                    let _ = element.set_attribute("inert", "");
                }
            }
        }
    }
}

fn initial_preference(key: &str) -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        storage_get(key)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = key;
        None
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct SessionUser {
    #[serde(alias = "ID", alias = "user_id", alias = "userId")]
    id: i64,
    #[serde(alias = "Username", alias = "userName", alias = "name")]
    username: String,
    email: String,
    #[serde(alias = "avatarUrl")]
    avatar_url: String,
    role: String,
    #[serde(alias = "isOAuth", alias = "isOauth")]
    is_oauth: bool,
    #[serde(alias = "totpEnabled")]
    totp_enabled: bool,
}

fn confirmed_session_identity(value: &Value) -> bool {
    serde_json::from_value::<SessionUser>(value.clone())
        .is_ok_and(|user| user.id > 0 || !user.username.trim().is_empty())
}

fn deserialize_user(value: &Value) -> Option<af_web_core::models::User> {
    let user: SessionUser = serde_json::from_value(value.clone()).ok()?;
    Some(af_web_core::models::User {
        id: user.id,
        username: if user.username.is_empty() {
            "Operator".into()
        } else {
            user.username
        },
        email: user.email,
        avatar_url: user.avatar_url,
        role: if user.role.is_empty() {
            "user".into()
        } else {
            user.role
        },
        is_oauth: user.is_oauth,
        totp_enabled: user.totp_enabled,
        ..Default::default()
    })
}

fn same_authenticated_identity(prev: Option<&Value>, next: Option<&Value>) -> bool {
    let (Some(prev), Some(next)) = (prev, next) else {
        return false;
    };
    match (
        prev.get("id").filter(|id| !id.is_null()),
        next.get("id").filter(|id| !id.is_null()),
    ) {
        (Some(prev), Some(next)) => prev == next,
        (None, None) => {
            let username = prev["username"]
                .as_str()
                .filter(|name| !name.trim().is_empty());
            username.is_some() && username == next["username"].as_str()
        }
        _ => false,
    }
}

pub fn detect_browser_locale(lang: Option<&str>) -> &'static str {
    match lang
        .unwrap_or_default()
        .trim()
        .split('-')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "de" => "de",
        "da" | "dk" => "dk",
        "es" => "es",
        "fr" => "fr",
        "zh" => "zh",
        _ => "en",
    }
}

fn defaulted_payload<T: Default + Serialize>(value: &Value) -> Value {
    let mut defaults = serde_json::to_value(T::default()).expect("serializable model defaults");
    if let (Some(defaults), Some(fields)) = (defaults.as_object_mut(), value.as_object()) {
        for (key, value) in fields.iter().filter(|(_, value)| !value.is_null()) {
            defaults.insert(key.clone(), value.clone());
        }
    }
    defaults
}

fn deserialize_metrics(value: &Value) -> af_web_core::models::SystemMetrics {
    use af_web_core::models::{DiskPartition, GpuMetric, ProcessInfo, SystemMetrics};
    let mut payload = defaulted_payload::<SystemMetrics>(value);
    for key in ["disks", "gpus", "processes"] {
        if let Some(records) = payload.get_mut(key).and_then(Value::as_array_mut) {
            for record in records {
                *record = match key {
                    "disks" => defaulted_payload::<DiskPartition>(record),
                    "gpus" => defaulted_payload::<GpuMetric>(record),
                    _ => defaulted_payload::<ProcessInfo>(record),
                };
            }
        }
    }
    serde_json::from_value(payload).unwrap_or_default()
}
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

#[derive(Clone, Copy)]
pub struct AppContext {
    pub user: RwSignal<Option<Value>>,
    pub auth_loading: RwSignal<bool>,
    auth_generation: RwSignal<u64>,
    pub session_epoch: RwSignal<u64>,
    pub authenticated_at: RwSignal<f64>,
    pub tab: RwSignal<TabId>,
    pub locale: RwSignal<String>,
    pub catalog_revision: RwSignal<u32>,
    pub theme: RwSignal<String>,
    pub reduced_motion: RwSignal<bool>,
    pub haptic_feedback: RwSignal<bool>,
    pub settings: RwSignal<Value>,
    pub metrics: RwSignal<Value>,
    pub services: RwSignal<Value>,
    services_order: RwSignal<ServicesOrder>,
    pub history: RwSignal<Vec<Point>>,
    pub connection: RwSignal<ConnectionState>,
    pub pending: RwSignal<usize>,
    pub notifications: RwSignal<Vec<Value>>,
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
        let locale = initial_preference("aetherflow-language")
            .filter(|locale| !locale.is_empty())
            .map(|locale| {
                if af_web_core::i18n::LOCALES.contains(&locale.as_str()) {
                    locale
                } else {
                    "en".into()
                }
            })
            .unwrap_or_else(|| {
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
            locale: RwSignal::new(locale),
            catalog_revision: RwSignal::new(0),
            theme: RwSignal::new(
                normalize_theme(&initial_preference("aetherflow-theme").unwrap_or_default()).into(),
            ),
            reduced_motion: RwSignal::new(
                initial_preference("aetherflow-reduced-motion").as_deref() == Some("true"),
            ),
            haptic_feedback: RwSignal::new(
                initial_preference("aetherflow-haptic-feedback").as_deref() != Some("false"),
            ),
            settings: RwSignal::new(Value::Null),
            metrics: RwSignal::new(Value::Null),
            services: RwSignal::new(Value::Null),
            services_order: RwSignal::new(ServicesOrder::default()),
            history: RwSignal::new(vec![]),
            connection: RwSignal::new(ConnectionState::Connecting),
            pending: RwSignal::new(0),
            notifications: RwSignal::new(vec![]),
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
            apply_locale_dom(locale);
            self.load_locale(locale.to_string());
        }
    }
    fn load_locale(self, locale: String) {
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
    pub(crate) fn publish_live_services(self, value: Value) {
        self.services_order.update(|order| {
            order.issued += 1;
            order.accepted = order.issued;
        });
        self.services.set(value);
    }
    pub fn is_light(self) -> bool {
        theme_is_light(&self.theme.get())
    }
    pub fn set_theme(self, pref: &str) {
        let pref = normalize_theme(pref);
        storage_set("aetherflow-theme", pref);
        self.theme.set(pref.into());
    }
    pub fn toggle_theme(self) {
        let light = theme_is_light(&self.theme.get_untracked());
        self.set_theme(if light { "dark" } else { "light" });
        self.haptic(10);
    }
    pub fn set_reduced_motion(self, enabled: bool) {
        storage_set(
            "aetherflow-reduced-motion",
            if enabled { "true" } else { "false" },
        );
        self.reduced_motion.set(enabled);
    }
    pub fn set_haptic_feedback(self, enabled: bool) {
        storage_set(
            "aetherflow-haptic-feedback",
            if enabled { "true" } else { "false" },
        );
        self.haptic_feedback.set(enabled);
    }
    pub fn haptic(self, ms: u32) {
        if !self.haptic_feedback.get_untracked() || self.reduced_motion.get_untracked() {
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
    pub fn normalize_fallback_url(self, tab: TabId) -> bool {
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
    fn revalidate_external_session(self) {
        // The cookie may already belong to another account. Close the transport
        // gate and invalidate the old shell before starting any async work.
        af_web_core::api::suspend_for_auth_revalidation();
        suspend_shell_interaction();
        self.auth_loading.set(true);
        self.clear_account_scoped_state();
        self.session_epoch.update(|epoch| *epoch += 1);
        self.refresh_session();
    }
    fn reset_account_scoped_state(self) {
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
        self.history.set(vec![]);
        self.pending.set(0);
        self.notifications.set(vec![]);
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
pub fn app() -> AppContext {
    expect_context::<AppContext>()
}
pub fn worker_pool() -> af_web_core::worker_pool::WorkerPool {
    af_web_core::worker_pool::WorkerPool::shared()
}
pub fn navigate(path: &str) {
    if let Some(window) = web_sys::window() {
        let _ = window.location().assign(path);
    }
}
pub fn query_param(key: &str) -> Option<String> {
    web_sys::window()
        .and_then(|w| w.location().search().ok())
        .and_then(|q| web_sys::UrlSearchParams::new_with_str(&q).ok())
        .and_then(|q| q.get(key))
}
pub fn current_path() -> String {
    web_sys::window()
        .map(|w| {
            format!(
                "{}{}{}",
                w.location().pathname().unwrap_or_default(),
                w.location().search().unwrap_or_default(),
                w.location().hash().unwrap_or_default()
            )
        })
        .unwrap_or_else(|| "/".into())
}
pub fn install_session(context: AppContext) {
    let public_route = web_sys::window()
        .and_then(|w| w.location().pathname().ok())
        .is_some_and(|p| matches!(p.trim_end_matches('/'), "/login" | "/share"));
    if public_route {
        context.auth_loading.set(false);
    } else {
        context.refresh_session();
    }
    let handles = StoredValue::new_local(Vec::<EventListener>::new());
    if let Some(window) = web_sys::window() {
        let storage = EventListener::new(&window, "storage", move |event| {
            let Some(event) = event.dyn_ref::<web_sys::StorageEvent>() else {
                return;
            };
            // Read the latest storage snapshot so delayed events cannot restore
            // a stale preference. A null key represents localStorage.clear().
            let key = event.key();
            if key.is_none() || key.as_deref() == Some("aetherflow-theme") {
                context.theme.set(
                    normalize_theme(&storage_get("aetherflow-theme").unwrap_or_default()).into(),
                );
            }
            if key.is_none() || key.as_deref() == Some("aetherflow-language") {
                let locale = storage_get("aetherflow-language")
                    .filter(|locale| af_web_core::i18n::LOCALES.contains(&locale.as_str()))
                    .unwrap_or_else(|| "en".into());
                context.locale.set(locale.clone());
                context.load_locale(locale);
            }
            if key.is_none() || key.as_deref() == Some("aetherflow-reduced-motion") {
                context
                    .reduced_motion
                    .set(storage_get("aetherflow-reduced-motion").as_deref() == Some("true"));
            }
            if key.is_none() || key.as_deref() == Some("aetherflow-haptic-feedback") {
                context
                    .haptic_feedback
                    .set(storage_get("aetherflow-haptic-feedback").as_deref() != Some("false"));
            }
            if key
                .as_deref()
                .is_some_and(|key| matches!(key, "af_login_sync" | "af_logout_sync"))
            {
                context.revalidate_external_session();
            }
        });
        let expired = EventListener::new(&window, "af:session-expired", move |_| {
            if context.auth_loading.get_untracked() {
                return;
            }
            if js_sys::Date::now() - context.authenticated_at.get_untracked() < 10_000.0 {
                context.refresh_session();
            } else {
                if context.user.with_untracked(Option::is_some) {
                    context.reset_account_scoped_state();
                    context.session_epoch.update(|epoch| *epoch += 1);
                }
                af_web_core::api::clear_csrf_token();
                context.user.set(None);
                context.connection.set(ConnectionState::Offline);
            }
        });
        let keys = EventListener::new_with_options(
            &window,
            "keydown",
            gloo_events::EventListenerOptions::enable_prevent_default(),
            move |event| {
                if let Some(event) = event.dyn_ref::<web_sys::KeyboardEvent>() {
                    if (event.ctrl_key() || event.meta_key())
                        && event.key().eq_ignore_ascii_case("k")
                    {
                        if event.cancelable() {
                            event.prevent_default();
                        }
                        context.command_open.update(|v| *v = !*v);
                    }
                }
            },
        );
        handles.set_value(vec![storage, expired, keys]);
        if let Some(query) =
            color_scheme_query().and_then(|query| query.dyn_into::<web_sys::EventTarget>().ok())
        {
            let scheme = EventListener::new(&query, "change", move |_| {
                if context.theme.with_untracked(|pref| pref == "system") {
                    // Notify DOM and Header consumers without persisting an
                    // explicit mode over the user's system preference.
                    context.theme.set("system".into());
                }
            });
            handles.update_value(|handles| handles.push(scheme));
        }
    }
    on_cleanup(move || handles.update_value(Vec::clear));
    let channel = StoredValue::new_local(web_sys::BroadcastChannel::new("aetherflow-auth").ok());
    let messages = StoredValue::new_local(channel.with_value(|channel| {
        channel.as_ref().map(|channel| {
            EventListener::new(channel, "message", move |_| {
                context.revalidate_external_session()
            })
        })
    }));
    on_cleanup(move || {
        messages.set_value(None);
        channel.update_value(|channel| {
            if let Some(channel) = channel.take() {
                channel.close();
            }
        });
    });
    let interval = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        600_000,
        move || {
            if context.user.with_untracked(Option::is_some) {
                spawn_local(async {
                    let _ = ApiClient
                        .request("/api/v1/auth/refresh", "POST", None)
                        .await;
                });
            }
        },
    )));
    on_cleanup(move || interval.set_value(None));
    Effect::new(move |_| {
        context.catalog_revision.get();
        apply_locale_dom(&context.locale.get());
    });
}
/// Drop each old request future before its replacement can start transport.
struct ResourceRead {
    abort: AbortHandle,
    finished: oneshot::Receiver<()>,
}

#[derive(Default)]
pub(crate) struct ResourceReads(Option<ResourceRead>);

pub(crate) fn owned_resource_reads() -> StoredValue<ResourceReads, LocalStorage> {
    let reads = StoredValue::new_local(ResourceReads::default());
    on_cleanup(move || {
        let _ = reads.try_with_value(ResourceReads::cancel);
    });
    reads
}

pub(crate) struct ResourceReadJob {
    previous: Option<oneshot::Receiver<()>>,
    registration: AbortRegistration,
    finished: oneshot::Sender<()>,
}

impl ResourceReads {
    pub(crate) fn cancel(&self) {
        if let Some(read) = &self.0 {
            read.abort.abort();
        }
    }

    pub(crate) fn next(&mut self) -> ResourceReadJob {
        let previous = self.0.take().map(|read| {
            read.abort.abort();
            read.finished
        });
        let (abort, registration) = AbortHandle::new_pair();
        let (finished, receiver) = oneshot::channel();
        self.0 = Some(ResourceRead {
            abort,
            finished: receiver,
        });
        ResourceReadJob {
            previous,
            registration,
            finished,
        }
    }
}

pub(crate) async fn run_resource_read<F: std::future::Future>(
    job: ResourceReadJob,
    work: F,
) -> Option<F::Output> {
    // Keep this barrier even if the new generation is already canceled: its
    // replacement must still wait for every older request guard to drop.
    if let Some(previous) = job.previous {
        let _ = previous.await;
    }
    let result = Abortable::new(work, job.registration).await.ok();
    // The aborted future and its ApiClient transport guard have dropped before
    // completing the barrier, so a replacement cannot overlap obsolete work.
    drop(job.finished);
    result
}

/// Standard resource boundary for tab builders: cancellation-generation guard,
/// visible loading/error state and explicit revalidation without stale writes.
pub struct ApiResource<T: 'static = Value> {
    pub data: RwSignal<T>,
    pub loading: RwSignal<bool>,
    pub error: RwSignal<Option<ApiError>>,
    pub revision: RwSignal<u64>,
}
impl<T: 'static> Copy for ApiResource<T> {}
impl<T: 'static> Clone for ApiResource<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: 'static> ApiResource<T> {
    pub fn refresh(self) {
        self.revision.update(|v| *v += 1);
    }
    /// Publish an acknowledged mutation and synchronously invalidate older
    /// reads, including responses queued before the next reactive effect runs.
    pub fn commit(self, data: T)
    where
        T: Send + Sync,
    {
        self.refresh();
        self.data.set(data);
        self.error.set(None);
        self.loading.set(false);
    }
}
pub fn use_api(path: impl Into<Signal<String>>) -> ApiResource {
    use_api_typed::<Value>(path.into())
}

/// Typed requests share the same loading, revalidation and stale-write guards
/// as JSON resources. Invalid responses keep the last good value and surface an
/// error, rather than passing a malformed domain object to a tab.
pub type TypedApiResource<T> = ApiResource<T>;

pub fn use_typed_api<T: DeserializeOwned + Default + Clone + Send + Sync + 'static>(
    path: impl Into<Signal<String>>,
) -> TypedApiResource<T> {
    use_api_typed(path.into())
}

pub fn use_api_typed<T: DeserializeOwned + Default + Clone + Send + Sync + 'static>(
    path: Signal<String>,
) -> ApiResource<T> {
    let context = app();
    let resource = ApiResource {
        data: RwSignal::new(T::default()),
        loading: RwSignal::new(true),
        error: RwSignal::new(None),
        revision: RwSignal::new(0),
    };
    let generation = RwSignal::new(0u64);
    let reads = owned_resource_reads();
    let last_epoch = StoredValue::new(context.session_epoch.get_untracked());
    Effect::new(move |_| {
        let epoch = context.session_epoch.get();
        if last_epoch.get_value() != epoch {
            resource.data.set(T::default());
            resource.error.set(None);
            last_epoch.set_value(epoch);
        }
        let path = path.get();
        let requested_revision = resource.revision.get();
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        resource.loading.set(true);
        let Some(job) = reads.try_update_value(ResourceReads::next) else {
            return;
        };
        spawn_local(async move {
            let work = async move {
                if generation.try_get_untracked() != Some(ticket)
                    || resource.revision.try_get_untracked() != Some(requested_revision)
                    || context.session_epoch.try_get_untracked() != Some(epoch)
                {
                    return None;
                }
                Some(ApiClient.get_typed::<T>(&path).await)
            };
            let Some(Some(result)) = run_resource_read(job, work).await else {
                return;
            };
            if generation.try_get_untracked() != Some(ticket)
                || resource.revision.try_get_untracked() != Some(requested_revision)
            {
                return;
            }
            if context.session_epoch.try_get_untracked() == Some(epoch) {
                match result {
                    Ok(data) => {
                        resource.data.set(data);
                        resource.error.set(None);
                    }
                    Err(error) => resource.error.set(Some(error)),
                }
            }
            resource.loading.set(false);
        });
    });
    resource
}
pub fn json_rows(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .cloned()
        .or_else(|| {
            [
                "items",
                "entries",
                "services",
                "data",
                "results",
                "notifications",
                "actions",
                "nodes",
                "users",
                "quotas",
            ]
            .iter()
            .find_map(|key| value[*key].as_array().cloned())
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        clamp_tab_for_role, confirmed_session_identity, detect_browser_locale,
        is_spa_fallback_path, normalize_theme, run_resource_read, same_authenticated_identity,
        ApiResource, AppContext, ResourceReads, TabId, Toast,
    };
    use af_web_core::models::{DiskPartition, GpuMetric, ProcessInfo, SystemMetrics, User};
    use leptos::prelude::*;
    use serde_json::json;

    #[test]
    fn resource_reads_drop_superseded_work_before_starting_a_replacement() {
        use futures::{executor::LocalPool, future, task::LocalSpawnExt};
        use std::{
            cell::{Cell, RefCell},
            rc::Rc,
        };

        struct Transport {
            name: char,
            active: Rc<Cell<usize>>,
            events: Rc<RefCell<Vec<(char, &'static str)>>>,
        }
        impl Drop for Transport {
            fn drop(&mut self) {
                self.active.set(self.active.get() - 1);
                self.events.borrow_mut().push((self.name, "drop"));
            }
        }
        let mut pool = LocalPool::new();
        let spawner = pool.spawner();
        let active = Rc::new(Cell::new(0usize));
        let peak = Rc::new(Cell::new(0usize));
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut reads = ResourceReads::default();
        let start = |reads: &mut ResourceReads, name| {
            let job = reads.next();
            let active = active.clone();
            let peak = peak.clone();
            let events = events.clone();
            spawner
                .spawn_local(async move {
                    let work = async move {
                        active.set(active.get() + 1);
                        peak.set(peak.get().max(active.get()));
                        events.borrow_mut().push((name, "start"));
                        let _transport = Transport {
                            name,
                            active,
                            events,
                        };
                        future::pending::<()>().await;
                    };
                    let _ = run_resource_read(job, work).await;
                })
                .unwrap();
        };
        start(&mut reads, 'a');
        pool.run_until_stalled();
        assert_eq!(active.get(), 1);
        start(&mut reads, 'b');
        start(&mut reads, 'c');
        pool.run_until_stalled();
        assert_eq!(
            *events.borrow(),
            vec![('a', "start"), ('a', "drop"), ('c', "start")]
        );
        assert_eq!(active.get(), 1);
        assert_eq!(peak.get(), 1);
        reads.cancel();
        pool.run_until_stalled();
        assert_eq!(active.get(), 0);
        assert_eq!(events.borrow().last(), Some(&('c', "drop")));
    }

    #[test]
    fn resource_read_canceled_before_poll_never_starts_its_transport() {
        let started = std::cell::Cell::new(false);
        let mut reads = ResourceReads::default();
        let job = reads.next();
        reads.cancel();
        let result = futures::executor::block_on(run_resource_read(job, async {
            started.set(true);
            1
        }));
        assert!(result.is_none());
        assert!(!started.get());
    }

    #[test]
    fn completed_resource_read_allows_a_later_refresh() {
        let mut reads = ResourceReads::default();
        assert_eq!(
            futures::executor::block_on(run_resource_read(reads.next(), async { 7 })),
            Some(7)
        );
        assert_eq!(
            futures::executor::block_on(run_resource_read(reads.next(), async { 9 })),
            Some(9)
        );
    }

    #[test]
    fn live_services_reject_older_http_and_allow_a_later_explicit_refresh() {
        Owner::new().with(|| {
            let context = AppContext::new();
            context.user.set(Some(json!({"id": 1})));
            let request = context.begin_services_request();
            context.publish_live_services(json!({"probe": {"status": "failed"}}));
            assert!(
                !context.finish_services_request(request, json!({"probe": {"status": "running"}}))
            );
            assert_eq!(
                context.services.get_untracked()["probe"]["status"],
                "failed"
            );
            let refresh = context.begin_services_request();
            assert!(
                context.finish_services_request(refresh, json!({"probe": {"status": "stopped"}}))
            );
            assert_eq!(
                context.services.get_untracked()["probe"]["status"],
                "stopped"
            );
        });
    }

    #[test]
    fn all_service_http_writers_share_request_and_account_ordering() {
        Owner::new().with(|| {
            let context = AppContext::new();
            context.user.set(Some(json!({"id": 1})));
            let shell = context.begin_services_request();
            let inventory = context.begin_services_request();
            assert!(
                context.finish_services_request(inventory, json!({"new": {"status": "running"}}))
            );
            assert!(!context.finish_services_request(shell, json!({"old": {"status": "stopped"}})));
            let old_account = context.begin_services_request();
            context.session_epoch.update(|epoch| *epoch += 1);
            assert!(!context.finish_services_request(old_account, json!({"old_account": {}})));
            assert!(context.services.get_untracked().get("new").is_some());
        });
    }

    #[test]
    fn pending_service_refresh_does_not_discard_an_available_bootstrap_snapshot() {
        Owner::new().with(|| {
            let context = AppContext::new();
            context.user.set(Some(json!({"id": 1})));
            let bootstrap = context.begin_services_request();
            let refresh = context.begin_services_request();
            assert!(context.finish_services_request(bootstrap, json!({"status": "bootstrap"})));
            assert!(context.finish_services_request(refresh, json!({"status": "refreshed"})));
            assert!(!context.finish_services_request(bootstrap, json!({"status": "stale"})));
            assert_eq!(context.services.get_untracked()["status"], "refreshed");
        });
    }

    #[test]
    fn revalidation_requires_a_real_identity_and_keeps_legacy_session_aliases() {
        for session in [
            json!({"id": 7, "role": "admin"}),
            json!({"user_id": 8}),
            json!({"userName": "alice", "role": "user"}),
        ] {
            assert!(confirmed_session_identity(&session), "{session}");
        }
        for session in [
            json!(null),
            json!({}),
            json!({"role": "admin"}),
            json!({"username": "  "}),
        ] {
            assert!(!confirmed_session_identity(&session), "{session}");
        }
    }

    #[test]
    fn visible_toast_text_tracks_locale_and_catalog_revision() {
        Owner::new().with(|| {
            let context = AppContext::new();
            let toast = Toast {
                id: 1,
                message: "Auth.signOutFailed".into(),
                params: vec![],
                error: true,
            };
            let renders = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let observed_renders = renders.clone();
            let rendered = Memo::new(move |_| {
                observed_renders.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                context.render_toast(&toast)
            });
            let english = rendered.get();
            context.locale.set("fr".into());
            let french = rendered.get();
            assert_ne!(english, french);
            assert_eq!(
                french,
                af_web_core::i18n::translate("fr", "Auth.signOutFailed")
            );
            context.catalog_revision.update(|revision| *revision += 1);
            assert_eq!(rendered.get(), french);
            assert_eq!(renders.load(std::sync::atomic::Ordering::Relaxed), 3);
        });
    }

    #[test]
    fn toast_rendering_translates_fallback_strings_and_preserves_dynamic_messages() {
        Owner::new().with(|| {
            let context = AppContext::new();
            context.locale.set("fr".into());
            let mut toast = Toast {
                id: 1,
                message: "Copy".into(),
                params: vec![],
                error: false,
            };
            assert_ne!(context.render_toast(&toast), toast.message);
            toast.message = "Uncatalogued failure for job 13".into();
            assert_eq!(context.render_toast(&toast), toast.message);
            toast.message = "Shell.pendingActions".into();
            toast.params = vec![("count".into(), "3".into())];
            assert_eq!(
                context.render_toast(&toast),
                context.t_with("Shell.pendingActions", &[("count", "3")])
            );
            assert!(!context.render_toast(&toast).contains("{count}"));
        });
    }

    #[test]
    fn generic_api_resources_are_copyable_without_copyable_response_values() {
        Owner::new().with(|| {
            let resource = ApiResource {
                data: RwSignal::new(Vec::<String>::new()),
                loading: RwSignal::new(false),
                error: RwSignal::new(None),
                revision: RwSignal::new(0),
            };
            let copied = resource;
            resource.refresh();
            assert_eq!(copied.revision.get_untracked(), 1);
            assert!(copied.data.get_untracked().is_empty());
        });
    }

    #[test]
    fn authenticated_identity_uses_stable_ids_across_profile_changes() {
        let prev = json!({"id": 7, "username": "operator", "email": "old@example.com"});
        let updated = json!({
            "id": 7, "username": "renamed", "email": "new@example.com",
            "role": "admin", "avatar_url": "/new-avatar.png", "totp_enabled": true
        });
        assert!(same_authenticated_identity(Some(&prev), Some(&updated)));
        assert!(!same_authenticated_identity(Some(&prev), None));
        assert!(!same_authenticated_identity(None, Some(&prev)));
        assert!(!same_authenticated_identity(None, None));
    }

    #[test]
    fn authenticated_identity_detects_account_switches_despite_matching_usernames() {
        let prev = json!({"id": 7, "username": "operator"});
        let switched = json!({"id": 8, "username": "operator"});
        assert!(!same_authenticated_identity(Some(&prev), Some(&switched)));
        assert!(!same_authenticated_identity(Some(&switched), Some(&prev)));
    }

    #[test]
    fn authenticated_identity_falls_back_to_nonempty_usernames_without_ids() {
        let prev = json!({"id": null, "username": "operator"});
        let same = json!({"username": "operator", "email": "updated@example.com"});
        let switched = json!({"username": "other"});
        let with_id = json!({"id": 7, "username": "operator"});
        assert!(same_authenticated_identity(Some(&prev), Some(&same)));
        assert!(!same_authenticated_identity(Some(&prev), Some(&switched)));
        assert!(!same_authenticated_identity(Some(&prev), Some(&with_id)));
        for missing in [json!({}), json!({"username": ""}), json!({"username": " "})] {
            assert!(!same_authenticated_identity(Some(&missing), Some(&missing)));
        }
    }

    #[test]
    fn browser_locale_matches_supported_primary_language_tags() {
        for (language, expected) in [
            ("de", "de"),
            ("DE-de", "de"),
            ("da", "dk"),
            ("da-DK", "dk"),
            ("dk", "dk"),
            ("es", "es"),
            ("ES-mx", "es"),
            ("fr", "fr"),
            ("fr-CA", "fr"),
            ("zh", "zh"),
            ("ZH-hant-TW", "zh"),
        ] {
            assert_eq!(
                detect_browser_locale(Some(language)),
                expected,
                "{language}"
            );
        }
    }

    #[test]
    fn browser_locale_defaults_to_english_for_missing_or_unsupported_languages() {
        assert_eq!(detect_browser_locale(None), "en");
        for language in ["", "en", "en-US", "en-GB", "it-IT", "francais", "deutsch"] {
            assert_eq!(detect_browser_locale(Some(language)), "en", "{language}");
        }
    }

    #[test]
    fn fallback_route_normalization_excludes_public_and_root_routes() {
        for path in [
            "/",
            "/login",
            "/login/",
            "/oauth/consent",
            "/oauth/consent/",
            "/share",
            "/share/",
        ] {
            assert!(!is_spa_fallback_path(path), "{path}");
        }
        for path in [
            "/unknown",
            "/settings",
            "/nested/fallback",
            "/login/unrecognized",
        ] {
            assert!(is_spa_fallback_path(path), "{path}");
        }
    }

    #[test]
    fn typed_user_preserves_canonical_session_fields_and_admin_role() {
        Owner::new().with(|| {
            let context = AppContext::new();
            assert!(context.typed_user().is_none());
            assert!(!context.is_admin());
            let user = User {
                id: 7,
                username: "admin".into(),
                email: "admin@example.com".into(),
                avatar_url: "/avatar.png".into(),
                role: "admin".into(),
                is_oauth: true,
                totp_enabled: true,
                ..Default::default()
            };
            context.user.set(Some(serde_json::to_value(&user).unwrap()));
            assert_eq!(context.typed_user(), Some(user));
            assert!(context.is_admin());
        });
    }

    #[test]
    fn typed_user_defaults_partial_sessions_and_accepts_legacy_aliases() {
        Owner::new().with(|| {
            let context = AppContext::new();
            // The session fixture omits email, avatar and MFA flags.
            context.user.set(Some(
                json!({"id": 2, "username": "operator", "role": "user"}),
            ));
            let user = context.typed_user().unwrap();
            assert_eq!(user.id, 2);
            assert_eq!(user.username, "operator");
            assert_eq!(user.role, "user");
            assert!(user.email.is_empty());
            assert!(!user.totp_enabled);
            assert!(!user.is_oauth);
            assert!(!context.is_admin());

            context.user.set(Some(
                json!({"userId": 9, "userName": "legacy", "isOAuth": true, "totpEnabled": true}),
            ));
            let user = context.typed_user().unwrap();
            assert_eq!(user.id, 9);
            assert_eq!(user.username, "legacy");
            assert_eq!(user.role, "user");
            assert!(user.is_oauth && user.totp_enabled);
            context.user.set(Some(json!({"role": "admin"})));
            assert!(context.is_admin());
            assert_eq!(context.typed_user().unwrap().username, "Operator");
            context.user.set(Some(json!({"role": ["admin"]})));
            assert!(context.typed_user().is_none());
            assert!(!context.is_admin());
        });
    }

    #[test]
    fn typed_metrics_preserves_the_full_shared_backend_contract() {
        Owner::new().with(|| {
            let context = AppContext::new();
            let metrics = SystemMetrics {
                cpu_usage: 18.2,
                per_core_cpu: vec![12.0, 24.4],
                disk_space: [("used".into(), 52.0)].into_iter().collect(),
                disks: vec![DiskPartition {
                    mount_point: "/".into(),
                    device: "/dev/sda1".into(),
                    fs_type: "ext4".into(),
                    total_gb: 100.0,
                    used_gb: 52.0,
                    free_gb: 48.0,
                    used_pct: 52.0,
                }],
                memory: [("used".into(), 12.0), ("total".into(), 64.0)]
                    .into_iter()
                    .collect(),
                swap: [("total".into(), 8.0)].into_iter().collect(),
                gpus: vec![GpuMetric {
                    name: "GPU".into(),
                    usage_pct: 42.0,
                    ..Default::default()
                }],
                processes: vec![ProcessInfo {
                    pid: 1,
                    name: "init".into(),
                    cpu: 0.1,
                    mem: 0.2,
                }],
                ..Default::default()
            };
            context.metrics.set(serde_json::to_value(&metrics).unwrap());
            assert_eq!(context.typed_metrics(), metrics);
        });
    }

    #[test]
    fn typed_metrics_defaults_partial_and_null_telemetry_without_losing_samples() {
        Owner::new().with(|| {
            let context = AppContext::new();
            assert_eq!(context.typed_metrics(), SystemMetrics::default());
            context.metrics.set(json!({
                "cpu_usage": 18.2,
                "per_core_cpu": [12, 24.4],
                "memory": {"used": 12, "total": 64},
                "swap": null,
                "disks": [{"mount_point": "/", "used_pct": 51.4}],
                "gpus": [{"name": "GPU", "usage_pct": 42}],
                "processes": [{"pid": 1, "name": "init"}]
            }));
            let metrics = context.typed_metrics();
            assert_eq!(metrics.cpu_usage, 18.2);
            assert_eq!(metrics.per_core_cpu, vec![12.0, 24.4]);
            assert_eq!(metrics.memory["used"], 12.0);
            assert!(metrics.swap.is_empty());
            assert!(metrics.disk_space.is_empty());
            assert_eq!(metrics.disks[0].mount_point, "/");
            assert_eq!(metrics.disks[0].used_pct, 51.4);
            assert_eq!(metrics.disks[0].total_gb, 0.0);
            assert_eq!(metrics.gpus[0].usage_pct, 42.0);
            assert_eq!(metrics.gpus[0].memory_total, 0.0);
            assert_eq!(metrics.processes[0].pid, 1);
            assert_eq!(metrics.processes[0].cpu, 0.0);
            context.metrics.set(json!({"cpu_usage": 9.5}));
            assert_eq!(context.typed_metrics().cpu_usage, 9.5);
            assert!(context.typed_metrics().gpus.is_empty());
        });
    }

    #[test]
    fn theme_preferences_preserve_system_and_default_invalid_values_to_dark() {
        for pref in ["system", "dark", "light"] {
            assert_eq!(normalize_theme(pref), pref);
        }
        for pref in ["", "auto", "LIGHT", "null"] {
            assert_eq!(normalize_theme(pref), "dark");
        }
    }

    #[test]
    fn non_admin_deep_links_clamp_restricted_tabs_and_keep_notifications() {
        for tab in TabId::ALL {
            assert_eq!(clamp_tab_for_role(tab, true), tab);
            let expected = if matches!(
                tab,
                TabId::Inbox
                    | TabId::Network
                    | TabId::Cluster
                    | TabId::Users
                    | TabId::Audit
                    | TabId::Quotas
            ) {
                TabId::Overview
            } else {
                tab
            };
            assert_eq!(clamp_tab_for_role(tab, false), expected, "{tab:?}");
        }
        assert_eq!(
            clamp_tab_for_role(TabId::Notifications, false),
            TabId::Notifications
        );
    }

    #[test]
    fn default_dashboard_respects_the_authenticated_role() {
        for tab in TabId::ALL {
            let settings = serde_json::json!({"defaultDashboard": tab.key()});
            let target = TabId::from_key(settings["defaultDashboard"].as_str().unwrap());
            assert_eq!(clamp_tab_for_role(target, true), tab);
            assert!(!clamp_tab_for_role(target, false).is_admin_only());
            if !tab.is_admin_only() {
                assert_eq!(clamp_tab_for_role(target, false), tab);
            }
        }
        assert_eq!(
            clamp_tab_for_role(TabId::from_key("retired-dashboard"), false),
            TabId::Overview
        );
    }

    #[test]
    fn default_dashboard_preferences_resolve_to_supported_tabs() {
        for tab in TabId::ALL {
            let settings = serde_json::json!({"defaultDashboard": tab.key()});
            assert_eq!(
                TabId::from_key(settings["defaultDashboard"].as_str().unwrap()),
                tab
            );
        }
        assert_eq!(TabId::from_key("retired-dashboard"), TabId::Overview);
        assert_eq!(TabId::from_key(""), TabId::Overview);
    }

    #[test]
    fn tab_keys_restore_navigation_and_default_unknown_keys() {
        for (key, expected) in [
            ("overview", TabId::Overview),
            ("services", TabId::Services),
            ("marketplace", TabId::Marketplace),
            ("mcbrowser", TabId::McBrowser),
            ("fileshare", TabId::Fileshare),
            ("streaming", TabId::Streaming),
            ("mediaflow", TabId::Mediaflow),
            ("ai", TabId::AiChat),
            ("inbox", TabId::Inbox),
            ("network", TabId::Network),
            ("cluster", TabId::Cluster),
            ("users", TabId::Users),
            ("audit", TabId::Audit),
            ("settings", TabId::Settings),
            ("notifications", TabId::Notifications),
            ("quotas", TabId::Quotas),
        ] {
            assert_eq!(TabId::from_key(key), expected, "{key}");
        }
        for key in ["", "unknown", "Services"] {
            assert_eq!(TabId::from_key(key), TabId::Overview, "{key}");
        }
    }

    #[test]
    fn administrator_navigation_is_limited_to_operator_tabs() {
        let admin_tabs = [
            TabId::Inbox,
            TabId::Network,
            TabId::Cluster,
            TabId::Users,
            TabId::Audit,
            TabId::Quotas,
        ];
        for tab in TabId::ALL {
            assert_eq!(tab.is_admin_only(), admin_tabs.contains(&tab), "{tab:?}");
        }
    }

    #[test]
    fn navigation_labels_translate_and_fall_back_to_english() {
        for tab in TabId::ALL {
            assert_eq!(tab.localized_label("en"), tab.label(), "{tab:?}");
            assert_eq!(tab.localized_label("unknown"), tab.label(), "{tab:?}");
        }
        assert_eq!(TabId::Overview.localized_label("de"), "Übersicht");
        assert_eq!(TabId::Services.localized_label("de"), "Dienste");
        assert_eq!(TabId::Settings.localized_label("fr"), "Paramètres");
    }
}
