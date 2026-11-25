use af_web_core::{
    i18n::{translate, translate_with},
    ws::ConnectionState,
};
use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// The application provides its live locale once for reusable UI controls.
#[derive(Clone, Copy)]
pub struct UiLocale(pub Signal<String>);

fn ui_locale() -> Signal<String> {
    use_context::<UiLocale>()
        .map(|locale| locale.0)
        .unwrap_or_else(|| "en".to_string().into())
}

pub fn ui_t(key: &str) -> String {
    translate(&ui_locale().get(), key)
}

pub fn ui_t_with(key: &str, params: &[(&str, &str)]) -> String {
    translate_with(&ui_locale().get(), key, params)
}

fn search_accessible_label(placeholder: &str) -> String {
    if placeholder.is_empty() {
        ui_t("Shell.search")
    } else {
        ui_t(placeholder)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BadgeTone {
    Neutral,
    Success,
    Warning,
    Danger,
    Indigo,
    Violet,
    Muted,
}

impl From<&str> for BadgeTone {
    fn from(tone: &str) -> Self {
        match tone.trim().to_ascii_lowercase().as_str() {
            "amber" | "warning" => Self::Warning,
            "emerald" | "green" | "success" => Self::Success,
            "rose" | "red" | "danger" => Self::Danger,
            "indigo" | "cyan" | "info" => Self::Indigo,
            "violet" | "purple" => Self::Violet,
            "muted" | "slate" => Self::Muted,
            _ => Self::Neutral,
        }
    }
}

fn badge_class(tone: &str) -> &'static str {
    match BadgeTone::from(tone) {
        BadgeTone::Neutral => "af-badge",
        BadgeTone::Success => "af-badge af-badge-success",
        BadgeTone::Warning => "af-badge af-badge-warning",
        BadgeTone::Danger => "af-badge af-badge-danger",
        BadgeTone::Indigo => "af-badge af-badge-indigo",
        BadgeTone::Violet => "af-badge af-badge-violet",
        BadgeTone::Muted => "af-badge af-badge-muted",
    }
}

fn connection_label(state: ConnectionState, locale: &str) -> String {
    let key = match state {
        ConnectionState::Connected => "Connection.connected",
        ConnectionState::Fallback => "Connection.polling",
        ConnectionState::Reconnecting => "Connection.reconnecting",
        ConnectionState::Offline => "Connection.offline",
        ConnectionState::Connecting => "Connection.connecting",
    };
    translate(locale, key)
}

fn tab_dom_id(prefix: &str, kind: &str, id: &str) -> String {
    let prefix = if prefix.is_empty() { "af" } else { prefix };
    let safe_id: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!("{prefix}-{kind}-{safe_id}")
}

fn card_class(interactive: bool) -> &'static str {
    if interactive {
        "af-card af-card-interactive p-5 min-w-0 max-w-full"
    } else {
        "af-card p-5 min-w-0 max-w-full"
    }
}

fn button_appearance(primary: bool, tone: &str) -> (&'static str, Option<&'static str>) {
    let normalized = tone.trim().to_ascii_lowercase();
    if primary || normalized == "primary" {
        ("af-btn-primary px-4 py-2", None)
    } else {
        let data_tone = match normalized.as_str() {
            "danger" => Some("danger"),
            "success" => Some("success"),
            _ => None,
        };
        ("af-btn px-4 py-2", data_tone)
    }
}

fn modal_dialog_class() -> &'static str {
    "af-modal min-w-0 max-w-full"
}

fn modal_close_button_class() -> &'static str {
    "af-btn px-3 min-w-10 min-h-10"
}

fn confirm_button_appearance(danger: bool) -> (&'static str, Option<&'static str>) {
    if danger {
        ("af-btn px-4 py-2", Some("danger"))
    } else {
        ("af-btn-primary px-4 py-2", None)
    }
}

#[component]
pub fn ObsCard(
    #[prop(optional, into)] title: Signal<String>,
    #[prop(optional)] interactive: bool,
    children: Children,
) -> impl IntoView {
    view! {
        <section class=card_class(interactive)>
            <Show when=move || !title.get().is_empty()>
                <h2 class="text-lg font-semibold mb-4">{move || ui_t(&title.get())}</h2>
            </Show>
            {children()}
        </section>
    }
}

#[component]
pub fn Button(
    #[prop(optional)] primary: bool,
    #[prop(optional, into)] tone: String,
    #[prop(optional, into)] disabled: Signal<bool>,
    #[prop(optional)] on_click: Option<Callback<web_sys::MouseEvent>>,
    children: Children,
) -> impl IntoView {
    let (class, data_tone) = button_appearance(primary, &tone);
    view! {
        <button
            type="button"
            class=class
            data-tone=data_tone
            disabled=move || disabled.get()
            on:click=move |event| {
                if let Some(callback) = on_click {
                    callback.run(event);
                }
            }
        >
            {children()}
        </button>
    }
}

#[component]
pub fn Badge(
    #[prop(into)] label: Signal<String>,
    #[prop(optional, into)] tone: String,
) -> impl IntoView {
    view! { <span class=badge_class(&tone)>{move || ui_t(&label.get())}</span> }
}

#[component]
pub fn StatusPill(
    #[prop(into)] state: Signal<ConnectionState>,
    #[prop(optional, into)] locale: Signal<String>,
) -> impl IntoView {
    let shared_locale = ui_locale();
    view! {
        <span class="af-status-pill" role="status">
            <span
                aria-hidden="true"
                class=move || match state.get() {
                    ConnectionState::Connected => "obs-beacon-live",
                    ConnectionState::Offline => "obs-beacon-offline",
                    _ => "obs-beacon-reconnecting",
                }
            ></span>
            <span class="af-status-label">
                {move || {
                    let current = shared_locale.get();
                    let explicit = locale.get();
                    connection_label(state.get(), if explicit.is_empty() { &current } else { &explicit })
                }}
            </span>
        </span>
    }
}

#[component]
pub fn MarkdownView(
    #[prop(into)] source: Signal<String>,
    #[prop(optional, into)] class: String,
) -> impl IntoView {
    let html = RwSignal::new(af_web_core::markdown::render_markdown(
        &source.get_untracked(),
    ));
    let generation = RwSignal::new(0u64);
    Effect::new(move |_| {
        let text = source.get();
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        html.set(af_web_core::markdown::render_markdown(&text));
        wasm_bindgen_futures::spawn_local(async move {
            let rendered = af_web_core::markdown::render_markdown_async(text).await;
            if generation.try_get_untracked() == Some(ticket) {
                html.set(rendered);
            }
        });
    });
    view! {
        <div
            class=format!("af-markdown-preview min-w-0 max-w-full {class}")
            inner_html=move || html.get()
        ></div>
    }
}

fn dialog_focusable_elements(dialog: &web_sys::Element) -> Vec<web_sys::HtmlElement> {
    let Ok(nodes) = dialog.query_selector_all(
        "button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex=\"-1\"])",
    ) else {
        return Vec::new();
    };
    (0..nodes.length())
        .filter_map(|index| nodes.item(index)?.dyn_into::<web_sys::HtmlElement>().ok())
        .filter(|element| {
            element.tab_index() >= 0
                && !element.matches(":disabled").unwrap_or(true)
                && element
                    .closest("[hidden], [inert]")
                    .ok()
                    .flatten()
                    .is_none()
                && element.get_bounding_client_rect().width() > 0.0
                && element.get_bounding_client_rect().height() > 0.0
        })
        .collect()
}

#[component]
pub fn Modal(
    open: RwSignal<bool>,
    #[prop(into)] title: Signal<String>,
    children: Children,
) -> impl IntoView {
    let dialog = NodeRef::<leptos::html::Dialog>::new();
    let previous_focus = StoredValue::new_local(None::<web_sys::HtmlElement>);
    let restore_focus = move || {
        if let Some(element) = previous_focus.with_value(|previous| previous.clone()) {
            previous_focus.set_value(None);
            if element.is_connected() {
                let _ = element.focus();
            }
        }
    };
    on_cleanup(move || {
        if let Some(element) = dialog.get_untracked() {
            if element.open() {
                element.close();
            }
        }
        restore_focus();
    });
    Effect::new(move |_| {
        let is_open = open.get();
        if let Some(element) = dialog.get() {
            if is_open {
                if !element.open() {
                    previous_focus.set_value(
                        web_sys::window()
                            .and_then(|window| window.document())
                            .and_then(|document| document.active_element())
                            .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok()),
                    );
                    if element.show_modal().is_ok() {
                        let focusable = dialog_focusable_elements(&element);
                        let target = focusable
                            .iter()
                            .find(|control| {
                                control.get_attribute("data-af-autofocus").as_deref()
                                    == Some("true")
                            })
                            .or_else(|| focusable.first());
                        if let Some(target) = target {
                            let _ = target.focus();
                        } else {
                            let _ = element.focus();
                        }
                    }
                }
            } else {
                if element.open() {
                    element.close();
                }
                restore_focus();
            }
        }
    });
    view! {
        <dialog
            node_ref=dialog
            class=modal_dialog_class()
            role="dialog"
            aria-modal="true"
            aria-label=move || ui_t(&title.get())
            tabindex="-1"
            on:keydown=move |event: web_sys::KeyboardEvent| {
                if !open.get_untracked() {
                    return;
                }
                if event.key() == "Escape" {
                    event.prevent_default();
                    event.stop_propagation();
                    open.set(false);
                    return;
                }
                if event.key() != "Tab" {
                    return;
                }
                let Some(dialog) = dialog.get() else { return; };
                let focusable = dialog_focusable_elements(&dialog);
                let Some(first) = focusable.first() else {
                    if event.cancelable() { event.prevent_default(); }
                    let _ = dialog.focus();
                    return;
                };
                let last = focusable.last().unwrap();
                let active = web_sys::window()
                    .and_then(|window| window.document())
                    .and_then(|document| document.active_element());
                let at_first = active.as_ref() == Some(first.unchecked_ref());
                let at_last = active.as_ref() == Some(last.unchecked_ref());
                let outside = active.as_ref().is_none_or(|active| !dialog.contains(Some(active)));
                let target = if event.shift_key() && (at_first || outside) {
                    Some(last)
                } else if !event.shift_key() && (at_last || outside) {
                    Some(first)
                } else {
                    None
                };
                if let Some(target) = target {
                    if event.cancelable() { event.prevent_default(); }
                    let _ = target.focus();
                }
            }
            on:cancel=move |event: web_sys::Event| {
                if event.cancelable() {
                    event.prevent_default();
                }
                open.set(false);
            }
            on:close=move |_| {
                // Native close events are queued. A dialog may already have
                // reopened when an earlier close event is delivered.
                if dialog.get_untracked().is_some_and(|element| !element.open()) {
                    open.set(false);
                }
            }
        >
            <div class="flex justify-between items-center gap-4 mb-4">
                <h2 class="text-xl font-semibold">{move || ui_t(&title.get())}</h2>
                <button
                    type="button"
                    class=modal_close_button_class()
                    aria-label=move || ui_t("Common.closeDialog")
                    on:click=move |_| open.set(false)
                >
                    "×"
                </button>
            </div>
            {children()}
        </dialog>
    }
}

#[component]
pub fn Drawer(
    open: RwSignal<bool>,
    #[prop(into)] title: Signal<String>,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="af-drawer">
            <Modal open title>{children()}</Modal>
        </div>
    }
}

#[component]
pub fn ConfirmDialog(
    open: RwSignal<bool>,
    #[prop(into)] title: Signal<String>,
    #[prop(into)] message: Signal<String>,
    on_confirm: Callback<()>,
    #[prop(optional, into)] busy: Signal<bool>,
    #[prop(optional)] danger: bool,
) -> impl IntoView {
    let (confirm_class, confirm_tone) = confirm_button_appearance(danger);
    view! {
        <Modal open title>
            <p class="text-slate-300 mb-5">{move || ui_t(&message.get())}</p>
            <div class="flex gap-3 justify-end">
                <button
                    type="button"
                    class="af-btn px-4 py-2"
                    disabled=move || busy.get()
                    on:click=move |_| open.set(false)
                >
                    {move || ui_t("Common.cancel")}
                </button>
                <button
                    type="button"
                    class=confirm_class
                    data-tone=confirm_tone
                    disabled=move || busy.get()
                    on:click=move |_| on_confirm.run(())
                >
                    {move || ui_t("Common.confirm")}
                </button>
            </div>
        </Modal>
    }
}

#[component]
pub fn TabsBar(
    #[prop(into)] tabs: Signal<Vec<(String, String)>>,
    active: RwSignal<String>,
    #[prop(optional, into)] id_prefix: String,
) -> impl IntoView {
    let prefix = StoredValue::new(id_prefix);
    Effect::new(move |_| {
        let available = tabs.get();
        let selected = active.get();
        if !available.iter().any(|(id, _)| *id == selected) {
            if let Some((fallback, _)) = available.first() {
                active.set(fallback.clone());
            }
        }
    });
    view! {
        <div
            role="tablist"
            class="af-tabs obs-touch-pills flex gap-2"
            on:keydown=move |event| {
                let direction = match event.key().as_str() {
                    "ArrowRight" => 1,
                    "ArrowLeft" => -1,
                    "Home" => -10000,
                    "End" => 10000,
                    _ => return,
                };
                event.prevent_default();
                let keys = tabs.get_untracked().into_iter().map(|(id, _)| id).collect::<Vec<_>>();
                if keys.is_empty() {
                    return;
                }
                let current = keys.iter().position(|key| *key == active.get_untracked()).unwrap_or(0) as i32;
                let index = if direction == -10000 {
                    0
                } else if direction == 10000 {
                    keys.len() - 1
                } else {
                    (current + direction).rem_euclid(keys.len() as i32) as usize
                };
                active.set(keys[index].clone());
                let target = prefix.with_value(|prefix| tab_dom_id(prefix, "tab", &keys[index]));
                if let Some(element) = web_sys::window()
                    .and_then(|window| window.document())
                    .and_then(|document| document.get_element_by_id(&target))
                {
                    use wasm_bindgen::JsCast;
                    if let Some(element) = element.dyn_ref::<web_sys::HtmlElement>() {
                        let _ = element.focus();
                    }
                }
            }
        >
            {move || tabs.get().into_iter().map(|(id, label)| {
                let selected = id.clone();
                let tab_index = id.clone();
                let ctrl_id = id.clone();
                let target = id.clone();
                view! {
                    <button
                        type="button"
                        id=prefix.with_value(|prefix| tab_dom_id(prefix, "tab", &id))
                        aria-controls=move || {
                            (active.get() == ctrl_id).then(|| {
                                prefix.with_value(|prefix| tab_dom_id(prefix, "tabpanel", &ctrl_id))
                            })
                        }
                        role="tab"
                        class="af-tab-pill px-4 py-2"
                        class:af-tab-pill-active=move || active.get() == selected
                        aria-selected=move || (active.get() == tab_index).to_string()
                        tabindex=move || if active.get() == id { 0 } else { -1 }
                        on:click=move |_| active.set(target.clone())
                    >
                        {move || ui_t(&label)}
                    </button>
                }
            }).collect_view()}
        </div>
    }
}

#[component]
pub fn TabPanel(
    #[prop(into)] id: Signal<String>,
    #[prop(optional, into)] id_prefix: String,
    children: Children,
) -> impl IntoView {
    let prefix = StoredValue::new(id_prefix);
    view! {
        <div
            role="tabpanel"
            id=move || prefix.with_value(|prefix| tab_dom_id(prefix, "tabpanel", &id.get()))
            aria-labelledby=move || prefix.with_value(|prefix| tab_dom_id(prefix, "tab", &id.get()))
            tabindex="0"
            class="min-w-0 max-w-full space-y-5"
        >
            {children()}
        </div>
    }
}

#[component]
pub fn SearchInput(
    value: RwSignal<String>,
    #[prop(optional, into)] placeholder: Signal<String>,
) -> impl IntoView {
    view! {
        <div class="relative flex items-center min-w-0">
            <svg
                class="pointer-events-none absolute left-3 text-slate-400"
                width="16" height="16" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" stroke-width="1.85" stroke-linecap="round"
                stroke-linejoin="round" aria-hidden="true"
            >
                <circle cx="10.5" cy="10.5" r="6.5"/>
                <path d="m16 16 4.5 4.5"/>
            </svg>
            <input
                type="search"
                aria-label=move || search_accessible_label(&placeholder.get())
                placeholder=move || ui_t(&placeholder.get())
                class="af-input obs-search-input pl-9 pr-3 py-2 min-w-0 w-full"
                prop:value=move || value.get()
                on:input=move |event| value.set(event_target_value(&event))
            />
        </div>
    }
}

#[component]
pub fn SkeletonBox(#[prop(optional, into)] class: String) -> impl IntoView {
    view! {
        <div aria-hidden="true" class=format!("af-skeleton animate-pulse rounded-xl bg-white/5 {class}")></div>
    }
}

#[component]
pub fn OverviewSkeleton() -> impl IntoView {
    view! {
        <div role="status" aria-label=move || ui_t("Overview.loading") class="grid grid-cols-1 md:grid-cols-3 gap-5">
            <SkeletonBox class="h-32"/>
            <SkeletonBox class="h-32"/>
            <SkeletonBox class="h-32"/>
            <SkeletonBox class="h-72 md:col-span-3"/>
        </div>
    }
}

#[component]
pub fn EmptyState(
    #[prop(into)] title: Signal<String>,
    #[prop(optional, into)] description: Signal<String>,
) -> impl IntoView {
    view! {
        <div class="py-12 px-4 text-center min-w-0 max-w-full">
            <div aria-hidden="true" class="text-indigo-400 text-3xl mb-3">"◇"</div>
            <h3 class="font-semibold text-slate-200">{move || ui_t(&title.get())}</h3>
            <p class="text-sm text-slate-400 mt-2">{move || ui_t(&description.get())}</p>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_preserves_the_placeholder_accessible_name_and_shared_query_state() {
        let owner = Owner::new();
        owner.with(|| {
            let value = RwSignal::new("active".to_string());
            let props = SearchInputProps::builder()
                .value(value)
                .placeholder("Filter services")
                .build();
            assert_eq!(props.placeholder.get_untracked(), "Filter services");
            assert_eq!(
                search_accessible_label(&props.placeholder.get_untracked()),
                "Filter services"
            );
            value.set("running".into());
            assert_eq!(props.value.get_untracked(), "running");
            props.value.set(String::new());
            assert!(value.get_untracked().is_empty());
            let defaults = SearchInputProps::builder().value(value).build();
            assert_eq!(
                search_accessible_label(&defaults.placeholder.get_untracked()),
                "Search"
            );
        });
    }

    #[test]
    fn badges_keep_label_and_tone_independent_and_support_neutral_state() {
        Owner::new().with(|| {
            for (tone, label) in [
                ("success", "Ready"),
                ("warning", "Queued"),
                ("danger", "Offline"),
            ] {
                let props = BadgeProps::builder().label(label).tone(tone).build();
                assert_eq!(props.label.get_untracked(), label);
                assert_eq!(
                    badge_class(&props.tone),
                    format!("af-badge af-badge-{tone}")
                );
            }
            let neutral = BadgeProps::builder().label("Unknown").build();
            assert_eq!(badge_class(&neutral.tone), "af-badge");
        });
    }

    #[test]
    fn badge_tones_normalize_supported_aliases_and_reject_untrusted_classes() {
        for (aliases, tone) in [
            (&["amber", "warning"][..], BadgeTone::Warning),
            (&["emerald", "green", "success"][..], BadgeTone::Success),
            (&["rose", "red", "danger"][..], BadgeTone::Danger),
            (&["indigo", "cyan", "info"][..], BadgeTone::Indigo),
            (&["violet", "purple"][..], BadgeTone::Violet),
            (&["muted", "slate"][..], BadgeTone::Muted),
        ] {
            for alias in aliases {
                assert_eq!(BadgeTone::from(*alias), tone);
                assert_eq!(badge_class(alias), badge_class(aliases[0]));
            }
        }
        assert_eq!(BadgeTone::from("  INDIGO  "), BadgeTone::Indigo);
        for unknown in ["", "neutral", "unknown", "fixed inset-0"] {
            assert_eq!(BadgeTone::from(unknown), BadgeTone::Neutral);
            assert_eq!(badge_class(unknown), "af-badge");
        }
    }

    #[test]
    fn connection_labels_preserve_english_defaults_and_translate_all_states() {
        for (state, english) in [
            (ConnectionState::Connected, "API Connected"),
            (ConnectionState::Fallback, "Degraded Polling"),
            (ConnectionState::Reconnecting, "Retrying"),
            (ConnectionState::Offline, "Offline"),
            (ConnectionState::Connecting, "Reconnecting"),
        ] {
            assert_eq!(connection_label(state, ""), english);
            assert_eq!(connection_label(state, "en"), english);
            for locale in ["de", "dk", "es", "fr", "zh"] {
                assert_ne!(
                    connection_label(state, locale),
                    english,
                    "{locale}: {state:?}"
                );
            }
        }
    }

    #[test]
    fn tab_associations_share_the_default_or_explicit_prefix() {
        assert_eq!(tab_dom_id("", "tab", "graph"), "af-tab-graph");
        assert_eq!(tab_dom_id("", "tabpanel", "graph"), "af-tabpanel-graph");
        assert_eq!(tab_dom_id("topology", "tab", "list"), "topology-tab-list");
        assert_eq!(
            tab_dom_id("topology", "tabpanel", "list"),
            "topology-tabpanel-list"
        );
    }

    #[test]
    fn button_tones_map_to_flat_classes_and_data_tones() {
        assert_eq!(
            button_appearance(true, ""),
            ("af-btn-primary px-4 py-2", None)
        );
        assert_eq!(
            button_appearance(false, "primary"),
            ("af-btn-primary px-4 py-2", None)
        );
        assert_eq!(
            button_appearance(false, " PRIMARY "),
            ("af-btn-primary px-4 py-2", None)
        );
        assert_eq!(
            button_appearance(false, "danger"),
            ("af-btn px-4 py-2", Some("danger"))
        );
        assert_eq!(
            button_appearance(false, " SUCCESS "),
            ("af-btn px-4 py-2", Some("success"))
        );
        for neutral in ["", "neutral", "unknown", "fixed inset-0"] {
            assert_eq!(
                button_appearance(false, neutral),
                ("af-btn px-4 py-2", None),
                "{neutral:?}"
            );
        }
        assert_eq!(
            confirm_button_appearance(false),
            ("af-btn-primary px-4 py-2", None)
        );
        assert_eq!(
            confirm_button_appearance(true),
            ("af-btn px-4 py-2", Some("danger"))
        );
    }

    #[test]
    fn card_and_modal_helpers_emit_flat_surface_classes() {
        assert_eq!(card_class(false), "af-card p-5 min-w-0 max-w-full");
        assert_eq!(
            card_class(true),
            "af-card af-card-interactive p-5 min-w-0 max-w-full"
        );
        let dialog_class = modal_dialog_class();
        assert_eq!(dialog_class, "af-modal min-w-0 max-w-full");
        assert!(
            !dialog_class
                .split_whitespace()
                .any(|cls| cls.starts_with("glass-") || cls == "af-card"),
            "modal overlay must never combine with card or legacy glass classes: {dialog_class}"
        );
        assert_eq!(
            modal_close_button_class(),
            "af-btn px-3 min-w-10 min-h-10"
        );
    }
}
