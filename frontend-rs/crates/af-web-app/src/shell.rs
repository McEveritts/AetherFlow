use crate::state::{
    app, clamp_tab_for_role, current_path, json_rows, navigate, query_param, stroke_icon,
    AppContext, TabId,
};
use af_web_core::{
    api::{storage_get, storage_set, ApiClient},
    charts::Point,
    worker::{SearchItem, SearchMatch, WorkerRequest, WorkerResponse},
    worker_pool::WorkerPool,
    ws::{BrowserConnection, ConnectionState, TransportEvent},
};
use af_web_ui::{Drawer, Modal, OverviewSkeleton, StatusPill};
use futures::future::{AbortHandle, Abortable};
use gloo_events::EventListener;
use leptos::prelude::*;
use serde_json::json;
use wasm_bindgen::{closure::Closure, JsCast};
use wasm_bindgen_futures::spawn_local;

fn shell_icon(name: &str) -> AnyView {
    stroke_icon(match name {
        "logout" => "M9 3H4v18h5 M9 12h12 M17 8l4 4-4 4",
        "menu" => "M3 6h18 M3 12h18 M3 18h18",
        "search" => "M10.5 3a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15Z m5.5 13 5 5",
        "sun" => "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z M12 2v2 M12 20v2 M2 12h2 M20 12h2 M5 5l1.5 1.5 M17.5 17.5 19 19 M5 19l1.5-1.5 M17.5 6.5 19 5",
        "moon" => "M20.9 13a9 9 0 0 1-9.9-9.9A9 9 0 1 0 20.9 13Z",
        "bell" => "M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9 M10 21h4",
        _ => "M6 6l12 12 M6 18 18 6",
    })
}

#[component]
pub fn PublicRouteToolbar() -> impl IntoView {
    let context = app();
    view! {
        <div class="af-public-toolbar">
            <select
                class="af-locale-select glass-input"
                aria-label=move || context.t("Shell.locale")
                prop:value=move || context.locale.get()
                on:change=move |event| context.set_locale(&event_target_value(&event))
            >
                {[("en", "English"), ("de", "Deutsch"), ("dk", "Dansk"), ("es", "Español"), ("fr", "Français"), ("zh", "中文")]
                    .into_iter().map(|(value, label)| view! { <option value=value>{label}</option> }).collect_view()}
            </select>
            <button
                type="button"
                class="glass-button af-public-theme-toggle"
                aria-label=move || context.t("Shell.toggleTheme")
                aria-pressed=move || context.is_light().to_string()
                on:click=move |_| context.toggle_theme()
            >
                {move || shell_icon(if context.is_light() { "moon" } else { "sun" })}
            </button>
        </div>
    }
}

#[component]
pub fn AuthGuard(children: ChildrenFn) -> impl IntoView {
    let context = app();
    Effect::new(move |_| {
        if !context.auth_loading.get() && context.user.with(Option::is_none) {
            navigate(&format!(
                "/login?returnTo={}",
                js_sys::encode_uri_component(&current_path())
            ));
        }
    });
    view! {
        <Show
            when=move || !context.auth_loading.get() && context.user.with(Option::is_some)
            fallback=|| view! { <div class="p-8"><OverviewSkeleton/></div> }
        >
            {children()}
        </Show>
    }
}

#[derive(Clone, Copy)]
struct ShellRefreshState {
    request: RwSignal<u64>,
    metrics: RwSignal<u64>,
    in_flight: StoredValue<Option<AbortHandle>, LocalStorage>,
}

fn refresh_shell(context: AppContext, revisions: ShellRefreshState) {
    // A slow cohort is allowed to finish. Poll ticks while it is active are
    // coalesced; a later tick starts the next cohort after the guard drops.
    let Some(Some(registration)) = revisions.in_flight.try_update_value(|active| {
        if active.is_some() {
            return None;
        }
        let (abort, registration) = AbortHandle::new_pair();
        *active = Some(abort);
        Some(registration)
    }) else {
        return;
    };
    let epoch = context.session_epoch.get_untracked();
    revisions.request.update(|n| *n = n.wrapping_add(1));
    let request = revisions.request.get_untracked();
    let metrics_revision = revisions.metrics.get_untracked();
    let services_request = context.begin_services_request();
    spawn_local(async move {
        let work = async move {
            let (metrics, services, notifications) = futures::join!(
                ApiClient.get("/api/v1/auth/system/metrics"),
                ApiClient.get("/api/v1/auth/services"),
                ApiClient.get("/api/v1/auth/notifications")
            );
            if context.session_epoch.try_get_untracked() != Some(epoch)
                || context.user.try_get_untracked().flatten().is_none()
                || revisions.request.try_get_untracked() != Some(request)
            {
                return;
            }
            if let Some(metrics) = metrics
                .ok()
                .filter(|_| revisions.metrics.try_get_untracked() == Some(metrics_revision))
            {
                context.metrics.set(metrics);
            }
            if let Ok(services) = services {
                context.finish_services_request(services_request, services);
            }
            if let Ok(notifications) = notifications {
                context.notifications.set(json_rows(&notifications));
            }
            if context.is_admin() {
                if let Ok(pending) = ApiClient
                    .get("/api/v1/admin/actions/pending?status=pending&limit=1")
                    .await
                {
                    if context.session_epoch.try_get_untracked() != Some(epoch)
                        || revisions.request.try_get_untracked() != Some(request)
                    {
                        return;
                    }
                    context.pending.set(
                        pending["total"]
                            .as_u64()
                            .or_else(|| pending["count"].as_u64())
                            .map(|n| n as usize)
                            .unwrap_or_else(|| json_rows(&pending).len()),
                    );
                }
            }
        };
        let _ = Abortable::new(work, registration).await;
        // Abortable has dropped the cohort's request guards before another
        // timer tick can observe an empty slot and start the next cohort.
        let _ = revisions
            .in_flight
            .try_update_value(|active| *active = None);
    });
}
#[component]
pub fn Dashboard() -> impl IntoView {
    let context = app();
    view! {
        <For each=move || [context.session_epoch.get()] key=|epoch| *epoch let:_>
            <AuthenticatedShell/>
        </For>
    }
}

#[component]
fn AuthenticatedShell() -> impl IntoView {
    let context = app();
    let epoch = context.session_epoch.get_untracked();
    let revisions = ShellRefreshState {
        request: RwSignal::new(0),
        metrics: RwSignal::new(0),
        in_flight: StoredValue::new_local(None),
    };
    on_cleanup(move || {
        revisions.in_flight.update_value(|active| {
            if let Some(abort) = active.take() {
                abort.abort();
            }
        });
    });
    let initial_tab_explicit = query_param("tab").is_some();
    Effect::new(move |_| {
        let loading = context.auth_loading.get();
        let authenticated = context.user.with(Option::is_some);
        let tab = context.tab.get();
        if !loading && authenticated && clamp_tab_for_role(tab, context.is_admin()) != tab {
            context.tab.set(TabId::Overview);
            context.replace_tab_url(TabId::Overview);
        }
    });
    let history = StoredValue::new_local(web_sys::window().map(|window| {
        EventListener::new(&window, "popstate", move |_| {
            context.tab.set(
                query_param("tab")
                    .map(|key| TabId::from_key(&key))
                    .unwrap_or_default(),
            );
            context.mobile_open.set(false);
        })
    }));
    on_cleanup(move || history.set_value(None));
    refresh_shell(context, revisions);
    let (settings_abort, settings_registration) = AbortHandle::new_pair();
    on_cleanup(move || settings_abort.abort());
    spawn_local(async move {
        let work = async move {
            let result = ApiClient.get("/api/v1/auth/settings").await;
            if context.session_epoch.try_get_untracked() != Some(epoch) {
                return;
            }
            match result {
                Ok(settings) => {
                    // This request only bootstraps the shell. A tab may have loaded
                    // or saved a newer snapshot while it was pending; use that
                    // accepted cache for both preferences and shared settings.
                    let settings = context.settings.with_untracked(|current| {
                        if current.is_null() {
                            settings
                        } else {
                            current.clone()
                        }
                    });
                    if !initial_tab_explicit && context.tab.get_untracked() == TabId::Overview {
                        if let Some(default_tab) = settings["defaultDashboard"]
                            .as_str()
                            .filter(|tab| !tab.is_empty())
                        {
                            let target = TabId::from_key(default_tab);
                            if clamp_tab_for_role(target, context.is_admin()) == target {
                                context.tab.set(target);
                                if target != TabId::Overview {
                                    context.replace_tab_url(target);
                                }
                            }
                        }
                    }
                    if let Some(locale) = settings["language"]
                        .as_str()
                        .filter(|s| af_web_core::i18n::LOCALES.contains(s))
                    {
                        // A browser choice (including one made while this request
                        // was in flight) takes precedence over the server default.
                        if storage_get("aetherflow-language")
                            .filter(|locale| af_web_core::i18n::LOCALES.contains(&locale.as_str()))
                            .is_none()
                        {
                            context.set_locale(locale);
                        }
                    }
                    context.settings.set(settings);
                }
                Err(error) => context.toast(context.t(&error.message), true),
            }
        };
        let _ = Abortable::new(work, settings_registration).await;
    });
    let connection = StoredValue::new_local(Some(BrowserConnection::start(move |event| {
        if context.session_epoch.try_get_untracked() != Some(epoch)
            || context.user.try_get_untracked().flatten().is_none()
        {
            return;
        }
        match event {
            TransportEvent::State(state) => {
                context.connection.set(state);
                if state == ConnectionState::Connected {
                    context.history_revision.update(|v| *v += 1);
                }
            }
            TransportEvent::Metrics(metrics) => {
                revisions.metrics.update(|n| *n = n.wrapping_add(1));
                if let Some(cpu) = metrics["cpu_usage"].as_f64() {
                    let point = Point {
                        x: js_sys::Date::now(),
                        y: cpu,
                    };
                    context.history.update(|history| {
                        history.push(point);
                        if history.len() > 2400 {
                            history.drain(..history.len() - 2400);
                        }
                    });
                }
                context.metrics.set(metrics);
            }
            TransportEvent::Services(services) => {
                context.publish_live_services(services);
            }
            TransportEvent::Control(event) => match event["type"].as_str() {
                Some("MARKETPLACE_UPDATE" | "package:progress" | "SYSTEM_HEAL") => {
                    context.marketplace_revision.update(|v| *v += 1)
                }
                Some("ACTION_QUEUED") => context.pending.update(|v| *v += 1),
                Some("MAINTENANCE" | "MAINTENANCE_MODE" | "SERVER_RESTART" | "SYSTEM_RESTART") => {
                    context.banners.update(|b| {
                        b.push(
                            event["data"]["message"]
                                .as_str()
                                .or_else(|| event["message"].as_str())
                                .map(str::to_string)
                                .unwrap_or_else(|| context.t("Shell.maintenance")),
                        )
                    })
                }
                _ => {}
            },
        }
    })));
    on_cleanup(move || connection.set_value(None));
    let polling = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        30_000,
        move || refresh_shell(context, revisions),
    )));
    on_cleanup(move || polling.set_value(None));
    let main = NodeRef::<leptos::html::Main>::new();
    Effect::new(move |_| {
        context.tab.track();
        if let Some(main) = main.get() {
            main.set_scroll_top(0);
        }
    });
    view! {
        <div class="af-shell flex min-h-screen min-w-0 max-w-full">
            <Sidebar/>
            <main
                id="main-content" node_ref=main tabindex="-1"
                data-dashboard-main="true" data-scroller="main"
                class="flex-1 min-w-0 max-w-full relative z-10 overflow-y-auto focus:outline-none"
            >
                <Header/>
                <GlobalBanners/>
                <div class="af-tab-content min-w-0 max-w-full px-4 md:px-8 pb-8">
                    <crate::tabs::TabRouter/>
                </div>
            </main>
            <MobileNavigation/>
            <OnboardingWizard/>
            <GlobalCommandPalette/>
            <NotificationDrawer/>
        </div>
    }
}

#[component]
pub fn Sidebar() -> impl IntoView {
    let context = app();
    let pinned =
        RwSignal::new(storage_get("aetherflow-sidebar-pinned").is_some_and(|s| s == "true"));
    let preferences = StoredValue::new_local(web_sys::window().map(|window| {
        EventListener::new(&window, "af:preferences-changed", move |_| {
            pinned.set(storage_get("aetherflow-sidebar-pinned").is_some_and(|s| s == "true"));
        })
    }));
    on_cleanup(move || preferences.set_value(None));
    Effect::new(move |_| {
        context.tab.track();
        pinned.track();
        if let Some(window) = web_sys::window() {
            let callback = Closure::once_into_js(move || {
                if let Some(active) = web_sys::window().and_then(|w| w.document()).and_then(|d| {
                    d.query_selector("#desktop-sidebar-navigation .af-nav-active")
                        .ok()
                        .flatten()
                }) {
                    active.scroll_into_view_with_bool(false);
                }
            });
            let _ = window.request_animation_frame(callback.unchecked_ref());
        }
    });
    view! {
        <aside
            id="desktop-sidebar-navigation"
            class="af-sidebar obs-gpu-120hz-rail shrink-0 relative z-30"
            class:af-sidebar-expanded=move || pinned.get()
        >
            <button
                type="button" class="af-logo-button"
                aria-label=move || format!("AetherFlow: {}", context.t(if pinned.get() { "Shell.collapseSidebar" } else { "Shell.expandSidebar" }))
                aria-expanded=move || pinned.get().to_string()
                on:click=move |_| {
                    context.haptic(8);
                    pinned.update(|pinned| *pinned = !*pinned);
                    storage_set("aetherflow-sidebar-pinned", if pinned.get_untracked() { "true" } else { "false" });
                }
            >
                <span class="obs-brand-logo af-sidebar-logo">
                    <img src="/img/aetherflow-mark.svg" alt="" class="obs-brand-mark"/>
                </span>
                <span class="af-nav-label font-semibold text-lg">"AetherFlow"</span>
            </button>
            <nav
                aria-label=move || context.t("Shell.mainNavigation")
                class="flex flex-col gap-1 flex-1 min-h-0 overflow-y-auto py-3"
            >
                {move || TabId::ALL.into_iter().filter(|tab| !tab.is_admin_only() || context.is_admin()).map(|tab| view! {
                    <button
                        type="button"
                        class=format!("af-nav-button af-nav-{}", tab.key())
                        class:af-nav-active=move || context.tab.get() == tab
                        aria-label=move || tab.localized_label(&context.locale.get())
                        data-testid=format!("nav-{}", tab.key())
                        title=move || tab.localized_label(&context.locale.get())
                        aria-current=move || if context.tab.get() == tab { Some("page") } else { None }
                        on:click=move |_| context.select_tab(tab)
                    >
                        <span class="af-nav-icon" aria-hidden="true">{tab.icon_svg()}</span>
                        <span class="af-nav-label">{move || tab.localized_label(&context.locale.get())}</span>
                        {(tab == TabId::Inbox).then(|| view! {
                            <Show when=move || { context.pending.get() > 0 }>
                                <span
                                    class="af-pending-badge"
                                    aria-label=move || context.t_with("Shell.pendingActions", &[("count", &context.pending.get().to_string())])
                                >
                                    {move || context.pending.get()}
                                </span>
                            </Show>
                        })}
                    </button>
                }).collect_view()}
            </nav>
            <button
                type="button" class="af-nav-button my-3"
                aria-label=move || context.t("Shell.logout")
                data-testid="nav-logout"
                title=move || context.t("Shell.logout")
                on:click=move |_| context.logout()
            >
                <span class="af-nav-icon" aria-hidden="true">{shell_icon("logout")}</span>
                <span class="af-nav-label">{move || context.t("Shell.logout")}</span>
            </button>
        </aside>
    }
}

#[component]
fn MobileNavigation() -> impl IntoView {
    let context = app();
    view! {
        <nav class="af-mobile-dock" aria-label=move || context.t("Shell.mobileDock")>
            {[TabId::Overview, TabId::Services, TabId::Streaming].into_iter().map(|tab| view! {
                <button
                    class="af-dock-button"
                    aria-label=move || tab.localized_label(&context.locale.get())
                    title=move || context.t_with("Shell.openTab", &[("tab", &tab.localized_label(&context.locale.get()))])
                    aria-current=move || if context.tab.get() == tab { Some("page") } else { None }
                    on:click=move |_| {
                        context.haptic(8);
                        context.select_tab(tab);
                    }
                >
                    <span aria-hidden="true">{tab.icon_svg()}</span>
                    <span>{move || tab.localized_label(&context.locale.get())}</span>
                </button>
            }).collect_view()}
            <button
                class="af-dock-button"
                aria-label=move || context.t("Shell.more")
                title=move || context.t("Shell.openNavigationMenu")
                aria-expanded=move || context.mobile_open.get().to_string()
                on:click=move |_| {
                    context.haptic(8);
                    context.mobile_open.set(true);
                }
            >
                <span aria-hidden="true">{shell_icon("menu")}</span>
                <span>{move || context.t("Shell.more")}</span>
            </button>
        </nav>
        <Drawer open=context.mobile_open title=Signal::derive(move || context.t("Shell.navigation"))>
            <nav aria-label=move || context.t("Shell.mobileNavigation") class="grid grid-cols-2 gap-2">
                {move || TabId::ALL.into_iter().filter(|tab| !tab.is_admin_only() || context.is_admin()).map(|tab| view! {
                    <button
                        class="af-mobile-nav-button glass-button px-3 py-3 text-left flex items-center"
                        aria-label=move || tab.localized_label(&context.locale.get())
                        data-testid=format!("mobile-nav-{}", tab.key())
                        on:click=move |_| {
                            context.haptic(8);
                            context.select_tab(tab);
                        }
                    >
                        <span class="text-indigo-300 mr-2" aria-hidden="true">{tab.icon_svg()}</span>
                        {move || tab.localized_label(&context.locale.get())}
                    </button>
                }).collect_view()}
                <button
                    class="af-mobile-nav-button glass-button px-3 py-3 text-left flex items-center"
                    aria-label=move || context.t("Shell.logout")
                    data-testid="mobile-nav-logout"
                    on:click=move |_| context.logout()
                >
                    <span class="text-indigo-300 mr-2" aria-hidden="true">{shell_icon("logout")}</span>
                    {move || context.t("Shell.logout")}
                </button>
            </nav>
        </Drawer>
    }
}

#[component]
pub fn Header() -> impl IntoView {
    let context = app();
    view! {
        <header class="af-header sticky top-0 z-20 flex flex-wrap gap-3 items-center justify-between px-4 md:px-8 py-4 border-b border-white/5 backdrop-blur-xl">
            <div class="af-header-heading flex items-center gap-3 min-w-0">
                <button
                    class="af-hamburger glass-button px-3"
                    aria-label=move || context.t("Shell.openNavigation")
                    on:click=move |_| context.mobile_open.set(true)
                >
                    {shell_icon("menu")}
                </button>
                <div class="min-w-0">
                    <p class="af-header-eyebrow text-xs text-slate-500 uppercase tracking-[.22em]">
                        {move || context.t("Shell.controlPlane")}
                    </p>
                    <h1 class="text-xl font-semibold mt-1">{move || context.tab.get().localized_label(&context.locale.get())}</h1>
                </div>
            </div>
            <div class="af-header-actions flex items-center gap-2 min-w-0">
                <StatusPill state=context.connection locale=context.locale/>
                <button
                    class="af-command-button glass-button px-3 text-sm inline-flex items-center gap-2"
                    aria-label=move || context.t("Shell.openCommandPalette")
                    title=move || context.t("Shell.commandPaletteShortcut")
                    on:click=move |_| context.command_open.set(true)
                >
                    {shell_icon("search")}
                    <span class="af-command-label">{move || context.t("Shell.search")}</span>
                    <kbd class="text-xs text-slate-400">"⌘ K"</kbd>
                </button>
                <select
                    aria-label=move || context.t("Shell.locale")
                    class="af-locale-select glass-input px-2 text-sm max-w-24"
                    prop:value=move || context.locale.get()
                    on:change=move |event| context.set_locale(&event_target_value(&event))
                >
                    {[("en", "English"), ("de", "Deutsch"), ("dk", "Dansk"), ("es", "Español"), ("fr", "Français"), ("zh", "中文")]
                        .into_iter().map(|(value, label)| view! { <option value=value>{label}</option> }).collect_view()}
                </select>
                <button
                    class="glass-button px-3"
                    aria-label=move || context.t("Shell.toggleTheme")
                    aria-pressed=move || context.is_light().to_string()
                    on:click=move |_| context.toggle_theme()
                >
                    {move || shell_icon(if context.is_light() { "moon" } else { "sun" })}
                </button>
                <button
                    class="glass-button px-3 relative"
                    aria-label=move || context.t("Shell.notifications")
                    on:click=move |_| context.notifications_open.set(true)
                >
                    {shell_icon("bell")}
                    <Show when=move || context.notifications.with(|notes| notes.iter().any(|note| note["read"] != true))>
                        <span class="af-notification-dot"></span>
                    </Show>
                </button>
                <span
                    class="af-user-badge text-sm px-3 py-2 rounded-full bg-indigo-500/10 text-indigo-200"
                    title=move || context.typed_user().map(|user| user.role).unwrap_or_else(|| "user".into())
                >
                    {move || context.typed_user().map(|user| user.username).unwrap_or_else(|| context.t("Shell.operator"))}
                </span>
            </div>
        </header>
    }
}

#[component]
pub fn GlobalBanners() -> impl IntoView {
    let context = app();
    view! {
        <div class="min-w-0 max-w-full">
            <Show when=move || matches!(context.connection.get(), ConnectionState::Reconnecting | ConnectionState::Fallback)>
                <div role="status" class="af-warning-banner mx-4 md:mx-8 my-4">{move || context.t("Shell.reconnecting")}</div>
            </Show>
            {move || context.banners.get().into_iter().enumerate().map(|(index, banner)| view! {
                <div role="alert" class="af-warning-banner mx-4 my-3 flex justify-between gap-3">
                    <span>{banner}</span>
                    <button
                        aria-label=move || context.t("Shell.dismissBanner")
                        on:click=move |_| context.banners.update(|banners| {
                            if index < banners.len() {
                                banners.remove(index);
                            }
                        })
                    >
                        {shell_icon("close")}
                    </button>
                </div>
            }).collect_view()}
        </div>
    }
}

#[component]
pub fn OnboardingWizard() -> impl IntoView {
    let context = app();
    let open = RwSignal::new(false);
    let step = RwSignal::new(1u8);
    let domain = RwSignal::new(String::new());
    let dirty = RwSignal::new(false);
    let busy = RwSignal::new(false);
    Effect::new(move |_| {
        let settings = context.settings.get();
        open.set(context.is_admin() && settings["setupCompleted"] == false);
        if !settings.is_null() && !dirty.get_untracked() {
            domain.set(settings["baseDomain"].as_str().unwrap_or_default().into());
        }
    });
    let finish = move || {
        if !context.is_admin() || busy.get_untracked() {
            return;
        }
        busy.set(true);
        let mut settings = context.settings.get_untracked();
        settings["setupCompleted"] = json!(true);
        settings["baseDomain"] = json!(domain.get_untracked().trim());
        let epoch = context.session_epoch.get_untracked();
        spawn_local(async move {
            let result = ApiClient
                .request("/api/v1/admin/settings", "PUT", Some(&settings))
                .await;
            if context.session_epoch.try_get_untracked() != Some(epoch) {
                return;
            }
            match result {
                Ok(_) => {
                    context.settings.set(settings);
                    open.set(false);
                    context.toast(context.t("Onboarding.ready"), false);
                }
                Err(e) => context.toast(context.t(&e.message), true),
            }
            busy.set(false);
        });
    };
    view! {
        <Modal open title=Signal::derive(move || context.t("Onboarding.title"))>
            <p class="text-slate-400 mb-5">
                {move || context.t(if step.get() == 1 { "Onboarding.introduction" } else { "Onboarding.domainDescription" })}
            </p>
            <Show when=move || step.get() == 2>
                <label for="onboarding-domain" class="text-sm">{move || context.t("Onboarding.baseDomain")}</label>
                <input
                    id="onboarding-domain" class="glass-input w-full px-3 py-3 my-4"
                    placeholder="example.com" prop:value=move || domain.get()
                    on:input=move |event| {
                        dirty.set(true);
                        domain.set(event_target_value(&event));
                    }
                />
            </Show>
            <div class="flex justify-end">
                <button
                    class="glass-button-primary px-5 py-3" disabled=move || busy.get()
                    on:click=move |_| if step.get_untracked() == 1 { step.set(2); } else { finish(); }
                >
                    {move || context.t(if busy.get() { "Common.saving" } else if step.get() == 1 {
                        "Onboarding.continue"
                    } else { "Onboarding.enterDashboard" })}
                </button>
            </div>
        </Modal>
    }
}

#[component]
pub fn GlobalCommandPalette() -> impl IntoView {
    let context = app();
    let search_input = NodeRef::<leptos::html::Input>::new();
    Effect::new(move |_| {
        if context.command_open.get() {
            // Modal opens its dialog in an effect. Focus in the next task so
            // showModal's initial focus does not return to the close button.
            gloo_timers::callback::Timeout::new(0, move || {
                if context.command_open.try_get_untracked() == Some(true) {
                    if let Some(input) = search_input.get_untracked() {
                        let _ = input.focus();
                    }
                }
            })
            .forget();
        }
    });
    let query = RwSignal::new(String::new());
    let results = RwSignal::new(Vec::<SearchMatch>::new());
    let focused = RwSignal::new(0usize);
    let generation = RwSignal::new(0u64);
    let pool = StoredValue::new_local(WorkerPool::shared());
    Effect::new(move |_| {
        if !context.command_open.get() {
            return;
        }
        let locale = context.locale.get();
        let query = query.get();
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        let pool = pool.get_value();
        let items = TabId::ALL
            .into_iter()
            .filter(|t| !t.is_admin_only() || context.is_admin())
            .map(|tab| SearchItem {
                id: tab.key().into(),
                text: tab.localized_label(&locale),
            })
            .collect();
        spawn_local(async move {
            if let WorkerResponse::SearchResults { items } = pool
                .execute(WorkerRequest::FuzzySearch {
                    query,
                    items,
                    limit: 16,
                })
                .await
            {
                if generation.try_get_untracked() == Some(ticket) {
                    results.set(items);
                    focused.set(0);
                }
            }
        });
    });
    let select = move |id: &str| {
        context.select_tab(TabId::from_key(id));
        context.command_open.set(false);
        query.set(String::new());
    };
    view! {
        <Modal open=context.command_open title=Signal::derive(move || context.t("Shell.commandPalette"))>
            <div on:keydown=move |event| {
                let len = results.with(Vec::len);
                match event.key().as_str() {
                    "ArrowDown" => {
                        event.prevent_default();
                        focused.update(|index| *index = (*index + 1).min(len.saturating_sub(1)));
                    }
                    "ArrowUp" => {
                        event.prevent_default();
                        focused.update(|index| *index = index.saturating_sub(1));
                    }
                    "Enter" => {
                        event.prevent_default();
                        if let Some(item) = results.with(|results| results.get(focused.get_untracked()).cloned()) {
                            select(&item.id);
                        }
                    }
                    _ => {}
                }
            }>
                <input
                    node_ref=search_input type="search"
                    class="glass-input w-full px-3 py-3"
                    aria-label=move || context.t("Shell.searchCommands")
                    placeholder=move || context.t("Shell.searchPlaceholder")
                    role="combobox" aria-expanded="true" aria-controls="af-command-results"
                    aria-activedescendant=move || {
                        let len = results.with(Vec::len);
                        (len > 0).then(|| format!("af-command-{}", focused.get().min(len - 1)))
                    }
                    prop:value=move || query.get()
                    on:input=move |event| query.set(event_target_value(&event))
                />
                <ul id="af-command-results" role="listbox" class="max-h-80 overflow-y-auto mt-3">
                    {move || results.get().into_iter().enumerate().map(|(index, item)| view! {
                        <li
                            role="option" id=format!("af-command-{index}") tabindex="-1"
                            aria-selected=move || (focused.get() == index).to_string()
                            class="w-full text-left px-3 py-3 rounded-lg hover:bg-indigo-500/10 cursor-pointer"
                            class=("bg-indigo-500/10", move || focused.get() == index)
                            on:click=move |_| select(&item.id)
                        >
                            {item.text}
                        </li>
                    }).collect_view()}
                </ul>
            </div>
        </Modal>
    }
}

#[component]
pub fn NotificationDrawer() -> impl IntoView {
    let context = app();
    view! {
        <Drawer open=context.notifications_open title=Signal::derive(move || context.t("Shell.notifications"))>
            <button
                class="glass-button px-3 py-2 mb-4"
                on:click=move |_| {
                    let epoch = context.session_epoch.get_untracked();
                    spawn_local(async move {
                        let result = ApiClient.request("/api/v1/auth/notifications/dismiss-all", "POST", None).await;
                        if context.session_epoch.try_get_untracked() != Some(epoch) {
                            return;
                        }
                        match result {
                            Ok(_) => context.notifications.update(|notes| {
                                for note in notes {
                                    note["read"] = json!(true);
                                }
                            }),
                            Err(error) => context.toast(context.t(&error.message), true),
                        }
                    });
                }
            >
                {move || context.t("Shell.markAllRead")}
            </button>
            <Show
                when=move || !context.notifications.with(Vec::is_empty)
                fallback=move || view! {
                    {move || view! {
                        <af_web_ui::EmptyState title=context.t("Shell.caughtUp") description=context.t("Shell.newActivity")/>
                    }}
                }
            >
                <ul class="divide-y divide-white/10">
                    {move || context.notifications.get().into_iter().map(|note| {
                        let id = note["id"].as_i64().unwrap_or_default();
                        view! {
                            <li class="py-4">
                                <p class="font-medium">
                                    {note["title"].as_str().map(str::to_string).unwrap_or_else(|| context.t("Shell.notification"))}
                                </p>
                                <p class="text-sm text-slate-400 mt-2">{note["message"].as_str().unwrap_or_default().to_string()}</p>
                                <button
                                    class="text-xs text-indigo-300 mt-2"
                                    on:click=move |_| {
                                        let epoch = context.session_epoch.get_untracked();
                                        spawn_local(async move {
                                            let result = ApiClient.request(&format!("/api/v1/auth/notifications/{id}/read"), "PUT", None).await;
                                            if context.session_epoch.try_get_untracked() != Some(epoch) {
                                                return;
                                            }
                                            match result {
                                                Ok(_) => context.notifications.update(|notes| {
                                                    for note in notes.iter_mut().filter(|note| note["id"] == id) {
                                                        note["read"] = json!(true);
                                                    }
                                                }),
                                                Err(error) => context.toast(context.t(&error.message), true),
                                            }
                                        });
                                    }
                                >
                                    {move || context.t("Shell.markRead")}
                                </button>
                            </li>
                        }
                    }).collect_view()}
                </ul>
            </Show>
        </Drawer>
    }
}

#[component]
pub fn ToastContainer() -> impl IntoView {
    let context = app();
    view! {
        <div class="af-toasts" aria-live="polite" aria-atomic="false">
            <For each=move || context.toasts.get() key=|toast| toast.id children=move |toast| {
                let rendered_toast = toast.clone();
                view! {
                <div
                    role=if toast.error { "alert" } else { "status" }
                    class=if toast.error { "glass-card af-toast border-rose-500/40" } else { "glass-card af-toast" }
                >
                    <span>{move || context.render_toast(&rendered_toast)}</span>
                    <button
                        class="px-2" aria-label=move || context.t("Shell.dismissNotification")
                        on:click=move |_| context.toasts.update(|toasts| toasts.retain(|current| current.id != toast.id))
                    >
                        {shell_icon("close")}
                    </button>
                </div>
                }
            }/>
        </div>
    }
}
