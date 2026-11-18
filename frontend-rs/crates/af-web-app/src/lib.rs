//! Browser application boundary. Wave 2 builders own individual tabs; context,
//! request resources, worker pool and design-system components are shared APIs.
pub mod routes;
pub mod shell;
pub mod state;
pub mod tabs;

use leptos::prelude::*;
use state::AppContext;
#[component]
pub fn App() -> impl IntoView {
    let context = AppContext::new();
    provide_context(context);
    Effect::new(move |_| state::apply_theme_dom(&context.theme.get()));
    Effect::new(move |_| state::apply_reduced_motion_dom(context.reduced_motion.get()));
    state::install_session(context);
    if let Some(window) = web_sys::window() {
        if window.is_secure_context() {
            let promise = window.navigator().service_worker().register("/sw.js");
            wasm_bindgen_futures::spawn_local(async move {
                let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
            });
        }
    }
    let path = web_sys::window()
        .and_then(|w| w.location().pathname().ok())
        .unwrap_or_else(|| "/".into());
    view! {<a href="#main-content" class="af-skip-link">{move || context.t("Shell.skipToContent")}</a>{match path.trim_end_matches('/'){
        "/login"=>view!{<routes::LoginPage/>}.into_any(),
        "/oauth/consent"=>view!{<routes::ConsentPage/>}.into_any(),
        "/share"=>view!{<routes::SharePage/>}.into_any(),
        _=>view!{<shell::AuthGuard><DashboardRoute/></shell::AuthGuard>}.into_any(),
    }}<shell::ToastContainer/>}
}

#[component]
fn DashboardRoute() -> impl IntoView {
    let context = state::app();
    Effect::new(move |_| {
        context.normalize_fallback_url(state::clamp_tab_for_role(
            context.tab.get(),
            context.is_admin(),
        ));
    });
    view! { <shell::Dashboard/> }
}
