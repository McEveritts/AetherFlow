use crate::{
    shell::PublicRouteToolbar,
    state::{app, current_path, navigate, query_param},
};
use af_web_core::{api::ApiClient, navigation::safe_oidc_redirect};
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsentDecision {
    DenyLocally,
    RequireLogin,
    Submit,
}

fn consent_decision(authenticated: bool, approved: bool) -> ConsentDecision {
    match (authenticated, approved) {
        (false, false) => ConsentDecision::DenyLocally,
        (false, true) => ConsentDecision::RequireLogin,
        (true, _) => ConsentDecision::Submit,
    }
}

#[component]
pub fn ConsentPage() -> impl IntoView {
    let context = app();
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let denied_local = RwSignal::new(false);
    let mut request = json!({});
    for key in [
        "client_id",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    ] {
        request[key] = Value::String(query_param(key).unwrap_or_else(|| {
            if key == "scope" {
                "openid profile email".into()
            } else {
                String::new()
            }
        }));
    }
    let request = StoredValue::new(request);
    let scopes = request.with_value(|r| {
        r["scope"]
            .as_str()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>()
    });
    let critical = scopes.iter().any(|s| {
        matches!(
            s.as_str(),
            "system:reboot" | "system:write" | "system:auth" | "system:shutdown" | "admin"
        )
    });
    let request_error = request.with_value(|request| {
        if request["client_id"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            Some("Consent.missingClient")
        } else if request["response_type"] != "code" {
            Some("Consent.codeFlow")
        } else if !safe_oidc_redirect(request["redirect_uri"].as_str().unwrap_or_default()) {
            Some("Consent.invalidCallback")
        } else {
            None
        }
    });
    let invalid = request_error.is_some();
    if let Some(key) = request_error {
        error.set(key.into());
    }
    let consent = move |approved: bool| {
        if busy.get_untracked()
            || denied_local.get_untracked()
            || context.auth_loading.get_untracked()
        {
            return;
        }
        let decision = consent_decision(context.user.with_untracked(Option::is_some), approved);
        if decision == ConsentDecision::DenyLocally {
            // Only the authenticated server can verify the registered callback.
            // Denying an unverified request never constructs a callback URL.
            denied_local.set(true);
            error.set("Consent.deniedUnverified".into());
            return;
        }
        if invalid {
            error.set("Consent.invalidRequest".into());
            return;
        }
        if decision == ConsentDecision::RequireLogin {
            navigate(&format!(
                "/login?returnTo={}",
                js_sys::encode_uri_component(&current_path())
            ));
            return;
        }
        busy.set(true);
        error.set(String::new());
        let mut body = request.get_value();
        body["approved"] = json!(approved);
        spawn_local(async move {
            match ApiClient
                .request("/api/v1/auth/oidc/consent", "POST", Some(&body))
                .await
            {
                Ok(data) => {
                    if let Some(target) = data["redirect_uri"]
                        .as_str()
                        .or_else(|| data["redirect_url"].as_str())
                    {
                        if safe_oidc_redirect(target) {
                            navigate(target);
                        } else {
                            error.set("Consent.unsafeRedirect".into());
                        }
                    } else {
                        error.set("Consent.missingDestination".into());
                    }
                }
                Err(e) => error.set(e.message),
            }
            busy.set(false);
        });
    };
    view! {
        <main id="main-content" tabindex="-1" class="af-public-route min-h-screen px-5 py-12 grid place-items-center">
            <PublicRouteToolbar/>
            <div class="w-full max-w-xl min-w-0 space-y-6">
                <header>
                    <p class="text-indigo-300 text-xs tracking-widest uppercase mb-3">
                        {move || context.t("Consent.subtitle")}
                    </p>
                    <h1 class="text-2xl font-semibold">{move || context.t("Routes.consentHeading")}</h1>
                    <p class="mt-3 text-slate-400">
                        <strong class="text-indigo-200">
                            {request.with_value(|request| request["client_id"].as_str().unwrap_or_default().to_string())}
                        </strong>
                        {move || context.t("Consent.requestingAccess")}
                    </p>
                </header>
                {critical.then(|| view! {
                    <div role="alert" class="af-danger-banner">
                        <strong>{move || context.t("Consent.critical")}</strong>
                        <p class="mt-1">{move || context.t("Consent.criticalDescription")}</p>
                    </div>
                })}
                <af_web_ui::ObsCard title=Signal::derive(move || context.t("Consent.scopes"))>
                    <ul class="divide-y divide-white/10">
                        {scopes.into_iter().map(|scope| view! {
                            <li class="py-3 font-mono text-sm break-all">{scope}</li>
                        }).collect_view()}
                    </ul>
                    <label class="block text-xs text-slate-400 mt-5" for="oauth-redirect-uri">
                        {move || context.t("Consent.redirect")}
                    </label>
                    <input
                        id="oauth-redirect-uri" type="text"
                        class="glass-input w-full p-3 mt-2 text-sm" readonly=true
                        value=request.with_value(|request| request["redirect_uri"].as_str().unwrap_or_default().to_string())
                    />
                </af_web_ui::ObsCard>
                <Show when=move || !error.get().is_empty()>
                    <p role="alert" class="af-danger-banner">{move || {
                        let msg = error.get();
                        if msg.is_empty() {
                            String::new()
                        } else {
                            let translated = context.t(&msg);
                            if msg == "Consent.deniedUnverified" && translated == msg {
                                "Authorization denied. Sign in to verify this application before continuing.".into()
                            } else {
                                translated
                            }
                        }
                    }}</p>
                </Show>
                <Show when=move || denied_local.get()>
                    <a href="/login" class="glass-button-primary inline-block px-5 py-3">
                        {move || context.t("Login.accessNexus")}
                    </a>
                </Show>
                <Show when=move || context.auth_loading.get()>
                    <p role="status" class="text-sm text-slate-400">{move || context.t("Common.loading")}</p>
                </Show>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <button
                        class="glass-button-primary px-5 py-3"
                        disabled=move || context.auth_loading.get() || busy.get() || invalid || denied_local.get()
                        on:click=move |_| consent(true)
                    >
                        {move || context.t("Consent.grant")}
                    </button>
                    <button
                        class="glass-button px-5 py-3"
                        disabled=move || context.auth_loading.get() || busy.get() || denied_local.get()
                        on:click=move |_| consent(false)
                    >
                        {move || context.t("Consent.deny")}
                    </button>
                </div>
                <a href="/" class="text-sm text-indigo-300">{move || context.t("Consent.return")}</a>
            </div>
        </main>
    }
}

#[cfg(test)]
mod tests {
    use super::{consent_decision, ConsentDecision};

    #[test]
    fn unauthenticated_denial_never_selects_an_external_redirect() {
        // Callback and state query parameters cannot affect this local action.
        assert_eq!(consent_decision(false, false), ConsentDecision::DenyLocally);
        assert_eq!(consent_decision(false, true), ConsentDecision::RequireLogin);
        assert_eq!(consent_decision(true, false), ConsentDecision::Submit);
        assert_eq!(consent_decision(true, true), ConsentDecision::Submit);
    }
}
