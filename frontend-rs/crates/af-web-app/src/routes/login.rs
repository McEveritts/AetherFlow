use crate::{
    shell::PublicRouteToolbar,
    state::{app, navigate, query_param, use_api},
};
use af_web_core::{
    api::{broadcast_login, ApiClient, ApiError},
    navigation::safe_login_return_to,
};
use af_web_ui::{EmptyState, QrCodeSvg};
use leptos::prelude::*;
use serde_json::json;
use wasm_bindgen_futures::spawn_local;

fn setup_password_is_valid(password: &str) -> bool {
    password.len() >= 8
}

fn login_error_message(error: ApiError, endpoint: &str) -> String {
    let message = error.message.to_lowercase();
    if error.code.as_deref() == Some("WEAK_PASSWORD")
        || (error.status == 400 && message == "password must be at least 8 characters")
    {
        "Password must be at least 8 characters".into()
    } else if error.code.as_deref() == Some("INVALID_CREDENTIALS")
        || (error.status == 401
            && matches!(endpoint, "/api/v1/auth/login" | "/api/v1/public/auth/login"))
        || message.contains("credentials")
        || message.contains("invalid username or password")
    {
        "Login.invalidCredentials".into()
    } else {
        error.message
    }
}

#[component]
pub fn LoginPage() -> impl IntoView {
    let context = app();
    let setup = use_api("/api/v1/public/auth/setup/check".to_string());
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let challenge = RwSignal::new(query_param("mfa").unwrap_or_default());
    let setup_mfa = RwSignal::new(false);
    let qr = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let authentication_error = StoredValue::new(
        query_param("error")
            .map(|error| error.replace('_', " "))
            .unwrap_or_default(),
    );
    let error = RwSignal::new(if authentication_error.with_value(String::is_empty) {
        String::new()
    } else {
        "Login.authenticationFailed".into()
    });
    let recovery = RwSignal::new(false);
    let destination = StoredValue::new(safe_login_return_to(
        &query_param("returnTo")
            .or_else(|| query_param("return_to"))
            .unwrap_or_else(|| "/".into()),
    ));
    // Challenges must not remain in history, referral URLs or copied login links.
    if let Some(window) = web_sys::window() {
        if let Ok(params) =
            web_sys::UrlSearchParams::new_with_str(&window.location().search().unwrap_or_default())
        {
            params.delete("mfa");
            params.delete("error");
            let query = String::from(params.to_string());
            let path = format!(
                "/login{}",
                if query.is_empty() {
                    String::new()
                } else {
                    format!("?{query}")
                }
            );
            if let Ok(history) = window.history() {
                let _ =
                    history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&path));
            }
        }
    }
    let finish = move || {
        broadcast_login();
        context.authenticated_at.set(js_sys::Date::now());
        navigate(&destination.get_value());
    };
    let submit = move |event: web_sys::SubmitEvent| {
        event.prevent_default();
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        error.set(String::new());
        let setup_required = setup
            .data
            .with_untracked(|v| v["setupRequired"].as_bool().unwrap_or(false));
        let mfa = challenge.get_untracked();
        let mfa_setup = setup_mfa.get_untracked();
        if setup_required
            && mfa.is_empty()
            && !mfa_setup
            && !setup_password_is_valid(&password.get_untracked())
        {
            error.set("Password must be at least 8 characters".into());
            busy.set(false);
            return;
        }
        let endpoint = if mfa_setup {
            "/api/v1/auth/user/2fa/verify"
        } else if !mfa.is_empty() {
            "/api/v1/public/auth/mfa/verify"
        } else if setup_required {
            "/api/v1/public/auth/setup"
        } else {
            "/api/v1/public/auth/login"
        };
        let body = if mfa_setup {
            json!({"code":code.get_untracked().trim()})
        } else if !mfa.is_empty() {
            json!({"mfa_token":mfa,"code":code.get_untracked().trim()})
        } else {
            json!({"username":username.get_untracked().trim(),"password":password.get_untracked()})
        };
        spawn_local(async move {
            match ApiClient.request(endpoint, "POST", Some(&body)).await {
                Ok(data) => {
                    password.set(String::new());
                    if data["requires_mfa"].as_bool() == Some(true) {
                        challenge.set(data["mfa_token"].as_str().unwrap_or_default().to_string());
                        code.set(String::new());
                    } else if data["requires_mfa_setup"].as_bool() == Some(true) {
                        setup_mfa.set(true);
                        match ApiClient.post("/api/v1/auth/user/2fa/setup", None).await {
                            Ok(data) => qr.set(
                                data["otpauth_uri"]
                                    .as_str()
                                    .or_else(|| data["otpauth_url"].as_str())
                                    .or_else(|| data["url"].as_str())
                                    .unwrap_or_default()
                                    .into(),
                            ),
                            Err(e) => {
                                error.set(login_error_message(e, "/api/v1/auth/user/2fa/setup"))
                            }
                        }
                    } else {
                        finish();
                    }
                }
                Err(e) => error.set(login_error_message(e, endpoint)),
            }
            busy.set(false);
        });
    };
    view! {
        <main id="main-content" tabindex="-1" class="af-public-route af-login min-h-screen grid place-items-center px-5 py-10">
            <PublicRouteToolbar/>
            <div class="w-full max-w-md min-w-0">
                <header class="text-center mb-8">
                    <div class="obs-brand-logo mx-auto w-20 h-20 flex items-center justify-center mb-5">
                        <img
                            src="/img/aetherflow-mark.svg"
                            alt=move || context.t("Common.logo")
                            class="obs-brand-mark w-16 h-16"
                        />
                    </div>
                    <p class="text-indigo-300 text-xs uppercase tracking-[.25em] mb-3">
                        {move || context.t("Routes.loginSubtitle")}
                    </p>
                    <h1 class="text-3xl font-semibold">
                        {move || context.t(if setup_mfa.get() {
                            "Login.secureAccount"
                        } else if !challenge.get().is_empty() {
                            "Login.verifyIdentity"
                        } else if setup.data.with(|value| value["setupRequired"] == true) {
                            "Login.createAdmin"
                        } else {
                            "Login.accessNexus"
                        })}
                    </h1>
                    <p class="text-slate-400 text-sm mt-3">{move || context.t("Login.tagline")}</p>
                </header>
                <div class="glass-card p-6 min-w-0">
                    <Show
                        when=move || !setup.loading.get()
                        fallback=move || view! { <p role="status">{move || context.t("Login.checking")}</p> }
                    >
                        <form on:submit=submit class="space-y-4">
                            <Show
                                when=move || challenge.get().is_empty() && !setup_mfa.get()
                                fallback=move || view! {
                                    <Show when=move || setup_mfa.get()>
                                        {move || view! { <QrCodeSvg payload=qr label=context.t("Login.scanAuthenticator")/> }}
                                    </Show>
                                    <label class="block text-sm text-slate-300" for="mfa-code">
                                        {move || context.t(if recovery.get() { "Login.recoveryCode" } else { "Login.authenticatorCode" })}
                                    </label>
                                    <input
                                        id="mfa-code"
                                        class="glass-input w-full px-3 py-3 font-mono tracking-widest"
                                        type="text"
                                        inputmode=move || if recovery.get() { "text" } else { "numeric" }
                                        autocomplete="one-time-code"
                                        placeholder=move || context.t(if recovery.get() { "Login.recoveryCode" } else { "Login.sixDigitCode" })
                                        required=true
                                        prop:value=move || code.get()
                                        on:input=move |event| code.set(event_target_value(&event))
                                    />
                                    <button
                                        type="button"
                                        class="text-indigo-300 text-sm"
                                        on:click=move |_| {
                                            recovery.update(|value| *value = !*value);
                                            code.set(String::new());
                                        }
                                    >
                                        {move || context.t(if recovery.get() { "Login.useAuthenticator" } else { "Login.useRecovery" })}
                                    </button>
                                }
                            >
                                <label class="block text-sm text-slate-300" for="username">
                                    {move || context.t("Login.username")}
                                </label>
                                <input
                                    id="username" type="text" required=true autocomplete="username"
                                    class="glass-input w-full px-3 py-3"
                                    placeholder=move || context.t(if setup.data.with(|value| value["setupRequired"] == true) {
                                        "Login.chooseUsername"
                                    } else { "Login.username" })
                                    prop:value=move || username.get()
                                    on:input=move |event| username.set(event_target_value(&event))
                                />
                                <label class="block text-sm text-slate-300" for="password">
                                    {move || context.t("Login.password")}
                                </label>
                                <input
                                    id="password" type="password" required=true
                                    autocomplete=move || if setup.data.with(|value| value["setupRequired"] == true) { "new-password" } else { "current-password" }
                                    class="glass-input w-full px-3 py-3"
                                    placeholder=move || context.t(if setup.data.with(|value| value["setupRequired"] == true) {
                                        "Login.choosePassword"
                                    } else { "Login.password" })
                                    prop:value=move || password.get()
                                    on:input=move |event| password.set(event_target_value(&event))
                                />
                            </Show>
                            <Show when=move || !error.get().is_empty()>
                                <p role="alert" class="text-rose-300 text-sm">{move || {
                                    let msg = error.get();
                                    if msg.is_empty() {
                                        String::new()
                                    } else if msg == "Login.authenticationFailed" {
                                        context.t_with(&msg, &[("error", &authentication_error.get_value())])
                                    } else {
                                        context.t(&msg)
                                    }
                                }}</p>
                            </Show>
                            <button
                                type="submit"
                                class="glass-button-primary w-full py-3 font-semibold"
                                disabled=move || busy.get()
                            >
                                {move || context.t(if busy.get() {
                                    "Login.verifying"
                                } else if !challenge.get().is_empty() || setup_mfa.get() {
                                    "Login.verifyEnter"
                                } else if setup.data.with(|value| value["setupRequired"] == true) {
                                    "Login.createEnter"
                                } else { "Login.unlock" })}
                            </button>
                        </form>
                        <Show when=move || setup.error.get().is_some()>
                            {move || view! {
                                <EmptyState title=context.t("Login.unavailable") description=context.t("Login.retryDescription")/>
                            }}
                            <button class="glass-button px-3" on:click=move |_| setup.refresh()>
                                {move || context.t("Common.retry")}
                            </button>
                        </Show>
                        <Show when=move || !setup.data.with(|value| value["setupRequired"] == true)
                            && challenge.get().is_empty() && !setup_mfa.get()>
                            <div class="border-t border-white/10 mt-6 pt-5 space-y-3">
                                <button
                                    type="button"
                                    class="glass-button w-full py-3"
                                    on:click=move |_| {
                                        let destination = destination.get_value();
                                        let query = if destination == "/" { String::new() } else {
                                            format!("?return_to={}", js_sys::encode_uri_component(&destination))
                                        };
                                        navigate(&format!("/api/v1/public/auth/google/login{query}"));
                                    }
                                >
                                    {move || context.t("Login.google")}
                                </button>
                            </div>
                        </Show>
                    </Show>
                </div>
                <p class="text-center text-xs text-slate-400 mt-6">{move || context.t("Login.footer")}</p>
            </div>
        </main>
    }
}

#[cfg(test)]
mod tests {
    use super::{login_error_message, setup_password_is_valid};
    use af_web_core::api::ApiError;

    #[test]
    fn setup_password_validation_matches_the_backend_utf8_byte_minimum() {
        for password in ["", "secret", "secrets", "密码", "密码a"] {
            assert!(!setup_password_is_valid(password), "{password:?}");
        }
        for password in ["password", "longer-password", "密码ab", "éééé", "🔐🔐"] {
            assert!(setup_password_is_valid(password), "{password:?}");
        }
    }

    #[test]
    fn weak_setup_password_errors_use_the_localized_validation_message() {
        for (code, message) in [
            (Some("WEAK_PASSWORD"), "Password is too short"),
            (
                Some("VALIDATION_ERROR"),
                "Password must be at least 8 characters",
            ),
            (None, "Password must be at least 8 characters"),
        ] {
            assert_eq!(
                login_error_message(
                    ApiError {
                        status: 400,
                        code: code.map(str::to_string),
                        message: message.into(),
                    },
                    "/api/v1/public/auth/setup",
                ),
                "Password must be at least 8 characters"
            );
        }
    }

    #[test]
    fn login_credentials_errors_use_the_translation_key_for_codes_status_and_messages() {
        for (status, code, message, endpoint) in [
            (
                400,
                Some("INVALID_CREDENTIALS"),
                "Access denied",
                "/api/v1/auth/login",
            ),
            (401, None, "Unauthorized", "/api/v1/auth/login"),
            (401, None, "Unauthorized", "/api/v1/public/auth/login"),
            (
                403,
                None,
                "CREDENTIALS rejected",
                "/api/v1/public/auth/mfa/verify",
            ),
            (
                400,
                None,
                "Invalid Username or Password",
                "/api/v1/public/auth/login",
            ),
        ] {
            assert_eq!(
                login_error_message(
                    ApiError {
                        status,
                        code: code.map(str::to_string),
                        message: message.into(),
                    },
                    endpoint
                ),
                "Login.invalidCredentials"
            );
        }
    }

    #[test]
    fn login_errors_preserve_mfa_setup_and_service_failure_messages() {
        for (status, message, endpoint) in [
            (
                401,
                "Invalid authenticator code",
                "/api/v1/public/auth/mfa/verify",
            ),
            (401, "Session expired", "/api/v1/auth/user/2fa/setup"),
            (503, "Service unavailable", "/api/v1/public/auth/login"),
            (
                401,
                "Setup is no longer available",
                "/api/v1/public/auth/setup",
            ),
        ] {
            assert_eq!(
                login_error_message(
                    ApiError {
                        status,
                        code: None,
                        message: message.into(),
                    },
                    endpoint
                ),
                message
            );
        }
    }
}
