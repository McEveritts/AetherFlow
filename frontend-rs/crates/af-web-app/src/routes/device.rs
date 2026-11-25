use crate::{
    shell::PublicRouteToolbar,
    state::{app, navigate, query_param},
};
use af_web_core::{
    api::{ApiClient, ApiError},
    navigation::safe_login_return_to,
};
use af_web_ui::{Badge, ObsCard};
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDeviceGrant {
    pub user_code: String,
    pub client_id: String,
    pub client_name: String,
    pub scope: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    pub critical: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DeviceDecisionOutcome {
    Approved { client_label: String },
    Denied { client_label: String },
}

pub fn normalize_user_code(input: &str) -> Result<String, &'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("OidcDevice.codeRequired");
    }
    if trimmed.len() > 16
        || trimmed.starts_with('-')
        || trimmed.ends_with('-')
        || trimmed.contains("--")
    {
        return Err("OidcDevice.invalidFormat");
    }
    let mut compact = String::with_capacity(8);
    for ch in trimmed.chars() {
        if ch == '-' || ch == ' ' {
            continue;
        }
        if !ch.is_ascii_alphanumeric() {
            return Err("OidcDevice.invalidFormat");
        }
        compact.push(ch.to_ascii_uppercase());
    }
    if compact.len() != 8 {
        return Err("OidcDevice.invalidFormat");
    }
    Ok(format!("{}-{}", &compact[..4], &compact[4..]))
}

fn scope_is_critical(scope: &str) -> bool {
    matches!(
        scope,
        "system:reboot" | "system:write" | "system:auth" | "system:shutdown" | "admin"
    )
}

fn scope_description_key(scope: &str) -> Option<&'static str> {
    match scope {
        "openid" => Some("OidcDevice.scopeOpenid"),
        "profile" => Some("OidcDevice.scopeProfile"),
        "email" => Some("OidcDevice.scopeEmail"),
        _ => None,
    }
}

pub fn parse_verified_grant(
    submitted_code: &str,
    data: &Value,
) -> Result<VerifiedDeviceGrant, &'static str> {
    if data["status"].as_str() != Some("pending") {
        return Err("OidcDevice.invalidCode");
    }
    let client_id = data["client_id"].as_str().unwrap_or_default().trim();
    if client_id.is_empty() {
        return Err("OidcDevice.invalidClient");
    }
    let client_name = data["client_name"]
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(client_id)
        .to_string();
    let scopes: Vec<String> = data["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if scopes.is_empty() {
        return Err("Consent.invalidRequest");
    }
    let scope = scopes.join(" ");
    let user_code = data["user_code"]
        .as_str()
        .and_then(|raw| normalize_user_code(raw).ok())
        .or_else(|| normalize_user_code(submitted_code).ok())
        .ok_or("OidcDevice.invalidFormat")?;
    let expires_at = data["expires_at"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let critical = scopes.iter().any(|s| scope_is_critical(s));
    Ok(VerifiedDeviceGrant {
        user_code,
        client_id: client_id.to_string(),
        client_name,
        scope,
        scopes,
        expires_at,
        critical,
    })
}

pub fn device_error_message(error: &ApiError) -> String {
    let raw = error
        .code
        .as_deref()
        .unwrap_or(error.message.as_str())
        .trim()
        .to_ascii_lowercase();
    let msg_lower = error.message.trim().to_ascii_lowercase();
    if raw == "expired_token" || msg_lower == "expired_token" {
        "OidcDevice.expiredCode".into()
    } else if raw == "invalid_user_code" || msg_lower == "invalid_user_code" {
        "OidcDevice.invalidCode".into()
    } else if raw == "invalid_client" || msg_lower == "invalid_client" {
        "OidcDevice.invalidClient".into()
    } else if msg_lower == "user_code is required" {
        "OidcDevice.codeRequired".into()
    } else if raw == "access_denied" || msg_lower == "access_denied" {
        "OidcDevice.accessDenied".into()
    } else if raw == "invalid_request" || msg_lower == "invalid_request" {
        "Consent.invalidRequest".into()
    } else {
        error.message.clone()
    }
}

fn should_reset_verified_grant(error: &ApiError) -> bool {
    let msg = error.message.trim().to_ascii_lowercase();
    let code = error
        .code
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    matches!(
        msg.as_str(),
        "expired_token" | "invalid_user_code" | "invalid_client" | "invalid_request"
    ) || matches!(
        code.as_str(),
        "expired_token" | "invalid_user_code" | "invalid_client" | "invalid_request"
    )
}

pub fn device_return_path(user_code: Option<&str>) -> String {
    let candidate = match user_code.map(str::trim).filter(|s| !s.is_empty()) {
        Some(code) => {
            let encoded: String = url::form_urlencoded::byte_serialize(code.as_bytes()).collect();
            format!("/oauth/device?user_code={encoded}")
        }
        None => "/oauth/device".into(),
    };
    let validated = safe_login_return_to(&candidate);
    if validated == "/" {
        "/oauth/device".into()
    } else {
        validated
    }
}

pub fn login_redirect_for_device(user_code: Option<&str>) -> String {
    let return_to = device_return_path(user_code);
    let encoded: String = url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect();
    format!("/login?returnTo={encoded}")
}

#[cfg(target_arch = "wasm32")]
fn sync_device_url_code(user_code: Option<&str>) {
    let target = device_return_path(user_code);
    if let Some(window) = web_sys::window() {
        if let Ok(history) = window.history() {
            let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&target));
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn sync_device_url_code(_user_code: Option<&str>) {}

#[component]
pub fn DevicePage() -> impl IntoView {
    let context = app();
    let initial_query_code = query_param("user_code").unwrap_or_default();
    let code_input = RwSignal::new(initial_query_code.clone());
    let verifying = RwSignal::new(false);
    let submitting = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let verified = RwSignal::new(None::<VerifiedDeviceGrant>);
    let outcome = RwSignal::new(None::<DeviceDecisionOutcome>);

    let run_verify = Callback::new(move |raw: String| {
        if verifying.get_untracked() || submitting.get_untracked() {
            return;
        }
        let normalized = match normalize_user_code(&raw) {
            Ok(code) => code,
            Err(key) => {
                verified.set(None);
                error.set(key.into());
                return;
            }
        };
        code_input.set(normalized.clone());
        sync_device_url_code(Some(&normalized));
        verifying.set(true);
        error.set(String::new());
        outcome.set(None);
        let body = json!({ "user_code": normalized });
        spawn_local(async move {
            match ApiClient
                .post("/api/v1/auth/oidc/device/verify", Some(&body))
                .await
            {
                Ok(data) => match parse_verified_grant(&normalized, &data) {
                    Ok(grant) => {
                        sync_device_url_code(Some(&grant.user_code));
                        code_input.set(grant.user_code.clone());
                        verified.set(Some(grant));
                        error.set(String::new());
                    }
                    Err(key) => {
                        verified.set(None);
                        error.set(key.into());
                    }
                },
                Err(api_err) => {
                    if api_err.status == 401 {
                        navigate(&login_redirect_for_device(Some(&normalized)));
                        return;
                    }
                    verified.set(None);
                    error.set(device_error_message(&api_err));
                }
            }
            verifying.set(false);
        });
    });

    if !initial_query_code.trim().is_empty() {
        let initial = initial_query_code.clone();
        Effect::new(move |ran: Option<bool>| {
            if ran == Some(true) {
                return true;
            }
            run_verify.run(initial.clone());
            true
        });
    }

    let on_verify_submit = move |event: web_sys::SubmitEvent| {
        event.prevent_default();
        run_verify.run(code_input.get_untracked());
    };

    let decide = move |approved: bool| {
        if submitting.get_untracked() || verifying.get_untracked() {
            return;
        }
        let Some(grant) = verified.get_untracked() else {
            return;
        };
        submitting.set(true);
        error.set(String::new());
        let body = json!({
            "user_code": grant.user_code,
            "client_id": grant.client_id,
            "scope": grant.scope,
            "approved": approved,
        });
        let client_label = grant.client_name.clone();
        let fallback_code = grant.user_code.clone();
        spawn_local(async move {
            match ApiClient
                .post("/api/v1/auth/oidc/device/consent", Some(&body))
                .await
            {
                Ok(data) => {
                    let status = data["status"].as_str().unwrap_or(if approved {
                        "approved"
                    } else {
                        "denied"
                    });
                    sync_device_url_code(None);
                    verified.set(None);
                    code_input.set(String::new());
                    outcome.set(Some(if status == "approved" {
                        DeviceDecisionOutcome::Approved { client_label }
                    } else {
                        DeviceDecisionOutcome::Denied { client_label }
                    }));
                }
                Err(api_err) => {
                    if api_err.status == 401 {
                        navigate(&login_redirect_for_device(Some(&fallback_code)));
                        return;
                    }
                    if should_reset_verified_grant(&api_err) {
                        verified.set(None);
                        sync_device_url_code(None);
                    }
                    error.set(device_error_message(&api_err));
                }
            }
            submitting.set(false);
        });
    };

    view! {
        <main id="main-content" tabindex="-1" class="af-public-route min-h-screen px-5 py-12 grid place-items-center">
            <PublicRouteToolbar/>
            <div class="w-full max-w-xl min-w-0 space-y-6">
                <header class="space-y-2">
                    <p class="text-indigo-300 text-xs tracking-widest uppercase">
                        {move || context.t("Consent.subtitle")}
                    </p>
                    <h1 class="text-2xl font-semibold">
                        {move || context.t("Routes.deviceHeading")}
                    </h1>
                    {move || {
                        context.typed_user().map(|user| {
                            view! {
                                <p class="text-xs text-slate-400">
                                    {context.t_with("OidcDevice.signedInAs", &[("username", &user.username)])}
                                </p>
                            }
                        })
                    }}
                </header>

                <Show when=move || !error.get().is_empty()>
                    <p role="alert" class="af-danger-banner">
                        {move || {
                            let key = error.get();
                            if key.is_empty() {
                                String::new()
                            } else {
                                context.t(&key)
                            }
                        }}
                    </p>
                </Show>

                {move || {
                    if let Some(done) = outcome.get() {
                        let (is_approved, client_label) = match done {
                            DeviceDecisionOutcome::Approved { client_label } => (true, client_label),
                            DeviceDecisionOutcome::Denied { client_label } => (false, client_label),
                        };
                        view! {
                            <ObsCard>
                                <div role="status" class="space-y-4">
                                    <div class="flex items-center gap-2 flex-wrap">
                                        <Badge
                                            label=context.t(if is_approved {
                                                "OidcDevice.approvedTitle"
                                            } else {
                                                "OidcDevice.deniedTitle"
                                            })
                                            tone=if is_approved { "success" } else { "danger" }
                                        />
                                    </div>
                                    <p class="text-sm text-slate-300">
                                        {context.t_with(
                                            if is_approved {
                                                "OidcDevice.approvedDescription"
                                            } else {
                                                "OidcDevice.deniedDescription"
                                            },
                                            &[("client", &client_label)],
                                        )}
                                    </p>
                                    <div class="flex flex-wrap gap-3 pt-2">
                                        <button
                                            type="button"
                                            class="af-btn px-4 py-2.5 text-sm"
                                            on:click=move |_| {
                                                outcome.set(None);
                                                error.set(String::new());
                                                code_input.set(String::new());
                                                sync_device_url_code(None);
                                            }
                                        >
                                            {move || context.t("OidcDevice.authorizeAnother")}
                                        </button>
                                        <a href="/" class="af-btn-primary px-4 py-2.5 text-sm inline-flex items-center">
                                            {move || context.t("Consent.return")}
                                        </a>
                                    </div>
                                </div>
                            </ObsCard>
                        }
                        .into_any()
                    } else if let Some(grant) = verified.get() {
                        let grant_client_name = grant.client_name.clone();
                        let grant_client_id = grant.client_id.clone();
                        let grant_code = grant.user_code.clone();
                        let grant_scopes = grant.scopes.clone();
                        let grant_critical = grant.critical;
                        view! {
                            <div class="space-y-5">
                                <p class="text-slate-300">
                                    <strong class="text-indigo-200">{grant_client_name}</strong>
                                    {move || context.t("Consent.requestingAccess")}
                                </p>
                                {grant_critical.then(|| view! {
                                    <div role="alert" class="af-danger-banner">
                                        <strong>{move || context.t("Consent.critical")}</strong>
                                        <p class="mt-1">{move || context.t("Consent.criticalDescription")}</p>
                                    </div>
                                })}
                                <ObsCard title=Signal::derive(move || context.t("Consent.scopes"))>
                                    <dl class="grid grid-cols-1 sm:grid-cols-2 gap-3 pb-4 mb-4 border-b border-white/10 text-sm">
                                        <div>
                                            <dt class="text-xs text-slate-400">{move || context.t("OidcDevice.clientIdLabel")}</dt>
                                            <dd class="font-mono text-slate-200 break-all mt-1">{grant_client_id}</dd>
                                        </div>
                                        <div>
                                            <dt class="text-xs text-slate-400">{move || context.t("OidcDevice.confirmedCodeLabel")}</dt>
                                            <dd class="font-mono text-indigo-200 tracking-wider mt-1">{grant_code}</dd>
                                        </div>
                                    </dl>
                                    <ul class="divide-y divide-white/10">
                                        {grant_scopes
                                            .into_iter()
                                            .map(|scope| {
                                                let desc_key = scope_description_key(&scope);
                                                view! {
                                                    <li class="py-3 flex flex-col gap-1">
                                                        <span class="font-mono text-sm text-slate-100 break-all">{scope}</span>
                                                        {desc_key.map(|key| view! {
                                                            <span class="text-xs text-slate-400">{move || context.t(key)}</span>
                                                        })}
                                                    </li>
                                                }
                                            })
                                            .collect_view()}
                                    </ul>
                                </ObsCard>
                                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                    <button
                                        type="button"
                                        class="af-btn-primary px-5 py-3 font-semibold"
                                        disabled=move || submitting.get() || verifying.get()
                                        on:click=move |_| decide(true)
                                    >
                                        {move || context.t(if submitting.get() {
                                            "OidcDevice.submitting"
                                        } else {
                                            "OidcDevice.allow"
                                        })}
                                    </button>
                                    <button
                                        type="button"
                                        class="af-btn px-5 py-3"
                                        disabled=move || submitting.get() || verifying.get()
                                        on:click=move |_| decide(false)
                                    >
                                        {move || context.t("Consent.deny")}
                                    </button>
                                </div>
                                <div class="flex flex-wrap items-center justify-between gap-3">
                                    <button
                                        type="button"
                                        class="text-sm text-slate-400 hover:text-slate-200"
                                        disabled=move || submitting.get()
                                        on:click=move |_| {
                                            verified.set(None);
                                            error.set(String::new());
                                            sync_device_url_code(None);
                                        }
                                    >
                                        {move || context.t("OidcDevice.useDifferentCode")}
                                    </button>
                                    <a href="/" class="text-sm text-indigo-300">{move || context.t("Consent.return")}</a>
                                </div>
                            </div>
                        }
                        .into_any()
                    } else {
                        view! {
                            <ObsCard>
                                <form on:submit=on_verify_submit class="space-y-4">
                                    <p class="text-sm text-slate-300">
                                        {move || context.t("OidcDevice.instructions")}
                                    </p>
                                    <div>
                                        <label class="block text-sm text-slate-300 mb-2" for="device-user-code">
                                            {move || context.t("OidcDevice.codeLabel")}
                                        </label>
                                        <input
                                            id="device-user-code"
                                            type="text"
                                            class="af-input w-full px-4 py-3 font-mono text-lg tracking-widest uppercase"
                                            placeholder="BCDF-2345"
                                            autocomplete="off"
                                            autocapitalize="characters"
                                            spellcheck="false"
                                            maxlength="16"
                                            required=true
                                            prop:value=move || code_input.get()
                                            on:input=move |event| {
                                                let next = event_target_value(&event);
                                                if let Ok(normalized) = normalize_user_code(&next) {
                                                    sync_device_url_code(Some(&normalized));
                                                }
                                                code_input.set(next);
                                            }
                                        />
                                    </div>
                                    <button
                                        type="submit"
                                        class="af-btn-primary w-full py-3 font-semibold"
                                        disabled=move || verifying.get() || submitting.get()
                                    >
                                        {move || context.t(if verifying.get() {
                                            "OidcDevice.verifying"
                                        } else {
                                            "OidcDevice.verifyButton"
                                        })}
                                    </button>
                                </form>
                                <div class="mt-4 pt-4 border-t border-white/10">
                                    <a href="/" class="text-sm text-indigo-300">{move || context.t("Consent.return")}</a>
                                </div>
                            </ObsCard>
                        }
                        .into_any()
                    }
                }}
            </div>
        </main>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_user_code_validates_and_formats_short_codes() {
        for (raw, expected) in [
            ("BCDF-2345", "BCDF-2345"),
            ("bcdf-2345", "BCDF-2345"),
            ("bcdf2345", "BCDF-2345"),
            ("  wxyz 6789 ", "WXYZ-6789"),
        ] {
            assert_eq!(
                normalize_user_code(raw),
                Ok(expected.to_string()),
                "{raw:?}"
            );
        }
        assert_eq!(normalize_user_code(""), Err("OidcDevice.codeRequired"));
        assert_eq!(normalize_user_code("   "), Err("OidcDevice.codeRequired"));
        for bad in [
            "BCDF",
            "BCDF-234",
            "BCDF-23456",
            "-BCDF2345",
            "BCDF2345-",
            "BCDF--2345",
            "BCDF_2345",
            "BCDF/2345",
            "0123456789ABCDEFG",
        ] {
            assert_eq!(
                normalize_user_code(bad),
                Err("OidcDevice.invalidFormat"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn parse_verified_grant_requires_server_confirmed_pending_client_and_scopes() {
        let valid = parse_verified_grant(
            "bcdf2345",
            &json!({
                "status": "pending",
                "user_code": "BCDF-2345",
                "client_id": "jellyfin-tv",
                "client_name": "Jellyfin Living Room",
                "scope": "openid profile email",
                "expires_at": "2026-11-19T08:00:00Z"
            }),
        )
        .unwrap();
        assert_eq!(valid.user_code, "BCDF-2345");
        assert_eq!(valid.client_id, "jellyfin-tv");
        assert_eq!(valid.client_name, "Jellyfin Living Room");
        assert_eq!(valid.scopes, vec!["openid", "profile", "email"]);
        assert!(!valid.critical);

        let fallback_name = parse_verified_grant(
            "BCDF-2345",
            &json!({
                "status": "pending",
                "client_id": "cli-tool",
                "client_name": " ",
                "scope": "openid admin"
            }),
        )
        .unwrap();
        assert_eq!(fallback_name.client_name, "cli-tool");
        assert!(fallback_name.critical);

        assert_eq!(
            parse_verified_grant(
                "BCDF-2345",
                &json!({"status": "approved", "client_id": "c", "scope": "openid"})
            ),
            Err("OidcDevice.invalidCode")
        );
        assert_eq!(
            parse_verified_grant(
                "BCDF-2345",
                &json!({"status": "pending", "client_id": "", "scope": "openid"})
            ),
            Err("OidcDevice.invalidClient")
        );
        assert_eq!(
            parse_verified_grant(
                "BCDF-2345",
                &json!({"status": "pending", "client_id": "c", "scope": "   "})
            ),
            Err("Consent.invalidRequest")
        );
    }

    #[test]
    fn device_error_mapping_and_return_routes_are_safe_and_explicit() {
        for (msg, expected, resets) in [
            ("expired_token", "OidcDevice.expiredCode", true),
            ("invalid_user_code", "OidcDevice.invalidCode", true),
            ("invalid_client", "OidcDevice.invalidClient", true),
            ("invalid_request", "Consent.invalidRequest", true),
            ("user_code is required", "OidcDevice.codeRequired", false),
            ("access_denied", "OidcDevice.accessDenied", false),
        ] {
            let err = ApiError {
                status: 400,
                message: msg.into(),
                code: None,
            };
            assert_eq!(device_error_message(&err), expected, "{msg}");
            assert_eq!(should_reset_verified_grant(&err), resets, "{msg}");
        }
        assert_eq!(
            device_return_path(Some("BCDF-2345")),
            "/oauth/device?user_code=BCDF-2345"
        );
        assert_eq!(device_return_path(None), "/oauth/device");
        assert_eq!(
            login_redirect_for_device(Some("BCDF-2345")),
            "/login?returnTo=%2Foauth%2Fdevice%3Fuser_code%3DBCDF-2345"
        );
    }
}
