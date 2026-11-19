use super::*;
use serde::Deserialize;

const MAX_AVATAR_URI_BYTES: usize = 2 * 1024 * 1024;

fn avatar_prefix(mime: &str) -> Option<&'static str> {
    match mime {
        "image/png" => Some("data:image/png;base64,"),
        "image/jpeg" | "image/jpg" => Some("data:image/jpeg;base64,"),
        "image/webp" => Some("data:image/webp;base64,"),
        "image/gif" => Some("data:image/gif;base64,"),
        _ => None,
    }
}

fn avatar_fits(mime: &str, size: usize) -> bool {
    avatar_prefix(mime).is_some_and(|prefix| {
        size > 0
            && size
                .checked_add(2)
                .and_then(|n| (n / 3).checked_mul(4))
                .and_then(|n| n.checked_add(prefix.len()))
                .is_some_and(|n| n <= MAX_AVATAR_URI_BYTES)
    })
}

fn avatar_data_uri(mime: &str, bytes: &[u8]) -> Option<String> {
    let prefix = avatar_prefix(mime)?;
    if !avatar_fits(mime, bytes.len()) {
        return None;
    }
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(prefix.len() + bytes.len().div_ceil(3) * 4);
    result.push_str(prefix);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        result.push(ALPHABET[(a >> 2) as usize] as char);
        result.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        result.push(if chunk.len() > 1 {
            ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            ALPHABET[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    Some(result)
}

fn safe_avatar_url(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_AVATAR_URI_BYTES
        || value.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return false;
    }
    if value.starts_with('/') {
        return !value.starts_with("//") && !value.starts_with("/\\") && !value.contains("..");
    }
    if [
        "data:image/png;base64,",
        "data:image/jpeg;base64,",
        "data:image/jpg;base64,",
        "data:image/webp;base64,",
        "data:image/gif;base64,",
    ]
    .iter()
    .any(|prefix| {
        value
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            && value[prefix.len()..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            && value.len() > prefix.len()
    }) {
        return true;
    }
    url::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

#[cfg(test)]
mod avatar_tests {
    use super::*;

    #[test]
    fn upload_contract_checks_encoded_size_and_raster_types() {
        for mime in ["image/png", "image/jpeg", "image/webp", "image/gif"] {
            let prefix = avatar_prefix(mime).unwrap();
            let limit = ((MAX_AVATAR_URI_BYTES - prefix.len()) / 4) * 3;
            assert!(avatar_fits(mime, limit));
            assert!(!avatar_fits(mime, limit + 1));
            assert!(!avatar_fits(mime, 0));
        }
        assert!(!avatar_fits("image/svg+xml", 10));
        assert_eq!(
            avatar_data_uri("image/png", &[0xff, 0xee, 0xdd, 0xcc]).unwrap(),
            "data:image/png;base64,/+7dzA=="
        );
    }

    #[test]
    fn avatar_display_rejects_active_content_and_unsafe_urls() {
        assert!(safe_avatar_url("/avatar.png"));
        assert!(safe_avatar_url("https://example.com/avatar.png"));
        assert!(safe_avatar_url("data:image/png;base64,YQ=="));
        assert!(safe_avatar_url("DATA:IMAGE/PNG;BASE64,YQ=="));
        for uri in [
            "javascript:alert(1)",
            "data:image/svg+xml;base64,YQ==",
            "//evil.example/a",
            "/../a",
            "https://u:p@example.com/a",
            "data:image/png;base64,",
        ] {
            assert!(!safe_avatar_url(uri), "{uri}");
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct PersonalQuotaContract {
    #[serde(deserialize_with = "crate::tabs::contracts::number")]
    quota_bytes: Option<f64>,
    #[serde(deserialize_with = "crate::tabs::contracts::number")]
    used_bytes: Option<f64>,
    #[serde(deserialize_with = "crate::tabs::contracts::number")]
    available_bytes: Option<f64>,
    #[serde(deserialize_with = "crate::tabs::contracts::number")]
    usage_pct: Option<f64>,
    configured: Option<bool>,
    #[serde(deserialize_with = "crate::tabs::contracts::string")]
    status: String,
    #[serde(deserialize_with = "crate::tabs::contracts::string")]
    source: String,
    #[serde(deserialize_with = "crate::tabs::contracts::string")]
    updated_at: String,
    #[serde(rename = "usedGB", deserialize_with = "crate::tabs::contracts::number")]
    used_gb: Option<f64>,
    #[serde(
        rename = "totalGB",
        deserialize_with = "crate::tabs::contracts::number"
    )]
    total_gb: Option<f64>,
    #[serde(deserialize_with = "crate::tabs::contracts::number")]
    percentage: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct PersonalQuotaSummary {
    pub used_bytes: f64,
    pub quota_bytes: f64,
    pub available_bytes: f64,
    pub percentage: f64,
    pub configured: bool,
    pub status: String,
    pub source: String,
    pub updated_at: String,
}

pub(super) fn summarize_personal_quota(value: &Value) -> Option<PersonalQuotaSummary> {
    if !value.is_object() {
        return None;
    }
    let parsed: PersonalQuotaContract = serde_json::from_value(value.clone()).ok()?;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let used_bytes = parsed
        .used_bytes
        .or_else(|| parsed.used_gb.map(|gb| gb * GIB))
        .unwrap_or(0.0)
        .max(0.0);
    let quota_bytes = parsed
        .quota_bytes
        .or_else(|| parsed.total_gb.map(|gb| gb * GIB))
        .unwrap_or(0.0)
        .max(0.0);
    let configured = parsed.configured.unwrap_or(quota_bytes > 0.0) && quota_bytes > 0.0;
    let available_bytes = parsed
        .available_bytes
        .unwrap_or_else(|| {
            if configured {
                (quota_bytes - used_bytes).max(0.0)
            } else {
                0.0
            }
        })
        .max(0.0);
    let percentage = parsed
        .usage_pct
        .or(parsed.percentage)
        .unwrap_or_else(|| {
            if configured {
                (used_bytes / quota_bytes) * 100.0
            } else {
                0.0
            }
        })
        .max(0.0);
    let status = if parsed.status.trim().is_empty() {
        "active".to_string()
    } else {
        parsed.status
    };
    let source = if parsed.source.trim().is_empty() {
        "manual".to_string()
    } else {
        parsed.source
    };
    Some(PersonalQuotaSummary {
        used_bytes,
        quota_bytes,
        available_bytes,
        percentage,
        configured,
        status,
        source,
        updated_at: parsed.updated_at,
    })
}

#[cfg(test)]
mod quota_tests {
    use super::*;

    #[test]
    fn personal_quota_summary_handles_configured_unconfigured_and_gb_fallbacks() {
        assert!(summarize_personal_quota(&Value::Null).is_none());

        let configured = summarize_personal_quota(&json!({
            "user_id": 7,
            "username": "alice",
            "quota_bytes": 10_737_418_240_i64,
            "used_bytes": 2_147_483_648_i64,
            "available_bytes": 8_589_934_592_i64,
            "usage_pct": 20.0,
            "configured": true,
            "status": "active",
            "source": "runner",
            "updated_at": "2026-11-19T05:00:00Z"
        }))
        .unwrap();
        assert!(configured.configured);
        assert_eq!(configured.percentage, 20.0);
        assert_eq!(configured.status, "active");
        assert_eq!(configured.source, "runner");
        assert_eq!(bytes(configured.used_bytes), "2.0 GiB");
        assert_eq!(bytes(configured.quota_bytes), "10.0 GiB");

        let unconfigured = summarize_personal_quota(&json!({
            "user_id": 7,
            "username": "alice",
            "quota_bytes": 0,
            "used_bytes": 536_870_912_i64,
            "configured": false
        }))
        .unwrap();
        assert!(!unconfigured.configured);
        assert_eq!(unconfigured.percentage, 0.0);
        assert_eq!(unconfigured.status, "active");
        assert_eq!(unconfigured.source, "manual");

        let legacy = summarize_personal_quota(&json!({
            "usedGB": 1.5,
            "totalGB": 3.0,
            "percentage": 50.0
        }))
        .unwrap();
        assert!(legacy.configured);
        assert_eq!(legacy.percentage, 50.0);
    }
}

#[component]
pub(super) fn ProfileSecurity() -> impl IntoView {
    let context = app();
    let draft = RwSignal::new(FormDraft::new(
        json!({"email":"","current_password":"","new_password":"","confirm_password":"","code":"","password":""}),
    ));
    let busy = RwSignal::new(false);
    let avatar_busy = RwSignal::new(false);
    let update_avatar = move |file: Option<web_sys::File>| {
        if avatar_busy.get_untracked() {
            return;
        }
        if let Some(file) = &file {
            if avatar_prefix(&file.type_()).is_none() {
                context.toast(tt(context, "Choose a PNG, JPEG, WEBP, or GIF image."), true);
                return;
            }
            if !avatar_fits(&file.type_(), file.size() as usize) {
                context.toast(
                    tt(context, "Avatar encoded size must not exceed 2 MiB."),
                    true,
                );
                return;
            }
        }
        let Some(user_id) = context.user.with_untracked(|user| {
            user.as_ref()
                .and_then(|user| user.get("id"))
                .filter(|id| !id.is_null())
                .cloned()
        }) else {
            return;
        };
        let epoch = context.session_epoch.get_untracked();
        let auth_epoch = af_web_core::api::current_auth_epoch();
        avatar_busy.set(true);
        let mut guard = crate::tabs::busy::BusyGuard::new(avatar_busy);
        spawn_local(async move {
            let still_owned = || {
                avatar_busy.try_get_untracked().is_some()
                    && context.session_epoch.try_get_untracked() == Some(epoch)
                    && af_web_core::api::current_auth_epoch() == auth_epoch
                    && context
                        .user
                        .try_with_untracked(|user| {
                            user.as_ref().and_then(|user| user.get("id")) == Some(&user_id)
                        })
                        .unwrap_or(false)
            };
            let result: Result<(), String> = async {
                if let Some(file) = file {
                    let buffer = JsFuture::from(file.array_buffer())
                        .await
                        .map_err(|_| "Could not read avatar image".to_string())?;
                    if !still_owned() {
                        return Ok(());
                    }
                    let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
                    let data = avatar_data_uri(&file.type_(), &bytes)
                        .ok_or_else(|| "Avatar encoded size must not exceed 2 MiB.".to_string())?;
                    ApiClient
                        .put("/api/v1/auth/profile/avatar", Some(&json!({"avatar":data})))
                        .await
                        .map_err(|e| e.message)?;
                } else {
                    if !still_owned() {
                        return Ok(());
                    }
                    ApiClient
                        .delete("/api/v1/auth/profile/avatar", None)
                        .await
                        .map_err(|e| e.message)?;
                }
                if still_owned() {
                    context.refresh_session();
                    context.toast(tt(context, "Avatar updated"), false);
                }
                Ok(())
            }
            .await;
            if still_owned() {
                if let Err(error) = result {
                    context.toast(tt(context, &error), true);
                }
            }
            guard.release();
        });
    };
    let sessions = use_api("/api/v1/auth/sessions".to_string());
    poll_resource(sessions, 30_000);
    let quota = use_api("/api/v1/auth/user/quota".to_string());
    poll_resource(quota, 30_000);
    let enrollment = RwSignal::new(Value::Null);
    let enroll_open = RwSignal::new(false);
    let recovery = RwSignal::new(Vec::<Value>::new());
    let recovery_open = RwSignal::new(false);
    let disable = RwSignal::new(false);
    Effect::new(move |_| {
        let user = context.user.get();
        if let Some(user) = user {
            let mut baseline = draft.with_untracked(|d| d.baseline().clone());
            baseline["email"] = user["email"].clone();
            draft.update(|d| d.apply_server_refresh(baseline));
        }
    });
    Effect::new(move |_| {
        if !enroll_open.get() {
            enrollment.set(Value::Null);
            edit(draft, "code", json!(""));
        }
        if !recovery_open.get() {
            recovery.set(vec![]);
        }
    });
    let mutate = move |action: &'static str| {
        if busy.get_untracked() {
            return;
        }
        let sent = draft_value(draft);
        if action == "password"
            && (text(&sent, "new_password").len() < 8
                || sent["new_password"] != sent["confirm_password"])
        {
            context.toast(
                tt(
                    context,
                    "Use a matching password with at least 8 characters",
                ),
                true,
            );
            return;
        }
        if action == "verify"
            && (text(&sent, "code").len() != 6
                || !text(&sent, "code").chars().all(|c| c.is_ascii_digit()))
        {
            context.toast(tt(context, "Enter the six-digit authenticator code"), true);
            return;
        }
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            let (path, method, payload) = match action {
                "profile" => (
                    "/api/v1/auth/profile",
                    "PUT",
                    json!({"email":sent["email"]}),
                ),
                "password" => (
                    "/api/v1/auth/profile/password",
                    "PUT",
                    json!({"current_password":sent["current_password"],"new_password":sent["new_password"]}),
                ),
                "setup" => ("/api/v1/auth/user/2fa/setup", "POST", Value::Null),
                "verify" => (
                    "/api/v1/auth/user/2fa/verify",
                    "POST",
                    json!({"code":sent["code"]}),
                ),
                "disable" => (
                    "/api/v1/auth/user/2fa/disable",
                    "POST",
                    json!({"code":sent["code"],"password":sent["password"]}),
                ),
                _ => (
                    "/api/v1/auth/user/2fa/recovery/regenerate",
                    "POST",
                    json!({"code":sent["code"],"password":sent["password"]}),
                ),
            };
            let result = ApiClient
                .request(path, method, (!payload.is_null()).then_some(&payload))
                .await;
            if busy.try_get_untracked().is_none() {
                return;
            }
            match result {
                Ok(value) => {
                    if action == "setup" {
                        enrollment.set(value);
                        enroll_open.set(true);
                    } else {
                        let mut baseline = draft.with_untracked(|d| d.baseline().clone());
                        let fields: &[&str] = match action {
                            "profile" => &["email"],
                            "password" => &["current_password", "new_password", "confirm_password"],
                            _ => &["code", "password"],
                        };
                        let mut acknowledged = baseline.clone();
                        for field in fields {
                            acknowledged[*field] = sent[*field].clone();
                            baseline[*field] = if *field == "email" {
                                sent[*field].clone()
                            } else {
                                json!("")
                            };
                        }
                        draft.update(|d| {
                            let _ = d.acknowledge_saved(&acknowledged, baseline);
                        });
                        if action == "verify" || action == "regenerate" {
                            recovery.set(
                                value["recovery_codes"]
                                    .as_array()
                                    .cloned()
                                    .unwrap_or_default(),
                            );
                            recovery_open.set(true);
                            enroll_open.set(false);
                        }
                        disable.set(false);
                        context.refresh_session();
                        sessions.refresh();
                        context.toast(
                            tt(
                                context,
                                value["message"].as_str().unwrap_or("Account updated"),
                            ),
                            false,
                        );
                    }
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            busy_guard.release();
        });
    };
    let revoke = move |session: Value| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            match ApiClient
                .delete(
                    &format!("/api/v1/auth/sessions/{}", encode(&text(&session, "jti"))),
                    None,
                )
                .await
            {
                Ok(_) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    sessions.refresh();
                    context.toast(tt(context, "Session family revoked"), false);
                    if session["is_current"] == true {
                        context.refresh_session();
                    }
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy_guard.release();
            }
        });
    };
    let other_sessions = Memo::new(move |_| {
        sessions.data.with(|v| {
            v["sessions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|s| s["is_current"] == false)
                .filter_map(|s| {
                    s["jti"]
                        .as_str()
                        .filter(|id| !id.is_empty())
                        .map(str::to_owned)
                })
                .collect::<Vec<_>>()
        })
    });
    let revoke_others = move |_| {
        if busy.get_untracked() {
            return;
        }
        let ids = other_sessions.get_untracked();
        let epoch = context.session_epoch.get_untracked();
        busy.set(true);
        let mut guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            for id in ids {
                if busy.try_get_untracked().is_none()
                    || context.session_epoch.try_get_untracked() != Some(epoch)
                {
                    return;
                }
                if let Err(error) = ApiClient
                    .delete(&format!("/api/v1/auth/sessions/{}", encode(&id)), None)
                    .await
                {
                    context.toast(error.message, true);
                    break;
                }
            }
            if busy.try_get_untracked().is_some() {
                sessions.refresh();
                guard.release();
            }
        });
    };
    view! {
        <ObsCard title=Signal::derive(move || tt(context, "Settings.profileSecurity"))>
            <div class="flex flex-wrap items-center gap-4 mb-4">
                {move || {
                    let avatar = context.user.with(|user| user.as_ref().map(|user| text(user, "avatar_url")).unwrap_or_default());
                    if safe_avatar_url(&avatar) {
                        view! { <img src=avatar alt=move || tt(context, "Profile avatar") class="h-20 w-20 rounded-xl object-cover border border-white/10" /> }.into_any()
                    } else {
                        view! { <div role="img" aria-label=move || tt(context, "Profile avatar") class="h-20 w-20 rounded-xl border border-white/10 flex items-center justify-center text-xl">
                            {move || context.user.with(|user| user.as_ref().and_then(|user| text(user, "username").chars().next()).map(|c| c.to_uppercase().to_string()).unwrap_or_default())}
                        </div> }.into_any()
                    }
                }}
                <div class="flex flex-wrap gap-2 items-center">
                    <label class="glass-button px-4 py-2 cursor-pointer">
                        {move || tt(context, "Upload avatar")}
                        <input type="file" accept="image/png,image/jpeg,image/webp,image/gif" class="block mt-2 max-w-full" disabled=move || avatar_busy.get()
                            on:change=move |event| {
                                let input = event_target::<web_sys::HtmlInputElement>(&event);
                                if let Some(file) = input.files().and_then(|files| files.get(0)) { update_avatar(Some(file)); }
                                input.set_value("");
                            } />
                    </label>
                    <button type="button" class="glass-button px-4 py-2" disabled=move || avatar_busy.get() || context.user.with(|user| user.as_ref().is_none_or(|user| text(user, "avatar_url").is_empty()))
                        on:click=move |_| update_avatar(None)>{move || tt(context, "Remove avatar")}</button>
                </div>
            </div>
            <p class="text-sm text-slate-400 mb-5">
                {move || {
                    context
                        .user
                        .with(|u| {
                            u.as_ref()
                                .map(|u| format!("{} · {}", text(u, "username"), text(u, "role")))
                                .unwrap_or_default()
                        })
                }}
            </p>
            <form
                class="space-y-4"
                on:submit=move |e| {
                    e.prevent_default();
                    mutate("profile");
                }
            >
                <DraftInput draft field="email" label="Email address" kind="email" required=true />
                <button
                    type="submit"
                    class="glass-button-primary px-4 py-2"
                    disabled=move || busy.get()
                >
                    {move || tt(context, "Update profile")}
                </button>
            </form>
            <form
                class="grid sm:grid-cols-3 gap-4 mt-6"
                on:submit=move |e| {
                    e.prevent_default();
                    mutate("password");
                }
            >
                <DraftInput
                    draft
                    field="current_password"
                    label="Current password"
                    kind="password"
                    required=true
                />
                <DraftInput
                    draft
                    field="new_password"
                    label="New password"
                    kind="password"
                    required=true
                />
                <DraftInput
                    draft
                    field="confirm_password"
                    label="Confirm new password"
                    kind="password"
                    required=true
                />
                <button type="submit" class="glass-button px-4 py-2" disabled=move || busy.get()>
                    {move || tt(context, "Update password")}
                </button>
            </form>
        </ObsCard>
        <ObsCard title=Signal::derive(move || tt(context, "Settings.twoFactorAuthentication"))>
            <p class="text-sm mb-4">
                {move || tt(context, if context
                        .user
                        .with(|u| {
                            u.as_ref()
                                .is_some_and(|u| {
                                    u["totp_enabled"] == true || u["totp_enabled"] == 1
                                })
                        })
                    {
                        "TOTP enabled"
                    } else {
                        "TOTP not enabled"
                    })}
            </p>
            <div class="flex flex-wrap gap-3">
                <button
                    type="button"
                    class="glass-button-primary px-4 py-2"
                    disabled=move || busy.get()
                    on:click=move |_| mutate("setup")
                >
                    {move || tt(context, "Enroll authenticator")}
                </button>
                <button
                    type="button"
                    class="glass-button px-4 py-2"
                    on:click=move |_| disable.set(true)
                >
                    {move || tt(context, "Disable TOTP")}
                </button>
            </div>
            <div class="grid sm:grid-cols-2 gap-4 mt-5">
                <DraftInput draft field="code" label="Authenticator or recovery code" />
                <DraftInput
                    draft
                    field="password"
                    label="Password for security changes"
                    kind="password"
                />
            </div>
            <button
                type="button"
                class="glass-button px-4 py-2 mt-4"
                disabled=move || busy.get()
                on:click=move |_| mutate("regenerate")
            >
                {move || tt(context, "Regenerate recovery codes")}
            </button>
        </ObsCard>
        <section aria-label=move || tt(context, "Account Storage Quota")>
        <ObsCard title=Signal::derive(move || tt(context, "Account Storage Quota"))>
            <ResourceFeedback resource=quota />
            {move || {
                summarize_personal_quota(&quota.data.get()).map(|summary| {
                    let used = bytes(summary.used_bytes);
                    let limit = if summary.configured {
                        bytes(summary.quota_bytes)
                    } else {
                        tt(context, "No quota limit configured")
                    };
                    let pct_text = format!("{:.1}", summary.percentage);
                    let pct_text_for_bar = pct_text.clone();
                    let avail_text = bytes(summary.available_bytes);
                    let bar_width = format!("{:.1}", summary.percentage.clamp(0.0, 100.0));
                    let bar_class = if summary.percentage >= 95.0 {
                        "fill-rose-400"
                    } else if summary.percentage >= 80.0 {
                        "fill-amber-400"
                    } else {
                        "fill-emerald-400"
                    };
                    let updated = if summary.updated_at.trim().is_empty() {
                        tt(context, "Not reported")
                    } else {
                        summary.updated_at.clone()
                    };
                    let configured = summary.configured;
                    let valuenow = summary.percentage.min(100.0);
                    let status_text = summary.status.clone();
                    let source_text = summary.source.clone();
                    view! {
                        <div class="space-y-3 text-sm">
                            <p class="text-slate-200">
                                {tt_with(
                                    context,
                                    "{used} used · {limit}",
                                    &[("used", &used), ("limit", &limit)],
                                )}
                            </p>
                            {configured.then(|| {
                                view! {
                                    <div
                                        role="progressbar"
                                        aria-label=move || tt(context, "Storage quota used")
                                        aria-valuemin="0"
                                        aria-valuemax="100"
                                        aria-valuenow=valuenow
                                        aria-valuetext=tt_with(
                                            context,
                                            "{pct}% used",
                                            &[("pct", &pct_text_for_bar)],
                                        )
                                        class="h-2 rounded-full bg-white/5 overflow-hidden"
                                    >
                                        <svg
                                            viewBox="0 0 100 8"
                                            preserveAspectRatio="none"
                                            class="w-full h-full block"
                                            aria-hidden="true"
                                        >
                                            <rect
                                                x="0"
                                                y="0"
                                                height="8"
                                                rx="4"
                                                width=bar_width
                                                class=bar_class
                                            />
                                        </svg>
                                    </div>
                                    <p class="text-xs text-slate-400">
                                        {tt_with(
                                            context,
                                            "{pct}% used · {available} available",
                                            &[("pct", &pct_text), ("available", &avail_text)],
                                        )}
                                    </p>
                                }
                            })}
                            <p class="text-xs text-slate-400">
                                {tt_with(
                                    context,
                                    "Status: {status} · Source: {source} · Updated: {updated}",
                                    &[
                                        ("status", &tt(context, &status_text)),
                                        ("source", &tt(context, &source_text)),
                                        ("updated", &updated),
                                    ],
                                )}
                            </p>
                        </div>
                    }
                })
            }}
        </ObsCard>
        </section>
        <ObsCard title=Signal::derive(move || tt(context, "Settings.sessionFamilies"))>
            <ResourceFeedback resource=sessions />
            <button type="button" class="glass-button px-3 py-2" disabled=move || busy.get() || other_sessions.with(Vec::is_empty)
                on:click=revoke_others>{move || tt(context, "Revoke all other sessions")}</button>
            {move || {
                sessions
                    .data
                    .with(|data| data["sessions"].as_array().cloned().unwrap_or_default())
                    .into_iter()
                    .map(move |session| {
                        let title = format!(
                            "{} · {}{}",
                            text(&session, "ip_address"),
                            text(&session, "jti"),
                            if session["is_current"] == true { tt(context, " · Current session") } else { String::new() },
                        );
                        let activity = tt_with(context, "Last active: {last} · Expires: {expires}", &[("last", &(text(&session, "last_active")).to_string()), ("expires", &(text(&session, "expires_at")).to_string())]);
                        let agent = text(&session, "user_agent");
                        view! {
                            <div class="flex flex-wrap items-center justify-between gap-4 border-t border-white/10 py-4">
                                <div class="min-w-0">
                                    <p class="text-sm break-all">{title}</p>
                                    <p class="text-xs text-slate-400 break-words">{agent}</p>
                                    <p class="text-xs text-slate-500">{activity}</p>
                                </div>
                                <button
                                    type="button"
                                    class="glass-button px-4 py-2"
                                    disabled=move || busy.get()
                                    on:click=move |_| revoke(session.clone())
                                >
                                    {move || tt(context, "Revoke session")}
                                </button>
                            </div>
                        }
                    })
                    .collect_view()
            }}
        </ObsCard>
        <Modal open=enroll_open title="Enroll TOTP authenticator">
            <p class="text-sm text-slate-400 mb-4">
                {move || tt(
                    context,
                    "Scan this QR code, then enter a six-digit code within five minutes.",
                )}
            </p>
            <QrCodeSvg
                payload=Signal::derive(move || enrollment.with(|v| text(v, "otpauth_uri")))
                label="Authenticator enrollment QR code"
            />
            <code class="block break-all my-4">
                {move || enrollment.with(|v| text(v, "secret"))}
            </code>
            <button type="button" class="glass-button px-3 py-2" on:click=move |_| {
                let secret = enrollment.with_untracked(|v| text(v, "secret"));
                if let Some(window) = web_sys::window() {
                    let write = window.navigator().clipboard().write_text(&secret);
                    spawn_local(async move {
                        if JsFuture::from(write).await.is_err() { context.toast(tt(context, "Clipboard unavailable"), true); }
                    });
                }
            }>{move || tt(context, "Copy setup key")}</button>
            <form
                class="space-y-4"
                on:submit=move |e| {
                    e.prevent_default();
                    mutate("verify");
                }
            >
                <DraftInput draft field="code" label="Six-digit verification code" required=true />
                <button
                    class="glass-button-primary px-4 py-2"
                    type="submit"
                    disabled=move || busy.get()
                >
                    {move || tt(context, "Verify and enable 2FA")}
                </button>
            </form>
        </Modal>
        <Modal open=recovery_open title="Save recovery codes">
            <p class="text-sm text-amber-300 mb-4">
                {move || tt(
                    context,
                    "Save these one-time codes securely. Closing this dialog clears them from this view.",
                )}
            </p>
            <pre class="text-sm whitespace-pre-wrap">
                {move || {
                    recovery.get().iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n")
                }}
            </pre>
            <button
                type="button"
                class="glass-button px-4 py-2 mt-4"
                on:click=move |_| {
                    let content = recovery
                        .get_untracked()
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join("\n");
                    if let Err(error) = download_text(
                        &content,
                        "aetherflow-recovery-codes.txt",
                        "text/plain",
                    ) {
                        context.toast(tt(context, &error), true);
                    }
                }
            >
                {move || tt(context, "Download recovery codes")}
            </button>
        </Modal>
        <ConfirmDialog
            open=disable
            title="Disable two-factor authentication?"
            message="Your current authenticator or recovery code is required. Active session families may be revoked."
            busy
            on_confirm=Callback::new(move |()| mutate("disable"))
        />
    }
}
