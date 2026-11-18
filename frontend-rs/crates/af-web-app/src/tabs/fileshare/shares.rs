//! Active shares, creation, revocation, QR codes, and one-time URL display.
use super::paths::{encode, relative_path, text};
use super::types::*;
use super::{cached_url, remember_url, CreatedShareUrls, SHARES, SHARES_CHANGED};
use crate::state::{app, use_api};
use crate::tabs::contracts;
use crate::tabs::l10n::{
    tt, tt_with, Badge, ConfirmDialog, EmptyState, Modal, ObsCard, SearchInput,
};
use af_web_core::api::ApiClient;
use af_web_ui::{use_worker_rows, QrCodeSvg, SkeletonBox};
use gloo_events::EventListener;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::{spawn_local, JsFuture};
pub(crate) fn share_url(row: &Value) -> Option<String> {
    let share: ShareRow = serde_json::from_value(row.clone()).ok()?;
    let raw = share.url.as_deref()?;
    let origin = web_sys::window()?.location().origin().ok()?;
    let url = web_sys::Url::new_with_base(raw, &origin).ok()?;
    let token = url.search_params().get("token")?;
    (url.origin() == origin
        && url.pathname() == "/share"
        && token.len() == 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    .then(|| url.href())
}

pub(crate) fn copy_url(url: String) {
    let context = app();
    if let Some(window) = web_sys::window() {
        spawn_local(async move {
            match JsFuture::from(window.navigator().clipboard().write_text(&url)).await {
                Ok(_) => context.toast(tt(context, "Share URL copied"), false),
                Err(_) => context.toast(
                    tt(
                        context,
                        "Clipboard access failed. Select and copy the URL below.",
                    ),
                    true,
                ),
            }
        });
    }
}

#[component]
pub(crate) fn ShareLinkDetails(#[prop(into)] url: Signal<String>) -> impl IntoView {
    let context = app();
    view! {
        <div class="space-y-4 min-w-0">
            <p class="text-sm text-amber-200">
                {move || tt(
                    context,
                    "Save this URL now. It is only returned when the share is created.",
                )}
            </p>
            <label class="block text-sm space-y-1">
                <span>{move || tt(context, "Share URL")}</span>
                <input class="glass-input w-full px-3 py-2" readonly prop:value=move || url.get() />
            </label>
            <div class="flex flex-wrap gap-2">
                <button
                    type="button"
                    class="glass-button-primary px-4 py-2"
                    on:click=move |_| copy_url(url.get_untracked())
                >
                    {move || tt(context, "Copy share URL")}
                </button>
                <a
                    class="glass-button px-4 py-2"
                    href=move || url.get()
                    target="_blank"
                    rel="noopener noreferrer"
                >
                    {move || tt(context, "Open share preview")}
                </a>
            </div>
            <QrCodeSvg payload=url label="Public share QR code" />
        </div>
    }
}

/// The payload follows CreateShareRequest exactly. Unsupported counters and
/// download limits must not be inferred or sent as ignored JSON fields.
#[component]
pub(crate) fn ShareCreateModal(
    open: RwSignal<bool>,
    initial_path: RwSignal<String>,
    on_created: Callback<Value>,
) -> impl IntoView {
    let context = app();
    let urls = use_context::<CreatedShareUrls>();
    let path = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let lifetime = RwSignal::new("86400".to_owned());
    let allow_download = RwSignal::new(true);
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let created_url = RwSignal::new(String::new());
    let generation = RwSignal::new(0u64);
    let was_open = RwSignal::new(false);
    Effect::new(move |_| {
        let is_open = open.get();
        if !is_open && busy.get_untracked() {
            open.set(true);
            return;
        }
        if was_open.get_untracked() == is_open {
            return;
        }
        was_open.set(is_open);
        generation.update(|value| *value += 1);
        if !is_open {
            password.set(String::new());
        }
        if is_open {
            path.set(initial_path.get_untracked());
            password.set(String::new());
            error.set(String::new());
            created_url.set(String::new());
            busy.set(false);
        }
    });
    let submit = move |event: web_sys::SubmitEvent| {
        event.prevent_default();
        if busy.get_untracked() || !created_url.get_untracked().is_empty() {
            return;
        }
        let target = match relative_path(&path.get_untracked(), false) {
            Ok(path) => path,
            Err(message) => {
                error.set(message);
                return;
            }
        };
        let secret = password.get_untracked();
        if secret.len() > 1024 || secret.contains('\0') {
            error.set(
                "Password must contain at most 1024 UTF-8 bytes and no NUL characters.".into(),
            );
            return;
        }
        let mut body = json!({"path": target, "allow_download": allow_download.get_untracked()});
        if !secret.is_empty() {
            body["password"] = json!(secret);
        }
        if let Ok(seconds) = lifetime.get_untracked().parse::<u64>() {
            if seconds > 0 {
                body["expires_at"] = json!(js_sys::Date::new(&JsValue::from_f64(
                    js_sys::Date::now() + seconds as f64 * 1000.0
                ))
                .to_iso_string()
                .as_string()
                .unwrap_or_default());
            }
        }
        busy.set(true);
        error.set(String::new());
        let ticket = generation.get_untracked();
        let auth = context.session_epoch.get_untracked();
        let mut busy_guard = crate::tabs::busy::BusyGuard::for_generation(busy, generation, ticket);
        spawn_local(async move {
            let result = ApiClient.post(SHARES, Some(&body)).await;
            if context.session_epoch.try_get_untracked() != Some(auth)
                || generation.try_get_untracked().is_none()
            {
                return;
            }
            if let Ok(data) = &result {
                let created: CreatedShare = contracts::decode(data);
                let share = serde_json::to_value(&created.share).unwrap_or_default();
                remember_url(urls, auth, &share);
                on_created.run(share.clone());
            }
            if generation.try_get_untracked() != Some(ticket) {
                return;
            }
            busy_guard.release();
            password.set(String::new());
            match result {
                Ok(data) => {
                    let created: CreatedShare = contracts::decode(&data);
                    let share = serde_json::to_value(&created.share).unwrap_or_default();
                    created_url.set(share_url(&share).unwrap_or_default());
                    context.toast(tt(context, "Share created"), false);
                    if created_url.get_untracked().is_empty() {
                        error.set(
                            "The share was created, but no valid public URL was returned.".into(),
                        );
                    }
                }
                Err(failure) => error.set(failure.to_string()),
            }
        });
    };
    view! {
        <Modal open title="Create public share">
            <Show
                when=move || created_url.get().is_empty()
                fallback=move || view! { <ShareLinkDetails url=created_url /> }
            >
                <form class="space-y-4" on:submit=submit>
                    <label class="block text-sm space-y-1">
                        <span>{move || tt(context, "File or folder path")}</span>
                        <input
                            class="glass-input w-full px-3 py-2"
                            required
                            prop:value=move || path.get()
                            disabled=move || busy.get()
                            on:input=move |event| path.set(event_target_value(&event))
                        />
                    </label>
                    <label class="block text-sm space-y-1">
                        <span>{move || tt(context, "Password (optional)")}</span>
                        <input
                            class="glass-input w-full px-3 py-2"
                            type="password"
                            autocomplete="new-password"
                            prop:value=move || password.get()
                            disabled=move || busy.get()
                            on:input=move |event| password.set(event_target_value(&event))
                        />
                    </label>
                    <label class="block text-sm space-y-1">
                        <span>{move || tt(context, "Expires after")}</span>
                        <select
                            class="glass-input w-full px-3 py-2"
                            prop:value=move || lifetime.get()
                            disabled=move || busy.get()
                            on:change=move |event| lifetime.set(event_target_value(&event))
                        >
                            <option value="3600">{move || tt(context, "1 hour")}</option>
                            <option value="86400">{move || tt(context, "24 hours")}</option>
                            <option value="604800">{move || tt(context, "7 days")}</option>
                            <option value="2592000">{move || tt(context, "30 days")}</option>
                            <option value="0">{move || tt(context, "No expiry")}</option>
                        </select>
                    </label>
                    <label class="flex gap-2 text-sm">
                        <input
                            type="checkbox"
                            prop:checked=move || allow_download.get()
                            disabled=move || busy.get()
                            on:change=move |event| allow_download.set(event_target_checked(&event))
                        />
                        <span>{move || tt(context, "Allow downloads")}</span>
                    </label>
                    <button
                        type="submit"
                        class="glass-button-primary px-4 py-2"
                        disabled=move || busy.get()
                    >
                        {move || tt(
                            context,
                            if busy.get() { "Creating…" } else { "Create share" },
                        )}
                    </button>
                </form>
            </Show>
            <p role="alert" class="text-rose-300 text-sm mt-3">
                {move || tt(context, &error.get())}
            </p>
        </Modal>
    }
}

fn expires(row: &ShareRow) -> Option<f64> {
    row.expires_at
        .as_deref()
        .map(js_sys::Date::parse)
        .filter(|time| time.is_finite())
}

#[component]
pub(super) fn PublicShareLinks() -> impl IntoView {
    let context = app();
    let urls = use_context::<CreatedShareUrls>();
    let resource = use_api(SHARES.to_owned());
    let known = RwSignal::new(Vec::<ShareRow>::new());
    let changes =
        StoredValue::new_local(web_sys::window().map(|window| {
            EventListener::new(&window, SHARES_CHANGED, move |_| resource.refresh())
        }));
    on_cleanup(move || changes.set_value(None));
    let query = RwSignal::new(String::new());
    let filter = RwSignal::new("all".to_owned());
    let now = RwSignal::new(js_sys::Date::now());
    let clock = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        30_000,
        move || now.set(js_sys::Date::now()),
    )));
    on_cleanup(move || clock.set_value(None));
    Effect::new(move |_| {
        let data = resource.data.get();
        let Some(_server) = data["shares"].as_array() else {
            return;
        };
        let server = contracts::decode::<SharesPage>(&data).shares;
        let current = js_sys::Date::now();
        known.update(|rows| {
            let expired: Vec<_> = rows
                .iter()
                .filter(|row| {
                    expires(row).is_some_and(|time| time <= current)
                        && !server.iter().any(|item| item.id == row.id)
                })
                .cloned()
                .collect();
            *rows = server.clone();
            rows.extend(expired);
        });
    });
    let rows = Signal::derive(move || {
        let filter = filter.get();
        let now = now.get();
        known
            .get()
            .into_iter()
            .filter(|row| match filter.as_str() {
                "active" => expires(row).is_none_or(|time| time > now),
                "expired" => expires(row).is_some_and(|time| time <= now),
                "protected" => row.password_required,
                _ => true,
            })
            .filter_map(|row| serde_json::to_value(row).ok())
            .collect()
    });
    let filtered = use_worker_rows(
        rows,
        query.into(),
        vec![
            "id".into(),
            "path".into(),
            "name".into(),
            "created_at".into(),
            "expires_at".into(),
        ],
    );
    let create_open = RwSignal::new(false);
    let initial_path = RwSignal::new(String::new());
    let qr_open = RwSignal::new(false);
    let qr_url = RwSignal::new(String::new());
    let revoke_open = RwSignal::new(false);
    let revoke_target = RwSignal::new(ShareRow::default());
    let busy = RwSignal::new(false);
    let revoke_error = RwSignal::new(String::new());
    let created = Callback::new(move |row: Value| {
        if let Ok(row) = serde_json::from_value::<ShareRow>(row) {
            known.update(|rows| rows.insert(0, row));
        }
        resource.refresh();
    });
    let revoke = Callback::new(move |()| {
        if busy.get_untracked() {
            return;
        }
        let id = revoke_target.get_untracked().id;
        if id.is_empty() {
            return;
        }
        busy.set(true);
        revoke_error.set(String::new());
        let auth = context.session_epoch.get_untracked();
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            let result = ApiClient
                .delete(&format!("{SHARES}/{}", encode(&id)), None)
                .await;
            if context.session_epoch.try_get_untracked() != Some(auth)
                || busy.try_get_untracked().is_none()
            {
                return;
            }
            busy_guard.release();
            match result {
                Ok(_) => {
                    if let Some(cache) = urls {
                        cache.0.update(|cache| {
                            cache.1.remove(&id);
                        });
                    }
                    known.update(|rows| rows.retain(|row| row.id != id));
                    revoke_open.set(false);
                    resource.refresh();
                    context.toast(tt(context, "Share revoked"), false);
                }
                Err(failure) => {
                    revoke_error.set(failure.to_string());
                    context.toast(tt(context, &failure.to_string()), true);
                }
            }
        });
    });
    view! {
        <div class="space-y-5 min-w-0 max-w-full">
            <div class="flex flex-wrap justify-between items-center gap-3">
                <div>
                    <h2 class="text-xl font-semibold">
                        {move || tt(context, "Fileshare.publicShareLinks")}
                    </h2>
                    <p class="text-sm text-slate-400">
                        {move || tt(context, "Control access to your public files and folders.")}
                    </p>
                </div>
                <div class="flex gap-2">
                    <button
                        type="button"
                        class="glass-button px-4 py-2"
                        on:click=move |_| resource.refresh()
                        aria-label=move || tt(context, "Refresh")
                    >
                        {move || tt(context, "Common.refresh")}
                    </button>
                    <button
                        type="button"
                        class="glass-button-primary px-4 py-2"
                        on:click=move |_| create_open.set(true)
                    >
                        {move || tt(context, "Create share")}
                    </button>
                </div>
            </div>
            <div class="grid grid-cols-2 xl:grid-cols-4 gap-4">
                <ObsCard title=Signal::derive(move || tt(context, "Fileshare.activeShares"))>
                    <p class="text-3xl font-semibold text-cyan-300">
                        {move || {
                            known
                                .with(|rows| {
                                    rows.iter()
                                        .filter(|row| {
                                            expires(row).is_none_or(|time| time > now.get())
                                        })
                                        .count()
                                })
                        }}
                    </p>
                </ObsCard>
                <ObsCard title=Signal::derive(move || tt(context, "Fileshare.passwordProtected"))>
                    <p class="text-3xl font-semibold text-violet-300">
                        {move || {
                            known
                                .with(|rows| {
                                    rows.iter()
                                        .filter(|row| {
                                            row.password_required
                                                && expires(row).is_none_or(|time| time > now.get())
                                        })
                                        .count()
                                })
                        }}
                    </p>
                </ObsCard>
                <ObsCard title=Signal::derive(move || tt(context, "Fileshare.totalDownloads"))>
                    <p class="text-sm text-slate-400">
                        {move || tt(context, "Not reported by the server")}
                    </p>
                </ObsCard>
                <ObsCard title=Signal::derive(move || tt(context, "Fileshare.expiringSoon"))>
                    <p class="text-3xl font-semibold text-amber-300">
                        {move || {
                            known
                                .with(|rows| {
                                    rows.iter()
                                        .filter(|row| {
                                            expires(row)
                                                .is_some_and(|time| {
                                                    time > now.get() && time <= now.get() + 86_400_000.0
                                                })
                                        })
                                        .count()
                                })
                        }}
                    </p>
                </ObsCard>
            </div>
            <ObsCard title=Signal::derive(move || tt(context, "Fileshare.publicShares"))>
                <div class="flex flex-wrap gap-3 mb-4">
                    <div class="flex-1 min-w-48">
                        <SearchInput value=query placeholder="Filter by name, path or share ID" />
                    </div>
                    <select
                        class="glass-input px-3 py-2"
                        aria-label=move || tt(context, "Share status")
                        prop:value=move || filter.get()
                        on:change=move |event| filter.set(event_target_value(&event))
                    >
                        <option value="all">{move || tt(context, "All known shares")}</option>
                        <option value="active">{move || tt(context, "Active")}</option>
                        <option value="expired">
                            {move || tt(context, "Expired this session")}
                        </option>
                        <option value="protected">
                            {move || tt(context, "Password protected")}
                        </option>
                    </select>
                </div>
                <p class="text-xs text-slate-400 mb-4">
                    {move || tt(
                        context,
                        "The server lists active shares. Expired links seen in this session remain visible. Previously created URLs cannot be recovered after reloading.",
                    )}
                </p>
                <Show when=move || resource.loading.get()>
                    <SkeletonBox class="h-24" />
                </Show>
                <Show when=move || resource.error.get().is_some()>
                    <p role="alert" class="text-rose-300">
                        {move || resource.error.get().map(|failure| tt(context, &failure.to_string()))}
                    </p>
                </Show>
                <div class="overflow-x-auto max-w-full">
                    <table class="w-full text-sm text-left">
                        <thead>
                            <tr class="text-slate-400">
                                <th class="p-3">{move || tt(context, "Target / share ID")}</th>
                                <th class="p-3">{move || tt(context, "Created")}</th>
                                <th class="p-3">{move || tt(context, "Expires")}</th>
                                <th class="p-3">{move || tt(context, "Access")}</th>
                                <th class="p-3">{move || tt(context, "Actions")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For
                                each=move || filtered.get()
                                key=|row| text(row, "id")
                                children=move |row| {
                                    let row = StoredValue::new(contracts::decode::<ShareRow>(&row));
                                    let expired = move || {
                                        row.with_value(|row| {
                                            expires(row).is_some_and(|time| time <= now.get())
                                        })
                                    };
                                    let url = move || {
                                        row.with_value(|row| {
                                            share_url(&serde_json::to_value(row).unwrap_or_default()).or_else(|| cached_url(context, urls, &row.id))
                                        })
                                    };
                                    view! {
                                        <tr class="border-t border-white/10 align-top">
                                            <td class="p-3">
                                                <p class="font-medium break-all">
                                                    {row.with_value(|row| row.path.clone())}
                                                </p>
                                                <p class="text-xs text-slate-500 break-all">
                                                    {row.with_value(|row| row.id.clone())}
                                                </p>
                                                <Show when=expired>
                                                    <Badge label="Expired" tone="amber" />
                                                </Show>
                                            </td>
                                            <td class="p-3 text-xs">
                                                {row.with_value(|row| row.created_at.clone())}
                                            </td>
                                            <td class="p-3 text-xs">
                                                {move || row.with_value(|row| tt(context, row.expires_at.as_deref().unwrap_or("No expiry")))}
                                            </td>
                                            <td class="p-3 space-y-1">
                                                {row
                                                    .with_value(|row| {
                                                        (row.password_required)
                                                            .then(|| {
                                                                view! { <Badge label="Password protected" tone="violet" /> }
                                                            })
                                                    })}
                                                <p class="text-xs text-slate-400">
                                                    {move || row.with_value(|row| tt(context, if row.allow_download { "Downloads allowed" } else { "Browsing only" }))}
                                                </p>
                                            </td>
                                            <td class="p-3">
                                                <div class="flex flex-wrap gap-2">
                                                    <button
                                                        type="button"
                                                        class="glass-button px-3 py-2"
                                                        disabled=move || url().is_none() || expired()
                                                        on:click=move |_| {
                                                            if let Some(url) = url() {
                                                                copy_url(url);
                                                            }
                                                        }
                                                    >
                                                        {move || tt(context, "Copy URL")}
                                                    </button>
                                                    <button
                                                        type="button"
                                                        class="glass-button px-3 py-2"
                                                        disabled=move || url().is_none() || expired()
                                                        on:click=move |_| {
                                                            if let Some(url) = url() {
                                                                qr_url.set(url);
                                                                qr_open.set(true);
                                                            }
                                                        }
                                                    >
                                                        {move || tt(context, "QR / Preview")}
                                                    </button>
                                                    <button
                                                        type="button"
                                                        class="glass-button px-3 py-2 text-rose-300"
                                                        disabled=move || busy.get()
                                                        on:click=move |_| {
                                                            revoke_target.set(row.get_value());
                                                            revoke_error.set(String::new());
                                                            revoke_open.set(true);
                                                        }
                                                    >
                                                        {move || tt(context, "Revoke")}
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    }
                                }
                            />
                        </tbody>
                    </table>
                </div>
                <Show when=move || !resource.loading.get() && filtered.with(Vec::is_empty)>
                    <EmptyState
                        title="No matching shares"
                        description="Create a link to share a file or folder from McBrowser."
                    />
                </Show>
                <p role="alert" class="text-sm text-rose-300 mt-3">
                    {move || tt(context, &revoke_error.get())}
                </p>
            </ObsCard>
            <ShareCreateModal open=create_open initial_path on_created=created />
            <Modal open=qr_open title="Share link">
                <ShareLinkDetails url=qr_url />
            </Modal>
            {move || {
                revoke_open
                    .get()
                    .then(|| {
                        view! {
                            <ConfirmDialog
                                open=revoke_open
                                title="Revoke public share"
                                message=Signal::derive(move || tt_with(context, "Disable public access to {name}? Existing copies of the URL will stop working.", &[("name", &(revoke_target.get().path).to_string())]))
                                on_confirm=revoke
                                busy=busy
                            />
                        }
                    })
            }}
        </div>
    }
}
