//! Active shares, creation, revocation, QR codes, and one-time URL display.
use super::paths::{encode, relative_path, text};
use super::types::*;
use super::{
    cached_url, remember_url, CreatedShareUrls, SHARES, SHARES_CHANGED, SHARE_GRANT_AREAS,
};
use crate::state::{app, is_valid_public_remote_host, use_api_when, PeerArea};
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

fn normalize_remote_origin(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = url::Url::parse(trimmed).ok()?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return None;
    }
    let host = parsed.host_str()?;
    if !is_valid_public_remote_host(host) {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

pub(crate) fn remote_public_origin(settings: &Value, local_origin: Option<&str>) -> Option<String> {
    let local_norm = local_origin
        .and_then(|origin| url::Url::parse(origin.trim()).ok())
        .map(|parsed| parsed.origin().ascii_serialization());
    let candidate = ["publicOrigin", "public_origin", "publicUrl", "public_url"]
        .iter()
        .find_map(|key| settings[key].as_str().and_then(normalize_remote_origin))
        .or_else(|| {
            ["baseDomain", "base_domain"]
                .iter()
                .find_map(|key| settings[key].as_str())
                .map(|raw| raw.trim().trim_start_matches("*.").to_ascii_lowercase())
                .filter(|domain| is_valid_public_remote_host(domain))
                .and_then(|domain| normalize_remote_origin(&format!("https://{domain}")))
        })?;
    if local_norm
        .as_deref()
        .is_some_and(|local| local.eq_ignore_ascii_case(&candidate))
    {
        return None;
    }
    Some(candidate)
}

fn valid_share_token(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn share_url_for_server(
    row: &Value,
    is_remote: bool,
    settings: &Value,
    local_origin: Option<&str>,
) -> Option<String> {
    let share: ShareRow = serde_json::from_value(row.clone()).ok()?;
    let raw = share.url.as_deref()?.trim();
    if raw.is_empty() {
        return None;
    }
    let target_origin = if is_remote {
        remote_public_origin(settings, local_origin)?
    } else {
        let local = local_origin?.trim();
        url::Url::parse(local).ok()?.origin().ascii_serialization()
    };
    let base = url::Url::parse(&target_origin).ok()?;
    let resolved = base.join(raw).ok()?;
    if resolved.origin() != base.origin()
        || resolved.path() != "/share"
        || resolved.fragment().is_some()
        || !resolved.username().is_empty()
        || resolved.password().is_some()
    {
        return None;
    }
    if is_remote {
        if resolved.scheme() != "https" {
            return None;
        }
        if let Some(local) = local_origin.and_then(|origin| url::Url::parse(origin.trim()).ok()) {
            if resolved.origin() == local.origin() {
                return None;
            }
        }
    }
    let token = resolved
        .query_pairs()
        .find_map(|(key, value)| (key == "token").then(|| value.into_owned()))?;
    valid_share_token(&token).then(|| resolved.to_string())
}

fn browser_origin() -> Option<String> {
    web_sys::window()?.location().origin().ok()
}

pub(crate) fn share_origin_available(context: crate::state::AppContext) -> bool {
    if !context.is_remote() {
        return true;
    }
    if !context.can_read_area(PeerArea::Settings) {
        return false;
    }
    let settings = context.settings.get();
    remote_public_origin(&settings, browser_origin().as_deref()).is_some()
}

pub(crate) fn share_origin_available_untracked(context: crate::state::AppContext) -> bool {
    if !context.is_remote_untracked() {
        return true;
    }
    if !context.can_read_area_untracked(PeerArea::Settings) {
        return false;
    }
    let settings = context.settings.get_untracked();
    remote_public_origin(&settings, browser_origin().as_deref()).is_some()
}

pub(crate) fn share_origin_block_reason(context: crate::state::AppContext) -> Option<String> {
    if share_origin_available(context) {
        return None;
    }
    let server = context
        .active_server_name()
        .unwrap_or_else(|| tt(context, "PeerSwitch.identityBarLabel"));
    Some(tt_with(
        context,
        "PeerSwitch.remoteShareOriginUnavailable",
        &[("server", &server)],
    ))
}

pub(crate) fn share_url_for_context(
    context: crate::state::AppContext,
    row: &Value,
) -> Option<String> {
    let is_remote = context.is_remote();
    if is_remote && !context.can_read_area(PeerArea::Settings) {
        return None;
    }
    let settings = context.settings.get();
    share_url_for_server(row, is_remote, &settings, browser_origin().as_deref())
}

pub(crate) fn share_url_for_context_untracked(
    context: crate::state::AppContext,
    row: &Value,
) -> Option<String> {
    let is_remote = context.is_remote_untracked();
    if is_remote && !context.can_read_area_untracked(PeerArea::Settings) {
        return None;
    }
    let settings = context.settings.get_untracked();
    share_url_for_server(row, is_remote, &settings, browser_origin().as_deref())
}

#[allow(dead_code)]
pub(crate) fn share_url(row: &Value) -> Option<String> {
    share_url_for_context_untracked(app(), row)
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
        <Show when=move || !url.with(String::is_empty)>
            <div class="space-y-4 min-w-0">
                <p class="text-sm text-amber-200">
                    {move || tt(
                        context,
                        "Save this URL now. It is only returned when the share is created.",
                    )}
                </p>
                <label class="block text-sm space-y-1">
                    <span>{move || tt(context, "Share URL")}</span>
                    <input class="af-input w-full px-3 py-2" readonly prop:value=move || url.get() />
                </label>
                <div class="flex flex-wrap gap-2">
                    <button
                        type="button"
                        class="af-btn-primary px-4 py-2"
                        on:click=move |_| copy_url(url.get_untracked())
                    >
                        {move || tt(context, "Copy share URL")}
                    </button>
                    <a
                        class="af-btn px-4 py-2"
                        href=move || url.get()
                        target="_blank"
                        rel="noopener noreferrer"
                    >
                        {move || tt(context, "Open share preview")}
                    </a>
                </div>
                <QrCodeSvg payload=url label="Public share QR code" />
            </div>
        </Show>
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
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        open.set(false);
        busy.set(false);
        created_url.set(String::new());
        error.set(String::new());
    });
    Effect::new(move |_| {
        context.areas_revocation_epoch(&SHARE_GRANT_AREAS);
        let origin_ok = share_origin_available(context);
        let files_ok = context.can_read_area(PeerArea::Files);
        if !files_ok {
            generation.update(|value| *value += 1);
            open.set(false);
            busy.set(false);
            created_url.set(String::new());
            error.set(String::new());
        } else if !origin_ok {
            generation.update(|value| *value += 1);
            busy.set(false);
            created_url.set(String::new());
        }
    });
    Effect::new(move |_| {
        if !context.can_write_area(PeerArea::Files) {
            generation.update(|value| *value += 1);
            busy.set(false);
        }
    });
    let origin_block_reason = Signal::derive(move || share_origin_block_reason(context));
    let submit = move |event: web_sys::SubmitEvent| {
        event.prevent_default();
        if busy.get_untracked()
            || !created_url.get_untracked().is_empty()
            || !context.can_write_area_untracked(PeerArea::Files)
            || !share_origin_available_untracked(context)
        {
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
        let server_epoch = context.server_epoch.get_untracked();
        let grant_epoch = context.areas_revocation_epoch_untracked(&SHARE_GRANT_AREAS);
        let mut busy_guard = crate::tabs::busy::BusyGuard::for_generation(busy, generation, ticket);
        spawn_local(async move {
            let result = ApiClient.post(SHARES, Some(&body)).await;
            if generation.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.areas_revocation_epoch_untracked(&SHARE_GRANT_AREAS) != grant_epoch
                || !context.can_read_area_untracked(PeerArea::Files)
                || !context.can_write_area_untracked(PeerArea::Files)
                || !share_origin_available_untracked(context)
            {
                return;
            }
            if let Ok(data) = &result {
                let created: CreatedShare = contracts::decode(data);
                let share = serde_json::to_value(&created.share).unwrap_or_default();
                remember_url(context, urls, auth, server_epoch, grant_epoch, &share);
                on_created.run(share.clone());
            }
            busy_guard.release();
            password.set(String::new());
            match result {
                Ok(data) => {
                    let created: CreatedShare = contracts::decode(&data);
                    let share = serde_json::to_value(&created.share).unwrap_or_default();
                    created_url
                        .set(share_url_for_context_untracked(context, &share).unwrap_or_default());
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
                    {move || {
                        origin_block_reason.get().map(|reason| {
                            view! {
                                <p
                                    role="status"
                                    data-testid="remote-share-origin-unavailable"
                                    class="rounded-xl border border-amber-400/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
                                >
                                    {reason}
                                </p>
                            }
                        })
                    }}
                    <label class="block text-sm space-y-1">
                        <span>{move || tt(context, "File or folder path")}</span>
                        <input
                            class="af-input w-full px-3 py-2"
                            required
                            prop:value=move || path.get()
                            disabled=move || busy.get()
                            on:input=move |event| path.set(event_target_value(&event))
                        />
                    </label>
                    <label class="block text-sm space-y-1">
                        <span>{move || tt(context, "Password (optional)")}</span>
                        <input
                            class="af-input w-full px-3 py-2"
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
                            class="af-input w-full px-3 py-2"
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
                        class="af-btn-primary px-4 py-2"
                        disabled=move || {
                            busy.get()
                                || !context.can_write_area(crate::state::PeerArea::Files)
                                || origin_block_reason.with(Option::is_some)
                        }
                        title=move || {
                            context
                                .area_block_reason(crate::state::PeerArea::Files, true)
                                .or_else(|| origin_block_reason.get())
                                .unwrap_or_default()
                        }
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
    let can_read_files = Signal::derive(move || context.can_read_area(PeerArea::Files));
    let resource = use_api_when(can_read_files, SHARES.to_owned());
    let known = RwSignal::new(Vec::<ShareRow>::new());
    let changes = StoredValue::new_local(web_sys::window().map(|window| {
        EventListener::new(&window, SHARES_CHANGED, move |_| {
            if context.can_read_area_untracked(PeerArea::Files) {
                resource.refresh();
            }
        })
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
        if !can_read_files.get() {
            known.set(vec![]);
            return;
        }
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
    let revoke_ticket = RwSignal::new(0u64);
    let revoke_error = RwSignal::new(String::new());
    let created = Callback::new(move |row: Value| {
        if !context.can_read_area_untracked(PeerArea::Files) {
            return;
        }
        if let Ok(row) = serde_json::from_value::<ShareRow>(row) {
            known.update(|rows| rows.insert(0, row));
        }
        resource.refresh();
    });
    Effect::new(move |_| {
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Files);
        revoke_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        busy.set(false);
        known.set(vec![]);
        create_open.set(false);
        qr_open.set(false);
        qr_url.set(String::new());
        revoke_open.set(false);
        revoke_error.set(String::new());
    });
    Effect::new(move |_| {
        if !context.can_write_area(PeerArea::Files) {
            revoke_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            busy.set(false);
            revoke_open.set(false);
        }
    });
    Effect::new(move |_| {
        context.area_revocation_epoch(PeerArea::Settings);
        if !share_origin_available(context) {
            qr_open.set(false);
            qr_url.set(String::new());
        }
    });
    let revoke = Callback::new(move |()| {
        if busy.get_untracked() || !context.can_write_area_untracked(PeerArea::Files) {
            return;
        }
        let id = revoke_target.get_untracked().id;
        if id.is_empty() {
            return;
        }
        revoke_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = revoke_ticket.get_untracked();
        busy.set(true);
        revoke_error.set(String::new());
        let auth = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let files_grant = context.area_revocation_epoch_untracked(PeerArea::Files);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(busy, revoke_ticket, ticket);
        spawn_local(async move {
            let result = ApiClient
                .delete(&format!("{SHARES}/{}", encode(&id)), None)
                .await;
            if revoke_ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Files) != files_grant
                || !context.can_write_area_untracked(PeerArea::Files)
                || busy.try_get_untracked().is_none()
            {
                return;
            }
            busy_guard.release();
            match result {
                Ok(_) => {
                    if let Some(cache) = urls {
                        cache.0.update(|cache| {
                            cache.3.remove(&id);
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
                        class="af-btn px-4 py-2"
                        disabled=move || !can_read_files.get()
                        title=move || {
                            context
                                .area_block_reason(PeerArea::Files, false)
                                .unwrap_or_default()
                        }
                        on:click=move |_| {
                            if can_read_files.get_untracked() {
                                resource.refresh();
                            }
                        }
                        aria-label=move || tt(context, "Refresh")
                    >
                        {move || tt(context, "Common.refresh")}
                    </button>
                    <button
                        type="button"
                        class="af-btn-primary px-4 py-2"
                        disabled=move || {
                            !context.can_write_area(PeerArea::Files)
                                || !share_origin_available(context)
                        }
                        title=move || {
                            context
                                .area_block_reason(PeerArea::Files, true)
                                .or_else(|| share_origin_block_reason(context))
                                .unwrap_or_default()
                        }
                        on:click=move |_| {
                            if context.can_write_area(PeerArea::Files)
                                && share_origin_available_untracked(context)
                            {
                                create_open.set(true);
                            }
                        }
                    >
                        {move || tt(context, "Create share")}
                    </button>
                </div>
            </div>
            <Show when=move || !can_read_files.get()>
                <p
                    role="status"
                    class="rounded-xl border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
                >
                    {move || {
                        context
                            .area_block_reason(PeerArea::Files, false)
                            .unwrap_or_default()
                    }}
                </p>
            </Show>
            {move || {
                share_origin_block_reason(context).map(|reason| {
                    view! {
                        <p
                            role="status"
                            data-testid="fileshare-remote-origin-notice"
                            class="rounded-xl border border-amber-400/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-200"
                        >
                            {reason}
                        </p>
                    }
                })
            }}
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
                        class="af-input px-3 py-2"
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
                                            share_url_for_context(
                                                context,
                                                &serde_json::to_value(row).unwrap_or_default(),
                                            )
                                            .or_else(|| cached_url(context, urls, &row.id))
                                        })
                                    };
                                    view! {
                                        <tr class="border-t border-[var(--af-border-hairline)] align-top">
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
                                                        class="af-btn px-3 py-2"
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
                                                        class="af-btn px-3 py-2"
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
                                                        class="af-btn px-3 py-2"
                                                        data-tone="danger"
                                                        disabled=move || {
                                                            busy.get()
                                                                || !context.can_write_area(
                                                                    crate::state::PeerArea::Files,
                                                                )
                                                        }
                                                        title=move || {
                                                            context
                                                                .area_block_reason(
                                                                    crate::state::PeerArea::Files,
                                                                    true,
                                                                )
                                                                .unwrap_or_default()
                                                        }
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_TOKEN: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm0123";

    #[test]
    fn remote_public_origin_validates_authoritative_https_domain_and_blocks_local_fallbacks() {
        assert_eq!(
            remote_public_origin(
                &json!({"baseDomain": "beta.example.com"}),
                Some("https://alpha.example.com")
            )
            .as_deref(),
            Some("https://beta.example.com")
        );
        assert_eq!(
            remote_public_origin(
                &json!({"baseDomain": "*.Beta.Example.COM"}),
                Some("http://127.0.0.1:8080")
            )
            .as_deref(),
            Some("https://beta.example.com")
        );
        assert_eq!(
            remote_public_origin(
                &json!({"publicOrigin": "https://share.peer-b.example.com:8443/"}),
                Some("https://alpha.example.com")
            )
            .as_deref(),
            Some("https://share.peer-b.example.com:8443")
        );
        for invalid in [
            json!({}),
            json!({"baseDomain": ""}),
            json!({"baseDomain": "localhost"}),
            json!({"baseDomain": "peer.localhost"}),
            json!({"baseDomain": "peer.aether.local"}),
            json!({"baseDomain": "peer.local"}),
            json!({"baseDomain": "192.168.1.50"}),
            json!({"baseDomain": "https://beta.example.com"}),
            json!({"baseDomain": "alpha.example.com"}),
            json!({"publicOrigin": "http://beta.example.com"}),
            json!({"publicOrigin": "https://user:pass@beta.example.com"}),
            json!({"publicOrigin": "https://beta.example.com/subpath"}),
            json!({"publicOrigin": "https://alpha.example.com"}),
        ] {
            assert_eq!(
                remote_public_origin(&invalid, Some("https://alpha.example.com")),
                None,
                "invalid remote origin settings must be rejected: {invalid}"
            );
        }
    }

    #[test]
    fn share_url_for_server_keeps_local_origin_and_never_sends_remote_tokens_locally() {
        let relative = json!({
            "id": "s-1",
            "url": format!("/share?token={SAMPLE_TOKEN}")
        });
        // Local server resolves relative share URLs against browser origin.
        assert_eq!(
            share_url_for_server(&relative, false, &json!({}), Some("http://127.0.0.1:8080"))
                .as_deref(),
            Some(format!("http://127.0.0.1:8080/share?token={SAMPLE_TOKEN}").as_str())
        );

        // Remote server with validated baseDomain uses the peer's public HTTPS origin.
        assert_eq!(
            share_url_for_server(
                &relative,
                true,
                &json!({"baseDomain": "peer-b.example.com"}),
                Some("http://127.0.0.1:8080")
            )
            .as_deref(),
            Some(format!("https://peer-b.example.com/share?token={SAMPLE_TOKEN}").as_str())
        );

        // Remote server without a safe remote origin refuses to generate a local link.
        assert_eq!(
            share_url_for_server(&relative, true, &json!({}), Some("http://127.0.0.1:8080")),
            None
        );
        assert_eq!(
            share_url_for_server(
                &relative,
                true,
                &json!({"baseDomain": "peer-b.aether.local"}),
                Some("http://127.0.0.1:8080")
            ),
            None
        );

        // Remote server rejects absolute URL pointing to local or foreign origin.
        let local_spoof = json!({
            "id": "s-2",
            "url": format!("https://alpha.example.com/share?token={SAMPLE_TOKEN}")
        });
        assert_eq!(
            share_url_for_server(
                &local_spoof,
                true,
                &json!({"baseDomain": "peer-b.example.com"}),
                Some("https://alpha.example.com")
            ),
            None
        );

        // Short or malformed tokens are rejected on both local and remote.
        let bad_token = json!({"id": "s-3", "url": "/share?token=short"});
        assert_eq!(
            share_url_for_server(&bad_token, false, &json!({}), Some("http://127.0.0.1:8080")),
            None
        );
        assert_eq!(
            share_url_for_server(
                &bad_token,
                true,
                &json!({"baseDomain": "peer-b.example.com"}),
                Some("http://127.0.0.1:8080")
            ),
            None
        );
    }
}
