//! Private filesystem workspace. Mutations use the authenticated API, TUS
//! transfers reconcile server offsets, and editor drafts retain their read ETag.
use super::fileshare::{encode, relative_path, text, ShareCreateModal, ShareLinkDetails};
use crate::state::{
    app, json_rows, use_api_when, worker_pool, ApiResource, AppContext, PeerArea, TabId,
};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{
    Badge, ConfirmDialog, DataGrid, Drawer, EmptyState, Modal, ObsCard, SearchInput, TabPanel,
    TabsBar,
};
use af_web_core::{
    api::{ApiClient, ApiError},
    draft::FormDraft,
    worker::{WorkerRequest, WorkerResponse},
};
use af_web_ui::{use_worker_rows, GridColumn, SkeletonBox, MAX_TEXT_EDITOR_BYTES};
use gloo_events::EventListener;
use leptos::prelude::*;
use serde_json::{json, Value};
use std::{cell::RefCell, collections::BTreeSet, rc::Rc};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::{spawn_local, JsFuture};

mod helpers;
use helpers::*;
mod transfers;
use transfers::*;
mod editor;
use editor::*;
mod actions;
use actions::*;
mod events;
use events::*;
mod toolbar;
use toolbar::*;
mod policy_audit;
use policy_audit::*;

fn resolve_mcbrowser_subtab(requested: &str, is_admin: bool) -> &'static str {
    if is_admin {
        match requested {
            "policy" => "policy",
            "events" => "events",
            _ => "workspace",
        }
    } else {
        "workspace"
    }
}

#[component]
pub fn McBrowserTab() -> impl IntoView {
    let context = app();
    let can_read_files = Signal::derive(move || context.can_read_area(PeerArea::Files));
    let path = RwSignal::new(String::new());
    let entries = use_api_when(
        can_read_files,
        Signal::derive(move || format!("{BASE}/entries?path={}", encode(&path.get()))),
    );
    let usage = use_api_when(can_read_files, format!("{BASE}/usage"));
    let policy = use_api_when(can_read_files, format!("{BASE}/policy"));
    let preferences = use_api_when(can_read_files, format!("{BASE}/preferences"));
    let initial_subtab = context
        .take_pending_subtab(TabId::McBrowser)
        .map(|target| resolve_mcbrowser_subtab(&target, context.is_admin()).to_owned())
        .unwrap_or_else(|| "workspace".to_owned());
    let subtab = RwSignal::new(initial_subtab);
    let refresh = Callback::new(move |()| {
        if !context.can_read_area_untracked(PeerArea::Files) {
            return;
        }
        entries.refresh();
        usage.refresh();
        policy.refresh();
    });
    let editor = Editor::new(refresh);
    let queue = TransferQueue::new(refresh);
    let selected = RwSignal::new(BTreeSet::<String>::new());
    let actions = Actions::new(selected, refresh);
    let filter = RwSignal::new(String::new());
    let search_query = RwSignal::new(String::new());
    let search_type = RwSignal::new(String::new());
    let search_data = RwSignal::new(None::<Value>);
    let search_busy = RwSignal::new(false);
    let search_error = RwSignal::new(String::new());
    let search_generation = RwSignal::new(0u64);
    let sort = RwSignal::new("name".to_owned());
    let descending = RwSignal::new(false);
    let grid = RwSignal::new(false);
    let editor_theme = RwSignal::new("chrome".to_owned());
    let pref_sync = StoredValue::new_local(PreferenceSyncState::default());
    let pref_disposed = StoredValue::new_local(false);
    let pref_epoch = RwSignal::new(0u64);
    let pref_error = RwSignal::new(Option::<String>::None);
    let conflict = RwSignal::new("error".to_owned());
    let media_open = RwSignal::new(false);
    let media_path = RwSignal::new(String::new());
    let share_open = RwSignal::new(false);
    let share_path = RwSignal::new(String::new());
    let share_preview = RwSignal::new(false);
    let share_preview_url = RwSignal::new(String::new());
    let switch_editor = RwSignal::new(false);
    let pending_editor = RwSignal::new(String::new());
    let dragging = RwSignal::new(false);
    let file_input = NodeRef::<leptos::html::Input>::new();
    let can = move |permission: &str| {
        crate::tabs::contracts::decode::<crate::tabs::contracts::McBrowserPolicy>(
            &policy.data.get(),
        )
        .permissions
        .get(permission)
        .copied()
        .unwrap_or(false)
    };
    Effect::new(move |_| {
        context.pending_subtab.track();
        let is_admin = context.is_admin();
        if let Some(target) = context.take_pending_subtab(TabId::McBrowser) {
            subtab.set(resolve_mcbrowser_subtab(&target, is_admin).to_owned());
        }
    });
    let flush_preferences = move || {
        if !context.can_write_area_untracked(crate::state::PeerArea::Files) {
            return;
        }
        let auth = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let files_grant = context.area_revocation_epoch_untracked(PeerArea::Files);
        let run_epoch = pref_epoch.get_untracked();
        spawn_local(async move {
            loop {
                if pref_disposed.try_get_value() != Some(false)
                    || context.session_epoch.try_get_untracked() != Some(auth)
                    || context.server_epoch.try_get_untracked() != Some(server_epoch)
                    || context.area_revocation_epoch_untracked(PeerArea::Files) != files_grant
                    || !context.can_write_area_untracked(PeerArea::Files)
                    || pref_epoch.try_get_untracked() != Some(run_epoch)
                {
                    return;
                }
                let next_payload = pref_sync
                    .try_update_value(|sync| sync.take_next_payload())
                    .flatten();
                let Some(payload) = next_payload else {
                    return;
                };
                let result = ApiClient
                    .put(&format!("{BASE}/preferences"), Some(&payload))
                    .await;
                if pref_disposed.try_get_value() != Some(false)
                    || context.session_epoch.try_get_untracked() != Some(auth)
                    || context.server_epoch.try_get_untracked() != Some(server_epoch)
                    || context.area_revocation_epoch_untracked(PeerArea::Files) != files_grant
                    || !context.can_write_area_untracked(PeerArea::Files)
                    || pref_epoch.try_get_untracked() != Some(run_epoch)
                {
                    return;
                }
                match result {
                    Ok(saved) => {
                        let _ = pref_sync.try_update_value(|sync| sync.on_success(payload, saved));
                        pref_error.set(None);
                    }
                    Err(failure) => {
                        let message = failure.to_string();
                        let _ = pref_sync.try_update_value(|sync| sync.on_error(message.clone()));
                        pref_error.set(Some(message));
                        return;
                    }
                }
            }
        });
    };
    let retry_preferences = move || {
        let should_flush = pref_sync
            .try_update_value(|sync| sync.retry())
            .unwrap_or(false);
        if should_flush {
            pref_error.set(None);
            flush_preferences();
        }
    };
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Files);
        pref_epoch.update(|epoch| *epoch = epoch.wrapping_add(1));
        let _ = pref_sync.try_update_value(PreferenceSyncState::reset);
        pref_error.set(None);
        editor_theme.set("chrome".to_owned());
        preferences.data.set(Value::Null);
        path.set(String::new());
        selected.set(BTreeSet::new());
        search_generation.update(|generation| *generation += 1);
        search_data.set(None);
        search_busy.set(false);
        search_error.set(String::new());
        media_open.set(false);
        media_path.set(String::new());
        share_open.set(false);
        share_path.set(String::new());
        share_preview.set(false);
        share_preview_url.set(String::new());
        switch_editor.set(false);
    });
    Effect::new(move |_| {
        if !context.can_write_area(PeerArea::Files) {
            pref_epoch.update(|epoch| *epoch = epoch.wrapping_add(1));
            let _ = pref_sync.try_update_value(PreferenceSyncState::reset);
            pref_error.set(None);
        }
    });
    Effect::new(move |_| {
        let data = preferences.data.get();
        if data.is_object() {
            let hydrated = pref_sync
                .try_update_value(|sync| sync.hydrate(data))
                .flatten();
            if let Some(saved) = hydrated {
                pref_error.set(None);
                grid.set(saved.grid);
                sort.set(saved.sort);
                descending.set(saved.descending);
                editor_theme.set(saved.editor_theme);
            }
        }
    });
    Effect::new(move |_| {
        let current_grid = grid.get();
        let current_sort = sort.get();
        let current_desc = descending.get();
        let current_theme = editor_theme.get();
        let should_flush = pref_sync
            .try_update_value(|sync| {
                sync.queue_change(current_grid, current_sort, current_desc, current_theme)
            })
            .unwrap_or(false);
        if should_flush {
            pref_error.set(None);
            flush_preferences();
        }
    });
    Effect::new(move |_| {
        path.track();
        search_generation.update(|generation| *generation += 1);
        selected.set(BTreeSet::new());
        search_data.set(None);
        search_busy.set(false);
        search_error.set(String::new());
    });
    Effect::new(move |_| {
        if !context.is_admin() && subtab.get_untracked() != "workspace" {
            subtab.set("workspace".into());
        }
    });
    let rows = Signal::derive(move || {
        if let Some(data) = search_data.get() {
            json_rows(&data)
        } else {
            let data = entries.data.get();
            if data["path"].as_str() == Some(path.get().as_str()) {
                json_rows(&data)
            } else {
                vec![]
            }
        }
    });
    let filtered = use_worker_rows(
        rows,
        filter.into(),
        vec![
            "name".into(),
            "path".into(),
            "kind".into(),
            "modified".into(),
        ],
    );
    let sorted = Memo::new(move |_| {
        let key = sort.get();
        let mut rows = filtered.get();
        rows.sort_by(|a, b| {
            let order = if key == "size" {
                a["size"]
                    .as_u64()
                    .unwrap_or(0)
                    .cmp(&b["size"].as_u64().unwrap_or(0))
            } else {
                text(a, &key)
                    .to_lowercase()
                    .cmp(&text(b, &key).to_lowercase())
            };
            let order = order.then_with(|| text(a, "path").cmp(&text(b, "path")));
            if descending.get() {
                order.reverse()
            } else {
                order
            }
        });
        rows
    });
    let search = move |event: web_sys::SubmitEvent| {
        event.prevent_default();
        let query = search_query.get_untracked().trim().to_owned();
        if query.is_empty()
            || search_busy.get_untracked()
            || !context.can_read_area_untracked(PeerArea::Files)
        {
            return;
        }
        search_generation.update(|generation| *generation += 1);
        let ticket = search_generation.get_untracked();
        let auth = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let files_grant = context.area_revocation_epoch_untracked(PeerArea::Files);
        let endpoint = format!(
            "{BASE}/search?path={}&q={}&type={}&ai=true",
            encode(&path.get_untracked()),
            encode(&query),
            encode(&search_type.get_untracked())
        );
        search_busy.set(true);
        search_error.set(String::new());
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(search_busy, search_generation, ticket);
        spawn_local(async move {
            let result = ApiClient.get(&endpoint).await;
            if search_generation.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Files) != files_grant
                || !context.can_read_area_untracked(PeerArea::Files)
            {
                return;
            }
            busy_guard.release();
            match result {
                Ok(data) => {
                    selected.set(BTreeSet::new());
                    search_data.set(Some(data));
                }
                Err(error) => search_error.set(error.to_string()),
            }
        });
    };
    let open_in_editor = Callback::new(move |target: String| {
        if !can("read") {
            return;
        }
        if editor.saving.get_untracked() || editor.loading.get_untracked() {
            context.toast(
                tt(context, "Wait for the current editor request to finish."),
                true,
            );
            return;
        }
        if editor.path.get_untracked() == target {
            editor.open.set(true);
            return;
        }
        if editor.dirty_untracked() {
            pending_editor.set(target);
            switch_editor.set(true);
        } else {
            editor.load(target);
        }
    });
    let open_entry = Callback::new(move |row: Value| {
        let target = match relative_path(&text(&row, "path"), false) {
            Ok(path) => path,
            Err(message) => {
                context.toast(tt(context, &message), true);
                return;
            }
        };
        let kind = if row["kind"] == "symlink" {
            text(&row, "target_kind")
        } else {
            text(&row, "kind")
        };
        if kind == "directory" {
            path.set(target);
            return;
        }
        if !can("read") {
            return;
        }
        let size = row["size"].as_u64().unwrap_or(0);
        let mkind = media_kind(&target);
        if !mkind.is_empty() {
            if mkind == "csv" && size > MAX_CSV_PREVIEW_BYTES {
                context.toast(
                    tt(
                        context,
                        "CSV preview is limited to 5 MiB. Download larger files.",
                    ),
                    true,
                );
                return;
            }
            if mkind == "epub" && size > MAX_EPUB_BYTES {
                context.toast(
                    tt(
                        context,
                        "EPUB preview is limited to 64 MiB. Download larger files.",
                    ),
                    true,
                );
                return;
            }
            media_path.set(target);
            media_open.set(true);
            return;
        }
        if size > MAX_TEXT_EDITOR_BYTES as u64 {
            context.toast(
                tt(
                    context,
                    "Text editing is limited to 10 MiB. Download larger files.",
                ),
                true,
            );
            return;
        }
        open_in_editor.run(target);
    });
    let previewable_items = Signal::derive(move || {
        sorted.with(|rows| {
            rows.iter()
                .filter(|row| row["kind"] != "directory")
                .filter_map(|row| {
                    let target = relative_path(&text(row, "path"), false).ok()?;
                    (!media_kind(&target).is_empty()).then_some(target)
                })
                .collect::<Vec<_>>()
        })
    });
    let upload_files = move |files: web_sys::FileList| {
        if !can("create") || !context.can_write_area(crate::state::PeerArea::Files) {
            context.toast(
                context
                    .area_block_reason(crate::state::PeerArea::Files, true)
                    .unwrap_or_else(|| tt(context, "Upload permission is required.")),
                true,
            );
            return;
        }
        queue.add(files, &path.get_untracked(), &conflict.get_untracked());
    };
    let unload = StoredValue::new_local(web_sys::window().map(|window| {
        EventListener::new(&window, "beforeunload", move |event| {
            if editor.dirty_untracked()
                || queue
                    .rows
                    .with_untracked(|rows| rows.iter().any(|row| !row.status.terminal()))
            {
                event.prevent_default();
                let _ = js_sys::Reflect::set(
                    event.as_ref(),
                    &JsValue::from_str("returnValue"),
                    &JsValue::from_str(""),
                );
            }
        })
    }));
    on_cleanup(move || {
        pref_disposed.set_value(true);
        unload.set_value(None);
        queue.inner.update_value(|inner| inner.disposed = true);
    });
    view! {
        <div class="space-y-5 min-w-0 max-w-full">
            <div class="flex flex-wrap justify-between gap-3 items-center">
                <div>
                    <h2 class="text-lg font-semibold">
                        {move || tt(context, "Tabs.mcbrowserHeading")}
                    </h2>
                    <p class="text-sm text-slate-400">
                        {move || tt(context, "McBrowser.subtitle")}
                    </p>
                </div>
                <button
                    type="button"
                    class="af-btn px-4 py-2"
                    on:click=move |_| queue.open.set(true)
                >
                    {move || tt_with(
                        context,
                        "McBrowser.transfers",
                        &[("count", &queue.rows.with(Vec::len).to_string())],
                    )}
                </button>
            </div>
            <TabsBar
                id_prefix="mcbrowser"
                active=subtab
                tabs=Signal::derive(move || {
                    let mut tabs = vec![("workspace".into(), tt(context, "McBrowser.workspace"))];
                    if context.is_admin() {
                        tabs.push(("policy".into(), tt(context, "McBrowser.storagePolicy")));
                        tabs.push(("events".into(), tt(context, "McBrowser.auditEvents")));
                    }
                    tabs
                })
            />
            <TabPanel id_prefix="mcbrowser" id=Signal::derive(move || subtab.get())>
                <Show when=move || subtab.get() == "workspace">
                    <ObsCard>
                        <Show when=move || !can_read_files.get()>
                            <p role="status" class="text-xs text-amber-300 mb-3">
                                {move || {
                                    context
                                        .area_block_reason(PeerArea::Files, false)
                                        .unwrap_or_default()
                                }}
                            </p>
                        </Show>
                        <div class="flex flex-wrap items-center justify-between gap-3 mb-2">
                            <p class="text-sm text-slate-300">
                                {move || {
                                    let data = usage.data.get();
                                    if usage.loading.get() {
                                        tt(context, "Loading quota…")
                                    } else if usage.error.get().is_some() {
                                        tt(context, "Quota unavailable")
                                    } else {
                                        let used = data["used_bytes"].as_u64().unwrap_or(0);
                                        let quota = data["quota_bytes"].as_u64().unwrap_or(0);
                                        tt_with(
                                            context,
                                            "{used} used / {total} · {status}",
                                            &[
                                                ("used", &bytes(used)),
                                                (
                                                    "total",
                                                    &if quota == 0 {
                                                        tt(context, "Unlimited")
                                                    } else {
                                                        bytes(quota)
                                                    },
                                                ),
                                                ("status", &tt(context, &text(&data, "status"))),
                                            ],
                                        )
                                    }
                                }}
                            </p>
                            <div class="flex gap-2">
                                <button
                                    type="button"
                                    class="af-btn px-3 py-2"
                                    disabled=move || path.get().is_empty()
                                    on:click=move |_| path.set(parent(&path.get_untracked()).to_owned())
                                >
                                    {move || tt(context, "Common.up")}
                                </button>
                                <button
                                    type="button"
                                    class="af-btn px-3 py-2"
                                    disabled=move || !can_read_files.get()
                                    title=move || {
                                        context
                                            .area_block_reason(PeerArea::Files, false)
                                            .unwrap_or_default()
                                    }
                                    on:click=move |_| refresh.run(())
                                    aria-label=move || tt(context, "Refresh")
                                >
                                    {move || tt(context, "Common.refresh")}
                                </button>
                            </div>
                        </div>
                        <progress
                            class="w-full h-2"
                            aria-label=move || tt(context, "Storage quota used")
                            max="100"
                            value=move || {
                                let data = usage.data.get();
                                let quota = data["quota_bytes"].as_u64().unwrap_or(0);
                                if quota == 0 {
                                    0.0
                                } else {
                                    (data["used_bytes"].as_u64().unwrap_or(0) as f64 / quota as f64
                                        * 100.0)
                                        .min(100.0)
                                }
                            }
                        />
                        <nav
                            aria-label=move || tt(context, "File breadcrumbs")
                            class="flex flex-wrap gap-2 items-center my-4"
                        >
                            <button
                                type="button"
                                class="af-btn px-3 py-2"
                                on:click=move |_| path.set(String::new())
                            >
                                {move || tt(context, "/")}
                            </button>
                            {move || {
                                let current = path.get();
                                let mut prefix = String::new();
                                current
                                    .split('/')
                                    .filter(|part| !part.is_empty())
                                    .map(|part| {
                                        prefix = join(&prefix, part);
                                        let target = prefix.clone();
                                        view! {
                                            <span aria-hidden="true">{move || tt(context, "/")}</span>
                                            <button
                                                type="button"
                                                class="af-btn px-3 py-2"
                                                on:click=move |_| path.set(target.clone())
                                            >
                                                {part.to_owned()}
                                            </button>
                                        }
                                    })
                                    .collect_view()
                            }}
                        </nav>
                        <WorkspaceToolbar state=ToolbarState {
                            path,
                            filter,
                            grid,
                            sort,
                            descending,
                            search_query,
                            search_type,
                            search_data,
                            search_busy,
                            search_error,
                            search_generation,
                            conflict,
                            selected,
                            actions,
                            share_open,
                            share_path,
                            file_input,
                            policy,
                            sorted,
                            search: Callback::new(search),
                            upload_files: Callback::new(upload_files),
                        } />
                        <Show when=move || pref_error.get().is_some()>
                            <p
                                role="alert"
                                class="text-xs text-amber-300 mb-2 flex flex-wrap items-center gap-3"
                                data-testid="mcbrowser-prefs-error"
                            >
                                <span>
                                    {move || {
                                        tt_with(
                                            context,
                                            "Could not save workspace preferences: {error}",
                                            &[(
                                                "error",
                                                &pref_error.get().unwrap_or_default(),
                                            )],
                                        )
                                    }}
                                </span>
                                <button
                                    type="button"
                                    class="underline"
                                    data-testid="mcbrowser-prefs-retry"
                                    on:click=move |_| retry_preferences()
                                >
                                    {move || tt(context, "Retry")}
                                </button>
                            </p>
                        </Show>
                        <p role="alert" class="text-sm text-rose-300">
                            {move || {
                                entries
                                    .error
                                    .get()
                                    .or_else(|| policy.error.get())
                                    .or_else(|| usage.error.get())
                                    .map(|failure| tt(context, &failure.to_string()))
                            }}
                        </p>
                        <Show when=move || entries.loading.get() && search_data.get().is_none()>
                            <SkeletonBox class="h-36" />
                        </Show>
                        <div
                            class="rounded-xl border border-dashed border-[var(--af-border-hairline)] min-h-36 p-3"
                            class=("bg-cyan-500/10", move || dragging.get())
                            on:dragover=move |event: web_sys::DragEvent| {
                                event.prevent_default();
                                dragging.set(true);
                            }
                            on:dragleave=move |event: web_sys::DragEvent| {
                                event.prevent_default();
                                dragging.set(false);
                            }
                            on:drop=move |event: web_sys::DragEvent| {
                                event.prevent_default();
                                dragging.set(false);
                                if let Some(files) = event.data_transfer().and_then(|data| data.files())
                                {
                                    upload_files(files);
                                }
                            }
                        >
                            <p class="text-xs text-slate-500 mb-3">
                                {move || tt(
                                    context,
                                    "Drop files here to upload to the current folder.",
                                )}
                            </p>
                            <div class=move || {
                                if grid.get() {
                                    "grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3"
                                } else {
                                    "flex flex-col"
                                }
                            }>
                                <For
                                    each=move || sorted.get()
                                    key=move |row| (
                                        context.active_server_id.get(),
                                        text(row, "path"),
                                        row["size"].as_u64().unwrap_or(0),
                                        text(row, "modified"),
                                    )
                                    children=move |row| {
                                        let row = StoredValue::new(row);
                                        let thumb_failed = RwSignal::new(false);
                                        let thumb_path = row.with_value(|row| {
                                            let row_path = text(row, "path");
                                            let size = row["size"].as_u64().unwrap_or(0);
                                            if row["kind"] != "directory"
                                                && media_kind(&row_path) == "image"
                                                && size <= MAX_THUMBNAIL_SOURCE_BYTES
                                            {
                                                Some(encode(&row_path))
                                            } else {
                                                None
                                            }
                                        });
                                        let thumb_alt = row.with_value(|row| text(row, "name"));
                                        view! {
                                            <div class=move || {
                                                if grid.get() {
                                                    "af-surface-inset flex flex-col gap-2 p-3 min-w-0"
                                                } else {
                                                    "flex flex-wrap items-center gap-3 p-3 border-b border-[var(--af-border-hairline)] min-w-0"
                                                }
                                            }>
                                                {thumb_path.clone().map(|encoded| {
                                                    let alt = thumb_alt.clone();
                                                    view! {
                                                        <Show when=move || grid.get() && can("read") && !thumb_failed.get()>
                                                            <button
                                                                type="button"
                                                                class="af-surface-inset w-full overflow-hidden"
                                                                on:click=move |_| open_entry.run(row.get_value())
                                                            >
                                                                <img
                                                                    src={
                                                                        let encoded = encoded.clone();
                                                                        move || {
                                                                            context.active_server_id.track();
                                                                            mcbrowser_preview_thumb_url_encoded(&encoded)
                                                                        }
                                                                    }
                                                                    alt=alt.clone()
                                                                    loading="lazy"
                                                                    decoding="async"
                                                                    class="w-full h-36 object-cover"
                                                                    data-testid="mcbrowser-grid-thumb"
                                                                    on:error=move |_| thumb_failed.set(true)
                                                                />
                                                            </button>
                                                        </Show>
                                                    }
                                                })}
                                                <div class="flex flex-wrap items-center gap-3 min-w-0 w-full">
                                                <input
                                                    type="checkbox"
                                                    aria-label=move || {
                                                        row.with_value(|row| tt_with(
                                                            context,
                                                            "Select {name}",
                                                            &[("name", &text(row, "name"))],
                                                        ))
                                                    }
                                                    prop:checked=move || {
                                                        selected
                                                            .with(|selection| {
                                                                selection.contains(&row.with_value(|row| text(row, "path")))
                                                            })
                                                    }
                                                    on:change=move |event| {
                                                        let checked = event_target_checked(&event);
                                                        let target = row.with_value(|row| text(row, "path"));
                                                        selected
                                                            .update(|selection| {
                                                                if checked {
                                                                    selection.insert(target);
                                                                } else {
                                                                    selection.remove(&target);
                                                                }
                                                            });
                                                    }
                                                />
                                                <div class="flex-1 min-w-0">
                                                    <button
                                                        type="button"
                                                        class="text-left font-medium text-sm text-cyan-200 break-all"
                                                        disabled=move || !can("read")
                                                        on:click=move |_| open_entry.run(row.get_value())
                                                    >
                                                        {move || {
                                                            row.with_value(|row| {
                                                                format!(
                                                                    "{} {}",
                                                                    tt(
                                                                        context,
                                                                        if row["kind"] == "directory" {
                                                                            "Directory"
                                                                        } else if row["kind"] == "symlink" {
                                                                            "Link"
                                                                        } else {
                                                                            "File"
                                                                        },
                                                                    ),
                                                                    text(row, "name"),
                                                                )
                                                            })
                                                        }}
                                                    </button>
                                                    <p class="text-xs text-slate-400 break-all">
                                                        {move || {
                                                            row.with_value(|row| {
                                                                format!(
                                                                    "{} · {} · {}",
                                                                    tt(context, &text(row, "kind")),
                                                                    bytes(row["size"].as_u64().unwrap_or(0)),
                                                                    text(row, "modified"),
                                                                )
                                                            })
                                                        }}
                                                    </p>
                                                    <Show when=move || search_data.get().is_some()>
                                                        <p class="text-xs text-slate-500 break-all">
                                                            {row.with_value(|row| text(row, "path"))}
                                                        </p>
                                                    </Show>
                                                </div>
                                                {row
                                                    .with_value(|row| {
                                                        (row["kind"] != "directory")
                                                            .then(|| {
                                                                let encoded = encode(&text(row, "path"));
                                                                view! {
                                                                    <Show when=move || can("download")>
                                                                        <a
                                                                            class="af-btn text-xs px-3 py-2"
                                                                            href={
                                                                                let encoded = encoded.clone();
                                                                                move || {
                                                                                    context.active_server_id.track();
                                                                                    mcbrowser_download_url_encoded(&encoded)
                                                                                }
                                                                            }
                                                                            download
                                                                        >
                                                                            {move || tt(context, "Common.download")}
                                                                        </a>
                                                                    </Show>
                                                                }
                                                            })
                                                    })}
                                                </div>
                                            </div>
                                        }
                                    }
                                />
                            </div>
                            <Show when=move || !entries.loading.get() && sorted.with(Vec::is_empty)>
                                <EmptyState
                                    title="No matching entries"
                                    description="Create a folder, upload files, or change the search."
                                />
                            </Show>
                        </div>
                    </ObsCard>
                    <Show when=move || !actions.results.with(Vec::is_empty)>
                        <ObsCard title=Signal::derive(move || tt(
                            context,
                            "McBrowser.operationResults",
                        ))>
                            <div class="space-y-3 max-h-80 overflow-auto">
                                {move || {
                                    actions
                                        .results
                                        .get()
                                        .into_iter()
                                        .map(|result| {
                                            let summary = result.clone();
                                            view! {
                                                <div class="text-xs border-b border-[var(--af-border-hairline)] pb-2">
                                                    <p class="font-medium break-all">
                                                        {move || format!(
                                                            "{} · {}",
                                                            text(&summary, "path"),
                                                            tt(context, &text(&summary, "status")),
                                                        )}
                                                    </p>
                                                    <pre class="whitespace-pre-wrap break-words text-slate-400">
                                                        {serde_json::to_string_pretty(
                                                                result.get("details").unwrap_or(&result),
                                                            )
                                                            .unwrap_or_default()}
                                                    </pre>
                                                </div>
                                            }
                                        })
                                        .collect_view()
                                }}
                            </div>
                        </ObsCard>
                    </Show>
                </Show>
                <Show when=move || context.is_admin() && subtab.get() == "policy">
                    <PolicyAdmin />
                </Show>
                <Show when=move || context.is_admin() && subtab.get() == "events">
                    <EventsAdmin />
                </Show>
            </TabPanel>
            <TransferPanel queue />
            <EditorPanel
                editor
                editor_theme
                readonly=Signal::derive(move || {
                    !can("modify") || !context.can_write_area(crate::state::PeerArea::Files)
                })
            />
            <MediaPreview
                open=media_open
                path=media_path
                items=previewable_items
                can_download=Signal::derive(move || can("download"))
                on_edit=open_in_editor
            />
            <ActionsDialog actions />
            <ShareCreateModal
                open=share_open
                initial_path=share_path
                on_created=Callback::new(move |row| {
                    if let Some(url) =
                        crate::tabs::fileshare::share_url_for_context_untracked(context, &row)
                    {
                        share_preview_url.set(url);
                    }
                    refresh.run(());
                })
            />
            <Show when=move || !share_preview_url.get().is_empty()>
                <button
                    type="button"
                    class="af-btn px-3 py-2"
                    on:click=move |_| share_preview.set(true)
                >
                    {move || tt(context, "Last created share URL / QR")}
                </button>
            </Show>
            <Modal open=share_preview title="Public share">
                <ShareLinkDetails url=share_preview_url />
            </Modal>
            <ConfirmDialog
                open=switch_editor
                title="Discard unsaved changes?"
                message="Opening another file will discard the current unsaved draft."
                busy=editor.saving
                on_confirm=Callback::new(move |()| {
                    editor.content.set(editor.baseline.get_untracked());
                    switch_editor.set(false);
                    editor.load(pending_editor.get_untracked());
                })
            />
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_names_reject_traversal_and_reserved_upload_paths() {
        assert_eq!(
            name_path("documents", "report.pdf").unwrap(),
            "documents/report.pdf"
        );
        for name in [
            "..",
            ".",
            "nested/file",
            "bad\\name",
            ".af-upload-tmp.secret",
            "",
        ] {
            assert!(name_path("documents", name).is_err(), "{name}");
        }
        assert_eq!(parent("documents/report.pdf"), "documents");
        assert_eq!(leaf("documents/report.pdf"), "report.pdf");
    }

    #[test]
    fn preview_kinds_recognize_pdfs_without_treating_markup_as_media() {
        assert_eq!(media_kind("Reports/ANNUAL.PDF"), "pdf");
        assert_eq!(media_kind("photo.avif"), "image");
        assert_eq!(media_kind("movie.mkv"), "video");
        assert_eq!(media_kind("track.flac"), "audio");
        assert_eq!(media_kind("metrics/export.csv"), "csv");
        assert_eq!(media_kind("metrics/export.TSV"), "csv");
        assert_eq!(media_kind("books/manual.epub"), "epub");
        assert_eq!(media_kind("document.html"), "");
        assert_eq!(media_kind("README"), "");
    }

    #[test]
    fn mcbrowser_subtab_resolution_gates_admin_routes() {
        assert_eq!(resolve_mcbrowser_subtab("policy", true), "policy");
        assert_eq!(resolve_mcbrowser_subtab("events", true), "events");
        assert_eq!(resolve_mcbrowser_subtab("policy", false), "workspace");
        assert_eq!(resolve_mcbrowser_subtab("events", false), "workspace");
        assert_eq!(resolve_mcbrowser_subtab("unknown", true), "workspace");
    }

    #[test]
    fn tus_checksum_encoding_and_retryable_transfer_states_are_stable() {
        assert_eq!(base64(&[]), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert!(TransferStatus::Completed.terminal());
        assert!(TransferStatus::Cancelled.terminal());
        assert!(!TransferStatus::Uncertain.terminal());
        assert!(!TransferStatus::Paused.terminal());
        assert!(!TransferStatus::Failed.terminal());
    }

    struct ActiveServerGuard;
    impl ActiveServerGuard {
        fn new(server: Option<&str>) -> Self {
            af_web_core::api::set_active_server(server.map(str::to_string));
            Self
        }
    }
    impl Drop for ActiveServerGuard {
        fn drop(&mut self) {
            af_web_core::api::set_active_server(None);
        }
    }

    #[test]
    fn grid_thumbnail_and_download_urls_route_active_peer_and_preserve_local() {
        let _guard = ActiveServerGuard::new(None);
        assert_eq!(
            mcbrowser_preview_thumb_url_encoded("gallery%2Fshot%201.png"),
            "/api/v1/auth/mcbrowser/preview/thumb?path=gallery%2Fshot%201.png"
        );
        assert_eq!(
            mcbrowser_download_url_encoded("gallery%2Fshot%201.png"),
            "/api/v1/auth/mcbrowser/download?path=gallery%2Fshot%201.png"
        );

        af_web_core::api::set_active_server(Some("media-2".into()));
        assert_eq!(
            mcbrowser_preview_thumb_url_encoded("gallery%2Fshot%201.png"),
            "/api/v1/peers/media-2/auth/mcbrowser/preview/thumb?path=gallery%2Fshot%201.png"
        );
        assert_eq!(
            mcbrowser_download_url_encoded("gallery%2Fshot%201.png"),
            "/api/v1/peers/media-2/auth/mcbrowser/download?path=gallery%2Fshot%201.png"
        );
    }
}
