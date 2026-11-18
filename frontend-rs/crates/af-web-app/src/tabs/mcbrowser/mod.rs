//! Private filesystem workspace. Mutations use the authenticated API, TUS
//! transfers reconcile server offsets, and editor drafts retain their read ETag.
use super::fileshare::{
    encode, relative_path, share_url, text, ShareCreateModal, ShareLinkDetails,
};
use crate::state::{app, json_rows, use_api, worker_pool, ApiResource, AppContext};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{
    Badge, ConfirmDialog, DataGrid, Drawer, EmptyState, Modal, ObsCard, SearchInput, TabPanel,
    TabsBar,
};
use af_web_core::{
    api::{ApiClient, ApiError},
    draft::FormDraft,
    worker::{WorkerRequest, WorkerResponse, MAX_EDITOR_BYTES},
};
use af_web_ui::{use_worker_rows, GridColumn, SkeletonBox};
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

#[component]
pub fn McBrowserTab() -> impl IntoView {
    let context = app();
    let path = RwSignal::new(String::new());
    let entries = use_api(Signal::derive(move || {
        format!("{BASE}/entries?path={}", encode(&path.get()))
    }));
    let usage = use_api(format!("{BASE}/usage"));
    let policy = use_api(format!("{BASE}/policy"));
    let subtab = RwSignal::new("workspace".to_owned());
    let refresh = Callback::new(move |()| {
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
        if query.is_empty() || search_busy.get_untracked() {
            return;
        }
        search_generation.update(|generation| *generation += 1);
        let ticket = search_generation.get_untracked();
        let auth = context.session_epoch.get_untracked();
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
        if !media_kind(&target).is_empty() {
            media_path.set(target);
            media_open.set(true);
            return;
        }
        if row["size"].as_u64().unwrap_or(0) > MAX_EDITOR_BYTES as u64 {
            context.toast(
                tt(
                    context,
                    "Text editing is limited to 256 KiB. Download larger files.",
                ),
                true,
            );
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
    let upload_files = move |files: web_sys::FileList| {
        if !can("create") {
            context.toast(tt(context, "Upload permission is required."), true);
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
                    class="glass-button px-4 py-2"
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
                                    class="glass-button px-3 py-2"
                                    disabled=move || path.get().is_empty()
                                    on:click=move |_| path.set(parent(&path.get_untracked()).to_owned())
                                >
                                    {move || tt(context, "Common.up")}
                                </button>
                                <button
                                    type="button"
                                    class="glass-button px-3 py-2"
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
                                class="glass-button px-3 py-2"
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
                                                class="glass-button px-3 py-2"
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
                            class="rounded-xl border border-dashed border-white/15 min-h-36 p-3"
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
                                    key=|row| (
                                        text(row, "path"),
                                        row["size"].as_u64().unwrap_or(0),
                                        text(row, "modified"),
                                    )
                                    children=move |row| {
                                        let row = StoredValue::new(row);
                                        view! {
                                            <div class="flex flex-wrap items-center gap-3 p-3 border-b border-white/5 min-w-0">
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
                                                                let href = format!(
                                                                    "{BASE}/download?path={}",
                                                                    encode(&text(row, "path")),
                                                                );
                                                                view! {
                                                                    <Show when=move || can("download")>
                                                                        <a
                                                                            class="glass-button text-xs px-3 py-2"
                                                                            href=href.clone()
                                                                            download
                                                                        >
                                                                            {move || tt(context, "Common.download")}
                                                                        </a>
                                                                    </Show>
                                                                }
                                                            })
                                                    })}
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
                                                <div class="text-xs border-b border-white/10 pb-2">
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
            <EditorPanel editor readonly=Signal::derive(move || !can("modify")) />
            <MediaPreview open=media_open path=media_path />
            <ActionsDialog actions />
            <ShareCreateModal
                open=share_open
                initial_path=share_path
                on_created=Callback::new(move |row| {
                    if let Some(url) = share_url(&row) {
                        share_preview_url.set(url);
                    }
                    refresh.run(());
                })
            />
            <Show when=move || !share_preview_url.get().is_empty()>
                <button
                    type="button"
                    class="glass-button px-3 py-2"
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
        assert_eq!(media_kind("document.html"), "");
        assert_eq!(media_kind("README"), "");
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
}
