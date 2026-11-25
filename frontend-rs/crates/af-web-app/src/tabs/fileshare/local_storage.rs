//! Host directory navigation, file listing, and cancellable upload UI.
use super::paths::*;
use super::storage::host_storage;
use super::types::*;
use super::upload::{browser_error, stream_upload, upload_id, MAX_UPLOAD_BYTES};
use crate::state::{app, use_api_when, PeerArea};
use crate::tabs::l10n::{tt, tt_with, ConfirmDialog, EmptyState, ObsCard};
use crate::tabs::settings::{bytes, ResourceFeedback};
use af_web_core::api::{api_url, ApiClient};
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;
#[component]
pub(crate) fn DirectoryPicker(current_path: RwSignal<String>) -> impl IntoView {
    let context = app();
    let can_read_files = Signal::derive(move || context.can_read_area(PeerArea::Files));
    let resource = use_api_when(
        can_read_files,
        Signal::derive(move || format!("/api/v1/auth/fs?path={}", encode(&current_path.get()))),
    );
    view! {
        <div
            class="af-surface-inset p-3 max-h-64 overflow-auto space-y-1"
            aria-label=move || tt(context, "Directory picker")
        >
            <Show when=move || !can_read_files.get()>
                <p role="status" class="text-xs text-amber-300 p-2">
                    {move || {
                        context
                            .area_block_reason(PeerArea::Files, false)
                            .unwrap_or_default()
                    }}
                </p>
            </Show>
            <ResourceFeedback resource />
            {move || {
                (if !can_read_files.get() || resource.loading.get() || resource.error.get().is_some() {
                    Vec::new()
                } else {
                    directory_names(&resource.data.get())
                })
                    .into_iter()
                    .map(|name| {
                        let label = name.clone();
                        view! {
                            <button
                                type="button"
                                class="block text-left af-btn px-3 py-2 w-full break-all"
                                on:click=move |_| {
                                    match child_path(&current_path.get_untracked(), &name) {
                                        Ok(path) => current_path.set(path),
                                        Err(error) => context.toast(tt(context, &error), true),
                                    }
                                }
                            >
                                {label}
                            </button>
                        }
                    })
                    .collect_view()
            }}
            <Show when=move || {
                can_read_files.get()
                    && !resource.loading.get()
                    && resource.error.get().is_none()
                    && directory_names(&resource.data.get()).is_empty()
            }>
                <p class="text-sm text-slate-400 p-2">
                    {move || tt(context, "No subdirectories in this path.")}
                </p>
            </Show>
        </div>
    }
}

fn fileshare_download_url_encoded(encoded_name: &str, encoded_path: &str) -> String {
    api_url(&format!(
        "/api/v1/auth/fileshare/download/{encoded_name}?path={encoded_path}"
    ))
}

#[component]
pub(super) fn LocalStorage() -> impl IntoView {
    let context = app();
    let can_read_files = Signal::derive(move || context.can_read_area(PeerArea::Files));
    let current_path = RwSignal::new("/".to_owned());
    let manual_path = RwSignal::new("/".to_owned());
    let picker_open = RwSignal::new(false);
    let listing = use_api_when(
        can_read_files,
        Signal::derive(move || {
            format!(
                "/api/v1/auth/fileshare?path={}",
                encode(&current_path.get())
            )
        }),
    );
    let files = Memo::new(move |_| parse_files(&listing.data.get()));
    let rows = Signal::derive(move || {
        if !can_read_files.get() || listing.loading.get() || listing.error.get().is_some() {
            Vec::new()
        } else {
            files.get().unwrap_or_default()
        }
    });
    let observed_bytes = Signal::derive(move || {
        rows.with(|rows| {
            rows.iter()
                .filter(|file| !file.is_dir)
                .map(|file| file.size)
                .fold(0u64, u64::saturating_add)
        })
    });
    let storage = Memo::new(move |_| host_storage(&context.metrics.get(), observed_bytes.get()));
    let used = Signal::derive(move || storage.get().used_bytes);
    let used_pct = Signal::derive(move || storage.get().percent().unwrap_or_default());
    let dragging = RwSignal::new(false);
    let uploading = RwSignal::new(false);
    let progress = RwSignal::new(0u32);
    let controller = StoredValue::new_local(None::<web_sys::AbortController>);
    let upload_epoch = StoredValue::new((
        context.session_epoch.get_untracked(),
        context.server_epoch.get_untracked(),
        context.area_revocation_epoch_untracked(PeerArea::Files),
    ));
    let input = NodeRef::<leptos::html::Input>::new();
    let delete_open = RwSignal::new(false);
    let deleting = RwSignal::new(false);
    let upload_ticket = RwSignal::new(0u64);
    let delete_ticket = RwSignal::new(0u64);
    let delete_target = RwSignal::new(None::<(String, String)>);
    Effect::new(move |_| {
        let next = (
            context.session_epoch.get(),
            context.server_epoch.get(),
            context.area_revocation_epoch(PeerArea::Files),
        );
        let can_read = can_read_files.get();
        let can_write = context.can_write_area(PeerArea::Files);
        if upload_epoch.get_value() != next || !can_read || !can_write {
            controller.update_value(|controller| {
                if let Some(controller) = controller.take() {
                    controller.abort();
                }
            });
            upload_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            delete_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            uploading.set(false);
            deleting.set(false);
            progress.set(0);
            delete_open.set(false);
            delete_target.set(None);
            if upload_epoch.get_value() != next || !can_read {
                current_path.set("/".to_owned());
                picker_open.set(false);
            }
            upload_epoch.set_value(next);
        }
    });
    Effect::new(move |_| manual_path.set(current_path.get()));
    on_cleanup(move || {
        controller.update_value(|controller| {
            if let Some(controller) = controller.take() {
                controller.abort();
            }
        })
    });
    let upload = Callback::new(move |file: web_sys::File| {
        if !context.is_admin() || !context.can_write_area_untracked(PeerArea::Files) {
            context.toast(
                context
                    .area_block_reason(PeerArea::Files, true)
                    .unwrap_or_else(|| tt(context, "Admin role required for host writes")),
                true,
            );
            return;
        }
        if uploading.get_untracked() {
            return;
        }
        if file.size() > MAX_UPLOAD_BYTES as f64 {
            context.toast(tt(context, "File exceeds the 50 MiB upload limit."), true);
            return;
        }
        let id = match upload_id() {
            Ok(id) => id,
            Err(error) => {
                context.toast(tt(context, &error), true);
                return;
            }
        };
        let abort = match web_sys::AbortController::new() {
            Ok(controller) => controller,
            Err(error) => {
                context.toast(tt(context, &browser_error(error)), true);
                return;
            }
        };
        let signal = abort.signal();
        controller.set_value(Some(abort));
        upload_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = upload_ticket.get_untracked();
        uploading.set(true);
        progress.set(0);
        let path = current_path.get_untracked();
        let auth = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let files_grant = context.area_revocation_epoch_untracked(PeerArea::Files);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(uploading, upload_ticket, ticket);
        spawn_local(async move {
            let result = stream_upload(context, &file, &path, &id, &signal, progress).await;
            if uploading.try_get_untracked().is_none()
                || upload_ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Files) != files_grant
                || !context.can_write_area_untracked(PeerArea::Files)
            {
                return;
            }
            busy_guard.release();
            controller.set_value(None);
            if signal.aborted() {
                context.toast(tt(context, "Upload cancelled."), false);
            } else {
                match result {
                    Ok(()) => {
                        context.toast(
                            tt_with(
                                context,
                                "Uploaded {name} successfully",
                                &[("name", &(file.name()).to_string())],
                            ),
                            false,
                        );
                        if context.can_read_area_untracked(PeerArea::Files) {
                            listing.refresh();
                        }
                    }
                    Err(error) => context.toast(tt(context, &error), true),
                }
            }
            progress.set(0);
        });
    });
    let remove = Callback::new(move |()| {
        if !context.is_admin()
            || !context.can_write_area_untracked(PeerArea::Files)
            || deleting.get_untracked()
        {
            return;
        }
        let Some((path, name)) = delete_target.get_untracked() else {
            return;
        };
        delete_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = delete_ticket.get_untracked();
        deleting.set(true);
        let auth = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let files_grant = context.area_revocation_epoch_untracked(PeerArea::Files);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(deleting, delete_ticket, ticket);
        spawn_local(async move {
            let result = ApiClient
                .delete(
                    &format!(
                        "/api/v1/admin/fileshare/{}?path={}",
                        encode(&name),
                        encode(&path)
                    ),
                    None,
                )
                .await;
            if deleting.try_get_untracked().is_none()
                || delete_ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Files) != files_grant
                || !context.can_write_area_untracked(PeerArea::Files)
            {
                return;
            }
            busy_guard.release();
            match result {
                Ok(_) => {
                    delete_open.set(false);
                    context.toast(
                        tt_with(context, "Deleted {name}", &[("name", &(name).to_string())]),
                        false,
                    );
                    if context.can_read_area_untracked(PeerArea::Files) {
                        listing.refresh();
                    }
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
        });
    });
    let enter =
        Callback::new(
            move |name: String| match child_path(&current_path.get_untracked(), &name) {
                Ok(path) => current_path.set(path),
                Err(error) => context.toast(tt(context, &error), true),
            },
        );
    view! {
        <div class="space-y-5 min-w-0 max-w-full">
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
            <div class="flex flex-wrap justify-between gap-3 items-center">
                <p class="text-sm text-slate-400 break-all">
                    {move || {
                        tt_with(
                            context,
                            "Fileshare.liveFilesystemSummary",
                            &[("count", &rows.with(Vec::len).to_string()), ("path", &current_path.get())],
                        )
                    }}
                </p>
                <div class="flex gap-2">
                    <button
                        type="button"
                        class="af-btn-primary px-4 py-2"
                        disabled=move || {
                            !context.is_admin()
                                || uploading.get()
                                || !context.can_write_area(PeerArea::Files)
                        }
                        title=move || {
                            context
                                .area_block_reason(PeerArea::Files, true)
                                .unwrap_or_else(|| tt(context, "Admin role required for host writes"))
                        }
                        on:click=move |_| {
                            if let Some(input) = input.get() {
                                input.click();
                            }
                        }
                    >
                        {move || tt(context, "Upload File")}
                    </button>
                    <button
                        type="button"
                        class="af-btn px-4 py-2"
                        aria-label=move || tt(context, "Refresh Directory")
                        disabled=move || !can_read_files.get()
                        title=move || {
                            context
                                .area_block_reason(PeerArea::Files, false)
                                .unwrap_or_default()
                        }
                        on:click=move |_| {
                            if can_read_files.get_untracked() {
                                listing.refresh();
                            }
                        }
                    >
                        {move || tt(context, "Common.refresh")}
                    </button>
                </div>
            </div>
            <div class="grid sm:grid-cols-2 xl:grid-cols-4 gap-4">
                <ObsCard title=Signal::derive(move || tt(context, "Fileshare.usedCapacity"))>
                    <p class="text-2xl font-semibold text-cyan-300">
                        {move || bytes(used.get() as f64)}
                    </p>
                    <p class="text-xs text-slate-400">
                        {move || {
                            storage
                                .get()
                                .percent()
                                .map(|percent| format!("{percent:.1}%"))
                                .unwrap_or_else(|| tt(context, "Observed file bytes"))
                        }}
                    </p>
                    <progress
                        class="w-full accent-cyan-400"
                        aria-label=move || tt(context, "Used storage capacity")
                        max="100"
                        value=move || used_pct.get()
                    ></progress>
                </ObsCard>
                <ObsCard title=Signal::derive(move || tt(context, "Fileshare.totalCapacity"))>
                    <p class="text-2xl font-semibold">
                        {move || {
                            storage
                                .get()
                                .total_bytes
                                .map(|total| bytes(total as f64))
                                .unwrap_or_else(|| tt(context, "Unreported capacity"))
                        }}
                    </p>
                    <p class="text-xs text-slate-400">
                        {move || {
                            storage
                                .get()
                                .source
                                .unwrap_or_else(|| tt(context, "Host storage telemetry"))
                        }}
                    </p>
                </ObsCard>
                <ObsCard title=Signal::derive(move || tt(context, "Fileshare.totalFiles"))>
                    <p class="text-2xl font-semibold">
                        {move || rows.with(|rows| rows.iter().filter(|file| !file.is_dir).count())}
                    </p>
                    <p class="text-xs text-slate-400">
                        {move || {
                            rows.with(|rows| {
                                tt_with(
                                    context,
                                    "Fileshare.subdirectoriesCount",
                                    &[("count", &rows.iter().filter(|file| file.is_dir).count().to_string())],
                                )
                            })
                        }}
                    </p>
                </ObsCard>
                <ObsCard title=Signal::derive(move || tt(context, "Fileshare.uploadStatus"))>
                    <p class="font-semibold text-cyan-300">
                        {move || {
                            if uploading.get() {
                                tt_with(context, "Fileshare.uploadingProgress", &[("pct", &progress.get().to_string())])
                            } else {
                                tt(context, "Fileshare.readyIdle")
                            }
                        }}
                    </p>
                    <p class="text-xs text-slate-400">
                        {move || tt(context, "5 MiB Chunk Streaming · 50 MiB Max")}
                    </p>
                </ObsCard>
            </div>
            <ObsCard title=Signal::derive(move || tt(context, "Fileshare.directoryNavigation"))>
                <div class="flex flex-wrap gap-2 mb-4">
                    {["/", "/mnt", "/srv", "/var/backups", "/home"]
                        .into_iter()
                        .map(|path| {
                            view! {
                                <button
                                    type="button"
                                    class="af-btn px-3 py-2 text-sm"
                                    on:click=move |_| current_path.set(path.into())
                                >
                                    {path}
                                </button>
                            }
                        })
                        .collect_view()}
                </div>
                <form
                    class="flex flex-wrap gap-2 items-end"
                    on:submit=move |event| {
                        event.prevent_default();
                        match absolute_path(&manual_path.get_untracked()) {
                            Ok(path) => current_path.set(path),
                            Err(error) => context.toast(tt(context, &error), true),
                        }
                    }
                >
                    <label class="flex-1 min-w-0 text-sm space-y-2">
                        <span>{move || tt(context, "Current directory")}</span>
                        <input
                            class="af-input px-3 py-2 w-full"
                            prop:value=move || manual_path.get()
                            on:input=move |event| manual_path.set(event_target_value(&event))
                        />
                    </label>
                    <button type="submit" class="af-btn px-4 py-2">
                        {move || tt(context, "Go")}
                    </button>
                    <button
                        type="button"
                        class="af-btn px-4 py-2"
                        disabled=move || current_path.get() == "/"
                        on:click=move |_| {
                            current_path.set(parent_path(&current_path.get_untracked()))
                        }
                    >
                        {move || tt(context, "Up")}
                    </button>
                    <button
                        type="button"
                        class="af-btn px-4 py-2"
                        aria-expanded=move || picker_open.get().to_string()
                        disabled=move || !can_read_files.get()
                        title=move || {
                            context
                                .area_block_reason(PeerArea::Files, false)
                                .unwrap_or_default()
                        }
                        on:click=move |_| {
                            if can_read_files.get_untracked() {
                                picker_open.update(|open| *open = !*open);
                            }
                        }
                    >
                        {move || tt(context, "Browse Directories")}
                    </button>
                </form>
                <Show when=move || picker_open.get() && can_read_files.get()>
                    <div class="mt-3">
                        <DirectoryPicker current_path />
                    </div>
                </Show>
            </ObsCard>
            <Show when=move || !context.is_admin()>
                <p class="text-sm text-amber-300">
                    {move || tt(
                        context,
                        "Admin role required for host writes. Browsing and downloads remain available.",
                    )}
                </p>
            </Show>
            <input
                node_ref=input
                type="file"
                class="hidden"
                aria-label=move || tt(context, "Select file to upload")
                disabled=move || !context.is_admin() || uploading.get()
                on:change=move |event| {
                    let element = event_target::<web_sys::HtmlInputElement>(&event);
                    if let Some(file) = element.files().and_then(|files| files.item(0)) {
                        upload.run(file);
                    }
                    element.set_value("");
                }
            />
            <div
                class="rounded-xl border-2 border-dashed border-cyan-500/30 p-8 text-center space-y-3"
                class=("bg-cyan-500/10", move || dragging.get())
                on:dragover=move |event| {
                    event.prevent_default();
                    dragging.set(true);
                }
                on:dragleave=move |_| dragging.set(false)
                on:drop=move |event| {
                    event.prevent_default();
                    dragging.set(false);
                    if let Some(file) = event
                        .data_transfer()
                        .and_then(|data| data.files())
                        .and_then(|files| files.item(0))
                    {
                        upload.run(file);
                    }
                }
            >
                <h3 class="font-semibold">{move || tt(context, "Drop a file to upload")}</h3>
                <p class="text-sm text-slate-400">
                    {move || tt(
                        context,
                        "Stream directly to the selected directory in 5 MiB chunks.",
                    )}
                </p>
                <button
                    type="button"
                    class="af-btn px-4 py-2"
                    disabled=move || {
                        !context.is_admin()
                            || uploading.get()
                            || !context.can_write_area(crate::state::PeerArea::Files)
                    }
                    title=move || {
                        context
                            .area_block_reason(crate::state::PeerArea::Files, true)
                            .unwrap_or_default()
                    }
                    on:click=move |_| {
                        if let Some(input) = input.get() {
                            input.click();
                        }
                    }
                >
                    {move || tt(context, "Browse Local Files")}
                </button>
                <Show when=move || uploading.get()>
                    <div>
                        <progress
                            max="100"
                            aria-label=move || tt(context, "Upload progress")
                            value=move || progress.get()
                        ></progress>
                        <button
                            type="button"
                            class="af-btn px-4 py-2 ml-3"
                            on:click=move |_| {
                                controller
                                    .with_value(|controller| {
                                        if let Some(controller) = controller {
                                            controller.abort();
                                        }
                                    })
                            }
                        >
                            {move || tt(context, "Cancel upload")}
                        </button>
                    </div>
                </Show>
            </div>
            <ObsCard title=Signal::derive(move || tt(context, "Fileshare.localFiles"))>
                <ResourceFeedback resource=listing />
                {move || {
                    files
                        .get()
                        .err()
                        .map(|error| {
                            view! {
                                <p role="alert" class="text-sm text-rose-300">
                                    {move || tt(context, &error)}
                                </p>
                            }
                        })
                }}
                <Show when=move || rows.with(|rows| !rows.is_empty())>
                <div class="overflow-x-auto max-w-full">
                    <table class="w-full text-sm text-left">
                        <caption class="sr-only">
                            {move || tt(context, "Files and directories in the current path")}
                        </caption>
                        <thead class="text-slate-400">
                            <tr>
                                <th scope="col" class="p-3">{move || tt(context, "Name")}</th>
                                <th scope="col" class="p-3">{move || tt(context, "Size")}</th>
                                <th scope="col" class="p-3">{move || tt(context, "Modified")}</th>
                                <th scope="col" class="p-3">{move || tt(context, "Actions")}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {move || {
                                rows.get()
                                    .into_iter()
                                    .map(|file| {
                                        let row_name = file.name.clone();
                                        let enter_name = file.name.clone();
                                        let delete_name = file.name.clone();
                                        let download_name = file.name.clone();
                                        let is_dir = file.is_dir;
                                        let kind = if is_dir {
                                            "Directory"
                                        } else if file.extension.is_empty() {
                                            "File"
                                        } else {
                                            &file.extension
                                        }
                                            .to_owned();
                                        view! {
                                            <tr
                                                class="border-t border-[var(--af-border-hairline)]"
                                                class=("cursor-pointer", is_dir)
                                                on:click=move |_| {
                                                    if is_dir {
                                                        enter.run(row_name.clone());
                                                    }
                                                }
                                            >
                                                <td class="p-3 break-all">
                                                    <span class="text-xs text-cyan-300 mr-2">{move || tt(context, &kind)}</span>
                                                    <button
                                                        type="button"
                                                        class="text-left underline"
                                                        disabled=!is_dir
                                                        on:click=move |event| {
                                                            event.stop_propagation();
                                                            enter.run(enter_name.clone());
                                                        }
                                                    >
                                                        {file.name}
                                                    </button>
                                                </td>
                                                <td class="p-3 whitespace-nowrap">
                                                    {move || tt(
                                                        context,
                                                        &(if is_dir {
                                                            "Directory".into()
                                                        } else {
                                                            bytes(file.size as f64)
                                                        }),
                                                    )}
                                                </td>
                                                <td class="p-3">{file.mod_time}</td>
                                                <td class="p-3">
                                                    <div class="flex gap-2">
                                                        {(!is_dir)
                                                            .then(|| {
                                                                view! {
                                                                    <a
                                                                        class="af-btn px-3 py-2"
                                                                        href=move || {
                                                                            context.active_server_id.track();
                                                                            fileshare_download_url_encoded(
                                                                                &encode(&download_name),
                                                                                &encode(&current_path.get()),
                                                                            )
                                                                        }
                                                                        download=""
                                                                        on:click=move |event| event.stop_propagation()
                                                                    >
                                                                        {move || tt(context, "Common.download")}
                                                                    </a>
                                                                }
                                                            })}
                                                        <button
                                                            type="button"
                                                            class="af-btn px-3 py-2"
                                                            data-tone="danger"
                                                            disabled=move || {
                                                                !context.is_admin()
                                                                    || deleting.get()
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
                                                                    .unwrap_or_else(|| {
                                                                        tt(
                                                                            context,
                                                                            "Admin role required for host writes",
                                                                        )
                                                                    })
                                                            }
                                                            on:click=move |event| {
                                                                event.stop_propagation();
                                                                delete_target
                                                                    .set(
                                                                        Some((current_path.get_untracked(), delete_name.clone())),
                                                                    );
                                                                delete_open.set(true);
                                                            }
                                                        >
                                                            {move || tt(context, "Delete")}
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        }
                                    })
                                    .collect_view()
                            }}
                        </tbody>
                    </table>
                </div>
                </Show>
                <Show when=move || {
                    !listing.loading.get() && listing.error.get().is_none() && files.get().is_ok()
                        && rows.with(Vec::is_empty)
                }>
                    <EmptyState
                        title="This directory is empty"
                        description="Choose another directory or upload a file."
                    />
                </Show>
            </ObsCard>
            {move || {
                delete_open
                    .get()
                    .then(|| {
                        view! {
                            <ConfirmDialog
                                open=delete_open
                                title="Delete local file?"
                                message=delete_target
                                    .with(|target| {
                                        target
                                            .as_ref()
                                            .map(|(path, name)| {
                                                tt_with(context, "Permanently delete {name} from {path}?", &[("name", &(name).to_string()), ("path", &(path).to_string())])
                                            })
                                            .unwrap_or_default()
                                    })
                                busy=deleting
                                on_confirm=remove
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
    use af_web_core::api::set_active_server;

    struct ActiveServerGuard;
    impl ActiveServerGuard {
        fn new(server: Option<&str>) -> Self {
            set_active_server(server.map(str::to_string));
            Self
        }
    }
    impl Drop for ActiveServerGuard {
        fn drop(&mut self) {
            set_active_server(None);
        }
    }

    #[test]
    fn fileshare_download_url_preserves_encoded_query_and_routes_active_peer() {
        let _guard = ActiveServerGuard::new(None);
        assert_eq!(
            fileshare_download_url_encoded("archive%201.zip", "%2Fmnt%2Fmedia"),
            "/api/v1/auth/fileshare/download/archive%201.zip?path=%2Fmnt%2Fmedia"
        );

        set_active_server(Some("media-2".into()));
        assert_eq!(
            fileshare_download_url_encoded("archive%201.zip", "%2Fmnt%2Fmedia"),
            "/api/v1/peers/media-2/auth/fileshare/download/archive%201.zip?path=%2Fmnt%2Fmedia"
        );

        set_active_server(Some("peer/a b".into()));
        assert_eq!(
            fileshare_download_url_encoded("archive%201.zip", "%2Fmnt%2Fmedia"),
            "/api/v1/peers/peer%2Fa%20b/auth/fileshare/download/archive%201.zip?path=%2Fmnt%2Fmedia"
        );
    }
}
