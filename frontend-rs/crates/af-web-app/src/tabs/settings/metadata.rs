use super::*;

#[component]
pub(super) fn MetadataSettings() -> impl IntoView {
    let context = app();
    let can_read_settings = Signal::derive(move || context.can_read_area(PeerArea::Settings));
    let can_read_files = Signal::derive(move || context.can_read_area(PeerArea::Files));
    let results = use_api_when(
        can_read_settings,
        "/api/v1/admin/ai/metadata/results".to_string(),
    );
    let status = use_api_when(
        can_read_settings,
        "/api/v1/admin/ai/metadata/status".to_string(),
    );
    poll_resource_when(status, 2000, move || {
        context.can_read_area_untracked(PeerArea::Settings)
    });
    let draft = RwSignal::new(FormDraft::new(json!({"path":""})));
    let picker = RwSignal::new(false);
    let current_path = RwSignal::new("/".to_string());
    let busy = RwSignal::new(false);
    let scan_ticket = RwSignal::new(0u64);
    let was_scanning = RwSignal::new(false);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Settings);
        scan_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        busy.set(false);
        picker.set(false);
        was_scanning.set(false);
    });
    Effect::new(move |_| {
        if !context.can_write_area(PeerArea::Settings) {
            scan_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            busy.set(false);
        }
    });
    Effect::new(move |_| {
        context.area_revocation_epoch(PeerArea::Files);
        if !can_read_files.get() {
            picker.set(false);
        }
    });
    Effect::new(move |_| {
        if !can_read_settings.get() {
            was_scanning.set(false);
            return;
        }
        let scanning = status.data.with(|v| v["scanning"] == true);
        if was_scanning.get_untracked() && !scanning {
            results.refresh();
        }
        was_scanning.set(scanning);
    });
    view! {
        <ObsCard title=Signal::derive(move || tt(context, "Settings.metadataEnrichment"))>
            <Show when=move || !can_read_settings.get()>
                <p role="status" class="text-xs text-amber-300 mb-3">
                    {move || {
                        context
                            .area_block_reason(PeerArea::Settings, false)
                            .unwrap_or_default()
                    }}
                </p>
            </Show>
            <form
                class="flex flex-wrap gap-4 items-end"
                on:submit=move |event| {
                    event.prevent_default();
                    if busy.get_untracked() || !context.can_write_area(PeerArea::Settings) {
                        return;
                    }
                    let sent = draft_value(draft);
                    let session_epoch = context.session_epoch.get_untracked();
                    let server_epoch = context.server_epoch.get_untracked();
                    let settings_grant =
                        context.area_revocation_epoch_untracked(PeerArea::Settings);
                    scan_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
                    let ticket = scan_ticket.get_untracked();
                    busy.set(true);
                    let mut busy_guard =
                        crate::tabs::busy::BusyGuard::for_generation(busy, scan_ticket, ticket);
                    spawn_local(async move {
                        let result = ApiClient.post("/api/v1/admin/ai/metadata/scan", Some(&sent)).await;
                        if busy.try_get_untracked().is_none()
                            || scan_ticket.try_get_untracked() != Some(ticket)
                            || context.session_epoch.try_get_untracked() != Some(session_epoch)
                            || context.server_epoch.try_get_untracked() != Some(server_epoch)
                            || context.area_revocation_epoch_untracked(PeerArea::Settings)
                                != settings_grant
                            || !context.can_write_area_untracked(PeerArea::Settings)
                        {
                            return;
                        }
                        match result {
                            Ok(_) => {
                                if context.can_read_area_untracked(PeerArea::Settings) {
                                    status.refresh();
                                }
                                context.toast(tt(context, "Metadata scan started"), false);
                            }
                            Err(error) => context.toast(tt(context, &error.message), true),
                        }
                        busy_guard.release();
                    });
                }
            >
                <DraftInput draft field="path" label="Media directory" required=true />
                <button
                    type="button"
                    class="af-btn px-3 py-2"
                    disabled=move || !can_read_files.get()
                    title=move || {
                        context
                            .area_block_reason(PeerArea::Files, false)
                            .unwrap_or_default()
                    }
                    on:click=move |_| {
                        if !context.can_read_area_untracked(PeerArea::Files) {
                            return;
                        }
                        let path = text(&draft_value(draft), "path");
                        current_path.set(if path.starts_with('/') { path } else { "/".into() });
                        picker.set(true);
                    }
                >
                    {move || tt(context, "Browse Directories")}
                </button>
                <button
                    type="submit"
                    class="af-btn-primary px-4 py-2"
                    disabled=move || {
                        busy.get()
                            || status.data.with(|v| v["scanning"] == true)
                            || !context.can_write_area(PeerArea::Settings)
                    }
                    title=move || {
                        context
                            .area_block_reason(PeerArea::Settings, true)
                            .unwrap_or_default()
                    }
                >
                    {move || tt(context, "Scan metadata")}
                </button>
            </form>
            <Show when=move || !can_read_files.get()>
                <p role="status" class="text-xs text-amber-300 mt-2">
                    {move || {
                        context
                            .area_block_reason(PeerArea::Files, false)
                            .unwrap_or_default()
                    }}
                </p>
            </Show>
            <Modal open=picker title="Browse Directories">
                <Show when=move || picker.get() && can_read_files.get()>
                    <p class="break-all">{move || current_path.get()}</p>
                    <button type="button" class="af-btn px-3 py-2" disabled=move || current_path.get() == "/"
                        on:click=move |_| current_path.update(|p| *p = crate::tabs::fileshare::parent_path(p))>{move || tt(context, "Up")}</button>
                    <crate::tabs::fileshare::DirectoryPicker current_path />
                    <button type="button" class="af-btn-primary px-3 py-2" on:click=move |_| {
                        edit(draft, "path", json!(current_path.get_untracked()));
                        picker.set(false);
                    }>{move || tt(context, "Use this directory")}</button>
                </Show>
            </Modal>
            <ResourceFeedback resource=status />
            <ResourceFeedback resource=results />
            <p role="status" class="text-sm text-slate-400 my-4">
                {move || {
                    status
                        .data
                        .with(|v| {
                            let err = text(v, "error");
                            if !err.is_empty() { return err; }
                            if v["scanning"] != true && v["total"].as_u64().unwrap_or(0) == 0 { return tt(context, "Idle"); }
                            format!("{} / {} · {}%", text(v, "done"), text(v, "total"), text(v, "progress"))
                        })
                }}
            </p>
            <DataGrid
                label="Enriched media metadata"
                columns=vec![
                    GridColumn::new("filename", "File"),
                    GridColumn::new("title", "Title"),
                    GridColumn::new("year", "Year"),
                    GridColumn::new("language", "Language"),
                    GridColumn::new("quality", "Quality"),
                    GridColumn::new("enriched_at", "Enriched"),
                ]
                rows=Signal::derive(move || json_rows(&results.data.get()))
            />
        </ObsCard>
    }
}
