use super::*;

#[component]
pub(super) fn MetadataSettings() -> impl IntoView {
    let context = app();
    let results = use_api("/api/v1/admin/ai/metadata/results".to_string());
    let status = use_api("/api/v1/admin/ai/metadata/status".to_string());
    poll_resource(status, 2000);
    let draft = RwSignal::new(FormDraft::new(json!({"path":""})));
    let busy = RwSignal::new(false);
    let was_scanning = RwSignal::new(false);
    Effect::new(move |_| {
        let scanning = status.data.with(|v| v["scanning"] == true);
        if was_scanning.get_untracked() && !scanning {
            results.refresh();
        }
        was_scanning.set(scanning);
    });
    view! {
        <ObsCard title=Signal::derive(move || tt(context, "Settings.metadataEnrichment"))>
            <form
                class="flex flex-wrap gap-4 items-end"
                on:submit=move |event| {
                    event.prevent_default();
                    if busy.get_untracked() {
                        return;
                    }
                    let sent = draft_value(draft);
                    busy.set(true);
                    let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
                    spawn_local(async move {
                        match ApiClient.post("/api/v1/admin/ai/metadata/scan", Some(&sent)).await {
                            Ok(_) => {
                                if busy.try_get_untracked().is_none() {
                                    return;
                                }
                                status.refresh();
                                context.toast(tt(context, "Metadata scan started"), false);
                            }
                            Err(error) => context.toast(tt(context, &error.message), true),
                        }
                        if busy.try_get_untracked().is_some() {
                            busy_guard.release();
                        }
                    });
                }
            >
                <DraftInput draft field="path" label="Media directory" required=true />
                <button
                    type="submit"
                    class="glass-button-primary px-4 py-2"
                    disabled=move || busy.get() || status.data.with(|v| v["scanning"] == true)
                >
                    {move || tt(context, "Scan metadata")}
                </button>
            </form>
            <ResourceFeedback resource=status />
            <ResourceFeedback resource=results />
            <p role="status" class="text-sm text-slate-400 my-4">
                {move || {
                    status
                        .data
                        .with(|v| {
                            format!(
                                "{} / {} · {}% · {}",
                                text(v, "done"),
                                text(v, "total"),
                                text(v, "progress"),
                                text(v, "error"),
                            )
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
