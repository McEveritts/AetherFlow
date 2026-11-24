//! Snapshot-scoped history filters, pagination, and CSV/JSON exports.
use super::analytics::HistoryAnalytics;
use super::common::*;
use super::types::*;
use crate::state::{app, run_resource_read, worker_pool, ApiResource, PeerArea, ResourceReads};
use crate::tabs::contracts;
use crate::tabs::l10n::{tt, tt_with, DataGrid, ObsCard};
use af_web_core::api::ApiClient;
use af_web_core::worker::{WorkerRequest, WorkerResponse};
use af_web_ui::GridColumn;
use leptos::prelude::*;
use serde_json::Value;
use std::collections::BTreeMap;
use wasm_bindgen_futures::spawn_local;

fn history_date_param(value: &str) -> String {
    // Date inputs have no time or offset; the API requires RFC3339 bounds.
    if value.len() == 10
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
    {
        format!("{value}T00:00:00Z")
    } else {
        value.to_string()
    }
}
#[derive(Clone, Debug, PartialEq)]
pub(super) struct HistoryQuery {
    pub(super) fields: BTreeMap<String, String>,
    pub(super) cursor: String,
    pub(super) snapshot: String,
    pub(super) previous: Vec<String>,
}
impl HistoryQuery {
    pub(super) fn new() -> Self {
        Self {
            fields: BTreeMap::from([
                ("window".into(), "all".into()),
                ("timezone".into(), "UTC".into()),
                ("sort".into(), "startedDesc".into()),
                ("pageSize".into(), "50".into()),
            ]),
            cursor: String::new(),
            snapshot: String::new(),
            previous: vec![],
        }
    }
    pub(super) fn reset(&mut self) {
        self.cursor.clear();
        self.snapshot.clear();
        self.previous.clear();
    }
    pub(super) fn edit(&mut self, key: &str, value: String) {
        self.fields.insert(key.into(), value);
        self.reset();
    }
    pub(super) fn params(&self, snapshot: Option<&str>, include_cursor: bool) -> String {
        let parameters = web_sys::UrlSearchParams::new().expect("valid URL search parameters");
        for (key, value) in &self.fields {
            if value.is_empty() || value == "all" && key != "window" {
                continue;
            }
            if matches!(key.as_str(), "from" | "until")
                && self.fields.get("window").is_none_or(|w| w != "custom")
            {
                continue;
            }
            if matches!(key.as_str(), "from" | "until") {
                parameters.set(key, &history_date_param(value));
            } else {
                parameters.set(key, value);
            }
        }
        if include_cursor && !self.cursor.is_empty() {
            parameters.set("cursor", &self.cursor);
        }
        let snapshot = snapshot.unwrap_or(&self.snapshot);
        // A page cursor already carries the snapshot; the API rejects both.
        if !snapshot.is_empty() && !(include_cursor && !self.cursor.is_empty()) {
            parameters.set("snapshot", snapshot);
        }
        parameters.to_string().as_string().unwrap_or_default()
    }
}

#[derive(Clone)]
struct CommittedHistory {
    query: HistoryQuery,
    revision: u64,
    epoch: u64,
    server_epoch: u64,
    page: HistoryPage,
}

impl CommittedHistory {
    fn matches(&self, query: &HistoryQuery, revision: u64, epoch: u64, server_epoch: u64) -> bool {
        &self.query == query
            && self.revision == revision
            && self.epoch == epoch
            && self.server_epoch == server_epoch
    }

    fn same_export_scope(&self, origin: &Self) -> bool {
        self.matches(
            &origin.query,
            origin.revision,
            origin.epoch,
            origin.server_epoch,
        ) && self.page.scope.snapshot_token == origin.page.scope.snapshot_token
    }
}

enum HistoryExportError {
    SnapshotConflict,
    Other(String),
}

impl From<String> for HistoryExportError {
    fn from(message: String) -> Self {
        Self::Other(message)
    }
}

// The snapshot in a history response belongs to the query that produced it.
// Commit both together; the current filter signal may change before an API
// effect observes it and sets loading, or while an older request is in flight.
fn use_history(query: RwSignal<HistoryQuery>) -> ApiResource<Option<CommittedHistory>> {
    let context = app();
    let resource = ApiResource {
        data: RwSignal::new(None::<CommittedHistory>),
        loading: RwSignal::new(false),
        error: RwSignal::new(None),
        revision: RwSignal::new(0),
    };
    let generation = RwSignal::new(0u64);
    let reads = StoredValue::new_local(ResourceReads::default());
    on_cleanup(move || reads.update_value(|reads| reads.cancel()));
    let last_epoch = StoredValue::new(context.session_epoch.get_untracked());
    let last_server_epoch = StoredValue::new(context.server_epoch.get_untracked());
    Effect::new(move |_| {
        let epoch = context.session_epoch.get();
        let server_epoch = context.server_epoch.get();
        let can_read = context.can_read_area(PeerArea::Services);
        let grant_epoch = context.area_revocation_epoch(PeerArea::Services);
        if last_epoch.get_value() != epoch || last_server_epoch.get_value() != server_epoch {
            resource.data.set(None);
            resource.error.set(None);
            last_epoch.set_value(epoch);
            last_server_epoch.set_value(server_epoch);
        }
        let requested_query = query.get();
        let revision = resource.revision.get();
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        if !can_read {
            reads.update_value(|reads| reads.cancel());
            resource.data.set(None);
            resource.error.set(None);
            resource.loading.set(false);
            return;
        }
        let path = format!(
            "/api/v1/auth/streaming/history?{}",
            requested_query.params(None, true)
        );
        resource.loading.set(true);
        let Some(job) = reads.try_update_value(ResourceReads::next) else {
            return;
        };
        spawn_local(async move {
            let work = async {
                if generation.try_get_untracked() != Some(ticket)
                    || query.try_get_untracked().as_ref() != Some(&requested_query)
                    || resource.revision.try_get_untracked() != Some(revision)
                    || context.session_epoch.try_get_untracked() != Some(epoch)
                    || context.server_epoch.try_get_untracked() != Some(server_epoch)
                    || context.area_revocation_epoch_untracked(PeerArea::Services) != grant_epoch
                    || !context.can_read_area_untracked(PeerArea::Services)
                {
                    return None;
                }
                Some(ApiClient.get_typed::<Value>(&path).await)
            };
            let Some(Some(result)) = run_resource_read(job, work).await else {
                return;
            };
            if generation.try_get_untracked() != Some(ticket)
                || query.try_get_untracked().as_ref() != Some(&requested_query)
                || resource.revision.try_get_untracked() != Some(revision)
                || context.session_epoch.try_get_untracked() != Some(epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Services) != grant_epoch
                || !context.can_read_area_untracked(PeerArea::Services)
            {
                return;
            }
            match result {
                Ok(data) => {
                    resource.data.set(Some(CommittedHistory {
                        query: requested_query,
                        revision,
                        epoch,
                        server_epoch,
                        page: contracts::decode::<HistoryPage>(&data),
                    }));
                    resource.error.set(None);
                }
                Err(error)
                    if matches!(
                        error.code.as_deref(),
                        Some("SERVER_CHANGED" | "SESSION_CHANGED" | "ABORTED")
                    ) =>
                {
                    return;
                }
                Err(error) => resource.error.set(Some(error)),
            }
            resource.loading.set(false);
        });
    });
    resource
}

#[component]
fn HistoryField(
    query: RwSignal<HistoryQuery>,
    field: &'static str,
    label: &'static str,
    #[prop(default = "text")] kind: &'static str,
) -> impl IntoView {
    let context = app();
    view! {
        <label class="text-xs text-slate-400 space-y-1 min-w-0">
            <span class="block">{move || tt(context, label)}</span>
            <input
                class="glass-input p-2 w-full min-w-0"
                type=kind
                prop:value=move || query.with(|q| q.fields.get(field).cloned().unwrap_or_default())
                on:change=move |e| query.update(|q| q.edit(field, event_target_value(&e)))
            />
        </label>
    }
}
#[component]
fn HistorySelect(
    query: RwSignal<HistoryQuery>,
    field: &'static str,
    label: &'static str,
    options: Vec<(&'static str, &'static str)>,
) -> impl IntoView {
    let context = app();
    view! {
        <label class="text-xs text-slate-400 space-y-1">
            <span class="block">{move || tt(context, label)}</span>
            <select
                class="glass-input p-2 w-full"
                prop:value=move || query.with(|q| q.fields.get(field).cloned().unwrap_or_default())
                on:change=move |e| query.update(|q| q.edit(field, event_target_value(&e)))
            >
                {options
                    .into_iter()
                    .map(|(id, label)| {
                        view! { <option value=id>{move || tt(context, label)}</option> }
                    })
                    .collect_view()}
            </select>
        </label>
    }
}

#[component]
pub(super) fn CanonicalHistory(on_inspect: Callback<Value>) -> impl IntoView {
    let context = app();
    let query = RwSignal::new(HistoryQuery::new());
    let history = use_history(query);
    let export_busy = RwSignal::new(false);
    // The caller signal remains connected to RawResponse while blob() consumes
    // the body, so disposing this view stops an unfinished CSV transfer.
    let export_abort = StoredValue::new_local(web_sys::AbortController::new().ok());
    on_cleanup(move || {
        export_abort.with_value(|controller| {
            if let Some(controller) = controller {
                controller.abort();
            }
        });
    });
    let snapshot_invalid = RwSignal::new(false);
    let last_view_epochs = StoredValue::new((
        context.session_epoch.get_untracked(),
        context.server_epoch.get_untracked(),
    ));
    Effect::new(move |_| {
        let next_epochs = (context.session_epoch.get(), context.server_epoch.get());
        if last_view_epochs.get_value() == next_epochs {
            return;
        }
        last_view_epochs.set_value(next_epochs);
        export_abort.update_value(|controller| {
            if let Some(old) = controller.take() {
                old.abort();
            }
            *controller = web_sys::AbortController::new().ok();
        });
        export_busy.set(false);
        snapshot_invalid.set(false);
        query.set(HistoryQuery::new());
    });
    let committed = Signal::derive(move || {
        let current_query = query.get();
        let revision = history.revision.get();
        let epoch = context.session_epoch.get();
        let server_epoch = context.server_epoch.get();
        if snapshot_invalid.get() || history.loading.get() || history.error.with(Option::is_some) {
            None
        } else {
            history.data.with(|data| {
                data.as_ref()
                    .filter(|data| data.matches(&current_query, revision, epoch, server_epoch))
                    .cloned()
            })
        }
    });
    let page = Signal::derive(move || {
        committed.with(|data| {
            data.as_ref()
                .map(|data| data.page.clone())
                .unwrap_or_default()
        })
    });
    let rows = Signal::derive(move || {
        page.get()
            .items
            .into_iter()
            .filter_map(|record| serde_json::to_value(record).ok())
            .collect::<Vec<_>>()
    });
    let revision = RwSignal::new(context.history_revision.get_untracked());
    Effect::new(move |_| {
        let next = context.history_revision.get();
        if next != revision.get_untracked() {
            revision.set(next);
            query.update(HistoryQuery::reset);
            history.refresh();
        }
    });
    let export = Callback::new(move |format: String| {
        if export_busy.get_untracked()
            || history.loading.get_untracked()
            || history.error.with_untracked(Option::is_some)
            || snapshot_invalid.get_untracked()
        {
            return;
        }
        let Some(origin) = committed.get_untracked() else {
            return;
        };
        let snapshot = origin.page.scope.snapshot_token.clone();
        if snapshot.is_empty() {
            context.toast(
                tt(context, "Load a valid history snapshot before exporting."),
                true,
            );
            return;
        }
        let rows = rows.get_untracked();
        let history_revision = context.history_revision.get_untracked();
        if revision.get_untracked() != history_revision {
            return;
        }
        let signal = export_abort
            .with_value(|controller| controller.as_ref().map(web_sys::AbortController::signal));
        if format == "canonical-csv" && signal.is_none() {
            context.toast(tt(context, "Could not start CSV export."), true);
            return;
        }
        export_busy.set(true);
        spawn_local(async move {
            // A pending export may outlive this history view, account session,
            // or selected server. Never download or toast across server/session boundaries.
            let is_alive = || {
                export_busy.try_get_untracked().is_some()
                    && context.session_epoch.try_get_untracked() == Some(origin.epoch)
                    && context.server_epoch.try_get_untracked() == Some(origin.server_epoch)
            };
            let result: Result<(), HistoryExportError> = async {
                if format == "canonical-csv" {
                    let path = format!(
                        "/api/v1/auth/streaming/history/export?{}",
                        origin.query.params(Some(&snapshot), false)
                    );
                    let response = ApiClient
                        .fetch_raw_body_with_signal(
                            &path,
                            "GET",
                            None,
                            None,
                            &[("Accept", "text/csv")],
                            signal.as_ref(),
                        )
                        .await
                        .map_err(|error| error.message)?;
                    if !is_alive() {
                        return Ok(());
                    }
                    if !response.ok() {
                        return Err(if response.status() == 409 {
                            HistoryExportError::SnapshotConflict
                        } else {
                            HistoryExportError::Other(tt_with(
                                context,
                                "CSV export failed (HTTP {status}).",
                                &[("status", &response.status().to_string())],
                            ))
                        });
                    }
                    let blob = response.blob().await.map_err(|error| error.message)?;
                    if !is_alive() {
                        return Ok(());
                    }
                    if blob.size() > 128.0 * 1024.0 * 1024.0 {
                        return Err("CSV exceeds 128 MiB; narrow the history filters."
                            .to_string()
                            .into());
                    }
                    download_blob(&blob, "aetherflow-streaming-history.csv")
                        .map_err(HistoryExportError::from)
                } else {
                    let rows = rows
                        .into_iter()
                        .filter_map(|row| {
                            row.as_object().map(|object| {
                                object
                                    .iter()
                                    .map(|(key, value)| (key.clone(), value.clone()))
                                    .collect::<BTreeMap<_, _>>()
                            })
                        })
                        .collect();
                    let response = worker_pool()
                        .execute(WorkerRequest::BuildExportPayload { rows, format })
                        .await;
                    if !is_alive() {
                        return Ok(());
                    }
                    match response {
                        WorkerResponse::Export {
                            content,
                            mime,
                            extension,
                        } => download_text(
                            &content,
                            &mime,
                            &format!("aetherflow-history-page.{extension}"),
                        )
                        .map_err(HistoryExportError::from),
                        WorkerResponse::Error { message } => Err(message.into()),
                        _ => Err("Unexpected export worker response".to_string().into()),
                    }
                }
            }
            .await;
            if !is_alive() {
                return;
            }
            // A failure is relevant only to the still-committed request. In
            // particular, an old 409 must not invalidate a newer snapshot.
            if let Err(error) = result {
                if context.history_revision.try_get_untracked() == Some(history_revision)
                    && revision.try_get_untracked() == Some(history_revision)
                    && committed
                        .try_get_untracked()
                        .flatten()
                        .is_some_and(|current| current.same_export_scope(&origin))
                {
                    let message = match error {
                        HistoryExportError::SnapshotConflict => {
                            snapshot_invalid.set(true);
                            "History snapshot expired or changed. Restart from page one before exporting.".to_string()
                        }
                        HistoryExportError::Other(message) => message,
                    };
                    context.toast(tt(context, &message), true);
                }
            }
            export_busy.set(false);
        });
    });
    view! {
        <ObsCard title="Canonical playback history">
            <div class="space-y-4">
                <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    <HistorySelect
                        query
                        field="window"
                        label="Date window"
                        options=vec![
                            ("all", "All time"),
                            ("7d", "7 days"),
                            ("30d", "30 days"),
                            ("90d", "90 days"),
                            ("365d", "365 days"),
                            ("today", "Today"),
                            ("month", "This month"),
                            ("year", "This year"),
                            ("custom", "Custom range"),
                        ]
                    />
                    <HistorySelect
                        query
                        field="provider"
                        label="Server provider"
                        options=vec![
                            ("", "All"),
                            ("jellyfin", "Jellyfin"),
                            ("emby", "Emby"),
                        ]
                    />
                    <HistorySelect
                        query
                        field="mediaType"
                        label="Media type"
                        options=vec![
                            ("", "All media"),
                            ("Movie", "Movie"),
                            ("Episode", "Episode"),
                            ("Audio", "Audio"),
                            ("Video", "Video"),
                            ("Unknown", "Unknown"),
                        ]
                    />
                    <HistoryField query field="userId" label="Provider user ID" />
                    <HistoryField query field="serverId" label="Server identity ID" />
                    <HistoryField query field="libraryId" label="Library ID" />
                    <HistoryField query field="genre" label="Genre" />
                    <HistoryField query field="search" label="Search entire archive (literal)" />
                </div>
                <Show when=move || {
                    query.with(|q| q.fields.get("window").is_some_and(|w| w == "custom"))
                }>
                    <div class="grid sm:grid-cols-2 gap-3">
                        <HistoryField query field="from" label="From (inclusive, UTC)" kind="date" />
                        <HistoryField query field="until" label="Until (exclusive, UTC)" kind="date" />
                    </div>
                </Show>
                <details>
                    <summary class="text-sm cursor-pointer py-2">
                        {move || tt(context, "Advanced archive filters")}
                    </summary>
                    <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 pt-2">
                        <HistoryField query field="timezone" label="IANA timezone" />
                        <HistoryField query field="client" label="Client" />
                        <HistoryField query field="device" label="Device" />
                        <HistoryField query field="itemId" label="Item ID" />
                        <HistorySelect
                            query
                            field="playMethod"
                            label="Play method"
                            options=vec![
                                ("", "All"),
                                ("DirectPlay", "Direct Play"),
                                ("DirectStream", "Direct Stream"),
                                ("Transcode", "Transcode"),
                            ]
                        />
                        <HistorySelect
                            query
                            field="provenance"
                            label="Evidence provenance"
                            options=vec![
                                ("", "All"),
                                ("observed_session", "Observed session"),
                                ("imported_event", "Imported event"),
                                ("item_summary", "Item summary"),
                                ("legacy_unverified", "Unverified legacy"),
                            ]
                        />
                        <HistorySelect
                            query
                            field="sort"
                            label="Date ordering"
                            options=vec![
                                ("startedDesc", "Newest first"),
                                ("startedAsc", "Oldest first"),
                            ]
                        />
                        <HistorySelect
                            query
                            field="pageSize"
                            label="Page size"
                            options=vec![("25", "25"), ("50", "50"), ("100", "100"), ("200", "200")]
                        />
                        <Show when=move || context.is_admin()>
                            <label class="text-sm flex gap-2 items-center">
                                <input
                                    type="checkbox"
                                    prop:checked=move || {
                                        query
                                            .with(|q| {
                                                q.fields.get("includeExcluded").is_some_and(|v| v == "true")
                                            })
                                    }
                                    on:change=move |e| {
                                        query
                                            .update(|q| {
                                                q.edit(
                                                    "includeExcluded",
                                                    event_target_checked(&e).to_string(),
                                                )
                                            })
                                    }
                                />
                                {move || tt(context, "Include policy-excluded evidence")}
                            </label>
                        </Show>
                    </div>
                </details>
                {move || {
                    history
                        .error
                        .get()
                        .map(|e| {
                            view! {
                                <div
                                    role="alert"
                                    class="rounded-xl border border-rose-400/30 p-3 text-sm text-rose-300"
                                >
                                    <p>
                                        {move || tt(
                                            context,
                                            &(if e.status == 409 {
                                                tt_with(context, "Snapshot expired or invalidated: {error}. Restart the query from page one.", &[("error", &(e.message).to_string())])
                                            } else {
                                                e.message.clone()
                                            }),
                                        )}
                                    </p>
                                    <button
                                        class="glass-button px-3 py-2 mt-2"
                                        on:click=move |_| {
                                            query.update(HistoryQuery::reset);
                                            history.refresh();
                                        }
                                    >
                                        {move || tt(context, "Restart history snapshot")}
                                    </button>
                                </div>
                            }
                        })
                }}
                <Show when=move || snapshot_invalid.get()>
                    <div role="alert" class="rounded-xl border border-rose-400/30 p-3 text-sm text-rose-300">
                        <p>{move || tt(context, "Analytics snapshot expired or changed. Restart history from page one.")}</p>
                        <button type="button" class="glass-button px-3 py-2 mt-2" on:click=move |_| {
                            query.update(HistoryQuery::reset);
                            history.refresh();
                            snapshot_invalid.set(false);
                        }>{move || tt(context, "Restart history snapshot")}</button>
                    </div>
                </Show>
                <Show when=move || history.loading.get()>
                    <p role="status" class="text-sm text-indigo-300">
                        {move || tt(context, "Loading history snapshot…")}
                    </p>
                </Show>
                <p class="text-sm text-slate-400">
                    {move || {
                        let counts = page.get().counts;
                        let counter = |value: Option<f64>| value.map(|v| v.to_string()).unwrap_or_else(|| tt(context, "Unrecorded"));
                        tt_with(context, "{matching} matching / {available} available · {confirmed} confirmed plays · {watch_time} watch time · {undated} undated", &[("matching", &counter(counts.matching_records)), ("available", &counter(counts.available_records)), ("confirmed", &counter(counts.confirmed_plays)), ("watch_time", &duration(&crate::tabs::l10n::locale(context), counts.watch_time_secs)), ("undated", &counter(counts.undated_records))])
                    }}
                </p>
                <DataGrid
                    rows
                    columns=vec![
                        GridColumn::new("startedAt", "Started (UTC)"),
                        GridColumn::new("itemName", "Media title"),
                        GridColumn::new("seriesName", "Series"),
                        GridColumn::new("userName", "Viewer"),
                        GridColumn::new("provider", "Provider"),
                        GridColumn::new("itemType", "Media type"),
                        GridColumn::new("playMethod", "Play method"),
                        GridColumn::numeric("watchedSecs", "Watched seconds"),
                        GridColumn::new("provenance", "Evidence"),
                        GridColumn::new("policyStatus", "Policy"),
                    ]
                    label="Canonical playback history; worker-backed page search"
                    on_select=on_inspect
                />
                <div class="flex flex-wrap gap-3 items-center">
                    <button
                        class="glass-button px-3 py-2"
                        disabled=move || {
                            snapshot_invalid.get() || history.loading.get() || history.error.with(Option::is_some)
                                || query.with(|q| q.previous.is_empty())
                        }
                        on:click=move |_| {
                            query
                                .update(|q| {
                                    if let Some(previous) = q.previous.pop() {
                                        q.cursor = previous;
                                    }
                                })
                        }
                    >
                        {move || tt(context, "Previous")}
                    </button>
                    <span class="text-sm">
                        {move || tt_with(context, "Page {page}", &[("page", &(query.with(|q| q.previous.len() + 1)).to_string())])}
                    </span>
                    <button
                        class="glass-button px-3 py-2"
                        disabled=move || {
                            snapshot_invalid.get() || history.loading.get() || history.error.with(Option::is_some)
                                || page.get().next_cursor.is_none()
                        }
                        on:click=move |_| {
                            let data = page.get_untracked();
                            let next = data.next_cursor.unwrap_or_default();
                            let snapshot = data.scope.snapshot_token;
                            if !next.is_empty() && !snapshot.is_empty() {
                                query
                                    .update(|q| {
                                        q.previous.push(q.cursor.clone());
                                        q.cursor = next;
                                        q.snapshot = snapshot;
                                    });
                            }
                        }
                    >
                        {move || tt(context, "Next")}
                    </button>
                    <button
                        class="glass-button px-3 py-2"
                        disabled=move || history.loading.get()
                        on:click=move |_| {
                            query.update(HistoryQuery::reset);
                            history.refresh();
                            snapshot_invalid.set(false);
                        }
                    >
                        {move || tt(context, "New snapshot")}
                    </button>
                    <button
                        class="glass-button-primary px-3 py-2"
                        disabled=move || {
                            snapshot_invalid.get() || export_busy.get() || history.loading.get()
                                || history.error.with(Option::is_some)
                        }
                        on:click=move |_| export.run("canonical-csv".into())
                    >
                        {move || tt(context, "Export CSV · all matches")}
                    </button>
                    <button
                        class="glass-button px-3 py-2"
                        disabled=move || {
                            snapshot_invalid.get() || export_busy.get() || history.loading.get()
                                || history.error.with(Option::is_some)
                        }
                        on:click=move |_| export.run("json".into())
                    >
                        {move || tt(context, "Export JSON · this page")}
                    </button>
                </div>
                <p class="text-xs text-slate-400 break-words">
                    {move || {
                        let scope = page.get().scope;
                        tt_with(context, "As of {as_of} · expires {expires} · {snapshot} · {timezone}", &[("as_of", &scope.as_of), ("expires", &scope.expires_at), ("snapshot", &scope.permission_scope), ("timezone", &scope.date_semantics)])
                    }}
                </p>
                <p class="text-xs text-slate-400">
                    {move || tt(
                        context,
                        "Archive filters apply after leaving the field. Page search runs in a worker. History pagination and analytics stay on the same snapshot; live polling does not replace it.",
                    )}
                </p>
                {move || committed.get().and_then(|data| {
                    let snapshot = data.page.scope.snapshot_token;
                    (!snapshot.is_empty()).then(|| {
                        let conflict_query = data.query.clone();
                        let conflict_snapshot = snapshot.clone();
                        let conflict_server_epoch = data.server_epoch;
                        view! {
                            <HistoryAnalytics
                                query
                                committed_query=data.query
                                snapshot
                                on_conflict=Callback::new(move |()| {
                                    // A late conflict belongs only to the pair
                                    // that issued it, not a newer selection or server.
                                    if committed.try_get_untracked().flatten().is_some_and(|current| {
                                        current.query == conflict_query
                                            && current.page.scope.snapshot_token == conflict_snapshot
                                            && current.server_epoch == conflict_server_epoch
                                    }) {
                                        snapshot_invalid.set(true);
                                    }
                                })
                            />
                        }
                    })
                })}
            </div>
        </ObsCard>
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::{duration, recorded};
    use super::*;
    use serde_json::json;

    #[test]
    fn date_inputs_are_explicit_utc_rfc3339_bounds() {
        assert_eq!(history_date_param("2026-11-17"), "2026-11-17T00:00:00Z");
        assert_eq!(
            history_date_param("2026-11-17T03:30:00+01:00"),
            "2026-11-17T03:30:00+01:00"
        );
    }

    #[test]
    fn history_filter_changes_clear_snapshot_and_pagination() {
        let mut query = HistoryQuery::new();
        query.cursor = "cursor-a".into();
        query.snapshot = "snapshot-a".into();
        query.previous.push("previous".into());
        query.edit("window", "custom".into());
        assert_eq!(query.fields["window"], "custom");
        assert!(query.cursor.is_empty());
        assert!(query.snapshot.is_empty());
        assert!(query.previous.is_empty());
        assert_eq!(query.fields["pageSize"], "50");
    }

    #[test]
    fn committed_history_is_visible_only_for_its_request_query() {
        let original = HistoryQuery::new();
        let committed = CommittedHistory {
            query: original.clone(),
            revision: 4,
            epoch: 2,
            server_epoch: 7,
            page: HistoryPage::default(),
        };
        assert!(committed.matches(&original, 4, 2, 7));
        assert!(!committed.matches(&original, 5, 2, 7));
        assert!(!committed.matches(&original, 4, 3, 7));
        assert!(!committed.matches(&original, 4, 2, 8));

        let mut edited = original.clone();
        edited.edit("pageSize", "25".into());
        assert!(!committed.matches(&edited, 4, 2, 7));
        edited.edit("sort", "startedAsc".into());
        assert!(!committed.matches(&edited, 4, 2, 7));

        let mut next_page = original;
        next_page.cursor = "next".into();
        next_page.snapshot = "snapshot".into();
        next_page.previous.push(String::new());
        assert!(!committed.matches(&next_page, 4, 2, 7));
    }

    #[test]
    fn export_conflict_is_scoped_to_query_snapshot_revision_and_session() {
        let mut origin = CommittedHistory {
            query: HistoryQuery::new(),
            revision: 4,
            epoch: 2,
            server_epoch: 7,
            page: HistoryPage::default(),
        };
        origin.page.scope.snapshot_token = "snapshot-a".into();
        assert!(origin.same_export_scope(&origin));

        let mut current = origin.clone();
        current.query.edit("provider", "emby".into());
        assert!(!current.same_export_scope(&origin));

        current = origin.clone();
        current.page.scope.snapshot_token = "snapshot-b".into();
        assert!(!current.same_export_scope(&origin));

        // A refresh can repeat the same query and even the same token; its
        // revision still distinguishes the newer committed history.
        current = origin.clone();
        current.revision += 1;
        assert!(!current.same_export_scope(&origin));

        current = origin.clone();
        current.epoch += 1;
        assert!(!current.same_export_scope(&origin));

        current = origin.clone();
        current.server_epoch += 1;
        assert!(!current.same_export_scope(&origin));
    }

    #[test]
    fn durations_reject_invalid_evidence_and_keep_zero() {
        assert_eq!(duration("en", Some(3660.0)), "1h 1m");
        assert_eq!(duration("en", Some(0.0)), "0h 0m");
        assert_eq!(duration("en", Some(-1.0)), "Unrecorded");
        assert_eq!(duration("en", Some(f64::NAN)), "Unrecorded");
        assert_eq!(recorded("en", &json!({}), "codec"), "Unrecorded");
        assert_eq!(recorded("en", &json!({"codec":"h264"}), "codec"), "h264");
    }
}
