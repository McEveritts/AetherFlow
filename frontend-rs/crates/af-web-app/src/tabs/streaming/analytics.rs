//! Worker rollups and charts for observed and imported history.
use super::common::*;
use super::history::HistoryQuery;
use super::types::*;
use crate::state::{app, use_api, worker_pool};
use crate::tabs::contracts;
use crate::tabs::l10n::{tt, tt_with, ObsCard};
use af_web_core::charts::Point;
use af_web_core::worker::{StreamingSample, WorkerRequest, WorkerResponse};
use af_web_ui::{AreaChart, LineChart};
use leptos::prelude::*;
use serde_json::Value;
use std::collections::BTreeMap;
use wasm_bindgen_futures::spawn_local;

// A display name is never a user, item or library identity. If the backend
// cannot supply the full scoped identity, present the totals without a link.
fn cohort_patch(kind: &str, row: &Value) -> Option<BTreeMap<String, String>> {
    let mut patch = BTreeMap::new();
    match kind {
        "users" | "items" | "libraries" => {
            for (source, target) in [
                ("provider", "provider"),
                ("serverId", "serverId"),
                (
                    match kind {
                        "users" => "userId",
                        "items" => "itemId",
                        _ => "libraryId",
                    },
                    match kind {
                        "users" => "userId",
                        "items" => "itemId",
                        _ => "libraryId",
                    },
                ),
            ] {
                let value = row[source].as_str()?.trim();
                if value.is_empty() || value == "all" {
                    return None;
                }
                patch.insert(target.to_string(), value.to_string());
            }
        }
        "clients" => {
            // The API groups client/device names together, including the
            // explicit Unknown bucket, and filters both names case-insensitively.
            for (source, target) in [("clientName", "client"), ("deviceName", "device")] {
                let value = row[source]
                    .as_str()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or("Unknown");
                patch.insert(target.into(), value.trim().into());
            }
        }
        "genres" => {
            let value = row["genre"].as_str()?.trim();
            if value.is_empty() {
                return None;
            }
            patch.insert("genre".into(), value.into());
        }
        _ => return None,
    }
    // Some servers report a scope for client/genre rows. Retain the current
    // scope when they are aggregated across servers, as in the Rust API.
    if matches!(kind, "clients" | "genres") {
        if let (Some(provider), Some(server)) = (row["provider"].as_str(), row["serverId"].as_str())
        {
            if !provider.trim().is_empty() && provider != "all" && !server.trim().is_empty() {
                patch.insert("provider".into(), provider.trim().into());
                patch.insert("serverId".into(), server.trim().into());
            }
        }
    }
    Some(patch)
}

fn client_filter_key(row: &Value) -> (String, String) {
    let part = |key: &str| {
        row[key]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("Unknown")
            .to_ascii_lowercase()
    };
    (part("clientName"), part("deviceName"))
}

#[cfg(test)]
mod cohort_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scoped_ids_are_required_and_duplicate_names_do_not_collide() {
        for (kind, id_key) in [
            ("users", "userId"),
            ("items", "itemId"),
            ("libraries", "libraryId"),
        ] {
            let mut first = json!({"provider":"jellyfin", "serverId":"server-a", "userName":"Same", "itemName":"Same", "libraryName":"Same"});
            first[id_key] = json!("id-a");
            let mut second = first.clone();
            second["serverId"] = json!("server-b");
            let a = cohort_patch(kind, &first).unwrap();
            let b = cohort_patch(kind, &second).unwrap();
            assert_ne!(a, b);
            assert_eq!(a[id_key], "id-a");
            first["serverId"] = json!("");
            assert!(cohort_patch(kind, &first).is_none());
            first["serverId"] = json!("server-a");
            first[id_key] = Value::Null;
            assert!(cohort_patch(kind, &first).is_none());
        }
    }

    #[test]
    fn aggregated_client_and_genre_filters_preserve_existing_scope() {
        let client =
            cohort_patch("clients", &json!({"clientName":"Web", "deviceName":null})).unwrap();
        assert_eq!(client["client"], "Web");
        assert_eq!(client["device"], "Unknown");
        assert!(!client.contains_key("serverId"));
        assert_eq!(
            client_filter_key(&json!({"clientName":"WEB", "deviceName":null})),
            client_filter_key(&json!({"clientName":"web", "deviceName":"Unknown"}))
        );
        let genre = cohort_patch("genres", &json!({"genre":"Drama"})).unwrap();
        assert_eq!(genre["genre"], "Drama");
        assert!(!genre.contains_key("provider"));
    }
}

#[component]
fn CohortGroup(
    kind: &'static str,
    title: &'static str,
    report: crate::state::ApiResource,
    query: RwSignal<HistoryQuery>,
) -> impl IntoView {
    let context = app();
    view! {
        <section class="space-y-2 min-w-0" aria-label=move || tt(context, title)>
            <h5 class="font-semibold text-sm">{move || tt(context, title)}</h5>
            <div class="space-y-2 max-h-80 overflow-auto">
                {move || {
                    let rows = report.data.with(|data| data[kind].as_array().cloned().unwrap_or_default());
                    let mut client_counts = BTreeMap::new();
                    if kind == "clients" {
                        for row in &rows { *client_counts.entry(client_filter_key(row)).or_insert(0usize) += 1; }
                    }
                    rows.into_iter().map(|row| {
                    let label = match kind {
                        "users" => text(&row, "userName"), "items" => text(&row, "itemName"),
                        "libraries" => text(&row, "libraryName"), "genres" => text(&row, "genre"),
                        _ => {
                            let client = row["clientName"].as_str().filter(|s| !s.trim().is_empty()).unwrap_or("Unknown");
                            let device = row["deviceName"].as_str().filter(|s| !s.trim().is_empty()).unwrap_or("Unknown");
                            format!("{} · {}", tt(context, client), tt(context, device))
                        },
                    };
                    let id = match kind { "users" => text(&row, "userId"), "items" => text(&row, "itemId"), "libraries" => text(&row, "libraryId"), _ => String::new() };
                    let identity = [text(&row, "provider"), text(&row, "serverId"), id].into_iter().filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" · ");
                    let count = text(&row, "playCount");
                    let seconds = row["watchTimeSecs"].as_f64();
                    // Client filters are case-insensitive even when source
                    // grouping distinguished case. Never select a row if
                    // that filter would silently include a different group.
                    let patch = if kind == "clients" && client_counts.get(&client_filter_key(&row)).copied().unwrap_or(0) > 1 {
                        None
                    } else { cohort_patch(kind, &row) };
                    let disabled = patch.is_none();
                    view! {
                        <button type="button" class="glass-button w-full text-left p-3 break-words disabled:opacity-60" disabled=disabled
                            on:click=move |_| if let Some(patch) = patch.clone() {
                                query.update(|query| {
                                    for (key, value) in patch { query.fields.insert(key, value); }
                                    query.reset();
                                });
                            }>
                            <span class="block font-semibold">{if label.trim().is_empty() { tt(context, "Unrecorded") } else { label }}</span>
                            {(!identity.is_empty()).then(|| view! { <span class="block text-xs text-slate-400">{identity}</span> })}
                            <span class="block text-xs text-slate-400">{move || tt_with(context, "{count} plays · {duration}", &[("count", &count), ("duration", &duration(&crate::tabs::l10n::locale(context), seconds))])}</span>
                            {disabled.then(|| view! { <span class="block text-xs text-amber-300">{move || tt(context, "Identity unavailable for filtering")}</span> })}
                        </button>
                    }
                    }).collect_view()
                }}
            </div>
        </section>
    }
}

#[component]
pub(super) fn HistoryAnalytics(
    query: RwSignal<HistoryQuery>,
    committed_query: HistoryQuery,
    snapshot: String,
    on_conflict: Callback<()>,
) -> impl IntoView {
    let context = app();
    // Both endpoints use the immutable query/snapshot pair from the history
    // response; `query` stays live only for applying a cohort filter.
    let params = committed_query.params(Some(&snapshot), false);
    let patterns_path = format!("/api/v1/auth/streaming/patterns?{params}");
    let drilldown_path = format!("/api/v1/auth/streaming/drilldown?{params}");
    let patterns = use_api(Signal::derive(move || patterns_path.clone()));
    let drilldown = use_api(Signal::derive(move || drilldown_path.clone()));
    Effect::new(move |_| {
        if patterns
            .error
            .with(|e| e.as_ref().is_some_and(|e| e.status == 409))
            || drilldown
                .error
                .with(|e| e.as_ref().is_some_and(|e| e.status == 409))
        {
            on_conflict.run(());
        }
    });
    let bucket_ms = RwSignal::new(86_400_000i64);
    let plays = RwSignal::new(Vec::<Point>::new());
    let hours = RwSignal::new(Vec::<Point>::new());
    let peaks = RwSignal::new(Vec::<Point>::new());
    let generation = RwSignal::new(0u64);
    let busy = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    Effect::new(move |_| {
        let report = patterns.data.get();
        let bucket_ms = bucket_ms.get();
        generation.update(|n| *n += 1);
        let ticket = generation.get_untracked();
        if report.is_null() {
            return;
        }
        let mut samples = vec![];
        if let Some(rows) = report["activity"]["timeseries"].as_array() {
            for row in rows {
                let Some(timestamp_ms) = timestamp(&text(row, "bucketStart")) else {
                    continue;
                };
                let mut values = BTreeMap::new();
                if let Some(value) = row["playCount"].as_f64() {
                    values.insert("plays".into(), value);
                }
                if let Some(value) = row["watchTimeSecs"].as_f64() {
                    values.insert("hours".into(), value / 3600.0);
                }
                samples.push(StreamingSample {
                    timestamp_ms,
                    values,
                });
            }
        }
        if let Some(rows) = report["concurrency"]["buckets"].as_array() {
            for row in rows {
                if !matches!(row["status"].as_str(), Some("available" | "no_activity")) {
                    continue;
                }
                if let (Some(timestamp_ms), Some(peak)) = (
                    timestamp(&text(row, "bucketStart")),
                    row["peakConcurrency"].as_f64(),
                ) {
                    samples.push(StreamingSample {
                        timestamp_ms,
                        values: BTreeMap::from([("peak".into(), peak)]),
                    });
                }
            }
        }
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            let response = worker_pool()
                .execute(WorkerRequest::AggregateStreaming { samples, bucket_ms })
                .await;
            if generation.try_get_untracked() != Some(ticket) {
                return;
            }
            match response {
                WorkerResponse::Aggregated { buckets } => {
                    plays.set(
                        buckets
                            .iter()
                            .filter_map(|b| {
                                b.values.get("plays").map(|v| Point {
                                    x: b.timestamp_ms as f64,
                                    y: v.sum,
                                })
                            })
                            .collect(),
                    );
                    hours.set(
                        buckets
                            .iter()
                            .filter_map(|b| {
                                b.values.get("hours").map(|v| Point {
                                    x: b.timestamp_ms as f64,
                                    y: v.sum,
                                })
                            })
                            .collect(),
                    );
                    peaks.set(
                        buckets
                            .iter()
                            .filter_map(|b| {
                                b.values.get("peak").map(|v| Point {
                                    x: b.timestamp_ms as f64,
                                    y: v.max,
                                })
                            })
                            .collect(),
                    );
                }
                WorkerResponse::Error { message } => error.set(Some(message)),
                _ => error.set(Some("Unexpected analytics worker response".into())),
            }
            busy.set(false);
        });
    });
    view! {
        <div class="space-y-3 border-t border-white/10 pt-4">
            <div class="flex flex-wrap justify-between gap-3">
                <h3 class="font-semibold">
                    {move || tt(
                        context,
                        "Worker-accelerated analytics · complete filtered snapshot",
                    )}
                </h3>
                <label class="text-sm">
                    {move || tt(context, "Rollup ")}
                    <select
                        class="glass-input p-2"
                        prop:value=move || bucket_ms.get().to_string()
                        on:change=move |e| {
                            if let Ok(value) = event_target_value(&e).parse() {
                                bucket_ms.set(value);
                            }
                        }
                    >
                        <option value="3600000">{move || tt(context, "Hourly")}</option>
                        <option value="86400000">{move || tt(context, "Daily")}</option>
                        <option value="604800000">{move || tt(context, "Weekly")}</option>
                    </select>
                </label>
            </div>
            {move || {
                patterns
                    .error
                    .get()
                    .map(|e| {
                        view! {
                            <p role="alert" class="text-rose-300">
                                {move || tt(context, &e.message)}
                            </p>
                        }
                    })
            }}
            {move || {
                error
                    .get()
                    .map(|e| {
                        view! {
                            <p role="alert" class="text-rose-300">
                                {move || tt(context, &e)}
                            </p>
                        }
                    })
            }}
            <Show when=move || patterns.loading.get() || busy.get()>
                <p role="status" class="text-sm text-indigo-300">
                    {move || tt(context, "Aggregating canonical evidence…")}
                </p>
            </Show>
            <div class="grid lg:grid-cols-3 gap-3">
                <div>
                    <h4 class="text-sm">{move || tt(context, "Confirmed plays")}</h4>
                    <AreaChart points=plays label="Confirmed plays per time bucket" />
                </div>
                <div>
                    <h4 class="text-sm">{move || tt(context, "Watch duration (hours)")}</h4>
                    <AreaChart points=hours label="Confirmed watch hours per time bucket" />
                </div>
                <div>
                    <h4 class="text-sm">{move || tt(context, "Peak concurrent streams")}</h4>
                    <LineChart points=peaks label="Sampled peak concurrency per time bucket" />
                </div>
            </div>
            <p class="text-xs text-slate-400">
                {move || tt(
                    context,
                    "UTC rollups use sums for plays and watch hours, and maximum observed concurrency. Unrecorded sampling intervals are omitted, not treated as zero. Hourly rollups cannot subdivide coarser source buckets.",
                )}
            </p>
            <details>
                <summary class="cursor-pointer text-sm">
                    {move || tt(context, "Concurrency coverage and retention limits")}
                </summary>
                <pre class="text-xs whitespace-pre-wrap break-all max-h-64 overflow-auto">
                    {move || {
                        patterns
                            .data
                            .with(|d| {
                                serde_json::to_string_pretty(&d["concurrency"]).unwrap_or_default()
                            })
                    }}
                </pre>
            </details>
            <section class="border-t border-white/10 pt-4 space-y-4" aria-label=move || tt(context, "Cohort drilldowns")>
                <h4 class="font-semibold">{move || tt(context, "Cohort drilldowns")}</h4>
                {move || drilldown.error.get().map(|error| view! { <p role="alert" class="text-rose-300">{move || tt(context, &error.message)}</p> })}
                <Show when=move || drilldown.loading.get()><p role="status">{move || tt(context, "Loading cohort report…")}</p></Show>
                <Show when=move || !drilldown.loading.get() && drilldown.error.with(Option::is_none) && drilldown.data.with(|d| d.is_object())>
                    <p class="text-sm text-slate-400">{move || drilldown.data.with(|d| tt_with(context, "{plays} distinct plays · {users} users · {items} items", &[("plays", &text(d, "cohortDistinctPlays")), ("users", &text(d, "cohortDistinctUsers")), ("items", &text(d, "cohortDistinctItems"))]))}</p>
                    <p class="text-xs text-slate-400">{move || tt(context, "Library and genre labels may overlap; their play counts can exceed the cohort total.")}</p>
                    <div class="grid sm:grid-cols-2 xl:grid-cols-3 gap-4">
                        <CohortGroup kind="users" title="Viewers" report=drilldown query />
                        <CohortGroup kind="clients" title="Clients and devices" report=drilldown query />
                        <CohortGroup kind="items" title="Media items" report=drilldown query />
                        <CohortGroup kind="libraries" title="Libraries" report=drilldown query />
                        <CohortGroup kind="genres" title="Genres" report=drilldown query />
                    </div>
                </Show>
            </section>
        </div>
    }
}

#[component]
pub(super) fn ImportedEstimates(
    dashboard: crate::state::ApiResource,
    window: RwSignal<String>,
) -> impl IntoView {
    let context = app();
    view! {
            <ObsCard title="Imported history estimates">
                <div class="space-y-3">
                    <label class="text-sm">
                        {move || tt(context, "Estimate window ")}
                        <select
                            class="glass-input p-2"
                            prop:value=move || window.get()
                            on:change=move |e| window.set(event_target_value(&e))
                        >
                            <option value="7">{move || tt(context, "7 days")}</option>
                            <option value="30">{move || tt(context, "30 days")}</option>
                            <option value="90">{move || tt(context, "90 days")}</option>
                            <option value="all">{move || tt(context, "All time")}</option>
                        </select>
                    </label>
                    <p class="text-xs text-amber-300">
                        {move || tt(
                            context,
                            "Item runtimes and legacy estimates are shown separately. They are not confirmed elapsed watch time and must not be added together.",
                        )}
                    </p>
                    {move || {
                        dashboard
                            .data
                            .with(|d| {
                                contracts::decode::<Dashboard>(d).analytics.historical_estimates
                            })
                            .into_iter()
                            .map(|estimate| {
                                let points = estimate.time_series.iter().filter_map(|row| Some(Point {
                                    x: timestamp(&row.date)? as f64,
                                    y: row.watch_time_secs? / 3600.0,
                                })).collect::<Vec<_>>();
                                view! {
                                    <div class="border-t border-white/10 pt-3">
                                        <h3 class="font-semibold">
                                            {move || display(context, &estimate.provenance)}
                                        </h3>
                                        <p class="text-sm text-slate-400">
                                            {move || tt_with(context, "{records} records · {estimated} estimated · {undated} undated", &[("records", &(display(context, &estimate.records)).to_string()), ("estimated", &(duration(&crate::tabs::l10n::locale(context), estimate.reported_watch_time_secs)).to_string()), ("undated", &(display(context, &estimate.undated_records)).to_string())])}
                                        </p>
                                        <LineChart
                                            points=Signal::stored(points)
                                            label="Imported estimated watch hours by stored UTC date"
                                        />
                                    </div>
                                }
                            })
                            .collect_view()
                    }}
                </div>
            </ObsCard>
    }
}
