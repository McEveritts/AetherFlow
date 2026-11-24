//! Worker rollups and charts for observed and imported history.
use super::common::*;
use super::history::HistoryQuery;
use super::types::*;
use crate::state::{app, use_api_when, worker_pool, PeerArea};
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
    let can_read_services = Signal::derive(move || context.can_read_area(PeerArea::Services));
    let patterns = use_api_when(
        can_read_services,
        Signal::derive(move || patterns_path.clone()),
    );
    let drilldown = use_api_when(
        can_read_services,
        Signal::derive(move || drilldown_path.clone()),
    );
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
        let session_epoch = context.session_epoch.get();
        let server_epoch = context.server_epoch.get();
        let report = patterns.data.get();
        let bucket_ms = bucket_ms.get();
        generation.update(|n| *n += 1);
        let ticket = generation.get_untracked();
        if report.is_null() {
            plays.set(vec![]);
            hours.set(vec![]);
            peaks.set(vec![]);
            busy.set(false);
            error.set(None);
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
            if generation.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
            {
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

pub(super) fn stream_type_fill_class(bg_class: &str) -> &'static str {
    match bg_class {
        "bg-emerald-400" => "fill-emerald-400",
        "bg-cyan-400" => "fill-cyan-400",
        "bg-amber-400" => "fill-amber-400",
        _ => "fill-slate-400",
    }
}

pub(super) fn stream_type_bar_segments(
    rows: &[(&'static str, i64, f64, &'static str)],
) -> Vec<(&'static str, f64, f64, &'static str)> {
    let mut cursor = 0.0_f64;
    let mut segments = Vec::new();
    for &(label, _count, pct, bg_class) in rows {
        if cursor >= 100.0 {
            break;
        }
        let clamped = if pct.is_finite() { pct.max(0.0) } else { 0.0 };
        let width = clamped.min(100.0 - cursor);
        if width > 0.0 {
            segments.push((label, cursor, width, stream_type_fill_class(bg_class)));
            cursor += width;
        }
    }
    segments
}

#[component]
fn BreakdownList(title: &'static str, rows: Vec<BreakdownEntry>) -> impl IntoView {
    let context = app();
    let total_rows = rows.len();
    view! {
        <section
            class="rounded-xl border border-white/10 bg-white/[0.02] p-4 space-y-3"
            aria-label=move || tt(context, title)
        >
            <h3 class="font-semibold text-sm">{move || tt(context, title)}</h3>
            {if total_rows == 0 {
                view! {
                    <p class="text-xs text-slate-400">
                        {move || tt(context, "No matching telemetry in this window.")}
                    </p>
                }
                .into_any()
            } else {
                view! {
                    <ul class="space-y-2.5 text-xs">
                        {rows
                            .into_iter()
                            .take(6)
                            .map(|row| {
                                let label = if row.label.trim().is_empty() {
                                    "Unknown".to_string()
                                } else {
                                    row.label.clone()
                                };
                                let clamped_pct = if row.pct.is_finite() {
                                    row.pct.clamp(0.0, 100.0)
                                } else {
                                    0.0
                                };
                                let pct_text = format!("{clamped_pct:.1}%");
                                let count_text = row.count.to_string();
                                let aria_label_text = label.clone();
                                view! {
                                    <li class="space-y-1">
                                        <div class="flex items-center justify-between gap-2">
                                            <span class="font-medium text-slate-200 truncate">
                                                {tt(context, &label)}
                                            </span>
                                            <span class="text-slate-400 font-mono shrink-0">
                                                {format!("{count_text} ({pct_text})")}
                                            </span>
                                        </div>
                                        <progress
                                            class="w-full h-1.5 accent-indigo-400"
                                            max="100"
                                            value=format!("{clamped_pct:.1}")
                                            aria-label=move || tt(context, &aria_label_text)
                                        ></progress>
                                    </li>
                                }
                            })
                            .collect_view()}
                    </ul>
                }
                .into_any()
            }}
        </section>
    }
}

#[component]
pub(super) fn DashboardDistributions(dashboard: crate::state::ApiResource) -> impl IntoView {
    let context = app();
    view! {
        <ObsCard title="Distribution & Trends">
            {move || {
                let analytics = dashboard
                    .data
                    .with(|d| contracts::decode::<Dashboard>(d).analytics);
                let locale = crate::tabs::l10n::locale(context);
                let watch_text = duration(&locale, Some(analytics.total_watch_time_secs.max(0) as f64));
                let data_text = crate::tabs::settings::bytes(analytics.total_data_used_bytes.max(0) as f64);
                let bw_text = format!("{:.1} Mbps", analytics.peak_bandwidth_mbps.max(0.0));
                let stream_rows = analytics.stream_types.rows(analytics.total_plays);
                let stream_segments = stream_type_bar_segments(&stream_rows);
                let play_points = analytics
                    .time_series
                    .iter()
                    .filter_map(|row| {
                        Some(Point {
                            x: timestamp(&row.date)? as f64,
                            y: row.plays as f64,
                        })
                    })
                    .collect::<Vec<_>>();
                let bw_points = analytics
                    .time_series
                    .iter()
                    .filter_map(|row| {
                        Some(Point {
                            x: timestamp(&row.date)? as f64,
                            y: row.peak_bandwidth_mbps,
                        })
                    })
                    .collect::<Vec<_>>();
                let media_rows = analytics.media_type_breakdown.clone();
                let res_rows = analytics.resolution_breakdown.clone();
                let codec_rows = analytics.codec_breakdown.clone();
                let top_users = analytics.top_users.clone();
                let top_titles = analytics.top_titles.clone();
                view! {
                    <div class="space-y-5">
                        <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 text-sm">
                            <div class="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                                <p class="text-xs text-slate-400">{move || tt(context, "Total plays")}</p>
                                <p class="text-lg font-semibold font-mono mt-1">{analytics.total_plays}</p>
                            </div>
                            <div class="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                                <p class="text-xs text-slate-400">{move || tt(context, "Watch time")}</p>
                                <p class="text-lg font-semibold font-mono mt-1">{watch_text}</p>
                            </div>
                            <div class="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                                <p class="text-xs text-slate-400">{move || tt(context, "Data transferred")}</p>
                                <p class="text-lg font-semibold font-mono mt-1">{data_text}</p>
                            </div>
                            <div class="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                                <p class="text-xs text-slate-400">{move || tt(context, "Peak bandwidth")}</p>
                                <p class="text-lg font-semibold font-mono mt-1">{bw_text}</p>
                            </div>
                        </div>

                        <section
                            class="rounded-xl border border-white/10 bg-white/[0.02] p-4 space-y-3"
                            aria-label=move || tt(context, "Playback method breakdown")
                        >
                            <div class="flex flex-wrap items-center justify-between gap-2">
                                <h3 class="font-semibold text-sm">{move || tt(context, "Playback method breakdown")}</h3>
                                <span class="text-xs text-slate-400">
                                    {tt_with(
                                        context,
                                        "{users} viewers · {titles} titles",
                                        &[
                                            ("users", &analytics.unique_users.to_string()),
                                            ("titles", &analytics.unique_titles.to_string()),
                                        ],
                                    )}
                                </span>
                            </div>
                            <svg
                                viewBox="0 0 100 6"
                                preserveAspectRatio="none"
                                class="w-full h-2.5 rounded-full bg-white/10 overflow-hidden block"
                                role="img"
                                aria-label=move || tt(context, "Playback method breakdown")
                            >
                                {stream_segments
                                    .into_iter()
                                    .map(|(_, x, width, fill_cls)| {
                                        view! {
                                            <rect
                                                x=format!("{x:.2}")
                                                y="0"
                                                width=format!("{width:.2}")
                                                height="6"
                                                class=fill_cls
                                            />
                                        }
                                    })
                                    .collect_view()}
                            </svg>
                            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                                {stream_rows
                                    .into_iter()
                                    .map(|(label, count, pct, color)| {
                                        let dot = format!("inline-block w-2.5 h-2.5 rounded-full {color}");
                                        view! {
                                            <div class="flex items-center gap-2">
                                                <span class=dot aria-hidden="true"></span>
                                                <span>
                                                    {format!("{}: {} ({:.1}%)", tt(context, label), count, pct)}
                                                </span>
                                            </div>
                                        }
                                    })
                                    .collect_view()}
                            </div>
                        </section>

                        <div class="grid md:grid-cols-3 gap-4">
                            <BreakdownList title="Media format distribution" rows=media_rows />
                            <BreakdownList title="Resolution distribution" rows=res_rows />
                            <BreakdownList title="Source codec distribution" rows=codec_rows />
                        </div>

                        {(!play_points.is_empty() || !bw_points.is_empty()).then(|| {
                            view! {
                                <div class="grid lg:grid-cols-2 gap-4">
                                    <div>
                                        <h4 class="text-sm mb-1">{move || tt(context, "Plays over time")}</h4>
                                        <AreaChart
                                            points=Signal::stored(play_points)
                                            label="Plays over time"
                                        />
                                    </div>
                                    <div>
                                        <h4 class="text-sm mb-1">{move || tt(context, "Peak bandwidth (Mbps)")}</h4>
                                        <LineChart
                                            points=Signal::stored(bw_points)
                                            label="Peak bandwidth (Mbps)"
                                        />
                                    </div>
                                </div>
                            }
                        })}

                        {(!top_users.is_empty() || !top_titles.is_empty()).then(|| {
                            view! {
                                <div class="grid lg:grid-cols-2 gap-4 text-xs">
                                    <section
                                        class="rounded-xl border border-white/10 bg-white/[0.02] p-4 space-y-2"
                                        aria-label=move || tt(context, "Top watchers")
                                    >
                                        <h3 class="font-semibold text-sm">{move || tt(context, "Top watchers")}</h3>
                                        {if top_users.is_empty() {
                                            view! { <p class="text-slate-400">{move || tt(context, "No matching telemetry in this window.")}</p> }.into_any()
                                        } else {
                                            view! {
                                                <ul class="divide-y divide-white/10">
                                                    {top_users
                                                        .iter()
                                                        .take(5)
                                                        .map(|u| {
                                                            let name = if u.user_name.is_empty() { tt(context, "Unknown") } else { u.user_name.clone() };
                                                            let watch = duration(&locale, Some(u.total_watch_secs.max(0) as f64));
                                                            let data = crate::tabs::settings::bytes(u.total_data_bytes.max(0) as f64);
                                                            view! {
                                                                <li class="py-2 flex items-center justify-between gap-2">
                                                                    <span class="font-medium truncate">{name}</span>
                                                                    <span class="text-slate-400 font-mono shrink-0">
                                                                        {format!("{} · {} · {}", tt_with(context, "{count} plays", &[("count", &u.total_plays.to_string())]), watch, data)}
                                                                    </span>
                                                                </li>
                                                            }
                                                        })
                                                        .collect_view()}
                                                </ul>
                                            }.into_any()
                                        }}
                                    </section>
                                    <section
                                        class="rounded-xl border border-white/10 bg-white/[0.02] p-4 space-y-2"
                                        aria-label=move || tt(context, "Top titles")
                                    >
                                        <h3 class="font-semibold text-sm">{move || tt(context, "Top titles")}</h3>
                                        {if top_titles.is_empty() {
                                            view! { <p class="text-slate-400">{move || tt(context, "No matching telemetry in this window.")}</p> }.into_any()
                                        } else {
                                            view! {
                                                <ul class="divide-y divide-white/10">
                                                    {top_titles
                                                        .iter()
                                                        .take(5)
                                                        .map(|t| {
                                                            let title = if t.series_name.is_empty() {
                                                                t.item_name.clone()
                                                            } else {
                                                                format!("{} — {}", t.series_name, t.item_name)
                                                            };
                                                            let title = if title.trim().is_empty() { tt(context, "Unknown") } else { title };
                                                            let spec = [t.video_resolution.as_str(), t.video_codec.as_str()]
                                                                .into_iter()
                                                                .filter(|s| !s.is_empty())
                                                                .collect::<Vec<_>>()
                                                                .join(" · ");
                                                            let data = crate::tabs::settings::bytes(t.total_data_bytes.max(0) as f64);
                                                            view! {
                                                                <li class="py-2 flex items-center justify-between gap-2">
                                                                    <span class="font-medium truncate">
                                                                        {if spec.is_empty() { title } else { format!("{title} ({spec})") }}
                                                                    </span>
                                                                    <span class="text-slate-400 font-mono shrink-0">
                                                                        {format!("{} · {}", tt_with(context, "{count} plays", &[("count", &t.total_plays.to_string())]), data)}
                                                                    </span>
                                                                </li>
                                                            }
                                                        })
                                                        .collect_view()}
                                                </ul>
                                            }.into_any()
                                        }}
                                    </section>
                                </div>
                            }
                        })}
                    </div>
                }
            }}
        </ObsCard>
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

#[cfg(test)]
mod distribution_bar_tests {
    use super::stream_type_bar_segments;

    #[test]
    fn stream_type_bar_segments_accumulate_offsets_and_clamp_overflow() {
        let rows = [
            ("Direct Play", 6, 60.0, "bg-emerald-400"),
            ("Direct Stream", 2, 20.0, "bg-cyan-400"),
            ("Transcode", 3, 35.0, "bg-amber-400"),
            ("Unknown", 0, 0.0, "bg-slate-400"),
        ];
        let segments = stream_type_bar_segments(&rows);
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0], ("Direct Play", 0.0, 60.0, "fill-emerald-400"));
        assert_eq!(segments[1], ("Direct Stream", 60.0, 20.0, "fill-cyan-400"));
        assert_eq!(segments[2], ("Transcode", 80.0, 20.0, "fill-amber-400"));
    }
}
