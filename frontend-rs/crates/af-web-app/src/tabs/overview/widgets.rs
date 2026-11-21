//! Reusable telemetry surfaces and administrator capacity analysis.
use super::telemetry::*;
use crate::state::{app, json_rows, use_api};
use crate::tabs::l10n::{tt, tt_with, EmptyState, ObsCard};
use af_web_core::{
    api::ApiClient,
    charts::{ChartTimeFormat, ChartValueFormat, Point},
    models::{DiskPartition, GpuMetric},
};
use af_web_ui::{AreaChart, TimeSparkline};
use leptos::prelude::*;
use serde_json::Value;
use wasm_bindgen_futures::spawn_local;

#[component]
fn Gauge(
    #[prop(into)] label: Signal<String>,
    #[prop(into)] value: Signal<Option<f64>>,
) -> impl IntoView {
    let context = app();
    view! {
        <div
            role="meter"
            aria-label=move || tt(context, &label.get())
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow=move || value.get().map(|n| n.clamp(0.0, 100.0).to_string())
            aria-valuetext=move || percent(value.get())
            class="h-2 rounded-full bg-white/5 overflow-hidden mt-3"
        >
            <svg
                viewBox="0 0 100 8"
                preserveAspectRatio="none"
                class="w-full h-full block"
                aria-hidden="true"
            >
                <rect
                    x="0"
                    y="0"
                    height="8"
                    rx="4"
                    width=move || {
                        format!("{:.1}", value.get().unwrap_or_default().clamp(0.0, 100.0))
                    }
                    class=move || {
                        match value.get().unwrap_or_default() {
                            n if n >= 95.0 => "fill-rose-400",
                            n if n >= 85.0 => "fill-amber-400",
                            _ => "fill-indigo-400",
                        }
                    }
                />
            </svg>
        </div>
    }
}
fn live_disk_rates(metrics: &Value, samples: &[Sample]) -> (Option<f64>, Option<f64>) {
    let live_read = number(
        metrics,
        &[
            "/disk_io/read_bytes_sec",
            "/disk_read_bps",
            "/disk_io/read_bps",
            "/disk_io/read",
        ],
    )
    .filter(|n| n.is_finite() && *n >= 0.0)
    .or_else(|| parse_rate(&metrics["disk_io"]["read_speed"]));
    let live_write = number(
        metrics,
        &[
            "/disk_io/write_bytes_sec",
            "/disk_write_bps",
            "/disk_io/write_bps",
            "/disk_io/write",
        ],
    )
    .filter(|n| n.is_finite() && *n >= 0.0)
    .or_else(|| parse_rate(&metrics["disk_io"]["write_speed"]));
    let fallback = samples.last();
    (
        live_read.or_else(|| fallback.and_then(|s| s.read)),
        live_write.or_else(|| fallback.and_then(|s| s.write)),
    )
}

fn live_network_rates(metrics: &Value, samples: &[Sample]) -> (Option<f64>, Option<f64>) {
    let live_rx = number(
        metrics,
        &[
            "/net_rx_bps",
            "/net_down_bps",
            "/network/rx_bps",
            "/network/rx_bytes_sec",
        ],
    )
    .filter(|n| n.is_finite() && *n >= 0.0)
    .or_else(|| parse_rate(&metrics["network"]["down"]));
    let live_tx = number(
        metrics,
        &[
            "/net_tx_bps",
            "/net_up_bps",
            "/network/tx_bps",
            "/network/tx_bytes_sec",
        ],
    )
    .filter(|n| n.is_finite() && *n >= 0.0)
    .or_else(|| parse_rate(&metrics["network"]["up"]));
    let fallback = samples.last();
    (
        live_rx.or_else(|| fallback.and_then(|s| s.rx)),
        live_tx.or_else(|| fallback.and_then(|s| s.tx)),
    )
}

#[component]
pub(super) fn TelemetrySummary(
    cpu: Signal<Option<f64>>,
    memory: Signal<Option<f64>>,
    cpu_points: Signal<Vec<Point>>,
    memory_points: Signal<Vec<Point>>,
    rx_points: Signal<Vec<Point>>,
    tx_points: Signal<Vec<Point>>,
    read_points: Signal<Vec<Point>>,
    write_points: Signal<Vec<Point>>,
    samples: Memo<Vec<Sample>>,
    window: RwSignal<TelemetryWindow>,
) -> impl IntoView {
    let context = app();
    let time_fmt = Signal::derive(move || window.get().time_format());
    let gap = Signal::derive(|| Some(GAP_THRESHOLD_MS));
    let sparse_hint = move |pts: Signal<Vec<Point>>| {
        move || {
            let cov = pts.with(|p| summarize_coverage(p, window.get()));
            cov.is_sparse().then(|| {
                let win_label = tt(context, window.get().key());
                tt_with(
                    context,
                    "Collecting · {count} samples · {window}",
                    &[
                        ("count", &cov.sample_count.to_string()),
                        ("window", &win_label),
                    ],
                )
            })
        }
    };
    view! {
            <div class=move || if context.immersive_overview.get() {
                "grid xl:grid-cols-2 gap-6"
            } else {
                "grid md:grid-cols-2 xl:grid-cols-4 gap-4"
            }>
                <section class="obs-telemetry-surface p-5 min-w-0 border-b border-white/10">
                    <h2 class="font-semibold">{move || tt(context, "Overview.cpuUtilization")}</h2>
                    <p class="text-3xl text-indigo-200 font-semibold tabular-nums mt-3">
                        {move || percent(cpu.get())}
                    </p>
                    <p class="text-xs text-slate-400 mt-2">
                        {move || {
                            context
                                .metrics
                                .with(|v| {
                                    let loads = list(v, &["/load_average"])
                                        .iter()
                                        .take(3)
                                        .map(|value| value.as_f64().map(|n| format!("{n:.2}")).unwrap_or_else(|| "—".into()))
                                        .collect::<Vec<_>>();
                                    let freq = number(v, &["/cpu_freq_mhz", "/cpu/frequency_mhz"])
                                        .map(|freq| format!("{freq:.1} MHz"));
                                    tt_with(
                                        context,
                                        if freq.is_some() { "Overview.loadSummary" } else { "Overview.loadOnly" },
                                        &[
                                            ("freq", freq.as_deref().unwrap_or("—")),
                                            ("l1", loads.first().map(String::as_str).unwrap_or("—")),
                                            ("l5", loads.get(1).map(String::as_str).unwrap_or("—")),
                                            ("l15", loads.get(2).map(String::as_str).unwrap_or("—")),
                                        ],
                                    )
                                })
                        }}
                    </p>
                    <div class="my-4">
                        <TimeSparkline
                            points=cpu_points
                            label="CPU utilization history"
                            primary_label="CPU %"
                            stroke="#818cf8"
                            fill="rgba(129, 140, 248, 0.16)"
                            value_format=ChartValueFormat::Percent
                            time_format=time_fmt
                            gap_threshold_x=gap
                            show_references=true
                            show_endpoints=true
                        />
                        {move || sparse_hint(cpu_points)().map(|msg| view! {
                            <p class="text-[11px] font-mono text-slate-400 mt-1">{msg}</p>
                        })}
                    </div>
                    <details>
                        <summary class="cursor-pointer text-xs text-slate-300 py-2">
                            {move || tt(context, "Per-core utilization")}
                        </summary>
                        <div class="grid grid-cols-4 gap-2 mt-3">
                            {move || {
                                context
                                    .metrics
                                    .with(|v| {
                                        list(v, &["/per_core_cpu", "/cpu/cores"])
                                            .into_iter()
                                            .enumerate()
                                            .map(|(index, core)| {
                                                let value = core
                                                    .as_f64()
                                                    .or_else(|| number(&core, &["/usage", "/usage_pct"]));
                                                view! {
                                                    <div class="min-w-0">
                                                        <p class="text-xs text-slate-400">
                                                            {format!("#{index} {}", percent(value))}
                                                        </p>
                                                        <Gauge
                                                            label=Signal::derive(move || tt_with(context, "Overview.coreGaugeLabel", &[("index", &index.to_string())]))
                                                            value=Signal::derive(move || value)
                                                        />
                                                    </div>
                                                }
                                            })
                                            .collect_view()
                                    })
                            }}
                        </div>
                    </details>
                </section>
                <section class="obs-telemetry-surface p-5 min-w-0 border-b border-white/10">
                    <h2 class="font-semibold">{move || tt(context, "Overview.memorySwap")}</h2>
                    <p class="text-3xl text-cyan-200 font-semibold tabular-nums mt-3">
                        {move || percent(memory.get())}
                    </p>
                    <p class="text-xs text-slate-400 mt-2">
                        {move || {
                            context
                                .metrics
                                .with(|v| match (
                                    gib(v, "memory", "used"),
                                    gib(v, "memory", "total"),
                                ) {
                                    (Some(used), Some(total)) => {
                                        tt_with(
                                            context,
                                            "Overview.memoryCounter",
                                            &[
                                                ("used", &format!("{used:.1}")),
                                                ("total", &format!("{total:.1}")),
                                                ("available", &format!("{:.1}", gib(v, "memory", "available").unwrap_or((total - used).max(0.0)))),
                                            ],
                                        )
                                    }
                                    _ => tt(context, "Overview.memoryWaiting"),
                                })
                        }}
                    </p>
                    <Gauge label="Physical memory pressure" value=memory />
                    <div class="my-4">
                        <TimeSparkline
                            points=memory_points
                            label="Memory usage history"
                            primary_label="Memory %"
                            stroke="#22d3ee"
                            fill="rgba(34, 211, 238, 0.16)"
                            value_format=ChartValueFormat::Percent
                            time_format=time_fmt
                            gap_threshold_x=gap
                            show_references=true
                            show_endpoints=true
                        />
                        {move || sparse_hint(memory_points)().map(|msg| view! {
                            <p class="text-[11px] font-mono text-slate-400 mt-1">{msg}</p>
                        })}
                    </div>
                    <p class="text-xs text-slate-400">
                        {move || {
                            context
                                .metrics
                                .with(|v| match (gib(v, "swap", "used"), gib(v, "swap", "total")) {
                                    (Some(used), Some(total)) if total > 0.0 => {
                                        tt_with(
                                            context,
                                            "Overview.swapCounter",
                                            &[
                                                ("used", &format!("{used:.2}")),
                                                ("total", &format!("{total:.1}")),
                                                ("pct", &format!("{:.1}%", used / total * 100.0)),
                                            ],
                                        )
                                    }
                                    (_, Some(0.0)) => tt(context, "Overview.noSwap"),
                                    _ => tt(context, "Overview.swapUnavailable"),
                                })
                        }}
                    </p>
                </section>
                <section class="obs-telemetry-surface p-5 min-w-0 border-b border-white/10">
                    <h2 class="font-semibold">
                        {move || tt(context, "Overview.networkBandwidth")}
                    </h2>
                    <div class="grid grid-cols-2 gap-3 mt-3">
                        <div>
                            <p class="text-xs text-cyan-300 flex items-center gap-1.5">
                                <span class="inline-block w-2 h-2 rounded-full bg-cyan-400"></span>
                                {move || tt(context, "Receive")}
                            </p>
                            <p class="text-xl text-cyan-200 tabular-nums mt-2">
                                {move || {
                                    let locale = crate::tabs::l10n::locale(context);
                                    let (rx, _) = context.metrics.with(|m| samples.with(|s| live_network_rates(m, s)));
                                    rate(&locale, rx)
                                }}
                            </p>
                        </div>
                        <div>
                            <p class="text-xs text-indigo-300 flex items-center gap-1.5">
                                <span class="inline-block w-2 h-2 rounded-full bg-indigo-400"></span>
                                {move || tt(context, "Transmit")}
                            </p>
                            <p class="text-xl text-indigo-200 tabular-nums mt-2">
                                {move || {
                                    let locale = crate::tabs::l10n::locale(context);
                                    let (_, tx) = context.metrics.with(|m| samples.with(|s| live_network_rates(m, s)));
                                    rate(&locale, tx)
                                }}
                            </p>
                        </div>
                    </div>
                    <div class="my-4">
                        <TimeSparkline
                            points=rx_points
                            secondary=tx_points
                            label="Network RX and TX throughput history"
                            primary_label="Receive"
                            secondary_label="Transmit"
                            stroke="#06b6d4"
                            fill="rgba(6, 182, 212, 0.16)"
                            secondary_stroke="#6366f1"
                            secondary_fill="rgba(99, 102, 241, 0.14)"
                            value_format=ChartValueFormat::BytesPerSec
                            time_format=time_fmt
                            gap_threshold_x=gap
                            show_references=true
                            show_endpoints=true
                        />
                        {move || sparse_hint(rx_points)().map(|msg| view! {
                            <p class="text-[11px] font-mono text-slate-400 mt-1">{msg}</p>
                        })}
                    </div>
                    <p class="text-xs text-slate-400">
                        {move || {
                            samples
                                .with(|s| {
                                    s.last()
                                        .map(|s| {
                                            tt_with(
                                                context,
                                                "Overview.sinceBootIo",
                                                &[("rx", &bytes(&crate::tabs::l10n::locale(context), s.rx_total)), ("tx", &bytes(&crate::tabs::l10n::locale(context), s.tx_total))],
                                            )
                                        })
                                        .unwrap_or_else(|| tt(context, "Overview.cumulativeUnavailable"))
                                })
                        }}
                    </p>
                    <details class="mt-3">
                        <summary class="cursor-pointer text-xs text-slate-300 py-2">
                            {move || tt(context, "Interface breakdown")}
                        </summary>
                        <Show when=move || context.metrics.with(|v| list(v, &["/network/interfaces", "/network_interfaces", "/interfaces"]).is_empty())>
                            <p class="text-xs text-slate-400">{move || tt(context, "No interface telemetry reported")}</p>
                        </Show>
                        {move || {
                            context
                                .metrics
                                .with(|v| {
                                    list(
                                            v,
                                            &[
                                                "/network/interfaces",
                                                "/network_interfaces",
                                                "/interfaces",
                                            ],
                                        )
                                        .into_iter()
                                        .map(|nic| {
                                            view! {
                                                <p class="text-xs text-slate-400 mt-2 break-words">
                                                    {move || tt_with(context, "{name} · RX {rx} · TX {tx}", &[("name", &(text(&crate::tabs::l10n::locale(context), &nic, &["/name", "/interface"])).to_string()), ("rx", &(rate(&crate::tabs::l10n::locale(context),
                                                            number(&nic, &["/rx_bps"])
                                                                .or_else(|| parse_rate(&nic["down"])),
                                                        )).to_string()), ("tx", &(rate(&crate::tabs::l10n::locale(context),
                                                            number(&nic, &["/tx_bps"])
                                                                .or_else(|| parse_rate(&nic["up"])),
                                                        )).to_string())])}
                                                </p>
                                            }
                                        })
                                        .collect_view()
                                })
                        }}
                    </details>
                </section>
                <section class="obs-telemetry-surface p-5 min-w-0 border-b border-white/10" data-testid="disk-io-card">
                    <div class="flex flex-wrap items-baseline justify-between gap-2">
                        <h2 class="font-semibold">{move || tt(context, "Disk I/O")}</h2>
                        <span class="text-xs text-slate-400 tabular-nums">
                            {move || {
                                let locale = crate::tabs::l10n::locale(context);
                                let (r, w) = context.metrics.with(|m| samples.with(|s| live_disk_rates(m, s)));
                                let total = match (r, w) {
                                    (Some(r), Some(w)) => Some(r + w),
                                    (Some(r), None) => Some(r),
                                    (None, Some(w)) => Some(w),
                                    (None, None) => None,
                                };
                                tt_with(context, "Total {rate}", &[("rate", &rate(&locale, total))])
                            }}
                        </span>
                    </div>
                    <div class="grid grid-cols-2 gap-3 mt-3">
                        <div>
                            <p class="text-xs text-amber-300 flex items-center gap-1.5">
                                <span class="inline-block w-2 h-2 rounded-full bg-amber-400"></span>
                                {move || tt(context, "Disk Read")}
                            </p>
                            <p class="text-xl text-amber-200 tabular-nums mt-2">
                                {move || {
                                    let locale = crate::tabs::l10n::locale(context);
                                    let (r, _) = context.metrics.with(|m| samples.with(|s| live_disk_rates(m, s)));
                                    rate(&locale, r)
                                }}
                            </p>
                        </div>
                        <div>
                            <p class="text-xs text-sky-300 flex items-center gap-1.5">
                                <span class="inline-block w-2 h-2 rounded-full bg-sky-400"></span>
                                {move || tt(context, "Disk Write")}
                            </p>
                            <p class="text-xl text-sky-200 tabular-nums mt-2">
                                {move || {
                                    let locale = crate::tabs::l10n::locale(context);
                                    let (_, w) = context.metrics.with(|m| samples.with(|s| live_disk_rates(m, s)));
                                    rate(&locale, w)
                                }}
                            </p>
                        </div>
                    </div>
                    <div class="my-4">
                        <TimeSparkline
                            points=read_points
                            secondary=write_points
                            label="Disk read and write throughput history"
                            primary_label="Disk Read"
                            secondary_label="Disk Write"
                            stroke="#f59e0b"
                            fill="rgba(245, 158, 11, 0.16)"
                            secondary_stroke="#38bdf8"
                            secondary_fill="rgba(56, 189, 248, 0.14)"
                            value_format=ChartValueFormat::BytesPerSec
                            time_format=time_fmt
                            gap_threshold_x=gap
                            show_references=true
                            show_endpoints=true
                        />
                        {move || sparse_hint(read_points)().map(|msg| view! {
                            <p class="text-[11px] font-mono text-slate-400 mt-1">{msg}</p>
                        })}
                    </div>
                    <div
                        role="group"
                        aria-label=move || tt(context, "Current disk throughput share")
                        class="grid grid-cols-2 gap-3 pt-2 border-t border-white/10 text-xs tabular-nums"
                    >
                        <div>
                            <p class="text-slate-400">{move || tt(context, "Read share")}</p>
                            <p class="font-mono font-semibold text-amber-300 mt-1">
                                {move || {
                                    let (r, w) = context.metrics.with(|m| samples.with(|s| live_disk_rates(m, s)));
                                    match disk_io_share(r, w).0 {
                                        Some(pct) => format!("{pct:.0}%"),
                                        None if r.is_some() || w.is_some() => tt(context, "Idle"),
                                        None => tt(context, "Unavailable"),
                                    }
                                }}
                            </p>
                        </div>
                        <div>
                            <p class="text-slate-400">{move || tt(context, "Write share")}</p>
                            <p class="font-mono font-semibold text-sky-300 mt-1">
                                {move || {
                                    let (r, w) = context.metrics.with(|m| samples.with(|s| live_disk_rates(m, s)));
                                    match disk_io_share(r, w).1 {
                                        Some(pct) => format!("{pct:.0}%"),
                                        None if r.is_some() || w.is_some() => tt(context, "Idle"),
                                        None => tt(context, "Unavailable"),
                                    }
                                }}
                            </p>
                        </div>
                    </div>
                </section>
            </div>
    }
}

#[component]
pub(super) fn DataUsageHistory() -> impl IntoView {
    let context = app();
    let days = RwSignal::new(30u32);
    // Uses the signed-in auth history endpoint with server-side daily_transfer
    // aggregation so 7/30/90-day coverage is never truncated by raw row caps.
    let history = use_api(Signal::derive(move || {
        context.history_revision.track();
        daily_transfer_history_url(days.get())
    }));
    let summary = Memo::new(move |_| history.data.with(decode_daily_usage));
    let series = Memo::new(move |_| summary.with(DailyUsageSummary::chart_series));
    let download_points = Signal::derive(move || series.with(|(d, _)| d.clone()));
    let upload_points = Signal::derive(move || series.with(|(_, u)| u.clone()));
    let gap = Signal::derive(|| Some(DAILY_GAP_THRESHOLD_MS));

    view! {
        <ObsCard>
            <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
                <div>
                    <h2 class="text-lg font-semibold">
                        {move || tt(context, "Overview.dataUsageHistory")}
                    </h2>
                    <p class="text-xs text-slate-400 mt-1">
                        {move || tt(
                            context,
                            "Daily network transfer from persisted host counters. Unobserved days remain distinct from zero-transfer days.",
                        )}
                    </p>
                </div>
                <div
                    role="group"
                    aria-label=move || tt(context, "History Range Selection")
                    class="flex gap-1"
                >
                    {[(7u32, "7d"), (30u32, "30d"), (90u32, "90d")]
                        .into_iter()
                        .map(|(option, label)| {
                            view! {
                                <button
                                    type="button"
                                    class="obs-tab-pill px-3 py-2 min-h-11"
                                    class:obs-tab-pill-active=move || days.get() == option
                                    aria-pressed=move || (days.get() == option).to_string()
                                    data-testid=format!("data-usage-window-{label}")
                                    on:click=move |_| days.set(option)
                                >
                                    {move || tt(context, label)}
                                </button>
                            }
                        })
                        .collect_view()}
                </div>
            </div>
            <div class="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-300 mb-3">
                <p class="font-mono">
                    {move || {
                        let observed = summary.with(|s| s.days.len());
                        let total_days = days.get() as usize;
                        let base = tt_with(
                            context,
                            "Coverage: {observed} of {days} days observed",
                            &[
                                ("observed", &observed.to_string()),
                                ("days", &total_days.to_string()),
                            ],
                        );
                        if observed > 0 && observed < total_days {
                            format!("{base} · {}", tt(context, "Partial coverage"))
                        } else {
                            base
                        }
                    }}
                </p>
                <div class="flex items-center gap-4 font-semibold">
                    <span class="inline-flex items-center gap-1.5 text-cyan-300">
                        <span class="w-2.5 h-2.5 rounded-full bg-cyan-400"></span>
                        {move || tt(context, "Downloaded")}
                    </span>
                    <span class="inline-flex items-center gap-1.5 text-indigo-300">
                        <span class="w-2.5 h-2.5 rounded-full bg-indigo-400"></span>
                        {move || tt(context, "Uploaded")}
                    </span>
                </div>
            </div>
            <p role="note" class="text-xs text-slate-400 mb-3">
                {move || {
                    let mut note = tt(
                        context,
                        "Counter deltas are assigned to the UTC day of the ending sample; sparse intervals may span days.",
                    );
                    let resets = summary.with(|s| s.counter_resets);
                    if resets > 0 {
                        note.push(' ');
                        note.push_str(&tt_with(
                            context,
                            "{count} counter resets detected; only post-reset values are counted.",
                            &[("count", &resets.to_string())],
                        ));
                    }
                    let ignored = summary.with(|s| s.invalid_samples + s.conflicting_samples);
                    if ignored > 0 {
                        note.push(' ');
                        note.push_str(&tt_with(
                            context,
                            "{count} invalid or conflicting samples ignored.",
                            &[("count", &ignored.to_string())],
                        ));
                    }
                    note
                }}
            </p>
            <Show when=move || history.error.get().is_some()>
                <p role="alert" class="text-sm text-amber-300 mb-3">
                    {move || tt(context, "Failed to load transfer history.")}
                    <button class="underline ml-3" on:click=move |_| history.refresh()>
                        {move || tt(context, "Retry")}
                    </button>
                </p>
            </Show>
            <Show when=move || history.loading.get() && summary.with(|s| s.days.is_empty())>
                <p role="status" class="text-xs text-slate-400 py-6">
                    {move || tt(context, "Loading selected history window…")}
                </p>
            </Show>
            <Show when=move || !history.loading.get() && history.error.get().is_none() && summary.with(|s| s.days.is_empty())>
                <p role="note" class="text-xs text-slate-400 py-6">
                    {move || tt(context, "No bandwidth observations for this window; no zero-valued days are inferred.")}
                </p>
            </Show>
            <Show when=move || summary.with(|s| !s.days.is_empty())>
                <Show
                    when=move || summary.with(DailyUsageSummary::has_measured_interval)
                    fallback=move || view! {
                        <p role="note" class="text-xs text-slate-400 py-4">
                            {move || tt(context, "Only single-point observations recorded; waiting for a second sample to measure transfer deltas.")}
                        </p>
                    }
                >
                    <AreaChart
                        points=download_points
                        secondary=upload_points
                        label="Daily download and upload transfer volume"
                        primary_label="Downloaded"
                        secondary_label="Uploaded"
                        stroke="#06b6d4"
                        fill="rgba(6, 182, 212, 0.22)"
                        secondary_stroke="#6366f1"
                        secondary_fill="rgba(99, 102, 241, 0.20)"
                        value_format=ChartValueFormat::Bytes
                        time_format=ChartTimeFormat::Date
                        gap_threshold_x=gap
                        show_dots=true
                        height=250.0
                    />
                </Show>
            </Show>
            <div class="grid sm:grid-cols-2 gap-4 mt-4 pt-3 border-t border-white/10">
                <div>
                    <p class="text-xs text-slate-400">
                        {move || tt_with(
                            context,
                            "Downloaded ({days})",
                            &[("days", &tt(context, match days.get() { 7 => "7d", 90 => "90d", _ => "30d" }))],
                        )}
                    </p>
                    <p class="text-2xl text-cyan-200 font-semibold tabular-nums mt-1">
                        {move || {
                            let locale = crate::tabs::l10n::locale(context);
                            bytes(&locale, summary.with(DailyUsageSummary::total_downloaded))
                        }}
                    </p>
                </div>
                <div>
                    <p class="text-xs text-slate-400">
                        {move || tt_with(
                            context,
                            "Uploaded ({days})",
                            &[("days", &tt(context, match days.get() { 7 => "7d", 90 => "90d", _ => "30d" }))],
                        )}
                    </p>
                    <p class="text-2xl text-indigo-200 font-semibold tabular-nums mt-1">
                        {move || {
                            let locale = crate::tabs::l10n::locale(context);
                            bytes(&locale, summary.with(DailyUsageSummary::total_uploaded))
                        }}
                    </p>
                </div>
            </div>
        </ObsCard>
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct StoragePartitionSummary {
    pub(super) row: Value,
    pub(super) mount: String,
    pub(super) total_gb: Option<f64>,
    pub(super) used_gb: Option<f64>,
    pub(super) usage_pct: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct StoragePoolSummary {
    pub(super) mounts: Vec<String>,
    pub(super) visible: Vec<StoragePartitionSummary>,
    pub(super) total_gb: Option<f64>,
    pub(super) used_gb: Option<f64>,
    pub(super) free_gb: Option<f64>,
    pub(super) usage_pct: Option<f64>,
}

pub(super) fn summarize_storage_pool(
    partitions: &[Value],
    selected_mount: &str,
) -> StoragePoolSummary {
    let parsed: Vec<StoragePartitionSummary> = partitions
        .iter()
        .map(|disk| {
            let mount = raw_text(disk, &["/mount_point", "/mount", "/path"]).unwrap_or_default();
            let total_gb = number(disk, &["/total_gb"])
                .or_else(|| number(disk, &["/total", "/total_bytes"]).map(|n| n / 1_073_741_824.0));
            let used_gb = number(disk, &["/used_gb"])
                .or_else(|| number(disk, &["/used", "/used_bytes"]).map(|n| n / 1_073_741_824.0));
            let usage_pct =
                number(disk, &["/used_pct", "/usage_pct"]).or_else(|| ratio(used_gb, total_gb));
            StoragePartitionSummary {
                row: disk.clone(),
                mount,
                total_gb,
                used_gb,
                usage_pct,
            }
        })
        .collect();
    let mut mounts: Vec<String> = Vec::new();
    for item in &parsed {
        if !item.mount.is_empty() && !mounts.iter().any(|existing| existing == &item.mount) {
            mounts.push(item.mount.clone());
        }
    }
    let effective_mount =
        if !selected_mount.is_empty() && mounts.iter().any(|existing| existing == selected_mount) {
            selected_mount
        } else {
            ""
        };
    let visible: Vec<StoragePartitionSummary> = if effective_mount.is_empty() {
        parsed
    } else {
        parsed
            .into_iter()
            .filter(|item| item.mount == effective_mount)
            .collect()
    };
    let mut total_acc = 0.0;
    let mut used_acc = 0.0;
    let mut has_capacity = false;
    for item in &visible {
        if let (Some(used), Some(total)) = (item.used_gb, item.total_gb) {
            if total.is_finite() && used.is_finite() && total > 0.0 && used >= 0.0 {
                total_acc += total;
                used_acc += used;
                has_capacity = true;
            }
        }
    }
    let (total_gb, used_gb, free_gb, usage_pct) = if has_capacity {
        let free = (total_acc - used_acc).max(0.0);
        (
            Some(total_acc),
            Some(used_acc),
            Some(free),
            ratio(Some(used_acc), Some(total_acc)),
        )
    } else {
        (None, None, None, None)
    };
    StoragePoolSummary {
        mounts,
        visible,
        total_gb,
        used_gb,
        free_gb,
        usage_pct,
    }
}

#[component]
pub(super) fn StorageGpuTelemetry() -> impl IntoView {
    let context = app();
    let selected_mount = RwSignal::new(String::new());
    let partitions = Memo::new(move |_| {
        context.metrics.with(|v| {
            list(v, &["/disk_partitions", "/disks", "/disk_space"])
                .into_iter()
                .map(telemetry_row::<DiskPartition>)
                .collect::<Vec<_>>()
        })
    });
    let pool = Memo::new(move |_| {
        partitions.with(|rows| summarize_storage_pool(rows, &selected_mount.get()))
    });
    view! {
            <div class=move || if context.show_gpu.get() { "grid lg:grid-cols-2 gap-5" } else { "grid gap-5" }>
                <ObsCard title=Signal::derive(move || tt(
                    context,
                    "Overview.storagePartitions",
                ))>
                    <Show when=move || pool.with(|summary| !summary.mounts.is_empty())>
                        <div class="flex flex-wrap items-center justify-between gap-3 pb-3 mb-3 border-b border-white/10">
                            <p class="text-xs text-slate-400">
                                {move || {
                                    let count = pool.with(|summary| summary.visible.len());
                                    tt_with(
                                        context,
                                        "{count} partitions shown",
                                        &[("count", &count.to_string())],
                                    )
                                }}
                            </p>
                            <select
                                class="glass-input px-3 py-1.5 text-xs min-h-9"
                                data-testid="storage-partition-filter"
                                aria-label=move || tt(context, "Filter storage partitions")
                                prop:value=move || {
                                    let current = selected_mount.get();
                                    if pool.with(|summary| summary.mounts.iter().any(|m| m == &current)) {
                                        current
                                    } else {
                                        String::new()
                                    }
                                }
                                on:change=move |event| selected_mount.set(event_target_value(&event))
                            >
                                <option value="">{move || tt(context, "All Drives")}</option>
                                {move || {
                                    pool.with(|summary| {
                                        summary
                                            .mounts
                                            .iter()
                                            .cloned()
                                            .map(|mount| {
                                                let label = mount.clone();
                                                view! { <option value=mount>{label}</option> }
                                            })
                                            .collect_view()
                                    })
                                }}
                            </select>
                        </div>
                    </Show>
                    <Show when=move || pool.with(|summary| summary.total_gb.is_some())>
                        <div
                            class="rounded-xl border border-white/10 bg-white/[0.02] p-3.5 mb-3"
                            data-testid="storage-pool-summary"
                        >
                            <div class="flex items-baseline justify-between gap-3">
                                <span class="text-xs font-semibold uppercase tracking-wide text-slate-300">
                                    {move || tt(context, "Storage pool summary")}
                                </span>
                                <span class="text-sm font-semibold tabular-nums text-indigo-200">
                                    {move || percent(pool.with(|summary| summary.usage_pct))}
                                </span>
                            </div>
                            <Gauge
                                label="Storage pool capacity"
                                value=Signal::derive(move || pool.with(|summary| summary.usage_pct))
                            />
                            <p class="text-xs text-slate-400 mt-2 tabular-nums">
                                {move || {
                                    pool.with(|summary| match (summary.used_gb, summary.total_gb, summary.free_gb) {
                                        (Some(used), Some(total), Some(free)) => tt_with(
                                            context,
                                            "{used} / {total} GB · {free} GB free",
                                            &[
                                                ("used", &format!("{used:.1}")),
                                                ("total", &format!("{total:.1}")),
                                                ("free", &format!("{free:.1}")),
                                            ],
                                        ),
                                        _ => tt(context, "Capacity counters unavailable"),
                                    })
                                }}
                            </p>
                        </div>
                    </Show>
                    {move || {
                        pool.with(|summary| {
                            summary
                                .visible
                                .iter()
                                .map(|entry| {
                                    let disk = entry.row.clone();
                                    let disk_heading = disk.clone();
                                    let used = entry.used_gb;
                                    let total = entry.total_gb;
                                    let usage = entry.usage_pct;
                                    view! {
                                        <article
                                            class="py-4 border-b border-white/5"
                                            data-testid="storage-partition-row"
                                        >
                                            <div class="flex justify-between gap-3">
                                                <h3 class="font-medium break-all">
                                                    {move || text(&crate::tabs::l10n::locale(context), &disk_heading, &["/mount_point", "/mount", "/path"])}
                                                </h3>
                                                <span class=move || {
                                                    if usage.unwrap_or_default() >= 95.0 {
                                                        "text-rose-300"
                                                    } else if usage.unwrap_or_default() >= 85.0 {
                                                        "text-amber-300"
                                                    } else {
                                                        "text-slate-300"
                                                    }
                                                }>{percent(usage)}</span>
                                            </div>
                                            <p class="text-xs text-slate-400 mt-2">
                                                {move || format!(
                                                    "{} · {}",
                                                    text(&crate::tabs::l10n::locale(context), &disk, &["/device", "/name"]),
                                                    text(&crate::tabs::l10n::locale(context), &disk, &["/fs_type", "/filesystem", "/file_system"]),
                                                )}
                                            </p>
                                            <Gauge
                                                label="Partition capacity"
                                                value=Signal::derive(move || usage)
                                            />
                                            <p class="text-xs text-slate-400 mt-2">
                                                {move || match (used, total) {
                                                    (Some(used), Some(total)) => tt_with(
                                                        context,
                                                        "{used} / {total} GB · {free} GB free",
                                                        &[
                                                            ("used", &format!("{used:.1}")),
                                                            ("total", &format!("{total:.1}")),
                                                            ("free", &format!("{:.1}", (total - used).max(0.0))),
                                                        ],
                                                    ),
                                                    _ => tt(context, "Capacity counters unavailable"),
                                                }}
                                            </p>
                                        </article>
                                    }
                                })
                                .collect_view()
                        })
                    }}
                    <Show when=move || partitions.with(Vec::is_empty)>
                        <EmptyState
                            title="No partition telemetry"
                            description="Mounted volumes appear when reported by the host."
                        />
                    </Show>
                </ObsCard>
                <Show when=move || context.show_gpu.get()>
                <ObsCard title=Signal::derive(move || tt(
                    context,
                    "Overview.gpuAccelerators",
                ))>
                    {move || {
                        context
                            .metrics
                            .with(|v| {
                                list(v, &["/gpus"])
                                    .into_iter()
                                    .map(telemetry_row::<GpuMetric>)
                                    .map(|gpu| {
                                        let usage = number(&gpu, &["/usage_pct", "/utilization"]);
                                        let total = number(
                                            &gpu,
                                            &["/memory_total", "/vram_total_mb"],
                                        );
                                        let gpu_heading = gpu.clone();
                                        let gpu_metadata = gpu.clone();
                                        view! {
                                            <article class="py-4 border-b border-white/5">
                                                <h3 class="font-medium break-words">
                                                    {move || text(&crate::tabs::l10n::locale(context), &gpu_heading, &["/name", "/product"])}
                                                </h3>
                                                <p class="text-sm text-indigo-200 mt-2">
                                                    {move || format!(
                                                        "{} · {} °C",
                                                        percent(usage),
                                                        text(&crate::tabs::l10n::locale(context), &gpu_metadata, &["/temp", "/temperature", "/temperature_c"]),
                                                    )}
                                                </p>
                                                <Gauge
                                                    label="GPU utilization"
                                                    value=Signal::derive(move || usage)
                                                />
                                                <p class="text-xs text-slate-400 mt-3">
                                                    {move || tt(
                                                        context,
                                                        &(if total.is_some_and(|n| n > 0.0) {
                                                            tt_with(context, "VRAM {used} / {total} MiB", &[("used", &(text(&crate::tabs::l10n::locale(context), &gpu, &["/memory_used", "/vram_used_mb"])).to_string()), ("total", &(text(&crate::tabs::l10n::locale(context), &gpu, &["/memory_total", "/vram_total_mb"])).to_string())])
                                                        } else {
                                                            "Integrated GPU · shared system memory".into()
                                                        }),
                                                    )}
                                                </p>
                                            </article>
                                        }
                                    })
                                    .collect_view()
                            })
                    }}<Show when=move || context.metrics.with(|v| list(v, &["/gpus"]).is_empty())>
                        <EmptyState
                            title="No GPU telemetry reported"
                            description="Dedicated GPU counters require NVML or DRM support. Integrated graphics can share system memory."
                        />
                    </Show>
                </ObsCard>
                </Show>
            </div>
    }
}

fn bandwidth_limits(recommendation: &Value) -> Option<Value> {
    let upload = recommendation["recommended_upload_kbps"]
        .as_i64()
        .filter(|value| *value >= 0)?;
    let download = recommendation["recommended_download_kbps"]
        .as_i64()
        .filter(|value| *value >= 0)?;
    Some(serde_json::json!({ "upload_kbps": upload, "download_kbps": download }))
}

fn trend_palette(trend: &str) -> (&'static str, &'static str, &'static str) {
    match trend.trim().to_ascii_lowercase().as_str() {
        "increasing" => (
            "#fbbf24",
            "rgba(245, 158, 11, 0.16)",
            "text-amber-300 border-amber-500/30 bg-amber-500/10",
        ),
        "critical" => (
            "#f87171",
            "rgba(239, 68, 68, 0.16)",
            "text-rose-300 border-rose-500/30 bg-rose-500/10",
        ),
        "stable" => (
            "#34d399",
            "rgba(16, 185, 129, 0.16)",
            "text-emerald-300 border-emerald-500/30 bg-emerald-500/10",
        ),
        "decreasing" => (
            "#60a5fa",
            "rgba(59, 130, 246, 0.16)",
            "text-sky-300 border-sky-500/30 bg-sky-500/10",
        ),
        _ => (
            "#94a3b8",
            "rgba(148, 163, 184, 0.14)",
            "text-slate-300 border-slate-500/30 bg-slate-500/10",
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BandwidthDiagnostics {
    partial_apply: bool,
    warning: Option<String>,
    warnings: Vec<String>,
    recovery: Option<String>,
    message: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BandwidthApplyOutcome {
    message: String,
    is_error: bool,
    is_partial_or_warning: bool,
}

impl BandwidthApplyOutcome {
    fn aria_role(&self) -> &'static str {
        if self.is_error {
            "alert"
        } else {
            "status"
        }
    }
}

fn non_empty_str(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn extract_bandwidth_diagnostics(payload: &Value) -> BandwidthDiagnostics {
    let partial_apply = payload["partial_apply"].as_bool() == Some(true)
        || payload["partialApply"].as_bool() == Some(true)
        || payload["status"].as_str().is_some_and(|s| {
            s.eq_ignore_ascii_case("partial") || s.eq_ignore_ascii_case("partial_apply")
        });

    let warning = ["/warning", "/recovery_warning", "/recoveryWarning"]
        .iter()
        .find_map(|ptr| payload.pointer(ptr).and_then(non_empty_str));

    let mut warnings = Vec::new();
    if let Some(items) = payload["warnings"].as_array() {
        for item in items {
            if let Some(text) = non_empty_str(item) {
                if warning.as_deref() != Some(text.as_str()) && !warnings.contains(&text) {
                    warnings.push(text);
                }
            }
        }
    }

    let recovery = [
        "/recovery_diagnostic",
        "/recoveryDiagnostic",
        "/recovery_error",
        "/recoveryError",
        "/recovery_message",
        "/recoveryMessage",
        "/recovery",
        "/diagnostic",
        "/rollback_error",
        "/rollbackError",
    ]
    .iter()
    .find_map(|ptr| payload.pointer(ptr).and_then(non_empty_str));

    let message = non_empty_str(&payload["message"]);
    let error = non_empty_str(&payload["error"]);

    BandwidthDiagnostics {
        partial_apply,
        warning,
        warnings,
        recovery,
        message,
        error,
    }
}

fn summarize_bandwidth_apply_outcome(
    context: crate::state::AppContext,
    ok: bool,
    status: u16,
    payload: &Value,
    raw_body: &str,
    requested_limits: &Value,
) -> BandwidthApplyOutcome {
    let diag = extract_bandwidth_diagnostics(payload);
    let has_partial_or_warning = diag.partial_apply
        || diag.warning.is_some()
        || !diag.warnings.is_empty()
        || diag.recovery.is_some();

    if ok && !has_partial_or_warning {
        return BandwidthApplyOutcome {
            message: format_bandwidth_applied_toast(context, payload, requested_limits),
            is_error: false,
            is_partial_or_warning: false,
        };
    }

    let mut parts: Vec<String> = Vec::new();
    let push_unique = |parts: &mut Vec<String>, text: String| {
        let trimmed = text.trim();
        if !trimmed.is_empty() && !parts.iter().any(|existing| existing == trimmed) {
            parts.push(trimmed.to_string());
        }
    };

    if diag.partial_apply {
        let (client, rx, tx) = parse_bandwidth_applied_details(payload, requested_limits);
        let headline = tt(context, "Bandwidth limits partially applied");
        let detail = match (client, rx, tx) {
            (Some(c), Some(r), Some(t)) => {
                let limits_text = tt_with(
                    context,
                    "RX {rx} KiB/s · TX {tx} KiB/s",
                    &[("rx", &r.to_string()), ("tx", &t.to_string())],
                );
                format!("{headline} ({c}: {limits_text})")
            }
            (Some(c), _, _) => format!("{headline} ({c})"),
            _ => headline,
        };
        push_unique(&mut parts, detail);
        if let Some(msg) = diag.message.as_ref().or(diag.error.as_ref()) {
            push_unique(&mut parts, tt(context, msg));
        }
    } else if !ok {
        if let Some(msg) = diag.message.as_ref().or(diag.error.as_ref()) {
            push_unique(&mut parts, tt(context, msg));
        } else if !raw_body.trim().is_empty() && payload.is_null() {
            push_unique(&mut parts, raw_body.trim().to_string());
        } else {
            push_unique(
                &mut parts,
                tt_with(
                    context,
                    "Bandwidth apply failed (HTTP {status})",
                    &[("status", &status.to_string())],
                ),
            );
        }
    } else {
        push_unique(
            &mut parts,
            format_bandwidth_applied_toast(context, payload, requested_limits),
        );
    }

    if let Some(warning) = diag.warning {
        push_unique(&mut parts, tt(context, &warning));
    }
    for extra in diag.warnings {
        push_unique(&mut parts, tt(context, &extra));
    }
    if let Some(recovery) = diag.recovery {
        push_unique(&mut parts, tt(context, &recovery));
    }

    BandwidthApplyOutcome {
        message: parts.join(" — "),
        is_error: true,
        is_partial_or_warning: has_partial_or_warning,
    }
}

fn format_bandwidth_applied_toast(
    context: crate::state::AppContext,
    response: &Value,
    requested_limits: &Value,
) -> String {
    let base = tt(context, "Bandwidth limits applied");
    let (client, rx, tx) = parse_bandwidth_applied_details(response, requested_limits);
    match (client, rx, tx) {
        (Some(c), Some(r), Some(t)) => {
            let limits_text = tt_with(
                context,
                "RX {rx} KiB/s · TX {tx} KiB/s",
                &[("rx", &r.to_string()), ("tx", &t.to_string())],
            );
            format!("{base} ({c}: {limits_text})")
        }
        (Some(c), _, _) => format!("{base} ({c})"),
        (None, Some(r), Some(t)) => {
            let limits_text = tt_with(
                context,
                "RX {rx} KiB/s · TX {tx} KiB/s",
                &[("rx", &r.to_string()), ("tx", &t.to_string())],
            );
            format!("{base} ({limits_text})")
        }
        (None, _, _) => base,
    }
}

fn parse_bandwidth_applied_details(
    response: &Value,
    requested_limits: &Value,
) -> (Option<String>, Option<i64>, Option<i64>) {
    let client = response["applied_client"]
        .as_str()
        .or_else(|| response["client"].as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let rx = response["download_kbps"]
        .as_i64()
        .or_else(|| requested_limits["download_kbps"].as_i64());
    let tx = response["upload_kbps"]
        .as_i64()
        .or_else(|| requested_limits["upload_kbps"].as_i64());
    (client, rx, tx)
}

#[component]
pub(super) fn CapacityPredictions() -> impl IntoView {
    let context = app();
    let report = use_api("/api/v1/admin/ai/predictions".to_string());
    let history_30d = use_api(capacity_history_url());
    let capacity_series =
        Memo::new(move |_| derive_capacity_history(&json_rows(&history_30d.data.get())));
    let busy = RwSignal::new(false);
    let applying = RwSignal::new(false);
    let bandwidth = RwSignal::new(Value::Null);
    let bandwidth_feedback = RwSignal::new(None::<BandwidthApplyOutcome>);
    view! {
        <ObsCard title=Signal::derive(move || tt(context, "Overview.capacityPredictions"))>
            <div class="flex flex-wrap items-center justify-between gap-3 mb-5">
                <div class="flex flex-wrap gap-3">
                    <button
                        class="glass-button px-4 py-2 min-h-11"
                        disabled=move || busy.get() || applying.get()
                        on:click=move |_| {
                            if !context.is_admin() || busy.get_untracked() || applying.get_untracked() {
                                return;
                            }
                            busy.set(true);
                            history_30d.refresh();
                            spawn_local(async move {
                                let result = ApiClient
                                    .post("/api/v1/admin/ai/predictions/analyze", None)
                                    .await;
                                if busy.is_disposed() {
                                    return;
                                }
                                match result {
                                    Ok(value) => {
                                        report.data.set(value);
                                        report.error.set(None);
                                    }
                                    Err(e) => context.toast(tt(context, &e.message), true),
                                }
                                busy.set(false);
                            });
                        }
                    >
                        {move || tt(context, "Analyze capacity")}
                    </button>
                    <button
                        class="glass-button px-4 py-2 min-h-11"
                        disabled=move || busy.get() || applying.get()
                        on:click=move |_| {
                            if !context.is_admin() || busy.get_untracked() || applying.get_untracked() {
                                return;
                            }
                            busy.set(true);
                            bandwidth_feedback.set(None);
                            spawn_local(async move {
                                let result = ApiClient
                                    .post("/api/v1/admin/ai/bandwidth/analyze", None)
                                    .await;
                                if busy.is_disposed() {
                                    return;
                                }
                                match result {
                                    Ok(value) => bandwidth.set(value),
                                    Err(e) => context.toast(tt(context, &e.message), true),
                                }
                                busy.set(false);
                            });
                        }
                    >
                        {move || tt(context, "Analyze bandwidth")}
                    </button>
                </div>
                <p class="text-xs font-mono text-slate-400">
                    {move || {
                        let (samples_n, observed_days) = capacity_series.with(|s| (s.sample_count, s.observed_days));
                        tt_with(
                            context,
                            "30d history · {samples} samples · {days} days observed",
                            &[
                                ("samples", &samples_n.to_string()),
                                ("days", &observed_days.to_string()),
                            ],
                        )
                    }}
                </p>
            </div>
            <Show when=move || history_30d.error.get().is_some()>
                <p role="status" class="text-xs text-amber-300 mb-3">
                    {move || tt(context, "30-day capacity history unavailable.")}
                    <button class="underline ml-3" on:click=move |_| history_30d.refresh()>
                        {move || tt(context, "Retry")}
                    </button>
                </p>
            </Show>
            <div class="grid sm:grid-cols-2 gap-4 mb-5" data-testid="capacity-history-plots">
                {[
                    ("cpu_trend", "CPU trend", "cpu", ChartValueFormat::Percent),
                    ("memory_trend", "Memory trend", "memory", ChartValueFormat::Percent),
                    ("disk_io_trend", "Disk I/O trend", "disk", ChartValueFormat::BytesPerSec),
                    ("network_trend", "Network trend", "network", ChartValueFormat::BytesPerSec),
                ]
                    .into_iter()
                    .map(|(trend_key, label, series_kind, fmt)| {
                        let pts = Signal::derive(move || {
                            capacity_series.with(|s| match series_kind {
                                "memory" => s.memory.clone(),
                                "disk" => s.disk_io.clone(),
                                "network" => s.network.clone(),
                                _ => s.cpu.clone(),
                            })
                        });
                        let raw_trend = Signal::derive(move || {
                            report
                                .data
                                .with(|v| raw_text(v, &[&format!("/{trend_key}")]).unwrap_or_default())
                        });
                        let stroke = Signal::derive(move || trend_palette(&raw_trend.get()).0.to_string());
                        let fill = Signal::derive(move || trend_palette(&raw_trend.get()).1.to_string());
                        let badge_class = move || {
                            format!(
                                "px-2 py-0.5 rounded-md text-xs font-semibold uppercase border {}",
                                trend_palette(&raw_trend.get()).2
                            )
                        };
                        view! {
                            <div class="obs-telemetry-surface p-3.5 border border-white/10 rounded-xl min-w-0">
                                <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
                                    <span class="text-xs font-semibold text-slate-200">
                                        {move || tt(context, label)}
                                    </span>
                                    <span class=badge_class>
                                        {move || {
                                            report.data.with(|v| {
                                                text(
                                                    &crate::tabs::l10n::locale(context),
                                                    v,
                                                    &[&format!("/{trend_key}")],
                                                )
                                            })
                                        }}
                                    </span>
                                </div>
                                <Show
                                    when=move || pts.with(|p| !p.is_empty())
                                    fallback=move || view! {
                                        <p class="text-xs text-slate-400 py-5">
                                            {move || tt(context, "No 30-day history samples recorded for this metric.")}
                                        </p>
                                    }
                                >
                                    <TimeSparkline
                                        points=pts
                                        label=label
                                        primary_label=label
                                        stroke=stroke
                                        fill=fill
                                        value_format=fmt
                                        time_format=ChartTimeFormat::DateTime
                                        height=68.0
                                        show_references=true
                                        show_endpoints=true
                                    />
                                </Show>
                            </div>
                        }
                    })
                    .collect_view()}
            </div>
            <Show
                when=move || report.data.with(|v| v["trend_summary"].as_str().is_some())
                fallback=move || {
                    view! {
                        <p class="text-sm text-slate-400">
                            {move || tt(
                                context,
                                "No capacity report available. Run an analysis to use measured host history.",
                            )}
                        </p>
                    }
                }
            >
                <p class="text-sm text-slate-300">
                    {move || report.data.with(|v| text(&crate::tabs::l10n::locale(context), v, &["/trend_summary"]))}
                </p>
                <div class="flex flex-wrap gap-4 mt-4 text-xs text-indigo-200">
                    {[
                        ("predicted_bottleneck", "Predicted bottleneck"),
                        ("confidence_score", "Confidence score"),
                    ]
                        .into_iter()
                        .map(|(key, label)| {
                            view! {
                                <p>
                                    {move || {
                                        report
                                            .data
                                            .with(|v| {
                                                format!(
                                                    "{}: {}",
                                                    tt(context, label),
                                                    text(&crate::tabs::l10n::locale(context), v, &[&format!("/{key}")]),
                                                )
                                            })
                                    }}
                                </p>
                            }
                        })
                        .collect_view()}
                </div>
                {move || {
                    report
                        .data
                        .with(|v| {
                            let mut items = list(v, &["/warnings"]);
                            items.extend(list(v, &["/recommendations"]));
                            items
                                .into_iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .map(|s| view! { <p class="text-sm text-amber-200 mt-3">{s}</p> })
                                .collect_view()
                        })
                }}
            </Show>
            <Show when=move || report.error.get().is_some()>
                <p role="status" class="text-xs text-amber-300 mt-3">
                    {move || report.error.get().map(|e| tt(context, &e.message))}
                </p>
            </Show>
            <Show when=move || !bandwidth.with(Value::is_null)>
                <div class="mt-5 border-t border-white/10 pt-4">
                    <h3 class="font-medium">{move || tt(context, "Bandwidth recommendation")}</h3>
                    <p class="text-sm text-slate-400 mt-2">
                        {move || bandwidth.with(|v| text(&crate::tabs::l10n::locale(context), v, &["/reasoning"]))}
                    </p>
                    <p class="text-sm text-cyan-200 mt-2">
                        {move || {
                            bandwidth
                                .with(|v| {
                                    tt_with(context, "RX {rx} KiB/s · TX {tx} KiB/s", &[("rx", &(text(&crate::tabs::l10n::locale(context), v, &["/recommended_download_kbps"])).to_string()), ("tx", &(text(&crate::tabs::l10n::locale(context), v, &["/recommended_upload_kbps"])).to_string())])
                                })
                        }}
                    </p>
                    <Show when=move || bandwidth.with(bandwidth_limits).is_none()>
                        <p role="status" class="text-sm text-amber-300 mt-2">
                            {move || tt(context, "Invalid bandwidth recommendation")}
                        </p>
                    </Show>
                    <button
                        class="glass-button px-4 py-2 min-h-11 mt-3"
                        disabled=move || !context.is_admin() || busy.get() || applying.get()
                            || bandwidth.with(bandwidth_limits).is_none()
                        on:click=move |_| {
                            if !context.is_admin() || busy.get_untracked() || applying.get_untracked() {
                                return;
                            }
                            let Some(limits) = bandwidth.with_untracked(bandwidth_limits) else {
                                return;
                            };
                            let epoch = context.session_epoch.get_untracked();
                            applying.set(true);
                            bandwidth_feedback.set(None);
                            spawn_local(async move {
                                let result = ApiClient
                                    .fetch("/api/v1/admin/ai/bandwidth/apply", "POST", Some(&limits))
                                    .await;
                                if applying.is_disposed()
                                    || context.session_epoch.try_get_untracked() != Some(epoch)
                                {
                                    return;
                                }
                                match result {
                                    Ok(response) => {
                                        let ok = response.ok();
                                        let status = response.status();
                                        let body_text = response.text().await.unwrap_or_default();
                                        if applying.is_disposed()
                                            || context.session_epoch.try_get_untracked() != Some(epoch)
                                        {
                                            return;
                                        }
                                        let payload = serde_json::from_str::<Value>(&body_text)
                                            .unwrap_or(Value::Null);
                                        let outcome = summarize_bandwidth_apply_outcome(
                                            context, ok, status, &payload, &body_text, &limits,
                                        );
                                        bandwidth_feedback.set(Some(outcome));
                                    }
                                    Err(failure) => {
                                        let message = tt(context, &failure.message);
                                        bandwidth_feedback.set(Some(BandwidthApplyOutcome {
                                            message,
                                            is_error: true,
                                            is_partial_or_warning: false,
                                        }));
                                    }
                                }
                                applying.set(false);
                            });
                        }
                    >
                        {move || tt(context, if applying.get() { "Applying bandwidth limits…" } else { "Apply bandwidth limits" })}
                    </button>
                    {move || {
                        bandwidth_feedback.get().map(|outcome| {
                            let role = outcome.aria_role();
                            let class = if outcome.is_error || outcome.is_partial_or_warning {
                                "text-sm text-amber-200 bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2 mt-3"
                            } else {
                                "text-sm text-emerald-200 bg-emerald-500/10 border border-emerald-500/30 rounded-lg px-3 py-2 mt-3"
                            };
                            view! {
                                <p role=role class=class>
                                    {outcome.message}
                                </p>
                            }
                        })
                    }}
                </div>
            </Show>
        </ObsCard>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn storage_pool_summary_aggregates_all_and_filters_by_mount() {
        let partitions = vec![
            json!({
                "mount_point": "/",
                "device": "/dev/nvme0n1p2",
                "fs_type": "ext4",
                "used_gb": 120.0,
                "total_gb": 400.0
            }),
            json!({
                "mount_point": "/mnt/media",
                "device": "/dev/md0",
                "fs_type": "xfs",
                "used_bytes": 200.0 * 1_073_741_824.0,
                "total_bytes": 1000.0 * 1_073_741_824.0
            }),
        ];

        let all = summarize_storage_pool(&partitions, "");
        assert_eq!(all.mounts, vec!["/".to_string(), "/mnt/media".to_string()]);
        assert_eq!(all.visible.len(), 2);
        assert!((all.total_gb.unwrap() - 1400.0).abs() < 1e-6);
        assert!((all.used_gb.unwrap() - 320.0).abs() < 1e-6);
        assert!((all.free_gb.unwrap() - 1080.0).abs() < 1e-6);
        assert!((all.usage_pct.unwrap() - (320.0 / 1400.0 * 100.0)).abs() < 1e-4);

        let filtered = summarize_storage_pool(&partitions, "/mnt/media");
        assert_eq!(filtered.visible.len(), 1);
        assert_eq!(filtered.visible[0].mount, "/mnt/media");
        assert!((filtered.total_gb.unwrap() - 1000.0).abs() < 1e-6);
        assert!((filtered.used_gb.unwrap() - 200.0).abs() < 1e-6);
        assert!((filtered.usage_pct.unwrap() - 20.0).abs() < 1e-4);

        let stale = summarize_storage_pool(&partitions, "/mnt/removed");
        assert_eq!(stale.visible.len(), 2);
        assert!((stale.total_gb.unwrap() - 1400.0).abs() < 1e-6);
    }

    #[test]
    fn bandwidth_applied_details_parse_applied_client_and_limits() {
        let req = json!({"download_kbps": 5000, "upload_kbps": 1200});
        assert_eq!(
            parse_bandwidth_applied_details(
                &json!({"applied_client": "qbittorrent", "download_kbps": 5000, "upload_kbps": 1200}),
                &req,
            ),
            (Some("qbittorrent".to_string()), Some(5000), Some(1200))
        );
        assert_eq!(
            parse_bandwidth_applied_details(&json!({"client": "transmission"}), &req),
            (Some("transmission".to_string()), Some(5000), Some(1200))
        );
        assert_eq!(
            parse_bandwidth_applied_details(&json!({}), &json!({})),
            (None, None, None)
        );
    }

    #[test]
    fn bandwidth_apply_outcome_surfaces_partial_failures_warnings_and_recovery_diagnostics() {
        let owner = Owner::new();
        owner.with(|| {
            let context = crate::state::AppContext::new();
            let req = json!({"download_kbps": 5000, "upload_kbps": 1200});

            let partial = summarize_bandwidth_apply_outcome(
                context,
                true,
                200,
                &json!({
                    "applied_client": "qbittorrent",
                    "partial_apply": true,
                    "warning": "setUploadLimit failed; download limit rollback succeeded",
                    "recovery_diagnostic": "Restored prior downloadLimit=409600",
                }),
                "",
                &req,
            );
            assert!(partial.is_error);
            assert!(partial.is_partial_or_warning);
            assert_eq!(partial.aria_role(), "alert");
            assert!(partial
                .message
                .contains("Bandwidth limits partially applied"));
            assert!(partial
                .message
                .contains("setUploadLimit failed; download limit rollback succeeded"));
            assert!(partial
                .message
                .contains("Restored prior downloadLimit=409600"));

            let failed_with_recovery = summarize_bandwidth_apply_outcome(
                context,
                false,
                502,
                &json!({
                    "error": "qBittorrent rejected setUploadLimit",
                    "warning": "Download limit rollback failed",
                    "recovery_error": "Transfer speed cap may remain altered at 5000 KiB/s",
                }),
                "",
                &req,
            );
            assert!(failed_with_recovery.is_error);
            assert!(failed_with_recovery.is_partial_or_warning);
            assert_eq!(failed_with_recovery.aria_role(), "alert");
            assert!(failed_with_recovery
                .message
                .contains("qBittorrent rejected setUploadLimit"));
            assert!(failed_with_recovery
                .message
                .contains("Download limit rollback failed"));
            assert!(failed_with_recovery
                .message
                .contains("Transfer speed cap may remain altered at 5000 KiB/s"));

            let clean = summarize_bandwidth_apply_outcome(
                context,
                true,
                200,
                &json!({
                    "applied_client": "qbittorrent",
                    "download_kbps": 5000,
                    "upload_kbps": 1200,
                }),
                "",
                &req,
            );
            assert!(!clean.is_error);
            assert!(!clean.is_partial_or_warning);
            assert_eq!(clean.aria_role(), "status");
            assert!(clean.message.contains("Bandwidth limits applied"));
            assert!(clean.message.contains("qbittorrent"));
        });
    }
}
