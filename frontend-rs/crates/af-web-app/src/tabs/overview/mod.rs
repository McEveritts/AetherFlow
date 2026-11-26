//! System overview, history controls, and service topology.
mod telemetry;
mod widgets;

pub(crate) use self::telemetry::Sample;
use self::telemetry::*;
use self::widgets::{CapacityPredictions, DataUsageHistory, StorageGpuTelemetry, TelemetrySummary};
use super::contracts::{grid_resource, use_api_typed, HardwareEnvelope, TopologyEnvelope};
use crate::state::{app, json_rows, use_api, TabId};
use crate::tabs::l10n::ObsCard;
use crate::tabs::l10n::{tt, tt_with, DataGrid};
use af_web_core::{
    charts::{format_duration_span, lttb, ChartValueFormat, Point},
    topology::{is_core_service, is_service_exception},
    ws::ConnectionState,
};
use af_web_ui::{AppTopologyMap, AreaChart, GridColumn};
use leptos::prelude::*;
use serde_json::{json, Value};

fn append_topology_nodes(services: &mut Vec<(String, Value)>, topology: &Value) {
    for node in list(topology, &["/nodes"]) {
        if let Some(id) = telemetry::raw_text(&node, &["/id"]) {
            if let Some((_, info)) = services.iter_mut().find(|(key, _)| *key == id) {
                if let Some(fields) = info.as_object_mut() {
                    for key in ["service_id", "group", "details"] {
                        if let Some(value) = node.get(key) {
                            fields.insert(key.into(), value.clone());
                        }
                    }
                }
            } else {
                services.push((id, node));
            }
        }
    }
}

#[component]
pub fn OverviewTab() -> impl IntoView {
    let context = app();
    let window = RwSignal::new(TelemetryWindow::from_url_or_default());
    let series = RwSignal::new("cpu".to_string());
    let hardware = grid_resource(use_api_typed::<HardwareEnvelope>(Signal::derive(|| {
        "/api/v1/auth/system/hardware".to_string()
    })));
    let hardware_view = Memo::new(move |_| hardware_profile(&hardware.data.get()));
    let topology = grid_resource(use_api_typed::<TopologyEnvelope>(Signal::derive(|| {
        "/api/v1/auth/system/topology".to_string()
    })));
    let history = use_api(Signal::derive(move || {
        context.history_revision.track();
        window.get().history_url()
    }));
    Effect::new(move |_| {
        context.history_revision.track();
        topology.refresh();
    });
    let samples = Memo::new(move |_| {
        let data = history.data.get();
        let persisted: Vec<_> = json_rows(&data)
            .iter()
            .filter_map(|v| Sample::parse(v, false))
            .collect();
        merge_samples(persisted, context.live_samples.get(), window.get())
    });
    let points = move |key: &str| {
        let points: Vec<Point> = samples.with(|samples| {
            samples
                .iter()
                .filter_map(|s| s.metric(key).map(|y| Point { x: s.at, y }))
                .collect()
        });
        lttb(&points, 600)
    };
    let chart_primary = Signal::derive(move || match series.get().as_str() {
        "network" => points("rx"),
        "disk" => points("read"),
        other => points(other),
    });
    let chart_secondary = Signal::derive(move || match series.get().as_str() {
        "network" => points("tx"),
        "disk" => points("write"),
        _ => vec![],
    });
    let cpu_points = Signal::derive(move || points("cpu"));
    let memory_points = Signal::derive(move || points("memory"));
    let rx_points = Signal::derive(move || points("rx"));
    let tx_points = Signal::derive(move || points("tx"));
    let read_points = Signal::derive(move || points("read"));
    let write_points = Signal::derive(move || points("write"));
    let chart_format = Signal::derive(move || {
        if matches!(series.get().as_str(), "cpu" | "memory") {
            ChartValueFormat::Percent
        } else {
            ChartValueFormat::BytesPerSec
        }
    });
    let chart_time_format = Signal::derive(move || window.get().time_format());
    let chart_gap = Signal::derive(|| Some(GAP_THRESHOLD_MS));
    let chart_primary_label = Signal::derive(move || match series.get().as_str() {
        "memory" => "Memory %".to_string(),
        "network" | "rx" => "Network RX".to_string(),
        "tx" => "Network TX".to_string(),
        "disk" | "read" => "Disk Read".to_string(),
        "write" => "Disk Write".to_string(),
        _ => "CPU %".to_string(),
    });
    let chart_secondary_label = Signal::derive(move || match series.get().as_str() {
        "network" => "Network TX".to_string(),
        "disk" => "Disk Write".to_string(),
        _ => String::new(),
    });
    let chart_primary_stroke = Signal::derive(move || match series.get().as_str() {
        "memory" => "#22d3ee".to_string(),
        "network" | "rx" => "#06b6d4".to_string(),
        "tx" => "#6366f1".to_string(),
        "disk" | "read" => "#f59e0b".to_string(),
        "write" => "#38bdf8".to_string(),
        _ => "var(--af-chart-stroke)".to_string(),
    });
    let chart_primary_fill = Signal::derive(move || match series.get().as_str() {
        "memory" => "rgba(34, 211, 238, 0.16)".to_string(),
        "network" | "rx" => "rgba(6, 182, 212, 0.16)".to_string(),
        "tx" => "rgba(99, 102, 241, 0.16)".to_string(),
        "disk" | "read" => "rgba(245, 158, 11, 0.16)".to_string(),
        "write" => "rgba(56, 189, 248, 0.16)".to_string(),
        _ => "var(--af-chart-area-fill)".to_string(),
    });
    let chart_secondary_stroke = Signal::derive(move || match series.get().as_str() {
        "disk" => "#38bdf8".to_string(),
        _ => "#6366f1".to_string(),
    });
    let chart_secondary_fill = Signal::derive(move || match series.get().as_str() {
        "disk" => "rgba(56, 189, 248, 0.14)".to_string(),
        _ => "rgba(99, 102, 241, 0.14)".to_string(),
    });
    let chart_coverage =
        Memo::new(move |_| chart_primary.with(|p| summarize_coverage(p, window.get())));
    let cpu = Signal::derive(move || context.metrics.with(metrics_cpu));
    let memory = Signal::derive(move || context.metrics.with(metrics_memory));
    let services = Memo::new(move |_| {
        let live = context.services.get();
        let source = if live.is_null() {
            context.metrics.get()["services"].clone()
        } else {
            live
        };
        let mut services: Vec<(String, Value)> = if let Some(object) = source.as_object() {
            object
                .iter()
                .map(|(id, v)| (id.clone(), v.clone()))
                .collect()
        } else {
            json_rows(&source)
                .into_iter()
                .map(|v| {
                    (
                        text(&crate::tabs::l10n::locale(context), &v, &["/id", "/name"]),
                        v,
                    )
                })
                .collect()
        };
        append_topology_nodes(&mut services, &topology.data.get());
        // The topology inspector prints its input: pass only public operational fields.
        services.into_iter().map(|(id,v)| {
            let job_status = if is_service_exception(&v) { json!("failed") } else { v["job_status"].clone() };
            let info = json!({"service_id":v["service_id"],"details":v["details"],"status":v["status"],"version":v["version"],"uptime":v["uptime"],"health":v["health"],"job_status":job_status,"degraded_components":v["degraded_components"]});
            (id,info)
        }).collect::<Vec<_>>()
    });
    let service_exceptions = Memo::new(move |_| {
        services.with(|rows| {
            rows.iter()
                .filter(|(_, v)| is_service_exception(v))
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
        })
    });
    let processes = Signal::derive(move || {
        let mut rows = context.metrics.with(|v| {
            list(v, &["/processes"])
                .into_iter()
                .map(process_row)
                .collect::<Vec<_>>()
        });
        rows.sort_by(|a, b| {
            number(b, &["/cpu"])
                .unwrap_or_default()
                .total_cmp(&number(a, &["/cpu"]).unwrap_or_default())
        });
        rows
    });
    view! {
        <section class="py-5 space-y-6 min-w-0 max-w-full">
            <div class="af-canvas-section af-overview-intro px-1 pb-5 flex flex-wrap justify-between items-start gap-4">
                <div class="min-w-0">
                    <p class="text-xs uppercase tracking-[.2em] text-indigo-300">
                        {move || tt(context, "AetherNexus / System pulse")}
                    </p>
                    <h2 class="text-2xl font-semibold mt-2">
                        {move || tt(context, "Tabs.overviewHeading")}
                    </h2>
                    <p class="text-sm text-slate-400 mt-2 break-words">
                        {move || hardware_view.with(|v| text(&crate::tabs::l10n::locale(context), v, &["/cpu/model"]))}
                    </p>
                </div>
                <button
                    type="button"
                    class="af-btn px-4 py-2 min-h-11 text-sm shrink-0"
                    data-testid="overview-configure-button"
                    on:click=move |_| context.navigate_to_subtab(TabId::Settings, "general")
                >
                    {move || tt(context, "Configure")}
                </button>
            </div>
            <Show when=move || !service_exceptions.with(Vec::is_empty)>
                <div
                    role="alert"
                    class="af-danger-banner flex flex-wrap items-center justify-between gap-4"
                    data-testid="overview-service-exception-banner"
                >
                    <div class="min-w-0 space-y-1">
                        <p class="font-semibold text-sm">
                            {move || {
                                let count = service_exceptions.with(Vec::len);
                                tt_with(
                                    context,
                                    "{count} services require attention",
                                    &[("count", &count.to_string())],
                                )
                            }}
                        </p>
                        <p class="text-xs opacity-90 break-words font-mono">
                            {move || {
                                service_exceptions.with(|items| {
                                    let head = items
                                        .iter()
                                        .take(5)
                                        .cloned()
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    if items.len() > 5 {
                                        format!("{head} (+{})", items.len() - 5)
                                    } else {
                                        head
                                    }
                                })
                            }}
                        </p>
                    </div>
                    <button
                        type="button"
                        class="af-btn px-4 py-2 min-h-11 text-xs shrink-0"
                        data-testid="overview-triage-services-button"
                        on:click=move |_| context.navigate_to_subtab(TabId::Services, "attention")
                    >
                        {move || tt(context, "Triage in Services")}
                    </button>
                </div>
            </Show>
            <Show when=move || !context.metrics.with(Value::is_object)>
                <div role="status" class="p-5 border border-amber-400/20 bg-amber-400/5 rounded-xl">
                    <h3 class="font-semibold text-amber-200">
                        {move || tt(
                            context,
                            match context.connection.get() {
                                ConnectionState::Offline => "Telemetry offline",
                                ConnectionState::Fallback => "Degraded telemetry",
                                ConnectionState::Reconnecting => "Reconnecting telemetry",
                                _ => "Connecting telemetry",
                            },
                        )}
                    </h3>
                    <p class="text-sm text-slate-400 mt-2">
                        {move || tt(
                            context,
                            "Waiting for a measured system snapshot. History and service health remain available.",
                        )}
                    </p>
                </div>
            </Show>
            <details class="af-canvas-section p-5">
                <summary class="cursor-pointer font-semibold min-h-11 py-2.5 px-2 rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--af-focus-ring)]">
                    {move || tt(context, "Overview.hardwareProfile")}
                </summary>
                <Show when=move || hardware.loading.get()>
                    <p role="status" class="text-slate-400 py-3">
                        {move || tt(context, "Reading hardware…")}
                    </p>
                </Show>
                <Show when=move || hardware.error.get().is_some()>
                    <p role="alert" class="text-amber-300">
                        {move || tt(context, "Hardware report unavailable.")}
                        <button
                            type="button"
                            class="underline ml-3 min-h-9 py-1.5 px-2 rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--af-focus-ring)]"
                            on:click=move |_| hardware.refresh()
                        >
                            {move || tt(context, "Retry")}
                        </button>
                    </p>
                </Show>
                <dl class="grid sm:grid-cols-2 xl:grid-cols-4 gap-5 text-sm mt-4">
                    <div>
                        <dt class="text-slate-400">{move || tt(context, "Processor")}</dt>
                        <dd class="mt-2 break-words">
                            {move || {
                                hardware_view
                                    .with(|v| {
                                        let locale = crate::tabs::l10n::locale(context);
                                        let mhz = context.metrics.with(|m| number(m, &["/cpu_freq_mhz"]))
                                            .filter(|mhz| *mhz > 0.0)
                                            .or_else(|| number(v, &["/cpu/frequency_mhz", "/cpu/freq_mhz", "/cpu/mhz"]))
                                            .map(|mhz| format!("{mhz:.0}")).unwrap_or_else(|| tt(context, "Unavailable"));
                                        tt_with(context, "{model} · {cores} cores / {threads} threads · {mhz} MHz", &[
                                            ("model", &text(&locale, v, &["/cpu/model"])),
                                            ("cores", &text(&locale, v, &["/cpu/cores"])),
                                            ("threads", &text(&locale, v, &["/cpu/threads"])), ("mhz", &mhz)])
                                    })
                            }}
                        </dd>
                    </div>
                    <div>
                        <dt class="text-slate-400">{move || tt(context, "Memory banks")}</dt>
                        <dd class="mt-2">
                            {move || {
                                hardware_view
                                    .with(|v| {
                                        tt_with(context, "{type} · {capacity} GiB · {banks} banks", &[("type", &(tt(context, &(text(&crate::tabs::l10n::locale(context), v, &["/memory/type", "/ram/type"])).to_string())).to_string()), ("capacity", &(text(&crate::tabs::l10n::locale(context), v, &["/memory/total_gb", "/ram/total_gb"])).to_string()), ("banks", &(text(&crate::tabs::l10n::locale(context), v, &["/memory/bank_count"])).to_string())])
                                    })
                            }}
                        </dd>
                        {move || {
                            hardware_view
                                .with(|v| {
                                    list(v, &["/memory/banks", "/ram/banks", "/memory_banks"])
                                        .into_iter()
                                        .map(|bank| {
                                            view! {
                                                <dd class="text-xs text-slate-400 mt-1">
                                                    {move || format!(
                                                        "{} · {} · {} GB",
                                                        text(&crate::tabs::l10n::locale(context), &bank, &["/locator", "/slot"]),
                                                        text(&crate::tabs::l10n::locale(context), &bank, &["/type"]),
                                                        text(&crate::tabs::l10n::locale(context), &bank, &["/size_gb", "/capacity_gb"]),
                                                    )}
                                                </dd>
                                            }
                                        })
                                        .collect_view()
                                })
                        }}
                    </div>
                    <div>
                        <dt class="text-slate-400">{move || tt(context, "Accelerators & NICs")}</dt>
                        {move || {
                            hardware_view
                                .with(|v| {
                                    let mut items = list(v, &["/gpus"]);
                                    items
                                        .extend(
                                            list(
                                                v,
                                                &[
                                                    "/network_interfaces",
                                                    "/network/interfaces",
                                                    "/nics",
                                                    "/network",
                                                ],
                                            ),
                                        );
                                    items
                                        .into_iter()
                                        .map(|item| {
                                            view! {
                                                <dd class="mt-2 break-words">
                                                    {move || {
                                                        let name = raw_text(&item, &["/name", "/interface"]);
                                                        let model = raw_text(&item, &["/product", "/model"]).filter(|label| label != "Unknown");
                                                        match (name, model) {
                                                            (Some(name), Some(model)) if name != model => format!("{name} · {model}"),
                                                            (Some(name), _) => name,
                                                            (_, Some(model)) => model,
                                                            _ => tt(context, "Unavailable"),
                                                        }
                                                    }}
                                                </dd>
                                            }
                                        })
                                        .collect_view()
                                })
                        }}
                    </div>
                    <div>
                        <dt class="text-slate-400">
                            {move || tt(context, "Physical drives / uptime")}
                        </dt>
                        <dd class="mt-2">
                            {move || context.metrics.with(|v| text(&crate::tabs::l10n::locale(context), v, &["/uptime"]))}
                        </dd>
                        {move || {
                            hardware_view
                                .with(|v| {
                                    list(v, &["/storage", "/disks", "/storage/drives", "/drives"])
                                        .into_iter()
                                        .map(|drive| {
                                            view! {
                                                <dd class="text-xs text-slate-400 mt-2 break-words">
                                                    {move || format!(
                                                        "{} · {}",
                                                        text(&crate::tabs::l10n::locale(context), &drive, &["/model", "/name", "/device"]),
                                                        number(&drive, &["/size_bytes"])
                                                            .map(|n| bytes(&crate::tabs::l10n::locale(context), Some(n)))
                                                            .unwrap_or_else(|| text(&crate::tabs::l10n::locale(context),
                                                                &drive,
                                                                &["/size", "/size_gb", "/capacity_gb"],
                                                            )),
                                                    )}
                                                </dd>
                                            }
                                        })
                                        .collect_view()
                                })
                        }}
                    </div>
                </dl>
            </details>
            <TelemetrySummary
                cpu
                memory
                cpu_points
                memory_points
                rx_points
                tx_points
                read_points
                write_points
                samples
                window
            />
            <ObsCard>
                <div class="flex flex-wrap justify-between items-center gap-4 mb-4">
                    <h2 class="text-lg font-semibold">
                        {move || tt(context, "Overview.liveTelemetry")}
                    </h2>
                    <div
                        role="group"
                        aria-label=move || tt(context, "Telemetry History Window")
                        class="af-surface-inset p-1 flex flex-wrap gap-1"
                    >
                        {TelemetryWindow::ALL
                            .into_iter()
                            .map(|option| {
                                let key = option.key();
                                view! {
                                    <button
                                        type="button"
                                        class="af-tab-pill px-3 py-2 min-h-11"
                                        class:af-tab-pill-active=move || window.get() == option
                                        aria-pressed=move || (window.get() == option).to_string()
                                        data-testid=format!("history-window-{key}")
                                        on:click=move |_| window.set(option)
                                    >
                                        {move || tt(context, key)}
                                    </button>
                                }
                            })
                            .collect_view()}
                    </div>
                </div>
                <div
                    role="group"
                    aria-label=move || tt(context, "Telemetry metric series")
                    class="af-surface-inset p-1 flex flex-wrap gap-1.5 mb-4"
                >
                    {[
                        ("cpu", "CPU %"),
                        ("memory", "Memory %"),
                        ("network", "Network RX / TX"),
                        ("disk", "Disk Read / Write"),
                        ("rx", "Network RX"),
                        ("tx", "Network TX"),
                        ("read", "Disk Read"),
                        ("write", "Disk Write"),
                    ]
                        .into_iter()
                        .map(|(key, label)| {
                            view! {
                                <button
                                    type="button"
                                    class="af-tab-pill px-3 py-2 min-h-11"
                                    class:af-tab-pill-active=move || series.get() == key
                                    aria-pressed=move || (series.get() == key).to_string()
                                    data-testid=format!("telemetry-series-{key}")
                                    on:click=move |_| series.set(key.into())
                                >
                                    {move || tt(context, label)}
                                </button>
                            }
                        })
                        .collect_view()}
                </div>
                <div class="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400 mb-2">
                    <div class="flex flex-wrap items-center gap-3">
                        <span>
                            {move || {
                                if matches!(series.get().as_str(), "cpu" | "memory") {
                                    tt(context, "Overview.percentUtilization")
                                } else {
                                    tt(context, "Overview.bytesPerSecond")
                                }
                            }}
                        </span>
                        <Show when=move || !chart_secondary_label.get().is_empty()>
                            <span class="inline-flex items-center gap-1.5 text-slate-200 font-medium">
                                <span class=move || {
                                    if series.get() == "disk" {
                                        "inline-block w-2 h-2 rounded-full bg-amber-400"
                                    } else {
                                        "inline-block w-2 h-2 rounded-full bg-cyan-400"
                                    }
                                }></span>
                                {move || tt(context, &chart_primary_label.get())}
                            </span>
                            <span class="inline-flex items-center gap-1.5 text-slate-200 font-medium">
                                <span class=move || {
                                    if series.get() == "disk" {
                                        "inline-block w-2 h-2 rounded-full bg-sky-400"
                                    } else {
                                        "inline-block w-2 h-2 rounded-full bg-indigo-400"
                                    }
                                }></span>
                                {move || tt(context, &chart_secondary_label.get())}
                            </span>
                        </Show>
                    </div>
                    <p class="font-mono tabular-nums" data-testid="telemetry-coverage-summary">
                        {move || {
                            let cov = chart_coverage.get();
                            let locale = crate::tabs::l10n::locale(context);
                            let win_label = tt(context, window.get().key());
                            if cov.sample_count == 0 {
                                tt_with(
                                    context,
                                    "0 samples ({window} window)",
                                    &[("window", &win_label)],
                                )
                            } else if cov.is_sparse() {
                                tt_with(
                                    context,
                                    "Collecting · {count} samples · {window}",
                                    &[
                                        ("count", &cov.sample_count.to_string()),
                                        ("window", &win_label),
                                    ],
                                )
                            } else {
                                let span_str = format_duration_span(
                                    (cov.observed_span_ms / 1000.0).round() as u64,
                                    &locale,
                                );
                                let base = tt_with(
                                    context,
                                    "{count} samples · {span} observed of {window}",
                                    &[
                                        ("count", &cov.sample_count.to_string()),
                                        ("span", &span_str),
                                        ("window", &win_label),
                                    ],
                                );
                                if cov.gap_count > 0 {
                                    format!(
                                        "{base} · {}",
                                        tt_with(
                                            context,
                                            "{count} gaps",
                                            &[("count", &cov.gap_count.to_string())],
                                        )
                                    )
                                } else {
                                    base
                                }
                            }
                        }}
                    </p>
                </div>
                <AreaChart
                    points=chart_primary
                    secondary=chart_secondary
                    label="Historical and live system telemetry"
                    primary_label=chart_primary_label
                    secondary_label=chart_secondary_label
                    stroke=chart_primary_stroke
                    fill=chart_primary_fill
                    secondary_stroke=chart_secondary_stroke
                    secondary_fill=chart_secondary_fill
                    value_format=chart_format
                    time_format=chart_time_format
                    gap_threshold_x=chart_gap
                />
                <Show when=move || history.loading.get()>
                    <p role="status" class="text-xs text-slate-400">
                        {move || tt(context, "Loading selected history window…")}
                    </p>
                </Show>
                <Show when=move || history.error.get().is_some()>
                    <p role="status" class="text-sm text-amber-300">
                        {move || tt(
                            context,
                            "History unavailable. Showing measured live telemetry.",
                        )}
                        <button
                            type="button"
                            class="ml-3 underline min-h-9 py-1.5 px-2 rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--af-focus-ring)]"
                            on:click=move |_| history.refresh()
                        >
                            {move || tt(context, "Retry")}
                        </button>
                    </p>
                </Show>
                <Show when=move || !history.loading.get() && chart_primary.with(Vec::is_empty) && chart_secondary.with(Vec::is_empty)>
                    <p class="text-xs text-slate-400">
                        {move || tt(context, "No samples for this series in the selected window.")}
                    </p>
                </Show>
            </ObsCard>
            <StorageGpuTelemetry />
            {
                let topology_mode = RwSignal::new("graph".to_string());
                view! {
                    <ObsCard>
                        <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
                            <div class="flex flex-wrap items-center gap-3">
                                <h2 class="text-lg font-semibold tracking-tight">
                                    {move || tt(context, "Overview.serviceHealth")}
                                </h2>
                                <af_web_ui::TopologyModeSwitcher active=topology_mode />
                            </div>
                            <div class="flex flex-wrap items-center gap-2">
                                <div class="flex flex-wrap items-center gap-1.5">
                                    {[
                                        (
                                            "Core Platform",
                                            "Overview.corePlatformCount",
                                            "af-topo-stat-dot af-topo-stat-dot-core",
                                        ),
                                        (
                                            "Running",
                                            "Overview.runningCount",
                                            "af-topo-stat-dot af-topo-stat-dot-active",
                                        ),
                                        (
                                            "Stopped",
                                            "Overview.stoppedCount",
                                            "af-topo-stat-dot af-topo-stat-dot-stopped",
                                        ),
                                        (
                                            "Exceptions",
                                            "Overview.exceptionsCount",
                                            "af-topo-stat-dot af-topo-stat-dot-exception",
                                        ),
                                    ]
                                        .into_iter()
                                        .map(|(label, key, dot_class)| {
                                            view! {
                                                <span class="af-topo-stat">
                                                    <span aria-hidden="true" class=dot_class></span>
                                                    <span>{move || tt(context, key)}</span>
                                                    <strong>
                                                        {move || {
                                                            services
                                                                .with(|rows| {
                                                                    rows.iter()
                                                                        .filter(|(id, v)| match label {
                                                                            "Core Platform" => {
                                                                                is_core_service(id)
                                                                                    || id.trim_end_matches(".service")
                                                                                        == "aetherflow-runner"
                                                                            }
                                                                            "Exceptions" => is_service_exception(v),
                                                                            "Running" => {
                                                                                matches!(
                                                                                    v["status"].as_str(),
                                                                                    Some("running" | "active")
                                                                                )
                                                                            }
                                                                            _ => {
                                                                                matches!(
                                                                                    v["status"].as_str(),
                                                                                    Some(
                                                                                        "stopped"
                                                                                            | "inactive"
                                                                                            | "disabled"
                                                                                    )
                                                                                )
                                                                            }
                                                                        })
                                                                        .count()
                                                                })
                                                        }}
                                                    </strong>
                                                </span>
                                            }
                                        })
                                        .collect_view()}
                                </div>
                                <button
                                    type="button"
                                    class="af-btn px-3.5 py-1.5 text-sm min-h-9"
                                    on:click=move |_| context.select_tab(TabId::Services)
                                >
                                    {move || tt(context, "Inspect Units")}
                                </button>
                            </div>
                        </div>
                        <AppTopologyMap
                            services=Signal::derive(move || services.get())
                            links=Signal::derive(move || topology.data.with(|v| {
                                list(v, &["/edges", "/links"]).iter().filter_map(|edge| Some((raw_text(edge, &["/source", "/from"])?, raw_text(edge, &["/target", "/to"])?))).collect::<Vec<_>>()
                            }))
                            mode=topology_mode
                        />
                        <Show when=move || topology.error.get().is_some()>
                            <p class="text-xs text-amber-300 mt-3">
                                {move || tt(
                                    context,
                                    "Topology discovery unavailable; showing live service inventory.",
                                )}
                            </p>
                        </Show>
                    </ObsCard>
                }
            }
            <Show when=move || context.show_transfer_history.get()>
                <DataUsageHistory />
            </Show>
            <ObsCard title=Signal::derive(move || tt(context, "Overview.topProcesses"))>
                <DataGrid
                    label="System processes"
                    rows=processes
                    columns=vec![
                        GridColumn::numeric("pid", "PID"),
                        GridColumn::new("name", "Process"),
                        GridColumn::numeric("cpu", "CPU %"),
                        GridColumn::numeric("mem", "Memory %"),
                    ]
                />
            </ObsCard>
            <Show when=move || context.is_admin()>
                <crate::tabs::GrantInvalidationBoundary areas=&[crate::state::PeerArea::Settings]>
                    <CapacityPredictions />
                </crate::tabs::GrantInvalidationBoundary>
            </Show>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_topology_ids_do_not_create_localized_phantom_nodes() {
        for locale in ["fr", "zh"] {
            let topology = json!({"nodes":[
                {"name":"missing id"}, {"id":"  "}, {"id":" valid-service "}
            ]});
            assert_ne!(text(locale, &topology["nodes"][0], &["/id"]), "Unavailable");
            let mut services = vec![];
            append_topology_nodes(&mut services, &topology);
            assert_eq!(services.len(), 1, "{locale}");
            assert_eq!(services[0].0, "valid-service");
        }
    }
}
