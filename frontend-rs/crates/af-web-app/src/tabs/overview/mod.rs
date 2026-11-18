//! System overview, history controls, and service topology.
mod telemetry;
mod widgets;

use self::telemetry::*;
use self::widgets::{CapacityPredictions, StorageGpuTelemetry, TelemetrySummary};
use super::contracts::{grid_resource, use_api_typed, HardwareEnvelope, TopologyEnvelope};
use crate::state::{app, json_rows, use_api, TabId};
use crate::tabs::l10n::ObsCard;
use crate::tabs::l10n::{tt, tt_with, DataGrid};
use af_web_core::{
    charts::{lttb, Point},
    topology::{is_core_service, is_service_exception},
    ws::ConnectionState,
};
use af_web_ui::{AppTopologyMap, AreaChart, GridColumn, Sparkline};
use leptos::prelude::*;
use serde_json::{json, Value};

fn append_topology_nodes(services: &mut Vec<(String, Value)>, topology: &Value) {
    for node in list(topology, &["/nodes"]) {
        if let Some(id) = telemetry::raw_text(&node, &["/id"]) {
            if !services.iter().any(|(key, _)| *key == id) {
                services.push((id, node));
            }
        }
    }
}

#[component]
pub fn OverviewTab() -> impl IntoView {
    let context = app();
    let window = RwSignal::new("5m".to_string());
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
        format!("/api/v1/auth/system/metrics/history?window={}&limit=2400&downsample=1&target_points=2400", window.get())
    }));
    let live = RwSignal::new(Vec::<Sample>::new());
    Effect::new(move |_| {
        let metrics = context.metrics.get();
        if !metrics.is_object() {
            return;
        }
        if let Some(sample) = Sample::parse(&metrics, true) {
            live.update(|samples| {
                if samples.last().is_some_and(|s| *s == sample) {
                    return;
                }
                samples.push(sample);
                if samples.len() > 2400 {
                    samples.drain(..samples.len() - 2400);
                }
            });
        }
    });
    Effect::new(move |_| {
        context.history_revision.track();
        topology.refresh();
    });
    let samples = Memo::new(move |_| {
        let data = history.data.get();
        let mut samples: Vec<_> = json_rows(&data)
            .iter()
            .filter_map(|v| Sample::parse(v, false))
            .collect();
        samples.extend(live.get());
        samples.sort_by(|a, b| a.at.total_cmp(&b.at));
        // Prefer live samples at duplicate timestamps. Counter resets never become negative traffic.
        samples.reverse();
        samples.dedup_by(|a, b| a.at == b.at);
        samples.reverse();
        for i in 1..samples.len() {
            let elapsed = (samples[i].at - samples[i - 1].at) / 1000.0;
            if elapsed > 0.0 {
                if samples[i].rx.is_none() {
                    samples[i].rx = counter_delta(samples[i - 1].rx_total, samples[i].rx_total)
                        .map(|n| n / elapsed);
                }
                if samples[i].tx.is_none() {
                    samples[i].tx = counter_delta(samples[i - 1].tx_total, samples[i].tx_total)
                        .map(|n| n / elapsed);
                }
            }
        }
        let span = match window.get().as_str() {
            "24h" => 86_400_000.0,
            "1h" => 3_600_000.0,
            _ => 300_000.0,
        };
        if let Some(latest) = samples.last().map(|sample| sample.at) {
            samples.retain(|sample| sample.at >= latest - span);
        }
        samples
    });
    let points = move |key: &str| {
        let mut points: Vec<Point> = samples.with(|samples| {
            samples
                .iter()
                .filter_map(|s| s.metric(key).map(|y| Point { x: s.at, y }))
                .collect()
        });
        if key == "cpu" {
            points.extend(
                context
                    .history
                    .get()
                    .into_iter()
                    .filter(|p| p.x.is_finite() && p.y.is_finite()),
            );
        }
        points.sort_by(|a, b| a.x.total_cmp(&b.x));
        points.dedup_by(|a, b| a.x == b.x);
        let span = match window.get().as_str() {
            "24h" => 86_400_000.0,
            "1h" => 3_600_000.0,
            _ => 300_000.0,
        };
        if let Some(latest) = points.last().map(|p| p.x) {
            points.retain(|p| p.x >= latest - span);
        }
        lttb(&points, 600)
    };
    let chart = Signal::derive(move || points(&series.get()));
    let cpu_line = Signal::derive(move || points("cpu").iter().map(|p| p.y).collect::<Vec<_>>());
    let memory_line =
        Signal::derive(move || points("memory").iter().map(|p| p.y).collect::<Vec<_>>());
    let network_line = Signal::derive(move || points("rx").iter().map(|p| p.y).collect::<Vec<_>>());
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
            let info = json!({"status":v["status"],"version":v["version"],"uptime":v["uptime"],"health":v["health"],"job_status":job_status,"degraded_components":v["degraded_components"]});
            (id,info)
        }).collect::<Vec<_>>()
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
            <div class="af-overview-intro px-1 pb-5 border-b border-white/10 flex flex-wrap justify-between gap-4">
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
            </div>
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
            <details class="obs-telemetry-surface p-5 border-b border-white/10">
                <summary class="cursor-pointer font-semibold min-h-11">
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
                        <button class="underline ml-3" on:click=move |_| hardware.refresh()>
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
                                        tt_with(context, "{model} · {cores} cores / {threads} threads · {mhz} MHz", &[("model", &(text(&crate::tabs::l10n::locale(context), v, &["/cpu/model"])).to_string()), ("cores", &(text(&crate::tabs::l10n::locale(context), v, &["/cpu/cores"])).to_string()), ("threads", &(text(&crate::tabs::l10n::locale(context), v, &["/cpu/threads"])).to_string()), ("mhz", &(text(&crate::tabs::l10n::locale(context),
                                                v,
                                                &["/cpu/frequency_mhz", "/cpu/freq_mhz", "/cpu/mhz"],
                                            )).to_string())])
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
                                        tt_with(context, "{type} · {capacity} GiB · {banks} banks", &[("type", &(tt(context, &(text(&crate::tabs::l10n::locale(context), v, &["/memory/type", "/ram/type"])).to_string())).to_string()), ("capacity", &(text(&crate::tabs::l10n::locale(context), v, &["/memory/total_gb", "/ram/total_gb"])).to_string()), ("banks", &(text(&crate::tabs::l10n::locale(context), v, &["/memory/bank_count", "/memory/banks"])).to_string())])
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
                                                    {move || text(&crate::tabs::l10n::locale(context),
                                                        &item,
                                                        &["/product", "/name", "/model", "/interface"],
                                                    )}
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
            <TelemetrySummary cpu memory cpu_line memory_line network_line samples />
            <ObsCard>
                <div class="flex flex-wrap justify-between items-center gap-4 mb-4">
                    <h2 class="text-lg font-semibold">
                        {move || tt(context, "Overview.liveTelemetry")}
                    </h2>
                    <div
                        role="group"
                        aria-label=move || tt(context, "Telemetry History Window")
                        class="flex gap-1"
                    >
                        {["5m", "1h", "24h"]
                            .into_iter()
                            .map(|key| {
                                view! {
                                    <button
                                        type="button"
                                        class="obs-tab-pill px-3 py-2 min-h-11"
                                        class:obs-tab-pill-active=move || window.get() == key
                                        aria-pressed=move || (window.get() == key).to_string()
                                        data-testid=format!("history-window-{key}")
                                        on:click=move |_| window.set(key.to_string())
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
                    class="flex flex-wrap gap-2 mb-4"
                >
                    {[
                        ("cpu", "CPU %"),
                        ("memory", "Memory %"),
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
                                    class="obs-tab-pill px-3 py-2 min-h-11"
                                    class:obs-tab-pill-active=move || series.get() == key
                                    aria-pressed=move || (series.get() == key).to_string()
                                    on:click=move |_| series.set(key.into())
                                >
                                    {move || tt(context, label)}
                                </button>
                            }
                        })
                        .collect_view()}
                </div>
                <p class="text-xs text-slate-400 mb-2">
                    {move || {
                        if matches!(series.get().as_str(), "cpu" | "memory") {
                            tt(context, "Overview.percentUtilization")
                        } else {
                            tt(context, "Overview.bytesPerSecond")
                        }
                    }}
                </p>
                <AreaChart points=chart label="Historical and live system telemetry" />
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
                        <button class="ml-3 underline" on:click=move |_| history.refresh()>
                            {move || tt(context, "Retry")}
                        </button>
                    </p>
                </Show>
                <Show when=move || !history.loading.get() && chart.with(Vec::is_empty)>
                    <p class="text-xs text-slate-400">
                        {move || tt(context, "No samples for this series in the selected window.")}
                    </p>
                </Show>
            </ObsCard>
            <StorageGpuTelemetry />
            <ObsCard title=Signal::derive(move || tt(context, "Overview.serviceHealth"))>
                <div class="flex flex-wrap gap-4 justify-between mb-5">
                    <div class="flex flex-wrap gap-5 text-sm">
                        {[
                            ("Core Platform", "Overview.corePlatformCount"),
                            ("Running", "Overview.runningCount"),
                            ("Stopped", "Overview.stoppedCount"),
                            ("Exceptions", "Overview.exceptionsCount"),
                        ]
                            .into_iter()
                            .map(|(label, key)| {
                                view! {
                                    <p class="text-slate-400">
                                        {move || tt(context, key)}
                                        <strong class="block text-2xl text-slate-100 mt-1">
                                            {move || {
                                                services
                                                    .with(|rows| {
                                                        rows.iter()
                                                            .filter(|(id, v)| match label {
                                                                "Core Platform" => {
                                                                    is_core_service(id)
                                                                        || id.trim_end_matches(".service") == "aetherflow-runner"
                                                                }
                                                                "Exceptions" => is_service_exception(v),
                                                                "Running" => {
                                                                    matches!(
                                                                        v["status"].as_str(),
                                                                        Some("running" | "active" | "installed")
                                                                    )
                                                                }
                                                                _ => {
                                                                    matches!(
                                                                        v["status"].as_str(),
                                                                        Some("stopped" | "inactive" | "disabled")
                                                                    )
                                                                }
                                                            })
                                                            .count()
                                                    })
                                            }}
                                        </strong>
                                    </p>
                                }
                            })
                            .collect_view()}
                    </div>
                    <button
                        class="glass-button px-4 py-2 min-h-11"
                        on:click=move |_| context.select_tab(TabId::Services)
                    >
                        {move || tt(context, "Inspect Units")}
                    </button>
                </div>
                <AppTopologyMap services=Signal::derive(move || services.get()) />
                <Show when=move || topology.error.get().is_some()>
                    <p class="text-xs text-amber-300 mt-3">
                        {move || tt(
                            context,
                            "Topology discovery unavailable; showing live service inventory.",
                        )}
                    </p>
                </Show>
            </ObsCard>
            <ObsCard title=Signal::derive(move || tt(context, "Overview.dataUsageHistory"))>
                <p class="text-sm text-slate-400 mb-4">
                    {move || tt(
                        context,
                        "Measured counter deltas for the selected telemetry window. Counter resets are excluded.",
                    )}
                </p>
                <div class="grid sm:grid-cols-2 gap-4">
                    {[("rx", "Downloaded"), ("tx", "Uploaded")]
                        .into_iter()
                        .map(|(key, label)| {
                            view! {
                                <div>
                                    <p class="text-sm text-slate-400">
                                        {move || tt(context, label)}
                                    </p>
                                    <p class="text-2xl text-cyan-200 mt-2">
                                        {move || {
                                            samples
                                                .with(|samples| {
                                                    let mut measured = false;
                                                    let total = samples
                                                        .windows(2)
                                                        .filter_map(|pair| {
                                                            let delta = if key == "rx" {
                                                                counter_delta(pair[0].rx_total, pair[1].rx_total)
                                                            } else {
                                                                counter_delta(pair[0].tx_total, pair[1].tx_total)
                                                            };
                                                            if delta.is_some() {
                                                                measured = true;
                                                            }
                                                            delta
                                                        })
                                                        .sum();
                                                    bytes(&crate::tabs::l10n::locale(context), measured.then_some(total))
                                                })
                                        }}
                                    </p>
                                    <Sparkline
                                        values=Signal::derive(move || {
                                            points(key).iter().map(|p| p.y).collect::<Vec<_>>()
                                        })
                                        label=Signal::derive(move || tt_with(context, "{label} throughput", &[("label", &tt(context, label))]))
                                    />
                                </div>
                            }
                        })
                        .collect_view()}
                </div>
            </ObsCard>
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
                <CapacityPredictions />
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
