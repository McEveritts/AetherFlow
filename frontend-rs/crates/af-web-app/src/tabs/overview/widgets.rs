//! Reusable telemetry surfaces and administrator capacity analysis.
use super::telemetry::*;
use crate::state::{app, use_api};
use crate::tabs::l10n::{tt, tt_with, EmptyState, ObsCard};
use af_web_core::{
    api::ApiClient,
    models::{DiskPartition, GpuMetric},
};
use af_web_ui::Sparkline;
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
#[component]
pub(super) fn TelemetrySummary(
    cpu: Signal<Option<f64>>,
    memory: Signal<Option<f64>>,
    cpu_line: Signal<Vec<f64>>,
    memory_line: Signal<Vec<f64>>,
    network_line: Signal<Vec<f64>>,
    samples: Memo<Vec<Sample>>,
) -> impl IntoView {
    let context = app();
    view! {
            <div class="grid md:grid-cols-2 xl:grid-cols-3 gap-5">
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
                    <div class="text-indigo-400 my-4">
                        <Sparkline values=cpu_line label="CPU utilization history" />
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
                    <div class="text-cyan-400 my-4">
                        <Sparkline values=memory_line label="Memory usage history" />
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
                        {[("rx", "Receive"), ("tx", "Transmit")]
                            .into_iter()
                            .map(|(key, label)| {
                                view! {
                                    <div>
                                        <p class="text-xs text-slate-400">
                                            {move || tt(context, label)}
                                        </p>
                                        <p class="text-xl text-emerald-200 tabular-nums mt-2">
                                            {move || rate(&crate::tabs::l10n::locale(context),
                                                samples.with(|s| s.last().and_then(|s| s.metric(key))),
                                            )}
                                        </p>
                                    </div>
                                }
                            })
                            .collect_view()}
                    </div>
                    <div class="text-emerald-400 my-4">
                        <Sparkline values=network_line label="Receive throughput history" />
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
            </div>
    }
}

#[component]
pub(super) fn StorageGpuTelemetry() -> impl IntoView {
    let context = app();
    view! {
            <div class="grid lg:grid-cols-2 gap-5">
                <ObsCard title=Signal::derive(move || tt(
                    context,
                    "Overview.storagePartitions",
                ))>
                    {move || {
                        context
                            .metrics
                            .with(|v| {
                                list(v, &["/disk_partitions", "/disks", "/disk_space"])
                                    .into_iter()
                                    .map(telemetry_row::<DiskPartition>)
                                    .map(|disk| {
                                        let total = number(&disk, &["/total_gb"])
                                            .or_else(|| {
                                                number(&disk, &["/total", "/total_bytes"])
                                                    .map(|n| n / 1_073_741_824.0)
                                            });
                                        let used = number(&disk, &["/used_gb"])
                                            .or_else(|| {
                                                number(&disk, &["/used", "/used_bytes"])
                                                    .map(|n| n / 1_073_741_824.0)
                                            });
                                        let usage = number(&disk, &["/used_pct", "/usage_pct"])
                                            .or_else(|| ratio(used, total));
                                        let disk_heading = disk.clone();
                                        view! {
                                            <article class="py-4 border-b border-white/5">
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
                                                    {move || tt(
                                                        context,
                                                        &(match (used, total) {
                                                            (Some(used), Some(total)) => {
                                                                tt_with(context, "{used} / {total} GB · {free} GB free", &[("used", &format!("{:.1}", used)), ("total", &format!("{:.1}", total)), ("free", &format!("{:.1}", (total - used).max(0.0)))])
                                                            }
                                                            _ => "Capacity counters unavailable".into(),
                                                        }),
                                                    )}
                                                </p>
                                            </article>
                                        }
                                    })
                                    .collect_view()
                            })
                    }}
                    <Show when=move || {
                        context
                            .metrics
                            .with(|v| {
                                list(v, &["/disk_partitions", "/disks", "/disk_space"]).is_empty()
                            })
                    }>
                        <EmptyState
                            title="No partition telemetry"
                            description="Mounted volumes appear when reported by the host."
                        />
                    </Show>
                </ObsCard>
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

#[component]
pub(super) fn CapacityPredictions() -> impl IntoView {
    let context = app();
    let report = use_api("/api/v1/admin/ai/predictions".to_string());
    let busy = RwSignal::new(false);
    let applying = RwSignal::new(false);
    let bandwidth = RwSignal::new(Value::Null);
    view! {
        <ObsCard title=Signal::derive(move || tt(context, "Overview.capacityPredictions"))>
            <div class="flex flex-wrap gap-3 mb-5">
                <button
                    class="glass-button px-4 py-2 min-h-11"
                    disabled=move || busy.get() || applying.get()
                    on:click=move |_| {
                        if !context.is_admin() || busy.get_untracked() || applying.get_untracked() {
                            return;
                        }
                        busy.set(true);
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
                        ("cpu_trend", "CPU trend"),
                        ("memory_trend", "Memory trend"),
                        ("disk_io_trend", "Disk I/O trend"),
                        ("network_trend", "Network trend"),
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
                            spawn_local(async move {
                                let result = ApiClient.post("/api/v1/admin/ai/bandwidth/apply", Some(&limits)).await;
                                if applying.is_disposed() || context.session_epoch.try_get_untracked() != Some(epoch) {
                                    return;
                                }
                                match result {
                                    Ok(_) => context.toast(tt(context, "Bandwidth limits applied"), false),
                                    Err(failure) => context.toast(tt(context, &failure.message), true),
                                }
                                applying.set(false);
                            });
                        }
                    >
                        {move || tt(context, if applying.get() { "Applying bandwidth limits…" } else { "Apply bandwidth limits" })}
                    </button>
                </div>
            </Show>
        </ObsCard>
    }
}
