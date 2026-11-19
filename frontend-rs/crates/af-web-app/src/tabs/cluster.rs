use super::contracts::{grid_resource, use_api_typed, ClusterNode, Records};
use super::settings::{encode, poll_resource, text, ResourceFeedback};
use crate::state::{app, use_api};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{ConfirmDialog, DataGrid, Drawer, EmptyState, Modal, ObsCard};
use af_web_core::api::ApiClient;
use af_web_ui::GridColumn;
use futures::{
    channel::oneshot,
    future::{AbortHandle, AbortRegistration, Abortable},
    stream, StreamExt,
};
use leptos::prelude::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use wasm_bindgen_futures::{spawn_local, JsFuture};

type MetricsTopologyKey = Vec<[String; 7]>;

fn metrics_topology_key(nodes: &[Value]) -> MetricsTopologyKey {
    let mut key = nodes
        .iter()
        .filter(|node| !text(node, "id").is_empty())
        .map(|node| {
            [
                "id",
                "hostname",
                "address",
                "role",
                "status",
                "version",
                "enrolled_at",
            ]
            .map(|field| text(node, field))
        })
        .collect::<Vec<_>>();
    key.sort_unstable();
    key
}

fn metrics_topology_snapshot(
    previous: Option<&Arc<MetricsTopologyKey>>,
    nodes: &[Value],
) -> Arc<MetricsTopologyKey> {
    let key = metrics_topology_key(nodes);
    if let Some(previous) = previous {
        if previous.as_ref() == &key {
            return previous.clone();
        }
    }
    Arc::new(key)
}

#[derive(Clone)]
struct MetricsScope {
    topology: Arc<MetricsTopologyKey>,
    session_epoch: u64,
    auth_epoch: u64,
}

impl PartialEq for MetricsScope {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.topology, &other.topology)
            && self.session_epoch == other.session_epoch
            && self.auth_epoch == other.auth_epoch
    }
}
impl Eq for MetricsScope {}

struct MetricsBatch {
    abort: AbortHandle,
    finished: oneshot::Receiver<()>,
    running: Arc<AtomicBool>,
}

#[derive(Default)]
struct MetricsBatches(Option<MetricsBatch>);

impl MetricsBatches {
    fn running(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(|batch| batch.running.load(Ordering::SeqCst))
    }

    fn cancel(&self) {
        if let Some(batch) = &self.0 {
            batch.abort.abort();
        }
    }

    fn next(
        &mut self,
    ) -> (
        Option<oneshot::Receiver<()>>,
        AbortRegistration,
        oneshot::Sender<()>,
        Arc<AtomicBool>,
    ) {
        let previous = self.0.take().map(|batch| {
            batch.abort.abort();
            batch.finished
        });
        let (abort, registration) = AbortHandle::new_pair();
        let (finished, receiver) = oneshot::channel();
        let running = Arc::new(AtomicBool::new(true));
        self.0 = Some(MetricsBatch {
            abort,
            finished: receiver,
            running: running.clone(),
        });
        (previous, registration, finished, running)
    }
}

async fn run_metrics_batch<F: Future>(
    previous: Option<oneshot::Receiver<()>>,
    registration: AbortRegistration,
    finished: oneshot::Sender<()>,
    running: Arc<AtomicBool>,
    work: F,
) -> Option<F::Output> {
    // Even an already-cancelled generation must wait for its predecessor:
    // a later generation uses this completion as its own transport barrier.
    if let Some(previous) = previous {
        let _ = previous.await;
    }
    let result = Abortable::new(work, registration).await.ok();
    // Dropping the aborted future first drops ApiClient's request guards,
    // which abort their fetches. Only then may the next batch start.
    running.store(false, Ordering::SeqCst);
    drop(finished);
    result
}

#[derive(Clone)]
struct MetricsBatchGuard {
    context: crate::state::AppContext,
    generation: RwSignal<u64>,
    ticket: u64,
    topology: Memo<Arc<MetricsTopologyKey>>,
    scope: Arc<MetricsScope>,
}

impl MetricsBatchGuard {
    fn current(&self) -> bool {
        self.generation.try_get_untracked() == Some(self.ticket)
            && self
                .topology
                .try_with_untracked(|topology| Arc::ptr_eq(topology, &self.scope.topology))
                == Some(true)
            && self.context.session_epoch.try_get_untracked() == Some(self.scope.session_epoch)
            && self.context.auth_loading.try_get_untracked() == Some(false)
            && af_web_core::api::current_auth_epoch() == self.scope.auth_epoch
            && !af_web_core::api::auth_revalidation_pending()
            && self.context.is_admin()
    }
}

fn metric(locale: &str, value: &Value, key: &str, suffix: &str) -> String {
    super::contracts::decode::<super::contracts::ClusterNode>(value)
        .metrics
        .get(key)
        .copied()
        .flatten()
        .filter(|v| v.is_finite())
        .map(|number| format!("{number:.1}{suffix}"))
        .unwrap_or_else(|| af_web_core::i18n::translate(locale, "Not reported"))
}
fn aggregate_metric(locale: &str, rows: &[Value], key: &str, average: bool) -> String {
    let values = rows
        .iter()
        .filter_map(|node| {
            super::contracts::decode::<super::contracts::ClusterNode>(node)
                .metrics
                .get(key)
                .copied()
                .flatten()
        })
        .filter(|number| number.is_finite())
        .collect::<Vec<_>>();
    if values.is_empty() {
        return af_web_core::i18n::translate(locale, "Not reported");
    }
    let total = values.iter().sum::<f64>();
    let value = if average {
        total / values.len() as f64
    } else {
        total
    };
    format!("{value:.1}")
}

fn merge_node_observation(node: &mut Value, observed: &Value) {
    if let Some(fields) = observed.as_object() {
        for (key, value) in fields {
            // Metrics may span several topology polls. The current listing
            // owns identity, status and heartbeat fields throughout that work.
            if !matches!(
                key.as_str(),
                "id" | "hostname"
                    | "address"
                    | "role"
                    | "status"
                    | "version"
                    | "enrolled_at"
                    | "last_heartbeat"
            ) {
                node[key] = value.clone();
            }
        }
    }
}

fn heartbeat(locale: &str, value: &Value) -> String {
    let raw = super::contracts::decode::<super::contracts::ClusterNode>(value).last_heartbeat;
    let timestamp = js_sys::Date::parse(&raw);
    if timestamp.is_finite() {
        af_web_core::i18n::translate_with(
            locale,
            "{n}s ago",
            &[(
                "n",
                &format!(
                    "{:.0}",
                    ((js_sys::Date::now() - timestamp) / 1000.0).max(0.0)
                ),
            )],
        )
    } else {
        af_web_core::i18n::translate(locale, "Not reported")
    }
}
fn format_enrollment_instructions(
    instructions: &str,
    origin: Option<&str>,
    hostname: Option<&str>,
) -> String {
    let clean_origin = origin
        .map(str::trim)
        .filter(|o| o.starts_with("https://"))
        .map(|o| o.trim_end_matches('/'));
    let clean_host = hostname.map(str::trim).filter(|h| !h.is_empty());

    let mut out = instructions.to_string();
    if let Some(host) = clean_host {
        let authority_host = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        // Preserve explicit port numbers (e.g. `https://<this-server>:50051`) before
        // substituting portless `https://<this-server>` with the HTTPS origin.
        out = out.replace("<this-server>:", &format!("{authority_host}:"));
        if let Some(https_origin) = clean_origin {
            out = out.replace("https://<this-server>", https_origin);
        } else {
            out = out.replace(
                "https://<this-server>",
                &format!("https://{authority_host}"),
            );
        }
        out = out.replace("<this-server>", host);
    } else if let Some(https_origin) = clean_origin {
        let origin_host = https_origin
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or_default();
        if !origin_host.is_empty() {
            let host_only = origin_host
                .strip_prefix('[')
                .and_then(|rest| rest.split_once(']'))
                .map(|(h, _)| format!("[{h}]"))
                .unwrap_or_else(|| {
                    origin_host
                        .split_once(':')
                        .map(|(h, _)| h)
                        .unwrap_or(origin_host)
                        .to_string()
                });
            out = out.replace("<this-server>:", &format!("{host_only}:"));
        }
        out = out.replace("https://<this-server>", https_origin);
    }
    out
}

#[component]
pub fn ClusterTab() -> impl IntoView {
    let context = app();
    view! {
        <Show
            when=move || context.is_admin()
            fallback=move || {
                view! {
                    <EmptyState title="Common.adminRequired" />
                }
            }
        >
            <ClusterAdminContent />
        </Show>
    }
}

#[component]
fn ClusterAdminContent() -> impl IntoView {
    let context = app();
    let topology = use_api_typed::<Records<ClusterNode>>(Signal::derive(|| {
        "/api/v1/admin/cluster/nodes".to_string()
    }));
    let cluster = grid_resource(topology);
    poll_resource(cluster, 10_000);
    let identity = use_api("/health/ready".to_string());
    poll_resource(identity, 30_000);
    let telemetry = RwSignal::new(BTreeMap::<String, Value>::new());
    let generation = RwSignal::new(0u64);
    let batches = StoredValue::new_local(MetricsBatches::default());
    let telemetry_epoch = StoredValue::new(context.session_epoch.get_untracked());
    let batch_scope = StoredValue::new(None::<Arc<MetricsScope>>);
    let topology_key = Memo::new(move |previous| {
        let snapshot = serde_json::to_value(topology.data.get()).unwrap_or_default();
        metrics_topology_snapshot(
            previous,
            &super::contracts::grid_rows::<ClusterNode>(&snapshot),
        )
    });
    on_cleanup(move || batches.update_value(|batches| batches.cancel()));
    let selected_id = RwSignal::new(String::new());
    let inspector = RwSignal::new(false);
    let enroll_open = RwSignal::new(false);
    let enrollment = RwSignal::new(Value::Null);
    let busy = RwSignal::new(false);
    let remove = RwSignal::new(false);
    Effect::new(move |_| {
        let session_epoch = context.session_epoch.get();
        let admin = context.is_admin();
        let auth_loading = context.auth_loading.get();
        let loading = cluster.loading.get();
        let snapshot = serde_json::to_value(topology.data.get()).unwrap_or_default();
        let nodes = super::contracts::grid_rows::<ClusterNode>(&snapshot);
        let scope = Arc::new(MetricsScope {
            topology: topology_key.get(),
            session_epoch,
            auth_epoch: af_web_core::api::current_auth_epoch(),
        });
        let same_scope = batch_scope.with_value(|previous| previous.as_ref() == Some(&scope));
        if telemetry_epoch.get_value() != session_epoch {
            telemetry.set(BTreeMap::new());
            telemetry_epoch.set_value(session_epoch);
        }
        if !admin || auth_loading || af_web_core::api::auth_revalidation_pending() {
            generation.update(|g| *g += 1);
            batches.update_value(|batches| batches.cancel());
            return;
        }
        // A routine poll does not invalidate metrics for the same node
        // identities. Let an in-flight bounded batch finish, even when it
        // spans several polling intervals. Changed identities still cancel
        // immediately; the guard also checks the latest key before publishing.
        if !same_scope {
            generation.update(|g| *g += 1);
            batches.update_value(|batches| batches.cancel());
        }
        if loading || (same_scope && batches.with_value(MetricsBatches::running)) {
            return;
        }
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        batch_scope.set_value(Some(scope.clone()));
        let guard = MetricsBatchGuard {
            context,
            generation,
            ticket,
            topology: topology_key,
            scope,
        };
        let Some((previous, registration, finished, running)) =
            batches.try_update_value(MetricsBatches::next)
        else {
            return;
        };
        spawn_local(async move {
            let request_guard = guard.clone();
            let work = async move {
                if !request_guard.current() {
                    return BTreeMap::new();
                }
                stream::iter(nodes.into_iter().filter_map(|node| {
                    let id = text(&node, "id");
                    if id.is_empty() {
                        return None;
                    }
                    let guard = request_guard.clone();
                    Some(async move {
                        if !guard.current() {
                            return None;
                        }
                        let value = ApiClient
                            .get(&format!(
                                "/api/v1/admin/cluster/nodes/{}/metrics",
                                encode(&id)
                            ))
                            .await
                            .unwrap_or_else(|error| json!({"observation_error":error.message}));
                        Some((id, value))
                    })
                }))
                .buffer_unordered(4)
                .filter_map(futures::future::ready)
                .collect::<BTreeMap<_, _>>()
                .await
            };
            if let Some(observations) =
                run_metrics_batch(previous, registration, finished, running, work).await
            {
                if !guard.current() {
                    return;
                }
                telemetry.set(observations);
            }
        });
    });
    Effect::new(move |_| {
        if !enroll_open.get() {
            enrollment.set(Value::Null);
        }
    });
    let rows = Signal::derive(move || {
        let observations = telemetry.get();
        super::contracts::grid_rows::<super::contracts::ClusterNode>(&cluster.data.get())
            .into_iter()
            .map(|mut node| {
                if let Some(observed) = observations.get(&text(&node, "id")) {
                    merge_node_observation(&mut node, observed);
                }
                node["heartbeat_age"] =
                    json!(heartbeat(&crate::tabs::l10n::locale(context), &node));
                node["latency"] = json!(node["heartbeat_latency_ms"]
                    .as_f64()
                    .map(|v| format!("{v:.1} ms"))
                    .unwrap_or_else(|| tt(context, "Not reported")));
                node["cpu"] = json!(metric(
                    &crate::tabs::l10n::locale(context),
                    &node,
                    "cpu_usage",
                    "%"
                ));
                node["memory"] = json!(match (
                    node["metrics"]["mem_used_gb"].as_f64(),
                    node["metrics"]["mem_total_gb"].as_f64()
                ) {
                    (Some(used), Some(total)) => format!("{used:.1} / {total:.1} GB"),
                    _ => tt(context, "Not reported"),
                });
                node["storage"] = json!(match (
                    node["metrics"]["disk_used_gb"].as_f64(),
                    node["metrics"]["disk_total_gb"].as_f64()
                ) {
                    (Some(used), Some(total)) => format!("{used:.1} / {total:.1} GB"),
                    _ => tt(context, "Not reported"),
                });
                let master = identity.data.with(|v| text(v, "version"));
                node["version_parity"] =
                    json!(if master.is_empty() || text(&node, "version").is_empty() {
                        "Not verified"
                    } else if text(&node, "version") == master {
                        "Matches coordinator"
                    } else {
                        "Version differs"
                    });
                node["mtls"] = json!(match node["mtls_verified"].as_bool() {
                    Some(true) => "Verified",
                    Some(false) => "Unverified",
                    None => "Not reported",
                });
                node["heartbeat_summary"] = json!(["heartbeat_age", "latency"]
                    .into_iter()
                    .map(|key| tt(context, &text(&node, key)))
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>()
                    .join(" · "));
                node["version_summary"] = json!(["version", "version_parity", "mtls"]
                    .into_iter()
                    .map(|key| tt(context, &text(&node, key)))
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>()
                    .join(" · "));
                for field in ["role", "status"] {
                    node[format!("{field}_label")] = json!(tt(context, &text(&node, field)));
                }
                node
            })
            .collect::<Vec<_>>()
    });
    let rollup = move |key: &str, average: bool| {
        rows.with(|rows| aggregate_metric(&crate::tabs::l10n::locale(context), rows, key, average))
    };
    let selected = Signal::derive(move || {
        rows.get()
            .into_iter()
            .find(|row| text(row, "id") == selected_id.get())
            .unwrap_or(Value::Null)
    });

    let enroll = move || {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        busy.set(true);
        enroll_open.set(true);
        spawn_local(async move {
            match ApiClient.post("/api/v1/admin/cluster/enroll", None).await {
                Ok(mut value) => {
                    if enroll_open.try_get_untracked() == Some(true) {
                        let location = web_sys::window().map(|w| w.location());
                        let origin = location.as_ref().and_then(|l| l.origin().ok());
                        let hostname = location.as_ref().and_then(|l| l.hostname().ok());
                        value["instructions"] = json!(format_enrollment_instructions(
                            &text(&value, "instructions"),
                            origin.as_deref(),
                            hostname.as_deref(),
                        ));
                        enrollment.set(value);
                    }
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy.set(false);
            }
        });
    };
    let copy = move |field: &'static str| {
        let value = enrollment.with_untracked(|v| text(v, field));
        if value.is_empty() {
            return;
        }
        spawn_local(async move {
            if let Some(window) = web_sys::window() {
                match JsFuture::from(window.navigator().clipboard().write_text(&value)).await {
                    Ok(_) => context.toast(tt(context, "Copied to clipboard"), false),
                    Err(_) => context.toast(
                        tt(context, "Clipboard unavailable; select and copy the value"),
                        true,
                    ),
                }
            }
        });
    };
    let decommission = Callback::new(move |()| {
        let value = selected.get_untracked();
        let id = text(&value, "id");
        if busy.get_untracked() || id.is_empty() || value["role"] == "master" || !context.is_admin()
        {
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match ApiClient
                .delete(
                    &format!("/api/v1/admin/cluster/nodes/{}", encode(&id)),
                    None,
                )
                .await
            {
                Ok(_) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    cluster.refresh();
                    remove.set(false);
                    inspector.set(false);
                    context.toast(tt(context, "Worker node removed"), false);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy.set(false);
            }
        });
    });
    view! {
        <section class="space-y-6 py-5 min-w-0 max-w-full">
            <Show
                when=move || context.is_admin()
                fallback=move || {
                    view! {
                        <EmptyState title="Common.adminRequired" />
                    }
                }
            >
                <ObsCard>
                    <h2 class="text-lg font-semibold mb-4">
                        {move || tt(context, "Tabs.clusterHeading")}
                    </h2>
                    <div class="flex flex-wrap justify-between items-center gap-4 mb-5">
                        <p class="text-sm text-slate-400">
                            {move || {
                                tt_with(
                                    context,
                                    "Cluster.nodesSummary",
                                    &[
                                        ("total", &rows.with(Vec::len).to_string()),
                                        ("online", &rows.with(|rows| rows.iter().filter(|v| v["status"] == "online").count().to_string())),
                                        ("mode", &cluster.data.with(|v| {
                                            v["mode"].as_str()
                                                .filter(|mode| !mode.is_empty())
                                                .map(|mode| tt(context, mode))
                                                .unwrap_or_else(|| tt(context, "Cluster.coordinatorView"))
                                        })),
                                    ],
                                )
                            }}
                        </p>
                        <div class="flex gap-3">
                            <button
                                type="button"
                                class="glass-button px-4 py-2"
                                on:click=move |_| cluster.refresh()
                                aria-label=move || tt(context, "Refresh topology")
                            >
                                {move || tt(context, "Common.refresh")}
                            </button>
                            <button
                                type="button"
                                class="glass-button-primary px-4 py-2"
                                disabled=move || busy.get()
                                on:click=move |_| enroll()
                            >
                                {move || tt(context, "Enroll Worker Node")}
                            </button>
                        </div>
                    </div>
                    <ResourceFeedback resource=cluster />
                    <div class="grid sm:grid-cols-3 gap-5 mb-6 text-sm">
                        <div>
                            <p class="text-xs text-slate-400">
                                {move || tt(context, "Reported CPU average (%)")}
                            </p>
                            <p class="text-lg">{move || rollup("cpu_usage", true)}</p>
                        </div>
                        <div>
                            <p class="text-xs text-slate-400">
                                {move || tt(context, "Reported memory (used / total GB)")}
                            </p>
                            <p class="text-lg">
                                {move || {
                                    format!(
                                        "{} / {}",
                                        rollup("mem_used_gb", false),
                                        rollup("mem_total_gb", false),
                                    )
                                }}
                            </p>
                        </div>
                        <div>
                            <p class="text-xs text-slate-400">
                                {move || tt(context, "Reported storage (used / total GB)")}
                            </p>
                            <p class="text-lg">
                                {move || {
                                    format!(
                                        "{} / {}",
                                        rollup("disk_used_gb", false),
                                        rollup("disk_total_gb", false),
                                    )
                                }}
                            </p>
                        </div>
                    </div>
                    <p class="text-xs text-slate-400 mb-5">
                        {move || {
                            tt_with(context, "Telemetry available for {reporting} / {total} nodes. Totals include reporting nodes only.", &[("reporting", &(rows
                                    .get()
                                    .iter()
                                    .filter(|node| node["metrics"].is_object())
                                    .count()).to_string()), ("total", &(rows.with(Vec::len)).to_string())])
                        }}
                    </p>
                    <div
                        role="list"
                        aria-label=move || tt(context, "Cluster heartbeat topology")
                        class="grid sm:grid-cols-2 xl:grid-cols-3 gap-4 mb-6"
                    >
                        <div role="listitem" class="rounded-xl border border-indigo-400/30 p-4">
                            <h3 class="font-semibold text-indigo-300">
                                {move || tt(context, "AetherFlow coordinator")}
                            </h3>
                            <p class="text-xs text-slate-400 mt-2">
                                {move || tt(context, "Heartbeat and enrollment API")}
                            </p>
                        </div>
                        {move || {
                            rows.get()
                                .into_iter()
                                .map(|node| {
                                    let name = text(&node, "hostname");
                                    let status = text(&node, "status");
                                    let role = text(&node, "role");
                                    let age = heartbeat(&crate::tabs::l10n::locale(context), &node);
                                    let id = text(&node, "id");
                                    view! {
                                        <button
                                            type="button"
                                            role="listitem"
                                            class="text-left rounded-xl border border-white/10 p-4 min-w-0"
                                            on:click=move |_| {
                                                selected_id.set(id.clone());
                                                inspector.set(true);
                                            }
                                        >
                                            <h3 class="font-semibold break-all">{name}</h3>
                                            <p class="text-sm text-cyan-300">
                                                {move || format!("{} · {}", tt(context, &role), tt(context, &status))}
                                            </p>
                                            <p class="text-xs text-slate-400 mt-2">{age}</p>
                                        </button>
                                    }
                                })
                                .collect_view()
                        }}
                    </div>
                    <DataGrid
                        label="Cluster node telemetry"
                        rows
                        columns=vec![
                            GridColumn::new("hostname", "Node"),
                            GridColumn::new("address", "Address"),
                            GridColumn::new("role_label", "Mode"),
                            GridColumn::new("status_label", "State"),
                            GridColumn::new("heartbeat_summary", "Last heartbeat"),
                            GridColumn::new("cpu", "CPU"),
                            GridColumn::new("memory", "Memory"),
                            GridColumn::new("version_summary", "Version"),
                        ]
                        on_select=Callback::new(move |row: Value| {
                            selected_id.set(text(&row, "id"));
                            inspector.set(true);
                        })
                    />
                    <p class="text-xs text-slate-400 mt-4">
                        {move || tt(
                            context,
                            "Enrollment uses the coordinator-provided credential. mTLS verification and node drain are not exposed by this server. Remove a worker after its workloads have been stopped or moved.",
                        )}
                    </p>
                </ObsCard>
            </Show>
            <Drawer open=inspector title="Worker telemetry & services">
                <h3 class="font-semibold break-all">
                    {move || selected.with(|v| text(v, "hostname"))}
                </h3>
                <p class="text-sm text-slate-400 my-4">
                    {move || {
                        selected
                            .with(|v| {
                                tt_with(context, "Service inventory: {running} · {total}", &[("running", &(text(v, "services_status")).to_string()), ("total", &(text(v, "observation_error")).to_string())])
                            })
                    }}
                </p>
                <DataGrid
                    label="Worker services"
                    columns=vec![
                        GridColumn::new("name", "Service"),
                        GridColumn::new("status_label", "State"),
                        GridColumn::new("uptime", "Uptime"),
                        GridColumn::new("managed_by", "Manager"),
                    ]
                    rows=Signal::derive(move || {
                        context.locale.get();
                        context.catalog_revision.get();
                        selected.get()["services"].as_array().cloned().unwrap_or_default()
                            .into_iter().map(|mut row| {
                                row["status_label"] = json!(tt(context, &text(&row, "status")));
                                row
                            }).collect::<Vec<_>>()
                    })
                />
                <pre class="text-xs whitespace-pre-wrap break-all max-h-72 overflow-auto my-5">
                    {move || serde_json::to_string_pretty(&selected.get()).unwrap_or_default()}
                </pre>
                <button
                    type="button"
                    class="glass-button px-4 py-2 text-rose-300"
                    disabled=move || {
                        busy.get() || selected.get().is_null() || selected.get()["role"] == "master"
                    }
                    on:click=move |_| remove.set(true)
                >
                    {move || tt(context, "Remove worker")}
                </button>
            </Drawer>
            <Modal open=enroll_open title="Worker enrollment">
                <p class="text-sm text-amber-300 mb-4">
                    {move || tt(
                        context,
                        "Keep this enrollment credential private. Closing this dialog clears it from this view.",
                    )}
                </p>
                <p class="text-sm text-slate-400" role="status">
                    {move || tt(context, if busy.get() { "Generating enrollment…" } else { "" })}
                </p>
                <code class="block break-all p-3 bg-white/5 rounded-lg">
                    {move || enrollment.with(|v| text(v, "enrollment_token"))}
                </code>
                <button
                    type="button"
                    class="glass-button px-4 py-2 my-3"
                    on:click=move |_| copy("enrollment_token")
                >
                    {move || tt(context, "Copy token")}
                </button>
                <pre class="whitespace-pre-wrap break-all text-sm">
                    {move || enrollment.with(|v| text(v, "instructions"))}
                </pre>
                <button
                    type="button"
                    class="glass-button px-4 py-2 mt-3"
                    on:click=move |_| copy("instructions")
                >
                    {move || tt(context, "Copy join command")}
                </button>
            </Modal>
            <ConfirmDialog
                open=remove
                title="Remove this worker node?"
                message="The worker will be decommissioned from cluster membership. Stop or migrate its workloads before continuing."
                busy
                on_confirm=decommission
            />
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{executor::LocalPool, future, task::LocalSpawnExt};
    use std::{cell::RefCell, rc::Rc};

    #[derive(Default)]
    struct BatchProbe {
        active: usize,
        peak: usize,
        started: Vec<(char, usize)>,
    }

    struct ActiveProbe(Rc<RefCell<BatchProbe>>);
    impl Drop for ActiveProbe {
        fn drop(&mut self) {
            self.0.borrow_mut().active -= 1;
        }
    }

    async fn held_metrics(probe: Rc<RefCell<BatchProbe>>, generation: char) {
        stream::iter(0..6)
            .map(|id| {
                let probe = probe.clone();
                async move {
                    {
                        let mut state = probe.borrow_mut();
                        state.active += 1;
                        state.peak = state.peak.max(state.active);
                        state.started.push((generation, id));
                    }
                    let _active = ActiveProbe(probe);
                    future::pending::<()>().await;
                }
            })
            .buffer_unordered(4)
            .collect::<Vec<_>>()
            .await;
    }

    #[test]
    fn superseded_batches_drop_active_requests_before_starting_the_latest() {
        let mut pool = LocalPool::new();
        let spawner = pool.spawner();
        let probe = Rc::new(RefCell::new(BatchProbe::default()));
        let mut batches = MetricsBatches::default();
        let start = |batches: &mut MetricsBatches, name| {
            let (previous, registration, finished, running) = batches.next();
            let work = held_metrics(probe.clone(), name);
            spawner
                .spawn_local(async move {
                    let _ =
                        run_metrics_batch(previous, registration, finished, running, work).await;
                })
                .unwrap();
        };

        start(&mut batches, 'a');
        pool.run_until_stalled();
        assert_eq!(probe.borrow().active, 4);

        // Cancel a second generation before it has passed the first barrier.
        start(&mut batches, 'b');
        start(&mut batches, 'c');
        pool.run_until_stalled();
        let state = probe.borrow();
        assert_eq!(state.active, 4);
        assert_eq!(state.peak, 4);
        assert_eq!(
            state.started,
            vec![
                ('a', 0),
                ('a', 1),
                ('a', 2),
                ('a', 3),
                ('c', 0),
                ('c', 1),
                ('c', 2),
                ('c', 3),
            ]
        );
        drop(state);

        batches.cancel();
        pool.run_until_stalled();
        assert_eq!(probe.borrow().active, 0);
    }

    #[test]
    fn metrics_identity_ignores_heartbeat_and_order_but_tracks_node_replacement() {
        let a = json!({"id":"a","hostname":"one","address":"host-a","status":"online","last_heartbeat":"old"});
        let b = json!({"id":"b","hostname":"two","address":"host-b","status":"online"});
        let original = metrics_topology_key(&[a.clone(), b.clone()]);
        let mut refreshed = a.clone();
        refreshed["last_heartbeat"] = json!("new");
        refreshed["metrics"] = json!({"cpu_usage": 42});
        assert_eq!(
            original,
            metrics_topology_key(&[b.clone(), refreshed.clone()])
        );
        refreshed["address"] = json!("replacement");
        assert_ne!(original, metrics_topology_key(&[b.clone(), refreshed]));
        let snapshot = metrics_topology_snapshot(None, &[a.clone(), b.clone()]);
        let same = metrics_topology_snapshot(Some(&snapshot), &[b.clone(), a.clone()]);
        assert!(Arc::ptr_eq(&snapshot, &same));
        let changed = metrics_topology_snapshot(Some(&same), std::slice::from_ref(&a));
        assert!(!Arc::ptr_eq(&same, &changed));
        let restored = metrics_topology_snapshot(Some(&changed), &[a, b]);
        assert!(!Arc::ptr_eq(&snapshot, &restored));
    }

    #[test]
    fn completed_metrics_batch_can_refresh_again() {
        let mut batches = MetricsBatches::default();
        let (previous, registration, finished, running) = batches.next();
        assert!(batches.running());
        assert_eq!(
            futures::executor::block_on(run_metrics_batch(
                previous,
                registration,
                finished,
                running,
                future::ready(42)
            )),
            Some(42)
        );
        assert!(!batches.running());
        let (previous, registration, finished, running) = batches.next();
        assert!(batches.running());
        assert_eq!(
            futures::executor::block_on(run_metrics_batch(
                previous,
                registration,
                finished,
                running,
                future::ready(77)
            )),
            Some(77)
        );
        assert!(!batches.running());
    }

    #[test]
    fn delayed_metrics_keep_current_topology_identity_and_heartbeat() {
        let mut node = json!({"id":"a","hostname":"current","address":"new-host","role":"worker","status":"online","version":"new","enrolled_at":"new-enrollment","last_heartbeat":"new-heartbeat"});
        let current = node.clone();
        let observed = json!({"id":"wrong","hostname":"old","address":"old-host","role":"old-role","status":"offline","version":"old","enrolled_at":"old-enrollment","last_heartbeat":"old-heartbeat","metrics":{"cpu_usage":42},"services_status":"unknown","observation_error":"offline"});
        merge_node_observation(&mut node, &observed);
        for key in [
            "id",
            "hostname",
            "address",
            "role",
            "status",
            "version",
            "enrolled_at",
            "last_heartbeat",
        ] {
            assert_eq!(node[key], current[key], "{key}");
        }
        assert_eq!(node["metrics"]["cpu_usage"], 42);
        assert_eq!(node["services_status"], "unknown");
        assert_eq!(node["observation_error"], "offline");
    }

    #[test]
    fn metrics_guard_rejects_identity_and_account_changes_before_effects_run() {
        Owner::new().with(|| {
            let context = crate::state::AppContext::new();
            context.auth_loading.set(false);
            context
                .user
                .set(Some(json!({"id": 1, "username": "admin", "role": "admin"})));
            let generation = RwSignal::new(7);
            let data = RwSignal::new(vec![
                json!({"id":"a","address":"original","last_heartbeat":"old"}),
            ]);
            let topology =
                Memo::new(move |previous| metrics_topology_snapshot(previous, &data.get()));
            let guard = MetricsBatchGuard {
                context,
                generation,
                ticket: 7,
                topology,
                scope: Arc::new(MetricsScope {
                    topology: topology.get_untracked(),
                    session_epoch: context.session_epoch.get_untracked(),
                    auth_epoch: af_web_core::api::current_auth_epoch(),
                }),
            };
            assert!(guard.current());
            data.update(|nodes| nodes[0]["last_heartbeat"] = json!("new"));
            assert!(guard.current());
            data.update(|nodes| nodes[0]["address"] = json!("replacement"));
            assert!(!guard.current());
            data.update(|nodes| nodes[0]["address"] = json!("original"));
            assert!(!guard.current());
            let current_guard = MetricsBatchGuard {
                scope: Arc::new(MetricsScope {
                    topology: topology.get_untracked(),
                    session_epoch: context.session_epoch.get_untracked(),
                    auth_epoch: af_web_core::api::current_auth_epoch(),
                }),
                ..guard
            };
            assert!(current_guard.current());
            context.session_epoch.update(|epoch| *epoch += 1);
            assert!(!current_guard.current());
        });
    }

    #[test]
    fn missing_node_metrics_translate_without_inventing_values() {
        let absent = json!({"metrics":{}});
        assert_eq!(metric("de", &absent, "cpu_usage", "%"), "Nicht gemeldet");
        assert_eq!(
            aggregate_metric("fr", &[absent], "cpu_usage", true),
            "Non renseigné"
        );
    }

    #[test]
    fn cluster_rollups_exclude_missing_measurements_from_averages() {
        let rows = vec![
            json!({"metrics":{"cpu_usage":20,"mem_total_gb":32}}),
            json!({"metrics":{"cpu_usage":60,"mem_total_gb":64}}),
            json!({"metrics":{"cpu_usage":null}}),
            json!({"observation_error":"offline"}),
        ];
        assert_eq!(aggregate_metric("en", &rows, "cpu_usage", true), "40.0");
        assert_eq!(aggregate_metric("en", &rows, "mem_total_gb", false), "96.0");
        assert_eq!(
            aggregate_metric("en", &rows, "unreported", true),
            "Not reported"
        );
        assert_eq!(
            aggregate_metric("en", &[], "cpu_usage", false),
            "Not reported"
        );
    }

    #[test]
    fn individual_node_metrics_do_not_invent_missing_counters() {
        assert_eq!(
            metric(
                "en",
                &json!({"metrics":{"cpu_usage":12.25}}),
                "cpu_usage",
                "%"
            ),
            "12.2%"
        );
        assert_eq!(
            metric("en", &json!({"metrics":{"cpu_usage":0}}), "cpu_usage", "%"),
            "0.0%"
        );
        assert_eq!(
            metric(
                "en",
                &json!({"metrics":{"cpu_usage":"unknown"}}),
                "cpu_usage",
                "%"
            ),
            "Not reported"
        );
    }

    #[test]
    fn enrollment_instructions_preserve_explicit_ports_and_format_server_host() {
        let with_port =
            "CLUSTER_MODE=worker\nCLUSTER_MASTER_ADDR=https://<this-server>:50051\nCLUSTER_PSK=abc";
        assert_eq!(
            format_enrollment_instructions(
                with_port,
                Some("https://panel.example.com"),
                Some("panel.example.com"),
            ),
            "CLUSTER_MODE=worker\nCLUSTER_MASTER_ADDR=https://panel.example.com:50051\nCLUSTER_PSK=abc"
        );
        assert_eq!(
            format_enrollment_instructions(
                with_port,
                Some("https://panel.example.com:8443"),
                Some("panel.example.com"),
            ),
            "CLUSTER_MODE=worker\nCLUSTER_MASTER_ADDR=https://panel.example.com:50051\nCLUSTER_PSK=abc"
        );
        assert_eq!(
            format_enrollment_instructions(
                with_port,
                Some("http://localhost:3000"),
                Some("localhost"),
            ),
            "CLUSTER_MODE=worker\nCLUSTER_MASTER_ADDR=https://localhost:50051\nCLUSTER_PSK=abc"
        );
        assert_eq!(
            format_enrollment_instructions(with_port, None, None),
            "CLUSTER_MODE=worker\nCLUSTER_MASTER_ADDR=https://<this-server>:50051\nCLUSTER_PSK=abc"
        );

        let portless =
            "CLUSTER_MODE=worker\nCLUSTER_MASTER_ADDR=https://<this-server>\nCLUSTER_PSK=abc";
        assert_eq!(
            format_enrollment_instructions(
                portless,
                Some("https://panel.example.com:8443"),
                Some("panel.example.com"),
            ),
            "CLUSTER_MODE=worker\nCLUSTER_MASTER_ADDR=https://panel.example.com:8443\nCLUSTER_PSK=abc"
        );
        assert_eq!(
            format_enrollment_instructions(
                portless,
                Some("http://localhost:3000"),
                Some("localhost"),
            ),
            "CLUSTER_MODE=worker\nCLUSTER_MASTER_ADDR=https://localhost\nCLUSTER_PSK=abc"
        );
    }
}
