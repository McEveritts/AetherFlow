use super::contracts::{grid_resource, use_api_typed, Records, SharedRecord};
use crate::state::{app, json_rows, use_api, ApiResource, AppContext};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{Badge, Drawer, EmptyState, Modal, SearchInput, TabPanel, TabsBar};
use af_web_core::{
    api::ApiClient,
    models::{MarketplaceApp, MarketplaceJobOutcome, PackageLifecycleRecord},
};
use af_web_ui::use_worker_rows;
use gloo_events::EventListener;
use leptos::prelude::*;
use serde_json::{json, Value};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;

mod catalog;
use catalog::*;
mod operations;
use operations::*;
mod sandbox;
use sandbox::*;

#[component]
pub fn MarketplaceTab() -> impl IntoView {
    let context = app();
    let catalog = grid_resource(use_api_typed::<Records<SharedRecord<MarketplaceApp>>>(
        Signal::derive(move || {
            context.marketplace_revision.track();
            "/api/v1/public/marketplace".to_string()
        }),
    ));
    let plugins = use_api(Signal::derive(move || {
        context.marketplace_revision.track();
        "/api/v1/auth/plugins".to_string()
    }));
    let ops = MarketplaceOps {
        context,
        catalog,
        jobs: RwSignal::new(BTreeMap::new()),
        submitting: RwSignal::new(BTreeSet::new()),
        checking: RwSignal::new(BTreeSet::new()),
        ticket: RwSignal::new(0),
        polling: RwSignal::new(false),
        deployment: RwSignal::new(None),
        drawer: RwSignal::new(false),
    };
    let query = RwSignal::new(String::new());
    let category = RwSignal::new("All".to_string());
    let rows = Signal::derive(move || {
        let mut rows = json_rows(&catalog.data.get())
            .into_iter()
            .map(catalog_row)
            .collect::<Vec<_>>();
        rows.sort_by_key(|v| field(v, &["name", "id"]).to_lowercase());
        rows
    });
    let matches = use_worker_rows(
        rows,
        query.into(),
        vec![
            "name".into(),
            "id".into(),
            "desc".into(),
            "description".into(),
            "category".into(),
        ],
    );
    let filtered = Memo::new(move |_| {
        let category = category.get();
        matches
            .get()
            .into_iter()
            .filter(|v| match category.as_str() {
                "All" => true,
                "Installed" => installed(v),
                "Updates Available" => v["update_available"] == true,
                _ => domain(v) == category,
            })
            .collect::<Vec<_>>()
    });
    let pending = RwSignal::new(None::<(Value, String)>);
    let confirm = RwSignal::new(false);
    let purge_data = RwSignal::new(false);
    let purge_confirmation = RwSignal::new(String::new());
    Effect::new(move |_| {
        if !confirm.get() {
            purge_data.set(false);
            purge_confirmation.set(String::new());
        }
    });
    Effect::new(move |_| {
        let rows = rows.get();
        ops.jobs.update(|jobs| {
            for row in rows {
                let id = field(&row, &["id"]);
                let status = field(&row, &["status"]);
                if id.is_empty() {
                    continue;
                }
                if matches!(
                    status.as_str(),
                    "installing" | "updating" | "uninstalling" | "reinstalling"
                ) && jobs.get(&id).is_none_or(|job| {
                    !job.active
                        && !field(&row, &["job_id"]).is_empty()
                        && field(&row, &["job_id"]) != job.job_id
                }) {
                    let action = match status.as_str() {
                        "updating" => "update",
                        "uninstalling" => "uninstall",
                        "reinstalling" => "reinstall",
                        _ => "install",
                    };
                    let mut job = PackageJob::new(action, 0, &row);
                    job.accepted = true;
                    job.observed = true;
                    job.job_id = field(&row, &["job_id"]);
                    job.started_at = field(&row, &["started_at"]);
                    job.status = status.clone();
                    job.progress = row["progress"].as_f64().unwrap_or(0.0).clamp(0.0, 100.0);
                    job.push_log(field(&row, &["log_line"]));
                    jobs.insert(id.clone(), job);
                }
                if let Some(job) = jobs.get_mut(&id).filter(|j| j.active && j.accepted) {
                    let last = &row["last_job"];
                    // Only a matching immutable receipt can resolve an active local operation.
                    if (!job.job_id.is_empty() && field(last, &["job_id"]) == job.job_id)
                        || (job.job_id.is_empty()
                            && !job.started_at.is_empty()
                            && field(last, &["started_at"]) == job.started_at)
                    {
                        job.observe(last);
                    }
                    if lifecycle(&status) && status != "running" {
                        job.observed = true;
                    }
                    // Older servers can omit job identities. A changed, authenticated
                    // inventory can still confirm a first install or data-preserving removal.
                    // Repair/update always require their operation's terminal receipt.
                    if job.active
                        && job.job_id.is_empty()
                        && job.started_at.is_empty()
                        && row["inventory_authenticated"] != false
                        && row["inventory_known"] != false
                        && ((job.action == "install"
                            && !job.was_installed
                            && status == "installed")
                            || (job.action == "uninstall"
                                && job.was_installed
                                && status == "not_installed"))
                    {
                        job.active = false;
                        job.status = "completed".into();
                        job.progress = 100.0;
                        job.error = None;
                        job.push_log(
                            "Operation result confirmed by refreshed package inventory.".into(),
                        );
                    }
                }
            }
        });
    });
    let interval = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        2000,
        move || {
            ops.poll();
            if ops
                .jobs
                .with_untracked(|jobs| jobs.values().any(|j| j.active && j.accepted))
                && !catalog.loading.get_untracked()
            {
                catalog.refresh();
            }
        },
    )));
    on_cleanup(move || interval.set_value(None));
    view! {
        <section class="py-5 space-y-6 min-w-0 max-w-full">
            <header class="flex flex-wrap items-start justify-between gap-4 pb-5 border-b border-white/10">
                <div>
                    <p class="text-xs uppercase tracking-[.2em] text-indigo-300 mb-2">
                        {move || tt(context, "Marketplace.discover")}
                    </p>
                    <h2 class="text-2xl font-semibold">
                        {move || tt(context, "AetherMarketplace")}
                    </h2>
                    <p class="text-sm text-slate-400 mt-3">
                        {move || tt(context, "Tabs.marketplaceSubtitle")}
                    </p>
                </div>
                <div class="flex flex-wrap gap-3">
                    <button
                        type="button"
                        class="glass-button px-4 py-2 min-h-11"
                        disabled=move || catalog.loading.get()
                        on:click=move |_| {
                            catalog.refresh();
                            plugins.refresh();
                        }
                        aria-label=move || tt(context, "Refresh catalog")
                    >
                        {move || tt(context, "Common.refresh")}
                    </button>
                    <Show when=move || context.is_admin()>
                        <button
                            type="button"
                            class="glass-button px-4 py-2 min-h-11"
                            disabled=move || ops.checking.with(|set| set.contains(""))
                            on:click=move |_| ops.check_updates(None)
                        >
                            {move || {
                                if ops.checking.with(|set| set.contains("")) {
                                    tt(context, "Marketplace.checkingUpdates")
                                } else {
                                    tt(context, "Marketplace.checkUpdates")
                                }
                            }}
                        </button>
                    </Show>
                </div>
            </header>
            <Show when=move || {
                !context.is_admin()
                    || rows.with(|rows| rows.iter().any(|p| p["inventory_authenticated"] == false))
            }>
                <div
                    role="status"
                    class="rounded-xl border border-indigo-400/30 bg-indigo-500/10 p-4 text-sm text-indigo-200"
                >
                    {move || tt(
                        context,
                        "Application inventory is read-only unless authenticated administrator inventory is available. Install and remove controls are hidden for public inventory or accounts without administrator access.",
                    )}
                </div>
            </Show>
            <SearchInput value=query placeholder="Search applications" />
            <TabsBar
                id_prefix="marketplace"
                active=category
                tabs=Signal::derive(move || {
                    vec![
                        ("All".into(), tt(context, "Common.all")),
                        ("Media & IPTV".into(), tt(context, "Marketplace.categoryMedia")),
                        ("Arr Stack".into(), tt(context, "Marketplace.categoryArr")),
                        ("Download Clients".into(), tt(context, "Marketplace.categoryDownloads")),
                        ("Cloud & Storage".into(), tt(context, "Marketplace.categoryCloud")),
                        ("Network & VPN".into(), tt(context, "Marketplace.categoryNetwork")),
                        ("Monitoring & Security".into(), tt(context, "Marketplace.categoryMonitoring")),
                        ("Productivity & Desktop".into(), tt(context, "Marketplace.categoryProductivity")),
                        ("Installed".into(), tt(context, "Marketplace.installed")),
                        ("Updates Available".into(), tt(context, "Marketplace.updatesAvailable")),
                    ]
                })
            />
            <TabPanel id_prefix="marketplace" id=Signal::derive(move || category.get())>
                <div class="space-y-6">
                    <p class="text-xs text-slate-500">
                        {move || {
                            tt_with(
                                context,
                                "Marketplace.matchingSummary",
                                &[("matching", &filtered.with(Vec::len).to_string()), ("total", &rows.with(Vec::len).to_string())],
                            )
                        }}
                    </p>
                    <Show when=move || catalog.error.get().is_some()>
                        <div role="alert" class="af-danger-banner">
                            {move || catalog.error.get().map(|e| tt(context, &e.message))}
                            <button class="ml-3 underline" on:click=move |_| catalog.refresh()>
                                {move || tt(context, "Retry")}
                            </button>
                        </div>
                    </Show>
                    <Show when=move || catalog.loading.get() && rows.with(Vec::is_empty)>
                        <p role="status" class="text-slate-400">
                            {move || tt(context, "Loading application catalog…")}
                        </p>
                    </Show>
                    <div class="grid sm:grid-cols-2 xl:grid-cols-3 border-y border-white/10 divide-y divide-white/10 gap-px">
                        <For
                            each=move || filtered.get()
                            key=|v| field(v, &["id"])
                            children=move |package| {
                                let id = field(&package, &["id"]);
                                view! { <PackageCard id rows ops pending confirm /> }
                            }
                        />
                    </div>
                    <Show when=move || !catalog.loading.get() && filtered.with(Vec::is_empty)>
                        <EmptyState
                            title="No matching applications"
                            description="Try another category or a shorter search."
                        />
                    </Show>
                </div>
            </TabPanel>
            <Show when=move || {
                pending.with(Option::is_some)
            }>
                {move || {
                    pending
                        .get()
                        .map(|(package, action)| {
                            let name = field(&package, &["name", "id"]);
                            let title = match action.as_str() {
                                "uninstall" => tt_with(context, "Uninstall {name}", &[("name", &(name).to_string())]),
                                "reinstall" => tt_with(context, "Repair {name}", &[("name", &(name).to_string())]),
                                _ => tt_with(context, "Install {name}", &[("name", &(name).to_string())]),
                            };
                            let requirements = package["config_schema"]["required"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(", ");
                            let message = match action.as_str() {
                                "uninstall" => tt(context, "Remove the application and keep its data, configuration, secrets, and allocated port for a later reinstall."),
                                "reinstall" => tt(context, "Reapply the installer using the existing configuration and data. The application may restart."),
                                _ => {
                                    let details = if requirements.is_empty() {
                                        tt(context, "Review this package's configuration before continuing.")
                                    } else {
                                        tt_with(context, "Required settings: {requirements}.", &[("requirements", &requirements)])
                                    };
                                    tt_with(context, "Install {name} using the host's configured installer settings. {details}", &[("name", &name), ("details", &details)])
                                }
                            };
                            let action = if action == "uninstall" {
                                "uninstall"
                            } else if action == "reinstall" {
                                "reinstall"
                            } else {
                                "install"
                            };
                            let package_id = StoredValue::new(field(&package, &["id"]));
                            view! {
                                <Modal open=confirm title>
                                    <p class="text-slate-300 mb-5">
                                        {move || {
                                            if action == "uninstall" && purge_data.get() {
                                                tt(context, "Remove the application and permanently delete its data, configuration, secrets, and allocated port. This cannot be undone.")
                                            } else {
                                                message.clone()
                                            }
                                        }}
                                    </p>
                                    <Show when=move || action == "uninstall">
                                        <label class="flex gap-3 items-start text-sm text-rose-200 mb-4">
                                            <input
                                                type="checkbox"
                                                prop:checked=move || purge_data.get()
                                                on:change=move |event| {
                                                    purge_data.set(event_target_checked(&event));
                                                    purge_confirmation.set(String::new());
                                                }
                                            />
                                            <span>
                                                {move || tt(
                                                    context,
                                                    "Permanently purge application data (?purge=true)",
                                                )}
                                            </span>
                                        </label>
                                        <Show when=move || purge_data.get()>
                                            <label class="block text-sm space-y-2 mb-5">
                                                <span>
                                                    {move || tt_with(context, "Type {id} to confirm permanent deletion", &[("id", &(package_id.get_value()).to_string())])}
                                                </span>
                                                <input
                                                    type="text"
                                                    class="glass-input w-full px-3 py-2"
                                                    autocomplete="off"
                                                    spellcheck="false"
                                                    aria-label=move || tt(
                                                        context,
                                                        "Package ID to confirm data purge",
                                                    )
                                                    prop:value=move || purge_confirmation.get()
                                                    on:input=move |event| {
                                                        purge_confirmation.set(event_target_value(&event))
                                                    }
                                                />
                                            </label>
                                        </Show>
                                    </Show>
                                    <div class="flex gap-3 justify-end">
                                        <button
                                            type="button"
                                            class="glass-button px-4 py-2"
                                            on:click=move |_| confirm.set(false)
                                        >
                                            {move || tt(context, "Cancel")}
                                        </button>
                                        <button
                                            type="button"
                                            class="glass-button-primary px-4 py-2"
                                            disabled=move || {
                                                !context.is_admin()
                                                    || !purge_confirmed(
                                                        &package_id.get_value(),
                                                        action == "uninstall" && purge_data.get(),
                                                        &purge_confirmation.get(),
                                                    )
                                            }
                                            on:click=move |_| {
                                                let purge = action == "uninstall"
                                                    && purge_data.get_untracked();
                                                if !purge_confirmed(
                                                    &package_id.get_value(),
                                                    purge,
                                                    &purge_confirmation.get_untracked(),
                                                ) {
                                                    return;
                                                }
                                                confirm.set(false);
                                                purge_data.set(false);
                                                purge_confirmation.set(String::new());
                                                ops.start_with_purge(package.clone(), action, purge);
                                            }
                                        >
                                            {move || tt(context, "Confirm")}
                                        </button>
                                    </div>
                                </Modal>
                            }
                        })
                }}
            </Show>
            <Drawer open=ops.drawer title="Deployment Status">
                <DeploymentStatus ops />
            </Drawer>
            <PluginCatalog resource=plugins />
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_purge_requires_exact_package_id_and_uninstall_action() {
        assert!(purge_confirmed("sonarr", false, ""));
        assert!(!purge_confirmed("sonarr", true, "Sonarr"));
        assert!(!purge_confirmed("sonarr", true, "sonarr "));
        assert!(!purge_confirmed("", true, ""));
        assert!(purge_confirmed("sonarr", true, "sonarr"));
        assert_eq!(
            lifecycle_path("sonarr", "uninstall", false),
            "/api/v1/admin/packages/sonarr/uninstall"
        );
        assert_eq!(
            lifecycle_path("sonarr", "uninstall", true),
            "/api/v1/admin/packages/sonarr/uninstall?purge=true"
        );
        assert_eq!(
            lifecycle_path("legacy%2Fid", "install", true),
            "/api/v1/admin/packages/legacy%2Fid/install"
        );
    }

    #[test]
    fn typed_lifecycle_outcomes_preserve_progress_and_version_evidence() {
        let outcome = MarketplaceJobOutcome {
            job_id: "job-1".into(),
            action: "update".into(),
            status: "completed".into(),
            started_at: "start".into(),
            finished_at: "finish".into(),
            expected_target_version: Some("2.0".into()),
            achieved_version: Some("2.0".into()),
            ..Default::default()
        };
        let mut payload = serde_json::to_value(outcome).unwrap();
        payload["progress"] = json!(100);
        payload["target_mismatch"] = json!(false);
        let normalized = lifecycle_payload(&payload);
        assert_eq!(normalized["progress"], 100);
        assert_eq!(normalized["achieved_version"], "2.0");
        assert_eq!(normalized["target_mismatch"], false);
        let legacy = json!({"status":"failed","error":"legacy failure"});
        assert_eq!(lifecycle_payload(&legacy), legacy);
        let mut job = PackageJob::new("update", 1, &json!({"latest_version":"2.0"}));
        job.accepted = true;
        job.job_id = "job-1".into();
        assert!(job.observe(&payload));
        assert!(!job.active);
        assert_eq!(job.status, "completed");
    }

    #[test]
    fn lifecycle_observation_rejects_stale_and_identity_free_terminal_receipts() {
        let mut job = PackageJob::new("install", 1, &json!({}));
        assert!(!job.observe(&json!({"status":"completed"})));
        job.accepted = true;
        assert!(!job.observe(&json!({"status":"completed"})));
        job.job_id = "current".into();
        assert!(!job.observe(&json!({"job_id":"old","action":"install","status":"completed"})));
        assert!(
            !job.observe(&json!({"job_id":"current","action":"uninstall","status":"completed"}))
        );
        assert!(job.active);
        assert!(job.observe(&json!({"job_id":"current","action":"install","status":"failed","error":"installer failed"})));
        assert_eq!(job.error.as_deref(), Some("installer failed"));
    }

    #[test]
    fn typed_catalog_preserves_lifecycle_and_unknown_capabilities() {
        let value = catalog_row(
            json!({"id":"bazarr","name":"Bazarr","desc":"Subtitles","hits":5,"category":"Media","status":"installing","progress":34,"log_line":"Pulling archive","custom_field":true}),
        );
        assert_eq!(value["name"], "Bazarr");
        assert_eq!(value["progress"], 34);
        assert_eq!(value["log_line"], "Pulling archive");
        assert_eq!(value["custom_field"], true);
        assert!(value["inventory_known"].is_null());
        assert_eq!(status_label("installing"), "Installing");
        let installed = catalog_row(
            json!({"id":"bazarr","name":"Bazarr","desc":"","hits":0,"category":"Media","status":"installed","progress":100,"installed_version":"1.1.0"}),
        );
        assert!(super::installed(&installed));
        assert_eq!(installed["installed_version"], "1.1.0");
        assert_eq!(status_label("installed"), "Installed");
        let partial = json!({"id":"legacy","description":"Legacy catalog"});
        assert_eq!(catalog_row(partial.clone()), partial);
    }

    #[test]
    fn proxy_permits_bound_concurrency_and_release_on_drop() {
        let count = Rc::new(Cell::new(0));
        let mut permits = (0..4)
            .map(|_| InFlightRequest::acquire(&count).unwrap())
            .collect::<Vec<_>>();
        assert!(InFlightRequest::acquire(&count).is_none());
        permits.pop();
        assert_eq!(count.get(), 3);
        assert!(InFlightRequest::acquire(&count).is_some());
        drop(permits);
        assert_eq!(count.get(), 0);
    }

    #[test]
    fn lifecycle_state_helpers_keep_failures_and_actions_distinct() {
        assert!(action_matches("uninstall", "remove"));
        assert!(!action_matches("update", "install"));
        assert!(lifecycle("queued"));
        assert_eq!(status_label("install_failed"), "Failed");
        assert_eq!(phase("update"), "updating");
        assert!(!valid_domain("example.com/path"));
    }
}
