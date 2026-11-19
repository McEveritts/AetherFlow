use super::*;

pub(super) fn field(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| {
            value
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_default()
        .to_string()
}
pub(super) fn catalog_row(mut row: Value) -> Value {
    if let Ok(app) = serde_json::from_value::<MarketplaceApp>(row.clone()) {
        row["id"] = json!(app.id);
        row["name"] = json!(app.name);
        row["desc"] = json!(app.desc);
        row["hits"] = json!(app.hits);
        row["category"] = json!(app.category);
        row["status"] = json!(app.status);
        row["progress"] = json!(app.progress);
        row["installed_version"] = json!(app.installed_version);
        row["latest_version"] = json!(app.latest_version);
        row["update_available"] = json!(app.update_available);
        row["log_line"] = json!(app.log_line);
        // Leave absent inventory capabilities absent for older servers.
    }
    if row["last_job"].is_object() {
        row["last_job"] = lifecycle_payload(&row["last_job"]);
    }
    row
}

pub(super) fn lifecycle_payload(value: &Value) -> Value {
    let mut normalized = value.clone();
    // Deserialize shared contracts while retaining progress, error details and
    // fields reported by older/newer servers outside those contracts.
    let typed = serde_json::from_value::<PackageLifecycleRecord>(value.clone())
        .ok()
        .and_then(|record| serde_json::to_value(record).ok())
        .or_else(|| {
            serde_json::from_value::<MarketplaceJobOutcome>(value.clone())
                .ok()
                .and_then(|outcome| serde_json::to_value(outcome).ok())
        });
    if let (Some(target), Some(fields)) = (
        normalized.as_object_mut(),
        typed.and_then(|v| v.as_object().cloned()),
    ) {
        target.extend(fields);
    }
    normalized
}

pub(super) fn purge_confirmed(id: &str, purge: bool, confirmation: &str) -> bool {
    !purge || (!id.is_empty() && confirmation == id)
}

pub(super) fn lifecycle_path(encoded_id: &str, action: &str, purge: bool) -> String {
    format!(
        "/api/v1/admin/packages/{encoded_id}/{action}{}",
        if action == "uninstall" && purge {
            "?purge=true"
        } else {
            ""
        }
    )
}

pub(super) const MAX_PLUGIN_REQUESTS: usize = 4;
pub(super) struct InFlightRequest(Rc<Cell<usize>>);
impl InFlightRequest {
    pub(super) fn acquire(counter: &Rc<Cell<usize>>) -> Option<Self> {
        if counter.get() >= MAX_PLUGIN_REQUESTS {
            return None;
        }
        counter.set(counter.get() + 1);
        Some(Self(Rc::clone(counter)))
    }
}
impl Drop for InFlightRequest {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}
pub(super) fn installed(value: &Value) -> bool {
    matches!(
        value["status"].as_str(),
        Some("installed" | "running" | "active" | "stopped")
    ) || !field(value, &["installed_version"]).is_empty()
}
pub(super) fn lifecycle(status: &str) -> bool {
    matches!(
        status,
        "installing"
            | "reinstalling"
            | "updating"
            | "uninstalling"
            | "removing"
            | "queued"
            | "running"
    )
}
pub(super) fn action_matches(expected: &str, actual: &str) -> bool {
    expected == actual || (expected == "uninstall" && actual == "remove")
}
pub(super) fn phase(action: &str) -> &'static str {
    match action {
        "update" => "updating",
        "uninstall" => "uninstalling",
        _ => "installing",
    }
}
pub(super) fn status_label(status: &str) -> &'static str {
    match status {
        "installed" | "running" | "active" | "stopped" => "Installed",
        "installing" | "reinstalling" | "queued" => "Installing",
        "updating" => "Updating",
        "uninstalling" | "removing" => "Uninstalling",
        "failed" | "install_failed" | "error" => "Failed",
        "unconfirmed" => "Outcome unconfirmed",
        _ => "Available",
    }
}
pub(super) fn identity(value: &Value) -> String {
    field(value, &["job_id", "started_at"])
}
pub(super) fn domain(value: &Value) -> &'static str {
    let category = field(value, &["category"]).to_lowercase();
    let id = field(value, &["id"]).to_lowercase();
    if category.contains("arr")
        || matches!(
            id.as_str(),
            "sonarr"
                | "radarr"
                | "bazarr"
                | "lidarr"
                | "readarr"
                | "prowlarr"
                | "recyclarr"
                | "maintainerr"
                | "unpackerr"
        )
    {
        "Arr Stack"
    } else if category.contains("download")
        || category.contains("torrent")
        || category.contains("usenet")
    {
        "Download Clients"
    } else if category.contains("vpn") || category.contains("network") || category.contains("proxy")
    {
        "Network & VPN"
    } else if category.contains("security")
        || category.contains("monitor")
        || category.contains("admin")
    {
        "Monitoring & Security"
    } else if category.contains("storage")
        || category.contains("cloud")
        || category.contains("file")
        || category.contains("backup")
    {
        "Cloud & Storage"
    } else if category.contains("media") || category.contains("iptv") || category.contains("stream")
    {
        "Media & IPTV"
    } else {
        "Productivity & Desktop"
    }
}
pub(super) fn app_url(value: &Value, settings: &Value) -> Option<String> {
    let host = web_sys::window().and_then(|w| w.location().hostname().ok());
    crate::tabs::services::launch_url_with_host(value, settings, host.as_deref())
}

#[component]
pub(super) fn PackageIcon(package: Signal<Value>) -> impl IntoView {
    let context = app();
    let failed = RwSignal::new(false);
    let name = Signal::derive(move || package.with(|p| field(p, &["name", "id"])));
    let src = Signal::derive(move || {
        package.with(|p| {
            let icon = field(p, &["icon", "id"]);
            let icon = icon.trim_start_matches("/img/").trim_end_matches(".png");
            let icon: String = icon
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
                .collect();
            format!("/img/{icon}.png")
        })
    });
    view! {
        <span
            class="w-12 h-12 shrink-0 rounded-xl bg-indigo-500/10 flex items-center justify-center overflow-hidden"
            role="img"
            aria-label=move || tt_with(context, "{name} icon", &[("name", &(name.get()).to_string())])
        >
            <Show
                when=move || !failed.get()
                fallback=move || {
                    view! {
                        <span class="text-indigo-300 font-bold text-lg">
                            {move || name.get().chars().take(2).collect::<String>().to_uppercase()}
                        </span>
                    }
                }
            >
                <img
                    src=move || src.get()
                    alt=""
                    loading="lazy"
                    class="w-10 h-10 object-contain"
                    on:error=move |_| failed.set(true)
                />
            </Show>
        </span>
    }
}
#[component]
pub(super) fn PackageCard(
    id: String,
    rows: Signal<Vec<Value>>,
    ops: MarketplaceOps,
    pending: RwSignal<Option<(Value, String)>>,
    confirm: RwSignal<bool>,
) -> impl IntoView {
    let context = app();
    let id = StoredValue::new(id);
    let package = Signal::derive(move || {
        rows.with(|rows| {
            rows.iter()
                .find(|v| v["id"] == id.get_value())
                .cloned()
                .unwrap_or(Value::Null)
        })
    });
    let job = Signal::derive(move || ops.jobs.with(|jobs| jobs.get(&id.get_value()).cloned()));
    let busy = Signal::derive(move || {
        job.with(|j| j.as_ref().is_some_and(|j| j.active))
            || ops.submitting.with(|set| set.contains(&id.get_value()))
    });
    let status = Signal::derive(move || {
        if let Some(job) = job
            .get()
            .filter(|j| j.active || matches!(j.status.as_str(), "failed" | "unconfirmed"))
        {
            status_label(&job.status).to_string()
        } else {
            package.with(|p| status_label(p["status"].as_str().unwrap_or_default()).to_string())
        }
    });
    let link = Signal::derive(move || {
        package.with(|p| context.settings.with(|settings| app_url(p, settings)))
    });
    let choose = move |action: &'static str| {
        if context.is_admin() && !busy.get_untracked() {
            pending.set(Some((package.get_untracked(), action.into())));
            confirm.set(true);
        }
    };
    view! {
        <article
            class="p-5 min-w-0 flex flex-col gap-4"
            aria-label=move || {
                tt_with(context, "{name} application", &[("name", &(package.with(|p| field(p, &["name", "id"]))).to_string())])
            }
        >
            <div class="flex items-center gap-3">
                <PackageIcon package />
                <div class="min-w-0">
                    <h3 class="font-semibold break-words">
                        {move || package.with(|p| field(p, &["name", "id"]))}
                    </h3>
                    <p class="text-xs text-slate-500 mt-1">{move || package.with(|p| tt(context, domain(p)))}</p>
                </div>
            </div>
            <p class="text-sm text-slate-400 flex-1">
                {move || package.with(|p| tt(context, &field(p, &["desc", "description"])))}
            </p>
            <div class="flex flex-wrap gap-2 items-center">
                {move || {
                    view! {
                        <Badge
                            label=status.get()
                            tone=if busy.get() {
                                "warning"
                            } else if package.with(installed) {
                                "success"
                            } else {
                                "muted"
                            }
                        />
                    }
                }} <Show when=move || package.with(installed)>
                    <span class="text-xs text-slate-400">
                        {move || {
                            package
                                .with(|p| {
                                    let version = field(p, &["installed_version", "version"]);
                                    if version.is_empty() {
                                        tt(context, "Installed")
                                    } else {
                                        tt_with(context, "Installed {version}", &[("version", &(version).to_string())])
                                    }
                                })
                        }}
                    </span>
                    <Show when=move || package.with(|p| p["update_available"] == true)>
                        {move || {
                            package.with(|p| {
                                let latest = field(p, &["latest_version"]);
                                let label = if latest.is_empty() {
                                    tt(context, "Update available")
                                } else {
                                    tt_with(
                                        context,
                                        "Update {version}",
                                        &[("version", &format!("v{}", latest.trim_start_matches(['v', 'V'])))],
                                    )
                                };
                                match crate::tabs::services::safe_release_url(p) {
                                    Some(url) => view! {
                                        <a
                                            href=url
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            title=move || tt(context, "View release notes")
                                            class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30 hover:text-amber-200"
                                        >
                                            {label}
                                        </a>
                                    }
                                    .into_any(),
                                    None => view! {
                                        <Badge
                                            label=Signal::stored(label)
                                            tone="warning"
                                        />
                                    }
                                    .into_any(),
                                }
                            })
                        }}
                    </Show>
                    <Show when=move || package.with(|p| !field(p, &["update_error"]).is_empty())>
                        <span class="text-xs text-rose-300 break-words">
                            {move || package.with(|p| {
                                tt_with(
                                    context,
                                    "Update check failed: {error}",
                                    &[("error", &field(p, &["update_error"]))],
                                )
                            })}
                        </span>
                    </Show>
                </Show>
            </div>
            <Show when=move || !busy.get() && job.with(|j| j.as_ref().is_none_or(|j| !j.active && j.error.is_none())) && package.with(|p| {
                let st = field(&p["last_job"], &["status"]);
                !st.is_empty() && st != "completed"
            })>
                <p role="status" class="text-xs text-rose-300 break-words">
                    {move || package.with(|p| {
                        let last = &p["last_job"];
                        let act = field(last, &["action"]);
                        let st = field(last, &["status"]);
                        let msg = field(last, &["sanitized_summary", "message"]);
                        if msg.is_empty() {
                            tt_with(context, "Last {action}: {status}", &[("action", &tt(context, &act)), ("status", &tt(context, &st))])
                        } else {
                            tt_with(context, "Last {action}: {status} — {message}", &[("action", &tt(context, &act)), ("status", &tt(context, &st)), ("message", &msg)])
                        }
                    })}
                </p>
            </Show>
            <Show when=move || busy.get()>
                <div class="space-y-2">
                    <progress
                        class="w-full h-2 accent-indigo-400"
                        max="100"
                        value=move || job.with(|j| j.as_ref().map(|j| j.progress).unwrap_or(0.0))
                        aria-label=move || tt_with(context, "Installation progress for {name}", &[("name", &(id.get_value()).to_string())])
                    ></progress>
                    <p class="text-xs text-slate-500 break-words">
                        {move || job.with(|j| j.as_ref().and_then(|j| j.logs.last().cloned()))}
                    </p>
                </div>
            </Show>
            <Show when=move || job.with(|j| j.as_ref().is_some_and(|j| j.error.is_some()))>
                <p role="status" class="text-xs text-amber-300 break-words">
                    {move || job.with(|j| j.as_ref().and_then(|j| j.error.as_ref().map(|message| tt(context, message))))}
                </p>
            </Show>
            <div class="flex flex-wrap gap-2 items-center">
                <Show when=move || {
                    context.is_admin()
                        && package
                            .with(|p| {
                                p["inventory_known"] != false
                                    && p["inventory_authenticated"] != false
                            })
                }>
                    <Show when=move || !package.with(installed)>
                        <button
                            type="button"
                            class="glass-button-primary px-4 py-2 min-h-11 text-xs"
                            disabled=move || busy.get()
                            on:click=move |_| {
                                let p = package.get_untracked();
                                if p["config_schema"].is_object()
                                    || p["requires_confirmation"] == true
                                {
                                    choose("install");
                                } else {
                                    ops.start(p, "install");
                                }
                            }
                        >
                            {move || tt(context, "Install")}
                        </button>
                    </Show>
                    <Show when=move || package.with(installed)>
                        <Show when=move || package.with(|p| p["update_available"] == true)>
                            <button
                                type="button"
                                class="glass-button-primary px-3 py-2 min-h-11 text-xs"
                                disabled=move || {
                                    busy.get()
                                        || package
                                            .with(|p| field(p, &["latest_version"]).is_empty())
                                }
                                on:click=move |_| ops.start(package.get_untracked(), "update")
                            >
                                {move || tt(context, "Update")}
                            </button>
                        </Show>
                        <button
                            type="button"
                            class="glass-button px-3 py-2 min-h-11 text-xs"
                            aria-label=move || {
                                tt_with(context, "Check updates for {name}", &[("name", &(package.with(|p| field(p, &["name", "id"]))).to_string())])
                            }
                            disabled=move || {
                                busy.get() || ops.checking.with(|set| set.contains(&id.get_value()))
                            }
                            on:click=move |_| ops.check_updates(Some(package.get_untracked()))
                        >
                            {move || tt(context, if ops.checking.with(|set| set.contains(&id.get_value())) {
                                    "Checking…"
                                } else {
                                    "Check update"
                                })}
                        </button>
                        <button
                            type="button"
                            class="glass-button px-3 py-2 min-h-11 text-xs"
                            disabled=move || busy.get()
                            on:click=move |_| choose("reinstall")
                        >
                            {move || tt(context, "Repair")}
                        </button>
                        <button
                            type="button"
                            class="glass-button px-3 py-2 min-h-11 text-xs text-rose-300"
                            disabled=move || busy.get()
                            on:click=move |_| choose("uninstall")
                        >
                            {move || tt(context, "Remove")}
                        </button>
                    </Show>
                </Show>
                <Show when=move || {
                    package.with(installed)
                }>
                    {move || {
                        link.get()
                            .map(|url| {
                                view! {
                                    <a
                                        class="glass-button px-3 py-2 min-h-11 text-xs inline-flex items-center"
                                        href=url
                                        target="_blank"
                                        rel="noopener noreferrer"
                                    >
                                        {move || tt(context, "Open App")}
                                    </a>
                                }
                            })
                    }}
                    <Show when=move || {
                        context.is_admin()
                            && package.with(crate::tabs::services::external_access_target).is_some()
                    }>
                        <button
                            type="button"
                            class="glass-button px-3 py-2 min-h-11 text-xs inline-flex items-center"
                            title=move || {
                                let name = package.with(|p| field(p, &["name", "id"]));
                                tt_with(context, "Configure external access for {name}", &[("name", &name)])
                            }
                            on:click=move |_| {
                                if let Some(target) = package.with_untracked(crate::tabs::services::external_access_target) {
                                    context.navigate_to_subtab(crate::state::TabId::Network, target);
                                }
                            }
                        >
                            {move || tt(context, "External access")}
                        </button>
                    </Show>
                </Show>
                <Show when=move || job.with(Option::is_some)>
                    <button
                        type="button"
                        class="text-xs text-indigo-300 min-h-11 px-2"
                        on:click=move |_| {
                            ops.deployment.set(Some(id.get_value()));
                            ops.drawer.set(true);
                        }
                    >
                        {move || tt(context, "Deployment logs")}
                    </button>
                </Show>
            </div>
        </article>
    }
}
#[component]
pub(super) fn DeploymentStatus(ops: MarketplaceOps) -> impl IntoView {
    let context = app();
    let job = Signal::derive(move || {
        ops.deployment.with(|id| {
            id.as_ref()
                .and_then(|id| ops.jobs.with(|jobs| jobs.get(id).cloned()))
        })
    });
    view! {
        <section
            data-testid="deployment-status-card"
            aria-label=move || tt(context, "Deployment status")
            class="min-w-0 space-y-4"
        >
            <h3 class="font-semibold break-all">{move || ops.deployment.get()}</h3>
            <p class="text-sm text-slate-400">
                {move || {
                    job.with(|job| {
                        job.as_ref().map(|job| format!("{} · {}", tt(context, &job.action), tt(context, &job.status)))
                    })
                }}
            </p>
            <progress
                class="w-full accent-indigo-400"
                aria-label=move || tt(context, "Deployment completion")
                max="100"
                value=move || job.with(|j| j.as_ref().map(|j| j.progress).unwrap_or(0.0))
            ></progress>
            <div
                class="max-h-[55vh] overflow-auto obs-scroller bg-slate-950 rounded-xl p-4 font-mono text-xs space-y-2"
                role="log"
                aria-label=move || tt(context, "Deployment logs")
                aria-live="polite"
            >
                {move || {
                    job.with(|job| {
                        job.as_ref()
                            .map(|job| {
                                job.logs
                                    .iter()
                                    .map(|line| {
                                        view! {
                                            <p class="text-slate-300 whitespace-pre-wrap break-all">
                                                {line.clone()}
                                            </p>
                                        }
                                    })
                                    .collect_view()
                            })
                    })
                }}
            </div>
            <Show when=move || job.with(|j| j.as_ref().is_some_and(|j| j.error.is_some()))>
                <p class="text-sm text-amber-300" role="status">
                    {move || job.with(|j| j.as_ref().and_then(|j| j.error.as_ref().map(|message| tt(context, message))))}
                </p>
            </Show>
        </section>
    }
}
