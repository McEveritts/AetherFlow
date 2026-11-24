use super::*;

fn update_status_auto_allowed(
    runner_available: Option<bool>,
    has_saved_job: bool,
    explicit_requests: u64,
) -> bool {
    runner_available == Some(true) || has_saved_job || explicit_requests > 0
}

#[cfg(test)]
fn runner_probe_path(is_admin: bool) -> Option<&'static str> {
    is_admin.then_some("/api/v1/admin/network/status")
}

fn runner_probe_path_for_access(is_admin: bool, can_read_network: bool) -> Option<&'static str> {
    (is_admin && can_read_network).then_some("/api/v1/admin/network/status")
}

fn update_status_auto_allowed_for_role(
    is_admin: bool,
    runner_available: Option<bool>,
    has_saved_job: bool,
    explicit_requests: u64,
) -> bool {
    !is_admin || update_status_auto_allowed(runner_available, has_saved_job, explicit_requests)
}

fn update_status_auto_allowed_for_access(
    is_admin: bool,
    is_remote: bool,
    can_read_network: bool,
    can_read_updates: bool,
    runner_available: Option<bool>,
    has_saved_job: bool,
    explicit_requests: u64,
) -> bool {
    if !can_read_updates {
        return false;
    }
    if is_remote && !can_read_network {
        return true;
    }
    update_status_auto_allowed_for_role(
        is_admin,
        runner_available,
        has_saved_job,
        explicit_requests,
    )
}

pub(super) fn update_operation_storage_key(server_id: Option<&str>) -> String {
    match server_id.map(str::trim).filter(|id| !id.is_empty()) {
        Some(id) => format!("af-update-operation:{id}"),
        None => "af-update-operation".to_string(),
    }
}

pub(super) fn update_readiness_endpoint(is_remote: bool) -> &'static str {
    if is_remote {
        "/api/v1/auth/ready"
    } else {
        "/health/ready"
    }
}

pub(super) fn update_status(value: &Value) -> Value {
    let mut normalized = value.clone();
    if let Ok(status) = serde_json::from_value::<SelfUpdateJobStatus>(value.clone()) {
        // Current APIs also report state/operationId. Older runner-shaped
        // responses can be displayed through the same view without losing extras.
        if normalized["state"].is_null() {
            normalized["state"] = json!(match status.status.as_str() {
                "succeeded" if status.completed && status.success => "complete",
                "failed" => "failed",
                "recovery_required" => "interrupted",
                "idle" => "idle",
                _ => "running",
            });
        }
        if normalized["operationId"].is_null() && !status.job_unit.is_empty() {
            normalized["operationId"] = json!(status.job_unit);
        }
    }
    normalized
}

pub(super) async fn api_is_ready_for_server(is_remote: bool) -> bool {
    let deadline = Box::pin(gloo_timers::future::TimeoutFuture::new(8000));
    if is_remote {
        let request = Box::pin(ApiClient.get(update_readiness_endpoint(true)));
        match select(request, deadline).await {
            Either::Left((result, _)) => {
                result.is_ok_and(|value| value["status"] == "ready" && value["database"] == "ok")
            }
            Either::Right(_) => false,
        }
    } else {
        let request =
            Box::pin(ApiClient.public_request(update_readiness_endpoint(false), "GET", None));
        match select(request, deadline).await {
            Either::Left((result, _)) => {
                result.is_ok_and(|value| value["status"] == "ready" && value["database"] == "ok")
            }
            Either::Right(_) => false,
        }
    }
}
#[component]
pub(super) fn SystemUpdates(draft: JsonDraft, settings_busy: RwSignal<bool>) -> impl IntoView {
    let context = app();
    let can_read_updates = Signal::derive(move || context.can_read_area(PeerArea::Updates));
    let check = use_api_when(
        can_read_updates,
        "/api/v1/auth/system/update/check".to_string(),
    );
    let job = RwSignal::new(if context.can_read_area_untracked(PeerArea::Updates) {
        storage_get(&update_operation_storage_key(
            context.active_server_id.get_untracked().as_deref(),
        ))
        .unwrap_or_default()
    } else {
        String::new()
    });
    let runner_probe_data = RwSignal::new(Value::Null);
    let runner_probe_generation = RwSignal::new(0u64);
    Effect::new(move |_| {
        let auth = context.session_epoch.get();
        let server_epoch = context.server_epoch.get();
        let network_grant = context.area_revocation_epoch(PeerArea::Network);
        let path = runner_probe_path_for_access(
            context.is_admin() && can_read_updates.get(),
            context.can_read_area(PeerArea::Network),
        );
        runner_probe_generation.update(|ticket| *ticket += 1);
        let ticket = runner_probe_generation.get_untracked();
        let Some(path) = path else {
            runner_probe_data.set(Value::Null);
            return;
        };
        spawn_local(async move {
            let result = ApiClient.get(path).await;
            if runner_probe_generation.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Network) != network_grant
                || !context.is_admin_untracked()
                || !context.can_read_area_untracked(PeerArea::Network)
                || !context.can_read_area_untracked(PeerArea::Updates)
            {
                return;
            }
            match result {
                Ok(data) => runner_probe_data.set(data),
                Err(_) => runner_probe_data.set(Value::Null),
            }
        });
    });
    let runner_available = Signal::derive(move || {
        crate::tabs::contracts::decode::<crate::tabs::contracts::NetworkStatus>(
            &runner_probe_data.get(),
        )
        .runner_available
    });
    let status = ApiResource {
        data: RwSignal::new(Value::Null),
        loading: RwSignal::new(false),
        error: RwSignal::new(None),
        revision: RwSignal::new(0),
    };
    let generation = RwSignal::new(0u64);
    Effect::new(move |_| {
        let is_admin = context.is_admin();
        let is_remote = context.is_remote();
        let can_read_network = context.can_read_area(PeerArea::Network);
        let can_read_updates_now = can_read_updates.get();
        let updates_grant = context.area_revocation_epoch(PeerArea::Updates);
        let available = runner_available.get();
        let unit = job.get();
        let requests = status.revision.get();
        let auth = context.session_epoch.get();
        let server_epoch = context.server_epoch.get();
        generation.update(|ticket| *ticket += 1);
        let ticket = generation.get_untracked();
        if !can_read_updates_now {
            status.data.set(Value::Null);
            status.loading.set(false);
            status.error.set(None);
            return;
        }
        if !update_status_auto_allowed_for_access(
            is_admin,
            is_remote,
            can_read_network,
            can_read_updates_now,
            available,
            !unit.is_empty(),
            requests,
        ) {
            status.loading.set(false);
            status.error.set(None);
            return;
        }
        status.loading.set(true);
        let path = if unit.is_empty() {
            "/api/v1/auth/system/update/status".to_string()
        } else {
            format!(
                "/api/v1/auth/system/update/status?job_unit={}",
                encode(&unit)
            )
        };
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(status.loading, generation, ticket);
        spawn_local(async move {
            let result = ApiClient.get(&path).await;
            if generation.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Updates) != updates_grant
                || !context.is_admin_untracked()
                || !context.can_read_area_untracked(PeerArea::Updates)
            {
                return;
            }
            match result {
                Ok(data) => {
                    status.data.set(data);
                    status.error.set(None);
                }
                Err(error) => status.error.set(Some(error)),
            }
            busy_guard.release();
        });
    });
    let status_value = Signal::derive(move || update_status(&status.data.get()));
    let confirm = RwSignal::new(false);
    let launching = RwSignal::new(false);
    let uncertain = RwSignal::new(false);
    let previous = RwSignal::new(String::new());
    let launch_at = RwSignal::new(0.0);
    let last_check = RwSignal::new(0.0);
    let last_status = RwSignal::new(0.0);
    let last_retry = RwSignal::new(js_sys::Date::now());
    let clock = RwSignal::new(js_sys::Date::now());
    let ready = RwSignal::new(false);
    let ready_busy = RwSignal::new(false);
    let observed_terminal = RwSignal::new(String::new());
    let tick = StoredValue::new_local(None::<gloo_timers::callback::Interval>);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Updates);
        let allowed = can_read_updates.get();
        let key = update_operation_storage_key(context.active_server_id.get_untracked().as_deref());
        job.set(if allowed {
            storage_get(&key).unwrap_or_default()
        } else {
            String::new()
        });
        status.data.set(Value::Null);
        status.error.set(None);
        status.loading.set(false);
        confirm.set(false);
        launching.set(false);
        uncertain.set(false);
        previous.set(String::new());
        last_check.set(0.0);
        last_status.set(0.0);
        ready.set(false);
        ready_busy.set(false);
        observed_terminal.set(String::new());
        tick.set_value(None);
    });
    Effect::new(move |_| {
        let active = can_read_updates.get()
            && (launching.get()
                || uncertain.get()
                || status_value
                    .with(|value| matches!(value["state"].as_str(), Some("running" | "queued"))));
        if !active {
            tick.set_value(None);
            return;
        }
        if tick.with_value(Option::is_some) {
            return;
        }
        tick.set_value(Some(gloo_timers::callback::Interval::new(
            2_000,
            move || {
                if !context.can_read_area_untracked(PeerArea::Updates) {
                    return;
                }
                let now = js_sys::Date::now();
                clock.set(now);
                if !status.loading.get_untracked() || now - last_retry.get_untracked() > 10_000.0 {
                    last_retry.set(now);
                    status.refresh();
                }
                if !ready_busy.get_untracked() {
                    let server_epoch = context.server_epoch.get_untracked();
                    let updates_grant = context.area_revocation_epoch_untracked(PeerArea::Updates);
                    let is_remote = context.is_remote_untracked();
                    ready_busy.set(true);
                    let mut busy_guard = crate::tabs::busy::BusyGuard::new(ready_busy);
                    spawn_local(async move {
                        let result = api_is_ready_for_server(is_remote).await;
                        if ready.try_get_untracked().is_some()
                            && context.server_epoch.try_get_untracked() == Some(server_epoch)
                            && context.area_revocation_epoch_untracked(PeerArea::Updates)
                                == updates_grant
                            && context.can_read_area_untracked(PeerArea::Updates)
                        {
                            ready.set(result);
                        }
                        if ready_busy.try_get_untracked().is_some() {
                            busy_guard.release();
                        }
                    });
                }
            },
        )));
    });
    on_cleanup(move || tick.set_value(None));
    Effect::new(move |_| {
        let value = check.data.get();
        if value.is_object() && check.error.get().is_none() {
            last_check.set(js_sys::Date::now());
        }
    });
    Effect::new(move |_| {
        let value = status_value.get();
        if value.is_object() && status.error.get().is_none() {
            let storage_key =
                update_operation_storage_key(context.active_server_id.get_untracked().as_deref());
            last_status.set(js_sys::Date::now());
            last_retry.set(js_sys::Date::now());
            let operation = text(&value, "operationId");
            clock.set(js_sys::Date::now());
            if matches!(value["state"].as_str(), Some("running" | "queued")) {
                launching.set(true);
            }
            if value["state"] == "running"
                && job.get_untracked().is_empty()
                && !operation.is_empty()
            {
                job.set(operation.clone());
                storage_set(&storage_key, &operation);
            }
            if uncertain.get_untracked()
                && !operation.is_empty()
                && operation != previous.get_untracked()
            {
                job.set(operation.clone());
                storage_set(&storage_key, &operation);
                uncertain.set(false);
            }
        }
    });
    Effect::new(move |_| {
        let value = status_value.get();
        let unit = job.get();
        if !unit.is_empty()
            && (launching.get() || uncertain.get())
            && text(&value, "operationId") == unit
            && matches!(
                value["state"].as_str(),
                Some("complete" | "failed" | "interrupted")
            )
            && observed_terminal.get_untracked() != unit
            && status.error.get().is_none()
            && clock.get() - last_status.get() < 15_000.0
            && (value["state"] != "complete" || ready.get())
        {
            observed_terminal.set(unit);
            launching.set(false);
            uncertain.set(false);
            if value["state"] == "complete" {
                check.refresh();
                context.toast(
                    tt(
                        context,
                        "Update receipt confirmed and API readiness restored",
                    ),
                    false,
                );
                if !context.is_remote_untracked() {
                    context.refresh_session();
                }
            } else {
                context.toast(
                    tt(
                        context,
                        value["error"]
                            .as_str()
                            .unwrap_or("Update failed; inspect updater logs"),
                    ),
                    true,
                );
            }
        }
    });
    let can_launch = Signal::derive(move || {
        let value = status_value.get();
        let release = check.data.get();
        let now = js_sys::Date::now();
        context.is_admin()
            && context.can_write_area(crate::state::PeerArea::Updates)
            && !launching.get()
            && !uncertain.get()
            && !settings_busy.get()
            && status.error.get().is_none()
            && check.error.get().is_none()
            && now - last_status.get() < 15_000.0
            && now - last_check.get() < 90_000.0
            && matches!(
                value["state"].as_str(),
                Some("idle" | "failed" | "complete")
            )
            && release["updateAvailable"] == true
            && release["error"].as_str().unwrap_or("").is_empty()
            && !text(&release, "currentVersion").is_empty()
            && !text(&release, "latestVersion").is_empty()
            && release["currentVersion"] != release["latestVersion"]
            && draft.with(|d| {
                d.value().ok().is_some_and(|v| {
                    v["updateChannel"] == d.baseline()["updateChannel"]
                        && (release["channel"].is_null()
                            || release["channel"] == d.baseline()["updateChannel"])
                })
            })
    });
    let launch = Callback::new(move |()| {
        if !can_launch.get_untracked() {
            return;
        }
        let session_epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let updates_grant = context.area_revocation_epoch_untracked(PeerArea::Updates);
        let storage_key =
            update_operation_storage_key(context.active_server_id.get_untracked().as_deref());
        launching.set(true);
        uncertain.set(true);
        previous.set(status_value.with_untracked(|v| text(v, "operationId")));
        // An uncertain launch must observe the global journal, not a prior
        // completed receipt left over from an earlier update.
        job.set(String::new());
        storage_set(&storage_key, "");
        launch_at.set(js_sys::Date::now());
        ready.set(false);
        spawn_local(async move {
            let result = ApiClient
                .post("/api/v1/admin/system/update/run", None)
                .await;
            if launching.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Updates) != updates_grant
                || !context.is_admin_untracked()
                || !context.can_read_area_untracked(PeerArea::Updates)
            {
                return;
            }
            match result {
                Ok(value) => {
                    let unit = text(&value, "job_unit");
                    if unit.starts_with("aetherflow-self-update-deploy-") {
                        job.set(unit.clone());
                        storage_set(&storage_key, &unit);
                        uncertain.set(false);
                        confirm.set(false);
                        context.toast(
                            tt(
                                context,
                                value["message"].as_str().unwrap_or("Update accepted"),
                            ),
                            false,
                        );
                    } else {
                        context.toast(tt(context, "Update response had no verifiable receipt. Reconnecting to determine its outcome."),true);
                    }
                }
                Err(error) => {
                    if error.status != 0 && error.status < 500 {
                        launching.set(false);
                        uncertain.set(false);
                    }
                    context.toast(tt(context, &error.message), true);
                }
            }
            status.refresh();
        });
    });
    view! {
        <ObsCard>
            <h2 class="text-lg font-semibold mb-4">
                {move || tt(context, "Settings.systemUpdates")}
            </h2>
            <Show when=move || !can_read_updates.get()>
                <p role="status" class="text-xs text-amber-300 mb-4">
                    {move || {
                        context
                            .area_block_reason(PeerArea::Updates, false)
                            .unwrap_or_default()
                    }}
                </p>
            </Show>
            <div class="grid sm:grid-cols-2 gap-5">
                <div class="space-y-2 text-sm">
                    <p>
                        {move || {
                            check
                                .data
                                .with(|v| {
                                    tt_with(context, "Current version: {current} · Latest: {latest}", &[("current", &(text(v, "currentVersion")).to_string()), ("latest", &(text(v, "latestVersion")).to_string())])
                                })
                        }}
                    </p>
                    <p class="text-slate-400">
                        {move || {
                            check
                                .data
                                .with(|v| {
                                    tt_with(context, "Commit: {commit}", &[("commit", &(v["currentCommit"]
                                            .as_str()
                                            .or_else(|| v["commit"].as_str())
                                            .map(|value| value.to_string()).unwrap_or_else(|| tt(context, "Not reported"))).to_string())])
                                })
                        }}
                    </p>
                    <p class="text-slate-400 break-all">
                        {move || {
                            status_value
                                .with(|v| {
                                    tt_with(context, "State: {state} · Phase: {phase} · Receipt: {receipt}", &[("state", &(tt(context, &(text(v, "state")).to_string())).to_string()), ("phase", &(tt(context, &(text(v, "phase")).to_string())).to_string()), ("receipt", &(text(v, "operationId")).to_string())])
                                })
                        }}
                    </p>
                    <Show when=move || {
                        status_value.with(|v| v["state"] == "running") || launching.get()
                            || uncertain.get()
                    }>
                        <p role="status" class="text-cyan-300">
                            {move || tt(
                                context,
                                "Update in progress. Reconnecting automatically while aetherflow-api restarts.",
                            )}
                        </p>
                    </Show>
                    <Show when=move || {
                        uncertain.get() && clock.get() - launch_at.get() > 180_000.0
                    }>
                        <p role="alert" class="text-amber-300">
                            {move || tt(
                                context,
                                "The launch outcome remains unverified. Inspect updater logs before retrying.",
                            )}
                        </p>
                    </Show>
                    <p role="status" class="text-slate-400 whitespace-pre-wrap">
                        {move || check.data.with(|v| text(v, "message"))}
                    </p>
                    {move || check.data.with(|v| {
                        let url = text(v, "url");
                        url.starts_with("https://github.com/McEveritts/AetherFlow/").then(|| view! {
                            <a class="underline" href=url target="_blank" rel="noopener noreferrer">{move || tt(context, "View release on GitHub")}</a>
                        })
                    })}
                    <Show when=move || {
                        !check.loading.get() && check.error.get().is_none()
                            && check.data.with(|v| v["updateAvailable"] == true)
                    }>
                        <p role="status" class="text-indigo-300">
                            {move || tt(context, "Settings.updateAvailable")}
                        </p>
                    </Show>
                    <Show when=move || {
                        !check.loading.get() && check.error.get().is_none()
                            && check.data.with(|v| v["updateAvailable"] == false)
                    }>
                        <p role="status" class="text-slate-400">
                            {move || tt(context, "Settings.upToDate")}
                        </p>
                    </Show>
                    <p role="alert" class="text-rose-300">
                        {move || status_value.with(|v| text(v, "error"))}
                    </p>
                </div>
                <div class="space-y-4">
                    <DraftSelect
                        draft
                        field="updateChannel"
                        label="Release channel"
                        options=vec![("stable", "Stable"), ("nightly", "Nightly")]
                    />
                    <p class="text-xs text-slate-400">
                        {move || tt(
                            context,
                            "Save the release channel in Settings before checking or applying an update.",
                        )}
                    </p>
                    <div class="flex flex-wrap gap-3">
                        <button
                            type="button"
                            class="glass-button px-4 py-2"
                            disabled=move || {
                                check.loading.get()
                                    || !context.can_read_area(crate::state::PeerArea::Updates)
                            }
                            title=move || {
                                context
                                    .area_block_reason(crate::state::PeerArea::Updates, false)
                                    .unwrap_or_default()
                            }
                            on:click=move |_| {
                                if context.can_read_area_untracked(PeerArea::Updates) {
                                    check.refresh();
                                    status.refresh();
                                }
                            }
                        >
                            {move || {
                                if check.loading.get() {
                                    tt(context, "Settings.checkingUpdates")
                                } else {
                                    tt(context, "Check for Updates")
                                }
                            }}
                        </button>
                        <button
                            type="button"
                            class="glass-button-primary px-4 py-2"
                            disabled=move || !can_launch.get()
                            title=move || {
                                context
                                    .area_block_reason(crate::state::PeerArea::Updates, true)
                                    .unwrap_or_default()
                            }
                            on:click=move |_| confirm.set(true)
                        >
                            {move || tt(context, "Apply Self-Update")}
                        </button>
                    </div>
                    <p class="text-xs text-slate-400">
                        {move || tt(
                            context,
                            "Rollback is managed by the host updater; this server does not expose a rollback API.",
                        )}
                    </p>
                </div>
            </div>
            <Show when=move || {
                runner_available.get() == Some(false)
                    || check.error.get().is_some_and(|error| error.status == 503)
                    || status.error.get().is_some_and(|error| error.status == 503)
            }>
                <p role="status" class="text-sm text-slate-400 mt-3">
                    {move || tt(context, "Runner daemon offline / idle")}
                </p>
            </Show>
            <Show when=move || !check.error.get().is_some_and(|error| error.status == 503)>
                <ResourceFeedback resource=check />
            </Show>
            <Show when=move || !status.error.get().is_some_and(|error| error.status == 503)>
                <ResourceFeedback resource=status />
            </Show>
            <ConfirmDialog
                open=confirm
                title="Apply system update?"
                message="The API and runner may restart. Keep this view open to verify the operation receipt and readiness."
                busy=launching
                on_confirm=launch
            />
        </ObsCard>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_status_only_runs_for_capability_receipts_or_explicit_checks() {
        for (available, saved, requests, expected) in [
            (None, false, 0, false),
            (Some(false), false, 0, false),
            (Some(true), false, 0, true),
            (None, true, 0, true),
            (Some(false), true, 0, true),
            (None, false, 1, true),
            (Some(false), false, 1, true),
            (Some(false), true, u64::MAX, true),
        ] {
            assert_eq!(
                update_status_auto_allowed(available, saved, requests),
                expected,
                "runner={available:?}, saved={saved}, requests={requests}"
            );
        }
    }

    #[test]
    fn non_admin_never_probes_admin_network_status_and_allows_update_status() {
        assert_eq!(
            runner_probe_path(true),
            Some("/api/v1/admin/network/status")
        );
        assert_eq!(runner_probe_path(false), None);
        assert!(update_status_auto_allowed_for_role(false, None, false, 0));
        assert!(!update_status_auto_allowed_for_role(true, None, false, 0));
        assert!(!update_status_auto_allowed_for_role(
            true,
            Some(false),
            false,
            0
        ));
        assert!(update_status_auto_allowed_for_role(
            true,
            Some(true),
            false,
            0
        ));
    }

    #[test]
    fn remote_updates_use_authenticated_ready_endpoint_and_server_scoped_storage_key() {
        assert_eq!(update_readiness_endpoint(false), "/health/ready");
        assert_eq!(update_readiness_endpoint(true), "/api/v1/auth/ready");
        assert_eq!(update_operation_storage_key(None), "af-update-operation");
        assert_eq!(
            update_operation_storage_key(Some("media-2")),
            "af-update-operation:media-2"
        );
        assert_eq!(runner_probe_path_for_access(true, false), None);
        assert!(update_status_auto_allowed_for_access(
            true, true, false, true, None, false, 0
        ));
        assert!(!update_status_auto_allowed_for_access(
            true, true, false, false, None, false, 0
        ));
    }
}
