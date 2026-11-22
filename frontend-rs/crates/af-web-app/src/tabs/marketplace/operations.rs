use super::*;

#[derive(Clone, Debug)]
pub(super) struct PackageJob {
    pub(super) action: String,
    pub(super) status: String,
    pub(super) progress: f64,
    pub(super) job_id: String,
    pub(super) started_at: String,
    pub(super) baseline: String,
    pub(super) observed: bool,
    pub(super) accepted: bool,
    pub(super) active: bool,
    pub(super) ticket: u64,
    pub(super) logs: Vec<String>,
    pub(super) error: Option<String>,
    pub(super) expected_version: String,
    pub(super) was_installed: bool,
}
impl PackageJob {
    pub(super) fn new(action: &str, ticket: u64, package: &Value) -> Self {
        Self {
            action: action.into(),
            status: phase(action).into(),
            progress: 0.0,
            job_id: String::new(),
            started_at: String::new(),
            baseline: identity(&package["last_job"]),
            observed: false,
            accepted: false,
            active: true,
            ticket,
            logs: Vec::new(),
            error: None,
            expected_version: field(package, &["latest_version"]),
            was_installed: installed(package),
        }
    }
    pub(super) fn push_log(&mut self, line: String) {
        if !line.is_empty() && self.logs.last() != Some(&line) {
            self.logs.push(line);
            if self.logs.len() > 400 {
                self.logs.remove(0);
            }
        }
    }
    pub(super) fn observe(&mut self, payload: &Value) -> bool {
        if !self.active || !self.accepted {
            return false;
        }
        let payload = lifecycle_payload(payload);
        let payload = &payload;
        let actual_action = field(payload, &["action"]);
        if !actual_action.is_empty() && !action_matches(&self.action, &actual_action) {
            return false;
        }
        let actual_id = field(payload, &["job_id"]);
        let actual_start = field(payload, &["started_at"]);
        if (!self.job_id.is_empty() && self.job_id != actual_id)
            || (self.job_id.is_empty()
                && !self.started_at.is_empty()
                && self.started_at != actual_start)
        {
            return false;
        }
        if self.job_id.is_empty() && self.started_at.is_empty() {
            let incoming = identity(payload);
            if !incoming.is_empty() {
                if incoming == self.baseline {
                    return false;
                }
                self.job_id = actual_id;
                self.started_at = actual_start;
            }
        }
        let status = field(payload, &["status"]);
        if status == "idle" || status.is_empty() {
            return false;
        }
        let has_identity = !self.job_id.is_empty() || !self.started_at.is_empty();
        if lifecycle(&status) {
            self.observed = true;
            self.status = phase(&self.action).into();
        } else if matches!(
            status.as_str(),
            "completed" | "failed" | "unconfirmed" | "cancelled" | "interrupted"
        ) {
            // Identity-free legacy receipts are trusted only after observing the active operation.
            if !has_identity && !self.observed {
                return false;
            }
            self.active = false;
            self.status = status.clone();
            if status == "completed" {
                self.progress = 100.0;
            }
            if status != "completed" {
                self.error = Some(field(payload, &["message", "last_line", "error"]));
            }
            if status == "completed" && self.action == "update" {
                let outcome = payload
                    .get("last_job")
                    .filter(|v| v.is_object())
                    .unwrap_or(payload);
                let achieved = field(outcome, &["achieved_version"]);
                let expected = field(outcome, &["expected_target_version"]);
                if outcome["target_unconfirmed"] == true
                    || outcome["target_mismatch"] == true
                    || (!self.expected_version.is_empty()
                        && (achieved.is_empty() || expected.is_empty()))
                {
                    self.status = "unconfirmed".into();
                    self.error = Some(
                        "The update finished, but its target version could not be confirmed."
                            .into(),
                    );
                }
            }
        } else {
            return false;
        }
        if let Some(progress) = payload["progress"].as_f64().filter(|n| n.is_finite()) {
            self.progress = progress.clamp(0.0, 100.0);
        }
        if self.active {
            self.error = None;
        }
        self.push_log(field(payload, &["last_line", "log_line", "message"]));
        true
    }
}

#[derive(Clone, Copy)]
pub(super) struct MarketplaceOps {
    pub(super) context: AppContext,
    pub(super) catalog: ApiResource,
    pub(super) jobs: RwSignal<BTreeMap<String, PackageJob>>,
    pub(super) submitting: RwSignal<BTreeSet<String>>,
    pub(super) checking: RwSignal<BTreeSet<String>>,
    pub(super) ticket: RwSignal<u64>,
    pub(super) polling: RwSignal<bool>,
    pub(super) deployment: RwSignal<Option<String>>,
    pub(super) drawer: RwSignal<bool>,
}
impl MarketplaceOps {
    pub(super) fn start(self, package: Value, action: &'static str) {
        self.start_with_purge(package, action, false);
    }
    pub(super) fn start_with_purge(self, package: Value, action: &'static str, purge: bool) {
        let context = self.context;
        let id = field(&package, &["id"]);
        let was_installed = installed(&package);
        let retained_purge_blocked = action == "uninstall"
            && !was_installed
            && !(purge && can_purge_retained_data(&package));
        if !context.is_admin()
            || id.is_empty()
            || package["inventory_authenticated"] == false
            || package["inventory_known"] == false
            || (action == "install" && retired_uninstalled(&package))
            || retained_purge_blocked
            || self.submitting.with_untracked(|set| set.contains(&id))
            || self
                .jobs
                .with_untracked(|jobs| jobs.get(&id).is_some_and(|job| job.active))
        {
            return;
        }
        self.ticket.update(|n| *n += 1);
        let ticket = self.ticket.get_untracked();
        self.submitting.update(|set| {
            set.insert(id.clone());
        });
        self.jobs.update(|jobs| {
            jobs.insert(id.clone(), PackageJob::new(action, ticket, &package));
        });
        spawn_local(async move {
            let target = field(&package, &["latest_version"]);
            let body = (action == "update" && !target.is_empty())
                .then(|| json!({"expected_target_version":target}));
            let result = ApiClient
                .post(
                    &lifecycle_path(
                        &js_sys::encode_uri_component(&id)
                            .as_string()
                            .unwrap_or_default(),
                        action,
                        purge,
                    ),
                    body.as_ref(),
                )
                .await;
            if self.jobs.is_disposed() {
                return;
            }
            self.submitting.update(|set| {
                set.remove(&id);
            });
            match result {
                Ok(receipt) => {
                    self.jobs.update(|jobs| {
                        if let Some(job) = jobs.get_mut(&id).filter(|j| j.ticket == ticket) {
                            job.accepted = true;
                            job.job_id = field(&receipt, &["job_id"]);
                            job.started_at = field(&receipt, &["started_at"]);
                            job.push_log(field(&receipt, &["message"]));
                        }
                    });
                    let message = match action {
                        "install" => tt_with(
                            context,
                            "Installation started for {id}",
                            &[("id", &(id).to_string())],
                        ),
                        "reinstall" => tt_with(
                            context,
                            "Repair started for {id}",
                            &[("id", &(id).to_string())],
                        ),
                        "update" => tt_with(
                            context,
                            "Update started for {id}",
                            &[("id", &(id).to_string())],
                        ),
                        _ if purge && !was_installed => tt_with(
                            context,
                            "Data purge started for {id}",
                            &[("id", &(id).to_string())],
                        ),
                        _ => tt_with(
                            context,
                            "Uninstall started for {id}",
                            &[("id", &(id).to_string())],
                        ),
                    };
                    context.toast(tt(context, &message), false);
                    self.catalog.refresh();
                    self.poll();
                }
                Err(error) => {
                    self.jobs.update(|jobs| {
                        if let Some(job) = jobs.get_mut(&id).filter(|j| j.ticket == ticket) {
                            job.active = false;
                            job.status = "failed".into();
                            job.error = Some(error.message.clone());
                        }
                    });
                    context.toast(tt(context, &error.message), true);
                    self.catalog.refresh();
                }
            }
        });
    }
    pub(super) fn check_updates(self, package: Option<Value>) {
        if !self.context.is_admin() {
            return;
        }
        let id = package.as_ref().map(|p| field(p, &["id"]));
        if id.as_ref().is_some_and(String::is_empty) {
            return;
        }
        let key = id.clone().unwrap_or_default();
        if self.checking.with_untracked(|set| set.contains(&key)) {
            return;
        }
        self.checking.update(|set| {
            set.insert(key.clone());
        });
        spawn_local(async move {
            let path = match &id {
                Some(id) => format!(
                    "/api/v1/admin/packages/{}/check-update",
                    js_sys::encode_uri_component(id)
                ),
                None => "/api/v1/admin/packages/updates/check".into(),
            };
            let result = ApiClient.post(&path, None).await;
            if self.checking.is_disposed() {
                return;
            }
            self.checking.update(|set| {
                set.remove(&key);
            });
            match result {
                Ok(_) => self.context.toast(
                    match id {
                        Some(id) => tt_with(
                            self.context,
                            "Update check completed for {id}",
                            &[("id", &(id).to_string())],
                        ),
                        None => tt(self.context, "Catalog update check completed"),
                    },
                    false,
                ),
                Err(error) => self.context.toast(tt(self.context, &error.message), true),
            }
            self.catalog.refresh();
        });
    }
    pub(super) fn poll(self) {
        let context = self.context;
        if self.polling.get_untracked() {
            return;
        }
        let jobs = self.jobs.with_untracked(|jobs| {
            jobs.iter()
                .filter(|(_, j)| j.active && j.accepted)
                .map(|(id, j)| (id.clone(), j.ticket, j.job_id.clone()))
                .collect::<Vec<_>>()
        });
        if jobs.is_empty() {
            return;
        }
        self.polling.set(true);
        spawn_local(async move {
            let mut changed = false;
            for (id, ticket, job_id) in jobs {
                let mut url = format!(
                    "/api/v1/auth/packages/{}/progress",
                    js_sys::encode_uri_component(&id)
                );
                if !job_id.is_empty() {
                    url.push_str(&format!(
                        "?job_id={}",
                        js_sys::encode_uri_component(&job_id)
                    ));
                }
                let result = match ApiClient.get(&url).await {
                    Err(error)
                        if !job_id.is_empty()
                            && error.status == 404
                            && error.code.as_deref() == Some("PACKAGE_JOB_NOT_FOUND") =>
                    {
                        Ok(json!({
                            "job_id": job_id,
                            "status": "unconfirmed",
                            "message": error.message,
                        }))
                    }
                    other => other,
                };
                if self.jobs.is_disposed() {
                    return;
                }
                match result {
                    Ok(payload) => {
                        let mut finished = None;
                        self.jobs.update(|jobs| {
                            if let Some(job) = jobs
                                .get_mut(&id)
                                .filter(|job| job.ticket == ticket && job.active)
                            {
                                if job.observe(&payload) && !job.active {
                                    finished = Some((job.status.clone(), job.error.clone()));
                                }
                            }
                        });
                        if let Some((status, error)) = finished {
                            changed = true;
                            context.toast(
                                if status == "completed" {
                                    tt_with(
                                        context,
                                        "Operation completed for {id}",
                                        &[("id", &(id).to_string())],
                                    )
                                } else {
                                    error.map(|message| tt(context, &message)).unwrap_or_else(
                                        || {
                                            tt_with(
                                                context,
                                                "Operation {status} for {id}",
                                                &[
                                                    (
                                                        "status",
                                                        &(tt(context, &(status).to_string()))
                                                            .to_string(),
                                                    ),
                                                    ("id", &(id).to_string()),
                                                ],
                                            )
                                        },
                                    )
                                },
                                status != "completed",
                            );
                        }
                    }
                    Err(error) => self.jobs.update(|jobs| {
                        if let Some(job) = jobs.get_mut(&id).filter(|job| job.ticket == ticket) {
                            job.error = Some(tt_with(
                                context,
                                "Progress unavailable: {error}. Retrying…",
                                &[("error", &(error.message).to_string())],
                            ));
                        }
                    }),
                }
            }
            if self.polling.is_disposed() {
                return;
            }
            self.polling.set(false);
            if changed {
                self.catalog.refresh();
                context.marketplace_revision.update(|r| *r += 1);
            }
        });
    }
}
