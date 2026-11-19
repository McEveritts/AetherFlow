mod upload;

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TransferStatus {
    Queued,
    Preparing,
    Uploading,
    Paused,
    Completed,
    Failed,
    Uncertain,
    Cancelled,
    Cancelling,
}
impl TransferStatus {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Preparing => "Preparing",
            Self::Uploading => "Uploading",
            Self::Paused => "Paused",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
            Self::Uncertain => "Check server state",
            Self::Cancelled => "Cancelled",
            Self::Cancelling => "Cancelling",
        }
    }
    pub(super) fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}
#[derive(Clone)]
pub(super) struct TransferRow {
    pub(super) id: u64,
    pub(super) path: String,
    pub(super) size: u64,
    pub(super) sent: u64,
    pub(super) rate: f64,
    pub(super) status: TransferStatus,
    pub(super) message: String,
}
pub(super) struct UploadJob {
    pub(super) epoch: u64,
    pub(super) file: web_sys::File,
    pub(super) row: TransferRow,
    pub(super) session: String,
    pub(super) fingerprint: String,
    pub(super) running: bool,
    pub(super) pause: bool,
    pub(super) cancel: bool,
    pub(super) abort: Option<web_sys::AbortController>,
    pub(super) conflict: String,
}
impl UploadJob {
    fn abort_request(&mut self) {
        if let Some(controller) = self.abort.take() {
            controller.abort();
        }
    }
}
pub(super) struct QueueInner {
    pub(super) epoch: u64,
    pub(super) jobs: Vec<Rc<RefCell<UploadJob>>>,
    pub(super) next_id: u64,
    pub(super) disposed: bool,
}
#[derive(Clone, Copy)]
pub(super) struct TransferQueue {
    pub(super) inner: StoredValue<QueueInner, LocalStorage>,
    pub(super) rows: RwSignal<Vec<TransferRow>>,
    pub(super) context: AppContext,
    pub(super) on_change: Callback<()>,
    pub(super) open: RwSignal<bool>,
}
pub(super) enum TransferEnd {
    Completed,
    Paused,
    Cancelled,
}
impl TransferQueue {
    pub(super) fn new(on_change: Callback<()>) -> Self {
        let context = app();
        let queue = Self {
            inner: StoredValue::new_local(QueueInner {
                epoch: context.session_epoch.get_untracked(),
                jobs: vec![],
                next_id: 1,
                disposed: false,
            }),
            rows: RwSignal::new(vec![]),
            context,
            on_change,
            open: RwSignal::new(false),
        };
        Effect::new(move |_| {
            let epoch = context.session_epoch.get();
            if queue.inner.with_value(|inner| inner.epoch != epoch) {
                queue.clear();
                queue.inner.update_value(|inner| inner.epoch = epoch);
            }
            queue.publish();
        });
        on_cleanup(move || {
            queue.clear();
            queue.inner.try_update_value(|inner| inner.disposed = true);
        });
        queue
    }
    pub(super) fn current(self) -> bool {
        self.inner
            .try_with_value(|inner| {
                !inner.disposed
                    && self.context.session_epoch.try_get_untracked() == Some(inner.epoch)
            })
            .unwrap_or(false)
    }
    fn job_current(self, job: &Rc<RefCell<UploadJob>>) -> bool {
        let current = self
            .inner
            .try_with_value(|inner| !inner.disposed)
            .unwrap_or(false)
            && self.context.session_epoch.try_get_untracked() == Some(job.borrow().epoch);
        if !current {
            Self::cancel_stale(job);
        }
        current
    }
    fn cancel_stale(job: &Rc<RefCell<UploadJob>>) {
        let mut job = job.borrow_mut();
        job.abort_request();
        job.running = false;
        job.cancel = true;
        job.row.status = TransferStatus::Cancelled;
        job.row.message.clear();
    }
    pub(super) fn job(self, id: u64) -> Option<Rc<RefCell<UploadJob>>> {
        self.inner
            .try_with_value(|inner| {
                inner
                    .jobs
                    .iter()
                    .find(|job| job.borrow().row.id == id)
                    .cloned()
            })
            .flatten()
    }
    pub(super) fn clear(self) {
        self.inner.try_update_value(|inner| {
            for job in &inner.jobs {
                Self::cancel_stale(job);
            }
            inner.jobs.clear();
        });
    }
    fn request_signal(
        self,
        job: &Rc<RefCell<UploadJob>>,
    ) -> Result<web_sys::AbortSignal, ApiError> {
        if !self.job_current(job) {
            return Err(error("Session ended"));
        }
        let controller = web_sys::AbortController::new().map_err(js_error)?;
        let signal = controller.signal();
        let mut job = job.borrow_mut();
        job.abort_request();
        job.abort = Some(controller);
        Ok(signal)
    }
    pub(super) fn publish(self) {
        if !self
            .inner
            .try_with_value(|inner| !inner.disposed)
            .unwrap_or(false)
        {
            return;
        }
        let epoch = self.context.session_epoch.try_get_untracked();
        let rows: Vec<TransferRow> = self.inner.with_value(|inner| {
            inner
                .jobs
                .iter()
                .map(|job| {
                    if epoch != Some(job.borrow().epoch) && !job.borrow().row.status.terminal() {
                        Self::cancel_stale(job);
                    }
                    job.borrow().row.clone()
                })
                .collect()
        });
        let summaries = rows
            .iter()
            .map(|row| crate::state::TransferSummary {
                id: row.id,
                path: leaf(&row.path).to_owned(),
                sent: row.sent,
                size: row.size,
                status: row.status.label().to_owned(),
                active: !row.status.terminal(),
            })
            .collect();
        self.rows.set(rows);
        let _ = self.context.transfers.try_set(summaries);
    }
    pub(super) fn add(self, files: web_sys::FileList, directory: &str, conflict: &str) {
        let Some(epoch) = self.context.session_epoch.try_get_untracked() else {
            return;
        };
        let ready = self.inner.try_update_value(|inner| {
            if inner.disposed {
                return false;
            }
            if inner.epoch != epoch {
                for job in &inner.jobs {
                    Self::cancel_stale(job);
                }
                inner.jobs.clear();
                inner.epoch = epoch;
            }
            true
        });
        if ready != Some(true) {
            return;
        }
        for index in 0..files.length() {
            let Some(file) = files.item(index) else {
                continue;
            };
            let path = match name_path(directory, &file.name()) {
                Ok(path) => path,
                Err(message) => {
                    self.context.toast(tt(self.context, &message), true);
                    continue;
                }
            };
            let size = file.size() as u64;
            if size > MAX_UPLOAD_BYTES {
                self.context.toast(
                    tt_with(
                        self.context,
                        "{name} exceeds the 64 GiB upload limit",
                        &[("name", &(file.name()).to_string())],
                    ),
                    true,
                );
                continue;
            }
            self.inner.update_value(|inner| {
                if inner.jobs.len() >= 1000 {
                    self.context.toast(
                        tt(
                            self.context,
                            "The transfer queue is full. Clear finished transfers first.",
                        ),
                        true,
                    );
                    return;
                }
                let id = inner.next_id;
                inner.next_id += 1;
                inner.jobs.push(Rc::new(RefCell::new(UploadJob {
                    epoch,
                    file,
                    row: TransferRow {
                        id,
                        path,
                        size,
                        sent: 0,
                        rate: 0.0,
                        status: TransferStatus::Queued,
                        message: String::new(),
                    },
                    session: String::new(),
                    fingerprint: String::new(),
                    running: false,
                    pause: false,
                    cancel: false,
                    abort: None,
                    conflict: conflict.to_owned(),
                })));
            });
        }
        self.open.set(true);
        self.publish();
        self.pump();
    }
    pub(super) fn pump(self) {
        if !self.current() {
            return;
        }
        let mut launch = vec![];
        self.inner.update_value(|inner| {
            let active = inner.jobs.iter().filter(|job| job.borrow().running).count();
            for job in &inner.jobs {
                if launch.len() + active >= 3 {
                    break;
                }
                let mut job = job.borrow_mut();
                if job.row.status == TransferStatus::Queued && !job.running {
                    job.running = true;
                    job.row.status = TransferStatus::Preparing;
                    launch.push(job.row.id);
                }
            }
        });
        self.publish();
        for id in launch {
            let Some(job) = self.job(id) else { continue };
            spawn_local(async move {
                let result = self.run(id).await;
                if !self.job_current(&job) {
                    Self::cancel_stale(&job);
                    self.publish();
                    return;
                }
                if let Some(job) = self.job(id) {
                    let mut job = job.borrow_mut();
                    job.running = false;
                    match result {
                        Ok(TransferEnd::Completed) => {
                            job.row.sent = job.row.size;
                            job.row.status = TransferStatus::Completed;
                            job.row.message = if job.cancel {
                                "Completed before cancellation was confirmed".into()
                            } else {
                                String::new()
                            };
                        }
                        Ok(TransferEnd::Paused) => job.row.status = TransferStatus::Paused,
                        Ok(TransferEnd::Cancelled) => job.row.status = TransferStatus::Cancelled,
                        Err(failure) => {
                            job.row.status = if failure.status == 0 {
                                TransferStatus::Uncertain
                            } else {
                                TransferStatus::Failed
                            };
                            job.row.message = failure.to_string();
                        }
                    }
                }
                self.publish();
                self.on_change.run(());
                self.pump();
            });
        }
    }
    pub(super) fn control(self, id: u64, action: &str) {
        let Some(job) = self.job(id) else {
            return;
        };
        if !self.job_current(&job) {
            Self::cancel_stale(&job);
            self.publish();
            return;
        }
        {
            let mut job = job.borrow_mut();
            match action {
                "pause" => {
                    job.pause = true;
                    job.abort_request();
                    if !job.running {
                        job.row.status = TransferStatus::Paused;
                    }
                    job.row.message = "Upload paused; resume to reconcile server progress.".into();
                }
                "resume" => {
                    if job.running || job.row.status.terminal() {
                        return;
                    }
                    job.pause = false;
                    job.cancel = false;
                    job.row.status = TransferStatus::Queued;
                    job.row.message.clear();
                }
                "cancel" => {
                    job.cancel = true;
                    job.abort_request();
                    job.pause = false;
                    job.row.status = if job.running {
                        TransferStatus::Cancelling
                    } else if job.session.is_empty() {
                        TransferStatus::Cancelled
                    } else {
                        TransferStatus::Queued
                    };
                }
                _ => return,
            }
        }
        self.publish();
        self.pump();
    }
}

#[component]
pub(super) fn TransferPanel(queue: TransferQueue) -> impl IntoView {
    let context = app();
    view! {
        <Drawer open=queue.open title="Transfer queue">
            <p class="text-xs text-slate-400 mb-3">
                {move || tt(
                    context,
                    "Progress counts acknowledged bytes. Pause and cancel abort the current request immediately. Resume checks server progress; larger files resume in 4 MiB chunks.",
                )}
            </p>
            <div class="space-y-3 max-h-[65vh] overflow-y-auto">
                <For
                    each=move || queue.rows.get()
                    key=|row| (
                        row.id,
                        row.sent,
                        row.status.label(),
                        row.message.clone(),
                        row.path.clone(),
                    )
                    children=move |row| {
                        let id = row.id;
                        let percent = if row.size == 0 {
                            if row.status == TransferStatus::Completed { 100.0 } else { 0.0 }
                        } else {
                            row.sent as f64 / row.size as f64 * 100.0
                        };
                        view! {
                            <div class="rounded-xl border border-white/10 p-3 space-y-2">
                                <p class="font-medium text-sm break-all">{row.path}</p>
                                <div class="flex justify-between gap-2 text-xs text-slate-400">
                                    <span>{move || tt(context, row.status.label())}</span>
                                    <span>
                                        {move || tt_with(context, "{pct}% · {sent} / {total} · {rate}/s", &[("pct", &format!("{:.1}", percent)), ("sent", &(bytes(row.sent)).to_string()), ("total", &(bytes(row.size)).to_string()), ("rate", &(bytes(row.rate as u64)).to_string())])}
                                    </span>
                                </div>
                                <progress
                                    max="100"
                                    value=percent
                                    class="w-full"
                                    aria-label=move || tt(context, "Acknowledged upload progress")
                                />
                                <p role="status" class="text-xs text-amber-200 break-words">
                                    {move || tt(context, &row.message)}
                                </p>
                                <div class="flex flex-wrap gap-2">
                                    {matches!(
                                        row.status,
                                        TransferStatus::Queued
                                        | TransferStatus::Preparing
                                        | TransferStatus::Uploading
                                    )
                                        .then(|| {
                                            view! {
                                                <button
                                                    type="button"
                                                    class="glass-button px-3 py-2"
                                                    on:click=move |_| queue.control(id, "pause")
                                                >
                                                    {move || tt(context, "Pause")}
                                                </button>
                                            }
                                        })}
                                    {matches!(
                                        row.status,
                                        TransferStatus::Paused
                                        | TransferStatus::Failed
                                        | TransferStatus::Uncertain
                                    )
                                        .then(|| {
                                            view! {
                                                <button
                                                    type="button"
                                                    class="glass-button-primary px-3 py-2"
                                                    on:click=move |_| queue.control(id, "resume")
                                                >
                                                    {move || tt(
                                                        context,
                                                        if row.status == TransferStatus::Paused {
                                                            "Resume"
                                                        } else {
                                                            "Retry / reconcile"
                                                        },
                                                    )}
                                                </button>
                                            }
                                        })}
                                    {(!row.status.terminal())
                                        .then(|| {
                                            view! {
                                                <button
                                                    type="button"
                                                    class="glass-button px-3 py-2 text-rose-300"
                                                    on:click=move |_| queue.control(id, "cancel")
                                                >
                                                    {move || tt(context, "Cancel")}
                                                </button>
                                            }
                                        })}
                                </div>
                            </div>
                        }
                    }
                />
                <Show when=move || queue.rows.with(Vec::is_empty)>
                    <EmptyState
                        title="No transfers"
                        description="Choose files or drop them into the workspace."
                    />
                </Show>
            </div>
            <button
                type="button"
                class="glass-button px-4 py-2 mt-4"
                on:click=move |_| {
                    queue
                        .inner
                        .update_value(|inner| {
                            inner.jobs.retain(|job| {
                                let mut job = job.borrow_mut();
                                if job.row.status.terminal() {
                                    job.abort_request();
                                    false
                                } else {
                                    true
                                }
                            })
                        });
                    queue.publish();
                }
            >
                {move || tt(context, "Clear finished")}
            </button>
        </Drawer>
    }
}
