use super::*;

#[derive(Clone, Copy)]
pub(super) struct Actions {
    pub(super) open: RwSignal<bool>,
    pub(super) confirm: RwSignal<bool>,
    pub(super) kind: RwSignal<String>,
    pub(super) targets: RwSignal<Vec<String>>,
    pub(super) directory: RwSignal<String>,
    pub(super) destination: RwSignal<String>,
    pub(super) format: RwSignal<String>,
    pub(super) recursive: RwSignal<bool>,
    pub(super) busy: RwSignal<bool>,
    pub(super) failure: RwSignal<String>,
    pub(super) results: RwSignal<Vec<Value>>,
    pub(super) selected: RwSignal<BTreeSet<String>>,
    pub(super) on_change: Callback<()>,
}
impl Actions {
    pub(super) fn new(selected: RwSignal<BTreeSet<String>>, on_change: Callback<()>) -> Self {
        Self {
            open: RwSignal::new(false),
            confirm: RwSignal::new(false),
            kind: RwSignal::new(String::new()),
            targets: RwSignal::new(vec![]),
            directory: RwSignal::new(String::new()),
            destination: RwSignal::new(String::new()),
            format: RwSignal::new("zip".into()),
            recursive: RwSignal::new(false),
            busy: RwSignal::new(false),
            failure: RwSignal::new(String::new()),
            results: RwSignal::new(vec![]),
            selected,
            on_change,
        }
    }
    pub(super) fn show(self, kind: &str, targets: Vec<String>, directory: String) {
        if self.busy.get_untracked() {
            return;
        }
        self.destination.set(match kind {
            "rename" => targets
                .first()
                .map(|path| leaf(path).to_owned())
                .unwrap_or_default(),
            "archive" => join(&directory, "archive.zip"),
            "copy" | "move" => directory.clone(),
            "extract" => {
                let filename = targets.first().map(|path| leaf(path)).unwrap_or("archive");
                let stem = ARCHIVES
                    .iter()
                    .filter_map(|(_, extension)| filename.strip_suffix(extension))
                    .min_by_key(|stem| stem.len())
                    .unwrap_or(filename);
                join(&directory, &format!("{stem}-extracted"))
            }
            _ => String::new(),
        });
        self.directory.set(directory);
        self.targets.set(targets);
        self.kind.set(kind.to_owned());
        self.format.set("zip".into());
        self.recursive.set(false);
        self.failure.set(String::new());
        self.open.set(true);
    }
    pub(super) fn run(self) {
        if self.busy.get_untracked() {
            return;
        }
        let kind = self.kind.get_untracked();
        let targets = self.targets.get_untracked();
        let raw = self.destination.get_untracked();
        let destination = match kind.as_str() {
            "folder" | "file" => name_path(&self.directory.get_untracked(), &raw),
            "rename" => targets
                .first()
                .ok_or_else(|| "Select one entry.".into())
                .and_then(|source| name_path(parent(source), &raw)),
            "archive" | "extract" => relative_path(&raw, false),
            "copy" | "move" => relative_path(&raw, true),
            _ => Ok(String::new()),
        };
        let destination = match destination {
            Ok(path) => path,
            Err(message) => {
                self.failure.set(message);
                return;
            }
        };
        if !matches!(kind.as_str(), "folder" | "file") && targets.is_empty() {
            self.failure
                .set("Select at least one file or folder.".into());
            return;
        }
        if matches!(kind.as_str(), "rename" | "extract" | "checksums" | "info")
            && targets.len() != 1
        {
            self.failure
                .set("This operation requires exactly one entry.".into());
            return;
        }
        let format = self.format.get_untracked();
        let recursive = self.recursive.get_untracked();
        let context = app();
        let auth = context.session_epoch.get_untracked();
        self.busy.set(true);
        self.failure.set(String::new());
        self.results.set(vec![]);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(self.busy);
        spawn_local(async move {
            let mut requests: Vec<(String, String, &'static str, Option<Value>)> = vec![];
            match kind.as_str() {
                "folder" => requests.push((destination.clone(), format!("{BASE}/directory"), "POST", Some(json!({"path":destination})))),
                "file" => requests.push((destination.clone(), format!("{BASE}/file"), "POST", Some(json!({"path":destination, "content":""})))),
                "archive" => requests.push((destination.clone(), format!("{BASE}/actions"), "POST", Some(json!({"action":"create_archive", "source_paths":targets, "destination_path":destination, "format":format})))),
                "extract" => requests.push((targets[0].clone(), format!("{BASE}/actions"), "POST", Some(json!({"action":"extract_archive", "archive_path":targets[0], "destination_dir":destination})))),
                "checksums" => requests.push((targets[0].clone(), format!("{BASE}/actions"), "POST", Some(json!({"action":"compute_checksums", "path":targets[0], "algorithms":["sha256","md5","sha1","sha512"]})))),
                "info" => requests.push((targets[0].clone(), format!("{BASE}/info?path={}&checksum=sha256", encode(&targets[0])), "GET", None)),
                _ => for source in targets {
                    let request = match kind.as_str() {
                        "rename" | "move" | "copy" => {
                            let target = if kind == "rename" { destination.clone() } else { join(&destination, leaf(&source)) };
                            (format!("{BASE}/{}", if kind == "copy" { "copy" } else { "rename" }), "POST", Some(json!({"from":source, "to":target, "conflict":"error"})))
                        }
                        "delete" if recursive => (format!("{BASE}/delete-recursive"), "POST", Some(json!({"path":source}))),
                        "delete" => (format!("{BASE}/entry?path={}", encode(&source)), "DELETE", None),
                        _ => continue,
                    };
                    requests.push((source, request.0, request.1, request.2));
                }
            }
            let mut failed = false;
            let mut failed_paths = vec![];
            for (path, endpoint, method, payload) in requests {
                if context.session_epoch.try_get_untracked() != Some(auth)
                    || self.busy.try_get_untracked().is_none()
                {
                    return;
                }
                let result = ApiClient.request(&endpoint, method, payload.as_ref()).await;
                if context.session_epoch.try_get_untracked() != Some(auth)
                    || self.busy.try_get_untracked().is_none()
                {
                    return;
                }
                let record = match result {
                    Ok(data) => {
                        self.selected.update(|selection| {
                            selection.remove(&path);
                        });
                        json!({"path":path, "status": if data["accounting_pending"] == true { "Saved; accounting pending" } else { "Success" }, "details":data})
                    }
                    Err(failure) => {
                        failed = true;
                        failed_paths.push(path.clone());
                        json!({"path":path, "status":"Failed", "message":failure.to_string(), "code":failure.code, "http_status":failure.status})
                    }
                };
                self.results.update(|rows| rows.push(record));
            }
            busy_guard.release();
            self.confirm.set(false);
            self.on_change.run(());
            if failed {
                if matches!(kind.as_str(), "rename" | "copy" | "move" | "delete") {
                    self.targets.set(failed_paths);
                }
                self.failure.set("Some operations failed. Review the per-item results; successful changes have been retained.".into());
                context.toast(
                    tt(context, "Some file operations failed. Review the results."),
                    true,
                );
            } else {
                self.open.set(false);
                context.toast(tt(context, "File operation completed"), false);
            }
        });
    }
}
#[component]
pub(super) fn ActionsDialog(actions: Actions) -> impl IntoView {
    let context = app();
    view! {
        <Modal open=actions.open title="File operation">
            <form
                class="space-y-4"
                on:submit=move |event: web_sys::SubmitEvent| {
                    event.prevent_default();
                    if actions.kind.get_untracked() == "delete" {
                        actions.confirm.set(true);
                    } else {
                        actions.run();
                    }
                }
            >
                <p class="font-semibold capitalize">
                    {move || action_label(context, &actions.kind.get())}
                </p>
                <p class="text-xs text-slate-400 break-all">
                    {move || actions.targets.get().join(", ")}
                </p>
                <Show when=move || {
                    !matches!(actions.kind.get().as_str(), "delete" | "checksums" | "info")
                }>
                    <label class="block space-y-1 text-sm">
                        <span>
                            {move || tt(
                                context,
                                match actions.kind.get().as_str() {
                                    "folder" => "New folder name",
                                    "file" => "New file name",
                                    "rename" => "New name",
                                    "archive" => "Archive destination path (relative to root)",
                                    "extract" => {
                                        "New extraction folder (relative to root; must not exist)"
                                    }
                                    _ => "Destination folder (relative to root; empty for root)",
                                },
                            )}
                        </span>
                        <input
                            class=FORM
                            prop:value=move || actions.destination.get()
                            disabled=move || actions.busy.get()
                            on:input=move |event| {
                                actions.destination.set(event_target_value(&event))
                            }
                        />
                    </label>
                </Show>
                <Show when=move || actions.kind.get() == "archive">
                    <label class="block space-y-1 text-sm">
                        <span>{move || tt(context, "Archive format")}</span>
                        <select
                            class=FORM
                            prop:value=move || actions.format.get()
                            disabled=move || actions.busy.get()
                            on:change=move |event| {
                                let format = event_target_value(&event);
                                let extension = ARCHIVES
                                    .iter()
                                    .find(|(id, _)| *id == format)
                                    .map_or(".zip", |(_, extension)| *extension);
                                let current = actions.destination.get_untracked();
                                let stem = ARCHIVES
                                    .iter()
                                    .filter_map(|(_, extension)| current.strip_suffix(extension))
                                    .min_by_key(|stem| stem.len())
                                    .unwrap_or(&current);
                                actions.format.set(format);
                                actions.destination.set(format!("{stem}{extension}"));
                            }
                        >
                            {ARCHIVES
                                .into_iter()
                                .map(|(id, extension)| {
                                    view! { <option value=id>{extension}</option> }
                                })
                                .collect_view()}
                        </select>
                    </label>
                </Show>
                <Show when=move || actions.kind.get() == "delete">
                    <label class="flex items-start gap-2 text-sm">
                        <input
                            type="checkbox"
                            prop:checked=move || actions.recursive.get()
                            disabled=move || actions.busy.get()
                            on:change=move |event| {
                                actions.recursive.set(event_target_checked(&event))
                            }
                        />
                        <span>
                            {move || tt(
                                context,
                                "Recursively delete folders and their contents. Unchecked: only empty folders can be removed.",
                            )}
                        </span>
                    </label>
                </Show>
                <p role="alert" class="text-sm text-rose-300">
                    {move || tt(context, &actions.failure.get())}
                </p>
                <Show when=move || !actions.results.with(Vec::is_empty)>
                    <details class="text-xs max-h-52 overflow-auto">
                        <summary>{move || tt(context, "Per-item results")}</summary>
                        <pre class="whitespace-pre-wrap break-words">
                            {move || {
                                serde_json::to_string_pretty(&actions.results.get())
                                    .unwrap_or_default()
                            }}
                        </pre>
                    </details>
                </Show>
                <button
                    type="submit"
                    class="glass-button-primary px-4 py-2"
                    disabled=move || actions.busy.get()
                >
                    {move || tt(
                        context,
                        if actions.busy.get() {
                            "Working…"
                        } else if actions.kind.get() == "delete" {
                            "Review deletion…"
                        } else {
                            "Run operation"
                        },
                    )}
                </button>
            </form>
        </Modal>
        {move || {
            actions
                .confirm
                .get()
                .then(|| {
                    view! {
                        <ConfirmDialog
                            open=actions.confirm
                            title="Permanently delete selected entries?"
                            message=Signal::derive(move || tt_with(
                                context,
                                "Delete {count} selected entries{contents}? This cannot be undone.",
                                &[
                                    ("count", &actions.targets.with(Vec::len).to_string()),
                                    (
                                        "contents",
                                        &if actions.recursive.get() {
                                            tt(context, " and all their contents")
                                        } else {
                                            String::new()
                                        },
                                    ),
                                ],
                            ))
                            busy=actions.busy
                            on_confirm=Callback::new(move |()| actions.run())
                        />
                    }
                })
        }}
    }
}
