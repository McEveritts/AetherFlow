use super::*;
use af_web_ui::McBrowserCodeEditor;

#[derive(Clone, Copy)]
pub(super) struct Editor {
    pub(super) open: RwSignal<bool>,
    pub(super) path: RwSignal<String>,
    pub(super) content: RwSignal<String>,
    pub(super) baseline: RwSignal<String>,
    pub(super) etag: RwSignal<String>,
    pub(super) loading: RwSignal<bool>,
    pub(super) saving: RwSignal<bool>,
    pub(super) failure: RwSignal<String>,
    pub(super) conflict: RwSignal<bool>,
    pub(super) load_seq: RwSignal<u64>,
    pub(super) save_seq: RwSignal<u64>,
    pub(super) on_change: Callback<()>,
}
impl Editor {
    pub(super) fn new(on_change: Callback<()>) -> Self {
        Self {
            open: RwSignal::new(false),
            path: RwSignal::new(String::new()),
            content: RwSignal::new(String::new()),
            baseline: RwSignal::new(String::new()),
            etag: RwSignal::new(String::new()),
            loading: RwSignal::new(false),
            saving: RwSignal::new(false),
            failure: RwSignal::new(String::new()),
            conflict: RwSignal::new(false),
            load_seq: RwSignal::new(0),
            save_seq: RwSignal::new(0),
            on_change,
        }
    }
    pub(super) fn dirty(self) -> bool {
        self.content.get() != self.baseline.get()
    }
    pub(super) fn dirty_untracked(self) -> bool {
        self.content.get_untracked() != self.baseline.get_untracked()
    }
    pub(super) fn load(self, target: String) {
        if self.saving.get_untracked() || self.loading.get_untracked() {
            return;
        }
        self.load_seq.update(|g| *g += 1);
        let ticket = self.load_seq.get_untracked();
        let context = app();
        let auth = context.session_epoch.get_untracked();
        self.open.set(true);
        self.loading.set(true);
        self.failure.set(String::new());
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(self.loading, self.load_seq, ticket);
        spawn_local(async move {
            let result = async {
                let response = ApiClient
                    .fetch(
                        &format!("{BASE}/content?path={}", encode(&target)),
                        "GET",
                        None,
                    )
                    .await?;
                let (data, etag) = response_value(context, response).await?;
                let content = data["content"]
                    .as_str()
                    .ok_or_else(|| error("Server returned no UTF-8 file content"))?
                    .to_owned();
                if content.len() > MAX_EDITOR_BYTES {
                    return Err(error(
                        "The editor supports files up to 256 KiB. Download this file instead.",
                    ));
                }
                let etag = etag
                    .or_else(|| data["etag"].as_str().map(str::to_owned))
                    .filter(|tag| !tag.is_empty())
                    .ok_or_else(|| {
                        error("Content has no ETag; editing is unavailable until reloaded.")
                    })?;
                Ok::<_, ApiError>((content, etag))
            }
            .await;
            if self.load_seq.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
            {
                return;
            }
            busy_guard.release();
            match result {
                Ok((content, etag)) => {
                    self.content.set(content.clone());
                    self.baseline.set(content);
                    self.path.set(target);
                    self.etag.set(etag);
                    self.conflict.set(false);
                }
                Err(failure) => self.failure.set(failure.to_string()),
            }
        });
    }
    pub(super) fn save(self, overwrite: bool) {
        if self.saving.get_untracked() || self.loading.get_untracked() || !self.dirty_untracked() {
            return;
        }
        let context = app();
        let auth = context.session_epoch.get_untracked();
        self.save_seq.update(|generation| *generation += 1);
        let ticket = self.save_seq.get_untracked();
        let target = self.path.get_untracked();
        let content = self.content.get_untracked();
        if content.len() > MAX_EDITOR_BYTES {
            self.failure
                .set("Content exceeds the 256 KiB editor limit.".into());
            return;
        }
        let original_etag = self.etag.get_untracked();
        self.saving.set(true);
        self.failure.set(String::new());
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(self.saving, self.save_seq, ticket);
        spawn_local(async move {
            let result = async {
                // Overwrite is still guarded against a second concurrent write:
                // obtain current truth and CAS against that ETag, never '*'.
                let etag = if overwrite {
                    let (data, header) = response_value(
                        context,
                        ApiClient
                            .fetch(
                                &format!("{BASE}/content?path={}", encode(&target)),
                                "GET",
                                None,
                            )
                            .await?,
                    )
                    .await?;
                    header
                        .or_else(|| data["etag"].as_str().map(str::to_owned))
                        .unwrap_or_default()
                } else {
                    original_etag
                };
                if etag.is_empty() {
                    return Err(error("Reload the file to obtain an ETag before saving."));
                }
                if context.session_epoch.try_get_untracked() != Some(auth) {
                    return Err(error("Session ended"));
                }
                let payload =
                    JsValue::from_str(&json!({"content": content, "etag": etag}).to_string());
                let response = ApiClient
                    .fetch_raw_body(
                        &format!("{BASE}/content?path={}", encode(&target)),
                        "PUT",
                        Some(&payload),
                        Some("application/json"),
                        &[("If-Match", &etag)],
                    )
                    .await?;
                let (data, header) = response_value(context, response).await?;
                let etag = header
                    .or_else(|| data["etag"].as_str().map(str::to_owned))
                    .filter(|tag| !tag.is_empty())
                    .ok_or_else(|| {
                        error("File saved, but no ETag was returned. Reload before saving again.")
                    })?;
                Ok::<_, ApiError>((etag, data["accounting_pending"] == true))
            }
            .await;
            if self.save_seq.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
            {
                return;
            }
            busy_guard.release();
            match result {
                Ok((etag, pending)) => {
                    self.etag.set(etag);
                    self.baseline.set(content);
                    self.conflict.set(false);
                    self.on_change.run(());
                    context.toast(
                        tt(
                            context,
                            if pending {
                                "File saved; storage accounting is pending."
                            } else {
                                "File saved"
                            },
                        ),
                        false,
                    );
                }
                Err(failure) => {
                    if failure.status == 412
                        || (failure.status == 409 && failure.message.contains("ETag"))
                    {
                        self.conflict.set(true);
                    }
                    self.failure.set(failure.to_string());
                }
            }
        });
    }
}

#[component]
pub(super) fn EditorPanel(editor: Editor, #[prop(into)] readonly: Signal<bool>) -> impl IntoView {
    let context = app();
    let discard = RwSignal::new(false);
    let markdown_preview = RwSignal::new(false);
    let overwrite = RwSignal::new(false);
    let reload = RwSignal::new(false);
    Effect::new(move |_| {
        if !editor.open.get() && editor.dirty_untracked() {
            editor.open.set(true);
            discard.set(true);
        }
    });
    view! {
        <Modal open=editor.open title="Code editor">
            <div class="space-y-3 min-w-0">
                <div class="flex flex-wrap items-center justify-between gap-2">
                    <p class="font-mono text-sm break-all">{move || editor.path.get()}</p>
                    <Badge label="ETag guarded" tone="cyan" />
                    <span class="text-xs text-amber-200">
                        {move || tt(
                            context,
                            if editor.dirty() { "Unsaved changes" } else { "Saved" },
                        )}
                    </span>
                </div>
                <Show when=move || editor.loading.get()>
                    <SkeletonBox class="h-48" />
                </Show>
                <p role="alert" class="text-sm text-rose-300">
                    {move || tt(context, &editor.failure.get())}
                </p>
                {move || {
                    (!editor.path.get().is_empty())
                        .then(|| {
                            let path = editor.path.get();
                            // Re-mount on file changes to reset per-file undo and language.
                            view! {
                                <For
                                    each=move || vec![path.clone()]
                                    key=|path| path.clone()
                                    children=move |path| {
                                        view! {
                                            <McBrowserCodeEditor
                                                value=editor.content
                                                language=language(&path).to_owned()
                                                show_save=false
                                                readonly=Signal::derive(move || {
                                                    readonly.get() || editor.saving.get()
                                                        || editor.loading.get()
                                                })
                                                on_save=Callback::new(move |_: String| {
                                                    if !readonly.get_untracked() && editor.dirty_untracked() {
                                                        editor.save(false);
                                                    }
                                                })
                                            />
                                        }
                                    }
                                />
                            }
                        })
                }}
                <div class="flex flex-wrap gap-2">
                    <button
                        type="button"
                        class="glass-button-primary px-4 py-2"
                        disabled=move || {
                            readonly.get() || editor.saving.get() || editor.loading.get()
                                || !editor.dirty()
                        }
                        on:click=move |_| editor.save(false)
                    >
                        {move || tt(
                            context,
                            if editor.saving.get() { "Saving…" } else { "Save" },
                        )}
                    </button>
                    <button
                        type="button"
                        class="glass-button px-4 py-2"
                        disabled=move || {
                            editor.saving.get() || editor.loading.get()
                                || editor.path.get().is_empty()
                        }
                        on:click=move |_| {
                            if editor.dirty_untracked() {
                                reload.set(true);
                            } else {
                                editor.load(editor.path.get_untracked());
                            }
                        }
                    >
                        {move || tt(context, "Reload file")}
                    </button>
                </div>
                <Show when=move || language(&editor.path.get()) == "markdown">
                    <button
                        type="button"
                        class="glass-button px-3 py-2"
                        on:click=move |_| markdown_preview.update(|open| *open = !*open)
                    >
                        {move || tt(context, "Markdown + MathML preview")}
                    </button>
                    <Show when=move || markdown_preview.get()>
                        <af_web_ui::MarkdownView
                            source=editor.content
                            class="overflow-auto max-h-[55vh]"
                        />
                    </Show>
                </Show>
                <Show when=move || editor.conflict.get()>
                    <div class="rounded-xl border border-amber-400/30 bg-amber-500/10 p-3 space-y-3">
                        <p class="text-sm text-amber-100">
                            {move || tt(
                                context,
                                "The file changed on the server. Your draft is intact. Reload to discard it, or replace the current server content with your draft.",
                            )}
                        </p>
                        <button
                            type="button"
                            class="glass-button px-3 py-2"
                            disabled=move || readonly.get() || editor.saving.get()
                            on:click=move |_| overwrite.set(true)
                        >
                            {move || tt(context, "Overwrite with my draft…")}
                        </button>
                    </div>
                </Show>
            </div>
        </Modal>
        <ConfirmDialog
            open=discard
            title="Discard unsaved changes?"
            message="Closing the editor will discard your unsaved changes."
            busy=editor.saving
            on_confirm=Callback::new(move |()| {
                editor.content.set(editor.baseline.get_untracked());
                discard.set(false);
                editor.open.set(false);
            })
        />
        <ConfirmDialog
            open=reload
            title="Reload server content?"
            message="Your unsaved draft will be replaced by the current server version."
            busy=editor.saving
            on_confirm=Callback::new(move |()| {
                reload.set(false);
                editor.load(editor.path.get_untracked());
            })
        />
        <ConfirmDialog
            open=overwrite
            title="Replace server content?"
            message="Save your draft over the current version. A further concurrent change will still be rejected."
            busy=editor.saving
            on_confirm=Callback::new(move |()| {
                overwrite.set(false);
                editor.save(true);
            })
        />
    }
}

#[component]
pub(super) fn MediaPreview(open: RwSignal<bool>, path: RwSignal<String>) -> impl IntoView {
    let context = app();
    let failed = RwSignal::new(false);
    Effect::new(move |_| {
        path.track();
        failed.set(false);
    });
    view! {
        <Modal open title="Media preview">
            <p class="text-sm font-mono break-all mb-3">{move || path.get()}</p>
            {move || {
                let path = path.get();
                let src = format!("{BASE}/media?path={}", encode(&path));
                match media_kind(&path) {
                    "image" => {
                        view! {
                            <img
                                src=src
                                alt=leaf(&path).to_owned()
                                class="max-w-full max-h-[65vh] mx-auto object-contain"
                                on:error=move |_| failed.set(true)
                            />
                        }
                            .into_any()
                    }
                    "video" => {
                        view! {
                            <video
                                src=src
                                controls
                                preload="metadata"
                                class="max-w-full max-h-[65vh]"
                                on:error=move |_| failed.set(true)
                            >
                                {move || tt(context, "Video playback is unavailable.")}
                            </video>
                        }
                            .into_any()
                    }
                    "audio" => {
                        view! {
                            <audio
                                src=src
                                controls
                                preload="metadata"
                                class="w-full"
                                on:error=move |_| failed.set(true)
                            >
                                {move || tt(context, "Audio playback is unavailable.")}
                            </audio>
                        }
                            .into_any()
                    }
                    "pdf" => {
                        let download_href = format!("{BASE}/download?path={}", encode(&path));
                        view! {
                            <div class="rounded-xl border border-white/10 bg-slate-950/60 p-5 space-y-4">
                                <div>
                                    <h3 class="font-semibold break-all">
                                        {leaf(&path).to_owned()}
                                    </h3>
                                    <p class="text-sm text-slate-400 mt-1">
                                        {move || tt(context, "PDF document · application/pdf")}
                                    </p>
                                </div>
                                <div class="flex flex-wrap gap-3">
                                    <a
                                        class="glass-button-primary px-4 py-2"
                                        href=src
                                        target="_blank"
                                        rel="noopener noreferrer"
                                    >
                                        {move || tt(context, "Open PDF in new tab")}
                                    </a>
                                    <a
                                        class="glass-button px-4 py-2"
                                        href=download_href
                                        download=leaf(&path).to_owned()
                                    >
                                        {move || tt(context, "Download PDF")}
                                    </a>
                                </div>
                            </div>
                        }
                            .into_any()
                    }
                    _ => {
                        view! {
                            <EmptyState
                                title="Preview unavailable"
                                description="Download this file to open it in a compatible application."
                            />
                        }
                            .into_any()
                    }
                }
            }}
            <Show when=move || failed.get()>
                <p role="alert" class="text-sm text-rose-300 mt-3">
                    {move || tt(
                        context,
                        "Preview could not load. Check file permissions or download the original.",
                    )}
                </p>
            </Show>
            <a
                class="glass-button inline-block px-4 py-2 mt-3"
                href=move || format!("{BASE}/download?path={}", encode(&path.get()))
                download=move || leaf(&path.get()).to_owned()
            >
                {move || tt(context, "Download original")}
            </a>
        </Modal>
    }
}

#[cfg(test)]
mod busy_tests {
    use super::*;
    use crate::tabs::busy::BusyGuard;

    #[test]
    fn editor_operations_release_busy_after_session_cancellation_and_allow_retry() {
        let owner = Owner::new();
        owner.with(|| {
            let context = AppContext::new();
            let editor = Editor::new(Callback::new(|()| {}));
            for (busy, seq) in [
                (editor.loading, editor.load_seq),
                (editor.saving, editor.save_seq),
            ] {
                busy.set(true);
                seq.set(1);
                let epoch = context.session_epoch.get_untracked();
                let operation = BusyGuard::for_generation(busy, seq, 1);
                // A same-account recheck leaves the authorization lifetime intact.
                assert_eq!(context.session_epoch.get_untracked(), epoch);
                assert!(busy.get_untracked());
                context.session_epoch.update(|epoch| *epoch += 1);
                drop(operation);
                assert!(!busy.get_untracked());
                busy.set(true);
                seq.set(2);
                drop(BusyGuard::for_generation(busy, seq, 2));
                assert!(!busy.get_untracked(), "retry stayed locked");
            }
            assert!(!editor.loading.get_untracked() && !editor.saving.get_untracked());
        });
    }
}
