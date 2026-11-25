use super::*;
use af_web_ui::{McBrowserCodeEditor, MAX_TEXT_EDITOR_BYTES};

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
        let context = app();
        if self.saving.get_untracked()
            || self.loading.get_untracked()
            || !context.can_read_area_untracked(PeerArea::Files)
        {
            return;
        }
        self.load_seq.update(|g| *g = g.wrapping_add(1));
        let ticket = self.load_seq.get_untracked();
        let fence = crate::tabs::busy::AreaFence::capture(
            context,
            PeerArea::Files,
            false,
            false,
            self.load_seq,
            ticket,
        );
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
                if !fence.is_valid() {
                    return Err(error("Session ended"));
                }
                let (data, etag) = response_value(context, response).await?;
                let content = data["content"]
                    .as_str()
                    .ok_or_else(|| error("Server returned no UTF-8 file content"))?
                    .to_owned();
                if content.len() > MAX_TEXT_EDITOR_BYTES {
                    return Err(error(
                        "The editor supports files up to 10 MiB. Download this file instead.",
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
            if self.loading.try_get_untracked().is_none() || !fence.is_valid() {
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
        let context = app();
        if self.saving.get_untracked()
            || self.loading.get_untracked()
            || !self.dirty_untracked()
            || !context.can_write_area_untracked(PeerArea::Files)
        {
            return;
        }
        self.save_seq
            .update(|generation| *generation = generation.wrapping_add(1));
        let ticket = self.save_seq.get_untracked();
        let fence = crate::tabs::busy::AreaFence::capture(
            context,
            PeerArea::Files,
            true,
            false,
            self.save_seq,
            ticket,
        );
        let target = self.path.get_untracked();
        let content = self.content.get_untracked();
        if content.len() > MAX_TEXT_EDITOR_BYTES {
            self.failure
                .set("Content exceeds the 10 MiB editor limit.".into());
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
                    if !fence.is_valid() {
                        return Err(error("Session ended"));
                    }
                    let response = ApiClient
                        .fetch(
                            &format!("{BASE}/content?path={}", encode(&target)),
                            "GET",
                            None,
                        )
                        .await?;
                    if !fence.is_valid() {
                        return Err(error("Session ended"));
                    }
                    let (data, header) = response_value(context, response).await?;
                    if !fence.is_valid() {
                        return Err(error("Session ended"));
                    }
                    header
                        .or_else(|| data["etag"].as_str().map(str::to_owned))
                        .unwrap_or_default()
                } else {
                    original_etag
                };
                if etag.is_empty() {
                    return Err(error("Reload the file to obtain an ETag before saving."));
                }
                if !fence.is_valid() {
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
                if !fence.is_valid() {
                    return Err(error("Session ended"));
                }
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
            if self.saving.try_get_untracked().is_none() || !fence.is_valid() {
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
pub(super) fn EditorPanel(
    editor: Editor,
    editor_theme: RwSignal<String>,
    #[prop(into)] readonly: Signal<bool>,
) -> impl IntoView {
    let context = app();
    let discard = RwSignal::new(false);
    let markdown_preview = RwSignal::new(false);
    let overwrite = RwSignal::new(false);
    let reload = RwSignal::new(false);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Files);
        editor.load_seq.update(|g| *g = g.wrapping_add(1));
        editor.save_seq.update(|g| *g = g.wrapping_add(1));
        editor.baseline.set(String::new());
        editor.content.set(String::new());
        editor.path.set(String::new());
        editor.etag.set(String::new());
        editor.failure.set(String::new());
        editor.conflict.set(false);
        editor.loading.set(false);
        editor.saving.set(false);
        editor.open.set(false);
        discard.set(false);
        overwrite.set(false);
        reload.set(false);
    });
    Effect::new(move |_| {
        if !context.can_write_area(PeerArea::Files) {
            editor.save_seq.update(|g| *g = g.wrapping_add(1));
            editor.saving.set(false);
            overwrite.set(false);
        }
    });
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
                    <div class="flex flex-wrap items-center gap-2">
                        <label class="inline-flex items-center gap-1.5 text-xs text-slate-400">
                            {move || tt(context, "Editor theme")}
                            <select
                                id="mcbrowser-editor-theme"
                                class="af-input px-2 py-1 text-xs font-mono"
                                data-testid="editor-theme-select"
                                aria-label=move || tt(context, "Editor theme")
                                prop:value=move || editor_theme.get()
                                on:change=move |event| {
                                    let next = event_target_value(&event);
                                    if is_valid_editor_theme(&next) {
                                        editor_theme.set(next);
                                    }
                                }
                            >
                                {move || {
                                    let current = editor_theme.get();
                                    let mut options: Vec<String> = EDITOR_THEME_OPTIONS
                                        .iter()
                                        .map(|opt| (*opt).to_owned())
                                        .collect();
                                    if is_valid_editor_theme(&current)
                                        && !options.iter().any(|opt| opt == &current)
                                    {
                                        options.push(current);
                                    }
                                    options
                                        .into_iter()
                                        .map(|theme_name| {
                                            let label = theme_name.clone();
                                            view! { <option value=theme_name>{label}</option> }
                                        })
                                        .collect_view()
                                }}
                            </select>
                        </label>
                        <Badge label="ETag guarded" tone="cyan" />
                        <span class="text-xs text-amber-200">
                            {move || tt(
                                context,
                                if editor.dirty() { "Unsaved changes" } else { "Saved" },
                            )}
                        </span>
                    </div>
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
                                                theme=Signal::derive(move || editor_theme.get())
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
                        class="af-btn-primary px-4 py-2"
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
                        class="af-btn px-4 py-2"
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
                        class="af-btn px-3 py-2"
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
                            class="af-btn px-3 py-2"
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

const ZOOM_STEPS: [u16; 8] = [50, 75, 100, 125, 150, 200, 250, 300];

fn next_zoom(current: u16, zoom_in: bool) -> u16 {
    let idx = ZOOM_STEPS
        .iter()
        .position(|step| *step == current)
        .unwrap_or(2);
    if zoom_in {
        ZOOM_STEPS[(idx + 1).min(ZOOM_STEPS.len() - 1)]
    } else {
        ZOOM_STEPS[idx.saturating_sub(1)]
    }
}

fn parse_subtitle_tracks(data: &Value, server: Option<&str>) -> Vec<(String, String, String)> {
    data["subtitles"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|track| {
            let url = safe_subtitle_url_for_server(track["url"].as_str()?, server)?;
            let label = track["label"]
                .as_str()
                .or_else(|| track["name"].as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("Subtitles")
                .to_owned();
            let lang = track["language"].as_str().unwrap_or_default().to_owned();
            Some((url, label, lang))
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EpubChapterPreview {
    title: String,
    paragraphs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EpubBookModel {
    title: String,
    author: String,
    language: String,
    description: String,
    chapters: Vec<EpubChapterPreview>,
}

fn epub_chapter_paragraphs(chapter: &Value) -> Vec<String> {
    if let Some(arr) = chapter["paragraphs"].as_array() {
        let items: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(str::trim))
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        if !items.is_empty() {
            return items;
        }
    }
    chapter["text"]
        .as_str()
        .unwrap_or_default()
        .split("\n\n")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn decode_epub_preview(data: &Value, fallback_title: &str) -> Result<EpubBookModel, &'static str> {
    let chapters_raw = data["chapters"]
        .as_array()
        .ok_or("Invalid EPUB preview response")?;
    let title = data["title"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_title)
        .to_owned();
    let author = data["author"]
        .as_str()
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    let language = data["language"]
        .as_str()
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    let description = data["description"]
        .as_str()
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    let chapters = chapters_raw
        .iter()
        .enumerate()
        .map(|(idx, ch)| {
            let name = ch["title"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("Chapter {}", idx + 1));
            EpubChapterPreview {
                title: name,
                paragraphs: epub_chapter_paragraphs(ch),
            }
        })
        .collect();
    Ok(EpubBookModel {
        title,
        author,
        language,
        description,
        chapters,
    })
}

#[component]
pub(super) fn MediaPreview(
    open: RwSignal<bool>,
    path: RwSignal<String>,
    #[prop(into)] items: Signal<Vec<String>>,
    #[prop(into)] can_download: Signal<bool>,
    #[prop(optional)] on_edit: Option<Callback<String>>,
) -> impl IntoView {
    let context = app();
    let failed = RwSignal::new(false);
    let image_fallback = RwSignal::new(false);
    let zoom = RwSignal::new(100u16);
    let playback_rate = RwSignal::new("1".to_owned());
    let media_host = NodeRef::<leptos::html::Div>::new();
    let metadata = RwSignal::new(Value::Null);
    let subtitles = RwSignal::new(Vec::<(String, String, String)>::new());
    let csv_bytes = RwSignal::new(Option::<Vec<u8>>::None);
    let csv_delim = RwSignal::new("auto".to_owned());
    let csv_encoding = RwSignal::new("utf-8".to_owned());
    let epub_data = RwSignal::new(Option::<EpubBookModel>::None);
    let epub_chapter = RwSignal::new(0usize);
    let epub_font = RwSignal::new(15u8);
    let aux_loading = RwSignal::new(false);
    let aux_error = RwSignal::new(String::new());
    let aux_seq = RwSignal::new(0u64);
    let disposed = StoredValue::new_local(false);
    on_cleanup(move || {
        disposed.set_value(true);
    });

    let apply_playback_rate = move |raw_rate: &str| {
        let rate = raw_rate.parse::<f64>().unwrap_or(1.0).clamp(0.25, 4.0);
        if let Some(host) = media_host.get() {
            if let Ok(Some(media_el)) = host.query_selector("video, audio") {
                let _ = js_sys::Reflect::set(
                    media_el.as_ref(),
                    &JsValue::from_str("playbackRate"),
                    &JsValue::from_f64(rate),
                );
            }
        }
    };

    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Files);
        open.set(false);
        path.set(String::new());
        aux_seq.update(|seq| *seq += 1);
    });

    Effect::new(move |_| {
        let is_open = open.get();
        let target = path.get();
        let server_epoch = context.server_epoch.get();
        let server_id = context.active_server_id.get_untracked();
        aux_seq.update(|seq| *seq += 1);
        let ticket = aux_seq.get_untracked();
        failed.set(false);
        image_fallback.set(false);
        zoom.set(100);
        playback_rate.set("1".to_owned());
        metadata.set(Value::Null);
        subtitles.set(vec![]);
        csv_bytes.set(None);
        csv_delim.set("auto".to_owned());
        csv_encoding.set("utf-8".to_owned());
        epub_data.set(None);
        epub_chapter.set(0);
        aux_error.set(String::new());
        aux_loading.set(false);

        if !is_open || target.is_empty() || !context.can_read_area_untracked(PeerArea::Files) {
            return;
        }
        let kind = media_kind(&target);
        let auth = context.session_epoch.get_untracked();
        let files_grant = context.area_revocation_epoch_untracked(PeerArea::Files);
        match kind {
            "image" | "video" | "audio" => {
                let is_video = kind == "video";
                spawn_local(async move {
                    let mut have_subs = false;
                    let info_url = format!("{BASE}/media-info?path={}", encode(&target));
                    if let Ok(info) = ApiClient.get(&info_url).await {
                        if disposed.try_get_value() != Some(false)
                            || aux_seq.try_get_untracked() != Some(ticket)
                            || context.session_epoch.try_get_untracked() != Some(auth)
                            || context.server_epoch.try_get_untracked() != Some(server_epoch)
                            || context.area_revocation_epoch_untracked(PeerArea::Files)
                                != files_grant
                            || !context.can_read_area_untracked(PeerArea::Files)
                        {
                            return;
                        }
                        if is_video {
                            let tracks = parse_subtitle_tracks(&info, server_id.as_deref());
                            if !tracks.is_empty() {
                                have_subs = true;
                                subtitles.set(tracks);
                            }
                        }
                        if info.is_object() {
                            metadata.set(info);
                        }
                    }
                    if is_video && !have_subs {
                        let sub_url = format!("{BASE}/subtitles?path={}", encode(&target));
                        if let Ok(subs) = ApiClient.get(&sub_url).await {
                            if disposed.try_get_value() != Some(false)
                                || aux_seq.try_get_untracked() != Some(ticket)
                                || context.session_epoch.try_get_untracked() != Some(auth)
                                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                                || context.area_revocation_epoch_untracked(PeerArea::Files)
                                    != files_grant
                                || !context.can_read_area_untracked(PeerArea::Files)
                            {
                                return;
                            }
                            let tracks = parse_subtitle_tracks(&subs, server_id.as_deref());
                            if !tracks.is_empty() {
                                subtitles.set(tracks);
                            }
                        }
                    }
                });
            }
            "csv" => {
                aux_loading.set(true);
                spawn_local(async move {
                    let url = format!("{BASE}/csv?path={}", encode(&target));
                    let result = async {
                        let resp = ApiClient.fetch(&url, "GET", None).await?;
                        let resp = checked(context, resp).await?;
                        let blob = resp
                            .blob_limited(MAX_CSV_PREVIEW_BYTES as u32, "text/csv")
                            .await?;
                        let buffer = JsFuture::from(blob.array_buffer())
                            .await
                            .map_err(js_error)?;
                        Ok::<_, ApiError>(js_sys::Uint8Array::new(&buffer).to_vec())
                    }
                    .await;
                    if disposed.try_get_value() != Some(false)
                        || aux_seq.try_get_untracked() != Some(ticket)
                        || context.session_epoch.try_get_untracked() != Some(auth)
                        || context.server_epoch.try_get_untracked() != Some(server_epoch)
                        || context.area_revocation_epoch_untracked(PeerArea::Files) != files_grant
                        || !context.can_read_area_untracked(PeerArea::Files)
                    {
                        return;
                    }
                    aux_loading.set(false);
                    match result {
                        Ok(raw_bytes) => csv_bytes.set(Some(raw_bytes)),
                        Err(err) => aux_error.set(err.to_string()),
                    }
                });
            }
            "epub" => {
                aux_loading.set(true);
                spawn_local(async move {
                    let url = format!("{BASE}/epub?path={}", encode(&target));
                    let result = ApiClient.get(&url).await;
                    if disposed.try_get_value() != Some(false)
                        || aux_seq.try_get_untracked() != Some(ticket)
                        || context.session_epoch.try_get_untracked() != Some(auth)
                        || context.server_epoch.try_get_untracked() != Some(server_epoch)
                        || context.area_revocation_epoch_untracked(PeerArea::Files) != files_grant
                        || !context.can_read_area_untracked(PeerArea::Files)
                    {
                        return;
                    }
                    aux_loading.set(false);
                    match result {
                        Ok(book) => match decode_epub_preview(&book, leaf(&target)) {
                            Ok(parsed) => epub_data.set(Some(parsed)),
                            Err(msg) => aux_error.set(msg.to_owned()),
                        },
                        Err(err) => aux_error.set(err.to_string()),
                    }
                });
            }
            _ => {}
        }
    });

    let nav_position = Memo::new(move |_| {
        let current = path.get();
        let list = items.get();
        list.iter()
            .position(|entry| entry == &current)
            .map(|idx| (idx, list.len()))
    });

    let csv_parsed = Memo::new(move |_| {
        let encoding = csv_encoding.get();
        let delim_choice = csv_delim.get();
        let current_path = path.get();
        csv_bytes.with(|maybe_bytes| {
            let bytes = maybe_bytes.as_deref()?;
            match decode_csv_bytes(bytes, &encoding) {
                Ok(raw) => {
                    let delim = match delim_choice.as_str() {
                        "," => ',',
                        ";" => ';',
                        "\t" => '\t',
                        "|" => '|',
                        _ => detect_csv_delimiter(&raw, &current_path),
                    };
                    Some(Ok(parse_csv_preview(&raw, delim, MAX_CSV_PREVIEW_ROWS)))
                }
                Err(msg) => Some(Err(msg)),
            }
        })
    });

    view! {
        <Modal open title="Media preview">
            <div class="flex flex-wrap items-center justify-between gap-2 mb-3">
                <p class="text-sm font-mono break-all flex-1 min-w-0">{move || path.get()}</p>
                <Show when=move || nav_position.get().is_some_and(|(_, total)| total > 1)>
                    <div class="flex items-center gap-2 shrink-0">
                        <button
                            type="button"
                            class="af-btn px-3 py-1.5 text-xs"
                            data-testid="media-preview-prev"
                            disabled=move || nav_position.get().is_none_or(|(idx, _)| idx == 0)
                            on:click=move |_| {
                                if let Some((idx, _)) = nav_position.get_untracked() {
                                    if idx > 0 {
                                        if let Some(prev) = items.with_untracked(|list| list.get(idx - 1).cloned()) {
                                            path.set(prev);
                                        }
                                    }
                                }
                            }
                        >
                            {move || tt(context, "Previous")}
                        </button>
                        <span class="text-xs font-mono text-slate-400 tabular-nums">
                            {move || {
                                nav_position
                                    .get()
                                    .map(|(idx, total)| format!("{} / {total}", idx + 1))
                                    .unwrap_or_default()
                            }}
                        </span>
                        <button
                            type="button"
                            class="af-btn px-3 py-1.5 text-xs"
                            data-testid="media-preview-next"
                            disabled=move || {
                                nav_position
                                    .get()
                                    .is_none_or(|(idx, total)| idx + 1 >= total)
                            }
                            on:click=move |_| {
                                if let Some((idx, total)) = nav_position.get_untracked() {
                                    if idx + 1 < total {
                                        if let Some(next) = items.with_untracked(|list| list.get(idx + 1).cloned()) {
                                            path.set(next);
                                        }
                                    }
                                }
                            }
                        >
                            {move || tt(context, "Next")}
                        </button>
                    </div>
                </Show>
            </div>
            <div node_ref=media_host>
                {move || {
                    context.active_server_id.track();
                    context.server_epoch.track();
                    let current_path = path.get();
                    if current_path.is_empty() {
                        return ().into_any();
                    }
                    let encoded_path = encode(&current_path);
                    let src = mcbrowser_media_url_encoded(&encoded_path);
                    let big_src = mcbrowser_preview_big_url_encoded(&encoded_path);
                    match media_kind(&current_path) {
                        "image" => {
                            let alt = leaf(&current_path).to_owned();
                            view! {
                                <div class="space-y-3">
                                    <div class="flex flex-wrap items-center gap-2">
                                        <button
                                            type="button"
                                            class="af-btn px-3 py-1 text-xs"
                                            data-testid="image-zoom-out"
                                            disabled=move || { zoom.get() <= ZOOM_STEPS[0] }
                                            on:click=move |_| zoom.update(|z| *z = next_zoom(*z, false))
                                        >
                                            "−"
                                        </button>
                                        <span class="text-xs font-mono tabular-nums">
                                            {move || format!("{}%", zoom.get())}
                                        </span>
                                        <button
                                            type="button"
                                            class="af-btn px-3 py-1 text-xs"
                                            data-testid="image-zoom-in"
                                            disabled=move || { zoom.get() >= ZOOM_STEPS[ZOOM_STEPS.len() - 1] }
                                            on:click=move |_| zoom.update(|z| *z = next_zoom(*z, true))
                                        >
                                            "+"
                                        </button>
                                        <button
                                            type="button"
                                            class="af-btn px-3 py-1 text-xs"
                                            disabled=move || zoom.get() == 100
                                            on:click=move |_| zoom.set(100)
                                        >
                                            {move || tt(context, "Reset zoom")}
                                        </button>
                                    </div>
                                    <div class="af-surface-inset overflow-auto max-h-[65vh] p-2">
                                        <img
                                            src=move || {
                                                if image_fallback.get() {
                                                    src.clone()
                                                } else {
                                                    big_src.clone()
                                                }
                                            }
                                            alt=alt
                                            class=move || {
                                                format!("mx-auto object-contain af-zoom-{}", zoom.get())
                                            }
                                            on:error=move |_| {
                                                if !image_fallback.get_untracked() {
                                                    image_fallback.set(true);
                                                } else {
                                                    failed.set(true);
                                                }
                                            }
                                        />
                                    </div>
                                </div>
                            }
                                .into_any()
                        }
                        "video" => {
                            view! {
                                <div class="space-y-3">
                                    <video
                                        src=src
                                        controls
                                        preload="metadata"
                                        class="max-w-full max-h-[65vh] mx-auto"
                                        on:play=move |_| apply_playback_rate(&playback_rate.get_untracked())
                                        on:error=move |_| failed.set(true)
                                    >
                                        <For
                                            each=move || subtitles.get()
                                            key=|(url, _, _)| url.clone()
                                            children=move |(url, label, lang)| {
                                                view! {
                                                    <track
                                                        kind="subtitles"
                                                        src=url
                                                        label=label
                                                        srclang=lang
                                                    />
                                                }
                                            }
                                        />
                                        {move || tt(context, "Video playback is unavailable.")}
                                    </video>
                                    <div class="flex flex-wrap items-center gap-3 text-xs text-slate-400">
                                        <label class="inline-flex items-center gap-2">
                                            {move || tt(context, "Playback speed")}
                                            <select
                                                class="af-input px-2 py-1 text-xs"
                                                data-testid="media-playback-speed"
                                                prop:value=move || playback_rate.get()
                                                on:change=move |event| {
                                                    let next = event_target_value(&event);
                                                    playback_rate.set(next.clone());
                                                    apply_playback_rate(&next);
                                                }
                                            >
                                                <option value="0.5">"0.5x"</option>
                                                <option value="0.75">"0.75x"</option>
                                                <option value="1">"1x"</option>
                                                <option value="1.25">"1.25x"</option>
                                                <option value="1.5">"1.5x"</option>
                                                <option value="2">"2x"</option>
                                            </select>
                                        </label>
                                        <Show when=move || !subtitles.with(Vec::is_empty)>
                                            <span>
                                                {move || tt_with(
                                                    context,
                                                    "{count} subtitle tracks",
                                                    &[("count", &subtitles.with(Vec::len).to_string())],
                                                )}
                                            </span>
                                        </Show>
                                    </div>
                                </div>
                            }
                                .into_any()
                        }
                        "audio" => {
                            view! {
                                <div class="space-y-3">
                                    <audio
                                        src=src
                                        controls
                                        preload="metadata"
                                        class="w-full"
                                        on:play=move |_| apply_playback_rate(&playback_rate.get_untracked())
                                        on:error=move |_| failed.set(true)
                                    >
                                        {move || tt(context, "Audio playback is unavailable.")}
                                    </audio>
                                    <label class="inline-flex items-center gap-2 text-xs text-slate-400">
                                        {move || tt(context, "Playback speed")}
                                        <select
                                            class="af-input px-2 py-1 text-xs"
                                            data-testid="media-playback-speed"
                                            prop:value=move || playback_rate.get()
                                            on:change=move |event| {
                                                let next = event_target_value(&event);
                                                playback_rate.set(next.clone());
                                                apply_playback_rate(&next);
                                            }
                                        >
                                            <option value="0.5">"0.5x"</option>
                                            <option value="0.75">"0.75x"</option>
                                            <option value="1">"1x"</option>
                                            <option value="1.25">"1.25x"</option>
                                            <option value="1.5">"1.5x"</option>
                                            <option value="2">"2x"</option>
                                        </select>
                                    </label>
                                </div>
                            }
                                .into_any()
                        }
                        "pdf" => {
                            let download_href = mcbrowser_download_url_encoded(&encoded_path);
                            let file_name = leaf(&current_path).to_owned();
                            let download_name = file_name.clone();
                            view! {
                                <div class="af-surface-inset p-5 space-y-4">
                                    <div>
                                        <h3 class="font-semibold break-all">{file_name}</h3>
                                        <p class="text-sm text-slate-400 mt-1">
                                            {move || tt(context, "PDF document · application/pdf")}
                                        </p>
                                    </div>
                                    <div class="flex flex-wrap gap-3">
                                        <a
                                            class="af-btn-primary px-4 py-2"
                                            href=src
                                            target="_blank"
                                            rel="noopener noreferrer"
                                        >
                                            {move || tt(context, "Open PDF in new tab")}
                                        </a>
                                        <Show when=move || can_download.get()>
                                            <a
                                                class="af-btn px-4 py-2"
                                                href=download_href.clone()
                                                download=download_name.clone()
                                            >
                                                {move || tt(context, "Download PDF")}
                                            </a>
                                        </Show>
                                    </div>
                                </div>
                            }
                                .into_any()
                        }
                        "csv" => {
                            let edit_target = current_path.clone();
                            view! {
                                <div class="space-y-3" data-testid="csv-preview">
                                    <div class="flex flex-wrap items-center justify-between gap-2">
                                        <div class="flex flex-wrap items-center gap-3">
                                            <label class="inline-flex items-center gap-2 text-xs text-slate-400">
                                                {move || tt(context, "Delimiter")}
                                                <select
                                                    class="af-input px-2 py-1 text-xs"
                                                    data-testid="csv-delimiter-select"
                                                    prop:value=move || csv_delim.get()
                                                    on:change=move |event| csv_delim.set(event_target_value(&event))
                                                >
                                                    <option value="auto">{move || tt(context, "Auto")}</option>
                                                    <option value=",">{move || tt(context, "Comma (,)")}</option>
                                                    <option value=";">{move || tt(context, "Semicolon (;)")}</option>
                                                    <option value="\t">{move || tt(context, "Tab")}</option>
                                                    <option value="|">{move || tt(context, "Pipe (|)")}</option>
                                                </select>
                                            </label>
                                            <label class="inline-flex items-center gap-2 text-xs text-slate-400">
                                                {move || tt(context, "Encoding")}
                                                <select
                                                    class="af-input px-2 py-1 text-xs font-mono"
                                                    data-testid="csv-encoding-select"
                                                    aria-label=move || tt(context, "Encoding")
                                                    prop:value=move || csv_encoding.get()
                                                    on:change=move |event| csv_encoding.set(event_target_value(&event))
                                                >
                                                    {CSV_ENCODING_OPTIONS
                                                        .iter()
                                                        .map(|enc| {
                                                            let enc_val = (*enc).to_owned();
                                                            let enc_label = (*enc).to_owned();
                                                            view! { <option value=enc_val>{enc_label}</option> }
                                                        })
                                                        .collect_view()}
                                                </select>
                                            </label>
                                        </div>
                                        {on_edit.map(|cb| {
                                            let edit_path = edit_target.clone();
                                            view! {
                                                <button
                                                    type="button"
                                                    class="af-btn px-3 py-1.5 text-xs"
                                                    on:click=move |_| {
                                                        open.set(false);
                                                        cb.run(edit_path.clone());
                                                    }
                                                >
                                                    {move || tt(context, "Open in code editor")}
                                                </button>
                                            }
                                        })}
                                    </div>
                                    <Show when=move || aux_loading.get()>
                                        <SkeletonBox class="h-44" />
                                    </Show>
                                    <Show when=move || !aux_error.get().is_empty()>
                                        <p role="alert" class="text-sm text-rose-300">
                                            {move || tt(context, &aux_error.get())}
                                        </p>
                                    </Show>
                                    {move || {
                                        csv_parsed.get().map(|outcome| match outcome {
                                            Err(decode_err) => view! {
                                                <p role="alert" class="text-sm text-rose-300">
                                                    {move || tt(context, decode_err)}
                                                </p>
                                            }
                                            .into_any(),
                                            Ok(parsed) => {
                                                let shown = parsed.rows.len();
                                                let total = parsed.total_rows;
                                                let truncated = parsed.truncated;
                                                let headers = parsed.headers;
                                                let rows = parsed.rows;
                                                view! {
                                                    <div class="space-y-2">
                                                        <p class="text-xs text-slate-400">
                                                            {move || {
                                                                if truncated {
                                                                    tt_with(
                                                                        context,
                                                                        "Showing {shown} of {total} rows",
                                                                        &[
                                                                            ("shown", &shown.to_string()),
                                                                            ("total", &total.to_string()),
                                                                        ],
                                                                    )
                                                                } else {
                                                                    tt_with(
                                                                        context,
                                                                        "{total} rows",
                                                                        &[("total", &total.to_string())],
                                                                    )
                                                                }
                                                            }}
                                                        </p>
                                                        <div class="overflow-auto max-h-[55vh] rounded-lg border border-[var(--af-border-hairline)]">
                                                            <table class="w-full text-xs text-left border-collapse">
                                                                <thead class="bg-[var(--af-bg-chrome)] sticky top-0">
                                                                    <tr>
                                                                        {headers
                                                                            .into_iter()
                                                                            .map(|header| {
                                                                                view! {
                                                                                    <th class="px-3 py-2 font-semibold border-b border-[var(--af-border-hairline)] whitespace-nowrap">
                                                                                        {header}
                                                                                    </th>
                                                                                }
                                                                            })
                                                                            .collect_view()}
                                                                    </tr>
                                                                </thead>
                                                                <tbody class="divide-y divide-white/5">
                                                                    {rows
                                                                        .into_iter()
                                                                        .map(|cols| {
                                                                            view! {
                                                                                <tr>
                                                                                    {cols
                                                                                        .into_iter()
                                                                                        .map(|cell| {
                                                                                            view! {
                                                                                                <td class="px-3 py-1.5 whitespace-nowrap">
                                                                                                    {cell}
                                                                                                </td>
                                                                                            }
                                                                                        })
                                                                                        .collect_view()}
                                                                                </tr>
                                                                            }
                                                                        })
                                                                        .collect_view()}
                                                                </tbody>
                                                            </table>
                                                        </div>
                                                    </div>
                                                }
                                                .into_any()
                                            }
                                        })
                                    }}
                                </div>
                            }
                                .into_any()
                        }
                        "epub" => {
                            view! {
                                <div class="space-y-3" data-testid="epub-preview">
                                    <Show when=move || aux_loading.get()>
                                        <SkeletonBox class="h-44" />
                                    </Show>
                                    <Show when=move || !aux_error.get().is_empty()>
                                        <p role="alert" class="text-sm text-rose-300">
                                            {move || tt(context, &aux_error.get())}
                                        </p>
                                    </Show>
                                    {move || {
                                        epub_data.get().map(|book| {
                                            let chapter_count = book.chapters.len();
                                            let chapter_titles: Vec<(usize, String)> = book
                                                .chapters
                                                .iter()
                                                .enumerate()
                                                .map(|(idx, ch)| (idx, ch.title.clone()))
                                                .collect();
                                            let active_idx = epub_chapter
                                                .get()
                                                .min(chapter_count.saturating_sub(1));
                                            let paragraphs = book
                                                .chapters
                                                .get(active_idx)
                                                .map(|ch| ch.paragraphs.clone())
                                                .unwrap_or_default();
                                            let byline = match (book.author.is_empty(), book.language.is_empty()) {
                                                (false, false) => format!("{} · {}", book.author, book.language),
                                                (false, true) => book.author.clone(),
                                                (true, false) => book.language.clone(),
                                                (true, true) => String::new(),
                                            };
                                            view! {
                                                <div class="space-y-3">
                                                    <div class="border-b border-[var(--af-border-hairline)] pb-3">
                                                        <h3 class="font-semibold text-base break-words">{book.title}</h3>
                                                        {(!byline.is_empty()).then(|| view! {
                                                            <p class="text-xs text-slate-400 mt-1">{byline}</p>
                                                        })}
                                                        {(!book.description.is_empty()).then(|| view! {
                                                            <p class="text-xs text-slate-400 mt-2">{book.description}</p>
                                                        })}
                                                    </div>
                                                    <div class="flex flex-wrap items-center gap-2">
                                                        {(!chapter_titles.is_empty()).then(|| view! {
                                                            <button
                                                                type="button"
                                                                class="af-btn px-3 py-1 text-xs"
                                                                disabled=move || epub_chapter.get() == 0
                                                                on:click=move |_| epub_chapter.update(|c| *c = c.saturating_sub(1))
                                                            >
                                                                {move || tt(context, "Previous chapter")}
                                                            </button>
                                                            <select
                                                                class="af-input px-2 py-1 text-xs flex-1 min-w-40"
                                                                data-testid="epub-chapter-select"
                                                                aria-label=move || tt(context, "EPUB chapter")
                                                                prop:value=move || active_idx.to_string()
                                                                on:change=move |event| {
                                                                    if let Ok(parsed) = event_target_value(&event).parse::<usize>() {
                                                                        epub_chapter.set(parsed);
                                                                    }
                                                                }
                                                            >
                                                                {chapter_titles
                                                                    .into_iter()
                                                                    .map(|(idx, label)| {
                                                                        view! { <option value=idx.to_string()>{label}</option> }
                                                                    })
                                                                    .collect_view()}
                                                            </select>
                                                            <button
                                                                type="button"
                                                                class="af-btn px-3 py-1 text-xs"
                                                                disabled=move || {
                                                                    chapter_count == 0 || epub_chapter.get() + 1 >= chapter_count
                                                                }
                                                                on:click=move |_| {
                                                                    epub_chapter.update(|c| {
                                                                        if *c + 1 < chapter_count {
                                                                            *c += 1;
                                                                        }
                                                                    })
                                                                }
                                                            >
                                                                {move || tt(context, "Next chapter")}
                                                            </button>
                                                        })}
                                                        <button
                                                            type="button"
                                                            class="af-btn px-2 py-1 text-xs"
                                                            aria-label=move || tt(context, "Decrease font size")
                                                            disabled=move || { epub_font.get() <= 12 }
                                                            on:click=move |_| epub_font.update(|f| *f = f.saturating_sub(1).max(12))
                                                        >
                                                            "−"
                                                        </button>
                                                        <span class="text-xs font-mono tabular-nums">
                                                            {move || format!("{}px", epub_font.get())}
                                                        </span>
                                                        <button
                                                            type="button"
                                                            class="af-btn px-2 py-1 text-xs"
                                                            aria-label=move || tt(context, "Increase font size")
                                                            disabled=move || { epub_font.get() >= 24 }
                                                            on:click=move |_| epub_font.update(|f| *f = (*f + 1).min(24))
                                                        >
                                                            "+"
                                                        </button>
                                                    </div>
                                                    <article class=move || {
                                                        format!(
                                                            "af-surface-inset space-y-3 leading-relaxed max-h-[50vh] overflow-auto p-4 af-editor-fs-{}",
                                                            epub_font.get()
                                                        )
                                                    }>
                                                        {if paragraphs.is_empty() {
                                                            view! {
                                                                <p class="text-xs text-slate-400">
                                                                    {move || tt(context, "This chapter contains no readable text.")}
                                                                </p>
                                                            }
                                                                .into_any()
                                                        } else {
                                                            paragraphs
                                                                .into_iter()
                                                                .map(|paragraph| view! { <p>{paragraph}</p> })
                                                                .collect_view()
                                                                .into_any()
                                                        }}
                                                    </article>
                                                </div>
                                            }
                                        })
                                    }}
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
            </div>
            <Show when=move || metadata.with(Value::is_object)>
                <p class="text-xs text-slate-400 mt-3 font-mono" data-testid="media-preview-metadata">
                    {move || {
                        metadata.with(|info| {
                            let mut parts = Vec::new();
                            if let (Some(w), Some(h)) = (
                                info["resolution"]["width"].as_u64(),
                                info["resolution"]["height"].as_u64(),
                            ) {
                                parts.push(format!("{w}×{h}"));
                            }
                            if let Some(ct) = info["content_type"].as_str().filter(|s| !s.is_empty()) {
                                parts.push(ct.to_owned());
                            }
                            if let Some(size) = info["size"].as_u64() {
                                parts.push(bytes(size));
                            }
                            parts.join(" · ")
                        })
                    }}
                </p>
            </Show>
            <Show when=move || failed.get()>
                <p role="alert" class="text-sm text-rose-300 mt-3">
                    {move || tt(
                        context,
                        "Preview could not load. Check file permissions or download the original.",
                    )}
                </p>
            </Show>
            <Show when=move || can_download.get() && !path.with(String::is_empty)>
                <a
                    class="af-btn inline-block px-4 py-2 mt-3"
                    href=move || {
                        context.server_epoch.track();
                        let server = context.active_server_id.get();
                        mcbrowser_preview_download_href(server.as_deref(), &encode(&path.get()))
                            .unwrap_or_default()
                    }
                    download=move || leaf(&path.get()).to_owned()
                >
                    {move || tt(context, "Download original")}
                </a>
            </Show>
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

    #[test]
    fn preview_helpers_bound_zoom_filter_subtitles_and_extract_inert_epub_paragraphs() {
        assert_eq!(next_zoom(100, true), 125);
        assert_eq!(next_zoom(300, true), 300);
        assert_eq!(next_zoom(50, false), 50);

        let subs = json!({
            "subtitles": [
                {
                    "url": "/api/v1/auth/mcbrowser/subtitle?path=clip.en.vtt",
                    "label": "English",
                    "language": "en"
                },
                {
                    "url": "https://evil.example/inject.vtt",
                    "label": "Evil",
                    "language": "xx"
                }
            ]
        });
        let parsed_subs = parse_subtitle_tracks(&subs, None);
        assert_eq!(parsed_subs.len(), 1);
        assert_eq!(parsed_subs[0].1, "English");

        let ch_paragraphs = epub_chapter_paragraphs(&json!({
            "paragraphs": ["  First <script>x</script>  ", "", "Second"]
        }));
        assert_eq!(ch_paragraphs, vec!["First <script>x</script>", "Second"]);

        let ch_fallback = epub_chapter_paragraphs(&json!({
            "text": "Para one\n\nPara two"
        }));
        assert_eq!(ch_fallback, vec!["Para one", "Para two"]);

        let valid_book = decode_epub_preview(
            &json!({
                "path": "book.epub",
                "title": "Guide",
                "author": "Team",
                "language": "en",
                "description": null,
                "chapters": [
                    { "id": "c1", "title": "", "href": "c1.xhtml", "paragraphs": ["Hello"], "text": "Hello" }
                ]
            }),
            "book.epub",
        )
        .expect("valid epub");
        assert_eq!(valid_book.title, "Guide");
        assert_eq!(valid_book.language, "en");
        assert_eq!(valid_book.chapters[0].title, "Chapter 1");
        assert!(decode_epub_preview(&json!({"title": "broken"}), "book.epub").is_err());
    }

    struct ActiveServerGuard;
    impl ActiveServerGuard {
        fn new(server: Option<&str>) -> Self {
            af_web_core::api::set_active_server(server.map(str::to_string));
            Self
        }
    }
    impl Drop for ActiveServerGuard {
        fn drop(&mut self) {
            af_web_core::api::set_active_server(None);
        }
    }

    #[test]
    fn preview_media_subtitle_and_download_urls_stay_same_origin_for_active_peer() {
        let _guard = ActiveServerGuard::new(Some("media-2"));
        let subs = json!({
            "subtitles": [
                {
                    "url": "/api/v1/auth/mcbrowser/subtitle?path=movies%2Fclip.en.vtt",
                    "label": "English",
                    "language": "en"
                },
                {
                    "url": "https://evil.example/inject.vtt",
                    "label": "Evil",
                    "language": "xx"
                },
                {
                    "url": "/api/v1/peers/other/auth/mcbrowser/subtitle?path=clip.en.vtt",
                    "label": "Spoofed",
                    "language": "xx"
                }
            ]
        });
        let parsed_subs = parse_subtitle_tracks(&subs, Some("media-2"));
        assert_eq!(parsed_subs.len(), 1);
        assert_eq!(
            parsed_subs[0].0,
            "/api/v1/peers/media-2/auth/mcbrowser/subtitle?path=movies%2Fclip.en.vtt"
        );
        let video_src = mcbrowser_media_url_encoded("movies%2Fclip.mp4");
        assert_eq!(
            video_src,
            "/api/v1/peers/media-2/auth/mcbrowser/media?path=movies%2Fclip.mp4"
        );
        assert!(video_src.starts_with('/') && !video_src.starts_with("//"));
        assert!(parsed_subs[0].0.starts_with('/') && !parsed_subs[0].0.starts_with("//"));
        assert_eq!(
            mcbrowser_preview_big_url_encoded("photos%2Fhero.jpg"),
            "/api/v1/peers/media-2/auth/mcbrowser/preview/big?path=photos%2Fhero.jpg"
        );
        assert_eq!(
            mcbrowser_download_url_encoded("docs%2Fguide.pdf"),
            "/api/v1/peers/media-2/auth/mcbrowser/download?path=docs%2Fguide.pdf"
        );
        assert_eq!(
            mcbrowser_preview_download_href(Some("media-2"), "docs%2Fguide.pdf").as_deref(),
            Some("/api/v1/peers/media-2/auth/mcbrowser/download?path=docs%2Fguide.pdf")
        );
        assert_eq!(
            mcbrowser_preview_download_href(None, "docs%2Fguide.pdf").as_deref(),
            Some("/api/v1/auth/mcbrowser/download?path=docs%2Fguide.pdf")
        );
        assert_eq!(mcbrowser_preview_download_href(Some("media-2"), ""), None);
    }
}
