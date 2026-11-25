use crate::state::{
    app, json_rows, owned_resource_reads, query_param, run_resource_read, ResourceReads,
};
use af_web_core::api::{ApiClient, ApiError, BODY_LIMIT_EXCEEDED};
use gloo_events::EventListener;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

fn normalize_path(path: &str) -> Option<String> {
    if path.starts_with('/') || path.contains('\\') || path.chars().any(char::is_control) {
        return None;
    }
    let parts: Vec<_> = path
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if parts.len() > 64 || path.len() > 4096 || parts.iter().any(|p| *p == ".." || p.len() > 255) {
        return None;
    }
    Some(parts.join("/"))
}
fn valid_token(token: &str) -> bool {
    (16..=256).contains(&token.len())
        && !token
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\' | '?' | '#'))
}
fn error_text(error: af_web_core::api::ApiError) -> String {
    match error.status {
        404 | 410 => "Share.expired".into(),
        429 => "Share.tooManyAttempts".into(),
        _ => error.message,
    }
}

fn display_filename(name: Option<String>, fallback: impl FnOnce() -> String) -> String {
    name.filter(|name| !name.is_empty())
        .unwrap_or_else(fallback)
}

#[derive(Clone, Default, PartialEq, Eq)]
struct ShareDirectory {
    path: String,
    revision: u64,
}

impl ShareDirectory {
    fn navigate(&mut self, path: String) {
        self.path = path;
        self.revision += 1;
    }
}

#[derive(Clone)]
struct ShareListing {
    directory: ShareDirectory,
    entries: Vec<Value>,
}

fn listing_entry_path(directory: &str, entry: &Value) -> Option<String> {
    let path = normalize_path(entry["path"].as_str()?)?;
    if path.is_empty() || path.rsplit_once('/').map_or("", |(parent, _)| parent) != directory {
        return None;
    }
    Some(path)
}

fn preview_mime(content_type: &str, name: &str) -> String {
    let reported = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !matches!(
        reported.as_str(),
        "" | "application/octet-stream" | "binary/octet-stream"
    ) {
        return reported;
    }
    // Public downloads are generic attachments. Infer only inert preview types
    // from the server-provided name; text is rendered as an escaped text node.
    let extension = name.rsplit_once('.').map(|(_, extension)| extension);
    let inferred = match extension.unwrap_or_default().to_ascii_lowercase().as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        "wav" => "audio/wav",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "opus" => "audio/opus",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "flac" => "audio/flac",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "ogv" => "video/ogg",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "txt" | "md" | "markdown" | "csv" | "log" => "text/plain",
        "json" => "application/json",
        "xml" => "application/xml",
        _ => return reported,
    };
    inferred.into()
}

const MEDIA_PREVIEW_MAX_BYTES: u32 = 20 * 1024 * 1024;
const TEXT_PREVIEW_MAX_BYTES: u32 = 1024 * 1024;
const PREVIEW_LONG_LINE_TRIGGER_BYTES: usize = 16 * 1024;
const PREVIEW_TEXT_SEGMENT_MAX_BYTES: usize = 8 * 1024;

fn split_preview_text_segments(text: &str) -> Option<Vec<String>> {
    split_preview_text_segments_with(
        text,
        PREVIEW_LONG_LINE_TRIGGER_BYTES,
        PREVIEW_TEXT_SEGMENT_MAX_BYTES,
    )
}

fn split_preview_text_segments_with(
    text: &str,
    trigger_line_bytes: usize,
    max_segment_bytes: usize,
) -> Option<Vec<String>> {
    debug_assert!(max_segment_bytes >= 4);
    if !text
        .split_inclusive('\n')
        .any(|line| line.len() > trigger_line_bytes)
    {
        return None;
    }

    let mut segments = Vec::new();
    let mut current = String::new();

    for line in text.split_inclusive('\n') {
        if line.len() <= max_segment_bytes {
            if !current.is_empty() && current.len() + line.len() > max_segment_bytes {
                segments.push(std::mem::take(&mut current));
            }
            current.push_str(line);
            continue;
        }

        if !current.is_empty() {
            segments.push(std::mem::take(&mut current));
        }

        let mut remaining = line;
        while remaining.len() > max_segment_bytes {
            let mut end = max_segment_bytes;
            while end > 0 && !remaining.is_char_boundary(end) {
                end -= 1;
            }
            if end > 1
                && remaining.as_bytes()[end - 1] == b'\r'
                && remaining.as_bytes().get(end) == Some(&b'\n')
            {
                end -= 1;
            }
            let tail = &remaining[end..];
            if (tail == "\n" || tail == "\r\n") && end > 1 {
                end -= 1;
                while end > 0 && !remaining.is_char_boundary(end) {
                    end -= 1;
                }
            }
            if end == 0 {
                end = remaining
                    .chars()
                    .next()
                    .map_or(remaining.len(), char::len_utf8);
            }
            let (chunk, rest) = remaining.split_at(end);
            segments.push(chunk.to_string());
            remaining = rest;
        }
        if !remaining.is_empty() {
            segments.push(remaining.to_string());
        }
    }

    if !current.is_empty() {
        segments.push(current);
    }

    Some(segments)
}

enum PreviewContent {
    Media(String, web_sys::Blob),
    Text(String),
}

enum PreviewError {
    Status(u16),
    Message(String),
}

fn preview_body_error(error: ApiError, limit_message: &str) -> PreviewError {
    PreviewError::Message(
        if error.code.as_deref() == Some(BODY_LIMIT_EXCEEDED) {
            limit_message
        } else {
            "Share.previewUnavailable"
        }
        .into(),
    )
}

fn share_token() -> String {
    query_param("token").unwrap_or_default().trim().to_string()
}

#[component]
pub fn SharePage() -> impl IntoView {
    let token = RwSignal::new(share_token());
    let history = StoredValue::new_local(web_sys::window().map(|window| {
        EventListener::new(&window, "popstate", move |_| {
            if web_sys::window()
                .and_then(|window| window.location().pathname().ok())
                .is_some_and(|path| path.trim_end_matches('/') == "/share")
            {
                token.set(share_token());
            }
        })
    }));
    on_cleanup(move || history.set_value(None));
    // Each token owns its view and reads, including when history traversal
    // revisits a share in the same document.
    view! {
        <For
            each=move || [token.get()]
            key=String::clone
            children=move |token| view! { <ShareContent token/> }
        />
    }
}

#[component]
fn ShareContent(token: String) -> impl IntoView {
    let context = app();
    let valid = valid_token(&token);
    let base = StoredValue::new(format!(
        "/api/v1/public/mcbrowser/shares/{}",
        js_sys::encode_uri_component(&token)
    ));
    let metadata = RwSignal::new(Value::Null);
    let locked = RwSignal::new(false);
    let password = RwSignal::new(String::new());
    let busy = RwSignal::new(valid);
    let error = RwSignal::new(if valid {
        String::new()
    } else {
        "Share.invalidToken".into()
    });
    let preview_status = RwSignal::new(0u16);
    let directory = RwSignal::new(ShareDirectory::default());
    let listing = RwSignal::new(None::<ShareListing>);
    let listing_busy = RwSignal::new(false);
    let listing_generation = RwSignal::new(0u64);
    let listing_ready = move || {
        !listing_busy.get()
            && listing.with(|value| {
                value
                    .as_ref()
                    .is_some_and(|value| value.directory == directory.get())
            })
    };
    let file = RwSignal::new(String::new());
    let selected_name = RwSignal::new(None::<String>);
    let display_selected_name =
        move || display_filename(selected_name.get(), || context.t("Share.file"));
    let preview_text = RwSignal::new(String::new());
    let media = RwSignal::new((String::new(), String::new()));
    let preview_busy = RwSignal::new(false);
    let preview_generation = RwSignal::new(0u64);
    let metadata_reads = owned_resource_reads();
    let listing_reads = owned_resource_reads();
    let preview_reads = owned_resource_reads();
    let object_url = StoredValue::new_local(None::<String>);
    let revoke_preview_url = move || {
        if let Some(Some(url)) = object_url.try_update_value(Option::take) {
            let _ = web_sys::Url::revoke_object_url(&url);
        }
    };
    on_cleanup(revoke_preview_url);
    let reset_preview = move || {
        preview_generation.update(|generation| *generation += 1);
        preview_reads.with_value(ResourceReads::cancel);
        revoke_preview_url();
        preview_text.set(String::new());
        media.set((String::new(), String::new()));
        preview_status.set(0);
        preview_busy.set(false);
        error.set(String::new());
    };
    let invalidate_selection = move || {
        reset_preview();
        file.set(String::new());
        selected_name.set(None);
    };
    let transfers_allowed = move || metadata.with(|value| value["allow_download"] == true);
    let preview_ready = move || {
        !locked.get()
            && transfers_allowed()
            && metadata.with(|value| {
                value["is_directory"] != true || (!file.get().is_empty() && listing_ready())
            })
    };
    Effect::new(move |_| {
        if !valid {
            return;
        }
        busy.set(true);
        let base = base.get_value();
        let Some(job) = metadata_reads.try_update_value(ResourceReads::next) else {
            return;
        };
        spawn_local(async move {
            let Some(result) =
                run_resource_read(job, ApiClient.public_request(&base, "GET", None)).await
            else {
                return;
            };
            if busy.try_get_untracked().is_none() {
                return;
            }
            match result {
                Ok(data) => {
                    locked.set(data["password_required"] == true && data["unlocked"] != true);
                    selected_name.set(
                        data["name"]
                            .as_str()
                            .filter(|name| !name.is_empty())
                            .map(str::to_string),
                    );
                    metadata.set(data);
                }
                Err(e) => error.set(error_text(e)),
            }
            busy.set(false);
        });
    });
    Effect::new(move |_| {
        let data = metadata.get();
        let requested = directory.get();
        let locked = locked.get();
        listing_generation.update(|generation| *generation += 1);
        let ticket = listing_generation.get_untracked();
        if data["is_directory"] != true || locked {
            listing_reads.with_value(ResourceReads::cancel);
            listing_busy.set(false);
            return;
        }
        listing_busy.set(true);
        error.set(String::new());
        let endpoint = format!(
            "{}/entries?path={}",
            base.get_value(),
            js_sys::encode_uri_component(&requested.path)
        );
        let Some(job) = listing_reads.try_update_value(ResourceReads::next) else {
            return;
        };
        spawn_local(async move {
            let Some(result) =
                run_resource_read(job, ApiClient.public_request(&endpoint, "GET", None)).await
            else {
                return;
            };
            // The navigation revision rejects same-path round trips as well as
            // other superseded requests. Disposed signals reject late results.
            if listing_generation.try_get_untracked() != Some(ticket)
                || directory.try_get_untracked().as_ref() != Some(&requested)
            {
                return;
            }
            match result {
                Ok(data) => {
                    if data["path"].as_str().and_then(normalize_path).as_deref()
                        == Some(requested.path.as_str())
                    {
                        listing.set(Some(ShareListing {
                            directory: requested,
                            entries: json_rows(&data),
                        }));
                    } else {
                        error.set("Share.previewUnavailable".into());
                    }
                }
                Err(e) => error.set(error_text(e)),
            }
            listing_busy.set(false);
        });
    });
    let unlock = move |event: web_sys::SubmitEvent| {
        event.prevent_default();
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let password_value = password.get_untracked();
        let base = base.get_value();
        spawn_local(async move {
            let result = ApiClient
                .public_request(
                    &format!("{base}/unlock"),
                    "POST",
                    Some(&json!({"password":password_value})),
                )
                .await;
            if busy.try_get_untracked().is_none() {
                return;
            }
            match result {
                Ok(_) => {
                    password.set(String::new());
                    locked.set(false);
                    metadata.update(|meta| meta["unlocked"] = json!(true));
                    error.set(String::new());
                }
                Err(e) => error.set(error_text(e)),
            }
            busy.set(false);
        });
    };
    let preview = move || {
        if !preview_ready() {
            return;
        }
        reset_preview();
        let ticket = preview_generation.get_untracked();
        let Some(job) = preview_reads.try_update_value(ResourceReads::next) else {
            return;
        };
        let path = file.get_untracked();
        let name = selected_name.get_untracked();
        let endpoint = format!(
            "{}/download?path={}",
            base.get_value(),
            js_sys::encode_uri_component(&path)
        );
        preview_busy.set(true);
        spawn_local(async move {
            let work = async move {
                let response = ApiClient
                    .public_fetch(&endpoint, "GET", None)
                    .await
                    .map_err(|error| PreviewError::Message(error_text(error)))?;
                if !response.ok() {
                    return Err(PreviewError::Status(response.status()));
                }
                let content_type = response
                    .headers()
                    .get("Content-Type")
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let mime = preview_mime(&content_type, name.as_deref().unwrap_or_default());
                if mime.starts_with("image/") && mime != "image/svg+xml"
                    || mime.starts_with("video/")
                    || mime.starts_with("audio/")
                {
                    let blob = response
                        .blob_limited(MEDIA_PREVIEW_MAX_BYTES, &mime)
                        .await
                        .map_err(|error| preview_body_error(error, "Share.tooLarge"))?;
                    Ok(PreviewContent::Media(mime, blob))
                } else if mime.starts_with("text/") || mime.contains("json") || mime.contains("xml")
                {
                    let text = response
                        .text_limited(TEXT_PREVIEW_MAX_BYTES)
                        .await
                        .map_err(|error| preview_body_error(error, "Share.textLimit"))?;
                    Ok(PreviewContent::Text(text))
                } else {
                    Err(PreviewError::Message("Share.unsupportedPreview".into()))
                }
            };
            let Some(result) = run_resource_read(job, work).await else {
                return;
            };
            if preview_generation.try_get_untracked() != Some(ticket) {
                return;
            }
            match result {
                Ok(PreviewContent::Media(_, blob))
                    if blob.size() > f64::from(MEDIA_PREVIEW_MAX_BYTES) =>
                {
                    error.set("Share.tooLarge".into());
                }
                Ok(PreviewContent::Media(mime, blob)) => {
                    match web_sys::Url::create_object_url_with_blob(&blob) {
                        Ok(url) => {
                            object_url.set_value(Some(url.clone()));
                            media.set((mime, url));
                        }
                        Err(_) => error.set("Share.previewUnavailable".into()),
                    }
                }
                Ok(PreviewContent::Text(text)) => preview_text.set(text),
                Err(PreviewError::Status(status)) => {
                    preview_status.set(status);
                    error.set("Share.previewStatus".into());
                }
                Err(PreviewError::Message(message)) => error.set(message),
            }
            preview_busy.set(false);
        });
    };
    view! {
        <main id="main-content" tabindex="-1" class="af-public-route min-h-screen px-5 py-10">
            <crate::shell::PublicRouteToolbar/>
            <div class="max-w-4xl mx-auto min-w-0 space-y-6">
                <header class="flex items-center gap-4">
                    <img src="/img/aetherflow-mark.svg" class="w-12 h-12" alt="AetherFlow"/>
                    <div>
                        <p class="text-xs text-indigo-300 uppercase tracking-widest">
                            {move || context.t("Share.subtitle")}
                        </p>
                        <h1 class="text-2xl font-semibold mt-1">{move || context.t("Routes.shareHeading")}</h1>
                        <p class="text-sm text-slate-400 mt-1 break-all">
                            {move || metadata.with(|value| value["name"].as_str().unwrap_or_default().to_string())}
                        </p>
                    </div>
                </header>
                <Show when=move || busy.get()>
                    <p role="status" class="text-slate-400">{move || context.t("Share.loading")}</p>
                </Show>
                <Show when=move || !error.get().is_empty()>
                    <p role="alert" class="af-danger-banner">{move || {
                        let msg = error.get();
                        if msg.is_empty() {
                            String::new()
                        } else if msg == "Share.previewStatus" {
                            context.t_with(&msg, &[("status", &preview_status.get().to_string())])
                        } else {
                            context.t(&msg)
                        }
                    }}</p>
                </Show>
                <Show when=move || locked.get()>
                    <af_web_ui::ObsCard title=Signal::derive(move || context.t("Share.passwordRequired"))>
                        <form on:submit=unlock class="flex flex-wrap gap-3">
                            <label for="share-password" class="w-full text-sm text-slate-400">
                                {move || context.t("Share.passwordDescription")}
                            </label>
                            <input
                                id="share-password" type="password"
                                class="af-input px-3 py-2 flex-1 min-w-0"
                                autocomplete="current-password" required=true
                                placeholder=move || context.t("Share.password")
                                prop:value=move || password.get()
                                on:input=move |event| password.set(event_target_value(&event))
                            />
                            <button type="submit" class="af-btn-primary px-4" disabled=move || busy.get()>
                                {move || context.t("Share.unlock")}
                            </button>
                        </form>
                    </af_web_ui::ObsCard>
                </Show>
                <Show when=move || !locked.get() && !metadata.with(Value::is_null)>
                    <p class="text-sm text-slate-400">
                        {move || metadata.with(|value| {
                            let kind = context.t(if value["is_directory"] == true { "Share.directory" } else { "Share.file" });
                            let expiry = value["expires_at"].as_str().map(str::to_string)
                                .unwrap_or_else(|| context.t("Share.noExpiry"));
                            context.t_with("Share.expires", &[("kind", &kind), ("expiry", &expiry)])
                        })}
                    </p>
                    <Show when=move || metadata.with(|value| value["is_directory"] == true)>
                        <af_web_ui::ObsCard title=Signal::derive(move || context.t("Share.files"))>
                            <div class="flex gap-3 mb-4">
                                <button
                                    class="af-btn px-3"
                                    disabled=move || directory.with(|value| value.path.is_empty())
                                    on:click=move |_| {
                                        invalidate_selection();
                                        directory.update(|value| {
                                        let parent = value.path.rsplit_once('/').map(|(parent, _)| parent.to_string()).unwrap_or_default();
                                        value.navigate(parent);
                                        });
                                    }
                                >
                                    {move || context.t("Share.parent")}
                                </button>
                                <p class="text-slate-400 break-all">{move || format!("/{}", directory.get().path)}</p>
                            </div>
                            <Show when=move || listing_busy.get()>
                                <p role="status">{move || context.t("Share.loading")}</p>
                            </Show>
                            <Show when=move || !listing_busy.get() && !listing_ready()>
                                <button class="af-btn px-3 py-2" on:click=move |_| {
                                    invalidate_selection();
                                    directory.update(|value| value.revision += 1);
                                }>
                                    {move || context.t("Common.retry")}
                                </button>
                            </Show>
                            <ul class="divide-y divide-white/10" aria-busy=move || if listing_busy.get() { "true" } else { "false" }>
                                {move || {
                                    let snapshot = listing.get();
                                    let snapshot_directory = snapshot.as_ref().map(|value| value.directory.clone()).unwrap_or_default();
                                    snapshot.into_iter().flat_map(|value| value.entries).map(|entry| {
                                    let selected_entry_name = entry["name"].as_str().filter(|name| !name.is_empty()).map(str::to_string);
                                    let name = selected_entry_name.clone().unwrap_or_else(|| context.t("Share.entry"));
                                    let display = name;
                                    let origin = snapshot_directory.clone();
                                    let path = listing_entry_path(&origin.path, &entry);
                                    let invalid_path = path.is_none();
                                    let is_directory = entry["is_directory"] == true || entry["kind"] == "directory";
                                    view! {
                                        <li>
                                            <button
                                                class="w-full py-3 text-left flex justify-between gap-3"
                                                disabled=move || invalid_path || !listing_ready() || (!is_directory && !transfers_allowed())
                                                on:click=move |_| {
                                                    if !listing_ready() || directory.get_untracked() != origin {
                                                        return;
                                                    }
                                                    if let Some(path) = path.clone() {
                                                        if is_directory {
                                                            invalidate_selection();
                                                            directory.update(|value| value.navigate(path));
                                                        } else {
                                                            if !transfers_allowed() { return; }
                                                            file.set(path);
                                                            selected_name.set(selected_entry_name.clone());
                                                            preview();
                                                        }
                                                    }
                                                }
                                            >
                                                <span>{if is_directory { "▱ " } else { "◇ " }}{display}</span>
                                                <span class="text-xs text-slate-400">
                                                    {move || entry["size"].as_u64().map(|count| {
                                                        context.t_with("Share.bytes", &[("count", &count.to_string())])
                                                    }).unwrap_or_default()}
                                                </span>
                                            </button>
                                        </li>
                                    }
                                }).collect_view()}}
                            </ul>
                        </af_web_ui::ObsCard>
                    </Show>
                    <Show when=transfers_allowed>
                    <div class="flex flex-wrap gap-3">
                        <button class="af-btn px-4 py-2" disabled=move || preview_busy.get() || !preview_ready() on:click=move |_| preview()>
                            {move || context.t("Share.preview")}
                        </button>
                        <Show when=preview_ready>
                            <a
                                class="af-btn-primary px-4 py-2"
                                href=move || format!("{}/download?path={}", base.get_value(), js_sys::encode_uri_component(&file.get()))
                                download=display_selected_name
                            >
                                {move || context.t("Common.download")}
                            </a>
                        </Show>
                    </div>
                    </Show>
                    <Show when=move || preview_busy.get()>
                        <p role="status">{move || context.t("Share.loadingPreview")}</p>
                    </Show>
                    <Show when=move || preview_text.with(|text| !text.is_empty())>
                        <pre class="af-card p-5 obs-scroller max-h-[65vh] text-sm whitespace-pre-wrap break-words">
                            {move || {
                                preview_text.with(|text| match split_preview_text_segments(text) {
                                    Some(segments) => segments
                                        .into_iter()
                                        .map(|segment| {
                                            view! { <span class="af-share-text-chunk">{segment}</span> }
                                        })
                                        .collect_view()
                                        .into_any(),
                                    None => text.clone().into_any(),
                                })
                            }}
                        </pre>
                    </Show>
                    {move || {
                        let (mime, url) = media.get();
                        if mime.starts_with("image/") {
                            view! { <img src=url alt=display_selected_name class="max-w-full max-h-[65vh] object-contain"/> }.into_any()
                        } else if mime.starts_with("video/") {
                            view! { <video src=url controls=true class="max-w-full max-h-[65vh]"></video> }.into_any()
                        } else if mime.starts_with("audio/") {
                            view! { <audio src=url controls=true class="max-w-full"></audio> }.into_any()
                        } else {
                            ().into_any()
                        }
                    }}
                </Show>
                <a href="/login" class="text-sm text-indigo-300 inline-block">{move || context.t("Share.open")}</a>
            </div>
        </main>
    }
}

#[cfg(test)]
mod tests {
    use super::{
        display_filename, listing_entry_path, normalize_path, owned_resource_reads, preview_mime,
        run_resource_read, split_preview_text_segments, split_preview_text_segments_with,
        valid_token, ResourceReads, PREVIEW_LONG_LINE_TRIGGER_BYTES,
        PREVIEW_TEXT_SEGMENT_MAX_BYTES, TEXT_PREVIEW_MAX_BYTES,
    };
    use leptos::prelude::*;
    use std::{
        future::{pending, Future},
        pin::pin,
        rc::Rc,
        task::{Context, Poll, Waker},
    };

    #[test]
    fn disposing_preview_owner_drops_pending_work() {
        let owner = Owner::new();
        let reads = owner.with(owned_resource_reads);
        let job = reads.try_update_value(ResourceReads::next).unwrap();
        let guard = Rc::new(());
        let alive = Rc::downgrade(&guard);
        let mut preview = pin!(run_resource_read(job, async move {
            pending::<()>().await;
            drop(guard);
        }));
        let mut context = Context::from_waker(Waker::noop());
        assert!(preview.as_mut().poll(&mut context).is_pending());
        assert!(alive.upgrade().is_some());

        owner.cleanup();
        assert_eq!(preview.as_mut().poll(&mut context), Poll::Ready(None));
        assert!(alive.upgrade().is_none());
    }
    use serde_json::json;

    #[test]
    fn listing_actions_use_share_relative_server_paths() {
        assert_eq!(
            listing_entry_path("", &json!({"name":"Archive", "path":"Archive"})),
            Some("Archive".into())
        );
        assert_eq!(
            listing_entry_path("資料", &json!({"name":"café.txt", "path":"資料/café.txt"})),
            Some("資料/café.txt".into())
        );
        assert_eq!(
            listing_entry_path(
                "alias",
                &json!({"name":"report.txt", "path":"alias/report.txt"})
            ),
            Some("alias/report.txt".into())
        );
        for entry in [
            json!({"name":"report.txt"}),
            json!({"path":"report.txt"}),
            json!({"path":"docs/../report.txt"}),
            json!({"path":"/docs/report.txt"}),
            json!({"path":"other/report.txt"}),
            json!({"path":"docs/sub/report.txt"}),
        ] {
            assert_eq!(listing_entry_path("docs", &entry), None, "{entry}");
        }
    }

    #[test]
    fn shared_filenames_are_verbatim_even_when_they_match_catalog_keys() {
        for name in ["Archive", "Copy", "Share.file", "été.txt"] {
            assert_eq!(
                display_filename(Some(name.into()), || panic!(
                    "filename must not be translated"
                )),
                name
            );
        }
        for name in [None, Some(String::new())] {
            assert_eq!(display_filename(name, || "Fichier".into()), "Fichier");
        }
    }

    #[test]
    fn share_previews_infer_inert_types_for_generic_attachment_responses() {
        for header in [
            "",
            "application/octet-stream",
            "BINARY/OCTET-STREAM; charset=binary",
        ] {
            for (name, expected) in [
                ("silence.WAV", "audio/wav"),
                ("music.mp3", "audio/mpeg"),
                ("photo.png", "image/png"),
                ("movie.webm", "video/webm"),
                ("notes.md", "text/plain"),
                ("data.json", "application/json"),
            ] {
                assert_eq!(preview_mime(header, name), expected);
            }
        }
        assert_eq!(
            preview_mime("Text/Plain; charset=UTF-8", "photo.png"),
            "text/plain"
        );
    }

    #[test]
    fn share_previews_do_not_promote_active_or_unknown_attachments() {
        for name in [
            "page.html",
            "page.xhtml",
            "image.svg",
            "image.svgz",
            "file.pdf",
            "file.bin",
            "wav",
        ] {
            assert_eq!(
                preview_mime("application/octet-stream", name),
                "application/octet-stream"
            );
        }
        assert_eq!(
            preview_mime("image/svg+xml; charset=utf-8", "photo.png"),
            "image/svg+xml"
        );
    }

    #[test]
    fn share_tokens_enforce_length_and_url_delimiter_bounds() {
        assert!(valid_token("abcdef0123456789-_"));
        assert!(valid_token(&"a".repeat(256)));
        for token in [String::new(), "a".repeat(15), "a".repeat(257)] {
            assert!(!valid_token(&token));
        }
        for invalid in ['/', '\\', '?', '#', '\n', '\0', ' ', '\u{2003}'] {
            assert!(
                !valid_token(&format!("abcdef0123456789{invalid}")),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn share_paths_normalize_relative_components_and_keep_utf8_names() {
        for (path, expected) in [
            ("", ""),
            (".", ""),
            ("docs//./file.txt/", "docs/file.txt"),
            ("資料/café.txt", "資料/café.txt"),
        ] {
            assert_eq!(normalize_path(path).as_deref(), Some(expected));
        }
    }

    #[test]
    fn share_paths_reject_traversal_absolute_control_and_oversized_inputs() {
        for path in [
            "/etc/passwd",
            "//host/share",
            "../file",
            "docs/../file",
            "docs\\file",
            "docs/\0file",
            "docs/\nfile",
        ] {
            assert_eq!(normalize_path(path), None, "{path:?}");
        }
        assert!(normalize_path(&"a".repeat(255)).is_some());
        assert!(normalize_path(&"a".repeat(256)).is_none());
        assert!(normalize_path(&vec!["a"; 64].join("/")).is_some());
        assert!(normalize_path(&vec!["a"; 65].join("/")).is_none());
        assert!(normalize_path(&"./".repeat(2048)).is_some());
        assert!(normalize_path(&"./".repeat(2049)).is_none());
        assert!(normalize_path(&"é".repeat(128)).is_none());
    }

    #[test]
    fn preview_text_leaves_normal_multiline_files_unsegmented() {
        assert_eq!(split_preview_text_segments(""), None);
        assert_eq!(split_preview_text_segments("hello\nworld\n"), None);
        let at_trigger = format!(
            "{}\nshort\n",
            "a".repeat(PREVIEW_LONG_LINE_TRIGGER_BYTES - 1)
        );
        assert_eq!(split_preview_text_segments(&at_trigger), None);
    }

    #[test]
    fn preview_text_segments_long_lines_preserving_exact_utf8_and_crlf_bytes() {
        let suffix = "λ🙂 original text\n";
        let exact_limit = format!(
            "{}{suffix}",
            "a".repeat(TEXT_PREVIEW_MAX_BYTES as usize - suffix.len())
        );
        let segments = split_preview_text_segments(&exact_limit).expect("1 MiB line must segment");
        assert!(segments.len() > 1);
        assert!(segments
            .iter()
            .all(|segment| !segment.is_empty() && segment.len() <= PREVIEW_TEXT_SEGMENT_MAX_BYTES));
        assert_eq!(segments.concat(), exact_limit);

        let mixed = format!("header\n\n{}λ🙂\r\nfooter\n", "b".repeat(20_000));
        let mixed_segments = split_preview_text_segments(&mixed).expect("mixed long line segments");
        assert_eq!(mixed_segments.concat(), mixed);
        assert!(mixed_segments
            .iter()
            .all(|segment| segment != "\n" && segment != "\r\n"));

        // Exercise multibyte UTF-8 and CRLF right on a small synthetic boundary.
        let crlf_edge = "1234567\r\n";
        let crlf_segments = split_preview_text_segments_with(crlf_edge, 8, 8).unwrap();
        assert_eq!(crlf_segments, vec!["123456", "7\r\n"]);

        let emoji_edge = "aaaa🙂\n";
        let emoji_segments = split_preview_text_segments_with(emoji_edge, 8, 8).unwrap();
        assert_eq!(emoji_segments, vec!["aaaa", "🙂\n"]);
    }
}
