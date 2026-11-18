use crate::{ui_t, ui_t_with};
use af_web_core::{
    markdown::highlighted_html,
    worker::{WorkerRequest, WorkerResponse, MAX_EDITOR_BYTES},
    worker_pool::WorkerPool,
};
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

#[derive(Clone)]
enum EditorStatus {
    Message(String),
    Replaced(usize),
}

impl EditorStatus {
    fn text(&self) -> String {
        match self {
            Self::Message(key) => ui_t(key),
            Self::Replaced(count) => {
                ui_t_with("Replaced {count} matches", &[("count", &count.to_string())])
            }
        }
    }
}

fn line_count(text: &str) -> usize {
    text.bytes().filter(|byte| *byte == b'\n').count() + 1
}

fn gutter_text(text: &str) -> String {
    (1..=line_count(text))
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}
fn within_editor_limit(text: &str) -> bool {
    text.len() <= MAX_EDITOR_BYTES
}
fn byte_offset(text: &str, utf16: u32) -> usize {
    let mut units = 0;
    for (index, c) in text.char_indices() {
        if units >= utf16 {
            return index;
        }
        units += c.len_utf16() as u32;
    }
    text.len()
}
fn record_edit(
    value: RwSignal<String>,
    undo: RwSignal<Vec<String>>,
    redo: RwSignal<Vec<String>>,
    next: String,
) {
    if !within_editor_limit(&next) {
        return;
    }
    let previous = value.get_untracked();
    if previous == next {
        return;
    }
    undo.update(|history| {
        history.push(previous);
        if history.len() > 100 {
            history.remove(0);
        }
    });
    redo.set(vec![]);
    value.set(next);
}
#[component]
pub fn McBrowserCodeEditor(
    value: RwSignal<String>,
    #[prop(into)] language: String,
    #[prop(optional, into)] readonly: Signal<bool>,
    #[prop(optional)] on_save: Option<Callback<String>>,
    #[prop(default = true)] show_save: bool,
) -> impl IntoView {
    let pool = StoredValue::new_local(WorkerPool::shared());
    let lang = StoredValue::new(language);
    let highlighted = RwSignal::new(String::new());
    let generation = RwSignal::new(0u64);
    let textarea = NodeRef::<leptos::html::Textarea>::new();
    let overlay = NodeRef::<leptos::html::Pre>::new();
    let gutter = NodeRef::<leptos::html::Pre>::new();
    let undo = RwSignal::new(Vec::<String>::new());
    let redo = RwSignal::new(Vec::<String>::new());
    #[cfg(target_arch = "wasm32")]
    let initial_font = af_web_core::api::storage_get("aetherflow-editor-font-size")
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(14)
        .clamp(12, 24);
    #[cfg(not(target_arch = "wasm32"))]
    let initial_font = 14u8;
    let font = RwSignal::new(initial_font);
    let preview = RwSignal::new(false);
    let find_open = RwSignal::new(false);
    let find = RwSignal::new(String::new());
    let replacement = RwSignal::new(String::new());
    let regex = RwSignal::new(false);
    let case_sensitive = RwSignal::new(false);
    let status = RwSignal::new(EditorStatus::Message(String::new()));
    let cursor = RwSignal::new((1usize, 1usize));
    let update_cursor = move || {
        if let Some(editor) = textarea.get() {
            let text = value.get_untracked();
            let offset = byte_offset(&text, editor.selection_start().ok().flatten().unwrap_or(0));
            let before = &text[..offset];
            let line = line_count(before);
            let column = before
                .rsplit('\n')
                .next()
                .unwrap_or_default()
                .chars()
                .count()
                + 1;
            cursor.set((line, column));
        }
    };
    Effect::new(move |_| {
        let text = value.get();
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        let pool = pool.get_value();
        let language = lang.get_value();
        spawn_local(async move {
            let result = pool
                .execute(WorkerRequest::TokenizeCode {
                    code: text.clone(),
                    language,
                })
                .await;
            if generation.try_get_untracked() == Some(ticket) {
                match result {
                    WorkerResponse::Tokens { spans } => {
                        highlighted.set(highlighted_html(&text, &spans))
                    }
                    WorkerResponse::Error { message } => status.set(EditorStatus::Message(message)),
                    _ => {}
                }
            }
        });
    });
    Effect::new(move |_| {
        font.track();
        #[cfg(target_arch = "wasm32")]
        af_web_core::api::storage_set(
            "aetherflow-editor-font-size",
            &font.get_untracked().to_string(),
        );
    });
    let undo_action = move || {
        if readonly.get_untracked() {
            return;
        }
        let mut past = undo.get_untracked();
        if let Some(previous) = past.pop() {
            redo.update(|future| future.push(value.get_untracked()));
            undo.set(past);
            value.set(previous);
        }
    };
    let redo_action = move || {
        if readonly.get_untracked() {
            return;
        }
        let mut future = redo.get_untracked();
        if let Some(next) = future.pop() {
            undo.update(|past| past.push(value.get_untracked()));
            redo.set(future);
            value.set(next);
        }
    };
    let clipboard = move |action: &str| {
        let Some(window) = web_sys::window() else {
            return;
        };
        let Some(editor) = textarea.get() else {
            return;
        };
        let Some(clipboard) = js_sys::Reflect::get(&window.navigator(), &"clipboard".into())
            .ok()
            .and_then(|clipboard| clipboard.dyn_into::<web_sys::Clipboard>().ok())
        else {
            status.set(EditorStatus::Message("Clipboard unavailable".into()));
            return;
        };
        let text = value.get_untracked();
        let start = byte_offset(&text, editor.selection_start().ok().flatten().unwrap_or(0));
        let end = byte_offset(&text, editor.selection_end().ok().flatten().unwrap_or(0));
        if action == "paste" {
            if readonly.get_untracked() {
                return;
            }
            spawn_local(async move {
                match JsFuture::from(clipboard.read_text()).await {
                    Ok(pasted) => {
                        if value.get_untracked() != text {
                            return;
                        }
                        let text = pasted.as_string().unwrap_or_default();
                        let mut current = value.get_untracked();
                        if current.is_char_boundary(start)
                            && current.is_char_boundary(end)
                            && end <= current.len()
                        {
                            current.replace_range(start..end, &text);
                            if within_editor_limit(&current) {
                                record_edit(value, undo, redo, current);
                                status.set(EditorStatus::Message("Clipboard updated".into()));
                            } else {
                                status.set(EditorStatus::Message("Editor limit is 256 KiB".into()));
                            }
                        }
                    }
                    Err(_) => status.set(EditorStatus::Message("Clipboard read denied".into())),
                }
            });
        } else {
            let selected = if start == end {
                text.clone()
            } else {
                text[start..end].to_string()
            };
            let cut = action == "cut";
            spawn_local(async move {
                match JsFuture::from(clipboard.write_text(&selected)).await {
                    Ok(_) => {
                        status.set(EditorStatus::Message("Clipboard updated".into()));
                        if cut && !readonly.get_untracked() && value.get_untracked() == text {
                            let mut next = text;
                            if start == end {
                                next.clear();
                            } else {
                                next.replace_range(start..end, "");
                            }
                            record_edit(value, undo, redo, next);
                        }
                    }
                    Err(_) => status.set(EditorStatus::Message("Clipboard unavailable".into())),
                }
            });
        }
    };
    let run_find = move |replace: bool| {
        if replace && readonly.get_untracked() {
            return;
        }
        let pool = pool.get_value();
        let original = value.get_untracked();
        let pattern = find.get_untracked();
        let replacement = replace.then(|| replacement.get_untracked());
        spawn_local(async move {
            match pool
                .execute(WorkerRequest::FindReplace {
                    code: original.clone(),
                    pattern,
                    replacement,
                    regex: regex.get_untracked(),
                    case_sensitive: case_sensitive.get_untracked(),
                })
                .await
            {
                WorkerResponse::FindResult {
                    ranges,
                    text,
                    replacements,
                } => {
                    if value.get_untracked() != original {
                        return;
                    }
                    if replace {
                        status.set(EditorStatus::Replaced(replacements));
                        record_edit(value, undo, redo, text);
                    } else if let (Some((start, end)), Some(editor)) =
                        (ranges.first(), textarea.get())
                    {
                        status.set(EditorStatus::Message("Match selected".into()));
                        let _ = editor.focus();
                        let _ = editor.set_selection_range(
                            original[..*start].encode_utf16().count() as u32,
                            original[..*end].encode_utf16().count() as u32,
                        );
                        update_cursor();
                    } else {
                        status.set(EditorStatus::Message("No matches".into()));
                    }
                }
                WorkerResponse::Error { message } => {
                    let key = if message.starts_with("regex parse error")
                        || message.contains("compiled regex exceeds")
                    {
                        "Invalid regular expression".to_string()
                    } else {
                        message
                    };
                    status.set(EditorStatus::Message(key));
                }
                _ => {}
            }
        });
    };
    view! {
        <div
            class="af-editor min-w-0 max-w-full border border-white/10 rounded-xl overflow-clip"
            on:keydown=move |event| {
                if event.ctrl_key() || event.meta_key() {
                    match event.key().to_lowercase().as_str() {
                        "s" => {
                            event.prevent_default();
                            if !readonly.get_untracked() {
                                if let Some(save) = on_save {
                                    save.run(value.get_untracked());
                                }
                            }
                        }
                        "f" => {
                            event.prevent_default();
                            find_open.set(true);
                        }
                        "z" => {
                            event.prevent_default();
                            if event.shift_key() { redo_action(); } else { undo_action(); }
                        }
                        "y" => {
                            event.prevent_default();
                            redo_action();
                        }
                        _ => {}
                    }
                } else if event.key() == "Escape" {
                    find_open.set(false);
                }
            }
        >
            <div class="af-editor-toolbar flex flex-wrap items-center gap-2 p-2 border-b border-white/10">
                <button class="glass-button px-3" disabled=move || readonly.get() || undo.with(Vec::is_empty) on:click=move |_| undo_action()>
                    {move || ui_t("Undo" )}
                </button>
                <button class="glass-button px-3" disabled=move || readonly.get() || redo.with(Vec::is_empty) on:click=move |_| redo_action()>
                    {move || ui_t("Redo" )}
                </button>
                <button class="glass-button px-3" on:click=move |_| find_open.update(|open| *open = !*open)>
                    {move || ui_t("Find / Replace" )}
                </button>
                <button
                    class="glass-button px-3" aria-label=move || ui_t("Decrease font size")
                    disabled=move || { font.get() <= 12 }
                    on:click=move |_| font.update(|font| *font = font.saturating_sub(1).max(12))
                >
                    "−"
                </button>
                <span class="text-xs tabular-nums">{move || ui_t_with("Font {size}px", &[("size", &font.get().to_string())])}</span>
                <button
                    class="glass-button px-3" aria-label=move || ui_t("Increase font size")
                    disabled=move || { font.get() >= 24 }
                    on:click=move |_| font.update(|font| *font = (*font + 1).min(24))
                >
                    "+"
                </button>
                <button class="glass-button px-3" on:click=move |_| clipboard("copy")>{move || ui_t("Copy")}</button>
                <button class="glass-button px-3" disabled=move || readonly.get() on:click=move |_| clipboard("cut")>{move || ui_t("Cut")}</button>
                <button class="glass-button px-3" disabled=move || readonly.get() on:click=move |_| clipboard("paste")>{move || ui_t("Paste")}</button>
                <button
                    class="glass-button px-3" aria-pressed=move || preview.get().to_string()
                    on:click=move |_| preview.update(|preview| *preview = !*preview)
                >
                    {move || ui_t("Markdown preview")}
                </button>
                <Show when=move || readonly.get()><crate::Badge label="ReadOnly · Locked" tone="warning"/></Show>
                <Show when=move || show_save && on_save.is_some()>
                <button
                    class="glass-button-primary px-3 ml-auto" disabled=move || readonly.get()
                    on:click=move |_| {
                        if let Some(save) = on_save {
                            save.run(value.get_untracked());
                        }
                    }
                >
                    {move || ui_t("Save" )}
                </button>
                </Show>
            </div>
            <Show when=move || find_open.get()>
                <div class="flex flex-wrap gap-2 p-3 border-b border-white/10">
                    <input
                        class="glass-input px-2" placeholder=move || ui_t("Find") aria-label=move || ui_t("Find")
                        prop:value=move || find.get()
                        on:input=move |event| find.set(event_target_value(&event))
                    />
                    <input
                        class="glass-input px-2" placeholder=move || ui_t("Replace") aria-label=move || ui_t("Replace")
                        prop:value=move || replacement.get()
                        on:input=move |event| replacement.set(event_target_value(&event))
                    />
                    <label class="flex gap-2 items-center text-xs">
                        <input type="checkbox" prop:checked=move || regex.get() on:change=move |event| regex.set(event_target_checked(&event))/>
                        {move || ui_t("Regular expression")}
                    </label>
                    <label class="flex gap-2 items-center text-xs">
                        <input type="checkbox" prop:checked=move || case_sensitive.get() on:change=move |event| case_sensitive.set(event_target_checked(&event))/>
                        {move || ui_t("Match case")}
                    </label>
                    <button class="glass-button px-3" on:click=move |_| run_find(false)>{move || ui_t("Find next")}</button>
                    <button class="glass-button px-3" disabled=move || readonly.get() on:click=move |_| run_find(true)>{move || ui_t("Replace all")}</button>
                </div>
            </Show>
            <div class=move || format!("af-editor-body flex min-w-0 max-w-full af-editor-fs-{}", font.get())>
                <pre node_ref=gutter aria-hidden="true" class="af-editor-gutter">{move || value.with(|text| gutter_text(text))}</pre>
                <div class="af-editor-layers min-w-0 flex-1 relative">
                    <pre node_ref=overlay aria-hidden="true" class="af-editor-highlight" inner_html=move || format!("{}\n", highlighted.get())></pre>
                    <textarea
                        node_ref=textarea aria-label=move || ui_t("Editor text") class="af-editor-input"
                        spellcheck="false" autocomplete="off" autocapitalize="off" wrap="off"
                        readonly=move || readonly.get() prop:value=move || value.get()
                        on:input=move |event| {
                            let next = event_target_value(&event);
                            if within_editor_limit(&next) {
                                record_edit(value, undo, redo, next);
                            } else {
                                status.set(EditorStatus::Message("Editor limit is 256 KiB".into()));
                                if let Some(editor) = textarea.get() {
                                    editor.set_value(&value.get_untracked());
                                }
                            }
                            update_cursor();
                        }
                        on:keyup=move |_| update_cursor()
                        on:click=move |_| update_cursor()
                        on:select=move |_| update_cursor()
                        on:scroll=move |_| {
                            if let Some(editor) = textarea.get() {
                                if let Some(highlight) = overlay.get() {
                                    highlight.set_scroll_top(editor.scroll_top());
                                    highlight.set_scroll_left(editor.scroll_left());
                                }
                                if let Some(gutter) = gutter.get() {
                                    gutter.set_scroll_top(editor.scroll_top());
                                }
                            }
                        }
                    ></textarea>
                </div>
                <Show when=move || preview.get()><crate::MarkdownView source=value/></Show>
            </div>
            <div role="status" class="px-3 py-2 text-xs text-slate-400 border-t border-white/5">
                {move || status.get().text()}
                <span class="float-right">{move || {
                    let (line, col) = cursor.get();
                    ui_t_with("Line {line}, Col {col} · {count} lines", &[
                        ("line", &line.to_string()), ("col", &col.to_string()),
                        ("count", &value.with(|text| line_count(text)).to_string()),
                    ])
                }}</span>
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_count_includes_empty_and_trailing_editor_lines() {
        for (text, count) in [
            ("", 1),
            ("hello", 1),
            ("\n", 2),
            ("one\ntwo\n", 3),
            ("α\r\n世界", 2),
        ] {
            assert_eq!(line_count(text), count, "{text:?}");
        }
    }

    #[test]
    fn gutter_numbers_match_the_editable_lines() {
        assert_eq!(gutter_text(""), "1");
        assert_eq!(gutter_text("one\ntwo\n"), "1\n2\n3");
        assert_eq!(
            gutter_text(&"\n".repeat(9)),
            "1\n2\n3\n4\n5\n6\n7\n8\n9\n10"
        );
    }

    #[test]
    fn browser_utf16_offsets_always_resolve_to_utf8_boundaries() {
        let text = "a😀é";
        for (units, bytes) in [(0, 0), (1, 1), (2, 5), (3, 5), (4, 7), (99, 7)] {
            assert_eq!(byte_offset(text, units), bytes);
            assert!(text.is_char_boundary(bytes));
        }
    }

    #[test]
    fn editor_limit_counts_bytes_and_accepts_the_exact_limit() {
        assert!(within_editor_limit(&"x".repeat(MAX_EDITOR_BYTES)));
        assert!(!within_editor_limit(&"x".repeat(MAX_EDITOR_BYTES + 1)));
        let mut utf8 = "é".repeat(MAX_EDITOR_BYTES / 2);
        assert!(within_editor_limit(&utf8));
        utf8.push('é');
        assert!(utf8.chars().count() < MAX_EDITOR_BYTES);
        assert!(!within_editor_limit(&utf8));
    }
}
