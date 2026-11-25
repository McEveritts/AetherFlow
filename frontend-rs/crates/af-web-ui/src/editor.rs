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

/// Maximum UTF-8 payload editable in plain-text mode (matches backend `MAX_EDITOR_CONTENT_BYTES`).
pub const MAX_TEXT_EDITOR_BYTES: usize = 10 * 1024 * 1024;

pub const BUNDLED_EDITOR_THEMES: [&str; 17] = [
    "chrome",
    "github",
    "solarized_light",
    "monokai",
    "dracula",
    "twilight",
    "tomorrow_night",
    "solarized_dark",
    "textmate",
    "clouds",
    "dawn",
    "eclipse",
    "xcode",
    "nord_dark",
    "one_dark",
    "terminal",
    "github_dark",
];

pub const EDITOR_LANGUAGES: &[(&str, &str)] = &[
    ("text", "Plain text"),
    ("rust", "Rust"),
    ("go", "Go"),
    ("python", "Python"),
    ("typescript", "TypeScript"),
    ("tsx", "TSX"),
    ("javascript", "JavaScript"),
    ("jsx", "JSX"),
    ("json", "JSON"),
    ("json5", "JSON5"),
    ("toml", "TOML"),
    ("yaml", "YAML"),
    ("shell", "Shell"),
    ("batchfile", "Batch"),
    ("powershell", "PowerShell"),
    ("markdown", "Markdown"),
    ("html", "HTML"),
    ("xml", "XML"),
    ("svg", "SVG"),
    ("css", "CSS"),
    ("scss", "SCSS"),
    ("less", "Less"),
    ("sql", "SQL"),
    ("ini", "INI / Env"),
    ("properties", "Properties"),
    ("dockerfile", "Dockerfile"),
    ("makefile", "Makefile"),
    ("gitignore", "Gitignore"),
    ("diff", "Diff / Patch"),
    ("c_cpp", "C / C++"),
    ("java", "Java"),
    ("csharp", "C#"),
    ("php", "PHP"),
    ("ruby", "Ruby"),
    ("lua", "Lua"),
    ("perl", "Perl"),
    ("swift", "Swift"),
    ("kotlin", "Kotlin"),
    ("scala", "Scala"),
    ("graphql", "GraphQL"),
    ("prisma", "Prisma"),
    ("terraform", "Terraform"),
    ("nginx", "Nginx"),
    ("apache_conf", "Apache Conf"),
    ("latex", "LaTeX"),
];

pub fn editor_theme_class(theme: &str) -> &'static str {
    let normalized = theme.trim().to_ascii_lowercase();
    let key = normalized.strip_prefix("ace/theme/").unwrap_or(&normalized);
    match key {
        "chrome" => "af-editor-theme-chrome",
        "github" => "af-editor-theme-github",
        "solarized_light" => "af-editor-theme-solarized-light",
        "monokai" => "af-editor-theme-monokai",
        "dracula" => "af-editor-theme-dracula",
        "twilight" => "af-editor-theme-twilight",
        "tomorrow_night" => "af-editor-theme-tomorrow-night",
        "solarized_dark" => "af-editor-theme-solarized-dark",
        "textmate" => "af-editor-theme-textmate",
        "clouds" => "af-editor-theme-clouds",
        "dawn" => "af-editor-theme-dawn",
        "eclipse" => "af-editor-theme-eclipse",
        "xcode" => "af-editor-theme-xcode",
        "nord_dark" => "af-editor-theme-nord-dark",
        "one_dark" => "af-editor-theme-one-dark",
        "terminal" => "af-editor-theme-terminal",
        "github_dark" => "af-editor-theme-github-dark",
        _ => "",
    }
}

pub fn editor_theme_tone(theme: &str) -> &'static str {
    let normalized = theme.trim().to_ascii_lowercase();
    let key = normalized.strip_prefix("ace/theme/").unwrap_or(&normalized);
    match key {
        "chrome" | "github" | "solarized_light" | "textmate" | "clouds" | "dawn" | "eclipse"
        | "xcode" => "light",
        "monokai" | "dracula" | "twilight" | "tomorrow_night" | "solarized_dark" | "nord_dark"
        | "one_dark" | "terminal" | "github_dark" => "dark",
        _ => "",
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
pub fn within_highlight_limit(text: &str) -> bool {
    text.len() <= MAX_EDITOR_BYTES
}
pub fn within_editor_limit(text: &str) -> bool {
    text.len() <= MAX_TEXT_EDITOR_BYTES
}
fn literal_find_ranges(code: &str, pattern: &str, case_sensitive: bool) -> Vec<(usize, usize)> {
    if pattern.is_empty() {
        return vec![];
    }
    if case_sensitive {
        return code
            .match_indices(pattern)
            .map(|(start, m)| (start, start + m.len()))
            .collect();
    }
    let needle: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    if needle.is_empty() {
        return vec![];
    }
    let mut folded: Vec<(char, usize, usize)> = Vec::with_capacity(code.len());
    for (idx, ch) in code.char_indices() {
        let end = idx + ch.len_utf8();
        for lower in ch.to_lowercase() {
            folded.push((lower, idx, end));
        }
    }
    let mut ranges = Vec::new();
    let mut i = 0;
    while i + needle.len() <= folded.len() {
        if folded[i..i + needle.len()]
            .iter()
            .zip(&needle)
            .all(|((c, _, _), n)| c == n)
        {
            let start = folded[i].1;
            let end = folded[i + needle.len() - 1].2;
            ranges.push((start, end));
            i += needle.len();
        } else {
            i += 1;
        }
    }
    ranges
}
fn plain_find_replace(
    code: &str,
    pattern: &str,
    replacement: Option<&str>,
    case_sensitive: bool,
) -> (Vec<(usize, usize)>, String, usize) {
    let ranges = literal_find_ranges(code, pattern, case_sensitive);
    let Some(repl) = replacement else {
        return (ranges, String::new(), 0);
    };
    if ranges.is_empty() {
        return (ranges, code.to_owned(), 0);
    }
    let mut out = String::with_capacity(code.len());
    let mut last = 0usize;
    let mut count = 0usize;
    for &(start, end) in &ranges {
        if start < last
            || end > code.len()
            || !code.is_char_boundary(start)
            || !code.is_char_boundary(end)
        {
            continue;
        }
        out.push_str(&code[last..start]);
        out.push_str(repl);
        last = end;
        count += 1;
    }
    out.push_str(&code[last..]);
    (ranges, out, count)
}
fn next_match_range(ranges: &[(usize, usize)], cursor_byte: usize) -> Option<(usize, usize)> {
    ranges
        .iter()
        .copied()
        .find(|&(start, _)| start >= cursor_byte)
        .or_else(|| ranges.first().copied())
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
    #[prop(optional, into)] theme: Signal<String>,
    #[prop(optional, into)] readonly: Signal<bool>,
    #[prop(optional)] on_save: Option<Callback<String>>,
    #[prop(default = true)] show_save: bool,
) -> impl IntoView {
    let pool = StoredValue::new_local(WorkerPool::shared());
    let active_language = RwSignal::new(language);
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
    #[cfg(target_arch = "wasm32")]
    let initial_wrap =
        af_web_core::api::storage_get("aetherflow-editor-word-wrap").as_deref() == Some("true");
    #[cfg(not(target_arch = "wasm32"))]
    let initial_wrap = false;
    let font = RwSignal::new(initial_font);
    let wrap_lines = RwSignal::new(initial_wrap);
    let preview = RwSignal::new(false);
    let find_open = RwSignal::new(false);
    let find = RwSignal::new(String::new());
    let replacement = RwSignal::new(String::new());
    let regex = RwSignal::new(false);
    let case_sensitive = RwSignal::new(false);
    let status = RwSignal::new(EditorStatus::Message(String::new()));
    let cursor = RwSignal::new((1usize, 1usize));
    let plain_mode = Memo::new(move |_| value.with(|text| !within_highlight_limit(text)));
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
        let language = active_language.get();
        generation.update(|g| *g += 1);
        if !within_highlight_limit(&text) {
            highlighted.set(String::new());
            return;
        }
        let ticket = generation.get_untracked();
        let pool = pool.get_value();
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
    Effect::new(move |_| {
        let wrap = wrap_lines.get();
        #[cfg(target_arch = "wasm32")]
        af_web_core::api::storage_set(
            "aetherflow-editor-word-wrap",
            if wrap { "true" } else { "false" },
        );
        #[cfg(not(target_arch = "wasm32"))]
        let _ = wrap;
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
                                status.set(EditorStatus::Message("Editor limit is 10 MiB".into()));
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
        let original = value.get_untracked();
        let pattern = find.get_untracked();
        let replacement = replace.then(|| replacement.get_untracked());
        let use_regex = regex.get_untracked();
        let match_case = case_sensitive.get_untracked();
        let cursor_byte = textarea
            .get()
            .and_then(|editor| editor.selection_end().ok().flatten())
            .map(|utf16| byte_offset(&original, utf16))
            .unwrap_or(0);
        if !within_highlight_limit(&original) {
            if use_regex {
                status.set(EditorStatus::Message(
                    "Regex search is limited to 256 KiB".into(),
                ));
                return;
            }
            let (ranges, text, replacements) =
                plain_find_replace(&original, &pattern, replacement.as_deref(), match_case);
            if replace {
                if !within_editor_limit(&text) {
                    status.set(EditorStatus::Message("Editor limit is 10 MiB".into()));
                } else {
                    status.set(EditorStatus::Replaced(replacements));
                    record_edit(value, undo, redo, text);
                }
            } else if let (Some((start, end)), Some(editor)) =
                (next_match_range(&ranges, cursor_byte), textarea.get())
            {
                status.set(EditorStatus::Message("Match selected".into()));
                let _ = editor.focus();
                let _ = editor.set_selection_range(
                    original[..start].encode_utf16().count() as u32,
                    original[..end].encode_utf16().count() as u32,
                );
                update_cursor();
            } else {
                status.set(EditorStatus::Message("No matches".into()));
            }
            return;
        }
        let pool = pool.get_value();
        spawn_local(async move {
            match pool
                .execute(WorkerRequest::FindReplace {
                    code: original.clone(),
                    pattern,
                    replacement,
                    regex: use_regex,
                    case_sensitive: match_case,
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
                        (next_match_range(&ranges, cursor_byte), textarea.get())
                    {
                        status.set(EditorStatus::Message("Match selected".into()));
                        let _ = editor.focus();
                        let _ = editor.set_selection_range(
                            original[..start].encode_utf16().count() as u32,
                            original[..end].encode_utf16().count() as u32,
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
            class=move || {
                let theme_cls = editor_theme_class(&theme.get());
                if theme_cls.is_empty() {
                    "af-editor min-w-0 max-w-full border border-white/10 rounded-xl overflow-clip"
                        .to_string()
                } else {
                    format!(
                        "af-editor {theme_cls} min-w-0 max-w-full border border-white/10 rounded-xl overflow-clip"
                    )
                }
            }
            data-editor-theme=move || theme.get()
            data-editor-tone=move || editor_theme_tone(&theme.get())
            data-editor-language=move || active_language.get()
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
                <button class="af-btn px-3" disabled=move || readonly.get() || undo.with(Vec::is_empty) on:click=move |_| undo_action()>
                    {move || ui_t("Undo" )}
                </button>
                <button class="af-btn px-3" disabled=move || readonly.get() || redo.with(Vec::is_empty) on:click=move |_| redo_action()>
                    {move || ui_t("Redo" )}
                </button>
                <button class="af-btn px-3" on:click=move |_| find_open.update(|open| *open = !*open)>
                    {move || ui_t("Find / Replace" )}
                </button>
                <button
                    class="af-btn px-3" aria-label=move || ui_t("Decrease font size")
                    disabled=move || { font.get() <= 12 }
                    on:click=move |_| font.update(|font| *font = font.saturating_sub(1).max(12))
                >
                    "−"
                </button>
                <span class="text-xs tabular-nums">{move || ui_t_with("Font {size}px", &[("size", &font.get().to_string())])}</span>
                <button
                    class="af-btn px-3" aria-label=move || ui_t("Increase font size")
                    disabled=move || { font.get() >= 24 }
                    on:click=move |_| font.update(|font| *font = (*font + 1).min(24))
                >
                    "+"
                </button>
                <button class="af-btn px-3" on:click=move |_| clipboard("copy")>{move || ui_t("Copy")}</button>
                <button class="af-btn px-3" disabled=move || readonly.get() on:click=move |_| clipboard("cut")>{move || ui_t("Cut")}</button>
                <button class="af-btn px-3" disabled=move || readonly.get() on:click=move |_| clipboard("paste")>{move || ui_t("Paste")}</button>
                <select
                    class="af-input px-2 py-1 text-xs"
                    data-testid="editor-language-select"
                    aria-label=move || ui_t("Syntax language")
                    prop:value=move || active_language.get()
                    on:change=move |event| active_language.set(event_target_value(&event))
                >
                    {EDITOR_LANGUAGES
                        .iter()
                        .map(|(code, label)| {
                            let code_val = (*code).to_owned();
                            let label_txt = (*label).to_owned();
                            view! { <option value=code_val>{label_txt}</option> }
                        })
                        .collect_view()}
                </select>
                <button
                    class="af-btn px-3"
                    data-testid="editor-word-wrap"
                    aria-pressed=move || wrap_lines.get().to_string()
                    on:click=move |_| wrap_lines.update(|wrap| *wrap = !*wrap)
                >
                    {move || ui_t("Word wrap")}
                </button>
                <button
                    class="af-btn px-3" aria-pressed=move || preview.get().to_string()
                    on:click=move |_| preview.update(|preview| *preview = !*preview)
                >
                    {move || ui_t("Markdown preview")}
                </button>
                <Show when=move || plain_mode.get()><crate::Badge label="Plain text · >256 KiB" tone="muted"/></Show>
                <Show when=move || readonly.get()><crate::Badge label="ReadOnly · Locked" tone="warning"/></Show>
                <Show when=move || show_save && on_save.is_some()>
                <button
                    class="af-btn-primary px-3 ml-auto" disabled=move || readonly.get()
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
                <div class="af-editor-find flex flex-wrap gap-2 p-3 border-b border-white/10">
                    <input
                        class="af-input px-2" placeholder=move || ui_t("Find") aria-label=move || ui_t("Find")
                        prop:value=move || find.get()
                        on:input=move |event| find.set(event_target_value(&event))
                    />
                    <input
                        class="af-input px-2" placeholder=move || ui_t("Replace") aria-label=move || ui_t("Replace")
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
                    <button class="af-btn px-3" on:click=move |_| run_find(false)>{move || ui_t("Find next")}</button>
                    <button class="af-btn px-3" disabled=move || readonly.get() on:click=move |_| run_find(true)>{move || ui_t("Replace all")}</button>
                </div>
            </Show>
            <div class=move || {
                format!(
                    "af-editor-body flex min-w-0 max-w-full af-editor-fs-{}{}",
                    font.get(),
                    if wrap_lines.get() { " af-editor-wrap" } else { "" }
                )
            }>
                <pre node_ref=gutter aria-hidden="true" class="af-editor-gutter">{move || value.with(|text| gutter_text(text))}</pre>
                <div class="af-editor-layers min-w-0 flex-1 relative">
                    <pre
                        node_ref=overlay
                        aria-hidden="true"
                        class="af-editor-highlight"
                        inner_html=move || {
                            if plain_mode.get() {
                                String::new()
                            } else {
                                format!("{}\n", highlighted.get())
                            }
                        }
                    ></pre>
                    <textarea
                        node_ref=textarea
                        aria-label=move || ui_t("Editor text")
                        class=move || {
                            if plain_mode.get() {
                                "af-editor-input af-editor-plain"
                            } else {
                                "af-editor-input"
                            }
                        }
                        spellcheck="false"
                        autocomplete="off"
                        autocapitalize="off"
                        wrap=move || if wrap_lines.get() { "soft" } else { "off" }
                        readonly=move || readonly.get()
                        prop:value=move || value.get()
                        on:input=move |event| {
                            let next = event_target_value(&event);
                            if within_editor_limit(&next) {
                                record_edit(value, undo, redo, next);
                            } else {
                                status.set(EditorStatus::Message("Editor limit is 10 MiB".into()));
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
        assert!(within_highlight_limit(&"x".repeat(MAX_EDITOR_BYTES)));
        assert!(!within_highlight_limit(&"x".repeat(MAX_EDITOR_BYTES + 1)));
        let mut utf8 = "é".repeat(MAX_EDITOR_BYTES / 2);
        assert!(within_highlight_limit(&utf8));
        utf8.push('é');
        assert!(utf8.chars().count() < MAX_EDITOR_BYTES);
        assert!(!within_highlight_limit(&utf8));
        assert!(within_editor_limit(&utf8));
        assert!(within_editor_limit(&"x".repeat(MAX_TEXT_EDITOR_BYTES)));
        assert!(!within_editor_limit(&"x".repeat(MAX_TEXT_EDITOR_BYTES + 1)));
    }

    #[test]
    fn plain_find_replace_handles_case_insensitive_unicode_and_replacements() {
        let source = "Alpha café ALPHA";
        let (ranges, _, _) = plain_find_replace(source, "alpha", None, false);
        assert_eq!(ranges.len(), 2);
        assert_eq!(&source[ranges[0].0..ranges[0].1], "Alpha");
        assert_eq!(&source[ranges[1].0..ranges[1].1], "ALPHA");

        let (_, replaced, count) = plain_find_replace(source, "alpha", Some("Beta"), false);
        assert_eq!(count, 2);
        assert_eq!(replaced, "Beta café Beta");

        let (sensitive, _, _) = plain_find_replace(source, "alpha", None, true);
        assert!(sensitive.is_empty());
    }

    #[test]
    fn editor_theme_class_maps_all_17_bundled_themes_to_finite_classes() {
        let mut light_count = 0usize;
        let mut dark_count = 0usize;
        for theme in BUNDLED_EDITOR_THEMES {
            let class = editor_theme_class(theme);
            assert!(
                class.starts_with("af-editor-theme-"),
                "expected finite theme class for {theme}, got {class:?}"
            );
            assert_eq!(editor_theme_class(&format!("ace/theme/{theme}")), class);
            let tone = editor_theme_tone(theme);
            assert!(
                matches!(tone, "light" | "dark"),
                "expected light or dark tone for {theme}, got {tone:?}"
            );
            assert_eq!(editor_theme_tone(&format!("ace/theme/{theme}")), tone);
            if tone == "light" {
                light_count += 1;
            } else {
                dark_count += 1;
            }
        }
        assert_eq!(light_count, 8);
        assert_eq!(dark_count, 9);
        assert_eq!(editor_theme_class("nord_dark"), "af-editor-theme-nord-dark");
        assert_eq!(
            editor_theme_class("github_dark"),
            "af-editor-theme-github-dark"
        );
        assert_eq!(editor_theme_class("textmate"), "af-editor-theme-textmate");
        assert_eq!(editor_theme_tone("chrome"), "light");
        assert_eq!(editor_theme_tone("dracula"), "dark");
        assert_eq!(editor_theme_tone("  ACE/THEME/SOLARIZED_LIGHT "), "light");
        assert_eq!(editor_theme_class("custom_unknown"), "");
        assert_eq!(editor_theme_tone("custom_unknown"), "");
        assert_eq!(editor_theme_tone(""), "");
    }

    #[test]
    fn next_match_range_advances_past_cursor_and_wraps_at_eof() {
        let ranges = vec![(0, 5), (12, 17), (30, 35)];
        assert_eq!(next_match_range(&ranges, 0), Some((0, 5)));
        assert_eq!(next_match_range(&ranges, 5), Some((12, 17)));
        assert_eq!(next_match_range(&ranges, 17), Some((30, 35)));
        assert_eq!(next_match_range(&ranges, 35), Some((0, 5)));
        assert_eq!(next_match_range(&[], 0), None);
    }
}
