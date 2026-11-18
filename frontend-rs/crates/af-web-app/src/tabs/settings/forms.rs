use super::*;

pub type JsonDraft = RwSignal<FormDraft<Value>>;

pub fn text(value: &Value, key: &str) -> String {
    match &value[key] {
        Value::String(value) => value.clone(),
        Value::Null => String::new(),
        value => value.to_string(),
    }
}
pub fn draft_value(draft: JsonDraft) -> Value {
    draft.with(|draft| draft.value().unwrap_or(Value::Null))
}
pub fn edit(draft: JsonDraft, key: &str, value: Value) {
    draft.update(|draft| {
        if let Err(error) = draft.edit(key, value) {
            app().toast(tt(app(), &error), true);
        }
    });
}
pub fn poll_resource(resource: ApiResource, milliseconds: u32) {
    let timer = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        milliseconds,
        move || {
            if !resource.loading.get_untracked() {
                resource.refresh();
            }
        },
    )));
    on_cleanup(move || timer.set_value(None));
}
pub fn encode(value: &str) -> String {
    js_sys::encode_uri_component(value)
        .as_string()
        .unwrap_or_default()
}
pub fn bytes(value: f64) -> String {
    if !value.is_finite() || value < 0.0 {
        return "Unknown".into();
    }
    let mut number = value;
    let units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut unit = 0;
    while number >= 1024.0 && unit < units.len() - 1 {
        number /= 1024.0;
        unit += 1;
    }
    format!("{number:.1} {}", units[unit])
}
pub fn click_download(url: &str, filename: &str) -> Result<(), String> {
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or_else(|| "Browser document unavailable".to_string())?;
    let anchor = document
        .create_element("a")
        .map_err(|_| "Could not create download link")?
        .dyn_into::<web_sys::HtmlAnchorElement>()
        .map_err(|_| "Could not create download link")?;
    anchor.set_href(url);
    anchor.set_download(filename);
    let body = document.body().ok_or("Browser document unavailable")?;
    body.append_child(&anchor)
        .map_err(|_| "Could not attach download link")?;
    anchor.click();
    anchor.remove();
    Ok(())
}
pub fn download_blob(blob: &web_sys::Blob, filename: &str) -> Result<(), String> {
    let url = web_sys::Url::create_object_url_with_blob(blob)
        .map_err(|_| "Could not prepare the download".to_string())?;
    let result = click_download(&url, filename);
    spawn_local(async move {
        gloo_timers::future::TimeoutFuture::new(1000).await;
        let _ = web_sys::Url::revoke_object_url(&url);
    });
    result
}
pub fn download_text(content: &str, filename: &str, mime: &str) -> Result<(), String> {
    let parts = js_sys::Array::new();
    parts.push(&wasm_bindgen::JsValue::from_str(content));
    let options = web_sys::BlobPropertyBag::new();
    options.set_type(mime);
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &options)
        .map_err(|_| "Could not prepare the download".to_string())?;
    download_blob(&blob, filename)
}
#[component]
pub fn ResourceFeedback(resource: ApiResource) -> impl IntoView {
    let context = app();
    view! {
        <Show when=move || resource.loading.get() && resource.data.with(Value::is_null)>
            <p role="status" class="text-sm text-slate-400 py-3">
                {move || tt(context, "Common.loading")}
            </p>
        </Show>
        <Show when=move || resource.error.get().is_some()>
            <div role="alert" class="text-sm text-rose-300 py-3 flex flex-wrap items-center gap-3">
                {move || resource.error.get().map(|error| tt(context, &error.message))}
                <button
                    type="button"
                    class="glass-button px-3 py-2"
                    on:click=move |_| resource.refresh()
                >
                    {move || tt(context, "Common.retry")}
                </button>
            </div>
        </Show>
    }
}
#[component]
pub fn DraftInput(
    draft: JsonDraft,
    field: &'static str,
    #[prop(into)] label: TextProp,
    #[prop(default = "text")] kind: &'static str,
    #[prop(optional, into)] placeholder: TextProp,
    #[prop(optional)] required: bool,
    #[prop(optional, into)] disabled: Signal<bool>,
) -> impl IntoView {
    let context = app();
    view! {
        <label class="block text-sm space-y-2 min-w-0">
            <span class="text-slate-300">{move || tt(context, &label.get())}</span>
            <input
                class="glass-input px-3 py-2 w-full min-w-0"
                type=kind
                placeholder=move || tt(context, &placeholder.get())
                required=required
                autocomplete=if kind == "password" { "new-password" } else { "off" }
                disabled=move || disabled.get()
                prop:value=move || text(&draft_value(draft), field)
                on:input=move |event| edit(draft, field, json!(event_target_value(&event)))
            />
        </label>
    }
}
#[component]
pub fn DraftSelect(
    draft: JsonDraft,
    field: &'static str,
    #[prop(into)] label: TextProp,
    options: Vec<(&'static str, &'static str)>,
    #[prop(optional, into)] disabled: Signal<bool>,
) -> impl IntoView {
    let context = app();
    view! {
        <label class="block text-sm space-y-2 min-w-0">
            <span>{move || tt(context, &label.get())}</span>
            <select
                class="glass-input px-3 py-2 w-full"
                disabled=move || disabled.get()
                prop:value=move || text(&draft_value(draft), field)
                on:change=move |event| edit(draft, field, json!(event_target_value(&event)))
            >
                {options
                    .into_iter()
                    .map(|(id, label)| {
                        view! {
                            <option value=id>
                                {move || {
                                    if field == "defaultDashboard" {
                                        TabId::from_key(id).localized_label(&context.locale.get())
                                    } else {
                                        tt(context, label)
                                    }
                                }}
                            </option>
                        }
                    })
                    .collect_view()}
            </select>
        </label>
    }
}
#[component]
pub fn DraftCheck(
    draft: JsonDraft,
    field: &'static str,
    #[prop(into)] label: TextProp,
) -> impl IntoView {
    let context = app();
    view! {
        <label class="flex items-center gap-3 text-sm py-2">
            <input
                type="checkbox"
                prop:checked=move || draft_value(draft)[field].as_bool().unwrap_or(false)
                on:change=move |event| edit(draft, field, json!(event_target_checked(&event)))
            />
            <span>{move || tt(context, &label.get())}</span>
        </label>
    }
}
#[component]
pub fn DraftButtons(
    draft: JsonDraft,
    busy: RwSignal<bool>,
    on_save: Callback<()>,
    #[prop(optional, into)] label: TextProp,
    #[prop(optional, into)] saving_label: TextProp,
) -> impl IntoView {
    let context = app();
    view! {
        <div class="flex flex-wrap justify-end items-center gap-3 mt-5">
            <span role="status" class="text-xs text-amber-300">
                {move || {
                    if draft.with(FormDraft::is_dirty) {
                        tt(context, "Common.unsavedChanges")
                    } else {
                        tt(context, "Common.upToDate")
                    }
                }}
            </span>
            <button
                type="button"
                class="glass-button px-4 py-2"
                disabled=move || busy.get() || !draft.with(FormDraft::is_dirty)
                on:click=move |_| draft.update(FormDraft::reset)
            >
                {move || tt(context, "Common.discardChanges")}
            </button>
            <button
                type="button"
                class="glass-button-primary px-4 py-2"
                disabled=move || busy.get() || !draft.with(FormDraft::is_dirty)
                on:click=move |_| on_save.run(())
            >
                {move || {
                    if busy.get() {
                        let label = saving_label.get();
                        if label.is_empty() {
                            tt(context, "Common.saving")
                        } else {
                            tt(context, &label)
                        }
                    } else {
                        let label = label.get();
                        if label.is_empty() {
                            tt(context, "Common.saveChanges")
                        } else {
                            tt(context, &label)
                        }
                    }
                }}
            </button>
        </div>
    }
}
