//! Shared evidence formatting and browser download helpers.
use serde_json::Value;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;
pub(super) fn text(value: &Value, key: &str) -> String {
    match &value[key] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        v => v.to_string(),
    }
}
pub(super) fn recorded(locale: &str, value: &Value, key: &str) -> String {
    let value = text(value, key);
    af_web_core::i18n::translate(
        locale,
        if value.trim().is_empty() {
            "Unrecorded"
        } else {
            &value
        },
    )
}
pub(super) fn duration(locale: &str, seconds: Option<f64>) -> String {
    match seconds.filter(|v| v.is_finite() && *v >= 0.0) {
        Some(v) => af_web_core::i18n::translate_with(
            locale,
            "{hours}h {minutes}m",
            &[
                ("hours", &(v as u64 / 3600).to_string()),
                ("minutes", &(v as u64 % 3600 / 60).to_string()),
            ],
        ),
        None => af_web_core::i18n::translate(locale, "Unrecorded"),
    }
}
pub(super) fn timestamp(raw: &str) -> Option<i64> {
    let mut value = raw.trim().replace(' ', "T");
    if value.is_empty() {
        return None;
    }
    if value.len() == 10 {
        value.push_str("T00:00:00Z");
    } else if !value.ends_with('Z')
        && !value
            .get(10..)
            .is_some_and(|s| s.contains('+') || s.contains('-'))
    {
        value.push('Z');
    }
    let millis = js_sys::Date::parse(&value);
    millis.is_finite().then_some(millis as i64)
}
pub(super) fn js_error(value: JsValue) -> String {
    value
        .as_string()
        .unwrap_or_else(|| "Browser download failed".into())
}
pub(super) fn download_blob(blob: &web_sys::Blob, filename: &str) -> Result<(), String> {
    let document = web_sys::window()
        .and_then(|w| w.document())
        .ok_or("Browser document unavailable")?;
    let body = document.body().ok_or("Browser document body unavailable")?;
    let url = web_sys::Url::create_object_url_with_blob(blob).map_err(js_error)?;
    let result = (|| {
        let link = document
            .create_element("a")
            .map_err(js_error)?
            .dyn_into::<web_sys::HtmlElement>()
            .map_err(|_| "Download element is unavailable".to_string())?;
        link.set_attribute("href", &url).map_err(js_error)?;
        link.set_attribute("download", filename).map_err(js_error)?;
        link.set_hidden(true);
        body.append_child(&link).map_err(js_error)?;
        link.click();
        link.remove();
        Ok(())
    })();
    // Let the browser consume the URL before revoking it, including on Safari.
    spawn_local(async move {
        gloo_timers::future::TimeoutFuture::new(1500).await;
        let _ = web_sys::Url::revoke_object_url(&url);
    });
    result
}
pub(super) fn download_text(content: &str, mime: &str, filename: &str) -> Result<(), String> {
    let parts = js_sys::Array::new();
    parts.push(&JsValue::from_str(content));
    let options = web_sys::BlobPropertyBag::new();
    options.set_type(mime);
    let blob =
        web_sys::Blob::new_with_str_sequence_and_options(&parts, &options).map_err(js_error)?;
    download_blob(&blob, filename)
}

pub(super) fn display(context: crate::state::AppContext, value: &str) -> String {
    crate::tabs::l10n::tt(
        context,
        if value.trim().is_empty() {
            "Unrecorded"
        } else {
            value
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use leptos::prelude::*;

    #[test]
    fn nonempty_server_sentinels_and_missing_metadata_follow_locale_changes() {
        let owner = Owner::new();
        owner.with(|| {
            let context = crate::state::AppContext::new();
            for sentinel in [
                "Unrecorded",
                "Unavailable",
                "Not configured",
                "Coming soon",
                "Unknown",
                "None",
            ] {
                let label = Memo::new(move |_| display(context, sentinel));
                context.locale.set("en".into());
                assert_eq!(label.get(), sentinel);
                context.locale.set("fr".into());
                assert_ne!(label.get(), sentinel);
                assert_eq!(
                    recorded("fr", &serde_json::json!({"value":sentinel}), "value"),
                    label.get()
                );
            }
            assert_eq!(display(context, ""), "Non enregistré");
            assert_eq!(display(context, "  "), "Non enregistré");
            assert_eq!(display(context, "server-identity"), "server-identity");
        });
    }
}
