//! Native archive export, typed summaries, and reviewed restore.
use super::common::*;
use super::types::*;
use crate::state::app;
use crate::tabs::contracts;
use crate::tabs::l10n::{tt, tt_with, ConfirmDialog};
use af_web_core::api::{current_auth_epoch, ApiClient};
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::{spawn_local, JsFuture};

const MAX_ARCHIVE_RAW_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024;

const ERR_ARCHIVE_RAW_SIZE: &str =
    "Choose an archive of 1 byte to 8 MiB (leaves headroom for the 10 MiB request wrapper).";
const ERR_ARCHIVE_FILE_TOO_LARGE: &str =
    "Archive exceeds 8 MiB raw limit (10 MiB max with request wrapper).";
const ERR_ARCHIVE_FORMAT: &str =
    "Choose a native aetherflow.streaming-history archive with manifest and data.";
const ERR_REQUEST_ENVELOPE_SIZE: &str =
    "Serialized archive request exceeds the 10 MiB backend limit.";

fn validate_raw_archive_len(len: usize) -> Result<(), &'static str> {
    if len == 0 || len > MAX_ARCHIVE_RAW_BYTES {
        Err(ERR_ARCHIVE_RAW_SIZE)
    } else {
        Ok(())
    }
}

fn validate_request_envelope(body: &Value) -> Result<(), &'static str> {
    match serde_json::to_vec(body) {
        Ok(bytes) if bytes.len() <= MAX_REQUEST_BODY_BYTES => Ok(()),
        _ => Err(ERR_REQUEST_ENVELOPE_SIZE),
    }
}

fn prepare_preview_request(mode: &str, content: &str) -> Result<Value, &'static str> {
    validate_raw_archive_len(content.len())?;
    let archive = match serde_json::from_str::<Value>(content) {
        Ok(value)
            if serde_json::from_value::<PortableArchive>(value.clone())
                .is_ok_and(|archive| archive.manifest.format == "aetherflow.streaming-history") =>
        {
            value
        }
        _ => return Err(ERR_ARCHIVE_FORMAT),
    };
    let body = json!({"mode": mode, "archive": archive});
    validate_request_envelope(&body)?;
    Ok(body)
}

#[component]
pub(super) fn HistoryPortability(on_changed: Callback<()>) -> impl IntoView {
    let context = app();
    let raw = RwSignal::new(String::new());
    let mode = RwSignal::new("merge".to_string());
    let frozen = RwSignal::new(Value::Null);
    let preview = RwSignal::new(Value::Null);
    let busy = RwSignal::new(false);
    let approved = RwSignal::new(false);
    let confirm = RwSignal::new(false);
    let result = RwSignal::new(None::<String>);
    let generation = RwSignal::new(0u64);
    let export_abort = StoredValue::new_local(web_sys::AbortController::new().ok());
    on_cleanup(move || {
        export_abort.with_value(|controller| {
            if let Some(controller) = controller {
                controller.abort();
            }
        });
    });
    let invalidate = Callback::new(move |(): ()| {
        preview.set(Value::Null);
        frozen.set(Value::Null);
        approved.set(false);
        confirm.set(false);
        generation.update(|n| *n += 1);
    });
    let export = Callback::new(move |(): ()| {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let epoch = context.session_epoch.get_untracked();
        let auth_epoch = current_auth_epoch();
        let signal = export_abort
            .with_value(|controller| controller.as_ref().map(web_sys::AbortController::signal));
        busy.set(true);
        spawn_local(async move {
            let is_current = || {
                busy.try_get_untracked().is_some()
                    && context.session_epoch.try_get_untracked() == Some(epoch)
                    && current_auth_epoch() == auth_epoch
                    && context
                        .user
                        .try_get_untracked()
                        .flatten()
                        .is_some_and(|user| user["role"] == "admin")
            };
            let response: Result<(), String> = async {
                let response = ApiClient
                    .fetch_raw_body_with_signal(
                        "/api/v1/admin/streaming/portability/export",
                        "GET",
                        None,
                        None,
                        &[("Accept", "application/json")],
                        signal.as_ref(),
                    )
                    .await
                    .map_err(|e| e.message)?;
                if !is_current() {
                    return Ok(());
                }
                if !response.ok() {
                    return Err(tt_with(
                        context,
                        "Archive export failed (HTTP {status}).",
                        &[(
                            "status",
                            &(tt(context, &(response.status()).to_string())).to_string(),
                        )],
                    ));
                }
                let blob = response.blob().await.map_err(|error| error.message)?;
                if !is_current() {
                    return Ok(());
                }
                download_blob(&blob, "aetherflow-streaming-archive.json")
            }
            .await;
            if !is_current() {
                return;
            }
            if let Err(e) = response {
                result.set(Some(e));
            }
            busy.set(false);
        });
    });
    let get_preview = Callback::new(move |(): ()| {
        if busy.get_untracked() {
            return;
        }
        invalidate.run(());
        let content = raw.get_untracked();
        let body = match prepare_preview_request(&mode.get_untracked(), &content) {
            Ok(body) => body,
            Err(message) => {
                result.set(Some(message.into()));
                return;
            }
        };
        let ticket = generation.get_untracked();
        busy.set(true);
        spawn_local(async move {
            let response = ApiClient
                .post("/api/v1/admin/streaming/portability/preview", Some(&body))
                .await;
            if generation.try_get_untracked() != Some(ticket) {
                return;
            }
            match response {
                Ok(data) => {
                    let mut body = body;
                    let summary = contracts::decode::<ArchivePreview>(&data);
                    if summary.approval_token.is_empty() {
                        result.set(Some(
                            "Archive preview is missing its approval token.".into(),
                        ));
                        busy.set(false);
                        return;
                    }
                    body["approvalToken"] = json!(summary.approval_token);
                    frozen.set(body);
                    preview.set(data);
                    result.set(None);
                }
                Err(e) => result.set(Some(e.message)),
            }
            busy.set(false);
        });
    });
    let restore = Callback::new(move |(): ()| {
        if busy.get_untracked() || !approved.get_untracked() || !context.is_admin() {
            return;
        }
        let body = frozen.get_untracked();
        if !body["approvalToken"].is_string() {
            return;
        }
        if timestamp(&preview.with_untracked(|v| contracts::decode::<ArchivePreview>(v).expires_at))
            .is_none_or(|expires| expires as f64 <= js_sys::Date::now())
        {
            invalidate.run(());
            result.set(Some(
                "Restore preview expired. Preview the archive again.".into(),
            ));
            return;
        }
        busy.set(true);
        spawn_local(async move {
            let response = ApiClient
                .post("/api/v1/admin/streaming/portability/restore", Some(&body))
                .await;
            if busy.try_get_untracked().is_none() {
                return;
            }
            match response {
                Ok(data) => {
                    result.set(Some(
                        serde_json::to_string_pretty(&data).unwrap_or_default(),
                    ));
                    on_changed.run(());
                    context.toast(tt(context, "Reviewed archive restore applied; inspect the backup verification receipt."),false);
                }
                Err(e) => result.set(Some(if e.status == 409 {
                    tt_with(
                        context,
                        "Restore preview is stale. Preview again. {error}",
                        &[("error", &(e.message).to_string())],
                    )
                } else {
                    e.message
                })),
            }
            invalidate.run(());
            busy.set(false);
        });
    });
    view! {
        <div class="space-y-4 pt-3">
            <button
                class="glass-button px-4 py-2"
                disabled=move || busy.get()
                on:click=move |_| export.run(())
            >
                {move || tt(context, "Export native JSON archive")}
            </button>
            <label class="block text-sm">
                {move || tt(context, "Restore mode")}
                <select
                    class="glass-input p-2"
                    disabled=move || busy.get()
                    prop:value=move || mode.get()
                    on:change=move |e| {
                        mode.set(event_target_value(&e));
                        invalidate.run(());
                    }
                >
                    <option value="merge">{move || tt(context, "Merge")}</option>
                    <option value="replace">{move || tt(context, "Replace history")}</option>
                </select>
            </label>
            <label class="block text-sm">
                {"Native archive JSON file (maximum 8 MiB raw to fit 10 MiB request limit)"}
                <input
                    type="file"
                    accept=".json,application/json"
                    disabled=move || busy.get()
                    on:change=move |e| {
                        let input = event_target::<web_sys::HtmlInputElement>(&e);
                        if let Some(file) = input.files().and_then(|files| files.get(0)) {
                            invalidate.run(());
                            if file.size() > MAX_ARCHIVE_RAW_BYTES as f64 {
                                result.set(Some(ERR_ARCHIVE_FILE_TOO_LARGE.into()));
                                return;
                            }
                            let ticket = generation.get_untracked();
                            spawn_local(async move {
                                let result_value = JsFuture::from(file.text()).await;
                                if generation.try_get_untracked() != Some(ticket) {
                                    return;
                                }
                                match result_value {
                                    Ok(v) => raw.set(v.as_string().unwrap_or_default()),
                                    Err(e) => result.set(Some(js_error(e))),
                                }
                            });
                        }
                    }
                />
            </label>
            <label class="block text-sm">
                {move || tt(context, "Archive JSON")}
                <textarea
                    rows="5"
                    class="glass-input p-3 w-full text-xs font-mono"
                    disabled=move || busy.get()
                    prop:value=move || raw.get()
                    on:input=move |e| {
                        raw.set(event_target_value(&e));
                        invalidate.run(());
                    }
                ></textarea>
            </label>
            <button
                class="glass-button px-4 py-2"
                disabled=move || busy.get()
                on:click=move |_| get_preview.run(())
            >
                {move || tt(context, "Preview restore diff")}
            </button>
            <Show when=move || preview.with(|p| !contracts::decode::<ArchivePreview>(p).approval_token.is_empty())>
                <div class="space-y-3 rounded-xl border border-amber-500/30 p-3">
                    <pre class="text-xs whitespace-pre-wrap break-all max-h-80 overflow-auto">
                        {move || {
                            preview
                                .with(|p| {
                                    let summary = contracts::decode::<ArchivePreview>(p);
                                    serde_json::to_string_pretty(
                                            &json!(
                                                {"mode":summary.mode,"archiveCounts":summary.archive_counts,"targetCounts":summary.target_counts,"plan":summary.plan,"replacementCounts":summary.replacement_counts,"replacementNotice":summary.replacement_notice,"conflicts":summary.conflicts,"expiresAt":summary.expires_at}
                                            ),
                                        )
                                        .unwrap_or_default()
                                })
                        }}
                    </pre>
                    <label class="text-sm flex gap-2">
                        <input
                            type="checkbox"
                            disabled=move || busy.get()
                            prop:checked=move || approved.get()
                            on:change=move |e| approved.set(event_target_checked(&e))
                        />
                        {move || tt(
                            context,
                            "I reviewed the exact merge / replacement plan and authorize this restore.",
                        )}
                    </label>
                    <button
                        class="glass-button-primary px-4 py-2"
                        disabled=move || busy.get() || !approved.get()
                        on:click=move |_| confirm.set(true)
                    >
                        {move || tt(context, "Restore approved archive")}
                    </button>
                </div>
            </Show>
            {move || {
                result
                    .get()
                    .map(|result| {
                        view! {
                            <pre
                                role="status"
                                class="text-xs whitespace-pre-wrap break-all max-h-64 overflow-auto"
                            >
                                {move || tt(context, &result)}
                            </pre>
                        }
                    })
            }}
            <ConfirmDialog
                open=confirm
                title="Restore the reviewed streaming archive?"
                message="Replacement mode can remove existing history. Confirm only the exact server-generated plan you reviewed; the signed token and archive are sent unchanged."
                busy=Signal::derive(move || busy.get())
                on_confirm=restore
            />
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_archive_with_padding(target_raw_bytes: usize) -> String {
        let base = serde_json::to_string(&json!({
            "manifest": {
                "format": "aetherflow.streaming-history",
                "version": 1,
                "exportedAt": "2026-11-19T00:00:00Z",
                "counts": { "history": 1 }
            },
            "data": {
                "history": [
                    { "sessionKey": "s-1", "padding": "" }
                ]
            }
        }))
        .unwrap();
        let pad_len = target_raw_bytes.saturating_sub(base.len());
        let padding = "a".repeat(pad_len);
        serde_json::to_string(&json!({
            "manifest": {
                "format": "aetherflow.streaming-history",
                "version": 1,
                "exportedAt": "2026-11-19T00:00:00Z",
                "counts": { "history": 1 }
            },
            "data": {
                "history": [
                    { "sessionKey": "s-1", "padding": padding }
                ]
            }
        }))
        .unwrap()
    }

    #[test]
    fn accepts_seven_point_five_mib_archive_and_rejects_over_eight_mib() {
        assert_eq!(MAX_ARCHIVE_RAW_BYTES, 8 * 1024 * 1024);
        assert_eq!(MAX_REQUEST_BODY_BYTES, 10 * 1024 * 1024);

        assert_eq!(validate_raw_archive_len(0), Err(ERR_ARCHIVE_RAW_SIZE));

        let seven_half_mib = (7 * 1024 * 1024) + (512 * 1024);
        let valid_raw = sample_archive_with_padding(seven_half_mib);
        assert_eq!(valid_raw.len(), seven_half_mib);
        assert!(validate_raw_archive_len(valid_raw.len()).is_ok());
        let prepared = prepare_preview_request("merge", &valid_raw)
            .expect("7.5 MiB native archive should pass client validation");
        assert_eq!(prepared["mode"], "merge");

        let exact_limit = sample_archive_with_padding(MAX_ARCHIVE_RAW_BYTES);
        assert_eq!(exact_limit.len(), MAX_ARCHIVE_RAW_BYTES);
        assert!(prepare_preview_request("merge", &exact_limit).is_ok());

        let over_archive = sample_archive_with_padding(MAX_ARCHIVE_RAW_BYTES + 1);
        assert_eq!(over_archive.len(), MAX_ARCHIVE_RAW_BYTES + 1);
        assert_eq!(
            prepare_preview_request("merge", &over_archive),
            Err(ERR_ARCHIVE_RAW_SIZE)
        );
    }

    #[test]
    fn accepts_nine_point_five_mib_envelope_and_rejects_over_ten_mib() {
        let nine_half_mib = (9 * 1024 * 1024) + (512 * 1024);
        let probe = json!({
            "mode": "replace",
            "archive": {
                "manifest": { "format": "aetherflow.streaming-history" },
                "data": { "blob": "" }
            }
        });
        let base_len = serde_json::to_vec(&probe).unwrap().len();
        let valid_envelope = json!({
            "mode": "replace",
            "archive": {
                "manifest": { "format": "aetherflow.streaming-history" },
                "data": { "blob": "b".repeat(nine_half_mib - base_len) }
            }
        });
        assert_eq!(
            serde_json::to_vec(&valid_envelope).unwrap().len(),
            nine_half_mib
        );
        assert!(validate_request_envelope(&valid_envelope).is_ok());

        let oversized_envelope = json!({
            "mode": "replace",
            "archive": {
                "manifest": { "format": "aetherflow.streaming-history" },
                "data": { "blob": "b".repeat((MAX_REQUEST_BODY_BYTES + 1) - base_len) }
            }
        });
        assert_eq!(
            serde_json::to_vec(&oversized_envelope).unwrap().len(),
            MAX_REQUEST_BODY_BYTES + 1
        );
        assert_eq!(
            validate_request_envelope(&oversized_envelope),
            Err(ERR_REQUEST_ENVELOPE_SIZE)
        );
    }
}
