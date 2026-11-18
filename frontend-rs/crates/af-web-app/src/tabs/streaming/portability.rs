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
        if content.is_empty() || content.len() > 8 * 1024 * 1024 {
            result.set(Some("Choose an archive of 1 byte to 8 MiB.".into()));
            return;
        }
        let archive = match serde_json::from_str::<Value>(&content) {
            Ok(value)
                if serde_json::from_value::<PortableArchive>(value.clone()).is_ok_and(
                    |archive| archive.manifest.format == "aetherflow.streaming-history",
                ) =>
            {
                value
            }
            _ => {
                result.set(Some(
                    "Choose a native aetherflow.streaming-history archive with manifest and data."
                        .into(),
                ));
                return;
            }
        };
        let body = json!({"mode":mode.get_untracked(),"archive":archive});
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
                {move || tt(context, "Native archive JSON file (maximum 8 MiB)")}
                <input
                    type="file"
                    accept=".json,application/json"
                    disabled=move || busy.get()
                    on:change=move |e| {
                        let input = event_target::<web_sys::HtmlInputElement>(&e);
                        if let Some(file) = input.files().and_then(|files| files.get(0)) {
                            invalidate.run(());
                            if file.size() > 8.0 * 1024.0 * 1024.0 {
                                result.set(Some("Archive exceeds 8 MiB.".into()));
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
