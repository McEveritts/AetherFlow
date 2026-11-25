//! Native archive export, typed summaries, and reviewed restore.
use super::common::*;
use super::types::*;
use crate::state::{app, AppContext};
use crate::tabs::contracts;
use crate::tabs::l10n::{tt, tt_with, ConfirmDialog};
use af_web_core::api::{current_auth_epoch, ApiClient};
use leptos::prelude::*;
use serde::Deserialize;
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportManifestOmitted {
    #[serde(default)]
    omitted_samples: Option<OmittedSamples>,
}

#[derive(Deserialize)]
struct ExportArchiveOmitted {
    manifest: ExportManifestOmitted,
}

fn parse_omitted_headers(
    telemetry: Option<&str>,
    session: Option<&str>,
    bandwidth: Option<&str>,
) -> Option<Option<OmittedSamples>> {
    let status = telemetry?.trim();
    if status.eq_ignore_ascii_case("complete") {
        return Some(None);
    }
    if !status.eq_ignore_ascii_case("partial") {
        return None;
    }
    let session_samples = session?.trim().parse::<u64>().ok()?;
    let bandwidth_samples = bandwidth?.trim().parse::<u64>().ok()?;
    let omitted = OmittedSamples {
        session_samples,
        bandwidth_samples,
        extra: Default::default(),
    };
    omitted.has_omissions().then_some(Some(omitted))
}

fn extract_omitted_samples_from_json(raw: &str) -> Option<OmittedSamples> {
    serde_json::from_str::<ExportArchiveOmitted>(raw)
        .ok()
        .and_then(|archive| archive.manifest.omitted_samples)
        .filter(OmittedSamples::has_omissions)
}

fn preview_summary_json(summary: &ArchivePreview) -> Value {
    let mut object = json!({
        "mode": summary.mode,
        "archiveCounts": summary.archive_counts,
        "targetCounts": summary.target_counts,
        "plan": summary.plan,
        "replacementCounts": summary.replacement_counts,
        "replacementNotice": summary.replacement_notice,
        "conflicts": summary.conflicts,
        "expiresAt": summary.expires_at
    });
    if let Some(map) = object.as_object_mut() {
        if let Some(omitted) = summary
            .omitted_samples
            .as_ref()
            .filter(|omitted| omitted.has_omissions())
        {
            map.insert("omittedSamples".into(), json!(omitted));
        }
        if let Some(notice) = &summary.partial_telemetry_notice {
            map.insert("partialTelemetryNotice".into(), json!(notice));
        }
    }
    object
}

fn partial_preview_warning(context: AppContext, summary: &ArchivePreview) -> Option<String> {
    if let Some(omitted) = summary
        .omitted_samples
        .as_ref()
        .filter(|omitted| omitted.has_omissions())
    {
        let session = omitted.session_samples.to_string();
        let bandwidth = omitted.bandwidth_samples.to_string();
        Some(if summary.mode == "replace" {
            tt_with(
                context,
                "Partial telemetry archive: {session} earlier session samples and {bandwidth} earlier bandwidth samples were omitted during export. Replacing history will delete destination samples and restore only the retained subset.",
                &[("session", &session), ("bandwidth", &bandwidth)],
            )
        } else {
            tt_with(
                context,
                "Partial telemetry archive: {session} earlier session samples and {bandwidth} earlier bandwidth samples were omitted during export. Merging will not restore those omitted earlier samples.",
                &[("session", &session), ("bandwidth", &bandwidth)],
            )
        })
    } else {
        summary.partial_telemetry_notice.clone()
    }
}

fn confirm_restore_message(context: AppContext, summary: &ArchivePreview) -> String {
    if summary.mode == "replace" {
        if let Some(omitted) = summary
            .omitted_samples
            .as_ref()
            .filter(|omitted| omitted.has_omissions())
        {
            let session = omitted.session_samples.to_string();
            let bandwidth = omitted.bandwidth_samples.to_string();
            return tt_with(
                context,
                "This partial archive omitted {session} earlier session samples and {bandwidth} earlier bandwidth samples; replacement mode will delete destination samples and restore only the retained subset. Confirm only the exact server-generated plan you reviewed; the signed token and archive are sent unchanged.",
                &[("session", &session), ("bandwidth", &bandwidth)],
            );
        }
    }
    tt(
        context,
        "Replacement mode can remove existing history. Confirm only the exact server-generated plan you reviewed; the signed token and archive are sent unchanged.",
    )
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
    let op_ticket = RwSignal::new(0u64);
    let approved = RwSignal::new(false);
    let confirm = RwSignal::new(false);
    let result = RwSignal::new(None::<String>);
    let export_omitted = RwSignal::new(None::<OmittedSamples>);
    let generation = RwSignal::new(0u64);
    let export_abort = StoredValue::new_local(web_sys::AbortController::new().ok());
    on_cleanup(move || {
        export_abort.with_value(|controller| {
            if let Some(controller) = controller {
                controller.abort();
            }
        });
    });
    let reset_export_abort = move || {
        export_abort.update_value(|controller| {
            if let Some(old) = controller.take() {
                old.abort();
            }
            *controller = web_sys::AbortController::new().ok();
        });
    };
    let invalidate = Callback::new(move |(): ()| {
        preview.set(Value::Null);
        frozen.set(Value::Null);
        approved.set(false);
        confirm.set(false);
        generation.update(|n| *n = n.wrapping_add(1));
    });
    let last_epochs = StoredValue::new((
        context.session_epoch.get_untracked(),
        context.server_epoch.get_untracked(),
        context.area_revocation_epoch_untracked(crate::state::PeerArea::Settings),
    ));
    Effect::new(move |_| {
        let next = (
            context.session_epoch.get(),
            context.server_epoch.get(),
            context.area_revocation_epoch(crate::state::PeerArea::Settings),
        );
        if last_epochs.get_value() == next {
            return;
        }
        last_epochs.set_value(next);
        reset_export_abort();
        op_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        busy.set(false);
        invalidate.run(());
        result.set(None);
        export_omitted.set(None);
    });
    Effect::new(move |_| {
        if !context.can_write_area(crate::state::PeerArea::Settings) {
            reset_export_abort();
            op_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            busy.set(false);
            invalidate.run(());
        }
    });
    let export = Callback::new(move |(): ()| {
        if busy.get_untracked()
            || !context.is_admin_untracked()
            || !context.can_write_area_untracked(crate::state::PeerArea::Settings)
        {
            return;
        }
        op_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = op_ticket.get_untracked();
        let fence = crate::tabs::busy::AreaFence::capture(
            context,
            crate::state::PeerArea::Settings,
            true,
            true,
            op_ticket,
            ticket,
        );
        let auth_epoch = current_auth_epoch();
        let signal = export_abort
            .with_value(|controller| controller.as_ref().map(web_sys::AbortController::signal));
        export_omitted.set(None);
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::for_generation(busy, op_ticket, ticket);
        spawn_local(async move {
            let is_current = || {
                busy.try_get_untracked().is_some()
                    && fence.is_valid()
                    && current_auth_epoch() == auth_epoch
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
                let headers = response.headers();
                let telemetry_header = headers
                    .get("x-aetherflow-archive-telemetry")
                    .ok()
                    .flatten();
                let omitted_session_header = headers
                    .get("x-aetherflow-omitted-session-samples")
                    .ok()
                    .flatten();
                let omitted_bw_header = headers
                    .get("x-aetherflow-omitted-bandwidth-samples")
                    .ok()
                    .flatten();
                let header_omitted = parse_omitted_headers(
                    telemetry_header.as_deref(),
                    omitted_session_header.as_deref(),
                    omitted_bw_header.as_deref(),
                );
                let blob = response.blob().await.map_err(|error| error.message)?;
                if !is_current() {
                    return Ok(());
                }
                download_blob(&blob, "aetherflow-streaming-archive.json")?;
                let omitted = match header_omitted {
                    Some(omitted) => omitted,
                    None => match JsFuture::from(blob.text()).await {
                        Ok(text) if is_current() => text
                            .as_string()
                            .as_deref()
                            .and_then(extract_omitted_samples_from_json),
                        _ => None,
                    },
                };
                if !is_current() {
                    return Ok(());
                }
                if let Some(omitted) = omitted {
                    let session = omitted.session_samples.to_string();
                    let bandwidth = omitted.bandwidth_samples.to_string();
                    export_omitted.set(Some(omitted));
                    context.toast_with(
                        "Partial telemetry archive exported: {session} earlier session samples and {bandwidth} earlier bandwidth samples were omitted to fit the 100,000-record archive limit.",
                        &[("session", &session), ("bandwidth", &bandwidth)],
                        false,
                    );
                }
                Ok(())
            }
            .await;
            if !is_current() {
                return;
            }
            busy_guard.release();
            if let Err(e) = response {
                result.set(Some(e));
            }
        });
    });
    let get_preview = Callback::new(move |(): ()| {
        if busy.get_untracked()
            || !context.is_admin_untracked()
            || !context.can_write_area_untracked(crate::state::PeerArea::Settings)
        {
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
        let draft_ticket = generation.get_untracked();
        op_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = op_ticket.get_untracked();
        let fence = crate::tabs::busy::AreaFence::capture(
            context,
            crate::state::PeerArea::Settings,
            true,
            true,
            op_ticket,
            ticket,
        );
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::for_generation(busy, op_ticket, ticket);
        spawn_local(async move {
            let response = ApiClient
                .post("/api/v1/admin/streaming/portability/preview", Some(&body))
                .await;
            if busy.try_get_untracked().is_none()
                || generation.try_get_untracked() != Some(draft_ticket)
                || !fence.is_valid()
            {
                return;
            }
            busy_guard.release();
            match response {
                Ok(data) => {
                    let mut body = body;
                    let summary = contracts::decode::<ArchivePreview>(&data);
                    if summary.approval_token.is_empty() {
                        result.set(Some(
                            "Archive preview is missing its approval token.".into(),
                        ));
                        return;
                    }
                    body["approvalToken"] = json!(summary.approval_token);
                    frozen.set(body);
                    preview.set(data);
                    result.set(None);
                }
                Err(e) => result.set(Some(e.message)),
            }
        });
    });
    let restore = Callback::new(move |(): ()| {
        if busy.get_untracked()
            || !approved.get_untracked()
            || !context.is_admin_untracked()
            || !context.can_write_area_untracked(crate::state::PeerArea::Settings)
        {
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
        let draft_ticket = generation.get_untracked();
        op_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = op_ticket.get_untracked();
        let fence = crate::tabs::busy::AreaFence::capture(
            context,
            crate::state::PeerArea::Settings,
            true,
            true,
            op_ticket,
            ticket,
        );
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::for_generation(busy, op_ticket, ticket);
        spawn_local(async move {
            let response = ApiClient
                .post("/api/v1/admin/streaming/portability/restore", Some(&body))
                .await;
            if busy.try_get_untracked().is_none()
                || generation.try_get_untracked() != Some(draft_ticket)
                || !fence.is_valid()
            {
                return;
            }
            busy_guard.release();
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
        });
    });
    view! {
        <div class="space-y-4 pt-3">
            <button
                class="af-btn px-4 py-2"
                disabled=move || {
                    busy.get() || !context.can_write_area(crate::state::PeerArea::Settings)
                }
                title=move || {
                    context
                        .area_block_reason(crate::state::PeerArea::Settings, true)
                        .unwrap_or_default()
                }
                on:click=move |_| export.run(())
            >
                {move || tt(context, "Export native JSON archive")}
            </button>
            <p class="text-xs text-slate-400">
                {move || tt(
                    context,
                    "Native JSON export preserves all playback history, labels, and tracking policy up to 100,000 total records and 8 MiB. Routine session and bandwidth samples beyond remaining capacity are truncated (oldest omitted) and flagged in the archive manifest.",
                )}
            </p>
            {move || {
                export_omitted.get().map(|omitted| {
                    view! {
                        <p
                            role="alert"
                            class="rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200"
                        >
                            {move || tt_with(
                                context,
                                "Partial telemetry archive exported: {session} earlier session samples and {bandwidth} earlier bandwidth samples were omitted to fit the 100,000-record archive limit.",
                                &[
                                    ("session", &omitted.session_samples.to_string()),
                                    ("bandwidth", &omitted.bandwidth_samples.to_string()),
                                ],
                            )}
                        </p>
                    }
                })
            }}
            <label class="block text-sm">
                {move || tt(context, "Restore mode")}
                <select
                    class="af-input p-2"
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
                    class="af-input p-3 w-full text-xs font-mono"
                    disabled=move || busy.get()
                    prop:value=move || raw.get()
                    on:input=move |e| {
                        raw.set(event_target_value(&e));
                        invalidate.run(());
                    }
                ></textarea>
            </label>
            <button
                class="af-btn px-4 py-2"
                disabled=move || {
                    busy.get() || !context.can_write_area(crate::state::PeerArea::Settings)
                }
                title=move || {
                    context
                        .area_block_reason(crate::state::PeerArea::Settings, true)
                        .unwrap_or_default()
                }
                on:click=move |_| get_preview.run(())
            >
                {move || tt(context, "Preview restore diff")}
            </button>
            <Show when=move || preview.with(|p| !contracts::decode::<ArchivePreview>(p).approval_token.is_empty())>
                <div class="space-y-3 rounded-xl border border-amber-500/30 p-3">
                    {move || {
                        let warning = preview.with(|p| {
                            let summary = contracts::decode::<ArchivePreview>(p);
                            partial_preview_warning(context, &summary)
                        });
                        warning.map(|text| {
                            view! {
                                <p
                                    role="alert"
                                    class="rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200"
                                >
                                    {text}
                                </p>
                            }
                        })
                    }}
                    <pre class="text-xs whitespace-pre-wrap break-all max-h-80 overflow-auto">
                        {move || {
                            preview
                                .with(|p| {
                                    let summary = contracts::decode::<ArchivePreview>(p);
                                    serde_json::to_string_pretty(&preview_summary_json(&summary))
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
                        class="af-btn-primary px-4 py-2"
                        disabled=move || {
                            busy.get()
                                || !approved.get()
                                || !context.can_write_area(crate::state::PeerArea::Settings)
                        }
                        title=move || {
                            context
                                .area_block_reason(crate::state::PeerArea::Settings, true)
                                .unwrap_or_default()
                        }
                        on:click=move |_| {
                            if context.can_write_area_untracked(crate::state::PeerArea::Settings) {
                                confirm.set(true);
                            }
                        }
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
                message=Signal::derive(move || {
                    preview.with(|p| {
                        let summary = contracts::decode::<ArchivePreview>(p);
                        confirm_restore_message(context, &summary)
                    })
                })
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

    #[test]
    fn partial_telemetry_headers_json_and_preview_summary_disclose_omitted_samples() {
        assert_eq!(parse_omitted_headers(None, None, None), None);
        assert_eq!(
            parse_omitted_headers(Some(" complete "), None, None),
            Some(None)
        );
        assert_eq!(
            parse_omitted_headers(Some("partial"), Some("12"), Some("3")),
            Some(Some(OmittedSamples {
                session_samples: 12,
                bandwidth_samples: 3,
                extra: Default::default(),
            }))
        );
        assert_eq!(
            parse_omitted_headers(Some("partial"), Some("0"), Some("0")),
            None
        );
        assert_eq!(
            parse_omitted_headers(Some("partial"), None, Some("3")),
            None
        );
        assert_eq!(
            parse_omitted_headers(Some("partial"), Some("bad"), Some("3")),
            None
        );
        assert_eq!(
            parse_omitted_headers(Some("unexpected"), Some("12"), Some("3")),
            None
        );

        let full_raw = r#"{"manifest":{"format":"aetherflow.streaming-history","recordCounts":{"history":1}},"data":{}}"#;
        assert_eq!(extract_omitted_samples_from_json(full_raw), None);

        let zeroed_raw = r#"{"manifest":{"format":"aetherflow.streaming-history","omittedSamples":{"sessionSamples":0,"bandwidthSamples":0}},"data":{}}"#;
        assert_eq!(extract_omitted_samples_from_json(zeroed_raw), None);

        let partial_raw = r#"{"manifest":{"format":"aetherflow.streaming-history","recordCounts":{"history":1},"omittedSamples":{"sessionSamples":42,"bandwidthSamples":7}},"data":{"history":[]}}"#;
        assert_eq!(
            extract_omitted_samples_from_json(partial_raw),
            Some(OmittedSamples {
                session_samples: 42,
                bandwidth_samples: 7,
                extra: Default::default(),
            })
        );

        let full_preview: ArchivePreview = serde_json::from_value(json!({
            "mode": "replace",
            "approvalToken": "tok",
            "archiveCounts": {"history": 1},
            "targetCounts": {"history": 0},
            "plan": {"insert": {"history": 1}},
            "conflicts": [],
            "expiresAt": "2026-11-20T00:00:00Z"
        }))
        .unwrap();
        let full_summary = preview_summary_json(&full_preview);
        assert!(full_summary.get("omittedSamples").is_none());
        assert!(full_summary.get("partialTelemetryNotice").is_none());

        let partial_replace_preview: ArchivePreview = serde_json::from_value(json!({
            "mode": "replace",
            "approvalToken": "tok",
            "archiveCounts": {"history": 1},
            "targetCounts": {"history": 0},
            "plan": {"insert": {"history": 1}},
            "omittedSamples": {"sessionSamples": 42, "bandwidthSamples": 7},
            "partialTelemetryNotice": "Partial telemetry archive",
            "conflicts": [],
            "expiresAt": "2026-11-20T00:00:00Z"
        }))
        .unwrap();
        let partial_summary = preview_summary_json(&partial_replace_preview);
        assert_eq!(partial_summary["omittedSamples"]["sessionSamples"], 42);
        assert_eq!(partial_summary["omittedSamples"]["bandwidthSamples"], 7);
        assert_eq!(
            partial_summary["partialTelemetryNotice"],
            "Partial telemetry archive"
        );

        let partial_merge_preview: ArchivePreview = serde_json::from_value(json!({
            "mode": "merge",
            "approvalToken": "tok",
            "archiveCounts": {"history": 1},
            "targetCounts": {"history": 0},
            "plan": {"insert": {"history": 1}},
            "omittedSamples": {"sessionSamples": 42, "bandwidthSamples": 7},
            "conflicts": [],
            "expiresAt": "2026-11-20T00:00:00Z"
        }))
        .unwrap();

        let owner = Owner::new();
        owner.with(|| {
            let context = AppContext::new();
            assert_eq!(partial_preview_warning(context, &full_preview), None);
            assert!(!confirm_restore_message(context, &full_preview).contains("omitted"));

            let replace_warn = partial_preview_warning(context, &partial_replace_preview).unwrap();
            assert!(replace_warn.contains("42"));
            assert!(replace_warn.contains("7"));
            assert!(replace_warn.contains("Replacing history"));

            let replace_confirm = confirm_restore_message(context, &partial_replace_preview);
            assert!(replace_confirm.contains("42"));
            assert!(replace_confirm.contains("7"));
            assert!(replace_confirm.contains("replacement mode will delete destination samples"));

            let merge_warn = partial_preview_warning(context, &partial_merge_preview).unwrap();
            assert!(merge_warn.contains("42"));
            assert!(merge_warn.contains("7"));
            assert!(merge_warn.contains("Merging will not restore"));
        });
    }

    fn parse_portability_contract_fixture(
        raw: &str,
    ) -> Result<(super::super::types::PortableArchive, ArchivePreview, Value), String> {
        let root: Value = serde_json::from_str(raw)
            .map_err(|e| format!("malformed portability fixture JSON: {e}"))?;
        let obj = root
            .as_object()
            .ok_or_else(|| "portability fixture root must be a JSON object".to_string())?;
        let archive_val = obj
            .get("archive")
            .ok_or_else(|| "portability fixture missing 'archive'".to_string())?;
        let preview_val = obj
            .get("preview")
            .ok_or_else(|| "portability fixture missing 'preview'".to_string())?;
        let restored_val = obj
            .get("restored")
            .ok_or_else(|| "portability fixture missing 'restored'".to_string())?;
        if !restored_val.is_object() {
            return Err("portability fixture 'restored' must be a JSON object".to_string());
        }
        let archive: super::super::types::PortableArchive =
            serde_json::from_value(archive_val.clone())
                .map_err(|e| format!("failed to decode portability fixture archive: {e}"))?;
        let preview: ArchivePreview = serde_json::from_value(preview_val.clone())
            .map_err(|e| format!("failed to decode portability fixture preview: {e}"))?;
        Ok((archive, preview, restored_val.clone()))
    }

    #[test]
    fn streaming_portability_fixture_decodes_archive_preview_and_restored() {
        let from_env = std::env::var_os("AF_STREAMING_PORTABILITY_FIXTURE");
        let raw = if let Some(path) = &from_env {
            std::fs::read_to_string(path).unwrap_or_else(|e| {
                panic!(
                    "AF_STREAMING_PORTABILITY_FIXTURE={:?} unreadable (fail-closed): {e}",
                    path
                )
            })
        } else {
            json!({
                "archive": {
                    "manifest": {
                        "format": "aetherflow.streaming-history",
                        "formatVersion": 1,
                        "recordCounts": { "history": 1 }
                    },
                    "data": { "history": [] }
                },
                "preview": {
                    "mode": "merge",
                    "approvalToken": "inline-approval-token",
                    "archiveCounts": { "history": 1 },
                    "targetCounts": { "history": 0 },
                    "plan": { "insert": { "history": 1 } },
                    "conflicts": [],
                    "expiresAt": "2026-12-01T00:00:00Z"
                },
                "restored": { "status": "ok" }
            })
            .to_string()
        };

        let (archive, preview, restored) = parse_portability_contract_fixture(&raw)
            .expect("AF_STREAMING_PORTABILITY_FIXTURE must decode cleanly");
        assert_eq!(archive.manifest.format, "aetherflow.streaming-history");
        assert!(!preview.approval_token.is_empty());
        assert!(restored.is_object());

        // Verify fail-closed rejection on malformed/missing-slot JSON.
        assert!(parse_portability_contract_fixture("{bad").is_err());
        assert!(parse_portability_contract_fixture(r#"{"archive":{}}"#).is_err());
    }
}
