//! Exporter normalization and explicit typed import validation previews.
use super::common::*;
use super::types::*;
use crate::state::app;
use crate::tabs::contracts;
use crate::tabs::l10n::{tt, tt_with, ConfirmDialog};
use af_web_core::api::ApiClient;
use leptos::prelude::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::{spawn_local, JsFuture};
fn import_scalar(row: &Value, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| {
        row.pointer(path).and_then(|v| match v {
            Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
    })
}
fn import_date(row: &Value, paths: &[&str]) -> Option<String> {
    let raw = import_scalar(row, paths)?;
    if let Ok(seconds) = raw.parse::<f64>() {
        if !seconds.is_finite() || seconds <= 0.0 {
            return None;
        }
        return js_sys::Date::new(&JsValue::from_f64(seconds * 1000.0))
            .to_iso_string()
            .as_string();
    }
    timestamp(&raw).map(|_| raw)
}
/// Normalize known exporter fields only. Missing identities/timestamps fail closed.
fn normalize_import_event(locale: &str, row: &Value, format: &str) -> Result<ImportEvent, String> {
    if format == "canonical" {
        for field in ["sourceEventId", "userId", "itemId", "itemName", "startedAt"] {
            if row[field]
                .as_str()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(af_web_core::i18n::translate_with(locale, "Canonical events require an explicit {field}; exporter aliases are not substituted.", &[("field", (field))]));
            }
        }
        if timestamp(&text(row, "startedAt")).is_none() {
            return Err("Canonical startedAt must contain a valid upstream timestamp.".into());
        }
        let event: ImportEvent = serde_json::from_value(row.clone()).map_err(|e| e.to_string())?;
        return Ok(event);
    }
    let mut event = json!({});
    for (key, paths) in [
        (
            "sourceEventId",
            &["/sourceEventId", "/Id", "/id", "/row_id"][..],
        ),
        ("userId", &["/userId", "/UserId", "/user_id"][..]),
        (
            "itemId",
            &["/itemId", "/ItemId", "/NowPlayingItem/Id", "/rating_key"][..],
        ),
        (
            "itemName",
            &[
                "/itemName",
                "/ItemName",
                "/NowPlayingItem/Name",
                "/full_title",
                "/title",
            ][..],
        ),
    ] {
        event[key] =
            json!(
                import_scalar(row, paths).ok_or_else(|| af_web_core::i18n::translate_with(
                    locale,
                    "Event requires a stable {key}; names cannot substitute for IDs.",
                    &[("key", (key))]
                ))?
            );
    }
    event["startedAt"] = json!(import_date(
        row,
        &[
            "/startedAt",
            "/ActivityDateInserted",
            "/started_at",
            "/started"
        ]
    )
    .ok_or("Event requires a recorded startedAt timestamp.")?);
    if let Some(ended) = import_date(row, &["/endedAt", "/ended_at", "/stopped"]) {
        event["endedAt"] = json!(ended);
    }
    for (key, paths) in [
        ("userName", &["/userName", "/UserName", "/user"][..]),
        (
            "seriesName",
            &[
                "/seriesName",
                "/NowPlayingItem/SeriesName",
                "/grandparent_title",
            ][..],
        ),
        ("clientName", &["/clientName", "/Client", "/player"][..]),
        (
            "deviceName",
            &["/deviceName", "/DeviceName", "/platform"][..],
        ),
        ("ipAddress", &["/ipAddress", "/ip_address"][..]),
    ] {
        if let Some(value) = import_scalar(row, paths) {
            event[key] = json!(value);
        }
    }
    if let Some(kind) = import_scalar(row, &["/itemType", "/NowPlayingItem/Type", "/media_type"]) {
        event["itemType"] = json!(match kind.to_ascii_lowercase().as_str() {
            "movie" => "Movie",
            "episode" => "Episode",
            "track" | "audio" => "Audio",
            _ => &kind,
        });
    }
    for key in [
        "itemType",
        "playMethod",
        "seriesId",
        "seasonNumber",
        "episodeNumber",
        "productionYear",
        "watchedSecs",
        "durationSecs",
        "container",
        "videoCodec",
        "videoResolution",
        "audioCodec",
        "audioChannels",
        "subtitleCodec",
        "hwAccel",
        "bitrateBps",
        "estimatedBytes",
        "deviceId",
        "libraries",
        "genres",
    ] {
        if let Some(value) = row.get(key) {
            event[key] = value.clone();
        }
    }
    if format == "tautulli" {
        if event["watchedSecs"].is_null() {
            if let Some(value) = row["play_duration"]
                .as_f64()
                .or_else(|| row["play_duration"].as_str().and_then(|s| s.parse().ok()))
            {
                event["watchedSecs"] = json!(value.max(0.0).floor() as u64);
            }
        }
        if event["durationSecs"].is_null() {
            if let Some(value) = row["duration"]
                .as_f64()
                .or_else(|| row["duration"].as_str().and_then(|s| s.parse().ok()))
            {
                event["durationSecs"] = json!((value / 1000.0).max(0.0).floor() as u64);
            }
        }
    }
    serde_json::from_value(event).map_err(|e| e.to_string())
}

pub(super) fn format_summary_sync_feedback(locale: &str, data: &Value) -> String {
    let count = recorded(locale, data, "imported");
    let is_partial = data["has_more"] == Value::Bool(true)
        || data["hasMore"] == Value::Bool(true)
        || data["complete"] == Value::Bool(false);
    if is_partial {
        let mut message = af_web_core::i18n::translate_with(
            locale,
            "Synchronized {count} item summaries in this bounded batch. Additional items remain; click synchronize again to resume from the saved checkpoint. These are not confirmed playback events.",
            &[("count", &count)],
        );
        if let Some(remaining) = data["remaining_sources"]
            .as_u64()
            .or_else(|| data["remainingSources"].as_u64())
            .filter(|&n| n > 0)
        {
            message.push(' ');
            message.push_str(&af_web_core::i18n::translate_with(
                locale,
                "({remaining} remaining sources)",
                &[("remaining", &remaining.to_string())],
            ));
        }
        message
    } else {
        af_web_core::i18n::translate_with(
            locale,
            "Synchronized {count} item summaries and available metadata. These are not confirmed playback events.",
            &[("count", &count)],
        )
    }
}

#[component]
pub(super) fn HistoryEventImport(
    servers: Signal<Vec<ProviderStatus>>,
    status: Signal<Value>,
    on_changed: Callback<()>,
) -> impl IntoView {
    let context = app();
    let raw = RwSignal::new(String::new());
    let format = RwSignal::new("canonical".to_string());
    let binding = RwSignal::new(String::new());
    let source = RwSignal::new("json".to_string());
    let checkpoint = RwSignal::new(String::new());
    let prepared = RwSignal::new(None::<ImportBatch>);
    let busy = RwSignal::new(false);
    let op_ticket = RwSignal::new(0u64);
    let confirm = RwSignal::new(false);
    let result = RwSignal::new(None::<String>);
    let revision = RwSignal::new(0u64);
    let invalidate = Callback::new(move |(): ()| {
        prepared.set(None);
        confirm.set(false);
        revision.update(|n| *n = n.wrapping_add(1));
    });
    let validate = Callback::new(move |(): ()| {
        invalidate.run(());
        let selection = binding.get_untracked();
        let content = raw.get_untracked();
        let result_value: Result<ImportBatch, String> = (|| {
            if content.is_empty() || content.len() > 1024 * 1024 {
                return Err("Event input must contain 1 byte to 1 MiB of JSON.".into());
            }
            let server = servers
                .get_untracked()
                .into_iter()
                .find(|s| {
                    format!("{}:{}", s.provider, s.server_id) == selection
                        && !s.server_id.is_empty()
                })
                .ok_or("Choose a verified server identity.")?;
            let provider = server.provider.clone();
            let server_id = server.server_id.clone();
            let format = format.get_untracked();
            if format == "tautulli" && provider != "plex" {
                return Err("Tautulli records belong to Plex. They cannot be rebound to Jellyfin or Emby. Plex import requires server-side support advertised in import capabilities.".into());
            }
            let status = contracts::decode::<ImportStatus>(&status.get_untracked());
            let capability = status
                .capabilities
                .iter()
                .find(|c| c.provider == provider && c.server_id == server_id);
            if capability.is_none_or(|c| !c.json_batch_import_supported) {
                return Err("This server does not advertise JSON event import support. Inspect the capability status below.".into());
            }
            let parsed: Value = serde_json::from_str(&content).map_err(|e| e.to_string())?;
            for (key, expected) in [("provider", &provider), ("serverId", &server_id)] {
                if parsed[key].as_str().is_some_and(|value| value != expected) {
                    return Err(tt_with(
                        context,
                        "Batch {key} conflicts with the selected server identity.",
                        &[("key", (key))],
                    ));
                }
            }
            let input = parsed
                .as_array()
                .or_else(|| parsed["events"].as_array())
                .or_else(|| parsed["data"].as_array())
                .or_else(|| parsed["response"]["data"]["data"].as_array())
                .ok_or("Expected an array, an events batch, or a source export data array.")?;
            let maximum = status.max_batch_events.unwrap_or(500).min(500);
            if input.is_empty() || input.len() > maximum {
                return Err(tt_with(
                    context,
                    "A batch must contain 1..{maximum} source events.",
                    &[("maximum", &(maximum).to_string())],
                ));
            }
            let mut events = Vec::with_capacity(input.len());
            let mut seen = std::collections::BTreeSet::new();
            for (index, row) in input.iter().enumerate() {
                let event =
                    normalize_import_event(&crate::tabs::l10n::locale(context), row, &format)
                        .map_err(|e| {
                            tt_with(
                                context,
                                "Event {index}: {error}",
                                &[
                                    ("index", &(index + 1).to_string()),
                                    ("error", &tt(context, &e)),
                                ],
                            )
                        })?;
                if !seen.insert(event.source_event_id.clone()) {
                    return Err(
                        "Duplicate sourceEventId within this batch. Review the upstream export."
                            .into(),
                    );
                }
                events.push(event);
            }
            let source = parsed["source"]
                .as_str()
                .unwrap_or(&source.get_untracked())
                .trim()
                .to_string();
            let checkpoint = parsed["checkpoint"]
                .as_str()
                .unwrap_or(&checkpoint.get_untracked())
                .trim()
                .to_string();
            if source.is_empty() || checkpoint.is_empty() {
                return Err("Source and a new opaque checkpoint are required.".into());
            }
            let expected = status
                .checkpoints
                .iter()
                .find(|r| r.provider == provider && r.server_id == server_id && r.source == source)
                .and_then(|r| r.checkpoint.as_ref())
                .map(|value| json!(value))
                .unwrap_or(Value::Null);
            if parsed
                .get("expectedCheckpoint")
                .is_some_and(|value| value != &expected)
            {
                return Err("The batch expectedCheckpoint does not match the current source checkpoint. Refresh status and review.".into());
            }
            Ok(ImportBatch {
                provider,
                server_id,
                server_name: Some(server.name),
                source,
                checkpoint,
                expected_checkpoint: expected.as_str().map(str::to_owned),
                events,
                extra: BTreeMap::new(),
            })
        })();
        match result_value {
            Ok(body) => {
                prepared.set(Some(body));
                result.set(None);
            }
            Err(e) => result.set(Some(e)),
        }
    });
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(crate::state::PeerArea::Services);
        op_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        busy.set(false);
        invalidate.run(());
        result.set(None);
    });
    Effect::new(move |_| {
        if !context.can_write_area(crate::state::PeerArea::Services) {
            op_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            busy.set(false);
            invalidate.run(());
        }
    });
    let import = Callback::new(move |(): ()| {
        if busy.get_untracked()
            || !context.is_admin_untracked()
            || !context.can_write_area_untracked(crate::state::PeerArea::Services)
            || prepared.with_untracked(Option::is_none)
        {
            return;
        }
        let Some(body) = prepared.get_untracked() else {
            return;
        };
        let body = serde_json::to_value(body).unwrap_or_default();
        let draft_ticket = revision.get_untracked();
        op_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = op_ticket.get_untracked();
        let fence = crate::tabs::busy::AreaFence::capture(
            context,
            crate::state::PeerArea::Services,
            true,
            true,
            op_ticket,
            ticket,
        );
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::for_generation(busy, op_ticket, ticket);
        spawn_local(async move {
            let response = ApiClient
                .post("/api/v1/admin/streaming/imports/events", Some(&body))
                .await;
            if busy.try_get_untracked().is_none()
                || revision.try_get_untracked() != Some(draft_ticket)
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
                    prepared.set(None);
                    on_changed.run(());
                    context.toast(tt(context, "Canonical source events imported; inspect duplicate and overlap outcomes."),false);
                }
                Err(e) => {
                    result.set(Some(e.message.clone()));
                    context.toast(tt(context, &e.message), true);
                    prepared.set(None);
                }
            }
            confirm.set(false);
        });
    });
    let sync = Callback::new(move |(): ()| {
        if busy.get_untracked()
            || !context.is_admin_untracked()
            || !context.can_write_area_untracked(crate::state::PeerArea::Services)
        {
            return;
        }
        op_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = op_ticket.get_untracked();
        let fence = crate::tabs::busy::AreaFence::capture(
            context,
            crate::state::PeerArea::Services,
            true,
            true,
            op_ticket,
            ticket,
        );
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::for_generation(busy, op_ticket, ticket);
        spawn_local(async move {
            let response = ApiClient
                .post("/api/v1/admin/streaming/servers/jellyfin/sync", None)
                .await;
            if busy.try_get_untracked().is_none() || !fence.is_valid() {
                return;
            }
            busy_guard.release();
            match response {
                Ok(data) => {
                    result.set(Some(format_summary_sync_feedback(
                        &crate::tabs::l10n::locale(context),
                        &data,
                    )));
                    on_changed.run(());
                }
                Err(e) => result.set(Some(e.message)),
            }
        });
    });
    view! {
        <div class="space-y-4 pt-3">
            <p class="text-xs text-slate-400">
                {move || tt(
                    context,
                    "Import is limited to providers advertised by the server. Source IDs and upstream timestamps are preserved; records are never matched by display name. Tautulli requires a verified Plex source.",
                )}
            </p>
            <div class="grid sm:grid-cols-2 gap-3">
                <label class="text-sm">
                    {move || tt(context, "Source format")}
                    <select
                        class="glass-input p-2 w-full"
                        disabled=move || busy.get()
                        prop:value=move || format.get()
                        on:change=move |e| {
                            format.set(event_target_value(&e));
                            invalidate.run(());
                        }
                    >
                        <option value="canonical">
                            {move || tt(context, "Canonical JSON event batch")}
                        </option>
                        <option value="jellystat">
                            {move || tt(context, "Jellystat JSON events")}
                        </option>
                        <option value="tautulli">
                            {move || tt(context, "Tautulli JSON events")}
                        </option>
                    </select>
                </label>
                <label class="text-sm">
                    {move || tt(context, "Bind to verified server")}
                    <select
                        class="glass-input p-2 w-full"
                        disabled=move || busy.get()
                        prop:value=move || binding.get()
                        on:change=move |e| {
                            binding.set(event_target_value(&e));
                            invalidate.run(());
                        }
                    >
                        <option value="">{move || tt(context, "Select server identity")}</option>
                        {move || {
                            servers
                                .get()
                                .into_iter()
                                .filter(|s| !s.server_id.is_empty())
                                .map(|server| {
                                    view! {
                                        <option value=format!(
                                            "{}:{}",
                                            server.provider.clone(),
                                            server.server_id.clone(),
                                        )>
                                            {format!(
                                                "{} · {} · {}",
                                                server.name.clone(),
                                                server.provider.clone(),
                                                server.server_id.clone(),
                                            )}
                                        </option>
                                    }
                                })
                                .collect_view()
                        }}
                    </select>
                </label>
                <label class="text-sm">
                    {move || tt(context, "Source / checkpoint namespace")}
                    <input
                        class="glass-input p-2 w-full"
                        disabled=move || busy.get()
                        prop:value=move || source.get()
                        on:input=move |e| {
                            source.set(event_target_value(&e));
                            invalidate.run(());
                        }
                    />
                </label>
                <label class="text-sm">
                    {move || tt(context, "New opaque checkpoint")}
                    <input
                        class="glass-input p-2 w-full"
                        disabled=move || busy.get()
                        prop:value=move || checkpoint.get()
                        on:input=move |e| {
                            checkpoint.set(event_target_value(&e));
                            invalidate.run(());
                        }
                    />
                </label>
            </div>
            <label class="block text-sm">
                {move || tt(context, "Import JSON file (maximum 1 MiB)")}
                <input
                    type="file"
                    accept=".json,application/json"
                    disabled=move || busy.get()
                    on:change=move |e| {
                        let input = event_target::<web_sys::HtmlInputElement>(&e);
                        if let Some(file) = input.files().and_then(|files| files.get(0)) {
                            invalidate.run(());
                            if file.size() > 1024.0 * 1024.0 {
                                result.set(Some("Import file exceeds 1 MiB.".into()));
                                return;
                            }
                            let ticket = revision.get_untracked();
                            spawn_local(async move {
                                let result_value = JsFuture::from(file.text()).await;
                                if revision.try_get_untracked() != Some(ticket) {
                                    return;
                                }
                                match result_value {
                                    Ok(value) => raw.set(value.as_string().unwrap_or_default()),
                                    Err(e) => result.set(Some(js_error(e))),
                                }
                            });
                        }
                    }
                />
            </label>
            <label class="block text-sm">
                {move || tt(context, "Source event JSON")}
                <textarea
                    rows="7"
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
                on:click=move |_| validate.run(())
            >
                {move || tt(context, "Validate and preview normalized batch")}
            </button>
            <Show when=move || prepared.with(Option::is_some)>
                <div class="space-y-3 rounded-xl border border-amber-500/30 p-3">
                    <p class="text-sm text-amber-300">
                        {move || {
                            prepared
                                .with(|p| {
                                    tt_with(context, "Validation preview · {count} events · no database writes", &[("count", &(p.as_ref().map(|batch| batch.events.len()).unwrap_or_default()).to_string())])
                                })
                        }}
                    </p>
                    <p class="text-xs text-slate-400">
                        {move || tt(
                            context,
                            "Duplicate and overlap dispositions are computed transactionally on import. This validation preview does not claim a server-side diff.",
                        )}
                    </p>
                    <pre class="text-xs whitespace-pre-wrap break-all max-h-64 overflow-auto">
                        {move || serde_json::to_string_pretty(&prepared.get()).unwrap_or_default()}
                    </pre>
                    <button
                        class="glass-button-primary px-4 py-2"
                        disabled=move || {
                            busy.get() || !context.can_write_area(crate::state::PeerArea::Services)
                        }
                        title=move || {
                            context
                                .area_block_reason(crate::state::PeerArea::Services, true)
                                .unwrap_or_default()
                        }
                        on:click=move |_| confirm.set(true)
                    >
                        {move || tt(context, "Import reviewed events")}
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
            <details>
                <summary class="cursor-pointer text-sm">
                    {move || tt(context, "Current import capabilities and checkpoints")}
                </summary>
                <pre class="text-xs whitespace-pre-wrap break-all max-h-64 overflow-auto">
                    {move || serde_json::to_string_pretty(&status.get()).unwrap_or_default()}
                </pre>
            </details>
            <button
                class="glass-button px-4 py-2"
                disabled=move || {
                    busy.get() || !context.can_write_area(crate::state::PeerArea::Services)
                }
                title=move || {
                    context
                        .area_block_reason(crate::state::PeerArea::Services, true)
                        .unwrap_or_default()
                }
                on:click=move |_| sync.run(())
            >
                {move || tt(context, "Sync Jellyfin item summaries & metadata")}
            </button>
            <ConfirmDialog
                open=confirm
                title="Import this reviewed event batch?"
                message="The reviewed source events will be written using their bound provider/server identity and expected checkpoint. Existing observed evidence and overlap policy remain authoritative."
                busy=Signal::derive(move || busy.get())
                on_confirm=import
            />
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_sync_feedback_distinguishes_partial_batches_from_complete_sweeps() {
        let partial = format_summary_sync_feedback(
            "en",
            &json!({
                "imported": 800,
                "complete": false,
                "has_more": true,
                "remaining_sources": 3
            }),
        );
        assert!(partial.contains("800"));
        assert!(partial.contains("bounded batch"));
        assert!(partial.contains("resume from the saved checkpoint"));
        assert!(partial.contains("3 remaining sources"));

        let incomplete_only = format_summary_sync_feedback(
            "en",
            &json!({
                "imported": 250,
                "complete": false
            }),
        );
        assert!(incomplete_only.contains("250"));
        assert!(incomplete_only.contains("bounded batch"));
        assert!(!incomplete_only.contains("remaining sources"));

        let finished = format_summary_sync_feedback(
            "en",
            &json!({
                "imported": 42,
                "complete": true,
                "has_more": false,
                "remaining_sources": 0
            }),
        );
        assert_eq!(
            finished,
            "Synchronized 42 item summaries and available metadata. These are not confirmed playback events."
        );
    }
}
