//! Expiring server previews and reviewed reconciliation mutations.
use super::common::*;
use super::types::*;
use crate::state::app;
use crate::tabs::contracts;
use crate::tabs::l10n::{tt, tt_with, ConfirmDialog};
use af_web_core::api::ApiClient;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;
#[component]
pub(super) fn HistoryReconciliation(on_changed: Callback<()>) -> impl IntoView {
    let context = app();
    let ids = RwSignal::new(String::new());
    let limit = RwSignal::new("1000".to_string());
    let preview = RwSignal::new(Value::Null);
    let approved = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let op_ticket = RwSignal::new(0u64);
    let confirm = RwSignal::new(false);
    let result = RwSignal::new(None::<String>);
    let generation = RwSignal::new(0u64);
    let invalidate = Callback::new(move |(): ()| {
        preview.set(Value::Null);
        approved.set(false);
        confirm.set(false);
        generation.update(|n| *n = n.wrapping_add(1));
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
    let get_preview = Callback::new(move |(): ()| {
        if busy.get_untracked()
            || !context.is_admin_untracked()
            || !context.can_write_area_untracked(crate::state::PeerArea::Services)
        {
            return;
        }
        invalidate.run(());
        let parsed: Result<Vec<i64>, _> = ids
            .get_untracked()
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .map(str::parse::<i64>)
            .collect();
        let Ok(mut candidate_ids) = parsed else {
            result.set(Some(
                "Candidate IDs must be comma-separated positive integers.".into(),
            ));
            return;
        };
        candidate_ids.sort_unstable();
        candidate_ids.dedup();
        let limit_value = limit
            .get_untracked()
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=1000).contains(n));
        if limit_value.is_none()
            || candidate_ids.len() > 1000
            || candidate_ids.iter().any(|n| *n <= 0)
        {
            result.set(Some(
                "Use at most 1000 positive IDs and a limit of 1..1000.".into(),
            ));
            return;
        }
        let draft_ticket = generation.get_untracked();
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
                .post(
                    "/api/v1/admin/streaming/reconciliation/preview",
                    Some(&json!({"candidateIds":candidate_ids,"limit":limit_value})),
                )
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
                    preview.set(data);
                    result.set(None);
                }
                Err(e) => result.set(Some(e.message)),
            }
        });
    });
    let apply = Callback::new(move |(): ()| {
        if busy.get_untracked()
            || !approved.get_untracked()
            || !context.is_admin_untracked()
            || !context.can_write_area_untracked(crate::state::PeerArea::Services)
        {
            return;
        }
        let data = contracts::decode::<ReconciliationPreview>(&preview.get_untracked());
        if data.approval_token.is_empty() || data.preview_hash.is_empty() {
            return;
        }
        if timestamp(&data.expires_at).is_none_or(|expires| expires as f64 <= js_sys::Date::now()) {
            invalidate.run(());
            result.set(Some(
                "Reconciliation preview expired. Generate a new preview.".into(),
            ));
            return;
        }
        let body = json!({"previewHash":data.preview_hash,"approvalToken":data.approval_token});
        let draft_ticket = generation.get_untracked();
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
                .post("/api/v1/admin/streaming/reconciliation/apply", Some(&body))
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
                    context.toast(tt(context, "Reviewed reconciliation applied. Inspect its audit and backup receipt."),
                        false,
                    );
                }
                Err(e) => result.set(Some(if e.status == 409 {
                    tt_with(
                        context,
                        "Preview is stale; generate a new diff. {error}",
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
            <p class="text-xs text-amber-300">
                {move || tt(
                    context,
                    "A suspected legacy classification is a proposal, not proof of fabricated evidence. Review upstream records and each before/after change. Apply is bound to the exact preview hash, actor, revision and expiring token.",
                )}
            </p>
            <label class="block text-sm">
                {move || tt(context, "Candidate IDs (empty selects the bounded legacy cohort)")}
                <input
                    class="af-input p-2 w-full"
                    disabled=move || busy.get()
                    prop:value=move || ids.get()
                    on:input=move |e| {
                        ids.set(event_target_value(&e));
                        invalidate.run(());
                    }
                />
            </label>
            <label class="block text-sm">
                {move || tt(context, "Maximum candidates")}
                <input
                    type="number"
                    min="1"
                    max="1000"
                    class="af-input p-2"
                    disabled=move || busy.get()
                    prop:value=move || limit.get()
                    on:input=move |e| {
                        limit.set(event_target_value(&e));
                        invalidate.run(());
                    }
                />
            </label>
            <button
                class="af-btn px-4 py-2"
                disabled=move || {
                    busy.get() || !context.can_write_area(crate::state::PeerArea::Services)
                }
                title=move || {
                    context
                        .area_block_reason(crate::state::PeerArea::Services, true)
                        .unwrap_or_default()
                }
                on:click=move |_| get_preview.run(())
            >
                {move || tt(context, "Generate server dry-run diff")}
            </button>
            <Show when=move || preview.with(|v| v["previewHash"].is_string())>
                <div class="rounded-xl border border-amber-500/30 p-3 space-y-3">
                    <p class="text-xs break-all">
                        {move || {
                            preview
                                .with(|p| {
                                    tt_with(context, "Preview {preview} · {affected} affected rows · expires {expires}", &[("preview", &(text(p, "previewHash")).to_string()), ("affected", &(recorded(&crate::tabs::l10n::locale(context), p, "totalAffectedRows")).to_string()), ("expires", &(text(p, "expiresAt")).to_string())])
                                })
                        }}
                    </p>
                    <pre class="text-xs whitespace-pre-wrap break-all max-h-96 overflow-auto">
                        {move || {
                            preview
                                .with(|p| {
                                    serde_json::to_string_pretty(
                                            &json!(
                                                {"before":p["countsBefore"],"after":p["countsAfter"],"changes":p["affectedRows"]}
                                            ),
                                        )
                                        .unwrap_or_default()
                                })
                        }}
                    </pre>
                    <label class="text-sm flex items-start gap-2">
                        <input
                            type="checkbox"
                            disabled=move || busy.get()
                            prop:checked=move || approved.get()
                            on:change=move |e| approved.set(event_target_checked(&e))
                        />
                        {move || tt(
                            context,
                            "I verified upstream evidence and approve this exact reconciliation preview.",
                        )}
                    </label>
                    <button
                        class="af-btn-primary px-4 py-2"
                        disabled=move || {
                            busy.get()
                                || !approved.get()
                                || !context.can_write_area(crate::state::PeerArea::Services)
                        }
                        title=move || {
                            context
                                .area_block_reason(crate::state::PeerArea::Services, true)
                                .unwrap_or_default()
                        }
                        on:click=move |_| {
                            if context.can_write_area_untracked(crate::state::PeerArea::Services) {
                                confirm.set(true);
                            }
                        }
                    >
                        {move || tt(context, "Apply reviewed reconciliation")}
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
                title="Apply the approved history reconciliation?"
                message="Apply only the reviewed before/after changes. The backend revalidates the signed preview and creates the reconciliation audit/backup receipt."
                busy=Signal::derive(move || busy.get())
                on_confirm=apply
            />
        </div>
    }
}
