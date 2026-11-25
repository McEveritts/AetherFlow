//! Read-only access policy and the backend's recorded McBrowser operations.
use super::types::{AuditPage, SharePolicy};
use crate::state::{app, use_api_when, PeerArea};
use crate::tabs::contracts::decode;
use crate::tabs::l10n::{tt, Badge, EmptyState, ObsCard};
use crate::tabs::settings::ResourceFeedback;
use leptos::prelude::*;

#[component]
pub(super) fn SharePolicyView() -> impl IntoView {
    let context = app();
    let can_read_files = Signal::derive(move || context.can_read_area(PeerArea::Files));
    let resource = use_api_when(can_read_files, "/api/v1/auth/mcbrowser/policy".to_owned());
    let policy = Signal::derive(move || decode::<SharePolicy>(&resource.data.get()));
    view! {
        <ObsCard title="Share policy">
            <div class="space-y-4 min-w-0 max-w-full">
                <Show when=move || !can_read_files.get()>
                    <p role="status" class="text-sm text-amber-300">
                        {move || {
                            context
                                .area_block_reason(PeerArea::Files, false)
                                .unwrap_or_default()
                        }}
                    </p>
                </Show>
                <ResourceFeedback resource />
                <Show when=move || can_read_files.get() && !resource.loading.get() && resource.error.with(Option::is_none)>
                    <p class="text-sm break-all">{move || policy.get().scope}</p>
                    <div class="flex flex-wrap gap-3">
                        {[("Share", true), ("Download", false)].into_iter().map(|(label, share)| view! {
                            <div class="text-sm space-y-1">
                                <span>{move || tt(context, label)}</span>
                                <Badge label=Signal::derive(move || {
                                    let permissions = policy.get().permissions;
                                    tt(context, match if share { permissions.share } else { permissions.download } {
                                        Some(true) => "Allowed", Some(false) => "Denied", None => "Unrecorded",
                                    })
                                }) />
                            </div>
                        }).collect_view()}
                    </div>
                    <pre class="text-xs whitespace-pre-wrap break-all max-h-96 overflow-auto">
                        {move || serde_json::to_string_pretty(&policy.get()).unwrap_or_default()}
                    </pre>
                </Show>
            </div>
        </ObsCard>
    }
}

#[component]
pub(super) fn ShareAuditView() -> impl IntoView {
    let context = app();
    let can_read_files =
        Signal::derive(move || context.is_admin() && context.can_read_area(PeerArea::Files));
    let resource = use_api_when(
        can_read_files,
        "/api/v1/auth/mcbrowser/audit-events?limit=100".to_owned(),
    );
    let audit = Signal::derive(move || decode::<AuditPage>(&resource.data.get()));
    view! {
        <ObsCard title="Audit log">
            <div class="space-y-4 min-w-0 max-w-full">
                <Show when=move || !can_read_files.get()>
                    <p role="status" class="text-sm text-amber-300">
                        {move || {
                            context
                                .area_block_reason(PeerArea::Files, false)
                                .unwrap_or_default()
                        }}
                    </p>
                </Show>
                <button
                    class="af-btn px-3 py-2"
                    disabled=move || !can_read_files.get()
                    title=move || {
                        context
                            .area_block_reason(PeerArea::Files, false)
                            .unwrap_or_default()
                    }
                    on:click=move |_| {
                        if can_read_files.get_untracked() {
                            resource.refresh();
                        }
                    }
                >
                    {move || tt(context, "Common.refresh")}
                </button>
                <ResourceFeedback resource />
                <div class="overflow-x-auto max-w-full">
                    <table class="w-full text-sm text-left">
                        <thead><tr>
                            {["Time", "User", "Action", "Path", "Status"].into_iter().map(|label| view! {
                                <th class="p-3">{move || tt(context, label)}</th>
                            }).collect_view()}
                        </tr></thead>
                        <tbody>{move || {
                            if !can_read_files.get() {
                                Vec::new()
                            } else {
                                audit.get().events
                            }
                            .into_iter()
                            .map(|row| view! {
                                <tr class="border-t border-[var(--af-border-hairline)]">
                                    <td class="p-3 whitespace-nowrap">{row.timestamp}</td>
                                    <td class="p-3 break-all">{row.username}</td>
                                    <td class="p-3 break-all">{row.trigger}</td>
                                    <td class="p-3 break-all">{row.relative_path}</td>
                                    <td class="p-3">{move || tt(context, &row.status)}</td>
                                </tr>
                            }).collect_view()
                        }}</tbody>
                    </table>
                </div>
                <Show when=move || can_read_files.get() && !resource.loading.get() && resource.error.with(Option::is_none) && audit.get().events.is_empty()>
                    <EmptyState title="No matching events" />
                </Show>
                <Show when=move || can_read_files.get() && audit.get().truncated>
                    <p class="text-xs text-slate-400">{move || tt(context, "Showing the latest 100 events")}</p>
                </Show>
            </div>
        </ObsCard>
    }
}
