use super::contracts::{grid_resource, use_api_typed_when, Records, UserQuota};
use super::settings::{
    bytes, draft_value, poll_resource_when, text, DraftButtons, DraftInput, ResourceFeedback,
};
use crate::state::{app, ApiResource, PeerArea};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{EmptyState, ObsCard, SearchInput};
use af_web_core::{api::ApiClient, draft::FormDraft};
use af_web_ui::use_worker_rows;
use leptos::prelude::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use wasm_bindgen_futures::spawn_local;

const QUOTA_PAGE_SIZE: usize = 25;

fn quota_percentage(value: &Value) -> f64 {
    let quota = super::contracts::decode::<super::contracts::UserQuota>(value);
    let hard = quota.quota_bytes.unwrap_or_default();
    let used = quota.used_bytes.unwrap_or_default();
    if hard > 0 {
        (used as f64 / hard as f64 * 100.0).max(0.0)
    } else {
        0.0
    }
}

fn refresh_quota_draft(draft: &mut FormDraft<Value>, value: &Value) {
    let quota = super::contracts::decode::<super::contracts::UserQuota>(value);
    let amount = quota.quota_bytes.unwrap_or(0);
    draft.apply_server_refresh(json!({"quota": format!("{amount}B")}));
}

fn quota_snapshot(data: Signal<Value>) -> (Memo<Vec<Value>>, Memo<BTreeMap<i64, Value>>) {
    let rows = Memo::new(move |_| super::contracts::grid_rows::<UserQuota>(&data.get()));
    let indexed = Memo::new(move |_| {
        rows.with(|rows| {
            rows.iter()
                .filter_map(|row| Some((row["user_id"].as_i64()?, row.clone())))
                .collect()
        })
    });
    (rows, indexed)
}

#[derive(Clone, Copy)]
struct ReconciliationFence {
    context: crate::state::AppContext,
    busy: RwSignal<bool>,
    sync_ticket: RwSignal<u64>,
    ticket: u64,
    app_epoch: u64,
    server_epoch: u64,
    users_grant: u64,
    transport_epoch: u64,
}

impl ReconciliationFence {
    fn is_current(self, alive: bool) -> bool {
        alive
            && self.busy.try_get_untracked().is_some()
            && self.sync_ticket.try_get_untracked() == Some(self.ticket)
            && self.context.auth_loading.try_get_untracked() == Some(false)
            && self.context.session_epoch.try_get_untracked() == Some(self.app_epoch)
            && self.context.server_epoch.try_get_untracked() == Some(self.server_epoch)
            && self
                .context
                .area_revocation_epoch_untracked(PeerArea::Users)
                == self.users_grant
            && af_web_core::api::current_auth_epoch() == self.transport_epoch
            && !af_web_core::api::auth_revalidation_pending()
            && self.context.is_admin_untracked()
            && self.context.can_write_area_untracked(PeerArea::Users)
    }
}

#[component]
pub fn QuotasTab() -> impl IntoView {
    let context = app();
    view! {
        <Show
            when=move || context.is_admin()
            fallback=move || {
                view! {
                    <EmptyState title="Common.adminRequired" />
                }
            }
        >
            <QuotasAdminContent />
        </Show>
    }
}

#[component]
fn QuotasAdminContent() -> impl IntoView {
    let context = app();
    let can_read_users = Signal::derive(move || context.can_read_area(PeerArea::Users));
    let quotas = grid_resource(use_api_typed_when::<Records<UserQuota>>(
        can_read_users,
        Signal::derive(|| "/api/v1/admin/quotas".to_string()),
    ));
    poll_resource_when(quotas, 15_000, move || {
        context.can_read_area_untracked(PeerArea::Users)
    });
    let query = RwSignal::new(String::new());
    let page = RwSignal::new(0usize);
    let sync_busy = RwSignal::new(false);
    let sync_ticket = RwSignal::new(0u64);
    let alive = Arc::new(AtomicBool::new(true));
    let cleanup_alive = alive.clone();
    on_cleanup(move || cleanup_alive.store(false, Ordering::SeqCst));
    let alive = StoredValue::new(alive);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Users);
        if !context.can_write_area(PeerArea::Users) {
            sync_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            sync_busy.set(false);
        }
    });
    let (rows, indexed) = quota_snapshot(quotas.data.into());
    let filtered = use_worker_rows(
        rows.into(),
        query.into(),
        vec!["username".into(), "user_id".into(), "status".into()],
    );
    // Worker results may briefly refer to a previous snapshot. Keep only
    // tenants in the current authoritative data before paging or rendering.
    let matching = Memo::new(move |_| {
        filtered.with(|matches| {
            indexed.with(|current| {
                matches
                    .iter()
                    .filter_map(|row| row["user_id"].as_i64())
                    .filter(|id| current.contains_key(id))
                    .collect::<Vec<_>>()
            })
        })
    });
    let matching_ids =
        Memo::new(move |_| matching.with(|ids| ids.iter().copied().collect::<BTreeSet<_>>()));
    let page_count =
        Memo::new(move |_| matching.with(|ids| ids.len().div_ceil(QUOTA_PAGE_SIZE).max(1)));
    // Clamp synchronously for display, then persist the clamp so later growth
    // does not unexpectedly jump back to a page that had disappeared.
    let current_page = Memo::new(move |_| page.get().min(page_count.get() - 1));
    Effect::new(move |_| {
        let last_page = page_count.get() - 1;
        if page.get_untracked() > last_page {
            page.set(last_page);
        }
    });
    Effect::new(move |_| {
        query.track();
        page.set(0);
    });
    let visible_ids = Memo::new(move |_| {
        let start = current_page.get() * QUOTA_PAGE_SIZE;
        matching.with(|ids| {
            ids.iter()
                .skip(start)
                .take(QUOTA_PAGE_SIZE)
                .copied()
                .collect::<BTreeSet<_>>()
        })
    });
    let reconcile = move || {
        if sync_busy.get_untracked()
            || context.auth_loading.get_untracked()
            || af_web_core::api::auth_revalidation_pending()
            || !context.is_admin()
            || !context.can_write_area_untracked(crate::state::PeerArea::Users)
        {
            return;
        }
        let users = rows.get_untracked();
        let alive = alive.get_value();
        sync_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = sync_ticket.get_untracked();
        let fence = ReconciliationFence {
            context,
            busy: sync_busy,
            sync_ticket,
            ticket,
            app_epoch: context.session_epoch.get_untracked(),
            server_epoch: context.server_epoch.get_untracked(),
            users_grant: context.area_revocation_epoch_untracked(PeerArea::Users),
            transport_epoch: af_web_core::api::current_auth_epoch(),
        };
        sync_busy.set(true);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(sync_busy, sync_ticket, ticket);
        spawn_local(async move {
            let mut failures = Vec::new();
            for user in users {
                if !fence.is_current(alive.load(Ordering::SeqCst)) {
                    return;
                }
                let Some(id) = user["user_id"].as_i64() else {
                    continue;
                };
                let result = ApiClient
                    .post(&format!("/api/v1/admin/quotas/{id}/refresh"), None)
                    .await;
                if !fence.is_current(alive.load(Ordering::SeqCst))
                    || result.as_ref().is_err_and(|error| {
                        matches!(
                            error.code.as_deref(),
                            Some("SESSION_CHANGED" | "SERVER_CHANGED")
                        )
                    })
                {
                    return;
                }
                if let Err(error) = result {
                    failures.push(format!("{}: {}", text(&user, "username"), error.message));
                }
            }
            if !fence.is_current(alive.load(Ordering::SeqCst)) {
                return;
            }
            quotas.refresh();
            busy_guard.release();
            if failures.is_empty() {
                context.toast(tt(context, "Quota reconciliation completed"), false);
            } else {
                context.toast(
                    tt_with(
                        context,
                        "Quota reconciliation errors: {errors}",
                        &[("errors", &(failures.join("; ")).to_string())],
                    ),
                    true,
                );
            }
        });
    };
    view! {
        <section class="space-y-6 py-5 min-w-0 max-w-full">
            <Show
                when=move || context.is_admin()
                fallback=move || {
                    view! {
                        <EmptyState title="Common.adminRequired" />
                    }
                }
            >
                <ObsCard>
                    <h2 class="text-lg font-semibold mb-4">
                        {move || tt(context, "Tabs.quotasHeading")}
                    </h2>
                    <Show when=move || !can_read_users.get()>
                        <p role="status" class="text-xs text-amber-300 mb-4">
                            {move || {
                                context
                                    .area_block_reason(PeerArea::Users, false)
                                    .unwrap_or_default()
                            }}
                        </p>
                    </Show>
                    <p class="text-sm text-slate-400 mb-5">
                        {move || tt(
                            context,
                            "Linux setdisk limits and McBrowser storage accounting. Limits round up to the nearest KiB. Soft limits and grace periods appear when reported by the host.",
                        )}
                    </p>
                    <div class="grid sm:grid-cols-3 gap-5 mb-6">
                        <div>
                            <p class="text-xs text-slate-400">{move || tt(context, "Allocated")}</p>
                            <p class="text-xl font-semibold">
                                {move || bytes(
                                    rows
                                        .get()
                                        .iter()
                                        .filter_map(|v| super::contracts::decode::<super::contracts::UserQuota>(v).quota_bytes)
                                        .map(i128::from)
                                        .sum::<i128>() as f64,
                                )}
                            </p>
                        </div>
                        <div>
                            <p class="text-xs text-slate-400">{move || tt(context, "Used")}</p>
                            <p class="text-xl font-semibold text-cyan-300">
                                {move || bytes(
                                    rows.get().iter().filter_map(|v| super::contracts::decode::<super::contracts::UserQuota>(v).used_bytes).map(i128::from).sum::<i128>() as f64,
                                )}
                            </p>
                        </div>
                        <div>
                            <p class="text-xs text-slate-400">
                                {move || tt(context, "Configured tenants")}
                            </p>
                            <p class="text-xl font-semibold">
                                {move || {
                                    rows.get()
                                        .iter()
                                        .filter(|v| {
                                            v["configured"] == true
                                                || super::contracts::decode::<super::contracts::UserQuota>(v).quota_bytes.unwrap_or(0) > 0
                                        })
                                        .count()
                                }}
                            </p>
                        </div>
                    </div>
                    <div class="flex flex-wrap gap-3 mb-5">
                        <button
                            type="button"
                            class="af-btn px-4 py-2"
                            disabled=move || !can_read_users.get()
                            title=move || {
                                context
                                    .area_block_reason(PeerArea::Users, false)
                                    .unwrap_or_default()
                            }
                            on:click=move |_| {
                                if can_read_users.get_untracked() {
                                    quotas.refresh();
                                }
                            }
                            aria-label=move || tt(context, "Refresh quotas")
                        >
                            {move || tt(context, "Common.refresh")}
                        </button>
                        <button
                            type="button"
                            class="af-btn-primary px-4 py-2"
                            disabled=move || {
                                sync_busy.get()
                                    || quotas.loading.get()
                                    || !context.can_write_area(crate::state::PeerArea::Users)
                            }
                            title=move || {
                                context
                                    .area_block_reason(crate::state::PeerArea::Users, true)
                                    .unwrap_or_default()
                            }
                            on:click=move |_| reconcile()
                        >
                            {move || tt(context, if sync_busy.get() {
                                    "Reconciling…"
                                } else {
                                    "Sync / reconcile quotas"
                                })}
                        </button>
                    </div>
                    <SearchInput value=query placeholder="Search tenants, IDs or quota status" />
                    <ResourceFeedback resource=quotas />
                    <div class="divide-y divide-[var(--af-border-hairline)] mt-5">
                        <For
                            each=move || {
                                let mut ids = matching.get();
                                matching_ids.with(|matches| {
                                    rows.with(|rows| {
                                        ids.extend(rows.iter()
                                            .filter_map(|row| row["user_id"].as_i64())
                                            .filter(|id| !matches.contains(id)));
                                    });
                                });
                                ids
                            }
                            key=|id| *id
                            children=move |id| {
                                let row = Signal::derive(move || {
                                    indexed.with(|rows| rows.get(&id).cloned().unwrap_or(Value::Null))
                                });
                                let visible = Signal::derive(move || visible_ids.with(|ids| ids.contains(&id)));
                                view! { <QuotaRow row quotas sync_busy visible /> }
                            }
                        />
                    </div>
                    <Show when=move || !quotas.loading.get() && matching.with(Vec::is_empty)>
                        <EmptyState title="No quota records found" />
                    </Show>
                    <nav class="flex flex-wrap justify-between items-center gap-3 mt-5 text-sm" aria-label=move || tt(context, "Tabs.quotasHeading")>
                        <p role="status" class="text-slate-400">
                            {move || tt_with(context, "Page {page} of {pages}", &[("page", &(current_page.get() + 1).to_string()), ("pages", &page_count.get().to_string())])}
                            " · "
                            {move || tt_with(context, "{count} matching records", &[("count", &matching.with(Vec::len).to_string())])}
                        </p>
                        <div class="flex gap-3">
                            <button
                                type="button"
                                class="af-btn px-4 py-2"
                                disabled=move || current_page.get() == 0
                                on:click=move |_| page.set(current_page.get_untracked().saturating_sub(1))
                            >
                                {move || tt(context, "Previous")}
                            </button>
                            <button
                                type="button"
                                class="af-btn px-4 py-2"
                                disabled=move || { current_page.get() + 1 >= page_count.get() }
                                on:click=move |_| page.set((current_page.get_untracked() + 1).min(page_count.get_untracked() - 1))
                            >
                                {move || tt(context, "Next")}
                            </button>
                        </div>
                    </nav>
                </ObsCard>
            </Show>
        </section>
    }
}
#[component]
fn QuotaRow(
    row: Signal<Value>,
    quotas: ApiResource,
    sync_busy: RwSignal<bool>,
    visible: Signal<bool>,
) -> impl IntoView {
    let context = app();
    let draft = RwSignal::new(FormDraft::new(json!({"quota":""})));
    let busy = RwSignal::new(false);
    let row_ticket = RwSignal::new(0u64);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Users);
        if !context.can_write_area(PeerArea::Users) {
            row_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            busy.set(false);
        }
    });
    Effect::new(move |_| {
        let value = row.get();
        if !value.is_null() {
            draft.update(|d| refresh_quota_draft(d, &value));
        }
    });
    let save = Callback::new(move |()| {
        if busy.get_untracked()
            || sync_busy.get_untracked()
            || !context.is_admin()
            || !context.can_write_area_untracked(crate::state::PeerArea::Users)
        {
            return;
        }
        let Some(id) = row.get_untracked()["user_id"].as_i64() else {
            return;
        };
        let sent = draft_value(draft);
        if text(&sent, "quota").trim().is_empty() {
            context.toast(tt(context, "Enter a positive storage allocation"), true);
            return;
        }
        let session_epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let users_grant = context.area_revocation_epoch_untracked(PeerArea::Users);
        row_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = row_ticket.get_untracked();
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::for_generation(busy, row_ticket, ticket);
        spawn_local(async move {
            let payload = json!({"quota":text(&sent,"quota").trim(),"source":"manual"});
            let result = ApiClient
                .put(&format!("/api/v1/admin/quotas/{id}"), Some(&payload))
                .await;
            if busy.try_get_untracked().is_none()
                || row_ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Users) != users_grant
                || !context.can_write_area_untracked(PeerArea::Users)
            {
                return;
            }
            match result {
                Ok(_) => {
                    draft.update(|d| {
                        let _ = d.acknowledge_saved(&sent, sent.clone());
                    });
                    quotas.refresh();
                    context.toast(
                        tt(context, "Quota saved and filesystem enforcement updated"),
                        false,
                    );
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            busy_guard.release();
        });
    });
    let refresh = move || {
        if busy.get_untracked()
            || sync_busy.get_untracked()
            || !context.can_write_area_untracked(crate::state::PeerArea::Users)
        {
            return;
        }
        let Some(id) = row.get_untracked()["user_id"].as_i64() else {
            return;
        };
        let session_epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let users_grant = context.area_revocation_epoch_untracked(PeerArea::Users);
        row_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = row_ticket.get_untracked();
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::for_generation(busy, row_ticket, ticket);
        spawn_local(async move {
            let result = ApiClient
                .post(&format!("/api/v1/admin/quotas/{id}/refresh"), None)
                .await;
            if busy.try_get_untracked().is_none()
                || row_ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Users) != users_grant
                || !context.can_write_area_untracked(PeerArea::Users)
            {
                return;
            }
            match result {
                Ok(_) => {
                    quotas.refresh();
                    context.toast(tt(context, "Disk usage reconciled"), false);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            busy_guard.release();
        });
    };
    let percentage = Signal::derive(move || row.with(quota_percentage));
    view! {
        // Filtering and paging hide controls, while this keyed row retains its
        // draft and pending save until the tenant disappears or the view ends.
        <Show when=move || visible.get()>
        <div class="grid lg:grid-cols-2 gap-5 py-5 min-w-0" data-quota-row="true">
            <div class="space-y-3 min-w-0">
                <h3 class="font-semibold break-all">
                    {move || {
                        row.with(|v| format!("{} · #{}", text(v, "username"), text(v, "user_id")))
                    }}
                </h3>
                <p class="text-sm text-slate-300">
                    {move || {
                        row.with(|v| {
                            tt_with(context, "{used} used · {limit} hard limit", &[("used", &(bytes(v["used_bytes"].as_f64().unwrap_or(0.0))).to_string()), ("limit", &(if v["quota_bytes"].as_f64().unwrap_or(0.0) > 0.0 {
                                    bytes(v["quota_bytes"].as_f64().unwrap_or(0.0))
                                } else {
                                    tt(context, "Not configured")
                                }).to_string())])
                        })
                    }}
                </p>
                <div
                    role="progressbar"
                    aria-label=move || {
                        row.with(|v| tt_with(context, "{user} storage utilization", &[("user", &(text(v, "username")).to_string())]))
                    }
                    aria-valuemin="0"
                    aria-valuemax="100"
                    aria-valuenow=move || percentage.get().min(100.0)
                    aria-valuetext=move || tt_with(context, "{pct}% used", &[("pct", &format!("{:.1}", percentage.get()))])
                    class="h-2 rounded-full bg-white/5 overflow-hidden"
                >
                    <svg
                        viewBox="0 0 100 8"
                        preserveAspectRatio="none"
                        class="w-full h-full block"
                        aria-hidden="true"
                    >
                        <rect
                            x="0"
                            y="0"
                            height="8"
                            rx="4"
                            width=move || format!("{:.1}", percentage.get().clamp(0.0, 100.0))
                            class=move || {
                                if percentage.get() >= 95.0 {
                                    "fill-rose-400"
                                } else {
                                    "fill-cyan-400"
                                }
                            }
                        />
                    </svg>
                </div>
                <p class="text-xs text-slate-400">
                    {move || {
                        row.with(|v| {
                            tt_with(
                                context,
                                "Quotas.rowMetaSummary",
                                &[
                                    ("soft", &v["soft_limit_bytes"]
                                        .as_f64()
                                        .map(bytes)
                                        .unwrap_or_else(|| tt(context, "Not reported"))),
                                    ("grace", &tt(context, v["grace_status"].as_str().unwrap_or("Not reported"))),
                                    ("status", &tt(context, &text(v, "status"))),
                                    ("source", &tt(context, &text(v, "source"))),
                                ],
                            )
                        })
                    }}
                </p>
                <p class="text-xs text-slate-500">
                    {move || row.with(|v| {
                        let time = text(v, "updated_at");
                        let time = if time.trim().is_empty() { tt(context, "Not reported") } else { time };
                        tt_with(context, "Last scan: {time}", &[("time", &time)])
                    })}
                </p>
                <button
                    type="button"
                    class="af-btn px-4 py-2"
                    disabled=move || {
                        busy.get()
                            || sync_busy.get()
                            || !context.can_write_area(crate::state::PeerArea::Users)
                    }
                    title=move || {
                        context
                            .area_block_reason(crate::state::PeerArea::Users, true)
                            .unwrap_or_default()
                    }
                    on:click=move |_| refresh()
                >
                    {move || tt(context, "Scan Disk")}
                </button>
            </div>
            <div>
                <DraftInput
                    draft
                    field="quota"
                    label="Allocated disk space"
                    placeholder="100GB, 2TB or exact bytes"
                    disabled=Signal::derive(move || {
                        sync_busy.get() || !context.can_write_area(crate::state::PeerArea::Users)
                    })
                />
                <DraftButtons
                    draft
                    busy
                    on_save=save
                    label="Apply Quota"
                    disabled=Signal::derive(move || {
                        !context.can_write_area(crate::state::PeerArea::Users)
                    })
                    title=Signal::derive(move || {
                        context
                            .area_block_reason(crate::state::PeerArea::Users, true)
                            .unwrap_or_default()
                    })
                />
            </div>
        </div>
        </Show>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousand_tenant_snapshot_is_read_once_per_refresh_not_per_row() {
        use std::sync::atomic::AtomicUsize;
        let owner = Owner::new();
        owner.with(|| {
            let source = RwSignal::new(json!({"quotas": (1..=1000).map(|id| {
                json!({"user_id":id,"username":format!("tenant-{id}"),"quota_bytes":1000,"used_bytes":id})
            }).collect::<Vec<_>>()}));
            let reads = Arc::new(AtomicUsize::new(0));
            let tracked_reads = reads.clone();
            let (rows, indexed) = quota_snapshot(Signal::derive(move || {
                tracked_reads.fetch_add(1, Ordering::SeqCst);
                source.get()
            }));
            for id in 1..=1000 {
                indexed.with_untracked(|rows| assert_eq!(rows[&id]["used_bytes"], id));
            }
            assert_eq!(rows.with_untracked(Vec::len), 1000);
            assert_eq!(reads.load(Ordering::SeqCst), 1);
            let mut draft = FormDraft::new(json!({"quota":"1000B"}));
            draft.edit("quota", json!("2GB")).unwrap();
            source.update(|value| value["quotas"][0]["quota_bytes"] = json!(4000));
            for id in 1..=1000 {
                indexed.with_untracked(|rows| assert_eq!(rows[&id]["user_id"], id));
            }
            indexed.with_untracked(|rows| {
                assert_eq!(rows[&1]["quota_bytes"], 4000);
                refresh_quota_draft(&mut draft, &rows[&1]);
            });
            assert_eq!(draft.value().unwrap()["quota"], "2GB");
            assert_eq!(reads.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn hundred_gib_quota_initializes_exact_bytes_after_grid_round_trip() {
        let amount = 107_374_182_400_i64;
        let rows = super::super::contracts::grid_rows::<super::super::contracts::UserQuota>(
            &json!([{"user_id": 9, "quota_bytes": amount, "used_bytes": amount / 4}]),
        );
        let mut draft = FormDraft::new(json!({"quota": ""}));
        refresh_quota_draft(&mut draft, &rows[0]);
        assert_eq!(draft.value().unwrap()["quota"], "107374182400B");
        assert_eq!(quota_percentage(&rows[0]), 25.0);
        draft.edit("quota", json!("200GB")).unwrap();
        refresh_quota_draft(&mut draft, &rows[0]);
        assert_eq!(draft.value().unwrap()["quota"], "200GB");
    }

    #[test]
    fn storage_percentage_preserves_overage_for_the_accessible_description() {
        assert_eq!(
            quota_percentage(&json!({"quota_bytes":100,"used_bytes":25})),
            25.0
        );
        assert_eq!(
            quota_percentage(&json!({"quota_bytes":100,"used_bytes":150})),
            150.0
        );
        assert_eq!(
            quota_percentage(&json!({"quota_bytes":100,"used_bytes":-1})),
            0.0
        );
    }

    #[test]
    fn unconfigured_or_legacy_quotas_do_not_divide_by_zero() {
        for value in [
            Value::Null,
            json!({"quota_bytes":0,"used_bytes":10}),
            json!({"quota_bytes":-1,"used_bytes":10}),
            json!({"quota_bytes":"unknown","used_bytes":10}),
        ] {
            assert_eq!(quota_percentage(&value), 0.0);
        }
        assert_eq!(quota_percentage(&json!({"quota_bytes":100})), 0.0);
    }
}
