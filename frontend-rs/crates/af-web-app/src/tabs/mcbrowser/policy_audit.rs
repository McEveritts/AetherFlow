use super::*;
use crate::state::PeerArea;

const POLICY_READ_REQS: [(PeerArea, bool); 2] =
    [(PeerArea::Files, false), (PeerArea::Users, false)];
const POLICY_WRITE_REQS: [(PeerArea, bool); 2] = [(PeerArea::Files, true), (PeerArea::Users, true)];
const POLICY_AREAS: [PeerArea; 2] = [PeerArea::Files, PeerArea::Users];

pub(super) fn initial_policy_target(is_remote: bool, user: Option<&Value>) -> String {
    if is_remote {
        return String::new();
    }
    user.and_then(|user| user["id"].as_u64())
        .map(|id| id.to_string())
        .unwrap_or_default()
}

pub(super) fn should_auto_load_policy(
    is_remote: bool,
    is_admin: bool,
    can_read_policy: bool,
    target: &str,
) -> bool {
    !is_remote
        && is_admin
        && can_read_policy
        && target.parse::<u64>().ok().filter(|id| *id > 0).is_some()
}

pub(super) fn draft_value(draft: RwSignal<Option<FormDraft<Value>>>) -> Value {
    draft.with(|draft| {
        draft
            .as_ref()
            .and_then(|draft| draft.value().ok())
            .unwrap_or(Value::Null)
    })
}
pub(super) fn draft_edit(draft: RwSignal<Option<FormDraft<Value>>>, key: &str, value: Value) {
    draft.update(|draft| {
        if let Some(draft) = draft {
            let _ = draft.edit(key, value);
        }
    });
}
pub(super) fn rule_edit(
    draft: RwSignal<Option<FormDraft<Value>>>,
    index: usize,
    key: &str,
    value: Value,
) {
    let mut rules = draft_value(draft)["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if let Some(rule) = rules.get_mut(index) {
        rule[key] = value;
        if key == "regex" && rule["regex"] == true && rule["regexp"].is_null() {
            rule["regexp"] = json!({"raw":".*"});
        }
        if key == "regex" && rule["regex"] == false {
            if let Some(rule) = rule.as_object_mut() {
                rule.remove("regexp");
            }
        }
        draft_edit(draft, "rules", json!(rules));
    }
}
#[derive(Clone, Copy)]
pub(super) struct PolicyForm {
    pub(super) target: RwSignal<String>,
    pub(super) loaded: RwSignal<String>,
    pub(super) draft: RwSignal<Option<FormDraft<Value>>>,
    pub(super) busy: RwSignal<bool>,
    pub(super) saving: RwSignal<bool>,
    pub(super) failure: RwSignal<String>,
    pub(super) ticket: RwSignal<u64>,
}
impl PolicyForm {
    pub(super) fn dirty(self) -> bool {
        self.draft
            .with(|draft| draft.as_ref().is_some_and(FormDraft::is_dirty))
    }
    pub(super) fn clear_state(self) {
        self.ticket
            .update(|ticket| *ticket = ticket.wrapping_add(1));
        self.busy.set(false);
        self.saving.set(false);
        self.draft.set(None);
        self.loaded.set(String::new());
        self.failure.set(String::new());
    }
    pub(super) fn cancel_save(self) {
        if self.saving.get_untracked() {
            self.ticket
                .update(|ticket| *ticket = ticket.wrapping_add(1));
            self.busy.set(false);
            self.saving.set(false);
        }
    }
    pub(super) fn load(self) {
        let context = app();
        if self.busy.get_untracked()
            || !context.is_admin_untracked()
            || !context.can_all_areas_untracked(&POLICY_READ_REQS)
        {
            return;
        }
        let target = self.target.get_untracked().trim().to_string();
        if target.parse::<u64>().ok().filter(|id| *id > 0).is_none() {
            self.failure.set("Enter a positive user ID.".into());
            return;
        }
        self.saving.set(false);
        self.busy.set(true);
        self.failure.set(String::new());
        self.ticket
            .update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = self.ticket.get_untracked();
        let auth = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let grant_epoch = context.areas_revocation_epoch_untracked(&POLICY_AREAS);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(self.busy, self.ticket, ticket);
        spawn_local(async move {
            let result = ApiClient
                .get(&format!("{BASE}/policy/{}", encode(&target)))
                .await;
            if self.ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.areas_revocation_epoch_untracked(&POLICY_AREAS) != grant_epoch
                || !context.is_admin_untracked()
                || !context.can_all_areas_untracked(&POLICY_READ_REQS)
            {
                return;
            }
            busy_guard.release();
            match result {
                Ok(server) => {
                    if self.loaded.get_untracked() == target {
                        self.draft.update(|draft| {
                            if let Some(draft) = draft {
                                draft.apply_server_refresh(server);
                            } else {
                                *draft = Some(FormDraft::new(server));
                            }
                        });
                    } else {
                        self.draft.set(Some(FormDraft::new(server)));
                    }
                    self.loaded.set(target);
                }
                Err(failure) => {
                    if !matches!(
                        failure.code.as_deref(),
                        Some("SERVER_CHANGED" | "SESSION_CHANGED" | "ABORTED")
                    ) {
                        self.failure.set(failure.to_string());
                    }
                }
            }
        });
    }
    pub(super) fn save(self) {
        let context = app();
        if self.busy.get_untracked()
            || !self.dirty()
            || !context.is_admin_untracked()
            || !context.can_all_areas_untracked(&POLICY_WRITE_REQS)
        {
            return;
        }
        let target = self.loaded.get_untracked().trim().to_string();
        if target.parse::<u64>().ok().filter(|id| *id > 0).is_none() {
            self.failure.set("Enter a positive user ID.".into());
            return;
        }
        let payload = draft_value(self.draft);
        let policy =
            crate::tabs::contracts::decode::<crate::tabs::contracts::McBrowserPolicy>(&payload);
        if let Err(message) = relative_path(&policy.scope, true) {
            self.failure.set(message);
            return;
        }
        if policy.rules.len() > 256 || !payload["rules"].is_array() {
            self.failure
                .set("A policy may contain at most 256 rules.".into());
            return;
        }
        let auth = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let grant_epoch = context.areas_revocation_epoch_untracked(&POLICY_AREAS);
        self.ticket
            .update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = self.ticket.get_untracked();
        self.saving.set(true);
        self.busy.set(true);
        self.failure.set(String::new());
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(self.busy, self.ticket, ticket);
        let mut saving_guard =
            crate::tabs::busy::BusyGuard::for_generation(self.saving, self.ticket, ticket);
        spawn_local(async move {
            let result = ApiClient
                .put(
                    &format!("{BASE}/policy/{}", encode(&target)),
                    Some(&payload),
                )
                .await;
            if self.ticket.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.areas_revocation_epoch_untracked(&POLICY_AREAS) != grant_epoch
                || !context.is_admin_untracked()
                || !context.can_all_areas_untracked(&POLICY_WRITE_REQS)
            {
                return;
            }
            saving_guard.release();
            busy_guard.release();
            match result {
                Ok(server) => {
                    self.draft.update(|draft| {
                        if let Some(draft) = draft {
                            let _ = draft.acknowledge_saved(&payload, server);
                        }
                    });
                    context.toast(tt(context, "Storage policy saved"), false);
                }
                Err(failure) => {
                    if !matches!(
                        failure.code.as_deref(),
                        Some("SERVER_CHANGED" | "SESSION_CHANGED" | "ABORTED")
                    ) {
                        self.failure.set(failure.to_string());
                    }
                }
            }
        });
    }
}
#[component]
pub(super) fn PolicyAdmin() -> impl IntoView {
    let context = app();
    let initial = context
        .user
        .with_untracked(|user| initial_policy_target(context.is_remote_untracked(), user.as_ref()));
    let form = PolicyForm {
        target: RwSignal::new(initial),
        loaded: RwSignal::new(String::new()),
        draft: RwSignal::new(None),
        busy: RwSignal::new(false),
        saving: RwSignal::new(false),
        failure: RwSignal::new(String::new()),
        ticket: RwSignal::new(0),
    };
    let switch = RwSignal::new(false);
    let reset = RwSignal::new(false);
    let unload = StoredValue::new_local(web_sys::window().map(|window| {
        EventListener::new(&window, "beforeunload", move |event| {
            if form
                .draft
                .with_untracked(|draft| draft.as_ref().is_some_and(FormDraft::is_dirty))
            {
                event.prevent_default();
                let _ = js_sys::Reflect::set(
                    event.as_ref(),
                    &JsValue::from_str("returnValue"),
                    &JsValue::from_str(""),
                );
            }
        })
    }));
    on_cleanup(move || unload.set_value(None));
    let can_read_policy =
        Signal::derive(move || context.is_admin() && context.can_all_areas(&POLICY_READ_REQS));
    let can_write_policy =
        Signal::derive(move || context.is_admin() && context.can_all_areas(&POLICY_WRITE_REQS));
    let can_edit_now = move || {
        !form.busy.get_untracked()
            && context.is_admin_untracked()
            && context.can_all_areas_untracked(&POLICY_WRITE_REQS)
    };
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        form.clear_state();
        switch.set(false);
        reset.set(false);
        let is_remote = context.is_remote_untracked();
        let next_target = context
            .user
            .with_untracked(|user| initial_policy_target(is_remote, user.as_ref()));
        form.target.set(next_target.clone());
        if should_auto_load_policy(
            is_remote,
            context.is_admin_untracked(),
            can_read_policy.get_untracked(),
            &next_target,
        ) {
            form.load();
        }
    });
    Effect::new(move |_| {
        let readable = can_read_policy.get();
        let _ = context.areas_revocation_epoch(&POLICY_AREAS);
        if !readable {
            form.clear_state();
            switch.set(false);
            reset.set(false);
        }
    });
    Effect::new(move |_| {
        if !can_write_policy.get() {
            form.cancel_save();
            reset.set(false);
        }
    });
    view! {
        <ObsCard title=Signal::derive(move || tt(context, "McBrowser.storagePolicyTitle"))>
            <p class="text-sm text-slate-400 mb-4">
                {move || tt(
                    context,
                    "Manage per-user storage scope, permissions and ordered path rules. Extension restrictions can be expressed with regular expressions.",
                )}
            </p>
            {move || {
                context
                    .areas_block_reason(&[
                        (crate::state::PeerArea::Files, false),
                        (crate::state::PeerArea::Users, false),
                    ])
                    .or_else(|| {
                        context.areas_block_reason(&[
                            (crate::state::PeerArea::Files, true),
                            (crate::state::PeerArea::Users, true),
                        ])
                    })
                    .map(|reason| {
                        view! {
                            <p
                                role="status"
                                data-testid="mcbrowser-policy-access-note"
                                class="text-xs text-amber-300 mb-3"
                            >
                                {reason}
                            </p>
                        }
                    })
            }}
            <div class="flex flex-wrap gap-2 mb-4">
                <label class="flex-1 min-w-32">
                    <span class="text-sm">{move || tt(context, "Target user ID")}</span>
                    <input
                        type="number"
                        min="1"
                        class=FORM
                        prop:value=move || form.target.get()
                        disabled=move || form.busy.get() || !can_read_policy.get()
                        on:input=move |event| form.target.set(event_target_value(&event))
                    />
                </label>
                <button
                    type="button"
                    class="glass-button px-4 py-2 self-end"
                    disabled=move || form.busy.get() || !can_read_policy.get()
                    title=move || {
                        context
                            .areas_block_reason(&[
                                (crate::state::PeerArea::Files, false),
                                (crate::state::PeerArea::Users, false),
                            ])
                            .unwrap_or_default()
                    }
                    on:click=move |_| {
                        if form.dirty()
                            && form.target.get_untracked() != form.loaded.get_untracked()
                        {
                            switch.set(true);
                        } else {
                            form.load();
                        }
                    }
                >
                    {move || tt(context, "Load / refresh policy")}
                </button>
            </div>
            <p role="alert" class="text-sm text-rose-300 mb-3">
                {move || tt(context, &form.failure.get())}
            </p>
            <Show when=move || form.draft.with(Option::is_some)>
                <div class="space-y-4">
                    <p class="text-xs text-slate-400">
                        {move || tt_with(
                            context,
                            "Editing user {id}{dirty}",
                            &[
                                ("id", &form.loaded.get()),
                                (
                                    "dirty",
                                    &if form.dirty() {
                                        tt(context, " · unsaved changes")
                                    } else {
                                        String::new()
                                    },
                                ),
                            ],
                        )}
                    </p>
                    <label class="block text-sm space-y-1">
                        <span>{move || tt(context, "Storage scope (relative path)")}</span>
                        <input
                            class=FORM
                            disabled=move || form.busy.get() || !can_write_policy.get()
                            prop:value=move || text(&draft_value(form.draft), "scope")
                            on:input=move |event| {
                                if can_edit_now() {
                                    draft_edit(
                                        form.draft,
                                        "scope",
                                        json!(event_target_value(&event)),
                                    );
                                }
                            }
                        />
                    </label>
                    <div class="flex flex-wrap gap-4">
                        {[
                            "read",
                            "create",
                            "rename",
                            "modify",
                            "delete",
                            "share",
                            "download",
                            "execute",
                        ]
                            .into_iter()
                            .map(|key| {
                                view! {
                                    <label class="flex gap-2 text-sm capitalize">
                                        <input
                                            type="checkbox"
                                            disabled=move || form.busy.get() || !can_write_policy.get()
                                            prop:checked=move || {
                                                draft_value(form.draft)["permissions"][key] == true
                                            }
                                            on:change=move |event| {
                                                if can_edit_now() {
                                                    draft_edit(
                                                        form.draft,
                                                        &format!("/permissions/{key}"),
                                                        json!(event_target_checked(&event)),
                                                    );
                                                }
                                            }
                                        />
                                        <span>{move || tt(context, key)}</span>
                                    </label>
                                }
                            })
                            .collect_view()}
                    </div>
                    <div class="space-y-3">
                        <For
                            each=move || {
                                (0..draft_value(form.draft)["rules"].as_array().map_or(0, Vec::len))
                                    .collect::<Vec<_>>()
                            }
                            key=|index| *index
                            children=move |index| {
                                view! {
                                    <div class="rounded-xl border border-white/10 p-3 space-y-2">
                                        <label class="block text-xs space-y-1">
                                            <span>
                                                {move || tt_with(
                                                    context,
                                                    "Rule {count}: path prefix",
                                                    &[("count", &(index + 1).to_string())],
                                                )}
                                            </span>
                                            <input
                                                class=FORM
                                                disabled=move || form.busy.get() || !can_write_policy.get()
                                                prop:value=move || text(
                                                    &draft_value(form.draft)["rules"][index],
                                                    "path",
                                                )
                                                on:input=move |event| {
                                                    if can_edit_now() {
                                                        rule_edit(
                                                            form.draft,
                                                            index,
                                                            "path",
                                                            json!(event_target_value(&event)),
                                                        );
                                                    }
                                                }
                                            />
                                        </label>
                                        <div class="flex flex-wrap gap-3">
                                            <label class="flex gap-2 text-xs">
                                                <input
                                                    type="checkbox"
                                                    disabled=move || form.busy.get() || !can_write_policy.get()
                                                    prop:checked=move || {
                                                        draft_value(form.draft)["rules"][index]["allow"] == true
                                                    }
                                                    on:change=move |event| {
                                                        if can_edit_now() {
                                                            rule_edit(
                                                                form.draft,
                                                                index,
                                                                "allow",
                                                                json!(event_target_checked(&event)),
                                                            );
                                                        }
                                                    }
                                                />
                                                {move || tt(context, "Allow")}
                                            </label>
                                            <label class="flex gap-2 text-xs">
                                                <input
                                                    type="checkbox"
                                                    disabled=move || form.busy.get() || !can_write_policy.get()
                                                    prop:checked=move || {
                                                        draft_value(form.draft)["rules"][index]["regex"] == true
                                                    }
                                                    on:change=move |event| {
                                                        if can_edit_now() {
                                                            rule_edit(
                                                                form.draft,
                                                                index,
                                                                "regex",
                                                                json!(event_target_checked(&event)),
                                                            );
                                                        }
                                                    }
                                                />
                                                {move || tt(context, "Regular expression")}
                                            </label>
                                            <button
                                                type="button"
                                                class="glass-button px-2"
                                                disabled=move || {
                                                    index == 0 || form.busy.get() || !can_write_policy.get()
                                                }
                                                on:click=move |_| {
                                                    if !can_edit_now() {
                                                        return;
                                                    }
                                                    let mut rules = draft_value(form.draft)["rules"]
                                                        .as_array()
                                                        .cloned()
                                                        .unwrap_or_default();
                                                    if index > 0 && index < rules.len() {
                                                        rules.swap(index, index - 1);
                                                        draft_edit(form.draft, "rules", json!(rules));
                                                    }
                                                }
                                            >
                                                {move || tt(context, "Move up")}
                                            </button>
                                            <button
                                                type="button"
                                                class="glass-button px-2"
                                                disabled=move || {
                                                    form.busy.get()
                                                        || !can_write_policy.get()
                                                        || index + 1
                                                            >= draft_value(form.draft)["rules"]
                                                                .as_array()
                                                                .map_or(0, Vec::len)
                                                }
                                                on:click=move |_| {
                                                    if !can_edit_now() {
                                                        return;
                                                    }
                                                    let mut rules = draft_value(form.draft)["rules"]
                                                        .as_array()
                                                        .cloned()
                                                        .unwrap_or_default();
                                                    if index + 1 < rules.len() {
                                                        rules.swap(index, index + 1);
                                                        draft_edit(form.draft, "rules", json!(rules));
                                                    }
                                                }
                                            >
                                                {move || tt(context, "Move down")}
                                            </button>
                                            <button
                                                type="button"
                                                class="glass-button px-2 text-rose-300"
                                                disabled=move || form.busy.get() || !can_write_policy.get()
                                                on:click=move |_| {
                                                    if !can_edit_now() {
                                                        return;
                                                    }
                                                    let mut rules = draft_value(form.draft)["rules"]
                                                        .as_array()
                                                        .cloned()
                                                        .unwrap_or_default();
                                                    if index < rules.len() {
                                                        rules.remove(index);
                                                        draft_edit(form.draft, "rules", json!(rules));
                                                    }
                                                }
                                            >
                                                {move || tt(context, "Remove")}
                                            </button>
                                        </div>
                                        <Show when=move || {
                                            draft_value(form.draft)["rules"][index]["regex"] == true
                                        }>
                                            <label class="block text-xs space-y-1">
                                                <span>{move || tt(context, "Regex expression")}</span>
                                                <input
                                                    class=FORM
                                                    disabled=move || form.busy.get() || !can_write_policy.get()
                                                    prop:value=move || text(
                                                        &draft_value(form.draft)["rules"][index]["regexp"],
                                                        "raw",
                                                    )
                                                    on:input=move |event| {
                                                        if can_edit_now() {
                                                            rule_edit(
                                                                form.draft,
                                                                index,
                                                                "regexp",
                                                                json!({"raw":event_target_value(&event)}),
                                                            );
                                                        }
                                                    }
                                                />
                                            </label>
                                        </Show>
                                    </div>
                                }
                            }
                        />
                    </div>
                    <div class="flex flex-wrap gap-2">
                        <button
                            type="button"
                            class="glass-button px-3 py-2"
                            disabled=move || {
                                form.busy.get()
                                    || !can_write_policy.get()
                                    || draft_value(form.draft)["rules"]
                                        .as_array()
                                        .map_or(0, Vec::len)
                                        >= 256
                            }
                            title=move || {
                                context
                                    .areas_block_reason(&POLICY_WRITE_REQS)
                                    .unwrap_or_default()
                            }
                            on:click=move |_| {
                                if !can_edit_now() {
                                    return;
                                }
                                let mut rules = draft_value(form.draft)["rules"]
                                    .as_array()
                                    .cloned()
                                    .unwrap_or_default();
                                rules.push(json!({"path":"","allow":true,"regex":false}));
                                draft_edit(form.draft, "rules", json!(rules));
                            }
                        >
                            {move || tt(context, "Add rule")}
                        </button>
                        <button
                            type="button"
                            class="glass-button-primary px-4 py-2"
                            disabled=move || {
                                form.busy.get() || !form.dirty() || !can_write_policy.get()
                            }
                            title=move || {
                                context
                                    .areas_block_reason(&POLICY_WRITE_REQS)
                                    .unwrap_or_default()
                            }
                            on:click=move |_| form.save()
                        >
                            {move || tt(context, "Save policy")}
                        </button>
                        <button
                            type="button"
                            class="glass-button px-4 py-2"
                            disabled=move || form.busy.get() || !form.dirty() || !can_write_policy.get()
                            on:click=move |_| reset.set(true)
                        >
                            {move || tt(context, "Discard edits…")}
                        </button>
                    </div>
                </div>
            </Show>
            <ConfirmDialog
                open=switch
                title="Switch target user?"
                message="Unsaved policy changes for the current user will be discarded."
                on_confirm=Callback::new(move |()| {
                    switch.set(false);
                    form.load();
                })
            />
            <ConfirmDialog
                open=reset
                title="Discard policy edits?"
                message="Restore the last loaded policy."
                on_confirm=Callback::new(move |()| {
                    form.draft
                        .update(|draft| {
                            if let Some(draft) = draft {
                                draft.reset();
                            }
                        });
                    reset.set(false);
                })
            />
        </ObsCard>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_admin_starts_empty_and_never_auto_loads_remotely_while_preserving_local_self_default()
    {
        let admin = json!({"id": 7, "username": "alice", "role": "admin"});
        assert_eq!(initial_policy_target(false, Some(&admin)), "7");
        assert!(should_auto_load_policy(false, true, true, "7"));
        assert!(!should_auto_load_policy(false, false, true, "7"));
        assert!(!should_auto_load_policy(false, true, false, "7"));

        // Remote mode must start empty and never auto-load local admin's user ID.
        assert_eq!(initial_policy_target(true, Some(&admin)), "");
        assert!(!should_auto_load_policy(true, true, true, ""));
        assert!(!should_auto_load_policy(true, true, true, "7"));
    }
}
