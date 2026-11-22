use super::contracts::{grid_resource, use_api_typed, Records, UserRecord};
use super::settings::{
    draft_value, poll_resource, text, DraftButtons, DraftSelect, ResourceFeedback,
};
use crate::state::{app, json_rows};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{Badge, ConfirmDialog, DataGrid, Drawer, EmptyState, ObsCard};
use af_web_core::{api::ApiClient, draft::FormDraft, models::User};
use af_web_ui::GridColumn;
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

fn user_row(value: Value) -> Value {
    let record = super::contracts::decode::<super::contracts::UserRecord>(&value);
    let user: User = record.user();
    let mut row = serde_json::to_value(&record).unwrap_or_default();
    row["two_factor"] = json!(if user.totp_enabled { "Enabled" } else { "Off" });
    row["oauth"] = json!(if user.is_oauth || !record.google_id.is_empty() {
        "OAuth"
    } else {
        "Local"
    });
    row["created"] = json!(if record.created_at.is_empty() {
        "Not reported"
    } else {
        &record.created_at
    });
    row
}
fn last_administrator(selected: &Value, users: &[Value]) -> bool {
    let selected = super::contracts::decode::<super::contracts::UserRecord>(selected);
    selected.role == "admin"
        && users
            .iter()
            .map(super::contracts::decode::<super::contracts::UserRecord>)
            .filter(|user| user.role == "admin")
            .count()
            <= 1
}

#[component]
pub fn UsersTab() -> impl IntoView {
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
            <UsersAdminContent />
        </Show>
    }
}

#[component]
fn UsersAdminContent() -> impl IntoView {
    let context = app();
    let user_records =
        use_api_typed::<Records<UserRecord>>(Signal::derive(|| "/api/v1/admin/users".to_string()));
    let users = grid_resource(user_records);
    poll_resource(users, 30_000);
    let selected = RwSignal::new(Value::Null);
    let inspector = RwSignal::new(false);
    let remove = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let draft = RwSignal::new(FormDraft::new(json!({"role":"user"})));
    let rows = Signal::derive(move || {
        json_rows(&users.data.get())
            .into_iter()
            .map(user_row)
            .map(|mut row| {
                for field in ["two_factor", "oauth", "created"] {
                    row[format!("{field}_label")] =
                        json!(tt(context, row[field].as_str().unwrap_or_default()));
                }
                row["role_label"] = json!(tt(context, row["role"].as_str().unwrap_or_default()));
                row
            })
            .collect::<Vec<_>>()
    });
    let self_selected = Signal::derive(move || {
        context.user.with(|user| {
            user.as_ref().is_some_and(|user| {
                user["id"] == selected.get()["id"] || user["username"] == selected.get()["username"]
            })
        })
    });
    let last_admin = Signal::derive(move || {
        selected.with(|user| last_administrator(user, &json_rows(&users.data.get())))
    });
    Effect::new(move |_| {
        let id = selected.with(|value| value["id"].clone());
        if !id.is_null() {
            if let Some(user) = json_rows(&users.data.get())
                .into_iter()
                .find(|user| user["id"] == id)
            {
                draft.update(|d| d.apply_server_refresh(json!({"role":user["role"]})));
            }
        }
    });
    let save_role = Callback::new(move |()| {
        if busy.get_untracked() || self_selected.get_untracked() || !context.is_admin() {
            return;
        }
        let id = selected.with_untracked(|row| row["id"].as_i64());
        let Some(id) = id else {
            return;
        };
        let mut saved_user = selected.with_untracked(super::contracts::decode::<UserRecord>);
        let sent = draft_value(draft);
        if !matches!(sent["role"].as_str(), Some("admin" | "user")) {
            return;
        }
        if last_admin.get_untracked() && sent["role"] != "admin" {
            context.toast(tt(context, "Keep at least one administrator"), true);
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match ApiClient
                .put(&format!("/api/v1/admin/users/{id}/role"), Some(&sent))
                .await
            {
                Ok(_) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    draft.update(|d| {
                        let _ = d.acknowledge_saved(&sent, sent.clone());
                    });
                    saved_user.role = text(&sent, "role");
                    let mut cached = user_records.data.get_untracked();
                    let rows = match &mut cached {
                        Records::List(rows) => rows,
                        Records::Envelope(envelope) => &mut envelope.items,
                    };
                    if let Some(user) = rows.iter_mut().find(|user| user.id == id) {
                        user.role = saved_user.role.clone();
                    } else {
                        rows.push(saved_user);
                    }
                    // The grid is a separate JSON mirror of the typed resource.
                    // Publish both before selected can re-enter the draft effect.
                    let grid_data = serde_json::to_value(&cached).unwrap_or_default();
                    user_records.commit(cached);
                    users.data.set(grid_data);
                    selected.update(|value| value["role"] = sent["role"].clone());
                    context.toast(tt(context, "User role updated"), false);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy.set(false);
            }
        });
    });
    let delete = Callback::new(move |()| {
        if busy.get_untracked()
            || self_selected.get_untracked()
            || last_admin.get_untracked()
            || !context.is_admin()
        {
            return;
        }
        let Some(id) = selected.with_untracked(|row| row["id"].as_i64()) else {
            return;
        };
        busy.set(true);
        spawn_local(async move {
            match ApiClient
                .delete(&format!("/api/v1/admin/users/{id}"), None)
                .await
            {
                Ok(response) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    users.refresh();
                    remove.set(false);
                    inspector.set(false);
                    let pending = response["cleanup_pending"].as_bool().unwrap_or_default();
                    let message = if pending {
                        "User deleted. Storage cleanup is pending."
                    } else {
                        "User deleted"
                    };
                    context.toast(tt(context, message), pending);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy.set(false);
            }
        });
    });
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
                        {move || tt(context, "Tabs.usersHeading")}
                    </h2>
                    <div class="flex flex-wrap justify-between gap-4 mb-5">
                        <div class="flex flex-wrap gap-3 items-center">
                            <Badge label="RBAC enforced" tone="indigo" />
                            <span class="text-sm text-slate-400">
                                {move || {
                                    tt_with(
                                        context,
                                        "Users.registeredCount",
                                        &[("count", &json_rows(&users.data.get()).len().to_string())],
                                    )
                                }}
                            </span>
                        </div>
                        <div class="flex gap-3">
                            <button
                                type="button"
                                class="glass-button px-4 py-2"
                                on:click=move |_| users.refresh()
                                aria-label=move || tt(context, "Refresh users")
                            >
                                {move || tt(context, "Common.refresh")}
                            </button>
                        </div>
                    </div>
                    <ResourceFeedback resource=users />
                    <DataGrid
                        label="User directory"
                        rows
                        columns=vec![
                            GridColumn::numeric("id", "ID"),
                            GridColumn::new("username", "Username"),
                            GridColumn::new("email", "Email"),
                            GridColumn::new("role_label", "Role"),
                            GridColumn::new("two_factor_label", "2FA"),
                            GridColumn::new("oauth_label", "Authentication"),
                            GridColumn::new("created_label", "Created"),
                        ]
                        on_select=Callback::new(move |row: Value| {
                            if busy.get_untracked() {
                                return;
                            }
                            draft.update(|d| d.mark_saved(json!({"role":row["role"]})));
                            selected.set(row);
                            inspector.set(true);
                        })
                    />
                    <p class="text-xs text-slate-400 mt-4">
                        {move || tt(
                            context,
                            "Search the virtualized directory and select a user to manage their role or delete the account. The server currently accepts admin and user roles.",
                        )}
                    </p>
                    <p class="text-xs text-slate-400 mt-3">
                        {move || tt(
                            context,
                            "New users are provisioned through the configured sign-in provider. This server has no local account creation, password reset, or account locking API.",
                        )}
                    </p>
                </ObsCard>
            </Show>
            <Drawer open=inspector title="Manage user">
                <p class="text-lg font-semibold break-all">
                    {move || selected.with(|v| text(v, "username"))}
                </p>
                <p class="text-sm text-slate-400 break-all mb-5">
                    {move || selected.with(|v| text(v, "email"))}
                </p>
                <div class="flex flex-wrap gap-3 mb-5">
                    <Badge
                        label=Signal::derive(move || selected.with(|v| text(v, "two_factor")))
                        tone="indigo"
                    />
                    <span class="text-sm">{move || selected.with(|v| tt(context, &text(v, "oauth")))}</span>
                </div>
                <Show when=move || !self_selected.get()>
                    <DraftSelect
                        draft
                        field="role"
                        label="Role"
                        options=vec![("admin", "Administrator"), ("user", "User")]
                    />
                    <DraftButtons draft busy on_save=save_role label="Update role" />
                    <button
                        type="button"
                        class="glass-button px-4 py-2 mt-5 text-rose-300"
                        disabled=move || busy.get() || last_admin.get()
                        on:click=move |_| remove.set(true)
                    >
                        {move || tt(context, "Delete User")}
                    </button>
                </Show>
                <Show when=move || self_selected.get()>
                    <p role="status" class="text-amber-300 text-sm">
                        {move || tt(context, "Your own account cannot be demoted or deleted here.")}
                    </p>
                </Show>
                <p class="text-xs text-slate-400 mt-5">
                    {move || tt(
                        context,
                        "Password resets and account locking are not exposed by this server. Users can change their own password under Profile & Security.",
                    )}
                </p>
            </Drawer>
            <ConfirmDialog
                open=remove
                title="Permanently delete this user?"
                message="The selected account and its access will be removed. Your own account and the last administrator are protected."
                busy
                on_confirm=delete
            />
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_users_keep_extra_fields_and_authentication_indicators() {
        let user = User {
            id: 42,
            username: "alice".into(),
            role: "admin".into(),
            is_oauth: true,
            totp_enabled: true,
            ..Default::default()
        };
        let mut value = serde_json::to_value(user).unwrap();
        value["created_at"] = json!("2026-11-16");
        value["future_field"] = json!(true);
        let row = user_row(value);
        assert_eq!(row["id"], 42);
        assert_eq!(row["role"], "admin");
        assert_eq!(row["two_factor"], "Enabled");
        assert_eq!(row["oauth"], "OAuth");
        assert_eq!(row["created"], "2026-11-16");
        assert_eq!(row["future_field"], true);
    }

    #[test]
    fn legacy_user_shapes_retain_numeric_totp_and_google_identity() {
        let row = user_row(
            json!({"id":7,"username":"legacy","role":"user","totp_enabled":1,"google_id":"provider-id"}),
        );
        assert_eq!(row["two_factor"], "Enabled");
        assert_eq!(row["oauth"], "OAuth");
        assert_eq!(row["created"], "Not reported");
        assert_eq!(row["username"], "legacy");
        assert_eq!(user_row(json!({"id":8}))["oauth"], "Local");
    }

    #[test]
    fn final_administrator_guard_distinguishes_regular_users() {
        let admin = json!({"id":1,"role":"admin"});
        let user = json!({"id":2,"role":"user"});
        assert!(last_administrator(&admin, &[admin.clone(), user.clone()]));
        assert!(!last_administrator(&user, &[admin.clone(), user.clone()]));
        assert!(!last_administrator(
            &admin,
            &[admin.clone(), json!({"id":3,"role":"admin"})]
        ));
    }
}
