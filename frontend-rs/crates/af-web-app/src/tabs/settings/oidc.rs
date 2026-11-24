use super::*;

#[component]
pub(super) fn OidcSettings() -> impl IntoView {
    let context = app();
    let can_read_settings = Signal::derive(move || context.can_read_area(PeerArea::Settings));
    let clients = use_api_when(can_read_settings, "/api/v1/admin/oidc/clients".to_string());
    let draft = RwSignal::new(FormDraft::new(
        json!({"name":"","redirects":"","public":false}),
    ));
    let busy = RwSignal::new(false);
    let reveal = RwSignal::new(false);
    let secret = RwSignal::new(Value::Null);
    let remove = RwSignal::new(false);
    let selected = RwSignal::new(Value::Null);
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Settings);
        reveal.set(false);
        remove.set(false);
        selected.set(Value::Null);
        secret.set(Value::Null);
    });
    Effect::new(move |_| {
        if !reveal.get() {
            secret.set(Value::Null);
        }
    });
    let create = move || {
        if busy.get_untracked() || context.is_remote_untracked() {
            return;
        }
        let sent = draft_value(draft);
        let redirects = text(&sent, "redirects")
            .split(['\n', ','])
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if text(&sent, "name").trim().is_empty() || redirects.is_empty() {
            context.toast(
                tt(context, "Name and at least one redirect URI are required"),
                true,
            );
            return;
        }
        let payload = json!({"name":text(&sent,"name").trim(),"redirect_uris":redirects,"public":sent["public"]});
        let server_epoch = context.server_epoch.get_untracked();
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            match ApiClient
                .post("/api/v1/admin/oidc/clients", Some(&payload))
                .await
            {
                Ok(value) => {
                    if secret.try_get_untracked().is_none()
                        || context.server_epoch.try_get_untracked() != Some(server_epoch)
                    {
                        return;
                    }
                    secret.set(value);
                    reveal.set(true);
                    clients.refresh();
                    draft.update(|d| {
                        let _ = d.acknowledge_saved(
                            &sent,
                            json!({"name":"","redirects":"","public":false}),
                        );
                    });
                }
                Err(error) => {
                    if context.server_epoch.try_get_untracked() == Some(server_epoch) {
                        context.toast(tt(context, &error.message), true);
                    }
                }
            }
            if busy.try_get_untracked().is_some() {
                busy_guard.release();
            }
        });
    };
    view! {
        <ObsCard title=Signal::derive(move || tt(context, "Settings.oidcClients"))>
            <Show when=move || !can_read_settings.get()>
                <p role="status" class="text-xs text-amber-300 mb-3">
                    {move || {
                        context
                            .area_block_reason(PeerArea::Settings, false)
                            .unwrap_or_default()
                    }}
                </p>
            </Show>
            <p class="text-sm text-slate-400 mb-4">
                {move || tt(
                    context,
                    "Register relying parties for openid, profile, and email. Public clients require PKCE (S256). To change a registration, register its replacement and remove the old client.",
                )}
            </p>
            <Show when=move || context.is_remote()>
                <p
                    role="status"
                    data-testid="oidc-remote-readonly-note"
                    class="text-xs text-amber-300 mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2"
                >
                    {move || tt(context, "PeerSwitch.oidcRemoteReadOnly")}
                </p>
            </Show>
            <form
                class="space-y-4"
                on:submit=move |event| {
                    event.prevent_default();
                    create();
                }
            >
                <DraftInput
                    draft
                    field="name"
                    label="Client name"
                    required=true
                    disabled=Signal::derive(move || context.is_remote())
                />
                <label class="block text-sm space-y-2">
                    <span>{move || tt(context, "Redirect URIs (one per line)")}</span>
                    <textarea
                        class="glass-input px-3 py-2 w-full"
                        rows="3"
                        required
                        disabled=move || context.is_remote()
                        prop:value=move || text(&draft_value(draft), "redirects")
                        on:input=move |event| edit(
                            draft,
                            "redirects",
                            json!(event_target_value(&event)),
                        )
                    ></textarea>
                </label>
                <DraftCheck
                    draft
                    field="public"
                    label="Public client (PKCE required, no client secret)"
                    disabled=Signal::derive(move || context.is_remote())
                />
                <button
                    type="submit"
                    class="glass-button-primary px-4 py-2"
                    disabled=move || busy.get() || context.is_remote()
                    title=move || {
                        if context.is_remote() {
                            tt(context, "PeerSwitch.oidcRemoteReadOnly")
                        } else {
                            String::new()
                        }
                    }
                >
                    {move || tt(context, "Register OIDC client")}
                </button>
            </form>
            <ResourceFeedback resource=clients />
            <DataGrid
                label="Registered OIDC clients"
                columns=vec![
                    GridColumn::new("id", "Client ID"),
                    GridColumn::new("name", "Name"),
                    GridColumn::new("redirect_uris", "Redirect URIs"),
                    GridColumn::new("created_at", "Created"),
                ]
                rows=Signal::derive(move || {
                    clients.data.with(|v| v["clients"].as_array().cloned().unwrap_or_default())
                })
                on_select=Callback::new(move |row: Value| {
                    if context.is_remote_untracked() {
                        context.toast(tt(context, "PeerSwitch.oidcRemoteReadOnly"), true);
                        return;
                    }
                    selected.set(row);
                    remove.set(true);
                })
            />
            <p class="text-xs text-slate-400 mt-3">
                {move || tt(context, "Select a client to remove it.")}
            </p>
        </ObsCard>
        <Modal open=reveal title="One-time OIDC credentials">
            <p class="text-amber-300 text-sm mb-4">
                {move || tt(
                    context,
                    "Save these credentials now. The client secret cannot be retrieved later.",
                )}
            </p>
            <dl class="space-y-3">
                <dt>{move || tt(context, "Client ID")}</dt>
                <dd class="font-mono break-all">{move || secret.with(|v| text(v, "client_id"))}</dd>
                <dt>{move || tt(context, "Client secret")}</dt>
                <dd class="font-mono break-all">
                    {move || {
                        secret
                            .with(|v| {
                                if text(v, "client_secret").is_empty() {
                                    tt(context, "Public client — PKCE S256")
                                } else {
                                    text(v, "client_secret")
                                }
                            })
                    }}
                </dd>
            </dl>
            <button
                type="button"
                class="glass-button px-4 py-2 mt-4"
                on:click=move |_| {
                    let content = secret.get_untracked().to_string();
                    if let Err(error) = download_text(
                        &content,
                        "aetherflow-oidc-client.json",
                        "application/json",
                    ) {
                        context.toast(tt(context, &error), true);
                    }
                }
            >
                {move || tt(context, "Download credentials")}
            </button>
        </Modal>
        <ConfirmDialog
            open=remove
            title="Delete OIDC client?"
            message="The selected relying party will no longer be able to sign in using this client registration."
            busy
            on_confirm=Callback::new(move |()| {
                if busy.get_untracked() || context.is_remote_untracked() {
                    return;
                }
                let server_epoch = context.server_epoch.get_untracked();
                busy.set(true);
                let id = selected.with_untracked(|v| text(v, "id"));
                let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
                spawn_local(async move {
                    match ApiClient
                        .delete(&format!("/api/v1/admin/oidc/clients/{}", encode(&id)), None)
                        .await
                    {
                        Ok(_) => {
                            if busy.try_get_untracked().is_none()
                                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                            {
                                return;
                            }
                            clients.refresh();
                            remove.set(false);
                            context.toast(tt(context, "OIDC client removed"), false);
                        }
                        Err(error) => {
                            if context.server_epoch.try_get_untracked() == Some(server_epoch) {
                                context.toast(tt(context, &error.message), true);
                            }
                        }
                    }
                    if busy.try_get_untracked().is_some() {
                        busy_guard.release();
                    }
                });
            })
        />
    }
}
