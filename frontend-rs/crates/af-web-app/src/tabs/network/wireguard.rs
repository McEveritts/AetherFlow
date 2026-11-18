use super::*;

#[component]
pub(super) fn ProviderControl(provider: &'static str, status: ApiResource) -> impl IntoView {
    let context = app();
    let busy = RwSignal::new(false);
    let confirm = RwSignal::new(false);
    let action = RwSignal::new("start".to_string());
    let execute = Callback::new(move |()| {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let command = action.get_untracked();
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            let payload = json!({"action":command});
            match ApiClient
                .post(
                    &format!("/api/v1/admin/network/{provider}/service"),
                    Some(&payload),
                )
                .await
            {
                Ok(value) => {
                    if confirm.try_get_untracked().is_some() {
                        confirm.set(false);
                        status.refresh();
                    }
                    context.toast(
                        tt(
                            context,
                            value["message"].as_str().unwrap_or("VPN service updated"),
                        ),
                        false,
                    );
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy_guard.release();
            }
        });
    });
    view! {
        <div class="flex flex-wrap gap-3 my-4">
            {["start", "stop", "restart"]
                .into_iter()
                .map(move |command| {
                    view! {
                        <button
                            type="button"
                            class="glass-button px-4 py-2"
                            disabled=move || busy.get()
                            on:click=move |_| {
                                action.set(command.to_string());
                                if command == "start" {
                                    execute.run(());
                                } else {
                                    confirm.set(true);
                                }
                            }
                        >
                            {move || tt(
                                context,
                                match command {
                                    "start" => "Start daemon",
                                    "stop" => "Stop daemon",
                                    _ => "Restart daemon",
                                },
                            )}
                        </button>
                    }
                })
                .collect_view()}
        </div>
        <ConfirmDialog
            open=confirm
            title="Change VPN daemon state?"
            message="Stopping or restarting this VPN may interrupt your connection to this host."
            busy
            on_confirm=execute
        />
    }
}
#[component]
pub(super) fn WireGuardSettings(status: ApiResource) -> impl IntoView {
    let context = app();
    let form = RwSignal::new(FormDraft::new(peer_form(&Value::Null)));
    let create = RwSignal::new(false);
    let editing = RwSignal::new(false);
    let selected = RwSignal::new(Value::Null);
    let revoke = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let generation = RwSignal::new(0u64);
    let private_key = RwSignal::new(String::new());
    let generated_public = RwSignal::new(String::new());
    let exported = RwSignal::new(String::new());
    let export_open = RwSignal::new(false);
    let filename = RwSignal::new("wg-peer.conf".to_string());
    let enrolled_key = RwSignal::new(String::new());
    let enrolled_peer = RwSignal::new(Value::Null);
    Effect::new(move |_| {
        if !create.get() {
            generation.update(|g| *g += 1);
            private_key.set(String::new());
            generated_public.set(String::new());
            enrolled_key.set(String::new());
            enrolled_peer.set(Value::Null);
        }
        if !export_open.get() {
            exported.set(String::new());
        }
    });
    Effect::new(move |_| {
        let key = enrolled_key.get();
        if !key.is_empty() {
            if let Some(peer) = status.data.get()["wireguard"]["peers"]
                .as_array()
                .and_then(|peers| peers.iter().find(|peer| text(peer, "public_key") == key))
                .cloned()
            {
                enrolled_peer.set(peer);
            }
        }
    });
    let prepare_export =
        move |sent: &Value, peer: &Value, private: &str, server: &Value| match client_config(
            sent, peer, private, server,
        ) {
            Ok(config) => {
                let name = text(sent, "name")
                    .to_lowercase()
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                            c
                        } else {
                            '-'
                        }
                    })
                    .take(48)
                    .collect::<String>();
                filename.set(format!(
                    "{}.conf",
                    if name.trim_matches('-').is_empty() {
                        "wg-peer"
                    } else {
                        &name
                    }
                ));
                exported.set(config);
                export_open.set(true);
                create.set(false);
            }
            Err(error) => context.toast(tt(context, &error), true),
        };
    Effect::new(move |_| {
        let current = text(&draft_value(form), "public_key");
        if !generated_public.get_untracked().is_empty()
            && current != generated_public.get_untracked()
        {
            private_key.set(String::new());
            generated_public.set(String::new());
        }
    });
    let generate = move || {
        if busy.get_untracked() || !enrolled_key.get_untracked().is_empty() {
            return;
        }
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            match ApiClient
                .post("/api/v1/admin/network/wireguard/keygen", None)
                .await
            {
                Ok(value) => {
                    if generation.try_get_untracked() != Some(ticket)
                        || create.try_get_untracked() != Some(true)
                    {
                        if busy.try_get_untracked().is_some() {
                            busy_guard.release();
                        }
                        return;
                    }
                    let public = text(&value, "public_key");
                    let private = text(&value, "private_key");
                    if public.is_empty() || private.is_empty() {
                        context.toast(
                            tt(context, "The key generator returned incomplete credentials"),
                            true,
                        );
                    } else {
                        edit(form, "public_key", json!(public));
                        generated_public.set(public);
                        private_key.set(private);
                    }
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy_guard.release();
            }
        });
    };
    let save = move || {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let sent = draft_value(form);
        let key = text(&sent, "public_key").trim().to_string();
        if key.is_empty() {
            context.toast(
                tt(context, "Generate or enter a WireGuard public key"),
                true,
            );
            return;
        }
        let keepalive = match text(&sent, "keepalive").parse::<u16>() {
            Ok(value) => value,
            Err(_) => {
                context.toast(
                    tt(context, "Keepalive must be between 0 and 65535 seconds"),
                    true,
                );
                return;
            }
        };
        let is_edit = editing.get_untracked();
        let client_private = if generated_public.get_untracked() == key {
            private_key.get_untracked()
        } else {
            String::new()
        };
        if !is_edit
            && !client_private.is_empty()
            && (text(&sent, "client_endpoint").trim().is_empty()
                || (sent["tunnel"] == "split" && text(&sent, "split").trim().is_empty()))
        {
            context.toast(
                tt(
                    context,
                    "Enter the server endpoint and split CIDRs before creating this client",
                ),
                true,
            );
            return;
        }
        if !is_edit && enrolled_key.get_untracked() == key {
            prepare_export(
                &sent,
                &enrolled_peer.get_untracked(),
                &client_private,
                &status.data.get_untracked(),
            );
            return;
        }
        let ticket = generation.get_untracked();
        let server = status.data.get_untracked();
        let payload = json!({"public_key":key,"name":text(&sent,"name").trim(),"allowed_ips":text(&sent,"allowed_ips").trim(),"endpoint":text(&sent,"endpoint").trim(),"persistent_keepalive":keepalive});
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            let path = if is_edit {
                format!("/api/v1/admin/network/wireguard/peers/{}", encode(&key))
            } else {
                "/api/v1/admin/network/wireguard/peers".into()
            };
            match ApiClient
                .request(&path, if is_edit { "PUT" } else { "POST" }, Some(&payload))
                .await
            {
                Ok(value) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    status.refresh();
                    context.toast(
                        tt(
                            context,
                            value["message"].as_str().unwrap_or("WireGuard peer saved"),
                        ),
                        false,
                    );
                    if generation.try_get_untracked() != Some(ticket) {
                        if busy.try_get_untracked().is_some() {
                            busy_guard.release();
                        }
                        return;
                    }
                    if !is_edit && create.get_untracked() && !client_private.is_empty() {
                        enrolled_key.set(key.clone());
                        if text(&value["peer"], "public_key") != key {
                            context.toast(tt(context, "Peer saved, but the returned peer identity could not be verified. Keep this view open and refresh before retrying."),true);
                        } else {
                            enrolled_peer.set(value["peer"].clone());
                            prepare_export(&sent, &value["peer"], &client_private, &server);
                        }
                    } else {
                        editing.set(false);
                        create.set(false);
                    }
                    form.update(|d| {
                        let _ = d.acknowledge_saved(&sent, sent.clone());
                    });
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy_guard.release();
            }
        });
    };
    let remove = Callback::new(move |()| {
        if busy.get_untracked() || !context.is_admin() {
            return;
        }
        let key = selected.with_untracked(|v| text(v, "public_key"));
        if key.is_empty() {
            return;
        }
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            match ApiClient
                .delete(
                    &format!("/api/v1/admin/network/wireguard/peers/{}", encode(&key)),
                    None,
                )
                .await
            {
                Ok(_) => {
                    if revoke.try_get_untracked().is_some() {
                        revoke.set(false);
                        editing.set(false);
                        status.refresh();
                    }
                    context.toast(tt(context, "WireGuard peer revoked"), false);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy_guard.release();
            }
        });
    });
    let peer_rows = Signal::derive(move || {
        status.data.get()["wireguard"]["peers"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|mut peer| {
                peer["handshake_age"] = json!(handshake_age(context, &peer));
                for (field, display) in [("transfer_rx", "rx"), ("transfer_tx", "tx")] {
                    let raw = text(&peer, field);
                    peer[display] =
                        json!(raw.parse::<f64>().map(bytes).unwrap_or_else(
                            |_| if raw.is_empty() {
                                tt(context, "Not reported")
                            } else {
                                raw
                            }
                        ));
                }
                peer
            })
            .collect::<Vec<_>>()
    });
    view! {
        <ObsCard title="WireGuard (wg0) VPN">
            <div class="grid sm:grid-cols-2 gap-4 text-sm">
                <p>
                    {move || {
                        status
                            .data
                            .with(|v| {
                                tt_with(context, "Interface: {iface} · State: {state} · Service: {service}", &[("iface", &(text(&v["wireguard"], "interface")).to_string()), ("state", &(tt(context, &(text(&v["wireguard"], "state")).to_string())).to_string()), ("service", &(tt(context, &(text(&v["wireguard"], "service_state")).to_string())).to_string())])
                            })
                    }}
                </p>
                <p>
                    {move || {
                        status
                            .data
                            .with(|v| {
                                tt_with(context, "Listen port: {port} · Addresses: {addresses}", &[("port", &tt(context, &wireguard_listen(&v["wireguard"]))), ("addresses", &tt(context, &wireguard_addresses(&v["wireguard"])))])
                            })
                    }}
                </p>
                <p class="break-all sm:col-span-2">
                    {move || {
                        status
                            .data
                            .with(|v| {
                                tt_with(context, "Public key: {key}", &[("key", &tt(context, &wireguard_public_key(&v["wireguard"])))])
                            })
                    }}
                </p>
                <p role="alert" class="text-rose-300 sm:col-span-2">
                    {move || status.data.with(|v| text(&v["wireguard"], "error"))}
                </p>
            </div>
            <ProviderControl provider="wireguard" status />
            <button
                type="button"
                class="glass-button-primary px-4 py-2 mb-5"
                disabled=move || busy.get() || status.data.get()["wireguard"]["state"] != "running"
                on:click=move |_| {
                    editing.set(false);
                    form.update(|d| d.mark_saved(peer_form(&status.data.get_untracked())));
                    private_key.set(String::new());
                    generated_public.set(String::new());
                    generation.update(|g| *g += 1);
                    create.set(true);
                }
            >
                {move || tt(context, "Create Peer")}
            </button>
            <DataGrid
                label="WireGuard peers"
                rows=peer_rows
                columns=vec![
                    GridColumn::new("name", "Peer"),
                    GridColumn::new("public_key", "Public key"),
                    GridColumn::new("allowed_ips", "Client IPs"),
                    GridColumn::new("endpoint", "Remote endpoint"),
                    GridColumn::new("handshake_age", "Handshake age"),
                    GridColumn::new("rx", "RX"),
                    GridColumn::new("tx", "TX"),
                ]
                on_select=Callback::new(move |peer: Value| {
                    if busy.get_untracked() {
                        return;
                    }
                    let mut value = peer_form(&status.data.get_untracked());
                    for field in ["name", "public_key", "allowed_ips", "endpoint"] {
                        value[field] = json!(text(&peer,field));
                    }
                    value["keepalive"] = json!(
                        peer["persistent_keepalive"].as_u64().unwrap_or(25).to_string()
                    );
                    form.update(|d| d.mark_saved(value));
                    selected.set(peer);
                    editing.set(true);
                })
            />
        </ObsCard>
        <Modal open=create title="Create WireGuard peer">
            <div class="grid sm:grid-cols-2 gap-4">
                <DraftInput draft=form field="name" label="Peer name" />
                <label class="text-sm space-y-2">
                    <span>{move || tt(context, "Client public key")}</span>
                    <input
                        class="glass-input w-full px-3 py-2"
                        disabled=move || busy.get() || !enrolled_key.get().is_empty()
                        prop:value=move || text(&draft_value(form), "public_key")
                        on:input=move |event| {
                            generation.update(|g| *g += 1);
                            private_key.set(String::new());
                            generated_public.set(String::new());
                            edit(form, "public_key", json!(event_target_value(&event)));
                        }
                    />
                </label>
                <DraftInput
                    draft=form
                    field="allowed_ips"
                    label="Assigned client address"
                    placeholder="Leave empty for allocation"
                />
                <DraftInput draft=form field="endpoint" label="Peer endpoint (optional)" />
                <DraftInput
                    draft=form
                    field="keepalive"
                    label="Persistent keepalive (seconds)"
                    kind="number"
                />
                <DraftInput
                    draft=form
                    field="client_endpoint"
                    label="Public server endpoint"
                    placeholder="vpn.example.com:51820"
                />
                <DraftInput draft=form field="dns" label="Client DNS resolvers" />
                <DraftSelect
                    draft=form
                    field="tunnel"
                    label="Tunnel mode"
                    options=vec![("full_ipv4", "Full tunnel (IPv4)"), ("split", "Split tunnel")]
                />
                <Show when=move || draft_value(form)["tunnel"] == "split">
                    <DraftInput
                        draft=form
                        field="split"
                        label="Split tunnel allowed CIDRs"
                        placeholder="10.66.66.0/24"
                    />
                </Show>
            </div>
            <p class="text-sm text-amber-300 my-4">
                {move || tt(
                    context,
                    "Generated private keys stay in this browser view. Download the configuration or scan the QR code after enrollment; it cannot be retrieved later.",
                )}
            </p>
            <div class="flex flex-wrap gap-3">
                <button
                    type="button"
                    class="glass-button px-4 py-2"
                    disabled=move || busy.get() || !enrolled_key.get().is_empty()
                    on:click=move |_| generate()
                >
                    {move || tt(context, "Generate client keypair")}
                </button>
                <button
                    type="button"
                    class="glass-button-primary px-4 py-2"
                    disabled=move || busy.get()
                    on:click=move |_| save()
                >
                    {move || tt(context, if enrolled_key.get().is_empty() {
                            "Enroll peer"
                        } else {
                            "Retry client export"
                        })}
                </button>
            </div>
        </Modal>
        <Modal open=editing title="Edit WireGuard peer">
            <p class="font-mono text-xs break-all mb-4">
                {move || selected.with(|v| text(v, "public_key"))}
            </p>
            <div class="grid sm:grid-cols-2 gap-4">
                <DraftInput draft=form field="name" label="Peer name" />
                <DraftInput draft=form field="allowed_ips" label="Client addresses" />
                <DraftInput draft=form field="endpoint" label="Peer endpoint" />
                <DraftInput
                    draft=form
                    field="keepalive"
                    label="Persistent keepalive (seconds)"
                    kind="number"
                />
            </div>
            <DraftButtons
                draft=form
                busy
                on_save=Callback::new(move |()| save())
                label="Update peer"
            />
            <button
                type="button"
                class="glass-button px-4 py-2 mt-4 text-rose-300"
                disabled=move || busy.get()
                on:click=move |_| revoke.set(true)
            >
                {move || tt(context, "Revoke Peer")}
            </button>
        </Modal>
        <Modal open=export_open title="One-time WireGuard client configuration">
            <p class="text-sm text-amber-300 mb-4">
                {move || tt(
                    context,
                    "Save this configuration securely. Closing the dialog clears its private key from this view.",
                )}
            </p>
            <div class="bg-white inline-block p-3 rounded-xl">
                <QrCodeSvg
                    payload=Signal::derive(move || exported.get())
                    label="WireGuard client configuration QR code"
                />
            </div>
            <pre class="text-xs whitespace-pre-wrap break-all max-h-72 overflow-auto my-4">
                {move || exported.get()}
            </pre>
            <button
                type="button"
                class="glass-button-primary px-4 py-2"
                on:click=move |_| {
                    if let Err(error) = download_text(
                        &exported.get_untracked(),
                        &filename.get_untracked(),
                        "text/plain",
                    ) {
                        context.toast(tt(context, &error), true);
                    }
                }
            >
                {move || tt(context, "Download .conf")}
            </button>
        </Modal>
        <ConfirmDialog
            open=revoke
            title="Revoke this WireGuard peer?"
            message="The selected peer will immediately lose VPN access and its persistent configuration will be removed."
            busy
            on_confirm=remove
        />
    }
}
