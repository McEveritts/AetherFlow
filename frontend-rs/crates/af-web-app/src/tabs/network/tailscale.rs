use super::*;

#[component]
pub(super) fn TailscaleSettings(status: ApiResource) -> impl IntoView {
    let context = app();
    let routes = RwSignal::new(FormDraft::new(json!({"routes":""})));
    let draft = RwSignal::new(FormDraft::new(
        json!({"accept_routes":false,"advertise_exit_node":false,"exit_node":"","exit_node_allow_lan_access":false}),
    ));
    let busy = RwSignal::new(false);
    let auth_url = RwSignal::new(String::new());
    let down = RwSignal::new(false);
    Effect::new(move |_| {
        let value = status.data.get()["tailscale"].clone();
        if value.is_object() {
            let advertised = value["advertised_routes"]
                .as_array()
                .map(|v| {
                    v.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            routes.update(|d| d.apply_server_refresh(json!({"routes":advertised})));
            draft.update(|d|d.apply_server_refresh(json!({
                "accept_routes":value["accept_routes"].as_bool().unwrap_or(false),
                "advertise_exit_node":value["advertise_exit_node"].as_bool().unwrap_or(false),
                "exit_node":text(&value,"exit_node"),"exit_node_allow_lan_access":value["exit_node_allow_lan_access"].as_bool().unwrap_or(false)
            })));
            if value["state"] == "running" {
                auth_url.set(String::new());
            } else if safe_login_url(&text(&value, "auth_url")) {
                auth_url.set(text(&value, "auth_url"));
            }
        }
    });
    let connect = move |reauth: bool| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        auth_url.set(String::new());
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            match ApiClient
                .post(
                    "/api/v1/admin/network/tailscale/connect",
                    Some(&json!({"reauth":reauth})),
                )
                .await
            {
                Ok(value) => {
                    if auth_url.try_get_untracked().is_none() {
                        return;
                    }
                    let url = text(&value, "auth_url");
                    if safe_login_url(&url) {
                        auth_url.set(url);
                    } else if !url.is_empty() {
                        context.toast(
                            tt(
                                context,
                                "The server returned an untrusted Tailscale login URL",
                            ),
                            true,
                        );
                    }
                    status.refresh();
                    context.toast(
                        tt(
                            context,
                            value["message"]
                                .as_str()
                                .filter(|message| !message.trim().is_empty())
                                .unwrap_or("Tailscale connection requested"),
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
    };
    let save_routes = Callback::new(move |()| {
        if busy.get_untracked() {
            return;
        }
        let sent = draft_value(routes);
        let values = text(&sent, "routes")
            .split([',', '\n'])
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            match ApiClient
                .post(
                    "/api/v1/admin/network/tailscale/routes",
                    Some(&json!({"routes":values})),
                )
                .await
            {
                Ok(value) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    let saved = value["routes"]
                        .as_array()
                        .map(|v| {
                            v.iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_else(|| text(&sent, "routes"));
                    routes.update(|d| {
                        let _ = d.acknowledge_saved(&sent, json!({"routes":saved}));
                    });
                    status.refresh();
                    context.toast(
                        tt(
                            context,
                            "Advertised routes saved; approve them in the tailnet console",
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
    let save_settings = Callback::new(move |()| {
        if busy.get_untracked() {
            return;
        }
        let sent = draft_value(draft);
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            match ApiClient
                .post("/api/v1/admin/network/tailscale/settings", Some(&sent))
                .await
            {
                Ok(_) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    draft.update(|d| {
                        let _ = d.acknowledge_saved(&sent, sent.clone());
                    });
                    status.refresh();
                    context.toast(tt(context, "Tailscale preferences saved"), false);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy_guard.release();
            }
        });
    });
    view! {
        <ObsCard title="Tailscale Mesh VPN">
            <div class="space-y-2 text-sm">
                <p>
                    {move || {
                        status
                            .data
                            .with(|v| {
                                tt_with(context, "Daemon: {daemon} · Tailnet: {tailnet} · State: {state}", &[("daemon", &(tt(context, &(text(&v["tailscale"], "service_state")).to_string())).to_string()), ("tailnet", &(text(&v["tailscale"], "tailnet_name")).to_string()), ("state", &(tt(context, &(text(&v["tailscale"], "backend_state")).to_string())).to_string())])
                            })
                    }}
                </p>
                <p>
                    {move || {
                        status
                            .data
                            .with(|v| {
                                tt_with(context, "Node IP: {ip} · MagicDNS: {dns} · Name: {name}", &[("ip", &(text(&v["tailscale"]["self"], "tailscale_ip")).to_string()), ("dns", &(tt(context, &(text(&v["tailscale"], "magic_dns")).to_string())).to_string()), ("name", &(text(&v["tailscale"]["self"], "dns_name")).to_string())])
                            })
                    }}
                </p>
                <p role="alert" class="text-rose-300">
                    {move || status.data.with(|v| tt(context, &text(&v["tailscale"], "error")))}
                </p>
                <p class="text-amber-300">
                    {move || status.data.with(|v| tt(context, &text(&v["tailscale"], "health")))}
                </p>
            </div>
            <ProviderControl provider="tailscale" status />
            <div class="flex flex-wrap gap-3 mb-5">
                <button
                    type="button"
                    class="glass-button-primary px-4 py-2"
                    disabled=move || busy.get()
                    on:click=move |_| connect(false)
                >
                    {move || tt(context, "Up / Interactive login")}
                </button>
                <button
                    type="button"
                    class="glass-button px-4 py-2"
                    disabled=move || busy.get()
                    on:click=move |_| connect(true)
                >
                    {move || tt(context, "Reauthenticate")}
                </button>
                <button
                    type="button"
                    class="glass-button px-4 py-2"
                    disabled=move || busy.get()
                    on:click=move |_| down.set(true)
                >
                    {move || tt(context, "Down")}
                </button>
            </div>
            <Show when=move || !auth_url.get().is_empty()>
                <a
                    class="glass-button-primary inline-block px-4 py-2 mb-4"
                    href=move || auth_url.get()
                    target="_blank"
                    rel="noopener noreferrer"
                >
                    {move || tt(context, "Continue at login.tailscale.com")}
                </a>
            </Show>
            <p class="text-xs text-slate-400 mb-5">
                {move || tt(
                    context,
                    "Authentication uses Tailscale's interactive login. This server does not accept auth keys.",
                )}
            </p>
            <div class="grid lg:grid-cols-2 gap-6">
                <div>
                    <DraftInput
                        draft=routes
                        field="routes"
                        label="Advertised subnet routes"
                        placeholder="192.168.1.0/24, 10.0.0.0/8"
                    />
                    <DraftButtons
                        draft=routes
                        busy
                        on_save=save_routes
                        label="Save advertised routes"
                    />
                    <p class="text-xs text-slate-400 mt-3">
                        {move || tt(
                            context,
                            "Routes require approval in the Tailscale admin console. Clear the field and save to withdraw all routes.",
                        )}
                    </p>
                </div>
                <div>
                    <DraftCheck
                        draft
                        field="accept_routes"
                        label="Accept routes from other nodes"
                    />
                    <DraftCheck
                        draft
                        field="advertise_exit_node"
                        label="Advertise this host as an exit node"
                    />
                    <DraftInput
                        draft
                        field="exit_node"
                        label="Use exit node (IP or name)"
                        placeholder="Leave empty to use direct routing"
                    />
                    <DraftCheck
                        draft
                        field="exit_node_allow_lan_access"
                        label="Allow LAN access when using an exit node"
                    />
                    <DraftButtons draft busy on_save=save_settings />
                </div>
            </div>
            <DataGrid
                label="Tailscale mesh peers"
                rows=Signal::derive(move || {
                    status.data.get()["tailscale"]["peers"].as_array().cloned().unwrap_or_default()
                })
                columns=vec![
                    GridColumn::new("hostname", "Node"),
                    GridColumn::new("dns_name", "MagicDNS"),
                    GridColumn::new("tailscale_ip", "IP"),
                    GridColumn::new("online", "Online"),
                    GridColumn::new("os", "OS"),
                    GridColumn::new("exit_node", "Exit node"),
                    GridColumn::numeric("rx_bytes", "RX bytes"),
                    GridColumn::numeric("tx_bytes", "TX bytes"),
                ]
            />
        </ObsCard>
        <ConfirmDialog
            open=down
            title="Disconnect Tailscale?"
            message="This host will leave the active mesh connection. Your current connection may be interrupted."
            busy
            on_confirm=Callback::new(move |()| {
                if busy.get_untracked() {
                    return;
                }
                busy.set(true);
                let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
                spawn_local(async move {
                    match ApiClient.post("/api/v1/admin/network/tailscale/disconnect", None).await {
                        Ok(_) => {
                            if down.try_get_untracked().is_some() {
                                down.set(false);
                                auth_url.set(String::new());
                                status.refresh();
                            }
                            context.toast(tt(context, "Tailscale disconnected"), false);
                        }
                        Err(error) => context.toast(tt(context, &error.message), true),
                    }
                    if busy.try_get_untracked().is_some() {
                        busy_guard.release();
                    }
                });
            })
        />
    }
}
