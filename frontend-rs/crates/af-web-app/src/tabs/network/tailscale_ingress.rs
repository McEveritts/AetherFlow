use super::*;

pub(super) fn ingress_rows(value: &Value) -> Vec<Value> {
    crate::tabs::contracts::grid_rows::<crate::tabs::contracts::IngressConfig>(&value["configs"])
}
pub(super) fn ingress_form(value: &Value) -> Value {
    let config: AppIngressConfig =
        crate::tabs::contracts::decode::<crate::tabs::contracts::IngressConfig>(value).config();
    json!({"publicDomain":config.public_domain,"externalAccessEnabled":config.external_access_enabled,"tlsEnabled":config.tls_enabled})
}

#[component]
pub(super) fn ExternalAccessSettings() -> impl IntoView {
    let context = app();
    let settings = use_api("/api/v1/auth/settings".to_string());
    let configs = use_api("/api/v1/admin/ingress/configs".to_string());
    let services = use_api("/api/v1/admin/services".to_string());
    poll_resource(configs, 15_000);
    poll_resource(services, 15_000);
    let draft = RwSignal::new(FormDraft::new(json!({"baseDomain":""})));
    let busy = RwSignal::new(false);
    Effect::new(move |_| {
        let value = settings.data.get();
        if value.is_object() {
            draft.update(|d| {
                d.apply_server_refresh(json!({"baseDomain":text(&value,"baseDomain")}))
            });
        }
    });
    let save = Callback::new(move |()| {
        if busy.get_untracked() {
            return;
        }
        let sent = draft_value(draft);
        let domain = text(&sent, "baseDomain")
            .trim()
            .trim_start_matches("*.")
            .to_lowercase();
        if !domain.is_empty() && !valid_domain(&domain) {
            context.toast(
                tt(
                    context,
                    "Enter a base domain without a scheme, port or path",
                ),
                true,
            );
            return;
        }
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            let result = async {
                let mut payload = ApiClient.get("/api/v1/auth/settings").await?;
                payload["baseDomain"] = json!(domain);
                ApiClient
                    .put("/api/v1/admin/settings", Some(&payload))
                    .await?;
                ApiClient.get("/api/v1/auth/settings").await
            }
            .await;
            if busy.try_get_untracked().is_none() {
                return;
            }
            match result {
                Ok(value) => {
                    draft.update(|d| {
                        let _ =
                            d.acknowledge_saved(&sent, json!({"baseDomain":value["baseDomain"]}));
                    });
                    context.settings.set(value);
                    settings.refresh();
                    configs.refresh();
                    context.toast(
                        tt(
                            context,
                            "Base domain saved; gateway and DNS synchronization requested",
                        ),
                        false,
                    );
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            busy_guard.release();
        });
    });
    let service_state = move |name: &str| {
        json_rows(&services.data.get())
            .into_iter()
            .find(|v| {
                ["name", "process", "id"]
                    .into_iter()
                    .any(|key| text(v, key) == name)
            })
            .map(|v| text(&v, "status"))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "Not reported".into())
    };
    view! {
        <ObsCard title="Automatic subdomain ingress & TLS">
            <div class="grid lg:grid-cols-2 gap-6">
                <div>
                    <DraftInput
                        draft
                        field="baseDomain"
                        label="Server base domain"
                        placeholder="example.com"
                    />
                    <p class="text-sm text-slate-400 mt-3">
                        {move || {
                            tt_with(context, "Public routing: <app>.{domain} · LAN routing: <app>.aether.local", &[("domain", &(text(&draft_value(draft), "baseDomain")).to_string())])
                        }}
                    </p>
                    <DraftButtons draft busy on_save=save label="Save base domain" />
                </div>
                <div class="text-sm space-y-3">
                    <p>
                        {move || {
                            tt_with(context, "Apache2 gateway: {gateway} · af-certbot-sync: {certbot}", &[("gateway", &(tt(context, &(service_state("apache2")).to_string())).to_string()), ("certbot", &(tt(context, &(service_state("af-certbot-sync")).to_string())).to_string())])
                        }}
                    </p>
                    <p class="text-slate-400">
                        {move || tt(
                            context,
                            "Saving ingress synchronizes Apache2, LAN split-horizon DNS, and VPN DNS providers. TLS-enabled apps trigger Let's Encrypt SAN synchronization. Certificate issuance and resolver readiness are not reported by this API.",
                        )}
                    </p>
                    <button
                        type="button"
                        class="glass-button px-4 py-2"
                        disabled=move || busy.get()
                        on:click=move |_| {
                            if busy.get_untracked() {
                                return;
                            }
                            busy.set(true);
                            let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
                            spawn_local(async move {
                                let result = async {
                                    let latest = ApiClient
                                        .get("/api/v1/admin/ingress/configs")
                                        .await
                                        .map_err(|e| e.message)?;
                                    let name = latest["configs"]
                                        .as_array()
                                        .and_then(|rows| {
                                            rows.iter().find(|v| v["tlsEnabled"] == true)
                                        })
                                        .map(|value| text(value, "appName"))
                                        .ok_or_else(|| {
                                            "Enable TLS for an application before synchronizing certificates"
                                                .to_string()
                                        })?;
                                    ApiClient
                                        .put(
                                            &format!("/api/v1/admin/ingress/apps/{}", encode(&name)),
                                            Some(&json!({"tlsEnabled":true})),
                                        )
                                        .await
                                        .map_err(|e| e.message)?;
                                    Ok::<(), String>(())
                                }
                                    .await;
                                match result {
                                    Ok(()) => {
                                        if busy.try_get_untracked().is_none() {
                                            return;
                                        }
                                        services.refresh();
                                        configs.refresh();
                                        context
                                            .toast(
                                                tt(context, "Let's Encrypt SAN synchronization requested"),
                                                false,
                                            );
                                    }
                                    Err(error) => context.toast(tt(context, &error), true),
                                }
                                if busy.try_get_untracked().is_some() {
                                    busy_guard.release();
                                }
                            });
                        }
                    >
                        {move || tt(context, "Sync Let's Encrypt SANs")}
                    </button>
                </div>
            </div>
            <ResourceFeedback resource=settings />
            <ResourceFeedback resource=services />
            <ResourceFeedback resource=configs />
            <Show when=move || ingress_rows(&configs.data.get()).iter().any(|value| !text(value, "appName").is_empty())>
            <div
                role="table"
                aria-label=move || tt(context, "Application external access")
                class="divide-y divide-white/10 mt-5"
            >
                <For
                    each=move || {
                        ingress_rows(&configs.data.get())
                            .iter()
                            .map(|v| text(v, "appName"))
                            .filter(|name| !name.is_empty())
                            .collect::<Vec<_>>()
                    }
                    key=|name| name.clone()
                    children=move |name| {
                        let key = StoredValue::new(name.clone());
                        let value = Signal::derive(move || {
                            ingress_rows(&configs.data.get())
                                .into_iter()
                                .find(|v| text(v, "appName") == key.get_value())
                                .unwrap_or(Value::Null)
                        });
                        view! { <IngressRow name value configs /> }
                    }
                />
            </div>
            </Show>
            <Show when=move || {
                !configs.loading.get()
                    && configs.data.get()["configs"].as_array().is_some_and(Vec::is_empty)
            }>
                <EmptyState
                    title="No ingress configurations"
                    description="Install an application to configure its external access."
                />
            </Show>
        </ObsCard>
    }
}
#[component]
pub(super) fn IngressRow(
    name: String,
    value: Signal<Value>,
    configs: ApiResource,
) -> impl IntoView {
    let context = app();
    let name = StoredValue::new(name);
    let draft: JsonDraft = RwSignal::new(FormDraft::new(ingress_form(&value.get_untracked())));
    let busy = RwSignal::new(false);
    Effect::new(move |_| draft.update(|d| d.apply_server_refresh(ingress_form(&value.get()))));
    let save = Callback::new(move |()| {
        if busy.get_untracked() {
            return;
        }
        let sent = draft_value(draft);
        let domain = text(&sent, "publicDomain").trim().to_string();
        if (sent["externalAccessEnabled"] == true || !domain.is_empty()) && !valid_domain(&domain) {
            context.toast(
                tt(context, "External access requires a valid public domain"),
                true,
            );
            return;
        }
        let mut payload = sent.clone();
        payload["publicDomain"] = json!(domain);
        busy.set(true);
        let app = name.get_value();
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            match ApiClient
                .put(
                    &format!("/api/v1/admin/ingress/apps/{}", encode(&app)),
                    Some(&payload),
                )
                .await
            {
                Ok(value) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    let saved = if value["config"].is_object() {
                        ingress_form(&value["config"])
                    } else {
                        payload
                    };
                    draft.update(|d| {
                        let _ = d.acknowledge_saved(&sent, saved);
                    });
                    configs.refresh();
                    context.toast(tt(context, "External access saved"), false);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy_guard.release();
            }
        });
    });
    view! {
        <div role="row" class="py-5 grid lg:grid-cols-2 gap-5 min-w-0">
            <div role="cell" class="space-y-3">
                <h3 class="font-semibold break-all">{name.get_value()}</h3>
                <p class="text-xs text-slate-400">
                    {move || tt_with(context, "LAN: {app}.aether.local", &[("app", &(name.get_value()).to_string())])}
                </p>
                <DraftInput draft field="publicDomain" label="Public domain" />
                <p class="text-xs text-slate-400">
                    {move || {
                        value
                            .with(|v| {
                                tt_with(context, "Host binding: 127.0.0.1:{port} · TLS configured: {tls}", &[("port", &(text(v, "listenPort")).to_string()), ("tls", &(tt(context, &(text(v, "tlsEnabled")).to_string())).to_string())])
                            })
                    }}
                </p>
            </div>
            <div role="cell">
                <DraftCheck draft field="externalAccessEnabled" label="Enable external access" />
                <DraftCheck draft field="tlsEnabled" label="Enable automatic TLS" />
                <DraftButtons draft busy on_save=save label="Save external access" />
            </div>
        </div>
    }
}
