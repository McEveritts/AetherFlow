use super::*;
use crate::state::AppContext;
use crate::tabs::busy::BusyGuard;

#[derive(Clone, Copy)]
struct IngressWrite {
    busy: RwSignal<bool>,
    generation: RwSignal<u64>,
}

impl IngressWrite {
    fn new(context: AppContext) -> Self {
        let write = Self {
            busy: RwSignal::new(false),
            generation: RwSignal::new(0),
        };
        Effect::new(move |_| {
            if !context.can_write_area(PeerArea::Network) {
                write
                    .generation
                    .update(|ticket| *ticket = ticket.wrapping_add(1));
                write.busy.set(false);
            }
        });
        write
    }

    fn begin(self, context: AppContext) -> (BusyGuard, impl Fn() -> bool + Copy) {
        let session = context.session_epoch.get_untracked();
        let server = context.server_epoch.get_untracked();
        let grant = context.area_revocation_epoch_untracked(PeerArea::Network);
        self.generation
            .update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = self.generation.get_untracked();
        self.busy.set(true);
        let guard = BusyGuard::for_generation(self.busy, self.generation, ticket);
        let is_current = move || {
            self.generation.try_get_untracked() == Some(ticket)
                && context.session_epoch.try_get_untracked() == Some(session)
                && context.server_epoch.try_get_untracked() == Some(server)
                && context.area_revocation_epoch_untracked(PeerArea::Network) == grant
                && context.can_write_area_untracked(PeerArea::Network)
        };
        (guard, is_current)
    }
}

pub(super) fn normalize_ingress_target(target: String) -> Option<String> {
    let trimmed = target.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

pub(super) fn filter_ingress_names(rows: &[Value], focused: Option<&str>) -> Vec<String> {
    let names = rows
        .iter()
        .map(|v| text(v, "appName"))
        .filter(|name| !name.is_empty());
    match focused.and_then(|s| normalize_ingress_target(s.to_string())) {
        Some(target) => names
            .filter(|name| name.eq_ignore_ascii_case(&target))
            .collect(),
        None => names.collect(),
    }
}

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
    let can_read_settings = Signal::derive(move || context.can_read_area(PeerArea::Settings));
    let can_read_network = Signal::derive(move || context.can_read_area(PeerArea::Network));
    let can_read_services = Signal::derive(move || context.can_read_area(PeerArea::Services));
    let settings = use_api_when(can_read_settings, "/api/v1/auth/settings".to_string());
    let configs = use_api_when(
        can_read_network,
        "/api/v1/admin/ingress/configs".to_string(),
    );
    let services = use_api_when(can_read_services, "/api/v1/admin/services".to_string());
    poll_resource_when(configs, 15_000, move || {
        context.can_read_area_untracked(PeerArea::Network)
    });
    poll_resource_when(services, 15_000, move || {
        context.can_read_area_untracked(PeerArea::Services)
    });
    let draft = RwSignal::new(FormDraft::new(json!({"baseDomain":""})));
    let busy = RwSignal::new(false);
    let save_ticket = RwSignal::new(0u64);
    let sync = IngressWrite::new(context);
    let focused_app = RwSignal::new(
        context
            .take_pending_subtab(crate::state::TabId::Network)
            .and_then(normalize_ingress_target),
    );
    Effect::new(move |_| {
        context.pending_subtab.track();
        if let Some(target) = context.take_pending_subtab(crate::state::TabId::Network) {
            focused_app.set(normalize_ingress_target(target));
        }
    });
    Effect::new(move |_| {
        context.session_epoch.track();
        context.server_epoch.track();
        context.area_revocation_epoch(PeerArea::Settings);
        can_read_settings.track();
        save_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        draft.set(FormDraft::new(json!({"baseDomain":""})));
        busy.set(false);
    });
    Effect::new(move |_| {
        if !context.can_write_area(PeerArea::Settings) {
            save_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
            busy.set(false);
        }
    });
    Effect::new(move |_| {
        if !can_read_settings.get() {
            return;
        }
        let value = settings.data.get();
        if value.is_object() {
            draft.update(|d| {
                d.apply_server_refresh(json!({"baseDomain":text(&value,"baseDomain")}))
            });
        }
    });
    let save = Callback::new(move |()| {
        if busy.get_untracked()
            || sync.busy.get_untracked()
            || !context.can_write_area_untracked(PeerArea::Settings)
        {
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
        let session_epoch = context.session_epoch.get_untracked();
        let server_epoch = context.server_epoch.get_untracked();
        let settings_grant = context.area_revocation_epoch_untracked(PeerArea::Settings);
        save_ticket.update(|ticket| *ticket = ticket.wrapping_add(1));
        let ticket = save_ticket.get_untracked();
        busy.set(true);
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(busy, save_ticket, ticket);
        spawn_local(async move {
            let result = async {
                let mut payload = ApiClient.get("/api/v1/auth/settings").await?;
                if save_ticket.try_get_untracked() != Some(ticket)
                    || context.session_epoch.try_get_untracked() != Some(session_epoch)
                    || context.server_epoch.try_get_untracked() != Some(server_epoch)
                    || context.area_revocation_epoch_untracked(PeerArea::Settings) != settings_grant
                    || !context.can_write_area_untracked(PeerArea::Settings)
                {
                    return Err(af_web_core::api::ApiError {
                        status: 0,
                        code: Some("SERVER_CHANGED".into()),
                        message: "Server changed; request cancelled".into(),
                    });
                }
                payload["baseDomain"] = json!(domain);
                ApiClient
                    .put("/api/v1/admin/settings", Some(&payload))
                    .await?;
                ApiClient.get("/api/v1/auth/settings").await
            }
            .await;
            if save_ticket.try_get_untracked() != Some(ticket)
                || busy.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(session_epoch)
                || context.server_epoch.try_get_untracked() != Some(server_epoch)
                || context.area_revocation_epoch_untracked(PeerArea::Settings) != settings_grant
                || !context.can_read_area_untracked(PeerArea::Settings)
                || !context.can_write_area_untracked(PeerArea::Settings)
            {
                return;
            }
            match result {
                Ok(value) => {
                    draft.update(|d| {
                        let _ =
                            d.acknowledge_saved(&sent, json!({"baseDomain":value["baseDomain"]}));
                    });
                    context.publish_settings_save(value.clone());
                    settings.commit(value);
                    if context.can_read_area_untracked(PeerArea::Network) {
                        configs.refresh();
                    }
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
                        disabled=Signal::derive(move || {
                            !context.can_write_area(PeerArea::Settings)
                        })
                    />
                    <Show when=move || !can_read_settings.get()>
                        <p role="status" class="text-xs text-amber-300 mt-2">
                            {move || {
                                context
                                    .area_block_reason(PeerArea::Settings, false)
                                    .unwrap_or_default()
                            }}
                        </p>
                    </Show>
                    <p class="text-sm text-slate-400 mt-3">
                        {move || {
                            tt_with(context, "Public routing: <app>.{domain} · LAN routing: <app>.aether.local", &[("domain", &(text(&draft_value(draft), "baseDomain")).to_string())])
                        }}
                    </p>
                    <DraftButtons
                        draft
                        busy
                        on_save=save
                        label="Save base domain"
                        disabled=Signal::derive(move || {
                            sync.busy.get() || !context.can_write_area(PeerArea::Settings)
                        })
                        title=Signal::derive(move || {
                            context
                                .area_block_reason(crate::state::PeerArea::Settings, true)
                                .unwrap_or_default()
                        })
                    />
                </div>
                <div class="text-sm space-y-3">
                    <p>
                        {move || {
                            tt_with(context, "Apache2 gateway: {gateway} · af-certbot-sync: {certbot}", &[("gateway", &(tt(context, &(service_state("apache2")).to_string())).to_string()), ("certbot", &(tt(context, &(service_state("af-certbot-sync")).to_string())).to_string())])
                        }}
                    </p>
                    <Show when=move || !can_read_services.get()>
                        <p role="status" class="text-xs text-amber-300">
                            {move || {
                                context
                                    .area_block_reason(PeerArea::Services, false)
                                    .unwrap_or_default()
                            }}
                        </p>
                    </Show>
                    <p class="text-slate-400">
                        {move || tt(
                            context,
                            "Saving ingress synchronizes Apache2, LAN split-horizon DNS, and VPN DNS providers. TLS-enabled apps trigger Let's Encrypt SAN synchronization. Certificate issuance and resolver readiness are not reported by this API.",
                        )}
                    </p>
                    <button
                        type="button"
                        class="glass-button px-4 py-2"
                        disabled=move || {
                            busy.get() || sync.busy.get() || !context.can_write_area(PeerArea::Network)
                        }
                        title=move || {
                            context
                                .area_block_reason(crate::state::PeerArea::Network, true)
                                .unwrap_or_default()
                        }
                        on:click=move |_| {
                            if busy.get_untracked()
                                || sync.busy.get_untracked()
                                || !context.can_write_area_untracked(PeerArea::Network)
                            {
                                return;
                            }
                            let (guard, is_current) = sync.begin(context);
                            spawn_local(async move {
                                let _guard = guard;
                                let result = async {
                                    let latest = ApiClient
                                        .get("/api/v1/admin/ingress/configs")
                                        .await
                                        .map_err(|e| e.message)?;
                                    if !is_current() {
                                        return Err("Server changed; request cancelled".to_string());
                                    }
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
                                if !is_current() {
                                    return;
                                }
                                match result {
                                    Ok(()) => {
                                        if context.can_read_area_untracked(PeerArea::Services) {
                                            services.refresh();
                                        }
                                        configs.refresh();
                                        context
                                            .toast(
                                                tt(context, "Let's Encrypt SAN synchronization requested"),
                                                false,
                                            );
                                    }
                                    Err(error) => context.toast(tt(context, &error), true),
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
            <Show when=move || focused_app.get().is_some()>
                <div class="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-indigo-400/25 bg-indigo-500/10 px-4 py-3 text-sm">
                    <span>
                        {move || {
                            focused_app
                                .get()
                                .map(|app| {
                                    tt_with(context, "Focused application: {app}", &[("app", &app)])
                                })
                                .unwrap_or_default()
                        }}
                    </span>
                    <button
                        type="button"
                        class="glass-button px-3 py-1.5 text-xs"
                        on:click=move |_| focused_app.set(None)
                    >
                        {move || tt(context, "Show all applications")}
                    </button>
                </div>
            </Show>
            <Show when=move || {
                let rows = ingress_rows(&configs.data.get());
                let focused = focused_app.get();
                !filter_ingress_names(&rows, focused.as_deref()).is_empty()
            }>
            <div
                role="table"
                aria-label=move || tt(context, "Application external access")
                class="divide-y divide-white/10 mt-5"
            >
                <For
                    each=move || {
                        let rows = ingress_rows(&configs.data.get());
                        let focused = focused_app.get();
                        filter_ingress_names(&rows, focused.as_deref())
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
                let rows = ingress_rows(&configs.data.get());
                focused_app.get().is_some_and(|target| {
                    !configs.loading.get()
                        && rows.iter().any(|v| !text(v, "appName").is_empty())
                        && filter_ingress_names(&rows, Some(&target)).is_empty()
                })
            }>
                <p role="status" class="text-sm text-slate-400 mt-4">
                    {move || {
                        focused_app
                            .get()
                            .map(|app| {
                                tt_with(
                                    context,
                                    "No external access entry found for {app}",
                                    &[("app", &app)],
                                )
                            })
                            .unwrap_or_default()
                    }}
                </p>
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
    let write = IngressWrite::new(context);
    let busy = write.busy;
    Effect::new(move |_| draft.update(|d| d.apply_server_refresh(ingress_form(&value.get()))));
    let save = Callback::new(move |()| {
        if busy.get_untracked() || !context.can_write_area_untracked(PeerArea::Network) {
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
        let app = name.get_value();
        let (guard, is_current) = write.begin(context);
        spawn_local(async move {
            let _guard = guard;
            if !is_current() {
                return;
            }
            let result = ApiClient
                .put(
                    &format!("/api/v1/admin/ingress/apps/{}", encode(&app)),
                    Some(&payload),
                )
                .await;
            if !is_current() {
                return;
            }
            match result {
                Ok(value) => {
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
                <DraftButtons
                    draft
                    busy
                    on_save=save
                    label="Save external access"
                    disabled=Signal::derive(move || {
                        !context.can_write_area(crate::state::PeerArea::Network)
                    })
                    title=Signal::derive(move || {
                        context
                            .area_block_reason(crate::state::PeerArea::Network, true)
                            .unwrap_or_default()
                    })
                />
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_ingress_rows_by_targeted_application_case_insensitively() {
        let rows = vec![
            json!({ "appName": "sonarr" }),
            json!({ "appName": "radarr" }),
        ];
        assert_eq!(filter_ingress_names(&rows, None), vec!["sonarr", "radarr"]);
        assert_eq!(filter_ingress_names(&rows, Some("Sonarr")), vec!["sonarr"]);
        assert_eq!(
            filter_ingress_names(&rows, Some("   ")),
            vec!["sonarr", "radarr"]
        );
        assert!(filter_ingress_names(&rows, Some("bazarr")).is_empty());
    }
}
