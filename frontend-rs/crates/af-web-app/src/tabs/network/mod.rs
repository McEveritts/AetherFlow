use super::settings::{
    bytes, download_text, draft_value, edit, encode, poll_resource, text, DraftButtons, DraftCheck,
    DraftInput, DraftSelect, JsonDraft, ResourceFeedback,
};
use crate::state::{
    app, json_rows, owned_resource_reads, run_resource_read, use_api, ApiResource, ResourceReads,
};
use crate::tabs::l10n::{tt, tt_with};
use crate::tabs::l10n::{ConfirmDialog, DataGrid, EmptyState, Modal, ObsCard};
use af_web_core::{api::ApiClient, draft::FormDraft, models::AppIngressConfig};
use af_web_ui::{GridColumn, QrCodeSvg};
use leptos::prelude::*;
use serde_json::{json, Value};
use wasm_bindgen_futures::spawn_local;

mod helpers;
use helpers::*;
mod wireguard;
use wireguard::*;
mod tailscale;
use tailscale::*;
mod tailscale_ingress;
use tailscale_ingress::*;

#[component]
pub fn NetworkTab() -> impl IntoView {
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
            <NetworkAdminContent />
        </Show>
    }
}

#[component]
fn NetworkAdminContent() -> impl IntoView {
    let context = app();
    let status = use_api("/api/v1/admin/network/status".to_string());
    poll_resource(status, 10_000);
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
                        {move || tt(context, "Tabs.networkHeading")}
                    </h2>
                    <div class="flex flex-wrap justify-between gap-4">
                        <p class="text-sm text-slate-400">
                            {move || {
                                status
                                    .data
                                    .with(|v| {
                                        tt_with(context, "{platform} · Runner: {runner} · Observed: {observed}", &[("platform", &(text(v, "platform")).to_string()), ("runner", &(tt(context, match v["runner_available"].as_bool() {
                                                Some(true) => "Available",
                                                Some(false) => "Unavailable",
                                                None => "Not reported",
                                            })).to_string()), ("observed", &(text(v, "checked_at")).to_string())])
                                    })
                            }}
                        </p>
                        <button
                            type="button"
                            class="glass-button px-4 py-2"
                            disabled=move || status.loading.get()
                            on:click=move |_| status.refresh()
                            aria-label=move || tt(context, "Refresh network")
                        >
                            {move || tt(context, "Common.refresh")}
                        </button>
                    </div>
                    <ResourceFeedback resource=status />
                </ObsCard>
                <WireGuardSettings status />
                <TailscaleSettings status />
                <ExternalAccessSettings />
                <NetworkDiagnostics status />
            </Show>
        </section>
    }
}
fn diagnostics_allowed(runner_available: Option<bool>, requested: u64) -> bool {
    runner_available == Some(true) || requested > 0
}
#[component]
fn NetworkDiagnostics(status: ApiResource) -> impl IntoView {
    let context = app();
    let hardware = use_api("/api/v1/auth/system/hardware".to_string());
    let provider = RwSignal::new("wireguard".to_string());
    let diagnostics = ApiResource {
        data: RwSignal::new(Value::Null),
        loading: RwSignal::new(false),
        error: RwSignal::new(None),
        revision: RwSignal::new(0),
    };
    let generation = RwSignal::new(0u64);
    let reads = owned_resource_reads();
    Effect::new(move |_| {
        let auth = context.session_epoch.get();
        let available = crate::tabs::contracts::decode::<crate::tabs::contracts::NetworkStatus>(
            &status.data.get(),
        )
        .runner_available;
        let requested = diagnostics.revision.get();
        let provider = provider.get();
        generation.update(|ticket| *ticket += 1);
        let ticket = generation.get_untracked();
        if !diagnostics_allowed(available, requested) {
            reads.with_value(ResourceReads::cancel);
            diagnostics.loading.set(false);
            diagnostics.error.set(None);
            return;
        }
        diagnostics.loading.set(true);
        let Some(job) = reads.try_update_value(ResourceReads::next) else {
            return;
        };
        let mut busy_guard =
            crate::tabs::busy::BusyGuard::for_generation(diagnostics.loading, generation, ticket);
        spawn_local(async move {
            let path = format!("/api/v1/admin/network/diagnostics?provider={provider}");
            let Some(result) = run_resource_read(job, ApiClient.get(&path)).await else {
                return;
            };
            if generation.try_get_untracked() != Some(ticket)
                || context.session_epoch.try_get_untracked() != Some(auth)
            {
                return;
            }
            match result {
                Ok(data) => {
                    diagnostics.data.set(data);
                    diagnostics.error.set(None);
                }
                Err(error) => diagnostics.error.set(Some(error)),
            }
            busy_guard.release();
        });
    });
    let interfaces = Signal::derive(move || {
        serde_json::to_value(crate::tabs::contracts::hardware(&hardware.data.get()).network)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
    });
    view! {
        <ObsCard title="Interfaces, firewall & DNS diagnostics">
            <div class="flex flex-wrap gap-3 items-end mb-5">
                <label class="text-sm space-y-2">
                    <span>{move || tt(context, "VPN diagnostic provider")}</span>
                    <select
                        class="glass-input px-3 py-2 block"
                        prop:value=move || provider.get()
                        on:change=move |event| provider.set(event_target_value(&event))
                    >
                        <option value="wireguard">{move || tt(context, "WireGuard")}</option>
                        <option value="tailscale">{move || tt(context, "Tailscale")}</option>
                    </select>
                </label>
                <button
                    type="button"
                    class="glass-button px-4 py-2"
                    disabled=move || diagnostics.loading.get()
                    on:click=move |_| {
                        diagnostics.refresh();
                        hardware.refresh();
                    }
                >
                    {move || tt(context, "Run diagnostics")}
                </button>
            </div>
            <Show when=move || {
                crate::tabs::contracts::decode::<
                    crate::tabs::contracts::NetworkStatus,
                >(&status.data.get())
                    .runner_available != Some(true)
            }>
                <p
                    role="status"
                    class="rounded-xl border border-sky-400/20 bg-sky-400/5 p-4 text-sm text-slate-400"
                >
                    {move || tt(
                        context,
                        "Live VPN daemon diagnostics require aetherflow-runner. Start the runner or choose Run diagnostics to request a check.",
                    )}
                </p>
            </Show>
            <ResourceFeedback resource=hardware />
            <ResourceFeedback resource=diagnostics />
            <DataGrid
                label="Host network adapters"
                rows=interfaces
                columns=vec![
                    GridColumn::new("name", "Interface"),
                    GridColumn::new("mac", "MAC"),
                    GridColumn::new("vendor", "Vendor"),
                    GridColumn::new("product", "Adapter"),
                ]
            />
            <DataGrid
                label="Firewall and connectivity checks"
                rows=Signal::derive(move || {
                    diagnostics.data.get()["checks"].as_array().cloned().unwrap_or_default()
                })
                columns=vec![
                    GridColumn::new("name", "Check"),
                    GridColumn::new("ok", "Passed"),
                    GridColumn::new("detail", "Result"),
                ]
            />
            <p class="text-sm text-slate-400 mt-4">
                {move || {
                    status
                        .data
                        .with(|v| {
                            tt_with(context, "WireGuard UDP binding: {port} · Client DNS resolvers are configured in the one-time peer configuration.", &[("port", &(text(&v["wireguard"], "listen_port")).to_string())])
                        })
                }}
            </p>
            <p class="text-xs text-slate-400 mt-3">
                {move || tt(
                    context,
                    "Host interface IP inventory, resolver inventory, firewall rules, and all listening port bindings are not exposed by this API. The adapter report and diagnostic checks show observed hardware, VPN connectivity, and forwarding state.",
                )}
            </p>
            <pre class="text-xs whitespace-pre-wrap break-all max-h-72 overflow-auto mt-5">
                {move || diagnostics.data.with(|v| text(v, "logs"))}
            </pre>
        </ObsCard>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_remain_lazy_without_a_runner_or_an_explicit_request() {
        assert!(!diagnostics_allowed(None, 0));
        assert!(!diagnostics_allowed(Some(false), 0));
        assert!(diagnostics_allowed(Some(true), 0));
        assert!(diagnostics_allowed(Some(false), 1));
        assert!(diagnostics_allowed(None, 1));
    }
    #[test]
    fn unconfigured_wireguard_has_readable_placeholders() {
        for value in [
            Value::Null,
            json!({"listen_port":"","addresses":[],"public_key":""}),
            json!({"listen_port":0,"address":[],"public_key":" "}),
        ] {
            assert_eq!(wireguard_listen(&value), "Not configured");
            assert_eq!(wireguard_addresses(&value), "None assigned");
            assert_eq!(wireguard_public_key(&value), "Not generated");
        }
        let configured = json!({"listen_port":51820,"addresses":["10.0.0.1/24","fd00::1/64"],"public_key":"server-key"});
        assert_eq!(wireguard_listen(&configured), "51820 / UDP");
        assert_eq!(wireguard_addresses(&configured), "10.0.0.1/24, fd00::1/64");
        assert_eq!(
            wireguard_addresses(&json!({"address":"10.1.0.1/24"})),
            "10.1.0.1/24"
        );
        assert_eq!(wireguard_public_key(&configured), "server-key");
    }

    #[test]
    fn tailscale_login_links_and_ingress_domains_are_validated() {
        assert!(safe_login_url("https://login.tailscale.com/a/abcdef"));
        for input in [
            "http://login.tailscale.com/a/abc",
            "https://login.tailscale.com.evil.test/a/abc",
            "https://user@login.tailscale.com/a/abc",
            "https://login.tailscale.com:8443/a/abc",
            "https://login.tailscale.com/a/",
        ] {
            assert!(!safe_login_url(input), "{input}");
        }
        assert!(valid_domain("media.example.com"));
        assert!(!valid_domain("-media.example.com"));
        assert!(!valid_domain("media..example.com"));
    }

    #[test]
    fn peer_export_requires_server_identity_and_explicit_split_routes() {
        let peer = json!({"allowed_ips":"10.0.0.2/32"});
        let server = json!({"wireguard":{"public_key":"server-key"}});
        let sent = json!({"tunnel":"full_ipv4","client_endpoint":"vpn.example.com:51820","dns":"1.1.1.1","keepalive":"25"});
        let config = client_config(&sent, &peer, "client-private", &server).unwrap();
        assert!(config.contains("Address = 10.0.0.2/32"));
        assert!(config.contains("AllowedIPs = 0.0.0.0/0"));
        assert!(!config.contains("::/0"));
        assert!(client_config(&sent, &peer, "", &server).is_err());
        assert!(client_config(&sent, &peer, "client-private", &json!({})).is_err());
        let split = json!({"tunnel":"split","split":"","client_endpoint":"vpn.example.com:51820"});
        assert!(client_config(&split, &peer, "client-private", &server).is_err());
    }
}
