//! Peer list projection, direction/access formatting, endpoint editing, and revocation consent.

use super::grants::GrantEditorModal;
use super::{
    copy_text_to_clipboard, format_countdown, peer_api_request, peer_endpoint_path,
    peer_revoke_path, CompletionScope, DialogGate, PeerApiError, PeerErrorAlert,
};
use crate::state::app;
use crate::tabs::l10n::{tt, tt_with, Badge, Drawer, EmptyState, Modal, ObsCard};
use af_web_core::i18n::{translate, translate_with};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessLevel {
    #[default]
    None,
    Read,
    Write,
}

impl AccessLevel {
    pub const fn allows_read(self) -> bool {
        matches!(self, Self::Read | Self::Write)
    }

    pub const fn allows_write(self) -> bool {
        matches!(self, Self::Write)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessMapView {
    pub services: AccessLevel,
    pub marketplace: AccessLevel,
    pub settings: AccessLevel,
    pub files: AccessLevel,
    pub users: AccessLevel,
    pub network: AccessLevel,
    pub updates: AccessLevel,
    pub transcoding: AccessLevel,
}

impl AccessMapView {
    pub const fn areas(&self) -> [(&'static str, AccessLevel); 8] {
        [
            ("Cluster.areaServices", self.services),
            ("Cluster.areaMarketplace", self.marketplace),
            ("Cluster.areaSettings", self.settings),
            ("Cluster.areaFiles", self.files),
            ("Cluster.areaUsers", self.users),
            ("Cluster.areaNetwork", self.network),
            ("Cluster.areaUpdates", self.updates),
            ("Cluster.areaTranscoding", self.transcoding),
        ]
    }

    pub const fn has_any_access(&self) -> bool {
        self.services.allows_read()
            || self.marketplace.allows_read()
            || self.settings.allows_read()
            || self.files.allows_read()
            || self.users.allows_read()
            || self.network.allows_read()
            || self.updates.allows_read()
            || self.transcoding.allows_read()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GrantSummaryView {
    pub id: String,
    pub run_as_user_id: i64,
    pub access: AccessMapView,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LinkGrantsView {
    pub inbound: Option<GrantSummaryView>,
    pub outbound: Option<GrantSummaryView>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerIdentityView {
    pub wg_pubkey: String,
    pub tunnel_ip: String,
    pub wg_port: u16,
    pub listen_port: u16,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PairingWindowSummary {
    pub id: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PairingAttemptView {
    pub id: String,
    pub window_id: Option<String>,
    pub remote_name: Option<String>,
    pub remote_pubkey: Option<String>,
    pub remote_tunnel_ip: Option<String>,
    pub remote_endpoint: Option<String>,
    pub source_ip: Option<String>,
    pub status: String,
    pub comparison_code: Option<String>,
    pub expires_at: i64,
    pub created_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectedEndpointView {
    pub interface: String,
    pub address: String,
    pub family: String,
    pub recommended: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerLinkView {
    pub id: String,
    pub name: String,
    pub wg_pubkey: String,
    pub tunnel_ip: String,
    pub endpoint: String,
    pub wg_port: u16,
    pub state: String,
    pub peer_version: Option<String>,
    pub peer_protocol: Option<i64>,
    pub capabilities: Vec<String>,
    pub compatibility: String,
    pub missing_capabilities: Vec<String>,
    pub rtt_ms: Option<f64>,
    pub high_latency: bool,
    pub last_ok_at: Option<String>,
    pub last_error: Option<String>,
    pub consecutive_failures: i64,
    pub pending_attempt_id: Option<String>,
    pub pending_expires_at: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
    pub grants: LinkGrantsView,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PeersSnapshot {
    pub identity: Option<PeerIdentityView>,
    pub peer_protocol: i64,
    pub capabilities: Vec<String>,
    pub rtt_warn_ms: f64,
    pub peers: Vec<PeerLinkView>,
    pub pairing_windows: Vec<PairingWindowSummary>,
    pub pairing_attempts: Vec<PairingAttemptView>,
    pub detected_endpoints: Vec<DetectedEndpointView>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UpdateEndpointRequest {
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateEndpointResponse {
    pub peer: PeerLinkView,
    pub updated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokePeerResponse {
    pub revoked: bool,
    pub link_id: String,
    pub name: String,
    pub notice_delivered: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeMode {
    ActiveOrDown,
    Pending,
    AlreadyRevoked,
}

pub fn is_unlinked_empty_state(snapshot: &PeersSnapshot) -> bool {
    snapshot.identity.is_none()
        && snapshot.peers.is_empty()
        && snapshot.pairing_windows.is_empty()
        && snapshot.pairing_attempts.is_empty()
}

pub fn endpoint_display(endpoint: &str, wg_port: u16) -> String {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.contains(':') && !trimmed.starts_with('[') {
        format!("[{trimmed}]:{wg_port}")
    } else {
        format!("{trimmed}:{wg_port}")
    }
}

pub fn status_presentation(state: &str) -> (&'static str, &'static str) {
    match state {
        "active" => ("Cluster.statusHealthy", "success"),
        "pending" => ("Cluster.statusPending", "warning"),
        "down" => ("Cluster.statusDown", "danger"),
        "revoked" => ("Cluster.statusRevoked", "danger"),
        _ => ("Unknown", "muted"),
    }
}

pub fn compatibility_presentation(compatibility: &str) -> (&'static str, &'static str) {
    match compatibility {
        "compatible" => ("Cluster.compatCompatible", "success"),
        "limited" => ("Cluster.compatLimited", "warning"),
        "incompatible" => ("Cluster.compatIncompatible", "danger"),
        _ => ("Unknown", "muted"),
    }
}

pub fn compatibility_guidance(locale: &str, peer: &PeerLinkView) -> Option<String> {
    match peer.compatibility.as_str() {
        "limited" => {
            if peer.missing_capabilities.is_empty() {
                Some(translate_with(
                    locale,
                    "Cluster.compatLimitedGeneric",
                    &[("peer", &peer.name)],
                ))
            } else {
                let caps = peer.missing_capabilities.join(", ");
                Some(translate_with(
                    locale,
                    "Cluster.compatLimitedHint",
                    &[("peer", &peer.name), ("caps", &caps)],
                ))
            }
        }
        "incompatible" => Some(translate_with(
            locale,
            "Cluster.compatIncompatibleHint",
            &[("peer", &peer.name)],
        )),
        _ => None,
    }
}

pub fn format_rtt(locale: &str, rtt_ms: Option<f64>) -> String {
    match rtt_ms {
        Some(value) if value.is_finite() && value >= 0.0 => format!("{value:.1} ms"),
        _ => translate(locale, "Not reported"),
    }
}

pub fn format_version(locale: &str, version: Option<&str>, protocol: Option<i64>) -> String {
    let clean_version = version.map(str::trim).filter(|text| !text.is_empty());
    match (clean_version, protocol) {
        (Some(ver), Some(proto)) => translate_with(
            locale,
            "Cluster.versionWithProtocol",
            &[("version", ver), ("protocol", &proto.to_string())],
        ),
        (Some(ver), None) => ver.to_string(),
        (None, Some(proto)) => translate_with(
            locale,
            "Cluster.protocolOnly",
            &[("protocol", &proto.to_string())],
        ),
        (None, None) => translate(locale, "Not reported"),
    }
}

pub fn summarize_access_map(locale: &str, access: &AccessMapView) -> String {
    let areas = access.areas();
    if areas.iter().all(|(_, level)| level.allows_write()) {
        return translate(locale, "Cluster.accessReadWriteAll");
    }
    if areas.iter().all(|(_, level)| *level == AccessLevel::Read) {
        return translate(locale, "Cluster.accessReadOnlyAll");
    }
    let write_areas: Vec<String> = areas
        .iter()
        .filter(|(_, level)| level.allows_write())
        .map(|(key, _)| translate(locale, key))
        .collect();
    let read_areas: Vec<String> = areas
        .iter()
        .filter(|(_, level)| *level == AccessLevel::Read)
        .map(|(key, _)| translate(locale, key))
        .collect();
    match (write_areas.is_empty(), read_areas.is_empty()) {
        (true, true) => translate(locale, "Cluster.accessNone"),
        (false, true) => translate_with(
            locale,
            "Cluster.accessReadWriteAreas",
            &[("areas", &write_areas.join(", "))],
        ),
        (true, false) => translate_with(
            locale,
            "Cluster.accessReadOnlyAreas",
            &[("areas", &read_areas.join(", "))],
        ),
        (false, false) => translate_with(
            locale,
            "Cluster.accessMixedAreas",
            &[
                ("write", &write_areas.join(", ")),
                ("read", &read_areas.join(", ")),
            ],
        ),
    }
}

/// Expresses link direction in plain language using the actual API grant contract:
/// links are bidirectional WireGuard tunnels while management access is granted separately
/// in each direction (`grants.inbound` = peer can manage this server, `grants.outbound` = this
/// server can manage peer).
pub fn direction_summary_for_grants(
    locale: &str,
    peer_name: &str,
    grants: &LinkGrantsView,
) -> String {
    let outbound = grants
        .outbound
        .as_ref()
        .filter(|grant| grant.access.has_any_access())
        .map(|grant| summarize_access_map(locale, &grant.access));
    let inbound = grants
        .inbound
        .as_ref()
        .filter(|grant| grant.access.has_any_access())
        .map(|grant| summarize_access_map(locale, &grant.access));

    match (outbound, inbound) {
        (Some(out_sum), Some(in_sum)) => translate_with(
            locale,
            "Cluster.directionTwoWay",
            &[
                ("peer", peer_name),
                ("outbound", &out_sum),
                ("inbound", &in_sum),
            ],
        ),
        (Some(out_sum), None) => translate_with(
            locale,
            "Cluster.directionOutboundOnly",
            &[("peer", peer_name), ("outbound", &out_sum)],
        ),
        (None, Some(in_sum)) => translate_with(
            locale,
            "Cluster.directionInboundOnly",
            &[("peer", peer_name), ("inbound", &in_sum)],
        ),
        (None, None) => translate(locale, "Cluster.directionBidirectionalNoGrants"),
    }
}

pub fn direction_summary(locale: &str, peer: &PeerLinkView) -> String {
    direction_summary_for_grants(locale, &peer.name, &peer.grants)
}

pub fn access_summary(locale: &str, peer: &PeerLinkView) -> String {
    let mut parts = Vec::new();
    if let Some(grant) = peer
        .grants
        .outbound
        .as_ref()
        .filter(|grant| grant.access.has_any_access())
    {
        parts.push(translate_with(
            locale,
            "Cluster.accessOutboundLabel",
            &[
                ("peer", &peer.name),
                ("summary", &summarize_access_map(locale, &grant.access)),
            ],
        ));
    }
    if let Some(grant) = peer
        .grants
        .inbound
        .as_ref()
        .filter(|grant| grant.access.has_any_access())
    {
        parts.push(translate_with(
            locale,
            "Cluster.accessInboundLabel",
            &[
                ("peer", &peer.name),
                ("summary", &summarize_access_map(locale, &grant.access)),
            ],
        ));
    }
    if parts.is_empty() {
        translate(locale, "Cluster.accessNoGrants")
    } else {
        parts.join(" · ")
    }
}

pub fn can_edit_endpoint(state: &str) -> bool {
    state != "revoked"
}

pub(super) fn supports_grant_delivery(peer: &PeerLinkView) -> bool {
    peer.compatibility != "incompatible"
        && !peer.missing_capabilities.iter().any(|cap| cap == "grants")
}

pub fn can_manage_grants(peer: &PeerLinkView) -> bool {
    let has_grant = peer.grants.inbound.is_some() || peer.grants.outbound.is_some();
    match peer.state.as_str() {
        "active" => supports_grant_delivery(peer) || has_grant,
        "down" => has_grant,
        _ => false,
    }
}

pub fn revoke_dialog_mode(state: &str) -> RevokeMode {
    match state {
        "pending" => RevokeMode::Pending,
        "revoked" => RevokeMode::AlreadyRevoked,
        _ => RevokeMode::ActiveOrDown,
    }
}

pub fn revoke_consequence_keys(mode: RevokeMode) -> &'static [&'static str] {
    match mode {
        RevokeMode::ActiveOrDown => &[
            "Cluster.revokeEffect1",
            "Cluster.revokeEffect2",
            "Cluster.revokeEffect3",
            "Cluster.revokeEffect4",
        ],
        RevokeMode::Pending => &[
            "Cluster.revokePendingEffect1",
            "Cluster.revokePendingEffect2",
        ],
        RevokeMode::AlreadyRevoked => &[
            "Cluster.revokeAlreadyEffect1",
            "Cluster.revokeAlreadyEffect2",
        ],
    }
}

pub fn build_update_endpoint_request(
    endpoint: &str,
    port_input: &str,
) -> Result<UpdateEndpointRequest, &'static str> {
    let trimmed_endpoint = endpoint.trim();
    if trimmed_endpoint.is_empty()
        || trimmed_endpoint
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err("Cluster.validationEndpointRequired");
    }
    let trimmed_port = port_input.trim();
    let wg_port = if trimmed_port.is_empty() {
        None
    } else {
        let port = trimmed_port
            .parse::<u16>()
            .ok()
            .filter(|&port| port > 0)
            .ok_or("Cluster.validationPortInvalid")?;
        Some(port)
    };
    Ok(UpdateEndpointRequest {
        endpoint: trimmed_endpoint.to_string(),
        wg_port,
    })
}

#[component]
pub fn PeerListSection(
    peers: Signal<Vec<PeerLinkView>>,
    rtt_warn_ms: Signal<f64>,
    now_secs: RwSignal<i64>,
    loaded: Signal<bool>,
    on_refresh: Callback<()>,
) -> impl IntoView {
    let context = app();
    let edit_target = RwSignal::new(None::<PeerLinkView>);
    let edit_open = RwSignal::new(false);
    let grant_target = RwSignal::new(None::<PeerLinkView>);
    let grant_open = RwSignal::new(false);
    let revoke_target = RwSignal::new(None::<PeerLinkView>);
    let revoke_open = RwSignal::new(false);
    let detail_target = RwSignal::new(None::<PeerLinkView>);
    let detail_open = RwSignal::new(false);

    Effect::new(move |_| {
        let latest = peers.get();
        if let Some(selected) = detail_target.get_untracked() {
            if let Some(updated) = latest.iter().find(|p| p.id == selected.id).cloned() {
                detail_target.set(Some(updated));
            } else {
                detail_open.set(false);
                detail_target.set(None);
            }
        }
        if let Some(selected) = grant_target.get_untracked() {
            let updated = latest.into_iter().find(|peer| {
                peer.id == selected.id && matches!(peer.state.as_str(), "active" | "down")
            });
            if updated.is_none() {
                grant_open.set(false);
            }
            grant_target.set(updated);
        }
    });

    let peer_ids = Memo::new(move |_| {
        peers.with(|list| list.iter().map(|peer| peer.id.clone()).collect::<Vec<_>>())
    });
    let on_inspect = Callback::new(move |peer: PeerLinkView| {
        detail_target.set(Some(peer));
        detail_open.set(true);
    });
    let on_manage_grants = Callback::new(move |peer: PeerLinkView| {
        grant_target.set(Some(peer));
        grant_open.set(true);
    });
    let on_edit = Callback::new(move |peer: PeerLinkView| {
        edit_target.set(Some(peer));
        edit_open.set(true);
    });
    let on_revoke = Callback::new(move |peer: PeerLinkView| {
        revoke_target.set(Some(peer));
        revoke_open.set(true);
    });

    view! {
        <ObsCard>
            <Show
                when=move || !peers.with(Vec::is_empty)
                fallback=move || {
                    view! {
                        <Show when=move || loaded.get()>
                            <EmptyState
                                title="Cluster.emptyTitle"
                                description="Cluster.emptyDescription"
                            />
                        </Show>
                    }
                }
            >
                <div
                    role="list"
                    aria-label=move || tt(context, "Cluster.peerListLabel")
                    class="space-y-4"
                >
                    <For
                        each=move || peer_ids.get()
                        key=|id| id.clone()
                        children=move |peer_id| {
                            view! {
                                <PeerRowCard
                                    peer_id=peer_id
                                    peers=peers
                                    rtt_warn_ms=rtt_warn_ms
                                    now_secs=now_secs
                                    on_inspect=on_inspect
                                    on_manage_grants=on_manage_grants
                                    on_edit=on_edit
                                    on_revoke=on_revoke
                                />
                            }
                        }
                    />
                </div>
            </Show>

            <GrantEditorModal
                open=grant_open
                target=grant_target
                on_refresh=on_refresh
            />
            <EditEndpointModal
                open=edit_open
                target=edit_target
                on_refresh=on_refresh
            />
            <RevokeLinkModal
                open=revoke_open
                target=revoke_target
                on_refresh=on_refresh
            />
            <PeerDetailsDrawer
                open=detail_open
                target=detail_target
                now_secs=now_secs
            />
        </ObsCard>
    }
}

#[component]
fn PeerRowCard(
    peer_id: String,
    peers: Signal<Vec<PeerLinkView>>,
    rtt_warn_ms: Signal<f64>,
    now_secs: RwSignal<i64>,
    on_inspect: Callback<PeerLinkView>,
    on_manage_grants: Callback<PeerLinkView>,
    on_edit: Callback<PeerLinkView>,
    on_revoke: Callback<PeerLinkView>,
) -> impl IntoView {
    let context = app();
    let peer_id = StoredValue::new(peer_id);
    let peer = Memo::new(move |_| {
        peer_id.with_value(|id| peers.with(|list| list.iter().find(|p| p.id == *id).cloned()))
    });
    let status_badge = Memo::new(move |_| {
        peer.with(|p| {
            p.as_ref()
                .map(|p| status_presentation(&p.state))
                .unwrap_or(("Unknown", "muted"))
        })
    });
    let compat_badge = Memo::new(move |_| {
        peer.with(|p| {
            p.as_ref()
                .map(|p| compatibility_presentation(&p.compatibility))
                .unwrap_or(("Unknown", "muted"))
        })
    });
    let grants_manageable =
        Memo::new(move |_| peer.with(|p| p.as_ref().is_some_and(can_manage_grants)));
    let editable =
        Memo::new(move |_| peer.with(|p| p.as_ref().is_some_and(|p| can_edit_endpoint(&p.state))));
    let revoke_mode = Memo::new(move |_| {
        peer.with(|p| {
            p.as_ref()
                .map(|p| revoke_dialog_mode(&p.state))
                .unwrap_or(RevokeMode::ActiveOrDown)
        })
    });
    let pending_expires = Memo::new(move |_| {
        peer.with(|p| {
            p.as_ref()
                .and_then(|p| p.pending_expires_at.filter(|_| p.state == "pending"))
        })
    });

    view! {
        <article
            role="listitem"
            class="rounded-xl border border-white/10 bg-white/5 p-4 space-y-4 min-w-0"
        >
            <div class="flex flex-wrap items-start justify-between gap-3">
                <div class="space-y-1 min-w-0">
                    <div class="flex flex-wrap items-center gap-2">
                        <h3 class="text-base font-semibold break-all">
                            {move || {
                                peer.with(|p| p.as_ref().map(|p| p.name.clone()).unwrap_or_default())
                            }}
                        </h3>
                        {move || {
                            let (label, tone) = status_badge.get();
                            view! { <Badge label=label tone=tone /> }
                        }}
                        {move || {
                            let (label, tone) = compat_badge.get();
                            view! { <Badge label=label tone=tone /> }
                        }}
                    </div>
                    <p class="text-xs font-mono text-slate-400 break-all">
                        {move || {
                            peer.with(|p| {
                                p.as_ref()
                                    .map(|p| {
                                        format!(
                                            "{} · {}",
                                            endpoint_display(&p.endpoint, p.wg_port),
                                            p.tunnel_ip
                                        )
                                    })
                                    .unwrap_or_default()
                            })
                        }}
                    </p>
                </div>
                <div class="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                        type="button"
                        class="glass-button px-3 py-1.5 text-sm"
                        aria-label=move || {
                            let name = peer.with(|p| {
                                p.as_ref().map(|p| p.name.clone()).unwrap_or_default()
                            });
                            tt_with(context, "Cluster.inspectPeerAria", &[("peer", &name)])
                        }
                        on:click=move |_| {
                            if let Some(current) = peer.get_untracked() {
                                on_inspect.run(current);
                            }
                        }
                    >
                        {move || tt(context, "Cluster.inspectPeer")}
                    </button>
                    <Show when=move || grants_manageable.get()>
                        <button
                            type="button"
                            class="glass-button px-3 py-1.5 text-sm"
                            aria-label=move || {
                                let name = peer.with(|p| {
                                    p.as_ref().map(|p| p.name.clone()).unwrap_or_default()
                                });
                                tt_with(context, "Cluster.manageGrantsAria", &[("peer", &name)])
                            }
                            on:click=move |_| {
                                if let Some(current) = peer.get_untracked() {
                                    on_manage_grants.run(current);
                                }
                            }
                        >
                            {move || tt(context, "Cluster.manageGrantsAction")}
                        </button>
                    </Show>
                    {move || {
                        let current = peer.get();
                        let current_peer = current?;
                        let id = current_peer.id.clone();
                        let is_active = context.active_server_id.get().as_deref() == Some(id.as_str());
                        let eligibility = crate::state::peer_switch_eligibility(&current_peer);
                        let disabled = is_active || eligibility.is_err();
                        let title = match eligibility {
                            Ok(()) => String::new(),
                            Err(key) => tt(context, key),
                        };
                        let label = if is_active {
                            tt(context, "PeerSwitch.currentlyManaging")
                        } else {
                            tt(context, "PeerSwitch.manageServer")
                        };
                        Some(view! {
                            <button
                                type="button"
                                class=if is_active {
                                    "glass-button px-3 py-1.5 text-sm text-cyan-200 border-cyan-500/30"
                                } else {
                                    "glass-button-primary px-3 py-1.5 text-sm disabled:opacity-50"
                                }
                                data-testid=format!("peer-manage-{}", id)
                                data-active=is_active.to_string()
                                disabled=disabled
                                title=title
                                on:click=move |_| {
                                    let _ = context.select_server(Some(id.clone()));
                                }
                            >
                                {label}
                            </button>
                        })
                    }}
                    <Show when=move || editable.get()>
                        <button
                            type="button"
                            class="glass-button px-3 py-1.5 text-sm"
                            aria-label=move || {
                                let name = peer.with(|p| {
                                    p.as_ref().map(|p| p.name.clone()).unwrap_or_default()
                                });
                                tt_with(context, "Cluster.editEndpointAria", &[("peer", &name)])
                            }
                            on:click=move |_| {
                                if let Some(current) = peer.get_untracked() {
                                    on_edit.run(current);
                                }
                            }
                        >
                            {move || tt(context, "Cluster.editEndpointAction")}
                        </button>
                    </Show>
                    <button
                        type="button"
                        class="glass-button px-3 py-1.5 text-sm"
                        data-tone="danger"
                        aria-label=move || {
                            let name = peer.with(|p| {
                                p.as_ref().map(|p| p.name.clone()).unwrap_or_default()
                            });
                            let key = match revoke_mode.get() {
                                RevokeMode::ActiveOrDown => "Cluster.revokeLinkAria",
                                RevokeMode::Pending => "Cluster.cancelPendingLinkAria",
                                RevokeMode::AlreadyRevoked => "Cluster.removeRevokedLinkAria",
                            };
                            tt_with(context, key, &[("peer", &name)])
                        }
                        on:click=move |_| {
                            if let Some(current) = peer.get_untracked() {
                                on_revoke.run(current);
                            }
                        }
                    >
                        {move || {
                            let key = match revoke_mode.get() {
                                RevokeMode::ActiveOrDown => "Cluster.revokeLinkAction",
                                RevokeMode::Pending => "Cluster.cancelPendingLinkAction",
                                RevokeMode::AlreadyRevoked => "Cluster.removeRevokedLinkAction",
                            };
                            tt(context, key)
                        }}
                    </button>
                </div>
            </div>

            <dl class="grid sm:grid-cols-2 lg:grid-cols-3 gap-3 text-sm">
                <div class="space-y-0.5 min-w-0">
                    <dt class="text-xs text-slate-400">
                        {move || tt(context, "Cluster.colDirection")}
                    </dt>
                    <dd class="text-slate-200 break-words">
                        {move || {
                            let locale = crate::tabs::l10n::locale(context);
                            peer.with(|p| {
                                p.as_ref()
                                    .map(|p| direction_summary(&locale, p))
                                    .unwrap_or_default()
                            })
                        }}
                    </dd>
                </div>
                <div class="space-y-0.5 min-w-0">
                    <dt class="text-xs text-slate-400">
                        {move || tt(context, "Cluster.colAccess")}
                    </dt>
                    <dd class="text-slate-200 break-words">
                        {move || {
                            let locale = crate::tabs::l10n::locale(context);
                            peer.with(|p| {
                                p.as_ref()
                                    .map(|p| access_summary(&locale, p))
                                    .unwrap_or_default()
                            })
                        }}
                    </dd>
                </div>
                <div class="space-y-0.5 min-w-0">
                    <dt class="text-xs text-slate-400">
                        {move || tt(context, "Cluster.colStatus")}
                    </dt>
                    <dd class="text-slate-200 break-words">
                        {move || tt(context, status_badge.get().0)}
                        {move || {
                            pending_expires.get().map(|exp| {
                                view! {
                                    <span
                                        aria-live="off"
                                        class="text-xs text-amber-300 ml-2 font-mono"
                                    >
                                        {move || {
                                            let loc = crate::tabs::l10n::locale(context);
                                            format_countdown(&loc, exp, now_secs.get()).0
                                        }}
                                    </span>
                                }
                            })
                        }}
                    </dd>
                </div>
                <div class="space-y-0.5 min-w-0">
                    <dt class="text-xs text-slate-400">
                        {move || tt(context, "Cluster.colRtt")}
                    </dt>
                    <dd class="text-slate-200 font-mono">
                        {move || {
                            let locale = crate::tabs::l10n::locale(context);
                            peer.with(|p| {
                                p.as_ref()
                                    .map(|p| format_rtt(&locale, p.rtt_ms))
                                    .unwrap_or_default()
                            })
                        }}
                        {move || {
                            let threshold = rtt_warn_ms.get();
                            let locale = crate::tabs::l10n::locale(context);
                            peer.with(|p| {
                                p.as_ref().filter(|p| p.high_latency).map(|_| {
                                    translate_with(
                                        &locale,
                                        "Cluster.highLatencyWarning",
                                        &[("threshold", &format!("{threshold:.0}"))],
                                    )
                                })
                            })
                            .map(|warn| {
                                view! {
                                    <span class="block text-xs font-sans text-amber-300 mt-0.5">
                                        {warn}
                                    </span>
                                }
                            })
                        }}
                    </dd>
                </div>
                <div class="space-y-0.5 min-w-0">
                    <dt class="text-xs text-slate-400">
                        {move || tt(context, "Cluster.colVersion")}
                    </dt>
                    <dd class="text-slate-200 break-words">
                        {move || {
                            let locale = crate::tabs::l10n::locale(context);
                            peer.with(|p| {
                                p.as_ref()
                                    .map(|p| {
                                        format_version(
                                            &locale,
                                            p.peer_version.as_deref(),
                                            p.peer_protocol,
                                        )
                                    })
                                    .unwrap_or_default()
                            })
                        }}
                    </dd>
                </div>
                <div class="space-y-0.5 min-w-0">
                    <dt class="text-xs text-slate-400">
                        {move || tt(context, "Cluster.colCompatibility")}
                    </dt>
                    <dd class="text-slate-200 break-words">
                        {move || tt(context, compat_badge.get().0)}
                        {move || {
                            let locale = crate::tabs::l10n::locale(context);
                            peer.with(|p| {
                                p.as_ref().and_then(|p| compatibility_guidance(&locale, p))
                            })
                            .map(|hint| {
                                view! {
                                    <span class="block text-xs text-amber-300 mt-0.5">
                                        {hint}
                                    </span>
                                }
                            })
                        }}
                    </dd>
                </div>
            </dl>

            {move || {
                peer.with(|p| {
                    p.as_ref()
                        .and_then(|p| p.last_error.clone())
                        .filter(|msg| !msg.trim().is_empty())
                })
                .map(|err_msg| {
                    view! {
                        <p
                            role="status"
                            class="af-danger-banner text-xs break-words"
                        >
                            <span class="font-semibold">
                                {move || tt(context, "Cluster.lastErrorLabel")}
                            </span>
                            ": "
                            {err_msg}
                        </p>
                    }
                })
            }}
        </article>
    }
}

#[component]
pub fn EditEndpointModal(
    open: RwSignal<bool>,
    target: RwSignal<Option<PeerLinkView>>,
    on_refresh: Callback<()>,
) -> impl IntoView {
    let context = app();
    let endpoint_input = RwSignal::new(String::new());
    let port_input = RwSignal::new(String::new());
    let error = RwSignal::new(None::<PeerApiError>);
    let gate = DialogGate::new();
    let last_session =
        StoredValue::new((false, None::<String>, context.session_epoch.get_untracked()));

    Effect::new(move |_| {
        let is_open = open.get();
        let epoch = context.session_epoch.get();
        let target_id = if is_open {
            target.with(|peer| peer.as_ref().map(|p| p.id.clone()))
        } else {
            None
        };
        let next_session = (is_open, target_id, epoch);
        if last_session.get_value() == next_session {
            return;
        }
        last_session.set_value(next_session);
        gate.reset();
        error.set(None);
        if is_open {
            if let Some(peer) = target.get_untracked() {
                endpoint_input.set(peer.endpoint);
                port_input.set(peer.wg_port.to_string());
            } else {
                endpoint_input.set(String::new());
                port_input.set(String::new());
            }
        }
    });

    let submit = move || {
        if gate.is_busy_untracked() || !context.is_admin() {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        let req = match build_update_endpoint_request(
            &endpoint_input.get_untracked(),
            &port_input.get_untracked(),
        ) {
            Ok(req) => req,
            Err(key) => {
                error.set(Some(PeerApiError::client(tt(context, key))));
                return;
            }
        };
        let body = match serde_json::to_value(&req) {
            Ok(val) => val,
            Err(err) => {
                error.set(Some(PeerApiError::client(err.to_string())));
                return;
            }
        };
        let peer_id = peer.id.clone();
        let path = peer_endpoint_path(&peer.id);
        let peer_name = peer.name.clone();
        error.set(None);
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result =
                peer_api_request::<UpdateEndpointResponse>(&path, "PUT", Some(&body)).await;
            match gate.classify(context.session_epoch, open, token, || {
                target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession => return,
                CompletionScope::StaleDialog => {
                    if result.is_ok() {
                        on_refresh.run(());
                    }
                    return;
                }
                CompletionScope::CurrentDialog => {}
            }
            busy_guard.release();
            match result {
                Ok(_) => {
                    open.set(false);
                    on_refresh.run(());
                    context.toast_with(
                        "Cluster.endpointUpdatedToast",
                        &[("peer", &peer_name)],
                        false,
                    );
                }
                Err(api_err) => {
                    // Retain entered endpoint and port so the operator can correct and retry.
                    error.set(Some(api_err));
                }
            }
        });
    };

    let modal_title = Signal::derive(move || {
        let name = target.get().map(|peer| peer.name).unwrap_or_default();
        tt_with(context, "Cluster.editEndpointTitle", &[("peer", &name)])
    });

    view! {
        <Modal open=open title=modal_title>
            <form
                class="space-y-4"
                on:submit=move |event| {
                    event.prevent_default();
                    submit();
                }
            >
                <p class="text-sm text-slate-300 font-mono break-all">
                    {move || {
                        target
                            .get()
                            .map(|peer| {
                                let current = endpoint_display(&peer.endpoint, peer.wg_port);
                                tt_with(
                                    context,
                                    "Cluster.editEndpointCurrent",
                                    &[("endpoint", &current)],
                                )
                            })
                            .unwrap_or_default()
                    }}
                </p>

                <div class="af-warning-banner text-xs space-y-1.5">
                    <p class="font-semibold">
                        {move || tt(context, "Cluster.effectsHeading")}
                    </p>
                    <ul class="list-disc pl-5 space-y-1 text-slate-300">
                        <li>{move || tt(context, "Cluster.editEndpointEffect1")}</li>
                        <li>{move || tt(context, "Cluster.editEndpointEffect2")}</li>
                        <li>{move || tt(context, "Cluster.editEndpointEffect3")}</li>
                    </ul>
                </div>

                <PeerErrorAlert error=error />

                <div class="space-y-1.5">
                    <label for="cluster-edit-endpoint-host" class="block text-sm font-medium text-slate-200">
                        {move || tt(context, "Cluster.endpointHostLabel")}
                    </label>
                    <input
                        id="cluster-edit-endpoint-host"
                        type="text"
                        data-af-autofocus="true"
                        autocomplete="off"
                        required
                        class="glass-input px-3 py-2 w-full"
                        placeholder=move || tt(context, "Cluster.endpointHostPlaceholder")
                        disabled=move || gate.is_busy()
                        prop:value=move || endpoint_input.get()
                        on:input=move |event| endpoint_input.set(event_target_value(&event))
                    />
                </div>

                <div class="space-y-1.5">
                    <label for="cluster-edit-endpoint-port" class="block text-sm font-medium text-slate-200">
                        {move || tt(context, "Cluster.wgPortLabel")}
                    </label>
                    <input
                        id="cluster-edit-endpoint-port"
                        type="number"
                        min="1"
                        max="65535"
                        inputmode="numeric"
                        aria-describedby="cluster-edit-endpoint-port-hint"
                        class="glass-input px-3 py-2 w-full"
                        disabled=move || gate.is_busy()
                        prop:value=move || port_input.get()
                        on:input=move |event| port_input.set(event_target_value(&event))
                    />
                    <p id="cluster-edit-endpoint-port-hint" class="text-xs text-slate-400">
                        {move || tt(context, "Cluster.wgPortHint")}
                    </p>
                </div>

                <div class="flex flex-wrap justify-end gap-3 pt-2">
                    <button
                        type="button"
                        class="glass-button px-4 py-2"
                        disabled=move || gate.is_busy()
                        on:click=move |_| open.set(false)
                    >
                        {move || tt(context, "Common.cancel")}
                    </button>
                    <button
                        type="submit"
                        class="glass-button-primary px-4 py-2"
                        disabled=move || gate.is_busy()
                    >
                        {move || {
                            if gate.is_busy() {
                                tt(context, "Common.saving")
                            } else {
                                tt(context, "Cluster.saveEndpointAction")
                            }
                        }}
                    </button>
                </div>
            </form>
        </Modal>
    }
}

#[component]
pub fn RevokeLinkModal(
    open: RwSignal<bool>,
    target: RwSignal<Option<PeerLinkView>>,
    on_refresh: Callback<()>,
) -> impl IntoView {
    let context = app();
    let error = RwSignal::new(None::<PeerApiError>);
    let gate = DialogGate::new();
    let last_session =
        StoredValue::new((false, None::<String>, context.session_epoch.get_untracked()));

    Effect::new(move |_| {
        let is_open = open.get();
        let epoch = context.session_epoch.get();
        let target_id = if is_open {
            target.with(|peer| peer.as_ref().map(|p| p.id.clone()))
        } else {
            None
        };
        let next_session = (is_open, target_id, epoch);
        if last_session.get_value() == next_session {
            return;
        }
        last_session.set_value(next_session);
        gate.reset();
        error.set(None);
    });

    let confirm_revoke = move || {
        if gate.is_busy_untracked() || !context.is_admin() {
            return;
        }
        let Some(peer) = target.get_untracked() else {
            return;
        };
        let mode = revoke_dialog_mode(&peer.state);
        let peer_id = peer.id.clone();
        let path = peer_revoke_path(&peer.id);
        let peer_name = peer.name.clone();
        error.set(None);
        let (token, mut busy_guard) = gate.begin(context.session_epoch);
        spawn_local(async move {
            let result = peer_api_request::<RevokePeerResponse>(&path, "DELETE", None).await;
            match gate.classify(context.session_epoch, open, token, || {
                target
                    .try_with_untracked(|cur| cur.as_ref().is_some_and(|p| p.id == peer_id))
                    .unwrap_or(false)
            }) {
                CompletionScope::ExpiredSession => return,
                CompletionScope::StaleDialog => {
                    if result.is_ok() {
                        on_refresh.run(());
                    }
                    return;
                }
                CompletionScope::CurrentDialog => {}
            }
            busy_guard.release();
            match result {
                Ok(resp) => {
                    open.set(false);
                    on_refresh.run(());
                    let toast_key = match mode {
                        RevokeMode::Pending => "Cluster.pendingLinkCancelledToast",
                        RevokeMode::AlreadyRevoked => "Cluster.revokedLinkRemovedToast",
                        RevokeMode::ActiveOrDown if resp.notice_delivered => {
                            "Cluster.linkRevokedNoticeToast"
                        }
                        RevokeMode::ActiveOrDown => "Cluster.linkRevokedLocalToast",
                    };
                    context.toast_with(toast_key, &[("peer", &peer_name)], false);
                }
                Err(api_err) => {
                    error.set(Some(api_err));
                }
            }
        });
    };

    let modal_title = Signal::derive(move || {
        let Some(peer) = target.get() else {
            return String::new();
        };
        let key = match revoke_dialog_mode(&peer.state) {
            RevokeMode::ActiveOrDown => "Cluster.revokeTitle",
            RevokeMode::Pending => "Cluster.cancelPendingTitle",
            RevokeMode::AlreadyRevoked => "Cluster.removeRevokedTitle",
        };
        tt_with(context, key, &[("peer", &peer.name)])
    });

    view! {
        <Modal open=open title=modal_title>
            <div class="space-y-4">
                <div class="af-danger-banner space-y-2">
                    <p class="font-semibold">
                        {move || tt(context, "Cluster.revokeEffectsHeading")}
                    </p>
                    <ul class="list-disc pl-5 space-y-1.5 text-slate-200">
                        {move || {
                            let Some(peer) = target.get() else {
                                return Vec::new().collect_view();
                            };
                            let mode = revoke_dialog_mode(&peer.state);
                            revoke_consequence_keys(mode)
                                .iter()
                                .map(|key| {
                                    let peer_name = peer.name.clone();
                                    let key = *key;
                                    view! {
                                        <li>
                                            {move || tt_with(context, key, &[("peer", &peer_name)])}
                                        </li>
                                    }
                                })
                                .collect::<Vec<_>>()
                                .collect_view()
                        }}
                    </ul>
                </div>

                <PeerErrorAlert error=error />

                <div class="flex flex-wrap justify-end gap-3 pt-2">
                    <button
                        type="button"
                        data-af-autofocus="true"
                        class="glass-button px-4 py-2"
                        disabled=move || gate.is_busy()
                        on:click=move |_| open.set(false)
                    >
                        {move || tt(context, "Common.cancel")}
                    </button>
                    <button
                        type="button"
                        class="glass-button px-4 py-2"
                        data-tone="danger"
                        disabled=move || gate.is_busy()
                        on:click=move |_| confirm_revoke()
                    >
                        {move || {
                            let Some(peer) = target.get() else {
                                return tt(context, "Cluster.confirmRevokeAction");
                            };
                            let key = match revoke_dialog_mode(&peer.state) {
                                RevokeMode::ActiveOrDown => "Cluster.confirmRevokeAction",
                                RevokeMode::Pending => "Cluster.confirmCancelPendingAction",
                                RevokeMode::AlreadyRevoked => "Cluster.confirmRemoveRevokedAction",
                            };
                            tt(context, key)
                        }}
                    </button>
                </div>
            </div>
        </Modal>
    }
}

#[component]
pub fn PeerDetailsDrawer(
    open: RwSignal<bool>,
    target: RwSignal<Option<PeerLinkView>>,
    now_secs: RwSignal<i64>,
) -> impl IntoView {
    let context = app();
    let drawer_title = Signal::derive(move || {
        let name = target.get().map(|peer| peer.name).unwrap_or_default();
        tt_with(context, "Cluster.peerDetailsTitle", &[("peer", &name)])
    });

    view! {
        <Drawer open=open title=drawer_title>
            {move || {
                target.get().map(|peer| {
                    let locale = crate::tabs::l10n::locale(context);
                    let pubkey_copy = peer.wg_pubkey.clone();
                    let endpoint = endpoint_display(&peer.endpoint, peer.wg_port);
                    let caps = if peer.capabilities.is_empty() {
                        translate(&locale, "Not reported")
                    } else {
                        peer.capabilities.join(", ")
                    };
                    let last_ok = peer
                        .last_ok_at
                        .clone()
                        .filter(|s| !s.trim().is_empty())
                        .unwrap_or_else(|| translate(&locale, "Not reported"));
                    let pending_exp = peer.pending_expires_at;

                    view! {
                        <div class="space-y-4 text-sm">
                            <dl class="space-y-3">
                                <div>
                                    <dt class="text-xs text-slate-400">
                                        {move || tt(context, "Cluster.colEndpoint")}
                                    </dt>
                                    <dd class="font-mono break-all">{endpoint}</dd>
                                </div>
                                <div>
                                    <dt class="text-xs text-slate-400">
                                        {move || tt(context, "Cluster.colTunnelIp")}
                                    </dt>
                                    <dd class="font-mono break-all">{peer.tunnel_ip.clone()}</dd>
                                </div>
                                <div class="space-y-1.5">
                                    <dt class="text-xs text-slate-400">
                                        {move || tt(context, "Cluster.detailWgPubkey")}
                                    </dt>
                                    <dd class="space-y-2">
                                        <code class="block text-xs break-all p-2.5 rounded-lg bg-white/5 font-mono">
                                            {peer.wg_pubkey.clone()}
                                        </code>
                                        <button
                                            type="button"
                                            class="glass-button px-3 py-1.5 text-xs"
                                            on:click=move |_| {
                                                copy_text_to_clipboard(context, pubkey_copy.clone());
                                            }
                                        >
                                            {move || tt(context, "Cluster.copyPubkey")}
                                        </button>
                                    </dd>
                                </div>
                                <div>
                                    <dt class="text-xs text-slate-400">
                                        {move || tt(context, "Cluster.detailCapabilities")}
                                    </dt>
                                    <dd class="font-mono text-xs break-words">{caps}</dd>
                                </div>
                                <div>
                                    <dt class="text-xs text-slate-400">
                                        {move || tt(context, "Cluster.detailLastHealthy")}
                                    </dt>
                                    <dd class="font-mono text-xs break-all">{last_ok}</dd>
                                </div>
                                <div>
                                    <dt class="text-xs text-slate-400">
                                        {move || tt(context, "Cluster.detailFailures")}
                                    </dt>
                                    <dd class="font-mono text-xs">{peer.consecutive_failures}</dd>
                                </div>
                                {pending_exp.map(|exp| {
                                    view! {
                                        <div>
                                            <dt class="text-xs text-slate-400">
                                                {move || tt(context, "Cluster.detailPendingExpiry")}
                                            </dt>
                                            <dd aria-live="off" class="font-mono text-xs text-amber-300">
                                                {move || {
                                                    let loc = crate::tabs::l10n::locale(context);
                                                    format_countdown(&loc, exp, now_secs.get()).0
                                                }}
                                            </dd>
                                        </div>
                                    }
                                })}
                                <div>
                                    <dt class="text-xs text-slate-400">
                                        {move || tt(context, "Cluster.detailCreatedAt")}
                                    </dt>
                                    <dd class="font-mono text-xs break-all">{peer.created_at.clone()}</dd>
                                </div>
                                <div>
                                    <dt class="text-xs text-slate-400">
                                        {move || tt(context, "Cluster.detailUpdatedAt")}
                                    </dt>
                                    <dd class="font-mono text-xs break-all">{peer.updated_at.clone()}</dd>
                                </div>
                            </dl>
                        </div>
                    }
                })
            }}
        </Drawer>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_empty_unlinked_peers_snapshot_fixture() {
        let payload = json!({
            "identity": null,
            "peer_protocol": 1,
            "capabilities": ["links"],
            "rtt_warn_ms": 25.0,
            "peers": [],
            "pairing_windows": [],
            "pairing_attempts": [],
            "detected_endpoints": [
                {
                    "interface": "eth0",
                    "address": "10.0.0.10",
                    "family": "ipv4",
                    "recommended": true
                }
            ]
        });

        let snapshot: PeersSnapshot = serde_json::from_value(payload).unwrap();
        assert!(is_unlinked_empty_state(&snapshot));
        assert_eq!(snapshot.peer_protocol, 1);
        assert_eq!(snapshot.capabilities, vec!["links"]);
        assert_eq!(snapshot.detected_endpoints.len(), 1);
        assert!(snapshot.detected_endpoints[0].recommended);
    }

    #[test]
    fn parses_full_p3_peers_snapshot_and_public_projections() {
        let payload = json!({
            "identity": {
                "wg_pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "tunnel_ip": "10.231.0.1",
                "wg_port": 51821,
                "listen_port": 9443,
                "created_at": "2026-11-23T10:00:00Z"
            },
            "peer_protocol": 1,
            "capabilities": ["links"],
            "rtt_warn_ms": 25.0,
            "peers": [
                {
                    "id": "link-1",
                    "name": "media-2",
                    "wg_pubkey": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                    "tunnel_ip": "10.231.0.2",
                    "endpoint": "10.0.0.20",
                    "wg_port": 51821,
                    "state": "active",
                    "peer_version": "4.0.0",
                    "peer_protocol": 1,
                    "capabilities": ["links"],
                    "compatibility": "compatible",
                    "missing_capabilities": [],
                    "rtt_ms": 1.45,
                    "high_latency": false,
                    "last_ok_at": "2026-11-23T10:05:00Z",
                    "last_error": null,
                    "consecutive_failures": 0,
                    "pending_attempt_id": null,
                    "pending_expires_at": null,
                    "created_at": "2026-11-23T10:00:00Z",
                    "updated_at": "2026-11-23T10:05:00Z",
                    "grants": { "inbound": null, "outbound": null },
                    "exports": [],
                    "mounts": [],
                    "transcode_worker": null
                },
                {
                    "id": "link-2",
                    "name": "archive-3",
                    "wg_pubkey": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
                    "tunnel_ip": "10.231.0.3",
                    "endpoint": "fd00::30",
                    "wg_port": 51821,
                    "state": "revoked",
                    "peer_version": "3.9.0",
                    "peer_protocol": 0,
                    "capabilities": [],
                    "compatibility": "incompatible",
                    "missing_capabilities": ["links"],
                    "rtt_ms": null,
                    "high_latency": false,
                    "last_ok_at": null,
                    "last_error": "Link revoked by archive-3",
                    "consecutive_failures": 2,
                    "pending_attempt_id": null,
                    "pending_expires_at": null,
                    "created_at": "2026-11-23T10:00:00Z",
                    "updated_at": "2026-11-23T10:06:00Z",
                    "grants": { "inbound": null, "outbound": null },
                    "exports": [],
                    "mounts": [],
                    "transcode_worker": null
                }
            ],
            "pairing_windows": [],
            "pairing_attempts": [],
            "detected_endpoints": []
        });

        let snapshot: PeersSnapshot = serde_json::from_value(payload).unwrap();
        assert!(!is_unlinked_empty_state(&snapshot));
        assert_eq!(snapshot.peers.len(), 2);

        let p1 = &snapshot.peers[0];
        assert_eq!(
            status_presentation(&p1.state),
            ("Cluster.statusHealthy", "success")
        );
        assert_eq!(
            compatibility_presentation(&p1.compatibility),
            ("Cluster.compatCompatible", "success")
        );
        assert_eq!(format_rtt("en", p1.rtt_ms), "1.4 ms");
        assert_eq!(
            format_version("en", p1.peer_version.as_deref(), p1.peer_protocol),
            "4.0.0 · protocol v1"
        );
        assert_eq!(
            endpoint_display(&p1.endpoint, p1.wg_port),
            "10.0.0.20:51821"
        );
        assert!(can_edit_endpoint(&p1.state));
        assert_eq!(revoke_dialog_mode(&p1.state), RevokeMode::ActiveOrDown);
        assert!(compatibility_guidance("en", p1).is_none());

        let p2 = &snapshot.peers[1];
        assert_eq!(
            status_presentation(&p2.state),
            ("Cluster.statusRevoked", "danger")
        );
        assert_eq!(
            compatibility_presentation(&p2.compatibility),
            ("Cluster.compatIncompatible", "danger")
        );
        assert_eq!(format_rtt("en", p2.rtt_ms), "Not reported");
        assert_eq!(
            endpoint_display(&p2.endpoint, p2.wg_port),
            "[fd00::30]:51821"
        );
        assert!(!can_edit_endpoint(&p2.state));
        assert_eq!(revoke_dialog_mode(&p2.state), RevokeMode::AlreadyRevoked);
        assert_eq!(
            compatibility_guidance("en", p2).as_deref(),
            Some("Update archive-3 to a compatible peer protocol version.")
        );
        assert_eq!(p2.last_error.as_deref(), Some("Link revoked by archive-3"));
    }

    #[test]
    fn direction_and_access_summaries_reflect_bidirectional_link_and_separate_grants() {
        let mut peer = PeerLinkView {
            name: "media-2".to_string(),
            state: "active".to_string(),
            ..Default::default()
        };

        assert_eq!(
            direction_summary("en", &peer),
            "Bidirectional link; management access is granted separately (none granted yet)"
        );
        assert_eq!(access_summary("en", &peer), "No management grants");

        // Inbound grant only (media-2 can view services on this server).
        peer.grants.inbound = Some(GrantSummaryView {
            id: "g-in".to_string(),
            access: AccessMapView {
                services: AccessLevel::Read,
                ..Default::default()
            },
            ..Default::default()
        });
        assert_eq!(
            direction_summary("en", &peer),
            "One-way access: media-2 can manage this server (Read-only: services); this server has no access on media-2"
        );
        assert_eq!(
            access_summary("en", &peer),
            "Inbound (media-2): Read-only: services"
        );

        // Two-way grants (this server has full read-write on media-2; media-2 has read-only services here).
        peer.grants.outbound = Some(GrantSummaryView {
            id: "g-out".to_string(),
            access: AccessMapView {
                services: AccessLevel::Write,
                marketplace: AccessLevel::Write,
                settings: AccessLevel::Write,
                files: AccessLevel::Write,
                users: AccessLevel::Write,
                network: AccessLevel::Write,
                updates: AccessLevel::Write,
                transcoding: AccessLevel::Write,
            },
            ..Default::default()
        });
        assert_eq!(
            direction_summary("en", &peer),
            "Two-way access: this server can manage media-2 (Read and write (everything)); media-2 can manage this server (Read-only: services)"
        );
        assert_eq!(
            access_summary("en", &peer),
            "Outbound (to media-2): Read and write (everything) · Inbound (media-2): Read-only: services"
        );

        // Outbound read-only all only.
        peer.grants.inbound = None;
        peer.grants.outbound = Some(GrantSummaryView {
            id: "g-out-ro".to_string(),
            access: AccessMapView {
                services: AccessLevel::Read,
                marketplace: AccessLevel::Read,
                settings: AccessLevel::Read,
                files: AccessLevel::Read,
                users: AccessLevel::Read,
                network: AccessLevel::Read,
                updates: AccessLevel::Read,
                transcoding: AccessLevel::Read,
            },
            ..Default::default()
        });
        assert_eq!(
            direction_summary("en", &peer),
            "One-way access: this server can manage media-2 (Read-only (everything)); media-2 has no access here"
        );
    }

    #[test]
    fn update_endpoint_request_and_revoke_response_match_backend_contracts() {
        let req = build_update_endpoint_request(" 10.0.0.25 ", "").unwrap();
        let encoded = serde_json::to_value(&req).unwrap();
        assert_eq!(encoded, json!({"endpoint": "10.0.0.25"}));

        let req_with_port = build_update_endpoint_request("peer.example.com", "51822").unwrap();
        let encoded_with_port = serde_json::to_value(&req_with_port).unwrap();
        assert_eq!(
            encoded_with_port,
            json!({"endpoint": "peer.example.com", "wg_port": 51822})
        );

        assert_eq!(
            build_update_endpoint_request("  ", "51821").unwrap_err(),
            "Cluster.validationEndpointRequired"
        );
        assert_eq!(
            build_update_endpoint_request("10.0.0.25", "0").unwrap_err(),
            "Cluster.validationPortInvalid"
        );
        assert_eq!(
            build_update_endpoint_request("10.0.0.25", "70000").unwrap_err(),
            "Cluster.validationPortInvalid"
        );

        let revoke_resp: RevokePeerResponse = serde_json::from_value(json!({
            "revoked": true,
            "link_id": "link-1",
            "name": "media-2",
            "notice_delivered": true
        }))
        .unwrap();
        assert!(revoke_resp.revoked);
        assert!(revoke_resp.notice_delivered);

        assert_eq!(revoke_consequence_keys(RevokeMode::ActiveOrDown).len(), 4);
        assert_eq!(revoke_consequence_keys(RevokeMode::Pending).len(), 2);
        assert_eq!(revoke_consequence_keys(RevokeMode::AlreadyRevoked).len(), 2);
    }

    #[test]
    fn keyed_peer_ids_stay_stable_while_row_projection_updates_live_across_health_polls() {
        let owner = Owner::new();
        owner.with(|| {
            let peers = RwSignal::new(vec![PeerLinkView {
                id: "link-1".into(),
                name: "media-2".into(),
                endpoint: "192.0.2.21".into(),
                wg_port: 51821,
                state: "active".into(),
                rtt_ms: Some(8.0),
                high_latency: false,
                compatibility: "compatible".into(),
                ..Default::default()
            }]);
            let peer_ids = Memo::new(move |_| {
                peers.with(|list| list.iter().map(|peer| peer.id.clone()).collect::<Vec<_>>())
            });
            let row = Memo::new(move |_| {
                peers.with(|list| list.iter().find(|peer| peer.id == "link-1").cloned())
            });

            assert_eq!(peer_ids.get(), vec!["link-1".to_string()]);
            assert_eq!(
                row.get().as_ref().map(|p| p.endpoint.as_str()),
                Some("192.0.2.21")
            );
            assert_eq!(row.get().and_then(|p| p.rtt_ms), Some(8.0));

            // Simulate a 10s health poll updating RTT, endpoint, status, and last_error.
            peers.set(vec![PeerLinkView {
                id: "link-1".into(),
                name: "media-2".into(),
                endpoint: "192.0.2.44".into(),
                wg_port: 51822,
                state: "down".into(),
                rtt_ms: Some(145.5),
                high_latency: true,
                last_error: Some("WireGuard handshake stale".into()),
                compatibility: "compatible".into(),
                ..Default::default()
            }]);

            assert_eq!(peer_ids.get(), vec!["link-1".to_string()]);
            let updated = row.get().expect("keyed peer row remains present");
            assert_eq!(updated.endpoint, "192.0.2.44");
            assert_eq!(updated.wg_port, 51822);
            assert_eq!(updated.state, "down");
            assert_eq!(updated.rtt_ms, Some(145.5));
            assert!(updated.high_latency);
            assert_eq!(
                updated.last_error.as_deref(),
                Some("WireGuard handshake stale")
            );
            assert!(can_edit_endpoint(&updated.state));
        });
    }

    #[test]
    fn grant_controls_are_limited_to_usable_completed_links() {
        let active_compatible = PeerLinkView {
            state: "active".into(),
            compatibility: "compatible".into(),
            ..Default::default()
        };
        assert!(can_manage_grants(&active_compatible));

        let active_limited = PeerLinkView {
            state: "active".into(),
            compatibility: "limited".into(),
            ..Default::default()
        };
        assert!(can_manage_grants(&active_limited));

        let mut link_only = active_limited.clone();
        link_only.missing_capabilities.push("grants".into());
        assert!(!can_manage_grants(&link_only));
        link_only.grants.inbound = Some(GrantSummaryView::default());
        assert!(can_manage_grants(&link_only));
        assert!(!supports_grant_delivery(&link_only));

        let active_incompatible = PeerLinkView {
            state: "active".into(),
            compatibility: "incompatible".into(),
            ..Default::default()
        };
        assert!(!can_manage_grants(&active_incompatible));

        let pending = PeerLinkView {
            state: "pending".into(),
            compatibility: "compatible".into(),
            ..Default::default()
        };
        assert!(!can_manage_grants(&pending));

        let revoked = PeerLinkView {
            state: "revoked".into(),
            compatibility: "compatible".into(),
            ..Default::default()
        };
        assert!(!can_manage_grants(&revoked));

        let down_no_grants = PeerLinkView {
            state: "down".into(),
            compatibility: "compatible".into(),
            ..Default::default()
        };
        assert!(!can_manage_grants(&down_no_grants));

        let down_with_inbound = PeerLinkView {
            state: "down".into(),
            compatibility: "compatible".into(),
            grants: LinkGrantsView {
                inbound: Some(GrantSummaryView {
                    id: "g-in".into(),
                    access: AccessMapView {
                        services: AccessLevel::Read,
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                outbound: None,
            },
            ..Default::default()
        };
        assert!(can_manage_grants(&down_with_inbound));
    }
}
