mod preferences;
mod resources;
pub mod server;
mod session;
mod tabs;

use crate::tabs::cluster::peers::{AccessLevel, PeerLinkView, PeersSnapshot};
pub use server::{
    evaluate_active_peer_health, is_valid_public_remote_host, normalize_server_selection,
    peer_compatibility_supports_management, peer_has_capability, peer_switch_eligibility,
    server_accent, ActivePeerHealth, PeerArea, ServerAccent,
};
use server::{peer_area_read_mask, peer_snapshot_allows_area_read, ServerStateSnapshot};
use std::collections::BTreeMap;

pub(crate) use preferences::hydrate_preferences_with;
#[allow(unused_imports)]
pub(crate) use preferences::HydratedPreferences;
pub use preferences::{
    apply_display_preferences_dom, apply_locale_dom, apply_theme_dom, detect_browser_locale,
    format_aurora_opacity_unit, normalize_aurora_opacity_pct, normalize_card_lift,
    normalize_high_refresh_mode, normalize_touch_mode, quantize_aurora_opacity_pct,
    quantize_refresh_rate, resolve_high_refresh_active, resolve_touch_mode_active,
};
use preferences::{
    detect_reduced_motion_preference, detect_touch_device, initial_preference,
    legacy_storage_envelope, legacy_touch_mode_value, normalize_theme, theme_is_light,
};
#[allow(unused_imports)]
pub(crate) use resources::ResourceReadJob;
pub use resources::{
    json_rows, use_api, use_api_typed, use_api_typed_when, use_api_when, use_typed_api,
    ApiResource, TypedApiResource,
};
pub(crate) use resources::{owned_resource_reads, run_resource_read, ResourceReads};
#[cfg(any(test, target_arch = "wasm32"))]
use session::is_spa_fallback_path;
pub use session::{app, current_path, install_session, navigate, query_param, worker_pool};
use session::{
    confirmed_session_identity, deserialize_metrics, deserialize_user, purge_ai_sessions,
    same_authenticated_identity, suspend_shell_interaction,
};
pub use tabs::{clamp_tab_for_role, stroke_icon, TabId};

use af_web_core::{
    api::{storage_set, ApiClient, ApiError},
    ws::ConnectionState,
};
use leptos::prelude::*;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

static NEXT_TOAST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct Toast {
    pub id: u64,
    pub message: String,
    pub params: Vec<(String, String)>,
    pub error: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct ServicesRequest {
    epoch: u64,
    server_epoch: u64,
    grant_epoch: u64,
    generation: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct SettingsRequest {
    epoch: u64,
    server_epoch: u64,
    grant_epoch: u64,
    generation: u64,
}

#[derive(Clone, Copy, Default)]
struct RequestOrder {
    issued: u64,
    accepted: u64,
}

fn user_role_changed(prev: Option<&Value>, next: &Value) -> bool {
    let prev_role = prev.and_then(deserialize_user).map(|user| user.role);
    let next_role = deserialize_user(next).map(|user| user.role);
    prev_role.is_some() && prev_role != next_role
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferSummary {
    pub id: u64,
    pub path: String,
    pub sent: u64,
    pub size: u64,
    pub status: String,
    pub active: bool,
}

#[derive(Clone, Copy)]
pub struct AppContext {
    pub user: RwSignal<Option<Value>>,
    pub auth_loading: RwSignal<bool>,
    auth_generation: RwSignal<u64>,
    pub session_epoch: RwSignal<u64>,
    pub server_epoch: RwSignal<u64>,
    pub active_server_id: RwSignal<Option<String>>,
    pub peers_snapshot: RwSignal<Option<PeersSnapshot>>,
    active_peer_last: RwSignal<Option<PeerLinkView>>,
    server_cache: RwSignal<BTreeMap<Option<String>, ServerStateSnapshot>>,
    active_read_mask: RwSignal<u8>,
    area_access: [RwSignal<AccessLevel>; 8],
    area_read: [RwSignal<bool>; 8],
    area_write: [RwSignal<bool>; 8],
    area_revocation_epochs: [RwSignal<u64>; 8],
    pub authenticated_at: RwSignal<f64>,
    pub tab: RwSignal<TabId>,
    pub pending_subtab: RwSignal<Option<(TabId, String)>>,
    pub locale: RwSignal<String>,
    pub catalog_revision: RwSignal<u32>,
    pub theme: RwSignal<String>,
    pub immersive_overview: RwSignal<bool>,
    pub show_gpu: RwSignal<bool>,
    pub show_transfer_history: RwSignal<bool>,
    pub reduced_motion: RwSignal<bool>,
    pub system_reduced_motion: RwSignal<bool>,
    pub haptic_feedback: RwSignal<bool>,
    pub high_refresh_mode: RwSignal<String>,
    pub detected_refresh_rate: RwSignal<u32>,
    pub touch_mode: RwSignal<String>,
    pub detected_touch_device: RwSignal<bool>,
    pub aurora_opacity: RwSignal<u8>,
    pub aurora_animation: RwSignal<bool>,
    pub grain_display: RwSignal<bool>,
    pub card_lift: RwSignal<i8>,
    pub settings: RwSignal<Value>,
    settings_order: RwSignal<RequestOrder>,
    pub metrics: RwSignal<Value>,
    pub services: RwSignal<Value>,
    services_order: RwSignal<RequestOrder>,
    pub(crate) live_samples: RwSignal<Vec<crate::tabs::overview::Sample>>,
    pub connection: RwSignal<ConnectionState>,
    pub pending: RwSignal<usize>,
    pub notifications: RwSignal<Vec<Value>>,
    pub transfers: RwSignal<Vec<TransferSummary>>,
    pub toasts: RwSignal<Vec<Toast>>,
    pub banners: RwSignal<Vec<String>>,
    pub command_open: RwSignal<bool>,
    pub notifications_open: RwSignal<bool>,
    pub mobile_open: RwSignal<bool>,
    pub history_revision: RwSignal<u64>,
    pub marketplace_revision: RwSignal<u64>,
}
impl AppContext {
    pub fn new() -> Self {
        #[cfg(target_arch = "wasm32")]
        let tab = web_sys::window()
            .and_then(|w| w.location().search().ok())
            .and_then(|q| web_sys::UrlSearchParams::new_with_str(&q).ok())
            .and_then(|q| q.get("tab"))
            .map(|s| TabId::from_key(&s))
            .unwrap_or_default();
        #[cfg(not(target_arch = "wasm32"))]
        let tab = TabId::default();
        let hydrated = hydrate_preferences_with(initial_preference);
        let locale = hydrated.locale.clone().unwrap_or_else(|| {
            #[cfg(target_arch = "wasm32")]
            let language = web_sys::window().and_then(|window| window.navigator().language());
            #[cfg(not(target_arch = "wasm32"))]
            let language: Option<String> = None;
            detect_browser_locale(language.as_deref()).into()
        });
        #[cfg(target_arch = "wasm32")]
        apply_locale_dom(&locale);
        let context = Self {
            user: RwSignal::new(None),
            auth_loading: RwSignal::new(true),
            auth_generation: RwSignal::new(0),
            session_epoch: RwSignal::new(0),
            server_epoch: RwSignal::new(0),
            active_server_id: RwSignal::new(None),
            peers_snapshot: RwSignal::new(None),
            active_peer_last: RwSignal::new(None),
            server_cache: RwSignal::new(BTreeMap::new()),
            active_read_mask: RwSignal::new(u8::MAX),
            area_access: std::array::from_fn(|_| RwSignal::new(AccessLevel::Write)),
            area_read: std::array::from_fn(|_| RwSignal::new(true)),
            area_write: std::array::from_fn(|_| RwSignal::new(true)),
            area_revocation_epochs: std::array::from_fn(|_| RwSignal::new(0u64)),
            authenticated_at: RwSignal::new(0.0),
            tab: RwSignal::new(tab),
            pending_subtab: RwSignal::new(None),
            locale: RwSignal::new(locale),
            catalog_revision: RwSignal::new(0),
            theme: RwSignal::new(hydrated.theme),
            immersive_overview: RwSignal::new(hydrated.immersive_overview),
            show_gpu: RwSignal::new(hydrated.show_gpu),
            show_transfer_history: RwSignal::new(hydrated.show_transfer_history),
            reduced_motion: RwSignal::new(hydrated.reduced_motion),
            system_reduced_motion: RwSignal::new(detect_reduced_motion_preference()),
            haptic_feedback: RwSignal::new(hydrated.haptic_feedback),
            high_refresh_mode: RwSignal::new(hydrated.high_refresh_mode),
            detected_refresh_rate: RwSignal::new(60),
            touch_mode: RwSignal::new(hydrated.touch_mode),
            detected_touch_device: RwSignal::new(detect_touch_device()),
            aurora_opacity: RwSignal::new(hydrated.aurora_opacity),
            aurora_animation: RwSignal::new(hydrated.aurora_animation),
            grain_display: RwSignal::new(hydrated.grain_display),
            card_lift: RwSignal::new(hydrated.card_lift),
            settings: RwSignal::new(Value::Null),
            settings_order: RwSignal::new(RequestOrder::default()),
            metrics: RwSignal::new(Value::Null),
            services: RwSignal::new(Value::Null),
            services_order: RwSignal::new(RequestOrder::default()),
            live_samples: RwSignal::new(vec![]),
            connection: RwSignal::new(ConnectionState::Connecting),
            pending: RwSignal::new(0),
            notifications: RwSignal::new(vec![]),
            transfers: RwSignal::new(vec![]),
            toasts: RwSignal::new(vec![]),
            banners: RwSignal::new(vec![]),
            command_open: RwSignal::new(false),
            notifications_open: RwSignal::new(false),
            mobile_open: RwSignal::new(false),
            history_revision: RwSignal::new(0),
            marketplace_revision: RwSignal::new(0),
        };
        provide_context(af_web_ui::UiLocale(Signal::derive(move || {
            context.catalog_revision.get();
            context.locale.get()
        })));
        context.load_locale(context.locale.get_untracked());
        context
    }
    pub fn is_admin(self) -> bool {
        self.typed_user().is_some_and(|user| user.role == "admin")
    }
    pub fn is_admin_untracked(self) -> bool {
        self.user.with_untracked(|user| {
            user.as_ref()
                .and_then(deserialize_user)
                .is_some_and(|u| u.role == "admin")
        })
    }
    pub fn is_remote(self) -> bool {
        self.active_server_id.with(Option::is_some)
    }
    pub fn is_remote_untracked(self) -> bool {
        self.active_server_id.with_untracked(Option::is_some)
    }
    pub fn api_url(self, path: &str) -> String {
        self.active_server_id.track();
        self.server_epoch.track();
        af_web_core::api::api_url(path)
    }
    fn current_read_mask_untracked(self) -> u8 {
        let is_admin = self.is_admin_untracked();
        let active_id = self.active_server_id.get_untracked();
        self.peers_snapshot.with_untracked(|snap| {
            self.active_peer_last.with_untracked(|cached| {
                peer_area_read_mask(
                    is_admin,
                    active_id.as_deref(),
                    snap.as_ref(),
                    cached.as_ref(),
                )
            })
        })
    }
    pub fn area_revocation_epoch(self, area: PeerArea) -> u64 {
        self.area_revocation_epochs[area.index()].get()
    }
    pub fn area_revocation_epoch_untracked(self, area: PeerArea) -> u64 {
        self.area_revocation_epochs[area.index()]
            .try_get_untracked()
            .unwrap_or(0)
    }
    pub fn areas_revocation_epoch(self, areas: &[PeerArea]) -> u64 {
        areas.iter().fold(0u64, |acc, &area| {
            acc.wrapping_add(self.area_revocation_epoch(area))
        })
    }
    pub fn areas_revocation_epoch_untracked(self, areas: &[PeerArea]) -> u64 {
        areas.iter().fold(0u64, |acc, &area| {
            acc.wrapping_add(self.area_revocation_epoch_untracked(area))
        })
    }
    fn compute_peer_access_untracked(self, area: PeerArea) -> AccessLevel {
        let Some(id) = self.active_server_id.get_untracked() else {
            return AccessLevel::Write;
        };
        if !self.is_admin_untracked() {
            return AccessLevel::None;
        }
        let health = self.peers_snapshot.with_untracked(|snap| {
            self.active_peer_last.with_untracked(|cached| {
                evaluate_active_peer_health(&id, snap.as_ref(), cached.as_ref())
            })
        });
        if !health.allows_management() {
            return AccessLevel::None;
        }
        self.active_peer_untracked()
            .and_then(|peer| peer.grants.outbound)
            .map(|grant| area.level(&grant.access))
            .unwrap_or(AccessLevel::None)
    }
    /// Keep per-area reactive signals strictly synchronized without notifying
    /// subscribers on unchanged peer polls or unrelated grant transitions.
    fn sync_active_area_signals(self) {
        for area in PeerArea::ALL {
            let idx = area.index();
            let next_level = self.compute_peer_access_untracked(area);
            if self.area_access[idx].get_untracked() != next_level {
                self.area_access[idx].set(next_level);
            }
            let next_read = next_level.allows_read();
            if self.area_read[idx].get_untracked() != next_read {
                self.area_read[idx].set(next_read);
            }
            let next_write = next_level.allows_write();
            if self.area_write[idx].get_untracked() != next_write {
                self.area_write[idx].set(next_write);
            }
        }
    }
    fn sync_active_read_mask(self) {
        let prev_mask = self.active_read_mask.get_untracked();
        let next_mask = self.current_read_mask_untracked();
        self.active_read_mask.set(next_mask);
        let lost_mask = prev_mask & !next_mask;
        for area in PeerArea::ALL {
            if (lost_mask & (1 << area.index())) != 0 {
                self.area_revocation_epochs[area.index()]
                    .update(|epoch| *epoch = epoch.wrapping_add(1));
            }
        }
        let lost_settings = (lost_mask & (1 << PeerArea::Settings.index())) != 0;
        let unauthorized_settings =
            self.is_remote_untracked() && !self.can_read_area_untracked(PeerArea::Settings);
        if lost_settings || (unauthorized_settings && !self.settings.with_untracked(Value::is_null))
        {
            self.settings_order.update(|order| {
                order.issued += 1;
                order.accepted = order.issued;
            });
            self.settings.set(Value::Null);
        }
        let lost_services = (lost_mask & (1 << PeerArea::Services.index())) != 0;
        let unauthorized_services =
            self.is_remote_untracked() && !self.can_read_area_untracked(PeerArea::Services);
        if lost_services
            || (unauthorized_services
                && (!self.services.with_untracked(Value::is_null)
                    || self.pending.get_untracked() != 0))
        {
            self.services_order.update(|order| {
                order.issued += 1;
                order.accepted = order.issued;
            });
            self.services.set(Value::Null);
            self.pending.set(0);
        }
        self.sync_active_area_signals();
    }
    pub fn apply_peers_snapshot(self, snapshot: PeersSnapshot) {
        if let Some(active_id) = self.active_server_id.get_untracked() {
            if let Some(found) = snapshot.peers.iter().find(|p| p.id == active_id).cloned() {
                self.active_peer_last.set(Some(found));
            }
        }
        self.server_cache.update(|cache| {
            for (server_key, entry) in cache.iter_mut() {
                let Some(peer_id) = server_key.as_deref() else {
                    continue;
                };
                if !peer_snapshot_allows_area_read(peer_id, &snapshot, PeerArea::Settings) {
                    entry.settings = Value::Null;
                }
                if !peer_snapshot_allows_area_read(peer_id, &snapshot, PeerArea::Services) {
                    entry.services = Value::Null;
                    entry.pending = 0;
                }
            }
        });
        self.peers_snapshot.set(Some(snapshot));
        self.sync_active_read_mask();
    }
    pub fn refresh_peers_snapshot(self) {
        if !self.is_admin() {
            return;
        }
        let epoch = self.session_epoch.get_untracked();
        spawn_local(async move {
            if let Ok(snapshot) = ApiClient
                .get_typed::<PeersSnapshot>("/api/v1/admin/peers")
                .await
            {
                if self.session_epoch.try_get_untracked() == Some(epoch) {
                    self.apply_peers_snapshot(snapshot);
                }
            }
        });
    }
    pub fn active_peer(self) -> Option<PeerLinkView> {
        let id = self.active_server_id.get()?;
        self.peers_snapshot
            .with(|snap| {
                snap.as_ref()
                    .and_then(|s| s.peers.iter().find(|p| p.id == id).cloned())
            })
            .or_else(|| {
                self.active_peer_last
                    .with(|cached| cached.as_ref().filter(|p| p.id == id).cloned())
            })
    }
    pub fn active_peer_untracked(self) -> Option<PeerLinkView> {
        let id = self.active_server_id.get_untracked()?;
        self.peers_snapshot
            .with_untracked(|snap| {
                snap.as_ref()
                    .and_then(|s| s.peers.iter().find(|p| p.id == id).cloned())
            })
            .or_else(|| {
                self.active_peer_last
                    .with_untracked(|cached| cached.as_ref().filter(|p| p.id == id).cloned())
            })
    }
    pub fn active_server_name(self) -> Option<String> {
        let id = self.active_server_id.get()?;
        let name = self.active_peer().map(|peer| peer.name).unwrap_or(id);
        Some(name)
    }
    pub fn active_server_name_untracked(self) -> Option<String> {
        let id = self.active_server_id.get_untracked()?;
        let name = self
            .active_peer_untracked()
            .map(|peer| peer.name)
            .unwrap_or(id);
        Some(name)
    }
    pub fn active_server_accent(self) -> Option<ServerAccent> {
        self.active_server_id
            .with(|id| id.as_deref().map(server_accent))
    }
    pub fn active_peer_health(self) -> Option<ActivePeerHealth> {
        let id = self.active_server_id.get()?;
        Some(self.peers_snapshot.with(|snap| {
            self.active_peer_last
                .with(|cached| evaluate_active_peer_health(&id, snap.as_ref(), cached.as_ref()))
        }))
    }
    pub fn eligible_peers(self) -> Vec<PeerLinkView> {
        if !self.is_admin() {
            return Vec::new();
        }
        self.peers_snapshot.with(|snap| {
            snap.as_ref()
                .map(|s| {
                    s.peers
                        .iter()
                        .filter(|peer| peer_switch_eligibility(peer).is_ok())
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        })
    }
    pub fn peer_access(self, area: PeerArea) -> AccessLevel {
        self.area_access[area.index()].get()
    }
    pub fn can_read_area(self, area: PeerArea) -> bool {
        self.area_read[area.index()].get()
    }
    pub fn can_read_area_untracked(self, area: PeerArea) -> bool {
        self.compute_peer_access_untracked(area).allows_read()
    }
    pub fn can_write_area(self, area: PeerArea) -> bool {
        self.area_write[area.index()].get()
    }
    pub fn can_write_area_untracked(self, area: PeerArea) -> bool {
        self.compute_peer_access_untracked(area).allows_write()
    }
    pub fn can_all_areas(self, reqs: &[(PeerArea, bool)]) -> bool {
        if !self.is_remote() {
            return true;
        }
        reqs.iter().all(|&(area, write)| {
            if write {
                self.can_write_area(area)
            } else {
                self.can_read_area(area)
            }
        })
    }
    pub fn can_all_areas_untracked(self, reqs: &[(PeerArea, bool)]) -> bool {
        if !self.is_remote_untracked() {
            return true;
        }
        reqs.iter().all(|&(area, write)| {
            if write {
                self.can_write_area_untracked(area)
            } else {
                self.can_read_area_untracked(area)
            }
        })
    }
    pub fn active_peer_allows_management(self) -> bool {
        if !self.is_remote() {
            return true;
        }
        self.active_peer_health()
            .is_some_and(ActivePeerHealth::allows_management)
    }
    pub fn active_peer_allows_management_untracked(self) -> bool {
        let Some(id) = self.active_server_id.get_untracked() else {
            return true;
        };
        if !self.is_admin_untracked() {
            return false;
        }
        self.peers_snapshot.with_untracked(|snap| {
            self.active_peer_last.with_untracked(|cached| {
                evaluate_active_peer_health(&id, snap.as_ref(), cached.as_ref()).allows_management()
            })
        })
    }
    pub fn has_peer_capability(self, capability: &str) -> bool {
        let Some(peer) = self.active_peer() else {
            return !self.is_remote();
        };
        peer_has_capability(&peer, capability)
    }
    pub fn area_block_reason(self, area: PeerArea, write: bool) -> Option<String> {
        let server_name = self.active_server_name()?;
        match self.active_peer_health()? {
            ActivePeerHealth::Unreachable => Some(self.t_with(
                "PeerSwitch.peerUnreachableReason",
                &[("server", &server_name)],
            )),
            ActivePeerHealth::Revoked => {
                Some(self.t_with("PeerSwitch.peerRevokedReason", &[("server", &server_name)]))
            }
            ActivePeerHealth::Incompatible => Some(self.t_with(
                "PeerSwitch.peerIncompatibleReason",
                &[("server", &server_name)],
            )),
            ActivePeerHealth::NoGrant => {
                Some(self.t_with("PeerSwitch.noGrantReason", &[("server", &server_name)]))
            }
            ActivePeerHealth::Healthy | ActivePeerHealth::Limited => {
                let level = self.peer_access(area);
                let allowed = if write {
                    level.allows_write()
                } else {
                    level.allows_read()
                };
                if allowed {
                    return None;
                }
                let area_label = self.t(area.label_key());
                if write && level.allows_read() {
                    Some(self.t_with(
                        "PeerSwitch.readOnlyAreaReason",
                        &[("area", &area_label), ("server", &server_name)],
                    ))
                } else {
                    Some(self.t_with(
                        "PeerSwitch.noAreaAccessReason",
                        &[("area", &area_label), ("server", &server_name)],
                    ))
                }
            }
        }
    }
    pub fn areas_block_reason(self, reqs: &[(PeerArea, bool)]) -> Option<String> {
        let server_name = self.active_server_name()?;
        match self.active_peer_health()? {
            ActivePeerHealth::Unreachable => {
                return Some(self.t_with(
                    "PeerSwitch.peerUnreachableReason",
                    &[("server", &server_name)],
                ))
            }
            ActivePeerHealth::Revoked => {
                return Some(
                    self.t_with("PeerSwitch.peerRevokedReason", &[("server", &server_name)]),
                )
            }
            ActivePeerHealth::Incompatible => {
                return Some(self.t_with(
                    "PeerSwitch.peerIncompatibleReason",
                    &[("server", &server_name)],
                ))
            }
            ActivePeerHealth::NoGrant => {
                return Some(self.t_with("PeerSwitch.noGrantReason", &[("server", &server_name)]))
            }
            ActivePeerHealth::Healthy | ActivePeerHealth::Limited => {}
        }
        let missing: Vec<String> = reqs
            .iter()
            .filter_map(|&(area, write)| {
                let level = self.peer_access(area);
                let ok = if write {
                    level.allows_write()
                } else {
                    level.allows_read()
                };
                if ok {
                    return None;
                }
                let area_label = self.t(area.label_key());
                Some(self.t_with(
                    if write {
                        "PeerSwitch.areaWriteRequired"
                    } else {
                        "PeerSwitch.areaReadRequired"
                    },
                    &[("area", &area_label)],
                ))
            })
            .collect();
        if missing.is_empty() {
            return None;
        }
        if missing.len() == 1 && reqs.len() == 1 {
            return self.area_block_reason(reqs[0].0, reqs[0].1);
        }
        let joined = missing.join(", ");
        Some(self.t_with(
            "PeerSwitch.missingMultiAreaReason",
            &[("requirements", &joined), ("server", &server_name)],
        ))
    }
    pub fn capability_block_reason(self, capability: &str) -> Option<String> {
        if self.has_peer_capability(capability) {
            return None;
        }
        let server_name = self.active_server_name()?;
        Some(self.t_with(
            "PeerSwitch.capabilityUpdateHint",
            &[("server", &server_name)],
        ))
    }
    pub fn select_server(self, target: Option<String>) -> bool {
        let is_admin = self.user.with_untracked(|user| {
            user.as_ref()
                .and_then(deserialize_user)
                .is_some_and(|u| u.role == "admin")
        });
        let normalized = if is_admin {
            normalize_server_selection(target)
        } else {
            None
        };
        let current = self.active_server_id.get_untracked();
        if current == normalized {
            return true;
        }
        let next_peer = if let Some(ref peer_id) = normalized {
            let found = self.peers_snapshot.with_untracked(|snap| {
                snap.as_ref()
                    .and_then(|s| s.peers.iter().find(|p| &p.id == peer_id).cloned())
            });
            let Some(peer) = found else {
                self.toast("PeerSwitch.peerUnavailable", true);
                return false;
            };
            if let Err(reason_key) = peer_switch_eligibility(&peer) {
                self.toast(reason_key, true);
                return false;
            }
            Some(peer)
        } else {
            None
        };
        let save_settings =
            if current.is_some() && !self.can_read_area_untracked(PeerArea::Settings) {
                Value::Null
            } else {
                self.settings.get_untracked()
            };
        let (save_services, save_pending) =
            if current.is_some() && !self.can_read_area_untracked(PeerArea::Services) {
                (Value::Null, 0)
            } else {
                (self.services.get_untracked(), self.pending.get_untracked())
            };
        let snapshot = ServerStateSnapshot {
            settings: save_settings,
            metrics: self.metrics.get_untracked(),
            services: save_services,
            live_samples: self.live_samples.get_untracked(),
            pending: save_pending,
            notifications: self.notifications.get_untracked(),
            banners: self.banners.get_untracked(),
        };
        self.server_cache.update(|cache| {
            cache.insert(current, snapshot);
        });
        let mut restored = self
            .server_cache
            .with_untracked(|cache| cache.get(&normalized).cloned())
            .unwrap_or_default();
        if normalized.is_some() {
            // Remote peers must always revalidate Settings, Services, and pending actions
            // after fresh authorized reads so stale origins or revoked access never flash.
            restored.settings = Value::Null;
            restored.services = Value::Null;
            restored.pending = 0;
        }
        af_web_core::api::set_active_server(normalized.clone());
        self.active_peer_last.set(next_peer);
        self.active_server_id.set(normalized);
        self.active_read_mask
            .set(self.current_read_mask_untracked());
        self.sync_active_area_signals();
        self.server_epoch
            .update(|epoch| *epoch = epoch.wrapping_add(1));
        self.settings_order.update(|order| {
            order.issued += 1;
            order.accepted = order.issued;
        });
        self.services_order.update(|order| {
            order.issued += 1;
            order.accepted = order.issued;
        });
        self.settings.set(restored.settings);
        self.metrics.set(restored.metrics);
        self.services.set(restored.services);
        self.live_samples.set(restored.live_samples);
        self.pending.set(restored.pending);
        self.notifications.set(restored.notifications);
        self.banners.set(restored.banners);
        self.transfers.set(vec![]);
        self.connection.set(ConnectionState::Connecting);
        self.notifications_open.set(false);
        self.command_open.set(false);
        true
    }
    pub fn exit_to_local_server(self) {
        let _ = self.select_server(None);
    }
    pub fn t(self, key: &str) -> String {
        self.catalog_revision.get();
        af_web_core::i18n::translate(&self.locale.get(), key)
    }
    pub fn t_with(self, key: &str, vars: &[(&str, &str)]) -> String {
        self.catalog_revision.get();
        af_web_core::i18n::translate_with(&self.locale.get(), key, vars)
    }
    pub fn set_locale(self, locale: &str) {
        if af_web_core::i18n::LOCALES.contains(&locale) {
            storage_set("aetherflow-language", locale);
            self.locale.set(locale.into());
            self.sync_legacy_system_storage();
            apply_locale_dom(locale);
            self.load_locale(locale.to_string());
        }
    }
    pub(super) fn load_locale(self, locale: String) {
        #[cfg(target_arch = "wasm32")]
        if locale != "en" {
            spawn_local(async move {
                match af_web_core::i18n::ensure_locale_loaded(&locale).await {
                    Ok(true) => {
                        let _ = self.catalog_revision.try_update(|revision| {
                            *revision = revision.wrapping_add(1);
                        });
                        // Shell navigation also has direct locale subscribers.
                        // Notify them when their deferred catalog becomes usable.
                        if self.locale.try_get_untracked().as_deref() == Some(locale.as_str()) {
                            let _ = self.locale.try_update(|_| {});
                        }
                    }
                    Ok(false) => {}
                    Err(error) => web_sys::console::warn_1(&error.into()),
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = locale;
    }
    pub fn typed_user(self) -> Option<af_web_core::models::User> {
        self.user
            .with(|user| user.as_ref().and_then(deserialize_user))
    }
    /// Tracks the existing JSON signal while exposing the shared domain model.
    pub fn typed_metrics(self) -> af_web_core::models::SystemMetrics {
        self.metrics.with(deserialize_metrics)
    }
    /// All HTTP Settings readers and writers share a monotonic generation fenced
    /// across session, server, and Settings grant transitions. Fresh authorized GETs
    /// replace stale snapshots without overwriting a newer explicit Settings save.
    pub(crate) fn begin_settings_request(self) -> SettingsRequest {
        self.settings_order.update(|order| order.issued += 1);
        SettingsRequest {
            epoch: self.session_epoch.get_untracked(),
            server_epoch: self.server_epoch.get_untracked(),
            grant_epoch: self.area_revocation_epoch_untracked(PeerArea::Settings),
            generation: self.settings_order.get_untracked().issued,
        }
    }
    pub(crate) fn finish_settings_request(self, request: SettingsRequest, value: Value) -> bool {
        if self.session_epoch.try_get_untracked() != Some(request.epoch)
            || self.server_epoch.try_get_untracked() != Some(request.server_epoch)
            || self.area_revocation_epoch_untracked(PeerArea::Settings) != request.grant_epoch
            || !self.can_read_area_untracked(PeerArea::Settings)
            || self
                .settings_order
                .try_get_untracked()
                .is_none_or(|order| order.accepted > request.generation)
            || self.user.try_get_untracked().flatten().is_none()
        {
            return false;
        }
        self.settings_order
            .update(|order| order.accepted = request.generation);
        self.settings.set(value);
        true
    }
    pub(crate) fn publish_settings_save(self, value: Value) -> bool {
        if self.user.try_get_untracked().flatten().is_none()
            || !self.can_read_area_untracked(PeerArea::Settings)
        {
            return false;
        }
        self.settings_order.update(|order| {
            order.issued += 1;
            order.accepted = order.issued;
        });
        self.settings.set(value);
        true
    }
    /// All HTTP service writers share an ordering with live telemetry. A newer
    /// accepted snapshot, grant revocation, or account reset invalidates an older snapshot.
    pub(crate) fn begin_services_request(self) -> ServicesRequest {
        self.services_order.update(|order| order.issued += 1);
        ServicesRequest {
            epoch: self.session_epoch.get_untracked(),
            server_epoch: self.server_epoch.get_untracked(),
            grant_epoch: self.area_revocation_epoch_untracked(PeerArea::Services),
            generation: self.services_order.get_untracked().issued,
        }
    }
    pub(crate) fn finish_services_request(self, request: ServicesRequest, value: Value) -> bool {
        if self.session_epoch.try_get_untracked() != Some(request.epoch)
            || self.server_epoch.try_get_untracked() != Some(request.server_epoch)
            || self.area_revocation_epoch_untracked(PeerArea::Services) != request.grant_epoch
            || !self.can_read_area_untracked(PeerArea::Services)
            || self
                .services_order
                .try_get_untracked()
                .is_none_or(|order| order.accepted > request.generation)
            || self.user.try_get_untracked().flatten().is_none()
        {
            return false;
        }
        self.services_order
            .update(|order| order.accepted = request.generation);
        self.services.set(value);
        true
    }
    pub(crate) fn publish_metrics(self, metrics: Value) {
        self.live_samples
            .update(|samples| crate::tabs::overview::Sample::record_live(samples, &metrics));
        self.metrics.set(metrics);
    }

    pub(crate) fn publish_live_services(self, value: Value) {
        if !self.can_read_area_untracked(PeerArea::Services)
            || self.user.try_get_untracked().flatten().is_none()
        {
            return;
        }
        self.services_order.update(|order| {
            order.issued += 1;
            order.accepted = order.issued;
        });
        self.services.set(value);
    }
    fn sync_legacy_system_storage(self) {
        let mut state_obj = initial_preference("aetherflow-system-storage")
            .as_deref()
            .and_then(|raw| legacy_storage_envelope(Some(raw)))
            .and_then(|val| val.as_object().cloned())
            .unwrap_or_default();
        let opacity_pct =
            quantize_aurora_opacity_pct(f64::from(self.aurora_opacity.get_untracked()));
        let opacity_unit = (f64::from(opacity_pct) / 100.0 * 100.0).round() / 100.0;
        state_obj.insert("theme".into(), Value::String(self.theme.get_untracked()));
        state_obj.insert(
            "language".into(),
            Value::String(self.locale.get_untracked()),
        );
        state_obj.insert("auroraOpacity".into(), serde_json::json!(opacity_unit));
        state_obj.insert(
            "auroraAnimation".into(),
            Value::Bool(self.aurora_animation.get_untracked()),
        );
        state_obj.insert(
            "grainDisplay".into(),
            Value::Bool(self.grain_display.get_untracked()),
        );
        state_obj.insert(
            "cardLift".into(),
            serde_json::json!(self.card_lift.get_untracked()),
        );
        state_obj.insert(
            "highRefreshMode".into(),
            Value::String(
                normalize_high_refresh_mode(&self.high_refresh_mode.get_untracked()).into(),
            ),
        );
        state_obj.insert(
            "touchMode".into(),
            Value::String(legacy_touch_mode_value(&self.touch_mode.get_untracked()).into()),
        );
        state_obj.insert(
            "hapticFeedback".into(),
            Value::Bool(self.haptic_feedback.get_untracked()),
        );
        state_obj.insert(
            "reducedMotion".into(),
            Value::Bool(self.reduced_motion.get_untracked()),
        );
        state_obj.insert(
            "dashboardDensity".into(),
            Value::String(
                if self.immersive_overview.get_untracked() {
                    "immersive"
                } else {
                    "compact"
                }
                .into(),
            ),
        );
        state_obj.insert(
            "showGpuWidget".into(),
            Value::Bool(self.show_gpu.get_untracked()),
        );
        state_obj.insert(
            "showDataUsageWidget".into(),
            Value::Bool(self.show_transfer_history.get_untracked()),
        );
        let envelope = serde_json::json!({
            "state": state_obj,
            "version": 0,
        });
        if let Ok(serialized) = serde_json::to_string(&envelope) {
            storage_set("aetherflow-system-storage", &serialized);
        }
    }
    pub fn effective_reduced_motion(self) -> bool {
        self.reduced_motion.get() || self.system_reduced_motion.get()
    }
    pub fn is_high_refresh_active(self) -> bool {
        !self.effective_reduced_motion()
            && resolve_high_refresh_active(
                &self.high_refresh_mode.get(),
                self.detected_refresh_rate.get(),
            )
    }
    pub fn is_touch_mode_active(self) -> bool {
        resolve_touch_mode_active(&self.touch_mode.get(), self.detected_touch_device.get())
    }
    pub fn is_light(self) -> bool {
        theme_is_light(&self.theme.get())
    }
    pub fn set_theme(self, pref: &str) {
        let pref = normalize_theme(pref);
        storage_set("aetherflow-theme", pref);
        self.theme.set(pref.into());
        self.sync_legacy_system_storage();
    }
    pub fn toggle_theme(self) {
        let light = theme_is_light(&self.theme.get_untracked());
        self.set_theme(if light { "dark" } else { "light" });
        self.haptic(10);
    }
    pub fn set_immersive_overview(self, enabled: bool) {
        storage_set(
            "aetherflow-immersive-overview",
            if enabled { "true" } else { "false" },
        );
        storage_set(
            "aetherflow-dashboard-density",
            if enabled { "immersive" } else { "compact" },
        );
        self.immersive_overview.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_show_gpu(self, enabled: bool) {
        storage_set(
            "aetherflow-show-gpu",
            if enabled { "true" } else { "false" },
        );
        self.show_gpu.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_show_transfer_history(self, enabled: bool) {
        storage_set(
            "aetherflow-show-transfer-history",
            if enabled { "true" } else { "false" },
        );
        self.show_transfer_history.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_reduced_motion(self, enabled: bool) {
        storage_set(
            "aetherflow-reduced-motion",
            if enabled { "true" } else { "false" },
        );
        self.reduced_motion.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_haptic_feedback(self, enabled: bool) {
        storage_set(
            "aetherflow-haptic-feedback",
            if enabled { "true" } else { "false" },
        );
        self.haptic_feedback.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_high_refresh_mode(self, mode: &str) {
        let normalized = normalize_high_refresh_mode(mode);
        storage_set("aetherflow-high-refresh-mode", normalized);
        self.high_refresh_mode.set(normalized.into());
        self.sync_legacy_system_storage();
    }
    pub fn set_touch_mode(self, mode: &str) {
        let normalized = normalize_touch_mode(mode);
        storage_set("aetherflow-touch-mode", normalized);
        self.touch_mode.set(normalized.into());
        self.sync_legacy_system_storage();
    }
    pub fn set_aurora_opacity(self, pct: u8) {
        let quantized = quantize_aurora_opacity_pct(f64::from(pct));
        storage_set(
            "aetherflow-aurora-opacity",
            &format_aurora_opacity_unit(quantized),
        );
        self.aurora_opacity.set(quantized);
        self.sync_legacy_system_storage();
    }
    pub fn set_aurora_opacity_str(self, raw: &str) {
        self.set_aurora_opacity(normalize_aurora_opacity_pct(raw));
    }
    pub fn set_aurora_animation(self, enabled: bool) {
        storage_set(
            "aetherflow-aurora-animation",
            if enabled { "true" } else { "false" },
        );
        self.aurora_animation.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_grain_display(self, enabled: bool) {
        let flag = if enabled { "true" } else { "false" };
        storage_set("aetherflow-grain-display", flag);
        storage_set("aetherflow-grain", flag);
        self.grain_display.set(enabled);
        self.sync_legacy_system_storage();
    }
    pub fn set_card_lift(self, lift_px: i8) {
        let normalized = normalize_card_lift(&lift_px.to_string());
        storage_set("aetherflow-card-lift", &normalized.to_string());
        self.card_lift.set(normalized);
        self.sync_legacy_system_storage();
    }
    pub fn set_card_lift_enabled(self, enabled: bool) {
        self.set_card_lift(if enabled { -4 } else { 0 });
    }
    pub fn haptic(self, ms: u32) {
        if !self.haptic_feedback.get_untracked()
            || self.reduced_motion.get_untracked()
            || self.system_reduced_motion.get_untracked()
        {
            return;
        }
        if let Some(window) = web_sys::window() {
            let navigator = window.navigator();
            if let Some(vibrate) = js_sys::Reflect::get(&navigator, &"vibrate".into())
                .ok()
                .and_then(|vibrate| vibrate.dyn_into::<js_sys::Function>().ok())
            {
                let _ = vibrate.call1(&navigator, &ms.into());
            }
        }
    }
    pub fn select_tab(self, tab: TabId) {
        let tab = clamp_tab_for_role(tab, self.is_admin());
        self.tab.set(tab);
        self.mobile_open.set(false);
        #[cfg(target_arch = "wasm32")]
        {
            if self.normalize_fallback_url(tab) {
                return;
            }
            if let Some(window) =
                web_sys::window().filter(|w| w.location().pathname().ok().as_deref() == Some("/"))
            {
                if let Ok(params) = web_sys::UrlSearchParams::new_with_str(
                    &window.location().search().unwrap_or_default(),
                ) {
                    if tab == TabId::Overview {
                        params.delete("tab");
                    } else {
                        params.set("tab", tab.key());
                    }
                    let query = String::from(params.to_string());
                    let target = format!(
                        "/{}{}",
                        if query.is_empty() {
                            String::new()
                        } else {
                            format!("?{query}")
                        },
                        window.location().hash().unwrap_or_default()
                    );
                    if current_path() != target {
                        if let Ok(history) = window.history() {
                            let _ = history.push_state_with_url(
                                &wasm_bindgen::JsValue::NULL,
                                "",
                                Some(&target),
                            );
                        }
                    }
                }
            }
        }
    }
    pub fn navigate_to_subtab(self, tab: TabId, subtab: impl Into<String>) {
        let clamped = clamp_tab_for_role(tab, self.is_admin());
        if clamped == tab {
            self.pending_subtab.set(Some((clamped, subtab.into())));
        } else {
            self.pending_subtab.set(None);
        }
        if self.tab.get_untracked() != clamped {
            self.select_tab(clamped);
        } else {
            self.mobile_open.set(false);
        }
    }
    pub fn take_pending_subtab(self, tab: TabId) -> Option<String> {
        let matched = self.pending_subtab.with_untracked(|pending| {
            pending
                .as_ref()
                .filter(|(target, _)| *target == tab)
                .map(|(_, subtab)| subtab.clone())
        });
        if matched.is_some() {
            self.pending_subtab.set(None);
        }
        matched
    }
    pub fn normalize_fallback_url(self, tab: TabId) -> bool {
        #[cfg(target_arch = "wasm32")]
        {
            if let Some(window) = web_sys::window().filter(|window| {
                window
                    .location()
                    .pathname()
                    .ok()
                    .is_some_and(|path| is_spa_fallback_path(&path))
            }) {
                if let Ok(history) = window.history() {
                    return history
                        .replace_state_with_url(
                            &wasm_bindgen::JsValue::NULL,
                            "",
                            Some(&format!("/?tab={}", tab.key())),
                        )
                        .is_ok();
                }
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = tab;
        false
    }
    pub fn replace_tab_url(self, tab: TabId) {
        #[cfg(target_arch = "wasm32")]
        {
            if self.normalize_fallback_url(tab) {
                return;
            }
            if let Some(window) =
                web_sys::window().filter(|w| w.location().pathname().ok().as_deref() == Some("/"))
            {
                if let Ok(url) = web_sys::Url::new(&window.location().href().unwrap_or_default()) {
                    if tab == TabId::Overview {
                        url.search_params().delete("tab");
                    } else {
                        url.search_params().set("tab", tab.key());
                    }
                    if let Ok(history) = window.history() {
                        let _ = history.replace_state_with_url(
                            &wasm_bindgen::JsValue::NULL,
                            "",
                            Some(&format!("{}{}{}", url.pathname(), url.search(), url.hash())),
                        );
                    }
                }
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = tab;
    }
    pub fn toast(self, message: impl Into<String>, error: bool) {
        self.toast_with(message, &[], error);
    }
    pub fn toast_with(self, key: impl Into<String>, params: &[(&str, &str)], error: bool) {
        let id = NEXT_TOAST_ID.fetch_add(1, Ordering::Relaxed);
        let message = key.into();
        let params = params
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();
        self.toasts.update(|toasts| {
            toasts.push(Toast {
                id,
                message,
                params,
                error,
            });
            if toasts.len() > 8 {
                toasts.remove(0);
            }
        });
        #[cfg(target_arch = "wasm32")]
        spawn_local(async move {
            gloo_timers::future::TimeoutFuture::new(6000).await;
            if self.toasts.try_get_untracked().is_some() {
                self.toasts.update(|toasts| toasts.retain(|t| t.id != id));
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        let _ = id;
    }
    pub fn render_toast(&self, toast: &Toast) -> String {
        if toast.params.is_empty() {
            self.t(&toast.message)
        } else {
            let borrowed = toast
                .params
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            self.t_with(&toast.message, &borrowed)
        }
    }
    pub(crate) fn apply_authenticated_user(self, next_user: Value, revalidating: bool) -> bool {
        let prev_user = self.user.get_untracked();
        let same_identity = same_authenticated_identity(prev_user.as_ref(), Some(&next_user));
        let role_changed = same_identity && user_role_changed(prev_user.as_ref(), &next_user);
        let is_admin = deserialize_user(&next_user).is_some_and(|user| user.role == "admin");
        let mut bump_session_epoch = false;

        if !revalidating && !same_identity {
            if prev_user.is_some() {
                self.reset_account_scoped_state();
            } else if self.session_epoch.get_untracked() > 0 {
                af_web_core::api::bump_auth_epoch_and_abort();
            }
            if prev_user.is_some() || self.session_epoch.get_untracked() > 0 {
                bump_session_epoch = true;
            }
        } else if !revalidating && role_changed {
            // Same authenticated user changed effective role: reset role-scoped caches,
            // peer selection/snapshot, and mounted shell state without ending the session.
            self.reset_role_scoped_state();
            bump_session_epoch = true;
        }

        if !is_admin {
            let was_remote = self.active_server_id.get_untracked().is_some();
            if was_remote && !role_changed {
                af_web_core::api::bump_server_epoch_and_abort();
                self.clear_server_projections();
            } else {
                af_web_core::api::set_active_server(None);
                self.active_server_id.set(None);
                self.active_peer_last.set(None);
                self.peers_snapshot.set(None);
                self.server_cache.set(BTreeMap::new());
                self.active_read_mask.set(u8::MAX);
                self.sync_active_area_signals();
            }
        }

        let tab = self.tab.get_untracked();
        let clamped = clamp_tab_for_role(tab, is_admin);
        if tab != clamped {
            self.tab.set(clamped);
            self.replace_tab_url(clamped);
        }
        #[cfg(target_arch = "wasm32")]
        self.authenticated_at.set(js_sys::Date::now());
        self.user.set(Some(next_user));
        self.sync_active_area_signals();
        if bump_session_epoch {
            self.session_epoch.update(|epoch| *epoch += 1);
        }
        bump_session_epoch
    }
    pub fn refresh_session(self) {
        self.auth_generation.update(|g| *g += 1);
        let generation = self.auth_generation.get_untracked();
        let epoch = self.session_epoch.get_untracked();
        let transport_epoch = af_web_core::api::current_auth_epoch();
        spawn_local(async move {
            let consent = web_sys::window()
                .and_then(|w| w.location().pathname().ok())
                .is_some_and(|p| p.trim_end_matches('/') == "/oauth/consent");
            let result = if consent {
                ApiClient.probe_session().await
            } else {
                ApiClient.get("/api/v1/auth/session").await
            };
            if self.auth_generation.try_get_untracked() != Some(generation)
                || self.session_epoch.try_get_untracked() != Some(epoch)
                || af_web_core::api::current_auth_epoch() != transport_epoch
            {
                return;
            }
            let result = result.and_then(|user| {
                if af_web_core::api::auth_revalidation_pending()
                    && !confirmed_session_identity(&user)
                {
                    Err(ApiError {
                        status: 401,
                        code: Some("SESSION_UNCONFIRMED".into()),
                        message: "Session identity could not be confirmed".into(),
                    })
                } else {
                    Ok(user)
                }
            });
            let prev_user = self.user.get_untracked();
            match result {
                Ok(next_user) => {
                    let revalidating = af_web_core::api::auth_revalidation_pending();
                    self.apply_authenticated_user(next_user, revalidating);
                    if revalidating
                        && !af_web_core::api::resume_after_auth_revalidation(transport_epoch)
                    {
                        return;
                    }
                }
                Err(_) => {
                    if prev_user.is_some() {
                        self.reset_account_scoped_state();
                        self.session_epoch.update(|epoch| *epoch += 1);
                    }
                    af_web_core::api::clear_csrf_token();
                    self.user.set(None);
                    self.sync_active_area_signals();
                }
            }
            self.auth_loading.set(false);
        });
    }
    pub(super) fn revalidate_external_session(self) {
        // The cookie may already belong to another account. Close the transport
        // gate and invalidate the old shell before starting any async work.
        af_web_core::api::suspend_for_auth_revalidation();
        suspend_shell_interaction();
        self.auth_loading.set(true);
        self.clear_account_scoped_state();
        self.session_epoch.update(|epoch| *epoch += 1);
        self.refresh_session();
    }
    pub(super) fn reset_account_scoped_state(self) {
        af_web_core::api::bump_auth_epoch_and_abort();
        self.clear_account_scoped_state();
    }
    fn clear_server_projections(self) {
        af_web_core::api::set_active_server(None);
        self.active_server_id.set(None);
        self.active_peer_last.set(None);
        self.peers_snapshot.set(None);
        self.server_cache.set(BTreeMap::new());
        self.active_read_mask.set(u8::MAX);
        self.sync_active_area_signals();
        for slot in self.area_revocation_epochs {
            slot.update(|epoch| *epoch = epoch.wrapping_add(1));
        }
        self.server_epoch
            .update(|epoch| *epoch = epoch.wrapping_add(1));
        self.settings_order.update(|order| {
            order.issued += 1;
            order.accepted = order.issued;
        });
        self.settings.set(Value::Null);
        self.metrics.set(Value::Null);
        self.services_order.update(|order| {
            order.issued += 1;
            order.accepted = order.issued;
        });
        self.services.set(Value::Null);
        self.live_samples.set(vec![]);
        self.pending.set(0);
        self.pending_subtab.set(None);
        self.notifications.set(vec![]);
        self.transfers.set(vec![]);
        self.banners.set(vec![]);
        self.connection.set(ConnectionState::Connecting);
        self.mobile_open.set(false);
        self.command_open.set(false);
        self.notifications_open.set(false);
    }
    fn reset_role_scoped_state(self) {
        af_web_core::api::bump_server_epoch_and_abort();
        self.clear_server_projections();
    }
    fn clear_account_scoped_state(self) {
        purge_ai_sessions();
        self.clear_server_projections();
        self.toasts.set(vec![]);
    }
    pub fn logout(self) {
        af_web_core::api::bump_auth_epoch_and_abort();
        self.auth_generation.update(|generation| *generation += 1);
        let origin_epoch = af_web_core::api::current_auth_epoch();
        spawn_local(async move {
            let mut revoked = false;
            for _ in 0..2 {
                let result = ApiClient.request("/api/v1/auth/logout", "POST", None).await;
                if af_web_core::api::current_auth_epoch() != origin_epoch {
                    return;
                }
                match result {
                    Ok(_) => {
                        revoked = true;
                        break;
                    }
                    Err(error) if error.status == 401 => {
                        let session = ApiClient.get("/api/v1/auth/session").await;
                        if af_web_core::api::current_auth_epoch() != origin_epoch {
                            return;
                        }
                        if session.is_err_and(|error| error.status == 401) {
                            revoked = true;
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
            if !revoked {
                let session = ApiClient.get("/api/v1/auth/session").await;
                if af_web_core::api::current_auth_epoch() != origin_epoch {
                    return;
                }
                match session {
                    Ok(_) => {
                        self.toast("Auth.signOutFailed", true);
                        return;
                    }
                    Err(error) if error.status != 401 => {
                        self.toast("Auth.signOutUnconfirmed", true);
                        return;
                    }
                    _ => {}
                }
            }
            self.reset_account_scoped_state();
            self.session_epoch.update(|epoch| *epoch += 1);
            storage_set("af_logout_sync", &js_sys::Date::now().to_string());
            self.user.set(None);
            navigate("/login");
        });
    }
}
impl Default for AppContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
