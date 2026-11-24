//! Reactive peer server selection, capability/grant evaluation, and per-server state cache.
use crate::tabs::cluster::peers::{AccessLevel, AccessMapView, PeerLinkView, PeersSnapshot};
use crate::tabs::overview::Sample;
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeerArea {
    Services,
    Marketplace,
    Settings,
    Files,
    Users,
    Network,
    Updates,
    Transcoding,
}

impl PeerArea {
    pub const ALL: [Self; 8] = [
        Self::Services,
        Self::Marketplace,
        Self::Settings,
        Self::Files,
        Self::Users,
        Self::Network,
        Self::Updates,
        Self::Transcoding,
    ];

    pub const fn index(self) -> usize {
        match self {
            Self::Services => 0,
            Self::Marketplace => 1,
            Self::Settings => 2,
            Self::Files => 3,
            Self::Users => 4,
            Self::Network => 5,
            Self::Updates => 6,
            Self::Transcoding => 7,
        }
    }

    pub const fn level(self, access: &AccessMapView) -> AccessLevel {
        match self {
            Self::Services => access.services,
            Self::Marketplace => access.marketplace,
            Self::Settings => access.settings,
            Self::Files => access.files,
            Self::Users => access.users,
            Self::Network => access.network,
            Self::Updates => access.updates,
            Self::Transcoding => access.transcoding,
        }
    }

    pub const fn label_key(self) -> &'static str {
        match self {
            Self::Services => "Cluster.areaServices",
            Self::Marketplace => "Cluster.areaMarketplace",
            Self::Settings => "Cluster.areaSettings",
            Self::Files => "Cluster.areaFiles",
            Self::Users => "Cluster.areaUsers",
            Self::Network => "Cluster.areaNetwork",
            Self::Updates => "Cluster.areaUpdates",
            Self::Transcoding => "Cluster.areaTranscoding",
        }
    }
}

/// Bitmask of effective read permissions across all `PeerArea` variants for the given server.
pub fn peer_area_read_mask(
    is_admin: bool,
    peer_id: Option<&str>,
    snapshot: Option<&PeersSnapshot>,
    cached: Option<&PeerLinkView>,
) -> u8 {
    let Some(peer_id) = peer_id else {
        return u8::MAX;
    };
    if !is_admin {
        return 0;
    }
    if !evaluate_active_peer_health(peer_id, snapshot, cached).allows_management() {
        return 0;
    }
    let peer = snapshot
        .and_then(|snap| snap.peers.iter().find(|p| p.id == peer_id))
        .or_else(|| cached.filter(|p| p.id == peer_id));
    let Some(grant) = peer.and_then(|p| p.grants.outbound.as_ref()) else {
        return 0;
    };
    let mut mask = 0u8;
    for area in PeerArea::ALL {
        if area.level(&grant.access).allows_read() {
            mask |= 1 << area.index();
        }
    }
    mask
}

/// Evaluates whether a peer in `snapshot` currently permits management read access to `area`.
pub fn peer_snapshot_allows_area_read(
    peer_id: &str,
    snapshot: &PeersSnapshot,
    area: PeerArea,
) -> bool {
    if !evaluate_active_peer_health(peer_id, Some(snapshot), None).allows_management() {
        return false;
    }
    snapshot
        .peers
        .iter()
        .find(|p| p.id == peer_id)
        .and_then(|p| p.grants.outbound.as_ref())
        .is_some_and(|grant| area.level(&grant.access).allows_read())
}

/// Canonical validated public DNS hostname check shared across remote share origins
/// and remote app launches (Services, Marketplace, MediaFlow). Rejects loopback,
/// localhost, internal/LAN suffixes, single-label names, numeric TLDs, and IP literals.
pub fn is_valid_public_remote_host(host: &str) -> bool {
    let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".localdomain")
        || host.ends_with(".aether.local")
        || host.ends_with(".internal")
        || host.ends_with(".lan")
        || host.ends_with(".home.arpa")
        || host.ends_with(".home")
        || host.ends_with(".corp")
        || host.ends_with(".intranet")
        || host.ends_with(".private")
        || host.ends_with(".localnet")
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) && labels
        .last()
        .is_some_and(|tld| !tld.bytes().all(|byte| byte.is_ascii_digit()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerAccent {
    pub key: &'static str,
    pub bar_class: &'static str,
    pub dot_class: &'static str,
    pub text_class: &'static str,
    pub badge_tone: &'static str,
}

const SERVER_PALETTE: [ServerAccent; 6] = [
    ServerAccent {
        key: "cyan",
        bar_class: "bg-cyan-500/10 border-cyan-500/30",
        dot_class: "bg-cyan-400",
        text_class: "text-cyan-200",
        badge_tone: "indigo",
    },
    ServerAccent {
        key: "emerald",
        bar_class: "bg-emerald-500/10 border-emerald-500/30",
        dot_class: "bg-emerald-400",
        text_class: "text-emerald-200",
        badge_tone: "success",
    },
    ServerAccent {
        key: "amber",
        bar_class: "bg-amber-500/10 border-amber-500/30",
        dot_class: "bg-amber-400",
        text_class: "text-amber-200",
        badge_tone: "warning",
    },
    ServerAccent {
        key: "indigo",
        bar_class: "bg-indigo-500/10 border-indigo-400/35",
        dot_class: "bg-indigo-400",
        text_class: "text-indigo-200",
        badge_tone: "indigo",
    },
    ServerAccent {
        key: "sky",
        bar_class: "bg-sky-500/10 border-sky-500/30",
        dot_class: "bg-sky-400",
        text_class: "text-sky-200",
        badge_tone: "indigo",
    },
    ServerAccent {
        key: "rose",
        bar_class: "bg-rose-500/10 border-rose-500/30",
        dot_class: "bg-rose-500",
        text_class: "text-rose-200",
        badge_tone: "danger",
    },
];

/// Deterministic, stable visual accent for a given peer ID.
pub fn server_accent(peer_id: &str) -> ServerAccent {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in peer_id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    SERVER_PALETTE[(hash as usize) % SERVER_PALETTE.len()]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivePeerHealth {
    Healthy,
    Limited,
    Unreachable,
    Incompatible,
    Revoked,
    NoGrant,
}

impl ActivePeerHealth {
    pub const fn allows_management(self) -> bool {
        matches!(self, Self::Healthy | Self::Limited)
    }

    pub const fn status_key(self) -> &'static str {
        match self {
            Self::Healthy => "PeerSwitch.statusHealthy",
            Self::Limited => "PeerSwitch.statusLimited",
            Self::Unreachable => "PeerSwitch.statusUnreachable",
            Self::Incompatible => "PeerSwitch.statusIncompatible",
            Self::Revoked => "PeerSwitch.statusRevoked",
            Self::NoGrant => "PeerSwitch.statusNoGrant",
        }
    }

    pub const fn badge_tone(self) -> &'static str {
        match self {
            Self::Healthy => "success",
            Self::Limited => "warning",
            Self::Unreachable | Self::Incompatible | Self::Revoked | Self::NoGrant => "danger",
        }
    }
}

pub fn normalize_server_selection(server: Option<String>) -> Option<String> {
    let trimmed = server?.trim().to_string();
    if trimmed.is_empty() || matches!(trimmed.as_str(), "." | "..") {
        return None;
    }
    Some(trimmed)
}

/// Matches backend peer proxy compatibility gating:
/// - `compatible`: eligible for remote management
/// - `limited`: eligible only when `grants` capability is not missing
/// - `unknown`, `incompatible`, or unrecognized values: fail closed (ineligible)
pub fn peer_compatibility_supports_management(peer: &PeerLinkView) -> bool {
    match peer.compatibility.as_str() {
        "compatible" => true,
        "limited" => !peer
            .missing_capabilities
            .iter()
            .any(|missing| missing.eq_ignore_ascii_case("grants")),
        _ => false,
    }
}

/// Evaluates whether a peer row can be selected for remote management.
pub fn peer_switch_eligibility(peer: &PeerLinkView) -> Result<(), &'static str> {
    if peer.state == "revoked" {
        return Err("PeerSwitch.peerRevoked");
    }
    if peer.state == "down" {
        return Err("PeerSwitch.peerUnreachable");
    }
    if peer.state == "pending" {
        return Err("PeerSwitch.peerPending");
    }
    if peer.state != "active" {
        return Err("PeerSwitch.peerUnavailable");
    }
    if !peer_compatibility_supports_management(peer) {
        return Err("PeerSwitch.peerIncompatible");
    }
    if !peer
        .grants
        .outbound
        .as_ref()
        .is_some_and(|grant| grant.access.has_any_access())
    {
        return Err("PeerSwitch.noOutboundGrant");
    }
    Ok(())
}

/// Evaluates live health/eligibility of an already-selected peer against the latest snapshot.
pub fn evaluate_active_peer_health(
    peer_id: &str,
    snapshot: Option<&PeersSnapshot>,
    cached: Option<&PeerLinkView>,
) -> ActivePeerHealth {
    let peer = match snapshot {
        Some(snap) => match snap.peers.iter().find(|item| item.id == peer_id) {
            Some(found) => found,
            None => return ActivePeerHealth::Revoked,
        },
        None => match cached {
            Some(found) if found.id == peer_id => found,
            _ => return ActivePeerHealth::Revoked,
        },
    };
    if peer.state == "revoked" {
        return ActivePeerHealth::Revoked;
    }
    if peer.state == "down" {
        return ActivePeerHealth::Unreachable;
    }
    if peer.state != "active" {
        return ActivePeerHealth::Revoked;
    }
    if !peer_compatibility_supports_management(peer) {
        return ActivePeerHealth::Incompatible;
    }
    if !peer
        .grants
        .outbound
        .as_ref()
        .is_some_and(|grant| grant.access.has_any_access())
    {
        return ActivePeerHealth::NoGrant;
    }
    if peer.compatibility == "limited" {
        return ActivePeerHealth::Limited;
    }
    ActivePeerHealth::Healthy
}

pub fn peer_has_capability(peer: &PeerLinkView, capability: &str) -> bool {
    if !peer_compatibility_supports_management(peer) {
        return false;
    }
    !peer
        .missing_capabilities
        .iter()
        .any(|missing| missing.eq_ignore_ascii_case(capability))
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ServerStateSnapshot {
    pub(crate) settings: Value,
    pub(crate) metrics: Value,
    pub(crate) services: Value,
    pub(crate) live_samples: Vec<Sample>,
    pub(crate) pending: usize,
    pub(crate) notifications: Vec<Value>,
    pub(crate) banners: Vec<String>,
}
