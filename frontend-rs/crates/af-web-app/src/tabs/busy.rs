//! Release an operation's busy flag on completion, cancellation, or disposal.
use crate::state::{AppContext, PeerArea};
use leptos::prelude::*;
use std::collections::BTreeSet;

pub(super) struct BusyGuard {
    busy: Option<RwSignal<bool>>,
    generation: Option<(RwSignal<u64>, u64)>,
}

impl BusyGuard {
    pub(super) fn new(busy: RwSignal<bool>) -> Self {
        Self {
            busy: Some(busy),
            generation: None,
        }
    }

    pub(super) fn for_generation(
        busy: RwSignal<bool>,
        generation: RwSignal<u64>,
        ticket: u64,
    ) -> Self {
        Self {
            busy: Some(busy),
            generation: Some((generation, ticket)),
        }
    }

    pub(super) fn release(&mut self) {
        if let Some(busy) = self.busy.take() {
            if self
                .generation
                .is_none_or(|(generation, ticket)| generation.try_get_untracked() == Some(ticket))
            {
                let _ = busy.try_update(|busy| *busy = false);
            }
        }
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// Release a non-boolean busy signal (such as `String` or `Option<String>`) back
/// to `T::default()` only when `generation` still matches `ticket`.
pub(super) struct ValueBusyGuard<T: Default + Send + Sync + 'static> {
    busy: Option<RwSignal<T>>,
    generation: (RwSignal<u64>, u64),
}

impl<T: Default + Send + Sync + 'static> ValueBusyGuard<T> {
    pub(super) fn for_generation(
        busy: RwSignal<T>,
        generation: RwSignal<u64>,
        ticket: u64,
    ) -> Self {
        Self {
            busy: Some(busy),
            generation: (generation, ticket),
        }
    }

    pub(super) fn release(&mut self) {
        if let Some(busy) = self.busy.take() {
            if self.generation.0.try_get_untracked() == Some(self.generation.1) {
                let _ = busy.try_update(|slot| *slot = T::default());
            }
        }
    }
}

impl<T: Default + Send + Sync + 'static> Drop for ValueBusyGuard<T> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Remove a single busy key from a set signal only when `generation` still
/// matches `ticket`, preventing stale completions from clearing a newer run.
pub(super) struct SetBusyGuard {
    busy: Option<RwSignal<BTreeSet<String>>>,
    key: String,
    generation: (RwSignal<u64>, u64),
}

impl SetBusyGuard {
    pub(super) fn for_generation(
        busy: RwSignal<BTreeSet<String>>,
        key: String,
        generation: RwSignal<u64>,
        ticket: u64,
    ) -> Self {
        Self {
            busy: Some(busy),
            key,
            generation: (generation, ticket),
        }
    }

    pub(super) fn release(&mut self) {
        if let Some(busy) = self.busy.take() {
            if self.generation.0.try_get_untracked() == Some(self.generation.1) {
                let _ = busy.try_update(|set| {
                    set.remove(&self.key);
                });
            }
        }
    }
}

impl Drop for SetBusyGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// Snapshot of session, server, area grant, role, and local ticket state used to
/// fence multi-step dispatches and async mutation completions across in-place
/// permission downgrades (`Write -> Read -> Write`) and revocations (`-> None`).
#[derive(Clone, Copy)]
pub(super) struct AreaFence {
    context: AppContext,
    area: PeerArea,
    require_write: bool,
    require_admin: bool,
    session_epoch: u64,
    server_epoch: u64,
    grant_epoch: u64,
    generation: RwSignal<u64>,
    ticket: u64,
}

impl AreaFence {
    pub(super) fn capture(
        context: AppContext,
        area: PeerArea,
        require_write: bool,
        require_admin: bool,
        generation: RwSignal<u64>,
        ticket: u64,
    ) -> Self {
        Self {
            context,
            area,
            require_write,
            require_admin,
            session_epoch: context.session_epoch.get_untracked(),
            server_epoch: context.server_epoch.get_untracked(),
            grant_epoch: context.area_revocation_epoch_untracked(area),
            generation,
            ticket,
        }
    }

    pub(super) fn is_valid(self) -> bool {
        self.generation.try_get_untracked() == Some(self.ticket)
            && self.context.session_epoch.try_get_untracked() == Some(self.session_epoch)
            && self.context.server_epoch.try_get_untracked() == Some(self.server_epoch)
            && self.context.area_revocation_epoch_untracked(self.area) == self.grant_epoch
            && (!self.require_admin || self.context.is_admin_untracked())
            && if self.require_write {
                self.context.can_write_area_untracked(self.area)
            } else {
                self.context.can_read_area_untracked(self.area)
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_editor_load_and_save_release_busy_without_touching_new_requests() {
        let owner = Owner::new();
        owner.with(|| {
            let generation = RwSignal::new(1);
            for busy in [RwSignal::new(true), RwSignal::new(true)] {
                drop(BusyGuard::for_generation(busy, generation, 1));
                assert!(!busy.get_untracked());
                busy.set(true);
                let stale = BusyGuard::for_generation(busy, generation, 1);
                generation.set(2);
                drop(stale);
                assert!(
                    busy.get_untracked(),
                    "old completion unlocked a new operation"
                );
                generation.set(1);
            }
        });
    }

    #[test]
    fn explicit_completion_and_disposal_are_safe() {
        let owner = Owner::new();
        let mut guard = owner.with(|| {
            let busy = RwSignal::new(true);
            let mut guard = BusyGuard::new(busy);
            guard.release();
            busy.set(true);
            drop(guard);
            assert!(
                busy.get_untracked(),
                "completion released a later operation twice"
            );
            BusyGuard::new(busy)
        });
        owner.cleanup();
        guard.release();
    }

    #[test]
    fn value_busy_guard_releases_only_matching_generation() {
        let owner = Owner::new();
        let mut disposed_guard = owner.with(|| {
            let generation = RwSignal::new(1u64);
            let string_busy = RwSignal::new("restart".to_owned());
            let stale = ValueBusyGuard::for_generation(string_busy, generation, 1);
            generation.set(2);
            string_busy.set("stop".to_owned());
            drop(stale);
            assert_eq!(
                string_busy.get_untracked(),
                "stop",
                "stale guard cleared newer String busy value"
            );

            let mut current = ValueBusyGuard::for_generation(string_busy, generation, 2);
            current.release();
            assert!(string_busy.get_untracked().is_empty());
            string_busy.set("start".to_owned());
            drop(current);
            assert_eq!(
                string_busy.get_untracked(),
                "start",
                "double-release cleared a subsequent operation"
            );

            let opt_busy = RwSignal::new(Some("sonarr".to_owned()));
            drop(ValueBusyGuard::for_generation(opt_busy, generation, 2));
            assert_eq!(opt_busy.get_untracked(), None);

            opt_busy.set(Some("radarr".to_owned()));
            ValueBusyGuard::for_generation(opt_busy, generation, 2)
        });
        owner.cleanup();
        disposed_guard.release();
    }

    #[test]
    fn set_busy_guard_removes_only_matching_key_and_generation() {
        let owner = Owner::new();
        owner.with(|| {
            let generation = RwSignal::new(1u64);
            let busy = RwSignal::new(BTreeSet::from(["sonarr".to_owned(), "radarr".to_owned()]));
            let sonarr_gen1 =
                SetBusyGuard::for_generation(busy, "sonarr".to_owned(), generation, 1);
            let radarr_gen1 =
                SetBusyGuard::for_generation(busy, "radarr".to_owned(), generation, 1);

            drop(sonarr_gen1);
            assert!(!busy.with_untracked(|set| set.contains("sonarr")));
            assert!(
                busy.with_untracked(|set| set.contains("radarr")),
                "releasing one key must not remove a sibling key in the same generation"
            );

            // Simulate Write -> Read -> Write bumping generation and starting a new radarr run.
            generation.set(2);
            busy.update(|set| {
                set.clear();
                set.insert("radarr".to_owned());
            });
            drop(radarr_gen1);
            assert!(
                busy.with_untracked(|set| set.contains("radarr")),
                "stale gen-1 drop must not remove gen-2 key"
            );
        });
    }

    #[test]
    fn area_fence_tracks_write_downgrade_revocation_read_only_and_local_modes() {
        use crate::tabs::cluster::peers::PeersSnapshot;
        use serde_json::json;

        Owner::new().with(|| {
            let context = AppContext::new();
            context.apply_authenticated_user(
                json!({"id": 1, "username": "admin", "role": "admin"}),
                false,
            );
            let mk_snapshot = |files: &str, services: &str, settings: &str| {
                serde_json::from_value::<PeersSnapshot>(json!({
                    "local_protocol_version": 1,
                    "local_capabilities": ["links", "grants", "proxy.http.v1"],
                    "peers": [{
                        "id": "peer-fence",
                        "name": "Fence Peer",
                        "state": "active",
                        "compatibility": "compatible",
                        "missing_capabilities": [],
                        "grants": {
                            "outbound": {
                                "id": "g-fence",
                                "run_as_user_id": 1,
                                "access": {
                                    "services": services,
                                    "settings": settings,
                                    "files": files,
                                    "marketplace": "write",
                                    "users": "read",
                                    "network": "write",
                                    "updates": "read",
                                    "transcoding": "read"
                                }
                            }
                        }
                    }]
                }))
                .unwrap()
            };

            context.apply_peers_snapshot(mk_snapshot("write", "write", "write"));
            assert!(context.select_server(Some("peer-fence".into())));

            let files_write_gen = RwSignal::new(1u64);
            let files_read_gen = RwSignal::new(1u64);
            let services_write_gen = RwSignal::new(1u64);

            let files_write_fence =
                AreaFence::capture(context, PeerArea::Files, true, false, files_write_gen, 1);
            let files_read_fence =
                AreaFence::capture(context, PeerArea::Files, false, false, files_read_gen, 1);
            let services_write_fence = AreaFence::capture(
                context,
                PeerArea::Services,
                true,
                true,
                services_write_gen,
                1,
            );
            assert!(files_write_fence.is_valid());
            assert!(files_read_fence.is_valid());
            assert!(services_write_fence.is_valid());

            // In-place Files Write -> Read immediately invalidates Files write fence
            // while preserving intentionally read-only Files work and separately authorized Services work.
            context.apply_peers_snapshot(mk_snapshot("read", "write", "write"));
            assert!(!files_write_fence.is_valid());
            assert!(files_read_fence.is_valid());
            assert!(services_write_fence.is_valid());

            // Write-loss effect bumps local write generation; subsequent Read -> Write keeps old run invalid.
            files_write_gen.set(2);
            context.apply_peers_snapshot(mk_snapshot("write", "write", "write"));
            assert!(!files_write_fence.is_valid());
            assert!(files_read_fence.is_valid());
            let files_write_fence_2 =
                AreaFence::capture(context, PeerArea::Files, true, false, files_write_gen, 2);
            assert!(files_write_fence_2.is_valid());

            // Full Files revocation (-> None) bumps area_revocation_epoch so read fence stays invalid even after re-grant.
            context.apply_peers_snapshot(mk_snapshot("none", "write", "write"));
            assert!(!files_read_fence.is_valid());
            assert!(!files_write_fence_2.is_valid());
            assert!(services_write_fence.is_valid());
            context.apply_peers_snapshot(mk_snapshot("write", "write", "write"));
            assert!(!files_read_fence.is_valid());
            assert!(!files_write_fence_2.is_valid());

            // Same-user demotion to non-admin invalidates admin fences, while local non-admin
            // AI Chat (require_admin = false) remains authorized on the local server.
            context.apply_authenticated_user(
                json!({"id": 1, "username": "admin", "role": "user"}),
                false,
            );
            assert!(!services_write_fence.is_valid());
            let local_gen = RwSignal::new(1u64);
            let local_ai_chat_fence =
                AreaFence::capture(context, PeerArea::Settings, true, false, local_gen, 1);
            let local_admin_settings_fence =
                AreaFence::capture(context, PeerArea::Settings, true, true, local_gen, 1);
            assert!(local_ai_chat_fence.is_valid());
            assert!(!local_admin_settings_fence.is_valid());
        });
    }
}
