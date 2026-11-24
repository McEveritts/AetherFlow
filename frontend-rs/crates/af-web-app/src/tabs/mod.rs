//! Stable Wave 2 extension boundary. Builders can replace any module's component
//! internals without editing the dispatcher, shell or application entry point.
pub mod ai_chat;
pub mod audit;
mod busy;
pub mod cluster;
pub mod contracts;
pub mod fileshare;
pub mod inbox;
pub mod l10n;
pub mod marketplace;
pub mod mcbrowser;
pub mod mediaflow;
pub mod network;
pub mod notifications;
pub mod overview;
pub mod quotas;
pub mod services;
pub mod settings;
pub mod streaming;
pub mod users;

use crate::state::{app, PeerArea, TabId};
use leptos::prelude::*;

/// Primary `PeerArea` read grants whose live revocation invalidates the mounted tab view.
/// Multi-area panels inside `Overview`, `Settings`, `Network`, `Mediaflow`, `Streaming`,
/// and `Notifications` use `GrantInvalidationBoundary` for fine-grained invalidation.
pub(crate) fn tab_grant_areas(tab: TabId) -> &'static [PeerArea] {
    match tab {
        TabId::Services | TabId::Inbox | TabId::Streaming => &[PeerArea::Services],
        TabId::Marketplace => &[PeerArea::Marketplace],
        TabId::Fileshare | TabId::McBrowser => &[PeerArea::Files],
        TabId::Network => &[PeerArea::Network],
        TabId::Users | TabId::Quotas => &[PeerArea::Users],
        TabId::Audit => &[PeerArea::Settings],
        TabId::Overview
        | TabId::Mediaflow
        | TabId::AiChat
        | TabId::Settings
        | TabId::Notifications
        | TabId::Cluster => &[],
    }
}

/// Reusable central invalidation boundary that unmounts and remounts server-scoped
/// subviews cleanly whenever the active server changes or any listed `PeerArea`
/// loses read access on the active peer.
#[component]
pub(crate) fn GrantInvalidationBoundary(
    areas: &'static [PeerArea],
    children: ChildrenFn,
) -> impl IntoView {
    let context = app();
    let owner_key = Memo::new(move |_| {
        (
            context.server_epoch.get(),
            context.areas_revocation_epoch(areas),
        )
    });
    view! {
        <For
            each=move || [owner_key.get()]
            key=|entry| *entry
            children=move |_| children()
        />
    }
}

/// Server-scoped views are keyed by `(server_epoch, grant_epoch)` so switching servers
/// or losing primary area read access disposes mounted loaders, modals, drawers, timers,
/// and in-flight reads cleanly.
/// `TabId::Cluster` owns local-only pairing and grant workflows and never remounts
/// on server switch or grant changes; `TabId::McBrowser` has its own keyed lifecycle below.
fn tab_view_owner_key(tab: TabId, server_epoch: u64, grant_epoch: u64) -> (TabId, u64, u64) {
    if matches!(tab, TabId::Cluster | TabId::McBrowser) {
        (tab, 0, 0)
    } else {
        (tab, server_epoch, grant_epoch)
    }
}

/// Keeps McBrowser mounted across tab switches on the same server to preserve
/// active transfers and editor drafts, while disposing it on server switch or
/// Files read revocation and avoiding hidden mounts on a new server until visited.
fn next_mcbrowser_mount_epoch(
    current: Option<(u64, u64)>,
    tab: TabId,
    server_epoch: u64,
    files_grant_epoch: u64,
) -> Option<(u64, u64)> {
    let target = (server_epoch, files_grant_epoch);
    if tab == TabId::McBrowser {
        Some(target)
    } else if current == Some(target) {
        current
    } else {
        None
    }
}

#[component]
pub fn TabRouter() -> impl IntoView {
    let context = app();
    let mcbrowser_epoch = RwSignal::new(next_mcbrowser_mount_epoch(
        None,
        context.tab.get_untracked(),
        context.server_epoch.get_untracked(),
        context.area_revocation_epoch_untracked(PeerArea::Files),
    ));
    Effect::new(move |_| {
        let next = next_mcbrowser_mount_epoch(
            mcbrowser_epoch.get_untracked(),
            context.tab.get(),
            context.server_epoch.get(),
            context.area_revocation_epoch(PeerArea::Files),
        );
        if mcbrowser_epoch.get_untracked() != next {
            mcbrowser_epoch.set(next);
        }
    });
    let active_view_key = Memo::new(move |_| {
        let tab = context.tab.get();
        let grant_epoch = context.areas_revocation_epoch(tab_grant_areas(tab));
        tab_view_owner_key(tab, context.server_epoch.get(), grant_epoch)
    });
    view! {
        // Mount on first visit per server, preserve same-server transfers/drafts across tabs,
        // and tear down cleanly when the active server changes or Files read is revoked.
        <For
            each=move || mcbrowser_epoch.get()
            key=|epoch| *epoch
            children=move |_| {
                view! {
                    <div class:hidden=move || context.tab.get() != TabId::McBrowser>
                        <mcbrowser::McBrowserTab />
                    </div>
                }
            }
        />
        <For
            each=move || [active_view_key.get()]
            key=|entry| *entry
            children=move |(tab, _, _)| match tab {
                TabId::Overview => view! { <overview::OverviewTab /> }.into_any(),
                TabId::Services => view! { <services::ServicesTab /> }.into_any(),
                TabId::Marketplace => view! { <marketplace::MarketplaceTab /> }.into_any(),
                TabId::McBrowser => ().into_any(),
                TabId::Fileshare => view! { <fileshare::FileshareTab /> }.into_any(),
                TabId::Streaming => view! { <streaming::StreamingTab /> }.into_any(),
                TabId::Mediaflow => view! { <mediaflow::MediaflowTab /> }.into_any(),
                TabId::AiChat => view! { <ai_chat::AiChatTab /> }.into_any(),
                TabId::Inbox => view! { <inbox::InboxTab /> }.into_any(),
                TabId::Network => view! { <network::NetworkTab /> }.into_any(),
                TabId::Cluster => view! { <cluster::ClusterTab /> }.into_any(),
                TabId::Users => view! { <users::UsersTab /> }.into_any(),
                TabId::Audit => view! { <audit::AuditTab /> }.into_any(),
                TabId::Settings => view! { <settings::SettingsTab /> }.into_any(),
                TabId::Notifications => view! { <notifications::NotificationsTab /> }.into_any(),
                TabId::Quotas => view! { <quotas::QuotasTab /> }.into_any(),
            }
        />
    }
}

#[cfg(test)]
mod tests {
    use super::{next_mcbrowser_mount_epoch, tab_grant_areas, tab_view_owner_key};
    use crate::state::{clamp_tab_for_role, PeerArea, TabId};

    #[test]
    fn cluster_tab_routing_keeps_cluster_query_key_and_admin_restriction() {
        assert_eq!(TabId::from_key("cluster"), TabId::Cluster);
        assert_eq!(TabId::Cluster.key(), "cluster");
        assert_eq!(clamp_tab_for_role(TabId::Cluster, true), TabId::Cluster);
        assert_eq!(clamp_tab_for_role(TabId::Cluster, false), TabId::Overview);
    }

    #[test]
    fn tab_router_keys_server_owned_views_by_server_and_grant_epochs_without_remounting_cluster() {
        for tab in [
            TabId::Overview,
            TabId::Services,
            TabId::Marketplace,
            TabId::Fileshare,
            TabId::Streaming,
            TabId::Mediaflow,
            TabId::AiChat,
            TabId::Inbox,
            TabId::Network,
            TabId::Users,
            TabId::Audit,
            TabId::Settings,
            TabId::Notifications,
            TabId::Quotas,
        ] {
            assert_eq!(tab_view_owner_key(tab, 0, 0), (tab, 0, 0));
            assert_eq!(tab_view_owner_key(tab, 4, 2), (tab, 4, 2));
            assert_ne!(tab_view_owner_key(tab, 0, 0), tab_view_owner_key(tab, 1, 0));
            assert_ne!(tab_view_owner_key(tab, 4, 0), tab_view_owner_key(tab, 4, 1));
        }

        // Local pairing/grant state in Cluster stays mounted across server switches and grant revocations.
        assert_eq!(tab_grant_areas(TabId::Cluster), &[]);
        assert_eq!(
            tab_view_owner_key(TabId::Cluster, 0, 0),
            (TabId::Cluster, 0, 0)
        );
        assert_eq!(
            tab_view_owner_key(TabId::Cluster, 7, 3),
            (TabId::Cluster, 0, 0)
        );
        assert_eq!(tab_grant_areas(TabId::Services), &[PeerArea::Services]);
        assert_eq!(tab_grant_areas(TabId::Network), &[PeerArea::Network]);

        // McBrowser mounts per (server_epoch, files_grant_epoch), stays alive across
        // same-server tab switches, and disposes on server switch or Files read revocation.
        assert_eq!(
            next_mcbrowser_mount_epoch(None, TabId::Overview, 0, 0),
            None
        );
        assert_eq!(
            next_mcbrowser_mount_epoch(None, TabId::McBrowser, 0, 0),
            Some((0, 0))
        );
        assert_eq!(
            next_mcbrowser_mount_epoch(Some((0, 0)), TabId::Overview, 0, 0),
            Some((0, 0))
        );
        assert_eq!(
            next_mcbrowser_mount_epoch(Some((0, 0)), TabId::Overview, 1, 0),
            None
        );
        assert_eq!(
            next_mcbrowser_mount_epoch(Some((0, 0)), TabId::Overview, 0, 1),
            None
        );
        assert_eq!(
            next_mcbrowser_mount_epoch(Some((0, 0)), TabId::McBrowser, 0, 1),
            Some((0, 1))
        );
    }
}
