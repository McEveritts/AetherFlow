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

use crate::state::{app, TabId};
use leptos::prelude::*;

#[component]
pub fn TabRouter() -> impl IntoView {
    let context = app();
    let mcbrowser_visited = RwSignal::new(context.tab.get_untracked() == TabId::McBrowser);
    Effect::new(move |_| {
        if context.tab.get() == TabId::McBrowser {
            mcbrowser_visited.set(true);
        }
    });
    view! {
        // Mount on first visit, then preserve transfers, selection and editor drafts.
        <Show when=move || mcbrowser_visited.get()>
            <div class:hidden=move || context.tab.get() != TabId::McBrowser>
                <mcbrowser::McBrowserTab />
            </div>
        </Show>
        {move || match context.tab.get() {
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
        }}
    }
}

#[cfg(test)]
mod tests {
    use crate::state::{clamp_tab_for_role, TabId};

    #[test]
    fn cluster_tab_routing_keeps_cluster_query_key_and_admin_restriction() {
        assert_eq!(TabId::from_key("cluster"), TabId::Cluster);
        assert_eq!(TabId::Cluster.key(), "cluster");
        assert_eq!(clamp_tab_for_role(TabId::Cluster, true), TabId::Cluster);
        assert_eq!(clamp_tab_for_role(TabId::Cluster, false), TabId::Overview);
    }
}
