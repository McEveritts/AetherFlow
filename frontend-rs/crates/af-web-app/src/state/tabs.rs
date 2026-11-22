use leptos::prelude::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TabId {
    #[default]
    Overview,
    Services,
    Marketplace,
    McBrowser,
    Fileshare,
    Streaming,
    Mediaflow,
    AiChat,
    Inbox,
    Network,
    Cluster,
    Users,
    Audit,
    Settings,
    Notifications,
    Quotas,
}
impl TabId {
    pub const ALL: [Self; 16] = [
        Self::Overview,
        Self::Inbox,
        Self::Services,
        Self::Marketplace,
        Self::McBrowser,
        Self::Fileshare,
        Self::Streaming,
        Self::Mediaflow,
        Self::AiChat,
        Self::Network,
        Self::Cluster,
        Self::Users,
        Self::Audit,
        Self::Settings,
        Self::Notifications,
        Self::Quotas,
    ];
    pub fn key(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Services => "services",
            Self::Marketplace => "marketplace",
            Self::McBrowser => "mcbrowser",
            Self::Fileshare => "fileshare",
            Self::Streaming => "streaming",
            Self::Mediaflow => "mediaflow",
            Self::AiChat => "ai",
            Self::Inbox => "inbox",
            Self::Network => "network",
            Self::Cluster => "cluster",
            Self::Users => "users",
            Self::Audit => "audit",
            Self::Settings => "settings",
            Self::Notifications => "notifications",
            Self::Quotas => "quotas",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Services => "Services",
            Self::Marketplace => "Marketplace",
            Self::McBrowser => "McBrowser",
            Self::Fileshare => "File Share",
            Self::Streaming => "Streaming",
            Self::Mediaflow => "MediaFlow",
            Self::AiChat => "FlowAI",
            Self::Inbox => "Approval Inbox",
            Self::Network => "Network",
            Self::Cluster => "Cluster",
            Self::Users => "Users",
            Self::Audit => "Audit Trail",
            Self::Settings => "Settings",
            Self::Notifications => "Notifications",
            Self::Quotas => "Quotas",
        }
    }
    pub fn icon(self) -> &'static str {
        match self {
            Self::Overview => "◇",
            Self::Services => "▤",
            Self::Marketplace => "◈",
            Self::McBrowser => "▱",
            Self::Fileshare => "↥",
            Self::Streaming => "▣",
            Self::Mediaflow => "▷",
            Self::AiChat => "✧",
            Self::Inbox => "✉",
            Self::Network => "◎",
            Self::Cluster => "⬡",
            Self::Users => "◎",
            Self::Audit => "≡",
            Self::Settings => "⚙",
            Self::Notifications => "◉",
            Self::Quotas => "◴",
        }
    }
    pub fn icon_svg(self) -> AnyView {
        stroke_icon(match self {
            Self::Overview => "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
            Self::Services => "M4 3h16v7H4z M4 14h16v7H4z M7 6.5h.01 M7 17.5h.01 M11 6.5h6 M11 17.5h6",
            Self::Marketplace => "M3 9 5 3h14l2 6 M3 9h18v3a3 3 0 0 1-6 0 3 3 0 0 1-6 0 3 3 0 0 1-6 0V9 M5 15v6h14v-6 M10 21v-5h4v5",
            Self::McBrowser => "M3 7V5a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z",
            Self::Fileshare => "M8 12h8 M15 6l3-3 3 3 M18 3v12 M6 3H4a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2 M6 7h5 M6 16h6",
            Self::Streaming => "M3 5h18v14H3z M8 22h8 M12 19v3 M10 9l5 3-5 3V9Z",
            Self::Mediaflow => "M4 3h16v18H4z M4 7h4 M4 12h4 M4 17h4 M16 7h4 M16 12h4 M16 17h4 M8 3v18 M16 3v18",
            Self::AiChat => "m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5L12 3Z M20 2v4 M18 4h4",
            Self::Inbox => "M3 13 6 4h12l3 9v7H3v-7Z M3 13h5l2 3h4l2-3h5",
            Self::Network => "M12 3a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z M5 16a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z M19 16a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z M12 9v3 M5 16v-4h14v4",
            Self::Cluster => "m12 2 9 5-9 5-9-5 9-5Z M3 12l9 5 9-5 M3 17l9 5 9-5",
            Self::Users => "M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z M2 21v-2a6 6 0 0 1 12 0v2 M17 3a4 4 0 0 1 0 8 M22 21v-2a6 6 0 0 0-4-5.66",
            Self::Audit => "M8 4H5v18h14V4h-3 M8 2h8v5H8z M8 12h8 M8 16h5",
            Self::Settings => "m9 3-1 3-3 1-2 3 2 2-1 3 3 2 1 3h4l1-3 3-1 2-3-2-2 1-3-3-2-1-3H9Z M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z",
            Self::Notifications => "M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9 M10 21h4",
            Self::Quotas => "M21 12a9 9 0 1 1-9-9v9h9Z M16 3a9 9 0 0 1 5 5h-5V3Z",
        })
    }
    pub fn localized_label(self, locale: &str) -> String {
        af_web_core::i18n::translate(locale, &format!("Navigation.{}", self.key()))
    }
    pub fn is_admin_only(self) -> bool {
        matches!(
            self,
            Self::Inbox | Self::Network | Self::Cluster | Self::Users | Self::Audit | Self::Quotas
        )
    }
    pub fn from_key(key: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|t| t.key() == key)
            .unwrap_or_default()
    }
}
pub fn stroke_icon(path: &'static str) -> AnyView {
    view! {<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d=path/></svg>}.into_any()
}

pub fn clamp_tab_for_role(tab: TabId, is_admin: bool) -> TabId {
    if tab.is_admin_only() && !is_admin {
        TabId::Overview
    } else {
        tab
    }
}
