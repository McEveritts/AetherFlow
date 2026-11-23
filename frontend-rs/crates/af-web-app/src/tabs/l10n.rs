//! Tab translations and canonical, reactively localized UI components.
#[cfg(test)]
mod catalog_tests;
use crate::state::AppContext;
use leptos::prelude::{Get, Track};

/// Locale for pure formatters, including notification after a lazy catalog load.
pub fn locale(context: AppContext) -> String {
    context.catalog_revision.track();
    context.locale.get()
}

pub fn tt(context: AppContext, key: &str) -> String {
    context.t(key)
}

pub fn tt_with(context: AppContext, key: &str, params: &[(&str, &str)]) -> String {
    context.t_with(key, params)
}

pub use af_web_ui::{
    Badge, ConfirmDialog, DataGrid, Drawer, EmptyState, Modal, ObsCard, SearchInput, TabPanel,
    TabsBar,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use leptos::prelude::*;

    #[test]
    fn named_tab_templates_interpolate_and_follow_locale_changes() {
        let owner = Owner::new();
        owner.with(|| {
            let context = AppContext::new();
            let versions = Memo::new(move |_| {
                tt_with(
                    context,
                    "Current version: {current} · Latest: {latest}",
                    &[("current", "v1"), ("latest", "v2")],
                )
            });
            let used = Memo::new(move |_| tt_with(context, "{pct}% used", &[("pct", "25.0")]));
            for (locale, version, quota) in [
                ("en", "Current version: v1 · Latest: v2", "25.0% used"),
                ("de", "Aktuelle Version: v1 · Neueste: v2", "25.0 % belegt"),
                ("dk", "Nuværende version: v1 · Seneste: v2", "25.0 % brugt"),
                ("es", "Versión actual: v1 · Última: v2", "25.0% usado"),
                (
                    "fr",
                    "Version actuelle : v1 · Dernière version : v2",
                    "25.0 % utilisés",
                ),
                ("zh", "当前版本：v1 · 最新版本：v2", "已用 25.0%"),
            ] {
                context.locale.set(locale.into());
                assert_eq!(versions.get(), version, "{locale}");
                assert_eq!(used.get(), quota, "{locale}");
            }
        });
    }

    #[test]
    fn translations_and_parameters_follow_the_live_context_locale() {
        let owner = Owner::new();
        owner.with(|| {
            let context = AppContext::new();
            let refresh = Memo::new(move |_| tt(context, "Common.refresh"));
            let transfers =
                Memo::new(move |_| tt_with(context, "McBrowser.transfers", &[("count", "3")]));
            for (locale, label, count) in [
                ("en", "Refresh", "Transfers (3)"),
                ("de", "Aktualisieren", "Übertragungen (3)"),
                ("dk", "Opdater", "Overførsler (3)"),
                ("es", "Actualizar", "Transferencias (3)"),
                ("fr", "Actualiser", "Transferts (3)"),
                ("zh", "刷新", "传输（3）"),
            ] {
                context.locale.set(locale.into());
                assert_eq!(refresh.get(), label, "{locale}");
                assert_eq!(transfers.get(), count, "{locale}");
            }
        });
    }

    #[test]
    fn cluster_peer_translations_replace_legacy_coordinator_wording_across_locales() {
        let owner = Owner::new();
        owner.with(|| {
            let context = AppContext::new();
            let heading = Memo::new(move |_| tt(context, "Tabs.clusterHeading"));
            let summary = Memo::new(move |_| {
                tt_with(
                    context,
                    "Cluster.peersSummary",
                    &[("total", "2"), ("healthy", "1"), ("protocol", "1")],
                )
            });
            for (locale, expected_heading) in [
                ("en", "Peer Clustering"),
                ("de", "Peer-Clustering"),
                ("dk", "Peer-klyngedrift"),
                ("es", "Clúster entre pares"),
                ("fr", "Clustering entre pairs"),
                ("zh", "对等集群"),
            ] {
                context.locale.set(locale.into());
                assert_eq!(heading.get(), expected_heading, "{locale}");
                let rendered = summary.get();
                assert!(
                    rendered.contains('2') && rendered.contains('1'),
                    "{locale}: {rendered}"
                );
                assert_ne!(rendered, "Cluster.peersSummary", "{locale}");
            }
            for retired in [
                "AetherFlow coordinator",
                "Cluster.coordinatorView",
                "Cluster.nodesSummary",
                "Enroll Worker Node",
                "Remove this worker node?",
            ] {
                for locale in ["en", "de"] {
                    assert_eq!(
                        af_web_core::i18n::translate(locale, retired),
                        retired,
                        "retired legacy cluster key still present ({locale}): {retired}"
                    );
                }
            }
        });
    }
}
