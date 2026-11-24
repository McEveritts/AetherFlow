//! Tab translations and canonical, reactively localized UI components.
#[cfg(test)]
mod catalog_tests;
use crate::state::{app, AppContext};
use leptos::prelude::*;

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
    Badge, DataGrid, Drawer, EmptyState, Modal, ObsCard, SearchInput, TabPanel, TabsBar,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedServer {
    pub server_id: Option<String>,
    pub server_name: Option<String>,
    pub server_epoch: u64,
}

impl CapturedServer {
    pub fn current(context: AppContext) -> Self {
        Self {
            server_id: context.active_server_id.get_untracked(),
            server_name: context.active_server_name_untracked(),
            server_epoch: context.server_epoch.get_untracked(),
        }
    }

    pub fn still_matches(&self, context: AppContext) -> bool {
        context.server_epoch.try_get_untracked() == Some(self.server_epoch)
            && context.active_server_id.try_get_untracked() == Some(self.server_id.clone())
    }
}

/// Captures the active server when `open` transitions to `true` and automatically
/// closes the dialog if the active server changes before confirmation completes.
pub fn guard_modal_server_switch(open: RwSignal<bool>) -> RwSignal<Option<CapturedServer>> {
    let context = app();
    let captured = RwSignal::new(None::<CapturedServer>);
    Effect::new(move |_| {
        if open.get() {
            if captured.with_untracked(Option::is_none) {
                captured.set(Some(CapturedServer::current(context)));
            }
        } else {
            captured.set(None);
        }
    });
    Effect::new(move |_| {
        let current_epoch = context.server_epoch.get();
        let current_id = context.active_server_id.get();
        if open.get_untracked() {
            let stale = captured.with_untracked(|entry| {
                entry.as_ref().is_some_and(|saved| {
                    saved.server_epoch != current_epoch || saved.server_id != current_id
                })
            });
            if stale {
                open.set(false);
                captured.set(None);
            }
        }
    });
    captured
}

pub fn confirm_dialog_title(context: AppContext, title: &str, server_name: Option<&str>) -> String {
    let localized = tt(context, title);
    match server_name {
        Some(server) if !server.trim().is_empty() => tt_with(
            context,
            "PeerSwitch.confirmTitleOnServer",
            &[("title", &localized), ("server", server)],
        ),
        _ => localized,
    }
}

/// Destructive confirmation dialog aware of the active remote server:
/// includes the target server name in the heading and callout, and closes / blocks
/// confirmation if the active server changes while the dialog is open.
#[component]
pub fn ConfirmDialog(
    open: RwSignal<bool>,
    #[prop(into)] title: TextProp,
    #[prop(into)] message: TextProp,
    #[prop(optional, into)] confirm_label: Option<TextProp>,
    #[prop(optional, into)] busy: Signal<bool>,
    on_confirm: Callback<()>,
) -> impl IntoView {
    let context = app();
    let captured = guard_modal_server_switch(open);
    let modal_title = Signal::derive(move || {
        let raw = title.get();
        let server_name = captured
            .get()
            .and_then(|c| c.server_name)
            .or_else(|| context.active_server_name());
        confirm_dialog_title(context, &raw, server_name.as_deref())
    });
    let confirm_text = Signal::derive(move || {
        confirm_label
            .as_ref()
            .map(|label| tt(context, &label.get()))
            .unwrap_or_else(|| tt(context, "Confirm"))
    });
    view! {
        <Modal open title=modal_title>
            {move || {
                captured
                    .get()
                    .and_then(|c| c.server_name)
                    .or_else(|| context.active_server_name())
                    .map(|server_name| {
                        let accent = context.active_server_accent();
                        let banner_class = accent
                            .map(|a| format!("mb-4 rounded-xl border px-3 py-2 text-xs font-medium flex items-center gap-2 {} {}", a.bar_class, a.text_class))
                            .unwrap_or_else(|| "mb-4 rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs font-medium text-amber-200 flex items-center gap-2".into());
                        let dot_class = accent
                            .map(|a| format!("w-2 h-2 rounded-full shrink-0 {}", a.dot_class))
                            .unwrap_or_else(|| "w-2 h-2 rounded-full shrink-0 bg-amber-400".into());
                        view! {
                            <p
                                data-testid="confirm-target-server"
                                class=banner_class
                            >
                                <span class=dot_class aria-hidden="true"></span>
                                <span>
                                    {tt_with(
                                        context,
                                        "PeerSwitch.confirmTargetServer",
                                        &[("server", &server_name)],
                                    )}
                                </span>
                            </p>
                        }
                    })
            }}
            <p class="text-slate-300 text-sm mb-6">{move || tt(context, &message.get())}</p>
            <div class="flex justify-end gap-3">
                <button
                    type="button"
                    class="glass-button px-4 py-2"
                    disabled=move || busy.get()
                    on:click=move |_| open.set(false)
                >
                    {move || tt(context, "Cancel")}
                </button>
                <button
                    type="button"
                    class="glass-button-primary px-4 py-2"
                    disabled=move || busy.get()
                    on:click=move |_| {
                        let valid = captured
                            .get_untracked()
                            .is_some_and(|saved| saved.still_matches(context));
                        if !valid {
                            open.set(false);
                            context.toast("PeerSwitch.staleConfirmBlocked", true);
                            return;
                        }
                        on_confirm.run(());
                    }
                >
                    {move || confirm_text.get()}
                </button>
            </div>
        </Modal>
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

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

    #[test]
    fn confirm_dialog_title_names_remote_server_and_peer_switch_catalog_translates() {
        let owner = Owner::new();
        owner.with(|| {
            let context = AppContext::new();
            assert_eq!(
                confirm_dialog_title(context, "Delete", None),
                tt(context, "Delete")
            );
            assert_eq!(
                confirm_dialog_title(context, "Delete", Some("Beta Media")),
                "Delete — Beta Media"
            );
            for locale in ["en", "de", "dk", "es", "fr", "zh"] {
                context.locale.set(locale.into());
                let title = confirm_dialog_title(context, "Delete", Some("Beta Media"));
                assert!(title.contains("Beta Media"), "{locale}: {title}");
                let banner = tt_with(
                    context,
                    "PeerSwitch.managingBanner",
                    &[("server", "Beta Media")],
                );
                assert!(banner.contains("Beta Media"), "{locale}: {banner}");
                assert_ne!(banner, "PeerSwitch.managingBanner", "{locale}");
            }
        });
    }
}
