//! Fileshare layout and authentication-scoped, component-owned bearer URLs.
use crate::state::app;
use crate::tabs::l10n::{tt, TabPanel, TabsBar};
use leptos::prelude::*;
use serde_json::Value;
use std::collections::BTreeMap;
mod local_storage;
mod paths;
mod policy_audit;
mod shares;
mod storage;
mod types;
mod upload;
pub(crate) use local_storage::DirectoryPicker;
use local_storage::LocalStorage;
pub(crate) use paths::parent_path;
pub(super) use paths::{encode, relative_path, text};
use policy_audit::{ShareAuditView, SharePolicyView};
use shares::PublicShareLinks;
pub(super) use shares::{
    share_origin_available, share_origin_available_untracked, share_origin_block_reason,
    share_url_for_context_untracked, ShareCreateModal, ShareLinkDetails,
};
pub(crate) use upload::upload_id;
const SHARES: &str = "/api/v1/auth/mcbrowser/shares";
const SHARES_CHANGED: &str = "af:mcbrowser-shares-changed";

// Bearer URLs belong to this mounted component, auth epoch, active server, and grant epoch.
#[derive(Clone, Copy)]
struct CreatedShareUrls(RwSignal<(u64, u64, u64, BTreeMap<String, String>)>);

const SHARE_GRANT_AREAS: [crate::state::PeerArea; 2] = [
    crate::state::PeerArea::Files,
    crate::state::PeerArea::Settings,
];

fn cached_url(
    context: crate::state::AppContext,
    cache: Option<CreatedShareUrls>,
    id: &str,
) -> Option<String> {
    if !context.can_read_area(crate::state::PeerArea::Files) || !share_origin_available(context) {
        return None;
    }
    let auth = context.session_epoch.get();
    let server = context.server_epoch.get();
    let grant = context.areas_revocation_epoch(&SHARE_GRANT_AREAS);
    cache?.0.with(|cache| {
        (cache.0 == auth && cache.1 == server && cache.2 == grant)
            .then(|| cache.3.get(id).cloned())
            .flatten()
    })
}

fn remember_url(
    context: crate::state::AppContext,
    cache: Option<CreatedShareUrls>,
    auth: u64,
    server: u64,
    grant: u64,
    row: &Value,
) {
    if !context.can_read_area_untracked(crate::state::PeerArea::Files)
        || !share_origin_available_untracked(context)
    {
        return;
    }
    let Some(url) = share_url_for_context_untracked(context, row) else {
        return;
    };
    if let Some(cache) = cache {
        cache.0.update(|cache| {
            if cache.0 != auth || cache.1 != server || cache.2 != grant {
                *cache = (auth, server, grant, BTreeMap::new());
            }
            cache.3.insert(text(row, "id"), url);
        });
    }
    if let (Some(window), Ok(event)) = (web_sys::window(), web_sys::Event::new(SHARES_CHANGED)) {
        let _ = window.dispatch_event(&event);
    }
}

#[component]
pub fn FileshareTab() -> impl IntoView {
    let context = app();
    let urls = CreatedShareUrls(RwSignal::new((
        context.session_epoch.get_untracked(),
        context.server_epoch.get_untracked(),
        context.areas_revocation_epoch_untracked(&SHARE_GRANT_AREAS),
        BTreeMap::new(),
    )));
    provide_context(urls);
    Effect::new(move |_| {
        let auth = context.session_epoch.get();
        let server = context.server_epoch.get();
        let grant = context.areas_revocation_epoch(&SHARE_GRANT_AREAS);
        let origin_ok = share_origin_available(context);
        let files_ok = context.can_read_area(crate::state::PeerArea::Files);
        urls.0.update(|cache| {
            if cache.0 != auth || cache.1 != server || cache.2 != grant || !origin_ok || !files_ok {
                *cache = (auth, server, grant, BTreeMap::new());
            }
        });
    });
    let active = RwSignal::new("local".to_owned());
    view! {
        <section class="space-y-5 py-5 min-w-0 max-w-full">
            <div>
                <h2 class="text-xl font-semibold">
                    {move || tt(context, "Tabs.fileshareHeading")}
                </h2>
                <p class="text-sm text-slate-400 mt-1">
                    {move || tt(context, "Fileshare.subtitle")}
                </p>
            </div>
            <TabsBar
                id_prefix="fileshare"
                active
                tabs=Signal::derive(move || {
                    let mut tabs = vec![
                        ("local".into(), tt(context, "Fileshare.localStorage")),
                        ("shares".into(), tt(context, "Fileshare.publicShareLinks")),
                        ("policy".into(), tt(context, "Share policy")),
                    ];
                    if context.is_admin() { tabs.push(("audit".into(), tt(context, "Audit log"))); }
                    tabs
                })
            />
            <TabPanel id_prefix="fileshare" id=Signal::derive(move || active.get())>
                <Show when=move || active.get() == "local">
                    <LocalStorage />
                </Show>
                <Show when=move || active.get() == "shares">
                    <PublicShareLinks />
                </Show>
                <Show when=move || active.get() == "policy"><SharePolicyView /></Show>
                <Show when=move || active.get() == "audit" && context.is_admin()><ShareAuditView /></Show>
            </TabPanel>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::paths::*;
    use super::storage::*;
    use super::types::*;
    use super::upload::*;
    use super::*;
    use serde_json::json;

    #[test]
    fn created_share_urls_are_component_and_authentication_scoped() {
        let owner = Owner::new();
        owner.with(|| {
            let context = crate::state::AppContext::new();
            let auth = context.session_epoch.get_untracked();
            let server = context.server_epoch.get_untracked();
            let grant = context.areas_revocation_epoch_untracked(&SHARE_GRANT_AREAS);
            let urls = CreatedShareUrls(RwSignal::new((
                auth,
                server,
                grant,
                BTreeMap::from([("share".into(), "secret".into())]),
            )));
            provide_context(urls);
            assert_eq!(
                cached_url(context, use_context::<CreatedShareUrls>(), "share"),
                Some("secret".into())
            );
            context.server_epoch.update(|generation| *generation += 1);
            assert_eq!(cached_url(context, Some(urls), "share"), None);
            context.session_epoch.update(|generation| *generation += 1);
            assert_eq!(cached_url(context, Some(urls), "share"), None);
            let remounted = CreatedShareUrls(RwSignal::new((
                context.session_epoch.get_untracked(),
                context.server_epoch.get_untracked(),
                context.areas_revocation_epoch_untracked(&SHARE_GRANT_AREAS),
                BTreeMap::new(),
            )));
            assert_eq!(cached_url(context, Some(remounted), "share"), None);
            assert_eq!(cached_url(context, None, "share"), None);
        });
    }

    #[test]
    fn parses_camel_case_file_contract_and_directory_defaults() {
        let files=parse_files(&json!([{"name":"movie.mkv","size":1048576,"modTime":"2026-11-16","extension":"mkv","isDir":false},{"name":"media","isDir":true}])).unwrap();
        assert_eq!(files[0].size, 1_048_576);
        assert_eq!(files[0].mod_time, "2026-11-16");
        assert!(files[1].is_dir);
        assert!(parse_files(&json!([{"size":5}])).is_err());
        assert_eq!(
            directory_names(
                &json!({"entries":[{"name":"dir","is_dir":true},{"name":"file","is_dir":false}]})
            ),
            vec!["dir"]
        );
    }

    #[test]
    fn live_disk_usage_prefers_root_then_largest_partition() {
        let value = json!({"disks":[{"mount_point":"/data","total_gb":500,"used_gb":100},{"mount_point":"/","total_gb":100,"used_gb":30}]});
        let usage = host_storage(&value, 99);
        assert_eq!(usage.total_bytes, Some(100 * 1_073_741_824));
        assert_eq!(usage.used_bytes, 30 * 1_073_741_824);
        assert_eq!(usage.percent(), Some(30.0));
        let usage = host_storage(
            &json!({"disks":[{"mount_point":"/a","total_gb":50,"used_gb":10},{"mount_point":"/data","total_gb":500,"used_gb":100}]}),
            0,
        );
        assert_eq!(usage.source.as_deref(), Some("/data"));
        let usage = host_storage(&json!({"disk_space":{"total":200,"used":50}}), 0);
        assert_eq!(usage.total_bytes, Some(200 * 1_073_741_824));
        assert_eq!(usage.percent(), Some(25.0));
    }
    #[test]
    fn zero_telemetry_reports_observed_files_without_fabricating_capacity() {
        for value in [
            Value::Null,
            json!({}),
            json!({"disks":[{"mount_point":"/","total_gb":0,"used_gb":0}],"disk_space":{"total":0,"used":0}}),
        ] {
            let usage = host_storage(&value, 1234);
            assert_eq!(usage.used_bytes, 1234);
            assert_eq!(usage.total_bytes, None);
            assert_eq!(usage.percent(), None);
        }
    }
    #[test]
    fn chunks_cover_empty_boundary_and_upload_limit() {
        assert_eq!(chunk_count(0), 1);
        assert_eq!(chunk_count(CHUNK_BYTES), 1);
        assert_eq!(chunk_count(CHUNK_BYTES + 1), 2);
        assert_eq!(chunk_count(MAX_UPLOAD_BYTES), 10);
    }

    #[test]
    fn directory_navigation_stays_absolute_and_rejects_invalid_entries() {
        assert_eq!(
            absolute_path("/mnt/media/../movies/").unwrap(),
            "/mnt/movies"
        );
        assert_eq!(parent_path("/"), "/");
        assert_eq!(parent_path("/mnt/media"), "/mnt");
        assert_eq!(child_path("/", "srv").unwrap(), "/srv");
        assert!(child_path("/mnt", "../etc").is_err());
        assert!(absolute_path("relative").is_err());
        assert!(absolute_path("/mnt/\0bad").is_err());
        assert!(relative_path("../private", false).is_err());
    }
}
