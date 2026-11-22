use super::{
    clamp_tab_for_role, confirmed_session_identity, detect_browser_locale,
    format_aurora_opacity_unit, hydrate_preferences_with, is_spa_fallback_path,
    normalize_aurora_opacity_pct, normalize_card_lift, normalize_high_refresh_mode,
    normalize_theme, normalize_touch_mode, quantize_refresh_rate, resolve_high_refresh_active,
    resolve_touch_mode_active, run_resource_read, same_authenticated_identity, ApiResource,
    AppContext, ResourceReads, TabId, Toast,
};
use af_web_core::models::{DiskPartition, GpuMetric, ProcessInfo, SystemMetrics, User};
use leptos::prelude::*;
use serde_json::json;

#[test]
fn resource_reads_drop_superseded_work_before_starting_a_replacement() {
    use futures::{executor::LocalPool, future, task::LocalSpawnExt};
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    struct Transport {
        name: char,
        active: Rc<Cell<usize>>,
        events: Rc<RefCell<Vec<(char, &'static str)>>>,
    }
    impl Drop for Transport {
        fn drop(&mut self) {
            self.active.set(self.active.get() - 1);
            self.events.borrow_mut().push((self.name, "drop"));
        }
    }
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    let active = Rc::new(Cell::new(0usize));
    let peak = Rc::new(Cell::new(0usize));
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut reads = ResourceReads::default();
    let start = |reads: &mut ResourceReads, name| {
        let job = reads.next();
        let active = active.clone();
        let peak = peak.clone();
        let events = events.clone();
        spawner
            .spawn_local(async move {
                let work = async move {
                    active.set(active.get() + 1);
                    peak.set(peak.get().max(active.get()));
                    events.borrow_mut().push((name, "start"));
                    let _transport = Transport {
                        name,
                        active,
                        events,
                    };
                    future::pending::<()>().await;
                };
                let _ = run_resource_read(job, work).await;
            })
            .unwrap();
    };
    start(&mut reads, 'a');
    pool.run_until_stalled();
    assert_eq!(active.get(), 1);
    start(&mut reads, 'b');
    start(&mut reads, 'c');
    pool.run_until_stalled();
    assert_eq!(
        *events.borrow(),
        vec![('a', "start"), ('a', "drop"), ('c', "start")]
    );
    assert_eq!(active.get(), 1);
    assert_eq!(peak.get(), 1);
    reads.cancel();
    pool.run_until_stalled();
    assert_eq!(active.get(), 0);
    assert_eq!(events.borrow().last(), Some(&('c', "drop")));
}

#[test]
fn resource_read_canceled_before_poll_never_starts_its_transport() {
    let started = std::cell::Cell::new(false);
    let mut reads = ResourceReads::default();
    let job = reads.next();
    reads.cancel();
    let result = futures::executor::block_on(run_resource_read(job, async {
        started.set(true);
        1
    }));
    assert!(result.is_none());
    assert!(!started.get());
}

#[test]
fn completed_resource_read_allows_a_later_refresh() {
    let mut reads = ResourceReads::default();
    assert_eq!(
        futures::executor::block_on(run_resource_read(reads.next(), async { 7 })),
        Some(7)
    );
    assert_eq!(
        futures::executor::block_on(run_resource_read(reads.next(), async { 9 })),
        Some(9)
    );
}

#[test]
fn live_services_reject_older_http_and_allow_a_later_explicit_refresh() {
    Owner::new().with(|| {
        let context = AppContext::new();
        context.user.set(Some(json!({"id": 1})));
        let request = context.begin_services_request();
        context.publish_live_services(json!({"probe": {"status": "failed"}}));
        assert!(!context.finish_services_request(request, json!({"probe": {"status": "running"}})));
        assert_eq!(
            context.services.get_untracked()["probe"]["status"],
            "failed"
        );
        let refresh = context.begin_services_request();
        assert!(context.finish_services_request(refresh, json!({"probe": {"status": "stopped"}})));
        assert_eq!(
            context.services.get_untracked()["probe"]["status"],
            "stopped"
        );
    });
}

#[test]
fn all_service_http_writers_share_request_and_account_ordering() {
    Owner::new().with(|| {
        let context = AppContext::new();
        context.user.set(Some(json!({"id": 1})));
        let shell = context.begin_services_request();
        let inventory = context.begin_services_request();
        assert!(context.finish_services_request(inventory, json!({"new": {"status": "running"}})));
        assert!(!context.finish_services_request(shell, json!({"old": {"status": "stopped"}})));
        let old_account = context.begin_services_request();
        context.session_epoch.update(|epoch| *epoch += 1);
        assert!(!context.finish_services_request(old_account, json!({"old_account": {}})));
        assert!(context.services.get_untracked().get("new").is_some());
    });
}

#[test]
fn pending_service_refresh_does_not_discard_an_available_bootstrap_snapshot() {
    Owner::new().with(|| {
        let context = AppContext::new();
        context.user.set(Some(json!({"id": 1})));
        let bootstrap = context.begin_services_request();
        let refresh = context.begin_services_request();
        assert!(context.finish_services_request(bootstrap, json!({"status": "bootstrap"})));
        assert!(context.finish_services_request(refresh, json!({"status": "refreshed"})));
        assert!(!context.finish_services_request(bootstrap, json!({"status": "stale"})));
        assert_eq!(context.services.get_untracked()["status"], "refreshed");
    });
}

#[test]
fn revalidation_requires_a_real_identity_and_keeps_legacy_session_aliases() {
    for session in [
        json!({"id": 7, "role": "admin"}),
        json!({"user_id": 8}),
        json!({"userName": "alice", "role": "user"}),
    ] {
        assert!(confirmed_session_identity(&session), "{session}");
    }
    for session in [
        json!(null),
        json!({}),
        json!({"role": "admin"}),
        json!({"username": "  "}),
    ] {
        assert!(!confirmed_session_identity(&session), "{session}");
    }
}

#[test]
fn visible_toast_text_tracks_locale_and_catalog_revision() {
    Owner::new().with(|| {
        let context = AppContext::new();
        let toast = Toast {
            id: 1,
            message: "Auth.signOutFailed".into(),
            params: vec![],
            error: true,
        };
        let renders = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let observed_renders = renders.clone();
        let rendered = Memo::new(move |_| {
            observed_renders.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            context.render_toast(&toast)
        });
        let english = rendered.get();
        context.locale.set("fr".into());
        let french = rendered.get();
        assert_ne!(english, french);
        assert_eq!(
            french,
            af_web_core::i18n::translate("fr", "Auth.signOutFailed")
        );
        context.catalog_revision.update(|revision| *revision += 1);
        assert_eq!(rendered.get(), french);
        assert_eq!(renders.load(std::sync::atomic::Ordering::Relaxed), 3);
    });
}

#[test]
fn toast_rendering_translates_fallback_strings_and_preserves_dynamic_messages() {
    Owner::new().with(|| {
        let context = AppContext::new();
        context.locale.set("fr".into());
        let mut toast = Toast {
            id: 1,
            message: "Copy".into(),
            params: vec![],
            error: false,
        };
        assert_ne!(context.render_toast(&toast), toast.message);
        toast.message = "Uncatalogued failure for job 13".into();
        assert_eq!(context.render_toast(&toast), toast.message);
        toast.message = "Shell.pendingActions".into();
        toast.params = vec![("count".into(), "3".into())];
        assert_eq!(
            context.render_toast(&toast),
            context.t_with("Shell.pendingActions", &[("count", "3")])
        );
        assert!(!context.render_toast(&toast).contains("{count}"));
    });
}

#[test]
fn generic_api_resources_are_copyable_without_copyable_response_values() {
    Owner::new().with(|| {
        let resource = ApiResource {
            data: RwSignal::new(Vec::<String>::new()),
            loading: RwSignal::new(false),
            error: RwSignal::new(None),
            revision: RwSignal::new(0),
        };
        let copied = resource;
        resource.refresh();
        assert_eq!(copied.revision.get_untracked(), 1);
        assert!(copied.data.get_untracked().is_empty());
    });
}

#[test]
fn authenticated_identity_uses_stable_ids_across_profile_changes() {
    let prev = json!({"id": 7, "username": "operator", "email": "old@example.com"});
    let updated = json!({
        "id": 7, "username": "renamed", "email": "new@example.com",
        "role": "admin", "avatar_url": "/new-avatar.png", "totp_enabled": true
    });
    assert!(same_authenticated_identity(Some(&prev), Some(&updated)));
    assert!(!same_authenticated_identity(Some(&prev), None));
    assert!(!same_authenticated_identity(None, Some(&prev)));
    assert!(!same_authenticated_identity(None, None));
}

#[test]
fn authenticated_identity_detects_account_switches_despite_matching_usernames() {
    let prev = json!({"id": 7, "username": "operator"});
    let switched = json!({"id": 8, "username": "operator"});
    assert!(!same_authenticated_identity(Some(&prev), Some(&switched)));
    assert!(!same_authenticated_identity(Some(&switched), Some(&prev)));
}

#[test]
fn authenticated_identity_falls_back_to_nonempty_usernames_without_ids() {
    let prev = json!({"id": null, "username": "operator"});
    let same = json!({"username": "operator", "email": "updated@example.com"});
    let switched = json!({"username": "other"});
    let with_id = json!({"id": 7, "username": "operator"});
    assert!(same_authenticated_identity(Some(&prev), Some(&same)));
    assert!(!same_authenticated_identity(Some(&prev), Some(&switched)));
    assert!(!same_authenticated_identity(Some(&prev), Some(&with_id)));
    for missing in [json!({}), json!({"username": ""}), json!({"username": " "})] {
        assert!(!same_authenticated_identity(Some(&missing), Some(&missing)));
    }
}

#[test]
fn browser_locale_matches_supported_primary_language_tags() {
    for (language, expected) in [
        ("de", "de"),
        ("DE-de", "de"),
        ("da", "dk"),
        ("da-DK", "dk"),
        ("dk", "dk"),
        ("es", "es"),
        ("ES-mx", "es"),
        ("fr", "fr"),
        ("fr-CA", "fr"),
        ("zh", "zh"),
        ("ZH-hant-TW", "zh"),
    ] {
        assert_eq!(
            detect_browser_locale(Some(language)),
            expected,
            "{language}"
        );
    }
}

#[test]
fn browser_locale_defaults_to_english_for_missing_or_unsupported_languages() {
    assert_eq!(detect_browser_locale(None), "en");
    for language in ["", "en", "en-US", "en-GB", "it-IT", "francais", "deutsch"] {
        assert_eq!(detect_browser_locale(Some(language)), "en", "{language}");
    }
}

#[test]
fn fallback_route_normalization_excludes_public_and_root_routes() {
    for path in [
        "/",
        "/login",
        "/login/",
        "/oauth/consent",
        "/oauth/consent/",
        "/oauth/device",
        "/oauth/device/",
        "/share",
        "/share/",
    ] {
        assert!(!is_spa_fallback_path(path), "{path}");
    }
    for path in [
        "/unknown",
        "/settings",
        "/nested/fallback",
        "/login/unrecognized",
    ] {
        assert!(is_spa_fallback_path(path), "{path}");
    }
}

#[test]
fn typed_user_preserves_canonical_session_fields_and_admin_role() {
    Owner::new().with(|| {
        let context = AppContext::new();
        assert!(context.typed_user().is_none());
        assert!(!context.is_admin());
        let user = User {
            id: 7,
            username: "admin".into(),
            email: "admin@example.com".into(),
            avatar_url: "/avatar.png".into(),
            role: "admin".into(),
            is_oauth: true,
            totp_enabled: true,
            ..Default::default()
        };
        context.user.set(Some(serde_json::to_value(&user).unwrap()));
        assert_eq!(context.typed_user(), Some(user));
        assert!(context.is_admin());
    });
}

#[test]
fn typed_user_defaults_partial_sessions_and_accepts_legacy_aliases() {
    Owner::new().with(|| {
        let context = AppContext::new();
        // The session fixture omits email, avatar and MFA flags.
        context.user.set(Some(
            json!({"id": 2, "username": "operator", "role": "user"}),
        ));
        let user = context.typed_user().unwrap();
        assert_eq!(user.id, 2);
        assert_eq!(user.username, "operator");
        assert_eq!(user.role, "user");
        assert!(user.email.is_empty());
        assert!(!user.totp_enabled);
        assert!(!user.is_oauth);
        assert!(!context.is_admin());

        context.user.set(Some(
            json!({"userId": 9, "userName": "legacy", "isOAuth": true, "totpEnabled": true}),
        ));
        let user = context.typed_user().unwrap();
        assert_eq!(user.id, 9);
        assert_eq!(user.username, "legacy");
        assert_eq!(user.role, "user");
        assert!(user.is_oauth && user.totp_enabled);
        context.user.set(Some(json!({"role": "admin"})));
        assert!(context.is_admin());
        assert_eq!(context.typed_user().unwrap().username, "Operator");
        context.user.set(Some(json!({"role": ["admin"]})));
        assert!(context.typed_user().is_none());
        assert!(!context.is_admin());
    });
}

#[test]
fn typed_metrics_preserves_the_full_shared_backend_contract() {
    Owner::new().with(|| {
        let context = AppContext::new();
        let metrics = SystemMetrics {
            cpu_usage: 18.2,
            per_core_cpu: vec![12.0, 24.4],
            disk_space: [("used".into(), 52.0)].into_iter().collect(),
            disks: vec![DiskPartition {
                mount_point: "/".into(),
                device: "/dev/sda1".into(),
                fs_type: "ext4".into(),
                total_gb: 100.0,
                used_gb: 52.0,
                free_gb: 48.0,
                used_pct: 52.0,
            }],
            memory: [("used".into(), 12.0), ("total".into(), 64.0)]
                .into_iter()
                .collect(),
            swap: [("total".into(), 8.0)].into_iter().collect(),
            gpus: vec![GpuMetric {
                name: "GPU".into(),
                usage_pct: 42.0,
                ..Default::default()
            }],
            processes: vec![ProcessInfo {
                pid: 1,
                name: "init".into(),
                cpu: 0.1,
                mem: 0.2,
            }],
            ..Default::default()
        };
        context.metrics.set(serde_json::to_value(&metrics).unwrap());
        assert_eq!(context.typed_metrics(), metrics);
    });
}

#[test]
fn typed_metrics_defaults_partial_and_null_telemetry_without_losing_samples() {
    Owner::new().with(|| {
        let context = AppContext::new();
        assert_eq!(context.typed_metrics(), SystemMetrics::default());
        context.metrics.set(json!({
            "cpu_usage": 18.2,
            "per_core_cpu": [12, 24.4],
            "memory": {"used": 12, "total": 64},
            "swap": null,
            "disks": [{"mount_point": "/", "used_pct": 51.4}],
            "gpus": [{"name": "GPU", "usage_pct": 42}],
            "processes": [{"pid": 1, "name": "init"}]
        }));
        let metrics = context.typed_metrics();
        assert_eq!(metrics.cpu_usage, 18.2);
        assert_eq!(metrics.per_core_cpu, vec![12.0, 24.4]);
        assert_eq!(metrics.memory["used"], 12.0);
        assert!(metrics.swap.is_empty());
        assert!(metrics.disk_space.is_empty());
        assert_eq!(metrics.disks[0].mount_point, "/");
        assert_eq!(metrics.disks[0].used_pct, 51.4);
        assert_eq!(metrics.disks[0].total_gb, 0.0);
        assert_eq!(metrics.gpus[0].usage_pct, 42.0);
        assert_eq!(metrics.gpus[0].memory_total, 0.0);
        assert_eq!(metrics.processes[0].pid, 1);
        assert_eq!(metrics.processes[0].cpu, 0.0);
        context.metrics.set(json!({"cpu_usage": 9.5}));
        assert_eq!(context.typed_metrics().cpu_usage, 9.5);
        assert!(context.typed_metrics().gpus.is_empty());
    });
}

#[test]
fn theme_preferences_preserve_system_and_default_invalid_values_to_dark() {
    for pref in ["system", "dark", "light"] {
        assert_eq!(normalize_theme(pref), pref);
    }
    for pref in ["", "auto", "LIGHT", "null"] {
        assert_eq!(normalize_theme(pref), "dark");
    }
}

#[test]
fn non_admin_deep_links_clamp_restricted_tabs_and_keep_notifications() {
    for tab in TabId::ALL {
        assert_eq!(clamp_tab_for_role(tab, true), tab);
        let expected = if matches!(
            tab,
            TabId::Inbox
                | TabId::Network
                | TabId::Cluster
                | TabId::Users
                | TabId::Audit
                | TabId::Quotas
        ) {
            TabId::Overview
        } else {
            tab
        };
        assert_eq!(clamp_tab_for_role(tab, false), expected, "{tab:?}");
    }
    assert_eq!(
        clamp_tab_for_role(TabId::Notifications, false),
        TabId::Notifications
    );
}

#[test]
fn default_dashboard_respects_the_authenticated_role() {
    for tab in TabId::ALL {
        let settings = serde_json::json!({"defaultDashboard": tab.key()});
        let target = TabId::from_key(settings["defaultDashboard"].as_str().unwrap());
        assert_eq!(clamp_tab_for_role(target, true), tab);
        assert!(!clamp_tab_for_role(target, false).is_admin_only());
        if !tab.is_admin_only() {
            assert_eq!(clamp_tab_for_role(target, false), tab);
        }
    }
    assert_eq!(
        clamp_tab_for_role(TabId::from_key("retired-dashboard"), false),
        TabId::Overview
    );
}

#[test]
fn default_dashboard_preferences_resolve_to_supported_tabs() {
    for tab in TabId::ALL {
        let settings = serde_json::json!({"defaultDashboard": tab.key()});
        assert_eq!(
            TabId::from_key(settings["defaultDashboard"].as_str().unwrap()),
            tab
        );
    }
    assert_eq!(TabId::from_key("retired-dashboard"), TabId::Overview);
    assert_eq!(TabId::from_key(""), TabId::Overview);
}

#[test]
fn tab_keys_restore_navigation_and_default_unknown_keys() {
    for (key, expected) in [
        ("overview", TabId::Overview),
        ("services", TabId::Services),
        ("marketplace", TabId::Marketplace),
        ("mcbrowser", TabId::McBrowser),
        ("fileshare", TabId::Fileshare),
        ("streaming", TabId::Streaming),
        ("mediaflow", TabId::Mediaflow),
        ("ai", TabId::AiChat),
        ("inbox", TabId::Inbox),
        ("network", TabId::Network),
        ("cluster", TabId::Cluster),
        ("users", TabId::Users),
        ("audit", TabId::Audit),
        ("settings", TabId::Settings),
        ("notifications", TabId::Notifications),
        ("quotas", TabId::Quotas),
    ] {
        assert_eq!(TabId::from_key(key), expected, "{key}");
    }
    for key in ["", "unknown", "Services"] {
        assert_eq!(TabId::from_key(key), TabId::Overview, "{key}");
    }
}

#[test]
fn administrator_navigation_is_limited_to_operator_tabs() {
    let admin_tabs = [
        TabId::Inbox,
        TabId::Network,
        TabId::Cluster,
        TabId::Users,
        TabId::Audit,
        TabId::Quotas,
    ];
    for tab in TabId::ALL {
        assert_eq!(tab.is_admin_only(), admin_tabs.contains(&tab), "{tab:?}");
    }
}

#[test]
fn navigation_labels_translate_and_fall_back_to_english() {
    for tab in TabId::ALL {
        assert_eq!(tab.localized_label("en"), tab.label(), "{tab:?}");
        assert_eq!(tab.localized_label("unknown"), tab.label(), "{tab:?}");
    }
    assert_eq!(TabId::Overview.localized_label("de"), "Übersicht");
    assert_eq!(TabId::Services.localized_label("de"), "Dienste");
    assert_eq!(TabId::Settings.localized_label("fr"), "Paramètres");
}

#[test]
fn display_preference_normalizers_handle_aliases_and_quantize_steps() {
    assert_eq!(normalize_high_refresh_mode("auto"), "auto");
    assert_eq!(normalize_high_refresh_mode("120"), "120hz");
    assert_eq!(normalize_high_refresh_mode("120Hz"), "120hz");
    assert_eq!(normalize_high_refresh_mode("60"), "standard");
    assert_eq!(normalize_high_refresh_mode("60hz"), "standard");
    assert_eq!(normalize_high_refresh_mode("standard"), "standard");
    assert_eq!(normalize_high_refresh_mode("unknown"), "auto");

    assert_eq!(normalize_touch_mode("auto"), "auto");
    assert_eq!(normalize_touch_mode("on"), "on");
    assert_eq!(normalize_touch_mode("enabled"), "on");
    assert_eq!(normalize_touch_mode("off"), "off");
    assert_eq!(normalize_touch_mode("desktop"), "off");
    assert_eq!(normalize_touch_mode("disabled"), "off");
    assert_eq!(normalize_touch_mode("unknown"), "auto");

    assert_eq!(normalize_aurora_opacity_pct("0"), 0);
    assert_eq!(normalize_aurora_opacity_pct("0.55"), 55);
    assert_eq!(normalize_aurora_opacity_pct("0.84"), 85);
    assert_eq!(normalize_aurora_opacity_pct("1"), 100);
    assert_eq!(normalize_aurora_opacity_pct("1.0"), 100);
    assert_eq!(normalize_aurora_opacity_pct("35%"), 35);
    assert_eq!(normalize_aurora_opacity_pct("75"), 75);
    assert_eq!(normalize_aurora_opacity_pct("-0.2"), 0);
    assert_eq!(normalize_aurora_opacity_pct("invalid"), 55);
    assert_eq!(format_aurora_opacity_unit(0), "0");
    assert_eq!(format_aurora_opacity_unit(5), "0.05");
    assert_eq!(format_aurora_opacity_unit(50), "0.5");
    assert_eq!(format_aurora_opacity_unit(55), "0.55");
    assert_eq!(format_aurora_opacity_unit(100), "1");

    assert_eq!(normalize_card_lift("0"), 0);
    assert_eq!(normalize_card_lift("false"), 0);
    assert_eq!(normalize_card_lift("flat"), 0);
    assert_eq!(normalize_card_lift("-4"), -4);
    assert_eq!(normalize_card_lift("-4px"), -4);
    assert_eq!(normalize_card_lift("true"), -4);
    assert_eq!(normalize_card_lift("-6"), -6);

    assert_eq!(quantize_refresh_rate(59.9), 60);
    assert_eq!(quantize_refresh_rate(119.4), 120);
    assert_eq!(quantize_refresh_rate(143.8), 144);
    assert!(resolve_high_refresh_active("auto", 120));
    assert!(!resolve_high_refresh_active("auto", 60));
    assert!(resolve_high_refresh_active("120hz", 60));
    assert!(!resolve_high_refresh_active("standard", 120));

    assert!(resolve_touch_mode_active("auto", true));
    assert!(!resolve_touch_mode_active("auto", false));
    assert!(resolve_touch_mode_active("on", false));
    assert!(!resolve_touch_mode_active("off", true));
}

#[test]
fn legacy_zustand_storage_hydrates_and_yields_to_explicit_flat_keys() {
    use std::collections::BTreeMap;

    let empty = BTreeMap::<String, String>::new();
    let defaults = hydrate_preferences_with(|k| empty.get(k).cloned());
    assert_eq!(defaults.theme, "dark");
    assert_eq!(defaults.locale, None);
    assert!(!defaults.immersive_overview);
    assert!(defaults.show_gpu);
    assert!(defaults.show_transfer_history);
    assert!(!defaults.reduced_motion);
    assert!(defaults.haptic_feedback);
    assert_eq!(defaults.high_refresh_mode, "auto");
    assert_eq!(defaults.touch_mode, "auto");
    assert_eq!(defaults.aurora_opacity, 55);
    assert!(!defaults.aurora_animation);
    assert!(defaults.grain_display);
    assert_eq!(defaults.card_lift, -4);

    let mut legacy = BTreeMap::<String, String>::new();
    legacy.insert(
        "aetherflow-system-storage".into(),
        serde_json::json!({
            "state": {
                "theme": "light",
                "language": "de",
                "auroraOpacity": 0.85,
                "auroraAnimation": true,
                "grainDisplay": false,
                "cardLift": -6,
                "highRefreshMode": "120hz",
                "touchMode": "enabled",
                "hapticFeedback": false
            },
            "version": 0
        })
        .to_string(),
    );
    legacy.insert(
        "aetherflow-connection-storage".into(),
        serde_json::json!({
            "state": {
                "dashboardDensity": "immersive",
                "showGpuWidget": false,
                "showDataUsageWidget": false
            }
        })
        .to_string(),
    );

    let hydrated = hydrate_preferences_with(|k| legacy.get(k).cloned());
    assert_eq!(hydrated.theme, "light");
    assert_eq!(hydrated.locale.as_deref(), Some("de"));
    assert!(hydrated.immersive_overview);
    assert!(!hydrated.show_gpu);
    assert!(!hydrated.show_transfer_history);
    assert!(!hydrated.haptic_feedback);
    assert_eq!(hydrated.high_refresh_mode, "120hz");
    assert_eq!(hydrated.touch_mode, "on");
    assert_eq!(hydrated.aurora_opacity, 85);
    assert!(hydrated.aurora_animation);
    assert!(!hydrated.grain_display);
    assert_eq!(hydrated.card_lift, -6);

    // Explicit flat keys take precedence over legacy Zustand JSON.
    legacy.insert("aetherflow-touch-mode".into(), "desktop".into());
    legacy.insert("aetherflow-high-refresh-mode".into(), "60".into());
    legacy.insert("aetherflow-aurora-opacity".into(), "0.25".into());
    legacy.insert("aetherflow-card-lift".into(), "0".into());
    let overridden = hydrate_preferences_with(|k| legacy.get(k).cloned());
    assert_eq!(overridden.touch_mode, "off");
    assert_eq!(overridden.high_refresh_mode, "standard");
    assert_eq!(overridden.aurora_opacity, 25);
    assert_eq!(overridden.card_lift, 0);
}
