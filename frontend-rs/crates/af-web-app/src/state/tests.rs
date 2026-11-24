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

#[test]
fn server_switching_partitions_cache_fences_services_and_resets_on_logout() {
    use super::server::{
        evaluate_active_peer_health, normalize_server_selection, peer_has_capability,
        peer_switch_eligibility, server_accent, ActivePeerHealth, PeerArea,
    };
    use crate::tabs::cluster::peers::{AccessLevel, PeersSnapshot};

    assert_eq!(normalize_server_selection(None), None);
    assert_eq!(normalize_server_selection(Some("  ".into())), None);
    assert_eq!(normalize_server_selection(Some("..".into())), None);
    assert_eq!(
        normalize_server_selection(Some(" peer-b ".into())).as_deref(),
        Some("peer-b")
    );
    assert_eq!(server_accent("peer-b"), server_accent("peer-b"));

    let snapshot: PeersSnapshot = serde_json::from_value(json!({
        "local_protocol_version": 1,
        "local_capabilities": ["links", "grants", "proxy.http.v1", "proxy.ws.logs.v1", "proxy.ws.telemetry.v1"],
        "peers": [
            {
                "id": "peer-b",
                "name": "Beta Media",
                "state": "active",
                "compatibility": "compatible",
                "missing_capabilities": [],
                "grants": {
                    "outbound": {
                        "id": "g-b",
                        "run_as_user_id": 1,
                        "access": {
                            "services": "read",
                            "marketplace": "write",
                            "settings": "write",
                            "files": "write",
                            "users": "none",
                            "network": "read",
                            "updates": "read",
                            "transcoding": "write"
                        }
                    }
                }
            },
            {
                "id": "peer-limited",
                "name": "Gamma Archive",
                "state": "active",
                "compatibility": "limited",
                "missing_capabilities": ["proxy.ws.logs.v1"],
                "grants": {
                    "outbound": {
                        "id": "g-l",
                        "run_as_user_id": 1,
                        "access": { "services": "write" }
                    }
                }
            },
            {
                "id": "peer-nogrant",
                "name": "Delta Empty",
                "state": "active",
                "compatibility": "compatible",
                "grants": {}
            },
            {
                "id": "peer-down",
                "name": "Epsilon Down",
                "state": "down",
                "compatibility": "compatible",
                "grants": { "outbound": { "id": "g-d", "run_as_user_id": 1, "access": { "services": "write" } } }
            },
            {
                "id": "peer-incompat",
                "name": "Zeta Old",
                "state": "active",
                "compatibility": "incompatible",
                "grants": { "outbound": { "id": "g-i", "run_as_user_id": 1, "access": { "services": "write" } } }
            },
            {
                "id": "peer-revoked",
                "name": "Eta Revoked",
                "state": "revoked",
                "compatibility": "compatible",
                "grants": { "outbound": { "id": "g-r", "run_as_user_id": 1, "access": { "services": "write" } } }
            }
        ]
    }))
    .unwrap();

    assert_eq!(peer_switch_eligibility(&snapshot.peers[0]), Ok(()));
    assert_eq!(peer_switch_eligibility(&snapshot.peers[1]), Ok(()));
    assert_eq!(
        peer_switch_eligibility(&snapshot.peers[2]),
        Err("PeerSwitch.noOutboundGrant")
    );
    assert_eq!(
        peer_switch_eligibility(&snapshot.peers[3]),
        Err("PeerSwitch.peerUnreachable")
    );
    assert_eq!(
        peer_switch_eligibility(&snapshot.peers[4]),
        Err("PeerSwitch.peerIncompatible")
    );
    assert_eq!(
        peer_switch_eligibility(&snapshot.peers[5]),
        Err("PeerSwitch.peerRevoked")
    );
    assert!(peer_has_capability(&snapshot.peers[0], "proxy.ws.logs.v1"));
    assert!(!peer_has_capability(&snapshot.peers[1], "proxy.ws.logs.v1"));
    assert!(!peer_has_capability(&snapshot.peers[4], "proxy.http.v1"));
    assert_eq!(
        evaluate_active_peer_health("peer-b", Some(&snapshot), None),
        ActivePeerHealth::Healthy
    );
    assert_eq!(
        evaluate_active_peer_health("peer-limited", Some(&snapshot), None),
        ActivePeerHealth::Limited
    );
    assert_eq!(
        evaluate_active_peer_health("peer-down", Some(&snapshot), None),
        ActivePeerHealth::Unreachable
    );
    assert_eq!(
        evaluate_active_peer_health("missing", Some(&snapshot), None),
        ActivePeerHealth::Revoked
    );

    Owner::new().with(|| {
        let context = AppContext::new();
        context
            .user
            .set(Some(json!({"id": 1, "username": "admin", "role": "admin"})));
        context.apply_peers_snapshot(snapshot.clone());
        context
            .services
            .set(json!({"local_svc": {"status": "running"}}));
        context.settings.set(json!({"baseDomain": "local.example"}));

        let local_req = context.begin_services_request();
        assert_eq!(context.eligible_peers().len(), 2);
        assert!(!context.select_server(Some("peer-down".into())));
        assert!(!context.select_server(Some("peer-nogrant".into())));
        assert!(!context.is_remote());

        assert!(context.select_server(Some("peer-b".into())));
        assert!(context.is_remote());
        assert_eq!(context.active_server_name().as_deref(), Some("Beta Media"));
        assert_eq!(
            context.api_url("/api/v1/auth/services"),
            "/api/v1/peers/peer-b/auth/services"
        );
        // Stale request from local server cannot overwrite peer-b services.
        assert!(!context.finish_services_request(local_req, json!({"stale": {}})));
        assert_eq!(context.services.get_untracked(), serde_json::Value::Null);

        // Area and P5 cross-area permission checks on peer-b.
        assert_eq!(context.peer_access(PeerArea::Services), AccessLevel::Read);
        assert!(context.can_read_area(PeerArea::Services));
        assert!(!context.can_write_area(PeerArea::Services));
        assert!(context
            .area_block_reason(PeerArea::Services, true)
            .unwrap()
            .contains("Beta Media"));
        // Blueprint Sync requires Marketplace:Write + Network:Write (peer-b only has Network:Read).
        assert!(
            !context.can_all_areas(&[(PeerArea::Marketplace, true), (PeerArea::Network, true),])
        );
        assert!(context
            .areas_block_reason(&[(PeerArea::Marketplace, true), (PeerArea::Network, true)])
            .unwrap()
            .contains("Beta Media"));
        // McBrowser Policy requires Files + Users (peer-b has Users:None).
        assert!(!context.can_all_areas(&[(PeerArea::Files, false), (PeerArea::Users, false)]));
        // Settings and Transcoding write are granted.
        assert!(context.can_write_area(PeerArea::Settings));
        assert!(context.can_write_area(PeerArea::Transcoding));

        // Populate peer-b state, then switch back to local -> local cache restored cleanly.
        let peer_req = context.begin_services_request();
        assert!(
            context.finish_services_request(peer_req, json!({"remote_svc": {"status": "running"}}))
        );
        context.exit_to_local_server();
        assert!(!context.is_remote());
        assert_eq!(
            context.services.get_untracked()["local_svc"]["status"],
            "running"
        );
        assert!(context.services.get_untracked().get("remote_svc").is_none());

        // Switching to peer-limited exposes missing capability hint and resets cleanly on logout.
        assert!(context.select_server(Some("peer-limited".into())));
        assert!(!context.has_peer_capability("proxy.ws.logs.v1"));
        assert!(context
            .capability_block_reason("proxy.ws.logs.v1")
            .unwrap()
            .contains("Gamma Archive"));

        context.clear_account_scoped_state();
        assert!(!context.is_remote());
        assert_eq!(af_web_core::api::active_server(), None);
    });
}

#[test]
fn peer_compatibility_gating_matches_backend_across_link_and_grant_states() {
    use super::{
        evaluate_active_peer_health, peer_compatibility_supports_management, peer_has_capability,
        peer_switch_eligibility, ActivePeerHealth,
    };
    use crate::tabs::cluster::peers::{PeerLinkView, PeersSnapshot};
    use serde_json::Value;

    let make_peer =
        |id: &str, state: &str, compatibility: &str, missing: &[&str], outbound: Value| {
            serde_json::from_value::<PeerLinkView>(json!({
                "id": id,
                "name": id,
                "state": state,
                "compatibility": compatibility,
                "missing_capabilities": missing,
                "grants": { "outbound": outbound }
            }))
            .unwrap()
        };

    let read_grant = json!({
        "id": "g-read",
        "run_as_user_id": 1,
        "access": { "services": "read" }
    });
    let empty_grant = json!({
        "id": "g-empty",
        "run_as_user_id": 1,
        "access": {}
    });

    // Compatible + active + grant with access => eligible + Healthy.
    let compatible = make_peer("p-compat", "active", "compatible", &[], read_grant.clone());
    assert!(peer_compatibility_supports_management(&compatible));
    assert_eq!(peer_switch_eligibility(&compatible), Ok(()));
    assert!(peer_has_capability(&compatible, "proxy.ws.logs.v1"));

    // Limited with grants capability intact (e.g. missing only proxy.ws.logs.v1) => eligible + Limited.
    let limited_ok = make_peer(
        "p-limited-ok",
        "active",
        "limited",
        &["proxy.ws.logs.v1"],
        read_grant.clone(),
    );
    assert!(peer_compatibility_supports_management(&limited_ok));
    assert_eq!(peer_switch_eligibility(&limited_ok), Ok(()));
    assert!(!peer_has_capability(&limited_ok, "proxy.ws.logs.v1"));
    assert!(peer_has_capability(&limited_ok, "grants"));

    // Limited missing "grants" capability => ineligible + Incompatible!
    let limited_no_grants = make_peer(
        "p-limited-nogrants",
        "active",
        "limited",
        &["grants"],
        read_grant.clone(),
    );
    assert!(!peer_compatibility_supports_management(&limited_no_grants));
    assert_eq!(
        peer_switch_eligibility(&limited_no_grants),
        Err("PeerSwitch.peerIncompatible")
    );
    assert!(!peer_has_capability(&limited_no_grants, "proxy.http.v1"));

    // Unknown, incompatible, and unrecognized ("full", "") fail closed even with active link + grant.
    for (id, compat) in [
        ("p-unknown", "unknown"),
        ("p-incompat", "incompatible"),
        ("p-unrecognized", "full"),
        ("p-blank", ""),
    ] {
        let peer = make_peer(id, "active", compat, &[], read_grant.clone());
        assert!(
            !peer_compatibility_supports_management(&peer),
            "compatibility={compat:?} must fail closed"
        );
        assert_eq!(
            peer_switch_eligibility(&peer),
            Err("PeerSwitch.peerIncompatible"),
            "compatibility={compat:?}"
        );
        assert!(!peer_has_capability(&peer, "proxy.http.v1"));
    }

    // Link state and grant state permutations on otherwise compatible peers.
    let pending = make_peer(
        "p-pending",
        "pending",
        "compatible",
        &[],
        read_grant.clone(),
    );
    let down = make_peer("p-down", "down", "compatible", &[], read_grant.clone());
    let revoked = make_peer(
        "p-revoked",
        "revoked",
        "compatible",
        &[],
        read_grant.clone(),
    );
    let missing_grant = make_peer("p-missing-grant", "active", "compatible", &[], Value::Null);
    let zero_grant = make_peer("p-zero-grant", "active", "compatible", &[], empty_grant);

    assert_eq!(
        peer_switch_eligibility(&pending),
        Err("PeerSwitch.peerPending")
    );
    assert_eq!(
        peer_switch_eligibility(&down),
        Err("PeerSwitch.peerUnreachable")
    );
    assert_eq!(
        peer_switch_eligibility(&revoked),
        Err("PeerSwitch.peerRevoked")
    );
    assert_eq!(
        peer_switch_eligibility(&missing_grant),
        Err("PeerSwitch.noOutboundGrant")
    );
    assert_eq!(
        peer_switch_eligibility(&zero_grant),
        Err("PeerSwitch.noOutboundGrant")
    );

    // Link state takes precedence before compatibility, and compatibility fails closed before grant.
    let revoked_unknown = make_peer("p-rev-unk", "revoked", "unknown", &[], Value::Null);
    let down_unknown = make_peer("p-down-unk", "down", "unknown", &[], Value::Null);
    let unknown_no_grant = make_peer("p-unk-ng", "active", "unknown", &[], Value::Null);
    assert_eq!(
        peer_switch_eligibility(&revoked_unknown),
        Err("PeerSwitch.peerRevoked")
    );
    assert_eq!(
        peer_switch_eligibility(&down_unknown),
        Err("PeerSwitch.peerUnreachable")
    );
    assert_eq!(
        peer_switch_eligibility(&unknown_no_grant),
        Err("PeerSwitch.peerIncompatible")
    );

    let mut snapshot: PeersSnapshot = serde_json::from_value(json!({
        "local_protocol_version": 1,
        "local_capabilities": ["links", "grants"]
    }))
    .unwrap();
    snapshot.peers = vec![
        compatible,
        limited_ok,
        limited_no_grants,
        make_peer("p-unknown", "active", "unknown", &[], read_grant.clone()),
        make_peer(
            "p-incompat",
            "active",
            "incompatible",
            &[],
            read_grant.clone(),
        ),
        make_peer("p-unrecognized", "active", "full", &[], read_grant),
        pending,
        down,
        revoked,
        missing_grant,
        zero_grant,
        revoked_unknown,
        down_unknown,
        unknown_no_grant,
    ];

    assert_eq!(
        evaluate_active_peer_health("p-compat", Some(&snapshot), None),
        ActivePeerHealth::Healthy
    );
    assert_eq!(
        evaluate_active_peer_health("p-limited-ok", Some(&snapshot), None),
        ActivePeerHealth::Limited
    );
    assert_eq!(
        evaluate_active_peer_health("p-limited-nogrants", Some(&snapshot), None),
        ActivePeerHealth::Incompatible
    );
    assert_eq!(
        evaluate_active_peer_health("p-unknown", Some(&snapshot), None),
        ActivePeerHealth::Incompatible
    );
    assert_eq!(
        evaluate_active_peer_health("p-incompat", Some(&snapshot), None),
        ActivePeerHealth::Incompatible
    );
    assert_eq!(
        evaluate_active_peer_health("p-unrecognized", Some(&snapshot), None),
        ActivePeerHealth::Incompatible
    );
    assert_eq!(
        evaluate_active_peer_health("p-pending", Some(&snapshot), None),
        ActivePeerHealth::Revoked
    );
    assert_eq!(
        evaluate_active_peer_health("p-down", Some(&snapshot), None),
        ActivePeerHealth::Unreachable
    );
    assert_eq!(
        evaluate_active_peer_health("p-revoked", Some(&snapshot), None),
        ActivePeerHealth::Revoked
    );
    assert_eq!(
        evaluate_active_peer_health("p-missing-grant", Some(&snapshot), None),
        ActivePeerHealth::NoGrant
    );
    assert_eq!(
        evaluate_active_peer_health("p-zero-grant", Some(&snapshot), None),
        ActivePeerHealth::NoGrant
    );
    assert_eq!(
        evaluate_active_peer_health("p-rev-unk", Some(&snapshot), None),
        ActivePeerHealth::Revoked
    );
    assert_eq!(
        evaluate_active_peer_health("p-down-unk", Some(&snapshot), None),
        ActivePeerHealth::Unreachable
    );
    assert_eq!(
        evaluate_active_peer_health("p-unk-ng", Some(&snapshot), None),
        ActivePeerHealth::Incompatible
    );

    assert!(!ActivePeerHealth::Incompatible.allows_management());
    assert!(ActivePeerHealth::Healthy.allows_management());
    assert!(ActivePeerHealth::Limited.allows_management());
}

#[test]
fn remote_settings_and_services_clear_on_revisit_and_live_grant_revocation_and_fence_ordering() {
    use super::server::PeerArea;
    use crate::tabs::cluster::peers::PeersSnapshot;
    use serde_json::Value;

    let make_snapshot = |settings_level: &str, services_level: &str| -> PeersSnapshot {
        serde_json::from_value(json!({
            "local_protocol_version": 1,
            "local_capabilities": ["links", "grants", "proxy.http.v1"],
            "peers": [{
                "id": "peer-b",
                "name": "Beta Peer",
                "state": "active",
                "compatibility": "compatible",
                "missing_capabilities": [],
                "grants": {
                    "outbound": {
                        "id": "g-b",
                        "run_as_user_id": 1,
                        "access": {
                            "services": services_level,
                            "settings": settings_level,
                            "files": "write"
                        }
                    }
                }
            }]
        }))
        .unwrap()
    };

    Owner::new().with(|| {
        let context = AppContext::new();
        context.apply_authenticated_user(
            json!({
                "id": 1,
                "username": "admin",
                "role": "admin"
            }),
            false,
        );
        context.apply_peers_snapshot(make_snapshot("write", "read"));
        context
            .settings
            .set(json!({"baseDomain": "local.example.com"}));
        context
            .services
            .set(json!({"local_svc": {"status": "running"}}));
        context.pending.set(2);

        // First visit to peer-b populates remote settings/services/pending.
        assert!(context.select_server(Some("peer-b".into())));
        assert_eq!(context.settings.get_untracked(), Value::Null);
        assert_eq!(context.services.get_untracked(), Value::Null);
        assert_eq!(context.pending.get_untracked(), 0);

        let older_get = context.begin_settings_request();
        // A newer explicit settings save must not be overwritten by an older in-flight GET.
        assert!(context.publish_settings_save(json!({"baseDomain": "saved.example.com"})));
        assert_eq!(
            context.settings.get_untracked()["baseDomain"],
            "saved.example.com"
        );
        assert!(!context
            .finish_settings_request(older_get, json!({"baseDomain": "stale-older.example.com"})));
        assert_eq!(
            context.settings.get_untracked()["baseDomain"],
            "saved.example.com"
        );

        let svc_req = context.begin_services_request();
        assert!(
            context.finish_services_request(svc_req, json!({"remote_svc": {"status": "running"}}))
        );
        context.pending.set(4);

        // Return to local -> local cache restores cleanly.
        context.exit_to_local_server();
        assert_eq!(
            context.settings.get_untracked()["baseDomain"],
            "local.example.com"
        );
        assert_eq!(
            context.services.get_untracked()["local_svc"]["status"],
            "running"
        );
        assert_eq!(context.pending.get_untracked(), 2);

        // Revisit peer-b -> remote settings/services/pending MUST start clean, never reusing stale cache!
        assert!(context.select_server(Some("peer-b".into())));
        assert_eq!(context.settings.get_untracked(), Value::Null);
        assert_eq!(context.services.get_untracked(), Value::Null);
        assert_eq!(context.pending.get_untracked(), 0);

        // Populate fresh authorized remote settings/services.
        let fresh_settings = context.begin_settings_request();
        assert!(context
            .finish_settings_request(fresh_settings, json!({"baseDomain": "updated.example.com"})));
        let fresh_services = context.begin_services_request();
        assert!(context.finish_services_request(
            fresh_services,
            json!({"remote_svc_2": {"status": "running"}})
        ));
        context.pending.set(3);

        // Live revocation of Settings read clears settings immediately, bumps revocation epoch, and fences late reads.
        let inflight_settings = context.begin_settings_request();
        let settings_rev_before = context.area_revocation_epoch_untracked(PeerArea::Settings);
        context.apply_peers_snapshot(make_snapshot("none", "read"));
        assert_eq!(
            context.area_revocation_epoch_untracked(PeerArea::Settings),
            settings_rev_before + 1
        );
        assert_eq!(context.settings.get_untracked(), Value::Null);
        assert!(!context.finish_settings_request(
            inflight_settings,
            json!({"baseDomain": "revoked-late.example.com"})
        ));
        assert_eq!(context.settings.get_untracked(), Value::Null);

        // Re-granting Settings read does NOT bump revocation epoch and does NOT restore stale cache.
        let settings_rev_after = context.area_revocation_epoch_untracked(PeerArea::Settings);
        context.apply_peers_snapshot(make_snapshot("read", "read"));
        assert_eq!(
            context.area_revocation_epoch_untracked(PeerArea::Settings),
            settings_rev_after
        );
        assert_eq!(context.settings.get_untracked(), Value::Null);
        assert!(!context.finish_settings_request(
            inflight_settings,
            json!({"baseDomain": "pre-revoke-late.example.com"})
        ));
        assert_eq!(context.settings.get_untracked(), Value::Null);
        let post_regrant_settings = context.begin_settings_request();
        assert!(context.finish_settings_request(
            post_regrant_settings,
            json!({"baseDomain": "regranted.example.com"})
        ));
        assert_eq!(
            context.settings.get_untracked()["baseDomain"],
            "regranted.example.com"
        );

        // Live revocation of Services read clears services & pending and rejects late HTTP + WS updates.
        let inflight_svc = context.begin_services_request();
        let svc_rev_before = context.area_revocation_epoch_untracked(PeerArea::Services);
        context.apply_peers_snapshot(make_snapshot("read", "none"));
        assert_eq!(
            context.area_revocation_epoch_untracked(PeerArea::Services),
            svc_rev_before + 1
        );
        assert_eq!(context.services.get_untracked(), Value::Null);
        assert_eq!(context.pending.get_untracked(), 0);
        assert!(!context.finish_services_request(inflight_svc, json!({"late": {}})));
        context.publish_live_services(json!({"ws_late": {}}));
        assert_eq!(context.services.get_untracked(), Value::Null);
    });
}

#[test]
fn same_user_role_demotion_and_promotion_reset_role_scoped_state_without_logout() {
    use crate::tabs::cluster::peers::PeersSnapshot;
    use serde_json::Value;

    let snapshot: PeersSnapshot = serde_json::from_value(json!({
        "local_protocol_version": 1,
        "local_capabilities": ["links", "grants", "proxy.http.v1"],
        "peers": [{
            "id": "peer-b",
            "name": "Beta Peer",
            "state": "active",
            "compatibility": "compatible",
            "missing_capabilities": [],
            "grants": {
                "outbound": {
                    "id": "g-b",
                    "run_as_user_id": 1,
                    "access": { "services": "read", "settings": "read" }
                }
            }
        }]
    }))
    .unwrap();

    Owner::new().with(|| {
        let context = AppContext::new();
        context.apply_authenticated_user(
            json!({
                "id": 7,
                "username": "operator",
                "role": "admin"
            }),
            false,
        );
        context.apply_peers_snapshot(snapshot.clone());
        context
            .settings
            .set(json!({"baseDomain": "local.example.com"}));
        context
            .services
            .set(json!({"local": {"status": "running"}}));
        context.pending.set(5);
        context.tab.set(TabId::Cluster);
        assert!(context.select_server(Some("peer-b".into())));
        context.publish_metrics(json!({
            "timestamp": 1_763_900_000_000_u64,
            "cpu_usage": 64.5,
            "memory_percent": 72.0
        }));
        context
            .notifications
            .set(vec![json!({"id": 99, "title": "Peer beta alert"})]);
        assert!(!context.metrics.get_untracked().is_null());
        assert!(!context.live_samples.get_untracked().is_empty());
        assert!(!context.notifications.get_untracked().is_empty());
        let epoch_before = context.server_epoch.get_untracked();
        let session_before = context.session_epoch.get_untracked();

        // Demote same user (admin -> user) while on remote peer: resets to local & clears all former-server projections, keeps session.
        context.apply_authenticated_user(
            json!({
                "id": 7,
                "username": "operator",
                "role": "user"
            }),
            false,
        );
        assert!(context.user.get_untracked().is_some());
        assert!(!context.is_admin_untracked());
        assert!(!context.is_remote_untracked());
        assert!(context.peers_snapshot.get_untracked().is_none());
        assert_eq!(context.settings.get_untracked(), Value::Null);
        assert_eq!(context.metrics.get_untracked(), Value::Null);
        assert!(context.live_samples.get_untracked().is_empty());
        assert!(context.notifications.get_untracked().is_empty());
        assert_eq!(context.services.get_untracked(), Value::Null);
        assert_eq!(context.pending.get_untracked(), 0);
        assert_eq!(context.tab.get_untracked(), TabId::Overview);
        assert!(context.server_epoch.get_untracked() > epoch_before);
        assert!(context.session_epoch.get_untracked() > session_before);

        // Same user demotion while ALREADY on local server still resets role-scoped state and projections!
        context.apply_authenticated_user(
            json!({
                "id": 7,
                "username": "operator",
                "role": "admin"
            }),
            false,
        );
        assert!(context.is_admin_untracked());
        context.apply_peers_snapshot(snapshot);
        context
            .settings
            .set(json!({"baseDomain": "admin-only.example.com"}));
        context.publish_metrics(json!({
            "timestamp": 1_763_900_010_000_u64,
            "cpu_usage": 31.0
        }));
        context
            .notifications
            .set(vec![json!({"id": 101, "title": "Admin notice"})]);
        assert!(!context.live_samples.get_untracked().is_empty());
        context.pending.set(3);
        context.tab.set(TabId::Audit);
        let local_epoch_before = context.server_epoch.get_untracked();
        let local_session_before = context.session_epoch.get_untracked();

        context.apply_authenticated_user(
            json!({
                "id": 7,
                "username": "operator",
                "role": "user"
            }),
            false,
        );
        assert!(context.user.get_untracked().is_some());
        assert!(!context.is_admin_untracked());
        assert!(context.peers_snapshot.get_untracked().is_none());
        assert_eq!(context.settings.get_untracked(), Value::Null);
        assert_eq!(context.metrics.get_untracked(), Value::Null);
        assert!(context.live_samples.get_untracked().is_empty());
        assert!(context.notifications.get_untracked().is_empty());
        assert_eq!(context.pending.get_untracked(), 0);
        assert_eq!(context.tab.get_untracked(), TabId::Overview);
        assert!(context.server_epoch.get_untracked() > local_epoch_before);
        assert!(context.session_epoch.get_untracked() > local_session_before);

        // Promotion (user -> admin) also bumps epochs and resets role-scoped cache cleanly without logout.
        context.settings.set(json!({"theme": "user-cached"}));
        context.publish_metrics(json!({
            "timestamp": 1_763_900_020_000_u64,
            "cpu_usage": 12.0
        }));
        context
            .notifications
            .set(vec![json!({"id": 102, "title": "User notice"})]);
        assert!(!context.live_samples.get_untracked().is_empty());
        let promo_epoch_before = context.server_epoch.get_untracked();
        let promo_session_before = context.session_epoch.get_untracked();
        context.apply_authenticated_user(
            json!({
                "id": 7,
                "username": "operator",
                "role": "admin"
            }),
            false,
        );
        assert!(context.user.get_untracked().is_some());
        assert!(context.is_admin_untracked());
        assert_eq!(context.settings.get_untracked(), Value::Null);
        assert_eq!(context.metrics.get_untracked(), Value::Null);
        assert!(context.live_samples.get_untracked().is_empty());
        assert!(context.notifications.get_untracked().is_empty());
        assert!(context.server_epoch.get_untracked() > promo_epoch_before);
        assert!(context.session_epoch.get_untracked() > promo_session_before);
    });
}

#[test]
fn peer_area_access_signals_deduplicate_unchanged_polls_and_separate_read_vs_write() {
    use crate::state::PeerArea;
    use crate::tabs::cluster::peers::{AccessLevel, PeersSnapshot};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    Owner::new().with(|| {
        let context = AppContext::new();
        context.apply_authenticated_user(
            json!({"id": 1, "username": "admin", "role": "admin"}),
            false,
        );
        let mk_snapshot = |settings: &str, services: &str| {
            serde_json::from_value::<PeersSnapshot>(json!({
                "local_protocol_version": 1,
                "local_capabilities": ["links", "grants", "proxy.http.v1"],
                "peers": [{
                    "id": "peer-sig",
                    "name": "Signal Peer",
                    "state": "active",
                    "compatibility": "compatible",
                    "missing_capabilities": [],
                    "grants": {
                        "outbound": {
                            "id": "g-sig",
                            "run_as_user_id": 1,
                            "access": {
                                "services": services,
                                "settings": settings,
                                "files": "read",
                                "marketplace": "read",
                                "users": "read",
                                "network": "read",
                                "updates": "read",
                                "transcoding": "read"
                            }
                        }
                    }
                }]
            }))
            .unwrap()
        };

        context.apply_peers_snapshot(mk_snapshot("write", "write"));
        assert!(context.select_server(Some("peer-sig".into())));

        let settings_read_evals = Arc::new(AtomicUsize::new(0));
        let settings_write_evals = Arc::new(AtomicUsize::new(0));
        let services_read_evals = Arc::new(AtomicUsize::new(0));
        let s_r = Arc::clone(&settings_read_evals);
        let s_w = Arc::clone(&settings_write_evals);
        let v_r = Arc::clone(&services_read_evals);

        let settings_read_memo = Memo::new(move |_| {
            s_r.fetch_add(1, Ordering::SeqCst);
            context.can_read_area(PeerArea::Settings)
        });
        let settings_write_memo = Memo::new(move |_| {
            s_w.fetch_add(1, Ordering::SeqCst);
            context.can_write_area(PeerArea::Settings)
        });
        let services_read_memo = Memo::new(move |_| {
            v_r.fetch_add(1, Ordering::SeqCst);
            context.can_read_area(PeerArea::Services)
        });

        assert!(settings_read_memo.get_untracked());
        assert!(settings_write_memo.get_untracked());
        assert!(services_read_memo.get_untracked());
        assert_eq!(settings_read_evals.load(Ordering::SeqCst), 1);
        assert_eq!(settings_write_evals.load(Ordering::SeqCst), 1);
        assert_eq!(services_read_evals.load(Ordering::SeqCst), 1);

        // Unchanged peer poll must NOT re-evaluate any area read/write memo.
        context.apply_peers_snapshot(mk_snapshot("write", "write"));
        assert!(settings_read_memo.get_untracked());
        assert!(settings_write_memo.get_untracked());
        assert!(services_read_memo.get_untracked());
        assert_eq!(settings_read_evals.load(Ordering::SeqCst), 1);
        assert_eq!(settings_write_evals.load(Ordering::SeqCst), 1);
        assert_eq!(services_read_evals.load(Ordering::SeqCst), 1);

        // Settings Write -> Read updates settings_write_memo ONLY (not settings_read or services_read).
        context.apply_peers_snapshot(mk_snapshot("read", "write"));
        assert!(settings_read_memo.get_untracked());
        assert!(!settings_write_memo.get_untracked());
        assert!(services_read_memo.get_untracked());
        assert_eq!(settings_read_evals.load(Ordering::SeqCst), 1);
        assert_eq!(settings_write_evals.load(Ordering::SeqCst), 2);
        assert_eq!(services_read_evals.load(Ordering::SeqCst), 1);
        assert_eq!(context.peer_access(PeerArea::Settings), AccessLevel::Read);

        // Settings Read -> None updates settings_read_memo (and bumps revocation epoch), leaving services_read untouched.
        let prev_epoch = context.area_revocation_epoch_untracked(PeerArea::Settings);
        context.apply_peers_snapshot(mk_snapshot("none", "write"));
        assert!(!settings_read_memo.get_untracked());
        assert!(!settings_write_memo.get_untracked());
        assert!(services_read_memo.get_untracked());
        assert_eq!(settings_read_evals.load(Ordering::SeqCst), 2);
        assert_eq!(settings_write_evals.load(Ordering::SeqCst), 2);
        assert_eq!(services_read_evals.load(Ordering::SeqCst), 1);
        assert_eq!(
            context.area_revocation_epoch_untracked(PeerArea::Settings),
            prev_epoch + 1
        );
    });
}
