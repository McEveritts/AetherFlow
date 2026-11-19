use super::{
    app_subdomain_proxy_middleware, is_host_trusted, is_private_or_loopback_ip,
    resolve_app_target_for_host,
};
use std::{env, fs, path::PathBuf};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = env::temp_dir().join(format!("af-routing-security-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("install")).unwrap();
        env::set_var("AETHERFLOW_FS_ROOT", &root);
        env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
        env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
        let database = root.join("gateway.sqlite");
        for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
            env::set_var(key, &database);
        }
        let catalog = root.join("packages.json");
        fs::write(
            &catalog,
            serde_json::to_vec(&serde_json::json!([{
                "name": "syncthing", "label": "Syncthing", "description": "disposable fixture",
                "lock_file": "/install/.syncthing.lock", "category": "test",
                "service_type": "systemd", "service_name": "syncthing", "default_port": 8384
            }]))
            .unwrap(),
        )
        .unwrap();
        env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
        let automation = root.join("automation.json");
        fs::write(&automation, "{}").unwrap();
        env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
        af_db::init_db().unwrap();
        assert_eq!(af_db::get_db_path(), database.to_string_lossy());
        af_services::initialize_package_jobs(rusqlite::Connection::open(&database).unwrap())
            .unwrap();
        af_db::set_base_domain("review.test").unwrap();
        Self { root }
    }

    fn active(&self, domain: &str, external: bool) {
        af_db::set_app_ingress_config(&af_models::AppIngressConfig {
            app_name: "syncthing".into(),
            public_domain: domain.into(),
            external_access_enabled: external,
            listen_port: 18384,
            ..Default::default()
        })
        .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn isolated(name: &str) -> bool {
    if env::var("AF_ROUTING_SECURITY_CHILD").as_deref() == Ok(name) {
        return true;
    }
    assert!(std::process::Command::new(env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("AF_ROUTING_SECURITY_CHILD", name)
        .status()
        .unwrap()
        .success());
    false
}

#[test]
fn security_gateway_archival_revokes_catalog_default_aliases() {
    if !isolated("middlewares::security_regressions::security_gateway_archival_revokes_catalog_default_aliases") {
        return;
    }
    let fixture = Fixture::new();
    fixture.active("saved.review.test", true);
    assert_eq!(
        resolve_app_target_for_host("saved.review.test"),
        Some(("syncthing".into(), 18384))
    );
    af_db::archive_app_ingress_config("syncthing", false).unwrap();
    assert!(af_db::get_all_app_ingress_configs().unwrap().is_empty());
    assert!(af_db::get_retained_app_ingress_config("syncthing")
        .unwrap()
        .is_some());
    assert!(!fixture.root.join("install/.syncthing.lock").exists());
    for host in [
        "saved.review.test",
        "syncthing.aether.local",
        "syncthing.review.test",
    ] {
        let target = resolve_app_target_for_host(host);
        println!("archived host={host}; deployed_resolver={target:?}");
        assert!(
            target.is_none(),
            "archived app regained route for {host}: {target:?}"
        );
    }
}

#[test]
fn security_gateway_installed_and_explicit_ingress_policies() {
    if !isolated("middlewares::security_regressions::security_gateway_installed_and_explicit_ingress_policies") {
        return;
    }
    let fixture = Fixture::new();
    fs::write(fixture.root.join("install/.syncthing.lock"), "installed").unwrap();
    assert_eq!(
        resolve_app_target_for_host("syncthing.aether.local"),
        Some(("syncthing".into(), 8384))
    );
    for host in ["syncthing.review.test", "SYNCTHING.review.test.:443"] {
        assert!(
            resolve_app_target_for_host(host).is_none(),
            "unconfigured external host must fail closed: {host}"
        );
    }
    fixture.active("saved.review.test", false);
    assert_eq!(
        resolve_app_target_for_host("syncthing.aether.local"),
        Some(("syncthing".into(), 18384))
    );
    assert!(resolve_app_target_for_host("syncthing.review.test").is_none());
    assert!(resolve_app_target_for_host("saved.review.test").is_none());
    fixture.active("saved.review.test", true);
    assert_eq!(
        resolve_app_target_for_host("saved.review.test:443"),
        Some(("syncthing".into(), 18384))
    );
    assert!(resolve_app_target_for_host("syncthing.review.test").is_none());
    fixture.active("", true);
    assert_eq!(
        resolve_app_target_for_host("syncthing.review.test"),
        Some(("syncthing".into(), 18384))
    );
    fs::remove_file(fixture.root.join("install/.syncthing.lock")).unwrap();
    assert_eq!(
        resolve_app_target_for_host("syncthing.aether.local"),
        Some(("syncthing".into(), 18384))
    );
    for port in [0, -1, 65536] {
        af_db::get_conn()
            .unwrap()
            .execute(
                "UPDATE app_ingress_configs SET listen_port=?1 WHERE app_name='syncthing'",
                [port],
            )
            .unwrap();
        af_db::invalidate_ingress_cache();
        for host in [
            "syncthing.aether.local",
            "syncthing.review.test",
            "saved.review.test",
        ] {
            assert!(
                resolve_app_target_for_host(host).is_none(),
                "port={port}; host={host}"
            );
        }
    }
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "explicit-app".into(),
        public_domain: "explicit.review.test".into(),
        external_access_enabled: true,
        listen_port: 18080,
        ..Default::default()
    })
    .unwrap();
    for host in ["explicit-app.aether.local", "explicit.review.test"] {
        assert_eq!(
            resolve_app_target_for_host(host),
            Some(("explicit-app".into(), 18080))
        );
    }
    for host in [
        "review.test",
        "www.review.test",
        "direct.review.test",
        "aetherflow.review.test",
        "unknown.aether.local",
        "syncthing.aether.local:bad",
    ] {
        assert!(resolve_app_target_for_host(host).is_none(), "{host}");
    }
}

#[test]
fn security_gateway_retained_state_cannot_be_revived_by_stale_install_lock() {
    if !isolated("middlewares::security_regressions::security_gateway_retained_state_cannot_be_revived_by_stale_install_lock") {
        return;
    }
    let fixture = Fixture::new();
    fixture.active("saved.review.test", true);
    af_db::archive_app_ingress_config("syncthing", false).unwrap();
    fs::write(fixture.root.join("install/.syncthing.lock"), "stale").unwrap();
    for host in [
        "syncthing.aether.local",
        "syncthing.review.test",
        "saved.review.test",
    ] {
        assert!(
            resolve_app_target_for_host(host).is_none(),
            "retained state revived {host}"
        );
    }
    af_db::get_conn()
        .unwrap()
        .execute(
            "UPDATE retained_app_ingress_configs SET config_json='{invalid'",
            [],
        )
        .unwrap();
    assert!(resolve_app_target_for_host("syncthing.aether.local").is_none());
    fixture.active("saved.review.test", true);
    assert_eq!(
        resolve_app_target_for_host("saved.review.test"),
        Some(("syncthing".into(), 18384))
    );
    af_db::archive_app_ingress_config("syncthing", true).unwrap();
    fs::remove_file(fixture.root.join("install/.syncthing.lock")).unwrap();
    assert!(resolve_app_target_for_host("syncthing.review.test").is_none());
}

#[test]
fn security_gateway_unknown_installation_and_catalog_fail_closed() {
    use std::os::unix::fs::symlink;
    if !isolated("middlewares::security_regressions::security_gateway_unknown_installation_and_catalog_fail_closed") {
        return;
    }
    let fixture = Fixture::new();
    fixture.active("saved.review.test", true);
    let lock = fixture.root.join("install/.syncthing.lock");
    let target = fixture.root.join("outside-lock");
    fs::write(&target, "installed").unwrap();
    symlink(&target, &lock).unwrap();
    for host in [
        "syncthing.aether.local",
        "syncthing.review.test",
        "saved.review.test",
    ] {
        assert!(
            resolve_app_target_for_host(host).is_none(),
            "symlink lock authorized {host}"
        );
    }
    fs::remove_file(&lock).unwrap();
    fs::create_dir(&lock).unwrap();
    assert!(resolve_app_target_for_host("saved.review.test").is_none());
    fs::remove_dir(&lock).unwrap();
    fs::write(&lock, "installed").unwrap();
    fs::write(fixture.root.join("packages.json"), "{invalid").unwrap();
    assert!(resolve_app_target_for_host("saved.review.test").is_none());
}

#[test]
fn security_gateway_lifecycle_uncertainty_blocks_all_aliases() {
    if !isolated("middlewares::security_regressions::security_gateway_lifecycle_uncertainty_blocks_all_aliases") {
        return;
    }
    let fixture = Fixture::new();
    fixture.active("saved.review.test", true);
    fs::write(fixture.root.join("install/.syncthing.lock"), "installed").unwrap();
    let states = [
        ("install", "installing"),
        ("remove", "uninstalling"),
        ("update", "updating"),
        ("install", "unknown-phase"),
        ("install", "failed"),
        ("remove", "failed"),
        ("update", "interrupted"),
    ];
    for (action, status) in states {
        af_db::get_conn().unwrap().execute(
            "INSERT OR REPLACE INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id) VALUES('syncthing','fixture-job',?1,?2,'now','fixture-owner')",
            rusqlite::params![action, status],
        ).unwrap();
        for host in [
            "syncthing.aether.local",
            "syncthing.review.test",
            "saved.review.test",
        ] {
            let target = resolve_app_target_for_host(host);
            assert!(
                target.is_none(),
                "{action}/{status} authorized {host}: {target:?}"
            );
        }
    }
    af_db::get_conn()
        .unwrap()
        .execute(
            "UPDATE package_lifecycle_jobs SET action='install', status='completed'",
            [],
        )
        .unwrap();
    assert_eq!(
        resolve_app_target_for_host("saved.review.test"),
        Some(("syncthing".into(), 18384))
    );
    af_db::get_conn()
        .unwrap()
        .execute("DROP TABLE package_lifecycle_jobs", [])
        .unwrap();
    assert!(resolve_app_target_for_host("saved.review.test").is_none());
}

#[test]
fn security_gateway_ingress_read_error_does_not_authorize_catalog_fallback() {
    if !isolated("middlewares::security_regressions::security_gateway_ingress_read_error_does_not_authorize_catalog_fallback") {
        return;
    }
    let fixture = Fixture::new();
    fs::write(fixture.root.join("install/.syncthing.lock"), "installed").unwrap();
    assert!(resolve_app_target_for_host("syncthing.aether.local").is_some());
    af_db::get_conn()
        .unwrap()
        .execute("DROP TABLE app_ingress_configs", [])
        .unwrap();
    af_db::invalidate_ingress_cache();
    for host in ["syncthing.aether.local", "syncthing.review.test"] {
        assert!(
            resolve_app_target_for_host(host).is_none(),
            "failed ingress read authorized {host}"
        );
    }
}

#[test]
fn security_gateway_ip_canonicalization_tailscale_cgnat_and_127_evil_rejection() {
    assert!(is_private_or_loopback_ip("127.0.0.1"));
    assert!(is_private_or_loopback_ip("::1"));
    assert!(is_private_or_loopback_ip("[::1]:8080"));
    assert!(is_private_or_loopback_ip("::ffff:127.0.0.1"));
    assert!(is_private_or_loopback_ip("[::ffff:127.0.0.1]:443"));
    assert!(is_private_or_loopback_ip("100.64.0.1"));
    assert!(is_private_or_loopback_ip("100.127.255.254"));
    assert!(is_private_or_loopback_ip("::ffff:100.100.100.100"));

    assert!(!is_private_or_loopback_ip("127.evil"));
    assert!(!is_private_or_loopback_ip("127.evil.example.com"));
    assert!(!is_private_or_loopback_ip("10.attacker.com"));
    assert!(!is_private_or_loopback_ip("localhost"));
    assert!(!is_private_or_loopback_ip(""));
    assert!(!is_private_or_loopback_ip("100.63.255.255"));
    assert!(!is_private_or_loopback_ip("100.128.0.1"));
    assert!(!is_private_or_loopback_ip("::ffff:203.0.113.10"));

    assert!(crate::ws::is_trusted_proxy_peer(
        "::ffff:127.0.0.1".parse().unwrap()
    ));
    assert!(!crate::ws::is_trusted_proxy_peer(
        "::ffff:203.0.113.10".parse().unwrap()
    ));
}

#[tokio::test]
async fn security_gateway_disabled_external_subdomain_fails_closed_without_serving_dashboard() {
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use std::collections::HashSet;
    use tower::ServiceExt;

    if !isolated("middlewares::security_regressions::security_gateway_disabled_external_subdomain_fails_closed_without_serving_dashboard") {
        return;
    }
    let fixture = Fixture::new();
    fs::write(
        fixture.root.join("packages.json"),
        serde_json::to_vec(&serde_json::json!([
            {
                "name": "syncthing", "label": "Syncthing", "description": "disposable fixture",
                "lock_file": "/install/.syncthing.lock", "category": "test",
                "service_type": "systemd", "service_name": "syncthing", "default_port": 8384
            },
            {
                "name": "sonarr", "label": "Sonarr", "description": "unconfigured catalog app",
                "lock_file": "/install/.sonarr.lock", "category": "test",
                "service_type": "systemd", "service_name": "sonarr", "default_port": 8989
            }
        ]))
        .unwrap(),
    )
    .unwrap();
    fs::write(fixture.root.join("install/.syncthing.lock"), "installed").unwrap();
    fixture.active("sync.review.test", false);

    // Disabled public_domain and disabled <catalog_app>.<base_domain> must NOT be trusted for control-plane routes
    let empty_allowed = HashSet::new();
    assert!(!is_host_trusted("sync.review.test", &empty_allowed));
    assert!(!is_host_trusted("syncthing.review.test", &empty_allowed));
    assert!(!is_host_trusted("sonarr.review.test", &empty_allowed));
    assert!(is_host_trusted("review.test", &empty_allowed));
    assert!(is_host_trusted("aetherflow.review.test", &empty_allowed));

    // app_subdomain_proxy_middleware must return 403 rather than falling through to dashboard
    let app = Router::new()
        .route("/", get(|| async { (StatusCode::OK, "DASHBOARD") }))
        .layer(middleware::from_fn(app_subdomain_proxy_middleware));

    for disabled_host in [
        "sync.review.test",
        "syncthing.review.test",
        "sonarr.review.test",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, disabled_host)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "disabled external app host {disabled_host} must fail closed"
        );
    }

    // Control-plane base_domain must still pass through cleanly even if packages.json is unreadable
    fs::write(fixture.root.join("packages.json"), "{corrupt").unwrap();
    let ok_resp = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::HOST, "review.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK);
}
