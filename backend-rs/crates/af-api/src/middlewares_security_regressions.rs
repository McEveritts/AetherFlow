use super::{
    app_subdomain_proxy_middleware, host_validation_middleware, is_host_trusted,
    is_private_or_loopback_ip, is_rate_limit_disabled_for_env, is_unauth_local_lan_ip,
    resolve_app_target_for_host, unauth_local_lan_enabled,
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

    // ESC-10: unauthenticated LAN bypass classifier allows strictly RFC 1918, link-local,
    // and IPv6 ULA — unconditionally excluding Tailscale CGNAT (100.64.0.0/10) and loopback.
    for allowed_lan in [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.50",
        "169.254.1.1",
        "fe80::1",
        "fc00::1",
        "fd12:3456:789a::1",
        "::ffff:192.168.1.50",
    ] {
        assert!(
            is_unauth_local_lan_ip(allowed_lan),
            "expected RFC 1918/ULA/link-local {allowed_lan} to qualify"
        );
    }
    for denied_bypass in [
        "100.64.0.1",
        "100.127.255.254",
        "::ffff:100.100.100.100",
        "127.0.0.1",
        "127.0.0.2",
        "::1",
        "[::1]:8080",
        "::ffff:127.0.0.1",
        "203.0.113.10",
        "localhost",
        "",
    ] {
        assert!(
            !is_unauth_local_lan_ip(denied_bypass),
            "must never grant unauth local LAN bypass to {denied_bypass}"
        );
    }

    assert!(!is_rate_limit_disabled_for_env(
        Some("1"),
        Some("production")
    ));
    assert!(!is_rate_limit_disabled_for_env(
        Some("true"),
        Some("PRODUCTION")
    ));
    assert!(!is_rate_limit_disabled_for_env(Some("1"), Some("release")));
    assert!(!is_rate_limit_disabled_for_env(
        Some("true"),
        Some("Release")
    ));
    assert!(is_rate_limit_disabled_for_env(Some("1"), None));
    assert!(is_rate_limit_disabled_for_env(Some("true"), Some("test")));
    assert!(!is_rate_limit_disabled_for_env(None, None));
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

#[test]
fn proxy_forwarding_uses_rightmost_untrusted_hop_and_validated_host() {
    use axum::http::{HeaderMap, HeaderValue};

    let name = "middlewares::security_regressions::proxy_forwarding_uses_rightmost_untrusted_hop_and_validated_host";
    if !isolated(name) {
        return;
    }
    env::remove_var("TRUSTED_PROXIES");
    env::set_var("TRUST_PROXY_HEADERS", "true");
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("203.0.113.7, 192.168.1.17, 127.0.0.1"),
    );
    headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.8"));
    headers.insert(
        "x-forwarded-host",
        HeaderValue::from_static("spoofed.example.test"),
    );
    let forwarded: HeaderMap = super::canonical_forwarded_headers(
        &headers,
        "app.example.test:443",
        Some("127.0.0.1".parse().unwrap()),
        true,
    )
    .into_iter()
    .collect();
    assert_eq!(forwarded["x-real-ip"], "192.168.1.17");
    assert_eq!(forwarded["x-forwarded-for"], "192.168.1.17");
    assert_eq!(forwarded["x-forwarded-host"], "app.example.test:443");
    assert!(!crate::ws::is_trusted_proxy_peer(
        "192.168.1.17".parse().unwrap()
    ));
}

#[test]
fn rate_limiter_evicts_oldest_at_capacity() {
    let limiter = super::SlidingWindowLimiter::new(1, std::time::Duration::from_secs(60));
    for index in 0..super::RATE_LIMIT_KEY_CAPACITY {
        assert!(limiter.allow(&format!("client-{index}")));
    }
    assert!(!limiter.allow("client-0"));
    assert!(limiter.allow("new-client"));
    let guard = limiter.visitors.lock().unwrap();
    assert_eq!(guard.timestamps.len(), super::RATE_LIMIT_KEY_CAPACITY);
    assert_eq!(guard.oldest_first.len(), super::RATE_LIMIT_KEY_CAPACITY);
    assert!(!guard.timestamps.contains_key("client-0"));
}

#[tokio::test]
async fn control_plane_requests_bypass_saturated_proxy_resolver() {
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    let _saturation = super::PROXY_RESOLVE_LIMIT.acquire_many(16).await.unwrap();
    let router = Router::new()
        .fallback(get(|| async { StatusCode::OK }))
        .layer(middleware::from_fn(app_subdomain_proxy_middleware));
    for path in ["/health", "/health/live", "/health/ready", "/static/app.js"] {
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            router.clone().oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::HOST, "localhost")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn protected_external_upstream_requires_auth_before_http_or_websocket() {
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    let name = "middlewares::security_regressions::protected_external_upstream_requires_auth_before_http_or_websocket";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    env::set_var("AETHERFLOW_BASE_DOMAIN", "review.test");
    env::set_var("ALLOWED_HOSTS", "localhost,prometheus.review.test");
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "prometheus".into(),
        public_domain: "prometheus.review.test".into(),
        external_access_enabled: true,
        listen_port: 19090,
        ..Default::default()
    })
    .unwrap();
    let app = Router::new()
        .fallback(get(|| async { StatusCode::OK }))
        .layer(middleware::from_fn(app_subdomain_proxy_middleware));
    let writer = af_db::get_conn().unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    for websocket in [false, true] {
        let mut request = Request::builder()
            .uri("/")
            .header(header::HOST, "prometheus.review.test");
        if websocket {
            request = request
                .header(header::UPGRADE, "websocket")
                .header(header::CONNECTION, "Upgrade");
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
    }
    assert!(is_host_trusted(
        "prometheus.review.test",
        &std::collections::HashSet::new()
    ));
    assert!(!is_host_trusted(
        "unknown.review.test",
        &std::collections::HashSet::new()
    ));
    assert!(!is_host_trusted(
        "a.b.review.test",
        &std::collections::HashSet::new()
    ));
    writer.execute_batch("ROLLBACK").unwrap();
    drop(writer);
    drop(fixture);
}

#[test]
fn librespeed_tls_requires_a_readable_pem_when_enabled() {
    let name =
        "middlewares::security_regressions::librespeed_tls_requires_a_readable_pem_when_enabled";
    if !isolated(name) {
        return;
    }
    let root = env::temp_dir().join(format!("af-librespeed-tls-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let settings = root.join("settings.toml");
    env::set_var("AETHERFLOW_LIBRESPEED_SETTINGS_PATH", &settings);
    fs::write(&settings, "enable_tls = false\n").unwrap();
    assert!(super::librespeed_tls_client().unwrap().is_none());

    let cert = root.join("upstream.pem");
    fs::write(
        &settings,
        format!(
            "enable_tls = true\ntls_cert_file = \"{}\"\n",
            cert.display()
        ),
    )
    .unwrap();
    assert!(super::librespeed_tls_client().is_err());
    fs::write(&cert, "invalid PEM").unwrap();
    assert!(super::librespeed_tls_client().is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn gateway_reopens_verified_failed_reinstall_across_restart_and_blocks_incomplete_or_removed() {
    let name = "middlewares::security_regressions::gateway_reopens_verified_failed_reinstall_across_restart_and_blocks_incomplete_or_removed";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    let db = fixture.root.join("gateway.sqlite");
    let lock = fixture.root.join("install/.syncthing.lock");
    fs::write(&lock, "installed").unwrap();
    fixture.active("saved.review.test", true);

    // 1. Complete recovery after a failed reinstall preserves failed outcome and reopens gateway.
    assert!(af_services::try_start_package_job(
        af_services::PackageJobInfo {
            job_id: "reinstall-verified-1".into(),
            package_id: "syncthing".into(),
            action: "reinstall".into(),
            status: "installing".into(),
            progress: 10,
            last_line: "reinstalling".into(),
            started_at: "2026-11-20T00:00:00Z".into(),
            expected_target_version: None,
        }
    ));
    // Active job blocks all gateway routes immediately.
    for host in ["saved.review.test", "syncthing.aether.local"] {
        assert!(
            resolve_app_target_for_host(host).is_none(),
            "active job allowed {host}"
        );
    }
    let outcome = af_services::finish_package_job_with_recovery(
        "syncthing",
        "reinstall",
        false,
        Some(af_services::PackageJobFailure::Installer),
        "reinstall-verified-1",
        Some("installer".into()),
        Some(1),
        Some("installer exited with status 1".into()),
        None,
        None,
        Some(af_runner::af_release::lifecycle::RECOVERY_STATE_PRIOR_VERIFIED.into()),
    )
    .unwrap();
    assert_eq!(outcome.status, "failed");
    assert_eq!(outcome.action, "reinstall");
    assert_eq!(
        outcome.recovery_state.as_deref(),
        Some(af_runner::af_release::lifecycle::RECOVERY_STATE_PRIOR_VERIFIED)
    );
    assert_eq!(
        resolve_app_target_for_host("saved.review.test"),
        Some(("syncthing".into(), 18384))
    );
    assert_eq!(
        resolve_app_target_for_host("syncthing.aether.local"),
        Some(("syncthing".into(), 18384))
    );

    // 2. Survives API restart (fresh JobRegistry opened against same SQLite DB + cache reset).
    af_services::initialize_package_jobs(rusqlite::Connection::open(&db).unwrap()).unwrap();
    af_db::invalidate_ingress_cache();
    let restarted = af_services::get_package_job_outcome("syncthing").unwrap();
    assert_eq!(restarted.job_id, "reinstall-verified-1");
    assert_eq!(restarted.status, "failed");
    assert_eq!(
        restarted.recovery_state.as_deref(),
        Some(af_runner::af_release::lifecycle::RECOVERY_STATE_PRIOR_VERIFIED)
    );
    assert_eq!(
        resolve_app_target_for_host("saved.review.test"),
        Some(("syncthing".into(), 18384))
    );
    assert_eq!(
        resolve_app_target_for_host("syncthing.aether.local"),
        Some(("syncthing".into(), 18384))
    );

    // 3. Current installed & ingress evidence must still hold: missing lock file closes gateway.
    fs::remove_file(&lock).unwrap();
    for host in [
        "saved.review.test",
        "syncthing.aether.local",
        "syncthing.review.test",
    ] {
        assert!(
            resolve_app_target_for_host(host).is_none(),
            "missing install receipt still opened {host}"
        );
    }
    fs::write(&lock, "installed").unwrap();
    assert_eq!(
        resolve_app_target_for_host("saved.review.test"),
        Some(("syncthing".into(), 18384))
    );

    // Disabling external access still blocks external host while allowing internal.
    fixture.active("saved.review.test", false);
    assert!(resolve_app_target_for_host("saved.review.test").is_none());
    assert_eq!(
        resolve_app_target_for_host("syncthing.aether.local"),
        Some(("syncthing".into(), 18384))
    );

    // Archiving ingress (removed/retained state) blocks all aliases even if lock file remains.
    af_db::archive_app_ingress_config("syncthing", false).unwrap();
    for host in [
        "saved.review.test",
        "syncthing.aether.local",
        "syncthing.review.test",
    ] {
        assert!(
            resolve_app_target_for_host(host).is_none(),
            "archived ingress still opened {host}"
        );
    }
    fixture.active("saved.review.test", true);

    // 4. Incomplete / unverified failures for reinstall, update, and install stay unavailable.
    for (idx, action) in ["reinstall", "update", "install"].iter().enumerate() {
        let jid = format!("incomplete-{idx}");
        assert!(af_services::try_start_package_job(
            af_services::PackageJobInfo {
                job_id: jid.clone(),
                package_id: "syncthing".into(),
                action: (*action).into(),
                status: if *action == "update" {
                    "updating"
                } else {
                    "installing"
                }
                .into(),
                progress: 10,
                last_line: "running".into(),
                started_at: "2026-11-20T00:05:00Z".into(),
                expected_target_version: None,
            }
        ));
        let failed = af_services::finish_package_job_with_recovery(
            "syncthing",
            action,
            false,
            Some(af_services::PackageJobFailure::Installer),
            &jid,
            Some("installer".into()),
            Some(1),
            Some("incomplete rollback".into()),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(failed.status, "failed");
        assert_eq!(
            failed.recovery_state.as_deref(),
            (*action == "update")
                .then_some(af_runner::af_release::lifecycle::RECOVERY_STATE_UNVERIFIED)
        );
        for host in [
            "saved.review.test",
            "syncthing.aether.local",
            "syncthing.review.test",
        ] {
            assert!(
                resolve_app_target_for_host(host).is_none(),
                "unverified failed {action} authorized {host}"
            );
        }
    }

    af_db::get_conn().unwrap().execute(
        "INSERT OR REPLACE INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id) VALUES('syncthing','legacy-update','update','failed','now','owner')",
        [],
    ).unwrap();
    assert_eq!(
        resolve_app_target_for_host("saved.review.test"),
        Some(("syncthing".into(), 18384))
    );
    fs::remove_file(&lock).unwrap();
    assert!(resolve_app_target_for_host("saved.review.test").is_none());
    fs::write(&lock, "installed").unwrap();

    // 5. Interrupted and failed remove stay unavailable even if DB recovery_state is tampered.
    for (action, status) in [
        ("remove", "failed"),
        ("reinstall", "interrupted"),
        ("update", "interrupted"),
    ] {
        af_db::get_conn()
            .unwrap()
            .execute(
                "INSERT OR REPLACE INTO package_lifecycle_jobs(package_id,job_id,action,status,started_at,owner_id,recovery_state) VALUES('syncthing','tampered',?1,?2,'now','owner','prior_state_verified')",
                rusqlite::params![action, status],
            )
            .unwrap();
        for host in [
            "saved.review.test",
            "syncthing.aether.local",
            "syncthing.review.test",
        ] {
            assert!(
                resolve_app_target_for_host(host).is_none(),
                "{action}/{status} with tampered recovery_state authorized {host}"
            );
        }
    }
}

#[test]
fn security_gateway_never_exposes_stale_legacy_swizzin_receipt_or_symlinked_install_dir() {
    use std::os::unix::fs::symlink;

    let name = "middlewares::security_regressions::security_gateway_never_exposes_stale_legacy_swizzin_receipt_or_symlinked_install_dir";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();

    // A stale /etc/Swizzin lock alone must never expose an app in the API gateway.
    let swizzin = fixture.root.join("etc/Swizzin");
    fs::create_dir_all(&swizzin).unwrap();
    fs::write(swizzin.join(".syncthing.lock"), "PORT=18384\n").unwrap();
    for host in ["syncthing.aether.local", "syncthing.review.test"] {
        assert!(
            resolve_app_target_for_host(host).is_none(),
            "stale legacy receipt exposed {host}"
        );
    }

    // A symlinked /install directory pointing to a decoy directory with a lock must fail closed.
    fs::remove_dir(fixture.root.join("install")).unwrap();
    let decoy = fixture.root.join("decoy-install");
    fs::create_dir_all(&decoy).unwrap();
    fs::write(decoy.join(".syncthing.lock"), "installed\n").unwrap();
    symlink(&decoy, fixture.root.join("install")).unwrap();
    assert!(
        resolve_app_target_for_host("syncthing.aether.local").is_none(),
        "symlinked /install directory exposed syncthing"
    );

    // Restoring a real /install directory with a canonical regular lock authorizes internal routing.
    fs::remove_file(fixture.root.join("install")).unwrap();
    fs::create_dir_all(fixture.root.join("install")).unwrap();
    fs::write(fixture.root.join("install/.syncthing.lock"), "installed\n").unwrap();
    assert_eq!(
        resolve_app_target_for_host("syncthing.aether.local"),
        Some(("syncthing".into(), 8384))
    );
}

#[tokio::test]
async fn esc13_unlisted_ip_hosts_fail_closed_without_csp_or_oidc_reflection() {
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{header, Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    let name = "middlewares::security_regressions::esc13_unlisted_ip_hosts_fail_closed_without_csp_or_oidc_reflection";
    if !isolated(name) {
        return;
    }
    let _fixture = Fixture::new();
    env::set_var("ALLOWED_HOSTS", "localhost,127.0.0.1,192.0.2.99");

    let allowed = HashSet::from(["192.0.2.99".to_string()]);
    assert!(is_host_trusted("127.0.0.1", &HashSet::new()));
    assert!(is_host_trusted("[::1]:8080", &HashSet::new()));
    assert!(is_host_trusted("192.0.2.99:8080", &allowed));
    assert!(!is_host_trusted("192.0.2.55", &allowed));
    assert!(!is_host_trusted("10.20.30.40:8080", &allowed));
    assert!(!is_host_trusted("[2001:db8::1]:8080", &allowed));

    let app = crate::routes::build_router();

    // Unlisted IPv4/IPv6 Host and X-Forwarded-Host must return 400 INVALID_HOST with zero CSP reflection.
    for bad_host in ["192.0.2.55:8080", "[2001:db8::1]:8080", "evil.example.test"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .header(header::HOST, bad_host)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad_host}");
        if let Some(csp) = resp
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
        {
            assert!(
                csp.contains("default-src 'none'")
                    && !csp.contains(bad_host)
                    && !csp.contains("'wasm-unsafe-eval'"),
                "rejected Host {bad_host} must not reflect into SPA CSP: {csp}"
            );
        }
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("INVALID_HOST"), "{bad_host}: {body_str}");
        assert!(!body_str.contains(bad_host), "{bad_host}: {body_str}");
    }

    // Trusted proxy forwarding an unlisted IP via X-Forwarded-Host also returns 400 INVALID_HOST.
    let xfh_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .header(header::HOST, "localhost:8080")
                .header("x-forwarded-host", "198.51.100.77:8080")
                .extension(ConnectInfo(
                    "127.0.0.1:45678".parse::<SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(xfh_resp.status(), StatusCode::BAD_REQUEST);

    // Allowed IP in ALLOWED_HOSTS succeeds and receives validated ws/wss connect-src on 200 OK,
    // while non-200 error responses omit SPA CSP.
    let ui_app = Router::new()
        .route("/ok", get(|| async { (StatusCode::OK, "ok") }))
        .route("/err", get(|| async { (StatusCode::NOT_FOUND, "missing") }))
        .layer(middleware::from_fn(
            crate::routes::security_headers_middleware,
        ))
        .layer(middleware::from_fn(host_validation_middleware));
    let ok_resp = ui_app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ok")
                .header(header::HOST, "192.0.2.99:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK);
    let csp = ok_resp.headers()["content-security-policy"]
        .to_str()
        .unwrap();
    assert!(csp.contains("connect-src 'self' ws://192.0.2.99:8080 wss://192.0.2.99:8080"));

    let err_resp = ui_app
        .oneshot(
            Request::builder()
                .uri("/err")
                .header(header::HOST, "192.0.2.99:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(err_resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        err_resp.headers()["content-security-policy"],
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    );

    // Verify AF_ALLOW_UNAUTH_LOCAL_LAN defaults to false and parses 1/true case-insensitively.
    env::remove_var("AF_ALLOW_UNAUTH_LOCAL_LAN");
    assert!(!unauth_local_lan_enabled());
    env::set_var("AF_ALLOW_UNAUTH_LOCAL_LAN", "TRUE");
    assert!(unauth_local_lan_enabled());
    env::set_var("AF_ALLOW_UNAUTH_LOCAL_LAN", "1");
    assert!(unauth_local_lan_enabled());
    env::set_var("AF_ALLOW_UNAUTH_LOCAL_LAN", "0");
    assert!(!unauth_local_lan_enabled());
    env::remove_var("AF_ALLOW_UNAUTH_LOCAL_LAN");
}
