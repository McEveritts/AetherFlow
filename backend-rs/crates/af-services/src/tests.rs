use super::*;

#[cfg(unix)]
#[tokio::test]
async fn local_service_guardian_outlives_parent_guard_without_leaking_into_daemon() {
    use tokio::io::AsyncReadExt;
    let root = env::temp_dir().join(format!("af-service-guardian-{}", uuid::Uuid::new_v4()));
    let path = root.join("maintenance.lock");
    let guard = af_release::ReleaseLockGuard::acquire(&path, std::time::Duration::ZERO).unwrap();
    let mut command = guarded_service_command(&guard, "/bin/sh", &[
        "-c", "test ! -e /proc/self/fd/\"$AF_MAINTENANCE_GUARD_FD\" || exit 92; printf ready; /bin/cat",
    ]).unwrap();
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = command.spawn().unwrap();
    drop(command);
    let mut ready = [0u8; 5];
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .await
        .unwrap();
    assert_eq!(&ready, b"ready");
    drop(guard);
    assert!(af_release::ReleaseLockGuard::acquire(&path, std::time::Duration::ZERO).is_err());
    drop(child.stdin.take());
    assert!(child.wait().await.unwrap().success());
    drop(af_release::ReleaseLockGuard::acquire(&path, std::time::Duration::ZERO).unwrap());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn launch_target_prefers_active_public_ingress_and_hides_loopback_ports() {
    let name = "tests::launch_target_prefers_active_public_ingress_and_hides_loopback_ports";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    let fixture = crate::inventory_regressions::Fixture::new();
    env::set_var("AETHERFLOW_CONFIG_ROOT", &fixture.root);
    let enabled = fixture.root.join("etc/apache2/sites-enabled");
    fs::create_dir_all(&enabled).unwrap();
    let public_vhost = enabled.join("aetherflow-ext-qbittorrent.conf");
    assert_eq!(qbittorrent_bind_scope(None), "loopback");
    assert_eq!(qbittorrent_bind_scope(Some("192.168.1.20")), "network");
    assert_eq!(
        launch_target("qbittorrent", 8080, "/", None, "192.168.1.9"),
        (
            None,
            Some(af_models::APP_LAUNCH_SCOPE_UNAVAILABLE.to_string())
        )
    );
    let ingress_http = af_models::AppIngressConfig {
        public_domain: "qbit.example.test".to_owned(),
        external_access_enabled: true,
        tls_enabled: false,
        listen_port: 8080,
        ..Default::default()
    };
    let unpublished = launch_target("qbittorrent", 8080, "/", Some(&ingress_http), "192.168.1.9");
    assert_eq!(unpublished.0, None);
    fs::write(
        &public_vhost,
        "<VirtualHost *:80>\n    ServerName qbit.example.test\n</VirtualHost>\n",
    )
    .unwrap();
    let launch_http = launch_target("qbittorrent", 8080, "/", Some(&ingress_http), "192.168.1.9");
    assert_eq!(launch_http.0.as_deref(), Some("http://qbit.example.test"));
    assert_eq!(launch_http.1.as_deref(), Some("public"));

    // The pending HTTP vhost only answers ACME requests.
    let ingress_tls = af_models::AppIngressConfig {
        public_domain: "qbit-unprovisioned.example.test".to_owned(),
        external_access_enabled: true,
        tls_enabled: true,
        listen_port: 8080,
        ..Default::default()
    };
    fs::write(
        &public_vhost,
        concat!(
            "<VirtualHost *:80>\n    ServerName qbit-unprovisioned.example.test\n",
            "    ErrorDocument 503 \"TLS certificate provisioning pending\"\n</VirtualHost>\n"
        ),
    )
    .unwrap();
    let launch_unready = launch_target("qbittorrent", 8080, "/", Some(&ingress_tls), "192.168.1.9");
    assert_eq!(
        launch_unready.1.as_deref(),
        Some(af_models::APP_LAUNCH_SCOPE_UNAVAILABLE)
    );
    assert_eq!(launch_unready.0, None);

    let launch = launch_target("direct-launch-test", 8989, "/app", None, "192.168.1.9");
    assert_eq!(launch.0.as_deref(), Some("http://192.168.1.9:8989/app"));
    assert_eq!(launch.1.as_deref(), Some("network"));
    for bad in ["/../admin", "//evil.test", "/app?x=1", "/app#frag"] {
        let fallback = launch_target("direct-launch-test", 8989, bad, None, "192.168.1.9");
        assert_eq!(
            fallback.0.as_deref(),
            Some("http://192.168.1.9:8989"),
            "{bad}"
        );
        assert_eq!(fallback.1.as_deref(), Some("network"), "{bad}");
    }
}

#[test]
fn launch_target_and_inventories_honor_retained_url_bases_safely() {
    let name = "tests::launch_target_and_inventories_honor_retained_url_bases_safely";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    let fixture = crate::inventory_regressions::Fixture::new();
    env::set_var("AETHERFLOW_CONFIG_ROOT", &fixture.root);
    af_db::init_db().unwrap();
    let enabled = fixture.root.join("etc/apache2/sites-enabled");
    fs::create_dir_all(&enabled).unwrap();

    let write_rel = |rel: &str, body: &str| {
        let full = fixture.root.join(rel);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(&full, body).unwrap();
    };

    let mut sonarr_pkg =
        crate::inventory_regressions::Fixture::package("sonarr", "systemd", "sonarr");
    sonarr_pkg["label"] = serde_json::json!("Sonarr");
    sonarr_pkg["default_port"] = serde_json::json!(8989);
    sonarr_pkg["web_path"] = serde_json::json!("/");

    let mut bazarr_pkg =
        crate::inventory_regressions::Fixture::package("bazarr", "systemd", "bazarr");
    bazarr_pkg["label"] = serde_json::json!("Bazarr");
    bazarr_pkg["default_port"] = serde_json::json!(6767);
    bazarr_pkg["web_path"] = serde_json::json!("/web");

    let mut sab_pkg =
        crate::inventory_regressions::Fixture::package("sabnzbd", "systemd", "sabnzbd");
    sab_pkg["label"] = serde_json::json!("SABnzbd");
    sab_pkg["default_port"] = serde_json::json!(8085);
    sab_pkg["web_path"] = serde_json::json!("/sabnzbd");

    let mut tautulli_pkg =
        crate::inventory_regressions::Fixture::package("tautulli", "systemd", "tautulli");
    tautulli_pkg["label"] = serde_json::json!("Tautulli");
    tautulli_pkg["default_port"] = serde_json::json!(8181);
    tautulli_pkg["web_path"] = serde_json::json!("/");

    let mut radarr_pkg =
        crate::inventory_regressions::Fixture::package("radarr", "systemd", "radarr");
    radarr_pkg["label"] = serde_json::json!("Radarr");
    radarr_pkg["default_port"] = serde_json::json!(7878);
    radarr_pkg["web_path"] = serde_json::json!("/");

    fixture.write_packages(&[sonarr_pkg, bazarr_pkg, sab_pkg, tautulli_pkg, radarr_pkg]);
    for app in ["sonarr", "bazarr", "sabnzbd", "tautulli"] {
        fixture.install(app);
    }

    write_rel(
        "var/lib/sonarr/config.xml",
        "<Config><Port>18989</Port><UrlBase> /tv/sonarr/ </UrlBase></Config>",
    );
    write_rel(
        "var/lib/bazarr/config/config.yaml",
        "general:\n  port: 16767\n  base_url: /subs/bazarr/\nsonarr:\n  base_url: /sonarr\n",
    );
    write_rel(
        "var/lib/sabnzbd/sabnzbd.ini",
        "__version__ = 19\n[misc]\nport = 18085\nurl_base = /sabnzbd/\n",
    );
    write_rel(
        "var/lib/tautulli/config.ini",
        "[General]\nhttp_port = 18181\nhttp_root = \"/../evil\"\n",
    );
    write_rel(
        "var/lib/radarr/config.xml",
        "<Config><Port>17878</Port><UrlBase>/movies</UrlBase></Config>",
    );

    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "sonarr".into(),
        public_domain: "sonarr.example.test".into(),
        external_access_enabled: true,
        tls_enabled: true,
        listen_port: 18989,
        ..Default::default()
    })
    .unwrap();
    fs::write(
        enabled.join("aetherflow-ext-sonarr.conf"),
        "<VirtualHost *:443>\n    ServerName sonarr.example.test\n    SSLEngine On\n</VirtualHost>\n",
    )
    .unwrap();
    for app in ["bazarr", "sabnzbd", "tautulli"] {
        fs::write(
            enabled.join(format!("aetherflow-app-{app}.conf")),
            format!("<VirtualHost *:80>\n    ServerName {app}.aether.local\n</VirtualHost>\n"),
        )
        .unwrap();
    }

    clear_service_status_cache();
    mutators::clear_app_runtime_meta_cache();

    // Direct listener with retained base path
    assert_eq!(
        launch_target(
            "direct-launch-test",
            18989,
            "/tv/sonarr",
            None,
            "192.168.1.9"
        ),
        (
            Some("http://192.168.1.9:18989/tv/sonarr".into()),
            Some("network".into())
        )
    );
    // Unexposed loopback app remains unavailable even with a valid base path
    assert_eq!(
        launch_target("radarr", 17878, "/movies", None, "192.168.1.9"),
        (None, Some(af_models::APP_LAUNCH_SCOPE_UNAVAILABLE.into()))
    );

    let pkgs = get_packages().unwrap();
    let pkg = |id: &str| pkgs.iter().find(|p| p.name == id).unwrap();
    assert_eq!(pkg("sonarr").web_path, "/tv/sonarr");
    assert_eq!(
        pkg("sonarr").launch_url.as_deref(),
        Some("https://sonarr.example.test/tv/sonarr")
    );
    assert_eq!(pkg("sonarr").launch_scope.as_deref(), Some("public"));
    assert_eq!(pkg("bazarr").web_path, "/subs/bazarr/web");
    assert_eq!(
        pkg("bazarr").launch_url.as_deref(),
        Some("http://bazarr.aether.local/subs/bazarr/web")
    );
    assert_eq!(pkg("sabnzbd").web_path, "/sabnzbd");
    assert_eq!(
        pkg("sabnzbd").launch_url.as_deref(),
        Some("http://sabnzbd.aether.local/sabnzbd")
    );
    assert_eq!(pkg("tautulli").web_path, "/");
    assert_eq!(
        pkg("tautulli").launch_url.as_deref(),
        Some("http://tautulli.aether.local")
    );
    assert_eq!(pkg("radarr").web_path, "/");
    assert_eq!(pkg("radarr").launch_url, None);
    assert_eq!(
        pkg("radarr").launch_scope.as_deref(),
        Some(af_models::APP_LAUNCH_SCOPE_UNAVAILABLE)
    );

    let services = get_active_services().unwrap();
    assert_eq!(services["Sonarr"].web_path, "/tv/sonarr");
    assert_eq!(
        services["Sonarr"].launch_url.as_deref(),
        Some("https://sonarr.example.test/tv/sonarr")
    );
    assert_eq!(services["Sonarr"].launch_scope.as_deref(), Some("public"));
    assert_eq!(services["Bazarr"].web_path, "/subs/bazarr/web");
    assert_eq!(
        services["Bazarr"].launch_url.as_deref(),
        Some("http://bazarr.aether.local/subs/bazarr/web")
    );
    assert_eq!(services["SABnzbd"].web_path, "/sabnzbd");
    assert_eq!(
        services["SABnzbd"].launch_url.as_deref(),
        Some("http://sabnzbd.aether.local/sabnzbd")
    );
    assert_eq!(services["Tautulli"].web_path, "/");
    assert_eq!(
        services["Tautulli"].launch_url.as_deref(),
        Some("http://tautulli.aether.local")
    );
    assert!(!services.contains_key("Radarr"));
}

#[test]
fn test_marketplace_service_units_include_companions_and_exact_names() {
    for (package, expected) in [
        ("mcvnc", vec!["af-mcvnc"]),
        ("kasmvnc", vec!["af-kasmvnc"]),
        ("qbittorrent", vec!["qbittorrent"]),
        ("prometheus", vec!["prometheus", "node_exporter"]),
        ("recyclarr", vec!["recyclarr", "recyclarr.timer"]),
        ("rclone", vec!["rclone", "rclone-vfs"]),
    ] {
        assert_eq!(resolve_service_units(package), expected, "{}", package);
    }
    for (package, companion) in [
        ("scrutiny", "scrutiny-collector.timer"),
        ("paperless-ngx", "paperless-worker"),
        ("dispatcharr", "dispatcharr-celerybeat"),
    ] {
        let units = resolve_service_units(package);
        assert!(units.iter().any(|unit| unit == companion));
        assert_eq!(resolve_service_units(companion), units);
    }
}

#[test]
fn test_duplicate_lifecycle_job_is_rejected_atomically() {
    let job = PackageJobInfo {
        job_id: uuid::Uuid::new_v4().to_string(),
        package_id: "jellyfin".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 0,
        last_line: String::new(),
        started_at: String::new(),
        expected_target_version: None,
    };
    assert!(try_start_package_job(job.clone()));
    assert!(!try_start_package_job(job.clone()));
    clear_package_job_info(&job.package_id);
    assert!(try_start_package_job(job.clone()));
    clear_package_job_info(&job.package_id);
}

#[test]
fn test_streaming_demo_mode_predicate() {
    let previous = is_streaming_demo_mode();
    set_streaming_demo_mode(true);
    assert!(is_streaming_demo_mode());
    set_streaming_demo_mode(false);
    assert!(!is_streaming_demo_mode());
    set_streaming_demo_mode(previous);
}

#[test]
fn test_internal_domains_are_derived_from_blueprints() {
    let blueprint = get_blueprint("jellyfin").unwrap();
    assert_eq!(
        resolve_app_internal_domain("jellyfin"),
        blueprint.internal_domain
    );
    assert_eq!(
        resolve_app_internal_domain("unknown-audit-app"),
        "unknown-audit-app.aether.local"
    );
}

#[test]
fn test_embedded_package_catalog_loads_all_apps() {
    let catalog = get_package_catalog().unwrap();
    assert!(catalog.len() >= 75);
    assert!(catalog.iter().any(|p| p.name == "jellyfin"));
    assert!(catalog.iter().any(|p| p.name == "kasmvnc"));
    assert!(catalog.iter().any(|p| p.name == "mcvnc"));
    assert!(catalog.iter().any(|p| p.name == "xrdp"));
    assert!(catalog.iter().any(|p| p.name == "tailscale"));
    let palate = catalog
        .iter()
        .find(|p| p.name == "palate")
        .expect("palate catalog entry");
    assert_eq!(palate.service_name, "af-palate");
    assert_eq!(palate.default_port, 28014);
    assert_eq!(palate.update_source, "git_tags");
    assert_eq!(palate.update_repo, "McEveritts/Palate");
    assert_eq!(palate.sandbox_profile, "node");
    let palate_bp = get_blueprint("palate").expect("palate blueprint");
    assert_eq!(palate_bp.health_check_path, "/login");
    assert_eq!(palate_bp.dependencies, vec!["jellyfin".to_string()]);
    let ts_bp = get_blueprint("tailscale").expect("tailscale blueprint");
    assert_eq!(ts_bp.service_name, "tailscaled");
    assert!(ts_bp.is_network_app);
}

#[test]
fn test_maintainerr_catalog_and_blueprint() {
    let catalog = get_package_catalog().unwrap();
    let maintainerr = catalog
        .iter()
        .find(|package| package.name == "maintainerr")
        .expect("maintainerr catalog entry");
    assert_eq!(maintainerr.service_name, "af-maintainerr");
    assert_eq!(maintainerr.default_port, 6246);
    assert_eq!(maintainerr.update_source, "github");
    assert_eq!(maintainerr.update_repo, "Maintainerr/Maintainerr");
    assert_eq!(maintainerr.sandbox_profile, "node");
    assert_eq!(
        maintainerr.version_command,
        vec!["cat", "/opt/maintainerr/.af-version"]
    );
    assert!(maintainerr
        .sandbox_read_write
        .iter()
        .any(|path| path == "/var/lib/maintainerr"));
    let blueprint = get_blueprint("maintainerr").expect("maintainerr blueprint");
    assert_eq!(blueprint.port_env_var, "UI_PORT");
    assert_eq!(blueprint.health_check_path, "/api/health/ready");
    assert!(blueprint.dependencies.is_empty());
    assert_eq!(resolve_service_units("maintainerr"), vec!["af-maintainerr"]);
    assert!(!should_pre_stop_on_update("maintainerr"));
    assert!(!should_pre_stop_on_update("af-maintainerr"));
    assert!(!should_pre_stop_on_update("af-maintainerr.service"));
    assert!(should_pre_stop_on_update("radarr"));
    assert!(should_pre_stop_on_update("jellyfin"));
}

#[test]
fn test_embedded_youtube_marketplace_contracts() {
    let catalog: Vec<Package> = serde_json::from_str(EMBEDDED_PACKAGES_JSON).unwrap();
    let automation: HashMap<String, PackageAutomation> =
        serde_json::from_str(EMBEDDED_AUTOMATION_JSON).unwrap();
    for (app, port, units) in [
        (
            "piped",
            8280,
            vec![
                "af-piped.service",
                "af-piped-api.service",
                "af-piped-proxy.service",
            ],
        ),
        (
            "invidious",
            8281,
            vec!["af-invidious.service", "af-invidious-companion.service"],
        ),
    ] {
        let package = catalog.iter().find(|package| package.name == app).unwrap();
        assert_eq!(package.default_port, port);
        assert_eq!(package.category, "Media");
        assert_eq!(package.service_name, format!("af-{app}"));
        let tracking = automation.get(app).unwrap();
        assert_eq!(tracking.update_source, "git");
        assert!(!tracking.version_command.is_empty());
        assert_ne!(
            tracking.version_command,
            vec!["cat".to_string(), format!("/opt/{app}/.af-version")]
        );
        assert!(!tracking
            .version_command
            .iter()
            .any(|arg| arg.contains(".af-version")));
        if app == "piped" {
            assert_eq!(
                tracking.version_command,
                vec![
                    "bash".to_string(),
                    "-lc".to_string(),
                    "fe=$(git -C /opt/piped/frontend rev-parse HEAD 2>/dev/null || git -C /opt/piped rev-parse HEAD 2>/dev/null) && be=$(git -C /opt/piped/backend rev-parse HEAD 2>/dev/null || git -C /opt/piped-backend rev-parse HEAD 2>/dev/null) && pr=$(git -C /opt/piped/proxy rev-parse HEAD 2>/dev/null || git -C /opt/piped-proxy rev-parse HEAD 2>/dev/null) && [ -n \"$fe\" ] && [ -n \"$be\" ] && [ -n \"$pr\" ] && printf 'frontend:%s,backend:%s,proxy:%s\\n' \"$fe\" \"$be\" \"$pr\"".to_string(),
                ]
            );
        } else if app == "invidious" {
            assert_eq!(
                tracking.version_command,
                vec![
                    "bash".to_string(),
                    "-lc".to_string(),
                    "git -C /opt/invidious/source rev-parse HEAD 2>/dev/null || git -C /opt/invidious rev-parse HEAD 2>/dev/null".to_string(),
                ]
            );
        }
        assert_eq!(tracking.sandbox_service_ids, units);
    }
}

#[test]
fn test_validate_server_url_blocks_ssrf() {
    assert!(validate_server_url("http://127.0.0.1:8096").is_ok());
    assert!(validate_server_url("http://169.254.169.254/latest/meta-data").is_err());
    assert!(validate_server_url("http://168.63.129.16/machine").is_err());
    assert!(validate_server_url("http://[64:ff9b::a9fe:a9fe]/latest/meta-data").is_err());
    assert!(validate_server_url("http://[64:ff9b:1::a9fe:a9fe]/latest/meta-data").is_err());
    assert!(validate_server_url("http://[2002:a9fe:a9fe::1]/latest/meta-data").is_err());
    assert!(validate_server_url("http://[100::1]:8096").is_err());
    assert!(validate_server_url("http://metadata.google.internal").is_err());
}

#[test]
fn test_resolve_service_units_and_format_uptime() {
    assert_eq!(
        resolve_service_units("deluge"),
        vec!["deluged".to_string(), "deluge-web".to_string()]
    );
    assert_eq!(
        resolve_service_units("plex"),
        vec!["plexmediaserver".to_string()]
    );
    assert_eq!(
        format_uptime_duration(chrono::Duration::seconds(90_060)),
        "1d 1h"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_runner_systemctl_propagates_runner_error_without_unprivileged_fallback() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    let sock_name = format!("af-services-runner-test-{}.sock", std::process::id());
    let candidate = std::env::var_os("TMPDIR")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(&sock_name);
    let sock_path = if candidate.as_os_str().len() < 95 {
        candidate
    } else {
        std::path::PathBuf::from("/tmp").join(sock_name)
    };
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).unwrap();

    let prev = std::env::var("AETHERFLOW_RUNNER_SOCK").ok();
    std::env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await.unwrap();
        let body = r#"{"success":false,"output":"Job for jellyfin.service canceled.","error":"exit status: 1"}"#;
        let resp = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
    });

    let err = control_service_with_manager("jellyfin", "restart", "systemd")
        .await
        .expect_err("expected runner failure to be returned directly");
    server.await.unwrap();

    match prev {
        Some(v) => std::env::set_var("AETHERFLOW_RUNNER_SOCK", v),
        None => std::env::remove_var("AETHERFLOW_RUNNER_SOCK"),
    }
    let _ = std::fs::remove_file(&sock_path);

    let msg = err.to_string();
    assert!(
        msg.contains("Job for jellyfin.service canceled"),
        "unexpected error message: {}",
        msg
    );
}

#[test]
fn test_service_capabilities_and_scopes() {
    for app in [
        "maintainerr",
        "palate",
        "kasmvnc",
        "mcvnc",
        "seedcross",
        "ombi",
        "n8n",
        "notifiarr",
        "invidious",
        "radarr",
        "adguardhome",
        "jackett",
        "librespeed",
        "novnc",
        "prometheus",
    ] {
        assert_eq!(
            resolve_service_bind_scope(app),
            "loopback",
            "expected loopback for {}",
            app
        );
    }
    assert_eq!(resolve_service_bind_scope("jellyfin"), "network");
    assert_eq!(resolve_service_web_scheme("kasmvnc", 6081), "https");
    assert_eq!(resolve_service_web_scheme("radarr", 7878), "http");

    for app in [
        "nextcloud",
        "rutorrent",
        "organizr",
        "Nextcloud",
        "ruTorrent",
        "Organizr",
    ] {
        assert_eq!(resolve_service_control_scope(app), "shared-vhost");
        assert!(!should_pre_stop_on_update(app));
    }
    assert_eq!(resolve_service_control_scope("apache2"), "service");
    assert_eq!(
        resolve_service_control_scope("Apache2 Web Server"),
        "service"
    );
    assert!(!should_pre_stop_on_update("maintainerr"));
    assert!(should_pre_stop_on_update("radarr"));
}

#[test]
fn test_component_policies_and_status_aggregation() {
    let autobrr_unconfigured = resolve_service_component_policies_with("rclone", false);
    assert_eq!(autobrr_unconfigured.len(), 2);
    assert_eq!(autobrr_unconfigured[0].unit, "rclone");
    assert_eq!(autobrr_unconfigured[0].role, "required");
    assert!(autobrr_unconfigured[0].configured);
    assert_eq!(autobrr_unconfigured[1].unit, "rclone-vfs");
    assert_eq!(autobrr_unconfigured[1].role, "optional");
    assert!(!autobrr_unconfigured[1].configured);

    assert_eq!(
        resolve_controllable_service_units_with("rclone", "restart", false),
        vec!["rclone".to_string()]
    );
    assert_eq!(
        resolve_controllable_service_units_with("rclone", "restart", true),
        vec!["rclone".to_string(), "rclone-vfs".to_string()]
    );

    let recyclarr_policies = resolve_service_component_policies_with("recyclarr", false);
    assert_eq!(recyclarr_policies[0].unit, "recyclarr");
    assert_eq!(recyclarr_policies[0].role, "oneshot");
    assert_eq!(recyclarr_policies[1].unit, "recyclarr.timer");
    assert_eq!(recyclarr_policies[1].role, "timer");
    assert_eq!(
        resolve_controllable_service_units_with("recyclarr", "start", false),
        vec!["recyclarr.timer".to_string()]
    );
    assert_eq!(
        resolve_controllable_service_units_with("recyclarr", "stop", false),
        vec!["recyclarr.timer".to_string(), "recyclarr".to_string()]
    );

    let autobrr_components = vec![
        ServiceComponentStatus {
            unit: "rclone".to_string(),
            role: "required".to_string(),
            status: "running".to_string(),
            configured: true,
        },
        ServiceComponentStatus {
            unit: "rclone-vfs".to_string(),
            role: "optional".to_string(),
            status: "stopped".to_string(),
            configured: false,
        },
    ];
    assert_eq!(
        aggregate_component_statuses(&autobrr_components, "rclone"),
        ("running".to_string(), "rclone".to_string())
    );

    let mut configured_mount_components = autobrr_components.clone();
    configured_mount_components[1].configured = true;
    assert_eq!(
        aggregate_component_statuses(&configured_mount_components, "rclone").0,
        "degraded"
    );

    let wire = serde_json::to_value(ServiceStatusItem {
        tls_enabled: false,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(wire["tls_enabled"], false);

    let scrutiny_components = vec![
        ServiceComponentStatus {
            unit: "scrutiny".to_string(),
            role: "required".to_string(),
            status: "running".to_string(),
            configured: true,
        },
        ServiceComponentStatus {
            unit: "scrutiny-collector.timer".to_string(),
            role: "timer".to_string(),
            status: "running".to_string(),
            configured: true,
        },
        ServiceComponentStatus {
            unit: "scrutiny-collector.service".to_string(),
            role: "oneshot".to_string(),
            status: "stopped".to_string(),
            configured: true,
        },
    ];
    assert_eq!(
        aggregate_component_statuses(&scrutiny_components, "scrutiny"),
        ("running".to_string(), "scrutiny".to_string())
    );

    let failed_oneshot = vec![
        ServiceComponentStatus {
            unit: "recyclarr.timer".to_string(),
            role: "timer".to_string(),
            status: "running".to_string(),
            configured: true,
        },
        ServiceComponentStatus {
            unit: "recyclarr.service".to_string(),
            role: "oneshot".to_string(),
            status: "failed".to_string(),
            configured: true,
        },
    ];
    assert_eq!(
        aggregate_component_statuses(&failed_oneshot, "recyclarr.timer"),
        ("degraded".to_string(), "recyclarr.timer".to_string())
    );
}

#[tokio::test]
async fn test_shared_vhost_service_control_rejected() {
    let err = control_service_with_manager("Nextcloud", "restart", "systemd")
        .await
        .expect_err("shared-vhost service control must be rejected");
    assert!(err.to_string().contains("shared Apache virtual host"));
}

fn job(pkg: &str, action: &str, status: &str, started_at: &str) -> PackageJobInfo {
    PackageJobInfo {
        job_id: started_at.to_string(),
        package_id: pkg.to_string(),
        action: action.to_string(),
        status: status.to_string(),
        progress: 5,
        last_line: String::new(),
        started_at: started_at.to_string(),
        expected_target_version: None,
    }
}

#[test]
fn test_failed_lifecycle_outcome_survives_active_job_removal() {
    // Regression: a failed update used to clear the active job and leave
    // the package "installed", which clients reported as a successful update.
    let pkg = "syncthing";
    assert!(try_start_package_job(job(pkg, "update", "updating", "t1")));
    assert!(get_package_job_outcome(pkg).is_none());
    let outcome = finish_package_job(pkg, "update", false, "  exit status 1\n", "t1").unwrap();
    assert_eq!(outcome.status, "failed");
    assert_eq!(outcome.message, "Operation failed. Check authenticated service logs for details; rollback and data recovery are not confirmed.");
    assert!(!outcome.message.contains("exit status 1"));
    assert!(get_package_job_info(pkg).is_none());
    let stored = get_package_job_outcome(pkg).expect("terminal outcome retained");
    assert_eq!(stored.action, "update");
    assert_eq!(stored.started_at, "t1");

    // A new job supersedes the previous outcome atomically with registration.
    assert!(try_start_package_job(job(pkg, "update", "updating", "t2")));
    assert!(get_package_job_outcome(pkg).is_none());
    finish_package_job(pkg, "update", true, "Completed update", "t2");
    assert_eq!(get_package_job_outcome(pkg).unwrap().status, "completed");
}

#[test]
fn test_stale_finish_does_not_remove_newer_active_job() {
    let pkg = "sonarr";
    assert!(try_start_package_job(job(
        pkg,
        "install",
        "installing",
        "new"
    )));
    finish_package_job(pkg, "install", false, "late result from old job", "old");
    let active = get_package_job_info(pkg).expect("newer job must remain active");
    assert_eq!(active.started_at, "new");
    assert!(
        get_package_job_outcome(pkg).is_none(),
        "stale finish must not publish an outcome while a newer job is active"
    );
    assert!(!try_start_package_job(job(
        pkg,
        "remove",
        "uninstalling",
        "other"
    )));
    finish_package_job(pkg, "install", true, "done", "new");
    assert!(get_package_job_info(pkg).is_none());
    // A late duplicate finish from the older job cannot replace the newer outcome.
    finish_package_job(pkg, "install", false, "late again", "mid");
    let stored = get_package_job_outcome(pkg).expect("newer outcome retained");
    assert_eq!(stored.started_at, "new");
    assert_eq!(stored.status, "completed");
}

#[test]
fn test_service_control_target_is_limited_to_card_units() {
    // Core cards control only themselves.
    assert_eq!(
        authorize_service_control_target("AetherFlow API", "aetherflow-api", "systemd").unwrap(),
        "aetherflow-api"
    );
    assert_eq!(
        authorize_service_control_target("Apache2 Web Server", "apache2", "systemd").unwrap(),
        "apache2"
    );
    assert!(authorize_service_control_target("AetherFlow API", "ssh", "systemd").is_err());
    assert!(
        authorize_service_control_target("apache2", "aetherflow-runner", "systemd-unit").is_err()
    );

    // Package cards control their own primary and companion units only.
    assert_eq!(
        authorize_service_control_target("sonarr", "sonarr", "systemd").unwrap(),
        "sonarr"
    );
    assert_eq!(
        authorize_service_control_target("sonarr", "", "systemd").unwrap(),
        "sonarr"
    );
    assert_eq!(
        authorize_service_control_target("sonarr", "sonarr.service", "systemd-unit").unwrap(),
        "sonarr.service"
    );
    for foreign in [
        "ssh",
        "sshd",
        "aetherflow-runner",
        "aetherflow-api",
        "radarr",
        "apache2",
    ] {
        assert!(
            authorize_service_control_target("sonarr", foreign, "systemd-unit").is_err(),
            "sonarr card must not control {}",
            foreign
        );
        assert!(
            authorize_service_control_target("sonarr", foreign, "systemd").is_err(),
            "sonarr card must not control {}",
            foreign
        );
    }
    assert_eq!(
        authorize_service_control_target(
            "paperless-ngx",
            "paperless-worker.service",
            "systemd-unit"
        )
        .unwrap(),
        "paperless-worker.service"
    );
    // Shared-vhost packages cannot reach the shared Apache daemon.
    assert!(authorize_service_control_target("nextcloud", "apache2", "systemd-unit").is_err());
    // Unknown cards are not a back door to arbitrary units.
    assert!(authorize_service_control_target("sshd", "sshd", "systemd").is_err());
    assert!(authorize_service_control_target("", "", "systemd").is_err());
}

#[test]
fn test_companion_units_resolve_to_owning_package() {
    assert_eq!(
        resolve_owning_package_id("sonarr").as_deref(),
        Some("sonarr")
    );
    assert_eq!(
        resolve_owning_package_id("paperless-worker.service").as_deref(),
        Some("paperless-ngx")
    );
    assert_eq!(resolve_owning_package_id("sshd"), None);
    assert_eq!(resolve_owning_package_id("aetherflow-api"), None);
}

#[test]
fn config_search_candidates_prioritize_canonical_config_over_legacy_fallback() {
    let candidates = config_search_candidates("packages.json");
    let strings: Vec<String> = candidates
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    assert_eq!(strings[0], "config/packages.json");
    assert_eq!(strings[1], "../config/packages.json");
    assert_eq!(strings[2], "../../config/packages.json");
    assert!(
        !strings
            .iter()
            .any(|s| s == "backend/config/packages.json" || s == "../backend/config/packages.json"),
        "dead relative backend/config paths must be removed: {strings:?}"
    );
    let opt_canonical_idx = strings
        .iter()
        .position(|s| s == "/opt/AetherFlow/current/config/packages.json")
        .unwrap();
    let opt_root_idx = strings
        .iter()
        .position(|s| s == "/opt/AetherFlow/config/packages.json")
        .unwrap();
    let legacy_curr_idx = strings
        .iter()
        .position(|s| s == "/opt/AetherFlow/current/backend/config/packages.json")
        .unwrap();
    let legacy_root_idx = strings
        .iter()
        .position(|s| s == "/opt/AetherFlow/backend/config/packages.json")
        .unwrap();
    assert!(opt_canonical_idx < opt_root_idx);
    assert!(opt_root_idx < legacy_curr_idx);
    assert!(legacy_curr_idx < legacy_root_idx);
}

#[cfg(unix)]
#[test]
fn catalog_reader_rejects_leaf_symlinks_and_directories() {
    let dir = std::env::temp_dir().join(format!("af-cat-sym-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let real_file = dir.join("real.json");
    std::fs::write(&real_file, "[]").unwrap();
    let sym_file = dir.join("sym.json");
    std::os::unix::fs::symlink(&real_file, &sym_file).unwrap();

    assert_eq!(read_catalog_file(&real_file).unwrap(), "[]");
    assert!(read_catalog_file(&sym_file).is_err());
    assert!(read_catalog_file(&dir).is_err());
    assert!(af_runner::open_and_read_regular_config(&sym_file).is_err());
    assert!(af_runner::open_and_read_regular_config(&dir).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_retired_status_tls_readiness_and_sanitized_update_map() {
    let name = "tests::test_retired_status_tls_readiness_and_sanitized_update_map";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    let root = env::temp_dir().join(format!("af-retired-tls-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("install")).unwrap();
    fs::create_dir_all(root.join("var/lib/aetherflow")).unwrap();
    fs::create_dir_all(root.join("etc/apache2/sites-enabled")).unwrap();
    fs::create_dir_all(root.join("etc/letsencrypt/live/sonarr.example.com")).unwrap();

    let catalog = root.join("packages.json");
    fs::write(
        &catalog,
        serde_json::json!([
            {
                "name": "readarr",
                "label": "Readarr",
                "description": "Retired eBook manager",
                "category": "Media",
                "lock_file": "/install/.readarr.lock",
                "default_port": 8787,
                "service_type": "systemd",
                "service_name": "readarr",
                "status": "retired"
            },
            {
                "name": "sonarr",
                "label": "Sonarr",
                "description": "Series manager",
                "category": "Media",
                "lock_file": "/install/.sonarr.lock",
                "default_port": 8989,
                "service_type": "systemd",
                "service_name": "sonarr",
                "status": "uninstalled"
            }
        ])
        .to_string(),
    )
    .unwrap();

    let db = root.join("var/lib/aetherflow/aetherflow.sqlite");
    env::set_var("AETHERFLOW_FS_ROOT", &root);
    env::set_var("AETHERFLOW_CONFIG_ROOT", &root);
    env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    env::set_var("AETHERFLOW_BASE_DOMAIN", "example.com");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db);
    }
    af_db::init_db().unwrap();

    // Seed raw internal SQLite error into `app_updates` to prove `public_update_error` sanitizes it
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO app_updates (package_name, installed_version, latest_version, update_available, update_url, last_error)
             VALUES ('sonarr', '4.0.1', '4.0.9', 1, 'https://github.com/Sonarr/Sonarr/releases/tag/v4.0.9', 'reqwest connect error at /var/lib/secret/internal.sock: ECONNREFUSED')",
            [],
        )
        .unwrap();
    }

    // 1. Uninstalled Readarr preserves `status = "retired"` while Sonarr is `"uninstalled"`
    fs::write(root.join("install/.sonarr.lock"), "installed").unwrap();
    let pkgs = get_packages().unwrap();
    let readarr = pkgs.iter().find(|p| p.name == "readarr").unwrap();
    let sonarr = pkgs.iter().find(|p| p.name == "sonarr").unwrap();
    assert_eq!(readarr.status, "retired");
    assert_eq!(sonarr.status, "installed");
    assert!(
        !sonarr.update_error.contains("/var/lib/secret"),
        "update_error must be sanitized by public_update_error, got: {}",
        sonarr.update_error
    );

    // 2. TLS cert NOT ready + internal vhost present -> falls back to internal `.aether.local`
    fs::write(
        root.join("etc/apache2/sites-enabled/aetherflow-app-sonarr.conf"),
        "# vhost",
    )
    .unwrap();
    let ing_unready = af_models::AppIngressConfig {
        app_name: "sonarr".to_string(),
        public_domain: "unprovisioned.example.com".to_string(),
        external_access_enabled: true,
        tls_enabled: true,
        listen_port: 8989,
        ..Default::default()
    };
    let fallback_launch = launch_target("sonarr", 8989, "/", Some(&ing_unready), "192.168.1.9");
    assert_eq!(
        fallback_launch,
        (
            Some("http://sonarr.aether.local".to_string()),
            Some("internal".to_string())
        )
    );

    // 3. Provisioning a certificate is independent of enabling its HTTPS vhost.
    fs::write(
        root.join("etc/letsencrypt/live/sonarr.example.com/fullchain.pem"),
        "-----BEGIN CERTIFICATE-----\n",
    )
    .unwrap();
    let ing_ready = af_models::AppIngressConfig {
        app_name: "sonarr".to_string(),
        public_domain: "sonarr.example.com".to_string(),
        external_access_enabled: true,
        tls_enabled: true,
        listen_port: 8989,
        ..Default::default()
    };
    assert_eq!(
        launch_target("sonarr", 8989, "/", Some(&ing_ready), "192.168.1.9")
            .1
            .as_deref(),
        Some("internal")
    );
    fs::write(
        root.join("etc/apache2/sites-enabled/aetherflow-ext-sonarr.conf"),
        concat!(
            "<VirtualHost *:80>\n    ServerName sonarr.example.com\n",
            "    RewriteRule ^ https://sonarr.example.com%{REQUEST_URI} [R=308,L]\n</VirtualHost>\n",
            "<VirtualHost *:443>\n    ServerName sonarr.example.com\n    SSLEngine On\n</VirtualHost>\n"
        ),
    )
    .unwrap();
    let https_launch = launch_target("sonarr", 8989, "/", Some(&ing_ready), "192.168.1.9");
    assert_eq!(
        https_launch,
        (
            Some("https://sonarr.example.com".to_string()),
            Some("public".to_string())
        )
    );

    // 4. Installing Readarr on disk transitions status to `"installed"` (so Services reports active/inactive)
    fs::write(root.join("install/.readarr.lock"), "installed").unwrap();
    let pkgs_installed = get_packages().unwrap();
    let readarr_installed = pkgs_installed.iter().find(|p| p.name == "readarr").unwrap();
    assert_eq!(readarr_installed.status, "installed");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_forbidden_streaming_ip_allows_tailscale_cgnat_and_blocks_metadata() {
    let name = "tests::test_forbidden_streaming_ip_allows_tailscale_cgnat_and_blocks_metadata";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    env::remove_var("AETHERFLOW_BLOCK_CGNAT");
    assert!(!forbidden_streaming_ip("100.64.0.1".parse().unwrap()));
    assert!(!forbidden_streaming_ip("100.127.255.254".parse().unwrap()));
    assert!(forbidden_streaming_ip("169.254.169.254".parse().unwrap()));
    assert!(forbidden_streaming_ip("168.63.129.16".parse().unwrap()));

    env::set_var("AETHERFLOW_BLOCK_CGNAT", "1");
    assert!(forbidden_streaming_ip("100.64.0.1".parse().unwrap()));
    assert!(forbidden_streaming_ip("169.254.169.254".parse().unwrap()));
    assert!(forbidden_streaming_ip("168.63.129.16".parse().unwrap()));
    env::remove_var("AETHERFLOW_BLOCK_CGNAT");
}

#[tokio::test]
async fn test_shared_vhost_stop_rejected_and_supports_dynamic_port_accurate() {
    for app in ["nextcloud", "rutorrent", "organizr"] {
        for manager in ["systemd", "systemd-unit"] {
            let err = control_service_with_manager(app, "stop", manager)
                .await
                .expect_err("shared-vhost stop must never touch apache2");
            assert!(err.to_string().contains("shared Apache virtual host"));
        }
    }
    assert!(get_blueprint("bazarr").unwrap().supports_dynamic_port);
    assert!(get_blueprint("dispatcharr").unwrap().supports_dynamic_port);
    assert!(!get_blueprint("kasmvnc").unwrap().supports_dynamic_port);
    assert!(!get_blueprint("calibreweb").unwrap().supports_dynamic_port);
}

#[test]
fn test_stopped_aetherflow_frontend_not_fabricated_as_running() {
    let name = "tests::test_stopped_aetherflow_frontend_not_fabricated_as_running";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    let fixture = crate::inventory_regressions::Fixture::new();
    fixture.command(
        "systemctl",
        "test \"$1\" = show || exit 92\nprintf 'ActiveState=inactive\\nSubState=dead\\n'\n",
    );
    clear_service_status_cache();
    let services = get_active_services().unwrap();
    assert!(!services.contains_key("AetherFlow Frontend"));
    assert_eq!(services["AetherFlow Runner"].status, "stopped");
    assert_eq!(services["AetherFlow API"].status, "stopped");

    let unit = fixture
        .root
        .join("etc/systemd/system/aetherflow-frontend.service");
    fs::create_dir_all(unit.parent().unwrap()).unwrap();
    fs::write(unit, "[Service]\n").unwrap();
    let legacy_services = get_active_services().unwrap();
    assert_eq!(legacy_services["AetherFlow Frontend"].status, "stopped");
}

#[test]
fn test_catalog_require_download_sha256_and_blueprint_metadata_parity() {
    let catalog = get_package_catalog().expect("load package catalog");
    assert_eq!(catalog.len(), 77, "expected all 77 catalog packages");
    for pkg in &catalog {
        assert!(
            pkg.require_download_sha256,
            "catalog package '{}' must load require_download_sha256 == true",
            pkg.name
        );
    }

    let adguard_bp = get_blueprint("adguardhome").expect("adguardhome blueprint");
    assert!(adguard_bp.is_network_app);

    for (app, expected_path) in [
        ("listenarr", "/etc/systemd/system/listenarr.service"),
        ("overseerr", "/etc/systemd/system/overseerr.service"),
        ("jellyseerr", "/etc/systemd/system/jellyseerr.service"),
    ] {
        let bp = get_blueprint(app).unwrap_or_else(|| panic!("{app} blueprint"));
        assert_eq!(bp.config_file_path, expected_path);
        assert!(bp.supports_dynamic_port);
    }
}
