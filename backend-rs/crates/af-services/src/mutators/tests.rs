use super::*;

#[test]
fn startup_ingress_keeps_saved_hostname_port_and_exposure() {
    let package = af_models::Package {
        name: "sonarr".into(),
        default_port: 8989,
        ..Default::default()
    };
    let saved = AppIngressConfig {
        app_name: package.name.clone(),
        public_domain: "series.custom.example".into(),
        listen_port: 20001,
        external_access_enabled: true,
        tls_enabled: true,
        ..Default::default()
    };
    for base in ["", "new.example"] {
        assert_eq!(
            startup_app_ingress_config(&package, base, Some(&saved)),
            saved
        );
    }
    let seeded = startup_app_ingress_config(&package, "new.example", None);
    assert_eq!(seeded.public_domain, "sonarr.new.example");
    assert_eq!(seeded.listen_port, 8989);
    assert!(!seeded.external_access_enabled);
}

#[test]
fn test_write_file_atomic_rejects_symlink_parent_directory() {
    let dir = temp_test_dir("symlink_parent");
    let real_target_dir = dir.join("real_target");
    fs::create_dir_all(&real_target_dir).unwrap();
    let symlink_parent = dir.join("linked_parent");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real_target_dir, &symlink_parent).unwrap();
        let victim_file = symlink_parent.join("victim.conf");
        let err = write_file_atomic(&victim_file, b"pwned").unwrap_err();
        assert!(
            err.contains("symlink parent directory"),
            "expected symlink parent rejection, got: {}",
            err
        );
        assert!(!real_target_dir.join("victim.conf").exists());
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_runner_app_meta_reads_response_payload() {
    let data = json!({"api_key": "runner-secret", "configured_port": 18989});
    for envelope in [
        json!({"id": "audit", "ok": true, "status": 200, "data": data.clone()}),
        json!({"success": true, "data": data.clone()}),
        json!({"success": true, "output": data.to_string()}),
    ] {
        let meta = parse_runner_app_meta(&envelope.to_string()).unwrap();
        assert_eq!(meta.api_key, "runner-secret");
        assert_eq!(meta.configured_port, 18989);
    }
}

#[test]
fn test_runner_app_meta_rejects_failed_or_missing_payloads() {
    for envelope in [
        json!({"ok": false, "data": {"api_key": "not-trusted"}}),
        json!({"success": false, "output": "{}"}),
        json!({"ok": true}),
        json!({"ok": true, "data": null}),
        json!({"api_key": "not-an-envelope", "configured_port": 1234}),
    ] {
        assert!(parse_runner_app_meta(&envelope.to_string()).is_none());
    }
}

fn temp_test_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("af_mutators_test_{}_{}", prefix, nanos));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_mutate_and_read_xml_element() {
    let dir = temp_test_dir("xml");
    let xml_path = dir.join("config.xml");
    fs::write(
        &xml_path,
        "<Config>\n  <Port>8989</Port>\n  <ApiKey>abc123xyz</ApiKey>\n</Config>\n",
    )
    .unwrap();

    assert_eq!(read_xml_element(&xml_path, "Port").as_deref(), Some("8989"));
    assert_eq!(
        read_xml_element(&xml_path, "ApiKey").as_deref(),
        Some("abc123xyz")
    );

    let changed = mutate_xml_element(&xml_path, "Port", "18989").unwrap();
    assert!(changed);
    assert_eq!(
        read_xml_element(&xml_path, "Port").as_deref(),
        Some("18989")
    );

    let added = mutate_xml_element(&xml_path, "UrlBase", "/sonarr").unwrap();
    assert!(added);
    assert_eq!(
        read_xml_element(&xml_path, "UrlBase").as_deref(),
        Some("/sonarr")
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_dispatcharr_blueprint_env_port_preserves_secrets_and_permissions() {
    let dir = temp_test_dir("dispatcharr");
    let path = dir.join("dispatcharr.env");
    let spec = native_app_spec("dispatcharr", "/stale/config");
    assert_eq!(spec.config_paths, vec!["/etc/dispatcharr/dispatcharr.env"]);
    for original in [
        "POSTGRES_PASSWORD=keep\nDISPATCHARR_PORT=9191\n",
        "POSTGRES_PASSWORD=keep",
        "",
    ] {
        fs::write(&path, original).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        }
        assert!(mutate_dispatcharr_port(&path, 19200).unwrap());
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(
            extract_ini_value(&text, &["DISPATCHARR_PORT"]).as_deref(),
            Some("19200")
        );
        assert!(!text.contains("[Preferences]"));
        if original.contains("POSTGRES_PASSWORD") {
            assert!(text.contains("POSTGRES_PASSWORD=keep"));
        }
        assert!(!mutate_dispatcharr_port(&path, 19200).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn test_mutate_ini_key() {
    let dir = temp_test_dir("ini");
    let ini_path = dir.join("qBittorrent.conf");
    fs::write(
        &ini_path,
        "[LegalNotice]\nAccepted=true\n\n[Preferences]\nWebUI\\Port=8080\nWebUI\\Address=*\n",
    )
    .unwrap();

    let changed = mutate_ini_key(&ini_path, "Preferences", r"WebUI\Port", "18180").unwrap();
    assert!(changed);
    let added = mutate_ini_key(
        &ini_path,
        "Preferences",
        r"WebUI\HostHeaderValidation",
        "false",
    )
    .unwrap();
    assert!(added);

    let content = fs::read_to_string(&ini_path).unwrap();
    assert!(content.contains("WebUI\\Port=18180"));
    assert!(content.contains("WebUI\\HostHeaderValidation=false"));
    assert!(content.contains("Accepted=true"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_mutate_json_key() {
    let dir = temp_test_dir("json");
    let json_path = dir.join("settings.json");
    fs::write(
        &json_path,
        "{\n  \"rpc-port\": 9091,\n  \"rpc-whitelist-enabled\": true\n}\n",
    )
    .unwrap();

    assert!(mutate_json_key(&json_path, "rpc-port", json!(19091)).unwrap());
    assert!(mutate_json_key(&json_path, "rpc-whitelist-enabled", json!(false)).unwrap());

    let parsed: Value = serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
    assert_eq!(parsed["rpc-port"], json!(19091));
    assert_eq!(parsed["rpc-whitelist-enabled"], json!(false));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_mutate_sqlite_setting_and_sql_ident_validation() {
    let dir = temp_test_dir("sqlite");
    let db_path = dir.join("app.db");

    // Reject SQL injection in table or column identifiers
    assert!(
        mutate_sqlite_setting(&db_path, "Config; DROP TABLE x", "Key", "Value", "k", "v").is_err()
    );

    let changed =
        mutate_sqlite_setting(&db_path, "Config", "Key", "Value", "Port", "17878").unwrap();
    assert!(changed);

    let unchanged =
        mutate_sqlite_setting(&db_path, "Config", "Key", "Value", "Port", "17878").unwrap();
    assert!(!unchanged);

    let updated =
        mutate_sqlite_setting(&db_path, "Config", "Key", "Value", "Port", "17879").unwrap();
    assert!(updated);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_md5_and_qbittorrent_pbkdf2() {
    assert_eq!(
        master_ha1("alice", "secret").unwrap(),
        "6bd888770befc89c83a914b36f95b87f"
    );

    let hash_str = generate_qbittorrent_pbkdf2("correcthorsebatterystaple");
    assert!(hash_str.starts_with("\"@ByteArray("));
    assert!(hash_str.ends_with(")\""));
    let inner = &hash_str[12..hash_str.len() - 2];
    let (salt_b64, dk_b64) = inner.split_once(':').unwrap();
    let salt = BASE64_STD.decode(salt_b64).unwrap();
    let dk = BASE64_STD.decode(dk_b64).unwrap();
    assert_eq!(salt.len(), 16);
    assert_eq!(dk.len(), 64);
}

static TEST_ENV_LOCK: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

#[tokio::test]
async fn test_afmp004_service_jellyfin_blueprint_preserves_operator_remote_access_and_known_proxies(
) {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let dir = temp_test_dir("afmp004-jellyfin-service");
    for subdir in [
        "etc/jellyfin",
        "etc/apache2/sites-available",
        "var/lib/aetherflow",
    ] {
        fs::create_dir_all(dir.join(subdir)).unwrap();
    }
    let net_xml = dir.join("etc/jellyfin/network.xml");
    let retained_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<NetworkConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <InternalHttpPort>8096</InternalHttpPort>
  <PublicHttpPort>8096</PublicHttpPort>
  <EnableIPV4>true</EnableIPV4>
  <EnableRemoteAccess>false</EnableRemoteAccess>
  <KnownProxies><string>10.20.30.40</string></KnownProxies>
</NetworkConfiguration>
"#;
    fs::write(&net_xml, retained_xml).unwrap();
    fs::write(dir.join("hosts"), "127.0.0.1 localhost\n").unwrap();
    let db_path = dir.join("var/lib/aetherflow/aetherflow.sqlite");

    let prev_fs_root = std::env::var_os("AETHERFLOW_FS_ROOT");
    let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
    let prev_af_db = std::env::var_os("AF_DB_PATH");
    let prev_db = std::env::var_os("DB_PATH");
    let prev_aether_db = std::env::var_os("AETHERFLOW_DB_PATH");
    let prev_hosts = std::env::var_os("AETHERFLOW_HOSTS_FILE");
    let prev_sock = std::env::var_os("AETHERFLOW_RUNNER_SOCK");

    std::env::set_var("AETHERFLOW_FS_ROOT", &dir);
    std::env::set_var("AETHERFLOW_CONFIG_ROOT", &dir);
    std::env::set_var("AF_DB_PATH", &db_path);
    std::env::set_var("DB_PATH", &db_path);
    std::env::set_var("AETHERFLOW_DB_PATH", &db_path);
    std::env::set_var("AETHERFLOW_HOSTS_FILE", dir.join("hosts"));
    std::env::set_var("AETHERFLOW_RUNNER_SOCK", dir.join("absent.sock"));

    af_db::init_db().unwrap();
    let res = apply_blueprint_app_config_admitted("jellyfin", 18096).await;

    for (key, prev) in [
        ("AETHERFLOW_FS_ROOT", prev_fs_root),
        ("AETHERFLOW_CONFIG_ROOT", prev_cfg_root),
        ("AF_DB_PATH", prev_af_db),
        ("DB_PATH", prev_db),
        ("AETHERFLOW_DB_PATH", prev_aether_db),
        ("AETHERFLOW_HOSTS_FILE", prev_hosts),
        ("AETHERFLOW_RUNNER_SOCK", prev_sock),
    ] {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    res.unwrap();
    let updated = fs::read_to_string(&net_xml).unwrap();
    assert!(updated.contains("<InternalHttpPort>18096</InternalHttpPort>"));
    assert!(updated.contains("<PublicHttpPort>18096</PublicHttpPort>"));
    assert!(
        updated.contains("<EnableRemoteAccess>false</EnableRemoteAccess>"),
        "must preserve explicit EnableRemoteAccess=false, got:\n{updated}"
    );
    assert!(
        updated.contains("<KnownProxies><string>10.20.30.40</string></KnownProxies>"),
        "must preserve custom KnownProxies, got:\n{updated}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_afmp_sol_001_service_vhost_sync_preserves_apache_access_policy() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let dir = temp_test_dir("afmp-sol-001-service-apache");
    let sites_avail = dir.join("etc/apache2/sites-available");
    let sites_en = dir.join("etc/apache2/sites-enabled");
    fs::create_dir_all(&sites_avail).unwrap();
    fs::create_dir_all(&sites_en).unwrap();
    fs::create_dir_all(dir.join("var/lib/aetherflow")).unwrap();
    fs::write(dir.join("hosts"), "127.0.0.1 localhost\n").unwrap();

    let int_conf = sites_avail.join("aetherflow-app-qui.conf");
    let ext_conf = sites_avail.join("aetherflow-ext-qui.conf");
    let en_ext_conf = sites_en.join("aetherflow-ext-qui.conf");

    let existing_int = "\
# Managed by AetherFlow v3.2.6
<VirtualHost *:80>
ServerName qui.aether.local
ProxyPreserveHost On
ProxyRequests Off
RewriteEngine On
RewriteCond %{HTTP:Upgrade} =websocket [NC]
RewriteRule /(.*) ws://127.0.0.1:8376/$1 [P,L]
ProxyPass / http://127.0.0.1:8376/
ProxyPassReverse / http://127.0.0.1:8376/
RequestHeader set X-Forwarded-Proto \"http\"
<Location /qui>
    AuthType Basic
    AuthName \"Restricted Qui\"
    AuthUserFile /etc/apache2/.htpasswd
    Require ip 192.0.2.0/24
</Location>
</VirtualHost>
";
    let existing_ext = "\
# Managed by AetherFlow v3.2.6 (External Ingress)
<VirtualHost *:80>
ServerName qui.example.com
ProxyPreserveHost On
ProxyRequests Off
RewriteEngine On
RewriteCond %{HTTP:Upgrade} =websocket [NC]
RewriteRule /(.*) ws://127.0.0.1:8376/$1 [P,L]
ProxyPass / http://127.0.0.1:8376/
ProxyPassReverse / http://127.0.0.1:8376/
<Location /qui>
    AuthType Basic
    AuthName \"Restricted Qui\"
    AuthUserFile /etc/apache2/.htpasswd
    Require ip 192.0.2.0/24
</Location>
</VirtualHost>
";
    fs::write(&int_conf, existing_int).unwrap();
    fs::write(&ext_conf, existing_ext).unwrap();
    fs::write(&en_ext_conf, existing_ext).unwrap();

    let prev_fs_root = std::env::var_os("AETHERFLOW_FS_ROOT");
    let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
    std::env::set_var("AETHERFLOW_FS_ROOT", &dir);
    std::env::set_var("AETHERFLOW_CONFIG_ROOT", &dir);

    let sync_res = sync_apache_app_vhost("qui", 18376, "qui.aether.local", "qui.example.com", true);

    for (key, prev) in [
        ("AETHERFLOW_FS_ROOT", prev_fs_root),
        ("AETHERFLOW_CONFIG_ROOT", prev_cfg_root),
    ] {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    assert!(sync_res.unwrap());
    for path in [&int_conf, &ext_conf, &en_ext_conf] {
        let updated = fs::read_to_string(path).unwrap();
        assert!(
            updated.contains("ws://127.0.0.1:18376/$1"),
            "must update websocket RewriteRule port to 18376 in {}: {updated}",
            path.display()
        );
        assert!(
            updated.contains("ProxyPass / http://127.0.0.1:18376/"),
            "must update ProxyPass port to 18376 in {}: {updated}",
            path.display()
        );
        assert!(
            updated.contains("ProxyPassReverse / http://127.0.0.1:18376/"),
            "must update ProxyPassReverse port to 18376 in {}: {updated}",
            path.display()
        );
        assert!(
            updated.contains("<Location /qui>"),
            "must preserve <Location /qui> block in {}: {updated}",
            path.display()
        );
        assert!(
            updated.contains("AuthType Basic"),
            "must preserve AuthType Basic in {}: {updated}",
            path.display()
        );
        assert!(
            updated.contains("Require ip 192.0.2.0/24"),
            "must preserve Require ip 192.0.2.0/24 in {}: {updated}",
            path.display()
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_sync_local_dns_domains_preserves_multiple_apps() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let scratch_dir = env::temp_dir().join(format!("af-dns-sync-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&scratch_dir).unwrap();
    let hosts_file = scratch_dir.join("hosts");
    fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();

    env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());

    // Install App A -> syncs appa.aether.local
    sync_local_dns_domains(&["appa.aether.local".to_string()])
        .await
        .unwrap();
    let content_after_a = fs::read_to_string(&hosts_file).unwrap();
    assert!(content_after_a.contains("appa.aether.local"));

    // Install App B -> syncs appb.aether.local without wiping appa
    sync_local_dns_domains(&["appb.aether.local".to_string()])
        .await
        .unwrap();
    let content_after_b = fs::read_to_string(&hosts_file).unwrap();
    assert!(
        content_after_b.contains("appa.aether.local"),
        "App A must be preserved when installing App B: {content_after_b}"
    );
    assert!(
        content_after_b.contains("appb.aether.local"),
        "App B must be present: {content_after_b}"
    );

    env::remove_var("AF_HOSTS_FILE");
    let _ = fs::remove_dir_all(&scratch_dir);
}

#[tokio::test]
async fn test_reconcile_local_dns_domains_non_root_invokes_runner_and_propagates_error() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    env::remove_var("AF_HOSTS_FILE");
    env::remove_var("AETHERFLOW_HOSTS_FILE");

    let dummy_sock =
        env::temp_dir().join(format!("nonexistent-runner-{}.sock", uuid::Uuid::new_v4()));
    env::set_var(
        "AETHERFLOW_RUNNER_SOCK",
        dummy_sock.to_string_lossy().as_ref(),
    );

    #[cfg(unix)]
    {
        extern "C" {
            fn geteuid() -> u32;
        }
        if unsafe { geteuid() != 0 } {
            let err = reconcile_local_dns_domains(&["testapp.aether.local".to_string()])
                .await
                .unwrap_err();
            assert!(
                err.contains("runner hosts reconcile error")
                    || err.contains("privileged runner hosts reconcile failed"),
                "Expected runner error, got: {err}"
            );
        }
    }

    env::remove_var("AETHERFLOW_RUNNER_SOCK");
}

#[tokio::test]
async fn test_reconcile_and_sync_dns_separates_hosts_loopback_and_provider_lan_ip() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let scratch_dir =
        env::temp_dir().join(format!("af-mutators-dns-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&scratch_dir).unwrap();

    let hosts_file = scratch_dir.join("hosts");
    fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
    let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
    fs::create_dir_all(&dnsmasq_dir).unwrap();
    let pihole_dir = scratch_dir.join("pihole");
    fs::create_dir_all(&pihole_dir).unwrap();

    env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());
    env::set_var(
        "AETHERFLOW_DNSMASQ_DIR",
        dnsmasq_dir.to_string_lossy().as_ref(),
    );
    env::set_var(
        "AETHERFLOW_PIHOLE_DIR",
        pihole_dir.to_string_lossy().as_ref(),
    );
    env::set_var("AETHERFLOW_LAN_IP", "192.168.1.150");

    let domains = vec![
        "sonarr.aether.local".to_string(),
        "media.example.com".to_string(),
    ];

    // Run reconcile
    reconcile_local_dns_domains(&domains).await.unwrap();

    // 1. /etc/hosts must contain 127.0.0.1 and sonarr.aether.local, but NOT media.example.com or 192.168.1.150
    let hosts_content = fs::read_to_string(&hosts_file).unwrap();
    assert!(hosts_content.contains("127.0.0.1\tsonarr.aether.local"));
    assert!(!hosts_content.contains("media.example.com"));
    assert!(!hosts_content.contains("192.168.1.150"));

    // 2. dnsmasq must contain LAN IP 192.168.1.150 and both domains, but not 127.0.0.1
    let dnsmasq_conf = fs::read_to_string(dnsmasq_dir.join("aetherflow.conf")).unwrap();
    assert!(dnsmasq_conf.contains("address=/sonarr.aether.local/192.168.1.150"));
    assert!(dnsmasq_conf.contains("address=/media.example.com/192.168.1.150"));
    assert!(!dnsmasq_conf.contains("127.0.0.1"));

    // 3. Pi-hole custom.list must contain LAN IP 192.168.1.150 and both domains
    let pihole_list = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
    assert!(pihole_list.contains("192.168.1.150 sonarr.aether.local # aetherflow-managed"));
    assert!(pihole_list.contains("192.168.1.150 media.example.com # aetherflow-managed"));
    assert!(!pihole_list.contains("127.0.0.1"));

    // Test remove_dns_provider_domain
    remove_dns_provider_domain("sonarr.aether.local").unwrap();
    let pihole_after_rm = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
    assert!(!pihole_after_rm.contains("sonarr.aether.local"));
    assert!(pihole_after_rm.contains("media.example.com"));

    env::remove_var("AF_HOSTS_FILE");
    env::remove_var("AETHERFLOW_DNSMASQ_DIR");
    env::remove_var("AETHERFLOW_PIHOLE_DIR");
    env::remove_var("AETHERFLOW_LAN_IP");
    let _ = fs::remove_dir_all(&scratch_dir);
}

#[tokio::test]
async fn test_untrimmed_or_invalid_lan_ip_fails_closed_without_modifications() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let scratch_dir = env::temp_dir().join(format!(
        "af-mutators-invalid-lan-ip-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&scratch_dir).unwrap();

    let hosts_file = scratch_dir.join("hosts");
    fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
    let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
    fs::create_dir_all(&dnsmasq_dir).unwrap();
    let pihole_dir = scratch_dir.join("pihole");
    fs::create_dir_all(&pihole_dir).unwrap();
    let initial_custom_list = "192.168.1.10 existing.local # aetherflow-managed\n";
    fs::write(pihole_dir.join("custom.list"), initial_custom_list).unwrap();

    env::set_var("AF_HOSTS_FILE", hosts_file.to_string_lossy().as_ref());
    env::set_var(
        "AETHERFLOW_DNSMASQ_DIR",
        dnsmasq_dir.to_string_lossy().as_ref(),
    );
    env::set_var(
        "AETHERFLOW_PIHOLE_DIR",
        pihole_dir.to_string_lossy().as_ref(),
    );

    let invalid_ips = [
        " 192.168.1.50 ",
        "192.168.1.50\nmalicious",
        "192.168.1.50\r\nmalicious",
        "192.168.1.50 ",
        " 192.168.1.50",
        "invalid-ip",
        "",
    ];

    let test_domains = vec!["app.aether.local".to_string()];

    for bad_ip in invalid_ips {
        env::set_var("AETHERFLOW_LAN_IP", bad_ip);

        assert!(
            detect_lan_ip_strict().is_err(),
            "detect_lan_ip_strict must fail for {bad_ip:?}"
        );

        let sync_res = sync_local_dns_domains(&test_domains).await;
        assert!(
            sync_res.is_err(),
            "sync_local_dns_domains must fail closed for {bad_ip:?}"
        );

        let rec_res = reconcile_local_dns_domains(&test_domains).await;
        assert!(
            rec_res.is_err(),
            "reconcile_local_dns_domains must fail closed for {bad_ip:?}"
        );

        // Verify files were not modified
        let hosts_cur = fs::read_to_string(&hosts_file).unwrap();
        assert_eq!(
            hosts_cur, "127.0.0.1 localhost\n",
            "hosts file must remain untouched for {bad_ip:?}"
        );

        assert!(
            !dnsmasq_dir.join("aetherflow.conf").exists(),
            "dnsmasq must not be created"
        );
        assert!(
            !dnsmasq_dir.join("aetherflow-local.conf").exists(),
            "dnsmasq must not be created"
        );

        let pihole_cur = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
        assert_eq!(
            pihole_cur, initial_custom_list,
            "custom.list must remain untouched for {bad_ip:?}"
        );
    }

    env::remove_var("AF_HOSTS_FILE");
    env::remove_var("AETHERFLOW_DNSMASQ_DIR");
    env::remove_var("AETHERFLOW_PIHOLE_DIR");
    env::remove_var("AETHERFLOW_LAN_IP");
    let _ = fs::remove_dir_all(&scratch_dir);
}

#[tokio::test]
async fn test_round8_save_master_credentials_preserves_legacy_on_primary_write_failure() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let scratch_dir = env::temp_dir().join(format!("af_r8_master_creds_{}", uuid::Uuid::new_v4()));
    let legacy_file = scratch_dir.join("opt/AetherFlow/backend/data/.master.creds");
    fs::create_dir_all(legacy_file.parent().unwrap()).unwrap();
    fs::write(&legacy_file, b"legacy-must-survive\n").unwrap();

    // Block primary `/var/lib/aetherflow/.master.creds` by making parent `/var/lib/aetherflow` a regular file.
    let blocked_dir = scratch_dir.join("var/lib/aetherflow");
    fs::create_dir_all(blocked_dir.parent().unwrap()).unwrap();
    fs::write(&blocked_dir, b"blocking-regular-file").unwrap();

    env::set_var("AETHERFLOW_CONFIG_ROOT", &scratch_dir);
    env::remove_var("AETHERFLOW_MASTER_CREDS_FILE");
    env::set_var("AES_MASTER_KEY", "d".repeat(64));
    let _ = af_db::init_aes_key();

    let err_res = save_master_credentials("admin", "R8StrongPass!");
    assert!(err_res.is_err(), "primary write failure must return error");
    assert_eq!(
        fs::read_to_string(&legacy_file).unwrap(),
        "legacy-must-survive\n",
        "legacy .master.creds must NOT be unlinked when primary write fails"
    );

    // Fix `/var/lib/aetherflow` into a real directory and verify primary write + legacy unlink succeed.
    fs::remove_file(&blocked_dir).unwrap();
    fs::create_dir_all(&blocked_dir).unwrap();
    save_master_credentials("admin", "R8StrongPass!").expect("primary write should succeed");
    assert!(blocked_dir.join(".master.creds").is_file());
    assert!(
        !legacy_file.exists(),
        "legacy .master.creds must be unlinked once all primary writes succeed"
    );

    env::remove_var("AETHERFLOW_CONFIG_ROOT");
    let _ = fs::remove_dir_all(&scratch_dir);
}

#[tokio::test]
async fn test_librespeed_apache_vhost_pins_upstream_ca_and_dynamic_proto_on_ext_vhost() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let dir = temp_test_dir("librespeed-tls-vhost");
    let sites_avail = dir.join("etc/apache2/sites-available");
    let sites_en = dir.join("etc/apache2/sites-enabled");
    let ls_dir = dir.join("opt/librespeed");
    fs::create_dir_all(&sites_avail).unwrap();
    fs::create_dir_all(&sites_en).unwrap();
    fs::create_dir_all(&ls_dir).unwrap();

    fs::write(
        ls_dir.join("cert.pem"),
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    fs::write(
        ls_dir.join("settings.toml"),
        "enable_tls = true\ntls_cert_file = \"/opt/librespeed/cert.pem\"\n",
    )
    .unwrap();

    let prev_fs_root = std::env::var_os("AETHERFLOW_FS_ROOT");
    let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
    std::env::set_var("AETHERFLOW_FS_ROOT", &dir);
    std::env::set_var("AETHERFLOW_CONFIG_ROOT", &dir);

    let sync_res = sync_apache_app_vhost(
        "librespeed",
        8988,
        "librespeed.aether.local",
        "speed.example.com",
        true,
    );

    for (key, prev) in [
        ("AETHERFLOW_FS_ROOT", prev_fs_root.clone()),
        ("AETHERFLOW_CONFIG_ROOT", prev_cfg_root.clone()),
    ] {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    assert!(sync_res.unwrap());
    let int_vhost = fs::read_to_string(sites_avail.join("aetherflow-app-librespeed.conf")).unwrap();
    let ext_vhost = fs::read_to_string(sites_avail.join("aetherflow-ext-librespeed.conf")).unwrap();
    for vhost in [&int_vhost, &ext_vhost] {
        assert!(vhost.contains("SSLProxyEngine On"));
        assert!(vhost.contains("SSLProxyVerify require"));
        assert!(vhost.contains("SSLProxyCACertificateFile /opt/librespeed/cert.pem"));
        assert!(!vhost.contains("SSLProxyVerify none"));
        assert!(vhost.contains("https://127.0.0.1:8988/"));
        assert!(vhost.contains("IncludeOptional /etc/aetherflow/librespeed-proxy-token.conf"));
    }
    assert!(int_vhost.contains("RequestHeader set X-Forwarded-Proto \"http\""));
    assert!(ext_vhost.contains("RequestHeader set X-Forwarded-Proto \"expr=%{REQUEST_SCHEME}\""));

    // Missing/invalid tls_cert_file when enable_tls=true must fail closed and NEVER write SSLProxyVerify none
    fs::write(
        ls_dir.join("settings.toml"),
        "enable_tls = true\ntls_cert_file = \"relative/cert.pem\"\ntls_key_file = \"/opt/librespeed/key.pem\"\n",
    )
    .unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &dir);
    std::env::set_var("AETHERFLOW_CONFIG_ROOT", &dir);
    let invalid_res = sync_apache_app_vhost(
        "librespeed",
        8988,
        "librespeed.aether.local",
        "speed.example.com",
        true,
    );
    for (key, prev) in [
        ("AETHERFLOW_FS_ROOT", prev_fs_root),
        ("AETHERFLOW_CONFIG_ROOT", prev_cfg_root),
    ] {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
    assert!(
        invalid_res.is_err(),
        "enable_tls=true with unusable cert must fail closed"
    );
    let preserved_vhost =
        fs::read_to_string(sites_avail.join("aetherflow-app-librespeed.conf")).unwrap();
    assert!(preserved_vhost.contains("SSLProxyVerify require"));
    assert!(!preserved_vhost.contains("SSLProxyVerify none"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_normalize_app_key_name_matches_canonical_catalog_ids() {
    assert_eq!(normalize_app_key_name("calibre-web"), "calibreweb");
    assert_eq!(normalize_app_key_name("uptime-kuma"), "uptimekuma");
    assert_eq!(normalize_app_key_name("af-kasmvnc"), "kasmvnc");
    assert_eq!(normalize_app_key_name("af-palate"), "palate");
    assert_eq!(normalize_app_key_name("af-mcvnc"), "mcvnc");
    assert_eq!(normalize_app_key_name("af-maintainerr"), "maintainerr");
    assert_eq!(normalize_app_key_name("af-piped"), "piped");
    assert_eq!(normalize_app_key_name("af-invidious"), "invidious");
}

#[tokio::test]
async fn test_detect_lan_ip_strict_and_dnsmasq_consolidation_with_pihole_v6() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    env::remove_var("AETHERFLOW_LAN_IP");
    let detected = detect_lan_ip_strict().expect("detect_lan_ip_strict succeeds when unset");
    assert!(detected.parse::<std::net::Ipv4Addr>().is_ok());

    let scratch_dir = temp_test_dir("dns-consolidate");
    let hosts_file = scratch_dir.join("hosts");
    let dnsmasq_dir = scratch_dir.join("dnsmasq.d");
    let pihole_dir = scratch_dir.join("pihole");
    fs::create_dir_all(&dnsmasq_dir).unwrap();
    fs::create_dir_all(&pihole_dir).unwrap();
    fs::write(&hosts_file, "127.0.0.1 localhost\n").unwrap();
    fs::write(
        dnsmasq_dir.join("aetherflow-local.conf"),
        "address=/legacy.aether.local/192.168.1.10\n",
    )
    .unwrap();
    fs::write(
        dnsmasq_dir.join("aetherflow-local-dns.conf"),
        "address=/legacy2.aether.local/192.168.1.10\n",
    )
    .unwrap();
    fs::write(
        pihole_dir.join("pihole.toml"),
        "[dns]\n  upstreams = [\"1.1.1.1\"]\n  hosts = [\n    \"192.168.1.20 manual.lan\"\n  ]\n",
    )
    .unwrap();

    env::set_var("AF_HOSTS_FILE", &hosts_file);
    env::set_var("AETHERFLOW_DNSMASQ_DIR", &dnsmasq_dir);
    env::set_var("AETHERFLOW_PIHOLE_DIR", &pihole_dir);
    env::set_var("AETHERFLOW_LAN_IP", "192.168.1.77");

    sync_local_dns_domains(&["radarr.aether.local".to_string()])
        .await
        .unwrap();

    assert!(!dnsmasq_dir.join("aetherflow-local.conf").exists());
    assert!(!dnsmasq_dir.join("aetherflow-local-dns.conf").exists());
    let canonical = fs::read_to_string(dnsmasq_dir.join("05-aetherflow-dns.conf")).unwrap();
    assert!(canonical.contains("address=/radarr.aether.local/192.168.1.77"));
    assert!(canonical.contains("address=/legacy.aether.local/192.168.1.77"));
    assert!(canonical.contains("address=/legacy2.aether.local/192.168.1.77"));

    let custom_list = fs::read_to_string(pihole_dir.join("custom.list")).unwrap();
    assert!(custom_list.contains("192.168.1.77 radarr.aether.local"));

    let pihole_toml = fs::read_to_string(pihole_dir.join("pihole.toml")).unwrap();
    assert!(pihole_toml.contains("\"192.168.1.20 manual.lan\""));
    assert!(pihole_toml.contains("\"192.168.1.77 radarr.aether.local\""));

    env::remove_var("AF_HOSTS_FILE");
    env::remove_var("AETHERFLOW_DNSMASQ_DIR");
    env::remove_var("AETHERFLOW_PIHOLE_DIR");
    env::remove_var("AETHERFLOW_LAN_IP");
    let _ = fs::remove_dir_all(&scratch_dir);
}

#[test]
fn test_pihole_bazarr_and_listenarr_mutators() {
    let dir = temp_test_dir("mutators-v2");

    // 1. Pi-hole: mutates [webserver] port only and never duplicates [webserver]
    let pihole_toml = dir.join("pihole.toml");
    fs::write(
        &pihole_toml,
        "[dns]\n  port = 53\n[webserver]\n  threads = 4\n[webserver.api]\n  pwhash = \"hash\"\n[misc]\n  etc_dnsmasq_d = false\n",
    )
    .unwrap();
    assert!(mutate_pihole_toml(&pihole_toml, 18089).unwrap());
    let pihole_after_1 = fs::read_to_string(&pihole_toml).unwrap();
    assert_eq!(pihole_after_1.matches("[webserver]").count(), 1);
    assert!(pihole_after_1.contains("  port = \"18089o\""));
    assert!(pihole_after_1.contains("[dns]\n  port = 53"));
    assert!(pihole_after_1.contains("etc_dnsmasq_d = true"));

    assert!(mutate_pihole_toml(&pihole_toml, 18090).unwrap());
    let pihole_after_2 = fs::read_to_string(&pihole_toml).unwrap();
    assert_eq!(pihole_after_2.matches("[webserver]").count(), 1);
    assert!(pihole_after_2.contains("  port = \"18090o\""));
    assert!(pihole_after_2.contains("[dns]\n  port = 53"));

    // 2. Bazarr: YAML general.port mutator
    let bazarr_yaml = dir.join("config.yaml");
    fs::write(
        &bazarr_yaml,
        "auth:\n  type: form\ngeneral:\n  ip: 127.0.0.1\n  port: 6767\n",
    )
    .unwrap();
    assert!(mutate_yaml_section_key(&bazarr_yaml, "general", "port", "16767").unwrap());
    let bazarr_after = fs::read_to_string(&bazarr_yaml).unwrap();
    assert!(bazarr_after.contains("  port: 16767"));
    assert!(bazarr_after.contains("  type: form"));

    // 3. Listenarr: ASPNETCORE_URLS mutator in systemd unit
    let listenarr_unit = dir.join("listenarr.service");
    fs::write(
        &listenarr_unit,
        "[Service]\nEnvironment=\"ASPNETCORE_URLS=http://127.0.0.1:4546\"\n",
    )
    .unwrap();
    assert!(mutate_systemd_aspnetcore_urls(&listenarr_unit, 14546).unwrap());
    let listenarr_after = fs::read_to_string(&listenarr_unit).unwrap();
    assert!(listenarr_after.contains("ASPNETCORE_URLS=http://127.0.0.1:14546"));

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[tokio::test]
async fn test_trigger_apache_cert_sync_uses_runner_socket() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    let _env_guard = TEST_ENV_LOCK.lock().await;
    let sock_path =
        PathBuf::from("/tmp").join(format!("af-cert-sync-test-{}.sock", std::process::id()));
    let _ = fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).unwrap();

    let prev_sock = env::var_os("AETHERFLOW_RUNNER_SOCK");
    env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        let body = r#"{"success":true,"output":"synced","error":""}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).await.unwrap();
        req
    });

    trigger_apache_cert_sync().await;
    let received = server.await.unwrap();
    assert!(received.starts_with("POST /v1/certbot-sync "));

    match prev_sock {
        Some(v) => env::set_var("AETHERFLOW_RUNNER_SOCK", v),
        None => env::remove_var("AETHERFLOW_RUNNER_SOCK"),
    }
    let _ = fs::remove_file(&sock_path);
}

#[tokio::test]
async fn test_remove_apache_app_vhost_cleans_managed_files_and_dangling_symlinks_only() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let dir = temp_test_dir("remove-apache-vhost");
    let sites_avail = dir.join("etc/apache2/sites-available");
    let sites_en = dir.join("etc/apache2/sites-enabled");
    fs::create_dir_all(&sites_avail).unwrap();
    fs::create_dir_all(&sites_en).unwrap();

    // Managed vhosts for sonarr (regular files + active symlinks + dangling le-ssl symlink)
    let sonarr_app_avail = sites_avail.join("aetherflow-app-sonarr.conf");
    let sonarr_app_en = sites_en.join("aetherflow-app-sonarr.conf");
    let sonarr_ext_avail = sites_avail.join("aetherflow-ext-sonarr.conf");
    let sonarr_ext_en = sites_en.join("aetherflow-ext-sonarr.conf");
    let sonarr_ssl_avail = sites_avail.join("aetherflow-ext-sonarr-le-ssl.conf");
    let sonarr_ssl_en = sites_en.join("aetherflow-ext-sonarr-le-ssl.conf");

    fs::write(&sonarr_app_avail, "<VirtualHost *:80></VirtualHost>\n").unwrap();
    fs::write(&sonarr_ext_avail, "<VirtualHost *:80></VirtualHost>\n").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            "../sites-available/aetherflow-app-sonarr.conf",
            &sonarr_app_en,
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../sites-available/aetherflow-ext-sonarr.conf",
            &sonarr_ext_en,
        )
        .unwrap();
        // Dangling symlink (target does not exist in sites-available)
        std::os::unix::fs::symlink(
            "../sites-available/aetherflow-ext-sonarr-le-ssl.conf",
            &sonarr_ssl_en,
        )
        .unwrap();
    }

    // Legacy sonarr.conf and another app's vhosts must be preserved
    let legacy_avail = sites_avail.join("sonarr.conf");
    let legacy_en = sites_en.join("sonarr.conf");
    let radarr_app_avail = sites_avail.join("aetherflow-app-radarr.conf");
    let radarr_app_en = sites_en.join("aetherflow-app-radarr.conf");
    let radarr_ext_avail = sites_avail.join("aetherflow-ext-radarr.conf");
    let radarr_ext_en = sites_en.join("aetherflow-ext-radarr.conf");

    fs::write(&legacy_avail, "# legacy sonarr vhost\n").unwrap();
    fs::write(&radarr_app_avail, "# radarr internal\n").unwrap();
    fs::write(&radarr_ext_avail, "# radarr external\n").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("../sites-available/sonarr.conf", &legacy_en).unwrap();
        std::os::unix::fs::symlink(
            "../sites-available/aetherflow-app-radarr.conf",
            &radarr_app_en,
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../sites-available/aetherflow-ext-radarr.conf",
            &radarr_ext_en,
        )
        .unwrap();
    }

    // Also stage an alias package ("transmission-daemon" -> "transmission")
    let tx_avail = sites_avail.join("aetherflow-app-transmission.conf");
    let tx_en = sites_en.join("aetherflow-app-transmission.conf");
    fs::write(&tx_avail, "# transmission internal\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "../sites-available/aetherflow-app-transmission.conf",
        &tx_en,
    )
    .unwrap();

    let prev_fs_root = env::var_os("AETHERFLOW_FS_ROOT");
    let prev_cfg_root = env::var_os("AETHERFLOW_CONFIG_ROOT");
    env::set_var("AETHERFLOW_FS_ROOT", &dir);
    env::remove_var("AETHERFLOW_CONFIG_ROOT");

    let remove_sonarr = remove_apache_app_vhost("sonarr").await;
    let remove_sonarr_again = remove_apache_app_vhost("sonarr").await;
    let remove_tx_alias = remove_apache_app_vhost("transmission-daemon").await;
    let remove_unknown = remove_apache_app_vhost("not-in-catalog-app").await;

    // Dangling-symlink-only case (no sites-available file present)
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "../sites-available/aetherflow-ext-sonarr-le-ssl.conf",
        &sonarr_ssl_en,
    )
    .unwrap();
    let remove_dangling_only = remove_apache_app_vhost("sonarr").await;

    // Missing apache2 dirs under isolated AETHERFLOW_FS_ROOT returns Ok(()) cleanly
    let empty_dir = temp_test_dir("remove-apache-vhost-empty");
    env::set_var("AETHERFLOW_FS_ROOT", &empty_dir);
    let remove_no_dirs = remove_apache_app_vhost("sonarr").await;

    for (key, prev) in [
        ("AETHERFLOW_FS_ROOT", prev_fs_root),
        ("AETHERFLOW_CONFIG_ROOT", prev_cfg_root),
    ] {
        match prev {
            Some(v) => env::set_var(key, v),
            None => env::remove_var(key),
        }
    }

    remove_sonarr.unwrap();
    remove_sonarr_again.unwrap();
    remove_tx_alias.unwrap();
    remove_unknown.unwrap();
    remove_dangling_only.unwrap();
    remove_no_dirs.unwrap();

    for removed in [
        &sonarr_app_avail,
        &sonarr_app_en,
        &sonarr_ext_avail,
        &sonarr_ext_en,
        &sonarr_ssl_avail,
        &sonarr_ssl_en,
        &tx_avail,
        &tx_en,
    ] {
        assert!(
            matches!(
                fs::symlink_metadata(removed),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound
            ),
            "expected {} to be removed",
            removed.display()
        );
    }

    assert_eq!(
        fs::read_to_string(&legacy_avail).unwrap(),
        "# legacy sonarr vhost\n"
    );
    assert!(fs::symlink_metadata(&legacy_en).is_ok());
    assert_eq!(
        fs::read_to_string(&radarr_app_avail).unwrap(),
        "# radarr internal\n"
    );
    assert_eq!(
        fs::read_to_string(&radarr_ext_avail).unwrap(),
        "# radarr external\n"
    );
    assert!(fs::symlink_metadata(&radarr_app_en).is_ok());
    assert!(fs::symlink_metadata(&radarr_ext_en).is_ok());

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&empty_dir);
}

#[cfg(unix)]
#[tokio::test]
async fn test_remove_apache_app_vhost_async_cleans_managed_vhosts() {
    let _env_guard = TEST_ENV_LOCK.lock().await;
    let dir = env::temp_dir().join(format!("af-rm-vhost-test-{}", uuid::Uuid::new_v4()));
    let sites_avail = dir.join("etc/apache2/sites-available");
    let sites_en = dir.join("etc/apache2/sites-enabled");
    fs::create_dir_all(&sites_avail).unwrap();
    fs::create_dir_all(&sites_en).unwrap();

    for name in [
        "aetherflow-app-nextcloud.conf",
        "aetherflow-ext-nextcloud.conf",
        "aetherflow-app-sonarr.conf",
    ] {
        fs::write(
            sites_avail.join(name),
            b"<VirtualHost *:80></VirtualHost>\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(format!("../sites-available/{name}"), sites_en.join(name))
            .unwrap();
    }

    let prev_root = env::var_os("AETHERFLOW_CONFIG_ROOT");
    env::set_var("AETHERFLOW_CONFIG_ROOT", &dir);

    let removed = remove_apache_app_vhost_async("nextcloud").await.unwrap();
    assert!(removed);
    assert!(!sites_avail.join("aetherflow-app-nextcloud.conf").exists());
    assert!(!sites_avail.join("aetherflow-ext-nextcloud.conf").exists());
    assert!(fs::symlink_metadata(sites_en.join("aetherflow-app-nextcloud.conf")).is_err());
    assert!(fs::symlink_metadata(sites_en.join("aetherflow-ext-nextcloud.conf")).is_err());
    assert!(sites_avail.join("aetherflow-app-sonarr.conf").is_file());
    assert!(fs::symlink_metadata(sites_en.join("aetherflow-app-sonarr.conf")).is_ok());

    match prev_root {
        Some(v) => env::set_var("AETHERFLOW_CONFIG_ROOT", v),
        None => env::remove_var("AETHERFLOW_CONFIG_ROOT"),
    }
    let _ = fs::remove_dir_all(&dir);
}
