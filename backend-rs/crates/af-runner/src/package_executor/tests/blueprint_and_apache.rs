use super::*;

#[test]
fn test_afmp004_runner_jellyfin_blueprint_preserves_operator_remote_access_and_known_proxies() {
    let root = create_isolated_test_dir("afmp004-jellyfin-runner");
    let net_xml = root.join("etc/jellyfin/network.xml");
    fs::create_dir_all(net_xml.parent().unwrap()).unwrap();
    let initial_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<NetworkConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <InternalHttpPort>8096</InternalHttpPort>
  <PublicHttpPort>8096</PublicHttpPort>
  <EnableIPV4>true</EnableIPV4>
  <EnableRemoteAccess>false</EnableRemoteAccess>
  <KnownProxies><string>10.20.30.40</string></KnownProxies>
</NetworkConfiguration>
"#;
    fs::write(&net_xml, initial_xml).unwrap();

    apply_runner_blueprint_app_config(Some(&root), "jellyfin", 18096);

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

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_afmp_sol_001_runner_blueprint_preserves_apache_access_policy() {
    let root = create_isolated_test_dir("afmp-sol-001-runner-apache");
    let sites_avail = root.join("etc/apache2/sites-available");
    let sites_en = root.join("etc/apache2/sites-enabled");
    fs::create_dir_all(&sites_avail).unwrap();
    fs::create_dir_all(&sites_en).unwrap();

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

    try_apply_runner_blueprint_app_config_with_ingress(Some(&root), "qui", 18376, |_| Ok(None))
        .unwrap();

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

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn blueprint_vhost_rejects_required_directory_target() {
    let root = create_isolated_test_dir("blueprint-vhost-directory");
    let target = root.join("etc/apache2/sites-available/aetherflow-app-qui.conf");
    fs::create_dir_all(&target).unwrap();

    let result = try_apply_runner_blueprint_app_config(Some(&root), "qui", 18376);
    assert!(
        result.is_err(),
        "required managed vhost directory must not be silently skipped: {result:?}"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains(&target.display().to_string()));
    assert!(target.is_dir());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn blueprint_vhost_rejects_required_symlink_target() {
    let root = create_isolated_test_dir("blueprint-vhost-symlink");
    let target = root.join("etc/apache2/sites-available/aetherflow-app-qui.conf");
    let operator_config = root.join("operator.conf");
    let original = "<VirtualHost *:80>\n    ProxyPass / http://127.0.0.1:8376/\n</VirtualHost>\n";
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&operator_config, original).unwrap();
    std::os::unix::fs::symlink(&operator_config, &target).unwrap();

    let result = try_apply_runner_blueprint_app_config(Some(&root), "qui", 18376);
    assert!(
        result.is_err(),
        "required managed vhost symlink must not be silently skipped: {result:?}"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains(&target.display().to_string()));
    assert!(fs::symlink_metadata(target)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_to_string(operator_config).unwrap(), original);
    fs::remove_dir_all(root).unwrap();
}

const BLUEPRINT_VHOST_FIXTURE: &str = "<VirtualHost *:80>\n    ServerName sonarr.example.com\n    ProxyPass / http://127.0.0.1:8989/\n    ProxyPassReverse / http://127.0.0.1:8989/\n</VirtualHost>\n";
const BLUEPRINT_APP_CONFIG_FIXTURE: &str = "<Config><Port>8989</Port><BindAddress>127.0.0.1</BindAddress><AuthenticationMethod>Forms</AuthenticationMethod><AnalyticsEnabled>False</AnalyticsEnabled></Config>\n";

fn blueprint_ingress_fixture(root: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(root.join("ingress.sqlite")).unwrap();
    conn.execute_batch(
        "CREATE TABLE app_ingress_configs (
                app_name TEXT PRIMARY KEY, public_domain TEXT NOT NULL,
                external_access_enabled INTEGER NOT NULL, listen_port INTEGER NOT NULL,
                tls_enabled INTEGER NOT NULL, created_at TEXT, updated_at TEXT
            );
            CREATE TABLE retained_app_ingress_configs (
                app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL
            );",
    )
    .unwrap();
    conn
}

#[cfg(unix)]
#[test]
fn blueprint_vhost_app_inspection_failure_restores_earlier_mutation() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let root = create_isolated_test_dir("blueprint-app-inspection-failure");
    let app_config = root.join("var/lib/sonarr/config.xml");
    let later_config = root.join("var/lib/sonarr/.config/sonarr/config.xml");
    let inaccessible = root.join("var/lib/sonarr/.config");
    fs::create_dir_all(later_config.parent().unwrap()).unwrap();
    fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
    fs::write(&later_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
    let permissions = fs::metadata(&inaccessible).unwrap().permissions();
    fs::set_permissions(&inaccessible, fs::Permissions::from_mode(0o000)).unwrap();

    let result = try_apply_runner_blueprint_app_config(Some(&root), "sonarr", 18989);
    fs::set_permissions(&inaccessible, permissions).unwrap();
    let error = result.unwrap_err().to_string();

    assert!(
        error.contains("failed to inspect required blueprint config"),
        "{error}"
    );
    assert!(
        error.contains(&later_config.display().to_string()),
        "{error}"
    );
    assert_eq!(
        fs::read_to_string(app_config).unwrap(),
        BLUEPRINT_APP_CONFIG_FIXTURE
    );
    assert_eq!(
        fs::read_to_string(later_config).unwrap(),
        BLUEPRINT_APP_CONFIG_FIXTURE
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn blueprint_vhost_read_failure_restores_app_config() {
    let root = create_isolated_test_dir("blueprint-vhost-read-failure");
    let app_config = root.join("var/lib/sonarr/config.xml");
    let internal = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
    let external = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
    fs::create_dir_all(app_config.parent().unwrap()).unwrap();
    fs::create_dir_all(internal.parent().unwrap()).unwrap();
    fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
    fs::write(&internal, BLUEPRINT_VHOST_FIXTURE).unwrap();
    fs::write(&external, [0xff, 0xfe]).unwrap();

    let error =
        try_apply_runner_blueprint_app_config_with_ingress(Some(&root), "sonarr", 18989, |_| {
            panic!("invalid vhost must fail before ingress lookup")
        })
        .unwrap_err()
        .to_string();

    assert!(
        error.contains("failed to read required Apache vhost"),
        "{error}"
    );
    assert!(error.contains(&external.display().to_string()), "{error}");
    assert_eq!(
        fs::read_to_string(app_config).unwrap(),
        BLUEPRINT_APP_CONFIG_FIXTURE
    );
    assert_eq!(
        fs::read_to_string(internal).unwrap(),
        BLUEPRINT_VHOST_FIXTURE
    );
    assert_eq!(fs::read(external).unwrap(), [0xff, 0xfe]);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn blueprint_vhost_failed_late_write_rolls_back_updates_creates_and_deletes() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for existing_internal in [false, true] {
        let root = create_isolated_test_dir("blueprint-vhost-late-write");
        let app_config = root.join("var/lib/sonarr/config.xml");
        let internal = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
        let external = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
        let enabled = root.join("etc/apache2/sites-enabled/aetherflow-app-sonarr.conf");
        fs::create_dir_all(app_config.parent().unwrap()).unwrap();
        fs::create_dir_all(internal.parent().unwrap()).unwrap();
        fs::create_dir_all(enabled.parent().unwrap()).unwrap();
        fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
        fs::set_permissions(&app_config, fs::Permissions::from_mode(0o640)).unwrap();
        if existing_internal {
            fs::write(&internal, BLUEPRINT_VHOST_FIXTURE).unwrap();
            fs::set_permissions(&internal, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(&external, BLUEPRINT_VHOST_FIXTURE).unwrap();
        fs::set_permissions(&external, fs::Permissions::from_mode(0o640)).unwrap();
        fs::write(&enabled, BLUEPRINT_VHOST_FIXTURE).unwrap();
        let enabled_directory = enabled.parent().unwrap();
        let permissions = fs::metadata(enabled_directory).unwrap().permissions();
        fs::set_permissions(enabled_directory, fs::Permissions::from_mode(0o555)).unwrap();

        let result = try_apply_runner_blueprint_app_config_with_ingress(
            Some(&root),
            "sonarr",
            18989,
            |_| Ok(Some(af_models::AppIngressConfig::default())),
        );
        fs::set_permissions(enabled_directory, permissions).unwrap();
        let error = result.unwrap_err().to_string();

        assert!(
            error.contains("failed to write required Apache vhost"),
            "{error}"
        );
        assert!(error.contains(&enabled.display().to_string()), "{error}");
        assert!(
            error.contains("restored previous blueprint configuration"),
            "{error}"
        );
        assert!(!error.contains("incomplete rollback"), "{error}");
        assert_eq!(
            fs::read_to_string(&app_config).unwrap(),
            BLUEPRINT_APP_CONFIG_FIXTURE
        );
        assert_eq!(
            fs::metadata(app_config).unwrap().permissions().mode() & 0o777,
            0o640
        );
        if existing_internal {
            assert_eq!(
                fs::read_to_string(&internal).unwrap(),
                BLUEPRINT_VHOST_FIXTURE
            );
            assert_eq!(
                fs::metadata(internal).unwrap().permissions().mode() & 0o777,
                0o600
            );
        } else {
            assert!(!internal.exists());
        }
        assert_eq!(
            fs::read_to_string(&external).unwrap(),
            BLUEPRINT_VHOST_FIXTURE
        );
        assert_eq!(
            fs::metadata(external).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            fs::read_to_string(enabled).unwrap(),
            BLUEPRINT_VHOST_FIXTURE
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn blueprint_vhost_failed_delete_is_explicit_and_preserves_original() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let root = create_isolated_test_dir("blueprint-vhost-delete-failure");
    let target = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, BLUEPRINT_VHOST_FIXTURE).unwrap();
    let directory = target.parent().unwrap();
    let permissions = fs::metadata(directory).unwrap().permissions();
    fs::set_permissions(directory, fs::Permissions::from_mode(0o555)).unwrap();
    let mut changes = RunnerBlueprintConfigChanges::new(Some(&root));
    let result = changes.remove_vhost(&target);
    fs::set_permissions(directory, permissions).unwrap();
    let error = changes.rollback(result.unwrap_err()).to_string();

    assert!(
        error.contains("failed to remove required Apache vhost"),
        "{error}"
    );
    assert!(error.contains(&target.display().to_string()), "{error}");
    assert_eq!(fs::read_to_string(target).unwrap(), BLUEPRINT_VHOST_FIXTURE);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn blueprint_vhost_incomplete_rollback_is_honest_and_continues_other_restores() {
    for previously_existed in [false, true] {
        let root = create_isolated_test_dir("blueprint-vhost-incomplete-rollback");
        let restored = root.join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
        let blocked = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
        fs::create_dir_all(restored.parent().unwrap()).unwrap();
        fs::write(&restored, BLUEPRINT_VHOST_FIXTURE).unwrap();
        if previously_existed {
            fs::write(&blocked, BLUEPRINT_VHOST_FIXTURE).unwrap();
        }
        let mut changes = RunnerBlueprintConfigChanges::new(Some(&root));
        changes
            .write_vhost(&restored, "updated internal config")
            .unwrap();
        changes
            .write_vhost(&blocked, "updated external config")
            .unwrap();
        fs::remove_file(&blocked).unwrap();
        fs::create_dir(&blocked).unwrap();

        let error = changes
            .rollback(PackageExecutorError::VerificationFailed(
                "fixture configtest failure".to_string(),
            ))
            .to_string();

        assert!(error.contains("fixture configtest failure"), "{error}");
        assert!(error.contains("incomplete rollback"), "{error}");
        assert!(error.contains(&blocked.display().to_string()), "{error}");
        assert!(!error.contains("restored previous"), "{error}");
        assert_eq!(
            fs::read_to_string(restored).unwrap(),
            BLUEPRINT_VHOST_FIXTURE
        );
        assert!(blocked.is_dir());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn blueprint_vhost_ingress_lookup_errors_restore_app_config_without_changing_ingress() {
    for corrupt_retained in [false, true] {
        let root = create_isolated_test_dir("blueprint-vhost-ingress-error");
        let conn = blueprint_ingress_fixture(&root);
        if corrupt_retained {
            conn.execute(
                "INSERT INTO retained_app_ingress_configs VALUES ('sonarr', 'invalid JSON')",
                [],
            )
            .unwrap();
        } else {
            conn.execute("DROP TABLE app_ingress_configs", []).unwrap();
        }
        let app_config = root.join("var/lib/sonarr/config.xml");
        let external = root.join("etc/apache2/sites-available/aetherflow-ext-sonarr.conf");
        fs::create_dir_all(app_config.parent().unwrap()).unwrap();
        fs::create_dir_all(external.parent().unwrap()).unwrap();
        fs::write(&app_config, BLUEPRINT_APP_CONFIG_FIXTURE).unwrap();
        fs::write(&external, BLUEPRINT_VHOST_FIXTURE).unwrap();

        let error = try_apply_runner_blueprint_app_config_with_ingress(
            Some(&root),
            "sonarr",
            18989,
            |canonical| load_runner_blueprint_ingress(&conn, canonical),
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("failed to load blueprint ingress for sonarr"),
            "{error}"
        );
        assert_eq!(
            fs::read_to_string(app_config).unwrap(),
            BLUEPRINT_APP_CONFIG_FIXTURE
        );
        assert_eq!(
            fs::read_to_string(external).unwrap(),
            BLUEPRINT_VHOST_FIXTURE
        );
        assert!(!root
            .join("etc/apache2/sites-available/aetherflow-app-sonarr.conf")
            .exists());
        drop(conn);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn blueprint_vhost_absent_ingress_preserves_external_domain_aliases_and_custom_blocks() {
    let root = create_isolated_test_dir("blueprint-vhost-enabled-aliases");
    let conn = blueprint_ingress_fixture(&root);
    let available = root.join("etc/apache2/sites-available");
    let enabled = root.join("etc/apache2/sites-enabled");
    fs::create_dir_all(&available).unwrap();
    fs::create_dir_all(&enabled).unwrap();
    let external = available.join("aetherflow-ext-qui.conf");
    let original = "<VirtualHost *:443>\n    ServerName operator.example.com\n    SSLEngine on\n    SSLCertificateFile /operator/certificate.pem\n    ProxyPass / http://127.0.0.1:8376/\n</VirtualHost>\n";
    fs::write(&external, original).unwrap();
    let policy = available.join("operator-policy.conf");
    let custom =
        "<Location /private>\n    AuthType Basic\n    Require ip 192.0.2.0/24\n</Location>\n";
    fs::write(&policy, custom).unwrap();
    let aliases = [
        (
            "aetherflow-app-qui.conf",
            "../sites-available/aetherflow-app-qui.conf",
        ),
        (
            "aetherflow-ext-qui.conf",
            "../sites-available/aetherflow-ext-qui.conf",
        ),
        ("qui.conf", "../sites-available/operator-policy.conf"),
    ];
    for (name, target) in aliases {
        std::os::unix::fs::symlink(target, enabled.join(name)).unwrap();
    }

    try_apply_runner_blueprint_app_config_with_ingress(Some(&root), "qui", 18376, |canonical| {
        load_runner_blueprint_ingress(&conn, canonical)
    })
    .unwrap();

    let updated_external = fs::read_to_string(external).unwrap();
    assert!(updated_external.contains("ServerName operator.example.com"));
    assert!(updated_external.contains("<VirtualHost *:443>"));
    assert!(updated_external.contains("SSLCertificateFile /operator/certificate.pem"));
    assert!(updated_external.contains("http://127.0.0.1:18376/"));
    assert!(updated_external.contains(custom.trim()));
    assert!(
        fs::read_to_string(available.join("aetherflow-app-qui.conf"))
            .unwrap()
            .contains(custom.trim())
    );
    assert_eq!(fs::read_to_string(policy).unwrap(), custom);
    for (name, target) in aliases {
        assert_eq!(
            fs::read_link(enabled.join(name)).unwrap(),
            Path::new(target)
        );
    }
    assert!(load_runner_blueprint_ingress(&conn, "qui")
        .unwrap()
        .is_none());
    drop(conn);
    fs::remove_dir_all(root).unwrap();
}


fn create_apache_test_certificate(directory: &Path, san: &str) {
    fs::create_dir_all(directory).unwrap();
    let output = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=example.test",
            "-addext",
            &format!("subjectAltName={san}"),
            "-keyout",
        ])
        .arg(directory.join("privkey.pem"))
        .arg("-out")
        .arg(directory.join("fullchain.pem"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn generated_master_credentials_include_encrypted_digest() {
    use std::os::unix::fs::PermissionsExt;
    let _env = crate::ENV_TEST_MUTEX.lock().await;
    let root = create_isolated_test_dir("generated-master-digest");
    let vars = [
        "AETHERFLOW_MASTER_PASS",
        "MASTER_PASS",
        "AF_PASS",
        "AETHERFLOW_VNC_PASSWORD",
        "AETHERFLOW_MASTER_CREDS_FILE",
        "AES_MASTER_KEY",
    ];
    let previous = vars.map(|key| (key, env::var_os(key)));
    for key in vars {
        env::remove_var(key);
    }
    env::set_var("AES_MASTER_KEY", "11".repeat(32));
    let result = try_resolve_master_credentials(Some(&root));
    let path = root.join("var/lib/aetherflow/.master.creds");
    let stored = fs::read_to_string(&path).unwrap();
    let stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
    let password = af_db::decrypt_secret_if_needed(stored["password"].as_str().unwrap());
    let stored_digest = af_db::decrypt_secret_if_needed(stored["ha1"].as_str().unwrap());
    for (key, value) in previous {
        if let Some(value) = value {
            env::set_var(key, value);
        } else {
            env::remove_var(key);
        }
    }
    let (user, secret) = result.unwrap();
    assert_eq!(stored["username"], user);
    assert!(stored["password"].as_str().unwrap().starts_with("enc:v1:"));
    assert!(stored["ha1"].as_str().unwrap().starts_with("enc:v1:"));
    assert!(password.is_ok_and(|password| password == secret));
    let expected = hex::encode(af_models::md5::md5_digest(
        format!("{user}:Welcome to AetherFlow:{secret}").as_bytes(),
    ));
    assert!(stored_digest.is_ok_and(|digest| digest == expected));
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn threadfin_ignores_unpinned_target_and_catalog_matches_native_recipes() {
    let _env = crate::ENV_TEST_MUTEX.lock().await;
    let key = "AF_TARGET_VERSION";
    let previous = env::var_os(key);
    env::set_var(key, "99.9.9");
    let version = resolve_threadfin_target_version();
    if let Some(value) = previous {
        env::set_var(key, value);
    } else {
        env::remove_var(key);
    }
    assert_eq!(version, THREADFIN_PINNED_VERSION);
    let recipes: HashMap<String, af_models::PackageAutomation> =
        serde_json::from_str(crate::EMBEDDED_AUTOMATION_JSON).unwrap();
    assert_eq!(recipes["threadfin"].update_source, "pinned");
    assert!(recipes["threadfin"].require_download_sha256);
    assert_eq!(recipes["prometheus"].update_source, "github");
    assert_eq!(recipes["prometheus"].update_repo, "prometheus/prometheus");
    assert_eq!(recipes["prometheus"].update_package, "prometheus");
    assert_eq!(
        recipes["prometheus"].version_command,
        ["/usr/local/bin/prometheus", "--version"]
    );
}

#[test]
fn apache_tls_uses_base_cert_only_for_covered_names() {
    let root = create_isolated_test_dir("base-san-cert");
    let base = root.join("etc/letsencrypt/live/example.test");
    create_apache_test_certificate(&base, "DNS:one.example.test,DNS:two.env.example.test");
    assert!(check_domain_tls_ready("one.example.test", Some(&root)));
    assert!(check_domain_tls_ready("two.env.example.test", Some(&root)));
    assert!(!check_domain_tls_ready("other.example.test", Some(&root)));

    create_apache_test_certificate(&base, "DNS:*.example.test");
    let pair = apache_tls_pair("other.example.test", Some(&root)).unwrap();
    assert_eq!(pair.0, "/etc/letsencrypt/live/example.test/fullchain.pem");
    assert!(!check_domain_tls_ready("two.env.example.test", Some(&root)));

    create_apache_test_certificate(&root.join("different-key"), "DNS:*.example.test");
    fs::copy(
        root.join("different-key/privkey.pem"),
        base.join("privkey.pem"),
    )
    .unwrap();
    assert!(!check_domain_tls_ready("other.example.test", Some(&root)));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn newly_created_non_secret_parents_are_traversable() {
    use std::os::unix::fs::PermissionsExt;
    let root = create_isolated_test_dir("install-parent-permissions");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let target = root.join("opt/new-app");
    create_dir_all_0755(&target).unwrap();
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for path in [target, root.join("opt")] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_apache_vhost_pins_kasm_tls_and_requires_auth_for_public_backends() {
    let root = create_isolated_test_dir("managed-vhost-tls-auth");
    let cert = root.join("var/lib/kasmvnc/.vnc/aetherflow-cert.pem");
    fs::create_dir_all(cert.parent().unwrap()).unwrap();
    fs::write(&cert, "upstream-cert-fixture").unwrap();
    let mut req = af_models::RunnerApacheVhostRequest {
        app_name: "kasmvnc".to_owned(),
        listen_port: 8444,
        ..Default::default()
    };
    let kasm_tls = apache_upstream_tls("kasmvnc", Some(&root)).unwrap();
    let rendered = render_managed_apache_vhost(
        &req,
        "kasmvnc.aether.local",
        true,
        &kasm_tls,
        Some(&root),
        &[],
        &[],
    )
    .unwrap();
    assert!(
        rendered.contains("SSLProxyCACertificateFile /var/lib/kasmvnc/.vnc/aetherflow-cert.pem")
    );
    assert!(rendered.contains("wss://127.0.0.1:8444/"));
    assert!(rendered.contains("https://127.0.0.1:8444/"));

    req.app_name = "prometheus".to_string();
    req.tls_enabled = true;
    let domain = "metrics.example.test";
    let options = LibreSpeedUpstreamTlsConfig::default();
    let legacy = "<Location /custom>\n    Require all granted\n</Location>\n";
    let pending =
        render_managed_apache_vhost(&req, domain, false, &options, Some(&root), &[], &[legacy])
            .unwrap();
    assert!(pending.contains("TLS certificate provisioning pending"));
    assert!(pending.contains("RewriteRule ^ - [R=503,L]"));
    assert!(pending.contains("ProxyPass /.well-known/acme-challenge/ !"));
    assert!(!pending.contains("ProxyPass / http"));
    assert!(!pending.contains("AuthType Basic"));
    assert!(!pending.contains("<VirtualHost *:443>"));
    assert!(pending.contains("# af-tls-pending: <Location /custom>"));
    assert!(!check_domain_tls_ready(domain, Some(&root)));
    let htpasswd = root.join(APACHE_HTPASSWD.trim_start_matches('/'));
    fs::create_dir_all(htpasswd.parent().unwrap()).unwrap();
    fs::write(&htpasswd, "fixture").unwrap();
    let tls_dir = root.join("etc/letsencrypt/live").join(domain);
    create_apache_test_certificate(&tls_dir, "DNS:metrics.example.test");
    let managed =
        render_managed_apache_vhost(&req, domain, false, &options, Some(&root), &[&pending], &[])
            .unwrap();
    assert!(managed.contains("RewriteRule ^ https://metrics.example.test%{REQUEST_URI} [R=308,L]"));
    assert!(managed.contains("<Location /custom>"));
    assert!(
        managed
            .find("ProxyPass /.well-known/acme-challenge/ !")
            .unwrap()
            < managed.find("[R=308,L]").unwrap()
    );
    for header in [
        "X-Real-IP",
        "X-Forwarded-Host",
        "X-Aetherflow-User",
        "Remote-User",
        "X-Forwarded-User",
    ] {
        assert!(managed.contains(&format!("RequestHeader unset {header}")));
    }
    assert!(managed.contains("RequestHeader set X-Real-IP \"%{REMOTE_ADDR}s\""));
    assert!(managed.contains("<VirtualHost *:443>"));
    assert!(managed
        .contains("SSLCertificateKeyFile /etc/letsencrypt/live/metrics.example.test/privkey.pem"));
    assert!(managed.contains("AuthUserFile /etc/apache2/AetherFlow/htpasswd"));
    assert!(managed.contains("Require valid-user"));
    let rerendered =
        render_managed_apache_vhost(&req, domain, false, &options, Some(&root), &[&managed], &[])
            .unwrap();
    assert_eq!(managed, rerendered);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn managed_apache_vhost_routes_protected_apps_through_the_gateway() {
    let root = create_isolated_test_dir("managed-vhost-gateway");
    let options = LibreSpeedUpstreamTlsConfig::default();
    let domain = "app.example.test";
    let old_auth = r#"    <If "true">
        AuthType Basic
        AuthName "AetherFlow"
        AuthBasicProvider file
        AuthUserFile /etc/apache2/AetherFlow/htpasswd
        AuthMerging And
        Require valid-user
    </If>
"#;
    let inherited = format!(
        "<VirtualHost *:443>\n    ServerName {domain}\n    ProxyPass / http://127.0.0.1:19090/\n{old_auth}</VirtualHost>\n"
    );
    let tls_dir = root.join("etc/letsencrypt/live").join(domain);
    create_apache_test_certificate(&tls_dir, "DNS:app.example.test");
    for app in [
        "mcvnc",
        "scrutiny",
        "prometheus",
        "flaresolverr",
        "jackett",
        "threadfin",
        "unmanic",
        "netdata",
        "autoscan",
    ] {
        let req = af_models::RunnerApacheVhostRequest {
            app_name: app.into(),
            listen_port: 19090,
            public_domain: Some(domain.into()),
            external_access_enabled: true,
            tls_enabled: true,
            ..Default::default()
        };
        let body = render_managed_apache_vhost(
            &req,
            domain,
            false,
            &options,
            Some(&root),
            &[&inherited],
            &[],
        )
        .unwrap();
        let (http, tls) = body.split_once("<VirtualHost *:443>").unwrap();
        assert!(http.contains(ACME_HTTP_EXEMPTION));
        assert!(http.contains(ACME_REWRITE_GUARD));
        assert!(http.contains("RewriteRule ^ https://app.example.test%{REQUEST_URI} [R=308,L]"));
        assert!(!http.contains(GATEWAY_APP_HEADER));
        assert!(tls.contains("ProxyPreserveHost On"));
        assert!(tls.contains("RequestHeader unset X-Forwarded-For"));
        assert!(tls.contains("RewriteRule /(.*) ws://127.0.0.1:8080/$1 [P,L]"));
        assert!(tls.contains("ProxyPass / http://127.0.0.1:8080/"));
        assert!(tls.contains("ProxyPassReverse / http://127.0.0.1:19090/"));
        assert!(tls.contains(&format!("RequestHeader set {GATEWAY_APP_HEADER} {app}")));
        assert!(!tls.contains("AuthUserFile"));
        assert!(!tls.contains("ProxyPass / http://127.0.0.1:19090/"));
        let mut missing_ingress = req.clone();
        missing_ingress.listen_port = 19091;
        missing_ingress.external_access_enabled = false;
        assert_eq!(
            update_legacy_apache_vhost(&body, &missing_ingress, &options, Some(&root), true)
                .unwrap(),
            body
        );
        assert_eq!(
            render_managed_apache_vhost(&req, domain, false, &options, Some(&root), &[&body], &[])
                .unwrap(),
            body
        );

        if app == "netdata" {
            let mut plain = req;
            plain.tls_enabled = false;
            let body =
                render_managed_apache_vhost(&plain, domain, false, &options, Some(&root), &[], &[])
                    .unwrap();
            assert!(
                body.find(ACME_HTTP_EXEMPTION).unwrap()
                    < body.find("ProxyPass / http://127.0.0.1:8080/").unwrap()
            );
            assert!(
                body.find(ACME_REWRITE_GUARD).unwrap()
                    < body.find("RewriteRule /(.*) ws://127.0.0.1:8080/").unwrap()
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn inherited_apache_vhost_and_rutorrent_keep_apache_auth() {
    let root = create_isolated_test_dir("inherited-vhost-auth");
    let htpasswd = root.join(APACHE_HTPASSWD.trim_start_matches('/'));
    fs::create_dir_all(htpasswd.parent().unwrap()).unwrap();
    fs::write(htpasswd, "fixture").unwrap();
    let mut req = af_models::RunnerApacheVhostRequest {
        app_name: "rutorrent".into(),
        listen_port: 8087,
        public_domain: Some("torrent.example.test".into()),
        external_access_enabled: true,
        ..Default::default()
    };
    let options = LibreSpeedUpstreamTlsConfig::default();
    let body = render_managed_apache_vhost(
        &req,
        "torrent.example.test",
        false,
        &options,
        Some(&root),
        &[],
        &[],
    )
    .unwrap();
    assert!(body.contains("ProxyPass / http://127.0.0.1:8087/"));
    assert!(body.contains(APACHE_HTPASSWD));
    assert!(!body.contains(GATEWAY_APP_HEADER));

    let legacy = "\
<VirtualHost *:80>
    ServerName app.example.test
    ProxyPass / http://127.0.0.1:19090/
    <Location /private>
        Require ip 192.0.2.0/24
    </Location>
</VirtualHost>
";
    req.app_name = "prometheus".into();
    req.public_domain = Some("app.example.test".into());
    req.listen_port = 19091;
    let updated = update_legacy_apache_vhost(legacy, &req, &options, Some(&root), false).unwrap();
    assert!(updated.contains("ProxyPass / http://127.0.0.1:19091/"));
    assert!(updated.contains("Require ip 192.0.2.0/24"));
    assert!(updated.contains("AuthMerging And"));
    assert!(updated.contains(APACHE_HTPASSWD));
    assert!(!updated.contains(GATEWAY_APP_HEADER));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_librespeed_apache_vhost_honors_and_toggles_upstream_tls() {
    assert!(!parse_librespeed_root_tls_flag("enable_tls = false\n"));
    assert!(parse_librespeed_root_tls_flag(
        "listen_port = 8988\nenable_tls = true # comment\n"
    ));
    assert!(!parse_librespeed_root_tls_flag(
        "enable_tls = false\n[extra]\nenable_tls = true\n"
    ));
    assert!(parse_librespeed_root_tls_flag(
        "enable_tls = true\nbanner = \"\"\"\n# example:\nenable_tls = false\n\"\"\"\n"
    ));
    assert!(parse_librespeed_root_tls_flag(
        "enable_tls = true\nnotes = '''\nenable_tls = false\n'''\n"
    ));

    let http_default = "# Managed by AetherFlow v3.2.6\n<VirtualHost *:80>\n    ServerName librespeed.aether.local\n    ProxyPreserveHost On\n    ProxyRequests Off\n    RewriteEngine On\n    RewriteCond %{HTTP:Upgrade} =websocket [NC]\n    RewriteRule /(.*) ws://127.0.0.1:8988/$1 [P,L]\n    ProxyPass / http://127.0.0.1:8988/\n    ProxyPassReverse / http://127.0.0.1:8988/\n    RequestHeader set X-Forwarded-Proto \"http\"\n    IncludeOptional /etc/aetherflow/librespeed-proxy-token.conf\n</VirtualHost>\n";

    // Pin operator certificate via SSLProxyCACertificateFile + SSLProxyVerify require when enable_tls=true
    let pinned_tls = render_or_update_runner_apache_vhost_with_ca(
        Some(http_default),
        http_default,
        Some("librespeed.aether.local"),
        18988,
        Some(true),
        Some("/opt/librespeed/cert.pem"),
        &["    IncludeOptional /etc/aetherflow/librespeed-proxy-token.conf".to_string()],
    );
    assert!(pinned_tls.contains("SSLProxyEngine On"));
    assert!(pinned_tls.contains("SSLProxyVerify require"));
    assert!(pinned_tls.contains("SSLProxyCACertificateFile /opt/librespeed/cert.pem"));
    assert!(!pinned_tls.contains("SSLProxyVerify none"));
    assert!(pinned_tls.contains("wss://127.0.0.1:18988/$1"));
    assert!(pinned_tls.contains("ProxyPass / https://127.0.0.1:18988/"));
    assert!(pinned_tls.contains("ProxyPassReverse / https://127.0.0.1:18988/"));

    // Fail closed if enable_tls=true in settings.toml lacks a valid regular tls_cert_file
    let tmp_dir = std::env::temp_dir().join(format!(
        "af-runner-librespeed-tls-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(tmp_dir.join("etc/apache2/sites-available")).unwrap();
    fs::create_dir_all(tmp_dir.join("etc/apache2/sites-enabled")).unwrap();
    fs::create_dir_all(tmp_dir.join("opt/librespeed")).unwrap();
    fs::write(
            tmp_dir.join("opt/librespeed/settings.toml"),
            "enable_tls = true\ntls_cert_file = \"/opt/librespeed/missing-cert.pem\"\ntls_key_file = \"/opt/librespeed/key.pem\"\n",
        )
        .unwrap();
    let mut changes = RunnerBlueprintConfigChanges::new(Some(&tmp_dir));
    let err =
        apply_runner_blueprint_app_config_changes(&mut changes, "librespeed", 18988, |_| Ok(None))
            .expect_err("enable_tls=true without valid tls_cert_file must fail closed");
    assert!(
        err.to_string().contains("SSLProxyCACertificateFile"),
        "unexpected error: {err}"
    );

    // Succeeds with pinned SSLProxyCACertificateFile once regular tls_cert_file exists
    fs::write(
        tmp_dir.join("opt/librespeed/cert.pem"),
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    fs::write(
            tmp_dir.join("opt/librespeed/settings.toml"),
            "enable_tls = true\ntls_cert_file = \"/opt/librespeed/cert.pem\"\ntls_key_file = \"/opt/librespeed/key.pem\"\n",
        )
        .unwrap();
    let mut ok_changes = RunnerBlueprintConfigChanges::new(Some(&tmp_dir));
    apply_runner_blueprint_app_config_changes(&mut ok_changes, "librespeed", 18988, |_| Ok(None))
        .expect("enable_tls=true with valid regular tls_cert_file must succeed");
    let rendered_on_disk = fs::read_to_string(
        tmp_dir.join("etc/apache2/sites-available/aetherflow-app-librespeed.conf"),
    )
    .unwrap();
    assert!(rendered_on_disk.contains("SSLProxyVerify require"));
    assert!(rendered_on_disk.contains("SSLProxyCACertificateFile /opt/librespeed/cert.pem"));
    assert!(!rendered_on_disk.contains("SSLProxyVerify none"));
    let _ = fs::remove_dir_all(&tmp_dir);

    // Downgrade back to HTTP cleanly when enable_tls=false
    let demoted_http = render_or_update_runner_apache_vhost(
        Some(&pinned_tls),
        http_default,
        Some("librespeed.aether.local"),
        18989,
        Some(false),
        &["    IncludeOptional /etc/aetherflow/librespeed-proxy-token.conf".to_string()],
    );
    assert!(!demoted_http.contains("SSLProxyEngine"));
    assert!(!demoted_http.contains("SSLProxyCACertificateFile"));
    assert!(demoted_http.contains("ws://127.0.0.1:18989/$1"));
    assert!(demoted_http.contains("ProxyPass / http://127.0.0.1:18989/"));
}

#[tokio::test]
async fn znc_update_rejects_mismatched_apt_version_when_target_version_differs() {
    let _serial = TEST_EXECUTION_SERIALIZER.lock().await;
    let root = create_isolated_test_dir("znc-target-mismatch");
    let version_file = root.join("var/lib/znc/.af-version");
    fs::create_dir_all(version_file.parent().unwrap()).unwrap();
    fs::write(&version_file, "1.9.1-2\n").unwrap();

    let mut env_cfg = PackageExecutionEnv::isolated(&root);
    env_cfg.app_port = 6501;
    env_cfg.expected_target_version = Some("1.9.9-1".to_string());

    let mock = MockCommandRunner::default();
    let executor = DeclarativePackageExecutor::with_runner(env_cfg, mock);
    let recipe = get_declarative_recipe("znc").unwrap();

    let err = executor
        .execute_recipe(
            &recipe,
            PackageAction::Update,
            CancellationToken::new(),
            |_| {},
        )
        .await
        .expect_err("znc update must reject mismatched APT version against target 1.9.9-1");
    assert!(
        err.to_string().contains("1.9.9-1"),
        "unexpected error: {err}"
    );
    // Must preserve pre-existing .af-version receipt on rollback.
    assert_eq!(fs::read_to_string(&version_file).unwrap().trim(), "1.9.1-2");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn tigervnc_rfb_password_roundtrips_and_drifted_recipes_fallback_to_bash() {
    // Known DES-ECB vector using the bit-reversed RFB key.
    let cipher = encode_tigervnc_passwd("password and ignored bytes");
    assert_eq!(hex::encode(cipher), "dbd83cfd727a1458");
    assert_ne!(&cipher, b"password");
    assert_eq!(decode_tigervnc_passwd(&cipher).as_deref(), Some("password"));

    assert!(crate::is_managed_runner_systemd_unit(
        "novnc-session.service"
    ));
    for deferred in ["prometheus", "syncthing", "novnc"] {
        assert!(get_declarative_recipe(deferred).is_none());
        assert_eq!(
            select_package_engine_with_flags(deferred, true, false),
            PackageEngineMode::LegacyBashFallback
        );
    }
}

#[test]
fn apache_htpasswd_provisions_bcrypt_and_fails_closed_without_credentials() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = env::temp_dir().join(format!("af-htpasswd-{}", uuid::Uuid::new_v4()));
    let path = root.join("etc/apache2/AetherFlow/htpasswd");
    assert!(ensure_apache_htpasswd_with(&path, || None).is_err());
    assert!(!path.exists());
    assert!(external_auth_policy("netdata", Some(&root)).is_err());
    let hash = format!("$2b$10{}{}", '$', "a".repeat(53));
    let entry = apache_bcrypt_entry("admin", &hash).unwrap();
    assert!(entry.starts_with("admin:$2y$10$"));
    ensure_apache_htpasswd_with(&path, || Some(entry.clone())).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), entry);
    let meta = path.metadata().unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
    if unsafe { libc::geteuid() } == 0 {
        assert_eq!(meta.uid(), 0);
        assert_eq!(meta.gid(), crate::lookup_group_gid("www-data").unwrap_or(0));
    }
    ensure_apache_htpasswd_with(&path, || panic!("must preserve an existing file")).unwrap();
    for app in ["netdata", "unmanic", "autoscan"] {
        assert!(external_auth_policy(app, Some(&root))
            .unwrap()
            .contains("Require valid-user"));
    }
    fs::write(&path, "").unwrap();
    assert!(ensure_apache_htpasswd_with(&path, || None).is_err());
    ensure_apache_htpasswd_with(&path, || Some(entry.clone())).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), entry);
    fs::remove_dir_all(root).unwrap();
}

