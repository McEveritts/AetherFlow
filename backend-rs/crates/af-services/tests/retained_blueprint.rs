use rusqlite::Connection;
use serde_json::json;
use std::{env, fs, os::unix::fs::PermissionsExt, path::Path};

async fn finalize(conn: &mut Connection, action: &str, job: &str) {
    let lease = af_release::lifecycle::admit_job(
        conn,
        "sabnzbd",
        job,
        action,
        "2026-11-06T00:00:00Z",
        &["sabnzbd".into()],
    )
    .unwrap();
    af_runner::PACKAGE_JOB_ID
        .scope(job.to_string(), async {
            af_services::mutators::apply_blueprint_app_config("sabnzbd", 18080)
                .await
                .unwrap();
        })
        .await;
    af_db::synchronize_lifecycle_ingress(
        conn,
        "sabnzbd",
        action,
        job,
        18080,
        false,
        "base.example.test",
    )
    .unwrap();
    af_release::lifecycle::finish_job(conn, "sabnzbd", job, action, true, "").unwrap();
    drop(lease);
}

fn read_config(root: &Path) -> String {
    fs::read_to_string(root.join("var/lib/sabnzbd/sabnzbd.ini")).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn owned_reinstall_materializes_retained_native_and_apache_configuration() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = env::temp_dir().join(format!(
        "af-retained-blueprint-{}-{stamp}",
        std::process::id()
    ));
    assert!(!root.exists());
    for directory in [
        "bin",
        "install",
        "var/lib/aetherflow",
        "var/lib/sabnzbd",
        "etc/apache2/sites-available",
    ] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    let database = root.join("var/lib/aetherflow/aetherflow.sqlite");
    for key in [
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_CONFIG_ROOT",
        "AETHERFLOW_RELEASE_ROOT",
    ] {
        env::set_var(key, &root);
    }
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &database);
    }
    env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    env::set_var("AETHERFLOW_PACKAGES_CONFIG", root.join("packages.json"));
    env::set_var(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        root.join("automation.json"),
    );
    env::set_var("AETHERFLOW_MASTER_CREDS_FILE", root.join("fake-creds.json"));
    env::set_var("AETHERFLOW_HOSTS_FILE", root.join("hosts"));
    env::set_var("AETHERFLOW_BASE_DOMAIN", "base.example.test");
    env::set_var("AETHERFLOW_RUNNER_SOCK", root.join("absent.sock"));
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );
    fs::write(root.join("packages.json"), json!([{
        "name": "sabnzbd", "label": "SABnzbd", "description": "disposable fixture", "category": "test",
        "lock_file": "/install/.sabnzbd.lock", "default_port": 18080,
        "service_type": "systemd", "service_name": "sabnzbd"
    }]).to_string()).unwrap();
    fs::write(root.join("automation.json"), "{}").unwrap();
    fs::write(
        root.join("fake-creds.json"),
        r#"{"username":"fixture-admin","password":"fixture-password"}"#,
    )
    .unwrap();
    fs::write(root.join("hosts"), "127.0.0.1 localhost\n").unwrap();
    fs::write(root.join("var/lib/sabnzbd/sabnzbd.ini"), "[misc]\nport = 18080\nhost_whitelist = custom.example.test, sabnzbd.aether.local, localhost, 127.0.0.1\nusername = fixture-admin\npassword = fixture-password\nuser_tuning = preserved\n").unwrap();
    let fake = root.join("bin/systemctl");
    fs::write(&fake, "#!/bin/sh\ntest \"$1\" = show || exit 94\nprintf 'ActiveState=active\\nSubState=running\\n'\n").unwrap();
    fs::set_permissions(fake, fs::Permissions::from_mode(0o755)).unwrap();
    af_db::init_db().unwrap();
    af_services::initialize_package_jobs(Connection::open(&database).unwrap()).unwrap();
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "sabnzbd".into(),
        public_domain: "custom.example.test".into(),
        external_access_enabled: true,
        tls_enabled: true,
        listen_port: 18080,
        ..Default::default()
    })
    .unwrap();
    let mut conn = Connection::open(database).unwrap();
    finalize(&mut conn, "update", "native-whitelist-before").await;
    let before = read_config(&root);
    assert!(before
        .lines()
        .find(|line| line.starts_with("host_whitelist"))
        .unwrap()
        .contains("custom.example.test"));
    let lease = af_release::lifecycle::admit_job(
        &mut conn,
        "sabnzbd",
        "native-whitelist-remove",
        "remove",
        "2026-11-06T00:00:00Z",
        &["sabnzbd".into()],
    )
    .unwrap();
    af_db::synchronize_lifecycle_ingress(
        &mut conn,
        "sabnzbd",
        "remove",
        "native-whitelist-remove",
        0,
        false,
        "",
    )
    .unwrap();
    af_release::lifecycle::finish_job(
        &conn,
        "sabnzbd",
        "native-whitelist-remove",
        "remove",
        true,
        "",
    )
    .unwrap();
    drop(lease);
    assert!(af_db::get_app_ingress_config("sabnzbd").unwrap().is_none());
    assert_eq!(read_config(&root), before);
    // Unowned settings refreshes must not restore archived public routing.
    af_services::mutators::apply_blueprint_app_config("sabnzbd", 18080)
        .await
        .unwrap();
    assert!(!root
        .join("etc/apache2/sites-available/aetherflow-ext-sabnzbd.conf")
        .exists());
    assert!(!read_config(&root).contains("custom.example.test"));
    finalize(&mut conn, "install", "native-whitelist-reinstall").await;
    let after = read_config(&root);
    let restored = af_db::load_lifecycle_ingress(&conn, "sabnzbd")
        .unwrap()
        .unwrap();
    let terminal: String = conn
        .query_row(
            "SELECT status FROM package_lifecycle_jobs WHERE package_id='sabnzbd'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(after.contains("custom.example.test"));
    assert!(after
        .lines()
        .any(|line| line.replace(' ', "") == "port=18080"));
    assert!(after
        .lines()
        .any(|line| line.replace(' ', "") == "password=fixture-password"));
    let external_vhost = root.join("etc/apache2/sites-available/aetherflow-ext-sabnzbd.conf");
    assert!(fs::read_to_string(&external_vhost)
        .unwrap()
        .contains("ServerName custom.example.test"));
    assert!(after.contains("user_tuning = preserved"));
    assert_eq!(restored.public_domain, "custom.example.test");
    assert!(restored.external_access_enabled);
    assert!(restored.tls_enabled);
    assert_eq!(terminal, "completed");
    let mut disabled = restored.clone();
    disabled.external_access_enabled = false;
    af_db::set_app_ingress_config(&disabled).unwrap();
    remove(&mut conn, "disabled-remove", false);
    finalize(&mut conn, "install", "disabled-install").await;
    assert!(!external_vhost.exists());
    assert!(
        !af_db::load_lifecycle_ingress(&conn, "sabnzbd")
            .unwrap()
            .unwrap()
            .external_access_enabled
    );
    remove(&mut conn, "purge-remove", true);
    assert!(af_db::load_lifecycle_ingress(&conn, "sabnzbd")
        .unwrap()
        .is_none());
    finalize(&mut conn, "install", "post-purge-install").await;
    assert!(!read_config(&root).contains("custom.example.test"));
    remove(&mut conn, "corrupt-remove", false);
    conn.execute("UPDATE retained_app_ingress_configs SET config_json='invalid-json' WHERE app_name='sabnzbd'", []).unwrap();
    let before_error = read_config(&root);
    let lease = af_release::lifecycle::admit_job(
        &mut conn,
        "sabnzbd",
        "corrupt-install",
        "install",
        "fixture",
        &["sabnzbd".into()],
    )
    .unwrap();
    let outcome = af_runner::PACKAGE_JOB_ID
        .scope("corrupt-install".to_owned(), async {
            af_services::mutators::apply_blueprint_app_config("sabnzbd", 18080).await
        })
        .await;
    assert!(outcome.is_err());
    assert_eq!(read_config(&root), before_error);
    af_release::lifecycle::finish_job(
        &conn,
        "sabnzbd",
        "corrupt-install",
        "install",
        false,
        "configuration",
    )
    .unwrap();
    drop(lease);
    fs::remove_dir_all(&root).unwrap();
}

fn remove(conn: &mut Connection, job: &str, purge: bool) {
    let lease = af_release::lifecycle::admit_job(
        conn,
        "sabnzbd",
        job,
        "remove",
        "fixture",
        &["sabnzbd".into()],
    )
    .unwrap();
    af_db::synchronize_lifecycle_ingress(conn, "sabnzbd", "remove", job, 0, purge, "").unwrap();
    af_release::lifecycle::finish_job(conn, "sabnzbd", job, "remove", true, "").unwrap();
    drop(lease);
}
