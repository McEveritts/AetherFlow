use super::{MockRunnerTransport, TempTestDir};
use crate::commands::package_discovery::{
    candidate_cli_sqlite_dbs, discover_listenarr_github_target_for_arch,
    query_persisted_ingress_port_from_sqlite, validate_cli_package_target_policy,
};
use crate::*;
use rusqlite::Connection;
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Mutex;

#[test]
fn package_list_matches_the_resolved_catalog_in_id_order() {
    let tmp = TempTestDir::new("package-list-catalog");
    let root = tmp.path().to_str().unwrap();
    let invocation = parse_cli_args(["--json", "--root", root, "package", "list"]).unwrap();
    let transport = MockRunnerTransport::default();
    let entries = || {
        let result = execute_invocation(&invocation, &transport);
        assert_eq!(result.status, "ok", "{}", result.message);
        serde_json::from_value::<Vec<PackageListEntry>>(result.data.unwrap()["packages"].clone())
            .unwrap()
    };

    let mut catalog: Vec<af_models::Package> =
        serde_json::from_str(include_str!("../../../../../config/packages.json")).unwrap();
    catalog.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(catalog.len(), 77);
    let actual = entries();
    assert_eq!(actual.len(), catalog.len());
    for (entry, package) in actual.iter().zip(&catalog) {
        assert_eq!(entry.package_id, package.name);
        assert!(!entry.installed);
    }

    let catalog_dir = tmp.path().join("opt/AetherFlow/current/config");
    fs::create_dir_all(&catalog_dir).unwrap();
    let mut extra = catalog[0].clone();
    extra.name = "test-catalog-app".to_string();
    extra.lock_file = "/install/.test-catalog-app.lock".to_string();
    let scoped_catalog = vec![extra, catalog.swap_remove(0)];
    fs::write(
        catalog_dir.join("packages.json"),
        serde_json::to_vec(&scoped_catalog).unwrap(),
    )
    .unwrap();
    fs::create_dir_all(tmp.path().join("install")).unwrap();
    fs::write(
        tmp.path().join("install/.test-catalog-app.lock"),
        "installed\n",
    )
    .unwrap();

    let actual = entries();
    assert_eq!(actual.len(), 2);
    assert_eq!(actual[0].package_id, scoped_catalog[1].name);
    assert_eq!(actual[1].package_id, scoped_catalog[0].name);
    assert!(actual[1].installed);
}

#[test]
fn package_update_target_version_parsing_probing_and_admit_fallback() {
    let tmp = TempTestDir::new("pkg-update-target");
    let root = tmp.path().join("rootfs");
    fs::create_dir_all(root.join("var/lib/aetherflow")).unwrap();
    let root_str = root.to_string_lossy().to_string();

    // 1. Explicit `--target-version <ver>` and `--target-version=<ver>`
    let inv_space = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "update",
        "sonarr",
        "--target-version",
        "4.0.10.2544",
    ])
    .unwrap();
    let transport = MockRunnerTransport::default();
    let env_space = execute_invocation(&inv_space, &transport);
    assert_eq!(env_space.status, "ok", "{}", env_space.message);
    let calls = transport.package_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].expected_target_version.as_deref(),
        Some("4.0.10.2544")
    );
    drop(calls);

    let inv_eq = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "package",
        "update",
        "radarr",
        "--target-version=5.14.0.9383",
    ])
    .unwrap();
    let env_eq = execute_invocation(&inv_eq, &transport);
    assert_eq!(env_eq.status, "ok", "{}", env_eq.message);
    let calls = transport.package_calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[1].expected_target_version.as_deref(),
        Some("5.14.0.9383")
    );
    drop(calls);

    // 2. Reject invalid `--target-version` tokens and `--target-version` without a package
    assert!(parse_cli_args(["update", "sonarr", "--target-version", "latest"]).is_err());
    assert!(parse_cli_args(["update", "sonarr", "--target-version=../etc/passwd"]).is_err());
    assert!(parse_cli_args(["update", "--target-version", "4.0.10"]).is_err());

    // 3. Omitted `--target-version`: never falls back to local installed probe version
    let probe_transport = MockRunnerTransport::default();
    probe_transport
        .probed_versions
        .lock()
        .unwrap()
        .insert("lidarr".to_string(), "2.8.2.4493".to_string());
    let inv_probe = parse_cli_args(["--json", "--root", &root_str, "update", "lidarr"]).unwrap();
    let env_probe = execute_invocation(&inv_probe, &probe_transport);
    assert_eq!(env_probe.status, "error");
    assert!(probe_transport.package_calls.lock().unwrap().is_empty());

    // 4. Omitted `--target-version`: resolves strictly from SQLite `app_updates.latest_version`
    let db_path = root.join("var/lib/aetherflow/aetherflow.sqlite");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE app_updates (
            package_name TEXT PRIMARY KEY,
            installed_version TEXT DEFAULT '',
            latest_version TEXT DEFAULT ''
        );
        INSERT INTO app_updates (package_name, installed_version, latest_version)
        VALUES ('prowlarr', '1.25.0', '1.26.2.4852');",
    )
    .unwrap();
    drop(conn);

    let db_transport = MockRunnerTransport::default();
    let inv_db = parse_cli_args([
        "--json", "--root", &root_str, "package", "update", "prowlarr",
    ])
    .unwrap();
    let env_db = execute_invocation(&inv_db, &db_transport);
    assert_eq!(env_db.status, "ok", "{}", env_db.message);
    let db_target = db_transport.package_calls.lock().unwrap()[0]
        .expected_target_version
        .clone()
        .expect("sqlite target version must be populated");
    assert_eq!(db_target, "1.26.2.4852");
    assert!(af_release::lifecycle::validate_target_version(&db_target));

    // 5. Omitted `--target-version` with no upstream source fails closed instead of fabricating "0.0.0"
    let fallback_transport = MockRunnerTransport::default();
    let inv_fallback = parse_cli_args(["--json", "--root", &root_str, "update", "bazarr"]).unwrap();
    let env_fallback = execute_invocation(&inv_fallback, &fallback_transport);
    assert_eq!(env_fallback.status, "error");
    assert!(fallback_transport.package_calls.lock().unwrap().is_empty());
}

#[test]
fn query_persisted_ingress_port_reads_retained_config_json_and_aligns_db_precedence() {
    static ENV_TEST_LOCK: once_cell::sync::Lazy<Mutex<()>> =
        once_cell::sync::Lazy::new(|| Mutex::new(()));
    let tmp = TempTestDir::new("h05-ingress");
    let db_path = tmp.path().join("aetherflow.sqlite");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE app_ingress_configs (app_name TEXT PRIMARY KEY, listen_port INTEGER NOT NULL);
         CREATE TABLE retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL);
         INSERT INTO app_ingress_configs(app_name, listen_port) VALUES ('sonarr', 18989);
         INSERT INTO retained_app_ingress_configs(app_name, config_json) VALUES ('radarr', '{\"app_name\":\"radarr\",\"listen_port\":17878}');",
    )
    .unwrap();
    drop(conn);

    assert_eq!(
        query_persisted_ingress_port_from_sqlite(&db_path, "Sonarr"),
        Some(18989)
    );
    assert_eq!(
        query_persisted_ingress_port_from_sqlite(&db_path, "Radarr"),
        Some(17878)
    );
    assert_eq!(
        query_persisted_ingress_port_from_sqlite(&db_path, "missing"),
        None
    );

    let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev_af = std::env::var("AF_DB_PATH").ok();
    let prev_db = std::env::var("DB_PATH").ok();
    let prev_legacy = std::env::var("AETHERFLOW_DB_PATH").ok();
    let prev_data = std::env::var("DATA_DIR").ok();

    std::env::set_var("AF_DB_PATH", "/tmp/af_1.sqlite");
    std::env::set_var("DB_PATH", "/tmp/db_2.sqlite");
    std::env::set_var("AETHERFLOW_DB_PATH", "/tmp/legacy_3.sqlite");
    std::env::set_var("DATA_DIR", "/tmp/data_4");

    let cands = candidate_cli_sqlite_dbs(&GlobalOptions::default());
    assert_eq!(
        &cands[..5],
        &[
            PathBuf::from("/tmp/af_1.sqlite"),
            PathBuf::from("/tmp/db_2.sqlite"),
            PathBuf::from("/tmp/legacy_3.sqlite"),
            PathBuf::from("/tmp/data_4/aetherflow.sqlite"),
            PathBuf::from("/var/lib/aetherflow/aetherflow.sqlite"),
        ]
    );

    let restore = |k: &str, v: Option<String>| match v {
        Some(val) => std::env::set_var(k, val),
        None => std::env::remove_var(k),
    };
    restore("AF_DB_PATH", prev_af);
    restore("DB_PATH", prev_db);
    restore("AETHERFLOW_DB_PATH", prev_legacy);
    restore("DATA_DIR", prev_data);
}

#[test]
fn legacy_receipt_parity_rejects_unsafe_locks_and_honors_custom_catalog_and_retained_ports() {
    let tmp = TempTestDir::new("legacy-receipt-parity");
    let root = tmp.path();
    let root_str = root.to_string_lossy().to_string();
    let transport = MockRunnerTransport::default();

    // 1. Retained SQLite ingress port takes precedence over stale legacy /etc/Swizzin lock port
    let swizzin_dir = root.join("etc/Swizzin");
    fs::create_dir_all(&swizzin_dir).unwrap();
    fs::write(swizzin_dir.join(".sonarr.lock"), b"PORT=18989\n").unwrap();
    let db_dir = root.join("var/lib/aetherflow");
    fs::create_dir_all(&db_dir).unwrap();
    let conn = Connection::open(db_dir.join("aetherflow.sqlite")).unwrap();
    conn.execute_batch(
        "CREATE TABLE app_ingress_configs (app_name TEXT PRIMARY KEY, listen_port INTEGER);
         CREATE TABLE retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT);
         INSERT INTO retained_app_ingress_configs (app_name, config_json)
         VALUES ('sonarr', '{\"app_name\":\"sonarr\",\"listen_port\":19111}');",
    )
    .unwrap();
    drop(conn);

    let install_inv = parse_cli_args(["--json", "--root", &root_str, "install", "sonarr"]).unwrap();
    let install_env = execute_invocation(&install_inv, &transport);
    assert_eq!(install_env.status, "ok", "{}", install_env.message);
    {
        let calls = transport.package_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].action, "reinstall");
        assert_eq!(calls[0].app_port, 19111);
    }

    // 2. Custom explicit catalog lock_file inside isolated root is honored without synthesizing /etc/Swizzin
    let cfg_dir = root.join("opt/AetherFlow/config");
    fs::create_dir_all(&cfg_dir).unwrap();
    fs::write(
        cfg_dir.join("packages.json"),
        serde_json::to_vec(&serde_json::json!([{
            "name": "sonarr",
            "label": "Sonarr",
            "description": "custom lock fixture",
            "category": "test",
            "lock_file": "/custom/locks/.sonarr.receipt",
            "service_type": "systemd",
            "service_name": "sonarr",
            "default_port": 8989
        }]))
        .unwrap(),
    )
    .unwrap();
    fs::write(cfg_dir.join("package_automation.json"), "{}").unwrap();
    let custom_info =
        parse_cli_args(["--json", "--root", &root_str, "package", "info", "sonarr"]).unwrap();
    let custom_env = execute_invocation(&custom_info, &transport);
    assert_eq!(custom_env.status, "ok", "{}", custom_env.message);
    let custom_data = custom_env.data.as_ref().unwrap();
    assert_eq!(custom_data["installed"], false);
    assert_eq!(custom_data["legacy_receipt_present"], false);
    assert_eq!(
        custom_data["lock_path"],
        root.join("custom/locks/.sonarr.receipt")
            .to_string_lossy()
            .as_ref()
    );
    fs::create_dir_all(root.join("custom/locks")).unwrap();
    fs::write(root.join("custom/locks/.sonarr.receipt"), b"installed\n").unwrap();
    let custom_installed_env = execute_invocation(&custom_info, &transport);
    assert_eq!(custom_installed_env.status, "ok");
    assert_eq!(
        custom_installed_env.data.as_ref().unwrap()["installed"],
        true
    );

    // 3. Unsafe lock types (symlink and directory) are rejected fail-closed
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        fs::remove_file(cfg_dir.join("packages.json")).unwrap();
        let outside = root.join("outside-target");
        fs::write(&outside, b"PORT=19999\n").unwrap();
        fs::remove_file(swizzin_dir.join(".sonarr.lock")).unwrap();
        symlink(&outside, swizzin_dir.join(".sonarr.lock")).unwrap();
        let sym_info = execute_invocation(&custom_info, &transport);
        assert_eq!(sym_info.status, "error");
        assert!(
            sym_info.message.contains("not a regular file"),
            "{}",
            sym_info.message
        );
        let sym_install = execute_invocation(&install_inv, &transport);
        assert_eq!(sym_install.status, "error");
        fs::remove_file(swizzin_dir.join(".sonarr.lock")).unwrap();

        fs::create_dir_all(root.join("install/.sonarr.lock")).unwrap();
        let dir_info = execute_invocation(&custom_info, &transport);
        assert_eq!(dir_info.status, "error");
        assert!(
            dir_info.message.contains("not a regular file"),
            "{}",
            dir_info.message
        );
    }
}

#[test]
fn cli_enforces_threadfin_pinned_and_pihole_vendor_exact_version_policies() {
    let tmp = TempTestDir::new("threadfin-pihole-policy");
    let root = tmp.path();
    let cfg_dir = root.join("opt/AetherFlow/config");
    fs::create_dir_all(&cfg_dir).unwrap();
    fs::write(
        cfg_dir.join("package_automation.json"),
        crate::EMBEDDED_PACKAGE_AUTOMATION_JSON,
    )
    .unwrap();
    let root_str = root.to_string_lossy().into_owned();
    let transport = MockRunnerTransport::default();

    let cached = root.join("var/lib/aetherflow/aetherflow.sqlite");
    fs::create_dir_all(cached.parent().unwrap()).unwrap();
    rusqlite::Connection::open(cached)
        .unwrap()
        .execute_batch(
            "CREATE TABLE app_updates (package_name TEXT, latest_version TEXT);
             INSERT INTO app_updates VALUES ('threadfin', '1.2.36');",
        )
        .unwrap();

    let inv_tf_default = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "package",
        "update",
        "threadfin",
    ])
    .unwrap();
    let env_tf_default = execute_invocation(&inv_tf_default, &transport);
    assert_eq!(env_tf_default.status, "ok", "{}", env_tf_default.message);
    {
        let calls = transport.package_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].package_id, "threadfin");
        assert_eq!(calls[0].expected_target_version.as_deref(), Some("1.2.37"));
    }

    // 2. Threadfin update with mismatched --target-version fails closed without calling runner
    let inv_tf_bad = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "package",
        "update",
        "threadfin",
        "--target-version",
        "1.2.36",
    ])
    .unwrap();
    let env_tf_bad = execute_invocation(&inv_tf_bad, &transport);
    assert_eq!(env_tf_bad.status, "error");
    assert!(
        env_tf_bad.message.contains("pinned to version 1.2.37"),
        "{}",
        env_tf_bad.message
    );
    assert_eq!(transport.package_calls.lock().unwrap().len(), 1);

    // 3. Pi-hole update (with or without --target-version) fails closed without calling runner
    for args in [
        vec!["--json", "--root", &root_str, "package", "update", "pihole"],
        vec![
            "--json",
            "--root",
            &root_str,
            "package",
            "update",
            "pihole",
            "--target-version",
            "6.9",
        ],
    ] {
        let inv = parse_cli_args(args).unwrap();
        let res = execute_invocation(&inv, &transport);
        assert_eq!(res.status, "error");
        assert!(res.message.contains("vendor installer"), "{}", res.message);
    }
    assert_eq!(transport.package_calls.lock().unwrap().len(), 1);

    // 4. Unpinned Pi-hole install succeeds cleanly
    let inv_ph_install = parse_cli_args([
        "--json", "--root", &root_str, "package", "install", "pihole",
    ])
    .unwrap();
    let env_ph_install = execute_invocation(&inv_ph_install, &transport);
    assert_eq!(env_ph_install.status, "ok", "{}", env_ph_install.message);
    {
        let calls = transport.package_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].package_id, "pihole");
        assert_eq!(calls[1].expected_target_version, None);
    }
}

#[test]
fn listenarr_cli_discovery_exact_target_and_early_arch_failure() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let valid_sha = "sha256:98ba3e01089554f632fa55f27bba4afe2393579061ca6aea9fb71658c72d2aac";
    let releases_body = serde_json::json!([
        {
            "tag_name": "v1.11.0-canary",
            "prerelease": true,
            "draft": true,
            "assets": [{
                "name": "listenarr-1.11.0-canary-linux-x64.zip",
                "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/v1.11.0-canary/listenarr-1.11.0-canary-linux-x64.zip",
                "digest": valid_sha
            }]
        },
        {
            "tag_name": "v1.10.6-canary",
            "prerelease": true,
            "draft": false,
            "assets": [{
                "name": "listenarr-1.10.6-canary-linux-x64.zip",
                "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-linux-x64.zip",
                "digest": valid_sha
            }]
        },
        {
            "tag_name": "0.2.71",
            "prerelease": true,
            "draft": false,
            "assets": [{
                "name": "listenarr-0.2.71-linux-x64.zip",
                "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/0.2.71/listenarr-0.2.71-linux-x64.zip",
                "digest": valid_sha
            }]
        }
    ])
    .to_string();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_body = releases_body.clone();
    let srv = std::thread::spawn(move || {
        for _ in 0..2 {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req_buf = [0u8; 4096];
                let n = stream.read(&mut req_buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&req_buf[..n]);
                assert!(
                    !req.contains("/tags"),
                    "Listenarr discovery must never fall back to unverified /tags: {req}"
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    srv_body.len(),
                    srv_body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        }
    });

    let api_base = format!("http://{addr}");
    // 1. x86_64 prerelease discovery selects v1.10.6-canary
    let discovered = discover_listenarr_github_target_for_arch(
        &api_base,
        "Listenarrs/Listenarr",
        "prerelease",
        "x86_64",
    )
    .expect("Listenarr x86_64 CLI discovery must succeed");
    assert_eq!(discovered, "1.10.6-canary");

    // 2. aarch64 fails early before touching network
    let arm_err = discover_listenarr_github_target_for_arch(
        "http://127.0.0.1:1",
        "Listenarrs/Listenarr",
        "prerelease",
        "aarch64",
    )
    .unwrap_err();
    assert!(
        arm_err.contains("arm64") && arm_err.contains("Linux x64"),
        "{arm_err}"
    );

    // 3. Zero linux-x64.zip assets fails cleanly without falling back to /tags
    let empty_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let empty_addr = empty_listener.local_addr().unwrap();
    let empty_srv = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = empty_listener.accept() {
            let mut req_buf = [0u8; 4096];
            let _ = stream.read(&mut req_buf);
            let body = "[]";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    let empty_err = discover_listenarr_github_target_for_arch(
        &format!("http://{empty_addr}"),
        "Listenarrs/Listenarr",
        "prerelease",
        "x86_64",
    )
    .unwrap_err();
    assert!(empty_err.contains("linux-x64.zip"), "{empty_err}");
    let _ = empty_srv.join();

    // 4. End-to-end CLI update dispatch with live discovery & exact --target-version
    let tmp = TempTestDir::new("listenarr-cli");
    let root = tmp.path();
    let root_str = root.to_string_lossy().into_owned();
    let cfg_dir = root.join("opt/AetherFlow/config");
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(root.join("install/.listenarr.lock"), "installed\n").unwrap();
    std::fs::write(
        cfg_dir.join("package_automation.json"),
        serde_json::json!({
            "listenarr": {
                "update_source": "github",
                "update_repo": "Listenarrs/Listenarr",
                "update_channel": "prerelease",
                "api_base_url": api_base,
                "require_download_sha256": true
            }
        })
        .to_string(),
    )
    .unwrap();

    let transport = MockRunnerTransport::default();

    // Auto-discovered update picks 1.10.6-canary
    let inv_auto = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "package",
        "update",
        "listenarr",
    ])
    .unwrap();
    let res_auto = execute_invocation(&inv_auto, &transport);
    assert_eq!(res_auto.status, "ok", "{}", res_auto.message);

    // Exact --target-version 1.10.5-canary dispatches cleanly
    let inv_exact = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "package",
        "update",
        "listenarr",
        "--target-version",
        "1.10.5-canary",
    ])
    .unwrap();
    let res_exact = execute_invocation(&inv_exact, &transport);
    assert_eq!(res_exact.status, "ok", "{}", res_exact.message);

    // Floating target token 'canary' fails closed at CLI parse/validation before calling runner
    let err_bad = parse_cli_args([
        "--json",
        "--root",
        &root_str,
        "package",
        "update",
        "listenarr",
        "--target-version",
        "canary",
    ])
    .unwrap_err();
    assert!(
        matches!(err_bad, CliError::Validation(ref msg) if msg.contains("canary")),
        "{err_bad:?}"
    );

    {
        let calls = transport.package_calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].package_id, "listenarr");
        assert_eq!(
            calls[0].expected_target_version.as_deref(),
            Some("1.10.6-canary")
        );
        assert_eq!(calls[1].package_id, "listenarr");
        assert_eq!(
            calls[1].expected_target_version.as_deref(),
            Some("1.10.5-canary")
        );
    }

    let _ = srv.join();
}

#[test]
fn test_cli_apt_exact_target_policy_parity() {
    let global = GlobalOptions::default();

    for (pkg, valid_ver) in [
        ("quassel", "1:0.14.0-1+deb12u1"),
        ("transmission", "4.0.6+dfsg-3+deb13u1"),
        ("wireguard", "1.0.20210914-1.1+b1"),
        ("jellyfin", "10.10.3+deb12"),
    ] {
        validate_cli_package_target_policy(&global, pkg, "install", Some(valid_ver))
            .unwrap_or_else(|e| {
                panic!("APT package {pkg} must accept exact Debian version {valid_ver}: {e:?}")
            });
        validate_cli_package_target_policy(&global, pkg, "install", None)
            .unwrap_or_else(|e| panic!("APT package {pkg} must allow unpinned install: {e:?}"));
    }

    for bad in ["v1.2.3", "latest", "1.2.*", "1.2_3", "deadbeef"] {
        assert!(
            validate_cli_package_target_policy(&global, "quassel", "update", Some(bad)).is_err(),
            "CLI APT policy must reject non-Debian token {bad:?}"
        );
    }

    let fixture = TempTestDir::new("cli-apt-target-embedded-catalog");
    let root = fixture.path().to_str().unwrap();
    for (target, status) in [("v1.27.7", "error"), ("1:1.27.7-4+deb13u1", "ok")] {
        let invocation = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            root,
            "package",
            "update",
            "syncthing",
            "--target-version",
            target,
        ])
        .unwrap();
        let response = execute_invocation(&invocation, &MockRunnerTransport::default());
        assert_eq!(response.status, status, "{}", response.message);
    }
}

#[test]
fn rclone_cli_reads_camel_case_retained_listen_port_and_forwards_secondary_port() {
    let tmp = TempTestDir::new("cli-rclone-ports");
    let db_path = tmp.path().join("var/lib/aetherflow/aetherflow.sqlite");
    fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    Connection::open(&db_path)
        .unwrap()
        .execute_batch(
            "CREATE TABLE app_ingress_configs (app_name TEXT PRIMARY KEY, listen_port INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL);
             INSERT INTO retained_app_ingress_configs VALUES ('rclone', '{\"appName\":\"rclone\",\"listenPort\":17572}');",
        )
        .unwrap();
    assert_eq!(
        query_persisted_ingress_port_from_sqlite(&db_path, "rclone"),
        Some(17572)
    );

    let saved_api_port = std::env::var_os("RCLONE_API_PORT");
    std::env::set_var("RCLONE_API_PORT", "17573");
    let ok_req = build_package_runner_request("install", "rclone", Some(17572)).unwrap();
    assert_eq!(ok_req.app_port, 17572);
    assert_eq!(ok_req.secondary_port, 17573);

    let remove_req = build_package_runner_request("remove", "rclone", None).unwrap();
    assert_eq!(remove_req.secondary_port, 0);

    let other_req = build_package_runner_request("install", "sonarr", Some(8989)).unwrap();
    assert_eq!(other_req.secondary_port, 0);

    std::env::set_var("RCLONE_API_PORT", "17572");
    assert!(build_package_runner_request("install", "rclone", Some(17572)).is_err());

    std::env::set_var("RCLONE_API_PORT", "not-a-port");
    assert!(build_package_runner_request("install", "rclone", Some(17572)).is_err());

    match saved_api_port {
        Some(val) => std::env::set_var("RCLONE_API_PORT", val),
        None => std::env::remove_var("RCLONE_API_PORT"),
    }
}

#[test]
fn update_target_resolution_rejects_installed_and_marker_fallbacks_and_discovers_live_upstream() {
    let root = std::env::temp_dir().join(format!(
        "af-cli-p3-target-res-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(root.join("var/lib/aetherflow")).unwrap();
    std::fs::create_dir_all(root.join("install")).unwrap();
    std::fs::create_dir_all(root.join("opt/sonarr")).unwrap();

    // Populate `.af-version` and lockfile VERSION markers — must NEVER be used as update targets!
    std::fs::write(root.join("opt/sonarr/.af-version"), "4.0.1.999\n").unwrap();
    std::fs::write(root.join("install/.sonarr.version"), "4.0.1.999\n").unwrap();
    std::fs::write(root.join("install/.sonarr.lock"), "VERSION=4.0.1.999\n").unwrap();

    // Populate `app_updates` with `installed_version` ONLY (`latest_version` empty) — must NEVER fall back to `installed_version`!
    let db_path = root.join("var/lib/aetherflow/aetherflow.sqlite");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE app_updates (
            package_name TEXT PRIMARY KEY,
            installed_version TEXT DEFAULT '',
            latest_version TEXT DEFAULT '',
            last_error TEXT DEFAULT ''
        );
        INSERT INTO app_updates (package_name, installed_version, latest_version, last_error)
        VALUES ('sonarr', '4.0.1.999', '', '');
        INSERT INTO app_updates (package_name, installed_version, latest_version, last_error)
        VALUES ('prowlarr', '1.20.0', '1.28.1.4900', '');
        INSERT INTO app_updates (package_name, installed_version, latest_version, last_error)
        VALUES ('radarr', '5.10.0', '5.12.0', 'HTTP 500 upstream failure');",
    )
    .unwrap();
    drop(conn);

    let root_str = root.to_string_lossy().to_string();
    let client = UnixSocketRunnerClient::new(Path::new("/nonexistent/af-runner.sock"));

    // 1. Offline & empty `latest_version` fails fast with actionable message (never 4.0.1.999 or 0.0.0)
    let inv_offline = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "update",
        "sonarr",
    ])
    .unwrap();
    let env_offline = execute_invocation(&inv_offline, &client);
    assert_eq!(env_offline.status, "error");
    assert!(
        env_offline.message.contains("--target-version"),
        "expected actionable --target-version guidance, got: {}",
        env_offline.message
    );

    // 2. Readarr without `--target-version` also fails fast instead of returning hardcoded 0.4.18.2805
    let inv_readarr = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "update",
        "readarr",
    ])
    .unwrap();
    let env_readarr = execute_invocation(&inv_readarr, &client);
    assert_eq!(env_readarr.status, "error");

    // 3. Valid `app_updates.latest_version` with empty `last_error` is used directly
    let inv_prowlarr = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "update",
        "prowlarr",
    ])
    .unwrap();
    let env_prowlarr = execute_invocation(&inv_prowlarr, &client);
    assert_eq!(env_prowlarr.status, "ok", "{}", env_prowlarr.message);
    assert_eq!(
        env_prowlarr.data.as_ref().unwrap()["request"]["expected_target_version"],
        "1.28.1.4900"
    );

    // 4. Stale `latest_version` accompanied by non-empty `last_error` is rejected when offline
    let inv_radarr = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "update",
        "radarr",
    ])
    .unwrap();
    let env_radarr = execute_invocation(&inv_radarr, &client);
    assert_eq!(env_radarr.status, "error");

    // 5. Explicit `--target-version` always succeeds when valid
    let inv_explicit = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "update",
        "sonarr",
        "--target-version",
        "4.0.11.2680",
    ])
    .unwrap();
    let env_explicit = execute_invocation(&inv_explicit, &client);
    assert_eq!(env_explicit.status, "ok", "{}", env_explicit.message);
    assert_eq!(
        env_explicit.data.as_ref().unwrap()["request"]["expected_target_version"],
        "4.0.11.2680"
    );

    // 6. Live upstream discovery resolves latest tag when `latest_version` is absent
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut req_buf = [0u8; 1024];
            let _ = stream.read(&mut req_buf);
            let body = r#"{"tag_name":"v4.0.12.2800"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    std::fs::create_dir_all(root.join("config")).unwrap();
    std::fs::write(
        root.join("config/package_automation.json"),
        serde_json::to_string(&json!({
            "sonarr": {
                "update_source": "github",
                "update_repo": "Sonarr/Sonarr",
                "api_base_url": format!("http://{}", addr)
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let inv_live = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "update",
        "sonarr",
    ])
    .unwrap();
    let env_live = execute_invocation(&inv_live, &client);
    server_handle.join().unwrap();
    assert_eq!(env_live.status, "ok", "{}", env_live.message);
    assert_eq!(
        env_live.data.as_ref().unwrap()["request"]["expected_target_version"],
        "4.0.12.2800"
    );

    let _ = std::fs::remove_dir_all(&root);
}
