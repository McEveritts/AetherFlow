use super::backups::{get_optimal_backup_window, set_backup_schedule};
use super::deploy::{
    af_common, allocate_or_verify_deploy_port,
    deploy_sse_session_still_authorized_for_peer_with_conn, deployment_ingress_config,
    ensure_or_reuse_deploy_stream, handle_deploy_stream, is_terminal_deploy_event,
    load_mediaflow_initial_snapshot_conn, publish_deploy_json_event,
    release_deploy_stream_if_matching, DEPLOY_STREAMS,
};
use super::deploy_rollback::{
    finalize_failed_deploy_rollback, is_transmission_deploy_unit, read_deploy_snapshot,
    rollback_deploy_files, rollback_deploy_files_inner, snapshot_deploy_files, DeployFileSnapshot,
    DeploySnapshotPrior, DeployStage,
};
use crate::auth::AuthUser;
use axum::extract::Query;
use axum::http::{header, StatusCode};
use axum::response::Json;
use chrono::{Duration, Utc};
use rusqlite::params;
use std::collections::HashMap;
use std::fs;
#[cfg(unix)]
use std::path::{Path as StdPath, PathBuf};

#[cfg(unix)]
fn short_test_socket_path(dir: &StdPath, prefix: &str) -> PathBuf {
    let candidate = dir.join("runner.sock");
    if candidate.as_os_str().len() < 95 {
        candidate
    } else {
        PathBuf::from("/tmp").join(format!(
            "{prefix}-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        ))
    }
}

#[test]
fn deployment_ingress_uses_canonical_schema_and_private_defaults() {
    let config = deployment_ingress_config("jellyfin", 18096, None);
    assert_eq!(config.app_name, "jellyfin");
    assert_eq!(config.listen_port, 18096);
    assert!(config.public_domain.is_empty());
    assert!(!config.external_access_enabled);
    assert!(!config.tls_enabled);
    let serialized = serde_json::to_value(config).unwrap();
    for obsolete in ["port", "domain", "bind_ip"] {
        assert!(serialized.get(obsolete).is_none());
    }
}

#[test]
fn deployment_ingress_preserves_existing_exposure_and_creation_time() {
    let created_at = Utc::now() - Duration::days(1);
    let existing = af_models::AppIngressConfig {
        app_name: "jellyfin".to_string(),
        public_domain: "media.example.test".to_string(),
        listen_port: 8096,
        external_access_enabled: true,
        tls_enabled: true,
        created_at,
        updated_at: created_at,
    };
    let config = deployment_ingress_config("jellyfin", 18096, Some(existing));
    assert_eq!(config.listen_port, 18096);
    assert_eq!(config.public_domain, "media.example.test");
    assert!(config.external_access_enabled && config.tls_enabled);
    assert_eq!(config.created_at, created_at);
    assert!(config.updated_at > created_at);
}

#[tokio::test]
async fn test_handle_deploy_stream_requires_admin_and_redacts_secrets() {
    let non_admin = AuthUser {
        user_id: 2,
        username: "viewer".to_string(),
        role: "user".to_string(),
        jti: "test-jti".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let mut q = HashMap::new();
    q.insert("appName".to_string(), "radarr".to_string());
    let resp = handle_deploy_stream(axum::Extension(non_admin), None, Query(q)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let redacted = af_common::redact::redact_secrets(
        "Restart failed with token=supersecretvalue123 and password: hiddenpass",
    );
    assert!(!redacted.contains("supersecretvalue123"));
    assert!(!redacted.contains("hiddenpass"));
    assert!(redacted.contains("[REDACTED]"));

    assert!(is_terminal_deploy_event("[SUCCESS] done"));
    assert!(is_terminal_deploy_event("[ROLLBACK] reverted"));
    assert!(is_terminal_deploy_event("[ERROR] failed"));
    assert!(is_terminal_deploy_event(
        r#"{"status":"completed","progress":100,"message":"done"}"#
    ));
    assert!(is_terminal_deploy_event(
        r#"{"status":"failed","progress":100,"message":"err"}"#
    ));
    assert!(is_terminal_deploy_event(
        r#"{"status":"done","progress":100}"#
    ));
    assert!(!is_terminal_deploy_event(
        r#"{"status":"running","progress":50}"#
    ));
}

fn ensure_test_admin_user_for_stream() {
    crate::plugins::tests::ensure_shared_test_db();
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin')",
        [],
    )
    .expect("insert the isolated stream test administrator");
}

#[tokio::test]
async fn test_mediaflow_engine_deploy_stream_returns_200_json_sse_and_closes_on_completion() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    ensure_test_admin_user_for_stream();
    let app_name = format!("mediaflow-test-{}", uuid::Uuid::new_v4());
    let sender = ensure_or_reuse_deploy_stream(&app_name).unwrap();
    publish_deploy_json_event(
        &app_name,
        &sender,
        &serde_json::json!({
            "status": "running",
            "progress": 25,
            "message": "Scanning library",
        }),
    );

    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: String::new(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let mut q = HashMap::new();
    q.insert("appName".to_string(), app_name.clone());
    let resp = handle_deploy_stream(axum::Extension(admin), None, Query(q)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/event-stream");

    let sender_for_finish = sender.clone();
    let app_for_finish = app_name.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        publish_deploy_json_event(
            &app_for_finish,
            &sender_for_finish,
            &serde_json::json!({
                "status": "completed",
                "progress": 100,
                "message": "Scan complete",
            }),
        );
    });

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains(r#""status":"running""#), "body={text}");
    assert!(text.contains(r#""status":"completed""#), "body={text}");

    release_deploy_stream_if_matching(&app_name, &sender);
    assert!(!DEPLOY_STREAMS.lock().unwrap().contains_key(&app_name));
}

#[tokio::test]
async fn test_mediaflow_engine_progress_stream_subscribes_worker_broadcasts_and_handles_lag() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    ensure_test_admin_user_for_stream();
    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: String::new(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let mut q = HashMap::new();
    q.insert("appName".to_string(), "mediaflow_engine".to_string());
    let resp = handle_deploy_stream(axum::Extension(admin), None, Query(q)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/event-stream");

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // Overflow the 256-slot broadcast buffer so subscriber experiences RecvError::Lagged
        for i in 0..300 {
            af_services::publish_mediaflow_progress(&serde_json::json!({
                "status": "running",
                "progress": i % 99,
                "message": format!("Tick {i}"),
            }));
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        af_services::publish_mediaflow_progress(&serde_json::json!({
            "status": "completed",
            "progress": 100,
            "message": "Worker transcode done",
        }));
    });

    let body = axum::body::to_bytes(resp.into_body(), 262_144)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains(r#""status":"#), "body={text}");
    assert!(
        text.contains(r#""status":"completed""#),
        "stream must survive lag and deliver completion: body={text}"
    );
}

#[test]
fn test_allocate_or_verify_deploy_port_respects_portless_and_fixed_port_blueprints() {
    let fail2ban = af_services::get_blueprint("fail2ban").expect("fail2ban blueprint");
    assert_eq!(fail2ban.default_port, 0);
    assert!(!fail2ban.supports_dynamic_port);
    assert_eq!(allocate_or_verify_deploy_port(&fail2ban), 0);

    let plex = af_services::get_blueprint("plex").expect("plex blueprint");
    assert_eq!(plex.default_port, 32400);
    assert!(!plex.supports_dynamic_port);
    assert_eq!(allocate_or_verify_deploy_port(&plex), 32400);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_deploy_rollback_reloads_apache_transmission_lifecycle_and_smart_backup_window() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let _db_env_guard = crate::streaming_ext::tests::TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tmp_dir = std::env::temp_dir().join(format!("af-storage-p4-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp_dir).unwrap();
    let db_file = tmp_dir.join("storage_p4.sqlite");
    let keys = ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"];
    let saved: Vec<(&str, Option<std::ffi::OsString>)> =
        keys.iter().map(|&k| (k, std::env::var_os(k))).collect();
    for &k in &keys {
        std::env::set_var(k, &db_file);
    }
    af_db::init_db().unwrap();

    // 1. Smart Backup with <24 samples returns heuristic_default (confidence=0.35, optimal_hour=3)
    let win_resp = get_optimal_backup_window().await;
    let win_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(win_resp.into_body(), 64 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(win_body["optimal_window"]["source"], "heuristic_default");
    assert_eq!(win_body["optimal_window"]["optimal_hour"], 3);
    assert_eq!(win_body["optimal_window"]["confidence"], 0.35);

    // Seed >=24 samples across 24 UTC hours with lowest load at 04:00 UTC
    {
        let conn = af_db::get_conn().unwrap();
        for h in 0..24 {
            let (cpu, mem_used) = if h == 4 { (3.0, 1.5) } else { (72.0, 13.0) };
            conn.execute(
                "INSERT INTO metrics_history (timestamp, cpu_avg, mem_used_gb, mem_total_gb) VALUES (?1, ?2, ?3, 16.0)",
                params![format!("2026-11-19T{h:02}:20:00Z"), cpu, mem_used],
            )
            .unwrap();
        }
    }

    let sched_resp = set_backup_schedule(Json(serde_json::json!({ "mode": "smart" }))).await;
    assert_eq!(sched_resp.status(), StatusCode::OK);
    let sched_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(sched_resp.into_body(), 64 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(sched_body["optimal_window"]["source"], "metrics_history");
    assert_eq!(sched_body["optimal_window"]["optimal_hour"], 4);
    use chrono::Timelike;
    let next_str = sched_body["next_backup_at"].as_str().unwrap();
    let next_dt = chrono::DateTime::parse_from_rfc3339(next_str)
        .unwrap()
        .with_timezone(&Utc);
    assert_eq!(next_dt.hour(), 4);
    assert_eq!(next_dt.minute(), 0);
    assert_eq!(next_dt.second(), 0);
    assert!(next_dt >= Utc::now() + chrono::Duration::minutes(55));

    // 2. Transmission safe deploy guard
    assert!(is_transmission_deploy_unit(
        "transmission",
        "transmission-daemon"
    ));
    assert!(!is_transmission_deploy_unit("sonarr", "sonarr"));

    // 3. Apache vhost rollback invokes runner_systemctl("reload", "apache2")
    #[cfg(unix)]
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let sock_path = short_test_socket_path(&tmp_dir, "af-deploy-p4");
        let prev_sock = std::env::var_os("AETHERFLOW_RUNNER_SOCK");
        let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
        let cfg_root = tmp_dir.join("cfg_root");
        let vhost_dir = cfg_root.join("etc/apache2/sites-enabled");
        fs::create_dir_all(&vhost_dir).unwrap();
        std::env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
        std::env::set_var("AETHERFLOW_CONFIG_ROOT", &cfg_root);

        let (reload_tx, mut reload_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
        let srv = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut req_buf = vec![0u8; 4096];
                let n = stream.read(&mut req_buf).await.unwrap_or(0);
                let _ = reload_tx.send(String::from_utf8_lossy(&req_buf[..n]).into_owned());
                let body = r#"{"success":true,"output":"reloaded","error":""}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });

        let vhost_file = vhost_dir.join("aetherflow-app-overseerr.conf");
        let snaps = vec![DeployFileSnapshot {
            path: vhost_file.clone(),
            prior: DeploySnapshotPrior::RegularFile {
                bytes: b"<VirtualHost *:80>prior</VirtualHost>\n".to_vec(),
                mode: 0o644,
            },
        }];
        fs::write(&vhost_file, b"<VirtualHost *:80>broken</VirtualHost>\n").unwrap();

        assert!(rollback_deploy_files(&snaps).await);
        assert_eq!(
            fs::read(&vhost_file).unwrap(),
            b"<VirtualHost *:80>prior</VirtualHost>\n"
        );
        let received = tokio::time::timeout(std::time::Duration::from_secs(3), reload_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(received.contains("POST /v1/systemctl"));
        assert!(received.contains(r#""action":"reload""#));
        assert!(received.contains(r#""service":"apache2""#));
        srv.abort();
        let _ = fs::remove_file(&sock_path);

        match prev_sock {
            Some(v) => std::env::set_var("AETHERFLOW_RUNNER_SOCK", v),
            None => std::env::remove_var("AETHERFLOW_RUNNER_SOCK"),
        }
        match prev_cfg_root {
            Some(v) => std::env::set_var("AETHERFLOW_CONFIG_ROOT", v),
            None => std::env::remove_var("AETHERFLOW_CONFIG_ROOT"),
        }
    }

    for (k, val) in saved {
        match val {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    let _ = fs::remove_dir_all(&tmp_dir);
}

#[cfg(unix)]
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_deploy_snapshot_distinguishes_absent_from_eacces_and_preserves_unreadable_files() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let _db_env_guard = crate::streaming_ext::tests::TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tmp_dir = std::env::temp_dir().join(format!("af-deploy-l02-snap-{}", uuid::Uuid::new_v4()));
    let cfg_root = tmp_dir.join("cfg_root");
    let app_dir = cfg_root.join("var/lib/sonarr");
    let avail_dir = cfg_root.join("etc/apache2/sites-available");
    let enabled_dir = cfg_root.join("etc/apache2/sites-enabled");
    fs::create_dir_all(&app_dir).unwrap();
    fs::create_dir_all(&avail_dir).unwrap();
    fs::create_dir_all(&enabled_dir).unwrap();

    let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
    std::env::set_var("AETHERFLOW_CONFIG_ROOT", &cfg_root);

    let absent_path = avail_dir.join("aetherflow-app-sonarr.conf");
    let secret_unreadable_path = app_dir.join("config.xml");
    let creds_path = app_dir.join("credentials.xml");
    let symlink_path = enabled_dir.join("aetherflow-app-sonarr.conf");

    fs::write(
        &secret_unreadable_path,
        b"<Config><ApiKey>top-secret</ApiKey></Config>\n",
    )
    .unwrap();
    fs::set_permissions(&secret_unreadable_path, fs::Permissions::from_mode(0o000)).unwrap();

    fs::write(
        &creds_path,
        b"<Config><Port>8989</Port><ApiKey>keep</ApiKey></Config>\n",
    )
    .unwrap();
    fs::set_permissions(&creds_path, fs::Permissions::from_mode(0o600)).unwrap();

    std::os::unix::fs::symlink(
        "../sites-available/aetherflow-app-sonarr.conf",
        &symlink_path,
    )
    .unwrap();

    // Snapshot before deploy: absent vs EACCES vs regular 0600 vs symlink.
    assert_eq!(
        read_deploy_snapshot(&absent_path),
        DeploySnapshotPrior::ConfirmedAbsent
    );
    let unreadable_snap = read_deploy_snapshot(&secret_unreadable_path);
    assert!(
        matches!(unreadable_snap, DeploySnapshotPrior::Unreadable { .. }),
        "EACCES file must be Unreadable, got {unreadable_snap:?}"
    );
    assert_eq!(
        read_deploy_snapshot(&creds_path),
        DeploySnapshotPrior::RegularFile {
            bytes: b"<Config><Port>8989</Port><ApiKey>keep</ApiKey></Config>\n".to_vec(),
            mode: 0o600,
        }
    );
    assert_eq!(
        read_deploy_snapshot(&symlink_path),
        DeploySnapshotPrior::Symlink {
            target: std::path::PathBuf::from("../sites-available/aetherflow-app-sonarr.conf"),
        }
    );

    let snaps = vec![
        DeployFileSnapshot {
            path: absent_path.clone(),
            prior: read_deploy_snapshot(&absent_path),
        },
        DeployFileSnapshot {
            path: secret_unreadable_path.clone(),
            prior: unreadable_snap,
        },
        DeployFileSnapshot {
            path: creds_path.clone(),
            prior: read_deploy_snapshot(&creds_path),
        },
        DeployFileSnapshot {
            path: symlink_path.clone(),
            prior: read_deploy_snapshot(&symlink_path),
        },
    ];

    // Simulate deploy mutating files: creating the previously absent vhost, overwriting creds,
    // replacing symlink with regular file.
    fs::write(&absent_path, b"<VirtualHost *:80>new</VirtualHost>\n").unwrap();
    fs::write(&creds_path, b"<Config><Port>18989</Port></Config>\n").unwrap();
    fs::remove_file(&symlink_path).unwrap();
    fs::write(&symlink_path, b"<VirtualHost *:80>wrong</VirtualHost>\n").unwrap();

    // Rollback when host mutation happened must preserve the unreadable 0600/0000 file,
    // remove the newly created ConfirmedAbsent file, restore 0600 credentials and symlink,
    // and truthfully report incomplete rollback for the unreadable file.
    let report = rollback_deploy_files_inner(&snaps, None, None, Some(18989), true, false).await;
    assert!(
        !report.fully_reverted,
        "unreadable pre-deploy file must prevent claiming clean rollback"
    );
    assert!(
        report
            .unrestored_paths
            .iter()
            .any(|p| p == &secret_unreadable_path.display().to_string()),
        "unreadable path must be reported: {:?}",
        report.unrestored_paths
    );

    // Critical: unreadable file was NEVER deleted despite writable parent dir!
    assert!(secret_unreadable_path.exists());
    fs::set_permissions(&secret_unreadable_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        fs::read(&secret_unreadable_path).unwrap(),
        b"<Config><ApiKey>top-secret</ApiKey></Config>\n"
    );

    // ConfirmedAbsent file was removed, 0600 credentials & symlink restored.
    assert!(!absent_path.exists());
    assert_eq!(
        fs::read(&creds_path).unwrap(),
        b"<Config><Port>8989</Port><ApiKey>keep</ApiKey></Config>\n"
    );
    assert_eq!(
        fs::metadata(&creds_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(fs::symlink_metadata(&symlink_path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read_link(&symlink_path).unwrap(),
        std::path::PathBuf::from("../sites-available/aetherflow-app-sonarr.conf")
    );

    // Pre-mutation failure (e.g. STEP 1 DNS error) leaves unreadable snapshot untouched and clean.
    fs::set_permissions(&secret_unreadable_path, fs::Permissions::from_mode(0o000)).unwrap();
    let pre_mut_report = rollback_deploy_files_inner(&snaps, None, None, None, false, false).await;
    assert!(pre_mut_report.fully_reverted);
    fs::set_permissions(&secret_unreadable_path, fs::Permissions::from_mode(0o600)).unwrap();

    match prev_cfg_root {
        Some(v) => std::env::set_var("AETHERFLOW_CONFIG_ROOT", v),
        None => std::env::remove_var("AETHERFLOW_CONFIG_ROOT"),
    }
    let _ = fs::remove_dir_all(&tmp_dir);
}

#[cfg(unix)]
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_deploy_rollback_surfaces_write_failures_and_keeps_ingress_consistent() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _db_env_guard = crate::streaming_ext::tests::TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tmp_dir = std::env::temp_dir().join(format!("af-deploy-l02-ing-{}", uuid::Uuid::new_v4()));
    let cfg_root = tmp_dir.join("cfg_root");
    let vhost_dir = cfg_root.join("etc/apache2/sites-available");
    let sonarr_dir = cfg_root.join("var/lib/sonarr");
    fs::create_dir_all(&vhost_dir).unwrap();
    fs::create_dir_all(&sonarr_dir).unwrap();

    let db_file = tmp_dir.join("deploy_l02.sqlite");
    let keys = ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"];
    let saved: Vec<(&str, Option<std::ffi::OsString>)> =
        keys.iter().map(|&k| (k, std::env::var_os(k))).collect();
    for &k in &keys {
        std::env::set_var(k, &db_file);
    }
    af_db::init_db().unwrap();

    let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
    let prev_sock = std::env::var_os("AETHERFLOW_RUNNER_SOCK");
    std::env::set_var("AETHERFLOW_CONFIG_ROOT", &cfg_root);
    let missing_sock = tmp_dir.join("missing-runner.sock");
    std::env::set_var("AETHERFLOW_RUNNER_SOCK", &missing_sock);

    let bp = af_services::get_blueprint("sonarr").expect("sonarr blueprint");
    let prior_ingress = af_models::AppIngressConfig {
        app_name: "sonarr".to_string(),
        listen_port: 8989,
        public_domain: "sonarr.example.test".to_string(),
        external_access_enabled: false,
        tls_enabled: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    af_db::set_app_ingress_config(&prior_ingress).unwrap();

    let vhost_file = vhost_dir.join("aetherflow-app-sonarr.conf");
    let cfg_file = sonarr_dir.join("config.xml");
    fs::write(&vhost_file, b"<VirtualHost *:80>8989</VirtualHost>\n").unwrap();
    fs::write(&cfg_file, b"<Config><Port>8989</Port></Config>\n").unwrap();
    let snaps = snapshot_deploy_files(&bp);

    // Simulate STEP 2 writing port 18989 and STEP 3 persisting 18989 to SQLite, then
    // make parent directory read-only (0o555) so rollback write_atomic_nofollow_mode fails (EACCES).
    fs::write(&vhost_file, b"<VirtualHost *:80>18989</VirtualHost>\n").unwrap();
    fs::write(&cfg_file, b"<Config><Port>18989</Port></Config>\n").unwrap();
    let new_ingress = deployment_ingress_config("sonarr", 18989, Some(prior_ingress.clone()));
    af_db::set_app_ingress_config(&new_ingress).unwrap();

    fs::set_permissions(&vhost_dir, fs::Permissions::from_mode(0o555)).unwrap();
    fs::set_permissions(&sonarr_dir, fs::Permissions::from_mode(0o555)).unwrap();

    // Direct rollback_deploy_files must return false (NOT ignore EACCES or mark apache_restored).
    assert!(!rollback_deploy_files(&snaps).await);

    let report = finalize_failed_deploy_rollback(
        &bp,
        "sonarr",
        false,
        DeployStage::IngressPersisted { target_port: 18989 },
        Some(&prior_ingress),
        &snaps,
    )
    .await;
    assert!(!report.fully_reverted);
    assert!(!report.apache_restored);
    assert!(report
        .unrestored_paths
        .iter()
        .any(|p| p == &vhost_file.display().to_string()));
    assert!(report
        .unrestored_paths
        .iter()
        .any(|p| p == &cfg_file.display().to_string()));
    // SQLite ingress MUST remain at 18989 to match un-reverted disk state!
    assert_eq!(
        af_db::get_app_ingress_config("sonarr")
            .unwrap()
            .unwrap()
            .listen_port,
        18989
    );

    // Also verify transmission_stopped=true does NOT start transmission-daemon when rollback fails.
    let tx_report = finalize_failed_deploy_rollback(
        &bp,
        "transmission-daemon",
        true,
        DeployStage::IngressPersisted { target_port: 18989 },
        Some(&prior_ingress),
        &snaps,
    )
    .await;
    assert!(!tx_report.fully_reverted);
    assert!(tx_report.errors.iter().any(|e| {
        e.contains("was not restarted because configuration rollback did not complete")
    }));

    // Restore directory permissions; now verify apache reload failure still marks fully_reverted=false
    // and keeps SQLite at 18989, whereas successful reload reverts SQLite to 8989.
    fs::set_permissions(&vhost_dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&sonarr_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let sock_path = short_test_socket_path(&tmp_dir, "af-deploy-ing");
    std::env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);
    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    let srv = tokio::spawn(async move {
        // 1st request: fail apache2 reload; 2nd request: succeed apache2 reload.
        for success in [false, true] {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut req_buf = vec![0u8; 4096];
                let _ = stream.read(&mut req_buf).await;
                let body = if success {
                    r#"{"success":true,"output":"reloaded","error":""}"#
                } else {
                    r#"{"success":false,"output":"","error":"apache2 reload failed"}"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        }
    });

    let fail_reload_report = finalize_failed_deploy_rollback(
        &bp,
        "sonarr",
        false,
        DeployStage::IngressPersisted { target_port: 18989 },
        Some(&prior_ingress),
        &snaps,
    )
    .await;
    assert!(!fail_reload_report.fully_reverted);
    assert_eq!(
        af_db::get_app_ingress_config("sonarr")
            .unwrap()
            .unwrap()
            .listen_port,
        18989
    );

    // Re-mutate files and run successful rollback + apache2 reload -> SQLite reverts to 8989!
    fs::write(&vhost_file, b"<VirtualHost *:80>18989</VirtualHost>\n").unwrap();
    fs::write(&cfg_file, b"<Config><Port>18989</Port></Config>\n").unwrap();
    let ok_report = finalize_failed_deploy_rollback(
        &bp,
        "sonarr",
        false,
        DeployStage::IngressPersisted { target_port: 18989 },
        Some(&prior_ingress),
        &snaps,
    )
    .await;
    assert!(ok_report.fully_reverted, "errors={:?}", ok_report.errors);
    assert_eq!(
        af_db::get_app_ingress_config("sonarr")
            .unwrap()
            .unwrap()
            .listen_port,
        8989
    );
    assert_eq!(
        fs::read(&cfg_file).unwrap(),
        b"<Config><Port>8989</Port></Config>\n"
    );
    srv.abort();
    let _ = fs::remove_file(&sock_path);

    match prev_sock {
        Some(v) => std::env::set_var("AETHERFLOW_RUNNER_SOCK", v),
        None => std::env::remove_var("AETHERFLOW_RUNNER_SOCK"),
    }
    match prev_cfg_root {
        Some(v) => std::env::set_var("AETHERFLOW_CONFIG_ROOT", v),
        None => std::env::remove_var("AETHERFLOW_CONFIG_ROOT"),
    }
    for (k, val) in saved {
        match val {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    let _ = fs::remove_dir_all(&tmp_dir);
}

#[cfg(unix)]
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn test_deploy_rollback_systemd_unit_reverts_and_reports_unprivileged_daemon_reload() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let _db_env_guard = crate::streaming_ext::tests::TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tmp_dir = std::env::temp_dir().join(format!("af-deploy-l02-unit-{}", uuid::Uuid::new_v4()));
    let cfg_root = tmp_dir.join("cfg_root");
    let unit_dir = cfg_root.join("etc/systemd/system");
    fs::create_dir_all(&unit_dir).unwrap();

    let prev_cfg_root = std::env::var_os("AETHERFLOW_CONFIG_ROOT");
    std::env::set_var("AETHERFLOW_CONFIG_ROOT", &cfg_root);

    let bp = af_services::get_blueprint("listenarr").expect("listenarr blueprint");
    let unit_path = unit_dir.join("listenarr.service");
    let prior_unit = b"[Service]\nEnvironment=ASPNETCORE_URLS=http://127.0.0.1:5050\n";
    fs::write(&unit_path, prior_unit).unwrap();

    let snaps = snapshot_deploy_files(&bp);
    fs::write(
        &unit_path,
        b"[Service]\nEnvironment=ASPNETCORE_URLS=http://127.0.0.1:15050\n",
    )
    .unwrap();

    // In fixture mode (is_real_host=false), unit file is reverted without calling host systemctl.
    let fixture_report =
        rollback_deploy_files_inner(&snaps, Some(&bp), None, Some(15050), true, false).await;
    assert!(fixture_report.fully_reverted);
    assert!(fixture_report.systemd_unit_restored);
    assert_eq!(fs::read(&unit_path).unwrap(), prior_unit);

    // When simulating real-host non-root execution without runner /v1/blueprint/apply fallback,
    // reverting a .service unit must surface the missing daemon-reload integration gap.
    if unsafe { libc::geteuid() } != 0 {
        fs::write(
            &unit_path,
            b"[Service]\nEnvironment=ASPNETCORE_URLS=http://127.0.0.1:15050\n",
        )
        .unwrap();
        let real_host_report =
            rollback_deploy_files_inner(&snaps, Some(&bp), None, Some(15050), true, true).await;
        assert!(real_host_report.systemd_unit_restored);
        assert!(!real_host_report.fully_reverted);
        assert!(real_host_report
            .errors
            .iter()
            .any(|e| e.contains("systemctl daemon-reload")));
    }

    match prev_cfg_root {
        Some(v) => std::env::set_var("AETHERFLOW_CONFIG_ROOT", v),
        None => std::env::remove_var("AETHERFLOW_CONFIG_ROOT"),
    }
    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn deploy_sse_session_authorization_fails_closed_on_sqlite_table_check_error() {
    let tmp_dir =
        std::env::temp_dir().join(format!("af-deploy-sse-corrupt-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp_dir).unwrap();
    let corrupt_path = tmp_dir.join("corrupt.sqlite");
    fs::write(&corrupt_path, b"not-a-valid-sqlite-database-header").unwrap();

    let conn = rusqlite::Connection::open(&corrupt_path).unwrap();
    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "live-jti".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    assert!(
        !deploy_sse_session_still_authorized_for_peer_with_conn(&conn, &admin, None, None),
        "SQLite error checking users table must fail closed instead of authorizing SSE"
    );

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn mediaflow_initial_snapshot_propagates_sqlite_errors_and_reports_empty_as_none() {
    let mem = rusqlite::Connection::open_in_memory().unwrap();
    mem.execute_batch(
        "CREATE TABLE mediaflow_queue (id INTEGER PRIMARY KEY, file_path TEXT, status TEXT, updated_at TEXT);",
    )
    .unwrap();
    assert_eq!(load_mediaflow_initial_snapshot_conn(&mem).unwrap(), None);

    mem.execute(
        "INSERT INTO mediaflow_queue (file_path, status, updated_at) VALUES ('/media/movie.mkv', 'APPROVED', '2026-11-22T00:00:00Z')",
        [],
    )
    .unwrap();
    let approved = load_mediaflow_initial_snapshot_conn(&mem)
        .unwrap()
        .expect("queued snapshot");
    assert!(approved.contains("/media/movie.mkv"));
    assert!(approved.contains("Transcode job queued"));

    let broken = rusqlite::Connection::open_in_memory().unwrap();
    assert!(load_mediaflow_initial_snapshot_conn(&broken).is_err());
}
