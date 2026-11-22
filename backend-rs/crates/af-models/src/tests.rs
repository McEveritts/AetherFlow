use super::*;
use std::collections::HashMap;

#[test]
fn package_automation_merge_preserves_all_policy_fields() {
    let automation = PackageAutomation {
        update_source: "apt".into(),
        require_download_sha256: true,
        update_repo: "owner/repo".into(),
        update_repo_url: "https://example.test".into(),
        update_package: "package".into(),
        update_channel: "nightly".into(),
        version_command: vec!["probe".into()],
        version_regex: "pattern".into(),
        sandbox_profile: "strict".into(),
        sandbox_read_write: vec!["/var/lib/pkg".into()],
        sandbox_service_ids: vec!["pkg.service".into()],
    };
    let mut package = Package {
        name: "pkg".into(),
        ..Default::default()
    };
    merge_package_automation(&mut package, &automation);
    let merged: PackageAutomation =
        serde_json::from_value(serde_json::to_value(&package).unwrap()).unwrap();
    assert_eq!(merged, automation);
    assert_eq!(package.name, "pkg");
}

#[test]
fn test_system_metrics_wire_format() {
    let mut mem = HashMap::new();
    mem.insert("total".to_string(), 32.0);
    mem.insert("used".to_string(), 8.5);
    let metrics = SystemMetrics {
        cpu_usage: 14.2,
        per_core_cpu: vec![12.0, 16.4],
        cpu_freq_mhz: 3600.0,
        memory: mem,
        uptime: "4d 2h 15m".to_string(),
        load_average: vec![0.42, 0.38, 0.31],
        gpus: vec![GpuMetric {
            index: 0,
            name: "NVIDIA RTX 4090".to_string(),
            usage_pct: 45.0,
            memory_total: 24576.0,
            memory_used: 4096.0,
            temp: 58.0,
        }],
        ..Default::default()
    };

    let json = serde_json::to_value(&metrics).unwrap();
    assert_eq!(json["cpu_usage"], 14.2);
    assert_eq!(json["gpus"][0]["name"], "NVIDIA RTX 4090");
    assert_eq!(json["gpus"][0]["usage_pct"], 45.0);
}

#[test]
fn test_user_wire_format_omits_google_id() {
    let user_item = User {
        id: 1,
        username: "admin".to_string(),
        email: "admin@aether.local".to_string(),
        avatar_url: "".to_string(),
        role: "admin".to_string(),
        google_id: "secret-google-sub".to_string(),
        is_oauth: true,
        totp_enabled: false,
    };
    let serialized = serde_json::to_string(&user_item).unwrap();
    assert!(!serialized.contains("secret-google-sub"));
    assert!(serialized.contains("\"is_oauth\":true"));
}

#[test]
fn test_unified_db_backup_and_lock_path_resolution() {
    let mut env = HashMap::new();
    env.insert(
        "DB_PATH".to_string(),
        "/srv/custom/legacy.sqlite".to_string(),
    );
    let db = try_resolve_active_db_path_with_env(None, "data/aetherflow.sqlite", |key| {
        env.get(key).cloned()
    })
    .unwrap();
    assert_eq!(db, std::path::PathBuf::from("/srv/custom/legacy.sqlite"));

    let backup_dir = resolve_active_backup_dir_with_env(None, Some(&db), "data/backups", |key| {
        env.get(key).cloned()
    });
    assert_eq!(backup_dir, std::path::PathBuf::from("/srv/custom/backups"));

    let lock_path = resolve_canonical_maintenance_lock_path_with_env(
        None,
        Some(&db),
        Some(&backup_dir),
        |key| env.get(key).cloned(),
    );
    assert_eq!(
        lock_path,
        std::path::PathBuf::from("/srv/custom/.snapshot.lock")
    );

    env.insert("AF_DB_PATH".to_string(), "/srv/other/db.sqlite".to_string());
    let conflict = try_resolve_active_db_path_with_env(None, "data/aetherflow.sqlite", |key| {
        env.get(key).cloned()
    });
    assert!(conflict.is_err());

    env.insert(
        "AF_DB_PATH".to_string(),
        "/srv/custom/legacy.sqlite".to_string(),
    );
    let resolved_same =
        try_resolve_active_db_path_with_env(None, "data/aetherflow.sqlite", |key| {
            env.get(key).cloned()
        })
        .unwrap();
    assert_eq!(
        resolved_same,
        std::path::PathBuf::from("/srv/custom/legacy.sqlite")
    );
}

#[test]
fn test_isolated_root_rejects_out_of_root_db_backup_and_lock_overrides() {
    let iso_root = std::path::Path::new("/tmp/af-iso-root");
    let mut env = HashMap::new();
    env.insert(
        "AETHERFLOW_DB_PATH".to_string(),
        "/var/lib/aetherflow/host.sqlite".to_string(),
    );
    let out_of_root_db =
        try_resolve_active_db_path_with_env(Some(iso_root), "data/aetherflow.sqlite", |key| {
            env.get(key).cloned()
        });
    assert!(out_of_root_db.is_err());

    env.insert(
        "AETHERFLOW_DB_PATH".to_string(),
        "/tmp/af-iso-root/custom/inside.sqlite".to_string(),
    );
    let inside_db =
        try_resolve_active_db_path_with_env(Some(iso_root), "data/aetherflow.sqlite", |key| {
            env.get(key).cloned()
        })
        .unwrap();
    assert_eq!(
        inside_db,
        std::path::PathBuf::from("/tmp/af-iso-root/custom/inside.sqlite")
    );

    env.insert(
        "AETHERFLOW_BACKUP_DIR".to_string(),
        "/var/lib/aetherflow/backups".to_string(),
    );
    let out_of_root_backup = try_resolve_active_backup_dir_with_env(
        Some(iso_root),
        Some(&inside_db),
        "data/backups",
        |key| env.get(key).cloned(),
    );
    assert!(out_of_root_backup.is_err());

    env.remove("AETHERFLOW_BACKUP_DIR");
    env.insert(
        "AETHERFLOW_MAINTENANCE_LOCK_PATH".to_string(),
        "/tmp/.snapshot.lock".to_string(),
    );
    let out_of_root_lock = try_resolve_canonical_maintenance_lock_path_with_env(
        Some(iso_root),
        Some(&inside_db),
        None,
        |key| env.get(key).cloned(),
    );
    assert!(out_of_root_lock.is_err());
}

#[test]
fn test_resolve_contained_sqlite_restore_override() {
    let custom_db = std::path::Path::new("/srv/af/live.sqlite");
    assert_eq!(
        resolve_contained_sqlite_restore_override(std::path::Path::new("/srv/af"), Some(custom_db)),
        Some(std::path::PathBuf::from("/srv/af/live.sqlite"))
    );
    assert_eq!(
        resolve_contained_sqlite_restore_override(std::path::Path::new("/"), Some(custom_db)),
        Some(std::path::PathBuf::from("/srv/af/live.sqlite"))
    );
    assert_eq!(
        resolve_contained_sqlite_restore_override(
            std::path::Path::new("/var/tmp/unrelated-staging"),
            Some(custom_db)
        ),
        None
    );
}

#[test]
fn test_self_update_job_status_invariants() {
    let valid_unit = "aetherflow-self-update-0123456789abcdef0123456789abcdef.service";
    let ok_running = SelfUpdateJobStatus {
        status: "running".to_string(),
        completed: false,
        success: false,
        job_unit: valid_unit.to_string(),
        error: String::new(),
        exit_code: None,
    };
    assert!(ok_running.validate_invariants(Some(valid_unit)).is_ok());
    assert!(ok_running
        .validate_invariants(Some(
            "aetherflow-self-update-fedcba9876543210fedcba9876543210.service"
        ))
        .is_err());

    let bad_completed = SelfUpdateJobStatus {
        status: "running".to_string(),
        completed: true,
        success: true,
        job_unit: valid_unit.to_string(),
        error: String::new(),
        exit_code: Some(0),
    };
    assert!(bad_completed.validate_invariants(Some(valid_unit)).is_err());

    let bad_failed_zero = SelfUpdateJobStatus {
        status: "failed".to_string(),
        completed: true,
        success: false,
        job_unit: valid_unit.to_string(),
        error: "boom".to_string(),
        exit_code: Some(0),
    };
    assert!(bad_failed_zero
        .validate_invariants(Some(valid_unit))
        .is_err());
}

#[test]
fn test_derive_sqlite_target_rel_path() {
    assert_eq!(
        derive_sqlite_target_rel_path(
            std::path::Path::new("/tmp/restore-root"),
            std::path::Path::new("/tmp/restore-root/custom/legacy.sqlite")
        ),
        Some("custom/legacy.sqlite".to_string())
    );
    assert_eq!(
        derive_sqlite_target_rel_path(
            std::path::Path::new("/"),
            std::path::Path::new("/opt/AetherFlow/data/aetherflow.sqlite")
        ),
        Some("opt/AetherFlow/data/aetherflow.sqlite".to_string())
    );
}

#[test]
fn test_marketplace_tls_false_is_explicit_on_wire() {
    let app = MarketplaceApp {
        tls_enabled: false,
        ..Default::default()
    };
    let value = serde_json::to_value(app).unwrap();
    assert_eq!(value["tls_enabled"], false);
    assert_eq!(value["external_access_enabled"], false);
}

#[test]
fn test_package_lifecycle_and_inventory_models() {
    let app = MarketplaceApp {
        inventory_known: true,
        ..Default::default()
    };
    let val = serde_json::to_value(&app).unwrap();
    assert_eq!(val["inventory_known"], true);
    assert!(val.get("retained_data_present").is_none());

    let retained_app = MarketplaceApp {
        inventory_known: true,
        inventory_authenticated: true,
        retained_data_present: true,
        ..Default::default()
    };
    let retained_val = serde_json::to_value(&retained_app).unwrap();
    assert_eq!(retained_val["retained_data_present"], true);

    let req = PackageRunnerRequest {
        action: "update".to_string(),
        package_id: "radarr".to_string(),
        script_name: "installpackage-radarr".to_string(),
        expected_target_version: Some("5.3.6.8612".to_string()),
        achieved_version: Some("5.3.6.8612".to_string()),
        ..Default::default()
    };
    let req_json = serde_json::to_string(&req).unwrap();
    assert!(req_json.contains("expected_target_version"));
    let parsed: PackageRunnerRequest = serde_json::from_str(&req_json).unwrap();
    assert_eq!(
        parsed.expected_target_version.as_deref(),
        Some("5.3.6.8612")
    );
    assert_eq!(parsed.achieved_version.as_deref(), Some("5.3.6.8612"));

    let rec = PackageLifecycleRecord {
        package_id: "radarr".to_string(),
        job_id: "job-1".to_string(),
        action: "update".to_string(),
        status: "failed".to_string(),
        started_at: "2026-11-08T12:00:00Z".to_string(),
        failed_stage: Some("target_verification".to_string()),
        exit_code: Some(1),
        sanitized_summary: Some("verification mismatch".to_string()),
        expected_target_version: Some("5.3.6".to_string()),
        achieved_version: Some("5.3.5".to_string()),
        ..Default::default()
    };
    let rec_json = serde_json::to_string(&rec).unwrap();
    let parsed_rec: PackageLifecycleRecord = serde_json::from_str(&rec_json).unwrap();
    assert_eq!(
        parsed_rec.failed_stage.as_deref(),
        Some("target_verification")
    );
    assert_eq!(parsed_rec.exit_code, Some(1));

    let vhost_req = RunnerApacheVhostRequest {
        app_name: "sonarr".to_string(),
        listen_port: 8989,
        internal_domain: Some("sonarr.aether.local".to_string()),
        public_domain: Some("sonarr.example.com".to_string()),
        external_access_enabled: true,
        tls_enabled: true,
        reload_apache: true,
        ..Default::default()
    };
    let vhost_json = serde_json::to_string(&vhost_req).unwrap();
    let parsed: RunnerApacheVhostRequest = serde_json::from_str(&vhost_json).unwrap();
    assert_eq!(parsed, vhost_req);
    assert!(serde_json::from_str::<RunnerApacheVhostRequest>(
        r#"{"app_name":"sonarr","vhost_content":"arbitrary Apache configuration"}"#
    )
    .is_err());
}

#[test]
fn test_plugin_runner_ipc_models_reject_unknown_fields_and_redact_tokens() {
    assert!(is_valid_plugin_id("telemetry-inspector"));
    assert!(!is_valid_plugin_id("../escape"));
    assert!(!is_valid_plugin_id("a"));
    assert_eq!(
        plugin_systemd_unit_name("telemetry-inspector").as_deref(),
        Some("aetherflow-plugin-telemetry-inspector.service")
    );
    assert_eq!(
        plugin_stop_hook_unit_name("telemetry-inspector").as_deref(),
        Some("aetherflow-plugin-telemetry-inspector-stop.service")
    );
    assert!(plugin_systemd_unit_name("../bad").is_none());

    // Reject arbitrary caller-supplied executable/path fields (`deny_unknown_fields`).
    assert!(serde_json::from_str::<PluginRunnerStartRequest>(
        r#"{"plugin_id":"demo","port":21000,"runtime_id":"00000000-0000-0000-0000-000000000000","api_base_url":"http://127.0.0.1:8080","initial_token":"t","executable":"/bin/sh"}"#
    )
    .is_err());
    assert!(serde_json::from_str::<PluginRunnerStopRequest>(
        r#"{"plugin_id":"demo","hook_path":"/tmp/evil.sh"}"#
    )
    .is_err());

    let start = PluginRunnerStartRequest {
        plugin_id: "demo".into(),
        port: 21000,
        runtime_id: "00000000-0000-0000-0000-000000000000".into(),
        api_base_url: "http://127.0.0.1:8080".into(),
        initial_token: "secret-start-token".into(),
    };
    let dbg = format!("{start:?}");
    assert!(!dbg.contains("secret-start-token"));
    assert!(dbg.contains("[REDACTED]"));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn test_resolve_plugins_dir_covers_source_packaged_and_isolated_roots() {
    let base = std::env::temp_dir().join(format!(
        "af-models-plugins-resolve-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&base);

    // 1. Explicit AETHERFLOW_PLUGINS_DIR always wins.
    let explicit = base.join("custom-plugins");
    assert_eq!(
        resolve_plugins_dir_from(Some(explicit.to_str().unwrap()), None, None, None),
        Some(explicit)
    );

    // 2. Packaged release executable resolves sibling plugins/ regardless of CWD.
    let release_slot = base.join("opt/AetherFlow/releases/1700000001");
    let release_plugins = release_slot.join("plugins");
    std::fs::create_dir_all(release_plugins.join("telemetry-inspector")).unwrap();
    let release_exe = release_slot.join("aetherflow-api");
    std::fs::write(&release_exe, b"bin").unwrap();
    let unrelated_cwd = base.join("unrelated-cwd");
    std::fs::create_dir_all(&unrelated_cwd).unwrap();
    assert_eq!(
        resolve_plugins_dir_from(None, None, Some(&release_exe), Some(&unrelated_cwd)),
        Some(release_plugins)
    );

    // 3. Source build (cargo target exe has no sibling plugins/) resolves CWD-relative plugins/.
    let repo = base.join("repo");
    let repo_plugins = repo.join("plugins");
    let target_dir = repo.join("backend-rs/target/release");
    std::fs::create_dir_all(repo_plugins.join("telemetry-inspector")).unwrap();
    std::fs::create_dir_all(&target_dir).unwrap();
    let dev_exe = target_dir.join("aetherflow-api");
    std::fs::write(&dev_exe, b"bin").unwrap();
    assert_eq!(
        resolve_plugins_dir_from(None, None, Some(&dev_exe), Some(&repo)),
        Some(repo.join("plugins"))
    );
    assert_eq!(
        resolve_plugins_dir_from(None, None, Some(&dev_exe), Some(&repo.join("backend-rs"))),
        Some(repo.join("backend-rs").join("../plugins"))
    );

    // 4. Isolated AETHERFLOW_FS_ROOT checks <root>/plugins, <root>/opt/AetherFlow/current/plugins,
    //    and <root>/opt/AetherFlow/plugins before falling back.
    let fs_root_packaged = base.join("fs-packaged");
    let fs_current_plugins = fs_root_packaged.join("opt/AetherFlow/current/plugins");
    std::fs::create_dir_all(&fs_current_plugins).unwrap();
    assert_eq!(
        resolve_plugins_dir_from(
            None,
            Some(fs_root_packaged.to_str().unwrap()),
            Some(&dev_exe),
            Some(&unrelated_cwd),
        ),
        Some(fs_current_plugins)
    );

    let fs_root_flat = base.join("fs-flat");
    let fs_flat_plugins = fs_root_flat.join("plugins");
    std::fs::create_dir_all(&fs_flat_plugins).unwrap();
    assert_eq!(
        resolve_plugins_dir_from(
            None,
            Some(fs_root_flat.to_str().unwrap()),
            Some(&release_exe),
            Some(&unrelated_cwd),
        ),
        Some(fs_flat_plugins)
    );

    let fs_root_empty = base.join("fs-empty");
    std::fs::create_dir_all(&fs_root_empty).unwrap();
    assert_eq!(
        resolve_plugins_dir_from(
            None,
            Some(fs_root_empty.to_str().unwrap()),
            Some(&release_exe),
            Some(&repo),
        ),
        None
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(release_slot.join("plugins"), fs_root_empty.join("plugins"))
            .unwrap();
        assert_eq!(
            resolve_plugins_dir_from(None, Some(fs_root_empty.to_str().unwrap()), None, None),
            None
        );
    }

    let _ = std::fs::remove_dir_all(&base);
}
