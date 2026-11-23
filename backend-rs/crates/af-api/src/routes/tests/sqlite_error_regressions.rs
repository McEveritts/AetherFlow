use super::*;
use axum::extract::{Extension, Path, Query};

#[tokio::test]
async fn route_handlers_report_sqlite_failures_instead_of_returning_empty_ok() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};

    if run_plugin_test_in_subprocess() {
        return;
    }

    let admin = AuthUser {
        user_id: 942,
        username: "sqlite-regression-admin".into(),
        role: "admin".into(),
        jti: String::new(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let default_page = || PageQuery {
        limit: 50,
        offset: 0,
        action: String::new(),
        username: String::new(),
    };

    // Phase 1: DB uninitialized -> every DB-backed endpoint must return 5xx, never 200 OK or 404.
    assert_eq!(
        get_notifications(Extension(admin.clone()), Query(default_page()))
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_notification_rules().await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_notification_channels().await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_audit_log(Query(default_page())).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_ingress_configs(Extension(admin.clone())).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_blueprints(Extension(admin.clone())).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_app_blueprint(Extension(admin.clone()), Path("sonarr".into()))
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        handle_streaming_demo(
            Extension(admin.clone()),
            HeaderMap::new(),
            Json(DemoReq {
                action: "clear".into(),
            }),
        )
        .await
        .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        reject_action(Path(1), Extension(admin.clone()), HeaderMap::new())
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );

    // Phase 2: DB initialized -> happy paths return 200 OK (and missing action returns 404).
    ensure_shared_test_db();
    af_db::get_conn()
        .unwrap()
        .execute(
            "INSERT OR IGNORE INTO users(id, username, role, password_hash) VALUES(942, 'sqlite-regression-admin', 'admin', '')",
            [],
        )
        .unwrap();

    assert_eq!(
        get_notifications(Extension(admin.clone()), Query(default_page()))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(get_notification_rules().await.status(), StatusCode::OK);
    assert_eq!(get_notification_channels().await.status(), StatusCode::OK);
    assert_eq!(
        get_audit_log(Query(default_page())).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        get_ingress_configs(Extension(admin.clone())).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        get_blueprints(Extension(admin.clone())).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        get_app_blueprint(
            Extension(admin.clone()),
            Path("nonexistent-blueprint-fixture".into())
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        handle_streaming_demo(
            Extension(admin.clone()),
            HeaderMap::new(),
            Json(DemoReq {
                action: "clear".into(),
            }),
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        reject_action(Path(999_999), Extension(admin.clone()), HeaderMap::new())
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(get_settings_for_role("admin").status(), StatusCode::OK);

    // Phase 3: Break tables / inject corrupt column values -> query failures must return 5xx,
    // never silently degrade to 200 OK with empty arrays or default payloads or false 404.
    af_db::invalidate_ingress_cache();
    af_db::get_conn()
        .unwrap()
        .execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TABLE notifications;
             DROP TABLE notification_rules;
             DROP TABLE notification_channels;
             DROP TABLE admin_audit_log;
             DROP TABLE app_ingress_configs;
             DROP TABLE pending_actions;
             DROP TABLE settings;",
        )
        .unwrap();

    assert_eq!(
        get_notifications(Extension(admin.clone()), Query(default_page()))
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_notification_rules().await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_notification_channels().await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_audit_log(Query(default_page())).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_ingress_configs(Extension(admin.clone())).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_blueprints(Extension(admin.clone())).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_app_blueprint(Extension(admin.clone()), Path("sonarr".into()))
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_settings_for_role("admin").status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        update_settings(
            Extension(admin.clone()),
            None,
            Json(SettingsPayload {
                ai_model: "gemini-4-argon".into(),
                language: "en".into(),
                timezone: "UTC".into(),
                update_channel: "stable".into(),
                default_dashboard: "overview".into(),
                ..SettingsPayload::default()
            }),
        )
        .await
        .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        reject_action(Path(1), Extension(admin.clone()), HeaderMap::new())
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );

    // Corrupt users table to ensure update_password_blocking distinguishes SQLite error from 404.
    af_db::get_conn()
        .unwrap()
        .execute_batch("PRAGMA foreign_keys = OFF; DROP TABLE users;")
        .unwrap();
    assert_eq!(
        update_password_blocking(
            admin,
            HeaderMap::new(),
            ChangePasswordReq {
                current_password: "old-password".into(),
                new_password: "new-password-123".into(),
            },
        )
        .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn marketplace_catalog_reports_sqlite_ingress_failure_for_authenticated_users() {
    use crate::plugins::tests::run_plugin_test_in_subprocess;

    if run_plugin_test_in_subprocess() {
        return;
    }

    let (root, _conn) = lifecycle_status_fixture();
    let catalog = root.join("packages.json");
    std::fs::write(
        &catalog,
        r#"[{"name":"radarr","label":"Radarr","description":"Movies","category":"media","service_type":"systemd","service_name":"radarr","default_port":7878,"lock_file":"/install/.radarr.lock"}]"#,
    )
    .unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    af_db::init_db().unwrap();
    af_db::get_conn()
        .unwrap()
        .execute(
            "INSERT INTO users(id, username, role) VALUES(1, 'mp-admin', 'admin')",
            [],
        )
        .unwrap();
    let (token, _) = crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        axum::http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );

    // Works normally when app_ingress_configs exists.
    assert_eq!(
        get_marketplace_apps_blocking(headers.clone(), true).status(),
        StatusCode::OK
    );

    // Corrupt package_lifecycle_history row so `retained_lifecycle_packages()` errors:
    // authenticated marketplace must return 500 DATABASE_ERROR instead of swallowing via unwrap_or_default.
    af_db::get_conn()
        .unwrap()
        .execute(
            "INSERT INTO package_lifecycle_history \
             (package_id, job_id, action, status, started_at, finished_at) \
             VALUES (?1, 'corrupt-job', 'uninstall', 'completed', '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z')",
            rusqlite::params![vec![0xffu8, 0x00u8, 0xfeu8]],
        )
        .unwrap();
    assert_eq!(
        get_marketplace_apps_blocking(headers.clone(), true).status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    af_db::get_conn()
        .unwrap()
        .execute(
            "DELETE FROM package_lifecycle_history WHERE job_id = 'corrupt-job'",
            [],
        )
        .unwrap();
    assert_eq!(
        get_marketplace_apps_blocking(headers.clone(), true).status(),
        StatusCode::OK
    );

    // Drop app_ingress_configs and invalidate cache -> authenticated marketplace must return 500
    // and get_active_services() must return Err (so get_services returns 503).
    af_db::invalidate_ingress_cache();
    af_db::get_conn()
        .unwrap()
        .execute_batch("DROP TABLE app_ingress_configs;")
        .unwrap();
    let response = get_marketplace_apps_blocking(headers, true);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(af_services::get_active_services().is_err());

    let _ = std::fs::remove_dir_all(&root);
}
