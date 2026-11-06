use super::*;
use axum::body::{to_bytes, Body};
use axum::http::Request;
use std::os::unix::fs::PermissionsExt;
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_and_historical_update_diagnostics_never_reach_status_consumers() {
    let name = "routes::update_error_regressions::raw_and_historical_update_diagnostics_never_reach_status_consumers";
    if env::var("AF_UPDATE_ERROR_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_UPDATE_ERROR_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    let root = env::temp_dir().join(format!("ue-{}", &uuid::Uuid::new_v4().to_string()[..8]));
    fs::create_dir_all(root.join("install")).unwrap();
    fs::create_dir(root.join("bin")).unwrap();
    for key in [
        "AETHERFLOW_FS_ROOT",
        "AETHERFLOW_CONFIG_ROOT",
        "AETHERFLOW_RELEASE_ROOT",
    ] {
        env::set_var(key, &root);
    }
    let db = root.join("fixture.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db);
    }
    env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
    env::set_var("AETHERFLOW_PACKAGES_CONFIG", root.join("packages.json"));
    env::set_var(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        root.join("automation.json"),
    );
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );
    let command = root.join("bin/systemctl");
    fs::write(&command, "#!/bin/sh\ntest \"$1\" = show || exit 99\nprintf 'ActiveState=active\\nSubState=running\\n'\n").unwrap();
    fs::set_permissions(&command, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(root.join("install/.fixture.lock"), "installed").unwrap();
    fs::write(root.join("packages.json"), r#"[{"name":"fixture","label":"Fixture","description":"isolated fixture","category":"test","service_type":"systemd","service_name":"fixture","lock_file":"/install/.fixture.lock"}]"#).unwrap();
    fs::write(root.join("automation.json"), r#"{"fixture":{"update_source":"command","version_command":["/bin/sh","-c","printf 'SYNTHETIC_PRIVATE_DIAGNOSTIC /etc/private/config' >&2; exit 27"]}}"#).unwrap();
    af_db::init_db().unwrap();
    af_services::initialize_package_jobs(rusqlite::Connection::open(&db).unwrap()).unwrap();
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users(id,username,role) VALUES(1,'status-viewer','user')",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO app_updates(package_name,installed_version,latest_version,update_available,last_error) VALUES('fixture','1.0','1.1',1,'SYNTHETIC_PRIVATE_DIAGNOSTIC /etc/private/config')", []).unwrap();
    drop(conn);
    let (token, _) = crate::auth::create_standard_jwt(1, &HeaderMap::new()).unwrap();
    let router = build_router();
    for path in ["/api/v1/public/marketplace", "/api/v1/auth/services"] {
        let mut request = Request::builder().uri(path);
        if path.contains("/auth/") {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            !text.contains("SYNTHETIC_PRIVATE_DIAGNOSTIC"),
            "{path}: {text}"
        );
        assert!(!text.contains("/etc/private/config"), "{path}: {text}");
        assert!(
            text.contains("Update status could not be confirmed"),
            "{path}: {text}"
        );
    }
    let record = af_services::workers::refresh_package_update_by_id("fixture")
        .await
        .unwrap();
    assert_eq!(
        record.error,
        "Installed version could not be confirmed; Latest version could not be confirmed"
    );
    let persisted: String = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT last_error FROM app_updates WHERE package_name='fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(persisted, record.error);
    let response = build_single_package_update_response(
        "fixture",
        Some(af_services::workers::PackageUpdateRecord {
            error: "SYNTHETIC_PRIVATE_DIAGNOSTIC".into(),
            ..record
        }),
    );
    assert_eq!(
        response["last_error"],
        "Update status could not be confirmed"
    );
    assert!(!response
        .to_string()
        .contains("SYNTHETIC_PRIVATE_DIAGNOSTIC"));
    fs::remove_dir_all(root).unwrap();
}
