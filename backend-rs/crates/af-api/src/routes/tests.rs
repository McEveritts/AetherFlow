use super::*;

pub(super) fn assert_proxy_document_policy(response: &axum::response::Response) {
    use axum::http::header;

    let policies = response.headers().get_all(header::CONTENT_SECURITY_POLICY);
    assert_eq!(policies.iter().count(), 1);
    assert_eq!(
        policies.iter().next().unwrap(),
        "sandbox; default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    );
    assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
    let cache_policies = response.headers().get_all(header::CACHE_CONTROL);
    assert_eq!(cache_policies.iter().count(), 1);
    assert_eq!(cache_policies.iter().next().unwrap(), "private, no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert_eq!(response.headers()[header::EXPIRES], "0");
    for name in [
        "surrogate-control",
        "cdn-cache-control",
        "cloudflare-cdn-cache-control",
    ] {
        assert!(!response.headers().contains_key(name), "{name}");
    }
}

pub(super) fn control_req(action: &str, managed_by: &str, process: &str) -> ServiceControlReq {
    ServiceControlReq {
        action: action.to_string(),
        managed_by: managed_by.to_string(),
        process: process.to_string(),
    }
}

pub(super) fn lifecycle_status_fixture() -> (std::path::PathBuf, rusqlite::Connection) {
    let root = std::env::temp_dir().join(format!("af-api-status-{}", uuid::Uuid::new_v4()));
    let path = root.join("backend/data/aetherflow.sqlite");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    std::env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
    std::env::set_var("DB_PATH", &path);
    af_services::initialize_package_jobs(rusqlite::Connection::open(&path).unwrap()).unwrap();
    (root, rusqlite::Connection::open(path).unwrap())
}

pub(super) fn progress_test_user(role: &str, plugin: Option<&str>) -> AuthUser {
    AuthUser {
        user_id: 1,
        username: "progress-fixture".into(),
        role: role.into(),
        jti: "progress-fixture".into(),
        plugin_id: plugin.map(str::to_owned),
        plugin_scopes: plugin
            .map(|_| vec!["telemetry:read".into()])
            .unwrap_or_default(),
    }
}

pub(super) fn short_test_socket_path(filename: &str) -> std::path::PathBuf {
    if let Some(tmpdir) = std::env::var_os("TMPDIR") {
        if !tmpdir.is_empty() {
            let candidate = std::path::PathBuf::from(tmpdir).join(filename);
            if candidate.as_os_str().len() < 95 {
                return candidate;
            }
        }
    }
    let candidate = std::env::temp_dir().join(filename);
    if candidate.as_os_str().len() < 95 {
        candidate
    } else {
        std::path::PathBuf::from("/tmp").join(filename)
    }
}

pub(super) static RECEIPT_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod marketplace_catalog;
mod marketplace_lifecycle;
mod marketplace_policies;
mod receipt_snapshots;
mod rollback_quiesce;
mod security_and_account;
mod service_control_and_ingress;
mod sqlite_error_regressions;
