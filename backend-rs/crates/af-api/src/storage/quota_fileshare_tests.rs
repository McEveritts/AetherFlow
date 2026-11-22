use super::fileshare::{delete_shared_file, download_file, get_files_list};
use super::quotas::{
    get_own_quota, list_user_quota_records_conn, list_user_quotas, parse_human_size,
};
use crate::auth::AuthUser;
use axum::body::Body;
use axum::extract::{Path, Query};
use axum::http::{Request, StatusCode};
use std::collections::HashMap;
use std::env;
use std::fs;

#[tokio::test]
async fn fileshare_reads_do_not_create_upload_directories() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let root = env::temp_dir().join(format!("af-fileshare-read-{}", uuid::Uuid::new_v4()));
    env::set_var("AETHERFLOW_UPLOAD_DIR", &root);
    let query = || Query(HashMap::from([("path".into(), "missing/nested".into())]));
    let listing = get_files_list(query()).await;
    assert_eq!(listing.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(listing.into_body(), 4096)
            .await
            .unwrap()
            .as_ref(),
        b"[]"
    );
    assert_eq!(
        download_file(Path("missing.txt".into()), query())
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(!root.exists());
    fs::create_dir(&root).unwrap();
    assert_eq!(get_files_list(query()).await.status(), StatusCode::OK);
    assert!(!root.join("missing").exists());
    fs::remove_dir(root).unwrap();
}

#[test]
fn parse_human_size_rejects_overflowing_values() {
    assert_eq!(parse_human_size("1024B").unwrap(), 1024);
    assert_eq!(parse_human_size("2GB").unwrap(), 2 * 1024 * 1024 * 1024);
    assert!(parse_human_size("999999999999PB").is_err());
}

#[tokio::test]
async fn list_user_quotas_returns_internal_error_instead_of_empty_list_on_db_failure() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    // Unit-level SQLite error propagation check.
    let broken = rusqlite::Connection::open_in_memory().unwrap();
    assert!(list_user_quota_records_conn(&broken).is_err());

    // Handler-level HTTP 500 regression check.
    crate::plugins::tests::ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch("DROP TABLE user_quotas;").unwrap();
    }
    let resp = list_user_quotas().await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn get_own_quota_maps_missing_user_to_not_found_and_db_failure_to_internal_error() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    crate::plugins::tests::ensure_shared_test_db();
    let make_req = |user_id: i64| {
        let mut req = Request::builder()
            .uri("/api/v1/auth/user/quota")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(AuthUser {
            user_id,
            username: format!("user-{user_id}"),
            role: "user".to_string(),
            jti: "jti".to_string(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        });
        req
    };

    // Non-existent user maps to 404 NOT_FOUND.
    let missing_resp = get_own_quota(make_req(999_123)).await;
    assert_eq!(missing_resp.status(), StatusCode::NOT_FOUND);

    // Existing user with a broken user_quotas table must return 500 INTERNAL_ERROR, not 404.
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users(id, username, role) VALUES (701, 'quota-err-user', 'user')",
            [],
        )
        .unwrap();
        conn.execute_batch("DROP TABLE user_quotas;").unwrap();
    }
    let broken_resp = get_own_quota(make_req(701)).await;
    assert_eq!(broken_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn delete_shared_file_returns_internal_error_on_db_failure_and_bad_request_on_missing_file() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    crate::plugins::tests::ensure_shared_test_db();
    let root = env::temp_dir().join(format!("af-fileshare-del-err-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    env::set_var("AETHERFLOW_UPLOAD_DIR", &root);

    // Missing file returns 400 BAD_REQUEST.
    let missing = delete_shared_file(Path("missing.txt".into()), Query(HashMap::new())).await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

    // Existing file with broken SQLite ledger returns 500 INTERNAL_ERROR.
    fs::write(root.join("present.txt"), b"hello").unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch("DROP TABLE fileshare_objects;").unwrap();
    }
    let db_err = delete_shared_file(Path("present.txt".into()), Query(HashMap::new())).await;
    assert_eq!(db_err.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let _ = fs::remove_dir_all(&root);
}
