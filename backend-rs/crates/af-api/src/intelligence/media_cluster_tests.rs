use super::mediaflow::{
    approve_mediaflow_item, decline_mediaflow_item, get_mediaflow_queue, is_mediaflow_extension,
    MEDIAFLOW_SCAN_CURSORS,
};
use super::metadata::{metadata_results, upsert_media_metadata_row};
use super::scan_cursor::{
    commit_auto_continuing_scan, prepare_auto_continuing_scan, run_auto_continuing_scan,
    MAX_SCAN_DEPTH, MAX_SCAN_FILES,
};
use super::telemetry::{
    analyze_predictions, filter_log_entries, get_auth_metrics_history, get_bookmarks,
    get_metrics_history, get_predictions, topology_from_inventory,
};
use crate::auth::AuthUser;
use axum::extract::{Path, Query, Request};
use axum::http::StatusCode;
use rusqlite::params;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

#[test]
fn topology_uses_inventory_status_and_one_gateway() {
    let mut items = HashMap::new();
    for (name, id, status) in [
        ("Apache2 Web Server", "apache2", "running"),
        ("AetherFlow API", "aetherflow-api", "running"),
        ("Privileged runner", "aetherflow-runner", "running"),
        ("Jellyfin", "jellyfin", "running"),
        ("Other", "other", "unknown"),
    ] {
        items.insert(
            name.to_string(),
            af_services::ServiceStatusItem {
                id: id.into(),
                status: status.into(),
                external_access_enabled: id == "jellyfin",
                public_domain: if id == "jellyfin" {
                    "media.example.test".into()
                } else {
                    String::new()
                },
                ..Default::default()
            },
        );
    }
    let topology = topology_from_inventory(items, false, true);
    let nodes = topology["nodes"].as_array().unwrap();
    let runners: Vec<_> = nodes
        .iter()
        .filter(|n| n["service_id"] == "aetherflow-runner")
        .collect();
    assert_eq!(runners.len(), 1);
    assert_eq!(runners[0]["id"], "Privileged runner");
    assert_eq!(runners[0]["status"], "unknown");
    assert!(topology["links"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l["target"] == "Privileged runner"));
    assert!(nodes
        .iter()
        .any(|n| n["id"] == "SQLite WAL" && n["status"] == "running"));
    assert!(nodes
        .iter()
        .any(|n| n["id"] == "Jellyfin" && n["status"] == "running"));
    assert!(nodes
        .iter()
        .any(|n| n["id"] == "Other" && n["status"] == "unknown"));
    assert!(!topology["links"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l["target"] == "Other"));
    assert!(!nodes.iter().any(|n| n["id"] == "Redis Cache"));
    assert_eq!(nodes.iter().filter(|n| n["group"] == 3).count(), 1);
    assert!(topology["links"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l["source"] == "Apache2 Web Server" && l["target"] == "Jellyfin"));
}

#[test]
fn test_filter_log_entries_preserves_journald_unit_lines_with_different_syslog_identifier() {
    let raw = vec![
        serde_json::json!({
            "timestamp": "2026-11-02T12:00:00Z",
            "source": "journald",
            "service": "node",
            "level": "INFO",
            "message": "Server listening on 127.0.0.1:6246",
        }),
        serde_json::json!({
            "timestamp": "2026-11-02T12:00:01Z",
            "source": "journald",
            "service": "hass",
            "level": "ERROR",
            "message": "Home Assistant core error",
        }),
        serde_json::json!({
            "timestamp": "2026-11-02T12:00:02Z",
            "source": "file",
            "service": "nginx-error",
            "level": "ERROR",
            "message": "upstream timed out",
        }),
        serde_json::json!({
            "timestamp": "2026-11-02T12:00:03Z",
            "source": "file",
            "service": "af-api",
            "level": "INFO",
            "message": "af-maintainerr proxy healthy",
        }),
    ];

    let filtered = filter_log_entries(raw.clone(), "af-maintainerr.service", "", "", 0, 50);
    assert_eq!(filtered.len(), 3);
    assert_eq!(filtered[0]["service"], "node");
    assert_eq!(filtered[1]["service"], "hass");
    assert_eq!(filtered[2]["service"], "af-api");

    let error_only = filter_log_entries(raw, "homeassistant.service", "ERROR", "core", 0, 50);
    assert_eq!(error_only.len(), 1);
    assert_eq!(error_only[0]["service"], "hass");
}

#[test]
fn test_media_scan_10001_files_reports_partial_cursor_and_resumes_to_completion() {
    let tmp = std::env::temp_dir().join(format!("af-scan-10001-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(tmp.join("Season_01")).unwrap();
    std::fs::create_dir_all(tmp.join("Season_02")).unwrap();

    for idx in 0..5_000usize {
        std::fs::write(
            tmp.join("Season_01").join(format!("ep_{:05}.mkv", idx)),
            b"",
        )
        .unwrap();
    }
    for idx in 5_000..10_001usize {
        std::fs::write(
            tmp.join("Season_02").join(format!("ep_{:05}.mkv", idx)),
            b"",
        )
        .unwrap();
    }

    // First scan hits MAX_SCAN_FILES (10,000), surfaces explicit truncation + next_cursor
    let page1 = run_auto_continuing_scan(
        &tmp,
        None,
        false,
        &MEDIAFLOW_SCAN_CURSORS,
        MAX_SCAN_FILES,
        MAX_SCAN_DEPTH,
        is_mediaflow_extension,
    );
    assert_eq!(page1.files.len(), 10_000);
    assert!(page1.truncated);
    assert!(page1.truncated_by_limit);
    let cursor = page1
        .next_cursor
        .clone()
        .expect("truncated 10,001-file scan must surface next_cursor");
    assert_eq!(cursor, "Season_02/ep_09999.mkv");

    // Second scan on the same root automatically resumes from cursor and reaches file #10,001
    let page2 = run_auto_continuing_scan(
        &tmp,
        None,
        false,
        &MEDIAFLOW_SCAN_CURSORS,
        MAX_SCAN_FILES,
        MAX_SCAN_DEPTH,
        is_mediaflow_extension,
    );
    assert_eq!(page2.files.len(), 1);
    assert!(!page2.truncated);
    assert!(page2.next_cursor.is_none());
    assert!(page2.files[0].ends_with("Season_02/ep_10000.mkv"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_bounded_flat_dir_windowing_and_deferred_cursor_commit_on_db_failure() {
    let tmp = std::env::temp_dir().join(format!("af-flat-window-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&tmp).unwrap();

    // Populate a single flat directory with 2,505 media files (> 2 * DIR_SCAN_WINDOW_CAP = 2048)
    // plus non-media sidecars to exercise multi-pass BinaryHeap windowing and extension pre-filtering.
    for idx in (0..2_505usize).rev() {
        std::fs::write(tmp.join(format!("movie_{:05}.mkv", idx)), b"").unwrap();
        if idx % 5 == 0 {
            std::fs::write(tmp.join(format!("movie_{:05}.nfo", idx)), b"meta").unwrap();
        }
    }

    let cursor_store: Mutex<HashMap<PathBuf, String>> = Mutex::new(HashMap::new());

    // Simulate a DB write failure after `prepare_auto_continuing_scan` BEFORE `commit_auto_continuing_scan`:
    // cursor_store MUST remain untouched so retry re-processes from `movie_00000.mkv` without losing batch 1!
    let prepared_fail = prepare_auto_continuing_scan(
        &tmp,
        None,
        false,
        &cursor_store,
        2_200,
        MAX_SCAN_DEPTH,
        is_mediaflow_extension,
    );
    assert_eq!(prepared_fail.outcome.files.len(), 2_200);
    assert!(prepared_fail.outcome.truncated_by_limit);
    assert_eq!(
        prepared_fail.outcome.next_cursor.as_deref(),
        Some("movie_02199.mkv")
    );
    assert!(
        cursor_store.lock().unwrap().is_empty(),
        "cursor must NOT advance before SQLite persistence commits"
    );

    // Retry after DB recovers: starts from the very beginning (`movie_00000.mkv`), then commits cursor
    let prepared_ok = prepare_auto_continuing_scan(
        &tmp,
        None,
        false,
        &cursor_store,
        2_200,
        MAX_SCAN_DEPTH,
        is_mediaflow_extension,
    );
    assert!(prepared_ok.outcome.files[0].ends_with("movie_00000.mkv"));
    assert!(prepared_ok.outcome.files[2_199].ends_with("movie_02199.mkv"));
    commit_auto_continuing_scan(&cursor_store, &prepared_ok);

    // Next continuation picks up at `movie_02200.mkv` through `movie_02504.mkv` (305 remaining files)
    let page2 = run_auto_continuing_scan(
        &tmp,
        None,
        false,
        &cursor_store,
        2_200,
        MAX_SCAN_DEPTH,
        is_mediaflow_extension,
    );
    assert_eq!(page2.files.len(), 305);
    assert!(!page2.truncated);
    assert!(page2.files[0].ends_with("movie_02200.mkv"));
    assert!(page2.files[304].ends_with("movie_02504.mkv"));
    assert!(cursor_store.lock().unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn intelligence_handlers_return_503_when_database_pool_is_unavailable() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }

    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "jti-admin".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    assert_eq!(
        metadata_results().await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        get_metrics_history(Query(HashMap::new())).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        get_auth_metrics_history(Query(HashMap::new()))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        get_predictions().await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        analyze_predictions().await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        get_mediaflow_queue().await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        approve_mediaflow_item(Path("1".to_string()), axum::body::Bytes::new())
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        decline_mediaflow_item(Path("1".to_string())).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let mut bookmark_req = Request::builder()
        .uri("/logs/bookmarks")
        .body(axum::body::Body::empty())
        .unwrap();
    bookmark_req.extensions_mut().insert(admin);
    assert_eq!(
        get_bookmarks(bookmark_req).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn intelligence_handlers_return_explicit_5xx_on_sqlite_query_and_write_errors() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    let db_path = crate::plugins::tests::ensure_shared_test_db();
    let media_dir = db_path.parent().unwrap().join("media");
    std::fs::create_dir_all(&media_dir).unwrap();
    let canon_media = media_dir.canonicalize().unwrap();
    std::env::set_var("AF_ALLOWED_FS_ROOTS", &canon_media);
    std::env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");

    // 1. SQLite write failures in approve_mediaflow_item and decline_mediaflow_item must return 500, never 409.
    let sample = canon_media.join("clip.mp4");
    std::fs::write(&sample, b"clip-payload-bytes").unwrap();
    let pinned = af_services::open_and_pin_mediaflow_source_in_roots(
        sample.to_str().unwrap(),
        std::slice::from_ref(&canon_media),
    )
    .unwrap();
    let id_rec = &pinned.identity;
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO mediaflow_queue (
                 id, file_path, original_codec, original_size, status,
                 source_dev, source_ino, source_size,
                 source_mtime_sec, source_mtime_nsec, source_fingerprint
             ) VALUES (901, ?1, 'h264', ?2, 'PENDING_APPROVAL', ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                pinned.canon_src.to_string_lossy().as_ref(),
                id_rec.size as i64,
                id_rec.dev as i64,
                id_rec.ino as i64,
                id_rec.size as i64,
                id_rec.mtime_sec,
                id_rec.mtime_nsec,
                &id_rec.fingerprint,
            ],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER abort_mediaflow_update BEFORE UPDATE ON mediaflow_queue \
             BEGIN SELECT RAISE(ABORT, 'simulated sqlite write failure'); END;",
        )
        .unwrap();
    }
    let approve_body = axum::body::Bytes::from(
        serde_json::json!({ "sourceFingerprint": &id_rec.fingerprint }).to_string(),
    );
    assert_eq!(
        approve_mediaflow_item(Path("901".to_string()), approve_body)
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        decline_mediaflow_item(Path("901".to_string()))
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );

    // 2. Real SQLite table/query failures must return 500/503, never 200 OK [] / healthy:true or 404.
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch(
            "DROP TRIGGER abort_mediaflow_update;
             DROP TABLE media_metadata;
             DROP TABLE metrics_history;
             DROP TABLE mediaflow_queue;
             DROP TABLE log_bookmarks;",
        )
        .unwrap();
    }

    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "jti-admin".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    assert_eq!(
        metadata_results().await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(upsert_media_metadata_row(
        "/media/test.mkv",
        "test.mkv",
        "Test",
        "2026",
        "en",
        "1080p",
        &[],
    )
    .is_err());
    assert_eq!(
        get_metrics_history(Query(HashMap::new())).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        get_predictions().await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        get_mediaflow_queue().await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );

    let mut bookmark_req = Request::builder()
        .uri("/logs/bookmarks")
        .body(axum::body::Body::empty())
        .unwrap();
    bookmark_req.extensions_mut().insert(admin);
    assert_eq!(
        get_bookmarks(bookmark_req).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}
