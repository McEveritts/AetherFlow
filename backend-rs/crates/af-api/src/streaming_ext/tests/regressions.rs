#![allow(clippy::await_holding_lock)]

use super::{init_isolated_streaming_db, TEST_STREAMING_DB_LOCK};
use crate::auth::AuthUser;
use crate::streaming_ext::analytics::try_query_streaming_analytics;
use crate::streaming_ext::emby::persist_emby_verified_identity;
use crate::streaming_ext::monitor::record_live_sessions_snapshot_for_source_inner;
use crate::streaming_ext::plex::persist_plex_verified_identity;
use crate::streaming_ext::{
    clear_streaming_demo_data, control_streaming_session, get_stored_plex_config_fail_closed,
    get_streaming_artwork, get_streaming_dashboard_handler, is_demo_mode_active,
    query_streaming_analytics, save_emby_server_configuration, save_plex_server_configuration,
    seed_streaming_demo_data, sync_jellyfin_watch_history, sync_streaming_server_history,
    test_streaming_server, SessionCommandReq, TestStreamingServerReq,
};
use af_services::{ActiveStreamSession, StreamingServerStatus};
use axum::body::Body;
use axum::extract::{Extension, Path, Query, Request};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Json;
use rusqlite::params;
use std::collections::HashMap;

fn admin_user() -> AuthUser {
    AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "regression-jti".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    }
}

#[tokio::test]
async fn test_dashboard_handler_returns_500_on_sqlite_read_failure_instead_of_empty_200() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("reg_dashboard_db_err");
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE streaming_history", []).unwrap();
    }

    assert!(try_query_streaming_analytics(30, "all", "all", false, true, 0.0).is_err());

    let mut request = Request::new(Body::empty());
    request.extensions_mut().insert(admin_user());
    let response = get_streaming_dashboard_handler(Query(HashMap::new()), request).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[test]
fn test_demo_seed_and_clear_propagate_sqlite_errors_without_flipping_demo_mode() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("reg_demo_db_err");
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE streaming_bandwidth_samples", [])
            .unwrap();
    }

    assert!(!is_demo_mode_active());
    assert!(seed_streaming_demo_data().is_err());
    assert!(!is_demo_mode_active());

    af_services::set_streaming_demo_mode(true);
    assert!(clear_streaming_demo_data().is_err());
    assert!(is_demo_mode_active());
    af_services::set_streaming_demo_mode(false);

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[test]
fn test_demo_mode_analytics_isolates_production_bandwidth_samples() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("reg_demo_bw_isolation");

    seed_streaming_demo_data().expect("seed demo data");
    {
        let conn = af_db::get_conn().unwrap();
        let now_ts = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        conn.execute(
            "INSERT INTO streaming_bandwidth_samples (timestamp, provider, active_streams, direct_play_count, direct_stream_count, transcode_count, total_bitrate_bps, bytes_delta) VALUES (?1, 'jellyfin', 5, 5, 0, 0, 999000000, 1000000)",
            params![now_ts],
        )
        .unwrap();
    }

    let demo_analytics = query_streaming_analytics(30, "all", "all", true, true, 0.0);
    assert!(
        demo_analytics.peak_bandwidth_mbps < 200.0,
        "production jellyfin bandwidth sample leaked into demo mode: {}",
        demo_analytics.peak_bandwidth_mbps
    );
    assert!(demo_analytics
        .time_series
        .iter()
        .all(|pt| pt.peak_bandwidth_mbps < 200.0));

    clear_streaming_demo_data().expect("clear demo data");
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[tokio::test]
async fn test_artwork_handler_returns_500_on_sqlite_failure_instead_of_403() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("reg_artwork_db_err");
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE streaming_servers", []).unwrap();
    }

    let response = get_streaming_artwork(
        Extension(admin_user()),
        Path("item-1".to_string()),
        Query(HashMap::from([("provider".into(), "jellyfin".into())])),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[tokio::test]
async fn test_session_control_maps_missing_media_control_to_400_and_db_failure_to_500() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("reg_session_cmd_status");

    let app = axum::Router::new().route(
        "/Sessions",
        axum::routing::get(|| async {
            Json(serde_json::json!([
                {
                    "Id": "sess-no-ctrl",
                    "UserId": "u-1",
                    "UserName": "viewer",
                    "Client": "Roku",
                    "DeviceName": "Roku Stick",
                    "SupportsMediaControl": false
                }
            ]))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    {
        let conn = af_db::get_conn().unwrap();
        let enc_key = af_db::encrypt_key("jf-ctrl-key-1234").unwrap_or_default();
        conn.execute(
            "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Mock JF', ?1, ?2, 1)",
            params![server_url, enc_key],
        )
        .unwrap();
    }

    let resp = control_streaming_session(
        Extension(admin_user()),
        Path("sess-no-ctrl".to_string()),
        HeaderMap::new(),
        Json(SessionCommandReq {
            command: "pause".to_string(),
            header: String::new(),
            message: String::new(),
            provider: "jellyfin".to_string(),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Dropping streaming_history must surface 500 during implicit provider resolution instead of silently defaulting.
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE streaming_history", []).unwrap();
    }
    let db_err_resp = control_streaming_session(
        Extension(admin_user()),
        Path("sess-no-ctrl".to_string()),
        HeaderMap::new(),
        Json(SessionCommandReq {
            command: "pause".to_string(),
            header: String::new(),
            message: String::new(),
            provider: String::new(),
        }),
    )
    .await;
    assert_eq!(db_err_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    server.abort();
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[test]
fn test_plex_save_rejects_url_change_with_empty_token_and_surfaces_db_errors() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("reg_plex_save_guards");

    save_plex_server_configuration(
        "Primary Plex",
        "http://127.0.0.1:32400",
        "plex-secret-token-1234",
        true,
    )
    .expect("initial plex save");

    // Changing URL with empty api_key must NOT silently transfer the stored token.
    let err_resp = save_plex_server_configuration("Other Plex", "http://127.0.0.1:32401", "", true)
        .unwrap_err();
    assert_eq!(err_resp.status(), StatusCode::BAD_REQUEST);
    let stored = get_stored_plex_config_fail_closed();
    assert_eq!(stored.url, "http://127.0.0.1:32400");
    assert_eq!(stored.api_key, "plex-secret-token-1234");

    // Corrupting/dropping streaming_servers must return 500 (not 400 STREAMING_KEY_REQUIRED) on save.
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DROP TABLE streaming_servers", []).unwrap();
    }
    let plex_db_err =
        save_plex_server_configuration("Primary Plex", "http://127.0.0.1:32400", "****1234", true)
            .unwrap_err();
    assert_eq!(plex_db_err.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let emby_db_err =
        save_emby_server_configuration("Primary Emby", "http://127.0.0.1:8096", "****1234", true)
            .unwrap_err();
    assert_eq!(emby_db_err.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[tokio::test]
async fn test_jellyfin_unconfigured_public_probe_returns_200_unconfigured_not_409_conflict() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("reg_jf_public_probe");

    let app = axum::Router::new().route(
        "/System/Info/Public",
        axum::routing::get(|| async {
            Json(serde_json::json!({
                "Id": "jf-public-1",
                "ServerName": "Public Jellyfin",
                "Version": "10.10.6"
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Public Jellyfin', ?1, '', 1)",
            params![server_url],
        )
        .unwrap();
    }

    let resp = test_streaming_server(Json(TestStreamingServerReq {
        provider: "jellyfin".to_string(),
        url: server_url,
        api_key: String::new(),
    }))
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["server"]["status"], "unconfigured");

    server.abort();
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[tokio::test]
async fn test_summary_sync_propagates_checkpoint_table_sqlite_errors() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("reg_summary_checkpoint_err");

    let app = axum::Router::new()
        .route(
            "/System/Info/Public",
            axum::routing::get(|| async { Json(serde_json::json!({"Id": "jf-ckpt-srv"})) }),
        )
        .route(
            "/Users",
            axum::routing::get(|| async {
                Json(serde_json::json!([{ "Id": "u-1", "Name": "alice" }]))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    {
        let conn = af_db::get_conn().unwrap();
        let enc_key = af_db::encrypt_key("jf-ckpt-key-1234").unwrap_or_default();
        conn.execute(
            "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Ckpt JF', ?1, ?2, 1)",
            params![server_url, enc_key],
        )
        .unwrap();
        conn.execute("DROP TABLE streaming_import_checkpoints", [])
            .unwrap();
    }

    let err = sync_jellyfin_watch_history().await.unwrap_err();
    assert!(
        err.to_string().contains("streaming_import_checkpoints"),
        "expected missing checkpoint table error, got: {err}"
    );

    let http_resp = sync_streaming_server_history(
        Extension(admin_user()),
        Path("jellyfin".to_string()),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(http_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    server.abort();
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[test]
fn test_live_snapshot_rolls_back_atomically_when_sqlite_write_fails() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("reg_snapshot_atomic_rollback");

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "CREATE TRIGGER fail_bw_insert BEFORE INSERT ON streaming_bandwidth_samples BEGIN SELECT RAISE(ABORT, 'simulated_bw_write_failure'); END;",
            [],
        )
        .unwrap();
    }

    let session = ActiveStreamSession {
        session_id: "atomic-sess-1".to_string(),
        item_id: "atomic-item-1".to_string(),
        item_name: "Atomic Test".to_string(),
        state: "playing".to_string(),
        bitrate_bps: 8_000_000,
        ..Default::default()
    };

    let err = record_live_sessions_snapshot_for_source_inner(
        "jellyfin",
        std::slice::from_ref(&session),
        15,
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("simulated_bw_write_failure"));

    let conn = af_db::get_conn().unwrap();
    let history_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM streaming_history", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        history_rows, 0,
        "streaming_history insert must roll back when bandwidth sample insert fails"
    );

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[test]
fn test_verified_identity_persistence_propagates_sqlite_write_errors() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("reg_identity_persist_err");

    save_emby_server_configuration(
        "Emby Fail",
        "http://127.0.0.1:8096",
        "emby-secret-key-9999",
        true,
    )
    .expect("save emby");
    save_plex_server_configuration(
        "Plex Fail",
        "http://127.0.0.1:32400",
        "plex-secret-key-9999",
        true,
    )
    .expect("save plex");

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "CREATE TRIGGER fail_server_update BEFORE UPDATE ON streaming_servers BEGIN SELECT RAISE(ABORT, 'simulated_server_update_failure'); END;",
            [],
        )
        .unwrap();
    }

    let emby_status = StreamingServerStatus {
        provider: "emby".to_string(),
        status: "connected".to_string(),
        server_id: "emby-srv-fail".to_string(),
        version: "4.8.10".to_string(),
        ..Default::default()
    };
    let emby_err = persist_emby_verified_identity(
        &emby_status,
        "http://127.0.0.1:8096",
        "emby-secret-key-9999",
    )
    .unwrap_err();
    assert!(emby_err
        .to_string()
        .contains("simulated_server_update_failure"));

    let plex_status = StreamingServerStatus {
        provider: "plex".to_string(),
        status: "connected".to_string(),
        server_id: "plex-srv-fail".to_string(),
        version: "1.41.3".to_string(),
        ..Default::default()
    };
    let plex_err = persist_plex_verified_identity(
        &plex_status,
        "http://127.0.0.1:32400",
        "plex-secret-key-9999",
    )
    .unwrap_err();
    assert!(plex_err
        .to_string()
        .contains("simulated_server_update_failure"));

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}
