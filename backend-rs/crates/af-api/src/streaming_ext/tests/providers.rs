#![allow(clippy::await_holding_lock, clippy::type_complexity)]

use super::{init_isolated_streaming_db, TEST_STREAMING_DB_LOCK};
use crate::auth::AuthUser;
use crate::streaming_ext::dashboard::cached_provider_telemetry;
use crate::streaming_ext::jellyfin::do_jellyfin_request;
use crate::streaming_ext::monitor::record_live_sessions_snapshot_for_source;
use crate::streaming_ext::{
    build_streaming_dashboard, control_streaming_session, fetch_jellyfin_live_sessions,
    fetch_plex_live_sessions, format_observed_session_key, get_stored_emby_config_fail_closed,
    get_streaming_artwork, query_streaming_analytics, record_live_sessions_snapshot,
    save_emby_server_configuration, save_plex_server_configuration, send_jellyfin_session_command,
    sync_jellyfin_watch_history, sync_streaming_server_history, test_jellyfin_connection,
    test_streaming_server, SessionCommandReq, TestStreamingServerReq,
};
use axum::extract::{Extension, Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use rusqlite::params;
use std::collections::HashMap;
use std::time::Duration;

#[tokio::test]
async fn test_streaming_pinned_cached_degraded_telemetry_and_artwork_denial() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = init_isolated_streaming_db("pinned_degraded");
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let router = axum::Router::new()
        .route(
            "/System/Info",
            axum::routing::get(move || {
                let observed = observed.clone();
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({"Id":"saved","ServerName":"Synthetic"}))
                }
            }),
        )
        .route(
            "/Items/Counts",
            axum::routing::get(|| async { Json(serde_json::json!({})) }),
        )
        .route(
            "/Sessions",
            axum::routing::get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    af_db::get_conn()
        .unwrap()
        .execute(
            "INSERT OR REPLACE INTO streaming_servers(provider,name,url,api_key,server_id,enabled) VALUES('jellyfin','Synthetic',?1,'fixture-key','saved',1)",
            [&url],
        )
        .unwrap();
    assert!(cached_provider_telemetry("jellyfin").await.is_err());
    assert!(cached_provider_telemetry("jellyfin").await.is_err());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    af_db::get_conn()
        .unwrap()
        .execute(
            "UPDATE streaming_servers SET server_id='original' WHERE provider='jellyfin'",
            [],
        )
        .unwrap();
    assert!(test_jellyfin_connection(&url, "fixture-key").await.is_err());
    assert_eq!(
        af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT server_id FROM streaming_servers WHERE provider='jellyfin'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "original"
    );
    let viewer = AuthUser {
        user_id: 1,
        username: "viewer".into(),
        role: "user".into(),
        jti: "fixture".into(),
        plugin_id: None,
        plugin_scopes: vec![],
    };
    let response = get_streaming_artwork(
        Extension(viewer),
        Path("unknown-item".into()),
        Query(HashMap::from([("provider".into(), "jellyfin".into())])),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(count.load(Ordering::SeqCst), 2);
    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn test_streaming_json_body_exact_cap_and_overflow() {
    let router = axum::Router::new()
        .route("/exact", axum::routing::get(|| async { "12345678" }))
        .route("/large", axum::routing::get(|| async { "123456789" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let exact = do_jellyfin_request(
        reqwest::Method::GET,
        &format!("{base}/exact"),
        "",
        None,
        Duration::from_secs(2),
        8,
    )
    .await
    .unwrap();
    assert_eq!(exact.0, b"12345678");
    assert!(do_jellyfin_request(
        reqwest::Method::GET,
        &format!("{base}/large"),
        "",
        None,
        Duration::from_secs(2),
        8
    )
    .await
    .is_err());
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn test_watch_history_sync_does_not_fabricate_metadata_bytes_or_now_timestamps() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("sync_truth");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock jellyfin");
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                let req_str = String::from_utf8_lossy(&buf[..n]);
                let first_line = req_str.lines().next().unwrap_or("");

                let body = if first_line.contains("GET /System/Info/Public") {
                    serde_json::json!({"Id":"mock-summary-server"}).to_string()
                } else if first_line.contains("GET /Users ") || first_line.contains("GET /Users?") {
                    serde_json::json!([
                        { "Id": "user-1", "Name": "diana" }
                    ])
                    .to_string()
                } else if first_line.contains("Filters=IsPlayed") {
                    serde_json::json!({
                        "TotalRecordCount": 2,
                        "Items": [
                            {
                                "Id": "item-known",
                                "Name": "Arrival",
                                "Type": "Movie",
                                "ProductionYear": 2016,
                                "RunTimeTicks": 69_600_000_000i64,
                                "Container": "mkv",
                                "Bitrate": 16_000_000i64,
                                "Width": 3840,
                                "Height": 2160,
                                "MediaStreams": [
                                    { "Type": "Video", "Codec": "hevc", "Width": 3840, "Height": 2160, "BitRate": 15_000_000 },
                                    { "Type": "Audio", "Codec": "dts", "Channels": 6, "BitRate": 1_000_000 }
                                ],
                                "UserData": {
                                    "Played": true,
                                    "PlaybackPositionTicks": 0,
                                    "PlayedPercentage": 100.0,
                                    "LastPlayedDate": "2026-10-15T18:30:00Z"
                                }
                            },
                            {
                                "Id": "item-unknown-meta",
                                "Name": "Mystery Track",
                                "Type": "Audio",
                                "RunTimeTicks": 0,
                                "Container": "",
                                "Bitrate": 0,
                                "Width": 0,
                                "Height": 0,
                                "MediaStreams": [],
                                "UserData": {
                                    "Played": true,
                                    "PlaybackPositionTicks": 0,
                                    "PlayedPercentage": 0.0,
                                    "LastPlayedDate": ""
                                }
                            }
                        ]
                    })
                    .to_string()
                } else {
                    serde_json::json!({
                        "TotalRecordCount": 0,
                        "Items": []
                    })
                    .to_string()
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });

    {
        let conn = af_db::get_conn().expect("db conn");
        let enc_key = af_db::encrypt_key("test-sync-api-key-9999").unwrap_or_default();
        conn.execute(
            "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Mock Jellyfin', ?1, ?2, 1)",
            params![format!("http://{}", addr), enc_key],
        )
        .unwrap();
    }

    let outcome = sync_jellyfin_watch_history()
        .await
        .expect("sync watch history");
    assert_eq!(outcome.imported, 2);
    assert!(outcome.complete);
    assert!(!outcome.has_more);
    assert_eq!(outcome.remaining_sources, 0);
    assert_eq!(outcome.next_offset, None);

    let conn = af_db::get_conn().expect("db conn");
    let (
        client1,
        device1,
        ip1,
        method1,
        v_codec1,
        v_res1,
        a_codec1,
        a_ch1,
        br1,
        dur1,
        watched1,
        bytes1,
        started1,
    ): (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i32,
        i64,
        i64,
        i64,
        i64,
        String,
    ) = conn
        .query_row(
            r#"
            SELECT client_name, device_name, ip_address, play_method,
                   video_codec, video_resolution, audio_codec, audio_channels,
                   bitrate_bps, duration_secs, watched_secs, data_used_bytes, started_at
            FROM streaming_history
            WHERE provenance = 'item_summary' AND user_id = 'user-1' AND item_id = 'item-known'
            "#,
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                ))
            },
        )
        .expect("known item row");

    // Known source metadata is retained, while unmeasured playback fields remain empty/zero
    assert_eq!(client1, "");
    assert_eq!(device1, "");
    assert_eq!(ip1, "");
    assert_eq!(method1, "");
    assert_eq!(v_codec1, "HEVC");
    assert_eq!(v_res1, "4K UHD");
    assert_eq!(a_codec1, "DTS");
    assert_eq!(a_ch1, 6);
    assert_eq!(br1, 16_000_000);
    assert_eq!(dur1, 6960);
    assert_eq!(watched1, 6960);
    assert_eq!(bytes1, 0);
    assert_eq!(started1, "2026-10-15 18:30:00");

    let (
        client2,
        device2,
        ip2,
        method2,
        v_codec2,
        v_res2,
        a_codec2,
        a_ch2,
        br2,
        dur2,
        watched2,
        bytes2,
        started2,
    ): (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i32,
        i64,
        i64,
        i64,
        i64,
        String,
    ) = conn
        .query_row(
            r#"
            SELECT client_name, device_name, ip_address, play_method,
                   video_codec, video_resolution, audio_codec, audio_channels,
                   bitrate_bps, duration_secs, watched_secs, data_used_bytes, started_at
            FROM streaming_history
            WHERE provenance = 'item_summary' AND user_id = 'user-1' AND item_id = 'item-unknown-meta'
            "#,
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                ))
            },
        )
        .expect("unknown meta item row");

    // Missing source metadata and missing LastPlayedDate must NOT fabricate 2700s, 8Mbps, HEVC/EAC3/1080p, or today's timestamp
    assert_eq!(client2, "");
    assert_eq!(device2, "");
    assert_eq!(ip2, "");
    assert_eq!(method2, "");
    assert_eq!(v_codec2, "");
    assert_eq!(v_res2, "");
    assert_eq!(a_codec2, "");
    assert_eq!(a_ch2, 0);
    assert_eq!(br2, 0);
    assert_eq!(dur2, 0);
    assert_eq!(watched2, 0);
    assert_eq!(bytes2, 0);
    assert_eq!(started2, "");

    drop(conn);

    // Verify 7-day window does NOT include the dateless imported row or the 2026-10-15 row
    let win7 = query_streaming_analytics(7, "all", "all", false, true, 0.0);
    assert_eq!(win7.total_plays, 0);

    // Item summaries remain raw evidence, not confirmed dashboard playback events.
    let all_time = query_streaming_analytics(0, "all", "all", false, true, 0.0);
    assert_eq!(all_time.window_days, 0);
    assert_eq!(all_time.total_plays, 0);
    assert_eq!(all_time.stream_types.direct_play_count, 0);
    assert_eq!(all_time.stream_types.direct_play_pct, 0.0);

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE streaming_history SET timestamp_certainty = 'unrecorded' WHERE item_id = 'item-known'",
            [],
        )
        .unwrap();
    }
    assert_eq!(sync_jellyfin_watch_history().await.unwrap().imported, 1);
    {
        let conn = af_db::get_conn().unwrap();
        let certainty: String = conn
            .query_row(
                "SELECT timestamp_certainty FROM streaming_history WHERE item_id = 'item-known'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(certainty, "last_played");
        conn.execute(
            "UPDATE streaming_history SET provenance = 'legacy_unverified', item_name = 'Preserved legacy' WHERE item_id = 'item-known'",
            [],
        )
        .unwrap();
    }
    assert_eq!(sync_jellyfin_watch_history().await.unwrap().imported, 0);
    {
        let conn = af_db::get_conn().unwrap();
        let title: String = conn
            .query_row(
                "SELECT item_name FROM streaming_history WHERE item_id = 'item-known'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(title, "Preserved legacy");
        conn.execute(
            "UPDATE streaming_servers SET server_id = 'replacement-server' WHERE provider = 'jellyfin'",
            [],
        )
        .unwrap();
    }
    assert!(sync_jellyfin_watch_history().await.is_err());
    {
        let conn = af_db::get_conn().unwrap();
        let records: i64 = conn
            .query_row("SELECT COUNT(*) FROM streaming_history", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(records, 2);
        let records: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM streaming_history WHERE server_id = 'replacement-server' AND provenance = 'item_summary'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(records, 0);
    }
    server_handle.abort();

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[tokio::test]
async fn test_watch_history_sync_reports_upstream_item_failures() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("history_sync_failure");
    let app = axum::Router::new()
        .route(
            "/System/Info/Public",
            axum::routing::get(|| async { Json(serde_json::json!({"Id":"mock-summary-server"})) }),
        )
        .route(
            "/Users",
            axum::routing::get(|| async {
                Json(serde_json::json!([{ "Id": "viewer", "Name": "Viewer" }]))
            }),
        )
        .route(
            "/Users/:user/Items",
            axum::routing::get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    {
        let conn = af_db::get_conn().unwrap();
        let api_key = af_db::encrypt_key("test-sync-failure-key").unwrap();
        conn.execute(
            "INSERT INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Unavailable History', ?1, ?2, 1)",
            params![server_url, api_key],
        )
        .unwrap();
    }
    let error = sync_jellyfin_watch_history().await.unwrap_err();
    assert!(error.to_string().contains("503"));
    server.abort();
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[tokio::test]
async fn test_fetch_live_sessions_and_session_command_capabilities() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("live_fetch_and_cmd");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock jellyfin");
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                let req_str = String::from_utf8_lossy(&buf[..n]);
                let first_line = req_str.lines().next().unwrap_or("");

                let body = if first_line.contains("GET /Sessions") {
                    serde_json::json!([
                        {
                            "Id": "sess-seek",
                            "UserId": "u-1",
                            "UserName": "claire",
                            "Client": "Swiftfin",
                            "DeviceName": "Apple TV",
                            "DeviceId": "atv-1",
                            "ApplicationVersion": "1.2",
                            "LastActivityDate": "2001-01-01T00:00:00Z",
                            "RemoteEndPoint": "192.168.1.99",
                            "SupportsMediaControl": true,
                            "Capabilities": {
                                "SupportsMediaControl": true,
                                "SupportedCommands": ["PlayState"]
                            },
                            "PlayState": {
                                "PositionTicks": 54_000_000_000i64,
                                "IsPaused": false,
                                "PlayMethod": "DirectPlay",
                                "PlaySessionId": "",
                                "MediaSourceId": "ms-1"
                            },
                            "NowPlayingItem": {
                                "Id": "item-seek-1",
                                "Name": "Dune",
                                "Type": "Movie",
                                "RunTimeTicks": 90_000_000_000i64,
                                "Container": "mkv",
                                "Bitrate": 20_000_000i64,
                                "Width": 3840,
                                "Height": 2160,
                                "MediaStreams": []
                            }
                        },
                        {
                            "Id": "sess-no-ws",
                            "UserId": "u-2",
                            "UserName": "dan",
                            "Client": "Roku",
                            "DeviceName": "Roku Ultra",
                            "DeviceId": "roku-1",
                            "SupportsMediaControl": false,
                            "PlayState": {
                                "PositionTicks": 10_000_000_000i64,
                                "IsPaused": false,
                                "PlayMethod": "DirectPlay"
                            },
                            "NowPlayingItem": {
                                "Id": "item-audio-1",
                                "Name": "Track 01",
                                "Type": "Audio",
                                "RunTimeTicks": 2_000_000_000i64,
                                "Container": "flac",
                                "Bitrate": 0,
                                "Width": 0,
                                "Height": 0,
                                "MediaStreams": []
                            }
                        }
                    ])
                    .to_string()
                } else {
                    "{}".to_string()
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });

    let server_url = format!("http://{}", addr);
    {
        let conn = af_db::get_conn().unwrap();
        let enc_key = af_db::encrypt_key("test-cmd-key-1234").unwrap_or_default();
        conn.execute(
            "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Mock JF', ?1, ?2, 1)",
            params![server_url, enc_key],
        )
        .unwrap();
    }

    // 1. Fetch live sessions: sess-seek is at 5400s (90m), but no bytes have been tracked in DB yet -> session_data_bytes must be 0, NOT 5400 * 2.5MB
    let live = fetch_jellyfin_live_sessions("Mock JF", &server_url, "test-cmd-key-1234")
        .await
        .expect("fetch live sessions");
    assert_eq!(live.len(), 2);
    assert_eq!(live[0].session_id, "sess-seek");
    assert_eq!(live[0].position_secs, 5400);
    assert_eq!(live[0].session_data_bytes, 0);
    assert_ne!(live[0].started_at, "2001-01-01T00:00:00Z");
    assert!(!live[0].can_send_message); // DisplayMessage not in SupportedCommands

    // Audio session without dimensions/streams must not fabricate H264/AAC/1080p FHD or 4Mbps
    assert_eq!(live[1].session_id, "sess-no-ws");
    assert_eq!(live[1].video_codec, "");
    assert_eq!(live[1].audio_codec, "");
    assert_eq!(live[1].video_resolution, "");
    assert_eq!(live[1].bitrate_bps, 0);

    record_live_sessions_snapshot("jellyfin", &live, 15);
    {
        let conn = af_db::get_conn().unwrap();
        let (watched, bytes): (i64, i64) = conn
            .query_row(
                "SELECT watched_secs, data_used_bytes FROM streaming_history WHERE item_id = 'item-seek-1' AND provenance = 'observed_session'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((watched, bytes), (0, 0));
        let samples: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM streaming_session_samples WHERE observed_secs = 0 AND playing = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(samples > 0);
    }
    record_live_sessions_snapshot("jellyfin", &live, 15);
    {
        let conn = af_db::get_conn().unwrap();
        let seek_key =
            format_observed_session_key("jellyfin", "", "sess-seek", "", "item-seek-1", 1);
        conn.execute(
            "UPDATE streaming_history SET started_at = '2026-10-01 10:00:00' WHERE session_key = ?1",
            params![seek_key],
        )
        .unwrap();
    }
    let live_after = fetch_jellyfin_live_sessions("Mock JF", &server_url, "test-cmd-key-1234")
        .await
        .expect("fetch live sessions after tick");
    assert_eq!(live_after[0].session_data_bytes, 0);
    assert_eq!(live_after[0].started_at, "2026-10-01 10:00:00");

    // 3. Session command verification: non-existent session, missing DisplayMessage, and SupportsMediaControl=false
    let err_missing = send_jellyfin_session_command("non-existent-id", "pause", "", "")
        .await
        .unwrap_err();
    assert!(err_missing.to_string().contains("not found"));

    let err_no_msg = send_jellyfin_session_command("sess-seek", "message", "Admin", "Hello")
        .await
        .unwrap_err();
    assert!(err_no_msg.to_string().contains("DisplayMessage"));

    let err_no_ws = send_jellyfin_session_command("sess-no-ws", "pause", "", "")
        .await
        .unwrap_err();
    assert!(err_no_ws.to_string().contains("SupportsMediaControl=false"));

    server_handle.abort();
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[tokio::test]
async fn test_emby_server_config_save_guards_and_identity_reset() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("emby_config_guards");

    // 1. Invalid URL rejected
    let bad_url_resp = save_emby_server_configuration(
        "Emby",
        "ftp://emby.local:8096",
        "emby-secret-key-1111",
        true,
    )
    .unwrap_err();
    assert_eq!(bad_url_resp.status(), StatusCode::BAD_REQUEST);

    // 2. Masked key rejected when no existing stored config exists
    let masked_initial_resp =
        save_emby_server_configuration("Emby", "http://127.0.0.1:8096", "****1111", true)
            .unwrap_err();
    assert_eq!(masked_initial_resp.status(), StatusCode::BAD_REQUEST);

    // 3. Valid initial save succeeds and preserves coming_soon support_stage
    let clean_url = save_emby_server_configuration(
        "Primary Emby",
        "http://127.0.0.1:8096/",
        "emby-secret-key-1111",
        false,
    )
    .expect("valid initial emby save");
    assert_eq!(clean_url, "http://127.0.0.1:8096");
    let dash = build_streaming_dashboard("30d", "all", "all", true).await;
    let saved_srv = dash
        .servers
        .iter()
        .find(|s| s.provider == "emby")
        .expect("emby server in dashboard");
    assert_eq!(saved_srv.support_stage, "coming_soon");
    assert_eq!(saved_srv.url, "http://127.0.0.1:8096");
    assert_eq!(saved_srv.api_key_masked, "****1111");

    // Seed verified server identity on the stored Emby row
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE streaming_servers SET server_id = 'emby-srv-1', server_version = '4.8.8.0', last_connected_at = datetime('now') WHERE provider = 'emby'",
            [],
        )
        .unwrap();
    }

    // 4. Masked key on the exact same normalized URL preserves both API key and verified identity
    let same_url = save_emby_server_configuration(
        "Primary Emby Renamed",
        "http://127.0.0.1:8096",
        "****1111",
        false,
    )
    .expect("same url masked save");
    assert_eq!(same_url, "http://127.0.0.1:8096");
    {
        let conn = af_db::get_conn().unwrap();
        let (srv_id, srv_ver): (String, String) = conn
            .query_row(
                "SELECT COALESCE(server_id, ''), COALESCE(server_version, '') FROM streaming_servers WHERE provider = 'emby'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(srv_id, "emby-srv-1");
        assert_eq!(srv_ver, "4.8.8.0");
    }
    let cfg_same = get_stored_emby_config_fail_closed();
    assert_eq!(cfg_same.api_key, "emby-secret-key-1111");

    // 5. Changing URL with masked or empty key is rejected (prevents exfiltrating stored key to a new host)
    let url_change_masked_resp =
        save_emby_server_configuration("Second Emby", "http://127.0.0.1:8097", "****1111", false)
            .unwrap_err();
    assert_eq!(url_change_masked_resp.status(), StatusCode::BAD_REQUEST);

    // 6. Changing URL with a new explicit API key succeeds and clears server_id, server_version, and last_connected_at
    let changed_url = save_emby_server_configuration(
        "Second Emby",
        "http://127.0.0.1:8097/emby/",
        "emby-secret-key-2222",
        false,
    )
    .expect("url change with new key");
    assert_eq!(changed_url, "http://127.0.0.1:8097/emby");
    {
        let conn = af_db::get_conn().unwrap();
        let (url, srv_id, srv_ver, last_conn): (String, String, String, Option<String>) = conn
            .query_row(
                "SELECT url, COALESCE(server_id, ''), COALESCE(server_version, ''), last_connected_at FROM streaming_servers WHERE provider = 'emby'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(url, "http://127.0.0.1:8097/emby");
        assert_eq!(srv_id, "");
        assert_eq!(srv_ver, "");
        assert!(last_conn.is_none());
    }

    // 7. Undecryptable enc:v1: stored key fails closed and requires a fresh key even on same URL
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE streaming_servers SET api_key = 'enc:v1:corrupted-ciphertext' WHERE provider = 'emby'",
            [],
        )
        .unwrap();
    }
    let cfg_corrupt = get_stored_emby_config_fail_closed();
    assert_eq!(cfg_corrupt.api_key, "");
    let masked_on_corrupt_resp = save_emby_server_configuration(
        "Second Emby",
        "http://127.0.0.1:8097/emby",
        "****2222",
        false,
    )
    .unwrap_err();
    assert_eq!(masked_on_corrupt_resp.status(), StatusCode::BAD_REQUEST);

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[tokio::test]
async fn test_emby_dashboard_artwork_and_session_control_dispatch() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("emby_dispatch_integration");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");

                if first_line.starts_with("GET /Items/emby-item-1/Images/Primary") {
                    let img = b"\x89PNG\r\n\x1a\nmock-emby-artwork";
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        img.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(img).await;
                    return;
                }

                if first_line.starts_with("POST /Sessions/emby-sess-1/Playing/Pause") {
                    let resp =
                        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = stream.write_all(resp.as_bytes()).await;
                    return;
                }

                let body = if first_line.starts_with("GET /System/Info") {
                    r#"{"ServerName":"Mock Emby","Version":"4.8.10.0","Id":"emby-srv-live"}"#
                        .to_string()
                } else if first_line.starts_with("GET /Sessions") {
                    r#"[
                        {
                            "Id": "emby-sess-1",
                            "ServerId": "emby-srv-live",
                            "UserId": "emby-u-1",
                            "UserName": "alex",
                            "Client": "Emby Theater",
                            "DeviceName": "Shield TV",
                            "DeviceId": "shield-1",
                            "RemoteEndPoint": "10.10.0.42",
                            "SupportsMediaControl": true,
                            "SupportedCommands": ["Pause"],
                            "PlayState": {
                                "PositionTicks": 6000000000,
                                "IsPaused": false,
                                "PlayMethod": "DirectStream",
                                "PlaySessionId": "emby-ps-1"
                            },
                            "NowPlayingItem": {
                                "Id": "emby-item-1",
                                "Name": "Ex Machina",
                                "Type": "Movie",
                                "RunTimeTicks": 64800000000,
                                "ProductionYear": 2014,
                                "MediaStreams": [
                                    {"Type": "Video", "Codec": "hevc", "Width": 3840, "Height": 2160, "BitRate": 16000000},
                                    {"Type": "Audio", "Codec": "eac3", "Channels": 6, "Language": "eng", "BitRate": 640000}
                                ]
                            }
                        }
                    ]"#
                    .to_string()
                } else {
                    "{}".to_string()
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });

    let server_url = format!("http://{}", addr);
    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "test-jti".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    // Save Emby config via save_emby_server_configuration
    let saved_url =
        save_emby_server_configuration("Mock Emby", &server_url, "emby-live-key-9876", true)
            .expect("save mock emby config");
    assert_eq!(saved_url, server_url);

    // Test connection endpoint with masked key on same URL persists server_id and keeps support_stage = coming_soon
    let test_resp = test_streaming_server(Json(TestStreamingServerReq {
        provider: "emby".to_string(),
        url: server_url.clone(),
        api_key: "****9876".to_string(),
    }))
    .await
    .into_response();
    assert_eq!(test_resp.status(), StatusCode::OK);
    let test_bytes = axum::body::to_bytes(test_resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let test_json: serde_json::Value = serde_json::from_slice(&test_bytes).unwrap();
    assert_eq!(test_json["ok"], true);
    assert_eq!(test_json["server"]["status"], "connected");
    assert_eq!(test_json["server"]["supportStage"], "coming_soon");
    assert_eq!(test_json["server"]["serverId"], "emby-srv-live");
    assert_eq!(test_json["server"]["version"], "4.8.10.0");

    // Record two 15s monitor snapshots so observed session metrics accumulate for Emby
    let live_sessions = crate::streaming_emby::fetch_emby_live_sessions(
        "Mock Emby",
        &server_url,
        "emby-live-key-9876",
        Some("emby-srv-live"),
    )
    .await
    .unwrap();
    record_live_sessions_snapshot("emby", &live_sessions, 15);
    record_live_sessions_snapshot("emby", &live_sessions, 15);

    // Dashboard reflects live Emby session, observed bytes, coming_soon stage, and redacts sensitive fields for non-admin
    let admin_dash = build_streaming_dashboard("30d", "all", "all", true).await;
    let emby_srv = admin_dash
        .servers
        .iter()
        .find(|s| s.provider == "emby")
        .expect("emby server entry");
    assert_eq!(emby_srv.support_stage, "coming_soon");
    assert_eq!(emby_srv.status, "connected");
    assert_eq!(emby_srv.server_id, "emby-srv-live");
    assert_eq!(emby_srv.api_key_masked, "****9876");
    assert_eq!(admin_dash.active_sessions.len(), 1);
    assert_eq!(admin_dash.active_sessions[0].provider, "emby");
    assert_eq!(admin_dash.active_sessions[0].session_id, "emby-sess-1");
    assert_eq!(admin_dash.active_sessions[0].ip_address, "10.10.0.42");
    assert_eq!(admin_dash.active_sessions[0].session_data_bytes, 0);

    let viewer_dash = build_streaming_dashboard("30d", "all", "all", false).await;
    let viewer_emby_srv = viewer_dash
        .servers
        .iter()
        .find(|s| s.provider == "emby")
        .unwrap();
    assert_eq!(viewer_emby_srv.api_key_masked, "");
    assert_eq!(viewer_dash.active_sessions[0].ip_address, "");

    // Artwork proxy dispatches to Emby via explicit provider query
    let mut art_q = HashMap::new();
    art_q.insert("provider".to_string(), "emby".to_string());
    let art_resp = get_streaming_artwork(
        Extension(admin.clone()),
        Path("emby-item-1".to_string()),
        Query(art_q),
    )
    .await
    .into_response();
    assert_eq!(art_resp.status(), StatusCode::OK);
    let art_bytes = axum::body::to_bytes(art_resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(&art_bytes[..], b"\x89PNG\r\n\x1a\nmock-emby-artwork");

    // Session control: supported Pause command succeeds via observed-session provider resolution
    let pause_resp = control_streaming_session(
        axum::Extension(admin.clone()),
        Path("emby-sess-1".to_string()),
        HeaderMap::new(),
        Json(SessionCommandReq {
            command: "pause".to_string(),
            header: String::new(),
            message: String::new(),
            provider: String::new(),
        }),
    )
    .await
    .into_response();
    assert_eq!(pause_resp.status(), StatusCode::OK);

    // Session control: unsupported DisplayMessage is rejected because SupportedCommands only has ["Pause"]
    let msg_resp = control_streaming_session(
        axum::Extension(admin),
        Path("emby-sess-1".to_string()),
        HeaderMap::new(),
        Json(SessionCommandReq {
            command: "message".to_string(),
            header: "Notice".to_string(),
            message: "Hello".to_string(),
            provider: "emby".to_string(),
        }),
    )
    .await
    .into_response();
    assert_eq!(msg_resp.status(), StatusCode::BAD_REQUEST);

    server_handle.abort();
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[tokio::test]
async fn test_plex_live_telemetry_canonical_history_and_server_probe() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("plex_live_telemetry");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let has_valid_token = req
                    .lines()
                    .any(|l| l.eq_ignore_ascii_case("x-plex-token: plex-secret-7788"));

                let (status, ct, body) = if first_line.starts_with("GET /identity ") {
                    (
                        "200 OK",
                        "application/json",
                        r#"{"MediaContainer":{"machineIdentifier":"plex-machine-001","version":"1.41.3.9314"}}"#
                            .as_bytes()
                            .to_vec(),
                    )
                } else if !has_valid_token {
                    (
                        "401 Unauthorized",
                        "application/json",
                        br#"{"error":"unauthorized"}"#.to_vec(),
                    )
                } else if first_line.starts_with("GET /library/sections ") {
                    (
                        "200 OK",
                        "application/json",
                        r#"{"MediaContainer":{"title1":"Nexus Plex","Directory":[{"key":"1","type":"movie","totalSize":412},{"key":"2","type":"show","totalSize":85},{"key":"3","type":"artist","totalSize":1200}]}}"#
                            .as_bytes()
                            .to_vec(),
                    )
                } else if first_line.starts_with("GET / ") {
                    (
                        "200 OK",
                        "application/json",
                        r#"{"MediaContainer":{"friendlyName":"Nexus Plex","platform":"Linux","platformVersion":"6.8","machineIdentifier":"plex-machine-001","version":"1.41.3.9314"}}"#
                            .as_bytes()
                            .to_vec(),
                    )
                } else if first_line.starts_with("GET /status/sessions ") {
                    (
                        "200 OK",
                        "application/json",
                        r#"{"MediaContainer":{"size":1,"Metadata":[{"ratingKey":"9001","grandparentRatingKey":"9000","grandparentTitle":"Andor","title":"One Way Out","type":"episode","parentIndex":1,"index":10,"year":2022,"duration":2700000,"viewOffset":1350000,"thumb":"/library/metadata/9001/thumb","User":{"id":42,"title":"Cassian"},"Player":{"machineIdentifier":"plex-client-tv","product":"Plex for LG","device":"LG OLED","state":"playing","address":"192.168.1.50","local":true},"Session":{"id":"plex-live-sess-1","bandwidth":18500,"location":"lan"},"TranscodeSession":{"key":"ts-plex-1","videoDecision":"transcode","audioDecision":"copy","container":"mp4","videoCodec":"h264","audioCodec":"eac3","transcodeHwEncoding":"nvenc","progress":62.5,"speed":3.4},"Media":[{"container":"mkv","videoCodec":"hevc","videoResolution":"4k","audioCodec":"eac3","audioChannels":6,"bitrate":18000}]}]}}"#
                            .as_bytes()
                            .to_vec(),
                    )
                } else if first_line.starts_with("GET /library/metadata/9001/thumb ") {
                    (
                        "200 OK",
                        "image/png",
                        b"\x89PNG\r\n\x1a\nmock-plex-artwork".to_vec(),
                    )
                } else {
                    ("404 Not Found", "application/json", b"{}".to_vec())
                };

                let hdr = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(hdr.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });

    let server_url = format!("http://{}", addr);
    let saved_url =
        save_plex_server_configuration("Nexus Plex", &server_url, "plex-secret-7788", true)
            .expect("save plex config");
    assert_eq!(saved_url, server_url);

    // Test connection endpoint with masked token persists verified machineIdentifier
    let test_resp = test_streaming_server(Json(TestStreamingServerReq {
        provider: "plex".to_string(),
        url: server_url.clone(),
        api_key: "****7788".to_string(),
    }))
    .await;
    assert_eq!(test_resp.status(), StatusCode::OK);
    let test_bytes = axum::body::to_bytes(test_resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let test_json: serde_json::Value = serde_json::from_slice(&test_bytes).unwrap();
    assert_eq!(test_json["ok"], true);
    assert_eq!(test_json["server"]["serverId"], "plex-machine-001");
    assert_eq!(test_json["server"]["supportStage"], "active");
    assert_eq!(test_json["server"]["libraryCounts"]["movies"], 412);
    assert_eq!(test_json["server"]["libraryCounts"]["series"], 85);

    // Poll live sessions & record canonical watch-history snapshots
    let live_sessions = fetch_plex_live_sessions(
        "Nexus Plex",
        &server_url,
        "plex-secret-7788",
        Some("plex-machine-001"),
    )
    .await
    .expect("fetch plex live sessions");
    assert_eq!(live_sessions.len(), 1);
    assert_eq!(live_sessions[0].provider, "plex");
    assert_eq!(live_sessions[0].user_name, "Cassian");
    assert_eq!(live_sessions[0].series_name, "Andor");
    assert_eq!(live_sessions[0].item_name, "One Way Out");
    assert_eq!(live_sessions[0].play_method, "Transcode");
    assert_eq!(live_sessions[0].bitrate_bps, 18_500_000);
    assert_eq!(live_sessions[0].position_secs, 1350);
    assert_eq!(live_sessions[0].duration_secs, 2700);

    record_live_sessions_snapshot_for_source(
        "plex",
        &live_sessions,
        15,
        Some((&server_url, "plex-machine-001")),
    );

    let admin_dash = build_streaming_dashboard("30", "all", "all", true).await;
    let plex_srv = admin_dash
        .servers
        .iter()
        .find(|s| s.provider == "plex")
        .expect("plex server entry");
    assert_eq!(plex_srv.status, "connected");
    assert_eq!(plex_srv.support_stage, "active");
    assert_eq!(plex_srv.api_key_masked, "****7788");
    assert_eq!(admin_dash.active_sessions.len(), 1);
    assert_eq!(admin_dash.active_sessions[0].provider, "plex");

    // Verify canonical observed_session row persisted in `streaming_history`
    let conn = af_db::get_conn().unwrap();
    let (persisted_title, persisted_prov): (String, String) = conn
        .query_row(
            "SELECT item_name, provider FROM streaming_history WHERE provider = 'plex' AND provenance = 'observed_session' LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("persisted plex observed_session");
    assert_eq!(persisted_prov, "plex");
    assert_eq!(persisted_title, "One Way Out");
    drop(conn);

    server_handle.abort();
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[tokio::test]
async fn test_jellyfin_summary_sync_partial_vs_completed_batches_and_deterministic_sort() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let db_path = init_isolated_streaming_db("jellyfin_summary_sync_paged");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen_sort = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen_sort_srv = std::sync::Arc::clone(&seen_sort);

    let server_handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let seen_flag = std::sync::Arc::clone(&seen_sort_srv);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let body = if first_line.contains("/System/Info") {
                    serde_json::json!({
                        "Id": "jf-paged-srv",
                        "ServerName": "Paged Jellyfin",
                        "Version": "10.10.6",
                        "OperatingSystem": "Linux"
                    })
                    .to_string()
                } else if first_line.contains("GET /Users ") || first_line.contains("GET /Users?") {
                    serde_json::json!([
                        { "Id": "u-1", "Name": "alice" },
                        { "Id": "u-2", "Name": "bob" }
                    ])
                    .to_string()
                } else if first_line.contains("Filters=IsPlayed")
                    && first_line.contains("/Users/u-1/Items")
                {
                    if first_line.contains("SortBy=SortName,Id&SortOrder=Ascending") {
                        seen_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    let start_idx: usize = first_line
                        .split("StartIndex=")
                        .nth(1)
                        .and_then(|s| s.split([' ', '&']).next())
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let total = 950usize; // 10 pages of 100 -> exceeds 8-page batch budget!
                    if start_idx >= total {
                        serde_json::json!({ "TotalRecordCount": total, "Items": [] }).to_string()
                    } else {
                        let take = (total - start_idx).min(100);
                        let items: Vec<serde_json::Value> = (start_idx..start_idx + take)
                            .map(|i| {
                                serde_json::json!({
                                    "Id": format!("item-{i:04}"),
                                    "Name": format!("Movie {i:04}"),
                                    "Type": "Movie",
                                    "RunTimeTicks": 36_000_000_000i64,
                                    "UserData": {
                                        "Played": true,
                                        "PlayedPercentage": 100.0,
                                        "LastPlayedDate": "2026-10-20T20:00:00Z"
                                    }
                                })
                            })
                            .collect();
                        serde_json::json!({
                            "TotalRecordCount": total,
                            "Items": items
                        })
                        .to_string()
                    }
                } else {
                    serde_json::json!({ "TotalRecordCount": 0, "Items": [] }).to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });

    {
        let conn = af_db::get_conn().unwrap();
        let enc_key = af_db::encrypt_key("paged-sync-token-1234").unwrap_or_default();
        conn.execute(
            "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Paged Jellyfin', ?1, ?2, 1)",
            params![format!("http://{}", addr), enc_key],
        )
        .unwrap();
    }

    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "jti-sync".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    // First HTTP sync: consumes 8 pages (800 items), returns partial batch with has_more=true
    let resp1 = sync_streaming_server_history(
        Extension(admin.clone()),
        Path("jellyfin".to_string()),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp1.into_body(), 64 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(seen_sort.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(body1["imported"], 800);
    assert_eq!(body1["complete"], false);
    assert_eq!(body1["has_more"], true);
    assert_eq!(body1["remaining_sources"], 4);
    assert_eq!(body1["next_offset"], 800);
    assert_eq!(
        body1["message"],
        "Jellyfin watch history batch synchronized (more items remain; run sync again to continue)"
    );

    // Second HTTP sync: finishes remaining 150 items + remaining empty sources, returns complete=true
    let resp2 = sync_streaming_server_history(
        Extension(admin),
        Path("jellyfin".to_string()),
        HeaderMap::new(),
    )
    .await;
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp2.into_body(), 64 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body2["imported"], 150);
    assert_eq!(body2["complete"], true);
    assert_eq!(body2["has_more"], false);
    assert_eq!(body2["remaining_sources"], 0);
    assert!(body2["next_offset"].is_null());
    assert_eq!(body2["message"], "Jellyfin watch history synchronized");

    server_handle.abort();
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}
