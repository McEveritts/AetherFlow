#![allow(clippy::await_holding_lock)]

use super::{
    init_isolated_streaming_db, mark_dashboard_fixtures_as_observed, TEST_STREAMING_DB_LOCK,
};
use crate::auth::AuthUser;
use crate::streaming_ext::analytics::streaming_time_buckets;
use crate::streaming_ext::{
    build_streaming_dashboard, get_streaming_dashboard_handler, parse_window_days,
    query_streaming_analytics,
};
use axum::body::Body;
use axum::extract::{Query, Request};
use axum::http::StatusCode;
use chrono::{Datelike, Months, NaiveDate, Utc};
use rusqlite::params;
use std::collections::HashMap;

#[test]
fn test_dashboard_preserves_imported_estimates_without_double_counting_confirmed_time() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = init_isolated_streaming_db("imported_estimates");
    let now = Utc::now();
    let old = (now - chrono::Duration::days(45))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let current = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let conn = af_db::get_conn().unwrap();
    for (key, provenance, timestamp, seconds, policy, user) in [
        (
            "legacy",
            "legacy_unverified",
            old.as_str(),
            3600,
            "included",
            "viewer",
        ),
        (
            "summary",
            "item_summary",
            old.as_str(),
            3600,
            "included",
            "viewer",
        ),
        ("undated", "item_summary", "", 600, "included", "viewer"),
        (
            "negative",
            "legacy_unverified",
            old.as_str(),
            -5,
            "included",
            "viewer",
        ),
        (
            "observed",
            "observed_session",
            current.as_str(),
            120,
            "included",
            "viewer",
        ),
        (
            "event",
            "imported_event",
            current.as_str(),
            240,
            "included",
            "viewer",
        ),
        (
            "excluded",
            "legacy_unverified",
            old.as_str(),
            9999,
            "excluded",
            "viewer",
        ),
        (
            "duplicate",
            "item_summary",
            old.as_str(),
            9999,
            "duplicate",
            "viewer",
        ),
        (
            "hidden-user",
            "item_summary",
            old.as_str(),
            9999,
            "included",
            "hidden",
        ),
    ] {
        conn.execute(
            "INSERT INTO streaming_history (session_key,provider,server_id,user_id,item_id,item_type,started_at,watched_secs,provenance,policy_status) VALUES (?1,'jellyfin','server',?2,'same-item','Movie',?3,?4,?5,?6)",
            params![key, user, timestamp, seconds, provenance, policy],
        )
        .unwrap();
    }
    conn.execute(
        "UPDATE streaming_tracking_policies SET excluded_users='[{\"provider\":\"jellyfin\",\"serverId\":\"server\",\"id\":\"hidden\"}]'",
        [],
    )
    .unwrap();
    let before: (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*),SUM(watched_secs) FROM streaming_history",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    drop(conn);
    let all = query_streaming_analytics(0, "all", "all", false, true, 0.0);
    assert_eq!(all.total_plays, 2);
    assert_eq!(all.total_watch_time_secs, 360);
    assert_eq!(all.total_data_used_bytes, 0);
    assert_eq!(all.historical_estimates.len(), 2);
    let item = all
        .historical_estimates
        .iter()
        .find(|estimate| estimate.provenance == "item_summary")
        .unwrap();
    assert_eq!(
        (
            item.records,
            item.reported_watch_time_secs,
            item.undated_records
        ),
        (2, 4200, 1)
    );
    let legacy = all
        .historical_estimates
        .iter()
        .find(|estimate| estimate.provenance == "legacy_unverified")
        .unwrap();
    assert_eq!((legacy.records, legacy.reported_watch_time_secs), (2, 3600));
    for estimate in &all.historical_estimates {
        assert_eq!(estimate.time_series.len(), all.time_series.len());
        assert_eq!(
            estimate
                .time_series
                .iter()
                .map(|point| point.watch_time_secs)
                .sum::<i64>(),
            3600
        );
        assert!(estimate
            .time_series
            .iter()
            .any(|point| point.date == old[..10] && point.watch_time_secs == 3600));
        assert!(estimate
            .time_series
            .iter()
            .all(|point| point.data_used_bytes == 0 && point.direct_play_count == 0));
    }
    assert!(all.time_series.first().unwrap().date.as_str() <= &old[..10]);
    assert!(query_streaming_analytics(7, "all", "all", false, true, 0.0)
        .historical_estimates
        .is_empty());
    assert!(
        query_streaming_analytics(0, "transcode", "all", false, true, 0.0)
            .historical_estimates
            .is_empty()
    );
    assert!(
        query_streaming_analytics(0, "all", "episode", false, true, 0.0)
            .historical_estimates
            .is_empty()
    );
    assert!(query_streaming_analytics(0, "all", "all", true, true, 0.0)
        .historical_estimates
        .is_empty());
    let conn = af_db::get_conn().unwrap();
    let after: (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*),SUM(watched_secs) FROM streaming_history",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(before, after);
    conn.execute(
        "UPDATE streaming_tracking_policies SET minimum_watch_secs=180",
        [],
    )
    .unwrap();
    drop(conn);
    let threshold = query_streaming_analytics(0, "all", "all", false, true, 0.0);
    assert_eq!(threshold.total_plays, 1);
    assert_eq!(threshold.total_watch_time_secs, 240);
    assert_eq!(threshold.historical_estimates[0].records, 2);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[tokio::test]
async fn test_nonadmin_dashboard_withholds_unscoped_legacy_cohorts() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("dashboard_private_scope");
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("UPDATE streaming_servers SET enabled = 0", [])
            .unwrap();
        conn.execute("INSERT INTO streaming_history(session_key,user_id,user_name,item_id,item_name,watched_secs,data_used_bytes) VALUES('private-session','another-user','Private Person','private-item','Private Title',900,123456)", []).unwrap();
    }
    let mut request = Request::new(Body::empty());
    request.extensions_mut().insert(AuthUser {
        user_id: 1,
        username: "unlinked".into(),
        role: "user".into(),
        jti: "test".into(),
        plugin_id: None,
        plugin_scopes: vec![],
    });
    let response = get_streaming_dashboard_handler(Query(HashMap::new()), request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!text.contains("Private Person"));
    assert!(!text.contains("Private Title"));
    assert!(!text.contains("private-session"));
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["analytics"]["totalPlays"], 0);
    assert_eq!(json["analytics"]["totalWatchTimeSecs"], 0);
    assert!(json["activeSessions"].as_array().unwrap().is_empty());
    assert!(json["analytics"]["topUsers"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[tokio::test]
async fn test_streaming_dashboard_contract_filters_and_redaction() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("contract_filters");

    // 1. Verify empty state contract (empty arrays [], coming_soon statuses, zero metrics)
    let empty_resp = build_streaming_dashboard("30", "all", "all", false).await;
    let empty_json = serde_json::to_value(&empty_resp).expect("serialize empty dashboard");

    assert!(empty_json.get("activeSessions").unwrap().is_array());
    assert_eq!(empty_json["activeSessions"].as_array().unwrap().len(), 0);
    assert!(empty_json.get("liveSessions").is_none());
    assert!(empty_json.get("updatedAt").unwrap().is_string());
    assert!(empty_json.get("generatedAt").is_none());

    let servers = empty_json["servers"].as_array().expect("servers array");
    assert_eq!(servers.len(), 3);
    assert_eq!(servers[0]["provider"], "jellyfin");
    assert_eq!(servers[0]["status"], "unconfigured");
    assert_eq!(servers[1]["provider"], "plex");
    assert_eq!(servers[1]["status"], "unconfigured");
    assert_eq!(servers[1]["supportStage"], "active");
    assert_eq!(servers[2]["provider"], "emby");
    assert_eq!(servers[2]["status"], "coming_soon");
    assert_eq!(servers[2]["supportStage"], "coming_soon");

    let empty_analytics = &empty_json["analytics"];
    assert_eq!(empty_analytics["windowDays"], 30);
    assert_eq!(empty_analytics["totalPlays"], 0);
    assert_eq!(empty_analytics["totalWatchTimeSecs"], 0);
    assert_eq!(empty_analytics["totalDataUsedBytes"], 0);
    assert!(empty_analytics.get("totalWatchedSecs").is_none());
    assert!(empty_analytics.get("totalDataBytes").is_none());
    assert!(empty_analytics["mediaTypeBreakdown"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(empty_analytics["resolutionBreakdown"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(empty_analytics["codecBreakdown"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(empty_analytics["topUsers"].as_array().unwrap().is_empty());
    assert!(empty_analytics["topTitles"].as_array().unwrap().is_empty());
    assert!(empty_analytics["recentHistory"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(empty_analytics["timeSeries"].as_array().unwrap().len(), 31);

    // 2. Seed realistic production-shaped Jellyfin history rows + bandwidth sample + server config
    let now = Utc::now();
    let recent_ts = (now - chrono::Duration::days(2))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let older_ts = (now - chrono::Duration::days(20))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    {
        let conn = af_db::get_conn().expect("db conn");
        let enc_key = af_db::encrypt_key("abcdef1234567890").unwrap_or_default();
        conn.execute(
            "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled) VALUES ('jellyfin', 'Vault Jellyfin', 'http://127.0.0.1:1', ?1, 1)",
            params![enc_key],
        )
        .unwrap();

        // Row 1: DirectPlay Movie 2 days ago (24.5 Mbps)
        conn.execute(
            r#"
            INSERT INTO streaming_history (
                session_key, provider, server_name, user_id, user_name,
                client_name, device_name, ip_address,
                item_id, item_name, item_type, series_name,
                season_number, episode_number, production_year,
                play_method, container, video_codec, video_resolution,
                audio_codec, audio_channels, hw_accel, bitrate_bps,
                duration_secs, watched_secs, data_used_bytes, completion_pct,
                started_at, last_seen_at, ended_at, is_active
            ) VALUES (
                'jf:sess:1', 'jellyfin', 'Vault Jellyfin', 'u1', 'alice',
                'Jellyfin Media Player', 'Apple TV', '192.168.1.50',
                'item-1', 'Oppenheimer', 'Movie', '',
                0, 0, 2023,
                'DirectPlay', 'MKV', 'HEVC', '4K UHD',
                'TRUEHD', 8, '', 24500000,
                10800, 10800, 33075000000, 100.0,
                ?1, ?1, ?1, 0
            )
            "#,
            params![recent_ts],
        )
        .unwrap();

        // Row 2: Transcode Episode 20 days ago (8.4 Mbps)
        conn.execute(
            r#"
            INSERT INTO streaming_history (
                session_key, provider, server_name, user_id, user_name,
                client_name, device_name, ip_address,
                item_id, item_name, item_type, series_name,
                season_number, episode_number, production_year,
                play_method, container, video_codec, video_resolution,
                audio_codec, audio_channels, hw_accel, bitrate_bps,
                duration_secs, watched_secs, data_used_bytes, completion_pct,
                started_at, last_seen_at, ended_at, is_active
            ) VALUES (
                'jf:sess:2', 'jellyfin', 'Vault Jellyfin', 'u2', 'bob',
                'Swiftfin', 'iPhone 16', '198.51.100.22',
                'item-2', 'Hello, Ms. Cobel', 'Episode', 'Severance',
                1, 1, 2022,
                'Transcode', 'TS', 'H264', '1080p FHD',
                'AAC', 2, 'NVENC', 8400000,
                3300, 1650, 1732500000, 50.0,
                ?1, ?1, ?1, 0
            )
            "#,
            params![older_ts],
        )
        .unwrap();

        // Bandwidth sample with higher concurrent bitrate (42.0 Mbps)
        conn.execute(
            r#"
            INSERT INTO streaming_bandwidth_samples (
                provider, timestamp, active_streams, direct_play_count, direct_stream_count, transcode_count, total_bitrate_bps, bytes_delta
            ) VALUES (
                'jellyfin', ?1, 2, 1, 0, 1, 42000000, 78750000
            )
            "#,
            params![recent_ts],
        )
        .unwrap();
    }

    // 3. Admin query over 30-day window
    mark_dashboard_fixtures_as_observed();
    let admin_resp = build_streaming_dashboard("30", "all", "all", true).await;
    let admin_json = serde_json::to_value(&admin_resp).expect("serialize admin dashboard");

    // Unreachable Jellyfin status (port 1 fails connection) and masked API key for admin
    let jf_srv = &admin_json["servers"][0];
    assert_eq!(jf_srv["status"], "unavailable");
    assert_eq!(jf_srv["apiKeyMasked"], "****7890");

    let an = &admin_json["analytics"];
    assert_eq!(an["totalPlays"], 2);
    assert_eq!(an["totalWatchTimeSecs"], 12450);
    assert_eq!(an["totalDataUsedBytes"], 34807500000i64);
    assert_eq!(an["uniqueUsers"], 2);
    assert_eq!(an["uniqueTitles"], 2);
    assert_eq!(an["avgCompletionPct"], 75.0);
    assert_eq!(an["peakBandwidthMbps"], 42.0);

    let st = &an["streamTypes"];
    assert_eq!(st["directPlayCount"], 1);
    assert_eq!(st["directStreamCount"], 0);
    assert_eq!(st["transcodeCount"], 1);
    assert_eq!(st["directPlayPct"], 50.0);
    assert_eq!(st["transcodePct"], 50.0);
    assert!(st.get("directPlay").is_none());

    // Breakdown entries must have label, count, pct, watchTimeSecs, dataUsedBytes
    let mt_bd = an["mediaTypeBreakdown"].as_array().unwrap();
    assert_eq!(mt_bd.len(), 2);
    assert!(mt_bd[0].get("pct").is_some());
    assert!(mt_bd[0].get("watchTimeSecs").is_some());
    assert!(mt_bd[0].get("dataUsedBytes").is_some());
    assert!(mt_bd[0].get("percentage").is_none());

    // TimeSeries points must have date, plays, watchTimeSecs, dataUsedBytes, peakBandwidthMbps, directPlayCount, directStreamCount, transcodeCount
    let ts_arr = an["timeSeries"].as_array().unwrap();
    assert_eq!(ts_arr.len(), 31);
    let sample_pt = &ts_arr[0];
    assert!(sample_pt.get("date").unwrap().is_string());
    assert!(sample_pt.get("watchTimeSecs").is_some());
    assert!(sample_pt.get("dataUsedBytes").is_some());
    assert!(sample_pt.get("peakBandwidthMbps").is_some());
    assert!(sample_pt.get("directPlayCount").is_some());
    assert!(sample_pt.get("directStreamCount").is_some());
    assert!(sample_pt.get("transcodeCount").is_some());

    // Top users and top titles field names
    let top_users = an["topUsers"].as_array().unwrap();
    assert_eq!(top_users.len(), 2);
    assert_eq!(top_users[0]["userName"], "alice");
    assert_eq!(top_users[0]["totalWatchSecs"], 10800);
    assert_eq!(top_users[0]["totalDataBytes"], 33075000000i64);
    assert_eq!(top_users[0]["uniqueItems"], 1);
    assert_eq!(top_users[0]["directPlayCount"], 1);
    assert_eq!(
        top_users[0]["lastDevice"],
        "Jellyfin Media Player · Apple TV"
    );
    assert!(!top_users[0]["lastSeenAt"].as_str().unwrap().is_empty());

    let top_titles = an["topTitles"].as_array().unwrap();
    assert_eq!(top_titles.len(), 2);
    assert!(top_titles[0].get("uniqueViewers").is_some());
    assert!(top_titles[0].get("totalWatchSecs").is_some());
    assert!(top_titles[0].get("totalDataBytes").is_some());
    assert!(top_titles[0].get("lastWatchedAt").is_some());

    // History items must include sessionKey, bandwidthMbps, lastSeenAt, and IP for admin
    let hist = an["recentHistory"].as_array().unwrap();
    assert_eq!(hist.len(), 2);
    assert_eq!(hist[0]["sessionKey"], "jf:sess:1");
    assert_eq!(hist[0]["bandwidthMbps"], 24.5);
    assert_eq!(hist[0]["ipAddress"], "192.168.1.50");
    assert!(!hist[0]["lastSeenAt"].as_str().unwrap().is_empty());
    assert_eq!(hist[1]["sessionKey"], "jf:sess:2");
    assert_eq!(hist[1]["bandwidthMbps"], 8.4);

    // 4. Non-admin redaction check
    mark_dashboard_fixtures_as_observed();
    let non_admin_resp = build_streaming_dashboard("30", "all", "all", false).await;
    assert_eq!(non_admin_resp.servers[0].api_key_masked, "");
    assert_eq!(non_admin_resp.analytics.recent_history[0].ip_address, "");
    assert_eq!(non_admin_resp.analytics.recent_history[1].ip_address, "");

    // 5. Filter checks: window=7 excludes the 20-day-old row
    mark_dashboard_fixtures_as_observed();
    let win7_resp = build_streaming_dashboard("7", "all", "all", true).await;
    assert_eq!(win7_resp.analytics.window_days, 7);
    assert_eq!(win7_resp.analytics.total_plays, 1);
    assert_eq!(win7_resp.analytics.recent_history.len(), 1);
    assert_eq!(
        win7_resp.analytics.recent_history[0].item_name,
        "Oppenheimer"
    );

    // playMethod=Transcode filter
    mark_dashboard_fixtures_as_observed();
    let tc_resp = build_streaming_dashboard("30", "Transcode", "all", true).await;
    assert_eq!(tc_resp.analytics.total_plays, 1);
    assert_eq!(tc_resp.analytics.recent_history.len(), 1);
    assert_eq!(tc_resp.analytics.recent_history[0].play_method, "Transcode");

    // mediaType=Movie filter
    mark_dashboard_fixtures_as_observed();
    let movie_resp = build_streaming_dashboard("30", "all", "Movie", true).await;
    assert_eq!(movie_resp.analytics.total_plays, 1);
    assert_eq!(movie_resp.analytics.recent_history.len(), 1);
    assert_eq!(movie_resp.analytics.recent_history[0].item_type, "Movie");

    // Let the frontend contract test render actual Rust responses, including
    // both empty history and populated live session cards.
    if let Some(path) = std::env::var_os("AF_STREAMING_CONTRACT_FIXTURE") {
        {
            let conn = af_db::get_conn().unwrap();
            conn.execute("UPDATE streaming_servers SET enabled = 0", [])
                .unwrap();
        }
        af_services::set_streaming_demo_mode(true);
        let sessions_resp = build_streaming_dashboard("30", "all", "all", true).await;
        assert!(!sessions_resp.active_sessions.is_empty());
        af_services::set_streaming_demo_mode(false);
        let fixtures = serde_json::json!({
            "empty": empty_json,
            "populated": admin_json,
            "sessions": sessions_resp,
        });
        std::fs::write(path, serde_json::to_vec_pretty(&fixtures).unwrap()).unwrap();
    }

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[test]
fn test_all_time_preserves_older_history_and_reports_bucket_granularity() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("all_time_older_history");
    let now = Utc::now();
    let older_date = (now - chrono::Duration::days(400))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO streaming_history (session_key, started_at, last_seen_at) VALUES ('older-history', ?1, ?1)",
            params![older_date],
        )
        .unwrap();
    }
    mark_dashboard_fixtures_as_observed();
    let daily = query_streaming_analytics(0, "all", "all", false, true, 0.0);
    assert_eq!(daily.window_days, 0);
    assert_eq!(daily.time_series_granularity, "day");
    assert_eq!(daily.time_series.len(), 401);
    assert_eq!(
        daily
            .time_series
            .iter()
            .map(|point| point.plays)
            .sum::<i32>(),
        daily.total_plays
    );

    let earliest = now
        .date_naive()
        .checked_sub_months(Months::new(144))
        .unwrap();
    let earliest_timestamp = format!("{} 12:00:00", earliest.format("%Y-%m-%d"));
    let earliest_bucket = earliest.with_day(1).unwrap().format("%Y-%m-%d").to_string();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO streaming_history (session_key, started_at, last_seen_at, watched_secs, data_used_bytes) VALUES ('oldest-history', ?1, ?1, 60, 30000000)",
            params![earliest_timestamp],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_bandwidth_samples (provider, timestamp, total_bitrate_bps) VALUES ('jellyfin', ?1, 42000000)",
            params![earliest_timestamp],
        )
        .unwrap();
    }
    mark_dashboard_fixtures_as_observed();
    let monthly = query_streaming_analytics(0, "all", "all", false, true, 0.0);
    assert_eq!(monthly.time_series_granularity, "month");
    assert_eq!(monthly.time_series.len(), 145);
    assert_eq!(
        monthly
            .time_series
            .iter()
            .map(|point| point.plays)
            .sum::<i32>(),
        monthly.total_plays
    );
    let first = monthly.time_series.first().unwrap();
    assert_eq!(first.date, earliest_bucket);
    assert_eq!(first.plays, 1);
    assert_eq!(first.watch_time_secs, 60);
    assert_eq!(first.data_used_bytes, 30000000);
    assert_eq!(first.peak_bandwidth_mbps, 42.0);
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[test]
fn test_extreme_all_time_range_uses_bounded_yearly_buckets() {
    let first_day = NaiveDate::from_ymd_opt(1, 1, 1).unwrap();
    let today = NaiveDate::from_ymd_opt(2026, 11, 1).unwrap();
    let (granularity, keys) = streaming_time_buckets(first_day, today);
    assert_eq!(granularity, "year");
    assert_eq!(keys.len(), 2026);
    assert_eq!(keys.first().unwrap(), "0001-01-01");
    assert_eq!(keys.last().unwrap(), "2026-01-01");
}

#[test]
fn test_window_parsing_timeseries_span_and_latest_user_device() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("window_and_leaderboard");

    assert_eq!(parse_window_days("0"), (0, "all"));
    assert_eq!(parse_window_days("all"), (0, "all"));
    assert_eq!(parse_window_days("365"), (365, "365d"));
    assert_eq!(parse_window_days("90d"), (90, "90d"));

    let now = Utc::now();
    let day_120_ago = (now - chrono::Duration::days(120))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let day_2_ago = (now - chrono::Duration::days(2))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let day_2_key = (now - chrono::Duration::days(2))
        .format("%Y-%m-%d")
        .to_string();

    {
        let conn = af_db::get_conn().unwrap();
        // Older row for user "alex" using "Zidoo Player · Z9X" (lexicographically > "Apple TV")
        conn.execute(
            r#"
            INSERT INTO streaming_history (
                session_key, provider, server_name, user_id, user_name,
                client_name, device_name, ip_address,
                item_id, item_name, item_type,
                play_method, video_codec, video_resolution,
                bitrate_bps, duration_secs, watched_secs, data_used_bytes, completion_pct,
                started_at, last_seen_at, ended_at, is_active
            ) VALUES (
                'jf:old:1', 'jellyfin', 'Vault', 'u-alex', 'alex',
                'Zidoo Player', 'Z9X', '192.168.1.20',
                'it-old', 'Old Movie', 'Movie',
                'DirectPlay', 'HEVC', '4K UHD',
                20000000, 7200, 7200, 18000000000, 100.0,
                ?1, ?1, ?1, 0
            )
            "#,
            params![day_120_ago],
        )
        .unwrap();

        // Newer row for user "alex" using "Apple TV · Living Room" (most recent session)
        conn.execute(
            r#"
            INSERT INTO streaming_history (
                session_key, provider, server_name, user_id, user_name,
                client_name, device_name, ip_address,
                item_id, item_name, item_type,
                play_method, video_codec, video_resolution,
                bitrate_bps, duration_secs, watched_secs, data_used_bytes, completion_pct,
                started_at, last_seen_at, ended_at, is_active
            ) VALUES (
                'jf:new:2', 'jellyfin', 'Vault', 'u-alex', 'alex',
                'Apple TV', 'Living Room', '192.168.1.21',
                'it-new', 'New Movie', 'Movie',
                'DirectPlay', 'HEVC', '4K UHD',
                15000000, 5400, 5400, 10125000000, 100.0,
                ?1, ?1, ?1, 0
            )
            "#,
            params![day_2_ago],
        )
        .unwrap();

        // Concurrent bandwidth sample 2 days ago (55.5 Mbps)
        conn.execute(
            r#"
            INSERT INTO streaming_bandwidth_samples (
                provider, timestamp, active_streams, direct_play_count, direct_stream_count, transcode_count, total_bitrate_bps, bytes_delta
            ) VALUES (
                'jellyfin', ?1, 3, 3, 0, 0, 55500000, 104062500
            )
            "#,
            params![day_2_ago],
        )
        .unwrap();
    }

    mark_dashboard_fixtures_as_observed();
    let an_365 = query_streaming_analytics(365, "all", "all", false, true, 0.0);
    assert_eq!(an_365.window_days, 365);
    assert_eq!(an_365.time_series.len(), 366);
    assert_eq!(an_365.total_plays, 2);

    // All-time window (0) must preserve window_days = 0 and span back to the 120-day-old play (121 days)
    mark_dashboard_fixtures_as_observed();
    let an_all = query_streaming_analytics(0, "all", "all", false, true, 0.0);
    assert_eq!(an_all.window_days, 0);
    assert_eq!(an_all.total_plays, 2);
    assert_eq!(an_all.time_series.len(), 121);

    // Daily timeSeries point for 2 days ago must reflect the 55.5 Mbps concurrent sample peak
    let pt_day2 = an_all
        .time_series
        .iter()
        .find(|p| p.date == day_2_key)
        .expect("day 2 point in timeSeries");
    assert_eq!(pt_day2.peak_bandwidth_mbps, 55.5);

    // Top users lastDevice must reflect the most recent session ("Apple TV · Living Room"), not lexicographical MAX ("Zidoo Player · Z9X")
    assert_eq!(an_all.top_users.len(), 1);
    assert_eq!(an_all.top_users[0].last_device, "Apple TV · Living Room");

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[test]
fn test_unknown_filter_percentages_and_latest_device_respect_the_cohort() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("unknown_and_cohort");
    let now = Utc::now();
    let recent = (now - chrono::Duration::days(2))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let latest = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let old = (now - chrono::Duration::days(10))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO streaming_history (session_key, user_name, play_method, item_type, client_name, started_at, last_seen_at) VALUES ('known', 'alex', ' directplay ', 'Movie', 'Original client', ?1, ?1)",
            params![recent],
        )
        .unwrap();
        for index in 0..9 {
            let method = match index % 3 {
                0 => "",
                1 => "Unknown",
                _ => "Unavailable",
            };
            conn.execute(
                "INSERT INTO streaming_history (session_key, user_name, play_method, item_type, started_at, last_seen_at) VALUES (?1, 'alex', ?2, 'Movie', ?3, ?3)",
                params![format!("jellyfin:sync:{index}"), method, recent],
            )
            .unwrap();
        }
    }
    mark_dashboard_fixtures_as_observed();
    let all = query_streaming_analytics(7, "all", "all", false, true, 0.0);
    assert_eq!(all.total_plays, 10);
    assert_eq!(all.stream_types.direct_play_count, 1);
    assert_eq!(all.stream_types.direct_play_pct, 10.0);
    mark_dashboard_fixtures_as_observed();
    let unknown = query_streaming_analytics(7, " UnKnOwN ", "movie", false, true, 0.0);
    assert_eq!(unknown.total_plays, 9);
    assert_eq!(unknown.recent_history.len(), 9);
    assert_eq!(unknown.stream_types.direct_play_count, 0);
    assert_eq!(
        unknown
            .time_series
            .iter()
            .map(|point| point.plays)
            .sum::<i32>(),
        9
    );
    assert_eq!(unknown.top_users[0].last_device, "");
    {
        let conn = af_db::get_conn().unwrap();
        for (key, provider, method, media_type, started_at) in [
            (
                "other-method",
                "jellyfin",
                "Transcode",
                "Movie",
                latest.as_str(),
            ),
            (
                "other-media",
                "jellyfin",
                "DirectPlay",
                "Episode",
                latest.as_str(),
            ),
            ("demo", "demo", "DirectPlay", "Movie", latest.as_str()),
            (
                "outside-window",
                "jellyfin",
                "DirectPlay",
                "Movie",
                old.as_str(),
            ),
        ] {
            conn.execute(
                "INSERT INTO streaming_history (session_key, provider, user_name, play_method, item_type, client_name, started_at, last_seen_at) VALUES (?1, ?2, 'alex', ?3, ?4, ?1, ?5, ?6)",
                params![key, provider, method, media_type, started_at, latest],
            )
            .unwrap();
        }
    }
    mark_dashboard_fixtures_as_observed();
    let filtered = query_streaming_analytics(7, "directplay", "movie", false, true, 0.0);
    assert_eq!(filtered.total_plays, 1);
    assert_eq!(filtered.top_users[0].last_device, "Original client");
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[test]
fn test_rolling_window_keeps_the_partial_boundary_day() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("rolling_boundary");
    let now = Utc::now();
    let boundary = now - chrono::Duration::days(7) + chrono::Duration::minutes(1);
    let timestamp = boundary.format("%Y-%m-%d %H:%M:%S").to_string();
    let date = boundary.format("%Y-%m-%d").to_string();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO streaming_history (session_key, started_at, last_seen_at, watched_secs, data_used_bytes) VALUES ('boundary', ?1, ?1, 60, 30000000)",
            params![timestamp],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_bandwidth_samples (provider, timestamp, total_bitrate_bps) VALUES ('jellyfin', ?1, 42000000)",
            params![timestamp],
        )
        .unwrap();
    }
    mark_dashboard_fixtures_as_observed();
    let analytics = query_streaming_analytics(7, "all", "all", false, true, 0.0);
    assert_eq!(analytics.total_plays, 1);
    assert_eq!(analytics.time_series.len(), 8);
    assert_eq!(
        analytics
            .time_series
            .iter()
            .map(|point| point.plays)
            .sum::<i32>(),
        1
    );
    assert_eq!(
        analytics
            .time_series
            .iter()
            .map(|point| point.watch_time_secs)
            .sum::<i64>(),
        60
    );
    assert_eq!(
        analytics
            .time_series
            .iter()
            .map(|point| point.data_used_bytes)
            .sum::<i64>(),
        30000000
    );
    assert_eq!(
        analytics
            .time_series
            .iter()
            .find(|point| point.date == date)
            .unwrap()
            .peak_bandwidth_mbps,
        42.0
    );
    mark_dashboard_fixtures_as_observed();
    let ten_year = query_streaming_analytics(3650, "all", "all", false, true, 0.0);
    assert_eq!(ten_year.window_days, 3650);
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}
