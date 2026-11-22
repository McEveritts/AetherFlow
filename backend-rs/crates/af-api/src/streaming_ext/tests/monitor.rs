#![allow(clippy::await_holding_lock)]

use super::{init_isolated_streaming_db, TEST_STREAMING_DB_LOCK};
use crate::streaming_ext::config::persist_verified_monitor_source;
use crate::streaming_ext::models::{resolve_session_capabilities, JellyfinSessionRaw};
use crate::streaming_ext::monitor::record_live_sessions_snapshot_for_source;
use crate::streaming_ext::{
    close_disabled_provider, format_observed_session_key, record_live_sessions_snapshot,
};
use af_services::ActiveStreamSession;
use rusqlite::params;

#[test]
fn test_streaming_distinct_elapsed_accounting_and_disable() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = init_isolated_streaming_db("elapsed_accounting");
    let session = ActiveStreamSession {
        session_id: "elapsed".into(),
        item_id: "movie".into(),
        state: "playing".into(),
        bitrate_bps: 8_000_000,
        ..Default::default()
    };
    record_live_sessions_snapshot("jellyfin", std::slice::from_ref(&session), 15);
    record_live_sessions_snapshot("jellyfin", std::slice::from_ref(&session), 15);
    let conn = af_db::get_conn().unwrap();
    assert_eq!(
        conn.query_row("SELECT watched_secs FROM streaming_history", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM streaming_bandwidth_samples",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    conn.execute(
        "UPDATE streaming_session_samples SET sampled_at=CAST(strftime('%s','now') AS INTEGER)-15",
        [],
    )
    .unwrap();
    drop(conn);
    record_live_sessions_snapshot("jellyfin", std::slice::from_ref(&session), 15);
    let conn = af_db::get_conn().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT watched_secs,data_used_bytes FROM streaming_history",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        )
        .unwrap(),
        (15, 15_000_000)
    );
    conn.execute("DELETE FROM streaming_session_samples", [])
        .unwrap();
    conn.execute(
        "INSERT INTO streaming_session_samples SELECT id,CAST(strftime('%s','now') AS INTEGER)-600,15,1,8000000 FROM streaming_history",
        [],
    )
    .unwrap();
    drop(conn);
    record_live_sessions_snapshot("jellyfin", &[session], 15);
    let conn = af_db::get_conn().unwrap();
    assert_eq!(
        conn.query_row("SELECT watched_secs FROM streaming_history", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        15
    );
    conn.execute(
        "UPDATE streaming_servers SET enabled=0 WHERE provider='jellyfin'",
        [],
    )
    .unwrap();
    drop(conn);
    close_disabled_provider("jellyfin");
    let conn = af_db::get_conn().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT is_active,ended_at IS NULL FROM streaming_history",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?))
        )
        .unwrap(),
        (0, true)
    );
    drop(conn);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn test_monitor_identity_cold_start_and_stale_source_refuse_writes() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = init_isolated_streaming_db("monitor_identity");
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO streaming_servers(provider,name,url,server_id,enabled) VALUES ('jellyfin','Test','http://127.0.0.1:8096','',1)",
        [],
    )
    .unwrap();
    assert!(
        persist_verified_monitor_source(&conn, "jellyfin", "http://127.0.0.1:8096", "").is_err()
    );
    assert_eq!(
        persist_verified_monitor_source(
            &conn,
            "jellyfin",
            "http://127.0.0.1:8096/",
            "Server-Verified"
        )
        .unwrap(),
        "Server-Verified"
    );
    assert_eq!(
        persist_verified_monitor_source(
            &conn,
            "jellyfin",
            "http://127.0.0.1:8096",
            "server-verified"
        )
        .unwrap(),
        "Server-Verified"
    );
    assert!(persist_verified_monitor_source(
        &conn,
        "jellyfin",
        "http://127.0.0.1:8096",
        "different-server"
    )
    .is_err());
    assert!(persist_verified_monitor_source(
        &conn,
        "jellyfin",
        "http://127.0.0.1:9999",
        "Server-Verified"
    )
    .is_err());
    let session = ActiveStreamSession {
        session_id: "source-session".to_string(),
        item_id: "source-item".to_string(),
        item_name: "Source item".to_string(),
        ..Default::default()
    };
    drop(conn);
    record_live_sessions_snapshot_for_source(
        "jellyfin",
        std::slice::from_ref(&session),
        15,
        Some(("http://127.0.0.1:8096", "different-server")),
    );
    let conn = af_db::get_conn().unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM streaming_history", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    drop(conn);
    record_live_sessions_snapshot_for_source(
        "jellyfin",
        std::slice::from_ref(&session),
        15,
        Some(("http://127.0.0.1:8096", "Server-Verified")),
    );
    let conn = af_db::get_conn().unwrap();
    assert_eq!(
        conn.query_row("SELECT server_id FROM streaming_history", [], |row| row
            .get::<_, String>(
            0
        ))
        .unwrap(),
        "Server-Verified"
    );
    conn.execute(
        "UPDATE streaming_servers SET enabled=0 WHERE provider='jellyfin'",
        [],
    )
    .unwrap();
    assert!(persist_verified_monitor_source(
        &conn,
        "jellyfin",
        "http://127.0.0.1:8096",
        "Server-Verified"
    )
    .is_err());
    let revision: i64 = conn
        .query_row(
            "SELECT revision FROM streaming_history_revision WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(conn);
    record_live_sessions_snapshot_for_source(
        "jellyfin",
        &[],
        15,
        Some(("http://127.0.0.1:8096", "Server-Verified")),
    );
    let conn = af_db::get_conn().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT revision FROM streaming_history_revision WHERE id=1",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        revision
    );
    drop(conn);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn test_unrecorded_capabilities_deny_commands_and_messages() {
    let unknown = JellyfinSessionRaw::default();
    let (media, remote, message, commands) = resolve_session_capabilities(&unknown);
    assert!(!media);
    assert!(!remote);
    assert!(!message);
    assert!(commands.is_empty());
    let controlled = JellyfinSessionRaw {
        supports_media_control: Some(true),
        ..Default::default()
    };
    assert!(!resolve_session_capabilities(&controlled).2);
}

#[tokio::test]
async fn test_live_session_interleaved_snapshots_seek_resume_and_paused_accounting() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("live_interleaved");

    // Session A: user resumes a movie at 1h30m (position_secs = 5400), initially PAUSED
    let mut sess = ActiveStreamSession {
        session_id: "sess-live-1".to_string(),
        provider: "jellyfin".to_string(),
        server_name: "Vault Jellyfin".to_string(),
        user_id: "u-live".to_string(),
        user_name: "marco".to_string(),
        client_name: "Jellyfin Web".to_string(),
        device_name: "Chrome".to_string(),
        device_id: "dev-chrome".to_string(),
        app_version: "10.10.6".to_string(),
        ip_address: "192.168.1.77".to_string(),
        is_lan: true,
        item_id: "item-movie-resume".to_string(),
        item_name: "Interstellar".to_string(),
        item_type: "Movie".to_string(),
        position_secs: 5400, // Resumed at 90 minutes!
        duration_secs: 10000,
        progress_pct: 54.0,
        state: "paused".to_string(),
        play_method: "DirectPlay".to_string(),
        container: "MKV".to_string(),
        video_codec: "HEVC".to_string(),
        video_resolution: "4K UHD".to_string(),
        audio_codec: "EAC3".to_string(),
        audio_channels: 6,
        bitrate_bps: 16_000_000, // 2,000,000 bytes/sec
        bandwidth_mbps: 0.0,
        session_data_bytes: 0,
        supports_media_control: true,
        supports_remote_control: true,
        can_send_message: true,
        ..Default::default()
    };

    let expected_key =
        format_observed_session_key("jellyfin", "", "sess-live-1", "", "item-movie-resume", 1);

    // 1. First observation: dashboard poll (interval = 0) while paused at 5400s
    record_live_sessions_snapshot("jellyfin", &[sess.clone()], 0);
    // 2. Monitor poll (interval = 15) while still paused at 5400s -> must NOT charge bytes or watch time
    record_live_sessions_snapshot("jellyfin", &[sess.clone()], 15);

    {
        let conn = af_db::get_conn().unwrap();
        let (watched, bytes, active): (i64, i64, i32) = conn
            .query_row(
                "SELECT watched_secs, data_used_bytes, is_active FROM streaming_history WHERE session_key = ?1",
                params![expected_key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(watched, 0);
        assert_eq!(bytes, 0);
        assert_eq!(active, 1);
    }

    // 3. User unpauses (state = "playing") and seeks ahead to 7200s (2 hours).
    // Dashboard refreshes twice (interval = 0) before the 15s monitor fires.
    sess.state = "playing".to_string();
    sess.position_secs = 7200;
    sess.progress_pct = 72.0;
    sess.bandwidth_mbps = 16.0;
    record_live_sessions_snapshot("jellyfin", &[sess.clone()], 0);
    record_live_sessions_snapshot("jellyfin", &[sess.clone()], 0);

    {
        let conn = af_db::get_conn().unwrap();
        let (watched, bytes): (i64, i64) = conn
            .query_row(
                "SELECT watched_secs, data_used_bytes FROM streaming_history WHERE session_key = ?1",
                params![expected_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        // Zero-interval dashboard refreshes must not accrue or reset anything
        assert_eq!(watched, 0);
        assert_eq!(bytes, 0);
    }

    // 4. Background monitor fires once (interval = 15s) -> accrues only real elapsed seconds, NOT 7200s * 2MB/s!
    record_live_sessions_snapshot("jellyfin", &[sess.clone()], 15);

    // 5. Interleaved dashboard poll (interval = 0) and second monitor tick (interval = 15s)
    record_live_sessions_snapshot("jellyfin", &[sess.clone()], 0);
    sess.position_secs = 7230;
    record_live_sessions_snapshot("jellyfin", &[sess.clone()], 15);
    record_live_sessions_snapshot("jellyfin", &[sess.clone()], 0);

    {
        let conn = af_db::get_conn().unwrap();
        let (watched, bytes): (i64, i64) = conn
            .query_row(
                "SELECT watched_secs, data_used_bytes FROM streaming_history WHERE session_key = ?1",
                params![expected_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(watched, 0);
        assert_eq!(bytes, 0);
    }

    // 6. Session ends (empty slice) -> marks session inactive without altering accrued bytes/watch time
    record_live_sessions_snapshot("jellyfin", &[], 15);
    {
        let conn = af_db::get_conn().unwrap();
        let (watched, bytes, active): (i64, i64, i32) = conn
            .query_row(
                "SELECT watched_secs, data_used_bytes, is_active FROM streaming_history WHERE session_key = ?1",
                params![expected_key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(watched, 0);
        assert_eq!(bytes, 0);
        assert_eq!(active, 0);
    }

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[test]
fn test_dashboard_observation_does_not_prune_bandwidth_history() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("pruning");
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO streaming_bandwidth_samples (provider, timestamp) VALUES ('jellyfin', datetime('now', '-91 days'))",
            [],
        )
        .unwrap();
    }
    record_live_sessions_snapshot("jellyfin", &[], 0);
    let count = || {
        af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM streaming_bandwidth_samples",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    };
    assert_eq!(count(), 1);
    record_live_sessions_snapshot("jellyfin", &[], 15);
    assert_eq!(count(), 0);
    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}

#[test]
fn test_observed_session_identity_generations_reconnect_server_and_legacy_isolation() {
    let _guard = TEST_STREAMING_DB_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let db_path = init_isolated_streaming_db("observed_identity_generations");

    let colliding_key_g1 =
        format_observed_session_key("jellyfin", "srv-alpha", "sess-1", "ps-100", "item-blade", 1);
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled, server_id) VALUES ('jellyfin', 'Alpha', 'http://127.0.0.1:8096', 'k', 1, 'srv-alpha')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_id, user_id, user_name, item_id, item_name, watched_secs, data_used_bytes, started_at, last_seen_at, ended_at, is_active, provenance) VALUES ('jellyfin:sess-1:item-blade', 'jellyfin', '', 'u-1', 'nora', 'item-blade', 'Blade Runner', 900, 12000000, '2026-01-01 00:00:00', '2026-01-01 00:15:00', '2026-01-01 00:15:00', 0, 'legacy_unverified')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_id, user_id, user_name, item_id, item_name, watched_secs, data_used_bytes, started_at, last_seen_at, ended_at, is_active, provenance) VALUES (?1, 'jellyfin', 'srv-alpha', 'u-1', 'nora', 'item-blade', 'Blade Runner', 600, 8000000, '2026-01-02 00:00:00', '2026-01-02 00:10:00', '2026-01-02 00:10:00', 0, 'legacy_unverified')",
            params![colliding_key_g1],
        )
        .unwrap();
    }

    let mut s1 = ActiveStreamSession {
        session_id: "sess-1".to_string(),
        play_session_id: "ps-100".to_string(),
        provider: "jellyfin".to_string(),
        server_name: "Alpha".to_string(),
        user_id: "u-1".to_string(),
        user_name: "nora".to_string(),
        client_name: "Infuse".to_string(),
        device_name: "Apple TV".to_string(),
        device_id: "atv-nora".to_string(),
        item_id: "item-blade".to_string(),
        item_name: "Blade Runner".to_string(),
        item_type: "Movie".to_string(),
        state: "playing".to_string(),
        play_method: "DirectPlay".to_string(),
        bitrate_bps: 8_000_000,
        duration_secs: 7000,
        progress_pct: 10.0,
        ..Default::default()
    };

    let rev_before: i64 = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT revision FROM streaming_history_revision WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    record_live_sessions_snapshot("jellyfin", &[s1.clone()], 0);
    let rev_after_zero: i64 = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT revision FROM streaming_history_revision WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rev_before, rev_after_zero);

    record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);
    let play1_key =
        format_observed_session_key("jellyfin", "srv-alpha", "sess-1", "ps-100", "item-blade", 2);
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE streaming_history SET started_at = '2026-10-10 12:00:00' WHERE session_key = ?1",
            params![play1_key],
        )
        .unwrap();
        let (legacy_prov1, legacy_watched1): (String, i64) = conn
            .query_row(
                "SELECT provenance, watched_secs FROM streaming_history WHERE session_key = 'jellyfin:sess-1:item-blade'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(legacy_prov1, "legacy_unverified");
        assert_eq!(legacy_watched1, 900);

        let (legacy_prov2, legacy_watched2): (String, i64) = conn
            .query_row(
                "SELECT provenance, watched_secs FROM streaming_history WHERE session_key = ?1",
                params![colliding_key_g1],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(legacy_prov2, "legacy_unverified");
        assert_eq!(legacy_watched2, 600);
    }

    s1.state = "paused".to_string();
    s1.position_secs = 1800;
    record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);
    s1.state = "playing".to_string();
    s1.position_secs = 2400;
    record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);
    record_live_sessions_snapshot("jellyfin", &[s1.clone()], 180);
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE streaming_history SET last_seen_at = datetime('now', '-95 seconds') WHERE session_key = ?1",
            params![play1_key],
        )
        .unwrap();
    }
    record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);

    {
        let conn = af_db::get_conn().unwrap();
        let (watched, bytes, started, active, prov): (i64, i64, String, i32, String) = conn
            .query_row(
                "SELECT watched_secs, data_used_bytes, started_at, is_active, provenance FROM streaming_history WHERE session_key = ?1",
                params![play1_key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(watched, 0);
        assert_eq!(bytes, 0);
        assert_eq!(started, "2026-10-10 12:00:00");
        assert_eq!(active, 1);
        assert_eq!(prov, "observed_session");
    }

    record_live_sessions_snapshot("jellyfin", &[], 15);
    s1.position_secs = 60;
    record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);

    let play2_key =
        format_observed_session_key("jellyfin", "srv-alpha", "sess-1", "ps-100", "item-blade", 3);
    {
        let conn = af_db::get_conn().unwrap();
        let (w1, act1): (i64, i32) = conn
            .query_row(
                "SELECT watched_secs, is_active FROM streaming_history WHERE session_key = ?1",
                params![play1_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(w1, 0);
        assert_eq!(act1, 0);

        let (w2, act2): (i64, i32) = conn
            .query_row(
                "SELECT watched_secs, is_active FROM streaming_history WHERE session_key = ?1",
                params![play2_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(w2, 0);
        assert_eq!(act2, 1);

        conn.execute(
            "UPDATE streaming_tracking_policies SET reconnect_window_secs = 60 WHERE id = 1",
            [],
        )
        .unwrap();
    }

    record_live_sessions_snapshot("jellyfin", &[], 15);
    record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);
    {
        let conn = af_db::get_conn().unwrap();
        let (w2, act2): (i64, i32) = conn
            .query_row(
                "SELECT watched_secs, is_active FROM streaming_history WHERE session_key = ?1",
                params![play2_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(w2, 0);
        assert_eq!(act2, 1);
    }

    record_live_sessions_snapshot("jellyfin", &[], 15);
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE streaming_history SET ended_at = datetime('now', '-120 seconds'), last_seen_at = datetime('now', '-120 seconds') WHERE session_key = ?1",
            params![play2_key],
        )
        .unwrap();
    }
    record_live_sessions_snapshot("jellyfin", &[s1.clone()], 15);
    let play3_key =
        format_observed_session_key("jellyfin", "srv-alpha", "sess-1", "ps-100", "item-blade", 4);
    {
        let conn = af_db::get_conn().unwrap();
        let (w3, act3): (i64, i32) = conn
            .query_row(
                "SELECT watched_secs, is_active FROM streaming_history WHERE session_key = ?1",
                params![play3_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(w3, 0);
        assert_eq!(act3, 1);
    }

    let mut s1_new_ps = s1.clone();
    s1_new_ps.play_session_id = "ps-200".to_string();
    let mut s2_concurrent = s1.clone();
    s2_concurrent.session_id = "sess-2".to_string();
    s2_concurrent.play_session_id = "ps-300".to_string();
    record_live_sessions_snapshot("jellyfin", &[s1_new_ps.clone(), s2_concurrent.clone()], 15);

    let ps200_key =
        format_observed_session_key("jellyfin", "srv-alpha", "sess-1", "ps-200", "item-blade", 1);
    let concurrent_key =
        format_observed_session_key("jellyfin", "srv-alpha", "sess-2", "ps-300", "item-blade", 1);
    {
        let conn = af_db::get_conn().unwrap();
        let act_old_ps: i32 = conn
            .query_row(
                "SELECT is_active FROM streaming_history WHERE session_key = ?1",
                params![play3_key],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(act_old_ps, 0);

        let act_ps200: i32 = conn
            .query_row(
                "SELECT is_active FROM streaming_history WHERE session_key = ?1",
                params![ps200_key],
                |r| r.get(0),
            )
            .unwrap();
        let act_conc: i32 = conn
            .query_row(
                "SELECT is_active FROM streaming_history WHERE session_key = ?1",
                params![concurrent_key],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(act_ps200, 1);
        assert_eq!(act_conc, 1);

        conn.execute(
            "UPDATE streaming_servers SET server_id = 'srv-beta' WHERE provider = 'jellyfin'",
            [],
        )
        .unwrap();
    }

    record_live_sessions_snapshot("jellyfin", &[s1_new_ps.clone()], 15);
    let beta_key =
        format_observed_session_key("jellyfin", "srv-beta", "sess-1", "ps-200", "item-blade", 1);
    {
        let conn = af_db::get_conn().unwrap();
        let act_alpha: i32 = conn
            .query_row(
                "SELECT is_active FROM streaming_history WHERE session_key = ?1",
                params![ps200_key],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(act_alpha, 1);

        let (act_beta, srv_beta): (i32, String) = conn
            .query_row(
                "SELECT is_active, server_id FROM streaming_history WHERE session_key = ?1",
                params![beta_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(act_beta, 1);
        assert_eq!(srv_beta, "srv-beta");
    }

    let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
}
