use super::validation::current_history_revision;
use super::*;
use crate::auth::AuthUser;
use axum::extract::{Extension, Json, Query};
use axum::http::StatusCode;
use chrono::Utc;
use rusqlite::{params, Connection};

use crate::streaming_history::{query_history, HistoryQuery};

const V19_STREAMING_DDL: &str = r#"
    PRAGMA foreign_keys = ON;
    CREATE TABLE schema_versions (
        version INTEGER PRIMARY KEY,
        applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        description TEXT
    );
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        role TEXT DEFAULT 'user'
    );
    CREATE TABLE admin_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL DEFAULT '',
        target_id TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        ip_address TEXT NOT NULL DEFAULT '',
        user_agent TEXT NOT NULL DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE streaming_servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL DEFAULT 'Jellyfin',
        url TEXT NOT NULL DEFAULT 'http://127.0.0.1:8096',
        api_key TEXT NOT NULL DEFAULT '',
        enabled BOOLEAN DEFAULT 1,
        server_id TEXT DEFAULT '',
        server_version TEXT DEFAULT '',
        last_connected_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE streaming_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_key TEXT UNIQUE NOT NULL,
        provider TEXT NOT NULL DEFAULT 'jellyfin',
        server_name TEXT NOT NULL DEFAULT 'Jellyfin',
        user_id TEXT NOT NULL DEFAULT '',
        user_name TEXT NOT NULL DEFAULT '',
        client_name TEXT NOT NULL DEFAULT '',
        device_name TEXT NOT NULL DEFAULT '',
        device_id TEXT NOT NULL DEFAULT '',
        ip_address TEXT NOT NULL DEFAULT '',
        item_id TEXT NOT NULL DEFAULT '',
        item_name TEXT NOT NULL DEFAULT '',
        item_type TEXT NOT NULL DEFAULT 'Movie',
        series_name TEXT NOT NULL DEFAULT '',
        series_id TEXT NOT NULL DEFAULT '',
        season_number INTEGER DEFAULT 0,
        episode_number INTEGER DEFAULT 0,
        production_year INTEGER DEFAULT 0,
        play_method TEXT NOT NULL DEFAULT 'DirectPlay',
        container TEXT NOT NULL DEFAULT '',
        video_codec TEXT NOT NULL DEFAULT '',
        video_resolution TEXT NOT NULL DEFAULT '',
        audio_codec TEXT NOT NULL DEFAULT '',
        audio_channels INTEGER DEFAULT 0,
        subtitle_codec TEXT NOT NULL DEFAULT '',
        hw_accel TEXT NOT NULL DEFAULT '',
        transcode_reasons TEXT NOT NULL DEFAULT '',
        bitrate_bps INTEGER DEFAULT 0,
        duration_secs INTEGER DEFAULT 0,
        watched_secs INTEGER DEFAULT 0,
        data_used_bytes INTEGER DEFAULT 0,
        completion_pct REAL DEFAULT 0,
        started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        ended_at DATETIME,
        is_active BOOLEAN DEFAULT 0
    );
    INSERT INTO schema_versions(version, description) VALUES (19, 'Streaming analytics');
"#;

const V20_MIGRATION_SQL: &str =
    include_str!("../../../af-db/src/migrations/020_streaming_history.sql");

fn setup_isolated_db() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory SQLite");
    conn.execute_batch(V19_STREAMING_DDL).expect("v19 DDL");
    conn.execute_batch(V20_MIGRATION_SQL).expect("v20 DDL");
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'alice', 'user'), (3, 'bob', 'user')",
        [],
    )
    .expect("seed users");
    conn.execute(
        "INSERT INTO streaming_servers (provider, name, server_id) VALUES ('jellyfin', 'Main Jellyfin', 'srv-main')",
        [],
    )
    .expect("seed streaming_servers");
    conn
}

fn admin_user() -> AuthUser {
    AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "jti-admin-1".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    }
}

fn alice_user() -> AuthUser {
    AuthUser {
        user_id: 2,
        username: "alice".to_string(),
        role: "user".to_string(),
        jti: "jti-user-2".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    }
}

#[tokio::test]
async fn http_handlers_deny_nonadmin_before_database_or_body_access() {
    let user = alice_user();
    let responses = [
        get_streaming_import_status_handler(
            Query(ImportStatusQuery::default()),
            Extension(user.clone()),
        )
        .await,
        get_streaming_policy_handler(Extension(user.clone())).await,
        list_streaming_user_links_handler(Extension(user.clone())).await,
        apply_legacy_reconciliation_handler(
            Extension(user.clone()),
            Json(ReconciliationApplyRequest {
                preview_hash: "not-approved".to_string(),
                approval_token: "not-approved".to_string(),
            }),
        )
        .await,
        crate::streaming_portability::export_handler(Extension(user.clone())).await,
        crate::streaming_portability::preview_handler(
            Extension(user.clone()),
            axum::http::Request::new(axum::body::Body::empty()),
        )
        .await,
        crate::streaming_portability::restore_handler(
            Extension(user),
            axum::http::Request::new(axum::body::Body::empty()),
        )
        .await,
    ];
    for response in responses {
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

fn sample_event(source_event_id: &str, started_at: &str) -> ImportedEventInput {
    ImportedEventInput {
        source_event_id: source_event_id.to_string(),
        user_id: "jf-alice".to_string(),
        user_name: "Alice".to_string(),
        item_id: "item-dune".to_string(),
        item_name: "Dune: Part Two".to_string(),
        item_type: Some("Movie".to_string()),
        series_name: None,
        series_id: None,
        season_number: None,
        episode_number: None,
        production_year: Some(2024),
        started_at: started_at.to_string(),
        ended_at: Some("2026-03-01T21:00:00Z".to_string()),
        watched_secs: Some(3600),
        duration_secs: Some(9900),
        play_method: None, // unknown stays unknown!
        client_name: None,
        device_name: None,
        device_id: None,
        ip_address: None,
        container: None,
        video_codec: None,
        video_resolution: None,
        audio_codec: None,
        audio_channels: None,
        subtitle_codec: None,
        hw_accel: None,
        bitrate_bps: None,
        estimated_bytes: None,
        libraries: vec![ImportLabelInput {
            id: "lib-movies".to_string(),
            name: "Movies".to_string(),
        }],
        genres: vec!["Sci-Fi".to_string()],
    }
}

#[test]
fn checkpoint_compare_and_swap_and_feed_namespaces_prevent_stale_retries() {
    let conn = setup_isolated_db();
    let admin = admin_user();
    let now = 1_772_400_000_i64;
    let first_batch = ImportEventsBatchRequest {
        provider: "jellyfin".to_string(),
        server_id: "srv-main".to_string(),
        server_name: None,
        source: "feed-one".to_string(),
        checkpoint: "batch-one".to_string(),
        expected_checkpoint: None,
        events: vec![sample_event("shared-id", "2026-03-01T20:00:00Z")],
    };
    import_events_batch(&conn, first_batch.clone(), &admin, now).unwrap();
    let retry = import_events_batch(&conn, first_batch.clone(), &admin, now).unwrap();
    assert_eq!(retry.deduplicated_retries, 1);
    let mut reused_checkpoint = first_batch.clone();
    reused_checkpoint
        .events
        .push(sample_event("unexpected-id", "2026-03-01T21:00:00Z"));
    for expected_checkpoint in [
        None,
        Some("batch-one".to_string()),
        Some("stale".to_string()),
    ] {
        reused_checkpoint.expected_checkpoint = expected_checkpoint;
        let error = import_events_batch(&conn, reused_checkpoint.clone(), &admin, now).unwrap_err();
        assert_eq!(error.code, "import_checkpoint_reused");
    }
    let mut second_batch = first_batch.clone();
    second_batch.checkpoint = "batch-two".to_string();
    second_batch.expected_checkpoint = Some("batch-one".to_string());
    second_batch.events[0].source_event_id = "another-id".to_string();
    second_batch.events[0].user_id = "other-viewer".to_string();
    import_events_batch(&conn, second_batch, &admin, now + 1).unwrap();
    let stale = import_events_batch(&conn, first_batch.clone(), &admin, now + 2).unwrap_err();
    assert_eq!(stale.code, "import_checkpoint_changed");
    let mut other_feed = first_batch;
    other_feed.source = "feed-two".to_string();
    other_feed.events[0].user_id = "third-viewer".to_string();
    let imported = import_events_batch(&conn, other_feed, &admin, now + 3).unwrap();
    assert_eq!(imported.deduplicated_retries, 0);
    assert_eq!(imported.inserted_included, 1);
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT source_event_id) FROM streaming_history",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 3);
    let checkpoint: String = conn
        .query_row(
            "SELECT checkpoint FROM streaming_import_checkpoints WHERE source = 'feed-one'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(checkpoint, "batch-two");
}

#[test]
fn cross_source_overlaps_are_ambiguous_with_zero_reconnect_window() {
    let conn = setup_isolated_db();
    let admin = admin_user();
    conn.execute(
        "UPDATE streaming_tracking_policies SET reconnect_window_secs=0 WHERE id=1",
        [],
    )
    .unwrap();
    let mut batch = ImportEventsBatchRequest {
        provider: "jellyfin".to_string(),
        server_id: "srv-main".to_string(),
        server_name: None,
        source: "feed-one".to_string(),
        checkpoint: "batch-one".to_string(),
        expected_checkpoint: None,
        events: vec![sample_event("event-one", "2026-03-01T20:00:00Z")],
    };
    import_events_batch(&conn, batch.clone(), &admin, 1_772_400_000).unwrap();
    batch.source = "feed-two".to_string();
    let response = import_events_batch(&conn, batch, &admin, 1_772_400_001).unwrap();
    assert_eq!(response.inserted_included, 0);
    assert_eq!(response.ambiguous_overlaps, 1);
    let included: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM streaming_history WHERE policy_status='included'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(included, 1);
}

#[test]
fn reconciliation_requires_a_real_disk_backup() {
    let conn = setup_isolated_db();
    let admin = admin_user();
    conn.execute("INSERT INTO streaming_history(session_key,started_at) VALUES ('jellyfin:sync:old:item','1970-01-01 00:00:00')", []).unwrap();
    let revision = current_history_revision(&conn).unwrap();
    let preview =
        preview_legacy_reconciliation(&conn, ReconciliationPreviewRequest::default(), &admin, 1000)
            .unwrap();
    let error = apply_legacy_reconciliation_with_db_path(
        &conn,
        ":memory:",
        ReconciliationApplyRequest {
            preview_hash: preview.preview_hash,
            approval_token: preview.approval_token,
        },
        &admin,
        1001,
    )
    .unwrap_err();
    assert_eq!(error.code, "streaming_backup_required");
    assert_eq!(current_history_revision(&conn).unwrap(), revision);
    let provenance: String = conn
        .query_row("SELECT provenance FROM streaming_history", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(provenance, "legacy_unverified");
}

#[test]
fn reconciliation_rejects_insert_only_drift_without_invalidating_archive_watermarks() {
    let conn = setup_isolated_db();
    let admin = admin_user();
    let now = 1_772_400_000_i64;
    conn.execute("INSERT INTO streaming_history(session_key, started_at) VALUES ('jellyfin:sync:legacy-user:legacy-item', '1970-01-01 00:00:00')", []).unwrap();
    let preview =
        preview_legacy_reconciliation(&conn, ReconciliationPreviewRequest::default(), &admin, now)
            .unwrap();
    assert_eq!(preview.total_affected_rows, 1);
    conn.execute("INSERT INTO streaming_history(session_key, provenance, started_at) VALUES ('new-observed-evidence', 'observed_session', '2026-03-01 20:00:00')", []).unwrap();
    assert_eq!(
        current_history_revision(&conn).unwrap(),
        preview.history_revision
    );
    let error = apply_legacy_reconciliation_with_db_path(
        &conn,
        ":memory:",
        ReconciliationApplyRequest {
            preview_hash: preview.preview_hash,
            approval_token: preview.approval_token,
        },
        &admin,
        now + 1,
    )
    .unwrap_err();
    assert_eq!(error.code, "reconciliation_stale");
    let provenance: String = conn.query_row("SELECT provenance FROM streaming_history WHERE session_key = 'jellyfin:sync:legacy-user:legacy-item'", [], |row| row.get(0)).unwrap();
    assert_eq!(provenance, "legacy_unverified");
}

#[test]
fn event_import_idempotent_retry_checkpoint_and_unknown_details_preserved() {
    let conn = setup_isolated_db();
    let admin = admin_user();
    let now = 1_772_400_000_i64;

    let req = ImportEventsBatchRequest {
        provider: "jellyfin".to_string(),
        server_id: "srv-main".to_string(),
        server_name: Some("Main Jellyfin".to_string()),
        source: "playback_reporting_export".to_string(),
        checkpoint: "cursor-batch-1".to_string(),
        expected_checkpoint: None,
        events: vec![sample_event("evt-1001", "2026-03-01T20:00:00Z")],
    };

    let first = import_events_batch(&conn, req.clone(), &admin, now).expect("first import");
    assert_eq!(first.inserted_included, 1);
    assert_eq!(first.deduplicated_retries, 0);
    assert_eq!(first.cumulative_imported, 1);

    // Retrying the exact same event with a new checkpoint must deduplicate without double counting
    let mut retry_req = req;
    retry_req.expected_checkpoint = Some(retry_req.checkpoint.clone());
    retry_req.checkpoint = "cursor-batch-1-retry".to_string();
    let second = import_events_batch(&conn, retry_req, &admin, now + 10).expect("retry import");
    assert_eq!(second.inserted_included, 0);
    assert_eq!(second.deduplicated_retries, 1);
    assert_eq!(second.cumulative_imported, 1);

    // Verify canonical history query surfaces the event with unknown playMethod/client/device/estimatedBytes as None
    let page = query_history(&conn, HistoryQuery::default(), &admin, now + 20)
        .expect("canonical history query");
    assert_eq!(page.counts.confirmed_plays, 1);
    assert_eq!(page.counts.watch_time_secs, 3600);
    assert_eq!(page.counts.estimated_bytes, 0);
    assert_eq!(page.items.len(), 1);
    let item = &page.items[0];
    assert_eq!(item.provenance, "imported_event");
    assert_eq!(item.timestamp_certainty, "source_event");
    assert_eq!(item.byte_accuracy, "unrecorded");
    assert_eq!(item.play_method, None);
    assert_eq!(item.client_name, None);
    assert_eq!(item.device_name, None);
    assert_eq!(item.estimated_bytes, None);
    assert_eq!(item.library_ids, vec!["lib-movies".to_string()]);
    assert_eq!(item.genres, vec!["Sci-Fi".to_string()]);

    // Verify checkpoint status endpoint contract
    let status =
        get_import_status(&conn, ImportStatusQuery::default(), &admin).expect("import status");
    assert_eq!(status.checkpoints.len(), 1);
    assert_eq!(status.checkpoints[0].checkpoint, "cursor-batch-1-retry");
    assert_eq!(status.checkpoints[0].imported, 1);
    assert!(!status.capabilities[0].upstream_direct_fetch_available);
}

#[test]
fn confirmed_overlap_deduplicates_while_ambiguous_overlap_and_concurrent_sessions_stay_conservative(
) {
    let conn = setup_isolated_db();
    let admin = admin_user();
    let now = 1_772_400_000_i64;

    // 1. Seed a completed observed_session for Alice watching item-dune from 20:00:00 to 21:00:00
    conn.execute(
        "INSERT INTO streaming_history (
            session_key, provider, server_id, user_id, user_name, client_name, device_name,
            item_id, item_name, item_type, play_method, watched_secs, duration_secs,
            started_at, last_seen_at, ended_at, is_active,
            provenance, timestamp_certainty, byte_accuracy, policy_status
         ) VALUES (
            'jf:srv-main:obs-1', 'jellyfin', 'srv-main', 'jf-alice', 'Alice', 'Jellyfin Web', 'Firefox',
            'item-dune', 'Dune: Part Two', 'Movie', 'DirectPlay', 3580, 9900,
            '2026-03-01 20:00:10', '2026-03-01 21:00:05', '2026-03-01 21:00:05', 0,
            'observed_session', 'observed', 'estimated', 'included'
         )",
        [],
    )
    .expect("insert observed_session 1");

    // 2. Seed an observed_session with a pause/poll gap or conflicting client for item-arrival
    conn.execute(
        "INSERT INTO streaming_history (
            session_key, provider, server_id, user_id, user_name, client_name, device_name,
            item_id, item_name, item_type, play_method, watched_secs, duration_secs,
            started_at, last_seen_at, ended_at, is_active,
            provenance, timestamp_certainty, byte_accuracy, policy_status
         ) VALUES (
            'jf:srv-main:obs-2', 'jellyfin', 'srv-main', 'jf-alice', 'Alice', 'Swiftfin', 'Apple TV',
            'item-arrival', 'Arrival', 'Movie', 'DirectPlay', 1800, 6960,
            '2026-03-01 22:00:00', '2026-03-01 22:30:00', '2026-03-01 22:30:00', 0,
            'observed_session', 'observed', 'estimated', 'included'
         )",
        [],
    )
    .expect("insert observed_session 2");

    let mut confirmed_dup_evt = sample_event("evt-dup-1", "2026-03-01T20:00:00Z");
    confirmed_dup_evt.client_name = Some("Jellyfin Web".to_string());
    confirmed_dup_evt.device_name = Some("Firefox".to_string());

    // Ambiguous overlap: same user+item+window as obs-2, but conflicting client ("Infuse" vs "Swiftfin")
    let mut ambiguous_evt = sample_event("evt-ambig-1", "2026-03-01T22:00:15Z");
    ambiguous_evt.item_id = "item-arrival".to_string();
    ambiguous_evt.item_name = "Arrival".to_string();
    ambiguous_evt.ended_at = Some("2026-03-01T22:30:10Z".to_string());
    ambiguous_evt.watched_secs = Some(1800);
    ambiguous_evt.client_name = Some("Infuse".to_string());
    ambiguous_evt.device_name = Some("iPad".to_string());

    // Repeat play of item-dune 3 hours later (no overlap) -> must be included as a separate play!
    let mut repeat_play_evt = sample_event("evt-repeat-1", "2026-03-02T00:30:00Z");
    repeat_play_evt.ended_at = Some("2026-03-02T01:30:00Z".to_string());

    let batch = ImportEventsBatchRequest {
        provider: "jellyfin".to_string(),
        server_id: "srv-main".to_string(),
        server_name: None,
        source: "playback_reporting_export".to_string(),
        checkpoint: "cp-overlap".to_string(),
        expected_checkpoint: None,
        events: vec![confirmed_dup_evt, ambiguous_evt, repeat_play_evt],
    };

    let resp = import_events_batch(&conn, batch, &admin, now).expect("import overlap batch");
    assert_eq!(resp.confirmed_overlap_duplicates, 1);
    assert_eq!(resp.ambiguous_overlaps, 1);
    assert_eq!(resp.inserted_included, 1);

    // Confirmed plays count: 2 original observed_sessions + 1 non-overlapping repeat play = 3.
    // Neither the confirmed duplicate nor the ambiguous overlap is double-counted in confirmed_plays!
    let page = query_history(&conn, HistoryQuery::default(), &admin, now + 5)
        .expect("query included history");
    assert_eq!(page.counts.confirmed_plays, 3);
    assert_eq!(page.counts.matching_records, 3);

    // Admin with include_excluded = true can inspect all 5 records including duplicate and ambiguous
    let all_page = query_history(
        &conn,
        HistoryQuery {
            include_excluded: true,
            ..HistoryQuery::default()
        },
        &admin,
        now + 5,
    )
    .expect("query with includeExcluded");
    assert_eq!(all_page.counts.matching_records, 5);
}

#[test]
fn policies_and_explicit_user_links_control_cohorts_and_privacy() {
    let conn = setup_isolated_db();
    let admin = admin_user();
    let alice = alice_user();
    let now = 1_772_400_000_i64;

    // Import two events: one for jf-alice (3600s, lib-movies) and one for jf-bob (120s, lib-kids)
    let mut bob_evt = sample_event("evt-bob-1", "2026-03-01T18:00:00Z");
    bob_evt.user_id = "jf-bob".to_string();
    bob_evt.user_name = "Alice".to_string(); // Display name intentionally collides with "Alice"!
    bob_evt.watched_secs = Some(120);
    bob_evt.ended_at = Some("2026-03-01T18:02:00Z".to_string());
    bob_evt.libraries = vec![ImportLabelInput {
        id: "lib-kids".to_string(),
        name: "Kids".to_string(),
    }];

    import_events_batch(
        &conn,
        ImportEventsBatchRequest {
            provider: "jellyfin".to_string(),
            server_id: "srv-main".to_string(),
            server_name: None,
            source: "verified_json".to_string(),
            checkpoint: "cp-1".to_string(),
            expected_checkpoint: None,
            events: vec![sample_event("evt-alice-1", "2026-03-01T20:00:00Z"), bob_evt],
        },
        &admin,
        now,
    )
    .expect("import alice and bob");

    // Before linking Alice's account, Alice sees 0 records even though bob's display name is "Alice"
    let alice_unlinked =
        query_history(&conn, HistoryQuery::default(), &alice, now + 1).expect("unlinked query");
    assert_eq!(alice_unlinked.counts.matching_records, 0);

    // Link Alice (af_user_id=2) explicitly to ('jellyfin', 'srv-main', 'jf-alice')
    upsert_user_link(
        &conn,
        UpsertStreamingUserLinkRequest {
            af_user_id: 2,
            provider: "jellyfin".to_string(),
            server_id: "srv-main".to_string(),
            provider_user_id: "jf-alice".to_string(),
        },
        &admin,
    )
    .expect("link alice");

    let alice_linked =
        query_history(&conn, HistoryQuery::default(), &alice, now + 2).expect("linked query");
    assert_eq!(alice_linked.counts.matching_records, 1);
    assert_eq!(alice_linked.items[0].user_id, "jf-alice");

    // Update tracking policy: minimum_watch_secs = 300 excludes bob's 120s play from standard analytics
    let policy_resp = update_tracking_policy(
        &conn,
        UpdateTrackingPolicyRequest {
            minimum_watch_secs: 300,
            reconnect_window_secs: 60,
            excluded_users: Vec::new(),
            excluded_libraries: Vec::new(),
        },
        &admin,
    )
    .expect("update policy min watch");
    assert_eq!(policy_resp.minimum_watch_secs, 300);

    let admin_filtered =
        query_history(&conn, HistoryQuery::default(), &admin, now + 3).expect("admin query");
    assert_eq!(admin_filtered.counts.confirmed_plays, 1);

    // Excluding library 'lib-movies' excludes Alice's movie from standard analytics while preserving raw row
    update_tracking_policy(
        &conn,
        UpdateTrackingPolicyRequest {
            minimum_watch_secs: 0,
            reconnect_window_secs: 60,
            excluded_users: Vec::new(),
            excluded_libraries: vec![PolicyScopeTarget {
                provider: "jellyfin".to_string(),
                server_id: "srv-main".to_string(),
                id: "lib-movies".to_string(),
                name: "Movies".to_string(),
            }],
        },
        &admin,
    )
    .expect("exclude library");

    let after_lib_exclude =
        query_history(&conn, HistoryQuery::default(), &admin, now + 4).expect("after exclude");
    assert_eq!(after_lib_exclude.counts.confirmed_plays, 1); // only bob's lib-kids remains
    assert_eq!(after_lib_exclude.items[0].user_id, "jf-bob");
}

#[test]
fn legacy_reconciliation_preview_is_conservative_and_apply_requires_backup_and_fresh_state() {
    // Use a disposable temporary file SQLite database so `verified_backup` (VACUUM INTO) is exercised!
    let temp_dir = std::env::temp_dir().join(format!(
        "af-streaming-reconcile-test-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&temp_dir).expect("create temp test dir");
    let db_file = temp_dir.join("test-reconcile.sqlite");
    let db_path = db_file.to_string_lossy().into_owned();

    let conn = Connection::open(&db_file).expect("open temp file sqlite");
    conn.execute_batch(V19_STREAMING_DDL).expect("v19 DDL");
    conn.execute_batch(V20_MIGRATION_SQL).expect("v20 DDL");
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'alice', 'user')",
        [],
    )
    .expect("seed users");
    conn.execute(
        "INSERT INTO streaming_servers (provider, name, server_id) VALUES ('jellyfin', 'Main Jellyfin', 'srv-main')",
        [],
    )
    .expect("seed server");

    // Row 1: Legacy pre-migration `:sync:` item summary with synthetic 1970 timestamp, default DirectPlay, and inflated bytes
    conn.execute(
        "INSERT INTO streaming_history (
            id, session_key, provider, server_id, user_id, user_name,
            client_name, device_name, item_id, item_name, item_type, play_method,
            watched_secs, duration_secs, data_used_bytes, started_at, last_seen_at,
            provenance, timestamp_certainty, byte_accuracy, policy_status
         ) VALUES (
            10, 'jellyfin:sync:u1:item-1', 'jellyfin', '', 'jf-alice', 'Alice',
            '', '', 'item-1', 'Legacy Synced Movie', 'Movie', 'DirectPlay',
            7200, 7200, 999999999, '1970-01-01 00:00:00', '2026-02-01 12:00:00',
            'legacy_unverified', 'legacy_unverified', 'legacy_unverified', 'included'
         )",
        [],
    )
    .expect("seed legacy sync row");

    // Row 2: Legitimate legacy row with real client/device and valid timestamp + DirectPlay/Movie
    // MUST NOT be falsely flagged just because play_method='DirectPlay' and item_type='Movie'!
    conn.execute(
        "INSERT INTO streaming_history (
            id, session_key, provider, server_id, user_id, user_name,
            client_name, device_name, item_id, item_name, item_type, play_method,
            watched_secs, duration_secs, data_used_bytes, bitrate_bps, started_at, last_seen_at,
            provenance, timestamp_certainty, byte_accuracy, policy_status
         ) VALUES (
            11, 'jellyfin:live:session-99', 'jellyfin', 'srv-main', 'jf-alice', 'Alice',
            'Jellyfin Media Player', 'Desktop-PC', 'item-2', 'Valid Legacy Movie', 'Movie', 'DirectPlay',
            3600, 7200, 0, 8000000, '2026-02-15 20:00:00', '2026-02-15 21:00:00',
            'legacy_unverified', 'legacy_unverified', 'legacy_unverified', 'included'
         )",
        [],
    )
    .expect("seed valid legacy row");

    let admin = admin_user();
    let alice = alice_user();
    let now = 1_772_400_000_i64;

    // Non-admin must be rejected
    let non_admin_err =
        preview_legacy_reconciliation(&conn, ReconciliationPreviewRequest::default(), &alice, now)
            .unwrap_err();
    assert_eq!(non_admin_err.status, StatusCode::FORBIDDEN);

    // Preview identifies ONLY Row 10, leaving Row 11 untouched
    let preview =
        preview_legacy_reconciliation(&conn, ReconciliationPreviewRequest::default(), &admin, now)
            .expect("preview reconciliation");
    assert_eq!(preview.total_affected_rows, 1);
    assert_eq!(preview.affected_rows[0].id, 10);
    assert_eq!(preview.affected_rows[0].after.provenance, "item_summary");
    assert_eq!(
        preview.affected_rows[0].after.timestamp_certainty,
        "unrecorded"
    );
    assert_eq!(preview.affected_rows[0].after.started_at, "");
    assert_eq!(preview.affected_rows[0].after.play_method, "");
    assert_eq!(preview.affected_rows[0].after.data_used_bytes, 0);
    assert_eq!(preview.affected_rows[0].after.byte_accuracy, "unrecorded");
    assert_eq!(preview.affected_rows[0].after.server_id, "");
    assert!(preview.affected_rows[0]
        .classification
        .starts_with("suspected_"));
    assert!(preview.affected_rows[0]
        .changes
        .iter()
        .all(|change| change.reason.starts_with("Unverified proposal")));
    assert_eq!(preview.counts_before.legacy_records, 2);
    assert_eq!(preview.counts_after.legacy_records, 1);
    assert_eq!(preview.counts_after.item_summaries, 1);

    // Verify backup failure aborts apply before any mutation (e.g. invalid file: URI path)
    let backup_fail = apply_legacy_reconciliation_with_db_path(
        &conn,
        "file:///invalid-uri-for-backup",
        ReconciliationApplyRequest {
            preview_hash: preview.preview_hash.clone(),
            approval_token: preview.approval_token.clone(),
        },
        &admin,
        now + 5,
    )
    .unwrap_err();
    assert_eq!(backup_fail.status, StatusCode::SERVICE_UNAVAILABLE);

    // Verify expired token is rejected
    let expired_err = apply_legacy_reconciliation_with_db_path(
        &conn,
        &db_path,
        ReconciliationApplyRequest {
            preview_hash: preview.preview_hash.clone(),
            approval_token: preview.approval_token.clone(),
        },
        &admin,
        now + RECONCILIATION_TOKEN_TTL_SECS + 1,
    )
    .unwrap_err();
    assert_eq!(expired_err.status, StatusCode::CONFLICT);
    assert_eq!(expired_err.code, "approval_token_expired");

    // Apply with valid token and real file-backed DB path -> creates verified backup, updates row 10, writes audit
    let applied = apply_legacy_reconciliation_with_db_path(
        &conn,
        &db_path,
        ReconciliationApplyRequest {
            preview_hash: preview.preview_hash.clone(),
            approval_token: preview.approval_token.clone(),
        },
        &admin,
        now + 10,
    )
    .expect("apply reconciliation");
    assert_eq!(applied.applied_rows, 1);
    assert!(applied.backup_path.is_some());
    assert_eq!(applied.counts_after.legacy_records, 1);
    assert_eq!(applied.counts_after.item_summaries, 1);

    // Re-applying the same preview token now fails with 409 Conflict (stale revision/state)
    let replay_err = apply_legacy_reconciliation_with_db_path(
        &conn,
        &db_path,
        ReconciliationApplyRequest {
            preview_hash: preview.preview_hash,
            approval_token: preview.approval_token,
        },
        &admin,
        now + 15,
    )
    .unwrap_err();
    assert_eq!(replay_err.status, StatusCode::CONFLICT);
    assert_eq!(replay_err.code, "reconciliation_stale");

    // Verify streaming_history_audit row was recorded with before and after JSON
    let (op, before_json, after_json): (String, String, String) = conn
        .query_row(
            "SELECT operation, before_json, after_json FROM streaming_history_audit WHERE id = ?1",
            params![applied.audit_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("audit record");
    assert_eq!(op, "legacy_reconciliation");
    assert!(before_json.contains("legacy_unverified"));
    assert!(after_json.contains("item_summary"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn atomic_batch_rollback_and_upstream_capability_rejection() {
    let conn = setup_isolated_db();
    let admin = admin_user();
    let now = 1_772_400_000_i64;

    // 1. Upstream capability probe must classify /Users/{id}/Items as item_summary_only
    // and /System/ActivityLog/Entries as activity_log_insufficient
    let summary_cap =
        evaluate_upstream_capability("jellyfin", "srv-main", "/Users/u1/Items").unwrap();
    assert_eq!(
        summary_cap.upstream_endpoint_classification,
        "item_summary_only"
    );
    assert!(!summary_cap.upstream_direct_fetch_available);

    let activity_cap =
        evaluate_upstream_capability("jellyfin", "srv-main", "/System/ActivityLog/Entries")
            .unwrap();
    assert_eq!(
        activity_cap.upstream_endpoint_classification,
        "activity_log_insufficient"
    );
    assert!(!activity_cap.upstream_direct_fetch_available);

    // 2. Attempting to import an item_summary source via the event import endpoint is rejected
    let summary_source_err = import_events_batch(
        &conn,
        ImportEventsBatchRequest {
            provider: "jellyfin".to_string(),
            server_id: "srv-main".to_string(),
            server_name: None,
            source: "jellyfin_item_summary_sync".to_string(),
            checkpoint: "cp-bad".to_string(),
            expected_checkpoint: None,
            events: vec![sample_event("evt-1", "2026-03-01T20:00:00Z")],
        },
        &admin,
        now,
    )
    .unwrap_err();
    assert_eq!(summary_source_err.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(summary_source_err.code, "summary_source_forbidden");

    // 3. Multi-event batch where second event has invalid timestamp rolls back the entire batch
    let valid_first = sample_event("evt-valid-1", "2026-03-01T20:00:00Z");
    let mut invalid_second = sample_event("evt-invalid-2", "1970-01-01T00:00:00Z");
    invalid_second.ended_at = None;

    let batch_err = import_events_batch(
        &conn,
        ImportEventsBatchRequest {
            provider: "jellyfin".to_string(),
            server_id: "srv-main".to_string(),
            server_name: None,
            source: "playback_reporting_export".to_string(),
            checkpoint: "cp-atomic-fail".to_string(),
            expected_checkpoint: None,
            events: vec![valid_first, invalid_second],
        },
        &admin,
        now,
    )
    .unwrap_err();
    assert_eq!(batch_err.status, StatusCode::BAD_REQUEST);

    let history_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM streaming_history", [], |r| r.get(0))
        .unwrap();
    assert_eq!(history_count, 0, "first event must be rolled back");

    let cp_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM streaming_import_checkpoints",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(cp_count, 0, "checkpoint must not advance on failed batch");

    // 4. Recording checkpoint error stores last_error without touching streaming_history
    record_import_checkpoint_error(
        &conn,
        "jellyfin",
        "srv-main",
        "playback_reporting_export",
        "Malformed upstream export payload at line 42",
        now + 5,
    )
    .expect("record checkpoint error");

    let status = get_import_status(&conn, ImportStatusQuery::default(), &admin).expect("status");
    assert_eq!(status.checkpoints.len(), 1);
    assert_eq!(
        status.checkpoints[0].last_error.as_deref(),
        Some("Malformed upstream export payload at line 42")
    );
}

#[test]
fn plex_native_json_and_csv_exports_import_cleanly_into_canonical_watch_history() {
    let conn = setup_isolated_db();
    let admin = admin_user();
    let now = 1_710_000_000_i64;

    conn.execute(
        "INSERT INTO streaming_servers (provider, name, server_id) VALUES ('plex', 'Main Plex', 'plex-srv-1')",
        [],
    )
    .unwrap();

    // 1. Native Plex MediaContainer.Metadata JSON export
    let plex_json = serde_json::json!({
        "MediaContainer": {
            "size": 2,
            "Metadata": [
                {
                    "historyKey": "/status/sessions/history/501",
                    "ratingKey": "12345",
                    "title": "Dune: Part Two",
                    "type": "movie",
                    "accountID": 7,
                    "user": "Paul",
                    "viewedAt": 1709990000,
                    "duration": 9960000,
                    "viewOffset": 9900000,
                    "videoDecision": "directplay",
                    "player": "Plex for Apple TV",
                    "platform": "tvOS",
                    "librarySectionID": "1",
                    "librarySectionTitle": "Movies"
                },
                {
                    "historyKey": "/status/sessions/history/502",
                    "ratingKey": "67890",
                    "grandparentRatingKey": "67000",
                    "grandparentTitle": "Severance",
                    "title": "Good News About Hell",
                    "type": "episode",
                    "parentIndex": 1,
                    "index": 1,
                    "accountID": 8,
                    "user": "Helly",
                    "viewedAt": 1709995000,
                    "duration": 3420000,
                    "viewOffset": 3420000,
                    "videoDecision": "copy",
                    "player": "Plex Web"
                }
            ]
        }
    });

    let json_resp = import_native_export_batch(
        &conn,
        NativeExportImportRequest {
            provider: "plex".to_string(),
            server_id: "plex-srv-1".to_string(),
            server_name: Some("Main Plex".to_string()),
            source: "plex_native_json_export".to_string(),
            checkpoint: "plex-json-cp-1".to_string(),
            expected_checkpoint: None,
            format: "json".to_string(),
            payload: plex_json,
        },
        &admin,
        now,
    )
    .expect("import plex json");
    assert_eq!(json_resp.provider, "plex");
    assert_eq!(json_resp.inserted_included, 2);

    // 2. Native Plex / Tautulli CSV watch-history export
    let plex_csv = "history_key,user_id,friendly_name,rating_key,title,media_type,started,stopped,play_duration,duration,transcode_decision,player,platform\n\
plex-csv-901,9,Irving,88801,\"The You You Are\",track,1709998000,1709998240,240,245,transcode,Plexamp,iOS\n";

    let csv_resp = import_native_export_batch(
        &conn,
        NativeExportImportRequest {
            provider: "plex".to_string(),
            server_id: "plex-srv-1".to_string(),
            server_name: Some("Main Plex".to_string()),
            source: "plex_csv_export".to_string(),
            checkpoint: "plex-csv-cp-1".to_string(),
            expected_checkpoint: None,
            format: "csv".to_string(),
            payload: serde_json::Value::String(plex_csv.to_string()),
        },
        &admin,
        now + 10,
    )
    .expect("import plex csv");
    assert_eq!(csv_resp.inserted_included, 1);

    // Verify canonical rows in `streaming_history`
    let history = query_history(
        &conn,
        HistoryQuery {
            provider: "plex".to_string(),
            ..HistoryQuery::default()
        },
        &admin,
        now + 20,
    )
    .expect("query plex history");
    assert_eq!(history.items.len(), 3);
    assert!(history.items.iter().any(|r| r.item_name == "Dune: Part Two"
        && r.item_type.as_deref() == Some("Movie")
        && r.play_method.as_deref() == Some("DirectPlay")
        && r.watched_secs == Some(9900)));
    assert!(history
        .items
        .iter()
        .any(|r| r.item_name == "Good News About Hell"
            && r.series_name.as_deref() == Some("Severance")
            && r.play_method.as_deref() == Some("DirectStream")));
    assert!(history
        .items
        .iter()
        .any(|r| r.item_name == "The You You Are"
            && r.item_type.as_deref() == Some("Audio")
            && r.play_method.as_deref() == Some("Transcode")
            && r.watched_secs == Some(240)));

    let status = get_import_status(
        &conn,
        ImportStatusQuery {
            provider: "plex".to_string(),
            server_id: "plex-srv-1".to_string(),
        },
        &admin,
    )
    .expect("plex import status");
    assert_eq!(status.checkpoints.len(), 2);
    assert!(status
        .capabilities
        .iter()
        .any(|c| c.provider == "plex" && c.real_event_import_supported));
}

#[test]
fn import_events_batch_surfaces_tracking_policy_db_errors_instead_of_silently_defaulting() {
    let conn = setup_isolated_db();
    let admin = admin_user();

    // 1. Missing policy row (empty table) still safely defaults reconnect_window_secs to 0.
    conn.execute("DELETE FROM streaming_tracking_policies", [])
        .unwrap();
    let ok_res = import_events_batch(
        &conn,
        ImportEventsBatchRequest {
            provider: "jellyfin".to_string(),
            server_id: "srv-1".to_string(),
            server_name: Some("Jellyfin".to_string()),
            source: "export".to_string(),
            checkpoint: "cp-1".to_string(),
            expected_checkpoint: None,
            events: vec![sample_event("ev-empty-policy", "2026-03-01T20:00:00Z")],
        },
        &admin,
        1_772_400_000,
    );
    assert!(
        ok_res.is_ok(),
        "absent policy row should default cleanly: {ok_res:?}"
    );

    // 2. Dropping streaming_tracking_policies causes a real SQLite error, which must fail
    //    with 500 instead of silently falling back to reconnect_window_secs = 0.
    conn.execute("DROP TABLE streaming_tracking_policies", [])
        .unwrap();
    let err = import_events_batch(
        &conn,
        ImportEventsBatchRequest {
            provider: "jellyfin".to_string(),
            server_id: "srv-1".to_string(),
            server_name: Some("Jellyfin".to_string()),
            source: "export".to_string(),
            checkpoint: "cp-2".to_string(),
            expected_checkpoint: Some("cp-1".to_string()),
            events: vec![sample_event("ev-broken-policy", "2026-03-01T20:15:00Z")],
        },
        &admin,
        1_772_400_900,
    )
    .expect_err("real SQLite error on streaming_tracking_policies must not be swallowed");
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(err.code, "streaming_import_internal_error");

    // 3. Dropping streaming_servers causes get_import_status to fail with 500 instead of silently
    //    swallowing server query errors.
    conn.execute("DROP TABLE streaming_servers", []).unwrap();
    let status_err = get_import_status(&conn, ImportStatusQuery::default(), &admin)
        .expect_err("real SQLite error on streaming_servers must not be swallowed");
    assert_eq!(status_err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(status_err.code, "streaming_import_internal_error");
}
