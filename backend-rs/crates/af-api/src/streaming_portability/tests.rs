use super::approvals::*;
use super::handlers::*;
use super::planning::*;
use super::restore::*;
use super::snapshot::*;
use super::types::*;
use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use rusqlite::{params, Connection};
use serde::Serialize;
use sha2::{Digest, Sha256};

use std::path::{Path, PathBuf};

const AF_DB_LIB: &str = include_str!("../../../af-db/src/lib.rs");
const MIGRATION_20: &str = include_str!("../../../af-db/src/migrations/020_streaming_history.sql");

struct DisposableDb {
    connection: Connection,
    database_path: PathBuf,
    root: PathBuf,
}

impl Drop for DisposableDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn raw_migration_19_table(migration_start: usize, marker: &str) -> String {
    let migration = &AF_DB_LIB[migration_start..];
    let literal_start = migration.find(marker).expect("migration 19 raw SQL marker") + 3;
    let literal_end = migration[literal_start..]
        .find("\"#")
        .expect("raw SQL terminator");
    migration[literal_start..literal_start + literal_end].to_owned()
}

fn disposable_db() -> DisposableDb {
    let root = std::env::temp_dir().join(format!(
        "aetherflow-streaming-portability-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let database_path = root.join("streaming.sqlite");
    let connection = Connection::open(&database_path).unwrap();
    connection.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    let migration_start = AF_DB_LIB.find("        19,\n        \"Add streaming_servers, streaming_history, and streaming_bandwidth_samples tables\"")
        .expect("migration 19 registration");
    for marker in [
        "r#\"CREATE TABLE IF NOT EXISTS streaming_servers",
        "r#\"CREATE TABLE IF NOT EXISTS streaming_history",
        "r#\"CREATE TABLE IF NOT EXISTS streaming_bandwidth_samples",
    ] {
        connection
            .execute_batch(&raw_migration_19_table(migration_start, marker))
            .unwrap();
    }
    connection.execute_batch(MIGRATION_20).unwrap();
    DisposableDb {
        connection,
        database_path,
        root,
    }
}

fn seed_sensitive_data(connection: &Connection) {
    connection.execute(
        "INSERT INTO streaming_servers(provider,name,url,api_key,enabled,server_id,server_version) VALUES ('jellyfin','Media','http://media.local','provider-secret-should-never-export',1,'server-a','10.9')",
        [],
    ).unwrap();
    connection.execute(
        "INSERT INTO streaming_history(id,session_key,provider,server_name,user_id,user_name,client_name,device_name,device_id,ip_address,item_id,item_name,item_type,series_name,series_id,season_number,episode_number,production_year,play_method,container,video_codec,video_resolution,audio_codec,audio_channels,subtitle_codec,hw_accel,transcode_reasons,bitrate_bps,duration_secs,watched_secs,data_used_bytes,completion_pct,started_at,last_seen_at,ended_at,is_active,provenance,server_id,source_event_id,timestamp_certainty,byte_accuracy,policy_status) VALUES (7,'jellyfin:session-7:item-2','jellyfin','Media','provider-user-2','Sam','TV','Living Room','device-secret-should-never-export','192.0.2.8','item-2','Example','Movie','','',NULL,NULL,NULL,'DirectPlay','','','','',NULL,'','','',NULL,NULL,NULL,NULL,NULL,'2026-10-01T12:00:00Z','2026-10-01T12:30:00Z',NULL,0,'imported_event','server-a','event-7','source_event','unrecorded','included')",
        [],
    ).unwrap();
    connection.execute(
        "INSERT INTO streaming_history_labels(history_id,kind,value,name) VALUES (7,'library','library-3','Films')",
        [],
    ).unwrap();
    connection.execute(
        "INSERT INTO streaming_session_samples(history_id,sampled_at,observed_secs,playing,bitrate_bps) VALUES (7,1790856000,30,1,1200000)",
        [],
    ).unwrap();
    connection.execute(
        "INSERT INTO streaming_bandwidth_samples(id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) VALUES (4,NULL,'jellyfin',1,1,0,0,1200000,NULL)",
        [],
    ).unwrap();
    connection.execute(
        "UPDATE streaming_tracking_policies SET minimum_watch_secs=45,excluded_users='[]',excluded_libraries='[]',reconnect_window_secs=30 WHERE id=1",
        [],
    ).unwrap();
}

fn export_archive(connection: &Connection) -> StreamingArchive {
    build_archive(connection, 1_798_876_800).unwrap()
}

fn preview_and_token(
    connection: &Connection,
    archive: &StreamingArchive,
    mode: RestoreMode,
    actor_id: i64,
    now: i64,
) -> (RestorePreview, String) {
    let preview = inspect_restore(connection, archive, mode).unwrap();
    let (token, _) = issue_approval(
        actor_id,
        mode,
        &preview.archive_sha256,
        &preview.preview_sha256,
        now,
    )
    .unwrap();
    (preview, token)
}

fn query_counts(connection: &Connection) -> (i64, i64, i64, i64, i64) {
    connection.query_row(
        "SELECT (SELECT COUNT(*) FROM streaming_history),(SELECT COUNT(*) FROM streaming_history_labels),(SELECT COUNT(*) FROM streaming_session_samples),(SELECT COUNT(*) FROM streaming_bandwidth_samples),(SELECT COUNT(*) FROM streaming_history_audit)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).unwrap()
}

fn assert_private_backup_exists(root: &Path) {
    let backup_dir = std::fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("streaming-backup-")
        })
        .expect("verified_backup created a private backup directory");
    let backup = backup_dir.join("before-migration.sqlite");
    assert!(backup.is_file());
    let verification =
        Connection::open_with_flags(&backup, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(
        verification
            .query_row::<String, _, _>("PRAGMA quick_check", [], |row| row.get(0))
            .unwrap(),
        "ok"
    );
}

#[test]
fn archive_round_trip_is_secret_free_and_preserves_provenance_and_nulls() {
    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    source
        .connection
        .execute("CREATE TABLE unrelated_sentinel(value TEXT NOT NULL)", [])
        .unwrap();
    source
        .connection
        .execute(
            "INSERT INTO unrelated_sentinel VALUES ('leave-me-alone')",
            [],
        )
        .unwrap();
    let archive = export_archive(&source.connection);
    let encoded = serde_json::to_string(&archive).unwrap();
    assert!(!encoded.contains("provider-secret-should-never-export"));
    assert!(!encoded.contains("device-secret-should-never-export"));
    assert!(!encoded.contains("Living Room"));
    assert!(!encoded.contains("192.0.2.8"));
    assert_eq!(archive.data.history[0].provenance, "imported_event");
    assert_eq!(
        archive.data.history[0].source_event_id.as_deref(),
        Some("event-7")
    );
    assert_eq!(archive.data.history[0].season_number, None);
    assert_eq!(archive.data.bandwidth_samples[0].timestamp, None);
    assert_eq!(archive.data.bandwidth_samples[0].bytes_delta, None);

    let mut target = disposable_db();
    target
        .connection
        .execute("CREATE TABLE unrelated_sentinel(value TEXT NOT NULL)", [])
        .unwrap();
    target
        .connection
        .execute(
            "INSERT INTO unrelated_sentinel VALUES ('leave-me-alone')",
            [],
        )
        .unwrap();
    target.connection.execute(
        "INSERT INTO streaming_servers(provider,name,url,api_key,server_id) VALUES ('jellyfin','Local','http://local','keep-target-secret','target-server')",
        [],
    ).unwrap();
    let (preview, token) = preview_and_token(
        &target.connection,
        &archive,
        RestoreMode::Replace,
        44,
        1_798_876_800,
    );
    let restored = restore_connection(
        &mut target.connection,
        target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Replace,
        &archive,
        &token,
        1_798_876_800,
    )
    .unwrap();
    assert_eq!(restored.archive_counts, archive.data.counts());
    assert_eq!(restored.preview_sha256, preview.preview_sha256);
    assert_eq!(query_counts(&target.connection), (1, 1, 1, 1, 1));
    let device_name: String = target
        .connection
        .query_row(
            "SELECT device_name FROM streaming_history WHERE id=7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let ip_address: String = target
        .connection
        .query_row(
            "SELECT ip_address FROM streaming_history WHERE id=7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(device_name.is_empty());
    assert!(ip_address.is_empty());
    let sentinel: String = target
        .connection
        .query_row("SELECT value FROM unrelated_sentinel", [], |row| row.get(0))
        .unwrap();
    assert_eq!(sentinel, "leave-me-alone");
    let api_key: String = target
        .connection
        .query_row(
            "SELECT api_key FROM streaming_servers WHERE provider='jellyfin'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(api_key, "keep-target-secret");
    assert_private_backup_exists(&target.root);
    if let Ok(path) = std::env::var("AF_STREAMING_PORTABILITY_FIXTURE") {
        let preview = response_from_preview(&preview, token, 1_798_876_800 + APPROVAL_TTL_SECS);
        let fixture =
            serde_json::json!({ "archive": archive, "preview": preview, "restored": restored });
        std::fs::write(path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    }
}

#[test]
fn merge_remaps_instance_local_ids_and_preserves_parent_links() {
    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    let archive = export_archive(&source.connection);
    let mut target = disposable_db();
    let mut unrelated = archive.data.history[0].clone();
    unrelated.session_key = "other-instance-session".to_string();
    unrelated.source_event_id = Some("other-instance-event".to_string());
    insert_history(&target.connection, &unrelated).unwrap();
    let (preview, token) =
        preview_and_token(&target.connection, &archive, RestoreMode::Merge, 44, 1000);
    assert_eq!(preview.plan.insert.history, 1);
    assert_eq!(preview.plan.conflict.history, 0);
    let response = restore_connection(
        &mut target.connection,
        target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Merge,
        &archive,
        &token,
        1001,
    )
    .unwrap();
    assert_eq!(response.resulting_counts.history, 2);
    let mapped_id: i64 = target
        .connection
        .query_row(
            "SELECT id FROM streaming_history WHERE session_key=?1",
            [&archive.data.history[0].session_key],
            |row| row.get(0),
        )
        .unwrap();
    assert_ne!(mapped_id, unrelated.id);
    let label_parent: i64 = target
        .connection
        .query_row(
            "SELECT history_id FROM streaming_history_labels",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let sample_parent: i64 = target
        .connection
        .query_row(
            "SELECT history_id FROM streaming_session_samples",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(label_parent, mapped_id);
    assert_eq!(sample_parent, mapped_id);
    let target_snapshot = load_snapshot(&target.connection).unwrap().snapshot;
    let repeat = plan_merge(&target_snapshot, &archive.data);
    assert_eq!(repeat.counts.insert.history, 0);
    assert_eq!(repeat.counts.exact_duplicate.history, 1);
}

#[test]
fn merge_maps_matching_source_event_and_skips_conflicting_identity() {
    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    let archive = export_archive(&source.connection);
    let mut target = disposable_db();
    let mut mapped_record = archive.data.history[0].clone();
    mapped_record.id = 99;
    insert_history(&target.connection, &mapped_record).unwrap();
    target.connection.execute(
        "INSERT INTO streaming_history_labels(history_id,kind,value,name) VALUES (99,'library','library-3','Films')",
        [],
    ).unwrap();
    target.connection.execute(
        "INSERT INTO streaming_session_samples(history_id,sampled_at,observed_secs,playing,bitrate_bps) VALUES (99,1790856000,30,1,1200000)",
        [],
    ).unwrap();
    target.connection.execute(
        "UPDATE streaming_tracking_policies SET minimum_watch_secs=45,reconnect_window_secs=30 WHERE id=1",
        [],
    ).unwrap();
    let (preview, token) = preview_and_token(
        &target.connection,
        &archive,
        RestoreMode::Merge,
        44,
        1_798_876_800,
    );
    assert_eq!(preview.plan.exact_duplicate.history, 1);
    assert!(preview.conflicts.is_empty());
    let response = restore_connection(
        &mut target.connection,
        target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Merge,
        &archive,
        &token,
        1_798_876_800,
    )
    .unwrap();
    assert_eq!(response.resulting_counts.history, 1);
    assert_eq!(response.resulting_counts.labels, 1);
    assert_eq!(response.resulting_counts.session_samples, 1);
    assert_eq!(response.resulting_counts.bandwidth_samples, 1);
    let sample_history_id: i64 = target
        .connection
        .query_row(
            "SELECT history_id FROM streaming_session_samples",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(sample_history_id, 99);
    assert_eq!(query_counts(&target.connection).4, 1);
}

#[test]
fn merge_preview_reports_event_and_policy_conflicts_without_overwriting() {
    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    let archive = export_archive(&source.connection);
    let mut target = disposable_db();
    target.connection.execute(
        "INSERT INTO streaming_history(id,session_key,provider,server_name,user_id,user_name,item_id,item_name,started_at,last_seen_at,provenance,server_id,source_event_id,timestamp_certainty,byte_accuracy,policy_status) VALUES (7,'jellyfin:session-7:item-2','jellyfin','Different','provider-user-2','Sam','item-2','Example','2026-10-01T12:00:00Z','2026-10-01T12:30:00Z','imported_event','server-a','event-7','source_event','unrecorded','included')",
        [],
    ).unwrap();
    target
        .connection
        .execute(
            "UPDATE streaming_tracking_policies SET minimum_watch_secs=99 WHERE id=1",
            [],
        )
        .unwrap();
    let (preview, token) = preview_and_token(
        &target.connection,
        &archive,
        RestoreMode::Merge,
        44,
        1_798_876_800,
    );
    assert_eq!(preview.conflicts.len(), 4);
    assert!(preview
        .conflicts
        .iter()
        .any(|entry| entry.reason == "history_identity_collision"));
    assert!(preview
        .conflicts
        .iter()
        .any(|entry| entry.reason == "parent_history_conflict"));
    assert!(preview
        .conflicts
        .iter()
        .any(|entry| entry.reason == "tracking_policy_collision"));
    let response = restore_connection(
        &mut target.connection,
        target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Merge,
        &archive,
        &token,
        1_798_876_800,
    )
    .unwrap();
    assert_eq!(response.conflicts, preview.conflicts);
    assert_eq!(response.resulting_counts.history, 1);
    let server_name: String = target
        .connection
        .query_row(
            "SELECT server_name FROM streaming_history WHERE id=7",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(server_name, "Different");
    let policy: i64 = target
        .connection
        .query_row(
            "SELECT minimum_watch_secs FROM streaming_tracking_policies WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(policy, 99);
}

#[test]
fn approval_is_actor_bound_expiring_one_time_and_preview_is_revalidated() {
    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    let archive = export_archive(&source.connection);
    let mut target = disposable_db();
    let (_, wrong_actor_token) =
        preview_and_token(&target.connection, &archive, RestoreMode::Merge, 44, 1000);
    assert!(consume_approval(
        &wrong_actor_token,
        45,
        RestoreMode::Merge,
        &archive.manifest.sha256,
        1001
    )
    .is_err());

    let (_, expired_token) =
        preview_and_token(&target.connection, &archive, RestoreMode::Merge, 44, 1000);
    assert!(consume_approval(
        &expired_token,
        44,
        RestoreMode::Merge,
        &archive.manifest.sha256,
        1301
    )
    .is_err());

    let (preview, stale_token) =
        preview_and_token(&target.connection, &archive, RestoreMode::Replace, 44, 2000);
    target
        .connection
        .execute(
            "INSERT INTO streaming_bandwidth_samples(id,provider) VALUES (123,'jellyfin')",
            [],
        )
        .unwrap();
    let stale = restore_connection(
        &mut target.connection,
        target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Replace,
        &archive,
        &stale_token,
        2001,
    );
    assert!(stale.is_err());
    assert_eq!(query_counts(&target.connection).3, 1);
    assert_eq!(query_counts(&target.connection).4, 0);
    assert!(!preview.preview_sha256.is_empty());
}

#[test]
fn redacted_private_field_change_invalidates_replacement_preview() {
    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    let archive = export_archive(&source.connection);
    let mut target = disposable_db();
    target.connection.execute(
        "INSERT INTO streaming_history(id,session_key,device_name,device_id,ip_address) VALUES (55,'local-session','Old Device','old-device','198.51.100.7')",
        [],
    ).unwrap();
    let (_, token) =
        preview_and_token(&target.connection, &archive, RestoreMode::Replace, 44, 2500);
    target
        .connection
        .execute(
            "UPDATE streaming_history SET ip_address='198.51.100.8' WHERE id=55",
            [],
        )
        .unwrap();
    let result = restore_connection(
        &mut target.connection,
        target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Replace,
        &archive,
        &token,
        2501,
    );
    assert!(result.is_err());
    assert_eq!(query_counts(&target.connection), (1, 0, 0, 0, 0));
    let ip_address: String = target
        .connection
        .query_row(
            "SELECT ip_address FROM streaming_history WHERE id=55",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ip_address, "198.51.100.8");
}

#[test]
fn audit_failure_rolls_back_restore_and_preserves_unrelated_data() {
    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    let archive = export_archive(&source.connection);
    let mut target = disposable_db();
    target
        .connection
        .execute("CREATE TABLE unrelated_sentinel(value TEXT NOT NULL)", [])
        .unwrap();
    target
        .connection
        .execute("INSERT INTO unrelated_sentinel VALUES ('stable')", [])
        .unwrap();
    target.connection.execute_batch(
        "CREATE TRIGGER reject_portability_audit BEFORE INSERT ON streaming_history_audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;",
    ).unwrap();
    let (_, token) =
        preview_and_token(&target.connection, &archive, RestoreMode::Replace, 44, 3000);
    let result = restore_connection(
        &mut target.connection,
        target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Replace,
        &archive,
        &token,
        3001,
    );
    assert!(result.is_err());
    assert_eq!(query_counts(&target.connection), (0, 0, 0, 0, 0));
    let sentinel: String = target
        .connection
        .query_row("SELECT value FROM unrelated_sentinel", [], |row| row.get(0))
        .unwrap();
    assert_eq!(sentinel, "stable");
}

#[test]
fn rejects_unknown_fields_bad_hash_duplicate_event_identity_and_size() {
    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    let archive = export_archive(&source.connection);
    let mut tampered = archive.clone();
    tampered.data.history[0].item_name = "tampered".to_owned();
    assert!(tampered.validate().is_err());
    let mut duplicate = archive.clone();
    let mut duplicate_row = duplicate.data.history[0].clone();
    duplicate_row.id = 8;
    duplicate_row.session_key = "different-session".to_owned();
    duplicate.data.history.push(duplicate_row);
    duplicate.manifest.record_counts.history = 2;
    duplicate.manifest.sha256 = duplicate.digest().unwrap();
    assert!(duplicate.validate().is_err());
    assert!(validate_archive_bytes(&vec![b' '; MAX_BODY_BYTES + 1]).is_err());
    let encoded = serde_json::to_vec(&archive).unwrap();
    let mut with_unknown = serde_json::from_slice::<serde_json::Value>(&encoded).unwrap();
    with_unknown["data"]["history"][0]["ipAddress"] =
        serde_json::Value::String("private".to_owned());
    let bytes = serde_json::to_vec(&with_unknown).unwrap();
    assert!(validate_archive_bytes(&bytes).is_err());
}

#[test]
fn replace_mode_succeeds_when_existing_db_has_over_ten_thousand_rows_and_body_headroom_exists() {
    const { assert!(MAX_REQUEST_BODY_BYTES >= MAX_ARCHIVE_BYTES + 1024 * 1024) };
    const { assert!(MAX_PORTABLE_ROWS >= 100_000) };

    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    let archive = export_archive(&source.connection);

    let mut target = disposable_db();
    let tx = target.connection.unchecked_transaction().unwrap();
    {
        let mut stmt = tx
            .prepare("INSERT INTO streaming_bandwidth_samples(id,provider,active_streams) VALUES (?1,'jellyfin',1)")
            .unwrap();
        for id in 1..=12_000_i64 {
            stmt.execute([id]).unwrap();
        }
    }
    tx.commit().unwrap();

    let (preview, token) =
        preview_and_token(&target.connection, &archive, RestoreMode::Replace, 44, 4000);
    assert_eq!(preview.target_counts.bandwidth_samples, 12_000);
    let restored = restore_connection(
        &mut target.connection,
        target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Replace,
        &archive,
        &token,
        4001,
    )
    .unwrap();
    assert_eq!(restored.resulting_counts.bandwidth_samples, 1);
}

#[tokio::test]
async fn archive_boundary_near_seven_point_five_mib_succeeds_and_above_eight_mib_is_rejected() {
    assert_eq!(MAX_ARCHIVE_BYTES, 8 * 1024 * 1024);
    assert_eq!(MAX_PORTABILITY_BODY_BYTES, 10 * 1024 * 1024);
    assert_eq!(MAX_REQUEST_BODY_BYTES, MAX_PORTABILITY_BODY_BYTES);

    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    let base_archive = export_archive(&source.connection);
    let template_row = base_archive.data.history[0].clone();

    // Build a valid ~7.5 MiB archive (~7,864,320 bytes)
    let mut near_limit = base_archive.clone();
    near_limit.data.history.clear();
    near_limit.data.labels.clear();
    near_limit.data.session_samples.clear();
    let pad = "x".repeat(15_200);
    for idx in 1..=500_i64 {
        let mut row = template_row.clone();
        row.id = idx;
        row.session_key = format!("plex:srv-1:sess-{idx}");
        row.provider = "plex".to_string();
        row.source_event_id = Some(format!("plex-evt-{idx}"));
        row.item_name = pad.clone();
        near_limit.data.history.push(row);
    }
    near_limit.manifest.record_counts = near_limit.data.counts();
    near_limit.manifest.sha256 = near_limit.digest().unwrap();

    let near_bytes = serde_json::to_vec(&near_limit).unwrap();
    assert!(
        near_bytes.len() >= 7 * 1024 * 1024 && near_bytes.len() <= MAX_ARCHIVE_BYTES,
        "expected ~7.5 MiB archive, got {} bytes",
        near_bytes.len()
    );
    ensure_archive_within_byte_limit(&near_limit).unwrap();
    validate_archive_bytes(&near_bytes).unwrap();

    // Request wrapper (`{"mode":"merge","archive":...}`) fits well within 10 MiB body limit
    let envelope = serde_json::json!({
        "mode": "merge",
        "archive": near_limit,
    });
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
    assert!(envelope_bytes.len() <= MAX_PORTABILITY_BODY_BYTES);
    let req = Request::builder()
        .method("POST")
        .uri(PREVIEW_ROUTE)
        .body(Body::from(envelope_bytes))
        .unwrap();
    let read_back = read_request_body(req).await.unwrap();
    let parsed_req: PreviewRequest = serde_json::from_slice(&read_back).unwrap();
    ensure_archive_within_byte_limit(&parsed_req.archive).unwrap();

    // Exceeding 8 MiB archive limit (~8.3 MiB) is rejected even though < 10 MiB body limit
    let mut over_archive = parsed_req.archive;
    for idx in 501..=555_i64 {
        let mut row = template_row.clone();
        row.id = idx;
        row.session_key = format!("plex:srv-1:sess-{idx}");
        row.provider = "plex".to_string();
        row.source_event_id = Some(format!("plex-evt-{idx}"));
        row.item_name = pad.clone();
        over_archive.data.history.push(row);
    }
    over_archive.manifest.record_counts = over_archive.data.counts();
    over_archive.manifest.sha256 = over_archive.digest().unwrap();
    assert!(ensure_archive_within_byte_limit(&over_archive).is_err());

    // Exceeding 10 MiB body limit is rejected by `read_request_body`
    let over_body_req = Request::builder()
        .method("POST")
        .uri(PREVIEW_ROUTE)
        .body(Body::from(vec![b' '; MAX_PORTABILITY_BODY_BYTES + 1]))
        .unwrap();
    assert!(read_request_body(over_body_req).await.is_err());
}

#[test]
fn merge_mode_deduplicates_bandwidth_samples_by_natural_key_when_target_has_existing_ids() {
    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    source
        .connection
        .execute("DELETE FROM streaming_bandwidth_samples", [])
        .unwrap();
    for (id, ts, prov, streams, br) in [
        (
            1_i64,
            "2026-10-01T10:00:00Z",
            "jellyfin",
            1_i64,
            4_000_000_i64,
        ),
        (
            2_i64,
            "2026-10-01T10:01:00Z",
            "jellyfin",
            2_i64,
            8_000_000_i64,
        ),
        (3_i64, "2026-10-01T10:02:00Z", "plex", 1_i64, 5_000_000_i64),
    ] {
        source.connection.execute(
            "INSERT INTO streaming_bandwidth_samples(id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) VALUES (?1,?2,?3,?4,1,0,0,?5,1024)",
            params![id, ts, prov, streams, br],
        ).unwrap();
    }
    let archive = export_archive(&source.connection);

    // Target DB ALREADY has rows id = 1..3 (with id=2 matching archive's 10:00:00Z natural key!)
    let mut target = disposable_db();
    target.connection.execute(
        "UPDATE streaming_tracking_policies SET minimum_watch_secs=45,excluded_users='[]',excluded_libraries='[]',reconnect_window_secs=30 WHERE id=1",
        [],
    ).unwrap();
    for (id, ts, prov, streams, br) in [
        (
            1_i64,
            "2026-09-30T09:00:00Z",
            "jellyfin",
            1_i64,
            2_000_000_i64,
        ),
        (
            2_i64,
            "2026-10-01T10:00:00Z",
            "jellyfin",
            1_i64,
            4_000_000_i64,
        ),
        (3_i64, "2026-09-30T09:05:00Z", "emby", 1_i64, 3_000_000_i64),
    ] {
        target.connection.execute(
            "INSERT INTO streaming_bandwidth_samples(id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) VALUES (?1,?2,?3,?4,1,0,0,?5,1024)",
            params![id, ts, prov, streams, br],
        ).unwrap();
    }

    let (preview, token) =
        preview_and_token(&target.connection, &archive, RestoreMode::Merge, 44, 5000);
    assert_eq!(preview.plan.exact_duplicate.bandwidth_samples, 1);
    assert_eq!(preview.plan.insert.bandwidth_samples, 2);
    assert_eq!(preview.plan.conflict.bandwidth_samples, 0);

    let restored = restore_connection(
        &mut target.connection,
        target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Merge,
        &archive,
        &token,
        5001,
    )
    .expect("merge into target with existing bandwidth_samples id=1..3 must succeed without UNIQUE id conflict");
    assert_eq!(restored.resulting_counts.bandwidth_samples, 5);

    // Repeat merge preview sees all 3 archive bandwidth samples as exact duplicates!
    let repeat_preview = inspect_restore(&target.connection, &archive, RestoreMode::Merge).unwrap();
    assert_eq!(repeat_preview.plan.insert.bandwidth_samples, 0);
    assert_eq!(repeat_preview.plan.exact_duplicate.bandwidth_samples, 3);
}

#[test]
fn legacy_full_v1_archive_keeps_exact_digest_and_omits_partial_fields() {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct LegacyV1DigestView<'a> {
        format: &'a str,
        format_version: u16,
        schema_version: u16,
        provenance_version: u16,
        exported_at: &'a str,
        record_counts: &'a RecordCounts,
        redacted_fields: &'a [String],
        omitted_tables: &'a [String],
        data: &'a ArchiveData,
    }

    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    let archive = export_archive(&source.connection);
    assert_eq!(archive.manifest.omitted_samples, None);

    let encoded = serde_json::to_vec(&archive).unwrap();
    let encoded_json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    assert!(encoded_json["manifest"].get("omittedSamples").is_none());

    let legacy_digest_input = LegacyV1DigestView {
        format: &archive.manifest.format,
        format_version: archive.manifest.format_version,
        schema_version: archive.manifest.schema_version,
        provenance_version: archive.manifest.provenance_version,
        exported_at: &archive.manifest.exported_at,
        record_counts: &archive.manifest.record_counts,
        redacted_fields: &archive.manifest.redacted_fields,
        omitted_tables: &archive.manifest.omitted_tables,
        data: &archive.data,
    };
    let expected_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&legacy_digest_input).unwrap(),
    ));
    assert_eq!(archive.manifest.sha256, expected_sha256);

    let parsed = validate_archive_bytes(&encoded).unwrap();
    assert_eq!(parsed, archive);

    // Explicit null omission metadata is rejected; only absent metadata is valid for full archives.
    let mut with_null = encoded_json.clone();
    with_null["manifest"]["omittedSamples"] = serde_json::Value::Null;
    assert!(validate_archive_bytes(&serde_json::to_vec(&with_null).unwrap()).is_err());

    let export_resp = build_export_response(&archive);
    assert_eq!(
        export_resp.headers().get(HEADER_ARCHIVE_TELEMETRY).unwrap(),
        "complete"
    );
    assert!(export_resp
        .headers()
        .get(HEADER_OMITTED_SESSION_SAMPLES)
        .is_none());
    assert!(export_resp
        .headers()
        .get(HEADER_OMITTED_BANDWIDTH_SAMPLES)
        .is_none());

    let mut target = disposable_db();
    let (preview, token) =
        preview_and_token(&target.connection, &parsed, RestoreMode::Replace, 44, 6000);
    let preview_resp = response_from_preview(&preview, token.clone(), 6300);
    let preview_json = serde_json::to_value(&preview_resp).unwrap();
    assert!(preview_json.get("omittedSamples").is_none());
    assert!(preview_json.get("partialTelemetryNotice").is_none());

    let restored = restore_connection(
        &mut target.connection,
        target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Replace,
        &parsed,
        &token,
        6001,
    )
    .unwrap();
    let restored_json = serde_json::to_value(&restored).unwrap();
    assert!(restored_json.get("omittedSamples").is_none());
    assert!(restored_json.get("partialTelemetryNotice").is_none());
    assert_private_backup_exists(&target.root);
}

#[test]
fn truncated_export_binds_omitted_samples_and_surfaces_in_export_preview_and_restore() {
    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    for ts in [
        1_790_856_060_i64,
        1_790_856_120,
        1_790_856_180,
        1_790_856_240,
    ] {
        source
            .connection
            .execute(
                "INSERT INTO streaming_session_samples(history_id,sampled_at,observed_secs,playing,bitrate_bps) VALUES (7,?1,30,1,1200000)",
                [ts],
            )
            .unwrap();
    }
    source
        .connection
        .execute(
            "UPDATE streaming_bandwidth_samples SET timestamp = '2026-10-01 12:30:00' WHERE id = 4",
            [],
        )
        .unwrap();
    for (id, timestamp) in [
        (5_i64, "2026-10-01T12:20:00Z"),
        (6, "2026-10-01 12:10:00"),
        (7, "2026-10-01T12:00:00Z"),
    ] {
        source
            .connection
            .execute(
                "INSERT INTO streaming_bandwidth_samples(id,timestamp,provider,active_streams,direct_play_count,direct_stream_count,transcode_count,total_bitrate_bps,bytes_delta) VALUES (?1,?2,'jellyfin',1,1,0,0,1200000,1024)",
                params![id, timestamp],
            )
            .unwrap();
    }

    // Total rows = 1 history + 1 label + 1 policy + 5 session + 4 bw = 12.
    // With budget = 8: remaining_sample_budget = 5, half_budget = 2 -> retains 2 session + 3 bw.
    let archive = build_archive_with_budget(&source.connection, 1_798_876_800, 8).unwrap();
    assert_eq!(
        archive.manifest.omitted_samples,
        Some(OmittedSamples {
            session_samples: 3,
            bandwidth_samples: 1,
        })
    );
    assert_eq!(archive.manifest.record_counts.total(), Some(8));
    assert_eq!(archive.manifest.record_counts.history, 1);
    assert_eq!(archive.manifest.record_counts.labels, 1);
    assert_eq!(
        archive
            .data
            .bandwidth_samples
            .iter()
            .map(|sample| sample.id)
            .collect::<Vec<_>>(),
        [4, 5, 6]
    );

    let encoded_str = serde_json::to_string(&archive).unwrap();
    for secret in [
        "provider-secret-should-never-export",
        "device-secret-should-never-export",
        "Living Room",
        "192.0.2.8",
    ] {
        assert!(!encoded_str.contains(secret));
    }

    let export_resp = build_export_response(&archive);
    assert_eq!(
        export_resp.headers().get(HEADER_ARCHIVE_TELEMETRY).unwrap(),
        "partial"
    );
    assert_eq!(
        export_resp
            .headers()
            .get(HEADER_OMITTED_SESSION_SAMPLES)
            .unwrap(),
        "3"
    );
    assert_eq!(
        export_resp
            .headers()
            .get(HEADER_OMITTED_BANDWIDTH_SAMPLES)
            .unwrap(),
        "1"
    );

    // Integrity checks on omittedSamples: stripping, nulling, tampering, zeroing, unknown fields all fail.
    let encoded = serde_json::to_vec(&archive).unwrap();
    let mut stripped: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    stripped["manifest"]
        .as_object_mut()
        .unwrap()
        .remove("omittedSamples");
    assert!(validate_archive_bytes(&serde_json::to_vec(&stripped).unwrap()).is_err());

    let mut nulled: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    nulled["manifest"]["omittedSamples"] = serde_json::Value::Null;
    assert!(validate_archive_bytes(&serde_json::to_vec(&nulled).unwrap()).is_err());

    let mut tampered = archive.clone();
    tampered.manifest.omitted_samples = Some(OmittedSamples {
        session_samples: 1,
        bandwidth_samples: 1,
    });
    assert!(tampered.validate().is_err());

    let mut zeroed = archive.clone();
    zeroed.manifest.omitted_samples = Some(OmittedSamples {
        session_samples: 0,
        bandwidth_samples: 0,
    });
    zeroed.manifest.sha256 = zeroed.digest().unwrap();
    assert!(zeroed.validate().is_err());

    let mut with_extra: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    with_extra["manifest"]["omittedSamples"]["extra"] = serde_json::json!(1);
    assert!(validate_archive_bytes(&serde_json::to_vec(&with_extra).unwrap()).is_err());

    // Merge preview + restore explicitly surface omitted samples, notice, and backup verification.
    let mut merge_target = disposable_db();
    let (merge_preview, merge_token) = preview_and_token(
        &merge_target.connection,
        &archive,
        RestoreMode::Merge,
        44,
        7000,
    );
    let merge_preview_resp = response_from_preview(&merge_preview, merge_token.clone(), 7300);
    assert_eq!(
        merge_preview_resp.omitted_samples,
        archive.manifest.omitted_samples
    );
    assert!(merge_preview_resp
        .partial_telemetry_notice
        .as_deref()
        .is_some_and(|n| n.contains("3 earlier session") && n.contains("1 earlier bandwidth")));
    // Approval issued for merge cannot be replayed in replace mode.
    assert!(restore_connection(
        &mut merge_target.connection,
        merge_target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Replace,
        &archive,
        &merge_token,
        7001,
    )
    .is_err());
    let merge_restored = restore_connection(
        &mut merge_target.connection,
        merge_target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Merge,
        &archive,
        &merge_token,
        7001,
    )
    .unwrap();
    assert!(merge_restored.backup_verified);
    assert_eq!(
        merge_restored.omitted_samples,
        archive.manifest.omitted_samples
    );
    assert!(merge_restored.partial_telemetry_notice.is_some());
    assert_private_backup_exists(&merge_target.root);

    // Replace preview + restore explicitly warn about deleting destination samples & restoring retained subset.
    let mut replace_target = disposable_db();
    let (replace_preview, replace_token) = preview_and_token(
        &replace_target.connection,
        &archive,
        RestoreMode::Replace,
        44,
        8000,
    );
    let replace_preview_resp = response_from_preview(&replace_preview, replace_token.clone(), 8300);
    assert_eq!(
        replace_preview_resp.omitted_samples,
        archive.manifest.omitted_samples
    );
    assert!(replace_preview_resp
        .partial_telemetry_notice
        .as_deref()
        .is_some_and(|n| n.contains("Replacement deletes existing destination samples")));
    assert!(replace_preview_resp
        .replacement_notice
        .as_deref()
        .is_some_and(|n| n.contains("3 earlier session")));
    let replace_restored = restore_connection(
        &mut replace_target.connection,
        replace_target.database_path.to_str().unwrap(),
        44,
        RestoreMode::Replace,
        &archive,
        &replace_token,
        8001,
    )
    .unwrap();
    assert!(replace_restored.backup_verified);
    assert_eq!(
        replace_restored.omitted_samples,
        archive.manifest.omitted_samples
    );
    assert!(replace_restored.partial_telemetry_notice.is_some());
    assert_private_backup_exists(&replace_target.root);
}

#[test]
fn history_and_labels_are_never_dropped_when_budget_is_exhausted() {
    let source = disposable_db();
    seed_sensitive_data(&source.connection);
    // Base rows = 1 history + 1 label + 1 policy = 3.
    // Budget = 3 leaves zero sample budget: preserves history/labels and explicitly omits all samples.
    let zero_sample_archive =
        build_archive_with_budget(&source.connection, 1_798_876_800, 3).unwrap();
    assert_eq!(zero_sample_archive.manifest.record_counts.history, 1);
    assert_eq!(zero_sample_archive.manifest.record_counts.labels, 1);
    assert_eq!(
        zero_sample_archive.manifest.record_counts.session_samples,
        0
    );
    assert_eq!(
        zero_sample_archive.manifest.record_counts.bandwidth_samples,
        0
    );
    assert_eq!(
        zero_sample_archive.manifest.omitted_samples,
        Some(OmittedSamples {
            session_samples: 1,
            bandwidth_samples: 1,
        })
    );

    // Budget below history + labels + policy fails closed rather than dropping history or labels.
    let err = build_archive_with_budget(&source.connection, 1_798_876_800, 2).unwrap_err();
    assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(err.code, "streaming_archive_too_large");
}

#[test]
fn real_hundred_thousand_row_cap_marks_omitted_session_samples_and_preserves_history() {
    let source = disposable_db();
    source
        .connection
        .execute(
            "INSERT INTO streaming_history(id,session_key,provider,server_name,user_id,user_name,item_id,item_name,provenance,server_id,timestamp_certainty,byte_accuracy,policy_status) VALUES (1,'s-1','plex','Plex','u1','Alice','i1','Film','observed_session','srv-1','observed','estimated','included')",
            [],
        )
        .unwrap();
    source
        .connection
        .execute(
            "INSERT INTO streaming_history_labels(history_id,kind,value,name) VALUES (1,'library','lib-1','Movies')",
            [],
        )
        .unwrap();
    let tx = source.connection.unchecked_transaction().unwrap();
    {
        let mut stmt = tx
            .prepare("INSERT INTO streaming_session_samples(history_id,sampled_at,observed_secs,playing,bitrate_bps) VALUES (1,?1,1,1,0)")
            .unwrap();
        for ts in 1..=100_005_i64 {
            stmt.execute([ts]).unwrap();
        }
    }
    tx.commit().unwrap();

    let archive = build_archive(&source.connection, 1_798_876_800).unwrap();
    assert_eq!(archive.manifest.record_counts.history, 1);
    assert_eq!(archive.manifest.record_counts.labels, 1);
    assert_eq!(
        archive.manifest.record_counts.session_samples,
        MAX_PORTABLE_ROWS - 3
    );
    assert_eq!(
        archive.manifest.omitted_samples,
        Some(OmittedSamples {
            session_samples: 8,
            bandwidth_samples: 0,
        })
    );
    // Oldest 8 samples (1..=8) were dropped; newest 99,997 (9..=100,005) are retained.
    assert_eq!(archive.data.session_samples.first().unwrap().sampled_at, 9);
    assert_eq!(
        archive.data.session_samples.last().unwrap().sampled_at,
        100_005
    );
    assert!(ensure_archive_within_byte_limit(&archive).is_ok());
}
