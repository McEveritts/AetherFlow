use super::*;
use crate::auth::AuthUser;
use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{TimeZone, Utc};
use rusqlite::{params, Connection};
use std::time::{Duration, Instant};

#[test]
fn search_matches_literal_wildcards_backslashes_and_bound_injection_text() {
    let conn = setup_local_db();
    insert_row(&conn, &SeedRow { session_key: "literal", item_name: r"100%_complete\media ' OR 1=1 --", ..Default::default() });
    insert_row(&conn, &SeedRow { session_key: "other", item_name: "100Xcomplete unrelated", ..Default::default() });
    for search in [r"%_", r"\media", "' OR 1=1 --", "100%_complete"] {
        let page = query_history(&conn, HistoryQuery { search: search.into(), ..Default::default() }, &admin_user(1), 1_793_577_600).unwrap();
        assert_eq!(page.counts.matching_records, 1, "{search}");
        assert_eq!(page.items[0].item_name, r"100%_complete\media ' OR 1=1 --");
    }
}

#[test]
fn serialized_archive_contract_preserves_provenance_nulls_and_linked_scope() {
    let conn = setup_local_db();
    conn.execute("INSERT INTO users(id,username,role) VALUES(1,'operator','admin'),(2,'viewer','user')", []).unwrap();
    for (session_key, item_name, provenance, certainty, accuracy, started_at) in [
        ("contract-observed", "Contract Observed Play", "observed_session", "observed", "estimated", "2026-10-30T20:00:00Z"),
        ("contract-imported", "Contract Imported Play", "imported_event", "source_event", "unrecorded", "2026-10-29T20:00:00Z"),
        ("contract-summary", "Contract Item Summary", "item_summary", "unrecorded", "unrecorded", ""),
        ("contract-legacy", "Contract Legacy Record", "legacy_unverified", "legacy_unverified", "legacy_unverified", ""),
    ] {
        insert_row(&conn, &SeedRow { session_key, item_name, provenance, timestamp_certainty: certainty, byte_accuracy: accuracy, started_at, ..Default::default() });
    }
    conn.execute("INSERT INTO streaming_user_links(af_user_id,provider,server_id,provider_user_id) VALUES(2,'jellyfin','srv-main','jf-u1')", []).unwrap();
    let now = 1_793_577_600;
    let administrative = query_history(&conn, HistoryQuery::default(), &admin_user(1), now).unwrap();
    let linked = query_history(&conn, HistoryQuery::default(), &member_user(2), now).unwrap();
    assert_eq!(administrative.counts.confirmed_plays, 2);
    assert_eq!(administrative.counts.item_summaries, 1);
    assert_eq!(administrative.counts.legacy_records, 1);
    assert_eq!(administrative.counts.undated_records, 2);
    assert!(linked.items.iter().all(|item| item.ip_address.is_none() && item.device_id.is_none()));
    let summary = administrative.items.iter().find(|item| item.provenance == "item_summary").unwrap();
    assert!(summary.started_at.is_none() && summary.watched_secs.is_none() && summary.estimated_bytes.is_none());
    if let Ok(path) = std::env::var("AF_STREAMING_ARCHIVE_FIXTURE") {
        std::fs::write(path, serde_json::to_vec_pretty(&serde_json::json!({"administrative": administrative, "linked": linked})).unwrap()).unwrap();
    }
}

fn extract_raw_strings(mut src: &str) -> Vec<String> {
    let mut out = Vec::new();
    while let Some(pos) = src.find("r#\"") {
        let after_start = &src[pos + 3..];
        let end = after_start
            .find("\"#")
            .expect("unterminated raw string literal in af-db/src/lib.rs");
        out.push(after_start[..end].to_string());
        src = &after_start[end + 2..];
    }
    out
}

fn extract_quoted_ddl(block: &str, prefix: &str) -> Vec<String> {
    block
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let stripped = trimmed.strip_prefix('"')?;
            let sql = stripped.strip_suffix("\",")?;
            if sql.starts_with(prefix) {
                Some(sql.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn setup_local_db() -> Connection {
    let conn = Connection::open_in_memory().expect("open local in-memory sqlite connection");
    conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;")
        .expect("pragmas");

    let lib_src = include_str!("../../af-db/src/lib.rs");

    let core_marker = "CREATE TABLE IF NOT EXISTS settings (";
    let core_idx = lib_src.find(core_marker).expect("core marker in af-db/lib.rs");
    let raw_start = lib_src[..core_idx].rfind("r#\"").expect("core raw start");
    let raw_body = &lib_src[raw_start + 3..];
    let raw_end = raw_body.find("\"#").expect("core raw end");
    conn.execute_batch(&raw_body[..raw_end])
        .expect("execute core DDL");

    let m19_marker =
        "\"Add streaming_servers, streaming_history, and streaming_bandwidth_samples tables\"";
    let m19_start = lib_src.find(m19_marker).expect("migration 19 marker");
    let m19_tail = &lib_src[m19_start..];
    let m19_end = m19_tail
        .find("streaming::migrate_history")
        .expect("migrate_history marker");
    let m19_block = &m19_tail[..m19_end];

    for ddl in extract_raw_strings(m19_block) {
        conn.execute_batch(&ddl).expect("migration 19 table DDL");
    }
    for idx_sql in extract_quoted_ddl(m19_block, "CREATE INDEX") {
        conn.execute_batch(&idx_sql).expect("migration 19 index DDL");
    }
    conn.execute(
        "INSERT OR IGNORE INTO schema_versions (version, description) VALUES (19, 'v19')",
        [],
    )
    .expect("v19 version row");

    af_db::streaming::migrate_history(&conn, ":memory:").expect("apply migration 20");
    conn
}

fn admin_user(id: i64) -> AuthUser {
    AuthUser {
        user_id: id,
        username: format!("admin_{id}"),
        role: "admin".to_string(),
        jti: format!("jti-admin-{id}"),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    }
}

fn member_user(id: i64) -> AuthUser {
    AuthUser {
        user_id: id,
        username: format!("user_{id}"),
        role: "user".to_string(),
        jti: format!("jti-user-{id}"),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    }
}

struct SeedRow<'a> {
    session_key: &'a str,
    provider: &'a str,
    server_id: &'a str,
    user_id: &'a str,
    user_name: &'a str,
    item_id: &'a str,
    item_name: &'a str,
    item_type: &'a str,
    play_method: &'a str,
    provenance: &'a str,
    timestamp_certainty: &'a str,
    byte_accuracy: &'a str,
    policy_status: &'a str,
    watched_secs: i64,
    duration_secs: i64,
    data_used_bytes: i64,
    started_at: &'a str,
    device_id: &'a str,
    ip_address: &'a str,
}

impl<'a> Default for SeedRow<'a> {
    fn default() -> Self {
        Self {
            session_key: "sess-default",
            provider: "jellyfin",
            server_id: "srv-main",
            user_id: "jf-u1",
            user_name: "Alice",
            item_id: "item-1",
            item_name: "Blade Runner 2049",
            item_type: "Movie",
            play_method: "DirectPlay",
            provenance: "observed_session",
            timestamp_certainty: "observed",
            byte_accuracy: "estimated",
            policy_status: "included",
            watched_secs: 1800,
            duration_secs: 9800,
            data_used_bytes: 500_000_000,
            started_at: "2026-06-01T12:00:00Z",
            device_id: "dev-secret-1",
            ip_address: "192.168.10.55",
        }
    }
}

fn insert_row(conn: &Connection, row: &SeedRow<'_>) -> i64 {
    conn.execute(
        r#"
        INSERT INTO streaming_history (
            session_key, provider, server_id, user_id, user_name,
            client_name, device_name, device_id, ip_address,
            item_id, item_name, item_type, series_name,
            play_method, provenance, timestamp_certainty, byte_accuracy, policy_status,
            watched_secs, duration_secs, data_used_bytes, started_at, last_seen_at, ended_at, is_active
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5,
            'Jellyfin Media Player', 'Shield TV', ?6, ?7,
            ?8, ?9, ?10, '',
            ?11, ?12, ?13, ?14, ?15,
            ?16, ?17, ?18, ?19, ?19, ?19, 0
        )
        "#,
        params![
            row.session_key,
            row.provider,
            row.server_id,
            row.user_id,
            row.user_name,
            row.device_id,
            row.ip_address,
            row.item_id,
            row.item_name,
            row.item_type,
            row.play_method,
            row.provenance,
            row.timestamp_certainty,
            row.byte_accuracy,
            row.policy_status,
            row.watched_secs,
            row.duration_secs,
            row.data_used_bytes,
            row.started_at,
        ],
    )
    .expect("insert streaming_history row");
    conn.last_insert_rowid()
}

#[test]
fn pagination_over_500_rows_both_directions_with_timestamp_ties_and_undated_nulls() {
    let conn = setup_local_db();
    let admin = admin_user(1);
    let now = 1_780_000_000i64;

    // Seed 540 rows total:
    // - 520 dated rows across shared timestamps (groups of 4 sharing identical started_at to exercise tie-breaking on id)
    // - 20 undated rows (started_at = '') to exercise event_missing = 1 placement at the tail of both ASC and DESC sorts
    let mut expected_dated = Vec::with_capacity(520);
    let mut expected_undated = Vec::with_capacity(20);

    let tx = conn.unchecked_transaction().unwrap();
    for i in 0..520i64 {
        let bucket_ts = 1_775_000_000 + (i / 4) * 60; // every 4 records share identical timestamp
        let iso = Utc.timestamp_opt(bucket_ts, 0).unwrap().to_rfc3339();
        let sk = format!("dated-sess-{i}");
        let item_id = format!("item-{i}");
        let title = format!("Archive Film #{i}");
        let id = insert_row(
            &tx,
            &SeedRow {
                session_key: &sk,
                item_id: &item_id,
                item_name: &title,
                started_at: &iso,
                watched_secs: 600 + (i % 300),
                data_used_bytes: 1_000_000 * ((i % 50) + 1),
                ..Default::default()
            },
        );
        expected_dated.push((bucket_ts, id));
    }

    for i in 0..20i64 {
        let sk = format!("undated-sess-{i}");
        let item_id = format!("undated-item-{i}");
        let title = format!("Undated Summary #{i}");
        let id = insert_row(
            &tx,
            &SeedRow {
                session_key: &sk,
                item_id: &item_id,
                item_name: &title,
                provenance: "item_summary",
                timestamp_certainty: "unrecorded",
                byte_accuracy: "unrecorded",
                started_at: "",
                watched_secs: 0,
                data_used_bytes: 0,
                ..Default::default()
            },
        );
        expected_undated.push(id);
    }
    tx.commit().unwrap();

    // Expected DESC order: dated sorted by (timestamp DESC, id DESC), followed by undated sorted by id DESC
    let mut expected_desc_ids: Vec<i64> = {
        let mut d = expected_dated.clone();
        d.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        let mut u = expected_undated.clone();
        u.sort_by(|a, b| b.cmp(a));
        d.into_iter().map(|(_, id)| id).chain(u).collect()
    };

    // Expected ASC order: dated sorted by (timestamp ASC, id ASC), followed by undated sorted by id ASC
    let expected_asc_ids: Vec<i64> = {
        let mut d = expected_dated.clone();
        d.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let mut u = expected_undated.clone();
        u.sort();
        d.into_iter().map(|(_, id)| id).chain(u).collect()
    };

    assert_eq!(expected_desc_ids.len(), 540);
    assert_eq!(expected_asc_ids.len(), 540);

    // Traverse all pages in startedDesc with page_size = 75 (8 pages)
    let mut collected_desc = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages_desc = 0;
    let mut initial_counts = None;

    loop {
        let page = query_history(
            &conn,
            HistoryQuery {
                sort: "startedDesc".into(),
                page_size: 75,
                cursor: cursor.clone(),
                ..Default::default()
            },
            &admin,
            now,
        )
        .expect("query startedDesc page");

        if initial_counts.is_none() {
            assert_eq!(page.counts.available_records, 540);
            assert_eq!(page.counts.matching_records, 540);
            assert_eq!(page.counts.undated_records, 20);
            assert_eq!(page.counts.confirmed_plays, 520);
            assert_eq!(page.counts.item_summaries, 20);
            initial_counts = Some(page.counts.clone());
        } else {
            assert_eq!(
                Some(&page.counts),
                initial_counts.as_ref(),
                "counts must remain frozen across cursor pages"
            );
        }

        pages_desc += 1;
        collected_desc.extend(page.items.iter().map(|it| it.id));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    assert_eq!(pages_desc, 8);
    assert_eq!(
        collected_desc, expected_desc_ids,
        "startedDesc pagination across >500 rows with timestamp ties and undated nulls must be exact and duplicate/gap-free"
    );

    // Traverse all pages in startedAsc with page_size = 75 (8 pages)
    let mut collected_asc = Vec::new();
    let mut cursor_asc: Option<String> = None;
    let mut pages_asc = 0;

    loop {
        let page = query_history(
            &conn,
            HistoryQuery {
                sort: "startedAsc".into(),
                page_size: 75,
                cursor: cursor_asc.clone(),
                ..Default::default()
            },
            &admin,
            now,
        )
        .expect("query startedAsc page");

        pages_asc += 1;
        collected_asc.extend(page.items.iter().map(|it| it.id));
        cursor_asc = page.next_cursor;
        if cursor_asc.is_none() {
            break;
        }
    }

    assert_eq!(pages_asc, 8);
    assert_eq!(
        collected_asc, expected_asc_ids,
        "startedAsc pagination across >500 rows with timestamp ties and undated nulls must be exact and duplicate/gap-free"
    );
    let _ = &mut expected_desc_ids;
}

#[test]
fn non_admin_requires_explicit_user_links_and_redacts_sensitive_fields() {
    let conn = setup_local_db();
    let now = 1_780_000_000i64;

    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'root', 'admin'), (2, 'alice_af', 'user'), (3, 'bob_af', 'user')",
        [],
    )
    .unwrap();

    // Seed rows across different (provider, server_id, user_id) tuples
    let id_alice_srv1 = insert_row(
        &conn,
        &SeedRow {
            session_key: "s-alice-srv1",
            provider: "jellyfin",
            server_id: "srv-1",
            user_id: "jf-alice",
            user_name: "Alice",
            device_id: "dev-alice-private",
            ip_address: "203.0.113.10",
            ..Default::default()
        },
    );
    let _id_alice_srv2 = insert_row(
        &conn,
        &SeedRow {
            session_key: "s-alice-srv2",
            provider: "jellyfin",
            server_id: "srv-2",
            user_id: "jf-alice",
            user_name: "Alice",
            ..Default::default()
        },
    );
    let _id_bob_srv1 = insert_row(
        &conn,
        &SeedRow {
            session_key: "s-bob-srv1",
            provider: "jellyfin",
            server_id: "srv-1",
            user_id: "jf-bob",
            user_name: "Bob",
            ..Default::default()
        },
    );
    let _id_demo = insert_row(
        &conn,
        &SeedRow {
            session_key: "s-demo",
            provider: "demo",
            server_id: "srv-1",
            user_id: "jf-alice",
            user_name: "Alice",
            ..Default::default()
        },
    );

    let alice = member_user(2);
    let admin = admin_user(1);

    // 1. Without any streaming_user_links, non-admin sees 0 records
    let unlinked_page = query_history(&conn, HistoryQuery::default(), &alice, now).unwrap();
    assert_eq!(unlinked_page.scope.permission_scope, "linked_user");
    assert_eq!(unlinked_page.counts.available_records, 0);
    assert_eq!(unlinked_page.counts.matching_records, 0);
    assert!(unlinked_page.items.is_empty());

    // 2. Link alice_af (id=2) ONLY to (jellyfin, srv-1, jf-alice)
    conn.execute(
        "INSERT INTO streaming_user_links (af_user_id, provider, server_id, provider_user_id) VALUES (2, 'jellyfin', 'srv-1', 'jf-alice')",
        [],
    )
    .unwrap();

    let linked_page = query_history(&conn, HistoryQuery::default(), &alice, now).unwrap();
    assert_eq!(linked_page.counts.available_records, 1);
    assert_eq!(linked_page.counts.matching_records, 1);
    assert_eq!(linked_page.items.len(), 1);
    assert_eq!(linked_page.items[0].id, id_alice_srv1);
    assert_eq!(
        linked_page.items[0].device_id, None,
        "non-admin must not receive device_id"
    );
    assert_eq!(
        linked_page.items[0].ip_address, None,
        "non-admin must not receive ip_address"
    );

    // 3. Non-admin requesting include_excluded = true is rejected with 403 FORBIDDEN
    let excl_err = query_history(
        &conn,
        HistoryQuery {
            include_excluded: true,
            ..Default::default()
        },
        &alice,
        now,
    )
    .expect_err("non-admin include_excluded must fail");
    assert_eq!(excl_err.status, StatusCode::FORBIDDEN);
    assert_eq!(excl_err.code, "admin_required");

    // 4. Admin sees all 3 non-demo records and receives device_id + ip_address
    let admin_page = query_history(&conn, HistoryQuery::default(), &admin, now).unwrap();
    assert_eq!(admin_page.scope.permission_scope, "administrative");
    assert_eq!(admin_page.counts.available_records, 3);
    let alice_item = admin_page
        .items
        .iter()
        .find(|i| i.id == id_alice_srv1)
        .unwrap();
    assert_eq!(alice_item.device_id.as_deref(), Some("dev-alice-private"));
    assert_eq!(alice_item.ip_address.as_deref(), Some("203.0.113.10"));
}

#[test]
fn cursor_tamper_cross_scope_filter_mismatch_revision_invalidation_and_insert_watermark_freeze() {
    let conn = setup_local_db();
    let admin = admin_user(1);
    let other_admin = admin_user(99);
    let member = member_user(2);
    let now = 1_780_000_000i64;

    for i in 1..=6 {
        let sk = format!("cursor-s-{i}");
        let ts = Utc.timestamp_opt(1_779_000_000 + i * 60, 0).unwrap().to_rfc3339();
        insert_row(
            &conn,
            &SeedRow {
                session_key: &sk,
                started_at: &ts,
                ..Default::default()
            },
        );
    }

    let first_page = query_history(
        &conn,
        HistoryQuery {
            page_size: 3,
            ..Default::default()
        },
        &admin,
        now,
    )
    .expect("first page");
    assert_eq!(first_page.items.len(), 3);
    let cursor = first_page.next_cursor.clone().expect("next_cursor present");
    let snapshot_token = first_page.scope.snapshot_token.clone();

    for (cursor_value, snapshot_value) in [(Some(snapshot_token.clone()), None), (None, Some(cursor.clone()))] {
        let error = query_history(&conn, HistoryQuery { page_size: 3, cursor: cursor_value, snapshot: snapshot_value, ..Default::default() }, &admin, now).unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    // 1. Passing both cursor and snapshot is rejected
    let both_err = query_history(
        &conn,
        HistoryQuery {
            page_size: 3,
            cursor: Some(cursor.clone()),
            snapshot: Some(snapshot_token.clone()),
            ..Default::default()
        },
        &admin,
        now,
    )
    .unwrap_err();
    assert_eq!(both_err.status, StatusCode::BAD_REQUEST);
    assert_eq!(both_err.code, "invalid_history_query");

    // 2. Signature tamper is rejected
    let (payload_b64, sig_b64) = cursor.split_once('.').unwrap();
    let mut sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
    sig_bytes[0] ^= 0xFF;
    let tampered_sig_cursor = format!("{}.{}", payload_b64, URL_SAFE_NO_PAD.encode(&sig_bytes));
    let tamper_err = query_history(
        &conn,
        HistoryQuery {
            page_size: 3,
            cursor: Some(tampered_sig_cursor),
            ..Default::default()
        },
        &admin,
        now,
    )
    .unwrap_err();
    assert_eq!(tamper_err.status, StatusCode::BAD_REQUEST);
    assert_eq!(tamper_err.message, "Invalid history cursor signature");

    // 3. Payload tamper with original signature is rejected
    let mut payload_json: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
    payload_json["watermark"] = serde_json::json!(999999);
    let tampered_payload_cursor = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload_json).unwrap()),
        sig_b64
    );
    let payload_tamper_err = query_history(
        &conn,
        HistoryQuery {
            page_size: 3,
            cursor: Some(tampered_payload_cursor),
            ..Default::default()
        },
        &admin,
        now,
    )
    .unwrap_err();
    assert_eq!(payload_tamper_err.status, StatusCode::BAD_REQUEST);
    assert_eq!(payload_tamper_err.message, "Invalid history cursor signature");

    // 4. Cross-viewer / cross-scope usage is rejected (different user_id or different role)
    for wrong_viewer in [&other_admin, &member] {
        let scope_err = query_history(
            &conn,
            HistoryQuery {
                page_size: 3,
                cursor: Some(cursor.clone()),
                ..Default::default()
            },
            wrong_viewer,
            now,
        )
        .unwrap_err();
        assert_eq!(scope_err.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            scope_err.message,
            "Cursor belongs to another query or viewer"
        );
    }

    // 5. Filter or sort mutation with existing cursor is rejected via fingerprint mismatch
    let filter_mismatch_err = query_history(
        &conn,
        HistoryQuery {
            page_size: 3,
            provider: "jellyfin".into(), // original was "all"
            cursor: Some(cursor.clone()),
            ..Default::default()
        },
        &admin,
        now,
    )
    .unwrap_err();
    assert_eq!(filter_mismatch_err.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        filter_mismatch_err.message,
        "Cursor belongs to another query or viewer"
    );

    // 6. Expired cursor (now >= expires_at) returns 409 CONFLICT stale
    let expired_err = query_history(
        &conn,
        HistoryQuery {
            page_size: 3,
            cursor: Some(cursor.clone()),
            ..Default::default()
        },
        &admin,
        now + CURSOR_TTL_SECS,
    )
    .unwrap_err();
    assert_eq!(expired_err.status, StatusCode::CONFLICT);
    assert_eq!(expired_err.code, "history_snapshot_changed");

    // 7. Concurrent INSERT freeze: inserting a new row does NOT bump revision, and watermark freezes the snapshot so page 2 sees only the original 3 remaining rows
    let new_ts = Utc.timestamp_opt(1_779_999_000, 0).unwrap().to_rfc3339();
    insert_row(
        &conn,
        &SeedRow {
            session_key: "cursor-s-new-after-snapshot",
            started_at: &new_ts,
            ..Default::default()
        },
    );

    // Re-querying page 1 via `snapshot_token` freezes watermark at 6 even though row 7 exists
    let frozen_first = query_history(
        &conn,
        HistoryQuery {
            page_size: 3,
            snapshot: Some(snapshot_token),
            ..Default::default()
        },
        &admin,
        now + 5,
    )
    .expect("snapshot token must freeze new inserts via watermark");
    assert_eq!(frozen_first.counts.matching_records, 6);
    assert_eq!(
        frozen_first.items.iter().map(|i| i.id).collect::<Vec<_>>(),
        first_page.items.iter().map(|i| i.id).collect::<Vec<_>>()
    );

    // Fetching page 2 via `cursor` succeeds and completes the 6-row snapshot
    let second_page = query_history(
        &conn,
        HistoryQuery {
            page_size: 3,
            cursor: Some(cursor.clone()),
            ..Default::default()
        },
        &admin,
        now + 5,
    )
    .expect("second page under watermark freeze");
    assert_eq!(second_page.items.len(), 3);
    assert_eq!(second_page.next_cursor, None);

    // 8. Revision invalidation: mutating an existing record or policy bumps streaming_history_revision and invalidates the cursor with 409 CONFLICT
    conn.execute(
        "UPDATE streaming_tracking_policies SET minimum_watch_secs = 10 WHERE id = 1",
        [],
    )
    .unwrap();
    let rev_err = query_history(
        &conn,
        HistoryQuery {
            page_size: 3,
            cursor: Some(cursor),
            ..Default::default()
        },
        &admin,
        now + 10,
    )
    .unwrap_err();
    assert_eq!(rev_err.status, StatusCode::CONFLICT);
    assert_eq!(rev_err.code, "history_snapshot_changed");
}

#[test]
fn tracking_policies_filter_minimum_watch_excluded_users_libraries_and_policy_status() {
    let conn = setup_local_db();
    let admin = admin_user(1);
    let now = 1_780_000_000i64;

    // Row 1: included observed_session with 600s watch time (above threshold)
    let id_ok = insert_row(
        &conn,
        &SeedRow {
            session_key: "p-ok",
            provider: "jellyfin",
            server_id: "srv-1",
            user_id: "u-good",
            watched_secs: 600,
            data_used_bytes: 100_000,
            ..Default::default()
        },
    );

    // Row 2: observed_session with short watch time (30s < 120s minimum_watch_secs)
    let id_short_observed = insert_row(
        &conn,
        &SeedRow {
            session_key: "p-short-obs",
            provider: "jellyfin",
            server_id: "srv-1",
            user_id: "u-good",
            watched_secs: 30,
            data_used_bytes: 50_000,
            ..Default::default()
        },
    );

    // Row 3: legacy_unverified with 10s watch time (exempt from minimum_watch_secs per INCLUDED rule!)
    let id_short_legacy = insert_row(
        &conn,
        &SeedRow {
            session_key: "p-short-legacy",
            provider: "jellyfin",
            server_id: "srv-1",
            user_id: "u-good",
            provenance: "legacy_unverified",
            timestamp_certainty: "legacy_unverified",
            byte_accuracy: "legacy_unverified",
            watched_secs: 10,
            data_used_bytes: 999_999,
            ..Default::default()
        },
    );

    // Row 4: excluded user on (jellyfin, srv-1, u-banned)
    let id_excl_user = insert_row(
        &conn,
        &SeedRow {
            session_key: "p-excl-user",
            provider: "jellyfin",
            server_id: "srv-1",
            user_id: "u-banned",
            watched_secs: 900,
            ..Default::default()
        },
    );

    // Row 5: same user_id 'u-banned' but on different server 'srv-2' -> NOT excluded!
    let id_other_server_user = insert_row(
        &conn,
        &SeedRow {
            session_key: "p-other-srv-user",
            provider: "jellyfin",
            server_id: "srv-2",
            user_id: "u-banned",
            watched_secs: 900,
            data_used_bytes: 200_000,
            ..Default::default()
        },
    );

    // Row 6: item tagged with excluded library 'lib-kids' on (jellyfin, srv-1)
    let id_excl_lib = insert_row(
        &conn,
        &SeedRow {
            session_key: "p-excl-lib",
            provider: "jellyfin",
            server_id: "srv-1",
            user_id: "u-good",
            watched_secs: 900,
            ..Default::default()
        },
    );
    conn.execute(
        "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES (?1, 'library', 'lib-kids', 'Kids'), (?1, 'genre', 'Animation', 'Animation')",
        params![id_excl_lib],
    )
    .unwrap();

    // Row 7: explicitly marked policy_status = 'duplicate'
    let id_duplicate = insert_row(
        &conn,
        &SeedRow {
            session_key: "p-dup",
            provider: "jellyfin",
            server_id: "srv-1",
            user_id: "u-good",
            policy_status: "duplicate",
            watched_secs: 900,
            ..Default::default()
        },
    );

    // Configure tracking policies
    conn.execute(
        r#"
        UPDATE streaming_tracking_policies
        SET minimum_watch_secs = 120,
            excluded_users = '[{"provider":"jellyfin","serverId":"srv-1","id":"u-banned"}]',
            excluded_libraries = '[{"provider":"jellyfin","serverId":"srv-1","id":"lib-kids"}]'
        WHERE id = 1
        "#,
        [],
    )
    .unwrap();

    // Default query (include_excluded = false): only id_ok, id_short_legacy, id_other_server_user are returned
    let default_page = query_history(&conn, HistoryQuery::default(), &admin, now).unwrap();
    let mut returned_ids: Vec<i64> = default_page.items.iter().map(|i| i.id).collect();
    returned_ids.sort();
    assert_eq!(
        returned_ids,
        vec![id_ok, id_short_legacy, id_other_server_user]
    );
    assert!(default_page.items.iter().all(|i| i.included));
    assert_eq!(default_page.counts.matching_records, 3);
    assert_eq!(default_page.counts.confirmed_plays, 2); // id_ok + id_other_server_user
    assert_eq!(default_page.counts.legacy_records, 1); // id_short_legacy
    assert_eq!(default_page.counts.watch_time_secs, 600 + 900);
    assert_eq!(default_page.counts.estimated_bytes, 100_000 + 200_000);

    // Admin with include_excluded = true sees all 7 rows, with `included` accurately computed per row
    // and confirmed_plays / watch_time_secs / estimated_bytes still only counting INCLUDED confirmed plays!
    let all_page = query_history(
        &conn,
        HistoryQuery {
            include_excluded: true,
            ..Default::default()
        },
        &admin,
        now,
    )
    .unwrap();
    assert_eq!(all_page.counts.matching_records, 7);
    assert_eq!(all_page.counts.confirmed_plays, 2);
    assert_eq!(all_page.counts.watch_time_secs, 1500);
    assert_eq!(all_page.counts.estimated_bytes, 300_000);

    for item in &all_page.items {
        let should_be_included =
            [id_ok, id_short_legacy, id_other_server_user].contains(&item.id);
        assert_eq!(
            item.included, should_be_included,
            "mismatch on item.included for id={}",
            item.id
        );
    }

    let lib_item = all_page.items.iter().find(|i| i.id == id_excl_lib).unwrap();
    assert_eq!(lib_item.library_ids, vec!["lib-kids".to_string()]);
    assert_eq!(lib_item.genres, vec!["Animation".to_string()]);

    let _ = (id_short_observed, id_excl_user, id_duplicate);
}

#[test]
fn timezone_dst_calendar_windows_and_half_open_bounds() {
    let conn = setup_local_db();
    let admin = admin_user(1);

    // Test America/New_York spring-forward DST day: 2026-03-08 (clocks jump 02:00 EST -> 03:00 EDT).
    // Local midnight 2026-03-08T00:00:00 in America/New_York is UTC-5 = 2026-03-08T05:00:00Z (1_772_946_000).
    // Reference `as_of`: 2026-03-08T18:00:00Z (1_772_992_800, which is 14:00 EDT).
    let as_of = Utc.with_ymd_and_hms(2026, 3, 8, 18, 0, 0).unwrap().timestamp();
    let ny_midnight_utc = Utc.with_ymd_and_hms(2026, 3, 8, 5, 0, 0).unwrap().timestamp();
    let mar1_ny_midnight_utc = Utc.with_ymd_and_hms(2026, 3, 1, 5, 0, 0).unwrap().timestamp();

    // Row A: 1 second before NY midnight (2026-03-07 23:59:59 EST = 2026-03-08T04:59:59Z)
    let id_before_today = insert_row(
        &conn,
        &SeedRow {
            session_key: "dst-before-today",
            started_at: &Utc
                .timestamp_opt(ny_midnight_utc - 1, 0)
                .unwrap()
                .to_rfc3339(),
            ..Default::default()
        },
    );
    // Row B: exact NY midnight (inclusive lower bound)
    let id_at_midnight = insert_row(
        &conn,
        &SeedRow {
            session_key: "dst-at-midnight",
            started_at: &Utc.timestamp_opt(ny_midnight_utc, 0).unwrap().to_rfc3339(),
            ..Default::default()
        },
    );
    // Row C: exact `as_of` (exclusive upper bound: event_unix < end)
    let id_at_as_of = insert_row(
        &conn,
        &SeedRow {
            session_key: "dst-at-as-of",
            started_at: &Utc.timestamp_opt(as_of, 0).unwrap().to_rfc3339(),
            ..Default::default()
        },
    );
    // Row D: March 1st NY midnight (in `month` window, before `today`)
    let id_month_start = insert_row(
        &conn,
        &SeedRow {
            session_key: "dst-month-start",
            started_at: &Utc
                .timestamp_opt(mar1_ny_midnight_utc, 0)
                .unwrap()
                .to_rfc3339(),
            ..Default::default()
        },
    );
    // Row E: undated record (only appears in `all`, excluded from bounded windows)
    let _id_undated = insert_row(
        &conn,
        &SeedRow {
            session_key: "dst-undated",
            provenance: "item_summary",
            timestamp_certainty: "unrecorded",
            byte_accuracy: "unrecorded",
            started_at: "",
            ..Default::default()
        },
    );

    // 1. `today` in America/New_York: includes [ny_midnight_utc, as_of) -> only id_at_midnight
    let today_ny = query_history(
        &conn,
        HistoryQuery {
            window: "today".into(),
            timezone: "America/New_York".into(),
            ..Default::default()
        },
        &admin,
        as_of,
    )
    .unwrap();
    let today_ny_ids: Vec<i64> = today_ny.items.iter().map(|i| i.id).collect();
    assert_eq!(
        today_ny_ids,
        vec![id_at_midnight],
        "today in America/New_York must start at 05:00Z and exclude >= as_of and undated"
    );

    // 2. `today` in UTC for the exact same `as_of`: UTC midnight was 00:00Z, so `id_before_today` (04:59:59Z) IS included in UTC today!
    let today_utc = query_history(
        &conn,
        HistoryQuery {
            window: "today".into(),
            timezone: "UTC".into(),
            ..Default::default()
        },
        &admin,
        as_of,
    )
    .unwrap();
    let today_utc_ids: Vec<i64> = today_utc.items.iter().map(|i| i.id).collect();
    assert_eq!(today_utc_ids, vec![id_at_midnight, id_before_today]);

    // 3. `month` in America/New_York: includes id_at_midnight, id_before_today, id_month_start
    let month_ny = query_history(
        &conn,
        HistoryQuery {
            window: "month".into(),
            timezone: "America/New_York".into(),
            ..Default::default()
        },
        &admin,
        as_of,
    )
    .unwrap();
    let month_ny_ids: Vec<i64> = month_ny.items.iter().map(|i| i.id).collect();
    assert_eq!(
        month_ny_ids,
        vec![id_at_midnight, id_before_today, id_month_start]
    );

    // 4. `custom` window with explicit RFC3339 offsets & validation
    let custom_page = query_history(
        &conn,
        HistoryQuery {
            window: "custom".into(),
            from: "2026-03-08T00:00:00-05:00".into(),
            until: "2026-03-08T14:00:01-04:00".into(), // 1 second after as_of, so id_at_as_of is included
            timezone: "America/New_York".into(),
            ..Default::default()
        },
        &admin,
        as_of,
    )
    .unwrap();
    let custom_ids: Vec<i64> = custom_page.items.iter().map(|i| i.id).collect();
    assert_eq!(custom_ids, vec![id_at_as_of, id_at_midnight]);
}

#[test]
fn csv_export_neutralizes_formula_injection_and_escapes_quotes() {
    assert_eq!(csv_cell("   \tpayload"), "\"'   \tpayload\"");
    let sample_item = HistoryItem {
        id: 42,
        provider: "jellyfin".into(),
        server_id: "srv-1".into(),
        source_event_id: None,
        provenance: "observed_session".into(),
        timestamp_certainty: "observed".into(),
        byte_accuracy: "estimated".into(),
        user_id: "+cmd|'/C calc'!A0".into(),
        user_name: "  =SUM(A1:A2)".into(),
        client_name: Some("-2+3+cmd".into()),
        device_name: Some("@IMPORTXML(\"http://evil\", \"//a\")".into()),
        device_id: Some("\tmalicious-tab".into()),
        ip_address: Some("\r\ninjected-header".into()),
        item_id: "item-csv".into(),
        item_name: "He said \"Hello, =World\"".into(),
        item_type: Some("Movie".into()),
        series_name: None,
        play_method: Some("directplay".into()),
        watched_secs: Some(1200),
        duration_secs: Some(3600),
        estimated_bytes: Some(4096),
        started_at: Some("2026-06-01T12:00:00+00:00".into()),
        last_seen_at: None,
        ended_at: Some("2026-06-01T12:20:00+00:00".into()),
        is_active: false,
        included: true,
        policy_status: "included".into(),
        library_ids: vec!["=lib1".into(), "lib2".into()],
        genres: vec!["Sci-Fi".into(), "Drama".into()],
    };

    // Member CSV: 20 columns (excludes IPAddress and DeviceId), dangerous formulas prefixed with single quote `'`
    let member_csv = csv_page(std::slice::from_ref(&sample_item), false);
    assert!(member_csv.ends_with("\r\n"));
    let member_fields: Vec<&str> = member_csv.trim_end_matches("\r\n").split("\",\"").collect();
    assert_eq!(
        member_fields.len(),
        20,
        "non-admin CSV must have 20 columns without IP/DeviceId"
    );
    assert!(
        member_csv.contains("\"'  =SUM(A1:A2)\""),
        "leading whitespace before '=' must still trigger formula neutralization"
    );
    assert!(
        member_csv.contains("\"'+cmd|'/C calc'!A0\""),
        "'+' formula prefix must be neutralized"
    );
    assert!(
        member_csv.contains("\"'-2+3+cmd\""),
        "'-' formula prefix must be neutralized"
    );
    assert!(
        member_csv.contains("\"'@IMPORTXML(\"\"http://evil\"\", \"\"//a\"\")\""),
        "'@' formula prefix and embedded double quotes must be neutralized and escaped"
    );
    assert!(
        member_csv.contains("\"He said \"\"Hello, =World\"\"\""),
        "normal text with embedded quotes must escape quotes without adding leading apostrophe"
    );
    assert!(
        member_csv.contains("\"'=lib1;lib2\""),
        "joined library_ids starting with '=' must be neutralized"
    );

    // Admin CSV: 22 columns (includes IPAddress and DeviceId with tab/CR/LF formula neutralization)
    let admin_csv = csv_page(&[sample_item], true);
    let admin_fields: Vec<&str> = admin_csv.trim_end_matches("\r\n").split("\",\"").collect();
    assert_eq!(admin_fields.len(), 22, "admin CSV must have 22 columns");
    assert!(
        admin_csv.contains("\"'\tmalicious-tab\""),
        "leading tab must be neutralized"
    );
    assert!(
        admin_csv.contains("\"'\r\ninjected-header\""),
        "leading CR/LF must be neutralized"
    );
}

#[test]
fn performance_100k_archive_initial_and_deep_cursor_queries_stay_within_budget() {
    let conn = setup_local_db();
    let admin = admin_user(1);
    let now = 1_800_000_000i64;

    // Bulk-insert 100,000 canonical archive rows in a single transaction
    conn.execute_batch(
        r#"
        WITH RECURSIVE seq(n) AS (
            VALUES(1)
            UNION ALL
            SELECT n + 1 FROM seq WHERE n < 100000
        )
        INSERT INTO streaming_history (
            session_key, provider, server_id, user_id, user_name,
            client_name, device_name, device_id, ip_address,
            item_id, item_name, item_type, series_name,
            play_method, provenance, timestamp_certainty, byte_accuracy, policy_status,
            watched_secs, duration_secs, data_used_bytes, started_at, last_seen_at, ended_at, is_active
        )
        SELECT
            'bulk-sess-' || n,
            CASE WHEN n % 10 = 0 THEN 'emby' ELSE 'jellyfin' END,
            'srv-perf',
            'user-' || (n % 25),
            'Viewer ' || (n % 25),
            'Jellyfin Media Player',
            'Apple TV',
            'dev-' || (n % 50),
            '10.0.0.' || (n % 250),
            'item-' || (n % 500),
            'Performance Title ' || (n % 500),
            CASE WHEN n % 3 = 0 THEN 'Episode' ELSE 'Movie' END,
            '',
            'DirectPlay',
            'observed_session',
            'observed',
            'estimated',
            'included',
            1200,
            3600,
            250000000,
            strftime('%Y-%m-%dT%H:%M:%SZ', 1700000000 + n * 10, 'unixepoch'),
            strftime('%Y-%m-%dT%H:%M:%SZ', 1700000000 + n * 10, 'unixepoch'),
            strftime('%Y-%m-%dT%H:%M:%SZ', 1700000000 + n * 10, 'unixepoch'),
            0
        FROM seq;
        "#,
    )
    .expect("bulk insert 100k streaming_history rows");

    let seek_plan: String = {
        let mut stmt = conn
            .prepare("EXPLAIN QUERY PLAN SELECT id FROM streaming_history WHERE event_missing = 0 AND (event_unix, id) < (1750000000, 50000) ORDER BY event_missing ASC, event_unix DESC, id DESC LIMIT 50")
            .unwrap();
        let rows: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.join(" | ")
    };
    assert!(
        seek_plan.contains("SEARCH")
            && (seek_plan.contains("idx_streaming_archive_desc")
                || seek_plan.contains("idx_streaming_archive_asc"))
            && !seek_plan.contains("USE TEMP B-TREE"),
        "100k archive seek must use either archive sort index without temp sort, got plan: {seek_plan}"
    );

    let actual_keyset_plan: String = {
        let sql = format!(
            "EXPLAIN QUERY PLAN SELECT h.id {FROM_HISTORY} WHERE p.id = 1 AND h.provider != 'demo' AND h.id <= 100000 AND ({INCLUDED}) AND h.event_missing = 0 AND (h.event_unix,h.id) < (1700005000, 500) ORDER BY h.event_missing ASC, h.event_unix DESC, h.id DESC LIMIT 201"
        );
        let mut stmt = conn.prepare(&sql).unwrap();
        let rows: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.join(" | ")
    };

    let start_first = Instant::now();
    let first_page = query_history(
        &conn,
        HistoryQuery {
            page_size: 200,
            ..Default::default()
        },
        &admin,
        now,
    )
    .expect("query first page on 100k archive");
    let first_elapsed = start_first.elapsed();

    assert_eq!(first_page.counts.available_records, 100_000);
    assert_eq!(first_page.counts.matching_records, 100_000);
    assert_eq!(first_page.counts.confirmed_plays, 100_000);
    assert_eq!(first_page.items.len(), 200);
    assert_eq!(first_page.items[0].id, 100_000);
    assert!(
        first_elapsed < Duration::from_secs(2),
        "initial 100k query took too long: {first_elapsed:?}"
    );

    let cursor = first_page.next_cursor.expect("next_cursor on 100k archive");
    let mut deep_snapshot = decode(&cursor, now).unwrap();
    deep_snapshot.anchor = Some(Anchor { missing: 0, timestamp: 1_700_005_000, id: 500 });
    let deep_start = Instant::now();
    let deep_page = query_history(&conn, HistoryQuery { page_size: 200, cursor: Some(sign(&deep_snapshot)), ..Default::default() }, &admin, now).unwrap();
    let deep_elapsed = deep_start.elapsed();
    assert_eq!(deep_page.items[0].id, 499);
    assert!(deep_elapsed < Duration::from_millis(250), "deep keyset seek: {deep_elapsed:?}");
    println!("100k_deep_seek: duration={deep_elapsed:?} plan={actual_keyset_plan}");
    let start_second = Instant::now();
    let second_page = query_history(
        &conn,
        HistoryQuery {
            page_size: 200,
            cursor: Some(cursor),
            ..Default::default()
        },
        &admin,
        now,
    )
    .expect("query second page on 100k archive");
    let second_elapsed = start_second.elapsed();

    println!(
        "100k_archive_perf: first_page={first_elapsed:?} second_page={second_elapsed:?} seek_plan=\"{seek_plan}\" actual_keyset_plan=\"{actual_keyset_plan}\""
    );

    assert_eq!(second_page.items.len(), 200);
    assert_eq!(second_page.items[0].id, 99_800);
    assert!(
        second_elapsed < Duration::from_millis(250),
        "cursor seek page on 100k archive must stay within budget, took: {second_elapsed:?}"
    );
    let export_start = Instant::now();
    let mut export_query = HistoryQuery { page_size: 200, snapshot: Some(first_page.scope.snapshot_token), ..Default::default() };
    let mut exported = 0;
    let mut largest_chunk = 0;
    loop {
        let page = query_history_batch(&conn, export_query.clone(), &admin, now, Some(1000)).unwrap();
        assert!(page.items.len() <= 1000);
        exported += page.items.len();
        largest_chunk = largest_chunk.max(csv_page(&page.items, true).len());
        match page.next_cursor {
            Some(cursor) => { export_query.snapshot = None; export_query.cursor = Some(cursor); }
            None => break,
        }
    }
    assert_eq!(exported, 100_000);
    assert!(export_start.elapsed() < Duration::from_secs(30));
    println!("100k_batched_csv: elapsed={:?}, rows={exported}, largest_chunk_bytes={largest_chunk}", export_start.elapsed());
}
