use super::*;
use crate::auth::AuthUser;
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use rand::Rng;
use rusqlite::{params, Connection};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let token: u128 = rng.gen();
            let path = std::env::temp_dir().join(format!("af-tus-uploads-test-{token:032x}"));
            if fs::create_dir(&path).is_ok() {
                return Self { path };
            }
        }
        panic!("failed to allocate test temp dir");
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn human_user(user_id: i64) -> AuthUser {
    AuthUser {
        user_id,
        username: format!("user{user_id}"),
        role: "user".to_string(),
        jti: format!("jti-{user_id}"),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    }
}

fn plugin_user(user_id: i64) -> AuthUser {
    AuthUser {
        user_id,
        username: format!("plugin:sonarr"),
        role: "plugin".to_string(),
        jti: "jti-plugin".to_string(),
        plugin_id: Some("sonarr".to_string()),
        plugin_scopes: vec!["/api/v1/auth/mcbrowser/*".to_string()],
    }
}

fn setup_isolated_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE user_quotas (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            quota_bytes INTEGER DEFAULT 0,
            used_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            source TEXT DEFAULT 'manual',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO users (id, username) VALUES (1, 'alice'), (2, 'bob'), (3, 'suspended_carol');
        INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status)
        VALUES (1, 'alice', 10000, 1000, 'active'),
               (2, 'bob', 10000, 0, 'active'),
               (3, 'suspended_carol', 10000, 0, 'suspended');
        "#,
    )
    .unwrap();
    ensure_uploads_schema(&conn).unwrap();
    conn
}

fn queried_used_bytes(conn: &Connection, user_id: i64) -> i64 {
    conn.query_row(
        "SELECT used_bytes FROM user_quotas WHERE user_id = ?1",
        params![user_id],
        |r| r.get(0),
    )
    .unwrap()
}

#[tokio::test]
async fn expired_cleanup_advances_past_a_full_page_of_ambiguous_uploads() {
    let conn = setup_isolated_db();
    let temporary = TestTempDir::new();
    conn.execute_batch(
        "INSERT INTO users (id, username) VALUES (4, 'dave'), (5, 'eve');
         INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status)
         VALUES (4, 'dave', 10000, 0, 'active'), (5, 'eve', 10000, 0, 'active');
         UPDATE user_quotas SET status = 'active' WHERE user_id = 3;",
    ).unwrap();
    let mut ambiguous = Vec::new();
    for index in 0..128 {
        let user_id = index / 32 + 1;
        let (session, _) = create_upload_session_at(
            &conn,
            temporary.path(),
            &human_user(user_id),
            &tus_post_headers(&format!("ambiguous-{index}.bin"), None, 4),
            None,
        ).unwrap();
        remove_publication_proof_at(temporary.path(), user_id, &session.id).unwrap();
        ambiguous.push(session);
    }
    let (safe, _) = create_upload_session_at(
        &conn,
        temporary.path(),
        &human_user(5),
        &tus_post_headers("safe-expired.bin", None, 4),
        None,
    ).unwrap();
    for session in &ambiguous {
        conn.execute(
            "UPDATE mcbrowser_uploads SET status = 'publishing', offset_bytes = 4, expires_at = 1 WHERE id = ?1",
            [&session.id],
        ).unwrap();
    }
    conn.execute("UPDATE mcbrowser_uploads SET expires_at = 2 WHERE id = ?1", [&safe.id]).unwrap();
    let retained_quota: Vec<i64> = (1..=4).map(|user_id| queried_used_bytes(&conn, user_id)).collect();
    assert_eq!(cleanup_expired_uploads_at(&conn, temporary.path(), 100).unwrap(), 0);
    assert!(load_session_conn(&conn, &safe.id).unwrap().is_some());
    assert_eq!(cleanup_expired_uploads_at(&conn, temporary.path(), 100).unwrap(), 1);
    assert!(load_session_conn(&conn, &safe.id).unwrap().is_none());
    assert!(open_existing_staging_file_at(temporary.path(), 5, &safe.id).is_err());
    assert_eq!(queried_used_bytes(&conn, 5), 0);
    assert_eq!(cleanup_expired_uploads_at(&conn, temporary.path(), 100).unwrap(), 0);
    for session in &ambiguous {
        assert!(load_session_conn(&conn, &session.id).unwrap().is_some());
        let audit = super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id).unwrap().unwrap();
        assert_eq!(audit.status, super::super::events::AuditEventStatus::Pending);
    }
    assert_eq!(retained_quota, (1..=4).map(|user_id| queried_used_bytes(&conn, user_id)).collect::<Vec<_>>());
}

#[tokio::test]
async fn public_head_audit_binding_repair_rolls_back_intent_when_binding_fails() {
    let conn = setup_isolated_db();
    let temporary = TestTempDir::new();
    let user = human_user(1);
    let (session, _) = create_upload_session_at(
        &conn,
        temporary.path(),
        &user,
        &tus_post_headers("binding-recovery.txt", None, 4),
        None,
    ).unwrap();
    let mut staging = open_existing_staging_file_at(temporary.path(), 1, &session.id).unwrap();
    staging.write_all(b"data").unwrap();
    staging.sync_all().unwrap();
    conn.execute("UPDATE mcbrowser_uploads SET offset_bytes = 4, status = 'publishing', audit_event_id = '' WHERE id = ?1", [&session.id]).unwrap();
    conn.execute("DELETE FROM mcbrowser_audit_events WHERE event_id = ?1", [&session.audit_event_id]).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_audit_binding BEFORE UPDATE OF audit_event_id ON mcbrowser_uploads
         WHEN NEW.audit_event_id != '' BEGIN SELECT RAISE(ABORT, 'binding unavailable'); END;",
    ).unwrap();
    let count_intents = || conn.query_row("SELECT COUNT(*) FROM mcbrowser_audit_events", [], |row| row.get::<_, i64>(0)).unwrap();
    assert_eq!(head_upload_at(&conn, temporary.path(), &user, &session.id, &tus_basic_headers()).unwrap_err().status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(count_intents(), 0);
    assert_eq!(load_session_conn(&conn, &session.id).unwrap().unwrap().audit_event_id, "");
    let filesystem = super::super::open_user_browser_fs_at(temporary.path(), 1).unwrap();
    assert!(filesystem.open_file("binding-recovery.txt").is_err());
    conn.execute_batch("DROP TRIGGER reject_audit_binding").unwrap();
    let response = head_upload_at(&conn, temporary.path(), &user, &session.id, &tus_basic_headers()).unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["Upload-Status"], "completed");
    assert_eq!(count_intents(), 1);
    let recovered = load_session_conn(&conn, &session.id).unwrap().unwrap();
    assert!(!recovered.audit_event_id.is_empty());
    let audit = super::super::events::load_audit_record_by_id_with_conn(&conn, &recovered.audit_event_id).unwrap().unwrap();
    assert_eq!(audit.status, super::super::events::AuditEventStatus::Completed);
    assert_eq!(queried_used_bytes(&conn, 1), 1004);
    head_upload_at(&conn, temporary.path(), &user, &session.id, &tus_basic_headers()).unwrap();
    assert_eq!(count_intents(), 1);
}

#[tokio::test]
async fn publication_journal_rejects_hostile_files_without_blocking_or_following_links() {
    use std::os::unix::fs::PermissionsExt;

    let conn = setup_isolated_db();
    let temporary = TestTempDir::new();
    let user = human_user(1);
    let (session, _) = create_upload_session_at(
        &conn,
        temporary.path(),
        &user,
        &tus_post_headers("journal.txt", None, 4),
        None,
    )
    .unwrap();
    let journal = temporary
        .path()
        .join(".af-upload-staging/user-1")
        .join(format!("{}.publication", session.id));
    for payload in [
        b"not-json".as_slice(),
        br#"{"state":"published","extra":true}"#.as_slice(),
        &[b'x'; 4097],
    ] {
        fs::write(&journal, payload).unwrap();
        assert!(read_publication_proof_at(temporary.path(), &session).is_err());
    }
    fs::write(&journal, br#"{"state":"published"}"#).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_publication_proof_at(temporary.path(), &session).is_err());
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    let hardlink = temporary.path().join("hardlink");
    fs::hard_link(&journal, &hardlink).unwrap();
    assert!(read_publication_proof_at(temporary.path(), &session).is_err());
    fs::remove_file(&hardlink).unwrap();
    fs::remove_file(&journal).unwrap();
    let outside = temporary.path().join("outside");
    fs::write(&outside, br#"{"state":"published"}"#).unwrap();
    std::os::unix::fs::symlink(&outside, &journal).unwrap();
    assert!(read_publication_proof_at(temporary.path(), &session).is_err());
    fs::remove_file(&journal).unwrap();
    let fifo = CString::new(journal.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(read_publication_proof_at(temporary.path(), &session).is_err());
    fs::remove_file(&journal).unwrap();
    assert!(read_publication_proof_at(temporary.path(), &session)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn known_unpublished_identical_collisions_never_complete_or_double_charge_uploads() {
    for policy in ["error", "skip", "overwrite", "resume"] {
        let conn = setup_isolated_db();
        let temporary = TestTempDir::new();
        let user = human_user(1);
        let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
        let target = temporary.path().join("user-1/identical.txt");
        if policy == "overwrite" || policy == "resume" {
            fs::write(&target, b"base").unwrap();
        }
        let payload = b"basenew";
        let (session, _) = create_upload_session_at(
            &conn,
            temporary.path(),
            &user,
            &tus_post_headers("identical.txt", Some(policy), payload.len() as u64),
            Some(policy),
        )
        .unwrap();
        let reserved = if session.base_target_exists { 3 } else { 7 };
        assert_eq!(queried_used_bytes(&conn, 1), 1000 + reserved);
        let expected = if session.base_target_exists {
            Some(filesystem.open_file("identical.txt").unwrap())
        } else {
            None
        };
        let mut pending = if expected.is_some() {
            filesystem.begin_replace("identical.txt").unwrap()
        } else {
            filesystem.begin_upload("identical.txt").unwrap()
        };
        pending.write_all(payload).unwrap();
        fs::write(temporary.path().join("competing"), payload).unwrap();
        fs::rename(temporary.path().join("competing"), &target).unwrap();
        assert!(matches!(
            commit_proven_upload_at(temporary.path(), &session, pending, expected.as_ref()),
            Err(McBrowserError::Conflict(_))
        ));
        conn.execute(
            "UPDATE mcbrowser_uploads SET status = 'publishing', offset_bytes = upload_length WHERE id = ?1", [&session.id],
        ).unwrap();
        let response = head_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_basic_headers(),
        );
        if policy == "skip" {
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["Upload-Status"], "completed");
            assert_eq!(response.headers()["Upload-Skipped"], "true");
        } else {
            assert_eq!(response.unwrap_err().status(), StatusCode::CONFLICT);
            let audit = super::super::events::load_audit_record_by_id_with_conn(
                &conn,
                &session.audit_event_id,
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                audit.status,
                super::super::events::AuditEventStatus::Pending
            );
            let response = delete_upload_at(
                &conn,
                temporary.path(),
                &user,
                &session.id,
                &tus_basic_headers(),
            )
            .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
        assert_eq!(queried_used_bytes(&conn, 1), 1000);
        assert_eq!(fs::read(&target).unwrap(), payload);
        let audit =
            super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id)
                .unwrap()
                .unwrap();
        assert_eq!(audit.status, super::super::events::AuditEventStatus::Failed);
        assert_eq!(audit.event.byte_delta, 0);
        let queued: i64 = conn
            .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(queued, 0);
    }
}

#[tokio::test]
async fn prepared_publication_uses_inode_bound_nonce_and_recovers_exactly_once() {
    let conn = setup_isolated_db();
    let temporary = TestTempDir::new();
    let user = human_user(1);
    let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
    conn.execute("INSERT INTO mcbrowser_event_settings (id, queue_enabled, updated_at) VALUES (1, 1, '2026-11-02T00:00:00Z')", []).unwrap();
    let (session, _) = create_upload_session_at(
        &conn,
        temporary.path(),
        &user,
        &tus_post_headers("recovered.txt", Some("prepared"), 4),
        None,
    )
    .unwrap();
    let mut pending = filesystem.begin_upload("recovered.txt").unwrap();
    pending.write_all(b"data").unwrap();
    prepare_publication_proof_at(temporary.path(), &session, &pending.file().unwrap()).unwrap();
    assert!(matches!(
        read_publication_proof_at(temporary.path(), &session).unwrap(),
        Some(UploadPublicationProof::Prepared { nonce: Some(_), .. })
    ));
    pending.commit().unwrap();
    conn.execute(
        "UPDATE mcbrowser_uploads SET status = 'publishing', offset_bytes = 4 WHERE id = ?1",
        [&session.id],
    )
    .unwrap();
    for _attempt in 0..2 {
        let response = head_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_basic_headers(),
        )
        .unwrap();
        assert_eq!(response.headers()["Upload-Status"], "completed");
        assert_eq!(response.headers()["Upload-Offset"], "4");
        assert_eq!(queried_used_bytes(&conn, 1), 1004);
    }
    let audit =
        super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        audit.status,
        super::super::events::AuditEventStatus::Completed
    );
    assert_eq!(audit.event.byte_delta, 4);
    let queued: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(queued, 1);
    assert_eq!(
        fs::read(temporary.path().join("user-1/recovered.txt")).unwrap(),
        b"data"
    );
}

#[tokio::test]
async fn missing_or_unmatched_publication_proof_preserves_expired_session_and_quota() {
    for variant in ["legacy", "unmatched-nonce", "unsupported-xattr"] {
        let conn = setup_isolated_db();
        let temporary = TestTempDir::new();
        let user = human_user(1);
        let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
        let (session, _) = create_upload_session_at(
            &conn,
            temporary.path(),
            &user,
            &tus_post_headers("unknown.txt", Some(variant), 4),
            None,
        )
        .unwrap();
        fs::write(temporary.path().join("user-1/unknown.txt"), b"data").unwrap();
        let file = filesystem.open_file("unknown.txt").unwrap();
        let metadata = fstat_fd(file.as_raw_fd()).unwrap();
        if variant == "legacy" {
            remove_publication_proof_at(temporary.path(), 1, &session.id).unwrap();
        } else {
            write_publication_proof_at(
                temporary.path(),
                &session,
                &UploadPublicationProof::Prepared {
                    device: metadata.st_dev as u64,
                    inode: metadata.st_ino as u64,
                    nonce: if variant == "unmatched-nonce" {
                        Some(Uuid::new_v4().simple().to_string())
                    } else {
                        None
                    },
                },
            )
            .unwrap();
        }
        conn.execute(
            "UPDATE mcbrowser_uploads SET status = 'publishing', offset_bytes = 4 WHERE id = ?1",
            [&session.id],
        )
        .unwrap();
        let response = head_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_basic_headers(),
        )
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{variant}");
        let response = delete_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_basic_headers(),
        )
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{variant}");
        conn.execute(
            "UPDATE mcbrowser_uploads SET expires_at = 1 WHERE id = ?1",
            [&session.id],
        )
        .unwrap();
        assert_eq!(
            cleanup_expired_uploads_at(&conn, temporary.path(), now_unix_secs()).unwrap(),
            0
        );
        assert!(load_session_conn(&conn, &session.id).unwrap().is_some());
        assert_eq!(queried_used_bytes(&conn, 1), 1004);
        let audit =
            super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id)
                .unwrap()
                .unwrap();
        assert_eq!(
            audit.status,
            super::super::events::AuditEventStatus::Pending
        );
    }
}

#[tokio::test]
async fn cancellation_and_expiry_roll_back_quota_when_audit_failure_cannot_be_recorded() {
    for operation in ["delete", "expiry"] {
        let conn = setup_isolated_db();
        let temporary = TestTempDir::new();
        let user = human_user(1);
        let (session, _) = create_upload_session_at(
            &conn,
            temporary.path(),
            &user,
            &tus_post_headers("cancel.txt", Some(operation), 4),
            None,
        )
        .unwrap();
        conn.execute_batch("CREATE TRIGGER reject_audit_failure BEFORE UPDATE OF status ON mcbrowser_audit_events WHEN NEW.status = 'failed' BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
        if operation == "delete" {
            assert!(delete_upload_at(
                &conn,
                temporary.path(),
                &user,
                &session.id,
                &tus_basic_headers()
            )
            .is_err());
        } else {
            conn.execute(
                "UPDATE mcbrowser_uploads SET expires_at = 1 WHERE id = ?1",
                [&session.id],
            )
            .unwrap();
            assert!(cleanup_expired_uploads_at(&conn, temporary.path(), now_unix_secs()).is_err());
        }
        assert!(load_session_conn(&conn, &session.id).unwrap().is_some());
        assert_eq!(queried_used_bytes(&conn, 1), 1004);
        conn.execute_batch("DROP TRIGGER reject_audit_failure")
            .unwrap();
        if operation == "delete" {
            assert_eq!(
                delete_upload_at(
                    &conn,
                    temporary.path(),
                    &user,
                    &session.id,
                    &tus_basic_headers()
                )
                .unwrap()
                .status(),
                StatusCode::NO_CONTENT
            );
        } else {
            assert_eq!(
                cleanup_expired_uploads_at(&conn, temporary.path(), now_unix_secs()).unwrap(),
                1
            );
        }
        assert!(load_session_conn(&conn, &session.id).unwrap().is_none());
        assert_eq!(queried_used_bytes(&conn, 1), 1000);
    }
}

#[tokio::test]
async fn zero_byte_skip_collision_at_publication_preserves_target_and_truthful_head() {
    let conn = setup_isolated_db();
    let temporary = TestTempDir::new();
    let user = human_user(1);
    let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
    let (mut session, _) = create_upload_session_at(
        &conn,
        temporary.path(),
        &user,
        &tus_post_headers("collision.txt", Some("zero-collision"), 1),
        Some("skip"),
    )
    .unwrap();
    let audit_id = session.audit_event_id.clone();
    release_user_quota_conn(&conn, 1, 1).unwrap();
    conn.execute(
        "UPDATE mcbrowser_uploads SET upload_length = 0, reserved_bytes = 0, status = 'publishing', staging_rel_path = '' WHERE id = ?1",
        params![session.id],
    ).unwrap();
    remove_staging_file_at(temporary.path(), 1, &session.id).unwrap();
    session.upload_length = 0;
    session.reserved_bytes = 0;
    session.status = "publishing".to_string();
    session.staging_rel_path.clear();
    let pending = filesystem.begin_upload("collision.txt").unwrap();
    fs::write(temporary.path().join("user-1/collision.txt"), b"existing").unwrap();
    publish_zero_byte_upload_conn(
        &conn,
        temporary.path(),
        &filesystem,
        &mut session,
        pending,
        None,
        now_unix_secs(),
    )
    .unwrap();
    assert_eq!(session.status, "completed");
    assert!(session.base_target_exists);
    assert!(session.audit_event_id.is_empty());
    assert_eq!(
        fs::read(temporary.path().join("user-1/collision.txt")).unwrap(),
        b"existing"
    );
    for _attempt in 0..2 {
        let response = head_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_basic_headers(),
        )
        .unwrap();
        assert_eq!(response.headers()["Upload-Skipped"], "true");
        assert_eq!(response.headers()["Upload-Offset"], "0");
        assert_eq!(response.headers()["Upload-Status"], "completed");
    }
    let audit = super::super::events::load_audit_record_by_id_with_conn(&conn, &audit_id)
        .unwrap()
        .unwrap();
    assert_eq!(audit.status, super::super::events::AuditEventStatus::Failed);
    assert_eq!(audit.event.byte_delta, 0);
    assert_eq!(audit.error_code.as_deref(), Some("SKIPPED_CONFLICT"));
    assert_eq!(queried_used_bytes(&conn, 1), 1000);
}

#[tokio::test]
async fn zero_byte_nonregular_skip_collision_fails_audit_and_removes_unpublished_session() {
    use std::os::unix::fs::symlink;
    for collision_kind in ["directory", "symlink"] {
        let conn = setup_isolated_db();
        let temporary = TestTempDir::new();
        let user = human_user(1);
        let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
        let (mut session, _) = create_upload_session_at(
            &conn,
            temporary.path(),
            &user,
            &tus_post_headers("collision.txt", Some("nonregular-zero"), 1),
            Some("skip"),
        )
        .unwrap();
        release_user_quota_conn(&conn, 1, 1).unwrap();
        conn.execute("UPDATE mcbrowser_uploads SET upload_length = 0, reserved_bytes = 0, status = 'publishing', staging_rel_path = '' WHERE id = ?1", params![session.id]).unwrap();
        remove_staging_file_at(temporary.path(), 1, &session.id).unwrap();
        session.upload_length = 0;
        session.reserved_bytes = 0;
        session.status = "publishing".to_string();
        session.staging_rel_path.clear();
        let pending = filesystem.begin_upload("collision.txt").unwrap();
        let root = temporary.path().join("user-1");
        fs::write(root.join("preserved.txt"), b"preserved").unwrap();
        if collision_kind == "directory" {
            fs::create_dir(root.join("collision.txt")).unwrap();
        } else {
            symlink("preserved.txt", root.join("collision.txt")).unwrap();
        }
        assert!(publish_zero_byte_upload_conn(
            &conn,
            temporary.path(),
            &filesystem,
            &mut session,
            pending,
            None,
            now_unix_secs()
        )
        .is_err());
        assert!(
            load_session_conn(&conn, &session.id).unwrap().is_none(),
            "{collision_kind} collision must not leave an active unpublished session"
        );
        let audit =
            super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id)
                .unwrap()
                .unwrap();
        assert_eq!(audit.status, super::super::events::AuditEventStatus::Failed);
        assert_eq!(audit.event.byte_delta, 0);
        assert_eq!(queried_used_bytes(&conn, 1), 1000);
        assert_eq!(fs::read(root.join("preserved.txt")).unwrap(), b"preserved");
        assert!(fs::symlink_metadata(root.join("collision.txt")).is_ok());
    }
}

#[tokio::test]
async fn public_head_reports_unpublished_bound_target_conflicts_without_false_completion() {
    for policy in ["error", "overwrite", "resume"] {
        let conn = setup_isolated_db();
        let temporary = TestTempDir::new();
        let user = human_user(1);
        let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
        let target = temporary.path().join("user-1/changed.txt");
        if policy != "error" {
            fs::write(&target, b"da").unwrap();
        }
        let (session, _) = create_upload_session_at(
            &conn,
            temporary.path(),
            &user,
            &tus_post_headers("changed.txt", Some(policy), 4),
            Some(policy),
        )
        .unwrap();
        let offset = session.offset_bytes;
        let payload = &b"data"[offset as usize..];
        let (prepared, staging) = prepare_patch_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            offset,
            Some(payload.len() as u64),
        )
        .unwrap();
        let (staging, written) = stream_patch_chunk_to_file(
            Body::from(payload.to_vec()),
            staging,
            offset,
            4 - offset,
            Some(payload.len() as u64),
        )
        .await
        .unwrap();
        if policy == "error" {
            fs::write(&target, b"data").unwrap();
        } else {
            let mut replacement = filesystem.begin_replace("changed.txt").unwrap();
            replacement.write_all(b"other").unwrap();
            let expected = filesystem.open_file("changed.txt").unwrap();
            replacement.commit_replace(&expected).unwrap();
        }
        let response = finalize_patch_upload_at(
            &conn,
            temporary.path(),
            1,
            &prepared,
            staging,
            offset + written,
        )
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{policy}");
        let response = head_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_basic_headers(),
        )
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{policy}");
        let persisted = load_session_conn(&conn, &session.id).unwrap().unwrap();
        assert_eq!(persisted.status, "uploading");
        assert_eq!(persisted.offset_bytes, 4);
        let audit =
            super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id)
                .unwrap()
                .unwrap();
        assert_eq!(
            audit.status,
            super::super::events::AuditEventStatus::Pending
        );
        delete_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_basic_headers(),
        )
        .unwrap();
        assert_eq!(queried_used_bytes(&conn, 1), 1000);
        assert_eq!(
            fs::read(&target).unwrap(),
            if policy == "error" {
                b"data".as_slice()
            } else {
                b"other".as_slice()
            }
        );
    }
}

#[tokio::test]
async fn public_skip_collision_recovery_preserves_synced_offset_after_audit_failure() {
    use std::os::unix::fs::symlink;
    for collision_kind in ["file", "same-content", "directory", "symlink"] {
        let conn = setup_isolated_db();
        let temporary = TestTempDir::new();
        let user = human_user(1);
        let (session, _) = create_upload_session_at(
            &conn,
            temporary.path(),
            &user,
            &tus_post_headers("late.txt", Some("public-collision"), 4),
            Some("skip"),
        )
        .unwrap();
        let root = temporary.path().join("user-1");
        fs::write(root.join("preserved.txt"), b"preserved").unwrap();
        match collision_kind {
            "file" => fs::write(root.join("late.txt"), b"preserved").unwrap(),
            "same-content" => fs::write(root.join("late.txt"), b"data").unwrap(),
            "directory" => fs::create_dir(root.join("late.txt")).unwrap(),
            _ => symlink("preserved.txt", root.join("late.txt")).unwrap(),
        }
        conn.execute_batch("CREATE TRIGGER reject_terminal_upload BEFORE UPDATE OF status ON mcbrowser_audit_events WHEN NEW.status = 'failed' BEGIN SELECT RAISE(ABORT, 'injected terminal failure'); END;").unwrap();
        let response = apply_patch_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_patch_headers(0, Some(4)),
            b"data".to_vec(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{collision_kind}"
        );
        let persisted = load_session_conn(&conn, &session.id).unwrap().unwrap();
        assert_eq!(persisted.offset_bytes, 4, "{collision_kind}");
        assert_eq!(queried_used_bytes(&conn, 1), 1004);
        conn.execute_batch("DROP TRIGGER reject_terminal_upload")
            .unwrap();
        let response = head_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_basic_headers(),
        );
        if collision_kind == "file" || collision_kind == "same-content" {
            let response = response.unwrap();
            assert_eq!(response.headers()["Upload-Skipped"], "true");
            assert_eq!(response.headers()["Upload-Offset"], "4");
            assert_eq!(
                fs::read(root.join("late.txt")).unwrap(),
                if collision_kind == "file" {
                    b"preserved".as_slice()
                } else {
                    b"data".as_slice()
                }
            );
        } else {
            assert!(response.is_err());
            assert!(load_session_conn(&conn, &session.id).unwrap().is_none());
        }
        assert_eq!(queried_used_bytes(&conn, 1), 1000);
        let audit =
            super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id)
                .unwrap()
                .unwrap();
        assert_eq!(audit.status, super::super::events::AuditEventStatus::Failed);
        assert_eq!(fs::read(root.join("preserved.txt")).unwrap(), b"preserved");
    }
}

#[tokio::test]
async fn final_publication_skip_collision_is_atomic_for_regular_and_nonregular_targets() {
    use std::os::unix::fs::symlink;
    for collision_kind in ["file", "directory", "symlink"] {
        let conn = setup_isolated_db();
        let temporary = TestTempDir::new();
        let user = human_user(1);
        let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
        let (session, _) = create_upload_session_at(
            &conn,
            temporary.path(),
            &user,
            &tus_post_headers("late.txt", Some("final-collision"), 4),
            Some("skip"),
        )
        .unwrap();
        conn.execute(
            "UPDATE mcbrowser_uploads SET status = 'publishing', offset_bytes = 4 WHERE id = ?1",
            params![session.id],
        )
        .unwrap();
        let root = temporary.path().join("user-1");
        fs::write(root.join("preserved.txt"), b"preserved").unwrap();
        let mut pending = filesystem.begin_upload("late.txt").unwrap();
        pending.write_all(b"data").unwrap();
        match collision_kind {
            "file" => fs::write(root.join("late.txt"), b"preserved").unwrap(),
            "directory" => fs::create_dir(root.join("late.txt")).unwrap(),
            _ => symlink("preserved.txt", root.join("late.txt")).unwrap(),
        }
        assert!(matches!(
            commit_proven_upload_at(temporary.path(), &session, pending, None),
            Err(McBrowserError::Conflict(_))
        ));
        conn.execute_batch("CREATE TRIGGER reject_terminal_upload BEFORE UPDATE OF status ON mcbrowser_audit_events WHEN NEW.status = 'failed' BEGIN SELECT RAISE(ABORT, 'injected terminal failure'); END;").unwrap();
        assert!(finish_unpublished_skip_conn(
            &conn,
            temporary.path(),
            &filesystem,
            &session,
            now_unix_secs()
        )
        .is_err());
        assert_eq!(queried_used_bytes(&conn, 1), 1004);
        assert_eq!(
            load_session_conn(&conn, &session.id)
                .unwrap()
                .unwrap()
                .status,
            "publishing"
        );
        let audit =
            super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id)
                .unwrap()
                .unwrap();
        assert_eq!(
            audit.status,
            super::super::events::AuditEventStatus::Pending
        );
        conn.execute_batch("DROP TRIGGER reject_terminal_upload")
            .unwrap();
        let result = head_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_basic_headers(),
        );
        if collision_kind == "file" {
            let response = result.unwrap();
            assert_eq!(response.headers()["Upload-Skipped"], "true");
            for _attempt in 0..2 {
                let response = head_upload_at(
                    &conn,
                    temporary.path(),
                    &user,
                    &session.id,
                    &tus_basic_headers(),
                )
                .unwrap();
                assert_eq!(response.headers()["Upload-Skipped"], "true");
                assert_eq!(response.headers()["Upload-Offset"], "4");
            }
            assert_eq!(fs::read(root.join("late.txt")).unwrap(), b"preserved");
        } else {
            assert!(result.is_err());
            assert!(load_session_conn(&conn, &session.id).unwrap().is_none());
            discard_unpublished_session_conn(
                &conn,
                &session,
                &McBrowserError::Forbidden("collision".to_string()),
            )
            .unwrap();
            assert!(conn.is_autocommit());
        }
        assert_eq!(queried_used_bytes(&conn, 1), 1000);
        let audit =
            super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id)
                .unwrap()
                .unwrap();
        assert_eq!(audit.status, super::super::events::AuditEventStatus::Failed);
        assert_eq!(audit.event.byte_delta, 0);
        assert_eq!(fs::read(root.join("preserved.txt")).unwrap(), b"preserved");
        let queued: i64 = conn
            .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(queued, 0);
    }
}

#[tokio::test]
async fn staging_initialization_cleanup_retains_session_when_quota_release_fails() {
    let conn = setup_isolated_db();
    let temporary = TestTempDir::new();
    let user = human_user(1);
    open_user_browser_fs_at(temporary.path(), 1).unwrap();
    ensure_uploads_schema(&conn).unwrap();
    fs::write(
        temporary.path().join(".af-upload-staging"),
        b"blocked staging directory",
    )
    .unwrap();
    conn.execute_batch("CREATE TRIGGER reject_initialization_release BEFORE UPDATE OF used_bytes ON user_quotas WHEN NEW.used_bytes < OLD.used_bytes BEGIN SELECT RAISE(ABORT, 'injected initialization release failure'); END;").unwrap();
    let failure = create_upload_session_at(
        &conn,
        temporary.path(),
        &user,
        &tus_post_headers("never-published.txt", Some("initialization-failure"), 4),
        None,
    )
    .unwrap_err();
    assert_eq!(failure.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(queried_used_bytes(&conn, 1), 1004);
    let session_id: String = conn
        .query_row(
            "SELECT id FROM mcbrowser_uploads WHERE target_path = 'never-published.txt'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let session = load_session_conn(&conn, &session_id).unwrap().unwrap();
    let audit =
        super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        audit.status,
        super::super::events::AuditEventStatus::Pending
    );
    assert!(conn.is_autocommit());
    conn.execute_batch("DROP TRIGGER reject_initialization_release")
        .unwrap();
    discard_unpublished_session_conn(
        &conn,
        &session,
        &McBrowserError::Forbidden("staging blocked".to_string()),
    )
    .unwrap();
    assert_eq!(queried_used_bytes(&conn, 1), 1000);
    assert!(load_session_conn(&conn, &session_id).unwrap().is_none());
    let audit =
        super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id)
            .unwrap()
            .unwrap();
    assert_eq!(audit.status, super::super::events::AuditEventStatus::Failed);
    assert_eq!(audit.event.byte_delta, 0);
    assert!(!temporary.path().join("user-1/never-published.txt").exists());
}

#[tokio::test]
async fn late_skip_persists_head_marker_and_atomically_releases_reservation_once() {
    let conn = setup_isolated_db();
    let temporary = TestTempDir::new();
    let user = human_user(1);
    let (session, _) = create_upload_session_at(
        &conn,
        temporary.path(),
        &user,
        &tus_post_headers("late.txt", Some("late-collision"), 4),
        Some("skip"),
    )
    .unwrap();
    fs::write(temporary.path().join("user-1/late.txt"), b"preserved").unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_skip_audit BEFORE UPDATE OF status ON mcbrowser_audit_events
         WHEN NEW.status = 'failed' BEGIN SELECT RAISE(ABORT, 'injected skipped audit failure'); END;",
    ).unwrap();
    let failed = apply_patch_at(
        &conn,
        temporary.path(),
        &user,
        &session.id,
        &tus_patch_headers(0, Some(4)),
        b"data".to_vec(),
    )
    .await;
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(queried_used_bytes(&conn, 1), 1004);
    let persisted = load_session_conn(&conn, &session.id).unwrap().unwrap();
    assert_eq!(persisted.status, "uploading");
    assert!(!persisted.base_target_exists);
    let audit =
        super::super::events::load_audit_record_by_id_with_conn(&conn, &session.audit_event_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        audit.status,
        super::super::events::AuditEventStatus::Pending
    );
    conn.execute_batch("DROP TRIGGER reject_skip_audit")
        .unwrap();
    let skipped = apply_patch_at(
        &conn,
        temporary.path(),
        &user,
        &session.id,
        &tus_patch_headers(0, Some(4)),
        b"data".to_vec(),
    )
    .await;
    assert_eq!(skipped.status(), StatusCode::NO_CONTENT);
    assert_eq!(skipped.headers()["Upload-Skipped"], "true");
    for _attempt in 0..2 {
        let response = head_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_basic_headers(),
        )
        .unwrap();
        assert_eq!(response.headers()["Upload-Skipped"], "true");
        assert_eq!(response.headers()["Upload-Offset"], "4");
    }
    assert_eq!(queried_used_bytes(&conn, 1), 1000);
    assert_eq!(
        fs::read(temporary.path().join("user-1/late.txt")).unwrap(),
        b"preserved"
    );
    let queued: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(queued, 0);
}

#[tokio::test]
async fn replacement_uploads_reserve_only_growth_and_cancel_without_touching_original() {
    let conn = setup_isolated_db();
    let temporary = TestTempDir::new();
    let user = human_user(1);
    let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
    let original = filesystem.begin_upload("replace.txt").unwrap();
    original.file().unwrap().write_all(b"old").unwrap();
    original.commit().unwrap();
    let (session, _) = create_upload_session_at(
        &conn,
        temporary.path(),
        &user,
        &tus_post_headers("replace.txt", Some("replacement"), 8),
        Some("overwrite"),
    )
    .unwrap();
    assert_eq!(session.reserved_bytes, 5);
    assert_eq!(queried_used_bytes(&conn, 1), 1005);
    let response = apply_patch_at(
        &conn,
        temporary.path(),
        &user,
        &session.id,
        &tus_patch_headers(0, Some(4)),
        b"new-".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        fs::read(temporary.path().join("user-1/replace.txt")).unwrap(),
        b"old"
    );
    delete_upload_at(
        &conn,
        temporary.path(),
        &user,
        &session.id,
        &tus_basic_headers(),
    )
    .unwrap();
    assert_eq!(queried_used_bytes(&conn, 1), 1000);
    assert_eq!(
        fs::read(temporary.path().join("user-1/replace.txt")).unwrap(),
        b"old"
    );
}

#[tokio::test]
async fn resume_existing_prefix_and_skip_existing_file_have_truthful_offsets_and_quota() {
    let conn = setup_isolated_db();
    let temporary = TestTempDir::new();
    let user = human_user(1);
    let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
    let original = filesystem.begin_upload("partial.txt").unwrap();
    original.file().unwrap().write_all(b"abc").unwrap();
    original.commit().unwrap();
    let (session, response) = create_upload_session_at(
        &conn,
        temporary.path(),
        &user,
        &tus_post_headers("partial.txt", Some("resume"), 6),
        Some("resume"),
    )
    .unwrap();
    assert_eq!(response.headers()["Upload-Offset"], "3");
    assert_eq!(
        parse_upload_metadata(response.headers()["Upload-Metadata"].to_str().ok())
            .unwrap()
            .conflict_policy,
        Some(ConflictPolicy::Resume)
    );
    assert_eq!(queried_used_bytes(&conn, 1), 1003);
    let result = apply_patch_at(
        &conn,
        temporary.path(),
        &user,
        &session.id,
        &tus_patch_headers(3, Some(3)),
        b"def".to_vec(),
    )
    .await;
    assert_eq!(result.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        fs::read(temporary.path().join("user-1/partial.txt")).unwrap(),
        b"abcdef"
    );
    assert_eq!(queried_used_bytes(&conn, 1), 1003);
    let (_, skipped) = create_upload_session_at(
        &conn,
        temporary.path(),
        &user,
        &tus_post_headers("partial.txt", Some("skip"), 99),
        Some("skip"),
    )
    .unwrap();
    assert_eq!(skipped.headers()["Upload-Skipped"], "true");
    assert_eq!(skipped.headers()["Upload-Offset"], "99");
    assert_eq!(queried_used_bytes(&conn, 1), 1003);
    assert_eq!(
        fs::read(temporary.path().join("user-1/partial.txt")).unwrap(),
        b"abcdef"
    );
}

#[test]
fn replacement_crash_recovery_releases_shrink_quota_exactly_once() {
    let conn = setup_isolated_db();
    let temporary = TestTempDir::new();
    let user = human_user(1);
    let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
    let original = filesystem.begin_upload("shrink.txt").unwrap();
    original.file().unwrap().write_all(b"original").unwrap();
    original.commit().unwrap();
    let (session, _) = create_upload_session_at(
        &conn,
        temporary.path(),
        &user,
        &tus_post_headers("shrink.txt", Some("shrink"), 3),
        Some("overwrite"),
    )
    .unwrap();
    let staging_path = temporary
        .path()
        .join(format!(".af-upload-staging/user-1/{}.part", session.id));
    fs::write(&staging_path, b"new").unwrap();
    conn.execute(
        "UPDATE mcbrowser_uploads SET status = 'publishing', offset_bytes = 3 WHERE id = ?1",
        params![session.id],
    )
    .unwrap();
    let expected = filesystem.open_file("shrink.txt").unwrap();
    let staging = open_existing_staging_file_at(temporary.path(), 1, &session.id).unwrap();
    publish_staging_file_to_browser_fs(
        staging,
        &filesystem,
        "shrink.txt",
        3,
        Some(&expected),
        temporary.path(),
        &session,
    )
    .unwrap();
    assert_eq!(queried_used_bytes(&conn, 1), 1000);
    for _ in 0..2 {
        let response = head_upload_at(
            &conn,
            temporary.path(),
            &user,
            &session.id,
            &tus_basic_headers(),
        )
        .unwrap();
        assert_eq!(response.headers()["Upload-Status"], "completed");
        assert_eq!(queried_used_bytes(&conn, 1), 995);
    }
}

fn tus_post_headers(path: &str, fingerprint: Option<&str>, upload_length: u64) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static("1.0.0"));
    h.insert(
        "Upload-Length",
        HeaderValue::from_str(&upload_length.to_string()).unwrap(),
    );
    let path_b64 = BASE64_STD.encode(path.as_bytes());
    let meta = match fingerprint {
        Some(fp) => {
            let fp_b64 = BASE64_STD.encode(fp.as_bytes());
            format!("path {path_b64}, fingerprint {fp_b64}")
        }
        None => format!("path {path_b64}"),
    };
    h.insert("Upload-Metadata", HeaderValue::from_str(&meta).unwrap());
    h
}

fn tus_basic_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static("1.0.0"));
    h
}

fn tus_patch_headers(offset: u64, content_length: Option<u64>) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("Tus-Resumable", HeaderValue::from_static("1.0.0"));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/offset+octet-stream"),
    );
    h.insert(
        "Upload-Offset",
        HeaderValue::from_str(&offset.to_string()).unwrap(),
    );
    if let Some(cl) = content_length {
        h.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&cl.to_string()).unwrap(),
        );
    }
    h
}

async fn apply_patch_at(
    conn: &Connection,
    base_root: &Path,
    user: &AuthUser,
    upload_id: &str,
    headers: &HeaderMap,
    payload: Vec<u8>,
) -> Response {
    let (client_offset, declared_cl) = match parse_patch_headers(headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let (session, staging_file) =
        match prepare_patch_upload_at(conn, base_root, user, upload_id, client_offset, declared_cl)
        {
            Ok(pair) => pair,
            Err(resp) => return resp,
        };
    let remaining = session.upload_length.saturating_sub(session.offset_bytes);
    let (staging_file, written) = match stream_patch_chunk_to_file(
        Body::from(payload),
        staging_file,
        session.offset_bytes,
        remaining,
        declared_cl,
    )
    .await
    {
        Ok(pair) => pair,
        Err(resp) => return resp,
    };
    let new_offset = session.offset_bytes.saturating_add(written);
    match finalize_patch_upload_at(
        conn,
        base_root,
        user.user_id,
        &session,
        staging_file,
        new_offset,
    ) {
        Ok(resp) => resp,
        Err(resp) => resp,
    }
}

#[test]
fn tus_metadata_parser_validates_path_fingerprint_and_rejects_traversal() {
    let path_b64 = BASE64_STD.encode("mods/sodium.jar".as_bytes());
    let fp_b64 = BASE64_STD.encode("sha256:abcdef123456:size=4096:mtime=1700000000".as_bytes());
    let raw = format!(
        "path {path_b64}, fingerprint {fp_b64}, filename {}",
        BASE64_STD.encode(b"sodium.jar")
    );

    let parsed = parse_upload_metadata(Some(&raw)).unwrap();
    assert_eq!(parsed.path, "mods/sodium.jar");
    assert_eq!(
        parsed.fingerprint.as_deref(),
        Some("sha256:abcdef123456:size=4096:mtime=1700000000")
    );

    // Roundtrip header encoding
    let encoded =
        encode_upload_metadata_header(&parsed.path, parsed.fingerprint.as_deref().unwrap_or(""));
    let reparsed = parse_upload_metadata(Some(&encoded)).unwrap();
    assert_eq!(reparsed, parsed);

    // Reject missing header, missing path, duplicate keys, invalid base64, traversal paths, reserved prefix
    assert!(parse_upload_metadata(None).is_err());
    assert!(parse_upload_metadata(Some("")).is_err());
    assert!(parse_upload_metadata(Some(&format!("fingerprint {fp_b64}"))).is_err());
    assert!(parse_upload_metadata(Some(&format!("path {path_b64}, path {path_b64}"))).is_err());
    assert!(parse_upload_metadata(Some("path !!!not-base64!!!")).is_err());

    for bad_path in [
        "",
        "/",
        "/etc/passwd",
        "../escape.txt",
        "a/../../b",
        "dir\\file.txt",
        ".af-upload-tmp.1234",
        "sub/.af-upload-tmp.abcd",
        "bad\0name.txt",
    ] {
        let bad_b64 = BASE64_STD.encode(bad_path.as_bytes());
        assert!(
            parse_upload_metadata(Some(&format!("path {bad_b64}"))).is_err(),
            "should reject bad path {bad_path:?}"
        );
    }
}

#[test]
fn tus_version_and_conflict_policy_validation_are_strict() {
    let mut h = HeaderMap::new();
    let err_missing = validate_tus_version(&h).unwrap_err();
    assert_eq!(err_missing.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(err_missing.headers().get("Tus-Version").unwrap(), "1.0.0");

    h.insert("Tus-Resumable", HeaderValue::from_static("0.2.2"));
    let err_wrong = validate_tus_version(&h).unwrap_err();
    assert_eq!(err_wrong.status(), StatusCode::PRECONDITION_FAILED);

    h.insert("Tus-Resumable", HeaderValue::from_static("1.0.0"));
    assert!(validate_tus_version(&h).is_ok());

    assert!(validate_conflict_policy(None).is_ok());
    assert!(validate_conflict_policy(Some("")).is_ok());
    for supported in [
        "error",
        "ERROR",
        "overwrite",
        "OVERWRITE",
        "replace",
        "skip",
        "SKIP",
        "resume",
        "RESUME",
    ] {
        assert!(
            validate_conflict_policy(Some(supported)).is_ok(),
            "expected policy {supported:?} to be valid"
        );
        let path_b64 = BASE64_STD.encode(b"mods/test.jar");
        let conflict_b64 = BASE64_STD.encode(supported.as_bytes());
        let meta = format!("path {path_b64}, conflict {conflict_b64}");
        assert!(
            parse_upload_metadata(Some(&meta)).is_ok(),
            "expected metadata conflict {supported:?} to be valid"
        );
    }
    for unsupported in ["keep-both", "keep_both", "rename", "autorename", "invalid"] {
        assert!(matches!(
            validate_conflict_policy(Some(unsupported)),
            Err(McBrowserError::BadRequest(_))
        ));
        let path_b64 = BASE64_STD.encode(b"mods/test.jar");
        let conflict_b64 = BASE64_STD.encode(unsupported.as_bytes());
        let meta = format!("path {path_b64}, conflict {conflict_b64}");
        assert!(matches!(
            parse_upload_metadata(Some(&meta)),
            Err(McBrowserError::BadRequest(_))
        ));
    }

    assert_eq!(
        resolve_max_upload_bytes_from_str(None),
        DEFAULT_MAX_RESUMABLE_UPLOAD_BYTES
    );
    assert_eq!(
        resolve_max_upload_bytes_from_str(Some("1048576")),
        1_048_576
    );
}

#[tokio::test]
async fn full_chunked_upload_lifecycle_head_reconcile_and_lost_completion_ack_recovery() {
    let conn = setup_isolated_db();
    let tmp = TestTempDir::new();
    let alice = human_user(1);

    let bfs = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs.create_directory_all("worlds/nether").unwrap();

    let fp = "fp-v1-sha256-first-last-size-11-mtime-999";
    let post_h = tus_post_headers("worlds/nether/level.dat", Some(fp), 11);
    let (rec, post_resp) =
        create_upload_session_at(&conn, tmp.path(), &alice, &post_h, None).unwrap();

    assert_eq!(post_resp.status(), StatusCode::CREATED);
    assert_eq!(
        post_resp.headers().get(header::LOCATION).unwrap(),
        &format!("/api/v1/auth/mcbrowser/uploads/{}", rec.id)
    );
    assert_eq!(post_resp.headers().get("Upload-Offset").unwrap(), "0");
    assert_eq!(
        post_resp.headers().get("Upload-Status").unwrap(),
        "uploading"
    );
    assert_eq!(post_resp.headers().get("Tus-Resumable").unwrap(), "1.0.0");

    // Full 11 bytes reserved immediately upon POST
    assert_eq!(queried_used_bytes(&conn, 1), 1011);

    // Private staging file exists outside user's browsable root with 0600 permissions
    assert!(bfs.list("worlds/nether").unwrap().is_empty());
    assert!(bfs
        .list("")
        .unwrap()
        .iter()
        .all(|e| !e.name.starts_with(".af-upload")));
    let staging_file_path = tmp
        .path()
        .join(".af-upload-staging")
        .join("user-1")
        .join(format!("{}.part", rec.id));
    let st_meta = fs::symlink_metadata(&staging_file_path).unwrap();
    assert_eq!(st_meta.permissions().mode() & 0o777, 0o600);

    // Patch chunk 1 (5 bytes: "hello")
    let patch1_h = tus_patch_headers(0, Some(5));
    let patch1_resp = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec.id,
        &patch1_h,
        b"hello".to_vec(),
    )
    .await;
    assert_eq!(patch1_resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(patch1_resp.headers().get("Upload-Offset").unwrap(), "5");
    assert_eq!(
        patch1_resp.headers().get("Upload-Status").unwrap(),
        "uploading"
    );

    // Simulate a partial uncommitted tail written to disk before an API restart (e.g. 3 extra garbage bytes)
    {
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&staging_file_path)
            .unwrap();
        f.write_all(b"XXX").unwrap();
    }
    assert_eq!(fs::metadata(&staging_file_path).unwrap().len(), 8);

    // HEAD after restart truncates uncommitted tail back to committed SQLite offset (5)
    let head_resp =
        head_upload_at(&conn, tmp.path(), &alice, &rec.id, &tus_basic_headers()).unwrap();
    assert_eq!(head_resp.status(), StatusCode::OK);
    assert_eq!(head_resp.headers().get("Upload-Offset").unwrap(), "5");
    assert_eq!(head_resp.headers().get("Upload-Length").unwrap(), "11");
    assert_eq!(
        head_resp.headers().get("Upload-Status").unwrap(),
        "uploading"
    );
    assert_eq!(fs::metadata(&staging_file_path).unwrap().len(), 5);

    // Discovery returns the session only when path, length, and fingerprint match exactly
    let disc = discover_uploads_at(
        &conn,
        tmp.path(),
        &alice,
        &DiscoverUploadsQuery {
            path: Some("worlds/nether/level.dat".to_string()),
            length: Some("11".to_string()),
            fingerprint: Some(fp.to_string()),
        },
    )
    .unwrap();
    assert_eq!(disc.uploads.len(), 1);
    assert_eq!(disc.uploads[0].id, rec.id);
    assert_eq!(disc.uploads[0].offset, 5);
    assert_eq!(disc.uploads[0].fingerprint, fp);

    // Mismatched fingerprint MUST NOT match (prevents silent corruption if file was modified)
    let disc_wrong_fp = discover_uploads_at(
        &conn,
        tmp.path(),
        &alice,
        &DiscoverUploadsQuery {
            path: Some("worlds/nether/level.dat".to_string()),
            length: Some("11".to_string()),
            fingerprint: Some("fp-v1-different-file-contents".to_string()),
        },
    )
    .unwrap();
    assert!(disc_wrong_fp.uploads.is_empty());

    // Patch with wrong offset returns 409 Conflict
    let bad_off_resp = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec.id,
        &tus_patch_headers(0, Some(6)),
        b" world".to_vec(),
    )
    .await;
    assert_eq!(bad_off_resp.status(), StatusCode::CONFLICT);

    // Patch final chunk (6 bytes: " world") -> reaches length 11, publishes atomically!
    let patch2_resp = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec.id,
        &tus_patch_headers(5, Some(6)),
        b" world".to_vec(),
    )
    .await;
    assert_eq!(patch2_resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(patch2_resp.headers().get("Upload-Offset").unwrap(), "11");
    assert_eq!(
        patch2_resp.headers().get("Upload-Status").unwrap(),
        "completed"
    );

    // Verify published file in BrowserFs and staging cleanup
    assert!(!staging_file_path.exists());
    let entries = bfs.list("worlds/nether").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "level.dat");
    assert_eq!(entries[0].size, 11);
    let published_bytes = fs::read(tmp.path().join("user-1/worlds/nether/level.dat")).unwrap();
    assert_eq!(published_bytes, b"hello world");

    // Quota remains permanently reserved for published file
    assert_eq!(queried_used_bytes(&conn, 1), 1011);

    // Lost completion ACK recovery: HEAD on completed upload still succeeds and reports Upload-Status: completed
    let head_done =
        head_upload_at(&conn, tmp.path(), &alice, &rec.id, &tus_basic_headers()).unwrap();
    assert_eq!(head_done.status(), StatusCode::OK);
    assert_eq!(head_done.headers().get("Upload-Offset").unwrap(), "11");
    assert_eq!(head_done.headers().get("Upload-Length").unwrap(), "11");
    assert_eq!(
        head_done.headers().get("Upload-Status").unwrap(),
        "completed"
    );
    let meta_hdr = head_done
        .headers()
        .get("Upload-Metadata")
        .unwrap()
        .to_str()
        .unwrap();
    let recovered_meta = parse_upload_metadata(Some(meta_hdr)).unwrap();
    assert_eq!(recovered_meta.path, "worlds/nether/level.dat");
    assert_eq!(recovered_meta.fingerprint.as_deref(), Some(fp));

    // DELETE on completed upload returns 409 Conflict and NEVER releases published file quota
    let del_done =
        delete_upload_at(&conn, tmp.path(), &alice, &rec.id, &tus_basic_headers()).unwrap_err();
    assert_eq!(del_done.status(), StatusCode::CONFLICT);
    assert_eq!(queried_used_bytes(&conn, 1), 1011);
}

#[test]
fn zero_byte_upload_publishes_immediately_at_post_and_remains_head_discoverable() {
    let conn = setup_isolated_db();
    let tmp = TestTempDir::new();
    let alice = human_user(1);

    let post_h = tus_post_headers("empty.txt", Some("fp-zero"), 0);
    let (rec, resp) = create_upload_session_at(&conn, tmp.path(), &alice, &post_h, None).unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(resp.headers().get("Upload-Offset").unwrap(), "0");
    assert_eq!(resp.headers().get("Upload-Status").unwrap(), "completed");

    let bfs = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    let listed = bfs.list("").unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "empty.txt");
    assert_eq!(listed[0].size, 0);

    // HEAD confirms completed status
    let head_resp =
        head_upload_at(&conn, tmp.path(), &alice, &rec.id, &tus_basic_headers()).unwrap();
    assert_eq!(head_resp.status(), StatusCode::OK);
    assert_eq!(head_resp.headers().get("Upload-Offset").unwrap(), "0");
    assert_eq!(head_resp.headers().get("Upload-Length").unwrap(), "0");
    assert_eq!(
        head_resp.headers().get("Upload-Status").unwrap(),
        "completed"
    );

    // DELETE on zero-byte upload returns 409 Conflict because it is already completed
    let del_err =
        delete_upload_at(&conn, tmp.path(), &alice, &rec.id, &tus_basic_headers()).unwrap_err();
    assert_eq!(del_err.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cross_user_isolation_and_plugin_token_rejection() {
    let conn = setup_isolated_db();
    let tmp = TestTempDir::new();
    let alice = human_user(1);
    let bob = human_user(2);
    let plugin = plugin_user(1);

    let post_h = tus_post_headers("secret.bin", Some("fp-secret"), 100);

    // Plugin token rejected with 403 Forbidden
    let plugin_err =
        create_upload_session_at(&conn, tmp.path(), &plugin, &post_h, None).unwrap_err();
    assert_eq!(plugin_err.status(), StatusCode::FORBIDDEN);

    let (rec, _) = create_upload_session_at(&conn, tmp.path(), &alice, &post_h, None).unwrap();

    // Bob cannot discover Alice's session
    let bob_disc = discover_uploads_at(
        &conn,
        tmp.path(),
        &bob,
        &DiscoverUploadsQuery {
            path: Some("secret.bin".to_string()),
            length: Some("100".to_string()),
            fingerprint: Some("fp-secret".to_string()),
        },
    )
    .unwrap();
    assert!(bob_disc.uploads.is_empty());

    // Bob gets 404 on HEAD, PATCH, and DELETE against Alice's upload ID
    let bob_head =
        head_upload_at(&conn, tmp.path(), &bob, &rec.id, &tus_basic_headers()).unwrap_err();
    assert_eq!(bob_head.status(), StatusCode::NOT_FOUND);

    let bob_patch = apply_patch_at(
        &conn,
        tmp.path(),
        &bob,
        &rec.id,
        &tus_patch_headers(0, Some(4)),
        b"hack".to_vec(),
    )
    .await;
    assert_eq!(bob_patch.status(), StatusCode::NOT_FOUND);

    let bob_del =
        delete_upload_at(&conn, tmp.path(), &bob, &rec.id, &tus_basic_headers()).unwrap_err();
    assert_eq!(bob_del.status(), StatusCode::NOT_FOUND);

    // Alice's session and quota remain untouched
    assert_eq!(queried_used_bytes(&conn, 1), 1100);
}

#[tokio::test]
async fn cancel_unfinished_upload_releases_quota_and_removes_staging_file() {
    let conn = setup_isolated_db();
    let tmp = TestTempDir::new();
    let alice = human_user(1);

    let post_h = tus_post_headers("partial.bin", Some("fp-part"), 500);
    let (rec, _) = create_upload_session_at(&conn, tmp.path(), &alice, &post_h, None).unwrap();
    assert_eq!(queried_used_bytes(&conn, 1), 1500);

    let patch_resp = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec.id,
        &tus_patch_headers(0, Some(5)),
        b"12345".to_vec(),
    )
    .await;
    assert_eq!(patch_resp.status(), StatusCode::NO_CONTENT);

    let staging_path = tmp
        .path()
        .join(".af-upload-staging/user-1")
        .join(format!("{}.part", rec.id));
    assert!(staging_path.exists());

    let del_resp =
        delete_upload_at(&conn, tmp.path(), &alice, &rec.id, &tus_basic_headers()).unwrap();
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

    // Quota returned to 1000 and staging file unlinked
    assert_eq!(queried_used_bytes(&conn, 1), 1000);
    assert!(!staging_path.exists());

    // Subsequent HEAD returns 404
    let head_after =
        head_upload_at(&conn, tmp.path(), &alice, &rec.id, &tus_basic_headers()).unwrap_err();
    assert_eq!(head_after.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn enforces_quota_limits_max_active_sessions_oversize_chunk_and_expiry_cleanup() {
    let conn = setup_isolated_db();
    let tmp = TestTempDir::new();
    let alice = human_user(1);
    let carol = human_user(3);

    // Suspended user is rejected with 403
    let carol_err = create_upload_session_at(
        &conn,
        tmp.path(),
        &carol,
        &tus_post_headers("file.bin", Some("fp-1"), 10),
        None,
    )
    .unwrap_err();
    assert_eq!(carol_err.status(), StatusCode::FORBIDDEN);

    // Alice has 1000 / 10000 used -> requesting 9001 bytes exceeds quota (413 QUOTA_EXCEEDED)
    let quota_err = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("huge.bin", Some("fp-huge"), 9001),
        None,
    )
    .unwrap_err();
    assert_eq!(quota_err.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(queried_used_bytes(&conn, 1), 1000);

    // Create 32 active sessions (each 10 bytes) for Alice
    let mut ids = Vec::new();
    for i in 0..MAX_ACTIVE_UPLOADS_PER_USER {
        let h = tus_post_headers(&format!("batch-{i}.bin"), Some(&format!("fp-{i}")), 10);
        let (rec, _) = create_upload_session_at(&conn, tmp.path(), &alice, &h, None).unwrap();
        ids.push(rec.id);
    }
    assert_eq!(queried_used_bytes(&conn, 1), 1000 + 32 * 10);

    // 33rd active session is rejected with 409 Conflict
    let cap_err = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("batch-33.bin", Some("fp-33"), 10),
        None,
    )
    .unwrap_err();
    assert_eq!(cap_err.status(), StatusCode::CONFLICT);

    // Expire the first 2 sessions in SQLite and trigger cleanup
    let past = now_unix_secs() - 10;
    conn.execute(
        "UPDATE mcbrowser_uploads SET expires_at = ?1 WHERE id IN (?2, ?3)",
        params![past, ids[0], ids[1]],
    )
    .unwrap();

    let cleaned = cleanup_expired_uploads_at(&conn, tmp.path(), now_unix_secs()).unwrap();
    assert_eq!(cleaned, 2);
    // Quota for the 2 expired uploading sessions (20 bytes) is released!
    assert_eq!(queried_used_bytes(&conn, 1), 1000 + 30 * 10);

    // Oversize chunk (> 4 MiB) is rejected with 413 Payload Too Large
    let oversize_headers = tus_patch_headers(0, Some(MAX_CHUNK_BYTES + 1));
    let oversize_resp = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &ids[2],
        &oversize_headers,
        vec![0u8; 16],
    )
    .await;
    assert_eq!(oversize_resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn symlink_in_staging_hierarchy_is_rejected_and_completed_expiry_never_releases_published_quota() {
    let conn = setup_isolated_db();
    let tmp = TestTempDir::new();
    let outside = TestTempDir::new();
    let alice = human_user(1);

    // Create a zero-byte upload and a 10-byte completed upload (simulated) and verify expiring a completed
    // session never releases quota.
    let (rec, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("keep.bin", Some("fp-keep"), 50),
        None,
    )
    .unwrap();
    assert_eq!(queried_used_bytes(&conn, 1), 1050);

    // Mark session completed and expired
    let past = now_unix_secs() - 100;
    conn.execute(
        "UPDATE mcbrowser_uploads SET status = 'completed', offset_bytes = 50, expires_at = ?1 WHERE id = ?2",
        params![past, rec.id],
    )
    .unwrap();

    let cleaned = cleanup_expired_uploads_at(&conn, tmp.path(), now_unix_secs()).unwrap();
    assert_eq!(cleaned, 1);
    // Published file's 50 bytes MUST remain accounted in user_quotas!
    assert_eq!(queried_used_bytes(&conn, 1), 1050);

    // Replace user-2 staging directory with a symlink to `outside` and verify staging open fails closed
    let staging_root = tmp.path().join(".af-upload-staging");
    symlink(outside.path(), staging_root.join("user-2")).unwrap();

    let bob = human_user(2);
    let sym_err = create_upload_session_at(
        &conn,
        tmp.path(),
        &bob,
        &tus_post_headers("escape.bin", Some("fp-esc"), 20),
        None,
    )
    .unwrap_err();
    assert_eq!(sym_err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    // Quota rolled back cleanly on staging failure
    assert_eq!(queried_used_bytes(&conn, 2), 0);
}

#[test]
fn crash_after_file_rename_before_db_completed_never_releases_published_quota_on_expiry_or_delete()
{
    let conn = setup_isolated_db();
    let tmp = TestTempDir::new();
    let alice = human_user(1);
    let bfs = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs.create_directory_all("worlds").unwrap();

    // 1. Simulate crash AFTER PendingUpload::commit() renamed the file into BrowserFs,
    //    BEFORE SQLite updated status from 'publishing' to 'completed'.
    let payload_a = b"published-before-db-ack!"; // 24 bytes
    let (rec_a, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("worlds/crash_a.dat", Some("fp-crash-a"), 24),
        None,
    )
    .unwrap();
    assert_eq!(queried_used_bytes(&conn, 1), 1024);

    let staging_a = tmp
        .path()
        .join(".af-upload-staging/user-1")
        .join(format!("{}.part", rec_a.id));
    fs::write(&staging_a, payload_a).unwrap();
    let staging_file_a = open_existing_staging_file_at(tmp.path(), 1, &rec_a.id).unwrap();
    publish_staging_file_to_browser_fs(
        staging_file_a,
        &bfs,
        "worlds/crash_a.dat",
        24,
        None,
        tmp.path(),
        &rec_a,
    )
    .unwrap();

    // DB was left in 'publishing' at offset_bytes = 24 when crash happened
    conn.execute(
        "UPDATE mcbrowser_uploads SET offset_bytes = 24, status = 'publishing' WHERE id = ?1",
        params![rec_a.id],
    )
    .unwrap();

    // DELETE must reconcile against disk, discover the file is already published, transition
    // to 'completed', reject cancellation with 409 Conflict, and NEVER release quota!
    let del_err =
        delete_upload_at(&conn, tmp.path(), &alice, &rec_a.id, &tus_basic_headers()).unwrap_err();
    assert_eq!(del_err.status(), StatusCode::CONFLICT);
    assert_eq!(queried_used_bytes(&conn, 1), 1024);
    assert!(!staging_a.exists());

    // Subsequent HEAD reports Upload-Status: completed
    let head_a =
        head_upload_at(&conn, tmp.path(), &alice, &rec_a.id, &tus_basic_headers()).unwrap();
    assert_eq!(head_a.status(), StatusCode::OK);
    assert_eq!(head_a.headers().get("Upload-Status").unwrap(), "completed");
    assert_eq!(head_a.headers().get("Upload-Offset").unwrap(), "24");

    // 2. Simulate crash after file rename where the session subsequently EXPIRES before any client
    //    retries HEAD/PATCH (both for `status = 'publishing'` and `status = 'uploading'` at full offset).
    let payload_b = b"expired-after-rename-publishing!"; // 32 bytes
    let (rec_b, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("worlds/crash_b.dat", Some("fp-crash-b"), 32),
        None,
    )
    .unwrap();
    assert_eq!(queried_used_bytes(&conn, 1), 1024 + 32);

    let staging_b = tmp
        .path()
        .join(".af-upload-staging/user-1")
        .join(format!("{}.part", rec_b.id));
    fs::write(&staging_b, payload_b).unwrap();
    let staging_file_b = open_existing_staging_file_at(tmp.path(), 1, &rec_b.id).unwrap();
    publish_staging_file_to_browser_fs(
        staging_file_b,
        &bfs,
        "worlds/crash_b.dat",
        32,
        None,
        tmp.path(),
        &rec_b,
    )
    .unwrap();

    let payload_c = b"expired-after-rename-uploading!!"; // 32 bytes
    let (rec_c, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("worlds/crash_c.dat", Some("fp-crash-c"), 32),
        None,
    )
    .unwrap();
    assert_eq!(queried_used_bytes(&conn, 1), 1024 + 64);

    let staging_c = tmp
        .path()
        .join(".af-upload-staging/user-1")
        .join(format!("{}.part", rec_c.id));
    fs::write(&staging_c, payload_c).unwrap();
    let staging_file_c = open_existing_staging_file_at(tmp.path(), 1, &rec_c.id).unwrap();
    publish_staging_file_to_browser_fs(
        staging_file_c,
        &bfs,
        "worlds/crash_c.dat",
        32,
        None,
        tmp.path(),
        &rec_c,
    )
    .unwrap();

    let past = now_unix_secs() - 60;
    conn.execute(
        "UPDATE mcbrowser_uploads SET offset_bytes = 32, status = 'publishing', expires_at = ?1 WHERE id = ?2",
        params![past, rec_b.id],
    )
    .unwrap();
    conn.execute(
        "UPDATE mcbrowser_uploads SET offset_bytes = 32, status = 'uploading', expires_at = ?1 WHERE id = ?2",
        params![past, rec_c.id],
    )
    .unwrap();

    // Expiry cleanup reconciles both against disk, cleans up the expired rows and leftover .part files,
    // and NEVER releases quota for the published files!
    let cleaned = cleanup_expired_uploads_at(&conn, tmp.path(), now_unix_secs()).unwrap();
    assert_eq!(cleaned, 2);
    assert_eq!(queried_used_bytes(&conn, 1), 1024 + 64);
    assert!(!staging_b.exists());
    assert!(!staging_c.exists());
    assert_eq!(
        fs::read(tmp.path().join("user-1/worlds/crash_b.dat")).unwrap(),
        payload_b
    );
    assert_eq!(
        fs::read(tmp.path().join("user-1/worlds/crash_c.dat")).unwrap(),
        payload_c
    );
}

#[test]
fn crash_during_publishing_reconciles_via_head_or_releases_only_when_proven_unpublished() {
    let conn = setup_isolated_db();
    let tmp = TestTempDir::new();
    let alice = human_user(1);
    let bfs = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs.create_directory_all("mods").unwrap();

    // Case A: Crash AFTER status = 'publishing' at offset_bytes == upload_length, BEFORE file rename.
    // Active HEAD recovery finishes publishing the intact staging file to BrowserFs!
    let payload_a = b"0123456789abcdef"; // 16 bytes
    let (rec_a, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("mods/recover_me.jar", Some("fp-rec-a"), 16),
        None,
    )
    .unwrap();
    assert_eq!(queried_used_bytes(&conn, 1), 1016);

    let staging_a = tmp
        .path()
        .join(".af-upload-staging/user-1")
        .join(format!("{}.part", rec_a.id));
    fs::write(&staging_a, payload_a).unwrap();
    conn.execute(
        "UPDATE mcbrowser_uploads SET offset_bytes = 16, status = 'publishing' WHERE id = ?1",
        params![rec_a.id],
    )
    .unwrap();

    let head_a =
        head_upload_at(&conn, tmp.path(), &alice, &rec_a.id, &tus_basic_headers()).unwrap();
    assert_eq!(head_a.status(), StatusCode::OK);
    assert_eq!(head_a.headers().get("Upload-Offset").unwrap(), "16");
    assert_eq!(head_a.headers().get("Upload-Status").unwrap(), "completed");
    assert!(!staging_a.exists());
    assert_eq!(
        fs::read(tmp.path().join("user-1/mods/recover_me.jar")).unwrap(),
        payload_a
    );
    assert_eq!(queried_used_bytes(&conn, 1), 1016);

    // Case B: Crash AFTER status = 'publishing' at offset_bytes == upload_length, BEFORE file rename.
    // User cancels via DELETE (or session expires): because target does not exist in BrowserFs and
    // staging file is intact, it is proven unpublished and safe to release quota.
    let payload_b = b"unpublished-staging!"; // 20 bytes
    let (rec_b, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("mods/cancel_me.jar", Some("fp-rec-b"), 20),
        None,
    )
    .unwrap();
    assert_eq!(queried_used_bytes(&conn, 1), 1016 + 20);

    let staging_b = tmp
        .path()
        .join(".af-upload-staging/user-1")
        .join(format!("{}.part", rec_b.id));
    fs::write(&staging_b, payload_b).unwrap();
    conn.execute(
        "UPDATE mcbrowser_uploads SET offset_bytes = 20, status = 'publishing' WHERE id = ?1",
        params![rec_b.id],
    )
    .unwrap();

    let del_b =
        delete_upload_at(&conn, tmp.path(), &alice, &rec_b.id, &tus_basic_headers()).unwrap();
    assert_eq!(del_b.status(), StatusCode::NO_CONTENT);
    assert!(!staging_b.exists());
    assert_eq!(queried_used_bytes(&conn, 1), 1016);

    // Case C: Ambiguous crash state in 'publishing' (both target file and staging file are gone,
    // e.g., file was published and then deleted/moved before crash recovery).
    // Both DELETE and expiry cleanup MUST conservatively retain the quota reservation!
    let (rec_c, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("mods/ambiguous.jar", Some("fp-rec-c"), 40),
        None,
    )
    .unwrap();
    assert_eq!(queried_used_bytes(&conn, 1), 1016 + 40);

    let staging_c = tmp
        .path()
        .join(".af-upload-staging/user-1")
        .join(format!("{}.part", rec_c.id));
    fs::remove_file(&staging_c).unwrap();
    write_publication_proof_at(
        tmp.path(),
        &rec_c,
        &UploadPublicationProof::Prepared {
            device: 0,
            inode: 0,
            nonce: None,
        },
    )
    .unwrap();
    conn.execute(
        "UPDATE mcbrowser_uploads SET offset_bytes = 40, status = 'publishing' WHERE id = ?1",
        params![rec_c.id],
    )
    .unwrap();

    // DELETE refuses to release quota on ambiguous 'publishing' state (409 Conflict)
    let del_c_err =
        delete_upload_at(&conn, tmp.path(), &alice, &rec_c.id, &tus_basic_headers()).unwrap_err();
    assert_eq!(del_c_err.status(), StatusCode::CONFLICT);
    assert_eq!(queried_used_bytes(&conn, 1), 1016 + 40);

    let past = now_unix_secs() - 30;
    conn.execute(
        "UPDATE mcbrowser_uploads SET expires_at = ?1 WHERE id = ?2",
        params![past, rec_c.id],
    )
    .unwrap();
    let cleaned = cleanup_expired_uploads_at(&conn, tmp.path(), now_unix_secs()).unwrap();
    assert_eq!(cleaned, 0);
    assert!(load_session_conn(&conn, &rec_c.id).unwrap().is_some());
    assert_eq!(queried_used_bytes(&conn, 1), 1016 + 40);
}

#[tokio::test]
async fn policy_authorize_create_permission_is_enforced_on_post_patch_and_head_recovery() {
    let conn = setup_isolated_db();
    let tmp = TestTempDir::new();
    let alice = human_user(1);

    // Insert an admin user so we can configure Alice's McBrowser policy via `crate::mcbrowser::policy::save_user_policy_conn`
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (99, 'admin', 'admin')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status) VALUES (99, 'admin', 10000, 0, 'active')",
        [],
    )
    .unwrap();
    let admin = AuthUser {
        user_id: 99,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "jti-admin".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    let bfs = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs.create_directory_all("restricted").unwrap();
    bfs.create_directory_all("allowed").unwrap();

    // 1. Configure path rule denying `restricted` while allowing `allowed`
    let policy_doc = crate::mcbrowser::policy::PolicyDocument {
        permissions: crate::mcbrowser::policy::PolicyPermissions::default(),
        rules: vec![crate::mcbrowser::policy::PathRule {
            path: "restricted".to_string(),
            allow: false,
            regex: false,
            regexp: None,
        }],
        scope: String::new(),
    };
    crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 1, policy_doc).unwrap();

    // POST to denied path `restricted/secret.jar` fails with 403 Forbidden and reserves 0 bytes
    let denied_err = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("restricted/secret.jar", Some("fp-denied"), 50),
        None,
    )
    .unwrap_err();
    assert_eq!(denied_err.status(), StatusCode::FORBIDDEN);
    assert_eq!(queried_used_bytes(&conn, 1), 1000);

    // POST to `/allowed/mod.jar` succeeds
    let (rec, post_resp) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("allowed/mod.jar", Some("fp-allowed"), 8),
        None,
    )
    .unwrap();
    assert_eq!(post_resp.status(), StatusCode::CREATED);
    assert_eq!(queried_used_bytes(&conn, 1), 1008);

    // 2. Revoke Alice's `Permission::Create` mid-upload
    let mut no_create_policy = crate::mcbrowser::policy::PolicyDocument::default();
    no_create_policy.permissions.create = false;
    crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 1, no_create_policy).unwrap();

    // PATCH is rejected with 403 Forbidden while `Permission::Create` is revoked
    let patch_forbidden = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec.id,
        &tus_patch_headers(0, Some(8)),
        b"mod-data".to_vec(),
    )
    .await;
    assert_eq!(patch_forbidden.status(), StatusCode::FORBIDDEN);

    // 3. Re-enable `Permission::Create` and verify PATCH succeeds and publishes the file
    crate::mcbrowser::policy::save_user_policy_conn(
        &conn,
        &admin,
        1,
        crate::mcbrowser::policy::PolicyDocument::default(),
    )
    .unwrap();
    let patch_ok = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec.id,
        &tus_patch_headers(0, Some(8)),
        b"mod-data".to_vec(),
    )
    .await;
    assert_eq!(patch_ok.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        patch_ok.headers().get("Upload-Status").unwrap(),
        "completed"
    );
    assert_eq!(
        fs::read(tmp.path().join("user-1/allowed/mod.jar")).unwrap(),
        b"mod-data"
    );
}

#[test]
fn ensure_uploads_schema_migrates_legacy_table_without_publishing_status() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE mcbrowser_uploads (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            target_path TEXT NOT NULL,
            fingerprint TEXT NOT NULL DEFAULT '',
            upload_length INTEGER NOT NULL CHECK (upload_length >= 0),
            offset_bytes INTEGER NOT NULL DEFAULT 0 CHECK (offset_bytes >= 0 AND offset_bytes <= upload_length),
            status TEXT NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'completed')),
            staging_rel_path TEXT NOT NULL DEFAULT '',
            quota_reserved INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        INSERT INTO mcbrowser_uploads
            (id, user_id, target_path, fingerprint, upload_length, offset_bytes, status, staging_rel_path, quota_reserved, created_at, updated_at, expires_at)
        VALUES
            ('0123456789abcdef0123456789abcdef', 1, 'legacy.bin', 'fp-1', 100, 50, 'uploading', 'user-1/0123456789abcdef0123456789abcdef.part', 1, 1000, 1000, 2000);
        "#,
    )
    .unwrap();

    ensure_uploads_schema(&conn).unwrap();

    // Verify existing row survived migration and 'publishing' status is now allowed by CHECK constraint
    conn.execute(
        "UPDATE mcbrowser_uploads SET offset_bytes = 100, status = 'publishing' WHERE id = '0123456789abcdef0123456789abcdef'",
        [],
    )
    .unwrap();

    let rec = load_session_conn(&conn, "0123456789abcdef0123456789abcdef")
        .unwrap()
        .unwrap();
    assert_eq!(rec.status, "publishing");
    assert_eq!(rec.offset_bytes, 100);
    assert_eq!(rec.owner_scope, "");
}

#[tokio::test]
async fn scope_remap_or_directory_replacement_fails_closed_on_discover_head_and_patch_publish() {
    let conn = setup_isolated_db();
    let tmp = TestTempDir::new();
    let alice = human_user(1);

    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (99, 'admin', 'admin')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status) VALUES (99, 'admin', 10000, 0, 'active')",
        [],
    )
    .unwrap();
    let admin = AuthUser {
        user_id: 99,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "jti-admin".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };

    let raw_bfs = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    raw_bfs.create_directory_all("scope_a/sub").unwrap();
    raw_bfs.create_directory_all("scope_b/sub").unwrap();

    // 1. Configure Alice's scope to `scope_a`
    let mut policy_a = crate::mcbrowser::policy::PolicyDocument::default();
    policy_a.scope = "scope_a".to_string();
    crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 1, policy_a).unwrap();

    // Create upload session for relative target `sub/plugin.jar` (12 bytes) under `scope_a`
    let (rec_1, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("sub/plugin.jar", Some("fp-scope-1"), 12),
        None,
    )
    .unwrap();
    assert_eq!(rec_1.owner_scope, "scope_a");
    assert!(rec_1.scope_root_dev != 0 && rec_1.scope_root_ino != 0);
    assert_eq!(queried_used_bytes(&conn, 1), 1012);

    // Upload first 6 bytes while still in `scope_a`
    let p1 = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec_1.id,
        &tus_patch_headers(0, Some(6)),
        b"hello-".to_vec(),
    )
    .await;
    assert_eq!(p1.status(), StatusCode::NO_CONTENT);

    // 2. Admin remaps Alice's scope from `scope_a` to `scope_b`
    let mut policy_b = crate::mcbrowser::policy::PolicyDocument::default();
    policy_b.scope = "scope_b".to_string();
    crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 1, policy_b).unwrap();

    // Discovery under `scope_b` must NOT return the `scope_a` session
    let disc_remap = discover_uploads_at(
        &conn,
        tmp.path(),
        &alice,
        &DiscoverUploadsQuery {
            path: Some("sub/plugin.jar".to_string()),
            length: Some("12".to_string()),
            fingerprint: Some("fp-scope-1".to_string()),
        },
    )
    .unwrap();
    assert!(disc_remap.uploads.is_empty());

    // HEAD on `rec_1` fails closed with 409 Conflict after scope remap
    let head_remap_err =
        head_upload_at(&conn, tmp.path(), &alice, &rec_1.id, &tus_basic_headers()).unwrap_err();
    assert_eq!(head_remap_err.status(), StatusCode::CONFLICT);

    // PATCH/publish on `rec_1` fails closed with 409 Conflict and never writes into `scope_b` or `scope_a`
    let patch_remap_err = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec_1.id,
        &tus_patch_headers(6, Some(6)),
        b"world!".to_vec(),
    )
    .await;
    assert_eq!(patch_remap_err.status(), StatusCode::CONFLICT);
    assert!(!tmp.path().join("user-1/scope_b/sub/plugin.jar").exists());
    assert!(!tmp.path().join("user-1/scope_a/sub/plugin.jar").exists());

    // Alice can still DELETE `rec_1` to release the unpublished 12-byte reservation
    let del_1 =
        delete_upload_at(&conn, tmp.path(), &alice, &rec_1.id, &tus_basic_headers()).unwrap();
    assert_eq!(del_1.status(), StatusCode::NO_CONTENT);
    assert_eq!(queried_used_bytes(&conn, 1), 1000);

    // 3. Under `scope_b`, create a new session `rec_2` (10 bytes) and upload 5 bytes
    let (rec_2, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("sub/plugin.jar", Some("fp-scope-2"), 10),
        None,
    )
    .unwrap();
    assert_eq!(rec_2.owner_scope, "scope_b");
    assert_eq!(queried_used_bytes(&conn, 1), 1010);

    let p2_first = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec_2.id,
        &tus_patch_headers(0, Some(5)),
        b"part1".to_vec(),
    )
    .await;
    assert_eq!(p2_first.status(), StatusCode::NO_CONTENT);

    // Replace `user-1/scope_b` on disk with a new directory (different inode at the same `/scope_b` path)
    let scope_b_dir = tmp.path().join("user-1/scope_b");
    let scope_b_displaced = tmp.path().join("user-1/scope_b_displaced");
    fs::rename(&scope_b_dir, &scope_b_displaced).unwrap();
    raw_bfs.create_directory_all("scope_b/sub").unwrap();

    // Discovery, HEAD, and PATCH on `rec_2` must fail closed because `(scope_root_dev, scope_root_ino)` changed!
    let disc_ino = discover_uploads_at(
        &conn,
        tmp.path(),
        &alice,
        &DiscoverUploadsQuery {
            path: Some("sub/plugin.jar".to_string()),
            length: Some("10".to_string()),
            fingerprint: Some("fp-scope-2".to_string()),
        },
    )
    .unwrap();
    assert!(disc_ino.uploads.is_empty());

    let head_ino_err =
        head_upload_at(&conn, tmp.path(), &alice, &rec_2.id, &tus_basic_headers()).unwrap_err();
    assert_eq!(head_ino_err.status(), StatusCode::CONFLICT);

    let patch_ino_err = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec_2.id,
        &tus_patch_headers(5, Some(5)),
        b"part2".to_vec(),
    )
    .await;
    assert_eq!(patch_ino_err.status(), StatusCode::CONFLICT);
    assert!(!tmp.path().join("user-1/scope_b/sub/plugin.jar").exists());

    // Cancel `rec_2` and verify a fresh upload under the new `/scope_b` directory publishes into `user-1/scope_b/sub/plugin.jar`
    let del_2 =
        delete_upload_at(&conn, tmp.path(), &alice, &rec_2.id, &tus_basic_headers()).unwrap();
    assert_eq!(del_2.status(), StatusCode::NO_CONTENT);
    assert_eq!(queried_used_bytes(&conn, 1), 1000);

    let (rec_3, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("sub/plugin.jar", Some("fp-scope-3"), 10),
        None,
    )
    .unwrap();
    let p3 = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec_3.id,
        &tus_patch_headers(0, Some(10)),
        b"scoped-ok!".to_vec(),
    )
    .await;
    assert_eq!(p3.status(), StatusCode::NO_CONTENT);
    assert_eq!(p3.headers().get("Upload-Status").unwrap(), "completed");
    assert_eq!(
        fs::read(tmp.path().join("user-1/scope_b/sub/plugin.jar")).unwrap(),
        b"scoped-ok!"
    );
    assert!(!tmp.path().join("user-1/sub/plugin.jar").exists());
}

#[tokio::test]
async fn upload_audit_reconciles_lost_completion_ack_idempotently_and_handles_audit_failures() {
    let tmp = TestTempDir::new();
    let conn = setup_isolated_db();
    let alice = human_user(1);
    let bfs = super::super::open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs.create_directory_all("plugins").unwrap();

    conn.execute(
        "INSERT INTO mcbrowser_event_settings (id, queue_enabled, updated_at) VALUES (1, 1, '2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();

    conn.execute_batch(
        "CREATE TRIGGER fail_upload_audit_pending BEFORE INSERT ON mcbrowser_audit_events \
         BEGIN SELECT RAISE(ABORT, 'simulated pending audit failure'); END;",
    )
    .unwrap();

    let post_err = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("plugins/worldedit.jar", Some("fp-audit-0"), 12),
        None,
    )
    .unwrap_err();
    assert_eq!(post_err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(queried_used_bytes(&conn, 1), 1000);

    conn.execute_batch("DROP TRIGGER fail_upload_audit_pending;")
        .unwrap();

    conn.execute_batch(
        "CREATE TRIGGER fail_upload_audit_complete BEFORE INSERT ON mcbrowser_event_queue \
         BEGIN SELECT RAISE(ABORT, 'simulated queue completion failure'); END;",
    )
    .unwrap();

    let (rec, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("plugins/worldedit.jar", Some("fp-audit-1"), 12),
        None,
    )
    .unwrap();
    assert!(!rec.audit_event_id.is_empty());

    let pending_row =
        super::super::events::load_audit_record_by_id_with_conn(&conn, &rec.audit_event_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        pending_row.status,
        super::super::events::AuditEventStatus::Pending
    );
    assert_eq!(pending_row.event.byte_delta, 12);

    let patch_err = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &rec.id,
        &tus_patch_headers(0, Some(12)),
        b"123456789012".to_vec(),
    )
    .await;
    assert_eq!(patch_err.status(), StatusCode::INTERNAL_SERVER_ERROR);

    assert_eq!(
        fs::read(tmp.path().join("user-1/plugins/worldedit.jar")).unwrap(),
        b"123456789012"
    );
    let sess_after_fail = load_session_conn(&conn, &rec.id).unwrap().unwrap();
    assert_eq!(sess_after_fail.status, "publishing");
    assert_eq!(sess_after_fail.audit_event_id, rec.audit_event_id);

    let still_pending =
        super::super::events::load_audit_record_by_id_with_conn(&conn, &rec.audit_event_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        still_pending.status,
        super::super::events::AuditEventStatus::Pending
    );

    let q_count_before: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(q_count_before, 0);

    conn.execute_batch("DROP TRIGGER fail_upload_audit_complete;")
        .unwrap();

    let head_1 = head_upload_at(&conn, tmp.path(), &alice, &rec.id, &tus_basic_headers()).unwrap();
    assert_eq!(head_1.status(), StatusCode::OK);
    assert_eq!(head_1.headers().get("Upload-Status").unwrap(), "completed");

    let head_2 = head_upload_at(&conn, tmp.path(), &alice, &rec.id, &tus_basic_headers()).unwrap();
    assert_eq!(head_2.status(), StatusCode::OK);
    assert_eq!(head_2.headers().get("Upload-Status").unwrap(), "completed");

    let completed_row =
        super::super::events::load_audit_record_by_id_with_conn(&conn, &rec.audit_event_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        completed_row.status,
        super::super::events::AuditEventStatus::Completed
    );
    assert_eq!(completed_row.event.byte_delta, 12);
    assert_eq!(completed_row.event.relative_path, "plugins/worldedit.jar");

    let audit_total: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_audit_events", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(audit_total, 1);

    let queue_total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM mcbrowser_event_queue WHERE event_id = ?1",
            params![rec.audit_event_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(queue_total, 1);
}

#[tokio::test]
async fn upload_audit_handles_conflict_deltas_skip_cancel_and_ambiguous_expiry() {
    let tmp = TestTempDir::new();
    let conn = setup_isolated_db();
    let alice = human_user(1);

    conn.execute(
        "INSERT INTO mcbrowser_event_settings (id, queue_enabled, updated_at) VALUES (1, 1, '2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();

    let bfs = super::super::open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs.create_directory_all("data").unwrap();
    fs::write(tmp.path().join("user-1/data/config.yml"), b"0123456789").unwrap();
    conn.execute(
        "UPDATE user_quotas SET used_bytes = 10 WHERE user_id = 1",
        [],
    )
    .unwrap();

    let (skip_rec, skip_resp) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("data/config.yml", Some("fp-skip-1"), 20),
        Some("skip"),
    )
    .unwrap();
    assert_eq!(skip_resp.status(), StatusCode::CREATED);
    assert_eq!(skip_resp.headers().get("Upload-Skipped").unwrap(), "true");
    assert!(skip_rec.audit_event_id.is_empty());

    let audit_after_skip: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_audit_events", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(audit_after_skip, 0);

    let (noop_resume_rec, noop_resume_resp) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("data/config.yml", Some("fp-resume-noop"), 10),
        Some("resume"),
    )
    .unwrap();
    assert_eq!(noop_resume_resp.status(), StatusCode::CREATED);
    assert_eq!(
        noop_resume_resp.headers().get("Upload-Status").unwrap(),
        "completed"
    );
    assert!(noop_resume_rec.audit_event_id.is_empty());
    let audit_after_noop_resume: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_audit_events", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(audit_after_noop_resume, 0);

    let (ow_rec, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("data/config.yml", Some("fp-ow-shrink"), 4),
        Some("overwrite"),
    )
    .unwrap();
    let ow_patch = apply_patch_at(
        &conn,
        tmp.path(),
        &alice,
        &ow_rec.id,
        &tus_patch_headers(0, Some(4)),
        b"abcd".to_vec(),
    )
    .await;
    assert_eq!(ow_patch.status(), StatusCode::NO_CONTENT);
    let ow_audit =
        super::super::events::load_audit_record_by_id_with_conn(&conn, &ow_rec.audit_event_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        ow_audit.status,
        super::super::events::AuditEventStatus::Completed
    );
    assert_eq!(ow_audit.event.byte_delta, -6);
    assert_eq!(queried_used_bytes(&conn, 1), 4);

    let (cancel_rec, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("data/cancelled.bin", Some("fp-cancel"), 8),
        None,
    )
    .unwrap();
    let del_resp = delete_upload_at(
        &conn,
        tmp.path(),
        &alice,
        &cancel_rec.id,
        &tus_basic_headers(),
    )
    .unwrap();
    assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);
    let cancel_audit =
        super::super::events::load_audit_record_by_id_with_conn(&conn, &cancel_rec.audit_event_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        cancel_audit.status,
        super::super::events::AuditEventStatus::Failed
    );
    assert_eq!(cancel_audit.event.byte_delta, 0);
    assert_eq!(cancel_audit.error_code.as_deref(), Some("UPLOAD_CANCELLED"));

    let (amb_rec, _) = create_upload_session_at(
        &conn,
        tmp.path(),
        &alice,
        &tus_post_headers("data/ambiguous.bin", Some("fp-amb"), 6),
        None,
    )
    .unwrap();
    remove_staging_file_at(tmp.path(), 1, &amb_rec.id).unwrap();
    write_publication_proof_at(
        tmp.path(),
        &amb_rec,
        &UploadPublicationProof::Prepared {
            device: 0,
            inode: 0,
            nonce: None,
        },
    )
    .unwrap();
    conn.execute(
        "UPDATE mcbrowser_uploads SET status = 'publishing', offset_bytes = 6, expires_at = 1 WHERE id = ?1",
        params![amb_rec.id],
    )
    .unwrap();

    cleanup_expired_uploads_at(&conn, tmp.path(), 100).unwrap();
    let amb_audit =
        super::super::events::load_audit_record_by_id_with_conn(&conn, &amb_rec.audit_event_id)
            .unwrap()
            .unwrap();
    assert_eq!(
        amb_audit.status,
        super::super::events::AuditEventStatus::Pending
    );
    assert_eq!(queried_used_bytes(&conn, 1), 10);
}
