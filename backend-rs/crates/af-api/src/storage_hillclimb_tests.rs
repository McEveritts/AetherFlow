use super::*;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = env::temp_dir().join(format!("af-storage-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn backup_upload_rejects_unbounded_chunk_counts_before_creating_files() {
    let root = Scratch::new();
    for total in [0, MAX_BACKUP_UPLOAD_CHUNKS + 1, usize::MAX] {
        let error = process_backup_chunk_upload_in_dir(
            &root.0,
            "archive.sqlite",
            0,
            total,
            None,
            None,
            None,
            b"x",
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    }
}

#[test]
fn quota_projection_preserves_storage_status_and_defaults_only_empty_values() {
    for (input, expected) in [
        ("", "active"),
        ("  ", "active"),
        (" ACTIVE ", "active"),
        (" Suspended ", "suspended"),
        ("pending", "pending"),
    ] {
        let record = normalize_quota_record(UserQuotaRecord {
            user_id: 1,
            username: "quota-projection".to_owned(),
            status: input.to_owned(),
            quota_bytes: 100,
            used_bytes: 25,
            available_bytes: 0,
            usage_pct: 0.0,
            configured: false,
            source: "manual".to_owned(),
            updated_at: String::new(),
            used_gb: 0.0,
            total_gb: 0.0,
            percentage: 0.0,
        });
        assert_eq!(record.status, expected);
        assert_eq!(record.available_bytes, 75);
    }
}

#[tokio::test]
async fn mounted_fileshare_routes_reject_suspended_accounts_before_filesystem_access() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use axum::http::Request;
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users(id, username, role) VALUES(694, 'suspended-share-admin', 'admin')",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO user_quotas(user_id, username, quota_bytes, used_bytes, status) VALUES(694, 'suspended-share-admin', 100, 0, 'suspended')", []).unwrap();
    drop(conn);
    let (token, _) = crate::auth::create_standard_jwt(694, &HeaderMap::new()).unwrap();
    let app = crate::routes::build_router();
    for (method, path) in [
        ("GET", "/api/v1/auth/fileshare"),
        ("GET", "/api/v1/auth/fileshare/download/missing.txt"),
        ("GET", "/api/v1/admin/fileshare/download/missing.txt"),
        ("DELETE", "/api/v1/admin/fileshare/missing.txt"),
        ("POST", "/api/v1/admin/fileshare/upload"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", format!("Bearer {token}"))
                    .header("X-Requested-With", "XMLHttpRequest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
    }
}

#[test]
fn upload_storage_survives_release_working_directory_changes() {
    assert_eq!(
        upload_dir_from_config(None, None),
        PathBuf::from("/var/lib/aetherflow/uploads")
    );
    assert_eq!(
        upload_dir_from_config(None, Some("/tmp/state:/tmp/other")),
        PathBuf::from("/tmp/state/uploads")
    );
    assert_eq!(
        upload_dir_from_config(Some("/tmp/not-created-yet"), None),
        PathBuf::from("/tmp/not-created-yet")
    );
}

#[test]
fn fileshare_capability_rejects_directory_and_leaf_symlink_escapes() {
    use std::os::unix::fs::symlink;
    let root = Scratch::new();
    let outside = Scratch::new();
    fs::write(outside.0.join("secret.txt"), b"outside").unwrap();
    symlink(&outside.0, root.0.join("escape")).unwrap();
    symlink(outside.0.join("secret.txt"), root.0.join("secret.txt")).unwrap();
    assert!(fileshare_directory(&root.0, "escape").is_err());
    assert!(fileshare_directory(&root.0, "../escape").is_err());
    let browser = fileshare_directory(&root.0, "").unwrap();
    assert!(browser.open_file("secret.txt").is_err());
    assert!(browser.begin_replace("secret.txt").is_err());
    assert_eq!(fs::read(outside.0.join("secret.txt")).unwrap(), b"outside");
}

#[test]
fn concurrent_same_name_uploads_never_publish_interleaved_or_partial_content() {
    let root = Scratch::new();
    let mut sessions = HashMap::new();
    assert!(!append_fileshare_chunk(
        &mut sessions,
        &root.0,
        1,
        "first",
        "",
        "media.txt",
        0,
        2,
        b"first-"
    )
    .unwrap());
    assert!(!append_fileshare_chunk(
        &mut sessions,
        &root.0,
        1,
        "second",
        "",
        "media.txt",
        0,
        2,
        b"second-"
    )
    .unwrap());
    assert!(!root.0.join("media.txt").exists());
    assert!(append_fileshare_chunk(
        &mut sessions,
        &root.0,
        1,
        "first",
        "",
        "media.txt",
        1,
        2,
        b"complete"
    )
    .unwrap());
    assert!(append_fileshare_chunk(
        &mut sessions,
        &root.0,
        1,
        "second",
        "",
        "media.txt",
        1,
        2,
        b"complete"
    )
    .is_err());
    assert_eq!(
        fs::read(root.0.join("media.txt")).unwrap(),
        b"first-complete"
    );
    assert!(sessions.is_empty());
}

#[test]
fn chunk_order_owner_and_metadata_are_enforced_and_empty_files_publish() {
    let root = Scratch::new();
    let mut sessions = HashMap::new();
    append_fileshare_chunk(
        &mut sessions,
        &root.0,
        1,
        "session",
        "",
        "a.txt",
        0,
        3,
        b"a",
    )
    .unwrap();
    for (uid, name, index) in [(1, "a.txt", 2), (2, "a.txt", 1), (1, "b.txt", 1)] {
        assert!(append_fileshare_chunk(
            &mut sessions,
            &root.0,
            uid,
            "session",
            "",
            name,
            index,
            3,
            b"WRONG"
        )
        .is_err());
    }
    append_fileshare_chunk(
        &mut sessions,
        &root.0,
        1,
        "session",
        "",
        "a.txt",
        1,
        3,
        b"b",
    )
    .unwrap();
    append_fileshare_chunk(
        &mut sessions,
        &root.0,
        1,
        "session",
        "",
        "a.txt",
        2,
        3,
        b"c",
    )
    .unwrap();
    assert_eq!(fs::read(root.0.join("a.txt")).unwrap(), b"abc");
    assert!(append_fileshare_chunk(
        &mut sessions,
        &root.0,
        1,
        "empty",
        "",
        "empty.txt",
        0,
        1,
        b""
    )
    .unwrap());
    assert_eq!(fs::metadata(root.0.join("empty.txt")).unwrap().len(), 0);
}

#[test]
fn executable_magic_split_across_chunks_is_rejected_before_publication() {
    let root = Scratch::new();
    let mut sessions = HashMap::new();
    append_fileshare_chunk(
        &mut sessions,
        &root.0,
        1,
        "exec",
        "",
        "innocent.txt",
        0,
        2,
        b"\x7f",
    )
    .unwrap();
    assert!(append_fileshare_chunk(
        &mut sessions,
        &root.0,
        1,
        "exec",
        "",
        "innocent.txt",
        1,
        2,
        b"ELFpayload"
    )
    .is_err());
    assert!(!root.0.join("innocent.txt").exists());
    assert!(sessions.is_empty());
}

#[test]
fn backup_chunk_size_and_offset_are_bounded_before_reauthentication() {
    for (index, size) in [
        ("0", "0"),
        ("0", "67108865"),
        ("18446744073709551615", "67108864"),
    ] {
        let q = HashMap::from([
            ("chunk".to_string(), index.to_string()),
            ("chunk_size".to_string(), size.to_string()),
        ]);
        assert!(backup_download_chunk(&q).is_err());
    }
    assert_eq!(
        backup_download_chunk(&HashMap::from([("chunk".to_string(), "3".to_string())])).unwrap(),
        Some((3, DEFAULT_BACKUP_CHUNK_SIZE))
    );
}

#[test]
fn backup_cache_reuses_verified_generation_and_rejects_later_file_mutation() {
    let root = Scratch::new();
    let temporary = root.0.join("stage.uploading");
    let name = "backup.sqlite";
    let path = root.0.join(name);
    let conn = rusqlite::Connection::open(&temporary).unwrap();
    conn.execute_batch("CREATE TABLE data (id INTEGER PRIMARY KEY); INSERT INTO data VALUES (1);")
        .unwrap();
    drop(conn);
    let checksum = compute_file_sha256(&temporary).unwrap();
    finalize_assembled_backup_upload(&root.0, name, &temporary, &path, &checksum).unwrap();
    open_verified_backup(&root.0, name).unwrap();
    let key = (
        path.clone(),
        af_models::resolve_trusted_sqlite_ids_from_env(None).0,
    );
    let checked = BACKUP_VERIFICATIONS
        .lock()
        .unwrap()
        .get(&key)
        .unwrap()
        .checked;
    open_verified_backup(&root.0, name).unwrap();
    assert_eq!(
        BACKUP_VERIFICATIONS
            .lock()
            .unwrap()
            .get(&key)
            .unwrap()
            .checked,
        checked
    );
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"tampered")
        .unwrap();
    assert!(open_verified_backup(&root.0, name).is_err());
}

#[tokio::test]
async fn streaming_download_respects_requested_byte_limit() {
    let root = Scratch::new();
    let path = root.0.join("large.bin");
    fs::write(&path, vec![42; 200_000]).unwrap();
    let file = fs::File::open(path).unwrap();
    let bytes = axum::body::to_bytes(stream_file(file, 70_000), 70_000)
        .await
        .unwrap();
    assert_eq!(bytes.len(), 70_000);
    assert!(bytes.iter().all(|byte| *byte == 42));
}

#[test]
fn deployment_reservation_prevents_overlap_and_releases_on_cancellation() {
    let app = format!("unit-test-{}", uuid::Uuid::new_v4());
    let first =
        register_deployment(&app).unwrap_or_else(|_| panic!("initial deployment must register"));
    assert_eq!(
        register_deployment(&app).err().unwrap().status(),
        StatusCode::CONFLICT
    );
    drop(first);
    let replacement = register_deployment(&app)
        .unwrap_or_else(|_| panic!("cancelled deployment must release slot"));
    drop(replacement);
    assert!(!SSE_DEPLOY_TX.lock().unwrap().contains_key(&app));
    let failure = deployment_restart_status(Err(anyhow::anyhow!("runner restart failed")));
    assert!(failure.starts_with("[ERROR]"));
    assert!(!failure.contains("[SUCCESS]"));
}

#[tokio::test]
async fn real_router_accepts_five_mib_fileshare_chunks_and_empty_files() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let root = Scratch::new();
    env::set_var("AETHERFLOW_UPLOAD_DIR", &root.0);
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users(id, username, role) VALUES (675, 'upload-contract', 'admin')",
        [],
    )
    .unwrap();
    drop(conn);
    let (token, _) = crate::auth::create_standard_jwt(675, &HeaderMap::new()).unwrap();
    let app = crate::routes::build_router();
    for (size, expected) in [
        (5 * 1024 * 1024, StatusCode::OK),
        (5 * 1024 * 1024 + 1, StatusCode::PAYLOAD_TOO_LARGE),
        (0, StatusCode::OK),
    ] {
        let name = format!("size-{size}.txt");
        let mut payload = format!("--af-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
        payload.resize(payload.len() + size, b'x');
        payload.extend_from_slice(b"\r\n--af-boundary--\r\n");
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/admin/fileshare/upload")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(
                header::CONTENT_TYPE,
                "multipart/form-data; boundary=af-boundary",
            )
            .header(header::CONTENT_LENGTH, payload.len())
            .header("X-Upload-ID", uuid::Uuid::new_v4().simple().to_string())
            .header("X-Chunk-Index", "0")
            .header("X-Total-Chunks", "1")
            .header("X-Target-Path", "")
            .header("X-File-Name", &name)
            .body(Body::from(payload))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 10000)
            .await
            .unwrap();
        assert_eq!(
            status,
            expected,
            "{size}: {}",
            String::from_utf8_lossy(&body)
        );
        if expected == StatusCode::OK {
            assert_eq!(fs::metadata(root.0.join(&name)).unwrap().len(), size as u64);
        } else {
            assert!(!root.0.join(name).exists());
        }
    }
}

#[tokio::test]
async fn browser_backup_proof_rejects_bad_password_and_binds_single_get_to_session_and_file() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let root = Scratch::new();
    env::set_var("AETHERFLOW_BACKUP_DIR", &root.0);
    let name = "proof.sqlite";
    let temporary = root.0.join("proof.uploading");
    let conn = rusqlite::Connection::open(&temporary).unwrap();
    conn.execute_batch(
        "CREATE TABLE retained(value TEXT); INSERT INTO retained VALUES ('private backup');",
    )
    .unwrap();
    drop(conn);
    let checksum = compute_file_sha256(&temporary).unwrap();
    finalize_assembled_backup_upload(&root.0, name, &temporary, &root.0.join(name), &checksum)
        .unwrap();
    let conn = af_db::get_conn().unwrap();
    conn.execute("INSERT INTO users(id, username, role, password_hash) VALUES(676, 'backup-contract', 'admin', ?1)", params![bcrypt::hash("fixture-password", 4).unwrap()]).unwrap();
    drop(conn);
    let (token, _) = crate::auth::create_standard_jwt(676, &HeaderMap::new()).unwrap();
    let (other, _) = crate::auth::create_standard_jwt(676, &HeaderMap::new()).unwrap();
    let app = crate::routes::build_router();
    let url = format!("/api/v1/admin/backup/download/{name}");
    let request = |method: &str, url: &str, token: &str| {
        axum::http::Request::builder()
            .method(method)
            .uri(url)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
    };
    let denied = app
        .clone()
        .oneshot(
            request("POST", &url, &token)
                .header("X-Reauth-Password", "wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(denied.headers().get(header::SET_COOKIE).is_none());
    let issued = app
        .clone()
        .oneshot(
            request("POST", &url, &token)
                .header("X-Reauth-Password", "fixture-password")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(issued.status(), StatusCode::OK);
    let set_cookie = issued.headers()[header::SET_COOKIE].to_str().unwrap();
    for attribute in [
        "HttpOnly",
        "SameSite=Strict",
        "Max-Age=60",
        "Path=/api/v1/admin/backup/download/",
    ] {
        assert!(set_cookie.contains(attribute), "{set_cookie}");
    }
    assert!(!set_cookie.contains("fixture-password"));
    let cookie = set_cookie.split(';').next().unwrap().to_string();
    let body = axum::body::to_bytes(issued.into_body(), 1000)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["url"],
        url
    );
    for (wrong_url, session) in [
        (url.clone(), other.as_str()),
        (
            "/api/v1/admin/backup/download/other.sqlite".into(),
            token.as_str(),
        ),
    ] {
        let denied = app
            .clone()
            .oneshot(
                request("GET", &wrong_url, session)
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }
    let response = app
        .clone()
        .oneshot(
            request("GET", &url, &token)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["X-Checksum-SHA256"], checksum);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], &fs::read(root.0.join(name)).unwrap());
    let replay = app
        .clone()
        .oneshot(
            request("GET", &url, &token)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    let cli = app
        .oneshot(
            request("GET", &url, &token)
                .header("X-Reauth-Password", "fixture-password")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cli.status(), StatusCode::OK);
}

#[test]
fn expired_backup_download_proof_is_rejected() {
    let user = AuthUser {
        user_id: 712,
        username: "proof-expiry".into(),
        role: "admin".into(),
        jti: uuid::Uuid::new_v4().to_string(),
        plugin_id: None,
        plugin_scopes: vec![],
    };
    let token = issue_backup_download_ticket(&user, "archive.sqlite").unwrap();
    BACKUP_DOWNLOAD_TICKETS
        .lock()
        .unwrap()
        .get_mut(&token)
        .unwrap()
        .issued = Instant::now() - StdDuration::from_secs(61);
    assert!(!redeem_backup_download_ticket(
        &token,
        &user,
        "archive.sqlite"
    ));
}

#[tokio::test]
async fn shared_uploads_account_payload_growth_and_refund_failed_publications() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let root = Scratch::new();
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users(id,username) VALUES(690,'share-accounting'),(691,'other-owner')",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO user_quotas(user_id,username,quota_bytes,used_bytes,status) VALUES(690,'share-accounting',4096,0,'active'),(691,'other-owner',4096,0,'active')",[]).unwrap();
    let upload = |user, name: &str, size: usize| {
        append_fileshare_chunk_with(
            &mut HashMap::new(),
            &root.0,
            user,
            &uuid::Uuid::new_v4().simple().to_string(),
            "",
            name,
            0,
            1,
            &vec![b'x'; size],
            |session| accounting::publish(&conn, &root.0, user, session),
        )
    };
    let used = || {
        conn.query_row(
            "SELECT used_bytes FROM user_quotas WHERE user_id=690",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
    };
    assert!(upload(690, "first.txt", 3072).unwrap());
    assert_eq!(used(), 3072);
    conn.execute(
        "UPDATE user_quotas SET status = 'suspended' WHERE user_id = 690",
        [],
    )
    .unwrap();
    for (name, size) in [("suspended.txt", 1), ("empty.txt", 0), ("first.txt", 1)] {
        assert!(upload(690, name, size).is_err());
        assert_eq!(used(), 3072);
    }
    assert!(!root.0.join("suspended.txt").exists());
    assert!(!root.0.join("empty.txt").exists());
    assert_eq!(fs::read(root.0.join("first.txt")).unwrap().len(), 3072);
    conn.execute(
        "UPDATE user_quotas SET status = 'active' WHERE user_id = 690",
        [],
    )
    .unwrap();
    assert!(upload(690, "second.txt", 3072)
        .unwrap_err()
        .is::<accounting::QuotaExceeded>());
    assert!(!root.0.join("second.txt").exists());
    assert!(upload(690, "first.txt", 3072).unwrap());
    assert_eq!(used(), 3072);
    assert!(upload(691, "first.txt", 4).is_err());
    assert!(upload(690, "first.txt", 2048).unwrap());
    assert_eq!(used(), 2048);
    assert!(upload(690, "second.txt", 2048).unwrap());
    assert_eq!(used(), 4096);
    accounting::delete(&conn, &root.0, "", "second.txt").unwrap();
    assert_eq!(used(), 2048);
    conn.execute_batch("CREATE TRIGGER fail_shared_ledger BEFORE INSERT ON fileshare_objects BEGIN SELECT RAISE(FAIL,'fixture persistence failure'); END;").unwrap();
    assert!(upload(690, "db-error.txt", 100).is_err());
    assert_eq!(used(), 2048);
    assert!(!root.0.join("db-error.txt").exists());
    conn.execute_batch("DROP TRIGGER fail_shared_ledger;")
        .unwrap();
    let browser = fileshare_directory(&root.0, "").unwrap();
    let pending = browser.begin_upload("raced.txt").unwrap();
    pending.file().unwrap().write_all(b"new").unwrap();
    fs::write(root.0.join("raced.txt"), b"keep").unwrap();
    assert!(accounting::publish(
        &conn,
        &root.0,
        690,
        FileshareUpload {
            filename: "raced.txt".into(),
            directory: "".into(),
            total_chunks: 1,
            next_chunk: 1,
            size: 3,
            prefix: vec![],
            pending,
            original: None,
            updated: Instant::now()
        }
    )
    .is_err());
    assert_eq!(used(), 2048);
    assert_eq!(fs::read(root.0.join("raced.txt")).unwrap(), b"keep");
}

#[tokio::test]
async fn fileshare_admission_rejects_before_polling_body() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users(id,username,role) VALUES(692,'share-admission','admin')",
        [],
    )
    .unwrap();
    drop(conn);
    let (token, _) = crate::auth::create_standard_jwt(692, &HeaderMap::new()).unwrap();
    let saturated = FILESHARE_WORKERS
        .clone()
        .acquire_many_owned(4)
        .await
        .unwrap();
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = polls.clone();
    let body = Body::from_stream(futures::stream::poll_fn(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        std::task::Poll::Ready(Some(Ok::<_, std::io::Error>(vec![b'x'; 65536])))
    }));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/admin/fileshare/upload")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=af-boundary",
        )
        .body(body)
        .unwrap();
    assert_eq!(
        crate::routes::build_router()
            .oneshot(request)
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    drop(saturated);
}

#[tokio::test]
async fn shared_storage_aliases_preserve_ownership_and_accounting_identity() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let root = Scratch::new();
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users(id,username) VALUES(694,'alias-owner'),(695,'alias-other')",
        [],
    )
    .unwrap();
    conn.execute("INSERT INTO user_quotas(user_id,username,quota_bytes,used_bytes) VALUES(694,'alias-owner',4096,0),(695,'alias-other',4096,0)", []).unwrap();
    let upload = |user, directory: &str, size: usize| {
        append_fileshare_chunk_with(
            &mut HashMap::new(),
            &root.0,
            user,
            &uuid::Uuid::new_v4().simple().to_string(),
            directory,
            "same.txt",
            0,
            1,
            &vec![b'x'; size],
            |session| accounting::publish(&conn, &root.0, user, session),
        )
    };
    assert!(upload(694, "nested//shared", 3072).unwrap());
    assert!(upload(695, "nested/shared/", 5).is_err());
    assert!(upload(694, "/nested/shared/", 2048).unwrap());
    let (rows, used): (i64, i64) = conn.query_row(
        "SELECT (SELECT COUNT(*) FROM fileshare_objects), used_bytes FROM user_quotas WHERE user_id=694",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!((rows, used), (1, 2048));
    accounting::delete(&conn, &root.0, "nested///shared", "same.txt").unwrap();
    let used: i64 = conn
        .query_row(
            "SELECT used_bytes FROM user_quotas WHERE user_id=694",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(used, 0);
    assert!(!root.0.join("nested/shared/same.txt").exists());
}

#[tokio::test]
async fn quotas_use_runner_scan_and_apply_and_report_persistence_failures() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    let root = Scratch::new();
    let candidate = root.0.join("runner.sock");
    let socket = if candidate.as_os_str().len() < 95 {
        candidate
    } else {
        let short_name = format!(
            "af-sock-{}.sock",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );
        let tmpdir_cand = env::var_os("TMPDIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join(&short_name);
        if tmpdir_cand.as_os_str().len() < 95 {
            tmpdir_cand
        } else {
            PathBuf::from("/tmp").join(short_name)
        }
    };
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    env::set_var("AETHERFLOW_RUNNER_SOCK", &socket);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(AtomicBool::new(false));
    let usage = Arc::new(AtomicU64::new(8123));
    let (captured, failed, measured) = (calls.clone(), fail.clone(), usage.clone());
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (captured, failed, measured) = (captured.clone(), failed.clone(), measured.clone());
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    move |request: hyper::Request<hyper::body::Incoming>| {
                        let (captured, failed, measured) =
                            (captured.clone(), failed.clone(), measured.clone());
                        async move {
                            let path = request.uri().path().to_owned();
                            let body = request.into_body().collect().await.unwrap().to_bytes();
                            captured.lock().unwrap().push((
                                path.clone(),
                                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                            ));
                            let success = !(path == "/v1/quota" && failed.load(Ordering::SeqCst));
                            let output = if path == "/v1/quota/usage" {
                                serde_json::json!({"used_bytes":measured.load(Ordering::SeqCst),"scanned_roots":[]}).to_string()
                            } else {
                                String::new()
                            };
                            Ok::<_,std::convert::Infallible>(Response::new(Body::from(serde_json::json!({"success":success,"output":output,"error":if success{""}else{"fixture quota apply failed"}}).to_string())))
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users(id,username) VALUES(693,'quota-runner')",
        [],
    )
    .unwrap();
    drop(conn);
    assert_eq!(
        update_user_quota(Path(693), Json(serde_json::json!({"quota_bytes":1537})))
            .await
            .status(),
        StatusCode::OK
    );
    let row = query_user_quota_record(693).unwrap();
    assert_eq!((row.quota_bytes, row.used_bytes), (2048, 8123));
    assert_eq!(calls.lock().unwrap()[0].0, "/v1/quota/usage");
    assert_eq!(calls.lock().unwrap()[1].1["size"], "2048B");
    usage.store(12000, Ordering::SeqCst);
    assert_eq!(refresh_user_quota(Path(693)).await.status(), StatusCode::OK);
    assert_eq!(query_user_quota_record(693).unwrap().used_bytes, 12000);
    fail.store(true, Ordering::SeqCst);
    assert!(
        update_user_quota(Path(693), Json(serde_json::json!({"quota":"8KB"})))
            .await
            .status()
            .is_server_error()
    );
    assert_eq!(query_user_quota_record(693).unwrap().quota_bytes, 2048);
    fail.store(false, Ordering::SeqCst);
    let conn = af_db::get_conn().unwrap();
    conn.execute_batch("CREATE TRIGGER reject_quota_persist BEFORE UPDATE ON user_quotas BEGIN SELECT RAISE(FAIL,'fixture persistence failure'); END;").unwrap();
    drop(conn);
    assert!(
        update_user_quota(Path(693), Json(serde_json::json!({"quota":"8KB"})))
            .await
            .status()
            .is_server_error()
    );
    assert_eq!(query_user_quota_record(693).unwrap().quota_bytes, 2048);
    server.abort();
    let _ = server.await;
    let _ = fs::remove_file(&socket);
}
