use super::*;
use crate::auth::AuthUser;
use crate::mcbrowser::open_user_browser_fs_at;
use rand::Rng;
use rusqlite::{params, Connection};
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let token: u128 = rng.gen();
            let path = std::env::temp_dir().join(format!("af-mcbrowser-ops-test-{token:032x}"));
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

fn setup_quota_db(user_id: i64, quota_bytes: i64, used_bytes: i64) -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL);
         CREATE TABLE user_quotas (
             user_id INTEGER PRIMARY KEY,
             username TEXT NOT NULL,
             quota_bytes INTEGER DEFAULT 0,
             used_bytes INTEGER DEFAULT 0,
             status TEXT DEFAULT 'active',
             source TEXT DEFAULT 'manual',
             updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
         );",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO users (id, username) VALUES (?1, ?2)",
        params![user_id, format!("user{user_id}")],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status)
         VALUES (?1, ?2, ?3, ?4, 'active')",
        params![user_id, format!("user{user_id}"), quota_bytes, used_bytes],
    )
    .unwrap();
    conn
}

fn read_used_bytes(conn: &Connection, user_id: i64) -> i64 {
    conn.query_row(
        "SELECT used_bytes FROM user_quotas WHERE user_id = ?1",
        params![user_id],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn info_resolves_confined_aliases_and_filters_counts_at_every_hop() {
    let temporary = TestTempDir::new();
    let filesystem = open_user_browser_fs_at(temporary.path(), 87).unwrap();
    let root = temporary.path().join("user-87");
    filesystem.create_directory_all("data/sub").unwrap();
    fs::write(root.join("data/public.txt"), b"hello").unwrap();
    fs::write(root.join("data/hidden.txt"), b"secret").unwrap();
    symlink("data", root.join("hop")).unwrap();
    symlink("hop", root.join("alias")).unwrap();
    symlink("hop/public.txt", root.join("file-alias.txt")).unwrap();

    let info = collect_entry_info_with_auth(
        &filesystem,
        "file-alias.txt",
        &[ChecksumAlgorithm::Md5],
        |_, _| true,
    )
    .unwrap();
    assert_eq!(info.entry.path, "file-alias.txt");
    assert_eq!(info.entry.name, "file-alias.txt");
    assert_eq!(info.entry.kind, "file");
    assert_eq!(info.entry.size, 5);
    assert_eq!(info.checksums["md5"], "5d41402abc4b2a76b9719d911017c592");
    for denied in ["file-alias.txt", "hop/public.txt", "data/public.txt"] {
        assert!(
            matches!(
                collect_entry_info_with_auth(
                    &filesystem,
                    "file-alias.txt",
                    &[ChecksumAlgorithm::Sha256],
                    |path, _| path != denied
                ),
                Err(McBrowserError::Forbidden(_))
            ),
            "inspection must authorize {denied}"
        );
    }
    for denied in ["alias/hidden.txt", "hop/hidden.txt", "data/hidden.txt"] {
        let info =
            collect_entry_info_with_auth(&filesystem, "alias", &[], |path, _| path != denied)
                .unwrap();
        assert_eq!(info.entry.path, "alias");
        assert_eq!(info.entry.kind, "directory");
        assert_eq!((info.num_files, info.num_dirs), (Some(1), Some(1)));
    }
    for denied in ["alias", "hop", "data"] {
        assert!(matches!(
            collect_entry_info_with_auth(&filesystem, "alias", &[], |path, _| path != denied),
            Err(McBrowserError::Forbidden(_))
        ));
    }
    symlink("../outside.txt", root.join("escape")).unwrap();
    fs::write(temporary.path().join("outside.txt"), b"outside").unwrap();
    symlink("loop", root.join("loop")).unwrap();
    symlink("missing", root.join("broken")).unwrap();
    for path in ["escape", "loop", "broken"] {
        assert!(collect_entry_info_with_auth(&filesystem, path, &[], |_, _| true).is_err());
    }
    fs::hard_link(root.join("data/public.txt"), root.join("hardlink")).unwrap();
    assert!(collect_entry_info_with_auth(&filesystem, "file-alias.txt", &[], |_, _| true).is_err());
}

#[test]
fn copy_and_move_keep_publication_success_when_quota_release_fails() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 5).unwrap();
    let conn = setup_quota_db(5, 100, 0);
    execute_create_file_conn(&conn, &bfs, "source.txt", Some("tiny"), 5).unwrap();
    execute_create_file_conn(&conn, &bfs, "destination.txt", Some("original"), 5).unwrap();
    execute_create_file_conn(&conn, &bfs, "move.txt", Some("moved"), 5).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_quota_release BEFORE UPDATE ON user_quotas
         WHEN NEW.used_bytes < OLD.used_bytes
         BEGIN SELECT RAISE(ABORT, 'injected quota release failure'); END;",
    )
    .unwrap();
    let mut accounting_complete = true;
    let destination = execute_copy_with_accounting_conn(
        &conn,
        &bfs,
        "source.txt",
        "destination.txt",
        OperationConflictPolicy::Overwrite,
        5,
        &mut accounting_complete,
    )
    .unwrap();
    assert_eq!(destination, "destination.txt");
    assert!(!accounting_complete);
    let (document, _) =
        read_utf8_editor_content_from_file(bfs.open_file(&destination).unwrap(), destination)
            .unwrap();
    assert_eq!(document.content, "tiny");
    accounting_complete = true;
    let destination = execute_rename_with_accounting_conn(
        &conn,
        &bfs,
        "move.txt",
        "destination.txt",
        OperationConflictPolicy::Overwrite,
        5,
        &mut accounting_complete,
    )
    .unwrap();
    assert!(!accounting_complete);
    assert!(bfs.metadata("move.txt").is_err());
    let (document, _) =
        read_utf8_editor_content_from_file(bfs.open_file(&destination).unwrap(), destination)
            .unwrap();
    assert_eq!(document.content, "moved");
    accounting_complete = true;
    let collision = copy_single_file_new_with_quota(
        &conn,
        &bfs,
        "source.txt",
        "destination.txt",
        4,
        5,
        &mut accounting_complete,
    );
    assert!(matches!(
        collision,
        Err(McBrowserError::AccountingPending(_))
    ));
    assert_eq!(read_used_bytes(&conn, 5), 21);
}

#[test]
fn content_accounting_failures_distinguish_publication_from_unpublished_compensation() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 5).unwrap();
    let conn = setup_quota_db(5, 100, 0);
    execute_create_file_conn(&conn, &bfs, "notes.txt", Some("original"), 5).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER reject_quota_release BEFORE UPDATE ON user_quotas
         WHEN NEW.used_bytes < OLD.used_bytes
         BEGIN SELECT RAISE(ABORT, 'injected quota release failure'); END;",
    )
    .unwrap();
    let response = execute_put_content_conn(
        &conn,
        &bfs,
        "notes.txt",
        "tiny",
        &compute_etag_bytes(b"original"),
        5,
    )
    .unwrap();
    assert!(response.success);
    assert!(response.accounting_pending);
    assert_eq!(response.etag, compute_etag_bytes(b"tiny"));
    assert_eq!(read_used_bytes(&conn, 5), 8);
    let (document, expected_file) =
        read_utf8_editor_content_from_file(bfs.open_file("notes.txt").unwrap(), "notes.txt".into())
            .unwrap();
    let mut replacement = bfs.begin_replace("notes.txt").unwrap();
    replacement.write_all(b"other").unwrap();
    replacement.commit_replace(&expected_file).unwrap();
    let failed_save = execute_put_content_with_loaded_target_conn(
        &conn,
        &bfs,
        "notes.txt",
        &document,
        &expected_file,
        "larger content",
        &document.etag,
        5,
    );
    assert!(matches!(
        failed_save,
        Err(McBrowserError::AccountingPending(_))
    ));
    let failed_create = execute_create_file_conn(&conn, &bfs, "notes.txt", Some("new"), 5);
    assert!(matches!(failed_create, Err(McBrowserError::Conflict(_))));
    let (unchanged, _) =
        read_utf8_editor_content_from_file(bfs.open_file("notes.txt").unwrap(), "notes.txt".into())
            .unwrap();
    assert_eq!(unchanged.content, "other");
    assert_eq!(read_used_bytes(&conn, 5), 18);
}

#[test]
fn search_filtering_supports_query_kind_and_truncation() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    let conn = setup_quota_db(1, 10_000_000, 0);

    bfs.create_directory_all("projects/rust/src").unwrap();
    bfs.create_directory_all("projects/docs").unwrap();
    execute_create_file_conn(
        &conn,
        &bfs,
        "projects/rust/Cargo.toml",
        Some("[package]"),
        1,
    )
    .unwrap();
    execute_create_file_conn(
        &conn,
        &bfs,
        "projects/rust/src/main.rs",
        Some("fn main() {}"),
        1,
    )
    .unwrap();
    execute_create_file_conn(&conn, &bfs, "projects/docs/readme.md", Some("# Docs"), 1).unwrap();

    let walked = bfs.walk("", MAX_SEARCH_ENTRIES).unwrap();
    let all_rs = filter_walked_entries(walked.clone(), "main", SearchKindFilter::File, 100);
    assert!(!all_rs.truncated);
    assert_eq!(all_rs.entries.len(), 1);
    assert_eq!(all_rs.entries[0].path, "projects/rust/src/main.rs");

    let dirs_only = filter_walked_entries(walked.clone(), "rust", SearchKindFilter::Directory, 100);
    assert_eq!(dirs_only.entries.len(), 1);
    assert_eq!(dirs_only.entries[0].path, "projects/rust");
    assert!(dirs_only.entries.iter().all(|e| e.kind == "directory"));

    let modifiers = filter_walked_entries(
        walked.clone(),
        "case:sensitive type:rs type:md main readme",
        SearchKindFilter::File,
        100,
    );
    assert_eq!(modifiers.entries.len(), 2);
    let parent_only =
        filter_walked_entries(walked.clone(), "projects", SearchKindFilter::File, 100);
    assert!(parent_only.entries.is_empty());

    let trunc = filter_walked_entries(walked, "", SearchKindFilter::Any, 2);
    assert!(trunc.truncated);
    assert_eq!(trunc.entries.len(), 2);

    assert!(parse_search_type_filter(Some("invalid")).is_err());
    assert_eq!(
        parse_search_type_filter(Some("FILE")).unwrap(),
        SearchKindFilter::File
    );
    assert_eq!(
        parse_search_type_filter(Some("directory")).unwrap(),
        SearchKindFilter::Directory
    );
}

#[test]
fn flowai_natural_language_search_and_bfs_walk_for_search_tests() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    let conn = setup_quota_db(1, 10_000_000, 0);

    bfs.create_directory_all("Google/Media/TV/The Pitt/Season 1")
        .unwrap();
    bfs.create_directory_all("Google/Documents/Finance").unwrap();
    execute_create_file_conn(
        &conn,
        &bfs,
        "Google/Media/TV/The Pitt/Season 1/The Pitt - S01E01 - 7-00 A.M. WEBDL-2160p.mkv",
        Some("video"),
        1,
    )
    .unwrap();
    execute_create_file_conn(
        &conn,
        &bfs,
        "Google/Documents/Finance/The_Other_Report.txt",
        Some("report"),
        1,
    )
    .unwrap();
    execute_create_file_conn(
        &conn,
        &bfs,
        "Google/Documents/Finance/Oil_Gas_Prices_2026.xlsx",
        Some("sheet"),
        1,
    )
    .unwrap();

    let (walked, truncated) = bfs.walk_for_search("", 500).unwrap();
    assert!(!truncated);

    // 1. Searching "The Pitt" in FlowAI mode matches The Pitt folder & episode, NOT "The_Other_Report.txt"
    let plan_pitt = build_deterministic_nl_plan("The Pitt");
    let res_pitt =
        filter_and_rank_entries_with_flowai(walked.clone(), &plan_pitt, SearchKindFilter::Any, 100);
    assert_eq!(res_pitt.ai_powered, Some(true));
    assert!(res_pitt.ai_interpretation.is_some());
    assert!(res_pitt
        .entries
        .iter()
        .any(|e| e.name == "The Pitt" && e.kind == "directory"));
    assert!(res_pitt
        .entries
        .iter()
        .any(|e| e.name.contains("S01E01")));
    assert!(!res_pitt
        .entries
        .iter()
        .any(|e| e.name == "The_Other_Report.txt"));

    // 2. Conversational natural language query: "find episodes of The Pitt in season 1"
    let plan_nl = build_deterministic_nl_plan("find episodes of The Pitt in season 1");
    let res_nl =
        filter_and_rank_entries_with_flowai(walked.clone(), &plan_nl, SearchKindFilter::Any, 100);
    assert!(res_nl.entries.iter().any(|e| e.name.contains("S01E01")));

    // 3. Natural language file type intent: "excel spreadsheets about gas prices"
    let plan_sheet = build_deterministic_nl_plan("excel spreadsheets about gas prices");
    let res_sheet = filter_and_rank_entries_with_flowai(
        walked,
        &plan_sheet,
        SearchKindFilter::Any,
        100,
    );
    assert_eq!(res_sheet.entries.len(), 1);
    assert_eq!(res_sheet.entries[0].name, "Oil_Gas_Prices_2026.xlsx");
}

#[test]
fn create_file_and_content_editor_optimistic_concurrency_and_quota_accounting() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 5).unwrap();
    let conn = setup_quota_db(5, 100, 0);

    // 1. Create file with initial content (11 bytes)
    execute_create_file_conn(&conn, &bfs, "notes.txt", Some("hello world"), 5).unwrap();
    assert_eq!(read_used_bytes(&conn, 5), 11);

    // No-clobber on POST /mcbrowser/file
    let dup_err = execute_create_file_conn(&conn, &bfs, "notes.txt", Some("overwrite"), 5);
    assert!(matches!(dup_err, Err(McBrowserError::Conflict(_))));
    assert_eq!(read_used_bytes(&conn, 5), 11);

    // 2. Read content & ETag
    let (doc1, _) =
        read_utf8_editor_content_from_file(bfs.open_file("notes.txt").unwrap(), "notes.txt".into())
            .unwrap();
    assert_eq!(doc1.content, "hello world");
    assert_eq!(doc1.etag, compute_etag_bytes(b"hello world"));

    // 3. Stale ETag rejected with 409 Conflict and leaves content & quota untouched
    let stale_err = execute_put_content_conn(
        &conn,
        &bfs,
        "notes.txt",
        "updated content longer",
        "\"0000000000000000\"",
        5,
    );
    assert!(matches!(stale_err, Err(McBrowserError::Conflict(_))));
    assert_eq!(read_used_bytes(&conn, 5), 11);

    // 4. Valid ETag expands file from 11 -> 25 bytes (+14 bytes quota)
    let put1 = execute_put_content_conn(
        &conn,
        &bfs,
        "notes.txt",
        "0123456789012345678901234",
        &doc1.etag,
        5,
    )
    .unwrap();
    assert!(put1.success);
    assert_eq!(read_used_bytes(&conn, 5), 25);

    // 5. Valid ETag shrinks file from 25 -> 4 bytes (-21 bytes quota released)
    let put2 = execute_put_content_conn(&conn, &bfs, "notes.txt", "tiny", &put1.etag, 5).unwrap();
    assert_eq!(read_used_bytes(&conn, 5), 4);

    // 6. Quota exceeded on expansion rolls back cleanly and keeps old content
    let too_big_for_quota = "x".repeat(102); // needs +98 bytes, total 102 > 100 quota
    let quota_err =
        execute_put_content_conn(&conn, &bfs, "notes.txt", &too_big_for_quota, &put2.etag, 5);
    assert!(matches!(quota_err, Err(McBrowserError::QuotaExceeded(_))));
    assert_eq!(read_used_bytes(&conn, 5), 4);

    let (doc_after, _) =
        read_utf8_editor_content_from_file(bfs.open_file("notes.txt").unwrap(), "notes.txt".into())
            .unwrap();
    assert_eq!(doc_after.content, "tiny");
}

#[test]
fn editor_enforces_source_pinned_10mib_limit_and_utf8_validation() {
    let tmp = TestTempDir::new();
    assert_eq!(MAX_EDITOR_CONTENT_BYTES, 10 * 1024 * 1024);
    let boundary = "é".repeat(MAX_EDITOR_CONTENT_BYTES / 2);
    assert_eq!(
        validate_editor_write_payload(&boundary).unwrap().len(),
        MAX_EDITOR_CONTENT_BYTES
    );
    let boundary_path = tmp.path().join("boundary.txt");
    fs::write(&boundary_path, &boundary).unwrap();
    let (read_boundary, _) = read_utf8_editor_content_from_file(
        File::open(&boundary_path).unwrap(),
        "boundary.txt".into(),
    )
    .unwrap();
    assert_eq!(read_boundary.content, boundary);
    let over_path = tmp.path().join("over.txt");
    fs::write(&over_path, vec![b'a'; MAX_EDITOR_CONTENT_BYTES + 1]).unwrap();
    assert!(matches!(
        read_utf8_editor_content_from_file(File::open(&over_path).unwrap(), "over.txt".into()),
        Err(McBrowserError::PayloadTooLarge(_))
    ));

    let bin_path = tmp.path().join("bin.txt");
    fs::write(&bin_path, b"abc\0def").unwrap();
    assert!(matches!(
        read_utf8_editor_content_from_file(File::open(&bin_path).unwrap(), "bin.txt".into()),
        Err(McBrowserError::BadRequest(_))
    ));

    let over_str = "a".repeat(MAX_EDITOR_CONTENT_BYTES + 1);
    assert!(matches!(
        validate_editor_write_payload(&over_str),
        Err(McBrowserError::PayloadTooLarge(_))
    ));
}

#[tokio::test]
async fn editor_admission_rejects_before_body_parsing_and_recovers_after_capacity_release() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let permits = EDITOR_SEMAPHORE
        .acquire_many(EDITOR_CONCURRENCY_LIMIT as u32)
        .await
        .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/mcbrowser/file")
        .header("content-type", "application/json")
        .body(Body::from_stream(futures::stream::pending::<
            Result<Bytes, io::Error>,
        >()))
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(1), router().oneshot(request))
        .await
        .expect("busy admission must not read the pending request body")
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[header::RETRY_AFTER], "1");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    drop(permits);
    let response = router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/file")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        EDITOR_SEMAPHORE.available_permits(),
        EDITOR_CONCURRENCY_LIMIT
    );
}

#[test]
fn copy_and_delete_recursive_update_quota_and_enforce_no_clobber() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 9).unwrap();
    let conn = setup_quota_db(9, 1000, 0);

    bfs.create_directory_all("src_dir/sub").unwrap();
    execute_create_file_conn(&conn, &bfs, "src_dir/a.txt", Some("12345"), 9).unwrap();
    execute_create_file_conn(&conn, &bfs, "src_dir/sub/b.txt", Some("1234567890"), 9).unwrap();
    assert_eq!(read_used_bytes(&conn, 9), 15);

    // Copy directory tree (adds 15 bytes -> 30 bytes used)
    execute_copy_conn(&conn, &bfs, "src_dir", "dst_dir", 9).unwrap();
    assert_eq!(read_used_bytes(&conn, 9), 30);

    // No-clobber on existing destination
    assert!(matches!(
        execute_copy_conn(&conn, &bfs, "src_dir", "dst_dir", 9),
        Err(McBrowserError::Conflict(_))
    ));
    assert_eq!(read_used_bytes(&conn, 9), 30);

    // Reject copying directory into itself
    assert!(matches!(
        execute_copy_conn(&conn, &bfs, "src_dir", "src_dir/nested", 9),
        Err(McBrowserError::BadRequest(_))
    ));

    // Delete recursive releases 15 bytes -> 15 bytes remaining
    execute_delete_recursive_conn(&conn, &bfs, "dst_dir", 9).unwrap();
    assert_eq!(read_used_bytes(&conn, 9), 15);
    assert!(bfs.metadata("dst_dir").is_err());
}

#[test]
fn checksums_match_known_test_vectors() {
    let algs = parse_checksum_algorithms(Some("md5,sha1,sha256,sha512")).unwrap();
    assert_eq!(algs.len(), 4);

    let sums = compute_checksums_from_reader(Cursor::new(b"abc"), &algs).unwrap();
    assert_eq!(sums["md5"], "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(sums["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(
        sums["sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sums["sha512"],
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
}

#[test]
fn archive_formats_stream_valid_zip_tar_and_targz_and_reject_unsafe_paths() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 12).unwrap();
    let conn = setup_quota_db(12, 1_000_000, 0);
    let user = human_user(12);

    bfs.create_directory_all("bundle/nested").unwrap();
    execute_create_file_conn(&conn, &bfs, "bundle/hello.txt", Some("Hello Archive!"), 12).unwrap();
    execute_create_file_conn(
        &conn,
        &bfs,
        "bundle/nested/data.json",
        Some("{\"ok\":true}"),
        12,
    )
    .unwrap();

    // Reject duplicate or overlapping selections
    assert!(normalize_archive_selection(&["bundle".into(), "bundle/hello.txt".into()]).is_err());
    assert!(normalize_archive_selection(&["../escape".into()]).is_err());

    let mut checked_paths = Vec::new();
    let plan = collect_archive_plan_with_auth(&bfs, &["bundle".to_string()], |path| {
        let _ = crate::mcbrowser::validate_mcbrowser_user(&user)?;
        checked_paths.push(path.to_string());
        Ok(())
    })
    .unwrap();
    assert_eq!(plan.len(), 4); // bundle/, bundle/nested/, bundle/nested/data.json, bundle/hello.txt
    assert_eq!(checked_paths.iter().collect::<HashSet<_>>().len(), 4);

    // Deny descendant path via policy callback
    let denied = collect_archive_plan_with_auth(&bfs, &["bundle".to_string()], |path| {
        if path == "bundle/nested/data.json" {
            return Err(McBrowserError::Forbidden("Denied by test policy".into()));
        }
        Ok(())
    });
    assert!(matches!(denied, Err(McBrowserError::Forbidden(_))));

    // Verify all 9 archive formats and their aliases parse and roundtrip decode cleanly
    let alias_cases = [
        ("zip", ArchiveFormat::Zip, "zip"),
        (".zip", ArchiveFormat::Zip, "zip"),
        ("tar", ArchiveFormat::Tar, "tar"),
        (".tar", ArchiveFormat::Tar, "tar"),
        ("targz", ArchiveFormat::TarGz, "tar.gz"),
        ("tar.gz", ArchiveFormat::TarGz, "tar.gz"),
        ("tarbz2", ArchiveFormat::TarBz2, "tar.bz2"),
        ("tar.bz2", ArchiveFormat::TarBz2, "tar.bz2"),
        ("tarxz", ArchiveFormat::TarXz, "tar.xz"),
        ("tar.xz", ArchiveFormat::TarXz, "tar.xz"),
        ("tarlz4", ArchiveFormat::TarLz4, "tar.lz4"),
        ("tar.lz4", ArchiveFormat::TarLz4, "tar.lz4"),
        ("tarsz", ArchiveFormat::TarSz, "tar.sz"),
        ("tar.sz", ArchiveFormat::TarSz, "tar.sz"),
        ("tarbr", ArchiveFormat::TarBr, "tar.br"),
        ("tar.br", ArchiveFormat::TarBr, "tar.br"),
        ("tarzst", ArchiveFormat::TarZst, "tar.zst"),
        ("tar.zst", ArchiveFormat::TarZst, "tar.zst"),
    ];
    for (raw, expected_fmt, expected_ext) in alias_cases {
        let parsed = ArchiveFormat::parse(raw).unwrap();
        assert_eq!(parsed, expected_fmt);
        assert_eq!(parsed.extension(), expected_ext);
    }

    for fmt in ArchiveFormat::ALL {
        let mut archive_bytes = Vec::new();
        write_archive_to_writer(&bfs, &plan, fmt, &mut archive_bytes).unwrap();
        assert!(!archive_bytes.is_empty());

        if fmt == ArchiveFormat::Zip {
            // Decode with mature `zip` crate
            let mut zip_reader = zip::ZipArchive::new(Cursor::new(&archive_bytes)).unwrap();
            let mut zip_files = BTreeMap::new();
            for i in 0..zip_reader.len() {
                let mut entry = zip_reader.by_index(i).unwrap();
                if entry.is_file() {
                    let mut content = String::new();
                    entry.read_to_string(&mut content).unwrap();
                    zip_files.insert(entry.name().unwrap().to_string(), content);
                }
            }
            assert_eq!(zip_files["bundle/hello.txt"], "Hello Archive!");
            assert_eq!(zip_files["bundle/nested/data.json"], "{\"ok\":true}");

            // Also verify with system `unzip -t`
            let zip_file_path = tmp.path().join("out.zip");
            fs::write(&zip_file_path, &archive_bytes).unwrap();
            let status = Command::new("unzip")
                .arg("-t")
                .arg(&zip_file_path)
                .output()
                .expect("unzip command should run");
            assert!(
                status.status.success(),
                "unzip -t failed: {}",
                String::from_utf8_lossy(&status.stderr)
            );
        } else {
            let decoded = decode_tar_archive_entries(fmt, Cursor::new(&archive_bytes)).unwrap();
            assert_eq!(
                String::from_utf8(decoded["bundle/hello.txt"].clone()).unwrap(),
                "Hello Archive!"
            );
            assert_eq!(
                String::from_utf8(decoded["bundle/nested/data.json"].clone()).unwrap(),
                "{\"ok\":true}"
            );
        }
    }

    // Symlink inside directory must be rejected during archive planning
    let user_root = crate::mcbrowser::derive_user_root_path(tmp.path(), 12).unwrap();
    symlink(
        tmp.path().join("out.zip"),
        user_root.join("bundle/evil_link"),
    )
    .unwrap();
    assert!(matches!(
        collect_archive_plan_with_auth(&bfs, &["bundle".to_string()], |_| Ok(())),
        Err(McBrowserError::Forbidden(_))
    ));
}

#[test]
fn confined_alias_archives_authorize_every_hop_preserve_names_and_pin_all_sources() {
    let temporary = TestTempDir::new();
    let filesystem = open_user_browser_fs_at(temporary.path(), 12).unwrap();
    let root = temporary.path().join("user-12");
    fs::create_dir_all(root.join("storage/sub")).unwrap();
    fs::write(root.join("storage/a.txt"), b"authorized bytes").unwrap();
    fs::write(root.join("private.txt"), b"must not disclose").unwrap();
    symlink("storage", root.join("hop")).unwrap();
    symlink("hop", root.join("alias")).unwrap();
    symlink("alias/a.txt", root.join("leaf.txt")).unwrap();
    symlink("../a.txt", root.join("storage/sub/copied.txt")).unwrap();
    let selection = vec!["alias".to_string(), "leaf.txt".to_string()];
    let mut checked = HashSet::new();
    let plan = collect_archive_plan_with_auth(&filesystem, &selection, |path| {
        checked.insert(path.to_string());
        Ok(())
    })
    .unwrap();
    for path in ["alias", "hop", "storage", "alias/a.txt", "hop/a.txt", "storage/a.txt", "leaf.txt"] {
        assert!(checked.contains(path), "authorization missing for {path}");
    }
    for denied in ["alias", "hop", "storage", "alias/a.txt", "hop/a.txt", "storage/a.txt", "leaf.txt", "alias/sub/copied.txt"] {
        assert!(matches!(
            collect_archive_plan_with_auth(&filesystem, &selection, |path| {
                if path == denied {
                    Err(McBrowserError::Forbidden("denied".to_string()))
                } else {
                    Ok(())
                }
            }),
            Err(McBrowserError::Forbidden(_))
        ), "denial was bypassed for {denied}");
    }
    fs::remove_file(root.join("leaf.txt")).unwrap();
    symlink("private.txt", root.join("leaf.txt")).unwrap();
    fs::remove_file(root.join("hop")).unwrap();
    symlink("missing", root.join("hop")).unwrap();
    fs::write(root.join("replacement"), b"different inode").unwrap();
    fs::rename(root.join("replacement"), root.join("storage/a.txt")).unwrap();

    for format in ArchiveFormat::ALL {
        let mut bytes = Vec::new();
        write_archive_to_writer(&filesystem, &plan, format, &mut bytes).unwrap();
        let decoded = if format == ArchiveFormat::Zip {
            let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
            let mut files = BTreeMap::new();
            for index in 0..archive.len() {
                let mut entry = archive.by_index(index).unwrap();
                if entry.is_file() {
                    let name = entry.name().unwrap().to_string();
                    let mut contents = Vec::new();
                    entry.read_to_end(&mut contents).unwrap();
                    files.insert(name, contents);
                }
            }
            files
        } else {
            decode_tar_archive_entries(format, Cursor::new(bytes)).unwrap()
        };
        assert_eq!(decoded.len(), 3);
        for path in ["alias/a.txt", "alias/sub/copied.txt", "leaf.txt"] {
            assert_eq!(decoded[path], b"authorized bytes", "{format:?}: {path}");
        }
        assert!(decoded.keys().all(|path| !path.starts_with("storage/") && !path.starts_with("hop/")));
    }

    fs::remove_file(root.join("hop")).unwrap();
    symlink("storage", root.join("hop")).unwrap();
    symlink("..", root.join("storage/sub/cycle")).unwrap();
    assert!(matches!(
        collect_archive_plan_with_auth(&filesystem, &["alias".to_string()], |_| Ok(())),
        Err(McBrowserError::Forbidden(_))
    ));
    fs::remove_file(root.join("storage/sub/cycle")).unwrap();
    symlink("../../outside", root.join("storage/escape")).unwrap();
    assert!(matches!(
        collect_archive_plan_with_auth(&filesystem, &["alias".to_string()], |_| Ok(())),
        Err(McBrowserError::Forbidden(_))
    ));
    fs::remove_file(root.join("storage/escape")).unwrap();
    fs::hard_link(root.join("storage/a.txt"), root.join("hardlink")).unwrap();
    assert!(matches!(
        collect_archive_plan_with_auth(&filesystem, &["alias/a.txt".to_string()], |_| Ok(())),
        Err(McBrowserError::Forbidden(_))
    ));
}

#[test]
fn pinned_archive_readers_bound_growth_reject_truncation_and_have_independent_offsets() {
    let temporary = TestTempDir::new();
    let filesystem = open_user_browser_fs_at(temporary.path(), 12).unwrap();
    let source = temporary.path().join("user-12/data.txt");
    fs::write(&source, b"original").unwrap();
    let plan = collect_archive_plan_with_auth(&filesystem, &["data.txt".to_string()], |_| Ok(())).unwrap();
    fs::write(&source, b"original plus appended bytes").unwrap();
    let mut first = open_planned_archive_file(&plan[0]).unwrap();
    let mut second = open_planned_archive_file(&plan[0]).unwrap();
    let mut prefix = [0; 3];
    first.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"ori");
    let mut second_contents = Vec::new();
    second.read_to_end(&mut second_contents).unwrap();
    assert_eq!(second_contents, b"original");
    let mut remaining = Vec::new();
    first.read_to_end(&mut remaining).unwrap();
    assert_eq!(remaining, b"ginal");
    fs::write(&source, b"short").unwrap();
    for format in [ArchiveFormat::Zip, ArchiveFormat::Tar] {
        assert_eq!(
            write_archive_to_writer(&filesystem, &plan, format, Vec::new()).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }
}

#[test]
fn archive_planning_checks_deadlines_cancellation_entry_boundaries_and_late_hardlinks() {
    let temporary = TestTempDir::new();
    let filesystem = open_user_browser_fs_at(temporary.path(), 12).unwrap();
    let root = temporary.path().join("user-12");
    fs::write(root.join("data.txt"), b"original").unwrap();
    let selection = vec!["data.txt".to_string()];
    let mut control = ArchivePlanningControl::new();
    control.deadline = Instant::now();
    assert!(matches!(collect_archive_plan_with_control(&filesystem, &selection, &control, |_| panic!("expired planning reached authorization")), Err(McBrowserError::RequestTimeout(_))));
    let control = ArchivePlanningControl::new();
    let guard = ArchivePlanningGuard(control.clone());
    drop(guard);
    assert!(matches!(collect_archive_plan_with_control(&filesystem, &selection, &control, |_| panic!("cancelled planning reached authorization")), Err(McBrowserError::RequestTimeout(_))));
    let control = ArchivePlanningControl::new();
    let mut guard = Some(ArchivePlanningGuard(control.clone()));
    assert!(matches!(collect_archive_plan_with_control(&filesystem, &selection, &control, |_| {
        drop(guard.take());
        Ok(())
    }), Err(McBrowserError::RequestTimeout(_))));
    let plan = collect_archive_plan_with_auth(&filesystem, &selection, |_| Ok(())).unwrap();
    fs::hard_link(root.join("data.txt"), root.join("late-hardlink.txt")).unwrap();
    for format in ArchiveFormat::ALL {
        assert_eq!(write_archive_to_writer(&filesystem, &plan, format, Vec::new()).unwrap_err().kind(), ErrorKind::PermissionDenied, "{format:?}");
    }
    let limit_selection: Vec<String> = (0..MAX_SEARCH_ENTRIES).map(|index| format!("directory-{index:05}")).collect();
    for path in &limit_selection {
        fs::create_dir(root.join(path)).unwrap();
    }
    let plan = collect_archive_plan_with_auth(&filesystem, &limit_selection, |_| Ok(())).unwrap();
    assert_eq!(plan.len(), MAX_SEARCH_ENTRIES);
    fs::create_dir(root.join(&limit_selection[0]).join("child")).unwrap();
    assert!(matches!(collect_archive_plan_with_auth(&filesystem, &limit_selection, |_| Ok(())), Err(McBrowserError::BadRequest(_))));
}

#[tokio::test]
async fn cancelled_archive_planning_retains_admission_until_the_blocking_worker_exits() {
    let temporary = TestTempDir::new();
    let filesystem = open_user_browser_fs_at(temporary.path(), 12).unwrap();
    fs::write(temporary.path().join("user-12/data.txt"), b"original").unwrap();
    let semaphore = Arc::new(Semaphore::new(1));
    let worker_semaphore = Arc::clone(&semaphore);
    let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::sync_channel::<()>(1);
    let (finished_sender, finished_receiver) = tokio::sync::oneshot::channel();
    let request = tokio::spawn(async move {
        let permit = worker_semaphore.acquire_owned().await.unwrap();
        let control = ArchivePlanningControl::new();
        let _guard = ArchivePlanningGuard(control.clone());
        tokio::task::spawn_blocking(move || {
            let mut started_sender = Some(started_sender);
            let result = collect_archive_plan_with_control(&filesystem, &["data.txt".to_string()], &control, |_| {
                if let Some(sender) = started_sender.take() {
                    sender.send(()).unwrap();
                    release_receiver.recv().unwrap();
                }
                Ok(())
            });
            drop(permit);
            finished_sender.send(matches!(result, Err(McBrowserError::RequestTimeout(_)))).unwrap();
        }).await.unwrap();
    });
    tokio::time::timeout(Duration::from_secs(5), started_receiver).await.unwrap().unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert_eq!(semaphore.available_permits(), 0);
    release_sender.send(()).unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(5), finished_receiver).await.unwrap().unwrap());
    assert_eq!(semaphore.available_permits(), 1);
}

#[tokio::test]
async fn archive_ticket_creation_and_both_download_routes_wait_for_archive_admission() {
    let permit = Arc::clone(&ARCHIVE_SEMAPHORE).acquire_many_owned(ARCHIVE_CONCURRENCY_LIMIT as u32).await.unwrap();
    let user = human_user(12);
    let request = || ArchiveRequest { paths: vec!["data.txt".to_string()], format: "zip".to_string() };
    assert!(tokio::time::timeout(Duration::from_millis(25), create_archive_ticket(Extension(user.clone()), Json(request()))).await.is_err());
    assert!(tokio::time::timeout(Duration::from_millis(25), download_archive(Extension(user.clone()), Json(request()))).await.is_err());
    assert!(tokio::time::timeout(Duration::from_millis(25), download_archive_by_ticket(Extension(user), AxumPath("a".repeat(64)))).await.is_err());
    drop(permit);
}

#[test]
fn zip64_central_directory_and_eocd_preserve_64bit_sizes_and_offsets() {
    let mut cw = CountingWriter::new(Vec::new());
    let large_uncompressed: u64 = (u32::MAX as u64) + 64 * 1024 * 1024;
    let large_compressed: u64 = (u32::MAX as u64) + 123_456;
    let large_offset: u64 = (u32::MAX as u64) + 987_654;

    let records = vec![ZipEntryRecord {
        name_bytes: b"huge.bin".to_vec(),
        version_needed: 45,
        method: 8,
        flags: 0x0808,
        crc32: 0x1234_5678,
        compressed_size: large_compressed,
        uncompressed_size: large_uncompressed,
        local_header_offset: large_offset,
        external_attr: 0o100644u32 << 16,
    }];

    write_zip_central_directory_and_eocd(&mut cw, &records).unwrap();
    let bytes = cw.inner;

    // Central directory header signature 0x02014b50
    assert_eq!(&bytes[0..4], &0x02014b50u32.to_le_bytes());
    // 32-bit fields must be 0xFFFF_FFFF sentinel
    assert_eq!(&bytes[20..24], &u32::MAX.to_le_bytes());
    assert_eq!(&bytes[24..28], &u32::MAX.to_le_bytes());
    assert_eq!(&bytes[42..46], &u32::MAX.to_le_bytes());
    // Extra field length = 28 bytes (header 0x0001 + len 24 + 3x u64)
    let extra_len = u16::from_le_bytes([bytes[30], bytes[31]]) as usize;
    assert_eq!(extra_len, 28);
    let extra_start = 46 + b"huge.bin".len();
    assert_eq!(
        u16::from_le_bytes([bytes[extra_start], bytes[extra_start + 1]]),
        0x0001
    );
    assert_eq!(
        u16::from_le_bytes([bytes[extra_start + 2], bytes[extra_start + 3]]),
        24
    );
    assert_eq!(
        u64::from_le_bytes(bytes[extra_start + 4..extra_start + 12].try_into().unwrap()),
        large_uncompressed
    );
    assert_eq!(
        u64::from_le_bytes(
            bytes[extra_start + 12..extra_start + 20]
                .try_into()
                .unwrap()
        ),
        large_compressed
    );
    assert_eq!(
        u64::from_le_bytes(
            bytes[extra_start + 20..extra_start + 28]
                .try_into()
                .unwrap()
        ),
        large_offset
    );

    // Verify ZIP64 EOCD (0x06064b50) and ZIP64 EOCD Locator (0x07064b50) are emitted before EOCD
    let cd_end = extra_start + extra_len;
    assert_eq!(&bytes[cd_end..cd_end + 4], &0x06064b50u32.to_le_bytes());
    assert_eq!(
        &bytes[cd_end + 56..cd_end + 60],
        &0x07064b50u32.to_le_bytes()
    );
    assert_eq!(
        &bytes[cd_end + 76..cd_end + 80],
        &0x06054b50u32.to_le_bytes()
    );
}

#[test]
fn archive_tickets_enforce_ownership_jti_expiry_capacity_scope_and_live_reauth() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 21).unwrap();
    let conn = setup_quota_db(21, 1_000_000, 0);

    bfs.create_directory_all("docs/sub").unwrap();
    execute_create_file_conn(&conn, &bfs, "docs/readme.txt", Some("doc1"), 21).unwrap();
    execute_create_file_conn(&conn, &bfs, "docs/sub/secret.txt", Some("doc2"), 21).unwrap();

    let store = ArchiveTicketStore::new(MAX_ARCHIVE_TICKETS, ARCHIVE_TICKET_TTL);
    let now = Instant::now();
    let user21 = human_user(21);

    // 1. Issue ticket and verify URL + filename
    let (ticket1, resp1) = store
        .issue_at(
            &user21,
            "workspace".to_string(),
            vec!["docs".to_string()],
            ArchiveFormat::TarZst,
            now,
        )
        .unwrap();
    assert_eq!(ticket1.len(), 64);
    assert_eq!(
        resp1.url,
        format!("/api/v1/auth/mcbrowser/archive/{ticket1}")
    );
    assert_eq!(resp1.filename, "docs.tar.zst");

    // 2. Wrong user cannot redeem ticket (and ticket is consumed on attempt)
    let user22 = human_user(22);
    assert!(matches!(
        store.redeem_at(&ticket1, &user22, "workspace", now),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        store.redeem_at(&ticket1, &user21, "workspace", now),
        Err(McBrowserError::NotFound(_))
    ));

    // 3. Different session JTI for same user is rejected
    let (ticket_jti, _) = store
        .issue_at(
            &user21,
            "workspace".to_string(),
            vec!["docs".to_string()],
            ArchiveFormat::Zip,
            now,
        )
        .unwrap();
    let mut rotated_session_user = user21.clone();
    rotated_session_user.jti = "jti-21-rotated".to_string();
    assert!(matches!(
        store.redeem_at(&ticket_jti, &rotated_session_user, "workspace", now),
        Err(McBrowserError::Forbidden(_))
    ));

    // 4. Scope change between ticket issue and GET redemption is rejected (no scope remap)
    let (ticket_scope, _) = store
        .issue_at(
            &user21,
            "workspace/team-a".to_string(),
            vec!["docs".to_string()],
            ArchiveFormat::TarGz,
            now,
        )
        .unwrap();
    assert!(matches!(
        store.redeem_at(&ticket_scope, &user21, "workspace/team-b", now),
        Err(McBrowserError::Forbidden(_))
    ));

    // 5. Expiry after 60s cleans up and rejects expired ticket
    let (ticket_exp, _) = store
        .issue_at(
            &user21,
            "workspace".to_string(),
            vec!["docs".to_string()],
            ArchiveFormat::Tar,
            now,
        )
        .unwrap();
    let after_ttl = now + ARCHIVE_TICKET_TTL + Duration::from_secs(1);
    assert!(matches!(
        store.redeem_at(&ticket_exp, &user21, "workspace", after_ttl),
        Err(McBrowserError::NotFound(_))
    ));
    assert_eq!(store.active_len_at(after_ttl), 0);

    // 6. Capacity bound (max 256 active tickets) fails truthfully and recovers after expiry
    for _ in 0..MAX_ARCHIVE_TICKETS {
        store
            .issue_at(
                &user21,
                "workspace".to_string(),
                vec!["docs".to_string()],
                ArchiveFormat::Zip,
                after_ttl,
            )
            .unwrap();
    }
    assert_eq!(store.active_len_at(after_ttl), MAX_ARCHIVE_TICKETS);
    assert!(matches!(
        store.issue_at(
            &user21,
            "workspace".to_string(),
            vec!["docs".to_string()],
            ArchiveFormat::Zip,
            after_ttl,
        ),
        Err(McBrowserError::Conflict(_))
    ));

    let after_second_ttl = after_ttl + ARCHIVE_TICKET_TTL + Duration::from_secs(1);
    let (ticket_live, _) = store
        .issue_at(
            &user21,
            "workspace".to_string(),
            vec!["docs".to_string()],
            ArchiveFormat::TarLz4,
            after_second_ttl,
        )
        .unwrap();

    // 7. Live reauthorization at GET time rejects if descendant path became denied after issue
    let live_denied = redeem_and_plan_archive_ticket_with(
        &store,
        &ticket_live,
        &user21,
        after_second_ttl,
        |_| Ok("workspace".to_string()),
        |uid| open_user_browser_fs_at(tmp.path(), uid),
        |path| {
            if path == "docs/sub/secret.txt" {
                return Err(McBrowserError::Forbidden(
                    "Descendant revoked before GET download".to_string(),
                ));
            }
            Ok(())
        },
    );
    assert!(matches!(live_denied, Err(McBrowserError::Forbidden(_))));
    // Ticket was single-use and is now gone
    assert!(matches!(
        store.redeem_at(&ticket_live, &user21, "workspace", after_second_ttl),
        Err(McBrowserError::NotFound(_))
    ));

    // 8. Successful redemption + single-use enforcement
    let (ticket_ok, _) = store
        .issue_at(
            &user21,
            "workspace".to_string(),
            vec!["docs".to_string()],
            ArchiveFormat::TarBr,
            after_second_ttl,
        )
        .unwrap();
    let (redeemed, bfs_live, plan_live) = redeem_and_plan_archive_ticket_with(
        &store,
        &ticket_ok,
        &user21,
        after_second_ttl,
        |_| Ok("workspace".to_string()),
        |uid| open_user_browser_fs_at(tmp.path(), uid),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(redeemed.format, ArchiveFormat::TarBr);
    assert_eq!(plan_live.len(), 4);

    let mut out_br = Vec::new();
    write_archive_to_writer(&bfs_live, &plan_live, redeemed.format, &mut out_br).unwrap();
    let decoded = decode_tar_archive_entries(ArchiveFormat::TarBr, Cursor::new(out_br)).unwrap();
    assert_eq!(decoded["docs/readme.txt"], b"doc1");
    assert_eq!(decoded["docs/sub/secret.txt"], b"doc2");

    // Second redemption of the same ticket fails with 404 NotFound
    assert!(matches!(
        store.redeem_at(&ticket_ok, &user21, "workspace", after_second_ttl),
        Err(McBrowserError::NotFound(_))
    ));
}

#[test]
fn archive_stream_cancellation_stops_writer_and_directory_info_counts_entries() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 33).unwrap();
    let conn = setup_quota_db(33, 10_000_000, 0);

    bfs.create_directory_all("tree/sub1").unwrap();
    bfs.create_directory_all("tree/sub2").unwrap();
    let big_payload = "ABCD".repeat(64 * 1024); // 256 KiB per file
    execute_create_file_conn(&conn, &bfs, "tree/f1.txt", Some(&big_payload), 33).unwrap();
    execute_create_file_conn(&conn, &bfs, "tree/f2.txt", Some(&big_payload), 33).unwrap();
    execute_create_file_conn(&conn, &bfs, "tree/hidden.txt", Some("secret"), 33).unwrap();

    // Verify directory `num_files` and `num_dirs` in `InfoResponse` with policy visibility filtering
    let dir_info =
        collect_entry_info_with_auth(&bfs, "tree", &[], |path, _is_dir| path != "tree/hidden.txt")
            .unwrap();
    assert_eq!(dir_info.entry.kind, "directory");
    assert_eq!(dir_info.num_files, Some(2));
    assert_eq!(dir_info.num_dirs, Some(2));

    let file_info = collect_entry_info_with_auth(
        &bfs,
        "tree/hidden.txt",
        &[ChecksumAlgorithm::Md5, ChecksumAlgorithm::Sha256],
        |_, _| true,
    )
    .unwrap();
    assert_eq!(file_info.entry.kind, "file");
    assert_eq!(file_info.num_files, None);
    assert_eq!(file_info.num_dirs, None);
    assert_eq!(
        file_info.checksums["md5"],
        "5ebe2294ecd0e0f08eab7690d2a6ee69"
    );

    // Verify stream cancellation aborts ChannelChunkWriter with BrokenPipe when receiver is dropped
    let plan = collect_archive_plan_with_auth(&bfs, &["tree".to_string()], |_| Ok(())).unwrap();
    let (tx, mut rx) = mpsc::channel::<Result<Bytes, io::Error>>(1);
    let handle = std::thread::spawn(move || {
        let writer = ChannelChunkWriter::new(tx);
        write_archive_to_writer(&bfs, &plan, ArchiveFormat::Tar, writer)
    });

    let first_chunk = rx.blocking_recv().unwrap().unwrap();
    assert_eq!(first_chunk.len(), ARCHIVE_CHUNK_BYTES);
    drop(rx);

    let writer_res = handle.join().unwrap();
    assert!(writer_res.is_err());
    assert_eq!(writer_res.unwrap_err().kind(), ErrorKind::BrokenPipe);
}

#[test]
fn version_suffix_formatting_and_conflict_policy_parsing_match_upstream_parity() {
    assert_eq!(
        format_version_suffix_candidate("note.txt", 1),
        "note(1).txt"
    );
    assert_eq!(
        format_version_suffix_candidate("docs/note.txt", 2),
        "docs/note(2).txt"
    );
    assert_eq!(
        format_version_suffix_candidate(".gitignore", 1),
        "(1).gitignore"
    );
    assert_eq!(
        format_version_suffix_candidate("dir/.env", 3),
        "dir/(3).env"
    );
    assert_eq!(
        format_version_suffix_candidate("archive.tar.gz", 1),
        "archive.tar(1).gz"
    );
    assert_eq!(format_version_suffix_candidate("README", 1), "README(1)");

    assert_eq!(
        OperationConflictPolicy::parse("error").unwrap(),
        OperationConflictPolicy::Error
    );
    assert_eq!(
        OperationConflictPolicy::parse("overwrite").unwrap(),
        OperationConflictPolicy::Overwrite
    );
    assert_eq!(
        OperationConflictPolicy::parse("override").unwrap(),
        OperationConflictPolicy::Overwrite
    );
    assert_eq!(
        OperationConflictPolicy::parse("replace").unwrap(),
        OperationConflictPolicy::Overwrite
    );
    assert_eq!(
        OperationConflictPolicy::parse("keep-both").unwrap(),
        OperationConflictPolicy::KeepBoth
    );
    assert_eq!(
        OperationConflictPolicy::parse("rename").unwrap(),
        OperationConflictPolicy::KeepBoth
    );
    assert!(OperationConflictPolicy::parse("invalid").is_err());

    assert_eq!(
        resolve_operation_conflict_policy(None, None, None).unwrap(),
        OperationConflictPolicy::Error
    );
    assert_eq!(
        resolve_operation_conflict_policy(None, Some(true), Some(false)).unwrap(),
        OperationConflictPolicy::Overwrite
    );
    assert_eq!(
        resolve_operation_conflict_policy(None, Some(false), Some(true)).unwrap(),
        OperationConflictPolicy::KeepBoth
    );
    assert!(resolve_operation_conflict_policy(None, Some(true), Some(true)).is_err());
    assert!(resolve_operation_conflict_policy(
        Some(OperationConflictPolicy::Overwrite),
        Some(false),
        None
    )
    .is_err());
}

#[test]
fn same_folder_keep_both_copy_and_move_allocate_distinct_authorized_destinations() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 44).unwrap();
    let conn = setup_quota_db(44, 200, 0);
    conn.execute_batch("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';")
        .unwrap();
    let user = human_user(44);
    execute_create_file_conn(&conn, &bfs, "note.txt", Some("original"), 44).unwrap();
    for conflict in [
        OperationConflictPolicy::Error,
        OperationConflictPolicy::Overwrite,
    ] {
        assert!(execute_copy_for_user_with_conn(
            &conn, &bfs, &user, "note.txt", "note.txt", conflict
        )
        .is_err());
        assert!(execute_rename_for_user_with_conn(
            &conn, &bfs, &user, "note.txt", "note.txt", conflict
        )
        .is_err());
    }
    let copied = execute_copy_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "note.txt",
        "note.txt",
        OperationConflictPolicy::KeepBoth,
    )
    .unwrap();
    assert_eq!(copied, "note(1).txt");
    assert_eq!(read_used_bytes(&conn, 44), 16);
    let moved = execute_rename_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "note.txt",
        "note.txt",
        OperationConflictPolicy::KeepBoth,
    )
    .unwrap();
    assert_eq!(moved, "note(2).txt");
    assert!(bfs.metadata("note.txt").is_err());
    assert!(bfs.metadata("note(1).txt").is_ok());
    assert!(bfs.metadata("note(2).txt").is_ok());
    assert_eq!(read_used_bytes(&conn, 44), 16);
    bfs.create_directory("folder").unwrap();
    assert!(execute_copy_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "folder",
        "folder/nested",
        OperationConflictPolicy::KeepBoth
    )
    .is_err());
}

#[test]
fn copy_conflict_policies_enforce_overwrite_keep_both_quota_and_policy_rules() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 44).unwrap();
    let conn = setup_quota_db(44, 200, 0);
    conn.execute_batch(
        "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';
         INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin');",
    )
    .unwrap();
    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "jti-admin".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let user = human_user(44);

    execute_create_file_conn(&conn, &bfs, "src.txt", Some("0123456789"), 44).unwrap();
    execute_create_file_conn(&conn, &bfs, "dst.txt", Some("abcd"), 44).unwrap();
    assert_eq!(read_used_bytes(&conn, 44), 14);

    assert!(matches!(
        execute_copy_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "src.txt",
            "dst.txt",
            OperationConflictPolicy::Error,
        ),
        Err(McBrowserError::Conflict(_))
    ));
    assert_eq!(read_used_bytes(&conn, 44), 14);

    let keep_first = execute_copy_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "src.txt",
        "dst.txt",
        OperationConflictPolicy::KeepBoth,
    )
    .unwrap();
    assert_eq!(keep_first, "dst(1).txt");
    assert_eq!(read_used_bytes(&conn, 44), 24);

    let keep_second = execute_copy_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "src.txt",
        "dst.txt",
        OperationConflictPolicy::KeepBoth,
    )
    .unwrap();
    assert_eq!(keep_second, "dst(2).txt");
    assert_eq!(read_used_bytes(&conn, 44), 34);

    let mut no_modify_policy = crate::mcbrowser::policy::PolicyDocument::default();
    no_modify_policy.permissions.modify = false;
    crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 44, no_modify_policy).unwrap();
    assert!(matches!(
        execute_copy_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "src.txt",
            "dst.txt",
            OperationConflictPolicy::Overwrite,
        ),
        Err(McBrowserError::Forbidden(_))
    ));
    let (dst_doc, _) =
        read_utf8_editor_content_from_file(bfs.open_file("dst.txt").unwrap(), "dst.txt".into())
            .unwrap();
    assert_eq!(dst_doc.content, "abcd");

    crate::mcbrowser::policy::save_user_policy_conn(
        &conn,
        &admin,
        44,
        crate::mcbrowser::policy::PolicyDocument::default(),
    )
    .unwrap();

    let overwritten = execute_copy_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "src.txt",
        "dst.txt",
        OperationConflictPolicy::Overwrite,
    )
    .unwrap();
    assert_eq!(overwritten, "dst.txt");
    assert_eq!(read_used_bytes(&conn, 44), 40);

    execute_create_file_conn(&conn, &bfs, "short.txt", Some("xy"), 44).unwrap();
    assert_eq!(read_used_bytes(&conn, 44), 42);
    execute_copy_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "short.txt",
        "dst.txt",
        OperationConflictPolicy::Overwrite,
    )
    .unwrap();
    assert_eq!(read_used_bytes(&conn, 44), 34);

    bfs.create_directory_all("dir_src/sub").unwrap();
    bfs.create_directory_all("dir_dst/sub").unwrap();
    execute_create_file_conn(&conn, &bfs, "dir_src/sub/item.txt", Some("new-value-9"), 44).unwrap();
    execute_create_file_conn(&conn, &bfs, "dir_dst/sub/item.txt", Some("old-7!!"), 44).unwrap();
    execute_create_file_conn(&conn, &bfs, "dir_dst/keep.txt", Some("untouched"), 44).unwrap();
    let used_before_merge = read_used_bytes(&conn, 44);

    execute_copy_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "dir_src",
        "dir_dst",
        OperationConflictPolicy::Overwrite,
    )
    .unwrap();
    assert_eq!(read_used_bytes(&conn, 44), used_before_merge + 4);
    let (merged_doc, _) = read_utf8_editor_content_from_file(
        bfs.open_file("dir_dst/sub/item.txt").unwrap(),
        "dir_dst/sub/item.txt".into(),
    )
    .unwrap();
    assert_eq!(merged_doc.content, "new-value-9");
    let (preserved_doc, _) = read_utf8_editor_content_from_file(
        bfs.open_file("dir_dst/keep.txt").unwrap(),
        "dir_dst/keep.txt".into(),
    )
    .unwrap();
    assert_eq!(preserved_doc.content, "untouched");
}

#[test]
fn rename_conflict_policies_enforce_overwrite_keep_both_symlink_target_policy_and_quota() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 55).unwrap();
    let conn = setup_quota_db(55, 500, 0);
    conn.execute_batch(
        "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';
         INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin');",
    )
    .unwrap();
    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "jti-admin".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let user = human_user(55);

    execute_create_file_conn(&conn, &bfs, "alpha.txt", Some("ten-bytes!"), 55).unwrap();
    execute_create_file_conn(&conn, &bfs, "beta.txt", Some("four"), 55).unwrap();
    assert_eq!(read_used_bytes(&conn, 55), 14);

    assert!(matches!(
        execute_rename_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "alpha.txt",
            "beta.txt",
            OperationConflictPolicy::Error,
        ),
        Err(McBrowserError::Conflict(_))
    ));

    execute_create_file_conn(&conn, &bfs, ".gitignore", Some("node_modules"), 55).unwrap();
    execute_create_file_conn(&conn, &bfs, "other_ignore", Some("target"), 55).unwrap();
    let renamed_dotfile = execute_rename_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "other_ignore",
        ".gitignore",
        OperationConflictPolicy::KeepBoth,
    )
    .unwrap();
    assert_eq!(renamed_dotfile, "(1).gitignore");
    assert!(bfs.metadata("(1).gitignore").is_ok());

    let mut no_modify_policy = crate::mcbrowser::policy::PolicyDocument::default();
    no_modify_policy.permissions.modify = false;
    crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 55, no_modify_policy).unwrap();
    assert!(matches!(
        execute_rename_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "alpha.txt",
            "beta.txt",
            OperationConflictPolicy::Overwrite,
        ),
        Err(McBrowserError::Forbidden(_))
    ));

    crate::mcbrowser::policy::save_user_policy_conn(
        &conn,
        &admin,
        55,
        crate::mcbrowser::policy::PolicyDocument::default(),
    )
    .unwrap();

    let used_before_overwrite = read_used_bytes(&conn, 55);
    let overwritten_path = execute_rename_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "alpha.txt",
        "beta.txt",
        OperationConflictPolicy::Overwrite,
    )
    .unwrap();
    assert_eq!(overwritten_path, "beta.txt");
    assert!(bfs.metadata("alpha.txt").is_err());
    assert_eq!(read_used_bytes(&conn, 55), used_before_overwrite - 4);
    let (beta_doc, _) =
        read_utf8_editor_content_from_file(bfs.open_file("beta.txt").unwrap(), "beta.txt".into())
            .unwrap();
    assert_eq!(beta_doc.content, "ten-bytes!");

    bfs.create_directory_all("secret").unwrap();
    bfs.create_directory_all("public").unwrap();
    execute_create_file_conn(&conn, &bfs, "secret/classified.txt", Some("top-secret"), 55).unwrap();
    let user_root = crate::mcbrowser::derive_user_root_path(tmp.path(), 55).unwrap();
    symlink(
        "../secret/classified.txt",
        user_root.join("public/alias_link"),
    )
    .unwrap();

    let mut deny_secret_policy = crate::mcbrowser::policy::PolicyDocument::default();
    deny_secret_policy
        .rules
        .push(crate::mcbrowser::policy::PathRule {
            path: "secret".to_string(),
            allow: false,
            regex: false,
            regexp: None,
        });
    crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 55, deny_secret_policy).unwrap();

    assert!(matches!(
        execute_rename_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "public/alias_link",
            "public/renamed_link",
            OperationConflictPolicy::Error,
        ),
        Err(McBrowserError::Forbidden(_))
    ));

    crate::mcbrowser::policy::save_user_policy_conn(
        &conn,
        &admin,
        55,
        crate::mcbrowser::policy::PolicyDocument::default(),
    )
    .unwrap();
    let renamed_link = execute_rename_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "public/alias_link",
        "public/renamed_link",
        OperationConflictPolicy::Error,
    )
    .unwrap();
    assert_eq!(renamed_link, "public/renamed_link");
}

#[test]
fn editor_content_get_and_put_follow_confined_internal_aliases_preserve_links_and_enforce_policy_etag_quota_and_races(
) {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 66).unwrap();
    let conn = setup_quota_db(66, 30, 0);
    conn.execute_batch(
        "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';
         INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin');",
    )
    .unwrap();
    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "jti-admin".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let user = human_user(66);
    let user_root = crate::mcbrowser::derive_user_root_path(tmp.path(), 66).unwrap();

    bfs.create_directory_all("docs").unwrap();
    bfs.create_directory_all("chain").unwrap();
    bfs.create_directory_all("secret").unwrap();
    execute_create_file_conn(&conn, &bfs, "docs/target.txt", Some("hello"), 66).unwrap();
    execute_create_file_conn(&conn, &bfs, "secret/classified.txt", Some("classified"), 66).unwrap();
    assert_eq!(read_used_bytes(&conn, 66), 15);

    symlink("docs/target.txt", user_root.join("leaf-alias.txt")).unwrap();
    symlink("docs", user_root.join("dir-alias")).unwrap();
    symlink("../dir-alias/target.txt", user_root.join("chain/hop.txt")).unwrap();

    assert!(matches!(
        execute_put_content_conn(&conn, &bfs, "leaf-alias.txt", "blocked", "\"etag\"", 66),
        Err(McBrowserError::Forbidden(_))
    ));

    let leaf_doc =
        execute_get_content_for_user_with_conn(&conn, &bfs, &user, "leaf-alias.txt").unwrap();
    assert_eq!(leaf_doc.path, "leaf-alias.txt");
    assert_eq!(leaf_doc.content, "hello");

    let dir_doc =
        execute_get_content_for_user_with_conn(&conn, &bfs, &user, "dir-alias/target.txt").unwrap();
    assert_eq!(dir_doc.path, "dir-alias/target.txt");
    assert_eq!(dir_doc.content, "hello");
    assert_eq!(dir_doc.etag, leaf_doc.etag);

    let hop_doc =
        execute_get_content_for_user_with_conn(&conn, &bfs, &user, "chain/hop.txt").unwrap();
    assert_eq!(hop_doc.path, "chain/hop.txt");
    assert_eq!(hop_doc.content, "hello");

    let (saved_leaf, leaf_delta) = execute_put_content_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "leaf-alias.txt",
        "hello world",
        &leaf_doc.etag,
    )
    .unwrap();
    assert!(saved_leaf.success);
    assert_eq!(leaf_delta, 6);
    assert_eq!(read_used_bytes(&conn, 66), 21);
    assert!(fs::symlink_metadata(user_root.join("leaf-alias.txt"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read_link(user_root.join("leaf-alias.txt")).unwrap(),
        std::path::PathBuf::from("docs/target.txt")
    );
    assert_eq!(
        fs::read_to_string(user_root.join("docs/target.txt")).unwrap(),
        "hello world"
    );

    assert!(matches!(
        execute_put_content_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "dir-alias/target.txt",
            "stale",
            &leaf_doc.etag,
        ),
        Err(McBrowserError::Conflict(_))
    ));
    assert_eq!(read_used_bytes(&conn, 66), 21);

    assert!(matches!(
        execute_put_content_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "dir-alias/target.txt",
            "012345678901234567890",
            &saved_leaf.etag,
        ),
        Err(McBrowserError::QuotaExceeded(_))
    ));
    assert_eq!(read_used_bytes(&conn, 66), 21);
    assert_eq!(
        fs::read_to_string(user_root.join("docs/target.txt")).unwrap(),
        "hello world"
    );

    let (saved_shrink, shrink_delta) = execute_put_content_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "chain/hop.txt",
        "hi",
        &saved_leaf.etag,
    )
    .unwrap();
    assert!(saved_shrink.success);
    assert_eq!(shrink_delta, -9);
    assert_eq!(read_used_bytes(&conn, 66), 12);
    assert!(fs::symlink_metadata(user_root.join("chain/hop.txt"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(fs::symlink_metadata(user_root.join("dir-alias"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read_to_string(user_root.join("docs/target.txt")).unwrap(),
        "hi"
    );

    for denied_path in ["chain/hop.txt", "dir-alias", "docs/target.txt"] {
        let mut policy = crate::mcbrowser::policy::PolicyDocument::default();
        policy.rules.push(crate::mcbrowser::policy::PathRule {
            path: denied_path.to_string(),
            allow: false,
            regex: false,
            regexp: None,
        });
        crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 66, policy).unwrap();

        assert!(matches!(
            execute_get_content_for_user_with_conn(&conn, &bfs, &user, "chain/hop.txt"),
            Err(McBrowserError::Forbidden(_))
        ));
        assert!(matches!(
            execute_put_content_for_user_with_conn(
                &conn,
                &bfs,
                &user,
                "chain/hop.txt",
                "denied",
                &saved_shrink.etag,
            ),
            Err(McBrowserError::Forbidden(_))
        ));
    }

    let mut no_modify_policy = crate::mcbrowser::policy::PolicyDocument::default();
    no_modify_policy.permissions.modify = false;
    crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 66, no_modify_policy).unwrap();
    assert!(execute_get_content_for_user_with_conn(&conn, &bfs, &user, "leaf-alias.txt").is_ok());
    assert!(matches!(
        execute_put_content_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "leaf-alias.txt",
            "denied",
            &saved_shrink.etag,
        ),
        Err(McBrowserError::Forbidden(_))
    ));

    crate::mcbrowser::policy::save_user_policy_conn(
        &conn,
        &admin,
        66,
        crate::mcbrowser::policy::PolicyDocument::default(),
    )
    .unwrap();

    let outside = tmp.path().join("outside.txt");
    fs::write(&outside, "outside").unwrap();
    symlink(&outside, user_root.join("escape-alias.txt")).unwrap();
    symlink("missing.txt", user_root.join("broken-alias.txt")).unwrap();
    symlink("loop-b.txt", user_root.join("loop-a.txt")).unwrap();
    symlink("loop-a.txt", user_root.join("loop-b.txt")).unwrap();

    assert!(matches!(
        execute_get_content_for_user_with_conn(&conn, &bfs, &user, "dir-alias"),
        Err(McBrowserError::BadRequest(_))
    ));
    assert!(matches!(
        execute_put_content_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "dir-alias",
            "x",
            &saved_shrink.etag
        ),
        Err(McBrowserError::BadRequest(_))
    ));
    assert!(matches!(
        execute_get_content_for_user_with_conn(&conn, &bfs, &user, "broken-alias.txt"),
        Err(McBrowserError::NotFound(_))
    ));
    assert!(matches!(
        execute_put_content_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "broken-alias.txt",
            "x",
            &saved_shrink.etag,
        ),
        Err(McBrowserError::NotFound(_))
    ));
    for invalid_alias in ["escape-alias.txt", "loop-a.txt"] {
        assert!(matches!(
            execute_get_content_for_user_with_conn(&conn, &bfs, &user, invalid_alias),
            Err(McBrowserError::Forbidden(_))
        ));
        assert!(matches!(
            execute_put_content_for_user_with_conn(
                &conn,
                &bfs,
                &user,
                invalid_alias,
                "x",
                &saved_shrink.etag,
            ),
            Err(McBrowserError::Forbidden(_))
        ));
    }

    fs::hard_link(
        user_root.join("docs/target.txt"),
        user_root.join("docs/hardlink.txt"),
    )
    .unwrap();
    assert!(matches!(
        execute_get_content_for_user_with_conn(&conn, &bfs, &user, "leaf-alias.txt"),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        execute_put_content_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "leaf-alias.txt",
            "x",
            &saved_shrink.etag,
        ),
        Err(McBrowserError::Forbidden(_))
    ));
    fs::remove_file(user_root.join("docs/hardlink.txt")).unwrap();

    let mut deny_secret = crate::mcbrowser::policy::PolicyDocument::default();
    deny_secret.rules.push(crate::mcbrowser::policy::PathRule {
        path: "secret".to_string(),
        allow: false,
        regex: false,
        regexp: None,
    });
    crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 66, deny_secret).unwrap();

    let (pinned_file, pinned_resolved_path) =
        open_authorized_file_for_put_content_with_conn(&conn, &user, &bfs, "leaf-alias.txt")
            .unwrap();
    assert_eq!(pinned_resolved_path, "docs/target.txt");
    let (pinned_doc, pinned_expected_file) =
        read_utf8_editor_content_from_file(pinned_file, pinned_resolved_path.clone()).unwrap();

    fs::remove_file(user_root.join("leaf-alias.txt")).unwrap();
    symlink("secret/classified.txt", user_root.join("leaf-alias.txt")).unwrap();

    let (retarget_resp, retarget_delta) = execute_put_content_with_loaded_target_conn(
        &conn,
        &bfs,
        &pinned_resolved_path,
        &pinned_doc,
        &pinned_expected_file,
        "pinned-update",
        &pinned_doc.etag,
        66,
    )
    .unwrap();
    assert!(retarget_resp.success);
    assert_eq!(retarget_delta, 11);
    assert_eq!(
        fs::read_to_string(user_root.join("docs/target.txt")).unwrap(),
        "pinned-update"
    );
    assert_eq!(
        fs::read_to_string(user_root.join("secret/classified.txt")).unwrap(),
        "classified"
    );

    fs::remove_file(user_root.join("leaf-alias.txt")).unwrap();
    symlink("docs/target.txt", user_root.join("leaf-alias.txt")).unwrap();

    let (race_file, race_resolved_path) =
        open_authorized_file_for_put_content_with_conn(&conn, &user, &bfs, "leaf-alias.txt")
            .unwrap();
    let (race_doc, race_expected_file) =
        read_utf8_editor_content_from_file(race_file, race_resolved_path.clone()).unwrap();
    let used_before_race = read_used_bytes(&conn, 66);

    fs::remove_file(user_root.join("docs/target.txt")).unwrap();
    fs::write(user_root.join("docs/target.txt"), "concurrent-replacement").unwrap();

    assert!(matches!(
        execute_put_content_with_loaded_target_conn(
            &conn,
            &bfs,
            &race_resolved_path,
            &race_doc,
            &race_expected_file,
            "should-not-overwrite",
            &race_doc.etag,
            66,
        ),
        Err(McBrowserError::Conflict(_))
    ));
    assert_eq!(read_used_bytes(&conn, 66), used_before_race);
    assert_eq!(
        fs::read_to_string(user_root.join("docs/target.txt")).unwrap(),
        "concurrent-replacement"
    );
}

#[test]
fn delete_recursive_accounting_outcomes_and_partial_removal_reconciliation() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 77).unwrap();
    let conn = setup_quota_db(77, 1000, 0);
    let user_root = crate::mcbrowser::derive_user_root_path(tmp.path(), 77).unwrap();

    bfs.create_directory_all("tree_full/sub").unwrap();
    execute_create_file_conn(&conn, &bfs, "tree_full/a.txt", Some("12345"), 77).unwrap();
    execute_create_file_conn(&conn, &bfs, "tree_full/sub/b.txt", Some("0123456789"), 77).unwrap();

    bfs.create_directory_all("tree_legacy").unwrap();
    execute_create_file_conn(&conn, &bfs, "tree_legacy/c.txt", Some("abcd"), 77).unwrap();

    bfs.create_directory_all("tree_partial").unwrap();
    execute_create_file_conn(&conn, &bfs, "tree_partial/removed.txt", Some("seven!!"), 77).unwrap();
    symlink("missing.txt", user_root.join("tree_partial/blocked_link")).unwrap();
    assert_eq!(read_used_bytes(&conn, 77), 26);

    conn.execute_batch(
        "CREATE TRIGGER reject_delete_quota_release BEFORE UPDATE ON user_quotas
         WHEN NEW.used_bytes < OLD.used_bytes
         BEGIN SELECT RAISE(ABORT, 'injected delete quota release failure'); END;",
    )
    .unwrap();

    let full_outcome =
        execute_delete_recursive_with_outcome_conn(&conn, &bfs, "tree_full", 77).unwrap();
    assert_eq!(
        full_outcome,
        DeleteRecursiveOutcome {
            removed_bytes: 15,
            accounting_pending: true,
        }
    );
    assert!(bfs.metadata("tree_full").is_err());
    assert_eq!(read_used_bytes(&conn, 77), 26);

    execute_delete_recursive_conn(&conn, &bfs, "tree_legacy", 77).unwrap();
    assert!(bfs.metadata("tree_legacy").is_err());
    assert_eq!(read_used_bytes(&conn, 77), 26);

    let partial_release_err =
        execute_delete_recursive_with_outcome_conn(&conn, &bfs, "tree_partial", 77);
    assert!(matches!(
        partial_release_err,
        Err(McBrowserError::AccountingPending(_))
    ));
    assert!(bfs.metadata("tree_partial/removed.txt").is_err());
    assert!(bfs.metadata("tree_partial").is_ok());
    assert_eq!(read_used_bytes(&conn, 77), 26);

    conn.execute_batch("DROP TRIGGER reject_delete_quota_release;")
        .unwrap();
    execute_create_file_conn(&conn, &bfs, "tree_partial/second.txt", Some("six!!!"), 77).unwrap();
    assert_eq!(read_used_bytes(&conn, 77), 32);

    let partial_honest_err = execute_delete_recursive_conn(&conn, &bfs, "tree_partial", 77);
    assert!(matches!(
        partial_honest_err,
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(bfs.metadata("tree_partial/second.txt").is_err());
    assert!(bfs.metadata("tree_partial").is_ok());
    assert_eq!(read_used_bytes(&conn, 77), 26);
}

#[test]
fn confined_alias_and_recursive_directory_copy_pin_sources_enforce_policy_hops_and_reject_cycles_and_escapes(
) {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 88).unwrap();
    let conn = setup_quota_db(88, 1000, 0);
    conn.execute_batch(
        "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';
         INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin');",
    )
    .unwrap();
    let admin = AuthUser {
        user_id: 1,
        username: "admin".to_string(),
        role: "admin".to_string(),
        jti: "jti-admin".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    };
    let user = human_user(88);
    let user_root = crate::mcbrowser::derive_user_root_path(tmp.path(), 88).unwrap();

    bfs.create_directory_all("real_dir/sub").unwrap();
    bfs.create_directory_all("normal_dir/nested").unwrap();
    bfs.create_directory_all("secret_dir").unwrap();
    execute_create_file_conn(&conn, &bfs, "real_dir/target.txt", Some("hello-target"), 88).unwrap();
    execute_create_file_conn(&conn, &bfs, "real_dir/sub/inner.txt", Some("inner-val"), 88).unwrap();
    execute_create_file_conn(&conn, &bfs, "normal_dir/plain.txt", Some("plain"), 88).unwrap();
    execute_create_file_conn(&conn, &bfs, "secret_dir/secret.txt", Some("top-secret-data"), 88)
        .unwrap();
    assert_eq!(read_used_bytes(&conn, 88), 41);

    symlink("real_dir/target.txt", user_root.join("file_alias.txt")).unwrap();
    symlink("real_dir", user_root.join("dir_hop")).unwrap();
    symlink("dir_hop", user_root.join("dir_alias")).unwrap();
    symlink(
        "../../real_dir/target.txt",
        user_root.join("normal_dir/nested/link_to_target.txt"),
    )
    .unwrap();
    symlink("../real_dir/sub", user_root.join("normal_dir/link_to_sub")).unwrap();

    let mut accounting_complete = true;
    let copied_file_alias = execute_copy_for_user_with_accounting_conn(
        &conn,
        &bfs,
        &user,
        "file_alias.txt",
        "copied_from_alias.txt",
        OperationConflictPolicy::Error,
        &mut accounting_complete,
    )
    .unwrap();
    assert_eq!(copied_file_alias, "copied_from_alias.txt");
    assert!(accounting_complete);
    assert!(
        !fs::symlink_metadata(user_root.join("copied_from_alias.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_to_string(user_root.join("copied_from_alias.txt")).unwrap(),
        "hello-target"
    );
    assert_eq!(read_used_bytes(&conn, 88), 53);

    let keep_both_alias = execute_copy_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "file_alias.txt",
        "copied_from_alias.txt",
        OperationConflictPolicy::KeepBoth,
    )
    .unwrap();
    assert_eq!(keep_both_alias, "copied_from_alias(1).txt");
    assert_eq!(read_used_bytes(&conn, 88), 65);

    let copied_dir_alias = execute_copy_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "dir_alias",
        "copied_dir_alias",
        OperationConflictPolicy::Error,
    )
    .unwrap();
    assert_eq!(copied_dir_alias, "copied_dir_alias");
    assert_eq!(
        fs::read_to_string(user_root.join("copied_dir_alias/target.txt")).unwrap(),
        "hello-target"
    );
    assert_eq!(
        fs::read_to_string(user_root.join("copied_dir_alias/sub/inner.txt")).unwrap(),
        "inner-val"
    );
    assert_eq!(read_used_bytes(&conn, 88), 86);

    let copied_normal_with_links = execute_copy_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "normal_dir",
        "copied_normal_dir",
        OperationConflictPolicy::Error,
    )
    .unwrap();
    assert_eq!(copied_normal_with_links, "copied_normal_dir");
    assert_eq!(
        fs::read_to_string(user_root.join("copied_normal_dir/plain.txt")).unwrap(),
        "plain"
    );
    assert_eq!(
        fs::read_to_string(user_root.join("copied_normal_dir/nested/link_to_target.txt")).unwrap(),
        "hello-target"
    );
    assert_eq!(
        fs::read_to_string(user_root.join("copied_normal_dir/link_to_sub/inner.txt")).unwrap(),
        "inner-val"
    );
    assert!(
        !fs::symlink_metadata(user_root.join("copied_normal_dir/nested/link_to_target.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(read_used_bytes(&conn, 88), 112);

    assert!(matches!(
        execute_copy_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "dir_alias",
            "real_dir/sub/into_target",
            OperationConflictPolicy::Error,
        ),
        Err(McBrowserError::BadRequest(_))
    ));

    let plan = prepare_copy_source_plan(
        &conn,
        &bfs,
        "file_alias.txt",
        "file_alias.txt/",
        Some(&user),
    )
    .unwrap();
    fs::remove_file(user_root.join("file_alias.txt")).unwrap();
    symlink("secret_dir/secret.txt", user_root.join("file_alias.txt")).unwrap();
    fs::write(user_root.join("real_dir/replacement.txt"), "different-inode").unwrap();
    fs::rename(
        user_root.join("real_dir/replacement.txt"),
        user_root.join("real_dir/target.txt"),
    )
    .unwrap();
    match plan {
        CopySourcePlan::File {
            mut file, size, ..
        } => {
            let mut pinned_accounting = true;
            copy_pinned_file_new_with_quota(
                &conn,
                &bfs,
                &mut file,
                "pinned_output.txt",
                size,
                88,
                &mut pinned_accounting,
            )
            .unwrap();
            assert!(pinned_accounting);
        }
        CopySourcePlan::Directory { .. } => panic!("expected file plan"),
    }
    assert_eq!(
        fs::read_to_string(user_root.join("pinned_output.txt")).unwrap(),
        "hello-target"
    );
    fs::write(user_root.join("real_dir/target.txt"), "hello-target").unwrap();
    fs::remove_file(user_root.join("file_alias.txt")).unwrap();
    symlink("real_dir/target.txt", user_root.join("file_alias.txt")).unwrap();

    for denied_path in [
        "dir_alias",
        "dir_hop",
        "real_dir",
        "dir_alias/sub/inner.txt",
        "dir_hop/sub/inner.txt",
        "real_dir/sub/inner.txt",
    ] {
        let mut policy = crate::mcbrowser::policy::PolicyDocument::default();
        policy.rules.push(crate::mcbrowser::policy::PathRule {
            path: denied_path.to_string(),
            allow: false,
            regex: false,
            regexp: None,
        });
        crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 88, policy).unwrap();
        let used_before = read_used_bytes(&conn, 88);
        assert!(matches!(
            execute_copy_for_user_with_conn(
                &conn,
                &bfs,
                &user,
                "dir_alias",
                "denied_copy_out",
                OperationConflictPolicy::Error,
            ),
            Err(McBrowserError::Forbidden(_))
        ));
        assert!(bfs.metadata("denied_copy_out").is_err());
        assert_eq!(read_used_bytes(&conn, 88), used_before);
    }

    let mut deny_dest_descendant = crate::mcbrowser::policy::PolicyDocument::default();
    deny_dest_descendant
        .rules
        .push(crate::mcbrowser::policy::PathRule {
            path: "preflight_dst/sub/inner.txt".to_string(),
            allow: false,
            regex: false,
            regexp: None,
        });
    crate::mcbrowser::policy::save_user_policy_conn(&conn, &admin, 88, deny_dest_descendant)
        .unwrap();
    let used_before_preflight = read_used_bytes(&conn, 88);
    assert!(matches!(
        execute_copy_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "dir_alias",
            "preflight_dst",
            OperationConflictPolicy::Error,
        ),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(bfs.metadata("preflight_dst").is_err());
    assert_eq!(read_used_bytes(&conn, 88), used_before_preflight);

    crate::mcbrowser::policy::save_user_policy_conn(
        &conn,
        &admin,
        88,
        crate::mcbrowser::policy::PolicyDocument::default(),
    )
    .unwrap();

    let outside_secret = tmp.path().join("outside_secret.txt");
    fs::write(&outside_secret, "outside-secret-payload").unwrap();
    bfs.create_directory_all("escape_holder").unwrap();
    symlink(&outside_secret, user_root.join("escape_holder/escape.txt")).unwrap();
    assert!(matches!(
        execute_copy_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "escape_holder",
            "escape_copy",
            OperationConflictPolicy::Error,
        ),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(bfs.metadata("escape_copy").is_err());

    bfs.create_directory_all("broken_holder").unwrap();
    symlink("does_not_exist.txt", user_root.join("broken_holder/broken.txt")).unwrap();
    assert!(matches!(
        execute_copy_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "broken_holder",
            "broken_copy",
            OperationConflictPolicy::Error,
        ),
        Err(McBrowserError::NotFound(_))
    ));
    assert!(bfs.metadata("broken_copy").is_err());

    bfs.create_directory_all("cycle_holder/sub").unwrap();
    symlink("..", user_root.join("cycle_holder/sub/back")).unwrap();
    assert!(matches!(
        execute_copy_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "cycle_holder",
            "cycle_copy",
            OperationConflictPolicy::Error,
        ),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(bfs.metadata("cycle_copy").is_err());

    fs::hard_link(
        user_root.join("real_dir/target.txt"),
        user_root.join("hardlinked_target.txt"),
    )
    .unwrap();
    assert!(matches!(
        execute_copy_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "file_alias.txt",
            "hardlink_rejected.txt",
            OperationConflictPolicy::Error,
        ),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(bfs.metadata("hardlink_rejected.txt").is_err());
    fs::remove_file(user_root.join("hardlinked_target.txt")).unwrap();

    symlink(
        "copied_from_alias.txt",
        user_root.join("symlink_dest_leaf.txt"),
    )
    .unwrap();
    assert!(matches!(
        execute_copy_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            "file_alias.txt",
            "symlink_dest_leaf.txt",
            OperationConflictPolicy::Overwrite,
        ),
        Err(McBrowserError::Forbidden(_))
    ));

    execute_create_file_conn(
        &conn,
        &bfs,
        "overwrite_target.txt",
        Some("longer-initial-content!!"),
        88,
    )
    .unwrap();
    let used_before_shrink = read_used_bytes(&conn, 88);
    execute_copy_for_user_with_conn(
        &conn,
        &bfs,
        &user,
        "file_alias.txt",
        "overwrite_target.txt",
        OperationConflictPolicy::Overwrite,
    )
    .unwrap();
    assert_eq!(read_used_bytes(&conn, 88), used_before_shrink - 12);
    assert_eq!(
        fs::read_to_string(user_root.join("overwrite_target.txt")).unwrap(),
        "hello-target"
    );
}
