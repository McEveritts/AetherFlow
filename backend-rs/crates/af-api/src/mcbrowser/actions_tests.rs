use super::*;
use crate::auth::AuthUser;
use crate::mcbrowser::operations::{execute_create_file_conn, ArchiveFormat};
use crate::mcbrowser::policy::{
    ensure_policy_tables, save_user_policy_conn, PathRule, PolicyDocument, RuleExpression,
};
use crate::mcbrowser::{derive_user_root_path, open_user_browser_fs_at, TEST_DATABASE_LOCK};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rand::Rng;
use rusqlite::{params, Connection};
use std::fs;
use std::io::{Cursor, Write};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tower::ServiceExt;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let token: u128 = rng.gen();
            let path = std::env::temp_dir().join(format!("af-mcbrowser-actions-test-{token:032x}"));
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

struct IsolatedPoolEnv {
    dir: PathBuf,
    prev_db: Option<std::ffi::OsString>,
    prev_root: Option<std::ffi::OsString>,
}

impl IsolatedPoolEnv {
    fn new(quota_bytes: i64) -> Self {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let token: u128 = rng.gen();
            let dir = std::env::temp_dir().join(format!("af-mcbrowser-actions-pool-{token:032x}"));
            if fs::create_dir(&dir).is_ok() {
                let prev_db = std::env::var_os("DB_PATH");
                let prev_root = std::env::var_os("AF_MCBROWSER_ROOT");
                let db_path = dir.join("test.sqlite");
                let root_path = dir.join("files");
                std::env::set_var("DB_PATH", &db_path);
                std::env::set_var("AF_MCBROWSER_ROOT", &root_path);
                af_db::init_db().expect("initialize af_db max_size(1) pool");
                {
                    let conn = af_db::get_conn().unwrap();
                    ensure_policy_tables(&conn).unwrap();
                    conn.execute_batch(
                        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'alice', 'user');",
                    )
                    .unwrap();
                    conn.execute(
                        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status)
                         VALUES (1, 'admin', ?1, 0, 'active'), (2, 'alice', ?1, 0, 'active')",
                        params![quota_bytes],
                    )
                    .unwrap();
                }
                return Self {
                    dir,
                    prev_db,
                    prev_root,
                };
            }
        }
        panic!("failed to allocate isolated pool test dir");
    }

    fn router_for(&self, user: AuthUser) -> Router {
        router().layer(Extension(user))
    }

    fn used_bytes(&self, user_id: i64) -> i64 {
        let conn = af_db::get_conn().unwrap();
        conn.query_row(
            "SELECT used_bytes FROM user_quotas WHERE user_id = ?1",
            params![user_id],
            |r| r.get(0),
        )
        .unwrap()
    }
}

impl Drop for IsolatedPoolEnv {
    fn drop(&mut self) {
        match &self.prev_db {
            Some(v) => std::env::set_var("DB_PATH", v),
            None => std::env::remove_var("DB_PATH"),
        }
        match &self.prev_root {
            Some(v) => std::env::set_var("AF_MCBROWSER_ROOT", v),
            None => std::env::remove_var("AF_MCBROWSER_ROOT"),
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn make_user(user_id: i64, username: &str, role: &str) -> AuthUser {
    AuthUser {
        user_id,
        username: username.to_string(),
        role: role.to_string(),
        jti: format!("jti-{user_id}"),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    }
}

fn setup_conn(user_id: i64, quota_bytes: i64, used_bytes: i64) -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
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
        "#,
    )
    .unwrap();
    ensure_policy_tables(&conn).unwrap();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin')",
        [],
    )
    .unwrap();
    if user_id != 1 {
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (?1, ?2, 'user')",
            params![user_id, format!("user{user_id}")],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status)
         VALUES (?1, ?2, ?3, ?4, 'active')",
        params![user_id, format!("user{user_id}"), quota_bytes, used_bytes],
    )
    .unwrap();
    conn
}

fn enable_execute_for_user(conn: &Connection, target_user_id: i64, mut policy: PolicyDocument) {
    let admin = make_user(1, "admin", "admin");
    policy.permissions.execute = true;
    save_user_policy_conn(conn, &admin, target_user_id, policy).unwrap();
}

fn read_used_bytes(conn: &Connection, user_id: i64) -> i64 {
    conn.query_row(
        "SELECT used_bytes FROM user_quotas WHERE user_id = ?1",
        params![user_id],
        |r| r.get(0),
    )
    .unwrap()
}

fn write_raw_file(bfs: &BrowserFs, path: &str, bytes: &[u8]) {
    if let Some((parent, _)) = path.rsplit_once('/') {
        bfs.create_directory_all(parent).unwrap();
    }
    let mut pending = bfs.begin_upload(path).unwrap();
    pending.write_all(bytes).unwrap();
    pending.flush().unwrap();
    pending.commit().unwrap();
}

fn build_png_header(width: u32, height: u32) -> Vec<u8> {
    fn crc32(chunk_type: &[u8; 4], data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for &b in chunk_type.iter().chain(data.iter()) {
            crc ^= b as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xedb8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }
    fn write_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(chunk_type);
        out.extend_from_slice(data);
        out.extend_from_slice(&crc32(chunk_type, data).to_be_bytes());
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr[8] = 8;
    ihdr[9] = 6;
    write_chunk(&mut out, b"IHDR", &ihdr);
    write_chunk(&mut out, b"IEND", &[]);
    out
}

#[test]
fn zip_preflight_decompresses_every_entry_before_creating_destinations() {
    let temporary = TestTempDir::new();
    let filesystem = open_user_browser_fs_at(temporary.path(), 6).unwrap();
    let connection = setup_conn(6, 50_000_000, 0);
    let user = make_user(6, "user6", "user");
    enable_execute_for_user(&connection, 6, PolicyDocument::default());
    let mut archive_bytes = Cursor::new(Vec::new());
    {
        let mut archive = ZipWriter::new(&mut archive_bytes);
        for (name, contents) in [
            ("first.txt", "valid-first-body"),
            ("second.txt", "corrupt-second-body"),
        ] {
            archive
                .start_file(
                    name,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                )
                .unwrap();
            archive.write_all(contents.as_bytes()).unwrap();
        }
        archive.finish().unwrap();
    }
    let mut archive_bytes = archive_bytes.into_inner();
    let payload_offset = archive_bytes
        .windows(b"corrupt-second-body".len())
        .position(|window| window == b"corrupt-second-body")
        .unwrap();
    archive_bytes[payload_offset] ^= 1;
    write_raw_file(&filesystem, "corrupt.zip", &archive_bytes);
    let mut archive = filesystem.open_file("corrupt.zip").unwrap();
    let outcome = preflight_zip_archive(
        &connection,
        &filesystem,
        &user,
        &mut archive,
        archive_bytes.len() as u64,
        "absent-parent/extracted",
        Instant::now() + MAX_ACTION_DURATION,
    );
    assert!(matches!(outcome, Err(McBrowserError::BadRequest(_))));
    assert!(filesystem.metadata("absent-parent").is_err());
    assert_eq!(read_used_bytes(&connection, 6), 0);
}

#[test]
fn extraction_rollback_releases_only_confirmed_reserved_bytes() {
    let temporary = TestTempDir::new();
    let filesystem = open_user_browser_fs_at(temporary.path(), 6).unwrap();
    let connection = setup_conn(6, 50_000_000, 2_000);
    write_raw_file(&filesystem, "extracted/file.bin", &[0_u8; 500]);
    assert!(!rollback_partial_extraction(
        &connection,
        &filesystem,
        6,
        "extracted",
        1_000
    ));
    assert_eq!(read_used_bytes(&connection, 6), 1_500);
    assert!(filesystem.metadata("extracted").is_err());
}

#[test]
fn extraction_commit_failure_tracks_reservation_when_compensation_fails() {
    struct CollisionReader {
        payload: Cursor<Vec<u8>>,
        target: PathBuf,
        collided: bool,
    }
    impl Read for CollisionReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.collided {
                fs::write(&self.target, b"preserved target")?;
                self.collided = true;
            }
            self.payload.read(buffer)
        }
    }
    for reject_release in [false, true] {
        let temporary = TestTempDir::new();
        let filesystem = open_user_browser_fs_at(temporary.path(), 7).unwrap();
        let connection = setup_conn(7, 10_000, 0);
        let user = make_user(7, "user7", "user");
        enable_execute_for_user(&connection, 7, PolicyDocument::default());
        if reject_release {
            connection.execute_batch("CREATE TRIGGER reject_commit_release BEFORE UPDATE OF used_bytes ON user_quotas WHEN NEW.used_bytes < OLD.used_bytes BEGIN SELECT RAISE(ABORT, 'injected commit release failure'); END;").unwrap();
        }
        let reader = CollisionReader {
            payload: Cursor::new(b"payload".to_vec()),
            target: temporary.path().join("user-7/collision.txt"),
            collided: false,
        };
        let mut total_bytes = 0;
        let mut reserved_bytes = 0;
        let result = stream_extract_single_file(
            &connection,
            &filesystem,
            &user,
            7,
            "collision.txt",
            reader,
            1024,
            7,
            &mut total_bytes,
            &mut reserved_bytes,
            Instant::now() + MAX_ACTION_DURATION,
        );
        assert!(matches!(result, Err(McBrowserError::Conflict(_))));
        assert_eq!(reserved_bytes, if reject_release { 7 } else { 0 });
        assert_eq!(
            read_used_bytes(&connection, 7),
            if reject_release { 7 } else { 0 }
        );
        assert_eq!(
            fs::read(temporary.path().join("user-7/collision.txt")).unwrap(),
            b"preserved target"
        );
    }
}

#[test]
fn extraction_audit_fails_only_after_confirmed_filesystem_and_quota_rollback() {
    for reject_release in [false, true] {
        let temporary = TestTempDir::new();
        let filesystem = open_user_browser_fs_at(temporary.path(), 7).unwrap();
        let connection = setup_conn(7, 10_000, 0);
        let user = make_user(7, "user7", "user");
        enable_execute_for_user(&connection, 7, PolicyDocument::default());
        super::super::events::ensure_events_tables(&connection).unwrap();
        let mut archive = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut archive);
            for name in ["first.txt", "second.txt"] {
                let mut header = tar::Header::new_gnu();
                header.set_mode(0o644);
                header.set_size(60);
                header.set_cksum();
                builder
                    .append_data(&mut header, name, &[b'A'; 60][..])
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        write_raw_file(&filesystem, "two.tar", &archive);
        connection.execute_batch("CREATE TRIGGER shrink_extraction_quota AFTER INSERT ON mcbrowser_audit_events WHEN NEW.relative_path = 'parent/extracted' BEGIN UPDATE user_quotas SET quota_bytes = 80 WHERE user_id = 7; END;").unwrap();
        if reject_release {
            connection.execute_batch("CREATE TRIGGER reject_extraction_release BEFORE UPDATE OF used_bytes ON user_quotas WHEN NEW.used_bytes < OLD.used_bytes BEGIN SELECT RAISE(ABORT, 'injected quota release failure'); END;").unwrap();
        }
        let outcome = execute_action_with_conn(
            &connection,
            &filesystem,
            &user,
            Action::ExtractArchive {
                archive_path: "two.tar".to_string(),
                destination_dir: "parent/extracted".to_string(),
            },
        );
        assert!(matches!(outcome, Err(McBrowserError::QuotaExceeded(_))));
        assert!(filesystem.metadata("parent").is_err());
        assert_eq!(
            read_used_bytes(&connection, 7),
            if reject_release { 60 } else { 0 }
        );
        let audit: (String, i64, Option<String>) = connection.query_row(
            "SELECT status, byte_delta, error_code FROM mcbrowser_audit_events WHERE relative_path = 'parent/extracted'", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(audit.0, if reject_release { "pending" } else { "failed" });
        assert_eq!(audit.1, 0);
        assert_eq!(
            audit.2.as_deref(),
            if reject_release {
                None
            } else {
                Some("EXTRACTION_ROLLED_BACK")
            }
        );
        let queued: i64 = connection
            .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(queued, 0);
    }
}

#[test]
fn closed_action_enum_parses_valid_variants_and_strictly_rejects_unknown_fields_and_shell_attempts()
{
    let cs: Action = serde_json::from_str(
        r#"{"action":"compute_checksums","path":"hello.txt","algorithms":["md5","sha256"]}"#,
    )
    .unwrap();
    assert_eq!(
        cs,
        Action::ComputeChecksums {
            path: "hello.txt".to_string(),
            algorithms: vec!["md5".to_string(), "sha256".to_string()],
        }
    );

    let cs_csv: Action = serde_json::from_str(
        r#"{"action":"ComputeChecksums","path":"hello.txt","algorithms":"sha1, sha512"}"#,
    )
    .unwrap();
    assert_eq!(
        cs_csv,
        Action::ComputeChecksums {
            path: "hello.txt".to_string(),
            algorithms: vec!["sha1".to_string(), "sha512".to_string()],
        }
    );

    let ext_extract: Action = serde_json::from_str(
        r#"{"ExtractArchive":{"archive_path":"bundle.zip","destination_dir":"unpacked"}}"#,
    )
    .unwrap();
    assert_eq!(
        ext_extract,
        Action::ExtractArchive {
            archive_path: "bundle.zip".to_string(),
            destination_dir: "unpacked".to_string(),
        }
    );

    let create_act: Action = serde_json::from_str(
        r#"{"action":"create_archive","source_paths":["src"],"destination_path":"out.tar.zst","format":"tarzst"}"#,
    )
    .unwrap();
    assert!(create_act.is_mutating());

    let inspect_act: Action =
        serde_json::from_str(r#"{"action":"inspect_media_metadata","path":"video.mp4"}"#).unwrap();
    assert!(!inspect_act.is_mutating());

    for invalid_json in [
        r#"{"action":"shell","cmd":"id"}"#,
        r#"{"action":"exec","command":["/bin/sh","-c","whoami"]}"#,
        r#"{"action":"compute_checksums","path":"a.txt","algorithms":["sha256"],"extra":true}"#,
        r#"{"action":"extract_archive","archive_path":"a.zip","destination_dir":"out","overwrite":true}"#,
        r#"{"action":"create_archive","source_paths":["a"],"destination_path":"b.zip","format":"zip","shell":"bash"}"#,
        r#"{"action":"inspect_media_metadata","path":"a.png","exec":"ffprobe"}"#,
        r#"{"ComputeChecksums":{"path":"a.txt","algorithms":["md5"],"unknown":1}}"#,
        r#"{"ComputeChecksums":{"path":"a.txt","algorithms":[]}}"#,
        r#"{}"#,
    ] {
        assert!(
            parse_action_payload_bytes(invalid_json.as_bytes()).is_err(),
            "expected rejection for payload: {invalid_json}"
        );
    }

    let oversized = vec![b' '; MAX_ACTION_BODY_BYTES + 1];
    assert!(matches!(
        parse_action_payload_bytes(&oversized),
        Err(McBrowserError::PayloadTooLarge(_))
    ));
}

#[test]
fn default_policy_denies_all_actions_until_execute_is_explicitly_enabled_and_enforces_secondary_permissions(
) {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 2).unwrap();
    let conn = setup_conn(2, 10_000_000, 0);
    let user = make_user(2, "user2", "user");

    execute_create_file_conn(&conn, &bfs, "hello.txt", Some("hello world\n"), 2).unwrap();

    for action in [
        Action::ComputeChecksums {
            path: "hello.txt".to_string(),
            algorithms: vec!["sha256".to_string()],
        },
        Action::InspectMediaMetadata {
            path: "hello.txt".to_string(),
        },
        Action::CreateArchive {
            source_paths: vec!["hello.txt".to_string()],
            destination_path: "out.zip".to_string(),
            format: "zip".to_string(),
        },
        Action::ExtractArchive {
            archive_path: "out.zip".to_string(),
            destination_dir: "extracted".to_string(),
        },
    ] {
        let res = execute_action_with_conn(&conn, &bfs, &user, action);
        assert!(matches!(res, Err(McBrowserError::Forbidden(_))));
    }

    enable_execute_for_user(&conn, 2, PolicyDocument::default());

    let cs_resp = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::ComputeChecksums {
            path: "hello.txt".to_string(),
            algorithms: vec![
                "md5".to_string(),
                "sha1".to_string(),
                "sha256".to_string(),
                "sha512".to_string(),
            ],
        },
    )
    .unwrap();
    match cs_resp {
        ActionResponse::ComputeChecksums { success, result } => {
            assert!(success);
            assert_eq!(result.path, "hello.txt");
            assert_eq!(result.size, 12);
            assert_eq!(result.checksums["md5"], "6f5902ac237024bdd0c176cb93063dc4");
            assert_eq!(
                result.checksums["sha1"],
                "22596363b3de40b06f981fb85d82312e8c0ed511"
            );
            assert_eq!(
                result.checksums["sha256"],
                "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
            );
            assert_eq!(
                result.checksums["sha512"],
                "db3974a97f2407b7cae1ae637c0030687a11913274d578492558e39c16c017de84eacdc8c62fe34ee4e12b4b1428817f09b6a2760c3f8a664ceae94d2434a593"
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let mut no_read = PolicyDocument::default();
    no_read.permissions.read = false;
    enable_execute_for_user(&conn, 2, no_read);
    assert!(matches!(
        execute_action_with_conn(
            &conn,
            &bfs,
            &user,
            Action::ComputeChecksums {
                path: "hello.txt".to_string(),
                algorithms: vec!["md5".to_string()],
            },
        ),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        execute_action_with_conn(
            &conn,
            &bfs,
            &user,
            Action::InspectMediaMetadata {
                path: "hello.txt".to_string(),
            },
        ),
        Err(McBrowserError::Forbidden(_))
    ));

    let mut no_download = PolicyDocument::default();
    no_download.permissions.download = false;
    enable_execute_for_user(&conn, 2, no_download);
    assert!(matches!(
        execute_action_with_conn(
            &conn,
            &bfs,
            &user,
            Action::CreateArchive {
                source_paths: vec!["hello.txt".to_string()],
                destination_path: "out.zip".to_string(),
                format: "zip".to_string(),
            },
        ),
        Err(McBrowserError::Forbidden(_))
    ));

    let mut no_create = PolicyDocument::default();
    no_create.permissions.create = false;
    enable_execute_for_user(&conn, 2, no_create);
    assert!(matches!(
        execute_action_with_conn(
            &conn,
            &bfs,
            &user,
            Action::CreateArchive {
                source_paths: vec!["hello.txt".to_string()],
                destination_path: "out.zip".to_string(),
                format: "zip".to_string(),
            },
        ),
        Err(McBrowserError::Forbidden(_))
    ));
}

#[test]
fn internal_symlinks_and_descendant_path_rules_are_enforced_for_all_actions() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 3).unwrap();
    let conn = setup_conn(3, 10_000_000, 0);
    let user = make_user(3, "user3", "user");

    bfs.create_directory_all("public").unwrap();
    bfs.create_directory_all("private").unwrap();
    execute_create_file_conn(&conn, &bfs, "public/open.txt", Some("open-data"), 3).unwrap();
    execute_create_file_conn(&conn, &bfs, "private/secret.txt", Some("top-secret"), 3).unwrap();

    let user_root = derive_user_root_path(tmp.path(), 3).unwrap();
    symlink(
        "../private/secret.txt",
        user_root.join("public/secret_alias.txt"),
    )
    .unwrap();
    symlink("open.txt", user_root.join("public/open_alias.txt")).unwrap();

    let mut policy = PolicyDocument::default();
    policy.rules.push(PathRule {
        path: "private".to_string(),
        allow: false,
        regex: false,
        regexp: None,
    });
    enable_execute_for_user(&conn, 3, policy);

    let ok_alias = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::ComputeChecksums {
            path: "public/open_alias.txt".to_string(),
            algorithms: vec!["sha256".to_string()],
        },
    );
    assert!(ok_alias.is_ok());

    let denied_alias = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::ComputeChecksums {
            path: "public/secret_alias.txt".to_string(),
            algorithms: vec!["sha256".to_string()],
        },
    );
    assert!(matches!(denied_alias, Err(McBrowserError::Forbidden(_))));

    let denied_inspect = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::InspectMediaMetadata {
            path: "public/secret_alias.txt".to_string(),
        },
    );
    assert!(matches!(denied_inspect, Err(McBrowserError::Forbidden(_))));
}

#[test]
fn extraction_rechecks_declared_payload_size_before_publication() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 4).unwrap();
    let conn = setup_conn(4, 10_000_000, 0);
    let user = make_user(4, "user4", "user");
    enable_execute_for_user(&conn, 4, PolicyDocument::default());

    for (path, declared_size) in [("short.txt", 5), ("long.txt", 1)] {
        let mut expanded = 0;
        let mut reserved = 0;
        let result = stream_extract_single_file(
            &conn,
            &bfs,
            &user,
            4,
            path,
            &b"abc"[..],
            100,
            declared_size,
            &mut expanded,
            &mut reserved,
            Instant::now() + MAX_ACTION_DURATION,
        );
        assert!(matches!(result, Err(McBrowserError::BadRequest(_))));
        assert!(bfs.metadata(path).is_err());
        assert_eq!(reserved, 0);
    }
}

#[test]
fn inspect_media_metadata_reports_dimensions_and_filters_subtitles_by_policy() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 4).unwrap();
    let conn = setup_conn(4, 10_000_000, 0);
    let user = make_user(4, "user4", "user");

    let png_bytes = build_png_header(800, 600);
    write_raw_file(&bfs, "banner.png", &png_bytes);
    write_raw_file(
        &bfs,
        "movies/clip.mp4",
        b"\0\0\0\x18ftypisom\0\0\x02\0isomiso2",
    );
    write_raw_file(
        &bfs,
        "movies/clip.en.srt",
        b"1\n00:00:01,000 --> 00:00:02,000\nHello\n",
    );
    write_raw_file(
        &bfs,
        "movies/sub/clip.fr.srt",
        b"1\n00:00:01,000 --> 00:00:02,000\nBonjour\n",
    );

    let mut policy = PolicyDocument::default();
    policy.rules.push(PathRule {
        path: "movies/sub".to_string(),
        allow: false,
        regex: false,
        regexp: None,
    });
    enable_execute_for_user(&conn, 4, policy);

    let img_res = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::InspectMediaMetadata {
            path: "banner.png".to_string(),
        },
    )
    .unwrap();
    match img_res {
        ActionResponse::InspectMediaMetadata { success, result } => {
            assert!(success);
            assert_eq!(result.content_type.as_deref(), Some("image/png"));
            assert_eq!(
                result.resolution,
                Some(ImageResolution {
                    width: 800,
                    height: 600
                })
            );
        }
        other => panic!("unexpected: {other:?}"),
    }

    let vid_res = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::InspectMediaMetadata {
            path: "movies/clip.mp4".to_string(),
        },
    )
    .unwrap();
    match vid_res {
        ActionResponse::InspectMediaMetadata { success, result } => {
            assert!(success);
            assert_eq!(result.content_type.as_deref(), Some("video/mp4"));
            assert_eq!(result.subtitles.len(), 1);
            assert_eq!(result.subtitles[0].path, "movies/clip.en.srt");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn create_and_extract_archive_roundtrip_all_nine_formats_with_quota_and_no_clobber() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 5).unwrap();
    let conn = setup_conn(5, 50_000_000, 0);
    let user = make_user(5, "user5", "user");
    enable_execute_for_user(&conn, 5, PolicyDocument::default());

    bfs.create_directory_all("project/src/nested").unwrap();
    execute_create_file_conn(
        &conn,
        &bfs,
        "project/README.md",
        Some("# Safe Actions\n"),
        5,
    )
    .unwrap();
    execute_create_file_conn(
        &conn,
        &bfs,
        "project/src/nested/lib.rs",
        Some("pub fn answer() -> u32 { 42 }\n"),
        5,
    )
    .unwrap();
    let initial_used = read_used_bytes(&conn, 5);
    assert_eq!(initial_used, 45);

    for fmt in ArchiveFormat::ALL {
        let archive_path = format!("archives/bundle.{}", fmt.extension());
        let extract_dir = format!("unpacked/{}", fmt.algo_id());

        let create_resp = execute_action_with_conn(
            &conn,
            &bfs,
            &user,
            Action::CreateArchive {
                source_paths: vec!["project".to_string()],
                destination_path: archive_path.clone(),
                format: fmt.algo_id().to_string(),
            },
        )
        .unwrap();

        let archive_bytes = match create_resp {
            ActionResponse::CreateArchive { success, result } => {
                assert!(success);
                assert_eq!(result.destination_path, archive_path);
                assert_eq!(result.format, fmt.algo_id());
                assert_eq!(result.entry_count, 5);
                assert!(result.archive_bytes > 0);
                result.archive_bytes
            }
            other => panic!("unexpected response: {other:?}"),
        };

        let dup_create = execute_action_with_conn(
            &conn,
            &bfs,
            &user,
            Action::CreateArchive {
                source_paths: vec!["project".to_string()],
                destination_path: archive_path.clone(),
                format: fmt.algo_id().to_string(),
            },
        );
        assert!(matches!(dup_create, Err(McBrowserError::Conflict(_))));

        let used_after_create = read_used_bytes(&conn, 5);

        let extract_resp = execute_action_with_conn(
            &conn,
            &bfs,
            &user,
            Action::ExtractArchive {
                archive_path: archive_path.clone(),
                destination_dir: extract_dir.clone(),
            },
        )
        .unwrap();

        match extract_resp {
            ActionResponse::ExtractArchive { success, result } => {
                assert!(success);
                assert_eq!(result.archive_path, archive_path);
                assert_eq!(result.destination_dir, extract_dir);
                assert_eq!(result.format, fmt.algo_id());
                assert_eq!(result.extracted_files, 2);
                assert_eq!(result.extracted_bytes, 45);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert_eq!(read_used_bytes(&conn, 5), used_after_create + 45);

        let dup_extract = execute_action_with_conn(
            &conn,
            &bfs,
            &user,
            Action::ExtractArchive {
                archive_path: archive_path.clone(),
                destination_dir: extract_dir.clone(),
            },
        );
        assert!(matches!(dup_extract, Err(McBrowserError::Conflict(_))));
        assert_eq!(read_used_bytes(&conn, 5), used_after_create + 45);

        let mut readme = String::new();
        bfs.open_file(&format!("{extract_dir}/project/README.md"))
            .unwrap()
            .read_to_string(&mut readme)
            .unwrap();
        assert_eq!(readme, "# Safe Actions\n");

        let mut lib_rs = String::new();
        bfs.open_file(&format!("{extract_dir}/project/src/nested/lib.rs"))
            .unwrap()
            .read_to_string(&mut lib_rs)
            .unwrap();
        assert_eq!(lib_rs, "pub fn answer() -> u32 { 42 }\n");
        let _ = archive_bytes;
    }
}

#[test]
fn extract_archive_rejects_traversal_backslash_staging_duplicates_links_devices_encrypted_and_bombs(
) {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 6).unwrap();
    let conn = setup_conn(6, 50_000_000, 0);
    let user = make_user(6, "user6", "user");
    enable_execute_for_user(&conn, 6, PolicyDocument::default());

    fn build_custom_tar(entries: &[(&[u8], tar::EntryType, Option<&[u8]>, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(raw_name, entry_type, link_target, payload) in entries {
            let mut block = [0u8; 512];
            let copy_len = raw_name.len().min(100);
            block[..copy_len].copy_from_slice(&raw_name[..copy_len]);
            block[100..108].copy_from_slice(b"0000644\0");
            block[108..116].copy_from_slice(b"0000000\0");
            block[116..124].copy_from_slice(b"0000000\0");
            let size_octal = format!("{:011o}\0", payload.len());
            block[124..136].copy_from_slice(size_octal.as_bytes());
            block[136..148].copy_from_slice(b"00000000000\0");
            block[148..156].fill(b' ');
            block[156] = entry_type.as_byte();
            if let Some(link) = link_target {
                let l_len = link.len().min(100);
                block[157..157 + l_len].copy_from_slice(&link[..l_len]);
            }
            block[257..263].copy_from_slice(b"ustar\0");
            block[263..265].copy_from_slice(b"00");
            let cksum: u32 = block.iter().map(|&b| u32::from(b)).sum();
            let cksum_str = format!("{:06o}\0 ", cksum);
            block[148..156].copy_from_slice(cksum_str.as_bytes());
            out.extend_from_slice(&block);
            if !payload.is_empty() {
                out.extend_from_slice(payload);
                let rem = payload.len() % 512;
                if rem != 0 {
                    out.extend(std::iter::repeat(0u8).take(512 - rem));
                }
            }
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    let malicious_tar_cases: &[(&str, Vec<u8>)] = &[
        (
            "traversal.tar",
            build_custom_tar(&[(b"../escape.txt", tar::EntryType::Regular, None, b"evil")]),
        ),
        (
            "nested_traversal.tar",
            build_custom_tar(&[(
                b"sub/../../escape.txt",
                tar::EntryType::Regular,
                None,
                b"evil",
            )]),
        ),
        (
            "absolute.tar",
            build_custom_tar(&[(b"/etc/passwd", tar::EntryType::Regular, None, b"evil")]),
        ),
        (
            "backslash.tar",
            build_custom_tar(&[(
                b"sub\\..\\escape.txt",
                tar::EntryType::Regular,
                None,
                b"evil",
            )]),
        ),
        (
            "staging.tar",
            build_custom_tar(&[(
                b".af-upload-tmp.1234",
                tar::EntryType::Regular,
                None,
                b"evil",
            )]),
        ),
        (
            "control.tar",
            build_custom_tar(&[(b"bad\x07name.txt", tar::EntryType::Regular, None, b"evil")]),
        ),
        (
            "duplicate.tar",
            build_custom_tar(&[
                (b"dup.txt", tar::EntryType::Regular, None, b"one"),
                (b"dup.txt", tar::EntryType::Regular, None, b"two"),
            ]),
        ),
        (
            "symlink.tar",
            build_custom_tar(&[(
                b"link.txt",
                tar::EntryType::Symlink,
                Some(b"/etc/passwd"),
                b"",
            )]),
        ),
        (
            "hardlink.tar",
            build_custom_tar(&[(b"hlink.txt", tar::EntryType::Link, Some(b"other.txt"), b"")]),
        ),
        (
            "fifo.tar",
            build_custom_tar(&[(b"pipe", tar::EntryType::Fifo, None, b"")]),
        ),
        (
            "chardev.tar",
            build_custom_tar(&[(b"null", tar::EntryType::Char, None, b"")]),
        ),
    ];

    for (idx, (name, bytes)) in malicious_tar_cases.iter().enumerate() {
        write_raw_file(&bfs, name, bytes);
        let dst = format!("bad_out_{idx}");
        let res = execute_action_with_conn(
            &conn,
            &bfs,
            &user,
            Action::ExtractArchive {
                archive_path: (*name).to_string(),
                destination_dir: dst.clone(),
            },
        );
        assert!(res.is_err(), "expected {name} to be rejected, got {res:?}");
        assert!(
            bfs.metadata(&dst).is_err(),
            "destination_dir '{dst}' must not exist after rejected preflight for {name}"
        );
        assert_eq!(read_used_bytes(&conn, 6), 0);
    }

    let mut valid_zip = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut valid_zip);
        zw.start_file(
            "secret.txt",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
        zw.write_all(b"encrypted-body").unwrap();
        zw.finish().unwrap();
    }
    let mut enc_zip = valid_zip.into_inner();
    enc_zip[6] |= 0x01;
    write_raw_file(&bfs, "encrypted.zip", &enc_zip);
    let enc_res = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::ExtractArchive {
            archive_path: "encrypted.zip".to_string(),
            destination_dir: "enc_out".to_string(),
        },
    );
    assert!(matches!(enc_res, Err(McBrowserError::BadRequest(_))));
    assert!(bfs.metadata("enc_out").is_err());

    let mut symlink_zip = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut symlink_zip);
        zw.add_symlink(
            "evil_link",
            "/etc/shadow",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
        zw.finish().unwrap();
    }
    write_raw_file(&bfs, "symlink.zip", &symlink_zip.into_inner());
    let sym_res = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::ExtractArchive {
            archive_path: "symlink.zip".to_string(),
            destination_dir: "sym_out".to_string(),
        },
    );
    assert!(matches!(sym_res, Err(McBrowserError::BadRequest(_))));
    assert!(bfs.metadata("sym_out").is_err());

    let mut bomb_zip = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut bomb_zip);
        zw.start_file(
            "bomb.bin",
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
        let zeros = vec![0u8; 2 * 1024 * 1024];
        zw.write_all(&zeros).unwrap();
        zw.finish().unwrap();
    }
    let bomb_bytes = bomb_zip.into_inner();
    assert!(bomb_bytes.len() < 8192);
    write_raw_file(&bfs, "bomb.zip", &bomb_bytes);
    let bomb_res = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::ExtractArchive {
            archive_path: "bomb.zip".to_string(),
            destination_dir: "bomb_out".to_string(),
        },
    );
    assert!(matches!(bomb_res, Err(McBrowserError::PayloadTooLarge(_))));
    assert!(bfs.metadata("bomb_out").is_err());
    assert_eq!(read_used_bytes(&conn, 6), 0);
}

#[test]
fn quota_exhaustion_during_create_and_extract_rolls_back_cleanly_without_partial_files() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 7).unwrap();
    let conn = setup_conn(7, 10_000, 0);
    let user = make_user(7, "user7", "user");
    enable_execute_for_user(&conn, 7, PolicyDocument::default());

    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        for (name, content) in [
            ("part1.txt", &[b'A'; 60][..]),
            ("sub/part2.txt", &[b'B'; 60][..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(content.len() as u64);
            header.set_mtime(0);
            header.set_cksum();
            builder.append_data(&mut header, name, content).unwrap();
        }
        builder.finish().unwrap();
    }
    write_raw_file(&bfs, "two_files.tar", &tar_buf);

    conn.execute(
        "UPDATE user_quotas SET quota_bytes = 80, used_bytes = 0 WHERE user_id = 7",
        [],
    )
    .unwrap();

    let extract_err = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::ExtractArchive {
            archive_path: "two_files.tar".to_string(),
            destination_dir: "partial_dest".to_string(),
        },
    );
    assert!(matches!(extract_err, Err(McBrowserError::QuotaExceeded(_))));
    assert!(bfs.metadata("partial_dest").is_err());
    assert_eq!(read_used_bytes(&conn, 7), 0);

    let random_payload: Vec<u8> = (0..512).map(|i| ((i * 73 + 19) & 0xff) as u8).collect();
    write_raw_file(&bfs, "input.bin", &random_payload);
    conn.execute(
        "UPDATE user_quotas SET quota_bytes = 50, used_bytes = 0 WHERE user_id = 7",
        [],
    )
    .unwrap();

    let create_err = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::CreateArchive {
            source_paths: vec!["input.bin".to_string()],
            destination_path: "not_created/too_small_quota.tar".to_string(),
            format: "tar".to_string(),
        },
    );
    assert!(matches!(create_err, Err(McBrowserError::QuotaExceeded(_))));
    assert!(bfs.metadata("not_created").is_err());
    assert_eq!(read_used_bytes(&conn, 7), 0);
    let audit: (String, i64, String) = conn
        .query_row(
            "SELECT status, byte_delta, error_code FROM mcbrowser_audit_events
         WHERE relative_path = 'not_created/too_small_quota.tar'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        audit,
        ("failed".to_string(), 0, "ARCHIVE_NOT_PUBLISHED".to_string())
    );
    let queued: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(queued, 0);
}

#[test]
fn extraction_denies_per_entry_policy_rules_inside_destination_dir() {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 8).unwrap();
    let conn = setup_conn(8, 1_000_000, 0);
    let user = make_user(8, "user8", "user");

    let mut zip_cursor = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut zip_cursor);
        zw.start_file("allowed.txt", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(b"ok").unwrap();
        zw.start_file("blocked/secret.txt", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(b"denied").unwrap();
        zw.finish().unwrap();
    }
    write_raw_file(&bfs, "mixed.zip", &zip_cursor.into_inner());

    let mut policy = PolicyDocument::default();
    policy.rules.push(PathRule {
        path: "dest/blocked".to_string(),
        allow: false,
        regex: false,
        regexp: None,
    });
    enable_execute_for_user(&conn, 8, policy);

    let res = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::ExtractArchive {
            archive_path: "mixed.zip".to_string(),
            destination_dir: "dest".to_string(),
        },
    );
    assert!(matches!(res, Err(McBrowserError::Forbidden(_))));
    assert!(bfs.metadata("dest").is_err());
    assert_eq!(read_used_bytes(&conn, 8), 0);

    let mut regex_policy = PolicyDocument::default();
    regex_policy.rules.push(PathRule {
        path: r"^/dest2/.*\.txt$".to_string(),
        allow: false,
        regex: true,
        regexp: Some(RuleExpression {
            raw: r"^/dest2/.*\.txt$".to_string(),
        }),
    });
    enable_execute_for_user(&conn, 8, regex_policy);
    let res_regex = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::ExtractArchive {
            archive_path: "mixed.zip".to_string(),
            destination_dir: "dest2".to_string(),
        },
    );
    assert!(matches!(res_regex, Err(McBrowserError::Forbidden(_))));
    assert!(bfs.metadata("dest2").is_err());
}

#[tokio::test]
async fn mounted_actions_router_works_with_max_size_1_pool_and_enforces_admission_and_mutation_stripe(
) {
    let _db_lock = TEST_DATABASE_LOCK.lock().await;
    let env = IsolatedPoolEnv::new(10_000_000);
    let alice = make_user(2, "alice", "user");

    {
        let conn = af_db::get_conn().unwrap();
        let bfs = open_configured_user_browser_fs_with_conn(&conn, 2).unwrap();
        execute_create_file_conn(&conn, &bfs, "notes.txt", Some("hello world\n"), 2).unwrap();
    }

    let forbidden_resp = env
        .router_for(alice.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/actions")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"action":"compute_checksums","path":"notes.txt","algorithms":["sha256"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden_resp.status(), StatusCode::FORBIDDEN);

    {
        let conn = af_db::get_conn().unwrap();
        enable_execute_for_user(&conn, 2, PolicyDocument::default());
    }

    let cs_resp = tokio::time::timeout(
        Duration::from_secs(5),
        env.router_for(alice.clone()).oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/actions")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"action":"compute_checksums","path":"notes.txt","algorithms":["md5","sha256"]}"#,
                ))
                .unwrap(),
        ),
    )
    .await
    .expect("must not deadlock on max_size=1 pool")
    .unwrap();
    assert_eq!(cs_resp.status(), StatusCode::OK);
    assert_eq!(cs_resp.headers()[header::CACHE_CONTROL], "no-store");
    let cs_json: serde_json::Value =
        serde_json::from_slice(&cs_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(cs_json["action"], "compute_checksums");
    assert_eq!(
        cs_json["checksums"]["md5"],
        "6f5902ac237024bdd0c176cb93063dc4"
    );

    let create_resp = tokio::time::timeout(
        Duration::from_secs(5),
        env.router_for(alice.clone()).oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/actions")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"action":"create_archive","source_paths":["notes.txt"],"destination_path":"notes.tar.gz","format":"targz"}"#,
                ))
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let extract_resp = tokio::time::timeout(
        Duration::from_secs(5),
        env.router_for(alice.clone()).oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/actions")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"action":"extract_archive","archive_path":"notes.tar.gz","destination_dir":"restored"}"#,
                ))
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(extract_resp.status(), StatusCode::CREATED);
    assert!(env.used_bytes(2) > 24);

    let permits = ACTIONS_SEMAPHORE
        .acquire_many(ACTIONS_CONCURRENCY_LIMIT as u32)
        .await
        .unwrap();
    let busy_req = Request::builder()
        .method("POST")
        .uri("/mcbrowser/actions")
        .header("content-type", "application/json")
        .body(Body::from_stream(futures::stream::pending::<
            Result<Bytes, io::Error>,
        >()))
        .unwrap();
    let busy_resp = tokio::time::timeout(
        Duration::from_secs(1),
        env.router_for(alice.clone()).oneshot(busy_req),
    )
    .await
    .expect("semaphore admission must reject before awaiting request body")
    .unwrap();
    assert_eq!(busy_resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(busy_resp.headers()[header::RETRY_AFTER], "1");
    drop(permits);

    let stripe_guard = user_mutation_stripe(2).lock_owned().await;
    let blocked_mutation = env.router_for(alice).oneshot(
        Request::builder()
            .method("POST")
            .uri("/mcbrowser/actions")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"action":"create_archive","source_paths":["notes.txt"],"destination_path":"notes2.zip","format":"zip"}"#,
            ))
            .unwrap(),
    );
    tokio::pin!(blocked_mutation);
    assert!(futures::poll!(&mut blocked_mutation).is_pending());
    drop(stripe_guard);
    let completed_mutation = tokio::time::timeout(Duration::from_secs(5), blocked_mutation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed_mutation.status(), StatusCode::CREATED);
}

#[test]
fn zip_admission_rejects_duplicate_zip64_fields_and_ignores_comment_locator_magic() {
    let temporary = TestTempDir::new();
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "file.txt",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(b"payload").unwrap();
    let original = writer.finish().unwrap().into_inner();
    let end_offset = original.len() - 22;
    let directory_offset = u32::from_le_bytes(
        original[end_offset + 16..end_offset + 20]
            .try_into()
            .unwrap(),
    ) as usize;
    let name_length = u16::from_le_bytes(
        original[directory_offset + 28..directory_offset + 30]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut field = Vec::new();
    field.extend_from_slice(&1u16.to_le_bytes());
    field.extend_from_slice(&8u16.to_le_bytes());
    field.extend_from_slice(&0u64.to_le_bytes());
    for (label, sentinel, duplicate, locator_comment) in [
        ("single", true, false, false),
        ("duplicate", true, true, false),
        ("unrequested-duplicate", false, true, false),
        ("locator-comment", false, false, true),
    ] {
        let mut header = original[directory_offset..directory_offset + 46].to_vec();
        let extra = if locator_comment {
            Vec::new()
        } else if duplicate {
            let mut fields = field.clone();
            let mut alternate = field.clone();
            alternate[4..12].copy_from_slice(&((directory_offset + 1) as u64).to_le_bytes());
            fields.extend_from_slice(&alternate);
            fields
        } else {
            field.clone()
        };
        header[30..32].copy_from_slice(&(extra.len() as u16).to_le_bytes());
        header[32..34].copy_from_slice(&(if locator_comment { 20u16 } else { 0u16 }).to_le_bytes());
        if sentinel {
            header[42..46].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        let mut archive = original[..directory_offset].to_vec();
        archive.extend_from_slice(&header);
        archive.extend_from_slice(
            &original[directory_offset + 46..directory_offset + 46 + name_length],
        );
        archive.extend_from_slice(&extra);
        if locator_comment {
            archive.extend_from_slice(&0x07064b50u32.to_le_bytes());
            archive.extend_from_slice(&[0u8; 16]);
        }
        let directory_size = archive.len() - directory_offset;
        let mut footer = original[end_offset..].to_vec();
        footer[12..16].copy_from_slice(&(directory_size as u32).to_le_bytes());
        archive.extend_from_slice(&footer);
        let path = temporary.path().join(format!("{label}.zip"));
        fs::write(&path, &archive).unwrap();
        let mut file = File::open(path).unwrap();
        let result = open_admitted_zip_archive(
            &mut file,
            archive.len() as u64,
            Instant::now() + MAX_ACTION_DURATION,
            "ZIP field regression",
        );
        if duplicate {
            assert!(
                matches!(result, Err(McBrowserError::BadRequest(_))),
                "{label}"
            );
        } else {
            let (mut decoded, count) = result.unwrap();
            assert_eq!(count, 1, "{label}");
            let mut payload = Vec::new();
            decoded
                .by_index(0)
                .unwrap()
                .read_to_end(&mut payload)
                .unwrap();
            assert_eq!(payload, b"payload", "{label}");
        }
    }
}

#[test]
fn admitted_zip_reader_does_not_select_an_unadmitted_abutting_directory() {
    let temporary = TestTempDir::new();
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "good.txt",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(b"payload").unwrap();
    let original = writer.finish().unwrap().into_inner();
    let end_offset = original.len() - 22;
    let directory_start = u32::from_le_bytes(
        original[end_offset + 16..end_offset + 20]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut alternate = original[directory_start..end_offset].to_vec();
    alternate[46..54].copy_from_slice(b"evil.txt");
    let mut bytes = original[..end_offset].to_vec();
    bytes.extend_from_slice(&alternate);
    bytes.extend_from_slice(&original[end_offset..]);
    let mut cases = vec![bytes];
    for fake_count in [1u16, 4097] {
        let mut commented = original[..end_offset].to_vec();
        commented.extend_from_slice(&alternate);
        let mut outer_end = original[end_offset..].to_vec();
        outer_end[20..22].copy_from_slice(&24u16.to_le_bytes());
        commented.extend_from_slice(&outer_end);
        let mut inner_end = original[end_offset..].to_vec();
        inner_end[8..10].copy_from_slice(&fake_count.to_le_bytes());
        inner_end[10..12].copy_from_slice(&fake_count.to_le_bytes());
        inner_end[16..20].copy_from_slice(&(end_offset as u32).to_le_bytes());
        commented.extend_from_slice(&inner_end);
        commented.extend_from_slice(b"xx");
        cases.push(commented);
    }

    fn zip64_record(directory_size: u64, directory_offset: u64) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&0x06064b50u32.to_le_bytes());
        record.extend_from_slice(&44u64.to_le_bytes());
        record.extend_from_slice(&45u16.to_le_bytes());
        record.extend_from_slice(&45u16.to_le_bytes());
        record.extend_from_slice(&0u64.to_le_bytes());
        record.extend_from_slice(&1u64.to_le_bytes());
        record.extend_from_slice(&1u64.to_le_bytes());
        record.extend_from_slice(&directory_size.to_le_bytes());
        record.extend_from_slice(&directory_offset.to_le_bytes());
        record
    }

    for duplicate_record in [false, true] {
        let mut zip64 = original[..end_offset].to_vec();
        if duplicate_record {
            zip64.extend_from_slice(&alternate);
        }
        let record_offset = zip64.len() as u64;
        zip64.extend_from_slice(&zip64_record(
            (end_offset - directory_start) as u64,
            directory_start as u64,
        ));
        if duplicate_record {
            zip64.extend_from_slice(&zip64_record(
                (end_offset - directory_start) as u64,
                end_offset as u64,
            ));
        }
        zip64.extend_from_slice(&0x07064b50u32.to_le_bytes());
        zip64.extend_from_slice(&0u32.to_le_bytes());
        zip64.extend_from_slice(&record_offset.to_le_bytes());
        zip64.extend_from_slice(&1u32.to_le_bytes());
        let mut end = original[end_offset..].to_vec();
        end[8..20].fill(0xff);
        if !duplicate_record {
            end[20..22].copy_from_slice(&u16::MAX.to_le_bytes());
        }
        zip64.extend_from_slice(&end);
        if !duplicate_record {
            zip64.extend(std::iter::repeat_n(b'A', u16::MAX as usize));
        }
        cases.push(zip64);
    }
    for (index, bytes) in cases.iter().enumerate() {
        let archive_path = temporary.path().join(format!("differential-{index}.zip"));
        fs::write(&archive_path, bytes).unwrap();
        let mut descriptor = File::open(archive_path).unwrap();
        let (mut archive, count) = open_admitted_zip_archive(
            &mut descriptor,
            bytes.len() as u64,
            Instant::now() + MAX_ACTION_DURATION,
            "parser differential",
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(archive.offset(), 0);
        assert_eq!(archive.central_directory_start(), directory_start as u64);
        assert_eq!(archive.name_for_index(0).unwrap().unwrap(), "good.txt");
        let mut decoded = Vec::new();
        archive
            .by_index(0)
            .unwrap()
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(
            decoded, b"payload",
            "case {index} must preserve original payload bytes"
        );
    }
}

#[test]
fn zip_central_directory_admission_rejects_excess_entries_malformed_metadata_and_expired_deadline_while_preserving_valid_small_zip64(
) {
    let tmp = TestTempDir::new();
    let bfs = open_user_browser_fs_at(tmp.path(), 9).unwrap();
    let conn = setup_conn(9, 50_000_000, 0);
    let user = make_user(9, "user9", "user");
    enable_execute_for_user(&conn, 9, PolicyDocument::default());

    let mut base_lfh = Vec::new();
    base_lfh.extend_from_slice(&0x04034b50u32.to_le_bytes());
    base_lfh.extend_from_slice(&20u16.to_le_bytes());
    base_lfh.extend_from_slice(&0u16.to_le_bytes());
    base_lfh.extend_from_slice(&0u16.to_le_bytes());
    base_lfh.extend_from_slice(&0u16.to_le_bytes());
    base_lfh.extend_from_slice(&0u16.to_le_bytes());
    base_lfh.extend_from_slice(&0u32.to_le_bytes());
    base_lfh.extend_from_slice(&0u32.to_le_bytes());
    base_lfh.extend_from_slice(&0u32.to_le_bytes());
    base_lfh.extend_from_slice(&5u16.to_le_bytes());
    base_lfh.extend_from_slice(&0u16.to_le_bytes());
    base_lfh.extend_from_slice(b"a.txt");

    fn build_cd_entry(
        name: &[u8],
        flags: u16,
        method: u16,
        lfh_offset: u32,
        extra: &[u8],
    ) -> Vec<u8> {
        let mut cd = Vec::with_capacity(46 + name.len() + extra.len());
        cd.extend_from_slice(&0x02014b50u32.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&flags.to_le_bytes());
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
        cd.extend_from_slice(&lfh_offset.to_le_bytes());
        cd.extend_from_slice(name);
        cd.extend_from_slice(extra);
        cd
    }

    fn append_eocd(
        buf: &mut Vec<u8>,
        disk_num: u16,
        cd_disk: u16,
        disk_entries: u16,
        total_entries: u16,
        cd_size: u32,
        cd_offset: u32,
    ) {
        buf.extend_from_slice(&0x06054b50u32.to_le_bytes());
        buf.extend_from_slice(&disk_num.to_le_bytes());
        buf.extend_from_slice(&cd_disk.to_le_bytes());
        buf.extend_from_slice(&disk_entries.to_le_bytes());
        buf.extend_from_slice(&total_entries.to_le_bytes());
        buf.extend_from_slice(&cd_size.to_le_bytes());
        buf.extend_from_slice(&cd_offset.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
    }

    fn append_zip64_eocd_and_locator(
        buf: &mut Vec<u8>,
        record_size: u64,
        disk_num: u32,
        cd_disk: u32,
        disk_entries: u64,
        total_entries: u64,
        cd_size: u64,
        cd_offset: u64,
        loc_cd_disk: u32,
        loc_offset: u64,
        loc_total_disks: u32,
    ) {
        buf.extend_from_slice(&0x06064b50u32.to_le_bytes());
        buf.extend_from_slice(&record_size.to_le_bytes());
        buf.extend_from_slice(&45u16.to_le_bytes());
        buf.extend_from_slice(&45u16.to_le_bytes());
        buf.extend_from_slice(&disk_num.to_le_bytes());
        buf.extend_from_slice(&cd_disk.to_le_bytes());
        buf.extend_from_slice(&disk_entries.to_le_bytes());
        buf.extend_from_slice(&total_entries.to_le_bytes());
        buf.extend_from_slice(&cd_size.to_le_bytes());
        buf.extend_from_slice(&cd_offset.to_le_bytes());

        buf.extend_from_slice(&0x07064b50u32.to_le_bytes());
        buf.extend_from_slice(&loc_cd_disk.to_le_bytes());
        buf.extend_from_slice(&loc_offset.to_le_bytes());
        buf.extend_from_slice(&loc_total_disks.to_le_bytes());
    }

    let over_limit_count = MAX_ACTION_ARCHIVE_ENTRIES + 1;
    let mut over_declared_zip = base_lfh.clone();
    let cd_offset_over = over_declared_zip.len() as u32;
    for i in 0..over_limit_count {
        let name = format!("f{i:04}.txt");
        over_declared_zip.extend_from_slice(&build_cd_entry(name.as_bytes(), 0, 0, 0, &[]));
    }
    let cd_size_over = (over_declared_zip.len() as u32) - cd_offset_over;
    append_eocd(
        &mut over_declared_zip,
        0,
        0,
        over_limit_count as u16,
        over_limit_count as u16,
        cd_size_over,
        cd_offset_over,
    );
    write_raw_file(&bfs, "over_4096_declared.zip", &over_declared_zip);
    let mut f_over_decl = bfs.open_file("over_4096_declared.zip").unwrap();
    let res_over_decl = open_admitted_zip_archive(
        &mut f_over_decl,
        over_declared_zip.len() as u64,
        Instant::now() + MAX_ACTION_DURATION,
        "test",
    );
    assert!(matches!(res_over_decl, Err(McBrowserError::BadRequest(_))));

    let mut spoofed_count_zip = base_lfh.clone();
    let cd_offset_spoof = spoofed_count_zip.len() as u32;
    for i in 0..over_limit_count {
        let name = format!("s{i:04}.txt");
        spoofed_count_zip.extend_from_slice(&build_cd_entry(name.as_bytes(), 0, 0, 0, &[]));
    }
    let cd_size_spoof = (spoofed_count_zip.len() as u32) - cd_offset_spoof;
    append_eocd(
        &mut spoofed_count_zip,
        0,
        0,
        1,
        1,
        cd_size_spoof,
        cd_offset_spoof,
    );
    write_raw_file(&bfs, "spoofed_4097_actual.zip", &spoofed_count_zip);
    let mut f_spoof = bfs.open_file("spoofed_4097_actual.zip").unwrap();
    let res_spoof = preflight_zip_raw_headers_for_encryption(
        &mut f_spoof,
        spoofed_count_zip.len() as u64,
        Instant::now() + MAX_ACTION_DURATION,
    );
    assert!(matches!(res_spoof, Err(McBrowserError::BadRequest(_))));

    let mut z64_over_zip = base_lfh.clone();
    let cd_offset_z64_over = z64_over_zip.len() as u64;
    let single_cd = build_cd_entry(b"a.txt", 0, 0, 0, &[]);
    z64_over_zip.extend_from_slice(&single_cd);
    let z64_eocd_pos = z64_over_zip.len() as u64;
    append_zip64_eocd_and_locator(
        &mut z64_over_zip,
        44,
        0,
        0,
        (MAX_ACTION_ARCHIVE_ENTRIES as u64) + 50,
        (MAX_ACTION_ARCHIVE_ENTRIES as u64) + 50,
        single_cd.len() as u64,
        cd_offset_z64_over,
        0,
        z64_eocd_pos,
        1,
    );
    append_eocd(
        &mut z64_over_zip,
        0,
        0,
        u16::MAX,
        u16::MAX,
        single_cd.len() as u32,
        cd_offset_z64_over as u32,
    );
    write_raw_file(&bfs, "z64_over_4096.zip", &z64_over_zip);
    let mut f_z64_over = bfs.open_file("z64_over_4096.zip").unwrap();
    assert!(matches!(
        open_admitted_zip_archive(
            &mut f_z64_over,
            z64_over_zip.len() as u64,
            Instant::now() + MAX_ACTION_DURATION,
            "test"
        ),
        Err(McBrowserError::BadRequest(_))
    ));

    let mut oversized_cd_decl = base_lfh.clone();
    let cd_off_big = oversized_cd_decl.len() as u32;
    oversized_cd_decl.extend_from_slice(&single_cd);
    append_eocd(
        &mut oversized_cd_decl,
        0,
        0,
        1,
        1,
        (MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES as u32) + 1,
        cd_off_big,
    );
    write_raw_file(&bfs, "oversized_cd.zip", &oversized_cd_decl);
    let mut f_big_cd = bfs.open_file("oversized_cd.zip").unwrap();
    assert!(matches!(
        open_admitted_zip_archive(
            &mut f_big_cd,
            oversized_cd_decl.len() as u64,
            Instant::now() + MAX_ACTION_DURATION,
            "test"
        ),
        Err(McBrowserError::PayloadTooLarge(_))
    ));

    let mut mismatch_entries = base_lfh.clone();
    let cd_off_mm = mismatch_entries.len() as u32;
    mismatch_entries.extend_from_slice(&single_cd);
    append_eocd(
        &mut mismatch_entries,
        0,
        0,
        2,
        2,
        single_cd.len() as u32,
        cd_off_mm,
    );

    let mut multi_disk = base_lfh.clone();
    let cd_off_md = multi_disk.len() as u32;
    multi_disk.extend_from_slice(&single_cd);
    append_eocd(
        &mut multi_disk,
        1,
        1,
        1,
        1,
        single_cd.len() as u32,
        cd_off_md,
    );

    let mut bad_cd_offset = base_lfh.clone();
    bad_cd_offset.extend_from_slice(&single_cd);
    append_eocd(
        &mut bad_cd_offset,
        0,
        0,
        1,
        1,
        single_cd.len() as u32,
        u32::MAX - 10,
    );

    let mut bad_lfh_offset = base_lfh.clone();
    let cd_off_lfh = bad_lfh_offset.len() as u32;
    let bad_lfh_cd = build_cd_entry(b"a.txt", 0, 0, cd_off_lfh, &[]);
    bad_lfh_offset.extend_from_slice(&bad_lfh_cd);
    append_eocd(
        &mut bad_lfh_offset,
        0,
        0,
        1,
        1,
        bad_lfh_cd.len() as u32,
        cd_off_lfh,
    );

    let mut missing_z64_locator = base_lfh.clone();
    let cd_off_m64 = missing_z64_locator.len() as u32;
    missing_z64_locator.extend_from_slice(&single_cd);
    append_eocd(
        &mut missing_z64_locator,
        0,
        0,
        u16::MAX,
        u16::MAX,
        single_cd.len() as u32,
        cd_off_m64,
    );

    let mut bad_z64_locator_offset = base_lfh.clone();
    let cd_off_b64 = bad_z64_locator_offset.len() as u64;
    bad_z64_locator_offset.extend_from_slice(&single_cd);
    append_zip64_eocd_and_locator(
        &mut bad_z64_locator_offset,
        44,
        0,
        0,
        1,
        1,
        single_cd.len() as u64,
        cd_off_b64,
        0,
        999_999,
        1,
    );
    append_eocd(
        &mut bad_z64_locator_offset,
        0,
        0,
        1,
        1,
        single_cd.len() as u32,
        cd_off_b64 as u32,
    );

    let mut z64_count_mismatch = base_lfh.clone();
    let cd_off_cm64 = z64_count_mismatch.len() as u64;
    z64_count_mismatch.extend_from_slice(&single_cd);
    let z64_pos_cm = z64_count_mismatch.len() as u64;
    append_zip64_eocd_and_locator(
        &mut z64_count_mismatch,
        44,
        0,
        0,
        1,
        1,
        single_cd.len() as u64,
        cd_off_cm64,
        0,
        z64_pos_cm,
        1,
    );
    append_eocd(
        &mut z64_count_mismatch,
        0,
        0,
        2,
        2,
        single_cd.len() as u32,
        cd_off_cm64 as u32,
    );

    let mut missing_z64_extra = base_lfh.clone();
    let cd_off_me = missing_z64_extra.len() as u32;
    let cd_sentinel_no_extra = build_cd_entry(b"a.txt", 0, 0, u32::MAX, &[]);
    missing_z64_extra.extend_from_slice(&cd_sentinel_no_extra);
    append_eocd(
        &mut missing_z64_extra,
        0,
        0,
        1,
        1,
        cd_sentinel_no_extra.len() as u32,
        cd_off_me,
    );

    let mut trunc_z64_extra = base_lfh.clone();
    let cd_off_te = trunc_z64_extra.len() as u32;
    let short_extra = [0x01, 0x00, 0x04, 0x00, 0, 0, 0, 0];
    let cd_sentinel_trunc_extra = build_cd_entry(b"a.txt", 0, 0, u32::MAX, &short_extra);
    trunc_z64_extra.extend_from_slice(&cd_sentinel_trunc_extra);
    append_eocd(
        &mut trunc_z64_extra,
        0,
        0,
        1,
        1,
        cd_sentinel_trunc_extra.len() as u32,
        cd_off_te,
    );

    let mut aes_encrypted_cd = base_lfh.clone();
    let cd_off_aes = aes_encrypted_cd.len() as u32;
    let cd_aes = build_cd_entry(b"a.txt", 0, 99, 0, &[]);
    aes_encrypted_cd.extend_from_slice(&cd_aes);
    append_eocd(
        &mut aes_encrypted_cd,
        0,
        0,
        1,
        1,
        cd_aes.len() as u32,
        cd_off_aes,
    );

    for (idx, payload) in [
        mismatch_entries,
        multi_disk,
        bad_cd_offset,
        bad_lfh_offset,
        missing_z64_locator,
        bad_z64_locator_offset,
        z64_count_mismatch,
        missing_z64_extra,
        trunc_z64_extra,
        aes_encrypted_cd,
    ]
    .into_iter()
    .enumerate()
    {
        let fname = format!("malformed_{idx}.zip");
        let dst = format!("malformed_out_{idx}");
        write_raw_file(&bfs, &fname, &payload);
        let res = execute_action_with_conn(
            &conn,
            &bfs,
            &user,
            Action::ExtractArchive {
                archive_path: fname.clone(),
                destination_dir: dst.clone(),
            },
        );
        assert!(
            matches!(res, Err(McBrowserError::BadRequest(_))),
            "expected BadRequest for {fname}, got {res:?}"
        );
        assert!(bfs.metadata(&dst).is_err());
    }

    let mut valid_small_z64 = Vec::new();
    {
        bfs.create_directory_all("z64_src").unwrap();
        execute_create_file_conn(
            &conn,
            &bfs,
            "z64_src/hello.txt",
            Some("zip64-payload-ok"),
            9,
        )
        .unwrap();
        let plan = super::super::operations::collect_archive_plan_for_user_with_conn(
            &conn,
            &bfs,
            &user,
            &["z64_src".to_string()],
        )
        .unwrap();
        super::super::operations::write_archive_to_writer(
            &bfs,
            &plan,
            ArchiveFormat::Zip,
            &mut valid_small_z64,
        )
        .unwrap();
    }
    let eocd_idx = valid_small_z64
        .windows(4)
        .rposition(|w| w == 0x06054b50u32.to_le_bytes())
        .unwrap();
    let orig_entries = u16::from_le_bytes([
        valid_small_z64[eocd_idx + 10],
        valid_small_z64[eocd_idx + 11],
    ]) as u64;
    let orig_cd_size = u32::from_le_bytes(
        valid_small_z64[eocd_idx + 12..eocd_idx + 16]
            .try_into()
            .unwrap(),
    ) as u64;
    let orig_cd_offset = u32::from_le_bytes(
        valid_small_z64[eocd_idx + 16..eocd_idx + 20]
            .try_into()
            .unwrap(),
    ) as u64;
    valid_small_z64.truncate(eocd_idx);
    let z64_eocd_offset = valid_small_z64.len() as u64;
    append_zip64_eocd_and_locator(
        &mut valid_small_z64,
        44,
        0,
        0,
        orig_entries,
        orig_entries,
        orig_cd_size,
        orig_cd_offset,
        0,
        z64_eocd_offset,
        1,
    );
    append_eocd(
        &mut valid_small_z64,
        0,
        0,
        u16::MAX,
        u16::MAX,
        u32::MAX,
        u32::MAX,
    );
    write_raw_file(&bfs, "small_valid_zip64.zip", &valid_small_z64);

    let mut expired_file = bfs.open_file("small_valid_zip64.zip").unwrap();
    let expired_deadline = Instant::now() - Duration::from_secs(1);
    let expired_adm = preflight_zip_raw_headers_for_encryption(
        &mut expired_file,
        valid_small_z64.len() as u64,
        expired_deadline,
    );
    assert!(matches!(
        expired_adm,
        Err(McBrowserError::RequestTimeout(_))
    ));
    let expired_open = open_admitted_zip_archive(
        &mut expired_file,
        valid_small_z64.len() as u64,
        expired_deadline,
        "expired_test",
    );
    assert!(matches!(
        expired_open,
        Err(McBrowserError::RequestTimeout(_))
    ));

    let extract_z64 = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::ExtractArchive {
            archive_path: "small_valid_zip64.zip".to_string(),
            destination_dir: "z64_unpacked".to_string(),
        },
    )
    .unwrap();
    match extract_z64 {
        ActionResponse::ExtractArchive { success, result } => {
            assert!(success);
            assert_eq!(result.extracted_files, 1);
            assert_eq!(result.extracted_bytes, 16);
        }
        other => panic!("unexpected response: {other:?}"),
    }
    let mut extracted_body = String::new();
    bfs.open_file("z64_unpacked/z64_src/hello.txt")
        .unwrap()
        .read_to_string(&mut extracted_body)
        .unwrap();
    assert_eq!(extracted_body, "zip64-payload-ok");

    let mut z64_entry_extra_zip = Vec::new();
    {
        let mut zw = ZipWriter::new(Cursor::new(&mut z64_entry_extra_zip));
        zw.start_file(
            "large_flag.txt",
            SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .large_file(true),
        )
        .unwrap();
        zw.write_all(b"zip64-entry-extra-field-payload").unwrap();
        zw.finish().unwrap();
    }
    write_raw_file(&bfs, "small_large_flag_zip64.zip", &z64_entry_extra_zip);
    let extract_z64_extra = execute_action_with_conn(
        &conn,
        &bfs,
        &user,
        Action::ExtractArchive {
            archive_path: "small_large_flag_zip64.zip".to_string(),
            destination_dir: "z64_extra_unpacked".to_string(),
        },
    )
    .unwrap();
    match extract_z64_extra {
        ActionResponse::ExtractArchive { success, result } => {
            assert!(success);
            assert_eq!(result.extracted_files, 1);
            assert_eq!(result.extracted_bytes, 31);
        }
        other => panic!("unexpected response: {other:?}"),
    }
    let mut extracted_extra_body = String::new();
    bfs.open_file("z64_extra_unpacked/large_flag.txt")
        .unwrap()
        .read_to_string(&mut extracted_extra_body)
        .unwrap();
    assert_eq!(extracted_extra_body, "zip64-entry-extra-field-payload");
}
