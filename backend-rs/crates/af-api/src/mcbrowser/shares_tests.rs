use super::*;
use crate::auth::AuthUser;
use crate::mcbrowser::derive_user_root_path;
use crate::mcbrowser::policy::{self, Permission};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use rand::Rng;
use rusqlite::{params, Connection};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let token: u128 = rng.gen();
            let path = std::env::temp_dir().join(format!("af-mcbrowser-shares-test-{token:032x}"));
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
        username: "plugin:sonarr".to_string(),
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
        INSERT INTO users (id, username, role) VALUES (1, 'user1', 'user'), (2, 'user2', 'user');
        INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status)
        VALUES (1, 'user1', 0, 0, 'active'), (2, 'user2', 0, 0, 'active');
        "#,
    )
    .unwrap();
    ensure_shares_schema(&conn).unwrap();
    conn
}

fn allow_all_policy() -> PolicyAuthorizer {
    Arc::new(|_conn, _user, _perm, _path| Ok(()))
}

#[test]
fn confined_alias_shares_preserve_names_revalidate_hops_and_confine_public_children() {
    use super::super::policy::Permission;
    use std::io::Read;
    use std::os::unix::fs::symlink;
    let temporary = TestTempDir::new();
    let conn = setup_isolated_db();
    let user = human_user(1);
    let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
    let root = derive_user_root_path(temporary.path(), 1).unwrap();
    filesystem.create_directory_all("shared/sub").unwrap();
    filesystem.create_directory_all("private").unwrap();
    fs::write(root.join("shared/real.txt"), b"public").unwrap();
    fs::write(root.join("shared/sub/nested.txt"), b"nested").unwrap();
    fs::write(root.join("private/secret.txt"), b"secret").unwrap();
    fs::write(root.join("private/owner-only.txt"), b"owner").unwrap();
    symlink("shared", root.join("hop")).unwrap();
    symlink("hop", root.join("links")).unwrap();
    symlink("links/real.txt", root.join("leaf.txt")).unwrap();
    symlink("real.txt", root.join("shared/inner-hop.txt")).unwrap();
    symlink("inner-hop.txt", root.join("shared/file-link.txt")).unwrap();
    symlink("sub", root.join("shared/dir-link")).unwrap();
    symlink("../private", root.join("shared/escape")).unwrap();
    symlink("loop", root.join("shared/loop")).unwrap();
    fs::hard_link(
        root.join("private/secret.txt"),
        root.join("shared/hard.txt"),
    )
    .unwrap();
    let denied = Arc::new(Mutex::new(None::<(Permission, String)>));
    let policy: PolicyAuthorizer =
        {
            let denied = Arc::clone(&denied);
            Arc::new(move |_conn, _user, permission, path| {
                if denied.lock().unwrap().as_ref().is_some_and(
                    |(blocked_permission, blocked_path)| {
                        *blocked_permission == permission
                            && (path == blocked_path
                                || path.starts_with(&format!("{blocked_path}/")))
                    },
                ) {
                    Err(McBrowserError::Forbidden(
                        "Denied by test policy".to_string(),
                    ))
                } else {
                    Ok(())
                }
            })
        };
    let create = |path: &str| {
        create_share_at(
            &conn,
            temporary.path(),
            &policy,
            &user,
            CreateShareRequest {
                path: path.to_string(),
                password: None,
                expires_at: None,
                allow_download: Some(true),
            },
        )
    };
    let (file_share, file_token) = create("leaf.txt").unwrap();
    let (dir_share, dir_token) = create("links").unwrap();
    assert_eq!(file_share.path, "leaf.txt");
    assert_eq!(file_share.name, "leaf.txt");
    assert_eq!(dir_share.path, "links");
    assert_eq!(dir_share.name, "links");
    let headers = HeaderMap::new();
    let entries =
        list_public_entries_at(&conn, temporary.path(), &policy, &dir_token, "", &headers).unwrap();
    assert!(entries
        .entries
        .iter()
        .any(|entry| entry.path == "file-link.txt" && entry.kind == "file"));
    assert!(entries
        .entries
        .iter()
        .any(|entry| entry.path == "dir-link" && entry.kind == "directory"));
    assert!(!entries
        .entries
        .iter()
        .any(|entry| ["escape", "loop", "hard.txt"].contains(&entry.name.as_str())));
    let nested = list_public_entries_at(
        &conn,
        temporary.path(),
        &policy,
        &dir_token,
        "dir-link",
        &headers,
    )
    .unwrap();
    assert_eq!(nested.entries[0].path, "dir-link/nested.txt");
    for (token, path, expected_name, expected) in [
        (&file_token, "", "leaf.txt", b"public".as_slice()),
        (
            &dir_token,
            "file-link.txt",
            "file-link.txt",
            b"public".as_slice(),
        ),
        (
            &dir_token,
            "dir-link/nested.txt",
            "nested.txt",
            b"nested".as_slice(),
        ),
    ] {
        let (mut file, name, _, _) =
            open_public_download_at(&conn, temporary.path(), &policy, token, path, &headers)
                .unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(name, expected_name);
    }
    for path in ["escape/secret.txt", "hard.txt", "loop"] {
        assert!(open_public_download_at(
            &conn,
            temporary.path(),
            &policy,
            &dir_token,
            path,
            &headers
        )
        .is_err());
    }
    for permission in [Permission::Share, Permission::Read, Permission::Download] {
        for path in [
            "leaf.txt",
            "links/real.txt",
            "hop/real.txt",
            "shared/real.txt",
        ] {
            *denied.lock().unwrap() = Some((permission, path.to_string()));
            assert!(create("leaf.txt").is_err(), "create {permission:?} {path}");
            assert!(
                open_public_download_at(
                    &conn,
                    temporary.path(),
                    &policy,
                    &file_token,
                    "",
                    &headers
                )
                .is_err(),
                "file {permission:?} {path}"
            );
        }
        for path in [
            "links/file-link.txt",
            "hop/inner-hop.txt",
            "shared/real.txt",
            "links/sub/nested.txt",
        ] {
            *denied.lock().unwrap() = Some((permission, path.to_string()));
            let selected = if path.contains("nested") {
                "dir-link/nested.txt"
            } else {
                "file-link.txt"
            };
            assert!(
                open_public_download_at(
                    &conn,
                    temporary.path(),
                    &policy,
                    &dir_token,
                    selected,
                    &headers
                )
                .is_err(),
                "directory {permission:?} {path}"
            );
        }
    }
    *denied.lock().unwrap() = Some((Permission::Read, "hop/inner-hop.txt".to_string()));
    let entries =
        list_public_entries_at(&conn, temporary.path(), &policy, &dir_token, "", &headers).unwrap();
    assert!(!entries
        .entries
        .iter()
        .any(|entry| entry.name == "file-link.txt"));
    *denied.lock().unwrap() = None;
    let (mut pinned, _, _, _) =
        open_public_download_at(&conn, temporary.path(), &policy, &file_token, "", &headers)
            .unwrap();
    fs::remove_file(root.join("leaf.txt")).unwrap();
    symlink("private/secret.txt", root.join("leaf.txt")).unwrap();
    assert!(get_public_metadata_at(&conn, temporary.path(), &policy, &file_token).is_err());
    let mut bytes = Vec::new();
    pinned.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"public");
    fs::remove_file(root.join("links")).unwrap();
    symlink("private", root.join("links")).unwrap();
    assert!(
        list_public_entries_at(&conn, temporary.path(), &policy, &dir_token, "", &headers).is_err()
    );
    assert!(create("shared/escape/owner-only.txt").is_ok());
    assert!(create("shared/hard.txt").is_err());
}

fn build_test_routers(
    conn: Arc<Mutex<Connection>>,
    base_root: PathBuf,
    policy: PolicyAuthorizer,
    auth_user: AuthUser,
) -> (Router, Router) {
    let runtime = ShareRuntime::Isolated {
        conn,
        base_root,
        policy,
    };
    let auth_router = router_with_runtime(runtime.clone()).layer(Extension(auth_user));
    let pub_router = public_router_with_runtime(runtime);
    (auth_router, pub_router)
}

async fn read_body_json(resp: Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn read_body_bytes(resp: Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

#[tokio::test]
async fn mounted_confined_alias_share_create_listing_and_download_preserve_public_paths() {
    let temporary = TestTempDir::new();
    let filesystem = open_user_browser_fs_at(temporary.path(), 1).unwrap();
    filesystem.create_directory_all("real/sub").unwrap();
    let root = derive_user_root_path(temporary.path(), 1).unwrap();
    fs::write(root.join("real/sub/file.txt"), b"shared bytes").unwrap();
    symlink("real", root.join("alias")).unwrap();
    symlink("sub", root.join("real/child-alias")).unwrap();
    symlink("alias/sub/file.txt", root.join("leaf.txt")).unwrap();
    let (authenticated, public) = build_test_routers(
        Arc::new(Mutex::new(setup_isolated_db())),
        temporary.path().to_path_buf(),
        allow_all_policy(),
        human_user(1),
    );
    for (path, download_path) in [("alias", "child-alias/file.txt"), ("leaf.txt", "")] {
        let response = authenticated
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcbrowser/shares")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::json!({"path":path}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = read_body_json(response).await;
        assert_eq!(created["share"]["path"], path);
        assert_eq!(created["share"]["name"], path);
        let token = created["share"]["url"]
            .as_str()
            .unwrap()
            .strip_prefix("/share?token=")
            .unwrap();
        let response = public
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/mcbrowser/shares/{token}/entries"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = read_body_json(response).await;
        let text = serde_json::to_string(&listed).unwrap();
        assert!(!text.contains("real/"));
        let response = public
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/mcbrowser/shares/{token}/download?path={download_path}"
                    ))
                    .header(header::RANGE, "bytes=0-5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(read_body_bytes(response).await, b"shared");
    }
}

#[tokio::test]
async fn create_list_delete_share_stores_hashed_token_only_and_enforces_owner_isolation() {
    let tmp = TestTempDir::new();
    let bfs1 = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs1.create_directory_all("docs/reports").unwrap();
    let user1_root = derive_user_root_path(tmp.path(), 1).unwrap();
    fs::write(user1_root.join("docs/reports/q4.txt"), b"Q4 results").unwrap();

    let conn = Arc::new(Mutex::new(setup_isolated_db()));
    let (auth_u1, pub_router) = build_test_routers(
        Arc::clone(&conn),
        tmp.path().to_path_buf(),
        allow_all_policy(),
        human_user(1),
    );
    let (auth_u2, _) = build_test_routers(
        Arc::clone(&conn),
        tmp.path().to_path_buf(),
        allow_all_policy(),
        human_user(2),
    );

    // Plugin tokens are rejected
    let (auth_plugin, _) = build_test_routers(
        Arc::clone(&conn),
        tmp.path().to_path_buf(),
        allow_all_policy(),
        plugin_user(1),
    );
    let plugin_resp = auth_plugin
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/shares")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(plugin_resp.status(), StatusCode::FORBIDDEN);

    // User 1 creates a share
    let create_resp = auth_u1
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"docs/reports/q4.txt"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let create_json = read_body_json(create_resp).await;
    let share_id = create_json["share"]["id"].as_str().unwrap().to_string();
    let share_url = create_json["share"]["url"].as_str().unwrap().to_string();
    assert!(share_url.starts_with("/share?token="));
    let raw_token = share_url.strip_prefix("/share?token=").unwrap().to_string();
    assert!(
        raw_token.len() >= 43,
        "256-bit base64url token must be >= 43 chars"
    );
    assert_eq!(create_json["share"]["path"], "docs/reports/q4.txt");
    assert_eq!(create_json["share"]["name"], "q4.txt");
    assert_eq!(create_json["share"]["is_directory"], false);
    assert_eq!(create_json["share"]["allow_download"], true);

    // Verify raw token is NOT stored in SQLite (only SHA-256 hash is stored)
    {
        let db = conn.lock().unwrap();
        let stored_hash: String = db
            .query_row(
                "SELECT token_hash FROM mcbrowser_shares WHERE id = ?1",
                params![share_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(stored_hash, raw_token);
        assert_eq!(stored_hash, hash_share_token(&raw_token));
    }

    // User 1 lists shares: raw token URL is not re-exposed on list
    let list_u1 = auth_u1
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/shares")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_u1.status(), StatusCode::OK);
    let list_u1_json = read_body_json(list_u1).await;
    let shares_u1 = list_u1_json["shares"].as_array().unwrap();
    assert_eq!(shares_u1.len(), 1);
    assert_eq!(shares_u1[0]["id"], share_id);
    assert!(shares_u1[0]["url"].is_null());

    // User 2 cannot see User 1's shares or delete User 1's share
    let list_u2 = auth_u2
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/shares")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list_u2_json = read_body_json(list_u2).await;
    assert!(list_u2_json["shares"].as_array().unwrap().is_empty());

    let del_by_u2 = auth_u2
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/mcbrowser/shares/{share_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_by_u2.status(), StatusCode::NOT_FOUND);

    // Public metadata works before revocation
    let meta_ok = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{raw_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(meta_ok.status(), StatusCode::OK);
    let meta_json = read_body_json(meta_ok).await;
    assert_eq!(meta_json["name"], "q4.txt");
    assert_eq!(meta_json["is_directory"], false);

    // User 1 revokes the share
    let del_by_u1 = auth_u1
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/mcbrowser/shares/{share_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_by_u1.status(), StatusCode::OK);

    // Public access immediately fails after revocation
    let meta_after_revoke = pub_router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{raw_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(meta_after_revoke.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn password_protected_share_enforces_unlock_cookie_and_header_and_rejects_query_passwords() {
    let tmp = TestTempDir::new();
    let bfs1 = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs1.create_directory_all("vault").unwrap();
    let user1_root = derive_user_root_path(tmp.path(), 1).unwrap();
    fs::write(user1_root.join("vault/secret.txt"), b"top-secret-payload").unwrap();

    let conn = Arc::new(Mutex::new(setup_isolated_db()));
    let (auth_u1, pub_router) = build_test_routers(
        Arc::clone(&conn),
        tmp.path().to_path_buf(),
        allow_all_policy(),
        human_user(1),
    );

    let create_resp = auth_u1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"path":"vault","password":"correct-horse-battery-staple"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let create_json = read_body_json(create_resp).await;
    assert_eq!(create_json["share"]["password_required"], true);
    assert!(create_json["share"].get("password").is_none());
    assert!(create_json["share"].get("password_hash").is_none());
    let raw_token = create_json["share"]["url"]
        .as_str()
        .unwrap()
        .strip_prefix("/share?token=")
        .unwrap()
        .to_string();

    // 1. Metadata requires no password and shows password_required: true
    let meta_resp = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{raw_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(meta_resp.status(), StatusCode::OK);
    let meta_json = read_body_json(meta_resp).await;
    assert_eq!(meta_json["name"], "vault");
    assert_eq!(meta_json["is_directory"], true);
    assert_eq!(meta_json["password_required"], true);

    // 2. ?password= in URL query string is rejected on entries and download
    for endpoint in ["entries", "download"] {
        let bad_q = pub_router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/mcbrowser/shares/{raw_token}/{endpoint}?path=secret.txt&password=correct-horse-battery-staple"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_q.status(), StatusCode::BAD_REQUEST);
    }

    // 3. Entries and download without unlock credential return 401
    let locked_entries = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{raw_token}/entries"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(locked_entries.status(), StatusCode::UNAUTHORIZED);

    let locked_dl = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/mcbrowser/shares/{raw_token}/download?path=secret.txt"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(locked_dl.status(), StatusCode::UNAUTHORIZED);

    // 4. Unlock with wrong password fails with 401
    let bad_unlock = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mcbrowser/shares/{raw_token}/unlock"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Real-IP", "10.99.1.10")
                .body(Body::from(r#"{"password":"wrong-password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_unlock.status(), StatusCode::UNAUTHORIZED);

    // 5. Unlock with correct password succeeds, returns access_token AND Set-Cookie
    let ok_unlock = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mcbrowser/shares/{raw_token}/unlock"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Real-IP", "10.99.1.10")
                .body(Body::from(r#"{"password":"correct-horse-battery-staple"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_unlock.status(), StatusCode::OK);
    let set_cookie = ok_unlock
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    let cookie_pair = set_cookie.split(';').next().unwrap().to_string();
    let unlock_json = read_body_json(ok_unlock).await;
    assert_eq!(unlock_json["success"], true);
    let access_token = unlock_json["access_token"].as_str().unwrap().to_string();

    // 6. Access entries using X-McBrowser-Share-Token header
    let entries_via_hdr = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{raw_token}/entries"))
                .header("X-McBrowser-Share-Token", &access_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(entries_via_hdr.status(), StatusCode::OK);
    let entries_json = read_body_json(entries_via_hdr).await;
    assert_eq!(entries_json["entries"].as_array().unwrap().len(), 1);
    assert_eq!(entries_json["entries"][0]["name"], "secret.txt");

    // 7. Download using scoped HttpOnly cookie (native browser anchor download flow)
    let dl_via_cookie = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/mcbrowser/shares/{raw_token}/download?path=secret.txt"
                ))
                .header(header::COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dl_via_cookie.status(), StatusCode::OK);
    assert_eq!(
        dl_via_cookie
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .unwrap(),
        "nosniff"
    );
    assert_eq!(
        dl_via_cookie.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert!(dl_via_cookie
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("attachment;"));
    let body_bytes = read_body_bytes(dl_via_cookie).await;
    assert_eq!(body_bytes, b"top-secret-payload");
}

#[tokio::test]
async fn brute_force_throttle_blocks_repeated_failed_unlock_attempts_with_bounded_state() {
    let tmp = TestTempDir::new();
    let _bfs = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    let user1_root = derive_user_root_path(tmp.path(), 1).unwrap();
    fs::write(user1_root.join("protected.txt"), b"data").unwrap();

    let conn = Arc::new(Mutex::new(setup_isolated_db()));
    let (auth_u1, pub_router) = build_test_routers(
        Arc::clone(&conn),
        tmp.path().to_path_buf(),
        allow_all_policy(),
        human_user(1),
    );

    let create_resp = auth_u1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"path":"protected.txt","password":"real-password-123"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let create_json = read_body_json(create_resp).await;
    let raw_token = create_json["share"]["url"]
        .as_str()
        .unwrap()
        .strip_prefix("/share?token=")
        .unwrap()
        .to_string();

    for _ in 0..MAX_FAILED_UNLOCKS_PER_SHARE_IP {
        let resp = pub_router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/mcbrowser/shares/{raw_token}/unlock"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("X-Real-IP", "198.51.100.77")
                    .body(Body::from(r#"{"password":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // 6th attempt from the same IP is throttled with 429 even if password is right
    let throttled = pub_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mcbrowser/shares/{raw_token}/unlock"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Real-IP", "198.51.100.77")
                .body(Body::from(r#"{"password":"real-password-123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn expiry_and_owner_suspension_are_checked_on_every_request_even_after_unlock() {
    let tmp = TestTempDir::new();
    let _bfs = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    let user1_root = derive_user_root_path(tmp.path(), 1).unwrap();
    fs::write(user1_root.join("report.txt"), b"hello-world").unwrap();

    let conn = Arc::new(Mutex::new(setup_isolated_db()));
    let (auth_u1, pub_router) = build_test_routers(
        Arc::clone(&conn),
        tmp.path().to_path_buf(),
        allow_all_policy(),
        human_user(1),
    );

    // Past expiration is rejected on creation
    let past_exp = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
    let bad_exp = auth_u1
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"path":"report.txt","expires_at":"{past_exp}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_exp.status(), StatusCode::BAD_REQUEST);

    // Create a valid password-protected share with future expiration
    let future_exp = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let create_resp = auth_u1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"path":"report.txt","password":"pw123","expires_at":"{future_exp}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_resp.status(), StatusCode::CREATED);
    let create_json = read_body_json(create_resp).await;
    let share_id = create_json["share"]["id"].as_str().unwrap().to_string();
    let raw_token = create_json["share"]["url"]
        .as_str()
        .unwrap()
        .strip_prefix("/share?token=")
        .unwrap()
        .to_string();

    // Unlock the share
    let unlock_resp = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/mcbrowser/shares/{raw_token}/unlock"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-Real-IP", "10.0.0.5")
                .body(Body::from(r#"{"password":"pw123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let access_token = read_body_json(unlock_resp).await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Suspend owner in user_quotas -> public download fails closed without leaking account state
    {
        let db = conn.lock().unwrap();
        db.execute(
            "UPDATE user_quotas SET status = 'suspended' WHERE user_id = 1",
            [],
        )
        .unwrap();
    }
    let suspended_dl = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{raw_token}/download"))
                .header("X-McBrowser-Share-Token", &access_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(suspended_dl.status(), StatusCode::NOT_FOUND);
    let err_json = read_body_json(suspended_dl).await;
    assert!(!err_json["message"].as_str().unwrap().contains("suspended"));

    // Restore owner status, then expire the share in DB -> fails closed immediately
    {
        let db = conn.lock().unwrap();
        db.execute(
            "UPDATE user_quotas SET status = 'active' WHERE user_id = 1",
            [],
        )
        .unwrap();
        let expired_ts = Utc::now().timestamp() - 10;
        let expired_str = (Utc::now() - chrono::Duration::seconds(10)).to_rfc3339();
        db.execute(
            "UPDATE mcbrowser_shares SET expires_at = ?1, expires_at_unix = ?2 WHERE id = ?3",
            params![expired_str, expired_ts, share_id],
        )
        .unwrap();
    }
    let expired_dl = pub_router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{raw_token}/download"))
                .header("X-McBrowser-Share-Token", &access_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expired_dl.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn single_file_share_vs_directory_share_scope_range_and_inode_replacement() {
    let tmp = TestTempDir::new();
    let bfs1 = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs1.create_directory_all("project/sub").unwrap();
    let user1_root = derive_user_root_path(tmp.path(), 1).unwrap();
    fs::write(user1_root.join("project/shared_file.txt"), b"0123456789").unwrap();
    fs::write(user1_root.join("project/sibling_secret.txt"), b"private").unwrap();
    fs::write(user1_root.join("project/sub/nested.txt"), b"nested-content").unwrap();

    let conn = Arc::new(Mutex::new(setup_isolated_db()));
    let (auth_u1, pub_router) = build_test_routers(
        Arc::clone(&conn),
        tmp.path().to_path_buf(),
        allow_all_policy(),
        human_user(1),
    );

    // 1. Create single-file share for "project/shared_file.txt"
    let file_share_resp = auth_u1
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"project/shared_file.txt"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let file_token = read_body_json(file_share_resp).await["share"]["url"]
        .as_str()
        .unwrap()
        .strip_prefix("/share?token=")
        .unwrap()
        .to_string();

    // Single-file share entries lists ONLY the single file, never sibling_secret.txt
    let file_entries_resp = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{file_token}/entries"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(file_entries_resp.status(), StatusCode::OK);
    let file_entries_json = read_body_json(file_entries_resp).await;
    let entries_arr = file_entries_json["entries"].as_array().unwrap();
    assert_eq!(entries_arr.len(), 1);
    assert_eq!(entries_arr[0]["name"], "shared_file.txt");

    // Single-file share rejects downloading sibling file
    let sibling_attempt = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/mcbrowser/shares/{file_token}/download?path=sibling_secret.txt"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sibling_attempt.status(), StatusCode::FORBIDDEN);

    // Single-file share supports HTTP Range download
    let range_dl = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{file_token}/download"))
                .header(header::RANGE, "bytes=2-5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(range_dl.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        range_dl.headers().get(header::CONTENT_RANGE).unwrap(),
        "bytes 2-5/10"
    );
    assert_eq!(read_body_bytes(range_dl).await, b"2345");

    // Replace "project/shared_file.txt" with a new inode (delete + recreate) -> share fails closed!
    fs::remove_file(user1_root.join("project/shared_file.txt")).unwrap();
    fs::write(user1_root.join("project/sibling_replacement.txt"), b"other").unwrap();
    fs::write(user1_root.join("project/shared_file.txt"), b"impostor").unwrap();
    // Force a different inode by linking/moving if filesystem reused inode:
    let st_impostor = fs::metadata(user1_root.join("project/shared_file.txt")).unwrap();
    {
        use std::os::unix::fs::MetadataExt;
        let db = conn.lock().unwrap();
        let orig_ino: i64 = db
            .query_row(
                "SELECT target_ino FROM mcbrowser_shares WHERE target_path = 'project/shared_file.txt'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        if st_impostor.ino() == orig_ino as u64 {
            // Keep first file alive while writing new file so kernel must allocate a distinct inode
            let hold = user1_root.join("project/.hold_old_ino");
            fs::rename(user1_root.join("project/shared_file.txt"), &hold).unwrap();
            fs::write(user1_root.join("project/shared_file.txt"), b"impostor2").unwrap();
            let _ = fs::remove_file(&hold);
        }
    }
    let replaced_dl = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{file_token}/download"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replaced_dl.status(), StatusCode::NOT_FOUND);

    // 2. Directory share with allow_download: false
    let dir_share_resp = auth_u1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"project","allow_download":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let dir_token = read_body_json(dir_share_resp).await["share"]["url"]
        .as_str()
        .unwrap()
        .strip_prefix("/share?token=")
        .unwrap()
        .to_string();

    // Browsing nested subdirectory works
    let sub_entries = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{dir_token}/entries?path=sub"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sub_entries.status(), StatusCode::OK);
    let sub_json = read_body_json(sub_entries).await;
    assert_eq!(sub_json["path"], "sub");
    assert_eq!(sub_json["entries"][0]["path"], "sub/nested.txt");

    // Downloading when allow_download == false is rejected with 403
    let disabled_dl = pub_router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/mcbrowser/shares/{dir_token}/download?path=sub/nested.txt"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disabled_dl.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn policy_denies_forbidden_share_and_filters_denied_descendants_and_symlinks() {
    let tmp = TestTempDir::new();
    let bfs1 = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs1.create_directory_all("workspace/public_docs").unwrap();
    bfs1.create_directory_all("workspace/denied_sub").unwrap();
    bfs1.create_directory_all("forbidden_root").unwrap();

    let user1_root = derive_user_root_path(tmp.path(), 1).unwrap();
    fs::write(user1_root.join("workspace/allowed.txt"), b"ok").unwrap();
    fs::write(user1_root.join("workspace/secret.key"), b"denied-file").unwrap();
    fs::write(
        user1_root.join("workspace/denied_sub/inside.txt"),
        b"denied-nested",
    )
    .unwrap();
    symlink(
        user1_root.join("workspace/allowed.txt"),
        user1_root.join("workspace/symlink.txt"),
    )
    .unwrap();
    fs::write(user1_root.join("workspace/hardlink_src.txt"), b"hl").unwrap();
    fs::hard_link(
        user1_root.join("workspace/hardlink_src.txt"),
        user1_root.join("workspace/hardlink_alias.txt"),
    )
    .unwrap();

    // Policy with dynamic toggle so we can test both:
    // (a) share creation rejecting a directory with denied actual descendants, and
    // (b) an existing directory share filtering/blocking descendants after policy changes.
    let deny_descendants = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let deny_flag = Arc::clone(&deny_descendants);
    let custom_policy: PolicyAuthorizer = Arc::new(move |_conn, _user, _perm, path| {
        if path == "forbidden_root" || path.starts_with("forbidden_root/") {
            return Err(McBrowserError::Forbidden(
                "Policy denies access to this path".to_string(),
            ));
        }
        if deny_flag.load(std::sync::atomic::Ordering::SeqCst)
            && (path == "workspace/secret.key"
                || path == "workspace/denied_sub"
                || path.starts_with("workspace/denied_sub/"))
        {
            return Err(McBrowserError::Forbidden(
                "Policy denies access to this path".to_string(),
            ));
        }
        Ok(())
    });

    let conn = Arc::new(Mutex::new(setup_isolated_db()));
    let (auth_u1, pub_router) = build_test_routers(
        Arc::clone(&conn),
        tmp.path().to_path_buf(),
        custom_policy,
        human_user(1),
    );

    // 1. Sharing a policy-forbidden root, a directory containing denied actual descendants,
    //    or a symlink/hardlink fails with 403
    for forbidden_target in [
        "forbidden_root",
        "workspace",
        "workspace/secret.key",
        "workspace/symlink.txt",
        "workspace/hardlink_src.txt",
    ] {
        let resp = auth_u1
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcbrowser/shares")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"path":"{forbidden_target}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "target {forbidden_target} must be rejected"
        );
    }

    // 2. Create share on "workspace" while descendants are permitted, then enable descendant deny
    //    rules and verify per-entry policy rules + symlink/hardlink filtering ensure denied
    //    descendants, symlinks, and hardlinks are NEVER exposed!
    deny_descendants.store(false, std::sync::atomic::Ordering::SeqCst);
    let share_ws = auth_u1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"workspace"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(share_ws.status(), StatusCode::CREATED);
    let ws_token = read_body_json(share_ws).await["share"]["url"]
        .as_str()
        .unwrap()
        .strip_prefix("/share?token=")
        .unwrap()
        .to_string();
    deny_descendants.store(true, std::sync::atomic::Ordering::SeqCst);

    let entries_resp = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{ws_token}/entries"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(entries_resp.status(), StatusCode::OK);
    let entries_json = read_body_json(entries_resp).await;
    let names: Vec<String> = entries_json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["public_docs", "allowed.txt"]);

    // 3. Direct access to denied descendants or symlinks/hardlinks inside the share is rejected with 403
    for blocked_sub in [
        "secret.key",
        "denied_sub/inside.txt",
        "symlink.txt",
        "hardlink_src.txt",
    ] {
        let dl_blocked = pub_router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/mcbrowser/shares/{ws_token}/download?path={blocked_sub}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            dl_blocked.status(),
            StatusCode::FORBIDDEN,
            "direct download of {blocked_sub} must be forbidden"
        );
    }

    let entries_denied_sub = pub_router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/mcbrowser/shares/{ws_token}/entries?path=denied_sub"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(entries_denied_sub.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn default_policy_authorizer_enforces_real_sqlite_policy_and_regex_rules() {
    let tmp = TestTempDir::new();
    let bfs1 = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs1.create_directory_all("docs/private").unwrap();
    bfs1.create_directory_all("regex_dir/sub").unwrap();
    let user1_root = derive_user_root_path(tmp.path(), 1).unwrap();
    fs::write(user1_root.join("docs/readme.txt"), b"public-readme").unwrap();
    fs::write(user1_root.join("docs/private/secret.txt"), b"secret").unwrap();
    fs::write(user1_root.join("regex_dir/ok.txt"), b"ok").unwrap();
    fs::write(user1_root.join("regex_dir/sub/credential.secret"), b"nope").unwrap();

    let conn = Arc::new(Mutex::new(setup_isolated_db()));
    let (auth_u1, pub_router) = build_test_routers(
        Arc::clone(&conn),
        tmp.path().to_path_buf(),
        default_policy_authorizer(),
        human_user(1),
    );

    // Insert a real prefix deny rule for "docs/private" AND a regex deny rule for "\.secret$"
    {
        let db = conn.lock().unwrap();
        policy::authorize_with_conn(&db, &human_user(1), Permission::Read, "docs/readme.txt")
            .unwrap();
        db.execute(
            r#"
            INSERT INTO mcbrowser_policies (user_id, perm_read, perm_create, perm_rename, perm_modify, perm_delete, perm_share, perm_download, scope)
            VALUES (1, 1, 1, 1, 1, 1, 1, 1, '');
            "#,
            [],
        )
        .unwrap();
        db.execute(
            r#"
            INSERT INTO mcbrowser_policy_rules (user_id, rule_order, path, allow, regex, expression)
            VALUES (1, 0, 'docs/private', 0, 0, NULL),
                   (1, 1, '\.secret$', 0, 1, '\.secret$');
            "#,
            [],
        )
        .unwrap();
    }

    // 1. Sharing "docs" when a descendant ("docs/private") has a prefix deny rule is blocked with 403
    let parent_share_blocked = auth_u1
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"docs"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(parent_share_blocked.status(), StatusCode::FORBIDDEN);

    // 2. Sharing "regex_dir" when an actual descendant ("regex_dir/sub/credential.secret") matches
    //    a regex deny rule is ALSO blocked with 403 because create_share_at walks actual descendants!
    let regex_dir_blocked = auth_u1
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"regex_dir"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(regex_dir_blocked.status(), StatusCode::FORBIDDEN);

    // 3. Sharing "docs/readme.txt" succeeds, and if owner's perm_share is later revoked, public access fails closed
    let file_share = auth_u1
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"docs/readme.txt"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(file_share.status(), StatusCode::CREATED);
    let token = read_body_json(file_share).await["share"]["url"]
        .as_str()
        .unwrap()
        .strip_prefix("/share?token=")
        .unwrap()
        .to_string();

    let ok_dl = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{token}/download"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_dl.status(), StatusCode::OK);

    // Revoke owner's perm_share in mcbrowser_policies -> public access immediately fails closed (404)
    {
        let db = conn.lock().unwrap();
        db.execute(
            "UPDATE mcbrowser_policies SET perm_share = 0 WHERE user_id = 1",
            [],
        )
        .unwrap();
    }

    let revoked_policy_dl = pub_router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{token}/download"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked_policy_dl.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn scoped_policy_root_confines_shares_and_fails_closed_on_scope_change() {
    let tmp = TestTempDir::new();
    let bfs1 = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs1.create_directory_all("team_a/sub").unwrap();
    bfs1.create_directory_all("team_b/sub").unwrap();
    let user1_root = derive_user_root_path(tmp.path(), 1).unwrap();
    fs::write(user1_root.join("root_only.txt"), b"raw-root-data").unwrap();
    fs::write(user1_root.join("team_a/report.txt"), b"team-a-secret").unwrap();
    fs::write(user1_root.join("team_a/sub/item.txt"), b"team-a-sub").unwrap();
    fs::write(
        user1_root.join("team_b/report.txt"),
        b"team-b-different-root",
    )
    .unwrap();

    let conn = Arc::new(Mutex::new(setup_isolated_db()));
    let (auth_u1, pub_router) = build_test_routers(
        Arc::clone(&conn),
        tmp.path().to_path_buf(),
        default_policy_authorizer(),
        human_user(1),
    );

    // 1. Create a share while user is in raw root scope ("")
    let raw_root_share = auth_u1
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"root_only.txt"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(raw_root_share.status(), StatusCode::CREATED);
    let raw_root_token = read_body_json(raw_root_share).await["share"]["url"]
        .as_str()
        .unwrap()
        .strip_prefix("/share?token=")
        .unwrap()
        .to_string();

    // 2. Admin changes user 1's policy scope to "team_a"
    {
        let db = conn.lock().unwrap();
        policy::authorize_with_conn(&db, &human_user(1), Permission::Read, "root_only.txt")
            .unwrap();
        db.execute(
            r#"
            INSERT INTO mcbrowser_policies (user_id, perm_read, perm_create, perm_rename, perm_modify, perm_delete, perm_share, perm_download, scope)
            VALUES (1, 1, 1, 1, 1, 1, 1, 1, 'team_a');
            "#,
            [],
        )
        .unwrap();
    }

    // Existing raw-root share MUST fail closed (404) on all public routes and disappear from list_shares
    let raw_meta_after_scope = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{raw_root_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(raw_meta_after_scope.status(), StatusCode::NOT_FOUND);

    let raw_dl_after_scope = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{raw_root_token}/download"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(raw_dl_after_scope.status(), StatusCode::NOT_FOUND);

    // 3. Under scope "team_a", raw user-root files ("root_only.txt") are unreachable (404),
    //    while scoped-relative paths ("report.txt", "sub") resolve inside <user1_root>/team_a!
    let unreach_resp = auth_u1
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"root_only.txt"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unreach_resp.status(), StatusCode::NOT_FOUND);

    let team_a_share = auth_u1
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/shares")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"path":"report.txt"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(team_a_share.status(), StatusCode::CREATED);
    let team_a_token = read_body_json(team_a_share).await["share"]["url"]
        .as_str()
        .unwrap()
        .strip_prefix("/share?token=")
        .unwrap()
        .to_string();

    let team_a_dl = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{team_a_token}/download"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(team_a_dl.status(), StatusCode::OK);
    assert_eq!(read_body_bytes(team_a_dl).await, b"team-a-secret");

    // 4. Admin changes scope from "team_a" to "team_b" (which ALSO has a "report.txt"!).
    //    The existing share for "report.txt" MUST fail closed (404) and NEVER serve "team_b/report.txt"!
    {
        let db = conn.lock().unwrap();
        db.execute(
            "UPDATE mcbrowser_policies SET scope = 'team_b' WHERE user_id = 1",
            [],
        )
        .unwrap();
    }

    let cross_scope_dl = pub_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{team_a_token}/download"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_scope_dl.status(), StatusCode::NOT_FOUND);

    let cross_scope_meta = pub_router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/mcbrowser/shares/{team_a_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_scope_meta.status(), StatusCode::NOT_FOUND);
}

#[test]
fn share_create_and_revoke_emit_audit_events_and_roll_back_on_audit_failure() {
    let tmp = TestTempDir::new();
    let bfs1 = open_user_browser_fs_at(tmp.path(), 1).unwrap();
    bfs1.create_directory_all("docs").unwrap();
    let user1_root = derive_user_root_path(tmp.path(), 1).unwrap();
    fs::write(user1_root.join("docs/notes.txt"), b"shared-notes").unwrap();

    let conn = setup_isolated_db();
    let policy = allow_all_policy();
    let alice = human_user(1);

    conn.execute(
        "INSERT INTO mcbrowser_event_settings (id, queue_enabled, updated_at) VALUES (1, 1, '2026-01-01T00:00:00Z')",
        [],
    )
    .unwrap();

    conn.execute_batch(
        "CREATE TRIGGER fail_audit_pending BEFORE INSERT ON mcbrowser_audit_events \
         BEGIN SELECT RAISE(ABORT, 'simulated pending audit failure'); END;",
    )
    .unwrap();

    let err_pending = create_share_at(
        &conn,
        tmp.path(),
        &policy,
        &alice,
        CreateShareRequest {
            path: "docs/notes.txt".to_string(),
            password: None,
            expires_at: None,
            allow_download: Some(true),
        },
    )
    .unwrap_err();
    assert!(matches!(err_pending, McBrowserError::Internal(_)));

    let share_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_shares", [], |r| r.get(0))
        .unwrap();
    assert_eq!(share_count, 0);

    conn.execute_batch("DROP TRIGGER fail_audit_pending;")
        .unwrap();

    conn.execute_batch(
        "CREATE TRIGGER fail_audit_queue BEFORE INSERT ON mcbrowser_event_queue \
         BEGIN SELECT RAISE(ABORT, 'simulated queue completion failure'); END;",
    )
    .unwrap();

    let err_complete = create_share_at(
        &conn,
        tmp.path(),
        &policy,
        &alice,
        CreateShareRequest {
            path: "docs/notes.txt".to_string(),
            password: None,
            expires_at: None,
            allow_download: Some(true),
        },
    )
    .unwrap_err();
    assert!(matches!(err_complete, McBrowserError::Internal(_)));

    let share_count_after_complete_err: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_shares", [], |r| r.get(0))
        .unwrap();
    assert_eq!(share_count_after_complete_err, 0);

    let (failed_trigger, failed_status): (String, String) = conn
        .query_row(
            "SELECT trigger, status FROM mcbrowser_audit_events ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(failed_trigger, "share_created");
    assert_eq!(failed_status, "failed");

    let queue_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(queue_count, 0);

    conn.execute_batch("DROP TRIGGER fail_audit_queue;")
        .unwrap();

    let (share, _raw_token) = create_share_at(
        &conn,
        tmp.path(),
        &policy,
        &alice,
        CreateShareRequest {
            path: "docs/notes.txt".to_string(),
            password: None,
            expires_at: None,
            allow_download: Some(true),
        },
    )
    .unwrap();

    let (created_trigger, created_path, created_delta, created_status): (String, String, i64, String) = conn
        .query_row(
            "SELECT trigger, relative_path, byte_delta, status FROM mcbrowser_audit_events ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(created_trigger, "share_created");
    assert_eq!(created_path, "docs/notes.txt");
    assert_eq!(created_delta, 0);
    assert_eq!(created_status, "completed");

    let queue_after_create: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(queue_after_create, 1);

    let missing_revoke = delete_share_at(&conn, &alice, "nonexistent-share-id").unwrap_err();
    assert!(matches!(missing_revoke, McBrowserError::NotFound(_)));
    let queue_after_missing: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(queue_after_missing, 1);

    conn.execute_batch(
        "CREATE TRIGGER fail_revoke_pending BEFORE INSERT ON mcbrowser_audit_events \
         BEGIN SELECT RAISE(ABORT, 'simulated revoke pending failure'); END;",
    )
    .unwrap();

    let revoke_pending_err = delete_share_at(&conn, &alice, &share.id).unwrap_err();
    assert!(matches!(revoke_pending_err, McBrowserError::Internal(_)));
    let revoked_flag: i64 = conn
        .query_row(
            "SELECT revoked FROM mcbrowser_shares WHERE id = ?1",
            params![&share.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(revoked_flag, 0);

    conn.execute_batch("DROP TRIGGER fail_revoke_pending;")
        .unwrap();

    conn.execute_batch(
        "CREATE TRIGGER fail_revoke_queue BEFORE INSERT ON mcbrowser_event_queue \
         BEGIN SELECT RAISE(ABORT, 'simulated revoke queue failure'); END;",
    )
    .unwrap();

    let revoke_queue_err = delete_share_at(&conn, &alice, &share.id).unwrap_err();
    assert!(matches!(revoke_queue_err, McBrowserError::Internal(_)));
    let revoked_flag_after_queue_err: i64 = conn
        .query_row(
            "SELECT revoked FROM mcbrowser_shares WHERE id = ?1",
            params![&share.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(revoked_flag_after_queue_err, 0);

    conn.execute_batch("DROP TRIGGER fail_revoke_queue;")
        .unwrap();

    delete_share_at(&conn, &alice, &share.id).unwrap();

    let revoked_flag_final: i64 = conn
        .query_row(
            "SELECT revoked FROM mcbrowser_shares WHERE id = ?1",
            params![&share.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(revoked_flag_final, 1);

    let (revoked_trigger, revoked_path, revoked_delta, revoked_status): (String, String, i64, String) = conn
        .query_row(
            "SELECT trigger, relative_path, byte_delta, status FROM mcbrowser_audit_events ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(revoked_trigger, "share_revoked");
    assert_eq!(revoked_path, "docs/notes.txt");
    assert_eq!(revoked_delta, 0);
    assert_eq!(revoked_status, "completed");

    let queue_after_revoke: i64 = conn
        .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(queue_after_revoke, 2);
}
