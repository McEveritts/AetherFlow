use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use serde_json::{json, Value};
use std::path::PathBuf;
use tower::ServiceExt;

struct StreamingHttpFixture {
    directory: PathBuf,
    previous_database: Option<std::ffi::OsString>,
    router: Router,
    admin_token: String,
    linked_token: String,
    unlinked_token: String,
}

impl StreamingHttpFixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("af-streaming-http-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let previous_database = std::env::var_os("DB_PATH");
        std::env::set_var("DB_PATH", directory.join("history.sqlite"));
        af_db::init_db().unwrap();
        {
            let connection = af_db::get_conn().unwrap();
            connection.execute_batch(
                "INSERT INTO users(id,username,role) VALUES (1,'stream-admin','admin'),(2,'linked-viewer','user'),(3,'unlinked-viewer','user');
                 INSERT INTO streaming_history(id,session_key,provider,server_id,user_id,user_name,item_id,item_name,provenance,timestamp_certainty,byte_accuracy,watched_secs,started_at,ip_address,device_id)
                 VALUES (10,'http-observed-10','jellyfin','server-main','provider-alice','Alice','item-alice','Linked Private Movie','observed_session','observed','unrecorded',120,'2026-10-31 20:00:00','198.51.100.42','secret-device-alice'),
                        (11,'http-observed-11','jellyfin','server-main','provider-bob','Bob','item-bob','Other Private Movie','observed_session','observed','unrecorded',90,'2026-10-31 21:00:00','198.51.100.43','secret-device-bob');
                 INSERT INTO streaming_user_links(af_user_id,provider,server_id,provider_user_id) VALUES (2,'jellyfin','server-main','provider-alice');
                 INSERT INTO streaming_history_labels(history_id,kind,value,name) VALUES (10,'library','library-films','Films');
                 UPDATE streaming_servers SET api_key='fixture-provider-secret',enabled=0;"
            ).unwrap();
        }
        let admin_token = crate::auth::create_standard_jwt(1, &HeaderMap::new())
            .unwrap()
            .0;
        let linked_token = crate::auth::create_standard_jwt(2, &HeaderMap::new())
            .unwrap()
            .0;
        let unlinked_token = crate::auth::create_standard_jwt(3, &HeaderMap::new())
            .unwrap()
            .0;
        Self {
            directory,
            previous_database,
            router: crate::routes::build_router(),
            admin_token,
            linked_token,
            unlinked_token,
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Response {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = match body {
            Some(value) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&value).unwrap())
            }
            None => Body::empty(),
        };
        self.router
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap()
    }
}

impl Drop for StreamingHttpFixture {
    fn drop(&mut self) {
        match &self.previous_database {
            Some(path) => std::env::set_var("DB_PATH", path),
            None => std::env::remove_var("DB_PATH"),
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

async fn response_json(response: Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "Manual local browser acceptance fixture; never starts application background workers"]
async fn disposable_streaming_browser_acceptance_server() {
    assert_eq!(
        std::env::var("AF_STREAMING_BROWSER_ACCEPTANCE").as_deref(),
        Ok("1")
    );
    let fixture = StreamingHttpFixture::new();
    let nonce = uuid::Uuid::new_v4().to_string();
    af_db::get_conn()
        .unwrap()
        .execute("UPDATE settings SET setup_completed=1", [])
        .unwrap();
    let admin_login = format!("/__streaming_acceptance/{nonce}/admin");
    let linked_login = format!("/__streaming_acceptance/{nonce}/linked");
    let unlinked_login = format!("/__streaming_acceptance/{nonce}/unlinked");
    let mut router = fixture.router.clone();
    for (path, user_id) in [(&admin_login, 1), (&linked_login, 2), (&unlinked_login, 3)] {
        router = router.route(path, axum::routing::get(move |headers: HeaderMap| {
            async move {
                let token = crate::auth::create_standard_jwt(user_id, &headers).unwrap().0;
                (
                    StatusCode::SEE_OTHER,
                    [
                        (header::SET_COOKIE, format!("aetherflow_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=900")),
                        (header::LOCATION, "/".to_string()),
                        (header::CACHE_CONTROL, "no-store".to_string()),
                    ],
                )
            }
        }));
    }
    router = router.layer(axum::middleware::from_fn(
        |request: Request<Body>, next: axum::middleware::Next| async move {
            let path = request.uri().path();
            let allowed_read = request.method() == Method::GET
                && (!path.starts_with("/api/")
                    || path == "/api/v1/auth/session"
                    || path == "/api/v1/auth/ws/ticket"
                    || path == "/api/v1/auth/settings"
                    || path == "/api/v1/auth/system/metrics"
                    || path == "/api/v1/public/csrf-token"
                    || path.starts_with("/api/v1/auth/streaming/")
                    || path.starts_with("/api/v1/admin/streaming/"));
            let allowed_preview = request.method() == Method::POST
                && path == "/api/v1/admin/streaming/portability/preview";
            if !allowed_read && !allowed_preview {
                return crate::auth::api_error(
                    StatusCode::FORBIDDEN,
                    "acceptance_fixture_read_only",
                    "This disposable fixture does not allow this action",
                );
            }
            let root_page = path == "/";
            let mut response = next.run(request).await;
            if root_page && response.status() == StatusCode::OK {
                let bytes = to_bytes(
                    std::mem::replace(response.body_mut(), Body::empty()),
                    2 * 1024 * 1024,
                )
                .await
                .unwrap();
                let html = String::from_utf8(bytes.to_vec()).unwrap().replacen(
                    "<head>",
                    "<head><script>window.__AF_DISABLE_WS__=true;</script>",
                    1,
                );
                response.headers_mut().remove(header::CONTENT_LENGTH);
                *response.body_mut() = Body::from(html);
            }
            response
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    println!("DISPOSABLE_STREAMING_ADMIN=http://{address}{admin_login}");
    println!("DISPOSABLE_STREAMING_LINKED=http://{address}{linked_login}");
    println!("DISPOSABLE_STREAMING_UNLINKED=http://{address}{unlinked_login}");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.unwrap();
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn mounted_streaming_routes_enforce_scope_approval_backup_and_restore_isolation() {
    if std::env::var("AF_STREAMING_HTTP_CHILD").as_deref() != Ok("1") {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "streaming_http_tests::mounted_streaming_routes_enforce_scope_approval_backup_and_restore_isolation", "--nocapture"])
            .env("AF_STREAMING_HTTP_CHILD", "1").status().unwrap();
        assert!(status.success(), "isolated mounted HTTP acceptance failed");
        return;
    }
    let fixture = StreamingHttpFixture::new();
    let history_path = "/api/v1/auth/streaming/history?window=all";
    let anonymous = fixture.request(Method::GET, history_path, None, None).await;
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let linked = fixture
        .request(Method::GET, history_path, Some(&fixture.linked_token), None)
        .await;
    assert_eq!(linked.status(), StatusCode::OK);
    let linked = response_json(linked).await;
    assert_eq!(linked["items"].as_array().unwrap().len(), 1);
    assert_eq!(linked["items"][0]["itemName"], "Linked Private Movie");
    assert!(linked["items"][0].get("ipAddress").is_none());
    assert!(linked["items"][0].get("deviceId").is_none());
    assert_eq!(linked["counts"]["confirmedPlays"], 1);
    let snapshot = linked["scope"]["snapshotToken"].as_str().unwrap();

    let unlinked = response_json(
        fixture
            .request(
                Method::GET,
                history_path,
                Some(&fixture.unlinked_token),
                None,
            )
            .await,
    )
    .await;
    assert!(unlinked["items"].as_array().unwrap().is_empty());
    assert_eq!(unlinked["counts"]["confirmedPlays"], 0);

    let csv = fixture
        .request(
            Method::GET,
            "/api/v1/auth/streaming/history/export?window=all",
            Some(&fixture.linked_token),
            None,
        )
        .await;
    assert_eq!(csv.status(), StatusCode::OK);
    let csv = String::from_utf8(
        to_bytes(csv.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(csv.contains("Linked Private Movie"));
    for private_value in [
        "Other Private Movie",
        "198.51.100.42",
        "198.51.100.43",
        "secret-device-alice",
        "secret-device-bob",
        "fixture-provider-secret",
    ] {
        assert!(!csv.contains(private_value));
    }

    for (method, path) in [
        (Method::GET, "/api/v1/auth/fs?path=/var/lib/aetherflow"),
        (Method::GET, "/api/v1/admin/streaming/portability/export"),
        (Method::POST, "/api/v1/admin/streaming/portability/preview"),
        (Method::POST, "/api/v1/admin/streaming/portability/restore"),
        (Method::POST, "/api/v1/admin/streaming/imports/events"),
        (Method::PUT, "/api/v1/admin/streaming/policies"),
        (Method::PUT, "/api/v1/admin/streaming/user-links"),
        (Method::POST, "/api/v1/admin/streaming/reconciliation/apply"),
    ] {
        let response = fixture
            .request(method, path, Some(&fixture.linked_token), Some(json!({})))
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }

    let export = fixture
        .request(
            Method::GET,
            "/api/v1/admin/streaming/portability/export",
            Some(&fixture.admin_token),
            None,
        )
        .await;
    assert_eq!(export.status(), StatusCode::OK);
    assert_eq!(
        export.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let archive = response_json(export).await;
    assert_eq!(archive["manifest"]["recordCounts"]["history"], 2);
    let serialized = serde_json::to_string(&archive).unwrap();
    for private_value in [
        "fixture-provider-secret",
        "secret-device-alice",
        "secret-device-bob",
        "198.51.100.42",
        "198.51.100.43",
    ] {
        assert!(!serialized.contains(private_value));
    }

    let preview_path = "/api/v1/admin/streaming/portability/preview";
    let restore_path = "/api/v1/admin/streaming/portability/restore";
    let payload = json!({"archive": archive, "mode": "replace"});
    let preview = fixture
        .request(
            Method::POST,
            preview_path,
            Some(&fixture.admin_token),
            Some(payload.clone()),
        )
        .await;
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = response_json(preview).await;
    assert!(preview["approvalToken"].as_str().is_some());
    {
        let connection = af_db::get_conn().unwrap();
        let audits: i64 = connection
            .query_row("SELECT COUNT(*) FROM streaming_history_audit", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(audits, 0);
    }

    let cookie_request = Request::builder()
        .method(Method::POST)
        .uri(preview_path)
        .header(
            header::COOKIE,
            format!("aetherflow_session={}", fixture.admin_token),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let csrf_denied = fixture
        .router
        .clone()
        .oneshot(cookie_request)
        .await
        .unwrap();
    assert_eq!(csrf_denied.status(), StatusCode::FORBIDDEN);
    let unsigned = fixture
        .request(
            Method::POST,
            restore_path,
            Some(&fixture.admin_token),
            Some(payload.clone()),
        )
        .await;
    assert!(!unsigned.status().is_success());

    af_db::get_conn()
        .unwrap()
        .execute(
            "UPDATE streaming_history SET watched_secs=watched_secs+1 WHERE id=10",
            [],
        )
        .unwrap();
    let stable_history = fixture
        .request(
            Method::GET,
            &format!("{history_path}&snapshot={snapshot}"),
            Some(&fixture.linked_token),
            None,
        )
        .await;
    assert_eq!(stable_history.status(), StatusCode::OK);
    let stale_payload =
        json!({"archive": archive, "mode": "replace", "approvalToken": preview["approvalToken"]});
    let stale_restore = fixture
        .request(
            Method::POST,
            restore_path,
            Some(&fixture.admin_token),
            Some(stale_payload),
        )
        .await;
    assert_eq!(stale_restore.status(), StatusCode::CONFLICT);

    af_db::get_conn().unwrap().execute(
        "UPDATE streaming_user_links SET provider_user_id='new-explicit-identity' WHERE af_user_id=2",
        [],
    ).unwrap();
    let stale_identity = fixture
        .request(
            Method::GET,
            &format!("{history_path}&snapshot={snapshot}"),
            Some(&fixture.linked_token),
            None,
        )
        .await;
    assert_eq!(stale_identity.status(), StatusCode::CONFLICT);

    let fresh = response_json(
        fixture
            .request(
                Method::POST,
                preview_path,
                Some(&fixture.admin_token),
                Some(payload),
            )
            .await,
    )
    .await;
    let approved =
        json!({"archive": archive, "mode": "replace", "approvalToken": fresh["approvalToken"]});
    let restored = fixture
        .request(
            Method::POST,
            restore_path,
            Some(&fixture.admin_token),
            Some(approved),
        )
        .await;
    assert_eq!(restored.status(), StatusCode::OK);
    let restored = response_json(restored).await;
    assert_eq!(restored["backupVerified"], true);
    assert_eq!(restored["resultingCounts"]["history"], 2);
    let connection = af_db::get_conn().unwrap();
    let users: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM users WHERE id IN (1,2,3)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let audits: i64 = connection
        .query_row("SELECT COUNT(*) FROM streaming_history_audit", [], |row| {
            row.get(0)
        })
        .unwrap();
    let watched: i64 = connection
        .query_row(
            "SELECT watched_secs FROM streaming_history WHERE id=10",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(users, 3);
    assert_eq!(audits, 1);
    assert_eq!(watched, 120);
}
