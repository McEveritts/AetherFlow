use super::*;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

#[path = "mcbrowser_archive_http_tests.rs"]
mod archive_alias_tests;

#[tokio::test]
async fn mounted_media_aliases_enforce_requested_intermediate_and_target_read_policy() {
    use std::os::unix::fs::symlink;

    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let initialized = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/directory",
        serde_json::json!({"path": "target"}),
    )
    .await;
    assert_eq!(initialized.status(), StatusCode::CREATED);
    af_db::get_conn()
        .unwrap()
        .execute("INSERT INTO mcbrowser_policies (user_id) VALUES (1)", [])
        .unwrap();
    let mut png = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        4,
        4,
        image::Rgba([255, 0, 0, 255]),
    ))
    .write_to(&mut png, image::ImageFormat::Png)
    .unwrap();
    fs::write(
        fixture.user_root().join("target/photo.png"),
        png.into_inner(),
    )
    .unwrap();
    fs::write(
        fixture.user_root().join("target/table.csv"),
        b"name,value\nalice,7\n",
    )
    .unwrap();
    fs::write(
        fixture.user_root().join("target/captions.vtt"),
        b"WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nhello\n",
    )
    .unwrap();
    symlink("target", fixture.user_root().join("hop")).unwrap();
    symlink("hop", fixture.user_root().join("links")).unwrap();
    symlink("links/photo.png", fixture.user_root().join("leaf.png")).unwrap();
    let endpoints = [
        "/mcbrowser/media?path=links/photo.png",
        "/mcbrowser/media-info?path=links/photo.png",
        "/mcbrowser/media?path=leaf.png",
        "/mcbrowser/media-info?path=leaf.png",
        "/mcbrowser/thumbnail?path=links/photo.png",
        "/mcbrowser/preview/thumb?path=links/photo.png",
        "/mcbrowser/preview/big?path=links/photo.png",
        "/mcbrowser/csv?path=links/table.csv",
        "/mcbrowser/subtitle?path=links/captions.vtt",
    ];
    for denied_path in [None, Some("links"), Some("hop"), Some("target")] {
        {
            let connection = af_db::get_conn().unwrap();
            connection
                .execute("DELETE FROM mcbrowser_policy_rules WHERE user_id = 1", [])
                .unwrap();
            if let Some(path) = denied_path {
                connection.execute(
                    "INSERT INTO mcbrowser_policy_rules (user_id, rule_order, path, allow) VALUES (1, 0, ?1, 0)",
                    [path],
                ).unwrap();
            }
        }
        for endpoint in endpoints {
            let response =
                request_json(fixture.router(), "GET", endpoint, serde_json::Value::Null).await;
            let expected = if denied_path.is_some() {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::OK
            };
            assert_eq!(response.status(), expected, "{endpoint}: {denied_path:?}");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            if denied_path.is_some() {
                let text = std::str::from_utf8(&body).unwrap();
                assert!(!text.contains("alice,7"));
                assert!(!text.contains("hello"));
            } else if endpoint.starts_with("/mcbrowser/media-info?") {
                let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let alias = endpoint.split_once("path=").unwrap().1;
                assert_eq!(payload["path"], alias);
                assert_eq!(payload["name"], alias.rsplit('/').next().unwrap());
                assert_eq!(payload["kind"], "file");
                assert_eq!(payload["resolution"]["width"], 4);
                assert_eq!(payload["resolution"]["height"], 4);
            } else if endpoint.starts_with("/mcbrowser/media?") {
                assert_eq!(
                    body.as_ref(),
                    fs::read(fixture.user_root().join("target/photo.png")).unwrap()
                );
            }
        }
    }
}

#[tokio::test]
async fn mounted_video_alias_subtitles_preserve_aliases_and_enforce_each_read_path() {
    use std::os::unix::fs::symlink;

    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/directory",
        serde_json::json!({"path": "target"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    af_db::get_conn()
        .unwrap()
        .execute(
            "INSERT INTO mcbrowser_policies (user_id, perm_execute) VALUES (1, 1)",
            [],
        )
        .unwrap();
    fs::write(
        fixture.user_root().join("target/movie.mp4"),
        b"\0\0\0\x18ftypisom\0\0\x02\0isomiso2",
    )
    .unwrap();
    let captions = b"WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nhello\n";
    fs::write(fixture.user_root().join("target/movie.en.vtt"), captions).unwrap();
    fs::write(fixture.user_root().join("leaf.en.vtt"), captions).unwrap();
    symlink("target", fixture.user_root().join("hop")).unwrap();
    symlink("hop", fixture.user_root().join("links")).unwrap();
    symlink("links/movie.mp4", fixture.user_root().join("leaf.mp4")).unwrap();

    for path in ["links/movie.mp4", "leaf.mp4"] {
        for route in ["subtitles", "media-info"] {
            let endpoint = format!("/mcbrowser/{route}?path={path}");
            let response =
                request_json(fixture.router(), "GET", &endpoint, serde_json::Value::Null).await;
            assert_eq!(response.status(), StatusCode::OK, "{endpoint}");
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let expected = if path.starts_with("links/") {
                "links/movie.en.vtt"
            } else {
                "leaf.en.vtt"
            };
            assert_eq!(payload["subtitles"][0]["path"], expected);
            assert!(!std::str::from_utf8(&body).unwrap().contains("target/"));
        }
        for denied in [path, "hop/movie.mp4", "target/movie.mp4"] {
            {
                let connection = af_db::get_conn().unwrap();
                connection
                    .execute("DELETE FROM mcbrowser_policy_rules WHERE user_id = 1", [])
                    .unwrap();
                connection.execute(
                    "INSERT INTO mcbrowser_policy_rules (user_id, rule_order, path, allow) VALUES (1, 0, ?1, 0)", [denied],
                ).unwrap();
            }
            for route in ["subtitles", "subtitle", "media-info"] {
                let endpoint = format!("/mcbrowser/{route}?path={path}");
                let response =
                    request_json(fixture.router(), "GET", &endpoint, serde_json::Value::Null).await;
                assert_eq!(
                    response.status(),
                    StatusCode::FORBIDDEN,
                    "{endpoint}: {denied}"
                );
            }
        }
        af_db::get_conn()
            .unwrap()
            .execute("DELETE FROM mcbrowser_policy_rules WHERE user_id = 1", [])
            .unwrap();
    }
    af_db::get_conn().unwrap().execute(
        "INSERT INTO mcbrowser_policy_rules (user_id, rule_order, path, allow) VALUES (1, 0, 'links/movie.en.vtt', 0)", [],
    ).unwrap();
    let response = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/subtitles?path=links/movie.mp4",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["subtitles"], serde_json::json!([]));
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/actions",
        serde_json::json!({"action": "inspect_media_metadata", "path": "leaf.mp4"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["path"], "leaf.mp4");
    assert_eq!(payload["name"], "leaf.mp4");
    assert!(payload["modified"].is_string());
}

struct TransportServer {
    child: tokio::process::Child,
    output: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    origin: String,
}

impl TransportServer {
    async fn start(directory: &Path) -> Self {
        use tokio::io::AsyncBufReadExt;
        let mut child = tokio::process::Command::new(env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "mcbrowser::http_tests::disposable_mcbrowser_transport_server",
                "--nocapture",
            ])
            .env("AF_MCBROWSER_TRANSPORT_FIXTURE", directory)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let output = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut server = Self {
            child,
            output,
            origin: String::new(),
        };
        let address = server.wait_for_marker("MCBROWSER_ACCEPTANCE_READY ").await;
        let address: std::net::SocketAddr = address.parse().unwrap();
        assert!(address.ip().is_loopback());
        server.origin = format!("http://{address}");
        server
    }

    async fn wait_for_marker(&mut self, marker: &str) -> String {
        tokio::time::timeout(Duration::from_secs(15), async {
            while let Some(line) = self.output.next_line().await.unwrap() {
                if let Some(position) = line.find(marker) {
                    return line[position + marker.len()..].trim().to_string();
                }
            }
            panic!("acceptance subprocess exited before {marker}");
        })
        .await
        .expect("acceptance subprocess marker deadline")
    }

    async fn crash(&mut self) {
        self.child.kill().await.unwrap();
        assert!(!self.child.wait().await.unwrap().success());
    }
}

async fn transport_body_progress(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if request.headers().get("x-acceptance-publication").is_some() {
        let response = next.run(request).await;
        println!(
            "MCBROWSER_ACCEPTANCE_PUBLICATION {}",
            response.status().as_u16()
        );
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        return response;
    }
    if request.headers().get("x-acceptance-interrupt").is_none() {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let monitored = async_stream::stream! {
        let mut stream = body.into_data_stream();
        while let Some(frame) = stream.next().await {
            yield frame;
            println!("MCBROWSER_ACCEPTANCE_BODY_PROGRESS");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }
    };
    next.run(Request::from_parts(parts, Body::from_stream(monitored)))
        .await
}

#[tokio::test]
#[ignore = "Subprocess-only loopback fixture exercised by real_http_upload_survives_process_crash"]
async fn disposable_mcbrowser_transport_server() {
    let directory = PathBuf::from(env::var_os("AF_MCBROWSER_TRANSPORT_FIXTURE").unwrap());
    assert_eq!(directory.parent(), Some(env::temp_dir().as_path()));
    assert!(directory
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("af-mcbrowser-http-"));
    assert!(directory.join("test.sqlite").is_file());
    env::set_var("DB_PATH", directory.join("test.sqlite"));
    env::set_var("AF_MCBROWSER_ROOT", directory.join("files"));
    af_db::init_db().unwrap();
    let browser_acceptance = env::var("AF_MCBROWSER_BROWSER_ACCEPTANCE").as_deref() == Ok("1");
    if browser_acceptance {
        let connection = af_db::get_conn().unwrap();
        connection.execute_batch(
            "INSERT OR IGNORE INTO users (id, username, role) VALUES (1, 'alice', 'user');
             INSERT OR IGNORE INTO user_quotas (user_id, username, quota_bytes, used_bytes, status)
             VALUES (1, 'alice', 1073741824, 0, 'active');",
        ).unwrap();
        policy::ensure_policy_tables(&connection).unwrap();
        connection.execute("INSERT OR IGNORE INTO mcbrowser_policies (user_id, perm_execute) VALUES (1, 1)", []).unwrap();
    }
    let mut application = Router::new().nest(
        "/api/v1/auth",
        router()
            .layer(Extension(AuthUser {
                user_id: 1,
                username: "alice".to_string(),
                role: "user".to_string(),
                jti: "transport-fixture".to_string(),
                plugin_id: None,
                plugin_scopes: Vec::new(),
            }))
            .layer(axum::middleware::from_fn(transport_body_progress)),
    );
    if browser_acceptance {
        application = application
            .route("/api/v1/auth/session", axum::routing::get(|| async {
                Json(serde_json::json!({"id":1,"username":"alice","email":"alice@example.invalid","role":"user","avatar_url":"","is_oauth":false,"totp_enabled":false}))
            }))
            .route("/api/v1/public/csrf-token", axum::routing::get(|| async {
                Json(serde_json::json!({"csrf_token":"disposable-browser-fixture"}))
            }))
            .nest("/api/v1/public", public_router());
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    println!(
        "MCBROWSER_ACCEPTANCE_READY {}",
        listener.local_addr().unwrap()
    );
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    axum::serve(listener, application).await.unwrap();
}

#[tokio::test]
async fn real_http_upload_survives_process_crash() {
    use base64::Engine;
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute(
                "UPDATE user_quotas SET quota_bytes = 67108864 WHERE user_id = 1",
                [],
            )
            .unwrap();
        events::ensure_events_tables(&connection).unwrap();
        connection.execute(
            "INSERT INTO mcbrowser_event_settings (id, queue_enabled, updated_at) VALUES (1, 1, '2026-11-02T00:00:00Z') ON CONFLICT(id) DO UPDATE SET queue_enabled = 1",
            [],
        ).unwrap();
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let payload: Vec<u8> = (0..2 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect();
    let committed = 512 * 1024;
    let interrupted_prefix = 64 * 1024;
    let mut server = TransportServer::start(&fixture.directory).await;
    let metadata = format!(
        "path {},fingerprint {}",
        base64::engine::general_purpose::STANDARD.encode("recovered.bin"),
        base64::engine::general_purpose::STANDARD.encode("real-http-recovery")
    );
    let created = client
        .post(format!("{}/api/v1/auth/mcbrowser/uploads", server.origin))
        .header("tus-resumable", "1.0.0")
        .header("upload-length", payload.len())
        .header("upload-metadata", metadata)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let location = created.headers()["location"].to_str().unwrap().to_string();
    let initial = client
        .patch(format!("{}{location}", server.origin))
        .header("tus-resumable", "1.0.0")
        .header("content-type", "application/offset+octet-stream")
        .header("upload-offset", "0")
        .body(payload[..committed].to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(initial.status(), StatusCode::NO_CONTENT);
    assert_eq!(initial.headers()["upload-offset"], committed.to_string());
    assert!(!fixture.user_root().join("recovered.bin").exists());
    let mut socket = tokio::net::TcpStream::connect(server.origin.trim_start_matches("http://"))
        .await
        .unwrap();
    let headers = format!("PATCH {location} HTTP/1.1\r\nHost: localhost\r\nTus-Resumable: 1.0.0\r\nContent-Type: application/offset+octet-stream\r\nUpload-Offset: {committed}\r\nContent-Length: 1048576\r\nX-Acceptance-Interrupt: true\r\n\r\n");
    socket.write_all(headers.as_bytes()).await.unwrap();
    socket
        .write_all(&payload[committed..committed + interrupted_prefix])
        .await
        .unwrap();
    server
        .wait_for_marker("MCBROWSER_ACCEPTANCE_BODY_PROGRESS")
        .await;
    let parallel = client
        .post(format!("{}/api/v1/auth/mcbrowser/uploads", server.origin))
        .header("tus-resumable", "1.0.0")
        .header("upload-length", "3")
        .header("upload-metadata", "path cGFyYWxsZWwudHh0")
        .send()
        .await
        .unwrap();
    assert_eq!(parallel.status(), StatusCode::CREATED);
    let parallel_location = parallel.headers()["location"].to_str().unwrap();
    let parallel = client
        .patch(format!("{}{parallel_location}", server.origin))
        .header("tus-resumable", "1.0.0")
        .header("content-type", "application/offset+octet-stream")
        .header("upload-offset", "0")
        .body("xyz")
        .send()
        .await
        .unwrap();
    assert_eq!(parallel.status(), StatusCode::NO_CONTENT);
    server.crash().await;
    drop(socket);
    let (stored_offset, staging): (usize, String) = af_db::get_conn().unwrap().query_row(
        "SELECT offset_bytes, staging_rel_path FROM mcbrowser_uploads WHERE target_path = 'recovered.bin'",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(stored_offset, committed);
    let staged = fs::metadata(
        fixture
            .directory
            .join("files/.af-upload-staging")
            .join(staging),
    )
    .unwrap()
    .len() as usize;
    assert!((committed..=committed + interrupted_prefix).contains(&staged));
    let mut server = TransportServer::start(&fixture.directory).await;
    let discovery = client
        .get(format!("{}/api/v1/auth/mcbrowser/uploads", server.origin))
        .header("tus-resumable", "1.0.0")
        .query(&[
            ("path", "recovered.bin"),
            ("length", "2097152"),
            ("fingerprint", "real-http-recovery"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(discovery.status(), StatusCode::OK);
    let discovery: uploads::DiscoverUploadsResponse = discovery.json().await.unwrap();
    assert_eq!(discovery.uploads.len(), 1);
    assert_eq!(
        discovery.uploads[0].id,
        location.rsplit('/').next().unwrap()
    );
    assert_eq!(discovery.uploads[0].offset, committed as u64);
    let unpublished = client
        .get(format!(
            "{}/api/v1/auth/mcbrowser/download?path=recovered.bin",
            server.origin
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unpublished.status(), StatusCode::NOT_FOUND);
    let resumed = client
        .head(format!("{}{location}", server.origin))
        .header("tus-resumable", "1.0.0")
        .send()
        .await
        .unwrap();
    assert_eq!(resumed.status(), StatusCode::OK);
    let offset: usize = resumed.headers()["upload-offset"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(offset, committed);
    assert_eq!(
        fs::metadata(
            fixture
                .directory
                .join("files/.af-upload-staging/user-1")
                .join(format!("{}.part", location.rsplit('/').next().unwrap()),),
        )
        .unwrap()
        .len(),
        committed as u64
    );
    assert!(!fixture.user_root().join("recovered.bin").exists());
    let mut socket = tokio::net::TcpStream::connect(server.origin.trim_start_matches("http://"))
        .await
        .unwrap();
    let remaining = payload.len() - offset;
    let headers = format!("PATCH {location} HTTP/1.1\r\nHost: localhost\r\nTus-Resumable: 1.0.0\r\nContent-Type: application/offset+octet-stream\r\nUpload-Offset: {offset}\r\nContent-Length: {remaining}\r\nX-Acceptance-Publication: true\r\n\r\n");
    socket.write_all(headers.as_bytes()).await.unwrap();
    socket.write_all(&payload[offset..]).await.unwrap();
    assert_eq!(
        server
            .wait_for_marker("MCBROWSER_ACCEPTANCE_PUBLICATION ")
            .await,
        "204"
    );
    server.crash().await;
    drop(socket);
    let mut server = TransportServer::start(&fixture.directory).await;
    for _attempt in 0..2 {
        let response = client
            .head(format!("{}{location}", server.origin))
            .header("tus-resumable", "1.0.0")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["upload-offset"],
            payload.len().to_string()
        );
    }
    let downloaded = client
        .get(format!(
            "{}/api/v1/auth/mcbrowser/download?path=recovered.bin",
            server.origin
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(downloaded.status(), StatusCode::OK);
    assert_eq!(
        downloaded.bytes().await.unwrap().as_ref(),
        payload.as_slice()
    );
    let ranged = client
        .get(format!(
            "{}/api/v1/auth/mcbrowser/download?path=recovered.bin",
            server.origin
        ))
        .header("range", "bytes=65530-65545")
        .send()
        .await
        .unwrap();
    assert_eq!(ranged.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        ranged.bytes().await.unwrap().as_ref(),
        &payload[65530..=65545]
    );
    assert_eq!(fixture.used_bytes(), payload.len() as u64 + 3);
    let connection = af_db::get_conn().unwrap();
    let completed_events: i64 = connection.query_row(
        "SELECT COUNT(*) FROM mcbrowser_audit_events WHERE relative_path = 'recovered.bin' AND status = 'completed'",
        [], |row| row.get(0),
    ).unwrap();
    let queued_events: i64 = connection.query_row(
        "SELECT COUNT(*) FROM mcbrowser_event_queue WHERE event_id IN (SELECT event_id FROM mcbrowser_audit_events WHERE relative_path = 'recovered.bin')",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!((completed_events, queued_events), (1, 1));
    drop(connection);
    server.crash().await;
}

struct HttpFixture {
    directory: PathBuf,
    previous_database: Option<std::ffi::OsString>,
    previous_root: Option<std::ffi::OsString>,
}

impl HttpFixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("af-mcbrowser-http-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let fixture = Self {
            directory,
            previous_database: env::var_os("DB_PATH"),
            previous_root: env::var_os("AF_MCBROWSER_ROOT"),
        };
        env::set_var("DB_PATH", fixture.directory.join("test.sqlite"));
        env::set_var("AF_MCBROWSER_ROOT", fixture.directory.join("files"));
        af_db::init_db().unwrap();
        let connection = af_db::get_conn().unwrap();
        connection
            .execute_batch(
                "INSERT INTO users (id, username, role) VALUES (1, 'alice', 'user');
             INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status)
             VALUES (1, 'alice', 1024, 0, 'active');",
            )
            .unwrap();
        fixture
    }

    fn router(&self) -> Router {
        router().layer(Extension(AuthUser {
            user_id: 1,
            username: "alice".to_string(),
            role: "user".to_string(),
            jti: "http-fixture".to_string(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }))
    }

    fn used_bytes(&self) -> u64 {
        af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT used_bytes FROM user_quotas WHERE user_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn user_root(&self) -> PathBuf {
        self.directory.join("files/user-1")
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        for (key, previous) in [
            ("DB_PATH", &self.previous_database),
            ("AF_MCBROWSER_ROOT", &self.previous_root),
        ] {
            match previous {
                Some(value) => env::set_var(key, value),
                None => env::remove_var(key),
            }
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

async fn request_json(
    router: Router,
    method: &str,
    endpoint: &str,
    body: serde_json::Value,
) -> Response {
    tokio::time::timeout(
        Duration::from_secs(5),
        router.oneshot(
            Request::builder()
                .method(method)
                .uri(endpoint)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        ),
    )
    .await
    .expect("mounted request must not stall on nested SQLite checkout")
    .unwrap()
}

#[tokio::test]
async fn mounted_alias_info_enforces_hop_policy_and_returns_alias_paths() {
    use std::os::unix::fs::symlink;
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let filesystem = open_user_browser_fs_at(&fixture.directory.join("files"), 1).unwrap();
    filesystem.create_directory_all("data/sub").unwrap();
    fs::write(fixture.user_root().join("data/public.txt"), b"hello").unwrap();
    fs::write(fixture.user_root().join("data/hidden.txt"), b"secret").unwrap();
    symlink("data", fixture.user_root().join("hop")).unwrap();
    symlink("hop", fixture.user_root().join("dir-alias")).unwrap();
    symlink("hop/public.txt", fixture.user_root().join("file-alias.txt")).unwrap();
    let response = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/info?path=file-alias.txt&checksum=md5",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let info: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(info["entry"]["path"], "file-alias.txt");
    assert_eq!(info["entry"]["kind"], "file");
    assert_eq!(info["checksums"]["md5"], "5d41402abc4b2a76b9719d911017c592");
    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute("INSERT INTO mcbrowser_policies (user_id) VALUES (1)", [])
            .unwrap();
        connection.execute("INSERT INTO mcbrowser_policy_rules (user_id, rule_order, path, allow) VALUES (1, 0, 'hop/hidden.txt', 0)", []).unwrap();
    }
    let response = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/info?path=dir-alias",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let info: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(info["entry"]["path"], "dir-alias");
    assert_eq!(info["num_files"], 1);
    assert_eq!(info["num_dirs"], 1);
    for denied in ["file-alias.txt", "hop/public.txt", "data/public.txt"] {
        {
            let connection = af_db::get_conn().unwrap();
            connection
                .execute(
                    "UPDATE mcbrowser_policy_rules SET path = ?1 WHERE user_id = 1",
                    [denied],
                )
                .unwrap();
        }
        let response = request_json(
            fixture.router(),
            "GET",
            "/mcbrowser/info?path=file-alias.txt&checksum=sha256",
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "must enforce {denied}"
        );
    }
    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute(
                "UPDATE user_quotas SET status = 'suspended' WHERE user_id = 1",
                [],
            )
            .unwrap();
    }
    let response = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/info?path=dir-alias",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(fixture.used_bytes(), 0);
}

#[tokio::test]
async fn unpublished_single_step_failures_finalize_audit_without_queueing() {
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let created = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/directory",
        serde_json::json!({"path":"occupied"}),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    fs::write(fixture.user_root().join("occupied/keep.txt"), b"keep").unwrap();
    let duplicate = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/directory",
        serde_json::json!({"path":"occupied"}),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    for path in ["missing.txt", "occupied"] {
        let removed = request_json(
            fixture.router(),
            "DELETE",
            &format!("/mcbrowser/entry?path={path}"),
            serde_json::Value::Null,
        )
        .await;
        assert!(!removed.status().is_success());
    }
    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute_batch(
                "UPDATE mcbrowser_event_settings SET queue_enabled = 1;
             CREATE TRIGGER reject_upload_reservation BEFORE UPDATE OF used_bytes ON user_quotas
             WHEN NEW.used_bytes > OLD.used_bytes
             BEGIN SELECT RAISE(ABORT, 'injected quota reservation failure'); END;",
            )
            .unwrap();
    }
    let rejected = fixture
        .router()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/mcbrowser/upload?path=rejected.txt")
                .header("content-length", "3")
                .body(Body::from("abc"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!fixture.user_root().join("rejected.txt").exists());
    assert_eq!(
        fs::read(fixture.user_root().join("occupied/keep.txt")).unwrap(),
        b"keep"
    );
    assert_eq!(fixture.used_bytes(), 0);
    let connection = af_db::get_conn().unwrap();
    let records: Vec<(String, i64, Option<String>)> = connection
        .prepare("SELECT status, byte_delta, error_code FROM mcbrowser_audit_events ORDER BY seq")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        records,
        vec![
            ("completed".to_string(), 0, None),
            (
                "failed".to_string(),
                0,
                Some("CREATE_DIRECTORY_FAILED".to_string())
            ),
            (
                "failed".to_string(),
                0,
                Some("DELETE_ENTRY_FAILED".to_string())
            ),
            (
                "failed".to_string(),
                0,
                Some("DELETE_ENTRY_FAILED".to_string())
            ),
            (
                "failed".to_string(),
                0,
                Some("QUOTA_RESERVATION_FAILED".to_string())
            ),
        ]
    );
    let queued: i64 = connection
        .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(queued, 0);
}

#[tokio::test]
async fn mounted_mutations_persist_audit_intents_and_never_claim_publication_rollback() {
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let directory = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/directory",
        serde_json::json!({"path":"docs"}),
    )
    .await;
    assert_eq!(directory.status(), StatusCode::CREATED);
    let created = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({"path":"docs/new.txt","content":"hello"}),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let duplicate = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({"path":"docs/new.txt","content":"replacement"}),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    let removed = request_json(
        fixture.router(),
        "DELETE",
        "/mcbrowser/entry?path=docs%2Fnew.txt",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(removed.status(), StatusCode::OK);
    {
        let connection = af_db::get_conn().unwrap();
        let mut statement = connection
            .prepare("SELECT trigger, status, byte_delta FROM mcbrowser_audit_events ORDER BY seq")
            .unwrap();
        let records = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            records,
            vec![
                ("upload_completed".to_string(), "completed".to_string(), 0),
                ("file_saved".to_string(), "completed".to_string(), 5),
                ("file_saved".to_string(), "failed".to_string(), 0),
                ("entry_deleted".to_string(), "completed".to_string(), -5),
            ]
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            0
        );
        connection
            .execute(
                "INSERT INTO mcbrowser_event_settings (id, queue_enabled, updated_at)
                 VALUES (1, 1, CURRENT_TIMESTAMP)
                 ON CONFLICT(id) DO UPDATE SET queue_enabled = 1",
                [],
            )
            .unwrap();
    }
    let queued = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({"path":"docs/queued.txt","content":"ok"}),
    )
    .await;
    assert_eq!(queued.status(), StatusCode::CREATED);
    {
        let connection = af_db::get_conn().unwrap();
        let payload: String = connection
            .query_row(
                "SELECT payload_json FROM mcbrowser_event_queue",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(payload["relative_path"], "docs/queued.txt");
        assert_eq!(payload["username"], "alice");
        assert_eq!(payload["byte_delta"], 2);
        connection.execute_batch(
            "CREATE TRIGGER reject_audit_completion BEFORE UPDATE OF status ON mcbrowser_audit_events
             WHEN NEW.status = 'completed' BEGIN SELECT RAISE(ABORT, 'injected completion failure'); END;",
        ).unwrap();
    }
    let published = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({"path":"docs/published.txt","content":"yes"}),
    )
    .await;
    assert_eq!(published.status(), StatusCode::CREATED);
    assert_eq!(
        fs::read(fixture.user_root().join("docs/published.txt")).unwrap(),
        b"yes"
    );
    assert_eq!(fixture.used_bytes(), 5);
    {
        let connection = af_db::get_conn().unwrap();
        let status: String = connection.query_row("SELECT status FROM mcbrowser_audit_events WHERE relative_path = 'docs/published.txt'", [], |row| row.get(0)).unwrap();
        assert_eq!(status, "pending");
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            1
        );
        connection.execute_batch(
            "CREATE TRIGGER reject_audit_intent BEFORE INSERT ON mcbrowser_audit_events
             WHEN NEW.relative_path = 'docs/blocked.txt' BEGIN SELECT RAISE(ABORT, 'injected intent failure'); END;",
        ).unwrap();
    }
    let blocked = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({"path":"docs/blocked.txt","content":"no"}),
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!fixture.user_root().join("docs/blocked.txt").exists());
    assert_eq!(fixture.used_bytes(), 5);
    let private_audit = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/events",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(private_audit.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn host_filesystem_listing_rejects_nonadmins_before_disclosing_service_backup_metadata() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let service_directory = fixture.directory.join("streaming-backup-private");
    fs::create_dir(&service_directory).unwrap();
    fs::set_permissions(&service_directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        service_directory.join("before-migration.sqlite"),
        b"private backup",
    )
    .unwrap();
    let alias = fixture.directory.join("backup-alias");
    symlink(&service_directory, &alias).unwrap();
    let headers = HeaderMap::new();
    let (user_token, _) = crate::auth::create_standard_jwt(1, &headers).unwrap();
    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute(
                "INSERT INTO users (id, username, role) VALUES (2, 'admin', 'admin')",
                [],
            )
            .unwrap();
    }
    let (admin_token, _) = crate::auth::create_standard_jwt(2, &headers).unwrap();
    for prefix in ["/api/v1/auth/fs", "/api/auth/fs", "/api/v1/fs", "/api/fs"] {
        for path in [
            &fixture.directory,
            &service_directory,
            &alias,
            &fixture.directory.join("absent-private-directory"),
        ] {
            let endpoint = format!(
                "{prefix}?path={}",
                urlencoding::encode(&path.to_string_lossy())
            );
            let anonymous = crate::routes::build_router()
                .oneshot(
                    Request::builder()
                        .uri(&endpoint)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
            let rejected = crate::routes::build_router()
                .oneshot(
                    Request::builder()
                        .uri(&endpoint)
                        .header("authorization", format!("Bearer {user_token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(rejected.status(), StatusCode::FORBIDDEN, "{endpoint}");
            let body = rejected.into_body().collect().await.unwrap().to_bytes();
            let body = std::str::from_utf8(&body).unwrap();
            assert!(!body.contains("streaming-backup"));
            assert!(!body.contains("before-migration.sqlite"));
            assert!(!body.contains("backup-alias"));
            assert!(!body.contains("entries"));
        }
        let endpoint = format!(
            "{prefix}?path={}",
            urlencoding::encode(&fixture.directory.to_string_lossy())
        );
        let allowed = crate::routes::build_router()
            .oneshot(
                Request::builder()
                    .uri(endpoint)
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
    }
    af_db::get_conn().unwrap().execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status) VALUES (2, 'admin', 0, 0, 'suspended')", [],
    ).unwrap();
    let rejected = crate::routes::build_router()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/auth/fs?path={}",
                    urlencoding::encode(&fixture.directory.to_string_lossy())
                ))
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let scoped = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/entries",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(scoped.status(), StatusCode::OK);
    assert_eq!(
        fs::read(service_directory.join("before-migration.sqlite")).unwrap(),
        b"private backup"
    );
}

#[tokio::test]
async fn mounted_editor_accepts_10mib_decoded_text_with_sixfold_json_escaping() {
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    af_db::get_conn()
        .unwrap()
        .execute(
            "UPDATE user_quotas SET quota_bytes = ?1 WHERE user_id = 1",
            [operations::MAX_EDITOR_CONTENT_BYTES as i64 + 1],
        )
        .unwrap();
    let content = "\u{0001}".repeat(operations::MAX_EDITOR_CONTENT_BYTES);
    let encoded = serde_json::json!({"path":"large.txt","content":content}).to_string();
    assert!(encoded.len() > operations::MAX_EDITOR_CONTENT_BYTES * 5);
    let created = fixture
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/file")
                .header("content-type", "application/json")
                .body(Body::from(encoded))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(
        fixture.used_bytes(),
        operations::MAX_EDITOR_CONTENT_BYTES as u64
    );
    let loaded = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/content?path=large.txt",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(loaded.status(), StatusCode::OK);
    let loaded: serde_json::Value =
        serde_json::from_slice(&loaded.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(loaded["content"].as_str().unwrap(), content);
    let oversized = format!("{content}x");
    let rejected = request_json(
        fixture.router(),
        "PUT",
        "/mcbrowser/content?path=large.txt",
        serde_json::json!({"content":oversized,"etag":loaded["etag"]}),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        fixture.used_bytes(),
        operations::MAX_EDITOR_CONTENT_BYTES as u64
    );
    assert_eq!(
        fs::metadata(fixture.user_root().join("large.txt"))
            .unwrap()
            .len(),
        operations::MAX_EDITOR_CONTENT_BYTES as u64
    );
}

#[tokio::test]
async fn account_deletion_serializes_metadata_cleanup_retains_disk_and_revokes_access() {
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let created = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({"path":"retained.txt","content":"retained"}),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let shared = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/shares",
        serde_json::json!({"path":"retained.txt","allow_download":true}),
    )
    .await;
    assert_eq!(shared.status(), StatusCode::CREATED);
    let shared: serde_json::Value =
        serde_json::from_slice(&shared.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let share_url = shared["share"]["url"].as_str().unwrap();
    let share_token = share_url.strip_prefix("/share?token=").unwrap();
    let upload = fixture
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcbrowser/uploads")
                .header("tus-resumable", "1.0.0")
                .header("upload-length", "12")
                .header("upload-metadata", "path cGVuZGluZy50eHQ=")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::CREATED);
    let upload_location = upload.headers()["location"].to_str().unwrap().to_owned();
    let staging_directory = fixture.directory.join("files/.af-upload-staging/user-1");
    let staging_files: Vec<_> = fs::read_dir(&staging_directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert!(!staging_files.is_empty());
    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute(
                "INSERT INTO users (id, username, role) VALUES (2, 'admin', 'admin')",
                [],
            )
            .unwrap();
    }
    let headers = HeaderMap::new();
    let (owner_token, _) = crate::auth::create_standard_jwt(1, &headers).unwrap();
    let (admin_token, _) = crate::auth::create_standard_jwt(2, &headers).unwrap();
    let mutation_guard = user_mutation_stripe(1).lock_owned().await;
    let deletion = crate::routes::build_router().oneshot(
        Request::builder()
            .method("DELETE")
            .uri("/api/v1/admin/users/1")
            .header("authorization", format!("Bearer {admin_token}"))
            .body(Body::empty())
            .unwrap(),
    );
    tokio::pin!(deletion);
    assert!(futures::poll!(&mut deletion).is_pending());
    assert_eq!(
        fs::read(fixture.user_root().join("retained.txt")).unwrap(),
        b"retained"
    );
    drop(mutation_guard);
    let deleted = tokio::time::timeout(Duration::from_secs(5), deletion)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    assert_eq!(
        fs::read(fixture.user_root().join("retained.txt")).unwrap(),
        b"retained"
    );
    assert!(staging_files.iter().all(|path| path.is_file()));
    {
        let connection = af_db::get_conn().unwrap();
        for query in [
            "SELECT COUNT(*) FROM users WHERE id = 1",
            "SELECT COUNT(*) FROM user_quotas WHERE user_id = 1",
            "SELECT COUNT(*) FROM active_sessions WHERE user_id = 1",
            "SELECT COUNT(*) FROM mcbrowser_uploads WHERE user_id = 1",
            "SELECT COUNT(*) FROM mcbrowser_shares WHERE owner_user_id = 1",
        ] {
            assert_eq!(
                connection
                    .query_row(query, [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                0,
                "{query}"
            );
        }
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM users WHERE id = 2", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    let rejected = crate::routes::build_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/mcbrowser/entries")
                .header("authorization", format!("Bearer {owner_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    let public = shares::public_router()
        .oneshot(
            Request::builder()
                .uri(format!("/mcbrowser/shares/{share_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(public.status(), StatusCode::NOT_FOUND);
    let upload = fixture
        .router()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(
                    upload_location
                        .strip_prefix("/api/v1/auth")
                        .unwrap_or(&upload_location),
                )
                .header("tus-resumable", "1.0.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!upload.status().is_success());
}

#[tokio::test]
async fn mounted_same_folder_keep_both_preserves_original_and_audits_allocated_paths() {
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({"path":"note.txt","content":"abc"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    for (endpoint, expected_path) in [("copy", "note(1).txt"), ("rename", "note(2).txt")] {
        let response = request_json(
            fixture.router(),
            "POST",
            &format!("/mcbrowser/{endpoint}"),
            serde_json::json!({"from":"note.txt","to":"note.txt","conflict":"keep-both"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let payload: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(payload["path"], expected_path);
        assert_eq!(
            fs::read(fixture.user_root().join(expected_path)).unwrap(),
            b"abc"
        );
    }
    assert_eq!(fixture.used_bytes(), 6);
    assert!(!fixture.user_root().join("note.txt").exists());
    let connection = af_db::get_conn().unwrap();
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM mcbrowser_audit_events WHERE status = 'completed' AND destination_path IN ('note(1).txt', 'note(2).txt')", [], |row| row.get(0)).unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn mounted_copy_move_conflicts_return_allocated_paths_and_exact_quota() {
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    for (path, content) in [("source.txt", "new"), ("target.txt", "old")] {
        let response = request_json(
            fixture.router(),
            "POST",
            "/mcbrowser/file",
            serde_json::json!({"path":path,"content":content}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/copy",
        serde_json::json!({"from":"source.txt","to":"target.txt","conflict":"keep-both"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(payload["path"], "target(1).txt");
    assert_eq!(fixture.used_bytes(), 9);
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/rename",
        serde_json::json!({"from":"source.txt","to":"target.txt"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(fixture.used_bytes(), 9);
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/rename",
        serde_json::json!({"from":"source.txt","to":"target.txt","conflict":"overwrite"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(payload["path"], "target.txt");
    assert_eq!(fixture.used_bytes(), 6);
    assert_eq!(
        fs::read(fixture.user_root().join("target.txt")).unwrap(),
        b"new"
    );
    assert!(!fixture.user_root().join("source.txt").exists());
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/rename",
        serde_json::json!({"from":"target(1).txt","to":"target.txt","rename":true}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(payload["path"], "target(2).txt");
    assert_eq!(fixture.used_bytes(), 6);
    let connection = af_db::get_conn().unwrap();
    let records: Vec<(String, String, i64)> = connection
        .prepare(
            "SELECT trigger, destination_path, byte_delta FROM mcbrowser_audit_events
         WHERE trigger IN ('entry_copied', 'entry_renamed') AND status = 'completed' ORDER BY seq",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        records,
        vec![
            ("entry_copied".to_string(), "target(1).txt".to_string(), 3),
            ("entry_renamed".to_string(), "target.txt".to_string(), -3),
            ("entry_renamed".to_string(), "target(2).txt".to_string(), 0),
        ]
    );
}

#[tokio::test]
async fn internal_symlink_http_reads_check_alias_and_target_and_leaf_mutations_preserve_targets() {
    use std::os::unix::fs::symlink;

    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let initial = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/entries",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(initial.status(), StatusCode::OK);
    fs::create_dir(fixture.user_root().join("docs")).unwrap();
    fs::write(fixture.user_root().join("docs/public.txt"), "hello").unwrap();
    fs::write(fixture.user_root().join("docs/hidden.txt"), "hide").unwrap();
    fs::write(fixture.user_root().join("secret.txt"), "secret").unwrap();
    let outside = fixture.directory.join("outside.txt");
    fs::write(&outside, "outside").unwrap();
    symlink("docs", fixture.user_root().join("folder-link")).unwrap();
    symlink(
        "../secret-public.txt",
        fixture.user_root().join("docs/secret-link"),
    )
    .unwrap();
    fs::write(fixture.user_root().join("secret-public.txt"), "public").unwrap();
    symlink("docs/public.txt", fixture.user_root().join("file-link.txt")).unwrap();
    symlink("secret.txt", fixture.user_root().join("denied-link.txt")).unwrap();
    symlink(
        "docs/public.txt",
        fixture.user_root().join("blocked-alias.txt"),
    )
    .unwrap();
    symlink(&outside, fixture.user_root().join("external-link")).unwrap();
    symlink("missing.txt", fixture.user_root().join("broken-link")).unwrap();
    symlink("loop", fixture.user_root().join("loop")).unwrap();
    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute("INSERT INTO mcbrowser_policies (user_id) VALUES (1)", [])
            .unwrap();
        connection
            .execute(
                "UPDATE user_quotas SET used_bytes = 15 WHERE user_id = 1",
                [],
            )
            .unwrap();
        for (order, path) in [
            (0, "secret.txt"),
            (1, "docs/hidden.txt"),
            (2, "blocked-alias.txt"),
            (3, "docs/secret-link"),
        ] {
            connection.execute("INSERT INTO mcbrowser_policy_rules (user_id, rule_order, path, allow) VALUES (1, ?1, ?2, 0)", params![order, path]).unwrap();
        }
    }
    let response = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/entries",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let entries = payload["entries"].as_array().unwrap();
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry["name"] == "folder-link")
            .unwrap()["target_kind"],
        "directory"
    );
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry["name"] == "file-link.txt")
            .unwrap()["target_kind"],
        "file"
    );
    for name in ["denied-link.txt", "external-link", "broken-link", "loop"] {
        assert!(entries
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap()
            .get("target_kind")
            .is_none());
    }
    assert!(!entries
        .iter()
        .any(|entry| entry["name"] == "blocked-alias.txt"));
    let response = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/entries?path=folder-link",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(payload["entries"].as_array().unwrap().len(), 1);
    assert_eq!(payload["entries"][0]["path"], "folder-link/public.txt");
    let response = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/preview?path=folder-link/public.txt",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(payload["content"], "hello");
    let response = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/download?path=file-link.txt",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        &response.into_body().collect().await.unwrap().to_bytes()[..],
        b"hello"
    );
    for path in [
        "denied-link.txt",
        "blocked-alias.txt",
        "folder-link/hidden.txt",
        "folder-link/secret-link",
    ] {
        for endpoint in ["preview", "download"] {
            let response = request_json(
                fixture.router(),
                "GET",
                &format!("/mcbrowser/{endpoint}?path={path}"),
                serde_json::Value::Null,
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{endpoint}: {path}"
            );
        }
    }
    for path in ["external-link", "broken-link", "loop"] {
        let response = request_json(
            fixture.router(),
            "GET",
            &format!("/mcbrowser/download?path={path}"),
            serde_json::Value::Null,
        )
        .await;
        assert!(!response.status().is_success());
    }
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/rename",
        serde_json::json!({"from":"external-link","to":"renamed-link"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        fs::symlink_metadata(fixture.user_root().join("renamed-link"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    for path in ["renamed-link", "broken-link"] {
        let response = request_json(
            fixture.router(),
            "DELETE",
            &format!("/mcbrowser/entry?path={path}"),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    assert_eq!(
        fs::read(fixture.user_root().join("docs/public.txt")).unwrap(),
        b"hello"
    );
    assert_eq!(fixture.used_bytes(), 15);
    fs::create_dir(fixture.user_root().join("public-dir")).unwrap();
    symlink(
        "../public-dir",
        fixture.user_root().join("docs/directory-hop"),
    )
    .unwrap();
    symlink(
        "../secret-public.txt",
        fixture.user_root().join("docs/escape-hop"),
    )
    .unwrap();
    {
        let connection = af_db::get_conn().unwrap();
        connection.execute("INSERT INTO mcbrowser_policy_rules (user_id, rule_order, path, allow) VALUES (1, 10, 'docs', 0), (1, 11, 'docs/public.txt', 1)", []).unwrap();
    }
    for (endpoint, path, expected) in [
        ("preview", "folder-link/escape-hop", StatusCode::FORBIDDEN),
        ("download", "folder-link/escape-hop", StatusCode::FORBIDDEN),
        (
            "entries",
            "folder-link/directory-hop",
            StatusCode::FORBIDDEN,
        ),
        ("preview", "folder-link/public.txt", StatusCode::OK),
        ("entries", "folder-link", StatusCode::OK),
    ] {
        let response = request_json(
            fixture.router(),
            "GET",
            &format!("/mcbrowser/{endpoint}?path={path}"),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(response.status(), expected, "{endpoint}: {path}");
    }
    af_db::get_conn()
        .unwrap()
        .execute(
            "DELETE FROM mcbrowser_policy_rules WHERE user_id = 1 AND rule_order >= 10",
            [],
        )
        .unwrap();
    symlink(
        "../secret.txt",
        fixture.user_root().join("docs/scope-escape"),
    )
    .unwrap();
    symlink("public.txt", fixture.user_root().join("docs/internal.txt")).unwrap();
    af_db::get_conn()
        .unwrap()
        .execute(
            "UPDATE mcbrowser_policies SET scope = 'docs' WHERE user_id = 1",
            [],
        )
        .unwrap();
    let response = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/download?path=internal.txt",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        &response.into_body().collect().await.unwrap().to_bytes()[..],
        b"hello"
    );
    let response = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/download?path=scope-escape",
        serde_json::Value::Null,
    )
    .await;
    assert!(!response.status().is_success());
}

#[tokio::test]
async fn raw_upload_and_delete_use_single_connection_pool_and_account_exact_bytes() {
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        fixture.router().oneshot(
            Request::builder()
                .method("PUT")
                .uri("/mcbrowser/upload?path=hello.txt")
                .header("content-length", "5")
                .body(Body::from("hello"))
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        fs::read(fixture.user_root().join("hello.txt")).unwrap(),
        b"hello"
    );
    assert_eq!(fixture.used_bytes(), 5);
    let response = request_json(
        fixture.router(),
        "DELETE",
        "/mcbrowser/entry?path=hello.txt",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fixture.used_bytes(), 0);
    assert!(!fixture.user_root().join("hello.txt").exists());
    let connection = af_db::get_conn().unwrap();
    let records: Vec<(String, i64)> = connection.prepare(
        "SELECT trigger, byte_delta FROM mcbrowser_audit_events WHERE status = 'completed' ORDER BY seq",
    ).unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap()
        .collect::<Result<_, _>>().unwrap();
    assert_eq!(
        records,
        vec![
            ("upload_completed".to_string(), 5),
            ("entry_deleted".to_string(), -5)
        ]
    );
}

#[tokio::test]
async fn aborted_raw_body_cleans_staging_before_releasing_mutation_lock() {
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let (observed_sender, observed_receiver) = tokio::sync::oneshot::channel();
    let body = Body::from_stream(async_stream::stream! {
        yield Ok::<_, io::Error>(axum::body::Bytes::from_static(b"partial"));
        let _ = observed_sender.send(());
        futures::future::pending::<()>().await;
    });
    let request = Request::builder()
        .method("PUT")
        .uri("/mcbrowser/upload?path=cancelled.txt")
        .body(body)
        .unwrap();
    let router = fixture.router();
    let task = tokio::spawn(async move { router.oneshot(request).await });
    tokio::time::timeout(Duration::from_secs(5), observed_receiver)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let mutation_guard =
        tokio::time::timeout(Duration::from_secs(5), user_mutation_stripe(1).lock_owned())
            .await
            .unwrap();
    assert_eq!(fixture.used_bytes(), 0);
    assert!(fs::read_dir(fixture.user_root()).unwrap().next().is_none());
    drop(mutation_guard);
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({"path":"cancelled.txt","content":"retry"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(fixture.used_bytes(), 5);
}

#[tokio::test]
async fn scoped_copy_editor_and_recursive_delete_complete_without_nested_checkouts() {
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/directory",
        serde_json::json!({"path":"scope"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    {
        let connection = af_db::get_conn().unwrap();
        policy::effective_scope_with_conn(&connection, 1).unwrap();
        connection
            .execute(
                "INSERT INTO mcbrowser_policies (user_id, scope) VALUES (1, 'scope')",
                [],
            )
            .unwrap();
    }
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({"path":"hello.txt","content":"hello"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(fixture.user_root().join("scope/hello.txt").exists());
    assert!(!fixture.user_root().join("hello.txt").exists());
    let response = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/content?path=hello.txt",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let response = request_json(
        fixture.router(),
        "PUT",
        "/mcbrowser/content?path=hello.txt",
        serde_json::json!({"content":"edited text", "etag":payload["etag"]}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/directory",
        serde_json::json!({"path":"copied"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/copy",
        serde_json::json!({"from":"hello.txt","to":"copied/hello.txt"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fixture.used_bytes(), 22);
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/delete-recursive",
        serde_json::json!({"path":"copied"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fixture.used_bytes(), 11);
    let connection = af_db::get_conn().unwrap();
    let records: Vec<(String, i64)> = connection.prepare(
        "SELECT trigger, byte_delta FROM mcbrowser_audit_events WHERE status = 'completed' ORDER BY seq",
    ).unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap()
        .collect::<Result<_, _>>().unwrap();
    assert_eq!(
        records,
        vec![
            ("upload_completed".to_string(), 0),
            ("file_saved".to_string(), 5),
            ("file_saved".to_string(), 6),
            ("upload_completed".to_string(), 0),
            ("entry_copied".to_string(), 11),
            ("entry_deleted".to_string(), -11),
        ]
    );
}

#[tokio::test]
async fn mounted_archive_actions_audit_publication_and_fail_closed_before_mutation() {
    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    let response = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({"path":"source.txt","content":"hello"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = request_json(fixture.router(), "POST", "/mcbrowser/actions",
        serde_json::json!({"action":"CreateArchive","source_paths":["source.txt"],"destination_path":"blocked.zip","format":"zip"})).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert!(!fixture.user_root().join("blocked.zip").exists());
    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute(
                "INSERT INTO mcbrowser_policies (user_id, perm_execute) VALUES (1, 1)",
                [],
            )
            .unwrap();
    }
    let response = request_json(fixture.router(), "POST", "/mcbrowser/actions",
        serde_json::json!({"action":"CreateArchive","source_paths":["source.txt"],"destination_path":"bundle.zip","format":"zip"})).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let archive_bytes = fs::metadata(fixture.user_root().join("bundle.zip"))
        .unwrap()
        .len();
    let response = request_json(fixture.router(), "POST", "/mcbrowser/actions",
        serde_json::json!({"action":"ExtractArchive","archive_path":"bundle.zip","destination_dir":"extracted"})).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        fs::read(fixture.user_root().join("extracted/source.txt")).unwrap(),
        b"hello"
    );
    {
        let connection = af_db::get_conn().unwrap();
        let records: Vec<(String, i64)> = connection.prepare(
            "SELECT relative_path, byte_delta FROM mcbrowser_audit_events WHERE trigger = 'upload_completed' AND status = 'completed' ORDER BY seq",
        ).unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap()
            .collect::<Result<_, _>>().unwrap();
        assert_eq!(
            records,
            vec![
                ("bundle.zip".to_string(), archive_bytes as i64),
                ("extracted".to_string(), 5)
            ]
        );
        connection.execute_batch("CREATE TRIGGER reject_archive_audit BEFORE INSERT ON mcbrowser_audit_events BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;").unwrap();
    }
    let previous_usage = fixture.used_bytes();
    let response = request_json(fixture.router(), "POST", "/mcbrowser/actions",
        serde_json::json!({"action":"CreateArchive","source_paths":["source.txt"],"destination_path":"not-created/bundle.zip","format":"zip"})).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!fixture.user_root().join("not-created").exists());
    assert_eq!(fixture.used_bytes(), previous_usage);
}

#[tokio::test]
async fn mounted_alias_content_get_and_put_enforce_policy_etag_quota_and_audit_under_max_size_one_pool(
) {
    use std::os::unix::fs::symlink;

    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();
    for dir in ["docs", "chain"] {
        let created_dir = request_json(
            fixture.router(),
            "POST",
            "/mcbrowser/directory",
            serde_json::json!({ "path": dir }),
        )
        .await;
        assert_eq!(created_dir.status(), StatusCode::CREATED);
    }
    let created_target = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({ "path": "docs/target.txt", "content": "hello" }),
    )
    .await;
    assert_eq!(created_target.status(), StatusCode::CREATED);
    let created_secret = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({ "path": "secret.txt", "content": "secret" }),
    )
    .await;
    assert_eq!(created_secret.status(), StatusCode::CREATED);
    assert_eq!(fixture.used_bytes(), 11);

    let outside = fixture.directory.join("outside.txt");
    fs::write(&outside, "outside").unwrap();
    symlink(
        "docs/target.txt",
        fixture.user_root().join("leaf-alias.txt"),
    )
    .unwrap();
    symlink("docs", fixture.user_root().join("dir-alias")).unwrap();
    symlink(
        "../dir-alias/target.txt",
        fixture.user_root().join("chain/hop.txt"),
    )
    .unwrap();
    symlink(
        "secret.txt",
        fixture.user_root().join("denied-target-alias.txt"),
    )
    .unwrap();
    symlink("missing.txt", fixture.user_root().join("broken-alias.txt")).unwrap();
    symlink(&outside, fixture.user_root().join("escape-alias.txt")).unwrap();
    symlink("loop-alias.txt", fixture.user_root().join("loop-alias.txt")).unwrap();

    let mut initial_etag = String::new();
    for alias_path in ["leaf-alias.txt", "dir-alias/target.txt", "chain/hop.txt"] {
        let response = request_json(
            fixture.router(),
            "GET",
            &format!("/mcbrowser/content?path={alias_path}"),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{alias_path}");
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let payload: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(payload["path"], alias_path);
        assert_eq!(payload["content"], "hello");
        initial_etag = payload["etag"].as_str().unwrap().to_string();
    }

    let put_leaf = request_json(
        fixture.router(),
        "PUT",
        "/mcbrowser/content?path=leaf-alias.txt",
        serde_json::json!({ "content": "hello world", "etag": initial_etag }),
    )
    .await;
    assert_eq!(put_leaf.status(), StatusCode::OK);
    let put_leaf_payload: serde_json::Value =
        serde_json::from_slice(&put_leaf.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let updated_etag = put_leaf_payload["etag"].as_str().unwrap().to_string();
    assert_eq!(fixture.used_bytes(), 17);
    assert!(
        fs::symlink_metadata(fixture.user_root().join("leaf-alias.txt"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_link(fixture.user_root().join("leaf-alias.txt")).unwrap(),
        std::path::PathBuf::from("docs/target.txt")
    );
    assert_eq!(
        fs::read_to_string(fixture.user_root().join("docs/target.txt")).unwrap(),
        "hello world"
    );

    let stale_put = request_json(
        fixture.router(),
        "PUT",
        "/mcbrowser/content?path=dir-alias/target.txt",
        serde_json::json!({ "content": "stale", "etag": initial_etag }),
    )
    .await;
    assert_eq!(stale_put.status(), StatusCode::CONFLICT);
    assert_eq!(fixture.used_bytes(), 17);

    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute(
                "UPDATE user_quotas SET quota_bytes = 20 WHERE user_id = 1",
                [],
            )
            .unwrap();
    }
    let over_quota = request_json(
        fixture.router(),
        "PUT",
        "/mcbrowser/content?path=dir-alias/target.txt",
        serde_json::json!({ "content": "0123456789012345", "etag": updated_etag }),
    )
    .await;
    assert_eq!(over_quota.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(fixture.used_bytes(), 17);
    assert_eq!(
        fs::read_to_string(fixture.user_root().join("docs/target.txt")).unwrap(),
        "hello world"
    );

    let shrink_put = request_json(
        fixture.router(),
        "PUT",
        "/mcbrowser/content?path=dir-alias/target.txt",
        serde_json::json!({ "content": "hi", "etag": updated_etag }),
    )
    .await;
    assert_eq!(shrink_put.status(), StatusCode::OK);
    let shrink_payload: serde_json::Value =
        serde_json::from_slice(&shrink_put.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    let shrunk_etag = shrink_payload["etag"].as_str().unwrap().to_string();
    assert_eq!(fixture.used_bytes(), 8);
    assert!(fs::symlink_metadata(fixture.user_root().join("dir-alias"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read_to_string(fixture.user_root().join("docs/target.txt")).unwrap(),
        "hi"
    );

    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute("INSERT INTO mcbrowser_policies (user_id) VALUES (1)", [])
            .unwrap();
    }
    for (denied_rule, request_path) in [
        ("secret.txt", "denied-target-alias.txt"),
        ("dir-alias", "chain/hop.txt"),
        ("leaf-alias.txt", "leaf-alias.txt"),
        ("docs/target.txt", "leaf-alias.txt"),
    ] {
        {
            let connection = af_db::get_conn().unwrap();
            connection
                .execute("DELETE FROM mcbrowser_policy_rules WHERE user_id = 1", [])
                .unwrap();
            connection
                .execute(
                    "INSERT INTO mcbrowser_policy_rules (user_id, rule_order, path, allow) VALUES (1, 0, ?1, 0)",
                    params![denied_rule],
                )
                .unwrap();
        }
        let get_denied = request_json(
            fixture.router(),
            "GET",
            &format!("/mcbrowser/content?path={request_path}"),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(
            get_denied.status(),
            StatusCode::FORBIDDEN,
            "GET {request_path} with denied {denied_rule}"
        );
        let put_denied = request_json(
            fixture.router(),
            "PUT",
            &format!("/mcbrowser/content?path={request_path}"),
            serde_json::json!({ "content": "nope", "etag": shrunk_etag }),
        )
        .await;
        assert_eq!(
            put_denied.status(),
            StatusCode::FORBIDDEN,
            "PUT {request_path} with denied {denied_rule}"
        );
    }

    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute("DELETE FROM mcbrowser_policy_rules WHERE user_id = 1", [])
            .unwrap();
        connection
            .execute(
                "UPDATE mcbrowser_policies SET perm_modify = 0 WHERE user_id = 1",
                [],
            )
            .unwrap();
    }
    let read_allowed = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/content?path=leaf-alias.txt",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(read_allowed.status(), StatusCode::OK);
    let modify_denied = request_json(
        fixture.router(),
        "PUT",
        "/mcbrowser/content?path=leaf-alias.txt",
        serde_json::json!({ "content": "nope", "etag": shrunk_etag }),
    )
    .await;
    assert_eq!(modify_denied.status(), StatusCode::FORBIDDEN);
    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute(
                "UPDATE mcbrowser_policies SET perm_modify = 1 WHERE user_id = 1",
                [],
            )
            .unwrap();
    }

    for (invalid_path, expected_status) in [
        ("dir-alias", StatusCode::BAD_REQUEST),
        ("broken-alias.txt", StatusCode::NOT_FOUND),
        ("escape-alias.txt", StatusCode::FORBIDDEN),
        ("loop-alias.txt", StatusCode::FORBIDDEN),
    ] {
        let get_res = request_json(
            fixture.router(),
            "GET",
            &format!("/mcbrowser/content?path={invalid_path}"),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(get_res.status(), expected_status, "GET {invalid_path}");
        let put_res = request_json(
            fixture.router(),
            "PUT",
            &format!("/mcbrowser/content?path={invalid_path}"),
            serde_json::json!({ "content": "nope", "etag": shrunk_etag }),
        )
        .await;
        assert_eq!(put_res.status(), expected_status, "PUT {invalid_path}");
    }

    fs::hard_link(
        fixture.user_root().join("docs/target.txt"),
        fixture.user_root().join("docs/hardlink.txt"),
    )
    .unwrap();
    let hardlink_get = request_json(
        fixture.router(),
        "GET",
        "/mcbrowser/content?path=leaf-alias.txt",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(hardlink_get.status(), StatusCode::FORBIDDEN);
    let hardlink_put = request_json(
        fixture.router(),
        "PUT",
        "/mcbrowser/content?path=leaf-alias.txt",
        serde_json::json!({ "content": "nope", "etag": shrunk_etag }),
    )
    .await;
    assert_eq!(hardlink_put.status(), StatusCode::FORBIDDEN);
    fs::remove_file(fixture.user_root().join("docs/hardlink.txt")).unwrap();

    let connection = af_db::get_conn().unwrap();
    let saved_records: Vec<(String, i64)> = connection
        .prepare(
            "SELECT relative_path, byte_delta FROM mcbrowser_audit_events
             WHERE trigger = 'file_saved' AND status = 'completed' ORDER BY seq",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        saved_records,
        vec![
            ("docs/target.txt".to_string(), 5),
            ("secret.txt".to_string(), 6),
            ("leaf-alias.txt".to_string(), 6),
            ("dir-alias/target.txt".to_string(), -9),
        ]
    );
}

#[tokio::test]
async fn mounted_delete_and_recursive_delete_preserve_accounting_pending_and_pending_audit_on_release_failure(
) {
    use std::os::unix::fs::symlink;

    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();

    for dir in ["tree/sub", "partial_abort", "partial_clean"] {
        let created_dir = request_json(
            fixture.router(),
            "POST",
            "/mcbrowser/directory",
            serde_json::json!({ "path": dir, "parents": true }),
        )
        .await;
        assert_eq!(created_dir.status(), StatusCode::CREATED);
    }

    for (path, content) in [
        ("single.txt", "hello"),
        ("clean.txt", "four"),
        ("tree/a.txt", "123456"),
        ("tree/sub/b.txt", "1234567"),
        ("partial_abort/first.txt", "eight!!!"),
        ("partial_clean/second.txt", "nine!!!!!"),
    ] {
        let created_file = request_json(
            fixture.router(),
            "POST",
            "/mcbrowser/file",
            serde_json::json!({ "path": path, "content": content }),
        )
        .await;
        assert_eq!(created_file.status(), StatusCode::CREATED);
    }
    symlink(
        "missing.txt",
        fixture.user_root().join("partial_abort/blocked_link"),
    )
    .unwrap();
    symlink(
        "missing.txt",
        fixture.user_root().join("partial_clean/blocked_link"),
    )
    .unwrap();
    assert_eq!(fixture.used_bytes(), 39);

    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute_batch(
                "DELETE FROM mcbrowser_event_queue;
                 INSERT INTO mcbrowser_event_settings (id, queue_enabled, updated_at)
                 VALUES (1, 1, CURRENT_TIMESTAMP)
                 ON CONFLICT(id) DO UPDATE SET queue_enabled = 1;
                 CREATE TRIGGER reject_delete_quota_release BEFORE UPDATE OF used_bytes ON user_quotas
                 WHEN NEW.used_bytes < OLD.used_bytes
                 BEGIN SELECT RAISE(ABORT, 'injected quota release failure'); END;",
            )
            .unwrap();
    }

    let delete_single = request_json(
        fixture.router(),
        "DELETE",
        "/mcbrowser/entry?path=single.txt",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(delete_single.status(), StatusCode::OK);
    let single_payload: serde_json::Value =
        serde_json::from_slice(&delete_single.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(
        single_payload,
        serde_json::json!({ "success": true, "accounting_pending": true })
    );
    assert!(!fixture.user_root().join("single.txt").exists());
    assert_eq!(fixture.used_bytes(), 39);

    let delete_tree = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/delete-recursive",
        serde_json::json!({ "path": "tree" }),
    )
    .await;
    assert_eq!(delete_tree.status(), StatusCode::OK);
    let tree_payload: serde_json::Value =
        serde_json::from_slice(&delete_tree.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(
        tree_payload,
        serde_json::json!({ "success": true, "accounting_pending": true })
    );
    assert!(!fixture.user_root().join("tree").exists());
    assert_eq!(fixture.used_bytes(), 39);

    let partial_abort = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/delete-recursive",
        serde_json::json!({ "path": "partial_abort" }),
    )
    .await;
    assert_eq!(partial_abort.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let partial_abort_payload: serde_json::Value =
        serde_json::from_slice(&partial_abort.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(partial_abort_payload["code"], "ACCOUNTING_PENDING");
    assert!(!fixture.user_root().join("partial_abort/first.txt").exists());
    assert!(fixture.user_root().join("partial_abort").exists());
    assert_eq!(fixture.used_bytes(), 39);

    {
        let connection = af_db::get_conn().unwrap();
        let queued_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM mcbrowser_event_queue", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(queued_count, 0);

        connection
            .execute_batch("DROP TRIGGER reject_delete_quota_release;")
            .unwrap();
    }

    let partial_clean = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/delete-recursive",
        serde_json::json!({ "path": "partial_clean" }),
    )
    .await;
    assert_eq!(partial_clean.status(), StatusCode::FORBIDDEN);
    assert!(!fixture.user_root().join("partial_clean/second.txt").exists());
    assert!(fixture.user_root().join("partial_clean").exists());
    assert_eq!(fixture.used_bytes(), 30);

    let delete_clean = request_json(
        fixture.router(),
        "DELETE",
        "/mcbrowser/entry?path=clean.txt",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(delete_clean.status(), StatusCode::OK);
    let clean_payload: serde_json::Value =
        serde_json::from_slice(&delete_clean.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(
        clean_payload,
        serde_json::json!({ "success": true, "accounting_pending": false })
    );
    assert!(!fixture.user_root().join("clean.txt").exists());
    assert_eq!(fixture.used_bytes(), 26);

    let connection = af_db::get_conn().unwrap();
    let delete_audits: Vec<(String, String, i64)> = connection
        .prepare(
            "SELECT relative_path, status, byte_delta FROM mcbrowser_audit_events
             WHERE trigger = 'entry_deleted' ORDER BY seq",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        delete_audits,
        vec![
            ("single.txt".to_string(), "pending".to_string(), 0),
            ("tree".to_string(), "pending".to_string(), 0),
            ("partial_abort".to_string(), "pending".to_string(), 0),
            ("partial_clean".to_string(), "pending".to_string(), 0),
            ("clean.txt".to_string(), "completed".to_string(), -4),
        ]
    );

    let queued_payloads: Vec<String> = connection
        .prepare("SELECT payload_json FROM mcbrowser_event_queue ORDER BY rowid")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(queued_payloads.len(), 1);
    let queued_json: serde_json::Value = serde_json::from_str(&queued_payloads[0]).unwrap();
    assert_eq!(queued_json["relative_path"], "clean.txt");
    assert_eq!(queued_json["byte_delta"], -4);
}

#[tokio::test]
async fn mounted_confined_alias_copy_enforces_policy_hops_conflicts_quota_and_audit_identity() {
    use std::os::unix::fs::symlink;

    let _guard = TEST_DATABASE_LOCK.lock().await;
    let fixture = HttpFixture::new();

    for dir in ["real/sub", "bundle/nested", "secret"] {
        let created_dir = request_json(
            fixture.router(),
            "POST",
            "/mcbrowser/directory",
            serde_json::json!({ "path": dir, "parents": true }),
        )
        .await;
        assert_eq!(created_dir.status(), StatusCode::CREATED);
    }

    for (path, content) in [
        ("real/note.txt", "hello"),
        ("real/sub/deep.txt", "world!"),
        ("bundle/plain.txt", "plain"),
        ("secret/private.txt", "classified"),
    ] {
        let created_file = request_json(
            fixture.router(),
            "POST",
            "/mcbrowser/file",
            serde_json::json!({ "path": path, "content": content }),
        )
        .await;
        assert_eq!(created_file.status(), StatusCode::CREATED);
    }
    assert_eq!(fixture.used_bytes(), 26);

    let outside = fixture.directory.join("outside.txt");
    fs::write(&outside, "outside").unwrap();
    symlink("real/note.txt", fixture.user_root().join("note-alias.txt")).unwrap();
    symlink("real", fixture.user_root().join("real-hop")).unwrap();
    symlink("real-hop", fixture.user_root().join("real-alias")).unwrap();
    symlink(
        "../../real/note.txt",
        fixture.user_root().join("bundle/nested/linked-note.txt"),
    )
    .unwrap();
    symlink("../real/sub", fixture.user_root().join("bundle/linked-sub")).unwrap();
    symlink(&outside, fixture.user_root().join("escape-alias.txt")).unwrap();
    symlink("missing.txt", fixture.user_root().join("broken-alias.txt")).unwrap();

    let copy_file_alias = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/copy",
        serde_json::json!({ "from": "note-alias.txt", "to": "copied-note.txt" }),
    )
    .await;
    assert_eq!(copy_file_alias.status(), StatusCode::OK);
    let copy_file_payload: serde_json::Value =
        serde_json::from_slice(&copy_file_alias.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(copy_file_payload["from"], "note-alias.txt");
    assert_eq!(copy_file_payload["to"], "copied-note.txt");
    assert_eq!(copy_file_payload["path"], "copied-note.txt");
    assert_eq!(fixture.used_bytes(), 31);
    assert_eq!(
        fs::read_to_string(fixture.user_root().join("copied-note.txt")).unwrap(),
        "hello"
    );

    let copy_keep_both = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/copy",
        serde_json::json!({
            "from": "note-alias.txt",
            "to": "copied-note.txt",
            "conflict": "keep-both"
        }),
    )
    .await;
    assert_eq!(copy_keep_both.status(), StatusCode::OK);
    let keep_both_payload: serde_json::Value =
        serde_json::from_slice(&copy_keep_both.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(keep_both_payload["path"], "copied-note(1).txt");
    assert_eq!(fixture.used_bytes(), 36);

    let copy_dir_alias = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/copy",
        serde_json::json!({ "from": "real-alias", "to": "copied-real" }),
    )
    .await;
    assert_eq!(copy_dir_alias.status(), StatusCode::OK);
    assert_eq!(fixture.used_bytes(), 47);
    assert_eq!(
        fs::read_to_string(fixture.user_root().join("copied-real/note.txt")).unwrap(),
        "hello"
    );
    assert_eq!(
        fs::read_to_string(fixture.user_root().join("copied-real/sub/deep.txt")).unwrap(),
        "world!"
    );

    let copy_bundle = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/copy",
        serde_json::json!({ "from": "bundle", "to": "copied-bundle" }),
    )
    .await;
    assert_eq!(copy_bundle.status(), StatusCode::OK);
    assert_eq!(fixture.used_bytes(), 63);
    assert_eq!(
        fs::read_to_string(fixture.user_root().join("copied-bundle/nested/linked-note.txt"))
            .unwrap(),
        "hello"
    );
    assert_eq!(
        fs::read_to_string(fixture.user_root().join("copied-bundle/linked-sub/deep.txt")).unwrap(),
        "world!"
    );

    let created_large = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({ "path": "shrink-target.txt", "content": "0123456789abcdef" }),
    )
    .await;
    assert_eq!(created_large.status(), StatusCode::CREATED);
    assert_eq!(fixture.used_bytes(), 79);

    let overwrite_shrink = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/copy",
        serde_json::json!({
            "from": "note-alias.txt",
            "to": "shrink-target.txt",
            "conflict": "overwrite"
        }),
    )
    .await;
    assert_eq!(overwrite_shrink.status(), StatusCode::OK);
    let shrink_payload: serde_json::Value =
        serde_json::from_slice(&overwrite_shrink.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(shrink_payload["from"], "note-alias.txt");
    assert_eq!(shrink_payload["to"], "shrink-target.txt");
    assert_eq!(shrink_payload["accounting_pending"], false);
    assert_eq!(fixture.used_bytes(), 68);

    let created_pending_target = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/file",
        serde_json::json!({ "path": "pending-shrink.txt", "content": "twelve-bytes" }),
    )
    .await;
    assert_eq!(created_pending_target.status(), StatusCode::CREATED);
    assert_eq!(fixture.used_bytes(), 80);

    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_copy_quota_release BEFORE UPDATE ON user_quotas
                 WHEN NEW.used_bytes < OLD.used_bytes
                 BEGIN SELECT RAISE(ABORT, 'injected copy quota release failure'); END;",
            )
            .unwrap();
    }
    let pending_shrink = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/copy",
        serde_json::json!({
            "from": "note-alias.txt",
            "to": "pending-shrink.txt",
            "conflict": "overwrite"
        }),
    )
    .await;
    assert_eq!(pending_shrink.status(), StatusCode::OK);
    let pending_payload: serde_json::Value =
        serde_json::from_slice(&pending_shrink.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(pending_payload["accounting_pending"], true);
    assert_eq!(
        fs::read_to_string(fixture.user_root().join("pending-shrink.txt")).unwrap(),
        "hello"
    );
    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute_batch("DROP TRIGGER reject_copy_quota_release;")
            .unwrap();
    }

    {
        let connection = af_db::get_conn().unwrap();
        connection
            .execute("INSERT INTO mcbrowser_policies (user_id) VALUES (1)", [])
            .unwrap();
        connection
            .execute(
                "INSERT INTO mcbrowser_policy_rules (user_id, rule_order, path, allow) VALUES (1, 0, 'real-hop', 0)",
                [],
            )
            .unwrap();
    }
    let denied_hop = request_json(
        fixture.router(),
        "POST",
        "/mcbrowser/copy",
        serde_json::json!({ "from": "real-alias", "to": "denied-hop-copy" }),
    )
    .await;
    assert_eq!(denied_hop.status(), StatusCode::FORBIDDEN);
    assert!(!fixture.user_root().join("denied-hop-copy").exists());

    for (invalid_source, expected_status) in [
        ("escape-alias.txt", StatusCode::FORBIDDEN),
        ("broken-alias.txt", StatusCode::NOT_FOUND),
    ] {
        let invalid_copy = request_json(
            fixture.router(),
            "POST",
            "/mcbrowser/copy",
            serde_json::json!({ "from": invalid_source, "to": "invalid-out" }),
        )
        .await;
        assert_eq!(invalid_copy.status(), expected_status);
        assert!(!fixture.user_root().join("invalid-out").exists());
    }

    let connection = af_db::get_conn().unwrap();
    let copy_audits: Vec<(String, String, i64)> = connection
        .prepare(
            "SELECT relative_path, destination_path, byte_delta FROM mcbrowser_audit_events
             WHERE trigger = 'entry_copied' AND status = 'completed' ORDER BY seq",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        copy_audits,
        vec![
            (
                "note-alias.txt".to_string(),
                "copied-note.txt".to_string(),
                5
            ),
            (
                "note-alias.txt".to_string(),
                "copied-note(1).txt".to_string(),
                5
            ),
            ("real-alias".to_string(), "copied-real".to_string(), 11),
            ("bundle".to_string(), "copied-bundle".to_string(), 16),
            (
                "note-alias.txt".to_string(),
                "shrink-target.txt".to_string(),
                -11
            ),
        ]
    );
    let pending_copy_audits: Vec<(String, String, String)> = connection
        .prepare(
            "SELECT relative_path, destination_path, status FROM mcbrowser_audit_events
             WHERE trigger = 'entry_copied' AND destination_path = 'pending-shrink.txt' ORDER BY seq",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        pending_copy_audits,
        vec![(
            "note-alias.txt".to_string(),
            "pending-shrink.txt".to_string(),
            "pending".to_string(),
        )]
    );
}
