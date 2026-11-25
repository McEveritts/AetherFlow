use super::host_resolution::strip_host_port_and_dot;
use super::host_validation::is_host_trusted;
use super::proxy_helpers::{
    forward_proxy_http_headers, is_strict_loopback_https_url, resolve_optional_authenticated_user,
    upstream_uses_tls, verify_proxy_basic_credentials,
};
use super::rate_limit::SlidingWindowLimiter;
use super::{app_subdomain_proxy_middleware, resolve_app_target_for_host};
use af_runner::package_executor::{
    requires_external_app_auth as external_proxy_requires_auth, GATEWAY_APP_HEADER,
};
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Json, Response};
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use axum::routing::any;
use axum::Router;
use chrono::Utc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn external_auth_covers_newly_protected_apps() {
    for app in ["unmanic", "netdata", "autoscan"] {
        assert!(external_proxy_requires_auth(app));
    }
}

#[tokio::test]
async fn external_proxy_limits_invalid_basic_auth_attempts_per_ip() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    ensure_shared_test_db();
    env::set_var("AETHERFLOW_BASE_DOMAIN", "proxy-auth.test");
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "netdata".into(),
        public_domain: "netdata.proxy-auth.test".into(),
        external_access_enabled: true,
        listen_port: 19999,
        ..Default::default()
    })
    .unwrap();
    let app = Router::new()
        .fallback(any(|| async { StatusCode::NOT_FOUND }))
        .layer(axum::middleware::from_fn(app_subdomain_proxy_middleware));
    for (ip, attempts) in [("198.51.100.1:1010", 21), ("198.51.100.2:1010", 1)] {
        for attempt in 0..attempts {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header(header::HOST, "netdata.proxy-auth.test")
                        .header(header::AUTHORIZATION, "Basic aW52YWxpZDpjcmVkZW50aWFscw==")
                        .extension(ConnectInfo(ip.parse::<SocketAddr>().unwrap()))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            if attempt == 20 {
                assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
                let body = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                assert!(std::str::from_utf8(&body).unwrap().contains("RATE_LIMITED"));
            } else {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }
        }
    }
}

#[tokio::test]
async fn managed_apache_proxy_routes_http_and_websocket_after_admin_authentication() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use base64::Engine;
    use tower::ServiceExt;

    if run_plugin_test_in_subprocess() {
        return;
    }
    let root = ensure_shared_test_db().parent().unwrap();
    env::set_var("AETHERFLOW_CONFIG_ROOT", root);
    env::set_var("AETHERFLOW_MASTER_CREDS_FILE", root.join("no-master-file"));
    env::set_var("AETHERFLOW_BASE_DOMAIN", "proxy-auth.test");
    let host = "metrics.apps.proxy-auth.test";
    let upstream_port = spawn_strict_kestrel_mock_upstream().await;
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "prometheus".into(),
        public_domain: host.into(),
        external_access_enabled: true,
        listen_port: upstream_port.into(),
        ..Default::default()
    })
    .unwrap();
    let conn = af_db::get_conn().unwrap();
    conn.execute(
        "INSERT INTO users (username, role, password_hash) VALUES ('managed-admin', 'admin', ?1)",
        [bcrypt::hash("fixture-password", 4).unwrap()],
    )
    .unwrap();
    drop(conn);
    let basic = base64::engine::general_purpose::STANDARD.encode("managed-admin:fixture-password");
    let app = Router::new()
        .fallback(any(|| async { "dashboard fixture" }))
        .layer(axum::middleware::from_fn(app_subdomain_proxy_middleware));

    for (authority, marker, peer, expected) in [
        (
            "localhost",
            "prometheus",
            "127.0.0.1:3000",
            StatusCode::MISDIRECTED_REQUEST,
        ),
        (
            host,
            "mcvnc",
            "127.0.0.1:3000",
            StatusCode::MISDIRECTED_REQUEST,
        ),
        (
            host,
            "prometheus",
            "192.0.2.1:3000",
            StatusCode::MISDIRECTED_REQUEST,
        ),
        (
            host,
            "prometheus",
            "127.0.0.1:3000",
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, authority)
                    .header(GATEWAY_APP_HEADER, marker)
                    .header(header::UPGRADE, "websocket")
                    .header(header::CONNECTION, "Upgrade")
                    .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{authority} {marker} {peer}");
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{gateway}/metrics?format=raw"))
        .header(header::HOST, host)
        .header(GATEWAY_APP_HEADER, "prometheus")
        .header(header::AUTHORIZATION, format!("Basic {basic}"))
        .header(
            header::COOKIE,
            "aetherflow_session=fixture; app_cookie=keep",
        )
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", "192.0.2.7")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let observed: serde_json::Value = response.json().await.unwrap();
    assert_eq!(observed["requestLine"], "GET /metrics?format=raw HTTP/1.1");
    assert_eq!(observed["host"], host);
    let headers = &observed["headers"];
    assert_eq!(headers["x-forwarded-proto"][0], "https");
    assert_eq!(headers["x-forwarded-for"][0], "192.0.2.7");
    assert_eq!(headers["x-aetherflow-user"][0], "managed-admin");
    assert_eq!(headers["cookie"][0], "app_cookie=keep");
    assert!(headers.get("authorization").is_none());
    assert!(headers.get(GATEWAY_APP_HEADER).is_none());

    let mut socket = tokio::net::TcpStream::connect(gateway).await.unwrap();
    let handshake = format!(
        "GET /socket HTTP/1.1\r\nHost: {host}\r\n{GATEWAY_APP_HEADER}: prometheus\r\nAuthorization: Basic {basic}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    socket.write_all(handshake.as_bytes()).await.unwrap();
    let mut response = [0; 1024];
    let read = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response[..read].starts_with(b"HTTP/1.1 101 Switching Protocols"));
}

#[tokio::test]
async fn proxy_basic_rejects_totp_admin_but_mfa_session_is_accepted() {
    use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
    use base64::Engine;
    use tower::ServiceExt;
    if run_plugin_test_in_subprocess() {
        return;
    }
    let fixture_root = ensure_shared_test_db().parent().unwrap();
    env::set_var("AETHERFLOW_CONFIG_ROOT", fixture_root);
    env::set_var(
        "AETHERFLOW_MASTER_CREDS_FILE",
        fixture_root.join("missing-master-file"),
    );
    let password = "test-proxy-admin-password";
    let secret = "JBSWY3DPEHPK3PXP";
    let writer = af_db::get_conn().unwrap();
    writer
        .execute(
            "INSERT INTO users (id, username, role, password_hash, totp_enabled, totp_secret)
        VALUES (93, 'proxy-mfa', 'admin', ?1, 1, ?2)",
            rusqlite::params![bcrypt::hash(password, 4).unwrap(), secret],
        )
        .unwrap();

    let master = af_db::encrypt_key(
        &serde_json::json!({
            "username": "proxy-mfa",
            "password": password,
        })
        .to_string(),
    )
    .unwrap();
    writer
        .execute(
            "INSERT INTO system_config (key, value) VALUES ('master_credentials', ?1)",
            [&master],
        )
        .unwrap();
    drop(writer);
    assert_eq!(
        af_services::mutators::load_master_credentials().0,
        "proxy-mfa"
    );

    let mut basic = axum::http::HeaderMap::new();
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("proxy-mfa:{password}"));
    basic.insert(
        header::AUTHORIZATION,
        format!("Basic {encoded}").parse().unwrap(),
    );
    assert_eq!(verify_proxy_basic_credentials(&basic), None);

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static("app-launch-browser"),
    );
    let login = crate::auth::local_login(
        headers.clone(),
        Json(crate::auth::CredentialsRequest {
            username: "proxy-mfa".into(),
            password: password.into(),
            setup_token: None,
        }),
    )
    .await;
    let body = axum::body::to_bytes(login.into_body(), 4096).await.unwrap();
    let challenge: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(challenge["requires_mfa"], true);
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret.as_bytes())
        .unwrap();
    let code =
        totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &secret, Utc::now().timestamp() as u64);
    let mfa = crate::auth::mfa_login_verify(
        headers,
        Json(crate::auth::MfaVerifyRequest {
            mfa_token: challenge["mfa_token"].as_str().unwrap().into(),
            code,
        }),
    )
    .await;
    assert_eq!(mfa.status(), StatusCode::OK);
    let cookie = mfa.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    basic.insert(header::COOKIE, cookie.parse().unwrap());
    basic.insert(
        header::USER_AGENT,
        HeaderValue::from_static("app-launch-browser"),
    );
    let principal = resolve_optional_authenticated_user(&basic, None).unwrap();
    assert_eq!(principal.role, "admin");
    assert_eq!(principal.username, "proxy-mfa");

    let upstream_port = spawn_strict_kestrel_mock_upstream().await;
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "netdata".into(),
        public_domain: "metrics.proxy-mfa.test".into(),
        external_access_enabled: true,
        tls_enabled: true,
        listen_port: upstream_port.into(),
        ..Default::default()
    })
    .unwrap();
    let app = crate::routes::build_router()
        .layer(axum::middleware::from_fn(app_subdomain_proxy_middleware));
    for (session, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(cookie), StatusCode::OK),
    ] {
        let mut request = Request::builder()
            .uri("/")
            .header(header::USER_AGENT, "app-launch-browser")
            .header(header::HOST, "metrics.proxy-mfa.test")
            .header(GATEWAY_APP_HEADER, "netdata")
            .header(header::AUTHORIZATION, &basic[header::AUTHORIZATION])
            .extension(ConnectInfo(
                "127.0.0.1:10443".parse::<SocketAddr>().unwrap(),
            ));
        if let Some(session) = session {
            request = request.header(header::COOKIE, session);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }

    let host = "metrics.proxy-mfa.test";
    let origin = "http://localhost";
    let destination = format!("https://{host}/graph?view=all");
    let launch_request = |destination: &str, csrf: bool| {
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/apps/launch")
            .header(header::HOST, "localhost")
            .header(header::ORIGIN, origin)
            .header(header::USER_AGENT, "app-launch-browser")
            .header(header::COOKIE, format!("{cookie}; csrf_token=launch-csrf"))
            .header(header::CONTENT_TYPE, "application/json");
        if csrf {
            req = req.header("x-csrf-token", "launch-csrf");
        }
        req.body(Body::from(
            serde_json::json!({ "app": "netdata", "destination": destination }).to_string(),
        ))
        .unwrap()
    };
    let read_json = |response: Response| async move {
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
    };

    let dir = fixture_root.join("etc/apache2/sites-enabled");
    std::fs::create_dir_all(&dir).unwrap();
    let vhost = dir.join("aetherflow-ext-netdata.conf");
    std::fs::write(
        &vhost,
        format!(
            "<VirtualHost *:443>
ServerName {host}
</VirtualHost>
"
        ),
    )
    .unwrap();
    let legacy = app
        .clone()
        .oneshot(launch_request(&destination, true))
        .await
        .unwrap();
    assert_eq!(read_json(legacy).await, serde_json::json!({}));
    std::fs::write(
        &vhost,
        format!(
            "<VirtualHost *:443>
ServerName {host}
RequestHeader set {GATEWAY_APP_HEADER} netdata
</VirtualHost>
"
        ),
    )
    .unwrap();

    let no_csrf = app
        .clone()
        .oneshot(launch_request(&destination, false))
        .await
        .unwrap();
    assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);
    let wrong_destination = app
        .clone()
        .oneshot(launch_request("https://other.proxy-mfa.test/", true))
        .await
        .unwrap();
    assert_eq!(read_json(wrong_destination).await, serde_json::json!({}));

    let issue = || async {
        let response = app
            .clone()
            .oneshot(launch_request(&destination, true))
            .await
            .unwrap();
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        read_json(response).await["ticket"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let exchange = |ticket: &str, dashboard: &str, managed: bool| {
        let mut builder = Request::builder()
            .method("POST")
            .uri(af_models::APP_LAUNCH_EXCHANGE_PATH)
            .header(header::HOST, host)
            .header("x-forwarded-proto", "https")
            .header(header::ORIGIN, dashboard)
            .header(header::USER_AGENT, "app-launch-browser")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .extension(ConnectInfo(
                "127.0.0.1:10443".parse::<SocketAddr>().unwrap(),
            ));
        if managed {
            builder = builder.header(GATEWAY_APP_HEADER, "netdata");
        }
        builder
            .body(Body::from(format!("ticket={ticket}")))
            .unwrap()
    };

    let ticket = issue().await;
    for (dashboard, managed, expected) in [
        ("https://unexpected.test", true, StatusCode::UNAUTHORIZED),
        (origin, false, StatusCode::NOT_FOUND),
    ] {
        let response = app
            .clone()
            .oneshot(exchange(&ticket, dashboard, managed))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let (first, second) = tokio::join!(
        app.clone().oneshot(exchange(&ticket, origin, true)),
        app.clone().oneshot(exchange(&ticket, origin, true)),
    );
    let (mut first, mut second) = (first.unwrap(), second.unwrap());
    if second.status() == StatusCode::SEE_OTHER {
        std::mem::swap(&mut first, &mut second);
    }
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(first.headers()[header::LOCATION], destination);
    assert_eq!(first.headers()[header::CACHE_CONTROL], "private, no-store");
    let set_cookie = first.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.starts_with("__Host-aetherflow_app="));
    assert!(set_cookie.contains("; Secure; HttpOnly"));
    assert!(!set_cookie.contains("Domain="));
    assert!(!set_cookie.contains(cookie));
    let app_cookie = set_cookie.split(';').next().unwrap();
    let request_app = || {
        Request::builder()
            .uri("/graph?view=all")
            .header(header::HOST, host)
            .header(header::USER_AGENT, "app-launch-browser")
            .header(header::COOKIE, format!("{app_cookie}; native=keep"))
            .header(GATEWAY_APP_HEADER, "netdata")
            .header("x-forwarded-proto", "https")
            .extension(ConnectInfo(
                "127.0.0.1:10443".parse::<SocketAddr>().unwrap(),
            ))
            .body(Body::empty())
            .unwrap()
    };
    let proxied = app.clone().oneshot(request_app()).await.unwrap();
    let observed = read_json(proxied).await;
    assert_eq!(observed["headers"]["cookie"][0], "native=keep");
    assert_eq!(observed["headers"]["x-aetherflow-user"][0], "proxy-mfa");
    assert_eq!(observed["requestLine"], "GET /graph?view=all HTTP/1.1");

    let pending = issue().await;
    let db = af_db::get_conn().unwrap();
    db.execute("UPDATE users SET role = 'user' WHERE id = 93", [])
        .unwrap();
    let denied = app.clone().oneshot(request_app()).await.unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let denied = app
        .clone()
        .oneshot(launch_request(&destination, true))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let denied = app
        .clone()
        .oneshot(exchange(&pending, origin, true))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    db.execute("UPDATE users SET role = 'admin' WHERE id = 93", [])
        .unwrap();
    let pending = issue().await;
    db.execute("DELETE FROM active_sessions WHERE user_id = 93", [])
        .unwrap();
    let denied = app
        .clone()
        .oneshot(exchange(&pending, origin, true))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let denied = app.oneshot(request_app()).await.unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
}

/// Spawns a strict raw HTTP/1.1 mock upstream that behaves like Jellyfin/Kestrel:
/// - Rejects any request with `!= 1` `Host:` header lines with `400 Bad Request`
/// - Supports WebSocket upgrade (`Upgrade: websocket`) and echoes a frame over the upgraded stream
/// - For normal HTTP requests, returns 200 OK with JSON detailing the observed request line,
///   host header count, headers, and body.
async fn spawn_strict_kestrel_mock_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut temp = [0u8; 4096];
                let header_end_pos = loop {
                    match socket.read(&mut temp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&temp[..n]);
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break pos;
                            }
                        }
                    }
                };

                let header_bytes = &buf[..header_end_pos];
                let header_text = String::from_utf8_lossy(header_bytes).to_string();
                let mut lines = header_text.split("\r\n");
                let request_line = lines.next().unwrap_or("").to_string();

                let mut host_headers = Vec::new();
                let mut content_length: usize = 0;
                let mut is_ws = false;
                let mut all_headers: HashMap<String, Vec<String>> = HashMap::new();

                for line in lines {
                    if let Some((k, v)) = line.split_once(':') {
                        let key_trim = k.trim();
                        let val_trim = v.trim().to_string();
                        if key_trim.eq_ignore_ascii_case("host") {
                            host_headers.push(val_trim.clone());
                        }
                        if key_trim.eq_ignore_ascii_case("content-length") {
                            content_length = val_trim.parse::<usize>().unwrap_or(0);
                        }
                        if key_trim.eq_ignore_ascii_case("upgrade")
                            && val_trim.eq_ignore_ascii_case("websocket")
                        {
                            is_ws = true;
                        }
                        all_headers
                            .entry(key_trim.to_ascii_lowercase())
                            .or_default()
                            .push(val_trim);
                    }
                }

                // Strict Kestrel check: must have exactly 1 Host header
                if host_headers.len() != 1 {
                    let resp = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\nDuplicate or missing Host header: count={}",
                        format!("Duplicate or missing Host header: count={}", host_headers.len()).len(),
                        host_headers.len()
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }

                let body_start = header_end_pos + 4;
                if request_line.starts_with("POST /Upload ") {
                    let mut received = buf.len().saturating_sub(body_start);
                    while received < content_length {
                        match socket.read(&mut temp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => received += n,
                        }
                    }
                    let payload = serde_json::json!({
                        "receivedBytes": received,
                    });
                    let body_json = serde_json::to_string(&payload).unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body_json.len(),
                        body_json
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }

                while buf.len() < body_start + content_length {
                    match socket.read(&mut temp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&temp[..n]),
                    }
                }
                let body_slice = if buf.len() >= body_start + content_length {
                    &buf[body_start..body_start + content_length]
                } else {
                    &buf[body_start..]
                };
                let body_str = String::from_utf8_lossy(body_slice).to_string();

                if is_ws {
                    let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Upstream-Host-Count: 1\r\n\r\n";
                    if socket.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                    // Read ping payload over upgraded tunnel and reply
                    let mut ws_buf = [0u8; 64];
                    if let Ok(n) = socket.read(&mut ws_buf).await {
                        if n > 0 {
                            let reply = format!(
                                "ws-ack:{}:{}",
                                host_headers[0],
                                String::from_utf8_lossy(&ws_buf[..n])
                            );
                            let _ = socket.write_all(reply.as_bytes()).await;
                        }
                    }
                    return;
                }

                let payload = serde_json::json!({
                    "requestLine": request_line,
                    "hostCount": host_headers.len(),
                    "host": host_headers[0],
                    "headers": all_headers,
                    "body": body_str,
                });
                let body_json = serde_json::to_string(&payload).unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Upstream-App: jellyfin\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_json.len(),
                    body_json
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });

    port
}

#[tokio::test]
async fn test_subdomain_proxy_sends_single_host_header_and_preserves_http_and_ws() {
    let tmp_dir = std::env::temp_dir().join(format!(
        "af-proxy-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let db_file = tmp_dir.join("proxy_test.sqlite");
    std::env::set_var("DB_PATH", &db_file);
    af_db::init_db().unwrap();

    let upstream_port = spawn_strict_kestrel_mock_upstream().await;
    let now = Utc::now();
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "jellyfin".to_string(),
        public_domain: "jellyfin.example.test".to_string(),
        external_access_enabled: true,
        listen_port: upstream_port as i32,
        tls_enabled: true,
        created_at: now,
        updated_at: now,
    })
    .unwrap();
    af_db::invalidate_ingress_cache();

    let app = Router::new()
        .route("/*path", any(|| async { StatusCode::NOT_FOUND }))
        .route("/", any(|| async { StatusCode::NOT_FOUND }))
        .layer(axum::middleware::from_fn(app_subdomain_proxy_middleware));

    let gw_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_port = gw_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(
            gw_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    let client = reqwest::Client::new();

    // 1. GET request with query params, cookies, Range, and spoofed X-Aetherflow-User
    let get_resp = client
        .get(format!(
            "http://127.0.0.1:{}/System/Info/Public?format=json",
            gw_port
        ))
        .header("Host", "jellyfin.example.test")
        .header("Cookie", "jellyfin_credentials=abc123")
        .header("Range", "bytes=0-1023")
        .header("X-Aetherflow-User", "spoofed-attacker")
        .send()
        .await
        .unwrap();

    assert_eq!(
        get_resp.status(),
        reqwest::StatusCode::OK,
        "strict upstream must return 200 OK (not 400 Bad Request from duplicate Host)"
    );
    assert_eq!(
        get_resp
            .headers()
            .get("x-upstream-app")
            .and_then(|v| v.to_str().ok()),
        Some("jellyfin")
    );
    let get_json: serde_json::Value = get_resp.json().await.unwrap();
    assert_eq!(get_json["hostCount"], 1);
    assert_eq!(get_json["host"], "jellyfin.example.test");
    assert_eq!(
        get_json["requestLine"],
        "GET /System/Info/Public?format=json HTTP/1.1"
    );
    assert_eq!(
        get_json["headers"]["cookie"][0],
        "jellyfin_credentials=abc123"
    );
    assert_eq!(get_json["headers"]["range"][0], "bytes=0-1023");
    assert!(
        get_json["headers"].get("x-aetherflow-user").is_none(),
        "spoofed X-Aetherflow-User header must be stripped on unauthenticated request"
    );
    assert_eq!(
        get_json["headers"]["x-forwarded-host"][0],
        "jellyfin.example.test"
    );

    // 2. POST request with JSON body via internal .aether.local domain from loopback
    let post_resp = client
        .post(format!(
            "http://127.0.0.1:{}/Users/AuthenticateByName",
            gw_port
        ))
        .header("Host", "jellyfin.aether.local")
        .header("Content-Type", "application/json")
        .body(r#"{"Username":"alice","Pw":"secret"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(post_resp.status(), reqwest::StatusCode::OK);
    let post_json: serde_json::Value = post_resp.json().await.unwrap();
    assert_eq!(post_json["hostCount"], 1);
    assert_eq!(post_json["host"], "jellyfin.aether.local");
    assert_eq!(post_json["body"], r#"{"Username":"alice","Pw":"secret"}"#);

    // 3. WebSocket upgrade tunneling against strict single-Host upstream
    let mut ws_sock = tokio::net::TcpStream::connect(("127.0.0.1", gw_port))
        .await
        .unwrap();
    let ws_handshake = concat!(
        "GET /socket?api_key=test HTTP/1.1\r\n",
        "Host: jellyfin.example.test\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    );
    ws_sock.write_all(ws_handshake.as_bytes()).await.unwrap();

    let mut resp_buf = [0u8; 1024];
    let n = ws_sock.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]).to_string();
    assert!(
        resp_str.starts_with("HTTP/1.1 101 Switching Protocols"),
        "expected 101 Switching Protocols, got: {}",
        resp_str
    );

    let mut ws_buf = [0u8; 1024];
    ws_sock.write_all(b"ping-jellyfin").await.unwrap();
    let n2 = ws_sock.read(&mut ws_buf).await.unwrap();
    let tunnel_reply = String::from_utf8_lossy(&ws_buf[..n2]).to_string();
    assert_eq!(tunnel_reply, "ws-ack:jellyfin.example.test:ping-jellyfin");

    // 4. Untrusted non-loopback peer cannot spoof X-Forwarded-* or X-Real-IP on HTTP or WS,
    // and >64 MiB request bodies stream cleanly without 413 buffering limits.
    let untrusted_peer: SocketAddr = "198.51.100.77:54321".parse().unwrap();
    let untrusted_req = axum::http::Request::builder()
        .method("GET")
        .uri("/System/Info")
        .header("Host", "jellyfin.example.test")
        .header("X-Forwarded-For", "10.0.0.5")
        .header("X-Forwarded-Host", "evil.attacker.example")
        .header("X-Forwarded-Proto", "https")
        .header("X-Real-IP", "10.0.0.5")
        .extension(ConnectInfo(untrusted_peer))
        .body(Body::empty())
        .unwrap();
    let untrusted_app = Router::new()
        .route("/*path", any(|| async { StatusCode::NOT_FOUND }))
        .layer(axum::middleware::from_fn(app_subdomain_proxy_middleware));
    let untrusted_resp = tower::ServiceExt::oneshot(untrusted_app.clone(), untrusted_req)
        .await
        .unwrap();
    assert_eq!(untrusted_resp.status(), StatusCode::OK);
    let untrusted_body = axum::body::to_bytes(untrusted_resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let untrusted_json: serde_json::Value = serde_json::from_slice(&untrusted_body).unwrap();
    assert_eq!(
        untrusted_json["headers"]["x-forwarded-for"][0],
        "198.51.100.77"
    );
    assert_eq!(untrusted_json["headers"]["x-real-ip"][0], "198.51.100.77");
    assert_eq!(
        untrusted_json["headers"]["x-forwarded-host"][0],
        "jellyfin.example.test"
    );
    assert_eq!(untrusted_json["headers"]["x-forwarded-proto"][0], "http");

    let upload_bytes: usize = 65 * 1024 * 1024;
    let streaming_body = futures::stream::iter(
        (0..65).map(|_| Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b'a'; 1024 * 1024]))),
    );
    let streaming_req = axum::http::Request::builder()
        .method("POST")
        .uri("/Upload")
        .header("Host", "jellyfin.example.test")
        .header("Content-Length", upload_bytes.to_string())
        .body(Body::from_stream(streaming_body))
        .unwrap();
    let streaming_resp = tower::ServiceExt::oneshot(untrusted_app, streaming_req)
        .await
        .unwrap();
    assert_eq!(streaming_resp.status(), StatusCode::OK);
    let streaming_resp_bytes = axum::body::to_bytes(streaming_resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let streaming_json: serde_json::Value = serde_json::from_slice(&streaming_resp_bytes).unwrap();
    assert_eq!(streaming_json["receivedBytes"], upload_bytes);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn upstream_uses_tls_identifies_kasmvnc_and_loopback_urls() {
    assert!(upstream_uses_tls("kasmvnc", 6081));
    assert!(upstream_uses_tls("af-kasmvnc", 6081));
    assert!(upstream_uses_tls(" KasmVNC ", 6081));
    assert!(!upstream_uses_tls("jellyfin", 8096));
    assert!(!upstream_uses_tls("kasmvnc", 0));

    assert!(is_strict_loopback_https_url(
        "https://127.0.0.1:6081/vnc.html"
    ));
    assert!(is_strict_loopback_https_url("https://[::1]:6081/"));
    assert!(!is_strict_loopback_https_url("http://127.0.0.1:6081/"));
    assert!(!is_strict_loopback_https_url("https://192.168.1.50:6081/"));
    assert!(!is_strict_loopback_https_url("https://evil.example.com/"));
}

#[test]
fn external_subdomain_fails_closed_without_explicit_enabled_ingress() {
    const CHILD_ENV: &str = "AF_EXTERNAL_FAIL_CLOSED_TEST_CHILD";
    if env::var(CHILD_ENV).as_deref() != Ok("1") {
        let status = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "middlewares::tests::external_subdomain_fails_closed_without_explicit_enabled_ingress",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    let root = env::temp_dir().join(format!("af-ext-fail-closed-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(root.join("install")).unwrap();
    env::set_var("AETHERFLOW_FS_ROOT", &root);
    env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
    env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    let db = root.join("gateway.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db);
    }
    let catalog = root.join("packages.json");
    std::fs::write(
        &catalog,
        serde_json::to_vec(&serde_json::json!([{
            "name": "syncthing",
            "label": "Syncthing",
            "description": "fixture",
            "lock_file": "/install/.syncthing.lock",
            "category": "test",
            "service_type": "systemd",
            "service_name": "syncthing",
            "default_port": 8384
        }]))
        .unwrap(),
    )
    .unwrap();
    env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    let automation = root.join("automation.json");
    std::fs::write(&automation, "{}").unwrap();
    env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", &automation);
    af_db::init_db().unwrap();
    af_services::initialize_package_jobs(rusqlite::Connection::open(&db).unwrap()).unwrap();
    af_db::set_base_domain("example.test").unwrap();
    std::fs::write(root.join("install/.syncthing.lock"), "installed").unwrap();

    // 1. No AppIngressConfig: internal .aether.local resolves, external <app>.<base_domain> fails closed
    assert_eq!(
        resolve_app_target_for_host("syncthing.aether.local"),
        Some(("syncthing".into(), 8384))
    );
    assert_eq!(resolve_app_target_for_host("syncthing.example.test"), None);

    // 2. Explicit AppIngressConfig with external_access_enabled: false -> external fails closed
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "syncthing".into(),
        public_domain: "syncthing.example.test".into(),
        external_access_enabled: false,
        listen_port: 18384,
        ..Default::default()
    })
    .unwrap();
    af_db::invalidate_ingress_cache();
    assert_eq!(
        resolve_app_target_for_host("syncthing.aether.local"),
        Some(("syncthing".into(), 18384))
    );
    assert_eq!(resolve_app_target_for_host("syncthing.example.test"), None);

    // 3. Stored AppIngressConfig with out-of-range listen_port: 0 -> both internal and external fail closed
    af_db::get_conn()
        .unwrap()
        .execute(
            "UPDATE app_ingress_configs SET external_access_enabled = 1, listen_port = 0 WHERE app_name = 'syncthing'",
            [],
        )
        .unwrap();
    af_db::invalidate_ingress_cache();
    assert_eq!(resolve_app_target_for_host("syncthing.aether.local"), None);
    assert_eq!(resolve_app_target_for_host("syncthing.example.test"), None);

    // 4. Explicit AppIngressConfig with external_access_enabled: true and valid port -> external allowed
    af_db::set_app_ingress_config(&af_models::AppIngressConfig {
        app_name: "syncthing".into(),
        public_domain: "syncthing.example.test".into(),
        external_access_enabled: true,
        listen_port: 18384,
        ..Default::default()
    })
    .unwrap();
    af_db::invalidate_ingress_cache();
    assert_eq!(
        resolve_app_target_for_host("syncthing.example.test"),
        Some(("syncthing".into(), 18384))
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn proxy_rate_limit_refunds_verified_credentials_without_refunding_failures() {
    let limiter = SlidingWindowLimiter::new(2, Duration::from_secs(60));
    assert!(limiter.allow("fixture-client"));
    for _ in 0..30 {
        let verified = limiter.reserve("fixture-client").unwrap();
        assert!(!limiter.allow("fixture-client"));
        limiter.refund("fixture-client", verified);
    }
    assert!(limiter.allow("fixture-client"));
    assert!(!limiter.allow("fixture-client"));
}

mod proxy_header_tests {
    use super::*;

    #[test]
    fn authority_validation_rejects_userinfo_and_non_numeric_ports() {
        let allowed = HashSet::from(["localhost".to_string()]);
        for invalid in [
            "localhost:@example.test",
            "localhost:word",
            "localhost:65536",
            "localhost:80:90",
            "localhost\\example.test",
            " localhost",
            "localhost/evil",
            "[::1]:bad",
        ] {
            assert!(strip_host_port_and_dot(invalid).is_empty(), "{invalid}");
            assert!(!is_host_trusted(invalid, &allowed), "{invalid}");
        }
        for (input, expected) in [
            ("LOCALHOST.:8080", "localhost"),
            ("example.test:443", "example.test"),
            ("[::1]:8080", "::1"),
            ("::1", "::1"),
            ("[2001:db8::1]", "2001:db8::1"),
        ] {
            assert_eq!(strip_host_port_and_dot(input), expected);
        }
    }

    #[test]
    fn forwards_public_host_once_and_filters_untrusted_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_static("jellyfin.example.com"),
        );
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert("x-aetherflow-user", HeaderValue::from_static("spoofed"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer test-token"),
        );
        let request = forward_proxy_http_headers(
            reqwest::Client::new().get("http://127.0.0.1:8096/health"),
            &headers,
            "jellyfin.example.com",
            Some("127.0.0.1".parse().unwrap()),
            true,
        )
        .build()
        .unwrap();

        assert_eq!(request.headers().get_all(header::HOST).iter().count(), 1);
        assert_eq!(request.headers()[header::HOST], "jellyfin.example.com");
        assert_eq!(
            request.headers()["x-forwarded-host"],
            "jellyfin.example.com"
        );
        assert_eq!(request.headers()["x-forwarded-proto"], "https");
        assert_eq!(request.headers()["authorization"], "Bearer test-token");
        assert!(!request.headers().contains_key(header::CONNECTION));
        assert!(!request.headers().contains_key("x-aetherflow-user"));
    }

    #[tokio::test]
    async fn esc09_master_credentials_never_authenticate_proxy_basic_after_user_changes() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        use base64::Engine;
        if run_plugin_test_in_subprocess() {
            return;
        }
        let fixture_root = ensure_shared_test_db().parent().unwrap();
        env::set_var("AETHERFLOW_CONFIG_ROOT", fixture_root);
        let master_pass = "legacy-provisioning-master-pass";
        let master_file = fixture_root.join(".master.creds");
        std::fs::write(
            &master_file,
            serde_json::json!({
                "username": "ghost-admin",
                "password": master_pass,
            })
            .to_string(),
        )
        .unwrap();
        env::set_var("AETHERFLOW_MASTER_CREDS_FILE", &master_file);
        let loaded_master = af_services::mutators::load_master_credentials();
        assert_eq!(loaded_master.0, "ghost-admin");
        assert_eq!(loaded_master.1, master_pass);

        let make_basic = |user: &str, pass: &str| {
            let mut h = axum::http::HeaderMap::new();
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            h.insert(
                header::AUTHORIZATION,
                format!("Basic {encoded}").parse().unwrap(),
            );
            h
        };

        // 1. Deleted/nonexistent admin with valid .master.creds file -> rejected.
        assert_eq!(
            verify_proxy_basic_credentials(&make_basic("ghost-admin", master_pass)),
            None
        );

        // 2. Active admin matching password -> accepted; after password rotation -> old master rejected.
        let writer = af_db::get_conn().unwrap();
        writer
            .execute(
                "INSERT INTO users (id, username, role, password_hash, totp_enabled) \
                 VALUES (401, 'ghost-admin', 'admin', ?1, 0)",
                rusqlite::params![bcrypt::hash("rotated-new-password", 4).unwrap()],
            )
            .unwrap();
        drop(writer);
        assert_eq!(
            verify_proxy_basic_credentials(&make_basic("ghost-admin", master_pass)),
            None
        );
        assert_eq!(
            verify_proxy_basic_credentials(&make_basic("ghost-admin", "rotated-new-password")),
            Some("ghost-admin".to_string())
        );

        // 3. Demoted to user -> rejected even with matching password.
        af_db::get_conn()
            .unwrap()
            .execute("UPDATE users SET role = 'user' WHERE id = 401", [])
            .unwrap();
        assert_eq!(
            verify_proxy_basic_credentials(&make_basic("ghost-admin", "rotated-new-password")),
            None
        );
    }

    #[tokio::test]
    async fn esc10_and_esc14_local_auth_lan_opt_in_totp_launch_and_rutorrent_proxy_token() {
        use crate::plugins::tests::{ensure_shared_test_db, run_plugin_test_in_subprocess};
        use tower::ServiceExt;
        if run_plugin_test_in_subprocess() {
            return;
        }
        let fixture_root = ensure_shared_test_db().parent().unwrap();
        env::set_var("AETHERFLOW_FS_ROOT", fixture_root);
        env::set_var("AETHERFLOW_CONFIG_ROOT", fixture_root);
        env::set_var(
            "ALLOWED_HOSTS",
            "localhost,127.0.0.1,aetherflow.aether.local",
        );
        std::fs::create_dir_all(fixture_root.join("install")).unwrap();
        std::fs::write(fixture_root.join("install/.rutorrent.lock"), "installed\n").unwrap();
        std::fs::write(
            fixture_root.join("packages.json"),
            serde_json::to_vec(&serde_json::json!([
                {
                    "name": "rutorrent", "label": "ruTorrent", "description": "fixture",
                    "lock_file": "/install/.rutorrent.lock", "category": "test",
                    "service_type": "apache", "service_name": "apache2", "default_port": 8087
                }
            ]))
            .unwrap(),
        )
        .unwrap();

        let upstream_port = spawn_strict_kestrel_mock_upstream().await;
        af_db::set_app_ingress_config(&af_models::AppIngressConfig {
            app_name: "rutorrent".into(),
            public_domain: "torrent.example.test".into(),
            external_access_enabled: false,
            tls_enabled: false,
            listen_port: upstream_port.into(),
            ..Default::default()
        })
        .unwrap();

        let token_file = fixture_root.join("rutorrent-proxy-token");
        let expected_proxy_token =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        std::fs::write(&token_file, format!("{expected_proxy_token}\n")).unwrap();
        env::set_var("AETHERFLOW_RUTORRENT_PROXY_TOKEN_FILE", &token_file);

        let writer = af_db::get_conn().unwrap();
        writer
            .execute(
                "INSERT INTO users (id, username, role, password_hash, totp_enabled, totp_secret) \
                 VALUES (402, 'totp-local-admin', 'admin', ?1, 1, 'JBSWY3DPEHPK3PXP')",
                rusqlite::params![bcrypt::hash("StrongPass!1", 4).unwrap()],
            )
            .unwrap();
        drop(writer);

        let app = crate::routes::build_router()
            .layer(axum::middleware::from_fn(app_subdomain_proxy_middleware));

        // 1. Default AF_ALLOW_UNAUTH_LOCAL_LAN unset -> RFC 1918 LAN client must authenticate.
        env::remove_var("AF_ALLOW_UNAUTH_LOCAL_LAN");
        let unauth_lan = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "rutorrent.aether.local")
                    .header("x-real-ip", "192.168.1.50")
                    .extension(ConnectInfo(
                        "127.0.0.1:41000".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth_lan.status(), StatusCode::UNAUTHORIZED);

        // 2. With AF_ALLOW_UNAUTH_LOCAL_LAN=1:
        //    - Tailscale CGNAT (100.64.0.10) still requires authentication (401, not 403).
        //    - Loopback (127.0.0.1) still requires authentication (401).
        //    - RFC 1918 LAN (192.168.1.50) is permitted unauthenticated and gets ruTorrent proxy token.
        env::set_var("AF_ALLOW_UNAUTH_LOCAL_LAN", "1");
        for denied_bypass_ip in ["100.64.0.10", "127.0.0.1"] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/")
                        .header(header::HOST, "rutorrent.aether.local")
                        .header("x-real-ip", denied_bypass_ip)
                        .extension(ConnectInfo(
                            "127.0.0.1:41001".parse::<SocketAddr>().unwrap(),
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{denied_bypass_ip} must not bypass auth even when AF_ALLOW_UNAUTH_LOCAL_LAN=1"
            );
        }

        let lan_ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "rutorrent.aether.local")
                    .header("x-real-ip", "192.168.1.50")
                    .header("x-aetherflow-rutorrent-token", "spoofed-client-token")
                    .extension(ConnectInfo(
                        "127.0.0.1:41002".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(lan_ok.status(), StatusCode::OK);
        let body = axum::body::to_bytes(lan_ok.into_body(), 16384)
            .await
            .unwrap();
        let observed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            observed["headers"]["x-aetherflow-rutorrent-token"][0],
            expected_proxy_token
        );

        // 3. TOTP admin launches http://rutorrent.aether.local via app_launch -> aetherflow_local_app cookie.
        env::remove_var("AF_ALLOW_UNAUTH_LOCAL_LAN");
        let mut ua_headers = axum::http::HeaderMap::new();
        ua_headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static("local-launch-ua"),
        );
        let (admin_jwt, _) = crate::auth::create_standard_jwt(402, &ua_headers).unwrap();

        let issue_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/api/v1/admin/apps/launch")
                    .header(header::HOST, "aetherflow.aether.local")
                    .header(header::ORIGIN, "http://aetherflow.aether.local")
                    .header(header::USER_AGENT, "local-launch-ua")
                    .header(header::AUTHORIZATION, format!("Bearer {admin_jwt}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("x-real-ip", "100.64.0.10")
                    .extension(ConnectInfo(
                        "127.0.0.1:41003".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::from(
                        r#"{"app":"rutorrent","destination":"http://rutorrent.aether.local/"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(issue_resp.status(), StatusCode::OK);
        let issue_body = axum::body::to_bytes(issue_resp.into_body(), 4096)
            .await
            .unwrap();
        let issue_json: serde_json::Value = serde_json::from_slice(&issue_body).unwrap();
        let ticket = issue_json["ticket"].as_str().expect("local launch ticket");

        let redeem_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri(af_models::APP_LAUNCH_EXCHANGE_PATH)
                    .header(header::HOST, "rutorrent.aether.local")
                    .header(header::ORIGIN, "http://aetherflow.aether.local")
                    .header(header::USER_AGENT, "local-launch-ua")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("x-real-ip", "100.64.0.10")
                    .extension(ConnectInfo(
                        "127.0.0.1:41004".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::from(format!("ticket={ticket}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(redeem_resp.status(), StatusCode::SEE_OTHER);
        let set_cookie = redeem_resp.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.starts_with("aetherflow_local_app="));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Lax"));
        assert!(!set_cookie.contains("Secure"));
        let cookie_pair = set_cookie.split(';').next().unwrap();

        // Authenticated Tailscale admin request using aetherflow_local_app cookie succeeds
        // and strips aetherflow_local_app before forwarding upstream while injecting X-Aetherflow-User
        // and X-Aetherflow-Rutorrent-Token.
        let authed_local = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "rutorrent.aether.local")
                    .header(header::USER_AGENT, "local-launch-ua")
                    .header(header::COOKIE, format!("{cookie_pair}; keep_me=1"))
                    .header("x-real-ip", "100.64.0.10")
                    .extension(ConnectInfo(
                        "127.0.0.1:41005".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authed_local.status(), StatusCode::OK);
        let authed_body = axum::body::to_bytes(authed_local.into_body(), 16384)
            .await
            .unwrap();
        let authed_obs: serde_json::Value = serde_json::from_slice(&authed_body).unwrap();
        assert_eq!(
            authed_obs["headers"]["x-aetherflow-user"][0],
            "totp-local-admin"
        );
        assert_eq!(
            authed_obs["headers"]["x-aetherflow-rutorrent-token"][0],
            expected_proxy_token
        );
        assert_eq!(authed_obs["headers"]["cookie"][0], "keep_me=1");

        // Deleting active_sessions immediately invalidates the local launch cookie (ESC-05).
        af_db::get_conn()
            .unwrap()
            .execute("DELETE FROM active_sessions WHERE user_id = 402", [])
            .unwrap();
        let revoked_local = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::HOST, "rutorrent.aether.local")
                    .header(header::USER_AGENT, "local-launch-ua")
                    .header(header::COOKIE, cookie_pair)
                    .header("x-real-ip", "100.64.0.10")
                    .extension(ConnectInfo(
                        "127.0.0.1:41006".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked_local.status(), StatusCode::UNAUTHORIZED);
    }
}
