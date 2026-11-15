use af_librespeed::config::Config;
use af_librespeed::db::TelemetryVault;
use af_librespeed::routes::build_router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE,
    USER_AGENT,
};
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(label: &str) -> Self {
        let unique = format!(
            "af-librespeed-it-{}-{}-{}",
            label,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn with_peer(mut req: Request<Body>, addr: &str) -> Request<Body> {
    let sock: SocketAddr = addr.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(sock));
    req
}

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec()
}

fn make_test_config(tmp: &TempDirGuard) -> (Config, TelemetryVault) {
    let assets_dir = tmp.0.join("assets");
    fs::create_dir_all(assets_dir.join("javascript")).unwrap();
    fs::write(assets_dir.join("index.html"), "<html>ObsidianIndex</html>").unwrap();
    fs::write(
        assets_dir.join("javascript").join("index.js"),
        "console.log('ok');",
    )
    .unwrap();

    let db_path = tmp.0.join("speedtest.db");
    let vault = TelemetryVault::open(&db_path).unwrap();

    let cfg = Config {
        bind_address: "127.0.0.1".to_string(),
        listen_port: 8988,
        url_base: "speedtest".to_string(),
        assets_path: assets_dir,
        statistics_password: "VaultSecretPassword!9".to_string(),
        redact_ip_addresses: false,
        database_type: "sqlite".to_string(),
        database_file: db_path,
        enable_id_obfuscation: false,
        enable_tls: false,
        tls_cert_file: PathBuf::new(),
        tls_key_file: PathBuf::new(),
        trusted_proxies: Vec::new(),
        max_telemetry_rows: 100_000,
        ..Config::default()
    };
    (cfg, vault)
}

#[tokio::test]
async fn empty_garbage_and_cors_endpoints_behave_correctly() {
    let tmp = TempDirGuard::new("empty-garbage");
    let (cfg, vault) = make_test_config(&tmp);
    let app = build_router(cfg, Some(vault));

    // /empty drains payload and returns empty 200 with CORS when cors=true
    let req = Request::builder()
        .method(Method::POST)
        .uri("/backend/empty.php?cors=true")
        .body(Body::from(vec![0x55u8; 8192]))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "*");
    assert!(body_bytes(res).await.is_empty());

    // OPTIONS preflight with cors=true
    let opts = Request::builder()
        .method(Method::OPTIONS)
        .uri("/speedtest/garbage?cors=true")
        .body(Body::empty())
        .unwrap();
    let opts_res = app.clone().oneshot(opts).await.unwrap();
    assert_eq!(opts_res.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        opts_res.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        "*"
    );

    // /empty rejects > 64 MiB stream without buffering indefinitely
    let too_big = futures::stream::iter((0..65).map(|_| {
        Ok::<axum::body::Bytes, std::convert::Infallible>(axum::body::Bytes::from(vec![
            0u8;
            1024 * 1024
        ]))
    }));
    let big_req = Request::builder()
        .method(Method::POST)
        .uri("/empty")
        .body(Body::from_stream(too_big))
        .unwrap();
    let big_res = app.clone().oneshot(big_req).await.unwrap();
    assert_eq!(big_res.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // /garbage respects ckSize and clamps to >=1 MiB
    let garbage_req = Request::builder()
        .method(Method::GET)
        .uri("/speedtest/backend/garbage.php?ckSize=2")
        .body(Body::empty())
        .unwrap();
    let garbage_res = app.clone().oneshot(garbage_req).await.unwrap();
    assert_eq!(garbage_res.status(), StatusCode::OK);
    assert_eq!(
        garbage_res.headers().get(CONTENT_LENGTH).unwrap(),
        "2097152"
    );
    assert_eq!(body_bytes(garbage_res).await.len(), 2 * 1024 * 1024);

    // HEAD /garbage preserves Content-Length with empty body
    let head_req = Request::builder()
        .method(Method::HEAD)
        .uri("/garbage?ckSize=0")
        .body(Body::empty())
        .unwrap();
    let head_res = app.clone().oneshot(head_req).await.unwrap();
    assert_eq!(head_res.status(), StatusCode::OK);
    assert_eq!(head_res.headers().get(CONTENT_LENGTH).unwrap(), "1048576");
    assert!(body_bytes(head_res).await.is_empty());
}

#[tokio::test]
async fn getip_proxy_trust_classification_isp_and_redaction() {
    let tmp = TempDirGuard::new("getip");
    let (mut cfg, vault) = make_test_config(&tmp);

    // 1. Default empty trusted_proxies ignores loopback X-Forwarded-For spoofing
    let untrusted_app = build_router(cfg.clone(), Some(vault.clone()));
    let req_untrusted_loop = with_peer(
        Request::builder()
            .uri("/backend/getIP.php?isp=true")
            .header("x-forwarded-for", "203.0.113.42")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:50000",
    );
    let res_untrusted_loop = untrusted_app.oneshot(req_untrusted_loop).await.unwrap();
    let json_untrusted: Value =
        serde_json::from_slice(&body_bytes(res_untrusted_loop).await).unwrap();
    assert_eq!(
        json_untrusted["processedString"],
        "127.0.0.1 - localhost IPv4 access"
    );

    // 2. Explicitly configured trusted_proxies trusts strictly the single rightmost hop
    cfg.trusted_proxies = vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()];
    let app = build_router(cfg.clone(), Some(vault.clone()));

    let req_loop = with_peer(
        Request::builder()
            .uri("/backend/getIP.php?isp=true")
            .header("x-forwarded-for", "10.0.0.1, 203.0.113.42")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:50000",
    );
    let res_loop = app.clone().oneshot(req_loop).await.unwrap();
    assert_eq!(res_loop.status(), StatusCode::OK);
    let json: Value = serde_json::from_slice(&body_bytes(res_loop).await).unwrap();
    assert_eq!(
        json["processedString"],
        "203.0.113.42 - documentation IPv4 access"
    );
    assert_eq!(json["rawIspInfo"], "");

    // Non-loopback peer ignores X-Forwarded-For spoofing attempt
    let req_ext = with_peer(
        Request::builder()
            .uri("/speedtest/getIP")
            .header("x-forwarded-for", "8.8.4.4")
            .header("x-real-ip", "8.8.8.8")
            .body(Body::empty())
            .unwrap(),
        "198.51.100.7:50000",
    );
    let res_ext = app.clone().oneshot(req_ext).await.unwrap();
    assert_eq!(res_ext.status(), StatusCode::OK);
    let text = String::from_utf8(body_bytes(res_ext).await).unwrap();
    assert_eq!(text, "198.51.100.7 - documentation IPv4 access");

    // With redact_ip_addresses=true, /getIP never discloses client IP
    cfg.redact_ip_addresses = true;
    let redacted_app = build_router(cfg, Some(vault));
    let req_red = with_peer(
        Request::builder()
            .uri("/getIP?isp=true")
            .header("x-forwarded-for", "203.0.113.42")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:50000",
    );
    let res_red = redacted_app.oneshot(req_red).await.unwrap();
    let json_red: Value = serde_json::from_slice(&body_bytes(res_red).await).unwrap();
    assert_eq!(json_red["processedString"], "0.0.0.0");
}

#[tokio::test]
async fn telemetry_urlencoded_multipart_obfuscation_redaction_and_png_badge() {
    let tmp = TempDirGuard::new("telemetry");
    let (mut cfg, vault) = make_test_config(&tmp);
    cfg.redact_ip_addresses = true;
    cfg.enable_id_obfuscation = true;
    cfg.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
    let app = build_router(cfg, Some(vault.clone()));

    // 1. Multipart form-data submission under /<url_base>/results/telemetry.php
    let boundary = "----afBoundary7d9c2";
    let mp_body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"dl\"\r\n\r\n842.15\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"ul\"\r\n\r\n710.80\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"ping\"\r\n\r\n3.41\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"jitter\"\r\n\r\n0.55\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"ispinfo\"\r\n\r\n{{\"processedString\":\"203.0.113.5 - ISP\",\"rawIspInfo\":\"{{\\\"ip\\\":\\\"203.0.113.5\\\",\\\"hostname\\\":\\\"edge1.isp.example\\\",\\\"org\\\":\\\"AS64500 FiberCo\\\"}}\"}}\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"log\"\r\n\r\n1731638400000: peer 203.0.113.5 v6 2001:db8::1234\r\n\
         --{b}\r\nContent-Disposition: form-data; name=\"extra\"\r\n\r\n<script>alert(1)</script> from 198.51.100.88\r\n\
         --{b}--\r\n",
        b = boundary
    );

    let mp_req = with_peer(
        Request::builder()
            .method(Method::POST)
            .uri("/speedtest/results/telemetry.php")
            .header(
                CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .header(USER_AGENT, "LibreTest/1.0 (client 203.0.113.5)")
            .header("accept-language", "en-US,203.0.113.5")
            .header("x-forwarded-for", "203.0.113.5")
            .body(Body::from(mp_body))
            .unwrap(),
        "127.0.0.1:44444",
    );
    let mp_res = app.clone().oneshot(mp_req).await.unwrap();
    assert_eq!(mp_res.status(), StatusCode::OK);
    let resp_str = String::from_utf8(body_bytes(mp_res).await).unwrap();
    assert!(resp_str.starts_with("id "));
    let obf_id = resp_str.strip_prefix("id ").unwrap().trim().to_string();
    assert_eq!(obf_id.len(), 26);

    // Raw DB record has redacted IP/ispinfo/log/extra/ua/lang while preserving timestamp and AS org
    let recent = vault.list_recent(10).await.unwrap();
    assert_eq!(recent.len(), 1);
    let saved = &recent[0];
    assert_ne!(saved.uuid, obf_id);
    assert_eq!(saved.ip, "0.0.0.0");
    assert!(!saved.ispinfo.contains("203.0.113.5"));
    assert!(!saved.ispinfo.contains("edge1.isp.example"));
    assert!(saved.ispinfo.contains("AS64500 FiberCo"));
    assert_eq!(saved.log, "1731638400000: peer 0.0.0.0 v6 ::");
    assert!(!saved.extra.contains("198.51.100.88"));
    assert!(!saved.ua.contains("203.0.113.5"));
    assert!(!saved.lang.contains("203.0.113.5"));

    // Unobfuscated raw DB UUID MUST NOT fetch /results when enable_id_obfuscation=true
    let raw_png_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/results?id={}", saved.uuid))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(raw_png_res.status(), StatusCode::NOT_FOUND);

    // Obfuscated ID renders valid 500x286 PNG and survives daemon restart (DB reopen)
    let reopened_vault = TelemetryVault::open(&tmp.0.join("speedtest.db")).unwrap();
    let mut cfg_reopened = make_test_config(&tmp).0;
    cfg_reopened.redact_ip_addresses = true;
    cfg_reopened.enable_id_obfuscation = true;
    let reopened_app = build_router(cfg_reopened, Some(reopened_vault));

    let ok_png_res = reopened_app
        .oneshot(
            Request::builder()
                .uri(format!("/results/?id={obf_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_png_res.status(), StatusCode::OK);
    assert_eq!(ok_png_res.headers().get(CONTENT_TYPE).unwrap(), "image/png");
    assert_eq!(
        ok_png_res.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    let png_bytes = body_bytes(ok_png_res).await;
    let img = image::load_from_memory(&png_bytes).unwrap();
    assert_eq!((img.width(), img.height()), (500, 286));

    // 2. Rejects > 256 KiB telemetry payload
    let oversize = "dl=1&log=".to_string() + &"A".repeat(260 * 1024);
    let over_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/results/telemetry")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(oversize))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(over_res.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 3. Urlencoded submission works cleanly too
    let form_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/results/telemetry")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("dl=123.4&ul=56.7&ping=14.2&jitter=1.1"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(form_res.status(), StatusCode::OK);
    let form_text = String::from_utf8(body_bytes(form_res).await).unwrap();
    assert!(form_text.starts_with("id "));
}

#[tokio::test]
async fn stats_auth_locked_cookies_xss_escaping_and_logout() {
    let tmp = TempDirGuard::new("stats");
    let (mut cfg, vault) = make_test_config(&tmp);

    // Locked when password is PASSWORD
    cfg.statistics_password = "PASSWORD".to_string();
    let locked_app = build_router(cfg.clone(), Some(vault.clone()));
    let locked_res = locked_app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let locked_html = String::from_utf8(body_bytes(locked_res).await).unwrap();
    assert!(locked_html.contains("Statistics Access Locked"));

    let locked_login = locked_app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/stats")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("op=login&password=PASSWORD"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(locked_login.headers().get(SET_COOKIE).is_none());

    // Unlocked instance with explicit trusted loopback proxy
    cfg.statistics_password = "StrongAdminPassword!42".to_string();
    cfg.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
    let app = build_router(cfg, Some(vault));

    // Seed record with XSS payload
    let seed_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/results/telemetry")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(USER_AGENT, "<img src=x onerror=alert(1)>")
                .body(Body::from(
                    "dl=500&ul=250&ping=5&jitter=1&extra=%3Cscript%3Ealert(9)%3C%2Fscript%3E",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let seed_id = String::from_utf8(body_bytes(seed_res).await)
        .unwrap()
        .strip_prefix("id ")
        .unwrap()
        .to_string();

    // Forged unsigned cookie rejected
    let forged_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/stats?op=id&id=L100")
                .header(COOKIE, "logged=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let forged_html = String::from_utf8(body_bytes(forged_res).await).unwrap();
    assert!(forged_html.contains("obs-auth-panel"));
    assert!(!forged_html.contains(&seed_id));

    // Wrong password rejected with 401
    let bad_pw = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/stats")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("op=login&password=wrong"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_pw.status(), StatusCode::UNAUTHORIZED);

    // Valid login under /speedtest/stats with trusted loopback X-Forwarded-Proto=https sets Secure signed cookie
    let login_res = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .method(Method::POST)
                .uri("/speedtest/stats")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("x-forwarded-proto", "https")
                .body(Body::from("op=login&password=StrongAdminPassword%2142"))
                .unwrap(),
            "127.0.0.1:41234",
        ))
        .await
        .unwrap();
    assert_eq!(login_res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        login_res.headers().get(LOCATION).unwrap(),
        "/speedtest/stats"
    );
    let set_cookie = login_res
        .headers()
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("Path=/speedtest/stats"));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(set_cookie.contains("Secure"));
    let cookie_pair = set_cookie.split(';').next().unwrap().to_string();

    // Authenticated L100 lookup
    let l100_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/speedtest/stats?op=id&id=L100")
                .header(COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(l100_res.status(), StatusCode::OK);
    let l100_html = String::from_utf8(body_bytes(l100_res).await).unwrap();
    assert!(l100_html.contains("obs-table"));
    assert!(l100_html.contains(&seed_id));

    // Authenticated single UUID lookup verifies strict HTML escaping of XSS payloads
    let detail_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/speedtest/stats?op=id&id={seed_id}"))
                .header(COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let detail_html = String::from_utf8(body_bytes(detail_res).await).unwrap();
    assert!(!detail_html.contains("<script>alert(9)</script>"));
    assert!(detail_html.contains("&lt;script&gt;alert(9)&lt;/script&gt;"));
    assert!(!detail_html.contains("<img src=x onerror=alert(1)>"));
    assert!(detail_html.contains("&lt;img src=x onerror=alert(1)&gt;"));

    // GET logout is rejected (405) to block cross-site <img>/<link> logout CSRF; POST logout clears cookie
    let get_logout_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/speedtest/stats?op=logout")
                .header(COOKIE, &cookie_pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_logout_res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(get_logout_res.headers().get(SET_COOKIE).is_none());

    let logout_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/speedtest/stats")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(COOKIE, &cookie_pair)
                .body(Body::from("op=logout"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_res.status(), StatusCode::SEE_OTHER);
    let clear_cookie = logout_res
        .headers()
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(clear_cookie.contains("Max-Age=0"));

    // Case A: Behind trusted loopback proxy, rotating spoofed leftmost XFF while rightmost hop stays
    // the attacker's IP (198.51.100.42) triggers 429 on the 11th attempt without locking out other proxy clients.
    for attempt in 0..10 {
        let fail_res = app
            .clone()
            .oneshot(with_peer(
                Request::builder()
                    .method(Method::POST)
                    .uri("/stats.php?cors=true")
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(
                        "x-forwarded-for",
                        format!("192.0.2.{attempt}, 198.51.100.42"),
                    )
                    .body(Body::from("op=login&password=bad"))
                    .unwrap(),
                "127.0.0.1:50000",
            ))
            .await
            .unwrap();
        assert_eq!(fail_res.status(), StatusCode::UNAUTHORIZED);
        assert!(fail_res
            .headers()
            .get(ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }
    let throttled = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .method(Method::POST)
                .uri("/stats.php")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("x-forwarded-for", "192.0.2.250, 198.51.100.42")
                .body(Body::from("op=login&password=bad"))
                .unwrap(),
            "127.0.0.1:50000",
        ))
        .await
        .unwrap();
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(throttled
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("default-src 'none'"));

    // Case B: Direct untrusted peer (not in trusted_proxies) rotating BOTH leftmost and rightmost XFF
    // is still throttled by peer IP after 10 failures.
    for attempt in 0..10 {
        let fail_res = app
            .clone()
            .oneshot(with_peer(
                Request::builder()
                    .method(Method::POST)
                    .uri("/stats.php")
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(
                        "x-forwarded-for",
                        format!("192.0.2.{attempt}, 198.51.100.{attempt}"),
                    )
                    .body(Body::from("op=login&password=bad"))
                    .unwrap(),
                "203.0.113.99:50000",
            ))
            .await
            .unwrap();
        assert_eq!(fail_res.status(), StatusCode::UNAUTHORIZED);
    }
    let untrusted_throttled = app
        .oneshot(with_peer(
            Request::builder()
                .method(Method::POST)
                .uri("/stats.php")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("x-forwarded-for", "192.0.2.250, 198.51.100.250")
                .body(Body::from("op=login&password=bad"))
                .unwrap(),
            "203.0.113.99:50000",
        ))
        .await
        .unwrap();
    assert_eq!(untrusted_throttled.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn telemetry_empty_rejection_retention_rate_limit_and_garbage_concurrency_cap() {
    let tmp = TempDirGuard::new("dos-hardening");
    let db_path = tmp.0.join("capped.db");
    let vault = TelemetryVault::open_with_max_rows(&db_path, 3).unwrap();
    let (mut cfg, _) = make_test_config(&tmp);
    cfg.database_file = db_path;
    cfg.max_telemetry_rows = 3;
    let app = build_router(cfg, Some(vault.clone()));

    // 1. Empty or non-numeric / PII measurement payload is rejected with 400
    let empty_meas = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .method(Method::POST)
                .uri("/results/telemetry")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("extra=spam-only&log=nometrics"))
                .unwrap(),
            "198.51.100.20:40000",
        ))
        .await
        .unwrap();
    assert_eq!(empty_meas.status(), StatusCode::BAD_REQUEST);

    for bad_metric in [
        "dl=203.0.113.42",
        "ul=%3Cscript%3E",
        "ping=-4.2",
        "jitter=NaN",
    ] {
        let bad_res = app
            .clone()
            .oneshot(with_peer(
                Request::builder()
                    .method(Method::POST)
                    .uri("/results/telemetry")
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(bad_metric))
                    .unwrap(),
                "198.51.100.20:40000",
            ))
            .await
            .unwrap();
        assert_eq!(
            bad_res.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for {bad_metric}"
        );
    }

    // 2. Retention cap keeps at most 3 newest telemetry rows
    for idx in 1..=5 {
        let res = app
            .clone()
            .oneshot(with_peer(
                Request::builder()
                    .method(Method::POST)
                    .uri("/results/telemetry")
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!("dl={idx}00.0")))
                    .unwrap(),
                "198.51.100.21:40000",
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
    let kept = vault.list_recent(10).await.unwrap();
    assert_eq!(kept.len(), 3);
    assert_eq!(kept[0].dl, "500.0");
    assert_eq!(kept[2].dl, "300.0");

    // 3. Per-client telemetry write rate limit triggers 429 after 30 writes in 60s
    for _ in 0..30 {
        let res = app
            .clone()
            .oneshot(with_peer(
                Request::builder()
                    .method(Method::POST)
                    .uri("/results/telemetry")
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("dl=99.9"))
                    .unwrap(),
                "198.51.100.99:40000",
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
    let limited = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .method(Method::POST)
                .uri("/results/telemetry")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("dl=99.9"))
                .unwrap(),
            "198.51.100.99:40000",
        ))
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

    // 4. Concurrent /garbage stream cap returns 503 when 32 active streams are held open
    let mut held_responses = Vec::new();
    for _ in 0..af_librespeed::routes::MAX_CONCURRENT_GARBAGE_STREAMS {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/garbage?ckSize=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        held_responses.push(res);
    }
    let over_cap = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/garbage?ckSize=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(over_cap.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(held_responses);
    let recovered = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/garbage?ckSize=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
    drop(recovered);

    // 5. Per-client-IP /garbage stream cap blocks single-IP starvation while leaving other IPs unblocked
    let mut per_ip_held = Vec::new();
    for _ in 0..af_librespeed::routes::MAX_GARBAGE_STREAMS_PER_IP {
        let res = app
            .clone()
            .oneshot(with_peer(
                Request::builder()
                    .uri("/garbage?ckSize=2")
                    .body(Body::empty())
                    .unwrap(),
                "198.51.100.55:41000",
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        per_ip_held.push(res);
    }
    let ip_capped = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .uri("/garbage?ckSize=2")
                .body(Body::empty())
                .unwrap(),
            "198.51.100.55:41001",
        ))
        .await
        .unwrap();
    assert_eq!(ip_capped.status(), StatusCode::TOO_MANY_REQUESTS);

    let other_ip_ok = app
        .oneshot(with_peer(
            Request::builder()
                .uri("/garbage?ckSize=1")
                .body(Body::empty())
                .unwrap(),
            "198.51.100.77:41000",
        ))
        .await
        .unwrap();
    assert_eq!(other_ip_ok.status(), StatusCode::OK);
    drop(per_ip_held);
}

#[tokio::test]
async fn native_tls_listener_serves_https_and_fails_closed_on_missing_cert() {
    use af_librespeed::tls::{build_tls_acceptor, serve_tls};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};
    use std::process::Command;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsConnector;

    let tmp = TempDirGuard::new("tls");
    let (mut bad_cfg, _) = make_test_config(&tmp);
    bad_cfg.enable_tls = true;
    bad_cfg.tls_cert_file = tmp.0.join("missing-cert.pem");
    bad_cfg.tls_key_file = tmp.0.join("missing-key.pem");
    assert!(build_tls_acceptor(&bad_cfg).is_err());

    let cert_path = tmp.0.join("localhost.crt");
    let key_path = tmp.0.join("localhost.key");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature",
            "-addext",
            "extendedKeyUsage=serverAuth",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout",
        ])
        .arg(&key_path)
        .arg("-out")
        .arg(&cert_path)
        .status()
        .expect("openssl available");
    assert!(status.success(), "openssl cert generation succeeded");

    let (mut cfg, vault) = make_test_config(&tmp);
    cfg.enable_tls = true;
    cfg.tls_cert_file = cert_path.clone();
    cfg.tls_key_file = key_path;
    let acceptor = build_tls_acceptor(&cfg).expect("build valid TLS acceptor");
    let app = build_router(cfg, Some(vault));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        serve_tls(listener, acceptor, app, async move {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });

    let mut root_store = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&cert_path).unwrap() {
        root_store.add(cert.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let tcp = TcpStream::connect(addr).await.unwrap();
    let domain = ServerName::try_from("localhost").unwrap();
    let mut tls_stream = connector.connect(domain, tcp).await.unwrap();
    tls_stream
        .write_all(
            b"POST /stats HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 39\r\nConnection: close\r\n\r\nop=login&password=VaultSecretPassword!9",
        )
        .await
        .unwrap();
    let mut resp_buf = Vec::new();
    tls_stream.read_to_end(&mut resp_buf).await.unwrap();
    let raw_http = String::from_utf8_lossy(&resp_buf);
    assert!(raw_http.starts_with("HTTP/1.1 303"), "got: {raw_http}");
    assert!(
        raw_http.contains("; Secure"),
        "expected Secure cookie on native TLS listener, got: {raw_http}"
    );

    let _ = tx.send(());
    server_task.await.unwrap();
}

#[tokio::test]
async fn static_assets_dual_mount_and_confinement() {
    let tmp = TempDirGuard::new("static");
    let (cfg, vault) = make_test_config(&tmp);
    let outside = tmp.0.join("host_secret.txt");
    fs::write(&outside, "DO_NOT_LEAK").unwrap();
    symlink(&outside, cfg.assets_path.join("sym_leak.txt")).unwrap();

    let app = build_router(cfg, Some(vault));

    for path in ["/", "/speedtest", "/speedtest/"] {
        let res = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "path {path}");
        let body = String::from_utf8(body_bytes(res).await).unwrap();
        assert_eq!(body, "<html>ObsidianIndex</html>");
    }

    let js_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/speedtest/javascript/index.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(js_res.status(), StatusCode::OK);
    assert_eq!(body_bytes(js_res).await, b"console.log('ok');");

    for bad_path in [
        "/../host_secret.txt",
        "/%2e%2e/host_secret.txt",
        "/sym_leak.txt",
    ] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(bad_path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "bad path {bad_path}");
    }
}

#[tokio::test]
async fn bundled_multistream_parity_and_stalled_non_reading_client_deadline_recovery() {
    use af_librespeed::routes::{
        build_router_with_stream_timeout, MAX_CONCURRENT_GARBAGE_STREAMS,
        MAX_GARBAGE_STREAMS_PER_IP,
    };
    use af_librespeed::tls::serve_http;
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    // 1. Verify bundled settings.json xhr_dlMultistream fits comfortably within server per-IP cap
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let settings_json_path =
        manifest_dir.join("../../../packages/package/assets/librespeed/settings.json");
    let raw_settings = fs::read_to_string(&settings_json_path).expect("read bundled settings.json");
    let parsed_settings: Value =
        serde_json::from_str(&raw_settings).expect("parse bundled settings.json");
    let dl_multistream = parsed_settings["xhr_dlMultistream"]
        .as_u64()
        .expect("xhr_dlMultistream integer") as usize;
    assert!(
        MAX_GARBAGE_STREAMS_PER_IP >= dl_multistream,
        "server per-IP stream cap ({MAX_GARBAGE_STREAMS_PER_IP}) must accommodate bundled xhr_dlMultistream ({dl_multistream})"
    );
    const { assert!(MAX_CONCURRENT_GARBAGE_STREAMS >= MAX_GARBAGE_STREAMS_PER_IP * 4) };

    // 2. Start real TCP HTTP server with 300ms stream deadline and hold non-reading sockets open
    let tmp = TempDirGuard::new("stalled-dl");
    let (mut cfg, _) = make_test_config(&tmp);
    cfg.database_type = "none".to_string();
    let app = build_router_with_stream_timeout(cfg, None, Duration::from_millis(300));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        serve_http(listener, app, async move {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });

    let mut stalled_sockets = Vec::new();
    for _ in 0..MAX_GARBAGE_STREAMS_PER_IP {
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET /garbage?ckSize=512 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        // Read only the status line ("HTTP/1.1 200 OK") so the handler has acquired its permit,
        // then stop reading completely to induce transport backpressure.
        let mut head_buf = [0u8; 15];
        sock.read_exact(&mut head_buf).await.unwrap();
        assert_eq!(&head_buf, b"HTTP/1.1 200 OK");
        stalled_sockets.push(sock);
    }

    // Before deadline: 17th stream from same IP gets 429
    {
        let mut extra = TcpStream::connect(addr).await.unwrap();
        extra
            .write_all(
                b"GET /garbage?ckSize=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        extra.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.starts_with("HTTP/1.1 429"),
            "expected 429, got: {text}"
        );
    }

    // Wait past the 300ms transport deadline while keeping stalled_sockets un-read in memory
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert_eq!(stalled_sockets.len(), MAX_GARBAGE_STREAMS_PER_IP);

    // Permits and IP slots must now be reclaimed even though stalled_sockets never read again
    {
        let mut recovered = TcpStream::connect(addr).await.unwrap();
        recovered
            .write_all(
                b"GET /garbage?ckSize=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        recovered.read_to_end(&mut buf).await.unwrap();
        let header_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("HTTP header terminator")
            + 4;
        let head = String::from_utf8_lossy(&buf[..header_end]);
        assert!(head.starts_with("HTTP/1.1 200 OK"), "got: {head}");
        assert_eq!(buf.len() - header_end, 1_048_576);
    }

    drop(stalled_sockets);
    let _ = tx.send(());
    server_task.await.unwrap();
}

#[tokio::test]
async fn stalled_post_stats_body_times_out_and_releases_http_and_https_listener_permits() {
    use af_librespeed::routes::{build_router_with_timeouts, RouteTimeouts};
    use af_librespeed::tls::{
        build_tls_acceptor, serve_http_with_limits, serve_tls_with_limits, ListenerLimits,
    };
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName};
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsConnector;

    let limits = ListenerLimits {
        max_connections: 4,
        header_read_timeout: Duration::from_secs(2),
        idle_connection_timeout: Duration::from_millis(400),
        response_drain_timeout: Duration::from_secs(5),
        http2_max_concurrent_streams: 8,
    };
    let timeouts = RouteTimeouts {
        garbage_stream: Duration::from_secs(5),
        empty_upload: Duration::from_millis(250),
        stats_body: Duration::from_millis(200),
    };

    // 1. Plain HTTP socket-level test: saturate all 4 permits with stalled POST /stats bodies
    {
        let tmp = TempDirGuard::new("stalled-stats-http");
        let (cfg, vault) = make_test_config(&tmp);
        let app = build_router_with_timeouts(cfg, Some(vault), timeouts);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            serve_http_with_limits(
                listener,
                app,
                async move {
                    let _ = rx.await;
                },
                limits,
            )
            .await
            .unwrap();
        });

        let mut stalled = Vec::new();
        for _ in 0..limits.max_connections {
            let mut sock = TcpStream::connect(addr).await.unwrap();
            sock.write_all(
                b"POST /stats HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n",
            )
            .await
            .unwrap();
            stalled.push(sock);
        }

        tokio::time::sleep(Duration::from_millis(380)).await;

        for mut sock in stalled {
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            let resp = String::from_utf8_lossy(&buf);
            assert!(
                resp.starts_with("HTTP/1.1 408"),
                "expected 408 timeout on stalled HTTP POST /stats, got: {resp}"
            );
        }

        let mut healthy = TcpStream::connect(addr).await.unwrap();
        healthy
            .write_all(b"GET /getIP HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut ok_buf = Vec::new();
        healthy.read_to_end(&mut ok_buf).await.unwrap();
        let ok_resp = String::from_utf8_lossy(&ok_buf);
        assert!(
            ok_resp.starts_with("HTTP/1.1 200 OK"),
            "expected recovered HTTP listener permit, got: {ok_resp}"
        );

        let _ = tx.send(());
        server_task.await.unwrap();
    }

    // 2. Native HTTPS socket-level test: saturate all 4 TLS permits with stalled POST /stats bodies
    {
        let tmp = TempDirGuard::new("stalled-stats-https");
        let cert_path = tmp.0.join("cert.pem");
        let key_path = tmp.0.join("key.pem");
        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout",
            ])
            .arg(&key_path)
            .arg("-out")
            .arg(&cert_path)
            .status()
            .expect("openssl available");
        assert!(status.success());

        let (mut cfg, vault) = make_test_config(&tmp);
        cfg.enable_tls = true;
        cfg.tls_cert_file = cert_path.clone();
        cfg.tls_key_file = key_path;
        let acceptor = build_tls_acceptor(&cfg).expect("build TLS acceptor");
        let app = build_router_with_timeouts(cfg, Some(vault), timeouts);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        let server_task = tokio::spawn(async move {
            serve_tls_with_limits(
                listener,
                acceptor,
                app,
                async move {
                    let _ = rx.await;
                },
                limits,
            )
            .await
            .unwrap();
        });

        let mut root_store = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(&cert_path).unwrap() {
            root_store.add(cert.unwrap()).unwrap();
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let mut stalled_tls = Vec::new();
        for _ in 0..limits.max_connections {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let domain = ServerName::try_from("localhost").unwrap();
            let mut tls_stream = connector.connect(domain, tcp).await.unwrap();
            tls_stream
                .write_all(
                    b"POST /stats HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n",
                )
                .await
                .unwrap();
            stalled_tls.push(tls_stream);
        }

        tokio::time::sleep(Duration::from_millis(380)).await;

        let tcp_ok = TcpStream::connect(addr).await.unwrap();
        let domain_ok = ServerName::try_from("localhost").unwrap();
        let mut tls_ok = connector.connect(domain_ok, tcp_ok).await.unwrap();
        tls_ok
            .write_all(b"GET /getIP HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut ok_buf = Vec::new();
        tls_ok.read_to_end(&mut ok_buf).await.unwrap();
        let ok_resp = String::from_utf8_lossy(&ok_buf);
        assert!(
            ok_resp.starts_with("HTTP/1.1 200 OK"),
            "expected recovered HTTPS listener permit while stalled_tls held open, got: {ok_resp}"
        );

        drop(stalled_tls);
        let _ = tx.send(());
        server_task.await.unwrap();
    }
}

#[tokio::test]
async fn upload_empty_enforces_per_ip_cap_and_reclaims_stalled_upload_permits() {
    use af_librespeed::routes::{
        build_router_with_timeouts, RouteTimeouts, MAX_UPLOAD_STREAMS_PER_IP,
    };
    use af_librespeed::tls::serve_http;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    let tmp = TempDirGuard::new("upload-cap");
    let (mut cfg, _) = make_test_config(&tmp);
    cfg.database_type = "none".to_string();
    let app = build_router_with_timeouts(
        cfg,
        None,
        RouteTimeouts {
            garbage_stream: Duration::from_secs(5),
            empty_upload: Duration::from_millis(250),
            stats_body: Duration::from_millis(250),
        },
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        serve_http(listener, app, async move {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });

    let mut stalled_uploads = Vec::new();
    for _ in 0..MAX_UPLOAD_STREAMS_PER_IP {
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"POST /empty HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1024\r\n\r\n")
            .await
            .unwrap();
        stalled_uploads.push(sock);
    }
    tokio::time::sleep(Duration::from_millis(40)).await;

    // 17th concurrent POST /empty from same IP must be rejected with 429
    {
        let mut extra = TcpStream::connect(addr).await.unwrap();
        extra
            .write_all(
                b"POST /empty HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        extra.read_to_end(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(
            resp.starts_with("HTTP/1.1 429"),
            "expected 429 on 17th concurrent upload stream, got: {resp}"
        );
    }

    // Lightweight GET /empty ping probe remains unaffected during upload saturation
    {
        let mut ping = TcpStream::connect(addr).await.unwrap();
        ping.write_all(b"GET /empty HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        ping.read_to_end(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
    }

    // Wait past 250ms upload deadline and confirm upload slots recover
    tokio::time::sleep(Duration::from_millis(350)).await;
    {
        let mut recovered = TcpStream::connect(addr).await.unwrap();
        recovered
            .write_all(
                b"POST /empty HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        recovered.read_to_end(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got: {resp}");
    }

    drop(stalled_uploads);
    let _ = tx.send(());
    server_task.await.unwrap();
}

#[tokio::test]
async fn trusted_proxy_stats_login_lockout_isolates_forwarded_clients() {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    let tmp = TempDirGuard::new("proxy-stats-lockout");
    let (mut cfg, vault) = make_test_config(&tmp);
    cfg.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
    let app = build_router(cfg, Some(vault));
    let proxy_peer: SocketAddr = "127.0.0.1:44001".parse().unwrap();

    // Attacker at 203.0.113.77 sends 10 bad passwords via trusted loopback reverse proxy
    for _ in 0..10 {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/stats")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-forwarded-for", "203.0.113.77")
            .body(Body::from("op=login&password=wrong"))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(proxy_peer));
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    // 11th attempt from attacker 203.0.113.77 is throttled with 429
    {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/stats")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-forwarded-for", "203.0.113.77")
            .body(Body::from("op=login&password=VaultSecretPassword!9"))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(proxy_peer));
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // Legitimate admin at 198.51.100.10 arriving via the SAME loopback reverse proxy succeeds!
    {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/stats")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-forwarded-for", "198.51.100.10")
            .body(Body::from("op=login&password=VaultSecretPassword!9"))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(proxy_peer));
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
    }

    // Attacker injecting obs-text into XFF + forged X-Real-IP still maps to 203.0.113.77 and stays 429-locked!
    {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/stats")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                "x-forwarded-for",
                axum::http::HeaderValue::from_bytes(b"\xffbypass, 203.0.113.77").unwrap(),
            )
            .header("x-real-ip", "198.51.100.250")
            .body(Body::from("op=login&password=VaultSecretPassword!9"))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(proxy_peer));
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // Rotating XFF from the same loopback proxy peer hits the outer per-peer cap (50 failures total;
    // 10 already recorded above, so 40 more rotating failures reach 50 and lock out attempt 51).
    for i in 0..40u8 {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/stats")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-forwarded-for", format!("192.0.2.{}", i + 1))
            .body(Body::from("op=login&password=wrong"))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(proxy_peer));
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/stats")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-forwarded-for", "192.0.2.254")
            .body(Body::from("op=login&password=VaultSecretPassword!9"))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(proxy_peer));
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}

#[tokio::test]
async fn http2_zero_window_stalled_garbage_stream_reclaims_listener_slots() {
    use af_librespeed::routes::{build_router_with_timeouts, RouteTimeouts};
    use af_librespeed::tls::{serve_http_with_limits, ListenerLimits};
    use http_body_util::Empty;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    let tmp = TempDirGuard::new("h2-zero-window");
    let (mut cfg, _) = make_test_config(&tmp);
    cfg.database_type = "none".to_string();
    let app = build_router_with_timeouts(
        cfg,
        None,
        RouteTimeouts {
            garbage_stream: Duration::from_millis(200),
            empty_upload: Duration::from_millis(200),
            stats_body: Duration::from_millis(200),
        },
    );

    let limits = ListenerLimits {
        max_connections: 2,
        header_read_timeout: Duration::from_secs(5),
        idle_connection_timeout: Duration::from_secs(30),
        response_drain_timeout: Duration::from_secs(30),
        http2_max_concurrent_streams: 8,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        serve_http_with_limits(
            listener,
            app,
            async move {
                let _ = rx.await;
            },
            limits,
        )
        .await
        .unwrap();
    });

    // Saturate all 2 listener connection slots with HTTP/2 clients that request 4 MiB (/garbage?ckSize=4)
    // and never read the response body (exhausting the 65,535-byte HTTP/2 stream window while the
    // spawned hyper h2 Connection driver continues answering SETTINGS/PING frames).
    let mut held_h2 = Vec::new();
    for _ in 0..limits.max_connections {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
                .await
                .unwrap();
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method("GET")
            .uri("http://127.0.0.1/garbage?ckSize=4")
            .body(Empty::<axum::body::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        held_h2.push((sender, resp, conn_task));
    }

    // Wait past 200ms garbage_stream deadline + 100ms HTTP/2 RST grace window.
    tokio::time::sleep(Duration::from_millis(480)).await;

    // A fresh client connection must succeed because wedged zero-window HTTP/2 connections were aborted.
    let mut fresh = TcpStream::connect(addr).await.unwrap();
    fresh
        .write_all(b"GET /getIP HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut ok_buf = Vec::new();
    fresh.read_to_end(&mut ok_buf).await.unwrap();
    let ok_resp = String::from_utf8_lossy(&ok_buf);
    assert!(
        ok_resp.starts_with("HTTP/1.1 200 OK"),
        "expected listener slot recovery after HTTP/2 zero-window stall, got: {ok_resp}"
    );

    drop(held_h2);
    let _ = tx.send(());
    server_task.await.unwrap();
}

#[tokio::test]
async fn http2_zero_window_stalled_static_asset_reclaims_listener_slots() {
    use af_librespeed::tls::{serve_http_with_limits, ListenerLimits};
    use http_body_util::Empty;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    let tmp = TempDirGuard::new("h2-zero-window-static");
    let (mut cfg, _) = make_test_config(&tmp);
    cfg.database_type = "none".to_string();
    let fonts_dir = cfg.assets_path.join("fonts");
    fs::create_dir_all(&fonts_dir).unwrap();
    // 80 KiB > 65,535-byte default HTTP/2 initial stream window so GuardedBody stalls
    // inside h2 flow control if the client withholds WINDOW_UPDATE while answering PINGs.
    fs::write(fonts_dir.join("Inter-latin.woff2"), vec![0xABu8; 80_000]).unwrap();
    let app = build_router(cfg, None);

    let limits = ListenerLimits {
        max_connections: 2,
        header_read_timeout: Duration::from_secs(5),
        idle_connection_timeout: Duration::from_secs(30),
        response_drain_timeout: Duration::from_millis(250),
        http2_max_concurrent_streams: 8,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        serve_http_with_limits(
            listener,
            app,
            async move {
                let _ = rx.await;
            },
            limits,
        )
        .await
        .unwrap();
    });

    // Case A: RFC 9113 default 65,535-byte window exhausted mid-transfer on an 80 KiB static font
    let mut held_h2 = Vec::new();
    for _ in 0..limits.max_connections {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(65_535)
            .initial_connection_window_size(65_535)
            .handshake(TokioIo::new(tcp))
            .await
            .unwrap();
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method("GET")
            .uri("http://127.0.0.1/fonts/Inter-latin.woff2")
            .body(Empty::<axum::body::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        held_h2.push((sender, resp, conn_task));
    }

    tokio::time::sleep(Duration::from_millis(420)).await;
    {
        // Prove listener slots recovered WHILE held_h2 is still held open without WINDOW_UPDATE
        let mut fresh_a = TcpStream::connect(addr).await.unwrap();
        fresh_a
            .write_all(b"GET /getIP HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf_a = Vec::new();
        fresh_a.read_to_end(&mut buf_a).await.unwrap();
        let resp_a = String::from_utf8_lossy(&buf_a);
        assert!(
            resp_a.starts_with("HTTP/1.1 200 OK"),
            "expected Case A 80 KiB static font zero-window recovery, got: {resp_a}"
        );
    }

    // Case B: Also verify zero initial stream window (SETTINGS_INITIAL_WINDOW_SIZE = 0) on tiny /getIP
    drop(held_h2);
    let mut held_zero = Vec::new();
    for _ in 0..limits.max_connections {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(0)
            .handshake(TokioIo::new(tcp))
            .await
            .unwrap();
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method("GET")
            .uri("http://127.0.0.1/getIP")
            .body(Empty::<axum::body::Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        held_zero.push((sender, resp, conn_task));
    }

    tokio::time::sleep(Duration::from_millis(420)).await;

    let mut fresh = TcpStream::connect(addr).await.unwrap();
    fresh
        .write_all(b"GET /getIP HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut ok_buf = Vec::new();
    fresh.read_to_end(&mut ok_buf).await.unwrap();
    let ok_resp = String::from_utf8_lossy(&ok_buf);
    assert!(
        ok_resp.starts_with("HTTP/1.1 200 OK"),
        "expected listener slot recovery after HTTP/2 static asset zero-window stall, got: {ok_resp}"
    );

    drop(held_zero);
    let _ = tx.send(());
    server_task.await.unwrap();
}

#[tokio::test]
async fn trusted_proxy_xff_rotation_enforces_outer_stream_and_telemetry_ceilings() {
    use af_librespeed::routes::MAX_STREAMS_PER_PROXY_PEER;
    use af_librespeed::stats::MAX_TELEMETRY_PER_PROXY_PEER_IP;
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    let tmp = TempDirGuard::new("proxy-peer-ceilings");
    let (mut cfg, vault) = make_test_config(&tmp);
    cfg.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
    let app = build_router(cfg, Some(vault));
    let proxy_peer: SocketAddr = "127.0.0.1:45000".parse().unwrap();

    // 1. /garbage outer proxy-peer stream ceiling (48 < global 64) stops local XFF rotation
    //    without starving unproxied direct peers.
    let mut held_streams = Vec::new();
    for idx in 0..MAX_STREAMS_PER_PROXY_PEER {
        let mut req = Request::builder()
            .uri("/garbage?ckSize=2")
            .header("x-forwarded-for", format!("198.51.100.{}", idx + 1))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(proxy_peer));
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        held_streams.push(res);
    }

    {
        let mut over_req = Request::builder()
            .uri("/garbage?ckSize=2")
            .header("x-forwarded-for", "198.51.100.200")
            .body(Body::empty())
            .unwrap();
        over_req.extensions_mut().insert(ConnectInfo(proxy_peer));
        let over_res = app.clone().oneshot(over_req).await.unwrap();
        assert_eq!(over_res.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    {
        let direct_res = app
            .clone()
            .oneshot(with_peer(
                Request::builder()
                    .uri("/garbage?ckSize=1")
                    .body(Body::empty())
                    .unwrap(),
                "203.0.113.99:51000",
            ))
            .await
            .unwrap();
        assert_eq!(direct_res.status(), StatusCode::OK);
    }
    drop(held_streams);

    // 2. POST /empty outer proxy-peer upload ceiling (48 < global 64) also enforces proxy cap
    let mut held_uploads = Vec::new();
    for idx in 0..MAX_STREAMS_PER_PROXY_PEER {
        let (_tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(1);
        let stream = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/empty")
            .header("x-forwarded-for", format!("198.51.100.{}", idx + 1))
            .body(Body::from_stream(stream))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(proxy_peer));
        let app_clone = app.clone();
        held_uploads.push((
            _tx,
            tokio::spawn(async move { app_clone.oneshot(req).await }),
        ));
    }
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    {
        let mut over_up = Request::builder()
            .method(Method::POST)
            .uri("/empty")
            .header("x-forwarded-for", "198.51.100.201")
            .body(Body::from("ping"))
            .unwrap();
        over_up.extensions_mut().insert(ConnectInfo(proxy_peer));
        let over_up_res = app.clone().oneshot(over_up).await.unwrap();
        assert_eq!(over_up_res.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    for (tx_hold, handle) in held_uploads {
        drop(tx_hold);
        let _ = handle.await;
    }

    // 3. POST /results/telemetry outer proxy-peer ceiling (120/min < global 300/min)
    for idx in 0..MAX_TELEMETRY_PER_PROXY_PEER_IP {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/results/telemetry")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-forwarded-for", format!("192.0.2.{}", (idx % 250) + 1))
            .body(Body::from("dl=100.0&ul=50.0&ping=10.0&jitter=1.0"))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(proxy_peer));
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "idx={idx}");
    }

    {
        let mut capped_tel = Request::builder()
            .method(Method::POST)
            .uri("/results/telemetry")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("x-forwarded-for", "192.0.2.253")
            .body(Body::from("dl=100.0&ul=50.0&ping=10.0&jitter=1.0"))
            .unwrap();
        capped_tel.extensions_mut().insert(ConnectInfo(proxy_peer));
        let capped_res = app.clone().oneshot(capped_tel).await.unwrap();
        assert_eq!(capped_res.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    {
        let direct_tel = app
            .oneshot(with_peer(
                Request::builder()
                    .method(Method::POST)
                    .uri("/results/telemetry")
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("dl=100.0&ul=50.0&ping=10.0&jitter=1.0"))
                    .unwrap(),
                "203.0.113.88:52000",
            ))
            .await
            .unwrap();
        assert_eq!(direct_tel.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn getip_isp_lookup_haversine_distance_cache_and_redaction() {
    use axum::routing::get as axum_get;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    let hits = Arc::new(AtomicUsize::new(0));
    let last_auth = Arc::new(Mutex::new(String::new()));
    let hits_srv = Arc::clone(&hits);
    let auth_srv = Arc::clone(&last_auth);

    let mock_app = axum::Router::new().route(
        "/8.8.8.8/json",
        axum_get(move |headers: axum::http::HeaderMap| {
            let hits_srv = Arc::clone(&hits_srv);
            let auth_srv = Arc::clone(&auth_srv);
            async move {
                hits_srv.fetch_add(1, Ordering::SeqCst);
                if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
                    *auth_srv.lock().unwrap() = auth.to_string();
                }
                (
                    [(CONTENT_TYPE, "application/json")],
                    r#"{"ip":"8.8.8.8","hostname":"dns.google","city":"Mountain View","region":"California","country":"US","loc":"37.3860,-122.0838","org":"AS15169 Google LLC","readme":"https://ipinfo.io/missingauth"}"#,
                )
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let mock_task = tokio::spawn(async move {
        axum::serve(listener, mock_app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });

    // 1. Unredacted lookup: ASN stripping + Haversine km/mi + IspLookupCache reuse
    let tmp = TempDirGuard::new("getip-isp");
    let (mut cfg, vault) = make_test_config(&tmp);
    cfg.redact_ip_addresses = false;
    cfg.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
    cfg.server_lat = 37.7749;
    cfg.server_lng = -122.4194;
    cfg.ipinfo_base_url = format!("http://127.0.0.1:{}", mock_addr.port());
    let app = build_router(cfg.clone(), Some(vault.clone()));

    let res_km = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .uri("/getIP?isp=true&distance=km")
                .header("x-forwarded-for", "8.8.8.8")
                .body(Body::empty())
                .unwrap(),
            "127.0.0.1:50000",
        ))
        .await
        .unwrap();
    assert_eq!(res_km.status(), StatusCode::OK);
    let json_km: Value = serde_json::from_slice(&body_bytes(res_km).await).unwrap();
    assert_eq!(
        json_km["processedString"],
        "8.8.8.8 - Google LLC, US (52 km)"
    );
    assert!(json_km["rawIspInfo"].is_object());
    assert_eq!(json_km["rawIspInfo"]["org"], "AS15169 Google LLC");
    assert!(json_km["rawIspInfo"].get("readme").is_none());
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let res_mi = app
        .oneshot(with_peer(
            Request::builder()
                .uri("/getIP?isp=true&distance=mi")
                .header("x-forwarded-for", "8.8.8.8")
                .body(Body::empty())
                .unwrap(),
            "127.0.0.1:50000",
        ))
        .await
        .unwrap();
    assert_eq!(res_mi.status(), StatusCode::OK);
    let json_mi: Value = serde_json::from_slice(&body_bytes(res_mi).await).unwrap();
    assert_eq!(
        json_mi["processedString"],
        "8.8.8.8 - Google LLC, US (33 mi)"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "second lookup for same IP must hit IspLookupCache"
    );

    // 2. Redacted lookup with explicit ipinfo_api_key sends Bearer token and sanitizes IP/hostname
    cfg.redact_ip_addresses = true;
    cfg.ipinfo_api_key = "test-ipinfo-token".to_string();
    let redacted_app = build_router(cfg, Some(vault));
    let res_red = redacted_app
        .oneshot(with_peer(
            Request::builder()
                .uri("/getIP?isp=true&distance=km")
                .header("x-forwarded-for", "8.8.8.8")
                .body(Body::empty())
                .unwrap(),
            "127.0.0.1:50000",
        ))
        .await
        .unwrap();
    assert_eq!(res_red.status(), StatusCode::OK);
    let raw_red_bytes = body_bytes(res_red).await;
    let raw_red_str = String::from_utf8_lossy(&raw_red_bytes);
    assert!(!raw_red_str.contains("8.8.8.8"), "leaked IP: {raw_red_str}");
    assert!(
        !raw_red_str.contains("dns.google"),
        "leaked hostname: {raw_red_str}"
    );
    let json_red: Value = serde_json::from_slice(&raw_red_bytes).unwrap();
    assert_eq!(
        json_red["processedString"],
        "0.0.0.0 - Google LLC, US (52 km)"
    );
    assert_eq!(json_red["rawIspInfo"]["ip"], "0.0.0.0");
    assert_eq!(json_red["rawIspInfo"]["hostname"], "REDACTED");
    assert_eq!(
        last_auth.lock().unwrap().as_str(),
        "Bearer test-ipinfo-token"
    );

    let _ = tx.send(());
    mock_task.await.unwrap();
}

#[tokio::test]
async fn stats_login_concurrent_burst_enforces_strict_atomic_10_attempt_budget() {
    let tmp = TempDirGuard::new("concurrent-login-burst");
    let (mut cfg, vault) = make_test_config(&tmp);
    cfg.statistics_password = "StrongAdminPassword!42".to_string();
    let app = build_router(cfg, Some(vault));

    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(25));
    let mut handles = Vec::new();
    for _ in 0..25 {
        let app_clone = app.clone();
        let b = barrier.clone();
        handles.push(tokio::spawn(async move {
            b.wait().await;
            let res = app_clone
                .oneshot(with_peer(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/stats")
                        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .body(Body::from("op=login&password=wrong"))
                        .unwrap(),
                    "203.0.113.150:49152",
                ))
                .await
                .unwrap();
            res.status()
        }));
    }

    let mut unauth = 0usize;
    let mut throttled = 0usize;
    for h in handles {
        match h.await.unwrap() {
            StatusCode::UNAUTHORIZED => unauth += 1,
            StatusCode::TOO_MANY_REQUESTS => throttled += 1,
            other => panic!("unexpected login burst status: {other}"),
        }
    }
    assert_eq!(
        unauth, 10,
        "concurrent login burst must atomically admit at most 10 password checks"
    );
    assert_eq!(throttled, 15);
}

#[tokio::test]
async fn trusted_proxy_secret_blocks_local_loopback_xff_spoofing_and_url_tls_nofollow_hardening() {
    use af_librespeed::redact::PROXY_TOKEN_HEADER;
    use af_librespeed::routes::build_safe_ipinfo_lookup_url;
    use af_librespeed::tls::build_tls_acceptor;
    use std::os::unix::fs::symlink;

    // 1. Strict URL parser rejects userinfo/authority confusion and non-empty paths
    let dns_ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
    assert!(build_safe_ipinfo_lookup_url("http://127.0.0.1:80@evil.com", dns_ip).is_none());
    assert!(build_safe_ipinfo_lookup_url("https://ipinfo.io@evil.com", dns_ip).is_none());
    assert!(build_safe_ipinfo_lookup_url("https://ipinfo.io/custom", dns_ip).is_none());
    assert!(build_safe_ipinfo_lookup_url("http://192.0.2.1:8080", dns_ip).is_none());
    let valid_url = build_safe_ipinfo_lookup_url("https://ipinfo.io", dns_ip).unwrap();
    assert_eq!(valid_url.as_str(), "https://ipinfo.io/8.8.8.8/json");

    // 2. TLS cert/key loader rejects symlinks via O_NOFOLLOW
    let tmp = TempDirGuard::new("proxy-secret-and-tls-nofollow");
    let real_cert = tmp.0.join("real.crt");
    let real_key = tmp.0.join("real.key");
    fs::write(&real_cert, b"not-a-pem").unwrap();
    fs::write(&real_key, b"not-a-key").unwrap();
    let sym_cert = tmp.0.join("sym.crt");
    symlink(&real_cert, &sym_cert).unwrap();
    let (mut tls_cfg, _) = make_test_config(&tmp);
    tls_cfg.enable_tls = true;
    tls_cfg.tls_cert_file = sym_cert;
    tls_cfg.tls_key_file = real_key;
    let Err(tls_err_raw) = build_tls_acceptor(&tls_cfg) else {
        panic!("expected O_NOFOLLOW error for symlinked TLS cert");
    };
    let tls_err = format!("{tls_err_raw:#}");
    assert!(
        tls_err.contains("refusing symlinked")
            || tls_err.contains("refusing to open")
            || tls_err.contains("Too many levels of symbolic links"),
        "expected O_NOFOLLOW rejection for symlinked TLS cert, got: {tls_err}"
    );

    // 3. Trusted loopback proxy secret blocks unauthenticated local processes from spoofing XFF / X-Forwarded-Proto
    let (mut cfg, vault) = make_test_config(&tmp);
    cfg.redact_ip_addresses = false;
    cfg.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
    cfg.trusted_proxy_secret = String::from_utf8(vec![b'x'; 32]).unwrap();
    cfg.statistics_password = "StrongAdminPassword!42".to_string();
    let app = build_router(cfg.clone(), Some(vault));

    // Loopback WITHOUT token: spoofed XFF is ignored, resolves to 127.0.0.1
    let no_tok = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .uri("/getIP")
                .header("x-forwarded-for", "198.51.100.88")
                .body(Body::empty())
                .unwrap(),
            "127.0.0.1:41000",
        ))
        .await
        .unwrap();
    let no_tok_text = String::from_utf8(body_bytes(no_tok).await).unwrap();
    assert!(
        no_tok_text.starts_with("127.0.0.1"),
        "expected loopback IP without token, got: {no_tok_text}"
    );

    // Loopback WITH duplicate smuggling headers (wrong + valid): rejected, resolves to 127.0.0.1
    let dup_tok = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .uri("/getIP")
                .header("x-forwarded-for", "198.51.100.88")
                .header(PROXY_TOKEN_HEADER, "wrong-secret")
                .header(PROXY_TOKEN_HEADER, &cfg.trusted_proxy_secret)
                .body(Body::empty())
                .unwrap(),
            "127.0.0.1:41000",
        ))
        .await
        .unwrap();
    let dup_tok_text = String::from_utf8(body_bytes(dup_tok).await).unwrap();
    assert!(
        dup_tok_text.starts_with("127.0.0.1"),
        "expected loopback IP on duplicate token headers, got: {dup_tok_text}"
    );

    // Loopback WITH valid single token: XFF honored -> 198.51.100.88
    let ok_tok = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .uri("/getIP")
                .header("x-forwarded-for", "198.51.100.88")
                .header(PROXY_TOKEN_HEADER, &cfg.trusted_proxy_secret)
                .body(Body::empty())
                .unwrap(),
            "127.0.0.1:41000",
        ))
        .await
        .unwrap();
    let ok_tok_text = String::from_utf8(body_bytes(ok_tok).await).unwrap();
    assert!(
        ok_tok_text.starts_with("198.51.100.88"),
        "expected forwarded IP with valid token, got: {ok_tok_text}"
    );

    // Loopback login WITHOUT token ignores spoofed X-Forwarded-Proto: https (no Secure cookie flag),
    // whereas WITH valid token sets Secure cookie flag
    let unauth_proto_login = app
        .clone()
        .oneshot(with_peer(
            Request::builder()
                .method(Method::POST)
                .uri("/stats")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("x-forwarded-proto", "https")
                .body(Body::from("op=login&password=StrongAdminPassword%2142"))
                .unwrap(),
            "127.0.0.1:41001",
        ))
        .await
        .unwrap();
    let cookie_without_tok = unauth_proto_login
        .headers()
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!cookie_without_tok.contains("Secure"));

    let auth_proto_login = app
        .oneshot(with_peer(
            Request::builder()
                .method(Method::POST)
                .uri("/stats")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("x-forwarded-proto", "https")
                .header(PROXY_TOKEN_HEADER, &cfg.trusted_proxy_secret)
                .body(Body::from("op=login&password=StrongAdminPassword%2142"))
                .unwrap(),
            "127.0.0.1:41002",
        ))
        .await
        .unwrap();
    let cookie_with_tok = auth_proto_login
        .headers()
        .get(SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie_with_tok.contains("Secure"));
}
