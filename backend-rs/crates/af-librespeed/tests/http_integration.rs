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

    // Brute-force login rate limiter triggers 429 after 10 failures even when rotating BOTH leftmost AND rightmost XFF behind loopback proxy (peer bucket enforced!)
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
                        format!("192.0.2.{attempt}, 198.51.100.{attempt}"),
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
        .oneshot(with_peer(
            Request::builder()
                .method(Method::POST)
                .uri("/stats.php")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("x-forwarded-for", "192.0.2.250, 198.51.100.250")
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
