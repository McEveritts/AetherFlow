use super::extract_client_ip;
use axum::http::{HeaderMap, HeaderValue};

#[test]
fn extract_client_ip_skips_trailing_trusted_proxies_and_validates_real_ip() {
    let mut h1 = HeaderMap::new();
    h1.insert(
        "X-Forwarded-For",
        HeaderValue::from_static("10.0.0.1, 203.0.113.42, 127.0.0.1"),
    );
    assert_eq!(extract_client_ip(&h1), "203.0.113.42");

    let mut h2 = HeaderMap::new();
    h2.insert(
        "X-Forwarded-For",
        HeaderValue::from_static("198.51.100.1, 203.0.113.9"),
    );
    assert_eq!(extract_client_ip(&h2), "203.0.113.9");

    let mut h3 = HeaderMap::new();
    h3.insert("X-Real-IP", HeaderValue::from_static("not-an-ip"));
    assert_eq!(extract_client_ip(&h3), "127.0.0.1");

    let mut h4 = HeaderMap::new();
    h4.insert("X-Real-IP", HeaderValue::from_static("[2001:db8::5]"));
    assert_eq!(extract_client_ip(&h4), "2001:db8::5");
}

#[test]
fn websocket_origin_enforces_scheme_host_port_and_cookie_origin_presence() {
    use super::websocket_origin_matches_host;
    use axum::http::header;

    // Cookie-authenticated browser upgrade without Origin must be rejected; non-cookie allowed.
    let mut h_no_origin = HeaderMap::new();
    h_no_origin.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8080"));
    assert!(websocket_origin_matches_host(&h_no_origin, None, false));
    assert!(!websocket_origin_matches_host(&h_no_origin, None, true));

    // Exact http match and port/scheme mismatch rejection.
    let mut h_http = h_no_origin.clone();
    h_http.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://127.0.0.1:8080"),
    );
    assert!(websocket_origin_matches_host(&h_http, None, true));
    h_http.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://127.0.0.1:8080"),
    );
    assert!(!websocket_origin_matches_host(&h_http, None, true));
    h_http.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://127.0.0.1:9999"),
    );
    assert!(!websocket_origin_matches_host(&h_http, None, true));
    h_http.insert(header::ORIGIN, HeaderValue::from_static("null"));
    assert!(!websocket_origin_matches_host(&h_http, None, true));

    // Trusted loopback reverse proxy with X-Forwarded-Proto=https vs untrusted public peer spoofing X-Forwarded-Host.
    let mut h_tls = HeaderMap::new();
    h_tls.insert(header::HOST, HeaderValue::from_static("panel.example.com"));
    h_tls.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://panel.example.com"),
    );
    h_tls.insert("X-Forwarded-Proto", HeaderValue::from_static("https"));
    h_tls.insert("X-Forwarded-Port", HeaderValue::from_static("443"));
    assert!(websocket_origin_matches_host(
        &h_tls,
        Some("127.0.0.1".parse().unwrap()),
        true
    ));

    let mut h_spoof = HeaderMap::new();
    h_spoof.insert(header::HOST, HeaderValue::from_static("panel.example.com"));
    h_spoof.insert(
        "X-Forwarded-Host",
        HeaderValue::from_static("evil.attacker.test"),
    );
    h_spoof.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://evil.attacker.test"),
    );
    assert!(!websocket_origin_matches_host(
        &h_spoof,
        Some("203.0.113.99".parse().unwrap()),
        true
    ));
}

#[test]
fn open_confined_live_log_file_rejects_symlinks_and_hardlinks() {
    let dir = std::env::temp_dir().join(format!("af-ws-log-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let real_log = dir.join("syslog.log");
    std::fs::write(&real_log, b"line1\n").unwrap();
    assert!(super::open_confined_live_log_file(&real_log).is_some());

    let sym_log = dir.join("sym.log");
    std::os::unix::fs::symlink(&real_log, &sym_log).unwrap();
    assert!(
        super::open_confined_live_log_file(&sym_log).is_none(),
        "symlinked log file must be rejected by O_NOFOLLOW"
    );

    let hard_log = dir.join("hard.log");
    std::fs::hard_link(&real_log, &hard_log).unwrap();
    assert!(
        super::open_confined_live_log_file(&hard_log).is_none(),
        "hardlinked log file (nlink > 1) must be rejected"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
