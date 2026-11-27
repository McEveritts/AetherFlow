//! P6 management proxy & WebSocket integration/unit tests (File 31, File 32 transport, File 34).
//!
//! Uses isolated SQLite fixtures, fake privileged runner, fake `journalctl`, and loopback TCP
//! listeners only. Never touches host WireGuard, NFS, systemd, apt, or host networking.

use super::proxy::{
    copy_peer_request_headers, rewrite_peer_backup_set_cookie, rewrite_peer_location_header,
};
use super::tests::{
    call_admin, fixture_wg_pubkey, open_isolated_peer_db, pair_two_test_runtimes, FakeClock,
    FakePeerRunner, RouterPublicTransport, UnreachablePublicTransport,
};
use super::{
    configured_peer_max_ws, is_active_link_state, KeyedAsyncLockPool, PeerDb, PeerRunner,
    PeerRuntime, PublicPairingTransport, TunnelTransportBinding, DEFAULT_PEER_MAX_WS,
    HEADER_GRANT_TOKEN, HEADER_LINK_TOKEN, HEADER_ORIGIN_OPERATOR, STATE_ACTIVE, STATE_DOWN,
    STATE_PENDING, STATE_REVOKED,
};
use crate::auth::{AuthUser, PeerPrincipal};
use crate::storage::BACKUP_DOWNLOAD_COOKIE;
use af_db::peers::{self as db_peers, AccessLevel, AccessMap, PeerIdentity, PeerLink};
use af_runner::PeerCredentialSlot;
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex as TokioMutex};
use tower::ServiceExt as _;

fn isolated_p6_subprocess(test_fn: &str) -> bool {
    if std::env::var("AF_P6_PROXY_TEST_CHILD").as_deref() == Ok(test_fn) {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_fn, "--nocapture"])
        .env("AF_P6_PROXY_TEST_CHILD", test_fn)
        .output()
        .expect("spawn isolated p6 test subprocess");
    if !output.status.success() {
        panic!(
            "isolated p6 subprocess `{test_fn}` failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    false
}

fn build_proxy_test_runtime(
    name: &str,
    runner: Arc<dyn PeerRunner>,
    public_transport: Arc<dyn PublicPairingTransport>,
    clock: &Arc<FakeClock>,
    max_conn: usize,
    max_ws: usize,
    header_timeout: Duration,
) -> (Arc<PeerRuntime>, Arc<StdMutex<rusqlite::Connection>>) {
    let db_conn = open_isolated_peer_db();
    db_peers::ensure_peer_grant_schema_invariants(&db_conn.lock().unwrap())
        .expect("apply peer grant schema invariants");
    let (revocation_tx, _) = broadcast::channel(64);
    let rt = Arc::new(PeerRuntime {
        db: PeerDb::Isolated(Arc::clone(&db_conn)),
        runner,
        storage_runner: Arc::new(super::storage_tests::FakePeerStorageRunner::new()),
        mount_health: super::storage::MountHealthTracker::new(),
        transcode_runner: Arc::new(super::transcode_tests::FakePeerTranscodeRunner::new()),
        transcode_state: Arc::new(super::transcode::TranscodeRuntimeState::new()),
        public_transport,
        revocation_tx,
        pairing_rate_limiter: super::pairing::PairingRateLimiter::new(
            super::pairing::PAIRING_RATE_LIMIT_PER_MIN,
            Duration::from_secs(60),
        ),
        attempt_locks: KeyedAsyncLockPool::new(),
        link_locks: KeyedAsyncLockPool::new(),
        link_semaphores: StdMutex::new(HashMap::new()),
        link_ws_semaphores: StdMutex::new(HashMap::new()),
        tunnel_clients: StdMutex::new(HashMap::new()),
        proxy_tunnel_clients: StdMutex::new(HashMap::new()),
        listener_state: TokioMutex::new(None),
        health_shutdown: TokioMutex::new(None),
        clock: clock.as_fn(),
        monotonic_clock: clock.as_monotonic_fn(),
        lock_wait_timeout: Duration::from_secs(5),
        listen_port: 0,
        max_conn_per_link: max_conn,
        max_ws_per_link: max_ws,
        proxy_header_timeout: header_timeout,
        rtt_warn_ms: 25.0,
        server_name_override: Some(name.to_string()),
        version_override: Some("4.0.0-p6".to_string()),
        tunnel_binding: TunnelTransportBinding::LoopbackFixture,
        tunnel_request_timeout: Duration::from_secs(3),
        tunnel_port_overrides: RwLock::new(HashMap::new()),
        bind_listener_in_handlers: true,
        management_router_override: None,
        allowed_fs_roots_override: None,
        interface_index_override: RwLock::new(None),
    });
    (rt, db_conn)
}

#[allow(clippy::too_many_arguments)]
fn seed_proxy_link(
    db: &Arc<StdMutex<rusqlite::Connection>>,
    runner: &FakePeerRunner,
    local_ip: IpAddr,
    link_id: &str,
    peer_name: &str,
    peer_ip: IpAddr,
    state: &str,
    peer_protocol: Option<i64>,
    capabilities: Option<&str>,
    grant_access: Option<AccessMap>,
    link_token: Option<&str>,
    grant_token: Option<(&str, &str)>,
) {
    let conn = db.lock().unwrap();
    let _ = db_peers::upsert_peer_identity(
        &conn,
        &PeerIdentity {
            wg_pubkey: fixture_wg_pubkey(201),
            tunnel_ip: local_ip.to_string(),
            wg_port: 51821,
            created_at: "2026-11-23T00:00:00Z".to_string(),
        },
    );
    db_peers::insert_peer_link(
        &conn,
        &PeerLink {
            id: link_id.to_string(),
            name: peer_name.to_string(),
            wg_pubkey: fixture_wg_pubkey(202),
            tunnel_ip: peer_ip.to_string(),
            endpoint: "198.51.100.50".to_string(),
            wg_port: 51821,
            state: state.to_string(),
            peer_version: Some("4.0.0-peer".to_string()),
            peer_protocol,
            capabilities: capabilities.map(str::to_string),
            rtt_ms: Some(1.5),
            last_ok_at: Some("2026-11-23T00:00:00Z".to_string()),
            last_error: None,
            consecutive_failures: 0,
            inbound_token_hash: Some("sha256:0000".to_string()),
            pending_attempt_id: None,
            pending_expires_at: None,
            created_at: "2026-11-23T00:00:00Z".to_string(),
            updated_at: "2026-11-23T00:00:00Z".to_string(),
        },
    )
    .unwrap();
    if let Some(access) = grant_access {
        let cred_id = grant_token.map(|(cid, _)| cid).unwrap_or(link_id);
        db_peers::upsert_peer_received_grant(
            &conn,
            &db_peers::PeerReceivedGrant {
                link_id: link_id.to_string(),
                grant_id: format!("grant-{link_id}"),
                run_as_user_id: 1,
                access,
                created_by: "admin".to_string(),
                created_at: "2026-11-23T00:00:00Z".to_string(),
                generation: 1,
                revoked_at: None,
                credential_id: Some(cred_id.to_string()),
                updated_at: "2026-11-23T00:00:00Z".to_string(),
            },
        )
        .unwrap();
    }
    drop(conn);

    let mut st = runner.state.lock().unwrap();
    if let Some(tok) = link_token {
        st.credentials.insert(
            (PeerCredentialSlot::LinkToken, link_id.to_string()),
            tok.to_string(),
        );
    }
    if let Some((cred_id, gtok)) = grant_token {
        st.credentials.insert(
            (PeerCredentialSlot::GrantToken, cred_id.to_string()),
            gtok.to_string(),
        );
    }
}

fn admin_proxy_app(runtime: Arc<PeerRuntime>, user: AuthUser) -> Router {
    Router::new()
        .route(
            "/:id/*rest",
            axum::routing::get(super::proxy::handle_peer_proxy)
                .head(super::proxy::handle_peer_proxy)
                .post(super::proxy::handle_peer_proxy)
                .put(super::proxy::handle_peer_proxy)
                .patch(super::proxy::handle_peer_proxy)
                .delete(super::proxy::handle_peer_proxy),
        )
        .layer(axum::Extension(user))
        .layer(axum::middleware::from_fn(
            crate::routes::security_headers_middleware,
        ))
        .with_state(runtime)
}

fn fixture_admin_user() -> AuthUser {
    AuthUser {
        user_id: 42,
        username: "alice-admin".to_string(),
        role: "admin".to_string(),
        jti: "sess-p6-admin".to_string(),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    }
}

async fn read_ws_frame(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(3), async {
        let first = stream.read_u8().await.unwrap();
        let second = stream.read_u8().await.unwrap();
        assert_eq!(second & 0x80, 0, "server frames must be unmasked");
        let len = match second & 0x7f {
            126 => stream.read_u16().await.unwrap() as usize,
            127 => stream.read_u64().await.unwrap() as usize,
            n => n as usize,
        };
        assert!(len < 256 * 1024);
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        (first & 0x0f, payload)
    })
    .await
    .expect("timed out reading websocket frame")
}

async fn read_ws_frame_with_timeout(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<Option<(u8, Vec<u8>)>, ()> {
    tokio::time::timeout(timeout, async {
        let first = match stream.read_u8().await {
            Ok(b) => b,
            Err(_) => return None,
        };
        let second = match stream.read_u8().await {
            Ok(b) => b,
            Err(_) => return None,
        };
        let len = match second & 0x7f {
            126 => match stream.read_u16().await {
                Ok(n) => n as usize,
                Err(_) => return None,
            },
            127 => match stream.read_u64().await {
                Ok(n) => n as usize,
                Err(_) => return None,
            },
            n => n as usize,
        };
        let mut payload = vec![0u8; len];
        if stream.read_exact(&mut payload).await.is_err() {
            return None;
        }
        Some((first & 0x0f, payload))
    })
    .await
    .map_err(|_| ())
}

async fn write_masked_client_ws_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) {
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    let mut buf = Vec::with_capacity(payload.len() + 10);
    buf.push(0x80 | (opcode & 0x0f));
    if payload.len() < 126 {
        buf.push(0x80 | (payload.len() as u8));
    } else {
        buf.push(0x80 | 126);
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    buf.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        buf.push(b ^ mask[i % 4]);
    }
    stream.write_all(&buf).await.unwrap();
}

async fn open_raw_ws(
    addr: SocketAddr,
    path_and_query: &str,
    extra_headers: &[(&str, &str)],
) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let ws_key = base64::engine::general_purpose::STANDARD.encode([0x42u8; 16]);
    let mut raw = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {ws_key}\r\n"
    );
    for (k, v) in extra_headers {
        raw.push_str(&format!("{k}: {v}\r\n"));
    }
    raw.push_str("\r\n");
    stream.write_all(raw.as_bytes()).await.unwrap();
    let mut hdr = Vec::new();
    while !hdr.ends_with(b"\r\n\r\n") {
        assert!(hdr.len() < 16_384);
        hdr.push(
            tokio::time::timeout(Duration::from_secs(3), stream.read_u8())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    (stream, String::from_utf8(hdr).unwrap())
}

#[test]
fn peer_request_headers_drop_connection_metadata_before_trusted_headers_are_added() {
    let mut client_headers = HeaderMap::new();
    client_headers.append(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    client_headers.append(
        header::CONNECTION,
        HeaderValue::from_static("X-Proxy-Fixture"),
    );
    client_headers.insert(
        "x-proxy-fixture",
        HeaderValue::from_static("connection-specific"),
    );
    client_headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));

    let trusted_fields = [
        HEADER_LINK_TOKEN,
        HEADER_GRANT_TOKEN,
        HEADER_ORIGIN_OPERATOR,
        "cookie",
        "x-request-id",
    ];
    for name in trusted_fields {
        client_headers.append(header::CONNECTION, HeaderValue::from_static(name));
    }

    let mut forwarded = copy_peer_request_headers(&client_headers, false);
    assert!(!forwarded.contains_key(header::CONNECTION));
    assert!(!forwarded.contains_key("x-proxy-fixture"));
    assert_eq!(forwarded[header::ACCEPT], "application/json");

    for name in trusted_fields {
        forwarded.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static("fixture-value"),
        );
    }
    assert!(crate::middlewares::connection_header_tokens(&forwarded).is_empty());
}

#[test]
fn peer_proxy_location_and_backup_set_cookie_rewriting_trust_boundaries() {
    assert_eq!(DEFAULT_PEER_MAX_WS, 16);
    assert!(configured_peer_max_ws() > 0);

    // 1. Safe root-relative /api/v1/... and tus upload Locations are rewritten under /api/v1/peers/{id}.
    assert_eq!(
        rewrite_peer_location_header("/api/v1/auth/mcbrowser/uploads/up-1234", "link-b").as_deref(),
        Some("/api/v1/peers/link-b/auth/mcbrowser/uploads/up-1234")
    );
    assert_eq!(
        rewrite_peer_location_header("/api/v1/admin/settings?section=general", "link-b").as_deref(),
        Some("/api/v1/peers/link-b/admin/settings?section=general")
    );
    assert_eq!(
        rewrite_peer_location_header("//api//v1/auth/mcbrowser/uploads/up-9", "link-b"),
        None,
        "protocol-relative // prefix must be stripped"
    );

    // 2. Hostile, off-origin, non-v1, traversal, and peer-hop Locations are stripped.
    for hostile in [
        "https://evil.example/api/v1/auth/mcbrowser/uploads/up-1",
        "http://127.0.0.1:9443/api/v1/admin/settings",
        "//evil.example/api/v1/admin/settings",
        "/login",
        "/api/admin/settings",
        "/api/v1/peers/other/admin/settings",
        "/api/v1/admin/peers/link-b/grant",
        "/api/v1/auth/../admin/peers",
        "/api/v1/auth/%2e%2e/admin/peers",
        "javascript:alert(1)",
        "/api/v1/admin/settings#frag",
        "/api/v1/admin/settings\r\nX-Injected: 1",
    ] {
        assert_eq!(
            rewrite_peer_location_header(hostile, "link-b"),
            None,
            "expected hostile Location to be stripped: {hostile:?}"
        );
    }

    // 3. Narrowly scoped backup download Set-Cookie (issue + clear) is rewritten cleanly.
    let tok = "a".repeat(64);
    let issue_raw = format!(
        "{BACKUP_DOWNLOAD_COOKIE}={tok}; Path=/api/v1/admin/backup/download/; Max-Age=60; SameSite=Strict; Secure; HttpOnly"
    );
    let rewritten_issue = rewrite_peer_backup_set_cookie(
        &issue_raw,
        "link-b",
        "/api/v1/admin/backup/download/snap.sqlite",
        true,
    )
    .expect("valid backup issue cookie should be rewritten");
    assert_eq!(
        rewritten_issue,
        format!(
            "{BACKUP_DOWNLOAD_COOKIE}={tok}; Path=/api/v1/peers/link-b/admin/backup/download/; Max-Age=60; SameSite=Strict; Secure; HttpOnly"
        )
    );

    // Oversized Max-Age from peer is clamped to 60s and Secure follows local policy.
    let long_age = format!(
        "{BACKUP_DOWNLOAD_COOKIE}={tok}; Path=/api/v1/admin/backup/download/; Max-Age=999999; SameSite=Strict; HttpOnly"
    );
    let clamped = rewrite_peer_backup_set_cookie(
        &long_age,
        "link-b",
        "/api/v1/admin/backup/download/snap.sqlite",
        false,
    )
    .expect("clamped backup issue cookie");
    assert!(clamped.contains("Max-Age=60"), "{clamped}");
    assert!(!clamped.contains("Secure"), "{clamped}");
    assert!(clamped.contains("HttpOnly"), "{clamped}");

    let clear_raw = format!(
        "{BACKUP_DOWNLOAD_COOKIE}=; Path=/api/v1/admin/backup/download/; Max-Age=-1; SameSite=Strict; Secure; HttpOnly"
    );
    let rewritten_clear = rewrite_peer_backup_set_cookie(
        &clear_raw,
        "link-b",
        "/api/v1/admin/backup/download/snap.sqlite",
        true,
    )
    .expect("valid backup clearing cookie should be rewritten");
    assert_eq!(
        rewritten_clear,
        format!(
            "{BACKUP_DOWNLOAD_COOKIE}=; Path=/api/v1/peers/link-b/admin/backup/download/; Max-Age=-1; SameSite=Strict; Secure; HttpOnly"
        )
    );

    // 4. All untrusted Set-Cookie attempts are rejected and stripped.
    assert_eq!(
        rewrite_peer_backup_set_cookie(
            &issue_raw,
            "link-b",
            "/api/v1/admin/settings", // wrong route!
            true,
        ),
        None
    );
    for bad_cookie in [
        "aetherflow_session=forged; Path=/; HttpOnly; SameSite=Lax",
        "csrf_token=forged; Path=/; HttpOnly; SameSite=Strict",
        &format!("{BACKUP_DOWNLOAD_COOKIE}={tok}; Path=/; Max-Age=60; SameSite=Strict; HttpOnly"),
        &format!("{BACKUP_DOWNLOAD_COOKIE}={tok}; Path=/api/v1/admin/backup/download/; Domain=evil.example; Max-Age=60; HttpOnly"),
        &format!("{BACKUP_DOWNLOAD_COOKIE}=not-hex-token; Path=/api/v1/admin/backup/download/; Max-Age=60; HttpOnly"),
        &format!("{BACKUP_DOWNLOAD_COOKIE}=; Path=/api/v1/admin/backup/download/; Max-Age=60; HttpOnly"),
    ] {
        assert_eq!(
            rewrite_peer_backup_set_cookie(
                bad_cookie,
                "link-b",
                "/api/v1/admin/backup/download/snap.sqlite",
                true,
            ),
            None,
            "expected untrusted Set-Cookie to be stripped: {bad_cookie}"
        );
    }
}

#[tokio::test]
async fn peer_proxy_link_state_compatibility_and_credential_gating() {
    let clock = FakeClock::new(1_800_800_000);
    let local_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 81));
    let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 82));
    let runner = FakePeerRunner::new(fixture_wg_pubkey(201), local_ip, 51821);
    let (rt, db) = build_proxy_test_runtime(
        "manager-a",
        Arc::clone(&runner) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        64,
        16,
        Duration::from_secs(5),
    );
    let app = admin_proxy_app(Arc::clone(&rt), fixture_admin_user());

    // 1. Unknown link -> 404 PEER_NOT_FOUND
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/missing-link/admin/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(body["code"], "PEER_NOT_FOUND");

    // 2. Pending, down, revoked, incompatible, missing grants capability, no held grant, missing link token
    let cases = [
        (
            "link-pending",
            STATE_PENDING,
            Some(1),
            Some(r#"["links","grants"]"#),
            Some(AccessMap::read_only_all()),
            Some("l-tok"),
            Some(("link-pending", "g-tok")),
            StatusCode::CONFLICT,
            "PEER_CONFLICT",
        ),
        (
            "link-down",
            STATE_DOWN,
            Some(1),
            Some(r#"["links","grants"]"#),
            Some(AccessMap::read_only_all()),
            Some("l-tok"),
            Some(("link-down", "g-tok")),
            StatusCode::BAD_GATEWAY,
            "LINK_DOWN",
        ),
        (
            "link-revoked",
            STATE_REVOKED,
            Some(1),
            Some(r#"["links","grants"]"#),
            Some(AccessMap::read_only_all()),
            Some("l-tok"),
            Some(("link-revoked", "g-tok")),
            StatusCode::FORBIDDEN,
            "LINK_REVOKED",
        ),
        (
            "link-incompat",
            STATE_ACTIVE,
            Some(0),
            Some(r#"["links","grants"]"#),
            Some(AccessMap::read_only_all()),
            Some("l-tok"),
            Some(("link-incompat", "g-tok")),
            StatusCode::UNPROCESSABLE_ENTITY,
            "VERSION_INCOMPATIBLE",
        ),
        (
            "link-no-grants-cap",
            STATE_ACTIVE,
            Some(1),
            Some(r#"["links"]"#),
            Some(AccessMap::read_only_all()),
            Some("l-tok"),
            Some(("link-no-grants-cap", "g-tok")),
            StatusCode::UNPROCESSABLE_ENTITY,
            "VERSION_INCOMPATIBLE",
        ),
        (
            "link-no-grant",
            STATE_ACTIVE,
            Some(1),
            Some(r#"["links","grants"]"#),
            None,
            Some("l-tok"),
            None,
            StatusCode::FORBIDDEN,
            "PEER_SCOPE_DENIED",
        ),
        (
            "link-missing-link-tok",
            STATE_ACTIVE,
            Some(1),
            Some(r#"["links","grants"]"#),
            Some(AccessMap::read_only_all()),
            None,
            Some(("cred-staged-1", "g-tok")),
            StatusCode::UNAUTHORIZED,
            "PEER_UNAUTHORIZED",
        ),
    ];

    for (idx, (id, state, proto, caps, access, ltok, gtok, exp_status, exp_code)) in
        cases.into_iter().enumerate()
    {
        let target_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, (90 + idx) as u8));
        seed_proxy_link(
            &db,
            &runner,
            local_ip,
            id,
            &format!("peer-{idx}"),
            target_ip,
            state,
            proto,
            caps,
            access,
            ltok,
            gtok,
        );
        // Ensure unique wg_pubkey per row
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "UPDATE peer_links SET wg_pubkey = ?1 WHERE id = ?2",
                rusqlite::params![fixture_wg_pubkey(210 + idx as u8), id],
            )
            .unwrap();
        }
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/{id}/admin/settings"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), exp_status, "case {id}");
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(body["code"], exp_code, "case {id}: {body}");
    }

    // 3. Peer-hop & path traversal rejected before touching upstream.
    seed_proxy_link(
        &db,
        &runner,
        local_ip,
        "link-ok",
        "peer-ok",
        peer_ip,
        STATE_ACTIVE,
        Some(1),
        Some(r#"["links","grants"]"#),
        Some(AccessMap::read_write_all()),
        Some("link-secret-ok"),
        Some(("staged-cred-ok", "grant-secret-ok")),
    );
    let hop = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/link-ok/peers/other/admin/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hop.status(), StatusCode::FORBIDDEN);
    let hop_body: Value =
        serde_json::from_slice(&to_bytes(hop.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(hop_body["code"], "PEER_SCOPE_DENIED");

    let trav = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/link-ok/admin/%2e%2e/admin/peers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(trav.status(), StatusCode::FORBIDDEN);
    let trav_body: Value =
        serde_json::from_slice(&to_bytes(trav.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(trav_body["code"], "PEER_ROUTE_UNCLASSIFIED");

    // 4. PeerPrincipal injected directly onto proxy route is rejected with PEER_SCOPE_DENIED.
    let mut peer_req = Request::builder()
        .uri("/link-ok/admin/services")
        .body(Body::empty())
        .unwrap();
    peer_req.extensions_mut().insert(PeerPrincipal {
        link_id: "link-other".to_string(),
        link_name: "peer-other".to_string(),
        local_server: "proxy-host".to_string(),
        grant_id: "grant-other".to_string(),
        run_as_user_id: 1,
        run_as_username: "admin".to_string(),
        access: AccessMap::read_write_all(),
        origin_operator: Some("alice".to_string()),
        request_id: "req-peer-hop".to_string(),
    });
    let peer_resp = app.clone().oneshot(peer_req).await.unwrap();
    assert_eq!(peer_resp.status(), StatusCode::FORBIDDEN);
    let peer_body: Value =
        serde_json::from_slice(&to_bytes(peer_resp.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(peer_body["code"], "PEER_SCOPE_DENIED");

    // 5. PluginTokenClaims injected directly onto proxy route is rejected with PLUGIN_SCOPE_DENIED.
    let mut plugin_req = Request::builder()
        .uri("/link-ok/admin/services")
        .body(Body::empty())
        .unwrap();
    plugin_req
        .extensions_mut()
        .insert(crate::plugins::PluginTokenClaims {
            typ: "plugin".to_string(),
            iss: "aetherflow".to_string(),
            aud: "aetherflow-plugin".to_string(),
            sub: "1".to_string(),
            plugin_id: "demo".to_string(),
            jti: "jti-plugin".to_string(),
            iat: 1_800_000_000,
            exp: 1_800_000_600,
            epoch: 1,
            scopes: Vec::new(),
        });
    let plugin_resp = app.oneshot(plugin_req).await.unwrap();
    assert_eq!(plugin_resp.status(), StatusCode::FORBIDDEN);
    let plugin_body: Value =
        serde_json::from_slice(&to_bytes(plugin_resp.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(plugin_body["code"], "PLUGIN_SCOPE_DENIED");

    let _ = rt;
}

#[tokio::test]
async fn peer_proxy_headers_request_id_streaming_tus_timeout_and_session_preservation() {
    let clock = FakeClock::new(1_800_801_000);
    let local_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 83));
    let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 84));
    let runner = FakePeerRunner::new(fixture_wg_pubkey(201), local_ip, 51821);
    let (rt, db) = build_proxy_test_runtime(
        "manager-a",
        Arc::clone(&runner) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        64,
        16,
        Duration::from_millis(350),
    );

    let (chunk_gate_tx, chunk_gate_rx) = tokio::sync::oneshot::channel::<()>();
    let chunk_gate_rx = Arc::new(TokioMutex::new(Some(chunk_gate_rx)));
    let (first_req_chunk_tx, first_req_chunk_rx) = tokio::sync::oneshot::channel::<String>();
    let first_req_chunk_tx = Arc::new(StdMutex::new(Some(first_req_chunk_tx)));

    let gate_clone = Arc::clone(&chunk_gate_rx);
    let req_chunk_tx_clone = Arc::clone(&first_req_chunk_tx);
    let upstream_app = Router::new()
        .route(
            "/api/v1/echo-headers",
            any(|req: Request| async move {
                let mut map = serde_json::Map::new();
                for (k, v) in req.headers() {
                    map.insert(
                        k.as_str().to_string(),
                        json!(v.to_str().unwrap_or("<non-utf8>")),
                    );
                }
                let uri = req.uri().to_string();
                let mut resp = axum::Json(json!({ "uri": uri, "headers": map })).into_response();
                resp.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=120"),
                );
                resp.headers_mut().insert(
                    "cdn-cache-control",
                    HeaderValue::from_static("public, max-age=120"),
                );
                resp.headers_mut()
                    .insert("refresh", HeaderValue::from_static("0"));
                resp.headers_mut()
                    .insert("service-worker-allowed", HeaderValue::from_static("/"));
                resp.headers_mut().insert(
                    header::SET_COOKIE,
                    HeaderValue::from_static("aetherflow_session=evil; Path=/; HttpOnly"),
                );
                resp.headers_mut().insert(
                    header::HeaderName::from_static("clear-site-data"),
                    HeaderValue::from_static("\"cookies\""),
                );
                resp.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Basic realm=\"Evil\""),
                );
                resp.headers_mut().insert(
                    header::LOCATION,
                    HeaderValue::from_static("https://evil.example/phish"),
                );
                resp
            }),
        )
        .route(
            "/api/v1/auth/mcbrowser/uploads",
            axum::routing::post(|| async move {
                let mut resp = Response::new(Body::empty());
                *resp.status_mut() = StatusCode::CREATED;
                resp.headers_mut().insert(
                    header::LOCATION,
                    HeaderValue::from_static("/api/v1/auth/mcbrowser/uploads/tus-sess-77"),
                );
                resp.headers_mut()
                    .insert("tus-resumable", HeaderValue::from_static("1.0.0"));
                resp.headers_mut()
                    .insert("upload-offset", HeaderValue::from_static("0"));
                resp
            }),
        )
        .route(
            "/api/v1/remote-401",
            get(|| async move {
                let mut resp = (
                    StatusCode::UNAUTHORIZED,
                    axum::Json(json!({"code": "PEER_UNAUTHORIZED", "message": "Remote denied"})),
                )
                    .into_response();
                resp.headers_mut().insert(
                    header::SET_COOKIE,
                    HeaderValue::from_static("aetherflow_session=; Path=/; Max-Age=-1; HttpOnly"),
                );
                resp.headers_mut().insert(
                    header::HeaderName::from_static("clear-site-data"),
                    HeaderValue::from_static("\"cookies\""),
                );
                resp
            }),
        )
        .route(
            "/api/v1/stream-upload",
            axum::routing::post(move |req: Request| {
                let tx_holder = Arc::clone(&req_chunk_tx_clone);
                async move {
                    use futures::StreamExt as _;
                    let mut stream = req.into_body().into_data_stream();
                    let mut total = Vec::new();
                    let mut notified = false;
                    while let Some(Ok(chunk)) = stream.next().await {
                        if !notified {
                            notified = true;
                            if let Some(tx) = tx_holder.lock().unwrap().take() {
                                let _ = tx.send(String::from_utf8_lossy(&chunk).into_owned());
                            }
                        }
                        total.extend_from_slice(&chunk);
                    }
                    axum::Json(json!({ "received_len": total.len(), "text": String::from_utf8_lossy(&total) }))
                }
            }),
        )
        .route(
            "/api/v1/stream-download",
            get(move || {
                let gate = Arc::clone(&gate_clone);
                async move {
                    let s = async_stream::stream! {
                        yield Ok::<Bytes, std::io::Error>(Bytes::from_static(b"chunk-1\n"));
                        if let Some(rx) = gate.lock().await.take() {
                            let _ = rx.await;
                        }
                        // Sleep longer than proxy_header_timeout (350ms) to prove streaming bodies
                        // are NOT capped by the connect/header budget!
                        tokio::time::sleep(Duration::from_millis(450)).await;
                        yield Ok::<Bytes, std::io::Error>(Bytes::from_static(b"chunk-2\n"));
                    };
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(Body::from_stream(s))
                        .unwrap()
                }
            }),
        )
        .route(
            "/api/v1/slow-headers",
            get(|| async move {
                tokio::time::sleep(Duration::from_millis(800)).await;
                StatusCode::OK
            }),
        );

    let listener = TcpListener::bind(SocketAddr::new(peer_ip, 0))
        .await
        .unwrap();
    let peer_port = listener.local_addr().unwrap().port();
    let upstream_task = tokio::spawn(async move {
        let _ = axum::serve(listener, upstream_app).await;
    });

    rt.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(peer_ip, peer_port);
    seed_proxy_link(
        &db,
        &runner,
        local_ip,
        "link-b",
        "media-2",
        peer_ip,
        STATE_ACTIVE,
        Some(1),
        Some(r#"["links","grants"]"#),
        Some(AccessMap::read_write_all()),
        Some("distinct-link-secret-1111"),
        Some(("cred-rotated-9", "distinct-grant-secret-2222")),
    );

    let app = admin_proxy_app(Arc::clone(&rt), fixture_admin_user());

    // 1. Header stripping, separate link/grant tokens, Host derivation, operator & RequestId propagation,
    //    and hostile response header stripping!
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/link-b/echo-headers?foo=bar")
                .header(header::HOST, "dashboard.example.test")
                .header(header::ORIGIN, "https://dashboard.example.test")
                .header(header::REFERER, "https://dashboard.example.test/tab")
                .header(header::AUTHORIZATION, "Bearer browser-jwt-secret")
                .header(
                    header::COOKIE,
                    "aetherflow_session=browser-cookie-secret; csrf_token=browser-csrf",
                )
                .header("X-CSRF-Token", "browser-csrf")
                .header("X-Forwarded-For", "203.0.113.55")
                .header("X-Forwarded-Host", "spoofed.example")
                .header("X-Reauth-Password", "super-secret-local-password")
                .header(HEADER_LINK_TOKEN, "spoofed-link-token")
                .header(HEADER_GRANT_TOKEN, "spoofed-grant-token")
                .header(HEADER_ORIGIN_OPERATOR, "spoofed-operator")
                .header("X-Request-ID", "req-p6-corr-123")
                .header(header::CONNECTION, "keep-alive, X-Proxy-Fixture")
                .header("X-Proxy-Fixture", "connection-specific")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["X-Request-ID"], "req-p6-corr-123");
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "private, no-store");
    assert_eq!(resp.headers()[header::EXPIRES], "0");
    assert!(!resp.headers().contains_key("cdn-cache-control"));
    assert!(!resp.headers().contains_key("refresh"));
    assert!(!resp.headers().contains_key("service-worker-allowed"));
    assert!(resp.headers().get(header::SET_COOKIE).is_none());
    assert!(resp.headers().get("clear-site-data").is_none());
    assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert!(resp.headers().get(header::LOCATION).is_none());

    let echo: Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 16_384).await.unwrap()).unwrap();
    assert_eq!(echo["uri"], "/api/v1/echo-headers?foo=bar");
    let hdrs = echo["headers"].as_object().unwrap();
    assert_eq!(hdrs[HEADER_LINK_TOKEN], "distinct-link-secret-1111");
    assert_eq!(hdrs[HEADER_GRANT_TOKEN], "distinct-grant-secret-2222");
    assert_eq!(hdrs[HEADER_ORIGIN_OPERATOR], "alice-admin");
    assert_eq!(hdrs["x-request-id"], "req-p6-corr-123");
    assert_eq!(hdrs["host"], format!("{peer_ip}:{peer_port}"));
    for stripped in [
        "authorization",
        "cookie",
        "origin",
        "referer",
        "x-csrf-token",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-reauth-password",
        "x-proxy-fixture",
    ] {
        assert!(
            !hdrs.contains_key(stripped),
            "header `{stripped}` must be stripped before upstream: {hdrs:?}"
        );
    }

    // 2. tus upload Location rewriting preserves tus headers and rewrites root-relative /api/v1 path.
    let tus_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/link-b/auth/mcbrowser/uploads")
                .header("Tus-Resumable", "1.0.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tus_resp.status(), StatusCode::CREATED);
    assert_eq!(
        tus_resp.headers()[header::LOCATION],
        "/api/v1/peers/link-b/auth/mcbrowser/uploads/tus-sess-77"
    );
    assert_eq!(tus_resp.headers()["tus-resumable"], "1.0.0");

    // 3. Remote 401 preserves managing browser session (no Set-Cookie / Clear-Site-Data leaked).
    let remote_401 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/link-b/remote-401")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(remote_401.status(), StatusCode::UNAUTHORIZED);
    assert!(remote_401.headers().get(header::SET_COOKIE).is_none());
    assert!(remote_401.headers().get("clear-site-data").is_none());

    // 4. Streaming request body: upstream observes chunk 1 BEFORE client sends chunk 2!
    let (body_tx, mut body_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    let req_stream = async_stream::stream! {
        while let Some(item) = body_rx.recv().await {
            yield item;
        }
    };
    let app_for_upload = app.clone();
    let upload_task = tokio::spawn(async move {
        app_for_upload
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/link-b/stream-upload")
                    .body(Body::from_stream(req_stream))
                    .unwrap(),
            )
            .await
            .unwrap()
    });
    body_tx
        .send(Ok(Bytes::from_static(b"first-stream-part|")))
        .await
        .unwrap();
    let observed_first = tokio::time::timeout(Duration::from_secs(2), first_req_chunk_rx)
        .await
        .expect("upstream must receive first request chunk before body closes (no buffering)")
        .unwrap();
    assert_eq!(observed_first, "first-stream-part|");
    body_tx
        .send(Ok(Bytes::from_static(b"second-stream-part")))
        .await
        .unwrap();
    drop(body_tx);
    let upload_resp = upload_task.await.unwrap();
    assert_eq!(upload_resp.status(), StatusCode::OK);
    let upload_json: Value =
        serde_json::from_slice(&to_bytes(upload_resp.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(upload_json["text"], "first-stream-part|second-stream-part");

    // 5. Streaming response body: first chunk arrives BEFORE chunk 2 is produced, and multi-chunk
    //    body lasting longer than proxy_header_timeout (350ms) succeeds!
    let dl_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/link-b/stream-download")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dl_resp.status(), StatusCode::OK);
    {
        use futures::StreamExt as _;
        let mut dl_stream = dl_resp.into_body().into_data_stream();
        let first = tokio::time::timeout(Duration::from_secs(2), dl_stream.next())
            .await
            .expect("first streamed response chunk must arrive before upstream finishes")
            .unwrap()
            .unwrap();
        assert_eq!(&first[..], b"chunk-1\n");
        let _ = chunk_gate_tx.send(());
        let second = tokio::time::timeout(Duration::from_secs(2), dl_stream.next())
            .await
            .expect("second chunk after >header_timeout must still stream cleanly")
            .unwrap()
            .unwrap();
        assert_eq!(&second[..], b"chunk-2\n");
    }

    // 6. Slow upstream headers exceeding proxy_header_timeout return 504 HANDSHAKE_TIMEOUT.
    let timeout_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/link-b/slow-headers")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(timeout_resp.status(), StatusCode::GATEWAY_TIMEOUT);
    let timeout_json: Value =
        serde_json::from_slice(&to_bytes(timeout_resp.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(timeout_json["code"], "HANDSHAKE_TIMEOUT");

    // Exercise an upload whose total duration exceeds the idle budget while bytes keep flowing.
    let active_body = async_stream::stream! {
        for chunk in [b"0", b"1", b"2", b"3", b"4", b"5"] {
            yield Ok::<_, std::io::Error>(Bytes::from_static(chunk));
            tokio::time::sleep(Duration::from_millis(90)).await;
        }
    };
    let started = Instant::now();
    let upload = app.clone().oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/link-b/stream-upload")
            .body(Body::from_stream(active_body))
            .unwrap(),
    );
    let uploaded = tokio::time::timeout(Duration::from_secs(3), upload)
        .await
        .unwrap()
        .unwrap();
    assert!(started.elapsed() > rt.proxy_header_timeout);
    assert_eq!(uploaded.status(), StatusCode::OK);
    let uploaded_json: Value =
        serde_json::from_slice(&to_bytes(uploaded.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(uploaded_json["text"], "012345");

    let permits_before_upload = rt.available_link_http_permits("link-b");
    let idle_upload = app.oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/link-b/stream-upload")
            .body(Body::from_stream(futures::stream::pending::<
                Result<Bytes, std::io::Error>,
            >()))
            .unwrap(),
    );
    let response = tokio::time::timeout(Duration::from_secs(2), idle_upload)
        .await
        .expect("an idle upload should release the HTTP slot")
        .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        rt.available_link_http_permits("link-b"),
        permits_before_upload
    );

    upstream_task.abort();
}

#[tokio::test]
async fn peer_proxy_concurrency_caps_hold_and_release_permits_across_streams_and_ws() {
    let clock = FakeClock::new(1_800_802_000);
    let local_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 85));
    let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 86));
    let runner = FakePeerRunner::new(fixture_wg_pubkey(201), local_ip, 51821);
    let (rt, db) = build_proxy_test_runtime(
        "manager-a",
        Arc::clone(&runner) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        2, // max_conn_per_link = 2
        2, // max_ws_per_link = 2
        Duration::from_secs(5),
    );

    let (release_tx, _) = broadcast::channel::<()>(4);
    let rel_http = release_tx.clone();
    let upstream_app = Router::new()
        .route(
            "/api/v1/hold-stream",
            get(move || {
                let mut rx = rel_http.subscribe();
                async move {
                    let s = async_stream::stream! {
                        yield Ok::<Bytes, std::io::Error>(Bytes::from_static(b"held\n"));
                        let _ = rx.recv().await;
                        yield Ok::<Bytes, std::io::Error>(Bytes::from_static(b"done\n"));
                    };
                    Response::new(Body::from_stream(s))
                }
            }),
        )
        .route(
            "/api/v1/auth/ws",
            get(|ws: WebSocketUpgrade| async move {
                ws.on_upgrade(|mut socket| async move {
                    while let Some(Ok(msg)) = socket.recv().await {
                        match msg {
                            Message::Ping(p) => {
                                let _ = socket.send(Message::Pong(p)).await;
                            }
                            Message::Text(t) => {
                                let _ = socket.send(Message::Text(format!("echo:{t}"))).await;
                            }
                            Message::Close(_) => break,
                            _ => {}
                        }
                    }
                })
            }),
        );

    let up_listener = TcpListener::bind(SocketAddr::new(peer_ip, 0))
        .await
        .unwrap();
    let up_port = up_listener.local_addr().unwrap().port();
    let up_task = tokio::spawn(async move {
        let _ = axum::serve(up_listener, upstream_app).await;
    });

    rt.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(peer_ip, up_port);
    seed_proxy_link(
        &db,
        &runner,
        local_ip,
        "link-cap",
        "cap-peer",
        peer_ip,
        STATE_ACTIVE,
        Some(1),
        Some(r#"["links","grants"]"#),
        Some(AccessMap::read_write_all()),
        Some("cap-link-token"),
        Some(("link-cap", "cap-grant-token")),
    );

    // Serve proxy on real loopback TCP so WebSocket upgrades run over real hyper HTTP/1.1!
    let proxy_router = admin_proxy_app(Arc::clone(&rt), fixture_admin_user());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let _ = axum::serve(
            proxy_listener,
            proxy_router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    let client = reqwest::Client::new();
    let url = format!("http://{proxy_addr}/link-cap/hold-stream");

    // 1. Open 2 concurrent HTTP streaming responses (filling max_conn_per_link = 2).
    let mut r1 = client.get(&url).send().await.unwrap();
    assert_eq!(r1.status(), reqwest::StatusCode::OK);
    let c1 = r1.chunk().await.unwrap().unwrap();
    assert_eq!(&c1[..], b"held\n");

    // A streaming HTTP route still uses an HTTP permit when offered a WebSocket upgrade.
    let mut r2 = client
        .get(&url)
        .header(header::CONNECTION, "Upgrade")
        .header(header::UPGRADE, "websocket")
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), reqwest::StatusCode::OK);
    let c2 = r2.chunk().await.unwrap().unwrap();
    assert_eq!(&c2[..], b"held\n");

    assert_eq!(rt.available_link_http_permits("link-cap"), 0);

    // 3rd HTTP request is rejected with 503 PEER_BUSY while streams are held open!
    let r3 = client.get(&url).send().await.unwrap();
    assert_eq!(r3.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let r3_body: Value = r3.json().await.unwrap();
    assert_eq!(r3_body["code"], "PEER_BUSY");

    // 2. While HTTP cap is saturated, WebSocket pool (max_ws_per_link = 2) is independent!
    let origin = format!("http://{proxy_addr}");
    let (mut ws1, hdr1) =
        open_raw_ws(proxy_addr, "/link-cap/auth/ws", &[("Origin", &origin)]).await;
    assert!(hdr1.starts_with("HTTP/1.1 101"), "{hdr1}");
    let (ws2, hdr2) = open_raw_ws(proxy_addr, "/link-cap/auth/ws", &[("Origin", &origin)]).await;
    assert!(hdr2.starts_with("HTTP/1.1 101"), "{hdr2}");
    assert_eq!(rt.available_link_ws_permits("link-cap"), 0);

    // 3rd WebSocket is rejected with 503 PEER_BUSY!
    let (_ws3, hdr3) = open_raw_ws(proxy_addr, "/link-cap/auth/ws", &[("Origin", &origin)]).await;
    assert!(hdr3.starts_with("HTTP/1.1 503"), "{hdr3}");

    // Verify Ping/Pong works through the proxied WebSocket tunnel!
    write_masked_client_ws_frame(&mut ws1, 0x9, b"ping-cap").await;
    let (op, data) = read_ws_frame(&mut ws1).await;
    assert_eq!(op, 0xA, "expected Pong frame");
    assert_eq!(&data[..], b"ping-cap");

    // 3. Disconnect HTTP stream 2 early and complete HTTP stream 1 -> permits release to 2!
    drop(r2);
    let _ = release_tx.send(());
    let rest1 = r1.chunk().await.unwrap().unwrap();
    assert_eq!(&rest1[..], b"done\n");
    assert!(r1.chunk().await.unwrap().is_none());
    drop(r1);

    tokio::time::timeout(Duration::from_secs(2), async {
        while rt.available_link_http_permits("link-cap") != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("HTTP permits must release after stream completion and disconnect");

    // 4. Close WS 1 cleanly and drop WS 2 -> WS permits release to 2!
    write_masked_client_ws_frame(&mut ws1, 0x8, &[]).await;
    drop(ws1);
    drop(ws2);
    tokio::time::timeout(Duration::from_secs(2), async {
        while rt.available_link_ws_permits("link-cap") != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("WS permits must release after clean close and disconnect");

    proxy_task.abort();
    up_task.abort();
}

#[tokio::test]
async fn peer_proxy_real_router_backup_download_isolated_ticket_and_auth_csrf_matrix() {
    let test_name =
        "peers::proxy_tests::peer_proxy_real_router_backup_download_isolated_ticket_and_auth_csrf_matrix";
    if !isolated_p6_subprocess(test_name) {
        return;
    }

    let root = std::env::temp_dir().join(format!("af-p6-backup-{}", uuid::Uuid::new_v4()));
    let backup_dir = root.join("backups");
    std::fs::create_dir_all(&backup_dir).unwrap();
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        std::env::set_var(key, root.join("fixture.sqlite"));
    }
    std::env::set_var("AETHERFLOW_BACKUP_DIR", &backup_dir);
    std::env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    std::env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
    std::env::set_var("AETHERFLOW_MASTER_CREDS_FILE", root.join("missing-creds"));
    std::env::set_var("ALLOWED_HOSTS", "localhost,127.0.0.1");
    std::env::set_var("COOKIE_SECURE", "false");
    std::env::set_var(
        "JWT_SECRET",
        "p6-test-jwt-secret-must-be-at-least-32-bytes!",
    );
    std::env::set_var("AES_MASTER_KEY", "ci-test-aes-key-exactly-32bytes!");

    af_db::init_db().unwrap();
    af_db::init_aes_key().unwrap();

    // Seed human admin + non-admin user on local DB (shared by production router for B).
    let pw_hash = bcrypt::hash("local-admin-pass", 4).unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role, password_hash) VALUES (1, 'alice', 'admin', ?1), (2, 'bob', 'user', ?1)",
            rusqlite::params![pw_hash],
        )
        .unwrap();
    }

    let created_backup = crate::storage::perform_system_backup().unwrap();

    // Pair server A (isolated DB) with server B (production DB + real build_router()).
    let ip_a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 91));
    let ip_b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 92));
    let clock = FakeClock::new(1_800_810_000);
    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(231), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(232), ip_b, 51821);

    let (rev_tx_b, _) = broadcast::channel(64);
    let rt_b = Arc::new(PeerRuntime {
        db: PeerDb::Production,
        runner: Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        storage_runner: Arc::new(super::storage_tests::FakePeerStorageRunner::new()),
        mount_health: super::storage::MountHealthTracker::new(),
        transcode_runner: Arc::new(super::transcode_tests::FakePeerTranscodeRunner::new()),
        transcode_state: Arc::new(super::transcode::TranscodeRuntimeState::new()),
        public_transport: Arc::new(UnreachablePublicTransport),
        revocation_tx: rev_tx_b,
        pairing_rate_limiter: super::pairing::PairingRateLimiter::new(
            super::pairing::PAIRING_RATE_LIMIT_PER_MIN,
            Duration::from_secs(60),
        ),
        attempt_locks: KeyedAsyncLockPool::new(),
        link_locks: KeyedAsyncLockPool::new(),
        link_semaphores: StdMutex::new(HashMap::new()),
        link_ws_semaphores: StdMutex::new(HashMap::new()),
        tunnel_clients: StdMutex::new(HashMap::new()),
        proxy_tunnel_clients: StdMutex::new(HashMap::new()),
        listener_state: TokioMutex::new(None),
        health_shutdown: TokioMutex::new(None),
        clock: clock.as_fn(),
        monotonic_clock: clock.as_monotonic_fn(),
        lock_wait_timeout: Duration::from_secs(5),
        listen_port: 0,
        max_conn_per_link: 64,
        max_ws_per_link: 16,
        proxy_header_timeout: Duration::from_secs(30),
        rtt_warn_ms: 25.0,
        server_name_override: Some("managed-b".to_string()),
        version_override: Some("4.0.0-p6".to_string()),
        tunnel_binding: TunnelTransportBinding::LoopbackFixture,
        tunnel_request_timeout: Duration::from_secs(3),
        tunnel_port_overrides: RwLock::new(HashMap::new()),
        bind_listener_in_handlers: true,
        management_router_override: None,
        allowed_fs_roots_override: None,
        interface_index_override: RwLock::new(None),
    });
    let (rt_a, _db_a) = build_proxy_test_runtime(
        "manager-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 41], 45200)),
        }),
        &clock,
        64,
        16,
        Duration::from_secs(30),
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "managed-b").await;

    // Grant settings: write on B to A.
    let mut write_settings = AccessMap::none();
    write_settings.settings = AccessLevel::Write;
    let (st, _) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": write_settings })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Mint human admin JWT, non-admin JWT, and plugin JWT.
    let mut hdrs = HeaderMap::new();
    hdrs.insert(header::USER_AGENT, HeaderValue::from_static("p6-browser"));
    let (admin_jwt, _) = crate::auth::create_standard_jwt(1, &hdrs).unwrap();
    let (user_jwt, _) = crate::auth::create_standard_jwt(2, &hdrs).unwrap();
    let (plugin_jwt, _) = crate::auth::mint_plugin_jwt(1, "demo", &[], 600).unwrap();

    // 1. Verify production router mounts /api/v1/peers/:id/*rest and NOT /api/peers/:id/*rest.
    let prod_app = crate::routes::build_router();
    let legacy_404 = prod_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/peers/{a_link_id}/admin/settings"))
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p6-browser")
                .header(header::AUTHORIZATION, format!("Bearer {admin_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(legacy_404.status(), StatusCode::NOT_FOUND);

    // Build A's full proxy router using the exact `tracked_proxy_routes_with_runtime` middleware stack
    // plus outer `security_headers_middleware` and `host_validation_middleware`.
    let a_proxy_app = Router::new()
        .nest(
            "/api/v1/peers",
            super::tracked_proxy_routes_with_runtime(Arc::clone(&rt_a)).into_router(),
        )
        .layer(axum::middleware::from_fn(
            crate::middlewares::host_validation_middleware,
        ))
        .layer(axum::middleware::from_fn(
            crate::routes::security_headers_middleware,
        ));

    // 2. Auth, role, plugin, PeerPrincipal, CSRF, and cross-origin WS checks on A's proxy router.
    let unauth = a_proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/peers/{a_link_id}/admin/settings"))
                .header(header::HOST, "localhost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    let non_admin = a_proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/peers/{a_link_id}/admin/settings"))
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p6-browser")
                .header(header::COOKIE, format!("aetherflow_session={user_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(non_admin.status(), StatusCode::FORBIDDEN);

    let plugin_resp = a_proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/peers/{a_link_id}/admin/settings"))
                .header(header::HOST, "localhost")
                .header(header::AUTHORIZATION, format!("Bearer {plugin_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(plugin_resp.status(), StatusCode::UNAUTHORIZED);

    // Cookie-authenticated admin POST without CSRF -> 403!
    let backup_path = format!(
        "/api/v1/peers/{a_link_id}/admin/backup/download/{}",
        created_backup.filename
    );
    let no_csrf = a_proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&backup_path)
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p6-browser")
                .header(header::COOKIE, format!("aetherflow_session={admin_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(no_csrf.status(), StatusCode::FORBIDDEN);

    // Cross-origin WS upgrade on A -> 403!
    let bad_ws_origin = a_proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/peers/{a_link_id}/auth/ws?ticket=abc"))
                .header(header::HOST, "localhost")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::CONNECTION, "Upgrade")
                .header(header::UPGRADE, "websocket")
                .header(header::USER_AGENT, "p6-browser")
                .header(header::COOKIE, format!("aetherflow_session={admin_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_ws_origin.status(), StatusCode::FORBIDDEN);

    // 3. Local backup download without password/ticket still fails 403 (local step-up preserved!).
    let local_no_stepup = prod_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/admin/backup/download/{}",
                    created_backup.filename
                ))
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p6-browser")
                .header(header::COOKIE, format!("aetherflow_session={admin_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(local_no_stepup.status(), StatusCode::FORBIDDEN);

    // 4. Remote backup download 2-step flow with isolated ticket cookie!
    let csrf_tok = "csrf-p6-backup-token-1234";
    let prep = a_proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&backup_path)
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p6-browser")
                .header(
                    header::COOKIE,
                    format!("aetherflow_session={admin_jwt}; csrf_token={csrf_tok}"),
                )
                .header("X-CSRF-Token", csrf_tok)
                // Even if an older caller passes local password, proxy strips it and uses grant!
                .header("X-Reauth-Password", "wrong-local-password")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"password":"wrong-local-password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(prep.status(), StatusCode::OK);
    let set_cookie = prep
        .headers()
        .get(header::SET_COOKIE)
        .expect("rewritten backup ticket Set-Cookie")
        .to_str()
        .unwrap()
        .to_string();
    let expected_peer_cookie_path =
        format!("Path=/api/v1/peers/{a_link_id}/admin/backup/download/");
    assert!(
        set_cookie.contains(&expected_peer_cookie_path),
        "cookie path must be scoped to selected peer: {set_cookie}"
    );
    assert!(set_cookie.contains("SameSite=Strict"), "{set_cookie}");
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
    assert!(set_cookie.contains("Max-Age=60"), "{set_cookie}");
    let ticket_pair = set_cookie.split(';').next().unwrap().to_string();
    assert!(ticket_pair.starts_with(&format!("{BACKUP_DOWNLOAD_COOKIE}=")));

    // 4a. Malformed, ambiguous, and wrong-file tickets MUST FAIL 403 without falling back to grant-only!
    for (desc, uri, cookie_val) in [
        (
            "malformed non-hex ticket",
            backup_path.clone(),
            format!("aetherflow_session={admin_jwt}; {BACKUP_DOWNLOAD_COOKIE}=not-valid-hex"),
        ),
        (
            "ambiguous duplicate ticket",
            backup_path.clone(),
            format!("aetherflow_session={admin_jwt}; {ticket_pair}; {ticket_pair}"),
        ),
        (
            "wrong filename for ticket",
            format!("/api/v1/peers/{a_link_id}/admin/backup/download/other.sqlite"),
            format!("aetherflow_session={admin_jwt}; {ticket_pair}"),
        ),
    ] {
        let bad = a_proxy_app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header(header::HOST, "localhost")
                    .header(header::USER_AGENT, "p6-browser")
                    .header(header::COOKIE, cookie_val)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            bad.status(),
            StatusCode::FORBIDDEN,
            "scenario `{desc}` must fail closed without falling back to grant-only"
        );
    }

    // 4b. Valid isolated ticket downloads the backup and emits rewritten clearing Set-Cookie!
    let dl = a_proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&backup_path)
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p6-browser")
                .header(
                    header::COOKIE,
                    format!("aetherflow_session={admin_jwt}; {ticket_pair}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dl.status(), StatusCode::OK);
    let clear_cookie = dl
        .headers()
        .get(header::SET_COOKIE)
        .expect("clearing backup ticket Set-Cookie")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        clear_cookie.contains(&expected_peer_cookie_path),
        "clearing cookie path must match peer scope: {clear_cookie}"
    );
    assert!(clear_cookie.contains("Max-Age=-1"), "{clear_cookie}");
    let dl_bytes = to_bytes(dl.into_body(), 2 * 1024 * 1024).await.unwrap();
    assert!(dl_bytes.starts_with(b"SQLite format 3\0"));

    // 4c. Replaying the consumed ticket MUST FAIL 403 (no fallback to grant-only!).
    let replay = a_proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&backup_path)
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p6-browser")
                .header(
                    header::COOKIE,
                    format!("aetherflow_session={admin_jwt}; {ticket_pair}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::FORBIDDEN);

    // 4d. Rotating the grant invalidates an unredeemed ticket issued under the previous grant!
    let prep2 = a_proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&backup_path)
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p6-browser")
                .header(
                    header::COOKIE,
                    format!("aetherflow_session={admin_jwt}; csrf_token={csrf_tok}"),
                )
                .header("X-CSRF-Token", csrf_tok)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(prep2.status(), StatusCode::OK);
    let ticket2_pair = prep2.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Rotate grant on B -> new grant_id -> old grant's ticket must fail!
    let (rot_st, _) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": write_settings })),
    )
    .await;
    assert_eq!(rot_st, StatusCode::OK);

    let wrong_grant = a_proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&backup_path)
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p6-browser")
                .header(
                    header::COOKIE,
                    format!("aetherflow_session={admin_jwt}; {ticket2_pair}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        wrong_grant.status(),
        StatusCode::FORBIDDEN,
        "ticket from superseded grant must be rejected without falling back"
    );

    // 4e. Cookie-less GET through proxy with active settings:write grant still succeeds (P5 preserved!).
    let cookieless = a_proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&backup_path)
                .header(header::HOST, "localhost")
                .header(header::USER_AGENT, "p6-browser")
                .header(header::COOKIE, format!("aetherflow_session={admin_jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cookieless.status(), StatusCode::OK);

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn peer_proxy_end_to_end_websockets_ticket_isolation_and_1s_revocation_gate() {
    let test_name =
        "peers::proxy_tests::peer_proxy_end_to_end_websockets_ticket_isolation_and_1s_revocation_gate";
    if !isolated_p6_subprocess(test_name) {
        return;
    }

    let root = std::env::temp_dir().join(format!("af-p6-ws-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(root.join("bin")).unwrap();
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        std::env::set_var(key, root.join("fixture.sqlite"));
    }
    std::env::set_var("AETHERFLOW_DISABLE_HOST_ENV_FILE", "1");
    std::env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");
    std::env::set_var("AETHERFLOW_MASTER_CREDS_FILE", root.join("missing-creds"));
    std::env::set_var("ALLOWED_HOSTS", "localhost,127.0.0.1");
    std::env::set_var("COOKIE_SECURE", "false");
    std::env::set_var("JWT_SECRET", "p6-ws-jwt-secret-must-be-at-least-32-bytes!");
    std::env::set_var("AES_MASTER_KEY", "ci-test-aes-key-exactly-32bytes!");
    std::env::set_var("AF_P6_WS_LOG_ROOT", &root);
    std::env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            std::env::var("PATH").unwrap()
        ),
    );

    // Fake journalctl outputting lines written to `$AF_P6_WS_LOG_ROOT/next-line`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let journal = root.join("bin/journalctl");
        std::fs::write(
            &journal,
            r#"#!/usr/bin/python3
import os, pathlib, time
root = pathlib.Path(os.environ['AF_P6_WS_LOG_ROOT'])
previous = ''
while True:
    try:
        line = (root / 'next-line').read_text()
    except FileNotFoundError:
        line = ''
    if line and line != previous:
        print(line, flush=True)
        previous = line
    time.sleep(0.01)
"#,
        )
        .unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    af_db::init_db().unwrap();
    af_db::init_aes_key().unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (1, 'alice', 'admin')",
            [],
        )
        .unwrap();
    }

    let ip_a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 95));
    let ip_b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 96));
    let ip_c = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 97));
    let clock = FakeClock::new(1_800_820_000);
    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(241), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(242), ip_b, 51821);
    let runner_c = FakePeerRunner::new(fixture_wg_pubkey(243), ip_c, 51821);

    let (rev_tx_b, _) = broadcast::channel(64);
    let rt_b = Arc::new(PeerRuntime {
        db: PeerDb::Production,
        runner: Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        storage_runner: Arc::new(super::storage_tests::FakePeerStorageRunner::new()),
        mount_health: super::storage::MountHealthTracker::new(),
        transcode_runner: Arc::new(super::transcode_tests::FakePeerTranscodeRunner::new()),
        transcode_state: Arc::new(super::transcode::TranscodeRuntimeState::new()),
        public_transport: Arc::new(UnreachablePublicTransport),
        revocation_tx: rev_tx_b,
        pairing_rate_limiter: super::pairing::PairingRateLimiter::new(
            super::pairing::PAIRING_RATE_LIMIT_PER_MIN,
            Duration::from_secs(60),
        ),
        attempt_locks: KeyedAsyncLockPool::new(),
        link_locks: KeyedAsyncLockPool::new(),
        link_semaphores: StdMutex::new(HashMap::new()),
        link_ws_semaphores: StdMutex::new(HashMap::new()),
        tunnel_clients: StdMutex::new(HashMap::new()),
        proxy_tunnel_clients: StdMutex::new(HashMap::new()),
        listener_state: TokioMutex::new(None),
        health_shutdown: TokioMutex::new(None),
        clock: clock.as_fn(),
        monotonic_clock: clock.as_monotonic_fn(),
        lock_wait_timeout: Duration::from_secs(5),
        listen_port: 0,
        max_conn_per_link: 64,
        max_ws_per_link: 16,
        proxy_header_timeout: Duration::from_secs(30),
        rtt_warn_ms: 25.0,
        server_name_override: Some("managed-b".to_string()),
        version_override: Some("4.0.0-p6".to_string()),
        tunnel_binding: TunnelTransportBinding::LoopbackFixture,
        tunnel_request_timeout: Duration::from_secs(3),
        tunnel_port_overrides: RwLock::new(HashMap::new()),
        bind_listener_in_handlers: true,
        management_router_override: None,
        allowed_fs_roots_override: None,
        interface_index_override: RwLock::new(None),
    });
    let (rt_a, _) = build_proxy_test_runtime(
        "manager-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 51], 45300)),
        }),
        &clock,
        64,
        16,
        Duration::from_secs(30),
    );
    let (rt_c, _) = build_proxy_test_runtime(
        "manager-c",
        Arc::clone(&runner_c) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 52], 45301)),
        }),
        &clock,
        64,
        16,
        Duration::from_secs(30),
    );

    let (a_link_id, b_a_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "managed-b").await;
    let (c_link_id, b_c_link_id, _) =
        pair_two_test_runtimes(&rt_c, &rt_b, ip_c, ip_b, "managed-b").await;

    // B grants BOTH A and C `services: read` (and `marketplace: none`).
    let mut svc_read = AccessMap::none();
    svc_read.services = AccessLevel::Read;
    for b_lid in [&b_a_link_id, &b_c_link_id] {
        let (st, _) = call_admin(
            &rt_b,
            Method::PUT,
            &format!("/{b_lid}/grant"),
            Some(json!({ "access": svc_read })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    // Serve A's proxy, C's proxy, AND B's local production router on loopback TCP!
    let a_srv = Router::new()
        .nest(
            "/api/v1/peers",
            super::tracked_proxy_routes_with_runtime(Arc::clone(&rt_a)).into_router(),
        )
        .layer(axum::middleware::from_fn(
            crate::routes::security_headers_middleware,
        ));
    let c_srv = Router::new()
        .nest(
            "/api/v1/peers",
            super::tracked_proxy_routes_with_runtime(Arc::clone(&rt_c)).into_router(),
        )
        .layer(axum::middleware::from_fn(
            crate::routes::security_headers_middleware,
        ));
    let b_local_srv = crate::routes::build_router();

    let a_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_listener.local_addr().unwrap();
    let c_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let c_addr = c_listener.local_addr().unwrap();
    let b_local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let b_local_addr = b_local_listener.local_addr().unwrap();

    let a_task = tokio::spawn(async move {
        let _ = axum::serve(
            a_listener,
            a_srv.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    let c_task = tokio::spawn(async move {
        let _ = axum::serve(
            c_listener,
            c_srv.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    let b_local_task = tokio::spawn(async move {
        let _ = axum::serve(
            b_local_listener,
            b_local_srv.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    let mut ua_hdrs = HeaderMap::new();
    ua_hdrs.insert(
        header::USER_AGENT,
        HeaderValue::from_static("p6-ws-browser"),
    );
    let (admin_jwt, _) = crate::auth::create_standard_jwt(1, &ua_hdrs).unwrap();
    let cookie_hdr = format!("aetherflow_session={admin_jwt}");
    let http = reqwest::Client::new();

    // 1. Issue tickets: peer A telemetry + logs, peer C logs, local human on B.
    let get_ticket = |base: SocketAddr, path: &str| {
        let http = http.clone();
        let cookie_hdr = cookie_hdr.clone();
        let url = format!("http://{base}{path}");
        async move {
            let resp = http
                .get(&url)
                .header(header::USER_AGENT, "p6-ws-browser")
                .header(header::COOKIE, cookie_hdr)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), reqwest::StatusCode::OK, "ticket url={url}");
            let body: Value = resp.json().await.unwrap();
            body["ticket"].as_str().unwrap().to_string()
        }
    };

    let a_tel_ticket =
        get_ticket(a_addr, &format!("/api/v1/peers/{a_link_id}/auth/ws/ticket")).await;
    let a_log_ticket =
        get_ticket(a_addr, &format!("/api/v1/peers/{a_link_id}/auth/ws/ticket")).await;
    let c_log_ticket =
        get_ticket(c_addr, &format!("/api/v1/peers/{c_link_id}/auth/ws/ticket")).await;
    let b_human_ticket = get_ticket(b_local_addr, "/api/v1/auth/ws/ticket").await;
    let a_cross_ticket =
        get_ticket(a_addr, &format!("/api/v1/peers/{a_link_id}/auth/ws/ticket")).await;

    // 2. Ticket isolation checks:
    //    - Peer A cannot redeem local human B ticket!
    let a_origin = format!("http://{a_addr}");
    let c_origin = format!("http://{c_addr}");
    let b_origin = format!("http://{b_local_addr}");
    let (_, bad_human_on_peer) = open_raw_ws(
        a_addr,
        &format!("/api/v1/peers/{a_link_id}/auth/ws?ticket={b_human_ticket}"),
        &[
            ("Origin", &a_origin),
            ("User-Agent", "p6-ws-browser"),
            ("Cookie", &cookie_hdr),
        ],
    )
    .await;
    assert!(
        bad_human_on_peer.starts_with("HTTP/1.1 401"),
        "peer must not redeem local human ticket: {bad_human_on_peer}"
    );
    //    - Local human on B cannot redeem peer A ticket!
    let (_, bad_peer_on_human) = open_raw_ws(
        b_local_addr,
        &format!("/api/v1/auth/ws?ticket={a_cross_ticket}"),
        &[
            ("Origin", &b_origin),
            ("User-Agent", "p6-ws-browser"),
            ("Cookie", &cookie_hdr),
        ],
    )
    .await;
    assert!(
        bad_peer_on_human.starts_with("HTTP/1.1 401"),
        "local human must not redeem peer ticket: {bad_peer_on_human}"
    );
    //    - Peer C cannot redeem peer A ticket!
    let (_, bad_peer_c_on_a) = open_raw_ws(
        c_addr,
        &format!("/api/v1/peers/{c_link_id}/auth/ws?ticket={a_cross_ticket}"),
        &[
            ("Origin", &c_origin),
            ("User-Agent", "p6-ws-browser"),
            ("Cookie", &cookie_hdr),
        ],
    )
    .await;
    assert!(
        bad_peer_c_on_a.starts_with("HTTP/1.1 401"),
        "peer C must not redeem peer A ticket: {bad_peer_c_on_a}"
    );

    // 3. Open Peer A telemetry WS, Peer A live-log WS, Peer C live-log WS, and local B live-log WS.
    let (mut a_tel_ws, hdr) = open_raw_ws(
        a_addr,
        &format!("/api/v1/peers/{a_link_id}/auth/ws?ticket={a_tel_ticket}"),
        &[
            ("Origin", &a_origin),
            ("User-Agent", "p6-ws-browser"),
            ("Cookie", &cookie_hdr),
        ],
    )
    .await;
    assert!(hdr.starts_with("HTTP/1.1 101"), "{hdr}");

    // Verify Ping/Pong on proxied telemetry WS!
    write_masked_client_ws_frame(&mut a_tel_ws, 0x9, b"tel-ping").await;
    let (op, pong_body) = read_ws_frame(&mut a_tel_ws).await;
    assert_eq!(op, 0xA);
    assert_eq!(&pong_body[..], b"tel-ping");

    let (mut a_log_ws, hdr) = open_raw_ws(
        a_addr,
        &format!("/api/v1/peers/{a_link_id}/auth/ws/logs?ticket={a_log_ticket}"),
        &[
            ("Origin", &a_origin),
            ("User-Agent", "p6-ws-browser"),
            ("Cookie", &cookie_hdr),
        ],
    )
    .await;
    assert!(hdr.starts_with("HTTP/1.1 101"), "{hdr}");

    let (mut c_log_ws, hdr) = open_raw_ws(
        c_addr,
        &format!("/api/v1/peers/{c_link_id}/auth/ws/logs?ticket={c_log_ticket}"),
        &[
            ("Origin", &c_origin),
            ("User-Agent", "p6-ws-browser"),
            ("Cookie", &cookie_hdr),
        ],
    )
    .await;
    assert!(hdr.starts_with("HTTP/1.1 101"), "{hdr}");

    let (mut b_local_log_ws, hdr) = open_raw_ws(
        b_local_addr,
        "/api/v1/auth/ws/logs",
        &[
            ("Origin", &b_origin),
            ("User-Agent", "p6-ws-browser"),
            ("Cookie", &cookie_hdr),
        ],
    )
    .await;
    assert!(hdr.starts_with("HTTP/1.1 101"), "{hdr}");

    // Read welcome frame on all 3 log streams.
    for (label, ws) in [
        ("peer-a", &mut a_log_ws),
        ("peer-c", &mut c_log_ws),
        ("local-b", &mut b_local_log_ws),
    ] {
        let (op, body) = read_ws_frame(ws).await;
        assert_eq!(op, 0x1, "{label}");
        assert!(
            String::from_utf8_lossy(&body).contains("Connected to AetherFlow Rust log stream"),
            "{label}"
        );
    }

    // Emit one fake journalctl line and verify all 3 log streams receive it.
    std::fs::write(
        root.join("next-line"),
        "2026-11-23T18:00:00 managed-b aetherflow: BEFORE_REVOKE_LINE",
    )
    .unwrap();
    for (label, ws) in [
        ("peer-a", &mut a_log_ws),
        ("peer-c", &mut c_log_ws),
        ("local-b", &mut b_local_log_ws),
    ] {
        let (op, body) = read_ws_frame(ws).await;
        assert_eq!(op, 0x1, "{label}");
        assert!(
            String::from_utf8_lossy(&body).contains("BEFORE_REVOKE_LINE"),
            "{label}: {}",
            String::from_utf8_lossy(&body)
        );
    }

    // 4. REVOKE Peer A's grant on B and assert BOTH Peer A sockets close within 1 second!
    let revoke_started = Instant::now();
    let (del_st, _) = call_admin(
        &rt_b,
        Method::DELETE,
        &format!("/{b_a_link_id}/grant"),
        None,
    )
    .await;
    assert_eq!(del_st, StatusCode::OK);

    let a_log_closed = read_ws_frame_with_timeout(&mut a_log_ws, Duration::from_secs(1)).await;
    let log_elapsed = revoke_started.elapsed();
    assert!(
        matches!(a_log_closed, Ok(None) | Ok(Some((0x8, _)))),
        "Peer A live-log WS must close within 1s of grant revocation, got {a_log_closed:?} in {log_elapsed:?}"
    );
    assert!(
        log_elapsed < Duration::from_secs(1),
        "Peer A live-log WS closed too slowly: {log_elapsed:?}"
    );

    let a_tel_closed = read_ws_frame_with_timeout(&mut a_tel_ws, Duration::from_secs(1)).await;
    let tel_elapsed = revoke_started.elapsed();
    assert!(
        matches!(a_tel_closed, Ok(None) | Ok(Some((0x8, _)))),
        "Peer A telemetry WS must close within 1s of grant revocation, got {a_tel_closed:?} in {tel_elapsed:?}"
    );
    assert!(
        tel_elapsed < Duration::from_secs(1),
        "Peer A telemetry WS closed too slowly: {tel_elapsed:?}"
    );

    // 5. Verify unrelated Peer C WS and local human B WS are PRESERVED and keep streaming!
    std::fs::write(
        root.join("next-line"),
        "2026-11-23T18:00:05 managed-b aetherflow: AFTER_PEER_A_REVOKE_LINE",
    )
    .unwrap();
    for (label, ws) in [("peer-c", &mut c_log_ws), ("local-b", &mut b_local_log_ws)] {
        let (op, body) = read_ws_frame(ws).await;
        assert_eq!(
            op, 0x1,
            "{label} should remain open after peer A revocation"
        );
        assert!(
            String::from_utf8_lossy(&body).contains("AFTER_PEER_A_REVOKE_LINE"),
            "{label}: {}",
            String::from_utf8_lossy(&body)
        );
    }

    // Verify link A stays active after grant revocation and A's WS permits are released.
    {
        let conn = af_db::get_read_conn().unwrap();
        let b_a_link = db_peers::get_peer_link(&conn, &b_a_link_id)
            .unwrap()
            .unwrap();
        assert!(is_active_link_state(&b_a_link.state));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while rt_a.available_link_ws_permits(&a_link_id) != 16 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("A's WS permits must release after peer A revocation closes sockets");

    // 6. Verify managing-side LINK revocation on A ALSO closes an active proxied WS within 1s!
    let (regrant_st, _) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_a_link_id}/grant"),
        Some(json!({ "access": svc_read })),
    )
    .await;
    assert_eq!(regrant_st, StatusCode::OK);
    let a_log_ticket2 =
        get_ticket(a_addr, &format!("/api/v1/peers/{a_link_id}/auth/ws/ticket")).await;
    let (mut a_log_ws2, hdr2) = open_raw_ws(
        a_addr,
        &format!("/api/v1/peers/{a_link_id}/auth/ws/logs?ticket={a_log_ticket2}"),
        &[
            ("Origin", &a_origin),
            ("User-Agent", "p6-ws-browser"),
            ("Cookie", &cookie_hdr),
        ],
    )
    .await;
    assert!(hdr2.starts_with("HTTP/1.1 101"), "{hdr2}");
    let _ = read_ws_frame(&mut a_log_ws2).await;

    let link_revoke_started = Instant::now();
    let (link_del_st, _) = call_admin(&rt_a, Method::DELETE, &format!("/{a_link_id}"), None).await;
    assert_eq!(link_del_st, StatusCode::OK);
    let closed_on_link_revoke =
        read_ws_frame_with_timeout(&mut a_log_ws2, Duration::from_secs(1)).await;
    assert!(
        matches!(closed_on_link_revoke, Ok(None) | Ok(Some((0x8, _)))),
        "Peer A proxied WS must close within 1s of link revocation, got {closed_on_link_revoke:?} in {:?}",
        link_revoke_started.elapsed()
    );
    assert!(link_revoke_started.elapsed() < Duration::from_secs(1));

    drop(c_log_ws);
    drop(b_local_log_ws);
    a_task.abort();
    c_task.abort();
    b_local_task.abort();
    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
    rt_c.shutdown_all().await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn peer_proxy_non_ws_http_streams_cancel_promptly_on_managing_revocation() {
    let clock = FakeClock::new(1_800_830_000);
    let local_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 141));
    let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 142));
    let runner = FakePeerRunner::new(fixture_wg_pubkey(141), local_ip, 51821);
    let (rt, db) = build_proxy_test_runtime(
        "manager-a",
        Arc::clone(&runner) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        2, // max_conn_per_link = 2
        2,
        Duration::from_secs(5),
    );

    let (slow_entered_tx, mut slow_entered_rx) = mpsc::channel::<()>(4);
    let (upload_first_tx, mut upload_first_rx) = mpsc::channel::<()>(4);
    let upstream_app = Router::new()
        .route(
            "/api/v1/stream-sse",
            get(|| async move {
                let s = async_stream::stream! {
                    yield Ok::<Bytes, std::io::Error>(Bytes::from_static(b"data: chunk-1\n\n"));
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    yield Ok::<Bytes, std::io::Error>(Bytes::from_static(b"data: never-delivered\n\n"));
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::from_stream(s))
                    .unwrap()
            }),
        )
        .route(
            "/api/v1/slow-headers",
            get(move || {
                let tx = slow_entered_tx.clone();
                async move {
                    let _ = tx.send(()).await;
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    StatusCode::OK
                }
            }),
        )
        .route(
            "/api/v1/stream-upload",
            axum::routing::post(move |req: Request| {
                let tx = upload_first_tx.clone();
                async move {
                    use futures::StreamExt as _;
                    let mut stream = req.into_body().into_data_stream();
                    if let Some(Ok(_)) = stream.next().await {
                        let _ = tx.send(()).await;
                    }
                    while let Some(Ok(_)) = stream.next().await {}
                    StatusCode::OK
                }
            }),
        );

    let up_listener = TcpListener::bind(SocketAddr::new(peer_ip, 0))
        .await
        .unwrap();
    let up_port = up_listener.local_addr().unwrap().port();
    let up_task = tokio::spawn(async move {
        let _ = axum::serve(up_listener, upstream_app).await;
    });

    rt.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(peer_ip, up_port);
    seed_proxy_link(
        &db,
        &runner,
        local_ip,
        "link-rev",
        "rev-peer",
        peer_ip,
        STATE_ACTIVE,
        Some(1),
        Some(r#"["links","grants"]"#),
        Some(AccessMap::read_write_all()),
        Some("rev-link-token"),
        Some(("link-rev", "rev-grant-token")),
    );

    let proxy_router = admin_proxy_app(Arc::clone(&rt), fixture_admin_user());
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let _ = axum::serve(
            proxy_listener,
            proxy_router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    let client = reqwest::Client::new();
    let sse_url = format!("http://{proxy_addr}/link-rev/stream-sse");
    let slow_url = format!("http://{proxy_addr}/link-rev/slow-headers");

    // 1. In-flight non-WS streaming HTTP response aborts << 1s on GrantRevoked and releases permit.
    let mut r_grant = client.get(&sse_url).send().await.unwrap();
    assert_eq!(r_grant.status(), reqwest::StatusCode::OK);
    let first = r_grant.chunk().await.unwrap().unwrap();
    assert_eq!(&first[..], b"data: chunk-1\n\n");
    assert_eq!(rt.available_link_http_permits("link-rev"), 1);

    let revoke_started = Instant::now();
    rt.publish_revocation(super::RevocationEvent::GrantRevoked {
        link_id: "link-rev".to_string(),
        grant_id: "grant-link-rev".to_string(),
        run_as_user_id: 1,
    });
    let next_res = tokio::time::timeout(Duration::from_secs(1), r_grant.chunk())
        .await
        .expect("managing-side streaming HTTP response must abort within 1s on GrantRevoked");
    assert!(
        revoke_started.elapsed() < Duration::from_secs(1),
        "abort took {:?}",
        revoke_started.elapsed()
    );
    assert!(
        next_res.is_err(),
        "aborted HTTP chunked stream must error instead of delivering remaining chunks, got {next_res:?}"
    );
    drop(r_grant);
    tokio::time::timeout(Duration::from_secs(1), async {
        while rt.available_link_http_permits("link-rev") != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("HTTP permit must release promptly after GrantRevoked abort");

    // 2. In-flight non-WS streaming HTTP response aborts << 1s on LinkRevoked and releases permit.
    let mut r_link = client.get(&sse_url).send().await.unwrap();
    assert_eq!(r_link.status(), reqwest::StatusCode::OK);
    let first2 = r_link.chunk().await.unwrap().unwrap();
    assert_eq!(&first2[..], b"data: chunk-1\n\n");
    assert_eq!(rt.available_link_http_permits("link-rev"), 1);

    let link_revoke_started = Instant::now();
    rt.publish_revocation(super::RevocationEvent::LinkRevoked {
        link_id: "link-rev".to_string(),
        peer_name: "rev-peer".to_string(),
    });
    let next_res2 = tokio::time::timeout(Duration::from_secs(1), r_link.chunk())
        .await
        .expect("managing-side streaming HTTP response must abort within 1s on LinkRevoked");
    assert!(link_revoke_started.elapsed() < Duration::from_secs(1));
    assert!(
        next_res2.is_err(),
        "expected stream abort error on LinkRevoked, got {next_res2:?}"
    );
    drop(r_link);
    tokio::time::timeout(Duration::from_secs(1), async {
        while rt.available_link_http_permits("link-rev") != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("HTTP permit must release promptly after LinkRevoked abort");

    // 3. Pre-headers pending request aborts << 1s with 403 LINK_REVOKED on LinkRevoked.
    let slow_client = client.clone();
    let slow_url_c = slow_url.clone();
    let slow_req = tokio::spawn(async move { slow_client.get(&slow_url_c).send().await.unwrap() });
    tokio::time::timeout(Duration::from_secs(2), slow_entered_rx.recv())
        .await
        .expect("upstream slow-headers handler must be reached")
        .unwrap();
    let pre_hdr_started = Instant::now();
    rt.publish_revocation(super::RevocationEvent::LinkRevoked {
        link_id: "link-rev".to_string(),
        peer_name: "rev-peer".to_string(),
    });
    let slow_resp = tokio::time::timeout(Duration::from_secs(1), slow_req)
        .await
        .expect("pre-headers request must abort within 1s of LinkRevoked")
        .unwrap();
    assert!(pre_hdr_started.elapsed() < Duration::from_secs(1));
    assert_eq!(slow_resp.status(), reqwest::StatusCode::FORBIDDEN);
    let slow_body: Value = slow_resp.json().await.unwrap();
    assert_eq!(slow_body["code"], "LINK_REVOKED");
    assert_eq!(rt.available_link_http_permits("link-rev"), 2);

    // 4. In-flight streaming HTTP upload aborts << 1s with 403 PEER_SCOPE_DENIED on GrantRevoked.
    let (up_tx, mut up_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    let up_stream = async_stream::stream! {
        while let Some(item) = up_rx.recv().await {
            yield item;
        }
    };
    let upload_url = format!("http://{proxy_addr}/link-rev/stream-upload");
    let up_client = client.clone();
    let upload_task = tokio::spawn(async move {
        up_client
            .post(&upload_url)
            .body(reqwest::Body::wrap_stream(up_stream))
            .send()
            .await
            .unwrap()
    });
    up_tx
        .send(Ok(Bytes::from_static(b"partial-upload-chunk")))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), upload_first_rx.recv())
        .await
        .expect("upstream upload handler must receive initial chunk")
        .unwrap();
    let upload_revoke_started = Instant::now();
    rt.publish_revocation(super::RevocationEvent::GrantRevoked {
        link_id: "link-rev".to_string(),
        grant_id: "grant-link-rev".to_string(),
        run_as_user_id: 1,
    });
    let upload_resp = tokio::time::timeout(Duration::from_secs(1), upload_task)
        .await
        .expect("in-flight streaming upload must abort within 1s of GrantRevoked")
        .unwrap();
    assert!(upload_revoke_started.elapsed() < Duration::from_secs(1));
    assert_eq!(upload_resp.status(), reqwest::StatusCode::FORBIDDEN);
    let upload_body: Value = upload_resp.json().await.unwrap();
    assert_eq!(upload_body["code"], "PEER_SCOPE_DENIED");
    drop(up_tx);
    tokio::time::timeout(Duration::from_secs(1), async {
        while rt.available_link_http_permits("link-rev") != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("HTTP permit must release promptly after upload abort");

    proxy_task.abort();
    up_task.abort();
}

#[tokio::test]
async fn peer_listener_non_ws_http_streams_cancel_promptly_on_target_revocation() {
    let clock = FakeClock::new(1_800_831_000);
    let ip_a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 143));
    let ip_b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 144));
    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(143), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(144), ip_b, 51821);

    let (slow_entered_tx, mut slow_entered_rx) = mpsc::channel::<()>(4);
    let target_mgmt_router = Router::new()
        .route(
            "/api/v1/auth/deploy/stream",
            get(|| async move {
                let s = async_stream::stream! {
                    yield Ok::<Bytes, std::io::Error>(Bytes::from_static(b"data: target-chunk-1\n\n"));
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    yield Ok::<Bytes, std::io::Error>(Bytes::from_static(b"data: target-never-delivered\n\n"));
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::from_stream(s))
                    .unwrap()
            }),
        )
        .route(
            "/api/v1/admin/services",
            get(move || {
                let tx = slow_entered_tx.clone();
                async move {
                    let _ = tx.send(()).await;
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    StatusCode::OK
                }
            }),
        );

    let (mut rt_b_raw, _db_b) = build_proxy_test_runtime(
        "target-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        2,
        2,
        Duration::from_secs(5),
    );
    Arc::get_mut(&mut rt_b_raw)
        .unwrap()
        .management_router_override = Some(target_mgmt_router);
    let rt_b = rt_b_raw;

    let (rt_a, _db_a) = build_proxy_test_runtime(
        "manager-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 61], 45400)),
        }),
        &clock,
        2,
        2,
        Duration::from_secs(5),
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "target-b").await;

    let mut grant_access = AccessMap::none();
    grant_access.marketplace = AccessLevel::Read;
    grant_access.services = AccessLevel::Read;
    let (st, _) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": grant_access })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Build a direct tunnel client bound to Server A's loopback IP hitting Server B's listener
    // directly (isolating target-side listener cancellation without managing-side proxy!).
    let b_binding = rt_a.resolve_outbound_tunnel_binding(ip_b).await.unwrap();
    let direct_client = rt_a.get_or_build_proxy_tunnel_client(&b_binding).unwrap();
    let link_token = runner_a
        .state
        .lock()
        .unwrap()
        .credentials
        .get(&(PeerCredentialSlot::LinkToken, a_link_id.clone()))
        .unwrap()
        .clone();
    let (_, grant_secret) = super::grants::read_committed_received_grant_token(&rt_a, &a_link_id)
        .await
        .unwrap()
        .unwrap();
    let grant_token = grant_secret.expose_secret().to_string();

    // 1. Target-side post-headers streaming response aborts << 1s on DELETE /grant.
    let stream_url = rt_a
        .build_tunnel_url(&ip_b.to_string(), "/api/v1/auth/deploy/stream")
        .unwrap();
    let mut resp = direct_client
        .get(stream_url)
        .header(HEADER_LINK_TOKEN, &link_token)
        .header(HEADER_GRANT_TOKEN, &grant_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let first = resp.chunk().await.unwrap().unwrap();
    assert_eq!(&first[..], b"data: target-chunk-1\n\n");
    assert_eq!(rt_b.available_link_http_permits(&b_link_id), 1);

    let revoke_started = Instant::now();
    let (del_st, _) = call_admin(&rt_b, Method::DELETE, &format!("/{b_link_id}/grant"), None).await;
    assert_eq!(del_st, StatusCode::OK);

    let next_chunk = tokio::time::timeout(Duration::from_secs(1), resp.chunk())
        .await
        .expect("target-side streaming HTTP response must abort within 1s of grant revocation");
    assert!(revoke_started.elapsed() < Duration::from_secs(1));
    assert!(
        next_chunk.is_err(),
        "expected target-side aborted chunked response error, got {next_chunk:?}"
    );
    drop(resp);
    tokio::time::timeout(Duration::from_secs(1), async {
        while rt_b.available_link_http_permits(&b_link_id) != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("target-side HTTP permit must release promptly after stream abort");

    // 2. Target-side pre-headers oneshot handler aborts << 1s with 403 PEER_SCOPE_DENIED on DELETE /grant.
    let (regrant_st, _) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": grant_access })),
    )
    .await;
    assert_eq!(regrant_st, StatusCode::OK);
    let (_, grant_secret2) = super::grants::read_committed_received_grant_token(&rt_a, &a_link_id)
        .await
        .unwrap()
        .unwrap();
    let grant_token2 = grant_secret2.expose_secret().to_string();

    let slow_url = rt_a
        .build_tunnel_url(&ip_b.to_string(), "/api/v1/admin/services")
        .unwrap();
    let client_c = direct_client.clone();
    let lt_c = link_token.clone();
    let gt_c = grant_token2.clone();
    let slow_task = tokio::spawn(async move {
        client_c
            .get(slow_url)
            .header(HEADER_LINK_TOKEN, lt_c)
            .header(HEADER_GRANT_TOKEN, gt_c)
            .header("X-Request-ID", "req-target-abort-99")
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), slow_entered_rx.recv())
        .await
        .expect("target management handler must be entered")
        .unwrap();

    let pre_started = Instant::now();
    let (del_st2, _) =
        call_admin(&rt_b, Method::DELETE, &format!("/{b_link_id}/grant"), None).await;
    assert_eq!(del_st2, StatusCode::OK);

    let aborted_resp = tokio::time::timeout(Duration::from_secs(1), slow_task)
        .await
        .expect("target-side pre-headers request must abort within 1s of grant revocation")
        .unwrap();
    assert!(pre_started.elapsed() < Duration::from_secs(1));
    assert_eq!(aborted_resp.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(
        aborted_resp
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok()),
        Some("req-target-abort-99")
    );
    let aborted_body: Value = aborted_resp.json().await.unwrap();
    assert_eq!(aborted_body["code"], "PEER_SCOPE_DENIED");
    assert_eq!(aborted_body["request_id"], "req-target-abort-99");
    assert_eq!(rt_b.available_link_http_permits(&b_link_id), 2);

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

#[tokio::test]
async fn peer_tunnel_health_reports_inbound_grant_generation_transcode_and_request_id() {
    let clock = FakeClock::new(1_800_832_000);
    let ip_a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 145));
    let ip_b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 146));
    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(145), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(146), ip_b, 51821);

    let (rt_b, _db_b) = build_proxy_test_runtime(
        "target-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        8,
        8,
        Duration::from_secs(5),
    );
    rt_b.transcode_state.set_local_capabilities_override(Some(
        af_transcode::TranscodeCapabilities {
            ffmpeg_path: "/usr/lib/jellyfin-ffmpeg/ffmpeg".to_string(),
            ffmpeg_version: Some("8.1.3".to_string()),
            ffmpeg_version_line: Some("ffmpeg version 8.1.3-Jellyfin".to_string()),
            package_name: Some("jellyfin-ffmpeg8".to_string()),
            package_version: Some("8.1.3-1-trixie".to_string()),
            encoders: vec!["h264_vaapi".to_string(), "libx264".to_string()],
            render_nodes: vec![],
            primary_render_node: Some("/dev/dri/renderD128".to_string()),
            worker_max_jobs: Some(6),
            hw_decoders: vec![],
            hw_encoders_verified: false,
            adapt_backend_mode: None,
            vulkan_compute: None,
            vulkan_device: None,
            vulkan_video: None,
            vulkan_video_decode_codecs: Vec::new(),
            vulkan_video_encode_codecs: Vec::new(),
        },
    ));

    let (rt_a, _db_a) = build_proxy_test_runtime(
        "manager-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 62], 45401)),
        }),
        &clock,
        8,
        8,
        Duration::from_secs(5),
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "target-b").await;

    let b_binding = rt_a.resolve_outbound_tunnel_binding(ip_b).await.unwrap();
    let client = rt_a.get_or_build_proxy_tunnel_client(&b_binding).unwrap();
    let health_url = rt_a.build_tunnel_url(&ip_b.to_string(), "/health").unwrap();
    let link_token = runner_a
        .state
        .lock()
        .unwrap()
        .credentials
        .get(&(PeerCredentialSlot::LinkToken, a_link_id.clone()))
        .unwrap()
        .clone();

    // 1. Before any grant exists: inbound_grant_generation is explicitly present and null,
    //    cached transcode capabilities (including worker_max_jobs) are non-null, and X-Request-ID is echoed.
    let resp0 = client
        .get(health_url.clone())
        .header(HEADER_LINK_TOKEN, &link_token)
        .header("X-Request-ID", "req-health-corr-1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp0.status(), reqwest::StatusCode::OK);
    assert_eq!(
        resp0
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok()),
        Some("req-health-corr-1")
    );
    let body0: Value = resp0.json().await.unwrap();
    assert!(
        body0
            .as_object()
            .unwrap()
            .contains_key("inbound_grant_generation"),
        "tunnel /health must always include inbound_grant_generation key: {body0}"
    );
    assert!(body0["inbound_grant_generation"].is_null(), "{body0}");
    assert_eq!(body0["transcode"]["worker_max_jobs"], 6);
    assert_eq!(body0["transcode"]["ffmpeg_version"], "8.1.3");

    // 2. Unauthorized tunnel call with explicit X-Request-ID echoes header AND populates PeerErrorBody.request_id.
    let err_resp = client
        .get(health_url.clone())
        .header(HEADER_LINK_TOKEN, "wrong-token")
        .header("X-Request-ID", "req-tunnel-err-42")
        .send()
        .await
        .unwrap();
    assert_eq!(err_resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(
        err_resp
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok()),
        Some("req-tunnel-err-42")
    );
    let err_body: Value = err_resp.json().await.unwrap();
    assert_eq!(err_body["code"], "PEER_UNAUTHORIZED");
    assert_eq!(err_body["request_id"], "req-tunnel-err-42");

    // 3. Unauthorized tunnel call WITHOUT X-Request-ID generates one and uses the same ID in header & JSON.
    let gen_err_resp = client
        .get(health_url.clone())
        .header(HEADER_LINK_TOKEN, "wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(gen_err_resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let generated_id = gen_err_resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("tunnel listener must generate and echo X-Request-ID")
        .to_string();
    assert!(!generated_id.is_empty());
    let gen_err_body: Value = gen_err_resp.json().await.unwrap();
    assert_eq!(gen_err_body["request_id"], generated_id);

    // 4. Grant created -> inbound_grant_generation = 1; rotated -> 2; revoked -> null.
    let mut svc_read = AccessMap::none();
    svc_read.services = AccessLevel::Read;
    let (st1, _) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": svc_read })),
    )
    .await;
    assert_eq!(st1, StatusCode::OK);
    let body1: Value = client
        .get(health_url.clone())
        .header(HEADER_LINK_TOKEN, &link_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body1["inbound_grant_generation"], 1);

    let (st2, _) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": svc_read })),
    )
    .await;
    assert_eq!(st2, StatusCode::OK);
    let body2: Value = client
        .get(health_url.clone())
        .header(HEADER_LINK_TOKEN, &link_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body2["inbound_grant_generation"], 2);

    let (del_st, _) = call_admin(&rt_b, Method::DELETE, &format!("/{b_link_id}/grant"), None).await;
    assert_eq!(del_st, StatusCode::OK);
    let body3: Value = client
        .get(health_url)
        .header(HEADER_LINK_TOKEN, &link_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(body3
        .as_object()
        .unwrap()
        .contains_key("inbound_grant_generation"));
    assert!(body3["inbound_grant_generation"].is_null(), "{body3}");

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

#[tokio::test]
async fn peer_proxy_updates_write_narrows_package_updates_to_jellyfin_and_ffmpeg() {
    let clock = FakeClock::new(1_800_833_000);
    let ip_a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 147));
    let ip_b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 148));
    let runner_a = FakePeerRunner::new(fixture_wg_pubkey(147), ip_a, 51821);
    let runner_b = FakePeerRunner::new(fixture_wg_pubkey(148), ip_b, 51821);

    let target_mgmt = Router::new().route(
        "/api/v1/admin/packages/:id/update",
        axum::routing::post(
            |axum::extract::Path(id): axum::extract::Path<String>| async move {
                (StatusCode::OK, axum::Json(json!({ "updated": id })))
            },
        ),
    );

    let (mut rt_b_raw, _db_b) = build_proxy_test_runtime(
        "target-b",
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        8,
        8,
        Duration::from_secs(5),
    );
    Arc::get_mut(&mut rt_b_raw)
        .unwrap()
        .management_router_override = Some(target_mgmt);
    let rt_b = rt_b_raw;

    let (rt_a, _db_a) = build_proxy_test_runtime(
        "manager-a",
        Arc::clone(&runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 63], 45402)),
        }),
        &clock,
        8,
        8,
        Duration::from_secs(5),
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "target-b").await;

    // 1. Grant updates:write ONLY on B -> A.
    let mut updates_only = AccessMap::none();
    updates_only.updates = AccessLevel::Write;
    let (st, _) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": updates_only })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let proxy_app = admin_proxy_app(Arc::clone(&rt_a), fixture_admin_user());

    for allowed_pkg in ["jellyfin", "jellyfin-ffmpeg8"] {
        let resp = proxy_app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/{a_link_id}/admin/packages/{allowed_pkg}/update"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "pkg={allowed_pkg}");
        let body: Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(body["updated"], allowed_pkg);
    }

    let denied_sonarr = proxy_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{a_link_id}/admin/packages/sonarr/update"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied_sonarr.status(), StatusCode::FORBIDDEN);
    let denied_body: Value =
        serde_json::from_slice(&to_bytes(denied_sonarr.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(denied_body["code"], "PEER_SCOPE_DENIED");

    // 2. Grant marketplace:write on B -> A allows updating non-Jellyfin packages.
    let mut marketplace_write = AccessMap::none();
    marketplace_write.marketplace = AccessLevel::Write;
    let (st2, _) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": marketplace_write })),
    )
    .await;
    assert_eq!(st2, StatusCode::OK);

    let allowed_sonarr = proxy_app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/{a_link_id}/admin/packages/sonarr/update"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed_sonarr.status(), StatusCode::OK);
    let allowed_body: Value =
        serde_json::from_slice(&to_bytes(allowed_sonarr.into_body(), 8192).await.unwrap()).unwrap();
    assert_eq!(allowed_body["updated"], "sonarr");

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}
