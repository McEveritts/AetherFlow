use super::auth::{hash_psk_sha256, verify_enrolled_cluster_psk};
use super::commands::truncate_diagnostic_utf8;
use super::grpc::{
    build_grpc_trailers, encode_grpc_data_frame, encode_proto_service_status,
    encode_proto_worker_metrics, pb_decode_bytes, pb_decode_string, pb_decode_varint,
    pb_encode_int32, pb_encode_int64, pb_encode_message_field, pb_encode_string, pb_skip_field,
    ClusterBody, ProtoWorkerMetrics,
};
use super::master::route_cluster_http_request;
use super::transport::load_root_cert_store;
use super::worker::{
    build_worker_heartbeat_payload, collect_worker_services, parse_confirmed_command_ids,
    poll_worker_service_inventory, register_worker_with_bounded_backoff, WorkerServiceInventory,
};
use super::*;
use axum::body::Bytes;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rusqlite::params;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

#[cfg(unix)]
#[test]
fn heartbeat_liveness_survives_unknown_and_pending_service_inventory() {
    use crate::inventory_regressions::{isolated, Fixture};
    let name =
        "cluster_daemon::tests::heartbeat_liveness_survives_unknown_and_pending_service_inventory";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    af_db::init_db().unwrap();
    assert_eq!(std::path::Path::new(&af_db::get_db_path()), fixture.journal);
    ensure_cluster_schema();
    let psk = "disposable-inventory-heartbeat-secret";
    env::set_var("CLUSTER_PSK", psk);
    let node = "node-inventory-regression";
    let reg = register_worker_node(&RegisterWorkerRequest {
        node_id: node.to_string(),
        hostname: "fixture".to_string(),
        address: "fixture:8080".to_string(),
        psk: psk.to_string(),
        version: "4.0.0".to_string(),
        system_info: None,
    })
    .unwrap();
    assert!(reg.accepted);
    let mut inventory = WorkerServiceInventory::default();
    let (unknown, _) =
        build_worker_heartbeat_payload(node, "fixture", "fixture:8080", psk, &inventory);
    assert!(serde_json::to_value(&unknown)
        .unwrap()
        .get("services")
        .is_none());
    assert!(process_worker_heartbeat(&unknown).unwrap().acknowledged);
    let cached = get_cached_worker_metrics(node).unwrap();
    assert!(cached["services"].is_null());
    assert_eq!(cached["services_status"], "unknown");
    let observed_at = Utc::now().timestamp() - 80;
    inventory.observe(collect_worker_services(), observed_at);
    let (healthy, _) =
        build_worker_heartbeat_payload(node, "fixture", "fixture:8080", psk, &inventory);
    process_worker_heartbeat(&healthy).unwrap();
    let previous_services = get_cached_worker_metrics(node).unwrap()["services"].clone();
    assert_eq!(previous_services.as_array().unwrap().len(), 4);
    let hidden = fixture.journal.with_extension("temporarily-hidden");
    std::fs::rename(&fixture.journal, &hidden).unwrap();
    inventory.observe(collect_worker_services(), observed_at + 5);
    std::fs::rename(&hidden, &fixture.journal).unwrap();
    assert_eq!(inventory.status(), "stale");
    assert_eq!(inventory.observed_at, Some(observed_at));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (release, blocked) = tokio::sync::oneshot::channel::<()>();
        let mut pending = Some(tokio::spawn(async move {
            let _ = blocked.await;
            Err(anyhow::anyhow!("simulated inventory failure after a blocked collector"))
        }));
        let (stale, _) = build_worker_heartbeat_payload(node, "fixture", "fixture:8080", psk, &inventory);
        for elapsed in (5..=80).step_by(5) {
            poll_worker_service_inventory(&mut pending, &mut inventory, observed_at + elapsed).await;
            assert!(pending.as_ref().is_some_and(|task| !task.is_finished()));
            {
                let conn = af_db::get_conn().unwrap();
                conn.execute("UPDATE cluster_nodes SET last_seen=datetime('now','-65 seconds'),last_heartbeat=datetime('now','-65 seconds') WHERE id=?1", params![node]).unwrap();
            }
            let mut request = stale.clone();
            request.timestamp = observed_at + elapsed;
            assert!(process_worker_heartbeat(&request).unwrap().acknowledged);
            assert_eq!(sweep_stale_cluster_nodes(), 0);
            let cached = get_cached_worker_metrics(node).unwrap();
            assert_eq!(cached["status"], "online");
            assert_eq!(cached["services"], previous_services);
            assert_eq!(cached["services_status"], "stale");
            assert_eq!(cached["services_observed_at"], observed_at);
        }
        release.send(()).unwrap();
        inventory.observe(pending.take().unwrap().await.unwrap(), observed_at + 80);
    });
    inventory.observe(collect_worker_services(), observed_at + 85);
    let (recovered, _) =
        build_worker_heartbeat_payload(node, "fixture", "fixture:8080", psk, &inventory);
    process_worker_heartbeat(&recovered).unwrap();
    assert_eq!(
        get_cached_worker_metrics(node).unwrap()["services_status"],
        "fresh"
    );
    assert_eq!(
        get_cached_worker_metrics(node).unwrap()["services_observed_at"],
        observed_at + 85
    );
    inventory.observe(Ok(Vec::new()), observed_at + 90);
    let (empty, _) =
        build_worker_heartbeat_payload(node, "fixture", "fixture:8080", psk, &inventory);
    process_worker_heartbeat(&empty).unwrap();
    assert_eq!(
        get_cached_worker_metrics(node).unwrap()["services"],
        serde_json::json!([])
    );
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("UPDATE cluster_nodes SET last_seen=datetime('now','-65 seconds'),last_heartbeat=datetime('now','-65 seconds') WHERE id=?1", params![node]).unwrap();
    }
    assert_eq!(sweep_stale_cluster_nodes(), 1);
    println!("16 fake 5-second heartbeats across 80 seconds kept actual disposable DB node online despite corrupt journal and pending inventory; retained services and original observation time; no-heartbeat negative control went offline");
}

#[test]
fn test_heartbeat_requires_psk_before_mutating_state() {
    let request = WorkerHeartbeatRequest {
        node_id: "node-audit-missing-psk".to_string(),
        ..Default::default()
    };
    let error = process_worker_heartbeat(&request).unwrap_err();
    assert_eq!(error.to_string(), "psk is required");
    assert!(get_cached_worker_metrics(&request.node_id).is_none());
}

#[test]
fn test_enrolled_psk_requires_a_trusted_matching_secret() {
    let candidate = "audit-secret-with-at-least-32-characters";
    assert!(verify_enrolled_cluster_psk(candidate, "").is_err());
    assert!(verify_enrolled_cluster_psk("", "").is_err());
    assert!(verify_enrolled_cluster_psk(candidate, &hash_psk_sha256("other-secret")).is_err());
    assert!(verify_enrolled_cluster_psk(candidate, &hash_psk_sha256(candidate)).is_ok());
    let stored_hash = hash_psk_sha256(candidate);
    assert!(verify_enrolled_cluster_psk(&stored_hash, &stored_hash).is_err());
    assert!(verify_enrolled_cluster_psk(candidate, candidate).is_ok());

    // Legacy Go cluster manager stored bcrypt ($2a$/$2b$) hashes in cluster_nodes.psk_hash
    let legacy_bcrypt = bcrypt::hash(candidate, 4).unwrap();
    let legacy_2a = legacy_bcrypt.replacen("$2b$", "$2a$", 1);
    assert!(verify_enrolled_cluster_psk(candidate, &legacy_bcrypt).is_ok());
    assert!(verify_enrolled_cluster_psk(candidate, &legacy_2a).is_ok());
    assert!(verify_enrolled_cluster_psk("wrong-secret-with-32-characters!!", &legacy_2a).is_err());
}

#[test]
fn test_constant_time_eq() {
    assert!(constant_time_eq(
        b"super-secret-psk-1234567890123456",
        b"super-secret-psk-1234567890123456"
    ));
    assert!(!constant_time_eq(
        b"super-secret-psk-1234567890123456",
        b"super-secret-psk-1234567890123457"
    ));
    assert!(!constant_time_eq(b"short", b"longer"));
}

#[test]
fn test_worker_metrics_cache_roundtrip() {
    let node_id = "node-test-worker-01";
    let payload = serde_json::json!({
        "node_id": node_id,
        "cpu_usage": 42.5,
        "ram_usage": 61.2,
        "disk_usage": 33.8,
    });
    cache_worker_metrics(node_id, payload.clone());
    let cached = get_cached_worker_metrics(node_id).expect("cached metrics should exist");
    assert_eq!(cached["cpu_usage"], serde_json::json!(42.5));
    remove_cached_worker_metrics(node_id);
    assert!(get_cached_worker_metrics(node_id).is_none());
}

#[cfg(unix)]
#[test]
fn mtls_default_loopback_and_legacy_grpc_wire_compatibility() {
    use crate::inventory_regressions::{isolated, Fixture};
    use std::process::Command as StdCommand;

    let name = "cluster_daemon::tests::mtls_default_loopback_and_legacy_grpc_wire_compatibility";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    af_db::init_db().unwrap();
    ensure_cluster_schema();

    // 1. Default master bind config MUST bind 127.0.0.1:50051 (never 0.0.0.0 by default)
    for k in [
        "CLUSTER_GRPC_HOST",
        "GRPC_HOST",
        "CLUSTER_GRPC_PORT",
        "GRPC_PORT",
        "CLUSTER_CA_CERT",
        "CLUSTER_SERVER_CERT",
        "CLUSTER_SERVER_KEY",
        "CLUSTER_CLIENT_CERT",
        "CLUSTER_CLIENT_KEY",
        "CLUSTER_ALLOW_INSECURE_LOOPBACK",
    ] {
        env::remove_var(k);
    }
    let default_bind = resolve_master_bind_config();
    assert_eq!(default_bind.host, "127.0.0.1");
    assert_eq!(default_bind.port, "50051");
    assert_eq!(default_bind.bind_addr, "127.0.0.1:50051");

    // 2. Master and Worker MUST fail closed when mTLS certs are unset (even on 127.0.0.1 without opt-in)
    assert!(load_master_transport_security("127.0.0.1").is_err());
    assert!(resolve_worker_transport("127.0.0.1:50051").is_err());
    assert!(resolve_worker_transport("10.0.0.5:50051").is_err());

    // Even with CLUSTER_ALLOW_INSECURE_LOOPBACK=true, non-loopback hosts MUST fail closed
    env::set_var("CLUSTER_ALLOW_INSECURE_LOOPBACK", "true");
    assert!(load_master_transport_security("0.0.0.0").is_err());
    assert!(resolve_worker_transport("10.0.0.5:50051").is_err());
    env::remove_var("CLUSTER_ALLOW_INSECURE_LOOPBACK");

    // 3. Mint disposable CA + server + client X.509 v3 certificates (SAN: IP:127.0.0.1, DNS:localhost)
    let cert_dir = fixture.root.join("certs");
    std::fs::create_dir_all(&cert_dir).unwrap();
    let ca_key = cert_dir.join("ca.key");
    let ca_crt = cert_dir.join("ca.crt");
    let srv_key = cert_dir.join("server.key");
    let srv_csr = cert_dir.join("server.csr");
    let srv_crt = cert_dir.join("server.crt");
    let srv_ext = cert_dir.join("server.ext");
    let cli_key = cert_dir.join("client.key");
    let cli_csr = cert_dir.join("client.csr");
    let cli_crt = cert_dir.join("client.crt");
    let cli_ext = cert_dir.join("client.ext");
    let cli2_key = cert_dir.join("client2.key");
    let cli2_csr = cert_dir.join("client2.csr");
    let cli2_crt = cert_dir.join("client2.crt");
    let admin_key = cert_dir.join("admin.key");
    let admin_csr = cert_dir.join("admin.csr");
    let admin_crt = cert_dir.join("admin.crt");

    std::fs::write(
        &srv_ext,
        "basicConstraints=CA:FALSE\nsubjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n",
    )
    .unwrap();
    std::fs::write(
        &cli_ext,
        "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n",
    )
    .unwrap();

    assert!(StdCommand::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            ca_key.to_str().unwrap(),
            "-out",
            ca_crt.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=AetherFlowClusterTestCA",
        ])
        .status()
        .unwrap()
        .success());

    for (key, csr, crt, ext, cn) in [
        (&srv_key, &srv_csr, &srv_crt, &srv_ext, "/CN=127.0.0.1"),
        (&cli_key, &cli_csr, &cli_crt, &cli_ext, "/CN=worker-node"),
        (
            &cli2_key,
            &cli2_csr,
            &cli2_crt,
            &cli_ext,
            "/CN=worker-node-2",
        ),
        (
            &admin_key,
            &admin_csr,
            &admin_crt,
            &cli_ext,
            "/CN=aetherflow-master",
        ),
    ] {
        assert!(StdCommand::new("openssl")
            .args([
                "req",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                csr.to_str().unwrap(),
                "-subj",
                cn,
            ])
            .status()
            .unwrap()
            .success());
        assert!(StdCommand::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                csr.to_str().unwrap(),
                "-CA",
                ca_crt.to_str().unwrap(),
                "-CAkey",
                ca_key.to_str().unwrap(),
                "-CAcreateserial",
                "-out",
                crt.to_str().unwrap(),
                "-days",
                "1",
                "-extfile",
                ext.to_str().unwrap(),
            ])
            .status()
            .unwrap()
            .success());
    }

    // Symlinked leaf, symlinked ancestor dir, and world-writable PEM files MUST be rejected
    let symlink_ca = cert_dir.join("symlink-ca.crt");
    std::os::unix::fs::symlink(&ca_crt, &symlink_ca).unwrap();
    assert!(build_master_mtls_acceptor(&symlink_ca, &srv_crt, &srv_key).is_err());

    let symlink_dir = fixture.root.join("certs-symlink-dir");
    std::os::unix::fs::symlink(&cert_dir, &symlink_dir).unwrap();
    assert!(
        build_master_mtls_acceptor(&symlink_dir.join("ca.crt"), &srv_crt, &srv_key).is_err(),
        "symlinked ancestor directory must be rejected by openat O_NOFOLLOW"
    );

    let ww_ca = cert_dir.join("world-writable-ca.crt");
    std::fs::copy(&ca_crt, &ww_ca).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ww_ca, std::fs::Permissions::from_mode(0o666)).unwrap();
    }
    assert!(
        build_master_mtls_acceptor(&ww_ca, &srv_crt, &srv_key).is_err(),
        "world-writable PEM file must be rejected"
    );

    let psk = "cluster-mtls-shared-secret-at-least-32-chars!!";
    env::set_var("CLUSTER_PSK", psk);
    env::set_var("CLUSTER_CA_CERT", &ca_crt);
    env::set_var("CLUSTER_SERVER_CERT", &srv_crt);
    env::set_var("CLUSTER_SERVER_KEY", &srv_key);
    env::set_var("CLUSTER_CLIENT_CERT", &cli_crt);
    env::set_var("CLUSTER_CLIENT_KEY", &cli_key);

    // Missing or unreadable CLUSTER_ADMIN_CLIENT_CERT MUST fail closed at startup
    env::set_var(
        "CLUSTER_ADMIN_CLIENT_CERT",
        cert_dir.join("missing-admin.crt"),
    );
    assert!(
        load_master_transport_security("127.0.0.1").is_err(),
        "invalid CLUSTER_ADMIN_CLIENT_CERT must fail closed at startup"
    );
    env::set_var("CLUSTER_ADMIN_CLIENT_CERT", &admin_crt);
    let pinned_sec = load_master_transport_security("127.0.0.1").unwrap();
    assert!(matches!(
        pinned_sec,
        MasterTransportSecurity::Mtls {
            admin_cert_sha256: Some(_),
            ..
        }
    ));
    env::remove_var("CLUSTER_ADMIN_CLIENT_CERT");

    // Plaintext http:// master addr MUST be rejected when worker mTLS certs are configured
    assert!(resolve_worker_transport("http://127.0.0.1:50051").is_err());

    let master_sec = load_master_transport_security("127.0.0.1").unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound_addr = listener.local_addr().unwrap();
        let server_sec = master_sec.clone();
        let server_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let sec = server_sec.clone();
                tokio::spawn(async move {
                    let _ = serve_cluster_master_connection(stream, sec).await;
                });
            }
        });

        // 4. Unauthenticated TLS client (no client cert) MUST be rejected by mTLS server
        {
            let root_store = load_root_cert_store(&ca_crt, "test_ca").unwrap();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let no_cert_cfg = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let no_cert_connector = TlsConnector::from(Arc::new(no_cert_cfg));
            let tcp = TcpStream::connect(bound_addr).await.unwrap();
            let sn = ServerName::try_from("127.0.0.1".to_string()).unwrap();
            if let Ok(mut tls_s) = no_cert_connector.connect(sn, tcp).await {
                // In TLS 1.3, post-ServerHello CertificateVerify rejection surfaces on first I/O
                let io_res = tls_s
                    .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                    .await;
                let mut buf = [0u8; 16];
                let read_res = tokio::io::AsyncReadExt::read(&mut tls_s, &mut buf).await;
                assert!(
                    io_res.is_err() || matches!(read_res, Err(_) | Ok(0)),
                    "TLS client without client certificate must be rejected"
                );
            }
        }

        // 5. Legacy Go gRPC worker simulation over TLS 1.3 + HTTP/2 (`cluster.ClusterService`)
        let (worker_ep, worker_sec) =
            resolve_worker_transport(&format!("127.0.0.1:{}", bound_addr.port())).unwrap();
        assert_eq!(worker_ep.scheme, "https");

        let connector = match &worker_sec {
            WorkerTransportSecurity::Mtls(c) => c.clone(),
            WorkerTransportSecurity::InsecureLoopback => panic!("expected mTLS connector"),
        };
        let tcp = TcpStream::connect(bound_addr).await.unwrap();
        let sn = ServerName::try_from("127.0.0.1".to_string()).unwrap();
        let tls_stream = connector.connect(sn, tcp).await.unwrap();
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(b"h2".as_slice())
        );

        let (mut h2_sender, h2_conn) = hyper::client::conn::http2::handshake(
            TokioExecutor::new(),
            TokioIo::new(tls_stream),
        )
        .await
        .unwrap();
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        // 5a. Unary gRPC RegisterWorker
        let mut sys_pb = Vec::new();
        pb_encode_string(&mut sys_pb, 1, "linux");
        pb_encode_string(&mut sys_pb, 2, "x86_64");
        pb_encode_int32(&mut sys_pb, 3, 8);
        pb_encode_int64(&mut sys_pb, 4, 16 * 1024 * 1024 * 1024);
        pb_encode_int64(&mut sys_pb, 5, 500 * 1024 * 1024 * 1024);

        let mut reg_pb = Vec::new();
        pb_encode_string(&mut reg_pb, 1, "legacy-go-worker");
        pb_encode_string(&mut reg_pb, 2, "10.10.0.12:8080");
        pb_encode_string(&mut reg_pb, 3, psk);
        pb_encode_string(&mut reg_pb, 4, "3.9.0");
        pb_encode_message_field(&mut reg_pb, 5, &sys_pb);

        let reg_req = Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}/cluster.ClusterService/RegisterWorker",
                worker_ep.authority
            ))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(
                &reg_pb,
            ))))
            .unwrap();
        let reg_resp = h2_sender.send_request(reg_req).await.unwrap();
        assert_eq!(reg_resp.status(), StatusCode::OK);
        let collected = reg_resp.into_body().collect().await.unwrap();
        let trailers = collected.trailers().cloned().unwrap_or_default();
        assert_eq!(
            trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
            Some("0")
        );
        let resp_bytes = collected.to_bytes();
        assert!(resp_bytes.len() > 5);
        let msg_len =
            u32::from_be_bytes([resp_bytes[1], resp_bytes[2], resp_bytes[3], resp_bytes[4]])
                as usize;
        let reg_slice = &resp_bytes[5..5 + msg_len];
        let mut pos = 0usize;
        let mut got_node_id = String::new();
        let mut got_accepted = false;
        while pos < reg_slice.len() {
            let tag = pb_decode_varint(reg_slice, &mut pos).unwrap();
            match ((tag >> 3) as u32, (tag & 7) as u8) {
                (1, 2) => got_node_id = pb_decode_string(reg_slice, &mut pos).unwrap(),
                (2, 0) => got_accepted = pb_decode_varint(reg_slice, &mut pos).unwrap() != 0,
                (_, wt) => pb_skip_field(reg_slice, &mut pos, wt).unwrap(),
            }
        }
        assert!(got_accepted);
        assert_eq!(got_node_id, "node-legacy-go-worker");

        // 5b. Enrolled worker cert MUST be rejected on ExecuteCommand BOTH without and WITH master CLUSTER_PSK
        let mut param_entry = Vec::new();
        pb_encode_string(&mut param_entry, 1, "service");
        pb_encode_string(&mut param_entry, 2, "radarr");
        let mut cmd_pb = Vec::new();
        pb_encode_string(&mut cmd_pb, 1, &got_node_id);
        pb_encode_string(&mut cmd_pb, 2, "cmd-99");
        pb_encode_string(&mut cmd_pb, 3, "restart_service");
        pb_encode_message_field(&mut cmd_pb, 4, &param_entry);

        let unauth_cmd_req = Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}/cluster.ClusterService/ExecuteCommand",
                worker_ep.authority
            ))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(
                &cmd_pb,
            ))))
            .unwrap();
        let unauth_cmd_resp = h2_sender.send_request(unauth_cmd_req).await.unwrap();
        let unauth_cmd_collected = unauth_cmd_resp.into_body().collect().await.unwrap();
        assert_eq!(
            unauth_cmd_collected
                .trailers()
                .and_then(|t| t.get("grpc-status"))
                .and_then(|v| v.to_str().ok()),
            Some("16"),
            "worker certificate without master CLUSTER_PSK must be rejected on ExecuteCommand"
        );

        let worker_psk_cmd_req = Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}/cluster.ClusterService/ExecuteCommand",
                worker_ep.authority
            ))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("x-cluster-psk", psk)
            .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(
                &cmd_pb,
            ))))
            .unwrap();
        let worker_psk_cmd_resp = h2_sender.send_request(worker_psk_cmd_req).await.unwrap();
        let worker_psk_cmd_collected = worker_psk_cmd_resp.into_body().collect().await.unwrap();
        assert_eq!(
            worker_psk_cmd_collected
                .trailers()
                .and_then(|t| t.get("grpc-status"))
                .and_then(|v| v.to_str().ok()),
            Some("16"),
            "enrolled worker certificate MUST be prohibited from ExecuteCommand even with shared CLUSTER_PSK"
        );

        // Dedicated control-plane certificate (CN=aetherflow-master, not enrolled as worker) queues ExecuteCommand
        let admin_connector =
            build_worker_mtls_connector(&ca_crt, &admin_crt, &admin_key).unwrap();
        let admin_tcp = TcpStream::connect(bound_addr).await.unwrap();
        let admin_tls = admin_connector
            .connect(
                ServerName::try_from("127.0.0.1".to_string()).unwrap(),
                admin_tcp,
            )
            .await
            .unwrap();
        let (mut admin_h2, admin_conn) = hyper::client::conn::http2::handshake(
            TokioExecutor::new(),
            TokioIo::new(admin_tls),
        )
        .await
        .unwrap();
        tokio::spawn(async move {
            let _ = admin_conn.await;
        });

        let cmd_req = Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}/cluster.ClusterService/ExecuteCommand",
                worker_ep.authority
            ))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(
                &cmd_pb,
            ))))
            .unwrap();
        let cmd_resp = admin_h2.send_request(cmd_req).await.unwrap();
        let cmd_collected = cmd_resp.into_body().collect().await.unwrap();
        assert_eq!(
            cmd_collected
                .trailers()
                .and_then(|t| t.get("grpc-status"))
                .and_then(|v| v.to_str().ok()),
            Some("0")
        );

        // 5c. Bidirectional gRPC Heartbeat stream WITHOUT PSK in HeartbeatPing (matching legacy Go client.go)
        let (ping_tx, ping_rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
        let hb_stream_req = Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}/cluster.ClusterService/Heartbeat",
                worker_ep.authority
            ))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(ClusterBody::Grpc(ping_rx))
            .unwrap();
        let hb_stream_resp = h2_sender.send_request(hb_stream_req).await.unwrap();
        assert_eq!(hb_stream_resp.status(), StatusCode::OK);
        let mut hb_incoming = hb_stream_resp.into_body();

        let metrics_pb = encode_proto_worker_metrics(&ProtoWorkerMetrics {
            cpu_usage: 31.5,
            memory_used_gb: 8.0,
            memory_total_gb: 16.0,
            disk_used_gb: 125.0,
            disk_total_gb: 500.0,
            network_rx_speed: "12.4 MB/s".to_string(),
            network_tx_speed: "3.1 MB/s".to_string(),
            uptime: "4d 2h".to_string(),
            load_average: vec![0.42, 0.38, 0.31],
        });
        let svc_pb = encode_proto_service_status(&WorkerService {
            name: "radarr".to_string(),
            status: "running".to_string(),
            uptime: "4d".to_string(),
            managed_by: "systemd".to_string(),
        });
        let mut ping_pb = Vec::new();
        pb_encode_string(&mut ping_pb, 1, &got_node_id);
        pb_encode_int64(&mut ping_pb, 2, 1_700_000_123);
        pb_encode_message_field(&mut ping_pb, 3, &metrics_pb);
        pb_encode_message_field(&mut ping_pb, 4, &svc_pb);

        ping_tx
            .send(Ok(Frame::data(encode_grpc_data_frame(&ping_pb))))
            .await
            .unwrap();

        // Receive streamed HeartbeatPong before closing client stream
        let first_pong_frame =
            tokio::time::timeout(Duration::from_secs(5), hb_incoming.frame())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        let pong_data = first_pong_frame.into_data().unwrap();
        assert!(pong_data.len() > 5);
        let pong_len =
            u32::from_be_bytes([pong_data[1], pong_data[2], pong_data[3], pong_data[4]])
                as usize;
        let pong_slice = &pong_data[5..5 + pong_len];
        let mut ppos = 0usize;
        let mut pong_ack = false;
        let mut pong_has_cmd = false;
        while ppos < pong_slice.len() {
            let tag = pb_decode_varint(pong_slice, &mut ppos).unwrap();
            match ((tag >> 3) as u32, (tag & 7) as u8) {
                (2, 0) => pong_ack = pb_decode_varint(pong_slice, &mut ppos).unwrap() != 0,
                (3, 2) => {
                    let cmd_bytes = pb_decode_bytes(pong_slice, &mut ppos).unwrap();
                    assert!(!cmd_bytes.is_empty());
                    pong_has_cmd = true;
                }
                (_, wt) => pb_skip_field(pong_slice, &mut ppos, wt).unwrap(),
            }
        }
        assert!(pong_ack);
        assert!(
            pong_has_cmd,
            "queued command must be delivered on HeartbeatPong"
        );

        drop(ping_tx);
        let remaining = hb_incoming.collect().await.unwrap();
        assert_eq!(
            remaining
                .trailers()
                .and_then(|t| t.get("grpc-status"))
                .and_then(|v| v.to_str().ok()),
            Some("0")
        );

        // Verify GetMetrics rejects enrolled worker cert (both without and WITH master PSK), then succeeds with admin cert
        let mut gm_pb = Vec::new();
        pb_encode_string(&mut gm_pb, 1, &got_node_id);
        let unauth_gm_req = Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}/cluster.ClusterService/GetMetrics",
                worker_ep.authority
            ))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(&gm_pb))))
            .unwrap();
        let unauth_gm_resp = h2_sender.send_request(unauth_gm_req).await.unwrap();
        let unauth_gm_collected = unauth_gm_resp.into_body().collect().await.unwrap();
        assert_eq!(
            unauth_gm_collected
                .trailers()
                .and_then(|t| t.get("grpc-status"))
                .and_then(|v| v.to_str().ok()),
            Some("16"),
            "worker certificate without master CLUSTER_PSK must be rejected on GetMetrics"
        );

        let worker_psk_gm_req = Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}/cluster.ClusterService/GetMetrics",
                worker_ep.authority
            ))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("x-cluster-psk", psk)
            .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(&gm_pb))))
            .unwrap();
        let worker_psk_gm_resp = h2_sender.send_request(worker_psk_gm_req).await.unwrap();
        let worker_psk_gm_collected = worker_psk_gm_resp.into_body().collect().await.unwrap();
        assert_eq!(
            worker_psk_gm_collected
                .trailers()
                .and_then(|t| t.get("grpc-status"))
                .and_then(|v| v.to_str().ok()),
            Some("16"),
            "enrolled worker certificate MUST be prohibited from GetMetrics even with shared CLUSTER_PSK"
        );

        // Dedicated control-plane certificate (CN=aetherflow-master) succeeds on GetMetrics WITHOUT PSK header
        let admin_gm_req = Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}/cluster.ClusterService/GetMetrics",
                worker_ep.authority
            ))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(ClusterBody::Json(Full::new(encode_grpc_data_frame(&gm_pb))))
            .unwrap();
        let admin_gm_resp = admin_h2.send_request(admin_gm_req).await.unwrap();
        let admin_gm_collected = admin_gm_resp.into_body().collect().await.unwrap();
        assert_eq!(
            admin_gm_collected
                .trailers()
                .and_then(|t| t.get("grpc-status"))
                .and_then(|v| v.to_str().ok()),
            Some("0")
        );
        assert!(admin_gm_collected.to_bytes().len() > 15);

        // 6. Single-use enrollment token + second worker cert (`cli2_crt`) + cross-node spoofing rejection
        let worker2_sec = WorkerTransportSecurity::Mtls(
            build_worker_mtls_connector(&ca_crt, &cli2_crt, &cli2_key).unwrap(),
        );
        let enrollment_tok = issue_cluster_enrollment_token().unwrap();
        assert_eq!(enrollment_tok.len(), 64);

        let rust_reg = RegisterWorkerRequest {
            node_id: "node-rust-mtls-worker".to_string(),
            hostname: "rust-mtls-worker".to_string(),
            address: "10.10.0.13:8080".to_string(),
            psk: String::new(),
            version: "4.0.0".to_string(),
            system_info: None,
        };
        let rust_reg_json = serde_json::to_vec(&rust_reg).unwrap();
        assert!(!String::from_utf8_lossy(&rust_reg_json).contains(&enrollment_tok));
        let (st, body) = send_worker_json_post(
            &worker_ep,
            &worker2_sec,
            "/cluster/v1/register",
            &enrollment_tok,
            rust_reg_json,
        )
        .await
        .unwrap();
        assert_eq!(st, StatusCode::OK);
        let parsed_reg: RegisterWorkerResponse = serde_json::from_slice(&body).unwrap();
        assert!(parsed_reg.accepted);
        assert_eq!(parsed_reg.node_id, "node-rust-mtls-worker");

        // Replay of consumed single-use enrollment token for a different node MUST fail closed (401)
        let replay_reg = RegisterWorkerRequest {
            node_id: "node-rogue-replay".to_string(),
            hostname: "rogue-replay".to_string(),
            address: "10.10.0.99:8080".to_string(),
            psk: String::new(),
            version: "4.0.0".to_string(),
            system_info: None,
        };
        let (replay_st, _) = send_worker_json_post(
            &worker_ep,
            &worker2_sec,
            "/cluster/v1/register",
            &enrollment_tok,
            serde_json::to_vec(&replay_reg).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            replay_st,
            StatusCode::UNAUTHORIZED,
            "consumed single-use enrollment token must reject replay by another node"
        );

        // Worker-2 (`cli2_crt`) attempting to overwrite already-enrolled `node-legacy-go-worker` (`cli_crt`)
        // MUST fail closed (401) BOTH with master PSK and with a fresh unconsumed enrollment token!
        let original_pin: String = af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT peer_cert_sha256 FROM cluster_nodes WHERE id = ?1",
                params![got_node_id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!original_pin.is_empty());

        let hijack_reg = RegisterWorkerRequest {
            node_id: got_node_id.clone(),
            hostname: "legacy-go-worker".to_string(),
            address: "10.10.0.99:8080".to_string(),
            psk: String::new(),
            version: "4.0.0".to_string(),
            system_info: None,
        };
        let (hijack_psk_st, _) = send_worker_json_post(
            &worker_ep,
            &worker2_sec,
            "/cluster/v1/register",
            psk,
            serde_json::to_vec(&hijack_reg).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            hijack_psk_st,
            StatusCode::UNAUTHORIZED,
            "mismatched peer certificate must not overwrite enrolled worker pin via shared CLUSTER_PSK"
        );

        let fresh_tok = issue_cluster_enrollment_token().unwrap();
        let (hijack_tok_st, _) = send_worker_json_post(
            &worker_ep,
            &worker2_sec,
            "/cluster/v1/register",
            &fresh_tok,
            serde_json::to_vec(&hijack_reg).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            hijack_tok_st,
            StatusCode::UNAUTHORIZED,
            "fresh single-use enrollment token must not overwrite an already-enrolled node"
        );
        let pin_after: String = af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT peer_cert_sha256 FROM cluster_nodes WHERE id = ?1",
                params![got_node_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pin_after, original_pin);
        let fresh_consumed: Option<String> = af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT consumed_by FROM cluster_enrollment_tokens WHERE token_hash = ?1",
                params![hash_psk_sha256(&fresh_tok)],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            fresh_consumed.is_none(),
            "rejected re-enrollment attempt must not consume unrelated enrollment token"
        );

        // Enrolled worker-2 can heartbeat for itself using its enrolled token...
        let (mut rust_hb, _) = build_worker_heartbeat_payload(
            "node-rust-mtls-worker",
            "rust-mtls-worker",
            "10.10.0.13:8080",
            "",
            &WorkerServiceInventory::default(),
        );
        rust_hb.psk.clear();
        let rust_hb_json = serde_json::to_vec(&rust_hb).unwrap();
        let (hb_st, hb_body) = send_worker_json_post(
            &worker_ep,
            &worker2_sec,
            "/cluster/v1/heartbeat",
            &enrollment_tok,
            rust_hb_json,
        )
        .await
        .unwrap();
        assert_eq!(hb_st, StatusCode::OK);
        let parsed_hb: WorkerHeartbeatResponse = serde_json::from_slice(&hb_body).unwrap();
        assert!(parsed_hb.acknowledged);

        // ...but worker-2 (`cli2_crt`) attempting to spoof `node-legacy-go-worker` (`cli_crt`) MUST be rejected EVEN with master PSK!
        let mut spoof_hb = rust_hb.clone();
        spoof_hb.node_id = got_node_id.clone();
        let (spoof_st, _) = send_worker_json_post(
            &worker_ep,
            &worker2_sec,
            "/cluster/v1/heartbeat",
            psk,
            serde_json::to_vec(&spoof_hb).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            spoof_st,
            StatusCode::UNAUTHORIZED,
            "peer certificate pinning must block cross-worker heartbeat spoofing"
        );

        server_task.abort();
    });
}

#[cfg(unix)]
#[test]
fn durable_sqlite_command_queue_leasing_ack_and_worker_backoff_registration() {
    let name =
        "cluster_daemon::tests::durable_sqlite_command_queue_leasing_ack_and_worker_backoff_registration";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let root = env::temp_dir().join(format!("af-cluster-p3-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let db_path = root.join("cluster.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    let master_psk = "master-secret-psk-1234567890-secure!!";
    env::set_var("CLUSTER_PSK", master_psk);
    env::set_var("CLUSTER_REGISTER_INITIAL_BACKOFF_MS", "15");
    env::set_var("CLUSTER_REGISTER_MAX_BACKOFF_MS", "40");
    af_db::init_db().unwrap();
    ensure_cluster_schema();

    let reg = register_worker_node(&RegisterWorkerRequest {
        node_id: "node-alpha".to_string(),
        hostname: "alpha".to_string(),
        address: "127.0.0.1:8080".to_string(),
        psk: master_psk.to_string(),
        version: "4.0.0".to_string(),
        system_info: None,
    })
    .unwrap();
    assert!(reg.accepted);

    // 1. Enqueue durable command in SQLite
    let queued = enqueue_cluster_command("node-alpha", "restart_service", "sonarr").unwrap();
    assert_eq!(queued.status, "queued");

    // First lease succeeds; second lease before lease expiry returns None
    let first_lease = lease_next_worker_command("node-alpha", 1000, 30).unwrap();
    assert_eq!(first_lease.id, queued.id);
    assert_eq!(first_lease.lease_generation, 1);
    assert_eq!(first_lease.cmd_type, "restart_service");
    assert_eq!(
        first_lease.params.get("service").map(String::as_str),
        Some("sonarr")
    );
    assert!(lease_next_worker_command("node-alpha", 1015, 30).is_none());

    // After lease expires (`now >= 1030`), command is re-leased cleanly with incremented generation
    let released = lease_next_worker_command("node-alpha", 1031, 30).unwrap();
    assert_eq!(released.id, queued.id);
    assert_eq!(released.lease_generation, 2);

    // Delayed stale ack from expired lease_generation=1 MUST NOT overwrite lease_generation=2!
    assert!(!acknowledge_worker_command(
        "node-alpha",
        &WorkerCommandAck {
            id: queued.id.clone(),
            status: "failed".to_string(),
            result_message: Some("stale expired worker attempt".to_string()),
            lease_generation: Some(1),
        }
    )
    .unwrap());

    // Heartbeat carrying `command_acks` for current lease_generation=2 marks command terminal (`executed`) and returns confirmed_command_ids
    let hb_resp = process_worker_heartbeat(&WorkerHeartbeatRequest {
        node_id: "node-alpha".to_string(),
        hostname: "alpha".to_string(),
        address: "127.0.0.1:8080".to_string(),
        psk: master_psk.to_string(),
        timestamp: 1035,
        command_acks: vec![WorkerCommandAck {
            id: queued.id.clone(),
            status: "executed".to_string(),
            result_message: Some("restart sonarr succeeded".to_string()),
            lease_generation: Some(2),
        }],
        ..Default::default()
    })
    .unwrap();
    assert!(hb_resp.acknowledged);
    assert_eq!(hb_resp.confirmed_command_ids, vec![queued.id.clone()]);
    assert!(hb_resp.command.is_none());

    let listed = list_cluster_commands(Some("node-alpha"), 10).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, "executed");
    assert_eq!(
        listed[0].result_message.as_deref(),
        Some("restart sonarr succeeded")
    );

    // 2. Worker registration retries bounded exponential backoff and persists 0600 O_NOFOLLOW state
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_srv = Arc::clone(&attempts);

        let srv = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let n = attempts_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    let (st, body) = if n < 2 {
                        (
                            "503 Service Unavailable",
                            r#"{"accepted":false,"message":"starting"}"#,
                        )
                    } else {
                        (
                            "200 OK",
                            r#"{"node_id":"node-backed-off-ok","accepted":true,"message":"enrolled"}"#,
                        )
                    };
                    let resp = format!(
                        "HTTP/1.1 {st}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });

        let state_file = root.join("state/worker_reg.json");
        let ep = WorkerTargetEndpoint {
            scheme: "http".to_string(),
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            authority: addr.to_string(),
        };
        let assigned = register_worker_with_bounded_backoff(
            &ep,
            &WorkerTransportSecurity::InsecureLoopback,
            master_psk,
            "node-initial",
            "worker-host",
            "127.0.0.1:8080",
            &state_file,
        )
        .await;
        assert_eq!(assigned, "node-backed-off-ok");
        assert!(attempts.load(Ordering::SeqCst) >= 3);

        let mode = std::fs::symlink_metadata(&state_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let loaded = load_worker_registration_state_nofollow(&state_file).unwrap();
        assert_eq!(loaded.node_id, "node-backed-off-ok");

        // Symlink state target must be rejected
        let sym_path = root.join("state/symlink_reg.json");
        std::os::unix::fs::symlink(&state_file, &sym_path).unwrap();
        assert!(persist_worker_registration_state_atomic(&sym_path, &loaded).is_err());
        assert!(load_worker_registration_state_nofollow(&sym_path).is_none());

        srv.abort();
    });

    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn utf8_truncation_deleted_node_guard_verb_allowlist_and_ack_outbox_retention() {
    let name = "cluster_daemon::tests::utf8_truncation_deleted_node_guard_verb_allowlist_and_ack_outbox_retention";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    // 1. UTF-8 boundary truncation at byte 509 (512 - 3) & byte 1024 across HTTP JSON + gRPC trailers
    // Construct multibyte strings where bytes 509 and 1024 land directly inside a 3-byte '☃' (E2 98 83) or 4-byte '🦀' (F0 9F A6 80)!
    let msg_509 = format!("{}🦀{}", "a".repeat(507), "z".repeat(40)); // '🦀' spans 507..511 (509 is mid-char!)
    let diag_512 = truncate_diagnostic_utf8(&msg_509, 512);
    assert!(diag_512.len() <= 512);
    assert_eq!(diag_512, format!("{}...", "a".repeat(507)));

    let trailers =
        build_grpc_trailers(16, Some(&format!("{}☃{}", "b".repeat(508), "x".repeat(20))));
    let grpc_msg = trailers.get("grpc-message").unwrap().to_str().unwrap();
    assert!(grpc_msg.len() <= 512);
    assert!(grpc_msg.ends_with("..."));

    let msg_1024 = format!("{}🦀{}", "c".repeat(1022), "y".repeat(30)); // '🦀' spans 1022..1026 (1024 is mid-char!)
    let trunc_1024 = truncate_utf8(&msg_1024, 1024);
    assert_eq!(trunc_1024.len(), 1022);

    let root = env::temp_dir().join(format!("af-cluster-p4-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let db_path = root.join("cluster_p4.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    let psk = "p4-cluster-master-psk-at-least-32-chars!!";
    env::set_var("CLUSTER_PSK", psk);
    af_db::init_db().unwrap();
    ensure_cluster_schema();

    // 2. Deleted-node heartbeat guard: unenrolled node rejected; enrolled then deleted node rejected (HTTP 403) without resurrection
    assert!(process_worker_heartbeat(&WorkerHeartbeatRequest {
        node_id: "node-never-enrolled".to_string(),
        hostname: "ghost".to_string(),
        address: "127.0.0.1:8080".to_string(),
        psk: psk.to_string(),
        timestamp: 2000,
        ..Default::default()
    })
    .is_err());

    let reg = register_worker_node(&RegisterWorkerRequest {
        node_id: "node-ephemeral".to_string(),
        hostname: "ephemeral".to_string(),
        address: "127.0.0.1:8081".to_string(),
        psk: psk.to_string(),
        version: "4.0.0".to_string(),
        system_info: None,
    })
    .unwrap();
    assert!(reg.accepted);

    // Admin deletes node from cluster_nodes
    af_db::get_conn()
        .unwrap()
        .execute("DELETE FROM cluster_nodes WHERE id = 'node-ephemeral'", [])
        .unwrap();
    remove_cached_worker_metrics("node-ephemeral");

    let hb_body = serde_json::to_vec(&WorkerHeartbeatRequest {
        node_id: "node-ephemeral".to_string(),
        hostname: "ephemeral".to_string(),
        address: "127.0.0.1:8081".to_string(),
        psk: String::new(),
        timestamp: 2005,
        ..Default::default()
    })
    .unwrap();
    let (hb_code, _, hb_json) = route_cluster_http_request(
        "POST",
        "/cluster/v1/heartbeat",
        "/cluster/v1/heartbeat",
        psk,
        &hb_body,
        &PeerTransportAuth::InsecureLoopback,
    );
    assert_eq!(
        hb_code, 403,
        "deleted worker heartbeat must be rejected with 403"
    );
    assert_eq!(hb_json["acknowledged"], false);
    let resurrected: i64 = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM cluster_nodes WHERE id = 'node-ephemeral'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        resurrected, 0,
        "deleted worker must NEVER be re-inserted on heartbeat"
    );

    // 3. Command type allowlist: systemctl, package, ping, restart_service allowed; arbitrary verbs rejected (HTTP + gRPC)
    let reg_live = register_worker_node(&RegisterWorkerRequest {
        node_id: "node-live".to_string(),
        hostname: "live".to_string(),
        address: "127.0.0.1:8082".to_string(),
        psk: psk.to_string(),
        version: "4.0.0".to_string(),
        system_info: None,
    })
    .unwrap();
    assert!(reg_live.accepted);

    assert!(enqueue_cluster_command("node-live", "systemctl", "radarr").is_ok());
    assert!(enqueue_cluster_command("node-live", "package", "sonarr").is_ok());
    assert!(enqueue_cluster_command("node-live", "ping", "").is_ok());
    assert!(enqueue_cluster_command("node-live", "exec_shell", "bash").is_err());
    assert!(!queue_worker_command(
        "node-live",
        PendingWorkerCommand {
            id: "bad-1".to_string(),
            cmd_type: "arbitrary_exec".to_string(),
            params: HashMap::from([("target".to_string(), "sh".to_string())]),
            lease_generation: 0,
        }
    ));

    // Acknowledge with multibyte 1024-byte UTF-8 boundary diagnostic
    let _ping_rec = enqueue_cluster_command("node-live", "ping", "health").unwrap();
    let leased_ping = lease_next_worker_command("node-live", 3000, 30).unwrap();
    let ack_ok = WorkerCommandAck {
        id: leased_ping.id.clone(),
        status: "executed".to_string(),
        result_message: Some(msg_1024.clone()),
        lease_generation: Some(leased_ping.lease_generation),
    };
    let ack_req_bytes = serde_json::to_vec(&WorkerCommandAckRequest {
        node_id: "node-live".to_string(),
        psk: String::new(),
        acks: vec![ack_ok.clone()],
    })
    .unwrap();
    let (ack_code, _, ack_json) = route_cluster_http_request(
        "POST",
        "/cluster/v1/commands/ack",
        "/cluster/v1/commands/ack",
        psk,
        &ack_req_bytes,
        &PeerTransportAuth::InsecureLoopback,
    );
    assert_eq!(ack_code, 200);
    assert_eq!(
        ack_json["confirmed_command_ids"],
        serde_json::json!([leased_ping.id])
    );

    // 4. Persistent 0600 ack outbox retains unconfirmed acks on HTTP 503 DB failure and evicts ONLY when confirmed
    let outbox_file = root.join("state/worker_ack_outbox.json");
    let mut pending = Vec::new();
    let unconfirmed = WorkerCommandAck {
        id: "cmd-unconfirmed-99".to_string(),
        status: "executed".to_string(),
        result_message: Some("ok".to_string()),
        lease_generation: Some(1),
    };
    enqueue_worker_ack_outbox_entry(&outbox_file, &mut pending, unconfirmed.clone()).unwrap();
    let outbox_mode = std::fs::symlink_metadata(&outbox_file)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(outbox_mode, 0o600);
    assert_eq!(
        load_worker_ack_outbox_nofollow(&outbox_file),
        vec![unconfirmed.clone()]
    );

    // Simulate DB failure on cluster_commands update via SQLite trigger -> /cluster/v1/commands/ack MUST return 503
    let _failing_cmd = enqueue_cluster_command("node-live", "ping", "db-fail").unwrap();
    let leased_fail = lease_next_worker_command("node-live", 3100, 30).unwrap();
    af_db::get_conn()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_cluster_cmd_ack BEFORE UPDATE ON cluster_commands BEGIN SELECT RAISE(ABORT, 'simulated sqlite busy'); END;",
        )
        .unwrap();
    let fail_ack_bytes = serde_json::to_vec(&WorkerCommandAckRequest {
        node_id: "node-live".to_string(),
        psk: String::new(),
        acks: vec![WorkerCommandAck {
            id: leased_fail.id.clone(),
            status: "executed".to_string(),
            result_message: Some("pong".to_string()),
            lease_generation: Some(leased_fail.lease_generation),
        }],
    })
    .unwrap();
    let (fail_code, _, fail_json) = route_cluster_http_request(
        "POST",
        "/cluster/v1/commands/ack",
        "/cluster/v1/commands/ack",
        psk,
        &fail_ack_bytes,
        &PeerTransportAuth::InsecureLoopback,
    );
    assert_eq!(
        fail_code, 503,
        "DB persistence error on /commands/ack must return 503"
    );
    assert_eq!(fail_json["acknowledged"], false);
    assert_eq!(
        parse_confirmed_command_ids(&serde_json::to_vec(&fail_json).unwrap()),
        Vec::<String>::new()
    );

    // Outbox retains entry until confirmed_command_ids explicitly names it
    evict_confirmed_acks_from_outbox(&outbox_file, &mut pending, &[]).unwrap();
    assert_eq!(load_worker_ack_outbox_nofollow(&outbox_file).len(), 1);
    evict_confirmed_acks_from_outbox(
        &outbox_file,
        &mut pending,
        &["cmd-unconfirmed-99".to_string()],
    )
    .unwrap();
    assert!(load_worker_ack_outbox_nofollow(&outbox_file).is_empty());

    let _ = std::fs::remove_dir_all(&root);
}
