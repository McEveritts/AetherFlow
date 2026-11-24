use super::{MockRunnerTransport, TempTestDir, ENV_TEST_LOCK};
use crate::*;
use af_models::{
    PackageRunnerRequest, QuotaRunnerRequest, RunnerResponse, SandboxRunnerRequest,
    SelfUpdateRequest, SystemctlRequest,
};
use af_runner::{
    HostsUpdateRequest, PeerMountStateResponse, PeerSentinelProbeResponse, PeerStatusPeer,
    PeerStatusResponse,
};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

const TEST_PUBKEY: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
const TEST_PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const TEST_INBOUND_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_OUTGOING_HASH: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const TEST_CREDENTIAL_ID: &str = "cred-secret-received-grant-991827";

#[derive(Default, Clone)]
struct MockClusterTransport {
    peer_status: Arc<Mutex<Option<CliResult<PeerStatusResponse>>>>,
    mount_states: Arc<Mutex<HashMap<String, CliResult<PeerMountStateResponse>>>>,
    sentinel_probes: Arc<Mutex<HashMap<String, CliResult<PeerSentinelProbeResponse>>>>,
    network_calls: Arc<Mutex<usize>>,
    mount_status_calls: Arc<Mutex<Vec<String>>>,
    sentinel_probe_calls: Arc<Mutex<Vec<String>>>,
}

impl RunnerClientTransport for MockClusterTransport {
    fn check_health(&self) -> CliResult<RunnerResponse> {
        Ok(RunnerResponse {
            success: true,
            output: "ready".to_string(),
            error: String::new(),
        })
    }

    fn execute_package(&self, _req: &PackageRunnerRequest) -> CliResult<PackageExecutionReceipt> {
        unreachable!("unused in cluster tests")
    }

    fn cancel_package(&self, _req: &SandboxRunnerRequest) -> CliResult<RunnerResponse> {
        unreachable!("unused in cluster tests")
    }

    fn execute_systemctl(&self, _req: &SystemctlRequest) -> CliResult<RunnerResponse> {
        unreachable!("unused in cluster tests")
    }

    fn execute_quota(&self, _req: &QuotaRunnerRequest) -> CliResult<RunnerResponse> {
        unreachable!("unused in cluster tests")
    }

    fn execute_sandbox(&self, _req: &SandboxRunnerRequest) -> CliResult<RunnerResponse> {
        unreachable!("unused in cluster tests")
    }

    fn execute_self_update(&self, _req: &SelfUpdateRequest) -> CliResult<RunnerResponse> {
        unreachable!("unused in cluster tests")
    }

    fn execute_hosts(&self, _req: &HostsUpdateRequest) -> CliResult<RunnerResponse> {
        unreachable!("unused in cluster tests")
    }

    fn query_peer_network_status(&self) -> CliResult<PeerStatusResponse> {
        *self.network_calls.lock().unwrap() += 1;
        match self.peer_status.lock().unwrap().as_ref() {
            Some(Ok(resp)) => Ok(resp.clone()),
            Some(Err(err)) => Err(CliError::RunnerIpc {
                endpoint: "/v1/peer-network".to_string(),
                message: err.to_string(),
            }),
            None => Err(CliError::RunnerIpc {
                endpoint: "/v1/peer-network".to_string(),
                message: "runner socket connection refused".to_string(),
            }),
        }
    }

    fn query_peer_mount_status(&self, mount_path: &str) -> CliResult<PeerMountStateResponse> {
        self.mount_status_calls
            .lock()
            .unwrap()
            .push(mount_path.to_string());
        match self.mount_states.lock().unwrap().get(mount_path) {
            Some(Ok(resp)) => Ok(resp.clone()),
            Some(Err(err)) => Err(CliError::RunnerIpc {
                endpoint: "/v1/peer-storage".to_string(),
                message: err.to_string(),
            }),
            None => Err(CliError::RunnerIpc {
                endpoint: "/v1/peer-storage".to_string(),
                message: format!("runner offline for mount status {mount_path}"),
            }),
        }
    }

    fn probe_peer_mount_sentinel(
        &self,
        mount_path: &str,
        _timeout_ms: Option<u64>,
    ) -> CliResult<PeerSentinelProbeResponse> {
        self.sentinel_probe_calls
            .lock()
            .unwrap()
            .push(mount_path.to_string());
        match self.sentinel_probes.lock().unwrap().get(mount_path) {
            Some(Ok(resp)) => Ok(resp.clone()),
            Some(Err(err)) => Err(CliError::RunnerIpc {
                endpoint: "/v1/peer-storage".to_string(),
                message: err.to_string(),
            }),
            None => Err(CliError::RunnerIpc {
                endpoint: "/v1/peer-storage".to_string(),
                message: format!("runner offline for sentinel probe {mount_path}"),
            }),
        }
    }
}

fn create_cluster_test_db(db_path: &Path) {
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let conn = Connection::open(db_path).unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE peer_links (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            wg_pubkey TEXT NOT NULL UNIQUE,
            tunnel_ip TEXT NOT NULL UNIQUE,
            endpoint TEXT NOT NULL,
            wg_port INTEGER NOT NULL,
            state TEXT NOT NULL,
            peer_version TEXT,
            peer_protocol INTEGER,
            capabilities TEXT,
            rtt_ms REAL,
            last_ok_at TEXT,
            last_error TEXT,
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            inbound_token_hash TEXT,
            pending_attempt_id TEXT,
            pending_expires_at INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE peer_grants (
            id TEXT PRIMARY KEY,
            link_id TEXT NOT NULL,
            run_as_user_id INTEGER NOT NULL,
            access TEXT NOT NULL,
            token_hash TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE TABLE peer_received_grants (
            link_id TEXT PRIMARY KEY,
            grant_id TEXT NOT NULL,
            run_as_user_id INTEGER NOT NULL,
            access TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            generation INTEGER NOT NULL DEFAULT 0,
            revoked_at TEXT,
            credential_id TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE peer_exports (
            id TEXT PRIMARY KEY,
            link_id TEXT NOT NULL,
            path TEXT NOT NULL,
            writable INTEGER NOT NULL DEFAULT 0,
            squash_uid INTEGER,
            squash_gid INTEGER,
            created_at TEXT NOT NULL
        );
        CREATE TABLE peer_mounts (
            id TEXT PRIMARY KEY,
            link_id TEXT NOT NULL,
            remote_path TEXT NOT NULL,
            mount_path TEXT NOT NULL UNIQUE,
            unit_name TEXT NOT NULL,
            writable INTEGER NOT NULL DEFAULT 0,
            purpose TEXT NOT NULL,
            state TEXT NOT NULL,
            last_error TEXT
        );
        CREATE TABLE transcode_workers (
            link_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            weight INTEGER NOT NULL DEFAULT 1,
            max_jobs INTEGER NOT NULL DEFAULT 2,
            ffmpeg_version TEXT,
            encoders TEXT,
            render_node TEXT,
            parity_ok INTEGER NOT NULL DEFAULT 0,
            parity_error TEXT
        );
        CREATE TABLE transcode_jobs (
            id TEXT PRIMARY KEY,
            link_id TEXT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            exit_code INTEGER,
            request_id TEXT,
            ran_locally INTEGER NOT NULL
        );
        CREATE TABLE admin_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL DEFAULT '',
            target_id TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .unwrap();

    let contaminated_link_err = format!(
        "transient handshake retry X-AF-Link-Token: raw-link-tok-9999 PrivateKey={TEST_PRIVATE_KEY} afpair1:secretpairpayload123"
    );

    conn.execute(
        "INSERT INTO peer_links (
            id, name, wg_pubkey, tunnel_ip, endpoint, wg_port, state,
            peer_version, peer_protocol, capabilities, rtt_ms, last_ok_at, last_error,
            consecutive_failures, inbound_token_hash, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            "link-media-2",
            "media-2",
            TEST_PUBKEY,
            "10.231.0.2",
            "203.0.113.20",
            51821,
            "online",
            "4.0.0",
            1,
            r#"["storage","transcode","proxy"]"#,
            4.25f64,
            "2026-11-24T04:00:00Z",
            contaminated_link_err,
            1,
            TEST_INBOUND_HASH,
            "2026-11-20T01:00:00Z",
            "2026-11-24T04:00:00Z"
        ],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO peer_links (
            id, name, wg_pubkey, tunnel_ip, endpoint, wg_port, state,
            created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            "link-other",
            "other-peer",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
            "10.231.0.9",
            "203.0.113.99",
            51821,
            "offline",
            "2026-11-20T01:00:00Z",
            "2026-11-24T04:00:00Z"
        ],
    )
    .unwrap();

    let access_json = r#"{"services":"write","marketplace":"read","settings":"none","files":"read","users":"none","network":"read","updates":"none","transcoding":"write"}"#;
    conn.execute(
        "INSERT INTO peer_grants (id, link_id, run_as_user_id, access, token_hash, created_by, created_at, revoked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
        params![
            "grant-out-1",
            "link-media-2",
            42,
            access_json,
            TEST_OUTGOING_HASH,
            "admin",
            "2026-11-21T10:00:00Z"
        ],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO peer_received_grants (link_id, grant_id, run_as_user_id, access, created_by, created_at, generation, revoked_at, credential_id, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9)",
        params![
            "link-media-2",
            "grant-in-9",
            1001,
            access_json,
            "remote-admin",
            "2026-11-21T11:00:00Z",
            3,
            TEST_CREDENTIAL_ID,
            "2026-11-21T11:05:00Z"
        ],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO peer_exports (id, link_id, path, writable, squash_uid, squash_gid, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            "exp-1",
            "link-media-2",
            "/srv/media/movies",
            0,
            1000,
            1000,
            "2026-11-22T00:00:00Z"
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO peer_exports (id, link_id, path, writable, squash_uid, squash_gid, created_at)
         VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5)",
        params![
            "exp-2",
            "link-media-2",
            "/srv/media/tv",
            1,
            "2026-11-22T01:00:00Z"
        ],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO peer_mounts (id, link_id, remote_path, mount_path, unit_name, writable, purpose, state, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)",
        params![
            "mnt-1",
            "link-media-2",
            "/srv/media/movies",
            "/mnt/af-peers/media-2/movies",
            "mnt-af\\x2dpeers-media\\x2d2-movies.mount",
            0,
            "media",
            "mounted"
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO peer_mounts (id, link_id, remote_path, mount_path, unit_name, writable, purpose, state, last_error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            "mnt-2",
            "link-media-2",
            "/srv/media/cache",
            "/mnt/af-peers/media-2/cache",
            "mnt-af\\x2dpeers-media\\x2d2-cache.mount",
            1,
            "transcode",
            "degraded",
            format!("nfs timeout with token_hash={TEST_OUTGOING_HASH}")
        ],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO transcode_workers (link_id, enabled, weight, max_jobs, ffmpeg_version, encoders, render_node, parity_ok, parity_error)
         VALUES (?1, 1, 3, 4, ?2, ?3, ?4, 1, NULL)",
        params![
            "link-media-2",
            "7.1.0-jellyfin",
            r#"["h264_vaapi","hevc_vaapi"]"#,
            "/dev/dri/renderD128"
        ],
    )
    .unwrap();

    // Insert 14 jobs for link-media-2 to verify 10-job cap + newest-first ordering, plus 2 unrelated jobs.
    for idx in 1..=14 {
        conn.execute(
            "INSERT INTO transcode_jobs (id, link_id, started_at, ended_at, exit_code, request_id, ran_locally)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                format!("job-{idx:02}"),
                "link-media-2",
                format!("2026-11-24T03:{idx:02}:00Z"),
                format!("2026-11-24T03:{idx:02}:30Z"),
                if idx == 13 { 1 } else { 0 },
                format!("req-{idx:02}"),
                if idx % 3 == 0 { 1 } else { 0 }
            ],
        )
        .unwrap();
    }
    for idx in 1..=2 {
        conn.execute(
            "INSERT INTO transcode_jobs (id, link_id, started_at, ended_at, exit_code, request_id, ran_locally)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, 0)",
            params![
                format!("other-job-{idx}"),
                "link-other",
                format!("2026-11-24T04:{idx:02}:00Z"),
                format!("2026-11-24T04:{idx:02}:30Z"),
                format!("other-req-{idx}")
            ],
        )
        .unwrap();
    }

    // Insert 25 matching audit entries + 5 unrelated entries to verify 20-entry cap, id DESC ordering, and redaction.
    for idx in 1..=25 {
        let (username, target_type, target_id, detail) = if idx == 25 {
            (
                "admin",
                "peer_link",
                "link-media-2",
                format!(
                    "reconciled link inbound_token_hash={TEST_INBOUND_HASH} outgoing={TEST_OUTGOING_HASH} cred={TEST_CREDENTIAL_ID} X-AF-Grant-Token: secret-grant-1234 PrivateKey={TEST_PRIVATE_KEY}"
                ),
            )
        } else if idx % 3 == 0 {
            (
                "peer-media-2",
                "service",
                "jellyfin",
                format!("delegated action #{idx}"),
            )
        } else if idx % 3 == 1 {
            (
                "admin",
                "peer_grant",
                "grant-out-1",
                format!("updated outgoing grant #{idx}"),
            )
        } else {
            (
                "admin",
                "peer_link",
                "link-media-2",
                format!("link heartbeat ok #{idx}"),
            )
        };
        conn.execute(
            "INSERT INTO admin_audit_log (user_id, username, action, target_type, target_id, detail, ip_address, user_agent, created_at)
             VALUES (1, ?1, 'peer_event', ?2, ?3, ?4, '10.231.0.2', 'af-test', ?5)",
            params![
                username,
                target_type,
                target_id,
                detail,
                format!("2026-11-24T04:{:02}:00Z", idx)
            ],
        )
        .unwrap();
    }
    for idx in 1..=5 {
        conn.execute(
            "INSERT INTO admin_audit_log (user_id, username, action, target_type, target_id, detail, ip_address, user_agent, created_at)
             VALUES (1, 'admin', 'login', 'user', 'link-other', ?1, '127.0.0.1', 'browser', '2026-11-24T05:00:00Z')",
            params![format!("unrelated event #{idx} for other-peer")],
        )
        .unwrap();
    }
}

fn live_mock_transport() -> MockClusterTransport {
    let transport = MockClusterTransport::default();
    *transport.peer_status.lock().unwrap() = Some(Ok(PeerStatusResponse {
        installed: true,
        state: "up".to_string(),
        interface: "afpeer0".to_string(),
        public_key: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=".to_string(),
        listen_port: "51821".to_string(),
        tunnel_ip: "10.231.0.1".to_string(),
        tunnel_cidr: "10.231.0.0/16".to_string(),
        interface_address: "10.231.0.1/16".to_string(),
        service_state: "active".to_string(),
        config_available: true,
        key_available: true,
        route_prefix_ready: true,
        peers: vec![PeerStatusPeer {
            public_key: TEST_PUBKEY.to_string(),
            endpoint: "203.0.113.20:51821".to_string(),
            allowed_ips: "10.231.0.2/32".to_string(),
            latest_handshake: "2026-11-24T04:01:00Z".to_string(),
            latest_handshake_epoch: 1_795_492_860,
            handshake_age_secs: Some(12),
            transfer_rx: "123456".to_string(),
            transfer_tx: "654321".to_string(),
            persistent_keepalive: 25,
            active: true,
            persistent: true,
            present_live: true,
        }],
        error: None,
    }));

    let mut states = transport.mount_states.lock().unwrap();
    states.insert(
        "/mnt/af-peers/media-2/movies".to_string(),
        Ok(PeerMountStateResponse {
            unit_name: "mnt-af\\x2dpeers-media\\x2d2-movies.mount".to_string(),
            mount_path: "/mnt/af-peers/media-2/movies".to_string(),
            exists: true,
            active: true,
            unit_state: "active".to_string(),
        }),
    );
    states.insert(
        "/mnt/af-peers/media-2/cache".to_string(),
        Ok(PeerMountStateResponse {
            unit_name: "mnt-af\\x2dpeers-media\\x2d2-cache.mount".to_string(),
            mount_path: "/mnt/af-peers/media-2/cache".to_string(),
            exists: true,
            active: false,
            unit_state: "failed".to_string(),
        }),
    );
    drop(states);

    let mut probes = transport.sentinel_probes.lock().unwrap();
    probes.insert(
        "/mnt/af-peers/media-2/movies".to_string(),
        Ok(PeerSentinelProbeResponse {
            mount_path: "/mnt/af-peers/media-2/movies".to_string(),
            sentinel_path: "/mnt/af-peers/media-2/movies/.af-peer-sentinel".to_string(),
            healthy: true,
            timed_out: false,
            error: None,
        }),
    );
    probes.insert(
        "/mnt/af-peers/media-2/cache".to_string(),
        Ok(PeerSentinelProbeResponse {
            mount_path: "/mnt/af-peers/media-2/cache".to_string(),
            sentinel_path: "/mnt/af-peers/media-2/cache/.af-peer-sentinel".to_string(),
            healthy: false,
            timed_out: true,
            error: Some("sentinel timed out X-AF-Link-Token: raw-link-tok-9999".to_string()),
        }),
    );
    drop(probes);
    transport
}

#[test]
fn cluster_cli_parser_and_help_surface() {
    let basic = parse_cli_args(["cluster", "diagnose", "media-2"]).unwrap();
    assert_eq!(
        basic.command,
        AfCommand::Cluster(ClusterCliCommand::Diagnose {
            link: "media-2".to_string(),
            db_path: None,
        })
    );
    assert_eq!(basic.command.domain_name(), "cluster");
    assert_eq!(basic.command.action_name(), "diagnose");

    let with_db = parse_cli_args([
        "--json",
        "cluster",
        "diagnose",
        "link-media-2",
        "--db",
        "/tmp/custom.db",
    ])
    .unwrap();
    assert!(with_db.global.json);
    assert_eq!(
        with_db.command,
        AfCommand::Cluster(ClusterCliCommand::Diagnose {
            link: "link-media-2".to_string(),
            db_path: Some(PathBuf::from("/tmp/custom.db")),
        })
    );

    let with_eq_before =
        parse_cli_args(["cluster", "diagnose", "--db=/tmp/other.sqlite", "media-2"]).unwrap();
    assert_eq!(
        with_eq_before.command,
        AfCommand::Cluster(ClusterCliCommand::Diagnose {
            link: "media-2".to_string(),
            db_path: Some(PathBuf::from("/tmp/other.sqlite")),
        })
    );

    for help_args in [
        vec!["help", "cluster"],
        vec!["help", "peer"],
        vec!["cluster", "--help"],
    ] {
        let inv = parse_cli_args(help_args).unwrap();
        assert_eq!(
            inv.command,
            AfCommand::Help {
                topic: HelpTopic::Cluster
            }
        );
        let resp = execute_invocation(&inv, &MockRunnerTransport::default());
        assert_eq!(resp.status, "ok");
        assert!(resp.message.contains("af cluster diagnose <link>"));
        assert!(resp.message.contains("--db <path>"));
    }

    let general_help = render_help_text(HelpTopic::General);
    assert!(general_help.contains("cluster"));

    for bad in [
        vec!["cluster"],
        vec!["cluster", "unknown"],
        vec!["cluster", "diagnose"],
        vec!["cluster", "diagnose", "a", "b"],
        vec!["cluster", "diagnose", "media-2", "--db"],
        vec!["cluster", "diagnose", "media-2", "--db="],
        vec!["cluster", "diagnose", "media-2", "--bogus"],
    ] {
        assert!(
            parse_cli_args(bad.clone()).is_err(),
            "expected parse error for {:?}",
            bad
        );
    }
}

#[test]
fn cluster_diagnose_full_report_json_and_human_and_secret_redaction() {
    let tmp = TempTestDir::new("cluster-diagnose-full");
    let db_path = tmp.path().join("aetherflow.sqlite");
    create_cluster_test_db(&db_path);
    let db_str = db_path.to_string_lossy().to_string();

    for selector in ["media-2", "link-media-2", "MEDIA-2"] {
        let transport = live_mock_transport();
        let inv =
            parse_cli_args(["--json", "cluster", "diagnose", selector, "--db", &db_str]).unwrap();
        let env = execute_invocation(&inv, &transport);
        assert_eq!(env.status, "ok", "selector={selector}: {}", env.message);
        assert_eq!(env.exit_code, 0);
        assert_eq!(env.domain, "cluster");
        assert_eq!(env.action, "diagnose");

        let data = env.data.as_ref().expect("structured diagnose payload");
        assert_eq!(data["link"]["id"], "link-media-2");
        assert_eq!(data["link"]["name"], "media-2");
        assert_eq!(data["link"]["state"], "online");
        assert_eq!(data["link"]["tunnel_ip"], "10.231.0.2");
        assert_eq!(data["link"]["wg_port"], 51821);
        assert_eq!(
            data["link"]["capabilities"],
            serde_json::json!(["storage", "transcode", "proxy"])
        );
        assert!(data["link"].get("inbound_token_hash").is_none());

        assert_eq!(data["wireguard"]["available"], true);
        assert_eq!(data["wireguard"]["interface"], "afpeer0");
        assert_eq!(data["wireguard"]["peer_found"], true);
        assert_eq!(data["wireguard"]["present_live"], true);
        assert_eq!(data["wireguard"]["active"], true);
        assert_eq!(data["wireguard"]["handshake_age_secs"], 12);
        assert_eq!(data["wireguard"]["rx_bytes"], 123456);
        assert_eq!(data["wireguard"]["tx_bytes"], 654321);

        assert_eq!(data["grants"]["outgoing"]["id"], "grant-out-1");
        assert_eq!(data["grants"]["outgoing"]["active"], true);
        assert_eq!(data["grants"]["outgoing"]["run_as_user_id"], 42);
        assert_eq!(data["grants"]["outgoing"]["access"]["services"], "write");
        assert_eq!(data["grants"]["outgoing"]["access"]["transcoding"], "write");
        assert!(data["grants"]["outgoing"].get("token_hash").is_none());

        assert_eq!(data["grants"]["incoming"]["grant_id"], "grant-in-9");
        assert_eq!(data["grants"]["incoming"]["active"], true);
        assert_eq!(data["grants"]["incoming"]["generation"], 3);
        assert!(data["grants"]["incoming"].get("credential_id").is_none());

        let exports = data["exports"].as_array().unwrap();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0]["path"], "/srv/media/movies");
        assert_eq!(exports[0]["writable"], false);
        assert_eq!(exports[1]["path"], "/srv/media/tv");
        assert_eq!(exports[1]["writable"], true);

        let mounts = data["mounts"].as_array().unwrap();
        assert_eq!(mounts.len(), 2);
        let movies_mount = mounts
            .iter()
            .find(|m| m["mount_path"] == "/mnt/af-peers/media-2/movies")
            .expect("movies mount present");
        assert_eq!(movies_mount["live_active"], true);
        assert_eq!(movies_mount["probe"]["ok"], true);
        assert_eq!(
            movies_mount["probe"]["checked_path"],
            "/mnt/af-peers/media-2/movies/.af-peer-sentinel"
        );
        let cache_mount = mounts
            .iter()
            .find(|m| m["mount_path"] == "/mnt/af-peers/media-2/cache")
            .expect("cache mount present");
        assert_eq!(cache_mount["live_active"], false);
        assert_eq!(cache_mount["probe"]["ok"], false);
        assert_eq!(cache_mount["probe"]["timed_out"], true);

        assert_eq!(data["transcode_worker"]["configured"], true);
        assert_eq!(data["transcode_worker"]["enabled"], true);
        assert_eq!(data["transcode_worker"]["weight"], 3);
        assert_eq!(data["transcode_worker"]["max_jobs"], 4);
        assert_eq!(
            data["transcode_worker"]["encoders"],
            serde_json::json!(["h264_vaapi", "hevc_vaapi"])
        );
        assert_eq!(
            data["transcode_worker"]["render_node"],
            "/dev/dri/renderD128"
        );
        let recent_jobs = data["transcode_worker"]["recent_jobs"].as_array().unwrap();
        assert_eq!(recent_jobs.len(), 10);
        assert_eq!(recent_jobs[0]["id"], "job-14");
        assert_eq!(recent_jobs[9]["id"], "job-05");

        let audit = data["audit"].as_array().unwrap();
        assert_eq!(audit.len(), 20);
        // Verify newest-first ordering (strictly descending id) and no unrelated rows.
        for pair in audit.windows(2) {
            assert!(
                pair[0]["id"].as_i64().unwrap() > pair[1]["id"].as_i64().unwrap(),
                "audit entries must be ordered id DESC"
            );
        }
        assert!(audit
            .iter()
            .all(|entry| !entry["detail"].as_str().unwrap().contains("other-peer")));

        // Verify zero secret leakage across BOTH JSON serialization and human text output.
        let serialized_json = serde_json::to_string(&env).unwrap();
        for forbidden in [
            TEST_INBOUND_HASH,
            TEST_OUTGOING_HASH,
            TEST_CREDENTIAL_ID,
            TEST_PRIVATE_KEY,
            "raw-link-tok-9999",
            "secret-grant-1234",
            "secretpairpayload123",
        ] {
            assert!(
                !serialized_json.contains(forbidden),
                "JSON output leaked secret fragment {forbidden:?}"
            );
            assert!(
                !env.message.contains(forbidden),
                "human output leaked secret fragment {forbidden:?}"
            );
        }
        assert!(env.message.contains("[REDACTED]"));
        assert!(env.message.contains("[Link Health]"));
        assert!(env.message.contains("[WireGuard (afpeer0)]"));
        assert!(env.message.contains("[Grants]"));
        assert!(env.message.contains("[Exports (2)]"));
        assert!(env.message.contains("[Mounts (2)]"));
        assert!(env.message.contains("[Transcode Worker]"));
        assert!(env.message.contains("[Audit Trail (last 20 entries)]"));
    }
}

#[test]
fn cluster_diagnose_degrades_gracefully_when_runner_is_offline() {
    let tmp = TempTestDir::new("cluster-diagnose-offline");
    let db_path = tmp.path().join("aetherflow.db");
    create_cluster_test_db(&db_path);
    let db_str = db_path.to_string_lossy().to_string();

    // Default MockClusterTransport has no responses -> simulates runner socket offline.
    let offline_transport = MockClusterTransport::default();
    let inv =
        parse_cli_args(["--json", "cluster", "diagnose", "media-2", "--db", &db_str]).unwrap();
    let env = execute_invocation(&inv, &offline_transport);

    assert_eq!(env.status, "ok", "{}", env.message);
    assert_eq!(env.exit_code, 0);
    let data = env.data.as_ref().unwrap();
    assert_eq!(data["link"]["id"], "link-media-2");
    assert_eq!(data["wireguard"]["available"], false);
    assert_eq!(data["wireguard"]["interface_state"], "unavailable");
    assert!(data["wireguard"]["error"]
        .as_str()
        .unwrap()
        .contains("connection refused"));

    let mounts = data["mounts"].as_array().unwrap();
    assert_eq!(mounts.len(), 2);
    for mount in mounts {
        assert!(mount["live_active"].is_null());
        assert!(mount["live_error"]
            .as_str()
            .unwrap()
            .contains("runner offline"));
        assert_eq!(mount["probe"]["ok"], false);
        assert!(mount["probe"]["error"]
            .as_str()
            .unwrap()
            .contains("runner offline"));
    }
    assert_eq!(data["exports"].as_array().unwrap().len(), 2);
    assert_eq!(data["audit"].as_array().unwrap().len(), 20);
    assert!(env.message.contains("unavailable (runner unreachable)"));
}

#[test]
fn cluster_diagnose_handles_missing_link_missing_db_dry_run_readonly_and_root() {
    let tmp = TempTestDir::new("cluster-diagnose-edge");
    let db_path = tmp.path().join("var/lib/aetherflow/aetherflow.sqlite");
    create_cluster_test_db(&db_path);
    let db_str = db_path.to_string_lossy().to_string();
    let root_str = tmp.path().to_string_lossy().to_string();

    let transport = MockClusterTransport::default();

    // 1. Unknown link returns clean error
    let unknown_inv = parse_cli_args([
        "--json",
        "cluster",
        "diagnose",
        "does-not-exist",
        "--db",
        &db_str,
    ])
    .unwrap();
    let unknown_env = execute_invocation(&unknown_inv, &transport);
    assert_eq!(unknown_env.status, "error");
    assert_ne!(unknown_env.exit_code, 0);
    assert!(unknown_env.message.contains("does-not-exist"));

    // 2. Missing DB returns clean error
    let missing_db = tmp.path().join("nope.db");
    let missing_inv = parse_cli_args([
        "--json",
        "cluster",
        "diagnose",
        "media-2",
        "--db",
        missing_db.to_str().unwrap(),
    ])
    .unwrap();
    let missing_env = execute_invocation(&missing_inv, &transport);
    assert_eq!(missing_env.status, "error");
    assert!(missing_env.message.contains("SQLite database not found"));

    // 3. --dry-run succeeds without touching DB or runner
    let dry_inv = parse_cli_args([
        "--json",
        "--dry-run",
        "cluster",
        "diagnose",
        "media-2",
        "--db",
        missing_db.to_str().unwrap(),
    ])
    .unwrap();
    let dry_env = execute_invocation(&dry_inv, &transport);
    assert_eq!(dry_env.status, "ok", "{}", dry_env.message);
    assert!(dry_env.message.contains("[DRY-RUN]"));
    assert_eq!(*transport.network_calls.lock().unwrap(), 0);

    // 4. --root resolves <root>/var/lib/aetherflow/aetherflow.sqlite when env vars are unset
    {
        let _guard = ENV_TEST_LOCK.lock().unwrap();
        let saved: Vec<(&str, Option<String>)> = ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"]
            .into_iter()
            .map(|k| {
                let prev = std::env::var(k).ok();
                std::env::remove_var(k);
                (k, prev)
            })
            .collect();

        let root_inv = parse_cli_args([
            "--json", "--root", &root_str, "cluster", "diagnose", "media-2",
        ])
        .unwrap();
        let root_env = execute_invocation(&root_inv, &transport);

        // Also test fallback to aetherflow.db when aetherflow.sqlite is moved aside
        let fallback_db = tmp.path().join("var/lib/aetherflow/aetherflow.db");
        fs::rename(&db_path, &fallback_db).unwrap();
        let fallback_env = execute_invocation(&root_inv, &transport);

        for (k, prev) in saved {
            if let Some(val) = prev {
                std::env::set_var(k, val);
            }
        }

        assert_eq!(root_env.status, "ok", "{}", root_env.message);
        assert_eq!(
            root_env.data.as_ref().unwrap()["db_path"],
            db_path.to_string_lossy().as_ref()
        );
        assert_eq!(fallback_env.status, "ok", "{}", fallback_env.message);
        assert_eq!(
            fallback_env.data.as_ref().unwrap()["db_path"],
            fallback_db.to_string_lossy().as_ref()
        );

        // 5. Read-only guarantee: DB file bytes unchanged and works with 0o444 permissions
        let before = fs::read(&fallback_db).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fallback_db, fs::Permissions::from_mode(0o444)).unwrap();
        }
        let ro_inv = parse_cli_args([
            "--json",
            "cluster",
            "diagnose",
            "media-2",
            "--db",
            fallback_db.to_str().unwrap(),
        ])
        .unwrap();
        let ro_env = execute_invocation(&ro_inv, &transport);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fallback_db, fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert_eq!(ro_env.status, "ok", "{}", ro_env.message);
        assert_eq!(fs::read(&fallback_db).unwrap(), before);
    }
}

#[cfg(unix)]
#[test]
fn cluster_unix_socket_client_dispatches_peer_network_and_peer_storage_requests() {
    use std::io::{Read, Write};

    let tmp = TempTestDir::new("cluster-uds");
    let db_path = tmp.path().join("aetherflow.db");
    create_cluster_test_db(&db_path);

    let dir_name = format!("c-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
    let sock_root = TempTestDir {
        path: PathBuf::from("/tmp").join(dir_name),
    };
    fs::create_dir_all(sock_root.path()).unwrap();
    let socket = sock_root.path().join("runner.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();

    // Expect 5 HTTP requests: 1x /v1/peer-network + 2 mounts * (mount_status + probe_sentinel).
    let server = std::thread::spawn(move || {
        for _ in 0..5 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let header_end;
            let content_len;
            loop {
                let mut chunk = [0u8; 1024];
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0);
                request.extend_from_slice(&chunk[..count]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let len = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + len {
                        header_end = end;
                        content_len = len;
                        break;
                    }
                }
            }
            let head = String::from_utf8_lossy(&request[..header_end]);
            let first_line = head.lines().next().unwrap_or("");
            let body_json: serde_json::Value =
                serde_json::from_slice(&request[header_end + 4..header_end + 4 + content_len])
                    .unwrap();

            let output = if first_line.contains("/v1/peer-network") {
                assert_eq!(body_json["action"], "status");
                serde_json::to_string(&PeerStatusResponse {
                    installed: true,
                    state: "up".to_string(),
                    interface: "afpeer0".to_string(),
                    public_key: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=".to_string(),
                    listen_port: "51821".to_string(),
                    tunnel_ip: "10.231.0.1".to_string(),
                    tunnel_cidr: "10.231.0.0/16".to_string(),
                    interface_address: "10.231.0.1/16".to_string(),
                    service_state: "active".to_string(),
                    config_available: true,
                    key_available: true,
                    route_prefix_ready: true,
                    peers: vec![PeerStatusPeer {
                        public_key: TEST_PUBKEY.to_string(),
                        endpoint: "203.0.113.20:51821".to_string(),
                        allowed_ips: "10.231.0.2/32".to_string(),
                        latest_handshake: "2026-11-24T04:01:00Z".to_string(),
                        latest_handshake_epoch: 1_795_492_860,
                        handshake_age_secs: Some(7),
                        transfer_rx: "4096".to_string(),
                        transfer_tx: "8192".to_string(),
                        persistent_keepalive: 25,
                        active: true,
                        persistent: true,
                        present_live: true,
                    }],
                    error: None,
                })
                .unwrap()
            } else if first_line.contains("/v1/peer-storage") {
                let mount_path = body_json["mount_path"].as_str().unwrap().to_string();
                match body_json["action"].as_str().unwrap() {
                    "mount_status" => serde_json::to_string(&PeerMountStateResponse {
                        unit_name: "mnt-test.mount".to_string(),
                        mount_path,
                        exists: true,
                        active: true,
                        unit_state: "active".to_string(),
                    })
                    .unwrap(),
                    "probe_sentinel" => serde_json::to_string(&PeerSentinelProbeResponse {
                        sentinel_path: format!("{mount_path}/.af-peer-sentinel"),
                        mount_path,
                        healthy: true,
                        timed_out: false,
                        error: None,
                    })
                    .unwrap(),
                    other => panic!("unexpected peer-storage action: {other}"),
                }
            } else {
                panic!("unexpected endpoint: {first_line}");
            };

            let resp_body = serde_json::to_string(&RunnerResponse {
                success: true,
                output,
                error: String::new(),
            })
            .unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp_body.len(),
                resp_body
            )
            .unwrap();
        }
    });

    let inv = parse_cli_args([
        "--json",
        "--socket",
        socket.to_str().unwrap(),
        "cluster",
        "diagnose",
        "media-2",
        "--db",
        db_path.to_str().unwrap(),
    ])
    .unwrap();
    let client = UnixSocketRunnerClient::new(&inv.global.socket_path);
    let env = execute_invocation(&inv, &client);
    server.join().unwrap();

    assert_eq!(env.status, "ok", "{}", env.message);
    let data = env.data.as_ref().unwrap();
    assert_eq!(data["wireguard"]["available"], true);
    assert_eq!(data["wireguard"]["handshake_age_secs"], 7);
    assert_eq!(data["wireguard"]["rx_bytes"], 4096);
    assert_eq!(data["wireguard"]["tx_bytes"], 8192);
    let mounts = data["mounts"].as_array().unwrap();
    assert_eq!(mounts.len(), 2);
    assert!(mounts
        .iter()
        .all(|m| m["live_active"] == true && m["probe"]["ok"] == true));
}
