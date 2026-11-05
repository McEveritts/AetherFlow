use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use axum::extract::{Path, Query, Request};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{Duration, Utc};
use once_cell::sync::Lazy;
use rand::RngCore;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::{Path as StdPath, PathBuf};
use std::process::Command;
use std::sync::Mutex;

#[cfg(test)]
mod audit_tests {
    use super::*;

    struct ScanFixture(PathBuf);

    impl ScanFixture {
        fn new() -> Self {
            let path = env::temp_dir().join(format!("af-mediaflow-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(path.join("library/nested")).unwrap();
            std::fs::create_dir_all(path.join("library-other")).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    impl Drop for ScanFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn custom_ai_clients_do_not_forward_credentials_on_redirect() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let visited = Arc::new(AtomicUsize::new(0));
        let observed = visited.clone();
        let server = tokio::spawn(async move {
            let app = axum::Router::new()
                .route(
                    "/v1/messages",
                    axum::routing::post(|| async {
                        axum::response::Redirect::temporary("/capture")
                    }),
                )
                .route(
                    "/v1/chat/completions",
                    axum::routing::post(|| async {
                        axum::response::Redirect::temporary("/capture")
                    }),
                )
                .route(
                    "/capture",
                    axum::routing::any(move || {
                        let observed = observed.clone();
                        async move {
                            observed.fetch_add(1, Ordering::SeqCst);
                            "unexpected redirect"
                        }
                    }),
                );
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://{address}");
        assert!(
            call_anthropic_api(&base, "fixture-only", "model", "", &[], "hello")
                .await
                .is_err()
        );
        assert!(
            call_openai_compatible_api(&base, "fixture-only", "model", "", &[], "hello")
                .await
                .is_err()
        );
        assert_eq!(visited.load(Ordering::SeqCst), 0);
        server.abort();
        assert!(call_anthropic_api(
            "file:///tmp/unused",
            "fixture-only",
            "model",
            "",
            &[],
            "hello"
        )
        .await
        .is_err());
    }

    #[test]
    fn mediaflow_paths_enforce_canonical_root_boundaries() {
        let fixture = ScanFixture::new();
        let root = fixture.0.join("library");
        let roots = vec![root.clone()];
        assert_eq!(validate_mediaflow_directory(&root, &roots).unwrap(), root);
        assert!(validate_mediaflow_directory(&root.join("nested"), &roots).is_ok());
        for path in [
            root.join("../library-other"),
            fixture.0.join("library-other"),
        ] {
            assert_eq!(
                validate_mediaflow_directory(&path, &roots).unwrap_err().0,
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(
            validate_mediaflow_directory(&root, &[]).unwrap_err().0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            validate_mediaflow_directory(&root.join("missing"), &roots)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
        std::fs::write(root.join("video.mp4"), []).unwrap();
        assert_eq!(
            validate_mediaflow_directory(&root.join("video.mp4"), &roots)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn mediaflow_collection_filters_hidden_and_non_video_files() {
        let fixture = ScanFixture::new();
        let root = fixture.0.join("library");
        std::fs::create_dir(root.join(".mediaflow_trash")).unwrap();
        for name in [
            "nested/movie.MKV",
            "notes.txt",
            ".hidden.mp4",
            ".mediaflow_trash/deleted.mp4",
        ] {
            std::fs::write(root.join(name), []).unwrap();
        }
        let mut files = Vec::new();
        collect_mediaflow_files(&root, &root, &mut files);
        assert_eq!(files, vec![root.join("nested/movie.MKV")]);
    }

    #[cfg(unix)]
    #[test]
    fn mediaflow_rejects_symlink_escapes_and_skips_cycles() {
        let fixture = ScanFixture::new();
        let root = fixture.0.join("library");
        let outside = fixture.0.join("library-other");
        std::fs::write(outside.join("secret.mp4"), []).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret.mp4"), root.join("linked.mp4")).unwrap();
        std::os::unix::fs::symlink(&root, root.join("nested/cycle")).unwrap();
        assert_eq!(
            validate_mediaflow_directory(&root.join("escape"), std::slice::from_ref(&root))
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
        let mut files = Vec::new();
        collect_mediaflow_files(&root, &root, &mut files);
        assert!(files.is_empty());
    }

    #[test]
    fn wireguard_dump_uses_all_interface_column_offsets_without_secrets() {
        let dump = "wg0\tprivate-secret\tpublic-key\t51820\toff\nwg0\tpeer-key\tpreshared-secret\t192.0.2.1:1234\t10.0.0.2/32\t123\t456\t789\t25\nwg1\tother-private\tother-public\t51821\toff\nwg1\tother-peer\tother-psk\t(none)\t10.1.0.2/32\t0\t0\t0\toff\n";
        let status = parse_wireguard_dump(dump).unwrap();
        assert_eq!(status["interface"], "wg0");
        assert_eq!(status["public_key"], "public-key");
        assert_eq!(status["listen_port"], "51820");
        assert_eq!(status["peers"].as_array().unwrap().len(), 1);
        assert_eq!(
            status["peers"][0],
            serde_json::json!({
                "public_key": "peer-key", "endpoint": "192.0.2.1:1234",
                "allowed_ips": "10.0.0.2/32", "latest_handshake": "123",
                "transfer_rx": "456", "transfer_tx": "789",
            })
        );
        assert!(!status.to_string().contains("secret"));
    }

    #[test]
    fn wireguard_dump_handles_empty_interfaces_and_malformed_rows() {
        assert!(parse_wireguard_dump("").is_none());
        assert!(parse_wireguard_dump("invalid\trow").is_none());
        let status =
            parse_wireguard_dump("wg0\tprivate\tpublic\t51820\toff\nwg0\ttruncated\n").unwrap();
        assert_eq!(status["peers"], serde_json::json!([]));
    }

    #[test]
    fn tailscale_status_preserves_frontend_fields_and_real_peer_data() {
        let raw = serde_json::json!({
            "BackendState": "Running", "MagicDNSSuffix": "tail.example",
            "Self": {"ID": "self-id", "HostName": "server", "DNSName": "server.tail.example.",
                "TailscaleIPs": ["100.64.0.1"], "OS": "linux", "Online": true},
            "Peer": {"peer-key": {"HostName": "laptop", "TailscaleIPs": ["100.64.0.2"],
                "Online": true, "ExitNode": true, "Tags": ["tag:media"]}},
        });
        let status = tailscale_status_value(&raw);
        assert_eq!(status["backend_state"], "Running");
        assert_eq!(status["magic_dns"], true);
        assert_eq!(status["self"]["hostname"], "server");
        assert_eq!(status["self"]["tailscale_ip"], "100.64.0.1");
        assert_eq!(status["peers"][0]["id"], "peer-key");
        assert_eq!(status["peers"][0]["online"], true);
        assert_eq!(status["peers"][0]["exit_node"], true);
        assert_eq!(status["peers"][0]["tags"], serde_json::json!(["tag:media"]));
        let stopped = tailscale_status_value(&serde_json::json!({}));
        assert_eq!(stopped["backend_state"], "Stopped");
        assert_eq!(stopped["peers"], serde_json::json!([]));
    }

    #[test]
    fn audit_log_fallback_reads_singular_detail_column() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE admin_audit_log (id INTEGER PRIMARY KEY, created_at TEXT, action TEXT, target_type TEXT, detail TEXT); INSERT INTO admin_audit_log VALUES (1, '2026-10-31', 'update', 'system', 'channel stable'), (2, NULL, NULL, NULL, NULL);").unwrap();
        let mut stmt = conn.prepare(AUDIT_LOG_FALLBACK_SQL).unwrap();
        let rows: Vec<(String, String)> = stmt
            .query_map([2], |row| Ok((row.get(1)?, row.get(3)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("event".to_string(), "".to_string()),
                ("update".to_string(), "channel stable".to_string())
            ]
        );
    }

    #[test]
    fn metrics_history_selects_latest_rows_in_chronological_order_and_supports_windows_and_downsample(
    ) {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE metrics_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                cpu_avg REAL,
                mem_used_gb REAL,
                mem_total_gb REAL,
                disk_read_bps REAL,
                disk_write_bps REAL,
                net_rx_bytes INTEGER,
                net_tx_bytes INTEGER,
                load_avg_1 REAL,
                active_conns INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_metrics_history_ts ON metrics_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_metrics_history_ts_id ON metrics_history(timestamp DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_metrics_history_norm_ts_id ON metrics_history(replace(CAST(timestamp AS TEXT), 'T', ' ') DESC, id DESC);",
        )
        .unwrap();

        let now = Utc::now();
        for step_idx in 0..10i64 {
            let point_time = now - Duration::minutes(10 - step_idx);
            let ts = if step_idx % 2 == 1 {
                point_time.format("%Y-%m-%dT%H:%M:%SZ").to_string()
            } else {
                point_time.format("%Y-%m-%d %H:%M:%S").to_string()
            };
            conn.execute(
                "INSERT INTO metrics_history (timestamp, cpu_avg, mem_used_gb, mem_total_gb, disk_read_bps, disk_write_bps, net_rx_bytes, net_tx_bytes, load_avg_1, active_conns)
                 VALUES (?1, ?2, 8.0, 32.0, 1024.0, 2048.0, ?3, ?4, 1.25, 10)",
                params![ts, (step_idx as f64) * 10.0, step_idx * 1000, step_idx * 500],
            )
            .unwrap();
        }

        for (query_sql, param_count) in [
            (METRICS_HISTORY_QUERY_SQL, 2usize),
            (METRICS_PREDICTIONS_HISTORY_SQL, 1usize),
        ] {
            let explain_sql = format!("EXPLAIN QUERY PLAN {}", query_sql);
            let mut explain_stmt = conn.prepare(&explain_sql).unwrap();
            let plan_details: Vec<String> = if param_count == 2 {
                explain_stmt
                    .query_map(params!["1970-01-01 00:00:00", 100i64], |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap()
            } else {
                explain_stmt
                    .query_map(params!["1970-01-01 00:00:00"], |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap()
            };
            assert!(
                plan_details.iter().any(|detail| {
                    detail.contains("SEARCH")
                        && detail.contains("USING INDEX idx_metrics_history_norm_ts_id")
                }),
                "expected index search in query plan, got: {:?}",
                plan_details
            );
            assert!(
                !plan_details
                    .iter()
                    .any(|detail| detail.contains("TEMP B-TREE")),
                "unexpected temp sort in query plan: {:?}",
                plan_details
            );
        }

        let mut query_params = HashMap::new();
        query_params.insert("days".to_string(), "7".to_string());
        query_params.insert("limit".to_string(), "4".to_string());
        let rows = query_metrics_history_rows(&conn, &query_params);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0]["cpu_avg"], 60.0);
        assert_eq!(rows[1]["cpu_avg"], 70.0);
        assert_eq!(rows[2]["cpu_avg"], 80.0);
        assert_eq!(rows[3]["cpu_avg"], 90.0);
        assert_eq!(rows[3]["net_rx_bytes"], 9000);
        assert_eq!(rows[3]["net_tx_bytes"], 4500);
        assert!(rows[3].get("net_down_bps").is_none());

        let mut q_ds = HashMap::new();
        q_ds.insert("window".to_string(), "1h".to_string());
        q_ds.insert("downsample".to_string(), "true".to_string());
        q_ds.insert("target_points".to_string(), "3".to_string());
        let ds_rows = query_metrics_history_rows(&conn, &q_ds);
        assert_eq!(ds_rows.len(), 3);
        assert_eq!(ds_rows[0]["cpu_avg"], 0.0);
        assert_eq!(ds_rows[2]["cpu_avg"], 90.0);
    }

    fn init_ai_test_settings() {
        crate::plugins::tests::ensure_shared_test_db();
        af_db::get_conn()
            .unwrap()
            .execute(
                "UPDATE settings SET gemini_api_key = '', openai_api_key = '', anthropic_api_key = '', \
                 anthropic_endpoint = '', lm_studio_endpoint = 'http://localhost:1234', \
                 ollama_endpoint = 'http://localhost:11434', ai_model = 'gemini-4-argon' WHERE id = 1",
                [],
            )
            .unwrap();
    }

    #[tokio::test]
    async fn local_provider_rejects_locality_aliases_and_dispatches_installed_model_id() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        init_ai_test_settings();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
        let app = axum::Router::new().route(
            "/v1/chat/completions",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(body);
                    axum::Json(serde_json::json!({
                        "choices": [{ "message": { "content": "local-ok" } }]
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        af_db::get_conn()
            .unwrap()
            .execute(
                "UPDATE settings SET ollama_endpoint = ?1 WHERE id = 1",
                [endpoint.as_str()],
            )
            .unwrap();

        for alias in [
            "ollama",
            "lm-studio",
            "anthropic-local",
            "localai",
            "local-test",
        ] {
            let rejected = run_chat_session(
                None,
                "",
                "",
                "",
                alias,
                "localai",
                vec![],
                "hello".to_string(),
            )
            .await;
            assert_eq!(
                rejected.status(),
                StatusCode::BAD_REQUEST,
                "alias '{alias}' must be rejected before calling upstream"
            );
        }
        assert!(
            rx.try_recv().is_err(),
            "no upstream call should occur for forbidden aliases"
        );

        let accepted = run_chat_session(
            None,
            "",
            "",
            "",
            "fixture-installed-model",
            "localai",
            vec![],
            "hello".to_string(),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);
        let sent_body = rx
            .recv()
            .await
            .expect("expected upstream chat completion request");
        assert_eq!(sent_body["model"], "fixture-installed-model");

        server.abort();
    }

    #[tokio::test]
    async fn anthropic_local_uses_messages_protocol_and_credentials() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        init_ai_test_settings();

        let (msg_tx, mut msg_rx) =
            tokio::sync::mpsc::unbounded_channel::<(String, String, serde_json::Value)>();
        let (openai_tx, mut openai_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let app = axum::Router::new()
            .route(
                "/v1/messages",
                axum::routing::post(
                    move |headers: axum::http::HeaderMap,
                          axum::Json(body): axum::Json<serde_json::Value>| {
                        let msg_tx = msg_tx.clone();
                        async move {
                            let api_key = headers
                                .get("x-api-key")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let version = headers
                                .get("anthropic-version")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let _ = msg_tx.send((api_key, version, body));
                            axum::Json(serde_json::json!({
                                "content": [{ "type": "text", "text": "anthropic-local-ok" }]
                            }))
                        }
                    },
                ),
            )
            .route(
                "/v1/chat/completions",
                axum::routing::post(move || {
                    let openai_tx = openai_tx.clone();
                    async move {
                        let _ = openai_tx.send(());
                        StatusCode::NOT_FOUND
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        af_db::get_conn()
            .unwrap()
            .execute(
                "UPDATE settings SET anthropic_endpoint = ?1, anthropic_api_key = 'fixture-local-key', ai_model = 'anthropic-local:local-claude-sonnet' WHERE id = 1",
                [endpoint.as_str()],
            )
            .unwrap();

        let resp = run_chat_session(
            None,
            "",
            "",
            "",
            "",
            "localai",
            vec![],
            "diagnose".to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            openai_rx.try_recv().is_err(),
            "must not hit OpenAI chat/completions"
        );

        let (api_key, version, body) = msg_rx
            .recv()
            .await
            .expect("expected request to /v1/messages");
        assert_eq!(api_key, "fixture-local-key");
        assert_eq!(version, "2023-06-01");
        assert_eq!(body["model"], "local-claude-sonnet");

        server.abort();
    }

    #[tokio::test]
    async fn versioned_v1_base_urls_do_not_duplicate_v1_segment() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let tx_msg = tx.clone();
        let tx_chat = tx.clone();
        let app = axum::Router::new()
            .route(
                "/v1/messages",
                axum::routing::post(move |uri: axum::http::Uri| {
                    let tx_msg = tx_msg.clone();
                    async move {
                        let _ = tx_msg.send(uri.path().to_string());
                        axum::Json(serde_json::json!({
                            "content": [{ "type": "text", "text": "ok-anthropic" }]
                        }))
                    }
                }),
            )
            .route(
                "/v1/chat/completions",
                axum::routing::post(move |uri: axum::http::Uri| {
                    let tx_chat = tx_chat.clone();
                    async move {
                        let _ = tx_chat.send(uri.path().to_string());
                        axum::Json(serde_json::json!({
                            "choices": [{ "message": { "content": "ok-openai" } }]
                        }))
                    }
                }),
            )
            .fallback(move |uri: axum::http::Uri| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(uri.path().to_string());
                    StatusCode::NOT_FOUND
                }
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_with_v1 = format!("http://{}/v1/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let validated = af_services::validate_server_url(&base_with_v1).unwrap();
        let anth_reply = call_anthropic_api(
            &validated,
            "fixture-key",
            "claude-sonnet-5-5",
            "",
            &[],
            "hello",
        )
        .await
        .expect("Anthropic call with /v1 base URL should succeed");
        assert_eq!(anth_reply, "ok-anthropic");
        assert_eq!(rx.recv().await.unwrap(), "/v1/messages");

        let oai_reply = call_openai_compatible_api(
            &validated,
            "fixture-key",
            "qwen2.5-coder:7b",
            "",
            &[],
            "hello",
        )
        .await
        .expect("OpenAI-compatible call with /v1 base URL should succeed");
        assert_eq!(oai_reply, "ok-openai");
        assert_eq!(rx.recv().await.unwrap(), "/v1/chat/completions");

        server.abort();
    }

    #[tokio::test]
    async fn test_ai_connection_honors_unsaved_anthropic_drafts_and_returns_bad_gateway_on_upstream_error(
    ) {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        init_ai_test_settings();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
        let app = axum::Router::new().route(
            "/v1/messages",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let tx = tx.clone();
                async move {
                    let model = body["model"].as_str().unwrap_or("").to_string();
                    let _ = tx.send(body);
                    if model == "claude-opus-5-6" {
                        (
                            StatusCode::OK,
                            axum::Json(serde_json::json!({
                                "content": [{ "type": "text", "text": "SUCCESS" }]
                            })),
                        )
                    } else {
                        (
                            StatusCode::UNAUTHORIZED,
                            axum::Json(serde_json::json!({
                                "error": "invalid upstream key"
                            })),
                        )
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let draft_endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let admin = AuthUser {
            user_id: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            jti: String::new(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };

        // 1. Unsaved draft endpoint + model override succeeds without saving settings first
        let ok_resp = test_ai_connection(
            axum::Extension(admin.clone()),
            Json(serde_json::json!({
                "provider": "anthropic",
                "anthropic_api_key": "draft-key",
                "endpoint": draft_endpoint,
                "model": "claude-opus-5-6",
            })),
        )
        .await;
        assert_eq!(ok_resp.status(), StatusCode::OK);
        let recorded = rx
            .recv()
            .await
            .expect("expected request to draft anthropic endpoint");
        assert_eq!(recorded["model"], "claude-opus-5-6");

        // 2. Upstream 401 maps to 502 BAD_GATEWAY (never 401 UNAUTHORIZED session logout)
        let err_resp = test_ai_connection(
            axum::Extension(admin),
            Json(serde_json::json!({
                "provider": "anthropic",
                "anthropic_api_key": "bad-key",
                "endpoint": draft_endpoint,
                "model": "claude-sonnet-5-5",
            })),
        )
        .await;
        assert_eq!(err_resp.status(), StatusCode::BAD_GATEWAY);

        server.abort();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. FlowAI Multi-Provider Chat, Support & Connection Test (`backend/api/ai.go`)
// ─────────────────────────────────────────────────────────────────────────────

static ALLOWED_AI_MODELS: &[&str] = &[
    "gemini-4-argon",
    "gemini-3.1-pro-preview",
    "gemini-3-flash-preview",
    "gemini-3.1-flash-lite-preview",
    "gemini-3-pro-image-preview",
    "gemini-3.1-flash-image-preview",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-pro",
    "gemini-1.5-flash",
    "gpt-6-astra",
    "gpt-6.1-sol",
    "gpt-6.1-terra",
    "gpt-6-luna",
    "claude-fable-5-1",
    "claude-opus-5-6",
    "claude-opus-5-5",
    "claude-sonnet-5-5",
    "claude-haiku-5-5",
];

static FORBIDDEN_MODEL_ALIASES: &[&str] = &[
    "lm-studio",
    "ollama",
    "anthropic-local",
    "localai",
    "local-test",
    "local",
    "gemini",
    "openai",
    "anthropic",
];

pub(crate) fn is_forbidden_model_alias(model_id: &str) -> bool {
    let trimmed = model_id.trim();
    trimmed.is_empty()
        || FORBIDDEN_MODEL_ALIASES
            .iter()
            .any(|alias| alias.eq_ignore_ascii_case(trimmed))
}

pub(crate) fn is_valid_local_model_id(model_id: &str) -> bool {
    let trimmed = model_id.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 128
        && !is_forbidden_model_alias(trimmed)
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/' | '@'))
}

fn build_versioned_endpoint_url(validated_base: &str, v1_subpath: &str) -> String {
    let trimmed = validated_base.trim_end_matches('/');
    let without_v1 = trimmed
        .strip_suffix("/v1")
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    let clean_subpath = v1_subpath.trim_start_matches('/');
    format!("{without_v1}/v1/{clean_subpath}")
}

fn split_runtime_prefixed_model(raw: &str) -> (Option<&'static str>, &str) {
    let trimmed = raw.trim();
    for runtime in ["lm-studio", "ollama", "anthropic-local"] {
        if let Some(rest) = trimmed.strip_prefix(runtime) {
            if let Some(model_part) = rest.strip_prefix(':') {
                let model_trimmed = model_part.trim();
                if !model_trimmed.is_empty() {
                    return (Some(runtime), model_trimmed);
                }
            }
        }
    }
    (None, trimmed)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAction {
    #[serde(rename = "type")]
    pub action_type: String,
    pub action_id: i64,
    pub title: String,
    pub description: String,
    pub danger_level: String,
    pub impact: String,
}

#[derive(Debug, Clone)]
pub struct ProviderSettings {
    pub gemini_api_key: String,
    pub openai_api_key: String,
    pub anthropic_api_key: String,
    pub anthropic_endpoint: String,
    pub lm_studio_endpoint: String,
    pub ollama_endpoint: String,
    pub default_model: String,
    pub local_provider: String,
    pub local_model: String,
    pub system_prompt: String,
}

pub fn resolve_provider_settings() -> ProviderSettings {
    let mut ps = ProviderSettings {
        gemini_api_key: String::new(),
        openai_api_key: String::new(),
        anthropic_api_key: String::new(),
        anthropic_endpoint: String::new(),
        lm_studio_endpoint: String::new(),
        ollama_endpoint: String::new(),
        default_model: "gemini-4-argon".to_string(),
        local_provider: String::new(),
        local_model: String::new(),
        system_prompt: "You are FlowAI, a helpful server assistant.".to_string(),
    };

    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.query_row(
            "SELECT COALESCE(gemini_api_key, ''), COALESCE(openai_api_key, ''), COALESCE(anthropic_api_key, ''), \
             COALESCE(anthropic_endpoint, ''), COALESCE(lm_studio_endpoint, ''), COALESCE(ollama_endpoint, ''), \
             COALESCE(ai_model, ''), COALESCE(system_prompt, ''), \
             COALESCE(local_provider, ''), COALESCE(local_model, '') FROM settings WHERE id = 1",
            [],
            |r| {
                ps.gemini_api_key = r.get(0)?;
                ps.openai_api_key = r.get(1)?;
                ps.anthropic_api_key = r.get(2)?;
                ps.anthropic_endpoint = r.get(3)?;
                ps.lm_studio_endpoint = r.get(4)?;
                ps.ollama_endpoint = r.get(5)?;
                let m: String = r.get(6)?;
                let trimmed_m = m.trim();
                if !trimmed_m.is_empty() {
                    let (prefixed_rt, clean_m) = split_runtime_prefixed_model(trimmed_m);
                    if let Some(rt) = prefixed_rt {
                        ps.local_provider = rt.to_string();
                        ps.default_model = clean_m.to_string();
                        if !is_forbidden_model_alias(clean_m) {
                            ps.local_model = clean_m.to_string();
                        }
                    } else if matches!(trimmed_m, "lm-studio" | "ollama" | "anthropic-local") {
                        ps.local_provider = trimmed_m.to_string();
                        ps.default_model = trimmed_m.to_string();
                    } else {
                        ps.default_model = clean_m.to_string();
                        if !ALLOWED_AI_MODELS.contains(&clean_m) && is_valid_local_model_id(clean_m) {
                            ps.local_model = clean_m.to_string();
                        }
                    }
                }
                let sp: String = r.get(7)?;
                if !sp.is_empty() {
                    ps.system_prompt = sp;
                }
                let local_provider: String = r.get(8)?;
                let local_model: String = r.get(9)?;
                if is_valid_local_model_id(local_model.trim()) {
                    ps.local_model = local_model.trim().to_owned();
                }
                if !ALLOWED_AI_MODELS.contains(&ps.default_model.as_str())
                    && matches!(local_provider.trim(), "lm-studio" | "ollama" | "anthropic-local")
                {
                    ps.local_provider = local_provider.trim().to_owned();
                }
                Ok(())
            },
        );
    }

    if !ps.gemini_api_key.is_empty() {
        if let Ok(dec) = af_db::decrypt_key(&ps.gemini_api_key) {
            ps.gemini_api_key = dec;
        }
    }
    if !ps.openai_api_key.is_empty() {
        if let Ok(dec) = af_db::decrypt_key(&ps.openai_api_key) {
            ps.openai_api_key = dec;
        }
    }
    if !ps.anthropic_api_key.is_empty() {
        if let Ok(dec) = af_db::decrypt_key(&ps.anthropic_api_key) {
            ps.anthropic_api_key = dec;
        }
    }

    if ps.gemini_api_key.is_empty() {
        ps.gemini_api_key = env::var("GEMINI_API_KEY").unwrap_or_default();
    }
    if ps.openai_api_key.is_empty() {
        ps.openai_api_key = env::var("OPENAI_API_KEY").unwrap_or_default();
    }
    if ps.anthropic_api_key.is_empty() {
        ps.anthropic_api_key = env::var("ANTHROPIC_API_KEY").unwrap_or_default();
    }

    ps
}

fn infer_local_runtime(provider_hint: &str, ps: &ProviderSettings) -> &'static str {
    match provider_hint.trim() {
        "ollama" => return "ollama",
        "lm-studio" => return "lm-studio",
        "anthropic-local" => return "anthropic-local",
        _ => {}
    }
    match ps.local_provider.as_str() {
        "ollama" => return "ollama",
        "lm-studio" => return "lm-studio",
        "anthropic-local" => return "anthropic-local",
        _ => {}
    }
    let anthropic_ep = ps.anthropic_endpoint.trim();
    if !anthropic_ep.is_empty() && anthropic_ep != "https://api.anthropic.com" {
        return "anthropic-local";
    }
    let ollama_ep = ps.ollama_endpoint.trim();
    let lm_ep = ps.lm_studio_endpoint.trim();
    if !ollama_ep.is_empty()
        && ollama_ep != "http://localhost:11434"
        && (lm_ep.is_empty() || lm_ep == "http://localhost:1234")
    {
        return "ollama";
    }
    "lm-studio"
}

fn resolve_provider(provider_hint: &str, model_id: &str) -> &'static str {
    match provider_hint.trim() {
        "gemini" => return "gemini",
        "openai" => return "openai",
        "anthropic" => return "anthropic",
        "localai" | "lm-studio" | "ollama" | "anthropic-local" => return "localai",
        _ => {}
    }
    if model_id.starts_with("gemini") {
        "gemini"
    } else if model_id.starts_with("gpt") {
        "openai"
    } else if model_id.starts_with("claude") {
        "anthropic"
    } else if !ALLOWED_AI_MODELS.contains(&model_id) && is_valid_local_model_id(model_id) {
        "localai"
    } else {
        "gemini"
    }
}

pub fn get_system_metrics_context() -> String {
    let m = af_hardware::get_system_metrics_core();
    let mut sb = String::from("=== CURRENT SYSTEM METRICS ===\n");
    sb.push_str(&format!("CPU Usage: {:.1}%\n", m.cpu_usage));
    sb.push_str(&format!("CPU Frequency: {:.0} MHz\n", m.cpu_freq_mhz));
    if let (Some(&used), Some(&total)) = (m.memory.get("used"), m.memory.get("total")) {
        let pct = if total > 0.0 {
            (used / total) * 100.0
        } else {
            0.0
        };
        sb.push_str(&format!(
            "Memory: {:.2} / {:.2} GB ({:.1}%)\n",
            used, total, pct
        ));
    }
    for disk in &m.disks {
        sb.push_str(&format!(
            "Disk {} ({}): {:.1} / {:.1} GB ({:.1}% used)\n",
            disk.mount_point, disk.device, disk.used_gb, disk.total_gb, disk.used_pct
        ));
    }
    sb.push_str(&format!("Uptime: {}\n", m.uptime));
    if m.load_average.len() >= 3 {
        sb.push_str(&format!(
            "Load Average: {:.2} / {:.2} / {:.2}\n",
            m.load_average[0], m.load_average[1], m.load_average[2]
        ));
    }
    sb.push_str("=== END METRICS ===\n");
    sb
}

async fn call_gemini_api(
    api_key: &str,
    model_name: &str,
    system_prompt: &str,
    history: &[ChatMessage],
    message: &str,
) -> anyhow::Result<String> {
    if api_key.trim().is_empty() {
        anyhow::bail!("gemini API key not configured. Set it in Settings → FlowAI Engine");
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(90))
        .build()?;

    let mut contents = Vec::new();
    for hm in history {
        let role = if hm.role == "assistant" {
            "model"
        } else {
            "user"
        };
        contents.push(serde_json::json!({
            "role": role,
            "parts": [{ "text": hm.text }],
        }));
    }
    contents.push(serde_json::json!({
        "role": "user",
        "parts": [{ "text": message }],
    }));

    let mut body = serde_json::json!({ "contents": contents });
    if !system_prompt.trim().is_empty() {
        body["systemInstruction"] = serde_json::json!({
            "parts": [{ "text": system_prompt }]
        });
    }

    let send_for_model = |m: &str| {
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            m, api_key
        );
        client.post(url).json(&body).send()
    };

    let mut resp = send_for_model(model_name).await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND && model_name == "gemini-4-argon" {
        resp = send_for_model("gemini-2.5-pro").await?;
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("gemini API error ({}): {}", status, text);
    }

    let val: serde_json::Value = resp.json().await?;
    let mut out = String::new();
    if let Some(parts) = val
        .pointer("/candidates/0/content/parts")
        .and_then(|v| v.as_array())
    {
        for p in parts {
            if let Some(t) = p.get("text").and_then(|v| v.as_str()) {
                out.push_str(t);
            }
        }
    }
    Ok(out)
}

async fn call_openai_compatible_api(
    endpoint: &str,
    api_key: &str,
    model_name: &str,
    system_prompt: &str,
    history: &[ChatMessage],
    message: &str,
) -> anyhow::Result<String> {
    if is_forbidden_model_alias(model_name) {
        anyhow::bail!(
            "Invalid AI model identifier '{}': provider or locality aliases cannot be sent as inference model IDs",
            model_name.trim()
        );
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let mut messages = Vec::new();
    if !system_prompt.trim().is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": system_prompt }));
    }
    for hm in history {
        messages.push(serde_json::json!({ "role": hm.role, "content": hm.text }));
    }
    messages.push(serde_json::json!({ "role": "user", "content": message }));

    let endpoint = af_services::validate_server_url(endpoint)
        .map_err(|error| anyhow::anyhow!("Invalid AI endpoint: {error}"))?;
    let url = build_versioned_endpoint_url(&endpoint, "chat/completions");
    let mut req = client.post(&url).json(&serde_json::json!({
        "model": model_name.trim(),
        "messages": messages,
    }));
    if !api_key.is_empty() {
        req = req.bearer_auth(api_key);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("openai API error ({}): {}", status, text);
    }
    let val: serde_json::Value = resp.json().await?;
    let content = val
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(content)
}

async fn call_anthropic_api(
    endpoint: &str,
    api_key: &str,
    model_name: &str,
    system_prompt: &str,
    history: &[ChatMessage],
    message: &str,
) -> anyhow::Result<String> {
    if is_forbidden_model_alias(model_name) {
        anyhow::bail!(
            "Invalid AI model identifier '{}': provider or locality aliases cannot be sent as inference model IDs",
            model_name.trim()
        );
    }
    let base_raw = if endpoint.trim().is_empty() {
        "https://api.anthropic.com"
    } else {
        endpoint.trim().trim_end_matches('/')
    };
    let base = af_services::validate_server_url(base_raw)
        .map_err(|error| anyhow::anyhow!("Invalid AI endpoint: {error}"))?;
    if base == "https://api.anthropic.com" && api_key.trim().is_empty() {
        anyhow::bail!(
            "anthropic API key not configured. Set it in Settings \u{2192} FlowAI Engine"
        );
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let mut messages = Vec::new();
    for hm in history {
        messages.push(serde_json::json!({ "role": hm.role, "content": hm.text }));
    }
    messages.push(serde_json::json!({ "role": "user", "content": message }));

    let mut body = serde_json::json!({
        "model": model_name.trim(),
        "messages": messages,
        "max_tokens": 4096,
    });
    if !system_prompt.trim().is_empty() {
        body["system"] = serde_json::Value::String(system_prompt.to_string());
    }

    let url = build_versioned_endpoint_url(&base, "messages");
    let mut req = client
        .post(&url)
        .header("anthropic-version", "2023-06-01")
        .json(&body);
    if !api_key.trim().is_empty() {
        req = req.header("x-api-key", api_key);
    }

    let resp = req.send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("anthropic API error ({}): {}", status, text);
    }
    let val: serde_json::Value = resp.json().await?;
    let mut out = String::new();
    if let Some(arr) = val.get("content").and_then(|v| v.as_array()) {
        for block in arr {
            if block.get("type").and_then(|v| v.as_str()) == Some("text") {
                if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                    out.push_str(t);
                }
            }
        }
    }
    Ok(out)
}

fn extract_service_target(message: &str) -> &'static str {
    let lower = message.to_lowercase();
    for svc in [
        "apache2",
        "apache",
        "aetherflow-api",
        "aetherflow-runner",
        "nginx",
        "postgres",
        "postgresql",
        "redis",
        "qbittorrent",
        "qui",
        "autobrr",
        "sonarr",
        "radarr",
        "lidarr",
        "prowlarr",
        "plex",
        "jellyfin",
        "emby",
        "threadfin",
        "dispatcharr",
        "transmission",
        "deluge",
        "jackett",
        "wireguard",
        "tailscale",
        "traefik",
        "duplicati",
        "filebot",
        "listenarr",
        "notifiarr",
        "novnc",
        "pyload",
        "quassel",
        "requestrr",
        "seedcross",
        "unmanic",
        "x2go",
        "invidious",
        "piped",
    ] {
        if lower.contains(svc) {
            return svc;
        }
    }
    "target service"
}

fn extract_proposed_action(ai_reply: &str, user_message: &str) -> Option<ProposedAction> {
    let combined = format!("{} {}", ai_reply, user_message).to_lowercase();
    let specs: &[(&[&str], &str, &str, &str)] = &[
        (
            &["restart", "reboot"],
            "warn",
            "Restart",
            "Service will be temporarily unavailable during restart (5-30 seconds).",
        ),
        (
            &["stop", "shutdown"],
            "warn",
            "Stop",
            "Service will become unavailable until manually started.",
        ),
        (
            &["delete", "remove", "uninstall", "purge"],
            "critical",
            "Delete",
            "Data associated with this service may be permanently lost.",
        ),
        (
            &["update", "upgrade", "patch"],
            "warn",
            "Update",
            "Service will restart after update. Configuration may change.",
        ),
    ];

    for (keywords, classification, verb, impact) in specs {
        for kw in *keywords {
            if combined.contains(kw) {
                let target = extract_service_target(user_message);
                let title = format!("{} {}", verb, target);
                return Some(ProposedAction {
                    action_type: "system_action".to_string(),
                    action_id: 0,
                    title: title.clone(),
                    description: format!("AI-proposed: {}", title),
                    danger_level: (*classification).to_string(),
                    impact: (*impact).to_string(),
                });
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
async fn run_chat_session(
    user: Option<AuthUser>,
    ip: &str,
    ua: &str,
    system_prompt_override: &str,
    model_override: &str,
    provider_hint: &str,
    history: Vec<ChatMessage>,
    message: String,
) -> Response {
    let ps = resolve_provider_settings();
    let trimmed_override = model_override.trim();
    let (override_rt, clean_override) = split_runtime_prefixed_model(trimmed_override);

    if !trimmed_override.is_empty() && is_forbidden_model_alias(clean_override) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid AI model: provider or locality aliases cannot be used as model identifiers.",
        );
    }

    let effective_hint = if !provider_hint.trim().is_empty() {
        provider_hint.trim()
    } else if let Some(rt) = override_rt {
        rt
    } else if !ps.local_provider.is_empty() && trimmed_override.is_empty() {
        ps.local_provider.as_str()
    } else {
        ""
    };

    let ai_model = if !clean_override.is_empty() {
        clean_override.to_string()
    } else if !ps.local_model.is_empty()
        && matches!(
            effective_hint,
            "localai" | "lm-studio" | "ollama" | "anthropic-local"
        )
    {
        ps.local_model.clone()
    } else {
        ps.default_model.clone()
    };

    if is_forbidden_model_alias(&ai_model) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid AI model. Check settings for available models.",
        );
    }

    let provider_type = resolve_provider(effective_hint, &ai_model);
    if provider_type == "localai" {
        if !is_valid_local_model_id(&ai_model) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid AI model. Check settings for available models.",
            );
        }
    } else if !ALLOWED_AI_MODELS.contains(&ai_model.as_str()) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid AI model. Check settings for available models.",
        );
    }

    let prompt = if !system_prompt_override.is_empty() {
        system_prompt_override.to_string()
    } else if user.as_ref().map(|u| u.role == "admin").unwrap_or(false) {
        format!(
            "{}\n\nLive system telemetry from this AetherFlow server is attached below:\n\n{}",
            ps.system_prompt,
            get_system_metrics_context()
        )
    } else {
        ps.system_prompt.clone()
    };

    let result = match provider_type {
        "openai" => {
            if ps.openai_api_key.is_empty() {
                Err(anyhow::anyhow!(
                    "AI provider initialization failed: openai API key not configured. Set it in Settings \u{2192} FlowAI Engine"
                ))
            } else {
                call_openai_compatible_api(
                    "https://api.openai.com",
                    &ps.openai_api_key,
                    &ai_model,
                    &prompt,
                    &history,
                    &message,
                )
                .await
            }
        }
        "anthropic" => {
            call_anthropic_api(
                &ps.anthropic_endpoint,
                &ps.anthropic_api_key,
                &ai_model,
                &prompt,
                &history,
                &message,
            )
            .await
        }
        "localai" => {
            let local_runtime = infer_local_runtime(effective_hint, &ps);
            match local_runtime {
                "anthropic-local" => {
                    let endpoint = if !ps.anthropic_endpoint.is_empty() {
                        ps.anthropic_endpoint.clone()
                    } else {
                        "http://localhost:8080".to_string()
                    };
                    call_anthropic_api(
                        &endpoint,
                        &ps.anthropic_api_key,
                        &ai_model,
                        &prompt,
                        &history,
                        &message,
                    )
                    .await
                }
                "ollama" => {
                    let endpoint = if !ps.ollama_endpoint.is_empty() {
                        ps.ollama_endpoint.clone()
                    } else {
                        "http://localhost:11434".to_string()
                    };
                    call_openai_compatible_api(
                        &endpoint, "", &ai_model, &prompt, &history, &message,
                    )
                    .await
                }
                _ => {
                    let endpoint = if !ps.lm_studio_endpoint.is_empty() {
                        ps.lm_studio_endpoint.clone()
                    } else {
                        "http://localhost:1234".to_string()
                    };
                    call_openai_compatible_api(
                        &endpoint, "", &ai_model, &prompt, &history, &message,
                    )
                    .await
                }
            }
        }
        _ => call_gemini_api(&ps.gemini_api_key, &ai_model, &prompt, &history, &message).await,
    };

    let reply_text = match result {
        Ok(t) if !t.trim().is_empty() => t,
        Ok(_) => "I received an empty response. Please try again.".to_string(),
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                format!("Generation error: {}", e),
            );
        }
    };

    if let Some(mut proposal) = extract_proposed_action(&reply_text, &message) {
        let (action_id, needs_approval) = af_db::queue_action(
            &proposal.danger_level,
            "FlowAI",
            &proposal.title,
            &proposal.description,
        );
        if needs_approval {
            proposal.action_id = action_id;
            let (uid, uname) = user
                .map(|u| (u.user_id, u.username))
                .unwrap_or((0, "anonymous".to_string()));
            af_db::record_audit(
                uid,
                &uname,
                "ai_action_proposed",
                "pending_action",
                &action_id.to_string(),
                &format!(
                    "classification={} title={}",
                    proposal.danger_level, proposal.title
                ),
                ip,
                ua,
            );
            return Json(serde_json::json!({
                "reply": reply_text,
                "proposed_action": proposal,
            }))
            .into_response();
        }
    }

    Json(serde_json::json!({ "reply": reply_text })).into_response()
}

pub async fn ai_chat(req: Request) -> Response {
    let user = req.extensions().get::<AuthUser>().cloned();
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 512 * 1024).await else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid body");
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON");
    };
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if message.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "message is required",
        );
    }
    let model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let provider = body
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let history: Vec<ChatMessage> = body
        .get("history")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    run_chat_session(user, &ip, &ua, "", &model, &provider, history, message).await
}

pub async fn ai_support(req: Request) -> Response {
    let user = req.extensions().get::<AuthUser>().cloned();
    if user.as_ref().map(|u| u.role.as_str()) != Some("admin") {
        return api_error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Forbidden: Admin access required for AI support diagnostics",
        );
    }
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 512 * 1024).await else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid body");
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON");
    };
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if message.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "message is required",
        );
    }
    let context_mode = body
        .get("context_mode")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("full");
    if !["logs", "metrics", "full"].contains(&context_mode) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid context_mode. Allowed: logs, metrics, full",
        );
    }
    let model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let provider = body
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let history: Vec<ChatMessage> = body
        .get("history")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let ps = resolve_provider_settings();
    let support_prompt = format!(
        "{}\n\nYou are in SUPPORT MODE. The user is troubleshooting a server issue. Use the following live system data to help diagnose problems:\n\n{}\nAnalyze the above data in context of the user's question.",
        ps.system_prompt,
        get_system_metrics_context()
    );

    run_chat_session(
        user,
        &ip,
        &ua,
        &support_prompt,
        &model,
        &provider,
        history,
        message,
    )
    .await
}

pub async fn test_ai_connection(
    axum::Extension(user): axum::Extension<AuthUser>,
    Json(req): Json<serde_json::Value>,
) -> Response {
    if user.role != "admin" {
        return api_error(StatusCode::FORBIDDEN, "FORBIDDEN", "Admin access required");
    }
    let mut ps = resolve_provider_settings();
    let provider_type = req
        .get("provider")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("gemini");

    if let Some(k) = req
        .get("gemini_api_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("****"))
    {
        ps.gemini_api_key = k.to_string();
    }
    if let Some(k) = req
        .get("openai_api_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("****"))
    {
        ps.openai_api_key = k.to_string();
    }
    if let Some(k) = req
        .get("anthropic_api_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("****"))
    {
        ps.anthropic_api_key = k.to_string();
    }
    if let Some(ep) = req
        .get("endpoint")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Ok(clean_ep) = af_services::validate_server_url(ep) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid or disallowed endpoint URL",
            );
        };
        ps.anthropic_endpoint = clean_ep.clone();
        ps.lm_studio_endpoint = clean_ep.clone();
        ps.ollama_endpoint = clean_ep;
    }
    if let Some(ep) = req
        .get("anthropic_endpoint")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Ok(clean_ep) = af_services::validate_server_url(ep) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid or disallowed endpoint URL",
            );
        };
        ps.anthropic_endpoint = clean_ep;
    }
    if let Some(ep) = req
        .get("lm_studio_endpoint")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Ok(clean_ep) = af_services::validate_server_url(ep) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid or disallowed endpoint URL",
            );
        };
        ps.lm_studio_endpoint = clean_ep;
    }
    if let Some(ep) = req
        .get("ollama_endpoint")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Ok(clean_ep) = af_services::validate_server_url(ep) else {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid or disallowed endpoint URL",
            );
        };
        ps.ollama_endpoint = clean_ep;
    }

    let requested_model = req
        .get("model")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(m) = requested_model {
        let (_, clean_m) = split_runtime_prefixed_model(m);
        if is_forbidden_model_alias(clean_m) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Invalid AI model: provider or locality aliases cannot be used as model identifiers",
            );
        }
    }

    let res = match provider_type {
        "openai" => {
            let model = requested_model.unwrap_or_else(|| {
                if ps.default_model.starts_with("gpt-") {
                    ps.default_model.as_str()
                } else {
                    "gpt-6.1-sol"
                }
            });
            if !ALLOWED_AI_MODELS.contains(&model) {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid AI model");
            }
            call_openai_compatible_api(
                "https://api.openai.com",
                &ps.openai_api_key,
                model,
                "",
                &[],
                "Reply with the exact word: SUCCESS",
            )
            .await
        }
        "anthropic" => {
            let model = requested_model.unwrap_or_else(|| {
                if ps.default_model.starts_with("claude-") {
                    ps.default_model.as_str()
                } else {
                    "claude-sonnet-5-5"
                }
            });
            if !ALLOWED_AI_MODELS.contains(&model) && !is_valid_local_model_id(model) {
                return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid AI model");
            }
            call_anthropic_api(
                &ps.anthropic_endpoint,
                &ps.anthropic_api_key,
                model,
                "",
                &[],
                "Reply with the exact word: SUCCESS",
            )
            .await
        }
        "localai" | "lm-studio" | "ollama" | "anthropic-local" => {
            let explicit_local_rt = req
                .get("local_provider")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(provider_type);
            let local_runtime = infer_local_runtime(explicit_local_rt, &ps);
            let local_model = if let Some(m) = requested_model {
                let (_, clean_m) = split_runtime_prefixed_model(m);
                clean_m
            } else if !ps.local_model.is_empty() {
                ps.local_model.as_str()
            } else if !is_forbidden_model_alias(&ps.default_model)
                && !ALLOWED_AI_MODELS.contains(&ps.default_model.as_str())
            {
                ps.default_model.as_str()
            } else {
                "qwen2.5-coder:7b"
            };
            if !is_valid_local_model_id(local_model) {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "BAD_REQUEST",
                    "Invalid local AI model identifier",
                );
            }
            match local_runtime {
                "anthropic-local" => {
                    let ep = if !ps.anthropic_endpoint.is_empty() {
                        ps.anthropic_endpoint.clone()
                    } else {
                        "http://localhost:8080".to_string()
                    };
                    call_anthropic_api(
                        &ep,
                        &ps.anthropic_api_key,
                        local_model,
                        "",
                        &[],
                        "Reply with the exact word: SUCCESS",
                    )
                    .await
                }
                "ollama" => {
                    let ep = if !ps.ollama_endpoint.is_empty() {
                        ps.ollama_endpoint.clone()
                    } else {
                        "http://localhost:11434".to_string()
                    };
                    call_openai_compatible_api(
                        &ep,
                        "",
                        local_model,
                        "",
                        &[],
                        "Reply with the exact word: SUCCESS",
                    )
                    .await
                }
                _ => {
                    let ep = if !ps.lm_studio_endpoint.is_empty() {
                        ps.lm_studio_endpoint.clone()
                    } else {
                        "http://localhost:1234".to_string()
                    };
                    call_openai_compatible_api(
                        &ep,
                        "",
                        local_model,
                        "",
                        &[],
                        "Reply with the exact word: SUCCESS",
                    )
                    .await
                }
            }
        }
        _ => {
            let model = requested_model.unwrap_or_else(|| {
                if ps.default_model.starts_with("gemini-") {
                    ps.default_model.as_str()
                } else {
                    "gemini-4-argon"
                }
            });
            call_gemini_api(
                &ps.gemini_api_key,
                model,
                "",
                &[],
                "Reply with the exact word: SUCCESS",
            )
            .await
        }
    };

    match res {
        Ok(_) => Json(serde_json::json!({
            "message": format!("{} connection successful", provider_type),
        }))
        .into_response(),
        Err(e) => api_error(
            StatusCode::BAD_GATEWAY,
            "AI_CONNECTION_FAILED",
            format!("Connection test failed: {}", e),
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Metadata Enricher, Bandwidth, Predictions & MediaFlow
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct EnricherState {
    scanning: bool,
    progress: f64,
    total: usize,
    done: usize,
    processed: usize,
    results: Vec<serde_json::Value>,
    last_err: String,
}

static ENRICHER_STATE: Lazy<Mutex<EnricherState>> =
    Lazy::new(|| Mutex::new(EnricherState::default()));

static MEDIA_EXTENSIONS: &[&str] = &[
    ".mkv", ".mp4", ".avi", ".mov", ".m4v", ".wmv", ".flv", ".webm", ".ts", ".srt", ".ass", ".ssa",
    ".sub", ".vtt", ".flac", ".mp3", ".aac", ".ogg", ".opus",
];

pub(crate) fn clean_json_fence(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if let Some(rest) = s.strip_prefix("```json") {
        s = rest.to_string();
    } else if let Some(rest) = s.strip_prefix("```") {
        s = rest.to_string();
    }
    if let Some(rest) = s.strip_suffix("```") {
        s = rest.to_string();
    }
    s.trim().to_string()
}

pub(crate) async fn call_configured_ai(
    ps: &ProviderSettings,
    system_prompt: &str,
    message: &str,
) -> anyhow::Result<String> {
    let provider = resolve_provider(&ps.local_provider, &ps.default_model);
    match provider {
        "openai" if !ps.openai_api_key.is_empty() => {
            call_openai_compatible_api(
                "https://api.openai.com",
                &ps.openai_api_key,
                &ps.default_model,
                system_prompt,
                &[],
                message,
            )
            .await
        }
        "anthropic" if !ps.anthropic_api_key.is_empty() => {
            call_anthropic_api(
                &ps.anthropic_endpoint,
                &ps.anthropic_api_key,
                &ps.default_model,
                system_prompt,
                &[],
                message,
            )
            .await
        }
        "localai" => {
            let local_model = if !ps.local_model.is_empty() {
                ps.local_model.as_str()
            } else if !is_forbidden_model_alias(&ps.default_model) {
                ps.default_model.as_str()
            } else {
                anyhow::bail!("Local AI model identifier is not configured");
            };
            let runtime = infer_local_runtime(&ps.local_provider, ps);
            match runtime {
                "anthropic-local" => {
                    let ep = if ps.anthropic_endpoint.is_empty() {
                        "http://localhost:8080".to_string()
                    } else {
                        ps.anthropic_endpoint.clone()
                    };
                    call_anthropic_api(
                        &ep,
                        &ps.anthropic_api_key,
                        local_model,
                        system_prompt,
                        &[],
                        message,
                    )
                    .await
                }
                "ollama" => {
                    let ep = if ps.ollama_endpoint.is_empty() {
                        "http://localhost:11434".to_string()
                    } else {
                        ps.ollama_endpoint.clone()
                    };
                    call_openai_compatible_api(&ep, "", local_model, system_prompt, &[], message)
                        .await
                }
                _ => {
                    let ep = if ps.lm_studio_endpoint.is_empty() {
                        "http://localhost:1234".to_string()
                    } else {
                        ps.lm_studio_endpoint.clone()
                    };
                    call_openai_compatible_api(&ep, "", local_model, system_prompt, &[], message)
                        .await
                }
            }
        }
        _ => {
            if !ps.gemini_api_key.is_empty() {
                let model = if ps.default_model.starts_with("gemini") {
                    ps.default_model.as_str()
                } else {
                    "gemini-2.5-flash"
                };
                call_gemini_api(&ps.gemini_api_key, model, system_prompt, &[], message).await
            } else if !ps.openai_api_key.is_empty() {
                call_openai_compatible_api(
                    "https://api.openai.com",
                    &ps.openai_api_key,
                    "gpt-6.1-sol",
                    system_prompt,
                    &[],
                    message,
                )
                .await
            } else if !ps.anthropic_api_key.is_empty() {
                call_anthropic_api(
                    &ps.anthropic_endpoint,
                    &ps.anthropic_api_key,
                    "claude-sonnet-5-5",
                    system_prompt,
                    &[],
                    message,
                )
                .await
            } else {
                anyhow::bail!("No AI provider API key configured")
            }
        }
    }
}

fn collect_files_recursive(dir: &StdPath, allowed_exts: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();
        if file_name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_files_recursive(&path, allowed_exts, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let dot_ext = format!(".{}", ext.to_lowercase());
            if allowed_exts.iter().any(|&a| a == dot_ext) {
                out.push(path);
            }
        }
    }
}

fn parse_filename_metadata(filename: &str) -> (String, String, String, String, Vec<String>) {
    static YEAR_RE: Lazy<regex::Regex> =
        Lazy::new(|| regex::Regex::new(r"\b(19\d{2}|20\d{2})\b").unwrap());
    static QUALITY_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"(?i)\b(2160p|4k|1080p|720p|480p|bluray|blu-ray|web-dl|webdl|webrip|remux|hdtv)\b",
        )
        .unwrap()
    });
    static CODEC_RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"(?i)\b(hevc|x265|h\.?265|av1|x264|h\.?264|10bit|hdr10|dv)\b").unwrap()
    });

    let stem = StdPath::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);

    let year = YEAR_RE
        .find(stem)
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    let mut quality_parts: Vec<String> = Vec::new();
    for m in QUALITY_RE.find_iter(stem) {
        let tok = m.as_str();
        let norm = match tok.to_lowercase().as_str() {
            "4k" | "2160p" => "2160p".to_string(),
            "1080p" => "1080p".to_string(),
            "720p" => "720p".to_string(),
            "480p" => "480p".to_string(),
            "bluray" | "blu-ray" => "BluRay".to_string(),
            "web-dl" | "webdl" => "WEB-DL".to_string(),
            "webrip" => "WEBRip".to_string(),
            "remux" => "Remux".to_string(),
            "hdtv" => "HDTV".to_string(),
            other => other.to_uppercase(),
        };
        if !quality_parts.contains(&norm) {
            quality_parts.push(norm);
        }
    }
    for m in CODEC_RE.find_iter(stem) {
        let tok = m.as_str().to_uppercase().replace('.', "");
        let norm = if tok == "X265" || tok == "H265" {
            "HEVC".to_string()
        } else if tok == "X264" {
            "H264".to_string()
        } else {
            tok
        };
        if !quality_parts.contains(&norm) {
            quality_parts.push(norm);
        }
    }
    let quality = if quality_parts.is_empty() {
        "Unknown".to_string()
    } else {
        quality_parts.join(" ")
    };

    // Extract clean title up to the year or quality token
    let mut cutoff_idx = stem.len();
    if let Some(m) = YEAR_RE.find(stem) {
        if m.start() > 0 {
            cutoff_idx = cutoff_idx.min(m.start());
        }
    }
    if let Some(m) = QUALITY_RE.find(stem) {
        if m.start() > 0 {
            cutoff_idx = cutoff_idx.min(m.start());
        }
    }
    let raw_title = &stem[..cutoff_idx];
    let cleaned_title = raw_title
        .replace(['.', '_', '-'], " ")
        .replace(['[', ']', '(', ')'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let title = if cleaned_title.is_empty() {
        stem.replace(['.', '_'], " ").trim().to_string()
    } else {
        cleaned_title
    };

    let lower = stem.to_lowercase();
    let language =
        if lower.contains("japanese") || lower.contains(".jpn.") || lower.contains("dual") {
            "ja".to_string()
        } else if lower.contains("spanish") || lower.contains(".spa.") {
            "es".to_string()
        } else if lower.contains("french") || lower.contains(".fre.") {
            "fr".to_string()
        } else if lower.contains("german") || lower.contains(".ger.") {
            "de".to_string()
        } else {
            "en".to_string()
        };

    let mut subs = Vec::new();
    if lower.contains("sub") || lower.contains("multi") {
        subs.push("en".to_string());
    }

    (title, year, language, quality, subs)
}

fn upsert_media_metadata_row(
    file_path: &str,
    filename: &str,
    title: &str,
    year: &str,
    language: &str,
    quality: &str,
    subtitles: &[String],
) -> Option<serde_json::Value> {
    let Ok(conn) = af_db::get_conn() else {
        return None;
    };
    let subs_json = serde_json::to_string(subtitles).unwrap_or_else(|_| "[]".to_string());
    let now_str = Utc::now().to_rfc3339();

    let updated = conn
        .execute(
            "UPDATE media_metadata SET filename = ?2, title = ?3, year = ?4, language = ?5, quality = ?6, subtitles_json = ?7, enriched_at = ?8 WHERE file_path = ?1",
            params![file_path, filename, title, year, language, quality, subs_json, now_str],
        )
        .unwrap_or(0);

    if updated == 0 {
        let _ = conn.execute(
            "INSERT INTO media_metadata (file_path, filename, title, year, language, quality, subtitles_json, enriched_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![file_path, filename, title, year, language, quality, subs_json, now_str],
        );
    }

    let id = conn
        .query_row(
            "SELECT id FROM media_metadata WHERE file_path = ?1 ORDER BY id DESC LIMIT 1",
            params![file_path],
            |r| r.get::<_, i64>(0),
        )
        .unwrap_or(0);

    Some(serde_json::json!({
        "id": id,
        "file_path": file_path,
        "filename": filename,
        "title": title,
        "year": year,
        "language": language,
        "quality": quality,
        "subtitles_json": subs_json,
        "enriched_at": now_str,
    }))
}

pub async fn metadata_scan(Json(req): Json<serde_json::Value>) -> Response {
    let raw_path = req
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if raw_path.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "path is required");
    }
    if raw_path.contains("..") {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Path traversal not allowed",
        );
    }
    let allowed_roots = mediaflow_library_roots();
    let clean_path = match validate_mediaflow_directory(&PathBuf::from(raw_path), &allowed_roots) {
        Ok(path) => path,
        Err((status, message)) => return api_error(status, "INVALID_SCAN_PATH", message),
    };

    {
        let st = ENRICHER_STATE.lock().unwrap();
        if st.scanning {
            return api_error(
                StatusCode::CONFLICT,
                "CONFLICT",
                "A scan is already in progress",
            );
        }
    }

    let mut media_files = Vec::new();
    collect_files_recursive(&clean_path, MEDIA_EXTENSIONS, &mut media_files);
    let total_files = media_files.len();

    if let Ok(mut st) = ENRICHER_STATE.lock() {
        st.scanning = true;
        st.progress = 0.0;
        st.total = total_files;
        st.done = 0;
        st.processed = 0;
        st.results.clear();
        st.last_err.clear();
    }

    let ps = resolve_provider_settings();
    let has_gemini_key = !ps.gemini_api_key.is_empty();

    // First pass: deterministically parse filenames and persist immediately so results
    // and progress are immediately available even before optional AI enrichment completes.
    let mut enriched_items = Vec::with_capacity(total_files);
    for (idx, path) in media_files.iter().enumerate() {
        let file_path_str = path.to_string_lossy().to_string();
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let (title, year, language, quality, subs) = parse_filename_metadata(&filename);
        if let Some(row) = upsert_media_metadata_row(
            &file_path_str,
            &filename,
            &title,
            &year,
            &language,
            &quality,
            &subs,
        ) {
            enriched_items.push(row);
        }
        if let Ok(mut st) = ENRICHER_STATE.lock() {
            st.done = idx + 1;
            st.processed = idx + 1;
            st.progress = if total_files > 0 {
                ((idx + 1) as f64 / total_files as f64) * 100.0
            } else {
                100.0
            };
        }
    }

    if let Ok(mut st) = ENRICHER_STATE.lock() {
        st.results = enriched_items;
        st.progress = 100.0;
        if !has_gemini_key || media_files.is_empty() {
            st.scanning = false;
        }
    }

    if has_gemini_key && !media_files.is_empty() {
        let api_key = ps.gemini_api_key.clone();
        tokio::spawn(async move {
            let batch_size = 10usize;
            let total = media_files.len();
            let mut updated_results = Vec::new();

            for (start, chunk) in media_files.chunks(batch_size).enumerate() {
                let filenames: Vec<String> = chunk
                    .iter()
                    .filter_map(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .map(|s| s.to_string())
                    })
                    .collect();
                let prompt = format!(
                    "Parse these media filenames and extract structured metadata. Return a JSON array where each element has: \"filename\", \"title\", \"year\", \"language\" (ISO 639-1), \"quality\" (e.g., 1080p BluRay), \"subtitles\" (array of likely subtitle languages). Only return valid JSON, no markdown.\n\nFilenames:\n{}",
                    filenames.join("\n")
                );
                if let Ok(resp_text) =
                    call_gemini_api(&api_key, "gemini-2.0-flash", "", &[], &prompt).await
                {
                    let cleaned = clean_json_fence(&resp_text);
                    if let Ok(parsed_arr) = serde_json::from_str::<Vec<serde_json::Value>>(&cleaned)
                    {
                        for (i, item) in parsed_arr.iter().enumerate() {
                            if let Some(full_path) = chunk.get(i) {
                                let fp_str = full_path.to_string_lossy().to_string();
                                let fname =
                                    full_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                                let (def_title, def_year, def_lang, def_qual, def_subs) =
                                    parse_filename_metadata(fname);
                                let title = item
                                    .get("title")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_title);
                                let year = item
                                    .get("year")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_year);
                                let language = item
                                    .get("language")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_lang);
                                let quality = item
                                    .get("quality")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&def_qual);
                                let subs: Vec<String> = item
                                    .get("subtitles")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                                    .unwrap_or(def_subs);
                                if let Some(row) = upsert_media_metadata_row(
                                    &fp_str, fname, title, year, language, quality, &subs,
                                ) {
                                    updated_results.push(row);
                                }
                            }
                        }
                    }
                }
                let done_count = ((start + 1) * batch_size).min(total);
                if let Ok(mut st) = ENRICHER_STATE.lock() {
                    st.done = done_count;
                    st.processed = done_count;
                    st.progress = (done_count as f64 / total as f64) * 100.0;
                    if !updated_results.is_empty() {
                        st.results = updated_results.clone();
                    }
                }
            }

            if let Ok(mut st) = ENRICHER_STATE.lock() {
                st.scanning = false;
                st.progress = 100.0;
            }
        });
    }

    Json(serde_json::json!({
        "message": "Metadata enrichment scan started",
        "path": raw_path,
        "total": total_files,
    }))
    .into_response()
}

pub async fn metadata_status() -> Response {
    let st = ENRICHER_STATE.lock().unwrap();
    Json(serde_json::json!({
        "scanning": st.scanning,
        "progress": st.progress,
        "total": st.total,
        "done": st.done,
        "processed": st.processed,
        "results": st.results,
        "error": st.last_err,
    }))
    .into_response()
}

pub async fn metadata_results() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return Json(serde_json::json!([])).into_response();
    };
    let mut results = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, file_path, filename, COALESCE(title, ''), COALESCE(year, ''), \
         COALESCE(language, ''), COALESCE(quality, ''), COALESCE(subtitles_json, '[]'), COALESCE(enriched_at, '') \
         FROM media_metadata ORDER BY enriched_at DESC, id DESC LIMIT 200",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "file_path": r.get::<_, String>(1)?,
                "filename": r.get::<_, String>(2)?,
                "title": r.get::<_, String>(3)?,
                "year": r.get::<_, String>(4)?,
                "language": r.get::<_, String>(5)?,
                "quality": r.get::<_, String>(6)?,
                "subtitles_json": r.get::<_, String>(7)?,
                "enriched_at": r.get::<_, String>(8)?,
            }))
        }) {
            for item in rows.flatten() {
                results.push(item);
            }
        }
    }
    Json(results).into_response()
}

pub async fn bandwidth_analyze() -> Response {
    let ps = resolve_provider_settings();
    let m = af_hardware::get_system_metrics_core();
    let active_services = af_services::get_active_services();
    let streaming = af_services::get_streaming_dashboard(7, true);
    let active_streams = streaming.live_summary.active_streams;
    let active_transcodes = streaming.live_summary.transcode_count;

    let mem_used = m.memory.get("used").copied().unwrap_or(0.0);
    let mem_total = m.memory.get("total").copied().unwrap_or(0.0);
    let mem_pct = if mem_total > 0.0 {
        (mem_used / mem_total) * 100.0
    } else {
        0.0
    };
    let disk_read_bps = m.disk_io.get("read_bytes_sec").copied().unwrap_or(0.0);
    let disk_write_bps = m.disk_io.get("write_bytes_sec").copied().unwrap_or(0.0);
    let disk_io_mb_s = (disk_read_bps + disk_write_bps) / (1024.0 * 1024.0);

    // Dynamic bandwidth calculation scaled by CPU, disk I/O, and active media streams
    let base_down_kbps: i64 = 102_400; // 100 MB/s baseline
    let base_up_kbps: i64 = 51_200; // 50 MB/s baseline

    let load_factor = if m.cpu_usage > 85.0 || disk_io_mb_s > 250.0 {
        0.45
    } else if m.cpu_usage > 65.0 || active_transcodes > 0 {
        0.70
    } else if m.cpu_usage < 25.0 && active_streams == 0 {
        1.25
    } else {
        1.0
    };

    let stream_headroom_kbps = (active_streams as i64) * 6_000 + (active_transcodes as i64) * 8_000;
    let recommended_download_kbps =
        (((base_down_kbps as f64) * load_factor) as i64 - stream_headroom_kbps).max(10_240);
    let recommended_upload_kbps =
        (((base_up_kbps as f64) * load_factor) as i64 - stream_headroom_kbps).max(5_120);

    let swarm_health = if m.cpu_usage > 85.0 || mem_pct > 90.0 || disk_io_mb_s > 250.0 {
        "congested"
    } else if m.cpu_usage < 25.0 && active_streams == 0 {
        "underutilized"
    } else {
        "healthy"
    };

    let mut suggestions = vec![
        "Maintain 20% egress headroom for Jellyfin direct-stream spikes".to_string(),
        "Enable alternative speed limits during active transcoding sessions".to_string(),
    ];
    if active_streams > 0 {
        suggestions.push(format!(
            "Reserved {} kbps egress headroom for {} active media stream(s)",
            stream_headroom_kbps, active_streams
        ));
    }
    if disk_io_mb_s > 100.0 {
        suggestions.push(format!(
            "Disk I/O throughput is {:.1} MB/s; throttle concurrent torrent writes to reduce seek contention",
            disk_io_mb_s
        ));
    }

    let prompt = format!(
        "Analyze the current server state and recommend optimal torrent bandwidth limits.\n\n{}\n\nActive Streams: {} (Transcodes: {})\nDisk I/O: {:.2} MB/s\n\nReturn a JSON object with these exact fields:\n- \"recommended_upload_kbps\": integer (in KB/s)\n- \"recommended_download_kbps\": integer (in KB/s)\n- \"reasoning\": string (1-2 sentences explaining why)\n- \"confidence\": float (0.0-1.0)\n- \"swarm_health\": string (\"healthy\", \"congested\", or \"underutilized\")\n- \"suggestions\": array of strings (2-3 actionable tips)\n\nOnly return valid JSON, no markdown fences.",
        get_system_metrics_context(),
        active_streams,
        active_transcodes,
        disk_io_mb_s
    );

    if let Ok(ai_text) = call_configured_ai(
        &ps,
        "You are an expert network traffic engineer for a media server running torrent clients alongside streaming services (Plex/Jellyfin).",
        &prompt,
    )
    .await
    {
        let cleaned = clean_json_fence(&ai_text);
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&cleaned) {
            if parsed.get("recommended_upload_kbps").is_some()
                && parsed.get("recommended_download_kbps").is_some()
            {
                return Json(parsed).into_response();
            }
        }
    }

    Json(serde_json::json!({
        "recommended_upload_kbps": recommended_upload_kbps,
        "recommended_download_kbps": recommended_download_kbps,
        "reasoning": format!(
            "Evaluated live CPU load ({:.1}%), memory utilization ({:.1}%), disk I/O ({:.1} MB/s), and {} active service(s) / {} active stream(s).",
            m.cpu_usage,
            mem_pct,
            disk_io_mb_s,
            active_services.len(),
            active_streams
        ),
        "confidence": 0.89,
        "swarm_health": swarm_health,
        "suggestions": suggestions,
    }))
    .into_response()
}

pub async fn bandwidth_apply(Json(req): Json<serde_json::Value>) -> Response {
    let upload_kbps = req.get("upload_kbps").and_then(|v| v.as_i64()).unwrap_or(0);
    let download_kbps = req
        .get("download_kbps")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let payload = serde_json::json!({
        "method": "session-set",
        "arguments": {
            "alt-speed-down": download_kbps,
            "alt-speed-up": upload_kbps,
            "alt-speed-enabled": true,
        }
    });

    match client
        .post("http://127.0.0.1:9091/transmission/rpc")
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if status != reqwest::StatusCode::OK {
                return api_error(
                    StatusCode::BAD_GATEWAY,
                    "BAD_GATEWAY",
                    "Torrent daemon rejected RPC request",
                );
            }
            Json(serde_json::json!({
                "message": "Limits applied successfully to Torrent engine via RPC",
                "upload_kbps": upload_kbps,
                "download_kbps": download_kbps,
                "rpc_response": text,
            }))
            .into_response()
        }
        Err(_) => api_error(
            StatusCode::GATEWAY_TIMEOUT,
            "GATEWAY_TIMEOUT",
            "Torrent daemon RPC timeout or unreachable",
        ),
    }
}

fn compute_linear_slope(values: &[f64]) -> f64 {
    let n = values.len();
    if n < 2 {
        return 0.0;
    }
    let nf = n as f64;
    let mut sum_x = 0.0;
    let mut sum_y = 0.0;
    let mut sum_xy = 0.0;
    let mut sum_x2 = 0.0;
    for (i, &v) in values.iter().enumerate() {
        let x = i as f64;
        sum_x += x;
        sum_y += v;
        sum_xy += x * v;
        sum_x2 += x * x;
    }
    let denom = nf * sum_x2 - sum_x * sum_x;
    if denom.abs() < 1e-12 {
        return 0.0;
    }
    (nf * sum_xy - sum_x * sum_y) / denom
}

fn classify_metric_trend(
    slope: f64,
    avg_val: f64,
    max_val: f64,
    crit_threshold: f64,
) -> &'static str {
    if max_val >= crit_threshold || avg_val >= crit_threshold * 0.95 {
        "critical"
    } else if slope > 0.05 {
        "increasing"
    } else if slope < -0.05 {
        "decreasing"
    } else {
        "stable"
    }
}

async fn build_resource_predictions(invoke_ai: bool) -> serde_json::Value {
    let m = af_hardware::get_system_metrics_core();
    let disk_pct = m.disks.first().map(|d| d.used_pct).unwrap_or(0.0);
    let disk_free_gb = m
        .disks
        .first()
        .map(|d| (d.total_gb - d.used_gb).max(0.0))
        .unwrap_or(100.0);

    #[derive(Clone)]
    struct HistPoint {
        cpu_avg: f64,
        mem_used_gb: f64,
        mem_total_gb: f64,
        disk_write_bps: f64,
        net_rx_bytes: i64,
        net_tx_bytes: i64,
        load_avg_1: f64,
    }

    let mut history: Vec<HistPoint> = Vec::new();
    if let Ok(conn) = af_db::get_conn() {
        let cutoff = (Utc::now() - Duration::days(30))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        if let Ok(mut stmt) = conn.prepare(METRICS_PREDICTIONS_HISTORY_SQL) {
            if let Ok(rows) = stmt.query_map(params![cutoff], |row| {
                Ok(HistPoint {
                    cpu_avg: row.get(1)?,
                    mem_used_gb: row.get(2)?,
                    mem_total_gb: row.get(3)?,
                    disk_write_bps: row.get(5)?,
                    net_rx_bytes: row.get(6)?,
                    net_tx_bytes: row.get(7)?,
                    load_avg_1: row.get(8)?,
                })
            }) {
                for pt in rows.flatten() {
                    history.push(pt);
                }
            }
        }
        history.reverse();
    }

    let mut cpu_vals = Vec::with_capacity(history.len().max(1));
    let mut mem_pcts = Vec::with_capacity(history.len().max(1));
    let mut disk_writes = Vec::with_capacity(history.len().max(1));
    let mut net_totals = Vec::with_capacity(history.len().max(1));
    let mut anomalies: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    if history.is_empty() {
        cpu_vals.push(m.cpu_usage);
        let used = m.memory.get("used").copied().unwrap_or(0.0);
        let total = m.memory.get("total").copied().unwrap_or(0.0);
        mem_pcts.push(if total > 0.0 {
            (used / total) * 100.0
        } else {
            0.0
        });
        disk_writes.push(m.disk_io.get("write_bytes_sec").copied().unwrap_or(0.0));
        net_totals.push(
            (m.total_net_bytes.get("rx").copied().unwrap_or(0)
                + m.total_net_bytes.get("tx").copied().unwrap_or(0)) as f64,
        );
    } else {
        for pt in &history {
            cpu_vals.push(pt.cpu_avg);
            let mp = if pt.mem_total_gb > 0.0 {
                (pt.mem_used_gb / pt.mem_total_gb) * 100.0
            } else {
                0.0
            };
            mem_pcts.push(mp);
            disk_writes.push(pt.disk_write_bps);
            net_totals.push((pt.net_rx_bytes.saturating_add(pt.net_tx_bytes)) as f64);
        }
    }

    let n = cpu_vals.len() as f64;
    let cpu_avg = cpu_vals.iter().sum::<f64>() / n;
    let cpu_max = cpu_vals.iter().copied().fold(0.0_f64, f64::max);
    let mem_avg = mem_pcts.iter().sum::<f64>() / n;
    let mem_max = mem_pcts.iter().copied().fold(0.0_f64, f64::max);
    let disk_write_avg = disk_writes.iter().sum::<f64>() / n;
    let load_avg = if history.is_empty() {
        m.load_average.first().copied().unwrap_or(0.0)
    } else {
        history.iter().map(|h| h.load_avg_1).sum::<f64>() / (history.len() as f64)
    };

    let cpu_slope = compute_linear_slope(&cpu_vals);
    let mem_slope = compute_linear_slope(&mem_pcts);
    let disk_io_slope = compute_linear_slope(&disk_writes);
    let net_slope = compute_linear_slope(&net_totals);

    let cpu_trend = classify_metric_trend(cpu_slope, cpu_avg, cpu_max, 90.0);
    let memory_trend = classify_metric_trend(mem_slope, mem_avg, mem_max, 92.0);
    let disk_trend = if disk_pct >= 92.0 {
        "critical"
    } else if disk_pct > 80.0 || disk_io_slope > 1024.0 {
        "increasing"
    } else if disk_io_slope < -1024.0 {
        "decreasing"
    } else {
        "stable"
    };
    let disk_io_trend = if disk_write_avg > 100.0 * 1024.0 * 1024.0 {
        "critical"
    } else if disk_io_slope > 1024.0 {
        "increasing"
    } else if disk_io_slope < -1024.0 {
        "decreasing"
    } else {
        "stable"
    };
    let network_trend = if net_slope > 10_000.0 {
        "increasing"
    } else if net_slope < -10_000.0 {
        "decreasing"
    } else {
        "stable"
    };

    // Estimate days until disk full from observed write rate or remaining capacity percentage
    let daily_write_gb = (disk_write_avg * 86_400.0) / (1024.0 * 1024.0 * 1024.0);
    let days_until_full = if disk_pct >= 99.0 {
        1
    } else if daily_write_gb > 0.5 && disk_free_gb > 0.0 {
        ((disk_free_gb / daily_write_gb).round() as i64).clamp(1, 365)
    } else {
        ((100.0 - disk_pct) * 3.5).round() as i64
    };

    if cpu_max > 85.0 {
        let msg = format!(
            "CPU utilization peaked at {:.1}% (average {:.1}%)",
            cpu_max, cpu_avg
        );
        anomalies.push(msg.clone());
        warnings.push(msg);
    }
    if mem_max > 90.0 {
        let msg = format!(
            "Memory pressure reached {:.1}% (average {:.1}%)",
            mem_max, mem_avg
        );
        anomalies.push(msg.clone());
        warnings.push(msg);
    }
    if load_avg > 4.0 {
        let msg = format!("Sustained 1m load average is elevated at {:.2}", load_avg);
        anomalies.push(msg.clone());
        warnings.push(msg);
    }
    if disk_pct > 85.0 {
        let msg = format!(
            "Primary storage utilization is at {:.1}% (~{} days remaining)",
            disk_pct, days_until_full
        );
        anomalies.push(msg.clone());
        warnings.push(msg);
    }

    let mut recommendations = Vec::new();
    if cpu_trend == "increasing" || cpu_trend == "critical" {
        recommendations.push(
            "Enable hardware-accelerated transcoding (NVENC/VAAPI/QSV) in MediaFlow to offload CPU spikes."
                .to_string(),
        );
    }
    if memory_trend == "increasing" || memory_trend == "critical" {
        recommendations.push(
            "Review memory-intensive services and configure swap or container memory limits."
                .to_string(),
        );
    }
    if disk_pct > 80.0 {
        recommendations.push(
            "Run MediaFlow HEVC/AV1 transcode optimization or prune old backups to reclaim storage."
                .to_string(),
        );
    }
    if recommendations.is_empty() {
        recommendations
            .push("Storage utilization is within healthy operational bounds.".to_string());
        recommendations.push("SQLite WAL retention pruning is active.".to_string());
    }

    let predicted_bottleneck = if disk_pct > 85.0 {
        "disk"
    } else if mem_max > 90.0 || memory_trend == "increasing" {
        "memory"
    } else if cpu_max > 85.0 || cpu_trend == "increasing" {
        "cpu"
    } else {
        "none"
    };

    let confidence_score = if history.len() >= 100 {
        0.92
    } else if history.len() >= 10 {
        0.80
    } else {
        0.65
    };

    let trend_summary = format!(
        "Analyzed {} telemetry snapshot(s): CPU avg {:.1}% (peak {:.1}%, trend {}), Memory avg {:.1}% (peak {:.1}%, trend {}), Disk {:.1}% used (~{} days until full).",
        history.len(),
        cpu_avg,
        cpu_max,
        cpu_trend,
        mem_avg,
        mem_max,
        memory_trend,
        disk_pct,
        days_until_full
    );

    if invoke_ai && history.len() >= 10 {
        let ps = resolve_provider_settings();
        let prompt = format!(
            "Analyze the following system metrics history and provide a resource prediction report.\n\n{}\n\nStatistical Summary:\n- Data points: {}\n- CPU Avg: {:.1}%, Max: {:.1}%, Linear Trend Slope: {:.4}\n- Memory Avg: {:.1}%, Max: {:.1}%, Linear Trend Slope: {:.4}\n- Avg 1m Load: {:.2}\n- Avg Disk Write: {:.0} B/s\n\nRespond ONLY with valid JSON in this exact format:\n{{\n  \"trend_summary\": \"2-3 sentence executive summary\",\n  \"cpu_trend\": \"increasing|decreasing|stable|critical\",\n  \"memory_trend\": \"increasing|decreasing|stable|critical\",\n  \"disk_io_trend\": \"increasing|decreasing|stable|critical\",\n  \"network_trend\": \"increasing|decreasing|stable|critical\",\n  \"warnings\": [\"warning 1\"],\n  \"recommendations\": [\"recommendation 1\"],\n  \"predicted_bottleneck\": \"cpu|memory|disk|network|none\",\n  \"confidence_score\": 0.85\n}}",
            get_system_metrics_context(),
            history.len(),
            cpu_avg,
            cpu_max,
            cpu_slope,
            mem_avg,
            mem_max,
            mem_slope,
            load_avg,
            disk_write_avg
        );
        if let Ok(ai_raw) = call_configured_ai(
            &ps,
            "You are FlowAI's predictive analytics engine for AetherFlow server management.",
            &prompt,
        )
        .await
        {
            let cleaned = clean_json_fence(&ai_raw);
            if let Ok(mut ai_val) = serde_json::from_str::<serde_json::Value>(&cleaned) {
                if let Some(obj) = ai_val.as_object_mut() {
                    obj.entry("disk_trend".to_string())
                        .or_insert_with(|| serde_json::json!(disk_trend));
                    obj.entry("days_until_disk_full".to_string())
                        .or_insert_with(|| serde_json::json!(days_until_full));
                    obj.entry("anomalies".to_string())
                        .or_insert_with(|| serde_json::json!(anomalies));
                    obj.entry("generated_at".to_string())
                        .or_insert_with(|| serde_json::json!(Utc::now().to_rfc3339()));
                    return ai_val;
                }
            }
        }
    }

    serde_json::json!({
        "trend_summary": trend_summary,
        "cpu_trend": cpu_trend,
        "memory_trend": memory_trend,
        "disk_trend": disk_trend,
        "disk_io_trend": disk_io_trend,
        "network_trend": network_trend,
        "days_until_disk_full": days_until_full,
        "anomalies": anomalies,
        "warnings": warnings,
        "recommendations": recommendations,
        "predicted_bottleneck": predicted_bottleneck,
        "confidence_score": confidence_score,
        "generated_at": Utc::now().to_rfc3339(),
    })
}

pub async fn get_predictions() -> Response {
    Json(build_resource_predictions(false).await).into_response()
}

pub async fn analyze_predictions() -> Response {
    Json(build_resource_predictions(true).await).into_response()
}

pub fn resolve_metrics_history_window_and_limit(
    q: &HashMap<String, String>,
) -> (Duration, i64, Option<usize>) {
    let mut default_limit: i64 = 2000;
    let window_dur = if let Some(win_raw) = q
        .get("window")
        .or_else(|| q.get("range"))
        .or_else(|| q.get("timeWindow"))
    {
        let w = win_raw.trim().to_ascii_lowercase();
        match w.as_str() {
            "1m" => Duration::minutes(1),
            "5m" => Duration::minutes(5),
            "15m" => Duration::minutes(15),
            "1h" => Duration::hours(1),
            "6h" => Duration::hours(6),
            "24h" | "1d" => {
                default_limit = 2400;
                Duration::hours(24)
            }
            "7d" => Duration::days(7),
            "30d" => Duration::days(30),
            "90d" => Duration::days(90),
            _ => {
                if let Some(num) = w.strip_suffix('m').and_then(|s| s.parse::<i64>().ok()) {
                    Duration::minutes(num.clamp(1, 60 * 24 * 365))
                } else if let Some(num) = w.strip_suffix('h').and_then(|s| s.parse::<i64>().ok()) {
                    Duration::hours(num.clamp(1, 24 * 365))
                } else if let Some(num) = w.strip_suffix('d').and_then(|s| s.parse::<i64>().ok()) {
                    Duration::days(num.clamp(1, 365))
                } else {
                    Duration::days(90)
                }
            }
        }
    } else if let Some(mins) = q
        .get("minutes")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&m| m > 0)
    {
        Duration::minutes(mins.clamp(1, 60 * 24 * 365))
    } else if let Some(hrs) = q
        .get("hours")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&h| h > 0)
    {
        if hrs <= 24 {
            default_limit = 2400;
        }
        Duration::hours(hrs.clamp(1, 24 * 365))
    } else {
        let days = q
            .get("days")
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&d| d > 0)
            .unwrap_or(90)
            .clamp(1, 365);
        if days == 1 {
            default_limit = 2400;
        }
        Duration::days(days)
    };

    let limit = q
        .get("limit")
        .or_else(|| q.get("max_points"))
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&l| l > 0)
        .map(|l| l.clamp(1, 10_000))
        .unwrap_or(default_limit);

    let downsample_target = if q
        .get("downsample")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        let target = q
            .get("target_points")
            .or_else(|| q.get("downsample_points"))
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n >= 2)
            .unwrap_or(360);
        Some(target)
    } else {
        None
    };

    (window_dur, limit, downsample_target)
}

pub const METRICS_PREDICTIONS_HISTORY_SQL: &str = "SELECT COALESCE(CAST(timestamp AS TEXT), ''), COALESCE(cpu_avg, 0), COALESCE(mem_used_gb, 0), COALESCE(mem_total_gb, 0), \
     COALESCE(disk_read_bps, 0), COALESCE(disk_write_bps, 0), COALESCE(net_rx_bytes, 0), COALESCE(net_tx_bytes, 0), \
     COALESCE(load_avg_1, 0), COALESCE(active_conns, 0) \
     FROM metrics_history WHERE replace(CAST(timestamp AS TEXT), 'T', ' ') >= ?1 \
     ORDER BY replace(CAST(timestamp AS TEXT), 'T', ' ') DESC, id DESC LIMIT 2000";

pub const METRICS_HISTORY_QUERY_SQL: &str = "SELECT id, COALESCE(CAST(timestamp AS TEXT), ''), COALESCE(cpu_avg, 0), COALESCE(mem_used_gb, 0), COALESCE(mem_total_gb, 0), \
     COALESCE(disk_read_bps, 0), COALESCE(disk_write_bps, 0), COALESCE(net_rx_bytes, 0), COALESCE(net_tx_bytes, 0), \
     COALESCE(load_avg_1, 0), COALESCE(active_conns, 0) \
     FROM metrics_history WHERE replace(CAST(timestamp AS TEXT), 'T', ' ') >= ?1 \
     ORDER BY replace(CAST(timestamp AS TEXT), 'T', ' ') DESC, id DESC LIMIT ?2";

pub fn query_metrics_history_rows(
    conn: &rusqlite::Connection,
    query_params: &HashMap<String, String>,
) -> Vec<serde_json::Value> {
    let (window_dur, limit, downsample_target) =
        resolve_metrics_history_window_and_limit(query_params);
    let cutoff = (Utc::now() - window_dur)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    let mut snapshots = Vec::new();
    if let Ok(mut stmt) = conn.prepare(METRICS_HISTORY_QUERY_SQL) {
        if let Ok(rows) = stmt.query_map(params![cutoff, limit], |row| {
            let id: i64 = row.get(0)?;
            let timestamp: String = row.get(1)?;
            let cpu_avg: f64 = row.get(2)?;
            let mem_used_gb: f64 = row.get(3)?;
            let mem_total_gb: f64 = row.get(4)?;
            let disk_read_bps: f64 = row.get(5)?;
            let disk_write_bps: f64 = row.get(6)?;
            let net_rx_bytes: i64 = row.get(7)?;
            let net_tx_bytes: i64 = row.get(8)?;
            let load_avg_1: f64 = row.get(9)?;
            let active_conns: i64 = row.get(10)?;
            Ok(serde_json::json!({
                "id": id,
                "timestamp": timestamp,
                "recorded_at": timestamp,
                "cpu_avg": cpu_avg,
                "cpu_usage": cpu_avg,
                "mem_used_gb": mem_used_gb,
                "mem_total_gb": mem_total_gb,
                "disk_read_bps": disk_read_bps,
                "disk_write_bps": disk_write_bps,
                "net_rx_bytes": net_rx_bytes,
                "net_tx_bytes": net_tx_bytes,
                "load_avg_1": load_avg_1,
                "load_1m": load_avg_1,
                "active_conns": active_conns,
            }))
        }) {
            for row in rows.flatten() {
                snapshots.push(row);
            }
        }
    }

    // Reverse newest-first rows into chronological ASC order (`oldest -> newest` within the latest bounded slice)
    snapshots.reverse();

    if let Some(target_pts) = downsample_target {
        if snapshots.len() > target_pts && target_pts >= 2 {
            let total = snapshots.len();
            let mut sampled = Vec::with_capacity(target_pts);
            for i in 0..target_pts {
                let idx = if i + 1 == target_pts {
                    total - 1
                } else {
                    (i * (total - 1)) / (target_pts - 1)
                };
                sampled.push(snapshots[idx].clone());
            }
            return sampled;
        }
    }

    snapshots
}

pub async fn get_metrics_history(Query(q): Query<HashMap<String, String>>) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return Json(serde_json::json!([])).into_response();
    };
    let snapshots = query_metrics_history_rows(&conn, &q);
    Json(snapshots).into_response()
}

pub async fn get_auth_metrics_history(Query(q): Query<HashMap<String, String>>) -> Response {
    get_metrics_history(Query(q)).await
}

pub async fn get_mediaflow_queue() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Failed to fetch queue" })),
        )
            .into_response();
    };
    let mut items = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, file_path, status, COALESCE(original_codec, ''), COALESCE(original_size, 0), \
         COALESCE(new_codec, ''), COALESCE(new_size, 0), COALESCE(error_log, ''), COALESCE(created_at, '') \
         FROM mediaflow_queue WHERE status != 'DECLINED' ORDER BY created_at DESC LIMIT 100",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "filePath": r.get::<_, String>(1)?,
                "status": r.get::<_, String>(2)?,
                "originalCodec": r.get::<_, String>(3)?,
                "originalSize": r.get::<_, i64>(4)?,
                "newCodec": r.get::<_, String>(5)?,
                "newSize": r.get::<_, i64>(6)?,
                "errorLog": r.get::<_, String>(7)?,
                "createdAt": r.get::<_, String>(8)?,
            }))
        }) {
            for item in rows.flatten() {
                items.push(item);
            }
        }
    }
    Json(items).into_response()
}

static MEDIAFLOW_VIDEO_EXTS: &[&str] = &[".mkv", ".mp4", ".avi", ".mov", ".ts", ".m2ts"];

fn probe_video_codec_and_size(file_path: &StdPath) -> (String, i64) {
    let fallback_size = std::fs::metadata(file_path)
        .map(|m| m.len() as i64)
        .unwrap_or(0);

    if let Ok(out) = Command::new("ffprobe")
        .args([
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
        ])
        .arg(file_path)
        .output()
    {
        if out.status.success() {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                let mut v_codec = String::new();
                if let Some(streams) = val.get("streams").and_then(|v| v.as_array()) {
                    for s in streams {
                        if s.get("codec_type").and_then(|v| v.as_str()) == Some("video") {
                            v_codec = s
                                .get("codec_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_lowercase();
                            break;
                        }
                    }
                }
                let size = val
                    .pointer("/format/size")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<i64>().ok())
                    .filter(|&sz| sz > 0)
                    .unwrap_or(fallback_size);
                if !v_codec.is_empty() {
                    return (v_codec, size);
                }
            }
        }
    }

    // Fallback when ffprobe is not installed or fails: infer from filename
    let fname_lower = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    let codec = if fname_lower.contains("hevc")
        || fname_lower.contains("x265")
        || fname_lower.contains("h265")
        || fname_lower.contains("h.265")
    {
        "hevc".to_string()
    } else if fname_lower.contains("av1") {
        "av1".to_string()
    } else if fname_lower.contains("mpeg2") {
        "mpeg2video".to_string()
    } else if fname_lower.contains("vp9") {
        "vp9".to_string()
    } else {
        "h264".to_string()
    };

    (codec, fallback_size)
}

fn mediaflow_library_roots() -> Vec<PathBuf> {
    let roots: Vec<PathBuf> = match env::var("AF_ALLOWED_FS_ROOTS") {
        Ok(configured) => configured
            .split(',')
            .map(str::trim)
            .filter(|root| !root.is_empty())
            .map(PathBuf::from)
            .collect(),
        Err(_) => vec![
            PathBuf::from("/mnt"),
            PathBuf::from("/media"),
            PathBuf::from("/home"),
            PathBuf::from("/opt/AetherFlow"),
            PathBuf::from("/var/lib/aetherflow"),
        ],
    };
    roots
        .into_iter()
        .filter_map(|root| root.canonicalize().ok())
        .collect()
}

fn validate_mediaflow_directory(
    directory: &StdPath,
    allowed_roots: &[PathBuf],
) -> Result<PathBuf, (StatusCode, String)> {
    let resolved = directory.canonicalize().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Directory does not exist or is not accessible".to_string(),
        )
    })?;
    if !resolved.is_dir() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Scan path must be a directory".to_string(),
        ));
    }
    if !allowed_roots.iter().any(|root| resolved.starts_with(root)) {
        return Err((
            StatusCode::FORBIDDEN,
            "Directory is outside configured library roots".to_string(),
        ));
    }
    Ok(resolved)
}

fn collect_mediaflow_files(directory: &StdPath, root: &StdPath, out: &mut Vec<PathBuf>) {
    let Ok(metadata) = std::fs::symlink_metadata(directory) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    let Ok(resolved) = directory.canonicalize() else {
        return;
    };
    if !resolved.starts_with(root) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(&resolved) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect_mediaflow_files(&path, root, out);
        } else if file_type.is_file() {
            let Ok(path) = path.canonicalize() else {
                continue;
            };
            if path.starts_with(root)
                && path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| {
                        MEDIAFLOW_VIDEO_EXTS
                            .iter()
                            .any(|allowed| allowed[1..].eq_ignore_ascii_case(ext))
                    })
            {
                out.push(path);
            }
        }
    }
}

fn scan_directory_for_mediaflow(root_dir: &StdPath) -> anyhow::Result<()> {
    let mut video_files = Vec::new();
    collect_mediaflow_files(root_dir, root_dir, &mut video_files);

    for path in video_files {
        let path_str = path.to_string_lossy().to_string();
        if path_str.contains(".mediaflow_trash") {
            continue;
        }
        let exists: i64 = {
            let conn = af_db::get_conn()?;
            conn.query_row(
                "SELECT COUNT(*) FROM mediaflow_queue WHERE file_path = ?1",
                params![path_str],
                |r| r.get(0),
            )?
        };
        if exists > 0 {
            continue;
        }

        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || !path.canonicalize()?.starts_with(root_dir) {
            continue;
        }
        let (codec, size) = probe_video_codec_and_size(&path);
        if codec != "hevc" && codec != "av1" {
            let conn = af_db::get_conn()?;
            conn.execute(
                "INSERT INTO mediaflow_queue (file_path, original_codec, original_size, status) SELECT ?1, ?2, ?3, 'PENDING_APPROVAL' WHERE NOT EXISTS (SELECT 1 FROM mediaflow_queue WHERE file_path = ?1)",
                params![path_str, codec, size],
            )?;
        }
    }
    Ok(())
}

pub async fn trigger_mediaflow_scan(Json(req): Json<serde_json::Value>) -> Response {
    let dir = req
        .get("directory")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if dir.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid payload" })),
        )
            .into_response();
    }
    let directory = PathBuf::from(dir);
    let dir_buf = match tokio::task::spawn_blocking(move || {
        validate_mediaflow_directory(&directory, &mediaflow_library_roots())
    })
    .await
    {
        Ok(Ok(directory)) => directory,
        Ok(Err((status, message))) => return api_error(status, "INVALID_SCAN_PATH", message),
        Err(error) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                error.to_string(),
            )
        }
    };
    let response_directory = dir_buf.to_string_lossy().into_owned();
    tokio::task::spawn_blocking(move || {
        if let Err(error) = scan_directory_for_mediaflow(&dir_buf) {
            tracing::error!(%error, directory = %dir_buf.display(), "MediaFlow scan failed");
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "message": "Scan initiated in background",
            "directory": response_directory,
        })),
    )
        .into_response()
}

pub async fn approve_mediaflow_item(Path(id): Path<String>) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Failed to approve" })),
        )
            .into_response();
    };
    let affected = conn
        .execute(
            "UPDATE mediaflow_queue SET status = 'APPROVED', updated_at = CURRENT_TIMESTAMP WHERE id = ?1 AND status = 'PENDING_APPROVAL'",
            params![id],
        )
        .unwrap_or(0);
    if affected == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Item not found or already processed" })),
        )
            .into_response();
    }
    Json(serde_json::json!({
        "message": "Transcode queued. MediaFlow Engine assumes control."
    }))
    .into_response()
}

pub async fn decline_mediaflow_item(Path(id): Path<String>) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "Failed to decline" })),
        )
            .into_response();
    };
    let affected = conn
        .execute(
            "UPDATE mediaflow_queue SET status = 'DECLINED', updated_at = CURRENT_TIMESTAMP WHERE id = ?1 AND status = 'PENDING_APPROVAL'",
            params![id],
        )
        .unwrap_or(0);
    if affected == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Item not found or already processed" })),
        )
            .into_response();
    }
    Json(serde_json::json!({ "message": "Transcode job declined." })).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Network VPN Management (`backend/api/network_handlers.go` & `network.go`)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
fn parse_wireguard_dump(stdout: &str) -> Option<serde_json::Value> {
    let interface_fields = stdout.lines().find_map(|line| {
        let fields: Vec<&str> = line.split('\t').collect();
        (fields.len() == 5).then_some(fields)
    })?;
    let mut peers = Vec::new();
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 9 || fields[0] != interface_fields[0] {
            continue;
        }
        peers.push(serde_json::json!({
            "public_key": fields[1],
            "endpoint": fields[3],
            "allowed_ips": fields[4],
            "latest_handshake": fields[5],
            "transfer_rx": fields[6],
            "transfer_tx": fields[7],
        }));
    }
    Some(serde_json::json!({
        "interface": interface_fields[0],
        "public_key": interface_fields[2],
        "listen_port": interface_fields[3],
        "peers": peers,
    }))
}

#[cfg(test)]
fn parse_tailscale_peer_obj(fallback_id: &str, p: &serde_json::Value) -> serde_json::Value {
    let id = p
        .get("ID")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_id);
    let host_name = p.get("HostName").and_then(|v| v.as_str()).unwrap_or("");
    let dns_name = p.get("DNSName").and_then(|v| v.as_str()).unwrap_or("");
    let os = p.get("OS").and_then(|v| v.as_str()).unwrap_or("");
    let online = p.get("Online").and_then(|v| v.as_bool()).unwrap_or(false);
    let exit_node = p.get("ExitNode").and_then(|v| v.as_bool()).unwrap_or(false);
    let rx_bytes = p.get("RxBytes").and_then(|v| v.as_i64()).unwrap_or(0);
    let tx_bytes = p.get("TxBytes").and_then(|v| v.as_i64()).unwrap_or(0);
    let ips: Vec<String> = p
        .get("TailscaleIPs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let primary_ip = ips.first().cloned().unwrap_or_default();
    let tags: Vec<&str> = p
        .get("Tags")
        .and_then(|value| value.as_array())
        .map(|tags| tags.iter().filter_map(|tag| tag.as_str()).collect())
        .unwrap_or_default();

    serde_json::json!({
        "id": id,
        "hostname": host_name,
        "dns_name": dns_name,
        "tailscale_ip": primary_ip,
        "tailscale_ips": ips,
        "tags": tags,
        "os": os,
        "online": online,
        "exit_node": exit_node,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
    })
}

#[cfg(test)]
fn parse_tailscale_status_json(
    raw: &serde_json::Value,
) -> (
    String,
    bool,
    Option<serde_json::Value>,
    Vec<serde_json::Value>,
) {
    let backend_state = raw
        .get("BackendState")
        .and_then(|v| v.as_str())
        .unwrap_or("Stopped")
        .to_string();
    let magic_dns = raw
        .get("MagicDNSSuffix")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    let self_peer = raw
        .get("Self")
        .filter(|v| v.is_object())
        .map(|s| parse_tailscale_peer_obj("self", s));

    let mut peers = Vec::new();
    if let Some(peer_map) = raw.get("Peer").and_then(|v| v.as_object()) {
        for (key, peer_val) in peer_map {
            peers.push(parse_tailscale_peer_obj(key, peer_val));
        }
    }

    (backend_state, magic_dns, self_peer, peers)
}

#[cfg(test)]
fn tailscale_status_value(raw: &serde_json::Value) -> serde_json::Value {
    let (backend_state, magic_dns, self_peer, peers) = parse_tailscale_status_json(raw);
    serde_json::json!({
        "backend_state": backend_state,
        "self": self_peer,
        "peers": peers,
        "magic_dns": magic_dns,
    })
}

// VPN host operations are implemented in crate::network and the privileged runner.

// ─────────────────────────────────────────────────────────────────────────────
// 4. Live System Topology, Log Bookmarks & Cluster Nodes
// ─────────────────────────────────────────────────────────────────────────────

pub async fn get_system_topology() -> Response {
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let runner_sock = af_runner::runner_socket_path();
    let runner_online = StdPath::new(&runner_sock).exists();

    let mut nodes = vec![
        serde_json::json!({
            "id": "AetherFlow API",
            "group": 1,
            "status": "running",
            "details": format!("Port {} (Rust/Axum)", port),
        }),
        serde_json::json!({
            "id": "Runner Daemon",
            "group": 1,
            "status": if runner_online { "running" } else { "stopped" },
            "details": if runner_online { runner_sock } else { "Socket offline / direct mode".to_string() },
        }),
        serde_json::json!({
            "id": "SQLite WAL",
            "group": 2,
            "status": "running",
            "details": "SQLite (WAL mode)",
        }),
        serde_json::json!({
            "id": "Redis Cache",
            "group": 2,
            "status": "stopped",
            "details": "Disabled / Memory cache active",
        }),
        serde_json::json!({
            "id": "Apache2 Reverse Proxy",
            "group": 3,
            "status": "running",
            "details": "Apache2 + AetherFlow Subdomain Gateway (443 / 80)",
        }),
    ];

    let mut links = vec![
        serde_json::json!({ "source": "AetherFlow API", "target": "Runner Daemon", "value": 1 }),
        serde_json::json!({ "source": "AetherFlow API", "target": "SQLite WAL", "value": 1 }),
        serde_json::json!({ "source": "Apache2 Reverse Proxy", "target": "AetherFlow API", "value": 1 }),
    ];

    if let Ok(pkgs) = af_services::get_packages() {
        for pkg in pkgs {
            if (pkg.status == "running" || pkg.status == "installed") && !pkg.name.is_empty() {
                let label = if pkg.label.is_empty() {
                    pkg.name.clone()
                } else {
                    pkg.label.clone()
                };
                let node_status = if pkg.status == "running" {
                    "running"
                } else {
                    "stopped"
                };
                let mut details = if pkg.status == "running" {
                    "Running".to_string()
                } else {
                    "Installed (inactive)".to_string()
                };
                if let Ok(Some(ingress)) = af_db::get_app_ingress_config(&pkg.name) {
                    if ingress.listen_port > 0 {
                        details = format!("Port {}", ingress.listen_port);
                        if !ingress.public_domain.is_empty() {
                            details = format!("{} | {}", details, ingress.public_domain);
                        }
                    }
                } else if let Some(bp) = af_services::get_blueprint(&pkg.name) {
                    if bp.default_port > 0 {
                        details = format!("Port {} (blueprint)", bp.default_port);
                    }
                }
                nodes.push(serde_json::json!({
                    "id": label,
                    "group": 4,
                    "status": node_status,
                    "details": details,
                }));
                links.push(serde_json::json!({
                    "source": "Apache2 Reverse Proxy",
                    "target": label,
                    "value": 1,
                }));
            }
        }
    }

    Json(serde_json::json!({
        "nodes": nodes,
        "links": links,
    }))
    .into_response()
}

fn infer_log_level(line: &str) -> &'static str {
    let lower = line.to_lowercase();
    if lower.contains("fatal") || lower.contains("panic") || lower.contains("crit") {
        "CRIT"
    } else if lower.contains("error") || lower.contains("err") || lower.contains("failed") {
        "ERROR"
    } else if lower.contains("warn") || lower.contains("warning") {
        "WARN"
    } else if lower.contains("debug") {
        "DEBUG"
    } else {
        "INFO"
    }
}

const AUDIT_LOG_FALLBACK_SQL: &str =
    "SELECT COALESCE(CAST(created_at AS TEXT), ''), COALESCE(action, 'event'), COALESCE(target_type, 'system'), COALESCE(detail, '') FROM admin_audit_log ORDER BY id DESC LIMIT ?1";

pub async fn get_logs(Query(q): Query<HashMap<String, String>>) -> Response {
    let source = q
        .get("source")
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    let unit = q
        .get("unit")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let search = q
        .get("search")
        .or_else(|| q.get("filter"))
        .or_else(|| q.get("keyword"))
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    let level_filter = q
        .get("level")
        .or_else(|| q.get("priority"))
        .map(|s| s.trim().to_uppercase())
        .unwrap_or_default();
    let limit = q
        .get("lines")
        .or_else(|| q.get("limit"))
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(200)
        .min(1000);
    let offset = q
        .get("offset")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    let mut raw_entries: Vec<serde_json::Value> = Vec::new();

    // 1. Read from /var/log/aetherflow-deploy.log or /var/log/syslog or apache logs when requested
    let mut candidate_files: Vec<(&str, &str)> = Vec::new();
    match source.as_str() {
        "application" | "deploy" => {
            candidate_files.push(("application", "/var/log/aetherflow-deploy.log"));
        }
        "syslog" => {
            candidate_files.push(("syslog", "/var/log/syslog"));
            candidate_files.push(("syslog", "/var/log/messages"));
        }
        "apache" => {
            candidate_files.push(("apache", "/var/log/apache2/error.log"));
            candidate_files.push(("apache", "/var/log/apache2/access.log"));
        }
        "" => {
            candidate_files.push(("application", "/var/log/aetherflow-deploy.log"));
            candidate_files.push(("syslog", "/var/log/syslog"));
            candidate_files.push(("apache", "/var/log/apache2/error.log"));
        }
        _ => {}
    }

    for (src_name, file_path) in candidate_files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            let all_lines: Vec<&str> = content.lines().collect();
            let start_idx = all_lines.len().saturating_sub(limit + offset);
            for line in &all_lines[start_idx..] {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let lvl = infer_log_level(trimmed);
                raw_entries.push(serde_json::json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "source": src_name,
                    "service": src_name,
                    "level": lvl,
                    "message": trimmed,
                }));
            }
        }
    }

    // 2. Query journalctl if source is empty or "journald"
    if source.is_empty() || source == "journald" {
        let mut args = vec![
            "-n".to_string(),
            limit.to_string(),
            "--no-pager".to_string(),
            "-o".to_string(),
            "short-iso".to_string(),
        ];
        if !unit.is_empty() {
            args.push("-u".to_string());
            args.push(unit.clone());
        }
        if let Ok(out) = Command::new("journalctl").args(&args).output() {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with("-- ") {
                        continue;
                    }
                    let mut parts = trimmed.splitn(3, ' ');
                    let ts = parts.next().unwrap_or("");
                    let _host = parts.next().unwrap_or("");
                    let rest = parts.next().unwrap_or(trimmed);
                    let (svc, msg) = if let Some((s, m)) = rest.split_once(": ") {
                        (s.trim(), m.trim())
                    } else {
                        ("journald", rest)
                    };
                    let lvl = infer_log_level(msg);
                    raw_entries.push(serde_json::json!({
                        "timestamp": ts,
                        "source": "journald",
                        "service": svc,
                        "level": lvl,
                        "message": msg,
                    }));
                }
            }
        }
    }

    // 3. Fallback: include audit/notification log entries from SQLite when host log files are absent
    if raw_entries.is_empty() {
        if let Ok(conn) = af_db::get_conn() {
            if let Ok(mut stmt) = conn.prepare(AUDIT_LOG_FALLBACK_SQL) {
                if let Ok(rows) = stmt.query_map(params![limit as i64], |r| {
                    let ts: String = r.get(0)?;
                    let action: String = r.get(1)?;
                    let target: String = r.get(2)?;
                    let details: String = r.get(3)?;
                    let msg = if details.is_empty() {
                        action.clone()
                    } else {
                        format!("{}: {}", action, details)
                    };
                    Ok(serde_json::json!({
                        "timestamp": ts,
                        "source": if source.is_empty() { "application" } else { source.as_str() },
                        "service": target,
                        "level": infer_log_level(&msg),
                        "message": msg,
                    }))
                }) {
                    for entry in rows.flatten() {
                        raw_entries.push(entry);
                    }
                }
            }
        }
    }

    // Apply unit, level, and search filters
    let filtered = filter_log_entries(raw_entries, &unit, &level_filter, &search, offset, limit);

    let count = filtered.len();
    Json(serde_json::json!({
        "logs": filtered,
        "count": count,
    }))
    .into_response()
}

pub(crate) fn filter_log_entries(
    raw_entries: Vec<serde_json::Value>,
    unit: &str,
    level_filter: &str,
    search: &str,
    offset: usize,
    limit: usize,
) -> Vec<serde_json::Value> {
    let unit_lower = unit.trim().to_lowercase();
    let unit_base = unit_lower.trim_end_matches(".service");
    let level_upper = level_filter.trim().to_uppercase();
    let search_lower = search.trim().to_lowercase();

    raw_entries
        .into_iter()
        .filter(|entry| {
            if !unit_lower.is_empty() {
                let entry_source = entry.get("source").and_then(|v| v.as_str()).unwrap_or("");
                if !entry_source.eq_ignore_ascii_case("journald") {
                    let svc = entry
                        .get("service")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    let msg = entry
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_lowercase();
                    let matches_unit = svc.contains(&unit_lower)
                        || msg.contains(&unit_lower)
                        || (!unit_base.is_empty()
                            && (svc.contains(unit_base) || msg.contains(unit_base)));
                    if !matches_unit {
                        return false;
                    }
                }
            }
            if !level_upper.is_empty() {
                let lvl = entry
                    .get("level")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_uppercase();
                if !lvl.contains(&level_upper) {
                    return false;
                }
            }
            if !search_lower.is_empty() {
                let msg = entry
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let svc = entry
                    .get("service")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                if !msg.contains(&search_lower) && !svc.contains(&search_lower) {
                    return false;
                }
            }
            true
        })
        .skip(offset)
        .take(limit)
        .collect()
}

pub async fn get_log_sources() -> Response {
    Json(serde_json::json!({
        "sources": ["journald", "syslog", "apache", "application"]
    }))
    .into_response()
}

pub async fn bookmark_log(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>().cloned() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 64 * 1024).await else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid body");
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON");
    };
    let log_source = body
        .get("log_source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let log_line = body.get("log_line").and_then(|v| v.as_str()).unwrap_or("");
    let timestamp = body.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
    let note = body.get("note").and_then(|v| v.as_str()).unwrap_or("");
    if log_source.is_empty() || log_line.is_empty() || timestamp.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "log_source, log_line, and timestamp are required",
        );
    }

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to bookmark log",
        );
    };
    if conn
        .execute(
            "INSERT INTO log_bookmarks (user_id, log_source, log_line, timestamp, note) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![user.user_id, log_source, log_line, timestamp, note],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to bookmark log",
        );
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "message": "Log bookmarked" })),
    )
        .into_response()
}

pub async fn get_bookmarks(req: Request) -> Response {
    let Some(user) = req.extensions().get::<AuthUser>() else {
        return api_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
    };
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to fetch bookmarks",
        );
    };
    let mut bookmarks = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, log_source, log_line, timestamp, COALESCE(note, ''), COALESCE(created_at, '') \
         FROM log_bookmarks WHERE user_id = ?1 ORDER BY created_at DESC",
    ) {
        if let Ok(rows) = stmt.query_map(params![user.user_id], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "log_source": r.get::<_, String>(1)?,
                "log_line": r.get::<_, String>(2)?,
                "timestamp": r.get::<_, String>(3)?,
                "note": r.get::<_, String>(4)?,
                "created_at": r.get::<_, String>(5)?,
            }))
        }) {
            for b in rows.flatten() {
                bookmarks.push(b);
            }
        }
    }
    Json(serde_json::json!({ "bookmarks": bookmarks })).into_response()
}

pub async fn get_cluster_nodes() -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return Json(serde_json::json!({
            "nodes": [],
            "summary": {
                "total_nodes": 0,
                "online": 0,
                "offline": 0,
                "total_cpu_avg": 0.0,
                "total_mem_used": 0.0,
                "total_mem_total": 0.0,
                "total_disk_used": 0.0,
                "total_disk_total": 0.0
            }
        }))
        .into_response();
    };

    let mut nodes = Vec::new();
    let mut online = 0usize;
    let mut offline = 0usize;
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, hostname, address, COALESCE(role, 'worker'), COALESCE(status, 'offline'), \
         COALESCE(last_heartbeat, ''), COALESCE(enrolled_at, '') FROM cluster_nodes",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| {
            let status: String = r.get(4)?;
            Ok((
                status.clone(),
                serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "hostname": r.get::<_, String>(1)?,
                    "address": r.get::<_, String>(2)?,
                    "role": r.get::<_, String>(3)?,
                    "status": status,
                    "version": "4.0.0",
                    "last_heartbeat": r.get::<_, String>(5)?,
                    "enrolled_at": r.get::<_, String>(6)?,
                }),
            ))
        }) {
            for (status, node) in rows.flatten() {
                if status == "online" {
                    online += 1;
                } else {
                    offline += 1;
                }
                nodes.push(node);
            }
        }
    }

    Json(serde_json::json!({
        "nodes": nodes,
        "summary": {
            "total_nodes": nodes.len(),
            "online": online,
            "offline": offline,
            "total_cpu_avg": 0.0,
            "total_mem_used": 0.0,
            "total_mem_total": 0.0,
            "total_disk_used": 0.0,
            "total_disk_total": 0.0
        }
    }))
    .into_response()
}

pub async fn enroll_worker() -> Response {
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);
    Json(serde_json::json!({
        "enrollment_token": token,
        "instructions": format!(
            "Run on the worker node: aetherflow-api --cluster-mode=worker --master-addr=<this-server>:50051 --psk={}",
            token
        ),
    }))
    .into_response()
}

pub async fn remove_worker(Path(node_id): Path<String>) -> Response {
    if node_id.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Node ID is required",
        );
    }
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let affected = conn
        .execute("DELETE FROM cluster_nodes WHERE id = ?1", params![node_id])
        .unwrap_or(0);
    if affected == 0 {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Node not found");
    }
    af_services::cluster_daemon::remove_cached_worker_metrics(&node_id);
    Json(serde_json::json!({
        "message": "Node removed successfully",
        "node_id": node_id,
    }))
    .into_response()
}

pub async fn get_worker_metrics(Path(node_id): Path<String>) -> Response {
    if let Some(cached) = af_services::cluster_daemon::get_cached_worker_metrics(&node_id) {
        return Json(cached).into_response();
    }
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    let Ok((hostname, status, last_hb)) = conn.query_row(
        "SELECT hostname, COALESCE(status, 'offline'), COALESCE(last_heartbeat, '') FROM cluster_nodes WHERE id = ?1",
        params![node_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
    ) else {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Node not found");
    };

    Json(serde_json::json!({
        "node_id": node_id,
        "hostname": hostname,
        "status": status,
        "metrics": null,
        "services": [],
        "system_info": null,
        "last_heartbeat": last_hb,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_log_entries_preserves_journald_unit_lines_with_different_syslog_identifier() {
        let raw = vec![
            serde_json::json!({
                "timestamp": "2026-11-02T12:00:00Z",
                "source": "journald",
                "service": "node",
                "level": "INFO",
                "message": "Server listening on 127.0.0.1:6246",
            }),
            serde_json::json!({
                "timestamp": "2026-11-02T12:00:01Z",
                "source": "journald",
                "service": "hass",
                "level": "ERROR",
                "message": "Home Assistant core error",
            }),
            serde_json::json!({
                "timestamp": "2026-11-02T12:00:02Z",
                "source": "file",
                "service": "nginx-error",
                "level": "ERROR",
                "message": "upstream timed out",
            }),
            serde_json::json!({
                "timestamp": "2026-11-02T12:00:03Z",
                "source": "file",
                "service": "af-api",
                "level": "INFO",
                "message": "af-maintainerr proxy healthy",
            }),
        ];

        let filtered = filter_log_entries(raw.clone(), "af-maintainerr.service", "", "", 0, 50);
        assert_eq!(filtered.len(), 3);
        assert_eq!(filtered[0]["service"], "node");
        assert_eq!(filtered[1]["service"], "hass");
        assert_eq!(filtered[2]["service"], "af-api");

        let error_only = filter_log_entries(raw, "homeassistant.service", "ERROR", "core", 0, 50);
        assert_eq!(error_only.len(), 1);
        assert_eq!(error_only[0]["service"], "hass");
    }
}
