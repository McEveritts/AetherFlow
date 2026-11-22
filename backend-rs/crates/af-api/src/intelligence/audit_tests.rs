use super::ai_providers::{call_anthropic_api, call_openai_compatible_api};
use super::flowai::{run_chat_session, test_ai_connection};
use super::mediaflow::{
    approve_mediaflow_item, collect_mediaflow_files, decline_mediaflow_item, get_mediaflow_queue,
    scan_directory_for_mediaflow,
};
use super::scan_cursor::{mediaflow_library_roots, validate_mediaflow_directory};
use super::telemetry::{
    query_metrics_history_rows, AUDIT_LOG_FALLBACK_SQL, METRICS_HISTORY_QUERY_SQL,
    METRICS_PREDICTIONS_HISTORY_SQL,
};
use crate::auth::AuthUser;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{Json, Response};
use chrono::{Duration, Utc};
use rusqlite::params;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

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
                axum::routing::post(|| async { axum::response::Redirect::temporary("/capture") }),
            )
            .route(
                "/v1/chat/completions",
                axum::routing::post(|| async { axum::response::Redirect::temporary("/capture") }),
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
    collect_mediaflow_files(&root, &root, 0, &mut files);
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
    collect_mediaflow_files(&root, &root, 0, &mut files);
    assert!(files.is_empty());
}

#[test]
fn mediaflow_library_roots_align_with_systemd_defaults_and_explicit_overrides() {
    assert_eq!(
        af_services::DEFAULT_MEDIAFLOW_ROOTS,
        &["/mnt", "/media", "/srv", "/data"]
    );
    let default_roots = af_services::mediaflow_allowed_roots_from_raw(None);
    if let Ok(canon_home) = std::fs::canonicalize("/home") {
        assert!(!default_roots.contains(&canon_home));
    }
    assert_eq!(
        mediaflow_library_roots(),
        af_services::mediaflow_allowed_roots()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn mediaflow_scan_approve_rescan_decline_and_legacy_upgrade_end_to_end() {
    let name =
        "intelligence::audit_tests::mediaflow_scan_approve_rescan_decline_and_legacy_upgrade_end_to_end";
    if env::var("AF_MEDIAFLOW_API_E2E_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_API_E2E_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use http_body_util::BodyExt;
    use std::os::unix::fs::PermissionsExt;

    async fn read_json(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, body)
    }

    let root = env::temp_dir().join(format!("af-mf-api-e2e-{}", uuid::Uuid::new_v4()));
    let media = root.join("media");
    let bin = root.join("bin");
    std::fs::create_dir_all(&media).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let canon_media = media.canonicalize().unwrap();

    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", &canon_media);
    env::set_var("AETHERFLOW_SKIP_ENV_FILES", "1");

    // Fake ffprobe reads the pinned fd/path and reports h264 JSON.
    let fake_ffprobe = bin.join("ffprobe");
    std::fs::write(
        &fake_ffprobe,
        "#!/bin/sh\nset -eu\nin=\"\"\nfor arg in \"$@\"; do in=\"$arg\"; done\nin_path=\"${in#file:}\"\nsz=$(wc -c < \"$in_path\" | tr -d ' ')\nprintf '{\"streams\":[{\"codec_type\":\"video\",\"codec_name\":\"h264\"}],\"format\":{\"size\":\"%s\"}}\\n' \"$sz\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake_ffprobe, std::fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!("{}:{}", bin.display(), env::var("PATH").unwrap()),
    );

    // 0. Seed a pre-v24 legacy DB with `file_path TEXT UNIQUE NOT NULL` and a legacy PENDING_APPROVAL row.
    let legacy_file = canon_media.join("legacy.mp4");
    std::fs::write(&legacy_file, b"legacy-h264-fixture-01").unwrap();
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            r#"CREATE TABLE schema_versions (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE mediaflow_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'PENDING_APPROVAL',
                original_codec TEXT DEFAULT '',
                original_size INTEGER DEFAULT 0,
                new_codec TEXT DEFAULT '',
                new_size INTEGER DEFAULT 0,
                error_log TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );"#,
        )
        .unwrap();
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, status, original_codec, original_size) VALUES (1, ?1, 'PENDING_APPROVAL', 'h264', 22)",
            params![legacy_file.to_string_lossy().to_string()],
        )
        .unwrap();
    }

    // Upgrade via normal init_db() path.
    af_db::init_db().unwrap();

    // Approving legacy row without identity must fail closed with 409 and transition to NEEDS_RESCAN.
    let (legacy_status, legacy_body) =
        read_json(approve_mediaflow_item(Path("1".to_string()), axum::body::Bytes::new()).await)
            .await;
    assert_eq!(legacy_status, StatusCode::CONFLICT);
    assert_eq!(legacy_body["code"], "NEEDS_RESCAN");

    // 1. Add a normal media fixture and run scan_directory_for_mediaflow.
    let episode = canon_media.join("episode.mp4");
    std::fs::write(&episode, b"episode-v1-bytes-12345").unwrap();

    scan_directory_for_mediaflow(&canon_media, None, true)
        .await
        .unwrap();

    let (q_status, q_body) = read_json(get_mediaflow_queue().await).await;
    assert_eq!(q_status, StatusCode::OK);
    let items = q_body.as_array().unwrap();
    let ep_row = items
        .iter()
        .find(|item| item["filePath"] == episode.to_string_lossy().as_ref())
        .expect("episode.mp4 should be enqueued");
    assert_eq!(ep_row["status"], "PENDING_APPROVAL");
    assert_eq!(ep_row["identityBound"], true);
    let fp_v1 = ep_row["sourceFingerprint"].as_str().unwrap().to_string();
    assert!(fp_v1.starts_with("v1:sha256:"));
    let ep_id_v1 = ep_row["id"].as_i64().unwrap();

    // Legacy file should also have been recovered into a fresh identity-bound PENDING_APPROVAL row.
    let legacy_refreshed = items
        .iter()
        .find(|item| {
            item["filePath"] == legacy_file.to_string_lossy().as_ref()
                && item["status"] == "PENDING_APPROVAL"
        })
        .expect("legacy.mp4 should be recovered by re-scan");
    assert_eq!(legacy_refreshed["identityBound"], true);
    assert_ne!(legacy_refreshed["id"].as_i64().unwrap(), 1);

    // 2. Modify episode.mp4 IN PLACE (exact same length, different bytes) before approval -> 409 SOURCE_CHANGED + NEEDS_RESCAN.
    std::fs::write(&episode, b"episode-v2-bytes-99999").unwrap();
    let approve_v1_body =
        axum::body::Bytes::from(serde_json::json!({ "sourceFingerprint": fp_v1 }).to_string());
    let (drift_status, drift_body) =
        read_json(approve_mediaflow_item(Path(ep_id_v1.to_string()), approve_v1_body).await).await;
    assert_eq!(drift_status, StatusCode::CONFLICT);
    assert_eq!(drift_body["code"], "SOURCE_CHANGED");

    // 3. Re-scan supersedes stale NEEDS_RESCAN row and creates fresh PENDING_APPROVAL row bound to v2.
    scan_directory_for_mediaflow(&canon_media, None, true)
        .await
        .unwrap();
    let (_, q_body2) = read_json(get_mediaflow_queue().await).await;
    let ep_row_v2 = q_body2
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["filePath"] == episode.to_string_lossy().as_ref()
                && item["status"] == "PENDING_APPROVAL"
        })
        .expect("episode.mp4 v2 should be enqueued after re-scan");
    let ep_id_v2 = ep_row_v2["id"].as_i64().unwrap();
    let fp_v2 = ep_row_v2["sourceFingerprint"].as_str().unwrap().to_string();
    assert_ne!(ep_id_v2, ep_id_v1);
    assert_ne!(fp_v2, fp_v1);

    // 4. Approving with a mismatched UI fingerprint returns 409 without mutating PENDING_APPROVAL.
    let wrong_fp_body =
        axum::body::Bytes::from(serde_json::json!({ "sourceFingerprint": fp_v1 }).to_string());
    let (mismatch_status, mismatch_body) =
        read_json(approve_mediaflow_item(Path(ep_id_v2.to_string()), wrong_fp_body).await).await;
    assert_eq!(mismatch_status, StatusCode::CONFLICT);
    assert_eq!(mismatch_body["code"], "IDENTITY_MISMATCH");

    // 5. Approving with matching fingerprint transitions atomically to APPROVED.
    let ok_fp_body =
        axum::body::Bytes::from(serde_json::json!({ "sourceFingerprint": fp_v2 }).to_string());
    let (ok_status, ok_body) =
        read_json(approve_mediaflow_item(Path(ep_id_v2.to_string()), ok_fp_body).await).await;
    assert_eq!(ok_status, StatusCode::OK);
    assert_eq!(ok_body["status"], "APPROVED");
    assert_eq!(ok_body["sourceFingerprint"], fp_v2);

    // 6. Declining an APPROVED job cancels it cleanly to DECLINED.
    let (dec_status, dec_body) =
        read_json(decline_mediaflow_item(Path(ep_id_v2.to_string())).await).await;
    assert_eq!(dec_status, StatusCode::OK);
    assert_eq!(dec_body["status"], "DECLINED");

    // 7. Re-scanning unchanged episode.mp4 must NOT re-enqueue the declined file.
    scan_directory_for_mediaflow(&canon_media, None, true)
        .await
        .unwrap();
    let (_, q_body3) = read_json(get_mediaflow_queue().await).await;
    assert!(
        !q_body3
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["filePath"] == episode.to_string_lossy().as_ref()),
        "unchanged declined file must not be re-enqueued"
    );

    // 8. Replacing episode.mp4 with a genuinely new file at the old path and re-scanning enqueues a new candidate!
    let swap_path = canon_media.join("episode.mp4.new");
    std::fs::write(&swap_path, b"genuinely-new-episode-v3-payload").unwrap();
    std::fs::rename(&swap_path, &episode).unwrap();
    scan_directory_for_mediaflow(&canon_media, None, true)
        .await
        .unwrap();
    let (_, q_body4) = read_json(get_mediaflow_queue().await).await;
    let ep_row_v3 = q_body4
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["filePath"] == episode.to_string_lossy().as_ref()
                && item["status"] == "PENDING_APPROVAL"
        })
        .expect("genuinely new file at old declined path must be enqueued");
    assert_ne!(ep_row_v3["id"].as_i64().unwrap(), ep_id_v2);
    assert_ne!(ep_row_v3["sourceFingerprint"].as_str().unwrap(), fp_v2);

    let _ = std::fs::remove_dir_all(&root);
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
fn metrics_history_selects_latest_rows_in_chronological_order_and_supports_windows_and_downsample()
{
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

pub(super) fn init_ai_test_settings() {
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
