use super::*;
use axum::body::{to_bytes, Body};
use axum::http::Request;
use axum::routing::{get, post, put};
use axum::Router;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::net::UnixListener;
use tower::ServiceExt;

static ENVIRONMENT: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

struct FakeRunner {
    path: PathBuf,
    previous: Option<std::ffi::OsString>,
    seen: Arc<StdMutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}
impl FakeRunner {
    async fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("af-network-api-{}.sock", uuid::Uuid::new_v4()));
        let listener = UnixListener::bind(&path).unwrap();
        let previous = std::env::var_os("AETHERFLOW_RUNNER_SOCK");
        std::env::set_var("AETHERFLOW_RUNNER_SOCK", &path);
        *STATUS.lock().await = None;
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let received = seen.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let received = received.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: hyper::Request<Incoming>| {
                        let received = received.clone();
                        async move {
                            assert_eq!(request.uri().path(), "/v1/network");
                            let bytes = request.into_body().collect().await.unwrap().to_bytes();
                            let request: Value = serde_json::from_slice(&bytes).unwrap();
                            received.lock().unwrap().push(request.clone());
                            let action = request["action"].as_str().unwrap();
                            let error = if request["options"]["name"] == "duplicate" {
                                Some("CONFLICT: Client address overlaps an existing peer")
                            } else {
                                None
                            };
                            let output = match action {
                                "network_status" => {
                                    json!({"platform":"linux","runner_available":true,
                                    "checked_at":"2026-11-01T00:00:00Z","wireguard_available":true,"tailscale_available":true,
                                    "wireguard":{"installed":true,"state":"stopped","interface":"wg0","public_key":"public",
                                        "listen_port":"51820","address":["10.66.66.1/24"],"next_ip":"10.66.66.3/32",
                                        "peers":[],"service_state":"inactive","config_available":true},
                                    "tailscale":{"installed":true,"state":"needs_login","backend_state":"NeedsLogin",
                                        "peers":[],"advertised_routes":[],"service_state":"active"}})
                                }
                                "wg_keygen" => {
                                    json!({"private_key":"one-time-synthetic-key","public_key":"synthetic-public"})
                                }
                                "wg_add_peer" | "wg_update_peer" => {
                                    json!({"message":"Peer saved","peer":{
                                    "public_key":request["public_key"],"name":request["options"]["name"],"allowed_ips":"10.66.66.3/32"}})
                                }
                                "tailscale_set_routes" => {
                                    json!({"message":"Routes saved","routes":request["routes"]})
                                }
                                "tailscale_connect" => {
                                    json!({"message":"Login required","backend_state":"NeedsLogin",
                                    "auth_url":"https://login.tailscale.com/a/network-api-test"})
                                }
                                _ => json!({"message":"Saved"}),
                            };
                            let response = af_models::RunnerResponse {
                                success: error.is_none(),
                                output: if error.is_some() {
                                    String::new()
                                } else {
                                    output.to_string()
                                },
                                error: error.unwrap_or("").into(),
                            };
                            Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from(
                                serde_json::to_vec(&response).unwrap(),
                            ))))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            path,
            previous,
            seen,
            task,
        }
    }
}
impl Drop for FakeRunner {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(previous) = &self.previous {
            std::env::set_var("AETHERFLOW_RUNNER_SOCK", previous);
        } else {
            std::env::remove_var("AETHERFLOW_RUNNER_SOCK");
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn router() -> Router {
    Router::new()
        .route("/status", get(get_network_status))
        .route(
            "/wireguard/peers",
            post(add_wireguard_peer).get(get_wireguard_peers),
        )
        .route(
            "/wireguard/peers/:key",
            put(update_wireguard_peer).delete(remove_wireguard_peer),
        )
        .route("/wireguard/keygen", post(generate_wireguard_keys))
        .route("/tailscale/routes", post(advertise_tailscale_routes))
        .route("/tailscale/connect", post(tailscale_connect))
        .route("/tailscale/settings", post(tailscale_settings))
        .route("/:provider/service", post(network_service))
        .layer(Extension(AuthUser {
            user_id: 1,
            username: "network-test".into(),
            role: "admin".into(),
            jti: "test".into(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }))
}

async fn call(router: Router, method: &str, uri: &str, body: Value) -> (StatusCode, Value, String) {
    let response = router
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("Host", "localhost")
                .header("Content-Type", "application/json")
                .body(if method == "GET" {
                    Body::empty()
                } else {
                    Body::from(body.to_string())
                })
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let cache = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)}));
    (status, body, cache)
}

#[tokio::test]
async fn http_round_trip_uses_runner_and_preserves_empty_routes_and_private_handoff() {
    let _environment = ENVIRONMENT.lock().await;
    let runner = FakeRunner::new().await;
    let (code, status, cache) = call(router(), "GET", "/status", Value::Null).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(status["wireguard"]["state"], "stopped");
    assert_eq!(cache, "no-store");
    call(router(), "GET", "/wireguard/peers", Value::Null).await;
    assert_eq!(
        runner.seen.lock().unwrap().len(),
        1,
        "compatibility endpoints share status snapshot"
    );
    let (code, peer, _) = call(
        router(),
        "POST",
        "/wireguard/peers",
        json!({"public_key":"public","name":"Phone"}),
    )
    .await;
    assert_eq!(code, StatusCode::CREATED);
    assert_eq!(peer["peer"]["allowed_ips"], "10.66.66.3/32");
    let request = runner.seen.lock().unwrap().last().unwrap().clone();
    assert_eq!(request["action"], "wg_add_peer");
    assert_eq!(request["options"]["name"], "Phone");
    assert!(
        request.get("allowed_ips").is_none(),
        "missing address requests allocation"
    );
    call(router(), "GET", "/status", Value::Null).await;
    assert_eq!(
        runner
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["action"] == "network_status")
            .count(),
        2,
        "mutations invalidate cached status"
    );
    let (code, body, cache) = call(router(), "POST", "/wireguard/keygen", json!({})).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(cache, "no-store");
    assert_eq!(body["private_key"], "one-time-synthetic-key");
    let (code, _, _) = call(router(), "POST", "/tailscale/routes", json!({"routes":[]})).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(
        runner.seen.lock().unwrap().last().unwrap()["routes"],
        Value::Null,
        "empty routes use model default without making the request invalid"
    );
    // Deserialize the actual wire payload to prove omission still means clear-all.
    let wire: NetworkRunnerRequest =
        serde_json::from_value(runner.seen.lock().unwrap().last().unwrap().clone()).unwrap();
    assert!(wire.routes.is_empty());
    let (code, body, _) = call(
        router(),
        "POST",
        "/tailscale/connect",
        json!({"reauth":true}),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["backend_state"], "NeedsLogin");
    assert_eq!(
        runner.seen.lock().unwrap().last().unwrap()["options"]["reauth"],
        true
    );
    let (code, _, _) = call(
        router(),
        "POST",
        "/tailscale/settings",
        json!({"exit_node":""}),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(
        runner.seen.lock().unwrap().last().unwrap()["options"]["exit_node"],
        ""
    );
}

#[tokio::test]
async fn http_errors_keep_messages_and_reject_unknown_arguments_before_dispatch() {
    let _environment = ENVIRONMENT.lock().await;
    let runner = FakeRunner::new().await;
    let (code, error, _) = call(
        router(),
        "POST",
        "/wireguard/peers",
        json!({"public_key":"public","name":"duplicate"}),
    )
    .await;
    assert_eq!(code, StatusCode::CONFLICT);
    assert_eq!(error["code"], "CONFLICT");
    assert!(error["message"].as_str().unwrap().contains("overlaps"));
    let count = runner.seen.lock().unwrap().len();
    for payload in [
        json!({"public_key":"public","args":["--help"]}),
        json!({"public_key":"public","options":{"service_action":"stop"}}),
    ] {
        let (code, _, _) = call(router(), "POST", "/wireguard/peers", payload).await;
        assert!(code.is_client_error());
    }
    let (code, _, _) = call(
        router(),
        "POST",
        "/anything/service",
        json!({"action":"start"}),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    let (code, _, _) = call(
        router(),
        "POST",
        "/wireguard/service",
        json!({"action":"start;whoami"}),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(runner.seen.lock().unwrap().len(), count);
}

#[tokio::test]
async fn missing_runner_has_actionable_state_and_compatibility_endpoints_fail() {
    let _environment = ENVIRONMENT.lock().await;
    let runner = FakeRunner::new().await;
    runner.task.abort();
    std::fs::remove_file(&runner.path).unwrap();
    let (code, status, _) = call(router(), "GET", "/status", Value::Null).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(status["runner_available"], false);
    assert_eq!(status["wireguard"]["state"], "error");
    assert!(status["wireguard"]["error"]
        .as_str()
        .unwrap()
        .contains("aetherflow-runner"));
    let (code, error, _) = call(router(), "GET", "/wireguard/peers", Value::Null).await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    assert!(error.get("message").is_some());
}

#[tokio::test]
async fn actual_admin_router_blocks_unauthenticated_network_operations() {
    let _environment = ENVIRONMENT.lock().await;
    let runner = FakeRunner::new().await;
    for (method, path, body) in [
        ("GET", "/api/v1/admin/network/status", Value::Null),
        ("POST", "/api/v1/admin/network/tailscale/connect", json!({})),
        (
            "POST",
            "/api/v1/admin/network/tailscale/routes",
            json!({"routes":[]}),
        ),
        (
            "PUT",
            "/api/v1/admin/network/wireguard/peers/key",
            json!({"name":"changed"}),
        ),
    ] {
        let (code, _, _) = call(crate::routes::build_router(), method, path, body).await;
        assert!(
            matches!(code, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
            "{path}: {code}"
        );
    }
    assert!(runner.seen.lock().unwrap().is_empty());
}
