use super::*;
use crate::inventory_regressions::{isolated, Fixture};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Notify, Semaphore};

#[derive(Clone)]
enum Reply {
    Silent,
    Drip,
    Bytes(Vec<u8>),
    Held(Arc<Semaphore>, Vec<u8>),
}

struct Runner {
    socket: PathBuf,
    reply: Arc<Mutex<Reply>>,
    calls: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    idle: Arc<Notify>,
    requests: mpsc::UnboundedReceiver<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Runner {
    fn new(reply: Reply) -> Self {
        let socket = env::temp_dir().join(format!(
            "nm-{}.sock",
            &uuid::Uuid::new_v4().to_string()[..8]
        ));
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        env::set_var("AETHERFLOW_RUNNER_SOCK", &socket);
        let reply = Arc::new(Mutex::new(reply));
        let calls = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let idle = Arc::new(Notify::new());
        let (sender, requests) = mpsc::unbounded_channel();
        let task = {
            let reply = reply.clone();
            let calls = calls.clone();
            let active = active.clone();
            let peak = peak.clone();
            let idle = idle.clone();
            tokio::spawn(async move {
                let mut peers = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (mut stream, _) = accepted.unwrap();
                            let reply = reply.lock().unwrap().clone();
                            let calls = calls.clone();
                            let active = active.clone();
                            let peak = peak.clone();
                            let idle = idle.clone();
                            let sender = sender.clone();
                            peers.spawn(async move {
                                let mut request = Vec::new();
                                let mut buffer = [0; 1024];
                                loop {
                                    let received = stream.read(&mut buffer).await.unwrap();
                                    assert!(received > 0);
                                    request.extend_from_slice(&buffer[..received]);
                                    assert!(request.len() < 4096);
                                    let text = String::from_utf8_lossy(&request);
                                    if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                                        let length = headers.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().parse::<usize>().unwrap();
                                        if body.len() == length {
                                            assert!(headers.starts_with("POST /v1/app-meta HTTP/1.1"));
                                            break;
                                        }
                                    }
                                }
                                calls.fetch_add(1, Ordering::SeqCst);
                                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                                peak.fetch_max(current, Ordering::SeqCst);
                                let _ = sender.send(());
                                match reply {
                                    Reply::Silent => { let _ = stream.read(&mut buffer).await; }
                                    Reply::Drip => {
                                        for byte in b"HTTP/1.1 200 OK\r\n\r\n                                                                                                    " {
                                            if stream.write_all(&[*byte]).await.is_err() { break; }
                                            tokio::time::sleep(Duration::from_millis(40)).await;
                                        }
                                    }
                                    Reply::Bytes(bytes) => { let _ = stream.write_all(&bytes).await; }
                                    Reply::Held(gate, bytes) => {
                                        let permit = gate.acquire().await.unwrap();
                                        permit.forget();
                                        let _ = stream.write_all(&bytes).await;
                                    }
                                }
                                active.fetch_sub(1, Ordering::SeqCst);
                                idle.notify_one();
                            });
                        }
                        Some(result) = peers.join_next(), if !peers.is_empty() => { result.unwrap(); }
                    }
                }
            })
        };
        Self {
            socket,
            reply,
            calls,
            active,
            peak,
            idle,
            requests,
            task,
        }
    }

    async fn request(&mut self) {
        tokio::time::timeout(Duration::from_secs(4), self.requests.recv())
            .await
            .unwrap()
            .unwrap();
    }

    async fn drained(&self) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let notification = self.idle.notified();
                if self.active.load(Ordering::SeqCst) == 0 {
                    break;
                }
                notification.await;
            }
        })
        .await
        .expect("metadata transports must close, not linger after the collector");
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        self.task.abort();
        let _ = fs::remove_file(&self.socket);
    }
}

fn response(api_key: &str, port: i32) -> Vec<u8> {
    let output = serde_json::json!({"api_key": api_key, "configured_port": port}).to_string();
    let body = serde_json::json!({"success": true, "output": output, "error": ""}).to_string();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn native_fixture(count: usize) -> Fixture {
    let fixture = Fixture::new();
    af_db::init_db().unwrap();
    let packages: Vec<_> = (0..count)
        .map(|index| {
            let name = format!("native-fiction-{index}");
            fixture.install(&name);
            let mut package = Fixture::package(&name, "systemd", &name);
            package["lock_file"] =
                serde_json::json!(fixture.root.join(format!("install/.{name}.lock")));
            package["default_port"] = serde_json::json!(19090);
            package
        })
        .collect();
    fixture.write_packages(&packages);
    env::remove_var("AETHERFLOW_FS_ROOT");
    env::remove_var("AETHERFLOW_CONFIG_ROOT");
    clear_service_status_cache();
    mutators::clear_app_runtime_meta_cache();
    fixture
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_snapshots_share_one_metadata_budget_and_worker_bound() {
    if !isolated(
        "native_metadata_regressions::native_snapshots_share_one_metadata_budget_and_worker_bound",
    ) {
        return;
    }
    let _fixture = native_fixture(6);
    let runner = Runner::new(Reply::Silent);
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let started = Instant::now();
    let mut collectors = Vec::new();
    for _ in 0..8 {
        let barrier = barrier.clone();
        collectors.push(tokio::task::spawn_blocking(move || {
            barrier.wait();
            get_active_services().unwrap()
        }));
    }
    for collector in collectors {
        let services = collector.await.unwrap();
        for index in 0..6 {
            let service = &services[&format!("native-fiction-{index}")];
            assert!(service.api_key.is_empty());
            assert_eq!(service.active_port, 19090);
            assert_eq!(service.status, "running");
        }
    }
    println!(
        "native overlapping collectors elapsed={:?}, calls={}, peak={}",
        started.elapsed(),
        runner.calls.load(Ordering::SeqCst),
        runner.peak.load(Ordering::SeqCst)
    );
    assert!(
        started.elapsed() < Duration::from_millis(3500),
        "metadata multiplied the aggregate snapshot budget"
    );
    assert!((4..=6).contains(&runner.calls.load(Ordering::SeqCst)));
    assert!(runner.peak.load(Ordering::SeqCst) <= 4);
    runner.drained().await;
    let calls = runner.calls.load(Ordering::SeqCst);
    let started = Instant::now();
    tokio::task::spawn_blocking(get_active_services)
        .await
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(runner.calls.load(Ordering::SeqCst), calls);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_transport_has_one_deadline_even_for_slow_drips() {
    if !isolated(
        "native_metadata_regressions::native_transport_has_one_deadline_even_for_slow_drips",
    ) {
        return;
    }
    let _fixture = native_fixture(0);
    let runner = Runner::new(Reply::Drip);
    let started = Instant::now();
    let meta = tokio::task::spawn_blocking(|| mutators::get_app_runtime_meta("native-drip"))
        .await
        .unwrap();
    assert!(meta.api_key.is_empty());
    println!("drip metadata elapsed={:?}", started.elapsed());
    assert!(
        started.elapsed() < Duration::from_millis(1900),
        "per-read timeout is not a total deadline"
    );
    runner.drained().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_transport_rejects_oversized_metadata() {
    if !isolated("native_metadata_regressions::native_transport_rejects_oversized_metadata") {
        return;
    }
    let _fixture = native_fixture(0);
    let runner = Runner::new(Reply::Bytes(response(&"x".repeat(128 * 1024), 12345)));
    let meta = tokio::task::spawn_blocking(|| mutators::get_app_runtime_meta("native-large"))
        .await
        .unwrap();
    assert!(
        meta.api_key.is_empty(),
        "unbounded runner reply was accepted"
    );
    assert_eq!(meta.configured_port, 0);
    runner.drained().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_metadata_invalidation_discards_in_flight_credentials() {
    if !isolated(
        "native_metadata_regressions::native_metadata_invalidation_discards_in_flight_credentials",
    ) {
        return;
    }
    let _fixture = native_fixture(1);
    let gate = Arc::new(Semaphore::new(0));
    let mut runner = Runner::new(Reply::Held(gate.clone(), response("old-key", 12345)));
    let pending = tokio::task::spawn_blocking(get_active_services);
    runner.request().await;
    mutators::clear_app_runtime_meta_cache();
    *runner.reply.lock().unwrap() = Reply::Bytes(response("new-key", 23456));
    gate.add_permits(1);
    let services = pending.await.unwrap().unwrap();
    assert_ne!(services["native-fiction-0"].api_key, "old-key");
    let services = tokio::task::spawn_blocking(get_active_services)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(services["native-fiction-0"].api_key, "new-key");
    assert_eq!(services["native-fiction-0"].active_port, 23456);
    runner.drained().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_direct_readers_coalesce_and_preserve_both_response_shapes() {
    if !isolated("native_metadata_regressions::native_direct_readers_coalesce_and_preserve_both_response_shapes") { return; }
    let _fixture = native_fixture(0);
    let gate = Arc::new(Semaphore::new(0));
    let mut runner = Runner::new(Reply::Held(gate.clone(), response("legacy-key", 12345)));
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut collectors = Vec::new();
    for _ in 0..8 {
        let barrier = barrier.clone();
        collectors.push(tokio::task::spawn_blocking(move || {
            barrier.wait();
            mutators::get_app_runtime_meta("native-direct.service")
        }));
    }
    runner.request().await;
    gate.add_permits(8);
    for collector in collectors {
        let meta = collector.await.unwrap();
        assert_eq!(meta.api_key, "legacy-key");
        assert_eq!(meta.configured_port, 12345);
    }
    assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    mutators::clear_app_runtime_meta_cache();
    *runner.reply.lock().unwrap() = Reply::Bytes(b"HTTP/1.0 200 OK\r\n\r\n{\"ok\":true,\"data\":{\"api_key\":\"data-key\",\"configured_port\":23456}}".to_vec());
    let meta = mutators::get_app_runtime_meta("native-direct");
    assert_eq!(meta.api_key, "data-key");
    assert_eq!(meta.configured_port, 23456);
    runner.drained().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_snapshot_deadline_includes_status_and_metadata_together() {
    if !isolated("native_metadata_regressions::native_snapshot_deadline_includes_status_and_metadata_together") { return; }
    let fixture = native_fixture(6);
    fixture.command("systemctl", "test \"$1\" = show || exit 92\nexec /usr/bin/python3 -c 'import sys,time\ntime.sleep(1.0) if sys.argv[1].startswith(\"native-fiction\") else None\nprint(\"ActiveState=active\\nSubState=running\")' \"$2\"\n");
    let runner = Runner::new(Reply::Silent);
    let started = Instant::now();
    let services = tokio::task::spawn_blocking(get_active_services)
        .await
        .unwrap()
        .unwrap();
    println!(
        "combined status/metadata elapsed={:?}, calls={}",
        started.elapsed(),
        runner.calls.load(Ordering::SeqCst)
    );
    assert!(started.elapsed() < Duration::from_millis(3500));
    assert!(
        runner.calls.load(Ordering::SeqCst) > 0,
        "native fallback was not exercised"
    );
    assert!(runner.calls.load(Ordering::SeqCst) <= 6);
    for index in 0..6 {
        assert_eq!(
            services[&format!("native-fiction-{index}")].status,
            "running"
        );
    }
    runner.drained().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_cached_observations_keep_lifecycle_and_credentials_fresh() {
    if !isolated("native_metadata_regressions::native_cached_observations_keep_lifecycle_and_credentials_fresh") { return; }
    let _fixture = native_fixture(1);
    let runner = Runner::new(Reply::Bytes(response("first-key", 12345)));
    let services = tokio::task::spawn_blocking(get_active_services)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(services["native-fiction-0"].api_key, "first-key");
    let calls = runner.calls.load(Ordering::SeqCst);
    let mut jobs = package_job_snapshot().unwrap();
    jobs.active.insert(
        "native-fiction-0".into(),
        PackageJobInfo {
            package_id: "native-fiction-0".into(),
            job_id: "fresh-job".into(),
            action: "update".into(),
            status: "updating".into(),
            started_at: "now".into(),
            progress: 42,
            last_line: "fresh progress".into(),
        },
    );
    let (services, mut jobs) =
        tokio::task::spawn_blocking(move || (get_active_services_with_jobs(&jobs).unwrap(), jobs))
            .await
            .unwrap();
    assert_eq!(services["native-fiction-0"].job_id, "fresh-job");
    assert_eq!(services["native-fiction-0"].progress, 42);
    assert_eq!(services["native-fiction-0"].api_key, "first-key");
    assert_eq!(runner.calls.load(Ordering::SeqCst), calls);
    *runner.reply.lock().unwrap() = Reply::Bytes(response("rotated-key", 23456));
    mutators::clear_app_runtime_meta_cache();
    let (services, returned_jobs) =
        tokio::task::spawn_blocking(move || (get_active_services_with_jobs(&jobs).unwrap(), jobs))
            .await
            .unwrap();
    jobs = returned_jobs;
    assert_eq!(services["native-fiction-0"].api_key, "rotated-key");
    assert_eq!(services["native-fiction-0"].active_port, 23456);
    assert_eq!(services["native-fiction-0"].job_id, "fresh-job");
    *runner.reply.lock().unwrap() = Reply::Bytes(response("terminal-key", 34567));
    jobs.active.clear();
    jobs.outcomes.insert(
        "native-fiction-0".into(),
        PackageJobOutcome {
            package_id: "native-fiction-0".into(),
            job_id: "fresh-terminal".into(),
            action: "update".into(),
            status: "completed".into(),
            message: "done".into(),
            started_at: "now".into(),
            finished_at: "later".into(),
        },
    );
    let services = tokio::task::spawn_blocking(move || get_active_services_with_jobs(&jobs))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(services["native-fiction-0"].api_key, "terminal-key");
    assert_eq!(services["native-fiction-0"].active_port, 34567);
    assert!(services["native-fiction-0"].job_id.is_empty());
    assert_eq!(
        services["native-fiction-0"]
            .last_job
            .as_ref()
            .unwrap()
            .job_id,
        "fresh-terminal"
    );
    runner.drained().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_connect_to_saturated_socket_is_bounded() {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn listen(socket: std::os::raw::c_int, backlog: std::os::raw::c_int)
            -> std::os::raw::c_int;
    }
    if !isolated("native_metadata_regressions::native_connect_to_saturated_socket_is_bounded") {
        return;
    }
    let _fixture = native_fixture(0);
    let socket = env::temp_dir().join(format!(
        "nc-{}.sock",
        &uuid::Uuid::new_v4().to_string()[..8]
    ));
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    assert_eq!(unsafe { listen(listener.as_raw_fd(), 1) }, 0);
    env::set_var("AETHERFLOW_RUNNER_SOCK", &socket);
    let mut held = Vec::new();
    let mut saturated = false;
    for _ in 0..512 {
        match tokio::time::timeout(
            Duration::from_millis(20),
            tokio::net::UnixStream::connect(&socket),
        )
        .await
        {
            Ok(Ok(stream)) => held.push(stream),
            _ => {
                saturated = true;
                break;
            }
        }
    }
    assert!(saturated, "fixture did not fill the accept queue");
    let started = Instant::now();
    let meta = tokio::task::spawn_blocking(|| mutators::get_app_runtime_meta("native-full-queue"))
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(1900));
    assert!(meta.api_key.is_empty());
    assert_eq!(meta.configured_port, 0);
    drop(held);
    drop(listener);
    fs::remove_file(socket).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_deadline_uses_only_valid_last_known_metadata_for_unstarted_probes() {
    if !isolated("native_metadata_regressions::native_deadline_uses_only_valid_last_known_metadata_for_unstarted_probes") {
        return;
    }
    let fixture = native_fixture(6);
    let runner = Runner::new(Reply::Bytes(response("last-known-key", 12345)));
    let meta = tokio::task::spawn_blocking(|| mutators::get_app_runtime_meta("native-fiction-0"))
        .await
        .unwrap();
    assert_eq!(meta.api_key, "last-known-key");
    fixture.command(
        "systemctl",
        "test \"$1\" = show || exit 92\nexec /usr/bin/python3 -c 'import signal; signal.pause()'\n",
    );
    clear_service_status_cache();
    let calls = runner.calls.load(Ordering::SeqCst);
    let started = Instant::now();
    let services = tokio::task::spawn_blocking(get_active_services)
        .await
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(3500));
    assert_eq!(services["native-fiction-0"].api_key, "last-known-key");
    assert_eq!(services["native-fiction-0"].active_port, 12345);
    for index in 1..6 {
        let service = &services[&format!("native-fiction-{index}")];
        assert_eq!(service.status, "unknown");
        assert!(service.api_key.is_empty());
        assert_eq!(service.active_port, 19090);
    }
    assert_eq!(
        runner.calls.load(Ordering::SeqCst),
        calls,
        "exhausted snapshot must not start metadata transports"
    );
    runner.drained().await;
}

#[test]
fn local_metadata_database_candidates_share_the_deadline() {
    if !isolated(
        "native_metadata_regressions::local_metadata_database_candidates_share_the_deadline",
    ) {
        return;
    }
    let fixture = Fixture::new();
    env::remove_var("AETHERFLOW_CONFIG_ROOT");
    let directory = fixture.root.join("var/lib/jellyfin/data");
    fs::create_dir_all(&directory).unwrap();
    let first = rusqlite::Connection::open(directory.join("jellyfin.db")).unwrap();
    let second =
        rusqlite::Connection::open(fixture.root.join("var/lib/jellyfin/jellyfin.db")).unwrap();
    first
        .execute_batch("CREATE TABLE ApiKeys(AccessToken TEXT, DateCreated TEXT); BEGIN EXCLUSIVE;")
        .unwrap();
    second
        .execute_batch("CREATE TABLE ApiKeys(AccessToken TEXT, DateCreated TEXT); BEGIN EXCLUSIVE;")
        .unwrap();
    mutators::clear_app_runtime_meta_cache();
    let started = Instant::now();
    let meta = mutators::get_app_runtime_meta("jellyfin");
    assert!(meta.api_key.is_empty());
    println!(
        "locked native metadata databases elapsed={:?}",
        started.elapsed()
    );
    assert!(started.elapsed() < Duration::from_millis(1900));
}
