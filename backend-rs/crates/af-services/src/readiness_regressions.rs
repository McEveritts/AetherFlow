use super::*;
use crate::inventory_regressions::{isolated, Fixture};
use std::sync::{Arc, Barrier};

#[test]
fn snapshots_bound_and_coalesce_slow_observations_without_caching_jobs() {
    if !isolated("readiness_regressions::snapshots_bound_and_coalesce_slow_observations_without_caching_jobs") {
        return;
    }
    let fixture = Fixture::new();
    let packages: Vec<_> = (0..6)
        .map(|index| {
            let name = format!("slow-{index}");
            fixture.install(&name);
            Fixture::package(&name, "systemd", &name)
        })
        .collect();
    fixture.write_packages(&packages);
    fixture.command("systemctl", "exec /usr/bin/python3 -c 'import os,signal,sys\nwith open(os.environ[\"AF_STATUS_CALLS\"], \"a\") as output: output.write(\" \".join(sys.argv[1:])+\"\\n\")\nassert sys.argv[1] == \"show\"\nif sys.argv[2] in (\"aetherflow-api\", \"aetherflow-frontend\", \"apache2\"):\n print(\"ActiveState=active\\nSubState=running\")\nelse: signal.pause()' \"$@\"\n");
    clear_service_status_cache();
    let barrier = Arc::new(Barrier::new(8));
    let started = Instant::now();
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    get_active_services().unwrap()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    let elapsed = started.elapsed();
    println!("eight overlapping snapshots: {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(5),
        "aggregate budget exceeded: {elapsed:?}"
    );
    for services in results {
        for core in [
            "AetherFlow API",
            "AetherFlow Frontend",
            "Apache2 Web Server",
        ] {
            assert_eq!(services[core].status, "running");
        }
        for index in 0..6 {
            let service = &services[&format!("slow-{index}")];
            assert_eq!(service.status, "unknown");
            assert_eq!(service.components[0].status, "unknown");
        }
    }
    let before = fs::read_to_string(&fixture.calls).unwrap();
    assert_eq!(
        before.lines().count(),
        9,
        "overlapping collectors duplicated probes: {before}"
    );
    let repeated = Instant::now();
    assert_eq!(get_active_services().unwrap()["slow-0"].status, "unknown");
    assert!(repeated.elapsed() < Duration::from_millis(500));
    assert_eq!(fs::read_to_string(&fixture.calls).unwrap(), before);
    let mut jobs = package_job_snapshot().unwrap();
    jobs.outcomes.insert(
        "slow-0".into(),
        PackageJobOutcome {
            job_id: "fresh-outcome".into(),
            package_id: "slow-0".into(),
            action: "update".into(),
            status: "failed".into(),
            message: "fresh failure".into(),
            started_at: String::new(),
            finished_at: String::new(),
        },
    );
    let changed = Instant::now();
    let services = get_active_services_with_jobs(&jobs).unwrap();
    assert!(changed.elapsed() < Duration::from_secs(5));
    assert_eq!(
        services["slow-0"].last_job.as_ref().unwrap().job_id,
        "fresh-outcome"
    );
    assert_eq!(services["slow-0"].status, "unknown");
    let refreshed = fs::read_to_string(&fixture.calls).unwrap();
    assert_eq!(
        refreshed.lines().count(),
        18,
        "terminal outcomes must invalidate observations"
    );
    jobs.active.insert(
        "slow-0".into(),
        PackageJobInfo {
            package_id: "slow-0".into(),
            job_id: "fresh-reservation".into(),
            action: "update".into(),
            status: "updating".into(),
            started_at: String::new(),
            progress: 5,
            last_line: "fresh progress".into(),
        },
    );
    let repeated = Instant::now();
    let services = get_active_services_with_jobs(&jobs).unwrap();
    assert!(repeated.elapsed() < Duration::from_millis(500));
    assert_eq!(services["slow-0"].job_id, "fresh-reservation");
    assert_eq!(services["slow-0"].job_status, "updating");
    assert_eq!(
        services["slow-0"].last_job.as_ref().unwrap().job_id,
        "fresh-outcome"
    );
    assert_eq!(fs::read_to_string(&fixture.calls).unwrap(), refreshed);
    clear_service_status_cache();
    fixture.command(
        "systemctl",
        "test \"$1\" = show || exit 92\nprintf 'ActiveState=active\\nSubState=running\\n'\n",
    );
    assert_eq!(get_active_services().unwrap()["slow-0"].status, "running");
}

#[test]
fn aggregate_budget_leaves_unstarted_units_unknown_and_bounds_pm2() {
    if !isolated(
        "readiness_regressions::aggregate_budget_leaves_unstarted_units_unknown_and_bounds_pm2",
    ) {
        return;
    }
    let fixture = Fixture::new();
    let mut packages: Vec<_> = (0..24)
        .map(|index| {
            let name = format!("slow-{index}");
            fixture.install(&name);
            Fixture::package(&name, "systemd", &name)
        })
        .collect();
    fixture.install("slow-node");
    packages.push(Fixture::package("slow-node", "pm2", "slow-node"));
    fixture.write_packages(&packages);
    fixture.command("systemctl", "exec /usr/bin/python3 -c 'import os,signal,sys\nwith open(os.environ[\"AF_STATUS_CALLS\"], \"a\") as output: output.write(\" \".join(sys.argv[1:])+\"\\n\")\nassert sys.argv[1] == \"show\"\nif sys.argv[2] in (\"aetherflow-api\", \"aetherflow-frontend\", \"apache2\"):\n print(\"ActiveState=active\\nSubState=running\")\nelse: signal.pause()' \"$@\"\n");
    fixture.command("pm2", "test \"$1\" = jlist || exit 92\nprintf 'pm2 jlist\\n' >> \"$AF_STATUS_CALLS\"\nexec /usr/bin/python3 -c 'import signal; signal.pause()'\n");
    clear_service_status_cache();
    let started = Instant::now();
    let services = get_active_services().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(services.len(), 28);
    for index in 0..24 {
        assert_eq!(services[&format!("slow-{index}")].status, "unknown");
    }
    assert_eq!(services["slow-node"].status, "unknown");
    assert_eq!(services["slow-node"].components[0].status, "unknown");
    let calls = fs::read_to_string(&fixture.calls).unwrap();
    assert!(
        calls.lines().count() <= 11,
        "aggregate budget must not start the entire queue: {calls}"
    );
    assert!(calls.lines().any(|line| line == "pm2 jlist"));
    assert_eq!(
        get_active_services().unwrap()["slow-node"].status,
        "unknown"
    );
    assert_eq!(fs::read_to_string(&fixture.calls).unwrap(), calls);
}

#[test]
fn unit_cache_lifetime_starts_after_probe_completion() {
    if !isolated("readiness_regressions::unit_cache_lifetime_starts_after_probe_completion") {
        return;
    }
    let fixture = Fixture::new();
    fixture.command(
        "systemctl",
        "test \"$1\" = show || exit 92\nexec /usr/bin/python3 -c 'import signal; signal.pause()'\n",
    );
    clear_service_status_cache();
    assert_eq!(get_systemd_unit_info("slow-unit").0, "unknown");
    let cache = SERVICE_INFO_CACHE.read().unwrap();
    let (_, expires) = cache.get("unit:slow-unit:required:true").unwrap();
    assert!(expires.saturating_duration_since(Instant::now()) > Duration::from_millis(2900));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalidated_in_flight_probes_cannot_repopulate_the_cache() {
    use tokio::io::AsyncWriteExt;
    if !isolated("readiness_regressions::invalidated_in_flight_probes_cannot_repopulate_the_cache")
    {
        return;
    }
    let fixture = Fixture::new();
    let socket = env::temp_dir().join(format!(
        "ic-{}.sock",
        &uuid::Uuid::new_v4().to_string()[..8]
    ));
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    env::set_var("AF_INVALIDATION_SOCKET", &socket);
    fixture.command("systemctl", "test \"$1\" = show || exit 92\nexec /usr/bin/python3 -c 'import os,socket\nprobe=socket.socket(socket.AF_UNIX)\nprobe.connect(os.environ[\"AF_INVALIDATION_SOCKET\"])\nprobe.recv(1)\nprint(\"ActiveState=inactive\\nSubState=dead\")'\n");
    clear_service_status_cache();
    let pending = tokio::task::spawn_blocking(|| get_systemd_unit_info("in-flight"));
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
        .await
        .unwrap()
        .unwrap();
    clear_service_status_cache();
    fixture.command(
        "systemctl",
        "test \"$1\" = show || exit 92\nprintf 'ActiveState=active\\nSubState=running\\n'\n",
    );
    stream.write_all(b"x").await.unwrap();
    assert_eq!(pending.await.unwrap().0, "stopped");
    assert_eq!(get_systemd_unit_info("in-flight").0, "running");
    drop(listener);
    fs::remove_file(socket).unwrap();
}
