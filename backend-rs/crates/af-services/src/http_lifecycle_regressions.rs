use super::*;
use crate::inventory_regressions::{isolated, Fixture};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn runner_controls_require_complete_success_acknowledgements() {
    if !isolated(
        "http_lifecycle_regressions::runner_controls_require_complete_success_acknowledgements",
    ) {
        return;
    }
    let fixture = Fixture::new();
    fixture.command(
        "systemctl",
        "printf 'unexpected fallback\\n' >> \"$AF_STATUS_CALLS\"; exit 93",
    );
    let socket = env::temp_dir().join(format!(
        "hc-{}.sock",
        &uuid::Uuid::new_v4().to_string()[..8]
    ));
    env::set_var("AETHERFLOW_RUNNER_SOCK", &socket);
    let valid = r#"{"success":true,"output":"","error":""}"#;
    let responses = vec![
        ("empty", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string(), false),
        ("truncated-json", "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"success\":".to_string(), false),
        ("wrong-shape", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_string(), false),
        ("short-frame", format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{valid}", valid.len() + 1), false),
        ("extra-frame", format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{valid}x", valid.len()), false),
        ("missing-length", format!("HTTP/1.1 200 OK\r\n\r\n{valid}"), false),
        ("wrong-status", format!("HTTP/1.1 2000 OK\r\nContent-Length: {}\r\n\r\n{valid}", valid.len()), false),
        ("negative", "HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n{\"success\":false}".to_string(), false),
        ("duplicate-length", format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Length: {}\r\n\r\n{valid}", valid.len(), valid.len()), false),
        ("chunked", format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: {}\r\n\r\n{valid}", valid.len()), false),
        ("valid", format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{valid}", valid.len()), true),
    ];
    let mut unexpected = Vec::new();
    for (label, response, expected_success) in responses {
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let received = stream.read(&mut request).await.unwrap();
            assert!(
                received > 0,
                "control request must precede its acknowledgement"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let result = control_service_with_manager("sonarr", "stop", "systemd-unit").await;
        peer.await.unwrap();
        fs::remove_file(&socket).unwrap();
        if result.is_ok() != expected_success {
            unexpected.push(format!("{label}: {result:?}"));
        }
    }
    assert!(
        !fixture.calls.exists(),
        "a transmitted request must never fall back locally"
    );
    assert!(
        unexpected.is_empty(),
        "invalid acknowledgements: {unexpected:?}"
    );
}

fn blueprint_fixture() -> Fixture {
    let fixture = Fixture::new();
    fixture.write_packages(&[
        Fixture::package("sonarr", "systemd", "sonarr"),
        Fixture::package("rutorrent", "systemd", "apache2"),
        Fixture::package("phpmyadmin", "systemd", "apache2"),
        Fixture::package("calibreweb", "systemd", "calibreweb"),
    ]);
    af_db::init_db().unwrap();
    env::set_var("AETHERFLOW_RUNNER_SOCK", fixture.root.join("absent.sock"));
    env::set_var("AETHERFLOW_HOSTS_FILE", fixture.root.join("hosts"));
    fs::write(fixture.root.join("hosts"), "127.0.0.1 localhost\n").unwrap();
    fs::create_dir_all(fixture.root.join("etc/apache2/sites-available")).unwrap();
    fs::create_dir_all(fixture.root.join("var/lib/sonarr")).unwrap();
    fs::write(
        fixture.root.join("var/lib/sonarr/config.xml"),
        "<Config><Port>18989</Port></Config>\n",
    )
    .unwrap();
    fixture
}

#[tokio::test]
async fn blueprint_mutations_reject_live_removal_before_any_filesystem_write() {
    if !isolated("http_lifecycle_regressions::blueprint_mutations_reject_live_removal_before_any_filesystem_write") {
        return;
    }
    let fixture = blueprint_fixture();
    let config = fixture.root.join("var/lib/sonarr/config.xml");
    let before = fs::read(&config).unwrap();
    let hosts_before = fs::read(fixture.root.join("hosts")).unwrap();
    let mut conn = rusqlite::Connection::open(&fixture.journal).unwrap();
    let owner = af_release::lifecycle::admit_job(
        &mut conn,
        "sonarr",
        "removal",
        "remove",
        "now",
        &["sonarr".into()],
    )
    .unwrap();
    let error = mutators::apply_blueprint_app_config("sonarr", 18989)
        .await
        .unwrap_err();
    assert!(error.contains("reservation"), "{error}");
    assert_eq!(fs::read(config).unwrap(), before);
    assert_eq!(fs::read(fixture.root.join("hosts")).unwrap(), hosts_before);
    assert_eq!(
        fs::read_dir(fixture.root.join("etc/apache2/sites-available"))
            .unwrap()
            .count(),
        0
    );
    assert!(af_runner::acquire_lifecycle_admission_lock(None).is_ok());
    drop(owner);
}

#[tokio::test]
async fn blueprint_admission_covers_shared_units_and_reentrant_owned_callbacks() {
    if !isolated("http_lifecycle_regressions::blueprint_admission_covers_shared_units_and_reentrant_owned_callbacks") {
        return;
    }
    let fixture = blueprint_fixture();
    let mut conn = rusqlite::Connection::open(&fixture.journal).unwrap();
    let owner = af_release::lifecycle::admit_job(
        &mut conn,
        "rutorrent",
        "shared",
        "remove",
        "now",
        &["apache2".into()],
    )
    .unwrap();
    let error = mutators::with_blueprint_mutation::<(), _>("phpmyadmin", async {
        panic!("shared-unit reservation must reject before the callback")
    })
    .await
    .unwrap_err();
    assert!(af_runner::is_lifecycle_busy(&error), "{error:#}");
    af_release::lifecycle::finish_job(&conn, "rutorrent", "shared", "remove", true, "").unwrap();
    drop(owner);

    let owner = af_release::lifecycle::admit_job(
        &mut conn,
        "sonarr",
        "owned",
        "update",
        "now",
        &["sonarr".into()],
    )
    .unwrap();
    af_runner::PACKAGE_JOB_ID
        .scope(
            "owned".into(),
            mutators::with_blueprint_mutation("sonarr", async {
                assert!(af_runner::acquire_lifecycle_admission_lock(None).is_err());
                mutators::apply_blueprint_app_config("sonarr", 18989)
                    .await
                    .map_err(anyhow::Error::msg)?;
                af_db::set_app_ingress_config_for_lifecycle(
                    &af_models::AppIngressConfig {
                        app_name: "sonarr".into(),
                        listen_port: 18989,
                        ..Default::default()
                    },
                    "owned",
                    "update",
                )?;
                assert!(af_runner::acquire_lifecycle_admission_lock(None).is_err());
                Ok(())
            }),
        )
        .await
        .unwrap();
    assert!(af_runner::acquire_lifecycle_admission_lock(None).is_ok());
    assert!(
        fs::read_to_string(fixture.root.join("var/lib/sonarr/config.xml"))
            .unwrap()
            .contains("<Port>18989</Port>")
    );
    assert_eq!(
        conn.query_row(
            "SELECT status FROM package_lifecycle_jobs WHERE job_id='owned'",
            [],
            |row| row.get::<_, String>(0)
        )
        .unwrap(),
        "updating"
    );
    af_release::lifecycle::finish_job(&conn, "sonarr", "owned", "update", true, "").unwrap();
    drop(owner);
    mutators::with_blueprint_mutation("calibreweb", async { Ok(()) })
        .await
        .unwrap();
}

#[tokio::test]
async fn blueprint_required_vhost_and_dns_failures_are_not_success() {
    if !isolated(
        "http_lifecycle_regressions::blueprint_required_vhost_and_dns_failures_are_not_success",
    ) {
        return;
    }
    let fixture = blueprint_fixture();
    let vhost = fixture
        .root
        .join("etc/apache2/sites-available/aetherflow-app-sonarr.conf");
    fs::create_dir(&vhost).unwrap();
    assert!(mutators::apply_blueprint_app_config("sonarr", 18989)
        .await
        .is_err());
    fs::remove_dir(vhost).unwrap();
    let hosts = fixture.root.join("hosts");
    fs::remove_file(&hosts).unwrap();
    fs::create_dir(&hosts).unwrap();
    assert!(mutators::apply_blueprint_app_config("sonarr", 18989)
        .await
        .is_err());
    assert!(af_runner::acquire_lifecycle_admission_lock(None).is_ok());
}

#[tokio::test]
async fn blueprint_admission_is_released_on_cancellation() {
    if !isolated("http_lifecycle_regressions::blueprint_admission_is_released_on_cancellation") {
        return;
    }
    let _fixture = blueprint_fixture();
    let (entered, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(mutators::with_blueprint_mutation("sonarr", async move {
        entered.send(()).unwrap();
        std::future::pending::<anyhow::Result<()>>().await
    }));
    started.await.unwrap();
    assert!(af_runner::acquire_lifecycle_admission_lock(None).is_err());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(af_runner::acquire_lifecycle_admission_lock(None).is_ok());
}
