use chrono::Utc;
use once_cell::sync::Lazy;
use std::sync::Mutex;

pub(crate) static TEST_STREAMING_DB_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

fn init_isolated_streaming_db(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "af_streaming_test_{}_{}_{}",
        name,
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db_path = dir.join("aetherflow_test.sqlite");
    std::env::remove_var("AF_DB_PATH");
    std::env::remove_var("AETHERFLOW_DB_PATH");
    std::env::set_var("DB_PATH", &db_path);
    std::env::remove_var("AETHERFLOW_DEMO_MODE");
    af_services::set_streaming_demo_mode(false);
    af_db::init_db().expect("init isolated test sqlite db");
    db_path
}

fn mark_dashboard_fixtures_as_observed() {
    af_db::get_conn()
        .unwrap()
        .execute(
            "UPDATE streaming_history SET provenance='observed_session', timestamp_certainty='observed', byte_accuracy='estimated' WHERE provider!='demo'",
            [],
        )
        .unwrap();
}

mod analytics;
mod monitor;
mod providers;
mod regressions;
