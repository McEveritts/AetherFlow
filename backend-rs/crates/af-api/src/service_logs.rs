//! Services diagnostics stay bounded and never run blocking commands on Tokio workers.
use crate::intelligence::{filter_log_entries, infer_log_level, AUDIT_LOG_FALLBACK_SQL};
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;

const MAX_CAPTURE: usize = 1024 * 1024;
const LOG_BUDGET: Duration = Duration::from_secs(5);
static LOG_READERS: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(8)));

pub async fn get_admin_logs(
    axum::Extension(user): axum::Extension<crate::auth::AuthUser>,
    query: Query<HashMap<String, String>>,
) -> Response {
    if let Err(response) = crate::auth::require_admin(&user) {
        return *response;
    }
    get_logs(query).await
}

pub async fn get_logs(Query(q): Query<HashMap<String, String>>) -> Response {
    let source = q
        .get("source")
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    let unit = q
        .get("unit")
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    if !unit.is_empty() && !af_runner::is_managed_runner_systemd_unit(&unit) {
        return crate::auth::api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Unit is not managed by AetherFlow",
        );
    }
    let Ok(_permit) = LOG_READERS.clone().try_acquire_owned() else {
        return crate::auth::api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "LOG_READ_BUSY",
            "Log readers are busy; retry shortly",
        );
    };
    let search = q
        .get("search")
        .or_else(|| q.get("filter"))
        .or_else(|| q.get("keyword"))
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();
    let level = q
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
        .unwrap_or(0)
        .min(10_000);
    let source_copy = source.clone();
    let mut raw =
        match tokio::task::spawn_blocking(move || file_entries(&source_copy, limit + offset)).await
        {
            Ok(Ok(entries)) => entries,
            Ok(Err(error)) => return diagnostic_failure(error, false),
            Err(error) => return diagnostic_failure(error, false),
        };
    if source.is_empty() || source == "journald" {
        let mut command = tokio::process::Command::new("journalctl");
        command.args([
            "-n",
            &(limit + offset).to_string(),
            "--no-pager",
            "-o",
            "short-iso",
        ]);
        if !unit.is_empty() {
            command.args(["-u", &unit]);
        }
        match af_runner::bounded_command::output(command, LOG_BUDGET, MAX_CAPTURE).await {
            Ok(output) if output.status.success() => {
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with("-- ") {
                        continue;
                    }
                    let mut parts = line.splitn(3, ' ');
                    let timestamp = parts.next().unwrap_or("");
                    let _host = parts.next();
                    let rest = parts.next().unwrap_or(line);
                    let (service, message) = rest.split_once(": ").unwrap_or(("journald", rest));
                    let safe_message = af_services::redact_secrets(message.trim());
                    raw.push(json!({"timestamp":timestamp,"source":"journald","service":service.trim(),"level":infer_log_level(&safe_message),"message":safe_message}));
                }
            }
            Ok(output) => {
                return diagnostic_failure(
                    format!(
                        "journalctl failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ),
                    false,
                )
            }
            Err(error) => {
                let timed_out = error.kind() == io::ErrorKind::TimedOut;
                return diagnostic_failure(error, timed_out);
            }
        }
    }
    // Keep the audit fallback for application/general logs. An empty successful
    // unit journal must not be silently replaced by unrelated audit events.
    if raw.is_empty() && source != "journald" && unit.is_empty() {
        let source = source.clone();
        match tokio::task::spawn_blocking(move || audit_entries(&source, limit)).await {
            Ok(Ok(entries)) => raw = entries,
            Ok(Err(error)) => return diagnostic_failure(error, false),
            Err(error) => return diagnostic_failure(error, false),
        }
    }
    let filtered = filter_log_entries(raw, &unit, &level, &search, offset, limit);
    Json(json!({"count":filtered.len(),"logs":filtered})).into_response()
}

fn diagnostic_failure(error: impl std::fmt::Display, timed_out: bool) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    tracing::warn!(error_id = %id, error = %error, "service log read failed");
    let (status, code, message) = if timed_out {
        (
            StatusCode::GATEWAY_TIMEOUT,
            "LOG_READ_TIMEOUT",
            "Log retrieval timed out; retry shortly",
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "LOG_READ_UNAVAILABLE",
            "Logs could not be read; retry shortly",
        )
    };
    (
        status,
        Json(json!({"code":code,"message":message,"error_id":id})),
    )
        .into_response()
}

fn log_path(path: &str) -> PathBuf {
    match std::env::var("AETHERFLOW_FS_ROOT") {
        Ok(root) if !root.trim().is_empty() => {
            PathBuf::from(root).join(path.trim_start_matches('/'))
        }
        _ => PathBuf::from(path),
    }
}

fn tail(path: &std::path::Path) -> io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("log source is not a regular file"));
    }
    let offset = metadata.len().saturating_sub(MAX_CAPTURE as u64);
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    file.take(MAX_CAPTURE as u64).read_to_end(&mut bytes)?;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if offset > 0 {
        text = text
            .split_once('\n')
            .map(|(_, tail)| tail.to_owned())
            .unwrap_or_default();
    }
    Ok(text)
}

static ISO_LOG_TS_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r"^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(?:\s|\]|$)",
    )
    .expect("valid ISO log timestamp regex")
});

static SYSLOG_TS_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r"^((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})(?:\s|$)",
    )
    .expect("valid syslog timestamp regex")
});

fn extract_log_timestamp(line: &str) -> String {
    let trimmed = line.trim_start();
    if let Some(caps) = ISO_LOG_TS_RE.captures(trimmed) {
        if let Some(m) = caps.get(1) {
            return m.as_str().to_string();
        }
    }
    if let Some(caps) = SYSLOG_TS_RE.captures(trimmed) {
        if let Some(m) = caps.get(1) {
            return m.as_str().to_string();
        }
    }
    String::new()
}

fn file_entries(source: &str, line_limit: usize) -> io::Result<Vec<Value>> {
    let files: Vec<(&str, &str)> = match source {
        "application" | "deploy" => vec![
            ("application", "/var/log/aetherflow/deploy.log"),
            ("application", "/var/log/aetherflow-deploy.log"),
        ],
        "syslog" => vec![
            ("syslog", "/var/log/syslog"),
            ("syslog", "/var/log/messages"),
        ],
        "apache" => vec![
            ("apache", "/var/log/apache2/error.log"),
            ("apache", "/var/log/apache2/access.log"),
        ],
        "" => vec![
            ("application", "/var/log/aetherflow/deploy.log"),
            ("application", "/var/log/aetherflow-deploy.log"),
            ("syslog", "/var/log/syslog"),
            ("apache", "/var/log/apache2/error.log"),
        ],
        _ => Vec::new(),
    };
    let resolved: Vec<(&str, PathBuf)> = files
        .into_iter()
        .map(|(src, path)| (src, log_path(path)))
        .collect();
    file_entries_from_paths(&resolved, line_limit)
}

fn file_entries_from_paths(files: &[(&str, PathBuf)], line_limit: usize) -> io::Result<Vec<Value>> {
    let mut entries = Vec::new();
    for (source, path) in files {
        let content = match tail(path) {
            Ok(content) => content,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for line in content
            .lines()
            .rev()
            .take(line_limit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
            if !line.trim().is_empty() {
                let safe_message = af_services::redact_secrets(line.trim());
                let timestamp = extract_log_timestamp(&safe_message);
                entries.push(json!({"timestamp":timestamp,"source":*source,"service":*source,"level":infer_log_level(&safe_message),"message":safe_message}));
            }
        }
    }
    Ok(entries)
}

fn audit_entries(source: &str, limit: usize) -> anyhow::Result<Vec<Value>> {
    let conn = af_db::get_read_conn()?;
    let mut stmt = conn.prepare(AUDIT_LOG_FALLBACK_SQL)?;
    let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
        let timestamp: String=row.get(0)?; let action: String=row.get(1)?;let target:String=row.get(2)?;let detail:String=row.get(3)?;
        let raw_message = if detail.is_empty(){action}else{format!("{action}: {detail}")};
        let message = af_services::redact_secrets(&raw_message);
        Ok(json!({"timestamp":timestamp,"source":if source.is_empty(){"application"}else{source},"service":target,"level":infer_log_level(&message),"message":message}))
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    #[test]
    fn file_tails_bound_bytes_and_reject_redirected_or_special_files() {
        let root = std::env::temp_dir().join(format!("af-log-tail-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let path = root.join("application.log");
        fs::write(
            &path,
            format!("{}\nlast-line\n", "x".repeat(MAX_CAPTURE * 2)),
        )
        .unwrap();
        let text = tail(&path).unwrap();
        assert!(text.len() <= MAX_CAPTURE);
        assert!(text.ends_with("last-line\n"));
        let redirected = root.join("redirect");
        symlink(&path, &redirected).unwrap();
        assert!(tail(&redirected).is_err());
        let fifo = root.join("pipe");
        let fifo_c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(tail(&fifo).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stalled_journal_yields_then_times_out_without_a_fabricated_empty_result() {
        if crate::plugins::tests::run_plugin_test_in_subprocess() {
            return;
        }
        let root = std::env::temp_dir().join(format!("af-journal-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let script = root.join("journalctl");
        let pidfile = root.join("pid");
        fs::write(
            &script,
            "#!/bin/sh\necho $$ > \"$AF_JOURNAL_PID\"\nexec sleep 60\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        std::env::set_var(
            "PATH",
            format!("{}:{}", root.display(), std::env::var("PATH").unwrap()),
        );
        std::env::set_var("AF_JOURNAL_PID", &pidfile);
        let query = Query(HashMap::from([("source".into(), "journald".into())]));
        let task = tokio::spawn(get_logs(query));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !pidfile.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            !task.is_finished(),
            "journal is still blocked while unrelated async work runs"
        );
        let response = tokio::time::timeout(Duration::from_secs(6), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], "LOG_READ_TIMEOUT");
        assert!(body.get("logs").is_none());
        let pid = fs::read_to_string(pidfile).unwrap();
        assert!(!std::path::Path::new(&format!("/proc/{}", pid.trim())).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn log_units_and_admin_identity_are_validated() {
        for unit in ["ssh*", "*.service", "unmanaged-fixture.service"] {
            let response = get_logs(Query(HashMap::from([("unit".into(), unit.into())]))).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let user = crate::auth::AuthUser {
            user_id: 1,
            username: "member".into(),
            role: "user".into(),
            jti: String::new(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        };
        let response = get_admin_logs(axum::Extension(user), Query(HashMap::new())).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn reader_saturation_is_rejected_without_spawning_commands() {
        let _all = LOG_READERS.clone().acquire_many_owned(8).await.unwrap();
        let response = get_logs(Query(HashMap::new())).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn file_entries_extract_leading_timestamps_and_do_not_fabricate_now() {
        assert_eq!(
            extract_log_timestamp("2026-11-19T14:42:44Z INFO service started"),
            "2026-11-19T14:42:44Z"
        );
        assert_eq!(
            extract_log_timestamp("2026-11-19 14:42:44.123+02:00 WARN disk near full"),
            "2026-11-19 14:42:44.123+02:00"
        );
        assert_eq!(
            extract_log_timestamp("[2026-11-19T14:42:44Z] deploy completed"),
            "2026-11-19T14:42:44Z"
        );
        assert_eq!(
            extract_log_timestamp("Nov  5 08:15:22 host sshd[12]: accepted"),
            "Nov  5 08:15:22"
        );
        assert_eq!(
            extract_log_timestamp("Nov 19 14:42:44 host kernel: ready"),
            "Nov 19 14:42:44"
        );
        assert_eq!(extract_log_timestamp("plain message without timestamp"), "");
        assert_eq!(
            extract_log_timestamp("Error occurred on 2026-11-19T14:42:44Z"),
            ""
        );

        let root = std::env::temp_dir().join(format!("af-log-ts-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let path = root.join("deploy.log");
        fs::write(
            &path,
            concat!(
                "2026-11-19T10:00:00Z deploy step 1\n",
                "Nov  5 08:15:22 host daemon: started\n",
                "untimestamped diagnostic line\n",
            ),
        )
        .unwrap();

        let entries = file_entries_from_paths(&[("application", path)], 10).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0]["timestamp"], "2026-11-19T10:00:00Z");
        assert_eq!(entries[1]["timestamp"], "Nov  5 08:15:22");
        assert_eq!(entries[2]["timestamp"], "");
        assert_eq!(entries[2]["message"], "untimestamped diagnostic line");

        fs::remove_dir_all(root).unwrap();
    }
}
