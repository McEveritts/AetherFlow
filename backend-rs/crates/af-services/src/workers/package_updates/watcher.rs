use super::*;

/// Helper recognizing 7..=40 character lowercase/uppercase hexadecimal strings (`^[0-9a-fA-F]{7,40}$`)
/// that contain NO dots (`.`), and either are 40 chars OR contain at least one hex letter `[a-fA-F]`.
pub fn is_git_commit_sha(token: &str) -> bool {
    let t = token.trim();
    if t.len() < 7 || t.len() > 40 || t.contains('.') {
        return false;
    }
    if !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    t.bytes().any(|b| matches!(b, b'a'..=b'f' | b'A'..=b'F'))
}

/// Normalizes a version token or tag into a canonical version string.
pub fn normalize_version_token(raw: &str) -> String {
    let extracted = extract_version(raw, "");
    if !extracted.is_empty() {
        extracted
    } else {
        raw.trim()
            .strip_prefix('v')
            .or_else(|| raw.trim().strip_prefix('V'))
            .unwrap_or(raw.trim())
            .to_string()
    }
}

/// Parses a synthetic commit-suffixed version such as `0.1.0-6e840ac`.
pub fn parse_synthetic_commit_version(token: &str) -> Option<(&str, &str)> {
    let s = token
        .trim()
        .strip_prefix('v')
        .or_else(|| token.trim().strip_prefix('V'))
        .unwrap_or(token.trim());
    let (prefix, sha) = s.rsplit_once('-')?;
    if sha.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !is_git_commit_sha(sha) {
        return None;
    }
    if prefix
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    {
        Some((prefix, sha))
    } else {
        None
    }
}

/// Parses a multi-component manifest like `frontend:<sha>,backend:<sha>,proxy:<sha>` or generic `comp1:1.1,comp2:2.0`.
pub fn parse_component_manifest(token: &str) -> Option<HashMap<String, String>> {
    let s = token.trim();
    if !s.contains(':') && !s.contains('=') {
        return None;
    }
    let parts: Vec<&str> = s.split(',').collect();
    let mut seen = std::collections::HashSet::new();
    for p in &parts {
        let trimmed = p.trim();
        if trimmed.is_empty() {
            return None;
        }
        let (k, _) = {
            let idx = trimmed.find(['=', ':'])?;
            (&trimmed[..idx], &trimmed[idx + 1..])
        };
        let key = k.trim().to_lowercase();
        if key.is_empty() || !seen.insert(key) {
            return None;
        }
    }
    af_release::lifecycle::parse_component_manifest(s)
}

pub fn normalize_component_manifest(map: &HashMap<String, String>) -> String {
    if map.contains_key("frontend")
        && map.contains_key("backend")
        && map.contains_key("proxy")
        && map.len() == 3
    {
        format!(
            "frontend:{},backend:{},proxy:{}",
            map["frontend"], map["backend"], map["proxy"]
        )
    } else {
        let mut keys: Vec<_> = map.keys().collect();
        keys.sort();
        keys.iter()
            .map(|k| format!("{}:{}", k, map[*k]))
            .collect::<Vec<_>>()
            .join(",")
    }
}

pub fn is_component_manifest(token: &str) -> bool {
    parse_component_manifest(token).is_some()
}

/// Status text is public (Marketplace) and visible to ordinary Services viewers.
/// Only fixed summaries may cross this boundary, including historical DB/cache rows.
pub fn public_update_error(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("rate limit") {
        return "GitHub API rate limit reached; retaining last confirmed version".to_string();
    }
    if lower.starts_with("installed version check failed") {
        return error.to_string();
    }
    match error {
        "" => String::new(),
        "Installed version could not be confirmed"
        | "Latest version could not be confirmed"
        | "Installed version could not be confirmed; Latest version could not be confirmed"
        | "Installed version probe returned no output; retaining last known installed version"
        | "GitHub API rate limit reached; retaining last confirmed version" => error.to_string(),
        _ => "Update status could not be confirmed".to_string(),
    }
}

/// Sanitizes internal update check error messages into stable, safe descriptions.
pub fn sanitize_update_check_error(error: &str) -> String {
    let lower = error.to_ascii_lowercase();
    if lower.contains("rate limit") {
        "GitHub API rate limit reached; retaining last confirmed version".to_string()
    } else {
        public_update_error(error)
    }
}

pub(in crate::workers) fn serialize_update_error<S: serde::Serializer>(
    error: &str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&public_update_error(error))
}

pub fn ensure_app_updates_columns() {
    let Ok(conn) = af_db::get_conn() else {
        return;
    };
    ensure_app_updates_columns_with_connection(&conn);
}

pub fn ensure_app_updates_columns_with_connection(conn: &rusqlite::Connection) {
    let _ = conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS app_updates (
            package_name TEXT PRIMARY KEY,
            installed_version TEXT,
            latest_version TEXT,
            update_available BOOLEAN,
            update_url TEXT,
            checked_at DATETIME,
            last_error TEXT,
            source_key TEXT NOT NULL DEFAULT ''
        );
        ALTER TABLE app_updates ADD COLUMN source_key TEXT NOT NULL DEFAULT '';",
    );
}

pub(in crate::workers) static PACKAGE_UPDATE_CACHE_DB_PATH: Lazy<Mutex<String>> =
    Lazy::new(|| Mutex::new(String::new()));

pub fn load_previous_package_update_records() -> HashMap<String, PackageUpdateRecord> {
    let mut result = HashMap::new();

    if let Ok(conn) = af_db::get_read_conn() {
        let with_source_sql =
            "SELECT package_name, COALESCE(installed_version, ''), COALESCE(latest_version, ''),
                    COALESCE(update_available, 0), COALESCE(update_url, ''),
                    COALESCE(CAST(checked_at AS TEXT), ''), COALESCE(last_error, ''),
                    COALESCE(source_key, '')
             FROM app_updates";
        let fallback_sql =
            "SELECT package_name, COALESCE(installed_version, ''), COALESCE(latest_version, ''),
                    COALESCE(update_available, 0), COALESCE(update_url, ''),
                    COALESCE(CAST(checked_at AS TEXT), ''), COALESCE(last_error, ''),
                    ''
             FROM app_updates";

        let stmt_res = conn
            .prepare(with_source_sql)
            .or_else(|_| conn.prepare(fallback_sql));
        if let Ok(mut stmt) = stmt_res {
            if let Ok(rows) = stmt.query_map([], |r| {
                let pkg_id: String = r.get(0)?;
                let installed_ver: String = r.get(1)?;
                Ok(PackageUpdateRecord {
                    package_id: pkg_id,
                    installed: !installed_ver.is_empty(),
                    installed_version: installed_ver,
                    latest_version: r.get(2)?,
                    update_available: r.get(3)?,
                    release_url: r.get(4)?,
                    checked_at: r.get(5)?,
                    error: public_update_error(&r.get::<_, String>(6)?),
                    source_key: r.get(7)?,
                })
            }) {
                for row in rows.flatten() {
                    result.insert(row.package_id.clone(), row);
                }
            }
        }
    }
    result
}

/// Returns persisted and cached update records with safe status summaries.
pub fn get_package_update_map() -> HashMap<String, PackageUpdateRecord> {
    let current_db = af_db::get_db_path();
    let mut result = load_previous_package_update_records();

    if let Ok(mut cache) = PACKAGE_UPDATE_CACHE.lock() {
        if let Ok(mut tracked_db) = PACKAGE_UPDATE_CACHE_DB_PATH.lock() {
            if *tracked_db != current_db {
                cache.clear();
                *tracked_db = current_db;
            }
        }
        for (k, v) in &result {
            cache.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for (k, v) in cache.iter() {
            let should_overlay = match result.get(k) {
                None => true,
                Some(db_rec) => !v.checked_at.is_empty() && v.checked_at > db_rec.checked_at,
            };
            if should_overlay {
                result.insert(k.clone(), v.clone());
            }
        }
    }

    for record in result.values_mut() {
        record.error = public_update_error(&record.error);
    }
    result
}

/// Refreshes the update status of a single package by ID (`pkg_id`), updating both
/// [`PACKAGE_UPDATE_CACHE`] and the `app_updates` table in SQLite.
pub async fn refresh_package_update_by_id(pkg_id: &str) -> Option<PackageUpdateRecord> {
    let trimmed = pkg_id.trim();
    if trimmed.is_empty() {
        return None;
    }

    let pkgs = crate::get_packages().ok()?;
    let pkg = pkgs.into_iter().find(|p| p.name == trimmed)?;

    let client = build_github_http_client();
    let base_url = resolve_github_api_base_url();

    let (record, notify) = check_single_package(&client, &base_url, &pkg).await;
    if notify {
        let label = if pkg.label.trim().is_empty() {
            &pkg.name
        } else {
            &pkg.label
        };
        insert_user_notification(
            1,
            "info",
            &format!("{} update available", label),
            &format!(
                "Installed {}, latest {}.",
                record.installed_version, record.latest_version
            ),
        );
    }

    Some(record)
}

/// Inspects all installed packages from [`crate::get_packages()`], detects local version
/// via binary `--version` / `dpkg-query` / version file where available, queries the
/// upstream GitHub release API (or `apt-cache` / `git ls-remote`), compares versions,
/// caches the results in [`PACKAGE_UPDATE_CACHE`] and `app_updates`, and returns the list.
pub async fn refresh_all_package_updates() -> anyhow::Result<Vec<PackageUpdateRecord>> {
    // Inventory errors must remain unknown, never a successful empty check.
    // Journal/catalog/lock inspection can block, so keep it off the async thread.
    let pkgs = tokio::task::spawn_blocking(crate::get_packages).await??;

    let client = build_github_http_client();
    let base_url = resolve_github_api_base_url();
    let mut records = Vec::new();

    for pkg in pkgs {
        let is_installed = package_is_installed(&pkg);
        if !is_installed || !should_track_package(&pkg) {
            continue;
        }

        let (record, notify) = check_single_package(&client, &base_url, &pkg).await;
        if notify {
            let label = if pkg.label.trim().is_empty() {
                &pkg.name
            } else {
                &pkg.label
            };
            insert_user_notification(
                1,
                "info",
                &format!("{} update available", label),
                &format!(
                    "Installed {}, latest {}.",
                    record.installed_version, record.latest_version
                ),
            );
        }
        records.push(record);
    }

    Ok(records)
}

/// Spawns the background App Update Watcher task, running an initial check after a
/// 45-second delay and repeating every 6 hours (or `AETHERFLOW_UPDATE_WATCH_INTERVAL`).
pub fn start_app_update_watcher() {
    if APP_UPDATE_WATCHER_ACTIVE.swap(true, Ordering::SeqCst) {
        return;
    }

    let interval = resolve_update_watch_interval();

    tokio::spawn(async move {
        tracing::info!(
            initial_delay_secs = 45,
            interval_secs = interval.as_secs(),
            "app update watcher initialized"
        );

        tokio::time::sleep(Duration::from_secs(45)).await;
        if let Err(error) = refresh_all_package_updates().await {
            tracing::warn!(error = %error, "application update watcher could not confirm inventory");
        }

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume immediate first tick
        ticker.tick().await;

        loop {
            ticker.tick().await;
            if let Err(error) = refresh_all_package_updates().await {
                tracing::warn!(error = %error, "application update watcher could not confirm inventory");
            }
        }
    });
}

pub(in crate::workers) fn resolve_update_watch_interval() -> Duration {
    if let Ok(raw) = env::var("AETHERFLOW_UPDATE_WATCH_INTERVAL") {
        let trimmed = raw.trim();
        if let Some(secs_str) = trimmed.strip_suffix('s') {
            if let Ok(s) = secs_str.parse::<u64>() {
                if s > 0 {
                    return Duration::from_secs(s);
                }
            }
        } else if let Some(mins_str) = trimmed.strip_suffix('m') {
            if let Ok(m) = mins_str.parse::<u64>() {
                if m > 0 {
                    return Duration::from_secs(m * 60);
                }
            }
        } else if let Some(hrs_str) = trimmed.strip_suffix('h') {
            if let Ok(h) = hrs_str.parse::<u64>() {
                if h > 0 {
                    return Duration::from_secs(h * 3600);
                }
            }
        } else if let Ok(s) = trimmed.parse::<u64>() {
            if s > 0 {
                return Duration::from_secs(s);
            }
        }
    }
    Duration::from_secs(6 * 3600)
}

pub(in crate::workers) fn resolve_github_api_base_url() -> String {
    if let Ok(raw) = env::var("AETHERFLOW_GITHUB_API_BASE_URL") {
        let trimmed = raw.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "https://api.github.com".to_string()
}

pub fn build_update_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("AetherFlow-Updater")
        .build()
        .unwrap_or_default()
}

pub(in crate::workers) fn parse_effective_origin(url: &reqwest::Url) -> Option<(String, String, u16)> {
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url.host_str()?.to_ascii_lowercase();
    let effective_port = url.port().unwrap_or(match scheme.as_str() {
        "https" => 443,
        "http" => 80,
        _ => return None,
    });
    Some((scheme, host, effective_port))
}

pub(in crate::workers) fn parse_effective_origin_str(raw: &str) -> Option<(String, String, u16)> {
    let parsed = if raw.starts_with("https://") || raw.starts_with("http://") {
        reqwest::Url::parse(raw).ok()?
    } else {
        reqwest::Url::parse(&format!("https://{}", raw)).ok()?
    };
    parse_effective_origin(&parsed)
}

pub fn should_attach_github_token(request_url: &str, configured_api_base: &str) -> bool {
    let Ok(req_url) = reqwest::Url::parse(request_url) else {
        return false;
    };
    let Some((req_scheme, req_host, req_port)) = parse_effective_origin(&req_url) else {
        return false;
    };

    let is_loopback = {
        let h = req_host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']');
        h == "127.0.0.1" || h == "localhost" || h == "::1"
    };

    // Reject plain http:// on non-loopback hosts
    if req_scheme != "https" && !is_loopback {
        return false;
    }

    // Reject untrusted third-party package registry hosts
    if req_host == "pypi.org"
        || req_host.ends_with(".pypi.org")
        || req_host == "files.pythonhosted.org"
        || req_host.ends_with(".pythonhosted.org")
        || req_host == "crates.io"
        || req_host.ends_with(".crates.io")
        || req_host == "registry.npmjs.org"
        || req_host.ends_with(".npmjs.org")
        || req_host == "gitlab.com"
        || req_host.ends_with(".gitlab.com")
        || req_host == "bitbucket.org"
        || req_host.ends_with(".bitbucket.org")
    {
        return false;
    }

    // 1. Built-in GitHub hosts: ONLY trust when scheme == "https" AND effective_port == 443!
    if req_scheme == "https"
        && req_port == 443
        && matches!(req_host.as_str(), "api.github.com" | "github.com")
    {
        return true;
    }

    // 2. Exact origin match with configured_api_base AND (https OR loopback)
    if let Some((base_scheme, base_host, base_port)) =
        parse_effective_origin_str(configured_api_base)
    {
        if req_scheme == base_scheme
            && req_host == base_host
            && req_port == base_port
            && (req_scheme == "https" || is_loopback)
        {
            return true;
        }
    }

    // 3. AF_TRUSTED_GITHUB_ORIGINS environment variable
    if req_scheme == "https" {
        if let Ok(trusted) = env::var("AF_TRUSTED_GITHUB_ORIGINS") {
            for entry in trusted.split(',') {
                let entry_trimmed = entry.trim();
                if entry_trimmed.is_empty() {
                    continue;
                }
                if let Some((e_scheme, e_host, e_port)) = parse_effective_origin_str(entry_trimmed)
                {
                    if req_scheme == e_scheme && req_host == e_host && req_port == e_port {
                        return true;
                    }
                }
            }
        }
    }

    false
}

pub fn is_trusted_github_api_url(url: &str, github_api_base: &str) -> bool {
    should_attach_github_token(url, github_api_base)
}

pub(in crate::workers) fn build_github_http_client() -> reqwest::Client {
    build_update_http_client()
}

#[cfg(test)]
#[tokio::test]
pub(in crate::workers) async fn github_release_observation_follows_canonical_repository_redirect() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for redirect in [true, false] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let length = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            let repository = if redirect {
                "davidnewhall/unpackerr"
            } else {
                "Unpackerr/unpackerr"
            };
            let (target_path, is_matched) = if request
                .starts_with(&format!("GET /repos/{repository}/releases?per_page=100 "))
            {
                ("releases?per_page=100", true)
            } else if request.starts_with(&format!("GET /repos/{repository}/releases/latest ")) {
                ("releases/latest", true)
            } else {
                ("", false)
            };
            assert!(is_matched, "unexpected request: {request}");
            let response = if redirect {
                format!("HTTP/1.1 301 Moved Permanently\r\nLocation: http://{address}/repos/Unpackerr/unpackerr/{target_path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            } else {
                let body = r#"[{"tag_name":"v0.14.2","html_url":"https://github.com/Unpackerr/unpackerr/releases/tag/v0.14.2"}]"#;
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
            };
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let observed = detect_latest_github_release(
        &build_github_http_client(),
        &format!("http://{address}"),
        "davidnewhall/unpackerr",
    )
    .await
    .unwrap();
    server.await.unwrap();
    assert_eq!(observed.0, "0.14.2");
    assert!(observed.1.contains("Unpackerr/unpackerr"));
}

pub fn persist_package_update_record(record: &PackageUpdateRecord) {
    ensure_app_updates_columns();
    let mut safe_record = record.clone();
    safe_record.release_url = af_release::lifecycle::sanitize_persisted_lifecycle_text(
        &sanitize_git_remote_url_for_display(&safe_record.release_url),
    );
    safe_record.error = af_release::lifecycle::sanitize_persisted_lifecycle_text(
        &public_update_error(&safe_record.error),
    );
    safe_record.source_key = sanitize_source_key_for_persistence(&safe_record.source_key);
    safe_record.latest_version =
        af_release::lifecycle::sanitize_persisted_lifecycle_text(&safe_record.latest_version);
    safe_record.installed_version =
        af_release::lifecycle::sanitize_persisted_lifecycle_text(&safe_record.installed_version);
    let record = &safe_record;

    if let Ok(conn) = af_db::get_conn() {
        let _ = conn.execute(
            "INSERT INTO app_updates (package_name, installed_version, latest_version, update_available, update_url, checked_at, last_error, source_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(package_name) DO UPDATE SET
               installed_version = excluded.installed_version,
               latest_version = excluded.latest_version,
               update_available = excluded.update_available,
               update_url = excluded.update_url,
               checked_at = excluded.checked_at,
               last_error = excluded.last_error,
               source_key = excluded.source_key",
            params![
                record.package_id,
                record.installed_version,
                record.latest_version,
                record.update_available,
                record.release_url,
                record.checked_at,
                record.error,
                record.source_key,
            ],
        );
    }
}

pub(in crate::workers) fn persist_and_cache_package_update(record: &PackageUpdateRecord) -> bool {
    let mut prev_update_available = false;
    let mut had_existing = false;

    if let Ok(mut cache) = PACKAGE_UPDATE_CACHE.lock() {
        if let Some(prev) = cache.get(&record.package_id) {
            had_existing = true;
            prev_update_available = prev.update_available;
        }
        cache.insert(record.package_id.clone(), record.clone());
    }

    if !had_existing {
        if let Ok(conn) = af_db::get_conn() {
            if let Ok(existing_avail) = conn.query_row(
                "SELECT COALESCE(update_available, 0) FROM app_updates WHERE package_name = ?1",
                params![record.package_id],
                |r| r.get::<_, bool>(0),
            ) {
                prev_update_available = existing_avail;
            }
        }
    }

    persist_package_update_record(record);

    !prev_update_available && record.update_available
}
