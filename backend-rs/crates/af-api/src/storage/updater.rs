use crate::auth::{api_error, AuthUser};
use crate::ws::extract_client_ip;
use axum::extract::{Query, Request};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Duration, Utc};
use once_cell::sync::Lazy;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::Mutex;

const GITHUB_REPO: &str = "McEveritts/AetherFlow";
const UPDATE_CHANNEL_STABLE: &str = "stable";
const UPDATE_CHANNEL_NIGHTLY: &str = "nightly";
const UPDATE_CHANNEL_EXPERIMENTAL: &str = "experimental";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubUpdateError {
    pub status: u16,
    pub retry_at: Option<DateTime<Utc>>,
    pub custom_message: Option<String>,
}

impl GitHubUpdateError {
    pub fn is_rate_limited(&self) -> bool {
        self.retry_at.is_some()
    }
}

impl std::fmt::Display for GitHubUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(retry_at) = self.retry_at {
            write!(
                f,
                "GitHub API rate limit reached; retry after {}",
                retry_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            )
        } else if let Some(ref msg) = self.custom_message {
            write!(f, "{}", msg)
        } else {
            write!(f, "GitHub update API returned HTTP {}", self.status)
        }
    }
}

impl std::error::Error for GitHubUpdateError {}

#[derive(Debug, Clone)]
struct GitHubUpdateCacheEntry {
    body: Option<Vec<u8>>,
    err: Option<GitHubUpdateError>,
    expires: DateTime<Utc>,
}

#[derive(Debug, Default)]
pub struct GitHubUpdateCache {
    entries: HashMap<String, GitHubUpdateCacheEntry>,
    token: String,
    limited: Option<GitHubUpdateError>,
}

static UPDATE_GITHUB_CACHE: Lazy<Mutex<GitHubUpdateCache>> =
    Lazy::new(|| Mutex::new(GitHubUpdateCache::default()));

static UPDATE_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("AetherFlow-Updater/4.0")
        .build()
        .unwrap_or_default()
});

pub fn github_update_token() -> String {
    for key in ["AF_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(val) = env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

pub fn compute_rate_limit_retry_at(
    status: u16,
    headers: &HeaderMap,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let remaining = headers
        .get("X-RateLimit-Remaining")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let retry_after_raw = headers
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();

    let is_limited =
        status == 429 || (status == 403 && (remaining == "0" || !retry_after_raw.is_empty()));
    if !is_limited {
        return None;
    }

    let mut retry_at = now + Duration::minutes(1);

    if let Some(reset_str) = headers
        .get("X-RateLimit-Reset")
        .and_then(|v| v.to_str().ok())
    {
        if let Ok(reset_epoch) = reset_str.trim().parse::<i64>() {
            if let Some(reset_dt) = DateTime::<Utc>::from_timestamp(reset_epoch, 0) {
                if reset_dt > retry_at {
                    retry_at = reset_dt;
                }
            }
        }
    }

    if !retry_after_raw.is_empty() {
        if let Ok(seconds) = retry_after_raw.parse::<i64>() {
            if seconds > 0 {
                let candidate = now + Duration::seconds(seconds);
                if candidate > retry_at {
                    retry_at = candidate;
                }
            }
        } else if let Ok(parsed_dt) = DateTime::parse_from_rfc2822(retry_after_raw)
            .or_else(|_| DateTime::parse_from_rfc3339(retry_after_raw))
        {
            let candidate = parsed_dt.with_timezone(&Utc);
            if candidate > retry_at {
                retry_at = candidate;
            }
        }
    }

    Some(retry_at)
}

impl GitHubUpdateCache {
    pub fn reset_if_token_changed(&mut self, token: &str) {
        if self.token != token {
            self.entries.clear();
            self.token = token.to_string();
            self.limited = None;
        }
    }

    pub fn get_cached(
        &self,
        url: &str,
        now: DateTime<Utc>,
    ) -> Option<Result<Vec<u8>, GitHubUpdateError>> {
        if let Some(entry) = self.entries.get(url) {
            if now < entry.expires {
                if let Some(ref err) = entry.err {
                    return Some(Err(err.clone()));
                }
                if let Some(ref body) = entry.body {
                    return Some(Ok(body.clone()));
                }
            }
        }
        if let Some(ref limited) = self.limited {
            if let Some(retry_at) = limited.retry_at {
                if now < retry_at {
                    return Some(Err(limited.clone()));
                }
            }
        }
        None
    }

    pub fn record_response(
        &mut self,
        url: &str,
        status: u16,
        headers: &HeaderMap,
        body_result: Result<Vec<u8>, String>,
        now: DateTime<Utc>,
    ) -> Result<Vec<u8>, GitHubUpdateError> {
        if status != 200 {
            let retry_at = compute_rate_limit_retry_at(status, headers, now);
            let failure = GitHubUpdateError {
                status,
                retry_at,
                custom_message: None,
            };
            let expires = retry_at.unwrap_or_else(|| now + Duration::minutes(1));
            if retry_at.is_some() {
                self.limited = Some(failure.clone());
            }
            self.entries.insert(
                url.to_string(),
                GitHubUpdateCacheEntry {
                    body: None,
                    err: Some(failure.clone()),
                    expires,
                },
            );
            return Err(failure);
        }

        match body_result {
            Ok(bytes) => {
                self.entries.insert(
                    url.to_string(),
                    GitHubUpdateCacheEntry {
                        body: Some(bytes.clone()),
                        err: None,
                        expires: now + Duration::minutes(5),
                    },
                );
                Ok(bytes)
            }
            Err(err_msg) => {
                let failure = GitHubUpdateError {
                    status: 0,
                    retry_at: None,
                    custom_message: Some(err_msg),
                };
                self.entries.insert(
                    url.to_string(),
                    GitHubUpdateCacheEntry {
                        body: None,
                        err: Some(failure.clone()),
                        expires: now + Duration::minutes(1),
                    },
                );
                Err(failure)
            }
        }
    }

    pub fn record_transport_error(
        &mut self,
        url: &str,
        message: String,
        now: DateTime<Utc>,
    ) -> GitHubUpdateError {
        let failure = GitHubUpdateError {
            status: 0,
            retry_at: None,
            custom_message: Some(message),
        };
        self.entries.insert(
            url.to_string(),
            GitHubUpdateCacheEntry {
                body: None,
                err: Some(failure.clone()),
                expires: now + Duration::minutes(1),
            },
        );
        failure
    }
}

async fn fetch_github_update_url(
    cache_mutex: &Mutex<GitHubUpdateCache>,
    client: &reqwest::Client,
    url: &str,
    token: &str,
    now: DateTime<Utc>,
) -> Result<Vec<u8>, GitHubUpdateError> {
    {
        let mut cache = cache_mutex
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.reset_if_token_changed(token);
        if let Some(cached) = cache.get_cached(url, now) {
            return cached;
        }
    }

    let mut req_builder = client
        .get(url)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header(header::USER_AGENT, "AetherFlow-Updater/4.0");
    if !token.is_empty() {
        req_builder = req_builder.header(header::AUTHORIZATION, format!("Bearer {}", token));
    }

    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            let body_result = if status == 200 {
                match resp.bytes().await {
                    Ok(b) => {
                        let max_len = 4 * 1024 * 1024;
                        if b.len() > max_len {
                            Ok(b[..max_len].to_vec())
                        } else {
                            Ok(b.to_vec())
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            } else {
                Ok(Vec::new())
            };
            let completed_at = Utc::now();
            let mut cache = cache_mutex
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.record_response(url, status, &headers, body_result, completed_at)
        }
        Err(e) => {
            let completed_at = Utc::now();
            let mut cache = cache_mutex
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Err(cache.record_transport_error(url, e.to_string(), completed_at))
        }
    }
}

async fn fetch_github_update(path: &str) -> Result<Vec<u8>, GitHubUpdateError> {
    let base = env::var("AF_GITHUB_API_BASE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://api.github.com".to_string());
    let url = format!(
        "{}/repos/{}{}",
        base.trim_end_matches('/'),
        GITHUB_REPO,
        path
    );
    let token = github_update_token();
    fetch_github_update_url(
        &UPDATE_GITHUB_CACHE,
        &UPDATE_HTTP_CLIENT,
        &url,
        &token,
        Utc::now(),
    )
    .await
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitHubReleaseAuthor {
    #[serde(default)]
    pub login: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitHubReleasePayload {
    #[serde(default)]
    pub tag_name: String,
    #[serde(default)]
    pub target_commitish: String,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub author: GitHubReleaseAuthor,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GitHubCommitDetail {
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GitHubCommitPayload {
    #[serde(default)]
    pub sha: String,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub commit: GitHubCommitDetail,
}

pub fn sanitize_release_body(body: &str) -> String {
    let without_bom = body.strip_prefix('\u{FEFF}').unwrap_or(body);
    let normalized_crlf = without_bom.replace("\r\n", "\n");
    normalized_crlf.replace("Release Notes ? ", "Release Notes — ")
}

pub fn normalize_update_channel(channel: &str) -> &'static str {
    match channel.trim().to_ascii_lowercase().as_str() {
        UPDATE_CHANNEL_NIGHTLY => UPDATE_CHANNEL_NIGHTLY,
        UPDATE_CHANNEL_EXPERIMENTAL => UPDATE_CHANNEL_NIGHTLY,
        _ => UPDATE_CHANNEL_STABLE,
    }
}

pub(super) fn read_update_channel_from_conn(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<&'static str> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT COALESCE(update_channel, 'stable') FROM settings WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(normalize_update_channel(
        raw.as_deref().unwrap_or(UPDATE_CHANNEL_STABLE),
    ))
}

fn read_update_channel_result() -> anyhow::Result<&'static str> {
    let conn = af_db::get_read_conn()?;
    Ok(read_update_channel_from_conn(&conn)?)
}

pub(super) fn get_local_version() -> String {
    af_runner::af_release::runtime::runtime_identity()
        .version
        .clone()
}

pub fn is_newer_version(local: &str, remote: &str) -> bool {
    let parse_ver = |v: &str| -> (i32, i32, i32, i32) {
        let clean = v
            .trim()
            .trim_start_matches('v')
            .split('-')
            .next()
            .unwrap_or("");
        let parts: Vec<&str> = clean.split('.').collect();
        let major = parts
            .first()
            .and_then(|p| p.parse::<i32>().ok())
            .unwrap_or(0);
        let minor = parts
            .get(1)
            .and_then(|p| p.parse::<i32>().ok())
            .unwrap_or(0);
        let (patch, subpatch) = if let Some(p2) = parts.get(2) {
            if p2.len() > 1 && p2.starts_with('0') {
                (0, p2.parse::<i32>().unwrap_or(0))
            } else {
                (p2.parse::<i32>().unwrap_or(0), 0)
            }
        } else {
            (0, 0)
        };
        (major, minor, patch, subpatch)
    };
    parse_ver(remote) > parse_ver(local)
}

pub fn nightly_update_available(current_version: &str, latest_version: &str) -> bool {
    if latest_version.trim().is_empty()
        || current_version
            .trim()
            .eq_ignore_ascii_case(latest_version.trim())
    {
        return false;
    }
    if current_version
        .trim()
        .to_ascii_lowercase()
        .starts_with("nightly-")
    {
        return true;
    }
    !is_newer_version(latest_version, current_version)
}

pub fn select_release_for_channel(
    releases: &[GitHubReleasePayload],
    channel: &str,
) -> Option<(String, String, String)> {
    let norm_channel = normalize_update_channel(channel);
    for rel in releases {
        let tag = rel.tag_name.trim();
        let author = rel.author.login.trim();
        if rel.draft
            || tag.is_empty()
            || (!author.is_empty()
                && !author.eq_ignore_ascii_case("McEveritts")
                && !author.eq_ignore_ascii_case("github-actions[bot]"))
        {
            continue;
        }
        let target = rel.target_commitish.trim();
        let tag_lower = tag.to_ascii_lowercase();
        let is_experimental = tag.eq_ignore_ascii_case("experimental")
            || target.eq_ignore_ascii_case("experimental")
            || tag_lower.contains("experimental");
        let is_nightly_target = target.eq_ignore_ascii_case("nightly")
            || rel.prerelease
            || tag_lower.contains("nightly");

        match norm_channel {
            UPDATE_CHANNEL_NIGHTLY => {
                if is_nightly_target && !is_experimental {
                    return Some((
                        tag.to_string(),
                        sanitize_release_body(&rel.body),
                        rel.html_url.clone(),
                    ));
                }
            }
            _ => {
                if !is_nightly_target && !is_experimental && !tag.contains('-') {
                    return Some((
                        tag.to_string(),
                        sanitize_release_body(&rel.body),
                        rel.html_url.clone(),
                    ));
                }
            }
        }
    }
    None
}

async fn fetch_releases_from_github() -> Result<Vec<GitHubReleasePayload>, GitHubUpdateError> {
    let body_bytes = fetch_github_update("/releases").await?;
    serde_json::from_slice::<Vec<GitHubReleasePayload>>(&body_bytes).map_err(|e| {
        GitHubUpdateError {
            status: 0,
            retry_at: None,
            custom_message: Some(e.to_string()),
        }
    })
}

async fn fetch_branch_head(
    prefix: &str,
    branches: &[&str],
) -> Result<(String, String, String), Option<GitHubUpdateError>> {
    let mut last_err: Option<GitHubUpdateError> = None;
    for branch in branches {
        match fetch_github_update(&format!("/commits/{}", branch)).await {
            Ok(body_bytes) => match serde_json::from_slice::<GitHubCommitPayload>(&body_bytes) {
                Ok(commit) => {
                    let sha = commit.sha.trim();
                    if !sha.is_empty() {
                        let short_sha: String = sha.chars().take(7).collect();
                        return Ok((
                            format!("{}-{}", prefix, short_sha),
                            commit.commit.message,
                            commit.html_url,
                        ));
                    }
                    last_err = Some(GitHubUpdateError {
                        status: 0,
                        retry_at: None,
                        custom_message: Some(format!(
                            "GitHub commit payload for branch '{branch}' had an empty sha"
                        )),
                    });
                }
                Err(err) => {
                    last_err = Some(GitHubUpdateError {
                        status: 0,
                        retry_at: None,
                        custom_message: Some(err.to_string()),
                    });
                }
            },
            Err(req_err) => {
                let is_limited = req_err.is_rate_limited();
                last_err = Some(req_err);
                if is_limited {
                    break;
                }
            }
        }
    }
    Err(last_err)
}

async fn resolve_stable_release_via_redirect() -> Option<(String, String, String)> {
    let download_base = env::var("AF_GITHUB_DOWNLOAD_BASE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://github.com".to_string());
    let latest_url = format!(
        "{}/{}/releases/latest",
        download_base.trim_end_matches('/'),
        GITHUB_REPO
    );
    let resp = UPDATE_HTTP_CLIENT
        .get(&latest_url)
        .header(header::USER_AGENT, "AetherFlow-Updater/4.0")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let effective = resp.url().as_str().trim_end_matches('/').to_string();
    let expected_prefix = format!(
        "{}/{}/releases/tag/",
        download_base.trim_end_matches('/'),
        GITHUB_REPO
    );
    let tag = effective.strip_prefix(&expected_prefix)?;
    let is_valid_semver = tag.starts_with('v') && {
        let parts: Vec<&str> = tag[1..].split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    };
    if !is_valid_semver {
        return None;
    }
    Some((tag.to_string(), String::new(), effective))
}

pub async fn check_update() -> Response {
    let current_version = get_local_version();
    let channel = match tokio::task::spawn_blocking(read_update_channel_result).await {
        Ok(Ok(channel)) => channel,
        Ok(Err(error)) => {
            tracing::warn!(%error, "Failed to read update channel configuration");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to read update channel setting",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "Update channel lookup worker failed");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to read update channel setting",
            );
        }
    };

    let mut latest_version = String::new();
    let mut message = String::new();
    let mut html_url = String::new();
    let mut update_available = false;
    let mut resolution_err: Option<GitHubUpdateError> = None;

    match channel {
        UPDATE_CHANNEL_NIGHTLY => {
            match fetch_releases_from_github().await {
                Ok(releases) => {
                    if let Some((tag, body, url)) =
                        select_release_for_channel(&releases, UPDATE_CHANNEL_NIGHTLY)
                    {
                        latest_version = tag;
                        message = body;
                        html_url = url;
                        update_available =
                            nightly_update_available(&current_version, &latest_version);
                    }
                }
                Err(err) => {
                    resolution_err = Some(err);
                }
            }

            if latest_version.is_empty()
                && !resolution_err
                    .as_ref()
                    .map(|e| e.is_rate_limited())
                    .unwrap_or(false)
            {
                match fetch_branch_head(UPDATE_CHANNEL_NIGHTLY, &["nightly", "Nightly"]).await {
                    Ok((ver, msg, url)) => {
                        latest_version = ver;
                        message = msg;
                        html_url = url;
                        update_available = current_version != latest_version;
                        resolution_err = None;
                    }
                    Err(Some(err)) => {
                        resolution_err = Some(err);
                    }
                    Err(None) => {}
                }
            }
        }

        _ => {
            match fetch_releases_from_github().await {
                Ok(releases) => {
                    if let Some((tag, body, url)) =
                        select_release_for_channel(&releases, UPDATE_CHANNEL_STABLE)
                    {
                        latest_version = tag;
                        message = body;
                        html_url = url;
                        update_available = is_newer_version(&current_version, &latest_version);
                    }
                }
                Err(err) => {
                    resolution_err = Some(err);
                }
            }

            if latest_version.is_empty()
                && !resolution_err
                    .as_ref()
                    .map(|e| e.is_rate_limited())
                    .unwrap_or(false)
            {
                if let Some((tag, body, url)) = resolve_stable_release_via_redirect().await {
                    latest_version = tag;
                    message = body;
                    html_url = url;
                    update_available = is_newer_version(&current_version, &latest_version);
                    resolution_err = None;
                }
            }
        }
    }

    if latest_version.is_empty() {
        let mut resp_obj = serde_json::json!({
            "updateAvailable": false,
            "currentVersion": current_version,
            "latestVersion": "Unknown (API Error or Rate Limited)",
            "message": "Could not fetch latest updates.",
        });
        if let Some(err) = resolution_err {
            resp_obj["message"] = serde_json::Value::String(err.to_string());
            if let Some(retry_at) = err.retry_at {
                resp_obj["error"] = serde_json::Value::String("github_rate_limited".to_string());
                resp_obj["retryAt"] = serde_json::Value::String(
                    retry_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                );
            } else {
                resp_obj["error"] = serde_json::Value::String("update_check_failed".to_string());
            }
        }
        return Json(resp_obj).into_response();
    }

    Json(serde_json::json!({
        "updateAvailable": update_available,
        "currentVersion": current_version,
        "latestVersion": latest_version,
        "message": message,
        "url": html_url,
    }))
    .into_response()
}

pub(crate) fn validate_runner_self_update_initiation_payload(
    output: &str,
) -> Result<(String, String), String> {
    let parsed_job: serde_json::Value = serde_json::from_str(output)
        .map_err(|err| format!("runner returned invalid self-update JSON payload: {}", err))?;
    let status = parsed_job
        .get("status")
        .and_then(|val| val.as_str())
        .unwrap_or("");
    if matches!(status, "succeeded" | "failed") {
        let receipt: af_models::SelfUpdateJobStatus = serde_json::from_value(parsed_job.clone())
            .map_err(|error| format!("runner returned invalid terminal receipt: {error}"))?;
        receipt.validate_invariants(None)?;
    } else if status != "initiated"
        || parsed_job
            .get("completed")
            .and_then(|value| value.as_bool())
            != Some(false)
    {
        return Err("runner returned neither a valid initiation nor a terminal receipt".into());
    }
    let job_unit = parsed_job
        .get("job_unit")
        .and_then(|val| val.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if !af_models::is_valid_self_update_job_unit_name(&job_unit) {
        return Err(format!(
            "runner self-update payload returned invalid or empty job_unit {:?}",
            job_unit
        ));
    }
    let engine_name = parsed_job
        .get("engine")
        .and_then(|val| val.as_str())
        .map(str::trim)
        .filter(|val| !val.is_empty())
        .unwrap_or("legacy_bash_release")
        .to_string();
    Ok((job_unit, engine_name))
}

pub async fn run_update(req: Request) -> Response {
    let actor = req.extensions().get::<AuthUser>().cloned();
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let channel = match tokio::task::spawn_blocking(read_update_channel_result).await {
        Ok(Ok(channel)) => channel.to_string(),
        Ok(Err(error)) => {
            tracing::warn!(%error, "Failed to read update channel before launching self-update");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to read update channel setting",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "Update channel lookup worker failed");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to read update channel setting",
            );
        }
    };

    // Serialize with Marketplace lifecycle jobs. The updater restarts the API
    // and runner; a running package job would lose its runner stream and the
    // package script would be killed mid-flight. Holding the lifecycle mutex
    // across the launch also guarantees a queued job re-checks after the
    // updater is registered (see dispatch_package_lifecycle).
    // A short wait tolerates a brief af-heal restart holding the mutex.
    let lifecycle_guard = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        af_services::PACKAGE_LIFECYCLE_MUTEX.lock(),
    )
    .await;
    let _lifecycle_guard = match lifecycle_guard {
        Ok(guard) if !af_services::has_active_package_jobs() => guard,
        _ => {
            return api_error(
                StatusCode::CONFLICT,
                "PACKAGE_LIFECYCLE_IN_PROGRESS",
                "An application install, update, or removal is in progress; retry the system update after it finishes",
            );
        }
    };

    let update_req = af_models::SelfUpdateRequest {
        command: "deploy".to_string(),
        channel: channel.clone(),
    };
    let runner_resp = match af_runner::dispatch_self_update_request(&update_req).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::error!(error = %err, "Failed to initiate self-update via runner");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "SERVICE_UNAVAILABLE",
                format!("Failed to initiate self-update: {}", err),
            );
        }
    };

    let (job_unit, engine_name) = match validate_runner_self_update_initiation_payload(
        &runner_resp.output,
    ) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::error!(error = %err, "Runner returned invalid self-update initiation payload");
            return api_error(StatusCode::BAD_GATEWAY, "BAD_GATEWAY", err);
        }
    };

    if let Some(actor_ctx) = actor {
        af_db::record_audit(
            actor_ctx.user_id,
            &actor_ctx.username,
            "system_deployment",
            "engine",
            "blue_green",
            &format!("Channel: {} (unit: {})", channel, job_unit),
            &ip,
            &ua,
        );
    }

    // A fast worker can finish before systemd-run returns. Preserve its exact
    // terminal receipt instead of manufacturing a fresh pending operation.
    if let Ok(receipt) = serde_json::from_str::<af_models::SelfUpdateJobStatus>(&runner_resp.output)
    {
        if receipt.completed {
            return Json(serde_json::json!({
                "message": if receipt.success { "System deployment completed successfully." } else { "System deployment failed; inspect its receipt and authenticated logs." },
                "status": receipt.status,
                "completed": receipt.completed,
                "success": receipt.success,
                "error": receipt.error,
                "exit_code": receipt.exit_code,
                "channel": channel,
                "engine": engine_name,
                "job_unit": job_unit,
            })).into_response();
        }
    }

    Json(serde_json::json!({
        "message": "Atomic deployment initiated. The system will cleanly transition once builds are complete.",
        "status": "initiated",
        "completed": false,
        "channel": channel,
        "engine": engine_name,
        "job_unit": job_unit
    }))
    .into_response()
}

fn self_update_action_from_unit(unit: &str) -> Option<String> {
    unit.strip_prefix("aetherflow-self-update-")
        .and_then(|suffix| suffix.split('-').next())
        .filter(|command| matches!(*command, "deploy" | "rollback" | "restart"))
        .map(str::to_owned)
}

pub(crate) fn render_self_update_status_response(
    job_unit: &str,
    result: anyhow::Result<af_models::SelfUpdateJobStatus>,
) -> Response {
    match result {
        Ok(status) => {
            let idle = job_unit.is_empty()
                && status.job_unit.is_empty()
                && status.status == "succeeded"
                && status.completed
                && status.success
                && status.exit_code == Some(0)
                && status.error.is_empty();
            let recovery = job_unit.is_empty()
                && status.job_unit.is_empty()
                && status.status == "recovery_required"
                && !status.completed
                && !status.success
                && status.exit_code.is_none();
            if !idle
                && !recovery
                && (status.job_unit != status.job_unit.trim()
                    || status
                        .validate_invariants((!job_unit.is_empty()).then_some(job_unit))
                        .is_err())
            {
                return api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "UPDATE_STATUS_ERROR",
                    "Update status identity or state could not be verified",
                );
            }
            let state = if idle {
                "idle"
            } else if recovery {
                "interrupted"
            } else {
                match status.status.as_str() {
                    "succeeded" => "complete",
                    "failed" => "failed",
                    _ => "running",
                }
            };
            let error = if recovery {
                "System update recovery is required before another update can start"
            } else if !status.error.is_empty() {
                "System update failed; inspect authenticated updater diagnostics"
            } else {
                ""
            };
            Json(serde_json::json!({
                "state": state,
                "action": self_update_action_from_unit(&status.job_unit),
                "operationId": if status.job_unit.is_empty() { None } else { Some(&status.job_unit) },
                "job_unit": status.job_unit,
                "active_job_unit": if !status.completed { &status.job_unit } else { "" },
                "status": if idle { "idle" } else { &status.status },
                "completed": status.completed,
                "success": !idle && status.success,
                "error": error,
                "exit_code": if idle { None } else { status.exit_code },
            })).into_response()
        }
        Err(err) => {
            let msg = err.to_string();
            let code = if !job_unit.is_empty()
                && (msg.contains("not found") || msg.contains("Not found"))
            {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            tracing::warn!(error = %err, "System update status observation failed");
            api_error(
                code,
                "UPDATE_STATUS_ERROR",
                if code == StatusCode::NOT_FOUND {
                    "Tracked update receipt was not found; its outcome is unverified"
                } else {
                    "System update status is unavailable; no idle or completed state is confirmed"
                },
            )
        }
    }
}

pub async fn get_system_update_status(Query(q): Query<HashMap<String, String>>) -> Response {
    let job_unit = q
        .get("job_unit")
        .or_else(|| q.get("unit"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if !job_unit.is_empty() && !af_models::is_valid_self_update_job_unit_name(&job_unit) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "A valid self-update job_unit is required",
        );
    }
    if q.get("action")
        .is_some_and(|expected| self_update_action_from_unit(&job_unit).as_ref() != Some(expected))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Update action does not match job identity",
        );
    }

    let status_req = af_models::SelfUpdateStatusRequest {
        job_unit: job_unit.clone(),
    };
    let result = af_runner::dispatch_self_update_status_request(&status_req).await;
    render_self_update_status_response(&job_unit, result)
}
