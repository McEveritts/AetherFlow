use crate::cli::{resolve_package_lock_name, GlobalOptions};
use crate::error::{CliError, CliResult};
use af_runner::get_runner_package_definition_in_root;
use std::path::{Path, PathBuf};

pub(crate) fn resolve_cli_package_definition(
    global: &GlobalOptions,
    pkg_id: &str,
) -> Option<af_models::Package> {
    let lock_name = resolve_package_lock_name(pkg_id);
    get_runner_package_definition_in_root(lock_name, global.root.as_deref())
        .or_else(|| get_runner_package_definition_in_root(pkg_id.trim(), global.root.as_deref()))
}

pub(crate) fn resolve_install_lock_dir(global: &GlobalOptions) -> PathBuf {
    let fs_root = af_models::resolve_package_fs_root(global.root.as_deref());
    af_models::resolve_path_for_fs_root("/install", fs_root.as_deref())
}

pub(crate) fn resolve_swizzin_lock_dir(global: &GlobalOptions) -> PathBuf {
    let fs_root = af_models::resolve_package_fs_root(global.root.as_deref());
    af_models::resolve_path_for_fs_root("/etc/Swizzin", fs_root.as_deref())
}

pub(crate) fn inspect_cli_package_receipts_for_def(
    global: &GlobalOptions,
    pkg_id: &str,
    def: Option<&af_models::Package>,
) -> CliResult<af_models::PackageReceiptStatus> {
    let explicit_lock = def
        .map(|d| d.lock_file.as_str())
        .filter(|s| !s.trim().is_empty());
    af_models::inspect_package_receipts(pkg_id, explicit_lock, global.root.as_deref())
        .map_err(CliError::PreflightOrIntegrity)
}

pub(crate) fn inspect_cli_package_receipts(
    global: &GlobalOptions,
    pkg_id: &str,
) -> CliResult<af_models::PackageReceiptStatus> {
    let def = resolve_cli_package_definition(global, pkg_id);
    inspect_cli_package_receipts_for_def(global, pkg_id, def.as_ref())
}

pub(crate) fn query_persisted_ingress_port_from_sqlite(
    db_path: &Path,
    app_name: &str,
) -> Option<i32> {
    if !db_path.is_file() {
        return None;
    }
    let conn =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    if let Ok(port) = conn.query_row(
        "SELECT listen_port FROM app_ingress_configs WHERE LOWER(app_name) = LOWER(?1) LIMIT 1",
        [app_name],
        |r| r.get::<_, i32>(0),
    ) {
        if (1024..=65535).contains(&port) {
            return Some(port);
        }
    }
    if let Ok(json_raw) = conn.query_row(
        "SELECT config_json FROM retained_app_ingress_configs WHERE LOWER(app_name) = LOWER(?1) LIMIT 1",
        [app_name],
        |r| r.get::<_, String>(0),
    ) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_raw) {
            if let Some(port) = val
                .get("listen_port")
                .or_else(|| val.get("listenPort"))
                .and_then(|v| v.as_i64())
                .and_then(|p| i32::try_from(p).ok())
            {
                if (1..=65535).contains(&port) {
                    return Some(port);
                }
            }
        }
    }
    None
}

pub(crate) fn candidate_cli_sqlite_dbs(global: &GlobalOptions) -> Vec<PathBuf> {
    af_runner::candidate_package_sqlite_dbs(global.root.as_deref())
}

fn query_app_update_target_version_from_sqlite(db_path: &Path, pkg_id: &str) -> Option<String> {
    if !db_path.is_file() {
        return None;
    }
    let conn =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    let with_err_sql = "SELECT COALESCE(latest_version, ''), COALESCE(last_error, '') FROM app_updates WHERE LOWER(package_name) = LOWER(?1) LIMIT 1";
    let fallback_sql = "SELECT COALESCE(latest_version, ''), '' FROM app_updates WHERE LOWER(package_name) = LOWER(?1) LIMIT 1";
    let (latest, last_error) = match conn.query_row(with_err_sql, [pkg_id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    }) {
        Ok(pair) => pair,
        Err(err) if err.to_string().contains("no such column") => conn
            .query_row(fallback_sql, [pkg_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .ok()?,
        Err(_) => return None,
    };
    if !last_error.trim().is_empty() {
        return None;
    }
    normalize_discovered_target_version(&latest)
}

fn normalize_discovered_target_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let stripped = if (trimmed.starts_with('v') || trimmed.starts_with('V'))
        && trimmed[1..].starts_with(|c: char| c.is_ascii_digit())
    {
        &trimmed[1..]
    } else {
        trimmed
    };
    if af_release::lifecycle::validate_target_version(stripped) {
        Some(stripped.to_string())
    } else if af_release::lifecycle::validate_target_version(trimmed) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn decode_chunked_http_body(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < raw.len() {
        let Some(rel_end) = raw[idx..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let line = String::from_utf8_lossy(&raw[idx..idx + rel_end]);
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(size_hex, 16) else {
            break;
        };
        idx += rel_end + 2;
        if chunk_len == 0 || idx + chunk_len > raw.len() {
            break;
        }
        out.extend_from_slice(&raw[idx..idx + chunk_len]);
        idx += chunk_len;
        if raw[idx..].starts_with(b"\r\n") {
            idx += 2;
        }
    }
    out
}

fn http_get_text(url: &str) -> Result<String, String> {
    if let Some(rest) = url.strip_prefix("http://") {
        use std::io::{Read, Write};
        use std::net::{TcpStream, ToSocketAddrs};
        use std::time::Duration;

        let (authority, path_part) = match rest.find('/') {
            Some(pos) => (&rest[..pos], &rest[pos..]),
            None => (rest, "/"),
        };
        let host_port = if authority.contains(':') {
            authority.to_string()
        } else {
            format!("{authority}:80")
        };
        let addr = host_port
            .to_socket_addrs()
            .map_err(|e| format!("failed to resolve {host_port}: {e}"))?
            .next()
            .ok_or_else(|| format!("no socket address resolved for {host_port}"))?;
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| format!("failed to connect to {host_port}: {e}"))?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let req = format!(
            "GET {path_part} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: AetherFlow-CLI\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("failed writing HTTP request to {host_port}: {e}"))?;
        let mut buf = Vec::new();
        stream
            .take(2 * 1024 * 1024)
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed reading HTTP response from {host_port}: {e}"))?;
        let Some(hdr_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            return Err(format!("malformed HTTP response from {host_port}"));
        };
        let headers = String::from_utf8_lossy(&buf[..hdr_end]);
        let status_line = headers.lines().next().unwrap_or("");
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status_code) {
            return Err(format!("upstream HTTP {status_code} from {url}"));
        }
        let body_bytes = &buf[hdr_end + 4..];
        let decoded = if headers.lines().any(|l| {
            l.to_ascii_lowercase()
                .contains("transfer-encoding: chunked")
        }) {
            decode_chunked_http_body(body_bytes)
        } else {
            body_bytes.to_vec()
        };
        return String::from_utf8(decoded)
            .map_err(|e| format!("non-UTF8 upstream response from {url}: {e}"));
    }

    let mut cmd = std::process::Command::new("curl");
    cmd.args([
        "-fsSL",
        "--max-time",
        "8",
        "-H",
        "Accept: application/json",
        "-A",
        "AetherFlow-CLI",
    ]);
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() && url.contains("github.com") {
            cmd.arg("-H")
                .arg(format!("Authorization: Bearer {trimmed}"));
        }
    }
    let output = cmd
        .arg(url)
        .output()
        .map_err(|e| format!("failed to execute curl for upstream discovery: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "upstream request to {url} failed ({})",
            stderr.trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("invalid UTF-8 from upstream {url}: {e}"))
}

fn load_package_automation_spec(
    global: &GlobalOptions,
    pkg_id: &str,
) -> Result<serde_json::Value, String> {
    let mut candidate_paths = Vec::new();
    if let Some(ref root) = global.root {
        candidate_paths.push(root.join("opt/AetherFlow/config/package_automation.json"));
        candidate_paths.push(root.join("etc/aetherflow/package_automation.json"));
        candidate_paths.push(root.join("config/package_automation.json"));
    } else {
        if let Ok(custom) = std::env::var("AETHERFLOW_PACKAGE_AUTOMATION_PATH") {
            let trimmed = custom.trim();
            if !trimmed.is_empty() {
                candidate_paths.push(PathBuf::from(trimmed));
            }
        }
        candidate_paths.push(PathBuf::from(
            "/opt/AetherFlow/config/package_automation.json",
        ));
        candidate_paths.push(PathBuf::from("/etc/aetherflow/package_automation.json"));
        candidate_paths.push(PathBuf::from("config/package_automation.json"));
    }

    let raw_catalog = candidate_paths
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .or_else(|| {
            if global.root.is_none() {
                Some(crate::EMBEDDED_PACKAGE_AUTOMATION_JSON.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| "no package_automation.json catalog available".to_string())?;

    let parsed: serde_json::Value = serde_json::from_str(&raw_catalog)
        .map_err(|e| format!("invalid package_automation.json: {e}"))?;
    let obj = parsed
        .as_object()
        .ok_or_else(|| "package_automation.json root must be an object".to_string())?;

    let lock_name = resolve_package_lock_name(pkg_id);
    for candidate_key in [pkg_id, lock_name] {
        if let Some((_, v)) = obj
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(candidate_key))
        {
            return Ok(v.clone());
        }
    }
    Err(format!(
        "package '{}' has no upstream automation entry",
        pkg_id
    ))
}

fn spec_non_empty_str<'a>(spec: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    spec.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn resolve_cli_upstream_api_base(spec: &serde_json::Value, env_var: &str, default: &str) -> String {
    spec_non_empty_str(spec, "api_base_url")
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var(env_var)
                .ok()
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| default.to_string())
}

fn discover_latest_github_tag(
    api_base: &str,
    repo: &str,
    missing_label: &str,
    invalid_label: &str,
) -> Result<String, String> {
    let tags_url = format!("{api_base}/repos/{repo}/tags?per_page=1");
    let body = http_get_text(&tags_url)?;
    let val: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("invalid JSON from {tags_url}: {e}"))?;
    let tag = val
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|item| item.get("name"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("no {missing_label} found for {repo}"))?;
    normalize_discovered_target_version(tag)
        .ok_or_else(|| format!("invalid {invalid_label} {:?} for {repo}", tag))
}

pub(crate) fn discover_listenarr_github_target_for_arch(
    api_base: &str,
    repo: &str,
    channel: &str,
    host_arch: &str,
) -> Result<String, String> {
    let asset_suffix = af_runner::listenarr_release_asset_suffix_for_arch(host_arch)?;
    let effective_channel = if channel.trim().eq_ignore_ascii_case("prerelease") {
        "prerelease"
    } else {
        "stable"
    };
    let is_stable = effective_channel == "stable";

    const PAGE_SIZE: usize = 100;
    const MAX_PAGES: usize = 10;
    let mut all_releases: Vec<serde_json::Value> = Vec::new();
    for page in 1..=MAX_PAGES {
        let releases_url =
            format!("{api_base}/repos/{repo}/releases?per_page={PAGE_SIZE}&page={page}");
        let body = http_get_text(&releases_url)?;
        let val: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| format!("invalid JSON from {releases_url}: {e}"))?;
        let page_items: Vec<serde_json::Value> = match val {
            serde_json::Value::Array(arr) => arr,
            obj @ serde_json::Value::Object(_) => vec![obj],
            _ => {
                return Err(format!(
                    "unexpected GitHub releases JSON shape from {releases_url}"
                ));
            }
        };
        let page_len = page_items.len();
        all_releases.extend(page_items);
        if page == MAX_PAGES && page_len >= PAGE_SIZE {
            return Err(format!(
                "GitHub release pagination exceeded maximum page limit ({MAX_PAGES}) for '{repo}'"
            ));
        }
        if page_len < PAGE_SIZE {
            break;
        }
    }

    let mut best_candidate: Option<(String, bool)> = None;
    for rel in &all_releases {
        if rel.get("draft").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }
        let rel_prerelease = rel
            .get("prerelease")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if is_stable && rel_prerelease {
            continue;
        }
        let Some(tag_name) = rel
            .get("tag_name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let Some(version) = normalize_discovered_target_version(tag_name) else {
            continue;
        };
        let is_pre = rel_prerelease || version.contains('-');
        if is_stable && is_pre {
            continue;
        }

        let Some(assets) = rel.get("assets").and_then(|v| v.as_array()) else {
            continue;
        };
        let has_checksum_companion = assets.iter().any(|asset| {
            let name = asset.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let url = asset
                .get("browser_download_url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            af_runner::listenarr_is_official_checksum_companion(tag_name, name, url)
        });
        let matching_assets: Vec<&serde_json::Value> = assets
            .iter()
            .filter(|asset| {
                asset
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .is_some_and(|name| name.ends_with(asset_suffix))
            })
            .collect();
        if matching_assets.len() != 1 {
            continue;
        }
        let asset = matching_assets[0];
        let asset_name = asset.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let asset_url = asset
            .get("browser_download_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let asset_digest = asset.get("digest").and_then(|v| v.as_str());
        if !af_runner::listenarr_release_asset_is_eligible(
            tag_name,
            asset_name,
            asset_url,
            asset_digest,
            has_checksum_companion,
            asset_suffix,
        ) {
            continue;
        }

        match &best_candidate {
            None => {
                best_candidate = Some((version, is_pre));
            }
            Some((current_ver, current_is_pre)) => {
                let ord = af_release::lifecycle::compare_versions(&version, current_ver);
                let should_replace = match ord {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Equal => !is_pre && *current_is_pre,
                    std::cmp::Ordering::Less => false,
                };
                if should_replace {
                    best_candidate = Some((version, is_pre));
                }
            }
        }
    }

    best_candidate.map(|(ver, _)| ver).ok_or_else(|| {
        format!(
            "no eligible official Listenarr release found in '{}' on channel '{}' with a verified {} asset for host architecture '{}'",
            repo,
            effective_channel,
            asset_suffix,
            host_arch.trim()
        )
    })
}

fn discover_live_upstream_target_version(
    global: &GlobalOptions,
    pkg_id: &str,
) -> Result<String, String> {
    let spec = load_package_automation_spec(global, pkg_id)?;
    let source = spec_non_empty_str(&spec, "update_source").unwrap_or("");
    let api_base = resolve_cli_upstream_api_base(
        &spec,
        "AETHERFLOW_GITHUB_API_BASE",
        "https://api.github.com",
    );

    match source {
        "retired" => Err(format!(
            "package '{}' is retired upstream and has no active update feed",
            pkg_id
        )),
        "github" | "github_release" => {
            let repo = spec_non_empty_str(&spec, "update_repo")
                .ok_or_else(|| format!("missing update_repo for '{}'", pkg_id))?;
            if resolve_package_lock_name(pkg_id).eq_ignore_ascii_case("listenarr") {
                let channel = spec_non_empty_str(&spec, "update_channel").unwrap_or("prerelease");
                return discover_listenarr_github_target_for_arch(
                    &api_base,
                    repo,
                    channel,
                    std::env::consts::ARCH,
                );
            }
            let release_url = format!("{api_base}/repos/{repo}/releases/latest");
            if let Ok(body) = http_get_text(&release_url) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(tag) = val.get("tag_name").and_then(|v| v.as_str()) {
                        if let Some(ver) = normalize_discovered_target_version(tag) {
                            return Ok(ver);
                        }
                    }
                }
            }
            discover_latest_github_tag(
                &api_base,
                repo,
                "upstream release or tag",
                "upstream tag",
            )
        }
        "git_tags" => {
            let repo = spec_non_empty_str(&spec, "update_repo")
                .ok_or_else(|| format!("missing update_repo for '{}'", pkg_id))?;
            discover_latest_github_tag(&api_base, repo, "upstream git tags", "upstream git tag")
        }
        "pypi" => {
            let pypi_pkg = spec_non_empty_str(&spec, "update_package").unwrap_or(pkg_id);
            let pypi_base =
                resolve_cli_upstream_api_base(&spec, "AETHERFLOW_PYPI_API_BASE", "https://pypi.org");
            let url = format!("{pypi_base}/pypi/{pypi_pkg}/json");
            let body = http_get_text(&url)?;
            let val: serde_json::Value =
                serde_json::from_str(&body).map_err(|e| format!("invalid PyPI JSON: {e}"))?;
            let ver = val
                .get("info")
                .and_then(|i| i.get("version"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("missing info.version from PyPI for {pypi_pkg}"))?;
            normalize_discovered_target_version(ver)
                .ok_or_else(|| format!("invalid PyPI version {:?} for {pypi_pkg}", ver))
        }
        "git" => {
            let normalize_short_sha =
                |sha: &str| normalize_discovered_target_version(sha.get(..12).unwrap_or(sha));
            if let Some(repo) = spec_non_empty_str(&spec, "update_repo") {
                let url = format!("{api_base}/repos/{repo}/commits/HEAD");
                if let Ok(body) = http_get_text(&url) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(ver) = val
                            .get("sha")
                            .and_then(|v| v.as_str())
                            .and_then(normalize_short_sha)
                        {
                            return Ok(ver);
                        }
                    }
                }
            }
            let repo_url = spec_non_empty_str(&spec, "update_repo_url")
                .ok_or_else(|| format!("missing update_repo_url for '{}'", pkg_id))?;
            let out = std::process::Command::new("git")
                .args(["ls-remote", repo_url, "HEAD"])
                .env("GIT_TERMINAL_PROMPT", "0")
                .output()
                .map_err(|e| format!("git ls-remote failed for {repo_url}: {e}"))?;
            if !out.status.success() {
                return Err(format!("git ls-remote returned error for {repo_url}"));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            let sha = stdout
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("empty git ls-remote output for {repo_url}"))?;
            normalize_short_sha(sha)
                .ok_or_else(|| format!("invalid git commit SHA {:?} for {repo_url}", sha))
        }
        "apt" => {
            if global.root.is_some() {
                return Err(format!(
                    "live apt candidate discovery is disabled under isolated --root for '{}'",
                    pkg_id
                ));
            }
            let apt_pkg = spec_non_empty_str(&spec, "update_package").unwrap_or(pkg_id);
            let out = std::process::Command::new("apt-cache")
                .args(["policy", apt_pkg])
                .output()
                .map_err(|e| format!("apt-cache policy failed for {apt_pkg}: {e}"))?;
            if !out.status.success() {
                return Err(format!("apt-cache policy returned non-zero for {apt_pkg}"));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            match af_release::lifecycle::parse_apt_policy_candidate(&stdout) {
                Some(candidate)
                    if af_release::lifecycle::validate_exact_apt_version(candidate.trim()) =>
                {
                    Ok(candidate.trim().to_string())
                }
                Some(candidate) => Err(format!(
                    "invalid apt candidate version {:?} for {apt_pkg}",
                    candidate.trim()
                )),
                None => Err(format!("no apt candidate version available for {apt_pkg}")),
            }
        }
        "vendor" => Err(format!(
            "package '{}' uses a multi-component vendor installer and does not support exact-version updates; use reinstall or the vendor updater instead",
            pkg_id
        )),
        "pinned" => spec_non_empty_str(&spec, "update_package")
            .and_then(normalize_discovered_target_version)
            .ok_or_else(|| {
                format!(
                    "package '{}' uses a pinned upstream source with no dynamic target version",
                    pkg_id
                )
            }),
        other => Err(format!(
            "unsupported upstream update_source {:?} for '{}'",
            other, pkg_id
        )),
    }
}

pub(crate) fn validate_cli_package_target_policy(
    global: &GlobalOptions,
    pkg_id: &str,
    action: &str,
    target_version: Option<&str>,
) -> CliResult<()> {
    let lock_name = resolve_package_lock_name(pkg_id);
    let (source, update_package) = match load_package_automation_spec(global, pkg_id) {
        Ok(spec) => (
            spec_non_empty_str(&spec, "update_source")
                .unwrap_or("")
                .to_string(),
            spec_non_empty_str(&spec, "update_package")
                .unwrap_or("")
                .to_string(),
        ),
        Err(_) => resolve_cli_package_definition(global, pkg_id)
            .map(|package| (package.update_source, package.update_package))
            .unwrap_or_default(),
    };
    af_runner::validate_package_target_policy(
        lock_name,
        &source,
        &update_package,
        action,
        target_version,
    )
    .map_err(CliError::Validation)
}

pub(crate) fn resolve_cli_package_target_version(
    global: &GlobalOptions,
    pkg_id: &str,
    explicit_target: Option<&str>,
) -> CliResult<String> {
    let validate_explicit = |raw: &str, label: &str| -> CliResult<String> {
        let trimmed = raw.trim();
        if !af_release::lifecycle::validate_target_version(trimmed) {
            return Err(CliError::Validation(format!(
                "invalid {label} {:?} (must be a concrete version, commit SHA, or component manifest)",
                raw
            )));
        }
        validate_cli_package_target_policy(global, pkg_id, "update", Some(trimmed))?;
        Ok(trimmed.to_string())
    };

    if let Some(explicit) = explicit_target {
        return validate_explicit(explicit, "--target-version");
    }

    if let Ok(env_target) = std::env::var("AF_TARGET_VERSION") {
        if !env_target.trim().is_empty() {
            return validate_explicit(&env_target, "AF_TARGET_VERSION");
        }
    }

    let lock_name = resolve_package_lock_name(pkg_id);
    if lock_name == "threadfin" {
        return af_runner::validate_threadfin_target_policy(None)
            .map(|(version, _)| version)
            .map_err(|error| CliError::Validation(error.to_string()));
    }
    validate_cli_package_target_policy(global, pkg_id, "update", None)?;

    for db_path in candidate_cli_sqlite_dbs(global) {
        if let Some(ver) = query_app_update_target_version_from_sqlite(&db_path, lock_name)
            .or_else(|| query_app_update_target_version_from_sqlite(&db_path, pkg_id))
        {
            validate_cli_package_target_policy(global, pkg_id, "update", Some(&ver))?;
            return Ok(ver);
        }
    }

    let discovered = discover_live_upstream_target_version(global, pkg_id).map_err(|reason| {
        CliError::PreflightOrIntegrity(format!(
            "unable to resolve upstream target version for package '{}' ({}); run an update check first to populate app_updates.latest_version or pass '--target-version <version>' explicitly when offline",
            pkg_id, reason
        ))
    })?;
    validate_cli_package_target_policy(global, pkg_id, "update", Some(&discovered))?;
    Ok(discovered)
}

pub(crate) fn resolve_cli_package_port(
    global: &GlobalOptions,
    pkg_id: &str,
    explicit_port: Option<i32>,
) -> Option<i32> {
    if let Some(p) = explicit_port {
        if (1024..=65535).contains(&p) {
            return Some(p);
        }
    }

    let lock_name = resolve_package_lock_name(pkg_id);
    let candidate_dbs = candidate_cli_sqlite_dbs(global);

    for db_path in &candidate_dbs {
        if let Some(p) = query_persisted_ingress_port_from_sqlite(db_path, lock_name)
            .or_else(|| query_persisted_ingress_port_from_sqlite(db_path, pkg_id))
        {
            return Some(p);
        }
    }

    if af_models::resolve_package_fs_root(global.root.as_deref()).is_none() {
        let runtime_meta = af_runner::extract_app_runtime_meta_local(lock_name);
        if (1024..=65535).contains(&runtime_meta.configured_port) {
            return Some(runtime_meta.configured_port);
        }
    }

    let def = resolve_cli_package_definition(global, pkg_id);
    if let Ok(Some(p)) = af_models::read_package_receipt_port(
        pkg_id,
        def.as_ref()
            .map(|d| d.lock_file.as_str())
            .filter(|s| !s.trim().is_empty()),
        global.root.as_deref(),
    ) {
        return Some(p);
    }

    def.map(|def| def.default_port)
        .filter(|p| (1024..=65535).contains(p))
}
