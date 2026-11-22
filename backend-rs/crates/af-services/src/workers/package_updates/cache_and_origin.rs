use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// 4. Package Update Watcher & On-Demand Checkers
// ─────────────────────────────────────────────────────────────────────────────

/// Represents the cached update status for an individual marketplace package,
/// supporting both Rust field names and Go wire aliases (`package_name`, `update_url`, `last_error`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageUpdateRecord {
    #[serde(alias = "package_name")]
    pub package_id: String,
    pub installed: bool,
    pub installed_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub checked_at: String,
    #[serde(alias = "update_url")]
    pub release_url: String,
    #[serde(
        alias = "last_error",
        default,
        serialize_with = "serialize_update_error"
    )]
    pub error: String,
    #[serde(default)]
    pub source_key: String,
}

/// Thread-safe in-memory cache of package update records keyed by `package_id`.
pub static PACKAGE_UPDATE_CACHE: Lazy<Mutex<HashMap<String, PackageUpdateRecord>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(in crate::workers) static APP_UPDATE_WATCHER_ACTIVE: AtomicBool = AtomicBool::new(false);

#[allow(clippy::type_complexity)]
pub(in crate::workers) static GITHUB_RELEASE_CACHE: Lazy<
    Mutex<HashMap<String, (String, String, Instant, String)>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));
#[allow(clippy::type_complexity)]
pub(in crate::workers) static GIT_REMOTE_HEAD_CACHE: Lazy<
    Mutex<HashMap<String, (String, String, Instant, String)>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));
pub(in crate::workers) static GITHUB_RATE_LIMIT_UNTIL: Lazy<Mutex<HashMap<String, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn normalize_api_origin(url_or_base: &str) -> String {
    let trimmed = url_or_base.trim();
    if let Ok(parsed) = reqwest::Url::parse(trimmed) {
        let scheme = parsed.scheme();
        let host = parsed.host_str().unwrap_or("");
        let port_part = match parsed.port() {
            Some(p) => format!(":{}", p),
            None => String::new(),
        };
        format!("{}://{}{}", scheme, host, port_part).to_ascii_lowercase()
    } else {
        trimmed.trim_end_matches('/').to_ascii_lowercase()
    }
}

pub fn sha256_hex_12(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    hex::encode(&result[..6])
}

pub fn sanitize_git_remote_url_for_display(raw_url: &str) -> String {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(parsed) = reqwest::Url::parse(trimmed) {
        let scheme = parsed.scheme().to_ascii_lowercase();
        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
        let port_part = match parsed.port() {
            Some(443) if scheme == "https" => String::new(),
            Some(80) if scheme == "http" => String::new(),
            Some(22) if scheme == "ssh" => String::new(),
            Some(p) => format!(":{}", p),
            None => String::new(),
        };
        let user_part = if scheme == "ssh" {
            let uname = parsed.username();
            if !uname.is_empty() {
                format!("{}@", uname)
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        let path = parsed.path();
        format!("{}://{}{}{}{}", scheme, user_part, host, port_part, path)
    } else if let Some((user_host, path)) = trimmed.split_once(':') {
        let without_frag = path.split('#').next().unwrap_or(path);
        let without_query = without_frag.split('?').next().unwrap_or(without_frag);
        let clean_path = without_query.trim_start_matches('/');
        if let Some((user, host)) = user_host.split_once('@') {
            let clean_user = if let Some((u, _)) = user.split_once(':') {
                u
            } else {
                user
            };
            format!(
                "ssh://{}@{}/{}",
                clean_user,
                host.to_ascii_lowercase(),
                clean_path
            )
        } else {
            format!("ssh://{}/{}", user_host.to_ascii_lowercase(), clean_path)
        }
    } else {
        let without_frag = trimmed.split('#').next().unwrap_or(trimmed);
        let without_query = without_frag.split('?').next().unwrap_or(without_frag);
        without_query.to_string()
    }
}

pub fn validate_release_url_origin(url: &str, expected_api_base: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    let Ok(expected) = reqwest::Url::parse(expected_api_base) else {
        return false;
    };
    parsed.scheme() == expected.scheme()
        && parsed
            .host_str()
            .unwrap_or("")
            .eq_ignore_ascii_case(expected.host_str().unwrap_or(""))
        && parsed.port_or_known_default() == expected.port_or_known_default()
}

pub fn validate_github_releases_next_url(
    next_url: &str,
    github_api_base: &str,
    clean_repo: &str,
) -> bool {
    if !validate_release_url_origin(next_url, github_api_base) {
        return false;
    }
    let Ok(parsed) = reqwest::Url::parse(next_url) else {
        return false;
    };
    let Ok(expected) = reqwest::Url::parse(github_api_base) else {
        return false;
    };
    let base_path = expected.path().trim_end_matches('/');
    let next_path = parsed.path().trim_end_matches('/');
    let Some(repo_suffix) = next_path.strip_prefix(base_path) else {
        return false;
    };
    let expected_repo_suffix = format!("/repos/{}/releases", clean_repo.trim_matches('/'));
    repo_suffix.eq_ignore_ascii_case(&expected_repo_suffix)
}

pub(in crate::workers) const GITHUB_RELEASE_PAGE_SIZE: usize = 100;

/// GitHub uses `/repositories/<id>/releases` in Link headers even when the
/// request used `/repos/<owner>/<repo>/releases`. Only take pagination parameters
/// from that alias: construct the next request against our configured repo,
/// so an unverified numeric repository ID cannot change the release source.
pub(in crate::workers) fn github_releases_next_request_url(
    next_url: &str,
    github_api_base: &str,
    clean_repo: &str,
) -> Option<String> {
    if !validate_release_url_origin(next_url, github_api_base) {
        return None;
    }
    let parsed = reqwest::Url::parse(next_url).ok()?;
    let base = reqwest::Url::parse(github_api_base).ok()?;
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return None;
    }
    let suffix = parsed
        .path()
        .strip_prefix(base.path().trim_end_matches('/'))?;
    let numeric_alias = suffix
        .strip_prefix("/repositories/")
        .and_then(|s| s.trim_end_matches('/').strip_suffix("/releases"))
        .map(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false);
    if !numeric_alias && !validate_github_releases_next_url(next_url, github_api_base, clean_repo) {
        return None;
    }
    let pages: Vec<_> = parsed
        .query_pairs()
        .filter(|(key, _)| key == "page")
        .collect();
    if pages.len() != 1 {
        return None;
    }
    let page = pages[0].1.parse::<u32>().ok().filter(|page| *page > 0)?;
    let sizes: Vec<_> = parsed
        .query_pairs()
        .filter(|(key, _)| key == "per_page")
        .collect();
    let size = match sizes.as_slice() {
        [] => GITHUB_RELEASE_PAGE_SIZE,
        [(_, value)] => value
            .parse::<usize>()
            .ok()
            .filter(|size| (1..=100).contains(size))?,
        _ => return None,
    };
    let mut request = reqwest::Url::parse(&format!(
        "{}/repos/{}/releases",
        github_api_base.trim_end_matches('/'),
        clean_repo.trim_matches('/'),
    ))
    .ok()?;
    request
        .query_pairs_mut()
        .append_pair("per_page", &size.to_string())
        .append_pair("page", &page.to_string());
    Some(request.to_string())
}

pub(in crate::workers) fn extract_canonical_query_hash_suffix(raw: &str) -> (&str, Option<String>) {
    if let Some(idx) = raw.find("?q#") {
        if raw.len() >= idx + 15 {
            let hex = &raw[idx + 3..idx + 15];
            let after_ok = raw.len() == idx + 15 || raw.as_bytes()[idx + 15] == b'#';
            if hex.bytes().all(|b| b.is_ascii_hexdigit()) && after_ok {
                return (
                    &raw[..idx],
                    Some(format!("?q#{}", hex.to_ascii_lowercase())),
                );
            }
        }
    }
    (raw, None)
}

pub(in crate::workers) fn split_git_repo_remote_and_branch(rest: &str) -> (&str, Option<&str>) {
    if let Some((left, right)) = rest.rsplit_once('#') {
        if left.ends_with("?q") && right.len() == 12 && right.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return (rest, None);
        }
        return (left, Some(right));
    }
    (rest, None)
}

pub fn normalize_git_remote_url_preserve_path_case(raw_url: &str) -> String {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let (trimmed_base, existing_q_hash) = extract_canonical_query_hash_suffix(trimmed);
    if let Some(q_hash) = existing_q_hash {
        let base = normalize_git_remote_url_preserve_path_case(trimmed_base);
        return format!("{}{}", base, q_hash);
    }
    if let Some((prefix, after_scheme)) = trimmed.split_once("://") {
        if let Some((userinfo, rest)) = after_scheme.split_once('@') {
            if let Some(hex) = userinfo.strip_prefix("cred#") {
                if hex.len() == 12 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    let temp_url = format!("{}://cred@{}", prefix, rest);
                    if let Ok(parsed) = reqwest::Url::parse(&temp_url) {
                        let scheme = parsed.scheme().to_ascii_lowercase();
                        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
                        let port_part = match parsed.port() {
                            Some(443) if scheme == "https" => String::new(),
                            Some(80) if scheme == "http" => String::new(),
                            Some(22) if scheme == "ssh" => String::new(),
                            Some(p) => format!(":{}", p),
                            None => String::new(),
                        };
                        let path = parsed.path();
                        let query_part = match parsed.query() {
                            Some(q) if !q.is_empty() => {
                                format!("?q#{}", sha256_hex_12(q.as_bytes()))
                            }
                            _ => String::new(),
                        };
                        return format!(
                            "{}://cred#{}@{}{}{}{}",
                            scheme, hex, host, port_part, path, query_part
                        );
                    }
                }
            }
        }
    }
    if let Ok(parsed) = reqwest::Url::parse(trimmed) {
        let scheme = parsed.scheme().to_ascii_lowercase();
        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
        let port_part = match parsed.port() {
            Some(443) if scheme == "https" => String::new(),
            Some(80) if scheme == "http" => String::new(),
            Some(22) if scheme == "ssh" => String::new(),
            Some(p) => format!(":{}", p),
            None => String::new(),
        };
        let user_part = if parsed.password().is_some() {
            let userinfo = format!("{}:{}", parsed.username(), parsed.password().unwrap());
            format!("cred#{}@", sha256_hex_12(userinfo.as_bytes()))
        } else if !parsed.username().is_empty() {
            if scheme == "http" || scheme == "https" {
                format!("cred#{}@", sha256_hex_12(parsed.username().as_bytes()))
            } else {
                format!("{}@", parsed.username())
            }
        } else {
            String::new()
        };
        let path = parsed.path();
        let query_part = match parsed.query() {
            Some(q) if !q.is_empty() => format!("?q#{}", sha256_hex_12(q.as_bytes())),
            _ => String::new(),
        };
        format!(
            "{}://{}{}{}{}{}",
            scheme, user_part, host, port_part, path, query_part
        )
    } else if let Some((user_host, path)) = trimmed.split_once(':') {
        let without_frag = path.split('#').next().unwrap_or(path);
        let (clean_path_raw, query_opt) = match without_frag.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (without_frag, None),
        };
        let clean_path = clean_path_raw
            .trim_start_matches('/')
            .trim_end_matches('/')
            .trim_end_matches(".git");
        let query_part = match query_opt {
            Some(q) if !q.is_empty() => format!("?q#{}", sha256_hex_12(q.as_bytes())),
            _ => String::new(),
        };
        if let Some((user, host)) = user_host.split_once('@') {
            let user_part = if let Some((u, pass)) = user.split_once(':') {
                let userinfo = format!("{}:{}", u, pass);
                format!("cred#{}@", sha256_hex_12(userinfo.as_bytes()))
            } else {
                format!("{}@", user)
            };
            format!(
                "ssh://{}{}/{}{}",
                user_part,
                host.to_ascii_lowercase(),
                clean_path,
                query_part
            )
        } else {
            format!(
                "ssh://{}/{}{}",
                user_host.to_ascii_lowercase(),
                clean_path,
                query_part
            )
        }
    } else {
        let without_frag = trimmed.split('#').next().unwrap_or(trimmed);
        let (clean_raw, query_opt) = match without_frag.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (without_frag, None),
        };
        let query_part = match query_opt {
            Some(q) if !q.is_empty() => format!("?q#{}", sha256_hex_12(q.as_bytes())),
            _ => String::new(),
        };
        let clean_with_cred = if let Some((userinfo, rest)) = clean_raw.split_once('@') {
            if let Some((u, pass)) = userinfo.split_once(':') {
                let full_cred = format!("{}:{}", u, pass);
                format!("cred#{}@{}", sha256_hex_12(full_cred.as_bytes()), rest)
            } else {
                clean_raw.to_string()
            }
        } else {
            clean_raw.to_string()
        };
        let clean_path = clean_with_cred
            .trim_end_matches('/')
            .trim_end_matches(".git");
        format!("{}{}", clean_path, query_part)
    }
}

pub fn is_github_rate_limited_for_origin(github_api_base: &str, bucket: &str) -> bool {
    let origin = sanitize_api_base_for_source_key(github_api_base);
    let now = Instant::now();
    let Ok(guard) = GITHUB_RATE_LIMIT_UNTIL.lock() else {
        return false;
    };
    let req_bucket = bucket.trim().to_ascii_lowercase();
    let buckets = [req_bucket.as_str(), "core", "default"];
    for b in buckets {
        let key = format!("{}|{}", origin, b);
        if let Some(&until) = guard.get(&key) {
            if now < until {
                return true;
            }
        }
    }
    false
}

pub fn github_rate_limit_remaining_secs_for_origin(github_api_base: &str, bucket: &str) -> u64 {
    let origin = sanitize_api_base_for_source_key(github_api_base);
    let now = Instant::now();
    let Ok(guard) = GITHUB_RATE_LIMIT_UNTIL.lock() else {
        return 0;
    };
    let req_bucket = bucket.trim().to_ascii_lowercase();
    let buckets = [req_bucket.as_str(), "core", "default"];
    let mut max_remaining = 0u64;
    for b in buckets {
        let key = format!("{}|{}", origin, b);
        if let Some(&until) = guard.get(&key) {
            if until > now {
                let secs = (until - now).as_secs();
                max_remaining = max_remaining.max(secs);
            }
        }
    }
    max_remaining
}

pub fn is_github_api_rate_limited(github_api_base: &str, bucket: &str) -> bool {
    is_github_rate_limited_for_origin(github_api_base, bucket)
}

pub fn record_github_api_rate_limit(github_api_base: &str, bucket: &str, cooldown: Duration) {
    let origin = sanitize_api_base_for_source_key(github_api_base);
    let bucket_name = if bucket.trim().is_empty() {
        "default".to_string()
    } else {
        bucket.trim().to_ascii_lowercase()
    };
    let key = format!("{}|{}", origin, bucket_name);
    let until = Instant::now() + cooldown;
    if let Ok(mut guard) = GITHUB_RATE_LIMIT_UNTIL.lock() {
        guard.insert(key, until);
    }
}

pub fn clear_github_rate_limits() {
    if let Ok(mut guard) = GITHUB_RATE_LIMIT_UNTIL.lock() {
        guard.clear();
    }
}

pub fn sanitize_api_base_for_source_key(raw_base: &str) -> String {
    let trimmed = raw_base.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Ok(parsed) = reqwest::Url::parse(trimmed) {
        let scheme = parsed.scheme().to_ascii_lowercase();
        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
        let port_part = match parsed.port() {
            Some(443) if scheme == "https" => String::new(),
            Some(80) if scheme == "http" => String::new(),
            Some(22) if scheme == "ssh" => String::new(),
            Some(p) => format!(":{}", p),
            None => String::new(),
        };
        let path = parsed.path().trim_end_matches('/');
        format!("{}://{}{}{}", scheme, host, port_part, path)
    } else {
        let s = af_release::lifecycle::sanitize_persisted_lifecycle_text(trimmed);
        let without_frag = s.split('#').next().unwrap_or(&s);
        let (raw_base, query_opt) = match without_frag.split_once('?') {
            Some((b, q)) => (b, Some(q)),
            None => (without_frag, None),
        };
        let query_part = match query_opt {
            Some(q) if !q.is_empty() => format!("?q#{}", sha256_hex_12(q.as_bytes())),
            _ => String::new(),
        };
        let base_no_slash = raw_base.trim_end_matches('/');
        let normalized_base = if let Some((scheme, rest)) = base_no_slash.split_once("://") {
            let scheme_lower = scheme.to_ascii_lowercase();
            if let Some((host, path)) = rest.split_once('/') {
                format!("{}://{}/{}", scheme_lower, host.to_ascii_lowercase(), path)
            } else {
                format!("{}://{}", scheme_lower, rest.to_ascii_lowercase())
            }
        } else {
            base_no_slash.to_string()
        };
        format!("{}{}", normalized_base, query_part)
    }
}

pub fn sanitize_source_key_for_persistence(raw_key: &str) -> String {
    let trimmed = raw_key.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // 1. git-repo:<remote>#<branch>
    if let Some(rest) = trimmed.strip_prefix("git-repo:") {
        let (remote, branch_opt) = split_git_repo_remote_and_branch(rest);
        let norm_remote = normalize_git_remote_url_preserve_path_case(remote);
        let combined = match branch_opt {
            Some(b) => format!("git-repo:{}#{}", norm_remote, b),
            None => format!("git-repo:{}", norm_remote),
        };
        return af_release::lifecycle::sanitize_persisted_lifecycle_text(&combined);
    }

    // 2. Canonical src:api_base|remote|repo|channel or similar
    if let Some((src, rest)) = trimmed.split_once(':') {
        let src_lower = src.to_ascii_lowercase();
        let parts: Vec<&str> = rest.split('|').collect();
        match src_lower.as_str() {
            "github" | "github_release" | "github-release" | "github-tag" => {
                if parts.len() >= 2 {
                    let api_base = sanitize_api_base_for_source_key(parts[0]);
                    let repo = parts[1].trim().to_ascii_lowercase();
                    let channel_suffix = if parts.len() >= 3 {
                        format!("|{}", parts[2].trim().to_ascii_lowercase())
                    } else {
                        String::new()
                    };
                    let key = format!("{}:{}|{}{}", src, api_base, repo, channel_suffix);
                    return af_release::lifecycle::sanitize_persisted_lifecycle_text(&key);
                }
            }
            "git" | "git_tag" | "git_tags" | "git_commit" | "git_head" if parts.len() >= 3 => {
                let api_base = sanitize_api_base_for_source_key(parts[0]);
                let norm_remote = normalize_git_remote_url_preserve_path_case(parts[1]);
                let repo_slug = parts[2].trim();
                let channel_suffix = if parts.len() >= 4 {
                    format!("|{}", parts[3].trim().to_ascii_lowercase())
                } else {
                    String::new()
                };
                let key = format!(
                    "{}:{}|{}|{}{}",
                    src, api_base, norm_remote, repo_slug, channel_suffix
                );
                return af_release::lifecycle::sanitize_persisted_lifecycle_text(&key);
            }
            _ => {}
        }
    }

    af_release::lifecycle::sanitize_persisted_lifecycle_text(trimmed)
}

pub fn canonical_update_source_key(github_api_base: &str, pkg: &Package) -> String {
    let (effective_source, effective_apt_pkg) = effective_update_source_and_apt_package(pkg);
    let src = if effective_source.trim().is_empty() && pkg.name == "threadfin" {
        "pinned".to_string()
    } else {
        effective_source.trim().to_ascii_lowercase()
    };
    let api_base = sanitize_api_base_for_source_key(github_api_base);
    let base_key = match src.as_str() {
        "pinned" => {
            if pkg.name == "threadfin" {
                let target_ver = af_runner::resolve_threadfin_target_version();
                format!("pinned:{}", target_ver.to_ascii_lowercase())
            } else if !pkg.update_package.trim().is_empty() {
                format!("pinned:{}", pkg.update_package.trim().to_ascii_lowercase())
            } else {
                format!("pinned:{}", pkg.name.trim().to_ascii_lowercase())
            }
        }
        "vendor" => {
            format!("vendor:{}", pkg.name.trim().to_ascii_lowercase())
        }
        "github" | "github_release" => {
            let repo = if pkg.name == "threadfin" && pkg.update_repo.trim().is_empty() {
                "threadfin/threadfin"
            } else {
                pkg.update_repo.trim()
            };
            format!("github:{}|{}", api_base, repo.to_ascii_lowercase())
        }
        "git" | "git_tag" | "git_tags" | "git_commit" | "git_head" => {
            let effective_remote = resolve_git_remote_url(&pkg.update_repo_url, &pkg.update_repo)
                .map(|url| normalize_git_remote_url_preserve_path_case(&url))
                .unwrap_or_default();
            let repo_slug = pkg.update_repo.trim();
            format!("{}:{}|{}|{}", src, api_base, effective_remote, repo_slug)
        }
        "pypi" => {
            let pypi_pkg = if pkg.name == "pyload" && pkg.update_package.trim().is_empty() {
                "pyload-ng"
            } else if !pkg.update_package.trim().is_empty() {
                pkg.update_package.trim()
            } else {
                pkg.name.trim()
            };
            format!("pypi:{}", pypi_pkg.to_ascii_lowercase())
        }
        "apt" => {
            let apt_pkg = if !effective_apt_pkg.trim().is_empty() {
                effective_apt_pkg.trim()
            } else if !pkg.update_package.trim().is_empty() {
                pkg.update_package.trim()
            } else {
                pkg.name.trim()
            };
            format!("apt:{}", apt_pkg.to_ascii_lowercase())
        }
        _ => {
            if !pkg.update_package.trim().is_empty() {
                format!("{}:{}", src, pkg.update_package.trim().to_ascii_lowercase())
            } else if !pkg.update_repo.trim().is_empty() {
                format!(
                    "{}:{}|{}",
                    src,
                    api_base,
                    pkg.update_repo.trim().to_ascii_lowercase()
                )
            } else {
                format!("{}:{}", src, pkg.name.trim().to_ascii_lowercase())
            }
        }
    };
    let channel = normalize_update_channel(&pkg.update_channel);
    let full_key = format!("{}|{}", base_key, channel);
    af_release::lifecycle::sanitize_persisted_lifecycle_text(&full_key)
}

pub fn github_release_cache(
) -> std::sync::MutexGuard<'static, HashMap<String, (String, String, Instant, String)>> {
    GITHUB_RELEASE_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

pub fn git_remote_head_cache(
) -> std::sync::MutexGuard<'static, HashMap<String, (String, String, Instant, String)>> {
    GIT_REMOTE_HEAD_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

pub fn git_head_cache_key(repo_url: &str, repo: &str) -> String {
    let effective_remote_url = if !repo_url.trim().is_empty() {
        normalize_git_remote_url_preserve_path_case(repo_url.trim())
    } else if !repo.trim().is_empty() {
        normalize_git_remote_url_preserve_path_case(&format!(
            "https://github.com/{}.git",
            repo.trim()
        ))
    } else {
        String::new()
    };
    format!("{}|{}", effective_remote_url, repo.trim())
}

pub fn github_release_cache_key(github_api_base: &str, repo: &str) -> String {
    github_release_cache_key_for_channel(github_api_base, repo, "stable")
}

pub fn github_release_cache_key_for_channel(
    github_api_base: &str,
    repo: &str,
    channel: &str,
) -> String {
    let effective_channel_owned = {
        let t = channel.trim().to_ascii_lowercase();
        if t.is_empty() {
            "stable".to_string()
        } else {
            t
        }
    };
    let effective_channel = effective_channel_owned.as_str();
    format!(
        "{}|{}|{}",
        sanitize_api_base_for_source_key(github_api_base),
        repo.trim().to_ascii_lowercase(),
        effective_channel
    )
}

pub fn get_cached_github_release_stale(
    github_api_base: &str,
    repo: &str,
) -> Option<(String, String, String)> {
    get_cached_github_release_stale_for_channel(github_api_base, repo, "stable")
}

pub fn get_cached_github_release_stale_for_channel(
    github_api_base: &str,
    repo: &str,
    channel: &str,
) -> Option<(String, String, String)> {
    let clean_repo = repo.trim().to_ascii_lowercase();
    if clean_repo.is_empty() {
        return None;
    }
    let effective_channel_owned = normalize_update_channel(channel);
    let effective_channel = effective_channel_owned.as_str();
    let cache_key =
        github_release_cache_key_for_channel(github_api_base, &clean_repo, effective_channel);
    let cache = github_release_cache();
    if let Some((ver, url, _, obs)) = cache.get(&cache_key) {
        if tag_allowed_by_channel(ver, effective_channel) {
            return Some((ver.clone(), url.clone(), obs.clone()));
        }
    }
    None
}
