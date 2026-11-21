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

pub(super) static APP_UPDATE_WATCHER_ACTIVE: AtomicBool = AtomicBool::new(false);

#[allow(clippy::type_complexity)]
pub(super) static GITHUB_RELEASE_CACHE: Lazy<
    Mutex<HashMap<String, (String, String, Instant, String)>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));
#[allow(clippy::type_complexity)]
pub(super) static GIT_REMOTE_HEAD_CACHE: Lazy<
    Mutex<HashMap<String, (String, String, Instant, String)>>,
> = Lazy::new(|| Mutex::new(HashMap::new()));
pub(super) static GITHUB_RATE_LIMIT_UNTIL: Lazy<Mutex<HashMap<String, Instant>>> =
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

pub(super) const GITHUB_RELEASE_PAGE_SIZE: usize = 100;

/// GitHub uses `/repositories/<id>/releases` in Link headers even when the
/// request used `/repos/<owner>/<repo>/releases`. Only take pagination parameters
/// from that alias: construct the next request against our configured repo,
/// so an unverified numeric repository ID cannot change the release source.
pub(super) fn github_releases_next_request_url(
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

pub(super) fn extract_canonical_query_hash_suffix(raw: &str) -> (&str, Option<String>) {
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

pub(super) fn split_git_repo_remote_and_branch(rest: &str) -> (&str, Option<&str>) {
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
            let effective_remote = if !pkg.update_repo_url.trim().is_empty() {
                normalize_git_remote_url_preserve_path_case(pkg.update_repo_url.trim())
            } else if !pkg.update_repo.trim().is_empty() {
                normalize_git_remote_url_preserve_path_case(&format!(
                    "https://github.com/{}.git",
                    pkg.update_repo.trim()
                ))
            } else {
                String::new()
            };
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
    let channel = if pkg.update_channel.trim().is_empty() {
        "stable"
    } else {
        pkg.update_channel.trim()
    }
    .to_ascii_lowercase();
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
    let effective_channel_owned = {
        let t = channel.trim().to_ascii_lowercase();
        if t.is_empty() {
            "stable".to_string()
        } else {
            t
        }
    };
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

pub(super) static DOTTED_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?\d+\.\d+(?:\.\d+)*(?:~[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)")
        .unwrap()
});
pub(super) static DEFAULT_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:^|[\s(\[\x22'])(?:v)?((?:\d+:)?[0-9]+(?:\.[0-9]+)*(?:~[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)")
        .unwrap()
});
pub(super) static SYNTHETIC_COMMIT_VERSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)-([0-9a-fA-F]{7,40})$").unwrap());

#[derive(Debug, Deserialize)]
pub(super) struct GitHubReleaseResponse {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct PyPiInfo {
    #[serde(default)]
    version: String,
    #[serde(default)]
    project_urls: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct PyPiResponse {
    info: PyPiInfo,
}

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

pub(super) fn serialize_update_error<S: serde::Serializer>(
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

pub(super) static PACKAGE_UPDATE_CACHE_DB_PATH: Lazy<Mutex<String>> =
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

pub(super) fn resolve_update_watch_interval() -> Duration {
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

pub(super) fn resolve_github_api_base_url() -> String {
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

pub(super) fn parse_effective_origin(url: &reqwest::Url) -> Option<(String, String, u16)> {
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url.host_str()?.to_ascii_lowercase();
    let effective_port = url.port().unwrap_or(match scheme.as_str() {
        "https" => 443,
        "http" => 80,
        _ => return None,
    });
    Some((scheme, host, effective_port))
}

pub(super) fn parse_effective_origin_str(raw: &str) -> Option<(String, String, u16)> {
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

pub(super) fn build_github_http_client() -> reqwest::Client {
    build_update_http_client()
}

#[cfg(test)]
#[tokio::test]
pub(super) async fn github_release_observation_follows_canonical_repository_redirect() {
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

pub(super) fn should_track_package(pkg: &Package) -> bool {
    if pkg.name == "readarr" {
        return true;
    }
    if pkg.update_source.is_empty() {
        return false;
    }
    match pkg.update_source.as_str() {
        "apt" => !pkg.update_package.is_empty(),
        "github" | "github_release" | "git_tags" | "git" | "git_commit" | "git_head" => {
            !pkg.version_command.is_empty()
                && (!pkg.update_repo.is_empty() || !pkg.update_repo_url.is_empty())
        }
        "pypi" => !pkg.version_command.is_empty(),
        "retired" | "legacy" | "pinned" | "vendor" => true,
        _ => !pkg.version_command.is_empty(),
    }
}

pub(super) fn package_is_installed(pkg: &Package) -> bool {
    if pkg.lock_file.trim().is_empty() {
        return false;
    }
    let resolved = resolve_fs_path(&pkg.lock_file);
    let fs_root = af_models::resolve_package_fs_root(None);
    let bound_root = fs_root.as_deref().filter(|root| resolved.starts_with(root));
    af_models::inspect_receipt_file(&resolved, bound_root).unwrap_or(false)
}

pub fn is_package_installed(pkg: &Package) -> bool {
    package_is_installed(pkg) || crate::is_package_installed(&pkg.name)
}

pub async fn probe_package_update(
    client: &reqwest::Client,
    github_api_base: &str,
    pkg: &Package,
) -> (PackageUpdateRecord, bool) {
    let is_installed = package_is_installed(pkg);

    let installed_res = detect_installed_version(pkg).await;
    let installed_failed_early = installed_res.is_err()
        || installed_res
            .as_ref()
            .map(|v| v.trim().is_empty())
            .unwrap_or(false);
    let installed_err_msg = installed_res.as_ref().err().map(|e| e.to_string());

    let latest_res = detect_latest_version(client, github_api_base, pkg).await;

    let observed_at = match &latest_res {
        Ok((_, _, obs)) => obs.clone(),
        Err(_) => String::new(),
    };

    let expected_source_key = canonical_update_source_key(github_api_base, pkg);
    let prev_record = get_package_update_map().get(&pkg.name).cloned();
    let (update_source, _) = effective_update_source_and_apt_package(pkg);
    let mut record = build_package_update_record_for_source(
        github_api_base,
        update_source,
        &pkg.name,
        is_installed,
        installed_res,
        latest_res
            .as_ref()
            .map(|(v, u, _)| (v.clone(), u.clone()))
            .map_err(|e| anyhow::anyhow!("{}", e)),
        prev_record.as_ref(),
        observed_at,
        &expected_source_key,
    );

    let source_matched = prev_record
        .as_ref()
        .map(|r| {
            !r.source_key.trim().is_empty() && r.source_key.trim() == expected_source_key.trim()
        })
        .unwrap_or(false);

    if record.latest_version.is_empty()
        && latest_res.is_err()
        && (pkg.update_source == "github_release" || pkg.update_source == "github")
        && !pkg.update_repo.is_empty()
    {
        if let Some((cached_v, cached_u, cached_obs)) = get_cached_github_release_stale_for_channel(
            github_api_base,
            &pkg.update_repo,
            &pkg.update_channel,
        ) {
            if tag_allowed_by_channel_for_source(&cached_v, &pkg.update_channel, &pkg.update_source)
            {
                record.latest_version = cached_v;
                if record.release_url.is_empty() {
                    record.release_url = cached_u;
                }
                if prev_record.is_none() || !source_matched {
                    record.checked_at = cached_obs;
                }
            }
        }
    }

    let is_retired = matches!(pkg.update_source.as_str(), "retired" | "legacy" | "pinned")
        || pkg.name == "readarr";
    let is_readarr_404 = pkg.name == "readarr"
        && !record.installed_version.is_empty()
        && match &latest_res {
            Err(e) => {
                let msg = e.to_string();
                msg.contains("404") || msg.contains("not found")
            }
            _ => false,
        };

    let installed_failed = installed_failed_early
        || record
            .error
            .to_ascii_lowercase()
            .contains("installed version");

    if is_retired || is_readarr_404 {
        if record.latest_version.is_empty() {
            if pkg.name == "readarr" {
                record.latest_version = "0.4.18.2805".to_string();
            } else if !record.installed_version.is_empty() {
                record.latest_version = record.installed_version.clone();
            }
        }
        if installed_failed {
            if let Some(ref e) = installed_err_msg {
                record.error = format!("Installed version check failed: {e}");
            } else if record.error.is_empty() {
                record.error =
                    "Installed version check failed: probe returned no output".to_string();
            }
            record.update_available = false;
        } else {
            if !record.installed_version.is_empty() && !record.latest_version.is_empty() {
                record.update_available = record.installed
                    && is_remote_version_newer_for_source(
                        &record.installed_version,
                        &record.latest_version,
                        &pkg.update_source,
                    );
            } else {
                record.update_available = false;
            }
            record.error = String::new();
        }
    }

    let notify = persist_and_cache_package_update(&record);
    (record, notify)
}

pub fn resolve_installed_package_version(
    installed_opt: Option<&str>,
    prev_record: Option<&PackageUpdateRecord>,
) -> (String, bool) {
    if let Some(v) = installed_opt {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return (trimmed.to_string(), false);
        }
    }
    let fallback = prev_record
        .map(|r| r.installed_version.trim().to_string())
        .unwrap_or_default();
    let fell_back = !fallback.is_empty();
    (fallback, fell_back)
}

pub async fn detect_installed_package_version(pkg: &Package) -> anyhow::Result<String> {
    detect_installed_version(pkg).await
}

pub fn open_dir_nofollow_stepwise(dir_path: &Path) -> Result<std::os::fd::OwnedFd, String> {
    use std::os::fd::FromRawFd;
    if !dir_path.is_absolute() {
        return Err(format!("path {:?} is not absolute", dir_path));
    }
    let root_fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("failed to open root directory '/': {}", err));
    }
    let mut current_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(root_fd) };

    for comp in dir_path.components() {
        match comp {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::ParentDir => {
                return Err("parent directory traversal ('..') is not permitted".to_string());
            }
            std::path::Component::Normal(name) => {
                use std::os::fd::AsRawFd;
                use std::os::unix::ffi::OsStrExt;
                let c_name = std::ffi::CString::new(name.as_bytes())
                    .map_err(|e| format!("invalid component name {:?}: {}", name, e))?;
                let next_fd = unsafe {
                    libc::openat(
                        current_fd.as_raw_fd(),
                        c_name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_fd < 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(format!(
                        "failed to open dir component {:?} in {:?}: {}",
                        name, dir_path, err
                    ));
                }
                current_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(next_fd) };
            }
            std::path::Component::Prefix(_) => {
                return Err("path prefix is not supported on Unix".to_string());
            }
        }
    }

    Ok(current_fd)
}

pub fn read_receipt_bounded_nofollow(path: &Path) -> Result<Option<String>, String> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    if !path.is_absolute() {
        return Err(format!("receipt path {:?} must be absolute", path));
    }

    let parent = match path.parent() {
        Some(p) => p,
        None => return Err(format!("receipt path {:?} has no parent", path)),
    };
    let file_name = match path.file_name() {
        Some(f) => f,
        None => return Err(format!("receipt path {:?} has no file name", path)),
    };

    let parent_fd = match open_dir_nofollow_stepwise(parent) {
        Ok(fd) => fd,
        Err(e) => {
            if e.contains("No such file or directory") {
                return Ok(None);
            }
            return Err(e);
        }
    };

    let c_file_name = std::ffi::CString::new(file_name.as_bytes())
        .map_err(|e| format!("invalid file name {:?}: {}", file_name, e))?;

    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    let fstatat_res = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c_file_name.as_ptr(),
            &mut stat_buf,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };

    if fstatat_res < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!("fstatat failed for {:?}: {}", path, err));
    }

    if (stat_buf.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "receipt {:?} is not a regular file (mode: {:o})",
            path, stat_buf.st_mode
        ));
    }

    if stat_buf.st_size < 0 || stat_buf.st_size > 64 * 1024 {
        return Err(format!(
            "receipt {:?} file size ({}) exceeds 64 KiB limit",
            path, stat_buf.st_size
        ));
    }

    let file_fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            c_file_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if file_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("openat failed for {:?}: {}", path, err));
    }
    let owned_file_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(file_fd) };

    let mut opened_stat: libc::stat = unsafe { std::mem::zeroed() };
    let fstat_res = unsafe { libc::fstat(owned_file_fd.as_raw_fd(), &mut opened_stat) };
    if fstat_res < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!(
            "fstat failed on opened receipt {:?}: {}",
            path, err
        ));
    }
    if (opened_stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(format!(
            "opened receipt {:?} is not a regular file (mode: {:o})",
            path, opened_stat.st_mode
        ));
    }
    if opened_stat.st_dev != stat_buf.st_dev || opened_stat.st_ino != stat_buf.st_ino {
        return Err(format!(
            "receipt {:?} changed identity between stat and open",
            path
        ));
    }

    let mut file = std::fs::File::from(owned_file_fd);
    let mut content = String::new();
    let mut reader = (&mut file).take(64 * 1024 + 1);
    reader
        .read_to_string(&mut content)
        .map_err(|e| format!("reading receipt {:?}: {}", path, e))?;

    if content.len() > 64 * 1024 {
        return Err(format!("receipt {:?} content exceeded 64 KiB limit", path));
    }

    Ok(Some(content))
}

pub(super) fn read_af_version_receipt(pkg: &Package) -> Option<String> {
    static AF_VER_PATH_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(/[A-Za-z0-9_./-]*/\.(?:af-version|af-components\.json))").unwrap()
    });
    let mut candidate_paths = Vec::new();
    let is_filebot = pkg.name.eq_ignore_ascii_case("filebot");
    let opt_name = if is_filebot {
        "filebot-node"
    } else {
        pkg.name.as_str()
    };
    if let Some(ref root) = resolve_configured_fs_root() {
        candidate_paths.push(root.join(format!("opt/{}/.af-version", opt_name)));
        candidate_paths.push(root.join(format!("opt/{}/.af-components.json", opt_name)));
        candidate_paths.push(root.join(format!("var/lib/{}/.af-version", pkg.name)));
        candidate_paths.push(root.join(format!("var/lib/{}/.af-components.json", pkg.name)));
        for token in &pkg.version_command {
            for cap in AF_VER_PATH_RE.captures_iter(token) {
                if let Some(m) = cap.get(1) {
                    let rel = m.as_str().trim_start_matches('/');
                    candidate_paths.push(root.join(rel));
                }
            }
        }
    }
    candidate_paths.push(resolve_fs_path(&format!("/opt/{}/.af-version", opt_name)));
    candidate_paths.push(resolve_fs_path(&format!(
        "/opt/{}/.af-components.json",
        opt_name
    )));
    candidate_paths.push(resolve_fs_path(&format!(
        "/var/lib/{}/.af-version",
        pkg.name
    )));
    candidate_paths.push(resolve_fs_path(&format!(
        "/var/lib/{}/.af-components.json",
        pkg.name
    )));
    for token in &pkg.version_command {
        for cap in AF_VER_PATH_RE.captures_iter(token) {
            if let Some(m) = cap.get(1) {
                candidate_paths.push(resolve_fs_path(m.as_str()));
            }
        }
    }
    if is_filebot {
        candidate_paths.retain(|p| {
            let s = p.to_string_lossy();
            !s.ends_with("opt/filebot/.af-version")
                && !s.ends_with("opt/filebot/.af-components.json")
        });
    }

    for path in candidate_paths {
        match read_receipt_bounded_nofollow(&path) {
            Ok(Some(contents)) => {
                let version = extract_version(&contents, &pkg.version_regex);
                if version.is_empty() {
                    let t = contents.trim();
                    if !t.is_empty() {
                        return Some(t.to_string());
                    }
                } else {
                    return Some(version);
                }
            }
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "rejected insecure or invalid receipt");
                continue;
            }
        }
    }
    None
}

pub(super) fn resolve_git_dir_for_probe(logical_path: &str) -> Option<PathBuf> {
    let clean = logical_path.trim_start_matches('/');
    let candidates = [
        resolve_configured_fs_root().map(|r| r.join(clean)),
        Some(resolve_fs_path(logical_path)),
    ];
    candidates.into_iter().flatten().find(|p| p.exists())
}

pub(super) async fn probe_live_git_version(
    pkg: &Package,
    _budget: Duration,
) -> Option<Result<String, anyhow::Error>> {
    // Cloudplow's checkout is private to root because it also holds rclone configuration.
    if pkg.name == "cloudplow"
        && resolve_configured_fs_root().is_none()
        && af_runner::is_runner_available()
    {
        return Some(af_runner::probe_package_version_via_runner(&pkg.name).await);
    }

    if pkg.name == "piped" || pkg.update_repo.eq_ignore_ascii_case("TeamPiped/Piped") {
        let fe_dir = resolve_git_dir_for_probe("/opt/piped/frontend/.git")
            .or_else(|| resolve_git_dir_for_probe("/opt/piped/.git"));
        let be_dir = resolve_git_dir_for_probe("/opt/piped/backend/.git")
            .or_else(|| resolve_git_dir_for_probe("/opt/piped-backend/.git"));
        let pr_dir = resolve_git_dir_for_probe("/opt/piped/proxy/.git")
            .or_else(|| resolve_git_dir_for_probe("/opt/piped-proxy/.git"));

        if fe_dir.is_some() || be_dir.is_some() || pr_dir.is_some() {
            let (Some(fe), Some(be), Some(pr)) = (fe_dir, be_dir, pr_dir) else {
                return Some(Err(anyhow::anyhow!(
                    "Incomplete or failed live git probe for piped components"
                )));
            };

            let fe_res = af_runner::probe_metadata::resolve_git_head_commit_nofollow(&fe)
                .map_err(|e| anyhow::anyhow!("piped frontend git probe failed: {}", e));
            let be_res = af_runner::probe_metadata::resolve_git_head_commit_nofollow(&be)
                .map_err(|e| anyhow::anyhow!("piped backend git probe failed: {}", e));
            let pr_res = af_runner::probe_metadata::resolve_git_head_commit_nofollow(&pr)
                .map_err(|e| anyhow::anyhow!("piped proxy git probe failed: {}", e));

            match (fe_res, be_res, pr_res) {
                (Ok(fe_sha), Ok(be_sha), Ok(pr_sha)) => Some(Ok(format!(
                    "frontend:{},backend:{},proxy:{}",
                    fe_sha.to_ascii_lowercase(),
                    be_sha.to_ascii_lowercase(),
                    pr_sha.to_ascii_lowercase()
                ))),
                _ => Some(Err(anyhow::anyhow!(
                    "Incomplete or failed live git probe for piped components"
                ))),
            }
        } else {
            None
        }
    } else if pkg.update_source.eq_ignore_ascii_case("git") {
        resolve_git_dir_for_probe(&format!("/opt/{}/source/.git", pkg.name))
            .or_else(|| resolve_git_dir_for_probe(&format!("/opt/{}/.git", pkg.name)))
            .map(|git_dir| {
                af_runner::probe_metadata::resolve_git_head_commit_nofollow(&git_dir)
                    .map_err(|e| anyhow::anyhow!("{}", e))
            })
    } else {
        None
    }
}

pub(super) fn is_regular_executable(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.file_type().is_file() && (meta.permissions().mode() & 0o111) != 0 {
            return true;
        }
        if meta.file_type().is_symlink() {
            let path_str = path.to_string_lossy();
            if path_str.starts_with("/bin/")
                || path_str.starts_with("/sbin/")
                || path_str.starts_with("/usr/bin/")
                || path_str.starts_with("/usr/sbin/")
                || path_str.starts_with("/usr/local/bin/")
                || path_str.starts_with("/usr/local/sbin/")
            {
                if let Ok(target_meta) = fs::metadata(path) {
                    if target_meta.file_type().is_file()
                        && (target_meta.permissions().mode() & 0o111) != 0
                    {
                        if let Ok(canonical) = fs::canonicalize(path) {
                            let can_str = canonical.to_string_lossy();
                            if !can_str.starts_with("/tmp")
                                && !can_str.starts_with("/var/tmp")
                                && !can_str.starts_with("/dev/shm")
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        meta.file_type().is_file()
    }
}

pub(super) fn dir_has_runtime_files(dir_path: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir_path) else {
        return false;
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let lower = name_str.to_ascii_lowercase();

        if lower == ".af-version" || lower == ".af-components.json" || lower == "." || lower == ".."
        {
            continue;
        }

        if lower.ends_with(".lock")
            || lower.ends_with(".log")
            || lower.ends_with(".tmp")
            || lower.ends_with(".pid")
            || lower.ends_with(".bak")
            || lower.ends_with(".json")
            || lower.ends_with(".txt")
            || lower.ends_with(".conf")
            || lower.ends_with(".ini")
            || lower.ends_with(".yaml")
            || lower.ends_with(".yml")
            || lower.ends_with(".toml")
            || lower.ends_with(".db")
            || lower.ends_with(".sqlite")
        {
            continue;
        }

        if let Ok(meta) = fs::symlink_metadata(&entry_path) {
            if meta.file_type().is_dir() {
                if name_str == "bin" && dir_has_runtime_files(&entry_path) {
                    return true;
                }
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.file_type().is_file() && (meta.permissions().mode() & 0o111) != 0 {
                    return true;
                }
            }
            #[cfg(not(unix))]
            {
                if meta.file_type().is_file() {
                    return true;
                }
            }
        }
    }
    false
}

pub(super) fn tokenize_systemd_command(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = cmd.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '\\' if in_double => {
                if let Some(&next_c) = chars.peek() {
                    if next_c == '"' || next_c == '\\' || next_c == '$' || next_c == '`' {
                        chars.next();
                        cur.push(next_c);
                        continue;
                    }
                }
                cur.push('\\');
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(cur);
                    cur = String::new();
                }
            }
            c => {
                cur.push(c);
            }
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

pub fn is_valid_systemd_service_unit(resolved_unit_path: &Path, pkg: &Package) -> bool {
    let content = match read_receipt_bounded_nofollow(resolved_unit_path) {
        Ok(Some(c)) => c,
        _ => return false,
    };

    if content.trim().is_empty() {
        return false;
    }

    let mut exec_commands: Vec<String> = Vec::new();
    let mut working_directory: Option<PathBuf> = None;
    let mut current_section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed[1..trimmed.len() - 1].trim().to_string();
            continue;
        }

        let Some((raw_key, raw_val)) = trimmed.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let val = raw_val.trim();

        if (key == "ExecStart" || key == "WorkingDirectory") && current_section != "Service" {
            return false;
        }

        if current_section != "Service" {
            continue;
        }

        if key == "WorkingDirectory" {
            if !val.is_empty() {
                working_directory = Some(PathBuf::from(val));
            }
            continue;
        }

        if key == "ExecStart" {
            if val.is_empty() {
                exec_commands.clear();
            } else {
                exec_commands.push(val.to_string());
            }
            continue;
        }
    }

    if exec_commands.is_empty() {
        return false;
    }

    const INTERPRETERS: &[&str] = &[
        "sh", "bash", "dash", "zsh", "env", "python", "python3", "python2", "node", "nodejs",
        "java", "ruby", "perl", "php", "dotnet",
    ];

    for cmd_str in &exec_commands {
        let mut raw = cmd_str.as_str();
        while raw.starts_with(['-', '@', '+', '!']) {
            raw = raw[1..].trim_start();
        }
        if raw.is_empty() {
            return false;
        }

        let tokens = tokenize_systemd_command(raw);
        if tokens.is_empty() {
            return false;
        }

        let exec_bin = &tokens[0];
        let resolved_exec = resolve_fs_path(exec_bin);
        if !is_regular_executable(&resolved_exec) {
            return false;
        }

        let bin_name = Path::new(exec_bin)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(exec_bin)
            .to_ascii_lowercase();

        let is_interpreter = INTERPRETERS.contains(&bin_name.as_str());

        if is_interpreter {
            for arg in &tokens[1..] {
                if arg.starts_with('-') {
                    continue;
                }
                let cand_path = if arg.starts_with('/') {
                    Some(PathBuf::from(arg))
                } else if let Some(ref wd) = working_directory {
                    Some(wd.join(arg))
                } else if arg.contains('.') || arg.contains('/') {
                    Some(PathBuf::from(arg))
                } else {
                    None
                };

                if let Some(p) = cand_path {
                    let resolved_p = resolve_fs_path(&p.to_string_lossy());
                    let is_file = fs::symlink_metadata(&resolved_p)
                        .map(|m| m.file_type().is_file())
                        .unwrap_or(false);
                    if !is_file {
                        return false;
                    }
                    break;
                }
            }

            let mut secondary_evidence = false;

            if pkg.name.eq_ignore_ascii_case("filebot") {
                let resolved_app = resolve_fs_path("/opt/filebot-node/server/app.js");
                if fs::symlink_metadata(&resolved_app)
                    .map(|m| m.file_type().is_file())
                    .unwrap_or(false)
                {
                    secondary_evidence = true;
                }
            }

            let candidate_dirs = [
                format!("/opt/{}", pkg.name),
                format!("/opt/{}/bin", pkg.name),
                format!("/var/lib/{}", pkg.name),
                format!("/etc/{}", pkg.name),
            ];
            for dir in &candidate_dirs {
                let resolved_dir = resolve_fs_path(dir);
                if dir_has_runtime_files(&resolved_dir) {
                    secondary_evidence = true;
                    break;
                }
            }

            if !secondary_evidence {
                let bin_paths = [
                    format!("/usr/local/bin/{}", pkg.name),
                    format!("/usr/bin/{}", pkg.name),
                    format!("/opt/{}/{}", pkg.name, pkg.name),
                    format!("/opt/{}/bin/{}", pkg.name, pkg.name),
                ];
                for b in &bin_paths {
                    let resolved_b = resolve_fs_path(b);
                    if is_regular_executable(&resolved_b) {
                        secondary_evidence = true;
                        break;
                    }
                }
            }

            if !secondary_evidence {
                let (update_source, apt_pkg) = effective_update_source_and_apt_package(pkg);
                let non_apt_package_field = matches!(
                    update_source.trim().to_ascii_lowercase().as_str(),
                    "pinned" | "retired" | "vendor" | "pypi"
                );
                if (update_source == "apt"
                    || (!non_apt_package_field && !pkg.update_package.is_empty()))
                    && !apt_pkg.is_empty()
                {
                    let mut cmd = std::process::Command::new("dpkg-query");
                    if let Some(ref root) = resolve_configured_fs_root() {
                        let dpkg_dir = root.join("var/lib/dpkg");
                        if dpkg_dir.exists() {
                            cmd.arg(format!("--admindir={}", dpkg_dir.display()));
                        }
                    }
                    cmd.args(["-W", "-f=${Status}", apt_pkg]);
                    if let Ok(out) = cmd.output() {
                        if out.status.success() {
                            let status_str = String::from_utf8_lossy(&out.stdout);
                            if status_str.trim() == "install ok installed" {
                                secondary_evidence = true;
                            }
                        }
                    }
                }
            }

            if !secondary_evidence {
                return false;
            }
        }
    }

    true
}

pub(super) fn has_independent_runtime_evidence(pkg: &Package) -> bool {
    if !is_package_installed(pkg) {
        return false;
    }

    if pkg.name.eq_ignore_ascii_case("filebot") {
        let resolved_app = resolve_fs_path("/opt/filebot-node/server/app.js");
        if fs::symlink_metadata(&resolved_app)
            .map(|m| m.file_type().is_file())
            .unwrap_or(false)
        {
            return true;
        }
    }

    // 1. Systemd unit file exists and is valid
    let mut unit_paths = vec![
        format!("/etc/systemd/system/{}.service", pkg.name),
        format!("/lib/systemd/system/{}.service", pkg.name),
    ];
    if !pkg.service_name.is_empty() {
        let u_str = if pkg.service_name.ends_with(".service") {
            pkg.service_name.clone()
        } else {
            format!("{}.service", pkg.service_name)
        };
        unit_paths.push(format!("/etc/systemd/system/{}", u_str));
        unit_paths.push(format!("/lib/systemd/system/{}", u_str));
    }
    for u in &unit_paths {
        let resolved = resolve_fs_path(u);
        if is_valid_systemd_service_unit(&resolved, pkg) {
            return true;
        }
    }

    // 2. Binary exists
    let bin_paths = [
        format!("/usr/local/bin/{}", pkg.name),
        format!("/usr/bin/{}", pkg.name),
        format!("/opt/{}/{}", pkg.name, pkg.name),
        format!("/opt/{}/bin/{}", pkg.name, pkg.name),
    ];
    for b in &bin_paths {
        let resolved = resolve_fs_path(b);
        if is_regular_executable(&resolved) {
            return true;
        }
    }
    if let Some(cmd_prog) = pkg.version_command.first() {
        if cmd_prog.starts_with('/') && !cmd_prog.ends_with("/cat") {
            let resolved = resolve_fs_path(cmd_prog);
            if is_regular_executable(&resolved) {
                return true;
            }
        }
    }

    // 3. Install directory contains actual runtime files beyond .af-version and .af-components.json
    let candidate_dirs = [
        format!("/opt/{}", pkg.name),
        format!("/opt/{}/bin", pkg.name),
        format!("/var/lib/{}", pkg.name),
        format!("/etc/{}", pkg.name),
    ];
    for dir in &candidate_dirs {
        let resolved = resolve_fs_path(dir);
        if dir_has_runtime_files(&resolved) {
            return true;
        }
    }

    false
}

pub(super) fn apt_receipt_matches_live_debian_revision(
    update_source: &str,
    receipt_ver: &str,
    live_ver: &str,
) -> bool {
    if !matches!(
        update_source.trim().to_ascii_lowercase().as_str(),
        "apt" | "deb" | "dpkg"
    ) {
        return false;
    }
    let live_trimmed = live_ver.trim();
    let without_epoch = match live_trimmed.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            rest
        }
        _ => live_trimmed,
    };
    let Some((live_upstream, deb_rev)) = without_epoch.rsplit_once('-') else {
        return false;
    };
    !live_upstream.contains('~')
        && af_release::lifecycle::is_valid_apt_debian_revision_suffix(deb_rev)
        && (af_release::lifecycle::versions_match_target(receipt_ver, live_upstream)
            || af_release::lifecycle::versions_match_target(live_upstream, receipt_ver))
}

pub async fn probe_installed_package_version_strict(pkg: &Package) -> anyhow::Result<String> {
    let receipt_opt = read_af_version_receipt(pkg);
    let cmd_only_reads_af_ver = pkg
        .version_command
        .first()
        .map(|s| s == "cat")
        .unwrap_or(false)
        && pkg
            .version_command
            .iter()
            .any(|arg| arg.contains(".af-version"));

    if let Some(git_res) = probe_live_git_version(pkg, Duration::from_secs(5)).await {
        match git_res {
            Ok(live_git_ver) => {
                if let Some(ref receipt_ver) = receipt_opt {
                    if !af_release::lifecycle::versions_match_target(receipt_ver, &live_git_ver)
                        && !af_release::lifecycle::versions_match_target(&live_git_ver, receipt_ver)
                    {
                        anyhow::bail!(
                            "Stale or mismatched .af-version receipt ({receipt_ver}) vs live git state ({live_git_ver})"
                        );
                    }
                }
                return Ok(live_git_ver);
            }
            Err(e) => return Err(e),
        }
    }

    let (update_source, _) = effective_update_source_and_apt_package(pkg);
    let has_live_command =
        !cmd_only_reads_af_ver && (!pkg.version_command.is_empty() || update_source == "apt");
    let live_res = if has_live_command {
        Some(run_live_version_command(pkg, Duration::from_secs(10)).await)
    } else {
        None
    };

    match (live_res, receipt_opt) {
        (Some(Ok(live_ver)), Some(receipt_ver)) => {
            if !af_release::lifecycle::versions_match_target(&receipt_ver, &live_ver)
                && !af_release::lifecycle::versions_match_target(&live_ver, &receipt_ver)
                && !apt_receipt_matches_live_debian_revision(
                    &pkg.update_source,
                    &receipt_ver,
                    &live_ver,
                )
            {
                anyhow::bail!(
                    "Stale or mismatched .af-version receipt ({receipt_ver}) vs live runtime ({live_ver})"
                );
            }
            Ok(live_ver)
        }
        (Some(Ok(live_ver)), None) => Ok(live_ver),
        (Some(Err(e)), _) => Err(e),
        (None, Some(receipt_ver)) => {
            if !has_independent_runtime_evidence(pkg) {
                anyhow::bail!(
                    "No independent runtime evidence found alongside .af-version receipt"
                );
            }
            Ok(receipt_ver)
        }
        (None, None) => {
            anyhow::bail!(
                "no installed version probe configured or available for {}",
                pkg.name
            );
        }
    }
}

pub(super) async fn check_single_package(
    client: &reqwest::Client,
    github_api_base: &str,
    pkg: &Package,
) -> (PackageUpdateRecord, bool) {
    probe_package_update(client, github_api_base, pkg).await
}

#[cfg(test)]
pub(super) fn build_package_update_record(
    pkg_name: &str,
    is_installed: bool,
    installed_res: anyhow::Result<String>,
    latest_res: anyhow::Result<(String, String)>,
    prev_record: Option<&PackageUpdateRecord>,
    checked_at: String,
) -> PackageUpdateRecord {
    build_package_update_record_for_source(
        "https://api.github.com",
        "",
        pkg_name,
        is_installed,
        installed_res,
        latest_res,
        prev_record,
        checked_at,
        "",
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_package_update_record_for_source(
    github_api_base: &str,
    update_source: &str,
    pkg_name: &str,
    is_installed: bool,
    installed_res: anyhow::Result<String>,
    latest_res: anyhow::Result<(String, String)>,
    prev_record: Option<&PackageUpdateRecord>,
    checked_at: String,
    expected_source_key: &str,
) -> PackageUpdateRecord {
    let mut err_parts = Vec::new();
    let (installed_version, installed_fell_back) = match &installed_res {
        Ok(v) if !v.trim().is_empty() => (v.trim().to_string(), false),
        Ok(_) => {
            let (fallback, fell_back) = resolve_installed_package_version(None, prev_record);
            if is_installed && fell_back {
                tracing::warn!(
                    package = pkg_name,
                    "installed version probe returned empty output"
                );
            }
            (fallback, is_installed && fell_back)
        }
        Err(e) => {
            tracing::warn!(package = pkg_name, error = %e, "installed version observation failed");
            let (fallback, fell_back) = resolve_installed_package_version(None, prev_record);
            (fallback, is_installed && fell_back)
        }
    };

    let resolved_expected_key = if !expected_source_key.trim().is_empty() {
        expected_source_key.trim().to_string()
    } else if let Ok(catalog) = crate::get_package_catalog() {
        if let Some(pkg) = catalog
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(pkg_name))
        {
            canonical_update_source_key(github_api_base, pkg)
        } else {
            let synth = Package {
                name: pkg_name.to_string(),
                update_source: update_source.to_string(),
                update_repo: pkg_name.to_string(),
                update_package: pkg_name.to_string(),
                ..Default::default()
            };
            canonical_update_source_key(github_api_base, &synth)
        }
    } else {
        let synth = Package {
            name: pkg_name.to_string(),
            update_source: update_source.to_string(),
            update_repo: pkg_name.to_string(),
            update_package: pkg_name.to_string(),
            ..Default::default()
        };
        canonical_update_source_key(github_api_base, &synth)
    };

    let source_matched = prev_record
        .map(|r| {
            !r.source_key.trim().is_empty() && r.source_key.trim() == resolved_expected_key.trim()
        })
        .unwrap_or(false);

    let current_channel = if let Some((_, ch)) = resolved_expected_key.rsplit_once('|') {
        let ch_clean = ch.trim();
        if ((resolved_expected_key.starts_with("github:")
            || resolved_expected_key.starts_with("git"))
            && resolved_expected_key.matches('|').count() < 2)
            || ch_clean.is_empty()
            || ch_clean.contains('/')
        {
            "stable"
        } else {
            ch_clean
        }
    } else {
        "stable"
    };

    let effective_update_source = if !update_source.trim().is_empty() {
        update_source.trim()
    } else if let Some((src, _)) = resolved_expected_key.split_once(':') {
        src.trim()
    } else {
        ""
    };

    let valid_prev_upstream = if source_matched { prev_record } else { None };

    let mut stale_cache_observed_at: Option<String> = None;
    let mut used_prev_latest = false;

    let (latest_version, release_url) = match &latest_res {
        Ok((v, u)) => (v.clone(), u.clone()),
        Err(e) => {
            tracing::warn!(package = pkg_name, error = %e, "latest version observation failed");
            err_parts.push("Latest version could not be confirmed");
            let mut prev_ver = valid_prev_upstream
                .filter(|r| {
                    !r.latest_version.trim().is_empty()
                        && tag_allowed_by_channel_for_source(
                            &r.latest_version,
                            current_channel,
                            effective_update_source,
                        )
                })
                .map(|r| r.latest_version.clone())
                .unwrap_or_default();
            let mut prev_url = if !prev_ver.is_empty() {
                valid_prev_upstream
                    .map(|r| r.release_url.clone())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            if !prev_ver.is_empty() {
                used_prev_latest = true;
            } else {
                if let Ok(pkgs) = crate::get_packages() {
                    if let Some(pkg) = pkgs.iter().find(|p| p.name == pkg_name) {
                        if (pkg.update_source == "github_release" || pkg.update_source == "github")
                            && !pkg.update_repo.is_empty()
                        {
                            let ch = if !pkg.update_channel.trim().is_empty() {
                                &pkg.update_channel
                            } else {
                                current_channel
                            };
                            if let Some((cached_v, cached_u, cached_obs)) =
                                get_cached_github_release_stale_for_channel(
                                    github_api_base,
                                    &pkg.update_repo,
                                    ch,
                                )
                            {
                                if tag_allowed_by_channel_for_source(
                                    &cached_v,
                                    ch,
                                    &pkg.update_source,
                                ) {
                                    prev_ver = cached_v;
                                    if prev_url.is_empty() {
                                        prev_url = cached_u;
                                    }
                                    stale_cache_observed_at = Some(cached_obs);
                                }
                            }
                        }
                        if prev_ver.is_empty() && pkg.name == "threadfin" {
                            let fallback = af_runner::resolve_threadfin_target_version();
                            if !fallback.is_empty() {
                                prev_ver = fallback.clone();
                                if prev_url.is_empty() {
                                    prev_url = format!("https://github.com/Threadfin/Threadfin/releases/tag/{fallback}");
                                }
                            }
                        }
                    }
                }
                if prev_ver.is_empty() {
                    if let Some((cached_v, cached_u, cached_obs)) =
                        get_cached_github_release_stale_for_channel(
                            github_api_base,
                            pkg_name,
                            current_channel,
                        )
                    {
                        if tag_allowed_by_channel_for_source(
                            &cached_v,
                            current_channel,
                            effective_update_source,
                        ) {
                            prev_ver = cached_v;
                            if prev_url.is_empty() {
                                prev_url = cached_u;
                            }
                            stale_cache_observed_at = Some(cached_obs);
                        }
                    }
                }
            }
            (prev_ver, prev_url)
        }
    };

    if installed_res.is_err()
        || installed_res
            .as_ref()
            .map(|v| v.trim().is_empty())
            .unwrap_or(false)
    {
        if is_installed && installed_fell_back && latest_res.is_ok() {
            err_parts.push("Installed version probe returned no output; retaining last known installed version");
        } else {
            err_parts.insert(0, "Installed version could not be confirmed");
        }
    }

    let update_available = if !is_installed {
        false
    } else if latest_res.is_ok() {
        if installed_res.is_ok()
            && !installed_fell_back
            && !installed_version.is_empty()
            && !installed_version.eq_ignore_ascii_case("unknown")
        {
            is_version_newer_for_source(
                &installed_version,
                &latest_version,
                effective_update_source,
            )
        } else {
            // Installed probe failed/fell back; do not claim a confirmed update against fresh upstream
            false
        }
    } else if used_prev_latest {
        // Upstream latest_res failed, but previous latest_version was retained
        if installed_res.is_ok()
            && !installed_fell_back
            && !installed_version.is_empty()
            && !installed_version.eq_ignore_ascii_case("unknown")
        {
            // Fresh installed observation succeeded: recompute availability against retained latest_version!
            is_version_newer_for_source(
                &installed_version,
                &latest_version,
                effective_update_source,
            )
        } else {
            // Installed probe also failed/fell back: preserve previous availability if channel allowed
            valid_prev_upstream
                .filter(|r| {
                    tag_allowed_by_channel_for_source(
                        &r.latest_version,
                        current_channel,
                        effective_update_source,
                    )
                })
                .map(|record| record.update_available)
                .unwrap_or(false)
        }
    } else {
        false
    };

    let checked_at = if latest_res.is_err() {
        if used_prev_latest {
            valid_prev_upstream
                .map(|p| p.checked_at.clone())
                .unwrap_or_default()
        } else {
            stale_cache_observed_at.unwrap_or_default()
        }
    } else {
        checked_at
    };

    PackageUpdateRecord {
        package_id: pkg_name.to_string(),
        installed: is_installed,
        installed_version,
        latest_version,
        update_available,
        checked_at,
        release_url,
        error: err_parts.join("; "),
        source_key: resolved_expected_key,
    }
}

pub(super) async fn update_probe_output(
    command: Command,
    budget: Duration,
) -> anyhow::Result<std::process::Output> {
    // The supervisor retains process-tree ownership through cancellation,
    // deadline/output failure and pipe cleanup; a response timeout is not enough.
    af_runner::bounded_command::output(command, budget, 1024 * 1024)
        .await
        .map_err(Into::into)
}

pub(super) fn effective_update_source_and_apt_package(pkg: &Package) -> (&str, &str) {
    if af_runner::select_package_engine(&pkg.name) == af_runner::PackageEngineMode::DeclarativeRust
        && matches!(pkg.name.as_str(), "prometheus" | "netdata" | "mergerfs")
    {
        let apt_pkg = if pkg.update_package.is_empty() {
            pkg.name.as_str()
        } else {
            pkg.update_package.as_str()
        };
        return ("apt", apt_pkg);
    }
    let src = pkg.update_source.as_str();
    if src == "github_release" || src == "github" {
        ("github", pkg.update_package.as_str())
    } else {
        (src, pkg.update_package.as_str())
    }
}

pub(super) fn resolve_configured_fs_root() -> Option<PathBuf> {
    for env_key in ["AETHERFLOW_FS_ROOT", "AETHERFLOW_INSTALL_ROOT"] {
        if let Ok(root) = env::var(env_key) {
            let trimmed = root.trim();
            if !trimmed.is_empty() && trimmed != "/" {
                return Some(PathBuf::from(trimmed));
            }
        }
    }
    None
}

pub(super) fn normalize_live_probe_output(
    pkg: &Package,
    update_source: &str,
    combined: &str,
    stdout_str: &str,
) -> anyhow::Result<String> {
    for line in combined.lines() {
        let trimmed_line = line.trim();
        if let Some(manifest) = parse_component_manifest(trimmed_line) {
            return Ok(normalize_component_manifest(&manifest));
        }
    }

    if update_source == "git" {
        return parse_git_head(stdout_str);
    }

    let version = extract_version(combined, &pkg.version_regex);
    if version.is_empty() {
        anyhow::bail!("unable to parse version output");
    }
    Ok(version)
}

pub(super) fn resolve_probe_program(raw_prog: &str, fs_root: Option<&Path>) -> PathBuf {
    if raw_prog.starts_with('/') {
        let resolved = resolve_fs_path(raw_prog);
        if resolved.exists() {
            return resolved;
        }
        if raw_prog == "/usr/local/bin/prometheus" {
            let alt = resolve_fs_path("/usr/bin/prometheus");
            if alt.exists() {
                return alt;
            }
            return resolved;
        }
        return PathBuf::from(raw_prog);
    }
    if let Some(root) = fs_root {
        for rel in [
            "usr/local/sbin",
            "usr/local/bin",
            "usr/sbin",
            "usr/bin",
            "sbin",
            "bin",
        ] {
            let candidate = root.join(rel).join(raw_prog);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from(raw_prog)
}

pub async fn run_live_version_command(pkg: &Package, budget: Duration) -> anyhow::Result<String> {
    if let Some(git_res) = probe_live_git_version(pkg, budget).await {
        return git_res;
    }
    let (update_source, apt_package) = effective_update_source_and_apt_package(pkg);
    let fs_root = resolve_configured_fs_root();
    match update_source {
        "apt" => {
            if apt_package.is_empty() {
                anyhow::bail!("no apt package configured for {}", pkg.name);
            }
            let dpkg_prog = resolve_probe_program("dpkg-query", fs_root.as_deref());
            let mut command = Command::new(&dpkg_prog);
            let mut dpkg_args: Vec<String> = Vec::new();
            if let Some(ref root) = fs_root {
                let dpkg_dir = root.join("var/lib/dpkg");
                if dpkg_dir.exists() {
                    dpkg_args.push(format!("--admindir={}", dpkg_dir.display()));
                }
            }
            dpkg_args.push("-W".to_string());
            dpkg_args.push("-f=${Version}".to_string());
            dpkg_args.push(apt_package.to_string());
            let sandbox_spec = af_runner::probe_metadata::ProbeSandboxSpec {
                drop_to_path_owner: false,
                fs_root: fs_root.clone(),
                package_user: None,
            };
            af_runner::probe_metadata::configure_sandboxed_tokio_command(
                &mut command,
                &dpkg_prog,
                &dpkg_args,
                &sandbox_spec,
            )
            .map_err(|e| anyhow::anyhow!("probe sandbox validation failed: {}", e))?;
            command.args(&dpkg_args);
            let out = update_probe_output(command, budget).await?;

            if !out.status.success() {
                anyhow::bail!(
                    "dpkg-query exited with {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }

            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let version = extract_version(&combined, &pkg.version_regex);
            if version.is_empty() {
                anyhow::bail!("unable to parse installed apt version for {}", pkg.name);
            }
            Ok(version)
        }
        _ => {
            if pkg.version_command.is_empty() {
                anyhow::bail!("no version command configured");
            }
            if let Some(static_res) = af_runner::probe_metadata::extract_static_package_version(
                &pkg.name,
                &pkg.version_command,
                &resolve_fs_path,
            ) {
                let raw = static_res.map_err(|e| anyhow::anyhow!("{}", e))?;
                if update_source == "git" {
                    return parse_git_head(&raw);
                }
                let extracted = extract_version(&raw, &pkg.version_regex);
                if !extracted.is_empty() {
                    return Ok(extracted);
                }
                let trimmed = raw.trim();
                if !trimmed.is_empty() && pkg.version_regex.is_empty() {
                    return Ok(trimmed.to_string());
                }
                anyhow::bail!("unable to parse static version output");
            }

            let mut version_command = pkg.version_command.clone();
            if version_command.len() == 3
                && (version_command[0] == "bash" || version_command[0] == "sh")
                && (version_command[1] == "-lc" || version_command[1] == "-c")
            {
                let script = &version_command[2];
                if script.contains(".af-version") {
                    let mut clean = script.as_str();
                    if let Some(pos) = clean.rfind("||") {
                        let rhs = clean[pos + 2..].trim();
                        if rhs.starts_with("cat ") && rhs.contains(".af-version") {
                            clean = clean[..pos].trim();
                        }
                    }
                    if clean.starts_with("if [ -s ")
                        && clean.contains(".af-version")
                        && clean.contains("; else ")
                        && clean.ends_with("; fi")
                    {
                        if let Some(idx1) = clean.find("; else ") {
                            if let Some(idx2) = clean.rfind("; fi") {
                                if idx1 < idx2 {
                                    let mut inner = clean[idx1 + 7..idx2].trim();
                                    if inner.starts_with("bash -lc ") {
                                        inner =
                                            inner[9..].trim().trim_matches('\'').trim_matches('"');
                                    }
                                    clean = inner;
                                }
                            }
                        }
                    }
                    version_command[2] = clean.to_string();
                }
            }
            let prog = resolve_probe_program(&version_command[0], fs_root.as_deref());
            let raw_args: Vec<String> = version_command[1..]
                .iter()
                .map(|arg| {
                    if arg.starts_with('/') {
                        let rebased = resolve_fs_path(arg);
                        if rebased.exists() {
                            return rebased.to_string_lossy().into_owned();
                        }
                    }
                    arg.clone()
                })
                .collect();
            let args = af_runner::probe_metadata::sanitize_probe_shell_args(&prog, &raw_args);
            let mut command = Command::new(&prog);
            let sandbox_spec = af_runner::probe_metadata::ProbeSandboxSpec {
                drop_to_path_owner: false,
                fs_root: fs_root.clone(),
                package_user: None,
            };
            if let Err(e) = af_runner::probe_metadata::configure_sandboxed_tokio_command(
                &mut command,
                &prog,
                &args,
                &sandbox_spec,
            ) {
                if fs_root.is_none() && af_runner::is_runner_available() {
                    let raw = af_runner::probe_package_version_via_runner(&pkg.name).await?;
                    return normalize_live_probe_output(pkg, update_source, &raw, &raw);
                }
                anyhow::bail!("probe sandbox validation failed: {}", e);
            }
            command.args(&args);
            let out = update_probe_output(command, budget).await?;

            if !out.status.success() {
                anyhow::bail!(
                    "version command exited with {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }

            let stdout_str = String::from_utf8_lossy(&out.stdout);
            let stderr_str = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{}\n{}", stdout_str, stderr_str);
            normalize_live_probe_output(pkg, update_source, &combined, &stdout_str)
        }
    }
}

pub(super) async fn detect_installed_version(pkg: &Package) -> anyhow::Result<String> {
    probe_installed_package_version_strict(pkg).await
}

pub async fn detect_latest_piped_manifest() -> anyhow::Result<(String, String, String)> {
    let (fe, be, px) = tokio::try_join!(
        detect_latest_git_head("https://github.com/TeamPiped/Piped.git", "TeamPiped/Piped"),
        detect_latest_git_head(
            "https://github.com/TeamPiped/Piped-Backend.git",
            "TeamPiped/Piped-Backend"
        ),
        detect_latest_git_head(
            "https://github.com/TeamPiped/Piped-Proxy.git",
            "TeamPiped/Piped-Proxy"
        ),
    )?;
    let manifest = format!("frontend:{},backend:{},proxy:{}", fe.0, be.0, px.0);
    let oldest = [&fe.2, &be.2, &px.2]
        .into_iter()
        .min_by_key(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .unwrap()
        .clone();
    Ok((
        manifest,
        "https://github.com/TeamPiped/Piped/commits/HEAD".to_string(),
        oldest,
    ))
}

pub(super) async fn detect_latest_version(
    client: &reqwest::Client,
    github_api_base: &str,
    pkg: &Package,
) -> anyhow::Result<(String, String, String)> {
    if pkg.name == "readarr" {
        let ver = if !pkg.update_package.is_empty() {
            pkg.update_package.clone()
        } else {
            "0.4.18.2805".to_string()
        };
        return Ok((ver, String::new(), Utc::now().to_rfc3339()));
    }
    if pkg.name == "threadfin" {
        let src = pkg.update_source.trim().to_ascii_lowercase();
        if src.is_empty()
            || src == "pinned"
            || af_runner::resolve_threadfin_sha256_override().is_some()
        {
            let target_ver = af_runner::resolve_threadfin_target_version();
            let release_url = format!(
                "https://github.com/Threadfin/Threadfin/releases/tag/{}",
                target_ver
            );
            return Ok((target_ver, release_url, Utc::now().to_rfc3339()));
        }
        let repo = if pkg.update_repo.trim().is_empty() {
            "Threadfin/Threadfin"
        } else {
            pkg.update_repo.trim()
        };
        return detect_latest_github_release_for_channel(
            client,
            github_api_base,
            repo,
            &pkg.update_channel,
        )
        .await;
    }
    if pkg.name == "piped"
        && pkg.update_repo == "TeamPiped/Piped"
        && (pkg.update_repo_url.is_empty()
            || pkg.update_repo_url.contains("github.com/TeamPiped/Piped"))
    {
        return detect_latest_piped_manifest().await;
    }
    let (update_source, apt_package) = effective_update_source_and_apt_package(pkg);
    match update_source {
        "vendor" => Ok((String::new(), String::new(), Utc::now().to_rfc3339())),
        "retired" | "legacy" | "pinned" => {
            let ver = if !pkg.update_package.is_empty() {
                pkg.update_package.clone()
            } else if pkg.name == "readarr" {
                "0.4.18.2805".to_string()
            } else {
                String::new()
            };
            Ok((ver, String::new(), Utc::now().to_rfc3339()))
        }
        "pypi" => {
            let pypi_pkg = if pkg.name == "pyload" {
                "pyload-ng"
            } else if !pkg.update_package.is_empty() {
                &pkg.update_package
            } else {
                &pkg.name
            };
            detect_latest_pypi_version(client, pypi_pkg).await
        }
        "apt" => detect_latest_apt_version(apt_package).await,
        "github" | "github_release" => {
            detect_latest_github_release_for_channel(
                client,
                github_api_base,
                &pkg.update_repo,
                &pkg.update_channel,
            )
            .await
        }
        "git_tags" | "git" | "git_commit" | "git_head" => {
            let repo_url = if !pkg.update_repo_url.is_empty() {
                pkg.update_repo_url.clone()
            } else if !pkg.update_repo.is_empty() {
                format!("https://github.com/{}.git", pkg.update_repo)
            } else {
                String::new()
            };
            if update_source == "git"
                || update_source == "git_commit"
                || update_source == "git_head"
            {
                detect_latest_git_head(&repo_url, &pkg.update_repo).await
            } else {
                detect_latest_git_tag_for_channel(&repo_url, &pkg.update_repo, &pkg.update_channel)
                    .await
            }
        }
        other => anyhow::bail!("unsupported update source {:?}", other),
    }
}

pub async fn detect_latest_pypi_version(
    client: &reqwest::Client,
    package_name: &str,
) -> anyhow::Result<(String, String, String)> {
    if package_name.trim().is_empty() {
        anyhow::bail!("missing PyPI package name");
    }
    let url = format!("https://pypi.org/pypi/{}/json", package_name.trim());
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .header("User-Agent", "AetherFlow-Updater")
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("PyPI API returned {}", resp.status());
    }

    let pypi: PyPiResponse = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("decode PyPI response: {}", e))?;

    let version = extract_version(&pypi.info.version, "");
    if version.is_empty() {
        anyhow::bail!("unable to parse PyPI version {:?}", pypi.info.version);
    }

    let homepage = pypi
        .info
        .project_urls
        .as_ref()
        .and_then(|urls| {
            urls.get("Homepage")
                .or_else(|| urls.get("homepage"))
                .or_else(|| urls.get("Source"))
                .or_else(|| urls.get("source"))
        })
        .cloned()
        .unwrap_or_else(|| {
            format!(
                "https://pypi.org/project/{}/{}/",
                package_name.trim(),
                version
            )
        });

    Ok((version, homepage, Utc::now().to_rfc3339()))
}

pub async fn detect_latest_git_head(
    repo_url: &str,
    repo: &str,
) -> anyhow::Result<(String, String, String)> {
    let url = if !repo_url.trim().is_empty() {
        repo_url.trim().to_string()
    } else if !repo.trim().is_empty() {
        format!("https://github.com/{}.git", repo.trim())
    } else {
        anyhow::bail!("missing repository URL");
    };

    let cache_key = git_head_cache_key(repo_url, repo);

    if let Ok(cache) = GIT_REMOTE_HEAD_CACHE.lock() {
        if let Some((head, h_url, timestamp, observed_at)) = cache.get(&cache_key) {
            if timestamp.elapsed() < Duration::from_secs(15 * 60) {
                return Ok((head.clone(), h_url.clone(), observed_at.clone()));
            }
        }
    }

    let mut command = Command::new("git");
    command.args(["ls-remote", "--exit-code", &url, "HEAD"]);
    let output = update_probe_output(command, Duration::from_secs(20)).await?;
    if !output.status.success() {
        anyhow::bail!(
            "git ls-remote HEAD failed: {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let head = parse_git_head(&String::from_utf8_lossy(&output.stdout))?;
    let sanitized_url = sanitize_git_remote_url_for_display(&url);
    let mut clean_url = sanitized_url.trim_end_matches(".git").to_string();
    if clean_url.is_empty() && !repo.trim().is_empty() {
        clean_url = format!("https://github.com/{}", repo.trim());
    }
    let res = (
        head,
        af_release::lifecycle::sanitize_persisted_lifecycle_text(&format!(
            "{}/commits/HEAD",
            clean_url
        )),
    );
    let now_rfc3339 = Utc::now().to_rfc3339();
    if let Ok(mut cache) = GIT_REMOTE_HEAD_CACHE.lock() {
        cache.insert(
            cache_key.clone(),
            (
                res.0.clone(),
                res.1.clone(),
                Instant::now(),
                now_rfc3339.clone(),
            ),
        );
    }
    Ok((res.0, res.1, now_rfc3339))
}

pub async fn detect_git_remote_head(
    repo_url: &str,
    repo: &str,
) -> anyhow::Result<(String, String, String)> {
    detect_latest_git_head(repo_url, repo).await
}

pub(super) async fn detect_latest_apt_version(
    package_name: &str,
) -> anyhow::Result<(String, String, String)> {
    let mut command = Command::new("apt-cache");
    command.args(["policy", package_name]);
    let out = update_probe_output(command, Duration::from_secs(15)).await?;

    if !out.status.success() {
        anyhow::bail!(
            "apt-cache exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Candidate:") {
            let candidate = rest.trim();
            if candidate != "(none)" && !candidate.is_empty() {
                let version = normalize_tag_or_version_prefix(candidate).trim();
                if !version.is_empty() {
                    return Ok((version.to_string(), String::new(), Utc::now().to_rfc3339()));
                }
            }
            break;
        }
    }

    anyhow::bail!("candidate version not found")
}

pub async fn detect_latest_github_release(
    client: &reqwest::Client,
    github_api_base: &str,
    repo: &str,
) -> anyhow::Result<(String, String, String)> {
    detect_latest_github_release_for_channel(client, github_api_base, repo, "stable").await
}

pub(super) fn parse_github_link_next_url(header_val: &str) -> Option<String> {
    for part in header_val.split(',') {
        let part = part.trim();
        if part.ends_with("rel=\"next\"") || part.contains("rel=\"next\"") {
            if let Some(start) = part.find('<') {
                if let Some(end) = part.find('>') {
                    if start < end {
                        return Some(part[start + 1..end].trim().to_string());
                    }
                }
            }
        }
    }
    None
}

pub async fn detect_latest_github_release_for_channel(
    client: &reqwest::Client,
    github_api_base: &str,
    repo: &str,
    channel: &str,
) -> anyhow::Result<(String, String, String)> {
    if repo.trim().is_empty() {
        anyhow::bail!("missing GitHub repo");
    }

    let clean_repo = repo.trim();
    let effective_channel_owned = {
        let t = channel.trim().to_ascii_lowercase();
        if t.is_empty() {
            "stable".to_string()
        } else {
            t
        }
    };
    let effective_channel = effective_channel_owned.as_str();
    let cache_key =
        github_release_cache_key_for_channel(github_api_base, clean_repo, effective_channel);

    if let Ok(cache) = GITHUB_RELEASE_CACHE.lock() {
        if let Some((ver, url, timestamp, observed_at)) = cache.get(&cache_key) {
            if timestamp.elapsed() < Duration::from_secs(15 * 60)
                && tag_allowed_by_channel(ver, effective_channel)
            {
                return Ok((ver.clone(), url.clone(), observed_at.clone()));
            }
        }
    }

    let is_rate_limited = is_github_api_rate_limited(github_api_base, "releases");
    if is_rate_limited {
        anyhow::bail!("GitHub API rate limit backoff active for {clean_repo}");
    }

    let is_stable = effective_channel == "stable";
    let mut all_releases: Vec<GitHubReleaseResponse> = Vec::new();
    let mut current_url = format!(
        "{}/repos/{}/releases?per_page={GITHUB_RELEASE_PAGE_SIZE}",
        github_api_base.trim_end_matches('/'),
        clean_repo
    );
    let mut page_count = 0;
    const MAX_RELEASE_PAGES: usize = 10;

    while page_count < MAX_RELEASE_PAGES {
        page_count += 1;
        let mut req = client
            .get(&current_url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "AetherFlow-Updater");

        if is_trusted_github_api_url(&current_url, github_api_base) {
            if let Ok(token) = env::var("AF_GITHUB_TOKEN").or_else(|_| env::var("GITHUB_TOKEN")) {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    req = req.header(
                        reqwest::header::AUTHORIZATION,
                        format!("Bearer {}", trimmed),
                    );
                }
            }
        }

        let resp = req.send().await?;
        let status = resp.status();
        let status_code = status.as_u16();

        if page_count == 1 && status == reqwest::StatusCode::NOT_FOUND {
            let fb_url = format!(
                "{}/repos/{}/releases/latest",
                github_api_base.trim_end_matches('/'),
                clean_repo
            );
            let mut fb_req = client
                .get(&fb_url)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "AetherFlow-Updater");
            if is_trusted_github_api_url(&fb_url, github_api_base) {
                if let Ok(token) = env::var("AF_GITHUB_TOKEN").or_else(|_| env::var("GITHUB_TOKEN"))
                {
                    let trimmed = token.trim();
                    if !trimmed.is_empty() {
                        fb_req = fb_req.header(
                            reqwest::header::AUTHORIZATION,
                            format!("Bearer {}", trimmed),
                        );
                    }
                }
            }
            let fb_resp = fb_req.send().await?;
            let fb_status = fb_resp.status();
            let fb_rem_zero = fb_resp
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim() == "0")
                .unwrap_or(false);
            let fb_ra_hdr = fb_resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let fb_res_hdr = fb_resp
                .headers()
                .get("x-ratelimit-reset")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let fb_rb_hdr = fb_resp
                .headers()
                .get("x-ratelimit-resource")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let fb_bytes = fb_resp.bytes().await?;
            let fb_str = String::from_utf8_lossy(&fb_bytes);
            let fb_lower = fb_str.to_ascii_lowercase();
            let fb_has_rate_limit = fb_lower.contains("rate limit")
                || fb_lower.contains("secondary rate limit")
                || fb_lower.contains("abuse detection")
                || fb_lower.contains("too many requests");

            let fb_is_rate_limit_resp = fb_status == reqwest::StatusCode::TOO_MANY_REQUESTS
                || (fb_status == reqwest::StatusCode::FORBIDDEN
                    && (fb_rem_zero || fb_ra_hdr.is_some() || fb_has_rate_limit));

            if fb_is_rate_limit_resp {
                let mut cooldown = Duration::from_secs(60);
                if let Some(retry_after) = fb_ra_hdr.as_deref() {
                    if let Ok(secs) = retry_after.trim().parse::<u64>() {
                        cooldown = Duration::from_secs(secs.clamp(1, 3600));
                    }
                } else if let Some(reset) = fb_res_hdr.as_deref() {
                    if let Ok(reset_epoch) = reset.trim().parse::<i64>() {
                        let now_epoch = Utc::now().timestamp();
                        if reset_epoch > now_epoch {
                            let diff = (reset_epoch - now_epoch) as u64;
                            cooldown = Duration::from_secs(diff.clamp(1, 3600));
                        }
                    }
                }

                if let Some(ref res_b) = fb_rb_hdr {
                    record_github_api_rate_limit(github_api_base, res_b, cooldown);
                }
                record_github_api_rate_limit(github_api_base, "releases", cooldown);
                record_github_api_rate_limit(github_api_base, "tags", cooldown);
                record_github_api_rate_limit(github_api_base, "commits", cooldown);
                record_github_api_rate_limit(github_api_base, "core", cooldown);
                record_github_api_rate_limit(github_api_base, "default", cooldown);

                anyhow::bail!(
                    "GitHub API rate limit exceeded for {clean_repo} (status {})",
                    fb_status.as_u16()
                );
            }

            if !fb_status.is_success() {
                anyhow::bail!("GitHub API returned {}", fb_status);
            }

            if let Ok(single) = serde_json::from_slice::<GitHubReleaseResponse>(&fb_bytes) {
                all_releases.push(single);
            }
            break;
        }

        let rem_zero = resp
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim() == "0")
            .unwrap_or(false);
        let ra_hdr = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let res_hdr = resp
            .headers()
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let rb_hdr = resp
            .headers()
            .get("x-ratelimit-resource")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let link_hdr = resp
            .headers()
            .get("link")
            .or_else(|| resp.headers().get("Link"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body_bytes = resp.bytes().await?;
        let body_str = String::from_utf8_lossy(&body_bytes);
        let body_lower = body_str.to_ascii_lowercase();

        let body_has_rate_limit = body_lower.contains("rate limit")
            || body_lower.contains("secondary rate limit")
            || body_lower.contains("abuse detection")
            || body_lower.contains("too many requests");

        let is_rate_limit_resp = status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || (status == reqwest::StatusCode::FORBIDDEN
                && (rem_zero || ra_hdr.is_some() || body_has_rate_limit));

        if is_rate_limit_resp {
            let mut cooldown = Duration::from_secs(60);
            if let Some(retry_after) = ra_hdr.as_deref() {
                if let Ok(secs) = retry_after.trim().parse::<u64>() {
                    cooldown = Duration::from_secs(secs.clamp(1, 3600));
                }
            } else if let Some(reset) = res_hdr.as_deref() {
                if let Ok(reset_epoch) = reset.trim().parse::<i64>() {
                    let now_epoch = Utc::now().timestamp();
                    if reset_epoch > now_epoch {
                        let diff = (reset_epoch - now_epoch) as u64;
                        cooldown = Duration::from_secs(diff.clamp(1, 3600));
                    }
                }
            }

            if let Some(ref res_b) = rb_hdr {
                record_github_api_rate_limit(github_api_base, res_b, cooldown);
            }
            record_github_api_rate_limit(github_api_base, "releases", cooldown);
            record_github_api_rate_limit(github_api_base, "tags", cooldown);
            record_github_api_rate_limit(github_api_base, "commits", cooldown);
            record_github_api_rate_limit(github_api_base, "core", cooldown);
            record_github_api_rate_limit(github_api_base, "default", cooldown);

            anyhow::bail!("GitHub API rate limit exceeded for {clean_repo} (status {status_code})");
        }

        if !status.is_success() {
            if page_count > 1 {
                anyhow::bail!("GitHub API returned {} on page {}", status, page_count);
            }
            anyhow::bail!("GitHub API returned {}", status);
        }

        let page_releases: Vec<GitHubReleaseResponse> =
            match serde_json::from_slice::<Vec<GitHubReleaseResponse>>(&body_bytes) {
                Ok(list) => list,
                Err(_) => {
                    let single = serde_json::from_slice::<GitHubReleaseResponse>(&body_bytes)
                        .map_err(|e| anyhow::anyhow!("decode GitHub releases: {}", e))?;
                    vec![single]
                }
            };

        let page_len = page_releases.len();
        all_releases.extend(page_releases);

        let next_from_link = link_hdr.as_deref().and_then(parse_github_link_next_url);
        let has_another_page = next_from_link.is_some() || page_len >= GITHUB_RELEASE_PAGE_SIZE;
        if page_count >= MAX_RELEASE_PAGES && has_another_page {
            anyhow::bail!(
                "GitHub release pagination exceeded maximum page limit ({}) for '{}'; refusing to cache incomplete release set",
                MAX_RELEASE_PAGES,
                clean_repo
            );
        }

        if let Some(next_url) = next_from_link {
            if let Some(request_url) =
                github_releases_next_request_url(&next_url, github_api_base, clean_repo)
            {
                current_url = request_url;
                continue;
            }
            anyhow::bail!(
                "Untrusted or cross-repository GitHub pagination Link URL '{}' for '{}'",
                sanitize_git_remote_url_for_display(&next_url),
                clean_repo
            );
        }

        if page_len >= GITHUB_RELEASE_PAGE_SIZE {
            current_url = format!(
                "{}/repos/{}/releases?per_page={GITHUB_RELEASE_PAGE_SIZE}&page={}",
                github_api_base.trim_end_matches('/'),
                clean_repo,
                page_count + 1
            );
        } else {
            break;
        }
    }

    let mut best_candidate: Option<(String, String, bool)> = None;
    for rel in all_releases {
        if rel.draft {
            continue;
        }
        if is_stable && rel.prerelease {
            continue;
        }
        let mut version = extract_version(&rel.tag_name, "");
        if version.is_empty() {
            let normalized_tag = af_release::lifecycle::normalize_version(&rel.tag_name);
            version = extract_version(normalized_tag, "");
        }
        if version.is_empty() {
            continue;
        }

        if !tag_allowed_by_channel_for_source(&version, effective_channel, "github")
            || !tag_allowed_by_channel_for_source(&rel.tag_name, effective_channel, "github")
        {
            continue;
        }

        let is_pre =
            rel.prerelease || !tag_allowed_by_channel_for_source(&rel.tag_name, "stable", "github");
        match &best_candidate {
            None => {
                best_candidate = Some((version, rel.html_url, is_pre));
            }
            Some((current_ver, _, current_is_pre)) => {
                let ord = af_release::lifecycle::compare_versions(&version, current_ver);
                let should_replace = match ord {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Equal => {
                        effective_channel == "prerelease" && is_pre && !*current_is_pre
                    }
                    std::cmp::Ordering::Less => false,
                };
                if should_replace {
                    best_candidate = Some((version, rel.html_url, is_pre));
                }
            }
        }
    }

    let Some((version, html_url, _)) = best_candidate else {
        anyhow::bail!(
            "No eligible GitHub release found for repo '{}' on channel '{}'",
            clean_repo,
            effective_channel
        );
    };

    let result = (
        af_release::lifecycle::sanitize_persisted_lifecycle_text(&version),
        sanitize_git_remote_url_for_display(&html_url),
    );
    let now_rfc3339 = Utc::now().to_rfc3339();
    if let Ok(mut cache) = GITHUB_RELEASE_CACHE.lock() {
        cache.insert(
            cache_key.clone(),
            (
                result.0.clone(),
                result.1.clone(),
                Instant::now(),
                now_rfc3339.clone(),
            ),
        );
    }
    Ok((result.0, result.1, now_rfc3339))
}

pub fn normalize_tag_or_version_prefix(raw: &str) -> &str {
    let mut s = raw.trim();
    loop {
        if let Some(rest) = s.strip_prefix("release-v") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("release-") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix("release/") {
            s = rest;
        } else if let Some(rest) = s.strip_prefix('v') {
            s = rest;
        } else if let Some(rest) = s.strip_prefix('V') {
            s = rest;
        } else {
            break;
        }
    }
    s
}

pub fn is_prerelease_version_for_channel(version_or_tag: &str) -> bool {
    af_release::lifecycle::is_prerelease_version_for_channel(version_or_tag)
}

pub fn tag_allowed_by_channel_for_source(
    version_or_tag: &str,
    channel: &str,
    update_source: &str,
) -> bool {
    let effective_channel_owned = {
        let t = channel.trim().to_ascii_lowercase();
        if t.is_empty() {
            "stable".to_string()
        } else {
            t
        }
    };
    let effective_channel = effective_channel_owned.as_str();

    let is_pre = af_release::lifecycle::is_prerelease_version_for_channel_with_source(
        version_or_tag,
        if update_source.trim().is_empty() {
            None
        } else {
            Some(update_source)
        },
    );

    if effective_channel == "stable" {
        return !is_pre;
    }
    if !is_pre {
        return true;
    }
    let lower = version_or_tag.to_ascii_lowercase();
    match effective_channel {
        "rc" => lower.contains("rc"),
        "beta" => lower.contains("beta") || lower.contains("rc"),
        "alpha" => lower.contains("alpha") || lower.contains("beta") || lower.contains("rc"),
        "nightly" => true,
        "prerelease" | "edge" | "all" => true,
        _ => lower.contains(effective_channel),
    }
}

pub fn tag_allowed_by_channel(version_or_tag: &str, channel: &str) -> bool {
    tag_allowed_by_channel_for_source(version_or_tag, channel, "")
}

pub async fn detect_latest_git_tag_for_channel(
    repo_url: &str,
    repo: &str,
    channel: &str,
) -> anyhow::Result<(String, String, String)> {
    let clean_repo_url = if !repo_url.trim().is_empty() {
        repo_url.trim().to_string()
    } else if !repo.trim().is_empty() {
        format!("https://github.com/{}.git", repo.trim())
    } else {
        anyhow::bail!("missing repository URL");
    };

    let mut command = Command::new("git");
    command.args(["ls-remote", "--tags", "--refs", clean_repo_url.trim()]);
    let out = update_probe_output(command, Duration::from_secs(20)).await?;

    if !out.status.success() {
        anyhow::bail!(
            "git ls-remote failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut best_allowed = String::new();
    let mut tag_count = 0usize;
    for line in stdout.lines() {
        if !line.contains("refs/tags/") {
            continue;
        }
        let Some(idx) = line.rfind('/') else {
            continue;
        };
        let ref_name = line[idx + 1..].trim();
        let mut version = extract_version(ref_name, "");
        if version.is_empty() {
            let normalized = af_release::lifecycle::normalize_version(ref_name);
            version = extract_version(normalized, "");
        }
        if version.is_empty() {
            continue;
        }
        tag_count += 1;
        if tag_allowed_by_channel_for_source(ref_name, channel, "git")
            && tag_allowed_by_channel_for_source(&version, channel, "git")
            && (best_allowed.is_empty() || is_remote_version_newer(&best_allowed, &version))
        {
            best_allowed = version;
        }
    }

    let effective_channel = if channel.trim().is_empty() {
        "stable"
    } else {
        channel.trim()
    };

    if best_allowed.is_empty() {
        if tag_count == 0
            && (repo.trim() == "ccf-2012/seedcross"
                || clean_repo_url.contains("ccf-2012/seedcross"))
        {
            return detect_latest_git_head(&clean_repo_url, repo).await;
        }
        if tag_count > 0 {
            anyhow::bail!(
                "No stable release tags found for {} on channel {}",
                repo_url,
                effective_channel
            );
        }
        anyhow::bail!("no tags discovered");
    }

    let sanitized_repo_url = sanitize_git_remote_url_for_display(&clean_repo_url);
    let mut display_url = sanitized_repo_url
        .trim()
        .trim_end_matches(".git")
        .to_string();
    if display_url.is_empty() && !repo.trim().is_empty() {
        display_url = format!("https://github.com/{}", repo.trim());
    }

    Ok((
        best_allowed,
        af_release::lifecycle::sanitize_persisted_lifecycle_text(&format!(
            "{}/releases",
            display_url
        )),
        Utc::now().to_rfc3339(),
    ))
}

pub async fn detect_latest_git_tag(
    repo_url: &str,
    repo: &str,
) -> anyhow::Result<(String, String, String)> {
    detect_latest_git_tag_for_channel(repo_url, repo, "stable").await
}

pub fn strip_trailing_version_punctuation(s: &str) -> &str {
    let mut trimmed = s.trim_end_matches(|c: char| {
        c == '.'
            || c == ','
            || c == ';'
            || c == ':'
            || c == ')'
            || c == ']'
            || c == '}'
            || c == '"'
            || c == '\''
    });
    if trimmed.ends_with('+') {
        trimmed = trimmed[..trimmed.len() - 1].trim_end_matches(|c: char| {
            c == '.'
                || c == ','
                || c == ';'
                || c == ':'
                || c == ')'
                || c == ']'
                || c == '}'
                || c == '"'
                || c == '\''
        });
    }
    if trimmed.ends_with('-') {
        let prefix = &trimmed[..trimmed.len() - 1];
        if !prefix.contains('-') && !prefix.contains('+') && !prefix.contains('~') {
            trimmed = prefix.trim_end_matches(|c: char| {
                c == '.'
                    || c == ','
                    || c == ';'
                    || c == ':'
                    || c == ')'
                    || c == ']'
                    || c == '}'
                    || c == '"'
                    || c == '\''
            });
        }
    }
    trimmed
}

pub fn extract_version_from_text(raw: &str) -> String {
    extract_version(raw, "")
}

pub fn extract_version(raw: &str, custom_expr: &str) -> String {
    let text = raw.trim();
    if text.is_empty() {
        return String::new();
    }

    for line in text.lines() {
        let line_trim = line.trim();
        if let Some(map) = parse_component_manifest(line_trim) {
            return normalize_component_manifest(&map);
        }
    }

    let norm_text = af_release::lifecycle::normalize_version(text);

    if !custom_expr.trim().is_empty() {
        if let Ok(re) = Regex::new(custom_expr) {
            if let Some(caps) = re.captures(text) {
                if let Some(m) = caps.get(1) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
                if let Some(m) = caps.get(0) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
            }
            if let Some(caps) = re.captures(norm_text) {
                if let Some(m) = caps.get(1) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
                if let Some(m) = caps.get(0) {
                    let s = strip_trailing_version_punctuation(m.as_str().trim());
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
            }
        }
    }

    if let Some(caps) = SYNTHETIC_COMMIT_VERSION_RE.captures(text) {
        if let Some(m) = caps.get(0) {
            let s = m.as_str().trim();
            let clean = s
                .strip_prefix('v')
                .or_else(|| s.strip_prefix('V'))
                .unwrap_or(s);
            return clean.to_string();
        }
    }
    if let Some(caps) = SYNTHETIC_COMMIT_VERSION_RE.captures(norm_text) {
        if let Some(m) = caps.get(0) {
            let s = m.as_str().trim();
            let clean = s
                .strip_prefix('v')
                .or_else(|| s.strip_prefix('V'))
                .unwrap_or(s);
            return clean.to_string();
        }
    }

    let clean_text = text
        .strip_prefix('v')
        .or_else(|| text.strip_prefix('V'))
        .unwrap_or(text);
    if is_git_commit_sha(clean_text) {
        return clean_text.to_string();
    }

    let clean_norm = norm_text
        .strip_prefix('v')
        .or_else(|| norm_text.strip_prefix('V'))
        .unwrap_or(norm_text);
    if is_git_commit_sha(clean_norm) {
        return clean_norm.to_string();
    }

    if let Some(caps) = DOTTED_VERSION_RE.captures(text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    if let Some(caps) = DOTTED_VERSION_RE.captures(norm_text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }

    for token in text.split_whitespace().chain(norm_text.split_whitespace()) {
        let trimmed_token = token.trim_matches(|c: char| {
            c == '(' || c == ')' || c == '[' || c == ']' || c == '"' || c == '\'' || c == ','
        });
        let clean = trimmed_token
            .strip_prefix('v')
            .or_else(|| trimmed_token.strip_prefix('V'))
            .unwrap_or(trimmed_token);
        if is_git_commit_sha(clean) {
            return clean.to_string();
        }
    }

    if let Some(caps) = DEFAULT_VERSION_RE.captures(text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
        if let Some(m) = caps.get(0) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    if let Some(caps) = DEFAULT_VERSION_RE.captures(norm_text) {
        if let Some(m) = caps.get(1) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
        if let Some(m) = caps.get(0) {
            let s = strip_trailing_version_punctuation(m.as_str().trim());
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }

    String::new()
}

pub(super) fn parse_git_head(output: &str) -> anyhow::Result<String> {
    let head = output.split_whitespace().next().unwrap_or_default();
    if !is_git_commit(head) {
        anyhow::bail!("invalid Git HEAD commit");
    }
    Ok(head.to_string())
}

pub(super) fn is_git_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn dpkg_char_order(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(b) if b.is_ascii_alphabetic() => b as i32,
        Some(b) => (b as i32) + 256,
    }
}

pub fn dpkg_verrevcmp(a: &str, b: &str) -> std::cmp::Ordering {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut i = 0;
    let mut j = 0;

    while i < ab.len() || j < bb.len() {
        while (i < ab.len() && !ab[i].is_ascii_digit()) || (j < bb.len() && !bb[j].is_ascii_digit())
        {
            let ac = if i < ab.len() && !ab[i].is_ascii_digit() {
                Some(ab[i])
            } else {
                None
            };
            let bc = if j < bb.len() && !bb[j].is_ascii_digit() {
                Some(bb[j])
            } else {
                None
            };
            let ord = dpkg_char_order(ac).cmp(&dpkg_char_order(bc));
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
            if ac.is_some() {
                i += 1;
            }
            if bc.is_some() {
                j += 1;
            }
        }

        while i < ab.len() && ab[i] == b'0' {
            i += 1;
        }
        while j < bb.len() && bb[j] == b'0' {
            j += 1;
        }

        let i_start = i;
        while i < ab.len() && ab[i].is_ascii_digit() {
            i += 1;
        }
        let j_start = j;
        while j < bb.len() && bb[j].is_ascii_digit() {
            j += 1;
        }

        let a_len = i - i_start;
        let b_len = j - j_start;
        if a_len != b_len {
            return a_len.cmp(&b_len);
        }

        let ord = ab[i_start..i].cmp(&bb[j_start..j]);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }

    std::cmp::Ordering::Equal
}

pub(super) fn parse_debian_version(raw: &str) -> (u64, &str, &str) {
    let mut s = raw.trim();
    if !s.starts_with(|c: char| c.is_ascii_digit()) {
        s = normalize_tag_or_version_prefix(s);
    }
    let (epoch, remainder) = if let Some((ep, rem)) = s.split_once(':') {
        if !ep.is_empty() && ep.bytes().all(|b| b.is_ascii_digit()) {
            (ep.parse::<u64>().unwrap_or(0), rem)
        } else {
            (0, s)
        }
    } else {
        (0, s)
    };
    let (upstream, debian_revision) = if let Some((up, rev)) = remainder.rsplit_once('-') {
        (up, rev)
    } else {
        (remainder, "")
    };
    (epoch, upstream, debian_revision)
}

pub fn compare_debian_versions_str(a: &str, b: &str) -> std::cmp::Ordering {
    let (a_epoch, a_up, a_rev) = parse_debian_version(a);
    let (b_epoch, b_up, b_rev) = parse_debian_version(b);

    if a_epoch != b_epoch {
        return a_epoch.cmp(&b_epoch);
    }

    let up_ord = dpkg_verrevcmp(a_up, b_up);
    if up_ord != std::cmp::Ordering::Equal {
        return up_ord;
    }

    dpkg_verrevcmp(a_rev, b_rev)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SemverVersion {
    epoch: u64,
    segments: Vec<u64>,
    prerelease: Option<Vec<PrereleaseIdentifier>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PrereleaseIdentifier {
    Numeric(String),
    Alpha(String),
}

pub(super) fn parse_semver(raw: &str) -> Option<SemverVersion> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // In SemVer mode, strip build metadata (+...)
    let s_no_build = match s.split_once('+') {
        Some((v, _)) => v.trim(),
        None => s,
    };
    let norm = af_release::lifecycle::normalize_version(s_no_build);
    if norm.is_empty() {
        return None;
    }

    let (epoch, rest) = if let Some((ep, rem)) = norm.split_once(':') {
        if !ep.is_empty() && ep.bytes().all(|b| b.is_ascii_digit()) {
            (ep.parse::<u64>().ok()?, rem)
        } else {
            (0, norm)
        }
    } else {
        (0, norm)
    };

    if rest.is_empty() || !rest.bytes().any(|b| b.is_ascii_digit()) {
        return None;
    }

    let (normal_str, prerelease_opt) = match rest.find(['-', '~']) {
        Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
        None => (rest, None),
    };

    let mut segments = Vec::new();
    for seg in normal_str.split('.') {
        let seg_trim = seg.trim();
        if seg_trim.is_empty() || !seg_trim.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        segments.push(seg_trim.parse::<u64>().ok()?);
    }
    if segments.is_empty() {
        return None;
    }

    let prerelease = match prerelease_opt {
        Some(pre) if !pre.trim().is_empty() => {
            let mut ids = Vec::new();
            for part in pre.trim().split('.') {
                let part_trim = part.trim();
                if part_trim.is_empty() {
                    continue;
                }
                if part_trim.bytes().all(|b| b.is_ascii_digit()) {
                    let canonical = part_trim.trim_start_matches('0');
                    let canonical = if canonical.is_empty() { "0" } else { canonical };
                    ids.push(PrereleaseIdentifier::Numeric(canonical.to_string()));
                } else {
                    ids.push(PrereleaseIdentifier::Alpha(part_trim.to_string()));
                }
            }
            if ids.is_empty() {
                None
            } else {
                Some(ids)
            }
        }
        _ => None,
    };

    Some(SemverVersion {
        epoch,
        segments,
        prerelease,
    })
}

pub(super) fn compare_semver_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let (Some(sa), Some(sb)) = (parse_semver(a), parse_semver(b)) else {
        let a_norm = af_release::lifecycle::normalize_version(a);
        let b_norm = af_release::lifecycle::normalize_version(b);
        return dpkg_verrevcmp(a_norm, b_norm);
    };

    if sa.epoch != sb.epoch {
        return sa.epoch.cmp(&sb.epoch);
    }

    let max_len = sa.segments.len().max(sb.segments.len());
    for i in 0..max_len {
        let seg_a = sa.segments.get(i).copied().unwrap_or(0);
        let seg_b = sb.segments.get(i).copied().unwrap_or(0);
        let ord = seg_a.cmp(&seg_b);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }

    match (&sa.prerelease, &sb.prerelease) {
        (None, None) => std::cmp::Ordering::Equal,
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(ids_a), Some(ids_b)) => {
            for (id_a, id_b) in ids_a.iter().zip(ids_b.iter()) {
                let ord = match (id_a, id_b) {
                    (PrereleaseIdentifier::Numeric(na), PrereleaseIdentifier::Numeric(nb)) => {
                        na.len().cmp(&nb.len()).then_with(|| na.cmp(nb))
                    }
                    (PrereleaseIdentifier::Numeric(_), PrereleaseIdentifier::Alpha(_)) => {
                        std::cmp::Ordering::Less
                    }
                    (PrereleaseIdentifier::Alpha(_), PrereleaseIdentifier::Numeric(_)) => {
                        std::cmp::Ordering::Greater
                    }
                    (PrereleaseIdentifier::Alpha(sa), PrereleaseIdentifier::Alpha(sb)) => {
                        sa.cmp(sb)
                    }
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            ids_a.len().cmp(&ids_b.len())
        }
    }
}

pub fn is_newer_version(local: &str, remote: &str) -> bool {
    is_remote_version_newer(local, remote)
}

pub fn versions_match_target_internal(expected: &str, achieved: &str) -> bool {
    af_release::lifecycle::versions_match_target(achieved, expected)
}

/// Compares two version strings using Debian Policy (§5.6.12 `dpkg --compare-versions`),
/// SemVer prerelease ordering, git commit SHAs, synthetic commit versions, and component manifests.
pub fn is_remote_version_newer(local: &str, remote: &str) -> bool {
    is_remote_version_newer_for_source(local, remote, "")
}

pub fn is_remote_version_newer_for_source(local: &str, remote: &str, update_source: &str) -> bool {
    let l_trim = local.trim();
    let r_trim = remote.trim();

    // 1. Multi-component manifests (frontend:...,backend:...,proxy:...)
    let l_manifest = parse_component_manifest(l_trim);
    let r_manifest = parse_component_manifest(r_trim);

    if l_manifest.is_some() || r_manifest.is_some() {
        if let (Some(installed_map), Some(latest_map)) = (l_manifest.as_ref(), r_manifest.as_ref())
        {
            if latest_map.len() != installed_map.len() {
                return true;
            }
            for (comp, latest_val) in latest_map {
                let Some(inst_val) = installed_map.get(comp) else {
                    return true;
                };
                let is_hex_pair = (af_release::lifecycle::is_hex_digits_7_to_40(latest_val)
                    || af_release::lifecycle::is_hex_digits_7_to_40(
                        af_release::lifecycle::normalize_version(latest_val),
                    ))
                    && (af_release::lifecycle::is_hex_digits_7_to_40(inst_val)
                        || af_release::lifecycle::is_hex_digits_7_to_40(
                            af_release::lifecycle::normalize_version(inst_val),
                        ));
                if is_hex_pair {
                    if !af_release::lifecycle::commits_match_prefix(latest_val, inst_val, true) {
                        return true;
                    }
                } else {
                    if af_release::lifecycle::commits_match_prefix(latest_val, inst_val, false) {
                        continue;
                    }
                    if af_release::lifecycle::single_version_matches(inst_val, latest_val) {
                        continue;
                    }
                    if is_newer_version_scalar_for_source(inst_val, latest_val, update_source) {
                        return true;
                    }
                }
            }
            return false;
        } else if let Some(l_map) = l_manifest.as_ref() {
            let r_clean = af_release::lifecycle::normalize_version(r_trim);
            if is_git_commit_sha(r_clean) {
                if let Some(l_frontend) = l_map.get("frontend") {
                    return !af_release::lifecycle::commits_match_prefix(l_frontend, r_clean, true);
                }
            }
            return true;
        } else if let Some(r_map) = r_manifest.as_ref() {
            let l_clean = af_release::lifecycle::normalize_version(l_trim);
            if is_git_commit_sha(l_clean) {
                if let Some(r_frontend) = r_map.get("frontend") {
                    return !af_release::lifecycle::commits_match_prefix(l_clean, r_frontend, true);
                }
            }
            return true;
        }
    }

    is_newer_version_scalar_for_source(l_trim, r_trim, update_source)
}

pub fn is_version_newer_for_source(local: &str, remote: &str, update_source: &str) -> bool {
    is_remote_version_newer_for_source(local, remote, update_source)
}

pub fn is_newer_version_scalar(local: &str, remote: &str) -> bool {
    is_newer_version_scalar_for_source(local, remote, "")
}

pub fn is_newer_version_scalar_for_source(local: &str, remote: &str, update_source: &str) -> bool {
    let l_trim = local.trim();
    let r_trim = remote.trim();

    if r_trim.is_empty() || update_source.trim().eq_ignore_ascii_case("vendor") {
        return false;
    }

    if update_source == "apt" {
        return compare_debian_versions_str(l_trim, r_trim) == std::cmp::Ordering::Less;
    }

    let l_norm = af_release::lifecycle::normalize_version(local);
    let r_norm = af_release::lifecycle::normalize_version(remote);

    if l_norm == r_norm
        || (is_git_commit_sha(l_norm)
            && is_git_commit_sha(r_norm)
            && l_norm.eq_ignore_ascii_case(r_norm))
    {
        return false;
    }

    let is_commit_source = matches!(
        update_source.trim().to_ascii_lowercase().as_str(),
        "git" | "git_commit" | "git_head"
    );

    // 2. Synthetic commit versions (0.1.0-<sha>)
    let l_synth = parse_synthetic_commit_version(l_trim);
    let r_synth = parse_synthetic_commit_version(r_trim);

    if let Some((l_base, l_sha)) = l_synth {
        if let Some((r_base, r_sha)) = r_synth {
            if is_commit_source {
                match compare_semver_versions(l_base, r_base) {
                    std::cmp::Ordering::Less => return true,
                    std::cmp::Ordering::Greater => return false,
                    std::cmp::Ordering::Equal => {
                        return !af_release::lifecycle::commits_match_prefix(l_sha, r_sha, true);
                    }
                }
            }
        } else {
            let r_clean = af_release::lifecycle::normalize_version(r_trim);
            if !r_clean.contains('.') && is_git_commit_sha(r_clean) {
                return !af_release::lifecycle::commits_match_prefix(l_sha, r_clean, true);
            }
        }
    } else if let Some((_r_base, r_sha)) = r_synth {
        let l_clean = af_release::lifecycle::normalize_version(l_trim);
        if !l_clean.contains('.') && is_git_commit_sha(l_clean) {
            return !af_release::lifecycle::commits_match_prefix(l_clean, r_sha, true);
        }
    }

    // 3. Short & full git commit SHAs
    let l_clean = af_release::lifecycle::normalize_version(l_trim);
    let r_clean = af_release::lifecycle::normalize_version(r_trim);
    let l_is_hex_sha =
        af_release::lifecycle::is_hex_digits_7_to_40(l_clean) && !l_clean.contains('.');
    let r_is_hex_sha =
        af_release::lifecycle::is_hex_digits_7_to_40(r_clean) && !r_clean.contains('.');
    let l_is_sha = is_git_commit_sha(l_clean) && !l_clean.bytes().all(|b| b.is_ascii_digit());
    let r_is_sha = is_git_commit_sha(r_clean) && !r_clean.bytes().all(|b| b.is_ascii_digit());

    let both_all_digits =
        l_clean.bytes().all(|b| b.is_ascii_digit()) && r_clean.bytes().all(|b| b.is_ascii_digit());
    let unequal_digit_tags = both_all_digits
        && l_clean.len() != r_clean.len()
        && l_clean.len() != 40
        && r_clean.len() != 40;

    if l_is_hex_sha
        && r_is_hex_sha
        && !unequal_digit_tags
        && (is_commit_source || l_is_sha || r_is_sha)
    {
        return !af_release::lifecycle::commits_match_prefix(l_clean, r_clean, true);
    }

    // Untagged branch SHA installed on a release-tag-tracked package
    if l_is_sha && !r_is_sha && parse_semver(r_trim).is_some() {
        return true;
    }

    compare_semver_versions(l_trim, r_trim) == std::cmp::Ordering::Less
}

pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    compare_versions_for_source(a, b, "")
}

pub fn compare_versions_for_source(a: &str, b: &str, update_source: &str) -> std::cmp::Ordering {
    if update_source == "apt" {
        return compare_debian_versions_str(a, b);
    }

    let a_norm = af_release::lifecycle::normalize_version(a);
    let b_norm = af_release::lifecycle::normalize_version(b);
    if a_norm == b_norm
        || (is_git_commit_sha(a_norm)
            && is_git_commit_sha(b_norm)
            && a_norm.eq_ignore_ascii_case(b_norm))
    {
        return std::cmp::Ordering::Equal;
    }

    if af_release::lifecycle::commits_match_prefix(a_norm, b_norm, false) {
        return std::cmp::Ordering::Equal;
    }
    if is_git_commit_sha(a_norm)
        && is_git_commit_sha(b_norm)
        && !(a_norm.bytes().all(|b| b.is_ascii_digit())
            && b_norm.bytes().all(|b| b.is_ascii_digit()))
    {
        return a_norm
            .to_ascii_lowercase()
            .cmp(&b_norm.to_ascii_lowercase());
    }

    compare_semver_versions(a, b)
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

pub(super) fn persist_and_cache_package_update(record: &PackageUpdateRecord) -> bool {
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
