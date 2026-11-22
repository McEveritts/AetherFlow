use super::*;

#[derive(Debug, Deserialize)]
struct GitHubReleaseAsset {
    #[serde(default)]
    name: String,
    #[serde(default)]
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubReleaseResponse {
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<GitHubReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct PyPiInfo {
    #[serde(default)]
    version: String,
    #[serde(default)]
    project_urls: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct PyPiResponse {
    info: PyPiInfo,
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

pub(super) fn normalize_update_channel(channel: &str) -> String {
    let trimmed = channel.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        "stable".to_string()
    } else {
        trimmed
    }
}

pub(super) fn resolve_git_remote_url(repo_url: &str, repo: &str) -> Option<String> {
    let url = repo_url.trim();
    if !url.is_empty() {
        return Some(url.to_string());
    }
    let slug = repo.trim();
    if !slug.is_empty() {
        return Some(format!("https://github.com/{slug}.git"));
    }
    None
}

fn extract_version_or_normalized(raw: &str) -> String {
    let version = extract_version(raw, "");
    if !version.is_empty() {
        return version;
    }
    extract_version(af_release::lifecycle::normalize_version(raw), "")
}

fn build_github_api_get_request(
    client: &reqwest::Client,
    url: &str,
    github_api_base: &str,
) -> reqwest::RequestBuilder {
    let mut req = client
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "AetherFlow-Updater");
    if is_trusted_github_api_url(url, github_api_base) {
        if let Ok(token) = env::var("AF_GITHUB_TOKEN").or_else(|_| env::var("GITHUB_TOKEN")) {
            let trimmed = token.trim();
            if !trimmed.is_empty() {
                req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {trimmed}"));
            }
        }
    }
    req
}

fn check_github_rate_limit_response(
    github_api_base: &str,
    clean_repo: &str,
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    body_bytes: &[u8],
) -> anyhow::Result<()> {
    let rem_zero = headers
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false);
    let ra_hdr = headers.get("retry-after").and_then(|v| v.to_str().ok());
    let res_hdr = headers
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok());
    let rb_hdr = headers
        .get("x-ratelimit-resource")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let body_lower = String::from_utf8_lossy(body_bytes).to_ascii_lowercase();
    let has_rate_limit = body_lower.contains("rate limit")
        || body_lower.contains("secondary rate limit")
        || body_lower.contains("abuse detection")
        || body_lower.contains("too many requests");

    let is_rate_limit_resp = status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || (status == reqwest::StatusCode::FORBIDDEN
            && (rem_zero || ra_hdr.is_some() || has_rate_limit));

    if !is_rate_limit_resp {
        return Ok(());
    }

    let mut cooldown = Duration::from_secs(60);
    if let Some(retry_after) = ra_hdr {
        if let Ok(secs) = retry_after.trim().parse::<u64>() {
            cooldown = Duration::from_secs(secs.clamp(1, 3600));
        }
    } else if let Some(reset) = res_hdr {
        if let Ok(reset_epoch) = reset.trim().parse::<i64>() {
            let now_epoch = Utc::now().timestamp();
            if reset_epoch > now_epoch {
                let diff = (reset_epoch - now_epoch) as u64;
                cooldown = Duration::from_secs(diff.clamp(1, 3600));
            }
        }
    }

    if let Some(res_b) = rb_hdr {
        record_github_api_rate_limit(github_api_base, res_b, cooldown);
    }
    for bucket in ["releases", "tags", "commits", "core", "default"] {
        record_github_api_rate_limit(github_api_base, bucket, cooldown);
    }

    anyhow::bail!(
        "GitHub API rate limit exceeded for {clean_repo} (status {})",
        status.as_u16()
    );
}

pub(in crate::workers) async fn detect_latest_version(
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
        "retired" | "legacy" | "pinned" => Ok((
            pkg.update_package.clone(),
            String::new(),
            Utc::now().to_rfc3339(),
        )),
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
            if pkg.name.eq_ignore_ascii_case("listenarr") {
                detect_latest_listenarr_release_for_arch(
                    client,
                    github_api_base,
                    &pkg.update_repo,
                    &pkg.update_channel,
                    env::consts::ARCH,
                )
                .await
            } else {
                detect_latest_github_release_for_channel(
                    client,
                    github_api_base,
                    &pkg.update_repo,
                    &pkg.update_channel,
                )
                .await
            }
        }
        "git_tags" | "git" | "git_commit" | "git_head" => {
            let repo_url =
                resolve_git_remote_url(&pkg.update_repo_url, &pkg.update_repo).unwrap_or_default();
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
    let url = resolve_git_remote_url(repo_url, repo)
        .ok_or_else(|| anyhow::anyhow!("missing repository URL"))?;

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

pub(in crate::workers) async fn detect_latest_apt_version(
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
    if let Some(candidate) = af_release::lifecycle::parse_apt_policy_candidate(&stdout) {
        let version = candidate.trim();
        if af_release::lifecycle::validate_exact_apt_version(version) {
            return Ok((version.to_string(), String::new(), Utc::now().to_rfc3339()));
        }
        anyhow::bail!(
            "apt-cache policy returned invalid Debian candidate version '{}' for '{}'",
            version,
            package_name
        );
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

pub(in crate::workers) fn parse_github_link_next_url(header_val: &str) -> Option<String> {
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

async fn fetch_github_releases_paginated(
    client: &reqwest::Client,
    github_api_base: &str,
    clean_repo: &str,
    allow_latest_fallback: bool,
) -> anyhow::Result<Vec<GitHubReleaseResponse>> {
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
        let resp = build_github_api_get_request(client, &current_url, github_api_base)
            .send()
            .await?;
        let status = resp.status();

        if page_count == 1 && status == reqwest::StatusCode::NOT_FOUND && allow_latest_fallback {
            let fb_url = format!(
                "{}/repos/{}/releases/latest",
                github_api_base.trim_end_matches('/'),
                clean_repo
            );
            let fb_resp = build_github_api_get_request(client, &fb_url, github_api_base)
                .send()
                .await?;
            let fb_status = fb_resp.status();
            let fb_headers = fb_resp.headers().clone();
            let fb_bytes = fb_resp.bytes().await?;
            check_github_rate_limit_response(
                github_api_base,
                clean_repo,
                fb_status,
                &fb_headers,
                &fb_bytes,
            )?;

            if !fb_status.is_success() {
                anyhow::bail!("GitHub API returned {}", fb_status);
            }

            if let Ok(single) = serde_json::from_slice::<GitHubReleaseResponse>(&fb_bytes) {
                all_releases.push(single);
            }
            break;
        }

        let headers = resp.headers().clone();
        let link_hdr = headers
            .get("link")
            .or_else(|| headers.get("Link"))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let body_bytes = resp.bytes().await?;
        check_github_rate_limit_response(
            github_api_base,
            clean_repo,
            status,
            &headers,
            &body_bytes,
        )?;

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

    Ok(all_releases)
}

/// Discovers the newest eligible official Listenarr release for `host_arch`.
/// Fails early before cache or network access on architectures without official assets
/// (currently Linux ARM64 and other non-x64 hosts), and requires each candidate release
/// to carry a single verified official archive asset matching the host architecture.
pub async fn detect_latest_listenarr_release_for_arch(
    client: &reqwest::Client,
    github_api_base: &str,
    repo: &str,
    channel: &str,
    host_arch: &str,
) -> anyhow::Result<(String, String, String)> {
    let asset_suffix = af_runner::listenarr_release_asset_suffix_for_arch(host_arch)
        .map_err(anyhow::Error::msg)?;
    if repo.trim().is_empty() {
        anyhow::bail!("missing GitHub repo");
    }

    let clean_repo = repo.trim();
    let effective_channel_owned = normalize_update_channel(channel);
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

    if is_github_api_rate_limited(github_api_base, "releases") {
        anyhow::bail!("GitHub API rate limit backoff active for {clean_repo}");
    }

    let is_stable = effective_channel == "stable";
    let all_releases =
        fetch_github_releases_paginated(client, github_api_base, clean_repo, false).await?;

    let mut best_candidate: Option<(String, String, bool)> = None;
    for rel in all_releases {
        if rel.draft {
            continue;
        }
        if is_stable && rel.prerelease {
            continue;
        }
        let version = extract_version_or_normalized(&rel.tag_name);
        if version.is_empty() {
            continue;
        }
        if !tag_allowed_by_channel_for_source(&version, effective_channel, "github")
            || !tag_allowed_by_channel_for_source(&rel.tag_name, effective_channel, "github")
        {
            continue;
        }

        let has_checksum_companion = rel.assets.iter().any(|asset| {
            af_runner::listenarr_is_official_checksum_companion(
                &rel.tag_name,
                &asset.name,
                &asset.browser_download_url,
            )
        });
        let matching_assets: Vec<&GitHubReleaseAsset> = rel
            .assets
            .iter()
            .filter(|asset| asset.name.trim().ends_with(asset_suffix))
            .collect();
        if matching_assets.len() != 1 {
            continue;
        }
        let asset = matching_assets[0];
        if !af_runner::listenarr_release_asset_is_eligible(
            &rel.tag_name,
            &asset.name,
            &asset.browser_download_url,
            asset.digest.as_deref(),
            has_checksum_companion,
            asset_suffix,
        ) {
            continue;
        }

        let html_url = if rel.html_url.trim().is_empty() {
            format!(
                "https://github.com/{clean_repo}/releases/tag/{}",
                rel.tag_name.trim()
            )
        } else {
            rel.html_url
        };
        let is_pre =
            rel.prerelease || !tag_allowed_by_channel_for_source(&rel.tag_name, "stable", "github");
        match &best_candidate {
            None => {
                best_candidate = Some((version, html_url, is_pre));
            }
            Some((current_ver, _, current_is_pre)) => {
                let ord = af_release::lifecycle::compare_versions(&version, current_ver);
                let should_replace = match ord {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Equal => !is_pre && *current_is_pre,
                    std::cmp::Ordering::Less => false,
                };
                if should_replace {
                    best_candidate = Some((version, html_url, is_pre));
                }
            }
        }
    }

    let Some((version, html_url, _)) = best_candidate else {
        anyhow::bail!(
            "No eligible official Listenarr release found in '{}' on channel '{}' with a verified {} asset for host architecture '{}'",
            clean_repo,
            effective_channel,
            asset_suffix,
            host_arch.trim()
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
    let effective_channel_owned = normalize_update_channel(channel);
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
    let all_releases =
        fetch_github_releases_paginated(client, github_api_base, clean_repo, true).await?;

    let mut best_candidate: Option<(String, String, bool)> = None;
    for rel in all_releases {
        if rel.draft {
            continue;
        }
        if is_stable && rel.prerelease {
            continue;
        }
        let version = extract_version_or_normalized(&rel.tag_name);
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
    let effective_channel_owned = normalize_update_channel(channel);
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
    let clean_repo_url = resolve_git_remote_url(repo_url, repo)
        .ok_or_else(|| anyhow::anyhow!("missing repository URL"))?;

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
        let version = extract_version_or_normalized(ref_name);
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
