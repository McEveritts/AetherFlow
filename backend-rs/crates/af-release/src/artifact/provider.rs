use super::{
    is_v4_or_newer_release_tag, select_release_tag_from_json, verify_artifact_checksum,
    verify_release_provenance_with_token,
};
use crate::config::{ReleaseChannel, ReleaseConfig};
use crate::error::{ReleaseError, ReleaseResult};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Validates and extracts a `vX.Y.Z` tag from an effective `/releases/latest` redirect URL
/// (e.g. `https://github.com/McEveritts/AetherFlow/releases/tag/v3.2.7`), matching
/// `[[ "${latest_url}" == "https://github.com/${GITHUB_REPO}/releases/tag/"* && "${latest_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]`
/// in `deploy/release-manager.sh`.
pub fn parse_stable_tag_from_redirect_url(
    effective_url: &str,
    download_base: &str,
    github_repo: &str,
) -> ReleaseResult<String> {
    let trimmed_url = effective_url.trim().trim_end_matches('/');
    let expected_prefix = format!(
        "{}/{}/releases/tag/",
        download_base.trim_end_matches('/'),
        github_repo.trim_matches('/')
    );
    let Some(tag) = trimmed_url.strip_prefix(&expected_prefix) else {
        return Err(ReleaseError::TagResolution {
            channel: ReleaseChannel::Stable.to_string(),
            reason: format!(
                "latest release redirect URL {:?} did not match expected prefix {:?}",
                effective_url, expected_prefix
            ),
        });
    };
    if tag.contains('-') || !is_v4_or_newer_release_tag(tag) {
        return Err(ReleaseError::TagResolution {
            channel: ReleaseChannel::Stable.to_string(),
            reason: format!(
                "latest release redirect tag {:?} is not a strict v4+ stable semver tag",
                tag
            ),
        });
    }
    Ok(tag.to_string())
}

/// Resolves the latest stable tag (`vX.Y.Z`) by following `https://github.com/<repo>/releases/latest`
/// when the GitHub `/releases` API fails or is rate-limited.
pub fn resolve_stable_tag_from_latest_redirect(
    download_base: &str,
    github_repo: &str,
    timeout: Duration,
) -> ReleaseResult<String> {
    resolve_stable_tag_from_latest_redirect_with_token(download_base, github_repo, timeout, None)
}

fn resolve_stable_tag_from_latest_redirect_with_token(
    download_base: &str,
    github_repo: &str,
    timeout: Duration,
    github_token: Option<&str>,
) -> ReleaseResult<String> {
    let latest_url = format!(
        "{}/{}/releases/latest",
        download_base.trim_end_matches('/'),
        github_repo.trim_matches('/')
    );
    let effective = run_blocking_http_effective_url(&latest_url, timeout, github_token)?;
    parse_stable_tag_from_redirect_url(&effective, download_base, github_repo)
}

/// Trait abstracting release tag resolution and artifact fetching so unit/integration tests
/// can supply local tarballs and manifests without making live network calls or downloading executables.
pub trait ArtifactProvider: Send + Sync {
    /// Resolves the target release tag for `channel` (e.g., `"v4.0.0"`, `"nightly"`, `"experimental"`).
    fn resolve_release_tag(
        &self,
        config: &ReleaseConfig,
        channel: ReleaseChannel,
    ) -> ReleaseResult<String>;

    /// Fetches the release tarball (`artifact_name`) and `SHA256SUMS` manifest (`checksum_name`)
    /// for `tag` into `staging_dir`, returning `(archive_path, manifest_content)`.
    fn fetch_release_bundle(
        &self,
        config: &ReleaseConfig,
        channel: ReleaseChannel,
        tag: &str,
        staging_dir: &Path,
    ) -> ReleaseResult<(PathBuf, String)>;
}

/// Production HTTP(S) `ArtifactProvider` backed by `reqwest` against GitHub Releases.
#[derive(Debug, Clone, Default)]
pub struct GithubHttpArtifactProvider {
    pub api_base_url: Option<String>,
    pub download_base_url: Option<String>,
}

impl ArtifactProvider for GithubHttpArtifactProvider {
    fn resolve_release_tag(
        &self,
        config: &ReleaseConfig,
        channel: ReleaseChannel,
    ) -> ReleaseResult<String> {
        let base = self
            .api_base_url
            .as_deref()
            .unwrap_or("https://api.github.com");
        let url = format!(
            "{}/repos/{}/releases",
            base.trim_end_matches('/'),
            config.github_repo
        );

        let token = config.github_auth_token_str();
        let body =
            run_blocking_http_get_text(&url, Duration::from_secs(15), token).unwrap_or_default();
        match select_release_tag_from_json(channel, &body) {
            Ok(tag) => Ok(tag),
            Err(api_err) if channel == ReleaseChannel::Stable => {
                let download_base = self
                    .download_base_url
                    .as_deref()
                    .unwrap_or("https://github.com");
                resolve_stable_tag_from_latest_redirect_with_token(
                    download_base,
                    &config.github_repo,
                    Duration::from_secs(15),
                    token,
                )
                .map_err(|_| api_err)
            }
            Err(err) => Err(err),
        }
    }

    fn fetch_release_bundle(
        &self,
        config: &ReleaseConfig,
        channel: ReleaseChannel,
        tag: &str,
        staging_dir: &Path,
    ) -> ReleaseResult<(PathBuf, String)> {
        if !is_v4_or_newer_release_tag(tag) {
            return Err(ReleaseError::ArtifactVerification(format!(
                "Refusing unsupported or pre-v4 release tag {:?} (v4+ semver required).",
                tag
            )));
        }
        crate::fs_security::create_dir_all_no_symlinks(staging_dir, 0o700)?;
        let base = self
            .download_base_url
            .as_deref()
            .unwrap_or("https://github.com");
        let release_base = format!(
            "{}/{}/releases/download/{}",
            base.trim_end_matches('/'),
            config.github_repo,
            tag
        );

        let artifact_url = format!("{}/{}", release_base, config.artifact_name);
        let checksum_url = format!("{}/{}", release_base, config.checksum_name);

        let token = config.github_auth_token_str();
        let archive_dest = staging_dir.join(&config.artifact_name);
        run_blocking_http_download_to_file(
            &artifact_url,
            &archive_dest,
            0o600,
            Duration::from_secs(180),
            MAX_RELEASE_ARCHIVE_BYTES,
            token,
        )?;

        let manifest_content =
            run_blocking_http_get_text(&checksum_url, Duration::from_secs(30), token).map_err(
                |e| {
                    ReleaseError::ArtifactVerification(format!(
                "Missing SHA256SUMS manifest for release {} ({}). Refusing unverified binary.",
                tag, e
            ))
                },
            )?;
        let checksum_dest = staging_dir.join(&config.checksum_name);
        let _ = crate::fs_security::atomic_write_bytes_with_mode(
            &checksum_dest,
            manifest_content.as_bytes(),
            0o600,
        );

        let verified_digest =
            verify_artifact_checksum(&archive_dest, &manifest_content, &config.artifact_name)?;
        if config.skip_provenance_verify
            || std::env::var("AETHERFLOW_SKIP_PROVENANCE_VERIFY").as_deref() == Ok("1")
        {
            tracing::warn!(
                tag = %tag,
                artifact = %config.artifact_name,
                digest = %verified_digest,
                provenance_bypassed = true,
                "AETHERFLOW_SKIP_PROVENANCE_VERIFY=1 is set; bypassing Sigstore build provenance verification"
            );
        } else {
            let mut bundle_override = std::env::var_os("AETHERFLOW_PROVENANCE_BUNDLE_FILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from);
            if bundle_override.is_none() {
                let bundle_name = format!("{}.sigstore.json", config.artifact_name);
                let bundle_url = format!("{}/{}", release_base, bundle_name);
                let bundle_dest = staging_dir.join(&bundle_name);
                if run_blocking_http_download_to_file(
                    &bundle_url,
                    &bundle_dest,
                    0o600,
                    Duration::from_secs(30),
                    8 * 1024 * 1024,
                    token,
                )
                .is_ok()
                {
                    if let Ok(meta) = std::fs::symlink_metadata(&bundle_dest) {
                        if meta.is_file() && meta.len() > 0 {
                            bundle_override = Some(bundle_dest);
                        }
                    }
                }
            }
            verify_release_provenance_with_token(
                &config.github_repo,
                &verified_digest,
                &config.artifact_name,
                Some(tag),
                Some(channel),
                bundle_override.as_deref(),
                token,
            )?;
        }

        Ok((archive_dest, manifest_content))
    }
}

const MAX_RELEASE_TEXT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RELEASE_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn is_trusted_github_auth_url(url: &reqwest::Url) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    let Some(host) = url.host_str().map(|h| h.to_ascii_lowercase()) else {
        return false;
    };
    if host == "github.com" || host == "api.github.com" || host.ends_with(".githubusercontent.com")
    {
        return true;
    }
    if let Ok(ghe_base) = std::env::var("AETHERFLOW_GITHUB_API_BASE") {
        if let Ok(parsed_ghe) = reqwest::Url::parse(ghe_base.trim()) {
            if parsed_ghe.scheme() == "https"
                && parsed_ghe
                    .host_str()
                    .is_some_and(|gh_host| gh_host.eq_ignore_ascii_case(&host))
            {
                return true;
            }
        }
    }
    false
}

fn resolve_github_auth_token_for_url(url: &str, configured_token: Option<&str>) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if !is_trusted_github_auth_url(&parsed) {
        return None;
    }
    if let Some(tok) = configured_token.map(str::trim).filter(|t| !t.is_empty()) {
        return Some(tok.to_string());
    }
    for key in ["AF_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn build_release_http_client(
    initial_url: &str,
    timeout: Duration,
) -> ReleaseResult<reqwest::Client> {
    let require_https = initial_url
        .trim()
        .to_ascii_lowercase()
        .starts_with("https://");
    let redirect_policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 10 {
            return attempt.error("too many HTTP redirects");
        }
        if require_https && attempt.url().scheme() != "https" {
            return attempt.error("refusing downgrade redirect from HTTPS to non-HTTPS URL");
        }
        attempt.follow()
    });
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(redirect_policy)
        .user_agent("AetherFlow-ReleaseEngine/4.0");
    if require_https {
        builder = builder.https_only(true);
    }
    builder
        .build()
        .map_err(|e| ReleaseError::ArtifactVerification(format!("http client init: {}", e)))
}

fn run_blocking_http_effective_url(
    url: &str,
    timeout: Duration,
    configured_token: Option<&str>,
) -> ReleaseResult<String> {
    let url_owned = url.to_string();
    let token_opt = resolve_github_auth_token_for_url(&url_owned, configured_token);
    std::thread::spawn(move || -> ReleaseResult<String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                ReleaseError::ArtifactVerification(format!("tokio runtime init: {}", e))
            })?;
        rt.block_on(async move {
            let client = build_release_http_client(&url_owned, timeout)?;
            let mut req = client.get(&url_owned);
            if let Some(ref tok) = token_opt {
                req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", tok));
            }
            let resp = req.send().await.map_err(|e| {
                ReleaseError::ArtifactVerification(format!("GET {} failed: {}", url_owned, e))
            })?;
            if !resp.status().is_success() {
                return Err(ReleaseError::ArtifactVerification(format!(
                    "GET {} returned HTTP {}",
                    url_owned,
                    resp.status()
                )));
            }
            Ok(resp.url().as_str().to_string())
        })
    })
    .join()
    .map_err(|_| ReleaseError::ArtifactVerification("HTTP worker thread panicked".to_string()))?
}

fn run_blocking_http_get_text(
    url: &str,
    timeout: Duration,
    configured_token: Option<&str>,
) -> ReleaseResult<String> {
    let bytes =
        run_blocking_http_get_bytes_capped(url, timeout, MAX_RELEASE_TEXT_BYTES, configured_token)?;
    String::from_utf8(bytes).map_err(|e| {
        ReleaseError::ArtifactVerification(format!("invalid UTF-8 response from {}: {}", url, e))
    })
}

fn run_blocking_http_get_bytes_capped(
    url: &str,
    timeout: Duration,
    max_bytes: u64,
    configured_token: Option<&str>,
) -> ReleaseResult<Vec<u8>> {
    let url_owned = url.to_string();
    let token_opt = resolve_github_auth_token_for_url(&url_owned, configured_token);
    std::thread::spawn(move || -> ReleaseResult<Vec<u8>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                ReleaseError::ArtifactVerification(format!("tokio runtime init: {}", e))
            })?;
        rt.block_on(async move {
            let client = build_release_http_client(&url_owned, timeout)?;
            let mut req = client.get(&url_owned);
            if let Some(ref tok) = token_opt {
                req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", tok));
            }
            let mut resp = req.send().await.map_err(|e| {
                ReleaseError::ArtifactVerification(format!("GET {} failed: {}", url_owned, e))
            })?;
            if !resp.status().is_success() {
                return Err(ReleaseError::ArtifactVerification(format!(
                    "GET {} returned HTTP {}",
                    url_owned,
                    resp.status()
                )));
            }
            if let Some(len) = resp.content_length() {
                if len > max_bytes {
                    return Err(ReleaseError::ArtifactVerification(format!(
                        "Response from {} exceeds maximum allowed size ({} > {} bytes)",
                        url_owned, len, max_bytes
                    )));
                }
            }
            let mut buf = Vec::new();
            while let Some(chunk) = resp.chunk().await.map_err(|e| {
                ReleaseError::ArtifactVerification(format!(
                    "reading body from {}: {}",
                    url_owned, e
                ))
            })? {
                if (buf.len() as u64).saturating_add(chunk.len() as u64) > max_bytes {
                    return Err(ReleaseError::ArtifactVerification(format!(
                        "Response from {} exceeded maximum allowed size ({} bytes)",
                        url_owned, max_bytes
                    )));
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(buf)
        })
    })
    .join()
    .map_err(|_| ReleaseError::ArtifactVerification("HTTP worker thread panicked".to_string()))?
}

fn run_blocking_http_download_to_file(
    url: &str,
    dest_path: &Path,
    mode: u32,
    timeout: Duration,
    max_bytes: u64,
    configured_token: Option<&str>,
) -> ReleaseResult<()> {
    let url_owned = url.to_string();
    let dest_owned = dest_path.to_path_buf();
    let token_opt = resolve_github_auth_token_for_url(&url_owned, configured_token);
    std::thread::spawn(move || -> ReleaseResult<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                ReleaseError::ArtifactVerification(format!("tokio runtime init: {}", e))
            })?;
        rt.block_on(async move {
            let client = build_release_http_client(&url_owned, timeout)?;
            let mut req = client.get(&url_owned);
            if let Some(ref tok) = token_opt {
                req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", tok));
            }
            let mut resp = req.send().await.map_err(|e| {
                ReleaseError::ArtifactVerification(format!("GET {} failed: {}", url_owned, e))
            })?;
            if !resp.status().is_success() {
                return Err(ReleaseError::ArtifactVerification(format!(
                    "GET {} returned HTTP {}",
                    url_owned,
                    resp.status()
                )));
            }
            if let Some(len) = resp.content_length() {
                if len > max_bytes {
                    return Err(ReleaseError::ArtifactVerification(format!(
                        "Download from {} exceeds maximum allowed size ({} > {} bytes)",
                        url_owned, len, max_bytes
                    )));
                }
            }
            let tmp_path = dest_owned.with_extension(format!("part.{}", uuid::Uuid::new_v4()));
            let mut file = crate::fs_security::open_exclusive_private_file(&tmp_path, mode)?;
            let mut written: u64 = 0;
            let write_res: ReleaseResult<()> = async {
                while let Some(chunk) = resp.chunk().await.map_err(|e| {
                    ReleaseError::ArtifactVerification(format!(
                        "streaming body from {}: {}",
                        url_owned, e
                    ))
                })? {
                    written = written.saturating_add(chunk.len() as u64);
                    if written > max_bytes {
                        return Err(ReleaseError::ArtifactVerification(format!(
                            "Download from {} exceeded maximum allowed size ({} bytes)",
                            url_owned, max_bytes
                        )));
                    }
                    file.write_all(&chunk).map_err(|e| {
                        ReleaseError::io(format!("writing download {}", tmp_path.display()), e)
                    })?;
                }
                file.sync_all().map_err(|e| {
                    ReleaseError::io(format!("syncing download {}", tmp_path.display()), e)
                })?;
                Ok(())
            }
            .await;
            drop(file);
            if let Err(err) = write_res {
                let _ = fs::remove_file(&tmp_path);
                return Err(err);
            }
            crate::fs_security::ensure_no_symlink_ancestors(&dest_owned)?;
            if let Err(err) = fs::rename(&tmp_path, &dest_owned) {
                let _ = fs::remove_file(&tmp_path);
                return Err(ReleaseError::io(
                    format!("renaming download to {}", dest_owned.display()),
                    err,
                ));
            }
            Ok(())
        })
    })
    .join()
    .map_err(|_| ReleaseError::ArtifactVerification("HTTP worker thread panicked".to_string()))?
}
