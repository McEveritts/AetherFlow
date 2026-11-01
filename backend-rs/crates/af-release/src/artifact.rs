//! Stage 1: Release tag resolution, SHA-256 manifest verification, safe tarball extraction,
//! and offline dry-run artifact simulation.

use crate::config::{ReleaseChannel, ReleaseConfig};
use crate::error::{ReleaseError, ReleaseResult};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tar::{Archive, EntryType};

/// Subset of GitHub Releases API response item required for channel tag resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GitHubReleaseItem {
    #[serde(default)]
    pub tag_name: String,
    #[serde(default)]
    pub target_commitish: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
}

/// Resolves a release tag from a GitHub Releases JSON payload using the exact rules of
/// `resolve_release_tag` in `deploy/release-manager.sh`:
/// - `experimental`: first non-draft release where `tag == "experimental"`, `target_commitish == "experimental"`,
///   or `tag` contains `"experimental"` (case-insensitive). Falls back to `"experimental"`.
/// - `nightly`: first non-draft release where `tag` is not `"nightly"` or `"experimental"`,
///   `target_commitish != "experimental"`, `tag` does not contain `"experimental"`, and
///   (`target_commitish == "nightly"` OR `prerelease == true` OR `tag` contains `"nightly"`).
///   Falls back to `"nightly"`.
/// - `stable`: first non-draft, non-prerelease release where `tag` does not contain `'-'`
///   and `target_commitish != "nightly"`. Returns `Err` if none found or JSON is empty.
pub fn select_release_tag_from_json(
    channel: ReleaseChannel,
    releases_json: &str,
) -> ReleaseResult<String> {
    let trimmed = releases_json.trim();
    let parsed: Vec<GitHubReleaseItem> = if trimmed.is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(trimmed).unwrap_or_default()
    };

    match channel {
        ReleaseChannel::Experimental => {
            for r in &parsed {
                if r.draft {
                    continue;
                }
                let tag = r.tag_name.trim();
                let tag_lower = tag.to_ascii_lowercase();
                let target_lower = r.target_commitish.trim().to_ascii_lowercase();
                if !tag.is_empty()
                    && (tag_lower == "experimental"
                        || target_lower == "experimental"
                        || tag_lower.contains("experimental"))
                {
                    return Ok(tag.to_string());
                }
            }
            Ok("experimental".to_string())
        }
        ReleaseChannel::Nightly => {
            for r in &parsed {
                if r.draft {
                    continue;
                }
                let tag = r.tag_name.trim();
                let tag_lower = tag.to_ascii_lowercase();
                let target_lower = r.target_commitish.trim().to_ascii_lowercase();
                if !tag.is_empty()
                    && tag_lower != "nightly"
                    && tag_lower != "experimental"
                    && target_lower != "experimental"
                    && !tag_lower.contains("experimental")
                    && (target_lower == "nightly" || r.prerelease || tag_lower.contains("nightly"))
                {
                    return Ok(tag.to_string());
                }
            }
            Ok("nightly".to_string())
        }
        ReleaseChannel::Stable => {
            if trimmed.is_empty() {
                return Err(ReleaseError::TagResolution {
                    channel: channel.to_string(),
                    reason: "empty GitHub releases response".to_string(),
                });
            }
            for r in &parsed {
                if r.draft || r.prerelease {
                    continue;
                }
                let tag = r.tag_name.trim();
                let target_lower = r.target_commitish.trim().to_ascii_lowercase();
                if !tag.is_empty() && !tag.contains('-') && target_lower != "nightly" {
                    return Ok(tag.to_string());
                }
            }
            Err(ReleaseError::TagResolution {
                channel: channel.to_string(),
                reason: "no matching stable release tag found".to_string(),
            })
        }
    }
}

/// Parses a `SHA256SUMS` manifest and extracts the expected 64-hex-character lowercase digest
/// for `artifact_name` (matching `awk -v f="${ARTIFACT_NAME}" '$2 == f || $2 == "*"f {print tolower($1); exit}'`).
pub fn parse_sha256_manifest(manifest_content: &str, artifact_name: &str) -> ReleaseResult<String> {
    let starred = format!("*{}", artifact_name);
    for raw_line in manifest_content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(hash_raw) = parts.next() else {
            continue;
        };
        let Some(file_raw) = parts.next() else {
            continue;
        };
        if file_raw == artifact_name || file_raw == starred {
            let lower = hash_raw.to_ascii_lowercase();
            if lower.len() == 64 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok(lower);
            } else {
                return Err(ReleaseError::ArtifactVerification(format!(
                    "malformed SHA-256 digest {:?} for {}",
                    hash_raw, artifact_name
                )));
            }
        }
    }

    Err(ReleaseError::ArtifactVerification(format!(
        "artifact {:?} not found in SHA256SUMS manifest",
        artifact_name
    )))
}

/// Computes the lowercase hex SHA-256 digest of a file on disk.
pub fn compute_file_sha256(path: &Path) -> ReleaseResult<String> {
    let mut f = fs::File::open(path)
        .map_err(|e| ReleaseError::io(format!("opening {} for SHA-256", path.display()), e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| ReleaseError::io(format!("reading {} for SHA-256", path.display()), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Verifies that `archive_path` matches the SHA-256 digest recorded in `manifest_content` for `artifact_name`.
pub fn verify_artifact_checksum(
    archive_path: &Path,
    manifest_content: &str,
    artifact_name: &str,
) -> ReleaseResult<String> {
    let expected = parse_sha256_manifest(manifest_content, artifact_name)?;
    let actual = compute_file_sha256(archive_path)?;
    if actual != expected {
        return Err(ReleaseError::ChecksumMismatch {
            artifact: artifact_name.to_string(),
            expected,
            actual,
        });
    }
    Ok(actual)
}

/// Safely extracts a `.tar.gz` release archive into `release_dir` with strict Zip-Slip / path-traversal,
/// ancestor symlink, destination collision, and symlink/device-node rejection, then validates the
/// extracted `aetherflow-api` binary and `.version` stamp.
pub fn extract_and_validate_release_archive(
    archive_path: &Path,
    release_dir: &Path,
    tag: &str,
    config: &ReleaseConfig,
) -> ReleaseResult<()> {
    crate::fs_security::ensure_no_symlink_ancestors(archive_path)?;
    crate::fs_security::ensure_no_symlink_ancestors(release_dir)?;

    if fs::symlink_metadata(release_dir).is_ok() {
        let meta = fs::symlink_metadata(release_dir).map_err(|e| {
            ReleaseError::io(
                format!("stat release directory {}", release_dir.display()),
                e,
            )
        })?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(ReleaseError::ArchiveExtraction {
                archive: archive_path.to_path_buf(),
                reason: format!(
                    "release directory '{}' exists and is a symlink or non-directory",
                    release_dir.display()
                ),
            });
        }
        let mut existing = fs::read_dir(release_dir).map_err(|e| {
            ReleaseError::io(
                format!("reading release directory {}", release_dir.display()),
                e,
            )
        })?;
        if existing.next().is_some() {
            return Err(ReleaseError::ArchiveExtraction {
                archive: archive_path.to_path_buf(),
                reason: format!(
                    "refusing to extract into non-empty release directory '{}'",
                    release_dir.display()
                ),
            });
        }
    } else {
        crate::fs_security::create_new_dir_exclusive(release_dir, 0o755, 0o755)?;
    }

    let file = fs::File::open(archive_path).map_err(|e| {
        ReleaseError::ArchiveExtraction {
            archive: archive_path.to_path_buf(),
            reason: format!("failed to open archive: {}", e),
        }
    })?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    let entries = archive
        .entries()
        .map_err(|e| ReleaseError::ArchiveExtraction {
            archive: archive_path.to_path_buf(),
            reason: format!("invalid tar header stream: {}", e),
        })?;

    for entry_result in entries {
        let mut entry = entry_result.map_err(|e| ReleaseError::ArchiveExtraction {
            archive: archive_path.to_path_buf(),
            reason: format!("corrupt tar entry: {}", e),
        })?;

        let entry_path = entry
            .path()
            .map_err(|e| ReleaseError::ArchiveExtraction {
                archive: archive_path.to_path_buf(),
                reason: format!("invalid entry path encoding: {}", e),
            })?
            .into_owned();

        let rel_path = sanitize_archive_entry_path(&entry_path, archive_path)?;
        if rel_path.as_os_str().is_empty() {
            continue;
        }

        crate::fs_security::ensure_no_symlink_in_relative_chain(release_dir, &rel_path).map_err(
            |e| ReleaseError::ArchiveExtraction {
                archive: archive_path.to_path_buf(),
                reason: e.to_string(),
            },
        )?;

        let entry_type = entry.header().entry_type();
        match entry_type {
            EntryType::Directory => {
                let dest = release_dir.join(&rel_path);
                crate::fs_security::create_dir_all_no_symlinks(&dest, 0o755).map_err(|e| {
                    ReleaseError::ArchiveExtraction {
                        archive: archive_path.to_path_buf(),
                        reason: format!("failed to create directory {}: {}", dest.display(), e),
                    }
                })?;
            }
            EntryType::Regular | EntryType::Continuous => {
                let dest = release_dir.join(&rel_path);
                if let Some(parent) = dest.parent() {
                    crate::fs_security::create_dir_all_no_symlinks(parent, 0o755).map_err(|e| {
                        ReleaseError::ArchiveExtraction {
                            archive: archive_path.to_path_buf(),
                            reason: format!("failed to create parent {}: {}", parent.display(), e),
                        }
                    })?;
                }
                if fs::symlink_metadata(&dest).is_ok() {
                    return Err(ReleaseError::ArchiveExtraction {
                        archive: archive_path.to_path_buf(),
                        reason: format!(
                            "duplicate or pre-planted destination entry rejected: {}",
                            dest.display()
                        ),
                    });
                }
                let raw_mode = entry.header().mode().unwrap_or(0o644) & 0o777;
                let safe_mode = if raw_mode == 0 { 0o644 } else { raw_mode };
                let mut out_file = crate::fs_security::open_exclusive_private_file(&dest, safe_mode)
                    .map_err(|e| ReleaseError::ArchiveExtraction {
                        archive: archive_path.to_path_buf(),
                        reason: format!(
                            "failed to create exclusive file {}: {}",
                            dest.display(),
                            e
                        ),
                    })?;
                std::io::copy(&mut entry, &mut out_file).map_err(|e| {
                    ReleaseError::ArchiveExtraction {
                        archive: archive_path.to_path_buf(),
                        reason: format!("failed to extract {}: {}", dest.display(), e),
                    }
                })?;
                let _ = out_file.sync_all();
            }
            other => {
                return Err(ReleaseError::ArchiveExtraction {
                    archive: archive_path.to_path_buf(),
                    reason: format!(
                        "disallowed tar entry type {:?} for path '{}' (symlinks, hardlinks, and device nodes are rejected)",
                        other,
                        entry_path.display()
                    ),
                });
            }
        }
    }

    let binary_path = release_dir.join("aetherflow-api");
    let Ok(meta) = fs::symlink_metadata(&binary_path) else {
        return Err(ReleaseError::ArtifactVerification(
            "Release archive has no ./aetherflow-api. Refusing to continue.".to_string(),
        ));
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(ReleaseError::ArtifactVerification(
            "Release archive ./aetherflow-api is not a regular file. Refusing to continue."
                .to_string(),
        ));
    }
    if meta.len() == 0 {
        return Err(ReleaseError::ArtifactVerification(
            "Extracted ./aetherflow-api binary is 0 bytes. Refusing to continue.".to_string(),
        ));
    }

    set_executable_permission(&binary_path)?;

    let version_path = release_dir.join(".version");
    let has_non_empty_version = fs::symlink_metadata(&version_path)
        .map(|m| !m.file_type().is_symlink() && m.is_file() && m.len() > 0)
        .unwrap_or(false);
    if !has_non_empty_version {
        crate::fs_security::atomic_write_bytes_with_mode(
            &version_path,
            format!("{}\n", tag).as_bytes(),
            0o644,
        )?;
    }

    stage_running_release_manager(release_dir, config)?;
    Ok(())
}

/// Validates and normalizes an archive entry path, stripping leading `./` and rejecting
/// absolute paths, drive prefixes, or `..` traversal components.
fn sanitize_archive_entry_path(entry_path: &Path, archive_path: &Path) -> ReleaseResult<PathBuf> {
    let mut normalized = PathBuf::new();
    for comp in entry_path.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(part) => {
                let s = part.to_string_lossy();
                if s.contains('\0') {
                    return Err(ReleaseError::ArchiveExtraction {
                        archive: archive_path.to_path_buf(),
                        reason: format!("NUL byte in archive entry path '{}'", entry_path.display()),
                    });
                }
                normalized.push(part);
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ReleaseError::ArchiveExtraction {
                    archive: archive_path.to_path_buf(),
                    reason: format!(
                        "unsafe path traversal or absolute path in archive entry: '{}'",
                        entry_path.display()
                    ),
                });
            }
        }
    }
    Ok(normalized)
}

/// Stages the executing `release-manager.sh` and `release-manager.conf` into `${RELEASE_DIR}/deploy`
/// when configured, matching `stage_running_release_manager` in `deploy/release-manager.sh`.
pub fn stage_running_release_manager(
    release_dir: &Path,
    config: &ReleaseConfig,
) -> ReleaseResult<()> {
    crate::fs_security::ensure_no_symlink_ancestors(release_dir)?;
    let deploy_dir = release_dir.join("deploy");
    crate::fs_security::create_dir_all_no_symlinks(&deploy_dir, 0o755)?;

    if let Some(ref script_src) = config.stage_script_path {
        if script_src.is_file() {
            let dst = deploy_dir.join("release-manager.sh");
            crate::fs_security::atomic_copy_file_with_mode(script_src, &dst, 0o755, None)?;
            set_executable_permission(&dst)?;
        }
    }
    if let Some(ref conf_src) = config.stage_conf_path {
        if conf_src.is_file() {
            let dst = deploy_dir.join("release-manager.conf");
            crate::fs_security::atomic_copy_file_with_mode(conf_src, &dst, 0o644, None)?;
        }
    }
    Ok(())
}

/// Simulates an offline single-binary artifact extraction during `--dry-run --offline`,
/// matching `simulate_offline_artifact` in `deploy/release-manager.sh`.
pub fn simulate_offline_artifact(
    release_dir: &Path,
    config: &ReleaseConfig,
) -> ReleaseResult<String> {
    crate::fs_security::ensure_no_symlink_ancestors(release_dir)?;
    for sub in ["deploy/systemd", "packages", "config"] {
        let dir = release_dir.join(sub);
        crate::fs_security::create_dir_all_no_symlinks(&dir, 0o755)?;
    }
    let bin_path = release_dir.join("aetherflow-api");
    crate::fs_security::atomic_write_bytes_with_mode(&bin_path, b"#!/bin/bash\n", 0o755)?;
    set_executable_permission(&bin_path)?;

    let version_stamp = "v3.1.7-dryrun";
    let version_path = release_dir.join(".version");
    crate::fs_security::atomic_write_bytes_with_mode(
        &version_path,
        format!("{}\n", version_stamp).as_bytes(),
        0o644,
    )?;

    stage_running_release_manager(release_dir, config)?;
    Ok(version_stamp.to_string())
}

fn set_executable_permission(path: &Path) -> ReleaseResult<()> {
    crate::fs_security::ensure_no_symlink_ancestors(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(path)
            .map_err(|e| ReleaseError::io(format!("metadata {}", path.display()), e))?;
        if meta.file_type().is_symlink() {
            return Err(ReleaseError::PathValidation {
                path: path.to_path_buf(),
                reason: "refusing chmod +x on symlink".to_string(),
            });
        }
        let mut perms = meta.permissions();
        perms.set_mode(perms.mode() | 0o755);
        fs::set_permissions(path, perms)
            .map_err(|e| ReleaseError::io(format!("chmod +x {}", path.display()), e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
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

        let body = run_blocking_http_get_text(&url, Duration::from_secs(15)).unwrap_or_default();
        select_release_tag_from_json(channel, &body)
    }

    fn fetch_release_bundle(
        &self,
        config: &ReleaseConfig,
        tag: &str,
        staging_dir: &Path,
    ) -> ReleaseResult<(PathBuf, String)> {
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

        let archive_dest = staging_dir.join(&config.artifact_name);
        let artifact_bytes =
            run_blocking_http_get_bytes(&artifact_url, Duration::from_secs(180))?;
        crate::fs_security::atomic_write_bytes_with_mode(&archive_dest, &artifact_bytes, 0o600)?;

        let manifest_content =
            run_blocking_http_get_text(&checksum_url, Duration::from_secs(30)).map_err(|e| {
                ReleaseError::ArtifactVerification(format!(
                    "Missing SHA256SUMS manifest for release {} ({}). Refusing unverified binary.",
                    tag, e
                ))
            })?;
        let checksum_dest = staging_dir.join(&config.checksum_name);
        let _ = crate::fs_security::atomic_write_bytes_with_mode(
            &checksum_dest,
            manifest_content.as_bytes(),
            0o600,
        );

        Ok((archive_dest, manifest_content))
    }
}

fn run_blocking_http_get_text(url: &str, timeout: Duration) -> ReleaseResult<String> {
    let bytes = run_blocking_http_get_bytes(url, timeout)?;
    String::from_utf8(bytes).map_err(|e| {
        ReleaseError::ArtifactVerification(format!("invalid UTF-8 response from {}: {}", url, e))
    })
}

fn run_blocking_http_get_bytes(url: &str, timeout: Duration) -> ReleaseResult<Vec<u8>> {
    let url_owned = url.to_string();
    std::thread::spawn(move || -> ReleaseResult<Vec<u8>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| ReleaseError::ArtifactVerification(format!("tokio runtime init: {}", e)))?;
        rt.block_on(async move {
            let client = reqwest::Client::builder()
                .timeout(timeout)
                .user_agent("AetherFlow-ReleaseEngine/4.0")
                .build()
                .map_err(|e| ReleaseError::ArtifactVerification(format!("http client init: {}", e)))?;
            let resp = client.get(&url_owned).send().await.map_err(|e| {
                ReleaseError::ArtifactVerification(format!("GET {} failed: {}", url_owned, e))
            })?;
            if !resp.status().is_success() {
                return Err(ReleaseError::ArtifactVerification(format!(
                    "GET {} returned HTTP {}",
                    url_owned,
                    resp.status()
                )));
            }
            let bytes = resp.bytes().await.map_err(|e| {
                ReleaseError::ArtifactVerification(format!("reading body from {}: {}", url_owned, e))
            })?;
            Ok(bytes.to_vec())
        })
    })
    .join()
    .map_err(|_| ReleaseError::ArtifactVerification("HTTP worker thread panicked".to_string()))?
}
