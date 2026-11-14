//! Stage 1: Release tag resolution, SHA-256 manifest verification, safe tarball extraction,
//! and offline dry-run artifact simulation.

use crate::config::{ReleaseChannel, ReleaseConfig};
use crate::error::{ReleaseError, ReleaseResult};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tar::{Archive, EntryType};

const EMBEDDED_VERIFY_PROVENANCE_PY: &str =
    include_str!("../../../../deploy/verify-provenance.py");

const PROVENANCE_VERIFIER_TIMEOUT: Duration = Duration::from_secs(60);

/// Returns `true` iff `tag` is a canonical v4+ semver release tag
/// (`^v([4-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+([._-][A-Za-z0-9]+)*)?$`).
pub fn is_v4_or_newer_release_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix('v') else {
        return false;
    };
    let (core, prerelease) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    let Ok(major) = parts[0].parse::<u64>() else {
        return false;
    };
    if major < 4 || (parts[0].len() > 1 && parts[0].starts_with('0')) {
        return false;
    }
    if let Some(pre) = prerelease {
        if pre.is_empty() {
            return false;
        }
        for token in pre.split(['.', '_', '-']) {
            if token.is_empty() || !token.chars().all(|c| c.is_ascii_alphanumeric()) {
                return false;
            }
        }
    }
    true
}

/// Verifies cryptographic Sigstore + SLSA v1 GitHub Actions build provenance for `expected_digest`
/// using the embedded zero-PyPI stdlib+OpenSSL verifier (`deploy/verify-provenance.py`) inside an
/// isolated (`python3 -I -B`), environment-scrubbed subprocess with a strict 60-second timeout.
pub fn verify_release_provenance(
    github_repo: &str,
    expected_digest: &str,
    artifact_name: &str,
    expected_tag: Option<&str>,
    expected_channel: Option<ReleaseChannel>,
    bundle_file: Option<&Path>,
) -> ReleaseResult<()> {
    let mut cmd = Command::new("python3");
    cmd.env_clear();
    for key in [
        "PATH",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "SYSTEMROOT",
        "AF_GITHUB_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "AETHERFLOW_GITHUB_API_BASE",
    ] {
        if let Some(val) = std::env::var_os(key) {
            cmd.env(key, val);
        }
    }
    cmd.args([
        "-I",
        "-B",
        "-",
        "--repo",
        github_repo,
        "--digest",
        expected_digest,
        "--artifact-name",
        artifact_name,
    ]);
    if let Some(tag) = expected_tag {
        cmd.args(["--tag", tag]);
    }
    if let Some(ch) = expected_channel {
        cmd.args(["--channel", &ch.to_string()]);
    }
    if let Some(bf) = bundle_file {
        cmd.arg("--bundle-file").arg(bf);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| {
        ReleaseError::ArtifactVerification(format!(
            "failed to spawn python3 for Sigstore provenance verification: {}",
            e
        ))
    })?;
    if let Some(mut stdin) = child.stdin.take() {
        let feed_res = stdin.write_all(EMBEDDED_VERIFY_PROVENANCE_PY.as_bytes());
        drop(stdin);
        if let Err(e) = feed_res {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ReleaseError::ArtifactVerification(format!(
                "failed to feed embedded provenance verifier to python3: {}",
                e
            )));
        }
    }

    let stdout_handle = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_handle = child.stderr.take().map(|mut err| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err.read_to_end(&mut buf);
            buf
        })
    });

    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if start.elapsed() >= PROVENANCE_VERIFIER_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ReleaseError::ArtifactVerification(format!(
                        "Sigstore build provenance verifier timed out after {}s for {}",
                        PROVENANCE_VERIFIER_TIMEOUT.as_secs(),
                        artifact_name
                    )));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ReleaseError::ArtifactVerification(format!(
                    "waiting on Sigstore provenance verifier failed: {}",
                    e
                )));
            }
        }
    };

    let stdout_bytes = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stderr_bytes = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr_bytes).trim().to_string();
        let stdout = String::from_utf8_lossy(&stdout_bytes).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return Err(ReleaseError::ArtifactVerification(format!(
            "Sigstore build provenance verification failed for {} (sha256:{}): {}",
            artifact_name, expected_digest, detail
        )));
    }
    Ok(())
}

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

pub fn is_v4_nightly_release_tag(tag: &str) -> bool {
    let trimmed = tag.trim();
    if !is_v4_or_newer_release_tag(trimmed) {
        return false;
    }
    let Some((_, pre)) = trimmed.split_once('-') else {
        return false;
    };
    if pre.len() <= 8 || !pre[..8].eq_ignore_ascii_case("nightly.") {
        return false;
    }
    let rest = &pre[8..];
    let parts: Vec<&str> = rest.split('.').collect();
    (parts.len() == 1 || parts.len() == 2)
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

/// Resolves a v4+ release tag from a GitHub Releases JSON payload, failing closed when
/// the response is empty, malformed, or lacks an eligible v4+ release tag (preventing
/// implicit v3 downgrades or unverified `"nightly"` literal tag fallbacks).
pub fn select_release_tag_from_json(
    channel: ReleaseChannel,
    releases_json: &str,
) -> ReleaseResult<String> {
    let trimmed = releases_json.trim();
    if trimmed.is_empty() {
        return Err(ReleaseError::TagResolution {
            channel: channel.to_string(),
            reason: "empty GitHub releases response".to_string(),
        });
    }
    let parsed: Vec<GitHubReleaseItem> = serde_json::from_str(trimmed).map_err(|e| {
        ReleaseError::TagResolution {
            channel: channel.to_string(),
            reason: format!("invalid GitHub releases JSON: {}", e),
        }
    })?;

    match channel {
        ReleaseChannel::Nightly => {
            for r in &parsed {
                if r.draft {
                    continue;
                }
                let tag = r.tag_name.trim();
                let target_lower = r.target_commitish.trim().to_ascii_lowercase();
                if is_v4_nightly_release_tag(tag)
                    && target_lower != "experimental"
                    && (r.prerelease || target_lower == "nightly")
                {
                    return Ok(tag.to_string());
                }
            }
            Err(ReleaseError::TagResolution {
                channel: channel.to_string(),
                reason: "no matching v4+ nightly prerelease tag found".to_string(),
            })
        }
        ReleaseChannel::Stable => {
            for r in &parsed {
                if r.draft || r.prerelease {
                    continue;
                }
                let tag = r.tag_name.trim();
                let target_lower = r.target_commitish.trim().to_ascii_lowercase();
                if is_v4_or_newer_release_tag(tag)
                    && !tag.contains('-')
                    && target_lower != "nightly"
                    && target_lower != "experimental"
                {
                    return Ok(tag.to_string());
                }
            }
            Err(ReleaseError::TagResolution {
                channel: channel.to_string(),
                reason: "no matching v4+ stable release tag found".to_string(),
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
        return Err(ReleaseError::ArtifactVerification(
            "Extracted release archive is missing a non-empty regular .version stamp. Refusing unverified archive."
                .to_string(),
        ));
    }
    let actual_version = fs::read_to_string(&version_path).map_err(|e| {
        ReleaseError::ArtifactVerification(format!(
            "Failed to read extracted .version at {}: {}",
            version_path.display(),
            e
        ))
    })?;
    let trimmed_version = actual_version.trim();
    if trimmed_version != tag {
        return Err(ReleaseError::ArtifactVerification(format!(
            "Extracted release .version {:?} does not match expected tag {:?}",
            trimmed_version, tag
        )));
    }

    stage_running_release_manager(release_dir, config)?;
    prepare_release_permissions(release_dir)?;
    Ok(())
}

/// Normalizes permissions across an extracted or staged release directory before symlink swap,
/// matching `prepare_release_permissions` in `deploy/release-manager.sh`:
/// - `0755` on all directories
/// - `a+r,go-w` (`(mode | 0o444) & !0o022`) on all regular files
/// - `0755` on `aetherflow-api`, `af` (if present), and `deploy/release-manager.sh` (if present)
/// - Verifies `.version` is readable and `./aetherflow-api` is executable.
pub fn prepare_release_permissions(release_dir: &Path) -> ReleaseResult<()> {
    crate::fs_security::ensure_no_symlink_ancestors(release_dir)?;
    normalize_release_tree_permissions(release_dir)?;

    let api_bin = release_dir.join("aetherflow-api");
    crate::fs_security::set_file_mode(&api_bin, 0o755)?;

    let af_bin = release_dir.join("af");
    if let Ok(meta) = fs::symlink_metadata(&af_bin) {
        if !meta.file_type().is_symlink() && meta.is_file() {
            crate::fs_security::set_file_mode(&af_bin, 0o755)?;
        }
    }

    for rel_exec in ["deploy/release-manager.sh", "deploy/verify-provenance.py"] {
        let staged_exec = release_dir.join(rel_exec);
        if let Ok(meta) = fs::symlink_metadata(&staged_exec) {
            if !meta.file_type().is_symlink() && meta.is_file() {
                crate::fs_security::set_file_mode(&staged_exec, 0o755)?;
            }
        }
    }

    // Verify `.version` is readable and `aetherflow-api` is executable
    let version_path = release_dir.join(".version");
    let version_content = fs::read_to_string(&version_path).map_err(|e| {
        ReleaseError::ArtifactVerification(format!(
            "Release .version at {} is unreadable: {}",
            version_path.display(),
            e
        ))
    })?;
    if version_content.trim().is_empty() {
        return Err(ReleaseError::ArtifactVerification(format!(
            "Release .version at {} is empty",
            version_path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bin_meta = fs::symlink_metadata(&api_bin).map_err(|e| {
            ReleaseError::ArtifactVerification(format!(
                "Release binary at {} is inaccessible: {}",
                api_bin.display(),
                e
            ))
        })?;
        if bin_meta.file_type().is_symlink()
            || !bin_meta.is_file()
            || (bin_meta.permissions().mode() & 0o111) == 0
        {
            return Err(ReleaseError::ArtifactVerification(format!(
                "Release binary at {} is not executable",
                api_bin.display()
            )));
        }
        let ver_meta = fs::symlink_metadata(&version_path).map_err(|e| {
            ReleaseError::ArtifactVerification(format!(
                "Release .version at {} metadata error: {}",
                version_path.display(),
                e
            ))
        })?;
        if (ver_meta.permissions().mode() & 0o444) != 0o444 {
            return Err(ReleaseError::ArtifactVerification(format!(
                "Release .version at {} is not world-readable (a+r)",
                version_path.display()
            )));
        }
    }

    Ok(())
}

fn normalize_release_tree_permissions(dir: &Path) -> ReleaseResult<()> {
    crate::fs_security::set_dir_mode(dir, 0o755)?;
    let entries = fs::read_dir(dir).map_err(|e| {
        ReleaseError::io(
            format!("reading release directory {} for permission normalization", dir.display()),
            e,
        )
    })?;

    for entry_res in entries {
        let entry = entry_res.map_err(|e| {
            ReleaseError::io(
                format!("iterating release directory {}", dir.display()),
                e,
            )
        })?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| {
            ReleaseError::io(format!("stat release entry {}", path.display()), e)
        })?;
        if meta.file_type().is_symlink() {
            return Err(ReleaseError::PathValidation {
                path,
                reason: "symlink entry rejected during release permission normalization".to_string(),
            });
        }
        if meta.is_dir() {
            normalize_release_tree_permissions(&path)?;
        } else if meta.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let current_mode = meta.permissions().mode() & 0o777;
                let normalized = (current_mode | 0o444) & !0o022;
                crate::fs_security::set_file_mode(&path, normalized)?;
            }
            #[cfg(not(unix))]
            {
                crate::fs_security::set_file_mode(&path, 0o644)?;
            }
        }
    }
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

/// Resolves a configured staging source path (`release-manager.sh` or `release-manager.conf`),
/// allowing ONLY the managed `config.current_link` symlink when it points to a direct child
/// release directory inside `config.releases_dir`.
///
/// Any untrusted ancestor symlink, `current_link` pointing outside `releases_dir`, or nested
/// symlink inside the active release directory is rejected with `ReleaseError::PathValidation`.
/// If the source file simply does not exist on disk, returns `Ok(None)`.
pub fn resolve_managed_current_source_path(
    src: &Path,
    config: &ReleaseConfig,
) -> ReleaseResult<Option<PathBuf>> {
    crate::config::validate_no_parent_traversal(src, "staging source path")?;

    if let Ok(rel) = src.strip_prefix(&config.current_link) {
        if rel.as_os_str().is_empty() {
            return Err(ReleaseError::PathValidation {
                path: src.to_path_buf(),
                reason: "staging source path must reference a file inside current release"
                    .to_string(),
            });
        }
        crate::config::validate_no_parent_traversal(rel, "relative staging source path")?;

        let parent = config
            .current_link
            .parent()
            .ok_or_else(|| ReleaseError::PathValidation {
                path: config.current_link.clone(),
                reason: "current release link has no parent".to_string(),
            })?;
        crate::fs_security::ensure_no_symlink_ancestors(parent)?;
        crate::fs_security::ensure_no_symlink_ancestors(&config.releases_dir)?;

        let current_meta = match fs::symlink_metadata(&config.current_link) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(ReleaseError::io(
                    format!("inspecting current release link {}", config.current_link.display()),
                    e,
                ))
            }
        };

        let target_release_dir = if current_meta.file_type().is_symlink() {
            let link_target = fs::read_link(&config.current_link).map_err(|e| {
                ReleaseError::io(
                    format!("reading current release link {}", config.current_link.display()),
                    e,
                )
            })?;
            crate::config::validate_no_parent_traversal(
                &link_target,
                "current release link target",
            )?;
            let resolved = if link_target.is_absolute() {
                link_target
            } else {
                parent.join(link_target)
            };
            crate::config::validate_no_parent_traversal(&resolved, "resolved current release dir")?;
            if resolved.parent() != Some(config.releases_dir.as_path()) {
                return Err(ReleaseError::PathValidation {
                    path: resolved,
                    reason: "current release link must target a direct child of releases_dir"
                        .to_string(),
                });
            }
            crate::fs_security::ensure_no_symlink_ancestors(&resolved)?;
            let target_meta = match fs::symlink_metadata(&resolved) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => {
                    return Err(ReleaseError::io(
                        format!("inspecting resolved current release {}", resolved.display()),
                        e,
                    ))
                }
            };
            if target_meta.file_type().is_symlink() || !target_meta.is_dir() {
                return Err(ReleaseError::PathValidation {
                    path: resolved,
                    reason: "resolved current release target is not a real directory".to_string(),
                });
            }
            resolved
        } else if current_meta.is_dir() {
            crate::fs_security::ensure_no_symlink_ancestors(&config.current_link)?;
            config.current_link.clone()
        } else {
            return Err(ReleaseError::PathValidation {
                path: config.current_link.clone(),
                reason: "current release path is neither a symlink nor a directory".to_string(),
            });
        };

        crate::fs_security::ensure_no_symlink_in_relative_chain(&target_release_dir, rel)?;
        let resolved_src = target_release_dir.join(rel);
        match fs::symlink_metadata(&resolved_src) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err(ReleaseError::PathValidation {
                        path: resolved_src,
                        reason: "staging source entry is not a regular file".to_string(),
                    });
                }
                Ok(Some(resolved_src))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ReleaseError::io(
                format!("inspecting staging source file {}", resolved_src.display()),
                e,
            )),
        }
    } else {
        crate::fs_security::ensure_no_symlink_ancestors(src)?;
        match fs::symlink_metadata(src) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    return Err(ReleaseError::PathValidation {
                        path: src.to_path_buf(),
                        reason: "staging source entry is not a regular file".to_string(),
                    });
                }
                Ok(Some(src.to_path_buf()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ReleaseError::io(
                format!("inspecting staging source file {}", src.display()),
                e,
            )),
        }
    }
}

/// Stages the executing `release-manager.sh`, embedded `verify-provenance.py`, and `release-manager.conf`
/// into `${RELEASE_DIR}/deploy` when configured, matching `stage_running_release_manager` in `deploy/release-manager.sh`.
pub fn stage_running_release_manager(
    release_dir: &Path,
    config: &ReleaseConfig,
) -> ReleaseResult<()> {
    crate::fs_security::ensure_no_symlink_ancestors(release_dir)?;
    let deploy_dir = release_dir.join("deploy");
    crate::fs_security::create_dir_all_no_symlinks(&deploy_dir, 0o755)?;

    let mut staged_script = false;
    if let Some(ref script_src) = config.stage_script_path {
        if let Some(resolved_src) = resolve_managed_current_source_path(script_src, config)? {
            let dst = deploy_dir.join("release-manager.sh");
            if resolved_src != dst {
                crate::fs_security::atomic_copy_file_with_mode(&resolved_src, &dst, 0o755, None)?;
            }
            set_executable_permission(&dst)?;
            staged_script = true;
        }
    }
    if staged_script || deploy_dir.join("release-manager.sh").is_file() {
        let verifier_dst = deploy_dir.join("verify-provenance.py");
        if let Ok(meta) = fs::symlink_metadata(&verifier_dst) {
            if meta.file_type().is_symlink() {
                return Err(ReleaseError::PathValidation {
                    path: verifier_dst,
                    reason: "refusing to overwrite symlinked verify-provenance.py".to_string(),
                });
            }
        }
        crate::fs_security::atomic_write_bytes_with_mode(
            &verifier_dst,
            EMBEDDED_VERIFY_PROVENANCE_PY.as_bytes(),
            0o755,
        )?;
        set_executable_permission(&verifier_dst)?;
    }
    if let Some(ref conf_src) = config.stage_conf_path {
        if let Some(resolved_src) = resolve_managed_current_source_path(conf_src, config)? {
            let dst = deploy_dir.join("release-manager.conf");
            if resolved_src != dst {
                crate::fs_security::atomic_copy_file_with_mode(&resolved_src, &dst, 0o644, None)?;
            }
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
    prepare_release_permissions(release_dir)?;
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
    let latest_url = format!(
        "{}/{}/releases/latest",
        download_base.trim_end_matches('/'),
        github_repo.trim_matches('/')
    );
    let effective = run_blocking_http_effective_url(&latest_url, timeout)?;
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

        let body = run_blocking_http_get_text(&url, Duration::from_secs(15)).unwrap_or_default();
        match select_release_tag_from_json(channel, &body) {
            Ok(tag) => Ok(tag),
            Err(api_err) if channel == ReleaseChannel::Stable => {
                let download_base = self
                    .download_base_url
                    .as_deref()
                    .unwrap_or("https://github.com");
                resolve_stable_tag_from_latest_redirect(
                    download_base,
                    &config.github_repo,
                    Duration::from_secs(15),
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

        let archive_dest = staging_dir.join(&config.artifact_name);
        run_blocking_http_download_to_file(
            &artifact_url,
            &archive_dest,
            0o600,
            Duration::from_secs(180),
            MAX_RELEASE_ARCHIVE_BYTES,
        )?;

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

        let verified_digest =
            verify_artifact_checksum(&archive_dest, &manifest_content, &config.artifact_name)?;
        if std::env::var("AETHERFLOW_SKIP_PROVENANCE_VERIFY").as_deref() != Ok("1") {
            let bundle_override = std::env::var_os("AETHERFLOW_PROVENANCE_BUNDLE_FILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from);
            verify_release_provenance(
                &config.github_repo,
                &verified_digest,
                &config.artifact_name,
                Some(tag),
                Some(channel),
                bundle_override.as_deref(),
            )?;
        }

        Ok((archive_dest, manifest_content))
    }
}

const MAX_RELEASE_TEXT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RELEASE_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

fn is_trusted_github_auth_url(url: &reqwest::Url) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    let Some(host) = url.host_str().map(|h| h.to_ascii_lowercase()) else {
        return false;
    };
    if host == "github.com"
        || host == "api.github.com"
        || host.ends_with(".githubusercontent.com")
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

fn resolve_github_auth_token_for_url(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if !is_trusted_github_auth_url(&parsed) {
        return None;
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

fn run_blocking_http_effective_url(url: &str, timeout: Duration) -> ReleaseResult<String> {
    let url_owned = url.to_string();
    let token_opt = resolve_github_auth_token_for_url(&url_owned);
    std::thread::spawn(move || -> ReleaseResult<String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                ReleaseError::ArtifactVerification(format!("tokio runtime init: {}", e))
            })?;
        rt.block_on(async move {
            let client = reqwest::Client::builder()
                .timeout(timeout)
                .user_agent("AetherFlow-ReleaseEngine/4.0")
                .build()
                .map_err(|e| {
                    ReleaseError::ArtifactVerification(format!("http client init: {}", e))
                })?;
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

fn run_blocking_http_get_text(url: &str, timeout: Duration) -> ReleaseResult<String> {
    let bytes = run_blocking_http_get_bytes_capped(url, timeout, MAX_RELEASE_TEXT_BYTES)?;
    String::from_utf8(bytes).map_err(|e| {
        ReleaseError::ArtifactVerification(format!("invalid UTF-8 response from {}: {}", url, e))
    })
}

fn run_blocking_http_get_bytes_capped(
    url: &str,
    timeout: Duration,
    max_bytes: u64,
) -> ReleaseResult<Vec<u8>> {
    let url_owned = url.to_string();
    let token_opt = resolve_github_auth_token_for_url(&url_owned);
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
                ReleaseError::ArtifactVerification(format!("reading body from {}: {}", url_owned, e))
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
) -> ReleaseResult<()> {
    let url_owned = url.to_string();
    let dest_owned = dest_path.to_path_buf();
    let token_opt = resolve_github_auth_token_for_url(&url_owned);
    std::thread::spawn(move || -> ReleaseResult<()> {
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn create_isolated_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "af_release_stage_test_{}_{}_{}",
            label,
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("create isolated test root");
        root
    }

    fn base_config(root: &Path) -> ReleaseConfig {
        let cfg = ReleaseConfig {
            releases_dir: root.join("releases"),
            current_link: root.join("current"),
            ..ReleaseConfig::default()
        };
        fs::create_dir_all(&cfg.releases_dir).expect("create releases_dir");
        cfg
    }

    #[test]
    fn test_stage_running_release_manager_normal_non_symlink_paths() {
        let root = create_isolated_root("normal");
        let mut cfg = base_config(&root);

        let host_deploy = root.join("deploy");
        fs::create_dir_all(&host_deploy).unwrap();
        let script_src = host_deploy.join("release-manager.sh");
        let conf_src = host_deploy.join("release-manager.conf");
        fs::write(&script_src, b"#!/usr/bin/env bash\necho normal\n").unwrap();
        fs::write(&conf_src, b"RELEASE_CHANNEL=experimental\n").unwrap();

        cfg.stage_script_path = Some(script_src);
        cfg.stage_conf_path = Some(conf_src);

        let next_release = cfg.releases_dir.join("v4-next");
        fs::create_dir_all(&next_release).unwrap();

        stage_running_release_manager(&next_release, &cfg).expect("stage normal paths");

        let staged_script = next_release.join("deploy/release-manager.sh");
        let staged_conf = next_release.join("deploy/release-manager.conf");
        assert_eq!(
            fs::read_to_string(&staged_script).unwrap(),
            "#!/usr/bin/env bash\necho normal\n"
        );
        assert_eq!(
            fs::read_to_string(&staged_conf).unwrap(),
            "RELEASE_CHANNEL=experimental\n"
        );
        let script_mode = fs::symlink_metadata(&staged_script)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(script_mode & 0o111, 0o111, "staged script must be executable");

        let staged_verifier = next_release.join("deploy/verify-provenance.py");
        assert!(staged_verifier.is_file(), "verify-provenance.py must be staged alongside release-manager.sh");
        let verifier_mode = fs::symlink_metadata(&staged_verifier)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(verifier_mode & 0o111, 0o111, "staged verify-provenance.py must be executable");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_stage_running_release_manager_resolves_managed_current_symlink() {
        let root = create_isolated_root("managed_symlink");
        let mut cfg = base_config(&root);

        let active_release = cfg
            .releases_dir
            .join("v4-experimental-89017a6-1793518346");
        let active_deploy = active_release.join("deploy");
        fs::create_dir_all(&active_deploy).unwrap();
        fs::write(
            active_deploy.join("release-manager.sh"),
            b"#!/usr/bin/env bash\necho from-current\n",
        )
        .unwrap();
        fs::write(
            active_deploy.join("release-manager.conf"),
            b"RELEASE_CHANNEL=experimental\n",
        )
        .unwrap();

        // Point managed current_link -> active_release
        symlink(&active_release, &cfg.current_link).unwrap();

        // Configure staging sources through /opt/AetherFlow/current/deploy/...
        cfg.stage_script_path = Some(cfg.current_link.join("deploy/release-manager.sh"));
        cfg.stage_conf_path = Some(cfg.current_link.join("deploy/release-manager.conf"));

        let candidate_release = cfg.releases_dir.join("v4-experimental-candidate");
        fs::create_dir_all(&candidate_release).unwrap();

        stage_running_release_manager(&candidate_release, &cfg)
            .expect("stage through managed current symlink must succeed");

        let staged_script = candidate_release.join("deploy/release-manager.sh");
        let staged_conf = candidate_release.join("deploy/release-manager.conf");
        assert_eq!(
            fs::read_to_string(&staged_script).unwrap(),
            "#!/usr/bin/env bash\necho from-current\n"
        );
        assert_eq!(
            fs::read_to_string(&staged_conf).unwrap(),
            "RELEASE_CHANNEL=experimental\n"
        );
        let script_mode = fs::symlink_metadata(&staged_script)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(script_mode & 0o111, 0o111);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_stage_running_release_manager_rejects_outside_root_and_untrusted_symlinks() {
        let root = create_isolated_root("reject_escapes");
        let mut cfg = base_config(&root);

        // 1. Malicious current_link pointing outside releases_dir
        let outside_dir = root.join("outside_escape");
        fs::create_dir_all(outside_dir.join("deploy")).unwrap();
        fs::write(
            outside_dir.join("deploy/release-manager.sh"),
            b"#!/bin/sh\necho pwned\n",
        )
        .unwrap();
        symlink(&outside_dir, &cfg.current_link).unwrap();

        cfg.stage_script_path = Some(cfg.current_link.join("deploy/release-manager.sh"));
        let candidate_release = cfg.releases_dir.join("v4-candidate-1");
        fs::create_dir_all(&candidate_release).unwrap();

        let err = stage_running_release_manager(&candidate_release, &cfg)
            .expect_err("must reject current_link pointing outside releases_dir");
        assert!(matches!(err, ReleaseError::PathValidation { .. }));

        // 2. Valid current_link, but nested symlink inside active release deploy/
        fs::remove_file(&cfg.current_link).unwrap();
        let active_release = cfg.releases_dir.join("v4-active");
        fs::create_dir_all(active_release.join("deploy")).unwrap();
        symlink(
            outside_dir.join("deploy/release-manager.sh"),
            active_release.join("deploy/release-manager.sh"),
        )
        .unwrap();
        symlink(&active_release, &cfg.current_link).unwrap();

        let err_nested = stage_running_release_manager(&candidate_release, &cfg)
            .expect_err("must reject nested symlink inside active release");
        assert!(matches!(err_nested, ReleaseError::PathValidation { .. }));

        // 3. Untrusted symlink ancestor outside current_link
        let untrusted_link = root.join("untrusted_deploy_link");
        symlink(outside_dir.join("deploy"), &untrusted_link).unwrap();
        cfg.stage_script_path = Some(untrusted_link.join("release-manager.sh"));

        let err_untrusted = stage_running_release_manager(&candidate_release, &cfg)
            .expect_err("must reject untrusted symlink ancestor");
        assert!(matches!(err_untrusted, ReleaseError::PathValidation { .. }));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_stage_running_release_manager_missing_source_files_is_noop() {
        let root = create_isolated_root("missing_noop");
        let mut cfg = base_config(&root);

        let active_release = cfg.releases_dir.join("v4-active");
        fs::create_dir_all(&active_release).unwrap();
        symlink(&active_release, &cfg.current_link).unwrap();

        cfg.stage_script_path = Some(cfg.current_link.join("deploy/release-manager.sh"));
        cfg.stage_conf_path = Some(root.join("nonexistent/release-manager.conf"));

        let candidate_release = cfg.releases_dir.join("v4-candidate");
        fs::create_dir_all(&candidate_release).unwrap();

        stage_running_release_manager(&candidate_release, &cfg)
            .expect("missing optional source files should be a clean no-op");
        assert!(!candidate_release.join("deploy/release-manager.sh").exists());
        assert!(!candidate_release.join("deploy/verify-provenance.py").exists());
        assert!(!candidate_release.join("deploy/release-manager.conf").exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_verify_release_provenance_accepts_real_sigstore_bundle_and_rejects_tag_replay() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../tests/fixtures/sigstore_bundle_nightly_109_1.json");
        let digest = "018a270e2833886b1c59e2f831912c794e2ed66dacf6c2249ab1390fc2d44b26";
        verify_release_provenance(
            "McEveritts/AetherFlow",
            digest,
            "aetherflow-linux-amd64.tar.gz",
            Some("v4.0.0-nightly.109.1"),
            Some(ReleaseChannel::Nightly),
            Some(&fixture),
        )
        .expect("real nightly.109.1 Sigstore bundle must pass verification");

        let replay_err = verify_release_provenance(
            "McEveritts/AetherFlow",
            digest,
            "aetherflow-linux-amd64.tar.gz",
            Some("v4.0.0"),
            Some(ReleaseChannel::Stable),
            Some(&fixture),
        )
        .expect_err("replaying nightly bundle under stable v4.0.0 must fail closed");
        assert!(matches!(replay_err, ReleaseError::ArtifactVerification(_)));
    }

    #[test]
    fn test_round3_strict_nightly_tag_gate_and_trusted_github_auth_host() {
        assert!(is_v4_nightly_release_tag("v4.0.0-nightly.110.1"));
        assert!(is_v4_nightly_release_tag("v4.1.2-Nightly.7"));
        assert!(!is_v4_nightly_release_tag("v4.9.0-rc.1"));
        assert!(!is_v4_nightly_release_tag("v4.0.0-beta.1"));
        assert!(!is_v4_nightly_release_tag("v4.0.0"));
        assert!(!is_v4_nightly_release_tag("v3.2.7-nightly.1.1"));

        let https_api = reqwest::Url::parse("https://api.github.com/repos/McEveritts/AetherFlow/releases").unwrap();
        let https_gh = reqwest::Url::parse("https://github.com/McEveritts/AetherFlow/releases/latest").unwrap();
        let https_obj = reqwest::Url::parse("https://objects.githubusercontent.com/github-production-release-asset/foo").unwrap();
        let http_downgrade = reqwest::Url::parse("http://api.github.com/repos/McEveritts/AetherFlow/releases").unwrap();
        let untrusted_host = reqwest::Url::parse("https://evil-mirror.example.com/aetherflow.tar.gz").unwrap();

        assert!(is_trusted_github_auth_url(&https_api));
        assert!(is_trusted_github_auth_url(&https_gh));
        assert!(is_trusted_github_auth_url(&https_obj));
        assert!(!is_trusted_github_auth_url(&http_downgrade));
        assert!(!is_trusted_github_auth_url(&untrusted_host));
    }
}
