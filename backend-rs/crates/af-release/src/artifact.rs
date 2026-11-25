//! Stage 1: Release tag resolution, SHA-256 manifest verification, safe tarball extraction,
//! and offline dry-run artifact simulation.

mod archive;
mod provider;

#[cfg(all(test, unix))]
mod tests;

pub use archive::{
    extract_and_validate_release_archive, prepare_release_permissions,
    resolve_managed_current_source_path, simulate_offline_artifact, stage_running_release_manager,
};
pub use provider::{
    parse_stable_tag_from_redirect_url, resolve_stable_tag_from_latest_redirect, ArtifactProvider,
    GithubHttpArtifactProvider,
};

use crate::config::ReleaseChannel;
use crate::error::{ReleaseError, ReleaseResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

const EMBEDDED_VERIFY_PROVENANCE_PY: &str = include_str!("../../../../deploy/verify-provenance.py");
const EMBEDDED_LOG_RETENTION_PY: &str = include_str!("../../../../deploy/log-retention.py");

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
    verify_release_provenance_with_token(
        github_repo,
        expected_digest,
        artifact_name,
        expected_tag,
        expected_channel,
        bundle_file,
        None,
    )
}

/// Same as [`verify_release_provenance`] while also forwarding an explicit `github_token`
/// loaded from `ReleaseConfig` into the scrubbed verifier subprocess environment.
pub fn verify_release_provenance_with_token(
    github_repo: &str,
    expected_digest: &str,
    artifact_name: &str,
    expected_tag: Option<&str>,
    expected_channel: Option<ReleaseChannel>,
    bundle_file: Option<&Path>,
    github_token: Option<&str>,
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
    if let Some(tok) = github_token.map(str::trim).filter(|t| !t.is_empty()) {
        cmd.env("AF_GITHUB_TOKEN", tok);
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
    let parsed: Vec<GitHubReleaseItem> =
        serde_json::from_str(trimmed).map_err(|e| ReleaseError::TagResolution {
            channel: channel.to_string(),
            reason: format!("invalid GitHub releases JSON: {}", e),
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
