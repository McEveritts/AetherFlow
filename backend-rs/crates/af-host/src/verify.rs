//! SHA-256 file hashing, `.sha256` sidecar parsing/writing, path sanitization,
//! and chunked backup helper verification for `af-host`.
//!
//! Aligns with both `packages/system/af-backup` (`sha256sum <file> > <file>.sha256`
//! and `split -b ... <file>.part.00000`) and `af-api`/`af-services` (`<checksum>\n`
//! sidecar format).

use crate::error::{HostBackupError, HostBackupResult};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

/// Strict filename allowlist for backup artifacts (`.sqlite`, `.tar.gz`, `.manifest.json`).
static SAFE_BACKUP_FILENAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,191}$").unwrap());

/// Strict 64-character hexadecimal SHA-256 digest matcher.
static SHA256_HEX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[0-9a-fA-F]{64}$").unwrap());

/// Result of verifying a file against an expected SHA-256 digest or `.sha256` sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumVerification {
    pub artifact_path: PathBuf,
    pub sidecar_path: Option<PathBuf>,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub size_bytes: u64,
    pub verified: bool,
}

/// Validates that `filename` is a single safe basename with no path separators,
/// parent traversal (`..`), NUL bytes, or leading dot-files.
pub fn validate_backup_filename(filename: &str) -> HostBackupResult<String> {
    let trimmed = filename.trim();
    if trimmed.is_empty() {
        return Err(HostBackupError::TraversalRejected {
            path: filename.to_string(),
            reason: "backup filename must not be empty".to_string(),
        });
    }
    if trimmed.contains('\0')
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed == "."
    {
        return Err(HostBackupError::TraversalRejected {
            path: filename.to_string(),
            reason: "backup filename must not contain path separators or '..'".to_string(),
        });
    }
    if !SAFE_BACKUP_FILENAME_RE.is_match(trimmed) {
        return Err(HostBackupError::TraversalRejected {
            path: filename.to_string(),
            reason: "backup filename contains disallowed characters".to_string(),
        });
    }
    Ok(trimmed.to_string())
}

/// Resolves a backup filename inside `backup_dir`, rejecting any path traversal or symlink escape
/// (including ancestor symlinks of `backup_dir`).
pub fn safe_backup_file_path(backup_dir: &Path, filename: &str) -> HostBackupResult<PathBuf> {
    validate_no_parent_traversal(backup_dir, "backup_dir")?;
    reject_if_symlink(backup_dir, "backup_dir")?;
    let clean_name = validate_backup_filename(filename)?;
    let candidate = backup_dir.join(&clean_name);
    reject_symlink_chain(backup_dir, &candidate)?;
    Ok(candidate)
}

/// Rejects empty paths, NUL bytes, or `.` / `..` segments in a filesystem path.
pub fn validate_no_parent_traversal(path: &Path, label: &str) -> HostBackupResult<()> {
    let raw = path.to_string_lossy();
    if raw.trim().is_empty() {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} must not be empty", label),
        });
    }
    if raw.contains('\0') {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} contains NUL byte", label),
        });
    }
    for segment in raw.split(['/', '\\']) {
        if segment == ".." {
            return Err(HostBackupError::TraversalRejected {
                path: raw.into_owned(),
                reason: format!("{} must not contain parent traversal ('..')", label),
            });
        }
        if segment == "." {
            return Err(HostBackupError::TraversalRejected {
                path: raw.into_owned(),
                reason: format!("{} must not contain '.' segment", label),
            });
        }
    }
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: raw.into_owned(),
                    reason: format!("{} must not contain parent traversal ('..')", label),
                });
            }
            Component::CurDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: raw.into_owned(),
                    reason: format!("{} must not contain '.' segment", label),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Validates a relative path stored in a backup manifest or tar archive.
///
/// Rejects:
/// - Empty paths or NUL bytes
/// - Leading `/` or `\` or Windows drive prefixes (`C:\`)
/// - Any `..` (`Component::ParentDir`) or `.` (`Component::CurDir`) traversal segments
pub fn validate_relative_backup_path(rel_path: &str) -> HostBackupResult<PathBuf> {
    let trimmed = rel_path.trim();
    if trimmed.is_empty() {
        return Err(HostBackupError::TraversalRejected {
            path: rel_path.to_string(),
            reason: "relative backup path must not be empty".to_string(),
        });
    }
    if trimmed.contains('\0') {
        return Err(HostBackupError::TraversalRejected {
            path: rel_path.to_string(),
            reason: "relative backup path contains NUL byte".to_string(),
        });
    }
    if trimmed.starts_with('/') || trimmed.starts_with('\\') || trimmed.contains(':') {
        return Err(HostBackupError::TraversalRejected {
            path: rel_path.to_string(),
            reason: "backup entry path must be relative (leading '/' or drive prefix rejected)"
                .to_string(),
        });
    }
    // Also reject raw `\` on Unix where `\` is not treated as a path separator by `Path`
    if trimmed.contains('\\') {
        return Err(HostBackupError::TraversalRejected {
            path: rel_path.to_string(),
            reason: "backup entry path must use forward slashes ('\\' rejected)".to_string(),
        });
    }

    if trimmed
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(HostBackupError::TraversalRejected {
            path: rel_path.to_string(),
            reason: "backup entry contains empty, '.' or '..' segment".to_string(),
        });
    }

    let path = Path::new(trimmed);
    let mut normalized = PathBuf::new();
    let mut depth = 0usize;
    for comp in path.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.is_empty() || s == "." || s == ".." {
                    return Err(HostBackupError::TraversalRejected {
                        path: rel_path.to_string(),
                        reason: "backup entry contains '.' or '..' segment".to_string(),
                    });
                }
                normalized.push(seg);
                depth += 1;
            }
            Component::CurDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: rel_path.to_string(),
                    reason: "backup entry contains '.' current-directory segment".to_string(),
                });
            }
            Component::ParentDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: rel_path.to_string(),
                    reason: "backup entry contains '..' parent traversal segment".to_string(),
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(HostBackupError::TraversalRejected {
                    path: rel_path.to_string(),
                    reason: "backup entry must not be rooted or prefixed".to_string(),
                });
            }
        }
    }

    if depth == 0 {
        return Err(HostBackupError::TraversalRejected {
            path: rel_path.to_string(),
            reason: "backup entry resolved to empty path".to_string(),
        });
    }

    Ok(normalized)
}

/// Checks `fs::symlink_metadata` for a single path component and returns
/// `HostBackupError::SymlinkRejected` if it is a symbolic link, or propagates
/// unexpected metadata errors (`NotFound` is ignored when a path does not yet exist).
fn reject_single_component_if_symlink(path: &Path, context: &str) -> HostBackupResult<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(HostBackupError::SymlinkRejected {
                    path: path.to_path_buf(),
                    reason: format!("{} is a symbolic link", context),
                });
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        // When a non-directory ancestor prevents looking up a child, or an intermediate component does not exist
        #[cfg(unix)]
        Err(err) if err.raw_os_error() == Some(libc::ENOTDIR) => Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("non-directory component encountered while inspecting {}: {}", context, err),
        }),
        Err(err) => Err(HostBackupError::io(
            format!("inspecting symlink metadata for {} ({})", path.display(), context),
            err,
        )),
    }
}

/// Checks every existing ancestor and the leaf of `path` using `fs::symlink_metadata`,
/// returning `HostBackupError::SymlinkRejected` if any component is a symbolic link
/// and propagating unexpected filesystem metadata errors.
pub fn reject_if_symlink(path: &Path, context: &str) -> HostBackupResult<()> {
    let mut acc = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => acc.push(p.as_os_str()),
            Component::RootDir => acc.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: path.to_string_lossy().into_owned(),
                    reason: format!("{} contains '..' parent traversal segment", context),
                });
            }
            Component::Normal(seg) => {
                acc.push(seg);
                reject_single_component_if_symlink(&acc, context)?;
            }
        }
    }
    reject_single_component_if_symlink(path, context)?;
    Ok(())
}

/// Walks every existing ancestor of `root` and every component from `root` to `candidate`,
/// rejecting any symbolic link along the entire path chain and propagating unexpected
/// metadata errors.
pub fn reject_symlink_chain(root: &Path, candidate: &Path) -> HostBackupResult<()> {
    reject_if_symlink(root, "root directory")?;
    reject_if_symlink(candidate, "target path")?;
    if let Ok(rel) = candidate.strip_prefix(root) {
        let mut current = root.to_path_buf();
        for comp in rel.components() {
            match comp {
                Component::Normal(seg) => {
                    current.push(seg);
                    reject_single_component_if_symlink(&current, "path component")?;
                }
                Component::ParentDir => {
                    return Err(HostBackupError::TraversalRejected {
                        path: candidate.to_string_lossy().into_owned(),
                        reason: "candidate path under root contains '..'".to_string(),
                    });
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Ensures `dir` and any missing parent directories exist with private `0700` permissions on Unix
/// (created with mode `0700` before any secrets are written inside, and tightened to `0700` if
/// `dir` already existed), while rejecting any symlink along the entire ancestor chain.
pub(crate) fn ensure_private_dir_all(dir: &Path, context: &str) -> HostBackupResult<()> {
    validate_no_parent_traversal(dir, context)?;
    reject_if_symlink(dir, context)?;

    let mut acc = PathBuf::new();
    for comp in dir.components() {
        match comp {
            Component::Prefix(p) => acc.push(p.as_os_str()),
            Component::RootDir => acc.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: dir.to_string_lossy().into_owned(),
                    reason: format!("{} must not contain '..'", context),
                });
            }
            Component::Normal(seg) => {
                acc.push(seg);
                match fs::symlink_metadata(&acc) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            return Err(HostBackupError::SymlinkRejected {
                                path: acc,
                                reason: format!("{} ancestor is a symbolic link", context),
                            });
                        }
                        if !meta.is_dir() {
                            return Err(HostBackupError::PathValidation {
                                path: acc,
                                reason: format!("{} component exists and is not a directory", context),
                            });
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        create_single_private_dir(&acc, context)?;
                    }
                    Err(err) => {
                        return Err(HostBackupError::io(
                            format!("inspecting directory component {} ({})", acc.display(), context),
                            err,
                        ));
                    }
                }
            }
        }
    }

    reject_if_symlink(dir, context)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(dir).map_err(|e| {
            HostBackupError::io(format!("inspecting {} ({})", dir.display(), context), e)
        })?;
        if meta.file_type().is_symlink() {
            return Err(HostBackupError::SymlinkRejected {
                path: dir.to_path_buf(),
                reason: format!("{} is a symbolic link", context),
            });
        }
        if (meta.permissions().mode() & 0o777) != 0o700 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
                HostBackupError::io(
                    format!("setting 0700 permissions on {} ({})", dir.display(), context),
                    e,
                )
            })?;
        }
    }
    Ok(())
}

fn create_single_private_dir(path: &Path, context: &str) -> HostBackupResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                reject_single_component_if_symlink(path, context)
            }
            Err(err) => Err(HostBackupError::io(
                format!("creating private directory {} ({})", path.display(), context),
                err,
            )),
        }
    }
    #[cfg(not(unix))]
    {
        match fs::create_dir(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                reject_single_component_if_symlink(path, context)
            }
            Err(err) => Err(HostBackupError::io(
                format!("creating private directory {} ({})", path.display(), context),
                err,
            )),
        }
    }
}

/// Creates a brand-new file exclusively (`create_new(true)`) with mode `0600` on Unix
/// (`O_CREAT | O_EXCL | O_WRONLY` + `O_NOFOLLOW` on Unix) so it can never follow a pre-planted
/// symlink or expose secret bytes with world/group-readable permissions before write.
pub(crate) fn create_private_new_file(path: &Path, context: &str) -> HostBackupResult<File> {
    reject_if_symlink(path, context)?;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path).map_err(|e| {
        HostBackupError::io(
            format!("exclusively creating private file {} ({})", path.display(), context),
            e,
        )
    })
}

/// Generates a collision-resistant temporary sibling path by appending
/// `.<tag>.<pid>.<uuid_v4>` to the full filename of `target_path` (never stripping extensions),
/// and opens it exclusively with `0600` permissions.
pub(crate) fn create_unique_private_temp_file(
    target_path: &Path,
    tag: &str,
    context: &str,
) -> HostBackupResult<(PathBuf, File)> {
    let parent = target_path
        .parent()
        .ok_or_else(|| HostBackupError::PathValidation {
            path: target_path.to_path_buf(),
            reason: format!("{} must have a parent directory", context),
        })?;
    if !parent.as_os_str().is_empty() {
        ensure_private_dir_all(parent, context)?;
    }
    let base_name = target_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| HostBackupError::PathValidation {
            path: target_path.to_path_buf(),
            reason: format!("{} must have a valid file name", context),
        })?;
    let tmp_name = format!(
        ".{}.{}.{}.{}",
        base_name,
        tag,
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let tmp_path = parent.join(tmp_name);
    let file = create_private_new_file(&tmp_path, context)?;
    Ok((tmp_path, file))
}

/// Atomically writes `bytes` to `target_path` via a `0600` exclusive temporary file + `sync_all` + `rename`.
pub(crate) fn write_private_file_atomic(
    target_path: &Path,
    bytes: &[u8],
    tag: &str,
    context: &str,
) -> HostBackupResult<()> {
    reject_if_symlink(target_path, context)?;
    let (tmp_path, mut tmp_file) = create_unique_private_temp_file(target_path, tag, context)?;
    if let Err(e) = tmp_file
        .write_all(bytes)
        .and_then(|()| tmp_file.sync_all())
    {
        drop(tmp_file);
        let _ = fs::remove_file(&tmp_path);
        return Err(HostBackupError::io(
            format!("writing temporary file {} ({})", tmp_path.display(), context),
            e,
        ));
    }
    drop(tmp_file);
    if let Err(e) = reject_if_symlink(target_path, context) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp_path, target_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(HostBackupError::io(
            format!(
                "renaming {} -> {} ({})",
                tmp_path.display(),
                target_path.display(),
                context
            ),
            e,
        ));
    }
    Ok(())
}

/// Creates a private `0700` temporary staging directory inside `parent_dir` with a unique
/// `.staging-dir.<tag>.<pid>.<uuid>` name using exclusive mkdir (`create_single_private_dir`).
pub(crate) fn create_unique_private_staging_dir(
    parent_dir: &Path,
    tag: &str,
    context: &str,
) -> HostBackupResult<PathBuf> {
    ensure_private_dir_all(parent_dir, context)?;
    let dir_name = format!(
        ".staging-{}.{}.{}",
        tag,
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let staging_dir = parent_dir.join(dir_name);
    reject_if_symlink(&staging_dir, context)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&staging_dir).map_err(|e| {
            HostBackupError::io(
                format!(
                    "creating exclusive staging dir {} ({})",
                    staging_dir.display(),
                    context
                ),
                e,
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(&staging_dir).map_err(|e| {
            HostBackupError::io(
                format!(
                    "creating exclusive staging dir {} ({})",
                    staging_dir.display(),
                    context
                ),
                e,
            )
        })?;
    }
    Ok(staging_dir)
}

/// Enforces `0600` permissions on an existing regular file on Unix after verifying it is not a symlink.
pub(crate) fn set_private_file_permissions(path: &Path, context: &str) -> HostBackupResult<()> {
    reject_if_symlink(path, context)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            HostBackupError::io(
                format!("setting 0600 permissions on {} ({})", path.display(), context),
                e,
            )
        })?;
    }
    Ok(())
}

/// Returns `Some(index)` if `candidate_name` is an exact 5-digit chunk filename
/// for `base_filename` (`<base_filename>.part.<5 ASCII digits>`).
pub(crate) fn parse_exact_chunk_index(base_filename: &str, candidate_name: &str) -> Option<usize> {
    let prefix = format!("{}.part.", base_filename);
    let suffix = candidate_name.strip_prefix(&prefix)?;
    if suffix.len() != 5 || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    suffix.parse::<usize>().ok()
}

/// Returns the canonical `.sha256` sidecar path for `file_path` (`<file_path>.sha256`).
pub fn checksum_sidecar_path(file_path: &Path) -> PathBuf {
    let mut os = file_path.as_os_str().to_os_string();
    os.push(".sha256");
    PathBuf::from(os)
}

/// Computes the lowercase hexadecimal SHA-256 digest and byte size of `file_path`
/// using a streaming 64 KiB buffer. Rejects symlinks (including ancestor symlinks) before opening.
pub fn compute_file_sha256(file_path: &Path) -> HostBackupResult<(String, u64)> {
    reject_if_symlink(file_path, "checksummed file")?;
    let meta = fs::symlink_metadata(file_path)
        .map_err(|e| HostBackupError::io(format!("stat {}", file_path.display()), e))?;
    if meta.file_type().is_symlink() {
        return Err(HostBackupError::SymlinkRejected {
            path: file_path.to_path_buf(),
            reason: "checksummed file is a symbolic link".to_string(),
        });
    }
    if !meta.is_file() {
        return Err(HostBackupError::PathValidation {
            path: file_path.to_path_buf(),
            reason: "checksummed path is not a regular file".to_string(),
        });
    }
    let mut file = File::open(file_path)
        .map_err(|e| HostBackupError::io(format!("opening {}", file_path.display()), e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;

    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| HostBackupError::io(format!("reading {}", file_path.display()), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total_bytes += n as u64;
    }

    Ok((hex::encode(hasher.finalize()), total_bytes))
}

/// Parses a `.sha256` sidecar content string.
///
/// Supports both GNU coreutils `sha256sum` output (`<hex>  <filename>` or `<hex> *<filename>`)
/// emitted by `packages/system/af-backup` and bare `<hex>\n` sidecars emitted by `af-api`/`af-services`.
pub fn parse_sha256_sidecar_str(content: &str) -> HostBackupResult<String> {
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let first_token = line.split_whitespace().next().unwrap_or("");
        if SHA256_HEX_RE.is_match(first_token) {
            return Ok(first_token.to_ascii_lowercase());
        }
        return Err(HostBackupError::InvalidManifest(format!(
            "malformed SHA-256 digest in sidecar: {:?}",
            first_token
        )));
    }

    Err(HostBackupError::InvalidManifest(
        "empty SHA-256 sidecar file".to_string(),
    ))
}

/// Writes a GNU `sha256sum`-compatible `.sha256` sidecar file (`<sha256>  <basename>\n`)
/// atomically for `file_path` (using a `0600` UUID-suffixed temporary file) and returns
/// `(sidecar_path, sha256_hex, size_bytes)`.
pub fn write_sha256_sidecar(file_path: &Path) -> HostBackupResult<(PathBuf, String, u64)> {
    let (digest, size_bytes) = compute_file_sha256(file_path)?;
    let sidecar = checksum_sidecar_path(file_path);
    reject_if_symlink(&sidecar, "checksum sidecar")?;

    let basename = file_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("artifact");
    let formatted = format!("{}  {}\n", digest, basename);

    write_private_file_atomic(&sidecar, formatted.as_bytes(), "sidecar-tmp", "checksum sidecar")?;

    Ok((sidecar, digest, size_bytes))
}

/// Verifies `file_path` against an explicit expected SHA-256 hex digest.
pub fn verify_file_sha256(
    file_path: &Path,
    expected_sha256: &str,
) -> HostBackupResult<ChecksumVerification> {
    let expected_clean = expected_sha256.trim().to_ascii_lowercase();
    if !SHA256_HEX_RE.is_match(&expected_clean) {
        return Err(HostBackupError::InvalidManifest(format!(
            "expected SHA-256 is not a valid 64-char hex digest: {:?}",
            expected_sha256
        )));
    }

    let (actual, size_bytes) = compute_file_sha256(file_path)?;
    if actual != expected_clean {
        return Err(HostBackupError::ChecksumMismatch {
            artifact: file_path.display().to_string(),
            expected: expected_clean,
            actual,
        });
    }

    Ok(ChecksumVerification {
        artifact_path: file_path.to_path_buf(),
        sidecar_path: None,
        expected_sha256: expected_clean,
        actual_sha256: actual,
        size_bytes,
        verified: true,
    })
}

/// Verifies `file_path` against its `<file_path>.sha256` sidecar file on disk.
/// Fails closed if either the artifact or the sidecar is missing, a symlink, or mismatched.
pub fn verify_file_with_sidecar(file_path: &Path) -> HostBackupResult<ChecksumVerification> {
    reject_if_symlink(file_path, "backup artifact")?;
    let art_meta = match fs::symlink_metadata(file_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HostBackupError::PathValidation {
                path: file_path.to_path_buf(),
                reason: "backup artifact does not exist or is not a regular file".to_string(),
            });
        }
        Err(e) => {
            return Err(HostBackupError::io(
                format!("stat backup artifact {}", file_path.display()),
                e,
            ));
        }
    };
    if art_meta.file_type().is_symlink() {
        return Err(HostBackupError::SymlinkRejected {
            path: file_path.to_path_buf(),
            reason: "backup artifact is a symbolic link".to_string(),
        });
    }
    if !art_meta.is_file() {
        return Err(HostBackupError::PathValidation {
            path: file_path.to_path_buf(),
            reason: "backup artifact does not exist or is not a regular file".to_string(),
        });
    }

    let sidecar = checksum_sidecar_path(file_path);
    reject_if_symlink(&sidecar, "checksum sidecar")?;
    let sc_meta = match fs::symlink_metadata(&sidecar) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(HostBackupError::MissingChecksumSidecar {
                artifact: file_path.to_path_buf(),
                sidecar_path: sidecar,
            });
        }
        Err(e) => {
            return Err(HostBackupError::io(
                format!("stat checksum sidecar {}", sidecar.display()),
                e,
            ));
        }
    };
    if sc_meta.file_type().is_symlink() {
        return Err(HostBackupError::SymlinkRejected {
            path: sidecar,
            reason: "checksum sidecar is a symbolic link".to_string(),
        });
    }
    if !sc_meta.is_file() {
        return Err(HostBackupError::MissingChecksumSidecar {
            artifact: file_path.to_path_buf(),
            sidecar_path: sidecar,
        });
    }

    let raw_sidecar = fs::read_to_string(&sidecar)
        .map_err(|e| HostBackupError::io(format!("reading sidecar {}", sidecar.display()), e))?;
    let expected = parse_sha256_sidecar_str(&raw_sidecar)?;
    let mut result = verify_file_sha256(file_path, &expected)?;
    result.sidecar_path = Some(sidecar);
    Ok(result)
}

/// Removes or rejects any pre-existing `<file_path>.part.<5 digits>` files before splitting
/// so stale trailing chunks from an earlier split with a smaller chunk size can never survive.
fn remove_existing_safe_chunks(file_path: &Path) -> HostBackupResult<()> {
    let Some(parent) = file_path.parent() else {
        return Ok(());
    };
    let Some(base_name) = file_path.file_name().and_then(|s| s.to_str()) else {
        return Ok(());
    };
    if !parent.exists() {
        return Ok(());
    }
    reject_if_symlink(parent, "chunk parent directory")?;
    for entry in fs::read_dir(parent)
        .map_err(|e| HostBackupError::io(format!("reading {}", parent.display()), e))?
    {
        let entry = entry.map_err(|e| HostBackupError::io("reading chunk dir entry", e))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if parse_exact_chunk_index(base_name, &name).is_some() {
            let p = entry.path();
            let meta = fs::symlink_metadata(&p)
                .map_err(|e| HostBackupError::io(format!("stat chunk {}", p.display()), e))?;
            if meta.file_type().is_symlink() {
                return Err(HostBackupError::SymlinkRejected {
                    path: p,
                    reason: "existing backup chunk is a symbolic link".to_string(),
                });
            }
            if !meta.is_file() {
                return Err(HostBackupError::ChunkError {
                    artifact: file_path.to_path_buf(),
                    reason: format!(
                        "existing chunk path '{}' is not a regular file",
                        p.display()
                    ),
                });
            }
            fs::remove_file(&p).map_err(|e| {
                HostBackupError::io(format!("removing stale chunk {}", p.display()), e)
            })?;
        }
    }
    Ok(())
}

/// Splits a verified backup file into fixed-size chunk files (`<file>.part.00000`, `<file>.part.00001`, ...)
/// matching `packages/system/af-backup`'s `split -b <size> -d -a 5` naming convention.
///
/// Creates each chunk exclusively with mode `0600` after clearing any stale exact-5-digit chunks.
pub fn split_backup_into_chunks(
    file_path: &Path,
    chunk_size_bytes: u64,
) -> HostBackupResult<Vec<PathBuf>> {
    if chunk_size_bytes == 0 {
        return Err(HostBackupError::ChunkError {
            artifact: file_path.to_path_buf(),
            reason: "chunk_size_bytes must be greater than zero".to_string(),
        });
    }
    reject_if_symlink(file_path, "backup file to split")?;
    if let Some(parent) = file_path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_private_dir_all(parent, "chunk output directory")?;
        }
    }
    remove_existing_safe_chunks(file_path)?;

    let mut src = File::open(file_path)
        .map_err(|e| HostBackupError::io(format!("opening {}", file_path.display()), e))?;

    let mut chunks: Vec<PathBuf> = Vec::new();
    let mut index = 0usize;
    let mut buf = vec![0u8; 64 * 1024];

    let split_res: HostBackupResult<()> = (|| {
        loop {
            if index > 99_999 {
                return Err(HostBackupError::ChunkError {
                    artifact: file_path.to_path_buf(),
                    reason: "chunk count exceeds 5-digit suffix limit (99999)".to_string(),
                });
            }
            let mut remaining = chunk_size_bytes;
            let part_path = PathBuf::from(format!("{}.part.{:05}", file_path.display(), index));
            let mut wrote_any = false;
            let mut part_file: Option<File> = None;

            while remaining > 0 {
                let to_read = (remaining as usize).min(buf.len());
                let n = src
                    .read(&mut buf[..to_read])
                    .map_err(|e| HostBackupError::io(format!("reading {}", file_path.display()), e))?;
                if n == 0 {
                    break;
                }
                if part_file.is_none() {
                    let f = create_private_new_file(&part_path, "backup chunk output")?;
                    chunks.push(part_path.clone());
                    part_file = Some(f);
                }
                if let Some(ref mut out) = part_file {
                    out.write_all(&buf[..n]).map_err(|e| {
                        HostBackupError::io(format!("writing chunk {}", part_path.display()), e)
                    })?;
                }
                wrote_any = true;
                remaining -= n as u64;
            }

            if let Some(out) = part_file {
                out.sync_all().map_err(|e| {
                    HostBackupError::io(format!("syncing chunk {}", part_path.display()), e)
                })?;
                index += 1;
            }

            if !wrote_any {
                break;
            }
        }
        Ok(())
    })();

    if let Err(err) = split_res {
        for created in &chunks {
            let _ = fs::remove_file(created);
        }
        return Err(err);
    }

    Ok(chunks)
}

/// Reassembles sequential `<output_path>.part.00000` chunk files into `output_path`
/// and verifies the reassembled file against `expected_sha256` before activating it.
pub fn assemble_verified_chunks(
    chunk_paths: &[PathBuf],
    output_path: &Path,
    expected_sha256: &str,
) -> HostBackupResult<ChecksumVerification> {
    if chunk_paths.is_empty() {
        return Err(HostBackupError::ChunkError {
            artifact: output_path.to_path_buf(),
            reason: "no chunk files provided for assembly".to_string(),
        });
    }
    validate_no_parent_traversal(output_path, "assembled backup target")?;
    reject_if_symlink(output_path, "assembled backup target")?;

    let (tmp_out, mut out) =
        create_unique_private_temp_file(output_path, "assembling", "temporary assembly file")?;

    for part in chunk_paths {
        if let Err(e) = reject_if_symlink(part, "backup chunk part") {
            drop(out);
            let _ = fs::remove_file(&tmp_out);
            return Err(e);
        }
        let meta = match fs::symlink_metadata(part) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                drop(out);
                let _ = fs::remove_file(&tmp_out);
                return Err(HostBackupError::ChunkError {
                    artifact: output_path.to_path_buf(),
                    reason: format!("missing chunk file: {}", part.display()),
                });
            }
            Err(e) => {
                drop(out);
                let _ = fs::remove_file(&tmp_out);
                return Err(HostBackupError::io(
                    format!("stat chunk {}", part.display()),
                    e,
                ));
            }
        };
        if meta.file_type().is_symlink() {
            drop(out);
            let _ = fs::remove_file(&tmp_out);
            return Err(HostBackupError::SymlinkRejected {
                path: part.clone(),
                reason: "backup chunk part is a symbolic link".to_string(),
            });
        }
        if !meta.is_file() {
            drop(out);
            let _ = fs::remove_file(&tmp_out);
            return Err(HostBackupError::ChunkError {
                artifact: output_path.to_path_buf(),
                reason: format!("chunk path is not a regular file: {}", part.display()),
            });
        }
        let mut part_file = match File::open(part) {
            Ok(f) => f,
            Err(e) => {
                drop(out);
                let _ = fs::remove_file(&tmp_out);
                return Err(HostBackupError::io(
                    format!("opening chunk {}", part.display()),
                    e,
                ));
            }
        };
        if let Err(e) = std::io::copy(&mut part_file, &mut out) {
            drop(out);
            let _ = fs::remove_file(&tmp_out);
            return Err(HostBackupError::io(
                format!("copying chunk {}", part.display()),
                e,
            ));
        }
    }

    if let Err(e) = out.sync_all() {
        drop(out);
        let _ = fs::remove_file(&tmp_out);
        return Err(HostBackupError::io(
            format!("syncing assembled file {}", tmp_out.display()),
            e,
        ));
    }
    drop(out);

    let verification = match verify_file_sha256(&tmp_out, expected_sha256) {
        Ok(v) => v,
        Err(err) => {
            let _ = fs::remove_file(&tmp_out);
            return Err(err);
        }
    };

    if let Err(e) = reject_if_symlink(output_path, "assembled backup target") {
        let _ = fs::remove_file(&tmp_out);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp_out, output_path) {
        let _ = fs::remove_file(&tmp_out);
        return Err(HostBackupError::io(
            format!("activating assembled backup {}", output_path.display()),
            e,
        ));
    }

    Ok(ChecksumVerification {
        artifact_path: output_path.to_path_buf(),
        ..verification
    })
}
