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
                let seg_str = seg.to_string_lossy();
                if seg_str.is_empty() || seg_str == "." || seg_str == ".." {
                    return Err(HostBackupError::TraversalRejected {
                        path: rel_path.to_string(),
                        reason: "backup entry contains '.' or '..' segment".to_string(),
                    });
                }
                let seg_lower = seg_str.to_ascii_lowercase();
                if seg_lower == ".restore-provenance"
                    || seg_lower.starts_with(".rollback-restore.")
                    || seg_lower.starts_with(".staging-restore.")
                {
                    return Err(HostBackupError::UnsafeOverwriteRejected {
                        target: PathBuf::from(rel_path),
                        reason: "backup entry must not target protected recovery provenance or internal restore directories".to_string(),
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
        Err(err) if err.raw_os_error() == Some(libc::ENOTDIR) => {
            Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!(
                    "non-directory component encountered while inspecting {}: {}",
                    context, err
                ),
            })
        }
        Err(err) => Err(HostBackupError::io(
            format!(
                "inspecting symlink metadata for {} ({})",
                path.display(),
                context
            ),
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

    #[cfg(unix)]
    if dir.is_absolute() {
        use std::os::unix::io::AsRawFd;
        let dir_file = open_or_create_dir_nofollow(dir, 0o700, context)?;
        let mut st_buf: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(dir_file.as_raw_fd(), &mut st_buf) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat {} ({})", dir.display(), context),
                std::io::Error::last_os_error(),
            ));
        }
        let euid = unsafe { libc::geteuid() };
        if (st_buf.st_mode & 0o777) != 0o700 && (euid == 0 || st_buf.st_uid == euid) {
            let chmod_rc = unsafe { libc::fchmod(dir_file.as_raw_fd(), 0o700) };
            if chmod_rc != 0 {
                return Err(HostBackupError::io(
                    format!("fchmod 0700 on {} ({})", dir.display(), context),
                    std::io::Error::last_os_error(),
                ));
            }
        }
        return Ok(());
    }

    let mut acc = PathBuf::new();
    for comp in dir.components() {
        match comp {
            Component::Prefix(prefix_comp) => acc.push(prefix_comp.as_os_str()),
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
                                reason: format!(
                                    "{} component exists and is not a directory",
                                    context
                                ),
                            });
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        create_single_private_dir(&acc, context)?;
                    }
                    Err(err) => {
                        return Err(HostBackupError::io(
                            format!(
                                "inspecting directory component {} ({})",
                                acc.display(),
                                context
                            ),
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
        let meta = fs::symlink_metadata(dir).map_err(|err| {
            HostBackupError::io(format!("inspecting {} ({})", dir.display(), context), err)
        })?;
        if meta.file_type().is_symlink() {
            return Err(HostBackupError::SymlinkRejected {
                path: dir.to_path_buf(),
                reason: format!("{} is a symbolic link", context),
            });
        }
        if (meta.permissions().mode() & 0o777) != 0o700 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
                HostBackupError::io(
                    format!(
                        "setting 0700 permissions on {} ({})",
                        dir.display(),
                        context
                    ),
                    err,
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
                format!(
                    "creating private directory {} ({})",
                    path.display(),
                    context
                ),
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
                format!(
                    "creating private directory {} ({})",
                    path.display(),
                    context
                ),
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
            format!(
                "exclusively creating private file {} ({})",
                path.display(),
                context
            ),
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

/// Flushes directory entries for `dir` to durable storage (`fsync` on a directory descriptor on Unix).
pub fn sync_parent_directory(dir: &Path, context: &str) -> HostBackupResult<()> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::FromRawFd;

        let dir_c = CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
            HostBackupError::PathValidation {
                path: dir.to_path_buf(),
                reason: format!("{} directory path contains interior NUL byte", context),
            }
        })?;
        let dir_fd = unsafe {
            libc::open(
                dir_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if dir_fd < 0 {
            return Err(HostBackupError::io(
                format!(
                    "opening parent directory {} for fsync ({})",
                    dir.display(),
                    context
                ),
                std::io::Error::last_os_error(),
            ));
        }
        let dir_file = unsafe { File::from_raw_fd(dir_fd) };
        dir_file.sync_all().map_err(|err| {
            HostBackupError::io(
                format!("fsyncing parent directory {} ({})", dir.display(), context),
                err,
            )
        })?;
    }
    Ok(())
}

/// Atomically writes `bytes` to `target_path` via a `0600` exclusive temporary file + `sync_all` + `rename` + parent dir `sync_all`.
pub(crate) fn write_private_file_atomic(
    target_path: &Path,
    bytes: &[u8],
    tag: &str,
    context: &str,
) -> HostBackupResult<()> {
    let mut renamed_into_place = false;
    write_private_file_atomic_tracking_rename(
        target_path,
        bytes,
        tag,
        context,
        false,
        &mut renamed_into_place,
    )
}

pub(crate) fn write_private_file_atomic_tracking_rename(
    target_path: &Path,
    bytes: &[u8],
    tag: &str,
    context: &str,
    fail_parent_sync: bool,
    renamed_into_place: &mut bool,
) -> HostBackupResult<()> {
    *renamed_into_place = false;
    reject_if_symlink(target_path, context)?;
    let (tmp_path, mut tmp_file) = create_unique_private_temp_file(target_path, tag, context)?;
    if let Err(err) = tmp_file.write_all(bytes).and_then(|()| tmp_file.sync_all()) {
        drop(tmp_file);
        let _ = fs::remove_file(&tmp_path);
        return Err(HostBackupError::io(
            format!(
                "writing temporary file {} ({})",
                tmp_path.display(),
                context
            ),
            err,
        ));
    }
    drop(tmp_file);
    if let Err(err) = reject_if_symlink(target_path, context) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    if let Err(err) = fs::rename(&tmp_path, target_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(HostBackupError::io(
            format!(
                "renaming {} -> {} ({})",
                tmp_path.display(),
                target_path.display(),
                context
            ),
            err,
        ));
    }
    *renamed_into_place = true;
    if fail_parent_sync {
        return Err(HostBackupError::io(
            format!(
                "simulated parent directory sync failure after renaming {} ({})",
                target_path.display(),
                context
            ),
            std::io::Error::other("simulated parent directory sync failure after rename"),
        ));
    }
    if let Some(parent) = target_path.parent() {
        sync_parent_directory(parent, context)?;
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
        builder.create(&staging_dir).map_err(|err| {
            HostBackupError::io(
                format!(
                    "creating exclusive staging dir {} ({})",
                    staging_dir.display(),
                    context
                ),
                err,
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(&staging_dir).map_err(|err| {
            HostBackupError::io(
                format!(
                    "creating exclusive staging dir {} ({})",
                    staging_dir.display(),
                    context
                ),
                err,
            )
        })?;
    }
    sync_parent_directory(parent_dir, context)?;
    Ok(staging_dir)
}

/// Enforces `0600` permissions on an existing regular file on Unix after verifying it is not a symlink.
pub(crate) fn set_private_file_permissions(path: &Path, context: &str) -> HostBackupResult<()> {
    reject_if_symlink(path, context)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|err| {
            HostBackupError::io(
                format!(
                    "setting 0600 permissions on {} ({})",
                    path.display(),
                    context
                ),
                err,
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
    if suffix.len() != 5 || !suffix.bytes().all(|byte_val| byte_val.is_ascii_digit()) {
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
    let Some((mut file, _)) =
        open_verified_regular_file_for_read(file_path, None, "checksummed file")?
    else {
        return Err(HostBackupError::io(
            format!("opening {}", file_path.display()),
            std::io::Error::new(std::io::ErrorKind::NotFound, "checksummed file not found"),
        ));
    };
    compute_reader_sha256(&mut file, file_path)
}

pub(crate) fn compute_reader_sha256<R: Read>(
    reader: &mut R,
    file_path: &Path,
) -> HostBackupResult<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;

    loop {
        let count = reader
            .read(&mut buf)
            .map_err(|err| HostBackupError::io(format!("reading {}", file_path.display()), err))?;
        if count == 0 {
            break;
        }
        hasher.update(&buf[..count]);
        total_bytes += count as u64;
    }

    Ok((hex::encode(hasher.finalize()), total_bytes))
}

pub fn open_verified_regular_file_for_read(
    path: &Path,
    extra_trusted_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<Option<(File, u64)>> {
    validate_no_parent_traversal(path, context)?;
    let resolved_abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        reject_if_symlink(path, context)?;
        let cwd = std::env::current_dir().map_err(|err| {
            HostBackupError::io(
                format!(
                    "resolving current working directory for {} ({})",
                    path.display(),
                    context
                ),
                err,
            )
        })?;
        cwd.join(path)
    };
    let Some((file, _, _, _)) =
        open_existing_regular_file_nofollow(&resolved_abs, extra_trusted_uid, context)?
    else {
        return Ok(None);
    };
    #[cfg(unix)]
    let byte_len = {
        use std::os::unix::io::AsRawFd;
        let mut st_buf: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut st_buf) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat {} ({})", path.display(), context),
                std::io::Error::last_os_error(),
            ));
        }
        if st_buf.st_nlink == 0 {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("{} was unlinked during open", context),
            });
        }
        st_buf.st_size.max(0) as u64
    };
    #[cfg(not(unix))]
    let byte_len = file
        .metadata()
        .map_err(|err| {
            HostBackupError::io(format!("metadata {} ({})", path.display(), context), err)
        })?
        .len();
    Ok(Some((file, byte_len)))
}

pub fn read_verified_text_file_nofollow(
    path: &Path,
    extra_trusted_uid: Option<u32>,
    max_bytes: u64,
    context: &str,
) -> HostBackupResult<Option<String>> {
    let Some((file, byte_len)) =
        open_verified_regular_file_for_read(path, extra_trusted_uid, context)?
    else {
        return Ok(None);
    };
    if byte_len > max_bytes {
        return Err(HostBackupError::InvalidManifest(format!(
            "{} '{}' exceeds maximum allowed size ({} > {} bytes)",
            context,
            path.display(),
            byte_len,
            max_bytes
        )));
    }
    let mut raw_bytes = Vec::new();
    let mut bounded = file.take(max_bytes.saturating_add(1));
    bounded.read_to_end(&mut raw_bytes).map_err(|err| {
        HostBackupError::io(format!("reading {} ({})", path.display(), context), err)
    })?;
    if raw_bytes.len() as u64 > max_bytes {
        return Err(HostBackupError::InvalidManifest(format!(
            "{} '{}' exceeds maximum allowed size ({} bytes)",
            context,
            path.display(),
            max_bytes
        )));
    }
    String::from_utf8(raw_bytes)
        .map_err(|_| {
            HostBackupError::InvalidManifest(format!(
                "{} '{}' contains invalid UTF-8 bytes (contents redacted)",
                context,
                path.display()
            ))
        })
        .map(Some)
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
            "malformed SHA-256 digest in sidecar (expected 64 hex characters, got {} characters; token redacted)",
            first_token.chars().count()
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

    write_private_file_atomic(
        &sidecar,
        formatted.as_bytes(),
        "sidecar-tmp",
        "checksum sidecar",
    )?;

    Ok((sidecar, digest, size_bytes))
}

/// Verifies `file_path` against an explicit expected SHA-256 hex digest.
pub fn verify_file_sha256(
    file_path: &Path,
    expected_sha256: &str,
) -> HostBackupResult<ChecksumVerification> {
    verify_file_sha256_with_trusted_uid(file_path, expected_sha256, None)
}

/// Variant of [`verify_file_sha256`] that accepts an explicit caller-configured `trusted_uid`.
pub fn verify_file_sha256_with_trusted_uid(
    file_path: &Path,
    expected_sha256: &str,
    trusted_uid: Option<u32>,
) -> HostBackupResult<ChecksumVerification> {
    let expected_clean = expected_sha256.trim().to_ascii_lowercase();
    if !SHA256_HEX_RE.is_match(&expected_clean) {
        return Err(HostBackupError::InvalidManifest(format!(
            "expected SHA-256 is not a valid 64-char hex digest (length={}; value redacted)",
            expected_clean.chars().count()
        )));
    }

    let Some((mut file, _)) =
        open_verified_regular_file_for_read(file_path, trusted_uid, "checksummed file")?
    else {
        return Err(HostBackupError::PathValidation {
            path: file_path.to_path_buf(),
            reason: "checksummed file does not exist or is not a regular file".to_string(),
        });
    };
    let (actual, size_bytes) = compute_reader_sha256(&mut file, file_path)?;
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
    verify_file_with_sidecar_and_trusted_uid(file_path, None)
}

/// Variant of [`verify_file_with_sidecar`] that accepts an explicit caller-configured `trusted_uid`.
pub fn verify_file_with_sidecar_and_trusted_uid(
    file_path: &Path,
    trusted_uid: Option<u32>,
) -> HostBackupResult<ChecksumVerification> {
    let Some((mut art_file, _)) =
        open_verified_regular_file_for_read(file_path, trusted_uid, "backup artifact")?
    else {
        return Err(HostBackupError::PathValidation {
            path: file_path.to_path_buf(),
            reason: "backup artifact does not exist or is not a regular file".to_string(),
        });
    };

    let sidecar = checksum_sidecar_path(file_path);
    let raw_sidecar = match read_verified_text_file_nofollow(
        &sidecar,
        trusted_uid,
        64 * 1024,
        "checksum sidecar",
    ) {
        Ok(Some(text)) => text,
        Ok(None) => {
            return Err(HostBackupError::MissingChecksumSidecar {
                artifact: file_path.to_path_buf(),
                sidecar_path: sidecar,
            });
        }
        Err(HostBackupError::UnsafeOverwriteRejected { .. }) => {
            return Err(HostBackupError::MissingChecksumSidecar {
                artifact: file_path.to_path_buf(),
                sidecar_path: sidecar,
            });
        }
        Err(other_err) => return Err(other_err),
    };

    let expected = parse_sha256_sidecar_str(&raw_sidecar)?;
    let (actual, size_bytes) = compute_reader_sha256(&mut art_file, file_path)?;
    if actual != expected {
        return Err(HostBackupError::ChecksumMismatch {
            artifact: file_path.display().to_string(),
            expected,
            actual,
        });
    }

    Ok(ChecksumVerification {
        artifact_path: file_path.to_path_buf(),
        sidecar_path: Some(sidecar),
        expected_sha256: expected,
        actual_sha256: actual,
        size_bytes,
        verified: true,
    })
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
        .map_err(|err| HostBackupError::io(format!("reading {}", parent.display()), err))?
    {
        let entry = entry.map_err(|err| HostBackupError::io("reading chunk dir entry", err))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if parse_exact_chunk_index(base_name, &name).is_some() {
            let chunk_path = entry.path();
            let meta = fs::symlink_metadata(&chunk_path).map_err(|err| {
                HostBackupError::io(format!("stat chunk {}", chunk_path.display()), err)
            })?;
            if meta.file_type().is_symlink() {
                return Err(HostBackupError::SymlinkRejected {
                    path: chunk_path,
                    reason: "existing backup chunk is a symbolic link".to_string(),
                });
            }
            if !meta.is_file() {
                return Err(HostBackupError::ChunkError {
                    artifact: file_path.to_path_buf(),
                    reason: format!(
                        "existing chunk path '{}' is not a regular file",
                        chunk_path.display()
                    ),
                });
            }
            fs::remove_file(&chunk_path).map_err(|err| {
                HostBackupError::io(
                    format!("removing stale chunk {}", chunk_path.display()),
                    err,
                )
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
        .map_err(|err| HostBackupError::io(format!("opening {}", file_path.display()), err))?;

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
                let count = src.read(&mut buf[..to_read]).map_err(|err| {
                    HostBackupError::io(format!("reading {}", file_path.display()), err)
                })?;
                if count == 0 {
                    break;
                }
                if part_file.is_none() {
                    let created_file = create_private_new_file(&part_path, "backup chunk output")?;
                    chunks.push(part_path.clone());
                    part_file = Some(created_file);
                }
                if let Some(ref mut out) = part_file {
                    out.write_all(&buf[..count]).map_err(|err| {
                        HostBackupError::io(format!("writing chunk {}", part_path.display()), err)
                    })?;
                }
                wrote_any = true;
                remaining -= count as u64;
            }

            if let Some(out) = part_file {
                out.sync_all().map_err(|err| {
                    HostBackupError::io(format!("syncing chunk {}", part_path.display()), err)
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

    if let Some(parent) = file_path.parent() {
        sync_parent_directory(parent, "chunk split directory")?;
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
        let mut part_file =
            match open_verified_regular_file_for_read(part, None, "backup chunk part") {
                Ok(Some((opened, _))) => opened,
                Ok(None) => {
                    drop(out);
                    let _ = fs::remove_file(&tmp_out);
                    return Err(HostBackupError::ChunkError {
                        artifact: output_path.to_path_buf(),
                        reason: format!("missing chunk file: {}", part.display()),
                    });
                }
                Err(HostBackupError::UnsafeOverwriteRejected { .. })
                | Err(HostBackupError::PathValidation { .. }) => {
                    drop(out);
                    let _ = fs::remove_file(&tmp_out);
                    return Err(HostBackupError::ChunkError {
                        artifact: output_path.to_path_buf(),
                        reason: format!("chunk path is not a regular file: {}", part.display()),
                    });
                }
                Err(err) => {
                    drop(out);
                    let _ = fs::remove_file(&tmp_out);
                    return Err(err);
                }
            };
        if let Err(err) = std::io::copy(&mut part_file, &mut out) {
            drop(out);
            let _ = fs::remove_file(&tmp_out);
            return Err(HostBackupError::io(
                format!("copying chunk {}", part.display()),
                err,
            ));
        }
    }

    if let Err(err) = out.sync_all() {
        drop(out);
        let _ = fs::remove_file(&tmp_out);
        return Err(HostBackupError::io(
            format!("syncing assembled file {}", tmp_out.display()),
            err,
        ));
    }
    drop(out);

    let verification = match verify_file_sha256(&tmp_out, expected_sha256) {
        Ok(ver) => ver,
        Err(err) => {
            let _ = fs::remove_file(&tmp_out);
            return Err(err);
        }
    };

    if let Err(err) = reject_if_symlink(output_path, "assembled backup target") {
        let _ = fs::remove_file(&tmp_out);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_out, output_path) {
        let _ = fs::remove_file(&tmp_out);
        return Err(HostBackupError::io(
            format!("activating assembled backup {}", output_path.display()),
            err,
        ));
    }

    if let Some(parent) = output_path.parent() {
        sync_parent_directory(parent, "activating assembled backup")?;
    }

    Ok(ChecksumVerification {
        artifact_path: output_path.to_path_buf(),
        ..verification
    })
}

/// Default system-wide maintenance lockfile path shared across `af-runner`, `af-api`,
/// `af-services`, `af-release`, `af-cli`, `deploy/release-manager.sh`, and `af-backup`.
pub const DEFAULT_MAINTENANCE_LOCK_PATH: &str = "/run/aetherflow/.snapshot.lock";

fn normalize_maintenance_lock_fallback_dir(candidate_dir: &Path) -> PathBuf {
    let mut current = candidate_dir;
    if current.file_name().and_then(|os_val| os_val.to_str()) == Some(".snapshot.lock") {
        if let Some(parent) = current.parent() {
            if !parent.as_os_str().is_empty() {
                current = parent;
            }
        }
    }
    if current
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "sqlite" | "db" | "sqlite3" | "gz" | "json"
            )
        })
        .unwrap_or(false)
    {
        if let Some(parent) = current.parent() {
            if !parent.as_os_str().is_empty() {
                current = parent;
            }
        }
    }

    let comps: Vec<Component<'_>> = current.components().collect();
    if comps.len() >= 3 {
        for idx in 0..=(comps.len() - 3) {
            if comps[idx].as_os_str() == "var"
                && comps[idx + 1].as_os_str() == "lib"
                && comps[idx + 2].as_os_str() == "aetherflow"
            {
                let mut state_dir = PathBuf::new();
                for seg in &comps[..=(idx + 2)] {
                    state_dir.push(seg.as_os_str());
                }
                return state_dir;
            }
        }
    }

    if comps.len() >= 2 {
        for idx in 0..=(comps.len() - 2) {
            let first_seg = comps[idx].as_os_str().to_string_lossy();
            let second_seg = comps[idx + 1].as_os_str().to_string_lossy();
            if (first_seg.eq_ignore_ascii_case("etc") || first_seg.eq_ignore_ascii_case("opt"))
                && second_seg.eq_ignore_ascii_case("aetherflow")
            {
                let mut prefix_root = PathBuf::new();
                for seg in &comps[..idx] {
                    prefix_root.push(seg.as_os_str());
                }
                if prefix_root.as_os_str().is_empty() {
                    prefix_root.push("/");
                }
                return prefix_root.join("var/lib/aetherflow");
            }
        }
    }

    while let Some(leaf) = current.file_name().and_then(|os_val| os_val.to_str()) {
        let is_sub_dir = matches!(
            leaf,
            "backups"
                | "restore-staging"
                | ".restore-provenance"
                | ".self-update-jobs"
                | "releases"
        ) || leaf.starts_with(".staging-")
            || leaf.starts_with(".rollback-restore.");
        if is_sub_dir {
            if let Some(parent) = current.parent() {
                if !parent.as_os_str().is_empty() {
                    current = parent;
                    continue;
                }
            }
        }
        break;
    }

    current.to_path_buf()
}

/// Resolves the shared cross-process maintenance lockfile path.
pub fn resolve_maintenance_lock_path(fallback_dir: Option<&Path>) -> PathBuf {
    if let Ok(raw) = std::env::var("AETHERFLOW_MAINTENANCE_LOCK_PATH") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    let has_explicit_db_or_root_env = [
        "AETHERFLOW_BACKUP_ISOLATED_ROOT",
        "AETHERFLOW_RESTORE_STAGING_ROOT",
        "AETHERFLOW_DB_PATH",
        "DB_PATH",
        "DATA_DIR",
    ]
    .iter()
    .any(|env_key| {
        std::env::var(env_key)
            .ok()
            .map(|val| !val.trim().is_empty())
            .unwrap_or(false)
    });

    let normalized_fallback = fallback_dir
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(normalize_maintenance_lock_fallback_dir);

    if has_explicit_db_or_root_env {
        if let Ok(resolved) = af_models::try_resolve_canonical_maintenance_lock_path_with_env(
            None,
            None,
            normalized_fallback.as_deref(),
            |env_key| std::env::var(env_key).ok(),
        ) {
            return resolved;
        }
    }

    if let Some(state_dir) = normalized_fallback {
        if state_dir == Path::new("/var/lib/aetherflow") {
            return PathBuf::from(DEFAULT_MAINTENANCE_LOCK_PATH);
        }
        let comps: Vec<Component<'_>> = state_dir.components().collect();
        if comps.len() >= 3
            && comps[comps.len() - 3].as_os_str() == "var"
            && comps[comps.len() - 2].as_os_str() == "lib"
            && comps[comps.len() - 1].as_os_str() == "aetherflow"
        {
            let mut prefix_root = PathBuf::new();
            for seg in &comps[..(comps.len() - 3)] {
                prefix_root.push(seg.as_os_str());
            }
            if !prefix_root.as_os_str().is_empty() && prefix_root != Path::new("/") {
                let candidate_run_dir = prefix_root.join("run/aetherflow");
                let mut map_to_run = candidate_run_dir.exists();
                #[cfg(unix)]
                if !map_to_run {
                    use std::os::unix::fs::MetadataExt;
                    if let (Ok(root_meta), Ok(var_meta)) = (
                        fs::symlink_metadata(&prefix_root),
                        fs::symlink_metadata(&state_dir),
                    ) {
                        if root_meta.uid() == 0 && var_meta.uid() != 0 {
                            map_to_run = true;
                        }
                    }
                }
                if map_to_run {
                    return candidate_run_dir.join(".snapshot.lock");
                }
            }
        }
        return state_dir.join(".snapshot.lock");
    }

    if let Ok(resolved) =
        af_models::try_resolve_canonical_maintenance_lock_path_from_env(None, None, None)
    {
        return resolved;
    }
    PathBuf::from(DEFAULT_MAINTENANCE_LOCK_PATH)
}

/// Resolves the UID and primary GID of the packaged `aetherflow` service user on Unix
/// (or an explicit numeric override via `AETHERFLOW_SERVICE_UID` / `AETHERFLOW_SERVICE_GID`
/// or account name override via `AETHERFLOW_SERVICE_USER`).
#[cfg(unix)]
pub fn resolve_trusted_service_account_ids() -> Option<(u32, u32)> {
    let uid_override = std::env::var("AETHERFLOW_SERVICE_UID")
        .ok()
        .and_then(|val| val.trim().parse::<u32>().ok());
    let gid_override = std::env::var("AETHERFLOW_SERVICE_GID")
        .ok()
        .and_then(|val| val.trim().parse::<u32>().ok());
    if let (Some(uid_val), Some(gid_val)) = (uid_override, gid_override) {
        return Some((uid_val, gid_val));
    }

    let account_name = std::env::var("AETHERFLOW_SERVICE_USER")
        .ok()
        .map(|val| val.trim().to_string())
        .filter(|val| !val.is_empty())
        .unwrap_or_else(|| "aetherflow".to_string());

    let account_c = std::ffi::CString::new(account_name).ok()?;
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0u8; 4096];
        let rc = libc::getpwnam_r(
            account_c.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        );
        if rc == 0 && !result.is_null() {
            let resolved_uid = uid_override.unwrap_or(pwd.pw_uid);
            let resolved_gid = gid_override.unwrap_or(pwd.pw_gid);
            return Some((resolved_uid, resolved_gid));
        }
    }
    uid_override.map(|uid_val| (uid_val, gid_override.unwrap_or(uid_val)))
}

#[cfg(not(unix))]
pub fn resolve_trusted_service_account_ids() -> Option<(u32, u32)> {
    None
}

/// Exclusive cross-process maintenance lock guard backed by `flock(LOCK_EX)` on Unix
/// (and an exclusive lockfile on non-Unix).
///
/// Serializes all mutating backup, restore, retention prune, and release self-update
/// operations across processes (`af-api`, `af-runner`, `af-services`, `af-cli`, `af-release`).
#[derive(Debug)]
pub struct HostMaintenanceLockGuard {
    lock_path: PathBuf,
    _file: File,
    #[cfg(unix)]
    parent_dir: File,
    #[cfg(unix)]
    leaf_name: String,
    #[cfg(unix)]
    locked_dev: u64,
    #[cfg(unix)]
    locked_ino: u64,
}

impl HostMaintenanceLockGuard {
    /// Acquires the exclusive maintenance lock at `lock_path`, waiting up to `timeout`.
    pub fn acquire(
        lock_path: impl AsRef<Path>,
        timeout: std::time::Duration,
    ) -> HostBackupResult<Self> {
        let path = lock_path.as_ref().to_path_buf();
        validate_no_parent_traversal(&path, "maintenance lock path")?;
        reject_if_symlink(&path, "maintenance lockfile")?;

        let start = std::time::Instant::now();
        loop {
            match Self::try_acquire_once(&path) {
                Ok(guard) => return Ok(guard),
                Err(AcquireAttemptError::Fatal(err)) => return Err(err),
                Err(AcquireAttemptError::Busy(reason)) => {
                    if start.elapsed() >= timeout {
                        return Err(HostBackupError::InvalidConfig(format!(
                            "maintenance lock busy at '{}': {}",
                            path.display(),
                            reason
                        )));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }
    }

    /// Acquires the default shared maintenance lock (resolving via [`resolve_maintenance_lock_path`]).
    pub fn acquire_default(
        fallback_dir: Option<&Path>,
        timeout: std::time::Duration,
    ) -> HostBackupResult<Self> {
        let primary = resolve_maintenance_lock_path(fallback_dir);
        Self::acquire(&primary, timeout)
    }

    /// Verifies that the held lock descriptor is still linked at `self.lock_path` under the
    /// pinned parent directory descriptor with the exact `(st_dev, st_ino)` acquired, and has
    /// not been unlinked, renamed, or replaced during the guarded maintenance operation.
    pub fn verify_still_active(&self) -> HostBackupResult<()> {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::os::unix::io::AsRawFd;

            let euid = unsafe { libc::geteuid() };
            let mut fd_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(self._file.as_raw_fd(), &mut fd_st) } != 0 {
                return Err(HostBackupError::io(
                    format!(
                        "fstat active maintenance lockfile {}",
                        self.lock_path.display()
                    ),
                    std::io::Error::last_os_error(),
                ));
            }
            if fd_st.st_nlink == 0 {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lockfile was unlinked while lock guard was held"
                        .to_string(),
                });
            }
            if fd_st.st_nlink > 1 {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lockfile has multiple hard links while held".to_string(),
                });
            }

            let leaf_c = CString::new(self.leaf_name.as_str()).map_err(|_| {
                HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lock filename contains NUL byte".to_string(),
                }
            })?;
            let mut dir_leaf_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    self.parent_dir.as_raw_fd(),
                    leaf_c.as_ptr(),
                    &mut dir_leaf_st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lockfile disappeared from parent directory while held"
                        .to_string(),
                });
            }
            if (dir_leaf_st.st_mode & libc::S_IFMT) != libc::S_IFREG
                || dir_leaf_st.st_dev as u64 != self.locked_dev
                || dir_leaf_st.st_ino as u64 != self.locked_ino
                || fd_st.st_dev as u64 != self.locked_dev
                || fd_st.st_ino as u64 != self.locked_ino
            {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason:
                        "maintenance lockfile inode was substituted in parent directory while held"
                            .to_string(),
                });
            }

            let parent_path = self.lock_path.parent().unwrap_or_else(|| Path::new("/"));
            let verified_parent_opt = open_existing_dir_nofollow_optional_with_trusted_uid(
                parent_path,
                None,
                euid != 0,
                "active maintenance lock parent",
            )?;
            let Some(verified_parent_dir) = verified_parent_opt else {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lock parent directory disappeared while held".to_string(),
                });
            };
            let mut verified_parent_st: libc::stat = unsafe { std::mem::zeroed() };
            let mut parent_fd_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(verified_parent_dir.as_raw_fd(), &mut verified_parent_st) } != 0
                || unsafe { libc::fstat(self.parent_dir.as_raw_fd(), &mut parent_fd_st) } != 0
                || verified_parent_st.st_dev != parent_fd_st.st_dev
                || verified_parent_st.st_ino != parent_fd_st.st_ino
            {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lock parent directory was renamed or replaced while held"
                        .to_string(),
                });
            }
            let mut active_leaf_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    verified_parent_dir.as_raw_fd(),
                    leaf_c.as_ptr(),
                    &mut active_leaf_st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
                || active_leaf_st.st_dev as u64 != self.locked_dev
                || active_leaf_st.st_ino as u64 != self.locked_ino
            {
                return Err(HostBackupError::PathValidation {
                    path: self.lock_path.clone(),
                    reason: "maintenance lockfile path no longer resolves to held lock inode"
                        .to_string(),
                });
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn try_acquire_once(path: &Path) -> Result<Self, AcquireAttemptError> {
        use std::ffi::CString;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let parent = path.parent().ok_or_else(|| {
            AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: "maintenance lock path must have a parent directory".to_string(),
            })
        })?;
        let leaf_name = path
            .file_name()
            .and_then(|os_val| os_val.to_str())
            .ok_or_else(|| {
                AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: "maintenance lock path must have a valid file name".to_string(),
                })
            })?;

        let service_ids = resolve_trusted_service_account_ids();
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        let (_target_uid, target_gid) = if let Some((svc_uid, svc_gid)) = service_ids {
            (svc_uid as libc::uid_t, svc_gid as libc::gid_t)
        } else {
            (euid, egid)
        };

        let parent_dir = open_or_create_lock_parent_dir_nofollow(
            parent,
            euid,
            target_gid,
            "maintenance lock parent",
        )
        .map_err(AcquireAttemptError::Fatal)?;
        let parent_dfd = parent_dir.as_raw_fd();

        let mut parent_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(parent_dfd, &mut parent_st) } != 0 {
            return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                format!("fstat maintenance lock parent {}", parent.display()),
                std::io::Error::last_os_error(),
            )));
        }

        if euid == 0 {
            if parent_st.st_uid != 0 {
                return Err(AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                    path: parent.to_path_buf(),
                    reason: format!(
                        "maintenance lock parent '{}' is owned by non-root uid={} while acquiring lock as root; refusing replaceable lock parent",
                        parent.display(),
                        parent_st.st_uid
                    ),
                }));
            }
            if (parent_st.st_mode & 0o020) != 0
                && parent_st.st_gid != 0
                && (parent_st.st_mode & libc::S_ISVTX) == 0
            {
                return Err(AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                    path: parent.to_path_buf(),
                    reason: format!(
                        "maintenance lock parent '{}' is group-writable without sticky bit (mode {:o})",
                        parent.display(),
                        parent_st.st_mode & 0o7777
                    ),
                }));
            }
        }

        let leaf_c = CString::new(leaf_name).map_err(|_| {
            AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: "maintenance lock filename contains NUL byte".to_string(),
            })
        })?;

        let mut lock_fd = unsafe {
            libc::openat(
                parent_dfd,
                leaf_c.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if lock_fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            lock_fd = unsafe {
                libc::openat(
                    parent_dfd,
                    leaf_c.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    0o660 as libc::c_uint,
                )
            };
            if lock_fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                return Err(AcquireAttemptError::Busy(
                    "maintenance lockfile created concurrently during openat".to_string(),
                ));
            }
        }
        if lock_fd < 0 {
            let open_err = std::io::Error::last_os_error();
            let mut err_st: libc::stat = unsafe { std::mem::zeroed() };
            let st_rc = unsafe {
                libc::fstatat(
                    parent_dfd,
                    leaf_c.as_ptr(),
                    &mut err_st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if st_rc == 0 && (err_st.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                return Err(AcquireAttemptError::Fatal(
                    HostBackupError::SymlinkRejected {
                        path: path.to_path_buf(),
                        reason: "maintenance lockfile is a symbolic link".to_string(),
                    },
                ));
            }
            if open_err.raw_os_error() == Some(libc::ELOOP) {
                return Err(AcquireAttemptError::Fatal(
                    HostBackupError::SymlinkRejected {
                        path: path.to_path_buf(),
                        reason: "maintenance lockfile is a symbolic link (ELOOP)".to_string(),
                    },
                ));
            }
            if open_err.raw_os_error() == Some(libc::EISDIR)
                || (st_rc == 0 && (err_st.st_mode & libc::S_IFMT) != libc::S_IFREG)
            {
                return Err(AcquireAttemptError::Fatal(
                    HostBackupError::PathValidation {
                        path: path.to_path_buf(),
                        reason: "maintenance lockfile exists and is not a regular file".to_string(),
                    },
                ));
            }
            return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                format!("opening maintenance lockfile {}", path.display()),
                open_err,
            )));
        }

        let mut file = unsafe { File::from_raw_fd(lock_fd) };
        let mut opened_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut opened_st) } != 0 {
            return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                format!("fstat opened maintenance lockfile {}", path.display()),
                std::io::Error::last_os_error(),
            )));
        }
        if (opened_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(AcquireAttemptError::Fatal(
                HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: "opened maintenance lockfile is not a regular file".to_string(),
                },
            ));
        }
        if opened_st.st_nlink > 1 {
            return Err(AcquireAttemptError::Fatal(
                HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: "opened maintenance lockfile has multiple hard links".to_string(),
                },
            ));
        }
        let allowed_owner = opened_st.st_uid == 0
            || opened_st.st_uid == euid
            || service_ids
                .map(|(svc_uid, _)| opened_st.st_uid == svc_uid as libc::uid_t)
                .unwrap_or(false);
        if !allowed_owner {
            return Err(AcquireAttemptError::Fatal(
                HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "maintenance lockfile '{}' has untrusted owner uid={}",
                        path.display(),
                        opened_st.st_uid
                    ),
                },
            ));
        }
        if (opened_st.st_mode & 0o002) != 0 {
            return Err(AcquireAttemptError::Fatal(
                HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "maintenance lockfile '{}' has unsafe world-writable permissions {:o}",
                        path.display(),
                        opened_st.st_mode & 0o777
                    ),
                },
            ));
        }

        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(AcquireAttemptError::Busy(format!(
                "flock(LOCK_EX | LOCK_NB) busy: {}",
                err
            )));
        }

        let mut verify_leaf_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                parent_dfd,
                leaf_c.as_ptr(),
                &mut verify_leaf_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
            || verify_leaf_st.st_dev != opened_st.st_dev
            || verify_leaf_st.st_ino != opened_st.st_ino
            || opened_st.st_nlink == 0
        {
            return Err(AcquireAttemptError::Busy(
                "lockfile inode changed during acquisition".to_string(),
            ));
        }

        if euid == 0 {
            if opened_st.st_uid != 0 || opened_st.st_gid != target_gid {
                let chown_rc = unsafe { libc::fchown(file.as_raw_fd(), 0, target_gid) };
                if chown_rc != 0 {
                    return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                        format!("fchown maintenance lockfile {}", path.display()),
                        std::io::Error::last_os_error(),
                    )));
                }
            }
            let chmod_rc = unsafe { libc::fchmod(file.as_raw_fd(), 0o660) };
            if chmod_rc != 0 {
                return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                    format!("fchmod maintenance lockfile {}", path.display()),
                    std::io::Error::last_os_error(),
                )));
            }
            let mut post_st: libc::stat = unsafe { std::mem::zeroed() };
            let mut post_leaf_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(file.as_raw_fd(), &mut post_st) } != 0
                || unsafe {
                    libc::fstatat(
                        parent_dfd,
                        leaf_c.as_ptr(),
                        &mut post_leaf_st,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } != 0
                || post_st.st_uid != 0
                || post_st.st_gid != target_gid
                || (post_st.st_mode & 0o777) != 0o660
                || post_st.st_nlink != 1
                || post_leaf_st.st_dev != opened_st.st_dev
                || post_leaf_st.st_ino != opened_st.st_ino
            {
                return Err(AcquireAttemptError::Fatal(HostBackupError::PathValidation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "maintenance lockfile '{}' metadata after root normalization is incompatible",
                        path.display()
                    ),
                }));
            }
        } else {
            let explicit_gid_override = std::env::var("AETHERFLOW_SERVICE_GID")
                .ok()
                .and_then(|val| val.trim().parse::<u32>().ok());
            let explicit_uid_override = std::env::var("AETHERFLOW_SERVICE_UID")
                .ok()
                .and_then(|val| val.trim().parse::<u32>().ok());
            let explicit_user_override = std::env::var("AETHERFLOW_SERVICE_USER")
                .ok()
                .map(|val| !val.trim().is_empty())
                .unwrap_or(false);
            let is_service_context = explicit_gid_override.is_some()
                || explicit_uid_override.is_some()
                || explicit_user_override
                || path.starts_with("/var/lib/aetherflow")
                || path.starts_with("/run/aetherflow")
                || service_ids
                    .map(|(svc_uid, svc_gid)| {
                        euid == svc_uid as libc::uid_t
                            || parent_st.st_uid == svc_uid as libc::uid_t
                            || parent_st.st_gid == svc_gid as libc::gid_t
                            || opened_st.st_uid == svc_uid as libc::uid_t
                            || opened_st.st_gid == svc_gid as libc::gid_t
                    })
                    .unwrap_or(false);
            let has_service_target_gid = explicit_gid_override.is_some() || service_ids.is_some();
            let expected_gid = if is_service_context && has_service_target_gid {
                target_gid
            } else {
                egid
            };

            if opened_st.st_uid == euid {
                if opened_st.st_gid != expected_gid {
                    let chown_rc = unsafe {
                        libc::fchown(file.as_raw_fd(), u32::MAX as libc::uid_t, expected_gid)
                    };
                    if chown_rc != 0 {
                        let chown_err = std::io::Error::last_os_error();
                        return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                            format!(
                                "fchown maintenance lockfile {} to expected gid={}",
                                path.display(),
                                expected_gid
                            ),
                            chown_err,
                        )));
                    }
                }
                if (opened_st.st_mode & 0o777) != 0o660 {
                    let chmod_rc = unsafe { libc::fchmod(file.as_raw_fd(), 0o660) };
                    if chmod_rc != 0 {
                        return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                            format!("fchmod maintenance lockfile {}", path.display()),
                            std::io::Error::last_os_error(),
                        )));
                    }
                }
            }

            let mut post_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(file.as_raw_fd(), &mut post_st) } != 0 {
                return Err(AcquireAttemptError::Fatal(HostBackupError::io(
                    format!(
                        "fstat maintenance lockfile {} after metadata check",
                        path.display()
                    ),
                    std::io::Error::last_os_error(),
                )));
            }
            if (post_st.st_mode & 0o777) != 0o660 {
                return Err(AcquireAttemptError::Fatal(
                    HostBackupError::PathValidation {
                        path: path.to_path_buf(),
                        reason: format!(
                        "maintenance lockfile '{}' has incompatible mode {:04o} (expected 0660)",
                        path.display(),
                        post_st.st_mode & 0o777
                    ),
                    },
                ));
            }
            let gid_compatible = post_st.st_gid == expected_gid
                || (!is_service_context
                    && (parent_st.st_mode & libc::S_ISGID) != 0
                    && post_st.st_gid == parent_st.st_gid);
            if !gid_compatible {
                return Err(AcquireAttemptError::Fatal(
                    HostBackupError::PathValidation {
                        path: path.to_path_buf(),
                        reason: format!(
                        "maintenance lockfile '{}' resulting gid={} does not match expected gid={}",
                        path.display(),
                        post_st.st_gid,
                        expected_gid
                    ),
                    },
                ));
            }
        }

        let _ = file.set_len(0);
        let _ = writeln!(file, "pid={}", std::process::id());
        let _ = file.flush();

        let guard = Self {
            lock_path: path.to_path_buf(),
            _file: file,
            parent_dir,
            leaf_name: leaf_name.to_string(),
            locked_dev: opened_st.st_dev as u64,
            locked_ino: opened_st.st_ino as u64,
        };
        guard
            .verify_still_active()
            .map_err(AcquireAttemptError::Fatal)?;
        Ok(guard)
    }

    #[cfg(not(unix))]
    fn try_acquire_once(path: &Path) -> Result<Self, AcquireAttemptError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|err| AcquireAttemptError::Busy(format!("lockfile already held: {}", err)))?;

        let _ = writeln!(file, "pid={}", std::process::id());
        let _ = file.flush();

        Ok(Self {
            lock_path: path.to_path_buf(),
            _file: file,
        })
    }

    pub fn path(&self) -> &Path {
        &self.lock_path
    }
}

enum AcquireAttemptError {
    Busy(String),
    Fatal(HostBackupError),
}

impl Drop for HostMaintenanceLockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let _ = libc::flock(self._file.as_raw_fd(), libc::LOCK_UN);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = fs::remove_file(&self.lock_path);
        }
    }
}

/// Enforces trusted ancestor policy and no-symlink traversal on `dir`, creating missing
/// leaf directories step-by-step using `openat` + `mkdirat` with `O_NOFOLLOW | O_DIRECTORY`
/// on Unix, and returns an open directory `File` handle pinned to the verified leaf directory.
pub fn open_or_create_dir_nofollow(
    dir: &Path,
    create_mode: u32,
    context: &str,
) -> HostBackupResult<File> {
    open_or_create_dir_nofollow_with_trusted_uid(dir, create_mode, None, context)
}

/// Variant of [`open_or_create_dir_nofollow`] that also accepts an explicit trusted service owner
/// UID (`extra_trusted_uid`) for AetherFlow state/data/home/staging directories.
pub fn open_or_create_dir_nofollow_with_trusted_uid(
    dir: &Path,
    create_mode: u32,
    extra_trusted_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<File> {
    open_or_create_dir_nofollow_internal(dir, create_mode, extra_trusted_uid, true, context)
}

/// Opens or creates a protected recovery provenance directory where every ancestor and the leaf
/// directory itself must be owned by `root` (`0`) or the current effective UID (`geteuid()`),
/// never delegating directory ownership trust to an unprivileged service UID when running as `root`.
pub fn open_or_create_provenance_dir_nofollow(dir: &Path, context: &str) -> HostBackupResult<File> {
    let dir_file = open_or_create_dir_nofollow_internal(dir, 0o700, None, false, context)?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let euid = unsafe { libc::geteuid() };
        let mut st_buf: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(dir_file.as_raw_fd(), &mut st_buf) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat provenance dir {} ({})", dir.display(), context),
                std::io::Error::last_os_error(),
            ));
        }
        if st_buf.st_uid != euid {
            return Err(HostBackupError::PathValidation {
                path: dir.to_path_buf(),
                reason: format!(
                    "{} must be owned by current executor uid={}, found uid={}",
                    context, euid, st_buf.st_uid
                ),
            });
        }
        if (st_buf.st_mode & 0o777) != 0o700 {
            let chmod_rc = unsafe { libc::fchmod(dir_file.as_raw_fd(), 0o700) };
            if chmod_rc != 0 {
                return Err(HostBackupError::io(
                    format!("fchmod 0700 provenance dir {} ({})", dir.display(), context),
                    std::io::Error::last_os_error(),
                ));
            }
        }
    }
    Ok(dir_file)
}

/// Opens or creates a maintenance lock parent directory with root-only ancestor ownership
/// enforcement when running as `root` (`euid == 0`) and sticky shared permissions (`01770`, `root:target_gid`)
/// on `/run/aetherflow` (or `.../run/aetherflow`).
#[cfg(unix)]
pub(crate) fn open_or_create_lock_parent_dir_nofollow(
    dir: &Path,
    euid: libc::uid_t,
    target_gid: libc::gid_t,
    context: &str,
) -> HostBackupResult<File> {
    use std::os::unix::io::AsRawFd;

    let allow_service_owner = euid != 0;
    let create_mode = if euid == 0 { 0o1770 } else { 0o750 };
    let dir_file =
        open_or_create_dir_nofollow_internal(dir, create_mode, None, allow_service_owner, context)?;

    if euid == 0 && dir.to_string_lossy().ends_with("run/aetherflow") {
        let mut st_buf: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(dir_file.as_raw_fd(), &mut st_buf) } != 0 {
            return Err(HostBackupError::io(
                format!(
                    "fstat maintenance lock parent {} ({})",
                    dir.display(),
                    context
                ),
                std::io::Error::last_os_error(),
            ));
        }
        if st_buf.st_uid != 0 {
            return Err(HostBackupError::PathValidation {
                path: dir.to_path_buf(),
                reason: format!(
                    "shared runtime lock directory '{}' is owned by non-root uid={}",
                    dir.display(),
                    st_buf.st_uid
                ),
            });
        }
        if st_buf.st_gid != target_gid {
            let chown_rc = unsafe { libc::fchown(dir_file.as_raw_fd(), 0, target_gid) };
            if chown_rc != 0 {
                return Err(HostBackupError::io(
                    format!(
                        "fchown shared runtime lock directory {} ({})",
                        dir.display(),
                        context
                    ),
                    std::io::Error::last_os_error(),
                ));
            }
        }
        if (st_buf.st_mode & 0o7777) != 0o1770 {
            let chmod_rc = unsafe { libc::fchmod(dir_file.as_raw_fd(), 0o1770) };
            if chmod_rc != 0 {
                return Err(HostBackupError::io(
                    format!(
                        "fchmod shared runtime lock directory {} ({})",
                        dir.display(),
                        context
                    ),
                    std::io::Error::last_os_error(),
                ));
            }
        }
    }

    Ok(dir_file)
}

fn open_or_create_dir_nofollow_internal(
    dir: &Path,
    create_mode: u32,
    extra_trusted_uid: Option<u32>,
    allow_service_owner: bool,
    context: &str,
) -> HostBackupResult<File> {
    validate_no_parent_traversal(dir, context)?;
    if !dir.is_absolute() {
        return Err(HostBackupError::PathValidation {
            path: dir.to_path_buf(),
            reason: format!("{} must be an absolute path", context),
        });
    }

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let root_c = CString::new("/").unwrap();
        let root_fd = unsafe {
            libc::open(
                root_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if root_fd < 0 {
            return Err(HostBackupError::io(
                format!("opening '/' directory descriptor ({})", context),
                std::io::Error::last_os_error(),
            ));
        }
        let mut current_dir = unsafe { File::from_raw_fd(root_fd) };
        let euid = unsafe { libc::geteuid() };
        let service_ids = if allow_service_owner {
            resolve_trusted_service_account_ids()
        } else {
            None
        };
        let service_uid = service_ids.map(|(uid_val, _)| uid_val);
        let mut acc = PathBuf::from("/");
        verify_dir_fd_trusted_owner(
            current_dir.as_raw_fd(),
            &acc,
            euid,
            service_uid,
            extra_trusted_uid,
            context,
        )?;

        let normal_segments: Vec<&std::ffi::OsStr> = dir
            .components()
            .filter_map(|comp| match comp {
                Component::Normal(seg) => Some(seg),
                _ => None,
            })
            .collect();
        for comp in dir.components() {
            if matches!(comp, Component::ParentDir) {
                return Err(HostBackupError::TraversalRejected {
                    path: dir.to_string_lossy().into_owned(),
                    reason: format!("{} contains '..' segment", context),
                });
            }
        }

        let total_segments = normal_segments.len();
        for (seg_idx, seg) in normal_segments.into_iter().enumerate() {
            let is_leaf_segment = seg_idx + 1 == total_segments;
            let step_create_mode = if is_leaf_segment {
                create_mode & 0o7777
            } else {
                0o750
            };

            acc.push(seg);
            let seg_c =
                CString::new(seg.as_bytes()).map_err(|_| HostBackupError::PathValidation {
                    path: acc.clone(),
                    reason: "directory component contains interior NUL byte".to_string(),
                })?;

            let mut next_fd = unsafe {
                libc::openat(
                    current_dir.as_raw_fd(),
                    seg_c.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            };

            let mut created_now = false;
            if next_fd < 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                        if let Ok(meta) = fs::symlink_metadata(&acc) {
                            if meta.file_type().is_symlink() {
                                return Err(HostBackupError::SymlinkRejected {
                                    path: acc,
                                    reason: format!("{} component is a symbolic link", context),
                                });
                            }
                        }
                        if err.raw_os_error() == Some(libc::ELOOP) {
                            return Err(HostBackupError::SymlinkRejected {
                                path: acc,
                                reason: format!("{} component is a symbolic link (ELOOP)", context),
                            });
                        }
                        return Err(HostBackupError::PathValidation {
                            path: acc,
                            reason: format!("{} component exists and is not a directory", context),
                        });
                    }
                    Some(libc::ENOENT) => {
                        let mk_rc = unsafe {
                            libc::mkdirat(
                                current_dir.as_raw_fd(),
                                seg_c.as_ptr(),
                                step_create_mode as libc::mode_t,
                            )
                        };
                        if mk_rc == 0 {
                            created_now = true;
                        } else {
                            let mk_err = std::io::Error::last_os_error();
                            if mk_err.raw_os_error() != Some(libc::EEXIST) {
                                return Err(HostBackupError::io(
                                    format!("mkdirat {} ({})", acc.display(), context),
                                    mk_err,
                                ));
                            }
                        }
                        current_dir.sync_all().map_err(|sync_err| {
                            HostBackupError::io(
                                format!(
                                    "fsync parent directory after mkdirat {} ({})",
                                    acc.display(),
                                    context
                                ),
                                sync_err,
                            )
                        })?;
                        next_fd = unsafe {
                            libc::openat(
                                current_dir.as_raw_fd(),
                                seg_c.as_ptr(),
                                libc::O_RDONLY
                                    | libc::O_CLOEXEC
                                    | libc::O_DIRECTORY
                                    | libc::O_NOFOLLOW,
                            )
                        };
                        if next_fd < 0 {
                            let open_err = std::io::Error::last_os_error();
                            if open_err.raw_os_error() == Some(libc::ELOOP) {
                                return Err(HostBackupError::SymlinkRejected {
                                    path: acc,
                                    reason: format!(
                                        "{} component is a symbolic link after mkdirat",
                                        context
                                    ),
                                });
                            }
                            return Err(HostBackupError::io(
                                format!("openat created directory {} ({})", acc.display(), context),
                                open_err,
                            ));
                        }
                    }
                    _ => {
                        return Err(HostBackupError::io(
                            format!("openat {} ({})", acc.display(), context),
                            err,
                        ));
                    }
                }
            }

            let next_dir = unsafe { File::from_raw_fd(next_fd) };
            let is_var_lib_aetherflow = acc.to_string_lossy().ends_with("var/lib/aetherflow");
            if created_now && euid == 0 && allow_service_owner && is_var_lib_aetherflow {
                if let Some((_svc_uid, svc_gid)) = service_ids {
                    let chown_rc =
                        unsafe { libc::fchown(next_dir.as_raw_fd(), 0, svc_gid as libc::gid_t) };
                    if chown_rc != 0 {
                        return Err(HostBackupError::io(
                            format!(
                                "fchown shared state directory {} ({})",
                                acc.display(),
                                context
                            ),
                            std::io::Error::last_os_error(),
                        ));
                    }
                    let chmod_rc = unsafe { libc::fchmod(next_dir.as_raw_fd(), 0o1770) };
                    if chmod_rc != 0 {
                        return Err(HostBackupError::io(
                            format!(
                                "fchmod shared state directory {} ({})",
                                acc.display(),
                                context
                            ),
                            std::io::Error::last_os_error(),
                        ));
                    }
                }
            }

            verify_dir_fd_trusted_owner(
                next_dir.as_raw_fd(),
                &acc,
                euid,
                service_uid,
                extra_trusted_uid,
                context,
            )?;
            current_dir = next_dir;
        }

        Ok(current_dir)
    }

    #[cfg(not(unix))]
    {
        let _ = (extra_trusted_uid, allow_service_owner);
        ensure_private_dir_all(dir, context)?;
        File::open(dir).map_err(|err| {
            HostBackupError::io(format!("opening dir {} ({})", dir.display(), context), err)
        })
    }
}

/// Opens an existing directory without creating missing components or following symlinks.
/// Returns `Ok(None)` if any component along `dir` does not exist (`ENOENT`).
#[cfg(unix)]
pub(crate) fn open_existing_dir_nofollow_optional_with_trusted_uid(
    dir: &Path,
    extra_trusted_uid: Option<u32>,
    allow_service_owner: bool,
    context: &str,
) -> HostBackupResult<Option<File>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    validate_no_parent_traversal(dir, context)?;
    if !dir.is_absolute() {
        return Err(HostBackupError::PathValidation {
            path: dir.to_path_buf(),
            reason: format!("{} must be an absolute path", context),
        });
    }

    let root_c = CString::new("/").unwrap();
    let root_fd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(HostBackupError::io(
            format!("opening '/' directory descriptor ({})", context),
            std::io::Error::last_os_error(),
        ));
    }
    let mut current_dir = unsafe { File::from_raw_fd(root_fd) };
    let euid = unsafe { libc::geteuid() };
    let service_uid = if allow_service_owner {
        resolve_trusted_service_account_ids().map(|(uid_val, _)| uid_val)
    } else {
        None
    };
    let mut acc = PathBuf::from("/");
    verify_dir_fd_trusted_owner(
        current_dir.as_raw_fd(),
        &acc,
        euid,
        service_uid,
        extra_trusted_uid,
        context,
    )?;

    for comp in dir.components() {
        match comp {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(HostBackupError::TraversalRejected {
                    path: dir.to_string_lossy().into_owned(),
                    reason: format!("{} contains '..' segment", context),
                });
            }
            Component::Normal(seg) => {
                acc.push(seg);
                let seg_c =
                    CString::new(seg.as_bytes()).map_err(|_| HostBackupError::PathValidation {
                        path: acc.clone(),
                        reason: "directory component contains interior NUL byte".to_string(),
                    })?;

                let next_fd = unsafe {
                    libc::openat(
                        current_dir.as_raw_fd(),
                        seg_c.as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    )
                };
                if next_fd < 0 {
                    let err = std::io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::ENOENT) => return Ok(None),
                        Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                            if let Ok(meta) = fs::symlink_metadata(&acc) {
                                if meta.file_type().is_symlink() {
                                    return Err(HostBackupError::SymlinkRejected {
                                        path: acc,
                                        reason: format!("{} component is a symbolic link", context),
                                    });
                                }
                            }
                            if err.raw_os_error() == Some(libc::ELOOP) {
                                return Err(HostBackupError::SymlinkRejected {
                                    path: acc,
                                    reason: format!(
                                        "{} component is a symbolic link (ELOOP)",
                                        context
                                    ),
                                });
                            }
                            return Err(HostBackupError::PathValidation {
                                path: acc,
                                reason: format!(
                                    "{} component exists and is not a directory",
                                    context
                                ),
                            });
                        }
                        _ => {
                            return Err(HostBackupError::io(
                                format!("openat {} ({})", acc.display(), context),
                                err,
                            ));
                        }
                    }
                }
                let next_dir = unsafe { File::from_raw_fd(next_fd) };
                verify_dir_fd_trusted_owner(
                    next_dir.as_raw_fd(),
                    &acc,
                    euid,
                    service_uid,
                    extra_trusted_uid,
                    context,
                )?;
                current_dir = next_dir;
            }
        }
    }

    Ok(Some(current_dir))
}

/// Opens an existing regular file at `path` without following symlinks on any ancestor or leaf
/// (`O_RDONLY | O_CLOEXEC | O_NOFOLLOW` via pinned parent directory descriptor on Unix),
/// verifies via `fstat(fd)` that the opened descriptor is a regular file (`S_IFREG`),
/// and returns `Ok(Some((file, mode, uid, gid)))`, or `Ok(None)` if the file or an ancestor
/// directory does not exist (`ENOENT`).
pub fn open_existing_regular_file_nofollow(
    path: &Path,
    extra_trusted_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<Option<(File, u32, u32, u32)>> {
    validate_no_parent_traversal(path, context)?;
    let resolved_path: PathBuf;
    let effective_path = if path.is_absolute() {
        path
    } else {
        reject_if_symlink(path, context)?;
        let cwd = std::env::current_dir().map_err(|err| {
            HostBackupError::io(
                format!(
                    "resolving current working directory for {} ({})",
                    path.display(),
                    context
                ),
                err,
            )
        })?;
        resolved_path = cwd.join(path);
        &resolved_path
    };
    let parent = effective_path
        .parent()
        .ok_or_else(|| HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} has no parent directory", context),
        })?;
    let leaf_name = effective_path
        .file_name()
        .and_then(|os_val| os_val.to_str())
        .ok_or_else(|| HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} has invalid file name", context),
        })?;

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let Some(parent_dir) = open_existing_dir_nofollow_optional_with_trusted_uid(
            parent,
            extra_trusted_uid,
            true,
            context,
        )?
        else {
            return Ok(None);
        };
        let parent_dfd = parent_dir.as_raw_fd();
        let leaf_c = CString::new(leaf_name).map_err(|_| HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: "filename contains NUL byte".to_string(),
        })?;

        let mut pre_st: libc::stat = unsafe { std::mem::zeroed() };
        let st_rc = unsafe {
            libc::fstatat(
                parent_dfd,
                leaf_c.as_ptr(),
                &mut pre_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if st_rc != 0 {
            let st_err = std::io::Error::last_os_error();
            if st_err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(HostBackupError::io(
                format!("fstatat {} ({})", path.display(), context),
                st_err,
            ));
        }

        let pre_type = pre_st.st_mode & libc::S_IFMT;
        if pre_type == libc::S_IFLNK {
            return Err(HostBackupError::SymlinkRejected {
                path: path.to_path_buf(),
                reason: format!("{} is a symbolic link", context),
            });
        }
        if pre_type != libc::S_IFREG {
            return Err(HostBackupError::UnsafeOverwriteRejected {
                target: path.to_path_buf(),
                reason: format!("{} exists and is not a regular file", context),
            });
        }

        let fd = unsafe {
            libc::openat(
                parent_dfd,
                leaf_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            let open_err = std::io::Error::last_os_error();
            if open_err.raw_os_error() == Some(libc::ELOOP) {
                return Err(HostBackupError::SymlinkRejected {
                    path: path.to_path_buf(),
                    reason: format!("{} is a symbolic link (ELOOP)", context),
                });
            }
            if open_err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(HostBackupError::io(
                format!("openat {} ({})", path.display(), context),
                open_err,
            ));
        }

        let file = unsafe { File::from_raw_fd(fd) };
        let mut opened_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut opened_st) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat {} ({})", path.display(), context),
                std::io::Error::last_os_error(),
            ));
        }
        if (opened_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(HostBackupError::UnsafeOverwriteRejected {
                target: path.to_path_buf(),
                reason: format!("opened descriptor for {} is not a regular file", context),
            });
        }
        if opened_st.st_dev != pre_st.st_dev || opened_st.st_ino != pre_st.st_ino {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!("{} inode changed during no-follow open", context),
            });
        }

        let euid = unsafe { libc::geteuid() };
        let service_uid = resolve_trusted_service_account_ids().map(|(uid_val, _)| uid_val);
        let mut owner_trusted = opened_st.st_uid == 0 || opened_st.st_uid == euid;
        if !owner_trusted && !is_top_level_system_root(effective_path) {
            if let Some(extra_uid) = extra_trusted_uid {
                if opened_st.st_uid == extra_uid as libc::uid_t {
                    owner_trusted = true;
                }
            }
            if !owner_trusted && is_service_owned_subtree_eligible(effective_path) {
                if let Some(svc_uid) = service_uid {
                    if opened_st.st_uid == svc_uid as libc::uid_t {
                        owner_trusted = true;
                    }
                }
            }
        }
        if !owner_trusted {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!(
                    "untrusted file owner uid={} on '{}' during {}",
                    opened_st.st_uid,
                    path.display(),
                    context
                ),
            });
        }

        Ok(Some((
            file,
            (opened_st.st_mode as u32) & 0o777,
            opened_st.st_uid as u32,
            opened_st.st_gid as u32,
        )))
    }

    #[cfg(not(unix))]
    {
        let _ = (parent, leaf_name, extra_trusted_uid);
        reject_if_symlink(effective_path, context)?;
        match fs::symlink_metadata(effective_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(HostBackupError::SymlinkRejected {
                        path: path.to_path_buf(),
                        reason: format!("{} is a symbolic link", context),
                    });
                }
                if !meta.is_file() {
                    return Err(HostBackupError::UnsafeOverwriteRejected {
                        target: path.to_path_buf(),
                        reason: format!("{} exists and is not a regular file", context),
                    });
                }
                let file = File::open(effective_path).map_err(|err| {
                    HostBackupError::io(format!("opening {} ({})", path.display(), context), err)
                })?;
                Ok(Some((file, 0o600, 0, 0)))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(HostBackupError::io(
                format!("stat {} ({})", path.display(), context),
                err,
            )),
        }
    }
}

#[cfg(unix)]
fn is_top_level_system_root(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    matches!(
        raw.as_ref(),
        "/" | "/var"
            | "/var/lib"
            | "/etc"
            | "/opt"
            | "/home"
            | "/tmp"
            | "/var/tmp"
            | "/usr"
            | "/bin"
            | "/sbin"
            | "/lib"
            | "/lib64"
            | "/boot"
            | "/proc"
            | "/sys"
            | "/dev"
            | "/run"
    )
}

#[cfg(unix)]
fn is_service_owned_subtree_eligible(path: &Path) -> bool {
    if is_top_level_system_root(path) {
        return false;
    }
    if path.starts_with("/var/lib/aetherflow")
        || path.starts_with("/run/aetherflow")
        || path.starts_with("/etc/aetherflow")
        || path.starts_with("/etc/AetherFlow")
        || path.starts_with("/opt/AetherFlow")
        || path.starts_with("/home/aetherflow")
        || path.starts_with("/var/www/html/dashboard")
        || path.starts_with("/tmp")
        || path.starts_with("/var/tmp")
    {
        return true;
    }
    for env_key in [
        "AETHERFLOW_BACKUP_ISOLATED_ROOT",
        "AETHERFLOW_RESTORE_STAGING_ROOT",
        "AETHERFLOW_BACKUP_DIR",
        "AETHERFLOW_OWNER_HOME",
    ] {
        if let Ok(env_val) = std::env::var(env_key) {
            let trimmed = env_val.trim();
            if !trimmed.is_empty() && path.starts_with(Path::new(trimmed)) {
                return true;
            }
        }
    }
    false
}

#[cfg(unix)]
fn verify_dir_fd_trusted_owner(
    fd: std::os::unix::io::RawFd,
    path: &Path,
    euid: libc::uid_t,
    service_uid: Option<u32>,
    extra_trusted_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        return Err(HostBackupError::io(
            format!("fstat directory {} ({})", path.display(), context),
            std::io::Error::last_os_error(),
        ));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!("{} descriptor is not a directory", context),
        });
    }
    let is_world_writable = (st.st_mode & 0o002) != 0;
    let is_sticky = (st.st_mode & libc::S_ISVTX) != 0;
    if is_world_writable && !is_sticky {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!(
                "refusing to traverse non-sticky world-writable directory '{}' (mode {:o}) during {}",
                path.display(),
                st.st_mode & 0o7777,
                context
            ),
        });
    }
    if euid == 0 && service_uid.is_none() && extra_trusted_uid.is_none() {
        let is_group_writable = (st.st_mode & 0o020) != 0;
        if is_group_writable && st.st_gid != 0 && !is_sticky {
            return Err(HostBackupError::PathValidation {
                path: path.to_path_buf(),
                reason: format!(
                    "refusing to traverse non-sticky group-writable directory '{}' (gid={}, mode {:o}) during {}",
                    path.display(),
                    st.st_gid,
                    st.st_mode & 0o7777,
                    context
                ),
            });
        }
    }

    let mut trusted = st.st_uid == 0 || st.st_uid == euid;
    if !trusted && !is_top_level_system_root(path) {
        if let Some(extra_uid) = extra_trusted_uid {
            if st.st_uid == extra_uid as libc::uid_t {
                trusted = true;
            }
        }
        if !trusted && is_service_owned_subtree_eligible(path) {
            if let Some(svc_uid) = service_uid {
                if st.st_uid == svc_uid as libc::uid_t {
                    trusted = true;
                }
            }
        }
    }

    if !trusted {
        return Err(HostBackupError::PathValidation {
            path: path.to_path_buf(),
            reason: format!(
                "untrusted directory owner uid={} on '{}' (expected root=0, current euid={}, or trusted AetherFlow service owner {:?}/{:?})",
                st.st_uid,
                path.display(),
                euid,
                service_uid,
                extra_trusted_uid
            ),
        });
    }
    Ok(())
}

#[cfg(unix)]
struct PrivateInstallDirectory {
    parent: File,
    directory: File,
    name: std::ffi::CString,
    temporary: std::ffi::CString,
    identity: (u64, u64),
    #[cfg(test)]
    path: PathBuf,
}

#[cfg(unix)]
impl PrivateInstallDirectory {
    fn create(parent: &File, path: &Path, temporary: &std::ffi::CString) -> HostBackupResult<Self> {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let name = std::ffi::CString::new(format!(".af-install.{}", uuid::Uuid::new_v4())).unwrap();
        let staging_path = path.join(name.to_str().unwrap());
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(HostBackupError::io(
                "creating private install directory",
                std::io::Error::last_os_error(),
            ));
        }
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(HostBackupError::io(
                "opening private install directory",
                std::io::Error::last_os_error(),
            ));
        }
        let directory = unsafe { File::from_raw_fd(descriptor) };
        let metadata = directory
            .metadata()
            .map_err(|error| HostBackupError::io("verifying private install directory", error))?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(HostBackupError::PathValidation {
                path: staging_path,
                reason: "install staging directory is not executor-owned and private".to_string(),
            });
        }
        Ok(Self {
            parent: parent
                .try_clone()
                .map_err(|error| HostBackupError::io("pinning install parent", error))?,
            directory,
            name,
            temporary: temporary.clone(),
            identity: (metadata.dev(), metadata.ino()),
            #[cfg(test)]
            path: staging_path,
        })
    }
}

#[cfg(unix)]
impl Drop for PrivateInstallDirectory {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), self.temporary.as_ptr(), 0);
            let mut metadata: libc::stat = std::mem::zeroed();
            if libc::fstatat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                &mut metadata,
                libc::AT_SYMLINK_NOFOLLOW,
            ) == 0
                && (metadata.st_dev as u64, metadata.st_ino as u64) == self.identity
            {
                libc::unlinkat(
                    self.parent.as_raw_fd(),
                    self.name.as_ptr(),
                    libc::AT_REMOVEDIR,
                );
            }
        }
    }
}

#[cfg(test)]
type PreRenameInstallHook = Box<dyn Fn(&Path, &Path, &str) + Send + Sync>;

#[cfg(test)]
static PRE_RENAME_INSTALL_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<PreRenameInstallHook>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn set_pre_rename_install_hook(hook: Option<PreRenameInstallHook>) {
    let lock = PRE_RENAME_INSTALL_HOOK.get_or_init(|| std::sync::Mutex::new(None));
    if let Ok(mut guard) = lock.lock() {
        *guard = hook;
    }
}

#[cfg(test)]
fn invoke_pre_rename_install_hook(dest: &Path, parent: &Path, tmp_name: &str) {
    if let Some(lock) = PRE_RENAME_INSTALL_HOOK.get() {
        if let Ok(guard) = lock.lock() {
            if let Some(ref hook) = *guard {
                hook(dest, parent, tmp_name);
            }
        }
    }
}

/// Atomically copies `src` into `dest` using dirfd-relative `openat(..., O_CREAT | O_EXCL | O_NOFOLLOW)`,
/// `fchmod`, optional `fchown` (preserving `uid`/`gid`), `fsync` on the temporary file,
/// `renameat(parent_dfd, tmp, parent_dfd, dest_leaf)` (after verifying the destination leaf is not
/// an existing directory or symlink via `fstatat(..., AT_SYMLINK_NOFOLLOW)`), and `fsync(parent_dfd)`.
pub fn atomic_install_file_at_destination(
    src: &Path,
    dest: &Path,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    atomic_install_file_at_destination_with_trusted_ancestor_uid(
        src, dest, mode, uid, gid, None, context,
    )
}

/// Variant of [`atomic_install_file_at_destination`] that accepts an independently supplied
/// caller/service `trusted_ancestor_uid` (never derived from archive headers or manifest entries).
pub fn atomic_install_file_at_destination_with_trusted_ancestor_uid(
    src: &Path,
    dest: &Path,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    trusted_ancestor_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    atomic_install_file_at_destination_with_verification(
        src,
        None,
        None,
        None,
        dest,
        mode,
        uid,
        gid,
        trusted_ancestor_uid,
        context,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn atomic_install_file_at_destination_with_verification(
    src: &Path,
    expected_dev_ino: Option<(u64, u64)>,
    expected_sha256: Option<&str>,
    expected_size: Option<u64>,
    dest: &Path,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    trusted_ancestor_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    let mut src_file = if src.is_absolute() {
        let (file, _, _, _) =
            open_existing_regular_file_nofollow(src, trusted_ancestor_uid, context)?.ok_or_else(
                || HostBackupError::PathValidation {
                    path: src.to_path_buf(),
                    reason: format!("{} staged source does not exist", context),
                },
            )?;
        file
    } else {
        reject_if_symlink(src, context)?;
        let mut src_opts = OpenOptions::new();
        src_opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            src_opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        src_opts.open(src).map_err(|err| {
            HostBackupError::io(
                format!("opening staged source {} ({})", src.display(), context),
                err,
            )
        })?
    };

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let mut src_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(src_file.as_raw_fd(), &mut src_st) } != 0 {
            return Err(HostBackupError::io(
                format!("fstat staged source {} ({})", src.display(), context),
                std::io::Error::last_os_error(),
            ));
        }
        if (src_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(HostBackupError::PathValidation {
                path: src.to_path_buf(),
                reason: format!("{} staged source is not a regular file", context),
            });
        }
        if src_st.st_nlink == 0 {
            return Err(HostBackupError::PathValidation {
                path: src.to_path_buf(),
                reason: format!("{} staged source was unlinked before installation", context),
            });
        }
        if src_st.st_nlink > 1 {
            return Err(HostBackupError::PathValidation {
                path: src.to_path_buf(),
                reason: format!("{} staged source has multiple hard links", context),
            });
        }
        if let Some((exp_dev, exp_ino)) = expected_dev_ino {
            let euid = unsafe { libc::geteuid() };
            if src_st.st_uid != euid {
                return Err(HostBackupError::PathValidation {
                    path: src.to_path_buf(),
                    reason: format!(
                        "{} source owner uid={} does not match effective uid={}",
                        context, src_st.st_uid, euid
                    ),
                });
            }
            if src_st.st_dev as u64 != exp_dev || src_st.st_ino as u64 != exp_ino {
                return Err(HostBackupError::PathValidation {
                    path: src.to_path_buf(),
                    reason: format!(
                        "{} source inode changed before installation (expected dev={} ino={}, actual dev={} ino={})",
                        context, exp_dev, exp_ino, src_st.st_dev, src_st.st_ino
                    ),
                });
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = expected_dev_ino;
    }

    atomic_install_verified_reader_at_destination(
        &mut src_file,
        expected_sha256,
        expected_size,
        dest,
        mode,
        uid,
        gid,
        trusted_ancestor_uid,
        context,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn atomic_install_verified_reader_at_destination<R: Read>(
    src_reader: &mut R,
    expected_sha256: Option<&str>,
    expected_size: Option<u64>,
    dest: &Path,
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    trusted_ancestor_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| HostBackupError::PathValidation {
            path: dest.to_path_buf(),
            reason: format!("{} has no parent directory", context),
        })?;
    let leaf_name = dest
        .file_name()
        .and_then(|os_val| os_val.to_str())
        .ok_or_else(|| HostBackupError::PathValidation {
            path: dest.to_path_buf(),
            reason: format!("{} has invalid file name", context),
        })?;

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let parent_dir = open_or_create_dir_nofollow_with_trusted_uid(
            parent,
            0o755,
            trusted_ancestor_uid,
            context,
        )?;
        let parent_dfd = parent_dir.as_raw_fd();

        let leaf_c = CString::new(leaf_name).map_err(|_| HostBackupError::PathValidation {
            path: dest.to_path_buf(),
            reason: "destination filename contains NUL byte".to_string(),
        })?;

        let mut existing_st: libc::stat = unsafe { std::mem::zeroed() };
        let st_rc = unsafe {
            libc::fstatat(
                parent_dfd,
                leaf_c.as_ptr(),
                &mut existing_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if st_rc == 0 {
            let ftype = existing_st.st_mode & libc::S_IFMT;
            if ftype == libc::S_IFLNK {
                return Err(HostBackupError::SymlinkRejected {
                    path: dest.to_path_buf(),
                    reason: format!("{} destination leaf is a symbolic link", context),
                });
            }
            if ftype != libc::S_IFREG {
                return Err(HostBackupError::UnsafeOverwriteRejected {
                    target: dest.to_path_buf(),
                    reason: format!(
                        "{} destination leaf exists and is not a regular file",
                        context
                    ),
                });
            }
        } else {
            let st_err = std::io::Error::last_os_error();
            if st_err.raw_os_error() != Some(libc::ENOENT) {
                return Err(HostBackupError::io(
                    format!("fstatat {} ({})", dest.display(), context),
                    st_err,
                ));
            }
        }

        let tmp_name = format!(
            ".{}.af-atomic.{}.{}",
            leaf_name,
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let tmp_c =
            CString::new(tmp_name.as_str()).map_err(|_| HostBackupError::PathValidation {
                path: dest.to_path_buf(),
                reason: "temporary filename contains NUL byte".to_string(),
            })?;

        let staging = PrivateInstallDirectory::create(&parent_dir, parent, &tmp_c)?;
        let staging_dfd = staging.directory.as_raw_fd();
        let tmp_fd = unsafe {
            libc::openat(
                staging_dfd,
                tmp_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                (mode & 0o7777) as libc::c_uint,
            )
        };
        if tmp_fd < 0 {
            return Err(HostBackupError::io(
                format!(
                    "openat temporary file in {} ({})",
                    parent.display(),
                    context
                ),
                std::io::Error::last_os_error(),
            ));
        }
        let mut tmp_file = unsafe { File::from_raw_fd(tmp_fd) };

        let write_res: HostBackupResult<libc::stat> = (|| {
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 64 * 1024];
            let mut copied_bytes = 0u64;
            loop {
                let count = src_reader.read(&mut buf).map_err(|err| {
                    HostBackupError::io(
                        format!("reading payload for {} ({})", dest.display(), context),
                        err,
                    )
                })?;
                if count == 0 {
                    break;
                }
                tmp_file.write_all(&buf[..count]).map_err(|err| {
                    HostBackupError::io(
                        format!("writing payload to {} ({})", dest.display(), context),
                        err,
                    )
                })?;
                hasher.update(&buf[..count]);
                copied_bytes += count as u64;
            }

            if let Some(exp_sz) = expected_size {
                if copied_bytes != exp_sz {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest.display().to_string(),
                        expected: format!("size={}", exp_sz),
                        actual: format!("size={}", copied_bytes),
                    });
                }
            }
            if let Some(exp_sha) = expected_sha256 {
                let exp_clean = exp_sha.trim().to_ascii_lowercase();
                let actual_sha = hex::encode(hasher.finalize());
                if actual_sha != exp_clean {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest.display().to_string(),
                        expected: exp_clean,
                        actual: actual_sha,
                    });
                }
            }

            if uid.is_some() || gid.is_some() {
                let target_uid = uid
                    .map(|uid_val| uid_val as libc::uid_t)
                    .unwrap_or(u32::MAX as libc::uid_t);
                let target_gid = gid
                    .map(|gid_val| gid_val as libc::gid_t)
                    .unwrap_or(u32::MAX as libc::gid_t);
                let chown_rc =
                    unsafe { libc::fchown(tmp_file.as_raw_fd(), target_uid, target_gid) };
                if chown_rc != 0 {
                    let chown_err = std::io::Error::last_os_error();
                    let euid = unsafe { libc::geteuid() };
                    let mut actual_st: libc::stat = unsafe { std::mem::zeroed() };
                    let stat_ok = unsafe { libc::fstat(tmp_file.as_raw_fd(), &mut actual_st) } == 0;
                    let uid_satisfied = stat_ok
                        && uid
                            .map(|req_uid| actual_st.st_uid == req_uid as libc::uid_t)
                            .unwrap_or(true);
                    let gid_satisfied = stat_ok
                        && gid
                            .map(|req_gid| actual_st.st_gid == req_gid as libc::gid_t)
                            .unwrap_or(true);
                    let is_perm_err = matches!(
                        chown_err.raw_os_error(),
                        Some(libc::EPERM) | Some(libc::EACCES)
                    );
                    if euid == 0 || !is_perm_err || !uid_satisfied || !gid_satisfied {
                        return Err(HostBackupError::io(
                            format!(
                                "fchown uid={:?} gid={:?} on {} ({})",
                                uid,
                                gid,
                                dest.display(),
                                context
                            ),
                            chown_err,
                        ));
                    }
                }
            }

            let chmod_rc =
                unsafe { libc::fchmod(tmp_file.as_raw_fd(), (mode & 0o7777) as libc::mode_t) };
            if chmod_rc != 0 {
                return Err(HostBackupError::io(
                    format!(
                        "fchmod {:o} on {} ({})",
                        mode & 0o7777,
                        dest.display(),
                        context
                    ),
                    std::io::Error::last_os_error(),
                ));
            }

            tmp_file.sync_all().map_err(|err| {
                HostBackupError::io(
                    format!("fsync temporary file for {} ({})", dest.display(), context),
                    err,
                )
            })?;

            let mut tmp_st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(tmp_file.as_raw_fd(), &mut tmp_st) } != 0 {
                return Err(HostBackupError::io(
                    format!("fstat temporary file for {} ({})", dest.display(), context),
                    std::io::Error::last_os_error(),
                ));
            }
            if (tmp_st.st_mode & libc::S_IFMT) != libc::S_IFREG || tmp_st.st_nlink != 1 {
                return Err(HostBackupError::PathValidation {
                    path: dest.to_path_buf(),
                    reason: format!(
                        "{} temporary file has unexpected link count or type before rename",
                        context
                    ),
                });
            }
            Ok(tmp_st)
        })();

        let tmp_st = match write_res {
            Ok(stat_val) => stat_val,
            Err(err) => {
                drop(tmp_file);
                unsafe {
                    let _ = libc::unlinkat(staging_dfd, tmp_c.as_ptr(), 0);
                }
                return Err(err);
            }
        };

        #[cfg(test)]
        invoke_pre_rename_install_hook(dest, &staging.path, &tmp_name);

        let mut pre_rename_fd_st: libc::stat = unsafe { std::mem::zeroed() };
        let mut pre_rename_dir_st: libc::stat = unsafe { std::mem::zeroed() };
        let pre_fd_ok = unsafe { libc::fstat(tmp_file.as_raw_fd(), &mut pre_rename_fd_st) } == 0;
        let pre_dir_ok = unsafe {
            libc::fstatat(
                staging_dfd,
                tmp_c.as_ptr(),
                &mut pre_rename_dir_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0;
        if !pre_fd_ok
            || !pre_dir_ok
            || (pre_rename_dir_st.st_mode & libc::S_IFMT) != libc::S_IFREG
            || pre_rename_fd_st.st_nlink != 1
            || pre_rename_dir_st.st_nlink != 1
            || pre_rename_dir_st.st_dev != tmp_st.st_dev
            || pre_rename_dir_st.st_ino != tmp_st.st_ino
        {
            drop(tmp_file);
            return Err(HostBackupError::PathValidation {
                path: dest.to_path_buf(),
                reason: format!(
                    "{} temporary file at '{}' was replaced, unlinked, or hard-linked before rename",
                    context,
                    parent.join(&tmp_name).display()
                ),
            });
        }

        let rename_rc =
            unsafe { libc::renameat(staging_dfd, tmp_c.as_ptr(), parent_dfd, leaf_c.as_ptr()) };
        if rename_rc != 0 {
            let ren_err = std::io::Error::last_os_error();
            drop(tmp_file);
            return Err(HostBackupError::io(
                format!("renameat -> {} ({})", dest.display(), context),
                ren_err,
            ));
        }

        let mut post_rename_dir_st: libc::stat = unsafe { std::mem::zeroed() };
        let mut post_rename_fd_st: libc::stat = unsafe { std::mem::zeroed() };
        let post_dir_ok = unsafe {
            libc::fstatat(
                parent_dfd,
                leaf_c.as_ptr(),
                &mut post_rename_dir_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0;
        let post_fd_ok = unsafe { libc::fstat(tmp_file.as_raw_fd(), &mut post_rename_fd_st) } == 0;
        drop(tmp_file);
        if !post_dir_ok
            || !post_fd_ok
            || (post_rename_dir_st.st_mode & libc::S_IFMT) != libc::S_IFREG
            || post_rename_dir_st.st_dev != tmp_st.st_dev
            || post_rename_dir_st.st_ino != tmp_st.st_ino
            || post_rename_dir_st.st_size != tmp_st.st_size
            || (post_rename_dir_st.st_mode & 0o7777) != (tmp_st.st_mode & 0o7777)
            || post_rename_dir_st.st_uid != tmp_st.st_uid
            || post_rename_dir_st.st_gid != tmp_st.st_gid
            || post_rename_fd_st.st_nlink != 1
        {
            return Err(HostBackupError::PathValidation {
                path: dest.to_path_buf(),
                reason: format!(
                    "{} destination '{}' failed post-rename inode/metadata verification",
                    context,
                    dest.display()
                ),
            });
        }

        parent_dir.sync_all().map_err(|err| {
            HostBackupError::io(
                format!("fsync parent directory {} ({})", parent.display(), context),
                err,
            )
        })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = (uid, gid, trusted_ancestor_uid);
        ensure_private_dir_all(parent, context)?;
        let (tmp_path, mut tmp_file) =
            create_unique_private_temp_file(dest, "atomic-install", context)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut copied_bytes = 0u64;
        let copy_res: HostBackupResult<()> = (|| {
            loop {
                let count = src_reader.read(&mut buf).map_err(|err| {
                    HostBackupError::io(
                        format!("reading payload for {} ({})", dest.display(), context),
                        err,
                    )
                })?;
                if count == 0 {
                    break;
                }
                tmp_file.write_all(&buf[..count]).map_err(|err| {
                    HostBackupError::io(
                        format!(
                            "writing temporary install file {} ({})",
                            tmp_path.display(),
                            context
                        ),
                        err,
                    )
                })?;
                hasher.update(&buf[..count]);
                copied_bytes += count as u64;
            }
            if let Some(exp_sz) = expected_size {
                if copied_bytes != exp_sz {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest.display().to_string(),
                        expected: format!("size={}", exp_sz),
                        actual: format!("size={}", copied_bytes),
                    });
                }
            }
            if let Some(exp_sha) = expected_sha256 {
                let exp_clean = exp_sha.trim().to_ascii_lowercase();
                let actual_sha = hex::encode(hasher.finalize());
                if actual_sha != exp_clean {
                    return Err(HostBackupError::ChecksumMismatch {
                        artifact: dest.display().to_string(),
                        expected: exp_clean,
                        actual: actual_sha,
                    });
                }
            }
            tmp_file.sync_all().map_err(|err| {
                HostBackupError::io(
                    format!(
                        "syncing temporary install file {} ({})",
                        tmp_path.display(),
                        context
                    ),
                    err,
                )
            })?;
            Ok(())
        })();
        drop(tmp_file);
        if let Err(err) = copy_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
        if let Err(err) = fs::rename(&tmp_path, dest) {
            let _ = fs::remove_file(&tmp_path);
            return Err(HostBackupError::io(
                format!(
                    "renaming {} -> {} ({})",
                    tmp_path.display(),
                    dest.display(),
                    context
                ),
                err,
            ));
        }
        Ok(())
    }
}

/// Removes a regular file at `target` using dirfd-relative `unlinkat(parent_dfd, leaf, 0)` on Unix
/// after verifying `parent` is free of symlinks and owned by a trusted user. Ignores `ENOENT`.
pub fn unlink_file_at_destination(target: &Path, context: &str) -> HostBackupResult<()> {
    unlink_file_at_destination_with_trusted_ancestor_uid(target, None, context)
}

/// Variant of [`unlink_file_at_destination`] that accepts an independently supplied
/// caller/service `trusted_ancestor_uid`.
pub fn unlink_file_at_destination_with_trusted_ancestor_uid(
    target: &Path,
    trusted_ancestor_uid: Option<u32>,
    context: &str,
) -> HostBackupResult<()> {
    let Some(parent) = target.parent() else {
        return Ok(());
    };
    let Some(leaf_name) = target.file_name().and_then(|os_val| os_val.to_str()) else {
        return Ok(());
    };

    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::io::AsRawFd;

        let Some(parent_dir) = open_existing_dir_nofollow_optional_with_trusted_uid(
            parent,
            trusted_ancestor_uid,
            true,
            context,
        )?
        else {
            return Ok(());
        };
        let parent_dfd = parent_dir.as_raw_fd();
        let leaf_c = CString::new(leaf_name).map_err(|_| HostBackupError::PathValidation {
            path: target.to_path_buf(),
            reason: "filename contains NUL byte".to_string(),
        })?;
        let mut leaf_st: libc::stat = unsafe { std::mem::zeroed() };
        let st_rc = unsafe {
            libc::fstatat(
                parent_dfd,
                leaf_c.as_ptr(),
                &mut leaf_st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if st_rc != 0 {
            let st_err = std::io::Error::last_os_error();
            if st_err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            return Err(HostBackupError::io(
                format!("fstatat {} ({})", target.display(), context),
                st_err,
            ));
        }
        let leaf_type = leaf_st.st_mode & libc::S_IFMT;
        if leaf_type == libc::S_IFLNK {
            return Err(HostBackupError::SymlinkRejected {
                path: target.to_path_buf(),
                reason: format!("{} target leaf is a symbolic link", context),
            });
        }
        if leaf_type != libc::S_IFREG {
            return Err(HostBackupError::UnsafeOverwriteRejected {
                target: target.to_path_buf(),
                reason: format!("{} target leaf exists and is not a regular file", context),
            });
        }
        let rc = unsafe { libc::unlinkat(parent_dfd, leaf_c.as_ptr(), 0) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(HostBackupError::io(
                    format!("unlinkat {} ({})", target.display(), context),
                    err,
                ));
            }
        } else {
            parent_dir.sync_all().map_err(|err| {
                HostBackupError::io(
                    format!(
                        "fsync parent directory {} after unlinkat ({})",
                        parent.display(),
                        context
                    ),
                    err,
                )
            })?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = (leaf_name, trusted_ancestor_uid);
        match fs::remove_file(target) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(HostBackupError::io(
                format!("removing {} ({})", target.display(), context),
                err,
            )),
        }
    }
}
