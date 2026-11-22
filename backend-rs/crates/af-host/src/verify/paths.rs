use super::dirfd::open_or_create_dir_nofollow;
use crate::error::{HostBackupError, HostBackupResult};
use once_cell::sync::Lazy;
use regex::Regex;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

/// Strict filename allowlist for backup artifacts (`.sqlite`, `.tar.gz`, `.manifest.json`).
static SAFE_BACKUP_FILENAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,191}$").unwrap());

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
